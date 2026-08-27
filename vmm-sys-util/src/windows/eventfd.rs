// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Windows analog of Linux [`eventfd`](http://man7.org/linux/man-pages/man2/eventfd.2.html),
//! backed by an auto-reset Win32 event object.
//!
//! A Win32 event has no counter, just signaled/not. [`EventFd::write`] and
//! [`EventFd::read`] only signal and wait — no add/drain semantics. That's
//! enough for doorbell use, the only way eventfd is used in rust-vmm.
//!
//! Auto-reset matters: the kernel consumes the signal atomically as part of
//! satisfying a wait, so one `write` wakes exactly one waiter — matching
//! Linux eventfd's atomic read — with no separate reset step to race
//! against. Every event this module creates is auto-reset.
//!
//! Reset mode is a property of the object, not the handle, and the rule for
//! peer-created events follows the *waiter*: an event this side will wait
//! on ([`EventFd::read`], or registration with [`crate::epoll::Epoll`])
//! must be created auto-reset by its minting process; an event this side
//! only ever signals ([`EventFd::write`]) works either way — `SetEvent`
//! is mode-agnostic. A creator cannot *prove* it got auto-reset —
//! `CreateEventW` over an existing name silently ignores `bManualReset`
//! and returns the existing object — which is why creation here fails on
//! `ERROR_ALREADY_EXISTS` instead of proceeding with an object whose
//! semantics someone else chose.
//!
//! [`EventFd::new`] creates an anonymous event. [`EventFd::new_shareable`]
//! mints an unguessable name instead, for a peer to open via
//! [`EventFd::open`] once it's passed out of band — a Win32 object can only
//! be named at creation, and most events never cross a process boundary.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::result;

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE,
    INFINITE,
};

use crate::windows::named_object;

// Reexported for #[cfg]-free callers. Only EFD_NONBLOCK has any effect;
// EFD_SEMAPHORE/EFD_CLOEXEC have no Win32 equivalent and are ignored.
/// Mirrors Linux's `EFD_NONBLOCK`, honored by [`EventFd`].
pub const EFD_NONBLOCK: i32 = 1 << 0;
/// Mirrors Linux's `EFD_CLOEXEC`; no effect on Windows.
pub const EFD_CLOEXEC: i32 = 1 << 1;
/// Mirrors Linux's `EFD_SEMAPHORE`; no effect on Windows (no counter).
pub const EFD_SEMAPHORE: i32 = 1 << 2;

fn unique_name() -> String {
    named_object::unique_name("vmm-sys-util-evt-")
}

/// Create an auto-reset event under `name` with a creator-only DACL,
/// failing (rather than adopting the impostor) if the name is taken.
fn create_named_event(name: &str) -> io::Result<HANDLE> {
    let sa = named_object::creator_only_attributes()?;
    let wide = named_object::to_wide_name(name)?;
    // SAFETY: `sa` and `wide` are valid for the duration of the call; the
    // return value is checked.
    let handle = unsafe { CreateEventW(&sa, 0, 0, wide.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // Nothing between the create and this check can clobber the
    // thread's last-error slot.
    named_object::reject_preexisting(handle)
}

/// A safe wrapper around an auto-reset Win32 event object, used as the
/// Windows analog of Linux `eventfd`.
#[derive(Debug)]
pub struct EventFd {
    event: HANDLE,
    nonblock: bool,
    /// The object's name; `None` when the event arrived as a bare handle
    /// ([`FromRawHandle`]) and its name is unknown.
    name: Option<String>,
}

// SAFETY: a Win32 HANDLE has no thread affinity.
unsafe impl Send for EventFd {}
// SAFETY: `&self` methods only call thread-safe Win32 APIs
// (SetEvent/WaitForSingleObject/ResetEvent).
unsafe impl Sync for EventFd {}

impl EventFd {
    /// Create a new anonymous `EventFd`, backed by a freshly created
    /// auto-reset event object.
    ///
    /// # Arguments
    ///
    /// * `flag`: only [`EFD_NONBLOCK`] has any effect; see the module docs.
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        // SAFETY: all arguments are simple values; the return value is
        // checked for failure.
        let handle = unsafe { CreateEventW(null(), 0, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd {
            event: handle,
            nonblock: flag & EFD_NONBLOCK != 0,
            name: None,
        })
    }

    /// Create a new `EventFd` under a freshly minted, unguessable name, for
    /// handing to another process (see the module docs).
    ///
    /// The name is 128 random bits, the object's DACL admits only the
    /// creating user, and creation fails if the name is somehow already
    /// taken instead of silently adopting the existing object.
    ///
    /// # Arguments
    ///
    /// * `flag`: only [`EFD_NONBLOCK`] has any effect; see the module docs.
    pub fn new_shareable(flag: i32) -> result::Result<EventFd, io::Error> {
        let name = unique_name();
        let handle = create_named_event(&name)?;
        Ok(EventFd {
            event: handle,
            nonblock: flag & EFD_NONBLOCK != 0,
            name: Some(name),
        })
    }

    /// The object's name, for transmitting to a peer that will
    /// [`open`](EventFd::open) the same event; `Some` only for events
    /// from [`new_shareable`](EventFd::new_shareable) or
    /// [`open`](EventFd::open) — an anonymous or bare-handle event has
    /// none to give.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Open an existing named event object created by a peer process (e.g.
    /// via [`EventFd::new_shareable`] there, with the name communicated out
    /// of band).
    ///
    /// The handle asks for signal, wait, and state-query access — the last
    /// so that [`crate::epoll::Epoll`]'s debug-build check can verify the
    /// event is auto-reset (see the module docs); a creator restricting
    /// its DACL below `EVENT_QUERY_STATE` breaks that verification.
    ///
    /// # Arguments
    ///
    /// * `name`: the name the creating process minted; must not contain an
    ///   interior NUL byte.
    /// * `flag`: only [`EFD_NONBLOCK`] has any effect, same as
    ///   [`new`](EventFd::new) — non-blocking is a property of this side's
    ///   handle use, not of who created the object.
    pub fn open(name: &str, flag: i32) -> result::Result<EventFd, io::Error> {
        // Not exposed outside windows-sys's Wdk tree; the value is fixed.
        const EVENT_QUERY_STATE: u32 = 0x0001;
        let wide = named_object::to_wide_name(name)?;
        // SAFETY: `wide` is a valid NUL-terminated wide string outliving the call.
        let handle = unsafe {
            OpenEventW(
                EVENT_MODIFY_STATE | EVENT_QUERY_STATE | SYNCHRONIZE,
                0,
                wide.as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd {
            event: handle,
            nonblock: flag & EFD_NONBLOCK != 0,
            name: Some(name.to_string()),
        })
    }

    /// Signal the event.
    ///
    /// Unlike Linux eventfd, this does not implement an add-to-counter: `v`
    /// is ignored and the event is simply set to the signaled state. This
    /// never blocks (there is no overflow condition on Windows).
    ///
    /// # Arguments
    ///
    /// * `v`: ignored; accepted only for source compatibility with the
    ///   Linux `EventFd::write` signature.
    pub fn write(&self, _v: u64) -> result::Result<(), io::Error> {
        // SAFETY: `self.event` is valid for the lifetime of `self`.
        let ret = unsafe { SetEvent(self.event) };
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait for the event to become signaled, consuming the signal.
    ///
    /// The event is auto-reset, so consumption is atomic in the kernel:
    /// one [`write`](EventFd::write) releases exactly one reader, even
    /// with several blocked concurrently.
    ///
    /// Returns `Ok(1)` on success as a placeholder: there is no real counter
    /// value to return (see the module docs). If the `EventFd` was created
    /// with [`EFD_NONBLOCK`], returns a [`io::ErrorKind::WouldBlock`] error
    /// instead of blocking when the event is not currently signaled.
    pub fn read(&self) -> result::Result<u64, io::Error> {
        let timeout = if self.nonblock { 0 } else { INFINITE };
        if self.wait_for_signal(timeout)? {
            Ok(1)
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    /// Waits up to `timeout_ms` for the event to become signaled. The event
    /// is auto-reset, so a satisfied wait consumes the signal atomically.
    /// Returns `Ok(true)` if signaled (and consumed), `Ok(false)` on
    /// timeout.
    fn wait_for_signal(&self, timeout_ms: u32) -> result::Result<bool, io::Error> {
        // SAFETY: `self.event` is valid for the lifetime of `self`.
        let ret = unsafe { WaitForSingleObject(self.event, timeout_ms) };
        if ret == WAIT_OBJECT_0 {
            Ok(true)
        } else if ret == WAIT_TIMEOUT {
            Ok(false)
        } else if ret == WAIT_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::other(format!(
                "unexpected WaitForSingleObject return value: {ret:#x}"
            )))
        }
    }

    /// Clone this `EventFd`.
    ///
    /// This creates a new handle referring to the same underlying event
    /// object.
    pub fn try_clone(&self) -> result::Result<EventFd, io::Error> {
        let mut new_handle: HANDLE = null_mut();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle valid for the
        // process lifetime; `self.event` is valid for `self`'s lifetime.
        let ret = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                self.event,
                process,
                &mut new_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd {
            event: new_handle,
            nonblock: self.nonblock,
            // The duplicate refers to the same kernel object, so the
            // object's name is unchanged.
            name: self.name.clone(),
        })
    }
}

impl AsRawHandle for EventFd {
    fn as_raw_handle(&self) -> RawHandle {
        self.event as RawHandle
    }
}

impl FromRawHandle for EventFd {
    /// The adopted `EventFd` is blocking: unlike a Unix fd's
    /// `O_NONBLOCK`, a Win32 handle carries no non-blocking mode to
    /// inherit, so a bare handle can't say how it was meant to be used.
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        EventFd {
            event: handle as HANDLE,
            nonblock: false,
            name: None,
        }
    }
}

impl IntoRawHandle for EventFd {
    fn into_raw_handle(self) -> RawHandle {
        // Suppress `Drop` (which would close the handle) without leaking
        // the rest of the struct: a bare `mem::forget` also leaked the
        // name's heap allocation, once per call.
        let mut this = std::mem::ManuallyDrop::new(self);
        drop(this.name.take());
        this.event as RawHandle
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        // SAFETY: `self.event` is owned by this `EventFd`.
        unsafe {
            CloseHandle(self.event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        EventFd::new(EFD_NONBLOCK).unwrap();
        EventFd::new(0).unwrap();
    }

    #[test]
    fn test_write_read_signal() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read().unwrap(), 1);
    }

    #[test]
    fn test_read_nothing() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let err = evt.read().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn a_single_write_wakes_exactly_one_reader() {
        // Auto-reset regression: consumption is atomic in the kernel, so
        // one write must satisfy exactly one read, even when several
        // threads race for it. The manual-reset implementation (wait, then
        // a separate ResetEvent) let two racing readers both return Ok.
        let evt = std::sync::Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        evt.write(1).unwrap();

        let successes: usize = (0..4)
            .map(|_| {
                let evt = evt.clone();
                std::thread::spawn(move || evt.read().is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap() as usize)
            .sum();
        assert_eq!(successes, 1);

        // And the signal is gone afterwards.
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 1);
    }

    #[test]
    fn test_open_by_name() {
        let name = unique_name();
        let wide = named_object::to_wide_name(&name).unwrap();
        // SAFETY: `wide` is a valid NUL-terminated wide string.
        let handle = unsafe { CreateEventW(null(), 0, 0, wide.as_ptr()) };
        assert!(!handle.is_null());
        // SAFETY: handle was just created successfully above.
        let created = unsafe { EventFd::from_raw_handle(handle as RawHandle) };

        let opened = EventFd::open(&name, 0).unwrap();
        created.write(1).unwrap();
        assert_eq!(opened.read().unwrap(), 1);
    }

    #[test]
    fn test_open_missing() {
        assert!(EventFd::open("vmm-sys-util-evt-does-not-exist", 0).is_err());
    }

    #[test]
    fn a_shareable_eventfd_carries_its_name_for_a_peer_to_open() {
        // The frontend side of a transport creates the event and sends
        // its name; without retention nothing could be transmitted.
        let evt = EventFd::new_shareable(0).unwrap();
        let name = evt.name().expect("a shareable EventFd must know its name");
        assert!(name.starts_with("Local\\vmm-sys-util-evt-"));

        let opened = EventFd::open(name, 0).unwrap();
        evt.write(1).unwrap();
        assert_eq!(opened.read().unwrap(), 1);
    }

    #[test]
    fn creating_over_a_squatted_name_fails_instead_of_adopting_it() {
        // Windows reports a name collision as success + ERROR_ALREADY_EXISTS,
        // returning the squatter's object. The create path must refuse it.
        let squatter = unique_name();
        let first = create_named_event(&squatter).unwrap();
        // SAFETY: `first` was just created successfully above.
        let _first = unsafe { EventFd::from_raw_handle(first as RawHandle) };

        let err = create_named_event(&squatter).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn a_non_ascii_name_round_trips() {
        // The point of the W entry points: the A variants convert names
        // through the process ANSI code page, so a name outside it could
        // resolve differently on each side of the process boundary. Wide
        // names have no code page.
        let name = format!(
            "Local\\vmm-sys-util-evt-\u{e9}v\u{e9}nement-{}",
            std::process::id()
        );
        let wide = named_object::to_wide_name(&name).unwrap();
        // SAFETY: `wide` is a valid NUL-terminated wide string.
        let created = unsafe { CreateEventW(null(), 0, 0, wide.as_ptr()) };
        assert!(!created.is_null());
        // SAFETY: just created above, not yet owned elsewhere.
        let created = unsafe { EventFd::from_raw_handle(created as RawHandle) };

        let opened = EventFd::open(&name, 0).unwrap();
        created.write(1).unwrap();
        assert_eq!(opened.read().unwrap(), 1);
    }

    #[test]
    fn a_peer_opened_eventfd_can_be_nonblocking() {
        // Regression: open() used to hardcode blocking, so a peer-opened
        // doorbell could not be polled without hanging.
        let evt = EventFd::new_shareable(0).unwrap();
        let opened = EventFd::open(evt.name().unwrap(), EFD_NONBLOCK).unwrap();
        // Unsignaled: must return WouldBlock immediately, not hang.
        assert_eq!(opened.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        // And still delivers a real signal.
        evt.write(1).unwrap();
        assert_eq!(opened.read().unwrap(), 1);
    }

    #[test]
    fn a_plain_eventfd_is_anonymous() {
        // Most events never cross a process boundary; they should not
        // occupy the session's object namespace.
        let evt = EventFd::new(0).unwrap();
        assert!(evt.name().is_none());
    }

    #[test]
    fn a_clone_keeps_the_name_and_a_bare_handle_loses_it() {
        let evt = EventFd::new_shareable(0).unwrap();
        let cloned = evt.try_clone().unwrap();
        assert_eq!(cloned.name(), evt.name());

        // SAFETY: the handle comes straight from into_raw_handle.
        let adopted = unsafe { EventFd::from_raw_handle(cloned.into_raw_handle()) };
        assert!(adopted.name().is_none());
    }

    #[test]
    fn a_thousand_into_raw_handle_cycles_leak_no_name_bytes() {
        // The handle-count tests can't see this leak: mem::forget in
        // into_raw_handle leaked the name's CString — memory, not a
        // handle. ~50 leaked bytes per cycle over N cycles is a clear
        // signal; the threshold leaves slack for other tests' allocation
        // noise in the same window.
        const N: isize = 2000;
        let before = crate::windows::allocated_bytes();
        for _ in 0..N {
            let e = EventFd::new_shareable(0).unwrap();
            let h = e.into_raw_handle();
            // SAFETY: `h` came from into_raw_handle and is closed exactly
            // once, keeping the handle count flat.
            unsafe { CloseHandle(h as HANDLE) };
        }
        let after = crate::windows::allocated_bytes();
        assert!(
            after - before < N * 25,
            "net allocation grew {} bytes over {N} cycles",
            after - before
        );
    }

    #[test]
    fn a_thousand_eventfd_cycles_leak_no_handles() {
        // Delta over N rather than exact equality: other test threads
        // add background handle noise, but a per-iteration leak adds N.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let e = EventFd::new_shareable(0).unwrap();
            let c = e.try_clone().unwrap();
            let o = EventFd::open(e.name().unwrap(), 0).unwrap();
            drop((e, c, o));
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }
}
