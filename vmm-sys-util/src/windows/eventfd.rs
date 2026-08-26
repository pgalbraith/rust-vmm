// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Windows analog of Linux [`eventfd`](http://man7.org/linux/man-pages/man2/eventfd.2.html),
//! backed by a manual-reset Win32 event object.
//!
//! A Win32 event has no counter, just signaled/not. [`EventFd::write`] and
//! [`EventFd::read`] only signal and wait — no add/drain semantics. That's
//! enough for doorbell use, the only way eventfd is used in rust-vmm.
//!
//! [`EventFd::new`] creates an anonymous event. [`EventFd::new_shareable`]
//! mints an unguessable name instead, for a peer to open via
//! [`EventFd::open`] once it's passed out of band — a Win32 object can only
//! be named at creation, and most events never cross a process boundary.

use std::ffi::CString;
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
    CreateEventA, GetCurrentProcess, OpenEventA, ResetEvent, SetEvent, WaitForSingleObject,
    EVENT_MODIFY_STATE, INFINITE,
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

fn unique_name() -> CString {
    named_object::unique_name("vmm-sys-util-evt-")
}

/// Create a manual-reset event under `name` with a creator-only DACL,
/// failing (rather than adopting the impostor) if the name is taken.
fn create_named_event(name: &CString) -> io::Result<HANDLE> {
    let sa = named_object::creator_only_attributes()?;
    // SAFETY: `sa` and `name` are valid for the duration of the call; the
    // return value is checked.
    let handle = unsafe { CreateEventA(&sa, 1, 0, name.as_ptr().cast()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // Nothing between the create and this check can clobber the
    // thread's last-error slot.
    named_object::reject_preexisting(handle)
}

/// A safe wrapper around a named, manual-reset Win32 event object, used as
/// the Windows analog of Linux `eventfd`.
#[derive(Debug)]
pub struct EventFd {
    event: HANDLE,
    nonblock: bool,
    /// The object's name; `None` when the event arrived as a bare handle
    /// ([`FromRawHandle`]) and its name is unknown.
    name: Option<CString>,
}

// SAFETY: a Win32 HANDLE has no thread affinity.
unsafe impl Send for EventFd {}
// SAFETY: `&self` methods only call thread-safe Win32 APIs
// (SetEvent/WaitForSingleObject/ResetEvent).
unsafe impl Sync for EventFd {}

impl EventFd {
    /// Create a new anonymous `EventFd`, backed by a freshly created
    /// manual-reset event object.
    ///
    /// # Arguments
    ///
    /// * `flag`: only [`EFD_NONBLOCK`] has any effect; see the module docs.
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        // SAFETY: all arguments are simple values; the return value is
        // checked for failure.
        let handle = unsafe { CreateEventA(null(), 1, 0, std::ptr::null()) };
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
        // The name was built from (or validated as) a Rust string, so
        // it converts back losslessly.
        self.name.as_ref().and_then(|n| n.to_str().ok())
    }

    /// Open an existing named manual-reset event object created by a peer
    /// process (e.g. via [`EventFd::new_shareable`] there, with the name
    /// communicated out of band).
    ///
    /// # Arguments
    ///
    /// * `name`: the name the creating process minted; must not contain an
    ///   interior NUL byte.
    pub fn open(name: &str) -> result::Result<EventFd, io::Error> {
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `name` is a valid NUL-terminated C string outliving the call.
        let handle =
            unsafe { OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, 0, name.as_ptr().cast()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd {
            event: handle,
            nonblock: false,
            name: Some(name),
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

    /// Wait for the event to become signaled, then reset it.
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

    /// Non-blocking check for a pending signal: resets it if signaled, and
    /// returns `Ok(())` either way — never waits, unlike [`EventFd::read`].
    /// Used by [`crate::event::EventConsumer`], which may run after
    /// [`crate::epoll::Epoll::wait`] has already reset the handle.
    pub(crate) fn try_consume(&self) -> result::Result<(), io::Error> {
        self.wait_for_signal(0).map(|_| ())
    }

    /// Waits up to `timeout_ms` for the event to become signaled, resetting
    /// it if so. Returns `Ok(true)` if signaled (and reset), `Ok(false)` on
    /// timeout.
    fn wait_for_signal(&self, timeout_ms: u32) -> result::Result<bool, io::Error> {
        // SAFETY: `self.event` is valid for the lifetime of `self`.
        let ret = unsafe { WaitForSingleObject(self.event, timeout_ms) };
        if ret == WAIT_OBJECT_0 {
            // Reset only after the wait succeeds: a signal racing this
            // reset just leaves the event signaled again, not lost.
            // SAFETY: `self.event` is valid for the lifetime of `self`.
            let ret = unsafe { ResetEvent(self.event) };
            if ret == 0 {
                return Err(io::Error::last_os_error());
            }
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
        let handle = self.event as RawHandle;
        std::mem::forget(self);
        handle
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
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 1);
    }

    #[test]
    fn test_open_by_name() {
        let name = unique_name().into_string().unwrap();
        // SAFETY: name is a valid C string with no interior NUL.
        let handle = unsafe {
            CreateEventA(
                null(),
                1,
                0,
                CString::new(name.clone()).unwrap().as_ptr().cast(),
            )
        };
        assert!(!handle.is_null());
        // SAFETY: handle was just created successfully above.
        let created = unsafe { EventFd::from_raw_handle(handle as RawHandle) };

        let opened = EventFd::open(&name).unwrap();
        created.write(1).unwrap();
        assert_eq!(opened.read().unwrap(), 1);
    }

    #[test]
    fn test_open_missing() {
        assert!(EventFd::open("vmm-sys-util-evt-does-not-exist").is_err());
    }

    #[test]
    fn a_shareable_eventfd_carries_its_name_for_a_peer_to_open() {
        // The frontend side of a transport creates the event and sends
        // its name; without retention nothing could be transmitted.
        let evt = EventFd::new_shareable(0).unwrap();
        let name = evt.name().expect("a shareable EventFd must know its name");
        assert!(name.starts_with("vmm-sys-util-evt-"));

        let opened = EventFd::open(name).unwrap();
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
    fn a_thousand_eventfd_cycles_leak_no_handles() {
        // Delta over N rather than exact equality: other test threads
        // add background handle noise, but a per-iteration leak adds N.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let e = EventFd::new_shareable(0).unwrap();
            let c = e.try_clone().unwrap();
            let o = EventFd::open(e.name().unwrap()).unwrap();
            drop((e, c, o));
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }
}
