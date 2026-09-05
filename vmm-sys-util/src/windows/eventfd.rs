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
//! is mode-agnostic.
//!
//! Every event created here is anonymous. An event that has to cross a
//! process boundary is not shared by name: the owning process duplicates
//! its handle into the peer with `DuplicateHandle`, and the peer adopts
//! the result with [`FromRawHandle`]. An unnamed object is reachable only
//! by a process that was deliberately handed a handle to it.

use std::io;
use std::os::windows::io::{
    AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, RawHandle,
};
use std::ptr::{null, null_mut};
use std::result;

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, SetEvent, WaitForSingleObject, INFINITE,
};

// Reexported for #[cfg]-free callers. Only EFD_NONBLOCK has any effect;
// EFD_SEMAPHORE/EFD_CLOEXEC have no Win32 equivalent and are ignored.
/// Mirrors Linux's `EFD_NONBLOCK`, honored by [`EventFd`].
pub const EFD_NONBLOCK: i32 = 1 << 0;
/// Mirrors Linux's `EFD_CLOEXEC`; no effect on Windows.
pub const EFD_CLOEXEC: i32 = 1 << 1;
/// Mirrors Linux's `EFD_SEMAPHORE`; no effect on Windows (no counter).
pub const EFD_SEMAPHORE: i32 = 1 << 2;

/// A safe wrapper around an auto-reset Win32 event object, used as the
/// Windows analog of Linux `eventfd`.
#[derive(Debug)]
pub struct EventFd {
    event: HANDLE,
    nonblock: bool,
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
    /// To hand the event to another process, duplicate its handle into
    /// that process; see the module docs.
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
        })
    }
}

impl AsRawHandle for EventFd {
    fn as_raw_handle(&self) -> RawHandle {
        self.event as RawHandle
    }
}

impl AsHandle for EventFd {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: `self.event` is open for as long as `self` is, which is
        // the lifetime the borrow carries.
        unsafe { BorrowedHandle::borrow_raw(self.event as RawHandle) }
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
        }
    }
}

impl IntoRawHandle for EventFd {
    fn into_raw_handle(self) -> RawHandle {
        // Suppress `Drop`, which would close the handle the caller is
        // taking ownership of. Nothing else in the struct owns memory.
        let this = std::mem::ManuallyDrop::new(self);
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

    /// Stand in for a peer receiving this event: duplicate the handle the
    /// way an owning process hands one over, and adopt the result.
    fn duplicate_to_peer(evt: &EventFd) -> EventFd {
        let mut dup: HANDLE = null_mut();
        // SAFETY: both process handles are the current-process pseudo
        // handle, `evt` is live, and `dup` is a valid out-pointer.
        let ok = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                evt.as_raw_handle() as HANDLE,
                process,
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        assert!(ok != 0, "{}", io::Error::last_os_error());
        // SAFETY: `dup` was just created and is owned by nothing else.
        unsafe { EventFd::from_raw_handle(dup as RawHandle) }
    }

    #[test]
    fn a_duplicated_eventfd_is_the_same_event() {
        // How an event crosses a process boundary now: the owner
        // duplicates its handle in, and signals reach the peer's copy.
        let evt = EventFd::new(0).unwrap();
        let peer = duplicate_to_peer(&evt);

        evt.write(1).unwrap();
        assert_eq!(peer.read().unwrap(), 1);
    }

    #[test]
    fn an_adopted_eventfd_can_be_polled() {
        // Regression: a doorbell adopted from a peer must be pollable
        // without hanging when unsignaled.
        let evt = EventFd::new(0).unwrap();
        let mut peer = duplicate_to_peer(&evt);
        peer.nonblock = true;

        assert_eq!(peer.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        evt.write(1).unwrap();
        assert_eq!(peer.read().unwrap(), 1);
    }

    #[test]
    fn a_thousand_eventfd_cycles_leak_no_handles() {
        // Delta over N rather than exact equality: other test threads
        // add background handle noise, but a per-iteration leak adds N.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let e = EventFd::new(0).unwrap();
            let c = e.try_clone().unwrap();
            let d = duplicate_to_peer(&e);
            drop((e, c, d));
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }

    #[test]
    fn a_thousand_into_raw_handle_cycles_leak_no_handles() {
        // into_raw_handle must suppress Drop without closing the handle
        // it hands over: the caller closes it exactly once.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let h = EventFd::new(0).unwrap().into_raw_handle();
            // SAFETY: `h` came from into_raw_handle and is closed once.
            unsafe { CloseHandle(h as HANDLE) };
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }
}
