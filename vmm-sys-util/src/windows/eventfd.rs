// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A Windows analog of Linux [`eventfd`](http://man7.org/linux/man-pages/man2/eventfd.2.html),
//! backed by a manual-reset Win32 event object.
//!
//! Unlike Linux eventfd there is no counter: [`EventFd::write`]/[`EventFd::read`]
//! only signal and wait, which is sufficient for doorbell use (kick, call,
//! wake-up) — the only way this type is used across rust-vmm.
//!
//! [`EventFd::new`] creates an anonymous event. An event meant for another
//! process is created with [`EventFd::new_shareable`] instead, which mints a
//! process-unique name the peer can [`open`](EventFd::open) once it is passed
//! out of band (e.g. over a control socket). The split exists because a Win32
//! object's name can only be given at creation — there is no naming an event
//! after the fact — and most events (wakeups, internal doorbells) never cross
//! a process boundary, so naming them all would only pollute the session's
//! object namespace.

use std::ffi::CString;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
use std::process;
use std::ptr::{null, null_mut};
use std::result;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    CreateEventA, GetCurrentProcess, OpenEventA, ResetEvent, SetEvent, WaitForSingleObject,
    EVENT_MODIFY_STATE, INFINITE,
};

// Reexported so callers can write `#[cfg]`-free code across platforms; only
// `EFD_NONBLOCK` has any effect here. `EFD_SEMAPHORE` and `EFD_CLOEXEC` have
// no Win32 equivalent and are silently ignored.
/// Flag mirroring Linux's `EFD_NONBLOCK`, honored by [`EventFd`].
pub const EFD_NONBLOCK: i32 = 1 << 0;
/// Flag mirroring Linux's `EFD_CLOEXEC`; has no effect on Windows.
pub const EFD_CLOEXEC: i32 = 1 << 1;
/// Flag mirroring Linux's `EFD_SEMAPHORE`; has no effect on Windows (there is
/// no counter to decrement one unit at a time).
pub const EFD_SEMAPHORE: i32 = 1 << 2;

static NEXT_ID: AtomicU32 = AtomicU32::new(0);

fn unique_name() -> CString {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the formatted string contains no interior NUL byte.
    CString::new(format!("vmm-sys-util-evt-{}-{}", process::id(), id)).unwrap()
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

// SAFETY: a Win32 HANDLE has no thread affinity; it is safe to use from any
// thread as long as accesses are synchronized, which the Win32 API itself
// guarantees for the operations this type performs.
unsafe impl Send for EventFd {}
// SAFETY: all methods either take `&self` and only call thread-safe Win32
// APIs (`SetEvent`/`WaitForSingleObject`/`ResetEvent`), or require exclusive
// access via Rust's own borrow checking.
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

    /// Create a new `EventFd` under a freshly minted, process-unique name,
    /// for handing to another process (see the module docs).
    ///
    /// # Arguments
    ///
    /// * `flag`: only [`EFD_NONBLOCK`] has any effect; see the module docs.
    pub fn new_shareable(flag: i32) -> result::Result<EventFd, io::Error> {
        let name = unique_name();
        // SAFETY: `name` is a valid, NUL-terminated C string that outlives
        // the call; all other arguments are simple values. We check the
        // return value for failure.
        let handle = unsafe { CreateEventA(null(), 1, 0, name.as_ptr().cast()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
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
    /// process (e.g. via [`EventFd::new`] there, with the name communicated
    /// out of band).
    ///
    /// # Arguments
    ///
    /// * `name`: the name the creating process minted; must not contain an
    ///   interior NUL byte.
    pub fn open(name: &str) -> result::Result<EventFd, io::Error> {
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `name` is a valid, NUL-terminated C string that outlives
        // the call. We check the return value for failure.
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
        // SAFETY: `self.event` is a valid handle for the lifetime of `self`.
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
    /// returns `Ok(())` either way — never waits, unlike [`EventFd::read`],
    /// and ignores [`EFD_NONBLOCK`]. Used by [`crate::event::EventConsumer`],
    /// which may be called after [`crate::epoll::Epoll::wait`] has already
    /// reset the handle.
    pub(crate) fn try_consume(&self) -> result::Result<(), io::Error> {
        self.wait_for_signal(0).map(|_| ())
    }

    /// Waits (for up to `timeout_ms`) for the event to become signaled, and
    /// if it does, resets it. Returns `Ok(true)` if the event was observed
    /// signaled (and has now been reset), `Ok(false)` on a timeout.
    fn wait_for_signal(&self, timeout_ms: u32) -> result::Result<bool, io::Error> {
        // SAFETY: `self.event` is a valid handle for the lifetime of `self`.
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
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle valid for the
        // lifetime of the process; `self.event` is a valid handle for the
        // lifetime of `self`; `new_handle` is a valid out-pointer.
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
        // SAFETY: `self.event` is a valid handle owned by this `EventFd`.
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
}
