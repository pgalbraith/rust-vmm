// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A Windows analog of Linux [`eventfd`](http://man7.org/linux/man-pages/man2/eventfd.2.html),
//! backed by a manual-reset Win32 event object.
//!
//! Unlike Linux eventfd, a Win32 event carries no counter: it is either
//! signaled or not. [`EventFd::write`] and [`EventFd::read`] therefore do
//! **not** implement eventfd's add/drain counter semantics (no accumulation,
//! no overflow blocking) — they only signal and wait. This is sufficient for
//! doorbell/notification use (kick, call, wake-up), which is the only way
//! this type is used across rust-vmm.
//!
//! An `EventFd` can be shared with another process by name: [`EventFd::new`]
//! mints a process-unique name that a peer can open with [`EventFd::open`],
//! provided the name is communicated out of band (e.g. over a control
//! socket). The name itself carries no meaning to the peer beyond being a
//! valid argument to `OpenEventA`.

use std::ffi::CString;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
use std::process;
use std::ptr::null_mut;
use std::result;
use std::sync::atomic::{AtomicU32, Ordering};

use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::synchapi::{CreateEventA, OpenEventA, ResetEvent, SetEvent, WaitForSingleObject};
use winapi::um::winbase::{INFINITE, WAIT_FAILED, WAIT_OBJECT_0};
use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, EVENT_MODIFY_STATE, HANDLE, SYNCHRONIZE};

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
    /// Create a new `EventFd`, backed by a freshly created, uniquely named
    /// manual-reset event object.
    ///
    /// # Arguments
    ///
    /// * `flag`: only [`EFD_NONBLOCK`] has any effect; see the module docs.
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        let name = unique_name();
        // SAFETY: `name` is a valid, NUL-terminated C string that outlives
        // the call; all other arguments are simple values. We check the
        // return value for failure.
        let handle = unsafe { CreateEventA(null_mut(), 1, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd {
            event: handle,
            nonblock: flag & EFD_NONBLOCK != 0,
        })
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
        let handle = unsafe { OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd {
            event: handle,
            nonblock: false,
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
        // SAFETY: `self.event` is a valid handle for the lifetime of `self`.
        let ret = unsafe { WaitForSingleObject(self.event, timeout) };
        if ret == WAIT_OBJECT_0 {
            // Reset only after a successful wait: a signal racing this
            // reset simply leaves the event (re-)signaled rather than being
            // lost, since we have not yet observed that later signal.
            //
            // SAFETY: `self.event` is a valid handle for the lifetime of
            // `self`.
            let ret = unsafe { ResetEvent(self.event) };
            if ret == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(1)
        } else if ret == WAIT_TIMEOUT {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
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
                null_mut(),
                1,
                0,
                CString::new(name.clone()).unwrap().as_ptr(),
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
}
