// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Windows analog of Linux [`epoll`](http://man7.org/linux/man-pages/man7/epoll.7.html),
//! backed by an I/O completion port and one persistent threadpool wait per
//! handle.
//!
//! Only [`EventSet::IN`] is supported; [`Epoll::ctl`] rejects any other bit
//! rather than silently ignoring it. Registered handles are expected to be
//! auto-reset events (what [`crate::eventfd::EventFd`] creates): satisfying
//! the wait consumes the signal atomically in the kernel, so each signal is
//! delivered as exactly one wake-up and nothing here ever mutates the
//! handle's state behind the caller's back. Anything running after the
//! wake-up must leave the handle alone — the signal is already consumed,
//! and even a zero-timeout wait could eat the *next* signal before this
//! `Epoll` delivers it ([`crate::event::EventConsumer::consume`] is
//! accordingly a no-op on Windows). A manual-reset event, by contrast,
//! would storm: it stays signaled, and the persistent wait would fire
//! continuously.
//!
//! A registered handle must be removed with [`ControlOperation::Delete`] (or
//! by dropping the `Epoll`) before it's closed — unlike Linux, closing first
//! doesn't implicitly unregister it and leaves a dangling wait registration.

use std::collections::HashMap;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_HANDLE, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    RegisterWaitForSingleObject, SetEvent, UnregisterWaitEx, INFINITE, WT_EXECUTEDEFAULT,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatusEx, PostQueuedCompletionStatus,
    OVERLAPPED_ENTRY,
};

bitflags::bitflags! {
    /// The type of events that can be monitored for a handle.
    ///
    /// Only [`EventSet::IN`] is implemented; [`Epoll::ctl`] rejects any
    /// other bit. The remaining variants exist only for API parity with the
    /// Linux `EventSet` type.
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub struct EventSet: u32 {
        /// The associated handle is signaled. The only variant actually
        /// implemented on Windows.
        const IN = 1 << 0;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const OUT = 1 << 1;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const ERROR = 1 << 2;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const READ_HANG_UP = 1 << 3;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const EDGE_TRIGGERED = 1 << 4;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const HANG_UP = 1 << 5;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const PRIORITY = 1 << 6;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const WAKE_UP = 1 << 7;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const ONE_SHOT = 1 << 8;
        /// Not implemented on Windows; passing this to [`Epoll::ctl`] fails.
        const EXCLUSIVE = 1 << 9;
    }
}

/// Wrapper over the actions that can be performed on a handle registered (or
/// to be registered) with an [`Epoll`] instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOperation {
    /// Add a handle to the interest list.
    Add,
    /// Change the settings associated with a handle already in the interest
    /// list.
    Modify,
    /// Remove a handle from the interest list.
    Delete,
}

/// Wrapper over the event data delivered by [`Epoll::wait`].
#[derive(Debug, Default, Clone, Copy)]
pub struct EpollEvent {
    /// Raw `EventSet` bits. Public since there's no underlying C struct to
    /// deref to, unlike the Linux implementation.
    pub events: u32,
    data: u64,
}

impl EpollEvent {
    /// Create a new `EpollEvent` instance.
    ///
    /// # Arguments
    ///
    /// `events` - contains an event mask; only [`EventSet::IN`] is
    ///   meaningful.
    /// `data` - a user data variable, returned unchanged by [`Epoll::wait`].
    pub fn new(events: EventSet, data: u64) -> Self {
        EpollEvent {
            events: events.bits(),
            data,
        }
    }

    /// Returns the `EventSet` corresponding to `events`.
    ///
    /// # Panics
    ///
    /// Panics if `events` contains bits outside of [`EventSet`].
    pub fn event_set(&self) -> EventSet {
        EventSet::from_bits(self.events).unwrap()
    }

    /// Returns the `data` associated with this event.
    pub fn data(&self) -> u64 {
        self.data
    }
}

struct Registration {
    /// This registration's completion key: monotonically increasing and
    /// never reused, so a completion queued for a since-deleted
    /// registration can never alias a newer one — unlike the context
    /// pointer previously used as the key, which the allocator was free
    /// to hand right back to the next `add`.
    token: usize,
    /// The persistent threadpool wait for this handle; freed by
    /// `UnregisterWaitEx` in `unregister`.
    wait_handle: HANDLE,
    ctx: *mut WaitCallbackCtx,
}

struct WaitCallbackCtx {
    iocp: HANDLE,
    handle: HANDLE,
    token: usize,
}

/// The interest list, under one lock: `by_handle` for `ctl`, and the
/// token-keyed view `data_by_token` for `wait` to resolve completions
/// with a lookup instead of a scan.
#[derive(Default)]
struct Registrations {
    by_handle: HashMap<HANDLE, Registration>,
    data_by_token: HashMap<usize, u64>,
}

// SAFETY: only ever invoked by the Win32 threadpool with the context pointer
// this callback was registered with, which stays valid until unregistered
// (the blocking `UnregisterWaitEx` in `unregister` waits out any in-flight
// invocation).
//
// The registration is persistent and the handle auto-reset: the kernel
// consumed the signal to satisfy the wait, so this callback only relays the
// wake-up to the completion port and never touches the handle's state.
unsafe extern "system" fn wait_callback(param: *mut c_void, _timer_or_wait_fired: bool) {
    // SAFETY: see the function's SAFETY comment.
    let ctx = unsafe { &*(param as *const WaitCallbackCtx) };

    // SAFETY: `ctx.iocp` is valid for as long as this registration is.
    let posted = unsafe { PostQueuedCompletionStatus(ctx.iocp, 0, ctx.token, null_mut()) };
    if posted == 0 {
        // The wake-up couldn't be queued, but the signal was already
        // consumed by the wait. For a transient failure (realistically:
        // resource exhaustion) re-signal so the persistent registration
        // retries instead of dropping the doorbell on the floor. For a
        // dead port (closed handle) the doorbell has no destination left,
        // and re-signaling would just spin wait-satisfy/post-fail forever.
        // SAFETY: reads the thread's last-error slot; `ctx.handle` is
        // valid for as long as this registration is.
        unsafe {
            if GetLastError() != ERROR_INVALID_HANDLE {
                SetEvent(ctx.handle);
            }
        }
    }
}

/// Wrapper over epoll-like functionality, backed by an I/O completion port.
///
/// See the module documentation for the (deliberately narrow) supported
/// feature set.
pub struct Epoll {
    iocp: HANDLE,
    registrations: Mutex<Registrations>,
    next_token: AtomicUsize,
}

impl std::fmt::Debug for Epoll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epoll").field("iocp", &self.iocp).finish()
    }
}

// SAFETY: `iocp` has no thread affinity, and all access to `registrations`
// goes through the `Mutex`.
unsafe impl Send for Epoll {}
// SAFETY: see above; all methods only require `&self` and synchronize
// through the `Mutex` or through Win32 APIs that are themselves thread-safe.
unsafe impl Sync for Epoll {}

/// Validates the raw bits of a caller-supplied [`EpollEvent`] — raw
/// because `events` is a public field, so it can hold bits no `EventSet`
/// variant names, and going through [`EpollEvent::event_set`] here would
/// panic on exactly the input this function exists to reject.
fn validate_event_set(bits: u32) -> io::Result<()> {
    let Some(events) = EventSet::from_bits(bits) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown EventSet bits: {bits:#x}"),
        ));
    };
    if !events.is_empty() && events != EventSet::IN {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Windows Epoll only supports EventSet::IN, got {events:?}"),
        ));
    }
    Ok(())
}

impl Epoll {
    /// Create a new epoll-like instance, backed by a fresh I/O completion
    /// port.
    pub fn new() -> io::Result<Self> {
        // SAFETY: `INVALID_HANDLE_VALUE`/null are the documented arguments
        // for creating a new, unassociated completion port.
        let iocp = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
        if iocp.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Epoll {
            iocp,
            registrations: Mutex::new(Registrations::default()),
            next_token: AtomicUsize::new(0),
        })
    }

    /// Add, modify, or remove a handle in the interest list of this
    /// instance.
    ///
    /// # Arguments
    ///
    /// * `operation` - the action to perform.
    /// * `handle` - a waitable kernel object handle (e.g. an
    ///   [`EventFd`](crate::eventfd::EventFd)); see the module docs for the
    ///   handle-lifetime requirement.
    /// * `event` - only [`EventSet::IN`] (or empty, for
    ///   [`ControlOperation::Delete`]) is accepted.
    pub fn ctl(
        &self,
        operation: ControlOperation,
        handle: RawHandle,
        event: EpollEvent,
    ) -> io::Result<()> {
        validate_event_set(event.events)?;
        let handle = handle as HANDLE;
        match operation {
            ControlOperation::Add => self.add(handle, event),
            ControlOperation::Modify => self.modify(handle, event),
            ControlOperation::Delete => self.delete(handle),
        }
    }

    fn add(&self, handle: HANDLE, event: EpollEvent) -> io::Result<()> {
        debug_assert_auto_reset(handle);
        let mut registrations = self.registrations.lock().unwrap();
        if registrations.by_handle.contains_key(&handle) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }

        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let ctx = Box::into_raw(Box::new(WaitCallbackCtx {
            iocp: self.iocp,
            handle,
            token,
        }));

        let mut wait_handle: HANDLE = null_mut();
        // SAFETY: `handle` is a caller-provided, valid waitable handle that
        // outlives this registration (the caller's responsibility, same as
        // `epoll_ctl` on Linux); `ctx` is freed only after `unregister`
        // confirms no callback can observe it again.
        let ret = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_handle,
                handle,
                Some(wait_callback),
                ctx as *mut c_void,
                INFINITE,
                WT_EXECUTEDEFAULT,
            )
        };
        if ret == 0 {
            // SAFETY: registration failed, so `ctx` was never handed to the
            // threadpool and nothing else can reference it.
            unsafe {
                drop(Box::from_raw(ctx));
            }
            return Err(io::Error::last_os_error());
        }

        registrations.by_handle.insert(
            handle,
            Registration {
                token,
                wait_handle,
                ctx,
            },
        );
        registrations.data_by_token.insert(token, event.data());
        Ok(())
    }

    /// Update a registration's user data in place.
    ///
    /// Deliberately not delete-then-add: retiring the token would silently
    /// drop any completion already queued under it — a consumed kick lost
    /// in the swap window — and there is nothing else to re-register,
    /// since only [`EventSet::IN`] exists. The wait registration and token
    /// stay untouched; only the data a future wake-up reports changes.
    fn modify(&self, handle: HANDLE, event: EpollEvent) -> io::Result<()> {
        let mut registrations = self.registrations.lock().unwrap();
        let token = registrations
            .by_handle
            .get(&handle)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            .token;
        registrations.data_by_token.insert(token, event.data());
        Ok(())
    }

    fn delete(&self, handle: HANDLE) -> io::Result<()> {
        let mut registrations = self.registrations.lock().unwrap();
        let reg = registrations
            .by_handle
            .remove(&handle)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        // A completion for this token may still be queued; `wait` skips
        // keys with no map entry, and the token is never minted again.
        registrations.data_by_token.remove(&reg.token);
        unregister(reg)
    }

    /// Wait for handles in the interest list to become signaled.
    ///
    /// Returns the number of ready events written to the front of `events`,
    /// or an error. Only [`EventSet::IN`] is ever reported.
    ///
    /// # Arguments
    ///
    /// * `timeout` - how long to wait, in milliseconds; `-1` waits
    ///   indefinitely.
    /// * `events` - storage for ready events.
    pub fn wait(&self, timeout: i32, events: &mut [EpollEvent]) -> io::Result<usize> {
        let mut count = 0;
        let mut wait_ms: u32 = if timeout < 0 {
            INFINITE
        } else {
            timeout as u32
        };

        // Dequeue in batches: one syscall and one lock acquisition cover
        // many ready doorbells, instead of one of each per completion.
        const BATCH: usize = 64;

        while count < events.len() {
            let mut entries = [OVERLAPPED_ENTRY::default(); BATCH];
            let want = (events.len() - count).min(BATCH) as u32;
            let mut removed: u32 = 0;
            // SAFETY: `self.iocp` is a valid completion port handle for the
            // lifetime of `self`; `entries` is valid for `want` writes and
            // `removed` is a valid out-pointer for the duration of the call.
            let ret = unsafe {
                GetQueuedCompletionStatusEx(
                    self.iocp,
                    entries.as_mut_ptr(),
                    want,
                    &mut removed,
                    wait_ms,
                    0,
                )
            };
            if ret == 0 {
                let err = io::Error::last_os_error();
                if count > 0 {
                    // Already found events; treat a non-blocking follow-up
                    // miss as "nothing more ready" not an error.
                    break;
                }
                if err.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                    return Ok(0);
                }
                return Err(err);
            }

            // Each key is a registration's token (see wait_callback). A
            // miss means the registration was deleted after the completion
            // was queued; don't report it. Tokens are never reused, so a
            // stale key can't alias a registration added since. The whole
            // batch resolves under one acquisition of the lock.
            let registrations = self.registrations.lock().unwrap();
            for entry in &entries[..removed as usize] {
                if let Some(&data) = registrations.data_by_token.get(&entry.lpCompletionKey) {
                    events[count] = EpollEvent::new(EventSet::IN, data);
                    count += 1;
                }
            }
            drop(registrations);

            // Only the first call blocks; the rest drain whatever is
            // already queued, mirroring epoll_wait returning several ready
            // fds from one call.
            wait_ms = 0;
        }

        Ok(count)
    }
}

impl AsRawHandle for Epoll {
    fn as_raw_handle(&self) -> RawHandle {
        self.iocp as RawHandle
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        let mut registrations = self.registrations.lock().unwrap();
        for (_, reg) in registrations.by_handle.drain() {
            // Can't act on errors in a `Drop` impl; leak on failure rather
            // than panic.
            let _ = unregister(reg);
        }
        registrations.data_by_token.clear();
        // SAFETY: `self.iocp` is owned by this `Epoll`.
        unsafe {
            CloseHandle(self.iocp);
        }
    }
}

/// Debug-build guard for the module's core precondition: a manual-reset
/// event under a persistent wait fires continuously, so catch the
/// misregistration at `ctl()` time instead of as a mystery hot spin.
///
/// `NtQueryEvent` lives in ntdll, which `windows-sys` does not bind; the
/// hand-declared extern is confined to debug builds.
#[cfg(debug_assertions)]
fn debug_assert_auto_reset(handle: HANDLE) {
    const EVENT_BASIC_INFORMATION_CLASS: i32 = 0;
    const SYNCHRONIZATION_EVENT: i32 = 1; // auto-reset; 0 = NotificationEvent

    #[repr(C)]
    struct EventBasicInformation {
        event_type: i32,
        event_state: i32,
    }
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryEvent(
            event_handle: HANDLE,
            event_information_class: i32,
            event_information: *mut c_void,
            event_information_length: u32,
            return_length: *mut u32,
        ) -> i32; // NTSTATUS
    }

    const STATUS_ACCESS_DENIED: i32 = 0xC0000022u32 as i32;

    let mut info = EventBasicInformation {
        event_type: SYNCHRONIZATION_EVENT,
        event_state: 0,
    };
    let mut len = 0u32;
    // SAFETY: `info` is a valid out-buffer of the stated length; the class
    // selects EVENT_BASIC_INFORMATION.
    let status = unsafe {
        NtQueryEvent(
            handle,
            EVENT_BASIC_INFORMATION_CLASS,
            (&mut info as *mut EventBasicInformation).cast(),
            std::mem::size_of::<EventBasicInformation>() as u32,
            &mut len,
        )
    };
    // ACCESS_DENIED means the handle IS an event but lacks
    // EVENT_QUERY_STATE (the type check precedes the access check, so
    // other waitables fail with STATUS_OBJECT_TYPE_MISMATCH instead).
    // Passing it through silently would leave this guard inert on
    // peer-handed doorbells — the production path it exists for — so an
    // unverifiable event is loud too. A peer duplicating a doorbell in with
    // DUPLICATE_SAME_ACCESS carries the right along.
    debug_assert!(
        status != STATUS_ACCESS_DENIED,
        "Epoll cannot verify this event's reset mode: the handle lacks \
         EVENT_QUERY_STATE; it must be granted when the handle is created \
         or duplicated"
    );
    // Any other failed query means the handle is some other waitable
    // (semaphore, process, ...), which is allowed; only a confirmed
    // manual-reset event is a misuse of this Epoll.
    debug_assert!(
        status != 0 || info.event_type == SYNCHRONIZATION_EVENT,
        "Epoll requires auto-reset events; a manual-reset event stays \
         signaled and would fire its persistent wait continuously"
    );
}

#[cfg(not(debug_assertions))]
fn debug_assert_auto_reset(_handle: HANDLE) {}

fn unregister(reg: Registration) -> io::Result<()> {
    // The blocking form of `UnregisterWaitEx` cancels the persistent wait
    // and waits until any in-flight callback returns, so after it nothing
    // can reference `reg.ctx`.
    // SAFETY: `reg.wait_handle` was produced by RegisterWaitForSingleObject
    // and is unregistered exactly once (the Registration is owned here).
    let ret = unsafe { UnregisterWaitEx(reg.wait_handle, INVALID_HANDLE_VALUE) };
    let result = if ret == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    // SAFETY: see the comment above; on failure we still own the Box and
    // leaking the wait registration is the kernel's problem, not a reason
    // to leak the context too.
    unsafe {
        drop(Box::from_raw(reg.ctx));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventConsumer;
    use crate::eventfd::EventFd;
    use std::os::windows::io::{FromRawHandle, IntoRawHandle};

    #[test]
    fn test_consume_after_epoll_wait_does_not_deadlock() {
        // Regression test for the vhost-user-backend kick pattern: signal,
        // Epoll::wait (whose wait registration consumes the auto-reset
        // signal), then consume via an EventConsumer built from the same
        // handle. Must not block.
        const TIMEOUT: i32 = 5000;

        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        let consumer_handle = event_fd.try_clone().unwrap().into_raw_handle();
        // SAFETY: `consumer_handle` was just obtained from `into_raw_handle`
        // and has not been closed.
        let consumer = unsafe { EventConsumer::from_raw_handle(consumer_handle) };

        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();

        event_fd.write(1).unwrap();

        let mut ready = [EpollEvent::default(); 8];
        let count = epoll.wait(TIMEOUT, &mut ready[..]).unwrap();
        assert_eq!(count, 1);

        // The regression: this used to hang forever.
        consumer.consume().unwrap();

        // Delete before `event_fd` drops (and closes its handle) — see the
        // module docs' handle-lifetime requirement.
        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();
    }

    #[test]
    fn test_event_ops() {
        let mut event = EpollEvent::default();
        assert_eq!(event.events, 0);
        assert_eq!(event.data(), 0);

        event = EpollEvent::new(EventSet::IN, 2);
        assert_eq!(event.events, 1);
        assert_eq!(event.event_set(), EventSet::IN);
        assert_eq!(event.data(), 2);
    }

    #[test]
    fn ctl_returns_an_error_for_unknown_bits_instead_of_panicking() {
        // `events` is a public u32, so callers can hand ctl() bits no
        // EventSet variant names; that used to panic inside validation.
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        let mut event = EpollEvent::new(EventSet::IN, 0);
        event.events = 1 << 30;
        let err = epoll
            .ctl(ControlOperation::Add, event_fd.as_raw_handle(), event)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_ctl_rejects_unsupported_events() {
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        let err = epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::OUT, 0),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_epoll_add_signal_wait() {
        const TIMEOUT: i32 = 5000;

        let epoll = Epoll::new().unwrap();
        let event_fd_1 = EventFd::new(0).unwrap();
        let event_fd_2 = EventFd::new(0).unwrap();

        epoll
            .ctl(
                ControlOperation::Add,
                event_fd_1.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd_2.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 2),
            )
            .unwrap();

        // Adding the same handle twice fails.
        assert!(epoll
            .ctl(
                ControlOperation::Add,
                event_fd_1.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 1),
            )
            .is_err());

        event_fd_1.write(1).unwrap();

        let mut ready = [EpollEvent::default(); 8];
        let count = epoll.wait(TIMEOUT, &mut ready[..]).unwrap();
        assert_eq!(count, 1);
        assert_eq!(ready[0].data(), 1);

        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd_1.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();
        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd_2.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();

        // Deleting a handle that's not registered fails.
        assert!(epoll
            .ctl(
                ControlOperation::Delete,
                event_fd_2.as_raw_handle(),
                EpollEvent::default(),
            )
            .is_err());
    }

    #[test]
    #[should_panic(expected = "auto-reset")]
    fn registering_a_manual_reset_event_is_caught_in_debug_builds() {
        // The module's core precondition, enforced at ctl() time: a
        // manual-reset event under a persistent wait would hot-spin.
        use windows_sys::Win32::System::Threading::CreateEventW;
        // SAFETY: plain create; checked before use.
        let manual = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        assert!(!manual.is_null());
        let epoll = Epoll::new().unwrap();
        let _ = epoll.ctl(
            ControlOperation::Add,
            manual as RawHandle,
            EpollEvent::new(EventSet::IN, 0),
        );
    }

    #[test]
    #[should_panic(expected = "EVENT_QUERY_STATE")]
    fn an_event_opened_without_query_rights_is_loud_not_silently_unverified() {
        // Empirically pins the NtQueryEvent access requirement (it's
        // undocumented): without EVENT_QUERY_STATE the query fails with
        // ACCESS_DENIED, and the guard must refuse to pass that through —
        // otherwise it is inert on exactly the peer-handed production path.
        use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::{
            CreateEventW, GetCurrentProcess, EVENT_MODIFY_STATE,
        };
        // SAFETY: simple arguments; checked before use. Auto-reset, so only
        // the rights — not the mode — can trip the guard.
        let created = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        assert!(!created.is_null());
        // A peer that narrowed the access it duplicated in. Access masks are
        // not a boundary between processes, but a peer may still hand over
        // less than the guard needs.
        let mut narrow: HANDLE = std::ptr::null_mut();
        // SAFETY: `created` is live; `narrow` is a valid out-pointer.
        let ok = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                created,
                process,
                &mut narrow,
                EVENT_MODIFY_STATE | SYNCHRONIZE,
                0,
                0,
            )
        };
        assert!(ok != 0);

        let epoll = Epoll::new().unwrap();
        let _ = epoll.ctl(
            ControlOperation::Add,
            narrow as RawHandle,
            EpollEvent::new(EventSet::IN, 0),
        );
    }

    #[test]
    #[should_panic(expected = "auto-reset")]
    fn a_peer_opened_manual_reset_event_is_caught_in_debug_builds() {
        // The end-to-end production shape: a peer mints a manual-reset
        // event (contract violation) and duplicates it in; this side adopts
        // the handle and registration must panic rather than wait on an
        // event whose signal it cannot consume.
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
        use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};
        // SAFETY: simple arguments; checked before use. Manual-reset on purpose.
        let created = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        assert!(!created.is_null());

        let mut dup: HANDLE = std::ptr::null_mut();
        // SAFETY: `created` is live; `dup` is a valid out-pointer.
        let ok = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                created,
                process,
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        assert!(ok != 0);
        // SAFETY: `dup` was just created and is owned by nothing else.
        let opened = unsafe { EventFd::from_raw_handle(dup as RawHandle) };
        let epoll = Epoll::new().unwrap();
        let _ = epoll.ctl(
            ControlOperation::Add,
            opened.as_raw_handle(),
            EpollEvent::new(EventSet::IN, 0),
        );
    }

    #[test]
    fn a_restricted_rights_semaphore_is_still_registrable() {
        // Pins the second undocumented kernel behavior the debug guard
        // rests on: the object TYPE check precedes the ACCESS check, so a
        // non-event waitable held with restricted rights fails NtQueryEvent
        // with STATUS_OBJECT_TYPE_MISMATCH (allowed) rather than
        // STATUS_ACCESS_DENIED (loud). If the ordering were the other way,
        // this registration would panic in debug builds.
        use windows_sys::Win32::Foundation::DuplicateHandle;
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::{
            CreateSemaphoreA, GetCurrentProcess, SEMAPHORE_MODIFY_STATE,
        };
        // SAFETY: plain create (count 0 = unsignaled); checked before use.
        let sem = unsafe { CreateSemaphoreA(std::ptr::null(), 0, 1, std::ptr::null()) };
        assert!(!sem.is_null());
        // Narrow the rights the way a peer-opened handle would be narrowed.
        let mut narrow: HANDLE = null_mut();
        // SAFETY: valid source handle and pseudo process handles; `narrow`
        // is a valid out-pointer. Explicit mask, not DUPLICATE_SAME_ACCESS.
        let ok = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                sem,
                process,
                &mut narrow,
                SEMAPHORE_MODIFY_STATE | SYNCHRONIZE,
                0,
                0,
            )
        };
        assert_ne!(ok, 0);

        let epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                narrow as RawHandle,
                EpollEvent::new(EventSet::IN, 0),
            )
            .expect("a restricted-rights non-event waitable must register");
        epoll
            .ctl(
                ControlOperation::Delete,
                narrow as RawHandle,
                EpollEvent::default(),
            )
            .unwrap();
    }

    #[test]
    fn a_stale_completion_key_is_skipped_not_misdelivered() {
        // Simulates the queued-completion-for-a-deleted-registration case
        // deterministically: post a key no live registration owns straight
        // to the port. wait() must skip it and still deliver the real
        // event — and since tokens are never reused, a stale key can't
        // alias a registration added later (the ABA the pointer key had).
        use windows_sys::Win32::System::IO::PostQueuedCompletionStatus;

        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 7),
            )
            .unwrap();

        // SAFETY: the epoll's port handle is valid; the key is a token
        // that was never minted.
        let posted = unsafe {
            PostQueuedCompletionStatus(epoll.as_raw_handle() as HANDLE, 0, usize::MAX, null_mut())
        };
        assert_ne!(posted, 0);
        event_fd.write(1).unwrap();

        let mut ready = [EpollEvent::default(); 8];
        let mut total = 0;
        while total == 0 {
            total = epoll.wait(5000, &mut ready[..]).unwrap();
        }
        assert_eq!(total, 1);
        assert_eq!(ready[0].data(), 7);
        // Nothing further: the stale key produced no event.
        assert_eq!(epoll.wait(100, &mut ready[..]).unwrap(), 0);

        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();
    }

    #[test]
    fn each_signal_delivers_exactly_one_wakeup_and_no_storm() {
        // Two writes: exactly two wake-ups, then silence. A manual-reset
        // event under a persistent wait would storm (stay signaled and
        // fire continuously); a lost signal would deliver fewer.
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 9),
            )
            .unwrap();

        event_fd.write(1).unwrap();
        event_fd.write(1).unwrap();

        let mut ready = [EpollEvent::default(); 8];
        let mut total = 0;
        while total < 2 {
            let n = epoll.wait(5000, &mut ready[..]).unwrap();
            assert_ne!(n, 0, "wake-up lost: got {total} of 2");
            total += n;
        }
        assert_eq!(total, 2);
        // Silence afterwards: nothing left signaled, nothing re-firing.
        assert_eq!(epoll.wait(100, &mut ready[..]).unwrap(), 0);

        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();
    }

    #[test]
    fn modify_does_not_drop_a_queued_completion() {
        // Modify used to be delete-then-add, which retired the token: a
        // kick already consumed and queued under it was silently dropped.
        // In-place modify keeps the token, so the queued wake-up arrives —
        // reporting the new data, whichever side of the modify the post
        // landed on.
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 7),
            )
            .unwrap();

        event_fd.write(1).unwrap();
        epoll
            .ctl(
                ControlOperation::Modify,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 42),
            )
            .unwrap();

        let mut ready = [EpollEvent::default(); 8];
        let mut total = 0;
        while total == 0 {
            total = epoll.wait(5000, &mut ready[..]).unwrap();
        }
        assert_eq!(total, 1);
        assert_eq!(ready[0].data(), 42);

        // Modify on an unregistered handle reports NotFound.
        let stranger = EventFd::new(0).unwrap();
        let err = epoll
            .ctl(
                ControlOperation::Modify,
                stranger.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();
    }

    #[test]
    fn a_batch_of_ready_doorbells_is_delivered_together() {
        // Exercises the GetQueuedCompletionStatusEx path with many distinct
        // registrations ready at once: all signals must arrive, each with
        // its own data, across however many wait calls the timing needs.
        const N: u64 = 8;
        let epoll = Epoll::new().unwrap();
        let fds: Vec<EventFd> = (0..N).map(|_| EventFd::new(0).unwrap()).collect();
        for (i, fd) in fds.iter().enumerate() {
            epoll
                .ctl(
                    ControlOperation::Add,
                    fd.as_raw_handle(),
                    EpollEvent::new(EventSet::IN, i as u64),
                )
                .unwrap();
        }
        for fd in &fds {
            fd.write(1).unwrap();
        }

        let mut seen = std::collections::HashSet::new();
        let mut ready = [EpollEvent::default(); 16];
        while seen.len() < N as usize {
            let n = epoll.wait(5000, &mut ready[..]).unwrap();
            assert_ne!(n, 0, "doorbell lost: got {} of {N}", seen.len());
            for ev in &ready[..n] {
                assert!(
                    seen.insert(ev.data()),
                    "duplicate wake-up for {}",
                    ev.data()
                );
            }
        }
        assert_eq!(seen, (0..N).collect());

        for fd in &fds {
            epoll
                .ctl(
                    ControlOperation::Delete,
                    fd.as_raw_handle(),
                    EpollEvent::default(),
                )
                .unwrap();
        }
    }

    #[test]
    fn test_epoll_wait_timeout() {
        let epoll = Epoll::new().unwrap();
        let mut ready = [EpollEvent::default(); 8];
        let count = epoll.wait(50, &mut ready[..]).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_epoll_modify() {
        const TIMEOUT: i32 = 5000;

        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();
        epoll
            .ctl(
                ControlOperation::Modify,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 42),
            )
            .unwrap();

        event_fd.write(1).unwrap();
        let mut ready = [EpollEvent::default(); 8];
        let count = epoll.wait(TIMEOUT, &mut ready[..]).unwrap();
        assert_eq!(count, 1);
        assert_eq!(ready[0].data(), 42);

        // See the comment in `test_consume_after_epoll_wait_does_not_deadlock`:
        // must delete before `event_fd` drops.
        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd.as_raw_handle(),
                EpollEvent::default(),
            )
            .unwrap();
    }

    #[test]
    fn a_thousand_fire_cycles_leak_no_handles() {
        // The registration is persistent, so N fires must not create (or
        // leak) N of anything: no wait-handle churn, no context churn.
        // Delta over N, not exact equality: other test threads add handle noise.
        const N: u32 = 1000;
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 7),
            )
            .unwrap();

        let mut events = [EpollEvent::default(); 4];
        // Warm-up so lazily created threadpool machinery is not counted.
        event_fd.write(1).unwrap();
        while epoll.wait(1000, &mut events).unwrap() == 0 {}

        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            event_fd.write(1).unwrap();
            while epoll.wait(1000, &mut events).unwrap() == 0 {}
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {} to {} over {} fire cycles",
            before,
            after,
            N
        );
    }

    #[test]
    fn a_thousand_registration_cycles_leak_no_handles() {
        // A leak in the Box round-trip or the wait handle shows up as +N here.
        // Delta over N, not exact equality: other test threads add handle noise.
        const N: u32 = 1000;
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(0).unwrap();
        let before = crate::windows::process_handle_count();
        for i in 0..N {
            epoll
                .ctl(
                    ControlOperation::Add,
                    event_fd.as_raw_handle(),
                    EpollEvent::new(EventSet::IN, i as u64),
                )
                .unwrap();
            epoll
                .ctl(
                    ControlOperation::Delete,
                    event_fd.as_raw_handle(),
                    EpollEvent::new(EventSet::empty(), 0),
                )
                .unwrap();
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }
}
