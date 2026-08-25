// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A Windows analog of Linux [`epoll`](http://man7.org/linux/man-pages/man7/epoll.7.html),
//! backed by an I/O completion port and one threadpool wait per handle.
//!
//! Only [`EventSet::IN`] is supported; [`Epoll::ctl`] rejects any other bit
//! rather than silently ignoring it. [`Epoll::wait`] resets a handle's event
//! as part of delivering its wake-up, so a consumer (e.g.
//! [`crate::event::EventConsumer::consume`]) must not block on it again.
//!
//! A registered handle must be removed with [`ControlOperation::Delete`] (or
//! by dropping the `Epoll`) before it is closed — unlike Linux, closing the
//! handle first does not implicitly unregister it, and leaves a dangling
//! wait registration.

use std::collections::HashMap;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    RegisterWaitForSingleObject, ResetEvent, UnregisterWaitEx, INFINITE, WT_EXECUTEONLYONCE,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus, OVERLAPPED,
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
    /// Raw `EventSet` bits. Public (rather than accessed through a Deref
    /// target, as on the Linux implementation) since there is no underlying
    /// C struct to deref to; call sites that read `event.events` work
    /// unchanged.
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
    ctx: *mut WaitCallbackCtx,
}

struct WaitCallbackCtx {
    iocp: HANDLE,
    handle: HANDLE,
    data: u64,
    // Current WT_EXECUTEONLYONCE registration for `handle`; re-armed by
    // `wait_callback` after each fire (see its comment).
    wait_handle: AtomicPtr<c_void>,
}

// SAFETY: only ever invoked by the Win32 threadpool with the context pointer
// this callback was registered with, which stays valid until unregistered.
//
// Deliberately does NOT re-arm the wait: a spent WT_EXECUTEONLYONCE
// registration still holds a wait handle that only UnregisterWaitEx can
// free, and a callback cannot safely unregister itself with the blocking
// form. Re-arming (and reaping the spent registration) happens in
// [`Epoll::wait`] when the completion is consumed -- a callback that
// re-registered and abandoned its spent handle leaked one handle per
// delivered event, found live as a daemon leaking one handle per FUSE
// request. The completion key is the context pointer, so `wait` can find
// the registration to re-arm (and skip completions whose registration was
// deleted before they were consumed).
unsafe extern "system" fn wait_callback(param: *mut c_void, _timer_or_wait_fired: bool) {
    // SAFETY: see the function's SAFETY comment.
    let ctx = unsafe { &*(param as *const WaitCallbackCtx) };

    // Reset before posting: a manual-reset event left signaled would just
    // retrigger the callback the moment `wait` re-arms it.
    // SAFETY: `ctx.handle` is valid for as long as this registration is.
    unsafe {
        ResetEvent(ctx.handle);
    }
    // SAFETY: `ctx.iocp` is valid for as long as this registration is.
    unsafe {
        PostQueuedCompletionStatus(ctx.iocp, 0, param as usize, null_mut());
    }
}

/// Wrapper over epoll-like functionality, backed by an I/O completion port.
///
/// See the module documentation for the (deliberately narrow) supported
/// feature set.
pub struct Epoll {
    iocp: HANDLE,
    registrations: Mutex<HashMap<HANDLE, Registration>>,
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

fn validate_event_set(events: EventSet) -> io::Result<()> {
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
        // for creating a new, unassociated completion port. The return
        // value is checked for failure.
        let iocp = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
        if iocp.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Epoll {
            iocp,
            registrations: Mutex::new(HashMap::new()),
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
    /// * `event` - the associated event; only [`EventSet::IN`] (or empty,
    ///   for [`ControlOperation::Delete`]) is accepted.
    pub fn ctl(
        &self,
        operation: ControlOperation,
        handle: RawHandle,
        event: EpollEvent,
    ) -> io::Result<()> {
        validate_event_set(event.event_set())?;
        let handle = handle as HANDLE;
        match operation {
            ControlOperation::Add => self.add(handle, event),
            ControlOperation::Modify => {
                self.delete(handle)?;
                self.add(handle, event)
            }
            ControlOperation::Delete => self.delete(handle),
        }
    }

    fn add(&self, handle: HANDLE, event: EpollEvent) -> io::Result<()> {
        let mut registrations = self.registrations.lock().unwrap();
        if registrations.contains_key(&handle) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }

        let ctx = Box::into_raw(Box::new(WaitCallbackCtx {
            iocp: self.iocp,
            handle,
            data: event.data(),
            wait_handle: AtomicPtr::new(null_mut()),
        }));

        let mut wait_handle: HANDLE = null_mut();
        // SAFETY: `handle` is a caller-provided, valid waitable kernel
        // object handle that outlives this registration (the caller's
        // responsibility, same as `epoll_ctl` on Linux); `ctx` was just
        // allocated and is freed only after `unregister` confirms no
        // callback can observe it again.
        let ret = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_handle,
                handle,
                Some(wait_callback),
                ctx as *mut c_void,
                INFINITE,
                WT_EXECUTEONLYONCE,
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
        // SAFETY: `ctx` is freshly allocated above and not yet reachable
        // from any callback until the store below completes.
        unsafe {
            (*ctx).wait_handle.store(wait_handle, Ordering::Release);
        }

        registrations.insert(handle, Registration { ctx });
        Ok(())
    }

    fn delete(&self, handle: HANDLE) -> io::Result<()> {
        let mut registrations = self.registrations.lock().unwrap();
        let reg = registrations
            .remove(&handle)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
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

        while count < events.len() {
            let mut bytes_transferred: u32 = 0;
            let mut completion_key: usize = 0;
            let mut overlapped: *mut OVERLAPPED = null_mut();
            // SAFETY: `self.iocp` is a valid completion port handle for the
            // lifetime of `self`; the out-parameters are valid for the
            // duration of the call.
            let ret = unsafe {
                GetQueuedCompletionStatus(
                    self.iocp,
                    &mut bytes_transferred,
                    &mut completion_key,
                    &mut overlapped,
                    wait_ms,
                )
            };
            if ret == 0 {
                let err = io::Error::last_os_error();
                if count > 0 {
                    // The blocking wait already found at least one event;
                    // treat a non-blocking follow-up miss as "no more ready
                    // right now" rather than an error.
                    break;
                }
                if err.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                    return Ok(0);
                }
                return Err(err);
            }

            // The key is the registration's context pointer (see
            // wait_callback). Find it among the live registrations: a miss
            // means the registration was deleted after the completion was
            // queued, and a deleted handle must not be reported.
            let registrations = self.registrations.lock().unwrap();
            let Some(reg) = registrations
                .values()
                .find(|reg| reg.ctx as usize == completion_key)
            else {
                drop(registrations);
                wait_ms = 0;
                continue;
            };
            // SAFETY: the registration is in the map, so `ctx` is alive.
            let ctx = unsafe { &*reg.ctx };
            let data = ctx.data;

            // Reap the spent wait registration and re-arm. Safe to block
            // here: this is not a callback thread, and the callback that
            // posted this completion finished before posting it.
            let spent = ctx.wait_handle.swap(null_mut(), Ordering::AcqRel);
            if !spent.is_null() {
                // SAFETY: `spent` was atomically claimed above.
                unsafe {
                    UnregisterWaitEx(spent as HANDLE, INVALID_HANDLE_VALUE);
                }
            }
            let mut new_wait_handle: HANDLE = null_mut();
            // SAFETY: `ctx.handle` outlives its registration (the caller's
            // contract, as on Linux), and `reg.ctx` is alive as above.
            let ret = unsafe {
                RegisterWaitForSingleObject(
                    &mut new_wait_handle,
                    ctx.handle,
                    Some(wait_callback),
                    reg.ctx as *mut c_void,
                    INFINITE,
                    WT_EXECUTEONLYONCE,
                )
            };
            if ret != 0 {
                ctx.wait_handle.store(new_wait_handle, Ordering::Release);
            }
            // On failure the handle stops being watched; the event itself
            // is still delivered below.
            drop(registrations);

            events[count] = EpollEvent::new(EventSet::IN, data);
            count += 1;
            // Only the first call should block; further calls just drain
            // whatever is already queued, mirroring epoll_wait's ability to
            // return several ready fds from one call.
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
        for (_, reg) in registrations.drain() {
            // Errors here can't be acted on in a `Drop` impl; leaking the
            // registration on failure is preferable to a panic.
            let _ = unregister(reg);
        }
        // SAFETY: `self.iocp` is a valid handle owned by this `Epoll`.
        unsafe {
            CloseHandle(self.iocp);
        }
    }
}

fn unregister(reg: Registration) -> io::Result<()> {
    // `Epoll::wait` re-arms under the registrations lock, which the caller
    // holds, so at most one claim is needed -- but the loop stays as a
    // belt-and-braces guard. The blocking `UnregisterWaitEx` waits until
    // any in-flight callback for that handle returns, so once the loop
    // ends nothing can reference `reg.ctx`.
    let mut result = Ok(());
    loop {
        // SAFETY: `reg.ctx` is valid until freed below.
        let handle = unsafe { (*reg.ctx).wait_handle.swap(null_mut(), Ordering::AcqRel) };
        if handle.is_null() {
            break;
        }
        // SAFETY: `handle` was just atomically claimed above.
        let ret = unsafe { UnregisterWaitEx(handle as HANDLE, INVALID_HANDLE_VALUE) };
        if ret == 0 {
            // Keep the first error but keep looping: a racing callback may
            // still have re-registered a handle that needs claiming.
            result = result.and(Err(io::Error::last_os_error()));
        }
    }
    // SAFETY: see the loop comment above.
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
        // Regression test for the exact `vhost-user-backend` kick pattern:
        // register a handle with `Epoll`, signal it, `Epoll::wait` for it
        // (which resets the handle as part of delivery), then consume it
        // through an `EventConsumer` built from the same handle, the way
        // `vring.rs` builds one from a wire-delivered handle via
        // `from_raw_handle`. This must not block: the whole point is that
        // `Epoll::wait` having already reported the event as ready is
        // sufficient, and `EventConsumer::consume` must not try to wait
        // again on an event `Epoll` has already reset.
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

        // `RegisterWaitForSingleObject` requires the registered handle to
        // stay open until explicitly unregistered (unlike Linux, where
        // closing a fd implicitly drops it from any epoll interest list) —
        // delete before `event_fd` drops (and closes its handle) below.
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
    fn a_thousand_fire_and_rearm_cycles_leak_no_handles() {
        // Every delivered event re-arms the underlying threadpool wait; a
        // spent wait registration abandoned per fire shows up as +N here.
        // Found live: the virtiofsd daemon leaked one handle per FUSE
        // request. Delta over N rather than exact equality, because other
        // test threads add background handle noise.
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
        // The registration path round-trips a Box through into_raw and a
        // threadpool wait handle; a leak on either shows up as +N here.
        // Delta over N rather than exact equality: other test threads add
        // background handle noise.
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
