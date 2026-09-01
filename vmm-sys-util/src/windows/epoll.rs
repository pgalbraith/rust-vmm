// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Windows analog of Linux [`epoll`](http://man7.org/linux/man-pages/man7/epoll.7.html),
//! backed by an I/O completion port and one persistent threadpool wait per
//! handle.
//!
//! Sockets here are polled with `WSAPoll`. The plan is to poll them through
//! the `\Device\Afd` driver instead, which is what libuv, mio, the JDK and
//! Microsoft's OpenVMM all do. `docs/windows-socket-polling.md` explains why,
//! what it costs to depend on an undocumented driver, and where each of those
//! projects does it.
//!
//! Two kinds of thing can be registered, and they differ in what they
//! report.
//!
//! *Sockets* report [`EventSet::IN`] and [`EventSet::OUT`], and are
//! level-triggered as epoll is by default: each [`Epoll::wait`] asks
//! `WSAPoll` what is ready now rather than remembering an earlier edge.
//! That is deliberate. Winsock's own notifications are edge-triggered --
//! `FD_WRITE` re-arms only after a send fails -- so a caller that had not
//! exhausted a socket would never hear about it again. Registration does
//! **not** change the socket: in particular it is not put into
//! non-blocking mode, which `WSAEventSelect` would have forced, since
//! Winsock offers no way to keep event notification and blocking mode
//! together. One caveat inherited from `WSAPoll`: it does not report a
//! *failed* non-blocking `connect`, so a caller detecting connection
//! failure through writability needs another way to see it.
//!
//! *Handles* report [`EventSet::IN`] only; [`Epoll::ctl`] rejects any
//! other bit for them rather than silently ignoring it. They are expected
//! to be
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
//! While any socket is registered, [`Epoll::wait`] blocks in `WSAPoll`
//! rather than on the completion port, so a signalled handle reaches it
//! over an internal loopback pair created with the first socket. An
//! `Epoll` that only ever watches handles never creates that pair and
//! never requires Winsock to have been initialised.
//!
//! A registered handle must be removed with [`ControlOperation::Delete`] (or
//! by dropping the `Epoll`) before it's closed — unlike Linux, closing first
//! doesn't implicitly unregister it and leaves a dangling wait registration.

use std::collections::HashMap;
use std::io;
use std::os::windows::io::{AsRawHandle, IntoRawSocket, RawHandle};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetHandleInformation, GetLastError, ERROR_INVALID_HANDLE, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    RegisterWaitForSingleObject, SetEvent, UnregisterWaitEx, INFINITE, WT_EXECUTEDEFAULT,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatusEx, PostQueuedCompletionStatus,
    OVERLAPPED_ENTRY,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, getsockopt, recv, send, WSAPoll, POLLRDNORM, POLLWRNORM, SOCKET,
    SOCKET_ERROR, SOL_SOCKET, SO_TYPE, WSAPOLLFD,
};

bitflags::bitflags! {
    /// The type of events that can be monitored for a handle.
    ///
    /// Only [`EventSet::IN`] is implemented; [`Epoll::ctl`] rejects any
    /// other bit. The remaining variants exist only for API parity with the
    /// Linux `EventSet` type.
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub struct EventSet: u32 {
        /// A registered handle is signaled, or a registered socket is
        /// readable.
        const IN = 1 << 0;
        /// A registered socket is writable. Not available for handles;
        /// passing it for one makes [`Epoll::ctl`] fail.
        const OUT = 1 << 1;
        /// Never requested. A socket in this condition is reported as
        /// [`EventSet::IN`], so the caller's next read observes it;
        /// passing this to [`Epoll::ctl`] fails.
        const ERROR = 1 << 2;
        /// Never requested; reported as [`EventSet::IN`] the same way
        /// [`EventSet::ERROR`] is. Passing it to [`Epoll::ctl`] fails.
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
    /// Points at the owning `Epoll`'s `wake_writer`. Sound because
    /// `unregister` blocks until no callback can observe this context
    /// again, and every registration is unregistered before the `Epoll`
    /// itself is dropped.
    wake_writer: *const AtomicIsize,
}

/// What a registered socket is watched for, and the data to report it
/// with. Sockets carry no threadpool wait of their own: readiness is
/// discovered by the sweep in [`Epoll::wait`], and one shared event does
/// the waking (see `socket_wake`).
struct SocketRegistration {
    interest: EventSet,
    data: u64,
}

/// The interest list, under one lock: `by_handle` for `ctl`, and the
/// token-keyed view `data_by_token` for `wait` to resolve completions
/// with a lookup instead of a scan.
#[derive(Default)]
struct Registrations {
    by_handle: HashMap<HANDLE, Registration>,
    data_by_token: HashMap<usize, u64>,
    sockets: HashMap<SOCKET, SocketRegistration>,
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

    // While sockets are registered `wait` blocks in `WSAPoll`, not on the
    // completion port, so the post above would go unnoticed until that poll
    // returned on its own. One byte on the wake pair is what ends it.
    // SAFETY: `wake_writer` points at the owning `Epoll`'s field, which
    // outlives every registration that can reach it.
    let writer = unsafe { &*ctx.wake_writer }.load(Ordering::Acquire);
    if writer >= 0 {
        let byte = 1u8;
        // SAFETY: the wake pair is closed only after every registration has
        // been unregistered, which blocks out any in-flight callback.
        unsafe { send(writer as SOCKET, &byte as *const u8, 1, 0) };
    }
}

/// A connected loopback pair used only to interrupt a blocked `WSAPoll`.
///
/// When sockets are registered, `wait` blocks in `WSAPoll` rather than on
/// the completion port, because only `WSAPoll` can report socket
/// readiness without altering the socket -- `WSAEventSelect` would work
/// too, but it forces the socket into non-blocking mode, and Winsock
/// offers no way to keep notification and blocking mode together. A
/// handle signalling while `wait` is blocked writes one byte here, which
/// is what makes that poll return.
struct SocketWake {
    /// Polled alongside the registered sockets, and written by
    /// `wait_callback` to interrupt that poll. One socket is both ends: a
    /// datagram socket connected to its own address, so what it sends it
    /// receives.
    sock: SOCKET,
}

/// Completion key for a socket wake-up. It carries no identity: it only
/// means "sweep the sockets", which is why one event serves all of them.
/// `next_token` counts up from zero, so this can never collide.
/// Wrapper over epoll-like functionality, backed by an I/O completion port.
///
/// See the module documentation for what is and is not supported: event
/// handles report readability only, while sockets report readability and
/// writability.
pub struct Epoll {
    iocp: HANDLE,
    registrations: Mutex<Registrations>,
    next_token: AtomicUsize,
    /// Created on the first socket registration, not in `new`: making it
    /// eagerly would require Winsock to be initialized in a process whose
    /// `Epoll` may only ever watch event handles.
    socket_wake: Mutex<Option<SocketWake>>,
    /// The wake pair's writer, or -1 while no socket is registered. Read
    /// without a lock by `wait_callback`, which must not block behind an
    /// in-progress `ctl`.
    wake_writer: AtomicIsize,
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
            format!("a Windows Epoll handle only supports EventSet::IN, got {events:?}"),
        ));
    }
    Ok(())
}

/// Sockets accept readability and writability; nothing else is reported.
fn validate_socket_event_set(bits: u32) -> io::Result<EventSet> {
    let Some(events) = EventSet::from_bits(bits) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown EventSet bits: {bits:#x}"),
        ));
    };
    let supported = EventSet::IN | EventSet::OUT;
    if !(events - supported).is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("a Windows Epoll socket supports IN and OUT, got {events:?}"),
        ));
    }
    Ok(events)
}

/// Whether `handle` names a socket rather than a waitable kernel object.
///
/// `getsockopt` is the test because it is total: on anything that is not a
/// socket it fails rather than misbehaving, and it inspects the object
/// without altering it.
fn is_socket(handle: HANDLE) -> bool {
    let mut sock_type: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as i32;
    // SAFETY: `getsockopt` validates the descriptor itself and reports a
    // non-socket as an error; the out-parameters are valid for the call.
    let ret = unsafe {
        getsockopt(
            handle as SOCKET,
            SOL_SOCKET,
            SO_TYPE,
            &mut sock_type as *mut i32 as *mut u8,
            &mut len,
        )
    };
    ret != SOCKET_ERROR
}

/// The `WSAPoll` request bits for an interest set.
fn poll_events(interest: EventSet) -> i16 {
    let mut events = 0;
    if interest.contains(EventSet::IN) {
        events |= POLLRDNORM;
    }
    if interest.contains(EventSet::OUT) {
        events |= POLLWRNORM;
    }
    events
}

/// What to report for a `WSAPoll` result, or `None` if nothing happened.
///
/// `POLLERR`/`POLLHUP`/`POLLNVAL` are returned whether or not they were
/// asked for. They are reported as readability, so the caller's next read
/// observes the condition and handles it the way it already handles a
/// closed peer, rather than needing a Windows-specific branch.
fn event_set_of(revents: i16) -> Option<EventSet> {
    if revents == 0 {
        return None;
    }
    let mut set = EventSet::empty();
    if revents & POLLRDNORM != 0 {
        set |= EventSet::IN;
    }
    if revents & POLLWRNORM != 0 {
        set |= EventSet::OUT;
    }
    if set.is_empty() {
        set = EventSet::IN;
    }
    Some(set)
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
            socket_wake: Mutex::new(None),
            wake_writer: AtomicIsize::new(-1),
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
        let raw = handle as HANDLE;
        if is_socket(raw) {
            let sock = handle as SOCKET;
            if matches!(operation, ControlOperation::Delete) {
                return self.delete_socket(sock);
            }
            let interest = validate_socket_event_set(event.events)?;
            return match operation {
                ControlOperation::Add => self.add_socket(sock, interest, event.data()),
                _ => self.modify_socket(sock, interest, event.data()),
            };
        }

        validate_event_set(event.events)?;
        match operation {
            ControlOperation::Add => self.add(raw, event),
            ControlOperation::Modify => self.modify(raw, event),
            ControlOperation::Delete => self.delete(raw),
        }
    }

    /// Install the wake pair, once, on the first socket registration.
    ///
    /// An `Epoll` that only ever watches event handles never pays for this,
    /// and never requires Winsock to have been started.
    fn ensure_wake(&self) -> io::Result<()> {
        let mut wake = self.socket_wake.lock().unwrap();
        if wake.is_some() {
            return Ok(());
        }
        // Built from `std` rather than raw Winsock calls: `std` performs the
        // process-wide Winsock start-up that `socket()` would otherwise
        // require this crate to do, and then never undo.
        //
        // One datagram socket, connected to its own address, so that a
        // `send` with no address arrives at its own `recv`. Connecting a UDP
        // socket only sets the peer address, so nothing here can block. A TCP
        // pair would need connect and accept to complete against each other,
        // which is not something to wait for while registering a socket.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
        sock.connect(sock.local_addr()?)?;
        // Drained from `wait`, which must never block doing it, and written
        // from a thread-pool callback, which must not block either.
        sock.set_nonblocking(true)?;

        let sock = sock.into_raw_socket() as SOCKET;
        // Published last: a callback that observes it must find it usable.
        self.wake_writer.store(sock as isize, Ordering::Release);
        *wake = Some(SocketWake { sock });
        Ok(())
    }

    fn add_socket(&self, sock: SOCKET, interest: EventSet, data: u64) -> io::Result<()> {
        self.ensure_wake()?;
        let mut regs = self.registrations.lock().unwrap();
        if regs.sockets.contains_key(&sock) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        regs.sockets.insert(sock, SocketRegistration { interest, data });
        Ok(())
    }

    fn modify_socket(&self, sock: SOCKET, interest: EventSet, data: u64) -> io::Result<()> {
        let mut regs = self.registrations.lock().unwrap();
        let reg = regs
            .sockets
            .get_mut(&sock)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        reg.interest = interest;
        reg.data = data;
        Ok(())
    }

    fn delete_socket(&self, sock: SOCKET) -> io::Result<()> {
        let mut regs = self.registrations.lock().unwrap();
        regs.sockets
            .remove(&sock)
            .map(|_| ())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    /// Report every registered socket ready at this instant.
    ///
    /// Asking rather than remembering is what makes socket readiness
    /// level-triggered, as epoll is by default. Winsock's own notifications
    /// are edge-triggered -- `FD_WRITE` in particular re-arms only after a
    /// send fails -- so a caller that had not exhausted a socket would
    /// otherwise never hear about it again.
    fn sweep_sockets(&self, events: &mut [EpollEvent]) -> io::Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let (mut fds, meta) = {
            let regs = self.registrations.lock().unwrap();
            if regs.sockets.is_empty() {
                return Ok(0);
            }
            let mut fds = Vec::with_capacity(regs.sockets.len());
            let mut meta = Vec::with_capacity(regs.sockets.len());
            for (sock, reg) in regs.sockets.iter() {
                fds.push(WSAPOLLFD {
                    fd: *sock,
                    events: poll_events(reg.interest),
                    revents: 0,
                });
                meta.push(reg.data);
            }
            (fds, meta)
        };

        // SAFETY: `fds` is valid for `len` elements for the duration of the
        // call, which returns at once at a zero timeout.
        let ret = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, 0) };
        if ret == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }

        let mut count = 0;
        for (fd, data) in fds.iter().zip(meta) {
            if count == events.len() {
                break;
            }
            let Some(set) = event_set_of(fd.revents) else {
                continue;
            };
            events[count] = EpollEvent::new(set, data);
            count += 1;
        }
        Ok(count)
    }

    /// Block until a registered socket is ready or a handle wakes us.
    ///
    /// Returns false if `timeout_ms` elapsed with nothing to report.
    fn poll_block(&self, timeout_ms: i32) -> io::Result<bool> {
        let (mut fds, wake_reader) = {
            let wake = self.socket_wake.lock().unwrap();
            let Some(wake) = wake.as_ref() else {
                return Ok(false);
            };
            let regs = self.registrations.lock().unwrap();
            let mut fds = Vec::with_capacity(regs.sockets.len() + 1);
            for (sock, reg) in regs.sockets.iter() {
                fds.push(WSAPOLLFD {
                    fd: *sock,
                    events: poll_events(reg.interest),
                    revents: 0,
                });
            }
            fds.push(WSAPOLLFD {
                fd: wake.sock,
                events: POLLRDNORM,
                revents: 0,
            });
            (fds, wake.sock)
        };

        // SAFETY: `fds` is valid for `len` elements for the duration.
        let ret = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, timeout_ms) };
        if ret == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Ok(false);
        }

        // Drain the wake pair if it fired, or it stays readable and every
        // later poll returns instantly.
        if fds.last().map(|f| f.revents) != Some(0) {
            let mut buf = [0u8; 64];
            loop {
                // SAFETY: `wake_reader` is owned by this `Epoll` and the
                // buffer is valid for the call; the socket is non-blocking.
                let n = unsafe { recv(wake_reader, buf.as_mut_ptr(), buf.len() as i32, 0) };
                if n <= 0 || (n as usize) < buf.len() {
                    break;
                }
            }
        }
        Ok(true)
    }

    fn add(&self, handle: HANDLE, event: EpollEvent) -> io::Result<()> {
        reject_unwaitable(handle)?;
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
            wake_writer: &self.wake_writer as *const AtomicIsize,
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
        // With no socket registered this is exactly the completion-port
        // wait it has always been, at no added cost.
        if self.registrations.lock().unwrap().sockets.is_empty() {
            return self.wait_handles(timeout, events);
        }

        let deadline = (timeout >= 0)
            .then(|| Instant::now() + Duration::from_millis(timeout as u64));

        loop {
            // Neither source may block while the other might have work:
            // sweep the sockets, then take whatever the port already holds.
            let mut count = self.sweep_sockets(events)?;
            count += self.wait_handles(0, &mut events[count..])?;
            if count > 0 {
                return Ok(count);
            }

            let remaining = match deadline {
                None => -1,
                Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                    None => return Ok(0),
                    Some(left) => left.as_millis().min(i32::MAX as u128) as i32,
                },
            };
            // Blocks in WSAPoll, which a signalled handle interrupts by
            // writing to the wake socket (see `wait_callback`).
            //
            // If that write is ever missed, the caller waits here forever
            // rather than late. So cap the wait and look at both sources
            // again, instead of trusting the wake to arrive.
            //
            // The cap costs one extra wake-up every RECHECK_MS while a socket
            // is registered, and nothing at all when none is. It can go when
            // sockets move to AFD (see `docs/windows-socket-polling.md`):
            // handle and socket readiness then both arrive on the completion
            // port, and there is no wake to miss.
            const RECHECK_MS: i32 = 50;
            let block_for = if remaining < 0 {
                RECHECK_MS
            } else {
                remaining.min(RECHECK_MS)
            };
            if !self.poll_block(block_for)? && remaining >= 0 && remaining <= RECHECK_MS {
                return Ok(0);
            }
        }
    }

    /// The completion-port half of [`Epoll::wait`]: event handles only.
    fn wait_handles(&self, timeout: i32, events: &mut [EpollEvent]) -> io::Result<usize> {
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
        // Order matters: `unregister` below blocks out any in-flight
        // callback, and a callback reads `wake_writer`. Stop publishing it
        // first, then close the pair after the waits are gone.
        self.wake_writer.store(-1, Ordering::Release);
        let mut registrations = self.registrations.lock().unwrap();
        for (_, reg) in registrations.by_handle.drain() {
            // Can't act on errors in a `Drop` impl; leak on failure rather
            // than panic.
            let _ = unregister(reg);
        }
        registrations.data_by_token.clear();
        registrations.sockets.clear();
        drop(registrations);

        // Safe to close now: every wait is unregistered, so no callback can
        // still be holding the writer.
        if let Some(wake) = self.socket_wake.lock().unwrap().take() {
            // SAFETY: owned by this `Epoll`; the registered sockets
            // themselves are the caller's to close.
            unsafe {
                closesocket(wake.sock);
            }
        }

        // SAFETY: `self.iocp` is owned by this `Epoll`.
        unsafe {
            CloseHandle(self.iocp);
        }
    }
}

/// Refuse a handle the threadpool cannot wait on.
///
/// Registering one does not fail: `RegisterWaitForSingleObject` accepts it
/// and the process then dies inside the threadpool. The realistic way to
/// arrive here is nesting -- handing one `Epoll` to another, which works on
/// Linux, where an epoll fd is itself pollable, and cannot here, because
/// this `Epoll` is a completion port and a completion port is not a
/// signalable object. Anything watching an `Epoll` on Windows has to be
/// told by other means, such as an [`EventFd`](crate::eventfd::EventFd) the
/// waiting side signals.
///
/// Only that one case is detected. It is the one that is both plausible and
/// fatal; a handle of some other unwaitable type still gets whatever
/// `RegisterWaitForSingleObject` does with it.
fn reject_unwaitable(handle: HANDLE) -> io::Result<()> {
    const OBJECT_TYPE_INFORMATION_CLASS: i32 = 2;

    // A handle that names nothing kills the process the same way, and is
    // cheaper to spot. `GetHandleInformation` answers without touching the
    // object, so unlike a zero-timeout wait it cannot swallow a signal from
    // an auto-reset event.
    let mut flags: u32 = 0;
    // SAFETY: the out-parameter is valid for the call, which tolerates any
    // handle value including an invalid one.
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a valid handle, so it cannot be registered with an Epoll",
        ));
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryObject(
            handle: HANDLE,
            object_information_class: i32,
            object_information: *mut c_void,
            object_information_length: u32,
            return_length: *mut u32,
        ) -> i32; // NTSTATUS
    }

    // PUBLIC_OBJECT_TYPE_INFORMATION: a UNICODE_STRING name, then reserved
    // words. Over-sized so the name's own buffer fits behind the struct.
    let mut buf = [0u8; 512];
    let mut len = 0u32;
    // SAFETY: `buf` is a valid out-buffer of the stated length.
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_TYPE_INFORMATION_CLASS,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut len,
        )
    };
    if status < 0 {
        // Unknown: leave it to the existing path rather than refuse a
        // handle that may be perfectly waitable.
        return Ok(());
    }

    // UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: *mut u16 }
    // SAFETY: the call succeeded, so the buffer holds the structure.
    let (name_len, name_ptr) = unsafe {
        let length = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ptr = std::ptr::read_unaligned(buf.as_ptr().add(std::mem::size_of::<usize>())
            as *const *const u16);
        (length / 2, ptr)
    };
    if name_ptr.is_null() || name_len == 0 || name_len > 64 {
        return Ok(());
    }
    // SAFETY: the name buffer is valid for `name_len` u16s while `handle`
    // is open, which it is for the duration of this call.
    let name = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
    if String::from_utf16_lossy(name) == "IoCompletion" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an I/O completion port cannot be waited on, so it cannot be \
             registered with an Epoll; on Windows an Epoll cannot be nested \
             inside another one the way an epoll fd can on Linux",
        ));
    }
    Ok(())
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::io::{AsRawSocket, FromRawHandle, IntoRawHandle};

    /// A connected loopback pair, both halves left in their default
    /// blocking mode so a test can observe whether registration changed it.
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn raw(sock: &TcpStream) -> RawHandle {
        sock.as_raw_socket() as RawHandle
    }

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

    // Asserts a `debug_assert!`, which release builds compile out.
    #[cfg(debug_assertions)]
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

    // Asserts a `debug_assert!`, which release builds compile out.
    #[cfg(debug_assertions)]
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

    // Asserts a `debug_assert!`, which release builds compile out.
    #[cfg(debug_assertions)]
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

    #[test]
    fn a_socket_reports_readability_and_goes_on_reporting_it() {
        let epoll = Epoll::new().unwrap();
        let (mut client, server) = tcp_pair();

        epoll
            .ctl(
                ControlOperation::Add,
                raw(&server),
                EpollEvent::new(EventSet::IN, 7),
            )
            .unwrap();

        client.write_all(b"x").unwrap();

        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(5000, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 7);
        assert!(events[0].event_set().contains(EventSet::IN));

        // Level-triggered: the byte is still unread, so a second wait must
        // report it again rather than waiting for a fresh edge.
        assert_eq!(epoll.wait(0, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 7);
    }

    #[test]
    fn a_socket_reports_writability() {
        let epoll = Epoll::new().unwrap();
        let (client, _server) = tcp_pair();

        epoll
            .ctl(
                ControlOperation::Add,
                raw(&client),
                EpollEvent::new(EventSet::OUT, 9),
            )
            .unwrap();

        // An idle connected socket is writable, and stays so; this is the
        // case Winsock's own edge-triggered FD_WRITE would report once at
        // most, which is why readiness is swept rather than remembered.
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(5000, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 9);
        assert!(events[0].event_set().contains(EventSet::OUT));
        assert_eq!(epoll.wait(0, &mut events).unwrap(), 1);
    }

    #[test]
    fn registering_a_socket_leaves_it_in_blocking_mode() {
        // The reason this shim polls rather than using WSAEventSelect,
        // which would put the caller's socket into non-blocking mode as a
        // side effect. Read from an empty socket under a receive timeout:
        // a blocking socket reports TimedOut, a non-blocking one reports
        // WouldBlock immediately, so the two are distinguishable.
        let epoll = Epoll::new().unwrap();
        let (_client, mut server) = tcp_pair();
        server
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();

        epoll
            .ctl(
                ControlOperation::Add,
                raw(&server),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();

        let mut buf = [0u8; 1];
        let err = server.read(&mut buf).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "registration must not have made the socket non-blocking, got {err:?}"
        );
    }

    #[test]
    fn a_signalled_handle_wakes_a_wait_blocked_on_sockets() {
        // Sockets make `wait` block in WSAPoll instead of on the completion
        // port, so a handle has to reach it some other way: the wake pair.
        let epoll = Epoll::new().unwrap();
        let (_client, server) = tcp_pair();
        let event_fd = EventFd::new(0).unwrap();

        epoll
            .ctl(
                ControlOperation::Add,
                raw(&server),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 42),
            )
            .unwrap();

        let writer = event_fd.try_clone().unwrap();
        let signaller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            writer.write(1).unwrap();
        });

        // The socket is idle, so only the handle can end this wait.
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(5000, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 42);
        signaller.join().unwrap();
    }

    #[test]
    fn socket_ctl_rejects_events_it_cannot_report() {
        let epoll = Epoll::new().unwrap();
        let (client, _server) = tcp_pair();

        let err = epoll
            .ctl(
                ControlOperation::Add,
                raw(&client),
                EpollEvent::new(EventSet::READ_HANG_UP, 1),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        // ...but IN|OUT together is exactly what a socket is for.
        epoll
            .ctl(
                ControlOperation::Add,
                raw(&client),
                EpollEvent::new(EventSet::IN | EventSet::OUT, 1),
            )
            .unwrap();
    }

    #[test]
    fn a_deleted_socket_is_no_longer_reported() {
        let epoll = Epoll::new().unwrap();
        let (mut client, server) = tcp_pair();

        epoll
            .ctl(
                ControlOperation::Add,
                raw(&server),
                EpollEvent::new(EventSet::IN, 3),
            )
            .unwrap();
        client.write_all(b"x").unwrap();

        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(5000, &mut events).unwrap(), 1);

        epoll
            .ctl(
                ControlOperation::Delete,
                raw(&server),
                EpollEvent::new(EventSet::empty(), 0),
            )
            .unwrap();
        assert_eq!(epoll.wait(0, &mut events).unwrap(), 0);

        // Deleting twice is a miss, not a silent success.
        assert!(epoll
            .ctl(
                ControlOperation::Delete,
                raw(&server),
                EpollEvent::new(EventSet::empty(), 0),
            )
            .is_err());
    }

    #[test]
    fn nesting_an_epoll_is_refused_rather_than_fatal() {
        // Registering a completion port does not fail in
        // RegisterWaitForSingleObject; the process dies in the threadpool
        // later. Since nesting is the natural thing to try -- it is how the
        // same code works on Linux -- it has to be refused up front.
        let outer = Epoll::new().unwrap();
        let inner = Epoll::new().unwrap();

        let err = outer
            .ctl(
                ControlOperation::Add,
                inner.as_raw_handle(),
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn an_invalid_handle_is_refused_rather_than_fatal() {
        // Registering one does not fail in RegisterWaitForSingleObject; the
        // process dies in the thread pool afterwards. Callers reach here by
        // passing a descriptor that names nothing -- a closed one, or the -1
        // that stands for "no descriptor" on the POSIX side.
        let epoll = Epoll::new().unwrap();

        for bad in [-1isize, 0isize] {
            let err = epoll
                .ctl(
                    ControlOperation::Add,
                    bad as RawHandle,
                    EpollEvent::new(EventSet::IN, 1),
                )
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "for {bad}");
        }
    }
}
