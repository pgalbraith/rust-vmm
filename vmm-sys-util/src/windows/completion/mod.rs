// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Completion-based I/O on Windows: submit a request, then be told when it
//! is done.
//!
//! This is the shape Windows is built for, and the opposite of the
//! readiness model in [`crate::epoll`] ("tell me when I can do the I/O").
//! Four types:
//!
//! - [`Port`] is the loop. It is an I/O completion port. Handles are
//!   associated with it, signals and timers are bridged into it, and
//!   [`Port::wait`] dequeues what has finished, a batch at a time.
//! - [`Operation`] is one submitted request: an overlapped block and the
//!   buffer it reads into or writes from. [`Port::read`] and [`Port::write`]
//!   submit one on any handle opened for overlapped I/O; the [`socket`]
//!   submodule submits one on a socket.
//! - [`Signal`] is an auto-reset event object. It is the same type as
//!   [`crate::eventfd::EventFd`], because that is what a doorbell is on the
//!   wire; [`Port::register`] bridges one into the port.
//! - [`Timer`] posts to the port when it expires.
//!
//! THE CONTRACT - four rules, and what breaks when one is ignored
//! --------------------------------------------------------------
//!
//! 1. **The buffer belongs to the `Operation` for the life of the request.**
//!    Submitting moves the `Operation` into the port, and the kernel may
//!    write into its buffer at any moment until the completion has been
//!    dequeued. The `Operation` comes back inside the
//!    [`Completion::Operation`] that reports it, and not before.
//! 2. **Cancellation is asynchronous, and a cancelled operation still
//!    completes.** [`Port::cancel`] asks; it does not wait. The operation is
//!    reported later by `wait`, normally with OS error 995
//!    (`ERROR_OPERATION_ABORTED`), and its buffer comes back with it. A
//!    cancel that lands after the operation finished changes nothing: the
//!    operation completes as it would have.
//! 3. **Every outstanding operation is drained before its block is freed.**
//!    Freeing an overlapped block the kernel may still write to corrupts
//!    memory, and nothing reports it. Dropping a `Port` with operations
//!    outstanding cancels them all, dequeues until each one has completed,
//!    and frees them only then. A block whose completion never arrives is
//!    leaked rather than freed; see the note on `Drop`.
//! 4. **A `Port` is not waitable and cannot be nested.** A completion port
//!    is not a signalable object. Registering one with another `Port` is
//!    refused up front, because the thread pool would accept it and then
//!    kill the process. Two loops in one process talk through a `Signal`.
//!
//! WHAT THIS FILE NEVER DOES - link Winsock
//! ----------------------------------------
//!
//! `Port`, `Operation`, `Signal` and `Timer` work over kernel handles:
//! files, pipes, events, and sockets treated as handles. Nothing in this
//! file names a Winsock function, so a program that only waits on doorbells
//! never initialises Winsock. The socket submissions (`AcceptEx`, `WSARecv`,
//! `WSASend`) live in [`socket`], which is the only place in the module that
//! does.
//!
//! HOW A DEQUEUED PACKET IS CLASSIFIED
//! -----------------------------------
//!
//! Every packet carries a key, a byte count and a pointer. `wait` sorts them
//! like this:
//!
//! - the key [`RESERVED_KEY`] is the port's own. The pointer is a token for
//!   a bridged signal or timer, and the packet is reported as
//!   [`Completion::Signal`] or [`Completion::Timer`] under the key given at
//!   registration. A token whose registration has since been removed is
//!   skipped, never misdelivered: tokens are minted once and never reused;
//! - a pointer that names an outstanding `Operation` is that operation's
//!   completion, reported as [`Completion::Operation`] under the key the
//!   handle was associated with;
//! - anything else was posted, by [`Port::post`] in this process or by
//!   another process through a duplicated port handle, and is reported as
//!   [`Completion::Posted`] with all three values intact.
//!
//! Two consequences for callers: `RESERVED_KEY` is refused as an
//! association key and as a post key, and a posted pointer must not be the
//! address of a live operation's block. Small integers and the poster's own
//! tags are what the pointer field is for.

use std::any::Any;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, RawHandle};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetHandleInformation, GetLastError, RtlNtStatusToDosError, ERROR_INVALID_HANDLE,
    ERROR_IO_PENDING, ERROR_NOT_FOUND, FILETIME, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Threading::{
    CloseThreadpoolTimer, CreateThreadpoolTimer, RegisterWaitForSingleObject, SetEvent,
    SetThreadpoolTimer, UnregisterWaitEx, WaitForThreadpoolTimerCallbacks, INFINITE, PTP_TIMER,
    WT_EXECUTEDEFAULT,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatusEx, PostQueuedCompletionStatus,
    OVERLAPPED, OVERLAPPED_ENTRY,
};

pub mod socket;

/// The doorbell type: an auto-reset event object, the same type as
/// [`crate::eventfd::EventFd`].
///
/// One name for one object. The `vhost` crate names `EventFd` in its
/// kick, call and error setters, and the completion loop bridges the same
/// handle through [`Port::register`], so this is a re-export rather than a
/// second type.
pub use crate::eventfd::EventFd as Signal;

/// The completion key this module keeps for itself.
///
/// Bridged signals and timers post under it, with their token in the
/// pointer field, so that `wait` can tell them from operations and posts.
/// [`Port::associate`] and [`Port::post`] refuse it.
pub const RESERVED_KEY: usize = usize::MAX;

/// How many packets one `GetQueuedCompletionStatusEx` call may return.
const BATCH: usize = 64;

/// Identifies a submitted [`Operation`] until it completes.
///
/// Returned by every submission and accepted by [`Port::cancel`]. It is the
/// address of the operation's block, which is also the pointer the
/// completion packet carries. An operation that has come back through
/// [`Completion::Operation`] reports the same value from
/// [`Operation::token`], so a caller can match completions against tokens
/// it saved at submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token(usize);

/// One dequeued packet, classified as the module header describes.
#[derive(Debug)]
pub enum Completion {
    /// A signal registered with [`Port::register`] was set. The kernel has
    /// already consumed it: the wait that noticed it is what reset the
    /// event, so there is nothing to read afterwards.
    Signal {
        /// The key given at registration, or the latest [`Port::rekey`].
        key: usize,
    },
    /// A [`Timer`] expired.
    Timer {
        /// The key given to [`Timer::new`].
        key: usize,
    },
    /// A submitted operation finished, successfully or not.
    Operation {
        /// The key the handle was associated with.
        key: usize,
        /// The byte count on success, or the OS error the operation ended
        /// with. A cancelled operation reports OS error 995.
        result: io::Result<usize>,
        /// The operation, with its buffer and anything it held, back in the
        /// caller's hands.
        operation: Operation,
    },
    /// Someone posted a packet: [`Port::post`] here, or [`post`] through a
    /// duplicated handle in another process.
    Posted {
        /// The key the poster gave.
        key: usize,
        /// The byte count the poster gave.
        bytes: u32,
        /// The pointer value the poster gave. It is a number, not a valid
        /// pointer; see the module header.
        pointer: usize,
    },
}

// ---------------------------------------------------------------------------
// Operation
// ---------------------------------------------------------------------------

/// The memory an operation is submitted with, at a fixed address for as long
/// as the request is outstanding.
///
/// The kernel writes `overlapped` while the request is in flight, so while
/// the block is outstanding it is owned through a raw pointer in the port's
/// table, not a `Box`, and no Rust reference to it exists. `overlapped` is
/// the first field so the block's address is the pointer the completion
/// packet reports.
#[repr(C)]
struct Block {
    overlapped: OVERLAPPED,
    /// The handle the request was issued on, for `CancelIoEx`. Null until
    /// submitted.
    handle: HANDLE,
    buffer: Vec<u8>,
    held: Option<Box<dyn Any + Send>>,
}

/// One request: an overlapped block that owns its buffer for as long as the
/// request is outstanding.
///
/// Build one with [`Operation::new`], submit it with [`Port::read`],
/// [`Port::write`] or a function in [`socket`], and get it back inside the
/// [`Completion::Operation`] that reports the result. The buffer's length
/// is the I/O length: a read fills `buffer[..bytes]`, a write sends the
/// whole buffer.
///
/// [`Operation::hold`] keeps something alive for exactly as long as the
/// request is outstanding. It exists for anything the kernel may still
/// touch through this operation, such as a guard on a memory mapping that
/// the buffer points into, and for anything that must not be released
/// before the completion is dequeued, such as the socket an accept is
/// filling in.
pub struct Operation {
    block: Box<Block>,
}

// SAFETY: the block holds a raw handle value and an `OVERLAPPED` with a raw
// pointer field, neither of which has thread affinity; everything else in it
// is `Send`.
unsafe impl Send for Operation {}

impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operation")
            .field("token", &self.token())
            .field("buffer_len", &self.block.buffer.len())
            .field("holds_something", &self.block.held.is_some())
            .finish()
    }
}

impl Operation {
    /// An operation over `buffer`. Its length is the I/O length.
    pub fn new(buffer: Vec<u8>) -> Operation {
        Operation {
            block: Box::new(Block {
                overlapped: OVERLAPPED::default(),
                handle: null_mut(),
                buffer,
                held: None,
            }),
        }
    }

    /// The buffer. After a read completes, the first `bytes` of it are what
    /// was read.
    pub fn buffer(&self) -> &[u8] {
        &self.block.buffer
    }

    /// The buffer, for filling before a write or resizing between uses.
    pub fn buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.block.buffer
    }

    /// Take the buffer out, dropping the rest of the operation.
    pub fn into_buffer(self) -> Vec<u8> {
        self.block.buffer
    }

    /// Keep `item` alive until this operation completes and is dequeued.
    /// Returns whatever was held before.
    pub fn hold(&mut self, item: Box<dyn Any + Send>) -> Option<Box<dyn Any + Send>> {
        self.block.held.replace(item)
    }

    /// Take back what [`Operation::hold`] was given.
    pub fn take_held(&mut self) -> Option<Box<dyn Any + Send>> {
        self.block.held.take()
    }

    /// Whether something is held; see [`Operation::hold`].
    pub fn holds_something(&self) -> bool {
        self.block.held.is_some()
    }

    /// The token this operation is (or will be) submitted under.
    pub fn token(&self) -> Token {
        Token(&*self.block as *const Block as usize)
    }

    /// The buffer as a pointer and a length the kernel accepts, or an error
    /// if it is too long for one request.
    fn io_range(&mut self) -> io::Result<(*mut u8, u32)> {
        let len = u32::try_from(self.block.buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "an operation's buffer must fit in a u32 length",
            )
        })?;
        Ok((self.block.buffer.as_mut_ptr(), len))
    }
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

/// A registered wait on one signal handle, bridging it into the port.
struct SignalRegistration {
    token: usize,
    /// Freed by `UnregisterWaitEx` in `unregister`.
    wait_handle: HANDLE,
    ctx: *mut WaitCallbackCtx,
}

struct WaitCallbackCtx {
    port: HANDLE,
    handle: HANDLE,
    token: usize,
}

#[derive(Clone, Copy)]
enum BridgedKind {
    Signal,
    Timer,
}

/// What a bridged token reports when its packet is dequeued.
#[derive(Clone, Copy)]
struct Bridged {
    key: usize,
    kind: BridgedKind,
}

/// Everything the port tracks, under one lock. The wait and timer callbacks
/// never take it: they only post.
#[derive(Default)]
struct State {
    /// Bridged signals, by the value of the handle each one waits on.
    signals: HashMap<usize, SignalRegistration>,
    /// Live tokens, for signals and timers alike.
    bridged: HashMap<usize, Bridged>,
    /// Submitted operations that have not been dequeued, by block address.
    outstanding: HashMap<usize, *mut Block>,
}

struct Inner {
    handle: HANDLE,
    state: Mutex<State>,
    /// Tokens count up from 1 and are never reused, so a packet queued for
    /// a registration removed since cannot alias a newer one. Zero is never
    /// a token, so a null pointer under `RESERVED_KEY` is always stale.
    next_token: AtomicUsize,
}

// SAFETY: the handle has no thread affinity, the raw pointers in `State`
// are only touched under its mutex, and the Win32 calls made on the handle
// are thread-safe.
unsafe impl Send for Inner {}
// SAFETY: see above.
unsafe impl Sync for Inner {}

/// An I/O completion port: the loop.
///
/// Three ways for something to arrive on it, and one call to collect them:
///
/// - [`Port::associate`] a handle, then submit operations on it with
///   [`Port::read`], [`Port::write`] or the [`socket`] functions. Each
///   completes here under the association key.
/// - [`Port::register`] a [`Signal`] (or any waitable handle) under a key.
///   Each time it is set, a [`Completion::Signal`] arrives. [`Timer`] works
///   the same way for time.
/// - [`Port::post`] a packet, from this process or, through a duplicated
///   handle, from another.
///
/// [`Port::wait`] dequeues them in batches. Several threads may wait on one
/// port at once; each packet goes to exactly one of them.
///
/// A `Port` is not itself waitable (rule 4 in the module header). It can be
/// duplicated into another process, which may then post to it; that is what
/// [`AsHandle`] is for.
pub struct Port {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Port")
            .field("handle", &self.inner.handle)
            .finish()
    }
}

// SAFETY: only invoked by the Win32 thread pool with the context pointer it
// was registered with, which stays valid until `unregister`'s blocking
// `UnregisterWaitEx` has waited out any in-flight invocation.
//
// The registration is persistent and the handle auto-reset: the kernel
// consumed the signal to satisfy the wait, so this only relays the wake-up
// to the port and never touches the handle's state.
unsafe extern "system" fn wait_callback(param: *mut c_void, _timer_or_wait_fired: bool) {
    // SAFETY: see the function's SAFETY comment.
    let ctx = unsafe { &*(param as *const WaitCallbackCtx) };

    // SAFETY: `ctx.port` is open for as long as this registration is:
    // `Port::drop` unregisters before the handle is closed.
    let posted = unsafe {
        PostQueuedCompletionStatus(ctx.port, 0, RESERVED_KEY, ctx.token as *mut OVERLAPPED)
    };
    if posted == 0 {
        // The signal is already consumed, so a failed post would lose it.
        // Re-signal so the persistent wait tries again, unless the port is
        // gone, in which case there is nowhere left to deliver to and
        // re-signalling would only spin.
        // SAFETY: reads the thread's last-error slot; `ctx.handle` is open
        // for as long as this registration is.
        unsafe {
            if GetLastError() != ERROR_INVALID_HANDLE {
                SetEvent(ctx.handle);
            }
        }
    }
}

impl Port {
    /// A fresh port with nothing associated.
    pub fn new() -> io::Result<Port> {
        // SAFETY: `INVALID_HANDLE_VALUE` with a null existing port is the
        // documented way to create a new, unassociated port.
        let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Port {
            inner: Arc::new(Inner {
                handle,
                state: Mutex::new(State::default()),
                next_token: AtomicUsize::new(1),
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().unwrap()
    }

    fn mint_token(&self) -> usize {
        self.inner.next_token.fetch_add(1, Ordering::Relaxed)
    }

    /// Route every operation submitted on `handle` to this port, reported
    /// under `key`.
    ///
    /// The handle must have been opened for overlapped I/O
    /// (`FILE_FLAG_OVERLAPPED`, or a socket). An association lasts until the
    /// handle is closed and cannot be changed or moved to another port.
    /// Sockets are associated through [`socket::associate`], which does the
    /// documented socket-to-handle conversion.
    pub fn associate(&self, handle: BorrowedHandle<'_>, key: usize) -> io::Result<()> {
        self.associate_raw(handle.as_raw_handle() as HANDLE, key)
    }

    fn associate_raw(&self, handle: HANDLE, key: usize) -> io::Result<()> {
        if key == RESERVED_KEY {
            return Err(reserved_key_error("an association"));
        }
        // SAFETY: `handle` is open for the borrow, and the port is open for
        // `self`. The kernel validates both.
        let port = unsafe { CreateIoCompletionPort(handle, self.inner.handle, key, 0) };
        if port.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Submit a read of `operation`'s whole buffer from `handle` at `offset`.
    ///
    /// The handle must be associated with this port, or the completion
    /// never arrives here and the operation is stranded until the port is
    /// dropped. `offset` is ignored by handles that cannot seek, such as
    /// pipes. Returns the token to cancel with. If the request is refused
    /// outright, the operation is dropped with the error.
    pub fn read(
        &self,
        handle: BorrowedHandle<'_>,
        offset: u64,
        mut operation: Operation,
    ) -> io::Result<Token> {
        let raw = handle.as_raw_handle() as HANDLE;
        let (ptr, len) = operation.io_range()?;
        self.submit(raw, operation, |block| {
            // SAFETY: `block` is the operation's block, at a fixed address
            // the port now owns, and no reference to it exists.
            unsafe {
                set_offset(block, offset);
                let ok = ReadFile(raw, ptr, len, null_mut(), block as *mut OVERLAPPED);
                request_outstanding(ok != 0)
            }
        })
    }

    /// Submit a write of `operation`'s whole buffer to `handle` at
    /// `offset`. Everything said for [`Port::read`] applies.
    pub fn write(
        &self,
        handle: BorrowedHandle<'_>,
        offset: u64,
        mut operation: Operation,
    ) -> io::Result<Token> {
        let raw = handle.as_raw_handle() as HANDLE;
        let (ptr, len) = operation.io_range()?;
        self.submit(raw, operation, |block| {
            // SAFETY: as in `read`.
            unsafe {
                set_offset(block, offset);
                let ok = WriteFile(raw, ptr, len, null_mut(), block as *mut OVERLAPPED);
                request_outstanding(ok != 0)
            }
        })
    }

    /// Hand `operation` to the port and issue it.
    ///
    /// `issue` gets the block's address after the port has taken ownership
    /// of it, and returns `Ok` once the request is outstanding (accepted
    /// synchronously or pending: both queue a packet). On `Err` the request
    /// was refused, the kernel never took the address, and the block is
    /// freed here.
    ///
    /// The block goes into the table before `issue` runs, not after: a
    /// completion can be dequeued by another thread the instant the request
    /// is accepted, and a pointer the table does not know is reported as a
    /// post.
    fn submit(
        &self,
        handle: HANDLE,
        mut operation: Operation,
        issue: impl FnOnce(*mut Block) -> io::Result<()>,
    ) -> io::Result<Token> {
        operation.block.overlapped = OVERLAPPED::default();
        operation.block.handle = handle;
        let block = Box::into_raw(operation.block);
        let token = block as usize;

        self.state().outstanding.insert(token, block);
        if let Err(e) = issue(block) {
            self.state().outstanding.remove(&token);
            // SAFETY: the request was refused, so nothing else references
            // the block; it came from `Box::into_raw` just above.
            unsafe { drop(Box::from_raw(block)) };
            return Err(e);
        }
        Ok(Token(token))
    }

    /// Ask for an outstanding operation to be cancelled.
    ///
    /// This does not wait (rule 2 in the module header). The operation is
    /// reported later by [`Port::wait`], normally with OS error 995; if it
    /// had already finished, it is reported as it finished. `NotFound`
    /// means the token names nothing outstanding: never submitted, or
    /// already dequeued.
    pub fn cancel(&self, token: Token) -> io::Result<()> {
        let state = self.state();
        let &block = state
            .outstanding
            .get(&token.0)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        // SAFETY: the block is outstanding, so its address is valid, and
        // reading one field through the pointer creates no reference to
        // the `OVERLAPPED` the kernel may be writing.
        let handle = unsafe { std::ptr::addr_of!((*block).handle).read() };
        cancel_block(handle, block)
    }

    /// How many operations are submitted and not yet dequeued.
    pub fn outstanding(&self) -> usize {
        self.state().outstanding.len()
    }

    /// Bridge a waitable handle into the port: each time it is signaled,
    /// a [`Completion::Signal`] with `key` arrives.
    ///
    /// Meant for a [`Signal`], and the handle must be auto-reset if it is
    /// an event: satisfying the wait consumes the signal atomically, so
    /// each one becomes exactly one packet. A manual-reset event stays
    /// signaled and would fire the persistent wait continuously; debug
    /// builds refuse one with a panic. Other waitables (a semaphore, a
    /// process) are accepted as they are.
    ///
    /// Registering the same handle twice is `AlreadyExists`. A handle that
    /// names nothing, or names another completion port, is `InvalidInput`.
    /// Unregister before closing the handle: the wait registration does
    /// not notice a close.
    pub fn register(&self, handle: BorrowedHandle<'_>, key: usize) -> io::Result<()> {
        let raw = handle.as_raw_handle() as HANDLE;
        reject_unwaitable(raw)?;
        debug_assert_auto_reset(raw);

        let mut state = self.state();
        if state.signals.contains_key(&(raw as usize)) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }

        let token = self.mint_token();
        let ctx = Box::into_raw(Box::new(WaitCallbackCtx {
            port: self.inner.handle,
            handle: raw,
            token,
        }));

        let mut wait_handle: HANDLE = null_mut();
        // SAFETY: `raw` is a caller-provided handle that outlives the
        // registration (the caller's responsibility, as for `epoll_ctl`);
        // `ctx` is freed only after `unregister` confirms no callback can
        // observe it again.
        let ret = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_handle,
                raw,
                Some(wait_callback),
                ctx as *mut c_void,
                INFINITE,
                WT_EXECUTEDEFAULT,
            )
        };
        if ret == 0 {
            // SAFETY: registration failed, so the thread pool never saw
            // `ctx` and nothing else references it.
            unsafe { drop(Box::from_raw(ctx)) };
            return Err(io::Error::last_os_error());
        }

        state.signals.insert(
            raw as usize,
            SignalRegistration {
                token,
                wait_handle,
                ctx,
            },
        );
        state.bridged.insert(
            token,
            Bridged {
                key,
                kind: BridgedKind::Signal,
            },
        );
        Ok(())
    }

    /// Change the key a registered handle reports.
    ///
    /// Done in place, not as unregister-then-register: retiring the token
    /// would silently drop a packet already queued under it, a consumed
    /// doorbell lost in the swap. A packet queued before the call reports
    /// the new key. `NotFound` if the handle is not registered.
    pub fn rekey(&self, handle: BorrowedHandle<'_>, key: usize) -> io::Result<()> {
        let raw = handle.as_raw_handle() as usize;
        let mut state = self.state();
        let token = state
            .signals
            .get(&raw)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            .token;
        state.bridged.insert(
            token,
            Bridged {
                key,
                kind: BridgedKind::Signal,
            },
        );
        Ok(())
    }

    /// Stop bridging a handle. A packet already queued for it is skipped
    /// by `wait`, not delivered. `NotFound` if it is not registered.
    pub fn unregister(&self, handle: BorrowedHandle<'_>) -> io::Result<()> {
        let raw = handle.as_raw_handle() as usize;
        let mut state = self.state();
        let reg = state
            .signals
            .remove(&raw)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        state.bridged.remove(&reg.token);
        unregister(reg)
    }

    /// Post a packet to this port. It comes back from `wait` as
    /// [`Completion::Posted`] with the same three values.
    pub fn post(&self, key: usize, bytes: u32, pointer: usize) -> io::Result<()> {
        post(self.as_handle(), key, bytes, pointer)
    }

    /// Dequeue what has completed, appending to `completions`.
    ///
    /// Returns how many were appended. `None` waits for ever; `Some` waits
    /// at most that long and returns `Ok(0)` on expiry. One call returns
    /// at most one batch (64 packets); if more are queued, the next call
    /// returns at once with them.
    ///
    /// Some packets report nothing: a bridged token whose registration was
    /// removed after the packet was queued. Those are not the caller's wait
    /// expiring, so the call goes round again with what is left of the
    /// timeout.
    pub fn wait(
        &self,
        timeout: Option<Duration>,
        completions: &mut Vec<Completion>,
    ) -> io::Result<usize> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            let remaining = match deadline {
                None => INFINITE,
                Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                    None => 0,
                    // Never INFINITE, which would turn a finite wait into an
                    // endless one.
                    Some(left) => left.as_millis().min(u32::MAX as u128 - 1) as u32,
                },
            };
            let count = self.dequeue_batch(remaining, completions)?;
            if count > 0 || remaining == 0 {
                return Ok(count);
            }
        }
    }

    /// One `GetQueuedCompletionStatusEx`, classified as the module header
    /// describes. `Ok(0)` on expiry or when the batch held only stale
    /// tokens.
    fn dequeue_batch(&self, wait_ms: u32, completions: &mut Vec<Completion>) -> io::Result<usize> {
        let mut entries = [OVERLAPPED_ENTRY::default(); BATCH];
        let mut removed: u32 = 0;
        // SAFETY: the port is open for `self`; `entries` is valid for
        // `BATCH` writes and `removed` for the duration of the call.
        let ret = unsafe {
            GetQueuedCompletionStatusEx(
                self.inner.handle,
                entries.as_mut_ptr(),
                BATCH as u32,
                &mut removed,
                wait_ms,
                0,
            )
        };
        if ret == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                return Ok(0);
            }
            return Err(err);
        }

        // The whole batch resolves under one acquisition of the lock.
        let mut count = 0;
        let mut state = self.state();
        for entry in &entries[..removed as usize] {
            let pointer = entry.lpOverlapped as usize;
            let key = entry.lpCompletionKey;

            if key == RESERVED_KEY {
                if let Some(bridged) = state.bridged.get(&pointer) {
                    completions.push(match bridged.kind {
                        BridgedKind::Signal => Completion::Signal { key: bridged.key },
                        BridgedKind::Timer => Completion::Timer { key: bridged.key },
                    });
                    count += 1;
                }
                continue;
            }

            if let Some(block) = state.outstanding.remove(&pointer) {
                // The packet is the kernel saying it has finished with the
                // block, so it is safe to own it again.
                // SAFETY: the pointer came from `Box::into_raw` in `submit`
                // and no request is outstanding against it any more.
                let block = unsafe { Box::from_raw(block) };
                let result =
                    status_to_result(block.overlapped.Internal, entry.dwNumberOfBytesTransferred);
                completions.push(Completion::Operation {
                    key,
                    result,
                    operation: Operation { block },
                });
                count += 1;
                continue;
            }

            completions.push(Completion::Posted {
                key,
                bytes: entry.dwNumberOfBytesTransferred,
                pointer,
            });
            count += 1;
        }
        Ok(count)
    }
}

impl AsHandle for Port {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: the port handle is open for as long as `self` is.
        unsafe { BorrowedHandle::borrow_raw(self.inner.handle as RawHandle) }
    }
}

impl AsRawHandle for Port {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.handle as RawHandle
    }
}

impl Drop for Port {
    /// Tear down in the order rule 3 needs: stop the bridges, cancel every
    /// outstanding operation, dequeue until each has completed, then let
    /// the handle close.
    ///
    /// If an operation does not complete within five seconds of nothing
    /// else completing, its block is leaked rather than freed. That only
    /// happens when a driver ignores cancellation or the handle was never
    /// associated with this port; a leak at shutdown is harmless where a
    /// freed block the kernel later writes to is not.
    fn drop(&mut self) {
        let mut state = self.state();
        for (_, reg) in state.signals.drain() {
            // Nothing to do with an error in `drop`; the registration is
            // leaked rather than the context freed under a live callback.
            let _ = unregister(reg);
        }
        state.bridged.clear();

        for (&pointer, &block) in state.outstanding.iter() {
            debug_assert_eq!(pointer, block as usize);
            // SAFETY: as in `cancel`.
            let handle = unsafe { std::ptr::addr_of!((*block).handle).read() };
            // A refusal here means the operation is already completing or
            // its handle is gone; either way the drain below sees it.
            let _ = cancel_block(handle, block);
        }
        drop(state);

        const PATIENCE: Duration = Duration::from_secs(5);
        let mut last_progress = Instant::now();
        while self.outstanding() > 0 {
            let mut drained = Vec::new();
            // Everything dequeued here is discarded: operations are freed
            // as they come back, and a stray post has no one left to read
            // it.
            match self.dequeue_batch(1000, &mut drained) {
                Ok(n) if n > 0 => last_progress = Instant::now(),
                Ok(_) if last_progress.elapsed() < PATIENCE => {}
                _ => break,
            }
        }

        // Anything still outstanding is leaked on purpose: the table is
        // simply dropped with its raw pointers, and the blocks stay
        // allocated for ever.
        self.state().outstanding.clear();
        // The handle itself closes in `Inner::drop`, once the last timer
        // callback that upgraded its `Weak` has let go.
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: the handle is owned here and closed once.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Post a packet to any port handle, including one duplicated in from
/// another process.
///
/// The three values arrive at the port's `wait` as [`Completion::Posted`].
/// `key` may not be [`RESERVED_KEY`], and `pointer` must not be the address
/// of a live operation's block at the receiving end; see the module header.
pub fn post(port: BorrowedHandle<'_>, key: usize, bytes: u32, pointer: usize) -> io::Result<()> {
    if key == RESERVED_KEY {
        return Err(reserved_key_error("a post"));
    }
    // SAFETY: the handle is open for the borrow; the kernel validates that
    // it is a completion port.
    let ok = unsafe {
        PostQueuedCompletionStatus(
            port.as_raw_handle() as HANDLE,
            bytes,
            key,
            pointer as *mut OVERLAPPED,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn reserved_key_error(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{what} may not use RESERVED_KEY; the port keeps that key for its own packets"),
    )
}

/// Put `offset` where `ReadFile` and `WriteFile` look for it.
///
/// # Safety
///
/// `block` must be a valid, exclusively owned block address.
unsafe fn set_offset(block: *mut Block, offset: u64) {
    // SAFETY: the caller guarantees the address; writing through raw
    // pointers creates no reference.
    unsafe {
        let overlapped = std::ptr::addr_of_mut!((*block).overlapped);
        (*overlapped).Anonymous.Anonymous.Offset = offset as u32;
        (*overlapped).Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    }
}

/// Whether an overlapped request is now outstanding, given whether the
/// call reported success. `ERROR_IO_PENDING` is the normal case; immediate
/// success still queues a packet.
fn request_outstanding(succeeded: bool) -> io::Result<()> {
    if succeeded {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
        Ok(())
    } else {
        Err(err)
    }
}

/// Ask the kernel to cancel one request. `ERROR_NOT_FOUND` means it has
/// already completed and its packet is on its way, which is not a failure.
fn cancel_block(handle: HANDLE, block: *mut Block) -> io::Result<()> {
    // SAFETY: the block is outstanding, so its address is the one the
    // request was issued with; cancelling a request that has already
    // completed is harmless.
    let ok = unsafe { CancelIoEx(handle, block as *mut OVERLAPPED) };
    if ok != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        Ok(())
    } else {
        Err(err)
    }
}

/// The result of a finished request, from the `NTSTATUS` the kernel left in
/// its block and the byte count in the packet.
fn status_to_result(status: usize, bytes: u32) -> io::Result<usize> {
    let status = status as NTSTATUS;
    if status >= 0 {
        return Ok(bytes as usize);
    }
    // SAFETY: a pure lookup.
    let code = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::from_raw_os_error(code as i32))
}

fn unregister(reg: SignalRegistration) -> io::Result<()> {
    // The blocking form of `UnregisterWaitEx` cancels the persistent wait
    // and waits until any in-flight callback returns, so afterwards nothing
    // can reference `reg.ctx`.
    // SAFETY: `reg.wait_handle` came from `RegisterWaitForSingleObject` and
    // is unregistered exactly once, since the registration is owned here.
    let ret = unsafe { UnregisterWaitEx(reg.wait_handle, INVALID_HANDLE_VALUE) };
    let result = if ret == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    // SAFETY: see above; on failure the context is still ours, and leaking
    // the wait registration is no reason to leak the context too.
    unsafe { drop(Box::from_raw(reg.ctx)) };
    result
}

/// Refuse a handle the thread pool cannot wait on.
///
/// Registering one does not fail: `RegisterWaitForSingleObject` accepts it
/// and the process then dies inside the thread pool. Two cases are caught.
/// A handle that names nothing, which `GetHandleInformation` spots without
/// touching the object (so, unlike a zero-timeout wait, it cannot swallow a
/// signal). And a completion port, which is what a caller hands over when
/// nesting one `Port` in another, the natural thing to try because it
/// works on Linux. Anything else of an unwaitable type still gets whatever
/// the thread pool does with it.
///
/// `epoll.rs` carries the same check for the same reason; that copy goes
/// when the shim does.
fn reject_unwaitable(handle: HANDLE) -> io::Result<()> {
    const OBJECT_TYPE_INFORMATION_CLASS: i32 = 2;

    let mut flags: u32 = 0;
    // SAFETY: the out-parameter is valid for the call, which tolerates any
    // handle value including an invalid one.
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a valid handle, so it cannot be registered with a Port",
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
        // Unknown: let the thread pool have it rather than refuse a handle
        // that may be perfectly waitable.
        return Ok(());
    }

    // UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: *mut u16 }
    // SAFETY: the call succeeded, so the buffer holds the structure.
    let (name_len, name_ptr) = unsafe {
        let length = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ptr = std::ptr::read_unaligned(
            buf.as_ptr().add(std::mem::size_of::<usize>()) as *const *const u16
        );
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
             registered with a Port; a Port cannot be nested inside another \
             the way an epoll fd can on Linux",
        ));
    }
    Ok(())
}

/// Debug-build guard for `register`'s precondition: a manual-reset event
/// under a persistent wait fires continuously, so catch it at registration
/// instead of as a mystery hot spin.
///
/// `NtQueryEvent` lives in ntdll, which `windows-sys` does not bind; the
/// hand-declared extern is confined to debug builds. The access it needs,
/// `EVENT_QUERY_STATE`, is undocumented and pinned by a test. `epoll.rs`
/// carries the same guard; that copy goes when the shim does.
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
    // Passing that through silently would leave this guard inert on
    // peer-handed doorbells, the production path it exists for, so an
    // unverifiable event is loud too. A peer duplicating a doorbell in with
    // DUPLICATE_SAME_ACCESS carries the right along.
    debug_assert!(
        status != STATUS_ACCESS_DENIED,
        "Port cannot verify this event's reset mode: the handle lacks \
         EVENT_QUERY_STATE; it must be granted when the handle is created \
         or duplicated"
    );
    // Any other failed query means the handle is some other waitable
    // (semaphore, process, ...), which is allowed; only a confirmed
    // manual-reset event is a misuse.
    debug_assert!(
        status != 0 || info.event_type == SYNCHRONIZATION_EVENT,
        "Port requires auto-reset events; a manual-reset event stays \
         signaled and would fire its persistent wait continuously"
    );
}

#[cfg(not(debug_assertions))]
fn debug_assert_auto_reset(_handle: HANDLE) {}

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

struct TimerCtx {
    port: Weak<Inner>,
    token: usize,
}

/// A one-shot timer that posts [`Completion::Timer`] to a port when it
/// expires.
///
/// It holds no strong reference to the port: if the port is dropped first,
/// an expiry goes nowhere, and the timer can be dropped in either order.
pub struct Timer {
    timer: PTP_TIMER,
    ctx: *mut TimerCtx,
    token: usize,
    port: Weak<Inner>,
}

// SAFETY: the thread-pool timer object and the context pointer have no
// thread affinity, and the Win32 calls made on them are thread-safe.
unsafe impl Send for Timer {}
// SAFETY: see above; `set` and `cancel` take `&self` and make only
// thread-safe calls.
unsafe impl Sync for Timer {}

impl std::fmt::Debug for Timer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timer").field("token", &self.token).finish()
    }
}

// SAFETY: only invoked by the thread pool with the context it was created
// with, which is freed only after `Timer::drop` has closed the timer and
// waited out any in-flight callback.
unsafe extern "system" fn timer_callback(
    _instance: isize,
    context: *mut c_void,
    _timer: PTP_TIMER,
) {
    // SAFETY: see the function's SAFETY comment.
    let ctx = unsafe { &*(context as *const TimerCtx) };
    // A port that is gone has nothing to deliver to. Holding the `Arc`
    // across the post keeps the handle open for it.
    if let Some(inner) = ctx.port.upgrade() {
        // SAFETY: the port handle is open while `inner` is held.
        unsafe {
            PostQueuedCompletionStatus(inner.handle, 0, RESERVED_KEY, ctx.token as *mut OVERLAPPED);
        }
    }
}

impl Timer {
    /// A timer that will report `key` on `port`. It is not running until
    /// [`Timer::set`].
    pub fn new(port: &Port, key: usize) -> io::Result<Timer> {
        let token = port.mint_token();
        let ctx = Box::into_raw(Box::new(TimerCtx {
            port: Arc::downgrade(&port.inner),
            token,
        }));
        // SAFETY: the callback and context are valid until `drop`, which
        // closes the timer before freeing the context.
        let timer =
            unsafe { CreateThreadpoolTimer(Some(timer_callback), ctx as *mut c_void, null_mut()) };
        if timer == 0 {
            // SAFETY: the thread pool never saw `ctx`.
            unsafe { drop(Box::from_raw(ctx)) };
            return Err(io::Error::last_os_error());
        }
        port.state().bridged.insert(
            token,
            Bridged {
                key,
                kind: BridgedKind::Timer,
            },
        );
        Ok(Timer {
            timer,
            ctx,
            token,
            port: Arc::downgrade(&port.inner),
        })
    }

    /// Expire once, `after` from now. Setting a timer that is already set
    /// moves its expiry; a packet it has already posted is not withdrawn.
    pub fn set(&self, after: Duration) {
        // A negative FILETIME is a relative due time, in 100 ns units.
        let ticks = -i64::try_from(after.as_nanos() / 100).unwrap_or(i64::MAX);
        let due = FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        // SAFETY: the timer is open for `self`; `due` is a valid FILETIME
        // for the duration of the call.
        unsafe { SetThreadpoolTimer(self.timer, &due, 0, 0) };
    }

    /// Stop the timer. Returns once no callback is running, so afterwards
    /// nothing more is posted; a packet posted before the call still
    /// arrives.
    pub fn cancel(&self) {
        // SAFETY: the timer is open for `self`. A null due time cancels.
        unsafe {
            SetThreadpoolTimer(self.timer, std::ptr::null(), 0, 0);
            WaitForThreadpoolTimerCallbacks(self.timer, 1);
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.cancel();
        // SAFETY: the timer is closed once, after `cancel` has waited out
        // any callback, so the context is unreferenced when it is freed.
        unsafe {
            CloseThreadpoolTimer(self.timer);
            drop(Box::from_raw(self.ctx));
        }
        // A packet already queued for this token is skipped by `wait` from
        // here on. If the port is gone, its table went with it.
        if let Some(inner) = self.port.upgrade() {
            inner.state.lock().unwrap().bridged.remove(&self.token);
        }
    }
}

#[cfg(test)]
mod tests;
