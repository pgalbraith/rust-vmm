// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Tests for the handle-agnostic core: the signal bridge, operations on an
//! overlapped pipe, posts, timers, and teardown. Nothing here touches
//! Winsock; the socket tests are in `socket.rs`.
//!
//! The signal-bridge tests are the handle-path tests of the epoll shim,
//! ported with their assertions intact, because the bridge is the same
//! registered-wait-to-port mechanism.

use super::*;
use crate::event::EventConsumer;
use std::io::{BufRead, Write};
use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
use std::sync::atomic::AtomicBool;

use windows_sys::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, GENERIC_READ, GENERIC_WRITE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

const TIMEOUT: Option<Duration> = Some(Duration::from_secs(5));
const SHORT: Option<Duration> = Some(Duration::from_millis(100));

/// The keys of the signal completions in `out`, in arrival order, with a
/// panic on anything that is not a signal.
fn signal_keys(out: &[Completion]) -> Vec<usize> {
    out.iter()
        .map(|c| match c {
            Completion::Signal { key } => *key,
            other => panic!("expected a signal completion, got {other:?}"),
        })
        .collect()
}

/// Wait once and return the signal keys delivered.
fn wait_signals(port: &Port, timeout: Option<Duration>) -> Vec<usize> {
    let mut out = Vec::new();
    port.wait(timeout, &mut out).unwrap();
    signal_keys(&out)
}

/// Wait for exactly one operation completion.
fn one_operation(port: &Port, timeout: Option<Duration>) -> (usize, io::Result<usize>, Operation) {
    let mut out = Vec::new();
    assert_eq!(port.wait(timeout, &mut out).unwrap(), 1);
    match out.pop().unwrap() {
        Completion::Operation {
            key,
            result,
            operation,
        } => (key, result, operation),
        other => panic!("expected an operation completion, got {other:?}"),
    }
}

/// A connected named-pipe pair, both ends opened for overlapped I/O:
/// `(server, client)`. A read on either end with nothing written to the
/// other stays pending for as long as the test likes.
fn overlapped_pipe() -> (OwnedHandle, OwnedHandle) {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let name = format!(
        r"\\.\pipe\vmm-sys-util-completion-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a NUL-terminated name valid for the call; the
    // result is checked.
    let server = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            std::ptr::null(),
        )
    };
    assert_ne!(
        server,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    // SAFETY: as above. Opening the one instance connects it, so no
    // ConnectNamedPipe is needed.
    let client = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    };
    assert_ne!(
        client,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    // SAFETY: both handles were just created and are owned by nothing else.
    unsafe {
        (
            OwnedHandle::from_raw_handle(server as RawHandle),
            OwnedHandle::from_raw_handle(client as RawHandle),
        )
    }
}

/// Sets a flag when dropped: proof of exactly when a held item was freed.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn the_loop_types_can_be_shared_between_threads() {
    // A worker thread owns the port and a device holds a reference to it;
    // a timer or an operation may be handed across threads.
    fn send_and_sync<T: Send + Sync>() {}
    fn send<T: Send>() {}
    send_and_sync::<Port>();
    send_and_sync::<Timer>();
    send::<Operation>();
    send::<Completion>();
}

// ---------------------------------------------------------------------------
// The signal bridge: the epoll shim's handle-path tests, assertions intact
// ---------------------------------------------------------------------------

#[test]
fn consume_after_wait_does_not_deadlock() {
    // The vhost-user-backend kick pattern: signal, wait (whose registered
    // wait consumes the auto-reset signal), then consume through an
    // EventConsumer built from the same handle. Must not block.
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    let consumer_handle = signal.try_clone().unwrap().into_raw_handle();
    // SAFETY: just obtained from `into_raw_handle` and not closed.
    let consumer = unsafe { EventConsumer::from_raw_handle(consumer_handle) };

    port.register(signal.as_handle(), 1).unwrap();
    signal.write(1).unwrap();

    assert_eq!(wait_signals(&port, TIMEOUT), vec![1]);

    // This used to hang for ever under the manual-reset shim.
    consumer.consume().unwrap();

    // Unregister before `signal` drops and closes the handle.
    port.unregister(signal.as_handle()).unwrap();
}

#[test]
fn register_signal_wait() {
    let port = Port::new().unwrap();
    let signal_1 = Signal::new(0).unwrap();
    let signal_2 = Signal::new(0).unwrap();

    port.register(signal_1.as_handle(), 1).unwrap();
    port.register(signal_2.as_handle(), 2).unwrap();

    // Registering the same handle twice fails.
    assert_eq!(
        port.register(signal_1.as_handle(), 1).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );

    signal_1.write(1).unwrap();
    assert_eq!(wait_signals(&port, TIMEOUT), vec![1]);

    port.unregister(signal_1.as_handle()).unwrap();
    port.unregister(signal_2.as_handle()).unwrap();

    // Unregistering a handle that is not registered fails.
    assert_eq!(
        port.unregister(signal_2.as_handle()).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

// Asserts a `debug_assert!`, which release builds compile out.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "auto-reset")]
fn registering_a_manual_reset_event_is_caught_in_debug_builds() {
    // The bridge's precondition, enforced at registration: a manual-reset
    // event under a persistent wait would hot-spin.
    // SAFETY: plain create; checked before use.
    let manual = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    assert!(!manual.is_null());
    let port = Port::new().unwrap();
    // SAFETY: `manual` is open for the call.
    let _ = port.register(
        unsafe { BorrowedHandle::borrow_raw(manual as RawHandle) },
        0,
    );
}

// Asserts a `debug_assert!`, which release builds compile out.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "EVENT_QUERY_STATE")]
fn an_event_opened_without_query_rights_is_loud_not_silently_unverified() {
    // Pins the undocumented NtQueryEvent access requirement: without
    // EVENT_QUERY_STATE the query fails with ACCESS_DENIED, and the guard
    // must not pass that through, or it is inert on exactly the
    // peer-handed production path.
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::EVENT_MODIFY_STATE;
    // SAFETY: simple arguments; checked before use. Auto-reset, so only the
    // rights, not the mode, can trip the guard.
    let created = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    assert!(!created.is_null());
    // A peer that narrowed the access it duplicated in.
    let mut narrow: HANDLE = null_mut();
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

    let port = Port::new().unwrap();
    // SAFETY: `narrow` is open for the call.
    let _ = port.register(
        unsafe { BorrowedHandle::borrow_raw(narrow as RawHandle) },
        0,
    );
}

// Asserts a `debug_assert!`, which release builds compile out.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "auto-reset")]
fn a_peer_opened_manual_reset_event_is_caught_in_debug_builds() {
    // The production shape: a peer mints a manual-reset event (contract
    // violation) and duplicates it in; this side adopts the handle and
    // registration must panic rather than wait on an event whose signal it
    // cannot consume.
    // SAFETY: simple arguments; checked before use. Manual-reset on purpose.
    let created = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    assert!(!created.is_null());

    let mut dup: HANDLE = null_mut();
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
    let opened = unsafe { Signal::from_raw_handle(dup as RawHandle) };
    let port = Port::new().unwrap();
    let _ = port.register(opened.as_handle(), 0);
}

#[test]
fn a_restricted_rights_semaphore_is_still_registrable() {
    // Pins the second undocumented kernel behaviour the debug guard rests
    // on: the object TYPE check precedes the ACCESS check, so a non-event
    // waitable held with restricted rights fails NtQueryEvent with
    // STATUS_OBJECT_TYPE_MISMATCH (allowed) rather than STATUS_ACCESS_DENIED
    // (loud). If the ordering were the other way, this registration would
    // panic in debug builds.
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::{CreateSemaphoreA, SEMAPHORE_MODIFY_STATE};
    // SAFETY: plain create (count 0 = unsignaled); checked before use.
    let sem = unsafe { CreateSemaphoreA(std::ptr::null(), 0, 1, std::ptr::null()) };
    assert!(!sem.is_null());
    let mut narrow: HANDLE = null_mut();
    // SAFETY: valid source and pseudo process handles; `narrow` is a valid
    // out-pointer. Explicit mask, not DUPLICATE_SAME_ACCESS.
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

    let port = Port::new().unwrap();
    // SAFETY: `narrow` is open for both calls.
    let handle = unsafe { BorrowedHandle::borrow_raw(narrow as RawHandle) };
    port.register(handle, 0)
        .expect("a restricted-rights non-event waitable must register");
    port.unregister(handle).unwrap();
}

#[test]
fn a_stale_completion_key_is_skipped_not_misdelivered() {
    // The queued-packet-for-a-removed-registration case, made
    // deterministic: post under the reserved key with a token no live
    // registration owns. `wait` must skip it and still deliver the real
    // signal, and since tokens are never reused a stale one cannot alias a
    // registration added later.
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    port.register(signal.as_handle(), 7).unwrap();

    // SAFETY: the port handle is open; the token was never minted.
    let posted = unsafe {
        PostQueuedCompletionStatus(
            port.as_raw_handle() as HANDLE,
            0,
            RESERVED_KEY,
            usize::MAX as *mut OVERLAPPED,
        )
    };
    assert_ne!(posted, 0);
    signal.write(1).unwrap();

    let mut keys = Vec::new();
    while keys.is_empty() {
        keys = wait_signals(&port, TIMEOUT);
    }
    assert_eq!(keys, vec![7]);
    // Nothing further: the stale token produced no completion.
    assert_eq!(wait_signals(&port, SHORT), Vec::<usize>::new());

    port.unregister(signal.as_handle()).unwrap();
}

#[test]
fn each_signal_delivers_exactly_one_wakeup_and_no_storm() {
    // Two writes: exactly two wake-ups, then silence. A manual-reset event
    // under a persistent wait would storm (stay signaled and fire
    // continuously); a lost signal would deliver fewer.
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    port.register(signal.as_handle(), 9).unwrap();

    signal.write(1).unwrap();
    signal.write(1).unwrap();

    let mut total = 0;
    while total < 2 {
        let n = wait_signals(&port, TIMEOUT).len();
        assert_ne!(n, 0, "wake-up lost: got {total} of 2");
        total += n;
    }
    assert_eq!(total, 2);
    // Silence afterwards: nothing left signaled, nothing re-firing.
    assert_eq!(wait_signals(&port, SHORT).len(), 0);

    port.unregister(signal.as_handle()).unwrap();
}

#[test]
fn rekey_does_not_drop_a_queued_completion() {
    // Rekeying in place keeps the token, so a wake-up queued before the
    // rekey arrives, reporting the new key, whichever side of the rekey
    // the post landed on.
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    port.register(signal.as_handle(), 7).unwrap();

    signal.write(1).unwrap();
    port.rekey(signal.as_handle(), 42).unwrap();

    let mut keys = Vec::new();
    while keys.is_empty() {
        keys = wait_signals(&port, TIMEOUT);
    }
    assert_eq!(keys, vec![42]);

    // Rekeying an unregistered handle reports NotFound.
    let stranger = Signal::new(0).unwrap();
    assert_eq!(
        port.rekey(stranger.as_handle(), 1).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );

    port.unregister(signal.as_handle()).unwrap();
}

#[test]
fn a_batch_of_ready_doorbells_is_delivered_together() {
    // Many distinct registrations ready at once: all signals must arrive,
    // each with its own key, across however many waits the timing needs.
    const N: usize = 8;
    let port = Port::new().unwrap();
    let signals: Vec<Signal> = (0..N).map(|_| Signal::new(0).unwrap()).collect();
    for (i, s) in signals.iter().enumerate() {
        port.register(s.as_handle(), i).unwrap();
    }
    for s in &signals {
        s.write(1).unwrap();
    }

    let mut seen = std::collections::HashSet::new();
    while seen.len() < N {
        let keys = wait_signals(&port, TIMEOUT);
        assert!(!keys.is_empty(), "doorbell lost: got {} of {N}", seen.len());
        for key in keys {
            assert!(seen.insert(key), "duplicate wake-up for {key}");
        }
    }
    assert_eq!(seen, (0..N).collect());

    for s in &signals {
        port.unregister(s.as_handle()).unwrap();
    }
}

#[test]
fn wait_times_out_with_nothing_queued() {
    let port = Port::new().unwrap();
    let mut out = Vec::new();
    let started = Instant::now();
    assert_eq!(
        port.wait(Some(Duration::from_millis(50)), &mut out)
            .unwrap(),
        0
    );
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(out.is_empty());
}

#[test]
fn rekey_changes_the_reported_key() {
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    port.register(signal.as_handle(), 1).unwrap();
    port.rekey(signal.as_handle(), 42).unwrap();

    signal.write(1).unwrap();
    assert_eq!(wait_signals(&port, TIMEOUT), vec![42]);

    port.unregister(signal.as_handle()).unwrap();
}

#[test]
fn a_thousand_fire_cycles_leak_no_handles() {
    // The registration is persistent, so N fires must not create (or leak)
    // N of anything: no wait-handle churn, no context churn. Delta over N,
    // not exact equality: other test threads add handle noise.
    const N: u32 = 1000;
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    port.register(signal.as_handle(), 7).unwrap();

    // Warm-up so lazily created thread-pool machinery is not counted.
    signal.write(1).unwrap();
    while wait_signals(&port, Some(Duration::from_secs(1))).is_empty() {}

    let before = crate::windows::process_handle_count();
    for _ in 0..N {
        signal.write(1).unwrap();
        while wait_signals(&port, Some(Duration::from_secs(1))).is_empty() {}
    }
    let after = crate::windows::process_handle_count();
    assert!(
        after.saturating_sub(before) < N / 2,
        "handle count grew from {before} to {after} over {N} fire cycles"
    );
}

#[test]
fn a_thousand_registration_cycles_leak_no_handles() {
    // A leak in the context round-trip or the wait handle shows up as +N.
    const N: u32 = 1000;
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    let before = crate::windows::process_handle_count();
    for i in 0..N {
        port.register(signal.as_handle(), i as usize).unwrap();
        port.unregister(signal.as_handle()).unwrap();
    }
    let after = crate::windows::process_handle_count();
    assert!(
        after.saturating_sub(before) < N / 2,
        "handle count grew from {before} to {after} over {N} cycles"
    );
}

#[test]
fn nesting_a_port_is_refused_rather_than_fatal() {
    // Registering a completion port does not fail in
    // RegisterWaitForSingleObject; the process dies in the thread pool
    // later. Nesting is the natural thing to try, since it is how the same
    // code works on Linux, so it has to be refused up front.
    let outer = Port::new().unwrap();
    let inner = Port::new().unwrap();
    assert_eq!(
        outer.register(inner.as_handle(), 1).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn an_invalid_handle_is_refused_rather_than_fatal() {
    // Callers reach here with a handle that names nothing: a closed one,
    // or the -1 that stands for "no descriptor" on the POSIX side.
    let port = Port::new().unwrap();
    for bad in [-1isize, 0isize] {
        // SAFETY: `borrow_raw` permits both values; the port checks them.
        let handle = unsafe { BorrowedHandle::borrow_raw(bad as RawHandle) };
        assert_eq!(
            port.register(handle, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "for {bad}"
        );
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

#[test]
fn a_read_and_a_write_complete_with_their_byte_counts() {
    let port = Port::new().unwrap();
    let (server, client) = overlapped_pipe();
    port.associate(server.as_handle(), 10).unwrap();
    port.associate(client.as_handle(), 20).unwrap();

    let read_token = port
        .read(server.as_handle(), 0, Operation::new(vec![0; 32]))
        .unwrap();
    let write_token = port
        .write(
            client.as_handle(),
            0,
            Operation::new(b"hello, port".to_vec()),
        )
        .unwrap();
    assert_ne!(read_token, write_token);
    assert_eq!(port.outstanding(), 2);

    let mut got = Vec::new();
    while got.len() < 2 {
        let mut out = Vec::new();
        assert_ne!(port.wait(TIMEOUT, &mut out).unwrap(), 0, "completion lost");
        got.extend(out);
    }
    assert_eq!(port.outstanding(), 0);

    for completion in got {
        match completion {
            Completion::Operation {
                key: 10,
                result,
                operation,
            } => {
                assert_eq!(result.unwrap(), 11);
                assert_eq!(&operation.buffer()[..11], b"hello, port");
                assert_eq!(operation.token(), read_token);
            }
            Completion::Operation {
                key: 20,
                result,
                operation,
            } => {
                assert_eq!(result.unwrap(), 11);
                assert_eq!(operation.token(), write_token);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn a_cancelled_operation_completes_with_an_error_and_returns_its_buffer_only_then() {
    let port = Port::new().unwrap();
    let (server, _client) = overlapped_pipe();
    port.associate(server.as_handle(), 5).unwrap();

    let buffer = vec![0u8; 64];
    let buffer_address = buffer.as_ptr();
    let mut op = Operation::new(buffer);
    let freed = Arc::new(AtomicBool::new(false));
    op.hold(Box::new(DropFlag(freed.clone())));

    let token = port.read(server.as_handle(), 0, op).unwrap();

    // Nothing written to the other end: the read stays pending, and the
    // buffer is not back.
    let mut out = Vec::new();
    assert_eq!(port.wait(SHORT, &mut out).unwrap(), 0);
    assert_eq!(port.outstanding(), 1);
    assert!(!freed.load(Ordering::SeqCst));

    // Asking is not waiting: the request is still outstanding afterwards.
    port.cancel(token).unwrap();

    let (key, result, mut op) = one_operation(&port, TIMEOUT);
    assert_eq!(key, 5);
    assert_eq!(
        result.unwrap_err().raw_os_error(),
        Some(995),
        "a cancelled operation reports ERROR_OPERATION_ABORTED"
    );
    assert_eq!(op.token(), token);
    assert_eq!(port.outstanding(), 0);

    // The same buffer and the same held item come back, untouched until now.
    assert!(!freed.load(Ordering::SeqCst));
    assert!(op.take_held().is_some());
    let buffer = op.into_buffer();
    assert_eq!(buffer.as_ptr(), buffer_address);

    // Cancelling again names nothing outstanding.
    assert_eq!(
        port.cancel(token).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn a_port_dropped_with_operations_outstanding_drains_them_before_freeing() {
    // Rule 3 of the module header. The held item's drop flag says the
    // block was freed at all (a leak would leave it unset); that it was
    // freed only after the kernel let go is what makes the flag safe to
    // read at all.
    let (server, client) = overlapped_pipe();
    let freed = Arc::new(AtomicBool::new(false));
    {
        let port = Port::new().unwrap();
        port.associate(server.as_handle(), 1).unwrap();
        let mut op = Operation::new(vec![0; 64]);
        op.hold(Box::new(DropFlag(freed.clone())));
        port.read(server.as_handle(), 0, op).unwrap();
        assert_eq!(port.outstanding(), 1);
        assert!(!freed.load(Ordering::SeqCst));
    }
    assert!(
        freed.load(Ordering::SeqCst),
        "the port dropped without freeing the drained operation"
    );

    // The pipe is intact and unassociated with anything: a plain write
    // through the other end still works, so nothing was corrupted.
    let port = Port::new().unwrap();
    port.associate(client.as_handle(), 2).unwrap();
    port.write(client.as_handle(), 0, Operation::new(b"x".to_vec()))
        .unwrap();
    let (_, result, _) = one_operation(&port, TIMEOUT);
    assert_eq!(result.unwrap(), 1);
}

#[test]
fn a_thousand_operation_cycles_leak_no_handles() {
    // Submit and dequeue create no kernel objects, so N round trips must
    // not move the handle count.
    const N: u32 = 1000;
    let port = Port::new().unwrap();
    let (server, client) = overlapped_pipe();
    port.associate(server.as_handle(), 1).unwrap();
    port.associate(client.as_handle(), 2).unwrap();

    let before = crate::windows::process_handle_count();
    for _ in 0..N {
        port.write(client.as_handle(), 0, Operation::new(b"z".to_vec()))
            .unwrap();
        port.read(server.as_handle(), 0, Operation::new(vec![0; 1]))
            .unwrap();
        let mut got = 0;
        while got < 2 {
            let mut out = Vec::new();
            got += port.wait(TIMEOUT, &mut out).unwrap();
        }
    }
    let after = crate::windows::process_handle_count();
    assert!(
        after.saturating_sub(before) < N / 2,
        "handle count grew from {before} to {after} over {N} cycles"
    );
}

#[test]
fn a_refused_submission_frees_the_operation_and_reports_the_error() {
    // A handle that was never opened for overlapped I/O, or is not a
    // file at all: ReadFile refuses, the block never reached the kernel,
    // and it is freed on the spot.
    let port = Port::new().unwrap();
    let signal = Signal::new(0).unwrap();
    let freed = Arc::new(AtomicBool::new(false));
    let mut op = Operation::new(vec![0; 8]);
    op.hold(Box::new(DropFlag(freed.clone())));
    port.read(signal.as_handle(), 0, op).unwrap_err();
    assert!(freed.load(Ordering::SeqCst));
    assert_eq!(port.outstanding(), 0);
}

#[test]
fn an_operation_holds_and_hands_back_what_it_is_given() {
    let mut op = Operation::new(vec![1, 2, 3]);
    assert!(!op.holds_something());
    assert!(op.hold(Box::new(String::from("guard"))).is_none());
    assert!(op.holds_something());
    let previous = op.hold(Box::new(7u8)).unwrap();
    assert_eq!(*previous.downcast::<String>().unwrap(), "guard");
    assert_eq!(*op.take_held().unwrap().downcast::<u8>().unwrap(), 7);
    assert!(op.take_held().is_none());
    op.buffer_mut().push(4);
    assert_eq!(op.into_buffer(), vec![1, 2, 3, 4]);
}

// ---------------------------------------------------------------------------
// Posts
// ---------------------------------------------------------------------------

#[test]
fn a_posted_completion_carries_key_bytes_and_pointer() {
    let port = Port::new().unwrap();
    port.post(0xA, 42, 0xA11CE).unwrap();

    let mut out = Vec::new();
    assert_eq!(port.wait(TIMEOUT, &mut out).unwrap(), 1);
    match out.pop().unwrap() {
        Completion::Posted {
            key,
            bytes,
            pointer,
        } => {
            assert_eq!(key, 0xA);
            assert_eq!(bytes, 42);
            assert_eq!(pointer, 0xA11CE);
        }
        other => panic!("expected a posted completion, got {other:?}"),
    }
}

#[test]
fn the_reserved_key_is_refused_for_association_and_post() {
    let port = Port::new().unwrap();
    let (server, _client) = overlapped_pipe();
    assert_eq!(
        port.associate(server.as_handle(), RESERVED_KEY)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        port.post(RESERVED_KEY, 0, 0).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

/// The environment variable that turns this test binary into the peer
/// process for `a_peer_process_posts_through_a_duplicated_port_handle`:
/// `<parent pid>:<port handle value in the parent>`.
const CHILD_ENV: &str = "VMM_SYS_UTIL_COMPLETION_CHILD";

/// The peer side of the cross-process test. Does nothing unless spawned as
/// the peer, so it passes trivially in a normal run.
///
/// Mirrors the verification program the design rests on: pull the port
/// handle out of the parent with `DuplicateHandle` (as a front-end does for
/// back-end-owned handles), post through it; take a handle the parent
/// pushed in, post through that; then post a burst and exit.
#[test]
fn cross_process_child() {
    let Ok(spec) = std::env::var(CHILD_ENV) else {
        return;
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_DUP_HANDLE};

    let (pid, value) = spec.split_once(':').expect("pid:handle");
    let parent_pid: u32 = pid.parse().unwrap();
    let parent_port = value.parse::<usize>().unwrap() as HANDLE;

    // SAFETY: plain open; checked before use.
    let parent = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, parent_pid) };
    assert!(
        !parent.is_null(),
        "OpenProcess: {}",
        io::Error::last_os_error()
    );
    let mut pulled: HANDLE = null_mut();
    // SAFETY: `parent` is open; `pulled` is a valid out-pointer. The value
    // is the parent's, which is what DuplicateHandle expects.
    let ok = unsafe {
        DuplicateHandle(
            parent,
            parent_port,
            GetCurrentProcess(),
            &mut pulled,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert_ne!(
        ok,
        0,
        "DuplicateHandle (pull): {}",
        io::Error::last_os_error()
    );
    // SAFETY: `pulled` is open and owned here.
    let pulled = unsafe { OwnedHandle::from_raw_handle(pulled as RawHandle) };
    post(pulled.as_handle(), 0xA, 42, 0xA11CE).unwrap();

    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    let pushed = line.trim().parse::<usize>().unwrap() as RawHandle;
    // SAFETY: the parent duplicated this handle into this process and it
    // is owned by nothing else here.
    let pushed = unsafe { OwnedHandle::from_raw_handle(pushed) };
    post(pushed.as_handle(), 0xB, 43, 0xB0B).unwrap();
    for i in 0..1000u32 {
        post(pushed.as_handle(), 0xC, i, 0).unwrap();
    }
    // SAFETY: `parent` is owned here and closed once.
    unsafe { CloseHandle(parent) };
}

#[test]
fn a_peer_process_posts_through_a_duplicated_port_handle() {
    use std::process::{Command, Stdio};

    let port = Port::new().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "windows::completion::tests::cross_process_child"])
        .env(
            CHILD_ENV,
            format!("{}:{}", std::process::id(), port.as_raw_handle() as usize),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    // Push a duplicate into the child and tell it the value.
    let mut in_child: HANDLE = null_mut();
    // SAFETY: the child's process handle is open for `child`; `in_child`
    // is a valid out-pointer.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            port.as_raw_handle() as HANDLE,
            child.as_raw_handle() as HANDLE,
            &mut in_child,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert_ne!(
        ok,
        0,
        "DuplicateHandle (push): {}",
        io::Error::last_os_error()
    );
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", in_child as usize).unwrap();
    drop(stdin);

    // Both posts arrive with key, byte count and pointer intact. The
    // burst follows the second post at once, so the batch that carries
    // the post can carry the start of the burst too: count both from the
    // start.
    let mut seen = std::collections::HashMap::new();
    let mut burst = 0;
    let mut out = Vec::new();
    while seen.len() < 2 {
        out.clear();
        assert_ne!(
            port.wait(TIMEOUT, &mut out).unwrap(),
            0,
            "a peer's post did not arrive; child status {:?}",
            child.try_wait()
        );
        for c in out.drain(..) {
            match c {
                Completion::Posted {
                    key,
                    bytes,
                    pointer,
                } if key == 0xA || key == 0xB => {
                    seen.insert(key, (bytes, pointer));
                }
                Completion::Posted { key: 0xC, .. } => burst += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    assert_eq!(
        seen[&0xA],
        (42, 0xA11CE),
        "posted via the handle the child pulled"
    );
    assert_eq!(
        seen[&0xB],
        (43, 0xB0B),
        "posted via the handle the parent pushed"
    );

    let status = child.wait().unwrap();
    assert!(status.success(), "child exited with {status}");

    // The rest of the burst is still there after the child is gone.
    while burst < 1000 {
        out.clear();
        if port.wait(Some(Duration::from_secs(1)), &mut out).unwrap() == 0 {
            break;
        }
        burst += out
            .iter()
            .filter(|c| matches!(c, Completion::Posted { key: 0xC, .. }))
            .count();
    }
    assert_eq!(burst, 1000, "burst completions drained after child exit");
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

fn timer_keys(out: &[Completion]) -> Vec<usize> {
    out.iter()
        .map(|c| match c {
            Completion::Timer { key } => *key,
            other => panic!("expected a timer completion, got {other:?}"),
        })
        .collect()
}

#[test]
fn a_timer_fires_once_with_its_key() {
    let port = Port::new().unwrap();
    let timer = Timer::new(&port, 77).unwrap();
    let started = Instant::now();
    timer.set(Duration::from_millis(50));

    let mut out = Vec::new();
    assert_eq!(port.wait(TIMEOUT, &mut out).unwrap(), 1);
    assert_eq!(timer_keys(&out), vec![77]);
    assert!(started.elapsed() >= Duration::from_millis(40));

    // One shot: silence afterwards.
    out.clear();
    assert_eq!(port.wait(SHORT, &mut out).unwrap(), 0);
}

#[test]
fn a_cancelled_timer_does_not_fire() {
    let port = Port::new().unwrap();
    let timer = Timer::new(&port, 1).unwrap();
    timer.set(Duration::from_millis(200));
    timer.cancel();

    let mut out = Vec::new();
    assert_eq!(
        port.wait(Some(Duration::from_millis(400)), &mut out)
            .unwrap(),
        0
    );
}

#[test]
fn a_dropped_timer_leaves_no_stale_delivery() {
    // A packet posted before the drop is skipped, not delivered under a
    // retired token, and a second timer with the same key is unaffected.
    let port = Port::new().unwrap();
    let timer = Timer::new(&port, 3).unwrap();
    timer.set(Duration::from_millis(10));
    std::thread::sleep(Duration::from_millis(100));
    drop(timer);

    let mut out = Vec::new();
    assert_eq!(
        port.wait(SHORT, &mut out).unwrap(),
        0,
        "stale timer delivered"
    );

    let again = Timer::new(&port, 3).unwrap();
    again.set(Duration::from_millis(10));
    assert_eq!(port.wait(TIMEOUT, &mut out).unwrap(), 1);
    assert_eq!(timer_keys(&out), vec![3]);
}

#[test]
fn a_timer_outlives_its_port_harmlessly() {
    let timer = {
        let port = Port::new().unwrap();
        Timer::new(&port, 1).unwrap()
    };
    timer.set(Duration::from_millis(10));
    std::thread::sleep(Duration::from_millis(100));
    // Nothing to assert beyond "no crash": the expiry had nowhere to go.
    drop(timer);
}

#[test]
fn a_thousand_timer_cycles_leak_no_handles() {
    const N: u32 = 1000;
    let port = Port::new().unwrap();
    // Warm-up so lazily created thread-pool machinery is not counted.
    {
        let t = Timer::new(&port, 0).unwrap();
        t.set(Duration::from_millis(1));
        let mut out = Vec::new();
        while port.wait(Some(Duration::from_secs(1)), &mut out).unwrap() == 0 {}
    }
    let before = crate::windows::process_handle_count();
    for i in 0..N {
        let t = Timer::new(&port, i as usize).unwrap();
        t.set(Duration::from_millis(1));
        drop(t);
    }
    let after = crate::windows::process_handle_count();
    assert!(
        after.saturating_sub(before) < N / 2,
        "handle count grew from {before} to {after} over {N} cycles"
    );
}
