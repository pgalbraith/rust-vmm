// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Talks to the Windows AFD driver, the layer under Winsock, to ask whether a
//! socket is ready to read or write.
//!
//! **None of this is documented or supported by Microsoft.** `\Device\Afd` is
//! in no SDK header and has no MSDN page. It is used here because there is no
//! supported way to get level-triggered readiness for sockets and waitable
//! handles from a single wait, and because every other project that needed
//! that reached the same driver: libuv, mio, OpenJDK (which vendors wepoll),
//! Trio, and Microsoft's own OpenVMM. `docs/windows-socket-polling.md` has the
//! reasoning, the references, and what to do if it ever stops working.
//!
//! Every call here reports failure as an ordinary `io::Error`. Nothing panics
//! and nothing hangs, so a future Windows that changes this interface gives
//! callers an error they can report rather than a crash.

use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{NtOpenFile, FILE_OPEN};
use windows_sys::Wdk::System::IO::NtDeviceIoControlFile;
use windows_sys::Win32::Foundation::{HANDLE, STATUS_PENDING, STATUS_SUCCESS, UNICODE_STRING};
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAIoctl, SIO_BASE_HANDLE, SIO_BSP_HANDLE, SIO_BSP_HANDLE_POLL,
    SIO_BSP_HANDLE_SELECT, SOCKET, SOCKET_ERROR,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// What the driver reports, and what it accepts as interest.
///
/// Only the bits this crate maps are named. The set is wider.
pub const POLL_RECEIVE: u32 = 1 << 0;
pub const POLL_RECEIVE_EXPEDITED: u32 = 1 << 1;
pub const POLL_SEND: u32 = 1 << 2;
pub const POLL_DISCONNECT: u32 = 1 << 3;
pub const POLL_ABORT: u32 = 1 << 4;
pub const POLL_LOCAL_CLOSE: u32 = 1 << 5;
pub const POLL_CONNECT: u32 = 1 << 6;
pub const POLL_ACCEPT: u32 = 1 << 7;
pub const POLL_CONNECT_FAIL: u32 = 1 << 8;

/// Everything that means "something happened", whatever the caller asked for.
/// The driver reports these whether or not they were requested, and a caller
/// waiting to read has to hear about a connection that died.
pub const POLL_ALWAYS: u32 = POLL_ABORT | POLL_LOCAL_CLOSE | POLL_CONNECT_FAIL;

const IOCTL_AFD_POLL: u32 = 0x0001_2024;

/// `\Device\Afd\vmm-sys-util`, as a counted UTF-16 string.
///
/// The path after `\Device\Afd` is free-form: the driver ignores it, and it
/// exists only to make the handle recognisable in a debugger or handle dump.
const DEVICE_NAME: &[u16] = &[
    0x005c, 0x0044, 0x0065, 0x0076, 0x0069, 0x0063, 0x0065, 0x005c, 0x0041, 0x0066, 0x0064, 0x005c,
    0x0076, 0x006d, 0x006d, 0x002d, 0x0073, 0x0079, 0x0073, 0x002d, 0x0075, 0x0074, 0x0069, 0x006c,
];

/// One socket's entry in a poll request. Laid out for the driver.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollHandleInfo {
    pub handle: HANDLE,
    pub events: u32,
    pub status: i32,
}

/// A poll request, and the buffer the driver writes the answer into.
///
/// The driver takes the same structure for input and output. This crate asks
/// about one socket at a time, so `handles` holds exactly one entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollInfo {
    /// In 100ns units. Negative is relative. `i64::MAX` means "no timeout",
    /// which is what this crate wants: the request stays outstanding until
    /// the socket is ready or the request is cancelled.
    pub timeout: i64,
    pub number_of_handles: u32,
    pub exclusive: u32,
    pub handles: [PollHandleInfo; 1],
}

impl PollInfo {
    /// A request asking about `handle` for `events`, with no timeout.
    pub fn new(handle: HANDLE, events: u32) -> Self {
        PollInfo {
            timeout: i64::MAX,
            number_of_handles: 1,
            exclusive: 0,
            handles: [PollHandleInfo {
                handle,
                events,
                status: 0,
            }],
        }
    }
}

/// Open `\Device\Afd`.
///
/// Opened with no extended attributes, which is what makes the driver accept
/// the poll ioctl. wepoll and OpenVMM both note the same thing.
pub fn open() -> io::Result<OwnedHandle> {
    let mut name = UNICODE_STRING {
        Length: (DEVICE_NAME.len() * 2) as u16,
        MaximumLength: (DEVICE_NAME.len() * 2) as u16,
        Buffer: DEVICE_NAME.as_ptr() as *mut u16,
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &mut name,
        Attributes: 0,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };

    let mut handle: HANDLE = null_mut();
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is to a local that outlives the call, and
    // `handle` is a valid out-parameter.
    let status = unsafe {
        NtOpenFile(
            &mut handle,
            SYNCHRONIZE,
            &attrs,
            &mut iosb,
            // The driver is shared: everyone polling sockets has it open.
            0x7, // FILE_SHARE_READ | WRITE | DELETE
            FILE_OPEN,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(nt_error(status, "opening \\Device\\Afd"));
    }
    // SAFETY: `NtOpenFile` succeeded, so `handle` owns an open file object
    // and nothing else holds it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

/// Start a poll on one socket.
///
/// Returns `Ok(true)` if the answer is already in `info`, `Ok(false)` if the
/// request is outstanding and will complete on the completion port the AFD
/// handle is associated with.
///
/// The completion identifies this request by the address of `iosb`, which is
/// passed as the request's APC context. That is where the NT API takes the
/// pointer it reports as `lpOverlapped` from -- not from the status block
/// argument, despite the two being the same address here.
///
/// `iosb` and `info` are written by the kernel after this returns, so they
/// must stay at the same address, and stay alive, until the completion
/// arrives or the request is cancelled and its completion collected.
///
/// # Safety
///
/// `iosb` and `info` must remain valid and pinned until this request
/// completes.
pub unsafe fn poll(
    afd: HANDLE,
    info: *mut PollInfo,
    iosb: *mut IO_STATUS_BLOCK,
) -> io::Result<bool> {
    // SAFETY: the caller guarantees both pointers stay valid until the
    // request completes; the driver reads and writes only within them.
    unsafe {
        (*iosb).Anonymous.Status = STATUS_PENDING;
        let status = NtDeviceIoControlFile(
            afd,
            null_mut(),
            None,
            iosb.cast(),
            iosb,
            IOCTL_AFD_POLL,
            info.cast(),
            size_of::<PollInfo>() as u32,
            info.cast(),
            size_of::<PollInfo>() as u32,
        );
        match status {
            STATUS_SUCCESS => Ok(true),
            STATUS_PENDING => Ok(false),
            other => Err(nt_error(other, "IOCTL_AFD_POLL")),
        }
    }
}

/// The socket the driver knows about.
///
/// A layered service provider (LSP) can sit in front of a socket, and then the
/// handle the application holds is not the one AFD polls. `SIO_BASE_HANDLE`
/// asks for the real one. mio records that at least one LSP deliberately
/// breaks that query, so the other three are tried in turn; they are less
/// correct but are not intercepted in the same way.
pub fn base_socket(sock: SOCKET) -> io::Result<SOCKET> {
    if let Ok(base) = try_ioctl(sock, SIO_BASE_HANDLE) {
        return Ok(base);
    }
    for ioctl in [SIO_BSP_HANDLE_SELECT, SIO_BSP_HANDLE_POLL, SIO_BSP_HANDLE] {
        if let Ok(base) = try_ioctl(sock, ioctl) {
            if base != sock {
                return Ok(base);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "cannot find the base socket to poll; a layered service provider may be in the way",
    ))
}

fn try_ioctl(sock: SOCKET, ioctl: u32) -> io::Result<SOCKET> {
    let mut base: SOCKET = 0;
    let mut bytes: u32 = 0;
    // SAFETY: `base` and `bytes` are valid out-parameters for the duration of
    // the call, sized as the ioctl expects.
    let ret = unsafe {
        WSAIoctl(
            sock,
            ioctl,
            null(),
            0,
            (&mut base as *mut SOCKET).cast(),
            size_of::<SOCKET>() as u32,
            &mut bytes,
            null_mut(),
            None,
        )
    };
    if ret == SOCKET_ERROR {
        // SAFETY: reads this thread's last Winsock error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(base)
}

/// An NTSTATUS as an `io::Error`, with what was being attempted.
///
/// The status is reported as-is rather than mapped: these codes are not the
/// Win32 errors `io::Error::from_raw_os_error` names, so inventing a mapping
/// would lose which call failed.
fn nt_error(status: i32, doing: &str) -> io::Error {
    io::Error::other(format!("{doing} failed: NTSTATUS {status:#010x}"))
}
