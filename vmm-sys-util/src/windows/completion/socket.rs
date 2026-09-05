// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Socket submissions for a [`Port`]: accept, receive and send.
//!
//! This is the only file in the completion module that links Winsock. A
//! program that never calls into it never initialises Winsock. Nothing here
//! initialises Winsock either: the caller creates the sockets, and whatever
//! created them (`std::net`, or a direct `WSAStartup`) has already done it.
//!
//! A socket is a kernel handle underneath, and the completion port treats
//! it as one. [`associate`] does the documented `SOCKET`-to-`HANDLE`
//! conversion; the submissions here cast the same way, once, at the call.
//! The contract in the module header applies unchanged: the buffer belongs
//! to the [`Operation`] until it comes back, cancellation goes through
//! [`Port::cancel`] and completes with an error, and the port drains
//! everything on drop.
//!
//! `AcceptEx` on an `AF_UNIX` listener, with the accepted socket then
//! carrying overlapped sends and receives through the same port, was
//! verified on Windows 11 before this was written; a test below repeats
//! that verification.

use std::any::Any;
use std::io;
use std::os::windows::io::{AsRawSocket, BorrowedSocket, OwnedSocket};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, WSAIoctl, WSARecv, WSASend, LPFN_ACCEPTEX,
    SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, SOL_SOCKET,
    SO_UPDATE_ACCEPT_CONTEXT, WSABUF, WSAID_ACCEPTEX, WSA_IO_PENDING,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::{Operation, Port, Token};

/// How much of an accept operation's buffer each address takes: the
/// largest socket address plus the 16 bytes `AcceptEx` requires after it.
const ADDRESS_LEN: usize = std::mem::size_of::<SOCKADDR_STORAGE>() + 16;

/// The smallest buffer an [`accept`] operation may carry: room for the
/// local and remote addresses of any family.
pub const ACCEPT_BUFFER_LEN: usize = 2 * ADDRESS_LEN;

/// Route every operation submitted on `socket` to `port`, reported under
/// `key`. The socket equivalent of [`Port::associate`], with the same rules:
/// once per socket, for the life of the socket, and not [`super::RESERVED_KEY`].
pub fn associate(port: &Port, socket: BorrowedSocket<'_>, key: usize) -> io::Result<()> {
    port.associate_raw(socket.as_raw_socket() as HANDLE, key)
}

/// Submit a receive into `operation`'s whole buffer.
///
/// Completes with the byte count received, which is zero when the peer has
/// closed its side. The socket must be associated with `port`.
pub fn recv(
    port: &Port,
    socket: BorrowedSocket<'_>,
    mut operation: Operation,
) -> io::Result<Token> {
    let sock = socket.as_raw_socket() as SOCKET;
    let (ptr, len) = operation.io_range()?;
    port.submit(sock as HANDLE, operation, |block| {
        // The WSABUF array only has to live for the call; the memory it
        // points at is the operation's buffer, which the port now owns.
        let buf = WSABUF { len, buf: ptr };
        let mut flags = 0u32;
        // SAFETY: `block` is the operation's block at a fixed address the
        // port owns; `buf` and `flags` are valid for the call.
        let ret = unsafe {
            WSARecv(
                sock,
                &buf,
                1,
                null_mut(),
                &mut flags,
                block as *mut OVERLAPPED,
                None,
            )
        };
        outstanding(ret)
    })
}

/// Submit a send of `operation`'s whole buffer.
///
/// Completes with the byte count sent. The socket must be associated with
/// `port`.
pub fn send(
    port: &Port,
    socket: BorrowedSocket<'_>,
    mut operation: Operation,
) -> io::Result<Token> {
    let sock = socket.as_raw_socket() as SOCKET;
    let (ptr, len) = operation.io_range()?;
    port.submit(sock as HANDLE, operation, |block| {
        let buf = WSABUF { len, buf: ptr };
        // SAFETY: as in `recv`.
        let ret = unsafe { WSASend(sock, &buf, 1, null_mut(), 0, block as *mut OVERLAPPED, None) };
        outstanding(ret)
    })
}

/// The socket an accept is filling in, kept in the operation's held slot
/// until [`finish_accept`] takes it out. The type is private so that only
/// `finish_accept`, which also updates the socket's accept context, can
/// hand it back.
struct Accepting(OwnedSocket);

/// Submit an accept on `listener`, into `accepted`.
///
/// `accepted` is a fresh, unbound socket of the listener's family; it is
/// kept in the operation's held slot until the completion is dequeued and
/// [`finish_accept`] is called on it, so the operation must be holding
/// nothing else. The buffer must be at least [`ACCEPT_BUFFER_LEN`] bytes;
/// the kernel writes the two addresses into it. No data is received with
/// the accept, so the completion arrives as soon as a client connects. The
/// listener must be associated with `port`.
///
/// One accept outstanding per listener at a time is the usual shape:
/// resubmit on each completion.
pub fn accept(
    port: &Port,
    listener: BorrowedSocket<'_>,
    accepted: OwnedSocket,
    mut operation: Operation,
) -> io::Result<Token> {
    if operation.holds_something() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an accept operation keeps the accepted socket in the held slot, which is occupied",
        ));
    }
    if operation.buffer().len() < ACCEPT_BUFFER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("an accept operation needs a buffer of at least {ACCEPT_BUFFER_LEN} bytes"),
        ));
    }
    let listen_sock = listener.as_raw_socket() as SOCKET;
    let accept_sock = accepted.as_raw_socket() as SOCKET;
    let acceptex = accept_ex(listen_sock)?;
    let (ptr, _) = operation.io_range()?;
    operation.hold(Box::new(Accepting(accepted)));

    port.submit(listen_sock as HANDLE, operation, |block| {
        let mut received = 0u32;
        // SAFETY: `block` and the buffer belong to the port now; the
        // accepted socket is held by the operation for as long as the
        // request is outstanding; `received` is valid for the call.
        let ok = unsafe {
            acceptex(
                listen_sock,
                accept_sock,
                ptr.cast(),
                0,
                ADDRESS_LEN as u32,
                ADDRESS_LEN as u32,
                &mut received,
                block as *mut OVERLAPPED,
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            outstanding(SOCKET_ERROR)
        }
    })
}

/// Take the accepted socket out of a completed [`accept`] operation and
/// make it a normal connected socket.
///
/// `SO_UPDATE_ACCEPT_CONTEXT` is what gives a socket accepted by `AcceptEx`
/// its peer name and the ordinary socket options; without it,
/// `getpeername` and `shutdown` on the socket fail. Call this after the
/// completion reports success. On failure the socket is dropped and
/// therefore closed. `InvalidInput` if the operation is not one that
/// [`accept`] submitted.
pub fn finish_accept(
    listener: BorrowedSocket<'_>,
    operation: &mut Operation,
) -> io::Result<OwnedSocket> {
    let held: Box<dyn Any + Send> = operation.take_held().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "not an accept operation: nothing is held",
        )
    })?;
    let socket = match held.downcast::<Accepting>() {
        Ok(accepting) => accepting.0,
        Err(other) => {
            operation.hold(other);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an accept operation: what it holds is not an accepted socket",
            ));
        }
    };
    let listen_sock = listener.as_raw_socket() as SOCKET;
    // SAFETY: the option value is the listener's SOCKET, of the documented
    // size, valid for the call.
    let ret = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_UPDATE_ACCEPT_CONTEXT,
            &listen_sock as *const SOCKET as *const u8,
            std::mem::size_of::<SOCKET>() as i32,
        )
    };
    if ret == SOCKET_ERROR {
        return Err(last_winsock_error());
    }
    Ok(socket)
}

/// Whether an overlapped Winsock call left its request outstanding.
/// `WSA_IO_PENDING` is the normal case; immediate success still queues a
/// packet.
fn outstanding(ret: i32) -> io::Result<()> {
    if ret != SOCKET_ERROR {
        return Ok(());
    }
    let err = last_winsock_error();
    if err.raw_os_error() == Some(WSA_IO_PENDING) {
        Ok(())
    } else {
        Err(err)
    }
}

fn last_winsock_error() -> io::Error {
    // SAFETY: reads the thread's last Winsock error.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// Fetch `AcceptEx` from the listener's provider.
///
/// `AcceptEx` is a Microsoft extension, not a Winsock export; the provider
/// behind a socket hands it out through this ioctl. Fetching it per call
/// is one ioctl per accept, which is nothing next to the accept itself,
/// and avoids caching a pointer across providers.
fn accept_ex(
    listener: SOCKET,
) -> io::Result<
    unsafe extern "system" fn(
        SOCKET,
        SOCKET,
        *mut std::ffi::c_void,
        u32,
        u32,
        u32,
        *mut u32,
        *mut OVERLAPPED,
    ) -> i32,
> {
    let mut acceptex: LPFN_ACCEPTEX = None;
    let mut bytes = 0u32;
    let guid = WSAID_ACCEPTEX;
    // SAFETY: the in and out buffers are valid for their stated sizes for
    // the duration of the call.
    let ret = unsafe {
        WSAIoctl(
            listener,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid as *const _ as *const std::ffi::c_void,
            std::mem::size_of_val(&guid) as u32,
            &mut acceptex as *mut LPFN_ACCEPTEX as *mut std::ffi::c_void,
            std::mem::size_of::<LPFN_ACCEPTEX>() as u32,
            &mut bytes,
            null_mut(),
            None,
        )
    };
    if ret == SOCKET_ERROR {
        return Err(last_winsock_error());
    }
    acceptex.ok_or_else(|| io::Error::other("the socket's provider has no AcceptEx"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::Completion;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::io::{AsSocket, FromRawSocket};
    use std::time::Duration;

    use windows_sys::Win32::Networking::WinSock::{
        bind, connect, listen, socket, WSAStartup, AF_INET, AF_UNIX, INVALID_SOCKET, IPPROTO_TCP,
        SOCKADDR, SOCKADDR_UN, SOCK_STREAM, WSADATA,
    };

    const TIMEOUT: Option<Duration> = Some(Duration::from_secs(5));

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    /// A fresh socket of `family`, for `accept` to fill in.
    fn fresh_socket(family: u16, protocol: i32) -> OwnedSocket {
        // SAFETY: plain create; checked before use.
        let s = unsafe { socket(family as i32, SOCK_STREAM, protocol) };
        assert_ne!(s, INVALID_SOCKET, "{}", last_winsock_error());
        // SAFETY: `s` is open and owned by nothing else.
        unsafe { OwnedSocket::from_raw_socket(s as _) }
    }

    /// Wait for one operation completion and return it.
    fn one_operation(port: &Port) -> (usize, io::Result<usize>, Operation) {
        let mut out = Vec::new();
        assert_eq!(port.wait(TIMEOUT, &mut out).unwrap(), 1);
        match out.pop().unwrap() {
            Completion::Operation {
                key,
                result,
                operation,
            } => (key, result, operation),
            other => panic!("expected an operation completion, got {other:?}"),
        }
    }

    #[test]
    fn a_receive_completes_with_the_bytes_the_peer_sent() {
        let port = Port::new().unwrap();
        let (mut client, server) = tcp_pair();
        associate(&port, server.as_socket(), 7).unwrap();

        let token = recv(&port, server.as_socket(), Operation::new(vec![0; 16])).unwrap();
        client.write_all(b"ping").unwrap();

        let (key, result, op) = one_operation(&port);
        assert_eq!(key, 7);
        assert_eq!(result.unwrap(), 4);
        assert_eq!(&op.buffer()[..4], b"ping");
        assert_eq!(op.token(), token);
    }

    #[test]
    fn a_send_completes_with_its_byte_count_and_the_peer_reads_it() {
        let port = Port::new().unwrap();
        let (mut client, server) = tcp_pair();
        associate(&port, server.as_socket(), 8).unwrap();

        send(&port, server.as_socket(), Operation::new(b"pong!".to_vec())).unwrap();
        let (key, result, op) = one_operation(&port);
        assert_eq!(key, 8);
        assert_eq!(result.unwrap(), 5);
        assert_eq!(op.into_buffer(), b"pong!");

        let mut got = [0u8; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"pong!");
    }

    #[test]
    fn a_receive_cancelled_before_data_arrives_completes_with_an_error() {
        // Sockets go through the same cancel path as handles: CancelIoEx on
        // the socket cast to a handle.
        let port = Port::new().unwrap();
        let (_client, server) = tcp_pair();
        associate(&port, server.as_socket(), 1).unwrap();

        let token = recv(&port, server.as_socket(), Operation::new(vec![0; 16])).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            port.wait(Some(Duration::from_millis(100)), &mut out)
                .unwrap(),
            0
        );
        port.cancel(token).unwrap();

        let (_, result, _) = one_operation(&port);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(995));
        assert_eq!(port.outstanding(), 0);
    }

    #[test]
    fn an_accept_completes_when_a_client_connects() {
        let port = Port::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        associate(&port, listener.as_socket(), 3).unwrap();

        let fresh = fresh_socket(AF_INET, IPPROTO_TCP);
        accept(
            &port,
            listener.as_socket(),
            fresh,
            Operation::new(vec![0; ACCEPT_BUFFER_LEN]),
        )
        .unwrap();

        let mut out = Vec::new();
        assert_eq!(
            port.wait(Some(Duration::from_millis(100)), &mut out)
                .unwrap(),
            0,
            "no client yet"
        );

        let mut client = TcpStream::connect(addr).unwrap();
        let (key, result, mut op) = one_operation(&port);
        assert_eq!(key, 3);
        assert_eq!(result.unwrap(), 0, "no data was asked for with the accept");

        let accepted = finish_accept(listener.as_socket(), &mut op).unwrap();
        assert!(!op.holds_something());

        // A normal connected socket from here on: data flows both ways.
        let mut server = TcpStream::from(accepted);
        client.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        assert!(
            server.peer_addr().is_ok(),
            "SO_UPDATE_ACCEPT_CONTEXT took effect"
        );
    }

    #[test]
    fn an_accept_refuses_a_buffer_too_small_for_the_addresses() {
        let port = Port::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        associate(&port, listener.as_socket(), 3).unwrap();
        let err = accept(
            &port,
            listener.as_socket(),
            fresh_socket(AF_INET, IPPROTO_TCP),
            Operation::new(vec![0; ACCEPT_BUFFER_LEN - 1]),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn finish_accept_refuses_an_operation_that_is_not_an_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut op = Operation::new(vec![0; 8]);
        let err = finish_accept(listener.as_socket(), &mut op).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Something else held is handed back, not lost.
        op.hold(Box::new(42u32));
        let err = finish_accept(listener.as_socket(), &mut op).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(*op.take_held().unwrap().downcast::<u32>().unwrap(), 42);
    }

    /// Repeats the verification the design rests on: `AcceptEx` on an
    /// `AF_UNIX` listener completes through the port, and the accepted
    /// socket carries overlapped sends and receives through the same port.
    #[test]
    fn an_accept_on_an_af_unix_listener_completes_through_the_port() {
        // Raw Winsock sockets need Winsock started; std would have done it
        // for a TcpListener, but nothing here uses one.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: `data` is a valid out-buffer.
        assert_eq!(unsafe { WSAStartup(0x0202, &mut data) }, 0);

        let path = std::env::temp_dir().join(format!(
            "vmm-sys-util-completion-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut addr: SOCKADDR_UN = unsafe { std::mem::zeroed() };
        addr.sun_family = AF_UNIX;
        assert!(
            path_bytes.len() < addr.sun_path.len(),
            "socket path too long"
        );
        for (dst, &src) in addr.sun_path.iter_mut().zip(path_bytes) {
            *dst = src as i8;
        }
        let addr_len = std::mem::size_of::<SOCKADDR_UN>() as i32;

        let listener = fresh_socket(AF_UNIX, 0);
        let l = listener.as_raw_socket() as SOCKET;
        // SAFETY: `addr` is a valid SOCKADDR_UN of the stated length.
        unsafe {
            assert_eq!(
                bind(l, &addr as *const _ as *const SOCKADDR, addr_len),
                0,
                "{}",
                last_winsock_error()
            );
            assert_eq!(listen(l, 1), 0, "{}", last_winsock_error());
        }

        let port = Port::new().unwrap();
        associate(&port, listener.as_socket(), 1).unwrap();
        accept(
            &port,
            listener.as_socket(),
            fresh_socket(AF_UNIX, 0),
            Operation::new(vec![0; ACCEPT_BUFFER_LEN]),
        )
        .unwrap();

        let client = std::thread::spawn(move || {
            let c = fresh_socket(AF_UNIX, 0);
            let cs = c.as_raw_socket() as SOCKET;
            // SAFETY: as for bind above.
            let ret = unsafe { connect(cs, &addr as *const _ as *const SOCKADDR, addr_len) };
            assert_eq!(ret, 0, "{}", last_winsock_error());
            // A plain blocking exchange on the client side.
            let mut buf = [0u8; 4];
            // SAFETY: `buf` is valid for the call.
            let n = unsafe {
                windows_sys::Win32::Networking::WinSock::recv(cs, buf.as_mut_ptr(), 4, 0)
            };
            assert_eq!(n, 4);
            assert_eq!(&buf, b"ping");
            // SAFETY: the literal is valid for the call.
            let n = unsafe {
                windows_sys::Win32::Networking::WinSock::send(cs, b"pong".as_ptr(), 4, 0)
            };
            assert_eq!(n, 4);
            drop(c);
        });

        let (key, result, mut op) = one_operation(&port);
        assert_eq!(key, 1);
        result.unwrap();
        let accepted = finish_accept(listener.as_socket(), &mut op).unwrap();
        associate(&port, accepted.as_socket(), 2).unwrap();

        send(
            &port,
            accepted.as_socket(),
            Operation::new(b"ping".to_vec()),
        )
        .unwrap();
        let (key, result, _) = one_operation(&port);
        assert_eq!(key, 2);
        assert_eq!(result.unwrap(), 4);

        recv(&port, accepted.as_socket(), Operation::new(vec![0; 16])).unwrap();
        let (key, result, op) = one_operation(&port);
        assert_eq!(key, 2);
        assert_eq!(result.unwrap(), 4);
        assert_eq!(&op.buffer()[..4], b"pong");

        client.join().unwrap();
        drop(accepted);
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }
}
