# vmm-sys-util

[![crates.io](https://img.shields.io/crates/v/vmm-sys-util)](https://crates.io/crates/vmm-sys-util)
[![docs.rs](https://img.shields.io/docsrs/vmm-sys-util)](https://docs.rs/vmm-sys-util/)

This crate is a collection of modules that provides helpers and utilities
used by multiple [rust-vmm](https://github.com/rust-vmm/community) components.

The crate implements safe wrappers around common utilities for working
with files, event file descriptors, ioctls and others.

## Support

**Platforms**:
- x86_64
- aarch64
- riscv64

**Operating Systems**:
- Linux
- Windows (partial support)

## Windows socket polling uses an undocumented interface

`Epoll` on Windows polls sockets through the Windows **AFD driver**
(`\Device\Afd`, `IOCTL_AFD_POLL`), which is **not a documented or supported
Windows API**. There is no supported way to get level-triggered readiness for
sockets and waitable handles from a single wait, so every project that has
needed `epoll` semantics on Windows has reached the same driver:

| Project | Where |
| --- | --- |
| **libuv** | `src/win/poll.c`, `src/win/winsock.c` (`uv_msafd_poll`, `AFD_POLL_INFO`) |
| **mio** (Tokio) | `src/sys/windows/afd.rs`, `src/sys/windows/selector.rs` |
| **OpenJDK** 17+ | `.../libnio/ch/wepoll.c` (vendored wepoll) + `sun/nio/ch/WEPoll.java`, `WEPollSelectorImpl.java`, `WEPollPoller.java` -- JDK-8266369 |
| **Trio** (Python) | `trio/_core/_io_windows.py` -- AFD polls completed through IOCP |
| **OpenVMM** (Microsoft) | `support/pal/src/windows/afd.rs`, `pal_async/src/windows/socket.rs` |

Microsoft's own position is that Windows programs should use completion I/O
rather than readiness polling, and there is no supported readiness API. That
is why five separate projects went under the covers for one.

[docs/windows-socket-polling.md](docs/windows-socket-polling.md) has the
reasoning, what the risk is and how to bound it, the full references, and
notes for anyone implementing it.

## License

This code is licensed under [BSD-3-Clause](LICENSE-BSD-3-Clause).
