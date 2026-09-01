# Windows socket polling

## Decision

`Epoll` on Windows polls sockets through the **AFD driver** -- `\Device\Afd`,
driven by `NtDeviceIoControlFile` with `IOCTL_AFD_POLL` (`0x00012024`), with
the results collected on the same I/O completion port the rest of `Epoll`
already uses.

**AFD is not a documented or supported Windows interface.** It appears in no
SDK header and has no MSDN contract; Microsoft is free to change it. That is
a real cost, taken with open eyes, and the rest of this document explains why
it is still the right call and who else has made it.

## Why the supported APIs do not work

`epoll` promises three things at once: readiness (not completion) notification,
level-triggered semantics, and a single wait that covers sockets *and* other
waitable objects. Windows offers no supported way to get all three.

| Supported option | Why it fails here |
| --- | --- |
| `select` / `WSAPoll` | O(n) in *registered* sockets on every call, not in ready ones. Cannot wait on a `HANDLE` at the same time, so handle signals need a side channel. `WSAPoll` also does not report a failed non-blocking `connect` -- a long-acknowledged defect. |
| `WSAEventSelect` | Edge-triggered (`FD_WRITE` re-arms only after a send fails), and it forces the socket into non-blocking mode. Winsock gives no way to keep event notification and blocking mode together, so registering a socket would silently change its semantics for its owner. |
| IOCP alone | Completion-based. There is no way to express "tell me when this is readable" without issuing the read yourself and thereby owning the buffer -- which a readiness-based caller cannot do. |
| A thread per socket | Scales with sockets rather than with activity, and multiplies the shutdown races. |

AFD is the layer beneath Winsock that all of these are built on. Asking it
directly is the only way to get readiness without also taking ownership of the
I/O, and it delivers through the IOCP, so sockets and handles arrive in one
wait.

## Prior art: everyone with this problem has landed here

This is the cross-reference to keep. Four independent projects -- one of them
Microsoft's own -- reached the same undocumented driver, and three of them
carry the identical `0x00012024` constant.

### libuv (C) -- github.com/libuv/libuv

The original, from Bert Belder's `epoll_windows`.

- `src/win/winsock.h` -- declares `AFD_POLL_INFO` and `uv_msafd_poll`
- `src/win/winsock.c` -- `uv_msafd_poll()`, plus the MSAFD provider GUIDs
  (`uv_msafd_provider_ids`) used to decide whether a socket is pollable
- `src/win/poll.c` -- the `uv_poll_t` implementation; falls back to `select`
  on a thread when the socket is not an MSAFD one

### mio (Rust) -- github.com/tokio-rs/mio

The dependency Tokio is built on, and the reference implementation for Rust.

- `src/sys/windows/afd.rs` -- `IOCTL_AFD_POLL = 0x00012024`, `AfdPollInfo`,
  and `Afd::poll()` over `NtDeviceIoControlFile`
- `src/sys/windows/selector.rs` -- `SockState` and the per-socket re-arm loop;
  `get_base_socket()` resolves the base socket before polling
- Rationale and history: tokio-rs/mio issue #281

### OpenJDK (C + Java) -- github.com/openjdk/jdk

JDK 17 and later, added by **JDK-8266369 "(se) Add wepoll based Selector"**
(2021-05-08). OpenJDK vendors Bert Belder's wepoll *verbatim*. It is the
closest analogue to this crate on the list, because it does the same thing:
re-present AFD behind an epoll-shaped API rather than consume the driver at
each call site.

- `src/java.base/windows/native/libnio/ch/wepoll.c`, `wepoll.h` -- upstream
  piscisaureus/wepoll, notice intact; defines `IOCTL_AFD_POLL 0x00012024` and
  opens `\Device\Afd`
- `src/java.base/windows/native/libnio/ch/WEPollNatives.c` -- the JNI layer
- `src/java.base/windows/classes/sun/nio/ch/WEPoll.java` -- the Java face, and
  literally epoll: `EPOLL_CTL_ADD` / `MOD` / `DEL`, and `EPOLLIN`, `EPOLLPRI`,
  `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`, `EPOLLONESHOT`

Two independent consumers sit on that single interface, which is worth seeing
before assuming one wait loop will do:

- `WEPollSelectorImpl.java` -- the classic `java.nio` `Selector`, polling up to
  256 events per `epoll_wait`, reached through `WEPollSelectorProvider`
- `WEPollPoller.java` -- the poller underneath virtual threads, arming each
  socket with `EPOLL_CTL_ADD | EPOLLONESHOT` and re-arming after every wake-up

Two of its choices transfer directly to this crate:

- **`EPOLLONESHOT` there is not an optimisation, it is the grain of the
  driver.** See the implementation notes below.
- **Its wake-up channel is an `AF_UNIX` pipe**, not a loopback TCP pair:
  `WEPollSelectorImpl` builds a `PipeImpl(sp, /* AF_UNIX */ true, false)` and
  registers one end with wepoll. Windows has had `AF_UNIX` since 1803.

On risk, OpenJDK is the most conservative consumer here and so the most
informative. The `select`-based `WindowsSelectorImpl.java` and
`WindowsSelectorProvider.java` do remain in the tree -- but
`DefaultSelectorProvider` now returns `new WEPollSelectorProvider()`
unconditionally, with no property or probe that would fall back to them. The
JDK today ships AFD as its only default path on Windows.

### OpenVMM (Rust) -- github.com/microsoft/openvmm

Microsoft's own hypervisor and VMM project, which is the strongest single
argument that this interface is not going to be withdrawn quietly.

- `support/pal/src/windows/afd.rs` -- `open_afd()` via `NtOpenFile`,
  `IOCTL_AFD_POLL = 0x00012024`, `PollInfo` / `PollHandleInfo`, and the full
  `POLL_RECEIVE` .. `POLL_ADDRESS_LIST_CHANGE` constant set
- `support/pal/pal_async/src/windows/socket.rs` -- `make_poll_handle_info()`
  maps portable readiness bits onto the AFD ones
- consumed by `support/pal/pal_async/src/windows/{iocp,local,tp}.rs`

## Living with an undocumented interface

What makes this defensible rather than reckless:

- **It is load-bearing for the ecosystem.** Node.js (via libuv), Tokio (via
  mio) and the JDK all depend on it. Breaking `IOCTL_AFD_POLL` would break a
  large fraction of the software Windows runs. That is a compatibility
  constraint on Microsoft in practice, whatever the documentation says.
- **Microsoft uses it themselves**, in OpenVMM, with no internal API available
  to them that they preferred.
- **The shape has been stable for well over a decade** -- libuv has shipped it
  since the early 2010s and the constant has not moved.

None of that is a support commitment. Two rules follow:

1. **Fail cleanly, never silently.** Opening `\Device\Afd` or the poll IOCTL
   failing must surface as an ordinary `io::Error` from `ctl`/`wait`, not a
   panic and not a hang. A caller on a future Windows where this stops working
   should get an error it can report.
2. **Keep a fallback path viable.** `WSAPoll` is inadequate as a primary
   mechanism but is perfectly adequate as a degraded one, and the code should
   stay shaped so it can be reinstated. Note that OpenJDK, having kept its
   `select`-based selector in the tree, no longer wires it up at all -- a fair
   measure of how much risk the ecosystem now assigns to AFD, but not a thing
   to copy without deciding so deliberately.

## Implementation notes

Details that are easy to get wrong, each learned from the implementations above:

- **The poll is one-shot.** `IOCTL_AFD_POLL` reports once and must be
  re-issued. Level-triggered behaviour is produced by re-arming after each
  completion, not by the driver. Both mio (the `SockState` re-arm loop) and
  OpenJDK (`EPOLLONESHOT` in `WEPollPoller`) are shaped around this.
- **Resolve the base socket first.** A socket may be layered by an LSP, and the
  handle the application holds is then not the one AFD knows. Query
  `SIO_BASE_HANDLE` -- but note mio's hard-won comment that at least one known
  LSP deliberately breaks it, so `SIO_BSP_HANDLE` is needed as a fallback.
- **Open `\Device\Afd` with no extended attributes**, via `NtOpenFile`; both
  wepoll and OpenVMM note this explicitly.
- **The socket is not modified.** This is the point of the exercise: unlike
  `WSAEventSelect`, polling through AFD leaves blocking mode and every other
  socket option exactly as the owner set them.
- **If an internal wake channel is still wanted, `AF_UNIX` beats loopback
  TCP.** The interim `WSAPoll` path uses a loopback TCP pair; OpenJDK uses an
  `AF_UNIX` pipe for the same job. Once readiness arrives on the port the pair
  may not be needed at all, but if one is, `AF_UNIX` avoids leaving a
  listening TCP socket in the process.
- **Associate the AFD handle with the existing completion port**, so socket
  readiness and handle signals are collected by one `wait`. That is what lets
  the internal loopback wake pair and the `WSAPoll` sweep go away entirely.

## Status in this fork

The AFD path described above is the **accepted direction, not yet the
implementation**. What is in the tree today is the interim mechanism: a
level-triggered `WSAPoll` sweep with an internal loopback pair to deliver
handle signals, described in the module documentation of
`src/windows/epoll.rs`. It is correct and tested, but it carries the `WSAPoll`
costs listed above.

One limitation is worth stating separately, because AFD does **not** by itself
resolve it: an `Epoll` still cannot be registered inside another `Epoll`, since
a completion port is not a waitable object. On Linux an epoll fd is pollable
and nesting is routine, so callers ported from Linux hit this. Whether to
address it by exposing the completion port for association, or by some other
means, is an open question independent of this decision.
