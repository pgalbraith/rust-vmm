# Windows socket polling

## Decision

`Epoll` on Windows polls sockets through the **AFD driver** -- `\Device\Afd`,
driven by `NtDeviceIoControlFile` with `IOCTL_AFD_POLL` (`0x00012024`), with
the results collected on the same I/O completion port the rest of `Epoll`
already uses.

**AFD is not a documented or supported Windows interface.** It is in no SDK
header and has no MSDN page, and Microsoft can change it. The rest of this
document says why we are doing it anyway, and who else already does.

## Why the supported APIs do not work

`epoll` gives you three things at once: readiness notification rather than
completion, level-triggered behaviour, and one wait that covers sockets *and*
other waitable objects. No supported Windows API gives all three.

| Supported option | Why it fails here |
| --- | --- |
| `select` / `WSAPoll` | O(n) in *registered* sockets on every call, not in ready ones. Cannot wait on a `HANDLE` at the same time, so handle signals need a side channel. `WSAPoll` also fails to report a failed non-blocking `connect`, which Microsoft has acknowledged and not fixed. |
| `WSAEventSelect` | Edge-triggered (`FD_WRITE` re-arms only after a send fails), and it forces the socket into non-blocking mode. Winsock gives no way to keep event notification and blocking mode together, so registering a socket would silently change its semantics for its owner. |
| IOCP alone | Reports completion, not readiness. To find out that a socket is readable you have to start the read, which means owning the buffer. A caller that just wants to be told when to read cannot do that. |
| A thread per socket | Scales with sockets rather than with activity, and multiplies the shutdown races. |

AFD is the layer beneath Winsock that all of these are built on. Asking it
directly is the only way to get readiness without also taking ownership of the
I/O, and it delivers through the IOCP, so sockets and handles arrive in one
wait.

## What Microsoft says

Not nothing, and not in our favour. There is no supported readiness API on
Windows because Microsoft has steered developers away from readiness and
towards completion I/O for twenty years.

- `WSAPoll` was added in Vista as a porting aid for `poll()` code. The Winsock
  team's own announcement tells anyone building for scale to use "the native
  Winsock overlapped IO facilities"
  [https://learn.microsoft.com/en-us/archive/blogs/wndp/wsapoll-a-new-winsock-api-to-simplify-porting-poll-applications-to-winsock]
  instead. In the comments on the same post a Microsoft engineer says plainly
  that `select` on Windows exists for compatibility rather than performance.
- The `WSAPoll` defect above is tracked by Microsoft as "Windows 8 Bugs 309411
  - WSAPoll does not report failed connections" and was **resolved Won't Fix**,
  on the grounds of application-compatibility risk and no other customer
  asking. So the one supported readiness call has a known defect that will not
  be repaired.
- AFD itself has never been documented or acknowledged.

CPython shows what following that advice looks like: `asyncio`'s default
Windows loop is `ProactorEventLoop`, which is IOCP-based and owns the buffers,
and its `SelectorEventLoop` falls back to `select()`. That route is open to a
library whose API is completion-shaped to begin with. It is not open here:
`Epoll` promises callers that it will say when to read, and let them do the
reading. Trio, whose API makes the same promise with `wait_readable`, ended up
exactly where this crate does.

## Who else does this

Five projects, one of them Microsoft's own, all ended up at the same
undocumented driver, and four of them use the identical `0x00012024`
constant. Their sources are the best reference material for writing this.

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

- **`EPOLLONESHOT` is not an optimisation there.** It is how the driver
  works: see the note on one-shot polls under "Implementation notes".
- **Its wake-up channel is an `AF_UNIX` pipe**, not a loopback TCP pair:
  `WEPollSelectorImpl` builds a `PipeImpl(sp, /* AF_UNIX */ true, false)` and
  registers one end with wepoll. Windows has had `AF_UNIX` since 1803.

OpenJDK is the most cautious project on this list, so what it does about the
risk is worth knowing. The `select`-based `WindowsSelectorImpl.java` and
`WindowsSelectorProvider.java` do remain in the tree -- but
`DefaultSelectorProvider` now returns `new WEPollSelectorProvider()`
unconditionally, with no property or probe that would fall back to them. The
JDK today ships AFD as its only default path on Windows.

### Trio (Python) -- github.com/python-trio/trio

Rewrote its Windows backend to use IOCP exclusively, and implements
`wait_readable` / `wait_writable` on AFD polls completed through it.

- `trio/_core/_io_windows.py` -- the AFD poll submission and completion
  handling, alongside the rest of the IOCP loop
- Rationale and history: python-trio/trio issue #52, and the rewrite in
  pull request #1269

Trio also contributes a constraint the others do not spell out: **the kernel
misbehaves if more than one `IOCTL_AFD_POLL` is outstanding on the same
socket**, so a caller wanting both readability and writability has to ask for
them in a single request.

### OpenVMM (Rust) -- github.com/microsoft/openvmm

Microsoft's own hypervisor and VMM project. That Microsoft uses AFD in their
own code is the strongest reason to think it will not be removed.

- `support/pal/src/windows/afd.rs` -- `open_afd()` via `NtOpenFile`,
  `IOCTL_AFD_POLL = 0x00012024`, `PollInfo` / `PollHandleInfo`, and the full
  `POLL_RECEIVE` .. `POLL_ADDRESS_LIST_CHANGE` constant set
- `support/pal/pal_async/src/windows/socket.rs` -- `make_poll_handle_info()`
  maps portable readiness bits onto the AFD ones
- consumed by `support/pal/pal_async/src/windows/{iocp,local,tp}.rs`

## Living with an undocumented interface

Reasons to think this is safe enough:

- **It is load-bearing for the ecosystem.** Node.js (via libuv), Tokio (via
  mio), Trio and the JDK all depend on it. Breaking `IOCTL_AFD_POLL` would break a
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
- **Resolve the base socket first.** A layered service provider (LSP) can sit
  in front of a socket, and then the handle the application holds is not the
  one AFD knows about. Query `SIO_BASE_HANDLE` for the real one. mio's comment
  records that at least one LSP deliberately breaks that query, so
  `SIO_BSP_HANDLE` is needed as a fallback.
- **Open `\Device\Afd` with no extended attributes**, via `NtOpenFile`; both
  wepoll and OpenVMM note this explicitly.
- **The socket is not modified.** This is the main reason to use AFD at all.
  Unlike `WSAEventSelect`, polling through AFD leaves blocking mode and every
  other socket option as the owner set them.
- **If a wake channel is still needed, prefer `AF_UNIX`.** Once readiness
  arrives on the completion port there may be nothing to wake, so this may not
  come up. If it does, OpenJDK uses an `AF_UNIX` pipe. The interim `WSAPoll`
  path here uses a loopback UDP socket, which works but is still a network
  socket in the process.
- **Associate the AFD handle with the existing completion port**, so socket
  readiness and handle signals are collected by one `wait`. That is what lets
  the internal loopback wake pair and the `WSAPoll` sweep go away entirely.

## Status in this fork

**Implemented.** `src/windows/afd.rs` opens the driver and issues the polls;
`src/windows/epoll.rs` registers sockets with it and collects the results on
the same completion port as the handle signals.

What that removed:

- the `WSAPoll` sweep, which asked about every registered socket on every call
  whether or not any was ready
- the loopback wake socket, which existed only to interrupt that sweep
- the cap on how long `wait` would block, which existed only because a lost
  wake would otherwise strand the caller forever

Handle signals and socket readiness now arrive by the same route, so there is
no message between mechanisms to lose. The epoll test suite runs in 0.16s
against 5.01s before, most of that being the cap.

Notes for anyone changing it:

- The completion identifies its request by the **APC context**, not by the
  status block, even though this crate passes the same address for both. Get
  that wrong and every completion comes back with a null pointer and is
  silently dropped.
- A socket deleted while its poll is in flight cannot be freed at once: the
  kernel may still write into the request. It moves to `dying` and is freed
  when the cancellation completes.
- `Epoll::drop` closes the AFD handle before freeing anything, which cancels
  and completes every outstanding poll. wepoll relies on the same ordering.

## Not solved

An `Epoll` still cannot be registered inside another `Epoll`, because a
completion port is not a waitable object. On Linux an epoll fd is pollable and
nesting one inside another is routine, so code ported from Linux runs into
this. Whether to solve it by letting a caller associate its sources with an
existing completion port, or some other way, is a separate question.
