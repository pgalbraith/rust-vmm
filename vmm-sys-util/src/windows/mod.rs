// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause
pub(crate) mod afd;
#[cfg(feature = "completion")]
pub mod completion;
pub mod epoll;
pub mod event;
pub mod eventfd;
pub mod section;

/// This process's kernel handle count, for leak-detection tests: a
/// per-iteration leak over N iterations shows up as a delta near +N.
#[cfg(test)]
pub(crate) fn process_handle_count() -> u32 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut count = 0u32;
    // SAFETY: the pseudo-handle is always valid; `count` is a valid
    // out-pointer for the duration of the call.
    let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
    assert_ne!(ok, 0, "GetProcessHandleCount failed");
    count
}
