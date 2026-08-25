// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause
pub mod epoll;
pub mod event;
pub mod eventfd;
pub mod section;

/// Leak-detection support for tests: this process's kernel handle count.
///
/// Tests that create and drop N of something assert the count's delta
/// stays far below N -- a real per-iteration leak shows up as +N, while
/// unrelated test threads only add background noise of a few handles.
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
