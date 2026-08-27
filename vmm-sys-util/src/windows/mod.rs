// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause
pub mod epoll;
pub mod event;
pub mod eventfd;
pub(crate) mod named_object;
pub mod section;

/// The heap-byte twin of [`process_handle_count`]: net bytes currently
/// allocated, for leak-detection tests that leak memory rather than
/// handles (a per-iteration leak of an S-byte allocation over N
/// iterations shows up as a delta near +N*S).
///
/// Counted by a thin wrapper over the system allocator, installed for
/// this crate's test builds only.
#[cfg(test)]
pub(crate) fn allocated_bytes() -> isize {
    counting_alloc::NET_ALLOCATED.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod counting_alloc {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicIsize, Ordering};

    pub(super) static NET_ALLOCATED: AtomicIsize = AtomicIsize::new(0);

    struct CountingAllocator;

    // SAFETY: delegates directly to `System`, only adding relaxed atomic
    // bookkeeping of the net allocated size.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: same contract as the caller's.
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                NET_ALLOCATED.fetch_add(layout.size() as isize, Ordering::Relaxed);
            }
            p
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            NET_ALLOCATED.fetch_sub(layout.size() as isize, Ordering::Relaxed);
            // SAFETY: same contract as the caller's.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: CountingAllocator = CountingAllocator;
}

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
