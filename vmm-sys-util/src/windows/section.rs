// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An anonymous, pagefile-backed section object (file mapping), the
//! Windows counterpart of a `memfd` for sharing memory between processes.
//!
//! Windows has no `SCM_RIGHTS`-style descriptor passing. Sharing one of
//! these with another process means duplicating its handle into that
//! process with `DuplicateHandle`; the peer adopts the result with
//! [`FromRawHandle`]. The object stays unnamed, so it is reachable only by
//! a process that was deliberately handed a handle — the same reachability
//! an `SCM_RIGHTS` descriptor has, and one the object namespace cannot
//! offer.
//!
//! Mapping a view is `vm-memory`'s job (`MmapRegion::from_section`); this
//! type only handles creation and handle ownership.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};

/// An anonymous, pagefile-backed section object of a fixed size.
#[derive(Debug)]
pub struct Section {
    handle: HANDLE,
}

// SAFETY: a Win32 HANDLE has no thread affinity, and every method takes
// `&self` only for thread-safe kernel calls or reads of immutable state.
unsafe impl Send for Section {}
// SAFETY: see above.
unsafe impl Sync for Section {}

impl Section {
    /// Create a new anonymous pagefile-backed section of `size` bytes.
    ///
    /// To share it with another process, duplicate the handle into that
    /// process; see the module docs.
    pub fn new(size: u64) -> io::Result<Section> {
        // SAFETY: `INVALID_HANDLE_VALUE` with a null name asks for an
        // anonymous pagefile-backed section; the result is checked.
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                std::ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Section { handle })
    }
}

impl AsRawHandle for Section {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle as RawHandle
    }
}

impl FromRawHandle for Section {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Section {
            handle: handle as HANDLE,
        }
    }
}

impl IntoRawHandle for Section {
    fn into_raw_handle(self) -> RawHandle {
        // Suppress `Drop`, which would close the handle the caller is
        // taking ownership of. Nothing else in the struct owns memory.
        let this = std::mem::ManuallyDrop::new(self);
        this.handle as RawHandle
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a valid handle owned by this value.
        // The underlying memory stays alive while any view of it exists;
        // closing the creating handle does not tear down a peer's view.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows_sys::Win32::System::Memory::{
        MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Map `size` bytes of the section for the duration of `f`.
    fn with_view<R>(s: &Section, size: usize, f: impl FnOnce(*mut u8) -> R) -> R {
        // SAFETY: the handle is a valid section for the lifetime of `s`,
        // and the view is unmapped before returning.
        unsafe {
            let view = MapViewOfFile(
                s.as_raw_handle() as HANDLE,
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                size,
            );
            assert!(!view.Value.is_null());
            let r = f(view.Value as *mut u8);
            UnmapViewOfFile(view);
            r
        }
    }

    /// Stand in for a peer receiving this section: duplicate the handle the
    /// way an owning process hands one over, and adopt the result.
    fn duplicate_to_peer(s: &Section) -> Section {
        let mut dup: HANDLE = std::ptr::null_mut();
        // SAFETY: both process handles are the current-process pseudo
        // handle, `s` is live, and `dup` is a valid out-pointer.
        let ok = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                s.as_raw_handle() as HANDLE,
                process,
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        assert!(ok != 0, "{}", io::Error::last_os_error());
        // SAFETY: `dup` was just created and is owned by nothing else.
        unsafe { Section::from_raw_handle(dup as RawHandle) }
    }

    #[test]
    fn a_created_section_is_readable_and_writable() {
        let s = Section::new(0x1000).unwrap();
        with_view(&s, 0x1000, |p| {
            // SAFETY: the view is valid for 0x1000 bytes.
            unsafe {
                p.write(0xA5);
                assert_eq!(p.read(), 0xA5);
            }
        });
    }

    #[test]
    fn a_peer_handed_a_handle_sees_the_same_memory() {
        // How a section crosses a process boundary now: the owner
        // duplicates its handle in, and both map the same pages.
        let created = Section::new(0x1000).unwrap();
        let peer = duplicate_to_peer(&created);

        with_view(&created, 0x1000, |p| {
            // SAFETY: the view is valid for 0x1000 bytes.
            unsafe { p.write(0xA5) };
        });
        let seen = with_view(&peer, 0x1000, |p| {
            // SAFETY: the view is valid for 0x1000 bytes.
            unsafe { p.read() }
        });
        assert_eq!(seen, 0xA5);
    }

    #[test]
    fn a_zero_size_section_is_refused() {
        // CreateFileMapping rejects a zero-size anonymous section rather
        // than sizing it from a backing file, as it would for a real one.
        assert!(Section::new(0).is_err());
    }

    #[test]
    fn a_thousand_into_raw_handle_cycles_leak_no_handles() {
        // into_raw_handle must suppress Drop without closing the handle it
        // hands over: the caller closes it exactly once.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let h = Section::new(0x1000).unwrap().into_raw_handle();
            // SAFETY: `h` came from into_raw_handle and is closed once.
            unsafe { CloseHandle(h as HANDLE) };
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }

    #[test]
    fn a_thousand_section_cycles_leak_no_handles() {
        // Delta over N rather than exact equality: see the eventfd twin.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let s = Section::new(0x1000).unwrap();
            let d = duplicate_to_peer(&s);
            drop((s, d));
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }
}
