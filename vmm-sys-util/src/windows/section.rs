// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A named, pagefile-backed section object (file mapping), the Windows
//! rendezvous for sharing memory between unrelated processes.
//!
//! Windows has no `SCM_RIGHTS`-style descriptor passing, so the native
//! mechanism is the kernel object namespace: one process creates the
//! section under a generated name with [`Section::new`], transmits the
//! name out of band, and the peer opens the same memory with
//! [`Section::open`]. Mapping a view is `vm-memory`'s job
//! (`MmapRegion::from_section`); this type only handles creation,
//! naming, and handle ownership.

use std::ffi::CString;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
use std::process;
use std::ptr::null;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingA, OpenFileMappingA, FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
};

static NEXT_ID: AtomicU32 = AtomicU32::new(0);

fn unique_name() -> CString {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the formatted string contains no interior NUL byte.
    CString::new(format!("vmm-sys-util-sec-{}-{}", process::id(), id)).unwrap()
}

/// A named, pagefile-backed section object of a fixed size.
#[derive(Debug)]
pub struct Section {
    handle: HANDLE,
    /// The object's name; `None` when the section arrived as a bare
    /// handle ([`FromRawHandle`]) and its name is unknown.
    name: Option<CString>,
}

// SAFETY: a Win32 HANDLE has no thread affinity, and every method takes
// `&self` only for thread-safe kernel calls or reads of immutable state.
unsafe impl Send for Section {}
// SAFETY: see above.
unsafe impl Sync for Section {}

impl Section {
    /// Create a new pagefile-backed section of `size` bytes under a
    /// freshly minted, process-unique name.
    pub fn new(size: u64) -> io::Result<Section> {
        let name = unique_name();
        // SAFETY: `name` is a valid NUL-terminated string for the
        // duration of the call; the return value is checked.
        let handle = unsafe {
            CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                name.as_ptr().cast(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Section {
            handle,
            name: Some(name),
        })
    }

    /// Open an existing named section created by a peer process, with
    /// the name communicated out of band.
    pub fn open(name: &str) -> io::Result<Section> {
        let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `cname` is a valid NUL-terminated string for the
        // duration of the call; the return value is checked.
        let handle = unsafe { OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, cname.as_ptr().cast()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Section {
            handle,
            name: Some(cname),
        })
    }

    /// The object's name, for transmitting to a peer; `None` when the
    /// section arrived as a bare handle and the name is unknown.
    pub fn name(&self) -> Option<&str> {
        // The name was built from (or validated as) a Rust string, so
        // it converts back losslessly.
        self.name.as_ref().and_then(|n| n.to_str().ok())
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
            name: None,
        }
    }
}

impl IntoRawHandle for Section {
    fn into_raw_handle(self) -> RawHandle {
        let handle = self.handle as RawHandle;
        std::mem::forget(self);
        handle
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
    use windows_sys::Win32::System::Memory::{MapViewOfFile, UnmapViewOfFile};

    /// Map `size` bytes of the section for the duration of `f`.
    fn with_view<R>(s: &Section, size: usize, f: impl FnOnce(*mut u8) -> R) -> R {
        // SAFETY: the handle is a valid section for the lifetime of `s`,
        // and the view is unmapped before returning.
        unsafe {
            let view = MapViewOfFile(s.as_raw_handle() as HANDLE, FILE_MAP_ALL_ACCESS, 0, 0, size);
            assert!(!view.Value.is_null());
            let r = f(view.Value as *mut u8);
            UnmapViewOfFile(view);
            r
        }
    }

    #[test]
    fn a_created_section_carries_its_name() {
        let s = Section::new(0x1000).unwrap();
        let name = s.name().expect("a created section must know its name");
        assert!(name.starts_with("vmm-sys-util-sec-"));
    }

    #[test]
    fn a_peer_opening_the_name_sees_the_same_memory() {
        let created = Section::new(0x1000).unwrap();
        let opened = Section::open(created.name().unwrap()).unwrap();

        with_view(&created, 0x1000, |p| {
            // SAFETY: the view is valid for 0x1000 bytes.
            unsafe { p.write(0xA5) };
        });
        let seen = with_view(&opened, 0x1000, |p| {
            // SAFETY: the view is valid for 0x1000 bytes.
            unsafe { p.read() }
        });
        assert_eq!(seen, 0xA5);
    }

    #[test]
    fn opening_a_missing_name_fails() {
        assert!(Section::open("vmm-sys-util-sec-does-not-exist").is_err());
    }

    #[test]
    fn a_bare_handle_has_no_name() {
        let created = Section::new(0x1000).unwrap();
        // SAFETY: the handle comes straight from into_raw_handle.
        let adopted = unsafe { Section::from_raw_handle(created.into_raw_handle()) };
        assert!(adopted.name().is_none());
    }

    #[test]
    fn a_thousand_section_cycles_leak_no_handles() {
        // Delta over N rather than exact equality: see the eventfd twin.
        const N: u32 = 1000;
        let before = crate::windows::process_handle_count();
        for _ in 0..N {
            let s = Section::new(0x1000).unwrap();
            let o = Section::open(s.name().unwrap()).unwrap();
            drop((s, o));
        }
        let after = crate::windows::process_handle_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "handle count grew from {before} to {after} over {N} cycles"
        );
    }
}
