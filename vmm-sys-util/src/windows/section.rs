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

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingA, OpenFileMappingA, FILE_MAP_READ, FILE_MAP_WRITE, PAGE_READWRITE,
};

use crate::windows::named_object;

fn unique_name() -> CString {
    named_object::unique_name("vmm-sys-util-sec-")
}

/// Create a pagefile-backed section under `name` with a creator-only DACL,
/// failing (rather than adopting the impostor) if the name is taken.
fn create_named_section(name: &CString, size: u64) -> io::Result<HANDLE> {
    let sa = named_object::creator_only_attributes()?;
    // SAFETY: `sa` and `name` are valid for the duration of the call; the
    // return value is checked.
    let handle = unsafe {
        CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            &sa,
            PAGE_READWRITE,
            (size >> 32) as u32,
            size as u32,
            name.as_ptr().cast(),
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // Nothing between the create and this check can clobber the
    // thread's last-error slot.
    named_object::reject_preexisting(handle)
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
    /// freshly minted, unguessable name.
    ///
    /// The name is 128 random bits, the object's DACL admits only the
    /// creating user, and creation fails if the name is somehow already
    /// taken instead of silently adopting the existing object.
    pub fn new(size: u64) -> io::Result<Section> {
        let name = unique_name();
        let handle = create_named_section(&name, size)?;
        Ok(Section {
            handle,
            name: Some(name),
        })
    }

    /// Open an existing named section created by a peer process, with
    /// the name communicated out of band.
    ///
    /// The handle carries read/write mapping access only — enough for
    /// `MmapRegion::from_section`, and nothing beyond it (no
    /// `SECTION_EXTEND_SIZE`, no `WRITE_DAC`). For memory this side
    /// should not be able to corrupt, use
    /// [`open_read_only`](Section::open_read_only) instead.
    pub fn open(name: &str) -> io::Result<Section> {
        Self::open_with_access(name, FILE_MAP_READ | FILE_MAP_WRITE)
    }

    /// Open an existing named section for reading only.
    ///
    /// The handle cannot map a writable view: least privilege for ROM,
    /// pflash, and any other region whose consumer must not be able to
    /// modify it, enforced by the kernel rather than by convention.
    pub fn open_read_only(name: &str) -> io::Result<Section> {
        Self::open_with_access(name, FILE_MAP_READ)
    }

    fn open_with_access(name: &str, access: u32) -> io::Result<Section> {
        let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `cname` is a valid NUL-terminated string for the
        // duration of the call; the return value is checked.
        let handle = unsafe { OpenFileMappingA(access, 0, cname.as_ptr().cast()) };
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
        // Suppress `Drop` (which would close the handle) without leaking
        // the rest of the struct: a bare `mem::forget` also leaked the
        // name's heap allocation, once per call.
        let mut this = std::mem::ManuallyDrop::new(self);
        drop(this.name.take());
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
    use windows_sys::Win32::System::Memory::{MapViewOfFile, UnmapViewOfFile};

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
    fn a_read_only_open_reads_but_cannot_map_a_writable_view() {
        let created = Section::new(0x1000).unwrap();
        with_view(&created, 0x1000, |p| {
            // SAFETY: the view is valid for 0x1000 bytes.
            unsafe { p.write(0x5A) };
        });

        let ro = Section::open_read_only(created.name().unwrap()).unwrap();
        // SAFETY: the handle is valid for `ro`'s lifetime; the read view is
        // unmapped before return.
        unsafe {
            let view = MapViewOfFile(ro.as_raw_handle() as HANDLE, FILE_MAP_READ, 0, 0, 0x1000);
            assert!(!view.Value.is_null());
            assert_eq!((view.Value as *const u8).read(), 0x5A);
            UnmapViewOfFile(view);

            // A writable view is refused by the kernel, not by convention:
            // the handle simply lacks the right.
            let w = MapViewOfFile(ro.as_raw_handle() as HANDLE, FILE_MAP_WRITE, 0, 0, 0x1000);
            assert!(w.Value.is_null());
        }
    }

    #[test]
    fn creating_over_a_squatted_name_fails_instead_of_adopting_it() {
        // Windows reports a name collision as success + ERROR_ALREADY_EXISTS,
        // returning the squatter's object — which here would mean treating
        // an attacker's memory as guest RAM. The create path must refuse it.
        let squatter = unique_name();
        let first = create_named_section(&squatter, 0x1000).unwrap();
        // SAFETY: `first` was just created successfully above.
        let _first = unsafe { Section::from_raw_handle(first as RawHandle) };

        let err = create_named_section(&squatter, 0x1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
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
    fn a_thousand_into_raw_handle_cycles_leak_no_name_bytes() {
        // See the eventfd twin: mem::forget in into_raw_handle leaked the
        // name's CString, invisible to the handle-count tests.
        const N: isize = 2000;
        let before = crate::windows::allocated_bytes();
        for _ in 0..N {
            let s = Section::new(0x1000).unwrap();
            let h = s.into_raw_handle();
            // SAFETY: `h` came from into_raw_handle and is closed exactly
            // once, keeping the handle count flat.
            unsafe { CloseHandle(h as HANDLE) };
        }
        let after = crate::windows::allocated_bytes();
        assert!(
            after - before < N * 25,
            "net allocation grew {} bytes over {N} cycles",
            after - before
        );
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
