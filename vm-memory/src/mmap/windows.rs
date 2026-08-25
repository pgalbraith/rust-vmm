// Copyright (C) 2019 CrowdStrike, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Helper structure for working with mmaped memory regions in Windows.

use std;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::{null, null_mut};

use libc::{c_void, size_t};

use windows_sys::Win32::Foundation::GetLastError;

use crate::bitmap::{Bitmap, NewBitmap, BS};
use crate::guest_memory::FileOffset;
use crate::volatile_memory::{self, compute_offset, VolatileMemory, VolatileSlice};

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "system" {
    pub fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: size_t,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;

    pub fn VirtualFree(lpAddress: *mut c_void, dwSize: size_t, dwFreeType: u32) -> u32;

    pub fn CreateFileMappingA(
        hFile: RawHandle,                       // HANDLE
        lpFileMappingAttributes: *const c_void, // LPSECURITY_ATTRIBUTES
        flProtect: u32,                         // DWORD
        dwMaximumSizeHigh: u32,                 // DWORD
        dwMaximumSizeLow: u32,                  // DWORD
        lpName: *const u8,                      // LPCSTR
    ) -> RawHandle; // HANDLE

    pub fn MapViewOfFile(
        hFileMappingObject: RawHandle,
        dwDesiredAccess: u32,
        dwFileOffsetHigh: u32,
        dwFileOffsetLow: u32,
        dwNumberOfBytesToMap: size_t,
    ) -> *mut c_void;

    pub fn UnmapViewOfFile(lpBaseAddress: *const c_void) -> u32; // BOOL

    pub fn CloseHandle(hObject: RawHandle) -> u32; // BOOL
}

const MM_HIGHEST_VAD_ADDRESS: u64 = 0x000007FFFFFDFFFF;

const MEM_COMMIT: u32 = 0x00001000;
const MEM_RELEASE: u32 = 0x00008000;
const FILE_MAP_ALL_ACCESS: u32 = 0xf001f;
const PAGE_READWRITE: u32 = 0x04;

pub const MAP_FAILED: *mut c_void = null_mut::<c_void>();
pub const INVALID_HANDLE_VALUE: RawHandle = (-1isize) as RawHandle;
#[allow(dead_code)]
pub const ERROR_INVALID_PARAMETER: i32 = 87;

/// Helper structure for working with mmaped memory regions in Unix.
///
/// The structure is used for accessing the guest's physical memory by mmapping it into
/// the current process.
///
/// # Limitations
/// When running a 64-bit virtual machine on a 32-bit hypervisor, only part of the guest's
/// physical memory may be mapped into the current process due to the limited virtual address
/// space size of the process.
#[derive(Debug)]
pub struct MmapRegion<B> {
    addr: *mut u8,
    size: usize,
    bitmap: B,
    file_offset: Option<FileOffset>,
    /// Whether `addr` is a view mapped with `MapViewOfFile` (from a file or a section) rather
    /// than memory from `VirtualAlloc`. The two have disjoint release functions, and calling
    /// the wrong one fails with `ERROR_INVALID_PARAMETER` and leaks the mapping.
    mapped_view: bool,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl<B: Send> Send for MmapRegion<B> {}
unsafe impl<B: Sync> Sync for MmapRegion<B> {}

impl<B: NewBitmap> MmapRegion<B> {
    /// Creates a shared anonymous mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - The size of the memory region in bytes.
    pub fn new(size: usize) -> io::Result<Self> {
        if (size == 0) || (size > MM_HIGHEST_VAD_ADDRESS as usize) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        let addr = unsafe { VirtualAlloc(null_mut::<c_void>(), size, MEM_COMMIT, PAGE_READWRITE) };
        if addr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr as *mut u8,
            size,
            bitmap: B::with_len(size),
            file_offset: None,
            mapped_view: false,
        })
    }

    /// Creates a shared file mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `file_offset` - The mapping will be created at offset `file_offset.start` in the file
    ///   referred to by `file_offset.file`.
    /// * `size` - The size of the memory region in bytes.
    pub fn from_file(file_offset: FileOffset, size: usize) -> io::Result<Self> {
        let handle = file_offset.file().as_raw_handle();
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        let mapping = unsafe {
            CreateFileMappingA(
                handle,
                null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                null(),
            )
        };
        if mapping == 0 as RawHandle {
            return Err(io::Error::last_os_error());
        }

        let offset = file_offset.start();

        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            MapViewOfFile(
                mapping,
                FILE_MAP_ALL_ACCESS,
                (offset >> 32) as u32,
                offset as u32,
                size,
            )
        };

        unsafe {
            CloseHandle(mapping);
        }

        if addr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr as *mut u8,
            size,
            bitmap: B::with_len(size),
            file_offset: Some(file_offset),
            mapped_view: true,
        })
    }

    /// Creates a mapping of `size` bytes over an existing section object.
    ///
    /// The counterpart of [`from_file`](Self::from_file) for a handle that *already is* a section
    /// (a file mapping object) rather than a file to create one from. `from_file` cannot serve
    /// here: it calls `CreateFileMappingA`, which requires a file handle and fails with
    /// `ERROR_INVALID_HANDLE` when handed a section.
    ///
    /// The distinction matters wherever memory is shared between processes with no file involved
    /// and no way to pass a handle directly — which is exactly the position the vhost-user
    /// transport is in on Windows, where guest memory arrives as the *name* of a pagefile-backed
    /// section and is opened with `OpenFileMappingA`.
    ///
    /// # Arguments
    /// * `section` - An open section object. Ownership stays with the caller; the mapping remains
    ///   valid even after that handle is closed, because Windows keeps a section alive while any
    ///   view of it exists.
    /// * `offset` - Offset within the section at which the mapping starts. Must be a multiple of
    ///   the system allocation granularity.
    /// * `size` - The size of the memory region in bytes.
    pub fn from_section(section: &impl AsRawHandle, offset: u64, size: usize) -> io::Result<Self> {
        let handle = section.as_raw_handle();
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        // Mapped directly: unlike `from_file` there is no intermediate object to create, because
        // the section already is one.
        let addr = unsafe {
            MapViewOfFile(
                handle,
                FILE_MAP_ALL_ACCESS,
                (offset >> 32) as u32,
                offset as u32,
                size,
            )
        };
        if addr.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            addr: addr as *mut u8,
            size,
            bitmap: B::with_len(size),
            // Deliberately `None`: the region is not backed by a file, and reporting a fabricated
            // `FileOffset` would suggest a caller could re-derive the mapping from one.
            file_offset: None,
            mapped_view: true,
        })
    }
}

impl<B: Bitmap> MmapRegion<B> {
    /// Returns a pointer to the beginning of the memory region. Mutable accesses performed
    /// using the resulting pointer are not automatically accounted for by the dirty bitmap
    /// tracking functionality.
    ///
    /// Should only be used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of this region.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns information regarding the offset into the file backing this region (if any).
    pub fn file_offset(&self) -> Option<&FileOffset> {
        self.file_offset.as_ref()
    }

    /// Returns a reference to the inner bitmap object.
    pub fn bitmap(&self) -> &B {
        &self.bitmap
    }
}

impl<B: Bitmap> VolatileMemory for MmapRegion<B> {
    type B = B;

    fn len(&self) -> usize {
        self.size
    }

    fn get_slice(
        &self,
        offset: usize,
        count: usize,
    ) -> volatile_memory::Result<VolatileSlice<'_, BS<'_, Self::B>>> {
        let end = compute_offset(offset, count)?;
        if end > self.size {
            return Err(volatile_memory::Error::OutOfBounds { addr: end });
        }

        // Safe because we checked that offset + count was within our range and we only ever hand
        // out volatile accessors.
        Ok(unsafe {
            VolatileSlice::with_bitmap(
                self.addr.add(offset),
                count,
                self.bitmap.slice_at(offset),
                None,
            )
        })
    }
}

impl<B> Drop for MmapRegion<B> {
    fn drop(&mut self) {
        // This is safe because we mapped the area at addr ourselves, and nobody
        // else is holding a reference to it.
        // A view from MapViewOfFile must be released with UnmapViewOfFile;
        // VirtualAlloc'd memory must be released with VirtualFree (with size 0
        // when using MEM_RELEASE, otherwise the function fails). Each fails
        // with ERROR_INVALID_PARAMETER on the other's memory, leaking it.
        unsafe {
            let ret_val = if self.mapped_view {
                UnmapViewOfFile(self.addr as *const libc::c_void)
            } else {
                VirtualFree(self.addr as *mut libc::c_void, 0, MEM_RELEASE)
            };
            if ret_val == 0 {
                let err = GetLastError();
                // We can't use any fancy logger here, yet we want to
                // pin point memory leaks.
                println!(
                    "WARNING: Could not deallocate mmap region. \
                     Address: {:?}. Size: {}. Error: {}",
                    self.addr, self.size, err
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::FromRawHandle;

    #[cfg(feature = "backend-bitmap")]
    use crate::bitmap::AtomicBitmap;
    use crate::guest_memory::FileOffset;
    use crate::mmap::windows::INVALID_HANDLE_VALUE;

    type MmapRegion = super::MmapRegion<()>;

    #[test]
    fn map_invalid_handle() {
        let file = unsafe { std::fs::File::from_raw_handle(INVALID_HANDLE_VALUE) };
        let file_offset = FileOffset::new(file, 0);
        let e = MmapRegion::from_file(file_offset, 1024).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    #[cfg(feature = "backend-bitmap")]
    fn test_dirty_tracking() {
        // Using the `crate` prefix because we aliased `MmapRegion` to `MmapRegion<()>` for
        // the rest of the unit tests above.
        let m = crate::MmapRegion::<AtomicBitmap>::new(0x1_0000).unwrap();
        crate::bitmap::tests::test_volatile_memory(&m);
    }

    // A view mapped with MapViewOfFile must be released with UnmapViewOfFile; VirtualFree
    // fails on it with ERROR_INVALID_PARAMETER and the view stays mapped. The three tests
    // below pin the release path of each constructor by asking the OS, after the drop,
    // whether the original allocation still sits at that address.
    //
    // The check retries with a fresh region because a single attempt is racy: tests run in
    // parallel, Windows hands out the lowest free address, and so another thread's mapping
    // can land exactly at the just-freed base between the drop and the query, looking
    // identical to a leak (measured at roughly 1 in 20 runs for the file-backed test, by
    // looping two copies of this test binary concurrently). The two outcomes separate
    // cleanly under retry: a broken release leaks the original allocation *every* time,
    // while a reuse collision has to recur independently per attempt.

    use libc::{c_void, size_t};

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualQuery(
            lpAddress: *const c_void,
            lpBuffer: *mut MemoryBasicInformation,
            dwLength: size_t,
        ) -> size_t;
    }

    const MEM_COMMIT_STATE: u32 = 0x1000;
    const MEM_MAPPED: u32 = 0x40000;
    const MEM_PRIVATE: u32 = 0x20000;

    /// True if dropping a region made by `make` genuinely releases its memory.
    ///
    /// Tries up to five times; see the comment above for why one attempt is not enough. A
    /// broken release fails all five, a parallel-test address-reuse collision does not.
    fn drops_cleanly(mem_type: u32, mut make: impl FnMut() -> MmapRegion) -> bool {
        for _ in 0..5 {
            let region = make();
            let addr = region.as_ptr();
            drop(region);
            if !still_allocated(addr, mem_type) {
                return true;
            }
        }
        false
    }

    /// True if the original allocation of kind `mem_type` still occupies `addr`.
    fn still_allocated(addr: *mut u8, mem_type: u32) -> bool {
        let mut info = MemoryBasicInformation {
            base_address: std::ptr::null_mut(),
            allocation_base: std::ptr::null_mut(),
            allocation_protect: 0,
            partition_id: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            type_: 0,
        };
        let len = unsafe {
            VirtualQuery(
                addr as *const c_void,
                &mut info,
                std::mem::size_of::<MemoryBasicInformation>(),
            )
        };
        assert_ne!(len, 0, "VirtualQuery failed");
        info.state == MEM_COMMIT_STATE
            && info.type_ == mem_type
            && std::ptr::eq(info.allocation_base, addr as *mut c_void)
    }

    #[test]
    fn dropping_an_anonymous_region_releases_its_memory() {
        assert!(drops_cleanly(MEM_PRIVATE, || {
            MmapRegion::new(0x1_0000).unwrap()
        }));
    }

    #[test]
    fn dropping_a_file_backed_region_releases_its_view() {
        let path =
            std::env::temp_dir().join(format!("vm-memory-drop-test-{}.bin", std::process::id()));
        assert!(drops_cleanly(MEM_MAPPED, || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .unwrap();
            file.set_len(0x1_0000).unwrap();
            MmapRegion::from_file(FileOffset::new(file, 0), 0x1_0000).unwrap()
        }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dropping_a_section_backed_region_releases_its_view() {
        // A pagefile-backed section, the shape guest memory arrives in over the
        // Windows vhost-user transport.
        assert!(drops_cleanly(MEM_MAPPED, || {
            let section = unsafe {
                super::CreateFileMappingA(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    super::PAGE_READWRITE,
                    0,
                    0x1_0000,
                    std::ptr::null(),
                )
            };
            assert!(!section.is_null());
            let section = unsafe { std::fs::File::from_raw_handle(section) };
            MmapRegion::from_section(&section, 0, 0x1_0000).unwrap()
        }));
    }
}
