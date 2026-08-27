// Copyright (C) 2019 CrowdStrike, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Helper structure for working with mmaped memory regions in Windows.

use std;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::null;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualFree,
    FILE_MAP_ALL_ACCESS, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MEM_COMMIT,
    MEM_RELEASE, PAGE_READWRITE,
};

use crate::bitmap::{Bitmap, NewBitmap, BS};
use crate::guest_memory::FileOffset;
use crate::volatile_memory::{self, compute_offset, VolatileMemory, VolatileSlice};

// The Win32 bindings come from windows-sys rather than a hand-declared
// extern block: the hand-rolled signatures typed MapViewOfFile's return
// and UnmapViewOfFile's argument as bare pointers where the real ABI uses
// MEMORY_MAPPED_VIEW_ADDRESS (a repr(C) newtype over the pointer), which
// only worked by coincidence of the x64 calling convention.

const MM_HIGHEST_VAD_ADDRESS: u64 = 0x000007FFFFFDFFFF;

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
    /// Whether `addr` came from `MapViewOfFile` (file/section) rather than `VirtualAlloc`.
    /// The two need different release functions; calling the wrong one leaks the mapping.
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
        let addr = unsafe { VirtualAlloc(null(), size, MEM_COMMIT, PAGE_READWRITE) };
        if addr.is_null() {
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
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }

        let offset = file_offset.start();

        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let view = unsafe {
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

        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: view.Value as *mut u8,
            size,
            bitmap: B::with_len(size),
            file_offset: Some(file_offset),
            mapped_view: true,
        })
    }

    /// Creates a mapping of `size` bytes over an existing section object.
    ///
    /// Counterpart to [`from_file`](Self::from_file) for a handle that's already a section rather
    /// than a file to create one from — `from_file` calls `CreateFileMappingA`, which fails with
    /// `ERROR_INVALID_HANDLE` on a section handle. Needed when memory is shared between processes
    /// with no file involved, e.g. the Windows vhost-user transport, where guest memory arrives as
    /// the name of a pagefile-backed section, opened with `OpenFileMappingA`.
    ///
    /// # Arguments
    /// * `section` - An open section object. Ownership stays with the caller; the mapping remains
    ///   valid after that handle is closed, since Windows keeps a section alive while any view of
    ///   it exists.
    /// * `offset` - Offset within the section at which the mapping starts. Must be a multiple of
    ///   the system allocation granularity.
    /// * `size` - The size of the memory region in bytes.
    pub fn from_section(section: &impl AsRawHandle, offset: u64, size: usize) -> io::Result<Self> {
        Self::from_section_with_access(section, offset, size, FILE_MAP_READ | FILE_MAP_WRITE)
    }

    /// Like [`from_section`](Self::from_section), but maps a read-only view.
    ///
    /// For regions the consumer must not be able to modify (ROM, pflash),
    /// with the kernel enforcing it: a write through the returned region
    /// faults instead of corrupting shared state. Accordingly, the region
    /// must only be read through (`Bytes::read()`-style access); writing
    /// through `VolatileMemory` accessors is a guaranteed access violation.
    /// Works with a section handle opened read-only (`Section::open_read_only`),
    /// which cannot map a writable view at all.
    pub fn from_section_read_only(
        section: &impl AsRawHandle,
        offset: u64,
        size: usize,
    ) -> io::Result<Self> {
        Self::from_section_with_access(section, offset, size, FILE_MAP_READ)
    }

    fn from_section_with_access(
        section: &impl AsRawHandle,
        offset: u64,
        size: usize,
        access: u32,
    ) -> io::Result<Self> {
        let handle = section.as_raw_handle();
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        // A `size` of 0 is special-cased by `MapViewOfFile` to map from `offset` to the end of the
        // section, which would leave the view and this region's recorded length disagreeing. Reject
        // it: a real region is never empty, and `offset`/`size` here can come off the wire.
        if size == 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // `offset` and `size` are trusted only as far as the kernel enforces them: `MapViewOfFile`
        // fails (NULL) if `offset` is not allocation-granularity aligned or `offset + size` exceeds
        // the section, so an out-of-range request becomes an error below rather than an out-of-bounds
        // view. The section's own size is not queryable before mapping, so this is the bounds check.
        // The section already is the mapping object, so unlike `from_file` there's nothing to create.
        // `access` is read/write or read-only, never FILE_MAP_ALL_ACCESS: a view needs nothing
        // more, and a peer-opened section handle (`Section::open`/`open_read_only`) doesn't
        // carry more — requesting FILE_MAP_ALL_ACCESS against one fails with access denied.
        let view =
            unsafe { MapViewOfFile(handle, access, (offset >> 32) as u32, offset as u32, size) };
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            addr: view.Value as *mut u8,
            size,
            bitmap: B::with_len(size),
            // Deliberately `None`: not file-backed, so a fabricated `FileOffset` would mislead.
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
        // Safe: we mapped `addr` ourselves and nobody else holds a reference.
        // A MapViewOfFile view needs UnmapViewOfFile; VirtualAlloc'd memory needs VirtualFree
        // (size 0 for MEM_RELEASE). Each fails with ERROR_INVALID_PARAMETER on the other's memory.
        unsafe {
            let ret_val = if self.mapped_view {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.addr.cast(),
                })
            } else {
                VirtualFree(self.addr.cast(), 0, MEM_RELEASE)
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

    // Pins each constructor's release path by checking, after drop, whether the original
    // allocation still sits at that address.
    //
    // Retries with a fresh region since one attempt is racy under parallel test runs: Windows
    // reuses the lowest free address, so another thread's mapping can land at the just-freed
    // base and look identical to a leak. A broken release leaks every attempt; a reuse
    // collision doesn't recur.

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
    fn a_read_only_section_region_reads_but_rejects_writable_mapping() {
        // The production least-privilege shape: a peer opens the section
        // read-only and can see the data but cannot obtain a writable view.
        use vmm_sys_util::section::Section;

        let section = Section::new(0x1_0000).unwrap();
        let rw = MmapRegion::from_section(&section, 0, 0x1_0000).unwrap();
        // SAFETY: the mapping is valid for 0x1_0000 bytes.
        unsafe { rw.as_ptr().write(0xA5) };

        let ro_handle = Section::open_read_only(section.name().unwrap()).unwrap();
        // A writable mapping of the read-only handle is refused by the
        // kernel — the enforcement, not just the convention.
        assert!(MmapRegion::from_section(&ro_handle, 0, 0x1_0000).is_err());

        let ro = MmapRegion::from_section_read_only(&ro_handle, 0, 0x1_0000).unwrap();
        // SAFETY: the mapping is valid for 0x1_0000 bytes and only read.
        assert_eq!(unsafe { ro.as_ptr().cast_const().read() }, 0xA5);
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

    /// Committed MEM_MAPPED regions in this process, by walking the
    /// address space.
    fn mapped_region_count() -> usize {
        let mut count = 0usize;
        let mut addr = 0usize;
        loop {
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
            if len == 0 {
                break;
            }
            if info.state == MEM_COMMIT_STATE && info.type_ == MEM_MAPPED {
                count += 1;
            }
            let next = (info.base_address as usize).saturating_add(info.region_size);
            if next <= addr {
                break;
            }
            addr = next;
        }
        count
    }

    #[test]
    fn a_thousand_mapping_cycles_leak_no_views() {
        // A view leaked per drop shows up as +N mapped regions. Delta over N, not
        // exact equality: other test threads map and unmap concurrently.
        const N: usize = 1000;
        let section = unsafe {
            super::CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                super::PAGE_READWRITE,
                0,
                0x1000,
                std::ptr::null(),
            )
        };
        assert!(!section.is_null());
        let section = unsafe { std::fs::File::from_raw_handle(section) };

        let before = mapped_region_count();
        for _ in 0..N {
            drop(MmapRegion::from_section(&section, 0, 0x1000).unwrap());
        }
        let after = mapped_region_count();
        assert!(
            after.saturating_sub(before) < N / 2,
            "mapped regions grew from {before} to {after} over {N} cycles"
        );
    }
}
