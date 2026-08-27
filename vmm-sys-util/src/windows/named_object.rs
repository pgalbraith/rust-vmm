// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Shared helpers for creating named kernel objects without the two classic
//! namespace hazards: name squatting (a `Create*` call that silently opens a
//! pre-existing object of the same name) and default-DACL exposure (any
//! process of the same user opening the object because nothing tighter was
//! ever asked for).
//!
//! Names minted here are 128 random bits from the OS CSPRNG, so they can't
//! be predicted or enumerated the way a pid-plus-counter scheme can. The
//! DACL built here grants access to the creating user's SID and nothing
//! else, replacing the token's default DACL. Neither measure stops a
//! same-user process that has *learned* a name — that limit is inherent to
//! the object namespace; a peer that must not be trusted with the namespace
//! should receive a duplicated handle instead.

use std::ffi::c_void;
use std::fmt::Write as _;
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::ProcessPrng;
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Mint an unguessable object name: an explicit `Local\` (session-local)
/// namespace prefix, then `prefix`, then 128 bits from the OS CSPRNG as
/// hex.
///
/// The namespace is written out rather than left implicit so the intent
/// survives review — with one caveat that can't be fixed from here: for a
/// process in session 0 (a service), `Local\` resolves to the machine's
/// global `BaseNamedObjects`, so it is a session boundary only when
/// there's a session to bound.
pub(crate) fn unique_name(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is a valid out-buffer of the stated length.
    // ProcessPrng is documented to always succeed.
    let ok = unsafe { ProcessPrng(bytes.as_mut_ptr(), bytes.len()) };
    assert_ne!(ok, 0, "ProcessPrng failed");
    let mut name = String::with_capacity(6 + prefix.len() + 32);
    name.push_str("Local\\");
    name.push_str(prefix);
    for b in bytes {
        // Infallible: writing hex into a String.
        write!(name, "{b:02x}").unwrap();
    }
    name
}

/// Encode `name` as a NUL-terminated wide string for the `W` entry points
/// — the native forms; the `A` variants convert through the process ANSI
/// code page, which is machine-configurable, so a non-ASCII name could
/// resolve differently on each side of a process boundary. Rejects
/// interior NULs, which would silently truncate the name.
pub(crate) fn to_wide_name(name: &str) -> io::Result<Vec<u16>> {
    if name.contains('\0') {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(name.encode_utf16().chain(std::iter::once(0)).collect())
}

/// Fail a `Create*` call that actually opened a pre-existing object.
///
/// Windows reports name collisions as *success* plus
/// `ERROR_ALREADY_EXISTS` in the thread's last-error slot, handing back the
/// existing object — which, for a name an attacker pre-created, means
/// signaling their event or mapping their memory. Must be called
/// immediately after the successful create, before anything else can
/// overwrite the last-error slot. Closes `handle` and errors on collision;
/// returns it unchanged otherwise.
pub(crate) fn reject_preexisting(handle: HANDLE) -> io::Result<HANDLE> {
    // SAFETY: trivially safe read of the thread's last-error slot.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // SAFETY: `handle` came from the just-succeeded create and is not
        // yet owned by anything else.
        unsafe { CloseHandle(handle) };
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an object with this name already exists (possible name squatting)",
        ));
    }
    Ok(handle)
}

/// `SECURITY_ATTRIBUTES` granting `GENERIC_ALL` to the current user's SID
/// and nothing else, for `Create*` calls on named objects.
///
/// The returned struct borrows a process-lifetime security descriptor; it's
/// valid for any later call but is only meant to be passed straight into a
/// create.
pub(crate) fn creator_only_attributes() -> io::Result<SECURITY_ATTRIBUTES> {
    Ok(SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: creator_only_sd()?,
        bInheritHandle: 0,
    })
}

/// The cached self-relative security descriptor behind
/// [`creator_only_attributes`], built once per process (0 = not yet built).
static CREATOR_ONLY_SD: AtomicUsize = AtomicUsize::new(0);

fn creator_only_sd() -> io::Result<*mut c_void> {
    let cached = CREATOR_ONLY_SD.load(Ordering::Acquire);
    if cached != 0 {
        return Ok(cached as *mut c_void);
    }
    let sd = build_creator_only_sd()?;
    match CREATOR_ONLY_SD.compare_exchange(0, sd as usize, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(sd),
        Err(winner) => {
            // Another thread built it first; free the loser.
            // SAFETY: `sd` was allocated by the SDDL conversion below and
            // never published.
            unsafe { LocalFree(sd as HLOCAL) };
            Ok(winner as *mut c_void)
        }
    }
}

/// Build a security descriptor whose protected DACL is exactly
/// `(A;;GA;;;<current user SID>)`.
fn build_creator_only_sd() -> io::Result<*mut c_void> {
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: the guard owns a valid handle.
            unsafe { CloseHandle(self.0) };
        }
    }

    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle is always valid; `token` is a valid
    // out-pointer.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let _token = HandleGuard(token);

    // TOKEN_USER is variable-size (the SID lives behind the header), so
    // query the size first.
    let mut len = 0u32;
    // SAFETY: a null buffer with zero length is the documented way to ask
    // for the required size.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` is `len` bytes, matching what the first call asked for.
    let ok =
        unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `buf` starts with a TOKEN_USER whose Sid pointer
    // targets the tail of the same buffer, which stays alive through the
    // SID-to-string call below.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };

    let mut sid_str: *mut u16 = null_mut();
    // SAFETY: `sid` is valid per above; `sid_str` receives a LocalAlloc'd
    // NUL-terminated wide string.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut sid_str) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_string = {
        let mut wide = Vec::new();
        let mut p = sid_str;
        // SAFETY: `sid_str` is NUL-terminated; the loop stops at the NUL.
        unsafe {
            while *p != 0 {
                wide.push(*p);
                p = p.add(1);
            }
        }
        String::from_utf16_lossy(&wide)
    };
    // SAFETY: `sid_str` was LocalAlloc'd by ConvertSidToStringSidW.
    unsafe { LocalFree(sid_str as HLOCAL) };

    // D: DACL, P: protected (no inherited entries), then a single
    // allow-GENERIC_ALL ACE for the current user.
    let sddl = format!("D:P(A;;GA;;;{sid_string})");
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: `sddl_w` is a valid NUL-terminated wide string for the
    // duration of the call; `sd` receives a LocalAlloc'd descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_names_are_long_distinct_and_session_local() {
        let a = unique_name("t-");
        let b = unique_name("t-");
        assert_ne!(a, b);
        // Explicit namespace + prefix + 32 hex chars of 128 random bits.
        assert!(a.starts_with("Local\\t-"));
        assert_eq!(a.len(), 6 + 2 + 32);
    }

    #[test]
    fn a_name_with_an_interior_nul_is_refused() {
        assert!(to_wide_name("bad name").is_err());
        assert_eq!(to_wide_name("fine").unwrap().last(), Some(&0));
    }

    #[test]
    fn the_creator_only_descriptor_builds_and_caches() {
        let first = creator_only_attributes().unwrap();
        let second = creator_only_attributes().unwrap();
        assert!(!first.lpSecurityDescriptor.is_null());
        // Cached: both calls hand out the same process-lifetime descriptor.
        assert_eq!(first.lpSecurityDescriptor, second.lpSecurityDescriptor);
    }
}
