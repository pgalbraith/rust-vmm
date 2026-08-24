// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Collection of modules that provides helpers and utilities used by multiple
//! [rust-vmm](https://github.com/rust-vmm/community) components.

#![deny(missing_docs, missing_debug_implementations)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use crate::linux::*;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use crate::unix::*;

#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use crate::windows::*;

pub mod align;
pub mod errno;
pub mod fam;
pub mod metric;
pub mod rand;
pub mod syscall;
pub mod tempfile;
