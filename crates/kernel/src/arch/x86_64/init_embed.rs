// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Embedded `init` and `/bin/sh` ELF blobs.
//!
//! Phase 13 stripped this module of its page-table-patching logic. The
//! singleton `USER_PT` / `USER_LOAD_REGION` plus
//! `install_user_mapping` / `load_init_elf` / `load_sh_elf` paths are
//! all gone — they were the source of the post-`wait4` `#UD` because
//! the parent's text was overwritten by the child's `execve`. Per-
//! process address spaces now live in
//! [`oncrix_mm::address_space::UserAddressSpace`], allocated through
//! [`crate::frame_alloc`], and installed at `PD_0_1G[2]` via
//! [`crate::arch::x86_64::init::install_user_pt`].
//!
//! What remains here is the build-time embedding of the userspace ELF
//! binaries. `kernel/build.rs` exports `ONCRIX_INIT_BIN` and
//! `ONCRIX_SH_BIN`; this module includes the bytes and exposes
//! [`embedded_init_elf`] / [`embedded_sh_elf`] for the boot path and
//! `sys_execve` respectively.

// ---------------------------------------------------------------------------
// Embedded binaries
// ---------------------------------------------------------------------------

/// The embedded `init` ELF binary.
///
/// Present only when the `embed-init` feature is enabled and
/// `ONCRIX_INIT_BIN` was set by `build.rs`.
#[cfg(feature = "embed-init")]
static EMBEDDED_INIT: &[u8] = include_bytes!(env!("ONCRIX_INIT_BIN"));

/// The embedded `/bin/sh` ELF binary.
///
/// Built alongside `init` by `build.rs` when `embed-init` is active.
/// Returned by [`embedded_sh_elf`] so that `sys_execve("/bin/sh", …)`
/// can replace the calling process image with it.
#[cfg(feature = "embed-init")]
static EMBEDDED_SH: &[u8] = include_bytes!(env!("ONCRIX_SH_BIN"));

// ---------------------------------------------------------------------------
// Public accessors
// ---------------------------------------------------------------------------

/// Return the embedded `init` ELF bytes.
///
/// Returns `Some(&[u8])` when the `embed-init` feature is enabled and
/// `ONCRIX_INIT_BIN` was set by `build.rs`. Returns `None` otherwise.
#[cfg(feature = "embed-init")]
pub fn embedded_init_elf() -> Option<&'static [u8]> {
    Some(EMBEDDED_INIT)
}

/// Placeholder when `embed-init` is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
pub fn embedded_init_elf() -> Option<&'static [u8]> {
    None
}

/// Return the embedded `/bin/sh` ELF bytes.
///
/// Returns `Some(&[u8])` when the `embed-init` feature is enabled and
/// `ONCRIX_SH_BIN` was set by `build.rs`. Returns `None` otherwise.
#[cfg(feature = "embed-init")]
pub fn embedded_sh_elf() -> Option<&'static [u8]> {
    Some(EMBEDDED_SH)
}

/// Placeholder when `embed-init` is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
pub fn embedded_sh_elf() -> Option<&'static [u8]> {
    None
}
