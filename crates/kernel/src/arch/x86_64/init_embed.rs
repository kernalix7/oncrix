// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Embedded `init` userspace binary and ELF launch path.
//!
//! When the kernel is built with the `embed-init` feature enabled, the
//! `init` ELF binary (pre-built by the kernel `build.rs`) is embedded
//! as a byte slice and launched after Phase 10 instead of the hello-world
//! smoke-test stub.
//!
//! # Build pipeline
//!
//! 1. `crates/kernel/build.rs` invokes `cargo build -p oncrix-init` and
//!    exports `ONCRIX_INIT_BIN` to the Rust compile environment.
//! 2. This module uses `include_bytes!(env!("ONCRIX_INIT_BIN"))` under
//!    `#[cfg(feature = "embed-init")]` to embed the binary.
//! 3. `kernel_main` calls [`load_init_elf`] and, if it returns a valid
//!    entry point, uses `jump_to_usermode` to launch it at ring 3.

#[cfg(feature = "embed-init")]
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
#[cfg(feature = "embed-init")]
use oncrix_hal::serial::SerialPort;

#[cfg(feature = "embed-init")]
use crate::elf;

// ---------------------------------------------------------------------------
// Embedded binary
// ---------------------------------------------------------------------------

/// The embedded `init` ELF binary.
///
/// Present only when the `embed-init` feature is enabled and
/// `ONCRIX_INIT_BIN` was set by `build.rs`.
#[cfg(feature = "embed-init")]
static INIT_ELF: &[u8] = include_bytes!(env!("ONCRIX_INIT_BIN"));

/// Placeholder when the feature is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
static INIT_ELF: Option<&[u8]> = None;

// ---------------------------------------------------------------------------
// Static user-space load region (4 MiB, page-aligned)
// ---------------------------------------------------------------------------

/// Size of the static user-space load region.
#[cfg(feature = "embed-init")]
const USER_REGION_SIZE: usize = 4 * 1024 * 1024;

/// Static backing store for the user-space ELF load region.
///
/// In a full kernel each process would have its own page-table-mapped
/// region.  For this early-boot single-process case a static array suffices.
#[cfg(feature = "embed-init")]
#[repr(C, align(4096))]
struct UserLoadRegion([u8; USER_REGION_SIZE]);

#[cfg(feature = "embed-init")]
static mut USER_LOAD_REGION: UserLoadRegion = UserLoadRegion([0; USER_REGION_SIZE]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the embedded `init` ELF and report it on the serial console.
///
/// Returns `None` unconditionally for now:
/// - Build-pipeline verification: when `embed-init` is enabled the ELF is
///   embedded via `include_bytes!(env!("ONCRIX_INIT_BIN"))` and its header
///   + PT_LOAD segment table is parsed to prove the binary is well-formed.
/// - Runtime launch is deferred to Phase 10b: jumping to 0x400000 requires
///   a per-process page table that maps the user VMA with the user-accessible
///   bit set. Until that lands the caller falls back to `usermode_test_entry`,
///   whose address is already mapped (it lives in the kernel image).
///
/// # Safety
///
/// Must be called exactly once during single-threaded boot.
pub unsafe fn load_init_elf() -> Option<u64> {
    #[cfg(not(feature = "embed-init"))]
    {
        // Feature not enabled — caller uses the smoke-test stub.
        let _ = INIT_ELF;
        None
    }

    #[cfg(feature = "embed-init")]
    {
        let data: &[u8] = INIT_ELF;

        let mut serial = Uart16550::new(COM1);
        let _ = serial.write_str("[ONCRIX] Verifying embedded init ELF...\n");

        let info = elf::parse_header(data).ok()?;
        let (_segments, seg_count) = elf::load_segments(data).ok()?;

        // Reference the segment staging area so the symbol is not dropped;
        // the real copy path lands with Phase 10b's process VM.
        // SAFETY: Single-threaded boot; USER_LOAD_REGION is not aliased.
        let _region = unsafe {
            let ptr = (&raw mut USER_LOAD_REGION).cast::<u8>();
            core::slice::from_raw_parts_mut(ptr, USER_REGION_SIZE)
        };

        let _ = serial.write_str("[ONCRIX] init ELF parsed (");
        let _ = serial.write_str(if seg_count == 1 {
            "1 segment"
        } else {
            "N segments"
        });
        let _ = serial.write_str(")\n");
        let _ = info.entry;

        // Falling back to the smoke-test stub until the page-table path exists.
        None
    }
}
