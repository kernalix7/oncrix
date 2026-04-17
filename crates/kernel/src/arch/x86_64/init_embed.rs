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

/// Load the embedded `init` ELF into the static user-load region.
///
/// Copies each PT_LOAD segment from the embedded ELF data into the static
/// `USER_LOAD_REGION` buffer and returns the entry-point virtual address.
///
/// Returns `None` when:
/// - The `embed-init` feature is not enabled.
/// - ELF parsing fails.
/// - A segment extends beyond `USER_REGION_SIZE`.
///
/// # Safety
///
/// Must be called exactly once during single-threaded boot, before any
/// jump to ring 3.  The `USER_LOAD_REGION` static must not be aliased.
pub unsafe fn load_init_elf() -> Option<u64> {
    #[cfg(not(feature = "embed-init"))]
    {
        // Feature not enabled — caller falls back to smoke-test stub.
        let _ = INIT_ELF;
        None
    }

    #[cfg(feature = "embed-init")]
    {
        let data: &[u8] = INIT_ELF;

        let mut serial = Uart16550::new(COM1);
        let _ = serial.write_str("[ONCRIX] Loading embedded init ELF...\n");

        let info = elf::parse_header(data).ok()?;
        let (segments, seg_count) = elf::load_segments(data).ok()?;

        // SAFETY: Single-threaded boot; USER_LOAD_REGION is not aliased.
        // `&raw mut` avoids creating a reference to the `static mut`, per
        // Rust 2024's `static_mut_refs` lint.
        let region = unsafe {
            let ptr = (&raw mut USER_LOAD_REGION).cast::<u8>();
            core::slice::from_raw_parts_mut(ptr, USER_REGION_SIZE)
        };

        // Base offset: ELF is linked at USER_BASE (0x400000); our static
        // region starts at its own address. Compute the delta so we can
        // map VMA → region offset.
        let region_base = region.as_ptr() as u64;

        for seg in &segments[..seg_count] {
            let file_data = data
                .get(seg.file_offset as usize..)
                .and_then(|s| s.get(..seg.file_size as usize))?;

            // Determine where in our static region this segment lands.
            // The ELF vaddr is the intended VMA (e.g. 0x401000).
            // We copy directly to USER_LOAD_REGION + (vaddr - region_base)
            // only if they happen to coincide. For the simple case where
            // the region IS mapped at the ELF's link address, the offset is 0.
            //
            // In this early-boot stub we copy to the raw vaddr, trusting
            // the kernel identity-maps physical == virtual for this range.
            if seg.mem_size as usize > USER_REGION_SIZE {
                let _ = serial.write_str("[ONCRIX] init ELF segment too large\n");
                return None;
            }

            // Copy using the region buffer as backing — offset from region base.
            let vaddr_offset = seg.vaddr.checked_sub(region_base)? as usize;
            if vaddr_offset + seg.mem_size as usize > USER_REGION_SIZE {
                // If the vaddr doesn't fall within our static region, fall back
                // to writing directly to the VMA (assumes identity mapping).
                // SAFETY: The identity mapping guarantees vaddr is accessible.
                let dst = unsafe {
                    core::slice::from_raw_parts_mut(seg.vaddr as *mut u8, seg.mem_size as usize)
                };
                dst[..seg.file_size as usize].copy_from_slice(file_data);
                for b in &mut dst[seg.file_size as usize..] {
                    *b = 0;
                }
            } else {
                let dst = &mut region[vaddr_offset..vaddr_offset + seg.mem_size as usize];
                dst[..seg.file_size as usize].copy_from_slice(file_data);
                for b in &mut dst[seg.file_size as usize..] {
                    *b = 0;
                }
            }
        }

        let _ = serial.write_str("[ONCRIX] init ELF loaded\n");
        Some(info.entry)
    }
}
