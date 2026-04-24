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
//!
//! # Phase 10b page-table layout (x86_64)
//!
//! The boot stub (`boot.S`) identity-maps physical 0..1 GiB via 2 MiB
//! huge pages in `PML4[0] → PDPT_low[0] → PD_0_1G` with no user bit.
//! To run ring-3 code at VMA 0x400000..0x600000, Phase 10b:
//!
//! 1. Sets the U bit on `PML4[0]` and `PDPT_low[0]` (ring 3 is now
//!    allowed to traverse the low canonical half).
//! 2. Replaces the 2 MiB huge PDE at `PD_0_1G[2]` (covers 0x400000..
//!    0x600000) with a pointer to a fresh 4 KiB page table [`USER_PT`]
//!    whose 512 entries remap those 2 MiB virtually onto the kernel
//!    BSS-backed [`USER_LOAD_REGION`] frames with P|W|U bits. That
//!    breaks the accidental identity collision with kernel physical
//!    memory and hands ring 3 a dedicated 2 MiB window.
//! 3. Copies the ELF PT_LOAD segments into `USER_LOAD_REGION` at their
//!    `p_vaddr - 0x400000` offset (with `.bss` tail zero-filled).
//! 4. Returns the ELF entry point so `kernel_main` can iretq to it at
//!    ring 3 with a 16-byte-aligned RSP inside the same 2 MiB window.

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
// Static user-space load region (2 MiB, page-aligned)
// ---------------------------------------------------------------------------

/// Kernel higher-half virtual base (matches `linker.ld` and `boot.S`).
#[cfg(feature = "embed-init")]
const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// User code base virtual address (matches `user.ld`).
#[cfg(feature = "embed-init")]
const USER_BASE: u64 = 0x0040_0000;

/// Size of the static user-space load region (2 MiB — one PD entry).
#[cfg(feature = "embed-init")]
const USER_REGION_SIZE: usize = 2 * 1024 * 1024;

/// User-space stack top (grows down from the end of the user region).
#[cfg(feature = "embed-init")]
const USER_STACK_TOP: u64 = USER_BASE + USER_REGION_SIZE as u64;

/// User-space initial RSP: 16 bytes below the top of the user region,
/// 16-byte aligned to satisfy the SysV AMD64 ABI at `_start`.
#[cfg(feature = "embed-init")]
const USER_INIT_RSP: u64 = USER_STACK_TOP - 16;

/// Page-table entry flag: present.
#[cfg(feature = "embed-init")]
const PTE_P: u64 = 1 << 0;
/// Page-table entry flag: writable.
#[cfg(feature = "embed-init")]
const PTE_W: u64 = 1 << 1;
/// Page-table entry flag: user-accessible (CPL 3).
#[cfg(feature = "embed-init")]
const PTE_U: u64 = 1 << 2;
/// Page-table entry physical-address mask (bits 12..51).
#[cfg(feature = "embed-init")]
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Static backing store for the user-space ELF load region.
///
/// Lives in kernel BSS (higher-half VMA, physical frames in the kernel's
/// load region). Phase 10b remaps virt 0x400000..0x600000 onto these
/// physical frames so ring 3 has a 2 MiB window that does not collide
/// with the kernel's own identity-mapped physical memory.
#[cfg(feature = "embed-init")]
#[repr(C, align(4096))]
struct UserLoadRegion([u8; USER_REGION_SIZE]);

#[cfg(feature = "embed-init")]
static mut USER_LOAD_REGION: UserLoadRegion = UserLoadRegion([0; USER_REGION_SIZE]);

/// A 4 KiB page table (512 × 8-byte entries).
#[cfg(feature = "embed-init")]
#[repr(C, align(4096))]
struct PageTablePage([u64; 512]);

/// Dedicated page table that remaps user VMA 0x400000..0x600000 onto
/// [`USER_LOAD_REGION`] with user-accessible PTEs. Linked into
/// `PD_0_1G[2]` by [`install_user_mapping`].
#[cfg(feature = "embed-init")]
static mut USER_PT: PageTablePage = PageTablePage([0; 512]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load the embedded `init` ELF and return its entry point, or `None`
/// if the feature is disabled or the binary is malformed.
///
/// On success:
/// - [`USER_LOAD_REGION`] holds the loaded PT_LOAD segments.
/// - The boot page tables have been patched so virt 0x400000..0x600000
///   is user-accessible and backed by [`USER_LOAD_REGION`].
/// - The caller should jump to the returned entry point at ring 3 with
///   RSP = [`USER_INIT_RSP`] (see [`user_init_rsp`]).
///
/// # Safety
///
/// Must be called exactly once during single-threaded boot after
/// GDT/IDT/heap initialization and before enabling multi-core or
/// multi-threading.
pub unsafe fn load_init_elf() -> Option<u64> {
    #[cfg(not(feature = "embed-init"))]
    {
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

        // SAFETY: Single-threaded boot. USER_LOAD_REGION is unaliased
        // and the segment bounds are validated before each copy.
        unsafe {
            copy_segments_into_user_region(data, &segments[..seg_count])?;
        }

        // SAFETY: Boot page tables are owned by the kernel and not yet
        // touched by any other core. We patch them in-place and flush
        // the TLB below.
        unsafe {
            install_user_mapping();
        }

        let _ = serial.write_str("[ONCRIX] init ELF loaded at 0x400000, entry=");
        write_hex(&mut serial, info.entry);
        let _ = serial.write_str("\n");

        Some(info.entry)
    }
}

/// Initial user RSP to pair with [`load_init_elf`]'s entry point.
///
/// Returns a 16-byte aligned address near the top of the user region.
/// Returns 0 when the `embed-init` feature is disabled — callers must
/// check the [`load_init_elf`] return value before using this.
#[cfg(feature = "embed-init")]
pub const fn user_init_rsp() -> u64 {
    USER_INIT_RSP
}

/// Placeholder when `embed-init` is disabled.
#[cfg(not(feature = "embed-init"))]
pub const fn user_init_rsp() -> u64 {
    0
}

/// Return the physical address of the per-process page table for the
/// init process (`USER_PT`).
///
/// Used by the boot path to record `user_pt_phys` on the init thread
/// so that the scheduler can patch `PD_0_1G[2]` correctly on every
/// context switch in Phase 10c's single-PT model.
///
/// Returns `None` when `embed-init` is disabled.
#[cfg(feature = "embed-init")]
pub fn init_user_pt_phys() -> Option<u64> {
    // SAFETY: Computing the virtual address of a static and converting
    // to a physical address via the known higher-half offset is safe as
    // long as the static lives in the kernel load region (which it does —
    // it's a BSS-allocated `static mut`).
    let virt = &raw const USER_PT as u64;
    Some(virt - KERNEL_VIRT_BASE)
}

/// Placeholder when `embed-init` is disabled.
#[cfg(not(feature = "embed-init"))]
pub fn init_user_pt_phys() -> Option<u64> {
    None
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Copy each PT_LOAD segment from `data` into [`USER_LOAD_REGION`] at
/// `p_vaddr - USER_BASE`, zero-filling the `.bss` tail.
///
/// # Safety
///
/// Must be called on the single-threaded boot CPU before
/// [`install_user_mapping`] exposes the region to ring 3.
#[cfg(feature = "embed-init")]
unsafe fn copy_segments_into_user_region(data: &[u8], segments: &[elf::LoadSegment]) -> Option<()> {
    // SAFETY: Single-threaded boot; USER_LOAD_REGION is not aliased.
    let region_ptr = (&raw mut USER_LOAD_REGION).cast::<u8>();

    for seg in segments {
        // Reject segments outside the 2 MiB user region.
        let start = seg.vaddr.checked_sub(USER_BASE)?;
        let mem_size = seg.mem_size;
        let end = start.checked_add(mem_size)?;
        if end > USER_REGION_SIZE as u64 {
            return None;
        }

        // Reject segments whose file range is out of bounds.
        let file_off = seg.file_offset as usize;
        let file_sz = seg.file_size as usize;
        let file_end = file_off.checked_add(file_sz)?;
        if file_end > data.len() {
            return None;
        }

        // SAFETY: Bounds checked above. Both buffers are byte arrays.
        unsafe {
            let dst = region_ptr.add(start as usize);
            core::ptr::copy_nonoverlapping(data.as_ptr().add(file_off), dst, file_sz);

            let bss_size = mem_size as usize - file_sz;
            if bss_size > 0 {
                core::ptr::write_bytes(dst.add(file_sz), 0, bss_size);
            }
        }
    }

    Some(())
}

/// Patch the boot page tables so user VMA 0x400000..0x600000 is
/// accessible at ring 3 and backed by [`USER_LOAD_REGION`] frames.
///
/// Walks the boot page tables via CR3, sets the user bit on `PML4[0]`
/// and `PDPT_low[0]`, then replaces the 2 MiB huge PDE at
/// `PD_0_1G[2]` with a pointer to [`USER_PT`] whose entries map each
/// 4 KiB page onto the corresponding physical frame of
/// [`USER_LOAD_REGION`] with P|W|U bits. Finishes with a full TLB
/// flush (reload of CR3).
///
/// # Safety
///
/// Must be called on the single-threaded boot CPU. Callers must have
/// already copied all needed data into [`USER_LOAD_REGION`] because
/// this function makes that memory reachable from ring 3.
#[cfg(feature = "embed-init")]
unsafe fn install_user_mapping() {
    // SAFETY: Reading CR3 is a privileged but side-effect-free operation.
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }
    let pml4_phys = cr3 & PTE_ADDR_MASK;

    // SAFETY: `phys_to_higher_half` is valid for any physical address
    // covered by the boot higher-half map (0..1 GiB). Boot page tables
    // live in `.boot.bss` whose physical frames fall in that range.
    let pml4 = phys_to_higher_half(pml4_phys) as *mut u64;
    unsafe {
        *pml4.add(0) |= PTE_U;
    }

    // SAFETY: PML4[0] now has a present mapping to PDPT_low — address
    // extracted from the same entry.
    let pdpt_low_phys = unsafe { *pml4.add(0) } & PTE_ADDR_MASK;
    let pdpt_low = phys_to_higher_half(pdpt_low_phys) as *mut u64;
    unsafe {
        *pdpt_low.add(0) |= PTE_U;
    }

    // SAFETY: PDPT_low[0] points at PD_0_1G.
    let pd_phys = unsafe { *pdpt_low.add(0) } & PTE_ADDR_MASK;
    let pd = phys_to_higher_half(pd_phys) as *mut u64;

    // Build USER_PT entries covering 0x400000..0x600000 mapped onto
    // USER_LOAD_REGION's contiguous physical frames.
    let region_virt = &raw const USER_LOAD_REGION as u64;
    let region_phys = region_virt - KERNEL_VIRT_BASE;

    let user_pt_virt = &raw mut USER_PT as u64;
    let user_pt_phys = user_pt_virt - KERNEL_VIRT_BASE;
    let user_pt = user_pt_virt as *mut u64;

    for i in 0..512 {
        let page_phys = region_phys + (i as u64) * 0x1000;
        // SAFETY: USER_PT has exactly 512 entries; `i < 512`.
        unsafe {
            *user_pt.add(i) = page_phys | PTE_P | PTE_W | PTE_U;
        }
    }

    // Replace the 2 MiB huge PDE at PD[2] with a pointer to USER_PT.
    // PD index for VMA 0x400000 = (0x400000 >> 21) & 0x1FF = 2.
    //
    // SAFETY: pd is a valid higher-half alias of PD_0_1G; entry 2
    // corresponds to the 2 MiB slot at 0x400000..0x600000.
    unsafe {
        *pd.add(2) = user_pt_phys | PTE_P | PTE_W | PTE_U;
    }

    // Full TLB flush — simplest way to drop the now-stale huge-page
    // translation and any cached NX/U bits along the walk.
    //
    // SAFETY: Writing CR3 with its current value reloads the page
    // tables and invalidates all non-global TLB entries. Interrupts
    // are disabled during boot so no in-flight memory access relies
    // on a specific TLB state.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr3",
            "mov cr3, {tmp}",
            tmp = out(reg) _,
            options(nomem, nostack),
        );
    }
}

/// Convert a physical address in the 0..1 GiB boot range into its
/// higher-half virtual alias.
#[cfg(feature = "embed-init")]
#[inline]
fn phys_to_higher_half(phys: u64) -> u64 {
    phys + KERNEL_VIRT_BASE
}

/// Write a 64-bit value as `0x`-prefixed hex to the serial console.
#[cfg(feature = "embed-init")]
fn write_hex<S: SerialPort>(serial: &mut S, value: u64) {
    let _ = serial.write_str("0x");
    let mut buf = [0u8; 16];
    let mut n = value;
    for byte in buf.iter_mut().rev() {
        let digit = (n & 0xF) as u8;
        *byte = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        n >>= 4;
    }
    let start = buf.iter().position(|&b| b != b'0').unwrap_or(15);
    for &b in &buf[start..] {
        let _ = serial.write_byte(b);
    }
}
