// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Global physical-frame allocator for the kernel.
//!
//! Phase 13 wires a single [`BitmapAllocator`] into the kernel so that
//! per-process [`UserAddressSpace`] instances (and any future page-table
//! work) can allocate fresh physical frames at runtime. Until SMP is
//! introduced, the allocator runs in single-CPU SYSCALL context with
//! interrupts off — the same invariant as `PROCESS_TABLE` and
//! `CURRENT_FD_TABLE`.
//!
//! # Memory layout
//!
//! The allocator manages **96 MiB** starting at physical `0x0200_0000`
//! (32 MiB):
//!
//! ```text
//!  phys 0x0000_0000 .. 0x0200_0000   reserved (BIOS, kernel image,
//!                                    boot page tables, kernel heap)
//!  phys 0x0200_0000 .. 0x0800_0000   FRAME_ALLOC pool (96 MiB)
//! ```
//!
//! The kernel image's `_end` symbol (linker-provided) sits around phys
//! `0x01BCA188` (≈ 28 MiB) on current builds; reserving up to 32 MiB
//! gives ample headroom for ROM data and boot-time scratch. The pool's
//! 96 MiB sits comfortably inside the QEMU `-m 128M` budget.
//!
//! # Kernel-side access (`phys_to_virt`)
//!
//! The boot page tables map the first 1 GiB of physical memory at the
//! higher-half virtual base [`KERNEL_VIRT_BASE`] (`0xFFFF_FFFF_8000_0000`).
//! [`phys_to_virt`] adds that base to a [`PhysAddr`] so kernel code can
//! read/write a freshly allocated frame without per-frame mapping work.
//! Every frame the allocator hands out lies inside `[0x0200_0000,
//! 0x0800_0000)`, well within the higher-half map.
//!
//! [`UserAddressSpace`]: oncrix_mm::address_space::UserAddressSpace

use oncrix_mm::addr::PhysAddr;
use oncrix_mm::bitmap::BitmapAllocator;

/// Higher-half kernel virtual base. The boot page tables map physical
/// `0..1 GiB` here.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Base physical address managed by the global frame allocator (32 MiB).
///
/// Chosen well above the kernel image (`_end ≈ 0x01BCA188`) so the
/// allocator never hands out a frame the kernel is using for code,
/// static data, or BSS.
pub const FRAME_ALLOC_BASE: u64 = 0x0200_0000;

/// Number of frames managed (96 MiB / 4 KiB = 24576).
pub const FRAME_ALLOC_FRAMES: usize = 24576;

/// Global physical frame allocator.
///
/// Single-CPU invariant: every accessor is `unsafe` and may only be
/// called with interrupts disabled (i.e. from the SYSCALL dispatch
/// path or from single-threaded boot). No `Mutex` is needed because
/// the entire kernel runs on a single CPU and no IRQ handler touches
/// physical-frame allocation.
// SAFETY: Accessed exclusively through [`frame_alloc`] from single-CPU
// contexts, mirroring the existing `PROCESS_TABLE` / `CURRENT_FD_TABLE`
// invariants.
static mut FRAME_ALLOC: BitmapAllocator =
    BitmapAllocator::new(PhysAddr::new(FRAME_ALLOC_BASE), FRAME_ALLOC_FRAMES);

/// Initialise the global frame allocator.
///
/// Marks every frame in `[FRAME_ALLOC_BASE, FRAME_ALLOC_BASE + 96 MiB)`
/// as free. Must be called exactly once during single-threaded boot,
/// before any code attempts to construct a [`UserAddressSpace`].
///
/// # Safety
///
/// Single-CPU boot context. No other code may touch [`FRAME_ALLOC`]
/// concurrently. Calling this twice will reset all allocations made
/// since the previous call (any outstanding frames will be silently
/// reissued).
pub unsafe fn init() {
    // SAFETY: Single-threaded boot; FRAME_ALLOC is not yet aliased.
    unsafe {
        #[allow(static_mut_refs)]
        let alloc = &mut FRAME_ALLOC;
        alloc.mark_range_free(0, FRAME_ALLOC_FRAMES);
    }
}

/// Return a `&'static mut` reference to the global frame allocator.
///
/// The reference is `'static` because [`FRAME_ALLOC`] lives for the
/// kernel's lifetime. Callers must release the borrow before yielding
/// the CPU or re-entering any path that could indirectly call
/// [`frame_alloc`] again — the single-CPU + interrupts-off invariant
/// makes the borrow trivially exclusive.
///
/// # Safety
///
/// * Must be called with interrupts disabled (single-CPU invariant).
/// * The returned mutable borrow must not alias any other reference
///   to [`FRAME_ALLOC`].
#[allow(static_mut_refs)]
pub unsafe fn frame_alloc() -> &'static mut BitmapAllocator {
    // SAFETY: caller upholds the single-CPU + no-aliasing contract.
    unsafe { &mut FRAME_ALLOC }
}

/// Translate a physical address into its kernel higher-half alias.
///
/// Used by [`oncrix_mm::address_space::UserAddressSpace`] to read/write
/// freshly allocated frames without per-frame mapping. The boot page
/// tables map the entire `0..1 GiB` physical range at
/// [`KERNEL_VIRT_BASE`] so any address inside the allocator's pool is
/// reachable through this offset.
///
/// # Safety contract for callers
///
/// The pointer is valid only for physical addresses covered by the
/// boot higher-half map (currently `0..1 GiB`). All frames returned by
/// the global frame allocator satisfy that invariant.
pub fn phys_to_virt(p: PhysAddr) -> *mut u8 {
    (p.as_u64() + KERNEL_VIRT_BASE) as *mut u8
}
