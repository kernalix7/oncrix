// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process user-mode address space (Phase 10c fork/exec support).
//!
//! The current boot path (`crates/kernel/src/arch/x86_64/init_embed.rs`)
//! uses a single, static pair:
//!
//! - `USER_PT`: 4 KiB page table mapped into `PD_0_1G[2]`, exposing
//!   VMA `0x400000..0x600000` to ring 3.
//! - `USER_LOAD_REGION`: static 2 MiB BSS buffer that `USER_PT`'s 512
//!   entries point at.
//!
//! That singleton cannot support `fork`/`execve`: each process needs
//! its own PT and its own backing frames so parent and child can
//! diverge. [`UserAddressSpace`] owns one of each, allocated from a
//! [`FrameAllocator`].
//!
//! # Layout
//!
//! Every [`UserAddressSpace`] reserves:
//!
//! ```text
//! PT  (4 KiB, 512 entries)           ← per-process, patched into PD[2]
//! └─ entries[0..512] ─► Backing region (contiguous 2 MiB)
//!                        VMA 0x0040_0000..0x0060_0000 at ring 3
//! ```
//!
//! The backing region is allocated as 512 contiguous 4 KiB frames so
//! the existing PD-entry-swap switching scheme keeps working: the PT
//! contains sequential physical frames covering a flat 2 MiB window.
//!
//! # Accessing per-process frames from the kernel
//!
//! Kernel code must read/write the backing region through a higher-half
//! alias (ONCRIX maps physical 0..1 GiB at `0xFFFF_FFFF_8000_0000`).
//! Rather than hard-code that mapping here, constructors accept a
//! [`PhysToVirt`] function pointer the caller (kernel-core) supplies.
//! This keeps `oncrix-mm` free of architecture-specific constants
//! beyond what's already in `page_table`.
//!
//! # What this type does NOT do
//!
//! - It does not itself install the PT into a live PD — kernel-core
//!   must do that while switching processes (see
//!   [`UserAddressSpace::user_pt_phys`]).
//! - It does not implement copy-on-write. [`clone_for_fork`] performs
//!   an eager copy of the full 2 MiB backing region. CoW can be added
//!   later on top of this primitive; POSIX `fork` semantics are
//!   preserved either way (see `susv5-html/functions/fork.html`).
//! - It does not allocate a per-process stack separately: the top of
//!   the 2 MiB region doubles as the initial user stack (matches the
//!   existing `USER_INIT_RSP` in `init_embed.rs`).

use crate::addr::{PAGE_SIZE, PhysAddr};
use crate::frame::{Frame, FrameAllocator};
use oncrix_lib::{Error, Result};

use super::elf_loader::{self, ElfLoadInfo};

/// Size of the per-process user-mode backing region (2 MiB).
///
/// Matches `USER_REGION_SIZE` in `init_embed.rs` exactly so the
/// existing PT/PD hand-off keeps working.
pub const USER_REGION_SIZE: usize = 2 * 1024 * 1024;

/// Number of 4 KiB frames backing one [`USER_REGION_SIZE`] region.
pub const USER_REGION_FRAMES: usize = USER_REGION_SIZE / PAGE_SIZE;

/// Entries in a 4 KiB page table.
const ENTRIES_PER_PT: usize = 512;

/// Index into `PD_0_1G` that covers VMA `0x400000..0x600000`.
///
/// `(0x400000 >> 21) & 0x1FF == 2`. Exported so kernel-core can
/// install the per-process PT at the right PD slot when switching.
pub const USER_PT_PD_INDEX: usize = 2;

/// PTE flags used for user-accessible data pages.
const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;

/// Physical-to-virtual translation supplied by the caller.
///
/// Given a physical address in the kernel-mapped low range, returns
/// the higher-half virtual alias the kernel can read/write through.
/// The function must be infallible for any address returned by the
/// [`FrameAllocator`] passed to [`UserAddressSpace::new_empty`] (in
/// practice the bitmap allocator only hands out frames in the kernel's
/// identity-mapped range).
pub type PhysToVirt = fn(PhysAddr) -> *mut u8;

/// One process's user-mode VMA.
///
/// Holds the physical addresses of its owned page table and backing
/// region, plus a cached `PhysToVirt` for in-kernel access. Dropping
/// this struct does **not** free its frames — the caller must return
/// them to the [`FrameAllocator`] via [`UserAddressSpace::release`]
/// before drop, otherwise the frames leak. This avoids forcing a
/// global allocator pointer into every [`UserAddressSpace`].
pub struct UserAddressSpace {
    /// Physical address of this process's 4 KiB page table.
    user_pt_phys: PhysAddr,
    /// Physical base address of the contiguous 2 MiB backing region.
    region_phys: PhysAddr,
    /// Function used to map a physical address back to its higher-half
    /// kernel alias for in-kernel reads/writes.
    phys_to_virt: PhysToVirt,
}

impl UserAddressSpace {
    /// Allocate and initialise an empty user address space.
    ///
    /// Allocates one 4 KiB frame for the per-process page table plus
    /// [`USER_REGION_FRAMES`] contiguous frames for the backing region.
    /// The PT is pre-wired so each entry maps its matching region
    /// frame with `PRESENT | WRITABLE | USER`. The backing region is
    /// zeroed — caller-supplied `map_elf_segments` will populate it.
    ///
    /// Returns [`Error::OutOfMemory`] if the allocator cannot produce
    /// `1 + USER_REGION_FRAMES` contiguous frames.
    ///
    /// # Contiguity requirement
    ///
    /// The current PT layout requires the 512 region frames to form a
    /// single contiguous run: the PT holds `region_phys + i*4KiB` for
    /// `i in 0..512`. We enforce this by allocating sequentially and
    /// checking each new frame is one page above the previous. If any
    /// gap is observed the partial allocation is released and the
    /// call fails. This mirrors the `USER_LOAD_REGION` static layout
    /// in `init_embed.rs`.
    pub fn new_empty<A: FrameAllocator>(alloc: &mut A, phys_to_virt: PhysToVirt) -> Result<Self> {
        // Allocate the PT frame first.
        let pt_frame = alloc.allocate_frame().ok_or(Error::OutOfMemory)?;

        // Allocate USER_REGION_FRAMES contiguous frames.
        let mut region_frames: [Option<Frame>; USER_REGION_FRAMES] = [None; USER_REGION_FRAMES];
        let first = match alloc.allocate_frame() {
            Some(f) => f,
            None => {
                alloc.deallocate_frame(pt_frame);
                return Err(Error::OutOfMemory);
            }
        };
        region_frames[0] = Some(first);
        let mut expected = first.number().wrapping_add(1);

        for slot in region_frames.iter_mut().skip(1) {
            let f = match alloc.allocate_frame() {
                Some(f) => f,
                None => {
                    release_frames(alloc, pt_frame, &region_frames);
                    return Err(Error::OutOfMemory);
                }
            };
            if f.number() != expected {
                // Non-contiguous. Put this one back, release the rest.
                alloc.deallocate_frame(f);
                release_frames(alloc, pt_frame, &region_frames);
                return Err(Error::OutOfMemory);
            }
            *slot = Some(f);
            expected = expected.wrapping_add(1);
        }

        // Zero the backing region.
        let region_phys = first.start_addr();
        // SAFETY: `phys_to_virt` returns a pointer to a kernel-mapped
        // range covering the freshly allocated, unaliased physical
        // frames. The region is [region_phys, region_phys + 2 MiB).
        unsafe {
            core::ptr::write_bytes(phys_to_virt(region_phys), 0, USER_REGION_SIZE);
        }

        // Populate the PT entries to map VMA 0x400000..0x600000 onto
        // the contiguous physical frames.
        let user_pt_phys = pt_frame.start_addr();
        // SAFETY: The PT frame was just allocated, is page-aligned,
        // and is not aliased. We write exactly 512 u64 entries.
        unsafe {
            let pt = phys_to_virt(user_pt_phys).cast::<u64>();
            for i in 0..ENTRIES_PER_PT {
                let page_phys = region_phys.as_u64() + (i as u64) * PAGE_SIZE as u64;
                *pt.add(i) = page_phys | PTE_P | PTE_W | PTE_U;
            }
        }

        Ok(Self {
            user_pt_phys,
            region_phys,
            phys_to_virt,
        })
    }

    /// Physical address of this process's user-mode page table.
    ///
    /// Kernel-core writes this (OR'd with `PRESENT|WRITABLE|USER`)
    /// into `PD_0_1G[`[`USER_PT_PD_INDEX`]`]` when switching to this
    /// process, then issues a TLB flush for the 2 MiB range.
    pub fn user_pt_phys(&self) -> PhysAddr {
        self.user_pt_phys
    }

    /// Physical base address of the 2 MiB backing region.
    pub fn region_phys(&self) -> PhysAddr {
        self.region_phys
    }

    /// Size of the backing region in bytes.
    pub const fn region_size(&self) -> usize {
        USER_REGION_SIZE
    }

    /// Return a kernel-side byte slice over the full backing region.
    ///
    /// # Safety
    ///
    /// The caller must guarantee this [`UserAddressSpace`]'s backing
    /// region is not concurrently mapped to ring 3 (i.e. the process
    /// owning it is not currently scheduled on any CPU), otherwise
    /// user code could race against kernel reads/writes of the same
    /// physical memory.
    pub unsafe fn backing_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: The backing region is USER_REGION_SIZE bytes of
        // valid, kernel-owned physical memory aliased at
        // `phys_to_virt(region_phys)`. Caller upholds the no-ring-3-
        // aliasing invariant documented above.
        unsafe {
            core::slice::from_raw_parts_mut((self.phys_to_virt)(self.region_phys), USER_REGION_SIZE)
        }
    }

    /// Load an ELF64 image into the backing region.
    ///
    /// Returns the entry point to jump to at ring 3. All PT_LOAD
    /// segments must fall inside `[0x400000, 0x400000 + 2 MiB)`; see
    /// [`elf_loader::load_elf_into`] for detailed error conditions.
    ///
    /// # Safety
    ///
    /// See [`backing_slice_mut`](Self::backing_slice_mut) — the
    /// caller must ensure the backing region is not concurrently
    /// visible to ring 3.
    pub unsafe fn map_elf_segments(&mut self, elf: &[u8]) -> Result<u64> {
        // SAFETY: Forwarded to caller (see function-level doc).
        let dst = unsafe { self.backing_slice_mut() };
        let info: ElfLoadInfo = elf_loader::load_elf_into(elf, dst)?;
        Ok(info.entry)
    }

    /// Duplicate this address space into a new one (eager copy, for
    /// POSIX `fork` semantics).
    ///
    /// Allocates a fresh PT and backing region from `alloc`, then
    /// `memcpy`s the parent's entire 2 MiB into the child. The child's
    /// PT is rewired to point at the child's own frames so no sharing
    /// remains. On failure the partially-allocated child is released.
    ///
    /// # Safety
    ///
    /// The parent's backing region must not be concurrently written
    /// by ring 3 during the copy. In practice `fork` freezes the
    /// parent across this call.
    pub unsafe fn clone_for_fork<A: FrameAllocator>(&self, alloc: &mut A) -> Result<Self> {
        let child = Self::new_empty(alloc, self.phys_to_virt)?;
        // SAFETY: Both pointers come from `phys_to_virt` on freshly
        // allocated or exclusively-owned frames. Sizes are exactly
        // USER_REGION_SIZE. Caller guarantees the parent region is
        // not being mutated via ring 3 during the copy.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.phys_to_virt)(self.region_phys),
                (self.phys_to_virt)(child.region_phys),
                USER_REGION_SIZE,
            );
        }
        Ok(child)
    }

    /// Release every owned frame back to `alloc`.
    ///
    /// Must be called before drop to avoid leaking frames. Callers
    /// typically invoke this from `exit` / the last close path.
    pub fn release<A: FrameAllocator>(self, alloc: &mut A) {
        // Return the PT frame.
        if let Some(frame) = Frame::from_addr(self.user_pt_phys) {
            alloc.deallocate_frame(frame);
        }
        // Return every region frame.
        for i in 0..USER_REGION_FRAMES {
            let addr = PhysAddr::new(self.region_phys.as_u64() + (i as u64) * PAGE_SIZE as u64);
            if let Some(frame) = Frame::from_addr(addr) {
                alloc.deallocate_frame(frame);
            }
        }
    }
}

/// Return partially allocated region frames plus the PT frame to
/// `alloc` when `new_empty` fails mid-way.
fn release_frames<A: FrameAllocator>(
    alloc: &mut A,
    pt_frame: Frame,
    frames: &[Option<Frame>; USER_REGION_FRAMES],
) {
    alloc.deallocate_frame(pt_frame);
    for f in frames.iter().flatten() {
        alloc.deallocate_frame(*f);
    }
}
