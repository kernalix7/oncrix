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

/// Base virtual address of the per-process anonymous mmap window.
pub const USER_MMAP_BASE: u64 = 0x0060_0000;
/// End (exclusive) of the per-process anonymous mmap window.
pub const USER_MMAP_END: u64 = 0x0080_0000;
/// Index into `PD_0_1G` that covers VMA `0x600000..0x800000`.
///
/// `(0x600000 >> 21) & 0x1FF == 3`. Exported so kernel-core can
/// install the mmap PT at the right PD slot when switching.
pub const USER_MMAP_PT_PD_INDEX: usize = 3;

/// POSIX `PROT_READ` — page is readable.
pub const MMAP_PROT_READ: u32 = 1;
/// POSIX `PROT_WRITE` — page is writable.
pub const MMAP_PROT_WRITE: u32 = 2;
/// POSIX `PROT_EXEC` — page is executable.
pub const MMAP_PROT_EXEC: u32 = 4;

/// PTE flags used for user-accessible data pages.
const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;
/// PTE flag bit 63: NX (no-execute). Treated as a `u64` so the constant
/// fits without truncation when OR'd into a PTE.
const PTE_NX: u64 = 1 << 63;

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
#[derive(Debug)]
pub struct UserAddressSpace {
    /// Physical address of this process's 4 KiB page table.
    user_pt_phys: PhysAddr,
    /// Physical base address of the contiguous 2 MiB backing region.
    region_phys: PhysAddr,
    /// Function used to map a physical address back to its higher-half
    /// kernel alias for in-kernel reads/writes.
    phys_to_virt: PhysToVirt,
    /// Physical address of the per-process anonymous-mmap page table,
    /// allocated lazily on the first call to [`Self::mmap_anonymous`].
    /// `None` means the process has never mapped any anonymous memory
    /// — kernel-core leaves `PD_0_1G[3]` as the boot huge-page entry
    /// while this process runs.
    mmap_pt_phys: Option<PhysAddr>,
    /// Number of 4 KiB pages currently allocated inside the mmap
    /// window. Anonymous mappings grow upward from [`USER_MMAP_BASE`];
    /// the next page returned to the user is at
    /// `USER_MMAP_BASE + mmap_used_pages * PAGE_SIZE`.
    mmap_used_pages: u32,
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
            mmap_pt_phys: None,
            mmap_used_pages: 0,
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

    /// Physical address of the per-process anonymous-mmap page table,
    /// or `None` if the process has not yet called `mmap`.
    ///
    /// Kernel-core writes this (OR'd with `PRESENT|WRITABLE|USER`)
    /// into `PD_0_1G[`[`USER_MMAP_PT_PD_INDEX`]`]` whenever the
    /// process is scheduled, and restores the boot kernel-only huge
    /// PDE for slot 3 when the value is `None` so anonymous mmap
    /// pages cannot leak across processes.
    pub fn mmap_pt_phys(&self) -> Option<PhysAddr> {
        self.mmap_pt_phys
    }

    /// Allocate `len_bytes` of anonymous, zero-filled, ring-3
    /// memory and return the user virtual address of the first page.
    ///
    /// `len_bytes` is rounded up to a multiple of [`PAGE_SIZE`].
    /// Allocations grow upward from [`USER_MMAP_BASE`]; if the
    /// request would exceed [`USER_MMAP_END`] the call returns
    /// [`Error::OutOfMemory`].
    ///
    /// On the first successful call this method also allocates the
    /// per-process mmap page table from `alloc` and stores its
    /// physical address in [`Self::mmap_pt_phys`]. Subsequent calls
    /// reuse the same PT.
    ///
    /// PTE flags are derived from `prot`:
    /// - `PRESENT | USER` is always set.
    /// - `WRITABLE` is set when `prot & MMAP_PROT_WRITE != 0`.
    /// - `NX` (no-execute) is set when `prot & MMAP_PROT_EXEC == 0`.
    ///
    /// # Safety
    ///
    /// Mutates physical memory the kernel exposes via `phys_to_virt`.
    /// Caller must hold the single-CPU + interrupts-off invariant the
    /// rest of the per-process VM machinery already requires.
    pub unsafe fn mmap_anonymous<A: FrameAllocator>(
        &mut self,
        alloc: &mut A,
        len_bytes: usize,
        prot: u32,
    ) -> Result<u64> {
        if len_bytes == 0 {
            return Err(Error::InvalidArgument);
        }
        let pages = len_bytes.div_ceil(PAGE_SIZE);
        if pages > u32::MAX as usize {
            return Err(Error::OutOfMemory);
        }

        // Bounds check against the 2 MiB mmap window.
        let start_page = self.mmap_used_pages as u64;
        let end_page = start_page
            .checked_add(pages as u64)
            .ok_or(Error::OutOfMemory)?;
        let window_pages = (USER_MMAP_END - USER_MMAP_BASE) / PAGE_SIZE as u64;
        if end_page > window_pages {
            return Err(Error::OutOfMemory);
        }

        // Lazily allocate the mmap page table on the first call.
        if self.mmap_pt_phys.is_none() {
            let pt_frame = alloc.allocate_frame().ok_or(Error::OutOfMemory)?;
            // SAFETY: Freshly allocated, page-aligned, unaliased frame.
            unsafe {
                core::ptr::write_bytes((self.phys_to_virt)(pt_frame.start_addr()), 0, PAGE_SIZE);
            }
            self.mmap_pt_phys = Some(pt_frame.start_addr());
        }
        let pt_phys = self.mmap_pt_phys.expect("mmap PT just installed");

        // Allocate `pages` frames; on any failure roll back this call's
        // newly-allocated frames so the caller sees an atomic ENOMEM.
        let mut new_frames: [Option<Frame>; 512] = [None; 512];
        for slot in new_frames.iter_mut().take(pages) {
            match alloc.allocate_frame() {
                Some(f) => *slot = Some(f),
                None => {
                    for f in new_frames.iter().flatten() {
                        alloc.deallocate_frame(*f);
                    }
                    return Err(Error::OutOfMemory);
                }
            }
        }

        // Compute PTE flags. NX is honoured only when the kernel has
        // enabled `EFER.NXE`; otherwise setting bit 63 raises a
        // "reserved bit set" page fault. Boot enables NXE for ONCRIX
        // (see `init_syscall`), so applying NX here is safe.
        let mut pte_flags: u64 = PTE_P | PTE_U;
        if prot & MMAP_PROT_WRITE != 0 {
            pte_flags |= PTE_W;
        }
        if prot & MMAP_PROT_EXEC == 0 {
            pte_flags |= PTE_NX;
        }

        // Zero each frame and write the PTE for it.
        // SAFETY: pt_phys is page-aligned and unaliased except via
        // phys_to_virt. We write exactly `pages` u64 entries within the
        // 512-entry table.
        unsafe {
            let pt = (self.phys_to_virt)(pt_phys).cast::<u64>();
            for (i, slot) in new_frames.iter().take(pages).enumerate() {
                let frame = slot.expect("frame populated above");
                let frame_phys = frame.start_addr();
                core::ptr::write_bytes((self.phys_to_virt)(frame_phys), 0, PAGE_SIZE);
                let pt_index = (start_page as usize) + i;
                *pt.add(pt_index) = frame_phys.as_u64() | pte_flags;
            }
        }

        self.mmap_used_pages += pages as u32;
        Ok(USER_MMAP_BASE + start_page * PAGE_SIZE as u64)
    }

    /// Duplicate this address space into a new one (eager copy, for
    /// POSIX `fork` semantics).
    ///
    /// Allocates a fresh PT and backing region from `alloc`, then
    /// `memcpy`s the parent's entire 2 MiB into the child. The child's
    /// PT is rewired to point at the child's own frames so no sharing
    /// remains. If the parent has any anonymous mmap pages the child
    /// also receives a freshly allocated mmap PT plus per-page frames
    /// memcpy'd from the parent, so post-fork the child observes the
    /// same contents but no shared physical pages. On failure the
    /// partially-allocated child is released.
    ///
    /// # Safety
    ///
    /// The parent's backing region must not be concurrently written
    /// by ring 3 during the copy. In practice `fork` freezes the
    /// parent across this call.
    pub unsafe fn clone_for_fork<A: FrameAllocator>(&self, alloc: &mut A) -> Result<Self> {
        let mut child = Self::new_empty(alloc, self.phys_to_virt)?;
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

        // Replicate the anonymous mmap region if present.
        if let Some(parent_pt_phys) = self.mmap_pt_phys {
            let used = self.mmap_used_pages as usize;
            // Allocate child mmap PT.
            let child_pt_frame = match alloc.allocate_frame() {
                Some(f) => f,
                None => {
                    child.release(alloc);
                    return Err(Error::OutOfMemory);
                }
            };
            // SAFETY: Freshly allocated, page-aligned, unaliased frame.
            unsafe {
                core::ptr::write_bytes(
                    (self.phys_to_virt)(child_pt_frame.start_addr()),
                    0,
                    PAGE_SIZE,
                );
            }
            child.mmap_pt_phys = Some(child_pt_frame.start_addr());

            // Copy each in-use mmap page.
            for page_index in 0..used {
                // Read parent PTE.
                // SAFETY: parent_pt_phys is page-aligned and exclusively
                // accessed via phys_to_virt during this single-CPU call.
                let parent_pte = unsafe {
                    let pt = (self.phys_to_virt)(parent_pt_phys).cast::<u64>();
                    *pt.add(page_index)
                };
                if parent_pte & PTE_P == 0 {
                    continue;
                }
                let parent_phys = PhysAddr::new(parent_pte & 0x000F_FFFF_FFFF_F000);
                let new_frame = match alloc.allocate_frame() {
                    Some(f) => f,
                    None => {
                        child.release(alloc);
                        return Err(Error::OutOfMemory);
                    }
                };
                // SAFETY: Both pointers refer to exclusively owned 4 KiB
                // frames. Single-CPU + interrupts-off context prevents
                // concurrent writes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (self.phys_to_virt)(parent_phys),
                        (self.phys_to_virt)(new_frame.start_addr()),
                        PAGE_SIZE,
                    );
                    let child_pt = (self.phys_to_virt)(child_pt_frame.start_addr()).cast::<u64>();
                    let flags_only = parent_pte & !0x000F_FFFF_FFFF_F000;
                    *child_pt.add(page_index) = new_frame.start_addr().as_u64() | flags_only;
                }
            }
            child.mmap_used_pages = self.mmap_used_pages;
        }

        Ok(child)
    }

    /// Release every owned frame back to `alloc`.
    ///
    /// Must be called before drop to avoid leaking frames. Callers
    /// typically invoke this from `exit` / the last close path.
    pub fn release<A: FrameAllocator>(self, alloc: &mut A) {
        // Return mmap-region frames first (if any).
        if let Some(mmap_pt_phys) = self.mmap_pt_phys {
            let used = self.mmap_used_pages as usize;
            // SAFETY: mmap_pt_phys is page-aligned, owned by this UAS,
            // and accessed exclusively through phys_to_virt.
            unsafe {
                let pt = (self.phys_to_virt)(mmap_pt_phys).cast::<u64>();
                for i in 0..used {
                    let pte = *pt.add(i);
                    if pte & PTE_P == 0 {
                        continue;
                    }
                    let phys = PhysAddr::new(pte & 0x000F_FFFF_FFFF_F000);
                    if let Some(frame) = Frame::from_addr(phys) {
                        alloc.deallocate_frame(frame);
                    }
                }
            }
            if let Some(frame) = Frame::from_addr(mmap_pt_phys) {
                alloc.deallocate_frame(frame);
            }
        }

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
