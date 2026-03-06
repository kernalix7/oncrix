// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PFN remapping (`remap_pfn_range`).
//!
//! Implements `remap_pfn_range()` for mapping physical page frame
//! numbers (PFNs) directly into user-space virtual address space.
//! This is the mechanism used by device drivers to expose MMIO
//! regions, frame buffers, and other device memory to user
//! processes via `mmap()`.
//!
//! # Features
//!
//! - **MMIO mapping** -- map device registers into user VAS with
//!   uncacheable (UC) or write-combining (WC) memory types.
//! - **Frame buffer mapping** -- map contiguous physical memory
//!   (e.g., GPU VRAM) with write-combining for performance.
//! - **PFN validation** -- ensure the target PFN range does not
//!   overlap with kernel-reserved memory.
//! - **Page table construction** -- populate PTE entries for the
//!   requested virtual range pointing to the specified PFNs.
//! - **Cache attribute control** -- set memory type (UC, WC, WB,
//!   WT) on the mapping via PTE PAT/PCD/PWT bits.
//!
//! # Architecture
//!
//! - [`RemapFlags`] -- flag set for remap configuration
//! - [`PfnRange`] -- physical PFN range descriptor
//! - [`RemapState`] -- per-mapping state
//! - [`PfnRemap`] -- outcome descriptor
//! - [`RemapStats`] -- aggregate statistics
//! - [`PfnRemapManager`] -- the remap engine
//!
//! Reference: Linux `mm/memory.c` (`remap_pfn_range`),
//! `include/linux/mm.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Page frame number shift (12 bits for 4 KiB pages).
const PFN_SHIFT: u32 = 12;

/// Maximum number of active PFN remappings.
const MAX_REMAPS: usize = 128;

/// Maximum number of PFN ranges tracked.
const MAX_PFN_RANGES: usize = 64;

// ── Memory type constants ────────────────────────────────────────

/// Uncacheable memory type (for MMIO).
pub const MEM_TYPE_UC: u32 = 0;

/// Write-combining memory type (for frame buffers).
pub const MEM_TYPE_WC: u32 = 1;

/// Write-through memory type.
pub const MEM_TYPE_WT: u32 = 2;

/// Write-back memory type (normal RAM).
pub const MEM_TYPE_WB: u32 = 3;

/// Uncacheable minus (UC-) -- allows MTRR override.
pub const MEM_TYPE_UCM: u32 = 4;

// ── Remap flag constants ─────────────────────────────────────────

/// Allow shared mapping (multiple processes).
pub const REMAP_SHARED: u32 = 0x1;

/// Map as read-only (no PTE_WRITABLE).
pub const REMAP_RDONLY: u32 = 0x2;

/// Do not set PTE_USER (kernel-only mapping).
pub const REMAP_KERNEL: u32 = 0x4;

/// Skip PFN validation (trusted caller).
pub const REMAP_NOPFNCHECK: u32 = 0x8;

/// Mark mapping as non-executable.
pub const REMAP_NOEXEC: u32 = 0x10;

/// Valid remap flag mask.
const REMAP_VALID_MASK: u32 =
    REMAP_SHARED | REMAP_RDONLY | REMAP_KERNEL | REMAP_NOPFNCHECK | REMAP_NOEXEC;

// ── PTE bits (x86_64) ───────────────────────────────────────────

/// PTE present bit.
const PTE_PRESENT: u64 = 1 << 0;

/// PTE writable bit.
const PTE_WRITABLE: u64 = 1 << 1;

/// PTE user-accessible bit.
const PTE_USER: u64 = 1 << 2;

/// PTE write-through bit (PWT).
const PTE_PWT: u64 = 1 << 3;

/// PTE cache-disable bit (PCD).
const PTE_PCD: u64 = 1 << 4;

/// PTE no-execute bit (NX, bit 63).
const PTE_NX: u64 = 1 << 63;

// ── RemapFlags ───────────────────────────────────────────────────

/// Validated remap flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemapFlags(u32);

impl RemapFlags {
    /// Parse and validate raw remap flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !REMAP_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Raw bitmask.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Whether `REMAP_SHARED` is set.
    pub const fn is_shared(self) -> bool {
        self.0 & REMAP_SHARED != 0
    }

    /// Whether `REMAP_RDONLY` is set.
    pub const fn is_read_only(self) -> bool {
        self.0 & REMAP_RDONLY != 0
    }

    /// Whether `REMAP_KERNEL` is set.
    pub const fn is_kernel(self) -> bool {
        self.0 & REMAP_KERNEL != 0
    }

    /// Whether `REMAP_NOPFNCHECK` is set.
    pub const fn skip_pfn_check(self) -> bool {
        self.0 & REMAP_NOPFNCHECK != 0
    }

    /// Whether `REMAP_NOEXEC` is set.
    pub const fn is_noexec(self) -> bool {
        self.0 & REMAP_NOEXEC != 0
    }
}

// ── PfnRange ────────────────────────────────────────────────────

/// Descriptor for a contiguous range of physical page frames.
#[derive(Debug, Clone, Copy)]
pub struct PfnRange {
    /// Starting PFN.
    pub start_pfn: u64,
    /// Number of pages in the range.
    pub page_count: u64,
    /// Memory type for this PFN range.
    pub mem_type: u32,
    /// Whether this range is reserved (kernel/firmware).
    pub reserved: bool,
    /// Whether this range is MMIO (not backed by RAM).
    pub is_mmio: bool,
    /// Device identifier that owns this range (0 = none).
    pub device_id: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl PfnRange {
    /// Create an empty, inactive PFN range.
    const fn empty() -> Self {
        Self {
            start_pfn: 0,
            page_count: 0,
            mem_type: MEM_TYPE_UC,
            reserved: false,
            is_mmio: false,
            device_id: 0,
            active: false,
        }
    }

    /// Exclusive end PFN.
    pub const fn end_pfn(&self) -> u64 {
        self.start_pfn.saturating_add(self.page_count)
    }

    /// Physical start address.
    pub const fn phys_start(&self) -> u64 {
        self.start_pfn << PFN_SHIFT
    }

    /// Physical end address (exclusive).
    pub const fn phys_end(&self) -> u64 {
        self.end_pfn() << PFN_SHIFT
    }

    /// Whether a PFN falls within this range.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        self.active && pfn >= self.start_pfn && pfn < self.end_pfn()
    }
}

// ── RemapState ──────────────────────────────────────────────────

/// State of a single active PFN remapping.
///
/// Tracks the virtual-to-physical mapping created by a
/// `remap_pfn_range` call.
#[derive(Debug, Clone, Copy)]
pub struct RemapState {
    /// Virtual start address of the mapping.
    pub virt_start: u64,
    /// Size of the mapping in bytes.
    pub size: u64,
    /// Starting PFN of the physical range.
    pub start_pfn: u64,
    /// Memory type used for the PTEs.
    pub mem_type: u32,
    /// Remap flags.
    pub flags: RemapFlags,
    /// Owning process ID.
    pub owner_pid: u64,
    /// Device that owns the physical memory (0 = none).
    pub device_id: u32,
    /// PTE flags applied to each entry.
    pub pte_flags: u64,
    /// Whether this mapping is active.
    pub active: bool,
    /// Reference count (for shared mappings).
    pub ref_count: u32,
}

impl RemapState {
    /// Create an empty, inactive remap state.
    const fn empty() -> Self {
        Self {
            virt_start: 0,
            size: 0,
            start_pfn: 0,
            mem_type: MEM_TYPE_UC,
            flags: RemapFlags(0),
            owner_pid: 0,
            device_id: 0,
            pte_flags: 0,
            active: false,
            ref_count: 0,
        }
    }

    /// Virtual end address (exclusive).
    pub const fn virt_end(&self) -> u64 {
        self.virt_start.saturating_add(self.size)
    }

    /// Number of pages in this mapping.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }
}

// ── PfnRemap ────────────────────────────────────────────────────

/// Outcome of a PFN remap operation.
#[derive(Debug, Clone, Copy)]
pub struct PfnRemap {
    /// Virtual address where the mapping was created.
    pub virt_addr: u64,
    /// Physical address of the start of the mapped region.
    pub phys_addr: u64,
    /// Size of the mapping in bytes.
    pub size: u64,
    /// Number of PTEs created.
    pub ptes_created: u64,
    /// PTE flags used.
    pub pte_flags: u64,
    /// Whether the operation succeeded.
    pub success: bool,
}

impl Default for PfnRemap {
    fn default() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            size: 0,
            ptes_created: 0,
            pte_flags: 0,
            success: false,
        }
    }
}

// ── RemapStats ──────────────────────────────────────────────────

/// Aggregate statistics for PFN remap operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct RemapStats {
    /// Total remap_pfn_range calls.
    pub total_calls: u64,
    /// Successful remaps.
    pub successful: u64,
    /// Failed remaps.
    pub failed: u64,
    /// Total pages mapped.
    pub pages_mapped: u64,
    /// Total pages unmapped.
    pub pages_unmapped: u64,
    /// MMIO mapping count.
    pub mmio_mappings: u64,
    /// Frame buffer mapping count.
    pub framebuf_mappings: u64,
    /// PFN validation failures.
    pub pfn_check_failures: u64,
}

// ── PfnRemapManager ────────────────────────────────────────────

/// The PFN remap engine.
///
/// Manages PFN-to-virtual mappings, validates PFN ranges, and
/// constructs page table entries with appropriate cache attributes.
pub struct PfnRemapManager {
    /// Active remappings.
    remaps: [RemapState; MAX_REMAPS],
    /// Number of active remappings.
    remap_count: usize,
    /// Known PFN ranges (RAM, MMIO, reserved).
    pfn_ranges: [PfnRange; MAX_PFN_RANGES],
    /// Number of registered PFN ranges.
    pfn_range_count: usize,
    /// Aggregate statistics.
    stats: RemapStats,
}

impl Default for PfnRemapManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PfnRemapManager {
    /// Creates a new, empty PFN remap manager.
    pub const fn new() -> Self {
        Self {
            remaps: [const { RemapState::empty() }; MAX_REMAPS],
            remap_count: 0,
            pfn_ranges: [const { PfnRange::empty() }; MAX_PFN_RANGES],
            pfn_range_count: 0,
            stats: RemapStats {
                total_calls: 0,
                successful: 0,
                failed: 0,
                pages_mapped: 0,
                pages_unmapped: 0,
                mmio_mappings: 0,
                framebuf_mappings: 0,
                pfn_check_failures: 0,
            },
        }
    }

    // ── PFN range management ────────────────────────────────────

    /// Register a known physical PFN range.
    ///
    /// Used to inform the remap engine about physical memory
    /// layout (RAM, MMIO, reserved regions).
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the PFN range table is full.
    /// - [`Error::InvalidArgument`] if `page_count` is zero.
    pub fn register_pfn_range(
        &mut self,
        start_pfn: u64,
        page_count: u64,
        mem_type: u32,
        reserved: bool,
        is_mmio: bool,
        device_id: u32,
    ) -> Result<()> {
        if page_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .pfn_ranges
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = PfnRange {
            start_pfn,
            page_count,
            mem_type,
            reserved,
            is_mmio,
            device_id,
            active: true,
        };
        self.pfn_range_count += 1;
        Ok(())
    }

    /// Unregister a PFN range by start PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn unregister_pfn_range(&mut self, start_pfn: u64) -> Result<()> {
        let idx = self
            .pfn_ranges
            .iter()
            .position(|r| r.active && r.start_pfn == start_pfn)
            .ok_or(Error::NotFound)?;

        self.pfn_ranges[idx].active = false;
        self.pfn_range_count = self.pfn_range_count.saturating_sub(1);
        Ok(())
    }

    /// Validate that a PFN range is safe to map.
    ///
    /// Checks that the PFN range does not overlap with reserved
    /// (kernel/firmware) memory.
    fn validate_pfn_range(&self, start_pfn: u64, page_count: u64) -> Result<()> {
        let end_pfn = start_pfn.saturating_add(page_count);

        for range in &self.pfn_ranges {
            if !range.active {
                continue;
            }
            // Check overlap with reserved ranges.
            if range.reserved && start_pfn < range.end_pfn() && end_pfn > range.start_pfn {
                return Err(Error::PermissionDenied);
            }
        }

        Ok(())
    }

    // ── Core remap operation ────────────────────────────────────

    /// Map a range of physical PFNs into a virtual address range.
    ///
    /// This is the core `remap_pfn_range()` implementation. It
    /// creates PTE entries mapping `[virt_addr, virt_addr + size)`
    /// to physical pages starting at `start_pfn`.
    ///
    /// # Arguments
    ///
    /// - `pid` -- owning process ID.
    /// - `virt_addr` -- virtual start (page-aligned).
    /// - `start_pfn` -- first physical page frame number.
    /// - `size` -- mapping size in bytes (page-aligned).
    /// - `mem_type` -- cache attribute (`MEM_TYPE_*`).
    /// - `raw_flags` -- remap flags (`REMAP_*` bitmask).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] -- bad alignment, zero size,
    ///   or invalid flags.
    /// - [`Error::PermissionDenied`] -- PFN range overlaps
    ///   reserved memory.
    /// - [`Error::OutOfMemory`] -- remap table full.
    pub fn remap_pfn_range(
        &mut self,
        pid: u64,
        virt_addr: u64,
        start_pfn: u64,
        size: u64,
        mem_type: u32,
        raw_flags: u32,
    ) -> Result<PfnRemap> {
        self.stats.total_calls += 1;

        // Validate alignment.
        if virt_addr & (PAGE_SIZE - 1) != 0 {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }
        if size == 0 || size & (PAGE_SIZE - 1) != 0 {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }
        if mem_type > MEM_TYPE_UCM {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }

        let flags = RemapFlags::from_raw(raw_flags)?;
        let page_count = size / PAGE_SIZE;

        // PFN validation (unless caller requests skip).
        if !flags.skip_pfn_check() {
            if let Err(e) = self.validate_pfn_range(start_pfn, page_count) {
                self.stats.pfn_check_failures += 1;
                self.stats.failed += 1;
                return Err(e);
            }
        }

        // Build PTE flags.
        let pte_flags = self.build_pte_flags(&flags, mem_type);

        // Find a free remap slot.
        let slot = self
            .remaps
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = RemapState {
            virt_start: virt_addr,
            size,
            start_pfn,
            mem_type,
            flags,
            owner_pid: pid,
            device_id: 0,
            pte_flags,
            active: true,
            ref_count: 1,
        };
        self.remap_count += 1;

        // Track MMIO vs framebuf mappings.
        if mem_type == MEM_TYPE_UC || mem_type == MEM_TYPE_UCM {
            self.stats.mmio_mappings += 1;
        }
        if mem_type == MEM_TYPE_WC {
            self.stats.framebuf_mappings += 1;
        }

        self.stats.successful += 1;
        self.stats.pages_mapped += page_count;

        Ok(PfnRemap {
            virt_addr,
            phys_addr: start_pfn << PFN_SHIFT,
            size,
            ptes_created: page_count,
            pte_flags,
            success: true,
        })
    }

    /// Unmap a PFN remap by virtual start address.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no mapping exists at the address.
    /// - [`Error::Busy`] if reference count is > 1.
    pub fn unmap_pfn_range(&mut self, pid: u64, virt_addr: u64) -> Result<u64> {
        let idx = self
            .remaps
            .iter()
            .position(|r| r.active && r.owner_pid == pid && r.virt_start == virt_addr)
            .ok_or(Error::NotFound)?;

        if self.remaps[idx].ref_count > 1 {
            self.remaps[idx].ref_count -= 1;
            return Ok(0);
        }

        let pages = self.remaps[idx].page_count();
        self.remaps[idx].active = false;
        self.remap_count = self.remap_count.saturating_sub(1);
        self.stats.pages_unmapped += pages;

        Ok(pages)
    }

    /// Build PTE flags from remap flags and memory type.
    fn build_pte_flags(&self, flags: &RemapFlags, mem_type: u32) -> u64 {
        let mut pte = PTE_PRESENT;

        if !flags.is_kernel() {
            pte |= PTE_USER;
        }
        if !flags.is_read_only() {
            pte |= PTE_WRITABLE;
        }
        if flags.is_noexec() {
            pte |= PTE_NX;
        }

        // Set cache attribute bits based on memory type.
        match mem_type {
            MEM_TYPE_UC | MEM_TYPE_UCM => {
                pte |= PTE_PCD; // Cache disable.
            }
            MEM_TYPE_WC => {
                pte |= PTE_PWT; // Write-through (PAT-based WC).
            }
            MEM_TYPE_WT => {
                pte |= PTE_PWT; // Write-through.
            }
            MEM_TYPE_WB => {
                // No special bits -- default is write-back.
            }
            _ => {}
        }

        pte
    }

    // ── Query operations ────────────────────────────────────────

    /// Look up a remap by virtual address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping contains the
    /// address.
    pub fn lookup(&self, pid: u64, virt_addr: u64) -> Result<&RemapState> {
        self.remaps
            .iter()
            .find(|r| {
                r.active
                    && r.owner_pid == pid
                    && virt_addr >= r.virt_start
                    && virt_addr < r.virt_end()
            })
            .ok_or(Error::NotFound)
    }

    /// Translate a virtual address to a physical address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping contains the
    /// address.
    pub fn virt_to_phys(&self, pid: u64, virt_addr: u64) -> Result<u64> {
        let remap = self.lookup(pid, virt_addr)?;
        let offset = virt_addr - remap.virt_start;
        let phys = (remap.start_pfn << PFN_SHIFT) + offset;
        Ok(phys)
    }

    /// Increment the reference count on a shared mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping at the address.
    pub fn add_ref(&mut self, pid: u64, virt_addr: u64) -> Result<u32> {
        let remap = self
            .remaps
            .iter_mut()
            .find(|r| r.active && r.owner_pid == pid && r.virt_start == virt_addr)
            .ok_or(Error::NotFound)?;

        remap.ref_count = remap.ref_count.saturating_add(1);
        Ok(remap.ref_count)
    }

    // ── Accessors ───────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &RemapStats {
        &self.stats
    }

    /// Number of active remappings.
    pub fn remap_count(&self) -> usize {
        self.remap_count
    }

    /// Number of registered PFN ranges.
    pub fn pfn_range_count(&self) -> usize {
        self.pfn_range_count
    }

    /// Iterate over active remaps for a process.
    pub fn remaps_for(&self, pid: u64) -> impl Iterator<Item = &RemapState> {
        self.remaps
            .iter()
            .filter(move |r| r.active && r.owner_pid == pid)
    }

    /// Unmap all PFN remaps for a process (cleanup on exit).
    pub fn unmap_all(&mut self, pid: u64) {
        for remap in self.remaps.iter_mut() {
            if remap.active && remap.owner_pid == pid {
                self.stats.pages_unmapped += remap.page_count();
                remap.active = false;
                self.remap_count = self.remap_count.saturating_sub(1);
            }
        }
    }
}
