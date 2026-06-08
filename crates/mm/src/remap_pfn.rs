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

/// Exclusive upper bound on a valid PFN.
///
/// A PFN `p` is only convertible to a physical address without
/// overflowing `u64` when `p << PFN_SHIFT` fits in 64 bits, i.e.
/// `p < 2^(64 - PFN_SHIFT)`. Any PFN at or above this bound is
/// rejected before it is ever shifted.
//
// SECURITY: this bound is what makes every `pfn << PFN_SHIFT` in this
// module safe. With overflow-checks ON an unbounded shift of an
// attacker-supplied PFN would panic in ring 0 (DoS); silently it would
// wrap and synthesise an arbitrary physical address.
const MAX_PFN: u64 = 1u64 << (64 - PFN_SHIFT);

/// Convert a PFN to a physical address, rejecting out-of-range PFNs.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `pfn >= MAX_PFN` (the shift
/// would overflow `u64`).
//
// SECURITY: single choke point for PFN→phys conversion so the
// `<< PFN_SHIFT` can never overflow / wrap.
const fn pfn_to_phys(pfn: u64) -> Result<u64> {
    if pfn >= MAX_PFN {
        return Err(Error::InvalidArgument);
    }
    match pfn.checked_shl(PFN_SHIFT) {
        Some(v) => Ok(v),
        None => Err(Error::InvalidArgument),
    }
}

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
    ///
    /// Saturates at [`u64::MAX`] for an out-of-range `start_pfn` rather
    /// than overflowing; registered ranges are bounded below `MAX_PFN`
    /// by [`PfnRemapManager::register_pfn_range`], so the saturation is
    /// only a defence-in-depth guard.
    //
    // SECURITY: the previous `start_pfn << PFN_SHIFT` panicked (ring 0
    // DoS, overflow-checks ON) / wrapped for `start_pfn >= MAX_PFN`.
    pub const fn phys_start(&self) -> u64 {
        if self.start_pfn >= MAX_PFN {
            return u64::MAX;
        }
        self.start_pfn << PFN_SHIFT
    }

    /// Physical end address (exclusive).
    ///
    /// Saturates at [`u64::MAX`] rather than overflowing.
    //
    // SECURITY: bounded shift; see [`Self::phys_start`].
    pub const fn phys_end(&self) -> u64 {
        let end = self.end_pfn();
        if end >= MAX_PFN {
            return u64::MAX;
        }
        end << PFN_SHIFT
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
    /// - [`Error::InvalidArgument`] if `page_count` is zero or the
    ///   `[start_pfn, start_pfn + page_count)` range is not fully
    ///   representable as a physical address (`end_pfn > MAX_PFN`).
    //
    // SECURITY: registered ranges are later used (default-deny) to
    // authorise user mappings and are shifted by `PFN_SHIFT`. Bounding
    // the PFN range here guarantees `phys_start` / `phys_end` and every
    // downstream `pfn << PFN_SHIFT` stay within `u64` and cannot panic
    // (ring 0 DoS, overflow-checks ON) or wrap to an arbitrary address.
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
        // Reject a PFN range that cannot be converted to a physical
        // address (or whose end PFN would wrap past `MAX_PFN`).
        let end_pfn = start_pfn
            .checked_add(page_count)
            .ok_or(Error::InvalidArgument)?;
        if start_pfn >= MAX_PFN || end_pfn > MAX_PFN {
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

    /// Validate that a PFN range is safe to map into user space.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the range is empty or its end
    ///   PFN would overflow / exceed [`MAX_PFN`].
    /// - [`Error::PermissionDenied`] if the range is not fully covered
    ///   by a registered, non-reserved PFN range.
    //
    // SECURITY: DEFAULT-DENY. The previous implementation only rejected
    // overlaps with explicitly *reserved* ranges, meaning any PFN the
    // caller had not bothered to reserve (the entire un-described
    // physical address space) was mappable into user space — an
    // arbitrary-physical-memory read/write primitive and a privilege
    // escalation. We now require the *whole* requested range to lie
    // inside a single registered range that is NOT reserved, so only
    // physical memory the kernel has explicitly published (device MMIO,
    // frame buffers) can ever be remapped. PFN remapping must remain
    // capability-gated at the caller; this is the in-module backstop.
    fn validate_pfn_range(&self, start_pfn: u64, page_count: u64) -> Result<()> {
        if page_count == 0 {
            return Err(Error::InvalidArgument);
        }
        // Bound the PFN range before any shift; a wrapping / oversized
        // end PFN is rejected outright.
        let end_pfn = start_pfn
            .checked_add(page_count)
            .ok_or(Error::InvalidArgument)?;
        if start_pfn >= MAX_PFN || end_pfn > MAX_PFN {
            return Err(Error::InvalidArgument);
        }

        // Require full containment in a registered, non-reserved range.
        let permitted = self.pfn_ranges.iter().any(|range| {
            range.active
                && !range.reserved
                && start_pfn >= range.start_pfn
                && end_pfn <= range.end_pfn()
        });
        if !permitted {
            return Err(Error::PermissionDenied);
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

        // SECURITY: bound the PFN range BEFORE any `<< PFN_SHIFT`, even
        // when `REMAP_NOPFNCHECK` is set. `skip_pfn_check` only waives
        // the registered-range (default-deny) check below; it must NOT
        // let an out-of-range PFN reach the shift and panic in ring 0
        // (overflow-checks ON) or wrap to a bogus physical address.
        let end_pfn = start_pfn
            .checked_add(page_count)
            .ok_or(Error::InvalidArgument)
            .inspect_err(|_| self.stats.failed += 1)?;
        if start_pfn >= MAX_PFN || end_pfn > MAX_PFN {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }

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

        // SECURITY: bounded PFN→phys conversion (no raw `<< PFN_SHIFT`).
        // `start_pfn < MAX_PFN` is already guaranteed above, so this
        // cannot fail here, but routing through the helper keeps the
        // shift impossible to overflow.
        let phys_addr = pfn_to_phys(start_pfn).inspect_err(|_| self.stats.failed += 1)?;

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
            phys_addr,
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
        // `lookup` guarantees `virt_addr >= remap.virt_start`, so this
        // subtraction cannot underflow.
        let offset = virt_addr - remap.virt_start;
        // SECURITY: bounded PFN→phys conversion plus a checked add for
        // the in-mapping offset, so neither the `<< PFN_SHIFT` nor the
        // base+offset can overflow / panic in ring 0. A stored
        // `start_pfn` is already `< MAX_PFN` (enforced at remap time).
        let base = pfn_to_phys(remap.start_pfn)?;
        let phys = base.checked_add(offset).ok_or(Error::InvalidArgument)?;
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
