// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory protection range operations (`mprotect` VMA-level).
//!
//! Implements the core logic for changing virtual memory area (VMA)
//! permissions via the `mprotect(2)` system call. This module handles:
//!
//! - **Page table permission updates** -- translating `PROT_*` flags
//!   into architecture-specific page table entry (PTE) bits.
//! - **TLB flush coordination** -- ensuring stale translations are
//!   invalidated after permission changes.
//! - **VMA splitting** -- when the mprotect range partially overlaps
//!   a VMA, the VMA must be split at the boundaries.
//! - **VMA merging** -- after permission changes, adjacent VMAs with
//!   identical attributes are merged to reduce fragmentation.
//! - **Access validation** -- ensuring requested permissions are
//!   compatible with the underlying mapping (e.g., no PROT_WRITE on
//!   a read-only file mapping).
//!
//! # Architecture
//!
//! - [`ProtFlags`] -- validated protection flag set
//! - [`ProtRange`] -- a contiguous virtual range with uniform
//!   protection
//! - [`MprotectInfo`] -- a single mprotect operation descriptor
//! - [`MprotectResult`] -- outcome of a mprotect operation
//! - [`MprotectStats`] -- aggregate statistics
//! - [`MprotectRangeManager`] -- the mprotect engine
//!
//! # POSIX Reference
//!
//! - `mprotect(2)` -- POSIX.1-2024, XSH `mprotect`
//!
//! Reference: Linux `mm/mprotect.c`, `include/linux/mm.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Maximum number of protection ranges tracked.
const MAX_PROT_RANGES: usize = 256;

/// Maximum number of pending mprotect operations.
const MAX_PENDING_OPS: usize = 64;

/// Maximum number of TLB flush entries batched.
const MAX_TLB_FLUSH_ENTRIES: usize = 128;

// ── Protection flag constants ────────────────────────────────────

/// No access allowed.
pub const PROT_NONE: u32 = 0x0;

/// Pages may be read.
pub const PROT_READ: u32 = 0x1;

/// Pages may be written.
pub const PROT_WRITE: u32 = 0x2;

/// Pages may be executed.
pub const PROT_EXEC: u32 = 0x4;

/// Memory should be mapped with grow-down semantics (stack-like).
pub const PROT_GROWSDOWN: u32 = 0x0100_0000;

/// Memory should be mapped with grow-up semantics.
pub const PROT_GROWSUP: u32 = 0x0200_0000;

/// Bitmask of valid base protection flags.
const PROT_BASE_MASK: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// Bitmask of all valid protection flags including extensions.
const PROT_VALID_MASK: u32 = PROT_BASE_MASK | PROT_GROWSDOWN | PROT_GROWSUP;

// ── PTE flag constants (x86_64) ──────────────────────────────────

/// Page Table Entry: page is present.
const PTE_PRESENT: u64 = 1 << 0;

/// Page Table Entry: page is writable.
const PTE_WRITABLE: u64 = 1 << 1;

/// Page Table Entry: page is accessible from user mode.
const PTE_USER: u64 = 1 << 2;

/// Page Table Entry: page has been accessed.
const _PTE_ACCESSED: u64 = 1 << 5;

/// Page Table Entry: page has been written (dirty).
const _PTE_DIRTY: u64 = 1 << 6;

/// Page Table Entry: no-execute (NX) bit (bit 63 on x86_64).
const PTE_NO_EXEC: u64 = 1 << 63;

// ── ProtFlags ────────────────────────────────────────────────────

/// Validated protection flag set for mprotect operations.
///
/// Wraps a raw `u32` bitmask and provides type-safe queries after
/// validation. Use [`ProtFlags::from_raw`] to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtFlags(u32);

impl Default for ProtFlags {
    /// Default protection is [`PROT_NONE`] (no access).
    fn default() -> Self {
        Self(PROT_NONE)
    }
}

impl ProtFlags {
    /// Create `ProtFlags` from a raw bitmask.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw != PROT_NONE && raw & !PROT_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw `u32` bitmask.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Return `true` if the region is readable.
    pub const fn is_readable(self) -> bool {
        self.0 & PROT_READ != 0
    }

    /// Return `true` if the region is writable.
    pub const fn is_writable(self) -> bool {
        self.0 & PROT_WRITE != 0
    }

    /// Return `true` if the region is executable.
    pub const fn is_executable(self) -> bool {
        self.0 & PROT_EXEC != 0
    }

    /// Return `true` if grow-down semantics are requested.
    pub const fn grows_down(self) -> bool {
        self.0 & PROT_GROWSDOWN != 0
    }

    /// Return `true` if grow-up semantics are requested.
    pub const fn grows_up(self) -> bool {
        self.0 & PROT_GROWSUP != 0
    }

    /// Convert to x86_64 PTE flags.
    ///
    /// Returns the appropriate PTE bitmask. If `PROT_NONE`, the PTE
    /// will lack `PTE_PRESENT`.
    pub const fn to_pte_flags(self) -> u64 {
        if self.0 == PROT_NONE {
            return 0;
        }
        let mut pte = PTE_PRESENT | PTE_USER;
        if self.0 & PROT_WRITE != 0 {
            pte |= PTE_WRITABLE;
        }
        if self.0 & PROT_EXEC == 0 {
            pte |= PTE_NO_EXEC;
        }
        pte
    }

    /// Return the base protection bits only (no extension flags).
    pub const fn base_only(self) -> Self {
        Self(self.0 & PROT_BASE_MASK)
    }
}

// ── ProtRange ────────────────────────────────────────────────────

/// A contiguous virtual address range with uniform protection.
///
/// Represents a segment of a VMA that has been assigned a specific
/// set of protection flags. Used both for tracking current state
/// and for describing mprotect targets.
#[derive(Debug, Clone, Copy)]
pub struct ProtRange {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Protection flags for this range.
    pub prot: ProtFlags,
    /// Original protection before the last mprotect operation.
    pub original_prot: ProtFlags,
    /// Whether this range is part of a file-backed mapping.
    pub file_backed: bool,
    /// Whether this range is shared (MAP_SHARED).
    pub shared: bool,
    /// Owning process ID.
    pub owner_pid: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl ProtRange {
    /// Create an empty, inactive protection range.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            prot: ProtFlags(PROT_NONE),
            original_prot: ProtFlags(PROT_NONE),
            file_backed: false,
            shared: false,
            owner_pid: 0,
            active: false,
        }
    }

    /// Exclusive end address.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Number of pages in this range.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Whether an address falls within this range.
    pub const fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end()
    }

    /// Whether this range overlaps `[start, start+size)`.
    pub const fn overlaps(&self, start: u64, size: u64) -> bool {
        if !self.active || size == 0 {
            return false;
        }
        let end = start.saturating_add(size);
        self.start < end && self.end() > start
    }
}

// ── MprotectInfo ─────────────────────────────────────────────────

/// Descriptor for a single mprotect operation.
///
/// Captures the parameters and metadata needed to process one
/// `mprotect(2)` call.
#[derive(Debug, Clone, Copy)]
pub struct MprotectInfo {
    /// Process ID requesting the change.
    pub pid: u64,
    /// Start of the target range (page-aligned).
    pub addr: u64,
    /// Length of the target range in bytes.
    pub len: u64,
    /// Requested new protection flags.
    pub new_prot: ProtFlags,
    /// Whether TLB flush is needed.
    pub needs_tlb_flush: bool,
    /// Number of pages affected.
    pub affected_pages: u64,
    /// Number of VMAs split during this operation.
    pub vmas_split: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl MprotectInfo {
    /// Create an empty, inactive mprotect descriptor.
    const fn empty() -> Self {
        Self {
            pid: 0,
            addr: 0,
            len: 0,
            new_prot: ProtFlags(PROT_NONE),
            needs_tlb_flush: false,
            affected_pages: 0,
            vmas_split: 0,
            active: false,
        }
    }
}

// ── TlbFlushEntry ────────────────────────────────────────────────

/// A single TLB invalidation entry.
///
/// Describes a virtual page whose TLB entry must be flushed after
/// a permission change.
#[derive(Debug, Clone, Copy)]
struct TlbFlushEntry {
    /// Virtual address to flush.
    addr: u64,
    /// Whether this entry is active.
    active: bool,
}

impl TlbFlushEntry {
    const fn empty() -> Self {
        Self {
            addr: 0,
            active: false,
        }
    }
}

// ── MprotectResult ───────────────────────────────────────────────

/// Outcome of a mprotect operation.
#[derive(Debug, Clone, Copy)]
pub struct MprotectResult {
    /// Number of pages whose protection was changed.
    pub pages_changed: u64,
    /// Number of VMA splits performed.
    pub splits_performed: u32,
    /// Number of VMA merges performed.
    pub merges_performed: u32,
    /// Number of TLB flushes issued.
    pub tlb_flushes: u32,
    /// Whether the operation completed successfully.
    pub success: bool,
}

impl Default for MprotectResult {
    fn default() -> Self {
        Self {
            pages_changed: 0,
            splits_performed: 0,
            merges_performed: 0,
            tlb_flushes: 0,
            success: false,
        }
    }
}

// ── MprotectStats ────────────────────────────────────────────────

/// Aggregate statistics for mprotect operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MprotectStats {
    /// Total mprotect calls.
    pub total_calls: u64,
    /// Successful mprotect calls.
    pub successful: u64,
    /// Failed mprotect calls.
    pub failed: u64,
    /// Total pages with changed protection.
    pub pages_changed: u64,
    /// Total VMA splits.
    pub vma_splits: u64,
    /// Total VMA merges.
    pub vma_merges: u64,
    /// Total TLB flushes issued.
    pub tlb_flushes: u64,
    /// Permission escalations (adding write/exec).
    pub escalations: u64,
    /// Permission reductions (removing write/exec).
    pub reductions: u64,
}

// ── MprotectRangeManager ─────────────────────────────────────────

/// The mprotect engine.
///
/// Manages protection ranges, processes mprotect requests,
/// coordinates TLB flushes, and tracks statistics. Operates on
/// a fixed-size array of [`ProtRange`] entries representing the
/// current virtual memory layout.
pub struct MprotectRangeManager {
    /// Protection ranges (VMA segments).
    ranges: [ProtRange; MAX_PROT_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Pending mprotect operations.
    pending: [MprotectInfo; MAX_PENDING_OPS],
    /// Number of pending operations.
    pending_count: usize,
    /// TLB flush batch buffer.
    tlb_batch: [TlbFlushEntry; MAX_TLB_FLUSH_ENTRIES],
    /// Number of entries in the TLB flush batch.
    tlb_batch_count: usize,
    /// Aggregate statistics.
    stats: MprotectStats,
}

impl Default for MprotectRangeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MprotectRangeManager {
    /// Creates a new, empty mprotect manager.
    pub const fn new() -> Self {
        Self {
            ranges: [const { ProtRange::empty() }; MAX_PROT_RANGES],
            range_count: 0,
            pending: [const { MprotectInfo::empty() }; MAX_PENDING_OPS],
            pending_count: 0,
            tlb_batch: [const { TlbFlushEntry::empty() }; MAX_TLB_FLUSH_ENTRIES],
            tlb_batch_count: 0,
            stats: MprotectStats {
                total_calls: 0,
                successful: 0,
                failed: 0,
                pages_changed: 0,
                vma_splits: 0,
                vma_merges: 0,
                tlb_flushes: 0,
                escalations: 0,
                reductions: 0,
            },
        }
    }

    // ── Range management ────────────────────────────────────────

    /// Register a protection range (VMA segment).
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the range table is full.
    /// - [`Error::InvalidArgument`] if addresses are not
    ///   page-aligned or size is zero.
    pub fn register_range(
        &mut self,
        start: u64,
        size: u64,
        prot: ProtFlags,
        owner_pid: u64,
        file_backed: bool,
        shared: bool,
    ) -> Result<()> {
        if start & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .ranges
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = ProtRange {
            start,
            size,
            prot,
            original_prot: prot,
            file_backed,
            shared,
            owner_pid,
            active: true,
        };
        self.range_count += 1;
        Ok(())
    }

    /// Unregister a protection range by start address and owner.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn unregister_range(&mut self, start: u64, owner_pid: u64) -> Result<()> {
        let idx = self
            .ranges
            .iter()
            .position(|r| r.active && r.start == start && r.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        self.ranges[idx].active = false;
        self.range_count = self.range_count.saturating_sub(1);
        Ok(())
    }

    // ── mprotect core ───────────────────────────────────────────

    /// Execute a mprotect operation on `[addr, addr+len)`.
    ///
    /// Changes the protection of all pages in the given range to
    /// `new_prot`. If the range partially overlaps a VMA, the VMA
    /// is split at the boundary. After the change, adjacent VMAs
    /// with identical protection are merged.
    ///
    /// # Arguments
    ///
    /// - `pid` -- process ID.
    /// - `addr` -- start of target range (must be page-aligned).
    /// - `len` -- length in bytes (rounded up to page boundary).
    /// - `new_prot` -- raw protection flags (`PROT_*` bitmask).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `addr` is not page-aligned,
    ///   `len` is zero, or `new_prot` contains unknown bits.
    /// - [`Error::NotFound`] if no VMA covers the range.
    /// - [`Error::PermissionDenied`] if trying to add write
    ///   permission to a read-only file-backed shared mapping.
    pub fn do_mprotect_range(
        &mut self,
        pid: u64,
        addr: u64,
        len: u64,
        new_prot: u32,
    ) -> Result<MprotectResult> {
        self.stats.total_calls += 1;

        // Validate address alignment.
        if addr & (PAGE_SIZE - 1) != 0 {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }

        if len == 0 {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }

        let prot = ProtFlags::from_raw(new_prot)?;
        let aligned_len = page_align_up(len);
        let end = addr.saturating_add(aligned_len);

        // Check that at least one range covers the target area.
        let has_coverage = self
            .ranges
            .iter()
            .any(|r| r.active && r.owner_pid == pid && r.overlaps(addr, aligned_len));

        if !has_coverage {
            self.stats.failed += 1;
            return Err(Error::NotFound);
        }

        // Validate permission compatibility.
        if prot.is_writable() {
            for range in &self.ranges {
                if !range.active || range.owner_pid != pid {
                    continue;
                }
                if !range.overlaps(addr, aligned_len) {
                    continue;
                }
                if range.file_backed && range.shared && !range.prot.is_writable() {
                    self.stats.failed += 1;
                    return Err(Error::PermissionDenied);
                }
            }
        }

        let mut result = MprotectResult::default();

        // Process splits and permission changes.
        // First: split ranges that partially overlap the target.
        self.split_ranges_at(addr, pid)?;
        if end < u64::MAX {
            self.split_ranges_at(end, pid)?;
        }

        // Update protection on all fully-covered ranges.
        // Collect flush targets first to avoid &mut self borrow conflict.
        let mut flush_targets: [(u64, u64); MAX_PROT_RANGES] = [(0, 0); MAX_PROT_RANGES];
        let mut flush_count = 0usize;

        for range in self.ranges.iter_mut() {
            if !range.active || range.owner_pid != pid {
                continue;
            }
            if range.start >= addr && range.end() <= end {
                let old_prot = range.prot;
                range.original_prot = old_prot;
                range.prot = prot;
                result.pages_changed += range.page_count();

                // Track escalation/reduction.
                if prot.as_raw() & !old_prot.as_raw() & PROT_BASE_MASK != 0 {
                    self.stats.escalations += 1;
                }
                if old_prot.as_raw() & !prot.as_raw() & PROT_BASE_MASK != 0 {
                    self.stats.reductions += 1;
                }

                if flush_count < MAX_PROT_RANGES {
                    flush_targets[flush_count] = (range.start, range.size);
                    flush_count += 1;
                }
            }
        }

        // Queue TLB flushes after the loop.
        for i in 0..flush_count {
            self.queue_tlb_flush(flush_targets[i].0, flush_targets[i].1);
        }

        // Attempt to merge adjacent ranges with same protection.
        let merges = self.merge_adjacent_ranges(pid);
        result.merges_performed = merges;

        // Flush the TLB batch.
        let flushed = self.flush_tlb_batch();
        result.tlb_flushes = flushed;

        result.success = true;
        self.stats.successful += 1;
        self.stats.pages_changed += result.pages_changed;
        self.stats.vma_merges += u64::from(result.merges_performed);
        self.stats.tlb_flushes += u64::from(result.tlb_flushes);

        Ok(result)
    }

    /// Split a protection range at the given address boundary.
    ///
    /// If a range spans across `boundary`, it is split into two
    /// ranges: `[start, boundary)` and `[boundary, end)`.
    fn split_ranges_at(&mut self, boundary: u64, pid: u64) -> Result<()> {
        // Find a range that contains the boundary as an interior point.
        let idx = self.ranges.iter().position(|r| {
            r.active && r.owner_pid == pid && boundary > r.start && boundary < r.end()
        });

        let idx = match idx {
            Some(i) => i,
            None => return Ok(()), // No split needed.
        };

        // Find a free slot for the second half.
        let free_idx = self
            .ranges
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let original = self.ranges[idx];
        let first_size = boundary - original.start;
        let second_size = original.end() - boundary;

        // Shrink the first range.
        self.ranges[idx].size = first_size;

        // Create the second range.
        self.ranges[free_idx] = ProtRange {
            start: boundary,
            size: second_size,
            prot: original.prot,
            original_prot: original.original_prot,
            file_backed: original.file_backed,
            shared: original.shared,
            owner_pid: original.owner_pid,
            active: true,
        };
        self.range_count += 1;
        self.stats.vma_splits += 1;

        Ok(())
    }

    /// Merge adjacent ranges with identical protection for a process.
    ///
    /// Returns the number of merges performed.
    fn merge_adjacent_ranges(&mut self, pid: u64) -> u32 {
        let mut merges = 0u32;
        let mut changed = true;

        while changed {
            changed = false;
            // Find two active ranges for this pid where one ends
            // where the other starts and both have the same prot.
            let mut merge_pair: Option<(usize, usize)> = None;

            for i in 0..MAX_PROT_RANGES {
                if !self.ranges[i].active || self.ranges[i].owner_pid != pid {
                    continue;
                }
                for j in (i + 1)..MAX_PROT_RANGES {
                    if !self.ranges[j].active || self.ranges[j].owner_pid != pid {
                        continue;
                    }
                    if self.ranges[i].end() == self.ranges[j].start
                        && self.ranges[i].prot.as_raw() == self.ranges[j].prot.as_raw()
                        && self.ranges[i].file_backed == self.ranges[j].file_backed
                        && self.ranges[i].shared == self.ranges[j].shared
                    {
                        merge_pair = Some((i, j));
                        break;
                    }
                    if self.ranges[j].end() == self.ranges[i].start
                        && self.ranges[i].prot.as_raw() == self.ranges[j].prot.as_raw()
                        && self.ranges[i].file_backed == self.ranges[j].file_backed
                        && self.ranges[i].shared == self.ranges[j].shared
                    {
                        merge_pair = Some((j, i));
                        break;
                    }
                }
                if merge_pair.is_some() {
                    break;
                }
            }

            if let Some((first, second)) = merge_pair {
                self.ranges[first].size += self.ranges[second].size;
                self.ranges[second].active = false;
                self.range_count = self.range_count.saturating_sub(1);
                merges += 1;
                changed = true;
            }
        }

        merges
    }

    /// Queue a TLB flush for a range of pages.
    fn queue_tlb_flush(&mut self, start: u64, size: u64) {
        let pages = size / PAGE_SIZE;
        let mut addr = start;
        for _ in 0..pages {
            if self.tlb_batch_count < MAX_TLB_FLUSH_ENTRIES {
                self.tlb_batch[self.tlb_batch_count] = TlbFlushEntry { addr, active: true };
                self.tlb_batch_count += 1;
            }
            addr = addr.saturating_add(PAGE_SIZE);
        }
    }

    /// Flush all batched TLB entries.
    ///
    /// Returns the number of entries flushed.
    fn flush_tlb_batch(&mut self) -> u32 {
        let flushed = self.tlb_batch_count as u32;
        // Stub: a real implementation would issue `invlpg`
        // instructions (x86_64) or equivalent for each entry,
        // potentially using a full TLB shootdown for large ranges.
        for entry in &mut self.tlb_batch[..self.tlb_batch_count] {
            entry.active = false;
        }
        self.tlb_batch_count = 0;
        flushed
    }

    // ── Query operations ────────────────────────────────────────

    /// Look up the protection flags for a given address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range covers the address.
    pub fn query_prot(&self, pid: u64, addr: u64) -> Result<ProtFlags> {
        self.ranges
            .iter()
            .find(|r| r.active && r.owner_pid == pid && r.contains(addr))
            .map(|r| r.prot)
            .ok_or(Error::NotFound)
    }

    /// Check whether a given address range has the required
    /// permissions.
    ///
    /// Returns `true` if every page in `[addr, addr+len)` has at
    /// least the permissions specified by `required`.
    pub fn check_access(&self, pid: u64, addr: u64, len: u64, required: ProtFlags) -> bool {
        if len == 0 {
            return false;
        }
        let end = addr.saturating_add(len);
        let mut cursor = addr;

        while cursor < end {
            let range = self
                .ranges
                .iter()
                .find(|r| r.active && r.owner_pid == pid && r.contains(cursor));

            match range {
                Some(r) => {
                    // Check that the range has required permissions.
                    let has_read = !required.is_readable() || r.prot.is_readable();
                    let has_write = !required.is_writable() || r.prot.is_writable();
                    let has_exec = !required.is_executable() || r.prot.is_executable();
                    if !has_read || !has_write || !has_exec {
                        return false;
                    }
                    // Advance cursor to the end of this range.
                    cursor = r.end();
                }
                None => return false,
            }
        }

        true
    }

    /// Return the PTE flags corresponding to the protection at a
    /// given address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range covers the address.
    pub fn pte_flags_for(&self, pid: u64, addr: u64) -> Result<u64> {
        let prot = self.query_prot(pid, addr)?;
        Ok(prot.to_pte_flags())
    }

    // ── Accessors ───────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &MprotectStats {
        &self.stats
    }

    /// Number of active protection ranges.
    pub fn range_count(&self) -> usize {
        self.range_count
    }

    /// Number of pending mprotect operations.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Iterate over active ranges for a process.
    pub fn ranges_for(&self, pid: u64) -> impl Iterator<Item = &ProtRange> {
        self.ranges
            .iter()
            .filter(move |r| r.active && r.owner_pid == pid)
    }

    /// Count total pages with a specific protection for a process.
    pub fn count_pages_with_prot(&self, pid: u64, prot: ProtFlags) -> u64 {
        self.ranges
            .iter()
            .filter(|r| r.active && r.owner_pid == pid && r.prot.as_raw() == prot.as_raw())
            .map(|r| r.page_count())
            .sum()
    }

    /// Unregister all ranges for a process.
    pub fn unregister_all(&mut self, pid: u64) {
        for range in self.ranges.iter_mut() {
            if range.active && range.owner_pid == pid {
                range.active = false;
                self.range_count = self.range_count.saturating_sub(1);
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Align a value up to the next page boundary.
const fn page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & PAGE_MASK
}
