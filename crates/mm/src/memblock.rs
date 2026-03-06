// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Early boot memory allocator (memblock).
//!
//! Provides a simple, firmware-table-driven memory allocator used during
//! early boot before the buddy/bitmap allocator is available. The kernel
//! uses memblock to carve out initial allocations (page tables, kernel
//! heap seed, per-CPU areas) from regions reported by the firmware
//! (E820, UEFI memory map, device-tree).
//!
//! Memblock tracks two region arrays:
//! - **memory** — regions of usable physical RAM
//! - **reserved** — regions that are already claimed (kernel image,
//!   initrd, ACPI tables, early allocations)
//!
//! An allocation request scans the memory regions for a gap that does
//! not overlap any reserved region, then marks the result as reserved.
//! Once the buddy allocator is initialised, all remaining free memblock
//! space is released to it.
//!
//! Modeled after Linux `mm/memblock.c`.
//!
//! Reference: `.kernelORG/` — `mm/memblock.c`, `include/linux/memblock.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of memory regions tracked.
const MAX_MEMORY_REGIONS: usize = 128;

/// Maximum number of reserved regions tracked.
const MAX_RESERVED_REGIONS: usize = 128;

/// Page size constant (4 KiB).
const PAGE_SIZE: u64 = 4096;

// ── MemoryTypeFlags ───────────────────────────────────────────────

/// Flags describing the type and properties of a memory region.
///
/// Multiple flags can be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryTypeFlags(u32);

impl MemoryTypeFlags {
    /// Usable RAM — available for general kernel allocation.
    pub const USABLE: Self = Self(1 << 0);

    /// Reserved by firmware — must not be touched.
    pub const RESERVED: Self = Self(1 << 1);

    /// ACPI reclaimable — can be freed after ACPI tables are parsed.
    pub const ACPI_RECLAIMABLE: Self = Self(1 << 2);

    /// ACPI NVS — must be preserved across sleep states.
    pub const ACPI_NVS: Self = Self(1 << 3);

    /// Bad / unusable memory reported by firmware.
    pub const BAD: Self = Self(1 << 4);

    /// Persistent memory (NVDIMM).
    pub const PERSISTENT: Self = Self(1 << 5);

    /// Memory that was hot-added at runtime.
    pub const HOTPLUGGED: Self = Self(1 << 6);

    /// Memory has been mirrored for reliability.
    pub const MIRRORED: Self = Self(1 << 7);

    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Create flags from a raw `u32` value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw `u32` representation.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether `other` flags are all present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ── MemblockRegion ────────────────────────────────────────────────

/// A contiguous physical memory region tracked by memblock.
///
/// Each region has a base address, size, NUMA node id, and type flags.
/// Regions within the same array (memory or reserved) are kept sorted
/// by base address and are merged when adjacent/overlapping regions
/// share the same flags and node.
#[derive(Debug, Clone, Copy)]
pub struct MemblockRegion {
    /// Base physical address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// NUMA node this region belongs to.
    pub node_id: u32,
    /// Type/property flags.
    pub flags: MemoryTypeFlags,
}

impl MemblockRegion {
    /// Create an empty (invalid) region.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            node_id: 0,
            flags: MemoryTypeFlags::NONE,
        }
    }

    /// Whether this slot is unused.
    const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// End address (exclusive) of the region.
    const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Check whether this region overlaps with `[base, base+size)`.
    const fn overlaps(&self, base: u64, size: u64) -> bool {
        self.base < base + size && base < self.end()
    }
}

// ── MemblockRegionArray ───────────────────────────────────────────

/// A sorted array of non-overlapping [`MemblockRegion`]s.
///
/// Maintains regions sorted by ascending base address. Insertion
/// automatically merges adjacent/overlapping regions when flags and
/// node match.
struct RegionArray {
    /// Fixed-capacity storage.
    regions: [MemblockRegion; MAX_MEMORY_REGIONS],
    /// Number of active entries (always <= `MAX_MEMORY_REGIONS`).
    count: usize,
}

impl RegionArray {
    /// Create an empty region array.
    const fn new() -> Self {
        Self {
            regions: [MemblockRegion::empty(); MAX_MEMORY_REGIONS],
            count: 0,
        }
    }

    /// Number of active regions.
    const fn len(&self) -> usize {
        self.count
    }

    /// Insert a region, maintaining sort order and merging where possible.
    ///
    /// Returns `Err(OutOfMemory)` if the array is full and the region
    /// cannot be merged with an existing entry.
    fn add(&mut self, base: u64, size: u64, node_id: u32, flags: MemoryTypeFlags) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        // Try to merge with an existing adjacent/overlapping region.
        for i in 0..self.count {
            let r = &self.regions[i];
            if r.node_id != node_id || r.flags.bits() != flags.bits() {
                continue;
            }
            // Check adjacency or overlap.
            let new_end = base.saturating_add(size);
            if r.end() >= base && r.base <= new_end {
                let merged_base = r.base.min(base);
                let merged_end = r.end().max(new_end);
                self.regions[i].base = merged_base;
                self.regions[i].size = merged_end - merged_base;
                self.coalesce();
                return Ok(());
            }
        }

        // No merge — insert in sorted position.
        if self.count >= MAX_MEMORY_REGIONS {
            return Err(Error::OutOfMemory);
        }

        // Find insertion point.
        let mut pos = self.count;
        for i in 0..self.count {
            if base < self.regions[i].base {
                pos = i;
                break;
            }
        }

        // Shift elements right.
        let mut j = self.count;
        while j > pos {
            self.regions[j] = self.regions[j - 1];
            j -= 1;
        }
        self.regions[pos] = MemblockRegion {
            base,
            size,
            node_id,
            flags,
        };
        self.count += 1;
        Ok(())
    }

    /// Remove a sub-range `[base, base+size)` from the array.
    ///
    /// Regions that partially overlap the removed range are trimmed.
    /// Regions fully contained are deleted. A region that straddles
    /// the range is split in two (if capacity permits).
    fn remove(&mut self, base: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = base.saturating_add(size);
        let mut i = 0;
        while i < self.count {
            let r_base = self.regions[i].base;
            let r_end = self.regions[i].end();

            if r_end <= base || r_base >= end {
                // No overlap.
                i += 1;
                continue;
            }

            if r_base >= base && r_end <= end {
                // Fully contained — delete.
                self.delete_index(i);
                continue; // don't increment i
            }

            if r_base < base && r_end > end {
                // Straddles — split into two.
                let right_base = end;
                let right_size = r_end - end;
                let node_id = self.regions[i].node_id;
                let flags = self.regions[i].flags;

                // Trim the left portion.
                self.regions[i].size = base - r_base;

                // Insert the right portion after.
                let _ = self.insert_at(
                    i + 1,
                    MemblockRegion {
                        base: right_base,
                        size: right_size,
                        node_id,
                        flags,
                    },
                );
                i += 2;
                continue;
            }

            if r_base < base {
                // Overlaps on the right — trim.
                self.regions[i].size = base - r_base;
            } else {
                // Overlaps on the left — trim.
                let trim = end - r_base;
                self.regions[i].base = end;
                self.regions[i].size = self.regions[i].size.saturating_sub(trim);
                if self.regions[i].size == 0 {
                    self.delete_index(i);
                    continue;
                }
            }
            i += 1;
        }
        Ok(())
    }

    /// Delete the region at index `i`, shifting subsequent entries left.
    fn delete_index(&mut self, i: usize) {
        if i >= self.count {
            return;
        }
        let mut j = i;
        while j + 1 < self.count {
            self.regions[j] = self.regions[j + 1];
            j += 1;
        }
        self.regions[self.count - 1] = MemblockRegion::empty();
        self.count -= 1;
    }

    /// Insert a region at a specific index, shifting others right.
    fn insert_at(&mut self, pos: usize, region: MemblockRegion) -> Result<()> {
        if self.count >= MAX_MEMORY_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let mut j = self.count;
        while j > pos {
            self.regions[j] = self.regions[j - 1];
            j -= 1;
        }
        self.regions[pos] = region;
        self.count += 1;
        Ok(())
    }

    /// Merge adjacent regions that share the same flags and node.
    fn coalesce(&mut self) {
        let mut i = 0;
        while i + 1 < self.count {
            let cur_end = self.regions[i].end();
            let next_base = self.regions[i + 1].base;
            let same_flags = self.regions[i].flags.bits() == self.regions[i + 1].flags.bits();
            let same_node = self.regions[i].node_id == self.regions[i + 1].node_id;

            if cur_end >= next_base && same_flags && same_node {
                let merged_end = cur_end.max(self.regions[i + 1].end());
                self.regions[i].size = merged_end - self.regions[i].base;
                self.delete_index(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// Total bytes covered by all regions.
    fn total_size(&self) -> u64 {
        let mut total: u64 = 0;
        for i in 0..self.count {
            total = total.saturating_add(self.regions[i].size);
        }
        total
    }

    /// Check whether any region contains `[base, base+size)`.
    fn contains_range(&self, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        for i in 0..self.count {
            if self.regions[i].base <= base && self.regions[i].end() >= end {
                return true;
            }
        }
        false
    }
}

// ── Memblock ──────────────────────────────────────────────────────

/// Early boot memory allocator.
///
/// Tracks usable RAM (memory regions) and claimed ranges (reserved
/// regions). Allocation works by scanning memory regions for a gap
/// not covered by any reserved region, then marking the result as
/// reserved.
///
/// Once the buddy allocator is ready, call [`transfer_free_regions`]
/// to hand over all remaining free space.
pub struct Memblock {
    /// Usable physical memory regions (from firmware tables).
    memory: RegionArray,
    /// Reserved (claimed) regions — kernel, initrd, allocations.
    reserved: RegionArray,
    /// Total bytes allocated via [`alloc`](Self::alloc).
    allocated_bytes: u64,
    /// Whether allocation is still allowed (false after transition).
    allocations_enabled: bool,
    /// Bottom-up vs top-down allocation direction.
    bottom_up: bool,
}

impl Default for Memblock {
    fn default() -> Self {
        Self::new()
    }
}

impl Memblock {
    /// Create a new, empty memblock allocator.
    ///
    /// Allocation starts in bottom-up mode.
    pub const fn new() -> Self {
        Self {
            memory: RegionArray::new(),
            reserved: RegionArray::new(),
            allocated_bytes: 0,
            allocations_enabled: true,
            bottom_up: true,
        }
    }

    // ── Region management ──────────────────────────────────────

    /// Register a usable memory region.
    ///
    /// Typically called once per entry in the firmware memory map
    /// (E820, UEFI, device-tree).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    /// Returns [`Error::OutOfMemory`] if the region table is full.
    pub fn add_memory(
        &mut self,
        base: u64,
        size: u64,
        node_id: u32,
        flags: MemoryTypeFlags,
    ) -> Result<()> {
        self.memory.add(base, size, node_id, flags)
    }

    /// Register a reserved memory region.
    ///
    /// Reserved regions are excluded from allocation. Used for the
    /// kernel image, initrd, ACPI tables, and firmware-reserved areas.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    /// Returns [`Error::OutOfMemory`] if the region table is full.
    pub fn reserve(&mut self, base: u64, size: u64) -> Result<()> {
        self.reserved.add(base, size, 0, MemoryTypeFlags::RESERVED)
    }

    /// Remove a memory region from the usable set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn remove_memory(&mut self, base: u64, size: u64) -> Result<()> {
        self.memory.remove(base, size)
    }

    /// Release (un-reserve) a previously reserved region.
    ///
    /// The freed range becomes available for future allocations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn free_reserve(&mut self, base: u64, size: u64) -> Result<()> {
        self.reserved.remove(base, size)
    }

    // ── Allocation ─────────────────────────────────────────────

    /// Allocate `size` bytes with the given alignment from memblock.
    ///
    /// Scans memory regions for a free gap (not overlapping any
    /// reserved region). Alignment must be a power of two. The
    /// allocated range is automatically marked as reserved.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero or
    /// `align` is not a power of two.
    /// Returns [`Error::OutOfMemory`] if no suitable gap exists.
    /// Returns [`Error::PermissionDenied`] if allocations have been
    /// disabled (after buddy transition).
    pub fn alloc(&mut self, size: u64, align: u64) -> Result<u64> {
        if !self.allocations_enabled {
            return Err(Error::PermissionDenied);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if align == 0 || !align.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }

        let addr = if self.bottom_up {
            self.find_bottom_up(size, align)?
        } else {
            self.find_top_down(size, align)?
        };

        self.reserved
            .add(addr, size, 0, MemoryTypeFlags::RESERVED)?;
        self.allocated_bytes = self.allocated_bytes.saturating_add(size);
        Ok(addr)
    }

    /// Allocate `size` bytes aligned to [`PAGE_SIZE`].
    ///
    /// Convenience wrapper around [`alloc`](Self::alloc).
    pub fn alloc_pages(&mut self, size: u64) -> Result<u64> {
        let aligned_size = align_up(size, PAGE_SIZE);
        self.alloc(aligned_size, PAGE_SIZE)
    }

    /// Free a previously allocated region back to memblock.
    ///
    /// Removes the range from the reserved set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the range is not currently
    /// reserved.
    pub fn free(&mut self, base: u64, size: u64) -> Result<()> {
        if !self.reserved.contains_range(base, size) {
            return Err(Error::NotFound);
        }
        self.reserved.remove(base, size)?;
        self.allocated_bytes = self.allocated_bytes.saturating_sub(size);
        Ok(())
    }

    /// Bottom-up first-fit scan.
    fn find_bottom_up(&self, size: u64, align: u64) -> Result<u64> {
        for i in 0..self.memory.count {
            let region = &self.memory.regions[i];
            let mut candidate = align_up(region.base, align);
            let region_end = region.end();

            while candidate.saturating_add(size) <= region_end {
                if !self.overlaps_reserved(candidate, size) {
                    return Ok(candidate);
                }
                // Skip past the conflicting reserved region.
                candidate = self.next_free_after(candidate, align);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Top-down first-fit scan.
    fn find_top_down(&self, size: u64, align: u64) -> Result<u64> {
        let mut i = self.memory.count;
        while i > 0 {
            i -= 1;
            let region = &self.memory.regions[i];
            let region_end = region.end();
            if region.size < size {
                continue;
            }

            // Start from the highest aligned address that fits.
            let raw_start = region_end.saturating_sub(size);
            let candidate = align_down(raw_start, align);
            if candidate >= region.base && !self.overlaps_reserved(candidate, size) {
                return Ok(candidate);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Check whether `[base, base+size)` overlaps any reserved region.
    fn overlaps_reserved(&self, base: u64, size: u64) -> bool {
        for i in 0..self.reserved.count {
            if self.reserved.regions[i].overlaps(base, size) {
                return true;
            }
        }
        false
    }

    /// Find the next aligned candidate after any overlapping reserved
    /// region.
    fn next_free_after(&self, candidate: u64, align: u64) -> u64 {
        let mut next = candidate.saturating_add(align);
        for i in 0..self.reserved.count {
            let r = &self.reserved.regions[i];
            if r.base <= candidate && r.end() > candidate {
                let past = align_up(r.end(), align);
                if past > next {
                    next = past;
                }
            }
        }
        next
    }

    // ── Allocation direction ───────────────────────────────────

    /// Enable bottom-up allocation mode (default).
    pub fn set_bottom_up(&mut self) {
        self.bottom_up = true;
    }

    /// Enable top-down allocation mode.
    ///
    /// Useful for reserving high memory for device mappings while
    /// keeping low memory free for DMA.
    pub fn set_top_down(&mut self) {
        self.bottom_up = false;
    }

    /// Whether bottom-up mode is active.
    pub fn is_bottom_up(&self) -> bool {
        self.bottom_up
    }

    // ── Buddy allocator transition ─────────────────────────────

    /// Disable further memblock allocations.
    ///
    /// Called when the buddy allocator has been initialised and
    /// memblock should no longer be used for new allocations.
    pub fn disable_allocations(&mut self) {
        self.allocations_enabled = false;
    }

    /// Iterate over free regions (memory minus reserved) and invoke
    /// `callback` for each contiguous free range.
    ///
    /// This is the primary entry point for transferring remaining free
    /// memblock space to the buddy/bitmap allocator.
    ///
    /// Returns the number of free regions yielded.
    pub fn transfer_free_regions<F>(&self, mut callback: F) -> usize
    where
        F: FnMut(u64, u64, u32),
    {
        let mut yielded = 0;

        for i in 0..self.memory.count {
            let region = &self.memory.regions[i];
            let mut pos = region.base;
            let region_end = region.end();

            while pos < region_end {
                // Find the end of any overlapping reserved region.
                let (is_reserved, skip_end) = self.reserved_overlap_at(pos, region_end);
                if is_reserved {
                    pos = skip_end;
                    continue;
                }

                // Determine extent of free space.
                let free_end = self.next_reserved_start(pos, region_end);
                let free_size = free_end - pos;
                if free_size > 0 {
                    callback(pos, free_size, region.node_id);
                    yielded += 1;
                }
                pos = free_end;
            }
        }

        yielded
    }

    /// Check if `pos` falls inside a reserved region; return the end
    /// of that reserved region if so.
    fn reserved_overlap_at(&self, pos: u64, limit: u64) -> (bool, u64) {
        for i in 0..self.reserved.count {
            let r = &self.reserved.regions[i];
            if r.base <= pos && r.end() > pos {
                return (true, r.end().min(limit));
            }
        }
        (false, pos)
    }

    /// Find the start of the next reserved region after `pos`.
    fn next_reserved_start(&self, pos: u64, limit: u64) -> u64 {
        let mut nearest = limit;
        for i in 0..self.reserved.count {
            let r = &self.reserved.regions[i];
            if r.base > pos && r.base < nearest {
                nearest = r.base;
            }
        }
        nearest
    }

    // ── Query / debug ──────────────────────────────────────────

    /// Total usable physical memory (sum of all memory regions).
    pub fn total_memory(&self) -> u64 {
        self.memory.total_size()
    }

    /// Total reserved bytes (sum of all reserved regions).
    pub fn total_reserved(&self) -> u64 {
        self.reserved.total_size()
    }

    /// Total free bytes (memory minus reserved, approximate).
    pub fn total_free(&self) -> u64 {
        self.total_memory().saturating_sub(self.total_reserved())
    }

    /// Total bytes allocated via [`alloc`](Self::alloc).
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    /// Number of memory regions.
    pub fn memory_region_count(&self) -> usize {
        self.memory.len()
    }

    /// Number of reserved regions.
    pub fn reserved_region_count(&self) -> usize {
        self.reserved.len()
    }

    /// Access a memory region by index.
    ///
    /// Returns `None` if `index` is out of bounds.
    pub fn memory_region(&self, index: usize) -> Option<&MemblockRegion> {
        if index < self.memory.count {
            Some(&self.memory.regions[index])
        } else {
            None
        }
    }

    /// Access a reserved region by index.
    ///
    /// Returns `None` if `index` is out of bounds.
    pub fn reserved_region(&self, index: usize) -> Option<&MemblockRegion> {
        if index < self.reserved.count {
            Some(&self.reserved.regions[index])
        } else {
            None
        }
    }

    /// Produce a debug summary of all memory and reserved regions.
    ///
    /// Writes formatted output into the provided buffer. Returns the
    /// number of bytes written, or `Err(OutOfMemory)` if the buffer
    /// is too small.
    pub fn dump(&self, buf: &mut [u8]) -> Result<usize> {
        let mut writer = BufWriter::new(buf);

        writer.write_str("=== Memblock Memory Regions ===")?;
        writer.write_newline()?;
        for i in 0..self.memory.count {
            let r = &self.memory.regions[i];
            writer.write_str("  [")?;
            writer.write_hex(r.base)?;
            writer.write_str(" - ")?;
            writer.write_hex(r.end())?;
            writer.write_str(") size=")?;
            writer.write_hex(r.size)?;
            writer.write_str(" node=")?;
            writer.write_u32(r.node_id)?;
            writer.write_str(" flags=")?;
            writer.write_hex(r.flags.bits() as u64)?;
            writer.write_newline()?;
        }

        writer.write_str("=== Memblock Reserved Regions ===")?;
        writer.write_newline()?;
        for i in 0..self.reserved.count {
            let r = &self.reserved.regions[i];
            writer.write_str("  [")?;
            writer.write_hex(r.base)?;
            writer.write_str(" - ")?;
            writer.write_hex(r.end())?;
            writer.write_str(") size=")?;
            writer.write_hex(r.size)?;
            writer.write_newline()?;
        }

        writer.write_str("Total memory: ")?;
        writer.write_hex(self.total_memory())?;
        writer.write_str("  Reserved: ")?;
        writer.write_hex(self.total_reserved())?;
        writer.write_str("  Free: ")?;
        writer.write_hex(self.total_free())?;
        writer.write_newline()?;

        Ok(writer.pos)
    }

    /// Check whether `[base, base+size)` is fully within usable
    /// memory and not reserved.
    pub fn is_free(&self, base: u64, size: u64) -> bool {
        self.memory.contains_range(base, size) && !self.overlaps_reserved(base, size)
    }

    /// Whether allocations are still enabled.
    pub fn allocations_enabled(&self) -> bool {
        self.allocations_enabled
    }
}

// ── BufWriter ─────────────────────────────────────────────────────

/// Minimal no-alloc buffer writer for the [`Memblock::dump`] method.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn write_byte(&mut self, b: u8) -> Result<()> {
        if self.pos >= self.buf.len() {
            return Err(Error::OutOfMemory);
        }
        self.buf[self.pos] = b;
        self.pos += 1;
        Ok(())
    }

    fn write_str(&mut self, s: &str) -> Result<()> {
        for b in s.bytes() {
            self.write_byte(b)?;
        }
        Ok(())
    }

    fn write_newline(&mut self) -> Result<()> {
        self.write_byte(b'\n')
    }

    fn write_hex(&mut self, val: u64) -> Result<()> {
        self.write_str("0x")?;
        if val == 0 {
            return self.write_byte(b'0');
        }

        // Find the highest non-zero nibble.
        let mut started = false;
        let mut shift: i32 = 60;
        while shift >= 0 {
            let nibble = ((val >> shift) & 0xf) as u8;
            if nibble != 0 || started {
                started = true;
                let ch = if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                };
                self.write_byte(ch)?;
            }
            shift -= 4;
        }
        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        if val == 0 {
            return self.write_byte(b'0');
        }
        // Max u32 is 10 digits.
        let mut digits = [0u8; 10];
        let mut n = val;
        let mut len = 0;
        while n > 0 {
            digits[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        // Write in reverse.
        let mut i = len;
        while i > 0 {
            i -= 1;
            self.write_byte(digits[i])?;
        }
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Round `val` up to the nearest multiple of `align`.
///
/// `align` must be a power of two.
const fn align_up(val: u64, align: u64) -> u64 {
    let mask = align - 1;
    (val + mask) & !mask
}

/// Round `val` down to the nearest multiple of `align`.
///
/// `align` must be a power of two.
const fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}
