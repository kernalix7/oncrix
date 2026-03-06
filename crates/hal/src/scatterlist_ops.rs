// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scatter-gather list operations.
//!
//! Provides full scatter-gather (SG) list lifecycle management: allocation of
//! SG tables from page arrays, DMA mapping of individual entries, chained SG
//! support, iteration, and cleanup. Modelled after Linux `lib/scatterlist.c`.
//!
//! # Architecture
//!
//! - [`SgEntry`] — a single contiguous memory segment (`#[repr(C)]` for DMA compat).
//! - [`SgTable`] — an allocated table holding up to [`MAX_SG_TABLE_ENTRIES`] entries.
//! - [`SgTablePool`] — a fixed-size pool of [`SgTable`]s for reuse.
//! - [`SgIter`] — a forward iterator over entries in a table.
//!
//! # DMA Mapping
//!
//! Entries carry both a physical address (for the DMA engine) and an optional
//! DMA address that may differ when IOMMU translation is active. The `map` and
//! `unmap` helpers update the DMA address field.
//!
//! Reference: Linux `include/linux/scatterlist.h`, `lib/scatterlist.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in a single SG table.
pub const MAX_SG_TABLE_ENTRIES: usize = 128;

/// Maximum number of SG tables in the pool.
pub const MAX_SG_TABLES: usize = 16;

/// SG entry flag: this is the last entry in the table.
pub const SG_FLAG_END: u32 = 1 << 0;

/// SG entry flag: entry has been DMA-mapped.
pub const SG_FLAG_MAPPED: u32 = 1 << 1;

/// SG entry flag: entry belongs to a chained (overflow) segment.
pub const SG_FLAG_CHAIN: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// DmaDirection
// ---------------------------------------------------------------------------

/// Direction of a DMA transfer for cache synchronization purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaDirection {
    /// From device to memory (device reads from this region).
    #[default]
    FromDevice,
    /// From memory to device (device writes to this region).
    ToDevice,
    /// Bidirectional — both read and write.
    Bidirectional,
}

// ---------------------------------------------------------------------------
// SgEntry
// ---------------------------------------------------------------------------

/// A single scatter-gather entry describing one contiguous memory region.
///
/// Marked `#[repr(C)]` for compatibility with DMA descriptor rings that
/// read these fields directly from memory.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SgEntry {
    /// Physical address of the region (CPU view).
    pub phys_addr: u64,
    /// DMA address (IOMMU-translated; equals `phys_addr` when no IOMMU).
    pub dma_addr: u64,
    /// Length of the region in bytes.
    pub length: u32,
    /// Page offset within the first page.
    pub page_offset: u16,
    /// SG flags: `SG_FLAG_*` constants.
    pub flags: u32,
}

impl SgEntry {
    /// Creates a new unmapped entry for a physical region.
    pub const fn new(phys_addr: u64, length: u32) -> Self {
        Self {
            phys_addr,
            dma_addr: 0,
            length,
            page_offset: 0,
            flags: 0,
        }
    }

    /// Creates an entry with an explicit page offset (for sub-page mappings).
    pub const fn with_offset(phys_addr: u64, length: u32, page_offset: u16) -> Self {
        Self {
            phys_addr,
            dma_addr: 0,
            length,
            page_offset,
            flags: 0,
        }
    }

    /// Returns `true` if this is the last entry in the table.
    pub fn is_end(&self) -> bool {
        self.flags & SG_FLAG_END != 0
    }

    /// Returns `true` if this entry is DMA-mapped.
    pub fn is_mapped(&self) -> bool {
        self.flags & SG_FLAG_MAPPED != 0
    }

    /// Returns `true` if this entry is a chain link to an overflow table.
    pub fn is_chain(&self) -> bool {
        self.flags & SG_FLAG_CHAIN != 0
    }

    /// Marks this as the end-of-table entry.
    pub fn mark_end(&mut self) {
        self.flags |= SG_FLAG_END;
    }

    /// Records the DMA address after IOMMU mapping and sets the MAPPED flag.
    pub fn set_dma_addr(&mut self, dma_addr: u64) {
        self.dma_addr = dma_addr;
        self.flags |= SG_FLAG_MAPPED;
    }

    /// Clears the DMA mapping.
    pub fn clear_dma(&mut self) {
        self.dma_addr = 0;
        self.flags &= !SG_FLAG_MAPPED;
    }
}

// ---------------------------------------------------------------------------
// SgTable
// ---------------------------------------------------------------------------

/// A scatter-gather table — an allocated list of [`SgEntry`]s.
///
/// The table is backed by a fixed-size inline array, avoiding heap allocation.
pub struct SgTable {
    /// Entries in this table.
    entries: [SgEntry; MAX_SG_TABLE_ENTRIES],
    /// Number of valid entries.
    count: usize,
    /// DMA transfer direction.
    pub direction: DmaDirection,
    /// Total byte count across all entries.
    total_len: u64,
    /// Whether this table slot is allocated.
    pub allocated: bool,
}

impl SgTable {
    /// Creates an empty, unallocated table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SgEntry::new(0, 0) }; MAX_SG_TABLE_ENTRIES],
            count: 0,
            direction: DmaDirection::Bidirectional,
            total_len: 0,
            allocated: false,
        }
    }

    /// Initializes the table for use with the given direction.
    pub fn init(&mut self, direction: DmaDirection) {
        self.count = 0;
        self.total_len = 0;
        self.direction = direction;
        self.allocated = true;
    }

    /// Returns the number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the total mapped byte length.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Returns `true` if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Appends an entry from a physical address and length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full, or
    /// [`Error::InvalidArgument`] if `length` is zero.
    pub fn append(&mut self, phys_addr: u64, length: u32) -> Result<()> {
        if self.count >= MAX_SG_TABLE_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.count] = SgEntry::new(phys_addr, length);
        self.total_len += u64::from(length);
        self.count += 1;
        Ok(())
    }

    /// Appends an entry with a page offset.
    pub fn append_with_offset(
        &mut self,
        phys_addr: u64,
        length: u32,
        page_offset: u16,
    ) -> Result<()> {
        if self.count >= MAX_SG_TABLE_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.count] = SgEntry::with_offset(phys_addr, length, page_offset);
        self.total_len += u64::from(length);
        self.count += 1;
        Ok(())
    }

    /// Marks the last entry with the end-of-table flag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the table is empty.
    pub fn finalize(&mut self) -> Result<()> {
        if self.count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.count - 1].mark_end();
        Ok(())
    }

    /// Maps all entries for DMA by assigning DMA addresses.
    ///
    /// In a system without IOMMU, `dma_addr == phys_addr`. With an IOMMU the
    /// caller should translate each physical address before calling this method,
    /// or use [`map_entry`](Self::map_entry) per-entry.
    pub fn map_all_identity(&mut self) {
        for i in 0..self.count {
            let phys = self.entries[i].phys_addr;
            self.entries[i].set_dma_addr(phys);
        }
    }

    /// Sets the DMA address for a specific entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn map_entry(&mut self, index: usize, dma_addr: u64) -> Result<()> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.entries[index].set_dma_addr(dma_addr);
        Ok(())
    }

    /// Unmaps all DMA mappings.
    pub fn unmap_all(&mut self) {
        for i in 0..self.count {
            self.entries[i].clear_dma();
        }
    }

    /// Returns a slice over the valid entries.
    pub fn entries(&self) -> &[SgEntry] {
        &self.entries[..self.count]
    }

    /// Returns a mutable slice over the valid entries.
    pub fn entries_mut(&mut self) -> &mut [SgEntry] {
        &mut self.entries[..self.count]
    }

    /// Returns the entry at `index`, or [`Error::InvalidArgument`].
    pub fn get(&self, index: usize) -> Result<&SgEntry> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[index])
    }

    /// Returns an iterator over entries in the table.
    pub fn iter(&self) -> SgIter<'_> {
        SgIter {
            table: self,
            pos: 0,
        }
    }

    /// Resets the table back to empty, freeing all entries.
    pub fn free(&mut self) {
        self.count = 0;
        self.total_len = 0;
        self.allocated = false;
    }
}

impl Default for SgTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SgIter
// ---------------------------------------------------------------------------

/// Forward iterator over entries in an [`SgTable`].
pub struct SgIter<'a> {
    table: &'a SgTable,
    pos: usize,
}

impl<'a> Iterator for SgIter<'a> {
    type Item = &'a SgEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.table.count {
            return None;
        }
        let entry = &self.table.entries[self.pos];
        self.pos += 1;
        Some(entry)
    }
}

// ---------------------------------------------------------------------------
// SgTablePool
// ---------------------------------------------------------------------------

/// A fixed-size pool of reusable [`SgTable`]s.
///
/// Avoids repeated allocation overhead for DMA-capable memory regions. Tables
/// are checked out via [`alloc`](SgTablePool::alloc) and returned via
/// [`free`](SgTablePool::free).
pub struct SgTablePool {
    tables: [SgTable; MAX_SG_TABLES],
}

impl SgTablePool {
    /// Creates a pool with all tables in unallocated state.
    pub fn new() -> Self {
        Self {
            tables: [const { SgTable::new() }; MAX_SG_TABLES],
        }
    }

    /// Allocates an SG table from the pool for the given direction.
    ///
    /// Returns the table index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no tables are free.
    pub fn alloc(&mut self, direction: DmaDirection) -> Result<usize> {
        let idx = self
            .tables
            .iter()
            .position(|t| !t.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.tables[idx].init(direction);
        Ok(idx)
    }

    /// Returns a reference to the table at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if out of range, [`Error::NotFound`]
    /// if not allocated.
    pub fn get(&self, index: usize) -> Result<&SgTable> {
        if index >= MAX_SG_TABLES {
            return Err(Error::InvalidArgument);
        }
        if !self.tables[index].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.tables[index])
    }

    /// Returns a mutable reference to the table at `index`.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut SgTable> {
        if index >= MAX_SG_TABLES {
            return Err(Error::InvalidArgument);
        }
        if !self.tables[index].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.tables[index])
    }

    /// Returns a table to the pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn free(&mut self, index: usize) -> Result<()> {
        if index >= MAX_SG_TABLES {
            return Err(Error::InvalidArgument);
        }
        self.tables[index].free();
        Ok(())
    }

    /// Returns the number of allocated tables.
    pub fn allocated_count(&self) -> usize {
        self.tables.iter().filter(|t| t.allocated).count()
    }
}

impl Default for SgTablePool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Builds an [`SgTable`] from a slice of `(phys_addr, length)` pairs.
///
/// # Errors
///
/// Returns [`Error::OutOfMemory`] if there are more segments than
/// [`MAX_SG_TABLE_ENTRIES`].
pub fn sg_alloc_table(direction: DmaDirection, segments: &[(u64, u32)]) -> Result<SgTable> {
    let mut table = SgTable::new();
    table.init(direction);
    for &(addr, len) in segments {
        table.append(addr, len)?;
    }
    table.finalize()?;
    Ok(table)
}

/// Computes the total byte length of a slice of `(phys_addr, length)` pairs.
pub fn sg_total_len(segments: &[(u64, u32)]) -> u64 {
    segments.iter().map(|&(_, l)| u64::from(l)).sum()
}

/// Validates that every entry in `table` is aligned to `alignment` bytes.
///
/// `alignment` must be a non-zero power of two.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if any entry is misaligned or if
/// `alignment` is not a power of two.
pub fn sg_validate_alignment(table: &SgTable, alignment: u32) -> Result<()> {
    if alignment == 0 || alignment & (alignment - 1) != 0 {
        return Err(Error::InvalidArgument);
    }
    let mask = u64::from(alignment - 1);
    for entry in table.entries() {
        if entry.phys_addr & mask != 0 {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}

/// Returns the DMA address of the first mapped entry, or [`Error::NotFound`]
/// if the table is empty or unmapped.
pub fn sg_dma_address(table: &SgTable) -> Result<u64> {
    let first = table.get(0)?;
    if !first.is_mapped() {
        return Err(Error::IoError);
    }
    Ok(first.dma_addr)
}
