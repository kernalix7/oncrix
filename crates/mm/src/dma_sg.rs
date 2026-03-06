// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA scatter-gather list management.
//!
//! Provides scatter-gather tables for DMA transfers that span
//! multiple non-contiguous physical memory regions. Each
//! [`SgTable`] holds up to [`MAX_SG_ENTRIES`] entries
//! describing the physical segments of a transfer, and an
//! [`SgPool`] pre-allocates tables for fast allocation on
//! hot paths.
//!
//! - [`SgEntry`] — single scatter-gather segment descriptor
//! - [`SgTable`] — collection of segments for one DMA transfer
//! - [`DmaSgDirection`] — transfer direction
//! - [`SgPool`] — pre-allocated pool of [`SgTable`]s
//!
//! Reference: Linux `include/linux/scatterlist.h`,
//! `lib/scatterlist.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries per scatter-gather table.
const MAX_SG_ENTRIES: usize = 64;

/// Maximum tables in the pre-allocated pool.
const MAX_SG_TABLES: usize = 32;

// -------------------------------------------------------------------
// SgEntry
// -------------------------------------------------------------------

/// A single scatter-gather segment descriptor.
///
/// Describes one physically contiguous region that is part of
/// a larger (possibly non-contiguous) DMA transfer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SgEntry {
    /// Physical address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub length: u32,
    /// Byte offset into the first page (for sub-page alignment).
    pub offset: u32,
}

// -------------------------------------------------------------------
// DmaSgDirection
// -------------------------------------------------------------------

/// Direction of a DMA scatter-gather transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaSgDirection {
    /// Data flows from CPU memory to the device.
    ToDevice,
    /// Data flows from the device to CPU memory.
    FromDevice,
    /// Data flows in both directions.
    Bidirectional,
    /// No transfer direction (default / unset).
    #[default]
    None,
}

// -------------------------------------------------------------------
// SgTable
// -------------------------------------------------------------------

/// A scatter-gather table describing a multi-segment DMA transfer.
///
/// Contains up to [`MAX_SG_ENTRIES`] segment descriptors. The
/// `nents` field tracks how many entries are actually in use.
#[derive(Clone)]
pub struct SgTable {
    /// Scatter-gather entries.
    entries: [SgEntry; MAX_SG_ENTRIES],
    /// Number of entries currently in use.
    nents: usize,
    /// Whether this table has been mapped for DMA.
    mapped: bool,
    /// Transfer direction (set on map).
    direction: DmaSgDirection,
    /// Whether this table slot is allocated from a pool.
    active: bool,
}

impl Default for SgTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SgTable {
    /// Creates a new, empty scatter-gather table.
    pub const fn new() -> Self {
        const EMPTY: SgEntry = SgEntry {
            phys_addr: 0,
            length: 0,
            offset: 0,
        };
        Self {
            entries: [EMPTY; MAX_SG_ENTRIES],
            nents: 0,
            mapped: false,
            direction: DmaSgDirection::None,
            active: false,
        }
    }

    /// Returns the number of entries in use.
    pub fn nents(&self) -> usize {
        self.nents
    }

    /// Returns `true` if the table has been DMA-mapped.
    pub fn is_mapped(&self) -> bool {
        self.mapped
    }

    /// Returns the transfer direction.
    pub fn direction(&self) -> DmaSgDirection {
        self.direction
    }

    /// Returns `true` if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.nents == 0
    }

    /// Returns an immutable slice of the active entries.
    pub fn entries(&self) -> &[SgEntry] {
        &self.entries[..self.nents]
    }

    /// Returns the maximum number of entries this table can
    /// hold.
    pub fn capacity(&self) -> usize {
        MAX_SG_ENTRIES
    }

    /// Computes the total byte length across all entries.
    pub fn total_length(&self) -> u64 {
        let mut total: u64 = 0;
        let mut i = 0;
        while i < self.nents {
            total += self.entries[i].length as u64;
            i += 1;
        }
        total
    }
}

// -------------------------------------------------------------------
// Scatter-gather free functions
// -------------------------------------------------------------------

/// Allocate (initialise) a scatter-gather table with `nents`
/// entries.
///
/// All entries are zeroed. The caller should populate them with
/// [`sg_set_buf`] before mapping.
///
/// Returns [`Error::InvalidArgument`] if `nents` is zero or
/// exceeds [`MAX_SG_ENTRIES`].
pub fn sg_alloc_table(table: &mut SgTable, nents: usize) -> Result<()> {
    if nents == 0 || nents > MAX_SG_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    *table = SgTable::new();
    table.nents = nents;
    table.active = true;
    Ok(())
}

/// Free a scatter-gather table, resetting it to the empty state.
///
/// Returns [`Error::Busy`] if the table is still DMA-mapped.
pub fn sg_free_table(table: &mut SgTable) -> Result<()> {
    if table.mapped {
        return Err(Error::Busy);
    }
    *table = SgTable::new();
    Ok(())
}

/// Set a buffer description for scatter-gather entry at `index`.
///
/// Returns [`Error::InvalidArgument`] if the index is out of
/// range or if length is zero.
pub fn sg_set_buf(
    table: &mut SgTable,
    index: usize,
    phys_addr: u64,
    length: u32,
    offset: u32,
) -> Result<()> {
    if index >= table.nents {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Err(Error::InvalidArgument);
    }
    table.entries[index] = SgEntry {
        phys_addr,
        length,
        offset,
    };
    Ok(())
}

/// Map a scatter-gather table for DMA in the given direction.
///
/// In a real implementation this would program the IOMMU and/or
/// perform cache maintenance. Here it validates the table and
/// marks it as mapped.
///
/// Returns [`Error::InvalidArgument`] if the table is empty or
/// already mapped.
pub fn sg_dma_map(table: &mut SgTable, direction: DmaSgDirection) -> Result<()> {
    if table.nents == 0 {
        return Err(Error::InvalidArgument);
    }
    if table.mapped {
        return Err(Error::Busy);
    }

    // Validate that all used entries have non-zero length.
    for entry in table.entries[..table.nents].iter() {
        if entry.length == 0 {
            return Err(Error::InvalidArgument);
        }
    }

    table.mapped = true;
    table.direction = direction;
    Ok(())
}

/// Unmap a previously DMA-mapped scatter-gather table.
///
/// Returns [`Error::InvalidArgument`] if the table is not
/// currently mapped.
pub fn sg_dma_unmap(table: &mut SgTable) -> Result<()> {
    if !table.mapped {
        return Err(Error::InvalidArgument);
    }
    table.mapped = false;
    table.direction = DmaSgDirection::None;
    Ok(())
}

/// Returns the total byte length across all entries in the
/// table.
pub fn sg_total_length(table: &SgTable) -> u64 {
    table.total_length()
}

// -------------------------------------------------------------------
// SgIterator
// -------------------------------------------------------------------

/// Iterator over the active entries of a scatter-gather table.
///
/// Created by [`sg_for_each`].
pub struct SgIterator<'a> {
    entries: &'a [SgEntry],
    pos: usize,
}

impl<'a> Iterator for SgIterator<'a> {
    type Item = &'a SgEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.entries.len() {
            let entry = &self.entries[self.pos];
            self.pos += 1;
            Some(entry)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.entries.len() - self.pos;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for SgIterator<'a> {}

/// Returns an iterator over the active entries of the table.
pub fn sg_for_each(table: &SgTable) -> SgIterator<'_> {
    SgIterator {
        entries: &table.entries[..table.nents],
        pos: 0,
    }
}

// -------------------------------------------------------------------
// SgPool
// -------------------------------------------------------------------

/// Pre-allocated pool of scatter-gather tables.
///
/// Keeps up to [`MAX_SG_TABLES`] tables ready for fast
/// allocation, avoiding heap traffic on hot DMA setup paths.
pub struct SgPool {
    /// Pre-allocated tables.
    tables: [SgTable; MAX_SG_TABLES],
    /// Number of tables currently allocated from the pool.
    allocated: usize,
}

impl Default for SgPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SgPool {
    /// Creates a new pool with all tables available.
    pub const fn new() -> Self {
        const EMPTY: SgTable = SgTable {
            entries: [SgEntry {
                phys_addr: 0,
                length: 0,
                offset: 0,
            }; MAX_SG_ENTRIES],
            nents: 0,
            mapped: false,
            direction: DmaSgDirection::None,
            active: false,
        };
        Self {
            tables: [EMPTY; MAX_SG_TABLES],
            allocated: 0,
        }
    }

    /// Allocate a table from the pool.
    ///
    /// Returns the pool-local index of the allocated table.
    pub fn alloc(&mut self) -> Result<usize> {
        for (i, table) in self.tables.iter_mut().enumerate() {
            if !table.active {
                *table = SgTable::new();
                table.active = true;
                self.allocated += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a table back to the pool by its index.
    ///
    /// Returns [`Error::Busy`] if the table is still
    /// DMA-mapped, or [`Error::InvalidArgument`] if the index
    /// is out of range.
    pub fn free(&mut self, index: usize) -> Result<()> {
        if index >= MAX_SG_TABLES {
            return Err(Error::InvalidArgument);
        }
        if !self.tables[index].active {
            return Err(Error::InvalidArgument);
        }
        if self.tables[index].mapped {
            return Err(Error::Busy);
        }
        self.tables[index] = SgTable::new();
        self.allocated = self.allocated.saturating_sub(1);
        Ok(())
    }

    /// Returns a mutable reference to the table at `index`.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut SgTable> {
        if index >= MAX_SG_TABLES {
            return Err(Error::InvalidArgument);
        }
        if !self.tables[index].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.tables[index])
    }

    /// Returns an immutable reference to the table at `index`.
    pub fn get(&self, index: usize) -> Result<&SgTable> {
        if index >= MAX_SG_TABLES {
            return Err(Error::InvalidArgument);
        }
        if !self.tables[index].active {
            return Err(Error::NotFound);
        }
        Ok(&self.tables[index])
    }

    /// Number of tables currently allocated.
    pub fn allocated(&self) -> usize {
        self.allocated
    }

    /// Number of tables available for allocation.
    pub fn available(&self) -> usize {
        MAX_SG_TABLES - self.allocated
    }

    /// Pool capacity (always [`MAX_SG_TABLES`]).
    pub fn capacity(&self) -> usize {
        MAX_SG_TABLES
    }
}
