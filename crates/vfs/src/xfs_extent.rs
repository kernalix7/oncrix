// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS extent management.
//!
//! XFS uses a B+ tree (the "B-map" or "bmbt") to record file extents.
//! This module implements the packed 128-bit extent record format,
//! the in-memory extent list, and basic operations: lookup, insert,
//! and gap detection for preallocation.

use oncrix_lib::{Error, Result};

/// Maximum number of extents in the in-memory extent list.
pub const XFS_EXTENTS_MAX: usize = 2048;

/// Extent state flags (stored in bits [127:126] of the packed record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XfsExtentState {
    /// Normal allocated extent.
    Normal = 0,
    /// Unwritten (pre-allocated, not yet initialized).
    Unwritten = 1,
}

/// Packed XFS extent record (128 bits on disk).
///
/// Bit layout (most-significant first):
/// - [127:126] state (2 bits)
/// - [125:73]  startoff — logical file offset in FSBs (53 bits)
/// - [72:21]   startblock — physical FSB address (52 bits)
/// - [20:0]    blockcount — length in FSBs (21 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfsExtentRaw {
    pub hi: u64,
    pub lo: u64,
}

impl XfsExtentRaw {
    /// Unpack into an `XfsExtent`.
    pub fn unpack(&self) -> XfsExtent {
        let state = ((self.hi >> 62) & 0x3) as u8;
        let startoff = ((self.hi >> 9) & 0x001f_ffff_ffff_ffff) as u64;
        let startblock = (((self.hi & 0x1ff) << 43) | (self.lo >> 21)) as u64;
        let blockcount = (self.lo & 0x001f_ffff) as u32;
        XfsExtent {
            startoff,
            startblock,
            blockcount,
            state: if state == 1 {
                XfsExtentState::Unwritten
            } else {
                XfsExtentState::Normal
            },
        }
    }
}

/// Unpacked XFS extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfsExtent {
    /// Logical start offset in file-system blocks.
    pub startoff: u64,
    /// Physical start address in file-system blocks.
    pub startblock: u64,
    /// Number of file-system blocks.
    pub blockcount: u32,
    /// Extent state.
    pub state: XfsExtentState,
}

impl XfsExtent {
    /// Create a new normal extent.
    pub fn new(startoff: u64, startblock: u64, blockcount: u32) -> Self {
        Self {
            startoff,
            startblock,
            blockcount,
            state: XfsExtentState::Normal,
        }
    }

    /// Last logical block in this extent (inclusive).
    pub fn last_off(&self) -> u64 {
        self.startoff + self.blockcount as u64 - 1
    }

    /// Whether the given logical block falls within this extent.
    pub fn contains(&self, off: u64) -> bool {
        off >= self.startoff && off <= self.last_off()
    }

    /// Whether this extent is unwritten (pre-allocated).
    pub fn is_unwritten(&self) -> bool {
        self.state == XfsExtentState::Unwritten
    }

    /// Physical block for a given logical offset within this extent.
    pub fn phys_block(&self, off: u64) -> Option<u64> {
        if self.contains(off) {
            Some(self.startblock + (off - self.startoff))
        } else {
            None
        }
    }
}

/// In-memory XFS extent list (sorted by `startoff`).
pub struct XfsExtentList {
    extents: [Option<XfsExtent>; XFS_EXTENTS_MAX],
    count: usize,
}

impl XfsExtentList {
    /// Create an empty extent list.
    pub const fn new() -> Self {
        Self {
            extents: [const { None }; XFS_EXTENTS_MAX],
            count: 0,
        }
    }

    /// Insert an extent in sorted order.
    pub fn insert(&mut self, ext: XfsExtent) -> Result<()> {
        if self.count >= XFS_EXTENTS_MAX {
            return Err(Error::OutOfMemory);
        }
        let pos = self.extents[..self.count]
            .iter()
            .filter_map(|s| s.as_ref())
            .position(|e| e.startoff > ext.startoff)
            .unwrap_or(self.count);
        // Shift right.
        if pos < self.count {
            self.extents.copy_within(pos..self.count, pos + 1);
        }
        self.extents[pos] = Some(ext);
        self.count += 1;
        Ok(())
    }

    /// Look up the extent containing `off`.
    pub fn lookup(&self, off: u64) -> Option<XfsExtent> {
        // Binary search: find last extent with startoff <= off.
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match &self.extents[mid] {
                Some(e) if e.startoff <= off => lo = mid + 1,
                _ => hi = mid,
            }
        }
        if lo == 0 {
            return None;
        }
        self.extents[lo - 1].filter(|e| e.contains(off))
    }

    /// Find the first hole at or after `off` (returns the hole start).
    pub fn next_hole(&self, off: u64) -> u64 {
        let mut cur = off;
        for slot in &self.extents[..self.count] {
            if let Some(e) = slot {
                if e.startoff <= cur && e.last_off() >= cur {
                    cur = e.last_off() + 1;
                } else if e.startoff > cur {
                    break;
                }
            }
        }
        cur
    }

    /// Remove the extent at `startoff` (exact match).
    pub fn remove(&mut self, startoff: u64) -> Result<XfsExtent> {
        for i in 0..self.count {
            if self.extents[i].map(|e| e.startoff) == Some(startoff) {
                let removed = self.extents[i].take().unwrap();
                self.extents.copy_within(i + 1..self.count, i);
                self.extents[self.count - 1] = None;
                self.count -= 1;
                return Ok(removed);
            }
        }
        Err(Error::NotFound)
    }

    /// Number of extents.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all extents.
    pub fn iter(&self) -> impl Iterator<Item = &XfsExtent> {
        self.extents[..self.count].iter().filter_map(|s| s.as_ref())
    }
}

impl Default for XfsExtentList {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the extent list.
#[derive(Debug, Default, Clone, Copy)]
pub struct XfsExtentStats {
    pub total_extents: u64,
    pub unwritten_extents: u64,
    pub total_blocks: u64,
}

impl XfsExtentStats {
    /// Compute stats from an extent list.
    pub fn from_list(list: &XfsExtentList) -> Self {
        let mut stats = Self::default();
        for ext in list.iter() {
            stats.total_extents += 1;
            stats.total_blocks += ext.blockcount as u64;
            if ext.is_unwritten() {
                stats.unwritten_extents += 1;
            }
        }
        stats
    }
}
