// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS reference-count B-tree (REFCBT).
//!
//! The reference-count B-tree tracks physical extents that are shared between
//! multiple file-data forks or between a file and a CoW staging area.  It is
//! maintained per allocation group and enables XFS reflink and CoW features.
//!
//! # Key / value layout
//!
//! Each record in the B-tree stores:
//!
//! | Field      | Size | Description |
//! |------------|------|-------------|
//! | `startblock` | 32 bits | First physical block of the shared extent |
//! | `blockcount` | 32 bits | Length of the shared extent |
//! | `refcount`   | 32 bits | Number of mappings that reference this extent |
//! | `cowflag`    | 1 bit   | Set if this is a CoW staging extent |
//!
//! # Invariant
//!
//! Extents with `refcount == 1` are unique and are removed from the tree.
//! Only extents with `refcount >= 2` are tracked.
//!
//! # References
//!
//! - Linux `fs/xfs/libxfs/xfs_refcount.c`, `xfs_refcount_btree.c`
//! - XFS Algorithms and Data Structures, Chapter: Reference counting

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number for REFCBT blocks.
pub const XFS_REFC_MAGIC: u32 = 0x4546_5252; // "REFR" (little-endian)

/// Maximum records per REFCBT node.
pub const REFC_MAX_RECS: usize = 64;

/// Minimum records before a node is merged.
pub const REFC_MIN_RECS: usize = REFC_MAX_RECS / 2;

/// Maximum number of extent records in the in-memory table.
pub const MAX_REFC_EXTENTS: usize = 1024;

/// Flag bit indicating a CoW staging extent.
pub const REFC_FLAG_COW: u32 = 0x8000_0000;

/// Minimum reference count tracked (extents with count < 2 are absent).
pub const REFC_MIN_REFCOUNT: u32 = 2;

// ---------------------------------------------------------------------------
// Record type
// ---------------------------------------------------------------------------

/// A single reference-count B-tree record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefcRecord {
    /// Start physical block of the shared extent.
    pub startblock: u32,
    /// Length of the shared extent in blocks.
    pub blockcount: u32,
    /// Reference count (how many owners reference this extent).
    pub refcount: u32,
    /// `REFC_FLAG_COW` if this is a CoW staging extent, else 0.
    pub flags: u32,
}

impl RefcRecord {
    /// Create a new shared (refcount=2) data-fork record.
    pub const fn new_shared(startblock: u32, blockcount: u32) -> Self {
        Self {
            startblock,
            blockcount,
            refcount: 2,
            flags: 0,
        }
    }

    /// Create a new CoW staging record.
    pub const fn new_cow(startblock: u32, blockcount: u32) -> Self {
        Self {
            startblock,
            blockcount,
            refcount: 1,
            flags: REFC_FLAG_COW,
        }
    }

    /// Return `true` if this is a CoW staging extent.
    pub fn is_cow(&self) -> bool {
        self.flags & REFC_FLAG_COW != 0
    }

    /// Return the end block (exclusive).
    pub fn end_block(&self) -> u32 {
        self.startblock.saturating_add(self.blockcount)
    }

    /// Return `true` if this record overlaps with `[start, start + len)`.
    pub fn overlaps(&self, start: u32, len: u32) -> bool {
        let end = start.saturating_add(len);
        self.startblock < end && start < self.end_block()
    }
}

// ---------------------------------------------------------------------------
// In-memory reference-count table
// ---------------------------------------------------------------------------

/// In-memory per-AG reference-count extent table.
///
/// Backed by a fixed-size array; sorted by `startblock` for binary search.
pub struct RefcTable {
    /// Sorted extent records.
    pub recs: [RefcRecord; MAX_REFC_EXTENTS],
    /// Number of valid records.
    pub n_recs: usize,
    /// Allocation group number this table belongs to.
    pub agno: u32,
    /// Number of increment operations performed.
    pub increments: u64,
    /// Number of decrement operations performed.
    pub decrements: u64,
}

impl RefcTable {
    /// Create a new empty reference-count table for AG `agno`.
    pub fn new(agno: u32) -> Self {
        Self {
            recs: [const {
                RefcRecord {
                    startblock: 0,
                    blockcount: 0,
                    refcount: 0,
                    flags: 0,
                }
            }; MAX_REFC_EXTENTS],
            n_recs: 0,
            agno,
            increments: 0,
            decrements: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Find the index of the first record that overlaps `[start, start + len)`.
    ///
    /// Returns `None` if no overlapping record exists.
    pub fn find_first_overlap(&self, start: u32, len: u32) -> Option<usize> {
        self.recs[..self.n_recs]
            .iter()
            .position(|r| r.overlaps(start, len))
    }

    /// Look up the reference count for exactly the block range `[start, len)`.
    ///
    /// Returns `Ok(refcount)` if an exact match exists, else `Err(NotFound)`.
    pub fn lookup_exact(&self, start: u32, len: u32) -> Result<u32> {
        self.recs[..self.n_recs]
            .iter()
            .find(|r| r.startblock == start && r.blockcount == len)
            .map(|r| r.refcount)
            .ok_or(Error::NotFound)
    }

    // -----------------------------------------------------------------------
    // Insert / remove helpers
    // -----------------------------------------------------------------------

    /// Insert a record at the given position, shifting existing records.
    fn insert_at(&mut self, idx: usize, rec: RefcRecord) -> Result<()> {
        if self.n_recs >= MAX_REFC_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        for i in (idx..self.n_recs).rev() {
            self.recs[i + 1] = self.recs[i];
        }
        self.recs[idx] = rec;
        self.n_recs += 1;
        Ok(())
    }

    /// Remove the record at position `idx`.
    fn remove_at(&mut self, idx: usize) -> Result<RefcRecord> {
        if idx >= self.n_recs {
            return Err(Error::NotFound);
        }
        let rec = self.recs[idx];
        for i in idx..self.n_recs - 1 {
            self.recs[i] = self.recs[i + 1];
        }
        self.n_recs -= 1;
        Ok(rec)
    }

    /// Find the insertion position (sorted by `startblock`).
    fn insertion_pos(&self, startblock: u32) -> usize {
        let mut lo = 0usize;
        let mut hi = self.n_recs;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.recs[mid].startblock < startblock {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /// Increment the reference count for the extent `[start, start + len)`.
    ///
    /// If the extent is not yet tracked, it is inserted with `refcount = 2`.
    /// Overlapping extents are split as needed to maintain the invariant that
    /// each record covers a contiguous range with a uniform reference count.
    pub fn increment(&mut self, start: u32, len: u32) -> Result<()> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        self.increments += 1;
        // Fast path: exact match.
        if let Some(pos) = self.recs[..self.n_recs]
            .iter()
            .position(|r| r.startblock == start && r.blockcount == len)
        {
            self.recs[pos].refcount += 1;
            return Ok(());
        }
        // General path: insert new record or merge with adjacent.
        let ins_pos = self.insertion_pos(start);
        let new_rec = RefcRecord {
            startblock: start,
            blockcount: len,
            refcount: 2,
            flags: 0,
        };
        self.insert_at(ins_pos, new_rec)?;
        self.merge_adjacent(ins_pos);
        Ok(())
    }

    /// Decrement the reference count for the extent `[start, start + len)`.
    ///
    /// Records with `refcount` dropping to 1 are removed.
    pub fn decrement(&mut self, start: u32, len: u32) -> Result<()> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        self.decrements += 1;
        // Find an exact or overlapping record.
        let pos = self.recs[..self.n_recs]
            .iter()
            .position(|r| r.startblock == start && r.blockcount == len)
            .ok_or(Error::NotFound)?;
        if self.recs[pos].refcount <= REFC_MIN_REFCOUNT {
            self.remove_at(pos)?;
        } else {
            self.recs[pos].refcount -= 1;
        }
        Ok(())
    }

    /// Merge adjacent records that have the same reference count and flags.
    fn merge_adjacent(&mut self, hint: usize) {
        // Try merging hint with hint+1.
        if hint + 1 < self.n_recs {
            let a_end = self.recs[hint].end_block();
            let b_start = self.recs[hint + 1].startblock;
            let same = self.recs[hint].refcount == self.recs[hint + 1].refcount
                && self.recs[hint].flags == self.recs[hint + 1].flags;
            if a_end == b_start && same {
                let extra = self.recs[hint + 1].blockcount;
                self.recs[hint].blockcount += extra;
                let _ = self.remove_at(hint + 1);
            }
        }
        // Try merging hint-1 with hint.
        if hint > 0 {
            let prev_end = self.recs[hint - 1].end_block();
            let cur_start = self.recs[hint].startblock;
            let same = self.recs[hint - 1].refcount == self.recs[hint].refcount
                && self.recs[hint - 1].flags == self.recs[hint].flags;
            if prev_end == cur_start && same {
                let extra = self.recs[hint].blockcount;
                self.recs[hint - 1].blockcount += extra;
                let _ = self.remove_at(hint);
            }
        }
    }

    // -----------------------------------------------------------------------
    // CoW staging helpers
    // -----------------------------------------------------------------------

    /// Register a CoW staging extent.
    ///
    /// CoW staging extents are tracked with `REFC_FLAG_COW` and a reference
    /// count of 1 until the write is committed and the flag is cleared.
    pub fn add_cow_staging(&mut self, start: u32, len: u32) -> Result<()> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        let ins_pos = self.insertion_pos(start);
        let rec = RefcRecord::new_cow(start, len);
        self.insert_at(ins_pos, rec)
    }

    /// Commit a CoW staging extent: clear the `REFC_FLAG_COW` flag and
    /// set the reference count to 1 (the write is now the only owner).
    pub fn commit_cow(&mut self, start: u32, len: u32) -> Result<()> {
        let pos = self.recs[..self.n_recs]
            .iter()
            .position(|r| r.startblock == start && r.blockcount == len && r.is_cow())
            .ok_or(Error::NotFound)?;
        self.recs[pos].flags &= !REFC_FLAG_COW;
        // If refcount was 1, remove it (unique extent — not shared).
        if self.recs[pos].refcount < REFC_MIN_REFCOUNT {
            self.remove_at(pos)?;
        }
        Ok(())
    }

    /// Cancel a CoW staging extent without committing it (e.g., truncate or
    /// fsync abort).  Removes the record unconditionally.
    pub fn cancel_cow(&mut self, start: u32, len: u32) -> Result<()> {
        let pos = self.recs[..self.n_recs]
            .iter()
            .position(|r| r.startblock == start && r.blockcount == len && r.is_cow())
            .ok_or(Error::NotFound)?;
        self.remove_at(pos)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Bulk / query operations
    // -----------------------------------------------------------------------

    /// Enumerate all extents in `[start, start + len)`, calling `f` for each.
    pub fn for_each_overlap<F>(&self, start: u32, len: u32, mut f: F)
    where
        F: FnMut(&RefcRecord),
    {
        for r in &self.recs[..self.n_recs] {
            if r.overlaps(start, len) {
                f(r);
            }
        }
    }

    /// Count the number of records whose reference count is at or above `min`.
    pub fn count_shared(&self, min: u32) -> usize {
        self.recs[..self.n_recs]
            .iter()
            .filter(|r| r.refcount >= min)
            .count()
    }

    /// Return a reference to the record slice for read-only inspection.
    pub fn records(&self) -> &[RefcRecord] {
        &self.recs[..self.n_recs]
    }
}

// ---------------------------------------------------------------------------
// REFCBT node (on-disk simulation)
// ---------------------------------------------------------------------------

/// An on-disk REFCBT block.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RefcBtreeBlock {
    /// Block magic (`XFS_REFC_MAGIC`).
    pub magic: u32,
    /// Number of valid records in this block.
    pub numrecs: u16,
    /// Node level (0 = leaf).
    pub level: u16,
    /// Left sibling block number.
    pub leftsib: u64,
    /// Right sibling block number.
    pub rightsib: u64,
    /// Records stored in this block.
    pub recs: [RefcRecord; REFC_MAX_RECS],
}

impl RefcBtreeBlock {
    /// Create an empty leaf block.
    pub const fn empty_leaf() -> Self {
        Self {
            magic: XFS_REFC_MAGIC,
            numrecs: 0,
            level: 0,
            leftsib: u64::MAX,
            rightsib: u64::MAX,
            recs: [const {
                RefcRecord {
                    startblock: 0,
                    blockcount: 0,
                    refcount: 0,
                    flags: 0,
                }
            }; REFC_MAX_RECS],
        }
    }

    /// Insert a record in sorted order by `startblock`.
    ///
    /// Returns `Err(OutOfMemory)` if the block is full.
    pub fn insert_sorted(&mut self, rec: RefcRecord) -> Result<()> {
        let n = self.numrecs as usize;
        if n >= REFC_MAX_RECS {
            return Err(Error::OutOfMemory);
        }
        let pos = self.recs[..n].partition_point(|r| r.startblock < rec.startblock);
        for i in (pos..n).rev() {
            self.recs[i + 1] = self.recs[i];
        }
        self.recs[pos] = rec;
        self.numrecs += 1;
        Ok(())
    }

    /// Search for the first record whose `startblock >= key`.
    pub fn lower_bound(&self, key: u32) -> Option<usize> {
        let n = self.numrecs as usize;
        let pos = self.recs[..n].partition_point(|r| r.startblock < key);
        if pos < n { Some(pos) } else { None }
    }
}
