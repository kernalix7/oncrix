// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS space allocator.
//!
//! XFS uses two B-trees per allocation group to track free space:
//! - **bnobt** — indexed by block number (for exact/near allocation)
//! - **cntbt** — indexed by extent length (for best-fit allocation)
//!
//! This module implements a simplified version of these trees using fixed-size
//! sorted arrays for the key/record sets, supporting alloc_extent and
//! free_extent operations.
//!
//! # Design
//!
//! - [`XfsAllocRecord`] — free extent record (startblock + blockcount)
//! - [`BtreeNode`] — simplified B-tree node (sorted records, up to 64 entries)
//! - [`XfsAllocAg`] — per-allocation-group allocator state
//! - [`alloc_extent`] — allocate blocks using best-fit/exact/near strategy
//! - [`free_extent`] — return blocks to free space
//! - [`trim_extent`] — discard free blocks (TRIM/UNMAP)
//!
//! # References
//!
//! - Linux `fs/xfs/libxfs/xfs_alloc.c`
//! - XFS Algorithms and Data Structures (Dave Chinner)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum records per B-tree node.
pub const BTREE_MAX_RECORDS: usize = 64;

/// Maximum allocation groups.
pub const MAX_AGS: usize = 32;

/// Allocation strategy hints.
pub const XFS_ALLOCTYPE_EXACT: u32 = 0;
pub const XFS_ALLOCTYPE_NEAR: u32 = 1;
pub const XFS_ALLOCTYPE_BEST: u32 = 2;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A free space record: contiguous run of `blockcount` blocks starting at
/// `startblock` within an allocation group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XfsAllocRecord {
    /// Starting block number (AG-relative).
    pub startblock: u64,
    /// Length of the free extent in blocks.
    pub blockcount: u64,
}

/// Simplified B-tree node holding sorted free space records.
///
/// bnobt: sorted by `startblock`.
/// cntbt: sorted by `blockcount` (then `startblock` as tiebreak).
#[derive(Clone)]
pub struct BtreeNode {
    /// Records stored in this node.
    pub records: [XfsAllocRecord; BTREE_MAX_RECORDS],
    /// Number of valid records.
    pub count: usize,
    /// B-tree level (0 = leaf).
    pub level: u32,
}

impl BtreeNode {
    /// Create an empty node.
    pub const fn empty() -> Self {
        Self {
            records: [XfsAllocRecord {
                startblock: 0,
                blockcount: 0,
            }; BTREE_MAX_RECORDS],
            count: 0,
            level: 0,
        }
    }
}

/// Allocation type for `alloc_extent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocType {
    /// Allocate exactly at `agbno`.
    Exact,
    /// Allocate near `agbno`.
    Near,
    /// Allocate best-fit (smallest sufficient extent).
    Best,
}

/// Per-allocation-group allocator state.
pub struct XfsAllocAg {
    /// AG number.
    pub agno: u32,
    /// Total blocks in this AG.
    pub ag_length: u64,
    /// Free blocks in this AG.
    pub free_blocks: u64,
    /// B-tree sorted by block number.
    pub bnobt: BtreeNode,
    /// B-tree sorted by block count.
    pub cntbt: BtreeNode,
}

impl XfsAllocAg {
    /// Create a new AG with all blocks free.
    pub fn new(agno: u32, ag_length: u64) -> Self {
        let mut ag = Self {
            agno,
            ag_length,
            free_blocks: ag_length,
            bnobt: BtreeNode::empty(),
            cntbt: BtreeNode::empty(),
        };
        // Single free extent covering the entire AG.
        let rec = XfsAllocRecord {
            startblock: 0,
            blockcount: ag_length,
        };
        ag.bnobt.records[0] = rec;
        ag.bnobt.count = 1;
        ag.cntbt.records[0] = rec;
        ag.cntbt.count = 1;
        ag
    }
}

/// The XFS allocator managing multiple AGs.
pub struct XfsAlloc {
    pub ags: [Option<XfsAllocAg>; MAX_AGS],
    pub ag_count: usize,
    pub total_free: u64,
}

impl XfsAlloc {
    /// Create an allocator with `ag_count` AGs of `ag_length` blocks each.
    pub fn new(ag_count: usize, ag_length: u64) -> Result<Self> {
        if ag_count > MAX_AGS || ag_count == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut alloc = Self {
            ags: core::array::from_fn(|_| None),
            ag_count,
            total_free: 0,
        };
        for i in 0..ag_count {
            let ag = XfsAllocAg::new(i as u32, ag_length);
            alloc.total_free += ag.free_blocks;
            alloc.ags[i] = Some(ag);
        }
        Ok(alloc)
    }
}

// ---------------------------------------------------------------------------
// BTree helpers
// ---------------------------------------------------------------------------

/// Insert a record into the bnobt (sorted by startblock).
fn bnobt_insert(bt: &mut BtreeNode, rec: XfsAllocRecord) -> Result<()> {
    if bt.count >= BTREE_MAX_RECORDS {
        return Err(Error::OutOfMemory);
    }
    // Find insertion point.
    let mut pos = bt.count;
    for i in 0..bt.count {
        if bt.records[i].startblock > rec.startblock {
            pos = i;
            break;
        }
    }
    // Shift right.
    for i in (pos..bt.count).rev() {
        bt.records[i + 1] = bt.records[i];
    }
    bt.records[pos] = rec;
    bt.count += 1;
    Ok(())
}

/// Insert a record into the cntbt (sorted by blockcount, then startblock).
fn cntbt_insert(bt: &mut BtreeNode, rec: XfsAllocRecord) -> Result<()> {
    if bt.count >= BTREE_MAX_RECORDS {
        return Err(Error::OutOfMemory);
    }
    let mut pos = bt.count;
    for i in 0..bt.count {
        let r = &bt.records[i];
        if r.blockcount > rec.blockcount
            || (r.blockcount == rec.blockcount && r.startblock > rec.startblock)
        {
            pos = i;
            break;
        }
    }
    for i in (pos..bt.count).rev() {
        bt.records[i + 1] = bt.records[i];
    }
    bt.records[pos] = rec;
    bt.count += 1;
    Ok(())
}

/// Remove a record from the bnobt by startblock.
fn bnobt_remove(bt: &mut BtreeNode, startblock: u64) -> Option<XfsAllocRecord> {
    for i in 0..bt.count {
        if bt.records[i].startblock == startblock {
            let rec = bt.records[i];
            for j in i..bt.count - 1 {
                bt.records[j] = bt.records[j + 1];
            }
            bt.count -= 1;
            return Some(rec);
        }
    }
    None
}

/// Remove a record from the cntbt by startblock (used when removing by extent identity).
fn cntbt_remove(bt: &mut BtreeNode, startblock: u64, blockcount: u64) -> Option<XfsAllocRecord> {
    for i in 0..bt.count {
        if bt.records[i].startblock == startblock && bt.records[i].blockcount == blockcount {
            let rec = bt.records[i];
            for j in i..bt.count - 1 {
                bt.records[j] = bt.records[j + 1];
            }
            bt.count -= 1;
            return Some(rec);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Allocate `length` blocks from AG `agno`.
///
/// `agbno` is the hint (used for Exact/Near allocation).
/// Returns the starting AG-relative block number.
pub fn alloc_extent(
    alloc: &mut XfsAlloc,
    agno: usize,
    agbno: u64,
    length: u64,
    atype: AllocType,
) -> Result<u64> {
    if agno >= alloc.ag_count || length == 0 {
        return Err(Error::InvalidArgument);
    }
    let ag = alloc.ags[agno].as_mut().ok_or(Error::NotFound)?;

    if ag.free_blocks < length {
        return Err(Error::OutOfMemory);
    }

    let record_idx = match atype {
        AllocType::Exact => {
            // Find exact match in bnobt.
            let mut found = None;
            for i in 0..ag.bnobt.count {
                let r = ag.bnobt.records[i];
                if r.startblock == agbno && r.blockcount >= length {
                    found = Some(i);
                    break;
                }
            }
            found
        }
        AllocType::Near => {
            // Find first extent at or after agbno with sufficient length.
            let mut found = None;
            for i in 0..ag.bnobt.count {
                let r = ag.bnobt.records[i];
                if r.startblock >= agbno && r.blockcount >= length {
                    found = Some(i);
                    break;
                }
            }
            // If not found, try any extent with sufficient length.
            if found.is_none() {
                for i in 0..ag.bnobt.count {
                    if ag.bnobt.records[i].blockcount >= length {
                        found = Some(i);
                        break;
                    }
                }
            }
            found
        }
        AllocType::Best => {
            // Best fit: smallest extent >= length (cntbt is sorted by count).
            let mut found = None;
            for i in 0..ag.cntbt.count {
                if ag.cntbt.records[i].blockcount >= length {
                    found = Some(i);
                    break;
                }
            }
            // Convert cntbt index to bnobt startblock.
            if let Some(ci) = found {
                let sb = ag.cntbt.records[ci].startblock;
                let mut bi = None;
                for i in 0..ag.bnobt.count {
                    if ag.bnobt.records[i].startblock == sb {
                        bi = Some(i);
                        break;
                    }
                }
                bi
            } else {
                None
            }
        }
    };

    let idx = record_idx.ok_or(Error::OutOfMemory)?;
    let rec = ag.bnobt.records[idx];
    let alloc_start = rec.startblock;

    // Remove from both trees.
    bnobt_remove(&mut ag.bnobt, rec.startblock);
    cntbt_remove(&mut ag.cntbt, rec.startblock, rec.blockcount);

    // If the extent is larger than needed, re-insert the remainder.
    if rec.blockcount > length {
        let remainder = XfsAllocRecord {
            startblock: alloc_start + length,
            blockcount: rec.blockcount - length,
        };
        bnobt_insert(&mut ag.bnobt, remainder)?;
        cntbt_insert(&mut ag.cntbt, remainder)?;
    }

    ag.free_blocks -= length;
    alloc.total_free -= length;
    Ok(alloc_start)
}

/// Free `length` blocks starting at `agbno` in AG `agno`.
///
/// Merges with adjacent free extents (coalescing).
pub fn free_extent(alloc: &mut XfsAlloc, agno: usize, agbno: u64, length: u64) -> Result<()> {
    if agno >= alloc.ag_count || length == 0 {
        return Err(Error::InvalidArgument);
    }
    let ag = alloc.ags[agno].as_mut().ok_or(Error::NotFound)?;

    let mut new_start = agbno;
    let mut new_len = length;

    // Check for left neighbour (extent ending at agbno).
    let mut left_idx = None;
    for i in 0..ag.bnobt.count {
        let r = ag.bnobt.records[i];
        if r.startblock + r.blockcount == agbno {
            left_idx = Some(i);
            break;
        }
    }
    if let Some(li) = left_idx {
        let lr = ag.bnobt.records[li];
        bnobt_remove(&mut ag.bnobt, lr.startblock);
        cntbt_remove(&mut ag.cntbt, lr.startblock, lr.blockcount);
        new_start = lr.startblock;
        new_len += lr.blockcount;
    }

    // Check for right neighbour (extent starting at agbno + length).
    let right_start = new_start + new_len;
    let mut right_rec = None;
    for i in 0..ag.bnobt.count {
        if ag.bnobt.records[i].startblock == right_start {
            right_rec = Some(ag.bnobt.records[i]);
            break;
        }
    }
    if let Some(rr) = right_rec {
        bnobt_remove(&mut ag.bnobt, rr.startblock);
        cntbt_remove(&mut ag.cntbt, rr.startblock, rr.blockcount);
        new_len += rr.blockcount;
    }

    let merged = XfsAllocRecord {
        startblock: new_start,
        blockcount: new_len,
    };
    bnobt_insert(&mut ag.bnobt, merged)?;
    cntbt_insert(&mut ag.cntbt, merged)?;

    ag.free_blocks += length;
    alloc.total_free += length;
    Ok(())
}

/// Trim (discard) free blocks in AG `agno` from `agbno` for `length` blocks.
///
/// This marks the range as available for TRIM/UNMAP. The blocks must already
/// be free. Returns the number of blocks trimmed.
pub fn trim_extent(alloc: &mut XfsAlloc, agno: usize, agbno: u64, length: u64) -> Result<u64> {
    if agno >= alloc.ag_count || length == 0 {
        return Err(Error::InvalidArgument);
    }
    let ag = alloc.ags[agno].as_ref().ok_or(Error::NotFound)?;

    // Verify the range is actually free.
    let mut covered = 0u64;
    for i in 0..ag.bnobt.count {
        let r = ag.bnobt.records[i];
        // Overlap check.
        let overlap_start = r.startblock.max(agbno);
        let overlap_end = (r.startblock + r.blockcount).min(agbno + length);
        if overlap_start < overlap_end {
            covered += overlap_end - overlap_start;
        }
    }
    // Return trimmed byte count (simplified: block-level).
    Ok(covered)
}

/// Return total free blocks across all AGs.
pub fn total_free_blocks(alloc: &XfsAlloc) -> u64 {
    alloc.total_free
}

/// Return free blocks in a specific AG.
pub fn ag_free_blocks(alloc: &XfsAlloc, agno: usize) -> u64 {
    alloc
        .ags
        .get(agno)
        .and_then(|ag| ag.as_ref())
        .map_or(0, |ag| ag.free_blocks)
}
