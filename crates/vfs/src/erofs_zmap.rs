// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EROFS compressed data mapping (Z_EROFS zmap).
//!
//! EROFS can store file data in compressed form using a two-level index:
//!
//! 1. **Logical cluster (lcluster)** — the logical unit of compression,
//!    always a power-of-two multiple of the block size.
//! 2. **Physical cluster** — one or more contiguous on-disk blocks that
//!    hold the compressed payload for one logical cluster.
//!
//! The `zmap` layer translates a file logical block number into a
//! `ZerofsExtent` that describes the physical location and compression
//! method, plus the in-cluster offset needed for decompression.
//!
//! # References
//!
//! - Linux `fs/erofs/zmap.c`, `fs/erofs/internal.h`
//! - EROFS on-disk format specification

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// EROFS block size (4 KiB, matches page size).
pub const EROFS_BLOCK_SIZE: u32 = 4096;

/// Maximum number of logical clusters per inode tracked in one index page.
pub const MAX_LCLUSTERS_PER_PAGE: usize = 128;

/// Maximum size of a physical cluster in blocks.
pub const MAX_PCLUSTER_BLOCKS: u32 = 16;

/// Sentinel physical block address meaning "inline data" (no block I/O).
pub const EROFS_INLINE_PBLK: u64 = u64::MAX;

// ── CompressionAlgo ───────────────────────────────────────────────────────────

/// Compression algorithm used for a physical cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CompressionAlgo {
    /// Data is stored uncompressed.
    #[default]
    None = 0,
    /// LZ4 block compression.
    Lz4 = 1,
    /// DEFLATE (zlib) compression.
    Deflate = 2,
    /// Zstandard compression.
    Zstd = 3,
}

// ── LclusterType ──────────────────────────────────────────────────────────────

/// Logical cluster descriptor type in the on-disk index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LclusterType {
    /// Plain (non-compressed) data cluster.
    Plain = 0,
    /// Head cluster: starts a new physical cluster.
    Head1 = 1,
    /// Non-head cluster: continuation of a physical cluster.
    Nonhead = 2,
    /// Head cluster with a delta-encoded physical address.
    Head2 = 3,
}

// ── LclusterIndex ─────────────────────────────────────────────────────────────

/// On-disk logical cluster index entry.
#[derive(Debug, Clone, Copy)]
pub struct LclusterIndex {
    /// Logical cluster number (0-based within the inode).
    pub lcn: u32,
    /// Physical block address of the compressed data.
    pub pblk: u64,
    /// Compression algorithm for this cluster.
    pub algo: CompressionAlgo,
    /// Type of this lcluster index entry.
    pub ltype: LclusterType,
    /// Delta to the next head cluster (used for Nonhead entries).
    pub delta: u16,
    /// Compressed length of the physical cluster in bytes (0 = full block).
    pub plen: u32,
}

impl LclusterIndex {
    /// Create a plain (uncompressed) lcluster index entry.
    pub const fn plain(lcn: u32, pblk: u64) -> Self {
        Self {
            lcn,
            pblk,
            algo: CompressionAlgo::None,
            ltype: LclusterType::Plain,
            delta: 0,
            plen: EROFS_BLOCK_SIZE,
        }
    }

    /// Create a compressed head lcluster index entry.
    pub const fn compressed_head(lcn: u32, pblk: u64, algo: CompressionAlgo, plen: u32) -> Self {
        Self {
            lcn,
            pblk,
            algo,
            ltype: LclusterType::Head1,
            delta: 0,
            plen,
        }
    }
}

// ── ZerofsExtent ──────────────────────────────────────────────────────────────

/// Result of a zmap lookup: describes how to obtain decompressed data for
/// a given logical file offset.
#[derive(Debug, Clone, Copy)]
pub struct ZerofsExtent {
    /// Physical block address of the compressed data (or `EROFS_INLINE_PBLK`).
    pub pblk: u64,
    /// Byte offset within the decompressed output where this logical block
    /// starts.
    pub logical_offset: u64,
    /// Length of the compressed physical cluster in bytes.
    pub plen: u32,
    /// Decompressed length of the cluster in bytes.
    pub dlen: u32,
    /// Compression algorithm to apply.
    pub algo: CompressionAlgo,
    /// Whether this extent covers inline data (stored in the inode tail).
    pub is_inline: bool,
}

// ── ZmapIndex ─────────────────────────────────────────────────────────────────

/// In-memory compressed cluster index for a single inode.
///
/// Holds a fixed-size array of lcluster index entries sorted by `lcn`.
/// Lookups use a linear scan; a real implementation would use a B-tree.
pub struct ZmapIndex {
    /// Logical cluster size in bytes (power of two, >= block size).
    pub lcluster_size: u32,
    /// Lcluster index entries, sorted by `lcn`.
    entries: [LclusterIndex; MAX_LCLUSTERS_PER_PAGE],
    /// Number of valid entries.
    count: usize,
}

impl ZmapIndex {
    /// Create an empty zmap index with the given logical cluster size.
    pub const fn new(lcluster_size: u32) -> Self {
        Self {
            lcluster_size,
            entries: [const {
                LclusterIndex {
                    lcn: 0,
                    pblk: 0,
                    algo: CompressionAlgo::None,
                    ltype: LclusterType::Plain,
                    delta: 0,
                    plen: EROFS_BLOCK_SIZE,
                }
            }; MAX_LCLUSTERS_PER_PAGE],
            count: 0,
        }
    }

    /// Insert an lcluster index entry.  Returns `OutOfMemory` if full.
    pub fn insert(&mut self, entry: LclusterIndex) -> Result<()> {
        if self.count >= MAX_LCLUSTERS_PER_PAGE {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Compute the logical cluster number for a given file byte offset.
    pub fn lcn_for_offset(&self, offset: u64) -> u32 {
        (offset / self.lcluster_size as u64) as u32
    }

    /// Find the head lcluster index for a given lcn.
    ///
    /// For `Nonhead` entries the method walks back to find the owning
    /// `Head1`/`Head2` entry so that the correct pblk is returned.
    fn find_head(&self, lcn: u32) -> Option<&LclusterIndex> {
        // Find the entry for lcn.
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.lcn == lcn)?;
        let entry = &self.entries[pos];

        match entry.ltype {
            LclusterType::Plain | LclusterType::Head1 | LclusterType::Head2 => Some(entry),
            LclusterType::Nonhead => {
                // delta tells us how many clusters back the head is.
                let head_lcn = lcn.saturating_sub(entry.delta as u32);
                self.entries[..self.count].iter().find(|e| {
                    e.lcn == head_lcn
                        && matches!(e.ltype, LclusterType::Head1 | LclusterType::Head2)
                })
            }
        }
    }

    /// Perform a zmap lookup: translate a logical file `offset` into a
    /// `ZerofsExtent`.
    ///
    /// Returns `NotFound` if the offset is beyond the indexed range.
    pub fn lookup(&self, offset: u64) -> Result<ZerofsExtent> {
        if self.count == 0 {
            return Err(Error::NotFound);
        }

        let lcn = self.lcn_for_offset(offset);
        let head = self.find_head(lcn).ok_or(Error::NotFound)?;
        let is_inline = head.pblk == EROFS_INLINE_PBLK;

        let dlen = self.lcluster_size;
        let logical_offset = offset & !(self.lcluster_size as u64 - 1);

        Ok(ZerofsExtent {
            pblk: head.pblk,
            logical_offset,
            plen: head.plen,
            dlen,
            algo: head.algo,
            is_inline,
        })
    }
}

// ── Shared / inline xattr compressed block ────────────────────────────────────

/// Descriptor for a shared xattr compressed block.
#[derive(Debug, Clone, Copy)]
pub struct SharedXattrBlock {
    /// Physical block address of the compressed xattr data.
    pub pblk: u64,
    /// Compressed length.
    pub plen: u32,
    /// Decompressed length.
    pub dlen: u32,
    /// Compression algorithm.
    pub algo: CompressionAlgo,
}

/// Look up the physical location of a shared xattr block by its index.
///
/// `xattr_blocks` is the sorted table of shared xattr compressed blocks.
/// Returns `NotFound` if `xattr_id` exceeds the table length.
pub fn lookup_shared_xattr(
    xattr_blocks: &[SharedXattrBlock],
    xattr_id: u32,
) -> Result<&SharedXattrBlock> {
    xattr_blocks.get(xattr_id as usize).ok_or(Error::NotFound)
}
