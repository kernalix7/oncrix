// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! btrfs chunk tree: logical-to-physical address translation.
//!
//! The chunk tree maps btrfs logical addresses to one or more physical
//! device extents (stripes). Every chunk covers a contiguous logical range
//! and is replicated across a configurable number of devices.
//!
//! # Design
//!
//! - [`Stripe`] — a single device extent within a chunk
//! - [`ChunkItem`] — chunk descriptor with stripe layout
//! - [`ChunkTree`] — chunk → device mapping table
//!
//! # References
//!
//! - Linux `fs/btrfs/volumes.c`, `fs/btrfs/ctree.h`
//! - btrfs on-disk format documentation

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum stripes per chunk (mirrors, RAID-6, etc.).
const MAX_STRIPES_PER_CHUNK: usize = 8;

/// Maximum chunks tracked by the chunk tree.
const MAX_CHUNKS: usize = 128;

/// Btrfs chunk type flags (matches Linux BTRFS_BLOCK_GROUP_*).
pub const CHUNK_TYPE_DATA: u64 = 1 << 0;
/// System chunk type.
pub const CHUNK_TYPE_SYSTEM: u64 = 1 << 1;
/// Metadata chunk type.
pub const CHUNK_TYPE_METADATA: u64 = 1 << 2;
/// DUP profile: two copies on the same device.
pub const CHUNK_PROFILE_DUP: u64 = 1 << 4;
/// RAID-1 profile: one copy per device.
pub const CHUNK_PROFILE_RAID1: u64 = 1 << 5;
/// RAID-10 profile: striped mirrors.
pub const CHUNK_PROFILE_RAID10: u64 = 1 << 6;
/// RAID-5 profile.
pub const CHUNK_PROFILE_RAID5: u64 = 1 << 7;
/// RAID-6 profile.
pub const CHUNK_PROFILE_RAID6: u64 = 1 << 8;

// ---------------------------------------------------------------------------
// Stripe
// ---------------------------------------------------------------------------

/// A single stripe within a btrfs chunk.
///
/// Each stripe maps to a contiguous region on one physical device starting
/// at `dev_offset`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stripe {
    /// Device UUID low 64 bits (identifies the device).
    pub dev_uuid_lo: u64,
    /// Device UUID high 64 bits.
    pub dev_uuid_hi: u64,
    /// Starting byte offset on the device.
    pub dev_offset: u64,
}

impl Stripe {
    /// Return `true` if this stripe slot is in use (non-zero device UUID).
    pub fn is_valid(&self) -> bool {
        self.dev_uuid_lo != 0 || self.dev_uuid_hi != 0
    }
}

// ---------------------------------------------------------------------------
// ChunkItem
// ---------------------------------------------------------------------------

/// btrfs chunk item: describes one logical address range.
///
/// Stored in the chunk tree keyed by `(BTRFS_FIRST_CHUNK_TREE_OBJECTID,
/// BTRFS_CHUNK_ITEM_KEY, logical_start)`.
#[derive(Clone, Copy, Debug)]
pub struct ChunkItem {
    /// Logical start address of this chunk.
    pub logical_start: u64,
    /// Length of the chunk in bytes.
    pub length: u64,
    /// Owner subvolume / objectid.
    pub owner: u64,
    /// Stripe length in bytes (typically 64 KiB).
    pub stripe_len: u64,
    /// Chunk type and profile flags (`CHUNK_TYPE_*`, `CHUNK_PROFILE_*`).
    pub chunk_type: u64,
    /// I/O alignment.
    pub io_align: u32,
    /// I/O width (total stripe width).
    pub io_width: u32,
    /// Sector size for this chunk.
    pub sector_size: u32,
    /// Number of active stripes.
    pub num_stripes: u16,
    /// Number of sub-stripes (RAID-10).
    pub sub_stripes: u16,
    /// Stripe array (up to `MAX_STRIPES_PER_CHUNK`).
    pub stripes: [Stripe; MAX_STRIPES_PER_CHUNK],
}

impl ChunkItem {
    /// Create a new single-device chunk.
    pub const fn new_single(logical: u64, length: u64, chunk_type: u64) -> Self {
        Self {
            logical_start: logical,
            length,
            owner: 1,
            stripe_len: 65536,
            chunk_type,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: [Stripe {
                dev_uuid_lo: 0,
                dev_uuid_hi: 0,
                dev_offset: 0,
            }; MAX_STRIPES_PER_CHUNK],
        }
    }

    /// Return `true` if `logical` falls within this chunk.
    pub fn contains(&self, logical: u64) -> bool {
        logical >= self.logical_start && logical < self.logical_start + self.length
    }

    /// Return the stripe index for a given logical offset within this chunk
    /// (simple round-robin over `num_stripes`).
    pub fn stripe_for_offset(&self, offset_in_chunk: u64) -> usize {
        if self.num_stripes == 0 {
            return 0;
        }
        let stripe_len = if self.stripe_len == 0 {
            65536
        } else {
            self.stripe_len
        };
        ((offset_in_chunk / stripe_len) % self.num_stripes as u64) as usize
    }
}

// ---------------------------------------------------------------------------
// ChunkTree
// ---------------------------------------------------------------------------

/// btrfs chunk tree: maps logical addresses to physical device extents.
pub struct ChunkTree {
    /// Sorted array of chunks (by `logical_start`).
    chunks: [ChunkItem; MAX_CHUNKS],
    /// Number of valid chunks.
    count: usize,
    /// Next logical address for auto-allocation.
    next_logical: u64,
}

impl ChunkTree {
    /// Create an empty chunk tree starting logical allocation at 1 GiB.
    pub const fn new() -> Self {
        const EMPTY_STRIPE: Stripe = Stripe {
            dev_uuid_lo: 0,
            dev_uuid_hi: 0,
            dev_offset: 0,
        };
        const EMPTY_CHUNK: ChunkItem = ChunkItem {
            logical_start: 0,
            length: 0,
            owner: 0,
            stripe_len: 0,
            chunk_type: 0,
            io_align: 0,
            io_width: 0,
            sector_size: 0,
            num_stripes: 0,
            sub_stripes: 0,
            stripes: [EMPTY_STRIPE; MAX_STRIPES_PER_CHUNK],
        };
        Self {
            chunks: [EMPTY_CHUNK; MAX_CHUNKS],
            count: 0,
            next_logical: 1 << 30, // 1 GiB start
        }
    }

    /// Translate a logical byte address to (stripe_index, device_offset).
    ///
    /// Returns `Err(NotFound)` if no chunk covers `logical`.
    pub fn logical_to_physical(&self, logical: u64) -> Result<(usize, u64)> {
        let chunk = self.find_chunk(logical)?;
        let offset_in_chunk = logical - chunk.logical_start;
        let stripe_idx = chunk.stripe_for_offset(offset_in_chunk);

        let stripe = &chunk.stripes[stripe_idx];
        let stripe_len = if chunk.stripe_len == 0 {
            65536
        } else {
            chunk.stripe_len
        };
        let stripe_offset = offset_in_chunk % stripe_len;
        let phys = stripe.dev_offset + (offset_in_chunk / stripe_len) * stripe_len + stripe_offset;

        Ok((stripe_idx, phys))
    }

    /// Look up the chunk that covers `logical`.
    pub fn find_chunk(&self, logical: u64) -> Result<&ChunkItem> {
        // Binary search: find last chunk whose logical_start <= logical.
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.chunks[mid].logical_start <= logical {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return Err(Error::NotFound);
        }
        let candidate = &self.chunks[lo - 1];
        if candidate.contains(logical) {
            Ok(candidate)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Allocate a new chunk at the next logical address.
    ///
    /// `length` must be a multiple of the stripe length (64 KiB).
    /// `chunk_type` selects the chunk profile (e.g., `CHUNK_TYPE_DATA`).
    ///
    /// Returns the logical start of the new chunk, or `Err(OutOfMemory)`.
    pub fn chunk_alloc(&mut self, length: u64, chunk_type: u64) -> Result<u64> {
        if self.count >= MAX_CHUNKS {
            return Err(Error::OutOfMemory);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        let logical = self.next_logical;
        let mut chunk = ChunkItem::new_single(logical, length, chunk_type);
        // Set up a placeholder stripe at device offset = logical start.
        chunk.stripes[0] = Stripe {
            dev_uuid_lo: 1,
            dev_uuid_hi: 0,
            dev_offset: logical,
        };
        chunk.num_stripes = 1;

        // Insert sorted.
        let pos = self.insert_position(logical);
        let mut i = self.count;
        while i > pos {
            self.chunks[i] = self.chunks[i - 1];
            i -= 1;
        }
        self.chunks[pos] = chunk;
        self.count += 1;
        self.next_logical = logical + length;
        Ok(logical)
    }

    /// Remove the chunk starting at `logical_start`.
    ///
    /// Returns `Err(NotFound)` if no such chunk exists.
    pub fn chunk_remove(&mut self, logical_start: u64) -> Result<()> {
        let idx = self.chunks[..self.count]
            .iter()
            .position(|c| c.logical_start == logical_start)
            .ok_or(Error::NotFound)?;
        let mut i = idx;
        while i + 1 < self.count {
            self.chunks[i] = self.chunks[i + 1];
            i += 1;
        }
        self.count -= 1;
        Ok(())
    }

    /// Return the number of chunks in the tree.
    pub fn chunk_count(&self) -> usize {
        self.count
    }

    /// Iterate over chunks and call `f(chunk)` for each.
    ///
    /// Stops early if `f` returns `Err`.
    pub fn for_each<F: FnMut(&ChunkItem) -> Result<()>>(&self, mut f: F) -> Result<()> {
        for i in 0..self.count {
            f(&self.chunks[i])?;
        }
        Ok(())
    }

    // ── Private helpers ────────────────────────────────────────────

    fn insert_position(&self, logical: u64) -> usize {
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.chunks[mid].logical_start < logical {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

// ---------------------------------------------------------------------------
// Stripe layout helpers
// ---------------------------------------------------------------------------

/// Compute the total usable size for a chunk with `num_stripes` and `stripe_len`.
///
/// For RAID-5, one stripe is parity; for RAID-6, two stripes are parity.
pub fn chunk_usable_size(length: u64, chunk_type: u64, num_stripes: u16) -> u64 {
    if num_stripes == 0 {
        return 0;
    }
    if chunk_type & CHUNK_PROFILE_RAID5 != 0 && num_stripes > 1 {
        return length * (num_stripes as u64 - 1) / num_stripes as u64;
    }
    if chunk_type & CHUNK_PROFILE_RAID6 != 0 && num_stripes > 2 {
        return length * (num_stripes as u64 - 2) / num_stripes as u64;
    }
    // DUP, RAID1, RAID10, single: all stripes hold identical data.
    if chunk_type & (CHUNK_PROFILE_DUP | CHUNK_PROFILE_RAID1 | CHUNK_PROFILE_RAID10) != 0 {
        return length / 2;
    }
    length
}
