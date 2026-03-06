// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs chunk allocation and space management.
//!
//! A btrfs *chunk* is the logical unit of disk space allocation.  Each
//! chunk describes a mapping from a logical byte range to one or more
//! physical stripes on one or more underlying devices.  Block groups are
//! the per-chunk accounting structures used by the allocator.
//!
//! # Architecture
//!
//! ```text
//! SpaceInfo (DATA / METADATA / SYSTEM)
//!   └─ BlockGroup[]   (64 MiB each, default)
//!        └─ Chunk      → stripe[] → Device physical offsets
//! ```
//!
//! # RAID Profiles
//!
//! - [`RaidProfile::Single`]  — one copy, one stripe
//! - [`RaidProfile::Dup`]     — two copies on the same device
//! - [`RaidProfile::Raid0`]   — striped across N devices, no redundancy
//! - [`RaidProfile::Raid1`]   — two copies on different devices
//!
//! # Structures
//!
//! - [`RaidProfile`]    — allocation profile selector
//! - [`SpaceType`]      — DATA / METADATA / SYSTEM flag
//! - [`Stripe`]         — (device_id, physical_offset, length) triple
//! - [`Chunk`]          — logical → physical mapping with RAID metadata
//! - [`BlockGroup`]     — per-chunk free space accounting
//! - [`SpaceInfo`]      — per-type aggregate accounting
//! - [`ChunkAllocator`] — top-level allocator state machine

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────────────

/// Default chunk size: 64 MiB.
const DEFAULT_CHUNK_SIZE: u64 = 64 * 1024 * 1024;

/// Minimum chunk size: 1 MiB.
const MIN_CHUNK_SIZE: u64 = 1024 * 1024;

/// Maximum stripes per chunk (RAID-6 uses up to 64+2).
const MAX_STRIPES: usize = 16;

/// Maximum chunks tracked by the allocator.
const MAX_CHUNKS: usize = 128;

/// Maximum block groups (one per chunk).
const MAX_BLOCK_GROUPS: usize = MAX_CHUNKS;

/// Maximum devices in the btrfs volume.
const MAX_DEVICES: usize = 16;

/// Maximum free-space extents per block group (simplified).
const MAX_FREE_EXTENTS: usize = 64;

/// Logical address of the first user-space chunk (first 1 MiB reserved).
const FIRST_CHUNK_OFFSET: u64 = 1024 * 1024;

// ── RaidProfile ─────────────────────────────────────────────────────────────

/// Btrfs RAID/redundancy profile for a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidProfile {
    /// Single copy on one device.
    Single,
    /// Two copies on the same device (mirrored writes).
    Dup,
    /// Striped across multiple devices with no redundancy (RAID-0).
    Raid0,
    /// Two copies on different devices (RAID-1).
    Raid1,
}

impl RaidProfile {
    /// Number of stripes required for this profile.
    pub fn min_stripes(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Dup => 1, // two logical copies → same device stripe
            Self::Raid0 => 2,
            Self::Raid1 => 2,
        }
    }

    /// Redundancy factor: how many copies of data are kept.
    pub fn copies(self) -> usize {
        match self {
            Self::Single | Self::Raid0 => 1,
            Self::Dup | Self::Raid1 => 2,
        }
    }

    /// Raw u64 flag bits (matches on-disk BTRFS_BLOCK_GROUP_* constants).
    pub fn flags(self) -> u64 {
        match self {
            Self::Single => 0,
            Self::Dup => 1 << 4,
            Self::Raid0 => 1 << 3,
            Self::Raid1 => 1 << 5,
        }
    }
}

// ── SpaceType ───────────────────────────────────────────────────────────────

/// Logical space usage type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceType {
    /// Stores regular file data.
    Data,
    /// Stores B-tree nodes and internal metadata.
    Metadata,
    /// Stores the chunk tree and device items.
    System,
}

impl SpaceType {
    /// On-disk flag bits (BTRFS_BLOCK_GROUP_DATA/METADATA/SYSTEM).
    pub fn flags(self) -> u64 {
        match self {
            Self::Data => 1 << 0,
            Self::Metadata => 1 << 2,
            Self::System => 1 << 1,
        }
    }
}

// ── Stripe ──────────────────────────────────────────────────────────────────

/// A single physical stripe: maps logical data to a device offset.
#[derive(Debug, Clone, Copy)]
pub struct Stripe {
    /// Device identifier (index into the device table).
    pub dev_id: u32,
    /// Physical byte offset on the device.
    pub physical: u64,
    /// Length of this stripe in bytes.
    pub length: u64,
    /// Whether this stripe slot is occupied.
    pub in_use: bool,
}

impl Stripe {
    /// Create an empty stripe slot.
    pub const fn empty() -> Self {
        Self {
            dev_id: 0,
            physical: 0,
            length: 0,
            in_use: false,
        }
    }

    /// Create a new stripe.
    pub const fn new(dev_id: u32, physical: u64, length: u64) -> Self {
        Self {
            dev_id,
            physical,
            length,
            in_use: true,
        }
    }
}

impl Default for Stripe {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Chunk ────────────────────────────────────────────────────────────────────

/// A chunk: logical byte range → physical stripes mapping.
#[derive(Debug)]
pub struct Chunk {
    /// Logical start address of this chunk.
    pub logical: u64,
    /// Total logical length in bytes.
    pub length: u64,
    /// RAID/redundancy profile.
    pub profile: RaidProfile,
    /// Space type (data, metadata, system).
    pub space_type: SpaceType,
    /// Physical stripes.
    pub stripes: [Stripe; MAX_STRIPES],
    /// Number of valid stripes.
    pub stripe_count: usize,
    /// Whether this chunk slot is occupied.
    pub in_use: bool,
    /// Transaction generation that created this chunk.
    pub generation: u64,
}

impl Chunk {
    /// Create an empty chunk slot.
    pub fn empty() -> Self {
        Self {
            logical: 0,
            length: 0,
            profile: RaidProfile::Single,
            space_type: SpaceType::Data,
            stripes: [const { Stripe::empty() }; MAX_STRIPES],
            stripe_count: 0,
            in_use: false,
            generation: 0,
        }
    }

    /// Create a new chunk.
    pub fn new(
        logical: u64,
        length: u64,
        profile: RaidProfile,
        space_type: SpaceType,
        generation: u64,
    ) -> Self {
        Self {
            logical,
            length,
            profile,
            space_type,
            stripes: [const { Stripe::empty() }; MAX_STRIPES],
            stripe_count: 0,
            in_use: true,
            generation,
        }
    }

    /// Append a physical stripe to this chunk.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the stripe array is full.
    pub fn add_stripe(&mut self, stripe: Stripe) -> Result<()> {
        if self.stripe_count >= MAX_STRIPES {
            return Err(Error::OutOfMemory);
        }
        self.stripes[self.stripe_count] = stripe;
        self.stripe_count += 1;
        Ok(())
    }

    /// Translate a logical offset within this chunk to a physical
    /// `(dev_id, physical_offset)` pair.
    ///
    /// For RAID-0 the offset is striped across all stripes.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `offset >= self.length` or no stripes exist.
    pub fn map_to_physical(&self, offset: u64) -> Result<(u32, u64)> {
        if offset >= self.length || self.stripe_count == 0 {
            return Err(Error::InvalidArgument);
        }
        match self.profile {
            RaidProfile::Single | RaidProfile::Dup => {
                let s = &self.stripes[0];
                Ok((s.dev_id, s.physical + offset))
            }
            RaidProfile::Raid0 => {
                let stripe_size = self.length / self.stripe_count as u64;
                let idx = (offset / stripe_size) as usize % self.stripe_count;
                let stripe_off = offset % stripe_size;
                let s = &self.stripes[idx];
                Ok((s.dev_id, s.physical + stripe_off))
            }
            RaidProfile::Raid1 => {
                // Both stripes hold the same data; use the first for reads.
                let s = &self.stripes[0];
                Ok((s.dev_id, s.physical + offset))
            }
        }
    }
}

// ── BlockGroup ───────────────────────────────────────────────────────────────

/// A single block group aligned to one chunk.
///
/// Tracks free space within the chunk as a list of (start, length) extents.
pub struct BlockGroup {
    /// Logical start address (matches owning chunk's `logical`).
    pub start: u64,
    /// Total size in bytes.
    pub size: u64,
    /// Space type.
    pub space_type: SpaceType,
    /// RAID profile.
    pub profile: RaidProfile,
    /// Free bytes remaining.
    pub free_bytes: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
    /// Index of the owning chunk in the chunk table.
    pub chunk_idx: usize,
    /// Free extents: (start, length) pairs.
    pub free_extents: [(u64, u64); MAX_FREE_EXTENTS],
    /// Number of valid free extents.
    pub free_extent_count: usize,
}

impl BlockGroup {
    /// Create an empty block group slot.
    pub fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            space_type: SpaceType::Data,
            profile: RaidProfile::Single,
            free_bytes: 0,
            in_use: false,
            chunk_idx: 0,
            free_extents: [(0, 0); MAX_FREE_EXTENTS],
            free_extent_count: 0,
        }
    }

    /// Create a new block group backed by chunk at `chunk_idx`.
    pub fn new(
        start: u64,
        size: u64,
        space_type: SpaceType,
        profile: RaidProfile,
        chunk_idx: usize,
    ) -> Self {
        let mut bg = Self {
            start,
            size,
            space_type,
            profile,
            free_bytes: size,
            in_use: true,
            chunk_idx,
            free_extents: [(0, 0); MAX_FREE_EXTENTS],
            free_extent_count: 0,
        };
        // Initially one big free extent.
        bg.free_extents[0] = (start, size);
        bg.free_extent_count = 1;
        bg
    }

    /// Allocate `num_bytes` from this block group using first-fit.
    ///
    /// Returns the logical start address of the allocated range.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free extent can satisfy the request.
    pub fn alloc(&mut self, num_bytes: u64) -> Result<u64> {
        let pos = self.free_extents[..self.free_extent_count]
            .iter()
            .position(|&(_, len)| len >= num_bytes)
            .ok_or(Error::OutOfMemory)?;
        let (ext_start, ext_len) = self.free_extents[pos];
        let alloc_start = ext_start;
        if ext_len == num_bytes {
            // Remove this extent.
            self.free_extents
                .copy_within(pos + 1..self.free_extent_count, pos);
            self.free_extent_count -= 1;
        } else {
            self.free_extents[pos] = (ext_start + num_bytes, ext_len - num_bytes);
        }
        self.free_bytes = self.free_bytes.saturating_sub(num_bytes);
        Ok(alloc_start)
    }

    /// Return `num_bytes` starting at `start` to free space.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the free-extent array is full.
    /// - `InvalidArgument` if the range is outside this block group.
    pub fn free_range(&mut self, start: u64, num_bytes: u64) -> Result<()> {
        if start < self.start || start + num_bytes > self.start + self.size {
            return Err(Error::InvalidArgument);
        }
        if self.free_extent_count >= MAX_FREE_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        self.free_extents[self.free_extent_count] = (start, num_bytes);
        self.free_extent_count += 1;
        self.free_bytes = self.free_bytes.saturating_add(num_bytes);
        Ok(())
    }
}

// ── SpaceInfo ────────────────────────────────────────────────────────────────

/// Aggregate accounting for one [`SpaceType`].
#[derive(Debug, Clone, Copy)]
pub struct SpaceInfo {
    /// Space type this record covers.
    pub space_type: SpaceType,
    /// Total bytes across all chunks of this type.
    pub total_bytes: u64,
    /// Bytes currently allocated (used by extents).
    pub bytes_used: u64,
    /// Bytes pinned (delalloc / reserved).
    pub bytes_pinned: u64,
    /// Whether this info slot is populated.
    pub in_use: bool,
}

impl SpaceInfo {
    /// Create an empty info slot.
    pub const fn empty() -> Self {
        Self {
            space_type: SpaceType::Data,
            total_bytes: 0,
            bytes_used: 0,
            bytes_pinned: 0,
            in_use: false,
        }
    }

    /// Bytes available for new allocations.
    pub fn available(&self) -> u64 {
        self.total_bytes
            .saturating_sub(self.bytes_used)
            .saturating_sub(self.bytes_pinned)
    }
}

// ── ChunkAllocator ───────────────────────────────────────────────────────────

/// Top-level btrfs chunk allocator.
///
/// Manages the chunk table, block group table, per-type space accounting, and
/// device free-space tracking.
pub struct ChunkAllocator {
    /// Chunk table.
    chunks: [Chunk; MAX_CHUNKS],
    /// Number of allocated chunks.
    chunk_count: usize,
    /// Block group table (parallel to chunks).
    block_groups: [BlockGroup; MAX_BLOCK_GROUPS],
    /// Number of populated block groups.
    bg_count: usize,
    /// Per-type space accounting (DATA, METADATA, SYSTEM).
    space_info: [SpaceInfo; 3],
    /// Next logical address to hand out for a new chunk.
    next_logical: u64,
    /// Per-device free bytes (simplified: one entry per device ID).
    device_free: [u64; MAX_DEVICES],
    /// Transaction generation.
    generation: u64,
}

impl ChunkAllocator {
    /// Create a new allocator, registering `num_devices` devices each with
    /// `device_size` bytes.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `num_devices` exceeds [`MAX_DEVICES`].
    pub fn new(num_devices: usize, device_size: u64) -> Result<Self> {
        if num_devices > MAX_DEVICES {
            return Err(Error::InvalidArgument);
        }
        let mut alloc = Self {
            chunks: core::array::from_fn(|_| Chunk::empty()),
            chunk_count: 0,
            block_groups: core::array::from_fn(|_| BlockGroup::empty()),
            bg_count: 0,
            space_info: [SpaceInfo::empty(); 3],
            next_logical: FIRST_CHUNK_OFFSET,
            device_free: [0u64; MAX_DEVICES],
            generation: 1,
        };
        for (i, free) in alloc.device_free[..num_devices].iter_mut().enumerate() {
            *free = device_size;
            let _ = i;
        }
        // Initialise space_info slots.
        alloc.space_info[0] = SpaceInfo {
            space_type: SpaceType::Data,
            ..SpaceInfo::empty()
        };
        alloc.space_info[0].in_use = true;
        alloc.space_info[1] = SpaceInfo {
            space_type: SpaceType::Metadata,
            ..SpaceInfo::empty()
        };
        alloc.space_info[1].in_use = true;
        alloc.space_info[2] = SpaceInfo {
            space_type: SpaceType::System,
            ..SpaceInfo::empty()
        };
        alloc.space_info[2].in_use = true;
        Ok(alloc)
    }

    /// Allocate a new chunk of the given type and RAID profile.
    ///
    /// Selects device(s) with sufficient free space, creates the chunk and
    /// a matching block group.
    ///
    /// Returns the logical start address of the new chunk.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the chunk or block-group table is full, or if not
    ///   enough device space exists.
    /// - `NotImplemented` if `profile` requires more devices than are
    ///   available.
    pub fn alloc_chunk(
        &mut self,
        space_type: SpaceType,
        profile: RaidProfile,
        size: u64,
    ) -> Result<u64> {
        let size = size.max(MIN_CHUNK_SIZE);
        if self.chunk_count >= MAX_CHUNKS || self.bg_count >= MAX_BLOCK_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let copies = profile.copies() as u64;
        let per_dev_bytes = size * copies / profile.min_stripes() as u64;

        // Find enough devices with free space.
        let mut chosen = [0u32; MAX_STRIPES];
        let mut chosen_count = 0usize;
        let need = profile.min_stripes();
        for (dev_id, &free) in self.device_free.iter().enumerate() {
            if free >= per_dev_bytes && chosen_count < need {
                chosen[chosen_count] = dev_id as u32;
                chosen_count += 1;
            }
        }
        if chosen_count < need {
            return Err(Error::OutOfMemory);
        }

        let logical = self.next_logical;
        self.next_logical = self.next_logical.saturating_add(size);

        let mut chunk = Chunk::new(logical, size, profile, space_type, self.generation);

        // Build stripes.
        let stripe_len = match profile {
            RaidProfile::Raid0 => size / chosen_count as u64,
            _ => size,
        };
        for (i, &dev_id) in chosen[..chosen_count].iter().enumerate() {
            let phys = self.device_free[dev_id as usize] - per_dev_bytes + i as u64 * stripe_len;
            chunk.add_stripe(Stripe::new(dev_id, phys, stripe_len))?;
            self.device_free[dev_id as usize] =
                self.device_free[dev_id as usize].saturating_sub(per_dev_bytes);
        }
        // Dup: duplicate the first stripe on the same device.
        if profile == RaidProfile::Dup && chosen_count == 1 {
            let s = chunk.stripes[0];
            chunk.add_stripe(Stripe::new(s.dev_id, s.physical + size, size))?;
        }

        let chunk_idx = self.chunk_count;
        self.chunks[chunk_idx] = chunk;
        self.chunk_count += 1;

        let bg = BlockGroup::new(logical, size, space_type, profile, chunk_idx);
        self.block_groups[self.bg_count] = bg;
        self.bg_count += 1;

        // Update space accounting.
        self.update_space_info(space_type, size, 0);
        Ok(logical)
    }

    /// Allocate `num_bytes` from a block group of type `space_type`.
    ///
    /// Returns the logical start address of the allocation.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no block group can satisfy the request.
    pub fn alloc_bytes(&mut self, space_type: SpaceType, num_bytes: u64) -> Result<u64> {
        let pos = self.block_groups[..self.bg_count]
            .iter()
            .position(|bg| bg.in_use && bg.space_type == space_type && bg.free_bytes >= num_bytes)
            .ok_or(Error::OutOfMemory)?;
        let start = self.block_groups[pos].alloc(num_bytes)?;
        self.update_space_used(space_type, num_bytes as i64);
        Ok(start)
    }

    /// Return `num_bytes` at logical `start` to its block group.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no block group covers `start`.
    pub fn free_bytes(&mut self, start: u64, num_bytes: u64) -> Result<()> {
        let pos = self.block_groups[..self.bg_count]
            .iter()
            .position(|bg| bg.in_use && start >= bg.start && start < bg.start + bg.size)
            .ok_or(Error::NotFound)?;
        self.block_groups[pos].free_range(start, num_bytes)?;
        let stype = self.block_groups[pos].space_type;
        self.update_space_used(stype, -(num_bytes as i64));
        Ok(())
    }

    /// Look up the chunk that covers logical address `logical`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no chunk covers `logical`.
    pub fn lookup_chunk(&self, logical: u64) -> Result<&Chunk> {
        self.chunks[..self.chunk_count]
            .iter()
            .find(|c| c.in_use && logical >= c.logical && logical < c.logical + c.length)
            .ok_or(Error::NotFound)
    }

    /// Map a logical address to `(dev_id, physical_offset)`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no chunk covers `logical`.
    /// - `InvalidArgument` from the chunk's stripe mapping.
    pub fn map_logical(&self, logical: u64) -> Result<(u32, u64)> {
        let chunk = self.lookup_chunk(logical)?;
        chunk.map_to_physical(logical - chunk.logical)
    }

    /// Return aggregate space info for a given type.
    pub fn space_info(&self, space_type: SpaceType) -> Option<&SpaceInfo> {
        self.space_info
            .iter()
            .find(|si| si.in_use && si.space_type == space_type)
    }

    /// Total number of allocated chunks.
    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    fn update_space_info(&mut self, stype: SpaceType, add_total: u64, add_used: u64) {
        for si in self.space_info.iter_mut() {
            if si.in_use && si.space_type == stype {
                si.total_bytes = si.total_bytes.saturating_add(add_total);
                si.bytes_used = si.bytes_used.saturating_add(add_used);
                return;
            }
        }
    }

    fn update_space_used(&mut self, stype: SpaceType, delta: i64) {
        for si in self.space_info.iter_mut() {
            if si.in_use && si.space_type == stype {
                if delta >= 0 {
                    si.bytes_used = si.bytes_used.saturating_add(delta as u64);
                } else {
                    si.bytes_used = si.bytes_used.saturating_sub((-delta) as u64);
                }
                return;
            }
        }
    }
}
