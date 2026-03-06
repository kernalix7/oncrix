// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory Tagging Extension (MTE) support.
//!
//! Memory tagging assigns a small tag (typically 4 bits) to every
//! aligned granule of memory. Pointers also carry a tag in their upper
//! bits. On every memory access the hardware (or software checker)
//! compares the pointer tag with the memory tag and faults on mismatch.
//! This catches use-after-free, buffer overflow, and similar bugs with
//! low overhead.
//!
//! # Design
//!
//! ```text
//! Pointer:   [tag:4][address:60]
//! Memory:    [granule 0 → tag 0][granule 1 → tag 1] ...
//!
//! Access check: pointer_tag == memory_tag → OK, else → fault
//! ```
//!
//! # Key Types
//!
//! - [`MemTag`] — a 4-bit memory tag value
//! - [`TagGranule`] — one tagged granule of memory
//! - [`TagTable`] — tag storage for a contiguous memory region
//! - [`MteConfig`] — MTE configuration parameters
//!
//! Reference: ARM MTE specification, Linux `arch/arm64/mm/mte.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Size of a tag granule in bytes (16 bytes for ARM MTE).
const GRANULE_SIZE: usize = 16;

/// Number of tag bits per granule.
const TAG_BITS: u32 = 4;

/// Maximum tag value.
const MAX_TAG: u8 = (1 << TAG_BITS) - 1;

/// Maximum number of granules in a tag table.
const MAX_GRANULES: usize = 16384;

/// Tag value indicating "match-all" (ignores comparison).
const MATCH_ALL_TAG: u8 = 0;

// -------------------------------------------------------------------
// MemTag
// -------------------------------------------------------------------

/// A 4-bit memory tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemTag(u8);

impl MemTag {
    /// Creates a new tag from a raw value (masked to 4 bits).
    pub const fn new(raw: u8) -> Self {
        Self(raw & MAX_TAG)
    }

    /// Returns the match-all tag (value 0).
    pub const fn match_all() -> Self {
        Self(MATCH_ALL_TAG)
    }

    /// Returns the raw tag value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Returns `true` if this tag matches another (including match-all).
    pub const fn matches(self, other: Self) -> bool {
        self.0 == MATCH_ALL_TAG || other.0 == MATCH_ALL_TAG || self.0 == other.0
    }
}

impl Default for MemTag {
    fn default() -> Self {
        Self::match_all()
    }
}

// -------------------------------------------------------------------
// TagGranule
// -------------------------------------------------------------------

/// A single tagged granule entry.
#[derive(Debug, Clone, Copy)]
pub struct TagGranule {
    /// The assigned tag.
    tag: MemTag,
    /// Whether this granule is allocated.
    allocated: bool,
}

impl TagGranule {
    /// Creates a new unallocated granule.
    pub const fn new() -> Self {
        Self {
            tag: MemTag::new(0),
            allocated: false,
        }
    }

    /// Creates an allocated granule with the given tag.
    pub const fn with_tag(tag: MemTag) -> Self {
        Self {
            tag,
            allocated: true,
        }
    }

    /// Returns the tag.
    pub const fn tag(&self) -> MemTag {
        self.tag
    }

    /// Returns whether the granule is allocated.
    pub const fn is_allocated(&self) -> bool {
        self.allocated
    }
}

impl Default for TagGranule {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MteMode
// -------------------------------------------------------------------

/// MTE checking mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MteMode {
    /// MTE disabled — no tag checks.
    Disabled,
    /// Synchronous mode — fault immediately on mismatch.
    Sync,
    /// Asynchronous mode — accumulate mismatches, report later.
    Async,
    /// Asymmetric mode — sync for reads, async for writes.
    Asymmetric,
}

impl Default for MteMode {
    fn default() -> Self {
        Self::Disabled
    }
}

// -------------------------------------------------------------------
// MteConfig
// -------------------------------------------------------------------

/// Configuration for the MTE subsystem.
#[derive(Debug, Clone, Copy)]
pub struct MteConfig {
    /// Checking mode.
    pub mode: MteMode,
    /// Set of tags excluded from random generation (bitmask).
    pub exclude_mask: u16,
    /// Whether to tag kernel allocations.
    pub tag_kernel: bool,
    /// Whether to tag user allocations.
    pub tag_user: bool,
}

impl MteConfig {
    /// Creates a default configuration (disabled).
    pub const fn new() -> Self {
        Self {
            mode: MteMode::Disabled,
            exclude_mask: 0,
            tag_kernel: false,
            tag_user: false,
        }
    }

    /// Returns `true` if MTE is active.
    pub const fn is_active(&self) -> bool {
        !matches!(self.mode, MteMode::Disabled)
    }

    /// Returns `true` if a tag value is excluded from random generation.
    pub const fn is_excluded(&self, tag: u8) -> bool {
        (self.exclude_mask >> (tag & MAX_TAG)) & 1 != 0
    }
}

impl Default for MteConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// TagTable
// -------------------------------------------------------------------

/// Tag storage for a contiguous memory region.
///
/// Stores one tag per granule. The region starts at a base address
/// and covers `count` granules of `GRANULE_SIZE` bytes each.
pub struct TagTable {
    /// Tag storage.
    tags: [TagGranule; MAX_GRANULES],
    /// Base address of the region.
    base: u64,
    /// Number of active granules.
    count: usize,
    /// Configuration.
    config: MteConfig,
    /// Running counter for pseudo-random tag generation.
    rng_state: u32,
}

impl TagTable {
    /// Creates a new tag table for the given base address and size.
    pub const fn new() -> Self {
        Self {
            tags: [const { TagGranule::new() }; MAX_GRANULES],
            base: 0,
            count: 0,
            config: MteConfig::new(),
            rng_state: 0x12345678,
        }
    }

    /// Initializes the table for a region.
    pub fn init(&mut self, base: u64, size: usize, config: MteConfig) -> Result<()> {
        let granules = size / GRANULE_SIZE;
        if granules > MAX_GRANULES {
            return Err(Error::InvalidArgument);
        }
        if (base as usize) % GRANULE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        self.base = base;
        self.count = granules;
        self.config = config;
        Ok(())
    }

    /// Returns the number of granules.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Converts an address to a granule index.
    fn addr_to_index(&self, addr: u64) -> Result<usize> {
        if addr < self.base {
            return Err(Error::InvalidArgument);
        }
        let offset = (addr - self.base) as usize;
        let idx = offset / GRANULE_SIZE;
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(idx)
    }

    /// Generates a pseudo-random non-excluded tag.
    fn next_random_tag(&mut self) -> MemTag {
        loop {
            // Simple xorshift.
            self.rng_state ^= self.rng_state << 13;
            self.rng_state ^= self.rng_state >> 17;
            self.rng_state ^= self.rng_state << 5;
            let tag = (self.rng_state as u8) & MAX_TAG;
            if tag != 0 && !self.config.is_excluded(tag) {
                return MemTag::new(tag);
            }
        }
    }

    /// Tags a range of memory starting at `addr` for `size` bytes.
    pub fn tag_range(&mut self, addr: u64, size: usize) -> Result<MemTag> {
        let start_idx = self.addr_to_index(addr)?;
        let granules = (size + GRANULE_SIZE - 1) / GRANULE_SIZE;
        if start_idx + granules > self.count {
            return Err(Error::InvalidArgument);
        }
        let tag = self.next_random_tag();
        for i in start_idx..(start_idx + granules) {
            self.tags[i] = TagGranule::with_tag(tag);
        }
        Ok(tag)
    }

    /// Clears tags for a range (e.g., on free).
    pub fn clear_range(&mut self, addr: u64, size: usize) -> Result<()> {
        let start_idx = self.addr_to_index(addr)?;
        let granules = (size + GRANULE_SIZE - 1) / GRANULE_SIZE;
        if start_idx + granules > self.count {
            return Err(Error::InvalidArgument);
        }
        for i in start_idx..(start_idx + granules) {
            self.tags[i] = TagGranule::new();
        }
        Ok(())
    }

    /// Checks a tagged pointer access against the memory tag.
    pub fn check_access(&self, ptr_tag: MemTag, addr: u64) -> Result<()> {
        if !self.config.is_active() {
            return Ok(());
        }
        let idx = self.addr_to_index(addr)?;
        let mem_tag = self.tags[idx].tag();
        if ptr_tag.matches(mem_tag) {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// Returns the tag assigned to an address.
    pub fn get_tag(&self, addr: u64) -> Result<MemTag> {
        let idx = self.addr_to_index(addr)?;
        Ok(self.tags[idx].tag())
    }
}

impl Default for TagTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a tag table for a memory region with the given config.
pub fn create_tag_table(base: u64, size: usize, config: MteConfig) -> Result<TagTable> {
    let mut table = TagTable::new();
    table.init(base, size, config)?;
    Ok(table)
}

/// Tags a freshly allocated region and returns the assigned pointer tag.
pub fn tag_allocation(table: &mut TagTable, addr: u64, size: usize) -> Result<MemTag> {
    table.tag_range(addr, size)
}

/// Checks a pointer access against memory tags.
pub fn check_tagged_access(table: &TagTable, ptr_tag: MemTag, addr: u64) -> Result<()> {
    table.check_access(ptr_tag, addr)
}
