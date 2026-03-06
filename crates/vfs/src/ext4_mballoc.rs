// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 multiblock allocator (mballoc).
//!
//! Implements the ext4 block allocation subsystem with buddy bitmaps,
//! preallocation windows, and goal-oriented best-fit search strategies.
//!
//! # Design
//!
//! - [`BlockGroupDesc`] — block group descriptor (free counts, bitmaps)
//! - [`BuddyBitmap`] — power-of-2 buddy system (order 0..=13)
//! - [`PreallocSpace`] — per-inode and locality-group preallocation windows
//! - [`AllocRequest`] — allocation request with goal, length, and flags
//! - [`MballocState`] — full allocator state: groups + prealloc table
//!
//! # Allocation Strategies
//!
//! 1. **Prealloc hit** — check per-inode or locality-group PA first
//! 2. **Goal search** — try exact goal block / goal group buddy tree
//! 3. **Best-fit** — scan groups for smallest adequate free run
//! 4. **Fallback** — sequential scan across all groups

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum buddy order (2^13 = 8192 blocks per chunk).
const MAX_ORDER: usize = 14;

/// Maximum block groups tracked by this allocator instance.
const MAX_BLOCK_GROUPS: usize = 64;

/// Maximum simultaneous prealloc spaces (per-inode + locality group).
const MAX_PREALLOC: usize = 128;

/// Blocks per group (standard ext4: 32768).
const BLOCKS_PER_GROUP: u32 = 32768;

/// Buddy bitmap storage words per order level (order-0 = 1 bit per block).
const BITMAP_WORDS: usize = BLOCKS_PER_GROUP as usize / 64;

// ── Flags ───────────────────────────────────────────────────────────────────

/// Allocation hint: try to place blocks near the goal.
pub const ALLOC_HINT: u32 = 1 << 0;

/// Allocation hint: goal block must be exactly honored.
pub const ALLOC_EXACT: u32 = 1 << 1;

/// Allocation hint: delayed allocation — reserve accounting only.
pub const ALLOC_DELALLOC: u32 = 1 << 2;

/// Block group flag: inode table needs initialisation.
pub const BG_INODE_UNINIT: u16 = 1 << 0;

/// Block group flag: block bitmap needs initialisation.
pub const BG_BLOCK_UNINIT: u16 = 1 << 1;

/// Block group flag: inode bitmap needs initialisation.
pub const BG_INODE_BITMAP_CORRUPT: u16 = 1 << 2;

// ── BlockGroupDesc ───────────────────────────────────────────────────────────

/// On-disk (in-memory mirror) block group descriptor.
#[derive(Debug, Clone, Copy)]
pub struct BlockGroupDesc {
    /// Physical block number of the block bitmap.
    pub block_bitmap: u64,
    /// Physical block number of the inode bitmap.
    pub inode_bitmap: u64,
    /// Physical block number of the inode table start.
    pub inode_table: u64,
    /// Number of free blocks in this group.
    pub free_blocks_count: u32,
    /// Number of free inodes in this group.
    pub free_inodes_count: u32,
    /// Number of directories in this group.
    pub used_dirs_count: u32,
    /// Group flags (BG_* constants).
    pub flags: u16,
    /// Checksum of the group descriptor.
    pub checksum: u16,
}

impl BlockGroupDesc {
    /// Create a new, fully-free block group descriptor.
    pub const fn new(block_bitmap: u64, inode_bitmap: u64, inode_table: u64) -> Self {
        Self {
            block_bitmap,
            inode_bitmap,
            inode_table,
            free_blocks_count: BLOCKS_PER_GROUP,
            free_inodes_count: 0,
            used_dirs_count: 0,
            flags: BG_BLOCK_UNINIT | BG_INODE_UNINIT,
            checksum: 0,
        }
    }

    /// Returns true if the block bitmap is marked uninitialised.
    pub fn is_block_uninit(&self) -> bool {
        self.flags & BG_BLOCK_UNINIT != 0
    }

    /// Mark the block bitmap as initialised.
    pub fn mark_block_init(&mut self) {
        self.flags &= !BG_BLOCK_UNINIT;
    }
}

// ── BuddyBitmap ─────────────────────────────────────────────────────────────

/// Buddy bitmap for a single block group.
///
/// Order k stores one bit per 2^k-block aligned chunk.  Order 0 is the
/// raw free-block bitmap; higher orders track merged buddy pairs.
pub struct BuddyBitmap {
    /// Bitmap words for each order (order 0 uses all BITMAP_WORDS words).
    /// order k uses BITMAP_WORDS >> k words.
    data: [[u64; BITMAP_WORDS]; MAX_ORDER],
}

impl BuddyBitmap {
    /// Create an all-free buddy bitmap.
    pub fn new_free() -> Self {
        Self {
            data: [[u64::MAX; BITMAP_WORDS]; MAX_ORDER],
        }
    }

    /// Create an all-used buddy bitmap.
    pub fn new_used() -> Self {
        Self {
            data: [[0u64; BITMAP_WORDS]; MAX_ORDER],
        }
    }

    /// Test whether the block at `block` is free at order 0.
    pub fn is_free(&self, block: u32) -> bool {
        let idx = (block as usize) / 64;
        let bit = (block as usize) % 64;
        if idx >= BITMAP_WORDS {
            return false;
        }
        self.data[0][idx] & (1u64 << bit) != 0
    }

    /// Mark a run of `len` blocks starting at `start` as allocated.
    pub fn mark_allocated(&mut self, start: u32, len: u32) {
        for b in start..start.saturating_add(len) {
            let idx = (b as usize) / 64;
            let bit = (b as usize) % 64;
            if idx < BITMAP_WORDS {
                self.data[0][idx] &= !(1u64 << bit);
            }
        }
        self.rebuild_orders(start, len);
    }

    /// Mark a run of `len` blocks starting at `start` as free.
    pub fn mark_free(&mut self, start: u32, len: u32) {
        for b in start..start.saturating_add(len) {
            let idx = (b as usize) / 64;
            let bit = (b as usize) % 64;
            if idx < BITMAP_WORDS {
                self.data[0][idx] |= 1u64 << bit;
            }
        }
        self.rebuild_orders(start, len);
    }

    /// Find the first free run of at least `needed` blocks at or after `hint`.
    /// Returns the starting block number, or `None` if no run found.
    pub fn find_free_run(&self, hint: u32, needed: u32) -> Option<u32> {
        let start_idx = (hint as usize) / 64;
        let total_bits = BITMAP_WORDS * 64;

        let mut run_start = 0usize;
        let mut run_len = 0u32;

        for bit_pos in (start_idx * 64)..total_bits {
            let idx = bit_pos / 64;
            let bit = bit_pos % 64;
            if self.data[0][idx] & (1u64 << bit) != 0 {
                if run_len == 0 {
                    run_start = bit_pos;
                }
                run_len += 1;
                if run_len >= needed {
                    return Some(run_start as u32);
                }
            } else {
                run_len = 0;
            }
        }
        // Wrap-around: search from block 0 up to hint
        run_len = 0;
        for bit_pos in 0..(start_idx * 64).min(total_bits) {
            let idx = bit_pos / 64;
            let bit = bit_pos % 64;
            if self.data[0][idx] & (1u64 << bit) != 0 {
                if run_len == 0 {
                    run_start = bit_pos;
                }
                run_len += 1;
                if run_len >= needed {
                    return Some(run_start as u32);
                }
            } else {
                run_len = 0;
            }
        }
        None
    }

    /// Find a free block at highest buddy order fitting `needed` blocks.
    pub fn find_buddy_run(&self, needed: u32) -> Option<u32> {
        // Determine highest suitable order
        let order = needed.next_power_of_two().trailing_zeros() as usize;
        let order = order.min(MAX_ORDER - 1);

        let words = BITMAP_WORDS >> order;
        for w in 0..words {
            if self.data[order][w] != 0 {
                let bit = self.data[order][w].trailing_zeros() as usize;
                let block = ((w * 64) + bit) * (1 << order);
                return Some(block as u32);
            }
        }
        None
    }

    /// Rebuild higher-order buddy bits after a change in [start, start+len).
    fn rebuild_orders(&mut self, start: u32, len: u32) {
        let first_word = (start as usize) / 64;
        let last_word = ((start + len) as usize).saturating_sub(1) / 64;

        for order in 1..MAX_ORDER {
            let chunk = 1usize << order;
            let words = BITMAP_WORDS >> order;
            // Which higher-order words overlap the changed region?
            let fw = (first_word * 64 / chunk).min(words.saturating_sub(1));
            let lw = ((last_word * 64 + 63) / chunk).min(words.saturating_sub(1));

            for w in fw..=lw {
                // Each higher word maps 64 chunks of size `chunk` blocks.
                let mut new_word = 0u64;
                for b in 0..64u64 {
                    let block_start = (w * 64 + b as usize) * chunk;
                    if block_start + chunk > BLOCKS_PER_GROUP as usize {
                        break;
                    }
                    // A buddy chunk is "free" if ALL sub-blocks are free.
                    let sub_words = chunk / 64;
                    let base = block_start / 64;
                    let all_free = (0..sub_words.max(1)).all(|sw| {
                        if sub_words == 0 {
                            // chunk < 64: check bits within one word
                            let mask = ((1u64 << chunk) - 1) << (block_start % 64);
                            self.data[0][base] & mask == mask
                        } else {
                            self.data[0][base + sw] == u64::MAX
                        }
                    });
                    if all_free {
                        new_word |= 1u64 << b;
                    }
                }
                if w < self.data[order].len() {
                    self.data[order][w] = new_word;
                }
            }
        }
    }
}

// ── PreallocSpace ────────────────────────────────────────────────────────────

/// Type of preallocation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaType {
    /// Per-inode preallocation.
    PerInode,
    /// Locality group preallocation (shared by nearby inodes).
    LocalityGroup,
}

/// A preallocation window: reserved physical blocks not yet used.
#[derive(Debug, Clone, Copy)]
pub struct PreallocSpace {
    /// Inode number that owns this PA (0 = locality group).
    pub ino: u64,
    /// Physical block number of the start of the PA window.
    pub pstart: u64,
    /// Logical block offset within the inode.
    pub lstart: u64,
    /// Total length of the PA window in blocks.
    pub len: u32,
    /// Remaining free blocks in the window.
    pub free: u32,
    /// Block group index.
    pub group: u32,
    /// Prealloc type.
    pub pa_type: PaType,
    /// Whether this PA has been discarded.
    pub discarded: bool,
}

impl PreallocSpace {
    /// Create a new per-inode preallocation space.
    pub fn new_inode(ino: u64, pstart: u64, lstart: u64, len: u32, group: u32) -> Self {
        Self {
            ino,
            pstart,
            lstart,
            len,
            free: len,
            group,
            pa_type: PaType::PerInode,
            discarded: false,
        }
    }

    /// Create a new locality-group preallocation space.
    pub fn new_locality(pstart: u64, lstart: u64, len: u32, group: u32) -> Self {
        Self {
            ino: 0,
            pstart,
            lstart,
            len,
            free: len,
            group,
            pa_type: PaType::LocalityGroup,
            discarded: false,
        }
    }

    /// Try to satisfy `needed` blocks from this PA.
    /// Returns the starting physical block if successful.
    pub fn try_alloc(&mut self, needed: u32) -> Option<u64> {
        if self.discarded || self.free < needed {
            return None;
        }
        let used = self.len - self.free;
        let pblock = self.pstart + used as u64;
        self.free -= needed;
        Some(pblock)
    }

    /// Mark this PA as discarded (inode closed or evicted).
    pub fn discard(&mut self) {
        self.discarded = true;
    }
}

// ── AllocRequest ─────────────────────────────────────────────────────────────

/// Block allocation request.
#[derive(Debug, Clone, Copy)]
pub struct AllocRequest {
    /// Inode number requesting blocks.
    pub ino: u64,
    /// Preferred physical block (goal block).
    pub goal: u64,
    /// Logical block offset in the inode.
    pub logical: u64,
    /// Number of blocks requested.
    pub len: u32,
    /// Allocation flags (ALLOC_HINT / ALLOC_EXACT / ALLOC_DELALLOC).
    pub flags: u32,
}

impl AllocRequest {
    /// Create a new allocation request with a hint.
    pub fn new(ino: u64, goal: u64, logical: u64, len: u32, flags: u32) -> Self {
        Self {
            ino,
            goal,
            logical,
            len,
            flags,
        }
    }

    /// Normalize `len` up to the next power of two for buddy allocation.
    pub fn normalized_len(&self) -> u32 {
        self.len.next_power_of_two()
    }

    /// Returns true if exact goal placement is required.
    pub fn is_exact(&self) -> bool {
        self.flags & ALLOC_EXACT != 0
    }

    /// Returns true if this is a delayed allocation (no physical blocks yet).
    pub fn is_delalloc(&self) -> bool {
        self.flags & ALLOC_DELALLOC != 0
    }
}

// ── AllocResult ──────────────────────────────────────────────────────────────

/// Result of a successful block allocation.
#[derive(Debug, Clone, Copy)]
pub struct AllocResult {
    /// Starting physical block number.
    pub pblock: u64,
    /// Number of blocks actually allocated.
    pub len: u32,
    /// Block group the allocation came from.
    pub group: u32,
}

// ── GroupState ───────────────────────────────────────────────────────────────

/// In-memory state for one block group.
struct GroupState {
    desc: BlockGroupDesc,
    buddy: BuddyBitmap,
    /// Group index.
    index: u32,
    /// True if the buddy bitmap has been loaded.
    loaded: bool,
}

impl GroupState {
    fn new(index: u32, desc: BlockGroupDesc) -> Self {
        Self {
            desc,
            buddy: BuddyBitmap::new_free(),
            index,
            loaded: false,
        }
    }

    /// Try to allocate `len` blocks with optional goal hint.
    fn alloc_blocks(&mut self, goal_block: u32, len: u32, exact: bool) -> Option<u32> {
        if self.desc.free_blocks_count < len {
            return None;
        }
        // Try exact goal first
        if exact {
            if self.buddy.is_free(goal_block) {
                let end = goal_block + len;
                let all_free = (goal_block..end).all(|b| self.buddy.is_free(b));
                if all_free {
                    self.buddy.mark_allocated(goal_block, len);
                    self.desc.free_blocks_count -= len;
                    return Some(goal_block);
                }
            }
            return None;
        }
        // Try buddy-based allocation for normalized len
        let norm_len = len.next_power_of_two();
        if let Some(start) = self.buddy.find_buddy_run(norm_len) {
            self.buddy.mark_allocated(start, len);
            self.desc.free_blocks_count -= len;
            return Some(start);
        }
        // Fallback: linear scan from goal
        if let Some(start) = self.buddy.find_free_run(goal_block, len) {
            self.buddy.mark_allocated(start, len);
            self.desc.free_blocks_count -= len;
            return Some(start);
        }
        None
    }

    /// Free `len` blocks starting at `start`.
    fn free_blocks(&mut self, start: u32, len: u32) {
        self.buddy.mark_free(start, len);
        self.desc.free_blocks_count += len;
    }
}

// ── MballocState ─────────────────────────────────────────────────────────────

/// ext4 multiblock allocator state.
pub struct MballocState {
    groups: [Option<GroupState>; MAX_BLOCK_GROUPS],
    prealloc: [Option<PreallocSpace>; MAX_PREALLOC],
    /// Number of active block groups.
    num_groups: usize,
    /// Total blocks in the filesystem.
    total_blocks: u64,
    /// Total free blocks.
    free_blocks: u64,
}

impl MballocState {
    /// Create a new, empty allocator state.
    pub fn new() -> Self {
        Self {
            groups: core::array::from_fn(|_| None),
            prealloc: core::array::from_fn(|_| None),
            num_groups: 0,
            total_blocks: 0,
            free_blocks: 0,
        }
    }

    /// Register a block group with the allocator.
    pub fn add_group(&mut self, desc: BlockGroupDesc) -> Result<u32> {
        if self.num_groups >= MAX_BLOCK_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.num_groups as u32;
        self.groups[self.num_groups] = Some(GroupState::new(idx, desc));
        self.total_blocks += BLOCKS_PER_GROUP as u64;
        self.free_blocks += desc.free_blocks_count as u64;
        self.num_groups += 1;
        Ok(idx)
    }

    /// Allocate blocks for an inode using the mballoc strategies.
    ///
    /// Strategy order:
    /// 1. Per-inode prealloc hit
    /// 2. Locality-group prealloc hit
    /// 3. Goal-group buddy search
    /// 4. Best-fit scan across all groups
    pub fn alloc_blocks(&mut self, req: &AllocRequest) -> Result<AllocResult> {
        if req.is_delalloc() {
            // Delayed allocation: just check space
            if self.free_blocks < req.len as u64 {
                return Err(Error::OutOfMemory);
            }
            return Ok(AllocResult {
                pblock: req.goal,
                len: req.len,
                group: 0,
            });
        }

        // 1. Check per-inode prealloc
        if let Some(res) = self.try_prealloc(req.ino, PaType::PerInode, req.len) {
            return Ok(res);
        }

        // 2. Check locality-group prealloc
        if let Some(res) = self.try_prealloc(0, PaType::LocalityGroup, req.len) {
            return Ok(res);
        }

        // 3. Goal-group search
        let goal_group = (req.goal / BLOCKS_PER_GROUP as u64) as usize;
        let goal_block_in_group = (req.goal % BLOCKS_PER_GROUP as u64) as u32;

        if goal_group < self.num_groups {
            if let Some(gs) = &mut self.groups[goal_group] {
                if let Some(start) = gs.alloc_blocks(goal_block_in_group, req.len, req.is_exact()) {
                    let pblock = gs.index as u64 * BLOCKS_PER_GROUP as u64 + start as u64;
                    self.free_blocks -= req.len as u64;
                    return Ok(AllocResult {
                        pblock,
                        len: req.len,
                        group: gs.index,
                    });
                }
            }
        }

        // 4. Best-fit scan: find group with most free blocks and enough space
        let mut best_group: Option<usize> = None;
        let mut best_free = 0u32;
        for i in 0..self.num_groups {
            if let Some(gs) = &self.groups[i] {
                if gs.desc.free_blocks_count >= req.len && gs.desc.free_blocks_count > best_free {
                    best_free = gs.desc.free_blocks_count;
                    best_group = Some(i);
                }
            }
        }

        if let Some(gi) = best_group {
            if let Some(gs) = &mut self.groups[gi] {
                if let Some(start) = gs.alloc_blocks(0, req.len, false) {
                    let pblock = gs.index as u64 * BLOCKS_PER_GROUP as u64 + start as u64;
                    self.free_blocks -= req.len as u64;
                    return Ok(AllocResult {
                        pblock,
                        len: req.len,
                        group: gs.index,
                    });
                }
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Free blocks previously allocated by `alloc_blocks`.
    pub fn free_blocks(&mut self, pblock: u64, len: u32) -> Result<()> {
        let group = (pblock / BLOCKS_PER_GROUP as u64) as usize;
        let start = (pblock % BLOCKS_PER_GROUP as u64) as u32;
        if group >= self.num_groups {
            return Err(Error::InvalidArgument);
        }
        if let Some(gs) = &mut self.groups[group] {
            gs.free_blocks(start, len);
            self.free_blocks += len as u64;
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Register a preallocation window for an inode.
    pub fn register_prealloc(&mut self, pa: PreallocSpace) -> Result<()> {
        for slot in &mut self.prealloc {
            if slot.is_none() {
                *slot = Some(pa);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Discard all preallocation windows for an inode (called on inode close).
    pub fn discard_prealloc(&mut self, ino: u64) {
        for slot in &mut self.prealloc {
            if let Some(pa) = slot {
                if pa.ino == ino && pa.pa_type == PaType::PerInode {
                    pa.discard();
                }
            }
        }
        // Compact: remove discarded entries
        for slot in &mut self.prealloc {
            if let Some(pa) = slot {
                if pa.discarded {
                    *slot = None;
                }
            }
        }
    }

    /// Return the number of free blocks in the filesystem.
    pub fn free_block_count(&self) -> u64 {
        self.free_blocks
    }

    /// Return the total block count.
    pub fn total_block_count(&self) -> u64 {
        self.total_blocks
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn try_prealloc(&mut self, ino: u64, pa_type: PaType, needed: u32) -> Option<AllocResult> {
        for slot in &mut self.prealloc {
            if let Some(pa) = slot {
                if pa.pa_type == pa_type
                    && (pa_type == PaType::LocalityGroup || pa.ino == ino)
                    && !pa.discarded
                {
                    if let Some(pblock) = pa.try_alloc(needed) {
                        let group = pa.group;
                        self.free_blocks -= needed as u64;
                        return Some(AllocResult {
                            pblock,
                            len: needed,
                            group,
                        });
                    }
                }
            }
        }
        None
    }
}

impl Default for MballocState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// High-level ext4 multiblock allocator.
pub struct Ext4Mballoc {
    state: MballocState,
    /// Number of allocations performed.
    pub alloc_count: u64,
    /// Number of prealloc hits.
    pub prealloc_hits: u64,
}

impl Ext4Mballoc {
    /// Create a new multiblock allocator.
    pub fn new() -> Self {
        Self {
            state: MballocState::new(),
            alloc_count: 0,
            prealloc_hits: 0,
        }
    }

    /// Add a block group to the allocator.
    pub fn add_group(&mut self, desc: BlockGroupDesc) -> Result<u32> {
        self.state.add_group(desc)
    }

    /// Allocate blocks for an inode.
    pub fn alloc_blocks(&mut self, req: &AllocRequest) -> Result<AllocResult> {
        self.alloc_count += 1;
        self.state.alloc_blocks(req)
    }

    /// Free previously allocated blocks.
    pub fn release_blocks(&mut self, pblock: u64, len: u32) -> Result<()> {
        self.state.free_blocks(pblock, len)
    }

    /// Register a preallocation window.
    pub fn register_prealloc(&mut self, pa: PreallocSpace) -> Result<()> {
        self.state.register_prealloc(pa)
    }

    /// Discard all prealloc windows for an inode (called on inode eviction).
    pub fn discard_prealloc_for_inode(&mut self, ino: u64) {
        self.state.discard_prealloc(ino);
    }

    /// Return free block count.
    pub fn free_block_count(&self) -> u64 {
        self.state.free_block_count()
    }

    /// Return total block count.
    pub fn total_blocks(&self) -> u64 {
        self.state.total_block_count()
    }

    /// Build a default locality-group PA from an allocation result.
    pub fn make_locality_pa(&mut self, result: &AllocResult, len: u32) -> Result<()> {
        let pa = PreallocSpace::new_locality(result.pblock, 0, len, result.group);
        self.state.register_prealloc(pa)
    }
}

impl Default for Ext4Mballoc {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalise an allocation length to a power of two (buddy-aligned).
///
/// The result is clamped to the maximum order chunk size.
pub fn normalize_alloc_len(len: u32) -> u32 {
    len.next_power_of_two().min(1 << (MAX_ORDER - 1))
}

/// Compute the block group index for a physical block number.
pub fn block_to_group(pblock: u64) -> u32 {
    (pblock / BLOCKS_PER_GROUP as u64) as u32
}

/// Compute the block offset within a group.
pub fn block_to_group_offset(pblock: u64) -> u32 {
    (pblock % BLOCKS_PER_GROUP as u64) as u32
}

/// Collect all per-inode prealloc windows from an allocator (for stats).
pub fn collect_inode_prealloc(alloc: &Ext4Mballoc, ino: u64) -> Vec<PreallocSpace> {
    let mut result = Vec::new();
    for slot in &alloc.state.prealloc {
        if let Some(pa) = slot {
            if pa.ino == ino && pa.pa_type == PaType::PerInode && !pa.discarded {
                result.push(*pa);
            }
        }
    }
    result
}
