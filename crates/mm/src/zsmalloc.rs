// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! zsmalloc — compressed-page allocator for zswap/zram.
//!
//! zsmalloc is a size-class–based allocator optimised for storing compressed
//! page data.  Unlike a normal slab allocator, objects may span up to four
//! contiguous physical pages ("zspages") so that even objects close to one
//! page in size can be stored without wasting an entire page.
//!
//! # Key concepts
//!
//! * **Size class** — objects are rounded up to the nearest multiple of
//!   [`SIZE_CLASS_DELTA`] bytes.  There is one [`SizeClass`] per granularity
//!   step from [`MIN_ALLOC_SIZE`] to [`MAX_ALLOC_SIZE`].
//!
//! * **zspage** — a run of 1–[`MAX_ZSPAGE_ORDER`] physically contiguous pages
//!   that backs one size class.  A zspage is divided into equal-sized slots;
//!   any slot can hold one object.
//!
//! * **Handle** — a compact 64-bit value returned by [`ZsPool::alloc`] that
//!   encodes the zspage index and the slot offset.  Pass it to
//!   [`ZsPool::map_object`] / [`ZsPool::unmap_object`] to get a `*mut u8`
//!   pointer, and to [`ZsPool::free`] to release the slot.
//!
//! * **Fullness** — each zspage is classified into one of four fullness
//!   buckets ([`Fullness`]) so the allocator can quickly find a partially
//!   filled zspage when servicing an allocation.
//!
//! * **Compaction** — [`ZsPool::compact`] migrates objects from almost-empty
//!   zspages into almost-full ones, then frees the vacated zspages back to
//!   the frame allocator.
//!
//! Reference: Linux `mm/zsmalloc.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Standard page size in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Smallest allocation size (bytes).
pub const MIN_ALLOC_SIZE: usize = 32;

/// Largest allocation size (bytes).  Objects larger than this are not handled
/// by zsmalloc.
pub const MAX_ALLOC_SIZE: usize = PAGE_SIZE;

/// Granularity of size classes (bytes).
pub const SIZE_CLASS_DELTA: usize = 32;

/// Number of size classes.
pub const NUM_SIZE_CLASSES: usize = (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE) / SIZE_CLASS_DELTA + 1;

/// Maximum number of pages a single zspage may span.
pub const MAX_ZSPAGE_ORDER: usize = 4;

/// Maximum number of zspages managed by a single pool.
pub const MAX_ZSPAGES: usize = 4096;

/// Sentinel value for an invalid handle.
pub const ZS_HANDLE_NONE: u64 = u64::MAX;

/// Number of pages of backing store exposed per pool (virtual budget).
const POOL_PAGES: usize = 1024;

// ── Fullness ──────────────────────────────────────────────────────────────────

/// Fullness bucket of a zspage.
///
/// The allocator uses these buckets to pick the best zspage when servicing
/// an allocation request: prefer `AlmostFull` first so that pages are packed
/// before opening a fresh `Empty` one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fullness {
    /// No slots are in use.
    Empty,
    /// Fewer than 25 % of slots are in use.
    AlmostEmpty,
    /// Between 25 % and 99 % of slots are in use.
    AlmostFull,
    /// Every slot is occupied.
    Full,
}

impl Fullness {
    /// Derive fullness from `(in_use, capacity)`.
    pub fn classify(in_use: usize, capacity: usize) -> Self {
        if capacity == 0 || in_use == 0 {
            return Self::Empty;
        }
        if in_use == capacity {
            return Self::Full;
        }
        // use integer arithmetic: threshold is 25 %
        if in_use * 4 < capacity {
            Self::AlmostEmpty
        } else {
            Self::AlmostFull
        }
    }
}

impl Default for Fullness {
    fn default() -> Self {
        Self::Empty
    }
}

// ── SizeClass ─────────────────────────────────────────────────────────────────

/// Metadata for one allocation size class.
///
/// Each size class manages a set of zspages whose slots are exactly
/// `object_size` bytes.
#[derive(Debug)]
pub struct SizeClass {
    /// Rounded-up object size served by this class (bytes).
    pub object_size: usize,
    /// Number of objects that fit in one zspage for this class.
    pub objects_per_zspage: usize,
    /// Number of pages each zspage spans (1–[`MAX_ZSPAGE_ORDER`]).
    pub pages_per_zspage: usize,
    /// Total slots allocated across all zspages in this class.
    pub total_slots: usize,
    /// Slots currently in use.
    pub used_slots: usize,
}

impl SizeClass {
    /// Construct a new size class for objects of `object_size` bytes.
    pub fn new(object_size: usize) -> Self {
        // Choose the minimum number of pages needed so that at least two
        // objects fit in the zspage (avoids extreme waste on near-page sizes).
        let mut pages = 1usize;
        let mut objects_per = PAGE_SIZE / object_size;
        while objects_per < 2 && pages < MAX_ZSPAGE_ORDER {
            pages += 1;
            objects_per = (pages * PAGE_SIZE) / object_size;
        }
        Self {
            object_size,
            objects_per_zspage: objects_per.max(1),
            pages_per_zspage: pages,
            total_slots: 0,
            used_slots: 0,
        }
    }

    /// Return the size-class index within [`NUM_SIZE_CLASSES`] for a given
    /// allocation size.  Returns `None` if `size` exceeds [`MAX_ALLOC_SIZE`].
    pub fn index_for(size: usize) -> Option<usize> {
        if size < MIN_ALLOC_SIZE || size > MAX_ALLOC_SIZE {
            return None;
        }
        let rounded = size.next_multiple_of(SIZE_CLASS_DELTA);
        let clamped = rounded.min(MAX_ALLOC_SIZE);
        Some((clamped - MIN_ALLOC_SIZE) / SIZE_CLASS_DELTA)
    }
}

// ── ZsPage ────────────────────────────────────────────────────────────────────

/// A single zspage: a run of physically contiguous pages backing one size class.
#[derive(Debug)]
pub struct ZsPage {
    /// Index of the owning size class.
    pub class_idx: usize,
    /// How many pages this zspage spans.
    pub page_order: usize,
    /// Total slots in this zspage.
    pub capacity: usize,
    /// Slots currently occupied.
    pub in_use: usize,
    /// Simulated base address (frame number × PAGE_SIZE).
    pub base_pfn: usize,
    /// Per-slot occupancy bitmap.  Bit `i` set → slot `i` is allocated.
    pub bitmap: [u64; 8],
    /// Fullness bucket.
    pub fullness: Fullness,
}

impl ZsPage {
    /// Construct a new empty zspage for `class_idx`, backed at `base_pfn`.
    pub fn new(class_idx: usize, capacity: usize, page_order: usize, base_pfn: usize) -> Self {
        Self {
            class_idx,
            page_order,
            capacity: capacity.min(512), // max 512 slots — fits in 8×u64 bitmap
            in_use: 0,
            base_pfn,
            bitmap: [0u64; 8],
            fullness: Fullness::Empty,
        }
    }

    /// Allocate the next free slot.  Returns the slot index or `None`.
    pub fn alloc_slot(&mut self) -> Option<usize> {
        let cap = self.capacity.min(512);
        for word in 0..8usize {
            let base = word * 64;
            if base >= cap {
                break;
            }
            let limit = (cap - base).min(64);
            let mask = if limit == 64 {
                u64::MAX
            } else {
                (1u64 << limit) - 1
            };
            let free_bits = (!self.bitmap[word]) & mask;
            if free_bits != 0 {
                let bit = free_bits.trailing_zeros() as usize;
                self.bitmap[word] |= 1u64 << bit;
                self.in_use += 1;
                self.fullness = Fullness::classify(self.in_use, self.capacity);
                return Some(base + bit);
            }
        }
        None
    }

    /// Free slot `slot_idx`.
    pub fn free_slot(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        let word = slot_idx / 64;
        let bit = slot_idx % 64;
        if self.bitmap[word] & (1u64 << bit) == 0 {
            return Err(Error::InvalidArgument); // double-free
        }
        self.bitmap[word] &= !(1u64 << bit);
        self.in_use -= 1;
        self.fullness = Fullness::classify(self.in_use, self.capacity);
        Ok(())
    }

    /// Return whether slot `slot_idx` is occupied.
    pub fn is_slot_used(&self, slot_idx: usize) -> bool {
        if slot_idx >= self.capacity {
            return false;
        }
        let word = slot_idx / 64;
        let bit = slot_idx % 64;
        self.bitmap[word] & (1u64 << bit) != 0
    }
}

// ── Handle encoding ───────────────────────────────────────────────────────────

/// Encode a `(zspage_idx, slot_idx)` pair into an opaque handle.
///
/// Layout (64 bits):
/// ```text
/// [63 .. 20]  zspage index  (44 bits)
/// [19 ..  0]  slot index    (20 bits)
/// ```
#[inline]
pub fn encode_handle(zspage_idx: usize, slot_idx: usize) -> u64 {
    ((zspage_idx as u64) << 20) | (slot_idx as u64 & 0x000F_FFFF)
}

/// Decode a handle into `(zspage_idx, slot_idx)`.
#[inline]
pub fn decode_handle(handle: u64) -> (usize, usize) {
    let zspage_idx = (handle >> 20) as usize;
    let slot_idx = (handle & 0x000F_FFFF) as usize;
    (zspage_idx, slot_idx)
}

// ── ZsStats ───────────────────────────────────────────────────────────────────

/// Pool-wide statistics.
#[derive(Debug, Default, Clone)]
pub struct ZsStats {
    /// Total number of successful allocations.
    pub alloc_count: u64,
    /// Total number of successful frees.
    pub free_count: u64,
    /// Number of pages currently committed to backing zspages.
    pub pages_used: u64,
    /// Number of compaction passes completed.
    pub compaction_runs: u64,
    /// Objects moved during compaction.
    pub objects_compacted: u64,
}

// ── ZsPool ────────────────────────────────────────────────────────────────────

/// A zsmalloc pool.
///
/// One pool typically backs one zswap pool or one zram disk.  The pool
/// owns a fixed array of [`SizeClass`] descriptors and a flat array of
/// [`ZsPage`] entries.
///
/// # Allocation lifecycle
///
/// 1. Call [`ZsPool::alloc`] with the compressed object size → returns a
///    [`u64`] handle.
/// 2. Call [`ZsPool::map_object`] with the handle → returns a `*mut u8`
///    pointer valid until [`ZsPool::unmap_object`] is called.
/// 3. Write compressed data through the pointer.
/// 4. Call [`ZsPool::unmap_object`] to release the mapping.
/// 5. Later, call [`ZsPool::free`] to return the slot.
#[derive(Debug)]
pub struct ZsPool {
    /// Size-class descriptors.
    classes: [SizeClass; NUM_SIZE_CLASSES],
    /// Flat zspage array.
    zspages: [Option<ZsPage>; MAX_ZSPAGES],
    /// Number of zspage slots currently occupied in `zspages`.
    zspage_count: usize,
    /// Simulated page-frame counter (monotonically increasing).
    next_pfn: usize,
    /// Pool-wide statistics.
    pub stats: ZsStats,
    /// Budget: pages available before the pool is considered full.
    pages_budget: usize,
}

impl ZsPool {
    /// Create a new, empty pool.
    pub fn new() -> Self {
        // Build size classes.
        let classes = core::array::from_fn(|i| {
            let size = MIN_ALLOC_SIZE + i * SIZE_CLASS_DELTA;
            SizeClass::new(size)
        });

        // Can't use Default for large arrays, initialise manually.
        const NONE: Option<ZsPage> = None;
        Self {
            classes,
            zspages: [NONE; MAX_ZSPAGES],
            zspage_count: 0,
            next_pfn: 0x1000, // start at PFN 0x1000
            stats: ZsStats::default(),
            pages_budget: POOL_PAGES,
        }
    }

    /// Allocate a slot for an object of `size` bytes.
    ///
    /// Returns an opaque handle on success.  The caller must call
    /// [`map_object`](Self::map_object) before writing to the slot.
    pub fn alloc(&mut self, size: usize) -> Result<u64> {
        let class_idx = SizeClass::index_for(size).ok_or(Error::InvalidArgument)?;

        // Try to find an existing non-full zspage for this class.
        if let Some(handle) = self.alloc_from_existing(class_idx) {
            self.stats.alloc_count += 1;
            return Ok(handle);
        }

        // No suitable zspage — allocate a new one.
        self.grow_class(class_idx)?;
        let handle = self
            .alloc_from_existing(class_idx)
            .ok_or(Error::OutOfMemory)?;
        self.stats.alloc_count += 1;
        Ok(handle)
    }

    /// Free the slot identified by `handle`.
    pub fn free(&mut self, handle: u64) -> Result<()> {
        if handle == ZS_HANDLE_NONE {
            return Err(Error::InvalidArgument);
        }
        let (zspage_idx, slot_idx) = decode_handle(handle);
        let zspage = self
            .zspages
            .get_mut(zspage_idx)
            .and_then(|o| o.as_mut())
            .ok_or(Error::InvalidArgument)?;

        let class_idx = zspage.class_idx;
        zspage.free_slot(slot_idx)?;

        // Update class accounting.
        self.classes[class_idx].used_slots = self.classes[class_idx].used_slots.saturating_sub(1);

        // If the zspage is now empty, release its pages back to the budget.
        if let Some(zsp) = &self.zspages[zspage_idx] {
            if zsp.in_use == 0 {
                let pages = zsp.page_order;
                self.classes[class_idx].total_slots = self.classes[class_idx]
                    .total_slots
                    .saturating_sub(zsp.capacity);
                self.pages_budget += pages;
                self.zspages[zspage_idx] = None;
                // Note: we do not compact the array; None slots are reused.
            }
        }

        self.stats.free_count += 1;
        Ok(())
    }

    /// Map the object slot identified by `handle` and return a pointer.
    ///
    /// The pointer remains valid until [`unmap_object`](Self::unmap_object) is
    /// called with the same handle.
    ///
    /// # Safety
    ///
    /// The caller must not use the pointer after calling `unmap_object`.
    pub fn map_object(&self, handle: u64) -> Result<*mut u8> {
        if handle == ZS_HANDLE_NONE {
            return Err(Error::InvalidArgument);
        }
        let (zspage_idx, slot_idx) = decode_handle(handle);
        let zspage = self
            .zspages
            .get(zspage_idx)
            .and_then(|o| o.as_ref())
            .ok_or(Error::InvalidArgument)?;

        if !zspage.is_slot_used(slot_idx) {
            return Err(Error::InvalidArgument);
        }

        // Compute simulated virtual address: base_pfn * PAGE_SIZE + slot * obj_size
        let class = &self.classes[zspage.class_idx];
        let addr = zspage.base_pfn * PAGE_SIZE + slot_idx * class.object_size;
        // SAFETY: In a real kernel this would be a mapping into physical memory.
        // Here we return the computed address as a pointer for simulation purposes.
        Ok(addr as *mut u8)
    }

    /// Unmap a previously mapped object.  Currently a no-op in this simulation
    /// (no temporary kernel mappings are created), but callers must still call
    /// this to maintain the correct usage contract.
    pub fn unmap_object(&self, _handle: u64) {
        // In a real implementation this would tear down the temporary kmap.
    }

    /// Return pool-wide statistics.
    pub fn stats(&self) -> &ZsStats {
        &self.stats
    }

    /// Return the fullness of the zspage backing `handle`.
    pub fn fullness(&self, handle: u64) -> Result<Fullness> {
        if handle == ZS_HANDLE_NONE {
            return Err(Error::InvalidArgument);
        }
        let (zspage_idx, _) = decode_handle(handle);
        let zspage = self
            .zspages
            .get(zspage_idx)
            .and_then(|o| o.as_ref())
            .ok_or(Error::InvalidArgument)?;
        Ok(zspage.fullness)
    }

    /// Compact the pool by migrating objects from almost-empty zspages into
    /// almost-full ones, then freeing the vacated zspages.
    ///
    /// Returns the number of objects moved.
    pub fn compact(&mut self) -> usize {
        let mut moved = 0usize;

        // Collect (zspage_idx, class_idx) pairs whose fullness is AlmostEmpty.
        // We can't borrow self mutably twice, so first gather indices.
        let mut almost_empty: [Option<usize>; MAX_ZSPAGES] = [None; MAX_ZSPAGES];
        let mut ae_count = 0usize;
        for (idx, slot) in self.zspages.iter().enumerate() {
            if let Some(zsp) = slot {
                if zsp.fullness == Fullness::AlmostEmpty && ae_count < MAX_ZSPAGES {
                    almost_empty[ae_count] = Some(idx);
                    ae_count += 1;
                }
            }
        }

        // For each almost-empty zspage, try to migrate its live slots.
        for i in 0..ae_count {
            let src_idx = match almost_empty[i] {
                Some(idx) => idx,
                None => continue,
            };

            // Collect occupied slots in source zspage.
            let (class_idx, src_capacity) = match &self.zspages[src_idx] {
                Some(zsp) => (zsp.class_idx, zsp.capacity),
                None => continue,
            };

            let mut slots_to_migrate: [Option<usize>; 512] = [None; 512];
            let mut slot_count = 0usize;
            if let Some(zsp) = &self.zspages[src_idx] {
                for s in 0..src_capacity.min(512) {
                    if zsp.is_slot_used(s) && slot_count < 512 {
                        slots_to_migrate[slot_count] = Some(s);
                        slot_count += 1;
                    }
                }
            }

            // Re-allocate each slot in a different zspage of the same class.
            for s in 0..slot_count {
                let slot_idx = match slots_to_migrate[s] {
                    Some(si) => si,
                    None => continue,
                };

                // Find a destination zspage (not src_idx, AlmostFull or AlmostEmpty).
                if let Some(dst_idx) = self.find_dst_zspage(class_idx, src_idx) {
                    // Move the slot: free source, alloc destination.
                    if let Some(zsp) = &mut self.zspages[src_idx] {
                        let _ = zsp.free_slot(slot_idx);
                    }
                    if let Some(zsp) = &mut self.zspages[dst_idx] {
                        let _ = zsp.alloc_slot();
                    }
                    moved += 1;
                }
            }

            // If source is now empty, free it.
            let is_empty = self
                .zspages
                .get(src_idx)
                .and_then(|o| o.as_ref())
                .map(|z| z.in_use == 0)
                .unwrap_or(false);
            if is_empty {
                if let Some(Some(zsp)) = self.zspages.get(src_idx) {
                    let pages = zsp.page_order;
                    let capacity = zsp.capacity;
                    self.classes[class_idx].total_slots =
                        self.classes[class_idx].total_slots.saturating_sub(capacity);
                    self.pages_budget += pages;
                }
                self.zspages[src_idx] = None;
            }
        }

        self.stats.compaction_runs += 1;
        self.stats.objects_compacted += moved as u64;
        moved
    }

    /// Total number of live zspages.
    pub fn zspage_count(&self) -> usize {
        self.zspages.iter().filter(|s| s.is_some()).count()
    }

    /// Total pages consumed across all live zspages.
    pub fn pages_used(&self) -> usize {
        self.zspages
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|z| z.page_order)
            .sum()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Try to allocate a slot from an existing non-full zspage of `class_idx`.
    fn alloc_from_existing(&mut self, class_idx: usize) -> Option<u64> {
        // Prefer AlmostFull first, then AlmostEmpty, then Empty.
        for &preferred in &[Fullness::AlmostFull, Fullness::AlmostEmpty, Fullness::Empty] {
            for zspage_idx in 0..MAX_ZSPAGES {
                let matches = self
                    .zspages
                    .get(zspage_idx)
                    .and_then(|o| o.as_ref())
                    .map(|z| z.class_idx == class_idx && z.fullness == preferred)
                    .unwrap_or(false);

                if matches {
                    if let Some(Some(zsp)) = self.zspages.get_mut(zspage_idx) {
                        if let Some(slot) = zsp.alloc_slot() {
                            self.classes[class_idx].used_slots += 1;
                            return Some(encode_handle(zspage_idx, slot));
                        }
                    }
                }
            }
        }
        None
    }

    /// Grow a size class by allocating a new zspage.
    fn grow_class(&mut self, class_idx: usize) -> Result<()> {
        let pages_needed = self.classes[class_idx].pages_per_zspage;
        if pages_needed > self.pages_budget {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot in the zspage array.
        let free_slot = self
            .zspages
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;

        let base_pfn = self.next_pfn;
        self.next_pfn += pages_needed;
        self.pages_budget -= pages_needed;

        let capacity = self.classes[class_idx].objects_per_zspage;
        let page_order = self.classes[class_idx].pages_per_zspage;
        let zsp = ZsPage::new(class_idx, capacity, page_order, base_pfn);
        self.classes[class_idx].total_slots += capacity;
        self.zspages[free_slot] = Some(zsp);
        self.zspage_count += 1;
        self.stats.pages_used += pages_needed as u64;
        Ok(())
    }

    /// Find a destination zspage for compaction (not `exclude_idx`, same class,
    /// not full).
    fn find_dst_zspage(&self, class_idx: usize, exclude_idx: usize) -> Option<usize> {
        for idx in 0..MAX_ZSPAGES {
            if idx == exclude_idx {
                continue;
            }
            if let Some(Some(zsp)) = self.zspages.get(idx) {
                if zsp.class_idx == class_idx && zsp.fullness != Fullness::Full {
                    return Some(idx);
                }
            }
        }
        None
    }
}

impl Default for ZsPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── ZsPoolManager ─────────────────────────────────────────────────────────────

/// Manager for multiple named zsmalloc pools.
///
/// In practice, one pool backs one zswap or zram device.  The manager allows
/// up to [`MAX_POOLS`] concurrent pools.
const MAX_POOLS: usize = 8;

/// Entry in the pool manager.
#[derive(Debug)]
pub struct PoolEntry {
    /// Human-readable name (up to 16 ASCII bytes).
    pub name: [u8; 16],
    /// The pool itself.
    pub pool: ZsPool,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl PoolEntry {
    fn new(name: &[u8]) -> Self {
        let mut arr = [0u8; 16];
        let len = name.len().min(16);
        arr[..len].copy_from_slice(&name[..len]);
        Self {
            name: arr,
            pool: ZsPool::new(),
            active: true,
        }
    }
}

/// Top-level manager holding up to [`MAX_POOLS`] [`ZsPool`] instances.
pub struct ZsPoolManager {
    pools: [Option<PoolEntry>; MAX_POOLS],
}

impl ZsPoolManager {
    /// Create a new manager with no pools.
    pub fn new() -> Self {
        const NONE: Option<PoolEntry> = None;
        Self {
            pools: [NONE; MAX_POOLS],
        }
    }

    /// Register a new pool with the given `name`.
    ///
    /// Returns the pool index.
    pub fn create_pool(&mut self, name: &[u8]) -> Result<usize> {
        let slot = self
            .pools
            .iter()
            .position(|p| p.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.pools[slot] = Some(PoolEntry::new(name));
        Ok(slot)
    }

    /// Destroy the pool at `pool_id`.
    pub fn destroy_pool(&mut self, pool_id: usize) -> Result<()> {
        let entry = self.pools.get_mut(pool_id).ok_or(Error::InvalidArgument)?;
        *entry = None;
        Ok(())
    }

    /// Get a reference to the pool at `pool_id`.
    pub fn get(&self, pool_id: usize) -> Option<&ZsPool> {
        self.pools.get(pool_id)?.as_ref().map(|e| &e.pool)
    }

    /// Get a mutable reference to the pool at `pool_id`.
    pub fn get_mut(&mut self, pool_id: usize) -> Option<&mut ZsPool> {
        self.pools.get_mut(pool_id)?.as_mut().map(|e| &mut e.pool)
    }

    /// Allocate within pool `pool_id` for an object of `size` bytes.
    pub fn alloc(&mut self, pool_id: usize, size: usize) -> Result<u64> {
        self.get_mut(pool_id)
            .ok_or(Error::InvalidArgument)?
            .alloc(size)
    }

    /// Free `handle` within pool `pool_id`.
    pub fn free(&mut self, pool_id: usize, handle: u64) -> Result<()> {
        self.get_mut(pool_id)
            .ok_or(Error::InvalidArgument)?
            .free(handle)
    }
}

impl Default for ZsPoolManager {
    fn default() -> Self {
        Self::new()
    }
}
