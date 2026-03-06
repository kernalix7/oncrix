// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SLUB allocator — unqueued slab allocator for kernel objects.
//!
//! An evolution of the classic slab allocator that removes per-slab
//! queues in favour of per-CPU active pages and node-level partial
//! lists.  This reduces metadata overhead, improves cache locality,
//! and scales better on multi-core systems.
//!
//! Key concepts:
//! - **SlubPage**: a page-sized arena divided into fixed-size objects,
//!   with an embedded free-list tracked by `u16` offsets.
//! - **SlubPerCpu**: per-CPU state holding an active page and a small
//!   partial-page cache to avoid contention on the node list.
//! - **SlubCache**: a named cache that owns pages, per-CPU structures,
//!   and a node-level partial list.
//! - **SlubAllocator**: top-level registry of up to 16 caches.
//!
//! Design inspired by Christoph Lameter's SLUB (Linux `mm/slub.c`).
//!
//! Reference: `.kernelORG/` — `mm/slub.rst`, `mm/slub.c`.

use oncrix_lib::{Error, Result};

/// Page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Maximum objects per page (worst case: 16-byte objects in 4 KiB).
const MAX_OBJECTS_PER_PAGE: usize = 256;

/// Maximum pages per cache.
const MAX_PAGES_PER_CACHE: usize = 64;

/// Maximum per-CPU partial pages.
const MAX_PER_CPU_PARTIAL: usize = 8;

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Maximum node-level partial pages.
const MAX_NODE_PARTIAL: usize = 32;

/// Maximum caches in the allocator.
const MAX_CACHES: usize = 16;

/// Sentinel value indicating "no page".
const NO_PAGE: u16 = u16::MAX;

// ── SlubPage ────────────────────────────────────────────────────────

/// A page-sized arena of fixed-size objects with an embedded free-list.
///
/// Objects are allocated and freed in O(1) via a `u16` offset free-list.
/// Each entry in `free_list` stores the index of the next free slot
/// (or [`NO_PAGE`] for the list tail).
#[derive(Debug)]
pub struct SlubPage {
    /// Raw object storage (one 4 KiB page).
    objects: [u8; PAGE_SIZE],
    /// Per-slot next-free pointer (`NO_PAGE` = end of list).
    free_list: [u16; MAX_OBJECTS_PER_PAGE],
    /// Head of the free list (slot index, or `NO_PAGE` if full).
    free_head: u16,
    /// Number of free slots remaining.
    free_count: usize,
    /// Total number of object slots in this page.
    total_objects: usize,
    /// Size of each object in bytes.
    obj_size: usize,
    /// Whether this page is frozen (owned by a per-CPU cache).
    frozen: bool,
    /// Whether this page is actively managed by a cache.
    in_use: bool,
}

impl Default for SlubPage {
    fn default() -> Self {
        Self {
            objects: [0u8; PAGE_SIZE],
            free_list: [NO_PAGE; MAX_OBJECTS_PER_PAGE],
            free_head: NO_PAGE,
            free_count: 0,
            total_objects: 0,
            obj_size: 0,
            frozen: false,
            in_use: false,
        }
    }
}

impl SlubPage {
    /// Initialise the page for a given object size.
    ///
    /// Builds the internal free-list so every slot is available.
    /// Returns [`Error::InvalidArgument`] if `obj_size` is zero or
    /// exceeds [`PAGE_SIZE`].
    pub fn init(&mut self, obj_size: usize) -> Result<()> {
        if obj_size == 0 || obj_size > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        let count = PAGE_SIZE / obj_size;
        self.obj_size = obj_size;
        self.total_objects = count;
        self.free_count = count;
        self.in_use = true;
        self.frozen = false;

        // Build a singly-linked free-list through the `free_list` array.
        for i in 0..count {
            self.free_list[i] = if i + 1 < count {
                (i + 1) as u16
            } else {
                NO_PAGE
            };
        }
        self.free_head = 0;

        // Zero the backing storage.
        self.objects = [0u8; PAGE_SIZE];

        Ok(())
    }

    /// Allocate one object from this page.
    ///
    /// Returns the slot offset (in units of `obj_size`) on success.
    pub fn alloc(&mut self) -> Result<u16> {
        if self.free_head == NO_PAGE {
            return Err(Error::OutOfMemory);
        }

        let slot = self.free_head;
        self.free_head = self.free_list[slot as usize];
        self.free_list[slot as usize] = NO_PAGE;
        self.free_count -= 1;

        Ok(slot)
    }

    /// Free a previously allocated slot back to this page.
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range
    /// or was not allocated.
    pub fn free(&mut self, offset: u16) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.total_objects {
            return Err(Error::InvalidArgument);
        }

        // Push onto the free-list head.
        self.free_list[idx] = self.free_head;
        self.free_head = offset;
        self.free_count += 1;

        Ok(())
    }

    /// Returns `true` when every slot is allocated.
    pub fn is_full(&self) -> bool {
        self.free_count == 0
    }

    /// Returns `true` when no slots are allocated.
    pub fn is_empty_slab(&self) -> bool {
        self.free_count == self.total_objects
    }

    /// Number of objects currently in use.
    pub fn objects_in_use(&self) -> usize {
        self.total_objects - self.free_count
    }

    /// Total object capacity.
    pub fn total_objects(&self) -> usize {
        self.total_objects
    }

    /// Object size in bytes.
    pub fn obj_size(&self) -> usize {
        self.obj_size
    }

    /// Whether this page is frozen (per-CPU owned).
    pub fn frozen(&self) -> bool {
        self.frozen
    }

    /// Whether this page is actively managed.
    pub fn in_use(&self) -> bool {
        self.in_use
    }
}

// ── SlubPerCpu ──────────────────────────────────────────────────────

/// Per-CPU state for the SLUB allocator.
///
/// Each CPU maintains an active page (fast-path) and a small list of
/// partial pages to reduce contention on the shared node list.
#[derive(Debug, Clone, Copy)]
pub struct SlubPerCpu {
    /// Index of the active page in the parent cache's page array
    /// ([`NO_PAGE`] if none).
    active_page: u16,
    /// Per-CPU partial-page indices.
    partial_pages: [u16; MAX_PER_CPU_PARTIAL],
    /// Number of valid entries in `partial_pages`.
    partial_count: usize,
    /// Logical CPU identifier.
    cpu_id: u32,
}

impl Default for SlubPerCpu {
    fn default() -> Self {
        Self {
            active_page: NO_PAGE,
            partial_pages: [NO_PAGE; MAX_PER_CPU_PARTIAL],
            partial_count: 0,
            cpu_id: 0,
        }
    }
}

impl SlubPerCpu {
    /// Create per-CPU state for the given CPU id.
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            ..Self::default()
        }
    }

    /// Set the active page index.
    pub fn set_active(&mut self, idx: u16) {
        self.active_page = idx;
    }

    /// Return the active page index, or `None` if unset.
    pub fn get_active(&self) -> Option<u16> {
        if self.active_page == NO_PAGE {
            None
        } else {
            Some(self.active_page)
        }
    }

    /// Push a page index onto the per-CPU partial list.
    ///
    /// Returns [`Error::OutOfMemory`] when the list is full.
    pub fn push_partial(&mut self, idx: u16) -> Result<()> {
        if self.partial_count >= MAX_PER_CPU_PARTIAL {
            return Err(Error::OutOfMemory);
        }
        self.partial_pages[self.partial_count] = idx;
        self.partial_count += 1;
        Ok(())
    }

    /// Pop a page index from the per-CPU partial list.
    pub fn pop_partial(&mut self) -> Option<u16> {
        if self.partial_count == 0 {
            return None;
        }
        self.partial_count -= 1;
        let idx = self.partial_pages[self.partial_count];
        self.partial_pages[self.partial_count] = NO_PAGE;
        Some(idx)
    }

    /// CPU identifier.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Number of partial pages held.
    pub fn partial_count(&self) -> usize {
        self.partial_count
    }
}

// ── SlubStats ───────────────────────────────────────────────────────

/// Allocation statistics for a [`SlubCache`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SlubStats {
    /// Fast-path allocations (from the per-CPU active page).
    pub alloc_fastpath: u64,
    /// Slow-path allocations (partial list or new page).
    pub alloc_slowpath: u64,
    /// Fast-path frees (object returns to per-CPU active page).
    pub free_fastpath: u64,
    /// Slow-path frees (page transitions to partial/empty).
    pub free_slowpath: u64,
    /// Allocation failures.
    pub alloc_fail: u64,
    /// Pages allocated from the page-level allocator.
    pub page_alloc: u64,
    /// Pages returned to the page-level allocator.
    pub page_free: u64,
}

// ── SlubCache ───────────────────────────────────────────────────────

/// A named SLUB cache managing objects of a single fixed size.
///
/// Owns a pool of [`SlubPage`]s, per-CPU structures, and a node-level
/// partial list.
pub struct SlubCache {
    /// Cache name (up to 32 bytes).
    name: [u8; 32],
    /// Valid length of `name`.
    name_len: usize,
    /// Object size in bytes.
    obj_size: usize,
    /// Object alignment in bytes.
    align: usize,
    /// Page pool.
    pages: [SlubPage; MAX_PAGES_PER_CACHE],
    /// Number of pages currently initialised.
    page_count: usize,
    /// Per-CPU state.
    per_cpu: [SlubPerCpu; MAX_CPUS],
    /// Node-level partial-page list (indices into `pages`).
    node_partial: [u16; MAX_NODE_PARTIAL],
    /// Number of valid entries in `node_partial`.
    node_partial_count: usize,
    /// Minimum number of partial pages to keep around.
    _min_partial: usize,
    /// Allocation statistics.
    stats: SlubStats,
    /// Whether this cache slot is active.
    in_use: bool,
}

impl SlubCache {
    /// Effective (aligned) object size.
    fn effective_obj_size(&self) -> usize {
        align_up(self.obj_size, self.align)
    }

    /// Create a new cache.
    ///
    /// `name` is truncated to 32 bytes.  `obj_size` must be non-zero
    /// and no larger than [`PAGE_SIZE`].  `align` must be a power of
    /// two; if zero it defaults to `core::mem::size_of::<usize>()`.
    pub fn new(name: &[u8], obj_size: usize, align: usize) -> Result<Self> {
        if obj_size == 0 || obj_size > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        let actual_align = if align == 0 {
            core::mem::size_of::<usize>()
        } else if !align.is_power_of_two() {
            return Err(Error::InvalidArgument);
        } else {
            align
        };

        let effective = align_up(obj_size, actual_align);
        if effective > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        // Initialise per-CPU structures with sequential CPU ids.
        let mut per_cpu = [SlubPerCpu::default(); MAX_CPUS];
        let mut i = 0;
        while i < MAX_CPUS {
            per_cpu[i].cpu_id = i as u32;
            i += 1;
        }

        Ok(Self {
            name: name_buf,
            name_len: copy_len,
            obj_size,
            align: actual_align,
            pages: core::array::from_fn(|_| SlubPage::default()),
            page_count: 0,
            per_cpu,
            node_partial: [NO_PAGE; MAX_NODE_PARTIAL],
            node_partial_count: 0,
            _min_partial: 4,
            stats: SlubStats::default(),
            in_use: true,
        })
    }

    /// Allocate an object for the given CPU.
    ///
    /// Returns `(page_idx, slot_offset)` on success.
    ///
    /// **Fast path**: try the per-CPU active page.
    /// **Slow path**: try per-CPU partials, then node partials,
    /// and finally grow a new page.
    pub fn alloc_object(&mut self, cpu_id: u32) -> Result<(u16, u16)> {
        let cpu = cpu_id as usize;
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        // Fast path — per-CPU active page.
        if let Some(page_idx) = self.per_cpu[cpu].get_active() {
            let pi = page_idx as usize;
            if pi < self.page_count && !self.pages[pi].is_full() {
                let offset = self.pages[pi].alloc()?;
                self.stats.alloc_fastpath += 1;
                return Ok((page_idx, offset));
            }
            // Active page is full — move it to node partial if it has
            // free objects, otherwise just clear.
            self.per_cpu[cpu].set_active(NO_PAGE);
            if pi < self.page_count {
                self.pages[pi].frozen = false;
                if !self.pages[pi].is_full() {
                    let _ = self.push_node_partial(page_idx);
                }
            }
        }

        // Slow path — try per-CPU partial pages.
        if let Some(page_idx) = self.per_cpu[cpu].pop_partial() {
            let pi = page_idx as usize;
            if pi < self.page_count && !self.pages[pi].is_full() {
                let offset = self.pages[pi].alloc()?;
                self.pages[pi].frozen = true;
                self.per_cpu[cpu].set_active(page_idx);
                self.stats.alloc_slowpath += 1;
                return Ok((page_idx, offset));
            }
        }

        // Slow path — try node partial list.
        if let Some(page_idx) = self.pop_node_partial() {
            let pi = page_idx as usize;
            if pi < self.page_count && !self.pages[pi].is_full() {
                let offset = self.pages[pi].alloc()?;
                self.pages[pi].frozen = true;
                self.per_cpu[cpu].set_active(page_idx);
                self.stats.alloc_slowpath += 1;
                return Ok((page_idx, offset));
            }
        }

        // Slow path — grow a new page.
        let page_idx = self.grow()?;
        let pi = page_idx as usize;
        let offset = self.pages[pi].alloc()?;
        self.pages[pi].frozen = true;
        self.per_cpu[cpu].set_active(page_idx);
        self.stats.alloc_slowpath += 1;

        Ok((page_idx, offset))
    }

    /// Free an object identified by `(page_idx, slot_offset)`.
    pub fn free_object(&mut self, page_idx: u16, offset: u16) -> Result<()> {
        let pi = page_idx as usize;
        if pi >= self.page_count || !self.pages[pi].in_use {
            return Err(Error::InvalidArgument);
        }

        let was_full = self.pages[pi].is_full();
        self.pages[pi].free(offset)?;

        if self.pages[pi].frozen {
            // Page belongs to a per-CPU cache — fast path.
            self.stats.free_fastpath += 1;
        } else {
            self.stats.free_slowpath += 1;

            // If page was full and now has free space, add to node partial.
            if was_full {
                let _ = self.push_node_partial(page_idx);
            }
        }

        Ok(())
    }

    /// Shrink the cache by reclaiming completely empty pages.
    ///
    /// Returns the number of pages freed.
    pub fn shrink(&mut self) -> Result<u32> {
        let mut freed: u32 = 0;

        // Remove empty pages from the node partial list.
        let mut new_list = [NO_PAGE; MAX_NODE_PARTIAL];
        let mut new_count = 0usize;

        for i in 0..self.node_partial_count {
            let idx = self.node_partial[i] as usize;
            if idx < self.page_count && self.pages[idx].is_empty_slab() {
                self.pages[idx].in_use = false;
                freed += 1;
                self.stats.page_free += 1;
            } else if new_count < MAX_NODE_PARTIAL {
                new_list[new_count] = self.node_partial[i];
                new_count += 1;
            }
        }

        self.node_partial = new_list;
        self.node_partial_count = new_count;

        Ok(freed)
    }

    /// Grow the cache by initialising a new page.
    ///
    /// Returns the index of the newly initialised page.
    pub fn grow(&mut self) -> Result<u16> {
        if self.page_count >= MAX_PAGES_PER_CACHE {
            self.stats.alloc_fail += 1;
            return Err(Error::OutOfMemory);
        }

        let idx = self.page_count;
        let effective = self.effective_obj_size();
        self.pages[idx].init(effective)?;
        self.page_count += 1;
        self.stats.page_alloc += 1;

        Ok(idx as u16)
    }

    /// Total number of objects currently allocated across all pages.
    pub fn objects_in_use(&self) -> usize {
        self.pages[..self.page_count]
            .iter()
            .filter(|p| p.in_use)
            .map(|p| p.objects_in_use())
            .sum()
    }

    /// Number of active (in-use) pages.
    pub fn pages_in_use(&self) -> usize {
        self.pages[..self.page_count]
            .iter()
            .filter(|p| p.in_use)
            .count()
    }

    /// Cache name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Object size (before alignment).
    pub fn obj_size(&self) -> usize {
        self.obj_size
    }

    /// Object alignment.
    pub fn align(&self) -> usize {
        self.align
    }

    /// Reference to the allocation statistics.
    pub fn stats(&self) -> &SlubStats {
        &self.stats
    }

    /// Whether this cache slot is active.
    pub fn in_use(&self) -> bool {
        self.in_use
    }

    /// Number of pages initialised.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    // ── internal helpers ────────────────────────────────────────────

    /// Push a page index onto the node-level partial list.
    fn push_node_partial(&mut self, idx: u16) -> Result<()> {
        if self.node_partial_count >= MAX_NODE_PARTIAL {
            return Err(Error::OutOfMemory);
        }
        self.node_partial[self.node_partial_count] = idx;
        self.node_partial_count += 1;
        Ok(())
    }

    /// Pop a page index from the node-level partial list.
    fn pop_node_partial(&mut self) -> Option<u16> {
        if self.node_partial_count == 0 {
            return None;
        }
        self.node_partial_count -= 1;
        let idx = self.node_partial[self.node_partial_count];
        self.node_partial[self.node_partial_count] = NO_PAGE;
        Some(idx)
    }
}

impl core::fmt::Debug for SlubCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = core::str::from_utf8(self.name()).unwrap_or("<invalid>");
        f.debug_struct("SlubCache")
            .field("name", &name)
            .field("obj_size", &self.obj_size)
            .field("align", &self.align)
            .field("pages", &self.page_count)
            .field("objects_in_use", &self.objects_in_use())
            .finish()
    }
}

// ── SlubAllocator ───────────────────────────────────────────────────

/// Top-level SLUB allocator managing up to [`MAX_CACHES`] named caches.
pub struct SlubAllocator {
    /// Cache slots.
    caches: [Option<SlubCache>; MAX_CACHES],
    /// Number of active caches.
    cache_count: usize,
}

impl Default for SlubAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SlubAllocator {
    /// Create an empty allocator.
    pub fn new() -> Self {
        const NONE: Option<SlubCache> = None;
        Self {
            caches: [NONE; MAX_CACHES],
            cache_count: 0,
        }
    }

    /// Create a new named cache.
    ///
    /// Returns the cache index on success.
    pub fn create_cache(&mut self, name: &[u8], obj_size: usize, align: usize) -> Result<u16> {
        if self.cache_count >= MAX_CACHES {
            return Err(Error::OutOfMemory);
        }

        let cache = SlubCache::new(name, obj_size, align)?;

        for (i, slot) in self.caches.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cache);
                self.cache_count += 1;
                return Ok(i as u16);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a cache by index.
    ///
    /// Fails with [`Error::Busy`] if the cache still has objects in
    /// use, or [`Error::InvalidArgument`] if the index is invalid.
    pub fn destroy_cache(&mut self, cache_idx: u16) -> Result<()> {
        let idx = cache_idx as usize;
        let cache = self
            .caches
            .get(idx)
            .and_then(|c| c.as_ref())
            .ok_or(Error::InvalidArgument)?;

        if cache.objects_in_use() > 0 {
            return Err(Error::Busy);
        }

        self.caches[idx] = None;
        self.cache_count = self.cache_count.saturating_sub(1);
        Ok(())
    }

    /// Allocate an object from the specified cache for the given CPU.
    ///
    /// Returns `(page_idx, slot_offset)`.
    pub fn alloc(&mut self, cache_idx: u16, cpu_id: u32) -> Result<(u16, u16)> {
        let idx = cache_idx as usize;
        let cache = self
            .caches
            .get_mut(idx)
            .and_then(|c| c.as_mut())
            .ok_or(Error::InvalidArgument)?;
        cache.alloc_object(cpu_id)
    }

    /// Free an object back to its cache.
    pub fn free(&mut self, cache_idx: u16, page_idx: u16, offset: u16) -> Result<()> {
        let idx = cache_idx as usize;
        let cache = self
            .caches
            .get_mut(idx)
            .and_then(|c| c.as_mut())
            .ok_or(Error::InvalidArgument)?;
        cache.free_object(page_idx, offset)
    }

    /// Shrink all caches, returning the total number of pages freed.
    pub fn shrink_all(&mut self) -> Result<u32> {
        let mut total: u32 = 0;
        for slot in self.caches.iter_mut().flatten() {
            total += slot.shrink()?;
        }
        Ok(total)
    }

    /// Get an immutable reference to a cache by index.
    pub fn get_cache(&self, idx: u16) -> Option<&SlubCache> {
        self.caches.get(idx as usize)?.as_ref()
    }

    /// Number of active caches.
    pub fn len(&self) -> usize {
        self.cache_count
    }

    /// Returns `true` when no caches are registered.
    pub fn is_empty(&self) -> bool {
        self.cache_count == 0
    }
}

impl core::fmt::Debug for SlubAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlubAllocator")
            .field("active_caches", &self.cache_count)
            .field("capacity", &MAX_CACHES)
            .finish()
    }
}

// ── helpers ─────────────────────────────────────────────────────────

/// Align `value` up to the next multiple of `align`.
///
/// `align` must be a power of two.
const fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}
