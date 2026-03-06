// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap subsystem for the ONCRIX operating system.
//!
//! Provides virtual memory paging to secondary storage via swap
//! areas. Supports up to [`MAX_SWAP_AREAS`] swap devices/files,
//! each with bitmap-based slot allocation. A priority-ordered swap
//! table manages area selection, and a swap cache avoids redundant
//! I/O for recently swapped pages.
//!
//! Key components:
//! - [`SwapEntry`] — identifies a slot on a swap device
//! - [`SwapArea`] — a single swap device/file with slot bitmap
//! - [`SwapTable`] — priority-ordered collection of swap areas
//! - [`SwapSlotAllocator`] — bitmap-based slot allocation
//! - [`SwapCache`] — cache of recently swapped page data
//! - [`SwapStats`] — per-area and global swap counters
//! - [`SwapPolicy`] — LRU-based victim page selection
//!
//! Reference: `.kernelORG/` — `mm/swap.c`, `mm/swapfile.c`,
//! `mm/swap_state.c`.

use crate::addr::PAGE_SIZE;
use crate::frame::Frame;
use oncrix_lib::{Error, Result};

/// Maximum number of swap areas the system can manage.
pub const MAX_SWAP_AREAS: usize = 4;

/// Maximum number of swap slots per area.
///
/// 8192 slots * 4 KiB = 32 MiB per swap area.
pub const MAX_SLOTS_PER_AREA: usize = 8192;

/// Number of `u64` words needed for the slot bitmap.
const BITMAP_WORDS: usize = MAX_SLOTS_PER_AREA / 64;

/// Maximum entries in the swap cache.
pub const SWAP_CACHE_SIZE: usize = 128;

/// Maximum entries in the LRU access tracker.
const LRU_MAX_ENTRIES: usize = 256;

// ── SwapEntry ───────────────────────────────────────────────────

/// Identifies a specific slot within a swap area.
///
/// Combines a device/area identifier with a slot offset to
/// uniquely address a swap slot across the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapEntry {
    /// Index of the swap area (0..`MAX_SWAP_AREAS`).
    device_id: u8,
    /// Slot offset within the swap area.
    offset: u32,
}

impl SwapEntry {
    /// Create a new swap entry for the given device and offset.
    ///
    /// Returns `Err(InvalidArgument)` if `device_id` exceeds the
    /// maximum number of swap areas or `offset` exceeds the
    /// maximum slots per area.
    pub const fn new(device_id: u8, offset: u32) -> Result<Self> {
        if device_id as usize >= MAX_SWAP_AREAS {
            return Err(Error::InvalidArgument);
        }
        if offset as usize >= MAX_SLOTS_PER_AREA {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { device_id, offset })
    }

    /// The swap area index.
    pub const fn device_id(self) -> u8 {
        self.device_id
    }

    /// The slot offset within the swap area.
    pub const fn offset(self) -> u32 {
        self.offset
    }

    /// Encode the entry as a single `u64` for compact storage.
    ///
    /// Layout: `[device_id: 8 bits][offset: 32 bits][reserved: 24]`.
    pub const fn as_u64(self) -> u64 {
        ((self.device_id as u64) << 56) | ((self.offset as u64) << 24)
    }

    /// Decode from a `u64` produced by [`as_u64`].
    ///
    /// Returns `Err(InvalidArgument)` if the encoded values are
    /// out of range.
    pub const fn from_u64(val: u64) -> Result<Self> {
        let dev = (val >> 56) as u8;
        let off = ((val >> 24) & 0xFFFF_FFFF) as u32;
        Self::new(dev, off)
    }
}

// ── SwapSlotAllocator ───────────────────────────────────────────

/// Bitmap-based swap slot allocator.
///
/// Manages up to [`MAX_SLOTS_PER_AREA`] slots using a fixed-size
/// bitmap. Bit `1` = allocated, bit `0` = free.
pub struct SwapSlotAllocator {
    /// Bitmap storage: one bit per slot.
    bitmap: [u64; BITMAP_WORDS],
    /// Total number of slots managed.
    total_slots: usize,
    /// Number of currently free slots.
    free_count: usize,
}

impl SwapSlotAllocator {
    /// Create a new allocator managing `slot_count` slots.
    ///
    /// All slots start as free. `slot_count` is clamped to
    /// [`MAX_SLOTS_PER_AREA`].
    pub const fn new(slot_count: usize) -> Self {
        let total = if slot_count > MAX_SLOTS_PER_AREA {
            MAX_SLOTS_PER_AREA
        } else {
            slot_count
        };
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            total_slots: total,
            free_count: total,
        }
    }

    /// Allocate a single swap slot.
    ///
    /// Returns the slot index, or `Err(OutOfMemory)` if no free
    /// slots remain.
    pub fn alloc(&mut self) -> Result<u32> {
        let words_needed = words_for(self.total_slots);
        for (word_idx, word) in self.bitmap[..words_needed].iter_mut().enumerate() {
            if *word == !0u64 {
                continue;
            }
            let bit = (*word).trailing_ones() as usize;
            let slot = word_idx * 64 + bit;
            if slot >= self.total_slots {
                return Err(Error::OutOfMemory);
            }
            *word |= 1 << bit;
            self.free_count = self.free_count.saturating_sub(1);
            return Ok(slot as u32);
        }
        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated swap slot.
    ///
    /// Returns `Err(InvalidArgument)` if the slot index is out of
    /// range or the slot is already free.
    pub fn free(&mut self, slot: u32) -> Result<()> {
        let idx = slot as usize;
        if idx >= self.total_slots {
            return Err(Error::InvalidArgument);
        }
        let word = idx / 64;
        let bit = idx % 64;
        if self.bitmap[word] & (1 << bit) == 0 {
            return Err(Error::InvalidArgument);
        }
        self.bitmap[word] &= !(1 << bit);
        self.free_count += 1;
        Ok(())
    }

    /// Number of free slots.
    pub const fn free_count(&self) -> usize {
        self.free_count
    }

    /// Total slots managed.
    pub const fn total_slots(&self) -> usize {
        self.total_slots
    }

    /// Check whether a specific slot is allocated.
    pub fn is_allocated(&self, slot: u32) -> bool {
        let idx = slot as usize;
        if idx >= self.total_slots {
            return false;
        }
        let word = idx / 64;
        let bit = idx % 64;
        self.bitmap[word] & (1 << bit) != 0
    }
}

impl Default for SwapSlotAllocator {
    fn default() -> Self {
        Self::new(MAX_SLOTS_PER_AREA)
    }
}

/// Number of `u64` words needed to cover `n` slots.
const fn words_for(n: usize) -> usize {
    n.div_ceil(64)
}

// ── SwapArea ────────────────────────────────────────────────────

/// Maximum length of a swap area path (device path or file path).
const MAX_PATH_LEN: usize = 64;

/// A single swap device or file.
///
/// Contains the device path, priority, capacity, and a slot
/// allocator that tracks which slots are in use.
pub struct SwapArea {
    /// Path to the swap device or file (null-terminated bytes).
    path: [u8; MAX_PATH_LEN],
    /// Length of the path string in bytes.
    path_len: usize,
    /// Priority (higher = preferred for allocation).
    priority: i16,
    /// Whether this area is currently active.
    active: bool,
    /// Bitmap-based slot allocator for this area.
    allocator: SwapSlotAllocator,
}

impl SwapArea {
    /// Create a new swap area with the given path, slot count,
    /// and priority.
    ///
    /// The area starts inactive; use [`SwapTable::swapon`] to
    /// enable it. `slot_count` is clamped to
    /// [`MAX_SLOTS_PER_AREA`].
    ///
    /// Returns `Err(InvalidArgument)` if the path is empty or
    /// exceeds [`MAX_PATH_LEN`].
    pub fn new(path: &[u8], slot_count: usize, priority: i16) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_PATH_LEN];
        buf[..path.len()].copy_from_slice(path);
        Ok(Self {
            path: buf,
            path_len: path.len(),
            priority,
            active: false,
            allocator: SwapSlotAllocator::new(slot_count),
        })
    }

    /// The path bytes for this swap area.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Priority of this swap area.
    pub const fn priority(&self) -> i16 {
        self.priority
    }

    /// Whether this area is currently active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Total number of slots in this area.
    pub const fn total_slots(&self) -> usize {
        self.allocator.total_slots()
    }

    /// Number of free slots in this area.
    pub const fn free_slots(&self) -> usize {
        self.allocator.free_count()
    }

    /// Number of used slots in this area.
    pub const fn used_slots(&self) -> usize {
        self.allocator.total_slots() - self.allocator.free_count()
    }
}

// ── SwapStats ───────────────────────────────────────────────────

/// Swap I/O and usage counters.
///
/// Tracks swap-in/swap-out operations and per-area slot usage
/// for monitoring and diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct SwapStats {
    /// Total number of pages swapped in.
    pub swap_in_count: u64,
    /// Total number of pages swapped out.
    pub swap_out_count: u64,
    /// Pages currently used in each swap area.
    pub pages_used: [u64; MAX_SWAP_AREAS],
    /// Pages currently free in each swap area.
    pub pages_free: [u64; MAX_SWAP_AREAS],
}

impl SwapStats {
    /// Create zeroed swap statistics.
    pub const fn new() -> Self {
        Self {
            swap_in_count: 0,
            swap_out_count: 0,
            pages_used: [0; MAX_SWAP_AREAS],
            pages_free: [0; MAX_SWAP_AREAS],
        }
    }
}

impl Default for SwapStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── SwapCache ───────────────────────────────────────────────────

/// A single entry in the swap cache.
#[derive(Clone, Copy)]
struct SwapCacheEntry {
    /// The swap entry this cached page corresponds to.
    entry: SwapEntry,
    /// Cached page data (4 KiB).
    data: [u8; PAGE_SIZE],
    /// Whether this cache slot is occupied.
    valid: bool,
}

impl SwapCacheEntry {
    /// Create an empty (invalid) cache entry.
    const fn empty() -> Self {
        Self {
            entry: SwapEntry {
                device_id: 0,
                offset: 0,
            },
            data: [0u8; PAGE_SIZE],
            valid: false,
        }
    }
}

/// Cache of recently swapped pages.
///
/// Avoids redundant disk I/O by keeping up to
/// [`SWAP_CACHE_SIZE`] recently swapped pages in memory.
/// Uses FIFO eviction when the cache is full.
pub struct SwapCache {
    /// Cache entries.
    entries: [SwapCacheEntry; SWAP_CACHE_SIZE],
    /// Number of valid entries.
    count: usize,
    /// Next slot to write (FIFO eviction pointer).
    next_slot: usize,
}

impl SwapCache {
    /// Create a new empty swap cache.
    pub const fn new() -> Self {
        Self {
            entries: [SwapCacheEntry::empty(); SWAP_CACHE_SIZE],
            count: 0,
            next_slot: 0,
        }
    }

    /// Look up a swap entry in the cache.
    ///
    /// Returns a reference to the cached page data if found,
    /// avoiding a disk read. Returns `None` on cache miss.
    pub fn lookup(&self, entry: &SwapEntry) -> Option<&[u8]> {
        for e in &self.entries {
            if e.valid && e.entry == *entry {
                return Some(&e.data);
            }
        }
        None
    }

    /// Insert a page into the cache.
    ///
    /// If the cache is full, the oldest entry is evicted (FIFO).
    /// `data` must be exactly [`PAGE_SIZE`] bytes.
    ///
    /// Returns `Err(InvalidArgument)` if `data` length does not
    /// match `PAGE_SIZE`.
    pub fn insert(&mut self, entry: SwapEntry, data: &[u8]) -> Result<()> {
        if data.len() != PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Overwrite existing entry for the same swap slot.
        for e in &mut self.entries {
            if e.valid && e.entry == entry {
                e.data.copy_from_slice(data);
                return Ok(());
            }
        }
        // FIFO eviction: write to the next slot.
        let slot = self.next_slot;
        if !self.entries[slot].valid {
            self.count += 1;
        }
        self.entries[slot].entry = entry;
        self.entries[slot].data.copy_from_slice(data);
        self.entries[slot].valid = true;
        self.next_slot = (slot + 1) % SWAP_CACHE_SIZE;
        Ok(())
    }

    /// Invalidate (remove) a cached entry for the given swap slot.
    ///
    /// Returns `true` if an entry was removed, `false` if not
    /// found.
    pub fn invalidate(&mut self, entry: &SwapEntry) -> bool {
        for e in &mut self.entries {
            if e.valid && e.entry == *entry {
                e.valid = false;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Number of valid entries in the cache.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SwapCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── SwapPolicy (LRU) ───────────────────────────────────────────

/// An entry in the LRU access tracker.
#[derive(Debug, Clone, Copy)]
struct LruEntry {
    /// The frame being tracked.
    frame: Frame,
    /// Monotonic access counter (higher = more recently used).
    access_tick: u64,
    /// Whether this tracker slot is occupied.
    valid: bool,
}

impl LruEntry {
    /// Create an empty tracker entry.
    const fn empty() -> Self {
        Self {
            frame: Frame::from_number(0),
            access_tick: 0,
            valid: false,
        }
    }
}

/// LRU-based swap-out victim selection policy.
///
/// Maintains a fixed-size access log of page frames. When a
/// swap-out victim is needed, the least recently accessed frame
/// is selected.
pub struct SwapPolicy {
    /// Access log entries.
    entries: [LruEntry; LRU_MAX_ENTRIES],
    /// Number of valid entries.
    count: usize,
    /// Monotonic tick counter.
    tick: u64,
}

impl SwapPolicy {
    /// Create a new empty LRU policy tracker.
    pub const fn new() -> Self {
        Self {
            entries: [LruEntry::empty(); LRU_MAX_ENTRIES],
            count: 0,
            tick: 0,
        }
    }

    /// Record an access to the given page frame.
    ///
    /// Updates the frame's access tick. If the frame is not yet
    /// tracked and the log is full, the least recently used entry
    /// is evicted to make room.
    pub fn record_access(&mut self, frame: Frame) {
        self.tick += 1;
        // Update existing entry if present.
        for e in &mut self.entries {
            if e.valid && e.frame == frame {
                e.access_tick = self.tick;
                return;
            }
        }
        // Find an empty slot.
        for e in &mut self.entries {
            if !e.valid {
                e.frame = frame;
                e.access_tick = self.tick;
                e.valid = true;
                self.count += 1;
                return;
            }
        }
        // Evict LRU entry and reuse its slot.
        let lru_idx = self.find_lru_index();
        self.entries[lru_idx].frame = frame;
        self.entries[lru_idx].access_tick = self.tick;
    }

    /// Remove a frame from tracking (e.g., after swap-out).
    pub fn remove(&mut self, frame: Frame) {
        for e in &mut self.entries {
            if e.valid && e.frame == frame {
                e.valid = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Select the least recently used frame as a swap-out victim.
    ///
    /// Returns `None` if no frames are being tracked.
    pub fn select_victim(&self) -> Option<Frame> {
        if self.count == 0 {
            return None;
        }
        let idx = self.find_lru_index();
        if self.entries[idx].valid {
            Some(self.entries[idx].frame)
        } else {
            None
        }
    }

    /// Number of frames currently tracked.
    pub const fn tracked_count(&self) -> usize {
        self.count
    }

    /// Find the index of the least recently used valid entry.
    fn find_lru_index(&self) -> usize {
        let mut min_tick = u64::MAX;
        let mut min_idx = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if e.valid && e.access_tick < min_tick {
                min_tick = e.access_tick;
                min_idx = i;
            }
        }
        min_idx
    }
}

impl Default for SwapPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ── SwapTable ───────────────────────────────────────────────────

/// Priority-ordered collection of swap areas.
///
/// Manages up to [`MAX_SWAP_AREAS`] swap devices/files. Slot
/// allocation prefers the active area with the highest priority.
pub struct SwapTable {
    /// Swap areas (indexed by device_id).
    areas: [Option<SwapArea>; MAX_SWAP_AREAS],
    /// Number of registered areas.
    area_count: usize,
    /// Swap cache for recently paged data.
    cache: SwapCache,
    /// Swap I/O and usage statistics.
    stats: SwapStats,
    /// LRU policy for victim selection.
    policy: SwapPolicy,
}

impl SwapTable {
    /// Create a new empty swap table.
    pub const fn new() -> Self {
        const NONE_AREA: Option<SwapArea> = None;
        Self {
            areas: [NONE_AREA; MAX_SWAP_AREAS],
            area_count: 0,
            cache: SwapCache::new(),
            stats: SwapStats::new(),
            policy: SwapPolicy::new(),
        }
    }

    /// Enable a swap area and add it to the table.
    ///
    /// This is the `swapon` operation. The area is inserted into
    /// the first free slot and marked active.
    ///
    /// Returns the device_id assigned to the area.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` — all swap area slots are occupied.
    /// - `AlreadyExists` — an area with the same path is already
    ///   registered.
    pub fn swapon(&mut self, mut area: SwapArea) -> Result<u8> {
        // Check for duplicate path.
        for existing in self.areas.iter().flatten() {
            if existing.path() == area.path() {
                return Err(Error::AlreadyExists);
            }
        }
        // Find a free slot.
        for (i, slot) in self.areas.iter_mut().enumerate() {
            if slot.is_none() {
                area.active = true;
                let total = area.total_slots() as u64;
                *slot = Some(area);
                self.area_count += 1;
                self.stats.pages_free[i] = total;
                self.stats.pages_used[i] = 0;
                return Ok(i as u8);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Disable and remove a swap area by device_id.
    ///
    /// This is the `swapoff` operation. The area must have no
    /// allocated slots (all pages must be swapped back in first).
    ///
    /// # Errors
    ///
    /// - `NotFound` — no area at the given device_id.
    /// - `Busy` — the area still has allocated swap slots.
    pub fn swapoff(&mut self, device_id: u8) -> Result<()> {
        let idx = device_id as usize;
        if idx >= MAX_SWAP_AREAS {
            return Err(Error::InvalidArgument);
        }
        let area = self.areas[idx].as_ref().ok_or(Error::NotFound)?;
        if area.used_slots() > 0 {
            return Err(Error::Busy);
        }
        self.areas[idx] = None;
        self.area_count = self.area_count.saturating_sub(1);
        self.stats.pages_free[idx] = 0;
        self.stats.pages_used[idx] = 0;
        Ok(())
    }

    /// Allocate a swap slot from the highest-priority active area.
    ///
    /// Returns a [`SwapEntry`] identifying the allocated slot.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` — no active area has free slots.
    fn alloc_slot(&mut self) -> Result<SwapEntry> {
        // Collect (index, priority) of active areas with free space,
        // then pick the one with the highest priority.
        let mut best_idx: Option<usize> = None;
        let mut best_pri = i16::MIN;
        for (i, slot) in self.areas.iter().enumerate() {
            if let Some(area) = slot {
                if area.is_active() && area.free_slots() > 0 && area.priority() > best_pri {
                    best_pri = area.priority();
                    best_idx = Some(i);
                }
            }
        }
        let idx = best_idx.ok_or(Error::OutOfMemory)?;
        let area = self.areas[idx].as_mut().ok_or(Error::OutOfMemory)?;
        let offset = area.allocator.alloc()?;
        self.stats.pages_used[idx] += 1;
        self.stats.pages_free[idx] = self.stats.pages_free[idx].saturating_sub(1);
        SwapEntry::new(idx as u8, offset)
    }

    /// Free a previously allocated swap slot.
    fn free_slot(&mut self, entry: &SwapEntry) -> Result<()> {
        let idx = entry.device_id() as usize;
        let area = self.areas[idx].as_mut().ok_or(Error::NotFound)?;
        area.allocator.free(entry.offset())?;
        self.stats.pages_used[idx] = self.stats.pages_used[idx].saturating_sub(1);
        self.stats.pages_free[idx] += 1;
        Ok(())
    }

    /// Swap out a page frame to secondary storage.
    ///
    /// Selects a victim frame via the LRU policy (or uses the
    /// provided `page_frame` directly), allocates a swap slot,
    /// stores the page data in the swap cache, and returns the
    /// resulting [`SwapEntry`].
    ///
    /// The `page_data` slice must be exactly [`PAGE_SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — `page_data` is not `PAGE_SIZE` bytes.
    /// - `OutOfMemory` — no swap slot available.
    pub fn swap_out_page(&mut self, page_frame: Frame, page_data: &[u8]) -> Result<SwapEntry> {
        if page_data.len() != PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let entry = self.alloc_slot()?;
        // Cache the page data so a subsequent swap_in can avoid
        // actual disk I/O if the page is accessed soon.
        self.cache.insert(entry, page_data)?;
        self.policy.remove(page_frame);
        self.stats.swap_out_count += 1;
        Ok(entry)
    }

    /// Swap in a page from secondary storage.
    ///
    /// Looks up the swap cache first; on a miss the caller must
    /// arrange actual disk I/O (this implementation returns the
    /// cached data or `Err(IoError)` to signal that a real read
    /// is needed).
    ///
    /// On success, copies the page data into `buf` (which must be
    /// at least [`PAGE_SIZE`] bytes) and frees the swap slot.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — `buf` is smaller than `PAGE_SIZE`.
    /// - `IoError` — page not in cache; real I/O required.
    /// - `NotFound` — swap slot not allocated.
    pub fn swap_in_page(&mut self, entry: &SwapEntry, buf: &mut [u8]) -> Result<()> {
        if buf.len() < PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Check cache first.
        let data = self.cache.lookup(entry).ok_or(Error::IoError)?;
        buf[..PAGE_SIZE].copy_from_slice(data);
        self.cache.invalidate(entry);
        self.free_slot(entry)?;
        self.stats.swap_in_count += 1;
        Ok(())
    }

    /// Record a page frame access for LRU tracking.
    pub fn record_access(&mut self, frame: Frame) {
        self.policy.record_access(frame);
    }

    /// Select a victim page frame for swap-out using LRU policy.
    ///
    /// Returns `None` if no candidate frames are tracked.
    pub fn select_victim(&self) -> Option<Frame> {
        self.policy.select_victim()
    }

    /// Current swap statistics.
    pub const fn stats(&self) -> &SwapStats {
        &self.stats
    }

    /// Number of registered swap areas.
    pub const fn area_count(&self) -> usize {
        self.area_count
    }

    /// Reference to the swap cache.
    pub const fn cache(&self) -> &SwapCache {
        &self.cache
    }

    /// Get a reference to a swap area by device id.
    pub fn area(&self, device_id: u8) -> Option<&SwapArea> {
        let idx = device_id as usize;
        if idx >= MAX_SWAP_AREAS {
            return None;
        }
        self.areas[idx].as_ref()
    }

    /// Total free swap slots across all active areas.
    pub fn total_free_slots(&self) -> usize {
        self.areas
            .iter()
            .filter_map(|a| a.as_ref())
            .filter(|a| a.is_active())
            .map(|a| a.free_slots())
            .sum()
    }

    /// Total swap slots across all active areas.
    pub fn total_slots(&self) -> usize {
        self.areas
            .iter()
            .filter_map(|a| a.as_ref())
            .filter(|a| a.is_active())
            .map(|a| a.total_slots())
            .sum()
    }
}

impl Default for SwapTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free functions: swapon / swapoff ────────────────────────────

/// Enable a swap area on the given swap table.
///
/// Convenience wrapper around [`SwapTable::swapon`].
pub fn swapon(table: &mut SwapTable, area: SwapArea) -> Result<u8> {
    table.swapon(area)
}

/// Disable a swap area on the given swap table.
///
/// Convenience wrapper around [`SwapTable::swapoff`].
pub fn swapoff(table: &mut SwapTable, device_id: u8) -> Result<()> {
    table.swapoff(device_id)
}

/// Swap out a page frame.
///
/// Convenience wrapper around [`SwapTable::swap_out_page`].
pub fn swap_out_page(
    table: &mut SwapTable,
    page_frame: Frame,
    page_data: &[u8],
) -> Result<SwapEntry> {
    table.swap_out_page(page_frame, page_data)
}

/// Swap in a page from the given swap entry.
///
/// Convenience wrapper around [`SwapTable::swap_in_page`].
pub fn swap_in_page(table: &mut SwapTable, entry: &SwapEntry, buf: &mut [u8]) -> Result<()> {
    table.swap_in_page(entry, buf)
}
