// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-task VMA lookup cache (vmacache).
//!
//! Every thread keeps a small, per-CPU cache of recently looked-up
//! VMAs so that repeated accesses to the same virtual address range
//! (e.g., successive page faults in the same mapping) bypass the
//! full VMA tree walk.
//!
//! The cache is a direct-mapped array indexed by a hash of the
//! faulting address. A sequence number is stored alongside each
//! cache entry and compared against the mm-level sequence counter
//! that increments on every VMA insertion, removal, or mutation.
//! A mismatch invalidates the cache entry without an explicit flush.
//!
//! # Architecture
//!
//! - [`VmaCacheEntry`] — one slot: VMA descriptor + sequence number
//! - [`VmaDescriptor`] — lightweight snapshot of a VMA (start, end,
//!   prot, flags)
//! - [`PerTaskVmaCache`] — per-task cache with `CACHE_SIZE` slots
//! - [`VmaCacheTable`] — system-wide table of per-task caches
//! - [`VmaCacheStats`] — hit/miss/invalidation counters
//! - [`VmaCacheSubsystem`] — top-level subsystem entry point
//!
//! Reference: Linux `include/linux/vmacache.h`, `mm/vmacache.c`.
//! (Note: Linux 6.1+ replaced vmacache with per-VMA maple tree
//! lookup, but the concept remains instructive.)

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of cache slots per task (must be a power of two).
const CACHE_SIZE: usize = 4;

/// Maximum number of tasks whose caches we track.
const MAX_TASKS: usize = 256;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Sequence number that means "never valid".
const SEQ_INVALID: u64 = 0;

/// Maximum VMA flags value.
const VMA_FLAG_MASK: u32 = 0x0001_FFFF;

/// Protection: readable.
const PROT_READ: u8 = 1 << 0;

/// Protection: writable.
const PROT_WRITE: u8 = 1 << 1;

/// Protection: executable.
const PROT_EXEC: u8 = 1 << 2;

/// VMA flag: anonymous mapping.
const VMA_ANON: u32 = 1 << 0;

/// VMA flag: shared mapping.
const VMA_SHARED: u32 = 1 << 1;

/// VMA flag: locked in memory.
const VMA_LOCKED: u32 = 1 << 3;

/// VMA flag: huge-page backed.
const VMA_HUGEPAGE: u32 = 1 << 4;

// -------------------------------------------------------------------
// VmaDescriptor
// -------------------------------------------------------------------

/// Lightweight snapshot of a VMA used inside the cache.
///
/// This is not the authoritative VMA record — it is a copy taken at
/// cache-fill time. Validity is ensured by the sequence number.
#[derive(Debug, Clone, Copy)]
pub struct VmaDescriptor {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// Protection bits (PROT_READ | PROT_WRITE | PROT_EXEC).
    pub prot: u8,
    /// VMA flags (anonymous, shared, locked, ...).
    pub flags: u32,
    /// Backing file inode (0 = anonymous).
    pub inode: u64,
    /// Offset within the backing file (in pages).
    pub file_pgoff: u64,
    /// Whether this descriptor is populated.
    pub valid: bool,
}

impl VmaDescriptor {
    /// Create an empty (invalid) descriptor.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            prot: 0,
            flags: 0,
            inode: 0,
            file_pgoff: 0,
            valid: false,
        }
    }

    /// Check whether `addr` falls inside this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        self.valid && addr >= self.start && addr < self.end
    }

    /// Size of the VMA in bytes.
    pub fn size(&self) -> u64 {
        if self.valid {
            self.end.saturating_sub(self.start)
        } else {
            0
        }
    }

    /// Size of the VMA in pages.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Whether the VMA is anonymous.
    pub fn is_anonymous(&self) -> bool {
        self.flags & VMA_ANON != 0
    }

    /// Whether the VMA is shared.
    pub fn is_shared(&self) -> bool {
        self.flags & VMA_SHARED != 0
    }

    /// Whether the VMA is locked (mlocked).
    pub fn is_locked(&self) -> bool {
        self.flags & VMA_LOCKED != 0
    }
}

impl Default for VmaDescriptor {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// VmaCacheEntry
// -------------------------------------------------------------------

/// One cache slot — holds a VMA snapshot and the mm sequence number
/// at the time the snapshot was taken.
#[derive(Debug, Clone, Copy)]
pub struct VmaCacheEntry {
    /// Cached VMA descriptor.
    pub vma: VmaDescriptor,
    /// Sequence number of the mm when this entry was filled.
    pub seq: u64,
}

impl VmaCacheEntry {
    /// Create an empty (invalid) entry.
    const fn empty() -> Self {
        Self {
            vma: VmaDescriptor::empty(),
            seq: SEQ_INVALID,
        }
    }

    /// Whether this entry is usable given the current mm sequence.
    pub fn is_valid(&self, current_seq: u64) -> bool {
        self.vma.valid && self.seq == current_seq
    }

    /// Fill this entry with a new VMA snapshot.
    pub fn fill(&mut self, vma: VmaDescriptor, seq: u64) {
        self.vma = vma;
        self.seq = seq;
    }

    /// Invalidate this entry.
    pub fn invalidate(&mut self) {
        self.vma.valid = false;
        self.seq = SEQ_INVALID;
    }
}

impl Default for VmaCacheEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PerTaskVmaCache
// -------------------------------------------------------------------

/// Per-task VMA cache.
///
/// Each task holds `CACHE_SIZE` cache slots. Lookup hashes the
/// virtual address to pick a slot. If the slot's sequence number
/// matches the current mm sequence, the cached VMA is returned
/// without walking the VMA tree.
#[derive(Debug, Clone, Copy)]
pub struct PerTaskVmaCache {
    /// Task (thread) identifier.
    pub task_id: u64,
    /// Memory space identifier.
    pub mm_id: u64,
    /// Cache slots.
    entries: [VmaCacheEntry; CACHE_SIZE],
    /// Whether this cache is active.
    pub active: bool,
    /// Number of lookups performed.
    pub lookups: u64,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of times the cache was invalidated.
    pub invalidations: u64,
}

impl PerTaskVmaCache {
    /// Create an empty per-task cache.
    const fn empty() -> Self {
        Self {
            task_id: 0,
            mm_id: 0,
            entries: [const { VmaCacheEntry::empty() }; CACHE_SIZE],
            active: false,
            lookups: 0,
            hits: 0,
            misses: 0,
            invalidations: 0,
        }
    }

    /// Hash an address to a cache slot index.
    fn slot(addr: u64) -> usize {
        // Shift by PAGE_SHIFT (12) then mask to CACHE_SIZE-1.
        ((addr >> 12) as usize) & (CACHE_SIZE - 1)
    }

    /// Look up `addr` in the cache.
    ///
    /// Returns the cached VMA descriptor if the slot is valid and
    /// the address falls within the cached range.
    pub fn lookup(&mut self, addr: u64, current_seq: u64) -> Option<VmaDescriptor> {
        if !self.active {
            return None;
        }
        self.lookups = self.lookups.saturating_add(1);

        let idx = Self::slot(addr);
        let entry = &self.entries[idx];
        if entry.is_valid(current_seq) && entry.vma.contains(addr) {
            self.hits = self.hits.saturating_add(1);
            Some(entry.vma)
        } else {
            self.misses = self.misses.saturating_add(1);
            None
        }
    }

    /// Insert a VMA snapshot into the cache at the slot determined
    /// by `vma.start`.
    pub fn update(&mut self, vma: VmaDescriptor, seq: u64) {
        if !self.active {
            return;
        }
        let idx = Self::slot(vma.start);
        self.entries[idx].fill(vma, seq);
    }

    /// Invalidate all cache entries (e.g., after munmap or mprotect).
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            entry.invalidate();
        }
        self.invalidations = self.invalidations.saturating_add(1);
    }

    /// Invalidate entries that overlap with `[start, end)`.
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        for entry in &mut self.entries {
            if entry.vma.valid && entry.vma.start < end && entry.vma.end > start {
                entry.invalidate();
            }
        }
        self.invalidations = self.invalidations.saturating_add(1);
    }

    /// Hit rate as a percentage (0..100).
    pub fn hit_rate(&self) -> u64 {
        if self.lookups == 0 {
            return 0;
        }
        (self.hits * 100) / self.lookups
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.lookups = 0;
        self.hits = 0;
        self.misses = 0;
        self.invalidations = 0;
    }
}

impl Default for PerTaskVmaCache {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// VmaCacheTable
// -------------------------------------------------------------------

/// System-wide table of per-task VMA caches.
///
/// Manages up to `MAX_TASKS` caches. Tasks are registered when they
/// first perform a VMA lookup and unregistered on exit.
pub struct VmaCacheTable {
    /// Per-task caches, indexed by internal slot (not by task_id).
    caches: [PerTaskVmaCache; MAX_TASKS],
    /// Number of active caches.
    active_count: usize,
    /// Global generation counter. Incremented on every mm mutation
    /// (mmap, munmap, mprotect, ...). Each mm has its own counter
    /// but we use a single global counter for simplicity.
    generation: u64,
}

impl VmaCacheTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            caches: [const { PerTaskVmaCache::empty() }; MAX_TASKS],
            active_count: 0,
            generation: 1, // start at 1 so that SEQ_INVALID (0) !=
        }
    }

    /// Register a task and return its slot index.
    pub fn register_task(&mut self, task_id: u64, mm_id: u64) -> Result<usize> {
        // Check for duplicate.
        for cache in self.caches.iter().take(self.active_count) {
            if cache.active && cache.task_id == task_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.active_count >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.active_count;
        self.caches[idx].task_id = task_id;
        self.caches[idx].mm_id = mm_id;
        self.caches[idx].active = true;
        self.caches[idx].invalidate_all();
        self.active_count += 1;
        Ok(idx)
    }

    /// Unregister a task and compact the table.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        let pos = self
            .caches
            .iter()
            .take(self.active_count)
            .position(|c| c.active && c.task_id == task_id)
            .ok_or(Error::NotFound)?;

        // Swap-remove with last active entry.
        self.active_count -= 1;
        if pos < self.active_count {
            self.caches[pos] = self.caches[self.active_count];
        }
        self.caches[self.active_count] = PerTaskVmaCache::empty();
        Ok(())
    }

    /// Lookup a VMA for a given task and address.
    pub fn lookup(&mut self, task_id: u64, addr: u64) -> Result<Option<VmaDescriptor>> {
        let cache = self
            .caches
            .iter_mut()
            .take(self.active_count)
            .find(|c| c.active && c.task_id == task_id)
            .ok_or(Error::NotFound)?;
        Ok(cache.lookup(addr, self.generation))
    }

    /// Fill a cache entry for a task.
    pub fn update(&mut self, task_id: u64, vma: VmaDescriptor) -> Result<()> {
        let cache = self
            .caches
            .iter_mut()
            .take(self.active_count)
            .find(|c| c.active && c.task_id == task_id)
            .ok_or(Error::NotFound)?;
        cache.update(vma, self.generation);
        Ok(())
    }

    /// Bump the generation counter. All cached entries that do not
    /// carry the new generation become stale on next lookup.
    pub fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == SEQ_INVALID {
            self.generation = 1;
        }
    }

    /// Invalidate all caches for a specific mm.
    pub fn invalidate_mm(&mut self, mm_id: u64) {
        for cache in self.caches.iter_mut().take(self.active_count) {
            if cache.active && cache.mm_id == mm_id {
                cache.invalidate_all();
            }
        }
        self.bump_generation();
    }

    /// Invalidate a range across all caches for a given mm.
    pub fn invalidate_range(&mut self, mm_id: u64, start: u64, end: u64) {
        for cache in self.caches.iter_mut().take(self.active_count) {
            if cache.active && cache.mm_id == mm_id {
                cache.invalidate_range(start, end);
            }
        }
    }

    /// Current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of active task caches.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Get cache statistics for a task.
    pub fn task_stats(&self, task_id: u64) -> Result<(u64, u64, u64, u64)> {
        let cache = self
            .caches
            .iter()
            .take(self.active_count)
            .find(|c| c.active && c.task_id == task_id)
            .ok_or(Error::NotFound)?;
        Ok((cache.lookups, cache.hits, cache.misses, cache.invalidations))
    }
}

impl Default for VmaCacheTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmaCacheStats
// -------------------------------------------------------------------

/// Aggregate statistics across all per-task VMA caches.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaCacheStats {
    /// Total number of lookups.
    pub total_lookups: u64,
    /// Total cache hits.
    pub total_hits: u64,
    /// Total cache misses.
    pub total_misses: u64,
    /// Total invalidations.
    pub total_invalidations: u64,
    /// Number of active caches.
    pub active_caches: u64,
    /// Global generation counter.
    pub generation: u64,
    /// Aggregate hit rate (0..100).
    pub hit_rate: u64,
}

// -------------------------------------------------------------------
// VmaCacheSubsystem
// -------------------------------------------------------------------

/// Top-level VMA cache subsystem.
///
/// Wraps [`VmaCacheTable`] and provides the public API for the rest
/// of the kernel to interact with the VMA cache.
pub struct VmaCacheSubsystem {
    /// The underlying cache table.
    table: VmaCacheTable,
    /// Whether the subsystem has been initialised.
    initialised: bool,
}

impl VmaCacheSubsystem {
    /// Create a new, uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            table: VmaCacheTable::new(),
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a task for VMA caching.
    pub fn register_task(&mut self, task_id: u64, mm_id: u64) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.register_task(task_id, mm_id)
    }

    /// Unregister a task.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.unregister_task(task_id)
    }

    /// Look up a VMA for the calling task.
    pub fn lookup(&mut self, task_id: u64, addr: u64) -> Result<Option<VmaDescriptor>> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.lookup(task_id, addr)
    }

    /// Fill the cache after a successful tree lookup.
    pub fn update(&mut self, task_id: u64, vma: VmaDescriptor) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.update(task_id, vma)
    }

    /// Notify the cache that the VMA tree for `mm_id` has changed.
    ///
    /// Call this after every mmap / munmap / mprotect / mremap.
    pub fn notify_mm_change(&mut self, mm_id: u64) {
        if !self.initialised {
            return;
        }
        self.table.invalidate_mm(mm_id);
    }

    /// Notify the cache that a specific range changed.
    pub fn notify_range_change(&mut self, mm_id: u64, start: u64, end: u64) {
        if !self.initialised {
            return;
        }
        self.table.invalidate_range(mm_id, start, end);
    }

    /// Collect aggregate statistics.
    pub fn stats(&self) -> VmaCacheStats {
        let mut s = VmaCacheStats {
            active_caches: self.table.active_count() as u64,
            generation: self.table.generation(),
            ..VmaCacheStats::default()
        };
        for cache in self.table.caches.iter() {
            if !cache.active {
                continue;
            }
            s.total_lookups = s.total_lookups.saturating_add(cache.lookups);
            s.total_hits = s.total_hits.saturating_add(cache.hits);
            s.total_misses = s.total_misses.saturating_add(cache.misses);
            s.total_invalidations = s.total_invalidations.saturating_add(cache.invalidations);
        }
        if s.total_lookups > 0 {
            s.hit_rate = (s.total_hits * 100) / s.total_lookups;
        }
        s
    }

    /// Whether the subsystem has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for VmaCacheSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmaCacheBatchOp
// -------------------------------------------------------------------

/// Descriptor for a batch cache operation.
#[derive(Debug, Clone, Copy)]
pub struct VmaCacheBatchOp {
    /// Task identifier.
    pub task_id: u64,
    /// Virtual address to look up / cache.
    pub addr: u64,
    /// VMA descriptor to insert (if any).
    pub vma: VmaDescriptor,
    /// Whether this is an insert (true) or lookup (false).
    pub is_insert: bool,
    /// Result of a lookup (filled on completion).
    pub result: Option<VmaDescriptor>,
    /// Whether this operation was successful.
    pub success: bool,
}

impl VmaCacheBatchOp {
    /// Create a lookup operation.
    pub const fn lookup(task_id: u64, addr: u64) -> Self {
        Self {
            task_id,
            addr,
            vma: VmaDescriptor::empty(),
            is_insert: false,
            result: None,
            success: false,
        }
    }

    /// Create an insert operation.
    pub const fn insert(task_id: u64, vma: VmaDescriptor) -> Self {
        Self {
            task_id,
            addr: vma.start,
            vma,
            is_insert: true,
            result: None,
            success: false,
        }
    }
}

impl Default for VmaCacheBatchOp {
    fn default() -> Self {
        Self::lookup(0, 0)
    }
}

// -------------------------------------------------------------------
// Batch processing
// -------------------------------------------------------------------

/// Maximum number of operations in a single batch.
const MAX_BATCH_OPS: usize = 64;

/// Execute a batch of cache operations.
///
/// Operations are processed in order. Each lookup/insert is executed
/// against the given subsystem. Results are written back into the
/// `ops` slice.
pub fn vmacache_batch_execute(
    subsys: &mut VmaCacheSubsystem,
    ops: &mut [VmaCacheBatchOp],
) -> Result<usize> {
    if ops.len() > MAX_BATCH_OPS {
        return Err(Error::InvalidArgument);
    }
    let mut completed = 0usize;
    for op in ops.iter_mut() {
        if op.is_insert {
            match subsys.update(op.task_id, op.vma) {
                Ok(()) => {
                    op.success = true;
                    completed += 1;
                }
                Err(_) => op.success = false,
            }
        } else {
            match subsys.lookup(op.task_id, op.addr) {
                Ok(vma) => {
                    op.result = vma;
                    op.success = true;
                    completed += 1;
                }
                Err(_) => op.success = false,
            }
        }
    }
    Ok(completed)
}

// -------------------------------------------------------------------
// Address hashing helpers
// -------------------------------------------------------------------

/// Hash a virtual address to a u64 value.
///
/// Uses a simple multiply-shift hash suitable for cache indexing.
pub fn vmacache_hash(addr: u64) -> u64 {
    let shifted = addr >> 12; // page-align
    // Golden-ratio-like constant for multiplicative hashing.
    shifted.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Determine whether two address ranges overlap.
pub fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Align an address down to the nearest page boundary.
pub fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Align an address up to the nearest page boundary.
pub fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// -------------------------------------------------------------------
// VmaCacheConfig
// -------------------------------------------------------------------

/// Configuration for the VMA cache subsystem.
#[derive(Debug, Clone, Copy)]
pub struct VmaCacheConfig {
    /// Whether to enable the cache at all.
    pub enabled: bool,
    /// Whether to collect per-task statistics.
    pub stats_enabled: bool,
    /// Whether to use range-based invalidation (vs full invalidation).
    pub range_invalidation: bool,
}

impl VmaCacheConfig {
    /// Default configuration.
    pub const fn default_config() -> Self {
        Self {
            enabled: true,
            stats_enabled: true,
            range_invalidation: true,
        }
    }
}

impl Default for VmaCacheConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// -------------------------------------------------------------------
// VmaCacheEvent
// -------------------------------------------------------------------

/// Events that the VMA cache produces for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaCacheEvent {
    /// A cache hit occurred.
    Hit {
        /// Task that performed the lookup.
        task_id: u64,
        /// Address looked up.
        addr: u64,
    },
    /// A cache miss occurred.
    Miss {
        /// Task that performed the lookup.
        task_id: u64,
        /// Address looked up.
        addr: u64,
    },
    /// A full cache invalidation was triggered.
    Invalidated {
        /// The mm whose cache was flushed.
        mm_id: u64,
    },
    /// A range invalidation was triggered.
    RangeInvalidated {
        /// The mm whose cache range was flushed.
        mm_id: u64,
        /// Start of the invalidated range.
        start: u64,
        /// End of the invalidated range.
        end: u64,
    },
    /// A task was registered.
    TaskRegistered {
        /// Task ID.
        task_id: u64,
    },
    /// A task was unregistered.
    TaskUnregistered {
        /// Task ID.
        task_id: u64,
    },
}

// -------------------------------------------------------------------
// VmaCacheEventLog
// -------------------------------------------------------------------

/// Ring-buffer event log for VMA cache diagnostics.
const EVENT_LOG_SIZE: usize = 128;

/// Ring-buffer of recent VMA cache events.
pub struct VmaCacheEventLog {
    /// Events buffer.
    events: [Option<VmaCacheEvent>; EVENT_LOG_SIZE],
    /// Write pointer (wraps around).
    head: usize,
    /// Total events logged (may exceed buffer size).
    total: u64,
}

impl VmaCacheEventLog {
    /// Create an empty event log.
    pub const fn new() -> Self {
        Self {
            events: [const { None }; EVENT_LOG_SIZE],
            head: 0,
            total: 0,
        }
    }

    /// Record an event.
    pub fn log(&mut self, event: VmaCacheEvent) {
        self.events[self.head] = Some(event);
        self.head = (self.head + 1) % EVENT_LOG_SIZE;
        self.total = self.total.saturating_add(1);
    }

    /// Total number of events recorded (including overwritten).
    pub fn total_events(&self) -> u64 {
        self.total
    }

    /// Get the most recent event, if any.
    pub fn last_event(&self) -> Option<VmaCacheEvent> {
        let idx = if self.head == 0 {
            EVENT_LOG_SIZE - 1
        } else {
            self.head - 1
        };
        self.events[idx]
    }

    /// Clear the log.
    pub fn clear(&mut self) {
        for slot in &mut self.events {
            *slot = None;
        }
        self.head = 0;
        self.total = 0;
    }
}

impl Default for VmaCacheEventLog {
    fn default() -> Self {
        Self::new()
    }
}
