// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stack trace depot for deduplicated storage.
//!
//! The stack depot stores unique stack traces in a hash table so
//! that subsystems (KASAN, page-owner, slub debug, etc.) can
//! reference a full backtrace via a compact 32-bit handle instead
//! of embedding the entire frame array.
//!
//! # Design
//!
//! ```text
//! StackDepot
//! ├── pool[MAX_ENTRIES]           flat entry storage
//! ├── buckets[HASH_BUCKETS]       hash table (each → chain head)
//! ├── next_handle                 monotonic handle counter
//! ├── stats: DepotStats
//! └── Methods:
//!     ├── store(frames)  → StackHandle   (insert or dedup)
//!     ├── fetch(handle)  → &[u64]        (lookup by handle)
//!     ├── lookup(frames) → Option<handle>(check if exists)
//!     └── memory_usage() → usize
//! ```
//!
//! # Handle Encoding
//!
//! `StackHandle(u32)` encodes the pool index directly. Handle 0
//! is reserved as the null/invalid sentinel.
//!
//! # Reference
//!
//! Linux `lib/stackdepot.c`, `include/linux/stackdepot.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum frames per stored stack trace.
const MAX_FRAMES: usize = 32;

/// Maximum unique stack traces the depot can hold.
const MAX_ENTRIES: usize = 2048;

/// Hash table bucket count (power of two).
const HASH_BUCKETS: usize = 512;

/// Mask for bucket index.
const HASH_MASK: usize = HASH_BUCKETS - 1;

/// Maximum chain length per bucket before rejecting.
const MAX_CHAIN_LEN: usize = 16;

// ══════════════════════════════════════════════════════════════
// StackHandle
// ══════════════════════════════════════════════════════════════

/// Compact 32-bit handle referencing a stored stack trace.
///
/// Handle 0 is the null sentinel and never refers to a valid entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackHandle(u32);

impl StackHandle {
    /// Create a handle from a raw value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw u32 value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Null (invalid) handle.
    pub const fn null() -> Self {
        Self(0)
    }

    /// Test whether this is the null handle.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl Default for StackHandle {
    fn default() -> Self {
        Self::null()
    }
}

// ══════════════════════════════════════════════════════════════
// DepotEntry
// ══════════════════════════════════════════════════════════════

/// A single stored stack trace in the depot pool.
#[derive(Clone)]
struct DepotEntry {
    /// Handle assigned to this trace.
    handle: StackHandle,
    /// Instruction-pointer frames.
    frames: [u64; MAX_FRAMES],
    /// Number of valid frames.
    frame_count: usize,
    /// Precomputed hash of the frame array.
    hash: u64,
    /// Index of the next entry in the same hash bucket chain,
    /// or `usize::MAX` for end-of-chain.
    chain_next: usize,
    /// Whether this pool slot is occupied.
    active: bool,
}

impl DepotEntry {
    /// Empty (inactive) entry.
    const fn empty() -> Self {
        Self {
            handle: StackHandle::null(),
            frames: [0u64; MAX_FRAMES],
            frame_count: 0,
            hash: 0,
            chain_next: usize::MAX,
            active: false,
        }
    }

    /// Return the stored frames as a slice.
    fn frames(&self) -> &[u64] {
        &self.frames[..self.frame_count]
    }
}

// ══════════════════════════════════════════════════════════════
// HashBucket
// ══════════════════════════════════════════════════════════════

/// A hash bucket storing the head of its chain.
#[derive(Clone, Copy)]
struct HashBucket {
    /// Pool index of the first entry in this chain, or
    /// `usize::MAX` if empty.
    head: usize,
    /// Number of entries chained in this bucket.
    count: u32,
}

impl HashBucket {
    const fn empty() -> Self {
        Self {
            head: usize::MAX,
            count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// DepotStats
// ══════════════════════════════════════════════════════════════

/// Aggregate statistics for the stack depot.
#[derive(Debug, Clone, Copy, Default)]
pub struct DepotStats {
    /// Total store() calls.
    pub store_calls: u64,
    /// Insertions (new unique traces).
    pub insertions: u64,
    /// Deduplications (existing trace found).
    pub dedup_hits: u64,
    /// Fetch calls.
    pub fetch_calls: u64,
    /// Failed fetches (invalid handle).
    pub fetch_misses: u64,
    /// Current number of stored entries.
    pub entry_count: u32,
    /// Maximum chain length observed.
    pub max_chain_len: u32,
}

// ══════════════════════════════════════════════════════════════
// StackDepot
// ══════════════════════════════════════════════════════════════

/// Hash-based deduplicated storage for stack traces.
pub struct StackDepot {
    /// Flat pool of depot entries.
    pool: [DepotEntry; MAX_ENTRIES],
    /// Hash buckets (each points to a chain of pool entries).
    buckets: [HashBucket; HASH_BUCKETS],
    /// Next pool slot to allocate.
    next_slot: usize,
    /// Next handle value to assign (starts at 1; 0 is null).
    next_handle: u32,
    /// Stats.
    stats: DepotStats,
    /// Whether the depot has been initialised.
    initialised: bool,
}

impl Default for StackDepot {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDepot {
    /// Create a new, uninitialised stack depot.
    pub const fn new() -> Self {
        Self {
            pool: [const { DepotEntry::empty() }; MAX_ENTRIES],
            buckets: [const { HashBucket::empty() }; HASH_BUCKETS],
            next_slot: 0,
            next_handle: 1,
            stats: DepotStats {
                store_calls: 0,
                insertions: 0,
                dedup_hits: 0,
                fetch_calls: 0,
                fetch_misses: 0,
                entry_count: 0,
                max_chain_len: 0,
            },
            initialised: false,
        }
    }

    /// Initialise the depot for use.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Store a stack trace. If an identical trace already exists,
    /// return its existing handle (deduplication). Otherwise
    /// allocate a new entry.
    pub fn store(&mut self, frames: &[u64]) -> Result<StackHandle> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        if frames.is_empty() {
            return Err(Error::InvalidArgument);
        }

        self.stats.store_calls += 1;

        let fcount = frames.len().min(MAX_FRAMES);
        let hash = hash_frames(&frames[..fcount]);
        let bucket_idx = (hash as usize) & HASH_MASK;

        // Search existing chain for a duplicate.
        if let Some(handle) = self.search_chain(bucket_idx, &frames[..fcount], hash) {
            self.stats.dedup_hits += 1;
            return Ok(handle);
        }

        // No duplicate — allocate a new entry.
        if self.next_slot >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let bucket = &self.buckets[bucket_idx];
        if bucket.count >= MAX_CHAIN_LEN as u32 {
            return Err(Error::OutOfMemory);
        }

        let slot = self.next_slot;
        let handle = StackHandle::new(self.next_handle);

        let entry = &mut self.pool[slot];
        entry.handle = handle;
        entry.frames[..fcount].copy_from_slice(&frames[..fcount]);
        entry.frame_count = fcount;
        entry.hash = hash;
        entry.active = true;

        // Prepend to the bucket chain.
        entry.chain_next = self.buckets[bucket_idx].head;
        self.buckets[bucket_idx].head = slot;
        self.buckets[bucket_idx].count += 1;

        if self.buckets[bucket_idx].count > self.stats.max_chain_len {
            self.stats.max_chain_len = self.buckets[bucket_idx].count;
        }

        self.next_slot += 1;
        self.next_handle += 1;
        self.stats.insertions += 1;
        self.stats.entry_count += 1;

        Ok(handle)
    }

    /// Fetch the frames associated with a handle.
    ///
    /// Returns a slice of instruction-pointer values, or
    /// `NotFound` if the handle is invalid.
    pub fn fetch(&mut self, handle: StackHandle) -> Result<&[u64]> {
        self.stats.fetch_calls += 1;

        if handle.is_null() {
            self.stats.fetch_misses += 1;
            return Err(Error::InvalidArgument);
        }

        // Linear scan for the handle. In a real implementation
        // the handle encodes the pool index directly, but here
        // we keep it simple.
        let entry = self.pool[..self.next_slot]
            .iter()
            .find(|e| e.active && e.handle == handle);

        match entry {
            Some(e) => Ok(e.frames()),
            None => {
                self.stats.fetch_misses += 1;
                Err(Error::NotFound)
            }
        }
    }

    /// Look up whether an identical trace already exists.
    /// Returns its handle if found, `None` otherwise.
    pub fn lookup(&self, frames: &[u64]) -> Option<StackHandle> {
        if frames.is_empty() || !self.initialised {
            return None;
        }
        let fcount = frames.len().min(MAX_FRAMES);
        let hash = hash_frames(&frames[..fcount]);
        let bucket_idx = (hash as usize) & HASH_MASK;
        self.search_chain(bucket_idx, &frames[..fcount], hash)
    }

    /// Return the number of unique traces currently stored.
    pub fn entry_count(&self) -> u32 {
        self.stats.entry_count
    }

    /// Approximate memory usage in bytes.
    pub fn memory_usage(&self) -> usize {
        let entry_size = core::mem::size_of::<DepotEntry>();
        let bucket_size = core::mem::size_of::<HashBucket>();
        (self.next_slot * entry_size) + (HASH_BUCKETS * bucket_size)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &DepotStats {
        &self.stats
    }

    // ── internal helpers ─────────────────────────────────────

    /// Walk the chain for `bucket_idx` looking for a matching trace.
    fn search_chain(&self, bucket_idx: usize, frames: &[u64], hash: u64) -> Option<StackHandle> {
        let mut idx = self.buckets[bucket_idx].head;

        while idx != usize::MAX {
            let entry = &self.pool[idx];
            if !entry.active {
                break;
            }
            if entry.hash == hash && entry.frame_count == frames.len() && entry.frames() == frames {
                return Some(entry.handle);
            }
            idx = entry.chain_next;
        }

        None
    }
}

// ══════════════════════════════════════════════════════════════
// Hash helpers
// ══════════════════════════════════════════════════════════════

/// FNV-1a 64-bit hash over a frame array.
fn hash_frames(frames: &[u64]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut h = FNV_OFFSET;
    for &frame in frames {
        // Hash each byte of the u64.
        let bytes = frame.to_le_bytes();
        for &b in &bytes {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
    }
    h
}
