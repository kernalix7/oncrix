// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stack trace depot for deduplication.
//!
//! The stack depot stores unique stack traces in a hash table,
//! assigning each unique trace a compact handle. Multiple subsystems
//! (KASAN, page allocation tracking, etc.) can reference the same
//! stack trace by handle, saving significant memory.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum frames per stack trace.
const MAX_FRAMES: usize = 64;

/// Maximum number of unique stack traces stored.
const MAX_DEPOT_ENTRIES: usize = 1024;

/// Hash table bucket count.
const HASH_BUCKETS: usize = 256;

/// Maximum entries per hash bucket.
const MAX_PER_BUCKET: usize = 8;

// ── Types ────────────────────────────────────────────────────────────

/// Compact handle referencing a stored stack trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackHandle(u32);

impl StackHandle {
    /// Creates a new stack handle.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw handle value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns an invalid/null handle.
    pub const fn null() -> Self {
        Self(0)
    }

    /// Returns whether this is the null handle.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// A stored stack trace.
#[derive(Debug, Clone)]
pub struct DepotStackEntry {
    /// Handle assigned to this trace.
    handle: StackHandle,
    /// Instruction pointer frames.
    frames: [u64; MAX_FRAMES],
    /// Number of valid frames.
    frame_count: usize,
    /// Hash of this stack trace.
    hash: u64,
    /// Number of references to this entry.
    ref_count: u32,
}

impl DepotStackEntry {
    /// Creates a new depot entry.
    pub const fn new(handle: StackHandle, hash: u64) -> Self {
        Self {
            handle,
            frames: [0u64; MAX_FRAMES],
            frame_count: 0,
            hash,
            ref_count: 1,
        }
    }

    /// Returns the handle for this entry.
    pub const fn handle(&self) -> StackHandle {
        self.handle
    }

    /// Returns the number of frames.
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Returns the reference count.
    pub const fn ref_count(&self) -> u32 {
        self.ref_count
    }
}

/// Hash bucket in the depot's hash table.
#[derive(Debug)]
pub struct DepotBucket {
    /// Entry indices stored in this bucket.
    entries: [Option<u32>; MAX_PER_BUCKET],
    /// Number of entries.
    count: usize,
}

impl DepotBucket {
    /// Creates an empty bucket.
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_PER_BUCKET],
            count: 0,
        }
    }
}

impl Default for DepotBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the stack depot.
#[derive(Debug, Clone)]
pub struct StackDepotStats {
    /// Number of unique stack traces stored.
    pub unique_traces: u32,
    /// Total save operations (including dedup hits).
    pub total_saves: u64,
    /// Number of times deduplication avoided a new entry.
    pub dedup_hits: u64,
    /// Number of lookups performed.
    pub lookups: u64,
    /// Number of failed lookups.
    pub lookup_misses: u64,
    /// Total memory used (approximate, in bytes).
    pub memory_used: u64,
}

impl Default for StackDepotStats {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDepotStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            unique_traces: 0,
            total_saves: 0,
            dedup_hits: 0,
            lookups: 0,
            lookup_misses: 0,
            memory_used: 0,
        }
    }
}

/// Central stack trace depot.
#[derive(Debug)]
pub struct StackDepot {
    /// Stored entries.
    entries: [Option<DepotStackEntry>; MAX_DEPOT_ENTRIES],
    /// Hash table buckets.
    buckets: [DepotBucket; HASH_BUCKETS],
    /// Number of stored entries.
    entry_count: usize,
    /// Next handle to assign (starts at 1, 0 is null).
    next_handle: u32,
    /// Statistics.
    total_saves: u64,
    dedup_hits: u64,
    lookups: u64,
    lookup_misses: u64,
}

impl Default for StackDepot {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDepot {
    /// Creates a new stack depot.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_DEPOT_ENTRIES],
            buckets: [const { DepotBucket::new() }; HASH_BUCKETS],
            entry_count: 0,
            next_handle: 1,
            total_saves: 0,
            dedup_hits: 0,
            lookups: 0,
            lookup_misses: 0,
        }
    }

    /// Computes a hash for a stack trace.
    fn hash_frames(frames: &[u64]) -> u64 {
        let mut h: u64 = 0xcbf29ce4_84222325;
        for &frame in frames {
            h ^= frame;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    /// Saves a stack trace, returning a handle.
    ///
    /// If an identical trace already exists, its handle is returned
    /// and the reference count is incremented.
    pub fn save(&mut self, frames: &[u64]) -> Result<StackHandle> {
        if frames.is_empty() || frames.len() > MAX_FRAMES {
            return Err(Error::InvalidArgument);
        }
        self.total_saves += 1;
        let hash = Self::hash_frames(frames);
        let bucket_idx = (hash as usize) % HASH_BUCKETS;
        // Check for existing entry.
        let bucket = &self.buckets[bucket_idx];
        for i in 0..bucket.count {
            if let Some(entry_idx) = bucket.entries[i] {
                if let Some(entry) = &mut self.entries[entry_idx as usize] {
                    if entry.hash == hash
                        && entry.frame_count == frames.len()
                        && entry.frames[..entry.frame_count] == *frames
                    {
                        entry.ref_count += 1;
                        self.dedup_hits += 1;
                        return Ok(entry.handle);
                    }
                }
            }
        }
        // No match — create new entry.
        if self.entry_count >= MAX_DEPOT_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let handle = StackHandle::new(self.next_handle);
        self.next_handle += 1;
        let mut entry = DepotStackEntry::new(handle, hash);
        entry.frames[..frames.len()].copy_from_slice(frames);
        entry.frame_count = frames.len();
        let entry_idx = self
            .entries
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[entry_idx] = Some(entry);
        self.entry_count += 1;
        // Add to bucket.
        let bucket = &mut self.buckets[bucket_idx];
        if bucket.count < MAX_PER_BUCKET {
            bucket.entries[bucket.count] = Some(entry_idx as u32);
            bucket.count += 1;
        }
        Ok(handle)
    }

    /// Looks up a stack trace by handle.
    pub fn lookup(&mut self, handle: StackHandle) -> Result<&DepotStackEntry> {
        self.lookups += 1;
        if handle.is_null() {
            self.lookup_misses += 1;
            return Err(Error::InvalidArgument);
        }
        let entry = self.entries.iter().flatten().find(|e| e.handle == handle);
        match entry {
            Some(e) => Ok(e),
            None => {
                self.lookup_misses += 1;
                Err(Error::NotFound)
            }
        }
    }

    /// Decrements the reference count; removes entry if zero.
    pub fn release(&mut self, handle: StackHandle) -> Result<()> {
        if handle.is_null() {
            return Err(Error::InvalidArgument);
        }
        let entry_idx = self
            .entries
            .iter()
            .position(|s| s.as_ref().map_or(false, |e| e.handle == handle))
            .ok_or(Error::NotFound)?;
        let entry = self.entries[entry_idx].as_mut().ok_or(Error::NotFound)?;
        if entry.ref_count <= 1 {
            self.entries[entry_idx] = None;
            self.entry_count -= 1;
        } else {
            entry.ref_count -= 1;
        }
        Ok(())
    }

    /// Returns depot statistics.
    pub fn stats(&self) -> StackDepotStats {
        StackDepotStats {
            unique_traces: self.entry_count as u32,
            total_saves: self.total_saves,
            dedup_hits: self.dedup_hits,
            lookups: self.lookups,
            lookup_misses: self.lookup_misses,
            memory_used: (self.entry_count * core::mem::size_of::<DepotStackEntry>()) as u64,
        }
    }

    /// Returns the number of unique traces stored.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }
}
