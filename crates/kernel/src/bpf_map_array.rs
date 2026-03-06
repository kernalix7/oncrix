// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF array map implementation.
//!
//! Array maps provide O(1) index-based lookup for BPF programs.
//! Each element is a fixed-size value addressed by an integer key
//! in the range `[0, max_entries)`.
//!
//! # Design
//!
//! ```text
//! BpfArrayMap
//!  ├── entries: [ArrayEntry; MAX_ENTRIES]
//!  ├── value_size: usize
//!  ├── max_entries: u32
//!  └── stats: ArrayMapStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/bpf/arraymap.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of entries in an array map.
const MAX_ENTRIES: usize = 1024;

/// Maximum value size in bytes (8 u64s).
const MAX_VALUE_SIZE: usize = 64;

/// Number of u64 words per value slot.
const VALUE_WORDS: usize = MAX_VALUE_SIZE / 8;

// ══════════════════════════════════════════════════════════════
// ArrayEntry
// ══════════════════════════════════════════════════════════════

/// A single entry in the array map.
#[derive(Clone, Copy)]
pub struct ArrayEntry {
    /// Value storage as u64 words.
    pub data: [u64; VALUE_WORDS],
    /// Whether this entry has been written.
    pub populated: bool,
}

impl ArrayEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            data: [0u64; VALUE_WORDS],
            populated: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ArrayMapStats
// ══════════════════════════════════════════════════════════════

/// Statistics for a BPF array map.
#[derive(Debug, Clone, Copy)]
pub struct ArrayMapStats {
    /// Total lookups performed.
    pub lookups: u64,
    /// Total updates performed.
    pub updates: u64,
    /// Total lookup misses (key out of range or unpopulated).
    pub misses: u64,
    /// Total deletions.
    pub deletes: u64,
}

impl ArrayMapStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            lookups: 0,
            updates: 0,
            misses: 0,
            deletes: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// BpfArrayMap
// ══════════════════════════════════════════════════════════════

/// BPF array map providing O(1) index-based element access.
///
/// Keys are unsigned 32-bit integers in `[0, max_entries)`.
/// Values are fixed-size byte blobs stored as u64 words.
pub struct BpfArrayMap {
    /// Map identifier.
    pub map_id: u32,
    /// Configured value size in bytes.
    pub value_size: usize,
    /// Configured maximum entries.
    pub max_entries: u32,
    /// Entry storage.
    entries: [ArrayEntry; MAX_ENTRIES],
    /// Access statistics.
    stats: ArrayMapStats,
    /// Whether the map has been created/initialised.
    created: bool,
}

impl BpfArrayMap {
    /// Create an uninitialised array map.
    pub const fn new() -> Self {
        Self {
            map_id: 0,
            value_size: 0,
            max_entries: 0,
            entries: [const { ArrayEntry::empty() }; MAX_ENTRIES],
            stats: ArrayMapStats::new(),
            created: false,
        }
    }

    /// Initialise the array map with the given parameters.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `value_size` or `max_entries` exceed limits.
    /// - `AlreadyExists` if already created.
    pub fn create(&mut self, map_id: u32, value_size: usize, max_entries: u32) -> Result<()> {
        if self.created {
            return Err(Error::AlreadyExists);
        }
        if value_size == 0 || value_size > MAX_VALUE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if max_entries == 0 || max_entries as usize > MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.map_id = map_id;
        self.value_size = value_size;
        self.max_entries = max_entries;
        self.created = true;
        Ok(())
    }

    /// Look up a value by key (index).
    ///
    /// Returns a reference to the entry's data words.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key >= max_entries`.
    /// - `NotFound` if the entry has not been populated.
    pub fn lookup(&mut self, key: u32) -> Result<&[u64; VALUE_WORDS]> {
        self.check_created()?;
        self.stats.lookups += 1;
        let idx = key as usize;
        if idx >= self.max_entries as usize {
            self.stats.misses += 1;
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].populated {
            self.stats.misses += 1;
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].data)
    }

    /// Update (or insert) a value at the given key.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key >= max_entries` or data length
    ///   exceeds value words.
    pub fn update(&mut self, key: u32, data: &[u64]) -> Result<()> {
        self.check_created()?;
        let idx = key as usize;
        if idx >= self.max_entries as usize {
            return Err(Error::InvalidArgument);
        }
        if data.len() > VALUE_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx].data[..data.len()].copy_from_slice(data);
        self.entries[idx].populated = true;
        self.stats.updates += 1;
        Ok(())
    }

    /// Delete (clear) an entry at the given key.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key >= max_entries`.
    /// - `NotFound` if the entry is not populated.
    pub fn delete(&mut self, key: u32) -> Result<()> {
        self.check_created()?;
        let idx = key as usize;
        if idx >= self.max_entries as usize {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].populated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = ArrayEntry::empty();
        self.stats.deletes += 1;
        Ok(())
    }

    /// Return the number of populated entries.
    pub fn count(&self) -> u32 {
        self.entries[..self.max_entries as usize]
            .iter()
            .filter(|e| e.populated)
            .count() as u32
    }

    /// Return map statistics.
    pub fn stats(&self) -> ArrayMapStats {
        self.stats
    }

    /// Check that the map has been created.
    fn check_created(&self) -> Result<()> {
        if !self.created {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }
}
