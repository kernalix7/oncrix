// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel hash table.
//!
//! A fixed-size hash table using separate chaining (index-based
//! linked buckets) and FNV-1a hashing. Designed for fast O(1)
//! average-case lookups of kernel objects by key.
//!
//! # Design
//!
//! ```text
//!   HashTable
//!   +--------+--------+--------+--------+
//!   | bkt[0] | bkt[1] | bkt[2] | bkt[3] | ...
//!   +--------+--------+--------+--------+
//!       |         |
//!     node[2]   node[5]
//!       |         |
//!     node[7]    NIL
//!       |
//!      NIL
//! ```
//!
//! Each bucket is a head index into the node pool. Nodes in the
//! same bucket form a singly-linked chain via `next` indices.
//!
//! # Reference
//!
//! Linux `include/linux/hashtable.h`,
//! `include/linux/hash.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Number of hash buckets (power of 2).
const NUM_BUCKETS: usize = 256;

/// Maximum entries in the table.
const MAX_ENTRIES: usize = 1024;

/// Maximum managed hash tables.
const MAX_TABLES: usize = 64;

/// Sentinel for empty bucket / end of chain.
const NIL_IDX: u32 = u32::MAX;

/// FNV-1a offset basis (64-bit).
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a prime (64-bit).
const FNV_PRIME: u64 = 0x0100_0000_01b3;

// ======================================================================
// HashNode
// ======================================================================

/// A node in the hash table.
#[derive(Debug, Clone, Copy)]
pub struct HashNode {
    /// Key.
    key: u64,
    /// Value.
    value: u64,
    /// Next node in the bucket chain (NIL_IDX if tail).
    next: u32,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl HashNode {
    /// Creates a new empty node.
    pub const fn new() -> Self {
        Self {
            key: 0,
            value: 0,
            next: NIL_IDX,
            occupied: false,
        }
    }

    /// Returns the key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns whether this slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }
}

// ======================================================================
// HashTable
// ======================================================================

/// Fixed-size hash table with FNV-1a hashing and separate
/// chaining.
pub struct HashTable {
    /// Bucket heads (indices into `nodes`).
    buckets: [u32; NUM_BUCKETS],
    /// Node pool.
    nodes: [HashNode; MAX_ENTRIES],
    /// Number of entries.
    count: usize,
    /// Pool used.
    pool_used: usize,
    /// Statistics: total lookups.
    stats_lookups: u64,
    /// Statistics: total collisions (chain length > 1).
    stats_collisions: u64,
}

impl HashTable {
    /// Creates a new empty hash table.
    pub const fn new() -> Self {
        Self {
            buckets: [NIL_IDX; NUM_BUCKETS],
            nodes: [const { HashNode::new() }; MAX_ENTRIES],
            count: 0,
            pool_used: 0,
            stats_lookups: 0,
            stats_collisions: 0,
        }
    }

    /// Inserts a key-value pair.
    ///
    /// If the key already exists, the value is updated.
    pub fn hash_add(&mut self, key: u64, value: u64) -> Result<()> {
        let bucket = self.hash_key(key);

        // Check for existing key.
        let mut cur = self.buckets[bucket];
        while cur != NIL_IDX {
            let ci = cur as usize;
            if self.nodes[ci].key == key {
                self.nodes[ci].value = value;
                return Ok(());
            }
            cur = self.nodes[ci].next;
        }

        // Allocate a new node.
        let idx = self.alloc_node()?;
        self.nodes[idx].key = key;
        self.nodes[idx].value = value;
        self.nodes[idx].occupied = true;

        // Prepend to bucket.
        if self.buckets[bucket] != NIL_IDX {
            self.stats_collisions += 1;
        }
        self.nodes[idx].next = self.buckets[bucket];
        self.buckets[bucket] = idx as u32;
        self.count += 1;
        Ok(())
    }

    /// Deletes an entry by key.
    pub fn hash_del(&mut self, key: u64) -> Result<u64> {
        let bucket = self.hash_key(key);
        let mut prev = NIL_IDX;
        let mut cur = self.buckets[bucket];

        while cur != NIL_IDX {
            let ci = cur as usize;
            if self.nodes[ci].key == key {
                let value = self.nodes[ci].value;
                let next = self.nodes[ci].next;
                // Unlink.
                if prev == NIL_IDX {
                    self.buckets[bucket] = next;
                } else {
                    self.nodes[prev as usize].next = next;
                }
                self.nodes[ci] = HashNode::new();
                self.count -= 1;
                self.pool_used -= 1;
                return Ok(value);
            }
            prev = cur;
            cur = self.nodes[ci].next;
        }

        Err(Error::NotFound)
    }

    /// Looks up a key in the hash table.
    ///
    /// Returns the value if found.
    pub fn hash_for_each_possible(&mut self, key: u64) -> Result<u64> {
        self.stats_lookups += 1;
        let bucket = self.hash_key(key);
        let mut cur = self.buckets[bucket];

        while cur != NIL_IDX {
            let ci = cur as usize;
            if self.nodes[ci].key == key {
                return Ok(self.nodes[ci].value);
            }
            cur = self.nodes[ci].next;
        }

        Err(Error::NotFound)
    }

    /// Iterates over all entries, collecting (key, value) pairs.
    ///
    /// Returns the number of entries collected.
    pub fn hash_for_each(&self, out: &mut [(u64, u64)]) -> usize {
        let mut collected = 0;
        for &head in &self.buckets {
            let mut cur = head;
            while cur != NIL_IDX && collected < out.len() {
                let ci = cur as usize;
                if self.nodes[ci].occupied {
                    out[collected] = (self.nodes[ci].key, self.nodes[ci].value);
                    collected += 1;
                }
                cur = self.nodes[ci].next;
            }
        }
        collected
    }

    /// Returns whether the table is empty.
    pub fn hash_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns a reference to a node by index.
    pub fn node(&self, idx: usize) -> Result<&HashNode> {
        if idx >= MAX_ENTRIES || !self.nodes[idx].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Returns total lookups.
    pub fn stats_lookups(&self) -> u64 {
        self.stats_lookups
    }

    /// Returns total collisions.
    pub fn stats_collisions(&self) -> u64 {
        self.stats_collisions
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// FNV-1a hash of a u64 key, mapped to a bucket index.
    fn hash_key(&self, key: u64) -> usize {
        let bytes = key.to_le_bytes();
        let mut hash = FNV_OFFSET;
        for &b in &bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        (hash as usize) & (NUM_BUCKETS - 1)
    }

    /// Allocates a node from the pool.
    fn alloc_node(&mut self) -> Result<usize> {
        if self.pool_used >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let pos = self
            .nodes
            .iter()
            .position(|n| !n.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.pool_used += 1;
        Ok(pos)
    }
}

// ======================================================================
// HashTableRegistry — global registry
// ======================================================================

/// Global registry of hash tables.
pub struct HashTableRegistry {
    /// Entries.
    entries: [HashTableRegistryEntry; MAX_TABLES],
    /// Number of allocated tables.
    count: usize,
}

/// Entry in the registry.
struct HashTableRegistryEntry {
    /// The hash table.
    table: HashTable,
    /// Whether allocated.
    allocated: bool,
}

impl HashTableRegistryEntry {
    const fn new() -> Self {
        Self {
            table: HashTable::new(),
            allocated: false,
        }
    }
}

impl HashTableRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { HashTableRegistryEntry::new() }; MAX_TABLES],
            count: 0,
        }
    }

    /// Allocates a new hash table.
    pub fn alloc(&mut self) -> Result<usize> {
        if self.count >= MAX_TABLES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].allocated = true;
        self.entries[idx].table = HashTable::new();
        self.count += 1;
        Ok(idx)
    }

    /// Frees a hash table by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_TABLES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = HashTableRegistryEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the table at `idx`.
    pub fn get(&self, idx: usize) -> Result<&HashTable> {
        if idx >= MAX_TABLES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].table)
    }

    /// Returns a mutable reference to the table at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut HashTable> {
        if idx >= MAX_TABLES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].table)
    }

    /// Returns the number of allocated tables.
    pub fn count(&self) -> usize {
        self.count
    }
}
