// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eBPF map types for the ONCRIX kernel.
//!
//! Extends the basic [`super::bpf::BpfMap`] with proper typed map
//! implementations modeled after the Linux eBPF map subsystem:
//!
//! - [`BpfHashMap`]: FNV-1a hash table with linear probing (256 entries).
//! - [`BpfArrayMap`]: fixed-size index-addressed array (256 entries).
//! - [`BpfPerCpuArray`]: per-CPU variant of the array map (8 CPUs x 64).
//! - [`BpfLruHashMap`]: hash map with LRU eviction (128 entries).
//! - [`BpfRingBuf`]: ring buffer for streaming perf events (1024 entries).
//! - [`BpfMapRegistry`]: global registry managing up to 64 maps.
//!
//! Reference: Linux `kernel/bpf/`, `include/uapi/linux/bpf.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum key size in bytes for all map types.
const MAX_KEY_SIZE: usize = 32;

/// Maximum value size in bytes for all map types.
const MAX_VALUE_SIZE: usize = 64;

/// Maximum entries in a [`BpfHashMap`].
const HASH_MAP_MAX_ENTRIES: usize = 256;

/// Maximum entries in a [`BpfArrayMap`].
const ARRAY_MAP_MAX_ENTRIES: usize = 256;

/// Number of CPUs supported by per-CPU maps.
const MAX_CPUS: usize = 8;

/// Entries per CPU in a [`BpfPerCpuArray`].
const PER_CPU_ENTRIES: usize = 64;

/// Maximum entries in a [`BpfLruHashMap`].
const LRU_MAP_MAX_ENTRIES: usize = 128;

/// Maximum entries in a [`BpfRingBuf`].
const RING_BUF_MAX_ENTRIES: usize = 1024;

/// Maximum number of maps managed by [`BpfMapRegistry`].
const MAX_MAPS: usize = 64;

/// Maximum length of a map name.
const MAX_NAME_LEN: usize = 32;

// ── FNV-1a hash ──────────────────────────────────────────────────

/// FNV-1a offset basis for 64-bit.
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;

/// FNV-1a prime for 64-bit.
const FNV_PRIME: u64 = 0x00000100000001B3;

/// Compute the FNV-1a hash of a byte slice.
fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ── BpfMapType ───────────────────────────────────────────────────

/// Supported eBPF map types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfMapType {
    /// Hash table with FNV-1a hashing.
    HashTable,
    /// Fixed-size array indexed by integer key.
    Array,
    /// Per-CPU hash table (one table per CPU).
    PerCpuHashTable,
    /// Per-CPU array (one array per CPU).
    PerCpuArray,
    /// Hash table with LRU eviction policy.
    LruHashTable,
    /// Ring buffer for streaming events.
    RingBuf,
    /// Stack trace map for capturing call stacks.
    StackTrace,
}

// ── BpfMapDef ────────────────────────────────────────────────────

/// Definition of a BPF map (creation parameters).
#[derive(Debug, Clone, Copy)]
pub struct BpfMapDef {
    /// The type of map to create.
    pub map_type: BpfMapType,
    /// Size of each key in bytes (must be <= [`MAX_KEY_SIZE`]).
    pub key_size: usize,
    /// Size of each value in bytes (must be <= [`MAX_VALUE_SIZE`]).
    pub value_size: usize,
    /// Maximum number of entries the map can hold.
    pub max_entries: usize,
}

impl BpfMapDef {
    /// Create a new map definition.
    pub const fn new(
        map_type: BpfMapType,
        key_size: usize,
        value_size: usize,
        max_entries: usize,
    ) -> Self {
        Self {
            map_type,
            key_size,
            value_size,
            max_entries,
        }
    }

    /// Validate the map definition against implementation limits.
    fn validate(&self) -> Result<()> {
        if self.key_size == 0 || self.key_size > MAX_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.value_size == 0 || self.value_size > MAX_VALUE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.max_entries == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── BpfHashMap ───────────────────────────────────────────────────

/// A single entry in a hash map.
#[derive(Clone)]
struct HashEntry {
    /// Key bytes.
    key: [u8; MAX_KEY_SIZE],
    /// Value bytes.
    value: [u8; MAX_VALUE_SIZE],
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Default for HashEntry {
    fn default() -> Self {
        Self {
            key: [0u8; MAX_KEY_SIZE],
            value: [0u8; MAX_VALUE_SIZE],
            occupied: false,
        }
    }
}

/// FNV-1a hash table map for eBPF programs.
///
/// Supports up to [`HASH_MAP_MAX_ENTRIES`] entries with linear
/// probing for collision resolution. Keys and values are
/// fixed-size byte arrays.
pub struct BpfHashMap {
    /// Storage slots.
    entries: [HashEntry; HASH_MAP_MAX_ENTRIES],
    /// Configured key size in bytes.
    key_size: usize,
    /// Configured value size in bytes.
    value_size: usize,
    /// Maximum allowed entries.
    max_entries: usize,
    /// Current number of occupied entries.
    count: usize,
}

impl BpfHashMap {
    /// Create a new hash map with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if sizes exceed limits
    /// or `max_entries` exceeds [`HASH_MAP_MAX_ENTRIES`].
    pub fn new(key_size: usize, value_size: usize, max_entries: usize) -> Result<Self> {
        if key_size == 0
            || key_size > MAX_KEY_SIZE
            || value_size == 0
            || value_size > MAX_VALUE_SIZE
            || max_entries == 0
            || max_entries > HASH_MAP_MAX_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            entries: core::array::from_fn(|_| HashEntry::default()),
            key_size,
            value_size,
            max_entries,
            count: 0,
        })
    }

    /// Compute the bucket index for a key using FNV-1a.
    fn bucket(&self, key: &[u8]) -> usize {
        fnv1a(&key[..self.key_size]) as usize % self.max_entries
    }

    /// Look up a value by key.
    ///
    /// Returns a reference to the value bytes on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is shorter than
    ///   `key_size`.
    /// - [`Error::NotFound`] if the key is absent.
    pub fn lookup(&self, key: &[u8]) -> Result<&[u8]> {
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                return Ok(&entry.value[..self.value_size]);
            }
        }
        Err(Error::NotFound)
    }

    /// Insert or update a key/value pair.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if slices are too short.
    /// - [`Error::OutOfMemory`] if the map is full and the key
    ///   does not already exist.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.len() < self.key_size || value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                let e = &mut self.entries[idx];
                e.key[..self.key_size].copy_from_slice(&key[..self.key_size]);
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                e.occupied = true;
                self.count += 1;
                return Ok(());
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                let e = &mut self.entries[idx];
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Delete an entry by key.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is too short.
    /// - [`Error::NotFound`] if the key is absent.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                self.entries[idx].occupied = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the current number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── BpfArrayMap ──────────────────────────────────────────────────

/// Fixed-size array map for eBPF programs.
///
/// Keys are integer indices (encoded as little-endian `u32` in the
/// key byte slice). Values are fixed-size byte arrays. The map is
/// pre-allocated with zeroed entries.
pub struct BpfArrayMap {
    /// Value storage (index-addressed).
    values: [[u8; MAX_VALUE_SIZE]; ARRAY_MAP_MAX_ENTRIES],
    /// Configured value size in bytes.
    value_size: usize,
    /// Maximum number of entries (array length).
    max_entries: usize,
}

impl BpfArrayMap {
    /// Create a new array map with the given value size and
    /// maximum entry count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `value_size` exceeds
    /// [`MAX_VALUE_SIZE`] or `max_entries` exceeds
    /// [`ARRAY_MAP_MAX_ENTRIES`].
    pub fn new(value_size: usize, max_entries: usize) -> Result<Self> {
        if value_size == 0
            || value_size > MAX_VALUE_SIZE
            || max_entries == 0
            || max_entries > ARRAY_MAP_MAX_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            values: [[0u8; MAX_VALUE_SIZE]; ARRAY_MAP_MAX_ENTRIES],
            value_size,
            max_entries,
        })
    }

    /// Extract the array index from a key byte slice.
    ///
    /// The key must be at least 4 bytes (little-endian `u32`).
    fn index_from_key(key: &[u8]) -> Result<u32> {
        if key.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        let bytes: [u8; 4] = [key[0], key[1], key[2], key[3]];
        Ok(u32::from_le_bytes(bytes))
    }

    /// Look up a value by index.
    ///
    /// `key` is a little-endian `u32` index encoded as 4 bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is too short or the
    ///   index is out of bounds.
    pub fn lookup(&self, key: &[u8]) -> Result<&[u8]> {
        let idx = Self::index_from_key(key)? as usize;
        if idx >= self.max_entries {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.values[idx][..self.value_size])
    }

    /// Update the value at the given index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is too short, the
    ///   index is out of bounds, or `value` is too short.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let idx = Self::index_from_key(key)? as usize;
        if idx >= self.max_entries {
            return Err(Error::InvalidArgument);
        }
        if value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }
        self.values[idx][..self.value_size].copy_from_slice(&value[..self.value_size]);
        Ok(())
    }

    /// Return the maximum number of entries.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
}

// ── BpfPerCpuArray ───────────────────────────────────────────────

/// Per-CPU array map for eBPF programs.
///
/// Maintains a separate array of values for each CPU, providing
/// lock-free per-CPU counters and accumulators. Supports up to
/// [`MAX_CPUS`] CPUs with [`PER_CPU_ENTRIES`] entries each.
pub struct BpfPerCpuArray {
    /// Per-CPU value storage: `[cpu][index] -> value`.
    values: [[[u8; MAX_VALUE_SIZE]; PER_CPU_ENTRIES]; MAX_CPUS],
    /// Configured value size in bytes.
    value_size: usize,
    /// Number of entries per CPU.
    entries_per_cpu: usize,
}

impl BpfPerCpuArray {
    /// Create a new per-CPU array map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `value_size` exceeds
    /// [`MAX_VALUE_SIZE`] or `entries_per_cpu` exceeds
    /// [`PER_CPU_ENTRIES`].
    pub fn new(value_size: usize, entries_per_cpu: usize) -> Result<Self> {
        if value_size == 0
            || value_size > MAX_VALUE_SIZE
            || entries_per_cpu == 0
            || entries_per_cpu > PER_CPU_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            values: [[[0u8; MAX_VALUE_SIZE]; PER_CPU_ENTRIES]; MAX_CPUS],
            value_size,
            entries_per_cpu,
        })
    }

    /// Look up the value at `index` for the given `cpu`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` >= [`MAX_CPUS`]
    /// or `index` >= `entries_per_cpu`.
    pub fn lookup(&self, cpu: usize, index: usize) -> Result<&[u8]> {
        if cpu >= MAX_CPUS || index >= self.entries_per_cpu {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.values[cpu][index][..self.value_size])
    }

    /// Update the value at `index` for the given `cpu`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if bounds are exceeded
    /// or `value` is too short.
    pub fn update(&mut self, cpu: usize, index: usize, value: &[u8]) -> Result<()> {
        if cpu >= MAX_CPUS || index >= self.entries_per_cpu {
            return Err(Error::InvalidArgument);
        }
        if value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }
        self.values[cpu][index][..self.value_size].copy_from_slice(&value[..self.value_size]);
        Ok(())
    }

    /// Return the number of supported CPUs.
    pub fn num_cpus(&self) -> usize {
        MAX_CPUS
    }

    /// Return the number of entries per CPU.
    pub fn entries_per_cpu(&self) -> usize {
        self.entries_per_cpu
    }
}

// ── BpfLruHashMap ────────────────────────────────────────────────

/// A single entry in the LRU hash map.
#[derive(Clone)]
struct LruEntry {
    /// Key bytes.
    key: [u8; MAX_KEY_SIZE],
    /// Value bytes.
    value: [u8; MAX_VALUE_SIZE],
    /// Whether this slot is occupied.
    occupied: bool,
    /// Access counter for LRU tracking (higher = more recent).
    access_tick: u64,
}

impl Default for LruEntry {
    fn default() -> Self {
        Self {
            key: [0u8; MAX_KEY_SIZE],
            value: [0u8; MAX_VALUE_SIZE],
            occupied: false,
            access_tick: 0,
        }
    }
}

/// Hash map with LRU (Least Recently Used) eviction for eBPF.
///
/// When the map is full and a new key is inserted, the least
/// recently accessed entry is evicted to make room. Supports
/// up to [`LRU_MAP_MAX_ENTRIES`] entries.
pub struct BpfLruHashMap {
    /// Storage slots.
    entries: [LruEntry; LRU_MAP_MAX_ENTRIES],
    /// Configured key size in bytes.
    key_size: usize,
    /// Configured value size in bytes.
    value_size: usize,
    /// Maximum allowed entries.
    max_entries: usize,
    /// Current number of occupied entries.
    count: usize,
    /// Monotonic tick counter for LRU ordering.
    tick: u64,
}

impl BpfLruHashMap {
    /// Create a new LRU hash map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if sizes exceed limits
    /// or `max_entries` exceeds [`LRU_MAP_MAX_ENTRIES`].
    pub fn new(key_size: usize, value_size: usize, max_entries: usize) -> Result<Self> {
        if key_size == 0
            || key_size > MAX_KEY_SIZE
            || value_size == 0
            || value_size > MAX_VALUE_SIZE
            || max_entries == 0
            || max_entries > LRU_MAP_MAX_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            entries: core::array::from_fn(|_| LruEntry::default()),
            key_size,
            value_size,
            max_entries,
            count: 0,
            tick: 0,
        })
    }

    /// Compute the bucket index for a key using FNV-1a.
    fn bucket(&self, key: &[u8]) -> usize {
        fnv1a(&key[..self.key_size]) as usize % self.max_entries
    }

    /// Advance and return the current tick for LRU ordering.
    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// Find the index of the least-recently-used occupied entry.
    fn find_lru_victim(&self) -> usize {
        let mut min_tick = u64::MAX;
        let mut victim = 0;
        for (i, entry) in self.entries.iter().enumerate() {
            if i >= self.max_entries {
                break;
            }
            if entry.occupied && entry.access_tick < min_tick {
                min_tick = entry.access_tick;
                victim = i;
            }
        }
        victim
    }

    /// Look up a value by key, updating its LRU position.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is too short.
    /// - [`Error::NotFound`] if the key is absent.
    pub fn lookup(&mut self, key: &[u8]) -> Result<&[u8]> {
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let tick = self.next_tick();
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                self.entries[idx].access_tick = tick;
                return Ok(&self.entries[idx].value[..self.value_size]);
            }
        }
        Err(Error::NotFound)
    }

    /// Insert or update a key/value pair, evicting the LRU
    /// entry if the map is full.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if slices are too short.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.len() < self.key_size || value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }
        let tick = self.next_tick();
        let start = self.bucket(key);

        // Try to find existing key or empty slot.
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                // Empty slot -- insert here.
                let e = &mut self.entries[idx];
                e.key[..self.key_size].copy_from_slice(&key[..self.key_size]);
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                e.occupied = true;
                e.access_tick = tick;
                self.count += 1;
                return Ok(());
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                // Existing key -- update value.
                let e = &mut self.entries[idx];
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                e.access_tick = tick;
                return Ok(());
            }
        }

        // Map is full -- evict the LRU entry.
        let victim = self.find_lru_victim();
        let e = &mut self.entries[victim];
        e.key[..self.key_size].copy_from_slice(&key[..self.key_size]);
        e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
        e.access_tick = tick;
        // `occupied` is already true; count stays the same.
        Ok(())
    }

    /// Delete an entry by key.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is too short.
    /// - [`Error::NotFound`] if the key is absent.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                self.entries[idx].occupied = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the current number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── BpfRingBuf ───────────────────────────────────────────────────

/// A single entry in the ring buffer.
#[derive(Clone)]
struct RingBufEntry {
    /// Event data.
    data: [u8; MAX_VALUE_SIZE],
    /// Actual length of data in this entry.
    len: usize,
    /// Whether this slot has been submitted (ready to consume).
    committed: bool,
}

impl Default for RingBufEntry {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_VALUE_SIZE],
            len: 0,
            committed: false,
        }
    }
}

/// Ring buffer for streaming perf events from eBPF programs.
///
/// Producers reserve a slot, write data, then submit. Consumers
/// read committed entries in FIFO order. The buffer wraps around
/// and overwrites stale entries when full.
pub struct BpfRingBuf {
    /// Entry storage (circular).
    entries: [RingBufEntry; RING_BUF_MAX_ENTRIES],
    /// Configured maximum data size per entry.
    value_size: usize,
    /// Total number of slots.
    capacity: usize,
    /// Write head (next slot to reserve).
    head: usize,
    /// Read tail (next slot to consume).
    tail: usize,
    /// Number of pending (submitted but unconsumed) entries.
    pending: usize,
}

impl BpfRingBuf {
    /// Create a new ring buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `value_size` exceeds
    /// [`MAX_VALUE_SIZE`] or `capacity` exceeds
    /// [`RING_BUF_MAX_ENTRIES`].
    pub fn new(value_size: usize, capacity: usize) -> Result<Self> {
        if value_size == 0
            || value_size > MAX_VALUE_SIZE
            || capacity == 0
            || capacity > RING_BUF_MAX_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            entries: core::array::from_fn(|_| RingBufEntry::default()),
            value_size,
            capacity,
            head: 0,
            tail: 0,
            pending: 0,
        })
    }

    /// Reserve a slot in the ring buffer for writing.
    ///
    /// Returns the slot index that can be written to via
    /// [`submit`](Self::submit). If the buffer is full, the
    /// oldest unconsumed entry is overwritten and the tail
    /// advances.
    pub fn reserve(&mut self) -> usize {
        let slot = self.head;

        // If the buffer is full, advance the tail to overwrite
        // the oldest entry.
        if self.pending >= self.capacity {
            self.tail = (self.tail + 1) % self.capacity;
            self.pending = self.pending.saturating_sub(1);
        }

        // Clear the slot for the new reservation.
        self.entries[slot].committed = false;
        self.entries[slot].len = 0;

        self.head = (self.head + 1) % self.capacity;
        slot
    }

    /// Submit data to a previously reserved slot.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `slot` is out of bounds
    ///   or `data` exceeds `value_size`.
    pub fn submit(&mut self, slot: usize, data: &[u8]) -> Result<()> {
        if slot >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        let len = data.len().min(self.value_size);
        if data.len() > self.value_size {
            return Err(Error::InvalidArgument);
        }
        self.entries[slot].data[..len].copy_from_slice(&data[..len]);
        self.entries[slot].len = len;
        self.entries[slot].committed = true;
        self.pending += 1;
        Ok(())
    }

    /// Consume the next committed entry from the ring buffer.
    ///
    /// Returns the data bytes of the consumed entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if no committed entries are
    /// available.
    pub fn consume(&mut self) -> Result<&[u8]> {
        if self.pending == 0 {
            return Err(Error::WouldBlock);
        }

        // Scan from tail to find the next committed entry.
        let idx = self.tail;
        if !self.entries[idx].committed {
            return Err(Error::WouldBlock);
        }

        let len = self.entries[idx].len;
        self.entries[idx].committed = false;
        self.tail = (self.tail + 1) % self.capacity;
        self.pending = self.pending.saturating_sub(1);
        Ok(&self.entries[idx].data[..len])
    }

    /// Return the number of pending (committed, unconsumed)
    /// entries.
    pub fn pending_count(&self) -> usize {
        self.pending
    }

    /// Return the total capacity of the ring buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return whether the ring buffer has no pending entries.
    pub fn is_empty(&self) -> bool {
        self.pending == 0
    }
}

// ── BpfMapRegistry ───────────────────────────────────────────────

/// The kind of map stored in a registry slot.
#[allow(clippy::large_enum_variant)]
enum MapSlotKind {
    /// Slot is empty.
    Empty,
    /// FNV-1a hash map.
    Hash(BpfHashMap),
    /// Fixed-size array map.
    Array(BpfArrayMap),
    /// Per-CPU array map.
    PerCpuArray(BpfPerCpuArray),
    /// LRU hash map.
    LruHash(BpfLruHashMap),
    /// Ring buffer.
    RingBuf(BpfRingBuf),
}

/// A named slot in the map registry.
struct MapRegistrySlot {
    /// Map storage.
    kind: MapSlotKind,
    /// Human-readable name of the map.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    name_len: usize,
    /// The map definition used to create this map.
    def: BpfMapDef,
}

impl MapRegistrySlot {
    /// Create a new empty slot.
    const fn empty() -> Self {
        Self {
            kind: MapSlotKind::Empty,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            def: BpfMapDef {
                map_type: BpfMapType::HashTable,
                key_size: 1,
                value_size: 1,
                max_entries: 1,
            },
        }
    }

    /// Return whether this slot is occupied.
    const fn is_occupied(&self) -> bool {
        !matches!(self.kind, MapSlotKind::Empty)
    }
}

/// Global registry managing up to [`MAX_MAPS`] eBPF maps.
///
/// Provides creation, destruction, and lookup of named maps by
/// their registry ID.
pub struct BpfMapRegistry {
    /// Map slots.
    slots: [MapRegistrySlot; MAX_MAPS],
    /// Number of active maps.
    count: usize,
}

impl Default for BpfMapRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfMapRegistry {
    /// Create an empty map registry.
    pub const fn new() -> Self {
        const EMPTY: MapRegistrySlot = MapRegistrySlot::empty();
        Self {
            slots: [EMPTY; MAX_MAPS],
            count: 0,
        }
    }

    /// Create a new map from a [`BpfMapDef`] and register it.
    ///
    /// `name` is a human-readable identifier (up to 32 bytes).
    /// Returns the map ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the definition is invalid
    ///   or the name is empty/too long.
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    /// - [`Error::NotImplemented`] for unsupported map types
    ///   (PerCpuHashTable, StackTrace).
    pub fn create(&mut self, name: &[u8], def: &BpfMapDef) -> Result<usize> {
        def.validate()?;

        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let idx = self
            .slots
            .iter()
            .position(|s| !s.is_occupied())
            .ok_or(Error::OutOfMemory)?;

        let kind = match def.map_type {
            BpfMapType::HashTable => MapSlotKind::Hash(BpfHashMap::new(
                def.key_size,
                def.value_size,
                def.max_entries.min(HASH_MAP_MAX_ENTRIES),
            )?),
            BpfMapType::Array => MapSlotKind::Array(BpfArrayMap::new(
                def.value_size,
                def.max_entries.min(ARRAY_MAP_MAX_ENTRIES),
            )?),
            BpfMapType::PerCpuArray => MapSlotKind::PerCpuArray(BpfPerCpuArray::new(
                def.value_size,
                def.max_entries.min(PER_CPU_ENTRIES),
            )?),
            BpfMapType::LruHashTable => MapSlotKind::LruHash(BpfLruHashMap::new(
                def.key_size,
                def.value_size,
                def.max_entries.min(LRU_MAP_MAX_ENTRIES),
            )?),
            BpfMapType::RingBuf => MapSlotKind::RingBuf(BpfRingBuf::new(
                def.value_size,
                def.max_entries.min(RING_BUF_MAX_ENTRIES),
            )?),
            BpfMapType::PerCpuHashTable | BpfMapType::StackTrace => {
                return Err(Error::NotImplemented);
            }
        };

        let slot = &mut self.slots[idx];
        slot.kind = kind;
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.def = *def;
        self.count += 1;

        Ok(idx)
    }

    /// Destroy a map by its registry ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID is invalid or the
    /// slot is empty.
    pub fn destroy(&mut self, id: usize) -> Result<()> {
        if id >= MAX_MAPS || !self.slots[id].is_occupied() {
            return Err(Error::NotFound);
        }
        self.slots[id].kind = MapSlotKind::Empty;
        self.slots[id].name_len = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Look up a hash map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a hash map.
    pub fn lookup_hash(&self, id: usize) -> Result<&BpfHashMap> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            MapSlotKind::Hash(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable hash map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a hash map.
    pub fn lookup_hash_mut(&mut self, id: usize) -> Result<&mut BpfHashMap> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            MapSlotKind::Hash(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up an array map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not an array.
    pub fn lookup_array(&self, id: usize) -> Result<&BpfArrayMap> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            MapSlotKind::Array(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable array map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not an array.
    pub fn lookup_array_mut(&mut self, id: usize) -> Result<&mut BpfArrayMap> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            MapSlotKind::Array(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a per-CPU array map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a per-CPU
    ///   array.
    pub fn lookup_percpu_array(&self, id: usize) -> Result<&BpfPerCpuArray> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            MapSlotKind::PerCpuArray(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable per-CPU array map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a per-CPU
    ///   array.
    pub fn lookup_percpu_array_mut(&mut self, id: usize) -> Result<&mut BpfPerCpuArray> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            MapSlotKind::PerCpuArray(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up an LRU hash map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not an LRU
    ///   hash map.
    pub fn lookup_lru_hash(&self, id: usize) -> Result<&BpfLruHashMap> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            MapSlotKind::LruHash(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable LRU hash map by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not an LRU
    ///   hash map.
    pub fn lookup_lru_hash_mut(&mut self, id: usize) -> Result<&mut BpfLruHashMap> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            MapSlotKind::LruHash(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a ring buffer by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a ring
    ///   buffer.
    pub fn lookup_ringbuf(&self, id: usize) -> Result<&BpfRingBuf> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            MapSlotKind::RingBuf(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable ring buffer by its registry ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a ring
    ///   buffer.
    pub fn lookup_ringbuf_mut(&mut self, id: usize) -> Result<&mut BpfRingBuf> {
        if id >= MAX_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            MapSlotKind::RingBuf(m) => Ok(m),
            MapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up the map definition by its registry ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID is invalid or empty.
    pub fn lookup_map_def(&self, id: usize) -> Result<&BpfMapDef> {
        if id >= MAX_MAPS || !self.slots[id].is_occupied() {
            return Err(Error::NotFound);
        }
        Ok(&self.slots[id].def)
    }

    /// Return the number of active maps.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
