// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended eBPF map types for the ONCRIX kernel.
//!
//! Complements [`super::bpf_maps`] with additional map types that
//! were left as `NotImplemented` in the base module:
//!
//! - [`BpfPerCpuHashMap`]: per-CPU hash table providing lock-free
//!   per-CPU counters with FNV-1a hashing and linear probing.
//! - [`BpfLpmTrie`]: longest-prefix-match trie for IP routing and
//!   policy lookups.
//! - [`BpfStackTraceMap`]: captures kernel/user stack traces as
//!   arrays of instruction pointer addresses.
//! - [`BpfMapTypeInfo`]: metadata descriptor for map introspection.
//! - [`BpfExtMapRegistry`]: registry managing all extended map types.
//!
//! Reference: Linux `kernel/bpf/hashtab.c`, `kernel/bpf/lpm_trie.c`,
//! `kernel/bpf/stackmap.c`.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// -- Constants ---------------------------------------------------------------

/// Maximum key size in bytes.
const MAX_KEY_SIZE: usize = 32;

/// Maximum value size in bytes.
const MAX_VALUE_SIZE: usize = 64;

/// Number of CPUs supported by per-CPU maps.
const MAX_CPUS: usize = 8;

/// Maximum entries per CPU in the per-CPU hash map.
const PER_CPU_HASH_ENTRIES: usize = 64;

/// Maximum number of nodes in the LPM trie.
const LPM_TRIE_MAX_NODES: usize = 256;

/// Maximum prefix length in bits for LPM trie keys.
const LPM_MAX_PREFIX_LEN: usize = 128;

/// Maximum number of stack traces in the stack trace map.
const STACK_TRACE_MAX_ENTRIES: usize = 128;

/// Maximum depth (frames) per stack trace.
const STACK_TRACE_MAX_DEPTH: usize = 32;

/// Maximum number of extended maps in the registry.
const MAX_EXT_MAPS: usize = 64;

/// Maximum name length for maps.
const MAX_NAME_LEN: usize = 32;

/// FNV-1a offset basis for 64-bit.
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;

/// FNV-1a prime for 64-bit.
const FNV_PRIME: u64 = 0x00000100000001B3;

// -- FNV-1a hash -------------------------------------------------------------

/// Compute the FNV-1a hash of a byte slice.
fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// -- ExtMapType --------------------------------------------------------------

/// Extended eBPF map type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtMapType {
    /// Per-CPU hash table.
    PerCpuHash,
    /// Longest prefix match trie.
    LpmTrie,
    /// Stack trace capture map.
    StackTrace,
}

// -- BpfMapTypeInfo ----------------------------------------------------------

/// Metadata descriptor for map introspection.
///
/// Provides read-only information about a created map instance,
/// suitable for userspace queries via bpf(BPF_MAP_GET_INFO_BY_FD).
#[derive(Debug, Clone, Copy)]
pub struct BpfMapTypeInfo {
    /// Map type.
    pub map_type: ExtMapType,
    /// Key size in bytes.
    pub key_size: usize,
    /// Value size in bytes.
    pub value_size: usize,
    /// Maximum entries.
    pub max_entries: usize,
    /// Map flags (reserved, currently 0).
    pub flags: u32,
    /// Map name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    name_len: usize,
}

impl BpfMapTypeInfo {
    /// Create a new map type info descriptor.
    pub fn new(
        map_type: ExtMapType,
        key_size: usize,
        value_size: usize,
        max_entries: usize,
        name: &[u8],
    ) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut info = Self {
            map_type,
            key_size,
            value_size,
            max_entries,
            flags: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: name.len(),
        };
        info.name[..name.len()].copy_from_slice(name);
        Ok(info)
    }

    /// Return the map name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// -- Per-CPU Hash Map --------------------------------------------------------

/// A single entry in the per-CPU hash map.
#[derive(Clone)]
struct PerCpuHashEntry {
    /// Key bytes.
    key: [u8; MAX_KEY_SIZE],
    /// Value bytes.
    value: [u8; MAX_VALUE_SIZE],
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Default for PerCpuHashEntry {
    fn default() -> Self {
        Self {
            key: [0u8; MAX_KEY_SIZE],
            value: [0u8; MAX_VALUE_SIZE],
            occupied: false,
        }
    }
}

/// Per-CPU FNV-1a hash table map for eBPF programs.
///
/// Maintains a separate hash table for each CPU, providing lock-free
/// per-CPU counters and statistics. Each CPU's table supports up to
/// [`PER_CPU_HASH_ENTRIES`] entries with linear probing.
pub struct BpfPerCpuHashMap {
    /// Per-CPU hash tables: `[cpu][slot]`.
    entries: [[PerCpuHashEntry; PER_CPU_HASH_ENTRIES]; MAX_CPUS],
    /// Configured key size in bytes.
    key_size: usize,
    /// Configured value size in bytes.
    value_size: usize,
    /// Maximum entries per CPU.
    max_entries: usize,
    /// Per-CPU entry counts.
    counts: [usize; MAX_CPUS],
}

impl BpfPerCpuHashMap {
    /// Create a new per-CPU hash map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if sizes exceed limits or
    /// `max_entries` exceeds [`PER_CPU_HASH_ENTRIES`].
    pub fn new(key_size: usize, value_size: usize, max_entries: usize) -> Result<Self> {
        if key_size == 0
            || key_size > MAX_KEY_SIZE
            || value_size == 0
            || value_size > MAX_VALUE_SIZE
            || max_entries == 0
            || max_entries > PER_CPU_HASH_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            entries: core::array::from_fn(|_| core::array::from_fn(|_| PerCpuHashEntry::default())),
            key_size,
            value_size,
            max_entries,
            counts: [0usize; MAX_CPUS],
        })
    }

    /// Compute the bucket index for a key on a given CPU.
    fn bucket(&self, key: &[u8]) -> usize {
        fnv1a(&key[..self.key_size]) as usize % self.max_entries
    }

    /// Look up a value by key on the specified CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` >= [`MAX_CPUS`] or
    ///   `key` is too short.
    /// - [`Error::NotFound`] if the key is absent on this CPU.
    pub fn lookup(&self, cpu: usize, key: &[u8]) -> Result<&[u8]> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[cpu][idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                return Ok(&entry.value[..self.value_size]);
            }
        }
        Err(Error::NotFound)
    }

    /// Insert or update a key/value pair on the specified CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` >= [`MAX_CPUS`] or
    ///   slices are too short.
    /// - [`Error::OutOfMemory`] if the CPU's table is full and the
    ///   key does not exist.
    pub fn update(&mut self, cpu: usize, key: &[u8], value: &[u8]) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if key.len() < self.key_size || value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[cpu][idx];
            if !entry.occupied {
                let e = &mut self.entries[cpu][idx];
                e.key[..self.key_size].copy_from_slice(&key[..self.key_size]);
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                e.occupied = true;
                self.counts[cpu] += 1;
                return Ok(());
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                let e = &mut self.entries[cpu][idx];
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Delete an entry by key on the specified CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` >= [`MAX_CPUS`] or
    ///   `key` is too short.
    /// - [`Error::NotFound`] if the key is absent.
    pub fn delete(&mut self, cpu: usize, key: &[u8]) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.bucket(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[cpu][idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                self.entries[cpu][idx].occupied = false;
                self.counts[cpu] = self.counts[cpu].saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the entry count for a specific CPU.
    ///
    /// Returns 0 if `cpu` is out of bounds.
    pub fn count(&self, cpu: usize) -> usize {
        if cpu >= MAX_CPUS {
            return 0;
        }
        self.counts[cpu]
    }

    /// Return the total entry count across all CPUs.
    pub fn total_count(&self) -> usize {
        self.counts.iter().sum()
    }

    /// Return the number of supported CPUs.
    pub fn num_cpus(&self) -> usize {
        MAX_CPUS
    }
}

// -- LPM Trie ---------------------------------------------------------------

/// A node in the longest-prefix-match trie.
///
/// Each node stores a prefix (key) and an optional value. Children
/// are identified by the bit value (0 or 1) at the current depth.
#[derive(Clone, Copy)]
struct LpmTrieNode {
    /// Prefix key bytes.
    key: [u8; MAX_KEY_SIZE],
    /// Prefix length in bits.
    prefix_len: usize,
    /// Value bytes.
    value: [u8; MAX_VALUE_SIZE],
    /// Whether this node has a value (is a terminal).
    has_value: bool,
    /// Index of child for bit=0 (0 = no child).
    child_0: usize,
    /// Index of child for bit=1 (0 = no child).
    child_1: usize,
    /// Whether this node slot is in use.
    occupied: bool,
}

impl LpmTrieNode {
    /// Create an empty node.
    const fn empty() -> Self {
        Self {
            key: [0u8; MAX_KEY_SIZE],
            prefix_len: 0,
            value: [0u8; MAX_VALUE_SIZE],
            has_value: false,
            child_0: 0,
            child_1: 0,
            occupied: false,
        }
    }
}

impl Default for LpmTrieNode {
    fn default() -> Self {
        Self::empty()
    }
}

/// Longest-prefix-match trie for eBPF programs.
///
/// Supports variable-length prefix keys up to [`LPM_MAX_PREFIX_LEN`]
/// bits. Used for IP routing table lookups, CIDR matching, and
/// hierarchical policy decisions.
///
/// Keys are encoded as: 4 bytes prefix_len (LE u32) + key data.
pub struct BpfLpmTrie {
    /// Node pool.
    nodes: [LpmTrieNode; LPM_TRIE_MAX_NODES],
    /// Configured key size in bytes (excluding prefix_len header).
    key_size: usize,
    /// Configured value size in bytes.
    value_size: usize,
    /// Index of the root node (0 = no root).
    root: usize,
    /// Number of occupied nodes.
    count: usize,
    /// Next free node index to check.
    next_free: usize,
}

impl BpfLpmTrie {
    /// Create a new LPM trie.
    ///
    /// `key_size` is the size of the key data in bytes (not including
    /// the 4-byte prefix length header).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if sizes exceed limits.
    pub fn new(key_size: usize, value_size: usize) -> Result<Self> {
        if key_size == 0
            || key_size > MAX_KEY_SIZE
            || value_size == 0
            || value_size > MAX_VALUE_SIZE
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            nodes: [LpmTrieNode::empty(); LPM_TRIE_MAX_NODES],
            key_size,
            value_size,
            root: 0,
            count: 0,
            next_free: 1, // slot 0 is reserved (means "no node")
        })
    }

    /// Extract a single bit from a key byte array.
    ///
    /// Bit 0 is the MSB of byte 0.
    fn get_bit(key: &[u8], bit_pos: usize) -> u8 {
        let byte_idx = bit_pos / 8;
        let bit_idx = 7 - (bit_pos % 8);
        if byte_idx < key.len() {
            (key[byte_idx] >> bit_idx) & 1
        } else {
            0
        }
    }

    /// Allocate a node from the pool.
    fn alloc_node(&mut self) -> Result<usize> {
        for i in 0..LPM_TRIE_MAX_NODES {
            let idx = (self.next_free + i) % LPM_TRIE_MAX_NODES;
            if idx == 0 {
                continue; // slot 0 is reserved
            }
            if !self.nodes[idx].occupied {
                self.next_free = (idx + 1) % LPM_TRIE_MAX_NODES;
                self.nodes[idx].occupied = true;
                self.count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Insert or update a prefix/value pair.
    ///
    /// The key format is: first 4 bytes = prefix_len (LE u32),
    /// followed by key data bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key` is too short or
    ///   `prefix_len` exceeds limits.
    /// - [`Error::OutOfMemory`] if the node pool is exhausted.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.len() < 4 + self.key_size {
            return Err(Error::InvalidArgument);
        }
        if value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }

        let prefix_len_bytes: [u8; 4] = [key[0], key[1], key[2], key[3]];
        let prefix_len = u32::from_le_bytes(prefix_len_bytes) as usize;
        let key_data = &key[4..4 + self.key_size];

        if prefix_len > self.key_size * 8 || prefix_len > LPM_MAX_PREFIX_LEN {
            return Err(Error::InvalidArgument);
        }

        // If there is no root, create one.
        if self.root == 0 {
            let node_idx = self.alloc_node()?;
            self.nodes[node_idx].key[..self.key_size].copy_from_slice(key_data);
            self.nodes[node_idx].prefix_len = prefix_len;
            self.nodes[node_idx].value[..self.value_size]
                .copy_from_slice(&value[..self.value_size]);
            self.nodes[node_idx].has_value = true;
            self.root = node_idx;
            return Ok(());
        }

        // Walk the trie to find the insertion point.
        let mut current = self.root;
        let mut depth = 0usize;

        while depth < prefix_len {
            let node = &self.nodes[current];
            // If the current node's prefix matches at this depth,
            // check if we need to go deeper.
            if node.prefix_len == prefix_len
                && node.key[..self.key_size] == key_data[..self.key_size]
            {
                // Exact match: update value.
                self.nodes[current].value[..self.value_size]
                    .copy_from_slice(&value[..self.value_size]);
                self.nodes[current].has_value = true;
                return Ok(());
            }

            let bit = Self::get_bit(key_data, depth);
            let child = if bit == 0 { node.child_0 } else { node.child_1 };

            if child == 0 {
                // No child at this bit position; create one.
                let new_node = self.alloc_node()?;
                self.nodes[new_node].key[..self.key_size].copy_from_slice(key_data);
                self.nodes[new_node].prefix_len = prefix_len;
                self.nodes[new_node].value[..self.value_size]
                    .copy_from_slice(&value[..self.value_size]);
                self.nodes[new_node].has_value = true;

                if bit == 0 {
                    self.nodes[current].child_0 = new_node;
                } else {
                    self.nodes[current].child_1 = new_node;
                }
                return Ok(());
            }

            current = child;
            depth += 1;
        }

        // We exhausted the prefix; update this node.
        self.nodes[current].value[..self.value_size].copy_from_slice(&value[..self.value_size]);
        self.nodes[current].has_value = true;
        Ok(())
    }

    /// Perform a longest-prefix-match lookup.
    ///
    /// Returns the value associated with the longest matching prefix.
    /// The key format is the same as [`update`](Self::update).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the key is too short.
    /// - [`Error::NotFound`] if no matching prefix exists.
    pub fn lookup(&self, key: &[u8]) -> Result<&[u8]> {
        if key.len() < 4 + self.key_size {
            return Err(Error::InvalidArgument);
        }

        let prefix_len_bytes: [u8; 4] = [key[0], key[1], key[2], key[3]];
        let prefix_len = u32::from_le_bytes(prefix_len_bytes) as usize;
        let key_data = &key[4..4 + self.key_size];

        if self.root == 0 {
            return Err(Error::NotFound);
        }

        let mut current = self.root;
        let mut best_match: Option<usize> = None;
        let mut depth = 0usize;

        // Walk down the trie, tracking the best (deepest) match.
        while current != 0 && depth <= prefix_len {
            let node = &self.nodes[current];
            if node.has_value && node.prefix_len <= prefix_len {
                best_match = Some(current);
            }

            if depth >= prefix_len {
                break;
            }

            let bit = Self::get_bit(key_data, depth);
            current = if bit == 0 { node.child_0 } else { node.child_1 };
            depth += 1;
        }

        match best_match {
            Some(idx) => Ok(&self.nodes[idx].value[..self.value_size]),
            None => Err(Error::NotFound),
        }
    }

    /// Delete a prefix from the trie.
    ///
    /// Removes the value associated with the exact prefix. Does not
    /// remove intermediate nodes (they may still be needed for
    /// routing to deeper prefixes).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the key is too short.
    /// - [`Error::NotFound`] if the prefix does not exist.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.len() < 4 + self.key_size {
            return Err(Error::InvalidArgument);
        }

        let prefix_len_bytes: [u8; 4] = [key[0], key[1], key[2], key[3]];
        let prefix_len = u32::from_le_bytes(prefix_len_bytes) as usize;
        let key_data = &key[4..4 + self.key_size];

        if self.root == 0 {
            return Err(Error::NotFound);
        }

        let mut current = self.root;
        let mut depth = 0usize;

        while current != 0 {
            let node = &self.nodes[current];

            if node.prefix_len == prefix_len
                && node.has_value
                && node.key[..self.key_size] == key_data[..self.key_size]
            {
                self.nodes[current].has_value = false;
                // If the node is a leaf with no children, free it.
                if self.nodes[current].child_0 == 0 && self.nodes[current].child_1 == 0 {
                    self.nodes[current].occupied = false;
                    self.count = self.count.saturating_sub(1);
                }
                return Ok(());
            }

            if depth >= prefix_len {
                break;
            }

            let bit = Self::get_bit(key_data, depth);
            current = if bit == 0 { node.child_0 } else { node.child_1 };
            depth += 1;
        }

        Err(Error::NotFound)
    }

    /// Return the number of nodes in the trie.
    pub fn node_count(&self) -> usize {
        self.count
    }

    /// Return whether the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.root == 0
    }
}

// -- Stack Trace Map ---------------------------------------------------------

/// A captured stack trace.
#[derive(Clone, Copy)]
struct StackTraceEntry {
    /// Instruction pointer addresses (bottom-up).
    ips: [u64; STACK_TRACE_MAX_DEPTH],
    /// Number of valid frames.
    depth: usize,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl StackTraceEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            ips: [0u64; STACK_TRACE_MAX_DEPTH],
            depth: 0,
            occupied: false,
        }
    }
}

impl Default for StackTraceEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Stack trace map for eBPF programs.
///
/// Captures kernel and/or user-space stack traces as arrays of
/// instruction pointer addresses. Each entry is keyed by a `u32`
/// stack ID assigned at capture time.
pub struct BpfStackTraceMap {
    /// Stack trace storage.
    traces: [StackTraceEntry; STACK_TRACE_MAX_ENTRIES],
    /// Maximum stack depth to capture.
    max_depth: usize,
    /// Number of occupied entries.
    count: usize,
    /// Next stack ID to assign.
    next_id: u32,
}

impl BpfStackTraceMap {
    /// Create a new stack trace map.
    ///
    /// `max_depth` is capped at [`STACK_TRACE_MAX_DEPTH`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `max_depth` is zero.
    pub fn new(max_depth: usize) -> Result<Self> {
        if max_depth == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            traces: [StackTraceEntry::empty(); STACK_TRACE_MAX_ENTRIES],
            max_depth: max_depth.min(STACK_TRACE_MAX_DEPTH),
            count: 0,
            next_id: 1,
        })
    }

    /// Capture a stack trace from an array of instruction pointers.
    ///
    /// Returns the stack ID assigned to this trace.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ips` is empty.
    /// - [`Error::OutOfMemory`] if the map is full.
    pub fn capture(&mut self, ips: &[u64]) -> Result<u32> {
        if ips.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .traces
            .iter()
            .position(|t| !t.occupied)
            .ok_or(Error::OutOfMemory)?;

        let depth = ips.len().min(self.max_depth);
        self.traces[slot].ips[..depth].copy_from_slice(&ips[..depth]);
        self.traces[slot].depth = depth;
        self.traces[slot].occupied = true;
        self.count += 1;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        Ok(id)
    }

    /// Look up a stack trace by slot index.
    ///
    /// Returns the instruction pointer array for the trace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the slot is out of bounds or
    /// unoccupied.
    pub fn lookup(&self, slot: usize) -> Result<&[u64]> {
        if slot >= STACK_TRACE_MAX_ENTRIES || !self.traces[slot].occupied {
            return Err(Error::NotFound);
        }
        let depth = self.traces[slot].depth;
        Ok(&self.traces[slot].ips[..depth])
    }

    /// Delete a stack trace by slot index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the slot is out of bounds or
    /// unoccupied.
    pub fn delete(&mut self, slot: usize) -> Result<()> {
        if slot >= STACK_TRACE_MAX_ENTRIES || !self.traces[slot].occupied {
            return Err(Error::NotFound);
        }
        self.traces[slot].occupied = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of captured stack traces.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the configured maximum stack depth.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
}

// -- BpfExtMapRegistry -------------------------------------------------------

/// The kind of extended map stored in a registry slot.
#[allow(clippy::large_enum_variant)]
enum ExtMapSlotKind {
    /// Slot is empty.
    Empty,
    /// Per-CPU hash map.
    PerCpuHash(BpfPerCpuHashMap),
    /// Longest prefix match trie.
    LpmTrie(BpfLpmTrie),
    /// Stack trace map.
    StackTrace(BpfStackTraceMap),
}

/// A named slot in the extended map registry.
struct ExtMapSlot {
    /// Map storage.
    kind: ExtMapSlotKind,
    /// Map name.
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Map type info.
    info: BpfMapTypeInfo,
}

impl ExtMapSlot {
    /// Create an empty slot.
    const fn empty() -> Self {
        Self {
            kind: ExtMapSlotKind::Empty,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            info: BpfMapTypeInfo {
                map_type: ExtMapType::PerCpuHash,
                key_size: 1,
                value_size: 1,
                max_entries: 1,
                flags: 0,
                name: [0u8; MAX_NAME_LEN],
                name_len: 0,
            },
        }
    }

    /// Return whether this slot is occupied.
    const fn is_occupied(&self) -> bool {
        !matches!(self.kind, ExtMapSlotKind::Empty)
    }
}

/// Registry managing all extended eBPF map types.
///
/// Provides creation, destruction, and typed lookup of per-CPU hash
/// maps, LPM tries, and stack trace maps.
pub struct BpfExtMapRegistry {
    /// Map slots.
    slots: [ExtMapSlot; MAX_EXT_MAPS],
    /// Number of active maps.
    count: usize,
}

impl Default for BpfExtMapRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfExtMapRegistry {
    /// Create an empty extended map registry.
    pub const fn new() -> Self {
        const EMPTY: ExtMapSlot = ExtMapSlot::empty();
        Self {
            slots: [EMPTY; MAX_EXT_MAPS],
            count: 0,
        }
    }

    /// Create a per-CPU hash map and register it.
    ///
    /// Returns the map ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if parameters are invalid or
    ///   name is empty/too long.
    /// - [`Error::OutOfMemory`] if no slots are available.
    pub fn create_percpu_hash(
        &mut self,
        name: &[u8],
        key_size: usize,
        value_size: usize,
        max_entries: usize,
    ) -> Result<usize> {
        let idx = self.find_free_slot()?;
        self.validate_name(name)?;

        let map = BpfPerCpuHashMap::new(key_size, value_size, max_entries)?;
        let info = BpfMapTypeInfo::new(
            ExtMapType::PerCpuHash,
            key_size,
            value_size,
            max_entries,
            name,
        )?;

        let slot = &mut self.slots[idx];
        slot.kind = ExtMapSlotKind::PerCpuHash(map);
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.info = info;
        self.count += 1;
        Ok(idx)
    }

    /// Create an LPM trie and register it.
    ///
    /// Returns the map ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if parameters are invalid or
    ///   name is empty/too long.
    /// - [`Error::OutOfMemory`] if no slots are available.
    pub fn create_lpm_trie(
        &mut self,
        name: &[u8],
        key_size: usize,
        value_size: usize,
    ) -> Result<usize> {
        let idx = self.find_free_slot()?;
        self.validate_name(name)?;

        let map = BpfLpmTrie::new(key_size, value_size)?;
        let info = BpfMapTypeInfo::new(
            ExtMapType::LpmTrie,
            key_size,
            value_size,
            LPM_TRIE_MAX_NODES,
            name,
        )?;

        let slot = &mut self.slots[idx];
        slot.kind = ExtMapSlotKind::LpmTrie(map);
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.info = info;
        self.count += 1;
        Ok(idx)
    }

    /// Create a stack trace map and register it.
    ///
    /// Returns the map ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `max_depth` is zero or name
    ///   is empty/too long.
    /// - [`Error::OutOfMemory`] if no slots are available.
    pub fn create_stack_trace(&mut self, name: &[u8], max_depth: usize) -> Result<usize> {
        let idx = self.find_free_slot()?;
        self.validate_name(name)?;

        let map = BpfStackTraceMap::new(max_depth)?;
        let info = BpfMapTypeInfo::new(
            ExtMapType::StackTrace,
            4, // u32 stack ID key
            (max_depth.min(STACK_TRACE_MAX_DEPTH)) * 8,
            STACK_TRACE_MAX_ENTRIES,
            name,
        )?;

        let slot = &mut self.slots[idx];
        slot.kind = ExtMapSlotKind::StackTrace(map);
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.info = info;
        self.count += 1;
        Ok(idx)
    }

    /// Destroy a map by its registry ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID is invalid or empty.
    pub fn destroy(&mut self, id: usize) -> Result<()> {
        if id >= MAX_EXT_MAPS || !self.slots[id].is_occupied() {
            return Err(Error::NotFound);
        }
        self.slots[id].kind = ExtMapSlotKind::Empty;
        self.slots[id].name_len = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Look up a per-CPU hash map by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a per-CPU hash.
    pub fn lookup_percpu_hash(&self, id: usize) -> Result<&BpfPerCpuHashMap> {
        if id >= MAX_EXT_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            ExtMapSlotKind::PerCpuHash(m) => Ok(m),
            ExtMapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable per-CPU hash map by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a per-CPU hash.
    pub fn lookup_percpu_hash_mut(&mut self, id: usize) -> Result<&mut BpfPerCpuHashMap> {
        if id >= MAX_EXT_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            ExtMapSlotKind::PerCpuHash(m) => Ok(m),
            ExtMapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up an LPM trie by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not an LPM trie.
    pub fn lookup_lpm_trie(&self, id: usize) -> Result<&BpfLpmTrie> {
        if id >= MAX_EXT_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            ExtMapSlotKind::LpmTrie(m) => Ok(m),
            ExtMapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable LPM trie by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not an LPM trie.
    pub fn lookup_lpm_trie_mut(&mut self, id: usize) -> Result<&mut BpfLpmTrie> {
        if id >= MAX_EXT_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            ExtMapSlotKind::LpmTrie(m) => Ok(m),
            ExtMapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a stack trace map by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a stack trace
    ///   map.
    pub fn lookup_stack_trace(&self, id: usize) -> Result<&BpfStackTraceMap> {
        if id >= MAX_EXT_MAPS {
            return Err(Error::NotFound);
        }
        match &self.slots[id].kind {
            ExtMapSlotKind::StackTrace(m) => Ok(m),
            ExtMapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up a mutable stack trace map by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::InvalidArgument`] if the map is not a stack trace
    ///   map.
    pub fn lookup_stack_trace_mut(&mut self, id: usize) -> Result<&mut BpfStackTraceMap> {
        if id >= MAX_EXT_MAPS {
            return Err(Error::NotFound);
        }
        match &mut self.slots[id].kind {
            ExtMapSlotKind::StackTrace(m) => Ok(m),
            ExtMapSlotKind::Empty => Err(Error::NotFound),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Look up the map type info by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID is invalid or empty.
    pub fn lookup_info(&self, id: usize) -> Result<&BpfMapTypeInfo> {
        if id >= MAX_EXT_MAPS || !self.slots[id].is_occupied() {
            return Err(Error::NotFound);
        }
        Ok(&self.slots[id].info)
    }

    /// Return the number of active maps.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // -- Internal helpers ----------------------------------------------------

    /// Find a free slot in the registry.
    fn find_free_slot(&self) -> Result<usize> {
        self.slots
            .iter()
            .position(|s| !s.is_occupied())
            .ok_or(Error::OutOfMemory)
    }

    /// Validate a map name.
    fn validate_name(&self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}
