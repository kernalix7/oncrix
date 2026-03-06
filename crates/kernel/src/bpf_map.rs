// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF map types — hash, array, and LPM trie.
//!
//! Implements the three most fundamental BPF map types used by kernel programs:
//!
//! - **Array map**: O(1) lookup by u32 index; fixed size; values zero-initialized.
//! - **Hash map**: O(1) average lookup by arbitrary key; open-addressing with
//!   linear probing.
//! - **LPM trie**: Longest-prefix match for routing / classifier programs.
//!
//! All maps are bounded at compile time (no heap in hot paths).
//!
//! # Architecture
//!
//! | Component        | Purpose                                             |
//! |------------------|-----------------------------------------------------|
//! | [`BpfMapType`]   | Discriminant for map type                           |
//! | [`ArrayMap`]     | Fixed-size array map                                |
//! | [`HashMap`]      | Open-addressing hash map                            |
//! | [`LpmTrieMap`]   | Longest-prefix-match trie map                       |
//! | [`BpfMapHandle`] | Unified handle over any map type                    |

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum key length in bytes.
pub const MAX_KEY_SIZE: usize = 64;

/// Maximum value length in bytes.
pub const MAX_VALUE_SIZE: usize = 256;

/// Maximum entries in an array map.
pub const ARRAY_MAP_MAX_ENTRIES: usize = 1024;

/// Maximum entries in a hash map.
pub const HASH_MAP_MAX_ENTRIES: usize = 1024;

/// Maximum entries in an LPM trie.
pub const LPM_TRIE_MAX_ENTRIES: usize = 512;

/// Maximum number of open map handles.
pub const MAX_MAP_HANDLES: usize = 128;

// ---------------------------------------------------------------------------
// Map type
// ---------------------------------------------------------------------------

/// BPF map type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfMapType {
    #[default]
    /// Unspecified.
    Unspecified,
    /// Fixed-size array indexed by u32.
    Array,
    /// Hash map with arbitrary key.
    Hash,
    /// Longest-prefix-match trie.
    LpmTrie,
}

// ---------------------------------------------------------------------------
// Key/value storage
// ---------------------------------------------------------------------------

/// Fixed-size key storage.
#[derive(Clone, Copy)]
pub struct MapKey {
    pub data: [u8; MAX_KEY_SIZE],
    pub len: u8,
}

impl MapKey {
    /// Create a key from a byte slice (truncated to `MAX_KEY_SIZE`).
    pub fn from_slice(s: &[u8]) -> Self {
        let len = s.len().min(MAX_KEY_SIZE);
        let mut data = [0u8; MAX_KEY_SIZE];
        data[..len].copy_from_slice(&s[..len]);
        Self {
            data,
            len: len as u8,
        }
    }

    /// Return the key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl Default for MapKey {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_KEY_SIZE],
            len: 0,
        }
    }
}

impl core::fmt::Debug for MapKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MapKey")
            .field("len", &self.len)
            .field("data", &&self.data[..self.len as usize])
            .finish()
    }
}

/// Fixed-size value storage.
#[derive(Clone, Copy)]
pub struct MapValue {
    pub data: [u8; MAX_VALUE_SIZE],
    pub len: u16,
}

impl MapValue {
    /// Create a value from a byte slice.
    pub fn from_slice(s: &[u8]) -> Self {
        let len = s.len().min(MAX_VALUE_SIZE);
        let mut data = [0u8; MAX_VALUE_SIZE];
        data[..len].copy_from_slice(&s[..len]);
        Self {
            data,
            len: len as u16,
        }
    }

    /// Return the value as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl Default for MapValue {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_VALUE_SIZE],
            len: 0,
        }
    }
}

impl core::fmt::Debug for MapValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MapValue")
            .field("len", &self.len)
            .field("data", &&self.data[..self.len as usize])
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Array map
// ---------------------------------------------------------------------------

/// Fixed-size BPF array map. Key is a u32 index.
pub struct ArrayMap {
    values: [MapValue; ARRAY_MAP_MAX_ENTRIES],
    max_entries: usize,
}

impl ArrayMap {
    /// Create a new array map with the given number of entries (capped at max).
    pub const fn new(max_entries: usize) -> Self {
        let cap = if max_entries > ARRAY_MAP_MAX_ENTRIES {
            ARRAY_MAP_MAX_ENTRIES
        } else {
            max_entries
        };
        Self {
            values: [MapValue {
                data: [0u8; MAX_VALUE_SIZE],
                len: 0,
            }; ARRAY_MAP_MAX_ENTRIES],
            max_entries: cap,
        }
    }

    /// Look up entry by index.
    pub fn lookup(&self, index: u32) -> Option<&MapValue> {
        let idx = index as usize;
        if idx < self.max_entries {
            Some(&self.values[idx])
        } else {
            None
        }
    }

    /// Update entry by index.
    pub fn update(&mut self, index: u32, value: &MapValue) -> Result<()> {
        let idx = index as usize;
        if idx >= self.max_entries {
            return Err(Error::InvalidArgument);
        }
        self.values[idx] = *value;
        Ok(())
    }

    /// Delete (zero) entry by index.
    pub fn delete(&mut self, index: u32) -> Result<()> {
        let idx = index as usize;
        if idx >= self.max_entries {
            return Err(Error::InvalidArgument);
        }
        self.values[idx] = MapValue::default();
        Ok(())
    }

    /// Maximum number of entries.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
}

impl Default for ArrayMap {
    fn default() -> Self {
        Self::new(ARRAY_MAP_MAX_ENTRIES)
    }
}

// ---------------------------------------------------------------------------
// Hash map (open addressing, linear probing)
// ---------------------------------------------------------------------------

/// A single hash map slot.
#[derive(Clone, Copy, Default)]
struct HashSlot {
    key: MapKey,
    value: MapValue,
    occupied: bool,
}

/// Open-addressing hash map.
pub struct HashMap {
    slots: [HashSlot; HASH_MAP_MAX_ENTRIES],
    count: usize,
    max_entries: usize,
}

impl HashMap {
    /// Create a new hash map.
    pub const fn new(max_entries: usize) -> Self {
        let cap = if max_entries > HASH_MAP_MAX_ENTRIES {
            HASH_MAP_MAX_ENTRIES
        } else {
            max_entries
        };
        Self {
            slots: [HashSlot {
                key: MapKey {
                    data: [0u8; MAX_KEY_SIZE],
                    len: 0,
                },
                value: MapValue {
                    data: [0u8; MAX_VALUE_SIZE],
                    len: 0,
                },
                occupied: false,
            }; HASH_MAP_MAX_ENTRIES],
            count: 0,
            max_entries: cap,
        }
    }

    fn hash(key: &MapKey) -> usize {
        // FNV-1a hash.
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in key.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h as usize
    }

    fn find_slot(&self, key: &MapKey) -> Option<usize> {
        let start = Self::hash(key) % self.max_entries;
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            if !self.slots[idx].occupied {
                return None;
            }
            if self.slots[idx].key.as_bytes() == key.as_bytes() {
                return Some(idx);
            }
        }
        None
    }

    fn find_free_slot(&self, key: &MapKey) -> Option<usize> {
        let start = Self::hash(key) % self.max_entries;
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            if !self.slots[idx].occupied {
                return Some(idx);
            }
        }
        None
    }

    /// Look up a value by key.
    pub fn lookup(&self, key: &MapKey) -> Option<&MapValue> {
        self.find_slot(key).map(|idx| &self.slots[idx].value)
    }

    /// Insert or update a key-value pair.
    pub fn update(&mut self, key: &MapKey, value: &MapValue) -> Result<()> {
        if let Some(idx) = self.find_slot(key) {
            self.slots[idx].value = *value;
            return Ok(());
        }
        if self.count >= self.max_entries {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot(key).ok_or(Error::OutOfMemory)?;
        self.slots[idx].key = *key;
        self.slots[idx].value = *value;
        self.slots[idx].occupied = true;
        self.count += 1;
        Ok(())
    }

    /// Delete a key.
    pub fn delete(&mut self, key: &MapKey) -> Result<()> {
        let idx = self.find_slot(key).ok_or(Error::NotFound)?;
        self.slots[idx].occupied = false;
        self.slots[idx].key = MapKey::default();
        self.slots[idx].value = MapValue::default();
        self.count -= 1;
        Ok(())
    }

    /// Number of entries in the map.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for HashMap {
    fn default() -> Self {
        Self::new(HASH_MAP_MAX_ENTRIES)
    }
}

// ---------------------------------------------------------------------------
// LPM trie map
// ---------------------------------------------------------------------------

/// An LPM trie key: prefix data + prefix length in bits.
#[derive(Clone, Copy, Debug)]
pub struct LpmKey {
    /// Prefix data (up to MAX_KEY_SIZE bytes).
    pub data: [u8; MAX_KEY_SIZE],
    /// Data length in bytes.
    pub data_len: u8,
    /// Prefix length in bits.
    pub prefix_len: u8,
}

impl Default for LpmKey {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_KEY_SIZE],
            data_len: 0,
            prefix_len: 0,
        }
    }
}

impl LpmKey {
    /// Create an LPM key from bytes and a bit prefix length.
    pub fn new(data: &[u8], prefix_len: u8) -> Self {
        let len = data.len().min(MAX_KEY_SIZE);
        let mut out = [0u8; MAX_KEY_SIZE];
        out[..len].copy_from_slice(&data[..len]);
        Self {
            data: out,
            data_len: len as u8,
            prefix_len,
        }
    }

    /// Returns true if `self` is a prefix of `other`.
    pub fn is_prefix_of(&self, other: &LpmKey) -> bool {
        if self.prefix_len > other.prefix_len {
            return false;
        }
        let full_bytes = self.prefix_len as usize / 8;
        let rem_bits = self.prefix_len as usize % 8;
        if full_bytes > 0 && self.data[..full_bytes] != other.data[..full_bytes] {
            return false;
        }
        if rem_bits > 0 && full_bytes < MAX_KEY_SIZE {
            let mask = 0xffu8 << (8 - rem_bits);
            if (self.data[full_bytes] & mask) != (other.data[full_bytes] & mask) {
                return false;
            }
        }
        true
    }
}

/// A single LPM trie entry.
#[derive(Clone, Copy, Default)]
struct LpmEntry {
    key: LpmKey,
    value: MapValue,
    occupied: bool,
}

/// Longest-prefix-match trie implemented as a linear search over stored prefixes.
///
/// For kernel BPF use cases the entry count is bounded and linear scan is
/// acceptable. A radix trie would be used in a production kernel.
pub struct LpmTrieMap {
    entries: [LpmEntry; LPM_TRIE_MAX_ENTRIES],
    count: usize,
    max_entries: usize,
}

impl LpmTrieMap {
    /// Create a new LPM trie.
    pub const fn new(max_entries: usize) -> Self {
        let cap = if max_entries > LPM_TRIE_MAX_ENTRIES {
            LPM_TRIE_MAX_ENTRIES
        } else {
            max_entries
        };
        Self {
            entries: [LpmEntry {
                key: LpmKey {
                    data: [0u8; MAX_KEY_SIZE],
                    data_len: 0,
                    prefix_len: 0,
                },
                value: MapValue {
                    data: [0u8; MAX_VALUE_SIZE],
                    len: 0,
                },
                occupied: false,
            }; LPM_TRIE_MAX_ENTRIES],
            count: 0,
            max_entries: cap,
        }
    }

    /// Longest-prefix lookup.
    ///
    /// Returns the value associated with the longest matching prefix.
    pub fn lookup(&self, key: &LpmKey) -> Option<&MapValue> {
        let mut best: Option<(u8, &MapValue)> = None;
        for entry in self.entries[..self.count].iter() {
            if !entry.occupied {
                continue;
            }
            if entry.key.is_prefix_of(key) {
                let is_better = best.map_or(true, |(len, _)| entry.key.prefix_len > len);
                if is_better {
                    best = Some((entry.key.prefix_len, &entry.value));
                }
            }
        }
        best.map(|(_, v)| v)
    }

    /// Insert or update a prefix entry.
    pub fn update(&mut self, key: &LpmKey, value: &MapValue) -> Result<()> {
        // Update existing entry if present.
        for entry in self.entries[..self.count].iter_mut() {
            if entry.occupied
                && entry.key.prefix_len == key.prefix_len
                && entry.key.data_len == key.data_len
                && entry.key.data[..key.data_len as usize] == key.data[..key.data_len as usize]
            {
                entry.value = *value;
                return Ok(());
            }
        }
        if self.count >= self.max_entries {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = LpmEntry {
            key: *key,
            value: *value,
            occupied: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Delete a prefix entry.
    pub fn delete(&mut self, key: &LpmKey) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| {
                e.occupied
                    && e.key.prefix_len == key.prefix_len
                    && e.key.data_len == key.data_len
                    && e.key.data[..key.data_len as usize] == key.data[..key.data_len as usize]
            })
            .ok_or(Error::NotFound)?;
        self.entries[pos].occupied = false;
        Ok(())
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.occupied)
            .count()
    }

    /// Returns true if the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for LpmTrieMap {
    fn default() -> Self {
        Self::new(LPM_TRIE_MAX_ENTRIES)
    }
}

// ---------------------------------------------------------------------------
// Unified map handle
// ---------------------------------------------------------------------------

/// Discriminated union over all map types.
pub enum BpfMapHandle {
    Array(ArrayMap),
    Hash(HashMap),
    LpmTrie(LpmTrieMap),
}

impl BpfMapHandle {
    /// Map type discriminant.
    pub fn map_type(&self) -> BpfMapType {
        match self {
            Self::Array(_) => BpfMapType::Array,
            Self::Hash(_) => BpfMapType::Hash,
            Self::LpmTrie(_) => BpfMapType::LpmTrie,
        }
    }
}
