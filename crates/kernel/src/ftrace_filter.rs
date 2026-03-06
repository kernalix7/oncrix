// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ftrace function filter management.
//!
//! Provides a mechanism to selectively enable or disable tracing for
//! individual kernel functions. Filters are applied through a hash-based
//! lookup that maps function addresses to their tracing state. Supports
//! both inclusive (trace only listed) and exclusive (trace all except
//! listed) filter modes.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of filter entries.
const MAX_FILTER_ENTRIES: usize = 512;

/// Maximum number of filter groups.
const MAX_FILTER_GROUPS: usize = 16;

/// Maximum symbol name length.
const MAX_SYMBOL_LEN: usize = 64;

/// Hash table bucket count for fast lookup.
const HASH_BUCKETS: usize = 128;

// ── Types ────────────────────────────────────────────────────────────

/// Filter mode determines the default tracing behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Only trace functions that match the filter (allowlist).
    Inclusive,
    /// Trace all functions except those matching the filter (denylist).
    Exclusive,
    /// No filtering — trace everything.
    Disabled,
}

impl Default for FilterMode {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Identifies a filter group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterGroupId(u32);

impl FilterGroupId {
    /// Creates a new filter group identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// A single function filter entry.
#[derive(Debug, Clone)]
pub struct FtraceFilterEntry {
    /// Address of the filtered function.
    function_addr: u64,
    /// Symbol name bytes.
    symbol: [u8; MAX_SYMBOL_LEN],
    /// Length of the symbol name.
    symbol_len: usize,
    /// Group this entry belongs to.
    group_id: FilterGroupId,
    /// Whether this entry is currently active.
    active: bool,
    /// Number of times this filter was matched.
    hit_count: u64,
}

impl FtraceFilterEntry {
    /// Creates a new filter entry.
    pub const fn new(function_addr: u64, group_id: FilterGroupId) -> Self {
        Self {
            function_addr,
            symbol: [0u8; MAX_SYMBOL_LEN],
            symbol_len: 0,
            group_id,
            active: true,
            hit_count: 0,
        }
    }

    /// Returns the function address.
    pub const fn function_addr(&self) -> u64 {
        self.function_addr
    }

    /// Returns whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the match hit count.
    pub const fn hit_count(&self) -> u64 {
        self.hit_count
    }
}

/// A named group of filter entries.
#[derive(Debug)]
pub struct FilterGroup {
    /// Group identifier.
    id: FilterGroupId,
    /// Group name bytes.
    name: [u8; 32],
    /// Length of valid name bytes.
    name_len: usize,
    /// Number of entries in this group.
    entry_count: u32,
    /// Filter mode for this group.
    mode: FilterMode,
    /// Whether the group is enabled.
    enabled: bool,
}

impl FilterGroup {
    /// Creates a new filter group.
    pub const fn new(id: FilterGroupId, mode: FilterMode) -> Self {
        Self {
            id,
            name: [0u8; 32],
            name_len: 0,
            entry_count: 0,
            mode,
            enabled: true,
        }
    }

    /// Returns the filter mode for this group.
    pub const fn mode(&self) -> FilterMode {
        self.mode
    }

    /// Returns whether the group is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Hash bucket for fast address lookup.
#[derive(Debug)]
pub struct FilterHashBucket {
    /// Indices into the entry array for this bucket.
    indices: [Option<u16>; 8],
    /// Number of valid indices.
    count: usize,
}

impl FilterHashBucket {
    /// Creates an empty hash bucket.
    pub const fn new() -> Self {
        Self {
            indices: [None; 8],
            count: 0,
        }
    }
}

impl Default for FilterHashBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the ftrace filter subsystem.
#[derive(Debug, Clone)]
pub struct FtraceFilterStats {
    /// Total number of filter entries.
    pub total_entries: u32,
    /// Total active entries.
    pub active_entries: u32,
    /// Total filter groups.
    pub total_groups: u32,
    /// Total lookup operations.
    pub total_lookups: u64,
    /// Total lookup hits.
    pub total_hits: u64,
}

impl Default for FtraceFilterStats {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceFilterStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_entries: 0,
            active_entries: 0,
            total_groups: 0,
            total_lookups: 0,
            total_hits: 0,
        }
    }
}

/// Central ftrace filter manager.
#[derive(Debug)]
pub struct FtraceFilterManager {
    /// Filter entries.
    entries: [Option<FtraceFilterEntry>; MAX_FILTER_ENTRIES],
    /// Filter groups.
    groups: [Option<FilterGroup>; MAX_FILTER_GROUPS],
    /// Hash buckets for address lookup.
    buckets: [FilterHashBucket; HASH_BUCKETS],
    /// Number of registered entries.
    entry_count: usize,
    /// Number of registered groups.
    group_count: usize,
    /// Global filter mode.
    global_mode: FilterMode,
    /// Total lookups performed.
    total_lookups: u64,
    /// Total hits.
    total_hits: u64,
}

impl Default for FtraceFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceFilterManager {
    /// Creates a new ftrace filter manager.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_FILTER_ENTRIES],
            groups: [const { None }; MAX_FILTER_GROUPS],
            buckets: [const { FilterHashBucket::new() }; HASH_BUCKETS],
            entry_count: 0,
            group_count: 0,
            global_mode: FilterMode::Disabled,
            total_lookups: 0,
            total_hits: 0,
        }
    }

    /// Computes the hash bucket index for an address.
    fn bucket_index(addr: u64) -> usize {
        ((addr >> 2) as usize) % HASH_BUCKETS
    }

    /// Creates a new filter group.
    pub fn create_group(&mut self, mode: FilterMode) -> Result<FilterGroupId> {
        if self.group_count >= MAX_FILTER_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let id = FilterGroupId::new(self.group_count as u32);
        let group = FilterGroup::new(id, mode);
        if let Some(slot) = self.groups.iter_mut().find(|s| s.is_none()) {
            *slot = Some(group);
            self.group_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Adds a function address to a filter group.
    pub fn add_filter(&mut self, function_addr: u64, group_id: FilterGroupId) -> Result<()> {
        if self.entry_count >= MAX_FILTER_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Verify group exists.
        let group_exists = self.groups.iter().flatten().any(|g| g.id == group_id);
        if !group_exists {
            return Err(Error::NotFound);
        }
        let entry = FtraceFilterEntry::new(function_addr, group_id);
        let entry_idx = self
            .entries
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[entry_idx] = Some(entry);
        self.entry_count += 1;
        // Insert into hash bucket.
        let bucket_idx = Self::bucket_index(function_addr);
        let bucket = &mut self.buckets[bucket_idx];
        if bucket.count < 8 {
            bucket.indices[bucket.count] = Some(entry_idx as u16);
            bucket.count += 1;
        }
        // Increment group entry count.
        if let Some(g) = self.groups.iter_mut().flatten().find(|g| g.id == group_id) {
            g.entry_count += 1;
        }
        Ok(())
    }

    /// Checks whether a function address should be traced.
    pub fn should_trace(&mut self, function_addr: u64) -> bool {
        self.total_lookups += 1;
        let bucket_idx = Self::bucket_index(function_addr);
        let bucket = &self.buckets[bucket_idx];
        let mut found = false;
        for i in 0..bucket.count {
            if let Some(idx) = bucket.indices[i] {
                if let Some(entry) = &self.entries[idx as usize] {
                    if entry.function_addr == function_addr && entry.active {
                        found = true;
                        break;
                    }
                }
            }
        }
        if found {
            self.total_hits += 1;
        }
        match self.global_mode {
            FilterMode::Inclusive => found,
            FilterMode::Exclusive => !found,
            FilterMode::Disabled => true,
        }
    }

    /// Removes a filter entry by function address.
    pub fn remove_filter(&mut self, function_addr: u64) -> Result<()> {
        let idx = self
            .entries
            .iter()
            .position(|s| {
                s.as_ref()
                    .map_or(false, |e| e.function_addr == function_addr)
            })
            .ok_or(Error::NotFound)?;
        self.entries[idx] = None;
        self.entry_count -= 1;
        Ok(())
    }

    /// Sets the global filter mode.
    pub fn set_global_mode(&mut self, mode: FilterMode) {
        self.global_mode = mode;
    }

    /// Collects statistics.
    pub fn stats(&self) -> FtraceFilterStats {
        let active = self.entries.iter().flatten().filter(|e| e.active).count() as u32;
        FtraceFilterStats {
            total_entries: self.entry_count as u32,
            active_entries: active,
            total_groups: self.group_count as u32,
            total_lookups: self.total_lookups,
            total_hits: self.total_hits,
        }
    }

    /// Returns the number of filter entries.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }
}
