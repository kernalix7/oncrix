// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Firmware loading.
//!
//! Provides the kernel-side firmware loading API. Drivers call
//! `request_firmware()` to load binary firmware blobs from a
//! firmware store, and `release_firmware()` to free them.
//!
//! # Design
//!
//! ```text
//!   FwEntry
//!   +------------------+
//!   | name             |
//!   | data[FW_MAX_SZ]  |
//!   | size             |
//!   | status           |  Loading → Ready | Error
//!   | ref_count        |
//!   +------------------+
//!
//!   FirmwareCache:
//!   Caches recently loaded firmware to avoid repeated disk I/O.
//! ```
//!
//! # Lifecycle
//!
//! 1. `request_firmware(name)` — loads firmware, waits until
//!    ready.
//! 2. Driver uses `fw.data()` / `fw.size()`.
//! 3. `release_firmware(idx)` — decrements refcount, frees on 0.
//!
//! # Reference
//!
//! Linux `drivers/base/firmware_loader/`,
//! `include/linux/firmware.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum firmware data size (64 KiB).
const FW_MAX_SIZE: usize = 65536;

/// Maximum firmware entries.
const MAX_FW_ENTRIES: usize = 64;

/// Maximum name length.
const MAX_NAME_LEN: usize = 64;

/// Firmware load timeout (ms).
const _FW_TIMEOUT_MS: u64 = 30_000;

/// Maximum cached firmware entries.
const MAX_CACHE_ENTRIES: usize = 16;

// ======================================================================
// FwStatus
// ======================================================================

/// Status of a firmware entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwStatus {
    /// Firmware is being loaded.
    Loading,
    /// Firmware is ready for use.
    Ready,
    /// An error occurred during loading.
    Error,
    /// Firmware has been released.
    Released,
}

// ======================================================================
// FwEntry
// ======================================================================

/// A loaded firmware blob.
pub struct FwEntry {
    /// Firmware name / path.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Firmware data.
    data: [u8; FW_MAX_SIZE],
    /// Actual data size.
    size: usize,
    /// Current status.
    status: FwStatus,
    /// Reference count.
    ref_count: u32,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Load timestamp (ns).
    load_time_ns: u64,
}

impl FwEntry {
    /// Creates a new empty entry.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            data: [0u8; FW_MAX_SIZE],
            size: 0,
            status: FwStatus::Released,
            ref_count: 0,
            allocated: false,
            load_time_ns: 0,
        }
    }

    /// Returns the firmware name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the firmware data.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }

    /// Returns the firmware size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the status.
    pub fn status(&self) -> FwStatus {
        self.status
    }

    /// Returns the reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Returns the load timestamp.
    pub fn load_time_ns(&self) -> u64 {
        self.load_time_ns
    }
}

// ======================================================================
// FirmwareCache
// ======================================================================

/// Cache entry for recently loaded firmware.
#[derive(Clone, Copy)]
struct CacheEntry {
    /// Firmware name hash.
    name_hash: u64,
    /// Firmware entry index.
    fw_idx: usize,
    /// Whether valid.
    valid: bool,
    /// Last access timestamp.
    last_access: u64,
}

impl CacheEntry {
    const fn new() -> Self {
        Self {
            name_hash: 0,
            fw_idx: 0,
            valid: false,
            last_access: 0,
        }
    }
}

// ======================================================================
// FirmwareManager
// ======================================================================

/// Manages firmware loading, caching, and lifecycle.
pub struct FirmwareManager {
    /// Firmware entries.
    entries: [FwEntry; MAX_FW_ENTRIES],
    /// Number of allocated entries.
    count: usize,
    /// Cache.
    cache: [CacheEntry; MAX_CACHE_ENTRIES],
    /// Global timestamp counter.
    timestamp: u64,
    /// Statistics: total requests.
    stats_requests: u64,
    /// Statistics: cache hits.
    stats_cache_hits: u64,
    /// Statistics: load failures.
    stats_failures: u64,
}

impl FirmwareManager {
    /// Creates a new firmware manager.
    pub const fn new() -> Self {
        Self {
            entries: [const { FwEntry::new() }; MAX_FW_ENTRIES],
            count: 0,
            cache: [const { CacheEntry::new() }; MAX_CACHE_ENTRIES],
            timestamp: 0,
            stats_requests: 0,
            stats_cache_hits: 0,
            stats_failures: 0,
        }
    }

    /// Requests firmware by name.
    ///
    /// Simulates loading firmware data. In a real kernel this
    /// would trigger a uevent to user space to supply the blob.
    /// Returns the firmware entry index.
    pub fn request_firmware(&mut self, name: &[u8], data: &[u8]) -> Result<usize> {
        self.stats_requests += 1;
        self.timestamp += 1;

        // Check cache first.
        let hash = self.hash_name(name);
        for i in 0..MAX_CACHE_ENTRIES {
            if self.cache[i].valid && self.cache[i].name_hash == hash {
                let fi = self.cache[i].fw_idx;
                if fi < MAX_FW_ENTRIES
                    && self.entries[fi].allocated
                    && self.entries[fi].status == FwStatus::Ready
                {
                    self.entries[fi].ref_count += 1;
                    self.cache[i].last_access = self.timestamp;
                    self.stats_cache_hits += 1;
                    return Ok(fi);
                }
            }
        }

        // Allocate new entry.
        if data.len() > FW_MAX_SIZE {
            self.stats_failures += 1;
            return Err(Error::InvalidArgument);
        }
        let idx = self.alloc_entry()?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.entries[idx].data[..data.len()].copy_from_slice(data);
        self.entries[idx].size = data.len();
        self.entries[idx].status = FwStatus::Ready;
        self.entries[idx].ref_count = 1;
        self.entries[idx].load_time_ns = self.timestamp;

        // Add to cache.
        self.cache_add(hash, idx);

        Ok(idx)
    }

    /// Releases a firmware entry.
    ///
    /// Decrements refcount; frees when it reaches zero.
    pub fn release_firmware(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_FW_ENTRIES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.entries[idx].ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx].ref_count -= 1;
        if self.entries[idx].ref_count == 0 {
            self.entries[idx].status = FwStatus::Released;
            self.entries[idx] = FwEntry::new();
            self.count -= 1;
        }
        Ok(())
    }

    /// Returns a reference to a firmware entry.
    pub fn get(&self, idx: usize) -> Result<&FwEntry> {
        if idx >= MAX_FW_ENTRIES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx])
    }

    /// Returns the number of loaded firmware entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns total requests.
    pub fn stats_requests(&self) -> u64 {
        self.stats_requests
    }

    /// Returns cache hits.
    pub fn stats_cache_hits(&self) -> u64 {
        self.stats_cache_hits
    }

    /// Returns load failures.
    pub fn stats_failures(&self) -> u64 {
        self.stats_failures
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Allocates a firmware entry slot.
    fn alloc_entry(&mut self) -> Result<usize> {
        if self.count >= MAX_FW_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].allocated = true;
        self.count += 1;
        Ok(idx)
    }

    /// Simple hash of a name for cache lookup.
    fn hash_name(&self, name: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in name {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h
    }

    /// Adds an entry to the cache (LRU eviction).
    fn cache_add(&mut self, hash: u64, fw_idx: usize) {
        // Find an empty slot or the oldest entry.
        let mut oldest_idx = 0;
        let mut oldest_ts = u64::MAX;
        for i in 0..MAX_CACHE_ENTRIES {
            if !self.cache[i].valid {
                self.cache[i] = CacheEntry {
                    name_hash: hash,
                    fw_idx,
                    valid: true,
                    last_access: self.timestamp,
                };
                return;
            }
            if self.cache[i].last_access < oldest_ts {
                oldest_ts = self.cache[i].last_access;
                oldest_idx = i;
            }
        }
        // Evict oldest.
        self.cache[oldest_idx] = CacheEntry {
            name_hash: hash,
            fw_idx,
            valid: true,
            last_access: self.timestamp,
        };
    }
}
