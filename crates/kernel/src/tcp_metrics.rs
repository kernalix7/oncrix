// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TCP metrics cache subsystem.
//!
//! Maintains a per-destination cache of TCP performance metrics
//! (RTT, congestion window, ssthresh) that persists across TCP
//! connections. When a new connection opens to a previously seen
//! destination, it can restore cached metrics for faster convergence
//! instead of starting from scratch.
//!
//! # Cached Metrics
//!
//! | Metric   | Description                                     |
//! |----------|-------------------------------------------------|
//! | RTT      | Smoothed round-trip time (microseconds)          |
//! | RTT var  | RTT variance (microseconds)                      |
//! | CWND     | Last known congestion window (MSS units)         |
//! | SSTHRESH | Last known slow-start threshold (MSS units)      |
//!
//! # Cache Design
//!
//! The cache uses a hash table with separate chaining (fixed-size
//! bucket arrays). Entries age out based on a configurable expiration
//! time. On connection close, metrics are saved. On connection open,
//! cached metrics are restored if available and not expired.
//!
//! # Reference
//!
//! Linux kernel `net/ipv4/tcp_metrics.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of hash buckets.
const HASH_BUCKETS: usize = 128;

/// Maximum entries per bucket (chain length).
const MAX_ENTRIES_PER_BUCKET: usize = 8;

/// Total maximum entries in the cache.
const MAX_TOTAL_ENTRIES: usize = HASH_BUCKETS * MAX_ENTRIES_PER_BUCKET;

/// Default entry expiration time in seconds (10 minutes).
const DEFAULT_EXPIRATION_SECS: u64 = 600;

/// Minimum valid RTT in microseconds (1 us).
const MIN_RTT_US: u64 = 1;

/// Maximum valid RTT in microseconds (30 seconds).
const MAX_RTT_US: u64 = 30_000_000;

/// Minimum valid cwnd.
const MIN_CWND: u32 = 1;

/// Maximum valid cwnd.
const MAX_CWND: u32 = 65535;

/// Initial cwnd when no cached value exists (RFC 6928).
const INITIAL_CWND: u32 = 10;

/// Initial ssthresh when no cached value exists.
const INITIAL_SSTHRESH: u32 = 65535;

/// FNV-1a hash offset basis for 64-bit.
const FNV_OFFSET: u64 = 14695981039346656037;

/// FNV-1a hash prime for 64-bit.
const FNV_PRIME: u64 = 1099511628211;

// ── DestAddr ──────────────────────────────────────────────────────────────────

/// A destination address used as the cache key.
///
/// Supports both IPv4 and IPv6 destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestAddr {
    /// IPv4 destination (address + port).
    V4 {
        /// IPv4 address bytes.
        addr: [u8; 4],
        /// Destination port (0 = any).
        port: u16,
    },
    /// IPv6 destination (address + port).
    V6 {
        /// IPv6 address bytes.
        addr: [u8; 16],
        /// Destination port (0 = any).
        port: u16,
    },
}

impl DestAddr {
    /// Compute a hash of the address for bucket selection.
    pub fn hash(&self) -> u64 {
        let mut h = FNV_OFFSET;
        match self {
            Self::V4 { addr, port } => {
                for &b in addr {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
                h ^= *port as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
            Self::V6 { addr, port } => {
                for &b in addr {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
                h ^= *port as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
        }
        h
    }

    /// Get the bucket index for this address.
    fn bucket_index(&self) -> usize {
        (self.hash() as usize) % HASH_BUCKETS
    }
}

// ── TcpMetricsEntry ───────────────────────────────────────────────────────────

/// A single cached TCP metrics entry.
#[derive(Debug, Clone, Copy)]
pub struct TcpMetricsEntry {
    /// Destination address (cache key).
    dest: DestAddr,
    /// Smoothed RTT in microseconds.
    rtt_us: u64,
    /// RTT variance in microseconds.
    rttvar_us: u64,
    /// Last known congestion window (MSS units).
    cwnd: u32,
    /// Last known slow-start threshold.
    ssthresh: u32,
    /// Timestamp when this entry was last updated (seconds since boot).
    last_update_secs: u64,
    /// Number of times this entry has been saved.
    save_count: u32,
    /// Number of times this entry has been restored.
    restore_count: u32,
    /// Whether this entry slot is occupied.
    occupied: bool,
}

impl TcpMetricsEntry {
    /// Create an empty entry.
    pub const fn new() -> Self {
        Self {
            dest: DestAddr::V4 {
                addr: [0; 4],
                port: 0,
            },
            rtt_us: 0,
            rttvar_us: 0,
            cwnd: 0,
            ssthresh: 0,
            last_update_secs: 0,
            save_count: 0,
            restore_count: 0,
            occupied: false,
        }
    }

    /// Get the destination address.
    pub const fn dest(&self) -> &DestAddr {
        &self.dest
    }

    /// Get the smoothed RTT.
    pub const fn rtt_us(&self) -> u64 {
        self.rtt_us
    }

    /// Get the RTT variance.
    pub const fn rttvar_us(&self) -> u64 {
        self.rttvar_us
    }

    /// Get the cached cwnd.
    pub const fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Get the cached ssthresh.
    pub const fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Get the last update timestamp.
    pub const fn last_update_secs(&self) -> u64 {
        self.last_update_secs
    }

    /// Get the save count.
    pub const fn save_count(&self) -> u32 {
        self.save_count
    }

    /// Get the restore count.
    pub const fn restore_count(&self) -> u32 {
        self.restore_count
    }

    /// Check if this entry is valid (occupied and within bounds).
    pub fn is_valid(&self) -> bool {
        self.occupied && self.rtt_us >= MIN_RTT_US && self.rtt_us <= MAX_RTT_US
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self, now_secs: u64, expiration_secs: u64) -> bool {
        if !self.occupied {
            return true;
        }
        now_secs.saturating_sub(self.last_update_secs) > expiration_secs
    }
}

impl Default for TcpMetricsEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ── HashBucket ────────────────────────────────────────────────────────────────

/// A bucket in the hash table (fixed-size chain).
#[derive(Debug)]
struct HashBucket {
    /// Entries in this bucket.
    entries: [TcpMetricsEntry; MAX_ENTRIES_PER_BUCKET],
    /// Number of occupied entries.
    count: usize,
}

impl HashBucket {
    /// Create an empty bucket.
    const fn new() -> Self {
        Self {
            entries: [const { TcpMetricsEntry::new() }; MAX_ENTRIES_PER_BUCKET],
            count: 0,
        }
    }

    /// Look up an entry by destination address.
    fn lookup(&self, dest: &DestAddr) -> Option<usize> {
        for i in 0..self.count {
            if self.entries[i].occupied && self.entries[i].dest == *dest {
                return Some(i);
            }
        }
        None
    }

    /// Insert or update an entry.
    fn upsert(
        &mut self,
        dest: DestAddr,
        rtt_us: u64,
        rttvar_us: u64,
        cwnd: u32,
        ssthresh: u32,
        now_secs: u64,
    ) -> Result<()> {
        // Check for existing entry.
        if let Some(idx) = self.lookup(&dest) {
            let entry = &mut self.entries[idx];
            entry.rtt_us = rtt_us;
            entry.rttvar_us = rttvar_us;
            entry.cwnd = cwnd;
            entry.ssthresh = ssthresh;
            entry.last_update_secs = now_secs;
            entry.save_count += 1;
            return Ok(());
        }

        // Find free slot or evict oldest.
        let slot = if self.count < MAX_ENTRIES_PER_BUCKET {
            let s = self.count;
            self.count += 1;
            s
        } else {
            self.find_oldest_slot()
        };

        let entry = &mut self.entries[slot];
        entry.dest = dest;
        entry.rtt_us = rtt_us;
        entry.rttvar_us = rttvar_us;
        entry.cwnd = cwnd;
        entry.ssthresh = ssthresh;
        entry.last_update_secs = now_secs;
        entry.save_count = 1;
        entry.restore_count = 0;
        entry.occupied = true;
        Ok(())
    }

    /// Find the oldest entry in the bucket (LRU eviction candidate).
    fn find_oldest_slot(&self) -> usize {
        let mut oldest_idx = 0;
        let mut oldest_time = u64::MAX;
        for i in 0..self.count {
            if self.entries[i].last_update_secs < oldest_time {
                oldest_time = self.entries[i].last_update_secs;
                oldest_idx = i;
            }
        }
        oldest_idx
    }

    /// Remove an entry by destination.
    fn remove(&mut self, dest: &DestAddr) -> bool {
        if let Some(idx) = self.lookup(dest) {
            self.entries[idx].occupied = false;
            return true;
        }
        false
    }

    /// Remove expired entries.
    fn expire(&mut self, now_secs: u64, expiration_secs: u64) -> u32 {
        let mut removed = 0u32;
        for i in 0..self.count {
            if self.entries[i].occupied && self.entries[i].is_expired(now_secs, expiration_secs) {
                self.entries[i].occupied = false;
                removed += 1;
            }
        }
        removed
    }

    /// Count occupied entries.
    fn occupied_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.entries[i].occupied {
                n += 1;
            }
        }
        n
    }
}

// ── TcpMetricsCacheStats ──────────────────────────────────────────────────────

/// Aggregate cache statistics.
#[derive(Debug, Clone, Copy)]
pub struct TcpMetricsCacheStats {
    /// Total entries in the cache.
    pub total_entries: usize,
    /// Cache hits (successful restores).
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Total saves.
    pub saves: u64,
    /// Total entries expired.
    pub expired: u64,
    /// Total entries flushed.
    pub flushed: u64,
}

impl TcpMetricsCacheStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_entries: 0,
            hits: 0,
            misses: 0,
            saves: 0,
            expired: 0,
            flushed: 0,
        }
    }
}

impl Default for TcpMetricsCacheStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── RestoredMetrics ───────────────────────────────────────────────────────────

/// Metrics restored from cache for a new connection.
#[derive(Debug, Clone, Copy)]
pub struct RestoredMetrics {
    /// Smoothed RTT (microseconds).
    pub rtt_us: u64,
    /// RTT variance (microseconds).
    pub rttvar_us: u64,
    /// Congestion window (MSS units).
    pub cwnd: u32,
    /// Slow-start threshold.
    pub ssthresh: u32,
}

impl RestoredMetrics {
    /// Create default (uncached) metrics.
    pub const fn defaults() -> Self {
        Self {
            rtt_us: 0,
            rttvar_us: 0,
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
        }
    }
}

impl Default for RestoredMetrics {
    fn default() -> Self {
        Self::defaults()
    }
}

// ── TcpMetricsCache ──────────────────────────────────────────────────────────

/// TCP metrics cache.
///
/// Provides save-on-close and restore-on-open functionality for TCP
/// connections, caching per-destination metrics in a hash table.
pub struct TcpMetricsCache {
    /// Hash buckets.
    buckets: [HashBucket; HASH_BUCKETS],
    /// Entry expiration time in seconds.
    expiration_secs: u64,
    /// Cache statistics.
    stats: TcpMetricsCacheStats,
}

impl TcpMetricsCache {
    /// Create a new empty cache.
    pub const fn new() -> Self {
        Self {
            buckets: [const { HashBucket::new() }; HASH_BUCKETS],
            expiration_secs: DEFAULT_EXPIRATION_SECS,
            stats: TcpMetricsCacheStats::new(),
        }
    }

    /// Create a cache with custom expiration.
    pub const fn with_expiration(expiration_secs: u64) -> Self {
        Self {
            buckets: [const { HashBucket::new() }; HASH_BUCKETS],
            expiration_secs,
            stats: TcpMetricsCacheStats::new(),
        }
    }

    /// Save metrics on connection close.
    ///
    /// Stores the connection's final RTT, cwnd, and ssthresh for
    /// future connections to the same destination.
    pub fn save(
        &mut self,
        dest: DestAddr,
        rtt_us: u64,
        rttvar_us: u64,
        cwnd: u32,
        ssthresh: u32,
        now_secs: u64,
    ) -> Result<()> {
        // Validate metrics.
        if rtt_us < MIN_RTT_US || rtt_us > MAX_RTT_US {
            return Err(Error::InvalidArgument);
        }
        if cwnd < MIN_CWND || cwnd > MAX_CWND {
            return Err(Error::InvalidArgument);
        }

        let bucket_idx = dest.bucket_index();
        self.buckets[bucket_idx].upsert(dest, rtt_us, rttvar_us, cwnd, ssthresh, now_secs)?;
        self.stats.saves += 1;
        Ok(())
    }

    /// Restore metrics on connection open.
    ///
    /// Returns cached metrics if available and not expired, or
    /// default values otherwise.
    pub fn restore(&mut self, dest: &DestAddr, now_secs: u64) -> RestoredMetrics {
        let bucket_idx = dest.bucket_index();
        let bucket = &mut self.buckets[bucket_idx];

        if let Some(entry_idx) = bucket.lookup(dest) {
            let entry = &mut bucket.entries[entry_idx];
            if !entry.is_expired(now_secs, self.expiration_secs) && entry.is_valid() {
                entry.restore_count += 1;
                self.stats.hits += 1;
                return RestoredMetrics {
                    rtt_us: entry.rtt_us,
                    rttvar_us: entry.rttvar_us,
                    cwnd: entry.cwnd,
                    ssthresh: entry.ssthresh,
                };
            }
        }

        self.stats.misses += 1;
        RestoredMetrics::defaults()
    }

    /// Look up an entry without modifying it.
    pub fn lookup(&self, dest: &DestAddr) -> Option<&TcpMetricsEntry> {
        let bucket_idx = dest.bucket_index();
        let bucket = &self.buckets[bucket_idx];
        if let Some(entry_idx) = bucket.lookup(dest) {
            if bucket.entries[entry_idx].occupied {
                return Some(&bucket.entries[entry_idx]);
            }
        }
        None
    }

    /// Remove a specific entry from the cache.
    pub fn remove(&mut self, dest: &DestAddr) -> Result<()> {
        let bucket_idx = dest.bucket_index();
        if self.buckets[bucket_idx].remove(dest) {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Expire old entries based on the current time.
    ///
    /// Returns the number of entries expired.
    pub fn expire(&mut self, now_secs: u64) -> u32 {
        let mut total = 0u32;
        for bucket in &mut self.buckets {
            total += bucket.expire(now_secs, self.expiration_secs);
        }
        self.stats.expired += total as u64;
        total
    }

    /// Flush (clear) the entire cache.
    pub fn flush(&mut self) {
        let count = self.total_entries();
        for bucket in &mut self.buckets {
            for i in 0..bucket.count {
                bucket.entries[i].occupied = false;
            }
            bucket.count = 0;
        }
        self.stats.flushed += count as u64;
    }

    /// Set the expiration time.
    pub fn set_expiration(&mut self, secs: u64) {
        self.expiration_secs = secs;
    }

    /// Get the expiration time.
    pub const fn expiration_secs(&self) -> u64 {
        self.expiration_secs
    }

    /// Get the total number of entries in the cache.
    pub fn total_entries(&self) -> usize {
        let mut total = 0;
        for bucket in &self.buckets {
            total += bucket.occupied_count();
        }
        total
    }

    /// Get cache statistics.
    pub fn stats(&self) -> TcpMetricsCacheStats {
        let mut s = self.stats;
        s.total_entries = self.total_entries();
        s
    }

    /// Dump all entries (for netlink tcp_metrics dump).
    ///
    /// Calls the provided closure for each occupied entry.
    /// Returns the number of entries dumped.
    pub fn dump<F>(&self, mut callback: F) -> usize
    where
        F: FnMut(&TcpMetricsEntry),
    {
        let mut count = 0;
        for bucket in &self.buckets {
            for i in 0..bucket.count {
                if bucket.entries[i].occupied {
                    callback(&bucket.entries[i]);
                    count += 1;
                }
            }
        }
        count
    }
}

impl Default for TcpMetricsCache {
    fn default() -> Self {
        Self::new()
    }
}
