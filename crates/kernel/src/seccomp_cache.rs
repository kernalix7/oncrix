// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Seccomp filter cache — caching seccomp filter decisions for performance.
//!
//! The seccomp cache stores the results of previous filter evaluations
//! to avoid re-running BPF programs for repeated syscall patterns.
//! Each task's seccomp filter chain produces a bitmap indicating which
//! syscalls are unconditionally allowed, avoiding BPF evaluation.
//!
//! # Reference
//!
//! Linux `kernel/seccomp.c` (seccomp_cache_prepare, __seccomp_filter).

use oncrix_lib::{Error, Result};

const MAX_CACHE_ENTRIES: usize = 256;
const MAX_SYSCALLS: usize = 512;
const BITMAP_WORDS: usize = MAX_SYSCALLS / 64;

/// Action cached for a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CachedAction {
    /// Must evaluate the BPF filter.
    Evaluate = 0,
    /// Unconditionally allowed.
    Allow = 1,
    /// Unconditionally denied (kill).
    Kill = 2,
    /// Unconditionally returns errno.
    Errno = 3,
    /// Log and allow.
    LogAllow = 4,
}

/// A per-task seccomp cache entry.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntry {
    /// PID of the task.
    pub pid: u64,
    /// Filter hash (identifies the filter chain).
    pub filter_hash: u64,
    /// Bitmap of allowed syscalls (bit set = allowed without BPF).
    pub allow_bitmap: [u64; BITMAP_WORDS],
    /// Bitmap of denied syscalls (bit set = denied without BPF).
    pub deny_bitmap: [u64; BITMAP_WORDS],
    /// Whether this entry is valid.
    pub valid: bool,
    /// Number of cache hits for this entry.
    pub hit_count: u64,
    /// Number of cache misses (required BPF evaluation).
    pub miss_count: u64,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            pid: 0,
            filter_hash: 0,
            allow_bitmap: [0u64; BITMAP_WORDS],
            deny_bitmap: [0u64; BITMAP_WORDS],
            valid: false,
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Check if a syscall is in the allow bitmap.
    pub fn is_allowed(&self, syscall_nr: usize) -> bool {
        if syscall_nr >= MAX_SYSCALLS {
            return false;
        }
        let word = syscall_nr / 64;
        let bit = syscall_nr % 64;
        (self.allow_bitmap[word] >> bit) & 1 != 0
    }

    /// Check if a syscall is in the deny bitmap.
    pub fn is_denied(&self, syscall_nr: usize) -> bool {
        if syscall_nr >= MAX_SYSCALLS {
            return false;
        }
        let word = syscall_nr / 64;
        let bit = syscall_nr % 64;
        (self.deny_bitmap[word] >> bit) & 1 != 0
    }

    /// Set a syscall as allowed in the bitmap.
    pub fn set_allowed(&mut self, syscall_nr: usize) {
        if syscall_nr < MAX_SYSCALLS {
            let word = syscall_nr / 64;
            let bit = syscall_nr % 64;
            self.allow_bitmap[word] |= 1u64 << bit;
        }
    }

    /// Set a syscall as denied in the bitmap.
    pub fn set_denied(&mut self, syscall_nr: usize) {
        if syscall_nr < MAX_SYSCALLS {
            let word = syscall_nr / 64;
            let bit = syscall_nr % 64;
            self.deny_bitmap[word] |= 1u64 << bit;
        }
    }
}

/// Statistics for the seccomp cache.
#[derive(Debug, Clone, Copy)]
pub struct SeccompCacheStats {
    /// Total cache lookups.
    pub total_lookups: u64,
    /// Total cache hits (avoided BPF evaluation).
    pub total_hits: u64,
    /// Total cache misses (required BPF evaluation).
    pub total_misses: u64,
    /// Total cache invalidations.
    pub total_invalidations: u64,
    /// Total entries created.
    pub total_created: u64,
}

impl SeccompCacheStats {
    const fn new() -> Self {
        Self {
            total_lookups: 0,
            total_hits: 0,
            total_misses: 0,
            total_invalidations: 0,
            total_created: 0,
        }
    }

    /// Cache hit rate as a percentage (0-100).
    pub fn hit_rate_pct(&self) -> u64 {
        if self.total_lookups == 0 {
            return 0;
        }
        self.total_hits * 100 / self.total_lookups
    }
}

/// Top-level seccomp filter cache.
pub struct SeccompCache {
    /// Cache entries.
    entries: [CacheEntry; MAX_CACHE_ENTRIES],
    /// Statistics.
    stats: SeccompCacheStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Whether the cache is enabled.
    enabled: bool,
}

impl Default for SeccompCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SeccompCache {
    /// Create a new seccomp cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { CacheEntry::empty() }; MAX_CACHE_ENTRIES],
            stats: SeccompCacheStats::new(),
            initialised: false,
            enabled: true,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Enable or disable the cache.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Look up a cached decision for a syscall.
    ///
    /// `filter_hash` identifies the caller's *current* seccomp filter chain.
    /// A cached entry is only honoured when its stored hash matches: if the
    /// process has since installed/replaced its filter (new hash), or a
    /// recycled PID now belongs to a different filter chain, the stale entry
    /// is discarded and the caller is told to re-evaluate the BPF program.
    /// This prevents a stale `Allow` from a prior filter (or a prior owner of
    /// the PID) from short-circuiting the current, possibly stricter, policy.
    pub fn lookup(
        &mut self,
        pid: u64,
        filter_hash: u64,
        syscall_nr: usize,
    ) -> Result<CachedAction> {
        if !self.enabled {
            return Ok(CachedAction::Evaluate);
        }

        self.stats.total_lookups += 1;

        let slot = match self.entries.iter().position(|e| e.valid && e.pid == pid) {
            Some(idx) => idx,
            None => {
                self.stats.total_misses += 1;
                return Ok(CachedAction::Evaluate);
            }
        };

        // Fail closed on a filter-generation mismatch: drop the stale entry and
        // force BPF re-evaluation rather than trusting an old verdict.
        if self.entries[slot].filter_hash != filter_hash {
            self.invalidate(pid);
            self.stats.total_misses += 1;
            return Ok(CachedAction::Evaluate);
        }

        let entry = &mut self.entries[slot];

        if entry.is_allowed(syscall_nr) {
            entry.hit_count += 1;
            self.stats.total_hits += 1;
            Ok(CachedAction::Allow)
        } else if entry.is_denied(syscall_nr) {
            entry.hit_count += 1;
            self.stats.total_hits += 1;
            Ok(CachedAction::Kill)
        } else {
            entry.miss_count += 1;
            self.stats.total_misses += 1;
            Ok(CachedAction::Evaluate)
        }
    }

    /// Create or update a cache entry for a task.
    pub fn create_entry(&mut self, pid: u64, filter_hash: u64) -> Result<usize> {
        // Try to find existing entry for this pid.
        if let Some(idx) = self.entries.iter().position(|e| e.valid && e.pid == pid) {
            self.entries[idx].filter_hash = filter_hash;
            self.entries[idx].allow_bitmap = [0u64; BITMAP_WORDS];
            self.entries[idx].deny_bitmap = [0u64; BITMAP_WORDS];
            self.entries[idx].hit_count = 0;
            self.entries[idx].miss_count = 0;
            return Ok(idx);
        }

        let slot = self
            .entries
            .iter()
            .position(|e| !e.valid)
            .ok_or(Error::OutOfMemory)?;

        self.entries[slot] = CacheEntry::empty();
        self.entries[slot].pid = pid;
        self.entries[slot].filter_hash = filter_hash;
        self.entries[slot].valid = true;
        self.stats.total_created += 1;
        Ok(slot)
    }

    /// Record a filter evaluation result.
    pub fn record_result(
        &mut self,
        pid: u64,
        syscall_nr: usize,
        action: CachedAction,
    ) -> Result<()> {
        let entry = match self.entries.iter_mut().find(|e| e.valid && e.pid == pid) {
            Some(e) => e,
            None => return Ok(()),
        };

        // Only cache verdicts that the two bitmaps can represent *exactly*.
        // `LogAllow` carries an audit side-effect and `Errno` returns a
        // specific errno without terminating the task; collapsing either into a
        // plain allow/deny bit would rewrite the verdict (drop the log, or turn
        // an EPERM into a kill). Leave those — and `Evaluate` — uncached so the
        // BPF program runs each time and produces the correct action.
        match action {
            CachedAction::Allow => {
                entry.set_allowed(syscall_nr);
            }
            CachedAction::Kill => {
                entry.set_denied(syscall_nr);
            }
            CachedAction::Errno | CachedAction::LogAllow | CachedAction::Evaluate => {}
        }
        Ok(())
    }

    /// Invalidate cache for a specific task.
    pub fn invalidate(&mut self, pid: u64) {
        for entry in &mut self.entries {
            if entry.valid && entry.pid == pid {
                *entry = CacheEntry::empty();
                self.stats.total_invalidations += 1;
            }
        }
    }

    /// Invalidate all cache entries.
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            if entry.valid {
                *entry = CacheEntry::empty();
                self.stats.total_invalidations += 1;
            }
        }
    }

    /// Return statistics.
    pub fn stats(&self) -> SeccompCacheStats {
        self.stats
    }

    /// Return the number of valid entries.
    pub fn entry_count(&self) -> usize {
        self.entries.iter().filter(|e| e.valid).count()
    }
}
