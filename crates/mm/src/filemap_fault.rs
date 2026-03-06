// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filemap page fault handler.
//!
//! Implements the generic file-backed page fault path: when a process
//! accesses a page that is not yet in memory, the fault handler looks
//! up (or reads in) the page from the page cache and maps it into the
//! faulting process's address space. Supports around-fault mapping
//! (mapping neighbouring pages speculatively) and readahead triggers.
//!
//! - [`VmFaultType`] — fault outcome flags
//! - [`FaultFlags`] — incoming fault request flags
//! - [`FilemapFaultContext`] — per-fault context
//! - [`FilemapFaultResult`] — result of handling a fault
//! - [`FilemapFaultHandler`] — the main fault handler engine
//! - [`FaultStats`] — aggregate fault statistics
//!
//! Reference: `.kernelORG/` — `mm/filemap.c` (`filemap_fault`,
//! `filemap_map_pages`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum around-fault pages to map speculatively.
const MAX_AROUND_PAGES: usize = 16;

/// Maximum readahead pages triggered by a fault.
const MAX_READAHEAD_PAGES: usize = 32;

/// Maximum number of pending faults.
const MAX_PENDING_FAULTS: usize = 64;

/// Maximum fault log entries.
const MAX_FAULT_LOG: usize = 128;

// -------------------------------------------------------------------
// VmFaultType
// -------------------------------------------------------------------

/// Fault outcome flags (can be combined).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmFaultType {
    /// Raw flag bits.
    bits: u32,
}

impl VmFaultType {
    /// Minor fault — page was in cache, no I/O needed.
    pub const MINOR: u32 = 1 << 0;
    /// Major fault — page had to be read from disk.
    pub const MAJOR: u32 = 1 << 1;
    /// Fault needs retry (page was locked).
    pub const RETRY: u32 = 1 << 2;
    /// Fault resulted in OOM.
    pub const OOM: u32 = 1 << 3;
    /// Fault resulted in SIGBUS.
    pub const SIGBUS: u32 = 1 << 4;
    /// Page was already mapped (no fault needed).
    pub const NOPAGE: u32 = 1 << 5;
    /// Readahead was triggered.
    pub const READAHEAD: u32 = 1 << 6;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns raw bits.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }

    /// Tests if a flag is set.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Returns `true` if this was a major fault.
    pub fn is_major(self) -> bool {
        self.contains(Self::MAJOR)
    }
}

// -------------------------------------------------------------------
// FaultFlags
// -------------------------------------------------------------------

/// Incoming fault request flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FaultFlags {
    /// Raw bits.
    bits: u32,
}

impl FaultFlags {
    /// Fault was a write access.
    pub const WRITE: u32 = 1 << 0;
    /// Fault from mkwrite (page was already mapped, need
    /// write permission).
    pub const MKWRITE: u32 = 1 << 1;
    /// Allow retry if page is locked.
    pub const ALLOW_RETRY: u32 = 1 << 2;
    /// Retry has already been attempted.
    pub const TRIED: u32 = 1 << 3;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Tests a flag.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }
}

// -------------------------------------------------------------------
// FilemapFaultContext
// -------------------------------------------------------------------

/// Per-fault context passed to the fault handler.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilemapFaultContext {
    /// File identifier.
    pub file_id: u64,
    /// VMA start address.
    pub vma_start: u64,
    /// VMA end address.
    pub vma_end: u64,
    /// Page offset within the file (in pages).
    pub pgoff: u64,
    /// Faulting virtual address.
    pub address: u64,
    /// Fault flags.
    pub flags: FaultFlags,
}

impl FilemapFaultContext {
    /// Creates a new fault context.
    pub fn new(
        file_id: u64,
        vma_start: u64,
        vma_end: u64,
        address: u64,
        flags: FaultFlags,
    ) -> Result<Self> {
        if address < vma_start || address >= vma_end {
            return Err(Error::InvalidArgument);
        }
        let pgoff = (address - vma_start) / PAGE_SIZE;
        Ok(Self {
            file_id,
            vma_start,
            vma_end,
            pgoff,
            address,
            flags,
        })
    }
}

// -------------------------------------------------------------------
// FilemapFaultResult
// -------------------------------------------------------------------

/// Result of handling a filemap fault.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilemapFaultResult {
    /// Fault type flags (MINOR, MAJOR, RETRY, etc.).
    pub fault_type: VmFaultType,
    /// PFN of the page that was mapped (0 if fault failed).
    pub pfn: u64,
    /// Number of around-fault pages mapped.
    pub around_pages: usize,
    /// Number of readahead pages triggered.
    pub readahead_pages: usize,
}

// -------------------------------------------------------------------
// FaultLogEntry
// -------------------------------------------------------------------

/// A recorded fault event for statistics/debugging.
#[derive(Debug, Clone, Copy, Default)]
pub struct FaultLogEntry {
    /// File that was faulted.
    pub file_id: u64,
    /// Page offset.
    pub pgoff: u64,
    /// Faulting address.
    pub address: u64,
    /// Fault outcome.
    pub fault_type: VmFaultType,
    /// Timestamp (monotonic ns).
    pub timestamp_ns: u64,
}

// -------------------------------------------------------------------
// FaultStats
// -------------------------------------------------------------------

/// Aggregate fault statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FaultStats {
    /// Total faults handled.
    pub total_faults: u64,
    /// Minor faults (page was in cache).
    pub minor_faults: u64,
    /// Major faults (page read from disk).
    pub major_faults: u64,
    /// Retry faults (page was locked).
    pub retries: u64,
    /// Around-fault pages mapped.
    pub around_mapped: u64,
    /// Readahead pages triggered.
    pub readahead_triggered: u64,
    /// OOM faults.
    pub oom_faults: u64,
}

impl FaultStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// CachedPageEntry
// -------------------------------------------------------------------

/// A simplified cached page for the fault handler's local cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct CachedPageEntry {
    /// File identifier.
    pub file_id: u64,
    /// Page offset.
    pub pgoff: u64,
    /// PFN where the page is stored.
    pub pfn: u64,
    /// Whether the page is locked.
    pub locked: bool,
    /// Whether the page is up-to-date.
    pub uptodate: bool,
    /// Whether this slot is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// FilemapFaultHandler
// -------------------------------------------------------------------

/// The main filemap fault handler engine.
///
/// Handles page faults for file-backed VMAs by looking up pages in
/// a local cache, performing readahead, and mapping around-fault
/// pages.
pub struct FilemapFaultHandler {
    /// Local page cache entries.
    cache: [CachedPageEntry; MAX_PENDING_FAULTS],
    /// Number of cache entries.
    cache_count: usize,
    /// Fault log.
    fault_log: [FaultLogEntry; MAX_FAULT_LOG],
    /// Fault log count.
    log_count: usize,
    /// Statistics.
    stats: FaultStats,
    /// Next PFN to allocate (simulated).
    next_pfn: u64,
}

impl Default for FilemapFaultHandler {
    fn default() -> Self {
        Self {
            cache: [CachedPageEntry::default(); MAX_PENDING_FAULTS],
            cache_count: 0,
            fault_log: [FaultLogEntry::default(); MAX_FAULT_LOG],
            log_count: 0,
            stats: FaultStats::default(),
            next_pfn: 0x1000,
        }
    }
}

impl FilemapFaultHandler {
    /// Creates a new fault handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populates a page in the local cache.
    pub fn add_cached_page(&mut self, file_id: u64, pgoff: u64, pfn: u64) -> Result<()> {
        if self.cache_count >= MAX_PENDING_FAULTS {
            return Err(Error::OutOfMemory);
        }
        self.cache[self.cache_count] = CachedPageEntry {
            file_id,
            pgoff,
            pfn,
            locked: false,
            uptodate: true,
            active: true,
        };
        self.cache_count += 1;
        Ok(())
    }

    /// Handles a filemap fault.
    pub fn filemap_fault(
        &mut self,
        ctx: &FilemapFaultContext,
        timestamp_ns: u64,
    ) -> FilemapFaultResult {
        self.stats.total_faults += 1;

        // Look up in local cache.
        let cached = self.find_cached(ctx.file_id, ctx.pgoff);

        let (pfn, fault_type) = match cached {
            Some(idx) => {
                let entry = &self.cache[idx];
                if entry.locked && ctx.flags.contains(FaultFlags::ALLOW_RETRY) {
                    // Page is locked, retry.
                    self.stats.retries += 1;
                    let ft = VmFaultType::empty().set(VmFaultType::RETRY);
                    self.log_fault(ctx, ft, timestamp_ns);
                    return FilemapFaultResult {
                        fault_type: ft,
                        pfn: 0,
                        around_pages: 0,
                        readahead_pages: 0,
                    };
                }
                // Minor fault — page was in cache.
                self.stats.minor_faults += 1;
                (entry.pfn, VmFaultType::empty().set(VmFaultType::MINOR))
            }
            None => {
                // Major fault — simulate a synchronous read.
                self.stats.major_faults += 1;
                let pfn = self.alloc_pfn();
                let _ = self.add_cached_page(ctx.file_id, ctx.pgoff, pfn);
                (pfn, VmFaultType::empty().set(VmFaultType::MAJOR))
            }
        };

        // Around-fault mapping.
        let around = self.filemap_map_pages(ctx);

        // Readahead trigger on major faults.
        let readahead = if fault_type.is_major() {
            self.trigger_readahead(ctx)
        } else {
            0
        };

        let final_type = if readahead > 0 {
            fault_type.set(VmFaultType::READAHEAD)
        } else {
            fault_type
        };

        self.log_fault(ctx, final_type, timestamp_ns);

        FilemapFaultResult {
            fault_type: final_type,
            pfn,
            around_pages: around,
            readahead_pages: readahead,
        }
    }

    /// Maps pages around the fault (speculative mapping).
    fn filemap_map_pages(&mut self, ctx: &FilemapFaultContext) -> usize {
        let mut mapped = 0;
        let vma_pages = (ctx.vma_end - ctx.vma_start) / PAGE_SIZE;

        for offset in 1..=MAX_AROUND_PAGES as u64 {
            let pgoff = ctx.pgoff + offset;
            if pgoff >= vma_pages {
                break;
            }
            if self.find_cached(ctx.file_id, pgoff).is_some() {
                mapped += 1;
            }
        }

        self.stats.around_mapped += mapped as u64;
        mapped
    }

    /// Triggers readahead for major faults.
    fn trigger_readahead(&mut self, ctx: &FilemapFaultContext) -> usize {
        let mut pages = 0;
        let vma_pages = (ctx.vma_end - ctx.vma_start) / PAGE_SIZE;

        for offset in 1..=MAX_READAHEAD_PAGES as u64 {
            let pgoff = ctx.pgoff + offset;
            if pgoff >= vma_pages {
                break;
            }
            if self.find_cached(ctx.file_id, pgoff).is_none() {
                let pfn = self.alloc_pfn();
                let _ = self.add_cached_page(ctx.file_id, pgoff, pfn);
                pages += 1;
            }
        }

        self.stats.readahead_triggered += pages as u64;
        pages
    }

    /// Finds a cached page by (file_id, pgoff).
    fn find_cached(&self, file_id: u64, pgoff: u64) -> Option<usize> {
        for i in 0..self.cache_count {
            if self.cache[i].active
                && self.cache[i].file_id == file_id
                && self.cache[i].pgoff == pgoff
            {
                return Some(i);
            }
        }
        None
    }

    /// Allocates a simulated PFN.
    fn alloc_pfn(&mut self) -> u64 {
        let pfn = self.next_pfn;
        self.next_pfn += 1;
        pfn
    }

    /// Logs a fault event.
    fn log_fault(&mut self, ctx: &FilemapFaultContext, fault_type: VmFaultType, timestamp_ns: u64) {
        if self.log_count < MAX_FAULT_LOG {
            self.fault_log[self.log_count] = FaultLogEntry {
                file_id: ctx.file_id,
                pgoff: ctx.pgoff,
                address: ctx.address,
                fault_type,
                timestamp_ns,
            };
            self.log_count += 1;
        }
    }

    /// Returns statistics.
    pub fn stats(&self) -> &FaultStats {
        &self.stats
    }

    /// Returns the number of logged faults.
    pub fn log_count(&self) -> usize {
        self.log_count
    }

    /// Returns the cache entry count.
    pub fn cache_count(&self) -> usize {
        self.cache_count
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
