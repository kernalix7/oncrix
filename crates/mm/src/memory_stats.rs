// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory statistics collection.
//!
//! Collects and formats system-wide memory statistics, similar to
//! `/proc/meminfo` in Linux. Tracks free pages, active/inactive pages
//! (both anonymous and file-backed), slab usage, dirty pages, writeback
//! pages, and mapped pages.
//!
//! - [`MemStats`] — the main statistics structure
//! - [`ZoneMemStats`] — per-zone statistics
//! - [`MemStatsCollector`] — collects statistics from subsystems
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c`, `fs/proc/meminfo.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Number of zones.
const NR_ZONES: usize = 5;

/// Maximum memory stat entries for history.
const MAX_HISTORY: usize = 64;

// -------------------------------------------------------------------
// MemStats
// -------------------------------------------------------------------

/// System-wide memory statistics.
///
/// Each field counts pages (not bytes). Multiply by `PAGE_SIZE` for bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemStats {
    /// Total pages in the system.
    pub nr_total_pages: u64,
    /// Free (unallocated) pages.
    pub nr_free_pages: u64,
    /// Active anonymous pages.
    pub nr_active_anon: u64,
    /// Inactive anonymous pages.
    pub nr_inactive_anon: u64,
    /// Active file-backed pages.
    pub nr_active_file: u64,
    /// Inactive file-backed pages.
    pub nr_inactive_file: u64,
    /// Unevictable pages (mlocked).
    pub nr_unevictable: u64,
    /// Slab reclaimable pages.
    pub nr_slab_reclaimable: u64,
    /// Slab unreclaimable pages.
    pub nr_slab_unreclaimable: u64,
    /// Dirty pages (need writeback).
    pub nr_dirty: u64,
    /// Pages under writeback.
    pub nr_writeback: u64,
    /// Mapped pages (in page tables).
    pub nr_mapped: u64,
    /// Shared memory pages (shmem/tmpfs).
    pub nr_shmem: u64,
    /// Page table pages.
    pub nr_page_table_pages: u64,
    /// Kernel stack pages.
    pub nr_kernel_stack: u64,
    /// Bounce buffer pages.
    pub nr_bounce: u64,
    /// Huge pages (free).
    pub nr_huge_pages_free: u64,
    /// Huge pages (total).
    pub nr_huge_pages_total: u64,
    /// Pages in swap cache.
    pub nr_swap_cached: u64,
    /// Total swap pages.
    pub nr_swap_total: u64,
    /// Free swap pages.
    pub nr_swap_free: u64,
}

impl MemStats {
    /// Creates new statistics with the given total pages.
    pub fn new(total_pages: u64) -> Self {
        Self {
            nr_total_pages: total_pages,
            nr_free_pages: total_pages,
            ..Self::default()
        }
    }

    /// Returns total memory in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.nr_total_pages * PAGE_SIZE
    }

    /// Returns free memory in bytes.
    pub fn free_bytes(&self) -> u64 {
        self.nr_free_pages * PAGE_SIZE
    }

    /// Returns used memory in pages.
    pub fn used_pages(&self) -> u64 {
        self.nr_total_pages.saturating_sub(self.nr_free_pages)
    }

    /// Returns total active pages.
    pub fn active_pages(&self) -> u64 {
        self.nr_active_anon + self.nr_active_file
    }

    /// Returns total inactive pages.
    pub fn inactive_pages(&self) -> u64 {
        self.nr_inactive_anon + self.nr_inactive_file
    }

    /// Returns total slab pages.
    pub fn slab_pages(&self) -> u64 {
        self.nr_slab_reclaimable + self.nr_slab_unreclaimable
    }

    /// Returns total anonymous pages.
    pub fn anon_pages(&self) -> u64 {
        self.nr_active_anon + self.nr_inactive_anon
    }

    /// Returns total file pages.
    pub fn file_pages(&self) -> u64 {
        self.nr_active_file + self.nr_inactive_file
    }

    /// Returns available memory estimate (free + reclaimable).
    pub fn available_pages(&self) -> u64 {
        self.nr_free_pages + self.nr_inactive_file + self.nr_slab_reclaimable
    }

    /// Returns memory usage percentage (0-100).
    pub fn usage_pct(&self) -> u64 {
        if self.nr_total_pages == 0 {
            return 0;
        }
        self.used_pages() * 100 / self.nr_total_pages
    }

    /// Formats as `/proc/meminfo`-style output.
    ///
    /// Writes into the provided buffer and returns the number of bytes
    /// written.
    pub fn format(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        let lines: [(&str, u64); 22] = [
            ("MemTotal", self.nr_total_pages * PAGE_SIZE / 1024),
            ("MemFree", self.nr_free_pages * PAGE_SIZE / 1024),
            ("MemAvailable", self.available_pages() * PAGE_SIZE / 1024),
            ("Active", self.active_pages() * PAGE_SIZE / 1024),
            ("Inactive", self.inactive_pages() * PAGE_SIZE / 1024),
            ("Active(anon)", self.nr_active_anon * PAGE_SIZE / 1024),
            ("Inactive(anon)", self.nr_inactive_anon * PAGE_SIZE / 1024),
            ("Active(file)", self.nr_active_file * PAGE_SIZE / 1024),
            ("Inactive(file)", self.nr_inactive_file * PAGE_SIZE / 1024),
            ("Unevictable", self.nr_unevictable * PAGE_SIZE / 1024),
            ("Dirty", self.nr_dirty * PAGE_SIZE / 1024),
            ("Writeback", self.nr_writeback * PAGE_SIZE / 1024),
            ("Mapped", self.nr_mapped * PAGE_SIZE / 1024),
            ("Shmem", self.nr_shmem * PAGE_SIZE / 1024),
            ("Slab", self.slab_pages() * PAGE_SIZE / 1024),
            ("SReclaimable", self.nr_slab_reclaimable * PAGE_SIZE / 1024),
            ("SUnreclaim", self.nr_slab_unreclaimable * PAGE_SIZE / 1024),
            ("KernelStack", self.nr_kernel_stack * PAGE_SIZE / 1024),
            ("PageTables", self.nr_page_table_pages * PAGE_SIZE / 1024),
            ("Bounce", self.nr_bounce * PAGE_SIZE / 1024),
            ("SwapTotal", self.nr_swap_total * PAGE_SIZE / 1024),
            ("SwapFree", self.nr_swap_free * PAGE_SIZE / 1024),
        ];

        for (name, kb) in &lines {
            let line = format_meminfo_line(name, *kb);
            let bytes: &[u8] = &line;
            if pos + bytes.len() > buf.len() {
                break;
            }
            buf[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
        }

        pos
    }
}

/// Formats a single meminfo line: "Name:       1234 kB\n".
fn format_meminfo_line(name: &str, kb: u64) -> [u8; 48] {
    let mut buf = [b' '; 48];
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(20);
    buf[..name_len].copy_from_slice(&name_bytes[..name_len]);
    buf[name_len] = b':';

    // Write the number right-justified in columns 22-35.
    let mut num = kb;
    let mut digits = [0u8; 16];
    let mut dlen = 0;
    if num == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while num > 0 {
            digits[dlen] = b'0' + (num % 10) as u8;
            num /= 10;
            dlen += 1;
        }
    }

    let num_start = 32usize.saturating_sub(dlen);
    for i in 0..dlen {
        if num_start + i < 44 {
            buf[num_start + i] = digits[dlen - 1 - i];
        }
    }

    // " kB\n"
    let suffix = b" kB\n";
    let suffix_start = 32.min(44);
    for (i, &b) in suffix.iter().enumerate() {
        if suffix_start + i < 48 {
            buf[suffix_start + i] = b;
        }
    }

    let total_len = suffix_start + suffix.len();
    if total_len < 48 {
        buf[total_len] = b'\n';
    }

    buf
}

// -------------------------------------------------------------------
// ZoneMemStats
// -------------------------------------------------------------------

/// Per-zone memory statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZoneMemStats {
    /// Zone index.
    pub zone_idx: usize,
    /// Free pages in this zone.
    pub nr_free: u64,
    /// Managed pages in this zone.
    pub nr_managed: u64,
    /// Present pages in this zone.
    pub nr_present: u64,
    /// High watermark.
    pub high_wmark: u64,
    /// Low watermark.
    pub low_wmark: u64,
    /// Min watermark.
    pub min_wmark: u64,
}

impl ZoneMemStats {
    /// Returns the zone usage percentage.
    pub fn usage_pct(&self) -> u64 {
        if self.nr_managed == 0 {
            return 0;
        }
        (self.nr_managed - self.nr_free.min(self.nr_managed)) * 100 / self.nr_managed
    }
}

// -------------------------------------------------------------------
// MemStatsCollector
// -------------------------------------------------------------------

/// Collects memory statistics from various subsystems.
pub struct MemStatsCollector {
    /// Current snapshot.
    current: MemStats,
    /// Per-zone stats.
    zones: [ZoneMemStats; NR_ZONES],
    /// History ring buffer.
    history: [MemStats; MAX_HISTORY],
    /// Next history index.
    history_idx: usize,
    /// Number of snapshots taken.
    snapshot_count: u64,
}

impl MemStatsCollector {
    /// Creates a new collector.
    pub fn new(total_pages: u64) -> Self {
        Self {
            current: MemStats::new(total_pages),
            zones: [ZoneMemStats::default(); NR_ZONES],
            history: [MemStats::default(); MAX_HISTORY],
            history_idx: 0,
            snapshot_count: 0,
        }
    }

    /// Takes a snapshot of the current stats into history.
    pub fn snapshot(&mut self) {
        self.history[self.history_idx] = self.current;
        self.history_idx = (self.history_idx + 1) % MAX_HISTORY;
        self.snapshot_count += 1;
    }

    /// Returns the current statistics.
    pub fn current(&self) -> &MemStats {
        &self.current
    }

    /// Returns a mutable reference to the current statistics.
    pub fn current_mut(&mut self) -> &mut MemStats {
        &mut self.current
    }

    /// Returns per-zone statistics.
    pub fn zones(&self) -> &[ZoneMemStats; NR_ZONES] {
        &self.zones
    }

    /// Updates zone statistics.
    pub fn update_zone(&mut self, zone_idx: usize, stats: ZoneMemStats) -> Result<()> {
        if zone_idx >= NR_ZONES {
            return Err(Error::InvalidArgument);
        }
        self.zones[zone_idx] = stats;
        Ok(())
    }

    /// Collects aggregate stats from zones.
    pub fn collect_from_zones(&mut self) {
        let mut total_free = 0u64;
        for zone in &self.zones {
            total_free += zone.nr_free;
        }
        self.current.nr_free_pages = total_free;
    }

    /// Returns the most recent history entry.
    pub fn last_snapshot(&self) -> &MemStats {
        let idx = if self.history_idx == 0 {
            MAX_HISTORY - 1
        } else {
            self.history_idx - 1
        };
        &self.history[idx]
    }

    /// Returns the number of snapshots taken.
    pub fn snapshot_count(&self) -> u64 {
        self.snapshot_count
    }

    /// Formats current stats into a buffer.
    pub fn format(&self, buf: &mut [u8]) -> usize {
        self.current.format(buf)
    }
}

impl Default for MemStatsCollector {
    fn default() -> Self {
        Self::new(0)
    }
}
