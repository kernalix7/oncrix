// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Heterogeneous Memory Mirror (HMM).
//!
//! Implements the HMM mirror that allows devices (GPUs, accelerators)
//! to mirror a process's CPU page tables. The device driver registers
//! a mirror, and the HMM subsystem provides callbacks for:
//! - Snapshotting CPU page tables into device PFN arrays
//! - Receiving invalidation notifications when CPU mappings change
//!
//! - [`HmmPfnFlags`] — flags for device PFN entries
//! - [`HmmPfnEntry`] — a single device PFN entry
//! - [`HmmRange`] — a range to fault/snapshot
//! - [`HmmMirror`] — a registered device mirror
//! - [`HmmManager`] — manages all HMM mirrors
//! - [`HmmStats`] — aggregate statistics
//!
//! Reference: `.kernelORG/` — `mm/hmm.c`, `include/linux/hmm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum PFN entries per range snapshot.
const MAX_PFN_ENTRIES: usize = 256;

/// Maximum registered mirrors.
const MAX_MIRRORS: usize = 16;

/// Maximum pending invalidations.
const MAX_INVALIDATIONS: usize = 64;

/// Maximum ranges per fault request.
const MAX_RANGES_PER_FAULT: usize = 8;

// -------------------------------------------------------------------
// HmmPfnFlags
// -------------------------------------------------------------------

/// Flags for device PFN entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HmmPfnFlags {
    /// Raw flag bits.
    bits: u32,
}

impl HmmPfnFlags {
    /// PFN entry is valid.
    pub const VALID: u32 = 1 << 0;
    /// PFN entry is writable.
    pub const WRITE: u32 = 1 << 1;
    /// Page is device-private memory.
    pub const DEVICE_PRIVATE: u32 = 1 << 2;
    /// Page fault needed to populate this entry.
    pub const FAULT: u32 = 1 << 3;
    /// Error occurred during fault.
    pub const ERROR: u32 = 1 << 4;
    /// Page is a special (zero-page, etc.).
    pub const SPECIAL: u32 = 1 << 5;

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

    /// Clears a flag.
    pub fn clear(self, flag: u32) -> Self {
        Self {
            bits: self.bits & !flag,
        }
    }
}

// -------------------------------------------------------------------
// HmmPfnEntry
// -------------------------------------------------------------------

/// A single device PFN entry in a range snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct HmmPfnEntry {
    /// Page frame number (device-side).
    pub pfn: u64,
    /// Entry flags.
    pub flags: HmmPfnFlags,
}

impl HmmPfnEntry {
    /// Creates a valid entry.
    pub fn valid(pfn: u64, writable: bool) -> Self {
        let mut flags = HmmPfnFlags::empty().set(HmmPfnFlags::VALID);
        if writable {
            flags = flags.set(HmmPfnFlags::WRITE);
        }
        Self { pfn, flags }
    }

    /// Creates an invalid (unmapped) entry.
    pub fn none() -> Self {
        Self::default()
    }

    /// Creates a fault entry (needs population).
    pub fn fault() -> Self {
        Self {
            pfn: 0,
            flags: HmmPfnFlags::empty().set(HmmPfnFlags::FAULT),
        }
    }

    /// Returns `true` if the entry is valid.
    pub fn is_valid(&self) -> bool {
        self.flags.contains(HmmPfnFlags::VALID)
    }

    /// Returns `true` if the entry is writable.
    pub fn is_writable(&self) -> bool {
        self.flags.contains(HmmPfnFlags::WRITE)
    }
}

// -------------------------------------------------------------------
// HmmRange
// -------------------------------------------------------------------

/// A range to fault/snapshot for device mirroring.
#[derive(Debug, Clone, Copy)]
pub struct HmmRange {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// PFN entries for this range (index: page offset from start).
    pub pfns: [HmmPfnEntry; MAX_PFN_ENTRIES],
    /// Number of PFN entries.
    pub nr_entries: usize,
    /// Whether write access is requested.
    pub write: bool,
}

impl Default for HmmRange {
    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            pfns: [const {
                HmmPfnEntry {
                    pfn: 0,
                    flags: HmmPfnFlags { bits: 0 },
                }
            }; MAX_PFN_ENTRIES],
            nr_entries: 0,
            write: false,
        }
    }
}

impl HmmRange {
    /// Creates a new HMM range.
    pub fn new(start: u64, end: u64, write: bool) -> Result<Self> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let nr_pages = ((end - start) / PAGE_SIZE) as usize;
        if nr_pages > MAX_PFN_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start,
            end,
            pfns: [HmmPfnEntry::default(); MAX_PFN_ENTRIES],
            nr_entries: nr_pages,
            write,
        })
    }

    /// Returns the number of pages in this range.
    pub fn page_count(&self) -> usize {
        self.nr_entries
    }
}

// -------------------------------------------------------------------
// HmmInvalidation
// -------------------------------------------------------------------

/// An invalidation notification for device mirrors.
#[derive(Debug, Clone, Copy, Default)]
pub struct HmmInvalidation {
    /// Start virtual address of the invalidated range.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// Mirror ID that should receive this invalidation.
    pub mirror_id: u64,
    /// Timestamp (monotonic ns).
    pub timestamp_ns: u64,
    /// Whether this invalidation is pending.
    pub pending: bool,
}

// -------------------------------------------------------------------
// HmmMirror
// -------------------------------------------------------------------

/// A registered device mirror.
#[derive(Debug, Clone, Copy, Default)]
pub struct HmmMirror {
    /// Mirror identifier.
    pub mirror_id: u64,
    /// Device identifier.
    pub device_id: u64,
    /// Range start being mirrored.
    pub range_start: u64,
    /// Range end being mirrored.
    pub range_end: u64,
    /// Whether this mirror is active.
    pub active: bool,
    /// Sequence number for invalidation ordering.
    pub seq: u64,
}

impl HmmMirror {
    /// Creates a new mirror.
    pub fn new(mirror_id: u64, device_id: u64, range_start: u64, range_end: u64) -> Self {
        Self {
            mirror_id,
            device_id,
            range_start,
            range_end,
            active: true,
            seq: 0,
        }
    }

    /// Returns `true` if the given range overlaps this mirror.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.range_start < end && start < self.range_end
    }
}

// -------------------------------------------------------------------
// HmmStats
// -------------------------------------------------------------------

/// Aggregate HMM statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HmmStats {
    /// Total range fault operations.
    pub range_faults: u64,
    /// Successful fault operations.
    pub fault_success: u64,
    /// Failed fault operations.
    pub fault_failures: u64,
    /// Total invalidation notifications sent.
    pub invalidations: u64,
    /// Mirrors registered.
    pub mirrors_registered: u64,
    /// Mirrors unregistered.
    pub mirrors_unregistered: u64,
    /// Total PFN entries populated.
    pub pfns_populated: u64,
}

impl HmmStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// HmmManager
// -------------------------------------------------------------------

/// Manages all HMM mirrors and invalidation tracking.
pub struct HmmManager {
    /// Registered mirrors.
    mirrors: [HmmMirror; MAX_MIRRORS],
    /// Number of registered mirrors.
    mirror_count: usize,
    /// Pending invalidations.
    invalidations: [HmmInvalidation; MAX_INVALIDATIONS],
    /// Number of pending invalidations.
    invalidation_count: usize,
    /// Statistics.
    stats: HmmStats,
    /// Global sequence counter.
    seq: u64,
}

impl Default for HmmManager {
    fn default() -> Self {
        Self {
            mirrors: [HmmMirror::default(); MAX_MIRRORS],
            mirror_count: 0,
            invalidations: [HmmInvalidation::default(); MAX_INVALIDATIONS],
            invalidation_count: 0,
            stats: HmmStats::default(),
            seq: 0,
        }
    }
}

impl HmmManager {
    /// Creates a new HMM manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a device mirror.
    pub fn register_mirror(
        &mut self,
        mirror_id: u64,
        device_id: u64,
        range_start: u64,
        range_end: u64,
    ) -> Result<usize> {
        if self.mirror_count >= MAX_MIRRORS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.mirror_count;
        self.mirrors[idx] = HmmMirror::new(mirror_id, device_id, range_start, range_end);
        self.mirror_count += 1;
        self.stats.mirrors_registered += 1;
        Ok(idx)
    }

    /// Unregisters a mirror.
    pub fn unregister_mirror(&mut self, mirror_idx: usize) -> Result<()> {
        if mirror_idx >= self.mirror_count {
            return Err(Error::NotFound);
        }
        self.mirrors[mirror_idx].active = false;
        self.stats.mirrors_unregistered += 1;
        Ok(())
    }

    /// Performs a range fault: snapshots CPU page tables into the
    /// HMM range's PFN array.
    ///
    /// In a real kernel, this would walk the CPU page tables and
    /// populate `range.pfns`. Here we simulate by marking entries
    /// as valid with sequential PFNs.
    pub fn hmm_range_fault(&mut self, range: &mut HmmRange, mirror_idx: usize) -> Result<()> {
        if mirror_idx >= self.mirror_count || !self.mirrors[mirror_idx].active {
            return Err(Error::NotFound);
        }

        self.stats.range_faults += 1;

        // Simulate populating PFN entries.
        let base_pfn = range.start / PAGE_SIZE;
        for i in 0..range.nr_entries {
            range.pfns[i] = HmmPfnEntry::valid(base_pfn + i as u64, range.write);
        }

        self.stats.fault_success += 1;
        self.stats.pfns_populated += range.nr_entries as u64;
        self.mirrors[mirror_idx].seq = self.seq;
        self.seq += 1;
        Ok(())
    }

    /// Sends invalidation notifications to all mirrors that overlap
    /// the given range.
    pub fn invalidate(&mut self, start: u64, end: u64, timestamp_ns: u64) -> usize {
        let mut notified = 0;
        for i in 0..self.mirror_count {
            if self.mirrors[i].overlaps(start, end) {
                if self.invalidation_count < MAX_INVALIDATIONS {
                    self.invalidations[self.invalidation_count] = HmmInvalidation {
                        start,
                        end,
                        mirror_id: self.mirrors[i].mirror_id,
                        timestamp_ns,
                        pending: true,
                    };
                    self.invalidation_count += 1;
                }
                notified += 1;
            }
        }
        self.stats.invalidations += notified as u64;
        notified
    }

    /// Acknowledges a pending invalidation.
    pub fn ack_invalidation(&mut self, index: usize) -> Result<()> {
        if index >= self.invalidation_count {
            return Err(Error::NotFound);
        }
        self.invalidations[index].pending = false;
        Ok(())
    }

    /// Returns the number of registered mirrors.
    pub fn mirror_count(&self) -> usize {
        self.mirror_count
    }

    /// Returns the number of pending invalidations.
    pub fn pending_invalidations(&self) -> usize {
        self.invalidations[..self.invalidation_count]
            .iter()
            .filter(|inv| inv.pending)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &HmmStats {
        &self.stats
    }

    /// Returns a reference to a mirror.
    pub fn get_mirror(&self, index: usize) -> Option<&HmmMirror> {
        if index < self.mirror_count {
            Some(&self.mirrors[index])
        } else {
            None
        }
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
