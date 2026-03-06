// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! btrfs scrub — data integrity verification pass.
//!
//! Scrub reads every data and metadata block on a btrfs filesystem and verifies
//! each block's checksum. Corrupted blocks are repaired from a mirror copy when
//! available (RAID-1/RAID-10/RAID-5/RAID-6 profiles).
//!
//! # Architecture
//!
//! ```text
//! ScrubController
//!   └── per-device ScrubWorker
//!         └── reads BlockRange → verifies checksum → repair or mark bad
//! ```
//!
//! This implementation models the scrub state machine and statistics without
//! performing actual block I/O (which depends on the block layer not yet
//! present in this codebase).
//!
//! # References
//!
//! - Linux `fs/btrfs/scrub.c`
//! - btrfs documentation: `Documentation/filesystems/btrfs.rst`

use oncrix_lib::{Error, Result};

/// Maximum number of devices tracked in one scrub session.
pub const MAX_SCRUB_DEVICES: usize = 16;

/// Result of verifying a single block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockVerifyResult {
    /// Checksum matched — block is good.
    Ok,
    /// Checksum mismatch — block is corrupted.
    Corrupt,
    /// Block could not be read (I/O error).
    IoError,
    /// Block was repaired from a mirror.
    Repaired,
}

/// Per-device scrub statistics.
#[derive(Debug, Clone, Default)]
pub struct ScrubDevStats {
    /// Total blocks examined.
    pub blocks_total: u64,
    /// Blocks with checksum errors.
    pub csum_errors: u64,
    /// Read errors encountered.
    pub read_errors: u64,
    /// Blocks successfully repaired.
    pub blocks_repaired: u64,
    /// Unrepaired (uncorrectable) errors.
    pub uncorrectable_errors: u64,
}

/// Scrub state for one device.
pub struct ScrubWorker {
    /// Device index (0-based).
    pub device_idx: usize,
    /// First logical byte to scrub.
    pub start_offset: u64,
    /// One-past-the-end logical byte.
    pub end_offset: u64,
    /// Current position within the scrub range.
    pub current_offset: u64,
    /// Per-device statistics accumulated so far.
    pub stats: ScrubDevStats,
    /// Whether scrub is paused.
    pub paused: bool,
    /// Whether scrub has completed.
    pub finished: bool,
}

impl ScrubWorker {
    /// Create a new scrub worker for `device_idx` covering `[start, end)`.
    pub fn new(device_idx: usize, start_offset: u64, end_offset: u64) -> Result<Self> {
        if start_offset >= end_offset {
            return Err(Error::InvalidArgument);
        }
        if device_idx >= MAX_SCRUB_DEVICES {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            device_idx,
            start_offset,
            end_offset,
            current_offset: start_offset,
            stats: ScrubDevStats::default(),
            paused: false,
            finished: false,
        })
    }

    /// Process the result of verifying one block at `offset` of size `block_size`.
    ///
    /// Advances `current_offset` and updates statistics accordingly.
    pub fn record_block(
        &mut self,
        offset: u64,
        block_size: u32,
        result: BlockVerifyResult,
    ) -> Result<()> {
        if offset < self.start_offset || offset >= self.end_offset {
            return Err(Error::InvalidArgument);
        }
        if block_size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.stats.blocks_total += 1;
        match result {
            BlockVerifyResult::Ok => {}
            BlockVerifyResult::Corrupt => {
                self.stats.csum_errors += 1;
                self.stats.uncorrectable_errors += 1;
            }
            BlockVerifyResult::IoError => {
                self.stats.read_errors += 1;
                self.stats.uncorrectable_errors += 1;
            }
            BlockVerifyResult::Repaired => {
                self.stats.csum_errors += 1;
                self.stats.blocks_repaired += 1;
            }
        }
        self.current_offset = offset.saturating_add(block_size as u64);
        if self.current_offset >= self.end_offset {
            self.finished = true;
        }
        Ok(())
    }

    /// Pause the scrub worker.
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume a paused scrub worker.
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Progress as a fraction in 0.0..=1.0, or `None` if the range is zero.
    pub fn progress(&self) -> Option<f64> {
        let total = self.end_offset.checked_sub(self.start_offset)? as f64;
        let done = self.current_offset.saturating_sub(self.start_offset) as f64;
        Some((done / total).clamp(0.0, 1.0))
    }
}

/// Controller coordinating scrub across multiple devices.
pub struct ScrubController {
    workers: [Option<ScrubWorker>; MAX_SCRUB_DEVICES],
    worker_count: usize,
}

impl ScrubController {
    /// Create an empty scrub controller.
    pub const fn new() -> Self {
        Self {
            workers: [const { None }; MAX_SCRUB_DEVICES],
            worker_count: 0,
        }
    }

    /// Add a device worker. Returns an error if already at capacity.
    pub fn add_device(
        &mut self,
        device_idx: usize,
        start_offset: u64,
        end_offset: u64,
    ) -> Result<()> {
        if self.worker_count >= MAX_SCRUB_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let w = ScrubWorker::new(device_idx, start_offset, end_offset)?;
        self.workers[self.worker_count] = Some(w);
        self.worker_count += 1;
        Ok(())
    }

    /// Get mutable reference to worker by device index.
    pub fn worker_mut(&mut self, device_idx: usize) -> Option<&mut ScrubWorker> {
        self.workers[..self.worker_count]
            .iter_mut()
            .filter_map(|w| w.as_mut())
            .find(|w| w.device_idx == device_idx)
    }

    /// Returns `true` if all workers have finished.
    pub fn all_finished(&self) -> bool {
        if self.worker_count == 0 {
            return false;
        }
        self.workers[..self.worker_count]
            .iter()
            .filter_map(|w| w.as_ref())
            .all(|w| w.finished)
    }

    /// Aggregate statistics across all devices.
    pub fn aggregate_stats(&self) -> ScrubDevStats {
        let mut agg = ScrubDevStats::default();
        for w in self.workers[..self.worker_count]
            .iter()
            .filter_map(|w| w.as_ref())
        {
            agg.blocks_total += w.stats.blocks_total;
            agg.csum_errors += w.stats.csum_errors;
            agg.read_errors += w.stats.read_errors;
            agg.blocks_repaired += w.stats.blocks_repaired;
            agg.uncorrectable_errors += w.stats.uncorrectable_errors;
        }
        agg
    }

    /// Pause all workers.
    pub fn pause_all(&mut self) {
        for w in self.workers[..self.worker_count]
            .iter_mut()
            .filter_map(|w| w.as_mut())
        {
            w.pause();
        }
    }

    /// Resume all workers.
    pub fn resume_all(&mut self) {
        for w in self.workers[..self.worker_count]
            .iter_mut()
            .filter_map(|w| w.as_mut())
        {
            w.resume();
        }
    }
}

impl Default for ScrubController {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a block checksum.
///
/// `stored_csum` is read from the on-disk block header.
/// `computed_csum` is computed from the block data by the caller.
///
/// Returns the appropriate [`BlockVerifyResult`].
pub fn verify_block_csum(stored_csum: u32, computed_csum: u32) -> BlockVerifyResult {
    if stored_csum == computed_csum {
        BlockVerifyResult::Ok
    } else {
        BlockVerifyResult::Corrupt
    }
}

/// Decide whether a corrupted block can be repaired.
///
/// Returns `true` if at least one mirror device index is provided.
pub fn can_repair(mirror_devices: &[usize]) -> bool {
    !mirror_devices.is_empty()
}
