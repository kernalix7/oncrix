// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem writeback control for the ONCRIX VFS.
//!
//! Coordinates the flushing of dirty page-cache pages and inode metadata
//! back to storage. Tracks per-filesystem writeback state, congestion
//! thresholds, and the list of inodes awaiting writeback.

use oncrix_lib::{Error, Result};

/// Maximum number of inodes tracked in the writeback queue per superblock.
pub const WB_MAX_INODES: usize = 512;

/// Number of dirty pages that triggers automatic background writeback.
pub const WB_DIRTY_THRESHOLD: usize = 1024;

/// Dirty page ratio (percent) above which processes begin throttling.
pub const WB_THROTTLE_RATIO: u8 = 80;

/// Writeback priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum WbPriority {
    /// Low priority background flush — occurs during idle periods.
    #[default]
    Background = 0,
    /// Normal priority sync — triggered by the periodic writeback timer.
    Normal = 1,
    /// High priority — triggered by `sync(2)` or low free-memory pressure.
    Sync = 2,
}

/// State of a single inode in the writeback queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WbInodeState {
    /// Inode is not queued for writeback.
    #[default]
    Clean,
    /// Inode has dirty data but is not yet being written.
    Dirty,
    /// Inode data is currently being written back.
    Writing,
}

/// An entry in the writeback inode queue.
#[derive(Debug, Clone, Copy)]
pub struct WbInodeEntry {
    /// Inode number.
    pub ino: u64,
    /// Current writeback state.
    pub state: WbInodeState,
    /// Number of dirty pages on this inode.
    pub dirty_pages: u32,
    /// Monotonic timestamp when the inode first became dirty (ticks).
    pub dirty_since: u64,
    /// Writeback priority.
    pub priority: WbPriority,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl WbInodeEntry {
    /// Create an inactive entry.
    pub const fn new() -> Self {
        Self {
            ino: 0,
            state: WbInodeState::Clean,
            dirty_pages: 0,
            dirty_since: 0,
            priority: WbPriority::Background,
            active: false,
        }
    }

    /// Return `true` if this inode needs writeback.
    pub fn needs_writeback(&self) -> bool {
        self.active && self.state == WbInodeState::Dirty && self.dirty_pages > 0
    }
}

impl Default for WbInodeEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-superblock writeback control structure.
pub struct WbControl {
    /// Queue of inodes awaiting or undergoing writeback.
    queue: [WbInodeEntry; WB_MAX_INODES],
    /// Number of active queue entries.
    count: usize,
    /// Total dirty pages across all tracked inodes.
    pub total_dirty_pages: usize,
    /// Total pages written back since mount.
    pub pages_written: u64,
    /// Whether the filesystem is in sync mode (blocks until clean).
    pub sync_mode: bool,
    /// Current writeback bandwidth limit in pages per tick (0 = unlimited).
    pub bw_limit: u32,
}

impl WbControl {
    /// Create an empty writeback control structure.
    pub const fn new() -> Self {
        Self {
            queue: [const { WbInodeEntry::new() }; WB_MAX_INODES],
            count: 0,
            total_dirty_pages: 0,
            pages_written: 0,
            sync_mode: false,
            bw_limit: 0,
        }
    }

    /// Mark an inode as dirty and add it to the writeback queue.
    ///
    /// If the inode is already queued, updates its dirty page count.
    pub fn mark_dirty(
        &mut self,
        ino: u64,
        dirty_pages: u32,
        now: u64,
        priority: WbPriority,
    ) -> Result<()> {
        // Update existing entry.
        for i in 0..self.count {
            let e = &mut self.queue[i];
            if e.active && e.ino == ino {
                let delta = dirty_pages.saturating_sub(e.dirty_pages) as usize;
                e.dirty_pages = dirty_pages;
                e.state = WbInodeState::Dirty;
                if priority > e.priority {
                    e.priority = priority;
                }
                self.total_dirty_pages += delta;
                return Ok(());
            }
        }

        // Insert new entry.
        if self.count >= WB_MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.queue[self.count];
        slot.ino = ino;
        slot.state = WbInodeState::Dirty;
        slot.dirty_pages = dirty_pages;
        slot.dirty_since = now;
        slot.priority = priority;
        slot.active = true;
        self.total_dirty_pages += dirty_pages as usize;
        self.count += 1;
        Ok(())
    }

    /// Pick the next inode to write back (highest priority, oldest dirty).
    ///
    /// Marks the selected inode as `Writing` and returns its index.
    pub fn pick_next(&mut self) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_prio = WbPriority::Background;
        let mut oldest = u64::MAX;

        for (i, e) in self.queue[..self.count].iter().enumerate() {
            if !e.active || e.state != WbInodeState::Dirty {
                continue;
            }
            if e.priority > best_prio || (e.priority == best_prio && e.dirty_since < oldest) {
                best_prio = e.priority;
                oldest = e.dirty_since;
                best = Some(i);
            }
        }

        if let Some(idx) = best {
            self.queue[idx].state = WbInodeState::Writing;
        }
        best
    }

    /// Mark writeback as complete for a given queue index.
    pub fn complete(&mut self, idx: usize, pages_written: u32) -> Result<()> {
        if idx >= self.count || !self.queue[idx].active {
            return Err(Error::InvalidArgument);
        }
        let e = &mut self.queue[idx];
        self.total_dirty_pages = self
            .total_dirty_pages
            .saturating_sub(e.dirty_pages as usize);
        self.pages_written += pages_written as u64;
        e.dirty_pages = 0;
        e.state = WbInodeState::Clean;
        e.active = false;
        Ok(())
    }

    /// Return `true` if the dirty page count exceeds the throttle threshold.
    pub fn is_congested(&self) -> bool {
        let threshold = WB_DIRTY_THRESHOLD * (WB_THROTTLE_RATIO as usize) / 100;
        self.total_dirty_pages >= threshold
    }

    /// Return the number of inodes currently queued for writeback.
    pub fn queued_count(&self) -> usize {
        self.queue[..self.count]
            .iter()
            .filter(|e| e.active && e.state == WbInodeState::Dirty)
            .count()
    }
}

impl Default for WbControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration knobs for the writeback subsystem.
#[derive(Debug, Clone, Copy)]
pub struct WbConfig {
    /// Dirty page ratio (percent) before background writeback kicks in.
    pub dirty_background_ratio: u8,
    /// Dirty page ratio (percent) before process throttling begins.
    pub dirty_ratio: u8,
    /// Maximum age of dirty data before forced writeback (in ticks).
    pub dirty_expire_ticks: u64,
    /// Interval between periodic writeback runs (in ticks).
    pub writeback_interval_ticks: u64,
}

impl WbConfig {
    /// Construct default writeback configuration.
    pub const fn new() -> Self {
        Self {
            dirty_background_ratio: 10,
            dirty_ratio: 20,
            dirty_expire_ticks: 3000,
            writeback_interval_ticks: 500,
        }
    }

    /// Validate that the configuration values are sane.
    pub fn validate(&self) -> Result<()> {
        if self.dirty_background_ratio >= self.dirty_ratio {
            return Err(Error::InvalidArgument);
        }
        if self.dirty_ratio > 100 {
            return Err(Error::InvalidArgument);
        }
        if self.writeback_interval_ticks == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for WbConfig {
    fn default() -> Self {
        Self::new()
    }
}
