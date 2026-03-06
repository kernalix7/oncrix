// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs balance operation management.
//!
//! The Btrfs balance operation redistributes data and metadata across devices
//! in a filesystem.  This module implements the balance filter structures,
//! progress tracking, and the state machine used to pause/resume/cancel
//! in-progress balance operations.

use oncrix_lib::{Error, Result};

/// Btrfs block group types (can be OR'd together as filter flags).
pub mod block_group {
    pub const DATA: u64 = 0x0000_0001;
    pub const SYSTEM: u64 = 0x0000_0002;
    pub const METADATA: u64 = 0x0000_0004;
    pub const RAID0: u64 = 0x0000_0008;
    pub const RAID1: u64 = 0x0000_0010;
    pub const DUP: u64 = 0x0000_0020;
    pub const RAID10: u64 = 0x0000_0040;
    pub const RAID5: u64 = 0x0000_0080;
    pub const RAID6: u64 = 0x0000_0100;
    pub const RAID1C3: u64 = 0x0000_0200;
    pub const RAID1C4: u64 = 0x0000_0400;
}

/// Balance filter applied to one block group class (data/meta/sys).
#[derive(Debug, Clone, Copy, Default)]
pub struct BalanceFilter {
    /// Profiles to include (OR of `block_group::RAID*` flags; 0 = all).
    pub profiles: u64,
    /// Only relocate block groups with usage percentage in [min, max].
    pub usage_min: u32,
    pub usage_max: u32,
    /// Filter by device ID (0 = any).
    pub devid: u64,
    /// Filter by physical address range.
    pub pstart: u64,
    pub pend: u64,
    /// Filter by virtual address range.
    pub vstart: u64,
    pub vend: u64,
    /// Bitmask of which filters are active.
    pub flags: u64,
    /// Limit the number of block groups relocated by this pass.
    pub limit: u32,
}

impl BalanceFilter {
    /// Whether any filter is active.
    pub fn has_filters(&self) -> bool {
        self.flags != 0
    }

    /// Check whether a block group with the given usage % and profile matches.
    pub fn matches(&self, usage_pct: u32, profile: u64) -> bool {
        if self.flags & 0x01 != 0 && (profiles_flag(self.profiles) & profile == 0) {
            return false;
        }
        if self.flags & 0x02 != 0 && (usage_pct < self.usage_min || usage_pct > self.usage_max) {
            return false;
        }
        true
    }
}

fn profiles_flag(profiles: u64) -> u64 {
    if profiles == 0 { u64::MAX } else { profiles }
}

/// Balance arguments (per-type filters).
#[derive(Debug, Clone, Default)]
pub struct BalanceArgs {
    pub data: BalanceFilter,
    pub metadata: BalanceFilter,
    pub system: BalanceFilter,
    /// Global flags (e.g., force flag).
    pub flags: u64,
}

/// Balance operation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceState {
    /// No balance in progress.
    Idle,
    /// Balance is actively running.
    Running,
    /// Balance has been paused (e.g., unmount during balance).
    Paused,
    /// Balance was cancelled by the user.
    Cancelled,
    /// Balance completed successfully.
    Completed,
    /// Balance failed due to an error.
    Failed,
}

/// Progress counters for a balance operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalanceProgress {
    /// Total block groups that need relocation.
    pub total_to_balance: u64,
    /// Block groups successfully relocated so far.
    pub completed: u64,
    /// Block groups skipped by filters.
    pub skipped: u64,
    /// Bytes of data relocated.
    pub bytes_relocated: u64,
}

impl BalanceProgress {
    /// Percentage complete (0–100).
    pub fn percent(&self) -> u8 {
        if self.total_to_balance == 0 {
            100
        } else {
            ((self.completed * 100) / self.total_to_balance).min(100) as u8
        }
    }
}

/// In-memory balance control block.
pub struct BalanceControl {
    pub state: BalanceState,
    pub args: BalanceArgs,
    pub progress: BalanceProgress,
    /// Number of times the balance has been paused.
    pub pause_count: u32,
    /// Opaque balance item key for resume (logical address of last chunk).
    pub resume_key: u64,
}

impl BalanceControl {
    /// Create a new idle balance control block.
    pub const fn new() -> Self {
        Self {
            state: BalanceState::Idle,
            args: BalanceArgs {
                data: BalanceFilter {
                    profiles: 0,
                    usage_min: 0,
                    usage_max: 100,
                    devid: 0,
                    pstart: 0,
                    pend: u64::MAX,
                    vstart: 0,
                    vend: u64::MAX,
                    flags: 0,
                    limit: 0,
                },
                metadata: BalanceFilter {
                    profiles: 0,
                    usage_min: 0,
                    usage_max: 100,
                    devid: 0,
                    pstart: 0,
                    pend: u64::MAX,
                    vstart: 0,
                    vend: u64::MAX,
                    flags: 0,
                    limit: 0,
                },
                system: BalanceFilter {
                    profiles: 0,
                    usage_min: 0,
                    usage_max: 100,
                    devid: 0,
                    pstart: 0,
                    pend: u64::MAX,
                    vstart: 0,
                    vend: u64::MAX,
                    flags: 0,
                    limit: 0,
                },
                flags: 0,
            },
            progress: BalanceProgress {
                total_to_balance: 0,
                completed: 0,
                skipped: 0,
                bytes_relocated: 0,
            },
            pause_count: 0,
            resume_key: 0,
        }
    }

    /// Start a new balance operation.
    pub fn start(&mut self, args: BalanceArgs, total: u64) -> Result<()> {
        if self.state == BalanceState::Running {
            return Err(Error::Busy);
        }
        self.args = args;
        self.progress = BalanceProgress {
            total_to_balance: total,
            completed: 0,
            skipped: 0,
            bytes_relocated: 0,
        };
        self.state = BalanceState::Running;
        self.resume_key = 0;
        Ok(())
    }

    /// Record completion of one block group relocation.
    pub fn record_chunk(&mut self, bytes: u64) {
        self.progress.completed += 1;
        self.progress.bytes_relocated += bytes;
    }

    /// Record that a block group was skipped by the filter.
    pub fn record_skip(&mut self) {
        self.progress.skipped += 1;
    }

    /// Pause the balance at the given logical address (for resume).
    pub fn pause(&mut self, resume_key: u64) -> Result<()> {
        if self.state != BalanceState::Running {
            return Err(Error::InvalidArgument);
        }
        self.resume_key = resume_key;
        self.state = BalanceState::Paused;
        self.pause_count += 1;
        Ok(())
    }

    /// Resume a paused balance.
    pub fn resume(&mut self) -> Result<u64> {
        if self.state != BalanceState::Paused {
            return Err(Error::InvalidArgument);
        }
        self.state = BalanceState::Running;
        Ok(self.resume_key)
    }

    /// Cancel the balance operation.
    pub fn cancel(&mut self) -> Result<()> {
        if !matches!(self.state, BalanceState::Running | BalanceState::Paused) {
            return Err(Error::InvalidArgument);
        }
        self.state = BalanceState::Cancelled;
        Ok(())
    }

    /// Mark the balance as completed.
    pub fn complete(&mut self) {
        self.state = BalanceState::Completed;
    }

    /// Mark the balance as failed.
    pub fn fail(&mut self) {
        self.state = BalanceState::Failed;
    }
}

impl Default for BalanceControl {
    fn default() -> Self {
        Self::new()
    }
}
