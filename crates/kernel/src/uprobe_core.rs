// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Uprobe core — user-space dynamic probing infrastructure.
//!
//! Uprobes insert breakpoints into user-space binaries at specified
//! offsets. When the probed instruction executes, the kernel is
//! notified and can collect trace data or invoke handlers.
//!
//! # Architecture
//!
//! ```text
//! UprobeManager
//!  ├── probes[MAX_UPROBES]
//!  │    ├── inode, offset, handler_id
//!  │    ├── state: UprobeState
//!  │    └── hit_count
//!  └── stats: UprobeStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/events/uprobes.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered uprobes.
const MAX_UPROBES: usize = 256;

/// Maximum saved instruction bytes.
const MAX_INSN_LEN: usize = 16;

// ══════════════════════════════════════════════════════════════
// UprobeState
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a uprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UprobeState {
    /// Slot is free.
    Free = 0,
    /// Registered but not yet armed.
    Registered = 1,
    /// Armed (breakpoint inserted into target binary).
    Armed = 2,
    /// Disabled (breakpoint removed but registration kept).
    Disabled = 3,
}

// ══════════════════════════════════════════════════════════════
// UprobeEntry
// ══════════════════════════════════════════════════════════════

/// A single uprobe registration.
#[derive(Clone, Copy)]
pub struct UprobeEntry {
    /// Target file inode number.
    pub inode: u64,
    /// Offset within the file.
    pub offset: u64,
    /// Original instruction bytes saved before probe insertion.
    pub saved_insn: [u8; MAX_INSN_LEN],
    /// Length of saved instruction.
    pub insn_len: u8,
    /// Handler callback identifier.
    pub handler_id: u64,
    /// Return probe handler (0 = none).
    pub ret_handler_id: u64,
    /// Reference count (multiple consumers per probe point).
    pub refcount: u32,
    /// Current state.
    pub state: UprobeState,
    /// Number of hits.
    pub hit_count: u64,
    /// Whether this is a return probe (uretprobe).
    pub is_return: bool,
}

impl UprobeEntry {
    /// Create a free slot.
    const fn empty() -> Self {
        Self {
            inode: 0,
            offset: 0,
            saved_insn: [0u8; MAX_INSN_LEN],
            insn_len: 0,
            handler_id: 0,
            ret_handler_id: 0,
            refcount: 0,
            state: UprobeState::Free,
            hit_count: 0,
            is_return: false,
        }
    }

    /// Returns `true` if the slot is occupied.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, UprobeState::Free)
    }
}

// ══════════════════════════════════════════════════════════════
// UprobeStats
// ══════════════════════════════════════════════════════════════

/// Uprobe subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct UprobeStats {
    /// Total uprobes registered.
    pub total_registered: u64,
    /// Total uprobes unregistered.
    pub total_unregistered: u64,
    /// Total hits across all probes.
    pub total_hits: u64,
    /// Total armed probes currently.
    pub armed_count: u32,
}

impl UprobeStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_registered: 0,
            total_unregistered: 0,
            total_hits: 0,
            armed_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// UprobeManager
// ══════════════════════════════════════════════════════════════

/// Manages user-space probes.
pub struct UprobeManager {
    /// Probe table.
    probes: [UprobeEntry; MAX_UPROBES],
    /// Statistics.
    stats: UprobeStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl UprobeManager {
    /// Create a new uprobe manager.
    pub const fn new() -> Self {
        Self {
            probes: [const { UprobeEntry::empty() }; MAX_UPROBES],
            stats: UprobeStats::new(),
            enabled: true,
        }
    }

    /// Register a uprobe at a file offset.
    ///
    /// # Errors
    ///
    /// - `NotImplemented` if uprobes are disabled.
    /// - `OutOfMemory` if no free slots.
    pub fn register(
        &mut self,
        inode: u64,
        offset: u64,
        handler_id: u64,
        is_return: bool,
    ) -> Result<usize> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // Check for existing probe at same location, increment ref.
        if let Some(idx) = self.find_probe(inode, offset) {
            self.probes[idx].refcount += 1;
            return Ok(idx);
        }
        let slot = self
            .probes
            .iter()
            .position(|p| matches!(p.state, UprobeState::Free))
            .ok_or(Error::OutOfMemory)?;
        self.probes[slot] = UprobeEntry {
            inode,
            offset,
            handler_id,
            refcount: 1,
            state: UprobeState::Registered,
            is_return,
            ..UprobeEntry::empty()
        };
        self.stats.total_registered += 1;
        Ok(slot)
    }

    /// Arm a registered uprobe.
    pub fn arm(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_UPROBES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.probes[slot].state, UprobeState::Registered) {
            return Err(Error::InvalidArgument);
        }
        self.probes[slot].state = UprobeState::Armed;
        self.stats.armed_count += 1;
        Ok(())
    }

    /// Disable an armed uprobe.
    pub fn disable(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_UPROBES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.probes[slot].state, UprobeState::Armed) {
            return Err(Error::InvalidArgument);
        }
        self.probes[slot].state = UprobeState::Disabled;
        self.stats.armed_count = self.stats.armed_count.saturating_sub(1);
        Ok(())
    }

    /// Unregister a uprobe (decrements refcount, frees at zero).
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_UPROBES {
            return Err(Error::InvalidArgument);
        }
        if !self.probes[slot].is_active() {
            return Err(Error::NotFound);
        }
        self.probes[slot].refcount = self.probes[slot].refcount.saturating_sub(1);
        if self.probes[slot].refcount == 0 {
            if matches!(self.probes[slot].state, UprobeState::Armed) {
                self.stats.armed_count = self.stats.armed_count.saturating_sub(1);
            }
            self.probes[slot] = UprobeEntry::empty();
            self.stats.total_unregistered += 1;
        }
        Ok(())
    }

    /// Record a probe hit.
    pub fn record_hit(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_UPROBES {
            return Err(Error::InvalidArgument);
        }
        self.probes[slot].hit_count += 1;
        self.stats.total_hits += 1;
        Ok(())
    }

    /// Find a probe by inode and offset.
    pub fn find_probe(&self, inode: u64, offset: u64) -> Option<usize> {
        self.probes
            .iter()
            .position(|p| p.is_active() && p.inode == inode && p.offset == offset)
    }

    /// Return probe entry.
    pub fn get(&self, slot: usize) -> Result<&UprobeEntry> {
        if slot >= MAX_UPROBES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.probes[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> UprobeStats {
        self.stats
    }
}
