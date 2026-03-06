// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF program attachment management.
//!
//! Manages the lifecycle of BPF programs attached to kernel hooks
//! (cgroup, tracepoint, XDP, socket filter, etc.). Each attachment
//! binds a compiled BPF program to a specific hook point.
//!
//! # Architecture
//!
//! ```text
//! AttachManager
//!  ├── attachments[MAX_ATTACHMENTS]
//!  │    ├── prog_id, target_id, attach_type
//!  │    ├── state: AttachState
//!  │    └── priority, flags
//!  └── stats: AttachStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/bpf/syscall.c` — `BPF_PROG_ATTACH` / `BPF_PROG_DETACH`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum concurrent BPF program attachments.
const MAX_ATTACHMENTS: usize = 256;

/// Maximum number of programs attached to a single target.
const MAX_PER_TARGET: usize = 16;

// ══════════════════════════════════════════════════════════════
// AttachType — hook categories
// ══════════════════════════════════════════════════════════════

/// Type of kernel hook a BPF program attaches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachType {
    /// Cgroup ingress traffic filter.
    CgroupInetIngress = 0,
    /// Cgroup egress traffic filter.
    CgroupInetEgress = 1,
    /// Cgroup socket creation hook.
    CgroupInetSockCreate = 2,
    /// Cgroup device access control.
    CgroupDevice = 3,
    /// XDP hook on network interface.
    Xdp = 4,
    /// Socket filter (classic BPF replacement).
    SocketFilter = 5,
    /// Tracepoint attachment.
    Tracepoint = 6,
    /// Kprobe attachment.
    Kprobe = 7,
    /// Perf event attachment.
    PerfEvent = 8,
    /// LSM security hook.
    Lsm = 9,
}

// ══════════════════════════════════════════════════════════════
// AttachState
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachState {
    /// Slot is free.
    Free = 0,
    /// Program is attached and active.
    Active = 1,
    /// Program is attached but disabled.
    Disabled = 2,
    /// Detachment in progress.
    Detaching = 3,
}

// ══════════════════════════════════════════════════════════════
// AttachFlags
// ══════════════════════════════════════════════════════════════

/// Flags controlling attachment behaviour.
#[derive(Debug, Clone, Copy)]
pub struct AttachFlags {
    /// Allow multiple programs on the same hook.
    pub multi: bool,
    /// Replace an existing program instead of adding.
    pub replace: bool,
    /// Run in override mode (skip other programs).
    pub override_mode: bool,
}

impl AttachFlags {
    /// Default flags (single, no replace, no override).
    pub const fn default_flags() -> Self {
        Self {
            multi: false,
            replace: false,
            override_mode: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Attachment — per-slot metadata
// ══════════════════════════════════════════════════════════════

/// Metadata for a single BPF program attachment.
#[derive(Debug, Clone, Copy)]
pub struct Attachment {
    /// BPF program identifier.
    pub prog_id: u64,
    /// Target identifier (cgroup fd, ifindex, etc.).
    pub target_id: u64,
    /// Type of hook.
    pub attach_type: AttachType,
    /// Current state.
    pub state: AttachState,
    /// Priority (lower = higher priority).
    pub priority: u32,
    /// Attachment flags.
    pub flags: AttachFlags,
    /// Monotonic attach sequence for ordering.
    pub attach_seq: u64,
}

impl Attachment {
    /// Create an empty attachment slot.
    const fn empty() -> Self {
        Self {
            prog_id: 0,
            target_id: 0,
            attach_type: AttachType::CgroupInetIngress,
            state: AttachState::Free,
            priority: 0,
            flags: AttachFlags::default_flags(),
            attach_seq: 0,
        }
    }

    /// Returns `true` if the slot is occupied.
    pub const fn is_active(&self) -> bool {
        matches!(self.state, AttachState::Active | AttachState::Disabled)
    }
}

// ══════════════════════════════════════════════════════════════
// AttachStats
// ══════════════════════════════════════════════════════════════

/// Attachment subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct AttachStats {
    /// Total successful attaches.
    pub total_attached: u64,
    /// Total detaches.
    pub total_detached: u64,
    /// Total failed attach attempts.
    pub total_failed: u64,
    /// Total replacements.
    pub total_replaced: u64,
}

impl AttachStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_attached: 0,
            total_detached: 0,
            total_failed: 0,
            total_replaced: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// AttachManager
// ══════════════════════════════════════════════════════════════

/// Manages BPF program attachments to kernel hooks.
pub struct AttachManager {
    /// Attachment table.
    attachments: [Attachment; MAX_ATTACHMENTS],
    /// Next sequence number for ordering.
    next_seq: u64,
    /// Statistics.
    stats: AttachStats,
}

impl AttachManager {
    /// Create a new, empty attachment manager.
    pub const fn new() -> Self {
        Self {
            attachments: [const { Attachment::empty() }; MAX_ATTACHMENTS],
            next_seq: 1,
            stats: AttachStats::new(),
        }
    }

    /// Attach a BPF program to a target hook.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free slots remain.
    /// - `AlreadyExists` if a duplicate attachment exists and
    ///   `replace` is not set.
    /// - `InvalidArgument` if per-target limit is exceeded.
    pub fn attach(
        &mut self,
        prog_id: u64,
        target_id: u64,
        attach_type: AttachType,
        flags: AttachFlags,
        priority: u32,
    ) -> Result<usize> {
        // Check for existing attachment.
        if let Some(idx) = self.find_attachment(prog_id, target_id, attach_type) {
            if flags.replace {
                self.attachments[idx].priority = priority;
                self.attachments[idx].flags = flags;
                self.stats.total_replaced += 1;
                return Ok(idx);
            }
            return Err(Error::AlreadyExists);
        }

        // Check per-target limit.
        if !flags.multi {
            let count = self.count_for_target(target_id, attach_type);
            if count >= MAX_PER_TARGET {
                self.stats.total_failed += 1;
                return Err(Error::InvalidArgument);
            }
        }

        let slot = self.find_free_slot()?;
        self.attachments[slot] = Attachment {
            prog_id,
            target_id,
            attach_type,
            state: AttachState::Active,
            priority,
            flags,
            attach_seq: self.next_seq,
        };
        self.next_seq += 1;
        self.stats.total_attached += 1;
        Ok(slot)
    }

    /// Detach a BPF program from a target hook.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching attachment exists.
    pub fn detach(&mut self, prog_id: u64, target_id: u64, attach_type: AttachType) -> Result<()> {
        let idx = self
            .find_attachment(prog_id, target_id, attach_type)
            .ok_or(Error::NotFound)?;
        self.attachments[idx] = Attachment::empty();
        self.stats.total_detached += 1;
        Ok(())
    }

    /// Disable an attachment without removing it.
    pub fn disable(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_ATTACHMENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.attachments[slot].is_active() {
            return Err(Error::NotFound);
        }
        self.attachments[slot].state = AttachState::Disabled;
        Ok(())
    }

    /// Return the number of active attachments.
    pub fn active_count(&self) -> usize {
        self.attachments.iter().filter(|a| a.is_active()).count()
    }

    /// Return statistics.
    pub fn stats(&self) -> AttachStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_free_slot(&self) -> Result<usize> {
        self.attachments
            .iter()
            .position(|a| matches!(a.state, AttachState::Free))
            .ok_or(Error::OutOfMemory)
    }

    fn find_attachment(
        &self,
        prog_id: u64,
        target_id: u64,
        attach_type: AttachType,
    ) -> Option<usize> {
        self.attachments.iter().position(|a| {
            a.is_active()
                && a.prog_id == prog_id
                && a.target_id == target_id
                && a.attach_type == attach_type
        })
    }

    fn count_for_target(&self, target_id: u64, attach_type: AttachType) -> usize {
        self.attachments
            .iter()
            .filter(|a| a.is_active() && a.target_id == target_id && a.attach_type == attach_type)
            .count()
    }
}
