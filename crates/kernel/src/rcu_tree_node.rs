// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU tree node management — hierarchical RCU state tracking.
//!
//! The tree-based RCU implementation uses a hierarchy of nodes to
//! track quiescent state reporting from individual CPUs up through
//! the tree to detect grace period completion efficiently.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    RcuTreeManager                            │
//! │                                                              │
//! │  RcuNode[0..MAX_NODES]  (tree hierarchy nodes)               │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  level: u8                                             │  │
//! │  │  qsmask: u64  (CPUs that haven't reported qs)          │  │
//! │  │  parent_idx: Option<usize>                             │  │
//! │  │  gp_seq: u64  (grace period sequence)                  │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  RcuPerCpu[0..MAX_CPUS]  (per-CPU RCU state)                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/rcu/tree.c`, `include/linux/rcutree.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum tree nodes (sufficient for 64 CPUs with fanout 16).
const MAX_NODES: usize = 8;

/// Maximum tree depth.
const MAX_DEPTH: usize = 3;

/// Node fanout (CPUs per leaf node).
const _FANOUT: usize = 16;

// ══════════════════════════════════════════════════════════════
// QsState — quiescent state
// ══════════════════════════════════════════════════════════════

/// Quiescent state of a CPU for the current grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QsState {
    /// CPU has not yet reported a quiescent state.
    Pending = 0,
    /// CPU has reported a quiescent state.
    Reported = 1,
    /// CPU is offline (auto-reported).
    Offline = 2,
}

// ══════════════════════════════════════════════════════════════
// GpState — grace period state
// ══════════════════════════════════════════════════════════════

/// State of a grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpState {
    /// No grace period in progress.
    Idle = 0,
    /// Grace period initialisation phase.
    Init = 1,
    /// Waiting for quiescent states.
    Wait = 2,
    /// All quiescent states reported, cleanup phase.
    Cleanup = 3,
}

// ══════════════════════════════════════════════════════════════
// RcuNode
// ══════════════════════════════════════════════════════════════

/// A node in the RCU tree hierarchy.
#[derive(Debug, Clone, Copy)]
pub struct RcuNode {
    /// Tree level (0 = root).
    pub level: u8,
    /// Bitmask of children that haven't reported quiescent states.
    pub qsmask: u64,
    /// Bitmask of online children.
    pub online_mask: u64,
    /// Parent node index (None = root).
    pub parent_idx: Option<usize>,
    /// Current grace period sequence number.
    pub gp_seq: u64,
    /// Whether this node is active.
    pub active: bool,
    /// Number of children (CPUs or lower nodes).
    pub child_count: u16,
}

impl RcuNode {
    const fn empty() -> Self {
        Self {
            level: 0,
            qsmask: 0,
            online_mask: 0,
            parent_idx: None,
            gp_seq: 0,
            active: false,
            child_count: 0,
        }
    }

    /// Returns `true` if all children have reported quiescent states.
    pub const fn all_reported(&self) -> bool {
        self.qsmask == 0
    }
}

// ══════════════════════════════════════════════════════════════
// RcuPerCpu
// ══════════════════════════════════════════════════════════════

/// Per-CPU RCU state.
#[derive(Debug, Clone, Copy)]
pub struct RcuPerCpu {
    /// Quiescent state for current GP.
    pub qs_state: QsState,
    /// Node index this CPU belongs to.
    pub node_idx: usize,
    /// Bit position in the node's qsmask.
    pub bit_pos: u8,
    /// Number of quiescent states reported.
    pub qs_count: u64,
    /// Pending callbacks count.
    pub cb_count: u64,
    /// Whether the CPU is online.
    pub online: bool,
}

impl RcuPerCpu {
    const fn new() -> Self {
        Self {
            qs_state: QsState::Offline,
            node_idx: 0,
            bit_pos: 0,
            qs_count: 0,
            cb_count: 0,
            online: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RcuTreeStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the RCU tree.
#[derive(Debug, Clone, Copy)]
pub struct RcuTreeStats {
    /// Total grace periods completed.
    pub total_gp_completed: u64,
    /// Total quiescent state reports.
    pub total_qs_reports: u64,
    /// Total callbacks processed.
    pub total_callbacks: u64,
    /// Current grace period sequence.
    pub current_gp_seq: u64,
    /// Current grace period state.
    pub gp_state: GpState,
}

impl RcuTreeStats {
    const fn new() -> Self {
        Self {
            total_gp_completed: 0,
            total_qs_reports: 0,
            total_callbacks: 0,
            current_gp_seq: 0,
            gp_state: GpState::Idle,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RcuTreeManager
// ══════════════════════════════════════════════════════════════

/// Top-level RCU tree node manager.
pub struct RcuTreeManager {
    /// Tree nodes.
    nodes: [RcuNode; MAX_NODES],
    /// Per-CPU state.
    per_cpu: [RcuPerCpu; MAX_CPUS],
    /// Statistics.
    stats: RcuTreeStats,
    /// Tree depth.
    depth: usize,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for RcuTreeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RcuTreeManager {
    /// Create a new RCU tree manager.
    pub const fn new() -> Self {
        Self {
            nodes: [const { RcuNode::empty() }; MAX_NODES],
            per_cpu: [const { RcuPerCpu::new() }; MAX_CPUS],
            stats: RcuTreeStats::new(),
            depth: 1,
            initialised: false,
        }
    }

    /// Initialise the tree with a given number of CPUs.
    pub fn init(&mut self, nr_cpus: usize) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        // Create a single root node for simplicity.
        self.nodes[0] = RcuNode {
            level: 0,
            qsmask: 0,
            online_mask: 0,
            parent_idx: None,
            gp_seq: 0,
            active: true,
            child_count: nr_cpus as u16,
        };

        // Assign CPUs to the root node.
        for cpu in 0..nr_cpus {
            self.per_cpu[cpu].node_idx = 0;
            self.per_cpu[cpu].bit_pos = cpu as u8;
            self.per_cpu[cpu].online = true;
            self.per_cpu[cpu].qs_state = QsState::Reported;
            self.nodes[0].online_mask |= 1u64 << cpu;
        }

        self.depth = 1;
        self.initialised = true;
        Ok(())
    }

    // ── Grace period management ──────────────────────────────

    /// Start a new grace period.
    pub fn start_gp(&mut self) -> Result<u64> {
        if !matches!(self.stats.gp_state, GpState::Idle) {
            return Err(Error::Busy);
        }

        self.stats.current_gp_seq += 1;
        self.stats.gp_state = GpState::Wait;

        // Set qsmask for all online CPUs.
        self.nodes[0].qsmask = self.nodes[0].online_mask;
        self.nodes[0].gp_seq = self.stats.current_gp_seq;

        // Reset per-CPU qs state.
        for cpu_state in &mut self.per_cpu {
            if cpu_state.online {
                cpu_state.qs_state = QsState::Pending;
            }
        }

        Ok(self.stats.current_gp_seq)
    }

    /// Report a quiescent state for a CPU.
    pub fn report_qs(&mut self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS || !self.per_cpu[cpu].online {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.per_cpu[cpu].qs_state, QsState::Reported) {
            return Ok(false); // Already reported.
        }

        self.per_cpu[cpu].qs_state = QsState::Reported;
        self.per_cpu[cpu].qs_count += 1;
        self.stats.total_qs_reports += 1;

        // Clear the CPU's bit in its node.
        let node_idx = self.per_cpu[cpu].node_idx;
        let bit = self.per_cpu[cpu].bit_pos;
        self.nodes[node_idx].qsmask &= !(1u64 << bit);

        // Check if grace period is complete.
        let complete = self.nodes[0].all_reported();
        if complete {
            self.complete_gp();
        }

        Ok(complete)
    }

    /// Complete the current grace period.
    fn complete_gp(&mut self) {
        self.stats.gp_state = GpState::Idle;
        self.stats.total_gp_completed += 1;
    }

    /// Process pending RCU callbacks for a CPU.
    pub fn process_callbacks(&mut self, cpu: usize, count: u64) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].cb_count = self.per_cpu[cpu].cb_count.saturating_sub(count);
        self.stats.total_callbacks += count;
        Ok(())
    }

    /// Queue callbacks for a CPU.
    pub fn queue_callback(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].cb_count += 1;
        Ok(())
    }

    // ── CPU online/offline ───────────────────────────────────

    /// Mark a CPU as online.
    pub fn cpu_online(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].online = true;
        self.per_cpu[cpu].qs_state = QsState::Reported;
        let node_idx = self.per_cpu[cpu].node_idx;
        let bit = self.per_cpu[cpu].bit_pos;
        self.nodes[node_idx].online_mask |= 1u64 << bit;
        Ok(())
    }

    /// Mark a CPU as offline.
    pub fn cpu_offline(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].online = false;
        self.per_cpu[cpu].qs_state = QsState::Offline;
        let node_idx = self.per_cpu[cpu].node_idx;
        let bit = self.per_cpu[cpu].bit_pos;
        self.nodes[node_idx].online_mask &= !(1u64 << bit);
        self.nodes[node_idx].qsmask &= !(1u64 << bit);
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> RcuTreeStats {
        self.stats
    }

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Result<&RcuPerCpu> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }

    /// Return a tree node.
    pub fn node(&self, idx: usize) -> Result<&RcuNode> {
        if idx >= MAX_NODES || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Return the tree depth.
    pub fn depth(&self) -> usize {
        self.depth.min(MAX_DEPTH)
    }

    /// Return the number of online CPUs.
    pub fn online_cpus(&self) -> usize {
        self.per_cpu.iter().filter(|c| c.online).count()
    }
}
