// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hierarchical RCU tree for scalable grace-period detection.
//!
//! This module extends the flat per-CPU RCU model in [`crate::rcu`] with
//! a multi-level tree structure, inspired by Linux's Tree RCU
//! (`kernel/rcu/rcu_tree.c`). The hierarchy allows quiescent-state
//! reports to propagate upward level-by-level, reducing contention on
//! a single global counter.
//!
//! # Tree structure
//!
//! A 4-level tree supports up to 64 CPUs:
//!
//! ```text
//! Level 0:                     [root]           (1 node)
//! Level 1:          [0] [1] [2] [3] ...         (up to 8 nodes)
//! Level 2:    [0..7] per level-1 node           (up to 64 nodes)
//! Level 3:    CPUs mapped 1:1 to leaf nodes     (64 CPUs max)
//! ```
//!
//! Each interior node tracks a bitmap of children that have completed
//! their quiescent states. When all children report, the node itself
//! propagates completion to its parent.
//!
//! # Usage
//!
//! ```ignore
//! let mut state = RcuTreeState::new();
//! state.init(4); // 4 CPUs online
//! state.start_gp()?;
//! state.note_quiescent_state(0)?;
//! state.note_quiescent_state(1)?;
//! // ...after all CPUs report:
//! state.check_gp_completion(); // returns true when done
//! ```

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum CPUs supported by the tree.
const MAX_CPUS: usize = 64;

/// Branching factor — each interior node has up to this many
/// children.
const _FANOUT: usize = 8;

/// Number of hierarchy levels (root + 2 interior + leaf).
const _LEVELS: usize = 4;

/// Maximum number of nodes in the tree (1 + 8 + 64 = 73).
const MAX_NODES: usize = 73;

/// Index of the root node.
const ROOT_IDX: usize = 0;

/// First index of level-1 nodes (children of root).
const LEVEL1_START: usize = 1;

/// First index of level-2 (leaf) nodes.
const LEVEL2_START: usize = 9;

// ── RcuNode ──────────────────────────────────────────────────────

/// A single node in the RCU hierarchy.
///
/// Interior nodes aggregate quiescent-state reports from their
/// children. Leaf nodes are associated 1:1 with CPUs.
#[derive(Debug, Clone, Copy)]
pub struct RcuNode {
    /// Level in the tree (0 = root, 1 = mid, 2 = leaf).
    pub level: u8,
    /// Index of the parent node (`u16::MAX` for root).
    pub parent_idx: u16,
    /// Bitmask of children (or CPUs at leaf level) that belong
    /// to this node.
    pub children_mask: u64,
    /// Bitmask of children (or CPUs) that have reported a
    /// quiescent state for the current grace period.
    pub qs_completed_mask: u64,
    /// Grace period sequence number this node last acknowledged.
    pub gp_seq: u64,
    /// Whether this node is in use.
    pub active: bool,
}

impl RcuNode {
    /// Create an inactive node for array initialisation.
    const fn empty() -> Self {
        Self {
            level: 0,
            parent_idx: u16::MAX,
            children_mask: 0,
            qs_completed_mask: 0,
            gp_seq: 0,
            active: false,
        }
    }

    /// Returns `true` if all expected children have reported
    /// quiescent states.
    pub fn all_children_reported(&self) -> bool {
        self.active
            && self.children_mask != 0
            && (self.qs_completed_mask & self.children_mask) == self.children_mask
    }

    /// Reset quiescent-state tracking for a new grace period.
    pub fn reset_for_gp(&mut self, gp_seq: u64) {
        self.qs_completed_mask = 0;
        self.gp_seq = gp_seq;
    }
}

impl Default for RcuNode {
    fn default() -> Self {
        Self::empty()
    }
}

// ── RcuTree ──────────────────────────────────────────────────────

/// The multi-level node hierarchy.
///
/// Organises [`RcuNode`] instances into a tree with up to 4 levels
/// supporting 64 CPUs. The layout is:
/// - Index 0: root (level 0)
/// - Indices 1..8: level-1 nodes (children of root)
/// - Indices 9..72: level-2 leaf nodes (children of level 1)
pub struct RcuTree {
    /// Tree node array.
    nodes: [RcuNode; MAX_NODES],
    /// Number of active leaf nodes (= number of online CPUs).
    nr_leaves: usize,
    /// Number of active level-1 nodes.
    nr_level1: usize,
    /// Total number of online CPUs.
    nr_cpus: usize,
}

impl RcuTree {
    /// Create an uninitialised tree.
    pub const fn new() -> Self {
        Self {
            nodes: [RcuNode::empty(); MAX_NODES],
            nr_leaves: 0,
            nr_level1: 0,
            nr_cpus: 0,
        }
    }

    /// Initialise the tree for `nr_cpus` online processors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `nr_cpus` is 0 or
    /// exceeds [`MAX_CPUS`].
    pub fn init(&mut self, nr_cpus: usize) -> Result<()> {
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        // Reset everything.
        self.nodes = [RcuNode::empty(); MAX_NODES];
        self.nr_cpus = nr_cpus;

        // Determine how many level-1 and level-2 nodes are needed.
        // Each leaf covers 1 CPU; each level-1 node covers up to 8 leaves.
        self.nr_leaves = nr_cpus;
        self.nr_level1 = nr_cpus.div_ceil(8);

        // Set up root (level 0).
        self.nodes[ROOT_IDX] = RcuNode {
            level: 0,
            parent_idx: u16::MAX,
            children_mask: (1u64 << self.nr_level1) - 1,
            qs_completed_mask: 0,
            gp_seq: 0,
            active: true,
        };

        // Set up level-1 nodes.
        for i in 0..self.nr_level1 {
            let idx = LEVEL1_START + i;
            let cpus_start = i * 8;
            let cpus_end = core::cmp::min(cpus_start + 8, nr_cpus);
            let nr_children = cpus_end - cpus_start;

            self.nodes[idx] = RcuNode {
                level: 1,
                parent_idx: ROOT_IDX as u16,
                children_mask: (1u64 << nr_children) - 1,
                qs_completed_mask: 0,
                gp_seq: 0,
                active: true,
            };
        }

        // Set up level-2 (leaf) nodes — one per CPU.
        for cpu in 0..nr_cpus {
            let idx = LEVEL2_START + cpu;
            let parent_l1 = LEVEL1_START + cpu / 8;

            self.nodes[idx] = RcuNode {
                level: 2,
                parent_idx: parent_l1 as u16,
                children_mask: 1u64 << cpu,
                qs_completed_mask: 0,
                gp_seq: 0,
                active: true,
            };
        }

        Ok(())
    }

    /// Return a reference to the root node.
    pub fn root(&self) -> &RcuNode {
        &self.nodes[ROOT_IDX]
    }

    /// Return the number of online CPUs configured in the tree.
    pub fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }

    /// Return a reference to a node by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn node(&self, idx: usize) -> Result<&RcuNode> {
        if idx >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[idx])
    }

    /// Reset all nodes for a new grace period.
    pub fn reset_for_gp(&mut self, gp_seq: u64) {
        for node in &mut self.nodes {
            if node.active {
                node.reset_for_gp(gp_seq);
            }
        }
    }

    /// Report a quiescent state for `cpu_id` and propagate
    /// completion upward through the tree.
    ///
    /// Returns `true` if the root becomes fully reported (grace
    /// period complete).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of
    /// range.
    pub fn report_qs(&mut self, cpu_id: usize) -> Result<bool> {
        if cpu_id >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }

        // Mark the leaf node.
        let leaf_idx = LEVEL2_START + cpu_id;
        self.nodes[leaf_idx].qs_completed_mask = self.nodes[leaf_idx].children_mask;

        // Propagate to level-1 parent.
        let l1_idx = self.nodes[leaf_idx].parent_idx as usize;
        let child_bit_in_l1 = cpu_id % 8;
        self.nodes[l1_idx].qs_completed_mask |= 1u64 << child_bit_in_l1;

        // If the level-1 node is complete, propagate to root.
        if self.nodes[l1_idx].all_children_reported() {
            let l1_bit_in_root = l1_idx - LEVEL1_START;
            self.nodes[ROOT_IDX].qs_completed_mask |= 1u64 << l1_bit_in_root;
        }

        Ok(self.nodes[ROOT_IDX].all_children_reported())
    }
}

impl Default for RcuTree {
    fn default() -> Self {
        Self::new()
    }
}

// ── RcuGracePeriod ───────────────────────────────────────────────

/// State of a tree-based grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpState {
    /// No grace period in progress.
    #[default]
    Idle,
    /// A grace period is in progress.
    InProgress,
    /// The grace period has completed.
    Completed,
}

/// Tracks a single tree-based RCU grace period.
#[derive(Debug, Clone, Copy)]
pub struct RcuGracePeriod {
    /// Grace period sequence number.
    pub gp_seq: u64,
    /// Current state.
    pub state: GpState,
    /// Tick at which the grace period started.
    pub start_tick: u64,
}

impl RcuGracePeriod {
    /// Create an idle grace period.
    pub const fn new() -> Self {
        Self {
            gp_seq: 0,
            state: GpState::Idle,
            start_tick: 0,
        }
    }
}

impl Default for RcuGracePeriod {
    fn default() -> Self {
        Self::new()
    }
}

// ── RcuTreeStats ─────────────────────────────────────────────────

/// Statistics for the tree RCU subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct RcuTreeStats {
    /// Number of grace periods completed.
    pub gp_completed: u64,
    /// Cumulative ticks spent in grace periods.
    pub gp_duration_total: u64,
    /// Number of forced quiescent-state scans.
    pub force_qs_count: u64,
}

impl RcuTreeStats {
    /// Create a zeroed statistics block.
    pub const fn new() -> Self {
        Self {
            gp_completed: 0,
            gp_duration_total: 0,
            force_qs_count: 0,
        }
    }
}

// ── Per-CPU quiescent-state tracking ─────────────────────────────

/// Per-CPU quiescent-state record used by the tree RCU subsystem.
#[derive(Debug, Clone, Copy)]
pub struct RcuCpuState {
    /// Whether this CPU has passed a quiescent state for the
    /// current grace period.
    pub qs_passed: bool,
    /// Read-side nesting depth.
    pub nesting: u32,
    /// Whether the CPU is online.
    pub online: bool,
}

impl RcuCpuState {
    /// Create an offline CPU state entry.
    const fn new() -> Self {
        Self {
            qs_passed: false,
            nesting: 0,
            online: false,
        }
    }
}

impl Default for RcuCpuState {
    fn default() -> Self {
        Self::new()
    }
}

// ── RcuTreeState ─────────────────────────────────────────────────

/// Central state for the hierarchical RCU tree subsystem.
///
/// Combines the [`RcuTree`] hierarchy, the current
/// [`RcuGracePeriod`], per-CPU quiescent-state tracking, and
/// performance statistics.
pub struct RcuTreeState {
    /// The node hierarchy.
    tree: RcuTree,
    /// Current grace period.
    gp: RcuGracePeriod,
    /// Per-CPU quiescent-state records.
    cpu_states: [RcuCpuState; MAX_CPUS],
    /// Statistics.
    stats: RcuTreeStats,
    /// Current tick counter (for duration tracking).
    current_tick: u64,
}

impl RcuTreeState {
    /// Create an uninitialised tree RCU state.
    pub const fn new() -> Self {
        Self {
            tree: RcuTree::new(),
            gp: RcuGracePeriod::new(),
            cpu_states: [RcuCpuState::new(); MAX_CPUS],
            stats: RcuTreeStats::new(),
            current_tick: 0,
        }
    }

    /// Initialise the RCU tree for `nr_cpus` online processors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `nr_cpus` is 0 or
    /// exceeds [`MAX_CPUS`].
    pub fn init(&mut self, nr_cpus: usize) -> Result<()> {
        self.tree.init(nr_cpus)?;
        for cpu in &mut self.cpu_states {
            *cpu = RcuCpuState::new();
        }
        for cpu in self.cpu_states.iter_mut().take(nr_cpus) {
            cpu.online = true;
        }
        self.gp = RcuGracePeriod::new();
        self.stats = RcuTreeStats::new();
        Ok(())
    }

    /// Note a quiescent state on `cpu_id`.
    ///
    /// If the CPU is inside a read-side critical section
    /// (nesting depth greater than zero), this is a no-op.
    /// Otherwise the quiescent state is propagated up through
    /// the tree. If the grace period completes as a result,
    /// `check_gp_completion` is called internally.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of
    /// range or the CPU is offline.
    pub fn note_quiescent_state(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS || !self.cpu_states[cpu_id].online {
            return Err(Error::InvalidArgument);
        }

        // Cannot report QS while in a read-side critical section.
        if self.cpu_states[cpu_id].nesting > 0 {
            return Ok(());
        }

        self.cpu_states[cpu_id].qs_passed = true;

        // Propagate through the tree only if a GP is active.
        if self.gp.state == GpState::InProgress {
            let complete = self.tree.report_qs(cpu_id)?;
            if complete {
                self.complete_gp();
            }
        }

        Ok(())
    }

    /// Check whether the current grace period has completed by
    /// inspecting the tree root.
    ///
    /// Returns `true` if the grace period just completed (state
    /// transitions to [`GpState::Completed`]).
    pub fn check_gp_completion(&mut self) -> bool {
        if self.gp.state != GpState::InProgress {
            return false;
        }
        if self.tree.root().all_children_reported() {
            self.complete_gp();
            return true;
        }
        false
    }

    /// Start a new grace period.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a grace period is already in
    /// progress.
    pub fn start_gp(&mut self) -> Result<()> {
        if self.gp.state == GpState::InProgress {
            return Err(Error::Busy);
        }

        self.gp.gp_seq = self.gp.gp_seq.wrapping_add(1);
        self.gp.state = GpState::InProgress;
        self.gp.start_tick = self.current_tick;

        // Reset per-CPU QS flags.
        for cpu in &mut self.cpu_states {
            cpu.qs_passed = false;
        }

        // Reset the tree for the new GP.
        self.tree.reset_for_gp(self.gp.gp_seq);

        Ok(())
    }

    /// Force a quiescent-state scan across all online CPUs.
    ///
    /// For CPUs that have already reported a QS, this propagates
    /// their report through the tree. Useful when the grace period
    /// is stuck and the kernel suspects some CPUs are in long-
    /// running loops.
    ///
    /// Returns `true` if the grace period completed as a result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no grace period is
    /// in progress.
    pub fn force_quiescent_state(&mut self) -> Result<bool> {
        if self.gp.state != GpState::InProgress {
            return Err(Error::InvalidArgument);
        }

        self.stats.force_qs_count = self.stats.force_qs_count.wrapping_add(1);

        let nr = self.tree.nr_cpus();
        for cpu in 0..nr {
            if self.cpu_states[cpu].qs_passed {
                let complete = self.tree.report_qs(cpu)?;
                if complete {
                    self.complete_gp();
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Synchronous RCU barrier: start a grace period and attempt
    /// to complete it by forcing quiescent-state propagation.
    ///
    /// In a real kernel the caller would block; here we start the
    /// GP and run one forced-QS scan.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a grace period is already in
    /// progress.
    pub fn synchronize_rcu_tree(&mut self) -> Result<()> {
        self.start_gp()?;
        let _ = self.force_quiescent_state()?;
        Ok(())
    }

    /// Advance the tick counter (call from timer interrupt).
    pub fn tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);
    }

    /// Return the current grace period info.
    pub fn grace_period(&self) -> &RcuGracePeriod {
        &self.gp
    }

    /// Return the statistics snapshot.
    pub fn stats(&self) -> &RcuTreeStats {
        &self.stats
    }

    /// Return a reference to the tree.
    pub fn tree(&self) -> &RcuTree {
        &self.tree
    }

    /// Return the number of online CPUs.
    pub fn nr_cpus(&self) -> usize {
        self.tree.nr_cpus()
    }

    // ── internal helpers ─────────────────────────────────────────

    /// Transition the current grace period to Completed and update
    /// statistics.
    fn complete_gp(&mut self) {
        let duration = self.current_tick.wrapping_sub(self.gp.start_tick);
        self.gp.state = GpState::Completed;
        self.stats.gp_completed = self.stats.gp_completed.wrapping_add(1);
        self.stats.gp_duration_total = self.stats.gp_duration_total.wrapping_add(duration);
    }
}

impl Default for RcuTreeState {
    fn default() -> Self {
        Self::new()
    }
}
