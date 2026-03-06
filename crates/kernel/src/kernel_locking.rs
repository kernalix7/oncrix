// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel lock validator (lockdep-lite) — deadlock detection
//! via lock ordering enforcement.
//!
//! Implements a simplified version of the Linux kernel's lockdep
//! subsystem.  It tracks the order in which lock classes are
//! acquired, builds a dependency graph, and detects potential
//! deadlocks via cycle detection.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     LockValidator                             │
//! │                                                              │
//! │  LockGraph                                                   │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  classes[0..MAX_LOCK_CLASSES]  (lock class registry)   │  │
//! │  │  edges[0..MAX_EDGES]  (dependency (a→b) records)       │  │
//! │  │  adjacency[0..MAX_LOCK_CLASSES]  (u64 bitmask rows)   │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  Per-CPU held stack                                          │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  held[0..MAX_HELD_DEPTH]  (LockInstance per level)     │  │
//! │  │  depth: u8                                              │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  LockValidatorStats (global counters)                        │
//! │  - acquires, releases, violations, deadlocks_detected        │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Deadlock Detection
//!
//! When a lock is acquired, the validator:
//! 1. Checks that the new lock class does not violate any existing
//!    ordering constraint.
//! 2. Adds edges from all currently held lock classes to the new one.
//! 3. Runs a DFS-based cycle detection on the updated graph.
//!
//! If a cycle is found, a `LockViolation::Deadlock` is reported.
//!
//! # Reference
//!
//! Linux `kernel/locking/lockdep.c`, `include/linux/lockdep.h`,
//! `Documentation/locking/lockdep-design.rst`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of lock classes tracked.
const MAX_LOCK_CLASSES: usize = 64;

/// Maximum dependency edges in the graph.
const MAX_EDGES: usize = 256;

/// Maximum lock nesting depth per CPU.
const MAX_HELD_DEPTH: usize = 8;

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Lock class name buffer length.
const LOCK_NAME_LEN: usize = 32;

/// Maximum depth for DFS cycle detection.
const MAX_DFS_DEPTH: usize = 64;

// ══════════════════════════════════════════════════════════════
// LockClass
// ══════════════════════════════════════════════════════════════

/// A lock class — all locks of the same "type" share a class.
///
/// Lock classes are identified by a unique ID and have a maximum
/// nesting depth limit.
#[derive(Clone, Copy)]
pub struct LockClass {
    /// Unique class ID.
    pub id: u32,
    /// Human-readable class name.
    pub name: [u8; LOCK_NAME_LEN],
    /// Maximum allowed nesting depth for this class.
    pub depth_limit: u8,
    /// Whether this class slot is registered.
    pub registered: bool,
    /// Total acquisitions of locks in this class.
    pub acquisition_count: u64,
    /// Total contentions (acquire while another CPU holds it).
    pub contention_count: u64,
}

impl LockClass {
    /// Create an empty lock class.
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; LOCK_NAME_LEN],
            depth_limit: 1,
            registered: false,
            acquisition_count: 0,
            contention_count: 0,
        }
    }

    /// Create a named lock class.
    pub fn with_name(id: u32, name: &[u8], depth_limit: u8) -> Self {
        let mut class = Self::new();
        class.id = id;
        let copy_len = name.len().min(LOCK_NAME_LEN);
        class.name[..copy_len].copy_from_slice(&name[..copy_len]);
        class.depth_limit = if depth_limit == 0 { 1 } else { depth_limit };
        class.registered = true;
        class
    }
}

impl Default for LockClass {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// LockInstance
// ══════════════════════════════════════════════════════════════

/// A specific lock acquisition on the held stack.
#[derive(Clone, Copy)]
pub struct LockInstance {
    /// Lock class ID.
    pub class_id: u32,
    /// Tick when this lock was acquired.
    pub acquired_tick: u64,
    /// CPU that acquired the lock.
    pub cpu: u32,
    /// PID of the owning task.
    pub owner_pid: u64,
    /// Whether this is a read (shared) acquisition.
    pub is_read: bool,
    /// Whether this instance slot is valid.
    pub valid: bool,
}

impl LockInstance {
    /// Create an empty lock instance.
    pub const fn new() -> Self {
        Self {
            class_id: 0,
            acquired_tick: 0,
            cpu: 0,
            owner_pid: 0,
            is_read: false,
            valid: false,
        }
    }
}

impl Default for LockInstance {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// LockOrder
// ══════════════════════════════════════════════════════════════

/// A lock ordering constraint: class_a must be acquired before class_b.
#[derive(Clone, Copy)]
pub struct LockOrder {
    /// Class that must be acquired first.
    pub class_a: u32,
    /// Class that must be acquired second.
    pub class_b: u32,
    /// Whether this edge is active.
    pub active: bool,
    /// Tick when this ordering was first observed.
    pub first_seen_tick: u64,
}

impl LockOrder {
    /// Create an empty lock order.
    pub const fn new() -> Self {
        Self {
            class_a: 0,
            class_b: 0,
            active: false,
            first_seen_tick: 0,
        }
    }
}

impl Default for LockOrder {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// LockViolation
// ══════════════════════════════════════════════════════════════

/// Types of lock ordering violations detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockViolation {
    /// Lock ordering violation: expected `class_a` before `class_b`,
    /// but `class_b` was already held when `class_a` was acquired.
    Ordering {
        /// Class that should have been acquired first.
        expected_first: u32,
        /// Class that was actually acquired first.
        actual_first: u32,
    },
    /// Potential deadlock detected — cycle in the dependency graph.
    /// The value is the class ID where the cycle was detected.
    Deadlock(u32),
    /// Attempt to acquire the same lock class twice (without recursion
    /// being allowed).
    DoubleAcquire(u32),
}

// ══════════════════════════════════════════════════════════════
// LockGraph
// ══════════════════════════════════════════════════════════════

/// Lock dependency graph with adjacency matrix representation.
///
/// Each bit `j` in `adjacency[i]` indicates that class `i` has
/// been observed acquired before class `j`.
pub struct LockGraph {
    /// Registered lock classes.
    pub classes: [LockClass; MAX_LOCK_CLASSES],
    /// Number of registered classes.
    pub class_count: u32,
    /// Dependency edges (for detailed reporting).
    pub edges: [LockOrder; MAX_EDGES],
    /// Number of active edges.
    pub edge_count: u32,
    /// Adjacency matrix: `adjacency[i]` bit `j` = class i → class j.
    pub adjacency: [u64; MAX_LOCK_CLASSES],
}

impl LockGraph {
    /// Create an empty lock graph.
    pub const fn new() -> Self {
        Self {
            classes: [const { LockClass::new() }; MAX_LOCK_CLASSES],
            class_count: 0,
            edges: [const { LockOrder::new() }; MAX_EDGES],
            edge_count: 0,
            adjacency: [0u64; MAX_LOCK_CLASSES],
        }
    }

    /// Register a new lock class.
    pub fn register_class(&mut self, id: u32, name: &[u8], depth_limit: u8) -> Result<()> {
        if self.class_count as usize >= MAX_LOCK_CLASSES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate ID.
        if self.find_class_index(id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let idx = self.class_count as usize;
        self.classes[idx] = LockClass::with_name(id, name, depth_limit);
        self.class_count += 1;
        Ok(())
    }

    /// Find the array index of a class by its ID.
    pub fn find_class_index(&self, id: u32) -> Option<usize> {
        self.classes[..self.class_count as usize]
            .iter()
            .position(|c| c.registered && c.id == id)
    }

    /// Add a directed edge from class_a to class_b.
    pub fn add_edge(&mut self, class_a: u32, class_b: u32, tick: u64) -> Result<()> {
        let idx_a = self.find_class_index(class_a).ok_or(Error::NotFound)?;
        let idx_b = self.find_class_index(class_b).ok_or(Error::NotFound)?;

        // Check if edge already exists in adjacency matrix.
        if (self.adjacency[idx_a] & (1u64 << idx_b)) != 0 {
            return Ok(()); // Edge already recorded.
        }

        // Add to adjacency matrix.
        self.adjacency[idx_a] |= 1u64 << idx_b;

        // Record detailed edge.
        if (self.edge_count as usize) < MAX_EDGES {
            self.edges[self.edge_count as usize] = LockOrder {
                class_a,
                class_b,
                active: true,
                first_seen_tick: tick,
            };
            self.edge_count += 1;
        }

        Ok(())
    }

    /// Check if an edge from class_a to class_b exists.
    pub fn has_edge(&self, class_a: u32, class_b: u32) -> bool {
        let idx_a = match self.find_class_index(class_a) {
            Some(i) => i,
            None => return false,
        };
        let idx_b = match self.find_class_index(class_b) {
            Some(i) => i,
            None => return false,
        };
        (self.adjacency[idx_a] & (1u64 << idx_b)) != 0
    }

    /// Check if adding edge (from → to) would create a cycle.
    ///
    /// Uses DFS from `to` to see if `from` is reachable (which
    /// would mean from → to → ... → from = cycle).
    pub fn would_create_cycle(&self, from_id: u32, to_id: u32) -> bool {
        let from_idx = match self.find_class_index(from_id) {
            Some(i) => i,
            None => return false,
        };
        let to_idx = match self.find_class_index(to_id) {
            Some(i) => i,
            None => return false,
        };

        if from_idx == to_idx {
            return true; // Self-loop.
        }

        // DFS from to_idx looking for from_idx.
        let mut visited = 0u64; // Bitmask of visited nodes.
        let mut stack = [0usize; MAX_DFS_DEPTH];
        let mut stack_top = 0usize;

        stack[stack_top] = to_idx;
        stack_top += 1;
        visited |= 1u64 << to_idx;

        while stack_top > 0 {
            stack_top -= 1;
            let current = stack[stack_top];

            let neighbors = self.adjacency[current];
            let mut remaining = neighbors & !visited;

            while remaining != 0 {
                let next = remaining.trailing_zeros() as usize;
                remaining &= remaining - 1; // Clear lowest set bit.

                if next == from_idx {
                    return true; // Cycle found.
                }
                if next < self.class_count as usize && stack_top < MAX_DFS_DEPTH {
                    visited |= 1u64 << next;
                    stack[stack_top] = next;
                    stack_top += 1;
                }
            }
        }

        false
    }

    /// Detect any cycle in the graph using DFS.
    ///
    /// Returns the class ID where a cycle was first detected,
    /// or `None` if no cycle exists.
    pub fn detect_cycle(&self) -> Option<u32> {
        let count = self.class_count as usize;
        // For each unvisited node, perform DFS.
        let mut global_visited = 0u64;

        for start in 0..count {
            if (global_visited & (1u64 << start)) != 0 {
                continue;
            }

            // DFS with "in current path" tracking.
            let mut in_path = 0u64;
            let mut stack = [0usize; MAX_DFS_DEPTH];
            let mut stack_top = 0usize;

            stack[stack_top] = start;
            stack_top += 1;
            in_path |= 1u64 << start;
            global_visited |= 1u64 << start;

            while stack_top > 0 {
                stack_top -= 1;
                let current = stack[stack_top];

                let neighbors = self.adjacency[current];
                let mut remaining = neighbors;

                while remaining != 0 {
                    let next = remaining.trailing_zeros() as usize;
                    remaining &= remaining - 1;

                    if next >= count {
                        continue;
                    }

                    if (in_path & (1u64 << next)) != 0 {
                        // Cycle detected.
                        return Some(self.classes[next].id);
                    }

                    if (global_visited & (1u64 << next)) == 0 {
                        global_visited |= 1u64 << next;
                        in_path |= 1u64 << next;
                        stack[stack_top] = next;
                        stack_top += 1;
                        if stack_top >= MAX_DFS_DEPTH {
                            break;
                        }
                    }
                }
            }
        }

        None
    }
}

impl Default for LockGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuHeldStack
// ══════════════════════════════════════════════════════════════

/// Per-CPU stack of currently held locks.
#[derive(Clone, Copy)]
pub struct PerCpuHeldStack {
    /// Lock instances currently held, ordered by acquisition time.
    pub held: [LockInstance; MAX_HELD_DEPTH],
    /// Current nesting depth (number of held locks).
    pub depth: u8,
}

impl PerCpuHeldStack {
    /// Create an empty held stack.
    pub const fn new() -> Self {
        Self {
            held: [const { LockInstance::new() }; MAX_HELD_DEPTH],
            depth: 0,
        }
    }

    /// Push a lock acquisition onto the stack.
    pub fn push(&mut self, instance: LockInstance) -> Result<()> {
        if self.depth as usize >= MAX_HELD_DEPTH {
            return Err(Error::OutOfMemory);
        }
        self.held[self.depth as usize] = instance;
        self.depth += 1;
        Ok(())
    }

    /// Pop the most recently acquired lock.
    pub fn pop(&mut self) -> Result<LockInstance> {
        if self.depth == 0 {
            return Err(Error::InvalidArgument);
        }
        self.depth -= 1;
        let instance = self.held[self.depth as usize];
        self.held[self.depth as usize] = LockInstance::new();
        Ok(instance)
    }

    /// Remove a specific lock class from the stack (out-of-order release).
    pub fn remove(&mut self, class_id: u32) -> Result<LockInstance> {
        let pos = self.held[..self.depth as usize]
            .iter()
            .position(|h| h.valid && h.class_id == class_id);
        match pos {
            Some(idx) => {
                let instance = self.held[idx];
                // Shift remaining entries down.
                let end = self.depth as usize - 1;
                for i in idx..end {
                    self.held[i] = self.held[i + 1];
                }
                self.held[end] = LockInstance::new();
                self.depth -= 1;
                Ok(instance)
            }
            None => Err(Error::NotFound),
        }
    }

    /// Check if a lock class is currently held.
    pub fn is_held(&self, class_id: u32) -> bool {
        self.held[..self.depth as usize]
            .iter()
            .any(|h| h.valid && h.class_id == class_id)
    }

    /// Get the topmost held lock class ID.
    pub fn top_class(&self) -> Option<u32> {
        if self.depth == 0 {
            None
        } else {
            Some(self.held[self.depth as usize - 1].class_id)
        }
    }
}

impl Default for PerCpuHeldStack {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// LockValidatorStats
// ══════════════════════════════════════════════════════════════

/// Global statistics for the lock validator.
#[derive(Clone, Copy)]
pub struct LockValidatorStats {
    /// Total lock acquisitions validated.
    pub acquires: u64,
    /// Total lock releases validated.
    pub releases: u64,
    /// Total ordering violations detected.
    pub violations: u64,
    /// Total deadlocks detected.
    pub deadlocks_detected: u64,
    /// Total double-acquire violations.
    pub double_acquires: u64,
    /// Total lock classes registered.
    pub classes_registered: u32,
    /// Maximum nesting depth observed.
    pub max_depth_observed: u8,
}

impl LockValidatorStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            acquires: 0,
            releases: 0,
            violations: 0,
            deadlocks_detected: 0,
            double_acquires: 0,
            classes_registered: 0,
            max_depth_observed: 0,
        }
    }
}

impl Default for LockValidatorStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// LockValidator
// ══════════════════════════════════════════════════════════════

/// Kernel lock validator — enforces lock ordering and detects
/// potential deadlocks.
pub struct LockValidator {
    /// Lock dependency graph.
    pub graph: LockGraph,
    /// Per-CPU held lock stacks.
    pub per_cpu: [PerCpuHeldStack; MAX_CPUS],
    /// Global statistics.
    pub stats: LockValidatorStats,
    /// Whether the validator is enabled.
    pub enabled: bool,
    /// Violation log (circular buffer of recent violations).
    pub violations: [Option<LockViolation>; 32],
    /// Next write position in the violation log.
    pub violation_idx: usize,
}

impl LockValidator {
    /// Create a new lock validator.
    pub const fn new() -> Self {
        Self {
            graph: LockGraph::new(),
            per_cpu: [const { PerCpuHeldStack::new() }; MAX_CPUS],
            stats: LockValidatorStats::new(),
            enabled: false,
            violations: [None; 32],
            violation_idx: 0,
        }
    }

    /// Initialize and enable the validator.
    pub fn init(&mut self) -> Result<()> {
        self.enabled = true;
        Ok(())
    }

    /// Register a new lock class.
    pub fn register_class(&mut self, id: u32, name: &[u8], depth_limit: u8) -> Result<()> {
        self.graph.register_class(id, name, depth_limit)?;
        self.stats.classes_registered += 1;
        Ok(())
    }

    /// Validate and record a lock acquisition.
    ///
    /// Returns `Ok(())` if the acquisition is valid, or
    /// `Err(Error::Busy)` with a recorded `LockViolation` if
    /// it violates ordering constraints.
    pub fn acquire(
        &mut self,
        class_id: u32,
        cpu: u32,
        pid: u64,
        tick: u64,
        is_read: bool,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.stats.acquires += 1;

        // Check for double acquire.
        if self.per_cpu[cpu as usize].is_held(class_id) {
            self.record_violation(LockViolation::DoubleAcquire(class_id));
            self.stats.double_acquires += 1;
            self.stats.violations += 1;
            return Err(Error::Busy);
        }

        // Check ordering against all currently held locks.
        let depth = self.per_cpu[cpu as usize].depth;
        for i in 0..depth as usize {
            let held = &self.per_cpu[cpu as usize].held[i];
            if !held.valid {
                continue;
            }
            let held_id = held.class_id;

            // Check if there's a reverse edge (class_id → held_id)
            // which would mean class_id should be acquired BEFORE held_id,
            // but held_id is already held.
            if self.graph.has_edge(class_id, held_id) {
                self.record_violation(LockViolation::Ordering {
                    expected_first: class_id,
                    actual_first: held_id,
                });
                self.stats.violations += 1;
                return Err(Error::Busy);
            }

            // Add edge: held_id → class_id (held_id was acquired first).
            // Check for cycle before adding.
            if self.graph.would_create_cycle(held_id, class_id) {
                self.record_violation(LockViolation::Deadlock(class_id));
                self.stats.deadlocks_detected += 1;
                self.stats.violations += 1;
                return Err(Error::Busy);
            }

            let _ = self.graph.add_edge(held_id, class_id, tick);
        }

        // Push onto held stack.
        let instance = LockInstance {
            class_id,
            acquired_tick: tick,
            cpu,
            owner_pid: pid,
            is_read,
            valid: true,
        };
        self.per_cpu[cpu as usize].push(instance)?;

        // Track max depth.
        let new_depth = self.per_cpu[cpu as usize].depth;
        if new_depth > self.stats.max_depth_observed {
            self.stats.max_depth_observed = new_depth;
        }

        // Update class stats.
        if let Some(idx) = self.graph.find_class_index(class_id) {
            self.graph.classes[idx].acquisition_count += 1;
        }

        Ok(())
    }

    /// Record a lock release.
    pub fn release(&mut self, class_id: u32, cpu: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.stats.releases += 1;
        self.per_cpu[cpu as usize].remove(class_id)?;
        Ok(())
    }

    /// Check ordering constraints without actually acquiring.
    ///
    /// Returns the violation that would occur, or `None` if safe.
    pub fn check_order(&self, class_id: u32, cpu: u32) -> Option<LockViolation> {
        if !self.enabled || cpu as usize >= MAX_CPUS {
            return None;
        }

        // Check double acquire.
        if self.per_cpu[cpu as usize].is_held(class_id) {
            return Some(LockViolation::DoubleAcquire(class_id));
        }

        // Check ordering.
        let depth = self.per_cpu[cpu as usize].depth;
        for i in 0..depth as usize {
            let held = &self.per_cpu[cpu as usize].held[i];
            if !held.valid {
                continue;
            }
            let held_id = held.class_id;

            if self.graph.has_edge(class_id, held_id) {
                return Some(LockViolation::Ordering {
                    expected_first: class_id,
                    actual_first: held_id,
                });
            }

            if self.graph.would_create_cycle(held_id, class_id) {
                return Some(LockViolation::Deadlock(class_id));
            }
        }

        None
    }

    /// Get the current held stack depth for a CPU.
    pub fn held_depth(&self, cpu: u32) -> u8 {
        if cpu as usize >= MAX_CPUS {
            return 0;
        }
        self.per_cpu[cpu as usize].depth
    }

    /// Get statistics.
    pub fn get_stats(&self) -> &LockValidatorStats {
        &self.stats
    }

    /// Get recent violations.
    pub fn recent_violations(&self) -> &[Option<LockViolation>; 32] {
        &self.violations
    }

    /// Reset all statistics and violation log.
    pub fn reset_stats(&mut self) {
        self.stats = LockValidatorStats::new();
        self.violations = [None; 32];
        self.violation_idx = 0;
    }

    /// Enable or disable the validator.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Record a violation in the circular log.
    fn record_violation(&mut self, violation: LockViolation) {
        self.violations[self.violation_idx] = Some(violation);
        self.violation_idx = (self.violation_idx + 1) % self.violations.len();
    }
}

impl Default for LockValidator {
    fn default() -> Self {
        Self::new()
    }
}
