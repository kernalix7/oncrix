// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lock dependency validator (lockdep).
//!
//! Runtime lock ordering validation to detect potential deadlocks
//! before they occur. Modeled after Linux's lockdep subsystem
//! (`kernel/locking/lockdep.c`).
//!
//! # Design
//!
//! Every lock type is registered as a **lock class** ([`LockClass`]).
//! When a lock is acquired, its class is pushed onto the per-CPU
//! **held-lock stack** ([`HeldLockStack`]). The validator records
//! ordering edges in a **dependency graph** ([`DepGraph`]) and runs
//! cycle detection to flag potential deadlocks.
//!
//! # Components
//!
//! - [`LockClass`] — metadata for a lock type (name, flags)
//! - [`LockClassRegistry`] — global table of registered classes
//! - [`DepGraph`] — adjacency-matrix dependency graph with cycle
//!   detection (DFS-based)
//! - [`HeldLockStack`] — per-CPU stack of currently held locks
//! - [`LockdepViolation`] — describes a detected ordering violation
//! - [`Lockdep`] — top-level validator tying all components together
//!
//! # Invariants
//!
//! - All structures use fixed-size arrays (no heap in hot paths).
//! - Lock acquire/release is O(depth) where depth is the held-lock
//!   count (typically small).
//! - Cycle detection is O(N^2) in the number of lock classes.
//!
//! Reference: Linux `kernel/locking/lockdep.c`,
//! `include/linux/lockdep.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of distinct lock classes.
const MAX_LOCK_CLASSES: usize = 128;

/// Maximum depth of the held-lock stack per CPU.
const MAX_HELD_LOCKS: usize = 48;

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum lock name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Maximum recorded violations before reporting stops.
const MAX_VIOLATIONS: usize = 32;

// ── LockFlags ─────────────────────────────────────────────────────

/// Bitfield flags describing lock properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockFlags(u32);

impl LockFlags {
    /// No special properties.
    pub const NONE: Self = Self(0);
    /// Lock may be acquired in interrupt context.
    pub const IRQ_SAFE: Self = Self(1 << 0);
    /// Lock may be acquired in softirq context.
    pub const SOFTIRQ_SAFE: Self = Self(1 << 1);
    /// Lock is a reader-writer lock (read side).
    pub const READ_LOCK: Self = Self(1 << 2);
    /// Lock is a reader-writer lock (write side).
    pub const WRITE_LOCK: Self = Self(1 << 3);
    /// Lock allows recursive acquisition.
    pub const RECURSIVE: Self = Self(1 << 4);

    /// Create flags from a raw u32.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Test whether a specific flag bit is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

// ── LockClass ─────────────────────────────────────────────────────

/// Metadata describing a single lock type.
///
/// Each unique lock (by source location or explicit registration)
/// gets one class entry. Multiple instances of the same lock share
/// the same class id.
#[derive(Debug, Clone, Copy)]
pub struct LockClass {
    /// Unique class identifier (index into the class table).
    pub id: u16,
    /// Human-readable name (truncated to [`MAX_NAME_LEN`]).
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the valid portion of `name`.
    pub name_len: usize,
    /// Lock property flags.
    pub flags: LockFlags,
    /// How many times this class has been acquired (global).
    pub acquire_count: u64,
    /// How many contention events have been observed.
    pub contention_count: u64,
    /// Whether this class slot is in use.
    pub active: bool,
}

impl LockClass {
    /// Create an empty, inactive class.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            flags: LockFlags::NONE,
            acquire_count: 0,
            contention_count: 0,
            active: false,
        }
    }
}

// ── LockClassRegistry ─────────────────────────────────────────────

/// Global registry of lock classes.
pub struct LockClassRegistry {
    /// Class table (indexed by class id).
    classes: [LockClass; MAX_LOCK_CLASSES],
    /// Number of registered classes.
    count: usize,
}

impl LockClassRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            classes: [LockClass::empty(); MAX_LOCK_CLASSES],
            count: 0,
        }
    }

    /// Register a new lock class, returning its id.
    pub fn register(&mut self, name: &[u8], flags: LockFlags) -> Result<u16> {
        if self.count >= MAX_LOCK_CLASSES {
            return Err(Error::OutOfMemory);
        }
        let id = self.count as u16;
        let mut entry = LockClass::empty();
        entry.id = id;
        let copy_len = name.len().min(MAX_NAME_LEN);
        entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
        entry.name_len = copy_len;
        entry.flags = flags;
        entry.active = true;
        self.classes[self.count] = entry;
        self.count += 1;
        Ok(id)
    }

    /// Look up a class by id.
    pub fn get(&self, id: u16) -> Result<&LockClass> {
        let idx = id as usize;
        if idx >= self.count || !self.classes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.classes[idx])
    }

    /// Look up a class mutably by id.
    pub fn get_mut(&mut self, id: u16) -> Result<&mut LockClass> {
        let idx = id as usize;
        if idx >= self.count || !self.classes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.classes[idx])
    }

    /// Number of registered classes.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ── DepGraph ──────────────────────────────────────────────────────

/// Adjacency-matrix dependency graph for lock ordering.
///
/// An edge `(A, B)` means "class A was held when class B was
/// acquired." If a cycle exists, a deadlock is possible.
pub struct DepGraph {
    /// `edges[a][b]` is true if class `a` was held when `b` was
    /// acquired.
    edges: [[bool; MAX_LOCK_CLASSES]; MAX_LOCK_CLASSES],
    /// Total number of edges recorded.
    edge_count: usize,
}

impl DepGraph {
    /// Create an empty graph.
    pub const fn new() -> Self {
        Self {
            edges: [[false; MAX_LOCK_CLASSES]; MAX_LOCK_CLASSES],
            edge_count: 0,
        }
    }

    /// Record a dependency edge: `held` was already held when
    /// `acquired` was taken.
    ///
    /// Returns `true` if this is a new edge.
    pub fn add_edge(&mut self, held: u16, acquired: u16) -> bool {
        let h = held as usize;
        let a = acquired as usize;
        if h >= MAX_LOCK_CLASSES || a >= MAX_LOCK_CLASSES {
            return false;
        }
        if self.edges[h][a] {
            return false;
        }
        self.edges[h][a] = true;
        self.edge_count += 1;
        true
    }

    /// Check whether adding `(held, acquired)` would create a cycle.
    ///
    /// Uses iterative DFS from `acquired` to see if `held` is
    /// reachable (which would mean `held -> ... -> acquired -> held`).
    pub fn would_cycle(&self, held: u16, acquired: u16, num_classes: usize) -> bool {
        if held == acquired {
            return true;
        }
        let target = held as usize;
        let start = acquired as usize;
        if start >= num_classes || target >= num_classes {
            return false;
        }

        // Iterative DFS using a fixed-size stack.
        let mut visited = [false; MAX_LOCK_CLASSES];
        let mut stack = [0usize; MAX_LOCK_CLASSES];
        let mut sp: usize = 0;

        stack[sp] = start;
        sp += 1;
        visited[start] = true;

        while sp > 0 {
            sp -= 1;
            let node = stack[sp];

            for next in 0..num_classes {
                if !self.edges[node][next] || visited[next] {
                    continue;
                }
                if next == target {
                    return true;
                }
                visited[next] = true;
                if sp < MAX_LOCK_CLASSES {
                    stack[sp] = next;
                    sp += 1;
                }
            }
        }
        false
    }

    /// Total recorded edges.
    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }
}

// ── HeldLock ──────────────────────────────────────────────────────

/// A single entry on the held-lock stack.
#[derive(Debug, Clone, Copy)]
pub struct HeldLock {
    /// Class id of the held lock.
    pub class_id: u16,
    /// Nesting depth (for recursive locks).
    pub depth: u16,
    /// Timestamp (tick count) when the lock was acquired.
    pub acquire_tick: u64,
}

impl HeldLock {
    /// Empty held-lock entry.
    const fn empty() -> Self {
        Self {
            class_id: 0,
            depth: 0,
            acquire_tick: 0,
        }
    }
}

// ── HeldLockStack ─────────────────────────────────────────────────

/// Per-CPU stack of currently held locks.
pub struct HeldLockStack {
    /// Stack storage.
    locks: [HeldLock; MAX_HELD_LOCKS],
    /// Current stack pointer (number of held locks).
    top: usize,
}

impl HeldLockStack {
    /// Create an empty stack.
    pub const fn new() -> Self {
        Self {
            locks: [HeldLock::empty(); MAX_HELD_LOCKS],
            top: 0,
        }
    }

    /// Push a lock acquisition. Returns the stack depth.
    pub fn push(&mut self, class_id: u16, tick: u64) -> Result<usize> {
        if self.top >= MAX_HELD_LOCKS {
            return Err(Error::OutOfMemory);
        }
        self.locks[self.top] = HeldLock {
            class_id,
            depth: 1,
            acquire_tick: tick,
        };
        self.top += 1;
        Ok(self.top)
    }

    /// Pop the most recent lock of the given class.
    ///
    /// Locks are not necessarily released in LIFO order (e.g., with
    /// trylock), so we scan from the top.
    pub fn pop(&mut self, class_id: u16) -> Result<HeldLock> {
        let pos = self.locks[..self.top]
            .iter()
            .rposition(|l| l.class_id == class_id);
        match pos {
            Some(idx) => {
                let entry = self.locks[idx];
                // Shift remaining entries down.
                let remaining = self.top - idx - 1;
                if remaining > 0 {
                    self.locks.copy_within(idx + 1..self.top, idx);
                }
                self.top -= 1;
                Ok(entry)
            }
            None => Err(Error::NotFound),
        }
    }

    /// Iterate over currently held locks (bottom to top).
    pub fn held(&self) -> &[HeldLock] {
        &self.locks[..self.top]
    }

    /// Number of currently held locks.
    pub const fn depth(&self) -> usize {
        self.top
    }

    /// Whether the stack is empty.
    pub const fn is_empty(&self) -> bool {
        self.top == 0
    }
}

// ── ViolationType ─────────────────────────────────────────────────

/// Kinds of lock ordering violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViolationType {
    /// Two classes form a potential deadlock cycle.
    #[default]
    PotentialDeadlock,
    /// A lock was acquired in IRQ context that is not IRQ-safe.
    IrqContextUnsafe,
    /// Lock acquisition exceeds maximum nesting depth.
    ExcessiveNesting,
    /// A non-recursive lock was acquired while already held.
    RecursiveAcquire,
}

// ── LockdepViolation ─────────────────────────────────────────────

/// A recorded lock ordering violation.
#[derive(Debug, Clone, Copy)]
pub struct LockdepViolation {
    /// Type of violation.
    pub kind: ViolationType,
    /// Class id of the lock already held.
    pub held_class: u16,
    /// Class id of the lock being acquired.
    pub acquired_class: u16,
    /// CPU on which the violation occurred.
    pub cpu: u16,
    /// Tick count when the violation was detected.
    pub tick: u64,
    /// Whether this entry is populated.
    pub valid: bool,
}

impl LockdepViolation {
    /// Empty violation entry.
    const fn empty() -> Self {
        Self {
            kind: ViolationType::PotentialDeadlock,
            held_class: 0,
            acquired_class: 0,
            cpu: 0,
            tick: 0,
            valid: false,
        }
    }
}

// ── LockdepStats ──────────────────────────────────────────────────

/// Runtime statistics for the lockdep validator.
#[derive(Debug, Clone, Copy)]
pub struct LockdepStats {
    /// Total lock acquisitions validated.
    pub total_acquires: u64,
    /// Total lock releases validated.
    pub total_releases: u64,
    /// Total new dependency edges discovered.
    pub edges_added: u64,
    /// Total cycle checks performed.
    pub cycle_checks: u64,
    /// Total violations detected.
    pub violations: u64,
}

impl LockdepStats {
    /// Zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_acquires: 0,
            total_releases: 0,
            edges_added: 0,
            cycle_checks: 0,
            violations: 0,
        }
    }
}

// ── Lockdep ───────────────────────────────────────────────────────

/// Top-level lock dependency validator.
///
/// Combines the class registry, dependency graph, per-CPU held-lock
/// stacks, and violation log into a single validation engine.
pub struct Lockdep {
    /// Registry of all lock classes.
    registry: LockClassRegistry,
    /// Dependency graph (adjacency matrix).
    graph: DepGraph,
    /// Per-CPU held-lock stacks.
    held: [HeldLockStack; MAX_CPUS],
    /// Recorded violations.
    violations: [LockdepViolation; MAX_VIOLATIONS],
    /// Number of violations recorded.
    violation_count: usize,
    /// Whether the validator is enabled.
    enabled: bool,
    /// Current tick counter (for timestamps).
    tick: u64,
    /// Aggregate statistics.
    stats: LockdepStats,
}

impl Lockdep {
    /// Create a new lockdep validator.
    pub const fn new() -> Self {
        const EMPTY_STACK: HeldLockStack = HeldLockStack::new();
        Self {
            registry: LockClassRegistry::new(),
            graph: DepGraph::new(),
            held: [EMPTY_STACK; MAX_CPUS],
            violations: [LockdepViolation::empty(); MAX_VIOLATIONS],
            violation_count: 0,
            enabled: true,
            tick: 0,
            stats: LockdepStats::new(),
        }
    }

    /// Register a lock class. Returns the class id.
    pub fn register_class(&mut self, name: &[u8], flags: LockFlags) -> Result<u16> {
        self.registry.register(name, flags)
    }

    /// Validate and record a lock acquisition on a given CPU.
    ///
    /// Checks for:
    /// 1. Recursive acquisition of non-recursive locks.
    /// 2. Potential deadlock cycles in the dependency graph.
    /// 3. IRQ-safety violations.
    pub fn acquire(&mut self, cpu: u16, class_id: u16, in_irq: bool) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        // Validate class exists.
        let flags = self.registry.get(class_id)?.flags;

        self.tick = self.tick.wrapping_add(1);
        self.stats.total_acquires += 1;

        // Check IRQ safety.
        if in_irq && !flags.contains(LockFlags::IRQ_SAFE) {
            self.record_violation(ViolationType::IrqContextUnsafe, 0, class_id, cpu);
        }

        // Check recursive acquisition.
        let stack = &self.held[cpu_idx];
        if stack.held().iter().any(|l| l.class_id == class_id) {
            if !flags.contains(LockFlags::RECURSIVE) {
                self.record_violation(ViolationType::RecursiveAcquire, class_id, class_id, cpu);
                return Err(Error::Busy);
            }
        }

        // Collect held class IDs to avoid borrow conflict with self methods.
        let num_classes = self.registry.count();
        let mut held_ids = [0u16; MAX_HELD_LOCKS];
        let mut held_count = 0;
        for entry in self.held[cpu_idx].held() {
            if held_count < MAX_HELD_LOCKS {
                held_ids[held_count] = entry.class_id;
                held_count += 1;
            }
        }

        // Add dependency edges and check for cycles.
        for i in 0..held_count {
            let held_class = held_ids[i];
            self.stats.cycle_checks += 1;
            if self.graph.would_cycle(held_class, class_id, num_classes) {
                self.record_violation(ViolationType::PotentialDeadlock, held_class, class_id, cpu);
            }
            if self.graph.add_edge(held_class, class_id) {
                self.stats.edges_added += 1;
            }
        }

        // Push onto held stack.
        self.held[cpu_idx].push(class_id, self.tick)?;

        // Update class stats.
        if let Ok(cls) = self.registry.get_mut(class_id) {
            cls.acquire_count += 1;
        }
        Ok(())
    }

    /// Record a lock release on a given CPU.
    pub fn release(&mut self, cpu: u16, class_id: u16) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_releases += 1;
        self.held[cpu_idx].pop(class_id)?;
        Ok(())
    }

    /// Enable or disable the validator at runtime.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the validator is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return recorded violations.
    pub fn violations(&self) -> &[LockdepViolation] {
        &self.violations[..self.violation_count]
    }

    /// Number of recorded violations.
    pub const fn violation_count(&self) -> usize {
        self.violation_count
    }

    /// Return aggregate statistics.
    pub const fn stats(&self) -> &LockdepStats {
        &self.stats
    }

    /// Number of registered lock classes.
    pub const fn class_count(&self) -> usize {
        self.registry.count()
    }

    /// Number of dependency edges.
    pub const fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Current held-lock depth on a CPU.
    pub fn held_depth(&self, cpu: u16) -> usize {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return 0;
        }
        self.held[idx].depth()
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Record a violation into the log.
    fn record_violation(
        &mut self,
        kind: ViolationType,
        held_class: u16,
        acquired_class: u16,
        cpu: u16,
    ) {
        if self.violation_count >= MAX_VIOLATIONS {
            return;
        }
        self.violations[self.violation_count] = LockdepViolation {
            kind,
            held_class,
            acquired_class,
            cpu,
            tick: self.tick,
            valid: true,
        };
        self.violation_count += 1;
        self.stats.violations += 1;
    }
}
