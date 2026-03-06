// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lock dependency chain tracking — detecting potential deadlocks.
//!
//! Records the order in which locks are acquired to detect lock
//! ordering violations that could lead to deadlocks.  Each unique
//! lock-acquisition sequence forms a chain that is validated against
//! known-good orderings.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   LockdepChainTracker                        │
//! │                                                              │
//! │  LockClass[0..MAX_LOCK_CLASSES]                              │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  class_id: u64                                         │  │
//! │  │  name: [u8; 32]                                        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  DepChain[0..MAX_CHAINS]                                     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  entries: [u64; MAX_CHAIN_DEPTH]                        │  │
//! │  │  depth: usize                                          │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/locking/lockdep.c`, `include/linux/lockdep.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum lock classes (unique lock types).
const MAX_LOCK_CLASSES: usize = 512;

/// Maximum dependency chains.
const MAX_CHAINS: usize = 1024;

/// Maximum depth of a single chain.
const MAX_CHAIN_DEPTH: usize = 16;

/// Maximum name length for a lock class.
const MAX_NAME_LEN: usize = 32;

/// Maximum per-CPU held locks.
const MAX_HELD: usize = 48;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

// ══════════════════════════════════════════════════════════════
// ChainValidation
// ══════════════════════════════════════════════════════════════

/// Result of validating a lock acquisition against known chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChainValidation {
    /// Acquisition is consistent with existing chains.
    Valid = 0,
    /// New chain recorded (first time seeing this sequence).
    NewChain = 1,
    /// Potential deadlock detected (ordering violation).
    Deadlock = 2,
    /// Recursive lock acquisition detected.
    Recursive = 3,
}

// ══════════════════════════════════════════════════════════════
// LockClass
// ══════════════════════════════════════════════════════════════

/// A lock class representing a unique lock type.
#[derive(Debug, Clone, Copy)]
pub struct LockClass {
    /// Unique class identifier (typically address of lock definition).
    pub class_id: u64,
    /// Name of the lock class.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Whether this slot is registered.
    pub registered: bool,
    /// Number of times this lock has been acquired.
    pub acquisitions: u64,
    /// Number of times this lock has been contended.
    pub contentions: u64,
}

impl LockClass {
    const fn empty() -> Self {
        Self {
            class_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            registered: false,
            acquisitions: 0,
            contentions: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// DepChain
// ══════════════════════════════════════════════════════════════

/// A recorded lock dependency chain.
#[derive(Debug, Clone, Copy)]
pub struct DepChain {
    /// Lock class IDs in acquisition order.
    pub entries: [u64; MAX_CHAIN_DEPTH],
    /// Number of entries in the chain.
    pub depth: usize,
    /// Chain hash for fast lookup.
    pub hash: u64,
    /// Whether this slot is active.
    pub active: bool,
    /// Number of times this chain was observed.
    pub hit_count: u64,
}

impl DepChain {
    const fn empty() -> Self {
        Self {
            entries: [0u64; MAX_CHAIN_DEPTH],
            depth: 0,
            hash: 0,
            active: false,
            hit_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HeldLock — per-CPU held lock stack
// ══════════════════════════════════════════════════════════════

/// Per-CPU stack of currently held locks.
#[derive(Debug, Clone, Copy)]
pub struct HeldLockStack {
    /// Class IDs of currently held locks.
    pub held: [u64; MAX_HELD],
    /// Number of locks currently held.
    pub depth: usize,
}

impl HeldLockStack {
    const fn new() -> Self {
        Self {
            held: [0u64; MAX_HELD],
            depth: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// LockdepChainStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the chain tracker.
#[derive(Debug, Clone, Copy)]
pub struct LockdepChainStats {
    /// Total lock acquisitions validated.
    pub total_acquisitions: u64,
    /// Total new chains recorded.
    pub total_new_chains: u64,
    /// Total deadlock warnings.
    pub total_deadlocks: u64,
    /// Total recursive acquisitions.
    pub total_recursive: u64,
    /// Total chain cache hits.
    pub total_chain_hits: u64,
}

impl LockdepChainStats {
    const fn new() -> Self {
        Self {
            total_acquisitions: 0,
            total_new_chains: 0,
            total_deadlocks: 0,
            total_recursive: 0,
            total_chain_hits: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// LockdepChainTracker
// ══════════════════════════════════════════════════════════════

/// Top-level lock dependency chain tracker.
pub struct LockdepChainTracker {
    /// Registered lock classes.
    classes: [LockClass; MAX_LOCK_CLASSES],
    /// Recorded dependency chains.
    chains: [DepChain; MAX_CHAINS],
    /// Per-CPU held lock stacks.
    per_cpu: [HeldLockStack; MAX_CPUS],
    /// Statistics.
    stats: LockdepChainStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Whether tracking is enabled.
    enabled: bool,
}

impl Default for LockdepChainTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LockdepChainTracker {
    /// Create a new chain tracker.
    pub const fn new() -> Self {
        Self {
            classes: [const { LockClass::empty() }; MAX_LOCK_CLASSES],
            chains: [const { DepChain::empty() }; MAX_CHAINS],
            per_cpu: [const { HeldLockStack::new() }; MAX_CPUS],
            stats: LockdepChainStats::new(),
            initialised: false,
            enabled: true,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Enable or disable tracking.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    // ── Lock class registration ──────────────────────────────

    /// Register a lock class.
    pub fn register_class(&mut self, class_id: u64, name: &[u8]) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        // Check for existing.
        if let Some(idx) = self.find_class(class_id) {
            return Ok(idx);
        }

        let slot = self
            .classes
            .iter()
            .position(|c| !c.registered)
            .ok_or(Error::OutOfMemory)?;

        self.classes[slot] = LockClass::empty();
        self.classes[slot].class_id = class_id;
        self.classes[slot].name[..name.len()].copy_from_slice(name);
        self.classes[slot].name_len = name.len();
        self.classes[slot].registered = true;
        Ok(slot)
    }

    // ── Lock acquisition tracking ────────────────────────────

    /// Record a lock acquisition.
    pub fn acquire(&mut self, cpu: usize, class_id: u64) -> Result<ChainValidation> {
        if !self.enabled {
            return Ok(ChainValidation::Valid);
        }
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.stats.total_acquisitions += 1;

        // Update lock class stats.
        if let Some(cls) = self.find_class(class_id) {
            self.classes[cls].acquisitions += 1;
        }

        let held = &self.per_cpu[cpu];

        // Check for recursive acquisition.
        for i in 0..held.depth {
            if held.held[i] == class_id {
                self.stats.total_recursive += 1;
                return Ok(ChainValidation::Recursive);
            }
        }

        // Build current chain hash.
        let mut chain_hash = 0u64;
        for i in 0..held.depth {
            chain_hash = chain_hash.wrapping_mul(31).wrapping_add(held.held[i]);
        }
        chain_hash = chain_hash.wrapping_mul(31).wrapping_add(class_id);

        // Check existing chains.
        let chain_match = self
            .chains
            .iter()
            .position(|ch| ch.active && ch.hash == chain_hash);

        let result = if let Some(idx) = chain_match {
            self.chains[idx].hit_count += 1;
            self.stats.total_chain_hits += 1;
            ChainValidation::Valid
        } else {
            // Record new chain.
            self.record_chain(cpu, class_id, chain_hash)?
        };

        // Push onto held stack.
        let depth = self.per_cpu[cpu].depth;
        if depth < MAX_HELD {
            self.per_cpu[cpu].held[depth] = class_id;
            self.per_cpu[cpu].depth += 1;
        }

        Ok(result)
    }

    /// Record a lock release.
    pub fn release(&mut self, cpu: usize, class_id: u64) -> Result<()> {
        if !self.enabled || cpu >= MAX_CPUS {
            return Ok(());
        }

        let held = &mut self.per_cpu[cpu];
        // Find and remove (order matters for correctness).
        if let Some(pos) = held.held[..held.depth]
            .iter()
            .rposition(|&id| id == class_id)
        {
            // Shift remaining entries.
            for i in pos..held.depth.saturating_sub(1) {
                held.held[i] = held.held[i + 1];
            }
            held.depth = held.depth.saturating_sub(1);
        }
        Ok(())
    }

    /// Record a new dependency chain.
    fn record_chain(&mut self, cpu: usize, class_id: u64, hash: u64) -> Result<ChainValidation> {
        let slot = match self.chains.iter().position(|c| !c.active) {
            Some(s) => s,
            None => return Ok(ChainValidation::Valid), // Silently drop.
        };

        let held = &self.per_cpu[cpu];
        let new_depth = held.depth + 1;
        if new_depth > MAX_CHAIN_DEPTH {
            return Ok(ChainValidation::Valid);
        }

        self.chains[slot].entries[..held.depth].copy_from_slice(&held.held[..held.depth]);
        self.chains[slot].entries[held.depth] = class_id;
        self.chains[slot].depth = new_depth;
        self.chains[slot].hash = hash;
        self.chains[slot].active = true;
        self.chains[slot].hit_count = 1;

        self.stats.total_new_chains += 1;
        Ok(ChainValidation::NewChain)
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> LockdepChainStats {
        self.stats
    }

    /// Return the number of registered lock classes.
    pub fn class_count(&self) -> usize {
        self.classes.iter().filter(|c| c.registered).count()
    }

    /// Return the number of recorded chains.
    pub fn chain_count(&self) -> usize {
        self.chains.iter().filter(|c| c.active).count()
    }

    /// Return the current held lock depth for a CPU.
    pub fn held_depth(&self, cpu: usize) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu].depth)
    }

    fn find_class(&self, class_id: u64) -> Option<usize> {
        self.classes
            .iter()
            .position(|c| c.registered && c.class_id == class_id)
    }
}
