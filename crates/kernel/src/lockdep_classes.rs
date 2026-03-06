// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lockdep lock class management.
//!
//! Tracks lock classes for the lock dependency validator. Each
//! unique lock type (e.g., `inode->i_rwsem`, `rq->lock`) is assigned
//! a class. The validator detects potential deadlocks by recording
//! and verifying the ordering of class acquisitions.
//!
//! # Architecture
//!
//! ```text
//! LockClassManager
//!  ├── classes[MAX_CLASSES]
//!  │    ├── id, name, subclass
//!  │    ├── dep_before[MAX_DEPS]  (classes taken before this)
//!  │    └── dep_after[MAX_DEPS]   (classes taken after this)
//!  └── stats: LockClassStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/locking/lockdep.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum lock classes.
const MAX_CLASSES: usize = 256;

/// Maximum dependency edges per class.
const MAX_DEPS: usize = 16;

/// Maximum class name length.
const MAX_NAME_LEN: usize = 48;

// ══════════════════════════════════════════════════════════════
// LockClass
// ══════════════════════════════════════════════════════════════

/// A lock class represents a unique lock type.
#[derive(Clone, Copy)]
pub struct LockClass {
    /// Class identifier.
    pub id: u32,
    /// Lock class name (zero-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Subclass (for nested locks of the same type).
    pub subclass: u8,
    /// Classes that must be held before acquiring this one.
    pub dep_before: [u32; MAX_DEPS],
    /// Number of "before" dependencies.
    pub nr_before: u8,
    /// Classes that may be acquired while holding this one.
    pub dep_after: [u32; MAX_DEPS],
    /// Number of "after" dependencies.
    pub nr_after: u8,
    /// Total acquisitions of this class.
    pub acquire_count: u64,
    /// Total contentions on this class.
    pub contention_count: u64,
    /// Whether this class is active.
    pub active: bool,
}

impl LockClass {
    /// Create an inactive class.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            subclass: 0,
            dep_before: [0u32; MAX_DEPS],
            nr_before: 0,
            dep_after: [0u32; MAX_DEPS],
            nr_after: 0,
            acquire_count: 0,
            contention_count: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// LockClassStats
// ══════════════════════════════════════════════════════════════

/// Lock class subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct LockClassStats {
    /// Total classes registered.
    pub total_classes: u64,
    /// Total dependency edges recorded.
    pub total_deps: u64,
    /// Total deadlock warnings.
    pub deadlock_warnings: u64,
    /// Total circular dependency detections.
    pub circular_deps: u64,
}

impl LockClassStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_classes: 0,
            total_deps: 0,
            deadlock_warnings: 0,
            circular_deps: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// LockClassManager
// ══════════════════════════════════════════════════════════════

/// Manages lock classes and their dependency graph.
pub struct LockClassManager {
    /// Lock class table.
    classes: [LockClass; MAX_CLASSES],
    /// Next class ID.
    next_id: u32,
    /// Statistics.
    stats: LockClassStats,
    /// Whether lockdep is enabled.
    enabled: bool,
}

impl LockClassManager {
    /// Create a new lock class manager.
    pub const fn new() -> Self {
        Self {
            classes: [const { LockClass::empty() }; MAX_CLASSES],
            next_id: 1,
            stats: LockClassStats::new(),
            enabled: true,
        }
    }

    /// Register a new lock class.
    pub fn register_class(&mut self, name: &[u8], subclass: u8) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .classes
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        let cls = &mut self.classes[slot];
        cls.id = id;
        cls.name[..name.len()].copy_from_slice(name);
        cls.name_len = name.len();
        cls.subclass = subclass;
        cls.active = true;
        self.stats.total_classes += 1;
        Ok(id)
    }

    /// Record a lock acquisition order: `held_class` was held
    /// when `acquired_class` was acquired.
    ///
    /// Returns `Err(InvalidArgument)` if a circular dependency
    /// is detected.
    pub fn record_dependency(&mut self, held_class: u32, acquired_class: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        // Check for direct circular dependency.
        if self.has_dep_after(acquired_class, held_class) {
            self.stats.circular_deps += 1;
            self.stats.deadlock_warnings += 1;
            return Err(Error::InvalidArgument);
        }

        // Add forward edge: held → acquired.
        let held_slot = self.find_class(held_class)?;
        let nr = self.classes[held_slot].nr_after as usize;
        if nr < MAX_DEPS {
            // Avoid duplicate.
            let already = self.classes[held_slot].dep_after[..nr]
                .iter()
                .any(|&d| d == acquired_class);
            if !already {
                self.classes[held_slot].dep_after[nr] = acquired_class;
                self.classes[held_slot].nr_after += 1;
                self.stats.total_deps += 1;
            }
        }

        // Add backward edge: acquired ← held.
        let acq_slot = self.find_class(acquired_class)?;
        let nr = self.classes[acq_slot].nr_before as usize;
        if nr < MAX_DEPS {
            let already = self.classes[acq_slot].dep_before[..nr]
                .iter()
                .any(|&d| d == held_class);
            if !already {
                self.classes[acq_slot].dep_before[nr] = held_class;
                self.classes[acq_slot].nr_before += 1;
            }
        }

        Ok(())
    }

    /// Record an acquisition of a class (for statistics).
    pub fn record_acquire(&mut self, class_id: u32) -> Result<()> {
        let slot = self.find_class(class_id)?;
        self.classes[slot].acquire_count += 1;
        Ok(())
    }

    /// Record a contention on a class.
    pub fn record_contention(&mut self, class_id: u32) -> Result<()> {
        let slot = self.find_class(class_id)?;
        self.classes[slot].contention_count += 1;
        Ok(())
    }

    /// Return class info.
    pub fn get_class(&self, class_id: u32) -> Result<&LockClass> {
        let slot = self.find_class(class_id)?;
        Ok(&self.classes[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> LockClassStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_class(&self, id: u32) -> Result<usize> {
        self.classes
            .iter()
            .position(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Check if `class_id` has `target` in its dep_after list.
    fn has_dep_after(&self, class_id: u32, target: u32) -> bool {
        if let Some(slot) = self
            .classes
            .iter()
            .position(|c| c.active && c.id == class_id)
        {
            let nr = self.classes[slot].nr_after as usize;
            self.classes[slot].dep_after[..nr]
                .iter()
                .any(|&d| d == target)
        } else {
            false
        }
    }
}
