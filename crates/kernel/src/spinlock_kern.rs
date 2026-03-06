// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Spinlock primitives.
//!
//! Provides busy-wait locks for short critical sections,
//! particularly in interrupt context where sleeping is
//! not allowed. Includes IRQ-safe variants that save and
//! restore interrupt state.
//!
//! # Design
//!
//! ```text
//!   +------------+
//!   | SpinLock   |
//!   |------------|
//!   | locked     |  (AtomicBool-like via bool for no_std)
//!   | owner      |
//!   | irq_saved  |
//!   +------------+
//!
//!   RawSpinLock — lower-level, no owner tracking.
//! ```
//!
//! # Variants
//!
//! - `lock()` / `unlock()` — basic spinlock.
//! - `trylock()` — non-blocking attempt.
//! - `lock_irqsave()` / `unlock_irqrestore()` — saves/restores
//!   interrupt flags.
//! - `lock_bh()` / `unlock_bh()` — disables/enables bottom halves
//!   (softirqs).
//!
//! # Reference
//!
//! Linux `include/linux/spinlock.h`,
//! `kernel/locking/spinlock.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum managed spinlocks.
const MAX_SPINLOCKS: usize = 1024;

/// No owner sentinel.
const NO_OWNER: u64 = 0;

/// Maximum spin iterations before yielding (architecture hint).
const _MAX_SPIN_ITERS: u32 = 10_000;

/// IRQ flags: interrupts were enabled.
const IRQ_FLAG_ENABLED: u64 = 1;

/// IRQ flags: interrupts were disabled.
const _IRQ_FLAG_DISABLED: u64 = 0;

// ======================================================================
// RawSpinLock
// ======================================================================

/// Low-level spinlock without owner tracking.
///
/// Used as the building block for higher-level locking.
#[derive(Debug)]
pub struct RawSpinLock {
    /// Whether the lock is held.
    locked: bool,
    /// Spin iteration counter (debugging).
    spin_count: u64,
}

impl RawSpinLock {
    /// Creates a new unlocked raw spinlock.
    pub const fn new() -> Self {
        Self {
            locked: false,
            spin_count: 0,
        }
    }

    /// Attempts to acquire the raw lock.
    ///
    /// Returns `true` if acquired.
    pub fn try_lock(&mut self) -> bool {
        if self.locked {
            self.spin_count += 1;
            false
        } else {
            self.locked = true;
            true
        }
    }

    /// Releases the raw lock.
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// Returns whether the lock is held.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns the spin count.
    pub fn spin_count(&self) -> u64 {
        self.spin_count
    }
}

// ======================================================================
// SpinLock
// ======================================================================

/// Spinlock with owner tracking and IRQ-save variants.
pub struct SpinLock {
    /// The underlying raw lock.
    raw: RawSpinLock,
    /// Task ID of the current owner (0 = none).
    owner: u64,
    /// Saved IRQ flags (for irqsave/irqrestore).
    irq_flags: u64,
    /// Whether bottom halves are disabled.
    bh_disabled: bool,
    /// Generation counter.
    generation: u64,
    /// Statistics: total acquisitions.
    stats_acquires: u64,
    /// Statistics: total contentions.
    stats_contentions: u64,
}

impl SpinLock {
    /// Creates a new unlocked spinlock.
    pub const fn new() -> Self {
        Self {
            raw: RawSpinLock::new(),
            owner: NO_OWNER,
            irq_flags: 0,
            bh_disabled: false,
            generation: 0,
            stats_acquires: 0,
            stats_contentions: 0,
        }
    }

    /// Acquires the spinlock.
    ///
    /// In a real kernel this busy-waits; here we model the
    /// state transition.
    pub fn lock(&mut self, task_id: u64) -> Result<()> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        if self.raw.locked && self.owner == task_id {
            return Err(Error::Busy);
        }
        if self.raw.locked {
            self.stats_contentions += 1;
            return Err(Error::WouldBlock);
        }
        self.raw.locked = true;
        self.owner = task_id;
        self.stats_acquires += 1;
        self.generation += 1;
        Ok(())
    }

    /// Releases the spinlock.
    pub fn unlock(&mut self) -> Result<()> {
        if !self.raw.locked {
            return Err(Error::InvalidArgument);
        }
        self.raw.locked = false;
        self.owner = NO_OWNER;
        self.generation += 1;
        Ok(())
    }

    /// Tries to acquire the spinlock without spinning.
    ///
    /// Returns `Ok(true)` if acquired, `Ok(false)` otherwise.
    pub fn trylock(&mut self, task_id: u64) -> Result<bool> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        if self.raw.locked {
            self.stats_contentions += 1;
            Ok(false)
        } else {
            self.raw.locked = true;
            self.owner = task_id;
            self.stats_acquires += 1;
            self.generation += 1;
            Ok(true)
        }
    }

    /// Returns whether the lock is held.
    pub fn is_locked(&self) -> bool {
        self.raw.locked
    }

    /// Acquires the spinlock and saves IRQ flags.
    ///
    /// Returns the saved flags for `unlock_irqrestore`.
    pub fn lock_irqsave(&mut self, task_id: u64) -> Result<u64> {
        let saved = self.irq_flags;
        self.irq_flags = IRQ_FLAG_ENABLED;
        self.lock(task_id)?;
        Ok(saved)
    }

    /// Releases the spinlock and restores IRQ flags.
    pub fn unlock_irqrestore(&mut self, flags: u64) -> Result<()> {
        self.unlock()?;
        self.irq_flags = flags;
        Ok(())
    }

    /// Acquires the spinlock and disables bottom halves.
    pub fn lock_bh(&mut self, task_id: u64) -> Result<()> {
        self.bh_disabled = true;
        self.lock(task_id)
    }

    /// Releases the spinlock and enables bottom halves.
    pub fn unlock_bh(&mut self) -> Result<()> {
        self.unlock()?;
        self.bh_disabled = false;
        Ok(())
    }

    /// Returns the current owner.
    pub fn owner(&self) -> u64 {
        self.owner
    }

    /// Returns the saved IRQ flags.
    pub fn irq_flags(&self) -> u64 {
        self.irq_flags
    }

    /// Returns whether bottom halves are disabled.
    pub fn bh_disabled(&self) -> bool {
        self.bh_disabled
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns total acquisitions.
    pub fn stats_acquires(&self) -> u64 {
        self.stats_acquires
    }

    /// Returns total contentions.
    pub fn stats_contentions(&self) -> u64 {
        self.stats_contentions
    }
}

// ======================================================================
// SpinLockTable — global registry
// ======================================================================

/// Global table of spinlocks.
pub struct SpinLockTable {
    /// Entries.
    entries: [SpinLockEntry; MAX_SPINLOCKS],
    /// Number of allocated locks.
    count: usize,
}

/// Entry in the spinlock table.
struct SpinLockEntry {
    /// The spinlock.
    lock: SpinLock,
    /// Whether allocated.
    allocated: bool,
    /// Name (for debugging).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
}

impl SpinLockEntry {
    const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }
}

impl SpinLockTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SpinLockEntry::new() }; MAX_SPINLOCKS],
            count: 0,
        }
    }

    /// Allocates a new spinlock.
    pub fn alloc(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_SPINLOCKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot()?;
        self.entries[idx].allocated = true;
        self.entries[idx].lock = SpinLock::new();
        let copy_len = name.len().min(32);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Frees a spinlock by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_SPINLOCKS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = SpinLockEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the spinlock at `idx`.
    pub fn get(&self, idx: usize) -> Result<&SpinLock> {
        if idx >= MAX_SPINLOCKS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].lock)
    }

    /// Returns a mutable reference to the spinlock at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut SpinLock> {
        if idx >= MAX_SPINLOCKS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].lock)
    }

    /// Returns the number of allocated spinlocks.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds the first free slot.
    fn find_free_slot(&self) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)
    }
}
