// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BSD flock-style advisory file locking.
//!
//! Implements whole-file advisory locks as acquired via the `flock(2)`
//! system call. flock locks are associated with open file descriptions
//! (not processes) and are inherited across `fork()`.
//!
//! Unlike POSIX locks, flock locks cover the entire file and are not
//! split into byte ranges.

use oncrix_lib::{Error, Result};

/// flock operation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlockOp(pub u32);

impl FlockOp {
    /// Acquire shared (read) lock.
    pub const LOCK_SH: u32 = 1;
    /// Acquire exclusive (write) lock.
    pub const LOCK_EX: u32 = 2;
    /// Release lock.
    pub const LOCK_UN: u32 = 8;
    /// Non-blocking flag (OR with LOCK_SH/LOCK_EX).
    pub const LOCK_NB: u32 = 4;

    /// Return true if this is a shared lock request.
    pub fn is_shared(self) -> bool {
        self.0 & Self::LOCK_SH != 0
    }

    /// Return true if this is an exclusive lock request.
    pub fn is_exclusive(self) -> bool {
        self.0 & Self::LOCK_EX != 0
    }

    /// Return true if this is an unlock request.
    pub fn is_unlock(self) -> bool {
        self.0 & Self::LOCK_UN != 0
    }

    /// Return true if the request is non-blocking.
    pub fn is_nonblock(self) -> bool {
        self.0 & Self::LOCK_NB != 0
    }

    /// Validate that exactly one of LOCK_SH, LOCK_EX, LOCK_UN is set.
    pub fn is_valid(self) -> bool {
        let base = self.0 & !Self::LOCK_NB;
        matches!(base, Self::LOCK_SH | Self::LOCK_EX | Self::LOCK_UN)
    }
}

/// State of a flock lock on a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlockState {
    /// No lock held.
    Unlocked,
    /// One or more shared locks held.
    Shared,
    /// Exactly one exclusive lock held.
    Exclusive,
}

/// A single flock lock holder.
#[derive(Debug, Clone, Copy)]
pub struct FlockHolder {
    /// Open file description identifier.
    pub owner: u64,
    /// Whether this holder has a shared or exclusive lock.
    pub exclusive: bool,
}

/// Per-inode flock lock table.
///
/// Tracks up to 64 simultaneous flock lock holders (for shared locks).
pub struct FlockTable {
    /// Lock holders.
    holders: [Option<FlockHolder>; 64],
    /// Number of current holders.
    count: usize,
    /// Current aggregate lock state.
    state: FlockState,
}

impl FlockTable {
    /// Create a new empty flock table.
    pub const fn new() -> Self {
        FlockTable {
            holders: [None; 64],
            count: 0,
            state: FlockState::Unlocked,
        }
    }

    /// Current lock state.
    pub fn state(&self) -> FlockState {
        self.state
    }

    /// Number of current lock holders.
    pub fn holder_count(&self) -> usize {
        self.count
    }

    /// Attempt to acquire a flock lock.
    ///
    /// Returns `Err(WouldBlock)` if the lock cannot be granted immediately
    /// and `LOCK_NB` was specified.
    pub fn lock(&mut self, op: FlockOp, owner: u64) -> Result<()> {
        if !op.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if op.is_unlock() {
            return self.unlock(owner);
        }
        let exclusive = op.is_exclusive();
        // Check compatibility with current state.
        match self.state {
            FlockState::Unlocked => {}
            FlockState::Shared => {
                if exclusive {
                    // Upgrade or conflict.
                    if self.sole_owner(owner) {
                        // Single shared holder — upgrade is allowed.
                        self.remove_holder(owner);
                    } else if op.is_nonblock() {
                        return Err(Error::WouldBlock);
                    } else {
                        return Err(Error::WouldBlock);
                    }
                }
                // Shared + shared is always compatible.
            }
            FlockState::Exclusive => {
                if self.sole_owner(owner) {
                    // Re-lock by the same owner: allowed (downgrade or no-op).
                    self.remove_holder(owner);
                } else if op.is_nonblock() {
                    return Err(Error::WouldBlock);
                } else {
                    return Err(Error::WouldBlock);
                }
            }
        }
        self.add_holder(owner, exclusive)
    }

    /// Release the flock lock held by `owner`.
    pub fn unlock(&mut self, owner: u64) -> Result<()> {
        self.remove_holder(owner);
        Ok(())
    }

    /// Release all locks (e.g., on file description close).
    pub fn release_owner(&mut self, owner: u64) {
        self.remove_holder(owner);
    }

    fn sole_owner(&self, owner: u64) -> bool {
        self.count == 1
            && self
                .holders
                .iter()
                .any(|h| matches!(h, Some(h) if h.owner == owner))
    }

    fn remove_holder(&mut self, owner: u64) {
        for slot in &mut self.holders {
            if let Some(h) = slot {
                if h.owner == owner {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    break;
                }
            }
        }
        self.update_state();
    }

    fn add_holder(&mut self, owner: u64, exclusive: bool) -> Result<()> {
        for slot in &mut self.holders {
            if slot.is_none() {
                *slot = Some(FlockHolder { owner, exclusive });
                self.count += 1;
                self.update_state();
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    fn update_state(&mut self) {
        if self.count == 0 {
            self.state = FlockState::Unlocked;
            return;
        }
        let has_exclusive = self.holders.iter().flatten().any(|h| h.exclusive);
        self.state = if has_exclusive {
            FlockState::Exclusive
        } else {
            FlockState::Shared
        };
    }
}

impl Default for FlockTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Global flock lock registry.
///
/// Maps inode numbers to their flock tables (up to 256 inodes).
pub struct FlockRegistry {
    entries: [Option<(u64, FlockTable)>; 256],
    count: usize,
}

impl FlockRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        // SAFETY: Option<(u64, FlockTable)> is safely zero-initializable; FlockTable
        // has a const constructor. Using `None` array literal directly.
        FlockRegistry {
            entries: {
                // Build the array using a const block since FlockTable is not Copy.
                // We use unsafe transmute via a manual approach: declare all None.
                const NONE_ENTRY: Option<(u64, FlockTable)> = None;
                [NONE_ENTRY; 256]
            },
            count: 0,
        }
    }

    /// Get or create the flock table for `ino`, returning the index.
    fn get_or_create_idx(&mut self, ino: u64) -> Result<usize> {
        // Check existing.
        for (idx, entry) in self.entries.iter().enumerate() {
            if let Some((i, _)) = entry {
                if *i == ino {
                    return Ok(idx);
                }
            }
        }
        // Create new.
        for (idx, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some((ino, FlockTable::new()));
                self.count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Perform a flock operation on `ino`.
    pub fn flock(&mut self, ino: u64, op: FlockOp, owner: u64) -> Result<()> {
        let idx = self.get_or_create_idx(ino)?;
        if let Some((_, table)) = &mut self.entries[idx] {
            return table.lock(op, owner);
        }
        Err(Error::NotFound)
    }

    /// Release all locks on `ino` held by `owner` (called on fd close).
    pub fn release(&mut self, ino: u64, owner: u64) {
        for entry in &mut self.entries {
            if let Some((i, table)) = entry {
                if *i == ino {
                    table.release_owner(owner);
                    return;
                }
            }
        }
    }

    /// Query the current lock state for `ino`.
    pub fn query_state(&self, ino: u64) -> FlockState {
        for entry in &self.entries {
            if let Some((i, table)) = entry {
                if *i == ino {
                    return table.state();
                }
            }
        }
        FlockState::Unlocked
    }
}

impl Default for FlockRegistry {
    fn default() -> Self {
        Self::new()
    }
}
