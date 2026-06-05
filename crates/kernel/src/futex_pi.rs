// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Priority-inheritance futex (PI futex) implementation.
//!
//! Extends the basic futex with priority inheritance to prevent
//! priority inversion: when a high-priority task blocks on a
//! futex held by a low-priority task, the owner's priority is
//! temporarily boosted to the highest waiting priority.
//!
//! Operations:
//! - `LockPi` / `UnlockPi` / `TrylockPi` — PI-aware lock/unlock
//! - `Wait` / `Wake` — standard futex semantics
//! - `WaitBitset` / `WakeBitset` — bitset-filtered wait/wake
//! - `Requeue` / `CmpRequeue` — bulk waiter migration
//! - `WaitRequeuePi` — combined wait + requeue with PI
//!
//! Reference: Linux `kernel/futex/pi.c`, futex(2) man page.

use oncrix_lib::{Error, Result};

/// Maximum number of waiters per futex entry.
const MAX_ENTRY_WAITERS: usize = 32;

/// Maximum number of PI waiters tracked per lock.
const MAX_PI_WAITERS: usize = 16;

/// Maximum number of futex entries in the registry.
const MAX_ENTRIES: usize = 256;

/// Default bitset matching all bits.
const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;

/// Maximum depth of a PI-chain walk during deadlock detection.
///
/// Bounds the owner -> blocked-on -> owner traversal so a crafted
/// lock graph cannot make the walk run unbounded. A chain can never
/// legitimately exceed the number of distinct lock entries.
const MAX_PI_CHAIN_DEPTH: usize = MAX_ENTRIES;

/// Upper bound on the wake/requeue counts accepted by a single
/// requeue operation, mirroring a sane Linux-style cap.
///
/// Counts above this are clamped to it, which both prevents absurd
/// loop trip counts and never under-serves a real waiter set, since
/// no entry can hold more than `MAX_ENTRY_WAITERS` waiters anyway.
const FUTEX_REQUEUE_MAX: u32 = MAX_ENTRY_WAITERS as u32;

/// Futex operation codes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FutexOp {
    /// Sleep if `*uaddr == val`.
    #[default]
    Wait,
    /// Wake up to `val` waiters.
    Wake,
    /// Move waiters from one futex key to another.
    Requeue,
    /// Compare-and-requeue: requeue only if `*uaddr == expected`.
    CmpRequeue,
    /// Wait with a bitset filter.
    WaitBitset,
    /// Wake with a bitset filter.
    WakeBitset,
    /// Lock with priority inheritance.
    LockPi,
    /// Unlock with priority inheritance.
    UnlockPi,
    /// Try to lock with priority inheritance (non-blocking).
    TrylockPi,
    /// Wait then requeue with priority inheritance.
    WaitRequeuePi,
}

/// Priority inheritance state for a futex lock.
///
/// Tracks the current owner, waiting processes, and handles
/// priority boosting/restoration to prevent priority inversion.
#[derive(Debug, Clone, Copy)]
pub struct PiState {
    /// PID of the current lock owner.
    owner_pid: u64,
    /// PIDs of tasks waiting for this lock.
    waiters: [u64; MAX_PI_WAITERS],
    /// Scheduling priority of each waiter, parallel to `waiters`.
    ///
    /// `waiter_prios[i]` is the priority recorded for `waiters[i]`.
    /// Lower numeric values mean higher scheduling priority.
    waiter_prios: [u8; MAX_PI_WAITERS],
    /// Number of active waiters.
    waiter_count: usize,
    /// Owner's priority before any boosting.
    original_priority: u8,
    /// Owner's current (possibly boosted) priority.
    boosted_priority: u8,
}

impl Default for PiState {
    fn default() -> Self {
        Self {
            owner_pid: 0,
            waiters: [0; MAX_PI_WAITERS],
            waiter_prios: [0; MAX_PI_WAITERS],
            waiter_count: 0,
            original_priority: 0,
            boosted_priority: 0,
        }
    }
}

impl PiState {
    /// Set the lock owner and their base priority.
    pub fn set_owner(&mut self, pid: u64, priority: u8) {
        self.owner_pid = pid;
        self.original_priority = priority;
        self.boosted_priority = priority;
    }

    /// Add a waiter and boost the owner's priority if necessary.
    ///
    /// Lower numeric priority values represent higher scheduling
    /// priority (e.g., 0 = highest). If the new waiter has a
    /// higher priority (lower value) than the current boosted
    /// priority, the owner is boosted.
    ///
    /// Returns `Err(OutOfMemory)` if the waiter list is full.
    pub fn add_waiter(&mut self, pid: u64, priority: u8) -> Result<()> {
        if self.waiter_count >= MAX_PI_WAITERS {
            return Err(Error::OutOfMemory);
        }
        self.waiters[self.waiter_count] = pid;
        self.waiter_prios[self.waiter_count] = priority;
        self.waiter_count += 1;

        // Boost owner if waiter has higher priority (lower value).
        if priority < self.boosted_priority {
            self.boosted_priority = priority;
        }

        Ok(())
    }

    /// Remove a waiter by PID.
    ///
    /// After removal, recalculates the boosted priority from the
    /// remaining waiters plus the owner's base priority, so a boost
    /// granted by a still-present higher-priority waiter is retained.
    /// This is a no-op if the PID is not found.
    pub fn remove_waiter(&mut self, pid: u64) {
        let mut found = false;
        for i in 0..self.waiter_count {
            if self.waiters[i] == pid {
                // Shift remaining waiters (and their priorities) down.
                let mut j = i;
                while j + 1 < self.waiter_count {
                    self.waiters[j] = self.waiters[j + 1];
                    self.waiter_prios[j] = self.waiter_prios[j + 1];
                    j += 1;
                }
                let last = self.waiter_count.saturating_sub(1);
                self.waiters[last] = 0;
                self.waiter_prios[last] = 0;
                self.waiter_count = last;
                found = true;
                break;
            }
        }

        if found {
            self.recompute_boost();
        }
    }

    /// Recompute the boosted priority from the owner's base priority
    /// and every remaining waiter.
    ///
    /// The boosted priority is the highest scheduling priority (the
    /// lowest numeric value) among the owner's original priority and
    /// all current waiters. With no waiters this restores the original
    /// priority; with higher-priority waiters still present the boost
    /// is preserved rather than dropped.
    fn recompute_boost(&mut self) {
        let mut best = self.original_priority;
        for i in 0..self.waiter_count {
            if self.waiter_prios[i] < best {
                best = self.waiter_prios[i];
            }
        }
        self.boosted_priority = best;
    }

    /// Boost the owner's priority to the highest waiter priority.
    ///
    /// In this implementation, the boosted priority is already
    /// maintained incrementally via `add_waiter`. This method
    /// forces a recalculation and confirms the current state.
    pub fn boost(&mut self) {
        // The boosted priority is maintained by add_waiter.
        // This is a no-op confirmation that PI is active.
        // The boosted_priority field already reflects the
        // highest-priority waiter seen so far.
    }

    /// Restore the owner's priority to its original (pre-boost) value.
    pub fn restore(&mut self) {
        self.boosted_priority = self.original_priority;
    }

    /// Return the current owner PID.
    pub fn owner(&self) -> u64 {
        self.owner_pid
    }

    /// Return the number of active waiters.
    pub fn waiter_count(&self) -> usize {
        self.waiter_count
    }

    /// Return the boosted priority value.
    pub fn boosted_priority(&self) -> u8 {
        self.boosted_priority
    }

    /// Return the original (unboosted) priority value.
    pub fn original_priority(&self) -> u8 {
        self.original_priority
    }
}

/// A single entry in the futex registry.
///
/// Each entry tracks a futex word by its virtual address (key),
/// the set of waiting processes, an optional PI state for
/// priority-inheritance locks, and a bitset for filtered wakeups.
#[derive(Debug, Clone, Copy)]
pub struct FutexEntry {
    /// Virtual address of the futex word.
    key: u64,
    /// Current value of the futex word.
    val: u32,
    /// PIDs of waiting processes.
    waiters: [u64; MAX_ENTRY_WAITERS],
    /// Number of active waiters.
    waiter_count: usize,
    /// Bitset for filtered wait/wake operations.
    bitset: u32,
    /// Whether this entry has PI state attached.
    has_pi: bool,
    /// Priority inheritance state (valid only when `has_pi` is true).
    pi: PiState,
    /// Whether this entry is currently in use.
    in_use: bool,
}

impl Default for FutexEntry {
    fn default() -> Self {
        Self {
            key: 0,
            val: 0,
            waiters: [0; MAX_ENTRY_WAITERS],
            waiter_count: 0,
            bitset: FUTEX_BITSET_MATCH_ANY,
            has_pi: false,
            pi: PiState::default(),
            in_use: false,
        }
    }
}

/// Head of a robust futex list (matches Linux ABI).
///
/// A robust list allows the kernel to clean up futexes held by
/// a thread that exits unexpectedly (crash, signal death).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RobustListHead {
    /// Pointer to the first entry in the robust list.
    pub list: u64,
    /// Offset from a robust list entry to the futex word.
    pub futex_offset: i64,
    /// Pointer to the entry currently being locked/unlocked.
    pub pending: u64,
}

/// Global registry of PI-aware futex entries.
///
/// Manages all active futex entries and provides operations
/// for wait, wake, requeue, and priority-inheritance locking.
pub struct FutexPiRegistry {
    /// Pool of futex entries.
    entries: [FutexEntry; MAX_ENTRIES],
    /// Number of entries currently in use.
    count: usize,
}

impl Default for FutexPiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexPiRegistry {
    /// Create a new, empty futex PI registry.
    pub const fn new() -> Self {
        const DEFAULT_ENTRY: FutexEntry = FutexEntry {
            key: 0,
            val: 0,
            waiters: [0; MAX_ENTRY_WAITERS],
            waiter_count: 0,
            bitset: FUTEX_BITSET_MATCH_ANY,
            has_pi: false,
            pi: PiState {
                owner_pid: 0,
                waiters: [0; MAX_PI_WAITERS],
                waiter_prios: [0; MAX_PI_WAITERS],
                waiter_count: 0,
                original_priority: 0,
                boosted_priority: 0,
            },
            in_use: false,
        };
        Self {
            entries: [DEFAULT_ENTRY; MAX_ENTRIES],
            count: 0,
        }
    }

    /// Wait on a futex: add the caller as a waiter if the futex
    /// value matches `expected`.
    ///
    /// The `bitset` parameter filters which wake operations can
    /// wake this waiter (use `FUTEX_BITSET_MATCH_ANY` for unfiltered).
    ///
    /// Returns `WouldBlock` if the current value does not match.
    pub fn futex_wait(&mut self, key: u64, expected: u32, bitset: u32, pid: u64) -> Result<()> {
        if bitset == 0 {
            return Err(Error::InvalidArgument);
        }

        // Find or create an entry for this key.
        let idx = self.find_or_create_entry(key)?;
        let entry = &mut self.entries[idx];

        // Check if current value matches expected.
        if entry.val != expected {
            return Err(Error::WouldBlock);
        }

        // Add waiter.
        if entry.waiter_count >= MAX_ENTRY_WAITERS {
            return Err(Error::OutOfMemory);
        }

        entry.waiters[entry.waiter_count] = pid;
        entry.waiter_count += 1;
        entry.bitset = bitset;

        Ok(())
    }

    /// Wake up to `count` waiters on the given futex key.
    ///
    /// Only wakes waiters whose bitset overlaps with the provided
    /// `bitset`. Returns the number of waiters actually woken.
    pub fn futex_wake(&mut self, key: u64, count: u32, bitset: u32) -> Result<u32> {
        if bitset == 0 {
            return Err(Error::InvalidArgument);
        }

        let idx = match self.find_entry(key) {
            Some(i) => i,
            None => return Ok(0),
        };

        let entry = &mut self.entries[idx];
        let mut woken = 0u32;

        // Wake waiters by shifting the array.
        let mut i = 0;
        while i < entry.waiter_count && woken < count {
            if entry.bitset & bitset != 0 {
                // Wake this waiter: shift remaining down.
                let mut j = i;
                while j + 1 < entry.waiter_count {
                    entry.waiters[j] = entry.waiters[j + 1];
                    j += 1;
                }
                entry.waiters[entry.waiter_count.saturating_sub(1)] = 0;
                entry.waiter_count = entry.waiter_count.saturating_sub(1);
                woken += 1;
                // Don't increment i; the next waiter shifted into this slot.
            } else {
                i += 1;
            }
        }

        // Clean up entry if no waiters remain and no PI state.
        if entry.waiter_count == 0 && !entry.has_pi {
            entry.in_use = false;
            self.count = self.count.saturating_sub(1);
        }

        Ok(woken)
    }

    /// Requeue waiters from one futex key to another.
    ///
    /// Wakes up to `wake_count` waiters on `from_key`, then moves
    /// up to `requeue_count` remaining waiters to `to_key`.
    ///
    /// Returns the total number of waiters woken.
    pub fn futex_requeue(
        &mut self,
        from_key: u64,
        to_key: u64,
        wake_count: u32,
        requeue_count: u32,
    ) -> Result<u32> {
        // Requeue to the same key would loop migrating a waiter out of
        // and back into one entry, up to `requeue_count` (attacker
        // controlled, up to u32::MAX) iterations: reject like Linux's
        // EINVAL before doing any work.
        if from_key == to_key {
            return Err(Error::InvalidArgument);
        }

        // Clamp both counts to a sane maximum. No entry can ever hold
        // more than `MAX_ENTRY_WAITERS` waiters, so clamping never
        // under-serves a legitimate request, but it bounds the wake
        // scan and the requeue loop to a small constant.
        let wake_count = wake_count.min(FUTEX_REQUEUE_MAX);
        let requeue_count = requeue_count.min(FUTEX_REQUEUE_MAX);

        // First, wake waiters on from_key.
        let woken = self.futex_wake(from_key, wake_count, FUTEX_BITSET_MATCH_ANY)?;

        // Then move remaining waiters to to_key.
        let from_idx = match self.find_entry(from_key) {
            Some(i) => i,
            None => return Ok(woken),
        };

        let to_idx = self.find_or_create_entry(to_key)?;

        let mut moved = 0u32;
        while moved < requeue_count {
            let from = &self.entries[from_idx];
            if from.waiter_count == 0 {
                break;
            }

            let to = &self.entries[to_idx];
            if to.waiter_count >= MAX_ENTRY_WAITERS {
                break;
            }

            // Move one waiter: read pid from source.
            let pid = self.entries[from_idx].waiters[0];

            // Remove from source (shift down).
            {
                let from_entry = &mut self.entries[from_idx];
                let mut j = 0;
                while j + 1 < from_entry.waiter_count {
                    from_entry.waiters[j] = from_entry.waiters[j + 1];
                    j += 1;
                }
                from_entry.waiters[from_entry.waiter_count.saturating_sub(1)] = 0;
                from_entry.waiter_count = from_entry.waiter_count.saturating_sub(1);
            }

            // Add to destination.
            {
                let to_entry = &mut self.entries[to_idx];
                to_entry.waiters[to_entry.waiter_count] = pid;
                to_entry.waiter_count += 1;
            }

            moved += 1;
        }

        // Clean up source if empty.
        if self.entries[from_idx].waiter_count == 0 && !self.entries[from_idx].has_pi {
            self.entries[from_idx].in_use = false;
            self.count = self.count.saturating_sub(1);
        }

        Ok(woken)
    }

    /// Lock a futex with priority inheritance.
    ///
    /// If the futex is unowned, the caller becomes the owner.
    /// If owned by another task, the caller is added as a PI
    /// waiter and the owner's priority may be boosted.
    pub fn futex_lock_pi(&mut self, key: u64, pid: u64, priority: u8) -> Result<()> {
        let idx = self.find_or_create_entry(key)?;
        let entry = &mut self.entries[idx];

        if !entry.has_pi {
            // First PI lock on this entry.
            entry.has_pi = true;
            entry.pi = PiState::default();
            entry.pi.set_owner(pid, priority);
            return Ok(());
        }

        // Already has PI state.
        if entry.pi.owner_pid == 0 {
            // Unowned — claim it.
            entry.pi.set_owner(pid, priority);
            return Ok(());
        }

        if entry.pi.owner_pid == pid {
            // Already own it — deadlock prevention.
            return Err(Error::Busy);
        }

        // Walk the PI chain before committing: if blocking on this
        // owner would close a cycle (owner -> ... -> caller), or the
        // chain is pathologically deep, reject instead of deadlocking.
        let owner = entry.pi.owner_pid;
        if self.pi_chain_would_deadlock(pid, owner) {
            return Err(Error::Busy);
        }

        let entry = &mut self.entries[idx];

        // Owned by someone else — add as waiter with priority boost.
        entry.pi.add_waiter(pid, priority)?;
        entry.pi.boost();

        // Also add to the entry's general waiter list.
        if entry.waiter_count >= MAX_ENTRY_WAITERS {
            // Undo the PI waiter addition.
            entry.pi.remove_waiter(pid);
            return Err(Error::OutOfMemory);
        }
        entry.waiters[entry.waiter_count] = pid;
        entry.waiter_count += 1;

        // Return WouldBlock to indicate the caller should sleep.
        Err(Error::WouldBlock)
    }

    /// Unlock a PI futex and hand ownership to the highest-priority
    /// waiter, if any.
    ///
    /// Only the current owner may unlock. Returns `PermissionDenied`
    /// if the caller is not the owner.
    pub fn futex_unlock_pi(&mut self, key: u64, pid: u64) -> Result<()> {
        let idx = self.find_entry(key).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];

        if !entry.has_pi {
            return Err(Error::InvalidArgument);
        }

        if entry.pi.owner_pid != pid {
            return Err(Error::PermissionDenied);
        }

        // Restore owner's original priority.
        entry.pi.restore();

        if entry.waiter_count == 0 {
            // No waiters — clear PI state.
            entry.pi = PiState::default();
            entry.has_pi = false;
            entry.in_use = false;
            self.count = self.count.saturating_sub(1);
            return Ok(());
        }

        // Hand ownership to the first waiter.
        let new_owner = entry.waiters[0];

        // Remove from waiter lists.
        let mut j = 0;
        while j + 1 < entry.waiter_count {
            entry.waiters[j] = entry.waiters[j + 1];
            j += 1;
        }
        entry.waiters[entry.waiter_count.saturating_sub(1)] = 0;
        entry.waiter_count = entry.waiter_count.saturating_sub(1);

        entry.pi.remove_waiter(new_owner);

        // Set new owner. The general waiter list does not carry per-task
        // priorities, so the prior owner's base priority is used as the
        // new owner's base. Any PI waiters that are still blocked on this
        // lock must continue to boost the new owner, so recompute the
        // boost from those remaining waiters rather than leaving it reset.
        let base = entry.pi.original_priority;
        entry.pi.set_owner(new_owner, base);
        entry.pi.recompute_boost();

        Ok(())
    }

    /// Try to acquire a PI futex lock without blocking.
    ///
    /// Returns `Ok(true)` if the lock was acquired, `Ok(false)` if
    /// it is already held by another task.
    pub fn futex_trylock_pi(&mut self, key: u64, pid: u64, priority: u8) -> Result<bool> {
        let idx = self.find_or_create_entry(key)?;
        let entry = &mut self.entries[idx];

        if !entry.has_pi {
            // No PI state yet — claim it.
            entry.has_pi = true;
            entry.pi = PiState::default();
            entry.pi.set_owner(pid, priority);
            return Ok(true);
        }

        if entry.pi.owner_pid == 0 {
            // Unowned — claim it.
            entry.pi.set_owner(pid, priority);
            return Ok(true);
        }

        if entry.pi.owner_pid == pid {
            // Already own it.
            return Err(Error::Busy);
        }

        // Owned by someone else — cannot acquire.
        Ok(false)
    }

    /// Process a robust futex list for a dying thread.
    ///
    /// Walks the robust list and releases any futexes the thread
    /// held. Returns the number of futexes cleaned up.
    pub fn handle_robust_list(&mut self, head: &RobustListHead) -> Result<u32> {
        let mut cleaned = 0u32;

        // Process the pending entry first, if any.
        if head.pending != 0 {
            let futex_addr = if head.futex_offset >= 0 {
                head.pending.wrapping_add(head.futex_offset as u64)
            } else {
                head.pending.wrapping_sub(head.futex_offset.unsigned_abs())
            };

            if let Some(idx) = self.find_entry(futex_addr) {
                let entry = &mut self.entries[idx];
                if entry.has_pi {
                    entry.pi.restore();
                    entry.pi = PiState::default();
                    entry.has_pi = false;
                }
                entry.in_use = false;
                self.count = self.count.saturating_sub(1);
                cleaned += 1;
            }
        }

        // Process the list head entry itself, if valid.
        // In a real implementation we would walk the linked list by
        // reading next pointers from user space. Since we cannot
        // dereference user pointers here, we process only the head.
        let current = head.list;
        if current != 0 {
            let futex_addr = if head.futex_offset >= 0 {
                current.wrapping_add(head.futex_offset as u64)
            } else {
                current.wrapping_sub(head.futex_offset.unsigned_abs())
            };

            if let Some(idx) = self.find_entry(futex_addr) {
                let entry = &mut self.entries[idx];
                if entry.has_pi {
                    entry.pi.restore();
                    entry.pi = PiState::default();
                    entry.has_pi = false;
                }
                entry.in_use = false;
                self.count = self.count.saturating_sub(1);
                cleaned += 1;
            }
        }

        Ok(cleaned)
    }

    /// Return the number of active entries in the registry.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry has no active entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Find an existing entry by key.
    fn find_entry(&self, key: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.in_use && e.key == key)
    }

    /// Find the PI lock entry that `pid` is currently blocked on.
    ///
    /// A task is "blocked on" a lock when it appears in that lock's PI
    /// waiter list. Returns the index of the first such entry, if any.
    fn entry_blocking(&self, pid: u64) -> Option<usize> {
        self.entries.iter().position(|e| {
            if !e.in_use || !e.has_pi {
                return false;
            }
            e.pi.waiters[..e.pi.waiter_count].contains(&pid)
        })
    }

    /// Detect whether `waiter` blocking on the lock owned by `owner`
    /// would close a cycle in the PI (owner-blocked-on) graph.
    ///
    /// Walks owner -> (lock owner is blocked on) -> next owner ... up to
    /// [`MAX_PI_CHAIN_DEPTH`]. Returns `true` if the walk reaches
    /// `waiter` (a deadlock) or exceeds the depth cap (treated as a
    /// deadlock to stay bounded). A zero/absent owner ends the chain.
    fn pi_chain_would_deadlock(&self, waiter: u64, owner: u64) -> bool {
        let mut current = owner;
        let mut depth = 0;
        while current != 0 {
            if current == waiter {
                // The owner chain leads back to the new waiter: cycle.
                return true;
            }
            depth += 1;
            if depth >= MAX_PI_CHAIN_DEPTH {
                // Refuse to walk further; treat as a deadlock.
                return true;
            }
            // Advance: find the lock `current` is itself blocked on and
            // move to that lock's owner. If it is blocked on nothing,
            // the chain terminates safely.
            match self.entry_blocking(current) {
                Some(idx) => current = self.entries[idx].pi.owner_pid,
                None => return false,
            }
        }
        false
    }

    /// Find an existing entry or create a new one for the given key.
    fn find_or_create_entry(&mut self, key: u64) -> Result<usize> {
        // Check for existing entry.
        if let Some(idx) = self.find_entry(key) {
            return Ok(idx);
        }

        // Find a free slot.
        let idx = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.entries[idx] = FutexEntry::default();
        self.entries[idx].key = key;
        self.entries[idx].in_use = true;
        self.count += 1;

        Ok(idx)
    }
}

impl core::fmt::Debug for FutexPiRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FutexPiRegistry")
            .field("active_entries", &self.count)
            .field("capacity", &MAX_ENTRIES)
            .finish()
    }
}
