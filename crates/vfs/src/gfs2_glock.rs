// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GFS2 global lock (glock) management.
//!
//! GFS2 (Global File System 2) is a cluster-aware filesystem that uses a
//! distributed lock manager (DLM) to coordinate access across nodes.  Every
//! protected resource is guarded by a *glock*, which can be held in one of
//! several exclusive or shared states.  This module implements the single-node
//! view of the glock state machine: the holder queue, state transitions, demote
//! requests, try-lock, and the lock-ordering discipline that prevents deadlock.
//!
//! # Lock states (POSIX-like ordering)
//!
//! ```text
//!   UN  (unlocked)
//!   NL  (null lock — holder exists but grants no access)
//!   SH  (shared read — multiple holders allowed)
//!   DF  (deferred — granted but waiting for EX promotion)
//!   EX  (exclusive — single holder, full write access)
//! ```
//!
//! Compatibility matrix:
//! - UN, NL, SH are compatible with SH.
//! - Only UN is compatible with EX.
//!
//! # References
//!
//! - Linux `fs/gfs2/glock.c`, `fs/gfs2/glock.h`
//! - `fs/gfs2/lkst.h` (lock state constants)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of glocks in the glock hash table.
pub const GLOCK_HASH_SIZE: usize = 128;

/// Maximum holders queued on a single glock.
pub const MAX_GLOCK_HOLDERS: usize = 16;

/// Lock number for the filesystem superblock glock.
pub const GLOCK_SB_NUMBER: u64 = 0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// GFS2 distributed lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LockState {
    /// Unlocked — no holder.
    #[default]
    Un,
    /// Null lock — holder exists but has no data protection.
    Nl,
    /// Shared read lock — multiple concurrent holders allowed.
    Sh,
    /// Deferred — transitioning toward EX; blocks new SH holders.
    Df,
    /// Exclusive — single holder, all other states incompatible.
    Ex,
}

impl LockState {
    /// Returns `true` when `other` is compatible with `self`.
    pub fn compatible_with(self, other: LockState) -> bool {
        use LockState::*;
        match (self, other) {
            (Un, _) | (_, Un) => true,
            (Nl, Nl) | (Nl, Sh) | (Sh, Nl) | (Sh, Sh) => true,
            _ => false,
        }
    }

    /// Human-readable abbreviation.
    pub fn as_str(self) -> &'static str {
        match self {
            LockState::Un => "UN",
            LockState::Nl => "NL",
            LockState::Sh => "SH",
            LockState::Df => "DF",
            LockState::Ex => "EX",
        }
    }
}

/// Flags for a glock holder request.
#[derive(Debug, Clone, Copy, Default)]
pub struct GlockFlags {
    /// Try the lock without blocking.
    pub try_lock: bool,
    /// Async acquisition — caller will poll for completion.
    pub async_req: bool,
    /// Allow the holder to be promoted from NL to SH/EX.
    pub promote: bool,
    /// Priority holder — placed at front of the wait queue.
    pub priority: bool,
}

/// One holder (or waiter) in a glock's queue.
#[derive(Debug, Clone, Copy)]
pub struct GlockHolder {
    /// Unique holder ID (e.g., process ID or task pointer).
    pub holder_id: u64,
    /// The lock state this holder is requesting or has been granted.
    pub state: LockState,
    /// Acquisition flags.
    pub flags: GlockFlags,
    /// Whether this holder has been granted the lock.
    pub granted: bool,
}

impl GlockHolder {
    /// Create a new holder request.
    pub fn new(holder_id: u64, state: LockState, flags: GlockFlags) -> Self {
        Self {
            holder_id,
            state,
            flags,
            granted: false,
        }
    }
}

/// A single GFS2 glock.
#[derive(Debug)]
pub struct Glock {
    /// Lock number (resource identifier).
    pub lock_number: u64,
    /// Lock type (e.g., inode glock, rgrp glock).
    pub lock_type: u8,
    /// Current granted state of this glock.
    pub state: LockState,
    /// Pending demote-to request from a remote node.
    pub demote_state: Option<LockState>,
    /// Queue of current holders and waiters.
    holders: [GlockHolder; MAX_GLOCK_HOLDERS],
    /// Number of valid entries in `holders`.
    holder_count: usize,
    /// Whether the glock is currently being demoted.
    pub demoting: bool,
    /// Whether the glock entry is active in the hash table.
    pub active: bool,
}

impl Glock {
    /// Create a new glock for `lock_number` and `lock_type`.
    pub fn new(lock_number: u64, lock_type: u8) -> Self {
        let placeholder = GlockHolder {
            holder_id: 0,
            state: LockState::Un,
            flags: GlockFlags::default(),
            granted: false,
        };
        Self {
            lock_number,
            lock_type,
            state: LockState::Un,
            demote_state: None,
            holders: [placeholder; MAX_GLOCK_HOLDERS],
            holder_count: 0,
            demoting: false,
            active: true,
        }
    }

    /// Return the number of active holders (granted entries).
    pub fn granted_count(&self) -> usize {
        self.holders[..self.holder_count]
            .iter()
            .filter(|h| h.granted)
            .count()
    }

    /// Attempt to acquire the glock in `state` on behalf of `holder_id`.
    ///
    /// - If `flags.try_lock` is set, returns [`Error::WouldBlock`] immediately
    ///   when the lock cannot be granted.
    /// - If `flags.async_req` is set, the holder is queued and `Ok(false)` is
    ///   returned; the caller must poll [`Glock::poll_holder`].
    /// - Otherwise, returns `Ok(true)` when the lock is granted, or queues the
    ///   request and returns `Ok(false)` (simulate a future grant).
    pub fn acquire(&mut self, holder_id: u64, state: LockState, flags: GlockFlags) -> Result<bool> {
        if self.holder_count >= MAX_GLOCK_HOLDERS {
            return Err(Error::Busy);
        }

        // Check compatibility.
        let compatible = self.state.compatible_with(state);

        if !compatible {
            if flags.try_lock {
                return Err(Error::WouldBlock);
            }
            // Queue the waiter.
            let holder = GlockHolder::new(holder_id, state, flags);
            let idx = self.holder_count;
            self.holders[idx] = holder;
            self.holder_count += 1;
            return Ok(false);
        }

        // Grant immediately.
        let mut holder = GlockHolder::new(holder_id, state, flags);
        holder.granted = true;
        // Upgrade the glock state if needed.
        if state > self.state {
            self.state = state;
        }
        let insert_pos = if flags.priority {
            // Shift existing entries right to insert at front.
            if self.holder_count > 0 {
                self.holders.copy_within(0..self.holder_count, 1);
            }
            0
        } else {
            self.holder_count
        };
        self.holders[insert_pos] = holder;
        self.holder_count += 1;
        Ok(true)
    }

    /// Release the lock held by `holder_id`.
    ///
    /// After release, any compatible waiters are promoted to granted.
    pub fn release(&mut self, holder_id: u64) {
        let pos = self.holders[..self.holder_count]
            .iter()
            .position(|h| h.holder_id == holder_id && h.granted);
        if let Some(p) = pos {
            // Remove by shifting.
            self.holders.copy_within(p + 1..self.holder_count, p);
            self.holder_count -= 1;
            // Recompute glock state.
            self.recompute_state();
            // Try to grant waiters.
            self.grant_waiters();
        }
    }

    /// Poll whether a previously queued holder has been granted.
    pub fn poll_holder(&self, holder_id: u64) -> Option<bool> {
        self.holders[..self.holder_count]
            .iter()
            .find(|h| h.holder_id == holder_id)
            .map(|h| h.granted)
    }

    /// Request a demote to `target_state` (simulates a DLM remote demote).
    ///
    /// If no holders are active, the demote is applied immediately.
    /// Otherwise it is queued and [`Glock::process_demote`] must be called
    /// once all conflicting holders release.
    pub fn request_demote(&mut self, target_state: LockState) {
        if self.granted_count() == 0 {
            self.state = target_state;
            self.demote_state = None;
        } else {
            self.demote_state = Some(target_state);
            self.demoting = true;
        }
    }

    /// Apply a pending demote request once all conflicting holders have released.
    pub fn process_demote(&mut self) {
        if !self.demoting {
            return;
        }
        if self.granted_count() == 0 {
            if let Some(target) = self.demote_state.take() {
                self.state = target;
            }
            self.demoting = false;
        }
    }

    /// Recompute the glock's effective state from the set of granted holders.
    fn recompute_state(&mut self) {
        let max_state = self.holders[..self.holder_count]
            .iter()
            .filter(|h| h.granted)
            .map(|h| h.state)
            .fold(LockState::Un, |acc, s| if s > acc { s } else { acc });
        self.state = max_state;
    }

    /// Grant compatible waiters in queue order.
    fn grant_waiters(&mut self) {
        for idx in 0..self.holder_count {
            if !self.holders[idx].granted {
                let req_state = self.holders[idx].state;
                if self.state.compatible_with(req_state) {
                    self.holders[idx].granted = true;
                    if req_state > self.state {
                        self.state = req_state;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Glock hash table
// ---------------------------------------------------------------------------

/// Hash table of active glocks for a GFS2 filesystem instance.
pub struct GlockTable {
    buckets: [Option<Glock>; GLOCK_HASH_SIZE],
}

impl Default for GlockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl GlockTable {
    /// Create an empty glock table.
    pub fn new() -> Self {
        Self {
            buckets: core::array::from_fn(|_| None),
        }
    }

    fn slot(lock_number: u64) -> usize {
        (lock_number as usize) % GLOCK_HASH_SIZE
    }

    /// Look up or create the glock for `(lock_number, lock_type)`.
    ///
    /// Returns [`Error::Busy`] when the bucket is occupied by a different lock.
    pub fn get_or_alloc(&mut self, lock_number: u64, lock_type: u8) -> Result<&mut Glock> {
        let idx = Self::slot(lock_number);
        match &self.buckets[idx] {
            Some(g) if g.lock_number == lock_number => {}
            None => {
                self.buckets[idx] = Some(Glock::new(lock_number, lock_type));
            }
            _ => return Err(Error::Busy),
        }
        Ok(self.buckets[idx].as_mut().unwrap())
    }

    /// Remove the glock for `lock_number` from the table.
    pub fn dealloc(&mut self, lock_number: u64) {
        let idx = Self::slot(lock_number);
        if self.buckets[idx].as_ref().map(|g| g.lock_number) == Some(lock_number) {
            self.buckets[idx] = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_sh_compatible() {
        assert!(LockState::Sh.compatible_with(LockState::Sh));
    }

    #[test]
    fn ex_sh_incompatible() {
        assert!(!LockState::Ex.compatible_with(LockState::Sh));
    }

    #[test]
    fn acquire_and_release() {
        let mut g = Glock::new(1, 2);
        let flags = GlockFlags::default();
        let granted = g.acquire(100, LockState::Sh, flags).unwrap();
        assert!(granted);
        assert_eq!(g.state, LockState::Sh);
        g.release(100);
        assert_eq!(g.state, LockState::Un);
    }

    #[test]
    fn try_lock_fails_when_ex_held() {
        let mut g = Glock::new(2, 1);
        let flags = GlockFlags::default();
        g.acquire(1, LockState::Ex, flags).unwrap();
        let result = g.acquire(
            2,
            LockState::Sh,
            GlockFlags {
                try_lock: true,
                ..Default::default()
            },
        );
        assert!(matches!(result, Err(Error::WouldBlock)));
    }

    #[test]
    fn demote_applied_when_no_holders() {
        let mut g = Glock::new(3, 1);
        let flags = GlockFlags::default();
        g.acquire(1, LockState::Ex, flags).unwrap();
        g.release(1);
        g.request_demote(LockState::Sh);
        assert_eq!(g.state, LockState::Sh);
    }
}
