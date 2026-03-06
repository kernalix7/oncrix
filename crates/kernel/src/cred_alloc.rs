// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Credential allocation and lifecycle management.
//!
//! Implements a copy-on-write credential model. Credentials are
//! immutable once committed; modifications require a
//! prepare/commit cycle that atomically swaps the task's active
//! credential pointer.
//!
//! Lifecycle: `prepare_creds` -> modify -> `commit_creds`
//! (or `abort_creds` on error).
//!
//! Reference: Linux `kernel/cred.c`, `include/linux/cred.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum credential objects in the pool.
const MAX_CREDS: usize = 512;

/// Maximum tasks that can have assigned credentials.
const MAX_TASKS: usize = 256;

/// Number of capability bitmask words (128 caps total).
const CAP_WORDS: usize = 2;

/// Root UID.
const ROOT_UID: u32 = 0;

/// Root GID.
const ROOT_GID: u32 = 0;

/// Bitmask capability set (128 capabilities max).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CapSet {
    /// Capability bitmask words.
    bits: [u64; CAP_WORDS],
}

impl CapSet {
    /// Empty capability set.
    pub const fn empty() -> Self {
        Self {
            bits: [0; CAP_WORDS],
        }
    }
    /// Full capability set (all bits set).
    pub const fn full() -> Self {
        Self {
            bits: [u64::MAX; CAP_WORDS],
        }
    }
    /// Check whether capability `cap` is raised.
    pub fn has(&self, cap: u32) -> bool {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word >= CAP_WORDS {
            return false;
        }
        (self.bits[word] & (1u64 << bit)) != 0
    }
    /// Raise capability `cap`.
    pub fn raise(&mut self, cap: u32) {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word < CAP_WORDS {
            self.bits[word] |= 1u64 << bit;
        }
    }
    /// Drop capability `cap`.
    pub fn drop_cap(&mut self, cap: u32) {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word < CAP_WORDS {
            self.bits[word] &= !(1u64 << bit);
        }
    }
    /// Intersect two capability sets.
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            bits: [self.bits[0] & other.bits[0], self.bits[1] & other.bits[1]],
        }
    }
    /// Check if the set is empty.
    pub const fn is_empty(self) -> bool {
        self.bits[0] == 0 && self.bits[1] == 0
    }
}

/// Lifecycle state of a credential slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredState {
    /// Slot is available for allocation.
    Free,
    /// Allocated via `prepare_creds`, awaiting commit or abort.
    Prepared,
    /// Committed and in use by one or more tasks.
    Active,
    /// Previously active, awaiting refcount drop to zero.
    Retired,
}

/// Process credentials (POSIX + Linux capability bitmasks).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Cred {
    /// Real user ID.
    pub uid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved set-user-ID.
    pub suid: u32,
    /// Saved set-group-ID.
    pub sgid: u32,
    /// Filesystem user ID.
    pub fsuid: u32,
    /// Filesystem group ID.
    pub fsgid: u32,
    /// Effective capabilities.
    pub cap_effective: CapSet,
    /// Permitted capabilities.
    pub cap_permitted: CapSet,
    /// Inheritable capabilities.
    pub cap_inheritable: CapSet,
}

impl Cred {
    /// Default root credentials.
    pub const fn root() -> Self {
        Self {
            uid: ROOT_UID,
            gid: ROOT_GID,
            euid: ROOT_UID,
            egid: ROOT_GID,
            suid: ROOT_UID,
            sgid: ROOT_GID,
            fsuid: ROOT_UID,
            fsgid: ROOT_GID,
            cap_effective: CapSet::full(),
            cap_permitted: CapSet::full(),
            cap_inheritable: CapSet::empty(),
        }
    }

    /// Default unprivileged credentials for a given uid/gid.
    pub const fn unprivileged(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            euid: uid,
            egid: gid,
            suid: uid,
            sgid: gid,
            fsuid: uid,
            fsgid: gid,
            cap_effective: CapSet::empty(),
            cap_permitted: CapSet::empty(),
            cap_inheritable: CapSet::empty(),
        }
    }

    /// Check if credentials belong to root.
    pub const fn is_root(&self) -> bool {
        self.euid == ROOT_UID
    }
}

/// A credential slot in the allocator pool.
#[derive(Debug, Clone, Copy)]
struct CredSlot {
    /// The credential data.
    cred: Cred,
    /// Reference count (number of tasks using this cred).
    ref_count: u32,
    /// Lifecycle state.
    state: CredState,
    /// Generation counter for ABA protection.
    generation: u64,
    /// Task that created this credential (for audit).
    owner_task: u64,
}

/// Per-task credential binding.
#[derive(Debug, Clone, Copy)]
struct TaskCred {
    /// Index into the credential pool for the active cred.
    active_cred_id: u64,
    /// Index for a cred being prepared (0 = none).
    prepared_cred_id: u64,
    /// Whether this task slot is in use.
    in_use: bool,
}

/// Allocator statistics.
#[derive(Debug, Clone, Copy)]
pub struct CredAllocStats {
    /// Total credentials allocated since boot.
    pub total_allocs: u64,
    /// Total credentials freed since boot.
    pub total_frees: u64,
    /// Total commit operations.
    pub total_commits: u64,
    /// Total abort operations.
    pub total_aborts: u64,
    /// Current active credential count.
    pub active_count: u32,
}

/// Global credential allocator.
pub struct CredAllocator {
    /// Credential object pool.
    slots: [CredSlot; MAX_CREDS],
    /// Per-task credential bindings.
    tasks: [TaskCred; MAX_TASKS],
    /// Next generation counter.
    next_generation: u64,
    /// Statistics.
    stats: CredAllocStats,
}

impl CredAllocator {
    /// Create a new credential allocator.
    pub const fn new() -> Self {
        let slot = CredSlot {
            cred: Cred::unprivileged(0, 0),
            ref_count: 0,
            state: CredState::Free,
            generation: 0,
            owner_task: 0,
        };
        let task = TaskCred {
            active_cred_id: 0,
            prepared_cred_id: 0,
            in_use: false,
        };
        Self {
            slots: [slot; MAX_CREDS],
            tasks: [task; MAX_TASKS],
            next_generation: 1,
            stats: CredAllocStats {
                total_allocs: 0,
                total_frees: 0,
                total_commits: 0,
                total_aborts: 0,
                active_count: 0,
            },
        }
    }

    /// Register a task with initial root credentials.
    pub fn register_task_root(&mut self, task_id: u64) -> Result<()> {
        self.register_task_with_cred(task_id, Cred::root())
    }

    /// Register a task with specified initial credentials.
    pub fn register_task_with_cred(&mut self, task_id: u64, cred: Cred) -> Result<()> {
        let tidx = task_id as usize;
        if tidx >= MAX_TASKS {
            return Err(Error::InvalidArgument);
        }
        if self.tasks[tidx].in_use {
            return Err(Error::AlreadyExists);
        }
        let slot_id = self.alloc_slot(cred, task_id)?;
        self.slots[slot_id].state = CredState::Active;
        self.slots[slot_id].ref_count = 1;
        self.tasks[tidx] = TaskCred {
            active_cred_id: slot_id as u64,
            prepared_cred_id: 0,
            in_use: true,
        };
        self.stats.active_count += 1;
        Ok(())
    }

    /// Prepare new credentials by copying the task's current ones.
    pub fn prepare_creds(&mut self, task_id: u64) -> Result<u64> {
        let tidx = task_id as usize;
        if tidx >= MAX_TASKS || !self.tasks[tidx].in_use {
            return Err(Error::NotFound);
        }
        let active_id = self.tasks[tidx].active_cred_id as usize;
        let cred_copy = self.slots[active_id].cred;
        let new_id = self.alloc_slot(cred_copy, task_id)?;
        self.slots[new_id].state = CredState::Prepared;
        self.tasks[tidx].prepared_cred_id = new_id as u64;
        Ok(new_id as u64)
    }

    /// Commit prepared credentials, atomically swapping active.
    pub fn commit_creds(&mut self, task_id: u64, cred_id: u64) -> Result<()> {
        let tidx = task_id as usize;
        if tidx >= MAX_TASKS || !self.tasks[tidx].in_use {
            return Err(Error::NotFound);
        }
        let new_idx = cred_id as usize;
        if new_idx >= MAX_CREDS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[new_idx].state != CredState::Prepared {
            return Err(Error::InvalidArgument);
        }
        if self.tasks[tidx].prepared_cred_id != cred_id {
            return Err(Error::InvalidArgument);
        }
        // Retire old credential.
        let old_idx = self.tasks[tidx].active_cred_id as usize;
        self.put_cred(old_idx);
        // Activate the new credential.
        self.slots[new_idx].state = CredState::Active;
        self.slots[new_idx].ref_count = 1;
        self.tasks[tidx].active_cred_id = cred_id;
        self.tasks[tidx].prepared_cred_id = 0;
        self.stats.total_commits += 1;
        Ok(())
    }

    /// Abort a prepared credential, freeing the slot.
    pub fn abort_creds(&mut self, cred_id: u64) -> Result<()> {
        let idx = cred_id as usize;
        if idx >= MAX_CREDS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state != CredState::Prepared {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].state = CredState::Free;
        self.slots[idx].ref_count = 0;
        self.stats.total_aborts += 1;
        self.stats.total_frees += 1;
        Ok(())
    }

    /// Get a read-only reference to a task's active credentials.
    pub fn get_cred(&self, task_id: u64) -> Result<&Cred> {
        let tidx = task_id as usize;
        if tidx >= MAX_TASKS || !self.tasks[tidx].in_use {
            return Err(Error::NotFound);
        }
        let cred_idx = self.tasks[tidx].active_cred_id as usize;
        Ok(&self.slots[cred_idx].cred)
    }

    /// Modify the prepared credential's UID fields.
    pub fn set_uid(&mut self, cred_id: u64, uid: u32, euid: u32, suid: u32) -> Result<()> {
        let idx = cred_id as usize;
        if idx >= MAX_CREDS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state != CredState::Prepared {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].cred.uid = uid;
        self.slots[idx].cred.euid = euid;
        self.slots[idx].cred.suid = suid;
        self.slots[idx].cred.fsuid = euid;
        Ok(())
    }

    /// Modify the prepared credential's GID fields.
    pub fn set_gid(&mut self, cred_id: u64, gid: u32, egid: u32, sgid: u32) -> Result<()> {
        let idx = cred_id as usize;
        if idx >= MAX_CREDS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state != CredState::Prepared {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].cred.gid = gid;
        self.slots[idx].cred.egid = egid;
        self.slots[idx].cred.sgid = sgid;
        self.slots[idx].cred.fsgid = egid;
        Ok(())
    }

    /// Increment refcount on a credential for sharing.
    pub fn get_cred_ref(&mut self, cred_id: u64) -> Result<()> {
        let idx = cred_id as usize;
        if idx >= MAX_CREDS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state != CredState::Active {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].ref_count += 1;
        Ok(())
    }

    /// Unregister a task and release its credentials.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        let tidx = task_id as usize;
        if tidx >= MAX_TASKS || !self.tasks[tidx].in_use {
            return Err(Error::NotFound);
        }
        let active_idx = self.tasks[tidx].active_cred_id as usize;
        self.put_cred(active_idx);
        let prep_id = self.tasks[tidx].prepared_cred_id;
        if prep_id != 0 {
            let _ = self.abort_creds(prep_id);
        }
        self.tasks[tidx].in_use = false;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        Ok(())
    }

    /// Return allocator statistics.
    pub fn stats(&self) -> &CredAllocStats {
        &self.stats
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Allocate a free slot and populate it.
    fn alloc_slot(&mut self, cred: Cred, owner: u64) -> Result<usize> {
        let pos = self
            .slots
            .iter()
            .position(|s| s.state == CredState::Free)
            .ok_or(Error::OutOfMemory)?;
        let cur_gen = self.next_generation;
        self.next_generation += 1;
        self.slots[pos] = CredSlot {
            cred,
            ref_count: 0,
            state: CredState::Free,
            generation: cur_gen,
            owner_task: owner,
        };
        self.stats.total_allocs += 1;
        Ok(pos)
    }

    /// Decrement refcount and retire/free if zero.
    fn put_cred(&mut self, idx: usize) {
        if idx >= MAX_CREDS {
            return;
        }
        let slot = &mut self.slots[idx];
        slot.ref_count = slot.ref_count.saturating_sub(1);
        if slot.ref_count == 0 {
            slot.state = CredState::Free;
            self.stats.total_frees += 1;
        } else {
            slot.state = CredState::Retired;
        }
    }
}
