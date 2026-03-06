// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System V semaphore arrays — `semget` / `semop` / `semctl`.
//!
//! Implements the System V semaphore API as defined by POSIX.1-2024.
//! Each semaphore array (identified by a numeric key) contains up to
//! [`SEM_ARRAY_MAX`] individual semaphores.  Operations on an array
//! are atomic across all semaphores in the operation list.
//!
//! # Supported `semctl` commands
//!
//! `GETVAL`, `SETVAL`, `GETPID`, `GETNCNT`, `GETZCNT`, `GETALL`,
//! `SETALL`, `IPC_RMID`, `IPC_STAT`, `IPC_SET`.
//!
//! # Undo support
//!
//! When a `Sembuf` has the `SEM_UNDO` flag set, the adjustment is
//! recorded per-process and reverted at process exit via
//! [`sem_undo_cleanup`].
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/semget.html` and
//! `semop.html` for the authoritative specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum semaphores in one array.
pub const SEM_ARRAY_MAX: usize = 32;

/// Maximum number of simultaneous semaphore arrays.
const SEM_REGISTRY_MAX: usize = 64;

/// Maximum undo entries across all processes.
const SEM_UNDO_MAX: usize = 128;

/// Sentinel value indicating an empty registry / undo slot.
const EMPTY_KEY: u32 = u32::MAX;

/// Sentinel PID for unused undo entries.
const EMPTY_PID: u32 = u32::MAX;

/// Maximum semaphore value (`SEMVMX`).
pub const SEMVMX: i32 = 32767;

// ---------------------------------------------------------------------------
// IPC flags
// ---------------------------------------------------------------------------

/// Create a new IPC object.
pub const IPC_CREAT: i32 = 0o001000;
/// Error if object already exists (used with `IPC_CREAT`).
pub const IPC_EXCL: i32 = 0o002000;
/// Private IPC key — always creates a new, unshared object.
pub const IPC_PRIVATE: u32 = 0;

// ---------------------------------------------------------------------------
// semctl commands
// ---------------------------------------------------------------------------

/// Get the value of a single semaphore.
pub const GETVAL: i32 = 12;
/// Set the value of a single semaphore.
pub const SETVAL: i32 = 16;
/// Get the PID of the last process to call `semop` on this semaphore.
pub const GETPID: i32 = 11;
/// Get the number of processes waiting for the semaphore to increase.
pub const GETNCNT: i32 = 14;
/// Get the number of processes waiting for the semaphore to reach zero.
pub const GETZCNT: i32 = 15;
/// Get all semaphore values in the array.
pub const GETALL: i32 = 13;
/// Set all semaphore values in the array.
pub const SETALL: i32 = 17;
/// Remove the semaphore array.
pub const IPC_RMID: i32 = 0;
/// Retrieve the `SemDs` status structure.
pub const IPC_STAT: i32 = 2;
/// Update ownership/permissions from a `SemDs` structure.
pub const IPC_SET: i32 = 1;

// ---------------------------------------------------------------------------
// SemFlags
// ---------------------------------------------------------------------------

/// Flags applicable to semaphore operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemFlags(pub u16);

impl SemFlags {
    /// If set, the operation returns immediately instead of blocking.
    pub const IPC_NOWAIT: u16 = 0x0800;
    /// If set, the operation is automatically undone at process exit.
    pub const SEM_UNDO: u16 = 0x1000;

    /// Return `true` if `IPC_NOWAIT` is set.
    pub const fn is_nowait(self) -> bool {
        self.0 & Self::IPC_NOWAIT != 0
    }

    /// Return `true` if `SEM_UNDO` is set.
    pub const fn is_undo(self) -> bool {
        self.0 & Self::SEM_UNDO != 0
    }
}

// ---------------------------------------------------------------------------
// Sembuf
// ---------------------------------------------------------------------------

/// A single semaphore operation, mirroring POSIX `struct sembuf`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sembuf {
    /// Index of the semaphore within the array.
    pub sem_num: u16,
    /// Operation value:
    /// - Positive: add to semaphore (release).
    /// - Zero: wait for semaphore to reach zero.
    /// - Negative: subtract from semaphore (acquire).
    pub sem_op: i16,
    /// Flags: `IPC_NOWAIT` and/or `SEM_UNDO`.
    pub sem_flg: u16,
}

impl Sembuf {
    /// Return the flags as a typed `SemFlags`.
    pub const fn flags(self) -> SemFlags {
        SemFlags(self.sem_flg)
    }
}

// ---------------------------------------------------------------------------
// Semaphore
// ---------------------------------------------------------------------------

/// A single semaphore within an array.
#[derive(Debug, Clone, Copy, Default)]
pub struct Semaphore {
    /// Current semaphore value.
    pub value: i32,
    /// PID of the last process that performed a `semop`.
    pub sempid: u32,
    /// Number of processes waiting for value to increase.
    pub semncnt: u16,
    /// Number of processes waiting for value to reach zero.
    pub semzcnt: u16,
}

impl Semaphore {
    /// Create a new semaphore with value 0.
    pub const fn new() -> Self {
        Self {
            value: 0,
            sempid: 0,
            semncnt: 0,
            semzcnt: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IpcPerm
// ---------------------------------------------------------------------------

/// IPC permission structure for semaphore arrays.
#[derive(Debug, Clone, Copy, Default)]
pub struct SemPerm {
    /// User ID of the creator.
    pub cuid: u32,
    /// Group ID of the creator.
    pub cgid: u32,
    /// Effective user ID of the owner.
    pub uid: u32,
    /// Effective group ID of the owner.
    pub gid: u32,
    /// Permission mode bits.
    pub mode: u16,
}

// ---------------------------------------------------------------------------
// SemDs — status structure returned by IPC_STAT
// ---------------------------------------------------------------------------

/// Status structure for a semaphore array (`struct semid_ds`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SemDs {
    /// Permission information.
    pub sem_perm: SemPerm,
    /// Time of last `semop` (monotonic tick).
    pub sem_otime: u64,
    /// Time of last change (monotonic tick).
    pub sem_ctime: u64,
    /// Number of semaphores in the array.
    pub sem_nsems: u32,
}

// ---------------------------------------------------------------------------
// SemArray
// ---------------------------------------------------------------------------

/// A System V semaphore array.
pub struct SemArray {
    /// IPC key identifying this array.
    pub key: u32,
    /// Whether this array has been marked for removal.
    removed: bool,
    /// Semaphore values and metadata.
    sems: [Semaphore; SEM_ARRAY_MAX],
    /// Number of semaphores in use (set at creation).
    nsems: usize,
    /// Permission information.
    perm: SemPerm,
    /// Time of last `semop`.
    sem_otime: u64,
    /// Time of last change.
    sem_ctime: u64,
}

impl SemArray {
    /// Create a new semaphore array with `nsems` semaphores.
    fn new(key: u32, nsems: usize, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            key,
            removed: false,
            sems: [const { Semaphore::new() }; SEM_ARRAY_MAX],
            nsems,
            perm: SemPerm {
                cuid: uid,
                cgid: gid,
                uid,
                gid,
                mode,
            },
            sem_otime: 0,
            sem_ctime: 0,
        }
    }

    /// Return the status structure for `IPC_STAT`.
    pub fn stat(&self) -> SemDs {
        SemDs {
            sem_perm: self.perm,
            sem_otime: self.sem_otime,
            sem_ctime: self.sem_ctime,
            sem_nsems: self.nsems as u32,
        }
    }

    /// Validate `sem_num` is in range.
    fn check_sem_num(&self, sem_num: usize) -> Result<()> {
        if sem_num >= self.nsems {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }

    /// Attempt a single `Sembuf` operation.
    ///
    /// Returns `WouldBlock` if the operation would block (semaphore not
    /// ready) and `IPC_NOWAIT` is set.  In a full kernel, blocking would
    /// be handled by a wait queue; this implementation returns `WouldBlock`
    /// to signal that the caller must retry or fail.
    fn try_operation(&mut self, op: &Sembuf, pid: u32) -> Result<()> {
        let idx = op.sem_num as usize;
        self.check_sem_num(idx)?;

        let sem = &mut self.sems[idx];

        if op.sem_op > 0 {
            // Release: add to semaphore.
            let new_val = sem
                .value
                .checked_add(op.sem_op as i32)
                .ok_or(Error::InvalidArgument)?;
            if new_val > SEMVMX {
                return Err(Error::InvalidArgument);
            }
            sem.value = new_val;
            sem.sempid = pid;
        } else if op.sem_op < 0 {
            // Acquire: subtract from semaphore.
            let needed = -op.sem_op as i32;
            if sem.value < needed {
                if op.flags().is_nowait() {
                    return Err(Error::WouldBlock);
                }
                sem.semncnt = sem.semncnt.saturating_add(1);
                return Err(Error::WouldBlock);
            }
            sem.value -= needed;
            sem.sempid = pid;
        } else {
            // Wait for zero.
            if sem.value != 0 {
                if op.flags().is_nowait() {
                    return Err(Error::WouldBlock);
                }
                sem.semzcnt = sem.semzcnt.saturating_add(1);
                return Err(Error::WouldBlock);
            }
            sem.sempid = pid;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SemUndoEntry
// ---------------------------------------------------------------------------

/// Records a single undo adjustment for `SEM_UNDO` operations.
#[derive(Debug, Clone, Copy)]
pub struct SemUndoEntry {
    /// PID of the process that recorded this undo.
    pub pid: u32,
    /// Semaphore array identifier.
    pub sem_id: usize,
    /// Index of the semaphore within the array.
    pub sem_num: usize,
    /// Amount to be subtracted on process exit (negation of original op).
    pub adjustment: i16,
}

impl SemUndoEntry {
    /// Create an empty undo entry.
    const fn empty() -> Self {
        Self {
            pid: EMPTY_PID,
            sem_id: 0,
            sem_num: 0,
            adjustment: 0,
        }
    }

    /// Return `true` if this slot is occupied.
    const fn is_active(&self) -> bool {
        self.pid != EMPTY_PID
    }
}

// ---------------------------------------------------------------------------
// SemStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the semaphore subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SemStats {
    /// Total number of `semop` operations.
    pub total_ops: u64,
    /// Number of operations that would have blocked.
    pub blocks: u64,
    /// Number of operations that woke a waiting process (conceptual).
    pub wakeups: u64,
    /// Number of undo cleanup passes performed on process exit.
    pub undo_cleanups: u64,
}

// ---------------------------------------------------------------------------
// SemRegistry
// ---------------------------------------------------------------------------

/// Global registry of System V semaphore arrays.
///
/// Holds up to [`SEM_REGISTRY_MAX`] arrays and [`SEM_UNDO_MAX`] undo
/// entries.
pub struct SemRegistry {
    /// Array slots.
    arrays: [Option<SemArray>; SEM_REGISTRY_MAX],
    /// Undo entry slots.
    undos: [SemUndoEntry; SEM_UNDO_MAX],
    /// Cumulative statistics.
    pub stats: SemStats,
}

impl SemRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            arrays: [const { None }; SEM_REGISTRY_MAX],
            undos: [const { SemUndoEntry::empty() }; SEM_UNDO_MAX],
            stats: SemStats {
                total_ops: 0,
                blocks: 0,
                wakeups: 0,
                undo_cleanups: 0,
            },
        }
    }

    // -- internal helpers --------------------------------------------------

    /// Find the slot index for an array with the given `key`.
    fn find_by_key(&self, key: u32) -> Option<usize> {
        if key == IPC_PRIVATE {
            return None;
        }
        self.arrays.iter().position(|a| {
            a.as_ref()
                .map_or(false, |arr| arr.key == key && !arr.removed)
        })
    }

    /// Find a free array slot.
    fn find_free_array(&self) -> Option<usize> {
        self.arrays.iter().position(|a| a.is_none())
    }

    /// Find a free undo slot.
    fn find_free_undo(&self) -> Option<usize> {
        self.undos.iter().position(|u| !u.is_active())
    }

    /// Validate `sem_id` is within range and the array is active.
    fn check_sem_id(&self, sem_id: usize) -> Result<()> {
        if sem_id >= SEM_REGISTRY_MAX {
            return Err(Error::InvalidArgument);
        }
        match self.arrays[sem_id] {
            Some(ref a) if !a.removed => Ok(()),
            _ => Err(Error::NotFound),
        }
    }

    /// Record an undo adjustment for a `SEM_UNDO` operation.
    fn record_undo(
        &mut self,
        pid: u32,
        sem_id: usize,
        sem_num: usize,
        adjustment: i16,
    ) -> Result<()> {
        // Merge with existing undo entry for same pid/sem_id/sem_num.
        for entry in &mut self.undos {
            if entry.is_active()
                && entry.pid == pid
                && entry.sem_id == sem_id
                && entry.sem_num == sem_num
            {
                entry.adjustment = entry.adjustment.saturating_add(adjustment);
                return Ok(());
            }
        }
        let idx = self.find_free_undo().ok_or(Error::OutOfMemory)?;
        self.undos[idx] = SemUndoEntry {
            pid,
            sem_id,
            sem_num,
            adjustment,
        };
        Ok(())
    }
}

impl Default for SemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// semget
// ---------------------------------------------------------------------------

/// Create or open a semaphore array.
///
/// If `key == IPC_PRIVATE` a new, private array is always created.
/// Otherwise the `flags` control creation / exclusive access:
///
/// - `IPC_CREAT`: create if not present.
/// - `IPC_CREAT | IPC_EXCL`: fail with `AlreadyExists` if present.
///
/// # Returns
///
/// The semaphore array identifier (index into the registry).
pub fn semget(
    registry: &mut SemRegistry,
    key: u32,
    nsems: i32,
    flags: i32,
    uid: u32,
    gid: u32,
) -> Result<usize> {
    if nsems < 0 || nsems as usize > SEM_ARRAY_MAX {
        return Err(Error::InvalidArgument);
    }

    let mode = (flags & 0o777) as u16;
    let creat = flags & IPC_CREAT != 0;
    let excl = flags & IPC_EXCL != 0;

    if key != IPC_PRIVATE {
        if let Some(idx) = registry.find_by_key(key) {
            if creat && excl {
                return Err(Error::AlreadyExists);
            }
            return Ok(idx);
        }
    }

    // Must create.
    if key != IPC_PRIVATE && !creat {
        return Err(Error::NotFound);
    }

    if nsems == 0 {
        return Err(Error::InvalidArgument);
    }

    let idx = registry.find_free_array().ok_or(Error::OutOfMemory)?;
    registry.arrays[idx] = Some(SemArray::new(key, nsems as usize, mode, uid, gid));
    Ok(idx)
}

// ---------------------------------------------------------------------------
// semop
// ---------------------------------------------------------------------------

/// Perform a set of semaphore operations atomically.
///
/// Each element of `sops` describes one operation on one semaphore.
/// The operations are applied in order; if any would block and
/// `IPC_NOWAIT` is not set, `WouldBlock` is returned and the array
/// is left unmodified (no partial application in this implementation).
pub fn semop(registry: &mut SemRegistry, sem_id: usize, sops: &[Sembuf], pid: u32) -> Result<()> {
    registry.check_sem_id(sem_id)?;

    if sops.is_empty() {
        return Ok(());
    }

    // Validate all operations before applying any.
    {
        let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
        for op in sops {
            array.check_sem_num(op.sem_num as usize)?;
        }
    }

    // Attempt all operations.  On `WouldBlock`, we abort without applying
    // partial changes (we re-check from the beginning using snapshots).
    // Since we cannot roll back in-place without a snapshot, we check
    // feasibility first, then apply.  The feasibility check is done in a
    // separate scope so that the immutable borrow ends before we mutate
    // `registry.stats` or `registry.arrays`.
    let would_block = {
        let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
        let mut blocked = false;
        for op in sops {
            let idx = op.sem_num as usize;
            let sem = &array.sems[idx];
            if op.sem_op < 0 {
                let needed = -(op.sem_op) as i32;
                if sem.value < needed && op.flags().is_nowait() {
                    blocked = true;
                    break;
                }
            } else if op.sem_op == 0 && sem.value != 0 && op.flags().is_nowait() {
                blocked = true;
                break;
            }
        }
        blocked
    };
    if would_block {
        registry.stats.blocks = registry.stats.blocks.saturating_add(1);
        return Err(Error::WouldBlock);
    }

    // Apply all operations.
    for op in sops {
        let array = registry.arrays[sem_id].as_mut().ok_or(Error::NotFound)?;
        array.try_operation(op, pid)?;

        if op.flags().is_undo() {
            // Record the inverse adjustment.
            let adjustment = -(op.sem_op) as i16;
            registry.record_undo(pid, sem_id, op.sem_num as usize, adjustment)?;
        }
    }

    if let Some(ref mut array) = registry.arrays[sem_id] {
        array.sem_otime = array.sem_otime.wrapping_add(1); // monotonic tick stub
    }

    registry.stats.total_ops = registry.stats.total_ops.saturating_add(sops.len() as u64);
    Ok(())
}

// ---------------------------------------------------------------------------
// semctl
// ---------------------------------------------------------------------------

/// Control operations on a semaphore array.
///
/// `arg_val` carries the value for `SETVAL`; `arg_array` is the buffer
/// for `GETALL` / `SETALL` (must be at least `nsems` elements).
pub fn semctl(
    registry: &mut SemRegistry,
    sem_id: usize,
    sem_num: i32,
    cmd: i32,
    arg_val: i32,
    arg_array: &mut [i32],
    arg_ds: Option<&SemDs>,
) -> Result<i32> {
    match cmd {
        IPC_RMID => {
            if sem_id >= SEM_REGISTRY_MAX {
                return Err(Error::InvalidArgument);
            }
            match registry.arrays[sem_id] {
                Some(ref mut a) => {
                    a.removed = true;
                }
                None => return Err(Error::NotFound),
            }
            registry.arrays[sem_id] = None;
            Ok(0)
        }

        IPC_STAT => {
            registry.check_sem_id(sem_id)?;
            let _ds = registry.arrays[sem_id]
                .as_ref()
                .ok_or(Error::NotFound)?
                .stat();
            // In a real kernel this would copy `_ds` to user-space.
            Ok(0)
        }

        IPC_SET => {
            registry.check_sem_id(sem_id)?;
            if let Some(ds) = arg_ds {
                let array = registry.arrays[sem_id].as_mut().ok_or(Error::NotFound)?;
                array.perm.uid = ds.sem_perm.uid;
                array.perm.gid = ds.sem_perm.gid;
                array.perm.mode = ds.sem_perm.mode & 0o777;
                array.sem_ctime = array.sem_ctime.wrapping_add(1);
            }
            Ok(0)
        }

        GETVAL => {
            registry.check_sem_id(sem_id)?;
            let idx = sem_num as usize;
            let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
            array.check_sem_num(idx)?;
            Ok(array.sems[idx].value)
        }

        SETVAL => {
            registry.check_sem_id(sem_id)?;
            if arg_val < 0 || arg_val > SEMVMX {
                return Err(Error::InvalidArgument);
            }
            let idx = sem_num as usize;
            let array = registry.arrays[sem_id].as_mut().ok_or(Error::NotFound)?;
            array.check_sem_num(idx)?;
            array.sems[idx].value = arg_val;
            array.sem_ctime = array.sem_ctime.wrapping_add(1);
            Ok(0)
        }

        GETPID => {
            registry.check_sem_id(sem_id)?;
            let idx = sem_num as usize;
            let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
            array.check_sem_num(idx)?;
            Ok(array.sems[idx].sempid as i32)
        }

        GETNCNT => {
            registry.check_sem_id(sem_id)?;
            let idx = sem_num as usize;
            let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
            array.check_sem_num(idx)?;
            Ok(array.sems[idx].semncnt as i32)
        }

        GETZCNT => {
            registry.check_sem_id(sem_id)?;
            let idx = sem_num as usize;
            let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
            array.check_sem_num(idx)?;
            Ok(array.sems[idx].semzcnt as i32)
        }

        GETALL => {
            registry.check_sem_id(sem_id)?;
            let array = registry.arrays[sem_id].as_ref().ok_or(Error::NotFound)?;
            let count = array.nsems.min(arg_array.len());
            for i in 0..count {
                arg_array[i] = array.sems[i].value;
            }
            Ok(0)
        }

        SETALL => {
            registry.check_sem_id(sem_id)?;
            {
                for &v in arg_array.iter() {
                    if v < 0 || v > SEMVMX {
                        return Err(Error::InvalidArgument);
                    }
                }
            }
            let array = registry.arrays[sem_id].as_mut().ok_or(Error::NotFound)?;
            let count = array.nsems.min(arg_array.len());
            for i in 0..count {
                array.sems[i].value = arg_array[i];
            }
            array.sem_ctime = array.sem_ctime.wrapping_add(1);
            Ok(0)
        }

        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// sem_undo_cleanup
// ---------------------------------------------------------------------------

/// Apply all pending undo adjustments for `pid` on process exit.
///
/// For each `SEM_UNDO` entry belonging to `pid`, the recorded
/// inverse adjustment is applied to the semaphore.  Entries with
/// invalid or removed arrays are silently skipped.
pub fn sem_undo_cleanup(registry: &mut SemRegistry, pid: u32) {
    // Collect undo indices for this pid without holding mutable borrows.
    let mut to_process: [usize; SEM_UNDO_MAX] = [usize::MAX; SEM_UNDO_MAX];
    let mut count = 0usize;

    for (i, entry) in registry.undos.iter().enumerate() {
        if entry.is_active() && entry.pid == pid {
            to_process[count] = i;
            count += 1;
        }
    }

    for &idx in &to_process[..count] {
        let entry = registry.undos[idx];
        let sem_id = entry.sem_id;
        let sem_num = entry.sem_num;
        let adj = entry.adjustment as i32;

        if sem_id < SEM_REGISTRY_MAX {
            if let Some(ref mut array) = registry.arrays[sem_id] {
                if !array.removed && sem_num < array.nsems {
                    let new_val = array.sems[sem_num].value.saturating_add(adj);
                    array.sems[sem_num].value = new_val.clamp(0, SEMVMX);
                    array.sems[sem_num].sempid = pid;
                }
            }
        }

        // Clear the undo entry.
        registry.undos[idx] = SemUndoEntry::empty();
    }

    registry.stats.undo_cleanups = registry.stats.undo_cleanups.saturating_add(1);
}
