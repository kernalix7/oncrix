// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `semget(2)`, `semop(2)`, and `semctl(2)` syscall handlers.
//!
//! System V semaphore interface.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `semget()` specification.  Key behaviours:
//! - `IPC_PRIVATE` always creates a new semaphore set.
//! - `SEMMSL` limits the number of semaphores per set.
//! - `semop` adjusts semaphore values atomically.
//! - `semctl(GETVAL)` / `SETVAL` operate on individual semaphores.
//! - `semctl(IPC_RMID)` removes the set.
//!
//! # References
//!
//! - POSIX.1-2024: `semget()`
//! - Linux man pages: `semget(2)`, `semop(2)`, `semctl(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Create if not exists.
pub const IPC_CREAT: i32 = 0o1000;
/// Fail if already exists.
pub const IPC_EXCL: i32 = 0o2000;
/// Private key.
pub const IPC_PRIVATE: i32 = 0;
/// Remove semaphore set.
pub const IPC_RMID: i32 = 0;
/// Get individual semaphore value.
pub const GETVAL: i32 = 12;
/// Set individual semaphore value.
pub const SETVAL: i32 = 16;
/// Get all semaphore values.
pub const GETALL: i32 = 13;

/// Maximum semaphores per set.
pub const SEMMSL: usize = 32;
/// Maximum semaphore sets.
pub const SEMMNI: usize = 32;
/// Maximum semaphore value.
pub const SEMVMX: i16 = 32767;

// ---------------------------------------------------------------------------
// Sembuf
// ---------------------------------------------------------------------------

/// A single semaphore operation (`struct sembuf`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sembuf {
    /// Semaphore number within the set.
    pub sem_num: u16,
    /// Operation value.
    pub sem_op: i16,
    /// Operation flags (`IPC_NOWAIT`, `SEM_UNDO`).
    pub sem_flg: i16,
}

/// No-wait flag for `semop`.
pub const IPC_NOWAIT: i16 = 0o4000;

// ---------------------------------------------------------------------------
// Semaphore set
// ---------------------------------------------------------------------------

/// A System V semaphore set.
#[derive(Debug, Clone, Copy)]
pub struct SemSet {
    /// IPC key.
    pub key: i32,
    /// Semaphore set ID.
    pub id: i32,
    /// Number of semaphores in this set.
    pub nsems: usize,
    /// Semaphore values.
    pub values: [i16; SEMMSL],
    /// Permission mode.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
}

/// Table of System V semaphore sets.
pub struct SemTable {
    sets: [Option<SemSet>; SEMMNI],
    next_id: i32,
}

impl Default for SemTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SemTable {
    /// Create an empty semaphore table.
    pub const fn new() -> Self {
        Self {
            sets: [const { None }; SEMMNI],
            next_id: 1,
        }
    }

    fn find_by_key(&self, key: i32) -> Option<usize> {
        self.sets
            .iter()
            .position(|s| s.as_ref().map_or(false, |ss| ss.key == key))
    }

    fn find_by_id(&self, id: i32) -> Option<usize> {
        self.sets
            .iter()
            .position(|s| s.as_ref().map_or(false, |ss| ss.id == id))
    }

    fn alloc_slot(&self) -> Option<usize> {
        self.sets.iter().position(|s| s.is_none())
    }

    /// Look up a set by semid.
    pub fn get(&self, id: i32) -> Option<&SemSet> {
        let idx = self.find_by_id(id)?;
        self.sets[idx].as_ref()
    }

    /// Look up a set mutably by semid.
    pub fn get_mut(&mut self, id: i32) -> Option<&mut SemSet> {
        let idx = self.find_by_id(id)?;
        self.sets[idx].as_mut()
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `semget(2)`.
///
/// # Errors
///
/// | `Error`         | Condition                                       |
/// |-----------------|-------------------------------------------------|
/// | `InvalidArgument` | `nsems` out of `[1, SEMMSL]` for new sets     |
/// | `AlreadyExists` | `IPC_CREAT|IPC_EXCL` and key already exists     |
/// | `NotFound`      | Key not found and `IPC_CREAT` not set           |
/// | `OutOfMemory`   | Set table is full                               |
pub fn do_semget(
    table: &mut SemTable,
    key: i32,
    nsems: usize,
    semflg: i32,
    uid: u32,
) -> Result<i32> {
    let creat = semflg & IPC_CREAT != 0;
    let excl = semflg & IPC_EXCL != 0;
    let mode = (semflg & 0o777) as u16;

    if key == IPC_PRIVATE {
        if nsems == 0 || nsems > SEMMSL {
            return Err(Error::InvalidArgument);
        }
        let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
        let id = table.next_id;
        table.next_id += 1;
        table.sets[slot] = Some(SemSet {
            key,
            id,
            nsems,
            values: [0i16; SEMMSL],
            mode,
            uid,
        });
        return Ok(id);
    }

    if let Some(idx) = table.find_by_key(key) {
        if creat && excl {
            return Err(Error::AlreadyExists);
        }
        return Ok(table.sets[idx].as_ref().unwrap().id);
    }

    if !creat {
        return Err(Error::NotFound);
    }

    if nsems == 0 || nsems > SEMMSL {
        return Err(Error::InvalidArgument);
    }
    let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
    let id = table.next_id;
    table.next_id += 1;
    table.sets[slot] = Some(SemSet {
        key,
        id,
        nsems,
        values: [0i16; SEMMSL],
        mode,
        uid,
    });
    Ok(id)
}

/// Handler for `semop(2)`.
///
/// Applies `ops` to the semaphore set `semid`.  Fails if any operation
/// would result in a negative value (unless `IPC_NOWAIT` is set).
///
/// # Errors
///
/// | `Error`         | Condition                                  |
/// |-----------------|--------------------------------------------|
/// | `NotFound`      | `semid` is invalid                         |
/// | `InvalidArgument` | `sem_num` out of range                   |
/// | `WouldBlock`    | Operation would block and `IPC_NOWAIT` set |
pub fn do_semop(table: &mut SemTable, semid: i32, ops: &[Sembuf]) -> Result<()> {
    let idx = table.find_by_id(semid).ok_or(Error::NotFound)?;
    let set = table.sets[idx].as_ref().unwrap();

    // Validate all ops first.
    for op in ops {
        if op.sem_num as usize >= set.nsems {
            return Err(Error::InvalidArgument);
        }
        let cur = set.values[op.sem_num as usize];
        let new_val = (cur as i32) + (op.sem_op as i32);
        if new_val < 0 {
            if op.sem_flg & IPC_NOWAIT != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel we'd block; here we return WouldBlock.
            return Err(Error::WouldBlock);
        }
        if new_val > SEMVMX as i32 {
            return Err(Error::InvalidArgument);
        }
    }

    // Apply ops.
    let set = table.sets[idx].as_mut().unwrap();
    for op in ops {
        let cur = set.values[op.sem_num as usize] as i32;
        set.values[op.sem_num as usize] = (cur + op.sem_op as i32) as i16;
    }
    Ok(())
}

/// Handler for `semctl(GETVAL)`.
pub fn do_semctl_getval(table: &SemTable, semid: i32, semnum: usize) -> Result<i16> {
    let set = table.get(semid).ok_or(Error::NotFound)?;
    if semnum >= set.nsems {
        return Err(Error::InvalidArgument);
    }
    Ok(set.values[semnum])
}

/// Handler for `semctl(SETVAL)`.
pub fn do_semctl_setval(table: &mut SemTable, semid: i32, semnum: usize, val: i16) -> Result<()> {
    if val < 0 || val > SEMVMX {
        return Err(Error::InvalidArgument);
    }
    let set = table.get_mut(semid).ok_or(Error::NotFound)?;
    if semnum >= set.nsems {
        return Err(Error::InvalidArgument);
    }
    set.values[semnum] = val;
    Ok(())
}

/// Handler for `semctl(IPC_RMID)`.
pub fn do_semctl_rmid(table: &mut SemTable, semid: i32) -> Result<()> {
    let idx = table.find_by_id(semid).ok_or(Error::NotFound)?;
    table.sets[idx] = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semget_private() {
        let mut t = SemTable::new();
        let id = do_semget(&mut t, IPC_PRIVATE, 3, 0o600, 1000).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn semctl_setval_getval() {
        let mut t = SemTable::new();
        let id = do_semget(&mut t, IPC_PRIVATE, 4, 0o600, 0).unwrap();
        do_semctl_setval(&mut t, id, 2, 10).unwrap();
        assert_eq!(do_semctl_getval(&t, id, 2).unwrap(), 10);
    }

    #[test]
    fn semop_ok() {
        let mut t = SemTable::new();
        let id = do_semget(&mut t, IPC_PRIVATE, 2, 0, 0).unwrap();
        do_semctl_setval(&mut t, id, 0, 5).unwrap();
        let ops = [Sembuf {
            sem_num: 0,
            sem_op: -3,
            sem_flg: 0,
        }];
        do_semop(&mut t, id, &ops).unwrap();
        assert_eq!(do_semctl_getval(&t, id, 0).unwrap(), 2);
    }

    #[test]
    fn semop_would_block() {
        let mut t = SemTable::new();
        let id = do_semget(&mut t, IPC_PRIVATE, 1, 0, 0).unwrap();
        let ops = [Sembuf {
            sem_num: 0,
            sem_op: -1,
            sem_flg: IPC_NOWAIT,
        }];
        assert_eq!(do_semop(&mut t, id, &ops), Err(Error::WouldBlock));
    }
}
