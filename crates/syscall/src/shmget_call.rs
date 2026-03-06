// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shmget(2)`, `shmat(2)`, `shmdt(2)`, and `shmctl(2)` syscall handlers.
//!
//! System V shared memory interface.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `shmget()` specification.  Key behaviours:
//! - `IPC_PRIVATE` (key == 0) always creates a new segment.
//! - `IPC_CREAT | IPC_EXCL` fails with `EEXIST` if the key already exists.
//! - `size` of 0 is only valid when attaching to an existing segment.
//! - Permission bits in `shmflg` (lower 9 bits) control access.
//! - `shmctl(IPC_RMID)` marks the segment for removal after last detach.
//!
//! # References
//!
//! - POSIX.1-2024: `shmget()`
//! - Linux man pages: `shmget(2)`, `shmat(2)`, `shmctl(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Create segment if key doesn't exist.
pub const IPC_CREAT: i32 = 0o1000;
/// Fail if segment already exists.
pub const IPC_EXCL: i32 = 0o2000;
/// Private (unique) key.
pub const IPC_PRIVATE: i32 = 0;
/// Remove identifier.
pub const IPC_RMID: i32 = 0;
/// Set options.
pub const IPC_SET: i32 = 1;
/// Get statistics.
pub const IPC_STAT: i32 = 2;
/// Attach read-only.
pub const SHM_RDONLY: i32 = 0o10000;
/// Attach at rounded address.
pub const SHM_RND: i32 = 0o20000;

/// Maximum number of System V shared memory segments.
pub const SHMMNI: usize = 64;
/// Maximum shared memory segment size (32 MiB).
pub const SHMMAX: usize = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Segment metadata
// ---------------------------------------------------------------------------

/// System V shared memory segment descriptor.
#[derive(Debug, Clone, Copy)]
pub struct ShmSegment {
    /// IPC key.
    pub key: i32,
    /// Segment ID (shmid).
    pub id: i32,
    /// Size in bytes.
    pub size: usize,
    /// Permission mode bits.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Creator UID.
    pub cuid: u32,
    /// Current attach count.
    pub nattch: u32,
    /// Marked for removal.
    pub removed: bool,
}

/// Table of System V shared memory segments.
pub struct ShmTable {
    segments: [Option<ShmSegment>; SHMMNI],
    next_id: i32,
}

impl Default for ShmTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ShmTable {
    /// Create an empty shared memory table.
    pub const fn new() -> Self {
        Self {
            segments: [const { None }; SHMMNI],
            next_id: 1,
        }
    }

    fn find_by_key(&self, key: i32) -> Option<usize> {
        self.segments.iter().position(|s| {
            s.as_ref()
                .map_or(false, |seg| seg.key == key && !seg.removed)
        })
    }

    fn find_by_id(&self, id: i32) -> Option<usize> {
        self.segments
            .iter()
            .position(|s| s.as_ref().map_or(false, |seg| seg.id == id))
    }

    fn alloc_slot(&self) -> Option<usize> {
        self.segments.iter().position(|s| s.is_none())
    }

    /// Look up a segment by shmid.
    pub fn get(&self, id: i32) -> Option<&ShmSegment> {
        let idx = self.find_by_id(id)?;
        self.segments[idx].as_ref()
    }

    /// Look up a segment mutably by shmid.
    pub fn get_mut(&mut self, id: i32) -> Option<&mut ShmSegment> {
        let idx = self.find_by_id(id)?;
        self.segments[idx].as_mut()
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `shmget(2)`.
///
/// Returns the shmid of the segment identified by `key` / `size` / `shmflg`.
///
/// # Errors
///
/// | `Error`         | Condition                                        |
/// |-----------------|--------------------------------------------------|
/// | `InvalidArgument` | `size` exceeds `SHMMAX` or is 0 for new segment|
/// | `AlreadyExists` | `IPC_CREAT|IPC_EXCL` and key already exists      |
/// | `NotFound`      | Key not found and `IPC_CREAT` not set            |
/// | `OutOfMemory`   | Segment table is full                            |
pub fn do_shmget(
    table: &mut ShmTable,
    key: i32,
    size: usize,
    shmflg: i32,
    uid: u32,
) -> Result<i32> {
    let creat = shmflg & IPC_CREAT != 0;
    let excl = shmflg & IPC_EXCL != 0;
    let mode = (shmflg & 0o777) as u16;

    // IPC_PRIVATE always creates a new segment.
    if key == IPC_PRIVATE {
        if size == 0 || size > SHMMAX {
            return Err(Error::InvalidArgument);
        }
        let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
        let id = table.next_id;
        table.next_id += 1;
        table.segments[slot] = Some(ShmSegment {
            key,
            id,
            size,
            mode,
            uid,
            cuid: uid,
            nattch: 0,
            removed: false,
        });
        return Ok(id);
    }

    // Check if key already exists.
    if let Some(idx) = table.find_by_key(key) {
        if creat && excl {
            return Err(Error::AlreadyExists);
        }
        return Ok(table.segments[idx].as_ref().unwrap().id);
    }

    // Key not found.
    if !creat {
        return Err(Error::NotFound);
    }

    // Create new segment.
    if size == 0 || size > SHMMAX {
        return Err(Error::InvalidArgument);
    }
    let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
    let id = table.next_id;
    table.next_id += 1;
    table.segments[slot] = Some(ShmSegment {
        key,
        id,
        size,
        mode,
        uid,
        cuid: uid,
        nattch: 0,
        removed: false,
    });
    Ok(id)
}

/// Handler for `shmctl(IPC_RMID)` — mark segment for removal.
///
/// # Errors
///
/// Returns `Err(NotFound)` if `shmid` is invalid.
pub fn do_shmctl_rmid(table: &mut ShmTable, shmid: i32) -> Result<()> {
    let seg = table.get_mut(shmid).ok_or(Error::NotFound)?;
    seg.removed = true;
    Ok(())
}

/// Record an attach to `shmid`.
pub fn do_shmat(table: &mut ShmTable, shmid: i32) -> Result<()> {
    let seg = table.get_mut(shmid).ok_or(Error::NotFound)?;
    if seg.removed {
        return Err(Error::NotFound);
    }
    seg.nattch = seg.nattch.saturating_add(1);
    Ok(())
}

/// Record a detach from `shmid`.
pub fn do_shmdt(table: &mut ShmTable, shmid: i32) -> Result<()> {
    let seg = table.get_mut(shmid).ok_or(Error::NotFound)?;
    seg.nattch = seg.nattch.saturating_sub(1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shmget_private() {
        let mut t = ShmTable::new();
        let id = do_shmget(&mut t, IPC_PRIVATE, 4096, 0o600, 1000).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn shmget_creat() {
        let mut t = ShmTable::new();
        let id = do_shmget(&mut t, 42, 8192, IPC_CREAT | 0o600, 1000).unwrap();
        // Second call with same key returns same id.
        let id2 = do_shmget(&mut t, 42, 8192, IPC_CREAT | 0o600, 1000).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn shmget_excl_conflict() {
        let mut t = ShmTable::new();
        do_shmget(&mut t, 99, 4096, IPC_CREAT | 0o600, 1000).unwrap();
        assert_eq!(
            do_shmget(&mut t, 99, 4096, IPC_CREAT | IPC_EXCL | 0o600, 1000),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn shmget_no_creat_not_found() {
        let mut t = ShmTable::new();
        assert_eq!(do_shmget(&mut t, 55, 4096, 0, 1000), Err(Error::NotFound));
    }

    #[test]
    fn shmat_shmdt() {
        let mut t = ShmTable::new();
        let id = do_shmget(&mut t, IPC_PRIVATE, 4096, 0, 0).unwrap();
        do_shmat(&mut t, id).unwrap();
        assert_eq!(t.get(id).unwrap().nattch, 1);
        do_shmdt(&mut t, id).unwrap();
        assert_eq!(t.get(id).unwrap().nattch, 0);
    }
}
