// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 orphan inode list management.
//!
//! When a file is unlinked while still open, its inode is placed on the orphan
//! list stored in the superblock. On the next mount, the orphan list is
//! traversed and orphaned inodes are truncated and freed. This ensures that
//! resources are reclaimed even after an unclean shutdown.
//!
//! # Orphan List Structure
//!
//! The orphan list is a singly-linked list threaded through the inode table:
//!
//! ```text
//! superblock.s_last_orphan → inode_A.i_dtime → inode_B.i_dtime → 0
//! ```
//!
//! The `i_dtime` field of an orphan inode holds the inode number of the next
//! orphan, not a deletion timestamp. A value of 0 marks end-of-list.
//!
//! # References
//!
//! - Linux `fs/ext4/namei.c`, `fs/ext4/super.c` (ext4_orphan_add/del)
//! - ext4 disk layout: `Documentation/filesystems/ext4/`

use oncrix_lib::{Error, Result};

/// Maximum number of orphan inodes tracked in memory.
pub const MAX_ORPHAN_INODES: usize = 256;

/// State of the orphan inode list for one filesystem instance.
pub struct Ext4OrphanState {
    /// In-memory list of orphan inode numbers (inode numbers, 1-based).
    orphans: [u32; MAX_ORPHAN_INODES],
    /// Number of active entries in `orphans`.
    count: usize,
    /// Inode number stored in `s_last_orphan` of the on-disk superblock.
    last_orphan: u32,
}

impl Ext4OrphanState {
    /// Create a new, empty orphan state.
    pub const fn new() -> Self {
        Self {
            orphans: [0u32; MAX_ORPHAN_INODES],
            count: 0,
            last_orphan: 0,
        }
    }

    /// Add inode `ino` to the orphan list.
    ///
    /// Returns `AlreadyExists` if the inode is already on the list, or
    /// `OutOfMemory` if the in-memory list is full.
    pub fn add(&mut self, ino: u32) -> Result<()> {
        if ino == 0 {
            return Err(Error::InvalidArgument);
        }
        // Duplicate check.
        for i in 0..self.count {
            if self.orphans[i] == ino {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_ORPHAN_INODES {
            return Err(Error::OutOfMemory);
        }
        self.orphans[self.count] = ino;
        self.count += 1;
        self.last_orphan = ino;
        Ok(())
    }

    /// Remove inode `ino` from the orphan list.
    ///
    /// Returns `NotFound` if the inode was not on the list.
    pub fn remove(&mut self, ino: u32) -> Result<()> {
        let pos = self.orphans[..self.count].iter().position(|&x| x == ino);
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.orphans[idx] = self.orphans[self.count];
                self.orphans[self.count] = 0;
                // Recompute last_orphan.
                self.last_orphan = if self.count > 0 {
                    self.orphans[self.count - 1]
                } else {
                    0
                };
                Ok(())
            }
        }
    }

    /// Return the inode number that should be stored in `s_last_orphan`.
    pub fn last_orphan(&self) -> u32 {
        self.last_orphan
    }

    /// Number of orphans currently tracked.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate orphan inode numbers.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.orphans[..self.count].iter().copied()
    }

    /// Load the orphan list from the on-disk superblock field `s_last_orphan`.
    ///
    /// `read_inode_next` is a callback that, given an inode number, returns the
    /// value of that inode's `i_dtime` field (which encodes the next pointer).
    /// A return value of `0` means end-of-list.
    pub fn load_from_disk<F>(&mut self, s_last_orphan: u32, mut read_inode_next: F) -> Result<()>
    where
        F: FnMut(u32) -> Result<u32>,
    {
        self.count = 0;
        self.last_orphan = s_last_orphan;
        let mut cur = s_last_orphan;
        let mut steps = 0usize;
        while cur != 0 {
            if steps >= MAX_ORPHAN_INODES {
                // Cycle or excessively long list — bail out.
                return Err(Error::IoError);
            }
            if self.count >= MAX_ORPHAN_INODES {
                return Err(Error::OutOfMemory);
            }
            self.orphans[self.count] = cur;
            self.count += 1;
            cur = read_inode_next(cur)?;
            steps += 1;
        }
        Ok(())
    }
}

impl Default for Ext4OrphanState {
    fn default() -> Self {
        Self::new()
    }
}

/// Truncate and free an orphan inode, then remove it from the list.
///
/// `truncate_fn` is called to release all data blocks of the inode.
/// `free_inode_fn` is called to mark the inode as free in the inode bitmap.
/// Both callbacks receive the inode number.
pub fn recover_orphan<T, F>(
    state: &mut Ext4OrphanState,
    ino: u32,
    mut truncate_fn: T,
    mut free_inode_fn: F,
) -> Result<()>
where
    T: FnMut(u32) -> Result<()>,
    F: FnMut(u32) -> Result<()>,
{
    truncate_fn(ino)?;
    free_inode_fn(ino)?;
    state.remove(ino)
}

/// Recover all orphans recorded in `state`.
///
/// On success, `state.count()` will be 0.  On the first error, recovery stops
/// and the error is returned, leaving the remaining orphans in `state`.
pub fn recover_all_orphans<T, F>(
    state: &mut Ext4OrphanState,
    mut truncate_fn: T,
    mut free_inode_fn: F,
) -> Result<()>
where
    T: FnMut(u32) -> Result<()>,
    F: FnMut(u32) -> Result<()>,
{
    // Collect snapshot of current orphans to avoid borrow issues.
    let mut pending = [0u32; MAX_ORPHAN_INODES];
    let n = state.count();
    pending[..n].copy_from_slice(&state.orphans[..n]);

    for i in 0..n {
        let ino = pending[i];
        recover_orphan(state, ino, &mut truncate_fn, &mut free_inode_fn)?;
    }
    Ok(())
}

/// Encode the orphan linked-list next pointer into an inode's `i_dtime` field.
///
/// Returns the value to write into `i_dtime` for inode `ino` when inserting it
/// at the head of the list whose current head is `old_last_orphan`.
///
/// ext4 stores the *previous* head in each orphan's `i_dtime`, forming a
/// reverse singly-linked list.
pub fn encode_orphan_dtime(old_last_orphan: u32) -> u32 {
    old_last_orphan
}

/// Decode the next inode number from an orphan inode's `i_dtime` field.
///
/// Returns `0` if this is the tail of the list.
pub fn decode_orphan_next(i_dtime: u32) -> u32 {
    i_dtime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_remove() {
        let mut s = Ext4OrphanState::new();
        assert_eq!(s.count(), 0);
        s.add(10).unwrap();
        s.add(20).unwrap();
        assert_eq!(s.count(), 2);
        s.remove(10).unwrap();
        assert_eq!(s.count(), 1);
        assert!(s.iter().any(|x| x == 20));
    }

    #[test]
    fn duplicate_rejected() {
        let mut s = Ext4OrphanState::new();
        s.add(5).unwrap();
        assert!(matches!(s.add(5), Err(Error::AlreadyExists)));
    }

    #[test]
    fn remove_missing() {
        let mut s = Ext4OrphanState::new();
        assert!(matches!(s.remove(99), Err(Error::NotFound)));
    }
}
