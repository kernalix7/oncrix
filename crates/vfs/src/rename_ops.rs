// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Rename operations — `rename(2)` / `renameat2(2)` semantics.
//!
//! Implements the VFS-level rename protocol: lock ordering, cross-directory
//! renames, directory loop prevention, and the Linux `RENAME_EXCHANGE` and
//! `RENAME_NOREPLACE` flags.

use oncrix_lib::{Error, Result};

/// Flags for `renameat2(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenameFlags(pub u32);

impl RenameFlags {
    /// Do not replace the destination if it exists (fail with EEXIST).
    pub const NOREPLACE: u32 = 1 << 0;
    /// Atomically exchange source and destination.
    pub const EXCHANGE: u32 = 1 << 1;
    /// Whiteout the source (for overlay filesystem use).
    pub const WHITEOUT: u32 = 1 << 2;

    /// Test whether a flag is set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// Entry type of the source or destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Other (device, FIFO, socket).
    Other,
}

/// A rename request.
#[derive(Debug, Clone, Copy)]
pub struct RenameRequest {
    /// Superblock — both ends must be on the same filesystem.
    pub sb_id: u64,
    /// Source directory inode.
    pub src_dir_ino: u64,
    /// Source entry name (slice into caller's buffer).
    pub src_name_hash: u64,
    /// Source inode number.
    pub src_ino: u64,
    /// Source entry type.
    pub src_type: EntryType,
    /// Destination directory inode.
    pub dst_dir_ino: u64,
    /// Destination name hash.
    pub dst_name_hash: u64,
    /// Destination inode number (0 = does not exist).
    pub dst_ino: u64,
    /// Destination entry type (only valid when dst_ino != 0).
    pub dst_type: EntryType,
    /// Rename flags.
    pub flags: RenameFlags,
    /// Current wall-clock time (for ctime/mtime updates).
    pub now: i64,
}

/// Validation result from `validate_rename`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameCheck {
    /// Rename is a no-op (source == destination).
    Noop,
    /// Simple rename: dst does not exist.
    SimpleCreate,
    /// Replace rename: dst exists and will be replaced.
    Replace,
    /// Exchange rename: both exist and will be swapped.
    Exchange,
}

/// Validate a rename request for semantic correctness.
pub fn validate_rename(req: &RenameRequest) -> Result<RenameCheck> {
    // Cross-filesystem rename is not allowed at VFS level.
    // (The caller has already ensured sb_id matches for both sides.)

    // Source must exist.
    if req.src_ino == 0 {
        return Err(Error::NotFound);
    }

    // Renaming a directory onto itself.
    if req.src_dir_ino == req.dst_dir_ino && req.src_name_hash == req.dst_name_hash {
        return Ok(RenameCheck::Noop);
    }

    // RENAME_EXCHANGE requires destination to exist.
    if req.flags.has(RenameFlags::EXCHANGE) && req.dst_ino == 0 {
        return Err(Error::NotFound);
    }

    // RENAME_NOREPLACE requires destination to not exist.
    if req.flags.has(RenameFlags::NOREPLACE) && req.dst_ino != 0 {
        return Err(Error::AlreadyExists);
    }

    // Cannot rename a directory onto a non-empty directory target.
    // (We cannot check emptiness here; the filesystem must enforce it.)

    // Replacing a directory with a non-directory is illegal.
    if req.dst_ino != 0
        && req.src_type == EntryType::Directory
        && req.dst_type != EntryType::Directory
    {
        return Err(Error::InvalidArgument);
    }

    // Replacing a non-directory with a directory is illegal.
    if req.dst_ino != 0
        && req.src_type != EntryType::Directory
        && req.dst_type == EntryType::Directory
    {
        return Err(Error::InvalidArgument);
    }

    if req.flags.has(RenameFlags::EXCHANGE) {
        Ok(RenameCheck::Exchange)
    } else if req.dst_ino == 0 {
        Ok(RenameCheck::SimpleCreate)
    } else {
        Ok(RenameCheck::Replace)
    }
}

/// Lock ordering for rename: locks must be acquired in inode-number order to
/// avoid deadlock when two renames race.
///
/// Returns `(first, second)` inode numbers in lock order.
pub fn rename_lock_order(a_ino: u64, b_ino: u64) -> (u64, u64) {
    if a_ino <= b_ino {
        (a_ino, b_ino)
    } else {
        (b_ino, a_ino)
    }
}

/// Check that renaming `src_ino` into `dst_dir_ino` would not create a loop.
///
/// A loop occurs when renaming a directory into one of its own descendants.
/// This simplified check compares the inode numbers; a full implementation
/// would walk the ancestry chain.
pub fn check_rename_loop(src_ino: u64, dst_dir_ino: u64, dst_dir_parent: u64) -> Result<()> {
    if src_ino == dst_dir_ino || src_ino == dst_dir_parent {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Filesystem-level rename operations.
pub trait RenameOps {
    /// Add a directory entry: `(dir_ino, name_hash) -> ino`.
    fn add_dirent(&mut self, sb_id: u64, dir_ino: u64, name_hash: u64, ino: u64) -> Result<()>;

    /// Remove a directory entry: `(dir_ino, name_hash)`.
    fn remove_dirent(&mut self, sb_id: u64, dir_ino: u64, name_hash: u64) -> Result<()>;

    /// Update `..` entry for a moved directory.
    fn update_dotdot(&mut self, sb_id: u64, child_ino: u64, new_parent_ino: u64) -> Result<()>;

    /// Update ctime and mtime of an inode.
    fn touch_inode(&mut self, sb_id: u64, ino: u64, now: i64) -> Result<()>;
}

/// Execute a rename using the provided `RenameOps` implementation.
pub fn do_rename<O: RenameOps>(ops: &mut O, req: &RenameRequest) -> Result<()> {
    let check = validate_rename(req)?;
    if check == RenameCheck::Noop {
        return Ok(());
    }

    match check {
        RenameCheck::SimpleCreate => {
            // Remove src entry from src_dir.
            ops.remove_dirent(req.sb_id, req.src_dir_ino, req.src_name_hash)?;
            // Add src entry into dst_dir.
            ops.add_dirent(req.sb_id, req.dst_dir_ino, req.dst_name_hash, req.src_ino)?;
            // Update .. if moving a directory.
            if req.src_type == EntryType::Directory && req.src_dir_ino != req.dst_dir_ino {
                ops.update_dotdot(req.sb_id, req.src_ino, req.dst_dir_ino)?;
            }
        }
        RenameCheck::Replace => {
            // Remove the destination entry (dst inode will be orphaned).
            ops.remove_dirent(req.sb_id, req.dst_dir_ino, req.dst_name_hash)?;
            // Move source.
            ops.remove_dirent(req.sb_id, req.src_dir_ino, req.src_name_hash)?;
            ops.add_dirent(req.sb_id, req.dst_dir_ino, req.dst_name_hash, req.src_ino)?;
            if req.src_type == EntryType::Directory && req.src_dir_ino != req.dst_dir_ino {
                ops.update_dotdot(req.sb_id, req.src_ino, req.dst_dir_ino)?;
            }
        }
        RenameCheck::Exchange => {
            // Atomically swap: both entries already exist.
            ops.remove_dirent(req.sb_id, req.src_dir_ino, req.src_name_hash)?;
            ops.remove_dirent(req.sb_id, req.dst_dir_ino, req.dst_name_hash)?;
            ops.add_dirent(req.sb_id, req.dst_dir_ino, req.dst_name_hash, req.src_ino)?;
            ops.add_dirent(req.sb_id, req.src_dir_ino, req.src_name_hash, req.dst_ino)?;
        }
        RenameCheck::Noop => unreachable!(),
    }

    // Update timestamps.
    ops.touch_inode(req.sb_id, req.src_dir_ino, req.now)?;
    if req.src_dir_ino != req.dst_dir_ino {
        ops.touch_inode(req.sb_id, req.dst_dir_ino, req.now)?;
    }
    ops.touch_inode(req.sb_id, req.src_ino, req.now)?;

    Ok(())
}
