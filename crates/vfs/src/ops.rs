// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS high-level operations for syscall handlers.
//!
//! These functions bridge the syscall layer and the filesystem layer.
//! Each operation takes a file descriptor table and filesystem ops,
//! performs the requested I/O, and returns the result.

use crate::file::{Fd, FdTable, OpenFlags};
use crate::inode::InodeOps;
use oncrix_lib::{Error, Result};

/// Seek origin constants (POSIX whence values).
pub mod whence {
    /// Seek from the beginning of the file.
    pub const SEEK_SET: u64 = 0;
    /// Seek relative to the current position.
    pub const SEEK_CUR: u64 = 1;
    /// Seek relative to the end of the file.
    pub const SEEK_END: u64 = 2;
}

/// Read from a file descriptor.
///
/// Reads up to `buf.len()` bytes from the file associated with `fd`,
/// starting at the current offset. Updates the offset on success.
pub fn vfs_read(
    fd_table: &mut FdTable,
    fd: Fd,
    buf: &mut [u8],
    fs: &dyn InodeOps,
    inode_lookup: &dyn Fn(crate::inode::InodeNumber) -> Option<crate::inode::Inode>,
) -> Result<usize> {
    let open_file = fd_table.get(fd).ok_or(Error::InvalidArgument)?;
    let offset = open_file.offset;
    let ino = open_file.inode;

    let inode = inode_lookup(ino).ok_or(Error::NotFound)?;
    let bytes_read = fs.read(&inode, offset, buf)?;

    // Update the offset.
    if let Some(file) = fd_table.get_mut(fd) {
        file.offset += bytes_read as u64;
    }

    Ok(bytes_read)
}

/// Write to a file descriptor.
///
/// Writes up to `data.len()` bytes to the file associated with `fd`,
/// starting at the current offset (or end of file if O_APPEND).
/// Updates the offset on success.
pub fn vfs_write(
    fd_table: &mut FdTable,
    fd: Fd,
    data: &[u8],
    fs: &mut dyn InodeOps,
    inode_lookup: &dyn Fn(crate::inode::InodeNumber) -> Option<crate::inode::Inode>,
) -> Result<usize> {
    let open_file = fd_table.get(fd).ok_or(Error::InvalidArgument)?;
    let mut offset = open_file.offset;
    let ino = open_file.inode;
    let flags = open_file.flags;

    let inode = inode_lookup(ino).ok_or(Error::NotFound)?;

    // O_APPEND: always write at the end.
    if flags.0 & OpenFlags::O_APPEND.0 != 0 {
        offset = inode.size;
    }

    let bytes_written = fs.write(&inode, offset, data)?;

    // Update the offset.
    if let Some(file) = fd_table.get_mut(fd) {
        file.offset = offset + bytes_written as u64;
    }

    Ok(bytes_written)
}

/// Seek a file descriptor.
///
/// Repositions the file offset according to `whence`:
/// - `SEEK_SET`: offset is set to `off`
/// - `SEEK_CUR`: offset += `off`
/// - `SEEK_END`: offset = file_size + `off`
///
/// Returns the new offset.
pub fn vfs_lseek(
    fd_table: &mut FdTable,
    fd: Fd,
    off: i64,
    seek_whence: u64,
    inode_lookup: &dyn Fn(crate::inode::InodeNumber) -> Option<crate::inode::Inode>,
) -> Result<u64> {
    let open_file = fd_table.get(fd).ok_or(Error::InvalidArgument)?;
    let current_offset = open_file.offset;
    let ino = open_file.inode;

    let new_offset = match seek_whence {
        whence::SEEK_SET => {
            if off < 0 {
                return Err(Error::InvalidArgument);
            }
            off as u64
        }
        whence::SEEK_CUR => {
            if off < 0 {
                // Use checked_neg to handle i64::MIN safely.
                let abs_off = off.checked_neg().ok_or(Error::InvalidArgument)? as u64;
                current_offset
                    .checked_sub(abs_off)
                    .ok_or(Error::InvalidArgument)?
            } else {
                current_offset
                    .checked_add(off as u64)
                    .ok_or(Error::InvalidArgument)?
            }
        }
        whence::SEEK_END => {
            let inode = inode_lookup(ino).ok_or(Error::NotFound)?;
            let size = inode.size;
            if off < 0 {
                let abs_off = off.checked_neg().ok_or(Error::InvalidArgument)? as u64;
                size.checked_sub(abs_off).ok_or(Error::InvalidArgument)?
            } else {
                size.checked_add(off as u64).ok_or(Error::InvalidArgument)?
            }
        }
        _ => return Err(Error::InvalidArgument),
    };

    if let Some(file) = fd_table.get_mut(fd) {
        file.offset = new_offset;
    }

    Ok(new_offset)
}

/// Get file status (stat) from an inode.
///
/// Fills a stat-like structure from the inode metadata.
pub fn vfs_stat(inode: &crate::inode::Inode) -> StatInfo {
    StatInfo {
        ino: inode.ino.0,
        mode: encode_mode(inode.file_type, inode.mode),
        nlink: inode.nlink,
        uid: inode.uid,
        gid: inode.gid,
        size: inode.size,
    }
}

/// Simplified stat result.
#[derive(Debug, Clone, Copy)]
pub struct StatInfo {
    /// Inode number.
    pub ino: u64,
    /// File mode (type + permissions encoded as a u32).
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
}

/// Encode file type and mode into a single u32 (POSIX st_mode).
fn encode_mode(file_type: crate::inode::FileType, mode: crate::inode::FileMode) -> u32 {
    let type_bits: u32 = match file_type {
        crate::inode::FileType::Regular => 0o100000,
        crate::inode::FileType::Directory => 0o040000,
        crate::inode::FileType::Symlink => 0o120000,
        crate::inode::FileType::CharDevice => 0o020000,
        crate::inode::FileType::BlockDevice => 0o060000,
        crate::inode::FileType::Fifo => 0o010000,
        crate::inode::FileType::Socket => 0o140000,
    };
    type_bits | (mode.0 as u32)
}
