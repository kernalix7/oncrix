// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Path resolution and VFS open operation.
//!
//! Resolves an absolute pathname like `/dev/console` by walking the
//! mount table and directory tree, calling `InodeOps::lookup` at
//! each component.

use crate::dentry::{Dentry, DentryCache, DentryName};
use crate::file::{Fd, FdTable, OpenFile, OpenFlags};
use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use crate::superblock::MountTable;
use oncrix_lib::{Error, Result};

/// Maximum path length (POSIX PATH_MAX).
pub const PATH_MAX: usize = 4096;

/// Maximum number of path components.
const MAX_COMPONENTS: usize = 64;

/// Split a path into components.
///
/// Returns the components as byte slices (without leading/trailing slashes).
/// The first component of an absolute path is empty (root).
pub fn split_path(path: &[u8]) -> ([&[u8]; MAX_COMPONENTS], usize) {
    let mut components: [&[u8]; MAX_COMPONENTS] = [&[]; MAX_COMPONENTS];
    let mut count = 0;

    // Skip leading slashes.
    let mut start = 0;
    while start < path.len() && path[start] == b'/' {
        start += 1;
    }

    while start < path.len() && count < MAX_COMPONENTS {
        // Find the next slash.
        let mut end = start;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }

        if end > start {
            components[count] = &path[start..end];
            count += 1;
        }

        // Skip trailing slashes.
        start = end;
        while start < path.len() && path[start] == b'/' {
            start += 1;
        }
    }

    (components, count)
}

/// Result of path resolution.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedPath {
    /// The inode of the resolved file/directory.
    pub inode: Inode,
    /// The inode of the parent directory.
    pub parent: Inode,
    /// Which mount point the file belongs to.
    pub mount_index: usize,
}

/// Resolve an absolute pathname to an inode.
///
/// Walks the path component by component, looking up each name in
/// the parent directory via `InodeOps::lookup`. Uses the mount table
/// to determine which filesystem handles each path prefix.
///
/// `fs_ops` is the filesystem operations for the root filesystem.
/// In a full kernel, each mount point would have its own ops.
pub fn resolve_path(
    path: &[u8],
    root_inode: &Inode,
    fs: &dyn InodeOps,
    _mount_table: &MountTable,
    _dcache: &DentryCache,
) -> Result<Inode> {
    if path.is_empty() || path[0] != b'/' {
        return Err(Error::InvalidArgument);
    }

    let (components, count) = split_path(path);

    if count == 0 {
        // Path is just "/".
        return Ok(*root_inode);
    }

    let mut current = *root_inode;

    for component in &components[..count] {
        // Current must be a directory to descend into.
        if current.file_type != FileType::Directory {
            return Err(Error::NotFound);
        }

        // Convert component bytes to &str for InodeOps::lookup.
        let name = core::str::from_utf8(component).map_err(|_| Error::InvalidArgument)?;

        // Handle `.` and `..` special entries.
        if name == "." {
            continue;
        }
        // `..` would need parent tracking; for now treat it as
        // a regular lookup (the filesystem should handle it).

        current = fs.lookup(&current, name)?;
    }

    Ok(current)
}

/// Open a file by pathname.
///
/// Resolves the path and creates an OpenFile entry. If `O_CREAT` is
/// set and the file doesn't exist, it will be created.
///
/// Returns the inode of the opened file.
pub fn vfs_open(
    path: &[u8],
    flags: OpenFlags,
    mode: FileMode,
    root_inode: &Inode,
    fs: &mut dyn InodeOps,
    mount_table: &MountTable,
    dcache: &mut DentryCache,
) -> Result<Inode> {
    // Try to resolve the full path.
    match resolve_path(path, root_inode, fs, mount_table, dcache) {
        Ok(inode) => {
            // File exists. If O_TRUNC and writable, truncate it.
            if flags.0 & OpenFlags::O_TRUNC.0 != 0 {
                fs.truncate(&inode, 0)?;
            }
            Ok(inode)
        }
        Err(Error::NotFound) => {
            // File doesn't exist. Create it if O_CREAT is set.
            if flags.0 & OpenFlags::O_CREAT.0 != 0 {
                // Find the parent directory and the filename.
                let (components, count) = split_path(path);
                if count == 0 {
                    return Err(Error::InvalidArgument);
                }

                // Resolve the parent directory.
                let parent = if count == 1 {
                    *root_inode
                } else {
                    let mut cur = *root_inode;
                    for component in &components[..count - 1] {
                        let name =
                            core::str::from_utf8(component).map_err(|_| Error::InvalidArgument)?;
                        cur = fs.lookup(&cur, name)?;
                    }
                    cur
                };

                let filename = core::str::from_utf8(components[count - 1])
                    .map_err(|_| Error::InvalidArgument)?;

                let new_inode = fs.create(&parent, filename, mode)?;

                // Cache the new dentry.
                if let Some(name) = DentryName::from_name(filename) {
                    dcache.insert(Dentry::new(name, new_inode.ino, parent.ino));
                }

                Ok(new_inode)
            } else {
                Err(Error::NotFound)
            }
        }
        Err(e) => Err(e),
    }
}

/// Allocate a file descriptor for an opened inode.
pub fn vfs_open_fd(fd_table: &mut FdTable, inode: InodeNumber, flags: OpenFlags) -> Result<Fd> {
    let open_file = OpenFile {
        inode,
        offset: 0,
        flags,
    };
    fd_table.alloc(open_file)
}
