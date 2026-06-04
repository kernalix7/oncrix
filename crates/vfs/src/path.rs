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
use crate::namei::MAX_SYMLINK_DEPTH;
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
    // `cur_path` tracks the absolute path that produced `current`, so a
    // relative symlink target can be resolved against the link's parent
    // directory. It starts as the caller's path. Bounded to SYMPATH_MAX
    // (not PATH_MAX) to keep the kernel-stack footprint small — ONCRIX
    // paths are short and a 4 KiB buffer here is wasteful/risky.
    const SYMPATH_MAX: usize = 512;
    let mut cur_path = [0u8; SYMPATH_MAX];
    if path.len() > SYMPATH_MAX {
        return Err(Error::InvalidArgument);
    }
    cur_path[..path.len()].copy_from_slice(path);
    let mut cur_len = path.len();

    // Shared symlink-follow depth counter; MAX_SYMLINK_DEPTH (40) is the
    // authoritative limit (POSIX ELOOP).  Using a single counter means
    // symlinks expanded during intermediate component resolution AND the
    // terminal symlink expansion both count against the same budget,
    // closing the cycle-via-intermediate-symlink window.
    let mut depth = 0u32;

    let mut current = walk_components(&cur_path[..cur_len], root_inode, fs, &mut depth)?;

    // Follow a terminal symbolic link to its target. Absolute targets
    // resolve from root; relative targets resolve against the link's
    // parent directory. A depth limit guards against cycles (ELOOP).
    let mut target_buf = [0u8; 256];
    let mut next_path = [0u8; SYMPATH_MAX];
    while current.file_type == FileType::Symlink {
        // Guard against symlink cycles / infinite loops.
        depth = depth.checked_add(1).ok_or(Error::InvalidArgument)?;
        if depth as usize > MAX_SYMLINK_DEPTH {
            return Err(Error::InvalidArgument); // ELOOP
        }
        let n = fs.readlink(&current, &mut target_buf)?;
        let target = &target_buf[..n];
        if target.is_empty() {
            break;
        }

        let new_len = if target[0] == b'/' {
            // Absolute target: replace the path entirely.
            if n > SYMPATH_MAX {
                return Err(Error::InvalidArgument);
            }
            next_path[..n].copy_from_slice(target);
            n
        } else {
            // Relative target: <dirname(cur_path)> '/' <target>.
            let dir = parent_slice(&cur_path[..cur_len]);
            // Join: dir + '/' + target (avoid a double slash after root).
            let mut len = 0usize;
            for &b in dir {
                if len >= SYMPATH_MAX {
                    return Err(Error::InvalidArgument);
                }
                next_path[len] = b;
                len += 1;
            }
            if dir.last() != Some(&b'/') {
                if len >= SYMPATH_MAX {
                    return Err(Error::InvalidArgument);
                }
                next_path[len] = b'/';
                len += 1;
            }
            for &b in target {
                if len >= SYMPATH_MAX {
                    return Err(Error::InvalidArgument);
                }
                next_path[len] = b;
                len += 1;
            }
            len
        };

        cur_path[..new_len].copy_from_slice(&next_path[..new_len]);
        cur_len = new_len;
        current = walk_components(&cur_path[..cur_len], root_inode, fs, &mut depth)?;
    }

    Ok(current)
}

/// Return the parent-directory slice of an absolute path.
///
/// `/a/b` → `/a`, `/a` → `/`, `/` → `/`. The result always begins with
/// `/` and never has a trailing slash unless it is the bare root.
fn parent_slice(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/",
        Some(i) => &path[..i],
    }
}

/// Walk an absolute path one component at a time WITHOUT following a
/// terminal symlink, returning the inode the final component names.
///
/// `.` is skipped; `..` respects the root boundary — if the current inode
/// equals `root_inode` the walk stays put (mirrors `namei_lookup` ~303-313).
/// The `depth` counter is shared with the caller so symlinks encountered
/// during intermediate resolution count against the same budget.
fn walk_components(
    path: &[u8],
    root_inode: &Inode,
    fs: &dyn InodeOps,
    depth: &mut u32,
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

        // Handle `.` — stay in place.
        if name == "." {
            continue;
        }

        // Handle `..` with root-boundary enforcement.
        //
        // SECURITY: If the current directory is the root inode we must NOT
        // forward ".." to the filesystem lookup — doing so allows escape from
        // a chroot/bind-mount jail.  Mirror namei_lookup (~303-313): clamp at
        // root by staying put.
        //
        // Both ino AND sb_id must match: two filesystems can share the same
        // inode number, so checking only ino risks a false clamp mid-tree
        // (different sb_id, same ino) or a missed clamp (same sb_id matched
        // against a different mount's inode).
        if name == ".." && current.ino == root_inode.ino && current.sb_id == root_inode.sb_id {
            // Already at root — ".." is a no-op (clamped).
            continue;
        }
        // If name == ".." and we are NOT at root: fall through to
        // fs.lookup() which knows the on-disk parent pointer.

        // If the inode is a symlink encountered as an intermediate component,
        // count it against the shared symlink budget to prevent cycles built
        // from chains of intermediate symlinks.
        let result = fs.lookup(&current, name)?;
        if result.file_type == FileType::Symlink {
            *depth = depth.checked_add(1).ok_or(Error::InvalidArgument)?;
            if *depth as usize > MAX_SYMLINK_DEPTH {
                return Err(Error::InvalidArgument); // ELOOP
            }
        }
        current = result;
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
