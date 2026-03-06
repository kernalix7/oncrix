// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! securityfs filesystem operations.
//!
//! securityfs is a pseudo-filesystem mounted at `/sys/kernel/security`.
//! It provides a virtual filesystem interface for Linux Security Modules (LSMs)
//! such as SELinux, AppArmor, and Smack to export policy state and accept
//! policy updates from user space.
//!
//! # Node Types
//!
//! securityfs nodes are either:
//! - **Files**: Export LSM state; accept writes for policy updates.
//! - **Directories**: Group related policy files.
//! - **Symlinks**: Redirect to other nodes.
//!
//! # Operations
//!
//! Nodes are registered via `securityfs_create_file()` and
//! `securityfs_create_dir()`. The VFS dispatches read/write to the
//! LSM-supplied `file_operations` callbacks.

use oncrix_lib::{Error, Result};

/// Maximum length of a securityfs node name.
pub const SECFS_NAME_MAX: usize = 64;

/// Maximum number of securityfs nodes per LSM.
pub const SECFS_MAX_NODES: usize = 128;

/// Type of a securityfs node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeKind {
    /// Regular file (exports/accepts LSM data).
    File,
    /// Directory containing other nodes.
    Directory,
    /// Symbolic link.
    Symlink,
}

impl Default for NodeKind {
    fn default() -> Self {
        Self::File
    }
}

/// POSIX mode bits for securityfs nodes.
pub mod mode {
    /// Owner read permission.
    pub const S_IRUSR: u16 = 0o0400;
    /// Owner write permission.
    pub const S_IWUSR: u16 = 0o0200;
    /// Group read permission.
    pub const S_IRGRP: u16 = 0o0040;
    /// World read permission.
    pub const S_IROTH: u16 = 0o0004;
    /// Default file mode (rw-r--r--).
    pub const DEFAULT_FILE: u16 = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    /// Default directory mode (rwxr-xr-x).
    pub const DEFAULT_DIR: u16 = 0o0755;
}

/// A read callback for securityfs file nodes.
///
/// Returns the number of bytes written into `buf`.
pub type ReadFn = fn(buf: &mut [u8], offset: u64) -> Result<usize>;

/// A write callback for securityfs file nodes.
///
/// Returns the number of bytes consumed from `data`.
pub type WriteFn = fn(data: &[u8], offset: u64) -> Result<usize>;

/// A securityfs node descriptor.
pub struct SecfsNode {
    /// Node name (null-padded).
    pub name: [u8; SECFS_NAME_MAX],
    /// Length of the name.
    pub name_len: usize,
    /// Node kind (file, directory, symlink).
    pub kind: NodeKind,
    /// POSIX permission mode bits.
    pub mode: u16,
    /// Inode number (assigned at registration).
    pub ino: u64,
    /// Parent inode number (0 = root).
    pub parent_ino: u64,
    /// Read callback (files only).
    pub read_fn: Option<ReadFn>,
    /// Write callback (files only).
    pub write_fn: Option<WriteFn>,
}

impl Default for SecfsNode {
    fn default() -> Self {
        Self {
            name: [0u8; SECFS_NAME_MAX],
            name_len: 0,
            kind: NodeKind::File,
            mode: mode::DEFAULT_FILE,
            ino: 0,
            parent_ino: 0,
            read_fn: None,
            write_fn: None,
        }
    }
}

impl SecfsNode {
    /// Returns the node name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns `true` if this node has read capability.
    pub const fn is_readable(&self) -> bool {
        self.mode & mode::S_IRUSR != 0
    }

    /// Returns `true` if this node has write capability.
    pub const fn is_writable(&self) -> bool {
        self.mode & mode::S_IWUSR != 0
    }

    /// Performs a read operation on this file node.
    pub fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        match self.kind {
            NodeKind::File => {
                let f = self.read_fn.ok_or(Error::NotImplemented)?;
                f(buf, offset)
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Performs a write operation on this file node.
    pub fn write(&self, data: &[u8], offset: u64) -> Result<usize> {
        match self.kind {
            NodeKind::File => {
                let f = self.write_fn.ok_or(Error::NotImplemented)?;
                f(data, offset)
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// The securityfs node registry for a single LSM.
pub struct SecfsRegistry {
    nodes: [SecfsNode; SECFS_MAX_NODES],
    count: usize,
    next_ino: u64,
    /// Inode number of the LSM's root directory under `/sys/kernel/security`.
    root_ino: u64,
}

impl Default for SecfsRegistry {
    fn default() -> Self {
        Self {
            nodes: core::array::from_fn(|_| SecfsNode::default()),
            count: 0,
            next_ino: 2, // 1 is reserved for the global securityfs root
            root_ino: 0,
        }
    }
}

impl SecfsRegistry {
    /// Creates a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the root inode number for this LSM's directory.
    pub fn set_root(&mut self, ino: u64) {
        self.root_ino = ino;
    }

    /// Registers a file node.
    ///
    /// Returns the inode number assigned to the new node.
    pub fn create_file(
        &mut self,
        name: &[u8],
        parent_ino: u64,
        mode: u16,
        read_fn: Option<ReadFn>,
        write_fn: Option<WriteFn>,
    ) -> Result<u64> {
        if self.count >= SECFS_MAX_NODES || name.len() > SECFS_NAME_MAX {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        let mut node = SecfsNode {
            kind: NodeKind::File,
            mode,
            ino,
            parent_ino,
            read_fn,
            write_fn,
            ..SecfsNode::default()
        };
        let copy_len = name.len().min(SECFS_NAME_MAX);
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
        node.name_len = copy_len;
        self.nodes[self.count] = node;
        self.count += 1;
        Ok(ino)
    }

    /// Registers a directory node.
    pub fn create_dir(&mut self, name: &[u8], parent_ino: u64) -> Result<u64> {
        if self.count >= SECFS_MAX_NODES || name.len() > SECFS_NAME_MAX {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        let mut node = SecfsNode {
            kind: NodeKind::Directory,
            mode: mode::DEFAULT_DIR,
            ino,
            parent_ino,
            ..SecfsNode::default()
        };
        let copy_len = name.len().min(SECFS_NAME_MAX);
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
        node.name_len = copy_len;
        self.nodes[self.count] = node;
        self.count += 1;
        Ok(ino)
    }

    /// Finds a node by inode number.
    pub fn find_by_ino(&self, ino: u64) -> Option<&SecfsNode> {
        self.nodes[..self.count].iter().find(|n| n.ino == ino)
    }

    /// Looks up a node by parent inode and name.
    pub fn lookup(&self, parent_ino: u64, name: &[u8]) -> Option<&SecfsNode> {
        self.nodes[..self.count]
            .iter()
            .find(|n| n.parent_ino == parent_ino && n.name_bytes() == name)
    }

    /// Removes a node by inode number.
    pub fn remove(&mut self, ino: u64) -> Result<()> {
        let pos = self.nodes[..self.count]
            .iter()
            .position(|n| n.ino == ino)
            .ok_or(Error::NotFound)?;
        self.count -= 1;
        // SAFETY: Swap with last element to fill the hole.
        if pos < self.count {
            self.nodes[pos] = SecfsNode::default();
            // Re-read the last node.
            let last_ino = self.nodes[self.count].ino;
            let last_parent = self.nodes[self.count].parent_ino;
            let last_kind = self.nodes[self.count].kind;
            let last_mode = self.nodes[self.count].mode;
            let last_name = self.nodes[self.count].name;
            let last_name_len = self.nodes[self.count].name_len;
            let last_read = self.nodes[self.count].read_fn;
            let last_write = self.nodes[self.count].write_fn;
            self.nodes[pos] = SecfsNode {
                name: last_name,
                name_len: last_name_len,
                kind: last_kind,
                mode: last_mode,
                ino: last_ino,
                parent_ino: last_parent,
                read_fn: last_read,
                write_fn: last_write,
            };
        }
        self.nodes[self.count] = SecfsNode::default();
        Ok(())
    }
}
