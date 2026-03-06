// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device filesystem (devfs).
//!
//! Provides `/dev` entries for device nodes. Each device driver
//! registers a node here, creating a file-like interface for
//! user-space programs to access hardware.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Device-specific ioctl operations.
///
/// Drivers implement this trait to handle `ioctl()` requests on
/// their device nodes. The kernel dispatches to the appropriate
/// implementation based on the device's major/minor number.
pub trait IoctlOps {
    /// Handle an ioctl request.
    ///
    /// - `request`: the ioctl request number
    /// - `arg`: opaque argument (typically a user pointer)
    ///
    /// Returns 0 on success, or a negative errno on failure.
    /// The driver is responsible for copying data to/from user space.
    fn ioctl(&self, request: u64, arg: u64) -> Result<u64>;
}

/// Maximum number of device nodes.
const MAX_DEV_NODES: usize = 64;

/// A device node in devfs.
#[derive(Debug, Clone, Copy)]
pub struct DevNode {
    /// Inode metadata.
    pub inode: Inode,
    /// Device name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Major device number.
    pub major: u16,
    /// Minor device number.
    pub minor: u16,
}

/// Device filesystem.
pub struct DevFs {
    /// Device nodes.
    nodes: [Option<DevNode>; MAX_DEV_NODES],
    /// Root inode.
    root: Inode,
    /// Next inode number.
    next_ino: u64,
    /// Node count.
    count: usize,
}

impl core::fmt::Debug for DevFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevFs").field("count", &self.count).finish()
    }
}

impl Default for DevFs {
    fn default() -> Self {
        Self::new()
    }
}

impl DevFs {
    /// Create a new devfs with a root directory.
    pub fn new() -> Self {
        const NONE: Option<DevNode> = None;
        Self {
            nodes: [NONE; MAX_DEV_NODES],
            root: Inode::new(InodeNumber(1), FileType::Directory, FileMode::DIR_DEFAULT),
            next_ino: 2,
            count: 0,
        }
    }

    /// Return the root inode.
    pub fn root(&self) -> &Inode {
        &self.root
    }

    /// Register a character device node.
    pub fn add_char_device(&mut self, name: &str, major: u16, minor: u16) -> Result<InodeNumber> {
        if self.count >= MAX_DEV_NODES {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 32 {
            return Err(Error::InvalidArgument);
        }

        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        let mut node_name = [0u8; 32];
        node_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let node = DevNode {
            inode: Inode::new(ino, FileType::CharDevice, FileMode::FILE_DEFAULT),
            name: node_name,
            name_len: name_bytes.len(),
            major,
            minor,
        };

        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(node);
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Register a block device node.
    pub fn add_block_device(&mut self, name: &str, major: u16, minor: u16) -> Result<InodeNumber> {
        if self.count >= MAX_DEV_NODES {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 32 {
            return Err(Error::InvalidArgument);
        }

        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        let mut node_name = [0u8; 32];
        node_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let node = DevNode {
            inode: Inode::new(ino, FileType::BlockDevice, FileMode::FILE_DEFAULT),
            name: node_name,
            name_len: name_bytes.len(),
            major,
            minor,
        };

        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(node);
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a device node by name.
    pub fn find_by_name(&self, name: &str) -> Option<&DevNode> {
        let name_bytes = name.as_bytes();
        self.nodes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|n| &n.name[..n.name_len] == name_bytes)
    }

    /// Return the number of registered nodes.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl InodeOps for DevFs {
    fn lookup(&self, _parent: &Inode, name: &str) -> Result<Inode> {
        self.find_by_name(name)
            .map(|n| n.inode)
            .ok_or(Error::NotFound)
    }

    fn create(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        Err(Error::NotImplemented)
    }

    fn mkdir(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        Err(Error::NotImplemented)
    }

    fn unlink(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn rmdir(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn read(&self, _inode: &Inode, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        // Device reads are delegated to the driver via IPC.
        Err(Error::NotImplemented)
    }

    fn write(&mut self, _inode: &Inode, _offset: u64, _data: &[u8]) -> Result<usize> {
        Err(Error::NotImplemented)
    }

    fn truncate(&mut self, _inode: &Inode, _size: u64) -> Result<()> {
        Err(Error::NotImplemented)
    }
}
