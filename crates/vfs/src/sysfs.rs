// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System filesystem (sysfs).
//!
//! Provides `/sys` entries exposing kernel objects, device hierarchy,
//! and tunable parameters as virtual files. Supports a hierarchical
//! directory structure with read-only and read-write attributes.
//!
//! # Hierarchy
//!
//! - `/sys/kernel/` — kernel-level information and tunables
//! - `/sys/devices/` — device tree
//! - `/sys/bus/` — bus subsystems
//! - `/sys/class/` — device classes
//!
//! # Design
//!
//! Each node is either a directory or an attribute (file). Attributes
//! have a read callback that generates content on the fly, and an
//! optional write callback for writable attributes. Parent-child
//! relationships are tracked via parent inode numbers.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Maximum number of sysfs entries (directories + attributes).
const MAX_SYSFS_ENTRIES: usize = 128;

/// Maximum length of a sysfs entry name.
const MAX_NAME_LEN: usize = 32;

/// Type of a sysfs node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysfsNodeType {
    /// A directory that can contain child entries.
    Directory,
    /// A read-only attribute file.
    Attribute,
    /// A read-write attribute file.
    WriteableAttribute,
}

/// Read callback for sysfs attributes.
///
/// Writes attribute content into `buf` and returns the number of
/// bytes written. The callback must not panic.
pub type SysfsReadFn = fn(&mut [u8]) -> usize;

/// Write callback for writable sysfs attributes.
///
/// Processes data written to the attribute. Returns `Ok(())` on
/// success or an error if the write is invalid.
pub type SysfsWriteFn = fn(&[u8]) -> Result<()>;

/// Sysfs attribute with read and optional write callbacks.
#[derive(Debug, Clone, Copy)]
pub struct SysfsAttr {
    /// Read callback that generates attribute content.
    pub read_fn: SysfsReadFn,
    /// Optional write callback for writable attributes.
    pub write_fn: Option<SysfsWriteFn>,
}

/// A node in the sysfs tree.
#[derive(Debug, Clone, Copy)]
pub struct SysfsEntry {
    /// Inode metadata.
    pub inode: Inode,
    /// Entry name (null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Actual length of the name.
    name_len: usize,
    /// Node type (directory or attribute).
    pub node_type: SysfsNodeType,
    /// Parent inode number (`InodeNumber(0)` for root).
    pub parent_ino: InodeNumber,
    /// Attribute callbacks (only meaningful for attribute nodes).
    pub attr: Option<SysfsAttr>,
}

impl SysfsEntry {
    /// Return the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// System filesystem.
///
/// Exposes kernel objects and parameters as a virtual file hierarchy
/// under `/sys`. Supports up to [`MAX_SYSFS_ENTRIES`] nodes total.
pub struct SysFs {
    /// All sysfs entries (directories and attributes).
    entries: [Option<SysfsEntry>; MAX_SYSFS_ENTRIES],
    /// Root inode.
    root: Inode,
    /// Next available inode number.
    next_ino: u64,
    /// Total entry count.
    count: usize,
}

impl core::fmt::Debug for SysFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysFs").field("count", &self.count).finish()
    }
}

impl Default for SysFs {
    fn default() -> Self {
        Self::new()
    }
}

/// Read callback for `/sys/kernel/version`.
fn read_kernel_version(buf: &mut [u8]) -> usize {
    let content = b"0.1.0\n";
    let len = content.len().min(buf.len());
    buf[..len].copy_from_slice(&content[..len]);
    len
}

/// Read callback for `/sys/kernel/hostname`.
fn read_kernel_hostname(buf: &mut [u8]) -> usize {
    let content = b"oncrix\n";
    let len = content.len().min(buf.len());
    buf[..len].copy_from_slice(&content[..len]);
    len
}

impl SysFs {
    /// Create a new sysfs with default directory structure.
    ///
    /// Initializes the following hierarchy:
    /// - `/sys/kernel/` with `version` and `hostname` attributes
    /// - `/sys/devices/`
    /// - `/sys/bus/`
    /// - `/sys/class/`
    pub fn new() -> Self {
        const NONE: Option<SysfsEntry> = None;
        let mut fs = Self {
            entries: [NONE; MAX_SYSFS_ENTRIES],
            root: Inode::new(InodeNumber(1), FileType::Directory, FileMode::DIR_DEFAULT),
            next_ino: 2,
            count: 0,
        };

        // Create top-level directories.
        let root_ino = InodeNumber(1);
        let kernel_ino = match fs.add_directory(root_ino, "kernel") {
            Ok(ino) => ino,
            Err(_) => return fs,
        };
        let _ = fs.add_directory(root_ino, "devices");
        let _ = fs.add_directory(root_ino, "bus");
        let _ = fs.add_directory(root_ino, "class");

        // Add default attributes under /sys/kernel/.
        let _ = fs.add_attribute(kernel_ino, "version", read_kernel_version, None);
        let _ = fs.add_attribute(kernel_ino, "hostname", read_kernel_hostname, None);

        fs
    }

    /// Return the root inode.
    pub fn root(&self) -> &Inode {
        &self.root
    }

    /// Return the number of registered entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Add a directory entry under the given parent.
    ///
    /// Returns the inode number of the new directory, or an error
    /// if the table is full or the name is too long.
    pub fn add_directory(&mut self, parent_ino: InodeNumber, name: &str) -> Result<InodeNumber> {
        self.insert_entry(parent_ino, name, SysfsNodeType::Directory, None)
    }

    /// Add an attribute (virtual file) under the given parent.
    ///
    /// - `read_fn`: callback that generates the attribute content
    /// - `write_fn`: optional callback for writable attributes
    ///
    /// Returns the inode number of the new attribute.
    pub fn add_attribute(
        &mut self,
        parent_ino: InodeNumber,
        name: &str,
        read_fn: SysfsReadFn,
        write_fn: Option<SysfsWriteFn>,
    ) -> Result<InodeNumber> {
        let node_type = if write_fn.is_some() {
            SysfsNodeType::WriteableAttribute
        } else {
            SysfsNodeType::Attribute
        };
        let attr = SysfsAttr { read_fn, write_fn };
        self.insert_entry(parent_ino, name, node_type, Some(attr))
    }

    /// Look up a child entry by name within a parent directory.
    ///
    /// Returns the entry if found, or `None` if no child with that
    /// name exists under the given parent.
    pub fn find_by_name(&self, parent_ino: InodeNumber, name: &str) -> Option<&SysfsEntry> {
        let name_bytes = name.as_bytes();
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.parent_ino == parent_ino && e.name_bytes() == name_bytes)
    }

    /// Internal helper to insert a new entry into the table.
    fn insert_entry(
        &mut self,
        parent_ino: InodeNumber,
        name: &str,
        node_type: SysfsNodeType,
        attr: Option<SysfsAttr>,
    ) -> Result<InodeNumber> {
        if self.count >= MAX_SYSFS_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        let mut entry_name = [0u8; MAX_NAME_LEN];
        entry_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let file_type = match node_type {
            SysfsNodeType::Directory => FileType::Directory,
            SysfsNodeType::Attribute | SysfsNodeType::WriteableAttribute => FileType::Regular,
        };
        let mode = match node_type {
            SysfsNodeType::Directory => FileMode::DIR_DEFAULT,
            SysfsNodeType::Attribute => FileMode(0o444),
            SysfsNodeType::WriteableAttribute => FileMode(0o644),
        };

        let entry = SysfsEntry {
            inode: Inode::new(ino, file_type, mode),
            name: entry_name,
            name_len: name_bytes.len(),
            node_type,
            parent_ino,
            attr,
        };

        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an entry by its inode number.
    fn find_by_ino(&self, ino: InodeNumber) -> Option<&SysfsEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.inode.ino == ino)
    }
}

impl InodeOps for SysFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        self.find_by_name(parent.ino, name)
            .map(|e| e.inode)
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

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let entry = self.find_by_ino(inode.ino).ok_or(Error::NotFound)?;

        // Directories cannot be read as files.
        if entry.node_type == SysfsNodeType::Directory {
            return Err(Error::InvalidArgument);
        }

        let attr = entry.attr.ok_or(Error::NotFound)?;

        // Generate content into a temporary buffer.
        let mut tmp = [0u8; 256];
        let total = (attr.read_fn)(&mut tmp);

        let off = offset as usize;
        if off >= total {
            return Ok(0);
        }
        let available = total - off;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&tmp[off..off + to_copy]);
        Ok(to_copy)
    }

    fn write(&mut self, inode: &Inode, _offset: u64, data: &[u8]) -> Result<usize> {
        let entry = self.find_by_ino(inode.ino).ok_or(Error::NotFound)?;

        // Directories cannot be written to.
        if entry.node_type == SysfsNodeType::Directory {
            return Err(Error::InvalidArgument);
        }

        let attr = entry.attr.ok_or(Error::NotFound)?;
        let write_fn = attr.write_fn.ok_or(Error::PermissionDenied)?;

        write_fn(data)?;
        Ok(data.len())
    }

    fn truncate(&mut self, _inode: &Inode, _size: u64) -> Result<()> {
        Err(Error::NotImplemented)
    }
}
