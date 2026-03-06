// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/filesystems — registered filesystem types.
//!
//! Implements the `/proc/filesystems` virtual file which lists all filesystem
//! types currently registered with the kernel.
//!
//! # Format
//!
//! Each line contains either:
//! - `nodev\t<name>` — for filesystem types that don't need a device
//! - `\t<name>` — for filesystem types that require a device
//!
//! # Reference
//!
//! Linux `fs/filesystems.c`, `fs/proc_namespace.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered filesystem types.
const MAX_FS_TYPES: usize = 64;

/// Maximum filesystem type name length.
const MAX_FS_NAME: usize = 32;

/// Maximum output buffer size for /proc/filesystems.
const MAX_OUTPUT_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Filesystem type entry
// ---------------------------------------------------------------------------

/// A registered filesystem type.
#[derive(Debug, Clone)]
pub struct FsTypeEntry {
    /// Filesystem name (e.g., "ext4", "tmpfs", "proc").
    pub name: [u8; MAX_FS_NAME],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Whether this filesystem requires a block device.
    pub requires_dev: bool,
    /// Whether this filesystem is currently mounted anywhere.
    pub in_use: bool,
    /// Reference count (number of active mounts).
    pub ref_count: u32,
    /// Filesystem flags.
    pub flags: u32,
}

impl FsTypeEntry {
    /// Creates a new filesystem type entry.
    pub fn new(name: &[u8], requires_dev: bool) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_FS_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_FS_NAME];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: buf,
            name_len: name.len(),
            requires_dev,
            in_use: false,
            ref_count: 0,
            flags: 0,
        })
    }

    /// Returns the filesystem name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Increments the reference count (a new mount was created).
    pub fn inc_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
        self.in_use = true;
    }

    /// Decrements the reference count (a mount was destroyed).
    pub fn dec_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_sub(1);
        if self.ref_count == 0 {
            self.in_use = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem registry
// ---------------------------------------------------------------------------

/// Global registry of filesystem types.
pub struct FsTypeRegistry {
    /// Registered entries.
    entries: [Option<FsTypeEntry>; MAX_FS_TYPES],
    /// Number of registered entries.
    count: usize,
}

impl FsTypeRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Returns the number of registered filesystem types.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Registers a new filesystem type.
    pub fn fs_type_register(&mut self, entry: FsTypeEntry) -> Result<()> {
        if self.count >= MAX_FS_TYPES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for slot in self.entries[..].iter().flatten() {
            if slot.name_bytes() == entry.name_bytes() {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a filesystem type by name.
    pub fn fs_type_unregister(&mut self, name: &[u8]) -> Result<()> {
        for slot in &mut self.entries {
            if slot.as_ref().map(|e| e.name_bytes()) == Some(name) {
                let entry = slot.as_ref().unwrap();
                if entry.ref_count > 0 {
                    return Err(Error::Busy);
                }
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Finds a filesystem type by name.
    pub fn find(&self, name: &[u8]) -> Option<&FsTypeEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.name_bytes() == name)
    }

    /// Finds a mutable filesystem type by name.
    pub fn find_mut(&mut self, name: &[u8]) -> Option<&mut FsTypeEntry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.name_bytes() == name)
    }

    /// Increments the reference count for a filesystem type.
    pub fn mount_fs(&mut self, name: &[u8]) -> Result<()> {
        self.find_mut(name).ok_or(Error::NotFound)?.inc_ref();
        Ok(())
    }

    /// Decrements the reference count for a filesystem type.
    pub fn umount_fs(&mut self, name: &[u8]) -> Result<()> {
        self.find_mut(name).ok_or(Error::NotFound)?.dec_ref();
        Ok(())
    }

    /// Returns an iterator over all registered entries.
    pub fn iter(&self) -> impl Iterator<Item = &FsTypeEntry> {
        self.entries.iter().flatten()
    }
}

impl Default for FsTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// /proc/filesystems generation
// ---------------------------------------------------------------------------

/// Generates the content of `/proc/filesystems`.
///
/// Writes lines of the form `nodev\t<name>\n` or `\t<name>\n` depending on
/// whether the filesystem requires a device.
///
/// Returns the number of bytes written.
pub fn generate_proc_filesystems(registry: &FsTypeRegistry, out: &mut [u8]) -> usize {
    let mut pos = 0usize;

    for entry in registry.iter() {
        // Prefix: "nodev" or empty tab.
        let prefix: &[u8] = if entry.requires_dev {
            b"\t"
        } else {
            b"nodev\t"
        };
        let name = entry.name_bytes();
        let line_len = prefix.len() + name.len() + 1; // +1 for newline

        if pos + line_len > out.len() {
            break;
        }

        out[pos..pos + prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        out[pos..pos + name.len()].copy_from_slice(name);
        pos += name.len();
        out[pos] = b'\n';
        pos += 1;
    }

    pos
}

/// Generates the /proc/filesystems content into a fixed-size buffer.
pub fn proc_filesystems_content(registry: &FsTypeRegistry) -> ([u8; MAX_OUTPUT_SIZE], usize) {
    let mut buf = [0u8; MAX_OUTPUT_SIZE];
    let len = generate_proc_filesystems(registry, &mut buf);
    (buf, len)
}

// ---------------------------------------------------------------------------
// Built-in filesystem registration
// ---------------------------------------------------------------------------

/// Registers the standard set of built-in filesystems.
///
/// These are the filesystems that are always available in ONCRIX.
pub fn register_builtin_filesystems(registry: &mut FsTypeRegistry) -> Result<()> {
    let builtins: &[(&[u8], bool)] = &[
        (b"ext4", true),
        (b"ext2", true),
        (b"fat32", true),
        (b"btrfs", true),
        (b"xfs", true),
        (b"tmpfs", false),
        (b"ramfs", false),
        (b"proc", false),
        (b"sysfs", false),
        (b"devtmpfs", false),
        (b"devpts", false),
        (b"overlayfs", false),
        (b"squashfs", true),
        (b"fuse", false),
        (b"nfs", true),
        (b"cifs", true),
        (b"configfs", false),
        (b"debugfs", false),
        (b"tracefs", false),
        (b"securityfs", false),
    ];

    for (name, requires_dev) in builtins {
        let entry = FsTypeEntry::new(name, *requires_dev)?;
        // Ignore AlreadyExists errors (idempotent).
        match registry.fs_type_register(entry) {
            Ok(()) | Err(Error::AlreadyExists) => {}
            Err(e) => return Err(e),
        }
    }

    Ok(())
}
