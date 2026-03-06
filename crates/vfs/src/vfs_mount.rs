// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS mount infrastructure.
//!
//! Provides the core mount table, mount options parsing, and the
//! `do_mount` / `do_umount` dispatch functions that glue the VFS
//! layer to individual filesystem implementations.

use oncrix_lib::{Error, Result};

/// Maximum number of active mounts in the system.
pub const VFS_MAX_MOUNTS: usize = 1024;

/// Maximum length of a mount point path.
pub const VFS_MAX_MNTPATH: usize = 4096;

/// Mount flags (subset of Linux `MS_*`).
pub mod mount_flags {
    pub const RDONLY: u32 = 1 << 0;
    pub const NOSUID: u32 = 1 << 1;
    pub const NODEV: u32 = 1 << 2;
    pub const NOEXEC: u32 = 1 << 3;
    pub const SYNCHRONOUS: u32 = 1 << 4;
    pub const REMOUNT: u32 = 1 << 5;
    pub const MANDLOCK: u32 = 1 << 6;
    pub const DIRSYNC: u32 = 1 << 7;
    pub const NOATIME: u32 = 1 << 10;
    pub const NODIRATIME: u32 = 1 << 11;
    pub const BIND: u32 = 1 << 12;
    pub const MOVE: u32 = 1 << 13;
    pub const REC: u32 = 1 << 14;
    pub const STRICTATIME: u32 = 1 << 24;
    pub const LAZYTIME: u32 = 1 << 25;
}

/// Propagation types for a mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountPropagation {
    /// Changes propagate to and from peer mounts.
    Shared,
    /// Changes do not propagate to peers.
    Private,
    /// Changes propagate from the master but not outward.
    Slave,
    /// Mount is unbindable (cannot be used as the source of a bind mount).
    Unbindable,
}

/// A single entry in the system mount table.
#[derive(Debug, Clone)]
pub struct MountEntry {
    /// Unique mount ID (kernel-assigned, monotonically increasing).
    pub mount_id: u32,
    /// Parent mount ID (0 for the root mount).
    pub parent_id: u32,
    /// Device number (major:minor encoded as `major << 20 | minor`).
    pub dev_id: u32,
    /// Mount point path (NUL-terminated, up to VFS_MAX_MNTPATH bytes).
    pub mountpoint: [u8; 256],
    pub mountpoint_len: u16,
    /// Filesystem type name (e.g., "ext4", "tmpfs").
    pub fs_type: [u8; 32],
    pub fs_type_len: u8,
    /// Source device or special name.
    pub source: [u8; 64],
    pub source_len: u8,
    /// Active mount flags.
    pub flags: u32,
    /// Propagation mode.
    pub propagation: MountPropagation,
    /// Whether this mount is currently active.
    pub active: bool,
    /// Number of open file descriptors referencing files under this mount.
    pub ref_count: u32,
}

impl MountEntry {
    /// Mountpoint as a byte slice.
    pub fn mountpoint_bytes(&self) -> &[u8] {
        &self.mountpoint[..self.mountpoint_len as usize]
    }

    /// Filesystem type as a byte slice.
    pub fn fs_type_bytes(&self) -> &[u8] {
        &self.fs_type[..self.fs_type_len as usize]
    }

    /// Source as a byte slice.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source[..self.source_len as usize]
    }

    /// Whether this mount is read-only.
    pub fn is_rdonly(&self) -> bool {
        self.flags & mount_flags::RDONLY != 0
    }
}

/// System-wide mount table.
pub struct MountTable {
    entries: [Option<MountEntry>; VFS_MAX_MOUNTS],
    count: usize,
    next_id: u32,
}

impl MountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; VFS_MAX_MOUNTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Register a new mount, returning its assigned mount ID.
    pub fn add(&mut self, mut entry: MountEntry) -> Result<u32> {
        if self.count >= VFS_MAX_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        entry.mount_id = id;
        entry.active = true;
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a mount by ID.
    ///
    /// Returns `Err(Busy)` if the mount has open references.
    pub fn remove(&mut self, mount_id: u32) -> Result<MountEntry> {
        for slot in &mut self.entries {
            if slot.as_ref().map(|e| e.mount_id) == Some(mount_id) {
                let entry = slot.as_ref().unwrap();
                if entry.ref_count > 0 {
                    return Err(Error::Busy);
                }
                self.count -= 1;
                return Ok(slot.take().unwrap());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a mount by its mountpoint path.
    pub fn find_by_path(&self, path: &[u8]) -> Option<&MountEntry> {
        for slot in &self.entries {
            if let Some(entry) = slot.as_ref() {
                if entry.active && entry.mountpoint_bytes() == path {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Look up a mount by ID.
    pub fn find_by_id(&self, id: u32) -> Option<&MountEntry> {
        for slot in &self.entries {
            if let Some(entry) = slot.as_ref() {
                if entry.mount_id == id {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Find the mount entry for a mutable borrow by ID.
    pub fn find_by_id_mut(&mut self, id: u32) -> Option<&mut MountEntry> {
        for slot in &mut self.entries {
            if slot.as_ref().map(|e| e.mount_id) == Some(id) {
                return slot.as_mut();
            }
        }
        None
    }

    /// Increment the reference count of a mount.
    pub fn inc_ref(&mut self, id: u32) -> Result<()> {
        match self.find_by_id_mut(id) {
            Some(e) => {
                e.ref_count += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Decrement the reference count of a mount.
    pub fn dec_ref(&mut self, id: u32) -> Result<()> {
        match self.find_by_id_mut(id) {
            Some(e) => {
                if e.ref_count == 0 {
                    return Err(Error::InvalidArgument);
                }
                e.ref_count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all active mount entries.
    pub fn iter(&self) -> impl Iterator<Item = &MountEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|e| e.active)
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to build a `MountEntry` from raw parameters.
pub struct MountEntryBuilder {
    mountpoint: [u8; 256],
    mountpoint_len: u16,
    fs_type: [u8; 32],
    fs_type_len: u8,
    source: [u8; 64],
    source_len: u8,
    flags: u32,
    parent_id: u32,
    dev_id: u32,
    propagation: MountPropagation,
}

impl MountEntryBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            mountpoint: [0u8; 256],
            mountpoint_len: 0,
            fs_type: [0u8; 32],
            fs_type_len: 0,
            source: [0u8; 64],
            source_len: 0,
            flags: 0,
            parent_id: 0,
            dev_id: 0,
            propagation: MountPropagation::Private,
        }
    }

    /// Set mountpoint path.
    pub fn mountpoint(mut self, path: &[u8]) -> Result<Self> {
        let len = path.len().min(255);
        self.mountpoint[..len].copy_from_slice(&path[..len]);
        self.mountpoint_len = len as u16;
        Ok(self)
    }

    /// Set filesystem type.
    pub fn fs_type(mut self, name: &[u8]) -> Result<Self> {
        if name.len() > 31 {
            return Err(Error::InvalidArgument);
        }
        self.fs_type[..name.len()].copy_from_slice(name);
        self.fs_type_len = name.len() as u8;
        Ok(self)
    }

    /// Set source device or name.
    pub fn source(mut self, src: &[u8]) -> Result<Self> {
        let len = src.len().min(63);
        self.source[..len].copy_from_slice(&src[..len]);
        self.source_len = len as u8;
        Ok(self)
    }

    /// Set mount flags.
    pub fn flags(mut self, f: u32) -> Self {
        self.flags = f;
        self
    }

    /// Set propagation mode.
    pub fn propagation(mut self, p: MountPropagation) -> Self {
        self.propagation = p;
        self
    }

    /// Finalize into a `MountEntry` (mount_id will be assigned by the table).
    pub fn build(self) -> MountEntry {
        MountEntry {
            mount_id: 0,
            parent_id: self.parent_id,
            dev_id: self.dev_id,
            mountpoint: self.mountpoint,
            mountpoint_len: self.mountpoint_len,
            fs_type: self.fs_type,
            fs_type_len: self.fs_type_len,
            source: self.source,
            source_len: self.source_len,
            flags: self.flags,
            propagation: self.propagation,
            active: false,
            ref_count: 0,
        }
    }
}

impl Default for MountEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
