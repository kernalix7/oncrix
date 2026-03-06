// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bind mount support — `MS_BIND` and `MS_RBIND` mount semantics.
//!
//! A bind mount makes a directory or file visible at a second location in the
//! VFS tree without copying data. This module tracks bind-mount relationships
//! and enforces propagation rules on unmount.

use oncrix_lib::{Error, Result};

/// Maximum number of bind mount entries in the registry.
pub const MAX_BIND_MOUNTS: usize = 128;

/// Flags for bind mount creation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BindFlags(pub u32);

impl BindFlags {
    /// Recursive bind mount (MS_RBIND) — also bind sub-mounts.
    pub const RECURSIVE: u32 = 1 << 0;
    /// Read-only bind (downgrade write permissions).
    pub const RDONLY: u32 = 1 << 1;
    /// Private propagation — changes don't propagate to/from peers.
    pub const PRIVATE: u32 = 1 << 2;

    /// Test whether a flag is set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// A single bind mount entry.
#[derive(Debug, Clone, Copy)]
pub struct BindMount {
    /// Superblock ID of the bind mount's view.
    pub view_sb_id: u64,
    /// Inode number at the root of the bind mount view.
    pub view_ino: u64,
    /// Superblock ID of the source (original) directory.
    pub src_sb_id: u64,
    /// Inode number of the source directory.
    pub src_ino: u64,
    /// Flags controlling propagation.
    pub flags: BindFlags,
    /// Whether this entry is active.
    pub active: bool,
    /// Unique bind mount ID.
    pub id: u32,
}

impl BindMount {
    /// Create an empty inactive entry.
    const fn empty() -> Self {
        Self {
            view_sb_id: 0,
            view_ino: 0,
            src_sb_id: 0,
            src_ino: 0,
            flags: BindFlags(0),
            active: false,
            id: 0,
        }
    }
}

/// Registry of all active bind mounts.
pub struct BindMountRegistry {
    entries: [BindMount; MAX_BIND_MOUNTS],
    count: usize,
    next_id: u32,
}

impl BindMountRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { BindMount::empty() }; MAX_BIND_MOUNTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Register a new bind mount.
    ///
    /// Returns the assigned bind mount ID.
    pub fn add(
        &mut self,
        view_sb_id: u64,
        view_ino: u64,
        src_sb_id: u64,
        src_ino: u64,
        flags: BindFlags,
    ) -> Result<u32> {
        if self.count >= MAX_BIND_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        for entry in self.entries.iter_mut() {
            if !entry.active {
                *entry = BindMount {
                    view_sb_id,
                    view_ino,
                    src_sb_id,
                    src_ino,
                    flags,
                    active: true,
                    id,
                };
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a bind mount by ID.
    pub fn remove(&mut self, id: u32) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.id == id {
                *entry = BindMount::empty();
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find the source for a bind-mounted path.
    ///
    /// Given the view (sb_id, ino), returns the source (sb_id, ino).
    pub fn resolve_to_source(&self, view_sb_id: u64, view_ino: u64) -> Option<(u64, u64)> {
        for entry in &self.entries {
            if entry.active && entry.view_sb_id == view_sb_id && entry.view_ino == view_ino {
                return Some((entry.src_sb_id, entry.src_ino));
            }
        }
        None
    }

    /// Return all bind mounts that originate from a given source.
    pub fn views_of_source(&self, src_sb_id: u64, src_ino: u64, out: &mut [(u64, u64)]) -> usize {
        let mut written = 0;
        for entry in &self.entries {
            if written >= out.len() {
                break;
            }
            if entry.active && entry.src_sb_id == src_sb_id && entry.src_ino == src_ino {
                out[written] = (entry.view_sb_id, entry.view_ino);
                written += 1;
            }
        }
        written
    }

    /// Remove all bind mounts associated with a superblock (on unmount).
    pub fn remove_super(&mut self, sb_id: u64) -> u32 {
        let mut removed = 0u32;
        for entry in self.entries.iter_mut() {
            if entry.active && (entry.view_sb_id == sb_id || entry.src_sb_id == sb_id) {
                *entry = BindMount::empty();
                self.count -= 1;
                removed += 1;
            }
        }
        removed
    }

    /// Return the number of active bind mounts.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Look up a bind mount by ID.
    pub fn get(&self, id: u32) -> Option<&BindMount> {
        self.entries.iter().find(|e| e.active && e.id == id)
    }
}

impl Default for BindMountRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a bind mount request is permissible.
///
/// Prevents binding a directory onto itself or onto its own descendant.
/// A full cycle check would require VFS traversal; here we perform basic
/// equality checks.
pub fn validate_bind_request(
    src_sb_id: u64,
    src_ino: u64,
    dst_sb_id: u64,
    dst_ino: u64,
) -> Result<()> {
    if src_sb_id == dst_sb_id && src_ino == dst_ino {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Apply read-only downgrade to a bind mount's effective permissions.
///
/// If `RDONLY` is set in flags, the caller must deny write operations on the
/// view even if the source allows them.
pub fn bind_allows_write(flags: BindFlags) -> bool {
    !flags.has(BindFlags::RDONLY)
}
