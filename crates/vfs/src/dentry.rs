// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Directory entry (dentry) cache.
//!
//! Dentries form the in-memory representation of the directory tree.
//! They cache the mapping from (parent, name) → inode and speed up
//! path resolution.

use crate::inode::InodeNumber;

/// Maximum filename length (POSIX NAME_MAX).
pub const NAME_MAX: usize = 255;

/// A cached directory entry.
#[derive(Debug, Clone)]
pub struct Dentry {
    /// Name of this entry within its parent directory.
    name: DentryName,
    /// Inode number this entry points to.
    inode: InodeNumber,
    /// Parent inode number (root's parent is itself).
    parent: InodeNumber,
}

/// Fixed-size filename buffer (avoids heap allocation in kernel).
#[derive(Debug, Clone)]
pub struct DentryName {
    /// Name bytes (not necessarily null-terminated).
    buf: [u8; NAME_MAX],
    /// Length of the name.
    len: usize,
}

impl DentryName {
    /// Create a name from a string slice.
    ///
    /// Returns `None` if the name exceeds `NAME_MAX` or is empty.
    pub fn from_name(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > NAME_MAX {
            return None;
        }
        let mut buf = [0u8; NAME_MAX];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            buf,
            len: bytes.len(),
        })
    }

    /// Return the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the name length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Dentry {
    /// Create a new dentry.
    pub fn new(name: DentryName, inode: InodeNumber, parent: InodeNumber) -> Self {
        Self {
            name,
            inode,
            parent,
        }
    }

    /// Return the entry name.
    pub fn name(&self) -> &DentryName {
        &self.name
    }

    /// Return the associated inode number.
    pub fn inode(&self) -> InodeNumber {
        self.inode
    }

    /// Return the parent's inode number.
    pub fn parent(&self) -> InodeNumber {
        self.parent
    }
}

/// Maximum number of cached dentries.
const DENTRY_CACHE_SIZE: usize = 256;

/// Simple linear-scan dentry cache.
///
/// A production kernel would use a hash table, but this fixed-size
/// array is sufficient for early boot.
pub struct DentryCache {
    /// Cached entries.
    entries: [Option<Dentry>; DENTRY_CACHE_SIZE],
    /// Number of cached entries.
    count: usize,
}

impl core::fmt::Debug for DentryCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DentryCache")
            .field("count", &self.count)
            .finish()
    }
}

impl Default for DentryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DentryCache {
    /// Create an empty dentry cache.
    pub const fn new() -> Self {
        const NONE: Option<Dentry> = None;
        Self {
            entries: [NONE; DENTRY_CACHE_SIZE],
            count: 0,
        }
    }

    /// Insert a dentry into the cache.
    ///
    /// Silently drops the entry if the cache is full.
    pub fn insert(&mut self, dentry: Dentry) {
        if self.count >= DENTRY_CACHE_SIZE {
            return;
        }
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(dentry);
                self.count += 1;
                return;
            }
        }
    }

    /// Look up a dentry by parent inode and name.
    pub fn lookup(&self, parent: InodeNumber, name: &[u8]) -> Option<&Dentry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|d| d.parent() == parent && d.name().as_bytes() == name)
    }

    /// Return the number of cached entries.
    pub fn count(&self) -> usize {
        self.count
    }
}
