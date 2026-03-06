// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended attributes (xattr) subsystem.
//!
//! Provides `setxattr`, `getxattr`, `listxattr`, and `removexattr`
//! operations for associating arbitrary name-value metadata with
//! inodes. Names are partitioned into four namespaces: `user.`,
//! `system.`, `security.`, and `trusted.`.
//!
//! Reference: Linux `fs/xattr.c`, xattr(7) man page.

use oncrix_lib::{Error, Result};

/// Maximum length of an xattr name in bytes.
const _MAX_XATTR_NAME: usize = 255;

/// Maximum length of an xattr value in bytes.
const _MAX_XATTR_VALUE: usize = 4096;

/// Maximum number of extended attributes per inode.
const _MAX_XATTRS_PER_INODE: usize = 32;

/// Maximum number of inodes tracked by the registry.
const _MAX_XATTR_INODES: usize = 256;

/// Flag: create the attribute; fail if it already exists.
pub const XATTR_CREATE: i32 = 1;

/// Flag: replace an existing attribute; fail if it does not exist.
pub const XATTR_REPLACE: i32 = 2;

// ─── Namespace ───────────────────────────────────────────────

/// Extended-attribute namespace classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XattrNamespace {
    /// User namespace (`user.`).
    #[default]
    User,
    /// System namespace (`system.`).
    System,
    /// Security namespace (`security.`).
    Security,
    /// Trusted namespace (`trusted.`).
    Trusted,
}

impl XattrNamespace {
    /// Returns the conventional prefix for this namespace.
    pub fn prefix(&self) -> &[u8] {
        match self {
            XattrNamespace::User => b"user.",
            XattrNamespace::System => b"system.",
            XattrNamespace::Security => b"security.",
            XattrNamespace::Trusted => b"trusted.",
        }
    }
}

/// Detect the namespace from a fully-qualified xattr name.
pub fn parse_namespace(name: &[u8]) -> XattrNamespace {
    if starts_with(name, b"system.") {
        XattrNamespace::System
    } else if starts_with(name, b"security.") {
        XattrNamespace::Security
    } else if starts_with(name, b"trusted.") {
        XattrNamespace::Trusted
    } else {
        XattrNamespace::User
    }
}

/// Byte-slice prefix check (no `std`).
fn starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    if haystack.len() < prefix.len() {
        return false;
    }
    haystack[..prefix.len()] == *prefix
}

// ─── XattrEntry ──────────────────────────────────────────────

/// A single extended-attribute key/value pair.
#[derive(Clone)]
pub struct XattrEntry {
    /// Attribute name bytes.
    name: [u8; 255],
    /// Valid length of `name`.
    name_len: usize,
    /// Attribute value bytes.
    value: [u8; 4096],
    /// Valid length of `value`.
    value_len: usize,
    /// Namespace this attribute belongs to.
    namespace: XattrNamespace,
    /// Whether this slot is occupied.
    active: bool,
}

impl XattrEntry {
    /// Creates an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; 255],
            name_len: 0,
            value: [0u8; 4096],
            value_len: 0,
            namespace: XattrNamespace::User,
            active: false,
        }
    }
}

// ─── XattrSet ────────────────────────────────────────────────

/// Per-inode collection of extended attributes.
pub struct XattrSet {
    /// Fixed-capacity entry array.
    entries: [XattrEntry; 32],
    /// Number of active entries.
    count: usize,
    /// Owning inode number.
    inode: u64,
    /// Whether this set is in use.
    active: bool,
}

/// Helper: create the 32-element array in a const context.
const fn empty_entries() -> [XattrEntry; 32] {
    let mut arr = [const { XattrEntry::empty() }; 32];
    let mut i = 0;
    while i < 32 {
        arr[i] = XattrEntry::empty();
        i += 1;
    }
    arr
}

impl XattrSet {
    /// Creates an empty, inactive xattr set.
    const fn empty() -> Self {
        Self {
            entries: empty_entries(),
            count: 0,
            inode: 0,
            active: false,
        }
    }

    /// Set or create an extended attribute.
    ///
    /// `flags`:
    /// - `0` — create or replace.
    /// - [`XATTR_CREATE`] — fail with `AlreadyExists` if the
    ///   name already exists.
    /// - [`XATTR_REPLACE`] — fail with `NotFound` if the name
    ///   does not already exist.
    pub fn setxattr(&mut self, name: &[u8], value: &[u8], flags: i32) -> Result<()> {
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        if value.len() > 4096 {
            return Err(Error::InvalidArgument);
        }

        let ns = parse_namespace(name);

        // Look for an existing entry with the same name.
        let existing = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.name_len == name.len() && e.name[..e.name_len] == *name);

        if let Some(entry) = existing {
            if flags == XATTR_CREATE {
                return Err(Error::AlreadyExists);
            }
            entry.value[..value.len()].copy_from_slice(value);
            entry.value_len = value.len();
            entry.namespace = ns;
            return Ok(());
        }

        // No existing entry.
        if flags == XATTR_REPLACE {
            return Err(Error::NotFound);
        }

        // Allocate a new slot.
        let slot = self.entries.iter_mut().find(|e| !e.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.value[..value.len()].copy_from_slice(value);
        slot.value_len = value.len();
        slot.namespace = ns;
        slot.active = true;
        self.count += 1;
        Ok(())
    }

    /// Retrieve the value of an extended attribute.
    pub fn getxattr(&self, name: &[u8]) -> Result<&[u8]> {
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.name_len == name.len() && e.name[..e.name_len] == *name);
        match entry {
            Some(e) => Ok(&e.value[..e.value_len]),
            None => Err(Error::NotFound),
        }
    }

    /// Write a null-terminated list of attribute names into
    /// `buf` and return the total number of bytes written.
    pub fn listxattr(&self, buf: &mut [u8]) -> Result<usize> {
        let mut offset: usize = 0;
        for entry in &self.entries {
            if !entry.active {
                continue;
            }
            let needed = entry.name_len + 1; // +1 for NUL
            if offset + needed > buf.len() {
                return Err(Error::InvalidArgument);
            }
            buf[offset..offset + entry.name_len].copy_from_slice(&entry.name[..entry.name_len]);
            buf[offset + entry.name_len] = 0;
            offset += needed;
        }
        Ok(offset)
    }

    /// Remove an extended attribute by name.
    pub fn removexattr(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.name_len == name.len() && e.name[..e.name_len] == *name);
        match entry {
            Some(e) => {
                e.active = false;
                e.name_len = 0;
                e.value_len = 0;
                self.count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Returns the number of active attributes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active attributes.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ─── XattrRegistry ───────────────────────────────────────────

/// Global registry that maps inodes to their xattr sets.
pub struct XattrRegistry {
    /// Fixed-capacity array of per-inode xattr sets.
    sets: [XattrSet; 256],
    /// Number of active sets.
    count: usize,
}

/// Helper: create the 256-element set array at compile time.
const fn empty_sets() -> [XattrSet; 256] {
    let mut arr = [const { XattrSet::empty() }; 256];
    let mut i = 0;
    while i < 256 {
        arr[i] = XattrSet::empty();
        i += 1;
    }
    arr
}

impl Default for XattrRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl XattrRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        Self {
            sets: empty_sets(),
            count: 0,
        }
    }

    /// Find the xattr set for `inode`, creating one if none
    /// exists yet.
    pub fn get_or_create(&mut self, inode: u64) -> Result<&mut XattrSet> {
        // First pass: look for an existing set.
        let found = self.sets.iter().position(|s| s.active && s.inode == inode);
        if let Some(idx) = found {
            return Ok(&mut self.sets[idx]);
        }

        // Second pass: allocate a free slot.
        let free = self.sets.iter().position(|s| !s.active);
        let idx = match free {
            Some(i) => i,
            None => return Err(Error::OutOfMemory),
        };

        self.sets[idx].inode = inode;
        self.sets[idx].active = true;
        self.sets[idx].count = 0;
        self.count += 1;
        Ok(&mut self.sets[idx])
    }

    /// Look up the xattr set for `inode` (read-only).
    pub fn get(&self, inode: u64) -> Option<&XattrSet> {
        self.sets.iter().find(|s| s.active && s.inode == inode)
    }

    /// Remove all extended attributes for `inode`.
    pub fn remove_inode(&mut self, inode: u64) -> Result<()> {
        let set = self.sets.iter_mut().find(|s| s.active && s.inode == inode);
        match set {
            Some(s) => {
                s.active = false;
                s.count = 0;
                s.inode = 0;
                self.count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Set an extended attribute on `inode`.
    pub fn do_setxattr(&mut self, inode: u64, name: &[u8], value: &[u8], flags: i32) -> Result<()> {
        let set = self.get_or_create(inode)?;
        set.setxattr(name, value, flags)
    }

    /// Get an extended attribute from `inode`, copying into
    /// `buf`. Returns the number of bytes written.
    pub fn do_getxattr(&mut self, inode: u64, name: &[u8], buf: &mut [u8]) -> Result<usize> {
        let set = self.get_or_create(inode)?;
        let val = set.getxattr(name)?;
        if val.len() > buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[..val.len()].copy_from_slice(val);
        Ok(val.len())
    }

    /// List all extended attribute names on `inode`.
    pub fn do_listxattr(&mut self, inode: u64, buf: &mut [u8]) -> Result<usize> {
        let set = self.get_or_create(inode)?;
        set.listxattr(buf)
    }

    /// Remove an extended attribute from `inode`.
    pub fn do_removexattr(&mut self, inode: u64, name: &[u8]) -> Result<()> {
        let set = self.get_or_create(inode)?;
        set.removexattr(name)
    }

    /// Returns the number of inodes with active xattr sets.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no inodes have xattr sets.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
