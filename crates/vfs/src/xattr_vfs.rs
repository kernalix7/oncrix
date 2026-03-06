// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS-level extended attribute (xattr) integration layer.
//!
//! Provides a unified interface for managing extended attributes
//! across different filesystem implementations. Supports namespace-
//! aware permission checks (user, trusted, security) and dispatches
//! operations to filesystem-specific handlers matched by prefix.
//!
//! # Design
//!
//! Each filesystem registers an [`XattrHandler`] with a prefix
//! (e.g., `user.`, `security.`). When an xattr operation arrives,
//! [`VfsXattrTable`] matches the attribute name to the appropriate
//! handler and enforces permission checks based on the namespace.
//!
//! # References
//!
//! - Linux `xattr(7)`, `setxattr(2)`, `getxattr(2)`
//! - POSIX.1-2024 extended attributes

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum size of an extended attribute value in bytes.
pub const XATTR_SIZE_MAX: usize = 65536;

/// Maximum total size of the xattr name list in bytes.
pub const XATTR_LIST_MAX: usize = 65536;

/// Maximum length of an extended attribute name in bytes.
pub const XATTR_NAME_MAX: usize = 255;

/// Maximum number of registered xattr handlers.
pub const MAX_XATTR_HANDLERS: usize = 8;

/// Maximum number of xattr entries in the table.
const MAX_XATTR_ENTRIES: usize = 512;

/// Xattr set flag: create only (fail if exists).
pub const XATTR_CREATE: i32 = 1;

/// Xattr set flag: replace only (fail if not exists).
pub const XATTR_REPLACE: i32 = 2;

// ── Namespace prefixes ──────────────────────────────────────────

/// Prefix for user namespace xattrs.
const NS_USER: &[u8] = b"user.";

/// Prefix for trusted namespace xattrs.
const NS_TRUSTED: &[u8] = b"trusted.";

/// Prefix for security namespace xattrs.
const NS_SECURITY: &[u8] = b"security.";

// ── XattrHandler ────────────────────────────────────────────────

/// Dispatches xattr operations to filesystem-specific handlers.
///
/// Each handler is associated with a namespace prefix and a
/// unique identifier used to route operations.
#[derive(Clone, Copy)]
pub struct XattrHandler {
    /// Namespace prefix (e.g., `user.`, `security.`).
    pub prefix: [u8; 16],
    /// Length of the prefix in bytes.
    pub prefix_len: usize,
    /// Unique handler identifier.
    pub handler_id: u32,
    /// Whether this handler slot is active.
    pub active: bool,
}

impl XattrHandler {
    /// Creates an inactive handler with zeroed fields.
    const fn empty() -> Self {
        Self {
            prefix: [0u8; 16],
            prefix_len: 0,
            handler_id: 0,
            active: false,
        }
    }
}

// ── XattrPermission ─────────────────────────────────────────────

/// Permission context for xattr operations.
///
/// Encapsulates the owner/group/mode of the target inode so
/// that namespace-specific permission checks can be performed
/// without accessing the full inode structure.
#[derive(Debug, Clone, Copy)]
pub struct XattrPermission {
    /// Owner UID of the inode.
    pub uid: u32,
    /// Owner GID of the inode.
    pub gid: u32,
    /// File permission mode bits (lower 12 bits).
    pub mode: u16,
}

impl XattrPermission {
    /// Returns `true` if `caller_uid` may set user-namespace
    /// xattrs on this inode.
    ///
    /// The caller must own the file (matching UID) or be root
    /// (UID 0).
    pub fn can_set_user(&self, caller_uid: u32) -> bool {
        caller_uid == 0 || caller_uid == self.uid
    }

    /// Returns `true` if `caller_uid` may set trusted-namespace
    /// xattrs.
    ///
    /// Only UID 0 (root) is allowed.
    pub fn can_set_trusted(&self, caller_uid: u32) -> bool {
        caller_uid == 0
    }

    /// Returns `true` if `caller_uid` may set security-namespace
    /// xattrs.
    ///
    /// Only UID 0 (root) is allowed.
    pub fn can_set_security(&self, caller_uid: u32) -> bool {
        caller_uid == 0
    }
}

// ── VfsXattrEntry ───────────────────────────────────────────────

/// A single extended attribute stored in the VFS table.
#[derive(Clone, Copy)]
pub struct VfsXattrEntry {
    /// Inode number this xattr belongs to.
    pub inode: u64,
    /// Attribute name bytes.
    pub name: [u8; XATTR_NAME_MAX],
    /// Length of the attribute name.
    pub name_len: usize,
    /// Attribute value bytes.
    pub value: [u8; 256],
    /// Length of the attribute value.
    pub value_len: usize,
    /// Handler that owns this entry.
    pub handler_id: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl VfsXattrEntry {
    /// Creates an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            inode: 0,
            name: [0u8; XATTR_NAME_MAX],
            name_len: 0,
            value: [0u8; 256],
            value_len: 0,
            handler_id: 0,
            active: false,
        }
    }
}

// ── VfsXattrTable ───────────────────────────────────────────────

/// Global table of extended attributes managed at the VFS level.
///
/// Stores up to 512 xattr entries and up to 8 namespace handlers.
/// Provides the full lifecycle: register handlers, set/get/list/
/// remove xattrs with namespace-aware permission enforcement.
pub struct VfsXattrTable {
    /// Xattr entry storage.
    entries: [VfsXattrEntry; MAX_XATTR_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Registered namespace handlers.
    handlers: [XattrHandler; MAX_XATTR_HANDLERS],
    /// Number of registered handlers.
    handler_count: usize,
}

impl Default for VfsXattrTable {
    fn default() -> Self {
        Self::new()
    }
}

impl VfsXattrTable {
    /// Creates a new, empty xattr table.
    pub const fn new() -> Self {
        Self {
            entries: [VfsXattrEntry::empty(); MAX_XATTR_ENTRIES],
            count: 0,
            handlers: [XattrHandler::empty(); MAX_XATTR_HANDLERS],
            handler_count: 0,
        }
    }

    /// Registers a handler for a given namespace prefix.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the handler table is full.
    /// - [`Error::InvalidArgument`] if the prefix is empty or
    ///   exceeds 16 bytes.
    /// - [`Error::AlreadyExists`] if `handler_id` is already
    ///   registered.
    pub fn register_handler(&mut self, prefix: &[u8], handler_id: u32) -> Result<()> {
        if prefix.is_empty() || prefix.len() > 16 {
            return Err(Error::InvalidArgument);
        }
        if self.handler_count >= MAX_XATTR_HANDLERS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate handler_id.
        let mut i = 0;
        while i < self.handler_count {
            if self.handlers[i].active && self.handlers[i].handler_id == handler_id {
                return Err(Error::AlreadyExists);
            }
            i += 1;
        }
        let mut buf = [0u8; 16];
        let mut j = 0;
        while j < prefix.len() {
            buf[j] = prefix[j];
            j += 1;
        }
        self.handlers[self.handler_count] = XattrHandler {
            prefix: buf,
            prefix_len: prefix.len(),
            handler_id,
            active: true,
        };
        self.handler_count += 1;
        Ok(())
    }

    /// Sets an extended attribute on `inode`.
    ///
    /// Enforces namespace-based permission checks via
    /// [`XattrPermission`] before storing the value. Supports
    /// `XATTR_CREATE` and `XATTR_REPLACE` semantics.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if name or value exceeds
    ///   size limits.
    /// - [`Error::PermissionDenied`] if the caller lacks rights
    ///   for the namespace.
    /// - [`Error::AlreadyExists`] with `XATTR_CREATE` if the
    ///   attribute already exists.
    /// - [`Error::NotFound`] with `XATTR_REPLACE` if the
    ///   attribute does not exist.
    /// - [`Error::OutOfMemory`] if the table is full.
    pub fn vfs_setxattr(
        &mut self,
        inode: u64,
        name: &[u8],
        value: &[u8],
        flags: i32,
        perm: &XattrPermission,
        caller_uid: u32,
    ) -> Result<()> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if value.len() > XATTR_SIZE_MAX || value.len() > 256 {
            return Err(Error::InvalidArgument);
        }

        // Namespace permission check.
        Self::check_namespace_perm(name, perm, caller_uid)?;

        // Find existing entry.
        let existing = self.find_entry_index(inode, name);

        if flags == XATTR_CREATE && existing.is_some() {
            return Err(Error::AlreadyExists);
        }
        if flags == XATTR_REPLACE && existing.is_none() {
            return Err(Error::NotFound);
        }

        let handler_id = self.find_handler(name).unwrap_or(0);

        if let Some(idx) = existing {
            // Update in place.
            self.write_entry(idx, inode, name, value, handler_id);
        } else {
            // Find a free slot.
            let slot = self.find_free_slot()?;
            self.write_entry(slot, inode, name, value, handler_id);
            self.count += 1;
        }
        Ok(())
    }

    /// Retrieves the value of an extended attribute.
    ///
    /// Copies the value into `buf` and returns the number of
    /// bytes written.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the attribute does not exist.
    /// - [`Error::InvalidArgument`] if `buf` is too small.
    pub fn vfs_getxattr(&self, inode: u64, name: &[u8], buf: &mut [u8]) -> Result<usize> {
        let idx = self.find_entry_index(inode, name).ok_or(Error::NotFound)?;
        let entry = &self.entries[idx];
        if buf.len() < entry.value_len {
            return Err(Error::InvalidArgument);
        }
        let mut i = 0;
        while i < entry.value_len {
            buf[i] = entry.value[i];
            i += 1;
        }
        Ok(entry.value_len)
    }

    /// Lists all xattr names for `inode` as a null-separated
    /// byte sequence.
    ///
    /// Returns the total number of bytes written to `buf`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `buf` is too small.
    pub fn vfs_listxattr(&self, inode: u64, buf: &mut [u8]) -> Result<usize> {
        // First pass: compute required size.
        let mut total: usize = 0;
        let mut i = 0;
        while i < MAX_XATTR_ENTRIES {
            if self.entries[i].active && self.entries[i].inode == inode {
                // name bytes + null terminator
                total = total
                    .checked_add(self.entries[i].name_len + 1)
                    .ok_or(Error::InvalidArgument)?;
            }
            i += 1;
        }
        if total > buf.len() {
            return Err(Error::InvalidArgument);
        }

        // Second pass: write names.
        let mut offset: usize = 0;
        i = 0;
        while i < MAX_XATTR_ENTRIES {
            if self.entries[i].active && self.entries[i].inode == inode {
                let nlen = self.entries[i].name_len;
                let mut j = 0;
                while j < nlen {
                    buf[offset + j] = self.entries[i].name[j];
                    j += 1;
                }
                buf[offset + nlen] = 0;
                offset += nlen + 1;
            }
            i += 1;
        }
        Ok(offset)
    }

    /// Removes an extended attribute from `inode`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the attribute does not exist.
    /// - [`Error::PermissionDenied`] if the caller lacks rights.
    pub fn vfs_removexattr(
        &mut self,
        inode: u64,
        name: &[u8],
        perm: &XattrPermission,
        caller_uid: u32,
    ) -> Result<()> {
        Self::check_namespace_perm(name, perm, caller_uid)?;
        let idx = self.find_entry_index(inode, name).ok_or(Error::NotFound)?;
        self.entries[idx].active = false;
        self.count -= 1;
        Ok(())
    }

    /// Removes all xattr entries belonging to `inode`.
    ///
    /// Returns the number of entries removed. Useful for inode
    /// deletion cleanup.
    pub fn remove_all_for_inode(&mut self, inode: u64) -> usize {
        let mut removed: usize = 0;
        let mut i = 0;
        while i < MAX_XATTR_ENTRIES {
            if self.entries[i].active && self.entries[i].inode == inode {
                self.entries[i].active = false;
                removed += 1;
            }
            i += 1;
        }
        self.count -= removed;
        removed
    }

    /// Finds the handler ID for the given attribute name by
    /// matching registered prefixes.
    ///
    /// Returns `None` if no handler matches.
    pub fn find_handler(&self, name: &[u8]) -> Option<u32> {
        let mut i = 0;
        while i < self.handler_count {
            let h = &self.handlers[i];
            if h.active
                && name.len() >= h.prefix_len
                && Self::prefix_matches(name, &h.prefix, h.prefix_len)
            {
                return Some(h.handler_id);
            }
            i += 1;
        }
        None
    }

    /// Returns the number of xattr entries belonging to `inode`.
    pub fn count_for_inode(&self, inode: u64) -> usize {
        let mut n: usize = 0;
        let mut i = 0;
        while i < MAX_XATTR_ENTRIES {
            if self.entries[i].active && self.entries[i].inode == inode {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Returns the total number of active xattr entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active xattr entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Private helpers ─────────────────────────────────────────

    /// Checks namespace-based permissions for the attribute name.
    fn check_namespace_perm(name: &[u8], perm: &XattrPermission, caller_uid: u32) -> Result<()> {
        let allowed = if Self::prefix_matches(name, NS_TRUSTED, NS_TRUSTED.len()) {
            perm.can_set_trusted(caller_uid)
        } else if Self::prefix_matches(name, NS_SECURITY, NS_SECURITY.len()) {
            perm.can_set_security(caller_uid)
        } else if Self::prefix_matches(name, NS_USER, NS_USER.len()) {
            perm.can_set_user(caller_uid)
        } else {
            true
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Returns `true` if `data` starts with the first
    /// `prefix_len` bytes of `prefix`.
    fn prefix_matches(data: &[u8], prefix: &[u8], prefix_len: usize) -> bool {
        if data.len() < prefix_len {
            return false;
        }
        let mut i = 0;
        while i < prefix_len {
            if data[i] != prefix[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Finds the index of an existing entry matching `inode`
    /// and `name`.
    fn find_entry_index(&self, inode: u64, name: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < MAX_XATTR_ENTRIES {
            let e = &self.entries[i];
            if e.active
                && e.inode == inode
                && e.name_len == name.len()
                && Self::prefix_matches(&e.name, name, name.len())
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Finds the first free (inactive) slot in the entries array.
    fn find_free_slot(&self) -> Result<usize> {
        let mut i = 0;
        while i < MAX_XATTR_ENTRIES {
            if !self.entries[i].active {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Writes name/value data into the entry at `idx`.
    fn write_entry(&mut self, idx: usize, inode: u64, name: &[u8], value: &[u8], handler_id: u32) {
        let entry = &mut self.entries[idx];
        entry.inode = inode;
        entry.name = [0u8; XATTR_NAME_MAX];
        let mut i = 0;
        while i < name.len() {
            entry.name[i] = name[i];
            i += 1;
        }
        entry.name_len = name.len();
        entry.value = [0u8; 256];
        i = 0;
        while i < value.len() {
            entry.value[i] = value[i];
            i += 1;
        }
        entry.value_len = value.len();
        entry.handler_id = handler_id;
        entry.active = true;
    }
}
