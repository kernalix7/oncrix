// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sysfs attribute operations.
//!
//! Extends the basic sysfs tree ([`crate::sysfs`]) with a full
//! attribute operation layer, modelling the Linux `struct
//! attribute_group` and `struct device_attribute` APIs.
//!
//! # Concepts
//!
//! - **Attribute**: A single virtual file under `/sys` that exposes or
//!   controls a kernel/device property. Reading returns a string;
//!   writing parses a string and updates the property.
//!
//! - **Attribute group**: A named collection of attributes logically
//!   belonging to the same object (e.g., all power-management
//!   attributes of a device). Groups can be created and removed
//!   atomically.
//!
//! - **Binary attribute**: Like a normal attribute but transfers raw
//!   bytes rather than human-readable strings.
//!
//! # Operations
//!
//! Each attribute declares:
//! - `read_fn`: Called on `read(2)`. Writes a text representation into
//!   the caller's buffer and returns the byte count.
//! - `write_fn` (optional): Called on `write(2)`. Receives the raw
//!   bytes and returns `Ok(())` or an error.
//! - `mode`: POSIX permission bits (e.g., 0o444 for read-only).
//!
//! # Namespace support
//!
//! Each attribute can declare a namespace tag. Only processes whose
//! network/user namespace matches the tag can see the attribute.
//! The `None` tag means globally visible.
//!
//! # References
//!
//! Linux `fs/sysfs/`, `include/linux/sysfs.h`;
//! Linux Device Model documentation.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of attribute definitions registered globally.
pub const MAX_ATTRS: usize = 256;

/// Maximum number of attribute groups.
pub const MAX_GROUPS: usize = 64;

/// Maximum number of attributes per group.
pub const MAX_ATTRS_PER_GROUP: usize = 32;

/// Maximum length of an attribute name.
pub const MAX_ATTR_NAME: usize = 64;

/// Maximum length of an attribute group name.
pub const MAX_GROUP_NAME: usize = 64;

/// Maximum length of a kobject path prefix.
pub const MAX_KOBJ_PATH: usize = 128;

// ── Attribute permissions ────────────────────────────────────────────────────

/// Read permission for owner (0o400).
pub const S_IRUSR: u16 = 0o400;
/// Write permission for owner (0o200).
pub const S_IWUSR: u16 = 0o200;
/// Read permission for group (0o040).
pub const S_IRGRP: u16 = 0o040;
/// Write permission for group (0o020).
pub const S_IWGRP: u16 = 0o020;
/// Read permission for others (0o004).
pub const S_IROTH: u16 = 0o004;

/// Standard read-only attribute permission (rw-r--r-- stripped of w).
pub const ATTR_MODE_RO: u16 = S_IRUSR | S_IRGRP | S_IROTH;

/// Standard read-write attribute permission.
pub const ATTR_MODE_RW: u16 = S_IRUSR | S_IWUSR | S_IRGRP;

// ── Callbacks ────────────────────────────────────────────────────────────────

/// Read callback: fills `buf` with attribute content and returns byte count.
pub type AttrReadFn = fn(attr_id: u32, buf: &mut [u8]) -> usize;

/// Write callback: processes `data` written to the attribute.
pub type AttrWriteFn = fn(attr_id: u32, data: &[u8]) -> Result<()>;

/// Binary read callback: fills `buf` with raw bytes.
pub type BinAttrReadFn = fn(attr_id: u32, buf: &mut [u8], offset: u64) -> usize;

/// Binary write callback: processes raw bytes written to the attribute.
pub type BinAttrWriteFn = fn(attr_id: u32, data: &[u8], offset: u64) -> Result<()>;

// ── SysfsAttrDef ─────────────────────────────────────────────────────────────

/// A sysfs attribute definition.
#[derive(Clone, Copy)]
pub struct SysfsAttrDef {
    /// Unique attribute identifier (index into the global table).
    pub id: u32,
    /// Attribute name (null-padded).
    name: [u8; MAX_ATTR_NAME],
    /// Length of the name.
    name_len: usize,
    /// POSIX permission bits.
    pub mode: u16,
    /// Read callback.
    pub read_fn: Option<AttrReadFn>,
    /// Write callback.
    pub write_fn: Option<AttrWriteFn>,
    /// Whether this is a binary attribute.
    pub is_binary: bool,
    /// Binary read callback (only meaningful when `is_binary` is true).
    pub bin_read_fn: Option<BinAttrReadFn>,
    /// Binary write callback.
    pub bin_write_fn: Option<BinAttrWriteFn>,
    /// Maximum binary attribute size in bytes (0 = unlimited).
    pub bin_size: usize,
    /// Namespace tag (`0` = globally visible).
    pub namespace: u32,
}

impl SysfsAttrDef {
    /// Create a text attribute with the given name, mode, and callbacks.
    pub fn new_text(
        name: &[u8],
        mode: u16,
        read_fn: Option<AttrReadFn>,
        write_fn: Option<AttrWriteFn>,
    ) -> Self {
        let mut buf = [0u8; MAX_ATTR_NAME];
        let len = name.len().min(MAX_ATTR_NAME);
        buf[..len].copy_from_slice(&name[..len]);
        Self {
            id: 0,
            name: buf,
            name_len: len,
            mode,
            read_fn,
            write_fn,
            is_binary: false,
            bin_read_fn: None,
            bin_write_fn: None,
            bin_size: 0,
            namespace: 0,
        }
    }

    /// Create a binary attribute.
    pub fn new_binary(
        name: &[u8],
        mode: u16,
        size: usize,
        read_fn: Option<BinAttrReadFn>,
        write_fn: Option<BinAttrWriteFn>,
    ) -> Self {
        let mut buf = [0u8; MAX_ATTR_NAME];
        let len = name.len().min(MAX_ATTR_NAME);
        buf[..len].copy_from_slice(&name[..len]);
        Self {
            id: 0,
            name: buf,
            name_len: len,
            mode,
            read_fn: None,
            write_fn: None,
            is_binary: true,
            bin_read_fn: read_fn,
            bin_write_fn: write_fn,
            bin_size: size,
            namespace: 0,
        }
    }

    /// Return the attribute name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return `true` if the attribute is readable.
    pub fn is_readable(&self) -> bool {
        self.mode & (S_IRUSR | S_IRGRP | S_IROTH) != 0
            && (self.read_fn.is_some() || self.bin_read_fn.is_some())
    }

    /// Return `true` if the attribute is writable.
    pub fn is_writable(&self) -> bool {
        self.mode & (S_IWUSR | S_IWGRP) != 0
            && (self.write_fn.is_some() || self.bin_write_fn.is_some())
    }
}

impl core::fmt::Debug for SysfsAttrDef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysfsAttrDef")
            .field("id", &self.id)
            .field("name", &self.name())
            .field("mode", &self.mode)
            .field("binary", &self.is_binary)
            .finish()
    }
}

// ── SysfsAttrGroup ────────────────────────────────────────────────────────────

/// A named group of sysfs attributes belonging to the same kobject.
#[derive(Clone, Copy)]
pub struct SysfsAttrGroup {
    /// Group identifier.
    pub id: u32,
    /// Group name (null-padded).
    name: [u8; MAX_GROUP_NAME],
    /// Length of the group name.
    name_len: usize,
    /// Kobject path this group is attached to.
    kobj_path: [u8; MAX_KOBJ_PATH],
    /// Length of the kobject path.
    kobj_path_len: usize,
    /// Attribute IDs in this group.
    attr_ids: [u32; MAX_ATTRS_PER_GROUP],
    /// Number of attributes in this group.
    attr_count: usize,
    /// Whether this group is currently visible.
    pub visible: bool,
}

impl SysfsAttrGroup {
    /// Create a new group with the given name and kobject path.
    pub fn new(name: &[u8], kobj_path: &[u8]) -> Self {
        let mut nbuf = [0u8; MAX_GROUP_NAME];
        let nlen = name.len().min(MAX_GROUP_NAME);
        nbuf[..nlen].copy_from_slice(&name[..nlen]);
        let mut kbuf = [0u8; MAX_KOBJ_PATH];
        let klen = kobj_path.len().min(MAX_KOBJ_PATH);
        kbuf[..klen].copy_from_slice(&kobj_path[..klen]);
        Self {
            id: 0,
            name: nbuf,
            name_len: nlen,
            kobj_path: kbuf,
            kobj_path_len: klen,
            attr_ids: [0u32; MAX_ATTRS_PER_GROUP],
            attr_count: 0,
            visible: true,
        }
    }

    /// Return the group name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the kobject path as a byte slice.
    pub fn kobj_path(&self) -> &[u8] {
        &self.kobj_path[..self.kobj_path_len]
    }

    /// Add an attribute ID to this group.
    pub fn add_attr(&mut self, attr_id: u32) -> Result<()> {
        if self.attr_count >= MAX_ATTRS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.attr_ids[self.attr_count] = attr_id;
        self.attr_count += 1;
        Ok(())
    }

    /// Remove an attribute ID from this group.
    pub fn remove_attr(&mut self, attr_id: u32) {
        for i in 0..self.attr_count {
            if self.attr_ids[i] == attr_id {
                self.attr_ids[i] = self.attr_ids[self.attr_count - 1];
                self.attr_count -= 1;
                return;
            }
        }
    }

    /// Return the number of attributes in this group.
    pub fn attr_count(&self) -> usize {
        self.attr_count
    }

    /// Iterate attribute IDs in this group.
    pub fn attr_ids(&self) -> &[u32] {
        &self.attr_ids[..self.attr_count]
    }
}

impl core::fmt::Debug for SysfsAttrGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysfsAttrGroup")
            .field("id", &self.id)
            .field("name", &self.name())
            .field("kobj_path", &self.kobj_path())
            .field("attr_count", &self.attr_count)
            .finish()
    }
}

// ── SysfsAttrRegistry ─────────────────────────────────────────────────────────

/// Global sysfs attribute and group registry.
///
/// Drivers and subsystems register their attributes here. The VFS
/// sysfs backend queries this registry to service `read(2)` and
/// `write(2)` on attribute files.
pub struct SysfsAttrRegistry {
    /// Registered attribute definitions.
    attrs: [Option<SysfsAttrDef>; MAX_ATTRS],
    /// Number of registered attributes.
    attr_count: usize,
    /// Next attribute ID to assign.
    next_attr_id: u32,
    /// Registered attribute groups.
    groups: [Option<SysfsAttrGroup>; MAX_GROUPS],
    /// Number of registered groups.
    group_count: usize,
    /// Next group ID to assign.
    next_group_id: u32,
    /// Read-operation counter.
    pub reads: u64,
    /// Write-operation counter.
    pub writes: u64,
}

impl SysfsAttrRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            attrs: [const { None }; MAX_ATTRS],
            attr_count: 0,
            next_attr_id: 1,
            groups: [const { None }; MAX_GROUPS],
            group_count: 0,
            next_group_id: 1,
            reads: 0,
            writes: 0,
        }
    }

    // ── Attribute registration ───────────────────────────────────────────────

    /// Register an attribute definition.
    ///
    /// Returns the assigned attribute ID.
    pub fn register_attr(&mut self, mut def: SysfsAttrDef) -> Result<u32> {
        if self.attr_count >= MAX_ATTRS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_attr_id;
        self.next_attr_id = self.next_attr_id.wrapping_add(1);
        def.id = id;
        for slot in self.attrs.iter_mut() {
            if slot.is_none() {
                *slot = Some(def);
                self.attr_count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister an attribute by ID.
    pub fn unregister_attr(&mut self, id: u32) -> Result<()> {
        for slot in self.attrs.iter_mut() {
            if slot.as_ref().map(|a| a.id == id).unwrap_or(false) {
                *slot = None;
                self.attr_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up an attribute by ID.
    pub fn find_attr(&self, id: u32) -> Option<&SysfsAttrDef> {
        self.attrs.iter().flatten().find(|a| a.id == id)
    }

    /// Find an attribute by name within a kobject path.
    pub fn find_attr_by_name(&self, kobj_path: &[u8], name: &[u8]) -> Option<&SysfsAttrDef> {
        // First find a group attached to kobj_path.
        for group in self.groups.iter().flatten() {
            if group.kobj_path() != kobj_path {
                continue;
            }
            for &attr_id in group.attr_ids() {
                if let Some(attr) = self.find_attr(attr_id) {
                    if attr.name() == name {
                        return Some(attr);
                    }
                }
            }
        }
        // Also scan ungrouped attributes by name only.
        self.attrs.iter().flatten().find(|a| a.name() == name)
    }

    // ── Group management ─────────────────────────────────────────────────────

    /// Register a new attribute group.
    ///
    /// Returns the assigned group ID.
    pub fn create_group(&mut self, mut group: SysfsAttrGroup) -> Result<u32> {
        if self.group_count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);
        group.id = id;
        for slot in self.groups.iter_mut() {
            if slot.is_none() {
                *slot = Some(group);
                self.group_count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a group by ID, along with all its registered attributes.
    pub fn remove_group(&mut self, group_id: u32) -> Result<()> {
        let mut attr_ids = [0u32; MAX_ATTRS_PER_GROUP];
        let mut attr_count = 0usize;

        for slot in self.groups.iter_mut() {
            if slot.as_ref().map(|g| g.id == group_id).unwrap_or(false) {
                if let Some(ref g) = *slot {
                    attr_count = g.attr_count();
                    attr_ids[..attr_count].copy_from_slice(g.attr_ids());
                }
                *slot = None;
                self.group_count -= 1;
                break;
            }
        }

        for i in 0..attr_count {
            let _ = self.unregister_attr(attr_ids[i]);
        }
        Ok(())
    }

    /// Find a group by its kobject path and name.
    pub fn find_group(&self, kobj_path: &[u8], name: &[u8]) -> Option<&SysfsAttrGroup> {
        self.groups
            .iter()
            .flatten()
            .find(|g| g.kobj_path() == kobj_path && g.name() == name)
    }

    // ── I/O dispatch ─────────────────────────────────────────────────────────

    /// Dispatch a read on attribute `id`, filling `buf` with content.
    ///
    /// Returns the number of bytes written into `buf`.
    pub fn read_attr(&mut self, id: u32, buf: &mut [u8]) -> Result<usize> {
        let attr = self
            .attrs
            .iter()
            .flatten()
            .find(|a| a.id == id)
            .ok_or(Error::NotFound)?;

        if !attr.is_readable() {
            return Err(Error::PermissionDenied);
        }

        let read_fn = if attr.is_binary {
            return Err(Error::InvalidArgument); // use read_bin_attr for binary
        } else {
            attr.read_fn.ok_or(Error::NotImplemented)?
        };

        self.reads += 1;
        let n = read_fn(id, buf);
        Ok(n)
    }

    /// Dispatch a write to attribute `id` with `data`.
    pub fn write_attr(&mut self, id: u32, data: &[u8]) -> Result<()> {
        let attr = self
            .attrs
            .iter()
            .flatten()
            .find(|a| a.id == id)
            .ok_or(Error::NotFound)?;

        if !attr.is_writable() {
            return Err(Error::PermissionDenied);
        }

        let write_fn = if attr.is_binary {
            return Err(Error::InvalidArgument);
        } else {
            attr.write_fn.ok_or(Error::NotImplemented)?
        };

        self.writes += 1;
        write_fn(id, data)
    }

    /// Dispatch a binary read on attribute `id`.
    pub fn read_bin_attr(&mut self, id: u32, buf: &mut [u8], offset: u64) -> Result<usize> {
        let attr = self
            .attrs
            .iter()
            .flatten()
            .find(|a| a.id == id)
            .ok_or(Error::NotFound)?;

        if !attr.is_binary || !attr.is_readable() {
            return Err(Error::InvalidArgument);
        }
        let read_fn = attr.bin_read_fn.ok_or(Error::NotImplemented)?;
        self.reads += 1;
        Ok(read_fn(id, buf, offset))
    }

    /// Dispatch a binary write to attribute `id`.
    pub fn write_bin_attr(&mut self, id: u32, data: &[u8], offset: u64) -> Result<()> {
        let attr = self
            .attrs
            .iter()
            .flatten()
            .find(|a| a.id == id)
            .ok_or(Error::NotFound)?;

        if !attr.is_binary || !attr.is_writable() {
            return Err(Error::InvalidArgument);
        }
        let write_fn = attr.bin_write_fn.ok_or(Error::NotImplemented)?;
        self.writes += 1;
        write_fn(id, data, offset)
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return the number of registered attributes.
    pub fn attr_count(&self) -> usize {
        self.attr_count
    }

    /// Return the number of registered groups.
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    /// Return a snapshot of registry statistics.
    pub fn stats(&self) -> SysfsAttrStats {
        let mut ro = 0usize;
        let mut rw = 0usize;
        let mut binary = 0usize;
        for attr in self.attrs.iter().flatten() {
            if attr.is_binary {
                binary += 1;
            } else if attr.is_writable() {
                rw += 1;
            } else {
                ro += 1;
            }
        }
        SysfsAttrStats {
            total_attrs: self.attr_count,
            readonly_attrs: ro,
            readwrite_attrs: rw,
            binary_attrs: binary,
            total_groups: self.group_count,
            reads: self.reads,
            writes: self.writes,
        }
    }
}

impl Default for SysfsAttrRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── SysfsAttrStats ───────────────────────────────────────────────────────────

/// Snapshot of sysfs attribute registry statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysfsAttrStats {
    /// Total registered attributes.
    pub total_attrs: usize,
    /// Read-only attributes.
    pub readonly_attrs: usize,
    /// Read-write attributes.
    pub readwrite_attrs: usize,
    /// Binary attributes.
    pub binary_attrs: usize,
    /// Total registered groups.
    pub total_groups: usize,
    /// Total read operations dispatched.
    pub reads: u64,
    /// Total write operations dispatched.
    pub writes: u64,
}

// ── Attribute builder ─────────────────────────────────────────────────────────

/// Builder for constructing [`SysfsAttrDef`] with method chaining.
pub struct AttrBuilder {
    def: SysfsAttrDef,
}

impl AttrBuilder {
    /// Create a builder for a text attribute with the given name.
    pub fn text(name: &[u8]) -> Self {
        Self {
            def: SysfsAttrDef::new_text(name, ATTR_MODE_RO, None, None),
        }
    }

    /// Create a builder for a binary attribute.
    pub fn binary(name: &[u8], size: usize) -> Self {
        Self {
            def: SysfsAttrDef::new_binary(name, ATTR_MODE_RO, size, None, None),
        }
    }

    /// Set the permission mode.
    pub fn mode(mut self, mode: u16) -> Self {
        self.def.mode = mode;
        self
    }

    /// Set the read callback.
    pub fn read(mut self, f: AttrReadFn) -> Self {
        self.def.read_fn = Some(f);
        self
    }

    /// Set the write callback.
    pub fn write(mut self, f: AttrWriteFn) -> Self {
        self.def.write_fn = Some(f);
        self.def.mode |= S_IWUSR;
        self
    }

    /// Set the namespace tag.
    pub fn namespace(mut self, ns: u32) -> Self {
        self.def.namespace = ns;
        self
    }

    /// Finalise and return the attribute definition.
    pub fn build(self) -> SysfsAttrDef {
        self.def
    }
}

// ── Symlink support ───────────────────────────────────────────────────────────

/// Maximum number of sysfs symlinks.
const MAX_LINKS: usize = 128;

/// Maximum length of a symlink target path.
const MAX_LINK_TARGET: usize = 256;

/// A sysfs symbolic link entry.
///
/// Mirrors Linux `sysfs_create_link()` / `kernfs_create_link()`.
#[derive(Debug, Clone, Copy)]
pub struct SysfsLink {
    /// Unique link ID.
    pub id: u32,
    /// Kobject path where the link lives (the directory).
    pub kobj_path: [u8; MAX_KOBJ_PATH],
    /// Length of kobj_path.
    pub kobj_path_len: usize,
    /// Link name (the filename of the symlink).
    pub link_name: [u8; MAX_ATTR_NAME],
    /// Length of link_name.
    pub link_name_len: usize,
    /// Target kobject path (what the symlink points to).
    pub target: [u8; MAX_LINK_TARGET],
    /// Length of target.
    pub target_len: usize,
}

impl SysfsLink {
    /// Create a new symlink descriptor.
    ///
    /// Returns `None` if any argument exceeds its buffer limit.
    pub fn new(kobj_path: &[u8], link_name: &[u8], target: &[u8]) -> Option<Self> {
        if kobj_path.len() > MAX_KOBJ_PATH
            || link_name.len() > MAX_ATTR_NAME
            || target.len() > MAX_LINK_TARGET
        {
            return None;
        }
        let mut kp = [0u8; MAX_KOBJ_PATH];
        kp[..kobj_path.len()].copy_from_slice(kobj_path);
        let mut ln = [0u8; MAX_ATTR_NAME];
        ln[..link_name.len()].copy_from_slice(link_name);
        let mut tgt = [0u8; MAX_LINK_TARGET];
        tgt[..target.len()].copy_from_slice(target);
        Some(Self {
            id: 0,
            kobj_path: kp,
            kobj_path_len: kobj_path.len(),
            link_name: ln,
            link_name_len: link_name.len(),
            target: tgt,
            target_len: target.len(),
        })
    }

    /// Return the kobject path as a byte slice.
    pub fn kobj_path(&self) -> &[u8] {
        &self.kobj_path[..self.kobj_path_len]
    }

    /// Return the link name as a byte slice.
    pub fn link_name(&self) -> &[u8] {
        &self.link_name[..self.link_name_len]
    }

    /// Return the link target as a byte slice.
    pub fn target(&self) -> &[u8] {
        &self.target[..self.target_len]
    }
}

// ── Poll / notify support ────────────────────────────────────────────────────

/// Maximum number of simultaneously pending sysfs poll notifications.
const MAX_NOTIFY_QUEUE: usize = 64;

/// A pending sysfs poll notification entry.
///
/// When an attribute value changes, `sysfs_notify()` records the
/// attribute ID so that `poll(2)` waiters can be woken up.
#[derive(Debug, Clone, Copy, Default)]
struct NotifyEntry {
    /// Attribute ID that changed.
    attr_id: u32,
    /// Sequence number of the notification.
    seq: u64,
}

// ── Extended registry ─────────────────────────────────────────────────────────

/// Extended sysfs registry that adds symlinks and poll notifications to
/// [`SysfsAttrRegistry`].
pub struct SysfsRegistry {
    /// Core attribute + group registry.
    pub attrs: SysfsAttrRegistry,
    /// Registered symlinks.
    links: [Option<SysfsLink>; MAX_LINKS],
    /// Number of registered links.
    link_count: usize,
    /// Next link ID.
    next_link_id: u32,
    /// Pending poll notifications ring buffer.
    notify_queue: [NotifyEntry; MAX_NOTIFY_QUEUE],
    /// Write head of the notify queue.
    notify_head: usize,
    /// Count of pending notifications.
    notify_count: usize,
    /// Global notification sequence counter.
    notify_seq: u64,
}

impl SysfsRegistry {
    /// Create an empty extended registry.
    pub fn new() -> Self {
        Self {
            attrs: SysfsAttrRegistry::new(),
            links: core::array::from_fn(|_| None),
            link_count: 0,
            next_link_id: 1,
            notify_queue: [NotifyEntry::default(); MAX_NOTIFY_QUEUE],
            notify_head: 0,
            notify_count: 0,
            notify_seq: 0,
        }
    }

    // ── sysfs_create_file ────────────────────────────────────────────────────

    /// Create a sysfs attribute file.
    ///
    /// Mirrors `sysfs_create_file()`. Registers `def` with the registry and
    /// adds it to the group identified by `kobj_path` (creating the group if
    /// it does not yet exist under the name `"default"`).
    ///
    /// Returns the attribute ID.
    pub fn sysfs_create_file(&mut self, kobj_path: &[u8], def: SysfsAttrDef) -> Result<u32> {
        let attr_id = self.attrs.register_attr(def)?;
        // Ensure a default group exists for this kobject.
        let group_id = match self.attrs.find_group(kobj_path, b"default") {
            Some(g) => g.id,
            None => {
                let group = SysfsAttrGroup::new(b"default", kobj_path);
                self.attrs.create_group(group)?
            }
        };
        // Add attr to the group.
        for slot in self.attrs.groups.iter_mut().flatten() {
            if slot.id == group_id {
                slot.add_attr(attr_id)?;
                break;
            }
        }
        Ok(attr_id)
    }

    /// Remove a sysfs attribute file by attribute ID.
    ///
    /// Mirrors `sysfs_remove_file()`.
    pub fn sysfs_remove_file(&mut self, attr_id: u32) -> Result<()> {
        // Remove from any group that contains it.
        for slot in self.attrs.groups.iter_mut().flatten() {
            slot.remove_attr(attr_id);
        }
        self.attrs.unregister_attr(attr_id)
    }

    // ── sysfs_create_group ───────────────────────────────────────────────────

    /// Create a named attribute group under `kobj_path`.
    ///
    /// Mirrors `sysfs_create_group()`. Registers all attributes in `defs`,
    /// creates a group, and adds all the attributes to it.
    ///
    /// Returns the group ID.
    pub fn sysfs_create_group(
        &mut self,
        kobj_path: &[u8],
        group_name: &[u8],
        defs: &[SysfsAttrDef],
    ) -> Result<u32> {
        let mut group = SysfsAttrGroup::new(group_name, kobj_path);
        // Pre-check capacity.
        if defs.len() > MAX_ATTRS_PER_GROUP {
            return Err(Error::InvalidArgument);
        }
        // Register all attributes.
        let mut attr_ids = [0u32; MAX_ATTRS_PER_GROUP];
        let mut registered = 0usize;
        for (i, def) in defs.iter().enumerate() {
            let id = self.attrs.register_attr(*def)?;
            attr_ids[i] = id;
            registered += 1;
        }
        // Add attribute IDs to the group.
        for i in 0..registered {
            group.add_attr(attr_ids[i])?;
        }
        self.attrs.create_group(group)
    }

    /// Remove a named attribute group.
    ///
    /// Mirrors `sysfs_remove_group()`. Removes all attributes in the group.
    pub fn sysfs_remove_group(&mut self, kobj_path: &[u8], group_name: &[u8]) -> Result<()> {
        let group_id = self
            .attrs
            .find_group(kobj_path, group_name)
            .map(|g| g.id)
            .ok_or(Error::NotFound)?;
        self.attrs.remove_group(group_id)
    }

    // ── sysfs_create_link ────────────────────────────────────────────────────

    /// Create a sysfs symbolic link.
    ///
    /// Mirrors `sysfs_create_link()`. Records `link_name` inside `kobj_path`
    /// pointing to `target`.
    ///
    /// Returns the link ID.
    pub fn sysfs_create_link(
        &mut self,
        kobj_path: &[u8],
        link_name: &[u8],
        target: &[u8],
    ) -> Result<u32> {
        if self.link_count >= MAX_LINKS {
            return Err(Error::OutOfMemory);
        }
        let mut link =
            SysfsLink::new(kobj_path, link_name, target).ok_or(Error::InvalidArgument)?;
        let id = self.next_link_id;
        self.next_link_id = self.next_link_id.wrapping_add(1);
        link.id = id;
        for slot in &mut self.links {
            if slot.is_none() {
                *slot = Some(link);
                self.link_count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a sysfs symbolic link.
    ///
    /// Mirrors `sysfs_remove_link()`.
    pub fn sysfs_remove_link(&mut self, kobj_path: &[u8], link_name: &[u8]) -> Result<()> {
        for slot in &mut self.links {
            let matches = slot
                .as_ref()
                .map(|l| l.kobj_path() == kobj_path && l.link_name() == link_name)
                .unwrap_or(false);
            if matches {
                *slot = None;
                self.link_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up the target of a symlink.
    ///
    /// Returns the target path bytes, or `None` if not found.
    pub fn readlink(&self, kobj_path: &[u8], link_name: &[u8]) -> Option<&[u8]> {
        for slot in self.links.iter().flatten() {
            if slot.kobj_path() == kobj_path && slot.link_name() == link_name {
                return Some(slot.target());
            }
        }
        None
    }

    // ── sysfs_notify ────────────────────────────────────────────────────────

    /// Notify poll waiters that attribute `attr_id` has changed.
    ///
    /// Mirrors `sysfs_notify()`. Enqueues a notification entry; callers
    /// polling on the attribute's file will see POLLIN | POLLRDNORM.
    ///
    /// If the notify queue is full, the oldest entry is silently overwritten
    /// (ring-buffer semantics).
    pub fn sysfs_notify(&mut self, attr_id: u32) {
        self.notify_seq = self.notify_seq.wrapping_add(1);
        let entry = NotifyEntry {
            attr_id,
            seq: self.notify_seq,
        };
        let slot = self.notify_head % MAX_NOTIFY_QUEUE;
        let was_full = self.notify_count >= MAX_NOTIFY_QUEUE;
        self.notify_queue[slot] = entry;
        self.notify_head = (self.notify_head + 1) % MAX_NOTIFY_QUEUE;
        if !was_full {
            self.notify_count += 1;
        }
    }

    /// Check whether `attr_id` has a pending notification.
    ///
    /// Returns the notification sequence number if pending, or `None`.
    pub fn poll_check(&self, attr_id: u32) -> Option<u64> {
        for i in 0..self.notify_count {
            let idx = self.notify_head.wrapping_sub(1 + i) % MAX_NOTIFY_QUEUE;
            if self.notify_queue[idx].attr_id == attr_id {
                return Some(self.notify_queue[idx].seq);
            }
        }
        None
    }

    /// Consume (drain) all pending notifications for `attr_id`.
    ///
    /// Returns the number of notifications consumed.
    pub fn poll_consume(&mut self, attr_id: u32) -> usize {
        let mut consumed = 0usize;
        for entry in &mut self.notify_queue {
            if entry.attr_id == attr_id && entry.seq != 0 {
                entry.seq = 0;
                entry.attr_id = 0;
                consumed += 1;
            }
        }
        if consumed > 0 {
            self.notify_count = self.notify_count.saturating_sub(consumed);
        }
        consumed
    }

    // ── I/O dispatch (delegated) ─────────────────────────────────────────────

    /// Read an attribute. Delegates to [`SysfsAttrRegistry::read_attr`].
    pub fn read_attr(&mut self, id: u32, buf: &mut [u8]) -> Result<usize> {
        self.attrs.read_attr(id, buf)
    }

    /// Write an attribute. Delegates to [`SysfsAttrRegistry::write_attr`].
    ///
    /// Automatically calls `sysfs_notify()` after a successful write.
    pub fn write_attr(&mut self, id: u32, data: &[u8]) -> Result<()> {
        self.attrs.write_attr(id, data)?;
        self.sysfs_notify(id);
        Ok(())
    }

    /// Read a binary attribute.
    pub fn read_bin_attr(&mut self, id: u32, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.attrs.read_bin_attr(id, buf, offset)
    }

    /// Write a binary attribute.
    ///
    /// Automatically calls `sysfs_notify()` after a successful write.
    pub fn write_bin_attr(&mut self, id: u32, data: &[u8], offset: u64) -> Result<()> {
        self.attrs.write_bin_attr(id, data, offset)?;
        self.sysfs_notify(id);
        Ok(())
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return combined statistics.
    pub fn stats(&self) -> SysfsRegistryStats {
        let inner = self.attrs.stats();
        SysfsRegistryStats {
            attrs: inner,
            link_count: self.link_count,
            pending_notifications: self.notify_count,
        }
    }

    /// Iterate all registered links.
    pub fn iter_links(&self) -> impl Iterator<Item = &SysfsLink> {
        self.links.iter().flatten()
    }
}

impl Default for SysfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined statistics for the extended registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysfsRegistryStats {
    /// Inner attribute registry stats.
    pub attrs: SysfsAttrStats,
    /// Number of registered symlinks.
    pub link_count: usize,
    /// Number of pending poll notifications.
    pub pending_notifications: usize,
}

// ── Linux-named free functions ────────────────────────────────────────────────
//
// These match the Linux kernel API signatures from fs/sysfs/file.c and
// fs/sysfs/symlink.c, adapted to work with our SysfsRegistry.

/// Create a single sysfs attribute file.
///
/// Mirrors `sysfs_create_file()`.
pub fn sysfs_create_file(
    reg: &mut SysfsRegistry,
    kobj_path: &[u8],
    def: SysfsAttrDef,
) -> Result<u32> {
    reg.sysfs_create_file(kobj_path, def)
}

/// Remove a sysfs attribute file.
///
/// Mirrors `sysfs_remove_file()`.
pub fn sysfs_remove_file(reg: &mut SysfsRegistry, attr_id: u32) -> Result<()> {
    reg.sysfs_remove_file(attr_id)
}

/// Create a named attribute group.
///
/// Mirrors `sysfs_create_group()`.
pub fn sysfs_create_group(
    reg: &mut SysfsRegistry,
    kobj_path: &[u8],
    group_name: &[u8],
    defs: &[SysfsAttrDef],
) -> Result<u32> {
    reg.sysfs_create_group(kobj_path, group_name, defs)
}

/// Remove a named attribute group.
///
/// Mirrors `sysfs_remove_group()`.
pub fn sysfs_remove_group(
    reg: &mut SysfsRegistry,
    kobj_path: &[u8],
    group_name: &[u8],
) -> Result<()> {
    reg.sysfs_remove_group(kobj_path, group_name)
}

/// Create a sysfs symlink.
///
/// Mirrors `sysfs_create_link()`.
pub fn sysfs_create_link(
    reg: &mut SysfsRegistry,
    kobj_path: &[u8],
    link_name: &[u8],
    target: &[u8],
) -> Result<u32> {
    reg.sysfs_create_link(kobj_path, link_name, target)
}

/// Remove a sysfs symlink.
///
/// Mirrors `sysfs_remove_link()`.
pub fn sysfs_remove_link(
    reg: &mut SysfsRegistry,
    kobj_path: &[u8],
    link_name: &[u8],
) -> Result<()> {
    reg.sysfs_remove_link(kobj_path, link_name)
}

/// Notify poll(2) waiters that an attribute value has changed.
///
/// Mirrors `sysfs_notify()`.
pub fn sysfs_notify(reg: &mut SysfsRegistry, attr_id: u32) {
    reg.sysfs_notify(attr_id);
}

/// Notify on a specific attribute identified by name within a kobject.
///
/// Mirrors `sysfs_notify_dirent()` (convenience wrapper).
pub fn sysfs_notify_by_name(
    reg: &mut SysfsRegistry,
    kobj_path: &[u8],
    attr_name: &[u8],
) -> Result<()> {
    let attr_id = reg
        .attrs
        .find_attr_by_name(kobj_path, attr_name)
        .map(|a| a.id)
        .ok_or(Error::NotFound)?;
    reg.sysfs_notify(attr_id);
    Ok(())
}
