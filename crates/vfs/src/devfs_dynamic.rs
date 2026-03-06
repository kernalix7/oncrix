// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dynamic device node creation for devfs.
//!
//! Implements the `/dev` filesystem's dynamic node management layer.
//! Device nodes are created by the kernel (or udevd) when devices are
//! probed and removed when devices are detached.
//!
//! # Design
//!
//! - [`DevNodeType`] — character device, block device, or FIFO/socket
//! - [`DevfsEntry`] — a device node record with major/minor/mode/type
//! - [`DevfsTable`] — fixed-size table of device entries
//! - `devfs_create_node` — register a new device node
//! - `devfs_remove_node` — unregister a device node by name
//!
//! # udev Compatibility
//!
//! Node names follow Linux naming conventions (e.g., `"ttyS0"`, `"sda1"`)
//! so that udev rules match the same paths.
//!
//! # References
//!
//! - Linux `drivers/base/devtmpfs.c`
//! - `man 7 udev`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a device node name (including terminator).
const NODE_NAME_LEN: usize = 64;

/// Maximum number of device entries in the table.
const MAX_DEV_ENTRIES: usize = 256;

/// S_IFBLK — block device mode bit.
pub const S_IFBLK: u16 = 0o060000;

/// S_IFCHR — character device mode bit.
pub const S_IFCHR: u16 = 0o020000;

/// S_IFIFO — named pipe mode bit.
pub const S_IFIFO: u16 = 0o010000;

/// Default mode for character device nodes (crw-rw-rw-).
pub const DEFAULT_CHR_MODE: u16 = S_IFCHR | 0o666;

/// Default mode for block device nodes (brw-rw----).
pub const DEFAULT_BLK_MODE: u16 = S_IFBLK | 0o660;

// ---------------------------------------------------------------------------
// DevNodeType
// ---------------------------------------------------------------------------

/// The type of a device node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevNodeType {
    /// Character device (streaming I/O).
    Char,
    /// Block device (random-access I/O).
    Block,
    /// Named pipe (FIFO).
    Fifo,
}

// ---------------------------------------------------------------------------
// DevfsEntry
// ---------------------------------------------------------------------------

/// A single device node entry in the devfs table.
#[derive(Clone, Debug)]
pub struct DevfsEntry {
    /// Node name (e.g., `"ttyS0"`), NUL-padded.
    pub name: [u8; NODE_NAME_LEN],
    /// Length of the node name.
    pub name_len: usize,
    /// Device major number.
    pub major: u32,
    /// Device minor number.
    pub minor: u32,
    /// POSIX mode bits including file type (S_IFCHR / S_IFBLK / S_IFIFO).
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Device node type.
    pub node_type: DevNodeType,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl DevfsEntry {
    const fn empty() -> Self {
        Self {
            name: [0u8; NODE_NAME_LEN],
            name_len: 0,
            major: 0,
            minor: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            node_type: DevNodeType::Char,
            active: false,
        }
    }

    /// Return the node name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the encoded device number (makedev format: major<<8 | minor).
    pub fn dev_t(&self) -> u64 {
        ((self.major as u64) << 8) | self.minor as u64
    }
}

// ---------------------------------------------------------------------------
// DevfsTable
// ---------------------------------------------------------------------------

/// Table of all active device nodes in devfs.
pub struct DevfsTable {
    entries: [DevfsEntry; MAX_DEV_ENTRIES],
    count: usize,
}

impl DevfsTable {
    /// Create an empty devfs table.
    pub const fn new() -> Self {
        Self {
            entries: [const { DevfsEntry::empty() }; MAX_DEV_ENTRIES],
            count: 0,
        }
    }

    /// Create a new device node.
    ///
    /// `name` must be a valid devfs node name (no path separators).
    /// `major` and `minor` must not exceed 255 each.
    ///
    /// Returns `Err(AlreadyExists)` if a node with the same name already exists.
    /// Returns `Err(OutOfMemory)` if the table is full.
    /// Returns `Err(InvalidArgument)` if the name is empty or too long.
    pub fn devfs_create_node(
        &mut self,
        name: &[u8],
        major: u32,
        minor: u32,
        mode: u16,
        uid: u32,
        gid: u32,
        node_type: DevNodeType,
    ) -> Result<()> {
        if name.is_empty() || name.len() >= NODE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        // Reject path separators to prevent directory traversal.
        if name.contains(&b'/') {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicates.
        if self.find_by_name(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_DEV_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let slot = self.count;
        let entry = &mut self.entries[slot];
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len();
        entry.major = major;
        entry.minor = minor;
        entry.mode = mode;
        entry.uid = uid;
        entry.gid = gid;
        entry.node_type = node_type;
        entry.active = true;
        self.count += 1;
        Ok(())
    }

    /// Remove a device node by name.
    ///
    /// Returns `Err(NotFound)` if no node with that name exists.
    pub fn devfs_remove_node(&mut self, name: &[u8]) -> Result<()> {
        let idx = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.name_bytes() == name)
            .ok_or(Error::NotFound)?;
        // Swap-remove for O(1) deletion.
        self.entries.swap(idx, self.count - 1);
        self.entries[self.count - 1] = DevfsEntry::empty();
        self.count -= 1;
        Ok(())
    }

    /// Look up a device node by name.
    ///
    /// Returns a reference to the entry or `None`.
    pub fn find_by_name(&self, name: &[u8]) -> Option<&DevfsEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.name_bytes() == name)
    }

    /// Look up a device node by major/minor number.
    pub fn find_by_devt(&self, major: u32, minor: u32) -> Option<&DevfsEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.major == major && e.minor == minor)
    }

    /// Return the total number of active entries.
    pub fn node_count(&self) -> usize {
        self.count
    }

    /// Iterate over all active entries, calling `f` for each.
    ///
    /// Stops on the first `Err` returned by `f`.
    pub fn for_each<F: FnMut(&DevfsEntry) -> Result<()>>(&self, mut f: F) -> Result<()> {
        for e in &self.entries[..self.count] {
            if e.active {
                f(e)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// udev-compatible naming helpers
// ---------------------------------------------------------------------------

/// Build a udev-compatible DEVPATH string for a node.
///
/// `class` is the device class (e.g., `"char"`, `"block"`).
/// `name` is the node name (e.g., `"ttyS0"`).
/// Writes `"/dev/<name>"` into `buf`, returning byte count.
pub fn devfs_make_devpath(class: &[u8], name: &[u8], buf: &mut [u8]) -> Result<usize> {
    let _ = class; // class not used in path but retained for API clarity
    let prefix = b"/dev/";
    let total = prefix.len() + name.len();
    if buf.len() < total {
        return Err(Error::InvalidArgument);
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..total].copy_from_slice(name);
    Ok(total)
}

/// Build a udev UEVENT string for a new device node.
///
/// Returns bytes written into `buf`.
/// Format: `"ACTION=add\nDEVNAME=<name>\nMAJOR=<major>\nMINOR=<minor>\n"`
pub fn devfs_uevent_add(entry: &DevfsEntry, buf: &mut [u8]) -> Result<usize> {
    let mut pos = 0;
    pos += copy_str(buf, pos, b"ACTION=add\n")?;
    pos += copy_str(buf, pos, b"DEVNAME=")?;
    pos += copy_str(buf, pos, entry.name_bytes())?;
    pos += copy_str(buf, pos, b"\n")?;
    pos += copy_str(buf, pos, b"MAJOR=")?;
    pos += write_u32_dec(buf, pos, entry.major)?;
    pos += copy_str(buf, pos, b"\n")?;
    pos += copy_str(buf, pos, b"MINOR=")?;
    pos += write_u32_dec(buf, pos, entry.minor)?;
    pos += copy_str(buf, pos, b"\n")?;
    Ok(pos)
}

fn copy_str(buf: &mut [u8], offset: usize, src: &[u8]) -> Result<usize> {
    if offset + src.len() > buf.len() {
        return Err(Error::InvalidArgument);
    }
    buf[offset..offset + src.len()].copy_from_slice(src);
    Ok(src.len())
}

fn write_u32_dec(buf: &mut [u8], offset: usize, mut v: u32) -> Result<usize> {
    if v == 0 {
        if offset >= buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[offset] = b'0';
        return Ok(1);
    }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    if offset + len > buf.len() {
        return Err(Error::InvalidArgument);
    }
    for i in 0..len {
        buf[offset + i] = tmp[len - 1 - i];
    }
    Ok(len)
}
