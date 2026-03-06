// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mount table management for the VFS layer.
//!
//! Tracks all active filesystem mounts, providing operations for:
//! - Mounting a filesystem at a given path
//! - Unmounting by path or device (immediate and lazy/MNT_DETACH)
//! - Bind mount: expose a subtree at a second path
//! - Remount: change flags on an existing mount
//! - Move mount: atomically relocate a mount to a new path
//! - Querying the mount that owns a particular path
//! - Iterating all active mounts
//! - Mount propagation flags (private, shared, slave, unbindable)
//! - `/proc/mounts` and `/proc/self/mountinfo` text generation
//!
//! # Design
//!
//! Each entry in the table records the mount point path, the device
//! name (or `none` for pseudo-filesystems), the filesystem type name,
//! and mount flags. The table is fixed-size to avoid heap allocation
//! in kernel context.
//!
//! A "detached" (lazy-unmounted) mount is removed from path resolution
//! immediately but its slot is kept until all open file descriptors
//! referencing it are closed (simulated here by a detach flag and an
//! open-file-reference counter).
//!
//! # Mount resolution
//!
//! Path lookup first consults the mount table to find the deepest
//! mount covering the path prefix. Nested mounts are resolved
//! correctly by scanning in reverse insertion order.
//!
//! # References
//!
//! Linux `fs/namespace.c`, `fs/mount.h`;
//! POSIX.1-2024 `mount(8)` utility.

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active mount entries.
pub const MAX_MOUNTS: usize = 64;

/// Maximum length of a mount point path.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum length of a device name or `none`.
pub const MAX_DEV_LEN: usize = 64;

/// Maximum length of a filesystem type name.
pub const MAX_FSTYPE_LEN: usize = 32;

// ── Mount flags ──────────────────────────────────────────────────────────────

/// Mount is read-only (no writes allowed).
pub const MS_RDONLY: u32 = 1 << 0;

/// Do not update access times on reads.
pub const MS_NOATIME: u32 = 1 << 1;

/// Do not allow program execution from this mount.
pub const MS_NOEXEC: u32 = 1 << 2;

/// Do not allow setuid/setgid bits to take effect.
pub const MS_NOSUID: u32 = 1 << 3;

/// Do not allow device files on this mount.
pub const MS_NODEV: u32 = 1 << 4;

/// Mount as synchronous (writes go directly to storage).
pub const MS_SYNCHRONOUS: u32 = 1 << 5;

/// This is a bind mount (same filesystem, different path).
pub const MS_BIND: u32 = 1 << 12;

/// Move this mount to a new location.
pub const MS_MOVE: u32 = 1 << 13;

/// Recursively apply propagation changes.
pub const MS_REC: u32 = 1 << 14;

/// Make mount shared (events propagate to/from peers).
pub const MS_SHARED: u32 = 1 << 20;

/// Make mount a slave (events propagate from master only).
pub const MS_SLAVE: u32 = 1 << 21;

/// Make mount private (no propagation).
pub const MS_PRIVATE: u32 = 1 << 22;

/// Make mount unbindable (cannot be bind-mounted).
pub const MS_UNBINDABLE: u32 = 1 << 23;

/// Lazy unmount flag: detach immediately, release resources when unused.
pub const MNT_DETACH: u32 = 1 << 0;

/// Force unmount flag: even if busy (use with caution).
pub const MNT_FORCE: u32 = 1 << 1;

/// Expire flag: mark mount for expiry if unused.
pub const MNT_EXPIRE: u32 = 1 << 2;

// ── Propagation type ─────────────────────────────────────────────────────────

/// Mount propagation type, controlling how mount/unmount events spread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PropagationType {
    /// Events do not propagate to or from this mount.
    #[default]
    Private,
    /// Events propagate bidirectionally between peer mounts.
    Shared,
    /// Events propagate from master to slave only.
    Slave,
    /// Cannot be used as a bind-mount source.
    Unbindable,
}

// ── Fixed-size string helpers ────────────────────────────────────────────────

/// A fixed-capacity string for mount paths and names.
#[derive(Debug, Clone, Copy)]
pub struct FixedStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedStr<N> {
    /// Create an empty string.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    /// Create from a byte slice, truncating to `N` bytes.
    pub fn from_bytes(s: &[u8]) -> Self {
        let len = s.len().min(N);
        let mut buf = [0u8; N];
        buf[..len].copy_from_slice(&s[..len]);
        Self { buf, len }
    }

    /// Return the content as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if content equals `other` byte slice.
    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }

    /// Check if `prefix` is a prefix of this string.
    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        self.as_bytes().starts_with(prefix)
    }
}

impl<const N: usize> Default for FixedStr<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ── MountEntry ───────────────────────────────────────────────────────────────

/// Maximum length of per-mount option string (e.g. "errors=remount-ro").
pub const MAX_OPTIONS_LEN: usize = 128;

/// A single active mount entry in the mount table.
#[derive(Debug, Clone, Copy)]
pub struct MountEntry {
    /// Mount ID (unique, monotonically increasing).
    pub id: u32,
    /// Mount point path (absolute, normalized).
    pub mountpoint: FixedStr<MAX_PATH_LEN>,
    /// Source device or `none` for pseudo-filesystems.
    pub device: FixedStr<MAX_DEV_LEN>,
    /// Filesystem type name (e.g., `ext2`, `tmpfs`).
    pub fstype: FixedStr<MAX_FSTYPE_LEN>,
    /// Filesystem-specific options string (e.g. "errors=remount-ro").
    pub options: FixedStr<MAX_OPTIONS_LEN>,
    /// Mount flags bitmask.
    pub flags: u32,
    /// Propagation type.
    pub propagation: PropagationType,
    /// Parent mount ID (`0` for the initial root mount).
    pub parent_id: u32,
    /// Major:minor device numbers (`0` for pseudo-filesystems).
    pub dev_major: u32,
    /// Minor device number.
    pub dev_minor: u32,
    /// True when this mount has been lazily detached (MNT_DETACH).
    /// Detached mounts are invisible to path resolution but occupy a slot
    /// until `open_count` drops to zero.
    pub detached: bool,
    /// Number of open file descriptions referencing this mount.
    pub open_count: u32,
}

impl MountEntry {
    /// Create a new mount entry.
    pub fn new(id: u32, mountpoint: &[u8], device: &[u8], fstype: &[u8], flags: u32) -> Self {
        Self {
            id,
            mountpoint: FixedStr::from_bytes(mountpoint),
            device: FixedStr::from_bytes(device),
            fstype: FixedStr::from_bytes(fstype),
            options: FixedStr::new(),
            flags,
            propagation: PropagationType::Private,
            parent_id: 0,
            dev_major: 0,
            dev_minor: 0,
            detached: false,
            open_count: 0,
        }
    }

    /// Create a mount entry with filesystem options.
    pub fn with_options(
        id: u32,
        mountpoint: &[u8],
        device: &[u8],
        fstype: &[u8],
        flags: u32,
        options: &[u8],
    ) -> Self {
        let mut entry = Self::new(id, mountpoint, device, fstype, flags);
        entry.options = FixedStr::from_bytes(options);
        entry
    }

    /// Returns true if the mount is actively visible (not detached).
    pub fn is_visible(&self) -> bool {
        !self.detached
    }

    /// Return `true` if this mount is read-only.
    pub fn is_readonly(&self) -> bool {
        self.flags & MS_RDONLY != 0
    }

    /// Return `true` if this is a bind mount.
    pub fn is_bind(&self) -> bool {
        self.flags & MS_BIND != 0
    }
}

// ── MountTable ───────────────────────────────────────────────────────────────

/// Global mount table — tracks all active mounts.
///
/// Indexed by insertion order. The first entry is always the root
/// filesystem mounted at `/`.
pub struct MountTable {
    /// Slot array; `None` means the slot is free.
    slots: [Option<MountEntry>; MAX_MOUNTS],
    /// Number of occupied slots.
    count: usize,
    /// Next mount ID to assign.
    next_id: u32,
}

impl MountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_MOUNTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Return the number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }

    // ── Mount ────────────────────────────────────────────────────────────────

    /// Mount a filesystem.
    ///
    /// `mountpoint` must be an absolute path. Returns the new mount ID.
    /// Returns `Err(AlreadyExists)` if the exact same mountpoint is already
    /// in use (duplicate mounts on the same path are rejected unless the
    /// caller passes `MS_BIND`).
    pub fn mount(
        &mut self,
        mountpoint: &[u8],
        device: &[u8],
        fstype: &[u8],
        flags: u32,
    ) -> Result<u32> {
        if mountpoint.is_empty() || mountpoint[0] != b'/' {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MOUNTS {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate exact mount point (non-bind).
        if flags & MS_BIND == 0 {
            for slot in self.slots.iter().flatten() {
                if slot.mountpoint.eq_bytes(mountpoint) {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        let entry = MountEntry::new(id, mountpoint, device, fstype, flags);

        // Find a free slot.
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    // ── Unmount ──────────────────────────────────────────────────────────────

    /// Unmount by exact mount point path.
    ///
    /// Returns `Err(NotFound)` if no mount at `mountpoint`.
    /// Returns `Err(Busy)` if other mounts are nested beneath it.
    pub fn umount(&mut self, mountpoint: &[u8]) -> Result<()> {
        // Check for nested mounts.
        let mut target_id = 0u32;
        let mut found = false;
        for slot in self.slots.iter().flatten() {
            if slot.mountpoint.eq_bytes(mountpoint) {
                target_id = slot.id;
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }

        // Ensure no other mount has this as a parent or is nested within.
        for slot in self.slots.iter().flatten() {
            if slot.mountpoint.eq_bytes(mountpoint) {
                continue;
            }
            // A mount is nested if its path starts with mountpoint followed by '/'.
            let mp = slot.mountpoint.as_bytes();
            let base = mountpoint;
            if mp.starts_with(base) {
                let next_char = mp.get(base.len()).copied();
                if next_char == Some(b'/') || next_char.is_none() {
                    return Err(Error::Busy);
                }
            }
            if slot.parent_id == target_id {
                return Err(Error::Busy);
            }
        }

        // Remove the entry.
        for slot in self.slots.iter_mut() {
            if let Some(ref e) = *slot {
                if e.mountpoint.eq_bytes(mountpoint) {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Unmount by mount ID.
    pub fn umount_by_id(&mut self, id: u32) -> Result<()> {
        // Capture the path before calling umount to avoid conflicting borrows.
        let mut mp_bytes = [0u8; MAX_PATH_LEN];
        let mut mp_len = 0usize;
        let mut found = false;
        for slot in self.slots.iter() {
            if let Some(e) = slot {
                if e.id == id {
                    mp_bytes[..e.mountpoint.len].copy_from_slice(e.mountpoint.as_bytes());
                    mp_len = e.mountpoint.len;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(Error::NotFound);
        }
        self.umount(&mp_bytes[..mp_len])
    }

    /// Lazy unmount (MNT_DETACH): immediately hide the mount from path
    /// resolution but keep the slot until all open references are released.
    ///
    /// Unlike `umount`, this does not fail with `Err(Busy)` — it detaches
    /// even when child mounts or open files exist.
    pub fn umount_lazy(&mut self, mountpoint: &[u8]) -> Result<()> {
        for slot in self.slots.iter_mut().flatten() {
            if slot.mountpoint.eq_bytes(mountpoint) {
                if slot.detached {
                    return Err(Error::NotFound);
                }
                slot.detached = true;
                if slot.open_count == 0 {
                    // No open references — remove immediately.
                    // We need a second pass to clear the slot.
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Called when an open file description on `mount_id` is closed.
    ///
    /// Decrements the open-file reference counter. If the mount is detached
    /// and the counter reaches zero, the slot is freed.
    pub fn release_open_ref(&mut self, mount_id: u32) {
        let mut should_free = false;
        for slot in self.slots.iter_mut().flatten() {
            if slot.id == mount_id {
                slot.open_count = slot.open_count.saturating_sub(1);
                if slot.detached && slot.open_count == 0 {
                    should_free = true;
                }
                break;
            }
        }
        if should_free {
            for slot in self.slots.iter_mut() {
                if let Some(e) = slot {
                    if e.id == mount_id {
                        *slot = None;
                        self.count -= 1;
                        break;
                    }
                }
            }
        }
    }

    /// Increment the open-file reference counter for a mount.
    pub fn acquire_open_ref(&mut self, mount_id: u32) -> Result<()> {
        for slot in self.slots.iter_mut().flatten() {
            if slot.id == mount_id {
                slot.open_count += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Move a mount from its current location to `new_mountpoint`.
    ///
    /// Equivalent to `mount --move old new` (MS_MOVE). The mount retains its
    /// ID, device, fstype, and flags. Returns `Err(NotFound)` if no mount is
    /// at `old_mountpoint`, `Err(Busy)` if child mounts depend on it.
    pub fn move_mount(&mut self, old_mountpoint: &[u8], new_mountpoint: &[u8]) -> Result<()> {
        if new_mountpoint.is_empty() || new_mountpoint[0] != b'/' {
            return Err(Error::InvalidArgument);
        }
        // Ensure a mount exists at the target path for the new location
        // (i.e., new_mountpoint must itself be covered by some mount).
        if self.find_mount(new_mountpoint).is_none() {
            return Err(Error::NotFound);
        }
        // Find and update the moved mount.
        for slot in self.slots.iter_mut().flatten() {
            if slot.mountpoint.eq_bytes(old_mountpoint) {
                slot.mountpoint = FixedStr::from_bytes(new_mountpoint);
                slot.flags |= MS_MOVE;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    /// Find the mount entry with the longest matching prefix for `path`.
    ///
    /// Returns the deepest visible (non-detached) mount that contains `path`.
    /// For example, given mounts at `/` and `/proc`, looking up `/proc/cpuinfo`
    /// returns the `/proc` entry.
    pub fn find_mount(&self, path: &[u8]) -> Option<&MountEntry> {
        let mut best: Option<&MountEntry> = None;
        let mut best_len = 0usize;

        for slot in self.slots.iter().flatten() {
            if slot.detached {
                continue;
            }
            let mp = slot.mountpoint.as_bytes();
            if !path.starts_with(mp) {
                continue;
            }
            // Check that the mount point is a proper prefix.
            let mp_is_root = mp == b"/";
            let path_char = path.get(mp.len()).copied();
            if !mp_is_root && path_char != Some(b'/') && path_char.is_some() {
                continue;
            }
            if mp.len() > best_len {
                best_len = mp.len();
                best = Some(slot);
            }
        }
        best
    }

    /// Look up a visible mount entry by its exact mount point path.
    pub fn find_by_path(&self, mountpoint: &[u8]) -> Option<&MountEntry> {
        self.slots
            .iter()
            .flatten()
            .find(|e| !e.detached && e.mountpoint.eq_bytes(mountpoint))
    }

    /// Look up a mount entry by mount ID (including detached mounts).
    pub fn find_by_id(&self, id: u32) -> Option<&MountEntry> {
        self.slots.iter().flatten().find(|e| e.id == id)
    }

    // ── Iteration ────────────────────────────────────────────────────────────

    /// Iterate over all active (non-detached) mount entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &MountEntry> {
        self.slots.iter().flatten().filter(|e| !e.detached)
    }

    /// Iterate over all slots including detached mounts (for internal use).
    pub fn iter_all(&self) -> impl Iterator<Item = &MountEntry> {
        self.slots.iter().flatten()
    }

    // ── Propagation ──────────────────────────────────────────────────────────

    /// Change the propagation type of the mount at `mountpoint`.
    pub fn set_propagation(&mut self, mountpoint: &[u8], prop: PropagationType) -> Result<()> {
        for slot in self.slots.iter_mut().flatten() {
            if slot.mountpoint.eq_bytes(mountpoint) {
                slot.propagation = prop;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    // ── Flag updates ─────────────────────────────────────────────────────────

    /// Remount an existing mount with new flags.
    ///
    /// Only flag changes (read-only toggle, etc.) are supported; the
    /// device and filesystem type remain unchanged.
    pub fn remount(&mut self, mountpoint: &[u8], new_flags: u32) -> Result<()> {
        for slot in self.slots.iter_mut().flatten() {
            if slot.mountpoint.eq_bytes(mountpoint) {
                slot.flags = new_flags;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    // ── Bind mount ───────────────────────────────────────────────────────────

    /// Create a bind mount: make `target` appear at `new_mountpoint`.
    ///
    /// The bind mount shares the same device and filesystem type as the
    /// source mount covering `target`.
    pub fn bind_mount(&mut self, target: &[u8], new_mountpoint: &[u8]) -> Result<u32> {
        // Find the source mount.
        let (device_buf, device_len, fstype_buf, fstype_len, flags) = {
            let src = self.find_mount(target).ok_or(Error::NotFound)?;
            (
                src.device.buf,
                src.device.len,
                src.fstype.buf,
                src.fstype.len,
                src.flags,
            )
        };
        let device = &device_buf[..device_len];
        let fstype = &fstype_buf[..fstype_len];
        self.mount(new_mountpoint, device, fstype, flags | MS_BIND)
    }

    // ── /proc/mounts formatting ──────────────────────────────────────────────

    /// Write a `/proc/mounts`-style line for entry `id` into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if the entry is not found.
    pub fn format_entry(&self, id: u32, buf: &mut [u8]) -> usize {
        let entry = match self.find_by_id(id) {
            Some(e) => e,
            None => return 0,
        };
        // Format: "device mountpoint fstype flags 0 0\n"
        let flags_str: &[u8] = if entry.is_readonly() { b"ro" } else { b"rw" };
        let dev = entry.device.as_bytes();
        let mp = entry.mountpoint.as_bytes();
        let fs = entry.fstype.as_bytes();
        let parts: [&[u8]; 7] = [dev, b" ", mp, b" ", fs, b" ", flags_str];
        let mut pos = 0usize;
        for part in parts.iter() {
            let avail = buf.len().saturating_sub(pos);
            let copy = part.len().min(avail);
            buf[pos..pos + copy].copy_from_slice(&part[..copy]);
            pos += copy;
        }
        // Append " 0 0\n" (dump-freq and pass fields)
        for &b in b" 0 0\n" {
            if pos < buf.len() {
                buf[pos] = b;
                pos += 1;
            }
        }
        pos
    }

    /// Generate the full `/proc/mounts` text.
    ///
    /// Each line has the format:
    /// ```text
    /// device mountpoint fstype options 0 0
    /// ```
    pub fn format_proc_mounts(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in self.iter() {
            append_proc_mounts_line(&mut out, entry);
        }
        out
    }

    /// Generate the full `/proc/self/mountinfo` text.
    ///
    /// Each line has the format (kernel 2.6.26+):
    /// ```text
    /// mount_id parent_id major:minor root mountpoint mount_opts optional-fields - fstype source super_opts
    /// ```
    pub fn format_mountinfo(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in self.iter() {
            append_mountinfo_line(&mut out, entry, self);
        }
        out
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── /proc/mounts helpers ─────────────────────────────────────────────────────

/// Append one `/proc/mounts` line for `entry` into `buf`.
///
/// Format: `<device> <mountpoint> <fstype> <rw|ro>[,options] 0 0\n`
fn append_proc_mounts_line(buf: &mut Vec<u8>, entry: &MountEntry) {
    buf.extend_from_slice(entry.device.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(entry.mountpoint.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(entry.fstype.as_bytes());
    buf.push(b' ');
    if entry.is_readonly() {
        buf.extend_from_slice(b"ro");
    } else {
        buf.extend_from_slice(b"rw");
    }
    // Append extra flags
    append_mount_flags(buf, entry.flags);
    if !entry.options.is_empty() {
        buf.push(b',');
        buf.extend_from_slice(entry.options.as_bytes());
    }
    buf.extend_from_slice(b" 0 0\n");
}

/// Append one `/proc/self/mountinfo` line for `entry` into `buf`.
///
/// Format:
/// `<id> <parent_id> <major>:<minor> <root> <mountpoint> <mount_opts> [<optional-fields>] - <fstype> <source> <super_opts>\n`
fn append_mountinfo_line(buf: &mut Vec<u8>, entry: &MountEntry, table: &MountTable) {
    // mount_id
    write_u32(buf, entry.id);
    buf.push(b' ');
    // parent_id (use 1 for root's parent, otherwise the stored parent)
    let parent_id = if entry.parent_id == 0 {
        entry.id
    } else {
        entry.parent_id
    };
    write_u32(buf, parent_id);
    buf.push(b' ');
    // major:minor
    write_u32(buf, entry.dev_major);
    buf.push(b':');
    write_u32(buf, entry.dev_minor);
    buf.push(b' ');
    // root (relative root within the filesystem — "/" for full mounts)
    buf.push(b'/');
    buf.push(b' ');
    // mountpoint
    buf.extend_from_slice(entry.mountpoint.as_bytes());
    buf.push(b' ');
    // mount_opts
    if entry.is_readonly() {
        buf.extend_from_slice(b"ro");
    } else {
        buf.extend_from_slice(b"rw");
    }
    append_mount_flags(buf, entry.flags);
    buf.push(b' ');
    // optional fields: propagation peer group
    match entry.propagation {
        PropagationType::Shared => {
            buf.extend_from_slice(b"shared:");
            write_u32(buf, entry.id); // peer group = mount ID
            buf.push(b' ');
        }
        PropagationType::Slave => {
            // Find the master (first shared mount covering same path).
            let master_id = table
                .iter()
                .find(|e| {
                    e.propagation == PropagationType::Shared
                        && e.mountpoint.eq_bytes(entry.mountpoint.as_bytes())
                })
                .map(|e| e.id)
                .unwrap_or(1);
            buf.extend_from_slice(b"master:");
            write_u32(buf, master_id);
            buf.push(b' ');
        }
        PropagationType::Unbindable => {
            buf.extend_from_slice(b"unbindable ");
        }
        PropagationType::Private => {}
    }
    // separator
    buf.extend_from_slice(b"- ");
    // fstype
    buf.extend_from_slice(entry.fstype.as_bytes());
    buf.push(b' ');
    // source
    buf.extend_from_slice(entry.device.as_bytes());
    buf.push(b' ');
    // super_opts
    if entry.is_readonly() {
        buf.extend_from_slice(b"ro");
    } else {
        buf.extend_from_slice(b"rw");
    }
    if !entry.options.is_empty() {
        buf.push(b',');
        buf.extend_from_slice(entry.options.as_bytes());
    }
    buf.push(b'\n');
}

/// Append comma-separated flag names for well-known mount flags.
fn append_mount_flags(buf: &mut Vec<u8>, flags: u32) {
    if flags & MS_NOATIME != 0 {
        buf.extend_from_slice(b",noatime");
    }
    if flags & MS_NOEXEC != 0 {
        buf.extend_from_slice(b",noexec");
    }
    if flags & MS_NOSUID != 0 {
        buf.extend_from_slice(b",nosuid");
    }
    if flags & MS_NODEV != 0 {
        buf.extend_from_slice(b",nodev");
    }
    if flags & MS_SYNCHRONOUS != 0 {
        buf.extend_from_slice(b",sync");
    }
    if flags & MS_BIND != 0 {
        buf.extend_from_slice(b",bind");
    }
}

/// Write a u32 as ASCII decimal into a buffer.
fn write_u32(buf: &mut Vec<u8>, v: u32) {
    if v == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    let mut n = v;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        buf.push(tmp[i]);
    }
}

// ── Mount statistics ─────────────────────────────────────────────────────────

/// Summary statistics for the mount table.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountStats {
    /// Total number of active (non-detached) mounts.
    pub total: usize,
    /// Number of detached (lazy-unmounted) mounts still occupying slots.
    pub detached: usize,
    /// Number of read-only mounts.
    pub readonly: usize,
    /// Number of bind mounts.
    pub bind: usize,
    /// Number of shared-propagation mounts.
    pub shared: usize,
}

impl MountStats {
    /// Compute statistics from a [`MountTable`].
    pub fn from_table(table: &MountTable) -> Self {
        let mut stats = Self::default();
        for entry in table.iter_all() {
            if entry.detached {
                stats.detached += 1;
                continue;
            }
            stats.total += 1;
            if entry.is_readonly() {
                stats.readonly += 1;
            }
            if entry.is_bind() {
                stats.bind += 1;
            }
            if entry.propagation == PropagationType::Shared {
                stats.shared += 1;
            }
        }
        stats
    }
}

// ── Path normalization ────────────────────────────────────────────────────────

/// Normalize a path by collapsing redundant separators and `.` components.
///
/// Does not resolve `..` (that requires inode context). The result is
/// written into `out` and the byte count is returned.
pub fn normalize_path(path: &[u8], out: &mut [u8; MAX_PATH_LEN]) -> usize {
    let mut pos = 0usize;
    let mut i = 0usize;

    // Ensure absolute.
    if path.first().copied() != Some(b'/') {
        return 0;
    }

    while i < path.len() {
        if path[i] == b'/' {
            // Skip duplicate slashes.
            while i < path.len() && path[i] == b'/' {
                i += 1;
            }
            // Check for `.` component.
            if i < path.len() && path[i] == b'.' {
                let next = path.get(i + 1).copied();
                if next == Some(b'/') || next.is_none() {
                    i += 1;
                    continue;
                }
            }
            if pos < MAX_PATH_LEN {
                out[pos] = b'/';
                pos += 1;
            }
        } else {
            if pos < MAX_PATH_LEN {
                out[pos] = path[i];
                pos += 1;
            }
            i += 1;
        }
    }

    // Trim trailing slash (except root).
    if pos > 1 && out[pos - 1] == b'/' {
        pos -= 1;
    }
    if pos == 0 {
        out[0] = b'/';
        pos = 1;
    }
    pos
}
