// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Debug pseudo-filesystem (debugfs).
//!
//! Provides a simple hierarchical filesystem for exposing kernel debug
//! information and tunable parameters. Unlike sysfs which exposes the
//! device model, debugfs is an unstructured namespace where any kernel
//! subsystem can create directories and files for debugging purposes.
//!
//! # Design
//!
//! - Up to [`MAX_DEBUGFS_ENTRIES`] nodes (directories + files) total.
//! - Nodes are identified by a stable [`DebugfsHandle`] (index into the table).
//! - File nodes carry read and optional write callbacks.
//! - Helper constructors create common typed files (u32, bool, blob).
//!
//! # Example layout
//!
//! ```text
//! /sys/kernel/debug/
//! ├── drm/
//! │   ├── device0/
//! │   │   ├── crtc_count   (u32 read-only)
//! │   │   └── enabled      (bool read-write)
//! └── mm/
//!     └── free_pages       (u32 read-only)
//! ```
//!
//! Reference: Linux `fs/debugfs/`, `include/linux/debugfs.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum total number of debugfs nodes.
const MAX_DEBUGFS_ENTRIES: usize = 128;

/// Maximum byte length of a node name.
const MAX_NAME_LEN: usize = 48;

/// Root node handle — the `/sys/kernel/debug/` directory.
pub const DEBUGFS_ROOT: DebugfsHandle = DebugfsHandle(0);

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// Read callback for a debugfs file.
///
/// Writes content into `buf` and returns the number of bytes written.
/// Must not panic.
pub type DebugfsReadFn = fn(&mut [u8]) -> usize;

/// Write callback for a writable debugfs file.
///
/// Processes `data` written by userspace. Returns `Ok(())` on success.
pub type DebugfsWriteFn = fn(&[u8]) -> Result<()>;

// ---------------------------------------------------------------------------
// DebugfsHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a debugfs node (index into the entry table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugfsHandle(pub usize);

impl DebugfsHandle {
    /// Returns `true` if this handle refers to the sentinel "not found" value.
    pub fn is_valid(self) -> bool {
        self.0 < MAX_DEBUGFS_ENTRIES
    }
}

// ---------------------------------------------------------------------------
// DebugfsEntry (node kind)
// ---------------------------------------------------------------------------

/// Describes what data a debugfs file contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugfsEntryKind {
    /// A directory — has children, no data.
    Dir,
    /// Generic file with user-supplied read/write callbacks.
    File,
    /// Typed u32 value backed by a static reference.
    U32,
    /// Typed bool value backed by a static reference.
    Bool,
    /// Fixed-size binary blob.
    Blob,
}

/// A single debugfs node (directory or file).
#[derive(Debug, Clone, Copy)]
pub struct DebugfsEntry {
    /// Node kind.
    pub kind: DebugfsEntryKind,
    /// Node name (null-padded ASCII).
    name: [u8; MAX_NAME_LEN],
    /// Byte length of the name.
    name_len: usize,
    /// Handle of the parent directory (`DEBUGFS_ROOT` for top-level nodes,
    /// `DebugfsHandle(usize::MAX)` for the root itself).
    pub parent: DebugfsHandle,
    /// Read callback (used by `File` nodes; `None` for directories).
    pub read_fn: Option<DebugfsReadFn>,
    /// Write callback (`None` for read-only nodes and directories).
    pub write_fn: Option<DebugfsWriteFn>,
    /// File mode flags: `0o444` read-only, `0o644` read-write.
    pub mode: u16,
}

impl DebugfsEntry {
    /// Return the node name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Attempt to return the name as a UTF-8 string slice.
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(self.name_bytes()).ok()
    }
}

// ---------------------------------------------------------------------------
// DebugfsNode — includes self-handle for convenience
// ---------------------------------------------------------------------------

/// A debugfs node together with its own handle.
#[derive(Debug, Clone, Copy)]
pub struct DebugfsNode {
    /// Position of this node in the entry table.
    pub handle: DebugfsHandle,
    /// The entry data.
    pub entry: DebugfsEntry,
}

// ---------------------------------------------------------------------------
// DebugfsRegistry
// ---------------------------------------------------------------------------

/// The debugfs node registry.
///
/// Manages up to [`MAX_DEBUGFS_ENTRIES`] nodes in a flat table. Slot 0 is
/// always the root directory (`/sys/kernel/debug/`).
pub struct DebugfsRegistry {
    /// All entries; index 0 is always the root directory.
    entries: [Option<DebugfsEntry>; MAX_DEBUGFS_ENTRIES],
    /// Total number of populated entries (including root).
    count: usize,
}

impl DebugfsRegistry {
    /// Create an empty registry and pre-populate the root directory.
    pub fn new() -> Self {
        let mut reg = Self {
            entries: [const { None }; MAX_DEBUGFS_ENTRIES],
            count: 0,
        };
        // Slot 0: root directory
        let mut root_name = [0u8; MAX_NAME_LEN];
        root_name[0] = b'/';
        reg.entries[0] = Some(DebugfsEntry {
            kind: DebugfsEntryKind::Dir,
            name: root_name,
            name_len: 1,
            parent: DebugfsHandle(usize::MAX), // sentinel: no parent
            read_fn: None,
            write_fn: None,
            mode: 0o555,
        });
        reg.count = 1;
        reg
    }

    // --- Internal slot allocation ---

    fn alloc_slot(&mut self) -> Result<usize> {
        // Find first free slot (including beyond count up to MAX)
        for (i, slot) in self.entries.iter().enumerate() {
            if slot.is_none() && i >= self.count {
                // extend count to cover this slot
                self.count = i + 1;
                return Ok(i);
            }
        }
        // Find a freed slot within existing range
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        if self.count < MAX_DEBUGFS_ENTRIES {
            let idx = self.count;
            self.count += 1;
            Ok(idx)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    fn make_entry(
        kind: DebugfsEntryKind,
        name: &[u8],
        parent: DebugfsHandle,
        read_fn: Option<DebugfsReadFn>,
        write_fn: Option<DebugfsWriteFn>,
        mode: u16,
    ) -> Result<DebugfsEntry> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);
        Ok(DebugfsEntry {
            kind,
            name: name_buf,
            name_len: name.len(),
            parent,
            read_fn,
            write_fn,
            mode,
        })
    }

    // --- Public creation API ---

    /// Create a directory under `parent`.
    ///
    /// Returns a handle that can be used as `parent` for child nodes.
    pub fn create_dir(&mut self, name: &[u8], parent: DebugfsHandle) -> Result<DebugfsHandle> {
        if !parent.is_valid() && parent != DebugfsHandle(usize::MAX) {
            return Err(Error::InvalidArgument);
        }
        let entry = Self::make_entry(DebugfsEntryKind::Dir, name, parent, None, None, 0o555)?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    /// Create a generic file under `parent` with the given callbacks.
    pub fn create_file(
        &mut self,
        name: &[u8],
        parent: DebugfsHandle,
        mode: u16,
        read_fn: DebugfsReadFn,
        write_fn: Option<DebugfsWriteFn>,
    ) -> Result<DebugfsHandle> {
        let entry = Self::make_entry(
            DebugfsEntryKind::File,
            name,
            parent,
            Some(read_fn),
            write_fn,
            mode,
        )?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    /// Create a read-only u32 file.
    ///
    /// The `read_fn` callback should write the decimal representation of
    /// the value into the provided buffer.
    pub fn create_u32(
        &mut self,
        name: &[u8],
        parent: DebugfsHandle,
        read_fn: DebugfsReadFn,
    ) -> Result<DebugfsHandle> {
        let entry = Self::make_entry(
            DebugfsEntryKind::U32,
            name,
            parent,
            Some(read_fn),
            None,
            0o444,
        )?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    /// Create a read-write u32 file.
    pub fn create_u32_rw(
        &mut self,
        name: &[u8],
        parent: DebugfsHandle,
        read_fn: DebugfsReadFn,
        write_fn: DebugfsWriteFn,
    ) -> Result<DebugfsHandle> {
        let entry = Self::make_entry(
            DebugfsEntryKind::U32,
            name,
            parent,
            Some(read_fn),
            Some(write_fn),
            0o644,
        )?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    /// Create a read-only bool file (`Y\n` / `N\n`).
    pub fn create_bool(
        &mut self,
        name: &[u8],
        parent: DebugfsHandle,
        read_fn: DebugfsReadFn,
    ) -> Result<DebugfsHandle> {
        let entry = Self::make_entry(
            DebugfsEntryKind::Bool,
            name,
            parent,
            Some(read_fn),
            None,
            0o444,
        )?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    /// Create a read-write bool file.
    pub fn create_bool_rw(
        &mut self,
        name: &[u8],
        parent: DebugfsHandle,
        read_fn: DebugfsReadFn,
        write_fn: DebugfsWriteFn,
    ) -> Result<DebugfsHandle> {
        let entry = Self::make_entry(
            DebugfsEntryKind::Bool,
            name,
            parent,
            Some(read_fn),
            Some(write_fn),
            0o644,
        )?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    /// Create a read-only binary blob file.
    ///
    /// The `read_fn` callback copies blob bytes into `buf` and returns
    /// the number of bytes written.
    pub fn create_blob(
        &mut self,
        name: &[u8],
        parent: DebugfsHandle,
        read_fn: DebugfsReadFn,
    ) -> Result<DebugfsHandle> {
        let entry = Self::make_entry(
            DebugfsEntryKind::Blob,
            name,
            parent,
            Some(read_fn),
            None,
            0o444,
        )?;
        let idx = self.alloc_slot()?;
        self.entries[idx] = Some(entry);
        Ok(DebugfsHandle(idx))
    }

    // --- Lookup / removal ---

    /// Look up a node by handle.
    pub fn get(&self, handle: DebugfsHandle) -> Option<DebugfsNode> {
        if handle.0 >= MAX_DEBUGFS_ENTRIES {
            return None;
        }
        self.entries[handle.0].map(|entry| DebugfsNode { handle, entry })
    }

    /// Remove a node (and optionally its children) by handle.
    ///
    /// This only removes the node itself; callers responsible for cleaning
    /// up children first to avoid orphaned entries.
    pub fn remove(&mut self, handle: DebugfsHandle) -> Result<()> {
        if handle == DEBUGFS_ROOT {
            return Err(Error::InvalidArgument); // cannot remove root
        }
        if handle.0 >= self.count {
            return Err(Error::InvalidArgument);
        }
        if self.entries[handle.0].is_none() {
            return Err(Error::InvalidArgument);
        }
        self.entries[handle.0] = None;
        Ok(())
    }

    /// Remove a subtree rooted at `dir` — removes all descendants then the
    /// directory itself.
    pub fn remove_recursive(&mut self, dir: DebugfsHandle) -> Result<()> {
        // Collect child handles first (no alloc: iterate up to count).
        let mut children = [DebugfsHandle(MAX_DEBUGFS_ENTRIES); MAX_DEBUGFS_ENTRIES];
        let mut child_count = 0usize;
        for i in 0..self.count {
            if let Some(ref e) = self.entries[i] {
                if e.parent == dir {
                    children[child_count] = DebugfsHandle(i);
                    child_count += 1;
                }
            }
        }
        for ch in &children[..child_count] {
            if let Some(ref e) = self.entries[ch.0] {
                if e.kind == DebugfsEntryKind::Dir {
                    self.remove_recursive(*ch)?;
                } else {
                    self.entries[ch.0] = None;
                }
            }
        }
        self.remove(dir)
    }

    /// Iterate over direct children of `parent`.
    pub fn children(&self, parent: DebugfsHandle) -> impl Iterator<Item = DebugfsNode> + '_ {
        self.entries[..self.count]
            .iter()
            .enumerate()
            .filter_map(move |(i, slot)| {
                slot.as_ref().and_then(|e| {
                    if e.parent == parent {
                        Some(DebugfsNode {
                            handle: DebugfsHandle(i),
                            entry: *e,
                        })
                    } else {
                        None
                    }
                })
            })
    }

    /// Find a child by name under `parent`.
    pub fn find_child(&self, parent: DebugfsHandle, name: &[u8]) -> Option<DebugfsNode> {
        self.children(parent).find(|n| n.entry.name_bytes() == name)
    }

    /// Invoke the read callback of a file node, writing into `buf`.
    ///
    /// Returns `Err(Error::InvalidArgument)` for directory nodes or missing
    /// handles.
    pub fn read_file(&self, handle: DebugfsHandle, buf: &mut [u8]) -> Result<usize> {
        let node = self.get(handle).ok_or(Error::InvalidArgument)?;
        if node.entry.kind == DebugfsEntryKind::Dir {
            return Err(Error::InvalidArgument);
        }
        let read_fn = node.entry.read_fn.ok_or(Error::InvalidArgument)?;
        Ok(read_fn(buf))
    }

    /// Invoke the write callback of a file node with `data`.
    ///
    /// Returns `Err(Error::InvalidArgument)` for read-only or directory nodes.
    pub fn write_file(&self, handle: DebugfsHandle, data: &[u8]) -> Result<()> {
        let node = self.get(handle).ok_or(Error::InvalidArgument)?;
        if node.entry.kind == DebugfsEntryKind::Dir {
            return Err(Error::InvalidArgument);
        }
        let write_fn = node.entry.write_fn.ok_or(Error::InvalidArgument)?;
        write_fn(data)
    }

    /// Total number of allocated entries (including freed slots within the
    /// high-water mark).
    pub fn capacity_used(&self) -> usize {
        self.count
    }

    /// Number of live (non-None) entries.
    pub fn len(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|s| s.is_some())
            .count()
    }

    /// Returns `true` if only the root entry exists.
    pub fn is_empty(&self) -> bool {
        self.len() <= 1
    }
}

impl Default for DebugfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Module-level singleton
// ---------------------------------------------------------------------------

/// Global debugfs registry.
static mut DEBUGFS: Option<DebugfsRegistry> = None;

/// Initialise the global debugfs registry.
///
/// # Safety
///
/// Must be called once during single-threaded kernel initialisation.
pub unsafe fn debugfs_init() {
    // SAFETY: Single-threaded init path; no concurrent access.
    unsafe {
        (*core::ptr::addr_of_mut!(DEBUGFS)) = Some(DebugfsRegistry::new());
    }
}

/// Obtain a reference to the global debugfs registry.
///
/// Returns `None` if [`debugfs_init`] has not been called.
pub fn debugfs_get() -> Option<&'static DebugfsRegistry> {
    // SAFETY: Read-only after init; registry is never moved.
    unsafe { (*core::ptr::addr_of!(DEBUGFS)).as_ref() }
}

/// Obtain a mutable reference to the global debugfs registry.
///
/// # Safety
///
/// The caller must ensure no other reference to the registry is live.
pub unsafe fn debugfs_get_mut() -> Option<&'static mut DebugfsRegistry> {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { (*core::ptr::addr_of_mut!(DEBUGFS)).as_mut() }
}

// ---------------------------------------------------------------------------
// Convenience helpers for common typed reads
// ---------------------------------------------------------------------------

/// Write a u32 value as a decimal ASCII string into `buf`.
///
/// Returns the number of bytes written.
pub fn fmt_u32(buf: &mut [u8], value: u32) -> usize {
    // Hand-rolled decimal formatter (no_std).
    let mut tmp = [0u8; 10];
    let mut pos = tmp.len();
    let mut v = value;
    if v == 0 {
        if buf.is_empty() {
            return 0;
        }
        buf[0] = b'0';
        if buf.len() > 1 {
            buf[1] = b'\n';
            return 2;
        }
        return 1;
    }
    while v > 0 {
        pos -= 1;
        tmp[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let digits = &tmp[pos..];
    let need = digits.len() + 1; // +1 for '\n'
    let write_len = need.min(buf.len());
    let copy_digits = (write_len).min(digits.len());
    buf[..copy_digits].copy_from_slice(&digits[..copy_digits]);
    if write_len > digits.len() {
        buf[digits.len()] = b'\n';
    }
    write_len
}

/// Write a bool value as `"Y\n"` or `"N\n"` into `buf`.
pub fn fmt_bool(buf: &mut [u8], value: bool) -> usize {
    let s: &[u8] = if value { b"Y\n" } else { b"N\n" };
    let len = s.len().min(buf.len());
    buf[..len].copy_from_slice(&s[..len]);
    len
}

/// Parse a u32 from an ASCII decimal string (with optional trailing newline).
///
/// Returns `Err(Error::InvalidArgument)` if parsing fails.
pub fn parse_u32(data: &[u8]) -> Result<u32> {
    let trimmed = if data.last() == Some(&b'\n') {
        &data[..data.len() - 1]
    } else {
        data
    };
    let mut result: u32 = 0;
    for &b in trimmed {
        if !b.is_ascii_digit() {
            return Err(Error::InvalidArgument);
        }
        result = result.checked_mul(10).ok_or(Error::InvalidArgument)?;
        result = result
            .checked_add((b - b'0') as u32)
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(result)
}

/// Parse a bool from `"Y"`, `"y"`, `"1"`, `"N"`, `"n"`, `"0"` (with optional
/// trailing newline).
///
/// Returns `Err(Error::InvalidArgument)` for unrecognised input.
pub fn parse_bool(data: &[u8]) -> Result<bool> {
    let trimmed = if data.last() == Some(&b'\n') {
        &data[..data.len() - 1]
    } else {
        data
    };
    match trimmed {
        b"Y" | b"y" | b"1" => Ok(true),
        b"N" | b"n" | b"0" => Ok(false),
        _ => Err(Error::InvalidArgument),
    }
}
