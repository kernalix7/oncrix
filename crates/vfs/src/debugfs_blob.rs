// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! debugfs blob attribute.
//!
//! Implements a binary blob (read-only) file in the debugfs virtual filesystem.
//! Blob files expose a raw byte buffer to userspace reads; they do not support
//! writing.
//!
//! # Components
//!
//! - [`BlobAttribute`] — holds a data buffer and size
//! - `debugfs_create_blob` — register a blob under a debugfs directory
//! - `debugfs_remove_blob` — unregister and release a blob entry
//! - Blob read: returns raw bytes at the requested offset
//!
//! # Reference
//!
//! Linux `fs/debugfs/file.c` (debugfs_create_blob), `include/linux/debugfs.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum blob data size (1 MiB).
const MAX_BLOB_SIZE: usize = 1048576;

/// Maximum number of blob entries in debugfs.
const MAX_BLOB_ENTRIES: usize = 64;

/// Maximum entry path length.
const MAX_PATH_LEN: usize = 128;

/// Maximum entry name length.
const MAX_NAME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Blob attribute
// ---------------------------------------------------------------------------

/// A read-only binary blob attribute file.
pub struct BlobAttribute {
    /// Entry name (filename in debugfs).
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Parent directory path.
    pub parent_path: [u8; MAX_PATH_LEN],
    /// Valid bytes in `parent_path`.
    pub parent_len: usize,
    /// Blob data.
    data: [u8; MAX_BLOB_SIZE],
    /// Valid bytes in `data`.
    pub size: usize,
    /// File permission mode (usually 0o400).
    pub mode: u16,
    /// Whether this blob is active.
    pub active: bool,
    /// Access count (read operations).
    pub read_count: u64,
}

impl BlobAttribute {
    /// Creates a new blob attribute.
    pub fn new(name: &[u8], parent: &[u8], data: &[u8], mode: u16) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if parent.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_BLOB_SIZE {
            return Err(Error::OutOfMemory);
        }

        let mut n_buf = [0u8; MAX_NAME_LEN];
        n_buf[..name.len()].copy_from_slice(name);
        let mut p_buf = [0u8; MAX_PATH_LEN];
        if !parent.is_empty() {
            p_buf[..parent.len()].copy_from_slice(parent);
        }
        let mut d_buf = [0u8; MAX_BLOB_SIZE];
        d_buf[..data.len()].copy_from_slice(data);

        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            parent_path: p_buf,
            parent_len: parent.len(),
            data: d_buf,
            size: data.len(),
            mode,
            active: true,
            read_count: 0,
        })
    }

    /// Returns the entry name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the parent path as bytes.
    pub fn parent_bytes(&self) -> &[u8] {
        &self.parent_path[..self.parent_len]
    }

    /// Returns the blob data.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }

    /// Reads blob data at the given offset into `out`.
    ///
    /// Returns the number of bytes read. Returns 0 at EOF.
    pub fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if self.mode & 0o444 == 0 {
            return Err(Error::PermissionDenied);
        }
        if offset >= self.size {
            return Ok(0);
        }
        let available = self.size - offset;
        let to_read = out.len().min(available);
        out[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        self.read_count += 1;
        Ok(to_read)
    }

    /// Updates the blob data in place.
    ///
    /// Blobs are technically read-only from userspace, but the kernel
    /// can update the data.
    pub fn update_data(&mut self, new_data: &[u8]) -> Result<()> {
        if new_data.len() > MAX_BLOB_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[..new_data.len()].copy_from_slice(new_data);
        if new_data.len() < self.size {
            // Zero out old data beyond new size.
            self.data[new_data.len()..self.size].fill(0);
        }
        self.size = new_data.len();
        Ok(())
    }

    /// Returns the full path ("<parent>/<name>").
    pub fn full_path(&self, out: &mut [u8]) -> usize {
        let plen = self.parent_len;
        let nlen = self.name_len;
        let needed = plen + 1 + nlen;
        if out.len() < needed {
            return 0;
        }
        if plen > 0 {
            out[..plen].copy_from_slice(&self.parent_path[..plen]);
            out[plen] = b'/';
            out[plen + 1..plen + 1 + nlen].copy_from_slice(&self.name[..nlen]);
        } else {
            out[..nlen].copy_from_slice(&self.name[..nlen]);
        }
        needed
    }
}

// ---------------------------------------------------------------------------
// debugfs blob registry
// ---------------------------------------------------------------------------

/// Registry of all debugfs blob files.
pub struct DebugfsBlobRegistry {
    /// Blob entries.
    entries: [Option<BlobAttribute>; MAX_BLOB_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl DebugfsBlobRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Returns the number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds an entry by name.
    pub fn find(&self, name: &[u8]) -> Option<&BlobAttribute> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.name_bytes() == name && e.active)
    }

    /// Finds a mutable entry by name.
    pub fn find_mut(&mut self, name: &[u8]) -> Option<&mut BlobAttribute> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.name_bytes() == name && e.active)
    }
}

impl Default for DebugfsBlobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Creates a new blob file in debugfs.
///
/// Registers the blob under `parent_dir/name` with the given data and mode.
/// Blobs are read-only from userspace; mode is typically 0o400.
pub fn debugfs_create_blob(
    registry: &mut DebugfsBlobRegistry,
    name: &[u8],
    parent_dir: &[u8],
    data: &[u8],
    mode: u16,
) -> Result<()> {
    if registry.count >= MAX_BLOB_ENTRIES {
        return Err(Error::OutOfMemory);
    }
    // Check for duplicate.
    if registry.find(name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let blob = BlobAttribute::new(name, parent_dir, data, mode)?;
    for slot in &mut registry.entries {
        if slot.is_none() {
            *slot = Some(blob);
            registry.count += 1;
            return Ok(());
        }
    }
    Err(Error::OutOfMemory)
}

/// Removes a blob file from debugfs.
pub fn debugfs_remove_blob(registry: &mut DebugfsBlobRegistry, name: &[u8]) -> Result<()> {
    for slot in &mut registry.entries {
        if slot.as_ref().map(|e| e.name_bytes() == name && e.active) == Some(true) {
            if let Some(entry) = slot.as_mut() {
                entry.active = false;
            }
            *slot = None;
            registry.count = registry.count.saturating_sub(1);
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

/// Reads data from a blob file.
pub fn blob_read(
    registry: &mut DebugfsBlobRegistry,
    name: &[u8],
    offset: usize,
    out: &mut [u8],
) -> Result<usize> {
    let blob = registry.find_mut(name).ok_or(Error::NotFound)?;
    blob.read(offset, out)
}

/// Returns the size of a blob.
pub fn blob_size(registry: &DebugfsBlobRegistry, name: &[u8]) -> Result<usize> {
    Ok(registry.find(name).ok_or(Error::NotFound)?.size)
}

/// Updates the data of an existing blob (kernel-side update).
pub fn blob_update(registry: &mut DebugfsBlobRegistry, name: &[u8], new_data: &[u8]) -> Result<()> {
    let blob = registry.find_mut(name).ok_or(Error::NotFound)?;
    blob.update_data(new_data)
}
