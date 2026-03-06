// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OverlayFS nlink fixup for copy-up files.
//!
//! When a lower-layer file is copied up to the upper layer, its hard-link
//! count may diverge from the value stored in the upper inode. The overlay
//! layer must track the delta between the "real" upper nlink and the nlink
//! value that should be visible to userspace.
//!
//! This module stores the nlink delta as an xattr on the upper inode
//! (`trusted.overlay.nlink`) and exposes corrected `nlink` values through
//! [`ovl_get_nlink`] and [`ovl_set_nlink`].
//!
//! # Design
//!
//! - [`NlinkEntry`] — per-inode nlink fixup record
//! - [`NlinkTable`] — table of fixup entries
//! - `ovl_set_nlink` — record a new displayed nlink
//! - `ovl_get_nlink` — return corrected nlink
//!
//! # References
//!
//! - Linux `fs/overlayfs/inode.c` (`ovl_set_nlink_upper`, `ovl_get_nlink`)
//! - Linux `fs/overlayfs/copy_up.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of inodes tracked in the nlink fixup table.
const MAX_NLINK_ENTRIES: usize = 256;

/// xattr name used to persist the nlink delta on the upper inode.
pub const OVL_NLINK_XATTR: &str = "trusted.overlay.nlink";

// ---------------------------------------------------------------------------
// NlinkEntry
// ---------------------------------------------------------------------------

/// nlink fixup record for one overlayfs inode.
#[derive(Clone, Copy, Debug)]
pub struct NlinkEntry {
    /// Inode number in the upper layer (0 = free slot).
    pub upper_ino: u64,
    /// The nlink value stored in the upper inode (real kernel value).
    pub upper_nlink: u32,
    /// The nlink value the lower layer had at copy-up time.
    pub lower_nlink: u32,
    /// Signed delta applied to the upper nlink to produce the displayed value.
    /// `displayed = upper_nlink + delta`
    pub delta: i32,
    /// Whether this entry has a persistent xattr backing.
    pub xattr_written: bool,
}

impl NlinkEntry {
    const fn empty() -> Self {
        Self {
            upper_ino: 0,
            upper_nlink: 0,
            lower_nlink: 0,
            delta: 0,
            xattr_written: false,
        }
    }

    /// Compute the nlink value that should be presented to userspace.
    ///
    /// The displayed nlink is clamped at 1 to avoid presenting 0 for an
    /// existing file.
    pub fn displayed_nlink(&self) -> u32 {
        let raw = self.upper_nlink as i64 + self.delta as i64;
        raw.max(1) as u32
    }
}

// ---------------------------------------------------------------------------
// NlinkTable
// ---------------------------------------------------------------------------

/// Table of per-inode nlink fixup entries for an overlayfs mount.
pub struct NlinkTable {
    entries: [NlinkEntry; MAX_NLINK_ENTRIES],
    count: usize,
}

impl NlinkTable {
    /// Create an empty nlink fixup table.
    pub const fn new() -> Self {
        Self {
            entries: [const { NlinkEntry::empty() }; MAX_NLINK_ENTRIES],
            count: 0,
        }
    }

    /// Record a new displayed nlink for an upper inode.
    ///
    /// If `upper_ino` already has an entry, it is updated.
    /// The delta is computed as `displayed_nlink − upper_nlink`.
    ///
    /// Returns `Err(OutOfMemory)` if the table is full.
    pub fn ovl_set_nlink(
        &mut self,
        upper_ino: u64,
        upper_nlink: u32,
        lower_nlink: u32,
        displayed_nlink: u32,
    ) -> Result<()> {
        if upper_ino == 0 {
            return Err(Error::InvalidArgument);
        }
        let delta = displayed_nlink as i64 - upper_nlink as i64;
        if delta > i32::MAX as i64 || delta < i32::MIN as i64 {
            return Err(Error::InvalidArgument);
        }
        let delta = delta as i32;

        // Update existing entry.
        if let Some(e) = self.entries[..self.count]
            .iter_mut()
            .find(|e| e.upper_ino == upper_ino)
        {
            e.upper_nlink = upper_nlink;
            e.lower_nlink = lower_nlink;
            e.delta = delta;
            e.xattr_written = false; // Needs re-sync to xattr.
            return Ok(());
        }

        // Allocate new slot.
        if self.count >= MAX_NLINK_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = NlinkEntry {
            upper_ino,
            upper_nlink,
            lower_nlink,
            delta,
            xattr_written: false,
        };
        self.count += 1;
        Ok(())
    }

    /// Return the displayed nlink for `upper_ino`.
    ///
    /// If no fixup entry exists, the `fallback_nlink` (from the inode itself)
    /// is returned unchanged.
    pub fn ovl_get_nlink(&self, upper_ino: u64, fallback_nlink: u32) -> u32 {
        if let Some(e) = self.entries[..self.count]
            .iter()
            .find(|e| e.upper_ino == upper_ino)
        {
            e.displayed_nlink()
        } else {
            fallback_nlink
        }
    }

    /// Mark the xattr as written for `upper_ino`.
    ///
    /// Called after `trusted.overlay.nlink` has been persisted on the upper
    /// layer inode.
    pub fn mark_xattr_written(&mut self, upper_ino: u64) -> Result<()> {
        self.entries[..self.count]
            .iter_mut()
            .find(|e| e.upper_ino == upper_ino)
            .map(|e| {
                e.xattr_written = true;
            })
            .ok_or(Error::NotFound)
    }

    /// Encode the nlink delta into an xattr value (little-endian i32).
    ///
    /// Returns `Err(NotFound)` if `upper_ino` has no fixup entry.
    pub fn encode_xattr(&self, upper_ino: u64, buf: &mut [u8; 4]) -> Result<()> {
        let entry = self.entries[..self.count]
            .iter()
            .find(|e| e.upper_ino == upper_ino)
            .ok_or(Error::NotFound)?;
        let delta_bytes = entry.delta.to_le_bytes();
        buf.copy_from_slice(&delta_bytes);
        Ok(())
    }

    /// Decode an xattr value and populate a fixup entry.
    ///
    /// `buf` must be exactly 4 bytes (little-endian i32 delta).
    /// If an entry for `upper_ino` already exists it is updated.
    pub fn decode_xattr(
        &mut self,
        upper_ino: u64,
        upper_nlink: u32,
        lower_nlink: u32,
        buf: &[u8; 4],
    ) -> Result<()> {
        let delta = i32::from_le_bytes(*buf);
        let displayed = (upper_nlink as i64 + delta as i64).max(1) as u32;
        self.ovl_set_nlink(upper_ino, upper_nlink, lower_nlink, displayed)?;
        // Mark as already written since we just loaded it from xattr storage.
        self.mark_xattr_written(upper_ino)
    }

    /// Remove the fixup entry for `upper_ino`.
    ///
    /// Called when the file is unlinked from the upper layer.
    pub fn remove(&mut self, upper_ino: u64) -> Result<()> {
        let idx = self.entries[..self.count]
            .iter()
            .position(|e| e.upper_ino == upper_ino)
            .ok_or(Error::NotFound)?;
        self.entries[idx] = self.entries[self.count - 1];
        self.entries[self.count - 1] = NlinkEntry::empty();
        self.count -= 1;
        Ok(())
    }

    /// Iterate over all entries whose xattr has not yet been persisted,
    /// calling `sync_fn(upper_ino, delta_buf)` for each.
    ///
    /// After `sync_fn` returns `Ok(())`, the entry is marked as written.
    pub fn sync_dirty<F>(&mut self, mut sync_fn: F) -> Result<()>
    where
        F: FnMut(u64, &[u8; 4]) -> Result<()>,
    {
        for i in 0..self.count {
            if !self.entries[i].xattr_written {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&self.entries[i].delta.to_le_bytes());
                sync_fn(self.entries[i].upper_ino, &buf)?;
                self.entries[i].xattr_written = true;
            }
        }
        Ok(())
    }

    /// Return the number of active fixup entries.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Adjust nlink on hard-link operations
// ---------------------------------------------------------------------------

/// Update displayed nlink in response to a `link` (hard-link) operation.
///
/// Increments the delta by 1, since the upper inode gains one more link but
/// the overlay must also account for the lower-layer view.
pub fn ovl_inc_nlink(table: &mut NlinkTable, upper_ino: u64, upper_nlink: u32) -> Result<()> {
    if let Some(e) = table.entries[..table.count]
        .iter_mut()
        .find(|e| e.upper_ino == upper_ino)
    {
        e.delta += 1;
        e.upper_nlink = upper_nlink;
        e.xattr_written = false;
        return Ok(());
    }
    // No entry yet — create one with delta = +1.
    table.ovl_set_nlink(upper_ino, upper_nlink, upper_nlink, upper_nlink + 1)
}

/// Update displayed nlink in response to an `unlink` operation.
///
/// Decrements the delta by 1, clamped so the displayed nlink never goes
/// below 1.
pub fn ovl_dec_nlink(table: &mut NlinkTable, upper_ino: u64, upper_nlink: u32) -> Result<()> {
    if let Some(e) = table.entries[..table.count]
        .iter_mut()
        .find(|e| e.upper_ino == upper_ino)
    {
        e.delta -= 1;
        e.upper_nlink = upper_nlink;
        e.xattr_written = false;
        return Ok(());
    }
    // No entry yet — create one with delta = -1 (displayed = nlink - 1).
    let displayed = upper_nlink.saturating_sub(1).max(1);
    table.ovl_set_nlink(upper_ino, upper_nlink, upper_nlink, displayed)
}
