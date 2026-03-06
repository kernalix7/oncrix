// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs upper layer management.
//!
//! The upper layer of an overlay filesystem is the writeable layer.  All
//! modifications (create, delete, rename, truncate, chmod, …) are applied
//! here.  This module tracks the upper-layer state and provides helpers for
//! copy-up, whiteout creation, and opaque directory marking.

use oncrix_lib::{Error, Result};

/// Maximum number of pending copy-up operations queued.
pub const UPPER_COPY_QUEUE_SIZE: usize = 128;

/// Inode number type used in upper-layer tracking.
pub type UpperIno = u64;

/// Reason a copy-up was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyUpReason {
    /// Write to a file that lives only in the lower layer.
    Write,
    /// chmod/chown/utimes on a lower-layer inode.
    MetaChange,
    /// Rename source that lives in the lower layer.
    Rename,
    /// Hard-link creation requiring the inode to be in the upper layer.
    HardLink,
}

/// Record of a pending or completed copy-up.
#[derive(Debug, Clone)]
pub struct CopyUpRecord {
    /// Lower-layer inode number being copied up.
    pub lower_ino: UpperIno,
    /// Upper-layer inode number assigned after copy.
    pub upper_ino: UpperIno,
    /// Reason the copy-up was initiated.
    pub reason: CopyUpReason,
    /// Whether the copy-up has completed successfully.
    pub done: bool,
}

impl CopyUpRecord {
    /// Create a pending copy-up record.
    pub fn new(lower_ino: UpperIno, upper_ino: UpperIno, reason: CopyUpReason) -> Self {
        Self {
            lower_ino,
            upper_ino,
            reason,
            done: false,
        }
    }
}

/// Fixed-capacity queue of pending copy-up operations.
pub struct CopyUpQueue {
    entries: [Option<CopyUpRecord>; UPPER_COPY_QUEUE_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl CopyUpQueue {
    /// Create an empty copy-up queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; UPPER_COPY_QUEUE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Enqueue a copy-up record. Returns `Err(Busy)` when full.
    pub fn enqueue(&mut self, record: CopyUpRecord) -> Result<()> {
        if self.count >= UPPER_COPY_QUEUE_SIZE {
            return Err(Error::Busy);
        }
        self.entries[self.tail] = Some(record);
        self.tail = (self.tail + 1) % UPPER_COPY_QUEUE_SIZE;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next copy-up record.
    pub fn dequeue(&mut self) -> Option<CopyUpRecord> {
        if self.count == 0 {
            return None;
        }
        let rec = self.entries[self.head].take();
        self.head = (self.head + 1) % UPPER_COPY_QUEUE_SIZE;
        self.count -= 1;
        rec
    }

    /// Number of pending copy-ups.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for CopyUpQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Whiteout entry — marks a lower-layer name as deleted.
#[derive(Debug, Clone)]
pub struct WhiteoutEntry {
    /// Parent directory inode in the upper layer.
    pub dir_ino: UpperIno,
    /// Name being whited out (up to 255 bytes).
    pub name: [u8; 256],
    pub name_len: u8,
}

impl WhiteoutEntry {
    /// Create a whiteout entry from a byte slice.
    pub fn new(dir_ino: UpperIno, name: &[u8]) -> Result<Self> {
        if name.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; 256];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            dir_ino,
            name: buf,
            name_len: name.len() as u8,
        })
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Opaque directory marker: a directory in the upper layer that hides all
/// lower-layer content beneath it.
#[derive(Debug, Clone, Copy)]
pub struct OpaqueDir {
    /// Upper-layer inode number of the opaque directory.
    pub ino: UpperIno,
}

/// Upper-layer context attached to an overlay superblock.
pub struct UpperContext {
    /// Copy-up queue.
    pub copy_up_queue: CopyUpQueue,
    /// Number of copy-ups performed since mount.
    pub total_copy_ups: u64,
    /// Number of whiteouts created since mount.
    pub total_whiteouts: u64,
    /// Number of opaque directories created since mount.
    pub total_opaque_dirs: u64,
    /// Whether the upper layer is currently writable.
    pub writable: bool,
    /// Whether `index` directory is enabled (for hard-link support).
    pub index_enabled: bool,
    /// Whether `metacopy` mode is enabled (metadata-only copy-up).
    pub metacopy_enabled: bool,
}

impl UpperContext {
    /// Create a new upper-layer context.
    pub const fn new() -> Self {
        Self {
            copy_up_queue: CopyUpQueue::new(),
            total_copy_ups: 0,
            total_whiteouts: 0,
            total_opaque_dirs: 0,
            writable: true,
            index_enabled: false,
            metacopy_enabled: false,
        }
    }

    /// Queue a copy-up operation.
    pub fn queue_copy_up(
        &mut self,
        lower_ino: UpperIno,
        upper_ino: UpperIno,
        reason: CopyUpReason,
    ) -> Result<()> {
        let record = CopyUpRecord::new(lower_ino, upper_ino, reason);
        self.copy_up_queue.enqueue(record)
    }

    /// Process the next pending copy-up.
    ///
    /// Returns `Ok(true)` if a copy-up was processed, `Ok(false)` if idle.
    pub fn process_next_copy_up(&mut self) -> Result<bool> {
        if !self.writable {
            return Err(Error::PermissionDenied);
        }
        match self.copy_up_queue.dequeue() {
            None => Ok(false),
            Some(_record) => {
                // In the real kernel this would perform the actual data copy.
                self.total_copy_ups += 1;
                Ok(true)
            }
        }
    }

    /// Record creation of a whiteout in the upper layer.
    pub fn record_whiteout(&mut self) -> Result<()> {
        if !self.writable {
            return Err(Error::PermissionDenied);
        }
        self.total_whiteouts += 1;
        Ok(())
    }

    /// Record creation of an opaque directory.
    pub fn record_opaque_dir(&mut self) -> Result<()> {
        if !self.writable {
            return Err(Error::PermissionDenied);
        }
        self.total_opaque_dirs += 1;
        Ok(())
    }

    /// Make the upper layer read-only (e.g., remount ro).
    pub fn set_readonly(&mut self) {
        self.writable = false;
    }
}

impl Default for UpperContext {
    fn default() -> Self {
        Self::new()
    }
}
