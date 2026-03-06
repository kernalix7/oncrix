// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O layer (bio).
//!
//! Implements the `bio` (block I/O) abstraction — the primary mechanism
//! for submitting I/O requests to block devices in the Linux-style VFS.
//!
//! A `Bio` represents a single I/O operation consisting of one or more
//! contiguous segments (`BioVec`). Each `BioVec` describes a page-aligned
//! range of data to be read or written.
//!
//! # Design
//!
//! - `BioVec` — a single data segment (page + offset + length)
//! - `Bio` — a complete I/O request (list of `BioVec` + device address)
//! - `BioQueue` — a per-device submission queue
//!
//! # References
//!
//! - Linux `bio.h`, `blk-core.c`
//! - Linux kernel docs: `Documentation/block/`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of bio vectors per bio.
pub const BIO_MAX_VECS: usize = 16;

/// Maximum number of bios in a device queue.
pub const BIO_QUEUE_DEPTH: usize = 64;

/// Page size (4 KiB).
pub const BIO_PAGE_SIZE: usize = 4096;

// ── BioOp ────────────────────────────────────────────────────────────

/// The operation type for a bio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// Read data from device.
    Read,
    /// Write data to device.
    Write,
    /// Flush device write cache.
    Flush,
    /// Discard sectors (TRIM/UNMAP).
    Discard,
}

// ── BioStatus ────────────────────────────────────────────────────────

/// Completion status of a bio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioStatus {
    /// Operation not yet completed.
    Pending,
    /// Operation completed successfully.
    Ok,
    /// Operation failed with I/O error.
    IoError,
    /// Operation was cancelled.
    Cancelled,
}

// ── BioVec ───────────────────────────────────────────────────────────

/// A single scatter-gather segment for a bio.
#[derive(Debug, Clone, Copy)]
pub struct BioVec {
    /// Physical page frame number.
    pub pfn: u64,
    /// Byte offset within the page.
    pub offset: u32,
    /// Number of bytes in this segment.
    pub len: u32,
}

impl BioVec {
    /// Create a new bio vector.
    pub const fn new(pfn: u64, offset: u32, len: u32) -> Self {
        Self { pfn, offset, len }
    }

    /// Returns `true` if this vector is valid (non-zero length, within page).
    pub fn is_valid(&self) -> bool {
        self.len > 0 && (self.offset as usize + self.len as usize) <= BIO_PAGE_SIZE
    }
}

// ── Bio ──────────────────────────────────────────────────────────────

/// A block I/O request.
pub struct Bio {
    /// Unique bio identifier.
    pub id: u64,
    /// Target block device ID.
    pub dev: u32,
    /// Starting sector on the device (512-byte sectors).
    pub sector: u64,
    /// I/O operation type.
    pub op: BioOp,
    /// Scatter-gather list.
    vecs: [Option<BioVec>; BIO_MAX_VECS],
    /// Number of valid vectors.
    pub vec_count: usize,
    /// Completion status.
    pub status: BioStatus,
    /// Total bytes to transfer (sum of `BioVec::len`).
    pub total_bytes: usize,
}

impl Bio {
    /// Create a new bio for the given device and sector.
    pub const fn new(id: u64, dev: u32, sector: u64, op: BioOp) -> Self {
        Self {
            id,
            dev,
            sector,
            op,
            vecs: [const { None }; BIO_MAX_VECS],
            vec_count: 0,
            status: BioStatus::Pending,
            total_bytes: 0,
        }
    }

    /// Add a scatter-gather segment to this bio.
    pub fn add_vec(&mut self, vec: BioVec) -> Result<()> {
        if !vec.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if self.vec_count >= BIO_MAX_VECS {
            return Err(Error::OutOfMemory);
        }
        self.vecs[self.vec_count] = Some(vec);
        self.vec_count += 1;
        self.total_bytes += vec.len as usize;
        Ok(())
    }

    /// Mark this bio as successfully completed.
    pub fn complete_ok(&mut self) {
        self.status = BioStatus::Ok;
    }

    /// Mark this bio as failed with an I/O error.
    pub fn complete_err(&mut self) {
        self.status = BioStatus::IoError;
    }

    /// Returns `true` if the bio has finished (success or failure).
    pub fn is_done(&self) -> bool {
        matches!(
            self.status,
            BioStatus::Ok | BioStatus::IoError | BioStatus::Cancelled
        )
    }

    /// Iterate over the valid bio vectors.
    pub fn iter_vecs(&self) -> impl Iterator<Item = &BioVec> {
        self.vecs[..self.vec_count]
            .iter()
            .filter_map(|v| v.as_ref())
    }
}

// ── BioQueue ─────────────────────────────────────────────────────────

/// A per-device bio submission queue.
pub struct BioQueue {
    /// Device ID this queue belongs to.
    pub dev: u32,
    queue: [Option<Bio>; BIO_QUEUE_DEPTH],
    head: usize,
    tail: usize,
    count: usize,
    next_id: u64,
}

impl BioQueue {
    /// Create a new bio queue for device `dev`.
    pub const fn new(dev: u32) -> Self {
        Self {
            dev,
            queue: [const { None }; BIO_QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
            next_id: 1,
        }
    }

    /// Allocate and submit a bio to the queue. Returns the bio ID.
    pub fn submit(&mut self, sector: u64, op: BioOp, vec: BioVec) -> Result<u64> {
        if self.count >= BIO_QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut bio = Bio::new(id, self.dev, sector, op);
        bio.add_vec(vec)?;
        self.queue[self.tail] = Some(bio);
        self.tail = (self.tail + 1) % BIO_QUEUE_DEPTH;
        self.count += 1;
        Ok(id)
    }

    /// Dequeue the next pending bio.
    pub fn pop(&mut self) -> Option<Bio> {
        if self.count == 0 {
            return None;
        }
        let bio = self.queue[self.head].take();
        self.head = (self.head + 1) % BIO_QUEUE_DEPTH;
        self.count = self.count.saturating_sub(1);
        bio
    }

    /// Returns the number of queued bios.
    pub fn depth(&self) -> usize {
        self.count
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.count >= BIO_QUEUE_DEPTH
    }
}

// ── BioLayer ─────────────────────────────────────────────────────────

/// Maximum number of block devices registered.
pub const MAX_BIO_DEVICES: usize = 16;

/// Global block I/O layer manager.
pub struct BioLayer {
    queues: [Option<BioQueue>; MAX_BIO_DEVICES],
    count: usize,
}

impl BioLayer {
    /// Create an empty bio layer.
    pub const fn new() -> Self {
        Self {
            queues: [const { None }; MAX_BIO_DEVICES],
            count: 0,
        }
    }

    /// Register a block device and create its bio queue.
    pub fn register_dev(&mut self, dev: u32) -> Result<()> {
        for slot in self.queues.iter() {
            if let Some(q) = slot {
                if q.dev == dev {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.count >= MAX_BIO_DEVICES {
            return Err(Error::OutOfMemory);
        }
        for slot in self.queues.iter_mut() {
            if slot.is_none() {
                *slot = Some(BioQueue::new(dev));
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Submit a bio to the queue for `dev`. Returns the bio ID.
    pub fn submit(&mut self, dev: u32, sector: u64, op: BioOp, vec: BioVec) -> Result<u64> {
        for slot in self.queues.iter_mut() {
            if let Some(q) = slot {
                if q.dev == dev {
                    return q.submit(sector, op, vec);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Pop the next bio from the queue for `dev`.
    pub fn pop(&mut self, dev: u32) -> Option<Bio> {
        for slot in self.queues.iter_mut() {
            if let Some(q) = slot {
                if q.dev == dev {
                    return q.pop();
                }
            }
        }
        None
    }

    /// Returns the queue depth for `dev`.
    pub fn queue_depth(&self, dev: u32) -> usize {
        for slot in self.queues.iter() {
            if let Some(q) = slot {
                if q.dev == dev {
                    return q.depth();
                }
            }
        }
        0
    }
}

impl Default for BioLayer {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
