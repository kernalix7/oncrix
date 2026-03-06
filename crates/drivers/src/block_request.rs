// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O request queue.
//!
//! Implements a simple block I/O request queue with per-request
//! descriptors, a FIFO submission queue, and a NOOP/deadline elevator
//! stub.  Drivers (AHCI, NVMe, VirtIO-blk) submit requests here;
//! the elevator reorders them for efficiency before dispatch.
//!
//! # Design
//!
//! - `BioRequest` — a single read/write/flush operation.
//! - `RequestQueue` — FIFO with merge hints and plug/unplug.
//! - `ElevatorPolicy` — request ordering strategy.

extern crate alloc;
use alloc::vec::Vec;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of pending requests in the queue.
const MAX_PENDING: usize = 256;

/// Maximum number of physical pages per request (scatter-gather).
const MAX_PAGES: usize = 32;

// ── BioDirection ─────────────────────────────────────────────────────────────

/// Direction of a block I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioDirection {
    /// Read from the device into memory.
    Read,
    /// Write from memory to the device.
    Write,
    /// Flush the device's write cache.
    Flush,
    /// Discard (TRIM) the specified sectors.
    Discard,
}

// ── BioPage ───────────────────────────────────────────────────────────────────

/// A single page in a scatter-gather list.
#[derive(Debug, Clone, Copy, Default)]
pub struct BioPage {
    /// Physical address of the page.
    pub phys_addr: u64,
    /// Offset within the page.
    pub offset: u16,
    /// Length of valid data in this page (bytes).
    pub len: u16,
}

// ── BioRequest ───────────────────────────────────────────────────────────────

/// A single block I/O request.
#[derive(Debug)]
pub struct BioRequest {
    /// Starting sector (512-byte LBA).
    pub sector: u64,
    /// Number of 512-byte sectors.
    pub nr_sectors: u32,
    /// I/O direction.
    pub direction: BioDirection,
    /// Physical page list (scatter-gather).
    pub pages: Vec<BioPage>,
    /// Unique request identifier (assigned by `RequestQueue`).
    pub id: u64,
    /// Completion callback function pointer (called with `id` and `result`).
    pub completion: Option<fn(id: u64, result: Result<()>)>,
    /// Private tag for the driver (e.g. NVMe command ID).
    pub driver_tag: u32,
    /// Whether the request has been submitted to hardware.
    pub submitted: bool,
}

impl BioRequest {
    /// Create a new read request.
    pub fn read(sector: u64, nr_sectors: u32) -> Self {
        Self {
            sector,
            nr_sectors,
            direction: BioDirection::Read,
            pages: Vec::new(),
            id: 0,
            completion: None,
            driver_tag: 0,
            submitted: false,
        }
    }

    /// Create a new write request.
    pub fn write(sector: u64, nr_sectors: u32) -> Self {
        Self {
            sector,
            nr_sectors,
            direction: BioDirection::Write,
            pages: Vec::new(),
            id: 0,
            completion: None,
            driver_tag: 0,
            submitted: false,
        }
    }

    /// Create a cache-flush request.
    pub fn flush() -> Self {
        Self {
            sector: 0,
            nr_sectors: 0,
            direction: BioDirection::Flush,
            pages: Vec::new(),
            id: 0,
            completion: None,
            driver_tag: 0,
            submitted: false,
        }
    }

    /// Add a scatter-gather page to the request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if `MAX_PAGES` is exceeded.
    pub fn add_page(&mut self, phys_addr: u64, offset: u16, len: u16) -> Result<()> {
        if self.pages.len() >= MAX_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages.push(BioPage {
            phys_addr,
            offset,
            len,
        });
        Ok(())
    }

    /// Return the total byte count across all pages.
    pub fn byte_count(&self) -> usize {
        self.pages.iter().map(|p| p.len as usize).sum()
    }

    /// Return whether this request can be merged with `other`.
    ///
    /// Two requests are mergeable if they are both reads (or both writes),
    /// the second starts immediately after the first, and the combined
    /// size does not exceed 512 sectors.
    pub fn can_merge(&self, other: &BioRequest) -> bool {
        if self.direction != other.direction {
            return false;
        }
        if matches!(self.direction, BioDirection::Flush | BioDirection::Discard) {
            return false;
        }
        let end = self.sector.saturating_add(self.nr_sectors as u64);
        end == other.sector && self.nr_sectors.saturating_add(other.nr_sectors) <= 512
    }
}

// ── ElevatorPolicy ───────────────────────────────────────────────────────────

/// Block I/O scheduler policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevatorPolicy {
    /// No-Operation — requests dispatched in submission order.
    Noop,
    /// Deadline — reads prioritised, with write starvation prevention.
    Deadline,
}

// ── RequestQueue ─────────────────────────────────────────────────────────────

/// Block I/O request queue.
pub struct RequestQueue {
    /// Pending requests (submission order).
    pending: Vec<BioRequest>,
    /// Currently active (submitted-to-hardware) requests.
    active: Vec<u64>,
    /// Elevator policy.
    policy: ElevatorPolicy,
    /// Next request ID.
    next_id: u64,
    /// Queue plugged (accumulate before dispatch).
    plugged: bool,
    /// Maximum queue depth before forced unplug.
    max_depth: usize,
}

impl RequestQueue {
    /// Create a new request queue with NOOP scheduling.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            active: Vec::new(),
            policy: ElevatorPolicy::Noop,
            next_id: 1,
            plugged: false,
            max_depth: MAX_PENDING,
        }
    }

    /// Set the elevator policy.
    pub fn set_policy(&mut self, policy: ElevatorPolicy) {
        self.policy = policy;
    }

    /// Return the current elevator policy.
    pub fn policy(&self) -> ElevatorPolicy {
        self.policy
    }

    /// Plug the queue — accumulate requests without dispatching.
    pub fn plug(&mut self) {
        self.plugged = true;
    }

    /// Unplug the queue and return all pending requests for dispatch.
    pub fn unplug(&mut self) -> Vec<BioRequest> {
        self.plugged = false;
        self.drain_for_dispatch()
    }

    /// Submit a request to the queue.
    ///
    /// If the queue is unplugged and not too deep, the request is
    /// returned immediately for direct dispatch (hot path).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn submit(&mut self, mut req: BioRequest) -> Result<Option<BioRequest>> {
        if self.pending.len() >= self.max_depth {
            return Err(Error::OutOfMemory);
        }

        req.id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Try merge with last pending request.
        if !self.pending.is_empty() && self.try_merge_back(&req) {
            return Ok(None);
        }

        if !self.plugged {
            // Dispatch immediately.
            req.submitted = true;
            self.active.push(req.id);
            return Ok(Some(req));
        }

        self.pending.push(req);
        Ok(None)
    }

    /// Complete a request by its ID.
    ///
    /// Removes the request from the active list and fires the
    /// completion callback.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `id` is not in the active list.
    pub fn complete(&mut self, id: u64, result: Result<()>) -> Result<()> {
        let pos = self
            .active
            .iter()
            .position(|&x| x == id)
            .ok_or(Error::NotFound)?;
        self.active.swap_remove(pos);
        let _ = result;
        Ok(())
    }

    /// Return the number of pending (not yet dispatched) requests.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Return the number of active (dispatched) requests.
    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    /// Return whether the queue is empty (no pending or active requests).
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.active.is_empty()
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Drain pending requests for dispatch, sorted by policy.
    fn drain_for_dispatch(&mut self) -> Vec<BioRequest> {
        let mut batch = Vec::new();
        core::mem::swap(&mut self.pending, &mut batch);

        if self.policy == ElevatorPolicy::Deadline {
            // Sort: reads before writes; by sector within each group.
            batch.sort_by(|a, b| {
                use core::cmp::Ordering;
                let a_is_read = a.direction == BioDirection::Read;
                let b_is_read = b.direction == BioDirection::Read;
                match (a_is_read, b_is_read) {
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    _ => a.sector.cmp(&b.sector),
                }
            });
        }

        for req in &mut batch {
            req.submitted = true;
            self.active.push(req.id);
        }

        batch
    }

    /// Attempt to merge `req` into the last pending request.
    fn try_merge_back(&mut self, req: &BioRequest) -> bool {
        if let Some(last) = self.pending.last_mut() {
            if last.can_merge(req) {
                last.nr_sectors = last.nr_sectors.saturating_add(req.nr_sectors);
                for page in &req.pages {
                    last.pages.push(*page);
                }
                return true;
            }
        }
        false
    }
}

impl Default for RequestQueue {
    fn default() -> Self {
        Self::new()
    }
}
