// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Multi-queue block layer (blk-mq).
//!
//! Implements the multi-queue block I/O dispatch infrastructure that
//! allows parallel submission of block I/O requests across multiple
//! hardware dispatch queues. This reduces lock contention for high-IOPS
//! NVMe and other fast storage devices.
//!
//! # Design
//!
//! - Each CPU (or CPU group) gets a software staging queue (`BlkMqHctx`).
//! - Each hardware queue (`BlkMqHw`) is the device-facing dispatch point.
//! - `BlkMqTag` maps request IDs to in-flight requests.
//! - `BlkMqOps` trait defines the device driver callbacks.
//!
//! # References
//!
//! - Linux `blk-mq.h`, `blk-mq.c`
//! - Linux kernel docs: `Documentation/block/blk-mq.rst`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of hardware queues per device.
pub const BLK_MQ_MAX_HW_QUEUES: usize = 8;

/// Maximum requests per hardware queue.
pub const BLK_MQ_QUEUE_DEPTH: usize = 256;

/// Maximum number of registered blk-mq devices.
pub const BLK_MQ_MAX_DEVS: usize = 8;

// ── BlkMqReqFlags ────────────────────────────────────────────────────

/// Request flags.
pub mod flags {
    /// Read operation.
    pub const READ: u32 = 1 << 0;
    /// Write operation.
    pub const WRITE: u32 = 1 << 1;
    /// Force unit access (FUA) — bypass write cache.
    pub const FUA: u32 = 1 << 2;
    /// Flush write cache.
    pub const FLUSH: u32 = 1 << 3;
    /// Discard / TRIM.
    pub const DISCARD: u32 = 1 << 4;
    /// Pre-flushed (flush already submitted).
    pub const PREFLUSHED: u32 = 1 << 5;
}

// ── BlkMqRequest ─────────────────────────────────────────────────────

/// A single block I/O request in the multi-queue layer.
#[derive(Clone, Copy)]
pub struct BlkMqRequest {
    /// Unique tag/ID for this request.
    pub tag: u32,
    /// Target device ID.
    pub dev: u32,
    /// Starting sector (512-byte units).
    pub sector: u64,
    /// Number of sectors.
    pub nr_sectors: u32,
    /// Request flags (see [`flags`]).
    pub req_flags: u32,
    /// Physical page address of the data buffer.
    pub buf_pfn: u64,
    /// Completion status: 0 = pending, 1 = success, -1 = error.
    pub status: i32,
    /// Whether this slot is in use.
    pub active: bool,
}

impl BlkMqRequest {
    /// Create a new pending request.
    pub const fn new(tag: u32, dev: u32, sector: u64, nr_sectors: u32, req_flags: u32) -> Self {
        Self {
            tag,
            dev,
            sector,
            nr_sectors,
            req_flags,
            buf_pfn: 0,
            status: 0,
            active: true,
        }
    }

    /// Returns `true` if this is a read request.
    pub fn is_read(&self) -> bool {
        self.req_flags & flags::READ != 0
    }

    /// Returns `true` if this is a write request.
    pub fn is_write(&self) -> bool {
        self.req_flags & flags::WRITE != 0
    }

    /// Complete this request successfully.
    pub fn complete_ok(&mut self) {
        self.status = 1;
        self.active = false;
    }

    /// Complete this request with an I/O error.
    pub fn complete_err(&mut self) {
        self.status = -1;
        self.active = false;
    }
}

// ── BlkMqHw ──────────────────────────────────────────────────────────

/// A hardware dispatch queue.
pub struct BlkMqHw {
    /// Hardware queue index.
    pub queue_num: u32,
    /// In-flight requests.
    requests: [Option<BlkMqRequest>; BLK_MQ_QUEUE_DEPTH],
    count: usize,
    next_tag: u32,
}

impl BlkMqHw {
    /// Create a new hardware queue.
    pub const fn new(queue_num: u32) -> Self {
        Self {
            queue_num,
            requests: [const { None }; BLK_MQ_QUEUE_DEPTH],
            count: 0,
            next_tag: 1,
        }
    }

    /// Dispatch a new request; returns the assigned tag.
    pub fn dispatch(
        &mut self,
        dev: u32,
        sector: u64,
        nr_sectors: u32,
        req_flags: u32,
    ) -> Result<u32> {
        if self.count >= BLK_MQ_QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        for slot in self.requests.iter_mut() {
            if slot.is_none() {
                *slot = Some(BlkMqRequest::new(tag, dev, sector, nr_sectors, req_flags));
                self.count += 1;
                return Ok(tag);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Complete a request by tag.
    pub fn complete(&mut self, tag: u32, ok: bool) -> Result<()> {
        for slot in self.requests.iter_mut() {
            if let Some(req) = slot {
                if req.tag == tag && req.active {
                    if ok {
                        req.complete_ok();
                    } else {
                        req.complete_err();
                    }
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of in-flight requests.
    pub fn inflight(&self) -> usize {
        self.count
    }

    /// Returns `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.count >= BLK_MQ_QUEUE_DEPTH
    }
}

// ── BlkMqDev ─────────────────────────────────────────────────────────

/// A block device registered with the multi-queue layer.
pub struct BlkMqDev {
    /// Device ID.
    pub dev: u32,
    /// Number of hardware queues.
    pub num_hw_queues: usize,
    /// Hardware queues.
    hw_queues: [BlkMqHw; BLK_MQ_MAX_HW_QUEUES],
    /// Round-robin queue selector.
    rr_idx: usize,
}

impl BlkMqDev {
    /// Create a new blk-mq device with `num_hw_queues` queues.
    pub fn new(dev: u32, num_hw_queues: usize) -> Result<Self> {
        if num_hw_queues == 0 || num_hw_queues > BLK_MQ_MAX_HW_QUEUES {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            dev,
            num_hw_queues,
            hw_queues: core::array::from_fn(|i| BlkMqHw::new(i as u32)),
            rr_idx: 0,
        })
    }

    /// Dispatch a request to the least-loaded hardware queue.
    ///
    /// Returns `(hw_queue_num, tag)`.
    pub fn dispatch(&mut self, sector: u64, nr_sectors: u32, req_flags: u32) -> Result<(u32, u32)> {
        // Select the next queue in round-robin order, skipping full ones.
        for _ in 0..self.num_hw_queues {
            let idx = self.rr_idx % self.num_hw_queues;
            self.rr_idx = (self.rr_idx + 1) % self.num_hw_queues;
            if !self.hw_queues[idx].is_full() {
                let tag = self.hw_queues[idx].dispatch(self.dev, sector, nr_sectors, req_flags)?;
                return Ok((idx as u32, tag));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Complete a request identified by `(hw_queue_num, tag)`.
    pub fn complete(&mut self, hw_queue: u32, tag: u32, ok: bool) -> Result<()> {
        let idx = hw_queue as usize;
        if idx >= self.num_hw_queues {
            return Err(Error::InvalidArgument);
        }
        self.hw_queues[idx].complete(tag, ok)
    }

    /// Returns the total number of in-flight requests across all queues.
    pub fn total_inflight(&self) -> usize {
        self.hw_queues[..self.num_hw_queues]
            .iter()
            .map(|q| q.inflight())
            .sum()
    }
}

// ── BlkMqLayer ───────────────────────────────────────────────────────

/// Global multi-queue block layer.
pub struct BlkMqLayer {
    devs: [Option<BlkMqDev>; BLK_MQ_MAX_DEVS],
    count: usize,
}

impl BlkMqLayer {
    /// Create an empty blk-mq layer.
    pub const fn new() -> Self {
        Self {
            devs: [const { None }; BLK_MQ_MAX_DEVS],
            count: 0,
        }
    }

    /// Register a new block device with `num_hw_queues` hardware queues.
    pub fn register(&mut self, dev: u32, num_hw_queues: usize) -> Result<()> {
        for slot in self.devs.iter() {
            if let Some(d) = slot {
                if d.dev == dev {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.count >= BLK_MQ_MAX_DEVS {
            return Err(Error::OutOfMemory);
        }
        let new_dev = BlkMqDev::new(dev, num_hw_queues)?;
        for slot in self.devs.iter_mut() {
            if slot.is_none() {
                *slot = Some(new_dev);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Dispatch I/O to device `dev`; returns `(hw_queue, tag)`.
    pub fn dispatch(
        &mut self,
        dev: u32,
        sector: u64,
        nr_sectors: u32,
        req_flags: u32,
    ) -> Result<(u32, u32)> {
        for slot in self.devs.iter_mut() {
            if let Some(d) = slot {
                if d.dev == dev {
                    return d.dispatch(sector, nr_sectors, req_flags);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Complete a request on device `dev`.
    pub fn complete(&mut self, dev: u32, hw_queue: u32, tag: u32, ok: bool) -> Result<()> {
        for slot in self.devs.iter_mut() {
            if let Some(d) = slot {
                if d.dev == dev {
                    return d.complete(hw_queue, tag, ok);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered devices.
    pub fn dev_count(&self) -> usize {
        self.count
    }
}

impl Default for BlkMqLayer {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
