// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vhost-blk driver.
//!
//! Implements the kernel-side vhost block device interface for accelerating
//! virtio-blk I/O by processing block requests in the host kernel without
//! round-tripping through userspace QEMU. Handles virtqueue request
//! dispatch and completion.

use oncrix_lib::{Error, Result};

/// Maximum number of vhost-blk request queues.
pub const MAX_QUEUES: usize = 8;
/// Maximum number of descriptors per request queue.
pub const RING_SIZE: usize = 128;

/// Virtio block request types.
pub const VIRTIO_BLK_T_IN: u32 = 0; // Read from device
pub const VIRTIO_BLK_T_OUT: u32 = 1; // Write to device
pub const VIRTIO_BLK_T_FLUSH: u32 = 4; // Cache flush
pub const VIRTIO_BLK_T_DISCARD: u32 = 11; // Discard (TRIM)
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

/// Virtio block request status codes.
pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Virtio block request header in `#[repr(C)]` for shared memory.
#[repr(C)]
pub struct VirtioBlkReqHeader {
    /// Request type (VIRTIO_BLK_T_*).
    pub req_type: u32,
    /// Reserved.
    pub reserved: u32,
    /// Sector number (512-byte sectors).
    pub sector: u64,
}

impl VirtioBlkReqHeader {
    pub const fn new(req_type: u32, sector: u64) -> Self {
        Self {
            req_type,
            reserved: 0,
            sector,
        }
    }
}

/// vhost-blk queue.
pub struct VhostBlkQueue {
    /// Queue index.
    index: usize,
    /// Last available ring index processed.
    last_avail_idx: u16,
    /// Queue is active.
    enabled: bool,
    /// Total requests processed.
    requests_completed: u64,
}

impl VhostBlkQueue {
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            last_avail_idx: 0,
            enabled: false,
            requests_completed: 0,
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Process one available request (placeholder — real impl accesses shared ring).
    pub fn process_request(&mut self, sector: u64, write: bool) -> Result<u8> {
        if !self.enabled {
            return Err(Error::IoError);
        }
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
        self.requests_completed += 1;
        // Real impl would dispatch to the backing block device here.
        let _ = (sector, write);
        Ok(VIRTIO_BLK_S_OK)
    }

    pub fn requests_completed(&self) -> u64 {
        self.requests_completed
    }
}

/// vhost-blk device driver.
pub struct VhostBlk {
    /// Request queues.
    queues: [VhostBlkQueue; MAX_QUEUES],
    /// Number of active queues.
    num_queues: usize,
    /// Total disk capacity in 512-byte sectors.
    capacity_sectors: u64,
    /// Device is in read-only mode.
    read_only: bool,
    /// Device is running.
    active: bool,
}

impl VhostBlk {
    /// Create a new vhost-blk driver.
    pub fn new(num_queues: usize, capacity_sectors: u64, read_only: bool) -> Self {
        let nq = num_queues.min(MAX_QUEUES);
        Self {
            queues: core::array::from_fn(|i| VhostBlkQueue::new(i)),
            num_queues: nq,
            capacity_sectors,
            read_only,
            active: false,
        }
    }

    /// Start the device.
    pub fn start(&mut self) -> Result<()> {
        if self.active {
            return Err(Error::Busy);
        }
        for q in self.queues[..self.num_queues].iter_mut() {
            q.enable();
        }
        self.active = true;
        Ok(())
    }

    /// Stop the device.
    pub fn stop(&mut self) {
        for q in self.queues[..self.num_queues].iter_mut() {
            q.disable();
        }
        self.active = false;
    }

    /// Dispatch a block I/O request on the given queue.
    pub fn dispatch(&mut self, queue: usize, sector: u64, write: bool) -> Result<u8> {
        if queue >= self.num_queues {
            return Err(Error::InvalidArgument);
        }
        if write && self.read_only {
            return Err(Error::PermissionDenied);
        }
        if sector >= self.capacity_sectors {
            return Err(Error::InvalidArgument);
        }
        self.queues[queue].process_request(sector, write)
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
    pub fn num_queues(&self) -> usize {
        self.num_queues
    }
}
