// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO block device driver.
//!
//! Implements a VirtIO block device (device type 2) using the MMIO
//! transport. Supports read and write operations via the virtqueue
//! request protocol.
//!
//! The driver uses a single virtqueue (queue 0) and submits requests
//! in the standard three-descriptor chain format:
//! 1. `VirtioBlkReqHeader` (device-readable) — operation type + sector
//! 2. Data buffer (device-readable for write, device-writable for read)
//! 3. Status byte (device-writable) — 0 = OK, 1 = IO error, 2 = unsupported
//!
//! Reference: VirtIO Specification v1.1, §5.2 (Block Device).

use oncrix_lib::{Error, Result};

use crate::virtio::{self, VirtioMmio, Virtqueue, desc_flags, status};

/// VirtIO block device type ID.
pub const VIRTIO_BLK_DEVICE_ID: u32 = 2;

/// Sector size (always 512 bytes for virtio-blk).
pub const SECTOR_SIZE: usize = 512;

/// Maximum number of in-flight requests.
const MAX_INFLIGHT: usize = 16;

/// Maximum sectors per request (256 KiB).
const MAX_SECTORS_PER_REQ: u64 = 512;

// ---------------------------------------------------------------------------
// Block request types (§5.2.6)
// ---------------------------------------------------------------------------

/// Read sectors.
const VIRTIO_BLK_T_IN: u32 = 0;
/// Write sectors.
const VIRTIO_BLK_T_OUT: u32 = 1;

// ---------------------------------------------------------------------------
// Block request status (§5.2.6)
// ---------------------------------------------------------------------------

/// Request completed successfully.
const VIRTIO_BLK_S_OK: u8 = 0;

// ---------------------------------------------------------------------------
// Block request header (§5.2.6)
// ---------------------------------------------------------------------------

/// Block request header — first descriptor in the chain.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtioBlkReqHeader {
    /// Request type (`VIRTIO_BLK_T_IN` or `VIRTIO_BLK_T_OUT`).
    pub req_type: u32,
    /// Reserved (must be zero).
    pub reserved: u32,
    /// Starting sector number.
    pub sector: u64,
}

// ---------------------------------------------------------------------------
// Block device configuration (§5.2.4)
// ---------------------------------------------------------------------------

/// Device configuration, read from MMIO config space.
#[derive(Debug, Clone, Copy)]
pub struct BlkConfig {
    /// Total capacity in 512-byte sectors.
    pub capacity: u64,
}

// ---------------------------------------------------------------------------
// In-flight request tracking
// ---------------------------------------------------------------------------

/// An in-flight block request.
#[derive(Debug, Clone, Copy)]
struct InflightReq {
    /// Head descriptor index.
    head_desc: u16,
    /// Whether this slot is in use.
    active: bool,
}

// ---------------------------------------------------------------------------
// VirtIO block device
// ---------------------------------------------------------------------------

/// VirtIO block device driver.
pub struct VirtioBlk {
    /// MMIO transport.
    mmio: VirtioMmio,
    /// The single virtqueue (queue 0).
    vq: Virtqueue,
    /// Device configuration.
    config: BlkConfig,
    /// In-flight request tracker.
    inflight: [InflightReq; MAX_INFLIGHT],
    /// Number of in-flight requests.
    inflight_count: usize,
    /// Request header storage (reused across requests).
    req_headers: [VirtioBlkReqHeader; MAX_INFLIGHT],
    /// Status byte storage (one per in-flight request).
    req_status: [u8; MAX_INFLIGHT],
    /// Whether the device has been initialized.
    initialized: bool,
}

impl VirtioBlk {
    /// Create a new virtio-blk driver for a device at `mmio_base`.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio: VirtioMmio::new(mmio_base),
            vq: Virtqueue::new(),
            config: BlkConfig { capacity: 0 },
            inflight: [InflightReq {
                head_desc: 0,
                active: false,
            }; MAX_INFLIGHT],
            inflight_count: 0,
            req_headers: [VirtioBlkReqHeader {
                req_type: 0,
                reserved: 0,
                sector: 0,
            }; MAX_INFLIGHT],
            req_status: [0xFF; MAX_INFLIGHT],
            initialized: false,
        }
    }

    /// Probe and initialize the virtio-blk device.
    ///
    /// Follows the VirtIO initialization sequence (§3.1):
    /// 1. Reset device
    /// 2. Set ACKNOWLEDGE + DRIVER status
    /// 3. Read device features, negotiate
    /// 4. Set FEATURES_OK
    /// 5. Set up virtqueue
    /// 6. Set DRIVER_OK
    pub fn init(&mut self) -> Result<()> {
        // Step 0: Probe — verify magic, version, device type.
        let device_id = self.mmio.probe()?;
        if device_id != VIRTIO_BLK_DEVICE_ID {
            return Err(Error::NotFound);
        }

        // Step 1: Reset.
        self.mmio.reset();

        // Step 2: Acknowledge.
        self.mmio.set_status(status::ACKNOWLEDGE);
        self.mmio.set_status(status::DRIVER);

        // Step 3: Feature negotiation.
        // Read device features word 0; we don't need any fancy features.
        let _dev_features = self.mmio.read_device_features(0);
        // Accept no optional features for now.
        self.mmio.write_driver_features(0, 0);
        self.mmio.write_driver_features(1, 0);

        // Step 4: Features OK.
        self.mmio.set_status(status::FEATURES_OK);
        if self.mmio.status() & status::FEATURES_OK == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        // Step 5: Set up queue 0.
        self.vq.init();
        self.mmio.write32(virtio::mmio_reg::QUEUE_SEL, 0);
        let max_size = self.mmio.read32(virtio::mmio_reg::QUEUE_NUM_MAX);
        if max_size == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }
        let queue_size = (self.vq.num as u32).min(max_size);
        self.mmio.write32(virtio::mmio_reg::QUEUE_NUM, queue_size);

        // Write descriptor table, available ring, and used ring addresses.
        // In a real driver these would be physical addresses from DMA-able
        // memory. Here we use the embedded arrays' addresses directly
        // (works under identity mapping or with proper virt→phys translation).
        let desc_addr = self.vq.desc.as_ptr() as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_LOW, desc_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);

        let avail_addr = &self.vq.avail_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_AVAIL_LOW, avail_addr as u32);
        self.mmio.write32(
            virtio::mmio_reg::QUEUE_AVAIL_HIGH,
            (avail_addr >> 32) as u32,
        );

        let used_addr = &self.vq.used_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_LOW, used_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_HIGH, (used_addr >> 32) as u32);

        self.mmio.write32(virtio::mmio_reg::QUEUE_READY, 1);

        // Step 6: Read configuration.
        // Block device config starts at offset 0x100 in MMIO.
        let cap_lo = self.mmio.read32(0x100) as u64;
        let cap_hi = self.mmio.read32(0x104) as u64;
        self.config.capacity = cap_lo | (cap_hi << 32);

        // Step 7: Driver OK.
        self.mmio.set_status(status::DRIVER_OK);

        self.initialized = true;
        Ok(())
    }

    /// Return the device capacity in sectors.
    pub fn capacity_sectors(&self) -> u64 {
        self.config.capacity
    }

    /// Return the device capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.config.capacity * SECTOR_SIZE as u64
    }

    /// Submit a read request for `sector_count` sectors starting at `sector`.
    ///
    /// `buf` must be at least `sector_count * SECTOR_SIZE` bytes.
    ///
    /// Returns the in-flight request slot index. Call `poll_completion()`
    /// to wait for the result.
    pub fn read_sectors(
        &mut self,
        sector: u64,
        sector_count: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        self.submit_request(VIRTIO_BLK_T_IN, sector, sector_count, buf)
    }

    /// Submit a write request for `sector_count` sectors starting at `sector`.
    ///
    /// `buf` must be at least `sector_count * SECTOR_SIZE` bytes.
    pub fn write_sectors(&mut self, sector: u64, sector_count: u64, buf: &[u8]) -> Result<usize> {
        // We need a mutable reference to pass through, but the device
        // only reads from this buffer. Create a mutable view via pointer.
        let buf_ptr = buf.as_ptr() as *mut u8;
        let buf_len = buf.len();
        // SAFETY: The device only reads from a VIRTIO_BLK_T_OUT buffer.
        // We maintain the original lifetime through the borrow of `buf`.
        let buf_mut = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };
        self.submit_request(VIRTIO_BLK_T_OUT, sector, sector_count, buf_mut)
    }

    /// Submit a block request (read or write).
    fn submit_request(
        &mut self,
        req_type: u32,
        sector: u64,
        sector_count: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if sector_count == 0 || sector_count > MAX_SECTORS_PER_REQ {
            return Err(Error::InvalidArgument);
        }
        let needed_bytes = sector_count as usize * SECTOR_SIZE;
        if buf.len() < needed_bytes {
            return Err(Error::InvalidArgument);
        }
        if sector + sector_count > self.config.capacity {
            return Err(Error::InvalidArgument);
        }

        // Find a free in-flight slot.
        let slot = self.alloc_inflight()?;

        // Set up the request header.
        self.req_headers[slot] = VirtioBlkReqHeader {
            req_type,
            reserved: 0,
            sector,
        };
        self.req_status[slot] = 0xFF; // sentinel

        // Allocate 3 descriptors: header, data, status.
        let d_hdr = self.vq.alloc_desc()?;
        let d_data = match self.vq.alloc_desc() {
            Ok(d) => d,
            Err(e) => {
                self.vq.free_desc(d_hdr);
                return Err(e);
            }
        };
        let d_status = match self.vq.alloc_desc() {
            Ok(d) => d,
            Err(e) => {
                self.vq.free_desc(d_hdr);
                self.vq.free_desc(d_data);
                return Err(e);
            }
        };

        // Descriptor 0: header (device-readable).
        self.vq.desc[d_hdr as usize].addr =
            &self.req_headers[slot] as *const VirtioBlkReqHeader as u64;
        self.vq.desc[d_hdr as usize].len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
        self.vq.desc[d_hdr as usize].flags = desc_flags::NEXT;
        self.vq.desc[d_hdr as usize].next = d_data;

        // Descriptor 1: data buffer.
        self.vq.desc[d_data as usize].addr = buf.as_ptr() as u64;
        self.vq.desc[d_data as usize].len = needed_bytes as u32;
        self.vq.desc[d_data as usize].flags = if req_type == VIRTIO_BLK_T_IN {
            desc_flags::WRITE | desc_flags::NEXT // device writes to buf
        } else {
            desc_flags::NEXT // device reads from buf
        };
        self.vq.desc[d_data as usize].next = d_status;

        // Descriptor 2: status byte (device-writable).
        self.vq.desc[d_status as usize].addr = &self.req_status[slot] as *const u8 as u64;
        self.vq.desc[d_status as usize].len = 1;
        self.vq.desc[d_status as usize].flags = desc_flags::WRITE;
        self.vq.desc[d_status as usize].next = 0;

        // Track the in-flight request.
        self.inflight[slot].head_desc = d_hdr;
        self.inflight[slot].active = true;
        self.inflight_count += 1;

        // Push to available ring and notify device.
        self.vq.push_avail(d_hdr);
        self.mmio.notify(0);

        Ok(slot)
    }

    /// Poll for a completed request.
    ///
    /// Returns `Some(slot_index)` if a request completed, `None` if
    /// no completions are available yet.
    pub fn poll_completion(&mut self) -> Option<usize> {
        let (desc_head, _len) = self.vq.pop_used()?;

        // Find the in-flight slot for this descriptor chain.
        for (i, req) in self.inflight.iter_mut().enumerate() {
            if req.active && req.head_desc == desc_head {
                req.active = false;
                self.inflight_count = self.inflight_count.saturating_sub(1);

                // Free the 3-descriptor chain.
                let d1 = self.vq.desc[desc_head as usize].next;
                let d2 = self.vq.desc[d1 as usize].next;
                self.vq.free_desc(d2);
                self.vq.free_desc(d1);
                self.vq.free_desc(desc_head);

                return Some(i);
            }
        }
        None
    }

    /// Check if the last completed request at `slot` succeeded.
    pub fn request_status(&self, slot: usize) -> Result<()> {
        if slot >= MAX_INFLIGHT {
            return Err(Error::InvalidArgument);
        }
        if self.req_status[slot] == VIRTIO_BLK_S_OK {
            Ok(())
        } else {
            Err(Error::IoError)
        }
    }

    /// Handle a virtio-blk interrupt.
    ///
    /// Acknowledges the interrupt and returns `true` if there are
    /// completions to process.
    pub fn handle_irq(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        let isr = self.mmio.ack_interrupt();
        isr & 1 != 0 // bit 0 = used buffer notification
    }

    /// Check if the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Number of in-flight requests.
    pub fn inflight_count(&self) -> usize {
        self.inflight_count
    }

    /// Allocate a free in-flight request slot.
    fn alloc_inflight(&self) -> Result<usize> {
        for (i, req) in self.inflight.iter().enumerate() {
            if !req.active {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }
}

impl core::fmt::Debug for VirtioBlk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBlk")
            .field("initialized", &self.initialized)
            .field("capacity_sectors", &self.config.capacity)
            .field("inflight", &self.inflight_count)
            .finish()
    }
}
