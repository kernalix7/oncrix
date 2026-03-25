// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO SCSI host adapter driver.
//!
//! Implements a VirtIO SCSI host bus adapter (device type 8) using the
//! VirtIO MMIO transport. The VirtIO SCSI device exposes three virtqueue
//! types:
//!
//! - Queue 0 (`controlq`) — SCSI task management (TMF) and control requests
//! - Queue 1 (`eventq`) — asynchronous device events (hot-plug, capacity change)
//! - Queues 2+ (`requestq`) — I/O command queues (one per CPU is recommended)
//!
//! Each SCSI request is submitted as a three-descriptor chain:
//! 1. `VirtioScsiReqHeader` (device-readable) — LUN, tag, CDB
//! 2. Data buffer (device-readable for WRITE, device-writable for READ)
//! 3. `VirtioScsiRespHeader` (device-writable) — sense data + status
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────┐
//! │  VirtioScsi      │ ← this driver
//! ├──────────────────┤
//! │  controlq (vq0)  │ ← task management
//! │  eventq   (vq1)  │ ← async events
//! │  requestq (vq2)  │ ← I/O commands
//! └──────────────────┘
//! ```
//!
//! Reference: VirtIO Specification v1.1, §5.6 (SCSI Host Device).

use oncrix_lib::{Error, Result};

use crate::virtio::{self, VirtioMmio, Virtqueue, desc_flags, status};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO SCSI device type ID.
pub const VIRTIO_SCSI_DEVICE_ID: u32 = 8;

/// Control virtqueue index.
const VQ_CONTROL: usize = 0;

/// Event virtqueue index.
const VQ_EVENT: usize = 1;

/// Request virtqueue index (first I/O queue).
const VQ_REQUEST: usize = 2;

/// Total number of virtqueues created by this driver (control + event + 1 request).
const NUM_VQS: usize = 3;

/// Maximum CDB (Command Descriptor Block) size.
pub const MAX_CDB_SIZE: usize = 32;

/// Maximum sense data size.
pub const MAX_SENSE_SIZE: usize = 96;

/// Maximum number of in-flight requests on the request queue.
const MAX_INFLIGHT: usize = 16;

/// Maximum data transfer size per request (1 MiB).
const MAX_TRANSFER_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// VirtIO SCSI feature bits (§5.6.3)
// ---------------------------------------------------------------------------

/// Support extra byte in CDB.
const VIRTIO_SCSI_F_INOUT: u32 = 1 << 0;
/// Support hotplug notification.
const VIRTIO_SCSI_F_HOTPLUG: u32 = 1 << 1;
/// Support T10-protected information.
const VIRTIO_SCSI_F_CHANGE: u32 = 1 << 2;
/// Support target reset.
const VIRTIO_SCSI_F_T10_PI: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Request header (§5.6.6.1)
// ---------------------------------------------------------------------------

/// VirtIO SCSI request header — placed in the first (device-readable) descriptor.
///
/// `lun` is an 8-byte field in the VirtIO SCSI wire format. The first byte
/// identifies the addressing type; for LUN 0 on target N, use
/// `[1, N, 0, 0, 0, 0, 0, 0]`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtioScsiReqHeader {
    /// Target LUN (8 bytes, VirtIO format).
    pub lun: [u8; 8],
    /// Command tag (must be unique among in-flight requests).
    pub tag: u64,
    /// Task attribute (SIMPLE = 0, HEAD_OF_QUEUE = 1, etc.).
    pub task_attr: u8,
    /// Priority (0 = normal).
    pub prio: u8,
    /// CRN (command reference number).
    pub crn: u8,
    /// Command descriptor block.
    pub cdb: [u8; MAX_CDB_SIZE],
}

// ---------------------------------------------------------------------------
// Response header (§5.6.6.1)
// ---------------------------------------------------------------------------

/// VirtIO SCSI response header — placed in the last (device-writable) descriptor.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtioScsiRespHeader {
    /// Number of sense bytes returned (may be less than `MAX_SENSE_SIZE`).
    pub sense_len: u32,
    /// Residual data count (bytes not transferred).
    pub residual: u32,
    /// SAM status byte (0x00 = GOOD, 0x02 = CHECK CONDITION, …).
    pub status: u8,
    /// VirtIO status (0 = OK, 1 = overrun, 2 = aborted, 3 = bad target, …).
    pub response: u8,
    /// Sense data (fixed allocation, `sense_len` bytes are valid).
    pub sense: [u8; MAX_SENSE_SIZE],
}

// ---------------------------------------------------------------------------
// Task management request (§5.6.6.2)
// ---------------------------------------------------------------------------

/// VirtIO SCSI task management request (TMF).
///
/// Sent via the control queue to abort, reset, or query tasks.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtioScsiCtrlTmf {
    /// Request type (must be `VIRTIO_SCSI_T_TMF` = 0).
    pub req_type: u32,
    /// Subtype (e.g., `VIRTIO_SCSI_T_TMF_ABORT_TASK` = 0).
    pub subtype: u32,
    /// Target LUN.
    pub lun: [u8; 8],
    /// Tag of the task to act on.
    pub tag: u64,
}

/// VirtIO SCSI TMF response.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtioScsiCtrlTmfResp {
    /// Response code (0 = complete, 1 = failed, …).
    pub response: u8,
}

// ---------------------------------------------------------------------------
// Task attribute constants
// ---------------------------------------------------------------------------

/// Simple task attribute (most I/O).
pub const TASK_ATTR_SIMPLE: u8 = 0;
/// Head-of-queue task attribute.
pub const TASK_ATTR_HEAD: u8 = 1;
/// Ordered task attribute.
pub const TASK_ATTR_ORDERED: u8 = 2;
/// ACA task attribute.
pub const TASK_ATTR_ACA: u8 = 3;

// ---------------------------------------------------------------------------
// VirtIO SCSI response codes
// ---------------------------------------------------------------------------

/// Request completed OK.
pub const VIRTIO_SCSI_S_OK: u8 = 0;
/// Request overrun (sense data truncated).
pub const VIRTIO_SCSI_S_OVERRUN: u8 = 1;
/// Request aborted.
pub const VIRTIO_SCSI_S_ABORTED: u8 = 2;
/// Bad target (LUN not present).
pub const VIRTIO_SCSI_S_BAD_TARGET: u8 = 3;
/// Reset observed.
pub const VIRTIO_SCSI_S_RESET: u8 = 4;
/// Transport failure.
pub const VIRTIO_SCSI_S_TRANSPORT_FAILURE: u8 = 5;
/// Target failure.
pub const VIRTIO_SCSI_S_TARGET_FAILURE: u8 = 6;
/// Nexus failure.
pub const VIRTIO_SCSI_S_NEXUS_FAILURE: u8 = 7;
/// Device or bus failure.
pub const VIRTIO_SCSI_S_FAILURE: u8 = 9;

// ---------------------------------------------------------------------------
// SCSI status bytes (SAM-5)
// ---------------------------------------------------------------------------

/// SCSI GOOD status.
pub const SCSI_STATUS_GOOD: u8 = 0x00;
/// SCSI CHECK CONDITION status.
pub const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;
/// SCSI BUSY status.
pub const SCSI_STATUS_BUSY: u8 = 0x08;

// ---------------------------------------------------------------------------
// In-flight request tracking
// ---------------------------------------------------------------------------

/// Tracks a single in-flight SCSI request.
#[derive(Clone, Copy)]
struct InflightReq {
    /// Head descriptor index in the virtqueue.
    head_desc: u16,
    /// Command tag.
    tag: u64,
    /// Whether this slot is in use.
    active: bool,
}

// ---------------------------------------------------------------------------
// VirtioScsiConfig
// ---------------------------------------------------------------------------

/// Device configuration read from VirtIO SCSI MMIO config space (§5.6.4).
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioScsiConfig {
    /// Number of event queue entries.
    pub num_queues: u32,
    /// Maximum number of segments per request.
    pub seg_max: u32,
    /// Maximum number of sectors per request.
    pub max_sectors: u32,
    /// Command queue depth.
    pub cmd_per_lun: u32,
    /// Maximum allowed CDB size (bytes).
    pub cdb_size: u32,
    /// Maximum number of LUNs per target.
    pub max_lun: u16,
    /// Maximum target ID.
    pub max_target: u16,
    /// Maximum number of channels.
    pub max_channel: u32,
}

// ---------------------------------------------------------------------------
// VirtioScsi
// ---------------------------------------------------------------------------

/// VirtIO SCSI host adapter driver.
pub struct VirtioScsi {
    /// MMIO transport.
    mmio: VirtioMmio,
    /// Control virtqueue (queue 0).
    vq_control: Virtqueue,
    /// Event virtqueue (queue 1).
    vq_event: Virtqueue,
    /// Request virtqueue (queue 2).
    vq_request: Virtqueue,
    /// Device configuration.
    config: VirtioScsiConfig,
    /// In-flight request slots.
    inflight: [InflightReq; MAX_INFLIGHT],
    /// Number of active in-flight requests.
    inflight_count: usize,
    /// Monotonically increasing command tag generator.
    next_tag: u64,
    /// Request headers (reused across requests).
    req_headers: [VirtioScsiReqHeader; MAX_INFLIGHT],
    /// Response headers (one per in-flight slot).
    resp_headers: [VirtioScsiRespHeader; MAX_INFLIGHT],
    /// Whether the device has been initialized.
    initialized: bool,
}

impl VirtioScsi {
    /// Create a new VirtIO SCSI adapter for a device at `mmio_base`.
    pub const fn new(mmio_base: u64) -> Self {
        const ZERO_REQ: VirtioScsiReqHeader = VirtioScsiReqHeader {
            lun: [0u8; 8],
            tag: 0,
            task_attr: 0,
            prio: 0,
            crn: 0,
            cdb: [0u8; MAX_CDB_SIZE],
        };
        const ZERO_RESP: VirtioScsiRespHeader = VirtioScsiRespHeader {
            sense_len: 0,
            residual: 0,
            status: 0,
            response: 0,
            sense: [0u8; MAX_SENSE_SIZE],
        };
        Self {
            mmio: VirtioMmio::new(mmio_base),
            vq_control: Virtqueue::new(),
            vq_event: Virtqueue::new(),
            vq_request: Virtqueue::new(),
            config: VirtioScsiConfig {
                num_queues: 0,
                seg_max: 0,
                max_sectors: 0,
                cmd_per_lun: 0,
                cdb_size: 0,
                max_lun: 0,
                max_target: 0,
                max_channel: 0,
            },
            inflight: [InflightReq {
                head_desc: 0,
                tag: 0,
                active: false,
            }; MAX_INFLIGHT],
            inflight_count: 0,
            next_tag: 1,
            req_headers: [ZERO_REQ; MAX_INFLIGHT],
            resp_headers: [ZERO_RESP; MAX_INFLIGHT],
            initialized: false,
        }
    }

    /// Probe and initialize the VirtIO SCSI adapter.
    ///
    /// Follows the VirtIO initialization sequence (§3.1):
    /// 1. Reset device
    /// 2. ACKNOWLEDGE + DRIVER status bits
    /// 3. Feature negotiation
    /// 4. FEATURES_OK
    /// 5. Set up virtqueues (control, event, request)
    /// 6. Read device configuration
    /// 7. DRIVER_OK
    pub fn init(&mut self) -> Result<()> {
        // Step 0: Verify device type.
        let device_id = self.mmio.probe()?;
        if device_id != VIRTIO_SCSI_DEVICE_ID {
            return Err(Error::NotFound);
        }

        // Step 1: Reset.
        self.mmio.reset();

        // Step 2: Acknowledge.
        self.mmio.set_status(status::ACKNOWLEDGE);
        self.mmio.set_status(status::DRIVER);

        // Step 3: Feature negotiation.
        let dev_features = self.mmio.read_device_features(0);
        // Accept HOTPLUG and CHANGE if offered; skip T10_PI and INOUT.
        let accepted = dev_features & (VIRTIO_SCSI_F_HOTPLUG | VIRTIO_SCSI_F_CHANGE) as u32;
        self.mmio.write_driver_features(0, accepted as u32);
        self.mmio.write_driver_features(1, 0);

        // Step 4: Features OK.
        self.mmio.set_status(status::FEATURES_OK);
        if self.mmio.status() & status::FEATURES_OK == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        // Step 5: Set up virtqueues.
        // Split borrows: take raw pointers before passing &mut self.
        let vq_ctl = &raw mut self.vq_control;
        let vq_evt = &raw mut self.vq_event;
        let vq_req = &raw mut self.vq_request;
        self.setup_vq(VQ_CONTROL, vq_ctl)?;
        self.setup_vq(VQ_EVENT, vq_evt)?;
        self.setup_vq(VQ_REQUEST, vq_req)?;

        // Step 6: Read device configuration (§5.6.4).
        // Config space begins at MMIO offset 0x100.
        let num_queues = self.mmio.read32(0x100);
        let seg_max = self.mmio.read32(0x104);
        let max_sectors = self.mmio.read32(0x108);
        let cmd_per_lun = self.mmio.read32(0x10C);
        let cdb_size = self.mmio.read32(0x110);
        let max_lun = (self.mmio.read32(0x114) & 0xFFFF) as u16;
        let max_target = ((self.mmio.read32(0x114) >> 16) & 0xFFFF) as u16;
        let max_channel = self.mmio.read32(0x118);
        self.config = VirtioScsiConfig {
            num_queues,
            seg_max,
            max_sectors,
            cmd_per_lun,
            cdb_size,
            max_lun,
            max_target,
            max_channel,
        };

        // Step 7: Driver OK.
        self.mmio.set_status(status::DRIVER_OK);

        self.initialized = true;
        Ok(())
    }

    /// Set up a single virtqueue by index.
    ///
    /// # Safety
    ///
    /// `vq_ptr` must point to a valid `Virtqueue` that outlives the MMIO
    /// configuration window. The function is called from `init()` which
    /// borrows `self` exclusively, so there are no aliasing issues.
    fn setup_vq(&mut self, queue_idx: usize, vq_ptr: *mut Virtqueue) -> Result<()> {
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_SEL, queue_idx as u32);
        let max_size = self.mmio.read32(virtio::mmio_reg::QUEUE_NUM_MAX);
        if max_size == 0 {
            return Err(Error::IoError);
        }

        // SAFETY: `vq_ptr` is a valid, exclusively-borrowed Virtqueue. We
        // initialise it here before any concurrent access is possible.
        let vq = unsafe { &mut *vq_ptr };
        vq.init();

        let queue_size = (vq.num as u32).min(max_size);
        self.mmio.write32(virtio::mmio_reg::QUEUE_NUM, queue_size);

        let desc_addr = vq.desc.as_ptr() as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_LOW, desc_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);

        let avail_addr = &vq.avail_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_AVAIL_LOW, avail_addr as u32);
        self.mmio.write32(
            virtio::mmio_reg::QUEUE_AVAIL_HIGH,
            (avail_addr >> 32) as u32,
        );

        let used_addr = &vq.used_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_LOW, used_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_HIGH, (used_addr >> 32) as u32);

        self.mmio.write32(virtio::mmio_reg::QUEUE_READY, 1);
        Ok(())
    }

    /// Submit a SCSI command.
    ///
    /// - `lun` — 8-byte VirtIO LUN address (e.g., `[1, target, 0, 0, 0, 0, 0, 0]`)
    /// - `cdb` — Command Descriptor Block slice (max [`MAX_CDB_SIZE`] bytes)
    /// - `data` — data buffer (device writes here for READ commands)
    /// - `is_write` — if `true`, the device reads from `data` (WRITE direction)
    ///
    /// Returns the in-flight slot index; call [`poll_completion`] to collect the result.
    pub fn submit(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: &mut [u8],
        is_write: bool,
    ) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if cdb.is_empty() || cdb.len() > MAX_CDB_SIZE {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_TRANSFER_SIZE {
            return Err(Error::InvalidArgument);
        }

        let slot = self.alloc_inflight()?;
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);

        // Build request header.
        let mut header = VirtioScsiReqHeader {
            lun,
            tag,
            task_attr: TASK_ATTR_SIMPLE,
            prio: 0,
            crn: 0,
            cdb: [0u8; MAX_CDB_SIZE],
        };
        let cdb_len = cdb.len().min(MAX_CDB_SIZE);
        header.cdb[..cdb_len].copy_from_slice(&cdb[..cdb_len]);
        self.req_headers[slot] = header;

        // Clear response header.
        self.resp_headers[slot] = VirtioScsiRespHeader {
            sense_len: 0,
            residual: 0,
            status: 0xFF,
            response: 0xFF,
            sense: [0u8; MAX_SENSE_SIZE],
        };

        // Allocate three descriptors.
        let d_req = self.vq_request.alloc_desc()?;
        let d_data = match self.vq_request.alloc_desc() {
            Ok(d) => d,
            Err(e) => {
                self.vq_request.free_desc(d_req);
                return Err(e);
            }
        };
        let d_resp = match self.vq_request.alloc_desc() {
            Ok(d) => d,
            Err(e) => {
                self.vq_request.free_desc(d_req);
                self.vq_request.free_desc(d_data);
                return Err(e);
            }
        };

        // Descriptor 0: request header (device-readable).
        self.vq_request.desc[d_req as usize].addr =
            &self.req_headers[slot] as *const VirtioScsiReqHeader as u64;
        self.vq_request.desc[d_req as usize].len =
            core::mem::size_of::<VirtioScsiReqHeader>() as u32;
        self.vq_request.desc[d_req as usize].flags = desc_flags::NEXT;
        self.vq_request.desc[d_req as usize].next = d_data;

        // Descriptor 1: data buffer.
        self.vq_request.desc[d_data as usize].addr = data.as_ptr() as u64;
        self.vq_request.desc[d_data as usize].len = data.len() as u32;
        self.vq_request.desc[d_data as usize].flags = if is_write {
            desc_flags::NEXT
        } else {
            desc_flags::WRITE | desc_flags::NEXT
        };
        self.vq_request.desc[d_data as usize].next = d_resp;

        // Descriptor 2: response header (device-writable).
        self.vq_request.desc[d_resp as usize].addr =
            &self.resp_headers[slot] as *const VirtioScsiRespHeader as u64;
        self.vq_request.desc[d_resp as usize].len =
            core::mem::size_of::<VirtioScsiRespHeader>() as u32;
        self.vq_request.desc[d_resp as usize].flags = desc_flags::WRITE;
        self.vq_request.desc[d_resp as usize].next = 0;

        // Track and notify.
        self.inflight[slot].head_desc = d_req;
        self.inflight[slot].tag = tag;
        self.inflight[slot].active = true;
        self.inflight_count += 1;

        self.vq_request.push_avail(d_req);
        self.mmio.notify(VQ_REQUEST as u32);

        Ok(slot)
    }

    /// Poll the request queue for a completed command.
    ///
    /// Returns `Some(slot)` if a command completed, `None` otherwise.
    pub fn poll_completion(&mut self) -> Option<usize> {
        let (desc_head, _len) = self.vq_request.pop_used()?;

        for (i, req) in self.inflight.iter_mut().enumerate() {
            if req.active && req.head_desc == desc_head {
                req.active = false;
                self.inflight_count = self.inflight_count.saturating_sub(1);

                // Free the three-descriptor chain.
                let d1 = self.vq_request.desc[desc_head as usize].next;
                let d2 = self.vq_request.desc[d1 as usize].next;
                self.vq_request.free_desc(d2);
                self.vq_request.free_desc(d1);
                self.vq_request.free_desc(desc_head);

                return Some(i);
            }
        }
        None
    }

    /// Inspect the result of a completed request at `slot`.
    ///
    /// Returns `Ok(())` when both the VirtIO response and SCSI status are
    /// successful, or an appropriate error otherwise.
    pub fn request_result(&self, slot: usize) -> Result<()> {
        if slot >= MAX_INFLIGHT {
            return Err(Error::InvalidArgument);
        }
        let resp = &self.resp_headers[slot];
        if resp.response != VIRTIO_SCSI_S_OK {
            return Err(Error::IoError);
        }
        if resp.status != SCSI_STATUS_GOOD {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Return the sense data from the last completed request at `slot`.
    ///
    /// Returns a slice of up to `MAX_SENSE_SIZE` bytes; the valid length
    /// is given by `VirtioScsiRespHeader::sense_len`.
    pub fn sense_data(&self, slot: usize) -> Option<(&[u8], u32)> {
        if slot >= MAX_INFLIGHT {
            return None;
        }
        let resp = &self.resp_headers[slot];
        let len = (resp.sense_len as usize).min(MAX_SENSE_SIZE);
        Some((&resp.sense[..len], resp.sense_len))
    }

    /// Return device configuration.
    pub fn config(&self) -> &VirtioScsiConfig {
        &self.config
    }

    /// Handle a VirtIO SCSI interrupt.
    ///
    /// Acknowledges the interrupt and returns `true` if used-buffer
    /// notifications are pending.
    pub fn handle_irq(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        let isr = self.mmio.ack_interrupt();
        isr & 1 != 0
    }

    /// Returns `true` if the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Number of in-flight requests.
    pub fn inflight_count(&self) -> usize {
        self.inflight_count
    }

    /// Find a free in-flight slot.
    fn alloc_inflight(&self) -> Result<usize> {
        for (i, req) in self.inflight.iter().enumerate() {
            if !req.active {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }
}

impl core::fmt::Debug for VirtioScsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioScsi")
            .field("initialized", &self.initialized)
            .field("inflight", &self.inflight_count)
            .field("max_target", &self.config.max_target)
            .finish()
    }
}
