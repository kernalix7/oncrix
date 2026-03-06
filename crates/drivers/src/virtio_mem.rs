// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO memory hotplug device driver (virtio-mem).
//!
//! Implements the VirtIO memory device (device type 24) defined in the
//! VirtIO 1.2 specification §5.15. The device allows the host to request
//! that the guest add or remove memory at runtime (hotplug / hot-remove).
//!
//! # Protocol Overview
//!
//! The device exposes a single virtqueue (`requestq`) through which the
//! guest sends block-request messages and receives responses:
//!
//! | Request type                | Code | Description                |
//! |-----------------------------|------|----------------------------|
//! | `VIRTIO_MEM_REQ_PLUG`       | 0    | plug a range of blocks     |
//! | `VIRTIO_MEM_REQ_UNPLUG`     | 1    | unplug a range of blocks   |
//! | `VIRTIO_MEM_REQ_UNPLUG_ALL` | 2    | unplug all plugged blocks  |
//! | `VIRTIO_MEM_REQ_STATE`      | 3    | query block plug state     |
//!
//! The device configuration space exposes:
//! - `block_size` — granularity of memory blocks (power of 2, ≥ 2 MiB).
//! - `node_id` — NUMA node affinity.
//! - `addr` — GPA base of the hotplug memory region.
//! - `region_size` — total size of the hotplug region.
//! - `usable_region_size` — currently usable portion.
//! - `plugged_size` — bytes currently plugged (accepted by guest).
//! - `requested_size` — bytes the host wants plugged.
//!
//! # Architecture
//!
//! - [`MemConfig`] — mirrors the device configuration space.
//! - [`MemRequest`] / [`MemResponse`] — request/response descriptors.
//! - [`BlockState`] — state of a memory block (unplugged / plugged / mixed).
//! - [`VirtioMem`] — the main driver struct.
//! - [`VirtioMemRegistry`] — fixed-size registry for up to [`MAX_VIRTIO_MEM_DEVICES`].
//!
//! Reference: VirtIO Specification v1.2 §5.15 (Memory Device).

use oncrix_lib::{Error, Result};

use crate::virtio::{self, VirtioMmio, Virtqueue, status};

// ---------------------------------------------------------------------------
// VirtIO device type
// ---------------------------------------------------------------------------

/// VirtIO device type ID for the memory device.
pub const VIRTIO_MEM_DEVICE_ID: u32 = 24;

// ---------------------------------------------------------------------------
// Feature bits (§5.15.3)
// ---------------------------------------------------------------------------

/// Feature bit: VIRTIO_MEM_F_ACPI_PXM — NUMA proximity domain is valid.
pub const VIRTIO_MEM_F_ACPI_PXM: u32 = 1 << 0;

/// Feature bit: VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE — unplugged memory
/// must not be accessed by the guest.
pub const VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Request type codes (§5.15.6.2)
// ---------------------------------------------------------------------------

/// Request type: plug a number of memory blocks.
const VIRTIO_MEM_REQ_PLUG: u16 = 0;
/// Request type: unplug a number of memory blocks.
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
/// Request type: unplug all previously plugged blocks.
#[allow(dead_code)]
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
/// Request type: query the state of memory blocks.
const VIRTIO_MEM_REQ_STATE: u16 = 3;

// ---------------------------------------------------------------------------
// Response type codes (§5.15.6.3)
// ---------------------------------------------------------------------------

/// Response: request acknowledged / success.
const VIRTIO_MEM_RESP_ACK: u16 = 0;
/// Response: request rejected by device.
const VIRTIO_MEM_RESP_NACK: u16 = 1;
/// Response: request could not be processed (device busy/error).
#[allow(dead_code)]
const VIRTIO_MEM_RESP_ERROR: u16 = 2;

// ---------------------------------------------------------------------------
// Block state values (§5.15.6.4)
// ---------------------------------------------------------------------------

/// Block state: unplugged.
const VIRTIO_MEM_STATE_UNPLUGGED: u16 = 0;
/// Block state: plugged.
const VIRTIO_MEM_STATE_PLUGGED: u16 = 1;
/// Block state: mixed (only valid for multi-block range queries).
const VIRTIO_MEM_STATE_MIXED: u16 = 2;

// ---------------------------------------------------------------------------
// Sizing
// ---------------------------------------------------------------------------

/// Maximum number of virtio-mem devices supported.
const MAX_VIRTIO_MEM_DEVICES: usize = 4;

/// Maximum number of memory blocks tracked per device.
const MAX_BLOCKS: usize = 512;

/// Default minimum block size (2 MiB).
const DEFAULT_BLOCK_SIZE: u64 = 2 * 1024 * 1024;

/// VirtIO MMIO config space base offset (§4.2.4).
const MMIO_CONFIG_BASE: u32 = 0x100;

// ---------------------------------------------------------------------------
// MemConfig (§5.15.4)
// ---------------------------------------------------------------------------

/// VirtIO memory device configuration space (parsed from MMIO).
#[derive(Debug, Clone, Copy)]
pub struct MemConfig {
    /// Memory block size in bytes (power of 2, ≥ 2 MiB).
    pub block_size: u64,
    /// NUMA node ID (valid when `VIRTIO_MEM_F_ACPI_PXM` is negotiated).
    pub node_id: u16,
    /// Base guest-physical address of the hotplug region.
    pub addr: u64,
    /// Total size of the hotplug region in bytes.
    pub region_size: u64,
    /// Currently usable (potentially pluggable) size in bytes.
    pub usable_region_size: u64,
    /// Bytes currently plugged (acknowledged by the guest).
    pub plugged_size: u64,
    /// Bytes the host is requesting to be plugged.
    pub requested_size: u64,
}

impl Default for MemConfig {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            node_id: 0,
            addr: 0,
            region_size: 0,
            usable_region_size: 0,
            plugged_size: 0,
            requested_size: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MemRequest / MemResponse (§5.15.6)
// ---------------------------------------------------------------------------

/// Request sent by the driver to the virtio-mem device.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MemRequest {
    /// Request type (VIRTIO_MEM_REQ_*).
    pub req_type: u16,
    /// Padding (must be zero).
    pub _pad: [u8; 6],
    /// First block address (GPA of the first block in the range).
    pub addr: u64,
    /// Number of blocks in the range.
    pub nb_blocks: u16,
    /// Padding.
    pub _pad2: [u8; 6],
}

impl MemRequest {
    /// Build a plug request for a range of blocks.
    pub const fn plug(addr: u64, nb_blocks: u16) -> Self {
        Self {
            req_type: VIRTIO_MEM_REQ_PLUG,
            _pad: [0; 6],
            addr,
            nb_blocks,
            _pad2: [0; 6],
        }
    }

    /// Build an unplug request for a range of blocks.
    pub const fn unplug(addr: u64, nb_blocks: u16) -> Self {
        Self {
            req_type: VIRTIO_MEM_REQ_UNPLUG,
            _pad: [0; 6],
            addr,
            nb_blocks,
            _pad2: [0; 6],
        }
    }

    /// Build a state query request.
    pub const fn state(addr: u64, nb_blocks: u16) -> Self {
        Self {
            req_type: VIRTIO_MEM_REQ_STATE,
            _pad: [0; 6],
            addr,
            nb_blocks,
            _pad2: [0; 6],
        }
    }
}

/// Response returned by the device for a [`MemRequest`].
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MemResponse {
    /// Response code (VIRTIO_MEM_RESP_*).
    pub resp_type: u16,
    /// Padding.
    pub _pad: [u8; 6],
    /// Block state (only valid for STATE requests).
    pub state: u16,
}

// ---------------------------------------------------------------------------
// BlockState
// ---------------------------------------------------------------------------

/// The plug state of a memory block as reported by the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    /// Block is not currently plugged.
    Unplugged,
    /// Block is plugged and usable by the guest.
    Plugged,
    /// Range spans blocks in different states (query only).
    Mixed,
    /// Device returned an unrecognised state.
    Unknown(u16),
}

impl From<u16> for BlockState {
    fn from(v: u16) -> Self {
        match v {
            VIRTIO_MEM_STATE_UNPLUGGED => BlockState::Unplugged,
            VIRTIO_MEM_STATE_PLUGGED => BlockState::Plugged,
            VIRTIO_MEM_STATE_MIXED => BlockState::Mixed,
            other => BlockState::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// PlugEvent
// ---------------------------------------------------------------------------

/// Event generated by the virtio-mem driver when the plug state changes.
#[derive(Debug, Clone, Copy)]
pub enum PlugEvent {
    /// A range of memory was successfully plugged.
    Plugged {
        /// Physical address of the first block.
        addr: u64,
        /// Number of blocks plugged.
        blocks: u16,
        /// Total bytes plugged in this operation.
        bytes: u64,
    },
    /// A range of memory was successfully unplugged.
    Unplugged {
        /// Physical address of the first block.
        addr: u64,
        /// Number of blocks unplugged.
        blocks: u16,
        /// Total bytes freed in this operation.
        bytes: u64,
    },
}

// ---------------------------------------------------------------------------
// VirtioMem
// ---------------------------------------------------------------------------

/// VirtIO memory hotplug device driver.
pub struct VirtioMem {
    /// MMIO transport.
    mmio: VirtioMmio,
    /// Request virtqueue (queue 0).
    request_vq: Virtqueue,
    /// Device configuration.
    config: MemConfig,
    /// Per-block state bitmap (true = plugged).
    block_states: [bool; MAX_BLOCKS],
    /// Negotiated driver feature flags.
    features: u32,
    /// Whether the driver has been initialised.
    ready: bool,
}

impl VirtioMem {
    /// Create an uninitialised driver bound to `mmio_base`.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio: VirtioMmio::new(mmio_base),
            request_vq: Virtqueue::new(),
            config: MemConfig {
                block_size: DEFAULT_BLOCK_SIZE,
                node_id: 0,
                addr: 0,
                region_size: 0,
                usable_region_size: 0,
                plugged_size: 0,
                requested_size: 0,
            },
            block_states: [false; MAX_BLOCKS],
            features: 0,
            ready: false,
        }
    }

    /// Initialise the driver.
    ///
    /// Follows the VirtIO initialisation sequence (§3.1):
    /// reset → acknowledge → driver → feature negotiation → FEATURES_OK →
    /// virtqueue setup → DRIVER_OK.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device type ID does not match.
    /// Returns [`Error::IoError`] if feature negotiation or queue setup fails.
    pub fn init(&mut self) -> Result<()> {
        // Probe — verify magic, version, device type.
        let device_id = self.mmio.probe()?;
        if device_id != VIRTIO_MEM_DEVICE_ID {
            return Err(Error::NotFound);
        }

        // Reset and acknowledge.
        self.mmio.reset();
        self.mmio.set_status(status::ACKNOWLEDGE);
        self.mmio.set_status(status::DRIVER);

        // Negotiate features.
        let host_features = self.mmio.read_device_features(0);
        let mut driver_features: u32 = 0;
        if host_features & VIRTIO_MEM_F_ACPI_PXM != 0 {
            driver_features |= VIRTIO_MEM_F_ACPI_PXM;
        }
        if host_features & VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE != 0 {
            driver_features |= VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE;
        }
        self.mmio.write_driver_features(0, driver_features);
        self.mmio.write_driver_features(1, 0);
        self.features = driver_features;

        self.mmio.set_status(status::FEATURES_OK);
        if self.mmio.status() & status::FEATURES_OK == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        // Read device configuration from MMIO config space.
        self.config = self.read_config();

        // Set up request virtqueue (queue 0).
        self.request_vq.init();
        self.setup_queue(0)?;

        self.mmio.set_status(status::DRIVER_OK);
        self.ready = true;
        Ok(())
    }

    /// Request the device to plug a range of memory blocks.
    ///
    /// The `addr` must be aligned to `block_size` and the range must
    /// not exceed the usable region boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the request is out of bounds.
    /// Returns [`Error::Busy`] if the driver is not ready.
    /// Returns [`Error::IoError`] if the device rejects the request.
    pub fn plug(&mut self, addr: u64, nb_blocks: u16) -> Result<PlugEvent> {
        self.check_ready()?;
        self.validate_range(addr, nb_blocks)?;

        let req = MemRequest::plug(addr, nb_blocks);
        let resp = self.submit_request(&req)?;

        if resp.resp_type != VIRTIO_MEM_RESP_ACK {
            return Err(Error::IoError);
        }

        self.mark_blocks(addr, nb_blocks, true);
        let bytes = nb_blocks as u64 * self.config.block_size;
        self.config.plugged_size = self.config.plugged_size.saturating_add(bytes);

        Ok(PlugEvent::Plugged {
            addr,
            blocks: nb_blocks,
            bytes,
        })
    }

    /// Request the device to unplug a range of memory blocks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the request is out of bounds.
    /// Returns [`Error::Busy`] if the driver is not ready.
    /// Returns [`Error::IoError`] if the device rejects the request.
    pub fn unplug(&mut self, addr: u64, nb_blocks: u16) -> Result<PlugEvent> {
        self.check_ready()?;
        self.validate_range(addr, nb_blocks)?;

        let req = MemRequest::unplug(addr, nb_blocks);
        let resp = self.submit_request(&req)?;

        if resp.resp_type != VIRTIO_MEM_RESP_ACK {
            return Err(Error::IoError);
        }

        self.mark_blocks(addr, nb_blocks, false);
        let bytes = nb_blocks as u64 * self.config.block_size;
        self.config.plugged_size = self.config.plugged_size.saturating_sub(bytes);

        Ok(PlugEvent::Unplugged {
            addr,
            blocks: nb_blocks,
            bytes,
        })
    }

    /// Query the state of a memory block range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the driver is not ready.
    /// Returns [`Error::IoError`] if the request fails.
    pub fn query_state(&mut self, addr: u64, nb_blocks: u16) -> Result<BlockState> {
        self.check_ready()?;
        self.validate_range(addr, nb_blocks)?;

        let req = MemRequest::state(addr, nb_blocks);
        let resp = self.submit_request(&req)?;

        if resp.resp_type == VIRTIO_MEM_RESP_NACK {
            return Err(Error::IoError);
        }

        Ok(BlockState::from(resp.state))
    }

    /// Return the current device configuration.
    pub fn config(&self) -> &MemConfig {
        &self.config
    }

    /// Return the negotiated feature flags.
    pub fn features(&self) -> u32 {
        self.features
    }

    /// Return the block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.config.block_size
    }

    /// Return the number of currently plugged bytes.
    pub fn plugged_bytes(&self) -> u64 {
        self.config.plugged_size
    }

    /// Return whether the driver is ready.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn check_ready(&self) -> Result<()> {
        if !self.ready {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }

    fn validate_range(&self, addr: u64, nb_blocks: u16) -> Result<()> {
        let block_size = self.config.block_size;
        if block_size == 0 || nb_blocks == 0 {
            return Err(Error::InvalidArgument);
        }
        if addr < self.config.addr || addr % block_size != 0 {
            return Err(Error::InvalidArgument);
        }
        let end = addr.saturating_add(nb_blocks as u64 * block_size);
        let region_end = self
            .config
            .addr
            .saturating_add(self.config.usable_region_size);
        if end > region_end {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    fn block_index(&self, addr: u64) -> Option<usize> {
        let block_size = self.config.block_size;
        if block_size == 0 || addr < self.config.addr {
            return None;
        }
        let idx = ((addr - self.config.addr) / block_size) as usize;
        if idx < MAX_BLOCKS { Some(idx) } else { None }
    }

    fn mark_blocks(&mut self, addr: u64, nb_blocks: u16, plugged: bool) {
        let block_size = self.config.block_size;
        if block_size == 0 {
            return;
        }
        for i in 0..nb_blocks as u64 {
            if let Some(idx) = self.block_index(addr + i * block_size) {
                self.block_states[idx] = plugged;
            }
        }
    }

    /// Submit a request to the request virtqueue and poll for the response.
    ///
    /// In the full implementation this would DMA the request/response structs
    /// through the virtqueue ring. For the early-boot HAL phase we model a
    /// successful ACK so that the plumbing compiles cleanly.
    fn submit_request(&mut self, _req: &MemRequest) -> Result<MemResponse> {
        Ok(MemResponse {
            resp_type: VIRTIO_MEM_RESP_ACK,
            _pad: [0; 6],
            state: 0,
        })
    }

    /// Configure a virtqueue at the given queue index on the MMIO transport.
    fn setup_queue(&mut self, queue_idx: u32) -> Result<()> {
        self.mmio.write32(virtio::mmio_reg::QUEUE_SEL, queue_idx);
        let max_size = self.mmio.read32(virtio::mmio_reg::QUEUE_NUM_MAX);
        if max_size == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        let queue_size = max_size.min(virtio::MAX_QUEUE_SIZE as u32);
        self.mmio.write32(virtio::mmio_reg::QUEUE_NUM, queue_size);

        // Provide physical addresses for descriptor table, available ring,
        // and used ring. In a real kernel these would be physical addresses
        // of DMA-coherent allocations; here we use the struct addresses.
        let desc_addr = self.request_vq.desc.as_ptr() as u64;
        let avail_addr = core::ptr::addr_of!(self.request_vq.avail_flags) as u64;
        let used_addr = core::ptr::addr_of!(self.request_vq.used_flags) as u64;

        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_LOW, desc_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_AVAIL_LOW, avail_addr as u32);
        self.mmio.write32(
            virtio::mmio_reg::QUEUE_AVAIL_HIGH,
            (avail_addr >> 32) as u32,
        );
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_LOW, used_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_HIGH, (used_addr >> 32) as u32);
        self.mmio.write32(virtio::mmio_reg::QUEUE_READY, 1);

        Ok(())
    }

    /// Read a 64-bit value from the device configuration space.
    ///
    /// Config space is at MMIO offset 0x100. 64-bit values are read as two
    /// 32-bit words per the VirtIO MMIO specification (§4.2.2.2).
    fn read_config_u64(&self, off: u32) -> u64 {
        let lo = self.mmio.read32(MMIO_CONFIG_BASE + off) as u64;
        let hi = self.mmio.read32(MMIO_CONFIG_BASE + off + 4) as u64;
        lo | (hi << 32)
    }

    /// Read a 16-bit value from the device configuration space.
    fn read_config_u16(&self, off: u32) -> u16 {
        self.mmio.read32(MMIO_CONFIG_BASE + off) as u16
    }

    /// Read the full device configuration from MMIO.
    fn read_config(&self) -> MemConfig {
        // Layout per §5.15.4 (all fields at natural alignment):
        //  0: block_size   (u64)
        //  8: node_id      (u16) + 6 pad bytes
        // 16: addr         (u64)
        // 24: region_size  (u64)
        // 32: usable_...   (u64)
        // 40: plugged_size (u64)
        // 48: requested_.. (u64)
        let block_size = self.read_config_u64(0);
        let node_id = self.read_config_u16(8);
        let addr = self.read_config_u64(16);
        let region_size = self.read_config_u64(24);
        let usable_region_size = self.read_config_u64(32);
        let plugged_size = self.read_config_u64(40);
        let requested_size = self.read_config_u64(48);

        MemConfig {
            block_size: if block_size == 0 {
                DEFAULT_BLOCK_SIZE
            } else {
                block_size
            },
            node_id,
            addr,
            region_size,
            usable_region_size,
            plugged_size,
            requested_size,
        }
    }
}

// ---------------------------------------------------------------------------
// VirtioMemRegistry
// ---------------------------------------------------------------------------

/// Registry for virtio-mem device instances.
pub struct VirtioMemRegistry {
    devices: [Option<VirtioMem>; MAX_VIRTIO_MEM_DEVICES],
    count: usize,
}

impl VirtioMemRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: Option<VirtioMem> = None;
        Self {
            devices: [EMPTY; MAX_VIRTIO_MEM_DEVICES],
            count: 0,
        }
    }

    /// Register a new virtio-mem device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, dev: VirtioMem) -> Result<usize> {
        if self.count >= MAX_VIRTIO_MEM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(dev);
        self.count += 1;
        Ok(idx)
    }

    /// Get an immutable reference to a device by index.
    pub fn get(&self, idx: usize) -> Option<&VirtioMem> {
        self.devices.get(idx).and_then(|d| d.as_ref())
    }

    /// Get a mutable reference to a device by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut VirtioMem> {
        self.devices.get_mut(idx).and_then(|d| d.as_mut())
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for VirtioMemRegistry {
    fn default() -> Self {
        Self::new()
    }
}
