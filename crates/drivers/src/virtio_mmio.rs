// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO MMIO transport layer.
//!
//! Implements the VirtIO over MMIO transport as defined in VirtIO 1.2
//! specification Section 4.2. The MMIO transport exposes device registers
//! at a memory-mapped base address; discovery is typically done via
//! device-tree or ACPI rather than PCI enumeration.
//!
//! # Register Map (offsets 0x000–0x0FC)
//!
//! | Offset | Register           | R/W |
//! |--------|--------------------|-----|
//! | 0x000  | MagicValue         | R   |
//! | 0x004  | Version            | R   |
//! | 0x008  | DeviceID           | R   |
//! | 0x00C  | VendorID           | R   |
//! | 0x010  | DeviceFeatures     | R   |
//! | 0x014  | DeviceFeaturesSel  | W   |
//! | 0x020  | DriverFeatures     | W   |
//! | 0x024  | DriverFeaturesSel  | W   |
//! | 0x030  | QueueSel           | W   |
//! | 0x034  | QueueNumMax        | R   |
//! | 0x038  | QueueNum           | W   |
//! | 0x044  | QueueReady         | R/W |
//! | 0x050  | QueueNotify        | W   |
//! | 0x060  | InterruptStatus    | R   |
//! | 0x064  | InterruptACK       | W   |
//! | 0x070  | Status             | R/W |
//! | 0x080  | QueueDescLow/High  | W   |
//! | 0x090  | QueueDriverLow/Hi  | W   |
//! | 0x0A0  | QueueDeviceLow/Hi  | W   |
//!
//! Reference: VirtIO 1.2 Spec, Section 4.2.

use oncrix_lib::{Error, Result};

// ── Magic and version ─────────────────────────────────────────────────────────

/// Magic value "virt" — little-endian 0x74726976.
const VIRTIO_MMIO_MAGIC: u32 = 0x74726976;

/// VirtIO MMIO version 2 (modern).
const VIRTIO_MMIO_VERSION2: u32 = 2;

// ── Device status bits ────────────────────────────────────────────────────────

/// Status bit: device acknowledged.
pub const STATUS_ACKNOWLEDGE: u32 = 1;

/// Status bit: driver found.
pub const STATUS_DRIVER: u32 = 2;

/// Status bit: driver features OK.
pub const STATUS_FEATURES_OK: u32 = 8;

/// Status bit: driver ready.
pub const STATUS_DRIVER_OK: u32 = 4;

/// Status bit: device needs reset.
pub const STATUS_DEVICE_NEEDS_RESET: u32 = 64;

/// Status bit: fatal failure.
pub const STATUS_FAILED: u32 = 128;

// ── Feature bits ─────────────────────────────────────────────────────────────

/// Feature bit: version 1 (mandatory for v2 transport).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// ── Interrupt bits ────────────────────────────────────────────────────────────

/// Interrupt cause: used buffer notification.
pub const INTR_VRING: u32 = 1 << 0;

/// Interrupt cause: device configuration changed.
pub const INTR_CONFIG: u32 = 1 << 1;

// ── Register offsets ─────────────────────────────────────────────────────────

const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_VENDOR_ID: u64 = 0x00C;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_INTERRUPT_STATUS: u64 = 0x060;
const REG_INTERRUPT_ACK: u64 = 0x064;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_DESC_HIGH: u64 = 0x084;
const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
const REG_QUEUE_DEVICE_LOW: u64 = 0x0A0;
const REG_QUEUE_DEVICE_HIGH: u64 = 0x0A4;
const REG_CONFIG_GENERATION: u64 = 0x0FC;
const REG_CONFIG: u64 = 0x100;

// ── Max virtqueue count ───────────────────────────────────────────────────────

/// Maximum number of virtqueues tracked per device.
pub const MAX_QUEUES: usize = 8;

// ── MMIO helpers ─────────────────────────────────────────────────────────────

/// Read a 32-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid mapped MMIO address, naturally aligned.
#[inline]
unsafe fn read32(addr: u64) -> u32 {
    // SAFETY: caller guarantees valid MMIO; volatile prevents reordering.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid mapped MMIO address, naturally aligned.
#[inline]
unsafe fn write32(addr: u64, val: u32) {
    // SAFETY: caller guarantees valid MMIO; volatile prevents reordering.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ── VirtqueuePhys ─────────────────────────────────────────────────────────────

/// Physical memory addresses for a single virtqueue.
#[derive(Clone, Copy, Default)]
pub struct VirtqueuePhys {
    /// Physical address of the descriptor table.
    pub desc_phys: u64,
    /// Physical address of the driver ring (avail).
    pub driver_phys: u64,
    /// Physical address of the device ring (used).
    pub device_phys: u64,
    /// Number of descriptors (power of two).
    pub num: u16,
}

// ── VirtioMmioDevice ─────────────────────────────────────────────────────────

/// VirtIO MMIO device handle.
pub struct VirtioMmioDevice {
    /// MMIO base address.
    base: u64,
    /// Device ID read from hardware.
    device_id: u32,
    /// Negotiated feature bits.
    features: u64,
    /// Configured queue count.
    queue_count: usize,
}

impl VirtioMmioDevice {
    /// Create a device handle for the given MMIO base.
    ///
    /// Does NOT access hardware; call [`init`](Self::init) to begin setup.
    pub fn new(base: u64) -> Self {
        Self {
            base,
            device_id: 0,
            features: 0,
            queue_count: 0,
        }
    }

    /// Initialize the device following the VirtIO 1.2 initialization sequence.
    ///
    /// Steps: verify magic/version, read device ID, ACKNOWLEDGE,
    /// DRIVER, feature negotiation, FEATURES_OK.
    ///
    /// `driver_features` is the set of feature bits the driver wants.
    ///
    /// # Safety
    /// `self.base` must be a valid, mapped VirtIO MMIO region.
    pub unsafe fn init(&mut self, driver_features: u64) -> Result<()> {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe {
            let magic = read32(self.base + REG_MAGIC);
            if magic != VIRTIO_MMIO_MAGIC {
                return Err(Error::NotFound);
            }

            let version = read32(self.base + REG_VERSION);
            if version != VIRTIO_MMIO_VERSION2 {
                return Err(Error::NotImplemented);
            }

            self.device_id = read32(self.base + REG_DEVICE_ID);
            if self.device_id == 0 {
                return Err(Error::NotFound);
            }

            // Reset device.
            write32(self.base + REG_STATUS, 0);

            // ACKNOWLEDGE + DRIVER.
            write32(self.base + REG_STATUS, STATUS_ACKNOWLEDGE);
            write32(self.base + REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

            // Negotiate features (low 32 bits).
            write32(self.base + REG_DEVICE_FEATURES_SEL, 0);
            let dev_feat_lo = read32(self.base + REG_DEVICE_FEATURES) as u64;

            // Negotiate features (high 32 bits).
            write32(self.base + REG_DEVICE_FEATURES_SEL, 1);
            let dev_feat_hi = (read32(self.base + REG_DEVICE_FEATURES) as u64) << 32;

            let device_features = dev_feat_lo | dev_feat_hi;
            let negotiated = (driver_features | VIRTIO_F_VERSION_1) & device_features;
            self.features = negotiated;

            // Write negotiated features.
            write32(self.base + REG_DRIVER_FEATURES_SEL, 0);
            write32(self.base + REG_DRIVER_FEATURES, negotiated as u32);
            write32(self.base + REG_DRIVER_FEATURES_SEL, 1);
            write32(self.base + REG_DRIVER_FEATURES, (negotiated >> 32) as u32);

            // FEATURES_OK.
            write32(
                self.base + REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            );

            let status = read32(self.base + REG_STATUS);
            if status & STATUS_FEATURES_OK == 0 {
                write32(self.base + REG_STATUS, STATUS_FAILED);
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }

    /// Configure a virtqueue by programming its physical memory addresses.
    ///
    /// Must be called after [`init`](Self::init) and before
    /// [`set_driver_ok`](Self::set_driver_ok).
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn setup_queue(&mut self, index: u16, phys: &VirtqueuePhys) -> Result<()> {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe {
            write32(self.base + REG_QUEUE_SEL, u32::from(index));

            let max = read32(self.base + REG_QUEUE_NUM_MAX);
            if max == 0 {
                return Err(Error::NotFound);
            }
            if u32::from(phys.num) > max {
                return Err(Error::InvalidArgument);
            }

            write32(self.base + REG_QUEUE_NUM, u32::from(phys.num));

            write32(self.base + REG_QUEUE_DESC_LOW, phys.desc_phys as u32);
            write32(
                self.base + REG_QUEUE_DESC_HIGH,
                (phys.desc_phys >> 32) as u32,
            );

            write32(self.base + REG_QUEUE_DRIVER_LOW, phys.driver_phys as u32);
            write32(
                self.base + REG_QUEUE_DRIVER_HIGH,
                (phys.driver_phys >> 32) as u32,
            );

            write32(self.base + REG_QUEUE_DEVICE_LOW, phys.device_phys as u32);
            write32(
                self.base + REG_QUEUE_DEVICE_HIGH,
                (phys.device_phys >> 32) as u32,
            );

            write32(self.base + REG_QUEUE_READY, 1);
        }
        self.queue_count = self.queue_count.max(usize::from(index) + 1);
        Ok(())
    }

    /// Complete initialization by setting DRIVER_OK status.
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn set_driver_ok(&self) {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe {
            let status = read32(self.base + REG_STATUS);
            write32(self.base + REG_STATUS, status | STATUS_DRIVER_OK);
        }
    }

    /// Notify the device that queue `index` has new entries.
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn notify_queue(&self, index: u16) {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe { write32(self.base + REG_QUEUE_NOTIFY, u32::from(index)) }
    }

    /// Read and clear the interrupt status register.
    ///
    /// Returns the cause bits: [`INTR_VRING`] and/or [`INTR_CONFIG`].
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn handle_interrupt(&self) -> u32 {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe {
            let status = read32(self.base + REG_INTERRUPT_STATUS);
            write32(self.base + REG_INTERRUPT_ACK, status);
            status
        }
    }

    /// Read a 32-bit device-specific configuration register.
    ///
    /// `cfg_offset` is relative to the device config space base (0x100).
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn read_config32(&self, cfg_offset: u64) -> u32 {
        // SAFETY: caller guarantees offset is within device config space.
        unsafe { read32(self.base + REG_CONFIG + cfg_offset) }
    }

    /// Write a 32-bit device-specific configuration register.
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn write_config32(&self, cfg_offset: u64, val: u32) {
        // SAFETY: caller guarantees offset is within device config space.
        unsafe { write32(self.base + REG_CONFIG + cfg_offset, val) }
    }

    /// Configuration generation counter (detect concurrent config updates).
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn config_generation(&self) -> u32 {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe { read32(self.base + REG_CONFIG_GENERATION) }
    }

    /// Maximum queue size for a given queue index.
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn queue_num_max(&self, index: u16) -> u32 {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe {
            write32(self.base + REG_QUEUE_SEL, u32::from(index));
            read32(self.base + REG_QUEUE_NUM_MAX)
        }
    }

    /// Check whether the device is requesting a reset.
    ///
    /// # Safety
    /// `self.base` must be a valid VirtIO MMIO region.
    pub unsafe fn needs_reset(&self) -> bool {
        // SAFETY: self.base is a valid VirtIO MMIO region.
        unsafe { read32(self.base + REG_STATUS) & STATUS_DEVICE_NEEDS_RESET != 0 }
    }

    /// Device ID from hardware.
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// Negotiated feature bits.
    pub fn features(&self) -> u64 {
        self.features
    }

    /// Number of queues configured so far.
    pub fn queue_count(&self) -> usize {
        self.queue_count
    }

    /// MMIO base address.
    pub fn base_address(&self) -> u64 {
        self.base
    }
}

// ── VirtioMmioRegistry ────────────────────────────────────────────────────────

/// Registry of discovered VirtIO MMIO devices (up to 8).
pub struct VirtioMmioRegistry {
    devices: [Option<VirtioMmioDevice>; MAX_QUEUES],
    count: usize,
}

impl VirtioMmioRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_QUEUES],
            count: 0,
        }
    }

    /// Register a device. Returns the assigned index.
    pub fn register(&mut self, dev: VirtioMmioDevice) -> Result<usize> {
        if self.count >= MAX_QUEUES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(dev);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a registered device.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut VirtioMmioDevice> {
        self.devices.get_mut(index)?.as_mut()
    }

    /// Total registered device count.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
