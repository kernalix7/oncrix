// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO PCI transport layer.
//!
//! Implements the VirtIO 1.2 PCI transport, which provides device discovery,
//! capability negotiation, and virtqueue setup using PCI configuration space
//! BAR-mapped MMIO registers.
//!
//! # PCI Capability chain
//! The transport searches the PCI capability list for capabilities with
//! `vendor_id = 0x09` (VirtIO vendor-specific). Each such capability describes
//! a region: Common Config, Notify, ISR, Device Config, or PCI Config Access.
//!
//! # Virtqueue setup
//! Each queue is described by size, descriptor table, driver ring, and device
//! ring addresses written to the Common Config region. The queue is then enabled.
//!
//! Reference: Virtual I/O Device (VIRTIO) Specification 1.2, Section 4.1.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// PCI VirtIO Vendor Capability ID
// ---------------------------------------------------------------------------

/// PCI capability ID: VirtIO vendor-specific capability.
pub const PCI_CAP_VIRTIO: u8 = 0x09;

// ---------------------------------------------------------------------------
// VirtIO Capability Types (cfg_type field)
// ---------------------------------------------------------------------------

/// Capability type: Common configuration.
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Capability type: Notifications.
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// Capability type: ISR status.
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Capability type: Device-specific configuration.
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
/// Capability type: PCI configuration access.
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

// ---------------------------------------------------------------------------
// Device Status Bits
// ---------------------------------------------------------------------------

/// Device status: ACKNOWLEDGE — OS has found the device.
pub const DEVICE_STATUS_ACKNOWLEDGE: u8 = 1;
/// Device status: DRIVER — OS knows how to drive the device.
pub const DEVICE_STATUS_DRIVER: u8 = 2;
/// Device status: DRIVER_OK — Driver is set up and ready.
pub const DEVICE_STATUS_DRIVER_OK: u8 = 4;
/// Device status: FEATURES_OK — Feature negotiation is complete.
pub const DEVICE_STATUS_FEATURES_OK: u8 = 8;
/// Device status: DEVICE_NEEDS_RESET — Device has experienced unrecoverable error.
pub const DEVICE_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
/// Device status: FAILED — Driver has given up on the device.
pub const DEVICE_STATUS_FAILED: u8 = 128;

// ---------------------------------------------------------------------------
// VirtIO Feature Bits
// ---------------------------------------------------------------------------

/// VirtIO feature bit: Version 1 compliance (must be negotiated).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// VirtIO feature bit: Ring indirect descriptors.
pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
/// VirtIO feature bit: Ring event index.
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;

// ---------------------------------------------------------------------------
// Common Config Register Layout (offsets within the Common Config BAR region)
// ---------------------------------------------------------------------------

/// Offset: device_feature_select — selects which 32-bit word of device features to read.
pub const COMMON_DEVICE_FEATURE_SELECT: u32 = 0x00;
/// Offset: device_feature — read-only device features (selected by device_feature_select).
pub const COMMON_DEVICE_FEATURE: u32 = 0x04;
/// Offset: driver_feature_select — selects which 32-bit word to write driver features.
pub const COMMON_DRIVER_FEATURE_SELECT: u32 = 0x08;
/// Offset: driver_feature — accepted driver features.
pub const COMMON_DRIVER_FEATURE: u32 = 0x0C;
/// Offset: config_msix_vector — MSI-X vector for config changes.
pub const COMMON_CONFIG_MSIX_VECTOR: u32 = 0x10;
/// Offset: num_queues — number of supported virtqueues (read-only).
pub const COMMON_NUM_QUEUES: u32 = 0x12;
/// Offset: device_status — driver/device status byte.
pub const COMMON_DEVICE_STATUS: u32 = 0x14;
/// Offset: config_generation — config change counter.
pub const COMMON_CONFIG_GENERATION: u32 = 0x15;
/// Offset: queue_select — selects the virtqueue for subsequent queue operations.
pub const COMMON_QUEUE_SELECT: u32 = 0x16;
/// Offset: queue_size — size of the selected virtqueue.
pub const COMMON_QUEUE_SIZE: u32 = 0x18;
/// Offset: queue_msix_vector — MSI-X vector for this queue.
pub const COMMON_QUEUE_MSIX_VECTOR: u32 = 0x1A;
/// Offset: queue_enable — set to 1 to enable the selected queue.
pub const COMMON_QUEUE_ENABLE: u32 = 0x1C;
/// Offset: queue_notify_off — per-queue notification offset multiplier.
pub const COMMON_QUEUE_NOTIFY_OFF: u32 = 0x1E;
/// Offset: queue_desc (64-bit) — physical address of the descriptor table.
pub const COMMON_QUEUE_DESC: u32 = 0x20;
/// Offset: queue_driver (64-bit) — physical address of the available (driver) ring.
pub const COMMON_QUEUE_DRIVER: u32 = 0x28;
/// Offset: queue_device (64-bit) — physical address of the used (device) ring.
pub const COMMON_QUEUE_DEVICE: u32 = 0x30;

// ---------------------------------------------------------------------------
// Virtqueue Descriptor Flags
// ---------------------------------------------------------------------------

/// Virtqueue descriptor flag: buffer is device-write-only.
pub const VRING_DESC_F_WRITE: u16 = 2;
/// Virtqueue descriptor flag: buffer is followed by another descriptor (chained).
pub const VRING_DESC_F_NEXT: u16 = 1;
/// Virtqueue descriptor flag: indirect descriptor table.
pub const VRING_DESC_F_INDIRECT: u16 = 4;

// ---------------------------------------------------------------------------
// Virtqueue Maximum Sizes
// ---------------------------------------------------------------------------

/// Maximum supported virtqueue size (number of descriptors).
pub const VIRTQ_MAX_SIZE: u16 = 1024;

// ---------------------------------------------------------------------------
// Virtqueue Descriptor
// ---------------------------------------------------------------------------

/// Virtqueue split-ring descriptor entry.
///
/// `#[repr(C)]` required for DMA — must match the device ABI exactly.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (VRING_DESC_F_*).
    pub flags: u16,
    /// Index of the next descriptor (if VRING_DESC_F_NEXT is set).
    pub next: u16,
}

// ---------------------------------------------------------------------------
// Available (Driver) Ring
// ---------------------------------------------------------------------------

/// Virtqueue available ring header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqAvail {
    /// Flags (bit 1 = VRING_AVAIL_F_NO_INTERRUPT).
    pub flags: u16,
    /// Index into the ring where the driver will place the next descriptor head.
    pub idx: u16,
}

// ---------------------------------------------------------------------------
// Used (Device) Ring Entry
// ---------------------------------------------------------------------------

/// One entry in the virtqueue used ring.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqUsedElem {
    /// Descriptor chain head index.
    pub id: u32,
    /// Total bytes written by the device into the chain.
    pub len: u32,
}

/// Virtqueue used ring header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqUsed {
    /// Flags (bit 1 = VRING_USED_F_NO_NOTIFY).
    pub flags: u16,
    /// Index into the ring of the next entry to be filled by the device.
    pub idx: u16,
}

// ---------------------------------------------------------------------------
// PCI Virtqueue (VirtqPci)
// ---------------------------------------------------------------------------

/// Describes one VirtIO PCI queue setup (addresses + size).
#[derive(Clone, Copy, Debug)]
pub struct VirtqPci {
    /// Physical address of the descriptor table.
    pub desc_phys: u64,
    /// Physical address of the available ring.
    pub avail_phys: u64,
    /// Physical address of the used ring.
    pub used_phys: u64,
    /// Number of descriptors in this queue.
    pub size: u16,
    /// Notification offset for this queue (queue_notify_off * notify_off_multiplier).
    pub notify_off: u32,
}

impl VirtqPci {
    /// Creates a new `VirtqPci` descriptor.
    pub const fn new(
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
        size: u16,
        notify_off: u32,
    ) -> Self {
        Self {
            desc_phys,
            avail_phys,
            used_phys,
            size,
            notify_off,
        }
    }
}

// ---------------------------------------------------------------------------
// Common Config MMIO Accessor
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from the Common Config MMIO region.
///
/// # Safety
/// `base` must be the virtual address of a mapped VirtIO Common Config region,
/// and `offset` must be a valid field offset within it.
#[inline]
unsafe fn read32(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    // SAFETY: Caller guarantees a valid mapped MMIO address.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Reads a 16-bit value from the Common Config MMIO region.
///
/// # Safety
/// See `read32`.
#[inline]
unsafe fn read16(base: u64, offset: u32) -> u16 {
    let ptr = (base + offset as u64) as *const u16;
    // SAFETY: See read32.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Reads an 8-bit value.
///
/// # Safety
/// See `read32`.
#[inline]
unsafe fn read8(base: u64, offset: u32) -> u8 {
    let ptr = (base + offset as u64) as *const u8;
    // SAFETY: See read32.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Writes a 32-bit value to the Common Config MMIO region.
///
/// # Safety
/// See `read32`.
#[inline]
unsafe fn write32(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees valid mapped MMIO address.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Writes a 16-bit value.
///
/// # Safety
/// See `write32`.
#[inline]
unsafe fn write16(base: u64, offset: u32, val: u16) {
    let ptr = (base + offset as u64) as *mut u16;
    // SAFETY: See write32.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Writes an 8-bit value.
///
/// # Safety
/// See `write32`.
#[inline]
unsafe fn write8(base: u64, offset: u32, val: u8) {
    let ptr = (base + offset as u64) as *mut u8;
    // SAFETY: See write32.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// ---------------------------------------------------------------------------
// VirtIO PCI Device
// ---------------------------------------------------------------------------

/// VirtIO PCI device transport.
///
/// Wraps the Common Config and Notify MMIO regions and provides a
/// high-level interface for feature negotiation, queue setup, and status.
pub struct VirtioPciDevice {
    /// Virtual base address of the Common Config region.
    common_cfg: u64,
    /// Virtual base address of the Notify region.
    notify_base: u64,
    /// Per-queue notify offset multiplier (from Notify capability).
    notify_multiplier: u32,
}

impl VirtioPciDevice {
    /// Creates a new `VirtioPciDevice`.
    ///
    /// # Parameters
    /// - `common_cfg`: Virtual address of the mapped Common Config BAR region.
    /// - `notify_base`: Virtual address of the Notify region.
    /// - `notify_multiplier`: The `notify_off_multiplier` from the Notify capability.
    pub const fn new(common_cfg: u64, notify_base: u64, notify_multiplier: u32) -> Self {
        Self {
            common_cfg,
            notify_base,
            notify_multiplier,
        }
    }

    /// Resets the device by writing 0 to device_status.
    ///
    /// # Safety
    /// Caller must ensure no outstanding DMA is in flight before reset.
    pub unsafe fn reset(&self) {
        // SAFETY: Writing 0 to device_status triggers device reset.
        unsafe { write8(self.common_cfg, COMMON_DEVICE_STATUS, 0) }
    }

    /// Reads the current device status byte.
    ///
    /// # Safety
    /// Caller must ensure the Common Config region is accessible.
    pub unsafe fn device_status(&self) -> u8 {
        // SAFETY: device_status is a valid readable field.
        unsafe { read8(self.common_cfg, COMMON_DEVICE_STATUS) }
    }

    /// Writes a new device status byte.
    ///
    /// # Safety
    /// Status transitions must follow the VirtIO specification (§3.1.1).
    pub unsafe fn set_device_status(&self, status: u8) {
        // SAFETY: Writing device_status to acknowledge and enable the device.
        unsafe { write8(self.common_cfg, COMMON_DEVICE_STATUS, status) }
    }

    /// Reads a 32-bit word of device features.
    ///
    /// # Parameters
    /// - `select`: 0 for bits 31:0, 1 for bits 63:32.
    ///
    /// # Safety
    /// Common Config must be accessible.
    pub unsafe fn device_features(&self, select: u32) -> u32 {
        // SAFETY: Feature select + feature read per VirtIO spec §4.1.4.3.
        unsafe {
            write32(self.common_cfg, COMMON_DEVICE_FEATURE_SELECT, select);
            read32(self.common_cfg, COMMON_DEVICE_FEATURE)
        }
    }

    /// Reads the full 64-bit device features.
    ///
    /// # Safety
    /// See `device_features`.
    pub unsafe fn device_features64(&self) -> u64 {
        // SAFETY: Two 32-bit reads to get full feature bitmap.
        unsafe {
            let lo = self.device_features(0) as u64;
            let hi = self.device_features(1) as u64;
            (hi << 32) | lo
        }
    }

    /// Writes driver-accepted features.
    ///
    /// # Parameters
    /// - `select`: 0 for bits 31:0, 1 for bits 63:32.
    /// - `features`: Feature bits to accept for the selected word.
    ///
    /// # Safety
    /// Must be called before setting FEATURES_OK in device_status.
    pub unsafe fn set_driver_features(&self, select: u32, features: u32) {
        // SAFETY: Writing driver features before FEATURES_OK.
        unsafe {
            write32(self.common_cfg, COMMON_DRIVER_FEATURE_SELECT, select);
            write32(self.common_cfg, COMMON_DRIVER_FEATURE, features);
        }
    }

    /// Writes the full 64-bit driver features.
    ///
    /// # Safety
    /// See `set_driver_features`.
    pub unsafe fn set_driver_features64(&self, features: u64) {
        // SAFETY: Two 32-bit writes for full feature bitmap.
        unsafe {
            self.set_driver_features(0, features as u32);
            self.set_driver_features(1, (features >> 32) as u32);
        }
    }

    /// Returns the number of supported virtqueues.
    ///
    /// # Safety
    /// See `device_features`.
    pub unsafe fn num_queues(&self) -> u16 {
        // SAFETY: Reading num_queues from Common Config.
        unsafe { read16(self.common_cfg, COMMON_NUM_QUEUES) }
    }

    /// Sets up a virtqueue.
    ///
    /// Selects the queue, configures its size and DMA ring addresses,
    /// then enables it.
    ///
    /// # Parameters
    /// - `queue_index`: Queue number.
    /// - `vq`: VirtqPci descriptor with physical addresses and size.
    ///
    /// # Safety
    /// All physical addresses in `vq` must be valid DMA-accessible memory.
    pub unsafe fn setup_queue(&self, queue_index: u16, vq: &VirtqPci) -> Result<()> {
        // SAFETY: Queue setup sequence per VirtIO spec §4.1.5.1.3.
        unsafe {
            // Select queue
            write16(self.common_cfg, COMMON_QUEUE_SELECT, queue_index);

            // Read back max size, clamp to our size
            let max_size = read16(self.common_cfg, COMMON_QUEUE_SIZE);
            if vq.size == 0 || vq.size > max_size {
                return Err(Error::InvalidArgument);
            }
            write16(self.common_cfg, COMMON_QUEUE_SIZE, vq.size);

            // Write physical addresses (64-bit as two 32-bit writes)
            write32(self.common_cfg, COMMON_QUEUE_DESC, vq.desc_phys as u32);
            write32(
                self.common_cfg,
                COMMON_QUEUE_DESC + 4,
                (vq.desc_phys >> 32) as u32,
            );
            write32(self.common_cfg, COMMON_QUEUE_DRIVER, vq.avail_phys as u32);
            write32(
                self.common_cfg,
                COMMON_QUEUE_DRIVER + 4,
                (vq.avail_phys >> 32) as u32,
            );
            write32(self.common_cfg, COMMON_QUEUE_DEVICE, vq.used_phys as u32);
            write32(
                self.common_cfg,
                COMMON_QUEUE_DEVICE + 4,
                (vq.used_phys >> 32) as u32,
            );

            // Enable the queue
            write16(self.common_cfg, COMMON_QUEUE_ENABLE, 1);
        }
        Ok(())
    }

    /// Sends a queue notification (doorbell) to the device.
    ///
    /// # Parameters
    /// - `queue_index`: Queue number.
    /// - `notify_off`: The queue's `queue_notify_off` value.
    ///
    /// # Safety
    /// `notify_base` must be a valid Notify region mapping.
    pub unsafe fn notify_queue(&self, queue_index: u16, notify_off: u32) {
        // SAFETY: Doorbell write triggers device to process new descriptors.
        unsafe {
            let offset = notify_off * self.notify_multiplier;
            let ptr = (self.notify_base + offset as u64) as *mut u16;
            core::ptr::write_volatile(ptr, queue_index);
        }
    }

    /// Reads the ISR status register.
    ///
    /// Bit 0 = queue interrupt, Bit 1 = device config change interrupt.
    /// Reading this register clears the ISR.
    ///
    /// # Parameters
    /// - `isr_base`: Virtual address of the mapped ISR BAR region.
    ///
    /// # Safety
    /// `isr_base` must be a valid ISR region mapping.
    pub unsafe fn read_isr(isr_base: u64) -> u8 {
        // SAFETY: Reading ISR is a standard VirtIO operation; clears interrupt.
        unsafe {
            let ptr = isr_base as *const u8;
            core::ptr::read_volatile(ptr)
        }
    }

    /// Configures MSI-X vectors for the device config and a queue.
    ///
    /// # Parameters
    /// - `config_vec`: MSI-X vector for device config changes (0xFFFF = none).
    /// - `queue_index`: Queue to configure.
    /// - `queue_vec`: MSI-X vector for this queue (0xFFFF = none).
    ///
    /// # Safety
    /// MSI-X vectors must have been allocated and mapped before calling.
    pub unsafe fn configure_msix(&self, config_vec: u16, queue_index: u16, queue_vec: u16) {
        // SAFETY: Writing MSI-X vectors to Common Config fields.
        unsafe {
            write16(self.common_cfg, COMMON_CONFIG_MSIX_VECTOR, config_vec);
            write16(self.common_cfg, COMMON_QUEUE_SELECT, queue_index);
            write16(self.common_cfg, COMMON_QUEUE_MSIX_VECTOR, queue_vec);
        }
    }
}
