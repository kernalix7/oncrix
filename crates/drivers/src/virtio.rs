// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO transport and common structures.
//!
//! Implements the VirtIO 1.1 MMIO transport layer, including virtqueue
//! (split ring) management. This module provides the shared foundation
//! for all VirtIO device drivers (block, network, console, etc.).
//!
//! Reference: VirtIO Specification v1.1, §2 (Basic Facilities) and
//! §4.2 (Virtio Over MMIO).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// VirtIO MMIO register offsets (§4.2.2)
// ---------------------------------------------------------------------------

/// MMIO register offsets for VirtIO devices.
pub mod mmio_reg {
    /// Magic value ("virt").
    pub const MAGIC: u32 = 0x000;
    /// Device version (2 = virtio 1.1).
    pub const VERSION: u32 = 0x004;
    /// Device type (1 = net, 2 = blk, …).
    pub const DEVICE_ID: u32 = 0x008;
    /// Vendor ID.
    pub const VENDOR_ID: u32 = 0x00C;
    /// Device feature bits (read, select via `DEVICE_FEATURES_SEL`).
    pub const DEVICE_FEATURES: u32 = 0x010;
    /// Device feature word selector.
    pub const DEVICE_FEATURES_SEL: u32 = 0x014;
    /// Driver feature bits (write, select via `DRIVER_FEATURES_SEL`).
    pub const DRIVER_FEATURES: u32 = 0x020;
    /// Driver feature word selector.
    pub const DRIVER_FEATURES_SEL: u32 = 0x024;
    /// Virtqueue selector.
    pub const QUEUE_SEL: u32 = 0x030;
    /// Maximum virtqueue size.
    pub const QUEUE_NUM_MAX: u32 = 0x034;
    /// Virtqueue size (driver writes).
    pub const QUEUE_NUM: u32 = 0x038;
    /// Virtqueue ready flag.
    pub const QUEUE_READY: u32 = 0x044;
    /// Queue notify (write queue index).
    pub const QUEUE_NOTIFY: u32 = 0x050;
    /// Interrupt status.
    pub const INTERRUPT_STATUS: u32 = 0x060;
    /// Interrupt acknowledge.
    pub const INTERRUPT_ACK: u32 = 0x064;
    /// Device status register.
    pub const STATUS: u32 = 0x070;
    /// Low 32 bits of descriptor table physical address.
    pub const QUEUE_DESC_LOW: u32 = 0x080;
    /// High 32 bits of descriptor table physical address.
    pub const QUEUE_DESC_HIGH: u32 = 0x084;
    /// Low 32 bits of available ring physical address.
    pub const QUEUE_AVAIL_LOW: u32 = 0x090;
    /// High 32 bits of available ring physical address.
    pub const QUEUE_AVAIL_HIGH: u32 = 0x094;
    /// Low 32 bits of used ring physical address.
    pub const QUEUE_USED_LOW: u32 = 0x0A0;
    /// High 32 bits of used ring physical address.
    pub const QUEUE_USED_HIGH: u32 = 0x0A4;
}

/// Expected MMIO magic value (little-endian "virt").
pub const VIRTIO_MAGIC: u32 = 0x7472_6976;

// ---------------------------------------------------------------------------
// Device status bits (§2.1)
// ---------------------------------------------------------------------------

/// Device status flags.
pub mod status {
    /// Driver has acknowledged the device.
    pub const ACKNOWLEDGE: u32 = 1;
    /// Driver knows how to drive the device.
    pub const DRIVER: u32 = 2;
    /// Feature negotiation complete.
    pub const FEATURES_OK: u32 = 8;
    /// Driver setup complete, device is live.
    pub const DRIVER_OK: u32 = 4;
    /// Something went wrong; device is broken.
    pub const FAILED: u32 = 128;
}

// ---------------------------------------------------------------------------
// Virtqueue (split ring) — §2.6
// ---------------------------------------------------------------------------

/// Maximum queue size we support.
pub const MAX_QUEUE_SIZE: usize = 128;

/// Virtqueue descriptor flags.
pub mod desc_flags {
    /// Buffer continues via `next` field.
    pub const NEXT: u16 = 1;
    /// Buffer is device-writable (otherwise device-readable).
    pub const WRITE: u16 = 2;
}

/// A virtqueue descriptor (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length in bytes.
    pub len: u32,
    /// Flags (see `desc_flags`).
    pub flags: u16,
    /// Next descriptor index if `NEXT` flag is set.
    pub next: u16,
}

/// An available-ring entry (for driver → device).
#[derive(Debug)]
#[repr(C)]
pub struct VirtqAvail {
    /// Flags (currently unused, set to 0).
    pub flags: u16,
    /// Next index the driver will write to.
    pub idx: u16,
    /// Ring of descriptor chain heads.
    pub ring: [u16; MAX_QUEUE_SIZE],
}

/// A used-ring element (device → driver).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqUsedElem {
    /// Index of the descriptor chain head.
    pub id: u32,
    /// Number of bytes written by the device.
    pub len: u32,
}

/// A used ring (for device → driver).
#[derive(Debug)]
#[repr(C)]
pub struct VirtqUsed {
    /// Flags.
    pub flags: u16,
    /// Next index the device will write to.
    pub idx: u16,
    /// Ring of used elements.
    pub ring: [VirtqUsedElem; MAX_QUEUE_SIZE],
}

/// A split virtqueue with embedded descriptor, available, and used rings.
///
/// For simplicity, all three rings are stored inline rather than in
/// separate physical pages. This works for our small queue sizes and
/// avoids the complexity of multi-page allocation during early boot.
pub struct Virtqueue {
    /// Descriptor table.
    pub desc: [VirtqDesc; MAX_QUEUE_SIZE],
    /// Available ring (driver → device).
    pub avail_flags: u16,
    /// Available ring index.
    pub avail_idx: u16,
    /// Available ring entries.
    pub avail_ring: [u16; MAX_QUEUE_SIZE],
    /// Used ring flags.
    pub used_flags: u16,
    /// Used ring index.
    pub used_idx: u16,
    /// Used ring entries.
    pub used_ring: [VirtqUsedElem; MAX_QUEUE_SIZE],
    /// Number of descriptors in use.
    pub num: u16,
    /// Index of the next free descriptor.
    free_head: u16,
    /// Last used index we've processed.
    last_used_idx: u16,
}

impl Default for Virtqueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Virtqueue {
    /// Create a new virtqueue with all entries initialized.
    pub const fn new() -> Self {
        Self {
            desc: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; MAX_QUEUE_SIZE],
            avail_flags: 0,
            avail_idx: 0,
            avail_ring: [0; MAX_QUEUE_SIZE],
            used_flags: 0,
            used_idx: 0,
            used_ring: [VirtqUsedElem { id: 0, len: 0 }; MAX_QUEUE_SIZE],
            num: MAX_QUEUE_SIZE as u16,
            free_head: 0,
            last_used_idx: 0,
        }
    }

    /// Initialize the free descriptor chain.
    pub fn init(&mut self) {
        for i in 0..MAX_QUEUE_SIZE {
            self.desc[i].next = if i + 1 < MAX_QUEUE_SIZE {
                (i + 1) as u16
            } else {
                u16::MAX // end of chain
            };
        }
        self.free_head = 0;
    }

    /// Allocate a descriptor from the free list.
    pub fn alloc_desc(&mut self) -> Result<u16> {
        if self.free_head == u16::MAX {
            return Err(Error::OutOfMemory);
        }
        let idx = self.free_head;
        self.free_head = self.desc[idx as usize].next;
        Ok(idx)
    }

    /// Free a descriptor back to the free list.
    pub fn free_desc(&mut self, idx: u16) {
        self.desc[idx as usize].next = self.free_head;
        self.free_head = idx;
    }

    /// Push a descriptor chain head onto the available ring.
    pub fn push_avail(&mut self, desc_idx: u16) {
        let avail_idx = self.avail_idx as usize % MAX_QUEUE_SIZE;
        self.avail_ring[avail_idx] = desc_idx;
        // Memory barrier would go here in real hardware.
        self.avail_idx = self.avail_idx.wrapping_add(1);
    }

    /// Pop a completed request from the used ring.
    ///
    /// Returns `(desc_chain_head, bytes_written)` or `None` if no
    /// new completions.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        if self.last_used_idx == self.used_idx {
            return None;
        }
        let idx = self.last_used_idx as usize % MAX_QUEUE_SIZE;
        let elem = self.used_ring[idx];
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id as u16, elem.len))
    }
}

impl core::fmt::Debug for Virtqueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Virtqueue")
            .field("num", &self.num)
            .field("avail_idx", &self.avail_idx)
            .field("used_idx", &self.used_idx)
            .field("last_used_idx", &self.last_used_idx)
            .finish()
    }
}

/// VirtIO MMIO transport — reads/writes device registers.
pub struct VirtioMmio {
    /// Base address of the MMIO region.
    base: u64,
}

impl VirtioMmio {
    /// Create a new MMIO transport for the given base address.
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Read a 32-bit register.
    pub fn read32(&self, offset: u32) -> u32 {
        // SAFETY: MMIO region is mapped in kernel address space.
        unsafe {
            let addr = (self.base + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    /// Write a 32-bit register.
    pub fn write32(&self, offset: u32, value: u32) {
        // SAFETY: MMIO region is mapped in kernel address space.
        unsafe {
            let addr = (self.base + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    /// Probe: check magic and version.
    pub fn probe(&self) -> Result<u32> {
        let magic = self.read32(mmio_reg::MAGIC);
        if magic != VIRTIO_MAGIC {
            return Err(Error::NotFound);
        }
        let version = self.read32(mmio_reg::VERSION);
        if version != 2 {
            return Err(Error::NotImplemented);
        }
        Ok(self.read32(mmio_reg::DEVICE_ID))
    }

    /// Reset the device (write 0 to status).
    pub fn reset(&self) {
        self.write32(mmio_reg::STATUS, 0);
    }

    /// Read current device status.
    pub fn status(&self) -> u32 {
        self.read32(mmio_reg::STATUS)
    }

    /// Set device status bits (OR with current).
    pub fn set_status(&self, bits: u32) {
        let cur = self.status();
        self.write32(mmio_reg::STATUS, cur | bits);
    }

    /// Acknowledge interrupt.
    pub fn ack_interrupt(&self) -> u32 {
        let isr = self.read32(mmio_reg::INTERRUPT_STATUS);
        self.write32(mmio_reg::INTERRUPT_ACK, isr);
        isr
    }

    /// Notify the device about activity in a queue.
    pub fn notify(&self, queue_idx: u32) {
        self.write32(mmio_reg::QUEUE_NOTIFY, queue_idx);
    }

    /// Read device features (word 0 or 1).
    pub fn read_device_features(&self, sel: u32) -> u32 {
        self.write32(mmio_reg::DEVICE_FEATURES_SEL, sel);
        self.read32(mmio_reg::DEVICE_FEATURES)
    }

    /// Write driver features (word 0 or 1).
    pub fn write_driver_features(&self, sel: u32, features: u32) {
        self.write32(mmio_reg::DRIVER_FEATURES_SEL, sel);
        self.write32(mmio_reg::DRIVER_FEATURES, features);
    }
}

impl core::fmt::Debug for VirtioMmio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioMmio")
            .field("base", &format_args!("{:#X}", self.base))
            .finish()
    }
}
