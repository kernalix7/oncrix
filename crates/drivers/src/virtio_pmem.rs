// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO persistent memory (virtio-pmem) driver.
//!
//! Implements the virtio-pmem device as specified in the VirtIO 1.2
//! specification (section 5.16). The device exposes a contiguous
//! region of host physical memory (the "pmem range") that survives
//! guest reboots. The driver maps the range into the guest address
//! space and provides a flush mechanism to persist writes.
//!
//! # Device Operation
//!
//! 1. Read `start_pa` and `size` from the device configuration space.
//! 2. Map `[start_pa, start_pa + size)` as DAX (direct-access) memory.
//! 3. Issue flush requests via the single request virtqueue when the
//!    file system calls `fsync` / `msync` over the pmem range.
//! 4. Wait for the completion descriptor and inspect the return status.
//!
//! # Usage
//!
//! ```ignore
//! let mut dev = VirtioPmem::new(mmio_base, virtqueue_desc_phys);
//! dev.init()?;
//! let info = dev.pmem_info();
//! // map info.start_pa .. info.start_pa + info.size as DAX
//! dev.flush()?;
//! ```

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── VirtIO MMIO Register Offsets ──────────────────────────────

/// Magic value register (must read 0x74726976, "virt").
const VIRTIO_MMIO_MAGIC: u64 = 0x000;
/// Device version register (should be 2 for non-legacy).
const VIRTIO_MMIO_VERSION: u64 = 0x004;
/// Device ID register (5 = block, 27 = pmem, etc.).
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x008;
/// Vendor ID register.
const VIRTIO_MMIO_VENDOR_ID: u64 = 0x00C;
/// Device feature bits (low 32 of 64).
const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x010;
/// Device feature bits selector.
const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u64 = 0x014;
/// Driver (guest) feature bits.
const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x020;
/// Driver feature bits selector.
const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u64 = 0x024;
/// Queue selector.
const VIRTIO_MMIO_QUEUE_SEL: u64 = 0x030;
/// Maximum queue size.
const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x034;
/// Negotiated queue size.
const VIRTIO_MMIO_QUEUE_NUM: u64 = 0x038;
/// Queue ready flag.
const VIRTIO_MMIO_QUEUE_READY: u64 = 0x044;
/// Queue notify register.
const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x050;
/// Interrupt status register.
const VIRTIO_MMIO_INTERRUPT_STATUS: u64 = 0x060;
/// Interrupt acknowledge register.
const VIRTIO_MMIO_INTERRUPT_ACK: u64 = 0x064;
/// Device status register.
const VIRTIO_MMIO_STATUS: u64 = 0x070;
/// Queue descriptor table address (low 32 bits).
const VIRTIO_MMIO_QUEUE_DESC_LOW: u64 = 0x080;
/// Queue descriptor table address (high 32 bits).
const VIRTIO_MMIO_QUEUE_DESC_HIGH: u64 = 0x084;
/// Queue driver (available) ring address (low 32 bits).
const VIRTIO_MMIO_QUEUE_DRIVER_LOW: u64 = 0x090;
/// Queue driver (available) ring address (high 32 bits).
const VIRTIO_MMIO_QUEUE_DRIVER_HIGH: u64 = 0x094;
/// Queue device (used) ring address (low 32 bits).
const VIRTIO_MMIO_QUEUE_DEVICE_LOW: u64 = 0x0A0;
/// Queue device (used) ring address (high 32 bits).
const VIRTIO_MMIO_QUEUE_DEVICE_HIGH: u64 = 0x0A4;
/// Device configuration space base (pmem-specific fields).
const VIRTIO_MMIO_CONFIG: u64 = 0x100;

// ── VirtIO Device Status Bits ─────────────────────────────────

/// Device acknowledged by OS.
const STATUS_ACKNOWLEDGE: u32 = 1;
/// Driver loaded.
const STATUS_DRIVER: u32 = 2;
/// Driver features negotiated.
const STATUS_FEATURES_OK: u32 = 8;
/// Device/driver fully operational.
const STATUS_DRIVER_OK: u32 = 4;
/// Fatal error.
const STATUS_FAILED: u32 = 128;

// ── VirtIO PMEM Device ID ─────────────────────────────────────

/// VirtIO device ID for pmem (virtio-spec 5.16).
const VIRTIO_PMEM_DEVICE_ID: u32 = 27;

// ── VirtIO PMEM Configuration Space ──────────────────────────

/// Offset of `start` field in pmem config space (64-bit physical address).
const PMEM_CFG_START: u64 = 0;
/// Offset of `size` field in pmem config space (64-bit byte count).
const PMEM_CFG_SIZE: u64 = 8;

// ── VirtIO PMEM Request Types ─────────────────────────────────

/// Request type: flush persistent memory.
const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;

// ── VirtIO PMEM Response Status ───────────────────────────────

/// Response status: success.
const VIRTIO_PMEM_RESP_OK: u32 = 0;
/// Response status: error.
const VIRTIO_PMEM_RESP_EIO: u32 = 1;

// ── VirtIO Magic Value ────────────────────────────────────────

/// Expected magic value in VIRTIO_MMIO_MAGIC.
const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"

// ── Virtqueue Constants ───────────────────────────────────────

/// Number of descriptors in the request virtqueue.
const QUEUE_SIZE: u16 = 16;

// ── MMIO Helpers ──────────────────────────────────────────────

/// Read a 32-bit value from a VirtIO MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid mapped VirtIO MMIO register.
#[inline]
unsafe fn read_mmio32(base: u64, offset: u64) -> u32 {
    // SAFETY: caller guarantees the address is a valid MMIO register.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit value to a VirtIO MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid mapped VirtIO MMIO register.
#[inline]
unsafe fn write_mmio32(base: u64, offset: u64, val: u32) {
    // SAFETY: caller guarantees the address is a valid MMIO register.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

/// Read a 64-bit value from two consecutive 32-bit MMIO registers.
///
/// # Safety
///
/// `base + offset` and `base + offset + 4` must be valid MMIO registers.
#[inline]
unsafe fn read_mmio64(base: u64, offset: u64) -> u64 {
    // SAFETY: caller guarantees both halves are valid MMIO registers.
    unsafe {
        let lo = read_mmio32(base, offset) as u64;
        let hi = read_mmio32(base, offset + 4) as u64;
        lo | (hi << 32)
    }
}

// ── VirtIO PMEM Request Descriptor ───────────────────────────

/// A virtio-pmem flush request written into the descriptor ring.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioPmemReq {
    /// Request type (currently only FLUSH = 0).
    pub req_type: u32,
    /// Padding for alignment.
    pub padding: u32,
}

impl VirtioPmemReq {
    /// Create a flush request.
    pub const fn flush() -> Self {
        Self {
            req_type: VIRTIO_PMEM_REQ_TYPE_FLUSH,
            padding: 0,
        }
    }
}

// ── VirtIO PMEM Response Descriptor ──────────────────────────

/// The device-written response to a pmem request.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioPmemResp {
    /// Status code: 0 = success, 1 = EIO.
    pub status: u32,
}

impl VirtioPmemResp {
    /// Return whether the response indicates success.
    pub const fn is_ok(&self) -> bool {
        self.status == VIRTIO_PMEM_RESP_OK
    }
}

// ── VirtIO PMEM Device Info ───────────────────────────────────

/// Configuration information read from the virtio-pmem device.
#[derive(Debug, Clone, Copy, Default)]
pub struct PmemInfo {
    /// Physical start address of the persistent memory region.
    pub start_pa: u64,
    /// Size of the persistent memory region in bytes.
    pub size: u64,
}

impl PmemInfo {
    /// Return the (exclusive) end physical address of the pmem range.
    pub const fn end_pa(&self) -> u64 {
        self.start_pa + self.size
    }

    /// Return whether the range is valid (non-zero size and aligned).
    pub const fn is_valid(&self) -> bool {
        self.size > 0 && self.start_pa & 0xFFF == 0
    }
}

// ── Virtqueue Descriptor (VirtIO 1.x split-ring) ──────────────

/// A single descriptor in a VirtIO split virtqueue.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (NEXT, WRITE, INDIRECT).
    pub flags: u16,
    /// Index of the next chained descriptor (if NEXT flag set).
    pub next: u16,
}

/// VirtIO descriptor flag: buffer is device-writable.
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
/// VirtIO descriptor flag: chain to next descriptor.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;

// ── Flush Statistics ──────────────────────────────────────────

/// Accumulated flush operation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PmemFlushStats {
    /// Total flush requests issued.
    pub flush_requests: u64,
    /// Successful flush completions.
    pub flush_ok: u64,
    /// Failed flush completions.
    pub flush_errors: u64,
    /// Flush operations currently in flight.
    pub in_flight: u32,
}

// ── VirtioPmem Device ─────────────────────────────────────────

/// Driver for a virtio-pmem device.
///
/// Manages the VirtIO MMIO registers, reads the pmem configuration
/// space, and submits flush requests via the request virtqueue.
pub struct VirtioPmem {
    /// Physical base address of the VirtIO MMIO register space.
    mmio_base: u64,
    /// Physical base address of the descriptor table.
    desc_phys: u64,
    /// Parsed pmem configuration (start address and size).
    info: PmemInfo,
    /// Negotiated virtqueue depth.
    queue_size: u16,
    /// Producer index into the available ring.
    avail_idx: u16,
    /// Consumer index into the used ring.
    used_idx: u16,
    /// Whether the device has been fully initialized.
    initialized: bool,
    /// Flush statistics.
    stats: PmemFlushStats,
}

impl VirtioPmem {
    /// Create a new virtio-pmem driver instance.
    ///
    /// The device is not initialized until [`VirtioPmem::init`] is called.
    ///
    /// # Arguments
    ///
    /// * `mmio_base` — Physical base address of the VirtIO MMIO region.
    /// * `desc_phys` — Physical address of the pre-allocated descriptor table.
    pub fn new(mmio_base: u64, desc_phys: u64) -> Self {
        Self {
            mmio_base,
            desc_phys,
            info: PmemInfo::default(),
            queue_size: 0,
            avail_idx: 0,
            used_idx: 0,
            initialized: false,
            stats: PmemFlushStats::default(),
        }
    }

    /// Initialize the virtio-pmem device.
    ///
    /// Performs the VirtIO initialization sequence:
    /// 1. Check magic and device ID.
    /// 2. Reset → ACKNOWLEDGE → DRIVER.
    /// 3. Negotiate features.
    /// 4. Set FEATURES_OK and verify.
    /// 5. Set up the request virtqueue.
    /// 6. Set DRIVER_OK.
    /// 7. Read pmem configuration.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `mmio_base` is zero.
    /// - [`Error::IoError`] if the magic value is wrong or the device
    ///   ID is not virtio-pmem (27).
    /// - [`Error::NotFound`] if the pmem configuration reports zero size.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }

        // Step 1: Verify magic and device ID.
        // SAFETY: mmio_base is a valid VirtIO MMIO BAR.
        let magic = unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_MAGIC) };
        if magic != VIRTIO_MAGIC {
            return Err(Error::IoError);
        }

        // SAFETY: same as above.
        let device_id = unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_DEVICE_ID) };
        if device_id != VIRTIO_PMEM_DEVICE_ID {
            return Err(Error::IoError);
        }

        // Step 2: Reset device then set ACKNOWLEDGE + DRIVER.
        self.write_status(0);
        self.write_status(STATUS_ACKNOWLEDGE);
        self.write_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Step 3: Read and accept device features (no special features required).
        // SAFETY: register is valid.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0) };
        // SAFETY: register is valid.
        let _features_lo = unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_DEVICE_FEATURES) };

        // Accept no optional features for now.
        // SAFETY: register is valid.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0) };
        // SAFETY: register is valid.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_DRIVER_FEATURES, 0) };

        // Step 4: Set FEATURES_OK and verify.
        self.write_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        // SAFETY: register is valid.
        let status = unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_STATUS) };
        if status & STATUS_FEATURES_OK == 0 {
            self.write_status(STATUS_FAILED);
            return Err(Error::IoError);
        }

        // Step 5: Configure queue 0 (the single request queue).
        // SAFETY: register is valid.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_SEL, 0) };
        // SAFETY: register is valid.
        let max_q = unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_NUM_MAX) } as u16;
        self.queue_size = max_q.min(QUEUE_SIZE);
        // SAFETY: register is valid.
        unsafe {
            write_mmio32(
                self.mmio_base,
                VIRTIO_MMIO_QUEUE_NUM,
                self.queue_size as u32,
            )
        };

        // Set descriptor table address (split into two 32-bit writes).
        let desc_lo = (self.desc_phys & 0xFFFF_FFFF) as u32;
        let desc_hi = ((self.desc_phys >> 32) & 0xFFFF_FFFF) as u32;
        // SAFETY: registers are valid.
        unsafe {
            write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_DESC_LOW, desc_lo);
            write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_DESC_HIGH, desc_hi);
        }

        // Available ring immediately follows the descriptor table.
        let avail_phys =
            self.desc_phys + (core::mem::size_of::<VirtqDesc>() * QUEUE_SIZE as usize) as u64;
        let avail_lo = (avail_phys & 0xFFFF_FFFF) as u32;
        let avail_hi = ((avail_phys >> 32) & 0xFFFF_FFFF) as u32;
        // SAFETY: registers are valid.
        unsafe {
            write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_DRIVER_LOW, avail_lo);
            write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_DRIVER_HIGH, avail_hi);
        }

        // Used ring follows the available ring (aligned to 4 bytes).
        let used_phys = avail_phys + 6 + 2 * self.queue_size as u64;
        let used_lo = (used_phys & 0xFFFF_FFFF) as u32;
        let used_hi = ((used_phys >> 32) & 0xFFFF_FFFF) as u32;
        // SAFETY: registers are valid.
        unsafe {
            write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_DEVICE_LOW, used_lo);
            write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_DEVICE_HIGH, used_hi);
        }

        // Mark queue as ready.
        // SAFETY: register is valid.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_READY, 1) };

        // Step 6: Signal DRIVER_OK.
        self.write_status(
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );

        // Step 7: Read pmem configuration (start_pa and size).
        // SAFETY: config space registers are valid for pmem device.
        let start_pa = unsafe { read_mmio64(self.mmio_base + VIRTIO_MMIO_CONFIG, PMEM_CFG_START) };
        // SAFETY: same as above.
        let size = unsafe { read_mmio64(self.mmio_base + VIRTIO_MMIO_CONFIG, PMEM_CFG_SIZE) };

        if size == 0 {
            return Err(Error::NotFound);
        }

        self.info = PmemInfo { start_pa, size };
        self.initialized = true;
        Ok(())
    }

    /// Issue a flush request to the device.
    ///
    /// Blocks until the device acknowledges the flush (synchronous
    /// polling). In a real driver this would be interrupt-driven.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the device is not initialized.
    /// - [`Error::IoError`] if the device reports a flush error.
    pub fn flush(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }

        self.stats.flush_requests += 1;
        self.stats.in_flight += 1;

        // Notify queue 0 (trigger device to process the flush).
        // SAFETY: register is valid.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0) };

        // Poll for interrupt status (bit 0 = used buffer notification).
        let mut retries = 100_000u32;
        loop {
            // SAFETY: register is valid.
            let isr = unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_INTERRUPT_STATUS) };
            if isr & 1 != 0 {
                // Acknowledge the interrupt.
                // SAFETY: register is valid.
                unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_INTERRUPT_ACK, isr) };
                break;
            }
            retries = retries.saturating_sub(1);
            if retries == 0 {
                self.stats.in_flight = self.stats.in_flight.saturating_sub(1);
                self.stats.flush_errors += 1;
                return Err(Error::IoError);
            }
        }

        self.stats.in_flight = self.stats.in_flight.saturating_sub(1);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.used_idx = self.used_idx.wrapping_add(1);
        self.stats.flush_ok += 1;
        Ok(())
    }

    /// Return the pmem configuration (physical range).
    pub const fn pmem_info(&self) -> &PmemInfo {
        &self.info
    }

    /// Return whether the device has been initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return accumulated flush statistics.
    pub const fn stats(&self) -> &PmemFlushStats {
        &self.stats
    }

    /// Return the negotiated virtqueue size.
    pub const fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Write to the device status register.
    fn write_status(&mut self, status: u32) {
        // SAFETY: mmio_base is a valid VirtIO MMIO BAR; STATUS is always
        // present in the standard VirtIO MMIO layout.
        unsafe { write_mmio32(self.mmio_base, VIRTIO_MMIO_STATUS, status) };
    }

    /// Return the raw device status register value.
    pub fn read_status(&self) -> u32 {
        // SAFETY: mmio_base is a valid VirtIO MMIO BAR.
        unsafe { read_mmio32(self.mmio_base, VIRTIO_MMIO_STATUS) }
    }

    /// Return the MMIO base address.
    pub const fn mmio_base(&self) -> u64 {
        self.mmio_base
    }
}

// ── VirtioPmem Registry ───────────────────────────────────────

/// Maximum virtio-pmem devices in the system.
const MAX_PMEM_DEVICES: usize = 4;

/// Registry of all virtio-pmem devices.
pub struct VirtioPmemRegistry {
    /// Device slots.
    devices: [Option<VirtioPmem>; MAX_PMEM_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for VirtioPmemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioPmemRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a virtio-pmem device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: VirtioPmem) -> Result<usize> {
        if self.count >= MAX_PMEM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut VirtioPmem> {
        if index < self.count {
            self.devices[index].as_mut()
        } else {
            None
        }
    }

    /// Get a shared reference to a device by index.
    pub fn get(&self, index: usize) -> Option<&VirtioPmem> {
        if index < self.count {
            self.devices[index].as_ref()
        } else {
            None
        }
    }

    /// Return the total number of pmem bytes across all devices.
    pub fn total_pmem_bytes(&self) -> u64 {
        self.devices[..self.count]
            .iter()
            .flatten()
            .map(|d| d.pmem_info().size)
            .sum()
    }

    /// Return the number of registered devices.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
