// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO entropy (random number generator) device driver.
//!
//! The virtio-rng device provides cryptographically strong random bytes
//! from the host's entropy source. The driver:
//!
//! 1. Negotiates features with the device
//! 2. Submits buffers on the `requestq` virtqueue
//! 3. The device fills buffers with random bytes and returns them
//!
//! This driver is intentionally simple — virtio-rng has no feature bits
//! beyond the standard transport features (RING_INDIRECT_DESC, etc.).
//!
//! Reference: Virtual I/O Device (VIRTIO) 1.2, §5.4.

use oncrix_lib::{Error, Result};

// ── VirtIO RNG Constants ───────────────────────────────────────────────────

/// Maximum bytes per entropy request.
pub const MAX_REQUEST_LEN: usize = 4096;
/// Maximum pending entropy requests.
const MAX_REQUESTS: usize = 4;
/// VirtIO device ID for entropy source.
pub const VIRTIO_ID_RNG: u32 = 4;

// ── Request State ──────────────────────────────────────────────────────────

/// State of a single entropy request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestState {
    Free,
    Submitted,
    Completed,
}

// ── Entropy Request ────────────────────────────────────────────────────────

/// An in-flight entropy request.
pub struct EntropyRequest {
    /// State of this request slot.
    pub state: RequestState,
    /// Physical address of the receive buffer.
    pub buf_phys: u64,
    /// Number of bytes requested.
    pub len: usize,
    /// Number of bytes actually received.
    pub received: usize,
}

impl EntropyRequest {
    const fn empty() -> Self {
        Self {
            state: RequestState::Free,
            buf_phys: 0,
            len: 0,
            received: 0,
        }
    }
}

// ── VirtIO RNG Device State ────────────────────────────────────────────────

/// VirtIO status register bits.
mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
}

/// Simulated VirtIO MMIO transport offsets (VIRTIO spec §4.2.2).
mod reg {
    pub const MAGIC: u32 = 0x000;
    pub const VERSION: u32 = 0x004;
    pub const DEVICE_ID: u32 = 0x008;
    pub const VENDOR_ID: u32 = 0x00C;
    pub const DEVICE_FEATURES: u32 = 0x010;
    pub const DRIVER_FEATURES: u32 = 0x020;
    pub const STATUS: u32 = 0x070;
    pub const QUEUE_NOTIFY: u32 = 0x050;
}

/// VirtIO MMIO magic value.
const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"

// ── MMIO helpers ───────────────────────────────────────────────────────────

#[inline]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

#[inline]
unsafe fn write32(base: usize, offset: u32, val: u32) {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

// ── Driver ─────────────────────────────────────────────────────────────────

/// VirtIO RNG driver.
pub struct VirtioRng {
    /// VirtIO MMIO base address.
    mmio_base: usize,
    /// Request slots.
    requests: [EntropyRequest; MAX_REQUESTS],
    /// Total bytes of entropy received.
    total_received: u64,
    /// Whether the driver has been initialized.
    initialized: bool,
}

impl VirtioRng {
    /// Create a new VirtIO RNG driver instance.
    ///
    /// # Safety
    /// `mmio_base` must be the MMIO base of a VirtIO MMIO transport
    /// implementing the entropy device (device ID 4).
    pub unsafe fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            requests: [const { EntropyRequest::empty() }; MAX_REQUESTS],
            total_received: 0,
            initialized: false,
        }
    }

    /// Validate the VirtIO MMIO magic and device ID.
    fn check_magic(&self) -> Result<()> {
        // SAFETY: mmio_base is valid VirtIO MMIO.
        let magic = unsafe { read32(self.mmio_base, reg::MAGIC) };
        if magic != VIRTIO_MAGIC {
            return Err(Error::NotFound);
        }
        let dev_id = unsafe { read32(self.mmio_base, reg::DEVICE_ID) };
        if dev_id != VIRTIO_ID_RNG {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Initialize the VirtIO RNG device.
    pub fn init(&mut self) -> Result<()> {
        self.check_magic()?;

        // Reset device.
        // SAFETY: STATUS register write 0 = device reset.
        unsafe { write32(self.mmio_base, reg::STATUS, 0) }

        // Acknowledge.
        // SAFETY: STATUS register write = driver bring-up sequence.
        unsafe { write32(self.mmio_base, reg::STATUS, status::ACKNOWLEDGE) }
        unsafe {
            write32(
                self.mmio_base,
                reg::STATUS,
                status::ACKNOWLEDGE | status::DRIVER,
            )
        }

        // No feature bits to negotiate for virtio-rng.
        // SAFETY: DRIVER_FEATURES = 0 (no optional features).
        unsafe { write32(self.mmio_base, reg::DRIVER_FEATURES, 0) }
        unsafe {
            write32(
                self.mmio_base,
                reg::STATUS,
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
            )
        }

        // Verify FEATURES_OK was accepted.
        let st = unsafe { read32(self.mmio_base, reg::STATUS) };
        if st & status::FEATURES_OK == 0 {
            return Err(Error::IoError);
        }

        // Mark driver ready.
        unsafe {
            write32(
                self.mmio_base,
                reg::STATUS,
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
            )
        }

        self.initialized = true;
        Ok(())
    }

    /// Submit a buffer to receive entropy.
    ///
    /// Returns the request slot index on success.
    pub fn submit_request(&mut self, buf_phys: u64, len: usize) -> Result<usize> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if len == 0 || len > MAX_REQUEST_LEN {
            return Err(Error::InvalidArgument);
        }
        // Find a free slot.
        let slot = self
            .requests
            .iter()
            .position(|r| r.state == RequestState::Free)
            .ok_or(Error::Busy)?;

        self.requests[slot] = EntropyRequest {
            state: RequestState::Submitted,
            buf_phys,
            len,
            received: 0,
        };

        // Notify device (queue 0 = requestq).
        // SAFETY: QUEUE_NOTIFY write kicks the virtqueue.
        unsafe { write32(self.mmio_base, reg::QUEUE_NOTIFY, 0) }

        Ok(slot)
    }

    /// Poll for completion of a request.
    pub fn poll_request(&mut self, slot: usize) -> Option<usize> {
        if slot >= MAX_REQUESTS || self.requests[slot].state != RequestState::Submitted {
            return None;
        }
        // In a real driver, we check the used ring for returned descriptors.
        // Here we model the device as immediately completing after notify.
        let received = self.requests[slot].len;
        self.requests[slot].state = RequestState::Completed;
        self.requests[slot].received = received;
        self.total_received += received as u64;
        Some(received)
    }

    /// Release a completed request slot.
    pub fn free_request(&mut self, slot: usize) -> Result<usize> {
        if slot >= MAX_REQUESTS || self.requests[slot].state != RequestState::Completed {
            return Err(Error::InvalidArgument);
        }
        let received = self.requests[slot].received;
        self.requests[slot].state = RequestState::Free;
        Ok(received)
    }

    /// Return total entropy bytes received since initialization.
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Return true if any requests are pending.
    pub fn has_pending(&self) -> bool {
        self.requests
            .iter()
            .any(|r| r.state == RequestState::Submitted)
    }

    /// Return the VirtIO device ID from MMIO.
    pub fn device_id(&self) -> u32 {
        // SAFETY: mmio_base is valid VirtIO MMIO.
        unsafe { read32(self.mmio_base, reg::DEVICE_ID) }
    }

    /// Return the vendor ID from MMIO.
    pub fn vendor_id(&self) -> u32 {
        // SAFETY: mmio_base is valid VirtIO MMIO.
        unsafe { read32(self.mmio_base, reg::VENDOR_ID) }
    }
}
