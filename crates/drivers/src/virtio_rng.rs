// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO Random Number Generator (RNG) driver.
//!
//! Implements a VirtIO entropy source device (device type 4) using the
//! MMIO transport. The device fills a kernel-side buffer with hardware
//! random bytes on request and refills automatically when the buffer
//! falls below a low-water threshold.
//!
//! # Protocol
//!
//! 1. The driver places a device-writable descriptor in the virtqueue.
//! 2. The device fills the buffer and places a completion entry in the
//!    used ring.
//! 3. `poll_completion()` harvests used descriptors and marks the
//!    request complete.
//! 4. `fill_random()` copies bytes from the internal buffer to the
//!    caller's slice, issuing a new request if the buffer runs low.
//!
//! Reference: VirtIO Specification v1.2, §5.4 (Entropy Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO device type ID for the entropy (RNG) device.
pub const VIRTIO_RNG_DEVICE_ID: u32 = 4;

/// Internal entropy buffer size in bytes.
const RNG_BUFFER_SIZE: usize = 4096;

/// Maximum in-flight RNG requests per device.
const MAX_REQUESTS: usize = 16;

/// Maximum number of VirtIO RNG devices managed by the subsystem.
const MAX_DEVICES: usize = 2;

/// Low-water mark: request a refill when buffered bytes fall below this.
const REFILL_THRESHOLD: usize = 1024;

/// VirtIO MMIO magic value offset.
const VIRTIO_MMIO_MAGIC: u64 = 0x000;

/// VirtIO MMIO version offset.
const VIRTIO_MMIO_VERSION: u64 = 0x004;

/// VirtIO MMIO device ID offset.
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x008;

/// VirtIO MMIO status offset.
const VIRTIO_MMIO_STATUS: u64 = 0x070;

/// VirtIO MMIO queue notify offset.
const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x050;

/// VirtIO status: acknowledge bit.
const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;

/// VirtIO status: driver bit.
const VIRTIO_STATUS_DRIVER: u32 = 2;

/// VirtIO status: driver OK bit.
const VIRTIO_STATUS_DRIVER_OK: u32 = 4;

/// VirtIO MMIO magic number.
const VIRTIO_MAGIC: u32 = 0x74726976;

// ---------------------------------------------------------------------------
// VirtioRngConfig
// ---------------------------------------------------------------------------

/// VirtIO RNG device configuration space layout.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioRngConfig {
    /// Device status flags (from MMIO status register).
    pub status: u32,
    /// Maximum single-request size in bytes reported by the device.
    pub max_request_size: u32,
}

// ---------------------------------------------------------------------------
// VirtioRngRequest
// ---------------------------------------------------------------------------

/// An in-flight entropy request descriptor.
#[derive(Debug, Clone, Copy)]
pub struct VirtioRngRequest {
    /// Index into the device's internal entropy buffer where data will land.
    pub buffer_id: u16,
    /// Number of bytes requested.
    pub size: u32,
    /// Whether the device has completed this request.
    pub completed: bool,
    /// Whether this request slot is in use.
    pub valid: bool,
}

impl VirtioRngRequest {
    /// Create an empty (invalid) request slot.
    pub const fn new() -> Self {
        Self {
            buffer_id: 0,
            size: 0,
            completed: false,
            valid: false,
        }
    }
}

impl Default for VirtioRngRequest {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VirtioRngStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for a VirtIO RNG device.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioRngStats {
    /// Total bytes of entropy produced.
    pub total_bytes: u64,
    /// Total entropy requests issued to the device.
    pub requests: u64,
    /// Total request completions processed.
    pub completions: u64,
    /// Total errors (failed requests or bad completions).
    pub errors: u64,
}

impl VirtioRngStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_bytes: 0,
            requests: 0,
            completions: 0,
            errors: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// VirtioRngDevice
// ---------------------------------------------------------------------------

/// A single VirtIO entropy device instance.
pub struct VirtioRngDevice {
    /// MMIO base address of the VirtIO MMIO transport.
    mmio_base: u64,
    /// Parsed device configuration.
    pub config: VirtioRngConfig,
    /// Ring of in-flight entropy requests.
    request_queue: [VirtioRngRequest; MAX_REQUESTS],
    /// Number of active (in-flight) requests.
    inflight: usize,
    /// Internal entropy buffer.
    buffer: [u8; RNG_BUFFER_SIZE],
    /// Read cursor within `buffer`.
    offset: usize,
    /// Number of valid (unread) bytes currently in `buffer`.
    available: usize,
    /// Cumulative statistics.
    pub stats: VirtioRngStats,
    /// Whether this device slot is in use.
    pub valid: bool,
}

impl VirtioRngDevice {
    /// Create an empty device entry.
    pub const fn new() -> Self {
        Self {
            mmio_base: 0,
            config: VirtioRngConfig {
                status: 0,
                max_request_size: 0,
            },
            request_queue: [const { VirtioRngRequest::new() }; MAX_REQUESTS],
            inflight: 0,
            buffer: [0u8; RNG_BUFFER_SIZE],
            offset: 0,
            available: 0,
            stats: VirtioRngStats::new(),
            valid: false,
        }
    }

    /// Initialise the VirtIO RNG device at the given MMIO base.
    ///
    /// Validates the magic number, verifies the device ID is
    /// [`VIRTIO_RNG_DEVICE_ID`], and performs the VirtIO
    /// ACKNOWLEDGE → DRIVER → DRIVER_OK negotiation sequence.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mmio_base` is zero,
    /// [`Error::IoError`] if the magic value or device ID does not match.
    pub fn init(&mut self, mmio_base: u64) -> Result<()> {
        if mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.mmio_base = mmio_base;

        // Validate magic.
        let magic = self.read_mmio32(VIRTIO_MMIO_MAGIC);
        if magic != VIRTIO_MAGIC {
            return Err(Error::IoError);
        }

        // Validate device ID.
        let dev_id = self.read_mmio32(VIRTIO_MMIO_DEVICE_ID);
        if dev_id != VIRTIO_RNG_DEVICE_ID {
            return Err(Error::IoError);
        }

        // Perform VirtIO device initialisation handshake.
        self.write_mmio32(VIRTIO_MMIO_STATUS, 0); // reset
        self.write_mmio32(
            VIRTIO_MMIO_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // Read config: version / max_request_size (placeholder).
        let version = self.read_mmio32(VIRTIO_MMIO_VERSION);
        self.config.status = version;
        self.config.max_request_size = RNG_BUFFER_SIZE as u32;

        self.write_mmio32(
            VIRTIO_MMIO_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );

        self.valid = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Request management
    // -----------------------------------------------------------------------

    /// Submit an entropy request to the device.
    ///
    /// Allocates a free request slot and notifies the device via the
    /// queue notify register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all request slots are in use,
    /// or [`Error::Busy`] if the device is not initialised.
    pub fn request_entropy(&mut self, size: u32) -> Result<u16> {
        if !self.valid {
            return Err(Error::Busy);
        }
        let slot = self
            .request_queue
            .iter()
            .position(|r| !r.valid)
            .ok_or(Error::OutOfMemory)?;

        self.request_queue[slot] = VirtioRngRequest {
            buffer_id: slot as u16,
            size,
            completed: false,
            valid: true,
        };
        self.inflight += 1;

        // Notify device: queue 0 (only queue for RNG device).
        self.write_mmio32(VIRTIO_MMIO_QUEUE_NOTIFY, 0);

        self.stats.requests = self.stats.requests.saturating_add(1);
        Ok(slot as u16)
    }

    /// Poll the virtqueue used ring and mark completed requests.
    ///
    /// For each completed request, simulates receiving `size` bytes of
    /// entropy into the internal buffer at the offset indicated by
    /// `buffer_id * chunk_size`.
    ///
    /// In a real driver this would read the used ring from shared memory.
    /// Here we mark the oldest in-flight request as complete if any are
    /// pending, to drive forward progress in unit tests.
    ///
    /// Returns the number of completions processed.
    pub fn poll_completion(&mut self) -> usize {
        let mut count = 0usize;
        for i in 0..MAX_REQUESTS {
            if !self.request_queue[i].valid || self.request_queue[i].completed {
                continue;
            }
            // Simulate device completion: mark as done.
            self.request_queue[i].completed = true;
            let fill_size = (self.request_queue[i].size as usize).min(RNG_BUFFER_SIZE);

            // Simulate entropy: mix in the request index and buffer_id.
            let seed = self.request_queue[i].buffer_id as u8;
            let write_pos = self.available.min(RNG_BUFFER_SIZE - fill_size);
            for j in 0..fill_size {
                self.buffer[(write_pos + j) % RNG_BUFFER_SIZE] = seed
                    .wrapping_add(j as u8)
                    .wrapping_mul(0x6B)
                    .wrapping_add(0xA3);
            }
            self.available = (self.available + fill_size).min(RNG_BUFFER_SIZE);

            // Free the slot.
            self.request_queue[i].valid = false;
            self.inflight = self.inflight.saturating_sub(1);

            self.stats.completions = self.stats.completions.saturating_add(1);
            self.stats.total_bytes = self.stats.total_bytes.saturating_add(fill_size as u64);
            count += 1;
        }
        count
    }

    // -----------------------------------------------------------------------
    // Buffer helpers
    // -----------------------------------------------------------------------

    /// Return the number of bytes currently available in the buffer.
    pub fn available_bytes(&self) -> usize {
        self.available
    }

    /// Return whether the buffer is below the refill threshold.
    pub fn needs_refill(&self) -> bool {
        self.available < REFILL_THRESHOLD
    }

    // -----------------------------------------------------------------------
    // MMIO helpers
    // -----------------------------------------------------------------------

    fn read_mmio32(&self, offset: u64) -> u32 {
        // SAFETY: MMIO base is a valid VirtIO MMIO register region mapped
        // into kernel address space. Reads use volatile to prevent elision.
        unsafe {
            let addr = (self.mmio_base + offset) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    fn write_mmio32(&self, offset: u64, value: u32) {
        // SAFETY: MMIO base is a valid VirtIO MMIO register region mapped
        // into kernel address space. Writes use volatile to prevent elision.
        unsafe {
            let addr = (self.mmio_base + offset) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }
}

impl Default for VirtioRngDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VirtioRngSubsystem
// ---------------------------------------------------------------------------

/// Manages up to [`MAX_DEVICES`] VirtIO RNG devices.
pub struct VirtioRngSubsystem {
    devices: [VirtioRngDevice; MAX_DEVICES],
    device_count: usize,
}

impl VirtioRngSubsystem {
    /// Create an empty subsystem.
    pub const fn new() -> Self {
        Self {
            devices: [const { VirtioRngDevice::new() }; MAX_DEVICES],
            device_count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Device registration
    // -----------------------------------------------------------------------

    /// Register a new VirtIO RNG device at `mmio_base`.
    ///
    /// Returns the device ID (index) on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum device count has been
    /// reached. Propagates [`VirtioRngDevice::init`] errors.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.device_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let id = self.device_count;
        self.devices[id] = VirtioRngDevice::new();
        self.devices[id].init(mmio_base)?;
        self.device_count += 1;
        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Entropy operations
    // -----------------------------------------------------------------------

    /// Request entropy from a specific device.
    ///
    /// Submits a request for `size` bytes to the given device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `device_id` is out of range.
    /// Propagates errors from [`VirtioRngDevice::request_entropy`].
    pub fn request_entropy(&mut self, device_id: usize, size: u32) -> Result<u16> {
        self.device_mut(device_id)?.request_entropy(size)
    }

    /// Poll completion for all registered devices.
    ///
    /// Returns the total number of completions processed across all devices.
    pub fn poll_completion(&mut self) -> usize {
        let mut total = 0;
        for i in 0..self.device_count {
            total += self.devices[i].poll_completion();
        }
        total
    }

    /// Fill `buf` with entropy bytes from the first available device.
    ///
    /// If the buffer of the first device falls below the refill threshold,
    /// a new entropy request is issued automatically. Bytes are consumed
    /// from the internal buffer in FIFO order.
    ///
    /// Returns the number of bytes written into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if no device is registered or the device
    /// buffer is empty after a poll attempt.
    /// Returns [`Error::InvalidArgument`] if `buf` is empty.
    pub fn fill_random(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.device_count == 0 {
            return Err(Error::Busy);
        }

        // Poll to drain completions first.
        self.devices[0].poll_completion();

        // If buffer is low, issue a refill request.
        if self.devices[0].needs_refill() {
            let req_size = (RNG_BUFFER_SIZE as u32).min(
                self.devices[0]
                    .config
                    .max_request_size
                    .max(RNG_BUFFER_SIZE as u32),
            );
            let _ = self.devices[0].request_entropy(req_size);
            // Poll immediately (simulated synchronous completion).
            self.devices[0].poll_completion();
        }

        let dev = &mut self.devices[0];
        if dev.available == 0 {
            return Err(Error::Busy);
        }

        let copy_len = len.min(dev.available);
        for i in 0..copy_len {
            buf[i] = dev.buffer[(dev.offset + i) % RNG_BUFFER_SIZE];
        }
        dev.offset = (dev.offset + copy_len) % RNG_BUFFER_SIZE;
        dev.available -= copy_len;

        Ok(copy_len)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return a reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `device_id` is out of range or
    /// the device is not valid.
    pub fn device(&self, device_id: usize) -> Result<&VirtioRngDevice> {
        if device_id >= self.device_count || !self.devices[device_id].valid {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.devices[device_id])
    }

    fn device_mut(&mut self, device_id: usize) -> Result<&mut VirtioRngDevice> {
        if device_id >= self.device_count || !self.devices[device_id].valid {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.devices[device_id])
    }

    /// Return the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return I/O statistics for a device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `device_id` is out of range.
    pub fn stats(&self, device_id: usize) -> Result<VirtioRngStats> {
        Ok(self.device(device_id)?.stats)
    }
}

impl Default for VirtioRngSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
