// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO Random Number Generator (VirtIO-RNG) driver.
//!
//! Implements the VirtIO entropy source device as defined in the
//! VirtIO 1.2 specification, section 5.4. The driver uses a single
//! virtqueue to request random bytes from the hypervisor, which
//! fills buffers with high-quality entropy from the host's RNG.
//!
//! # Architecture
//!
//! - [`VirtqDesc`] — virtqueue descriptor entry (`repr(C)`)
//! - [`VirtqAvail`] — available ring for submitting descriptors
//! - [`VirtqUsed`] — used ring for completed descriptors
//! - [`VirtQueue`] — a single virtqueue (descriptor table + rings)
//! - [`EntropyPool`] — local entropy pool with XOR-fold mixing
//! - [`RngBuffer`] — DMA-compatible buffer for entropy requests
//! - [`VirtioRng`] — top-level VirtIO-RNG device driver
//! - [`VirtioRngRegistry`] — system-wide registry of VirtIO-RNG devices
//!
//! Reference: VirtIO Specification 1.2, Section 5.4 (Entropy Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of descriptors per virtqueue.
const VIRTQ_SIZE: usize = 16;

/// Size of each entropy request buffer in bytes.
const RNG_BUFFER_SIZE: usize = 256;

/// Maximum number of pending RNG buffers.
const MAX_RNG_BUFFERS: usize = 4;

/// Size of the entropy pool in bytes.
const ENTROPY_POOL_SIZE: usize = 512;

/// Maximum number of VirtIO-RNG devices in the registry.
const MAX_VIRTIO_RNG_DEVICES: usize = 4;

/// VirtIO device status bits.
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
/// VirtIO device status: driver loaded.
const VIRTIO_STATUS_DRIVER: u8 = 2;
/// VirtIO device status: feature negotiation complete.
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
/// VirtIO device status: driver ready.
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
/// VirtIO device status: device has failed.
const VIRTIO_STATUS_FAILED: u8 = 128;

/// VirtIO device ID for entropy source.
const VIRTIO_DEVICE_ID_RNG: u32 = 4;

/// Virtqueue descriptor flag: buffer continues in next descriptor.
const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Virtqueue descriptor flag: buffer is device-writable (host fills it).
const VIRTQ_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// VirtqDesc — Virtqueue Descriptor
// ---------------------------------------------------------------------------

/// A single virtqueue descriptor entry.
///
/// Laid out as `repr(C)` to be placed in DMA-accessible memory.
/// Each descriptor points to a guest-physical buffer and optionally
/// chains to the next descriptor via the `next` field.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    /// Guest-physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (NEXT, WRITE, INDIRECT).
    pub flags: u16,
    /// Index of the next descriptor in the chain.
    pub next: u16,
}

impl Default for VirtqDesc {
    fn default() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }
}

impl VirtqDesc {
    /// Create an empty descriptor.
    pub const fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }

    /// Set this descriptor to point at a device-writable buffer.
    ///
    /// Used for RNG buffers where the host writes entropy data.
    pub fn set_write_buffer(&mut self, addr: u64, len: u32) {
        self.addr = addr;
        self.len = len;
        self.flags = VIRTQ_DESC_F_WRITE;
        self.next = 0;
    }

    /// Chain this descriptor to the next one.
    pub fn set_next(&mut self, next_idx: u16) {
        self.flags |= VIRTQ_DESC_F_NEXT;
        self.next = next_idx;
    }

    /// Return `true` if this descriptor is unused.
    pub fn is_free(&self) -> bool {
        self.addr == 0 && self.len == 0
    }
}

// ---------------------------------------------------------------------------
// VirtqAvail — Available Ring
// ---------------------------------------------------------------------------

/// The available ring for a virtqueue.
///
/// The driver writes descriptor chain heads into this ring to
/// notify the device that buffers are ready for processing.
#[derive(Debug, Clone, Copy)]
pub struct VirtqAvail {
    /// Flags (0 = no interrupt suppression).
    pub flags: u16,
    /// Index of the next entry the driver will write.
    pub idx: u16,
    /// Ring entries (descriptor chain head indices).
    pub ring: [u16; VIRTQ_SIZE],
}

impl Default for VirtqAvail {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtqAvail {
    /// Create an empty available ring.
    pub const fn new() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [0u16; VIRTQ_SIZE],
        }
    }

    /// Add a descriptor chain head to the available ring.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the ring is full.
    pub fn push(&mut self, desc_idx: u16) -> Result<()> {
        let slot = (self.idx as usize) % VIRTQ_SIZE;
        self.ring[slot] = desc_idx;
        self.idx = self.idx.wrapping_add(1);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VirtqUsedElem
// ---------------------------------------------------------------------------

/// A single entry in the used ring, returned by the device.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqUsedElem {
    /// Index of the descriptor chain head that was consumed.
    pub id: u32,
    /// Total number of bytes written by the device.
    pub len: u32,
}

// ---------------------------------------------------------------------------
// VirtqUsed — Used Ring
// ---------------------------------------------------------------------------

/// The used ring for a virtqueue.
///
/// The device writes entries here to indicate which descriptor
/// chains have been consumed and how many bytes were written.
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsed {
    /// Flags (0 = no notification suppression).
    pub flags: u16,
    /// Index of the next entry the device will write.
    pub idx: u16,
    /// Ring entries (completed descriptor info).
    pub ring: [VirtqUsedElem; VIRTQ_SIZE],
}

impl Default for VirtqUsed {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtqUsed {
    /// Create an empty used ring.
    pub const fn new() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [VirtqUsedElem { id: 0, len: 0 }; VIRTQ_SIZE],
        }
    }
}

// ---------------------------------------------------------------------------
// VirtQueue
// ---------------------------------------------------------------------------

/// A single virtqueue comprising a descriptor table, available ring,
/// and used ring.
///
/// The VirtIO-RNG device uses exactly one virtqueue (virtqueue 0) to
/// receive entropy buffers from the host.
pub struct VirtQueue {
    /// Descriptor table.
    pub descriptors: [VirtqDesc; VIRTQ_SIZE],
    /// Available ring (driver -> device).
    pub avail: VirtqAvail,
    /// Used ring (device -> driver).
    pub used: VirtqUsed,
    /// Number of free descriptors remaining.
    free_count: usize,
    /// Index of the next free descriptor.
    free_head: u16,
    /// Last seen used ring index (for polling completion).
    last_used_idx: u16,
}

impl Default for VirtQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtQueue {
    /// Create a new virtqueue with all descriptors free.
    pub const fn new() -> Self {
        Self {
            descriptors: [VirtqDesc::new(); VIRTQ_SIZE],
            avail: VirtqAvail::new(),
            used: VirtqUsed::new(),
            free_count: VIRTQ_SIZE,
            free_head: 0,
            last_used_idx: 0,
        }
    }

    /// Initialise the virtqueue by chaining free descriptors.
    ///
    /// Each descriptor's `next` field points to the following
    /// descriptor, forming a free list.
    pub fn init(&mut self) {
        let mut i: usize = 0;
        while i < VIRTQ_SIZE {
            self.descriptors[i] = VirtqDesc::new();
            if i + 1 < VIRTQ_SIZE {
                self.descriptors[i].next = (i + 1) as u16;
                self.descriptors[i].flags = VIRTQ_DESC_F_NEXT;
            }
            i += 1;
        }
        self.free_count = VIRTQ_SIZE;
        self.free_head = 0;
        self.avail = VirtqAvail::new();
        self.used = VirtqUsed::new();
        self.last_used_idx = 0;
    }

    /// Allocate a single descriptor from the free list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no free descriptors remain.
    pub fn alloc_desc(&mut self) -> Result<u16> {
        if self.free_count == 0 {
            return Err(Error::OutOfMemory);
        }
        let idx = self.free_head;
        self.free_head = self.descriptors[idx as usize].next;
        self.free_count -= 1;
        // Clear the allocated descriptor.
        self.descriptors[idx as usize] = VirtqDesc::new();
        Ok(idx)
    }

    /// Return a descriptor to the free list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn free_desc(&mut self, idx: u16) -> Result<()> {
        if (idx as usize) >= VIRTQ_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.descriptors[idx as usize] = VirtqDesc::new();
        self.descriptors[idx as usize].next = self.free_head;
        self.descriptors[idx as usize].flags = VIRTQ_DESC_F_NEXT;
        self.free_head = idx;
        self.free_count += 1;
        Ok(())
    }

    /// Submit a device-writable buffer to the virtqueue.
    ///
    /// Allocates a descriptor, configures it for the specified
    /// guest-physical address and length, and adds it to the
    /// available ring.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if no free descriptors are available.
    /// - [`Error::InvalidArgument`] if `addr` is zero or `len` is
    ///   zero.
    pub fn submit_buffer(&mut self, addr: u64, len: u32) -> Result<u16> {
        if addr == 0 || len == 0 {
            return Err(Error::InvalidArgument);
        }
        let desc_idx = self.alloc_desc()?;
        self.descriptors[desc_idx as usize].set_write_buffer(addr, len);
        self.avail.push(desc_idx)?;
        Ok(desc_idx)
    }

    /// Check for completed buffers in the used ring.
    ///
    /// Returns the descriptor index and bytes written for the next
    /// completed entry, or `None` if no new completions are available.
    pub fn poll_used(&mut self) -> Option<(u16, u32)> {
        if self.last_used_idx == self.used.idx {
            return None;
        }
        let slot = (self.last_used_idx as usize) % VIRTQ_SIZE;
        let elem = self.used.ring[slot];
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id as u16, elem.len))
    }

    /// Return the number of free descriptors.
    pub fn free_count(&self) -> usize {
        self.free_count
    }
}

// ---------------------------------------------------------------------------
// EntropyPool
// ---------------------------------------------------------------------------

/// Local entropy pool with XOR-fold mixing.
///
/// Accumulates entropy from VirtIO-RNG completions and provides
/// mixed random bytes to callers. The pool uses a simple XOR-fold
/// to combine multiple entropy contributions.
pub struct EntropyPool {
    /// Pooled entropy data.
    pool: [u8; ENTROPY_POOL_SIZE],
    /// Number of valid bytes in the pool.
    valid: usize,
    /// Read offset for consuming bytes.
    read_offset: usize,
    /// Number of times the pool has been seeded.
    seed_count: u64,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyPool {
    /// Create an empty entropy pool.
    pub const fn new() -> Self {
        Self {
            pool: [0u8; ENTROPY_POOL_SIZE],
            valid: 0,
            read_offset: 0,
            seed_count: 0,
        }
    }

    /// Add entropy to the pool using XOR-fold mixing.
    ///
    /// Each byte in `data` is XORed into the pool at the current
    /// write position, wrapping around to provide mixing across
    /// the entire pool.
    pub fn add_entropy(&mut self, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let pos = (self.valid + i) % ENTROPY_POOL_SIZE;
            self.pool[pos] ^= byte;
        }
        let new_valid = self.valid.saturating_add(data.len());
        self.valid = if new_valid > ENTROPY_POOL_SIZE {
            ENTROPY_POOL_SIZE
        } else {
            new_valid
        };
        self.seed_count += 1;
    }

    /// Read bytes from the entropy pool into `dst`.
    ///
    /// Returns the number of bytes actually copied. If the pool
    /// is exhausted, returns 0.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        if self.valid == 0 {
            return 0;
        }
        let available = self.valid - self.read_offset;
        if available == 0 {
            return 0;
        }
        let copy_len = if dst.len() < available {
            dst.len()
        } else {
            available
        };
        dst[..copy_len].copy_from_slice(&self.pool[self.read_offset..self.read_offset + copy_len]);
        self.read_offset += copy_len;
        copy_len
    }

    /// Reset the read offset to allow re-reading the pool.
    ///
    /// Does not clear the entropy data. Use [`Self::clear`] to
    /// zero the pool entirely.
    pub fn reset_read(&mut self) {
        self.read_offset = 0;
    }

    /// Clear the entropy pool, zeroing all data.
    pub fn clear(&mut self) {
        self.pool.fill(0);
        self.valid = 0;
        self.read_offset = 0;
    }

    /// Return the number of valid entropy bytes in the pool.
    pub fn available(&self) -> usize {
        if self.read_offset >= self.valid {
            0
        } else {
            self.valid - self.read_offset
        }
    }

    /// Return the total number of seedings performed.
    pub fn seed_count(&self) -> u64 {
        self.seed_count
    }

    /// Return `true` if the pool has been seeded at least once.
    pub fn is_seeded(&self) -> bool {
        self.seed_count > 0
    }
}

// ---------------------------------------------------------------------------
// RngBuffer
// ---------------------------------------------------------------------------

/// A DMA-compatible buffer for entropy requests.
///
/// Each buffer holds up to [`RNG_BUFFER_SIZE`] bytes of entropy
/// received from the host. Buffers are submitted to the virtqueue
/// and reclaimed after the device fills them.
#[derive(Debug, Clone, Copy)]
pub struct RngBuffer {
    /// Buffer data.
    pub data: [u8; RNG_BUFFER_SIZE],
    /// Guest-physical address of this buffer (for DMA).
    pub phys_addr: u64,
    /// Number of valid bytes written by the device.
    pub valid_bytes: usize,
    /// Whether this buffer has been submitted to the virtqueue.
    pub submitted: bool,
    /// Descriptor index in the virtqueue (valid when submitted).
    pub desc_idx: u16,
}

impl Default for RngBuffer {
    fn default() -> Self {
        Self {
            data: [0u8; RNG_BUFFER_SIZE],
            phys_addr: 0,
            valid_bytes: 0,
            submitted: false,
            desc_idx: 0,
        }
    }
}

impl RngBuffer {
    /// Create a new RNG buffer with the given physical address.
    pub fn new(phys_addr: u64) -> Self {
        Self {
            data: [0u8; RNG_BUFFER_SIZE],
            phys_addr,
            valid_bytes: 0,
            submitted: false,
            desc_idx: 0,
        }
    }

    /// Reset the buffer contents and state for reuse.
    pub fn reset(&mut self) {
        self.data.fill(0);
        self.valid_bytes = 0;
        self.submitted = false;
        self.desc_idx = 0;
    }

    /// Return the valid data portion of the buffer.
    pub fn valid_data(&self) -> &[u8] {
        let len = if self.valid_bytes > RNG_BUFFER_SIZE {
            RNG_BUFFER_SIZE
        } else {
            self.valid_bytes
        };
        &self.data[..len]
    }
}

// ---------------------------------------------------------------------------
// VirtioRngState
// ---------------------------------------------------------------------------

/// Driver state machine for a VirtIO-RNG device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VirtioRngState {
    /// Device has not been discovered or reset.
    #[default]
    Reset,
    /// Device status ACKNOWLEDGE has been written.
    Acknowledged,
    /// Device status DRIVER has been written; feature negotiation.
    DriverLoaded,
    /// Feature negotiation succeeded; FEATURES_OK written.
    FeaturesOk,
    /// Driver is fully operational; DRIVER_OK written.
    Ready,
    /// Device has encountered an unrecoverable error.
    Failed,
}

// ---------------------------------------------------------------------------
// VirtioRng
// ---------------------------------------------------------------------------

/// VirtIO-RNG device driver.
///
/// Manages a single VirtIO entropy device with one virtqueue. The
/// driver submits empty buffers to the device, which fills them with
/// random bytes from the host's entropy source.
pub struct VirtioRng {
    /// Device identifier.
    pub device_id: u8,
    /// MMIO base address of the VirtIO transport.
    pub base_addr: u64,
    /// Current driver state.
    pub state: VirtioRngState,
    /// The single virtqueue used for entropy requests.
    pub vq: VirtQueue,
    /// Pre-allocated RNG buffers.
    buffers: [RngBuffer; MAX_RNG_BUFFERS],
    /// Number of buffers currently submitted.
    submitted_count: usize,
    /// Local entropy pool for mixing received data.
    pub pool: EntropyPool,
    /// VirtIO device status register value.
    status: u8,
    /// Total bytes of entropy received since initialisation.
    total_bytes_received: u64,
}

impl Default for VirtioRng {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioRng {
    /// Create an uninitialised VirtIO-RNG driver instance.
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            base_addr: 0,
            state: VirtioRngState::Reset,
            vq: VirtQueue::new(),
            buffers: [RngBuffer {
                data: [0u8; RNG_BUFFER_SIZE],
                phys_addr: 0,
                valid_bytes: 0,
                submitted: false,
                desc_idx: 0,
            }; MAX_RNG_BUFFERS],
            submitted_count: 0,
            pool: EntropyPool::new(),
            status: 0,
            total_bytes_received: 0,
        }
    }

    /// Initialise the VirtIO-RNG device.
    ///
    /// Performs the VirtIO device initialisation sequence:
    /// 1. Reset the device
    /// 2. Set ACKNOWLEDGE status bit
    /// 3. Set DRIVER status bit
    /// 4. Negotiate features (none for RNG)
    /// 5. Set FEATURES_OK
    /// 6. Initialise virtqueue
    /// 7. Set DRIVER_OK
    ///
    /// # Arguments
    ///
    /// * `device_id` — Unique device identifier.
    /// * `base_addr` — MMIO base address of the VirtIO transport.
    /// * `buffer_phys_addrs` — Physical addresses for the RNG
    ///   buffers. Must contain at least 1 and at most
    ///   [`MAX_RNG_BUFFERS`] entries.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `base_addr` is zero or
    ///   `buffer_phys_addrs` is empty.
    pub fn init(&mut self, device_id: u8, base_addr: u64, buffer_phys_addrs: &[u64]) -> Result<()> {
        if base_addr == 0 || buffer_phys_addrs.is_empty() {
            return Err(Error::InvalidArgument);
        }

        self.device_id = device_id;
        self.base_addr = base_addr;

        // Step 1: Reset
        self.status = 0;
        self.state = VirtioRngState::Reset;

        // Step 2: ACKNOWLEDGE
        self.status |= VIRTIO_STATUS_ACKNOWLEDGE;
        self.state = VirtioRngState::Acknowledged;

        // Step 3: DRIVER
        self.status |= VIRTIO_STATUS_DRIVER;
        self.state = VirtioRngState::DriverLoaded;

        // Step 4-5: Feature negotiation (RNG has no features)
        self.status |= VIRTIO_STATUS_FEATURES_OK;
        self.state = VirtioRngState::FeaturesOk;

        // Step 6: Initialise virtqueue
        self.vq.init();

        // Configure RNG buffers.
        let buf_count = if buffer_phys_addrs.len() > MAX_RNG_BUFFERS {
            MAX_RNG_BUFFERS
        } else {
            buffer_phys_addrs.len()
        };
        for i in 0..buf_count {
            self.buffers[i] = RngBuffer::new(buffer_phys_addrs[i]);
        }

        // Step 7: DRIVER_OK
        self.status |= VIRTIO_STATUS_DRIVER_OK;
        self.state = VirtioRngState::Ready;

        Ok(())
    }

    /// Request entropy by submitting all available buffers.
    ///
    /// Each unsubmitted buffer is configured as a device-writable
    /// descriptor and added to the virtqueue's available ring.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the device is not in the
    ///   [`VirtioRngState::Ready`] state.
    /// - [`Error::Busy`] if all buffers are already submitted.
    pub fn request_entropy(&mut self) -> Result<usize> {
        if self.state != VirtioRngState::Ready {
            return Err(Error::InvalidArgument);
        }

        let mut submitted = 0usize;
        for i in 0..MAX_RNG_BUFFERS {
            if self.buffers[i].submitted || self.buffers[i].phys_addr == 0 {
                continue;
            }
            let phys = self.buffers[i].phys_addr;
            match self.vq.submit_buffer(phys, RNG_BUFFER_SIZE as u32) {
                Ok(desc_idx) => {
                    self.buffers[i].submitted = true;
                    self.buffers[i].desc_idx = desc_idx;
                    self.submitted_count += 1;
                    submitted += 1;
                }
                Err(_) => break,
            }
        }

        if submitted == 0 {
            return Err(Error::Busy);
        }
        Ok(submitted)
    }

    /// Process completed entropy buffers.
    ///
    /// Polls the used ring for completed descriptors, copies the
    /// received entropy into the local pool, and reclaims the
    /// descriptors and buffers for reuse.
    ///
    /// Returns the total number of entropy bytes received in this
    /// call.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the device is not ready.
    pub fn fill_buffer(&mut self) -> Result<usize> {
        if self.state != VirtioRngState::Ready {
            return Err(Error::InvalidArgument);
        }

        let mut total_received = 0usize;

        while let Some((desc_idx, bytes_written)) = self.vq.poll_used() {
            // Find the buffer that was submitted with this descriptor.
            let buf_idx = self.find_buffer_by_desc(desc_idx);
            if let Some(idx) = buf_idx {
                let written = bytes_written as usize;
                let valid = if written > RNG_BUFFER_SIZE {
                    RNG_BUFFER_SIZE
                } else {
                    written
                };
                self.buffers[idx].valid_bytes = valid;

                // Add received entropy to the pool.
                let data_slice_end = valid;
                // Copy data to a temporary buffer to avoid borrow conflict.
                let mut tmp = [0u8; RNG_BUFFER_SIZE];
                tmp[..data_slice_end].copy_from_slice(&self.buffers[idx].data[..data_slice_end]);
                self.pool.add_entropy(&tmp[..data_slice_end]);

                total_received += valid;
                self.total_bytes_received += valid as u64;

                // Reclaim the buffer and descriptor.
                self.buffers[idx].reset();
                let _ = self.vq.free_desc(desc_idx);
                self.submitted_count = self.submitted_count.saturating_sub(1);
            }
        }

        Ok(total_received)
    }

    /// Get random bytes from the entropy pool.
    ///
    /// Reads up to `dst.len()` bytes from the pool. If the pool
    /// does not contain enough data, only the available bytes are
    /// returned.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the device is not ready.
    /// - [`Error::NotFound`] if the pool has not been seeded.
    pub fn get_random_bytes(&mut self, dst: &mut [u8]) -> Result<usize> {
        if self.state != VirtioRngState::Ready {
            return Err(Error::InvalidArgument);
        }
        if !self.pool.is_seeded() {
            return Err(Error::NotFound);
        }
        Ok(self.pool.read(dst))
    }

    /// Handle a VirtIO-RNG interrupt.
    ///
    /// Processes completed buffers and returns the number of bytes
    /// received. The caller should call [`Self::request_entropy`]
    /// after handling to replenish the submitted buffers.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the device is not ready.
    pub fn handle_interrupt(&mut self) -> Result<usize> {
        self.fill_buffer()
    }

    /// Reset the device to its initial state.
    ///
    /// Clears the virtqueue, entropy pool, and all buffers.
    pub fn reset(&mut self) {
        self.state = VirtioRngState::Reset;
        self.status = 0;
        self.vq = VirtQueue::new();
        for buf in &mut self.buffers {
            buf.reset();
        }
        self.submitted_count = 0;
        self.pool.clear();
    }

    /// Mark the device as failed.
    ///
    /// Sets the FAILED status bit and transitions to the
    /// [`VirtioRngState::Failed`] state.
    pub fn set_failed(&mut self) {
        self.status |= VIRTIO_STATUS_FAILED;
        self.state = VirtioRngState::Failed;
    }

    /// Return the total bytes of entropy received since init.
    pub fn total_bytes_received(&self) -> u64 {
        self.total_bytes_received
    }

    /// Return the number of entropy bytes available in the pool.
    pub fn available_entropy(&self) -> usize {
        self.pool.available()
    }

    /// Return `true` if the device is in the ready state.
    pub fn is_ready(&self) -> bool {
        self.state == VirtioRngState::Ready
    }

    /// Find the buffer index associated with a descriptor index.
    fn find_buffer_by_desc(&self, desc_idx: u16) -> Option<usize> {
        for (i, buf) in self.buffers.iter().enumerate() {
            if buf.submitted && buf.desc_idx == desc_idx {
                return Some(i);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// VirtioRngRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of VirtIO-RNG devices.
///
/// Tracks up to [`MAX_VIRTIO_RNG_DEVICES`] devices discovered during
/// PCI or MMIO transport enumeration. Provides convenience methods
/// for obtaining random bytes from the best available device.
pub struct VirtioRngRegistry {
    /// Registered VirtIO-RNG devices.
    devices: [Option<VirtioRng>; MAX_VIRTIO_RNG_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for VirtioRngRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioRngRegistry {
    /// Create an empty VirtIO-RNG device registry.
    pub const fn new() -> Self {
        const NONE: Option<VirtioRng> = None;
        Self {
            devices: [NONE; MAX_VIRTIO_RNG_DEVICES],
            count: 0,
        }
    }

    /// Register a new VirtIO-RNG device.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a device with the same
    ///   `device_id` is already registered.
    pub fn register(&mut self, device: VirtioRng) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.device_id == device.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a device by its identifier.
    pub fn find(&self, device_id: u8) -> Option<&VirtioRng> {
        self.devices
            .iter()
            .find_map(|slot| slot.as_ref().filter(|d| d.device_id == device_id))
    }

    /// Find a mutable reference to a device by its identifier.
    pub fn find_mut(&mut self, device_id: u8) -> Option<&mut VirtioRng> {
        self.devices
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|d| d.device_id == device_id))
    }

    /// Get random bytes from the first ready device.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no ready devices are registered.
    pub fn get_random_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        for slot in &mut self.devices {
            if let Some(dev) = slot {
                if dev.is_ready() {
                    return dev.get_random_bytes(buf);
                }
            }
        }
        Err(Error::NotFound)
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
