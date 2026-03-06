// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O subsystem.
//!
//! Provides the block I/O layer that bridges the VFS and block device
//! drivers. This module defines:
//!
//! - [`BioRequest`] — a single block I/O request
//! - [`BioQueue`] — a fixed-capacity I/O request queue
//! - [`BlockDevice`] — trait for block device drivers
//! - [`BlockDeviceRegistry`] — device registration and lookup
//! - [`IoScheduler`] — elevator (SCAN) I/O scheduler

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sector size in bytes (standard 512-byte sectors).
pub const SECTOR_SIZE: u32 = 512;

/// Maximum number of sectors per single I/O request.
pub const MAX_SECTORS_PER_REQUEST: u32 = 8;

/// Maximum number of pending I/O requests in a queue.
pub const MAX_BIO_REQUESTS: usize = 64;

/// Maximum number of registered block devices.
const MAX_BLOCK_DEVICES: usize = 8;

/// Maximum device name length in bytes.
const MAX_DEVICE_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// BioOp — I/O operation type
// ---------------------------------------------------------------------------

/// Block I/O operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// Read sectors from the device.
    Read,
    /// Write sectors to the device.
    Write,
    /// Flush device write caches to stable storage.
    Flush,
    /// Discard (trim) sectors — hint that data is no longer needed.
    Discard,
}

// ---------------------------------------------------------------------------
// BioStatus — request lifecycle status
// ---------------------------------------------------------------------------

/// Status of a block I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioStatus {
    /// Request is queued but not yet started.
    Pending,
    /// Request is currently being processed by the device.
    InProgress,
    /// Request completed successfully.
    Complete,
    /// Request failed with an error.
    Error,
}

// ---------------------------------------------------------------------------
// BioPriority — request priority levels
// ---------------------------------------------------------------------------

/// Priority level for block I/O requests.
///
/// Higher priority requests are dequeued first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BioPriority {
    /// Low priority — background I/O (prefetch, writeback).
    Low = 0,
    /// Normal priority — regular user I/O.
    Normal = 1,
    /// High priority — latency-sensitive I/O.
    High = 2,
    /// Critical priority — filesystem metadata, journal.
    Critical = 3,
}

// ---------------------------------------------------------------------------
// BioRequest — a single block I/O request
// ---------------------------------------------------------------------------

/// A single block I/O request.
///
/// Each request targets a contiguous range of sectors on a specific
/// device. The embedded buffer holds up to 8 sectors (4096 bytes).
#[derive(Clone)]
pub struct BioRequest {
    /// Operation type (read, write, flush, discard).
    pub op: BioOp,
    /// Target block device identifier.
    pub device_id: u32,
    /// Starting 512-byte sector number.
    pub sector: u64,
    /// Number of sectors to transfer (max [`MAX_SECTORS_PER_REQUEST`]).
    pub count: u32,
    /// Data buffer (max 8 sectors = 4096 bytes).
    pub buffer: [u8; 4096],
    /// Current request status.
    pub status: BioStatus,
    /// Request scheduling priority.
    pub priority: BioPriority,
}

impl BioRequest {
    /// Create a new block I/O request with default (zeroed) buffer.
    pub fn new(op: BioOp, device_id: u32, sector: u64, count: u32, priority: BioPriority) -> Self {
        Self {
            op,
            device_id,
            sector,
            count,
            buffer: [0u8; 4096],
            status: BioStatus::Pending,
            priority,
        }
    }
}

impl core::fmt::Debug for BioRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BioRequest")
            .field("op", &self.op)
            .field("device_id", &self.device_id)
            .field("sector", &self.sector)
            .field("count", &self.count)
            .field("status", &self.status)
            .field("priority", &self.priority)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// BioQueue — fixed-capacity I/O request queue
// ---------------------------------------------------------------------------

/// Slot in the I/O request queue.
struct BioSlot {
    /// The request stored in this slot.
    request: BioRequest,
    /// Whether this slot is occupied.
    active: bool,
    /// Monotonic ID assigned at submission time.
    id: usize,
}

/// Fixed-capacity block I/O request queue.
///
/// Supports up to [`MAX_BIO_REQUESTS`] concurrent requests. Each
/// submitted request receives a unique ID that can be used to query
/// status or cancel the request.
pub struct BioQueue {
    /// Request slots.
    slots: [Option<BioSlot>; MAX_BIO_REQUESTS],
    /// Next request ID to assign (monotonically increasing).
    next_id: usize,
}

impl Default for BioQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl BioQueue {
    /// Create a new, empty I/O request queue.
    pub const fn new() -> Self {
        const NONE: Option<BioSlot> = None;
        Self {
            slots: [NONE; MAX_BIO_REQUESTS],
            next_id: 0,
        }
    }

    /// Submit a request to the queue.
    ///
    /// Returns a unique request ID that can be used with
    /// [`complete`](Self::complete), [`get_status`](Self::get_status),
    /// or [`cancel`](Self::cancel).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the queue is full.
    /// Returns [`Error::InvalidArgument`] if `count` exceeds
    /// [`MAX_SECTORS_PER_REQUEST`].
    pub fn submit(&mut self, request: BioRequest) -> Result<usize> {
        if request.count > MAX_SECTORS_PER_REQUEST {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self.find_free_slot()?;
        let id = self.next_id;
        // Wrap-safe increment using wrapping arithmetic.
        self.next_id = self.next_id.wrapping_add(1);

        self.slots[slot_idx] = Some(BioSlot {
            request,
            active: true,
            id,
        });

        Ok(id)
    }

    /// Dequeue the highest-priority pending request.
    ///
    /// Returns `(request_id, request)` for the highest-priority
    /// pending request, or `None` if no pending requests exist.
    /// The request status is changed to [`BioStatus::InProgress`].
    pub fn dequeue(&mut self) -> Option<(usize, BioRequest)> {
        let mut best_idx: Option<usize> = None;
        let mut best_priority = BioPriority::Low;

        for (i, slot_opt) in self.slots.iter().enumerate() {
            if let Some(slot) = slot_opt {
                if slot.active
                    && slot.request.status == BioStatus::Pending
                    && (best_idx.is_none() || slot.request.priority > best_priority)
                {
                    best_idx = Some(i);
                    best_priority = slot.request.priority;
                }
            }
        }

        let idx = best_idx?;
        if let Some(ref mut slot) = self.slots[idx] {
            slot.request.status = BioStatus::InProgress;
            Some((slot.id, slot.request.clone()))
        } else {
            None
        }
    }

    /// Mark a request as complete with the given status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active request with the
    /// given ID exists.
    pub fn complete(&mut self, id: usize, status: BioStatus) -> Result<()> {
        for slot in self.slots.iter_mut().flatten() {
            if slot.id == id && slot.active {
                slot.request.status = status;
                slot.active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Query the status of a request by ID.
    ///
    /// Returns `None` if the ID is not found in the queue.
    pub fn get_status(&self, id: usize) -> Option<BioStatus> {
        for slot in self.slots.iter().flatten() {
            if slot.id == id {
                return Some(slot.request.status);
            }
        }
        None
    }

    /// Return the number of pending (not yet started) requests.
    pub fn pending_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    Some(slot) if slot.active
                        && slot.request.status == BioStatus::Pending
                )
            })
            .count()
    }

    /// Cancel a pending request.
    ///
    /// Only requests with [`BioStatus::Pending`] can be cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID does not exist.
    /// Returns [`Error::Busy`] if the request is already in progress.
    pub fn cancel(&mut self, id: usize) -> Result<()> {
        for slot_opt in self.slots.iter_mut() {
            if let Some(slot) = slot_opt {
                if slot.id == id && slot.active {
                    if slot.request.status != BioStatus::Pending {
                        return Err(Error::Busy);
                    }
                    slot.active = false;
                    *slot_opt = None;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a free slot in the queue.
    fn find_free_slot(&self) -> Result<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.is_none() || !slot.as_ref().is_some_and(|s| s.active) {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }
}

// ---------------------------------------------------------------------------
// BlockDevice trait
// ---------------------------------------------------------------------------

/// Trait for block device drivers.
///
/// Implementations provide sector-level read/write access to a block
/// device. The block I/O layer dispatches [`BioRequest`]s to the
/// appropriate device via this interface.
pub trait BlockDevice {
    /// Return the device sector size in bytes (typically 512).
    fn sector_size(&self) -> u32;

    /// Return the total number of sectors on the device.
    fn total_sectors(&self) -> u64;

    /// Read `count` sectors starting at `start` into `buf`.
    ///
    /// `buf` must be at least `count * sector_size()` bytes.
    fn read_sectors(&mut self, start: u64, count: u32, buf: &mut [u8]) -> Result<()>;

    /// Write `count` sectors starting at `start` from `buf`.
    ///
    /// `buf` must be at least `count * sector_size()` bytes.
    fn write_sectors(&mut self, start: u64, count: u32, buf: &[u8]) -> Result<()>;

    /// Flush any cached writes to stable storage.
    fn flush(&mut self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// BlockDeviceInfo — device metadata
// ---------------------------------------------------------------------------

/// Metadata for a registered block device.
#[derive(Debug, Clone, Copy)]
pub struct BlockDeviceInfo {
    /// Human-readable device name (e.g., b"vda", b"sda").
    pub name: [u8; MAX_DEVICE_NAME_LEN],
    /// Length of the valid portion of `name`.
    pub name_len: usize,
    /// Sector size in bytes.
    pub sector_size: u32,
    /// Total number of sectors on the device.
    pub total_sectors: u64,
    /// Whether the device is read-only.
    pub read_only: bool,
}

// ---------------------------------------------------------------------------
// BlockDeviceRegistry — device registration
// ---------------------------------------------------------------------------

/// Registry slot for a block device.
struct RegistrySlot {
    /// Device metadata.
    info: BlockDeviceInfo,
    /// Whether this slot is occupied.
    active: bool,
}

/// Registry of block devices.
///
/// Supports up to [`MAX_BLOCK_DEVICES`] (8) concurrently registered
/// devices. Each device is assigned a unique numeric ID (its slot
/// index) at registration time.
pub struct BlockDeviceRegistry {
    /// Device slots.
    slots: [Option<RegistrySlot>; MAX_BLOCK_DEVICES],
}

impl Default for BlockDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDeviceRegistry {
    /// Create a new, empty device registry.
    pub const fn new() -> Self {
        const NONE: Option<RegistrySlot> = None;
        Self {
            slots: [NONE; MAX_BLOCK_DEVICES],
        }
    }

    /// Register a new block device.
    ///
    /// Returns the assigned device ID (slot index).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the registry is full.
    /// Returns [`Error::InvalidArgument`] if `name` is empty or
    /// exceeds 32 bytes.
    pub fn register(&mut self, name: &[u8], sector_size: u32, total_sectors: u64) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_DEVICE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self.find_free_slot()?;

        let mut info = BlockDeviceInfo {
            name: [0u8; MAX_DEVICE_NAME_LEN],
            name_len: name.len(),
            sector_size,
            total_sectors,
            read_only: false,
        };
        info.name[..name.len()].copy_from_slice(name);

        self.slots[slot_idx] = Some(RegistrySlot { info, active: true });

        Ok(slot_idx as u32)
    }

    /// Unregister a block device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device ID is invalid or
    /// already unregistered.
    pub fn unregister(&mut self, device_id: u32) -> Result<()> {
        let idx = device_id as usize;
        if idx >= MAX_BLOCK_DEVICES {
            return Err(Error::NotFound);
        }
        match self.slots[idx] {
            Some(ref slot) if slot.active => {
                self.slots[idx] = None;
                Ok(())
            }
            _ => Err(Error::NotFound),
        }
    }

    /// Look up device information by ID.
    ///
    /// Returns `None` if the device ID is invalid or unregistered.
    pub fn get_info(&self, device_id: u32) -> Option<BlockDeviceInfo> {
        let idx = device_id as usize;
        if idx >= MAX_BLOCK_DEVICES {
            return None;
        }
        self.slots[idx]
            .as_ref()
            .filter(|s| s.active)
            .map(|s| s.info)
    }

    /// Find a free slot in the registry.
    fn find_free_slot(&self) -> Result<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.is_none() || !slot.as_ref().is_some_and(|s| s.active) {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }
}

// ---------------------------------------------------------------------------
// ScanDirection — elevator direction
// ---------------------------------------------------------------------------

/// Direction of the elevator (SCAN) I/O scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDirection {
    /// Scanning toward higher sector numbers.
    Up,
    /// Scanning toward lower sector numbers.
    Down,
}

// ---------------------------------------------------------------------------
// IoScheduler — SCAN (elevator) scheduler
// ---------------------------------------------------------------------------

/// Elevator (SCAN) I/O scheduler.
///
/// Sorts I/O requests by sector number and services them in the
/// current scan direction, reversing direction when no more requests
/// exist ahead. This minimizes seek distance on rotational media.
pub struct IoScheduler {
    /// Pending requests waiting to be dispatched.
    requests: [Option<BioRequest>; MAX_BIO_REQUESTS],
    /// Number of pending requests.
    count: usize,
    /// Current scan direction.
    pub direction: ScanDirection,
    /// Current head position (sector number).
    pub current_sector: u64,
}

impl Default for IoScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl IoScheduler {
    /// Create a new I/O scheduler starting at sector 0, scanning up.
    pub const fn new() -> Self {
        const NONE: Option<BioRequest> = None;
        Self {
            requests: [NONE; MAX_BIO_REQUESTS],
            count: 0,
            direction: ScanDirection::Up,
            current_sector: 0,
        }
    }

    /// Add a request to the scheduler.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the scheduler queue is full.
    pub fn add_request(&mut self, req: BioRequest) -> Result<()> {
        if self.count >= MAX_BIO_REQUESTS {
            return Err(Error::Busy);
        }

        for slot in self.requests.iter_mut() {
            if slot.is_none() {
                *slot = Some(req);
                self.count = self.count.saturating_add(1);
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Get the next request according to the elevator algorithm.
    ///
    /// Picks the closest request in the current scan direction. If
    /// no requests remain in that direction, reverses direction and
    /// picks the closest request going the other way.
    ///
    /// Returns `None` if no requests are pending.
    pub fn next_request(&mut self) -> Option<BioRequest> {
        if self.count == 0 {
            return None;
        }

        // Try current direction first.
        let idx = self.find_nearest_in_direction(self.direction);
        if let Some(i) = idx {
            return self.take_request(i);
        }

        // Reverse direction and try again.
        self.direction = match self.direction {
            ScanDirection::Up => ScanDirection::Down,
            ScanDirection::Down => ScanDirection::Up,
        };

        let idx = self.find_nearest_in_direction(self.direction);
        if let Some(i) = idx {
            return self.take_request(i);
        }

        None
    }

    /// Find the index of the nearest request in the given direction.
    fn find_nearest_in_direction(&self, direction: ScanDirection) -> Option<usize> {
        let mut best_idx: Option<usize> = None;
        let mut best_sector: u64 = match direction {
            ScanDirection::Up => u64::MAX,
            ScanDirection::Down => 0,
        };

        for (i, slot) in self.requests.iter().enumerate() {
            if let Some(req) = slot {
                match direction {
                    ScanDirection::Up => {
                        if req.sector >= self.current_sector && req.sector < best_sector {
                            best_sector = req.sector;
                            best_idx = Some(i);
                        }
                    }
                    ScanDirection::Down => {
                        if req.sector <= self.current_sector && req.sector > best_sector {
                            best_sector = req.sector;
                            best_idx = Some(i);
                        }
                    }
                }
            }
        }

        best_idx
    }

    /// Remove a request from the scheduler and update head position.
    fn take_request(&mut self, idx: usize) -> Option<BioRequest> {
        let req = self.requests[idx].take()?;
        self.count = self.count.saturating_sub(1);
        self.current_sector = req.sector;
        Some(req)
    }
}
