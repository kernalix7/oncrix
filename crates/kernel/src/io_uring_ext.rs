// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring extensions — linked SQEs, timeouts, fixed buffers, and CQ overflow.
//!
//! Extends the base [`super::io_uring`] subsystem with advanced features
//! inspired by Linux io_uring:
//!
//! - **Linked SQEs** ([`LinkedSqe`]) — chain operations so that failure
//!   of one entry cancels all subsequent entries in the chain.
//! - **Timeouts** ([`IoUringTimeout`]) — arm a timeout that fires after
//!   a duration or after N completions, whichever comes first.
//! - **Fixed buffers** ([`FixedBufferTable`]) — pre-register a set of
//!   buffers to avoid per-I/O address validation overhead.
//! - **CQ overflow ring** ([`CqOverflow`]) — secondary ring that absorbs
//!   completions when the primary CQ is full.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  IoUringExtRegistry (up to MAX_EXT_INSTANCES)           │
//! │                                                         │
//! │  ┌──────────────────────────────────────────────────┐   │
//! │  │ Instance N                                       │   │
//! │  │  IoUringParams   FixedBufferTable   CqOverflow   │   │
//! │  │  LinkedSqe[]     IoUringTimeout                  │   │
//! │  └──────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum io_uring extension instances system-wide.
const MAX_EXT_INSTANCES: usize = 32;

/// Maximum linked SQEs in a single chain.
const MAX_LINKED_CHAIN: usize = 16;

/// Number of pre-registered fixed buffer slots.
const FIXED_BUFFER_SLOTS: usize = 16;

/// Size of each fixed buffer in bytes (4 KiB).
const FIXED_BUFFER_SIZE: usize = 4096;

/// Number of entries in the CQ overflow ring.
const CQ_OVERFLOW_ENTRIES: usize = 64;

// ── IoUringExtFlags ──────────────────────────────────────────────

/// Setup flag: kernel-side submission queue polling.
pub const IORING_SETUP_SQPOLL: u32 = 1 << 0;

/// Setup flag: busy-poll for I/O completions.
pub const IORING_SETUP_IOPOLL: u32 = 1 << 1;

/// Setup flag: bind SQ poll thread to a specific CPU.
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;

/// SQE flag: this entry is linked to the next one.
///
/// If this SQE fails, all subsequent linked SQEs are cancelled
/// with `-ECANCELED`.
pub const IOSQE_IO_LINK: u8 = 1 << 0;

/// CQ flag: the overflow ring has been used.
pub const IORING_CQ_OVERFLOW: u32 = 1 << 0;

// ── IoUringExtParams ─────────────────────────────────────────────

/// Setup parameters for an extended io_uring instance.
///
/// Extends the base [`super::io_uring::IoUringParams`] with SQ poll
/// thread affinity and idle timeout settings.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoUringExtParams {
    /// Requested number of submission queue entries.
    pub sq_entries: u32,
    /// Requested number of completion queue entries.
    pub cq_entries: u32,
    /// Setup flags bitmask (`IORING_SETUP_*`).
    pub flags: u32,
    /// CPU to bind the SQ poll thread to (only meaningful when
    /// `IORING_SETUP_SQ_AFF` is set).
    pub sq_thread_cpu: u32,
    /// Idle timeout in milliseconds for the SQ poll thread (only
    /// meaningful when `IORING_SETUP_SQPOLL` is set).
    pub sq_thread_idle: u32,
}

impl IoUringExtParams {
    /// Create default parameters (256 SQEs, 512 CQEs, no flags).
    pub const fn new() -> Self {
        Self {
            sq_entries: 256,
            cq_entries: 512,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle: 1000,
        }
    }

    /// Validate the parameters.
    ///
    /// Returns `Err(InvalidArgument)` if entries counts are zero
    /// or not powers of two, or if unknown flag bits are set.
    pub const fn validate(&self) -> Result<()> {
        let known_flags = IORING_SETUP_SQPOLL | IORING_SETUP_IOPOLL | IORING_SETUP_SQ_AFF;
        if self.flags & !known_flags != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.sq_entries == 0 || self.cq_entries == 0 {
            return Err(Error::InvalidArgument);
        }
        if !self.sq_entries.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if !self.cq_entries.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check whether `IORING_SETUP_SQPOLL` is set.
    pub const fn sqpoll(&self) -> bool {
        self.flags & IORING_SETUP_SQPOLL != 0
    }

    /// Check whether `IORING_SETUP_IOPOLL` is set.
    pub const fn iopoll(&self) -> bool {
        self.flags & IORING_SETUP_IOPOLL != 0
    }

    /// Check whether `IORING_SETUP_SQ_AFF` is set.
    pub const fn sq_affinity(&self) -> bool {
        self.flags & IORING_SETUP_SQ_AFF != 0
    }
}

impl Default for IoUringExtParams {
    fn default() -> Self {
        Self::new()
    }
}

// ── Timespec ─────────────────────────────────────────────────────

/// POSIX-style time specification used for io_uring timeouts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new timespec.
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Check whether this timespec represents a zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Validate that nanoseconds are in the legal range.
    pub const fn validate(&self) -> Result<()> {
        if self.tv_sec < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── LinkedSqe ────────────────────────────────────────────────────

/// A submission queue entry with `IOSQE_IO_LINK` support.
///
/// When the `linked` flag is set, this SQE is chained with the next
/// entry. If this SQE fails (negative result), all subsequent linked
/// SQEs are cancelled with result `-125` (ECANCELED).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LinkedSqe {
    /// I/O operation opcode.
    pub opcode: u8,
    /// SQE flags — bit 0 is `IOSQE_IO_LINK`.
    pub flags: u8,
    /// Target file descriptor.
    pub fd: i32,
    /// Byte offset (opcode-dependent).
    pub offset: u64,
    /// User-space buffer address or opcode-dependent parameter.
    pub addr: u64,
    /// Buffer length or opcode-dependent parameter.
    pub len: u32,
    /// Opaque user data carried through to the completion entry.
    pub user_data: u64,
}

impl LinkedSqe {
    /// Create a new linked SQE.
    pub const fn new(
        opcode: u8,
        fd: i32,
        offset: u64,
        addr: u64,
        len: u32,
        user_data: u64,
    ) -> Self {
        Self {
            opcode,
            flags: IOSQE_IO_LINK,
            fd,
            offset,
            addr,
            len,
            user_data,
        }
    }

    /// Create a linked SQE that is the last entry in a chain (no link flag).
    pub const fn tail(
        opcode: u8,
        fd: i32,
        offset: u64,
        addr: u64,
        len: u32,
        user_data: u64,
    ) -> Self {
        Self {
            opcode,
            flags: 0,
            fd,
            offset,
            addr,
            len,
            user_data,
        }
    }

    /// Check whether this SQE is linked to the next entry.
    pub const fn is_linked(&self) -> bool {
        self.flags & IOSQE_IO_LINK != 0
    }
}

impl Default for LinkedSqe {
    fn default() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            fd: -1,
            offset: 0,
            addr: 0,
            len: 0,
            user_data: 0,
        }
    }
}

// ── LinkedChainResult ────────────────────────────────────────────

/// Result of processing a linked SQE chain.
#[derive(Debug, Clone, Copy)]
pub struct LinkedChainResult {
    /// User data from the SQE.
    pub user_data: u64,
    /// Result code: >= 0 on success, negative errno on failure.
    pub result: i32,
    /// Whether this entry was cancelled due to a prior failure.
    pub cancelled: bool,
}

impl LinkedChainResult {
    /// Create a new chain result.
    pub const fn new(user_data: u64, result: i32, cancelled: bool) -> Self {
        Self {
            user_data,
            result,
            cancelled,
        }
    }
}

// ── IoUringTimeout ───────────────────────────────────────────────

/// Timeout specification for an io_uring instance.
///
/// A timeout fires when either the specified duration elapses or
/// `count` completion events have been produced, whichever comes
/// first. Setting `count` to 0 means duration-only.
#[derive(Debug, Clone, Copy)]
pub struct IoUringTimeout {
    /// Absolute or relative timeout value.
    pub timeout_ts: Timespec,
    /// Number of completions after which the timeout triggers
    /// (0 = duration-only).
    pub count: u32,
    /// Timeout flags (reserved for future use).
    pub flags: u32,
    /// Whether this timeout is armed.
    armed: bool,
    /// Number of completions observed since the timeout was armed.
    completions_seen: u32,
}

impl IoUringTimeout {
    /// Create a new timeout specification.
    pub const fn new(timeout_ts: Timespec, count: u32, flags: u32) -> Self {
        Self {
            timeout_ts,
            count,
            flags,
            armed: false,
            completions_seen: 0,
        }
    }

    /// Arm this timeout, resetting the completion counter.
    pub fn arm(&mut self) {
        self.armed = true;
        self.completions_seen = 0;
    }

    /// Disarm this timeout.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Check whether this timeout is armed.
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Record a completion event and check if the count threshold
    /// has been reached.
    ///
    /// Returns `true` if the timeout should fire because `count`
    /// completions have been observed.
    pub fn record_completion(&mut self) -> bool {
        if !self.armed || self.count == 0 {
            return false;
        }
        self.completions_seen = self.completions_seen.saturating_add(1);
        self.completions_seen >= self.count
    }
}

impl Default for IoUringTimeout {
    fn default() -> Self {
        Self::new(Timespec::default(), 0, 0)
    }
}

// ── FixedBuffer ──────────────────────────────────────────────────

/// A single pre-registered fixed buffer (4 KiB).
#[derive(Clone)]
struct FixedBuffer {
    /// Buffer contents.
    data: [u8; FIXED_BUFFER_SIZE],
    /// Whether this buffer slot is registered and valid.
    registered: bool,
    /// Logical length of valid data in the buffer.
    len: usize,
}

impl FixedBuffer {
    /// Create an empty, unregistered buffer.
    const fn empty() -> Self {
        Self {
            data: [0u8; FIXED_BUFFER_SIZE],
            registered: false,
            len: 0,
        }
    }
}

// ── FixedBufferTable ─────────────────────────────────────────────

/// Table of pre-registered fixed I/O buffers.
///
/// Pre-registering buffers avoids per-I/O user-pointer validation
/// overhead. Each buffer is [`FIXED_BUFFER_SIZE`] bytes (4 KiB).
/// Up to [`FIXED_BUFFER_SLOTS`] buffers can be registered.
pub struct FixedBufferTable {
    /// Fixed buffer slots.
    buffers: [FixedBuffer; FIXED_BUFFER_SLOTS],
    /// Number of currently registered buffers.
    registered_count: usize,
}

impl FixedBufferTable {
    /// Create an empty buffer table with no registered buffers.
    pub const fn new() -> Self {
        Self {
            buffers: [const { FixedBuffer::empty() }; FIXED_BUFFER_SLOTS],
            registered_count: 0,
        }
    }

    /// Register a buffer at the given index.
    ///
    /// Copies `data` into the fixed buffer slot. Returns
    /// `Err(InvalidArgument)` if the index is out of range or
    /// `data` exceeds [`FIXED_BUFFER_SIZE`]. Returns
    /// `Err(AlreadyExists)` if the slot is already registered.
    pub fn register(&mut self, index: usize, data: &[u8]) -> Result<()> {
        let buf = self.buffers.get_mut(index).ok_or(Error::InvalidArgument)?;
        if buf.registered {
            return Err(Error::AlreadyExists);
        }
        if data.len() > FIXED_BUFFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf.data[..data.len()].copy_from_slice(data);
        buf.len = data.len();
        buf.registered = true;
        self.registered_count = self.registered_count.saturating_add(1);
        Ok(())
    }

    /// Unregister the buffer at the given index.
    ///
    /// Returns `Err(InvalidArgument)` if the index is out of range
    /// or `Err(NotFound)` if the slot is not registered.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        let buf = self.buffers.get_mut(index).ok_or(Error::InvalidArgument)?;
        if !buf.registered {
            return Err(Error::NotFound);
        }
        *buf = FixedBuffer::empty();
        self.registered_count = self.registered_count.saturating_sub(1);
        Ok(())
    }

    /// Access the data in a registered buffer by index.
    ///
    /// Returns a slice of the valid data within the buffer.
    /// Returns `Err(InvalidArgument)` if the index is out of range
    /// or `Err(NotFound)` if the slot is not registered.
    pub fn get(&self, index: usize) -> Result<&[u8]> {
        let buf = self.buffers.get(index).ok_or(Error::InvalidArgument)?;
        if !buf.registered {
            return Err(Error::NotFound);
        }
        Ok(&buf.data[..buf.len])
    }

    /// Write data into a registered buffer by index.
    ///
    /// Returns `Err(InvalidArgument)` if the index is out of range,
    /// `data` exceeds buffer capacity, or `Err(NotFound)` if the
    /// slot is not registered.
    pub fn write(&mut self, index: usize, data: &[u8]) -> Result<()> {
        let buf = self.buffers.get_mut(index).ok_or(Error::InvalidArgument)?;
        if !buf.registered {
            return Err(Error::NotFound);
        }
        if data.len() > FIXED_BUFFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf.data[..data.len()].copy_from_slice(data);
        buf.len = data.len();
        Ok(())
    }

    /// Return the number of registered buffers.
    pub const fn count(&self) -> usize {
        self.registered_count
    }

    /// Return the total capacity of the buffer table.
    pub const fn capacity(&self) -> usize {
        FIXED_BUFFER_SLOTS
    }

    /// Return the size of each individual buffer in bytes.
    pub const fn buffer_size(&self) -> usize {
        FIXED_BUFFER_SIZE
    }
}

impl Default for FixedBufferTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── CqOverflowEntry ─────────────────────────────────────────────

/// A completion entry stored in the overflow ring.
#[derive(Debug, Clone, Copy, Default)]
struct CqOverflowEntry {
    /// Opaque user data from the corresponding SQE.
    user_data: u64,
    /// Result value.
    res: i32,
    /// Completion flags.
    flags: u32,
}

// ── CqOverflow ───────────────────────────────────────────────────

/// Secondary overflow ring for completion entries.
///
/// When the primary CQ is full, completions are diverted to this
/// ring. The `IORING_CQ_OVERFLOW` flag is set to signal user space
/// that the overflow ring should be drained.
pub struct CqOverflow {
    /// Overflow ring entries.
    entries: [CqOverflowEntry; CQ_OVERFLOW_ENTRIES],
    /// Consumer index.
    head: u32,
    /// Producer index.
    tail: u32,
    /// Bitmask for wrapping.
    mask: u32,
    /// Aggregate CQ flags (includes `IORING_CQ_OVERFLOW` when
    /// overflow entries are present).
    cq_flags: u32,
}

impl CqOverflow {
    /// Create an empty overflow ring.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                CqOverflowEntry {
                    user_data: 0,
                    res: 0,
                    flags: 0,
                }
            }; CQ_OVERFLOW_ENTRIES],
            head: 0,
            tail: 0,
            mask: (CQ_OVERFLOW_ENTRIES as u32).wrapping_sub(1),
            cq_flags: 0,
        }
    }

    /// Return the number of pending overflow entries.
    pub const fn pending(&self) -> u32 {
        self.tail.wrapping_sub(self.head)
    }

    /// Check whether the overflow ring is full.
    pub const fn is_full(&self) -> bool {
        self.pending() >= CQ_OVERFLOW_ENTRIES as u32
    }

    /// Check whether the overflow ring is empty.
    pub const fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Push a completion into the overflow ring.
    ///
    /// Sets the `IORING_CQ_OVERFLOW` flag. Returns
    /// `Err(OutOfMemory)` if the overflow ring itself is full.
    pub fn push(&mut self, user_data: u64, res: i32, flags: u32) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let idx = (self.tail & self.mask) as usize;
        self.entries[idx] = CqOverflowEntry {
            user_data,
            res,
            flags,
        };
        self.tail = self.tail.wrapping_add(1);
        self.cq_flags |= IORING_CQ_OVERFLOW;
        Ok(())
    }

    /// Pop the next overflow entry.
    ///
    /// Returns `(user_data, res, flags)` or `None` if empty.
    /// Clears the `IORING_CQ_OVERFLOW` flag when the ring becomes
    /// empty.
    pub fn pop(&mut self) -> Option<(u64, i32, u32)> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head & self.mask) as usize;
        let entry = self.entries[idx];
        self.entries[idx] = CqOverflowEntry::default();
        self.head = self.head.wrapping_add(1);
        if self.is_empty() {
            self.cq_flags &= !IORING_CQ_OVERFLOW;
        }
        Some((entry.user_data, entry.res, entry.flags))
    }

    /// Return the current CQ flags bitmask.
    pub const fn cq_flags(&self) -> u32 {
        self.cq_flags
    }

    /// Return the overflow ring capacity.
    pub const fn capacity(&self) -> usize {
        CQ_OVERFLOW_ENTRIES
    }
}

impl Default for CqOverflow {
    fn default() -> Self {
        Self::new()
    }
}

// ── IoUringExtInstance ────────────────────────────────────────────

/// A single extended io_uring instance with linked SQE, timeout,
/// fixed buffer, and CQ overflow support.
struct IoUringExtInstance {
    /// Setup parameters.
    params: IoUringExtParams,
    /// Pre-registered fixed buffers.
    buffers: FixedBufferTable,
    /// CQ overflow ring.
    overflow: CqOverflow,
    /// Timeout configuration for this instance.
    timeout: IoUringTimeout,
    /// Whether this instance slot is in use.
    in_use: bool,
}

impl IoUringExtInstance {
    /// Create an inactive instance.
    const fn empty() -> Self {
        Self {
            params: IoUringExtParams::new(),
            buffers: FixedBufferTable::new(),
            overflow: CqOverflow::new(),
            timeout: IoUringTimeout::new(Timespec::new(0, 0), 0, 0),
            in_use: false,
        }
    }
}

// ── IoUringExtRegistry ───────────────────────────────────────────

/// System-wide registry of extended io_uring instances.
///
/// Manages up to [`MAX_EXT_INSTANCES`] concurrent extended io_uring
/// instances, each supporting linked SQEs, timeouts, fixed buffers,
/// and CQ overflow.
pub struct IoUringExtRegistry {
    /// Fixed array of instance slots.
    instances: [IoUringExtInstance; MAX_EXT_INSTANCES],
}

impl Default for IoUringExtRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IoUringExtRegistry {
    /// Create an empty registry with no active instances.
    pub const fn new() -> Self {
        Self {
            instances: [const { IoUringExtInstance::empty() }; MAX_EXT_INSTANCES],
        }
    }

    /// Create a new extended io_uring instance with the given parameters.
    ///
    /// Returns the instance ID on success. Fails with
    /// `InvalidArgument` if parameters are invalid, or
    /// `OutOfMemory` if all slots are occupied.
    pub fn create_with_params(&mut self, params: IoUringExtParams) -> Result<usize> {
        params.validate()?;

        for (id, inst) in self.instances.iter_mut().enumerate() {
            if !inst.in_use {
                inst.params = params;
                inst.buffers = FixedBufferTable::new();
                inst.overflow = CqOverflow::new();
                inst.timeout = IoUringTimeout::default();
                inst.in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Register a fixed buffer for the given instance.
    ///
    /// Copies `data` into the buffer slot at `buf_index`.
    pub fn register_buffers(&mut self, id: usize, buf_index: usize, data: &[u8]) -> Result<()> {
        let inst = self.get_instance_mut(id)?;
        inst.buffers.register(buf_index, data)
    }

    /// Unregister a fixed buffer for the given instance.
    pub fn unregister_buffers(&mut self, id: usize, buf_index: usize) -> Result<()> {
        let inst = self.get_instance_mut(id)?;
        inst.buffers.unregister(buf_index)
    }

    /// Access a registered fixed buffer.
    pub fn get_buffer(&self, id: usize, buf_index: usize) -> Result<&[u8]> {
        let inst = self.get_instance(id)?;
        inst.buffers.get(buf_index)
    }

    /// Submit a chain of linked SQEs.
    ///
    /// Processes each SQE in order. If any linked SQE fails (negative
    /// result), all subsequent linked SQEs are cancelled with result
    /// `-125` (ECANCELED). Results are written to `results`.
    ///
    /// Returns the number of entries processed.
    pub fn submit_linked(
        &mut self,
        id: usize,
        chain: &[LinkedSqe],
        results: &mut [LinkedChainResult],
    ) -> Result<usize> {
        let inst = self.get_instance_mut(id)?;

        if chain.is_empty() {
            return Ok(0);
        }

        let count = chain.len().min(MAX_LINKED_CHAIN).min(results.len());
        let mut cancel_rest = false;

        for i in 0..count {
            let sqe = &chain[i];
            if cancel_rest {
                // Cancel due to prior linked failure.
                results[i] = LinkedChainResult::new(sqe.user_data, -125, true);
                // Push to overflow if we were going to produce CQEs.
                let _ = inst.overflow.push(sqe.user_data, -125, 0);
            } else {
                // Stub processing: validate minimal preconditions.
                let res = process_linked_sqe(sqe);
                results[i] = LinkedChainResult::new(sqe.user_data, res, false);
                let _ = inst.overflow.push(sqe.user_data, res, 0);

                // If this SQE is linked and failed, cancel the rest.
                if res < 0 && sqe.is_linked() {
                    cancel_rest = true;
                }
            }

            // Record completion for timeout tracking.
            if inst.timeout.record_completion() {
                inst.timeout.disarm();
            }
        }

        Ok(count)
    }

    /// Add a timeout to an instance.
    ///
    /// The timeout fires after `timeout.timeout_ts` elapses or after
    /// `timeout.count` completions, whichever comes first.
    pub fn add_timeout(&mut self, id: usize, timeout: IoUringTimeout) -> Result<()> {
        timeout.timeout_ts.validate()?;
        let inst = self.get_instance_mut(id)?;
        inst.timeout = timeout;
        inst.timeout.arm();
        Ok(())
    }

    /// Check whether the timeout for an instance has been triggered
    /// by completion count.
    pub fn is_timeout_fired(&self, id: usize) -> Result<bool> {
        let inst = self.get_instance(id)?;
        Ok(!inst.timeout.is_armed() && inst.timeout.count > 0)
    }

    /// Get the CQ overflow flags for an instance.
    pub fn overflow_flags(&self, id: usize) -> Result<u32> {
        let inst = self.get_instance(id)?;
        Ok(inst.overflow.cq_flags())
    }

    /// Drain one entry from the overflow ring.
    pub fn drain_overflow(&mut self, id: usize) -> Result<Option<(u64, i32, u32)>> {
        let inst = self.get_instance_mut(id)?;
        Ok(inst.overflow.pop())
    }

    /// Get the setup parameters for an instance.
    pub fn params(&self, id: usize) -> Result<&IoUringExtParams> {
        let inst = self.get_instance(id)?;
        Ok(&inst.params)
    }

    /// Destroy an extended io_uring instance, freeing its slot.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let inst = self.get_instance_mut(id)?;
        *inst = IoUringExtInstance::empty();
        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Get a shared reference to an active instance.
    fn get_instance(&self, id: usize) -> Result<&IoUringExtInstance> {
        let inst = self.instances.get(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        Ok(inst)
    }

    /// Get a mutable reference to an active instance.
    fn get_instance_mut(&mut self, id: usize) -> Result<&mut IoUringExtInstance> {
        let inst = self.instances.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        Ok(inst)
    }
}

// ── Linked SQE processing stub ──────────────────────────────────

/// Dispatch a single linked SQE (stub implementation).
///
/// Validates minimal preconditions and returns `-38` (ENOSYS) for
/// all operations, mirroring the base io_uring stub pattern.
fn process_linked_sqe(sqe: &LinkedSqe) -> i32 {
    if sqe.fd < 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS — not yet wired to real I/O backends
}
