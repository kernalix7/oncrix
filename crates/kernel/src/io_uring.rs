// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring-style asynchronous I/O interface.
//!
//! Provides a high-performance, zero-copy async I/O mechanism inspired
//! by Linux's io_uring. Applications submit I/O requests via a
//! [`SubmissionQueue`] and receive completions via a
//! [`CompletionQueue`], both implemented as lock-free ring buffers
//! shared between kernel and user space.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//!   User space                                       │
//! │                                                  │
//! │  ┌──────────────┐        ┌──────────────┐       │
//! │  │ SQ (256 SQE) │ ──────▶│ CQ (512 CQE) │       │
//! │  │ head ──▶ tail │        │ head ──▶ tail │       │
//! │  └──────────────┘        └──────────────┘       │
//! │         │                        ▲               │
//! └─────────┼────────────────────────┼───────────────┘
//!           │  submit                │  complete
//! ┌─────────▼────────────────────────┼───────────────┐
//! │         IoUring::submit_and_complete              │
//! │                                                   │
//! │         process_sqe() ──▶ produce Cqe             │
//! │                                                   │
//! │  Kernel space                                     │
//! └───────────────────────────────────────────────────┘
//! ```
//!
//! # Example workflow
//!
//! 1. User creates an [`IoUring`] via [`IoUringRegistry::create`].
//! 2. User pushes [`Sqe`] entries onto the submission queue.
//! 3. User calls [`IoUring::submit_and_complete`] to process pending
//!    submissions and generate completions.
//! 4. User peeks/consumes [`Cqe`] entries from the completion queue.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Default number of submission queue entries.
const SQ_ENTRIES: usize = 256;

/// Default number of completion queue entries.
const CQ_ENTRIES: usize = 512;

/// Maximum io_uring instances system-wide.
const MAX_URING_INSTANCES: usize = 16;

// ── IoUringFlags ─────────────────────────────────────────────────

/// Setup flag: kernel-side submission queue polling.
///
/// When set, the kernel spawns a polling thread that continuously
/// drains the submission queue without requiring explicit
/// `submit` system calls.
pub const IORING_SETUP_SQPOLL: u32 = 1 << 0;

/// Setup flag: busy-poll for I/O completions.
///
/// When set, the kernel performs busy-polling on the underlying
/// device rather than relying on interrupts, reducing latency
/// at the cost of CPU usage.
pub const IORING_SETUP_IOPOLL: u32 = 1 << 1;

/// Setup flag: clamp queue sizes to implementation limits.
///
/// When set, the kernel silently reduces requested queue sizes
/// to the maximum supported values instead of returning an error.
pub const IORING_SETUP_CLAMP: u32 = 1 << 2;

/// Aggregate io_uring setup flags.
///
/// Stores a bitmask of `IORING_SETUP_*` constants that control
/// the behaviour of an [`IoUring`] instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringFlags(u32);

impl IoUringFlags {
    /// Create a flags value from a raw bitmask.
    ///
    /// Returns `Err(InvalidArgument)` if any unknown bits are set.
    pub const fn from_raw(raw: u32) -> Result<Self> {
        let known = IORING_SETUP_SQPOLL | IORING_SETUP_IOPOLL | IORING_SETUP_CLAMP;
        if raw & !known != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Create an empty flags value (no flags set).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Return the raw bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether `IORING_SETUP_SQPOLL` is set.
    pub const fn sqpoll(self) -> bool {
        self.0 & IORING_SETUP_SQPOLL != 0
    }

    /// Check whether `IORING_SETUP_IOPOLL` is set.
    pub const fn iopoll(self) -> bool {
        self.0 & IORING_SETUP_IOPOLL != 0
    }

    /// Check whether `IORING_SETUP_CLAMP` is set.
    pub const fn clamp(self) -> bool {
        self.0 & IORING_SETUP_CLAMP != 0
    }
}

impl Default for IoUringFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ── IoUringOp ────────────────────────────────────────────────────

/// I/O operation opcodes for submission queue entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum IoUringOp {
    /// No-op; used for probing or benchmarking the ring itself.
    #[default]
    Nop = 0,
    /// Asynchronous read from a file descriptor.
    Read = 1,
    /// Asynchronous write to a file descriptor.
    Write = 2,
    /// Flush file data and/or metadata to storage.
    Fsync = 3,
    /// Poll a file descriptor for readiness events.
    Poll = 4,
    /// Accept a connection on a listening socket.
    Accept = 5,
    /// Initiate a connection on a socket.
    Connect = 6,
    /// Close a file descriptor.
    Close = 7,
    /// Arm a timeout that fires after a specified duration.
    Timeout = 8,
    /// Cancel a previously submitted in-flight operation.
    Cancel = 9,
}

impl IoUringOp {
    /// Convert a raw `u8` opcode to an [`IoUringOp`].
    ///
    /// Returns `Err(InvalidArgument)` for unknown opcodes.
    pub const fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            0 => Ok(Self::Nop),
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Fsync),
            4 => Ok(Self::Poll),
            5 => Ok(Self::Accept),
            6 => Ok(Self::Connect),
            7 => Ok(Self::Close),
            8 => Ok(Self::Timeout),
            9 => Ok(Self::Cancel),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Sqe (Submission Queue Entry) ─────────────────────────────────

/// Submission Queue Entry — a single I/O request.
///
/// Laid out as a 64-byte C-compatible structure so it can be
/// memory-mapped directly into user space. The interpretation of
/// `addr` and `len` depends on the `opcode`.
///
/// | Field       | Read/Write | Fsync | Poll  | Close |
/// |-------------|-----------|-------|-------|-------|
/// | `fd`        | target fd | fd    | fd    | fd    |
/// | `off`       | offset    | —     | —     | —     |
/// | `addr`      | buf ptr   | —     | mask  | —     |
/// | `len`       | buf len   | —     | —     | —     |
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Sqe {
    /// Operation code (see [`IoUringOp`]).
    pub opcode: u8,
    /// Per-SQE flags (reserved, must be 0).
    pub flags: u8,
    /// Padding for alignment.
    _pad0: u16,
    /// Target file descriptor.
    pub fd: i32,
    /// Byte offset into the file (opcode-dependent).
    pub off: u64,
    /// User-space buffer address or opcode-dependent parameter.
    pub addr: u64,
    /// Length of the buffer or opcode-dependent parameter.
    pub len: u32,
    /// Padding for alignment.
    _pad1: u32,
    /// Opaque user data carried through to the completion entry.
    pub user_data: u64,
    /// Reserved space to reach exactly 64 bytes.
    _reserved: [u64; 3],
}

// Compile-time size assertion: Sqe must be exactly 64 bytes.
const _: () = {
    assert!(core::mem::size_of::<Sqe>() == 64);
};

impl Sqe {
    /// Create a zeroed submission queue entry (NOP).
    pub const fn new() -> Self {
        Self {
            opcode: IoUringOp::Nop as u8,
            flags: 0,
            _pad0: 0,
            fd: -1,
            off: 0,
            addr: 0,
            len: 0,
            _pad1: 0,
            user_data: 0,
            _reserved: [0; 3],
        }
    }

    /// Create a read SQE.
    pub const fn read(fd: i32, addr: u64, len: u32, off: u64, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Read as u8,
            flags: 0,
            _pad0: 0,
            fd,
            off,
            addr,
            len,
            _pad1: 0,
            user_data,
            _reserved: [0; 3],
        }
    }

    /// Create a write SQE.
    pub const fn write(fd: i32, addr: u64, len: u32, off: u64, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Write as u8,
            flags: 0,
            _pad0: 0,
            fd,
            off,
            addr,
            len,
            _pad1: 0,
            user_data,
            _reserved: [0; 3],
        }
    }

    /// Create a close SQE.
    pub const fn close(fd: i32, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Close as u8,
            flags: 0,
            _pad0: 0,
            fd,
            off: 0,
            addr: 0,
            len: 0,
            _pad1: 0,
            user_data,
            _reserved: [0; 3],
        }
    }

    /// Return the opcode as an [`IoUringOp`].
    pub const fn op(&self) -> Result<IoUringOp> {
        IoUringOp::from_raw(self.opcode)
    }
}

impl Default for Sqe {
    fn default() -> Self {
        Self::new()
    }
}

// ── Cqe (Completion Queue Entry) ─────────────────────────────────

/// Completion Queue Entry — the result of a submitted I/O request.
///
/// Laid out as a 16-byte C-compatible structure for direct
/// memory-mapping into user space.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Cqe {
    /// Opaque user data copied from the corresponding [`Sqe`].
    pub user_data: u64,
    /// Result value: bytes transferred on success, negative errno
    /// on failure.
    pub res: i32,
    /// Completion flags (reserved, currently 0).
    pub flags: u32,
}

// Compile-time size assertion: Cqe must be exactly 16 bytes.
const _: () = {
    assert!(core::mem::size_of::<Cqe>() == 16);
};

impl Cqe {
    /// Create a completion entry from a user-data tag and result.
    pub const fn new(user_data: u64, res: i32, flags: u32) -> Self {
        Self {
            user_data,
            res,
            flags,
        }
    }

    /// Check whether the operation completed successfully.
    pub const fn is_success(&self) -> bool {
        self.res >= 0
    }
}

impl Default for Cqe {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ── SubmissionQueue ──────────────────────────────────────────────

/// Ring buffer of [`Sqe`] entries.
///
/// Producers (user space) advance `tail`; the consumer (kernel)
/// advances `head`. The queue can hold up to [`SQ_ENTRIES`] entries
/// (power-of-two, so masking works).
pub struct SubmissionQueue {
    /// Backing storage for SQEs.
    entries: [Sqe; SQ_ENTRIES],
    /// Consumer index (kernel reads from here).
    head: u32,
    /// Producer index (user pushes here).
    tail: u32,
    /// Bitmask for wrapping (`SQ_ENTRIES - 1`).
    mask: u32,
}

impl SubmissionQueue {
    /// Create an empty submission queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { Sqe::new() }; SQ_ENTRIES],
            head: 0,
            tail: 0,
            mask: (SQ_ENTRIES as u32).wrapping_sub(1),
        }
    }

    /// Return the number of pending (un-consumed) entries.
    pub const fn pending(&self) -> u32 {
        self.tail.wrapping_sub(self.head)
    }

    /// Return the total capacity of the queue.
    pub const fn capacity(&self) -> u32 {
        SQ_ENTRIES as u32
    }

    /// Check whether the queue is full.
    pub const fn is_full(&self) -> bool {
        self.pending() >= self.capacity()
    }

    /// Check whether the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Push a single [`Sqe`] onto the queue.
    ///
    /// Returns `Err(OutOfMemory)` if the queue is full.
    pub fn push(&mut self, sqe: Sqe) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let idx = (self.tail & self.mask) as usize;
        self.entries[idx] = sqe;
        self.tail = self.tail.wrapping_add(1);
        Ok(())
    }

    /// Push a batch of SQEs, returning the number actually pushed.
    ///
    /// Pushes as many entries as possible without exceeding capacity.
    /// Returns the number of entries successfully pushed.
    pub fn push_batch(&mut self, sqes: &[Sqe]) -> usize {
        let mut pushed = 0usize;
        for sqe in sqes {
            if self.is_full() {
                break;
            }
            let idx = (self.tail & self.mask) as usize;
            self.entries[idx] = *sqe;
            self.tail = self.tail.wrapping_add(1);
            pushed = pushed.saturating_add(1);
        }
        pushed
    }

    /// Pop a single [`Sqe`] from the head of the queue.
    ///
    /// Returns `None` if the queue is empty.
    fn pop(&mut self) -> Option<Sqe> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head & self.mask) as usize;
        let sqe = self.entries[idx];
        self.head = self.head.wrapping_add(1);
        Some(sqe)
    }
}

impl Default for SubmissionQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ── CompletionQueue ──────────────────────────────────────────────

/// Ring buffer of [`Cqe`] entries.
///
/// The kernel (producer) advances `tail`; user space (consumer)
/// advances `head`. The queue can hold up to [`CQ_ENTRIES`] entries.
pub struct CompletionQueue {
    /// Backing storage for CQEs.
    entries: [Cqe; CQ_ENTRIES],
    /// Consumer index (user reads from here).
    head: u32,
    /// Producer index (kernel pushes here).
    tail: u32,
    /// Bitmask for wrapping (`CQ_ENTRIES - 1`).
    mask: u32,
    /// Number of completions that were dropped because the queue
    /// was full (overflow counter).
    overflow: u32,
}

impl CompletionQueue {
    /// Create an empty completion queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { Cqe::new(0, 0, 0) }; CQ_ENTRIES],
            head: 0,
            tail: 0,
            mask: (CQ_ENTRIES as u32).wrapping_sub(1),
            overflow: 0,
        }
    }

    /// Return the number of unconsumed completion entries.
    pub const fn ready(&self) -> u32 {
        self.tail.wrapping_sub(self.head)
    }

    /// Return the total capacity of the queue.
    pub const fn capacity(&self) -> u32 {
        CQ_ENTRIES as u32
    }

    /// Check whether the queue is full.
    pub const fn is_full(&self) -> bool {
        self.ready() >= self.capacity()
    }

    /// Check whether the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Return the number of dropped completions due to overflow.
    pub const fn overflow_count(&self) -> u32 {
        self.overflow
    }

    /// Push a completion entry onto the queue.
    ///
    /// If the queue is full the entry is dropped and the overflow
    /// counter is incremented. Returns `Ok(())` on success or
    /// `Err(OutOfMemory)` on overflow.
    fn push(&mut self, cqe: Cqe) -> Result<()> {
        if self.is_full() {
            self.overflow = self.overflow.saturating_add(1);
            return Err(Error::OutOfMemory);
        }
        let idx = (self.tail & self.mask) as usize;
        self.entries[idx] = cqe;
        self.tail = self.tail.wrapping_add(1);
        Ok(())
    }

    /// Peek at the next completion entry without consuming it.
    ///
    /// Returns `None` if the queue is empty.
    pub fn peek(&self) -> Option<&Cqe> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head & self.mask) as usize;
        Some(&self.entries[idx])
    }

    /// Consume and return the next completion entry.
    ///
    /// Returns `None` if the queue is empty.
    pub fn consume(&mut self) -> Option<Cqe> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head & self.mask) as usize;
        let cqe = self.entries[idx];
        self.head = self.head.wrapping_add(1);
        Some(cqe)
    }

    /// Consume up to `max` completions into the provided buffer.
    ///
    /// Returns the number of entries actually consumed.
    pub fn consume_batch(&mut self, buf: &mut [Cqe], max: usize) -> usize {
        let limit = max.min(buf.len());
        let mut consumed = 0usize;
        while consumed < limit {
            match self.consume() {
                Some(cqe) => {
                    buf[consumed] = cqe;
                    consumed = consumed.saturating_add(1);
                }
                None => break,
            }
        }
        consumed
    }
}

impl Default for CompletionQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ── IoUringParams ────────────────────────────────────────────────

/// Setup parameters for creating an [`IoUring`] instance.
///
/// Passed to [`IoUringRegistry::create`] to configure the queue
/// sizes and operational flags.
#[derive(Debug, Clone, Copy)]
pub struct IoUringParams {
    /// Requested number of submission queue entries (rounded to
    /// the implementation default if `IORING_SETUP_CLAMP` is set).
    pub sq_entries: u32,
    /// Requested number of completion queue entries (rounded to
    /// the implementation default if `IORING_SETUP_CLAMP` is set).
    pub cq_entries: u32,
    /// Setup flags controlling instance behaviour.
    pub flags: IoUringFlags,
}

impl IoUringParams {
    /// Create default parameters (256 SQEs, 512 CQEs, no flags).
    pub const fn new() -> Self {
        Self {
            sq_entries: SQ_ENTRIES as u32,
            cq_entries: CQ_ENTRIES as u32,
            flags: IoUringFlags::empty(),
        }
    }

    /// Validate the parameters.
    ///
    /// Returns `Err(InvalidArgument)` if entries counts are zero
    /// or not powers of two (unless `CLAMP` is set, in which case
    /// they are silently clamped to defaults).
    pub const fn validate(&self) -> Result<()> {
        if self.flags.clamp() {
            return Ok(());
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
}

impl Default for IoUringParams {
    fn default() -> Self {
        Self::new()
    }
}

// ── process_sqe ──────────────────────────────────────────────────

/// Dispatch a single [`Sqe`] and produce the corresponding [`Cqe`].
///
/// Each opcode is routed to its handler. Currently, all operations
/// except `Nop` return a stub `NotImplemented` result so that the
/// ring infrastructure can be exercised before real I/O back-ends
/// are wired in.
pub fn process_sqe(sqe: &Sqe) -> Cqe {
    let res = match IoUringOp::from_raw(sqe.opcode) {
        Ok(IoUringOp::Nop) => 0i32,
        Ok(IoUringOp::Read) => handle_read(sqe),
        Ok(IoUringOp::Write) => handle_write(sqe),
        Ok(IoUringOp::Fsync) => handle_fsync(sqe),
        Ok(IoUringOp::Poll) => handle_poll(sqe),
        Ok(IoUringOp::Accept) => handle_accept(sqe),
        Ok(IoUringOp::Connect) => handle_connect(sqe),
        Ok(IoUringOp::Close) => handle_close(sqe),
        Ok(IoUringOp::Timeout) => handle_timeout(sqe),
        Ok(IoUringOp::Cancel) => handle_cancel(sqe),
        Err(_) => -1, // EINVAL equivalent
    };

    Cqe::new(sqe.user_data, res, 0)
}

// ── Opcode stubs ─────────────────────────────────────────────────
//
// Each stub validates minimal preconditions and returns -38
// (ENOSYS equivalent) until the real subsystem is wired in.

/// Stub: validate and dispatch a read request.
fn handle_read(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 || sqe.len == 0 || sqe.addr == 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS — not yet implemented
}

/// Stub: validate and dispatch a write request.
fn handle_write(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 || sqe.len == 0 || sqe.addr == 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch an fsync request.
fn handle_fsync(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch a poll request.
fn handle_poll(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch an accept request.
fn handle_accept(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch a connect request.
fn handle_connect(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 || sqe.addr == 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch a close request.
fn handle_close(sqe: &Sqe) -> i32 {
    if sqe.fd < 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch a timeout request.
fn handle_timeout(sqe: &Sqe) -> i32 {
    if sqe.addr == 0 {
        return -1; // EINVAL
    }
    -38 // ENOSYS
}

/// Stub: validate and dispatch a cancel request.
fn handle_cancel(_sqe: &Sqe) -> i32 {
    -38 // ENOSYS
}

// ── IoUring ──────────────────────────────────────────────────────

/// Main io_uring instance binding a submission queue to a
/// completion queue.
///
/// The typical lifecycle is:
///
/// 1. Push SQEs via [`sq_mut()`](IoUring::sq_mut).
/// 2. Call [`submit_and_complete()`](IoUring::submit_and_complete).
/// 3. Drain CQEs via [`cq_mut()`](IoUring::cq_mut).
pub struct IoUring {
    /// Submission queue.
    sq: SubmissionQueue,
    /// Completion queue.
    cq: CompletionQueue,
    /// Setup parameters used to create this instance.
    params: IoUringParams,
    /// Whether this instance slot is in use.
    in_use: bool,
}

impl IoUring {
    /// Create a new, inactive io_uring instance.
    const fn new() -> Self {
        Self {
            sq: SubmissionQueue::new(),
            cq: CompletionQueue::new(),
            params: IoUringParams::new(),
            in_use: false,
        }
    }

    /// Initialise the instance with the given parameters.
    fn setup(&mut self, params: IoUringParams) {
        self.sq = SubmissionQueue::new();
        self.cq = CompletionQueue::new();
        self.params = params;
        self.in_use = true;
    }

    /// Return a shared reference to the submission queue.
    pub const fn sq(&self) -> &SubmissionQueue {
        &self.sq
    }

    /// Return a mutable reference to the submission queue.
    pub fn sq_mut(&mut self) -> &mut SubmissionQueue {
        &mut self.sq
    }

    /// Return a shared reference to the completion queue.
    pub const fn cq(&self) -> &CompletionQueue {
        &self.cq
    }

    /// Return a mutable reference to the completion queue.
    pub fn cq_mut(&mut self) -> &mut CompletionQueue {
        &mut self.cq
    }

    /// Return the setup parameters.
    pub const fn params(&self) -> &IoUringParams {
        &self.params
    }

    /// Drain up to `max` SQEs from the submission queue, process
    /// each one, and push the resulting CQEs onto the completion
    /// queue.
    ///
    /// Returns the number of submissions successfully processed.
    /// If `max` is 0, all pending SQEs are drained.
    pub fn submit_and_complete(&mut self, max: u32) -> u32 {
        let limit = if max == 0 { u32::MAX } else { max };
        let mut processed = 0u32;

        while processed < limit {
            match self.sq.pop() {
                Some(sqe) => {
                    let cqe = process_sqe(&sqe);
                    // Best-effort push; overflow is tracked inside CQ.
                    let _ = self.cq.push(cqe);
                    processed = processed.saturating_add(1);
                }
                None => break,
            }
        }

        processed
    }
}

// ── IoUringRegistry ──────────────────────────────────────────────

/// System-wide registry of [`IoUring`] instances.
///
/// Manages up to [`MAX_URING_INSTANCES`] concurrent io_uring
/// instances. Each instance is identified by a numeric ID returned
/// by [`create`](IoUringRegistry::create).
pub struct IoUringRegistry {
    /// Fixed array of io_uring instance slots.
    instances: [IoUring; MAX_URING_INSTANCES],
}

impl Default for IoUringRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IoUringRegistry {
    /// Create an empty registry with no active instances.
    pub const fn new() -> Self {
        Self {
            instances: [const { IoUring::new() }; MAX_URING_INSTANCES],
        }
    }

    /// Allocate and initialise a new io_uring instance.
    ///
    /// Returns the instance ID on success, or `Err(OutOfMemory)` if
    /// all slots are occupied. Returns `Err(InvalidArgument)` if
    /// `params` fails validation.
    pub fn create(&mut self, params: IoUringParams) -> Result<usize> {
        params.validate()?;

        for (id, inst) in self.instances.iter_mut().enumerate() {
            if !inst.in_use {
                inst.setup(params);
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a shared reference to an io_uring instance by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get(&self, id: usize) -> Result<&IoUring> {
        let inst = self.instances.get(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        Ok(inst)
    }

    /// Get a mutable reference to an io_uring instance by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get_mut(&mut self, id: usize) -> Result<&mut IoUring> {
        let inst = self.instances.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        Ok(inst)
    }

    /// Destroy an io_uring instance, freeing its slot.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let inst = self.instances.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        *inst = IoUring::new();
        Ok(())
    }
}
