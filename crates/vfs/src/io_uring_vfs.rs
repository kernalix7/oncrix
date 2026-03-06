// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring VFS integration layer.
//!
//! Provides the kernel-side structures and dispatch logic for io_uring-based
//! asynchronous filesystem operations. io_uring is a high-performance
//! asynchronous I/O interface that uses shared memory ring buffers between
//! user space and the kernel to avoid syscall overhead.
//!
//! # Architecture
//!
//! ```text
//! User space                           Kernel io_uring VFS
//! ──────────                           ───────────────────
//! Build SQE in mmap'd ring  ──►  SubmissionQueue::consume()
//!   │                                    │
//!   │                                    ▼
//!   │                               IoUringVfs::dispatch_sqe()
//!   │                                    │
//!   │                                    ▼
//!   │                               VFS operation (read/write/open/…)
//!   │                                    │
//!   │                                    ▼
//!   │                               CompletionQueue::push()
//!   │                                    │
//! Read CQE from mmap'd ring  ◄──  completion ring entry
//! ```
//!
//! # Structures
//!
//! - [`IoUringOp`] — operation type enum (Read, Write, Fsync, etc.)
//! - [`IoUringSqe`] — submission queue entry (user → kernel)
//! - [`IoUringCqe`] — completion queue entry (kernel → user)
//! - [`SubmissionQueue`] — ring buffer of pending SQEs
//! - [`CompletionQueue`] — ring buffer of completed CQEs
//! - [`IoUringVfs`] — main dispatch engine
//!
//! # References
//!
//! - Linux `io_uring(7)`, `io_uring_enter(2)`, `io_uring_setup(2)`
//! - `include/uapi/linux/io_uring.h` — SQE/CQE definitions
//! - `fs/io_uring.c` — kernel implementation

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────

/// Maximum number of entries in a submission queue.
pub const SQ_MAX_ENTRIES: usize = 256;

/// Maximum number of entries in a completion queue.
pub const CQ_MAX_ENTRIES: usize = 512;

/// Maximum inline data buffer size for SQE fixed buffers.
pub const SQE_INLINE_DATA_MAX: usize = 4096;

/// Maximum number of registered file descriptors.
pub const MAX_REGISTERED_FDS: usize = 64;

/// Maximum number of registered buffers.
pub const MAX_REGISTERED_BUFS: usize = 32;

/// Maximum number of concurrent io_uring instances.
pub const MAX_IO_URING_INSTANCES: usize = 16;

/// SQE flag: issue after previous SQE completes.
pub const IOSQE_IO_LINK: u8 = 1 << 0;

/// SQE flag: always go async (do not attempt inline completion).
pub const IOSQE_ASYNC: u8 = 1 << 1;

/// SQE flag: use registered fd (index in registered fd table).
pub const IOSQE_FIXED_FILE: u8 = 1 << 2;

/// SQE flag: use registered buffer (index in registered buf table).
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 3;

/// SQE flag: drain the queue before this SQE.
pub const IOSQE_IO_DRAIN: u8 = 1 << 4;

/// CQE flag: more completions follow for this SQE (multi-shot).
pub const IORING_CQE_F_MORE: u32 = 1 << 0;

/// CQE flag: buffer id is valid.
pub const IORING_CQE_F_BUFFER: u32 = 1 << 1;

/// CQE flag: notification event (not a completion).
pub const IORING_CQE_F_NOTIF: u32 = 1 << 2;

// ── io_uring_enter flags ────────────────────────────────────────────────

/// Flag for `io_uring_enter`: fetch new SQEs from the submission ring.
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

/// Flag for `io_uring_enter`: submit SQEs.
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;

/// Flag for `io_uring_enter`: register eventfd for notifications.
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 2;

// ── IoUringOp ───────────────────────────────────────────────────────────

/// io_uring operation types.
///
/// Each SQE carries an opcode that determines which VFS operation the
/// kernel executes when the request is dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoUringOp {
    /// No operation (used for link chains or testing).
    Nop = 0,
    /// Read from a file descriptor at offset.
    Read = 1,
    /// Write to a file descriptor at offset.
    Write = 2,
    /// Flush file data and metadata to storage.
    Fsync = 3,
    /// Open a file relative to a directory fd.
    OpenAt = 4,
    /// Close a file descriptor.
    Close = 5,
    /// Extended stat (`statx`).
    Statx = 6,
    /// Create a directory relative to a directory fd.
    MkdirAt = 7,
    /// Unlink (remove) a file relative to a directory fd.
    UnlinkAt = 8,
    /// Rename a file relative to directory fds.
    RenameAt = 9,
    /// Read from a fixed buffer (pre-registered).
    ReadFixed = 10,
    /// Write from a fixed buffer (pre-registered).
    WriteFixed = 11,
    /// Poll a file descriptor for readiness.
    PollAdd = 12,
    /// Remove a previously added poll request.
    PollRemove = 13,
    /// Attempt to cancel a pending request.
    Cancel = 14,
    /// Preallocate file space.
    Fallocate = 15,
}

impl IoUringOp {
    /// Convert from a raw `u8` opcode value.
    pub fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Nop),
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Fsync),
            4 => Some(Self::OpenAt),
            5 => Some(Self::Close),
            6 => Some(Self::Statx),
            7 => Some(Self::MkdirAt),
            8 => Some(Self::UnlinkAt),
            9 => Some(Self::RenameAt),
            10 => Some(Self::ReadFixed),
            11 => Some(Self::WriteFixed),
            12 => Some(Self::PollAdd),
            13 => Some(Self::PollRemove),
            14 => Some(Self::Cancel),
            15 => Some(Self::Fallocate),
            _ => None,
        }
    }

    /// Return the human-readable name of this operation.
    pub fn name(self) -> &'static str {
        match self {
            Self::Nop => "NOP",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Fsync => "FSYNC",
            Self::OpenAt => "OPENAT",
            Self::Close => "CLOSE",
            Self::Statx => "STATX",
            Self::MkdirAt => "MKDIRAT",
            Self::UnlinkAt => "UNLINKAT",
            Self::RenameAt => "RENAMEAT",
            Self::ReadFixed => "READ_FIXED",
            Self::WriteFixed => "WRITE_FIXED",
            Self::PollAdd => "POLL_ADD",
            Self::PollRemove => "POLL_REMOVE",
            Self::Cancel => "CANCEL",
            Self::Fallocate => "FALLOCATE",
        }
    }
}

impl core::fmt::Display for IoUringOp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── IoUringSqe — Submission Queue Entry ─────────────────────────────────

/// Submission Queue Entry — user-space request passed to the kernel.
///
/// Layout mirrors `struct io_uring_sqe` from the Linux UAPI header.
/// Fields are overloaded depending on the opcode — for example, `addr`
/// may hold a user-space buffer pointer (read/write) or a path pointer
/// (openat/mkdirat).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoUringSqe {
    /// Operation code — one of [`IoUringOp`].
    pub opcode: u8,
    /// Per-SQE flags (see `IOSQE_*` constants).
    pub flags: u8,
    /// IO priority (ioprio class + level).
    pub ioprio: u16,
    /// Target file descriptor (or registered fd index).
    pub fd: i32,
    /// File offset for read/write, or flags for openat/unlinkat.
    pub off: u64,
    /// User-space buffer address, or path address, or related fd.
    pub addr: u64,
    /// Buffer length, or path length, or mode for mkdir.
    pub len: u32,
    /// Operation-specific flags (e.g., `O_CREAT` for openat,
    /// `fsync_flags` for fsync, `poll_events` for poll).
    pub op_flags: u32,
    /// Opaque user data returned in the corresponding CQE.
    pub user_data: u64,
    /// Registered buffer index (when `IOSQE_BUFFER_SELECT` is set).
    pub buf_index: u16,
    /// Personality credentials index (for multi-user rings).
    pub personality: u16,
    /// Second fd for operations like renameat (new directory fd).
    pub splice_fd_in: i32,
}

impl IoUringSqe {
    /// Create a zeroed SQE.
    pub const fn zeroed() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            ioprio: 0,
            fd: -1,
            off: 0,
            addr: 0,
            len: 0,
            op_flags: 0,
            user_data: 0,
            buf_index: 0,
            personality: 0,
            splice_fd_in: -1,
        }
    }

    /// Parse the opcode field into an [`IoUringOp`].
    pub fn op(&self) -> Option<IoUringOp> {
        IoUringOp::from_raw(self.opcode)
    }

    /// Check whether the `IOSQE_IO_LINK` flag is set.
    pub fn is_linked(&self) -> bool {
        self.flags & IOSQE_IO_LINK != 0
    }

    /// Check whether the `IOSQE_ASYNC` flag is set.
    pub fn is_async(&self) -> bool {
        self.flags & IOSQE_ASYNC != 0
    }

    /// Check whether the `IOSQE_FIXED_FILE` flag is set.
    pub fn is_fixed_file(&self) -> bool {
        self.flags & IOSQE_FIXED_FILE != 0
    }

    /// Check whether the `IOSQE_IO_DRAIN` flag is set.
    pub fn is_drain(&self) -> bool {
        self.flags & IOSQE_IO_DRAIN != 0
    }

    /// Build a NOP SQE.
    pub fn nop(user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::Nop as u8;
        sqe.user_data = user_data;
        sqe
    }

    /// Build a Read SQE.
    pub fn read(fd: i32, addr: u64, len: u32, off: u64, user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::Read as u8;
        sqe.fd = fd;
        sqe.addr = addr;
        sqe.len = len;
        sqe.off = off;
        sqe.user_data = user_data;
        sqe
    }

    /// Build a Write SQE.
    pub fn write(fd: i32, addr: u64, len: u32, off: u64, user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::Write as u8;
        sqe.fd = fd;
        sqe.addr = addr;
        sqe.len = len;
        sqe.off = off;
        sqe.user_data = user_data;
        sqe
    }

    /// Build an Fsync SQE.
    pub fn fsync(fd: i32, fsync_flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::Fsync as u8;
        sqe.fd = fd;
        sqe.op_flags = fsync_flags;
        sqe.user_data = user_data;
        sqe
    }

    /// Build an OpenAt SQE.
    pub fn openat(
        dirfd: i32,
        path_addr: u64,
        path_len: u32,
        open_flags: u32,
        user_data: u64,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::OpenAt as u8;
        sqe.fd = dirfd;
        sqe.addr = path_addr;
        sqe.len = path_len;
        sqe.op_flags = open_flags;
        sqe.user_data = user_data;
        sqe
    }

    /// Build a Close SQE.
    pub fn close(fd: i32, user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::Close as u8;
        sqe.fd = fd;
        sqe.user_data = user_data;
        sqe
    }

    /// Build a Statx SQE.
    pub fn statx(
        dirfd: i32,
        path_addr: u64,
        path_len: u32,
        statx_flags: u32,
        user_data: u64,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::Statx as u8;
        sqe.fd = dirfd;
        sqe.addr = path_addr;
        sqe.len = path_len;
        sqe.op_flags = statx_flags;
        sqe.user_data = user_data;
        sqe
    }

    /// Build a MkdirAt SQE.
    pub fn mkdirat(dirfd: i32, path_addr: u64, path_len: u32, mode: u32, user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::MkdirAt as u8;
        sqe.fd = dirfd;
        sqe.addr = path_addr;
        sqe.len = path_len;
        sqe.op_flags = mode;
        sqe.user_data = user_data;
        sqe
    }

    /// Build an UnlinkAt SQE.
    pub fn unlinkat(dirfd: i32, path_addr: u64, path_len: u32, flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::UnlinkAt as u8;
        sqe.fd = dirfd;
        sqe.addr = path_addr;
        sqe.len = path_len;
        sqe.op_flags = flags;
        sqe.user_data = user_data;
        sqe
    }

    /// Build a RenameAt SQE.
    pub fn renameat(
        old_dirfd: i32,
        old_path_addr: u64,
        old_path_len: u32,
        new_dirfd: i32,
        user_data: u64,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = IoUringOp::RenameAt as u8;
        sqe.fd = old_dirfd;
        sqe.addr = old_path_addr;
        sqe.len = old_path_len;
        sqe.splice_fd_in = new_dirfd;
        sqe.user_data = user_data;
        sqe
    }
}

impl Default for IoUringSqe {
    fn default() -> Self {
        Self::zeroed()
    }
}

// ── IoUringCqe — Completion Queue Entry ─────────────────────────────────

/// Completion Queue Entry — kernel result returned to user space.
///
/// Layout mirrors `struct io_uring_cqe` from the Linux UAPI header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoUringCqe {
    /// Opaque user data copied from the corresponding SQE.
    pub user_data: u64,
    /// Result value: >= 0 on success (typically bytes transferred),
    /// negative errno on failure.
    pub res: i32,
    /// CQE flags (see `IORING_CQE_F_*` constants).
    pub flags: u32,
}

impl IoUringCqe {
    /// Create a CQE with the given result.
    pub const fn new(user_data: u64, res: i32, flags: u32) -> Self {
        Self {
            user_data,
            res,
            flags,
        }
    }

    /// Create a success CQE.
    pub const fn success(user_data: u64, bytes: i32) -> Self {
        Self::new(user_data, bytes, 0)
    }

    /// Create an error CQE.
    pub const fn error(user_data: u64, errno: i32) -> Self {
        Self::new(user_data, -errno, 0)
    }

    /// Return `true` if the result indicates success.
    pub fn is_success(&self) -> bool {
        self.res >= 0
    }

    /// Return `true` if more CQEs follow for the same SQE.
    pub fn has_more(&self) -> bool {
        self.flags & IORING_CQE_F_MORE != 0
    }
}

impl Default for IoUringCqe {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ── SubmissionQueue ─────────────────────────────────────────────────────

/// Fixed-size ring buffer of pending submission queue entries.
///
/// SQEs are produced by user space and consumed by the kernel's
/// dispatch loop. The ring uses head/tail indices with wrap-around.
pub struct SubmissionQueue {
    /// Ring buffer of SQE slots.
    entries: [IoUringSqe; SQ_MAX_ENTRIES],
    /// Head index — next entry to consume (kernel reads here).
    head: usize,
    /// Tail index — next entry to produce (user writes here).
    tail: usize,
    /// Number of entries currently in the ring.
    count: usize,
    /// Total SQEs ever submitted to this ring.
    total_submitted: u64,
    /// Total SQEs ever consumed from this ring.
    total_consumed: u64,
}

impl SubmissionQueue {
    /// Create an empty submission queue.
    pub const fn new() -> Self {
        Self {
            entries: [IoUringSqe::zeroed(); SQ_MAX_ENTRIES],
            head: 0,
            tail: 0,
            count: 0,
            total_submitted: 0,
            total_consumed: 0,
        }
    }

    /// Return the number of pending entries.
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Return the number of available (free) slots.
    pub fn available(&self) -> usize {
        SQ_MAX_ENTRIES - self.count
    }

    /// Return `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.count == SQ_MAX_ENTRIES
    }

    /// Total SQEs ever submitted.
    pub fn total_submitted(&self) -> u64 {
        self.total_submitted
    }

    /// Total SQEs ever consumed.
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    /// Push an SQE onto the tail of the queue.
    ///
    /// Returns `Err(OutOfMemory)` if the queue is full.
    pub fn push(&mut self, sqe: IoUringSqe) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.tail] = sqe;
        self.tail = (self.tail + 1) % SQ_MAX_ENTRIES;
        self.count += 1;
        self.total_submitted += 1;
        Ok(())
    }

    /// Pop an SQE from the head of the queue (kernel consumption).
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop(&mut self) -> Option<IoUringSqe> {
        if self.is_empty() {
            return None;
        }
        let sqe = self.entries[self.head];
        self.head = (self.head + 1) % SQ_MAX_ENTRIES;
        self.count -= 1;
        self.total_consumed += 1;
        Some(sqe)
    }

    /// Peek at the head SQE without consuming it.
    pub fn peek(&self) -> Option<&IoUringSqe> {
        if self.is_empty() {
            return None;
        }
        Some(&self.entries[self.head])
    }

    /// Drop all pending SQEs.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

impl Default for SubmissionQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SubmissionQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubmissionQueue")
            .field("pending", &self.count)
            .field("total_submitted", &self.total_submitted)
            .field("total_consumed", &self.total_consumed)
            .finish()
    }
}

// ── CompletionQueue ─────────────────────────────────────────────────────

/// Fixed-size ring buffer of completion queue entries.
///
/// CQEs are produced by the kernel dispatch loop and consumed by
/// user space. Overflow entries are counted and reported.
pub struct CompletionQueue {
    /// Ring buffer of CQE slots.
    entries: [IoUringCqe; CQ_MAX_ENTRIES],
    /// Head index — next entry to consume (user reads here).
    head: usize,
    /// Tail index — next entry to produce (kernel writes here).
    tail: usize,
    /// Number of entries currently in the ring.
    count: usize,
    /// Number of CQEs dropped due to ring overflow.
    overflow: u64,
    /// Total CQEs ever produced.
    total_produced: u64,
    /// Total CQEs ever consumed.
    total_consumed: u64,
}

impl CompletionQueue {
    /// Create an empty completion queue.
    pub const fn new() -> Self {
        Self {
            entries: [IoUringCqe::new(0, 0, 0); CQ_MAX_ENTRIES],
            head: 0,
            tail: 0,
            count: 0,
            overflow: 0,
            total_produced: 0,
            total_consumed: 0,
        }
    }

    /// Return the number of ready entries.
    pub fn ready(&self) -> usize {
        self.count
    }

    /// Return `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.count == CQ_MAX_ENTRIES
    }

    /// Number of CQEs dropped due to overflow.
    pub fn overflow_count(&self) -> u64 {
        self.overflow
    }

    /// Total CQEs ever produced.
    pub fn total_produced(&self) -> u64 {
        self.total_produced
    }

    /// Total CQEs ever consumed.
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    /// Push a CQE onto the tail of the ring.
    ///
    /// If the ring is full the entry is dropped and the overflow
    /// counter is incremented.
    pub fn push(&mut self, cqe: IoUringCqe) {
        if self.is_full() {
            self.overflow += 1;
            return;
        }
        self.entries[self.tail] = cqe;
        self.tail = (self.tail + 1) % CQ_MAX_ENTRIES;
        self.count += 1;
        self.total_produced += 1;
    }

    /// Pop a CQE from the head of the ring.
    ///
    /// Returns `None` if the ring is empty.
    pub fn pop(&mut self) -> Option<IoUringCqe> {
        if self.is_empty() {
            return None;
        }
        let cqe = self.entries[self.head];
        self.head = (self.head + 1) % CQ_MAX_ENTRIES;
        self.count -= 1;
        self.total_consumed += 1;
        Some(cqe)
    }

    /// Peek at the head CQE without consuming it.
    pub fn peek(&self) -> Option<&IoUringCqe> {
        if self.is_empty() {
            return None;
        }
        Some(&self.entries[self.head])
    }

    /// Consume up to `max` CQEs into the provided buffer.
    ///
    /// Returns the number of CQEs copied.
    pub fn pop_batch(&mut self, buf: &mut [IoUringCqe], max: usize) -> usize {
        let n = max.min(buf.len()).min(self.count);
        for entry in buf.iter_mut().take(n) {
            let cqe = self.entries[self.head];
            self.head = (self.head + 1) % CQ_MAX_ENTRIES;
            self.count -= 1;
            self.total_consumed += 1;
            *entry = cqe;
        }
        n
    }

    /// Drop all pending CQEs.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

impl Default for CompletionQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for CompletionQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompletionQueue")
            .field("ready", &self.count)
            .field("overflow", &self.overflow)
            .field("total_produced", &self.total_produced)
            .field("total_consumed", &self.total_consumed)
            .finish()
    }
}

// ── IoUringParams — setup parameters ────────────────────────────────────

/// Parameters for io_uring instance creation (`io_uring_setup`).
#[derive(Debug, Clone, Copy)]
pub struct IoUringParams {
    /// Requested submission queue depth (capped to [`SQ_MAX_ENTRIES`]).
    pub sq_entries: u32,
    /// Requested completion queue depth (capped to [`CQ_MAX_ENTRIES`]).
    pub cq_entries: u32,
    /// Feature flags (kernel-reported capabilities).
    pub features: u32,
    /// Setup flags controlling ring behaviour.
    pub flags: u32,
}

impl IoUringParams {
    /// Create default parameters with the specified SQ depth.
    pub fn with_depth(sq_entries: u32) -> Self {
        Self {
            sq_entries: sq_entries.min(SQ_MAX_ENTRIES as u32),
            cq_entries: (sq_entries * 2).min(CQ_MAX_ENTRIES as u32),
            features: 0,
            flags: 0,
        }
    }
}

impl Default for IoUringParams {
    fn default() -> Self {
        Self::with_depth(128)
    }
}

// ── RegisteredFd / RegisteredBuf ────────────────────────────────────────

/// A pre-registered file descriptor for use with `IOSQE_FIXED_FILE`.
#[derive(Debug, Clone, Copy)]
pub struct RegisteredFd {
    /// The real file descriptor number.
    pub fd: i32,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RegisteredFd {
    const fn empty() -> Self {
        Self {
            fd: -1,
            in_use: false,
        }
    }
}

/// A pre-registered buffer for use with `IOSQE_BUFFER_SELECT`.
#[derive(Debug, Clone, Copy)]
pub struct RegisteredBuf {
    /// User-space buffer address (opaque pointer as `usize`).
    pub addr: usize,
    /// Buffer length in bytes.
    pub len: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RegisteredBuf {
    const fn empty() -> Self {
        Self {
            addr: 0,
            len: 0,
            in_use: false,
        }
    }
}

// ── IoUringStats ────────────────────────────────────────────────────────

/// Runtime statistics for an io_uring instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringStats {
    /// Total SQEs dispatched.
    pub ops_dispatched: u64,
    /// Total CQEs generated (successes + errors).
    pub ops_completed: u64,
    /// Operations that completed with an error.
    pub ops_errored: u64,
    /// Operations completed inline (no async needed).
    pub ops_inline: u64,
    /// CQEs dropped due to completion ring overflow.
    pub cq_overflows: u64,
}

// ── IoUringVfs — main dispatch engine ───────────────────────────────────

/// A single io_uring instance tying together submission and completion
/// queues, registered resources, and VFS dispatch logic.
pub struct IoUringVfs {
    /// Submission queue (user → kernel).
    pub sq: SubmissionQueue,
    /// Completion queue (kernel → user).
    pub cq: CompletionQueue,
    /// Pre-registered file descriptors.
    registered_fds: [RegisteredFd; MAX_REGISTERED_FDS],
    /// Pre-registered user buffers.
    registered_bufs: [RegisteredBuf; MAX_REGISTERED_BUFS],
    /// Instance creation parameters.
    params: IoUringParams,
    /// Runtime statistics.
    stats: IoUringStats,
    /// Whether the instance has been set up.
    active: bool,
    /// Whether a drain barrier is pending.
    drain_pending: bool,
}

impl IoUringVfs {
    /// Create an uninitialised io_uring instance.
    pub const fn new() -> Self {
        Self {
            sq: SubmissionQueue::new(),
            cq: CompletionQueue::new(),
            registered_fds: [RegisteredFd::empty(); MAX_REGISTERED_FDS],
            registered_bufs: [RegisteredBuf::empty(); MAX_REGISTERED_BUFS],
            params: IoUringParams {
                sq_entries: 128,
                cq_entries: 256,
                features: 0,
                flags: 0,
            },
            stats: IoUringStats {
                ops_dispatched: 0,
                ops_completed: 0,
                ops_errored: 0,
                ops_inline: 0,
                cq_overflows: 0,
            },
            active: false,
            drain_pending: false,
        }
    }

    /// Set up the io_uring instance with the given parameters.
    pub fn setup(&mut self, params: IoUringParams) -> Result<()> {
        if self.active {
            return Err(Error::Busy);
        }
        self.params = params;
        self.sq.clear();
        self.cq.clear();
        self.stats = IoUringStats::default();
        self.drain_pending = false;
        self.active = true;
        Ok(())
    }

    /// Return `true` if this instance is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Tear down the io_uring instance.
    pub fn teardown(&mut self) {
        self.sq.clear();
        self.cq.clear();
        self.active = false;
        for fd in &mut self.registered_fds {
            *fd = RegisteredFd::empty();
        }
        for buf in &mut self.registered_bufs {
            *buf = RegisteredBuf::empty();
        }
    }

    /// Return a snapshot of runtime statistics.
    pub fn stats(&self) -> &IoUringStats {
        &self.stats
    }

    // ── Registered resources ────────────────────────────────────────

    /// Register a file descriptor at the given index.
    pub fn register_fd(&mut self, index: usize, fd: i32) -> Result<()> {
        if index >= MAX_REGISTERED_FDS {
            return Err(Error::InvalidArgument);
        }
        self.registered_fds[index] = RegisteredFd { fd, in_use: true };
        Ok(())
    }

    /// Unregister a file descriptor at the given index.
    pub fn unregister_fd(&mut self, index: usize) -> Result<()> {
        if index >= MAX_REGISTERED_FDS {
            return Err(Error::InvalidArgument);
        }
        if !self.registered_fds[index].in_use {
            return Err(Error::NotFound);
        }
        self.registered_fds[index] = RegisteredFd::empty();
        Ok(())
    }

    /// Resolve a registered fd index to the actual fd number.
    pub fn resolve_fd(&self, index: usize) -> Result<i32> {
        if index >= MAX_REGISTERED_FDS {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.registered_fds[index];
        if !slot.in_use {
            return Err(Error::NotFound);
        }
        Ok(slot.fd)
    }

    /// Register a user buffer at the given index.
    pub fn register_buf(&mut self, index: usize, addr: usize, len: usize) -> Result<()> {
        if index >= MAX_REGISTERED_BUFS {
            return Err(Error::InvalidArgument);
        }
        self.registered_bufs[index] = RegisteredBuf {
            addr,
            len,
            in_use: true,
        };
        Ok(())
    }

    /// Unregister a user buffer at the given index.
    pub fn unregister_buf(&mut self, index: usize) -> Result<()> {
        if index >= MAX_REGISTERED_BUFS {
            return Err(Error::InvalidArgument);
        }
        if !self.registered_bufs[index].in_use {
            return Err(Error::NotFound);
        }
        self.registered_bufs[index] = RegisteredBuf::empty();
        Ok(())
    }

    // ── Submission ──────────────────────────────────────────────────

    /// Submit an SQE to the submission ring.
    pub fn submit(&mut self, sqe: IoUringSqe) -> Result<()> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        self.sq.push(sqe)
    }

    /// Submit a batch of SQEs. Returns the number successfully queued.
    pub fn submit_batch(&mut self, sqes: &[IoUringSqe]) -> Result<usize> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        let mut count = 0usize;
        for sqe in sqes {
            if self.sq.push(*sqe).is_err() {
                break;
            }
            count += 1;
        }
        if count == 0 && !sqes.is_empty() {
            return Err(Error::OutOfMemory);
        }
        Ok(count)
    }

    // ── Dispatch ────────────────────────────────────────────────────

    /// Process all pending SQEs, dispatching each to the appropriate
    /// VFS handler and generating CQEs for the results.
    ///
    /// Returns the number of SQEs processed.
    pub fn process(&mut self) -> usize {
        if !self.active {
            return 0;
        }
        let mut processed = 0usize;
        loop {
            let sqe = match self.sq.pop() {
                Some(s) => s,
                None => break,
            };

            if sqe.is_drain() {
                self.drain_pending = false;
            }

            let cqe = self.dispatch_sqe(&sqe);
            self.stats.ops_dispatched += 1;

            if cqe.is_success() {
                self.stats.ops_completed += 1;
            } else {
                self.stats.ops_completed += 1;
                self.stats.ops_errored += 1;
            }

            if self.cq.is_full() {
                self.stats.cq_overflows += 1;
            }
            self.cq.push(cqe);
            processed += 1;

            // If a linked SQE failed, cancel the rest of the chain.
            if sqe.is_linked() && !cqe.is_success() {
                processed += self.cancel_linked_chain();
            }
        }
        processed
    }

    /// Dispatch a single SQE to the appropriate VFS handler.
    fn dispatch_sqe(&self, sqe: &IoUringSqe) -> IoUringCqe {
        let op = match sqe.op() {
            Some(op) => op,
            None => return IoUringCqe::error(sqe.user_data, 22),
        };

        let fd = if sqe.is_fixed_file() {
            match self.resolve_fd(sqe.fd as usize) {
                Ok(real_fd) => real_fd,
                Err(_) => return IoUringCqe::error(sqe.user_data, 9),
            }
        } else {
            sqe.fd
        };

        match op {
            IoUringOp::Nop => self.handle_nop(sqe),
            IoUringOp::Read | IoUringOp::ReadFixed => self.handle_read(sqe, fd),
            IoUringOp::Write | IoUringOp::WriteFixed => self.handle_write(sqe, fd),
            IoUringOp::Fsync => self.handle_fsync(sqe, fd),
            IoUringOp::OpenAt => self.handle_openat(sqe),
            IoUringOp::Close => self.handle_close(sqe, fd),
            IoUringOp::Statx => self.handle_statx(sqe),
            IoUringOp::MkdirAt => self.handle_mkdirat(sqe),
            IoUringOp::UnlinkAt => self.handle_unlinkat(sqe),
            IoUringOp::RenameAt => self.handle_renameat(sqe),
            IoUringOp::PollAdd => self.handle_poll_add(sqe, fd),
            IoUringOp::PollRemove => self.handle_poll_remove(sqe),
            IoUringOp::Cancel => self.handle_cancel(sqe),
            IoUringOp::Fallocate => self.handle_fallocate(sqe, fd),
        }
    }

    /// Cancel all linked SQEs following a failed link head.
    fn cancel_linked_chain(&mut self) -> usize {
        let mut cancelled = 0usize;
        loop {
            let sqe = match self.sq.pop() {
                Some(s) => s,
                None => break,
            };
            let is_linked = sqe.is_linked();
            self.cq.push(IoUringCqe::error(sqe.user_data, 125));
            self.stats.ops_dispatched += 1;
            self.stats.ops_completed += 1;
            self.stats.ops_errored += 1;
            cancelled += 1;
            if !is_linked {
                break;
            }
        }
        cancelled
    }

    // ── Per-opcode handlers ─────────────────────────────────────────

    /// Handle NOP — always succeeds with result 0.
    fn handle_nop(&self, sqe: &IoUringSqe) -> IoUringCqe {
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle Read / ReadFixed.
    ///
    /// In a full kernel this dispatches to the VFS `read()` path.
    /// Here we validate parameters and return a stub result.
    fn handle_read(&self, sqe: &IoUringSqe, fd: i32) -> IoUringCqe {
        if fd < 0 {
            return IoUringCqe::error(sqe.user_data, 9);
        }
        if sqe.addr == 0 || sqe.len == 0 {
            return IoUringCqe::error(sqe.user_data, 22);
        }
        IoUringCqe::success(sqe.user_data, sqe.len as i32)
    }

    /// Handle Write / WriteFixed.
    fn handle_write(&self, sqe: &IoUringSqe, fd: i32) -> IoUringCqe {
        if fd < 0 {
            return IoUringCqe::error(sqe.user_data, 9);
        }
        if sqe.addr == 0 || sqe.len == 0 {
            return IoUringCqe::error(sqe.user_data, 22);
        }
        IoUringCqe::success(sqe.user_data, sqe.len as i32)
    }

    /// Handle Fsync.
    fn handle_fsync(&self, sqe: &IoUringSqe, fd: i32) -> IoUringCqe {
        if fd < 0 {
            return IoUringCqe::error(sqe.user_data, 9);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle OpenAt.
    fn handle_openat(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 14);
        }
        IoUringCqe::success(sqe.user_data, 3)
    }

    /// Handle Close.
    fn handle_close(&self, sqe: &IoUringSqe, fd: i32) -> IoUringCqe {
        if fd < 0 {
            return IoUringCqe::error(sqe.user_data, 9);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle Statx.
    fn handle_statx(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 14);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle MkdirAt.
    fn handle_mkdirat(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 14);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle UnlinkAt.
    fn handle_unlinkat(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 14);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle RenameAt.
    fn handle_renameat(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 14);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle PollAdd — register poll interest on a fd.
    fn handle_poll_add(&self, sqe: &IoUringSqe, fd: i32) -> IoUringCqe {
        if fd < 0 {
            return IoUringCqe::error(sqe.user_data, 9);
        }
        IoUringCqe::success(sqe.user_data, sqe.op_flags as i32)
    }

    /// Handle PollRemove — remove a previously registered poll.
    fn handle_poll_remove(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 2);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle Cancel — attempt to cancel a pending request.
    fn handle_cancel(&self, sqe: &IoUringSqe) -> IoUringCqe {
        if sqe.addr == 0 {
            return IoUringCqe::error(sqe.user_data, 22);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    /// Handle Fallocate — preallocate file space.
    fn handle_fallocate(&self, sqe: &IoUringSqe, fd: i32) -> IoUringCqe {
        if fd < 0 {
            return IoUringCqe::error(sqe.user_data, 9);
        }
        IoUringCqe::success(sqe.user_data, 0)
    }

    // ── Completion retrieval ────────────────────────────────────────

    /// Retrieve a single CQE from the completion ring.
    pub fn get_completion(&mut self) -> Option<IoUringCqe> {
        self.cq.pop()
    }

    /// Retrieve up to `max` CQEs into the provided buffer.
    ///
    /// Returns the number of CQEs copied.
    pub fn get_completions(&mut self, buf: &mut [IoUringCqe], max: usize) -> usize {
        self.cq.pop_batch(buf, max)
    }

    /// Return the number of ready CQEs.
    pub fn completions_ready(&self) -> usize {
        self.cq.ready()
    }
}

impl Default for IoUringVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for IoUringVfs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoUringVfs")
            .field("active", &self.active)
            .field("sq", &self.sq)
            .field("cq", &self.cq)
            .field("stats", &self.stats)
            .finish()
    }
}

// ── IoUringTable — global pool of instances ─────────────────────────────

/// Global pool of io_uring instances.
pub struct IoUringTable {
    instances: [IoUringVfs; MAX_IO_URING_INSTANCES],
}

impl IoUringTable {
    /// Create a table with all instances inactive.
    pub const fn new() -> Self {
        Self {
            instances: [const { IoUringVfs::new() }; MAX_IO_URING_INSTANCES],
        }
    }

    /// Set up a new io_uring instance, returning its slot index.
    pub fn setup(&mut self, params: IoUringParams) -> Result<usize> {
        for (idx, inst) in self.instances.iter_mut().enumerate() {
            if !inst.is_active() {
                inst.setup(params)?;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Tear down an io_uring instance by index.
    pub fn teardown(&mut self, idx: usize) -> Result<()> {
        let inst = self.instances.get_mut(idx).ok_or(Error::InvalidArgument)?;
        if !inst.is_active() {
            return Err(Error::NotFound);
        }
        inst.teardown();
        Ok(())
    }

    /// Get a shared reference to an instance by index.
    pub fn get(&self, idx: usize) -> Option<&IoUringVfs> {
        let inst = self.instances.get(idx)?;
        if inst.is_active() { Some(inst) } else { None }
    }

    /// Get a mutable reference to an instance by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut IoUringVfs> {
        let inst = self.instances.get_mut(idx)?;
        if inst.is_active() { Some(inst) } else { None }
    }

    /// Count active io_uring instances.
    pub fn active_count(&self) -> usize {
        self.instances.iter().filter(|i| i.is_active()).count()
    }
}

impl Default for IoUringTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global singleton ────────────────────────────────────────────────────

static mut IO_URING_TABLE: IoUringTable = IoUringTable::new();

/// Initialise the global io_uring table.
///
/// # Safety
///
/// Must be called once during single-threaded kernel initialisation.
pub unsafe fn io_uring_init() {
    // SAFETY: Single-threaded init; no concurrent access.
    unsafe {
        *core::ptr::addr_of_mut!(IO_URING_TABLE) = IoUringTable::new();
    }
}

/// Obtain a shared reference to the global io_uring table.
pub fn io_uring_table() -> &'static IoUringTable {
    // SAFETY: Read-only after init; never moved.
    unsafe { &*core::ptr::addr_of!(IO_URING_TABLE) }
}

/// Obtain a mutable reference to the global io_uring table.
///
/// # Safety
///
/// Caller must ensure no other reference is live.
pub unsafe fn io_uring_table_mut() -> &'static mut IoUringTable {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { &mut *core::ptr::addr_of_mut!(IO_URING_TABLE) }
}

// ── Convenience wrappers ────────────────────────────────────────────────

/// Map an [`oncrix_lib::Error`] to a Linux-style negative errno.
fn error_to_errno(err: Error) -> i32 {
    match err {
        Error::PermissionDenied => 13,
        Error::NotFound => 2,
        Error::OutOfMemory => 12,
        Error::InvalidArgument => 22,
        Error::Busy => 16,
        Error::WouldBlock => 11,
        Error::Interrupted => 4,
        Error::IoError => 5,
        Error::NotImplemented => 38,
        Error::AlreadyExists => 17,
    }
}

/// Map a Linux-style errno to an [`oncrix_lib::Error`].
pub fn errno_to_error(errno: i32) -> Error {
    match errno.abs() {
        13 => Error::PermissionDenied,
        2 => Error::NotFound,
        12 => Error::OutOfMemory,
        22 => Error::InvalidArgument,
        16 => Error::Busy,
        11 => Error::WouldBlock,
        4 => Error::Interrupted,
        5 => Error::IoError,
        38 => Error::NotImplemented,
        17 => Error::AlreadyExists,
        _ => Error::IoError,
    }
}

/// Convert an `oncrix_lib::Result` to a CQE result value.
pub fn result_to_cqe_res(res: Result<usize>) -> i32 {
    match res {
        Ok(n) => n as i32,
        Err(e) => -error_to_errno(e),
    }
}
