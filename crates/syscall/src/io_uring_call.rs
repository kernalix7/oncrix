// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unified io_uring syscall interface.
//!
//! Provides a single-entry-point dispatcher for the three io_uring syscalls
//! (`io_uring_setup`, `io_uring_enter`, `io_uring_register`) and manages
//! the lifecycle of io_uring instances from creation through teardown.
//!
//! This module sits above the individual io_uring modules:
//!
//! - [`crate::io_uring_setup`] — ring creation, SQ/CQ sizing, feature flags
//! - [`crate::io_uring_enter`] — extended enter, typed register ops
//! - [`crate::io_uring_register`] — per-ring resource registration context
//!
//! # Architecture
//!
//! ```text
//! user space           io_uring_call.rs         low-level modules
//! ──────────           ────────────────         ─────────────────
//! syscall(NR)  ──►  IoUringCall::dispatch()
//!                       ├─ Setup   ──►  io_uring_setup::sys_io_uring_setup()
//!                       ├─ Enter   ──►  io_uring_enter::sys_io_uring_enter2()
//!                       ├─ Register──►  io_uring_setup::sys_io_uring_register()
//!                       └─ Destroy ──►  io_uring_setup::sys_io_uring_destroy()
//! ```
//!
//! # Key types
//!
//! - [`IoUringCall`] — discriminated syscall request
//! - [`IoUringParams`] — re-exported setup parameters
//! - [`SqEntry`] — submission queue entry builder
//! - [`CqEntry`] — completion queue entry reader
//! - [`IoUringFlags`] — typed setup/enter/register flag sets
//! - [`IoUringInstance`] — per-instance state snapshot
//!
//! # References
//!
//! - Linux: `io_uring/io_uring.c`, `include/uapi/linux/io_uring.h`
//! - `io_uring_setup(2)`, `io_uring_enter(2)`, `io_uring_register(2)`

use oncrix_lib::{Error, Result};

use crate::io_uring_setup::{
    IORING_ENTER_GETEVENTS, IORING_SETUP_CLAMP, IORING_SETUP_COOP_TASKRUN, IORING_SETUP_CQSIZE,
    IORING_SETUP_DEFER_TASKRUN, IORING_SETUP_IOPOLL, IORING_SETUP_R_DISABLED,
    IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_SQ_AFF, IORING_SETUP_SQPOLL, IORING_SETUP_SUBMIT_ALL,
    IORING_SETUP_TASKRUN_FLAG, IoUringCqe, IoUringParams, IoUringSqe, sys_io_uring_destroy,
    sys_io_uring_enter, sys_io_uring_query, sys_io_uring_register, sys_io_uring_setup,
    sys_io_uring_stats,
};

// ---------------------------------------------------------------------------
// IoUringFlags — typed flag wrappers
// ---------------------------------------------------------------------------

/// Validated setup flags for `io_uring_setup`.
///
/// Wraps the raw `IORING_SETUP_*` bitmask with checked construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoUringSetupFlags(u32);

/// Mask of all valid setup flag bits.
const SETUP_FLAGS_VALID: u32 = IORING_SETUP_IOPOLL
    | IORING_SETUP_SQPOLL
    | IORING_SETUP_SQ_AFF
    | IORING_SETUP_CQSIZE
    | IORING_SETUP_CLAMP
    | IORING_SETUP_R_DISABLED
    | IORING_SETUP_SUBMIT_ALL
    | IORING_SETUP_COOP_TASKRUN
    | IORING_SETUP_TASKRUN_FLAG
    | IORING_SETUP_SINGLE_ISSUER
    | IORING_SETUP_DEFER_TASKRUN;

impl IoUringSetupFlags {
    /// Construct from raw flags, rejecting unknown bits.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !SETUP_FLAGS_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bit pattern.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Whether I/O polling is enabled.
    pub const fn iopoll(&self) -> bool {
        self.0 & IORING_SETUP_IOPOLL != 0
    }

    /// Whether SQ polling is enabled.
    pub const fn sqpoll(&self) -> bool {
        self.0 & IORING_SETUP_SQPOLL != 0
    }

    /// Whether SQ affinity is set.
    pub const fn sq_aff(&self) -> bool {
        self.0 & IORING_SETUP_SQ_AFF != 0
    }

    /// Whether a custom CQ size is requested.
    pub const fn cqsize(&self) -> bool {
        self.0 & IORING_SETUP_CQSIZE != 0
    }

    /// Whether ring sizes should be clamped.
    pub const fn clamp(&self) -> bool {
        self.0 & IORING_SETUP_CLAMP != 0
    }

    /// Whether the ring starts disabled.
    pub const fn r_disabled(&self) -> bool {
        self.0 & IORING_SETUP_R_DISABLED != 0
    }

    /// Whether single-issuer mode is active.
    pub const fn single_issuer(&self) -> bool {
        self.0 & IORING_SETUP_SINGLE_ISSUER != 0
    }
}

/// Unified flag set for all io_uring operations.
///
/// Wraps setup, enter, and register flags into a single type for
/// the [`IoUringCall`] dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringFlags {
    /// Setup flags for `io_uring_setup`.
    Setup(IoUringSetupFlags),
    /// Enter flags (raw u32, validated by the enter handler).
    Enter(u32),
    /// Register opcode + nr_args.
    Register { opcode: u32, nr_args: u32 },
}

// ---------------------------------------------------------------------------
// SqEntry — submission queue entry builder
// ---------------------------------------------------------------------------

/// Operation codes for submission queue entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoUringOp {
    /// No operation (useful for wakeup).
    Nop = 0,
    /// Vectored read.
    Readv = 1,
    /// Vectored write.
    Writev = 2,
    /// Fsync.
    Fsync = 3,
    /// Read from a fixed buffer.
    ReadFixed = 4,
    /// Write from a fixed buffer.
    WriteFixed = 5,
    /// Poll for events.
    PollAdd = 6,
    /// Remove a poll request.
    PollRemove = 7,
    /// Sync a file range.
    SyncFileRange = 8,
    /// Send a message on a socket.
    SendMsg = 9,
    /// Receive a message from a socket.
    RecvMsg = 10,
    /// Timeout.
    Timeout = 11,
    /// Remove a timeout.
    TimeoutRemove = 12,
    /// Accept a connection.
    Accept = 13,
    /// Cancel an in-flight request.
    AsyncCancel = 14,
    /// Link a timeout to another SQE.
    LinkTimeout = 15,
    /// Connect a socket.
    Connect = 16,
    /// Allocate file space.
    Fallocate = 17,
    /// Open a file.
    Openat = 18,
    /// Close a file descriptor.
    Close = 19,
    /// Update registered files.
    FilesUpdate = 20,
    /// Stat a file.
    Statx = 21,
    /// Read (non-vectored).
    Read = 22,
    /// Write (non-vectored).
    Write = 23,
    /// Advise on file data.
    Fadvise = 24,
    /// Advise on memory.
    Madvise = 25,
    /// Send data on a socket.
    Send = 26,
    /// Receive data from a socket.
    Recv = 27,
    /// Open a file relative to directory (with extended flags).
    Openat2 = 28,
    /// Register an epoll event.
    EpollCtl = 29,
    /// Splice data between file descriptors.
    Splice = 30,
    /// Provide buffers to the ring.
    ProvideBuffers = 31,
    /// Remove previously provided buffers.
    RemoveBuffers = 32,
}

/// SQE flags.
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
/// Link the next SQE.
pub const IOSQE_IO_LINK: u8 = 1 << 2;
/// Hard-link the next SQE.
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
/// Use async execution.
pub const IOSQE_ASYNC: u8 = 1 << 4;
/// Use a provided buffer group.
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;

/// Builder for submission queue entries.
///
/// Provides a fluent API for constructing [`IoUringSqe`] values with
/// validated fields.
#[derive(Debug, Clone, Copy)]
pub struct SqEntry {
    inner: IoUringSqe,
}

impl SqEntry {
    /// Create a new SQE builder for the given operation.
    pub const fn new(op: IoUringOp) -> Self {
        Self {
            inner: IoUringSqe {
                opcode: op as u8,
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
                splice_fd_in: 0,
                _pad: [0],
            },
        }
    }

    /// Set the file descriptor.
    pub const fn fd(mut self, fd: i32) -> Self {
        self.inner.fd = fd;
        self
    }

    /// Set the file offset.
    pub const fn offset(mut self, off: u64) -> Self {
        self.inner.off = off;
        self
    }

    /// Set the buffer address.
    pub const fn addr(mut self, addr: u64) -> Self {
        self.inner.addr = addr;
        self
    }

    /// Set the I/O length.
    pub const fn len(mut self, len: u32) -> Self {
        self.inner.len = len;
        self
    }

    /// Set opaque user data.
    pub const fn user_data(mut self, data: u64) -> Self {
        self.inner.user_data = data;
        self
    }

    /// Set SQE flags.
    pub const fn flags(mut self, flags: u8) -> Self {
        self.inner.flags = flags;
        self
    }

    /// Set the I/O priority.
    pub const fn ioprio(mut self, ioprio: u16) -> Self {
        self.inner.ioprio = ioprio;
        self
    }

    /// Set per-operation flags.
    pub const fn op_flags(mut self, op_flags: u32) -> Self {
        self.inner.op_flags = op_flags;
        self
    }

    /// Set the buffer group index.
    pub const fn buf_index(mut self, index: u16) -> Self {
        self.inner.buf_index = index;
        self
    }

    /// Set the personality ID.
    pub const fn personality(mut self, id: u16) -> Self {
        self.inner.personality = id;
        self
    }

    /// Build the raw SQE.
    pub const fn build(self) -> IoUringSqe {
        self.inner
    }

    /// Validate the SQE before submission.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the opcode is out of range or
    /// required fields are missing.
    pub fn validate(&self) -> Result<()> {
        // Opcode range check.
        if self.inner.opcode > IoUringOp::RemoveBuffers as u8 {
            return Err(Error::InvalidArgument);
        }
        // NOP does not require a valid fd.
        if self.inner.opcode != IoUringOp::Nop as u8 && self.inner.fd < 0 {
            // Fixed file uses index, so fd == -1 when FIXED_FILE is set
            // but buf_index is the real file index.
            if self.inner.flags & IOSQE_FIXED_FILE == 0 {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }
}

impl Default for SqEntry {
    fn default() -> Self {
        Self::new(IoUringOp::Nop)
    }
}

// ---------------------------------------------------------------------------
// CqEntry — completion queue entry reader
// ---------------------------------------------------------------------------

/// Reader for completion queue entries.
///
/// Wraps [`IoUringCqe`] with convenience accessors for result
/// interpretation.
#[derive(Debug, Clone, Copy)]
pub struct CqEntry {
    inner: IoUringCqe,
}

/// CQE flag: buffer was provided from a buffer group.
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
/// CQE flag: more CQEs will follow for this request.
pub const IORING_CQE_F_MORE: u32 = 1 << 1;

impl CqEntry {
    /// Wrap a raw CQE.
    pub const fn from_raw(cqe: IoUringCqe) -> Self {
        Self { inner: cqe }
    }

    /// Return the user data associated with the original SQE.
    pub const fn user_data(&self) -> u64 {
        self.inner.user_data
    }

    /// Return the result code.
    ///
    /// Positive values typically indicate byte counts; negative values
    /// represent errors (as negated errno).
    pub const fn result(&self) -> i32 {
        self.inner.res
    }

    /// Return `true` if the operation succeeded (result >= 0).
    pub const fn is_success(&self) -> bool {
        self.inner.res >= 0
    }

    /// Return the error as an `Error` if the result is negative.
    pub fn error(&self) -> Option<Error> {
        if self.inner.res >= 0 {
            return None;
        }
        Some(match self.inner.res {
            -1 => Error::PermissionDenied,
            -2 => Error::NotFound,
            -9 => Error::InvalidArgument,
            -12 => Error::OutOfMemory,
            -16 => Error::Busy,
            -5 => Error::IoError,
            -11 => Error::WouldBlock,
            -4 => Error::Interrupted,
            _ => Error::IoError,
        })
    }

    /// Return the CQE flags.
    pub const fn flags(&self) -> u32 {
        self.inner.flags
    }

    /// Whether the buffer flag is set.
    pub const fn has_buffer(&self) -> bool {
        self.inner.flags & IORING_CQE_F_BUFFER != 0
    }

    /// Whether more CQEs will follow.
    pub const fn has_more(&self) -> bool {
        self.inner.flags & IORING_CQE_F_MORE != 0
    }

    /// Extract the buffer ID from the CQE flags (upper 16 bits).
    pub const fn buffer_id(&self) -> u16 {
        (self.inner.flags >> 16) as u16
    }

    /// Return the raw CQE.
    pub const fn raw(&self) -> &IoUringCqe {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// IoUringInstanceSnapshot — read-only state snapshot
// ---------------------------------------------------------------------------

/// Read-only snapshot of an io_uring instance's state.
///
/// Obtained via [`query_ring`]; useful for diagnostics and monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringInstanceSnapshot {
    /// File descriptor (ring index).
    pub fd: i32,
    /// Number of pending submissions.
    pub pending_submissions: u32,
    /// Number of pending completions.
    pub pending_completions: u32,
    /// Total CQ overflow count.
    pub cq_overflow: u64,
    /// Total submissions ever made.
    pub total_submitted: u64,
    /// Total completions ever produced.
    pub total_completed: u64,
}

// ---------------------------------------------------------------------------
// IoUringCall — discriminated syscall request
// ---------------------------------------------------------------------------

/// Discriminated io_uring syscall request.
///
/// Each variant carries the validated arguments for one of the three
/// io_uring syscalls.  [`IoUringCall::dispatch`] executes the request.
#[derive(Debug)]
pub enum IoUringCall<'a> {
    /// `io_uring_setup(entries, params)`.
    Setup {
        /// Desired SQ entries.
        entries: u32,
        /// In/out parameters (mutable for kernel to fill).
        params: &'a mut IoUringParams,
    },
    /// `io_uring_enter(fd, to_submit, min_complete, flags)`.
    Enter {
        /// Ring file descriptor.
        fd: i32,
        /// SQEs to submit.
        to_submit: u32,
        /// Minimum completions to wait for.
        min_complete: u32,
        /// Enter flags.
        flags: u32,
    },
    /// `io_uring_register(fd, opcode, nr_args)`.
    Register {
        /// Ring file descriptor.
        fd: i32,
        /// Register opcode.
        opcode: u32,
        /// Number of items.
        nr_args: u32,
    },
    /// `io_uring_destroy(fd)` — ONCRIX extension.
    Destroy {
        /// Ring file descriptor.
        fd: i32,
    },
}

impl<'a> IoUringCall<'a> {
    /// Dispatch the call to the appropriate handler.
    ///
    /// # Returns
    ///
    /// An `i32` result whose meaning depends on the call variant:
    /// - Setup: ring file descriptor
    /// - Enter: number of SQEs submitted
    /// - Register: 0 or personality ID
    /// - Destroy: always 0
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying handler.
    pub fn dispatch(self) -> Result<i32> {
        match self {
            Self::Setup { entries, params } => sys_io_uring_setup(entries, params),
            Self::Enter {
                fd,
                to_submit,
                min_complete,
                flags,
            } => sys_io_uring_enter(fd, to_submit, min_complete, flags),
            Self::Register {
                fd,
                opcode,
                nr_args,
            } => sys_io_uring_register(fd, opcode, nr_args),
            Self::Destroy { fd } => {
                sys_io_uring_destroy(fd)?;
                Ok(0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// High-level helpers
// ---------------------------------------------------------------------------

/// Create an io_uring instance with default parameters.
///
/// # Arguments
///
/// * `sq_entries` — desired SQ ring size (rounded up to power of 2)
///
/// # Returns
///
/// `(fd, params)` where `fd` is the ring file descriptor and `params`
/// contains the negotiated ring configuration.
pub fn create_ring(sq_entries: u32) -> Result<(i32, IoUringParams)> {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(sq_entries, &mut params)?;
    Ok((fd, params))
}

/// Create an io_uring instance with SQPOLL enabled.
///
/// # Arguments
///
/// * `sq_entries` — desired SQ ring size
/// * `idle_ms` — SQ poll thread idle timeout in milliseconds
///
/// # Returns
///
/// `(fd, params)` on success.
pub fn create_ring_sqpoll(sq_entries: u32, idle_ms: u32) -> Result<(i32, IoUringParams)> {
    let mut params = IoUringParams::default();
    params.flags = IORING_SETUP_SQPOLL;
    params.sq_thread_idle = idle_ms;
    let fd = sys_io_uring_setup(sq_entries, &mut params)?;
    Ok((fd, params))
}

/// Create an io_uring instance with a custom CQ size.
///
/// # Arguments
///
/// * `sq_entries` — desired SQ ring size
/// * `cq_entries` — desired CQ ring size (must be >= sq_entries)
///
/// # Returns
///
/// `(fd, params)` on success.
pub fn create_ring_with_cq(sq_entries: u32, cq_entries: u32) -> Result<(i32, IoUringParams)> {
    let mut params = IoUringParams::default();
    params.flags = IORING_SETUP_CQSIZE;
    params.cq_entries = cq_entries;
    let fd = sys_io_uring_setup(sq_entries, &mut params)?;
    Ok((fd, params))
}

/// Submit SQEs and optionally wait for completions.
///
/// Convenience wrapper around `io_uring_enter`.
///
/// # Arguments
///
/// * `fd` — ring file descriptor
/// * `to_submit` — number of SQEs to submit
/// * `wait_nr` — number of completions to wait for (0 = no wait)
///
/// # Returns
///
/// Number of SQEs submitted.
pub fn submit_and_wait(fd: i32, to_submit: u32, wait_nr: u32) -> Result<i32> {
    let flags = if wait_nr > 0 {
        IORING_ENTER_GETEVENTS
    } else {
        0
    };
    sys_io_uring_enter(fd, to_submit, wait_nr, flags)
}

/// Query the state of an io_uring instance.
///
/// Returns a snapshot of the ring's current submission/completion
/// counters and overflow status.
pub fn query_ring(fd: i32) -> Result<IoUringInstanceSnapshot> {
    let (pending_sub, pending_cmp, overflow) = sys_io_uring_query(fd)?;
    let (total_sub, total_cmp) = sys_io_uring_stats(fd)?;
    Ok(IoUringInstanceSnapshot {
        fd,
        pending_submissions: pending_sub,
        pending_completions: pending_cmp,
        cq_overflow: overflow,
        total_submitted: total_sub,
        total_completed: total_cmp,
    })
}

/// Destroy an io_uring instance and release resources.
pub fn destroy_ring(fd: i32) -> Result<()> {
    sys_io_uring_destroy(fd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_flags_valid() {
        let f = IoUringSetupFlags::from_raw(IORING_SETUP_SQPOLL).unwrap();
        assert!(f.sqpoll());
        assert!(!f.iopoll());
    }

    #[test]
    fn test_setup_flags_invalid() {
        assert!(IoUringSetupFlags::from_raw(0x8000_0000).is_err());
    }

    #[test]
    fn test_sq_entry_builder() {
        let sqe = SqEntry::new(IoUringOp::Read)
            .fd(3)
            .offset(0)
            .addr(0x1000)
            .len(4096)
            .user_data(42)
            .build();
        assert_eq!(sqe.opcode, IoUringOp::Read as u8);
        assert_eq!(sqe.fd, 3);
        assert_eq!(sqe.len, 4096);
        assert_eq!(sqe.user_data, 42);
    }

    #[test]
    fn test_sq_entry_validate_nop() {
        let sqe = SqEntry::new(IoUringOp::Nop);
        assert!(sqe.validate().is_ok());
    }

    #[test]
    fn test_sq_entry_validate_read_no_fd() {
        let sqe = SqEntry::new(IoUringOp::Read);
        // fd == -1 without FIXED_FILE should fail.
        assert!(sqe.validate().is_err());
    }

    #[test]
    fn test_sq_entry_validate_read_fixed_file() {
        let sqe = SqEntry::new(IoUringOp::Read)
            .flags(IOSQE_FIXED_FILE)
            .buf_index(0);
        assert!(sqe.validate().is_ok());
    }

    #[test]
    fn test_cq_entry_success() {
        let cqe = CqEntry::from_raw(IoUringCqe {
            user_data: 42,
            res: 4096,
            flags: 0,
        });
        assert!(cqe.is_success());
        assert_eq!(cqe.user_data(), 42);
        assert_eq!(cqe.result(), 4096);
        assert!(cqe.error().is_none());
    }

    #[test]
    fn test_cq_entry_error() {
        let cqe = CqEntry::from_raw(IoUringCqe {
            user_data: 1,
            res: -9,
            flags: 0,
        });
        assert!(!cqe.is_success());
        assert_eq!(cqe.error(), Some(Error::InvalidArgument));
    }

    #[test]
    fn test_cq_entry_buffer_flag() {
        let cqe = CqEntry::from_raw(IoUringCqe {
            user_data: 0,
            res: 0,
            flags: IORING_CQE_F_BUFFER | (7u32 << 16),
        });
        assert!(cqe.has_buffer());
        assert_eq!(cqe.buffer_id(), 7);
    }

    #[test]
    fn test_cq_entry_more_flag() {
        let cqe = CqEntry::from_raw(IoUringCqe {
            user_data: 0,
            res: 0,
            flags: IORING_CQE_F_MORE,
        });
        assert!(cqe.has_more());
    }

    #[test]
    fn test_create_ring() {
        let (fd, params) = create_ring(8).unwrap();
        assert!(fd >= 0);
        assert!(params.sq_entries >= 8);
        assert!(params.cq_entries >= params.sq_entries);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_create_ring_with_cq() {
        let (fd, params) = create_ring_with_cq(8, 32).unwrap();
        assert!(fd >= 0);
        assert!(params.cq_entries >= 32);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_submit_and_wait() {
        let (fd, _) = create_ring(16).unwrap();
        let submitted = submit_and_wait(fd, 4, 0).unwrap();
        assert_eq!(submitted, 4);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_submit_and_wait_with_getevents() {
        let (fd, _) = create_ring(16).unwrap();
        let submitted = submit_and_wait(fd, 2, 1).unwrap();
        assert_eq!(submitted, 2);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_query_ring() {
        let (fd, _) = create_ring(8).unwrap();
        submit_and_wait(fd, 3, 0).unwrap();
        let snap = query_ring(fd).unwrap();
        assert_eq!(snap.fd, fd);
        assert_eq!(snap.total_submitted, 3);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_dispatch_setup() {
        let mut params = IoUringParams::default();
        let fd = IoUringCall::Setup {
            entries: 8,
            params: &mut params,
        }
        .dispatch()
        .unwrap();
        assert!(fd >= 0);

        IoUringCall::Destroy { fd }.dispatch().unwrap();
    }

    #[test]
    fn test_dispatch_enter() {
        let (fd, _) = create_ring(16).unwrap();
        let n = IoUringCall::Enter {
            fd,
            to_submit: 2,
            min_complete: 0,
            flags: 0,
        }
        .dispatch()
        .unwrap();
        assert_eq!(n, 2);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_dispatch_register() {
        let (fd, _) = create_ring(8).unwrap();
        // Register 4 buffers.
        let result = IoUringCall::Register {
            fd,
            opcode: 0, // IORING_REGISTER_BUFFERS
            nr_args: 4,
        }
        .dispatch();
        assert!(result.is_ok());
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_dispatch_destroy() {
        let (fd, _) = create_ring(8).unwrap();
        let result = IoUringCall::Destroy { fd }.dispatch();
        assert!(result.is_ok());
    }

    #[test]
    fn test_destroy_invalid_fd() {
        assert!(destroy_ring(-1).is_err());
    }

    #[test]
    fn test_io_uring_op_values() {
        assert_eq!(IoUringOp::Nop as u8, 0);
        assert_eq!(IoUringOp::Read as u8, 22);
        assert_eq!(IoUringOp::Write as u8, 23);
        assert_eq!(IoUringOp::RemoveBuffers as u8, 32);
    }

    #[test]
    fn test_sq_entry_default() {
        let sqe = SqEntry::default();
        assert_eq!(sqe.inner.opcode, 0);
    }

    #[test]
    fn test_sq_entry_personality() {
        let sqe = SqEntry::new(IoUringOp::Nop).personality(7).build();
        assert_eq!(sqe.personality, 7);
    }

    #[test]
    fn test_sq_entry_ioprio() {
        let sqe = SqEntry::new(IoUringOp::Read).fd(3).ioprio(4).build();
        assert_eq!(sqe.ioprio, 4);
    }

    #[test]
    fn test_cq_entry_unknown_error() {
        let cqe = CqEntry::from_raw(IoUringCqe {
            user_data: 0,
            res: -999,
            flags: 0,
        });
        assert_eq!(cqe.error(), Some(Error::IoError));
    }

    #[test]
    fn test_create_ring_sqpoll() {
        let result = create_ring_sqpoll(8, 1000);
        assert!(result.is_ok());
        let (fd, params) = result.unwrap();
        assert!(params.flags & IORING_SETUP_SQPOLL != 0);
        destroy_ring(fd).unwrap();
    }

    #[test]
    fn test_instance_snapshot_fields() {
        let snap = IoUringInstanceSnapshot {
            fd: 5,
            pending_submissions: 10,
            pending_completions: 3,
            cq_overflow: 0,
            total_submitted: 100,
            total_completed: 97,
        };
        assert_eq!(snap.fd, 5);
        assert_eq!(snap.total_submitted, 100);
    }
}
