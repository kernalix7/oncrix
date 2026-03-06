// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring filesystem operation integration for the ONCRIX VFS.
//!
//! Provides the VFS-side submission and completion plumbing for async file
//! operations submitted via io_uring. SQEs for read/write/fsync operations
//! are translated into VFS calls and their results returned via CQEs.

use oncrix_lib::{Error, Result};

/// Maximum number of SQEs that can be in-flight simultaneously.
pub const IOURING_FS_MAX_INFLIGHT: usize = 256;

/// io_uring operation codes relevant to filesystem operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoUringFsOp {
    /// `IORING_OP_READ` — read from a file descriptor.
    Read = 22,
    /// `IORING_OP_WRITE` — write to a file descriptor.
    Write = 23,
    /// `IORING_OP_FSYNC` — fsync a file.
    Fsync = 14,
    /// `IORING_OP_READV` — vectored read.
    Readv = 1,
    /// `IORING_OP_WRITEV` — vectored write.
    Writev = 2,
    /// `IORING_OP_FALLOCATE` — allocate file space.
    Fallocate = 28,
    /// `IORING_OP_OPENAT` — open a file by path relative to dirfd.
    Openat = 18,
    /// `IORING_OP_CLOSE` — close a file descriptor.
    Close = 19,
    /// `IORING_OP_STATX` — get file status.
    Statx = 21,
    /// `IORING_OP_SPLICE` — splice data between file descriptors.
    Splice = 38,
    /// `IORING_OP_COPY_FILE_RANGE` — copy file range.
    CopyFileRange = 46,
}

impl IoUringFsOp {
    /// Convert from a raw opcode byte.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Readv),
            2 => Ok(Self::Writev),
            14 => Ok(Self::Fsync),
            18 => Ok(Self::Openat),
            19 => Ok(Self::Close),
            21 => Ok(Self::Statx),
            22 => Ok(Self::Read),
            23 => Ok(Self::Write),
            28 => Ok(Self::Fallocate),
            38 => Ok(Self::Splice),
            46 => Ok(Self::CopyFileRange),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Flags usable in an io_uring filesystem SQE.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringSqeFlags {
    /// Use fixed (pre-registered) file descriptor table.
    pub fixed_file: bool,
    /// Buffer is pre-registered with the ring.
    pub fixed_buf: bool,
    /// This SQE depends on the previous completing first.
    pub io_link: bool,
    /// Drain all preceding SQEs before starting.
    pub io_drain: bool,
}

impl IoUringSqeFlags {
    /// Encode flags as the SQE `flags` byte.
    pub fn to_byte(&self) -> u8 {
        let mut b = 0u8;
        if self.fixed_file {
            b |= 1 << 0;
        }
        if self.io_drain {
            b |= 1 << 1;
        }
        if self.io_link {
            b |= 1 << 2;
        }
        if self.fixed_buf {
            b |= 1 << 4;
        }
        b
    }
}

/// Minimal io_uring SQE representation for filesystem operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringSqe {
    /// Operation code.
    pub opcode: u8,
    /// SQE flags.
    pub flags: u8,
    /// I/O priority.
    pub ioprio: u16,
    /// File descriptor (or fixed-file index).
    pub fd: i32,
    /// File offset or miscellaneous argument.
    pub off: u64,
    /// User-space buffer address.
    pub addr: u64,
    /// Length of the I/O transfer in bytes.
    pub len: u32,
    /// Operation-specific flags (e.g., `O_SYNC` for fsync).
    pub op_flags: u32,
    /// User data (returned unchanged in the CQE).
    pub user_data: u64,
}

/// Minimal io_uring CQE representation.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringCqe {
    /// User data from the corresponding SQE.
    pub user_data: u64,
    /// Result: bytes transferred, or negative errno on error.
    pub res: i32,
    /// CQE flags (e.g., `IORING_CQE_F_MORE`).
    pub flags: u32,
}

impl IoUringCqe {
    /// Construct a successful CQE with a byte count.
    pub const fn ok(user_data: u64, bytes: i32) -> Self {
        Self {
            user_data,
            res: bytes,
            flags: 0,
        }
    }

    /// Construct an error CQE from a negative errno.
    pub const fn err(user_data: u64, errno: i32) -> Self {
        Self {
            user_data,
            res: -errno,
            flags: 0,
        }
    }
}

/// State for a single in-flight io_uring filesystem operation.
#[derive(Debug, Clone, Copy)]
pub struct IoUringFsReq {
    /// Copy of the SQE.
    pub sqe: IoUringSqe,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl IoUringFsReq {
    /// Construct an inactive slot.
    pub const fn new() -> Self {
        Self {
            sqe: IoUringSqe {
                opcode: 0,
                flags: 0,
                ioprio: 0,
                fd: 0,
                off: 0,
                addr: 0,
                len: 0,
                op_flags: 0,
                user_data: 0,
            },
            active: false,
        }
    }
}

impl Default for IoUringFsReq {
    fn default() -> Self {
        Self::new()
    }
}

/// In-flight request table for io_uring filesystem operations.
pub struct IoUringFsQueue {
    reqs: [IoUringFsReq; IOURING_FS_MAX_INFLIGHT],
    count: usize,
}

impl IoUringFsQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            reqs: [const { IoUringFsReq::new() }; IOURING_FS_MAX_INFLIGHT],
            count: 0,
        }
    }

    /// Submit an SQE, returning its slot index or `Busy` if full.
    pub fn submit(&mut self, sqe: IoUringSqe) -> Result<usize> {
        if self.count >= IOURING_FS_MAX_INFLIGHT {
            return Err(Error::Busy);
        }
        for (i, slot) in self.reqs.iter_mut().enumerate() {
            if !slot.active {
                slot.sqe = sqe;
                slot.active = true;
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Complete a request at `slot_idx`, returning its CQE.
    pub fn complete(&mut self, slot_idx: usize, res: i32) -> Result<IoUringCqe> {
        if slot_idx >= IOURING_FS_MAX_INFLIGHT || !self.reqs[slot_idx].active {
            return Err(Error::InvalidArgument);
        }
        let user_data = self.reqs[slot_idx].sqe.user_data;
        self.reqs[slot_idx] = IoUringFsReq::new();
        self.count -= 1;
        Ok(if res >= 0 {
            IoUringCqe::ok(user_data, res)
        } else {
            IoUringCqe::err(user_data, -res)
        })
    }

    /// Return the number of in-flight requests.
    pub fn inflight(&self) -> usize {
        self.count
    }
}

impl Default for IoUringFsQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate an SQE's parameters for a filesystem read/write operation.
///
/// Checks that `fd` is non-negative, `len` is non-zero, and `addr` is non-null.
pub fn validate_rw_sqe(sqe: &IoUringSqe) -> Result<()> {
    if sqe.fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if sqe.len == 0 {
        return Err(Error::InvalidArgument);
    }
    if sqe.addr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Translate a VFS `Error` into a negative errno value for a CQE.
pub fn error_to_errno(e: &Error) -> i32 {
    match e {
        Error::NotFound => -2,          // ENOENT
        Error::PermissionDenied => -13, // EACCES
        Error::Busy => -16,             // EBUSY
        Error::AlreadyExists => -17,    // EEXIST
        Error::InvalidArgument => -22,  // EINVAL
        Error::OutOfMemory => -12,      // ENOMEM
        Error::WouldBlock => -11,       // EAGAIN
        Error::Interrupted => -4,       // EINTR
        Error::IoError => -5,           // EIO
        Error::NotImplemented => -38,   // ENOSYS
    }
}
