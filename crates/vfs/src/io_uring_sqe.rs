// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring submission queue entries.
//!
//! Implements the io_uring SQE (Submission Queue Entry) structures and
//! parsing/validation logic. The SQE ring is a lock-free circular buffer
//! shared between user space and the kernel for submitting I/O operations.

use oncrix_lib::{Error, Result};

/// io_uring opcode constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoUringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    FSync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    SendMsg = 9,
    RecvMsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    OpenAt = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    FAdvise = 24,
    MAdvise = 25,
    Send = 26,
    Recv = 27,
    OpenAt2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    RenameAt = 35,
    UnlinkAt = 36,
    MkdirAt = 37,
    SymlinkAt = 38,
    LinkAt = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendMsgZc = 48,
}

impl TryFrom<u8> for IoUringOp {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Nop),
            1 => Ok(Self::Readv),
            2 => Ok(Self::Writev),
            3 => Ok(Self::FSync),
            4 => Ok(Self::ReadFixed),
            5 => Ok(Self::WriteFixed),
            6 => Ok(Self::PollAdd),
            7 => Ok(Self::PollRemove),
            8 => Ok(Self::SyncFileRange),
            9 => Ok(Self::SendMsg),
            10 => Ok(Self::RecvMsg),
            11 => Ok(Self::Timeout),
            12 => Ok(Self::TimeoutRemove),
            13 => Ok(Self::Accept),
            14 => Ok(Self::AsyncCancel),
            15 => Ok(Self::LinkTimeout),
            16 => Ok(Self::Connect),
            17 => Ok(Self::Fallocate),
            18 => Ok(Self::OpenAt),
            19 => Ok(Self::Close),
            20 => Ok(Self::FilesUpdate),
            21 => Ok(Self::Statx),
            22 => Ok(Self::Read),
            23 => Ok(Self::Write),
            24 => Ok(Self::FAdvise),
            25 => Ok(Self::MAdvise),
            26 => Ok(Self::Send),
            27 => Ok(Self::Recv),
            28 => Ok(Self::OpenAt2),
            29 => Ok(Self::EpollCtl),
            30 => Ok(Self::Splice),
            31 => Ok(Self::ProvideBuffers),
            32 => Ok(Self::RemoveBuffers),
            33 => Ok(Self::Tee),
            34 => Ok(Self::Shutdown),
            35 => Ok(Self::RenameAt),
            36 => Ok(Self::UnlinkAt),
            37 => Ok(Self::MkdirAt),
            38 => Ok(Self::SymlinkAt),
            39 => Ok(Self::LinkAt),
            40 => Ok(Self::MsgRing),
            41 => Ok(Self::Fsetxattr),
            42 => Ok(Self::Setxattr),
            43 => Ok(Self::Fgetxattr),
            44 => Ok(Self::Getxattr),
            45 => Ok(Self::Socket),
            46 => Ok(Self::UringCmd),
            47 => Ok(Self::SendZc),
            48 => Ok(Self::SendMsgZc),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// SQE flags.
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// io_uring setup flags.
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;

/// A Submission Queue Entry (SQE) — 64 bytes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringSqe {
    /// Operation code.
    pub opcode: u8,
    /// SQE flags (IOSQE_*).
    pub flags: u8,
    /// ioprio for the request.
    pub ioprio: u16,
    /// File descriptor index.
    pub fd: i32,
    /// Union: offset, addr2, or splice_off_in.
    pub off_addr2: u64,
    /// Union: buffer address, splice_fd_in, or addr3.
    pub addr_splice_fd: u64,
    /// Buffer length or number of iovecs.
    pub len: u32,
    /// Opcode-specific flags.
    pub op_flags: u32,
    /// User data tag passed through to CQE.
    pub user_data: u64,
    /// Buffer index or group (for fixed/provided buffers).
    pub buf_index: u16,
    /// Personality (credential) to use.
    pub personality: u16,
    /// Splice source fd or file_index.
    pub splice_fd_in: i32,
    /// Additional address or padding.
    pub addr3: u64,
    /// Reserved.
    pub _pad: u64,
}

/// A Completion Queue Entry (CQE) — 16 bytes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringCqe {
    /// User data from the corresponding SQE.
    pub user_data: u64,
    /// Result: ≥0 on success, negative errno on error.
    pub res: i32,
    /// CQE flags.
    pub flags: u32,
}

/// CQE flags.
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;
pub const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
pub const IORING_CQE_F_NOTIF: u32 = 1 << 3;

/// Maximum SQ/CQ ring size.
pub const IORING_MAX_ENTRIES: u32 = 32768;

/// Submission Queue ring state (kernel-managed).
#[derive(Debug)]
pub struct SqRing {
    /// Ring entries (SQEs).
    pub sqes: [IoUringSqe; 256],
    /// Indirect index array.
    pub array: [u32; 256],
    /// Head (consumer) position.
    pub head: u32,
    /// Tail (producer) position.
    pub tail: u32,
    /// Ring mask (entries - 1).
    pub ring_mask: u32,
    /// Number of entries.
    pub ring_entries: u32,
    /// Dropped submissions.
    pub dropped: u32,
    /// Ring flags.
    pub flags: u32,
}

impl SqRing {
    /// Create a new SQ ring with the given number of entries (must be power of 2).
    pub fn new(entries: u32) -> Result<Self> {
        if entries == 0 || entries > 256 || (entries & (entries - 1)) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            sqes: [IoUringSqe::default(); 256],
            array: [0u32; 256],
            head: 0,
            tail: 0,
            ring_mask: entries - 1,
            ring_entries: entries,
            dropped: 0,
            flags: 0,
        })
    }

    /// Number of pending (unconsumed) entries.
    pub fn pending(&self) -> u32 {
        self.tail.wrapping_sub(self.head)
    }

    /// Return true if the ring has no pending entries.
    pub fn is_empty(&self) -> bool {
        self.pending() == 0
    }

    /// Consume the next SQE, returning it.
    pub fn consume(&mut self) -> Option<IoUringSqe> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.array[self.head as usize & self.ring_mask as usize]) as usize;
        let sqe = self.sqes[idx % self.ring_entries as usize];
        self.head = self.head.wrapping_add(1);
        Some(sqe)
    }

    /// Submit a single SQE to the ring.
    pub fn submit(&mut self, sqe: IoUringSqe) -> Result<()> {
        if self.pending() >= self.ring_entries {
            return Err(Error::WouldBlock);
        }
        let tail_idx = self.tail as usize & self.ring_mask as usize;
        self.sqes[tail_idx] = sqe;
        self.array[tail_idx] = tail_idx as u32;
        self.tail = self.tail.wrapping_add(1);
        Ok(())
    }
}

/// Completion Queue ring state.
#[derive(Debug)]
pub struct CqRing {
    /// CQEs array.
    pub cqes: [IoUringCqe; 512],
    /// Head (consumer) position.
    pub head: u32,
    /// Tail (producer) position.
    pub tail: u32,
    /// Ring mask.
    pub ring_mask: u32,
    /// Number of entries.
    pub ring_entries: u32,
    /// Overflowed CQE count.
    pub overflow: u32,
    /// CQ flags.
    pub flags: u32,
}

impl CqRing {
    /// Create a new CQ ring with the given number of entries.
    pub fn new(entries: u32) -> Result<Self> {
        if entries == 0 || entries > 512 || (entries & (entries - 1)) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cqes: [IoUringCqe::default(); 512],
            head: 0,
            tail: 0,
            ring_mask: entries - 1,
            ring_entries: entries,
            overflow: 0,
            flags: 0,
        })
    }

    /// Number of available completions.
    pub fn available(&self) -> u32 {
        self.tail.wrapping_sub(self.head)
    }

    /// Post a completion event.
    pub fn post(&mut self, cqe: IoUringCqe) -> Result<()> {
        if self.available() >= self.ring_entries {
            self.overflow += 1;
            return Err(Error::OutOfMemory);
        }
        let tail_idx = self.tail as usize & self.ring_mask as usize;
        self.cqes[tail_idx] = cqe;
        self.tail = self.tail.wrapping_add(1);
        Ok(())
    }

    /// Consume the next CQE.
    pub fn consume(&mut self) -> Option<IoUringCqe> {
        if self.available() == 0 {
            return None;
        }
        let cqe = self.cqes[self.head as usize & self.ring_mask as usize];
        self.head = self.head.wrapping_add(1);
        Some(cqe)
    }
}

/// Validate a submitted SQE for well-formedness.
pub fn validate_sqe(sqe: &IoUringSqe) -> Result<()> {
    let _ = IoUringOp::try_from(sqe.opcode)?;

    // NOP requires no fd.
    if sqe.opcode == IoUringOp::Nop as u8 {
        return Ok(());
    }

    // Fixed file operations require the FIXED_FILE flag.
    if sqe.opcode == IoUringOp::ReadFixed as u8 || sqe.opcode == IoUringOp::WriteFixed as u8 {
        if sqe.flags & IOSQE_FIXED_FILE == 0 {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(())
}
