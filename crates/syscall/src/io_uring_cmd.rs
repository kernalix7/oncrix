// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_uring` passthrough commands — `IORING_OP_URING_CMD`.
//!
//! `IORING_OP_URING_CMD` allows device drivers to expose custom,
//! device-specific commands through the io_uring interface. The
//! submission queue entry (SQE) carries a `cmd_op` field that is
//! routed to the target file's `uring_cmd` file operation.
//!
//! Typical consumers:
//! - **NVMe passthrough**: submit vendor-specific NVMe commands without
//!   a dedicated `ioctl(2)` fd.
//! - **io_uring network**: send/receive via socket-specific uring ops.
//! - **GPU compute**: submit command buffers to DRM subsystem.
//!
//! # SQE layout for `IORING_OP_URING_CMD`
//!
//! ```text
//! struct io_uring_sqe {
//!   __u8  opcode;       // IORING_OP_URING_CMD = 40
//!   __u8  flags;
//!   __u16 ioprio;
//!   __s32 fd;           // target file descriptor
//!   __u64 off / addr2;  // command-specific offset or secondary buffer
//!   __u64 addr;         // pointer to device-specific command struct
//!   __u32 len;          // length of command buffer
//!   __u32 cmd_op;       // driver-defined opcode
//!   __u64 user_data;
//!   __u8  buf_index;    // fixed-buffer index (IOSQE_FIXED_FILE)
//!   // ... rest is command-specific payload (cmd[0])
//! };
//! ```
//!
//! # Fixed buffer support
//!
//! When `IOSQE_FIXED_BUFFER` is set in `sqe.flags`, `addr` is an index
//! into the pre-registered buffer table rather than a user-space pointer.
//!
//! # Completion
//!
//! The CQE carries `res` (32-bit return value) and `flags` which may
//! include `IORING_CQE_F_MORE` for multi-shot completions.
//!
//! # References
//!
//! - Linux: `io_uring/uring_cmd.c`, `include/linux/io_uring.h`
//! - Linux: `include/uapi/linux/io_uring.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// io_uring opcode for passthrough commands.
pub const IORING_OP_URING_CMD: u8 = 40;

/// SQE flag: use fixed (pre-registered) file descriptor.
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;

/// SQE flag: use fixed (pre-registered) buffer.
pub const IOSQE_FIXED_BUFFER: u8 = 1 << 3;

/// CQE flag: more completions will follow for this request.
pub const IORING_CQE_F_MORE: u32 = 1 << 1;

/// Maximum number of registered buffers in the stub table.
pub const URING_CMD_MAX_FIXED_BUFS: usize = 64;

/// Maximum length of a single uring command buffer (64 KiB).
pub const URING_CMD_MAX_BUF_LEN: u32 = 64 * 1024;

/// Syscall number for `io_uring_enter` (x86_64 Linux ABI).
pub const SYS_IO_URING_ENTER: u64 = 426;

// ---------------------------------------------------------------------------
// NVMe passthrough cmd_op codes (subset, for documentation)
// ---------------------------------------------------------------------------

/// NVMe Identify controller/namespace.
pub const NVME_URING_CMD_IO: u32 = 0x0001;
/// NVMe IO passthrough.
pub const NVME_URING_CMD_IO_VEC: u32 = 0x0002;
/// NVMe Admin passthrough.
pub const NVME_URING_CMD_ADMIN: u32 = 0x0003;
/// NVMe Admin passthrough (vectored).
pub const NVME_URING_CMD_ADMIN_VEC: u32 = 0x0004;

// ---------------------------------------------------------------------------
// UringCmdSqe — SQE fields relevant to IORING_OP_URING_CMD
// ---------------------------------------------------------------------------

/// The subset of `io_uring_sqe` fields used by `IORING_OP_URING_CMD`.
///
/// This does not reproduce the full SQE union; only fields consumed by
/// the uring_cmd dispatch path are included.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UringCmdSqe {
    /// Must be [`IORING_OP_URING_CMD`].
    pub opcode: u8,
    /// SQE flags (`IOSQE_*`).
    pub flags: u8,
    /// I/O priority.
    pub ioprio: u16,
    /// Target file descriptor (or fixed-file index if `IOSQE_FIXED_FILE`).
    pub fd: i32,
    /// Command-specific secondary address / offset.
    pub addr2: u64,
    /// User-space address of the device command buffer (or fixed-buf index
    /// if `IOSQE_FIXED_BUFFER`).
    pub addr: u64,
    /// Length of the command buffer in bytes.
    pub len: u32,
    /// Driver-defined command opcode.
    pub cmd_op: u32,
    /// User data echoed in the CQE.
    pub user_data: u64,
    /// Fixed-buffer slot index (when `IOSQE_FIXED_BUFFER` is set).
    pub buf_index: u16,
    /// Personality index (0 = default).
    pub personality: u16,
    /// Padding / additional cmd payload offset.
    pub splice_fd_in: i32,
}

impl UringCmdSqe {
    /// Return `true` if the fixed-file flag is set.
    pub const fn is_fixed_file(&self) -> bool {
        self.flags & IOSQE_FIXED_FILE != 0
    }

    /// Return `true` if the fixed-buffer flag is set.
    pub const fn is_fixed_buffer(&self) -> bool {
        self.flags & IOSQE_FIXED_BUFFER != 0
    }
}

// ---------------------------------------------------------------------------
// UringCmdCqe — CQE result for a uring_cmd
// ---------------------------------------------------------------------------

/// Completion queue entry result for `IORING_OP_URING_CMD`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringCmdCqe {
    /// User data echoed from the SQE.
    pub user_data: u64,
    /// 32-bit result code (negative → errno).
    pub res: i32,
    /// CQE flags (`IORING_CQE_F_*`).
    pub flags: u32,
    /// Extra data (driver-defined, e.g. NVMe completion DW0).
    pub extra: u64,
}

impl UringCmdCqe {
    /// Construct a successful CQE.
    pub const fn ok(user_data: u64, res: i32) -> Self {
        Self {
            user_data,
            res,
            flags: 0,
            extra: 0,
        }
    }

    /// Construct an error CQE.
    pub const fn err(user_data: u64, errno: i32) -> Self {
        Self {
            user_data,
            res: -errno,
            flags: 0,
            extra: 0,
        }
    }

    /// Construct a multi-shot CQE.
    pub const fn more(user_data: u64, res: i32, extra: u64) -> Self {
        Self {
            user_data,
            res,
            flags: IORING_CQE_F_MORE,
            extra,
        }
    }

    /// Return `true` if this is an error CQE.
    pub const fn is_err(&self) -> bool {
        self.res < 0
    }
}

// ---------------------------------------------------------------------------
// FixedBuffer — pre-registered buffer entry
// ---------------------------------------------------------------------------

/// A pre-registered buffer entry in the io_uring context.
#[derive(Debug, Clone, Copy)]
pub struct FixedBuffer {
    /// User-space base address of the registered buffer.
    pub base: u64,
    /// Length of the buffer.
    pub len: u32,
    /// `true` if this slot is occupied.
    pub occupied: bool,
}

impl FixedBuffer {
    /// Create an occupied fixed-buffer entry.
    pub const fn new(base: u64, len: u32) -> Self {
        Self {
            base,
            len,
            occupied: true,
        }
    }

    /// Create an empty (unused) slot.
    pub const fn empty() -> Self {
        Self {
            base: 0,
            len: 0,
            occupied: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FixedBufTable — per-ring registered buffer table
// ---------------------------------------------------------------------------

/// Fixed-buffer registration table for a single io_uring context.
pub struct FixedBufTable {
    bufs: [FixedBuffer; URING_CMD_MAX_FIXED_BUFS],
    count: usize,
}

impl FixedBufTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            bufs: [const { FixedBuffer::empty() }; URING_CMD_MAX_FIXED_BUFS],
            count: 0,
        }
    }

    /// Register a buffer at slot `index`.
    ///
    /// Returns `InvalidArgument` if `index` is out of range or already occupied.
    pub fn register(&mut self, index: usize, base: u64, len: u32) -> Result<()> {
        if index >= URING_CMD_MAX_FIXED_BUFS {
            return Err(Error::InvalidArgument);
        }
        if self.bufs[index].occupied {
            return Err(Error::InvalidArgument);
        }
        if len == 0 || len > URING_CMD_MAX_BUF_LEN {
            return Err(Error::InvalidArgument);
        }
        self.bufs[index] = FixedBuffer::new(base, len);
        self.count += 1;
        Ok(())
    }

    /// Unregister the buffer at slot `index`.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= URING_CMD_MAX_FIXED_BUFS {
            return Err(Error::InvalidArgument);
        }
        if !self.bufs[index].occupied {
            return Err(Error::NotFound);
        }
        self.bufs[index] = FixedBuffer::empty();
        self.count -= 1;
        Ok(())
    }

    /// Resolve a fixed-buffer index to `(base, len)`.
    pub fn resolve(&self, index: u16) -> Result<(u64, u32)> {
        let i = index as usize;
        if i >= URING_CMD_MAX_FIXED_BUFS {
            return Err(Error::InvalidArgument);
        }
        let b = &self.bufs[i];
        if !b.occupied {
            return Err(Error::NotFound);
        }
        Ok((b.base, b.len))
    }

    /// Return the number of registered buffers.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for FixedBufTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UringCmdCtx — resolved context for executing a uring_cmd
// ---------------------------------------------------------------------------

/// Resolved execution context derived from a validated SQE.
#[derive(Debug, Clone, Copy)]
pub struct UringCmdCtx {
    /// Resolved file descriptor (after fixed-file indirection).
    pub fd: i32,
    /// Resolved command buffer base address.
    pub buf_addr: u64,
    /// Command buffer length.
    pub buf_len: u32,
    /// Driver-defined command opcode.
    pub cmd_op: u32,
    /// Secondary address / offset (driver-specific).
    pub addr2: u64,
    /// User data for CQE matching.
    pub user_data: u64,
}

// ---------------------------------------------------------------------------
// UringCmdDriver — trait for device-specific command handlers
// ---------------------------------------------------------------------------

/// Trait implemented by drivers that handle `IORING_OP_URING_CMD`.
pub trait UringCmdDriver {
    /// Handle a resolved uring command.
    ///
    /// Returns a [`UringCmdCqe`] that will be placed into the CQE ring.
    fn handle(&self, ctx: &UringCmdCtx) -> UringCmdCqe;
}

// ---------------------------------------------------------------------------
// validate_uring_cmd_sqe
// ---------------------------------------------------------------------------

/// Validate a `IORING_OP_URING_CMD` SQE.
///
/// # Checks
///
/// - `opcode` is `IORING_OP_URING_CMD`.
/// - `fd` is non-negative (or fixed-file index is valid).
/// - `len` is within bounds.
/// - No unknown flags.
pub fn validate_uring_cmd_sqe(sqe: &UringCmdSqe) -> Result<()> {
    if sqe.opcode != IORING_OP_URING_CMD {
        return Err(Error::InvalidArgument);
    }
    // fd must be non-negative unless fixed-file mode is used.
    if !sqe.is_fixed_file() && sqe.fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if sqe.len > URING_CMD_MAX_BUF_LEN {
        return Err(Error::InvalidArgument);
    }
    // Unknown flag bits (only IOSQE_FIXED_FILE and IOSQE_FIXED_BUFFER known).
    let known_flags = IOSQE_FIXED_FILE | IOSQE_FIXED_BUFFER;
    if sqe.flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixed-file table (stub)
// ---------------------------------------------------------------------------

/// Fixed-file (pre-registered) file descriptor entry.
#[derive(Debug, Clone, Copy)]
pub struct FixedFile {
    /// The actual file descriptor.
    pub fd: i32,
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl FixedFile {
    /// Create an occupied entry.
    pub const fn new(fd: i32) -> Self {
        Self { fd, occupied: true }
    }

    /// Create an empty slot.
    pub const fn empty() -> Self {
        Self {
            fd: -1,
            occupied: false,
        }
    }
}

/// Maximum number of pre-registered files.
pub const URING_CMD_MAX_FIXED_FILES: usize = 1024;

/// Fixed-file registration table.
pub struct FixedFileTable {
    files: alloc::boxed::Box<[FixedFile; URING_CMD_MAX_FIXED_FILES]>,
}

impl FixedFileTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            files: alloc::boxed::Box::new(
                [const { FixedFile::empty() }; URING_CMD_MAX_FIXED_FILES],
            ),
        }
    }

    /// Register a file at slot `index`.
    pub fn register(&mut self, index: usize, fd: i32) -> Result<()> {
        if index >= URING_CMD_MAX_FIXED_FILES {
            return Err(Error::InvalidArgument);
        }
        if self.files[index].occupied {
            return Err(Error::InvalidArgument);
        }
        self.files[index] = FixedFile::new(fd);
        Ok(())
    }

    /// Resolve a fixed-file index to a real `fd`.
    pub fn resolve(&self, index: i32) -> Result<i32> {
        if index < 0 || index as usize >= URING_CMD_MAX_FIXED_FILES {
            return Err(Error::InvalidArgument);
        }
        let f = &self.files[index as usize];
        if !f.occupied {
            return Err(Error::NotFound);
        }
        Ok(f.fd)
    }
}

impl Default for FixedFileTable {
    fn default() -> Self {
        Self::new()
    }
}

extern crate alloc;

// ---------------------------------------------------------------------------
// do_uring_cmd_dispatch
// ---------------------------------------------------------------------------

/// Resolve and prepare a `IORING_OP_URING_CMD` request.
///
/// # Steps
///
/// 1. Validate the SQE.
/// 2. Resolve the file descriptor (fixed-file indirection if needed).
/// 3. Resolve the buffer address (fixed-buffer indirection if needed).
/// 4. Return the resolved [`UringCmdCtx`].
///
/// # Arguments
///
/// - `sqe`      — The submission queue entry.
/// - `file_tbl` — Fixed-file registration table (may be `None` if not used).
/// - `buf_tbl`  — Fixed-buffer registration table (may be `None` if not used).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Invalid SQE fields.
/// - [`Error::NotFound`]        — Fixed-file or fixed-buffer slot not occupied.
pub fn do_uring_cmd_dispatch(
    sqe: &UringCmdSqe,
    file_tbl: Option<&FixedFileTable>,
    buf_tbl: Option<&FixedBufTable>,
) -> Result<UringCmdCtx> {
    validate_uring_cmd_sqe(sqe)?;

    // Resolve file descriptor.
    let fd = if sqe.is_fixed_file() {
        match file_tbl {
            Some(tbl) => tbl.resolve(sqe.fd)?,
            None => return Err(Error::NotFound),
        }
    } else {
        sqe.fd
    };

    // Resolve buffer.
    let (buf_addr, buf_len) = if sqe.is_fixed_buffer() {
        match buf_tbl {
            Some(tbl) => tbl.resolve(sqe.buf_index)?,
            None => return Err(Error::NotFound),
        }
    } else {
        (sqe.addr, sqe.len)
    };

    // Validate resolved buffer pointer (must not be null for non-zero length).
    if buf_len > 0 && buf_addr == 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(UringCmdCtx {
        fd,
        buf_addr,
        buf_len,
        cmd_op: sqe.cmd_op,
        addr2: sqe.addr2,
        user_data: sqe.user_data,
    })
}

// ---------------------------------------------------------------------------
// NVMe stub driver
// ---------------------------------------------------------------------------

/// Stub NVMe uring_cmd driver for documentation/testing purposes.
///
/// In a real implementation this would interact with the NVMe controller
/// via the hardware submission/completion queues.
pub struct NvmeUringDriver {
    /// Device namespace ID (used to route commands).
    pub nsid: u32,
}

impl UringCmdDriver for NvmeUringDriver {
    fn handle(&self, ctx: &UringCmdCtx) -> UringCmdCqe {
        match ctx.cmd_op {
            NVME_URING_CMD_IO | NVME_URING_CMD_IO_VEC => {
                // Simulated successful I/O completion.
                UringCmdCqe::ok(ctx.user_data, 0)
            }
            NVME_URING_CMD_ADMIN | NVME_URING_CMD_ADMIN_VEC => {
                // Simulated admin command — return nsid as extra data.
                UringCmdCqe {
                    user_data: ctx.user_data,
                    res: 0,
                    flags: 0,
                    extra: self.nsid as u64,
                }
            }
            _ => UringCmdCqe::err(ctx.user_data, 22), // EINVAL
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_sqe(cmd_op: u32) -> UringCmdSqe {
        UringCmdSqe {
            opcode: IORING_OP_URING_CMD,
            flags: 0,
            ioprio: 0,
            fd: 5,
            addr2: 0,
            addr: 0x1000,
            len: 64,
            cmd_op,
            user_data: 0xDEAD,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
        }
    }

    // --- validate_uring_cmd_sqe ---

    #[test]
    fn validate_ok() {
        assert_eq!(
            validate_uring_cmd_sqe(&basic_sqe(NVME_URING_CMD_IO)),
            Ok(())
        );
    }

    #[test]
    fn validate_wrong_opcode() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.opcode = 0;
        assert_eq!(validate_uring_cmd_sqe(&sqe), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_negative_fd_without_fixed_file() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.fd = -1;
        assert_eq!(validate_uring_cmd_sqe(&sqe), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_len_overflow() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.len = URING_CMD_MAX_BUF_LEN + 1;
        assert_eq!(validate_uring_cmd_sqe(&sqe), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_unknown_flag_bits() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.flags = 0xFF;
        assert_eq!(validate_uring_cmd_sqe(&sqe), Err(Error::InvalidArgument));
    }

    // --- FixedBufTable ---

    #[test]
    fn fixed_buf_register_and_resolve() {
        let mut tbl = FixedBufTable::new();
        tbl.register(0, 0x2000, 512).unwrap();
        let (base, len) = tbl.resolve(0).unwrap();
        assert_eq!(base, 0x2000);
        assert_eq!(len, 512);
    }

    #[test]
    fn fixed_buf_double_register_fails() {
        let mut tbl = FixedBufTable::new();
        tbl.register(0, 0x2000, 512).unwrap();
        assert_eq!(tbl.register(0, 0x3000, 256), Err(Error::InvalidArgument));
    }

    #[test]
    fn fixed_buf_unregister() {
        let mut tbl = FixedBufTable::new();
        tbl.register(1, 0x4000, 256).unwrap();
        tbl.unregister(1).unwrap();
        assert_eq!(tbl.resolve(1), Err(Error::NotFound));
    }

    #[test]
    fn fixed_buf_resolve_empty_slot() {
        let tbl = FixedBufTable::new();
        assert_eq!(tbl.resolve(5), Err(Error::NotFound));
    }

    #[test]
    fn fixed_buf_zero_len_rejected() {
        let mut tbl = FixedBufTable::new();
        assert_eq!(tbl.register(0, 0x1000, 0), Err(Error::InvalidArgument));
    }

    // --- FixedFileTable ---

    #[test]
    fn fixed_file_register_resolve() {
        let mut tbl = FixedFileTable::new();
        tbl.register(3, 7).unwrap();
        assert_eq!(tbl.resolve(3).unwrap(), 7);
    }

    #[test]
    fn fixed_file_resolve_empty() {
        let tbl = FixedFileTable::new();
        assert_eq!(tbl.resolve(0), Err(Error::NotFound));
    }

    // --- do_uring_cmd_dispatch ---

    #[test]
    fn dispatch_plain_sqe() {
        let sqe = basic_sqe(NVME_URING_CMD_IO);
        let ctx = do_uring_cmd_dispatch(&sqe, None, None).unwrap();
        assert_eq!(ctx.fd, 5);
        assert_eq!(ctx.buf_addr, 0x1000);
        assert_eq!(ctx.buf_len, 64);
        assert_eq!(ctx.cmd_op, NVME_URING_CMD_IO);
        assert_eq!(ctx.user_data, 0xDEAD);
    }

    #[test]
    fn dispatch_with_fixed_file() {
        let mut file_tbl = FixedFileTable::new();
        file_tbl.register(2, 99).unwrap();

        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.flags = IOSQE_FIXED_FILE;
        sqe.fd = 2; // index into fixed-file table

        let ctx = do_uring_cmd_dispatch(&sqe, Some(&file_tbl), None).unwrap();
        assert_eq!(ctx.fd, 99);
    }

    #[test]
    fn dispatch_with_fixed_buffer() {
        let mut buf_tbl = FixedBufTable::new();
        buf_tbl.register(1, 0x8000, 1024).unwrap();

        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.flags = IOSQE_FIXED_BUFFER;
        sqe.buf_index = 1;
        sqe.addr = 1; // index (overridden by fixed-buf resolution)
        sqe.len = 0; // overridden

        let ctx = do_uring_cmd_dispatch(&sqe, None, Some(&buf_tbl)).unwrap();
        assert_eq!(ctx.buf_addr, 0x8000);
        assert_eq!(ctx.buf_len, 1024);
    }

    #[test]
    fn dispatch_fixed_file_no_table_fails() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.flags = IOSQE_FIXED_FILE;
        assert_eq!(
            do_uring_cmd_dispatch(&sqe, None, None),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn dispatch_fixed_buf_no_table_fails() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.flags = IOSQE_FIXED_BUFFER;
        assert_eq!(
            do_uring_cmd_dispatch(&sqe, None, None),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn dispatch_null_buf_addr_nonzero_len_fails() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.addr = 0; // null pointer
        sqe.len = 64;
        assert_eq!(
            do_uring_cmd_dispatch(&sqe, None, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn dispatch_zero_len_null_addr_ok() {
        let mut sqe = basic_sqe(NVME_URING_CMD_IO);
        sqe.addr = 0;
        sqe.len = 0;
        let ctx = do_uring_cmd_dispatch(&sqe, None, None).unwrap();
        assert_eq!(ctx.buf_len, 0);
    }

    // --- UringCmdCqe ---

    #[test]
    fn cqe_ok_not_error() {
        let cqe = UringCmdCqe::ok(42, 0);
        assert!(!cqe.is_err());
        assert_eq!(cqe.res, 0);
    }

    #[test]
    fn cqe_err_is_negative() {
        let cqe = UringCmdCqe::err(1, 22);
        assert!(cqe.is_err());
        assert_eq!(cqe.res, -22);
    }

    #[test]
    fn cqe_more_flag_set() {
        let cqe = UringCmdCqe::more(5, 0, 0xABCD);
        assert_eq!(cqe.flags & IORING_CQE_F_MORE, IORING_CQE_F_MORE);
        assert_eq!(cqe.extra, 0xABCD);
    }

    // --- NvmeUringDriver ---

    #[test]
    fn nvme_driver_io_success() {
        let drv = NvmeUringDriver { nsid: 1 };
        let ctx = UringCmdCtx {
            fd: 3,
            buf_addr: 0x1000,
            buf_len: 512,
            cmd_op: NVME_URING_CMD_IO,
            addr2: 0,
            user_data: 0xBEEF,
        };
        let cqe = drv.handle(&ctx);
        assert!(!cqe.is_err());
        assert_eq!(cqe.user_data, 0xBEEF);
    }

    #[test]
    fn nvme_driver_admin_returns_nsid() {
        let drv = NvmeUringDriver { nsid: 42 };
        let ctx = UringCmdCtx {
            fd: 3,
            buf_addr: 0x1000,
            buf_len: 64,
            cmd_op: NVME_URING_CMD_ADMIN,
            addr2: 0,
            user_data: 1,
        };
        let cqe = drv.handle(&ctx);
        assert_eq!(cqe.extra, 42);
    }

    #[test]
    fn nvme_driver_unknown_cmd_op_fails() {
        let drv = NvmeUringDriver { nsid: 1 };
        let ctx = UringCmdCtx {
            fd: 3,
            buf_addr: 0x1000,
            buf_len: 64,
            cmd_op: 0xFFFF,
            addr2: 0,
            user_data: 0,
        };
        let cqe = drv.handle(&ctx);
        assert!(cqe.is_err());
        assert_eq!(cqe.res, -22); // EINVAL
    }
}
