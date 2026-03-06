// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy `splice(2)` and `tee(2)` syscall handlers.
//!
//! These syscalls move or duplicate data between file descriptors using the
//! kernel pipe buffer as an intermediary, avoiding copies through user space.
//!
//! | Syscall   | Handler            | Purpose                                       |
//! |-----------|--------------------|-----------------------------------------------|
//! | `splice`  | [`do_splice`]      | Move data between an fd and a pipe            |
//! | `tee`     | [`do_tee`]         | Duplicate pipe data without consuming it      |
//! | `vmsplice`| [`do_vmsplice`]    | Map user-space memory pages into a pipe       |
//!
//! # Zero-copy model
//!
//! The kernel maintains a list of pages ("pipe buffers") for each pipe file
//! descriptor.  `splice` / `tee` operate on those page references without
//! copying the underlying data:
//!
//! ```text
//! File ──splice──▶ [pipe buf pages] ──splice──▶ Socket/File
//!                        │
//!                       tee
//!                        ▼
//!                 [pipe buf copy]   (same pages, new references)
//! ```
//!
//! `vmsplice` goes in the opposite direction: user-space virtual memory
//! pages are donated to or read from the pipe.
//!
//! # POSIX conformance
//!
//! `splice` and `tee` are Linux-specific and have no POSIX equivalent.
//! The `iovec` structure used by `vmsplice` follows the POSIX definition in
//! `.TheOpenGroup/susv5-html/basedefs/sys_uio.h.html`.
//!
//! # References
//!
//! - Linux `fs/splice.c`
//! - Linux `include/uapi/linux/splice.h`
//! - man: `splice(2)`, `tee(2)`, `vmsplice(2)`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — splice / tee flags
// ---------------------------------------------------------------------------

/// Try the operation in a non-blocking fashion.
pub const SPLICE_F_NONBLOCK: u32 = 0x0000_0002;

/// Hint: more data will follow; don't finalise the packet/segment yet.
pub const SPLICE_F_MORE: u32 = 0x0000_0004;

/// Move pages if possible (zero-copy).  Currently a no-op hint in Linux.
pub const SPLICE_F_MOVE: u32 = 0x0000_0001;

/// Splice from/to a socket with `MSG_GIFT` semantics.
pub const SPLICE_F_GIFT: u32 = 0x0000_0008;

/// Mask of all recognised splice/tee/vmsplice flags.
const SPLICE_FLAGS_KNOWN: u32 = SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_MOVE | SPLICE_F_GIFT;

/// Maximum number of bytes that may be spliced in a single call.
pub const SPLICE_MAX_LEN: usize = 1 << 26; // 64 MiB

/// Maximum pipe buffer capacity (in bytes) tracked by this stub.
pub const PIPE_MAX_BUF: usize = 1 << 20; // 1 MiB

/// Maximum number of `iovec` elements in a single `vmsplice` call.
pub const VMSPLICE_MAX_IOV: usize = 16;

// ---------------------------------------------------------------------------
// Fd type classification
// ---------------------------------------------------------------------------

/// Classification of a file descriptor endpoint for `splice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// A pipe (anonymous or named).
    Pipe,
    /// A regular file or block device.
    File,
    /// A network socket.
    Socket,
}

// ---------------------------------------------------------------------------
// PipeBuf — stub pipe buffer state
// ---------------------------------------------------------------------------

/// State of a kernel pipe buffer as seen by the splice/tee subsystem.
///
/// In a real kernel each pipe has a ring of `pipe_buffer` structs pointing
/// at page-cache pages.  Here we track only byte counts to allow correct
/// argument validation and progress simulation.
#[derive(Debug, Clone)]
pub struct PipeBuf {
    /// Pipe file descriptor number.
    pub fd: u32,
    /// Bytes currently in the buffer.
    pub used: usize,
    /// Maximum capacity in bytes.
    pub capacity: usize,
    /// Whether the write end of the pipe is closed.
    pub write_closed: bool,
    /// Whether the read end of the pipe is closed.
    pub read_closed: bool,
}

impl PipeBuf {
    /// Create a new empty pipe buffer with default capacity.
    pub const fn new(fd: u32) -> Self {
        Self {
            fd,
            used: 0,
            capacity: PIPE_MAX_BUF,
            write_closed: false,
            read_closed: false,
        }
    }

    /// Free space remaining in the buffer.
    pub const fn free(&self) -> usize {
        self.capacity - self.used
    }

    /// Return `true` if the buffer is empty.
    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }
}

// ---------------------------------------------------------------------------
// SpliceArgs — argument block for do_splice
// ---------------------------------------------------------------------------

/// Arguments for the `splice(2)` syscall.
///
/// Either `fd_in` or `fd_out` must be a pipe; the other may be any file type.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SpliceArgs {
    /// Source file descriptor.
    pub fd_in: u32,
    /// Offset in `fd_in` (`None` = use file position, `Some(n)` = explicit).
    pub off_in: Option<u64>,
    /// Destination file descriptor.
    pub fd_out: u32,
    /// Offset in `fd_out` (`None` = use file position, `Some(n)` = explicit).
    pub off_out: Option<u64>,
    /// Number of bytes to transfer.
    pub len: usize,
    /// `SPLICE_F_*` flags.
    pub flags: u32,
}

impl Default for SpliceArgs {
    fn default() -> Self {
        Self {
            fd_in: 0,
            off_in: None,
            fd_out: 0,
            off_out: None,
            len: 0,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IoVec — POSIX iovec for vmsplice
// ---------------------------------------------------------------------------

/// POSIX `iovec` structure (user-space virtual address + length).
///
/// Matches `struct iovec` from `sys/uio.h`.  The `iov_base` is a virtual
/// address in the caller's address space; in a real kernel it would be
/// validated via `access_ok` before use.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoVec {
    /// Base virtual address of the buffer.
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: usize,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `splice` flags.
fn validate_splice_flags(flags: u32) -> Result<()> {
    if flags & !SPLICE_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a transfer length.
fn validate_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if len > SPLICE_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_splice
// ---------------------------------------------------------------------------

/// `splice(2)` — transfer data between a file and a pipe.
///
/// At least one of `fd_in` / `fd_out` must identify a pipe.  Data is
/// transferred without copying through user space.
///
/// # Arguments
///
/// * `pipe`       — The pipe buffer (either input or output side).
/// * `pipe_is_in` — `true` if the pipe is the source; `false` if destination.
/// * `args`       — Splice arguments.
/// * `in_kind`    — Kind of the non-pipe endpoint.
///
/// # Returns
///
/// Number of bytes transferred (may be less than `args.len` if the pipe
/// buffer was not large enough or `SPLICE_F_NONBLOCK` was set and no data
/// was available).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags, zero length, length exceeds
///                                 limit, or `fd_in == fd_out`.
/// * [`Error::WouldBlock`]       — `SPLICE_F_NONBLOCK` set and no data
///                                 available / pipe full.
/// * [`Error::Interrupted`]      — Pipe read end or write end is closed.
pub fn do_splice(
    pipe: &mut PipeBuf,
    pipe_is_in: bool,
    args: &mut SpliceArgs,
    in_kind: FdKind,
) -> Result<usize> {
    validate_splice_flags(args.flags)?;
    validate_len(args.len)?;

    // fd_in and fd_out must differ.
    if args.fd_in == args.fd_out {
        return Err(Error::InvalidArgument);
    }

    // Offsets are not allowed for pipe endpoints.
    if pipe_is_in && args.off_in.is_some() {
        return Err(Error::InvalidArgument);
    }
    if !pipe_is_in && args.off_out.is_some() {
        return Err(Error::InvalidArgument);
    }

    // Sockets may not have explicit offsets either.
    if in_kind == FdKind::Socket {
        if pipe_is_in && args.off_out.is_some() {
            return Err(Error::InvalidArgument);
        }
        if !pipe_is_in && args.off_in.is_some() {
            return Err(Error::InvalidArgument);
        }
    }

    let nonblock = args.flags & SPLICE_F_NONBLOCK != 0;

    if pipe_is_in {
        // Pipe → file/socket: drain bytes from the pipe.
        if pipe.read_closed {
            return Err(Error::Interrupted);
        }
        if pipe.is_empty() {
            if nonblock {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock); // stub: would block on real data
        }
        let transfer = args.len.min(pipe.used);
        pipe.used -= transfer;
        // Advance destination offset if explicit.
        if let Some(ref mut off) = args.off_out {
            *off = off.saturating_add(transfer as u64);
        }
        Ok(transfer)
    } else {
        // File/socket → pipe: fill the pipe buffer.
        if pipe.write_closed {
            return Err(Error::Interrupted);
        }
        if pipe.free() == 0 {
            if nonblock {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock); // stub
        }
        let transfer = args.len.min(pipe.free());
        pipe.used += transfer;
        // Advance source offset if explicit.
        if let Some(ref mut off) = args.off_in {
            *off = off.saturating_add(transfer as u64);
        }
        Ok(transfer)
    }
}

// ---------------------------------------------------------------------------
// do_tee
// ---------------------------------------------------------------------------

/// `tee(2)` — duplicate data between two pipes without consuming the source.
///
/// Copies `len` bytes from `src` pipe to `dst` pipe by sharing the same
/// page references.  The source pipe retains its data (unlike `splice`).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags, zero length, length exceeds
///                                 limit, `fd_in == fd_out`, or either
///                                 descriptor is not a pipe.
/// * [`Error::WouldBlock`]       — `SPLICE_F_NONBLOCK` set and source is
///                                 empty or destination is full.
/// * [`Error::Interrupted`]      — A pipe end is closed.
pub fn do_tee(src: &PipeBuf, dst: &mut PipeBuf, len: usize, flags: u32) -> Result<usize> {
    validate_splice_flags(flags)?;
    validate_len(len)?;

    if src.fd == dst.fd {
        return Err(Error::InvalidArgument);
    }

    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    if src.read_closed || dst.write_closed {
        return Err(Error::Interrupted);
    }
    if src.is_empty() {
        if nonblock {
            return Err(Error::WouldBlock);
        }
        return Err(Error::WouldBlock); // stub
    }
    if dst.free() == 0 {
        if nonblock {
            return Err(Error::WouldBlock);
        }
        return Err(Error::WouldBlock); // stub
    }

    // tee: share pages — limited by available data and destination capacity.
    let transfer = len.min(src.used).min(dst.free());
    // Source is NOT drained.
    dst.used += transfer;
    Ok(transfer)
}

// ---------------------------------------------------------------------------
// do_vmsplice
// ---------------------------------------------------------------------------

/// `vmsplice(2)` — splice user-space pages into or out of a pipe.
///
/// When `SPLICE_F_GIFT` is set and the operation is "into pipe", the pages
/// are donated to the kernel (the caller must not modify them afterwards).
/// Otherwise the kernel copies the data.
///
/// # Arguments
///
/// * `pipe`        — Target or source pipe buffer.
/// * `iov`         — Array of `iovec` structures describing user-space buffers.
/// * `iov_count`   — Number of valid entries in `iov`.
/// * `flags`       — `SPLICE_F_*` flags.
/// * `into_pipe`   — `true` = write iov data into pipe; `false` = read from pipe.
///
/// # Returns
///
/// Total number of bytes moved.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags, `iov_count == 0`,
///                                 `iov_count > VMSPLICE_MAX_IOV`, any
///                                 `iov_len == 0`, or total length exceeds
///                                 `SPLICE_MAX_LEN`.
/// * [`Error::WouldBlock`]       — Non-blocking and pipe is full/empty.
/// * [`Error::Interrupted`]      — Pipe end is closed.
pub fn do_vmsplice(
    pipe: &mut PipeBuf,
    iov: &[IoVec],
    iov_count: usize,
    flags: u32,
    into_pipe: bool,
) -> Result<usize> {
    validate_splice_flags(flags)?;

    if iov_count == 0 || iov_count > VMSPLICE_MAX_IOV {
        return Err(Error::InvalidArgument);
    }
    if iov.len() < iov_count {
        return Err(Error::InvalidArgument);
    }

    // Compute total length and validate each iovec.
    let mut total_len: usize = 0;
    for v in &iov[..iov_count] {
        if v.iov_len == 0 {
            return Err(Error::InvalidArgument);
        }
        total_len = total_len.saturating_add(v.iov_len);
    }
    if total_len > SPLICE_MAX_LEN {
        return Err(Error::InvalidArgument);
    }

    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    if into_pipe {
        if pipe.write_closed {
            return Err(Error::Interrupted);
        }
        if pipe.free() == 0 {
            return if nonblock {
                Err(Error::WouldBlock)
            } else {
                Err(Error::WouldBlock)
            };
        }
        let transfer = total_len.min(pipe.free());
        pipe.used += transfer;
        Ok(transfer)
    } else {
        // Out of pipe: read data from the pipe into user-space buffers.
        if pipe.read_closed {
            return Err(Error::Interrupted);
        }
        if pipe.is_empty() {
            return if nonblock {
                Err(Error::WouldBlock)
            } else {
                Err(Error::WouldBlock)
            };
        }
        let transfer = total_len.min(pipe.used);
        pipe.used -= transfer;
        Ok(transfer)
    }
}

// ---------------------------------------------------------------------------
// Convenience dispatch wrappers
// ---------------------------------------------------------------------------

/// Dispatch entry for `splice`.
pub fn sys_splice(
    pipe: &mut PipeBuf,
    pipe_is_in: bool,
    args: &mut SpliceArgs,
    in_kind: FdKind,
) -> Result<usize> {
    do_splice(pipe, pipe_is_in, args, in_kind)
}

/// Dispatch entry for `tee`.
pub fn sys_tee(src: &PipeBuf, dst: &mut PipeBuf, len: usize, flags: u32) -> Result<usize> {
    do_tee(src, dst, len, flags)
}

/// Dispatch entry for `vmsplice`.
pub fn sys_vmsplice(
    pipe: &mut PipeBuf,
    iov: &[IoVec],
    iov_count: usize,
    flags: u32,
    into_pipe: bool,
) -> Result<usize> {
    do_vmsplice(pipe, iov, iov_count, flags, into_pipe)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pipe(fd: u32, used: usize) -> PipeBuf {
        let mut p = PipeBuf::new(fd);
        p.used = used;
        p
    }

    // --- validate helpers ---

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            validate_splice_flags(0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_len_rejected() {
        assert_eq!(validate_len(0), Err(Error::InvalidArgument));
    }

    #[test]
    fn too_large_len_rejected() {
        assert_eq!(
            validate_len(SPLICE_MAX_LEN + 1),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_splice (file → pipe) ---

    #[test]
    fn splice_file_to_pipe_fills_buf() {
        let mut pipe = make_pipe(5, 0);
        let mut args = SpliceArgs {
            fd_in: 3,
            fd_out: 5,
            len: 4096,
            ..Default::default()
        };
        let n = do_splice(&mut pipe, false, &mut args, FdKind::File).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(pipe.used, 4096);
    }

    #[test]
    fn splice_pipe_to_file_drains_buf() {
        let mut pipe = make_pipe(5, 8192);
        let mut args = SpliceArgs {
            fd_in: 5,
            fd_out: 3,
            len: 4096,
            ..Default::default()
        };
        let n = do_splice(&mut pipe, true, &mut args, FdKind::File).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(pipe.used, 4096);
    }

    #[test]
    fn splice_advances_file_offset() {
        let mut pipe = make_pipe(5, 0);
        let mut args = SpliceArgs {
            fd_in: 3,
            off_in: Some(100),
            fd_out: 5,
            off_out: None,
            len: 512,
            flags: 0,
        };
        do_splice(&mut pipe, false, &mut args, FdKind::File).unwrap();
        assert_eq!(args.off_in, Some(612));
    }

    #[test]
    fn splice_same_fd_rejected() {
        let mut pipe = make_pipe(5, 0);
        let mut args = SpliceArgs {
            fd_in: 5,
            fd_out: 5,
            len: 1024,
            ..Default::default()
        };
        assert_eq!(
            do_splice(&mut pipe, false, &mut args, FdKind::File),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn splice_offset_on_pipe_side_rejected() {
        let mut pipe = make_pipe(5, 1024);
        // Pipe is input (pipe_is_in=true), but off_in is Some — invalid.
        let mut args = SpliceArgs {
            fd_in: 5,
            off_in: Some(0),
            fd_out: 3,
            len: 512,
            ..Default::default()
        };
        assert_eq!(
            do_splice(&mut pipe, true, &mut args, FdKind::File),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn splice_empty_pipe_nonblock_wouldblock() {
        let mut pipe = make_pipe(5, 0);
        let mut args = SpliceArgs {
            fd_in: 5,
            fd_out: 3,
            len: 1024,
            flags: SPLICE_F_NONBLOCK,
            ..Default::default()
        };
        assert_eq!(
            do_splice(&mut pipe, true, &mut args, FdKind::File),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn splice_read_closed_interrupted() {
        let mut pipe = make_pipe(5, 0);
        pipe.read_closed = true;
        let mut args = SpliceArgs {
            fd_in: 5,
            fd_out: 3,
            len: 1024,
            ..Default::default()
        };
        assert_eq!(
            do_splice(&mut pipe, true, &mut args, FdKind::File),
            Err(Error::Interrupted)
        );
    }

    #[test]
    fn splice_capped_by_pipe_free_space() {
        let mut pipe = make_pipe(5, PIPE_MAX_BUF - 100); // only 100 bytes free
        let mut args = SpliceArgs {
            fd_in: 3,
            fd_out: 5,
            len: 4096,
            ..Default::default()
        };
        let n = do_splice(&mut pipe, false, &mut args, FdKind::File).unwrap();
        assert_eq!(n, 100);
    }

    // --- do_tee ---

    #[test]
    fn tee_copies_without_draining_source() {
        let src = make_pipe(3, 4096);
        let mut dst = make_pipe(4, 0);
        let n = do_tee(&src, &mut dst, 2048, 0).unwrap();
        assert_eq!(n, 2048);
        assert_eq!(src.used, 4096); // source unchanged
        assert_eq!(dst.used, 2048);
    }

    #[test]
    fn tee_same_fd_rejected() {
        let src = make_pipe(3, 4096);
        let mut dst = make_pipe(3, 0); // same fd
        assert_eq!(do_tee(&src, &mut dst, 1024, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn tee_empty_source_wouldblock() {
        let src = make_pipe(3, 0);
        let mut dst = make_pipe(4, 0);
        assert_eq!(
            do_tee(&src, &mut dst, 1024, SPLICE_F_NONBLOCK),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn tee_capped_by_src_used() {
        let src = make_pipe(3, 100);
        let mut dst = make_pipe(4, 0);
        let n = do_tee(&src, &mut dst, 4096, 0).unwrap();
        assert_eq!(n, 100);
    }

    #[test]
    fn tee_capped_by_dst_free() {
        let src = make_pipe(3, 8192);
        let mut dst = make_pipe(4, PIPE_MAX_BUF - 50); // 50 bytes free
        let n = do_tee(&src, &mut dst, 8192, 0).unwrap();
        assert_eq!(n, 50);
    }

    #[test]
    fn tee_closed_pipe_interrupted() {
        let mut src = make_pipe(3, 4096);
        src.read_closed = true;
        let mut dst = make_pipe(4, 0);
        assert_eq!(do_tee(&src, &mut dst, 1024, 0), Err(Error::Interrupted));
    }

    // --- do_vmsplice ---

    #[test]
    fn vmsplice_into_pipe_fills_buf() {
        let mut pipe = make_pipe(5, 0);
        let iov = [
            IoVec {
                iov_base: 0x1000,
                iov_len: 1024,
            },
            IoVec {
                iov_base: 0x2000,
                iov_len: 2048,
            },
        ];
        let n = do_vmsplice(&mut pipe, &iov, 2, 0, true).unwrap();
        assert_eq!(n, 3072);
        assert_eq!(pipe.used, 3072);
    }

    #[test]
    fn vmsplice_out_of_pipe_drains_buf() {
        let mut pipe = make_pipe(5, 2048);
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 4096,
        }];
        let n = do_vmsplice(&mut pipe, &iov, 1, 0, false).unwrap();
        assert_eq!(n, 2048);
        assert_eq!(pipe.used, 0);
    }

    #[test]
    fn vmsplice_zero_iov_count_rejected() {
        let mut pipe = make_pipe(5, 0);
        assert_eq!(
            do_vmsplice(&mut pipe, &[], 0, 0, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_too_many_iovecs_rejected() {
        let mut pipe = make_pipe(5, 0);
        let iov = [IoVec::default(); VMSPLICE_MAX_IOV + 1];
        assert_eq!(
            do_vmsplice(&mut pipe, &iov, VMSPLICE_MAX_IOV + 1, 0, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_zero_iov_len_rejected() {
        let mut pipe = make_pipe(5, 0);
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 0,
        }];
        assert_eq!(
            do_vmsplice(&mut pipe, &iov, 1, 0, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_unknown_flags_rejected() {
        let mut pipe = make_pipe(5, 0);
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 512,
        }];
        assert_eq!(
            do_vmsplice(&mut pipe, &iov, 1, 0xDEAD, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_full_pipe_wouldblock() {
        let mut pipe = make_pipe(5, PIPE_MAX_BUF);
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 512,
        }];
        assert_eq!(
            do_vmsplice(&mut pipe, &iov, 1, SPLICE_F_NONBLOCK, true),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn vmsplice_capped_by_pipe_capacity() {
        let free = 200usize;
        let mut pipe = make_pipe(5, PIPE_MAX_BUF - free);
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 4096,
        }];
        let n = do_vmsplice(&mut pipe, &iov, 1, 0, true).unwrap();
        assert_eq!(n, free);
    }

    #[test]
    fn vmsplice_gift_flag_accepted() {
        let mut pipe = make_pipe(5, 0);
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 4096,
        }];
        let n = do_vmsplice(&mut pipe, &iov, 1, SPLICE_F_GIFT, true).unwrap();
        assert_eq!(n, 4096);
    }

    // --- PipeBuf helpers ---

    #[test]
    fn pipebuf_free_space() {
        let p = make_pipe(1, 1024);
        assert_eq!(p.free(), PIPE_MAX_BUF - 1024);
    }

    #[test]
    fn pipebuf_empty() {
        let p = make_pipe(1, 0);
        assert!(p.is_empty());
    }
}
