// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `splice(2)`, `sendfile(2)`, `tee(2)`, and `vmsplice(2)` — zero-copy I/O.
//!
//! These Linux system calls allow data to be moved between file descriptors
//! and pipes without copying through user space. This module implements the
//! kernel-side data-path logic for all four operations.
//!
//! # Operation summary
//!
//! | Syscall      | From          | To            | Copies data? |
//! |--------------|---------------|---------------|--------------|
//! | `splice`     | fd or pipe    | fd or pipe    | No (ref)     |
//! | `sendfile`   | file fd       | socket/fd     | No (ref)     |
//! | `tee`        | pipe (read)   | pipe (write)  | No (ref)     |
//! | `vmsplice`   | user iovec    | pipe          | One copy in  |
//!
//! # Design
//!
//! - [`PipeBuffer`] — a fixed-size ring buffer modelling a kernel pipe.
//! - [`SpliceFlags`] — flag bits for `splice` / `tee` / `vmsplice`.
//! - [`SpliceEndpoint`] — describes one end of a splice operation (pipe or fd).
//! - [`do_splice`] — move data between a pipe and another fd or pipe.
//! - [`do_sendfile`] — transfer data from a file fd to an output fd.
//! - [`do_tee`] — duplicate pipe data into another pipe without consuming.
//! - [`do_vmsplice`] — copy user-supplied `IoVec` segments into a pipe.
//!
//! Reference: Linux `fs/splice.c`, `include/linux/splice.h`,
//! `man 2 splice`, `man 2 sendfile`, `man 2 tee`, `man 2 vmsplice`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default pipe buffer capacity in bytes (64 KiB).
pub const PIPE_BUF_SIZE: usize = 65536;

/// Maximum number of pages that can be spliced in one call.
pub const SPLICE_MAX_PAGES: usize = 16;

/// Maximum bytes that can be moved in a single `sendfile` call (2 GiB - 1).
pub const SENDFILE_MAX_BYTES: usize = 0x7FFF_FFFF;

/// Maximum bytes for a single `vmsplice` call (16 MiB).
pub const VMSPLICE_MAX_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SpliceFlags
// ---------------------------------------------------------------------------

/// Flag bits for `splice`, `tee`, and `vmsplice`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpliceFlags(pub u32);

impl SpliceFlags {
    /// Do not block if the pipe would block (`SPLICE_F_NONBLOCK`).
    pub const NONBLOCK: u32 = 0x02;
    /// Hint that more data will follow (`SPLICE_F_MORE`).
    pub const MORE: u32 = 0x04;
    /// Move pages instead of copying when possible (`SPLICE_F_MOVE`).
    pub const MOVE: u32 = 0x01;
    /// Unused gift flag (`SPLICE_F_GIFT`).
    pub const GIFT: u32 = 0x08;

    pub fn nonblock(self) -> bool {
        self.0 & Self::NONBLOCK != 0
    }

    pub fn more(self) -> bool {
        self.0 & Self::MORE != 0
    }

    pub fn move_pages(self) -> bool {
        self.0 & Self::MOVE != 0
    }
}

// ---------------------------------------------------------------------------
// IoVec — user-space scatter-gather segment
// ---------------------------------------------------------------------------

/// Kernel representation of a user-space `struct iovec`.
///
/// In a no-std environment we represent the user buffer as an opaque
/// `(base, len)` pair. The caller is responsible for validating the
/// pointer before passing it to [`do_vmsplice`].
#[derive(Debug, Clone, Copy)]
pub struct IoVec {
    /// Opaque base address (user-space pointer as `usize`).
    pub iov_base: usize,
    /// Length of the buffer in bytes.
    pub iov_len: usize,
}

// ---------------------------------------------------------------------------
// PipeBuffer
// ---------------------------------------------------------------------------

/// A fixed-capacity kernel pipe ring buffer.
///
/// Used as the in-kernel staging area for all splice / tee / vmsplice
/// operations. Data written to a pipe is held here until consumed by a
/// reader or forwarded via another splice call.
pub struct PipeBuffer {
    buf: [u8; PIPE_BUF_SIZE],
    /// Write position (next byte to write).
    write_pos: usize,
    /// Read position (next byte to read / consume).
    read_pos: usize,
    /// Number of bytes currently available.
    available: usize,
    /// Monotonic byte counter for total bytes written.
    pub total_written: u64,
    /// Monotonic byte counter for total bytes read.
    pub total_read: u64,
}

impl PipeBuffer {
    /// Create an empty pipe buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; PIPE_BUF_SIZE],
            write_pos: 0,
            read_pos: 0,
            available: 0,
            total_written: 0,
            total_read: 0,
        }
    }

    /// Number of bytes available to read.
    pub fn available(&self) -> usize {
        self.available
    }

    /// Number of bytes of free space.
    pub fn free_space(&self) -> usize {
        PIPE_BUF_SIZE - self.available
    }

    /// Return `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.available == 0
    }

    /// Return `true` if the buffer is full.
    pub fn is_full(&self) -> bool {
        self.available == PIPE_BUF_SIZE
    }

    /// Write up to `data.len()` bytes into the pipe.
    ///
    /// Returns the number of bytes actually written (may be less than
    /// `data.len()` if the buffer is nearly full).
    /// Returns `Err(WouldBlock)` if the buffer is completely full.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        let to_write = data.len().min(self.free_space());
        for &b in &data[..to_write] {
            self.buf[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % PIPE_BUF_SIZE;
        }
        self.available += to_write;
        self.total_written += to_write as u64;
        Ok(to_write)
    }

    /// Read and consume up to `buf.len()` bytes from the pipe.
    ///
    /// Returns `Err(WouldBlock)` if the buffer is empty.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.is_empty() {
            return Err(Error::WouldBlock);
        }
        let to_read = buf.len().min(self.available);
        for b in buf[..to_read].iter_mut() {
            *b = self.buf[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF_SIZE;
        }
        self.available -= to_read;
        self.total_read += to_read as u64;
        Ok(to_read)
    }

    /// Peek at up to `buf.len()` bytes without consuming them.
    ///
    /// Returns the number of bytes copied.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.available);
        let mut pos = self.read_pos;
        for b in buf[..to_read].iter_mut() {
            *b = self.buf[pos];
            pos = (pos + 1) % PIPE_BUF_SIZE;
        }
        to_read
    }

    /// Discard up to `n` bytes from the read end (advance read pointer).
    ///
    /// Returns the number of bytes actually discarded.
    pub fn discard(&mut self, n: usize) -> usize {
        let to_discard = n.min(self.available);
        self.read_pos = (self.read_pos + to_discard) % PIPE_BUF_SIZE;
        self.available -= to_discard;
        self.total_read += to_discard as u64;
        to_discard
    }

    /// Clear the buffer (discard all data).
    pub fn clear(&mut self) {
        self.write_pos = 0;
        self.read_pos = 0;
        self.available = 0;
    }
}

impl Default for PipeBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PipeBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeBuffer")
            .field("available", &self.available)
            .field("free_space", &self.free_space())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SpliceEndpoint
// ---------------------------------------------------------------------------

/// One endpoint of a splice operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceEndpoint {
    /// A kernel pipe buffer identified by its slot index.
    Pipe(usize),
    /// A regular file descriptor (not a pipe).
    File(i32),
}

impl SpliceEndpoint {
    /// Return `true` if this endpoint is a pipe.
    pub fn is_pipe(self) -> bool {
        matches!(self, Self::Pipe(_))
    }
}

// ---------------------------------------------------------------------------
// SpliceState — manages a pool of pipe buffers
// ---------------------------------------------------------------------------

/// Maximum number of concurrent pipe buffers managed by [`SpliceState`].
pub const MAX_PIPE_BUFS: usize = 32;

/// Global splice/pipe state: a pool of [`PipeBuffer`] slots.
pub struct SpliceState {
    pipes: [Option<PipeBuffer>; MAX_PIPE_BUFS],
    count: usize,
}

impl SpliceState {
    /// Create an empty splice state.
    pub const fn new() -> Self {
        const NONE: Option<PipeBuffer> = None;
        Self {
            pipes: [NONE; MAX_PIPE_BUFS],
            count: 0,
        }
    }

    /// Allocate a new pipe buffer, returning its slot index.
    pub fn alloc_pipe(&mut self) -> Result<usize> {
        for (i, slot) in self.pipes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(PipeBuffer::new());
                if i >= self.count {
                    self.count = i + 1;
                }
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a pipe buffer slot.
    pub fn free_pipe(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_PIPE_BUFS || self.pipes[idx].is_none() {
            return Err(Error::InvalidArgument);
        }
        self.pipes[idx] = None;
        Ok(())
    }

    /// Get a shared reference to a pipe buffer.
    pub fn get_pipe(&self, idx: usize) -> Option<&PipeBuffer> {
        self.pipes.get(idx)?.as_ref()
    }

    /// Get a mutable reference to a pipe buffer.
    pub fn get_pipe_mut(&mut self, idx: usize) -> Option<&mut PipeBuffer> {
        self.pipes.get_mut(idx)?.as_mut()
    }

    // -----------------------------------------------------------------------
    // do_splice
    // -----------------------------------------------------------------------

    /// Transfer up to `count` bytes from `src` to `dst`.
    ///
    /// Implements `splice(2)`. At least one of `src` / `dst` must be a
    /// [`SpliceEndpoint::Pipe`]. The `off_in` / `off_out` offsets are used
    /// when the endpoint is a [`SpliceEndpoint::File`]; they are advanced
    /// by the number of bytes transferred and returned.
    ///
    /// In this model, file endpoints are represented by pre-supplied data
    /// slices (`file_in_data` / `file_out_buf`). Pass `None` for endpoints
    /// that are pipes.
    ///
    /// Returns `(bytes_spliced, new_off_in, new_off_out)`.
    pub fn do_splice(
        &mut self,
        src: SpliceEndpoint,
        off_in: Option<u64>,
        dst: SpliceEndpoint,
        off_out: Option<u64>,
        count: usize,
        flags: SpliceFlags,
        file_in_data: Option<&[u8]>,
        file_out_buf: Option<&mut [u8]>,
    ) -> Result<(usize, u64, u64)> {
        // At least one endpoint must be a pipe.
        if !src.is_pipe() && !dst.is_pipe() {
            return Err(Error::InvalidArgument);
        }

        let limit = count.min(PIPE_BUF_SIZE);
        let mut tmp = [0u8; PIPE_BUF_SIZE];

        // ── Step 1: read from source ─────────────────────────────────────
        let (bytes_read, new_off_in) = match src {
            SpliceEndpoint::Pipe(idx) => {
                let pipe = self
                    .pipes
                    .get_mut(idx)
                    .and_then(|p| p.as_mut())
                    .ok_or(Error::InvalidArgument)?;
                let n = match pipe.read(&mut tmp[..limit]) {
                    Ok(n) => n,
                    Err(Error::WouldBlock) if flags.nonblock() => return Err(Error::WouldBlock),
                    Err(Error::WouldBlock) => 0,
                    Err(e) => return Err(e),
                };
                (n, off_in.unwrap_or(0))
            }
            SpliceEndpoint::File(_fd) => {
                let data = file_in_data.ok_or(Error::InvalidArgument)?;
                let start = off_in.unwrap_or(0) as usize;
                if start >= data.len() {
                    return Ok((0, off_in.unwrap_or(0), off_out.unwrap_or(0)));
                }
                let available = data.len() - start;
                let n = limit.min(available);
                tmp[..n].copy_from_slice(&data[start..start + n]);
                (n, off_in.unwrap_or(0) + n as u64)
            }
        };

        if bytes_read == 0 {
            return Ok((0, off_in.unwrap_or(0), off_out.unwrap_or(0)));
        }

        // ── Step 2: write to destination ─────────────────────────────────
        let new_off_out = match dst {
            SpliceEndpoint::Pipe(idx) => {
                let pipe = self
                    .pipes
                    .get_mut(idx)
                    .and_then(|p| p.as_mut())
                    .ok_or(Error::InvalidArgument)?;
                let n = match pipe.write(&tmp[..bytes_read]) {
                    Ok(n) => n,
                    Err(Error::WouldBlock) if flags.nonblock() => return Err(Error::WouldBlock),
                    Err(Error::WouldBlock) => 0,
                    Err(e) => return Err(e),
                };
                if n < bytes_read {
                    // Partial write: we cannot put the unwritten bytes back.
                    // A real implementation would block or return the partial count.
                    return Ok((n, new_off_in, off_out.unwrap_or(0)));
                }
                off_out.unwrap_or(0)
            }
            SpliceEndpoint::File(_fd) => {
                let out_buf = file_out_buf.ok_or(Error::InvalidArgument)?;
                let start = off_out.unwrap_or(0) as usize;
                if start + bytes_read > out_buf.len() {
                    return Err(Error::InvalidArgument);
                }
                out_buf[start..start + bytes_read].copy_from_slice(&tmp[..bytes_read]);
                off_out.unwrap_or(0) + bytes_read as u64
            }
        };

        Ok((bytes_read, new_off_in, new_off_out))
    }

    // -----------------------------------------------------------------------
    // do_sendfile
    // -----------------------------------------------------------------------

    /// Transfer up to `count` bytes from a file into `out_pipe` (or output
    /// buffer).
    ///
    /// Implements `sendfile(2)`. `in_data` is a slice of the source file's
    /// contents starting at byte 0; `in_offset` is the file position to
    /// begin reading from.
    ///
    /// Returns `(bytes_sent, new_in_offset)`.
    pub fn do_sendfile(
        &mut self,
        in_data: &[u8],
        in_offset: u64,
        count: usize,
        out_pipe: Option<usize>,
        out_buf: Option<&mut [u8]>,
    ) -> Result<(usize, u64)> {
        let start = in_offset as usize;
        if start >= in_data.len() {
            return Ok((0, in_offset));
        }
        let available = in_data.len() - start;
        let to_send = count.min(available).min(SENDFILE_MAX_BYTES);

        let src = &in_data[start..start + to_send];

        let sent = if let Some(pipe_idx) = out_pipe {
            let pipe = self
                .pipes
                .get_mut(pipe_idx)
                .and_then(|p| p.as_mut())
                .ok_or(Error::InvalidArgument)?;
            pipe.write(src)?
        } else if let Some(buf) = out_buf {
            let copy = to_send.min(buf.len());
            buf[..copy].copy_from_slice(&src[..copy]);
            copy
        } else {
            return Err(Error::InvalidArgument);
        };

        Ok((sent, in_offset + sent as u64))
    }

    // -----------------------------------------------------------------------
    // do_tee
    // -----------------------------------------------------------------------

    /// Duplicate up to `count` bytes from `src_pipe` into `dst_pipe`
    /// **without consuming** the source data.
    ///
    /// Implements `tee(2)`. Both endpoints must be pipes. The source pipe's
    /// read position is not advanced.
    ///
    /// Returns the number of bytes duplicated.
    pub fn do_tee(
        &mut self,
        src_pipe: usize,
        dst_pipe: usize,
        count: usize,
        flags: SpliceFlags,
    ) -> Result<usize> {
        if src_pipe == dst_pipe {
            return Err(Error::InvalidArgument);
        }
        let limit = count.min(PIPE_BUF_SIZE);
        let mut tmp = [0u8; PIPE_BUF_SIZE];

        // Peek (non-consuming) from source.
        let peeked = {
            let src = self
                .pipes
                .get(src_pipe)
                .and_then(|p| p.as_ref())
                .ok_or(Error::InvalidArgument)?;
            if src.is_empty() {
                if flags.nonblock() {
                    return Err(Error::WouldBlock);
                }
                return Ok(0);
            }
            src.peek(&mut tmp[..limit])
        };
        if peeked == 0 {
            return Ok(0);
        }

        // Write to destination.
        let written = {
            let dst = self
                .pipes
                .get_mut(dst_pipe)
                .and_then(|p| p.as_mut())
                .ok_or(Error::InvalidArgument)?;
            match dst.write(&tmp[..peeked]) {
                Ok(n) => n,
                Err(Error::WouldBlock) if flags.nonblock() => return Err(Error::WouldBlock),
                Err(Error::WouldBlock) => 0,
                Err(e) => return Err(e),
            }
        };

        Ok(written)
    }

    // -----------------------------------------------------------------------
    // do_vmsplice
    // -----------------------------------------------------------------------

    /// Copy user-space `iov` segments into `pipe`, implementing `vmsplice(2)`.
    ///
    /// `iov_data` maps each [`IoVec`] to its actual byte content — in a real
    /// kernel the iov_base would be a user-space pointer; here the caller
    /// supplies slices directly via `segments`.
    ///
    /// Returns the total number of bytes written to `pipe`.
    pub fn do_vmsplice(
        &mut self,
        pipe_idx: usize,
        iovs: &[IoVec],
        segments: &[&[u8]],
        flags: SpliceFlags,
    ) -> Result<usize> {
        if iovs.len() != segments.len() {
            return Err(Error::InvalidArgument);
        }
        let pipe = self
            .pipes
            .get_mut(pipe_idx)
            .and_then(|p| p.as_mut())
            .ok_or(Error::InvalidArgument)?;

        let mut total = 0usize;
        for (iov, &data) in iovs.iter().zip(segments.iter()) {
            if iov.iov_len == 0 {
                continue;
            }
            let to_write = iov.iov_len.min(data.len()).min(VMSPLICE_MAX_BYTES - total);
            if to_write == 0 {
                break;
            }
            match pipe.write(&data[..to_write]) {
                Ok(n) => total += n,
                Err(Error::WouldBlock) if flags.nonblock() => {
                    if total == 0 {
                        return Err(Error::WouldBlock);
                    }
                    break;
                }
                Err(Error::WouldBlock) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    /// Number of allocated pipe slots.
    pub fn active_pipe_count(&self) -> usize {
        self.pipes[..self.count]
            .iter()
            .filter(|p| p.is_some())
            .count()
    }
}

impl Default for SpliceState {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SpliceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpliceState")
            .field("active_pipes", &self.active_pipe_count())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Standalone function wrappers (mirror Linux kernel API surface)
// ---------------------------------------------------------------------------

/// Perform a `splice` between two endpoints using `state`.
///
/// Convenience wrapper around [`SpliceState::do_splice`].
#[allow(clippy::too_many_arguments)]
pub fn do_splice(
    state: &mut SpliceState,
    src: SpliceEndpoint,
    off_in: Option<u64>,
    dst: SpliceEndpoint,
    off_out: Option<u64>,
    count: usize,
    flags: SpliceFlags,
    file_in_data: Option<&[u8]>,
    file_out_buf: Option<&mut [u8]>,
) -> Result<(usize, u64, u64)> {
    state.do_splice(
        src,
        off_in,
        dst,
        off_out,
        count,
        flags,
        file_in_data,
        file_out_buf,
    )
}

/// Perform a `sendfile` transfer using `state`.
pub fn do_sendfile(
    state: &mut SpliceState,
    in_data: &[u8],
    in_offset: u64,
    count: usize,
    out_pipe: Option<usize>,
    out_buf: Option<&mut [u8]>,
) -> Result<(usize, u64)> {
    state.do_sendfile(in_data, in_offset, count, out_pipe, out_buf)
}

/// Perform a `tee` between two pipes using `state`.
pub fn do_tee(
    state: &mut SpliceState,
    src_pipe: usize,
    dst_pipe: usize,
    count: usize,
    flags: SpliceFlags,
) -> Result<usize> {
    state.do_tee(src_pipe, dst_pipe, count, flags)
}

/// Perform a `vmsplice` from user-space segments into a pipe.
pub fn do_vmsplice(
    state: &mut SpliceState,
    pipe_idx: usize,
    iovs: &[IoVec],
    segments: &[&[u8]],
    flags: SpliceFlags,
) -> Result<usize> {
    state.do_vmsplice(pipe_idx, iovs, segments, flags)
}

// ---------------------------------------------------------------------------
// SpliceResult — return type summary
// ---------------------------------------------------------------------------

/// Summary of a completed splice / sendfile operation.
#[derive(Debug, Clone, Copy)]
pub struct SpliceResult {
    /// Number of bytes transferred.
    pub bytes: usize,
    /// Updated input file offset (for file sources).
    pub off_in: u64,
    /// Updated output file offset (for file destinations).
    pub off_out: u64,
}

impl SpliceResult {
    pub fn new(bytes: usize, off_in: u64, off_out: u64) -> Self {
        Self {
            bytes,
            off_in,
            off_out,
        }
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global splice/pipe state.
static mut SPLICE_STATE: SpliceState = SpliceState::new();

/// Initialise the global splice state.
///
/// # Safety
///
/// Must be called once during single-threaded kernel initialisation.
pub unsafe fn splice_init() {
    // SAFETY: Single-threaded init; no concurrent access.
    unsafe {
        *core::ptr::addr_of_mut!(SPLICE_STATE) = SpliceState::new();
    }
}

/// Obtain a shared reference to the global splice state.
pub fn splice_state() -> &'static SpliceState {
    // SAFETY: Read-only after init; never moved.
    unsafe { &*core::ptr::addr_of!(SPLICE_STATE) }
}

/// Obtain a mutable reference to the global splice state.
///
/// # Safety
///
/// Caller must ensure no other reference is live.
pub unsafe fn splice_state_mut() -> &'static mut SpliceState {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { &mut *core::ptr::addr_of_mut!(SPLICE_STATE) }
}
