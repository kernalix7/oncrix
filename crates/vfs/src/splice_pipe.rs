// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! splice/sendfile/tee pipe operations.
//!
//! Implements zero-copy data transfer between file descriptors using
//! pipe buffers as an intermediate staging area. These operations avoid
//! copying data through user space.
//!
//! # Operations
//!
//! - **splice**: Move data between a file and a pipe, or between two pipes.
//! - **tee**: Duplicate data between two pipes without consuming the source.
//! - **sendfile**: Transfer data from a regular file to a socket/fd directly.
//!
//! # Pipe buffer model
//!
//! Data moved via splice is represented as `SpliceBuf` — a reference to a
//! fixed-size kernel buffer. Real zero-copy involves page remapping; here
//! we use a fixed pool of shared buffers.
//!
//! # References
//!
//! - Linux `splice(2)`, `tee(2)`, `sendfile(2)`
//! - Linux `pipe(7)` — pipe buffer internals

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Size of each splice buffer (4 KiB, one page).
pub const SPLICE_BUF_SIZE: usize = 4096;

/// Maximum number of splice buffers in the global pool.
pub const SPLICE_BUF_POOL: usize = 64;

/// Maximum bytes transferred per splice call.
pub const SPLICE_MAX_BYTES: usize = SPLICE_BUF_SIZE * SPLICE_BUF_POOL;

/// Splice flag: do not block.
pub const SPLICE_F_NONBLOCK: u32 = 0x2;

/// Splice flag: expect more data (hint for TCP_CORK).
pub const SPLICE_F_MORE: u32 = 0x4;

// ── SpliceBuf ────────────────────────────────────────────────────────

/// A single kernel buffer used for splice operations.
#[derive(Clone, Copy)]
pub struct SpliceBuf {
    /// Raw data storage.
    data: [u8; SPLICE_BUF_SIZE],
    /// Number of valid bytes in `data`.
    pub len: usize,
    /// Offset within `data` where valid data starts.
    pub offset: usize,
    /// Whether this buffer is currently in use.
    pub in_use: bool,
}

impl SpliceBuf {
    /// Create an empty, unused splice buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; SPLICE_BUF_SIZE],
            len: 0,
            offset: 0,
            in_use: false,
        }
    }

    /// Fill the buffer from a byte slice; returns bytes copied.
    pub fn fill(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(SPLICE_BUF_SIZE);
        self.data[..n].copy_from_slice(&src[..n]);
        self.len = n;
        self.offset = 0;
        self.in_use = true;
        n
    }

    /// Read up to `dst.len()` bytes from the buffer into `dst`.
    pub fn drain(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.len.saturating_sub(self.offset);
        let n = dst.len().min(avail);
        dst[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        if self.offset >= self.len {
            self.in_use = false;
            self.len = 0;
            self.offset = 0;
        }
        n
    }

    /// Returns the number of bytes still available in this buffer.
    pub fn available(&self) -> usize {
        self.len.saturating_sub(self.offset)
    }
}

impl Default for SpliceBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ── SplicePipe ───────────────────────────────────────────────────────

/// Maximum buffers per splice pipe.
const SPLICE_PIPE_BUFS: usize = 16;

/// A pipe-like staging area for splice operations.
///
/// A `SplicePipe` holds a ring of [`SpliceBuf`] entries. Data spliced
/// from a source fd lands here; from here it can be forwarded to a
/// destination fd or tee'd to another `SplicePipe`.
pub struct SplicePipe {
    bufs: [SpliceBuf; SPLICE_PIPE_BUFS],
    head: usize,
    tail: usize,
    count: usize,
}

impl SplicePipe {
    /// Create an empty splice pipe.
    pub const fn new() -> Self {
        Self {
            bufs: [const { SpliceBuf::new() }; SPLICE_PIPE_BUFS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Returns `true` if no buffers are queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` if all buffer slots are full.
    pub fn is_full(&self) -> bool {
        self.count >= SPLICE_PIPE_BUFS
    }

    /// Write `src` into the pipe's next available buffer slot.
    ///
    /// Returns the number of bytes accepted, or `WouldBlock` if full.
    pub fn push(&mut self, src: &[u8]) -> Result<usize> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        let n = self.bufs[self.tail].fill(src);
        self.tail = (self.tail + 1) % SPLICE_PIPE_BUFS;
        self.count += 1;
        Ok(n)
    }

    /// Read from the pipe's head buffer into `dst`.
    ///
    /// Returns `WouldBlock` if the pipe is empty.
    pub fn pop(&mut self, dst: &mut [u8]) -> Result<usize> {
        if self.is_empty() {
            return Err(Error::WouldBlock);
        }
        let n = self.bufs[self.head].drain(dst);
        if !self.bufs[self.head].in_use {
            self.head = (self.head + 1) % SPLICE_PIPE_BUFS;
            self.count = self.count.saturating_sub(1);
        }
        Ok(n)
    }

    /// Returns the number of bytes currently buffered.
    pub fn buffered_bytes(&self) -> usize {
        let mut total = 0;
        let mut i = self.head;
        for _ in 0..self.count {
            total += self.bufs[i].available();
            i = (i + 1) % SPLICE_PIPE_BUFS;
        }
        total
    }
}

impl Default for SplicePipe {
    fn default() -> Self {
        Self::new()
    }
}

// ── splice ───────────────────────────────────────────────────────────

/// Splice data from `src` bytes into `pipe`.
///
/// Moves up to `len` bytes from the source byte slice into the splice
/// pipe. Returns the number of bytes moved, or an error.
pub fn splice_to_pipe(src: &[u8], pipe: &mut SplicePipe, len: usize) -> Result<usize> {
    let to_move = src.len().min(len);
    let mut moved = 0;
    let mut offset = 0;
    while moved < to_move {
        let chunk = &src[offset..(offset + (to_move - moved)).min(src.len() - offset)];
        if chunk.is_empty() {
            break;
        }
        let n = pipe.push(chunk)?;
        moved += n;
        offset += n;
    }
    Ok(moved)
}

/// Splice data from `pipe` into `dst`.
///
/// Returns the number of bytes moved.
pub fn splice_from_pipe(pipe: &mut SplicePipe, dst: &mut [u8], len: usize) -> Result<usize> {
    let to_read = dst.len().min(len);
    let mut read = 0;
    while read < to_read {
        match pipe.pop(&mut dst[read..to_read]) {
            Ok(n) if n > 0 => read += n,
            Ok(_) => break,
            Err(Error::WouldBlock) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(read)
}

/// Tee data: copy from `src` pipe to `dst` pipe without consuming the source.
///
/// Returns the number of bytes copied.
pub fn tee(src: &mut SplicePipe, dst: &mut SplicePipe, len: usize) -> Result<usize> {
    let mut tmp = [0u8; SPLICE_BUF_SIZE];
    let mut copied = 0;
    let mut remaining = len;
    // We simulate tee by reading into a temp buffer and pushing to both pipes.
    // In a real implementation this would use page reference counting.
    while remaining > 0 && !src.is_empty() {
        let n = match src.pop(&mut tmp[..remaining.min(SPLICE_BUF_SIZE)]) {
            Ok(n) => n,
            Err(Error::WouldBlock) => break,
            Err(e) => return Err(e),
        };
        dst.push(&tmp[..n])?;
        // Put back into src — in a real kernel we'd increment refcount.
        src.push(&tmp[..n])?;
        copied += n;
        remaining -= n;
    }
    Ok(copied)
}

/// sendfile: transfer `len` bytes from `src` slice to `dst` pipe.
///
/// Equivalent to splice from a regular file. Returns bytes transferred.
pub fn sendfile(src: &[u8], offset: usize, pipe: &mut SplicePipe, len: usize) -> Result<usize> {
    if offset >= src.len() {
        return Ok(0);
    }
    let available = &src[offset..];
    splice_to_pipe(available, pipe, len)
}
