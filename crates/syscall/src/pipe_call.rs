// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pipe(2)` and `pipe2(2)` syscall handlers.
//!
//! A pipe is a unidirectional data channel.  The `pipe` syscall creates a
//! pair of file descriptors where data written to the write end is buffered
//! and can be read from the read end.
//!
//! `pipe2` adds support for the `O_CLOEXEC` and `O_NONBLOCK` flags so that
//! these properties can be set atomically without a subsequent `fcntl` call.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `pipe()` specification.  `pipe2` is a Linux
//! extension providing atomic flag setting.
//!
//! Key behaviours:
//! - Returns a pair `(read_fd, write_fd)`.
//! - The read end returns 0 (EOF) once the write end is closed and the buffer
//!   is drained.
//! - Writing to a pipe with no readers generates `SIGPIPE` / `EPIPE`.
//! - Default pipe capacity is [`PIPE_BUF_SIZE`] bytes.
//! - `PIPE_BUF` writes are atomic when the data fits within the buffer.
//!
//! # References
//!
//! - POSIX.1-2024: `pipe()`
//! - Linux man pages: `pipe(2)`, `pipe2(2)`
//! - Linux source: `fs/pipe.c` (`do_pipe2`, `__do_pipe_flags`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default pipe buffer capacity in bytes.
///
/// POSIX requires `PIPE_BUF` to be at least 512 bytes.  Linux uses 65536 bytes
/// (16 pages of 4096 bytes each) as the default pipe capacity.
pub const PIPE_BUF_SIZE: usize = 65536;

/// The guaranteed atomic write size for pipes (POSIX `PIPE_BUF`).
pub const PIPE_BUF: usize = 4096;

/// Maximum number of pipe instances simultaneously open.
const MAX_PIPES: usize = 256;

/// Maximum number of file descriptors per process.
const MAX_OPEN_FDS: usize = 1024;

/// Flag: set close-on-exec on the pipe file descriptors.
pub const O_CLOEXEC: u32 = 0x80000;

/// Flag: open the pipe in non-blocking mode.
pub const O_NONBLOCK: u32 = 0x800;

/// All valid `pipe2` flag bits.
const PIPE2_VALID_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;

// ---------------------------------------------------------------------------
// Pipe state
// ---------------------------------------------------------------------------

/// State of a pipe instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeState {
    /// Both ends are open.
    Open,
    /// Write end has been closed; remaining data can still be read.
    WriteEnd,
    /// Read end has been closed; writing will produce EPIPE.
    ReadEnd,
    /// Both ends have been closed; pipe is fully drained.
    Closed,
}

/// A pipe buffer backed by a fixed-size byte array.
///
/// Uses a ring buffer layout with `head` (read position) and `len` (bytes
/// available).  In the real kernel this is a linked list of pages.
pub struct PipeBuf {
    buf: [u8; PIPE_BUF_SIZE],
    /// Index of the next byte to read.
    head: usize,
    /// Number of bytes currently in the buffer.
    len: usize,
}

impl PipeBuf {
    /// Create a new, empty pipe buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; PIPE_BUF_SIZE],
            head: 0,
            len: 0,
        }
    }

    /// Number of bytes available to read.
    pub const fn available(&self) -> usize {
        self.len
    }

    /// Number of bytes of free space in the buffer.
    pub const fn free_space(&self) -> usize {
        PIPE_BUF_SIZE - self.len
    }

    /// Write `data` into the pipe buffer.
    ///
    /// Returns the number of bytes written (may be less than `data.len()` if
    /// the buffer is full).
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.free_space());
        if to_write == 0 {
            return 0;
        }
        let tail = (self.head + self.len) % PIPE_BUF_SIZE;
        let first_chunk = (PIPE_BUF_SIZE - tail).min(to_write);
        self.buf[tail..tail + first_chunk].copy_from_slice(&data[..first_chunk]);
        if first_chunk < to_write {
            let second_chunk = to_write - first_chunk;
            self.buf[..second_chunk]
                .copy_from_slice(&data[first_chunk..first_chunk + second_chunk]);
        }
        self.len += to_write;
        to_write
    }

    /// Read up to `dst.len()` bytes from the pipe buffer.
    ///
    /// Returns the number of bytes actually read.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.len);
        if to_read == 0 {
            return 0;
        }
        let first_chunk = (PIPE_BUF_SIZE - self.head).min(to_read);
        dst[..first_chunk].copy_from_slice(&self.buf[self.head..self.head + first_chunk]);
        if first_chunk < to_read {
            let second_chunk = to_read - first_chunk;
            dst[first_chunk..first_chunk + second_chunk].copy_from_slice(&self.buf[..second_chunk]);
        }
        self.head = (self.head + to_read) % PIPE_BUF_SIZE;
        self.len -= to_read;
        to_read
    }

    /// Discard all data in the buffer.
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

// ---------------------------------------------------------------------------
// Pipe instance
// ---------------------------------------------------------------------------

/// A single pipe, consisting of a buffer and its current state.
pub struct Pipe {
    buf: PipeBuf,
    state: PipeState,
    nonblocking: bool,
}

impl Pipe {
    /// Create a new pipe with an empty buffer.
    pub const fn new(nonblocking: bool) -> Self {
        Self {
            buf: PipeBuf::new(),
            state: PipeState::Open,
            nonblocking,
        }
    }

    /// Write data to the pipe.
    ///
    /// Returns the number of bytes written, or an error.
    ///
    /// # Errors
    ///
    /// - `Error::Busy` — write end has been closed (`EPIPE`).
    /// - `Error::WouldBlock` — buffer is full and non-blocking mode is set.
    /// - `Error::Interrupted` — would block in blocking mode (simulated).
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<usize> {
        match self.state {
            PipeState::ReadEnd | PipeState::Closed => return Err(Error::Busy), // EPIPE
            PipeState::WriteEnd | PipeState::Open => {}
        }

        if data.is_empty() {
            return Ok(0);
        }

        if self.buf.free_space() == 0 {
            if self.nonblocking {
                return Err(Error::WouldBlock);
            }
            return Err(Error::Interrupted); // Would block
        }

        Ok(self.buf.write(data))
    }

    /// Read data from the pipe.
    ///
    /// Returns the number of bytes read (`0` means EOF).
    ///
    /// # Errors
    ///
    /// - `Error::WouldBlock` — no data available and non-blocking mode is set.
    pub fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }

        if self.buf.available() == 0 {
            // No data; check if writer is still alive.
            match self.state {
                PipeState::WriteEnd | PipeState::Closed => {
                    // EOF — write end is closed.
                    return Ok(0);
                }
                PipeState::Open | PipeState::ReadEnd => {
                    if self.nonblocking {
                        return Err(Error::WouldBlock);
                    }
                    return Err(Error::Interrupted); // Would block
                }
            }
        }

        Ok(self.buf.read(dst))
    }

    /// Close the write end of the pipe.
    pub fn close_write_end(&mut self) {
        self.state = match self.state {
            PipeState::Open => PipeState::WriteEnd,
            PipeState::ReadEnd => PipeState::Closed,
            other => other,
        };
    }

    /// Close the read end of the pipe.
    pub fn close_read_end(&mut self) {
        self.state = match self.state {
            PipeState::Open => PipeState::ReadEnd,
            PipeState::WriteEnd => PipeState::Closed,
            other => other,
        };
    }

    /// Return the current pipe state.
    pub const fn state(&self) -> PipeState {
        self.state
    }

    /// Return the number of bytes buffered in the pipe.
    pub fn buffered(&self) -> usize {
        self.buf.available()
    }
}

// ---------------------------------------------------------------------------
// Pipe table
// ---------------------------------------------------------------------------

/// Result of allocating a pipe: indices into the pipe table for read/write ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeFdPair {
    /// File descriptor for the read end of the pipe.
    pub read_fd: i32,
    /// File descriptor for the write end of the pipe.
    pub write_fd: i32,
    /// Whether `O_CLOEXEC` is set on both file descriptors.
    pub cloexec: bool,
    /// Whether `O_NONBLOCK` is set on both file descriptors.
    pub nonblock: bool,
}

// ---------------------------------------------------------------------------
// Fd table (minimal, for pipe fd allocation)
// ---------------------------------------------------------------------------

/// Slot state for pipe-related file descriptor allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PipeFdSlot {
    #[default]
    Empty,
    PipeRead {
        cloexec: bool,
    },
    PipeWrite {
        cloexec: bool,
    },
}

impl PipeFdSlot {
    fn is_open(self) -> bool {
        !matches!(self, PipeFdSlot::Empty)
    }
}

/// Minimal file descriptor allocator used in pipe creation.
pub struct PipeFdAllocator {
    slots: [PipeFdSlot; MAX_OPEN_FDS],
    open_count: usize,
}

impl PipeFdAllocator {
    /// Create a new allocator with no open slots.
    pub const fn new() -> Self {
        Self {
            slots: [PipeFdSlot::Empty; MAX_OPEN_FDS],
            open_count: 0,
        }
    }

    /// Allocate the lowest-numbered free slot.
    ///
    /// Returns `Err(OutOfMemory)` if no slots are available.
    fn alloc_slot(&mut self, slot: PipeFdSlot) -> Result<usize> {
        let idx = self
            .slots
            .iter()
            .position(|s| !s.is_open())
            .ok_or(Error::OutOfMemory)?;
        self.slots[idx] = slot;
        self.open_count += 1;
        Ok(idx)
    }

    /// Return the number of open slots.
    pub const fn open_count(&self) -> usize {
        self.open_count
    }

    /// Query the slot state at position `fd`.
    pub(crate) fn slot(&self, fd: usize) -> PipeFdSlot {
        if fd < MAX_OPEN_FDS {
            self.slots[fd]
        } else {
            PipeFdSlot::Empty
        }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `pipe(2)`.
///
/// Creates a new pipe and allocates two file descriptors for its read and
/// write ends.  Neither descriptor has `O_CLOEXEC` or `O_NONBLOCK` set.
///
/// # Errors
///
/// - `Error::OutOfMemory` — no free file descriptor slots remain (`EMFILE`).
///
/// # POSIX conformance
///
/// Returns `[read_fd, write_fd]` in a two-element array per POSIX.
pub fn do_pipe(alloc: &mut PipeFdAllocator) -> Result<PipeFdPair> {
    do_pipe2(alloc, 0)
}

/// Handler for `pipe2(2)`.
///
/// Like `pipe`, but atomically sets `O_CLOEXEC` and/or `O_NONBLOCK` on the
/// returned file descriptors.
///
/// # Arguments
///
/// * `alloc` — File descriptor allocator for the calling process.
/// * `flags` — Combination of `O_CLOEXEC` and/or `O_NONBLOCK`.
///
/// # Errors
///
/// - `Error::InvalidArgument` — unknown flag bits are set (`EINVAL`).
/// - `Error::OutOfMemory` — no free file descriptor slots remain (`EMFILE`).
///
/// # Linux conformance
///
/// `pipe2` is a Linux extension.  It is equivalent to calling `pipe` followed
/// by `fcntl(F_SETFL, O_NONBLOCK)` and `fcntl(F_SETFD, FD_CLOEXEC)` on
/// both ends, but avoids a race condition in multi-threaded programs.
pub fn do_pipe2(alloc: &mut PipeFdAllocator, flags: u32) -> Result<PipeFdPair> {
    if flags & !PIPE2_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    let cloexec = flags & O_CLOEXEC != 0;
    let nonblock = flags & O_NONBLOCK != 0;

    let read_fd = alloc.alloc_slot(PipeFdSlot::PipeRead { cloexec })? as i32;
    let write_fd = alloc.alloc_slot(PipeFdSlot::PipeWrite { cloexec })? as i32;

    Ok(PipeFdPair {
        read_fd,
        write_fd,
        cloexec,
        nonblock,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- PipeBuf ---

    #[test]
    fn pipe_buf_write_and_read() {
        let mut pb = PipeBuf::new();
        let written = pb.write(b"hello");
        assert_eq!(written, 5);
        assert_eq!(pb.available(), 5);

        let mut dst = [0u8; 5];
        let read = pb.read(&mut dst);
        assert_eq!(read, 5);
        assert_eq!(&dst, b"hello");
        assert_eq!(pb.available(), 0);
    }

    #[test]
    fn pipe_buf_partial_read() {
        let mut pb = PipeBuf::new();
        pb.write(b"abcdef");
        let mut dst = [0u8; 3];
        let n = pb.read(&mut dst);
        assert_eq!(n, 3);
        assert_eq!(&dst, b"abc");
        assert_eq!(pb.available(), 3);
    }

    #[test]
    fn pipe_buf_wrap_around() {
        let mut pb = PipeBuf::new();
        // Fill all but 3 bytes.
        let filler = vec![0u8; PIPE_BUF_SIZE - 3];
        pb.write(&filler);
        // Read some to move head forward.
        let mut tmp = vec![0u8; PIPE_BUF_SIZE - 10];
        pb.read(&mut tmp);
        // Now write more data that wraps around.
        pb.write(b"WRAP");
        let mut out = [0u8; 4];
        let n = pb.read(&mut out);
        assert_eq!(n, 4);
        assert_eq!(&out, b"WRAP");
    }

    #[test]
    fn pipe_buf_free_space() {
        let mut pb = PipeBuf::new();
        assert_eq!(pb.free_space(), PIPE_BUF_SIZE);
        pb.write(&[0u8; 100]);
        assert_eq!(pb.free_space(), PIPE_BUF_SIZE - 100);
    }

    // --- Pipe ---

    #[test]
    fn pipe_write_and_read() {
        let mut p = Pipe::new(false);
        let n = p.write_bytes(b"data").unwrap();
        assert_eq!(n, 4);
        let mut dst = [0u8; 4];
        let r = p.read_bytes(&mut dst).unwrap();
        assert_eq!(r, 4);
        assert_eq!(&dst, b"data");
    }

    #[test]
    fn pipe_eof_on_write_end_closed() {
        let mut p = Pipe::new(false);
        p.write_bytes(b"end").unwrap();
        p.close_write_end();
        let mut dst = [0u8; 3];
        p.read_bytes(&mut dst).unwrap();
        // Now buffer is empty and write end is closed: EOF.
        let n = p.read_bytes(&mut dst).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn pipe_epipe_when_read_end_closed() {
        let mut p = Pipe::new(false);
        p.close_read_end();
        let r = p.write_bytes(b"x");
        assert_eq!(r, Err(Error::Busy));
    }

    #[test]
    fn pipe_nonblocking_wouldblock_on_full() {
        let mut p = Pipe::new(true);
        // Fill the buffer.
        let data = vec![1u8; PIPE_BUF_SIZE];
        p.write_bytes(&data).unwrap();
        // Next write should return WouldBlock.
        let r = p.write_bytes(b"x");
        assert_eq!(r, Err(Error::WouldBlock));
    }

    #[test]
    fn pipe_nonblocking_wouldblock_on_empty() {
        let mut p = Pipe::new(true);
        let mut dst = [0u8; 4];
        let r = p.read_bytes(&mut dst);
        assert_eq!(r, Err(Error::WouldBlock));
    }

    // --- do_pipe / do_pipe2 ---

    #[test]
    fn do_pipe_allocates_two_fds() {
        let mut alloc = PipeFdAllocator::new();
        let pair = do_pipe(&mut alloc).unwrap();
        assert_eq!(pair.read_fd, 0);
        assert_eq!(pair.write_fd, 1);
        assert!(!pair.cloexec);
        assert!(!pair.nonblock);
        assert_eq!(alloc.open_count(), 2);
    }

    #[test]
    fn do_pipe2_cloexec_flag() {
        let mut alloc = PipeFdAllocator::new();
        let pair = do_pipe2(&mut alloc, O_CLOEXEC).unwrap();
        assert!(pair.cloexec);
        assert!(!pair.nonblock);
        assert!(matches!(
            alloc.slot(pair.read_fd as usize),
            PipeFdSlot::PipeRead { cloexec: true }
        ));
        assert!(matches!(
            alloc.slot(pair.write_fd as usize),
            PipeFdSlot::PipeWrite { cloexec: true }
        ));
    }

    #[test]
    fn do_pipe2_nonblock_flag() {
        let mut alloc = PipeFdAllocator::new();
        let pair = do_pipe2(&mut alloc, O_NONBLOCK).unwrap();
        assert!(pair.nonblock);
        assert!(!pair.cloexec);
    }

    #[test]
    fn do_pipe2_both_flags() {
        let mut alloc = PipeFdAllocator::new();
        let pair = do_pipe2(&mut alloc, O_CLOEXEC | O_NONBLOCK).unwrap();
        assert!(pair.cloexec);
        assert!(pair.nonblock);
    }

    #[test]
    fn do_pipe2_rejects_unknown_flags() {
        let mut alloc = PipeFdAllocator::new();
        assert_eq!(do_pipe2(&mut alloc, 0xFF), Err(Error::InvalidArgument));
    }

    #[test]
    fn do_pipe_read_fd_less_than_write_fd() {
        let mut alloc = PipeFdAllocator::new();
        let pair = do_pipe(&mut alloc).unwrap();
        assert!(pair.read_fd < pair.write_fd);
    }
}
