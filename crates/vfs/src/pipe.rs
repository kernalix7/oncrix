// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX pipe implementation (unidirectional byte stream).
//!
//! A pipe provides a unidirectional data channel: one end writes,
//! the other reads. Data is buffered in a fixed-size ring buffer.
//! This module implements the kernel-side pipe object.

use oncrix_lib::{Error, Result};

/// Pipe buffer size (4 KiB, matching POSIX PIPE_BUF).
const PIPE_BUF_SIZE: usize = 4096;

/// Maximum number of active pipes system-wide.
const MAX_PIPES: usize = 64;

/// A unidirectional pipe.
pub struct Pipe {
    /// Ring buffer for pipe data.
    buf: [u8; PIPE_BUF_SIZE],
    /// Read position in the ring buffer.
    read_pos: usize,
    /// Write position in the ring buffer.
    write_pos: usize,
    /// Number of bytes currently in the buffer.
    count: usize,
    /// Whether the read end is open.
    read_open: bool,
    /// Whether the write end is open.
    write_open: bool,
}

impl Pipe {
    /// Create a new empty pipe.
    const fn new() -> Self {
        Self {
            buf: [0; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            read_open: true,
            write_open: true,
        }
    }

    /// Read up to `buf.len()` bytes from the pipe.
    ///
    /// Returns the number of bytes actually read. Returns 0 if the
    /// write end is closed and the buffer is empty (EOF).
    /// Returns `WouldBlock` if the buffer is empty but the write end
    /// is still open.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.count == 0 {
            if !self.write_open {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }

        let to_read = buf.len().min(self.count);
        for byte in buf.iter_mut().take(to_read) {
            *byte = self.buf[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count -= to_read;
        Ok(to_read)
    }

    /// Write up to `data.len()` bytes to the pipe.
    ///
    /// Returns the number of bytes actually written.
    /// Returns `IoError` (broken pipe) if the read end is closed.
    /// Returns `WouldBlock` if the buffer is full.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.read_open {
            return Err(Error::IoError); // EPIPE
        }

        let available = PIPE_BUF_SIZE - self.count;
        if available == 0 {
            return Err(Error::WouldBlock);
        }

        let to_write = data.len().min(available);
        for &byte in data.iter().take(to_write) {
            self.buf[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count += to_write;
        Ok(to_write)
    }

    /// Close the read end of the pipe.
    pub fn close_read(&mut self) {
        self.read_open = false;
    }

    /// Close the write end of the pipe.
    pub fn close_write(&mut self) {
        self.write_open = false;
    }

    /// Return the number of bytes available for reading.
    pub fn available(&self) -> usize {
        self.count
    }

    /// Check if the pipe is fully closed (both ends).
    pub fn is_closed(&self) -> bool {
        !self.read_open && !self.write_open
    }

    /// Check if the read end is open.
    pub fn is_read_open(&self) -> bool {
        self.read_open
    }

    /// Check if the write end is open.
    pub fn is_write_open(&self) -> bool {
        self.write_open
    }
}

/// Unique identifier for a pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeId(pub u32);

impl core::fmt::Display for PipeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "pipe:{}", self.0)
    }
}

impl core::fmt::Debug for Pipe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pipe")
            .field("count", &self.count)
            .field("read_open", &self.read_open)
            .field("write_open", &self.write_open)
            .finish()
    }
}

/// System-wide pipe registry.
pub struct PipeRegistry {
    /// Pipe slots.
    pipes: [Option<Pipe>; MAX_PIPES],
    /// Next pipe ID.
    next_id: u32,
}

impl Default for PipeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeRegistry {
    /// Create an empty pipe registry.
    pub const fn new() -> Self {
        const NONE: Option<Pipe> = None;
        Self {
            pipes: [NONE; MAX_PIPES],
            next_id: 0,
        }
    }

    /// Create a new pipe and return its ID and slot index.
    pub fn create(&mut self) -> Result<(PipeId, usize)> {
        for (i, slot) in self.pipes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Pipe::new());
                let id = PipeId(self.next_id);
                self.next_id = self.next_id.wrapping_add(1);
                return Ok((id, i));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a reference to a pipe by slot index.
    pub fn get(&self, slot: usize) -> Option<&Pipe> {
        self.pipes.get(slot).and_then(|s| s.as_ref())
    }

    /// Get a mutable reference to a pipe by slot index.
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut Pipe> {
        self.pipes.get_mut(slot).and_then(|s| s.as_mut())
    }

    /// Remove a pipe if both ends are closed.
    pub fn try_remove(&mut self, slot: usize) -> bool {
        if let Some(pipe) = self.pipes.get(slot).and_then(|s| s.as_ref()) {
            if pipe.is_closed() {
                self.pipes[slot] = None;
                return true;
            }
        }
        false
    }

    /// Return the number of active pipes.
    pub fn count(&self) -> usize {
        self.pipes.iter().filter(|s| s.is_some()).count()
    }
}
