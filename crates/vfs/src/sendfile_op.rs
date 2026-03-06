// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sendfile` zero-copy file transfer for the ONCRIX VFS.
//!
//! Implements the `sendfile(2)` system call helper that transfers data between
//! a source file descriptor and an output socket/file descriptor entirely in
//! kernel space, avoiding a round-trip through user-space buffers.

use oncrix_lib::{Error, Result};

/// Maximum bytes transferable in a single `sendfile` call.
pub const SENDFILE_MAX_COUNT: usize = 0x7fff_f000;

/// Internal transfer chunk size used for page-by-page iteration.
pub const SENDFILE_CHUNK_SIZE: usize = 65536;

/// Maximum number of simultaneous sendfile operations tracked globally.
pub const SENDFILE_MAX_OPS: usize = 32;

/// State of an in-progress `sendfile` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendfileState {
    /// Slot is not in use.
    #[default]
    Idle,
    /// Transfer is in progress.
    Running,
    /// Transfer completed successfully.
    Done,
    /// Transfer was aborted due to an error.
    Error,
}

/// Descriptor for a single `sendfile` operation.
#[derive(Debug, Clone, Copy)]
pub struct SendfileOp {
    /// Source file descriptor.
    pub in_fd: i32,
    /// Destination file descriptor (or socket).
    pub out_fd: i32,
    /// Current read position within the source file.
    pub offset: u64,
    /// Total bytes requested for transfer.
    pub count: usize,
    /// Bytes transferred so far.
    pub transferred: usize,
    /// Current operation state.
    pub state: SendfileState,
}

impl SendfileOp {
    /// Construct a new sendfile operation descriptor.
    pub const fn new(in_fd: i32, out_fd: i32, offset: u64, count: usize) -> Self {
        Self {
            in_fd,
            out_fd,
            offset,
            count,
            transferred: 0,
            state: SendfileState::Idle,
        }
    }

    /// Return the number of bytes remaining to transfer.
    pub fn remaining(&self) -> usize {
        self.count.saturating_sub(self.transferred)
    }

    /// Return `true` if the transfer is complete.
    pub fn is_done(&self) -> bool {
        self.transferred >= self.count || self.state == SendfileState::Done
    }

    /// Advance the transfer by `n` bytes.
    pub fn advance(&mut self, n: usize) {
        self.transferred += n;
        self.offset += n as u64;
        if self.transferred >= self.count {
            self.state = SendfileState::Done;
        }
    }

    /// Mark the operation as errored.
    pub fn fail(&mut self) {
        self.state = SendfileState::Error;
    }
}

impl Default for SendfileOp {
    fn default() -> Self {
        Self::new(-1, -1, 0, 0)
    }
}

/// Intermediate staging buffer used for page-granular sendfile transfers.
pub struct SendfileStage {
    buf: [u8; SENDFILE_CHUNK_SIZE],
    valid: usize,
}

impl SendfileStage {
    /// Create a zeroed staging buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; SENDFILE_CHUNK_SIZE],
            valid: 0,
        }
    }

    /// Return a slice of the valid bytes in the staging buffer.
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.valid]
    }

    /// Fill the staging buffer from a source slice (up to `SENDFILE_CHUNK_SIZE`).
    pub fn fill(&mut self, src: &[u8]) {
        let n = src.len().min(SENDFILE_CHUNK_SIZE);
        self.buf[..n].copy_from_slice(&src[..n]);
        self.valid = n;
    }

    /// Reset the staging buffer.
    pub fn reset(&mut self) {
        self.valid = 0;
    }
}

impl Default for SendfileStage {
    fn default() -> Self {
        Self::new()
    }
}

/// Global table of active sendfile operations.
pub struct SendfileTable {
    ops: [SendfileOp; SENDFILE_MAX_OPS],
    active: [bool; SENDFILE_MAX_OPS],
    count: usize,
}

impl SendfileTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            ops: [const { SendfileOp::new(-1, -1, 0, 0) }; SENDFILE_MAX_OPS],
            active: [false; SENDFILE_MAX_OPS],
            count: 0,
        }
    }

    /// Register a new sendfile operation, returning its index or `Busy`.
    pub fn register(&mut self, op: SendfileOp) -> Result<usize> {
        if self.count >= SENDFILE_MAX_OPS {
            return Err(Error::Busy);
        }
        for (i, a) in self.active.iter_mut().enumerate() {
            if !*a {
                self.ops[i] = op;
                *a = true;
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Get a mutable reference to an active operation by index.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut SendfileOp> {
        if idx >= SENDFILE_MAX_OPS || !self.active[idx] {
            return Err(Error::NotFound);
        }
        Ok(&mut self.ops[idx])
    }

    /// Deregister a completed or failed operation by index.
    pub fn deregister(&mut self, idx: usize) -> Result<SendfileOp> {
        if idx >= SENDFILE_MAX_OPS || !self.active[idx] {
            return Err(Error::NotFound);
        }
        let op = self.ops[idx];
        self.active[idx] = false;
        self.count -= 1;
        Ok(op)
    }

    /// Return the number of active operations.
    pub fn active_count(&self) -> usize {
        self.count
    }
}

impl Default for SendfileTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate sendfile parameters.
pub fn validate_sendfile_args(in_fd: i32, out_fd: i32, count: usize) -> Result<()> {
    if in_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if out_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if count == 0 || count > SENDFILE_MAX_COUNT {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Compute the maximum transfer size for a single sendfile chunk.
pub fn chunk_size(remaining: usize) -> usize {
    remaining.min(SENDFILE_CHUNK_SIZE)
}
