// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Advanced pipe buffer with vectored I/O support.
//!
//! Implements a circular buffer pool modelled after the Linux kernel
//! `pipe_buffer` ring.  Each [`PipeInode`] owns a fixed array of
//! [`PipeBuffer`] slots that are cycled through as data is written
//! and consumed.  Scatter/gather I/O is provided via [`IoVec`]-based
//! `writev` / `readv` methods.
//!
//! A global [`PipeRegistry`] tracks all active pipes.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Size of a single pipe buffer page (bytes).
pub const PIPE_BUF: usize = 4096;

/// Maximum number of buffer slots per pipe.
pub const MAX_PIPE_BUFS: usize = 16;

/// Flag: the buffer page can be merged with subsequent writes.
pub const PIPE_BUF_FLAG_CAN_MERGE: u32 = 0x01;

/// Flag: the buffer page was gifted (splice / vmsplice).
pub const PIPE_BUF_FLAG_GIFT: u32 = 0x02;

/// Maximum number of pipes tracked by [`PipeRegistry`].
pub const MAX_PIPES: usize = 64;

// -------------------------------------------------------------------
// PipeBufFlags
// -------------------------------------------------------------------

/// Bitfield wrapper for per-buffer flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PipeBufFlags {
    /// Raw flag bits.
    bits: u32,
}

impl PipeBufFlags {
    /// Returns `true` if the buffer can be merged with new data.
    pub const fn can_merge(self) -> bool {
        self.bits & PIPE_BUF_FLAG_CAN_MERGE != 0
    }

    /// Returns `true` if the buffer was gifted.
    pub const fn is_gift(self) -> bool {
        self.bits & PIPE_BUF_FLAG_GIFT != 0
    }

    /// Set (or clear) the merge flag.
    pub fn set_can_merge(&mut self, val: bool) {
        if val {
            self.bits |= PIPE_BUF_FLAG_CAN_MERGE;
        } else {
            self.bits &= !PIPE_BUF_FLAG_CAN_MERGE;
        }
    }

    /// Set (or clear) the gift flag.
    pub fn set_gift(&mut self, val: bool) {
        if val {
            self.bits |= PIPE_BUF_FLAG_GIFT;
        } else {
            self.bits &= !PIPE_BUF_FLAG_GIFT;
        }
    }
}

// -------------------------------------------------------------------
// PipeBuffer
// -------------------------------------------------------------------

/// A single buffer slot inside a pipe.
///
/// Holds up to [`PIPE_BUF`] bytes with an offset/length window
/// tracking the valid region.
pub struct PipeBuffer {
    /// Backing storage.
    data: [u8; PIPE_BUF],
    /// Start offset of valid data within `data`.
    offset: u16,
    /// Number of valid bytes starting at `offset`.
    len: u16,
    /// Per-buffer flags.
    flags: PipeBufFlags,
    /// Whether this slot currently holds data.
    active: bool,
}

impl PipeBuffer {
    /// Create a new, empty pipe buffer.
    const fn new() -> Self {
        Self {
            data: [0u8; PIPE_BUF],
            offset: 0,
            len: 0,
            flags: PipeBufFlags { bits: 0 },
            active: false,
        }
    }

    /// Number of valid bytes available for reading.
    pub const fn available(&self) -> usize {
        self.len as usize
    }

    /// Remaining capacity for writing (from end of valid data).
    pub const fn remaining(&self) -> usize {
        PIPE_BUF - (self.offset as usize + self.len as usize)
    }

    /// Read up to `count` bytes into `dst`, returning bytes copied.
    ///
    /// Advances the internal offset and shrinks the valid window.
    pub fn read(&mut self, dst: &mut [u8], count: usize) -> usize {
        let to_copy = count.min(self.len as usize).min(dst.len());
        if to_copy == 0 {
            return 0;
        }
        let start = self.offset as usize;
        dst[..to_copy].copy_from_slice(&self.data[start..start + to_copy]);
        self.offset += to_copy as u16;
        self.len -= to_copy as u16;
        if self.len == 0 {
            self.offset = 0;
            self.active = false;
        }
        to_copy
    }

    /// Write up to `count` bytes from `src`, returning bytes copied.
    ///
    /// Appends after the current valid data window.
    pub fn write(&mut self, src: &[u8], count: usize) -> usize {
        let space = self.remaining();
        let to_copy = count.min(space).min(src.len());
        if to_copy == 0 {
            return 0;
        }
        let start = self.offset as usize + self.len as usize;
        self.data[start..start + to_copy].copy_from_slice(&src[..to_copy]);
        self.len += to_copy as u16;
        self.active = true;
        to_copy
    }
}

// -------------------------------------------------------------------
// IoVec
// -------------------------------------------------------------------

/// Scatter/gather I/O vector (matches POSIX `struct iovec` layout).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoVec {
    /// Base address (in-kernel logical pointer stored as `u64`).
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

// -------------------------------------------------------------------
// PipeInode
// -------------------------------------------------------------------

/// Kernel-internal representation of a pipe.
///
/// Manages a ring of [`PipeBuffer`] slots with independent reader
/// and writer reference counts.  Supports both simple and vectored
/// I/O through [`write_data`]/[`read_data`] and
/// [`writev`]/[`readv`].
pub struct PipeInode {
    /// Ring of buffer slots.
    bufs: [PipeBuffer; MAX_PIPE_BUFS],
    /// Index of the next slot to write into.
    head: usize,
    /// Index of the next slot to read from.
    tail: usize,
    /// Number of active (non-empty) buffer slots in the ring.
    count: usize,
    /// Number of open read endpoints.
    readers: u32,
    /// Number of open write endpoints.
    writers: u32,
    /// Unique pipe identifier.
    id: u32,
    /// Total byte capacity across all buffer slots.
    pub capacity: usize,
    /// Whether this pipe is allocated.
    active: bool,
}

/// Helper: create a default array of `MAX_PIPE_BUFS` pipe buffers.
const fn new_bufs() -> [PipeBuffer; MAX_PIPE_BUFS] {
    let mut arr = [const { PipeBuffer::new() }; MAX_PIPE_BUFS];
    let mut i = 0;
    while i < MAX_PIPE_BUFS {
        arr[i] = PipeBuffer::new();
        i += 1;
    }
    arr
}

impl PipeInode {
    /// Create a new, inactive pipe inode.
    const fn new() -> Self {
        Self {
            bufs: new_bufs(),
            head: 0,
            tail: 0,
            count: 0,
            readers: 0,
            writers: 0,
            id: 0,
            capacity: PIPE_BUF * MAX_PIPE_BUFS,
            active: false,
        }
    }

    /// Write `data` into the pipe, returning the number of bytes
    /// actually written.
    ///
    /// Returns [`Error::WouldBlock`] when no buffer slots are
    /// available (all slots are in use).
    pub fn write_data(&mut self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;

        // Try merging into the current head slot if allowed.
        if self.count > 0 {
            let prev = if self.head == 0 {
                MAX_PIPE_BUFS - 1
            } else {
                self.head - 1
            };
            let buf = &mut self.bufs[prev];
            if buf.active && buf.flags.can_merge() {
                let n = buf.write(&data[written..], data.len() - written);
                written += n;
            }
        }

        // Fill new slots as needed.
        while written < data.len() {
            if self.count >= MAX_PIPE_BUFS {
                break;
            }
            let slot = self.head;
            let buf = &mut self.bufs[slot];
            buf.offset = 0;
            buf.len = 0;
            buf.active = true;
            buf.flags.set_can_merge(true);
            let n = buf.write(&data[written..], data.len() - written);
            written += n;
            self.head = (self.head + 1) % MAX_PIPE_BUFS;
            self.count += 1;
        }

        if written == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(written)
    }

    /// Read data from the pipe into `buf`, returning the number of
    /// bytes actually read.
    ///
    /// Returns [`Error::WouldBlock`] when the pipe is empty.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }

        let mut total = 0usize;
        let buf_len = buf.len();
        while total < buf_len && self.count > 0 {
            let slot = self.tail;
            let pb = &mut self.bufs[slot];
            let n = pb.read(&mut buf[total..], buf_len - total);
            total += n;
            if !pb.active {
                self.tail = (self.tail + 1) % MAX_PIPE_BUFS;
                self.count -= 1;
            }
        }

        if total == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(total)
    }

    /// Vectored write — scatter data from multiple [`IoVec`]s into
    /// the pipe.
    ///
    /// Each `IoVec::base` is treated as an in-kernel pointer.
    /// Returns total bytes written or [`Error::WouldBlock`].
    ///
    /// # Safety caveat
    /// The caller must ensure that each `IoVec::base` points to a
    /// valid, readable region of at least `IoVec::len` bytes.  This
    /// function performs the raw pointer dereference internally.
    pub fn writev(&mut self, iovs: &[IoVec]) -> Result<usize> {
        let mut total = 0usize;
        for iov in iovs {
            if iov.len == 0 || iov.base == 0 {
                continue;
            }
            // SAFETY: caller guarantees base is a valid kernel
            // pointer with at least `len` readable bytes.
            let slice =
                unsafe { core::slice::from_raw_parts(iov.base as *const u8, iov.len as usize) };
            match self.write_data(slice) {
                Ok(n) => total += n,
                Err(Error::WouldBlock) if total > 0 => break,
                Err(e) => {
                    if total > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        if total == 0 && !iovs.is_empty() {
            return Err(Error::WouldBlock);
        }
        Ok(total)
    }

    /// Vectored read — gather data from the pipe into multiple
    /// [`IoVec`]s.
    ///
    /// Returns total bytes read or [`Error::WouldBlock`].
    ///
    /// # Safety caveat
    /// The caller must ensure that each `IoVec::base` points to a
    /// valid, writable region of at least `IoVec::len` bytes.
    pub fn readv(&mut self, iovs: &mut [IoVec]) -> Result<usize> {
        let mut total = 0usize;
        for iov in iovs.iter() {
            if iov.len == 0 || iov.base == 0 {
                continue;
            }
            // SAFETY: caller guarantees base is a valid kernel
            // pointer with at least `len` writable bytes.
            let slice =
                unsafe { core::slice::from_raw_parts_mut(iov.base as *mut u8, iov.len as usize) };
            match self.read_data(slice) {
                Ok(n) => total += n,
                Err(Error::WouldBlock) if total > 0 => break,
                Err(e) => {
                    if total > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        if total == 0 && !iovs.is_empty() {
            return Err(Error::WouldBlock);
        }
        Ok(total)
    }

    /// Total bytes available for reading across all active slots.
    pub fn available_read(&self) -> usize {
        let mut total = 0usize;
        let mut idx = self.tail;
        let mut remaining = self.count;
        while remaining > 0 {
            total += self.bufs[idx].available();
            idx = (idx + 1) % MAX_PIPE_BUFS;
            remaining -= 1;
        }
        total
    }

    /// Total bytes of write capacity remaining.
    pub fn available_write(&self) -> usize {
        let free_slots = MAX_PIPE_BUFS.saturating_sub(self.count);
        let mut space = free_slots * PIPE_BUF;
        // Also count remaining space in the current head slot.
        if self.count > 0 {
            let prev = if self.head == 0 {
                MAX_PIPE_BUFS - 1
            } else {
                self.head - 1
            };
            let buf = &self.bufs[prev];
            if buf.active && buf.flags.can_merge() {
                space += buf.remaining();
            }
        }
        space
    }

    /// Returns `true` if the pipe contains data to read.
    pub fn is_readable(&self) -> bool {
        self.count > 0
    }

    /// Returns `true` if the pipe has space for more data.
    pub fn is_writable(&self) -> bool {
        self.count < MAX_PIPE_BUFS
    }

    /// Decrement the reader count.
    pub fn close_read(&mut self) {
        self.readers = self.readers.saturating_sub(1);
    }

    /// Decrement the writer count.
    pub fn close_write(&mut self) {
        self.writers = self.writers.saturating_sub(1);
    }

    /// Returns `true` if the pipe is broken (no readers **or** no
    /// writers).
    pub fn is_broken(&self) -> bool {
        self.readers == 0 || self.writers == 0
    }
}

// -------------------------------------------------------------------
// PipeRegistry
// -------------------------------------------------------------------

/// Global registry of all kernel pipes.
///
/// Provides allocation, lookup, and deallocation of [`PipeInode`]
/// instances.
pub struct PipeRegistry {
    /// Fixed pool of pipe inodes.
    pipes: [PipeInode; MAX_PIPES],
    /// Monotonically increasing ID counter.
    next_id: u32,
    /// Number of currently active pipes.
    count: usize,
}

/// Helper: create a default array of `MAX_PIPES` pipe inodes.
const fn new_pipes() -> [PipeInode; MAX_PIPES] {
    let mut arr = [const { PipeInode::new() }; MAX_PIPES];
    let mut i = 0;
    while i < MAX_PIPES {
        arr[i] = PipeInode::new();
        i += 1;
    }
    arr
}

impl PipeRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            pipes: new_pipes(),
            next_id: 1,
            count: 0,
        }
    }

    /// Allocate a new pipe, returning its unique id.
    ///
    /// The pipe starts with one reader and one writer.
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create_pipe(&mut self) -> Result<u32> {
        if self.count >= MAX_PIPES {
            return Err(Error::OutOfMemory);
        }
        let mut i = 0;
        while i < MAX_PIPES {
            if !self.pipes[i].active {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                let pipe = &mut self.pipes[i];
                *pipe = PipeInode::new();
                pipe.id = id;
                pipe.active = true;
                pipe.readers = 1;
                pipe.writers = 1;
                self.count += 1;
                return Ok(id);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Deallocate the pipe with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no active pipe has that id.
    pub fn close_pipe(&mut self, id: u32) -> Result<()> {
        let mut i = 0;
        while i < MAX_PIPES {
            if self.pipes[i].active && self.pipes[i].id == id {
                self.pipes[i].active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Look up a pipe by id (shared reference).
    pub fn get(&self, id: u32) -> Option<&PipeInode> {
        let mut i = 0;
        while i < MAX_PIPES {
            if self.pipes[i].active && self.pipes[i].id == id {
                return Some(&self.pipes[i]);
            }
            i += 1;
        }
        None
    }

    /// Look up a pipe by id (mutable reference).
    pub fn get_mut(&mut self, id: u32) -> Option<&mut PipeInode> {
        let mut i = 0;
        while i < MAX_PIPES {
            if self.pipes[i].active && self.pipes[i].id == id {
                return Some(&mut self.pipes[i]);
            }
            i += 1;
        }
        None
    }

    /// Number of active pipes.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no pipes are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PipeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
