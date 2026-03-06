// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pipe buffer ring implementation.
//!
//! Provides a fixed-capacity, byte-oriented ring buffer used by the pipe
//! subsystem. Supports blocking semantics tracking (readers/writers), splice,
//! and peek operations. The ring is designed for single-producer single-consumer
//! use, with locking done by the caller.

use oncrix_lib::{Error, Result};

/// Default pipe buffer capacity in bytes.
pub const PIPE_DEF_BUFFERS: usize = 16;

/// Maximum pipe buffer capacity (256 pages × 4096 bytes).
pub const PIPE_MAX_SIZE: usize = 1048576;

/// Default page size for pipe buffer pages.
pub const PIPE_BUF_PAGE_SIZE: usize = 4096;

/// Pipe buffer flags.
pub const PIPE_BUF_FLAG_LRU: u32 = 0x01;
pub const PIPE_BUF_FLAG_ATOMIC: u32 = 0x02;
pub const PIPE_BUF_FLAG_GIFT: u32 = 0x04;
pub const PIPE_BUF_FLAG_PACKET: u32 = 0x08;
pub const PIPE_BUF_FLAG_WHOLE: u32 = 0x10;
pub const PIPE_BUF_FLAG_CAN_MERGE: u32 = 0x10;

/// A single pipe buffer slot (represents one page of data).
#[derive(Debug, Clone, Copy)]
pub struct PipeBufSlot {
    /// Offset into the page where data begins.
    pub offset: u32,
    /// Length of valid data in this slot.
    pub len: u32,
    /// Slot flags.
    pub flags: u32,
}

impl PipeBufSlot {
    /// Create an empty slot.
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            len: 0,
            flags: 0,
        }
    }

    /// Return true if this slot is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the end offset within the page.
    pub fn end_offset(&self) -> u32 {
        self.offset + self.len
    }
}

/// Pipe ring buffer.
///
/// Data is stored in a backing array of `PIPE_BUF_PAGE_SIZE`-byte pages.
/// The ring maintains head (read pointer) and tail (write pointer) indices
/// into a slot array.
#[derive(Debug)]
pub struct PipeRingBuf {
    /// Backing data storage.
    data: [u8; PIPE_BUF_PAGE_SIZE * PIPE_DEF_BUFFERS],
    /// Slot metadata array.
    slots: [PipeBufSlot; PIPE_DEF_BUFFERS],
    /// Read (head) index into slots.
    pub head: usize,
    /// Write (tail) index into slots.
    pub tail: usize,
    /// Total bytes available to read.
    pub bytes_ready: usize,
    /// Number of reader processes.
    pub readers: u32,
    /// Number of writer processes.
    pub writers: u32,
    /// Whether O_NONBLOCK is set.
    pub nonblock: bool,
    /// Whether packet mode (O_DIRECT on pipe) is active.
    pub packet_mode: bool,
}

impl PipeRingBuf {
    /// Create a new empty pipe ring buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; PIPE_BUF_PAGE_SIZE * PIPE_DEF_BUFFERS],
            slots: [PipeBufSlot::empty(); PIPE_DEF_BUFFERS],
            head: 0,
            tail: 0,
            bytes_ready: 0,
            readers: 0,
            writers: 0,
            nonblock: false,
            packet_mode: false,
        }
    }

    /// Return the number of occupied slots.
    pub fn occupied_slots(&self) -> usize {
        if self.tail >= self.head {
            self.tail - self.head
        } else {
            PIPE_DEF_BUFFERS - self.head + self.tail
        }
    }

    /// Return the number of free slots.
    pub fn free_slots(&self) -> usize {
        PIPE_DEF_BUFFERS - self.occupied_slots()
    }

    /// Return true if the ring is empty (no data to read).
    pub fn is_empty(&self) -> bool {
        self.bytes_ready == 0
    }

    /// Return true if the ring is full (no room to write another page).
    pub fn is_full(&self) -> bool {
        self.free_slots() == 0
    }

    /// Write `buf` into the pipe, returning bytes written.
    ///
    /// May write less than `buf.len()` if the ring becomes full.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.readers == 0 {
            return Err(Error::IoError); // EPIPE: no readers
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        let mut remaining = buf;

        while !remaining.is_empty() {
            if self.is_full() {
                if written > 0 {
                    break;
                }
                return Err(Error::WouldBlock);
            }

            let slot_idx = self.tail;
            let page_base = slot_idx * PIPE_BUF_PAGE_SIZE;
            let slot = &self.slots[slot_idx];

            // Try to merge with the existing tail slot if flags allow.
            let can_merge =
                !slot.is_empty() && slot.flags & PIPE_BUF_FLAG_CAN_MERGE != 0 && !self.packet_mode;
            let (copy_offset, copy_max) = if can_merge {
                let end = slot.end_offset() as usize;
                if end < PIPE_BUF_PAGE_SIZE {
                    (end, PIPE_BUF_PAGE_SIZE - end)
                } else {
                    (0, 0)
                }
            } else {
                (0, PIPE_BUF_PAGE_SIZE)
            };

            if copy_max == 0 {
                // Advance to next slot.
                self.tail = (self.tail + 1) % PIPE_DEF_BUFFERS;
                continue;
            }

            let to_copy = remaining.len().min(copy_max);
            let dst = &mut self.data[page_base + copy_offset..page_base + copy_offset + to_copy];
            dst.copy_from_slice(&remaining[..to_copy]);

            if can_merge {
                self.slots[slot_idx].len += to_copy as u32;
            } else {
                self.slots[slot_idx] = PipeBufSlot {
                    offset: 0,
                    len: to_copy as u32,
                    flags: PIPE_BUF_FLAG_CAN_MERGE,
                };
                self.tail = (self.tail + 1) % PIPE_DEF_BUFFERS;
            }

            self.bytes_ready += to_copy;
            written += to_copy;
            remaining = &remaining[to_copy..];
        }

        Ok(written)
    }

    /// Read up to `buf.len()` bytes from the pipe.
    ///
    /// Returns the number of bytes actually read.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.is_empty() {
            if self.writers == 0 {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }

        let mut read_bytes = 0usize;
        let mut remaining = buf.len();

        while remaining > 0 && !self.is_empty() {
            let slot_idx = self.head;
            let slot = self.slots[slot_idx];
            if slot.is_empty() {
                self.head = (self.head + 1) % PIPE_DEF_BUFFERS;
                continue;
            }

            let page_base = slot_idx * PIPE_BUF_PAGE_SIZE;
            let src_off = slot.offset as usize;
            let avail = slot.len as usize;
            let to_copy = remaining.min(avail);

            let src = &self.data[page_base + src_off..page_base + src_off + to_copy];
            buf[read_bytes..read_bytes + to_copy].copy_from_slice(src);

            read_bytes += to_copy;
            remaining -= to_copy;
            self.bytes_ready -= to_copy;

            if to_copy == avail {
                // Slot consumed.
                self.slots[slot_idx] = PipeBufSlot::empty();
                self.head = (self.head + 1) % PIPE_DEF_BUFFERS;
            } else {
                self.slots[slot_idx].offset += to_copy as u32;
                self.slots[slot_idx].len -= to_copy as u32;
            }

            if self.packet_mode {
                break; // Packet mode: one read = one message.
            }
        }

        Ok(read_bytes)
    }

    /// Peek at up to `buf.len()` bytes without consuming them.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        if self.is_empty() {
            return 0;
        }

        let mut peeked = 0usize;
        let mut idx = self.head;
        let mut remaining = buf.len();

        loop {
            if remaining == 0 || peeked >= self.bytes_ready {
                break;
            }
            let slot = self.slots[idx];
            if slot.is_empty() {
                idx = (idx + 1) % PIPE_DEF_BUFFERS;
                if idx == self.tail {
                    break;
                }
                continue;
            }
            let page_base = idx * PIPE_BUF_PAGE_SIZE;
            let src_off = slot.offset as usize;
            let avail = slot.len as usize;
            let to_copy = remaining.min(avail);

            buf[peeked..peeked + to_copy]
                .copy_from_slice(&self.data[page_base + src_off..page_base + src_off + to_copy]);
            peeked += to_copy;
            remaining -= to_copy;
            idx = (idx + 1) % PIPE_DEF_BUFFERS;
            if idx == self.tail {
                break;
            }
        }

        peeked
    }

    /// Return the total bytes available to read without blocking.
    pub fn bytes_available(&self) -> usize {
        self.bytes_ready
    }

    /// Return the total writable capacity remaining.
    pub fn bytes_capacity(&self) -> usize {
        self.free_slots() * PIPE_BUF_PAGE_SIZE
    }

    /// Set the pipe buffer capacity (not actually resizable in fixed impl).
    pub fn set_size(&mut self, size: usize) -> Result<()> {
        if size > PIPE_MAX_SIZE || size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.bytes_ready > size {
            return Err(Error::Busy);
        }
        // In a dynamic implementation we would resize; here we just validate.
        Ok(())
    }
}

impl Default for PipeRingBuf {
    fn default() -> Self {
        Self::new()
    }
}
