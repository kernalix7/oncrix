// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel FIFO circular buffer.
//!
//! `Kfifo` is a fixed-size circular (ring) buffer that supports
//! single-element and bulk put/get operations. The indices wrap
//! around using a power-of-two mask, making modular arithmetic
//! branchless.
//!
//! # Design
//!
//! ```text
//!   +------+------+------+------+------+------+------+------+
//!   |  D0  |  D1  |  D2  | .... | .... | .... |  Dn  | .... |
//!   +------+------+------+------+------+------+------+------+
//!          ^                             ^
//!        out_idx                       in_idx
//!
//!   mask = SIZE - 1   (SIZE must be power of 2)
//!   len  = in_idx - out_idx
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/kfifo.h`,
//! `lib/kfifo.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Default FIFO size (must be power of 2).
const DEFAULT_FIFO_SIZE: usize = 256;

/// Maximum FIFO size.
const _MAX_FIFO_SIZE: usize = 65536;

/// Maximum managed FIFOs.
const MAX_FIFOS: usize = 256;

// ======================================================================
// Kfifo
// ======================================================================

/// Fixed-size circular buffer.
///
/// Uses wrapping indices with power-of-two mask for efficient
/// modular arithmetic.
pub struct Kfifo {
    /// Data buffer.
    buffer: [u8; DEFAULT_FIFO_SIZE],
    /// Write index (monotonically increasing).
    in_idx: u32,
    /// Read index (monotonically increasing).
    out_idx: u32,
    /// Mask (size - 1, for wrapping).
    mask: u32,
    /// Actual size of the buffer.
    size: u32,
    /// Statistics: total bytes written.
    stats_bytes_in: u64,
    /// Statistics: total bytes read.
    stats_bytes_out: u64,
}

impl Kfifo {
    /// Creates a new empty FIFO.
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; DEFAULT_FIFO_SIZE],
            in_idx: 0,
            out_idx: 0,
            mask: (DEFAULT_FIFO_SIZE as u32) - 1,
            size: DEFAULT_FIFO_SIZE as u32,
            stats_bytes_in: 0,
            stats_bytes_out: 0,
        }
    }

    /// Puts a single byte into the FIFO.
    ///
    /// Returns `Err(WouldBlock)` if the FIFO is full.
    pub fn kfifo_put(&mut self, val: u8) -> Result<()> {
        if self.kfifo_is_full() {
            return Err(Error::WouldBlock);
        }
        let idx = (self.in_idx & self.mask) as usize;
        self.buffer[idx] = val;
        self.in_idx = self.in_idx.wrapping_add(1);
        self.stats_bytes_in += 1;
        Ok(())
    }

    /// Gets a single byte from the FIFO.
    ///
    /// Returns `Err(WouldBlock)` if the FIFO is empty.
    pub fn kfifo_get(&mut self) -> Result<u8> {
        if self.kfifo_is_empty() {
            return Err(Error::WouldBlock);
        }
        let idx = (self.out_idx & self.mask) as usize;
        let val = self.buffer[idx];
        self.out_idx = self.out_idx.wrapping_add(1);
        self.stats_bytes_out += 1;
        Ok(val)
    }

    /// Bulk put: copies `data` into the FIFO.
    ///
    /// Returns the number of bytes actually written.
    pub fn kfifo_in(&mut self, data: &[u8]) -> usize {
        let avail = self.kfifo_avail() as usize;
        let to_write = data.len().min(avail);
        for i in 0..to_write {
            let idx = (self.in_idx & self.mask) as usize;
            self.buffer[idx] = data[i];
            self.in_idx = self.in_idx.wrapping_add(1);
        }
        self.stats_bytes_in += to_write as u64;
        to_write
    }

    /// Bulk get: copies from the FIFO into `buf`.
    ///
    /// Returns the number of bytes actually read.
    pub fn kfifo_out(&mut self, buf: &mut [u8]) -> usize {
        let len = self.kfifo_len() as usize;
        let to_read = buf.len().min(len);
        for i in 0..to_read {
            let idx = (self.out_idx & self.mask) as usize;
            buf[i] = self.buffer[idx];
            self.out_idx = self.out_idx.wrapping_add(1);
        }
        self.stats_bytes_out += to_read as u64;
        to_read
    }

    /// Peeks at the next byte without removing it.
    pub fn peek(&self) -> Result<u8> {
        if self.kfifo_is_empty() {
            return Err(Error::WouldBlock);
        }
        let idx = (self.out_idx & self.mask) as usize;
        Ok(self.buffer[idx])
    }

    /// Skips `n` bytes in the FIFO (advances out_idx).
    ///
    /// Returns the number of bytes actually skipped.
    pub fn skip(&mut self, n: u32) -> u32 {
        let len = self.kfifo_len();
        let to_skip = n.min(len);
        self.out_idx = self.out_idx.wrapping_add(to_skip);
        self.stats_bytes_out += to_skip as u64;
        to_skip
    }

    /// Resets the FIFO (discards all data).
    pub fn reset(&mut self) {
        self.in_idx = 0;
        self.out_idx = 0;
    }

    /// Returns whether the FIFO is empty.
    pub fn kfifo_is_empty(&self) -> bool {
        self.in_idx == self.out_idx
    }

    /// Returns whether the FIFO is full.
    pub fn kfifo_is_full(&self) -> bool {
        self.kfifo_len() >= self.size
    }

    /// Returns the number of bytes in the FIFO.
    pub fn kfifo_len(&self) -> u32 {
        self.in_idx.wrapping_sub(self.out_idx)
    }

    /// Returns the number of free bytes.
    pub fn kfifo_avail(&self) -> u32 {
        self.size - self.kfifo_len()
    }

    /// Returns the FIFO size (capacity).
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Returns total bytes written.
    pub fn stats_bytes_in(&self) -> u64 {
        self.stats_bytes_in
    }

    /// Returns total bytes read.
    pub fn stats_bytes_out(&self) -> u64 {
        self.stats_bytes_out
    }
}

// ======================================================================
// KfifoTable — global registry
// ======================================================================

/// Global table of kernel FIFOs.
pub struct KfifoTable {
    /// Entries.
    entries: [KfifoEntry; MAX_FIFOS],
    /// Number of allocated FIFOs.
    count: usize,
}

/// Entry in the FIFO table.
struct KfifoEntry {
    /// The FIFO.
    fifo: Kfifo,
    /// Whether allocated.
    allocated: bool,
    /// Name (debugging).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
}

impl KfifoEntry {
    const fn new() -> Self {
        Self {
            fifo: Kfifo::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }
}

impl KfifoTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { KfifoEntry::new() }; MAX_FIFOS],
            count: 0,
        }
    }

    /// Allocates a new FIFO.
    pub fn alloc(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_FIFOS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot()?;
        self.entries[idx].allocated = true;
        self.entries[idx].fifo = Kfifo::new();
        let copy_len = name.len().min(32);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Frees a FIFO by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_FIFOS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = KfifoEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the FIFO at `idx`.
    pub fn get(&self, idx: usize) -> Result<&Kfifo> {
        if idx >= MAX_FIFOS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].fifo)
    }

    /// Returns a mutable reference to the FIFO at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut Kfifo> {
        if idx >= MAX_FIFOS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].fifo)
    }

    /// Returns the number of allocated FIFOs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds the first free slot.
    fn find_free_slot(&self) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)
    }
}
