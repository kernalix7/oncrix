// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA memory pool allocator.
//!
//! Manages pools of physically contiguous, DMA-capable memory buffers.
//! Provides fixed-size buffer allocation to avoid repeated large DMA allocations
//! and minimize fragmentation of the DMA-addressable memory space.
//!
//! # Design
//!
//! Each pool is a slab of pre-allocated DMA memory split into equal-sized chunks.
//! Allocation and deallocation are O(1) via a free-list bitmap.

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum buffers per DMA pool.
pub const DMA_POOL_MAX_BUFS: usize = 64;

/// A single DMA buffer descriptor.
#[derive(Debug, Clone, Copy)]
pub struct DmaBuffer {
    /// Physical (bus) address for DMA programming.
    pub phys: u64,
    /// Virtual address for CPU access.
    pub virt: usize,
    /// Buffer size in bytes.
    pub size: usize,
}

/// Fixed-size DMA buffer pool.
pub struct DmaPool {
    /// Virtual address of the pool base.
    virt_base: usize,
    /// Physical address of the pool base.
    phys_base: u64,
    /// Size of each buffer in the pool.
    buf_size: usize,
    /// Total number of buffers.
    capacity: usize,
    /// Bitmap tracking free buffers (bit=1 means free).
    free_bitmap: u64,
}

impl DmaPool {
    /// Creates a new DMA pool.
    ///
    /// # Arguments
    ///
    /// * `virt_base` - Virtual (CPU) address of pre-allocated DMA memory
    /// * `phys_base` - Physical (bus) address for DMA programming
    /// * `buf_size` - Size of each buffer in bytes
    /// * `capacity` - Number of buffers (max 64)
    pub const fn new(virt_base: usize, phys_base: u64, buf_size: usize, capacity: usize) -> Self {
        let free_bitmap = if capacity >= 64 {
            u64::MAX
        } else {
            (1u64 << capacity) - 1
        };
        Self {
            virt_base,
            phys_base,
            buf_size,
            capacity,
            free_bitmap,
        }
    }

    /// Allocates a buffer from the pool.
    pub fn alloc(&mut self) -> Result<DmaBuffer> {
        if self.free_bitmap == 0 {
            return Err(Error::OutOfMemory);
        }
        let idx = self.free_bitmap.trailing_zeros() as usize;
        self.free_bitmap &= !(1u64 << idx);
        Ok(DmaBuffer {
            phys: self.phys_base + (idx * self.buf_size) as u64,
            virt: self.virt_base + idx * self.buf_size,
            size: self.buf_size,
        })
    }

    /// Returns a buffer to the pool.
    pub fn free(&mut self, buf: &DmaBuffer) -> Result<()> {
        if buf.virt < self.virt_base {
            return Err(Error::InvalidArgument);
        }
        let offset = buf.virt - self.virt_base;
        if offset % self.buf_size != 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = offset / self.buf_size;
        if idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        let bit = 1u64 << idx;
        if self.free_bitmap & bit != 0 {
            return Err(Error::AlreadyExists); // Double-free
        }
        self.free_bitmap |= bit;
        Ok(())
    }

    /// Returns the number of free buffers.
    pub fn free_count(&self) -> usize {
        self.free_bitmap.count_ones() as usize
    }

    /// Returns the total buffer count.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns whether the pool is empty (no free buffers).
    pub fn is_exhausted(&self) -> bool {
        self.free_bitmap == 0
    }

    /// Returns the buffer size.
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }
}

impl Default for DmaPool {
    fn default() -> Self {
        Self::new(0, 0, 4096, 0)
    }
}
