// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Buffer head management — block I/O buffering layer.
//!
//! The buffer head subsystem provides a caching layer between the page
//! cache and the block device.  Each `BufferHead` represents a single
//! disk block mapped into memory, tracking its state (uptodate, dirty,
//! locked, mapped) and providing synchronous and asynchronous I/O
//! primitives.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  VFS / filesystem (ext2, ext4, etc.)                       │
//! │       │  getblk / bread / bwrite                           │
//! │       ▼                                                    │
//! │  ┌──────────────────────────────────────────┐              │
//! │  │  Buffer head layer                       │              │
//! │  │  ┌────────────────────────────────────┐  │              │
//! │  │  │  BufferHead pool                   │  │              │
//! │  │  │  [block_nr, device, state, data]   │  │              │
//! │  │  └────────────────────────────────────┘  │              │
//! │  │  ┌────────────────────────────────────┐  │              │
//! │  │  │  LRU list (reclaimable buffers)    │  │              │
//! │  │  └────────────────────────────────────┘  │              │
//! │  │  ┌────────────────────────────────────┐  │              │
//! │  │  │  Per-page buffer list              │  │              │
//! │  │  │  (page → list of block buffers)    │  │              │
//! │  │  └────────────────────────────────────┘  │              │
//! │  └──────────────────────────────────────────┘              │
//! │       │  submit_bh                                         │
//! │       ▼                                                    │
//! │  Block device layer                                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Buffer states
//!
//! Each buffer head has a set of state flags:
//! - **BH_Uptodate**: Buffer contains valid data from disk.
//! - **BH_Dirty**: Buffer has been modified and needs writeback.
//! - **BH_Lock**: Buffer is locked for I/O.
//! - **BH_Mapped**: Buffer has a valid block mapping on disk.
//! - **BH_New**: Buffer was newly allocated (not yet written).
//! - **BH_Async_Read**: Buffer is involved in async read I/O.
//! - **BH_Async_Write**: Buffer is involved in async write I/O.
//!
//! ## Operations
//!
//! - `getblk`: Find or create a buffer for a given (device, block_nr).
//! - `bread`: Read a block synchronously (getblk + wait for uptodate).
//! - `bwrite`: Write a dirty buffer to disk.
//! - `brelse`: Release a reference to a buffer.
//! - `sync_dirty_buffer`: Write a dirty buffer and wait for completion.
//! - `submit_bh`: Submit a buffer for async I/O.
//!
//! ## Per-page buffer lists
//!
//! A single page can contain multiple buffers (e.g., a 4096-byte page
//! with 1024-byte block size has 4 buffers).  The per-page list links
//! all buffers belonging to the same page.
//!
//! # Reference
//!
//! Linux `fs/buffer.c`, `include/linux/buffer_head.h`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default block size in bytes.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Minimum supported block size.
const MIN_BLOCK_SIZE: usize = 512;

/// Maximum supported block size.
const MAX_BLOCK_SIZE: usize = 65536;

/// Maximum number of buffer heads in the pool.
const MAX_BUFFER_HEADS: usize = 512;

/// Page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Sentinel for "no buffer" in linked lists.
const NONE_IDX: u32 = u32::MAX;

/// Maximum number of per-page buffer list heads.
const MAX_PAGE_LISTS: usize = 128;

// ── Buffer state flags ───────────────────────────────────────────────────────

/// State flags for a buffer head.
#[derive(Debug, Clone, Copy)]
pub struct BhState {
    /// Buffer contains valid data from disk.
    pub uptodate: bool,
    /// Buffer has been modified and needs writeback.
    pub dirty: bool,
    /// Buffer is locked for I/O.
    pub locked: bool,
    /// Buffer has a valid block-to-disk mapping.
    pub mapped: bool,
    /// Buffer was newly allocated.
    pub new: bool,
    /// Async read in progress.
    pub async_read: bool,
    /// Async write in progress.
    pub async_write: bool,
    /// Buffer is on the LRU (reclaimable).
    pub on_lru: bool,
}

impl BhState {
    /// Create a default (clean, unmapped) state.
    const fn new() -> Self {
        Self {
            uptodate: false,
            dirty: false,
            locked: false,
            mapped: false,
            new: false,
            async_read: false,
            async_write: false,
            on_lru: false,
        }
    }
}

// ── Buffer head ──────────────────────────────────────────────────────────────

/// A single buffer head representing a disk block in memory.
struct BufferHead {
    /// Block number on the device.
    block_nr: u64,
    /// Device identifier.
    device_id: u32,
    /// Block size in bytes.
    block_size: u32,
    /// State flags.
    state: BhState,
    /// Reference count.
    ref_count: u32,
    /// Data buffer (holds the block contents).
    /// For blocks <= PAGE_SIZE we store inline; larger blocks use
    /// a secondary buffer (not implemented in this fixed-size version).
    data: [u8; PAGE_SIZE],
    /// Actual data length (block_size, up to PAGE_SIZE).
    data_len: usize,
    /// Page this buffer belongs to (index into page_lists).
    page_list: u32,
    /// Next buffer in the same page's buffer list.
    page_next: u32,
    /// Next buffer in the LRU list.
    lru_next: u32,
    /// Previous buffer in the LRU list.
    lru_prev: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl BufferHead {
    /// Create an empty, unused buffer head.
    const fn empty() -> Self {
        Self {
            block_nr: 0,
            device_id: 0,
            block_size: DEFAULT_BLOCK_SIZE as u32,
            state: BhState::new(),
            ref_count: 0,
            data: [0; PAGE_SIZE],
            data_len: 0,
            page_list: NONE_IDX,
            page_next: NONE_IDX,
            lru_next: NONE_IDX,
            lru_prev: NONE_IDX,
            in_use: false,
        }
    }
}

// ── Per-page buffer list ─────────────────────────────────────────────────────

/// Tracks all buffers belonging to a single page.
struct PageBufferList {
    /// Page index (file_offset / PAGE_SIZE).
    page_index: u64,
    /// Device ID this page belongs to.
    device_id: u32,
    /// Head of the buffer chain for this page.
    head: u32,
    /// Number of buffers in this page.
    buffer_count: u8,
    /// Whether this slot is in use.
    in_use: bool,
}

impl PageBufferList {
    /// Create an empty, unused page buffer list.
    const fn empty() -> Self {
        Self {
            page_index: 0,
            device_id: 0,
            head: NONE_IDX,
            buffer_count: 0,
            in_use: false,
        }
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Buffer head subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct BufferHeadStats {
    /// Total getblk calls.
    pub getblk_calls: u64,
    /// getblk hits (buffer already existed).
    pub getblk_hits: u64,
    /// bread calls (synchronous reads).
    pub bread_calls: u64,
    /// bwrite calls (writes submitted).
    pub bwrite_calls: u64,
    /// brelse calls (references released).
    pub brelse_calls: u64,
    /// Buffers currently in use.
    pub buffers_active: u32,
    /// Dirty buffers.
    pub dirty_buffers: u32,
    /// Locked buffers.
    pub locked_buffers: u32,
    /// LRU reclaims.
    pub lru_reclaims: u64,
    /// sync_dirty_buffer calls.
    pub sync_writes: u64,
}

impl BufferHeadStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            getblk_calls: 0,
            getblk_hits: 0,
            bread_calls: 0,
            bwrite_calls: 0,
            brelse_calls: 0,
            buffers_active: 0,
            dirty_buffers: 0,
            locked_buffers: 0,
            lru_reclaims: 0,
            sync_writes: 0,
        }
    }
}

// ── I/O request type ─────────────────────────────────────────────────────────

/// Type of I/O operation for submit_bh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BhIoType {
    /// Read from device into buffer.
    Read,
    /// Write from buffer to device.
    Write,
}

// ── Buffer head manager ──────────────────────────────────────────────────────

/// The buffer head manager.
///
/// Provides getblk/bread/bwrite/brelse operations and LRU-based
/// buffer recycling.
pub struct BufferHeadManager {
    /// Buffer head pool.
    buffers: [BufferHead; MAX_BUFFER_HEADS],
    /// Per-page buffer lists.
    page_lists: [PageBufferList; MAX_PAGE_LISTS],
    /// LRU list head (index into buffers).
    lru_head: u32,
    /// LRU list tail.
    lru_tail: u32,
    /// Default block size.
    default_block_size: usize,
    /// Cumulative statistics.
    stats: BufferHeadStats,
}

impl BufferHeadManager {
    /// Create a new buffer head manager.
    pub fn new() -> Self {
        Self {
            buffers: [const { BufferHead::empty() }; MAX_BUFFER_HEADS],
            page_lists: [const { PageBufferList::empty() }; MAX_PAGE_LISTS],
            lru_head: NONE_IDX,
            lru_tail: NONE_IDX,
            default_block_size: DEFAULT_BLOCK_SIZE,
            stats: BufferHeadStats::new(),
        }
    }

    /// Set the default block size for new buffers.
    pub fn set_block_size(&mut self, size: usize) -> Result<()> {
        if size < MIN_BLOCK_SIZE || size > MAX_BLOCK_SIZE || !size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        self.default_block_size = size;
        Ok(())
    }

    // ── getblk ───────────────────────────────────────────────────────────

    /// Find or create a buffer for a given (device, block_nr).
    ///
    /// If the buffer already exists in the cache, its reference count
    /// is incremented.  Otherwise a new buffer is allocated.
    /// Returns the buffer index.
    pub fn getblk(&mut self, device_id: u32, block_nr: u64) -> Result<usize> {
        self.stats.getblk_calls += 1;

        // Search for existing buffer.
        for (idx, bh) in self.buffers.iter_mut().enumerate() {
            if bh.in_use && bh.device_id == device_id && bh.block_nr == block_nr {
                bh.ref_count = bh.ref_count.saturating_add(1);
                if bh.state.on_lru {
                    self.lru_remove_buffer(idx);
                }
                self.stats.getblk_hits += 1;
                return Ok(idx);
            }
        }

        // Allocate new buffer.
        let idx = self.alloc_buffer()?;
        let bh = &mut self.buffers[idx];
        bh.block_nr = block_nr;
        bh.device_id = device_id;
        bh.block_size = self.default_block_size as u32;
        bh.state = BhState::new();
        bh.state.new = true;
        bh.ref_count = 1;
        bh.data = [0; PAGE_SIZE];
        bh.data_len = self.default_block_size;
        bh.page_list = NONE_IDX;
        bh.page_next = NONE_IDX;
        bh.in_use = true;

        self.stats.buffers_active += 1;
        Ok(idx)
    }

    // ── bread ────────────────────────────────────────────────────────────

    /// Read a block synchronously.
    ///
    /// Gets the buffer (via getblk) and if it is not uptodate,
    /// simulates reading from the device.  In a real kernel this
    /// would submit an I/O request and wait for completion.
    /// Returns the buffer index.
    pub fn bread(&mut self, device_id: u32, block_nr: u64) -> Result<usize> {
        self.stats.bread_calls += 1;
        let idx = self.getblk(device_id, block_nr)?;

        if !self.buffers[idx].state.uptodate {
            // Simulate read: mark as uptodate.
            self.buffers[idx].state.locked = true;
            self.stats.locked_buffers += 1;

            // In a real implementation, this would submit I/O and wait.
            // Here we simulate completion.
            self.buffers[idx].state.uptodate = true;
            self.buffers[idx].state.mapped = true;
            self.buffers[idx].state.locked = false;
            self.stats.locked_buffers = self.stats.locked_buffers.saturating_sub(1);
        }

        Ok(idx)
    }

    /// Read a full page worth of blocks.
    ///
    /// Reads all blocks that make up one page, creating a per-page
    /// buffer list.  Returns the page list index.
    pub fn block_read_full_page(&mut self, device_id: u32, page_index: u64) -> Result<usize> {
        let blocks_per_page = PAGE_SIZE / self.default_block_size;
        let first_block = page_index * blocks_per_page as u64;

        // Allocate or find page list.
        let pl_idx = self.get_or_alloc_page_list(device_id, page_index)?;

        for i in 0..blocks_per_page {
            let block_nr = first_block + i as u64;
            let bh_idx = self.bread(device_id, block_nr)?;

            // Link to page list.
            let bh = &mut self.buffers[bh_idx];
            bh.page_list = pl_idx as u32;
            bh.page_next = self.page_lists[pl_idx].head;
            self.page_lists[pl_idx].head = bh_idx as u32;
            self.page_lists[pl_idx].buffer_count += 1;
        }

        Ok(pl_idx)
    }

    // ── bwrite ───────────────────────────────────────────────────────────

    /// Write a buffer's contents to the device.
    ///
    /// Marks the buffer as no longer dirty after successful write.
    pub fn bwrite(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }

        let bh = &mut self.buffers[idx];
        if !bh.state.dirty {
            return Ok(()); // Nothing to write.
        }
        if bh.state.locked {
            return Err(Error::Busy);
        }

        bh.state.locked = true;
        self.stats.locked_buffers += 1;

        // Simulate write completion.
        bh.state.dirty = false;
        bh.state.async_write = false;
        bh.state.locked = false;
        self.stats.locked_buffers = self.stats.locked_buffers.saturating_sub(1);
        self.stats.dirty_buffers = self.stats.dirty_buffers.saturating_sub(1);
        self.stats.bwrite_calls += 1;

        Ok(())
    }

    // ── brelse ───────────────────────────────────────────────────────────

    /// Release a reference to a buffer.
    ///
    /// When the reference count drops to zero, the buffer is moved
    /// to the LRU list for potential reclamation.
    pub fn brelse(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }

        self.stats.brelse_calls += 1;

        let bh = &mut self.buffers[idx];
        if bh.ref_count == 0 {
            return Ok(());
        }

        bh.ref_count -= 1;
        if bh.ref_count == 0 {
            // Move to LRU.
            self.lru_push(idx);
        }

        Ok(())
    }

    // ── sync_dirty_buffer ────────────────────────────────────────────────

    /// Synchronously write a dirty buffer and wait for completion.
    pub fn sync_dirty_buffer(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }
        self.stats.sync_writes += 1;
        self.bwrite(idx)
    }

    /// Sync all dirty buffers for a device.
    pub fn sync_device(&mut self, device_id: u32) -> Result<u32> {
        let mut synced = 0u32;
        for idx in 0..MAX_BUFFER_HEADS {
            if self.buffers[idx].in_use
                && self.buffers[idx].device_id == device_id
                && self.buffers[idx].state.dirty
            {
                self.bwrite(idx)?;
                synced += 1;
            }
        }
        Ok(synced)
    }

    // ── submit_bh ────────────────────────────────────────────────────────

    /// Submit a buffer for asynchronous I/O.
    ///
    /// Sets the appropriate async flag and locks the buffer.
    pub fn submit_bh(&mut self, idx: usize, io_type: BhIoType) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }

        let bh = &mut self.buffers[idx];
        if bh.state.locked {
            return Err(Error::Busy);
        }

        bh.state.locked = true;
        self.stats.locked_buffers += 1;

        match io_type {
            BhIoType::Read => {
                bh.state.async_read = true;
            }
            BhIoType::Write => {
                bh.state.async_write = true;
            }
        }

        Ok(())
    }

    /// Complete an asynchronous I/O operation.
    pub fn end_buffer_io(&mut self, idx: usize, uptodate: bool) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }

        let bh = &mut self.buffers[idx];
        bh.state.locked = false;
        self.stats.locked_buffers = self.stats.locked_buffers.saturating_sub(1);

        if bh.state.async_read {
            bh.state.async_read = false;
            if uptodate {
                bh.state.uptodate = true;
                bh.state.mapped = true;
            }
        }
        if bh.state.async_write {
            bh.state.async_write = false;
            if uptodate {
                bh.state.dirty = false;
                self.stats.dirty_buffers = self.stats.dirty_buffers.saturating_sub(1);
            }
        }

        Ok(())
    }

    // ── Dirty marking ────────────────────────────────────────────────────

    /// Mark a buffer as dirty.
    pub fn mark_dirty(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }
        if !self.buffers[idx].state.dirty {
            self.buffers[idx].state.dirty = true;
            self.stats.dirty_buffers += 1;
        }
        Ok(())
    }

    /// Clear the dirty flag on a buffer.
    pub fn clear_dirty(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }
        if self.buffers[idx].state.dirty {
            self.buffers[idx].state.dirty = false;
            self.stats.dirty_buffers = self.stats.dirty_buffers.saturating_sub(1);
        }
        Ok(())
    }

    // ── Data access ──────────────────────────────────────────────────────

    /// Read data from a buffer into the provided slice.
    ///
    /// `offset` is relative to the start of the block.
    pub fn read_buffer(&self, idx: usize, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }
        let bh = &self.buffers[idx];
        if !bh.state.uptodate {
            return Err(Error::IoError);
        }
        if offset >= bh.data_len {
            return Ok(0);
        }
        let available = bh.data_len - offset;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&bh.data[offset..offset + to_copy]);
        Ok(to_copy)
    }

    /// Write data into a buffer from the provided slice.
    ///
    /// `offset` is relative to the start of the block.
    /// The buffer is automatically marked dirty.
    pub fn write_buffer(&mut self, idx: usize, offset: usize, data: &[u8]) -> Result<usize> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }
        let bh = &mut self.buffers[idx];
        if bh.state.locked {
            return Err(Error::Busy);
        }
        if offset >= bh.data_len {
            return Ok(0);
        }
        let available = bh.data_len - offset;
        let to_copy = data.len().min(available);
        bh.data[offset..offset + to_copy].copy_from_slice(&data[..to_copy]);

        if !bh.state.dirty {
            bh.state.dirty = true;
            self.stats.dirty_buffers += 1;
        }
        bh.state.uptodate = true;

        Ok(to_copy)
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Return the state of a buffer.
    pub fn buffer_state(&self, idx: usize) -> Result<BhState> {
        if idx >= MAX_BUFFER_HEADS || !self.buffers[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(self.buffers[idx].state)
    }

    /// Return statistics.
    pub fn stats(&self) -> BufferHeadStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = BufferHeadStats::new();
    }

    // ── Internal: allocation ─────────────────────────────────────────────

    /// Allocate a free buffer slot, reclaiming from LRU if needed.
    fn alloc_buffer(&mut self) -> Result<usize> {
        // Try to find a free slot.
        if let Some(idx) = self.buffers.iter().position(|b| !b.in_use) {
            return Ok(idx);
        }

        // Reclaim from LRU.
        self.reclaim_lru()
    }

    /// Reclaim a buffer from the LRU list.
    fn reclaim_lru(&mut self) -> Result<usize> {
        let mut idx = self.lru_tail;
        while idx != NONE_IDX {
            let i = idx as usize;
            if i >= MAX_BUFFER_HEADS {
                break;
            }
            let prev = self.buffers[i].lru_prev;

            if self.buffers[i].in_use
                && self.buffers[i].ref_count == 0
                && !self.buffers[i].state.dirty
                && !self.buffers[i].state.locked
            {
                self.lru_remove_buffer(i);
                self.buffers[i].in_use = false;
                self.stats.buffers_active = self.stats.buffers_active.saturating_sub(1);
                self.stats.lru_reclaims += 1;
                return Ok(i);
            }
            idx = prev;
        }
        Err(Error::OutOfMemory)
    }

    // ── Internal: LRU management ─────────────────────────────────────────

    /// Push a buffer to the LRU list head.
    fn lru_push(&mut self, idx: usize) {
        if self.buffers[idx].state.on_lru {
            return;
        }

        self.buffers[idx].state.on_lru = true;
        self.buffers[idx].lru_prev = NONE_IDX;
        self.buffers[idx].lru_next = self.lru_head;

        if self.lru_head != NONE_IDX {
            self.buffers[self.lru_head as usize].lru_prev = idx as u32;
        }
        self.lru_head = idx as u32;

        if self.lru_tail == NONE_IDX {
            self.lru_tail = idx as u32;
        }
    }

    /// Remove a buffer from the LRU list.
    fn lru_remove_buffer(&mut self, idx: usize) {
        if !self.buffers[idx].state.on_lru {
            return;
        }

        let prev = self.buffers[idx].lru_prev;
        let next = self.buffers[idx].lru_next;

        if prev != NONE_IDX {
            self.buffers[prev as usize].lru_next = next;
        } else {
            self.lru_head = next;
        }

        if next != NONE_IDX {
            self.buffers[next as usize].lru_prev = prev;
        } else {
            self.lru_tail = prev;
        }

        self.buffers[idx].lru_prev = NONE_IDX;
        self.buffers[idx].lru_next = NONE_IDX;
        self.buffers[idx].state.on_lru = false;
    }

    // ── Internal: page list management ───────────────────────────────────

    /// Find or allocate a per-page buffer list.
    fn get_or_alloc_page_list(&mut self, device_id: u32, page_index: u64) -> Result<usize> {
        // Search for existing.
        for (i, pl) in self.page_lists.iter().enumerate() {
            if pl.in_use && pl.device_id == device_id && pl.page_index == page_index {
                return Ok(i);
            }
        }

        // Allocate new.
        let idx = self
            .page_lists
            .iter()
            .position(|pl| !pl.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.page_lists[idx].page_index = page_index;
        self.page_lists[idx].device_id = device_id;
        self.page_lists[idx].head = NONE_IDX;
        self.page_lists[idx].buffer_count = 0;
        self.page_lists[idx].in_use = true;

        Ok(idx)
    }
}
