// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pipefs — internal pseudo-filesystem backing pipe file descriptors.
//!
//! Every `pipe(2)` system call creates two file descriptors that refer to
//! a single kernel pipe inode hosted on `pipefs`.  Unlike named FIFOs (which
//! live on a real filesystem), anonymous pipes never appear in any directory;
//! their sole representation is through file descriptors.
//!
//! # Design
//!
//! ```text
//! pipe(2)
//!   │
//!   └─► PipeFs::alloc_pipe()
//!           │
//!           ├─► PipeInode { ring: PipeBufRing, max_size: 65536 }
//!           │
//!           ├─► fd[0] = read end  (pipe_read)
//!           └─► fd[1] = write end (pipe_write)
//! ```
//!
//! Data flow within a pipe inode:
//!
//! ```text
//! write(fd[1], data) ──► pipe_write ──► PipeBufRing (scatter)
//!                                           ↑ ring of PipeBuffer pages
//! read(fd[0], buf) ──► pipe_read ──► PipeBufRing (gather)
//! ```
//!
//! # Zero-copy splice support
//!
//! [`splice_to_pipe`] and [`splice_from_pipe`] allow a filesystem page to be
//! transferred into / out of the pipe ring without a data copy.
//!
//! # References
//!
//! - Linux `fs/pipe.c`, `include/linux/pipe_fs_i.h`
//! - POSIX.1-2024 `pipe(2)`, `read(2)`, `write(2)` on FIFOs
//! - Linux `fs/splice.c` (splice helpers)

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic number for the pipefs superblock.
pub const PIPEFS_MAGIC: u32 = 0x5049_5045; // 'PIPE'

/// Size of a single pipe page buffer in bytes (one page).
pub const PIPE_PAGE_SIZE: usize = 4096;

/// Number of page slots in the pipe ring buffer (Linux default: 16 pages).
pub const PIPE_RING_SLOTS: usize = 16;

/// Default maximum pipe capacity in bytes (16 pages = 65536 bytes).
pub const PIPE_DEF_MAX_SIZE: usize = PIPE_PAGE_SIZE * PIPE_RING_SLOTS;

/// Maximum number of simultaneously active pipes system-wide.
const MAX_PIPES: usize = 256;

/// `FIONREAD` ioctl: return the number of bytes available to read.
pub const FIONREAD: u32 = 0x541B;

/// `F_GETPIPE_SZ` / `F_SETPIPE_SZ` (Linux fcntl commands).
pub const F_GETPIPE_SZ: u32 = 1032;
/// Set the pipe capacity (must be a multiple of `PIPE_PAGE_SIZE`).
pub const F_SETPIPE_SZ: u32 = 1031;

// ── PipeBufFlags ──────────────────────────────────────────────────────────────

/// Flags carried by a [`PipeBuffer`] slot.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeBufFlags(pub u32);

impl PipeBufFlags {
    /// Buffer was donated by the producer (used by splice).
    pub const CAN_MERGE: u32 = 0x01;
    /// Buffer is a reference to an existing page (no copy needed for splice).
    pub const GIFT: u32 = 0x02;
    /// Buffer was written atomically (whole write fits in one buffer).
    pub const WHOLE: u32 = 0x04;

    /// Returns `true` if writes may be merged into this buffer.
    pub fn can_merge(self) -> bool {
        self.0 & Self::CAN_MERGE != 0
    }

    /// Returns `true` if this buffer is a page reference (zero-copy eligible).
    pub fn is_gift(self) -> bool {
        self.0 & Self::GIFT != 0
    }
}

// ── PipeBuffer ────────────────────────────────────────────────────────────────

/// One page-sized buffer slot in the pipe ring.
///
/// Each slot owns a 4096-byte data page and tracks how much of it is occupied.
#[derive(Clone, Copy)]
pub struct PipeBuffer {
    /// Raw page data.
    pub page: [u8; PIPE_PAGE_SIZE],
    /// Byte offset of the first valid byte within `page`.
    pub offset: usize,
    /// Number of valid bytes starting at `offset`.
    pub len: usize,
    /// Modifier flags for this buffer.
    pub flags: PipeBufFlags,
}

impl PipeBuffer {
    /// Create an empty pipe buffer.
    pub const fn empty() -> Self {
        Self {
            page: [0u8; PIPE_PAGE_SIZE],
            offset: 0,
            len: 0,
            flags: PipeBufFlags(0),
        }
    }

    /// Return the bytes available for reading.
    pub fn readable(&self) -> &[u8] {
        &self.page[self.offset..self.offset + self.len]
    }

    /// Return the bytes available for writing (tail of the page).
    pub fn writable_tail(&self) -> usize {
        PIPE_PAGE_SIZE - (self.offset + self.len)
    }

    /// Returns `true` if this buffer has been fully consumed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if this buffer's page is fully occupied.
    pub fn is_full(&self) -> bool {
        self.offset + self.len == PIPE_PAGE_SIZE
    }
}

impl core::fmt::Debug for PipeBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeBuffer")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .field("flags", &self.flags)
            .finish()
    }
}

// ── PipeBufRing ───────────────────────────────────────────────────────────────

/// A circular ring of [`PipeBuffer`] slots, forming the pipe's data queue.
#[derive(Debug)]
pub struct PipeBufRing {
    /// Fixed-size array of page slots.
    pub bufs: [PipeBuffer; PIPE_RING_SLOTS],
    /// Index of the next slot to read from (consumer head).
    pub head: usize,
    /// Index of the next slot to write into (producer tail).
    pub tail: usize,
    /// Number of open readers (file descriptors at the read end).
    pub readers_count: u32,
    /// Number of open writers (file descriptors at the write end).
    pub writers_count: u32,
}

impl PipeBufRing {
    /// Create a new, empty pipe ring.
    pub const fn new() -> Self {
        Self {
            bufs: [const { PipeBuffer::empty() }; PIPE_RING_SLOTS],
            head: 0,
            tail: 0,
            readers_count: 1,
            writers_count: 1,
        }
    }

    /// Return the number of slots currently occupied (containing data).
    pub fn occupied(&self) -> usize {
        self.tail.wrapping_sub(self.head) % PIPE_RING_SLOTS
    }

    /// Return the number of free slots available for writing.
    pub fn free_slots(&self) -> usize {
        PIPE_RING_SLOTS - 1 - self.occupied()
    }

    /// Return `true` if there is no data in any buffer.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Return `true` if all slots are occupied.
    pub fn is_full(&self) -> bool {
        self.free_slots() == 0
    }

    /// Total bytes available to read across all occupied slots.
    pub fn bytes_readable(&self) -> usize {
        if self.head == self.tail {
            return 0;
        }
        let mut count = 0usize;
        let mut idx = self.head;
        while idx != self.tail {
            count += self.bufs[idx % PIPE_RING_SLOTS].len;
            idx = idx.wrapping_add(1);
        }
        count
    }
}

impl Default for PipeBufRing {
    fn default() -> Self {
        Self::new()
    }
}

// ── PipeInode ─────────────────────────────────────────────────────────────────

/// The kernel inode backing a single anonymous pipe.
pub struct PipeInode {
    /// Circular buffer ring.
    pub ring: PipeBufRing,
    /// Maximum capacity of the pipe in bytes (default: `PIPE_DEF_MAX_SIZE`).
    pub max_size: usize,
    /// Pipe-level flags (O_DIRECT, etc.).
    pub flags: u32,
    /// Whether async notification (fasync) is active on this pipe.
    pub fasync: bool,
    /// Whether this slot is occupied in the pool.
    in_use: bool,
}

impl PipeInode {
    /// Create an empty (unused) pipe inode slot.
    pub const fn empty() -> Self {
        Self {
            ring: PipeBufRing::new(),
            max_size: PIPE_DEF_MAX_SIZE,
            flags: 0,
            fasync: false,
            in_use: false,
        }
    }

    /// Returns `true` if any writer is still attached.
    pub fn has_writers(&self) -> bool {
        self.ring.writers_count > 0
    }

    /// Returns `true` if any reader is still attached.
    pub fn has_readers(&self) -> bool {
        self.ring.readers_count > 0
    }
}

impl core::fmt::Debug for PipeInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeInode")
            .field("max_size", &self.max_size)
            .field("flags", &self.flags)
            .field("fasync", &self.fasync)
            .field("in_use", &self.in_use)
            .finish()
    }
}

// ── PipeFsSuper ───────────────────────────────────────────────────────────────

/// Superblock for the pipefs pseudo-filesystem.
#[derive(Debug, Clone, Copy)]
pub struct PipeFsSuper {
    /// Filesystem magic number.
    pub magic: u32,
    /// Total number of pipe inodes created since boot.
    pub total_created: u64,
}

impl PipeFsSuper {
    /// Create a new pipefs superblock.
    pub const fn new() -> Self {
        Self {
            magic: PIPEFS_MAGIC,
            total_created: 0,
        }
    }
}

impl Default for PipeFsSuper {
    fn default() -> Self {
        Self::new()
    }
}

// ── PipeFsStats ───────────────────────────────────────────────────────────────

/// Runtime statistics for the pipefs subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeFsStats {
    /// Total pipes created since boot.
    pub total_created: u64,
    /// Total pipes destroyed since boot.
    pub total_destroyed: u64,
    /// Number of pipes currently active.
    pub current_active: u64,
    /// Total bytes transferred through all pipes since boot.
    pub bytes_transferred: u64,
}

// ── PipeFs ────────────────────────────────────────────────────────────────────

/// The pipefs subsystem: manages the pool of kernel pipe inodes.
pub struct PipeFs {
    /// Superblock metadata.
    pub superblock: PipeFsSuper,
    /// Fixed pool of pipe inode slots.
    pipes: [PipeInode; MAX_PIPES],
    /// Operational statistics.
    pub stats: PipeFsStats,
}

impl PipeFs {
    /// Create a new pipefs instance.
    pub const fn new() -> Self {
        Self {
            superblock: PipeFsSuper::new(),
            pipes: [const { PipeInode::empty() }; MAX_PIPES],
            stats: PipeFsStats {
                total_created: 0,
                total_destroyed: 0,
                current_active: 0,
                bytes_transferred: 0,
            },
        }
    }

    /// Allocate a new pipe inode.
    ///
    /// Returns the slot index (used as a handle for subsequent operations).
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — pool is exhausted.
    pub fn alloc_pipe(&mut self) -> Result<usize> {
        let slot = self
            .pipes
            .iter()
            .position(|p| !p.in_use)
            .ok_or(Error::OutOfMemory)?;
        let pipe = &mut self.pipes[slot];
        *pipe = PipeInode::empty();
        pipe.in_use = true;
        self.superblock.total_created += 1;
        self.stats.total_created += 1;
        self.stats.current_active += 1;
        Ok(slot)
    }

    /// Free a pipe inode at `slot`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — slot is not in use.
    pub fn free_pipe(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PIPES {
            return Err(Error::InvalidArgument);
        }
        let pipe = &mut self.pipes[slot];
        if !pipe.in_use {
            return Err(Error::NotFound);
        }
        pipe.in_use = false;
        self.stats.total_destroyed += 1;
        self.stats.current_active = self.stats.current_active.saturating_sub(1);
        Ok(())
    }

    /// Borrow a shared reference to the pipe at `slot`.
    pub fn get(&self, slot: usize) -> Option<&PipeInode> {
        self.pipes.get(slot).filter(|p| p.in_use)
    }

    /// Borrow a mutable reference to the pipe at `slot`.
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut PipeInode> {
        let pipe = self.pipes.get_mut(slot)?;
        if pipe.in_use { Some(pipe) } else { None }
    }
}

impl Default for PipeFs {
    fn default() -> Self {
        Self::new()
    }
}

// ── pipe_read ─────────────────────────────────────────────────────────────────

/// Read up to `buf.len()` bytes from the pipe at `slot`.
///
/// Data is gathered from the head of the ring buffer.  Returns the number of
/// bytes actually read.
///
/// # Errors
///
/// - [`Error::WouldBlock`] — pipe is empty but writers are still attached.
/// - [`Error::NotFound`] — invalid slot.
pub fn pipe_read(fs: &mut PipeFs, slot: usize, buf: &mut [u8]) -> Result<usize> {
    let pipe = fs.get_mut(slot).ok_or(Error::NotFound)?;
    if pipe.ring.is_empty() {
        if pipe.has_writers() {
            return Err(Error::WouldBlock);
        }
        return Ok(0); // EOF — all writers closed
    }
    let mut read = 0usize;
    while read < buf.len() {
        if pipe.ring.head == pipe.ring.tail {
            break;
        }
        let slot_idx = pipe.ring.head % PIPE_RING_SLOTS;
        let pbuf = &mut pipe.ring.bufs[slot_idx];
        if pbuf.is_empty() {
            pipe.ring.head = pipe.ring.head.wrapping_add(1);
            continue;
        }
        let readable = pbuf.len.min(buf.len() - read);
        buf[read..read + readable].copy_from_slice(&pbuf.page[pbuf.offset..pbuf.offset + readable]);
        pbuf.offset += readable;
        pbuf.len -= readable;
        read += readable;
        if pbuf.is_empty() {
            // Slot fully consumed — advance head.
            *pbuf = PipeBuffer::empty();
            pipe.ring.head = pipe.ring.head.wrapping_add(1);
        }
    }
    fs.stats.bytes_transferred += read as u64;
    Ok(read)
}

// ── pipe_write ────────────────────────────────────────────────────────────────

/// Write up to `data.len()` bytes into the pipe at `slot`.
///
/// Data is scattered into the tail of the ring buffer.  Returns the number of
/// bytes actually written.
///
/// # Errors
///
/// - [`Error::IoError`] — broken pipe (no readers remain).
/// - [`Error::WouldBlock`] — pipe is full and non-blocking flag is set.
/// - [`Error::NotFound`] — invalid slot.
pub fn pipe_write(fs: &mut PipeFs, slot: usize, data: &[u8]) -> Result<usize> {
    {
        let pipe = fs.get(slot).ok_or(Error::NotFound)?;
        if !pipe.has_readers() {
            return Err(Error::IoError); // EPIPE / broken pipe
        }
        if pipe.ring.is_full() {
            return Err(Error::WouldBlock);
        }
    }
    let mut written = 0usize;
    while written < data.len() {
        let pipe = fs.get_mut(slot).ok_or(Error::NotFound)?;
        if pipe.ring.is_full() {
            break;
        }
        let tail_slot = pipe.ring.tail % PIPE_RING_SLOTS;
        let pbuf = &mut pipe.ring.bufs[tail_slot];
        // Try to append to the current tail buffer if space remains.
        if !pbuf.is_full() && pbuf.len > 0 {
            let tail_space = pbuf.writable_tail();
            let to_write = tail_space.min(data.len() - written);
            let write_start = pbuf.offset + pbuf.len;
            pbuf.page[write_start..write_start + to_write]
                .copy_from_slice(&data[written..written + to_write]);
            pbuf.len += to_write;
            written += to_write;
        } else if pbuf.is_empty() {
            // Fresh slot — fill from the beginning.
            let to_write = PIPE_PAGE_SIZE.min(data.len() - written);
            pbuf.page[..to_write].copy_from_slice(&data[written..written + to_write]);
            pbuf.offset = 0;
            pbuf.len = to_write;
            written += to_write;
            pipe.ring.tail = pipe.ring.tail.wrapping_add(1);
        } else {
            // Current tail is full — advance to a new slot.
            pipe.ring.tail = pipe.ring.tail.wrapping_add(1);
        }
    }
    fs.stats.bytes_transferred += written as u64;
    Ok(written)
}

// ── pipe_poll ─────────────────────────────────────────────────────────────────

/// Poll events available on the pipe at `slot`.
///
/// Returns a bitmask:
/// - bit 0 (`POLLIN`)  — data available to read.
/// - bit 2 (`POLLOUT`) — space available to write.
/// - bit 4 (`POLLHUP`) — write end has been closed (EOF condition).
///
/// # Errors
///
/// - [`Error::NotFound`] — invalid slot.
pub fn pipe_poll(fs: &PipeFs, slot: usize) -> Result<u32> {
    let pipe = fs.get(slot).ok_or(Error::NotFound)?;
    let mut events = 0u32;
    if !pipe.ring.is_empty() {
        events |= 0x01; // POLLIN
    }
    if !pipe.ring.is_full() {
        events |= 0x04; // POLLOUT
    }
    if !pipe.has_writers() {
        events |= 0x10; // POLLHUP
    }
    Ok(events)
}

// ── pipe_ioctl ────────────────────────────────────────────────────────────────

/// Handle pipe-specific `ioctl(2)` commands.
///
/// Supported commands:
/// - `FIONREAD` — return bytes available to read.
/// - `F_GETPIPE_SZ` — return current maximum pipe capacity.
/// - `F_SETPIPE_SZ` — set maximum pipe capacity (must be >= current data, rounded to page).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown command or invalid argument.
/// - [`Error::NotFound`] — invalid slot.
pub fn pipe_ioctl(fs: &mut PipeFs, slot: usize, cmd: u32, arg: usize) -> Result<usize> {
    if slot >= MAX_PIPES {
        return Err(Error::InvalidArgument);
    }
    match cmd {
        FIONREAD => {
            let pipe = fs.get(slot).ok_or(Error::NotFound)?;
            Ok(pipe.ring.bytes_readable())
        }
        F_GETPIPE_SZ => {
            let pipe = fs.get(slot).ok_or(Error::NotFound)?;
            Ok(pipe.max_size)
        }
        F_SETPIPE_SZ => {
            // Round up to nearest page.
            let requested = arg;
            if requested == 0 {
                return Err(Error::InvalidArgument);
            }
            let aligned = requested.saturating_add(PIPE_PAGE_SIZE - 1) & !(PIPE_PAGE_SIZE - 1);
            let pipe = fs.get_mut(slot).ok_or(Error::NotFound)?;
            let current_data = pipe.ring.bytes_readable();
            if aligned < current_data {
                return Err(Error::InvalidArgument); // can't shrink below existing data
            }
            pipe.max_size = aligned;
            Ok(aligned)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ── pipe_release ──────────────────────────────────────────────────────────────

/// Close one end of a pipe.
///
/// `is_writer` indicates whether the write end is being closed.  When all
/// readers or writers are gone the corresponding count is decremented.  When
/// both counts reach zero the pipe inode is freed.
///
/// # Errors
///
/// - [`Error::NotFound`] — invalid slot.
pub fn pipe_release(fs: &mut PipeFs, slot: usize, is_writer: bool) -> Result<()> {
    if slot >= MAX_PIPES {
        return Err(Error::InvalidArgument);
    }
    {
        let pipe = fs.get_mut(slot).ok_or(Error::NotFound)?;
        if is_writer {
            pipe.ring.writers_count = pipe.ring.writers_count.saturating_sub(1);
        } else {
            pipe.ring.readers_count = pipe.ring.readers_count.saturating_sub(1);
        }
        if pipe.ring.readers_count > 0 || pipe.ring.writers_count > 0 {
            return Ok(());
        }
    }
    // Both ends closed — free the inode.
    fs.free_pipe(slot)
}

// ── Splice helpers ────────────────────────────────────────────────────────────

/// Copy `data` into the pipe ring at `slot`, simulating a zero-copy page gift.
///
/// In a real kernel implementation the page would be referenced rather than
/// copied.  Here we copy the bytes and set the [`PipeBufFlags::GIFT`] flag to
/// indicate the transfer origin.
///
/// Returns the number of bytes transferred.
pub fn splice_to_pipe(fs: &mut PipeFs, slot: usize, data: &[u8]) -> Result<usize> {
    {
        let pipe = fs.get(slot).ok_or(Error::NotFound)?;
        if !pipe.has_readers() {
            return Err(Error::IoError);
        }
        if pipe.ring.is_full() {
            return Err(Error::WouldBlock);
        }
    }
    let transferred = pipe_write(fs, slot, data)?;
    // Mark the last-written buffer as a gift (page reference in real kernel).
    if let Some(pipe) = fs.get_mut(slot) {
        let prev_tail = pipe.ring.tail.wrapping_sub(1) % PIPE_RING_SLOTS;
        pipe.ring.bufs[prev_tail].flags.0 |= PipeBufFlags::GIFT;
    }
    Ok(transferred)
}

/// Read data out of the pipe at `slot` into `buf`, marking the transfer as a
/// splice-from operation.
///
/// Returns the number of bytes transferred.
pub fn splice_from_pipe(fs: &mut PipeFs, slot: usize, buf: &mut [u8]) -> Result<usize> {
    pipe_read(fs, slot, buf)
}
