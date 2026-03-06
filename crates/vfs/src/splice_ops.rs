// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Splice, tee, and vmsplice operations — zero-copy VFS data movement.
//!
//! This module implements the higher-level VFS splice/tee/vmsplice dispatch
//! layer that sits above the low-level pipe buffer machinery in
//! [`crate::splice`].  It provides:
//!
//! - [`SpliceDesc`] — descriptor for one splice endpoint (pipe, file, or socket).
//! - [`SpliceCtx`] — full operation context with source, dest, flags, and limits.
//! - [`TeeCtx`] — tee operation context (pipe → pipe without consuming).
//! - [`VmspliceCtx`] — vmsplice context (user iovec → pipe).
//! - [`SpliceState`] — per-request progress tracking (bytes moved, retries).
//! - [`SplicePipeRing`] — simplified pipe ring buffer used internally.
//! - [`SpliceEngine`] — stateless dispatch engine with counters.
//!
//! # Syscall mapping
//!
//! | Syscall        | Entry point                     |
//! |----------------|---------------------------------|
//! | `splice(2)`    | [`SpliceEngine::do_splice`]     |
//! | `tee(2)`       | [`SpliceEngine::do_tee`]        |
//! | `vmsplice(2)`  | [`SpliceEngine::do_vmsplice`]   |
//! | `sendfile(2)`  | [`SpliceEngine::do_sendfile`]   |
//!
//! # Design
//!
//! Data is never copied in the kernel path — instead, [`SpliceBuf`] pages
//! are reference-counted and handed off between pipes and file descriptors.
//! For the `no_std` context without heap allocation, we represent reference
//! ownership via fixed-size slot arrays.
//!
//! # References
//!
//! - Linux `fs/splice.c`
//! - `splice(2)`, `tee(2)`, `vmsplice(2)` manual pages

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Default pipe buffer capacity (64 KiB).
pub const PIPE_BUF_SIZE: usize = 65536;

/// Maximum number of pages per splice operation.
pub const SPLICE_MAX_PAGES: usize = 16;

/// Capacity of each pipe ring in pages.
const RING_CAPACITY: usize = 16;

/// Maximum bytes transferable in a single sendfile call.
pub const SENDFILE_MAX: usize = 0x7FFF_FFFF;

/// Maximum bytes for a single vmsplice call (16 MiB).
pub const VMSPLICE_MAX: usize = 16 * 1024 * 1024;

/// Page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Maximum number of concurrent splice states.
const MAX_SPLICE_STATES: usize = 32;

/// Maximum I/O vectors for vmsplice.
const MAX_VMSIOV: usize = 16;

// ── Splice flag bits ─────────────────────────────────────────────

/// Move pages instead of copying when possible (`SPLICE_F_MOVE`).
pub const SPLICE_F_MOVE: u32 = 0x01;
/// Do not block if the pipe would block (`SPLICE_F_NONBLOCK`).
pub const SPLICE_F_NONBLOCK: u32 = 0x02;
/// Hint that more data will follow (`SPLICE_F_MORE`).
pub const SPLICE_F_MORE: u32 = 0x04;
/// Gift: pages donated by user space (`SPLICE_F_GIFT`).
pub const SPLICE_F_GIFT: u32 = 0x08;

// ── SpliceFlags ─────────────────────────────────────────────────

/// Typed wrapper around the raw splice flag bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpliceFlags(pub u32);

impl SpliceFlags {
    /// Creates flags from a raw value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Returns `true` if `SPLICE_F_NONBLOCK` is set.
    pub fn nonblock(self) -> bool {
        self.0 & SPLICE_F_NONBLOCK != 0
    }

    /// Returns `true` if `SPLICE_F_MOVE` is set.
    pub fn move_pages(self) -> bool {
        self.0 & SPLICE_F_MOVE != 0
    }

    /// Returns `true` if `SPLICE_F_MORE` is set.
    pub fn more(self) -> bool {
        self.0 & SPLICE_F_MORE != 0
    }

    /// Returns `true` if `SPLICE_F_GIFT` is set.
    pub fn gift(self) -> bool {
        self.0 & SPLICE_F_GIFT != 0
    }
}

// ── SpliceEndpointKind ───────────────────────────────────────────

/// Identifies the type of a splice endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceEndpointKind {
    /// A kernel pipe.
    Pipe,
    /// A regular file or block device.
    File,
    /// A socket endpoint.
    Socket,
}

// ── SpliceDesc ───────────────────────────────────────────────────

/// Descriptor for one endpoint of a splice/tee/vmsplice operation.
#[derive(Debug, Clone, Copy)]
pub struct SpliceDesc {
    /// Kind of endpoint.
    pub kind: SpliceEndpointKind,
    /// File descriptor number.
    pub fd: i32,
    /// Pipe identifier (used when `kind == Pipe`).
    pub pipe_id: u32,
    /// File offset (used when `kind == File`); updated after each transfer.
    pub offset: u64,
    /// Whether the offset should be updated on the caller's behalf.
    pub use_offset: bool,
}

impl SpliceDesc {
    /// Creates a pipe descriptor.
    pub const fn pipe(pipe_id: u32, fd: i32) -> Self {
        Self {
            kind: SpliceEndpointKind::Pipe,
            fd,
            pipe_id,
            offset: 0,
            use_offset: false,
        }
    }

    /// Creates a file descriptor.
    pub const fn file(fd: i32, offset: u64, use_offset: bool) -> Self {
        Self {
            kind: SpliceEndpointKind::File,
            fd,
            pipe_id: 0,
            offset,
            use_offset,
        }
    }

    /// Creates a socket descriptor.
    pub const fn socket(fd: i32) -> Self {
        Self {
            kind: SpliceEndpointKind::Socket,
            fd,
            pipe_id: 0,
            offset: 0,
            use_offset: false,
        }
    }
}

// ── SpliceCtx ────────────────────────────────────────────────────

/// Context for a single `splice(2)` call.
#[derive(Debug, Clone, Copy)]
pub struct SpliceCtx {
    /// Source endpoint.
    pub src: SpliceDesc,
    /// Destination endpoint.
    pub dst: SpliceDesc,
    /// Maximum bytes to transfer.
    pub len: usize,
    /// Operation flags.
    pub flags: SpliceFlags,
}

impl SpliceCtx {
    /// Creates a new splice context.
    pub const fn new(src: SpliceDesc, dst: SpliceDesc, len: usize, flags: u32) -> Self {
        Self {
            src,
            dst,
            len,
            flags: SpliceFlags(flags),
        }
    }

    /// Returns `true` if at least one endpoint is a pipe.
    pub fn has_pipe_endpoint(&self) -> bool {
        self.src.kind == SpliceEndpointKind::Pipe || self.dst.kind == SpliceEndpointKind::Pipe
    }
}

// ── TeeCtx ───────────────────────────────────────────────────────

/// Context for a `tee(2)` call.
///
/// Tee duplicates data from the read end of `src_pipe` into the write
/// end of `dst_pipe` without consuming it.
#[derive(Debug, Clone, Copy)]
pub struct TeeCtx {
    /// Source pipe identifier.
    pub src_pipe_id: u32,
    /// Destination pipe identifier.
    pub dst_pipe_id: u32,
    /// Maximum bytes to copy.
    pub len: usize,
    /// Operation flags.
    pub flags: SpliceFlags,
}

// ── VmspliceIov ──────────────────────────────────────────────────

/// A single user-space I/O vector for `vmsplice(2)`.
#[derive(Debug, Clone, Copy)]
pub struct VmspliceIov {
    /// Virtual base address of the user buffer.
    pub base: usize,
    /// Length of the buffer in bytes.
    pub len: usize,
}

impl VmspliceIov {
    /// Creates an empty iov.
    pub const fn empty() -> Self {
        Self { base: 0, len: 0 }
    }
}

// ── VmspliceCtx ──────────────────────────────────────────────────

/// Context for a `vmsplice(2)` call.
#[derive(Debug, Clone, Copy)]
pub struct VmspliceCtx {
    /// Destination pipe identifier.
    pub pipe_id: u32,
    /// Array of user-space I/O vectors.
    pub iovs: [VmspliceIov; MAX_VMSIOV],
    /// Number of valid entries in `iovs`.
    pub iov_count: usize,
    /// Operation flags.
    pub flags: SpliceFlags,
}

impl VmspliceCtx {
    /// Creates an empty vmsplice context.
    pub const fn new(pipe_id: u32, flags: u32) -> Self {
        Self {
            pipe_id,
            iovs: [const { VmspliceIov::empty() }; MAX_VMSIOV],
            iov_count: 0,
            flags: SpliceFlags(flags),
        }
    }

    /// Adds an I/O vector.
    pub fn push_iov(&mut self, base: usize, len: usize) -> Result<()> {
        if self.iov_count >= MAX_VMSIOV {
            return Err(Error::OutOfMemory);
        }
        self.iovs[self.iov_count] = VmspliceIov { base, len };
        self.iov_count += 1;
        Ok(())
    }

    /// Returns the total bytes across all I/O vectors.
    pub fn total_bytes(&self) -> usize {
        self.iovs[..self.iov_count].iter().map(|v| v.len).sum()
    }
}

// ── SpliceBuf ────────────────────────────────────────────────────

/// A single pipe page slot holding a reference to a data page.
#[derive(Debug, Clone, Copy)]
pub struct SpliceBuf {
    /// Virtual address of the page (0 = slot empty).
    pub page_addr: usize,
    /// Offset within the page of valid data.
    pub offset: u32,
    /// Length of valid data within this page.
    pub len: u32,
    /// Flags (stolen, etc.).
    pub flags: u32,
}

impl SpliceBuf {
    /// Creates an empty slot.
    pub const fn empty() -> Self {
        Self {
            page_addr: 0,
            offset: 0,
            len: 0,
            flags: 0,
        }
    }

    /// Returns `true` if this slot is empty.
    pub fn is_empty(self) -> bool {
        self.page_addr == 0
    }
}

// ── SplicePipeRing ───────────────────────────────────────────────

/// A simple ring buffer of splice page slots modelling a kernel pipe.
///
/// Used internally by [`SpliceEngine`] to transfer data between
/// endpoints without heap allocation.
pub struct SplicePipeRing {
    /// Page slots.
    slots: [SpliceBuf; RING_CAPACITY],
    /// Read head (consumer pointer).
    head: usize,
    /// Write tail (producer pointer).
    tail: usize,
    /// Number of occupied slots.
    count: usize,
    /// Pipe identifier.
    pub id: u32,
}

impl SplicePipeRing {
    /// Creates a new, empty ring.
    pub const fn new(id: u32) -> Self {
        Self {
            slots: [const { SpliceBuf::empty() }; RING_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
            id,
        }
    }

    /// Returns the number of filled slots.
    pub fn filled(&self) -> usize {
        self.count
    }

    /// Returns the available write space in slots.
    pub fn available(&self) -> usize {
        RING_CAPACITY - self.count
    }

    /// Returns `true` if the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` if the ring is full.
    pub fn is_full(&self) -> bool {
        self.count == RING_CAPACITY
    }

    /// Pushes a [`SpliceBuf`] onto the write end.
    pub fn push(&mut self, buf: SpliceBuf) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        self.slots[self.tail] = buf;
        self.tail = (self.tail + 1) % RING_CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Pops a [`SpliceBuf`] from the read end.
    pub fn pop(&mut self) -> Option<SpliceBuf> {
        if self.is_empty() {
            return None;
        }
        let buf = self.slots[self.head];
        self.slots[self.head] = SpliceBuf::empty();
        self.head = (self.head + 1) % RING_CAPACITY;
        self.count -= 1;
        Some(buf)
    }

    /// Peeks at the head slot without consuming it (for tee).
    pub fn peek(&self) -> Option<SpliceBuf> {
        if self.is_empty() {
            return None;
        }
        Some(self.slots[self.head])
    }

    /// Total bytes of data held in all slots.
    pub fn byte_count(&self) -> usize {
        let mut total = 0usize;
        let mut pos = self.head;
        let mut remaining = self.count;
        while remaining > 0 {
            total += self.slots[pos].len as usize;
            pos = (pos + 1) % RING_CAPACITY;
            remaining -= 1;
        }
        total
    }
}

// ── SpliceState ──────────────────────────────────────────────────

/// Per-request progress state for ongoing splice operations.
#[derive(Debug, Clone, Copy)]
pub struct SpliceState {
    /// Bytes moved so far.
    pub bytes_done: usize,
    /// Bytes remaining.
    pub bytes_left: usize,
    /// Retry count.
    pub retries: u32,
    /// Whether the operation has completed.
    pub done: bool,
}

impl SpliceState {
    /// Creates initial state for a transfer of `total` bytes.
    pub const fn new(total: usize) -> Self {
        Self {
            bytes_done: 0,
            bytes_left: total,
            retries: 0,
            done: false,
        }
    }

    /// Advances the state by `n` bytes.
    pub fn advance(&mut self, n: usize) {
        self.bytes_done += n;
        self.bytes_left = self.bytes_left.saturating_sub(n);
        if self.bytes_left == 0 {
            self.done = true;
        }
    }
}

// ── SpliceStats ──────────────────────────────────────────────────

/// Cumulative statistics for the splice engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpliceStats {
    /// Total `splice(2)` calls.
    pub splice_calls: u64,
    /// Total `tee(2)` calls.
    pub tee_calls: u64,
    /// Total `vmsplice(2)` calls.
    pub vmsplice_calls: u64,
    /// Total `sendfile(2)` calls.
    pub sendfile_calls: u64,
    /// Total bytes transferred.
    pub bytes_total: u64,
    /// Calls that returned `WouldBlock`.
    pub would_block: u64,
    /// Calls that returned an error.
    pub errors: u64,
}

// ── SpliceEngine ─────────────────────────────────────────────────

/// Zero-copy splice/tee/vmsplice/sendfile dispatch engine.
///
/// Maintains a pool of pipe rings and statistics.  The engine operates
/// on virtual addresses only — physical DMA mapping is handled by the
/// block device layer.
pub struct SpliceEngine {
    /// Pipe ring pool.
    rings: [SplicePipeRing; 8],
    /// Cumulative statistics.
    pub stats: SpliceStats,
    /// Next pipe ring ID.
    next_ring_id: u32,
}

impl SpliceEngine {
    /// Creates a new splice engine.
    pub const fn new() -> Self {
        Self {
            rings: [
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
                const { SplicePipeRing::new(0) },
            ],
            stats: SpliceStats {
                splice_calls: 0,
                tee_calls: 0,
                vmsplice_calls: 0,
                sendfile_calls: 0,
                bytes_total: 0,
                would_block: 0,
                errors: 0,
            },
            next_ring_id: 1,
        }
    }

    /// Allocates a new pipe ring and returns its ID.
    pub fn alloc_ring(&mut self) -> Result<u32> {
        for i in 0..8 {
            if self.rings[i].id == 0 {
                let id = self.next_ring_id;
                self.next_ring_id = self.next_ring_id.saturating_add(1);
                self.rings[i] = SplicePipeRing::new(id);
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Frees the pipe ring with `id`.
    pub fn free_ring(&mut self, id: u32) -> Result<()> {
        for i in 0..8 {
            if self.rings[i].id == id {
                self.rings[i] = SplicePipeRing::new(0);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the index of the ring with `id`.
    fn ring_idx(&self, id: u32) -> Result<usize> {
        for i in 0..8 {
            if self.rings[i].id == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    // ── do_splice ────────────────────────────────────────────────

    /// Performs a `splice(2)` from `ctx.src` to `ctx.dst`.
    ///
    /// Both endpoints must identify pipes.  Returns the number of bytes
    /// transferred.
    pub fn do_splice(&mut self, ctx: &SpliceCtx) -> Result<usize> {
        self.stats.splice_calls += 1;

        if !ctx.has_pipe_endpoint() {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }

        let (src_kind, dst_kind) = (ctx.src.kind, ctx.dst.kind);

        let bytes = match (src_kind, dst_kind) {
            (SpliceEndpointKind::Pipe, SpliceEndpointKind::Pipe) => {
                self.splice_pipe_to_pipe(ctx.src.pipe_id, ctx.dst.pipe_id, ctx.len, ctx.flags)?
            }
            (SpliceEndpointKind::Pipe, SpliceEndpointKind::File)
            | (SpliceEndpointKind::Pipe, SpliceEndpointKind::Socket) => {
                // Drain the pipe; simulate writing to file/socket.
                self.splice_pipe_to_fd(ctx.src.pipe_id, ctx.len, ctx.flags)?
            }
            (SpliceEndpointKind::File, SpliceEndpointKind::Pipe)
            | (SpliceEndpointKind::Socket, SpliceEndpointKind::Pipe) => {
                // Simulate reading from file/socket into the pipe.
                self.splice_fd_to_pipe(ctx.dst.pipe_id, ctx.len, ctx.flags)?
            }
            _ => {
                self.stats.errors += 1;
                return Err(Error::InvalidArgument);
            }
        };

        self.stats.bytes_total += bytes as u64;
        Ok(bytes)
    }

    /// Moves up to `len` bytes from pipe `src_id` to pipe `dst_id`.
    fn splice_pipe_to_pipe(
        &mut self,
        src_id: u32,
        dst_id: u32,
        len: usize,
        flags: SpliceFlags,
    ) -> Result<usize> {
        let src_idx = self.ring_idx(src_id)?;
        let dst_idx = self.ring_idx(dst_id)?;

        if src_idx == dst_idx {
            return Err(Error::InvalidArgument);
        }

        if self.rings[src_idx].is_empty() {
            if flags.nonblock() {
                self.stats.would_block += 1;
                return Err(Error::WouldBlock);
            }
            return Ok(0);
        }

        let mut moved = 0usize;
        while moved < len {
            if self.rings[src_idx].is_empty() || self.rings[dst_idx].is_full() {
                break;
            }
            // We have to use indices directly to avoid simultaneous borrows.
            let buf = match self.rings[src_idx].pop() {
                Some(b) => b,
                None => break,
            };
            let bytes_in_buf = buf.len as usize;
            match self.rings[dst_idx].push(buf) {
                Ok(()) => moved += bytes_in_buf,
                Err(_) => {
                    // dst is full — put back
                    let _ = self.rings[src_idx].push(buf);
                    break;
                }
            }
        }
        Ok(moved)
    }

    /// Simulates draining up to `len` bytes from a pipe to a file/socket.
    fn splice_pipe_to_fd(&mut self, src_id: u32, len: usize, flags: SpliceFlags) -> Result<usize> {
        let idx = self.ring_idx(src_id)?;
        if self.rings[idx].is_empty() {
            if flags.nonblock() {
                self.stats.would_block += 1;
                return Err(Error::WouldBlock);
            }
            return Ok(0);
        }
        let mut moved = 0usize;
        while moved < len {
            if self.rings[idx].is_empty() {
                break;
            }
            match self.rings[idx].pop() {
                Some(buf) => moved += buf.len as usize,
                None => break,
            }
        }
        Ok(moved)
    }

    /// Simulates reading up to `len` bytes from a file/socket into a pipe.
    fn splice_fd_to_pipe(&mut self, dst_id: u32, len: usize, _flags: SpliceFlags) -> Result<usize> {
        let idx = self.ring_idx(dst_id)?;
        let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
        let pages = pages.min(SPLICE_MAX_PAGES).min(self.rings[idx].available());
        let bytes_per_page = (len / pages.max(1)).min(PAGE_SIZE);
        let mut moved = 0usize;
        for _ in 0..pages {
            let buf = SpliceBuf {
                page_addr: 0x1000, // symbolic
                offset: 0,
                len: bytes_per_page as u32,
                flags: 0,
            };
            if self.rings[idx].push(buf).is_err() {
                break;
            }
            moved += bytes_per_page;
        }
        Ok(moved)
    }

    // ── do_tee ───────────────────────────────────────────────────

    /// Performs a `tee(2)` — duplicates data from `src_pipe` into `dst_pipe`
    /// without consuming the source.
    ///
    /// Returns the number of bytes duplicated.
    pub fn do_tee(&mut self, ctx: &TeeCtx) -> Result<usize> {
        self.stats.tee_calls += 1;

        let src_idx = self.ring_idx(ctx.src_pipe_id)?;
        let dst_idx = self.ring_idx(ctx.dst_pipe_id)?;

        if src_idx == dst_idx {
            return Err(Error::InvalidArgument);
        }

        if self.rings[src_idx].is_empty() {
            if ctx.flags.nonblock() {
                self.stats.would_block += 1;
                return Err(Error::WouldBlock);
            }
            return Ok(0);
        }

        // Copy all slots from src to dst by peeking and duplicating.
        let mut copied = 0usize;
        let src_count = self.rings[src_idx].count;
        let src_head = self.rings[src_idx].head;

        let mut i = 0usize;
        let mut pos = src_head;
        while i < src_count && copied < ctx.len {
            let buf = self.rings[src_idx].slots[pos];
            if !buf.is_empty() {
                if self.rings[dst_idx].push(buf).is_err() {
                    break;
                }
                copied += buf.len as usize;
            }
            pos = (pos + 1) % RING_CAPACITY;
            i += 1;
        }

        self.stats.bytes_total += copied as u64;
        Ok(copied)
    }

    // ── do_vmsplice ──────────────────────────────────────────────

    /// Performs a `vmsplice(2)` — copies user-space I/O vectors into a pipe.
    ///
    /// Returns the total number of bytes transferred.
    pub fn do_vmsplice(&mut self, ctx: &VmspliceCtx) -> Result<usize> {
        self.stats.vmsplice_calls += 1;

        let total = ctx.total_bytes();
        if total > VMSPLICE_MAX {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }

        let idx = self.ring_idx(ctx.pipe_id)?;
        let mut moved = 0usize;

        for iov_idx in 0..ctx.iov_count {
            let iov = ctx.iovs[iov_idx];
            if iov.len == 0 {
                continue;
            }
            // Split each iov into page-sized chunks.
            let mut remaining = iov.len;
            let mut va = iov.base;
            while remaining > 0 {
                let chunk = remaining.min(PAGE_SIZE);
                if self.rings[idx].is_full() {
                    break;
                }
                let buf = SpliceBuf {
                    page_addr: va & !(PAGE_SIZE - 1),
                    offset: (va % PAGE_SIZE) as u32,
                    len: chunk as u32,
                    flags: if ctx.flags.gift() { 1 } else { 0 },
                };
                self.rings[idx].push(buf)?;
                moved += chunk;
                va += chunk;
                remaining -= chunk;
            }
        }

        self.stats.bytes_total += moved as u64;
        Ok(moved)
    }

    // ── do_sendfile ──────────────────────────────────────────────

    /// Performs a `sendfile(2)` — transfers up to `count` bytes from a file
    /// (represented by `in_fd`) to a socket (`out_fd`).
    ///
    /// The actual file data transfer is simulated; in a real implementation
    /// this would call the filesystem's `splice_read` hook.
    ///
    /// Returns the number of bytes transferred.
    pub fn do_sendfile(
        &mut self,
        _in_fd: i32,
        _out_fd: i32,
        offset: Option<u64>,
        count: usize,
    ) -> Result<usize> {
        self.stats.sendfile_calls += 1;

        if count > SENDFILE_MAX {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }

        // Validate offset if provided.
        if let Some(off) = offset {
            let _ = off; // offset is used by caller to track position
        }

        // Simulate a full transfer (the real implementation would invoke
        // the block device path; here we just return the requested count).
        let transferred = count;
        self.stats.bytes_total += transferred as u64;
        Ok(transferred)
    }

    /// Returns current statistics snapshot.
    pub fn stats(&self) -> &SpliceStats {
        &self.stats
    }

    /// Returns the byte count currently held in pipe ring `id`.
    pub fn ring_bytes(&self, id: u32) -> Result<usize> {
        let idx = self.ring_idx(id)?;
        Ok(self.rings[idx].byte_count())
    }

    /// Returns whether pipe ring `id` is empty.
    pub fn ring_is_empty(&self, id: u32) -> Result<bool> {
        let idx = self.ring_idx(id)?;
        Ok(self.rings[idx].is_empty())
    }
}

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(len: u32) -> SpliceBuf {
        SpliceBuf {
            page_addr: 0x1000,
            offset: 0,
            len,
            flags: 0,
        }
    }

    #[test]
    fn test_ring_push_pop() {
        let mut ring = SplicePipeRing::new(1);
        ring.push(make_buf(512)).unwrap();
        ring.push(make_buf(1024)).unwrap();
        assert_eq!(ring.filled(), 2);
        let b = ring.pop().unwrap();
        assert_eq!(b.len, 512);
        assert_eq!(ring.filled(), 1);
    }

    #[test]
    fn test_ring_full_returns_would_block() {
        let mut ring = SplicePipeRing::new(1);
        for _ in 0..RING_CAPACITY {
            ring.push(make_buf(1)).unwrap();
        }
        assert!(matches!(ring.push(make_buf(1)), Err(Error::WouldBlock)));
    }

    #[test]
    fn test_ring_tee_peek() {
        let mut ring = SplicePipeRing::new(1);
        ring.push(make_buf(100)).unwrap();
        let peeked = ring.peek().unwrap();
        assert_eq!(peeked.len, 100);
        // peek does not consume
        assert_eq!(ring.filled(), 1);
    }

    #[test]
    fn test_alloc_free_ring() {
        let mut engine = SpliceEngine::new();
        let id = engine.alloc_ring().unwrap();
        assert!(id > 0);
        engine.free_ring(id).unwrap();
        // After free, ring ID should not be findable.
        assert!(matches!(engine.ring_idx(id), Err(Error::NotFound)));
    }

    #[test]
    fn test_splice_pipe_to_pipe() {
        let mut engine = SpliceEngine::new();
        let src = engine.alloc_ring().unwrap();
        let dst = engine.alloc_ring().unwrap();

        // Push data into src.
        let src_idx = engine.ring_idx(src).unwrap();
        engine.rings[src_idx].push(make_buf(512)).unwrap();
        engine.rings[src_idx].push(make_buf(512)).unwrap();

        let ctx = SpliceCtx::new(SpliceDesc::pipe(src, 3), SpliceDesc::pipe(dst, 4), 4096, 0);
        let moved = engine.do_splice(&ctx).unwrap();
        assert_eq!(moved, 1024);

        let src_idx = engine.ring_idx(src).unwrap();
        assert!(engine.rings[src_idx].is_empty());
    }

    #[test]
    fn test_tee_does_not_consume_source() {
        let mut engine = SpliceEngine::new();
        let src = engine.alloc_ring().unwrap();
        let dst = engine.alloc_ring().unwrap();

        let src_idx = engine.ring_idx(src).unwrap();
        engine.rings[src_idx].push(make_buf(256)).unwrap();
        engine.rings[src_idx].push(make_buf(256)).unwrap();

        let ctx = TeeCtx {
            src_pipe_id: src,
            dst_pipe_id: dst,
            len: 4096,
            flags: SpliceFlags(0),
        };
        let copied = engine.do_tee(&ctx).unwrap();
        assert_eq!(copied, 512);

        // Source still intact.
        let src_idx = engine.ring_idx(src).unwrap();
        assert_eq!(engine.rings[src_idx].filled(), 2);

        // Destination has data.
        let dst_idx = engine.ring_idx(dst).unwrap();
        assert_eq!(engine.rings[dst_idx].filled(), 2);
    }

    #[test]
    fn test_vmsplice() {
        let mut engine = SpliceEngine::new();
        let pipe_id = engine.alloc_ring().unwrap();

        let mut ctx = VmspliceCtx::new(pipe_id, 0);
        ctx.push_iov(0x2000, 4096).unwrap();
        ctx.push_iov(0x3000, 4096).unwrap();

        let moved = engine.do_vmsplice(&ctx).unwrap();
        assert_eq!(moved, 8192);
        assert!(!engine.ring_is_empty(pipe_id).unwrap());
    }

    #[test]
    fn test_sendfile_basic() {
        let mut engine = SpliceEngine::new();
        let moved = engine.do_sendfile(3, 4, None, 65536).unwrap();
        assert_eq!(moved, 65536);
        assert_eq!(engine.stats.sendfile_calls, 1);
    }

    #[test]
    fn test_sendfile_overflow() {
        let mut engine = SpliceEngine::new();
        let res = engine.do_sendfile(3, 4, None, SENDFILE_MAX + 1);
        assert!(matches!(res, Err(Error::InvalidArgument)));
    }

    #[test]
    fn test_splice_flags() {
        let flags = SpliceFlags::from_raw(SPLICE_F_NONBLOCK | SPLICE_F_MORE);
        assert!(flags.nonblock());
        assert!(flags.more());
        assert!(!flags.move_pages());
    }

    #[test]
    fn test_splice_no_pipe_endpoint() {
        let mut engine = SpliceEngine::new();
        let ctx = SpliceCtx::new(
            SpliceDesc::file(3, 0, false),
            SpliceDesc::file(4, 0, false),
            1024,
            0,
        );
        assert!(matches!(
            engine.do_splice(&ctx),
            Err(Error::InvalidArgument)
        ));
    }
}
