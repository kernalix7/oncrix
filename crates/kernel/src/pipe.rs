// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel pipe implementation.
//!
//! Provides a fixed-size ring-buffer backed anonymous pipe conforming to
//! POSIX.1-2024 `pipe(3p)` / `pipe2(3p)`.
//!
//! # Design
//!
//! Each pipe is represented by a [`PipeRing`] stored in a global static
//! array [`PIPE_TABLE`].  A `ring_id` (index into that array) is embedded
//! in the per-fd [`crate::fd_table::FileBackend::Pipe`] variant so that
//! read and write operations can locate the shared ring without heap
//! allocation.
//!
//! Phase 18 simplifications:
//! - Maximum [`MAX_PIPES`] concurrent pipes (8).
//! - Ring capacity [`PIPE_BUF`] = 4096 bytes (POSIX minimum for atomic
//!   write guarantee).
//! - Blocking read/write via `yield_now` spin — no proper wait queue.
//! - No `O_NONBLOCK`, `O_CLOEXEC`, `O_CLOFORK` support (flag argument is
//!   accepted but ignored); those are deferred.
//!
//! # POSIX.1-2024 references
//!
//! - `pipe(3p)` — `susv5-html/functions/pipe.html`
//!   - Returns 0 on success; `fildes[0]` = read end, `fildes[1]` = write end.
//!   - `EMFILE` when all fds are in use; `ENFILE` when no pipe slots remain.
//! - `read(3p)` — Blocks if no data; returns 0 on write-end closed (EOF).
//! - `write(3p)` — Blocks if buffer full; returns `-EPIPE` if no readers.

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of simultaneously open pipes.
pub const MAX_PIPES: usize = 8;

/// Pipe ring-buffer capacity in bytes.
///
/// Matches the POSIX `PIPE_BUF` minimum (512 bytes) and the common
/// Linux default (4096 bytes) — large enough for typical shell I/O.
pub const PIPE_BUF: usize = 4096;

// ── PipeRing ──────────────────────────────────────────────────────

/// A fixed-capacity ring buffer backing a single anonymous pipe.
///
/// `head` is the next read position; `tail` is the next write position.
/// The buffer is full when `(tail + 1) % PIPE_BUF == head` (one slot
/// wasted to distinguish full from empty — standard ring-buffer idiom).
///
/// `write_open` and `read_open` track whether the write / read end of
/// the pipe is still open.  When the write end is closed and the buffer
/// is empty, reads return 0 (EOF).  When the read end is closed, writes
/// return `-EPIPE` (32).
///
/// `write_refs` / `read_refs` count how many fd slots reference each
/// end (incremented by `dup2` / `fork`, decremented by `close`).  An
/// end transitions from open to closed only when its refcount hits
/// zero.
pub struct PipeRing {
    buf: [u8; PIPE_BUF],
    head: usize,
    tail: usize,
    /// `true` while at least one write-end fd is open.
    pub write_open: bool,
    /// `true` while at least one read-end fd is open.
    pub read_open: bool,
    /// `true` when this slot is in use.
    pub in_use: bool,
    /// Reference count for write-end fds.
    pub write_refs: u32,
    /// Reference count for read-end fds.
    pub read_refs: u32,
}

impl Default for PipeRing {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeRing {
    /// Create an empty, unallocated ring slot.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; PIPE_BUF],
            head: 0,
            tail: 0,
            write_open: false,
            read_open: false,
            in_use: false,
            write_refs: 0,
            read_refs: 0,
        }
    }

    /// Initialize this slot as a live pipe with a single fd on each end.
    pub fn open(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.write_open = true;
        self.read_open = true;
        self.in_use = true;
        self.write_refs = 1;
        self.read_refs = 1;
    }

    /// Initialize this slot as a FIFO backing ring with **no** fds attached.
    ///
    /// Unlike [`open`](Self::open), both ends start with a zero refcount and
    /// are marked closed; each `open(2)` of the FIFO path bumps exactly one
    /// end via [`pipe_open_end`]. This lets a writer and a reader that open
    /// the same FIFO path independently share one buffer, and lets the slot
    /// free itself once both ends drop back to zero.
    pub fn open_fifo(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.write_open = false;
        self.read_open = false;
        self.in_use = true;
        self.write_refs = 0;
        self.read_refs = 0;
    }

    /// Number of bytes available to read.
    pub fn available(&self) -> usize {
        (self.tail + PIPE_BUF - self.head) % PIPE_BUF
    }

    /// Number of bytes of free space for writing.
    pub fn free_space(&self) -> usize {
        // One slot is always kept empty (full/empty disambiguation).
        PIPE_BUF - 1 - self.available()
    }

    /// Return `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Return `true` if the buffer is full (no space to write).
    pub fn is_full(&self) -> bool {
        (self.tail + 1) % PIPE_BUF == self.head
    }

    /// Push up to `src.len()` bytes into the ring; return bytes written.
    ///
    /// Returns 0 if the buffer is full.
    pub fn push(&mut self, src: &[u8]) -> usize {
        let mut written = 0usize;
        for &byte in src {
            if self.is_full() {
                break;
            }
            self.buf[self.tail] = byte;
            self.tail = (self.tail + 1) % PIPE_BUF;
            written += 1;
        }
        written
    }

    /// Pop up to `dst.len()` bytes from the ring; return bytes read.
    ///
    /// Returns 0 if the buffer is empty.
    pub fn pop(&mut self, dst: &mut [u8]) -> usize {
        let mut read = 0usize;
        for slot in dst.iter_mut() {
            if self.is_empty() {
                break;
            }
            *slot = self.buf[self.head];
            self.head = (self.head + 1) % PIPE_BUF;
            read += 1;
        }
        read
    }
}

// ── Global pipe table ─────────────────────────────────────────────

/// Global table of pipe ring buffers (Phase 18: fixed-size, no heap).
///
/// # Safety invariant
///
/// Accessed exclusively from the SYSCALL dispatch path where the single
/// CPU is in ring 0 with interrupts effectively disabled (FMASK cleared
/// IF on SYSCALL entry).  No concurrent mutation is possible on
/// single-CPU builds.
// SAFETY: See module-level note. Single-CPU SYSCALL context only.
static mut PIPE_TABLE: [PipeRing; MAX_PIPES] = {
    const EMPTY: PipeRing = PipeRing::new();
    [EMPTY; MAX_PIPES]
};

/// Allocate a free pipe slot and return its `ring_id`.
///
/// Returns `None` if all [`MAX_PIPES`] slots are occupied (`ENFILE`).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled).
pub unsafe fn pipe_alloc() -> Option<u32> {
    // SAFETY: Single-CPU SYSCALL context; no aliased mutation.
    unsafe {
        #[allow(static_mut_refs)]
        for (i, slot) in PIPE_TABLE.iter_mut().enumerate() {
            if !slot.in_use {
                slot.open();
                return Some(i as u32);
            }
        }
    }
    None
}

/// Allocate a free pipe slot as a FIFO backing ring and return its `ring_id`.
///
/// The slot is initialized with [`PipeRing::open_fifo`] (both ends closed,
/// zero refs); the caller must follow up with [`pipe_open_end`] for each
/// fd that opens the FIFO. Returns `None` if all [`MAX_PIPES`] slots are
/// occupied (`ENFILE`).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled).
pub unsafe fn pipe_alloc_fifo() -> Option<u32> {
    // SAFETY: Single-CPU SYSCALL context; no aliased mutation.
    unsafe {
        #[allow(static_mut_refs)]
        for (i, slot) in PIPE_TABLE.iter_mut().enumerate() {
            if !slot.in_use {
                slot.open_fifo();
                return Some(i as u32);
            }
        }
    }
    None
}

/// Attach one fd to an end of FIFO ring `ring_id`, bumping its refcount and
/// marking that end open.
///
/// `is_write_end` selects the write end (`true`) or read end (`false`).
/// Returns `false` if the slot is out of range or not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_open_end(ring_id: u32, is_write_end: bool) -> bool {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = PIPE_TABLE.get_mut(ring_id as usize)
            && slot.in_use
        {
            if is_write_end {
                slot.write_refs = slot.write_refs.saturating_add(1);
                slot.write_open = true;
            } else {
                slot.read_refs = slot.read_refs.saturating_add(1);
                slot.read_open = true;
            }
            return true;
        }
    }
    false
}

/// Return the reference count of the **peer** end of FIFO ring `ring_id`.
///
/// For a caller opening the write end (`opening_write_end == true`) this is
/// the read-end refcount, and vice versa. Used by blocking FIFO `open(2)`
/// to wait until a peer has attached. Returns 0 if the slot is out of range
/// or not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_peer_refs(ring_id: u32, opening_write_end: bool) -> u32 {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = PIPE_TABLE.get(ring_id as usize)
            && slot.in_use
        {
            return if opening_write_end {
                slot.read_refs
            } else {
                slot.write_refs
            };
        }
    }
    0
}

/// Get a shared reference to the pipe ring for `ring_id`.
///
/// Returns `None` if the id is out of range or the slot is not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_get(ring_id: u32) -> Option<&'static PipeRing> {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = PIPE_TABLE.get(ring_id as usize)?;
        if slot.in_use { Some(slot) } else { None }
    }
}

/// Get a mutable reference to the pipe ring for `ring_id`.
///
/// Returns `None` if the id is out of range or the slot is not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_get_mut(ring_id: u32) -> Option<&'static mut PipeRing> {
    // SAFETY: Single-CPU SYSCALL context; sole accessor.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = PIPE_TABLE.get_mut(ring_id as usize)?;
        if slot.in_use { Some(slot) } else { None }
    }
}

/// Drop one reference to the write end of pipe `ring_id`.
///
/// When the refcount reaches zero, the write end is marked closed; if
/// the read end is also closed, the slot is released entirely.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_close_write(ring_id: u32) {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = PIPE_TABLE.get_mut(ring_id as usize)
            && slot.in_use
        {
            slot.write_refs = slot.write_refs.saturating_sub(1);
            if slot.write_refs == 0 {
                slot.write_open = false;
                if !slot.read_open {
                    slot.in_use = false;
                }
            }
        }
    }
}

/// Drop one reference to the read end of pipe `ring_id`.
///
/// When the refcount reaches zero, the read end is marked closed; if
/// the write end is also closed, the slot is released entirely.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_close_read(ring_id: u32) {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = PIPE_TABLE.get_mut(ring_id as usize)
            && slot.in_use
        {
            slot.read_refs = slot.read_refs.saturating_sub(1);
            if slot.read_refs == 0 {
                slot.read_open = false;
                if !slot.write_open {
                    slot.in_use = false;
                }
            }
        }
    }
}

/// Add one reference to the write end of pipe `ring_id`.
///
/// Used by `dup`/`dup2`/`fork` when an additional fd starts referencing
/// the same write end.  No-op if the slot is not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_dup_write(ring_id: u32) {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = PIPE_TABLE.get_mut(ring_id as usize)
            && slot.in_use
        {
            slot.write_refs = slot.write_refs.saturating_add(1);
        }
    }
}

/// Add one reference to the read end of pipe `ring_id`.
///
/// Used by `dup`/`dup2`/`fork` when an additional fd starts referencing
/// the same read end.  No-op if the slot is not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn pipe_dup_read(ring_id: u32) {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = PIPE_TABLE.get_mut(ring_id as usize)
            && slot.in_use
        {
            slot.read_refs = slot.read_refs.saturating_add(1);
        }
    }
}

// ── sys_pipe2 ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_PIPE2` (Linux number 293).
///
/// POSIX.1-2024 `pipe2(3p)` semantics:
/// - Allocates a pipe ring in [`PIPE_TABLE`].
/// - Installs `fildes[0]` (read end) and `fildes[1]` (write end) in the
///   current process's fd table.
/// - Writes both fd numbers to the user-space `fildes[2]` array.
/// - Returns 0 on success, negative errno on failure.
///
/// Phase 18: the `flags` argument is accepted but not acted on
/// (`O_NONBLOCK`, `O_CLOEXEC`, `O_CLOFORK` are deferred).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_pipe2(fildes_ptr: u64, _flags: u64) -> i64 {
    // Validate the user pointer.
    if fildes_ptr == 0 || fildes_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Allocate a pipe slot.
    // SAFETY: Single-CPU SYSCALL context.
    let ring_id = unsafe {
        match pipe_alloc() {
            Some(id) => id,
            None => return -23, // ENFILE — no free pipe slots
        }
    };

    // Build FileHandles for the read and write ends.
    let read_handle = crate::fd_table::FileHandle {
        backend: crate::fd_table::FileBackend::Pipe {
            ring_id,
            is_write_end: false,
        },
        offset: 0,
        flags: crate::fd_table::HandleFlags::RDONLY,
    };
    let write_handle = crate::fd_table::FileHandle {
        backend: crate::fd_table::FileBackend::Pipe {
            ring_id,
            is_write_end: true,
        },
        offset: 0,
        flags: crate::fd_table::HandleFlags::WRONLY,
    };

    // Install both fds (lowest-available order).
    // SAFETY: Single-CPU SYSCALL context.
    let read_fd = unsafe {
        match crate::fd_table::fd_install(read_handle) {
            Ok(fd) => fd,
            Err(_) => {
                // Roll back the pipe allocation.
                pipe_close_read(ring_id);
                pipe_close_write(ring_id);
                return -24; // EMFILE
            }
        }
    };

    let write_fd = unsafe {
        match crate::fd_table::fd_install(write_handle) {
            Ok(fd) => fd,
            Err(_) => {
                // Roll back: close both ends so the slot is freed.
                crate::fd_table::fd_close(read_fd).ok();
                pipe_close_read(ring_id);
                pipe_close_write(ring_id);
                return -24; // EMFILE
            }
        }
    };

    // Write the two fd numbers to user space.
    // SAFETY: `fildes_ptr` validated above. Writing two i32 values
    // (8 bytes total) at a user-space address checked to be below the
    // kernel canonical boundary.
    unsafe {
        let arr = fildes_ptr as *mut i32;
        arr.write_volatile(read_fd as i32);
        arr.add(1).write_volatile(write_fd as i32);
    }

    0 // success
}
