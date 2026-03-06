// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel I/O control block (kiocb) — represents a single in-flight I/O.
//!
//! A `Kiocb` tracks the state of an asynchronous or synchronous I/O
//! operation initiated by the VFS layer. It is the kernel counterpart to
//! POSIX `aiocb` and serves as the link between the file system and the
//! completion/notification mechanism.

use oncrix_lib::{Error, Result};

/// Maximum number of simultaneous kiocbs per process.
pub const MAX_KIOCBS: usize = 64;

/// I/O operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KiocbOp {
    /// Read from file into user buffer.
    Read,
    /// Write from user buffer into file.
    Write,
    /// Vectored read (readv).
    Readv,
    /// Vectored write (writev).
    Writev,
    /// File synchronization (fsync / fdatasync).
    Fsync,
    /// Poll for I/O readiness.
    Poll,
}

/// Flags modifying I/O behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct KiocbFlags(pub u32);

impl KiocbFlags {
    /// I/O should bypass the page cache (direct I/O).
    pub const DIRECT: u32 = 1 << 0;
    /// I/O must not block (IOCB_NOWAIT).
    pub const NOWAIT: u32 = 1 << 1;
    /// Append-only write (O_APPEND semantics).
    pub const APPEND: u32 = 1 << 2;
    /// Data synchronisation on write (O_DSYNC).
    pub const DSYNC: u32 = 1 << 3;
    /// Full synchronisation on write (O_SYNC).
    pub const SYNC: u32 = 1 << 4;
    /// This is an asynchronous (io_uring / aio) operation.
    pub const ASYNC: u32 = 1 << 5;

    /// Test whether a flag is set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// Lifecycle state of a kiocb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KiocbState {
    /// Newly allocated, not yet submitted.
    Init,
    /// Submitted to the filesystem / block layer.
    InFlight,
    /// I/O completed successfully.
    Done,
    /// I/O failed.
    Error,
    /// Cancelled before completion.
    Cancelled,
}

/// A kernel I/O control block.
#[derive(Debug, Clone, Copy)]
pub struct Kiocb {
    /// File descriptor index this I/O targets.
    pub fd: u32,
    /// Open-file description index.
    pub ofd: u32,
    /// Operation type.
    pub op: KiocbOp,
    /// Flags.
    pub flags: KiocbFlags,
    /// Current file position for this operation.
    pub pos: i64,
    /// User-space buffer address (virtual address in caller's address space).
    pub buf_addr: u64,
    /// Length of the I/O request in bytes.
    pub len: u64,
    /// Number of bytes actually transferred.
    pub transferred: u64,
    /// Lifecycle state.
    pub state: KiocbState,
    /// Error code (0 = no error).
    pub errno: i32,
    /// Completion token (used by io_uring for SQE linkage).
    pub completion_token: u64,
    /// Wall-clock time when this kiocb was submitted (seconds).
    pub submitted_at: i64,
}

impl Kiocb {
    /// Create a new synchronous kiocb.
    pub const fn new_sync(
        fd: u32,
        ofd: u32,
        op: KiocbOp,
        pos: i64,
        buf_addr: u64,
        len: u64,
        flags: KiocbFlags,
    ) -> Self {
        Self {
            fd,
            ofd,
            op,
            flags,
            pos,
            buf_addr,
            len,
            transferred: 0,
            state: KiocbState::Init,
            errno: 0,
            completion_token: 0,
            submitted_at: 0,
        }
    }

    /// Create a new asynchronous kiocb with a completion token.
    pub const fn new_async(
        fd: u32,
        ofd: u32,
        op: KiocbOp,
        pos: i64,
        buf_addr: u64,
        len: u64,
        flags: KiocbFlags,
        completion_token: u64,
    ) -> Self {
        let mut kb = Self::new_sync(fd, ofd, op, pos, buf_addr, len, flags);
        kb.completion_token = completion_token;
        kb
    }

    /// Mark the kiocb as in-flight.
    pub fn submit(&mut self, now: i64) {
        self.state = KiocbState::InFlight;
        self.submitted_at = now;
    }

    /// Mark the kiocb as completed with `transferred` bytes.
    pub fn complete(&mut self, transferred: u64) {
        self.transferred = transferred;
        self.state = KiocbState::Done;
        self.errno = 0;
    }

    /// Mark the kiocb as failed with the given errno.
    pub fn fail(&mut self, errno: i32) {
        self.state = KiocbState::Error;
        self.errno = errno;
    }

    /// Cancel a pending kiocb.
    pub fn cancel(&mut self) {
        if self.state == KiocbState::Init || self.state == KiocbState::InFlight {
            self.state = KiocbState::Cancelled;
        }
    }

    /// Return true if this I/O is complete (success, error, or cancelled).
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            KiocbState::Done | KiocbState::Error | KiocbState::Cancelled
        )
    }

    /// Return the effective file position after a successful read/write.
    pub fn effective_pos(&self) -> i64 {
        if self.state == KiocbState::Done && !self.flags.has(KiocbFlags::APPEND) {
            self.pos.saturating_add(self.transferred as i64)
        } else {
            self.pos
        }
    }
}

/// A per-process pool of kiocbs.
pub struct KiocbPool {
    items: [Option<Kiocb>; MAX_KIOCBS],
    count: usize,
}

impl KiocbPool {
    /// Create an empty kiocb pool.
    pub const fn new() -> Self {
        Self {
            items: [const { None }; MAX_KIOCBS],
            count: 0,
        }
    }

    /// Allocate a slot for a new kiocb. Returns the slot index.
    pub fn alloc(&mut self, kb: Kiocb) -> Result<usize> {
        for (i, slot) in self.items.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(kb);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a reference to the kiocb at `slot`.
    pub fn get(&self, slot: usize) -> Option<&Kiocb> {
        self.items.get(slot)?.as_ref()
    }

    /// Get a mutable reference to the kiocb at `slot`.
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut Kiocb> {
        self.items.get_mut(slot)?.as_mut()
    }

    /// Free (release) the kiocb at `slot`.
    pub fn free(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_KIOCBS {
            return Err(Error::InvalidArgument);
        }
        if self.items[slot].is_none() {
            return Err(Error::NotFound);
        }
        self.items[slot] = None;
        self.count -= 1;
        Ok(())
    }

    /// Return number of active kiocbs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Cancel all in-flight kiocbs for a given fd.
    pub fn cancel_fd(&mut self, fd: u32) -> u32 {
        let mut cancelled = 0u32;
        for slot in self.items.iter_mut() {
            if let Some(kb) = slot {
                if kb.fd == fd && !kb.is_terminal() {
                    kb.cancel();
                    cancelled += 1;
                }
            }
        }
        cancelled
    }
}

impl Default for KiocbPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a kiocb buffer address and length are safe.
///
/// In a real kernel this would verify the pointer is in user address space.
/// Here we perform basic sanity checks only.
pub fn validate_kiocb_buffer(buf_addr: u64, len: u64) -> Result<()> {
    if buf_addr == 0 && len > 0 {
        return Err(Error::InvalidArgument);
    }
    if len > (1u64 << 32) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
