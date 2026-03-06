// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX AIO context management.
//!
//! Provides the kernel-side AIO context (`io_context`) that underpins
//! `io_setup(2)`, `io_submit(2)`, `io_getevents(2)`, and `io_destroy(2)`.
//!
//! Each AIO context maintains a submission queue and a completion ring.
//! I/O operations are submitted asynchronously and their results are
//! collected via `io_getevents`.
//!
//! # POSIX references
//!
//! - POSIX.1-2024 `aio_read()`, `aio_write()`, `aio_fsync()`, `aio_error()`, `aio_return()`
//! - Linux `io_setup(2)`, `io_submit(2)`, `io_getevents(2)`, `io_destroy(2)`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of AIO contexts system-wide.
pub const MAX_AIO_CONTEXTS: usize = 32;

/// Maximum in-flight operations per context.
pub const MAX_AIO_OPS: usize = 128;

/// Maximum completions in the ring per context.
pub const MAX_AIO_EVENTS: usize = 256;

// ── IocbCmd ──────────────────────────────────────────────────────────

/// AIO operation command type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocbCmd {
    /// Asynchronous read.
    Pread,
    /// Asynchronous write.
    Pwrite,
    /// Asynchronous fsync.
    Fsync,
    /// Asynchronous data-only fsync.
    Fdsync,
}

// ── Iocb ─────────────────────────────────────────────────────────────

/// An I/O control block — describes one async I/O operation.
#[derive(Debug, Clone, Copy)]
pub struct Iocb {
    /// User-defined data returned with the completion event.
    pub data: u64,
    /// File descriptor to operate on.
    pub fd: i32,
    /// Operation type.
    pub cmd: IocbCmd,
    /// Byte offset within the file.
    pub offset: i64,
    /// Number of bytes to transfer.
    pub len: u64,
    /// Buffer address (user-space virtual address; validated by syscall layer).
    pub buf_addr: u64,
    /// Operation flags (reserved, must be 0).
    pub flags: u32,
}

// ── IoEvent ──────────────────────────────────────────────────────────

/// A completion event returned by `io_getevents`.
#[derive(Debug, Clone, Copy)]
pub struct IoEvent {
    /// User-defined data from the corresponding `Iocb`.
    pub data: u64,
    /// Opaque pointer identifying the completed `Iocb`.
    pub obj: u64,
    /// Result of the operation (bytes transferred, or negative errno).
    pub res: i64,
    /// Secondary result (currently unused).
    pub res2: i64,
}

impl IoEvent {
    /// Construct a successful completion event.
    pub const fn success(data: u64, obj: u64, bytes: u64) -> Self {
        Self {
            data,
            obj,
            res: bytes as i64,
            res2: 0,
        }
    }

    /// Construct a failed completion event.
    pub const fn error(data: u64, obj: u64, errno: i32) -> Self {
        Self {
            data,
            obj,
            res: -(errno as i64),
            res2: 0,
        }
    }
}

// ── AioOp ────────────────────────────────────────────────────────────

/// Tracks an in-flight AIO operation.
#[derive(Clone, Copy)]
pub struct AioOp {
    /// The submitted control block.
    pub iocb: Iocb,
    /// Whether this slot is occupied.
    pub active: bool,
    /// Whether the operation has completed.
    pub done: bool,
    /// Bytes transferred (valid when `done` is true).
    pub result: i64,
}

impl AioOp {
    /// Create an active in-flight operation.
    pub const fn new(iocb: Iocb) -> Self {
        Self {
            iocb,
            active: true,
            done: false,
            result: 0,
        }
    }
}

// ── AioContext ───────────────────────────────────────────────────────

/// A single AIO context (`io_context_t`).
pub struct AioContext {
    /// Context ID (maps to userspace `aio_context_t`).
    pub id: u64,
    /// In-flight operations.
    ops: [Option<AioOp>; MAX_AIO_OPS],
    op_count: usize,
    /// Completion ring buffer.
    events: [Option<IoEvent>; MAX_AIO_EVENTS],
    ev_head: usize,
    ev_tail: usize,
    ev_count: usize,
    /// Whether this context is active.
    pub active: bool,
}

impl AioContext {
    /// Create a new AIO context.
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            ops: [const { None }; MAX_AIO_OPS],
            op_count: 0,
            events: [const { None }; MAX_AIO_EVENTS],
            ev_head: 0,
            ev_tail: 0,
            ev_count: 0,
            active: true,
        }
    }

    /// Submit an I/O control block; returns a slot index.
    pub fn submit(&mut self, iocb: Iocb) -> Result<usize> {
        if self.op_count >= MAX_AIO_OPS {
            return Err(Error::OutOfMemory);
        }
        for (i, slot) in self.ops.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(AioOp::new(iocb));
                self.op_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Mark operation at slot `idx` as complete with result `res`.
    pub fn complete(&mut self, idx: usize, res: i64) -> Result<()> {
        let op = self
            .ops
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        if !op.active {
            return Err(Error::InvalidArgument);
        }
        op.done = true;
        op.result = res;
        let ev = if res >= 0 {
            IoEvent::success(op.iocb.data, idx as u64, res as u64)
        } else {
            IoEvent::error(op.iocb.data, idx as u64, (-res) as i32)
        };
        if self.ev_count < MAX_AIO_EVENTS {
            self.events[self.ev_tail] = Some(ev);
            self.ev_tail = (self.ev_tail + 1) % MAX_AIO_EVENTS;
            self.ev_count += 1;
        }
        self.ops[idx] = None;
        self.op_count = self.op_count.saturating_sub(1);
        Ok(())
    }

    /// Retrieve up to `min_nr..=nr` completion events.
    ///
    /// Returns the number of events written to `out`.
    pub fn getevents(&mut self, min_nr: usize, nr: usize, out: &mut [IoEvent]) -> usize {
        let _ = min_nr; // blocking logic deferred to syscall layer
        let to_read = nr.min(out.len()).min(self.ev_count);
        for i in 0..to_read {
            out[i] = self.events[self.ev_head].unwrap_or(IoEvent {
                data: 0,
                obj: 0,
                res: 0,
                res2: 0,
            });
            self.events[self.ev_head] = None;
            self.ev_head = (self.ev_head + 1) % MAX_AIO_EVENTS;
        }
        self.ev_count = self.ev_count.saturating_sub(to_read);
        to_read
    }

    /// Cancel a pending operation by slot index.
    pub fn cancel(&mut self, idx: usize) -> Result<()> {
        let op = self
            .ops
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        if op.done {
            return Err(Error::InvalidArgument);
        }
        op.active = false;
        self.ops[idx] = None;
        self.op_count = self.op_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of pending (in-flight) operations.
    pub fn pending_count(&self) -> usize {
        self.op_count
    }

    /// Returns the number of queued completion events.
    pub fn event_count(&self) -> usize {
        self.ev_count
    }
}

// ── AioSubsystem ─────────────────────────────────────────────────────

/// Global AIO subsystem — manages all AIO contexts.
pub struct AioSubsystem {
    contexts: [Option<AioContext>; MAX_AIO_CONTEXTS],
    count: usize,
    next_id: u64,
}

impl AioSubsystem {
    /// Create an empty AIO subsystem.
    pub const fn new() -> Self {
        Self {
            contexts: [const { None }; MAX_AIO_CONTEXTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Create a new AIO context (`io_setup`); returns its ID.
    pub fn setup(&mut self, _max_events: u32) -> Result<u64> {
        if self.count >= MAX_AIO_CONTEXTS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        for slot in self.contexts.iter_mut() {
            if slot.is_none() {
                *slot = Some(AioContext::new(id));
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy an AIO context (`io_destroy`).
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        for slot in self.contexts.iter_mut() {
            if let Some(ctx) = slot {
                if ctx.id == id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up an AIO context by ID (mutable).
    pub fn context_mut(&mut self, id: u64) -> Option<&mut AioContext> {
        for slot in self.contexts.iter_mut() {
            if let Some(ctx) = slot {
                if ctx.id == id {
                    return Some(ctx);
                }
            }
        }
        None
    }

    /// Submit an `Iocb` to context `id`.
    pub fn submit(&mut self, id: u64, iocb: Iocb) -> Result<usize> {
        self.context_mut(id).ok_or(Error::NotFound)?.submit(iocb)
    }

    /// Collect completion events from context `id`.
    pub fn getevents(
        &mut self,
        id: u64,
        min_nr: usize,
        nr: usize,
        out: &mut [IoEvent],
    ) -> Result<usize> {
        let ctx = self.context_mut(id).ok_or(Error::NotFound)?;
        Ok(ctx.getevents(min_nr, nr, out))
    }

    /// Returns the number of active contexts.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for AioSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
