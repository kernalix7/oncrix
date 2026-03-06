// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX Asynchronous I/O (AIO) subsystem.
//!
//! Implements the POSIX.1-2024 asynchronous I/O interface including
//! `aio_read`, `aio_write`, `aio_fsync`, `aio_error`, `aio_return`,
//! `aio_cancel`, `aio_suspend`, and `lio_listio`.
//!
//! Requests are submitted via [`AioContext`] and processed
//! asynchronously. Each request transitions through the states
//! defined by [`AioState`]: Pending, InProgress, Completed,
//! Canceled, or Error.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum number of concurrent AIO requests.
const MAX_AIO_REQUESTS: usize = 128;

/// Return value: all requested operations were canceled.
const _AIO_CANCELED: i32 = 0;

/// Return value: some operations could not be canceled.
const _AIO_NOTCANCELED: i32 = 1;

/// Return value: all operations already completed.
const _AIO_ALLDONE: i32 = 2;

/// List I/O opcode: read operation.
const _LIO_READ: i32 = 0;

/// List I/O opcode: write operation.
const _LIO_WRITE: i32 = 1;

/// List I/O opcode: no-op (skip this entry).
const _LIO_NOP: i32 = 2;

/// List I/O mode: wait for all operations to complete.
const LIO_WAIT: i32 = 0;

/// List I/O mode: return immediately after submission.
const _LIO_NOWAIT: i32 = 1;

/// Error code indicating the operation is still in progress.
const EINPROGRESS: i32 = 115;

// ── AioOpcode ────────────────────────────────────────────────────

/// Asynchronous I/O operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AioOpcode {
    /// Asynchronous read operation.
    Read,
    /// Asynchronous write operation.
    Write,
    /// Asynchronous file synchronization.
    Fsync,
    /// No operation (placeholder in list I/O).
    #[default]
    Nop,
}

// ── AioState ─────────────────────────────────────────────────────

/// State of an asynchronous I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AioState {
    /// Request has been submitted but not yet started.
    #[default]
    Pending,
    /// Request is currently being processed.
    InProgress,
    /// Request completed successfully.
    Completed,
    /// Request was canceled before completion.
    Canceled,
    /// Request failed with an error.
    Error,
}

// ── AioCb ────────────────────────────────────────────────────────

/// POSIX asynchronous I/O control block.
///
/// This is the `#[repr(C)]` analog of the POSIX `struct aiocb`.
/// It describes a single asynchronous I/O operation including the
/// file descriptor, buffer location, byte count, and operation
/// type.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AioCb {
    /// File descriptor for the I/O operation.
    pub fd: i32,
    /// File offset at which the I/O begins.
    pub offset: u64,
    /// Pointer to the user-space buffer.
    pub buf_ptr: u64,
    /// Number of bytes to transfer.
    pub nbytes: usize,
    /// Type of I/O operation to perform.
    pub opcode: AioOpcode,
    /// Scheduling priority for this request.
    pub priority: i32,
    /// Signal number for completion notification.
    pub sigevent_signo: i32,
}

impl Default for AioCb {
    fn default() -> Self {
        Self {
            fd: -1,
            offset: 0,
            buf_ptr: 0,
            nbytes: 0,
            opcode: AioOpcode::Nop,
            priority: 0,
            sigevent_signo: 0,
        }
    }
}

// ── AioRequest ───────────────────────────────────────────────────

/// Internal representation of a queued AIO request.
///
/// Wraps an [`AioCb`] with tracking metadata such as the unique
/// request ID, current processing state, and owning process.
#[derive(Debug, Clone, Copy)]
pub struct AioRequest {
    /// Unique identifier for this request.
    pub id: u32,
    /// The control block describing the I/O operation.
    pub cb: AioCb,
    /// Current state of this request.
    pub state: AioState,
    /// Bytes transferred (positive) or negative errno on error.
    pub result: i64,
    /// POSIX error code (0 on success).
    pub error_code: i32,
    /// PID of the process that owns this request.
    pub owner_pid: u64,
    /// Whether this slot is actively in use.
    pub active: bool,
}

impl Default for AioRequest {
    fn default() -> Self {
        Self {
            id: 0,
            cb: AioCb::default(),
            state: AioState::Pending,
            result: 0,
            error_code: 0,
            owner_pid: 0,
            active: false,
        }
    }
}

// ── AioContext ────────────────────────────────────────────────────

/// Manages all in-flight asynchronous I/O requests.
///
/// Provides the full POSIX AIO interface: submission, status
/// queries, cancellation, and batch operations via `lio_listio`.
pub struct AioContext {
    /// Fixed-size pool of request slots.
    requests: [AioRequest; MAX_AIO_REQUESTS],
    /// Monotonically increasing ID for the next request.
    next_id: u32,
    /// Number of active (in-use) request slots.
    count: usize,
    /// Total requests that completed successfully.
    completed_count: u64,
    /// Total requests that ended in error.
    _error_count: u64,
}

impl Default for AioContext {
    fn default() -> Self {
        Self::new()
    }
}

impl AioContext {
    /// Creates a new, empty AIO context.
    pub const fn new() -> Self {
        const DEFAULT_REQ: AioRequest = AioRequest {
            id: 0,
            cb: AioCb {
                fd: -1,
                offset: 0,
                buf_ptr: 0,
                nbytes: 0,
                opcode: AioOpcode::Nop,
                priority: 0,
                sigevent_signo: 0,
            },
            state: AioState::Pending,
            result: 0,
            error_code: 0,
            owner_pid: 0,
            active: false,
        };

        Self {
            requests: [DEFAULT_REQ; MAX_AIO_REQUESTS],
            next_id: 1,
            count: 0,
            completed_count: 0,
            _error_count: 0,
        }
    }

    /// Submits an asynchronous read request.
    ///
    /// Returns the unique request ID on success, or an error if
    /// the request pool is full or the control block is invalid.
    pub fn aio_read(&mut self, cb: &AioCb, pid: u64) -> Result<u32> {
        if cb.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let mut submit_cb = *cb;
        submit_cb.opcode = AioOpcode::Read;
        self.submit_request(&submit_cb, pid)
    }

    /// Submits an asynchronous write request.
    ///
    /// Returns the unique request ID on success, or an error if
    /// the request pool is full or the control block is invalid.
    pub fn aio_write(&mut self, cb: &AioCb, pid: u64) -> Result<u32> {
        if cb.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let mut submit_cb = *cb;
        submit_cb.opcode = AioOpcode::Write;
        self.submit_request(&submit_cb, pid)
    }

    /// Submits an asynchronous fsync request.
    ///
    /// Returns the unique request ID on success, or an error if
    /// the request pool is full or the file descriptor is invalid.
    pub fn aio_fsync(&mut self, fd: i32, pid: u64) -> Result<u32> {
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let cb = AioCb {
            fd,
            opcode: AioOpcode::Fsync,
            ..AioCb::default()
        };
        self.submit_request(&cb, pid)
    }

    /// Returns the error status of the request with the given ID.
    ///
    /// - `Ok(0)` — the operation completed successfully.
    /// - `Ok(EINPROGRESS)` — the operation is still in progress.
    /// - `Ok(code)` — the operation failed with `code`.
    /// - `Err(NotFound)` — no request with that ID exists.
    pub fn aio_error(&self, id: u32) -> Result<i32> {
        let req = self.find_request(id)?;
        match req.state {
            AioState::Completed => Ok(0),
            AioState::Pending | AioState::InProgress => Ok(EINPROGRESS),
            AioState::Canceled => Ok(req.error_code),
            AioState::Error => Ok(req.error_code),
        }
    }

    /// Returns the result of a completed request and frees the
    /// slot.
    ///
    /// The return value is the number of bytes transferred, or a
    /// negative errno on failure. After this call the request ID
    /// is no longer valid.
    pub fn aio_return(&mut self, id: u32) -> Result<i64> {
        let idx = self.find_request_index(id)?;
        let result = self.requests[idx].result;
        self.requests[idx].active = false;
        self.count = self.count.saturating_sub(1);
        Ok(result)
    }

    /// Cancels all pending requests for the given file descriptor.
    ///
    /// Returns one of:
    /// - `AIO_CANCELED` (0) — all matching requests canceled.
    /// - `AIO_NOTCANCELED` (1) — some could not be canceled.
    /// - `AIO_ALLDONE` (2) — no pending requests found.
    pub fn aio_cancel(&mut self, fd: i32) -> Result<i32> {
        let mut found = false;
        let mut all_canceled = true;

        for slot in &mut self.requests {
            if !slot.active || slot.cb.fd != fd {
                continue;
            }
            found = true;
            match slot.state {
                AioState::Pending => {
                    slot.state = AioState::Canceled;
                    slot.error_code = -1;
                }
                AioState::InProgress => {
                    all_canceled = false;
                }
                _ => {}
            }
        }

        if !found {
            Ok(_AIO_ALLDONE)
        } else if all_canceled {
            Ok(_AIO_CANCELED)
        } else {
            Ok(_AIO_NOTCANCELED)
        }
    }

    /// Waits until at least one of the specified requests has
    /// completed.
    ///
    /// In this stub implementation the method checks the current
    /// state of each listed request and returns `Ok(())` if any
    /// has finished, or `Err(WouldBlock)` otherwise.
    pub fn aio_suspend(&self, ids: &[u32]) -> Result<()> {
        for &id in ids {
            if let Ok(req) = self.find_request(id) {
                match req.state {
                    AioState::Completed | AioState::Canceled | AioState::Error => return Ok(()),
                    _ => {}
                }
            }
        }
        Err(Error::WouldBlock)
    }

    /// Submits a batch of I/O requests.
    ///
    /// If `mode` is `LIO_WAIT` the method processes all submitted
    /// requests before returning. If `mode` is `LIO_NOWAIT` the
    /// requests are queued and control returns immediately.
    pub fn lio_listio(&mut self, mode: i32, cbs: &[AioCb], pid: u64) -> Result<()> {
        for cb in cbs {
            match cb.opcode {
                AioOpcode::Read => {
                    self.aio_read(cb, pid)?;
                }
                AioOpcode::Write => {
                    self.aio_write(cb, pid)?;
                }
                AioOpcode::Fsync => {
                    self.aio_fsync(cb.fd, pid)?;
                }
                AioOpcode::Nop => {}
            }
        }

        if mode == LIO_WAIT {
            self.process_pending();
        }

        Ok(())
    }

    /// Stub I/O processor: transitions pending requests through
    /// in-progress to completed.
    ///
    /// A real implementation would dispatch to the underlying
    /// block or character device. This stub marks every pending
    /// request as successfully completed with `nbytes` bytes
    /// transferred.
    pub fn process_pending(&mut self) {
        for slot in &mut self.requests {
            if !slot.active {
                continue;
            }
            match slot.state {
                AioState::Pending => {
                    slot.state = AioState::InProgress;
                }
                AioState::InProgress => {
                    slot.state = AioState::Completed;
                    slot.result = slot.cb.nbytes as i64;
                    slot.error_code = 0;
                    self.completed_count += 1;
                }
                _ => {}
            }
        }
    }

    /// Cancels and deactivates all requests owned by `pid`.
    ///
    /// Called during process teardown to ensure no stale requests
    /// remain in the context.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for slot in &mut self.requests {
            if slot.active && slot.owner_pid == pid {
                slot.state = AioState::Canceled;
                slot.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Returns the number of active requests.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active requests.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Allocates a slot and records a new request.
    fn submit_request(&mut self, cb: &AioCb, pid: u64) -> Result<u32> {
        if self.count >= MAX_AIO_REQUESTS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .requests
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        *slot = AioRequest {
            id,
            cb: *cb,
            state: AioState::Pending,
            result: 0,
            error_code: 0,
            owner_pid: pid,
            active: true,
        };

        self.count += 1;
        Ok(id)
    }

    /// Finds an active request by ID (immutable).
    fn find_request(&self, id: u32) -> Result<&AioRequest> {
        self.requests
            .iter()
            .find(|r| r.active && r.id == id)
            .ok_or(Error::NotFound)
    }

    /// Finds the index of an active request by ID.
    fn find_request_index(&self, id: u32) -> Result<usize> {
        self.requests
            .iter()
            .position(|r| r.active && r.id == id)
            .ok_or(Error::NotFound)
    }
}
