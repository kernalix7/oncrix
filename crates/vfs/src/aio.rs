// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX Asynchronous I/O (AIO).
//!
//! Implements the POSIX.1-2024 asynchronous I/O interface, allowing
//! user-space applications to submit read, write, and fsync requests
//! that execute without blocking the calling thread.
//!
//! # Architecture
//!
//! ```text
//! User space                     Kernel AIO subsystem
//! ─────────                      ────────────────────
//! aio_read(aiocbp)        ──►  AioContext::submit()
//!   │                              │
//!   │                              ▼
//!   │                          submit_queue (priority-ordered)
//!   │                              │
//!   │                              ▼
//!   │                          process_queue() — execute I/O
//!   │                              │
//!   │                              ▼
//!   │                          completion_ring (results)
//!   │                              │
//! aio_error(aiocbp)       ◄──  check status
//! aio_return(aiocbp)      ◄──  retrieve result
//! aio_suspend(list, n, t) ◄──  wait for completion
//! ```
//!
//! # Structures
//!
//! - [`AioOpcode`] — operation type (Read, Write, Fsync, Nop)
//! - [`AioStatus`] — request lifecycle state
//! - [`SigEvent`] — notification method on completion
//! - [`AioCb`] — asynchronous I/O control block
//! - [`AioRequest`] — internal request wrapping an AioCb with metadata
//! - [`CompletionEntry`] — result of a completed AIO request
//! - [`AioContext`] — main AIO engine with submit queue and completion ring
//!
//! # POSIX functions
//!
//! - [`aio_read`] — enqueue an asynchronous read
//! - [`aio_write`] — enqueue an asynchronous write
//! - [`aio_fsync`] — enqueue an asynchronous fsync
//! - [`aio_error`] — query the status of a request
//! - [`aio_return`] — retrieve the result of a completed request
//! - [`aio_suspend`] — wait for one or more requests to complete
//! - [`aio_cancel`] — attempt to cancel a pending request
//! - [`lio_listio`] — submit a batch of AIO requests
//!
//! # References
//!
//! - POSIX.1-2024 `<aio.h>` and associated function specifications
//! - Linux `io_submit(2)` / `io_getevents(2)` (kernel AIO)

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of pending AIO requests per context.
const MAX_AIO_REQUESTS: usize = 256;

/// Maximum number of entries in the completion ring.
const MAX_COMPLETIONS: usize = 256;

/// Maximum number of requests in a single `lio_listio` batch.
const MAX_LIO_BATCH: usize = 64;

/// Default priority for AIO requests (middle of range).
const DEFAULT_PRIORITY: i32 = 0;

/// EINPROGRESS — operation is in progress (POSIX aio_error return).
pub const AIO_EINPROGRESS: i32 = -115;

/// AIO_CANCELED — request was successfully canceled.
pub const AIO_CANCELED: i32 = 0;

/// AIO_NOTCANCELED — request could not be canceled (in progress).
pub const AIO_NOTCANCELED: i32 = 1;

/// AIO_ALLDONE — request already completed.
pub const AIO_ALLDONE: i32 = 2;

/// LIO_WAIT — lio_listio blocks until all requests complete.
pub const LIO_WAIT: i32 = 0;

/// LIO_NOWAIT — lio_listio returns immediately after submission.
pub const LIO_NOWAIT: i32 = 1;

// ── AioOpcode ───────────────────────────────────────────────────

/// Asynchronous I/O operation type.
///
/// Each [`AioCb`] carries an opcode that determines which I/O
/// operation the kernel performs when the request is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AioOpcode {
    /// Asynchronous read (`aio_read`).
    Read = 0,
    /// Asynchronous write (`aio_write`).
    Write = 1,
    /// Asynchronous fsync (`aio_fsync`).
    Fsync = 2,
    /// No-op (used internally or for `lio_listio` skip entries).
    Nop = 3,
}

impl AioOpcode {
    /// Convert from a raw `u8` value.
    pub fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Fsync),
            3 => Some(Self::Nop),
            _ => None,
        }
    }
}

impl core::fmt::Display for AioOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read => write!(f, "AIO_READ"),
            Self::Write => write!(f, "AIO_WRITE"),
            Self::Fsync => write!(f, "AIO_FSYNC"),
            Self::Nop => write!(f, "AIO_NOP"),
        }
    }
}

// ── AioStatus ───────────────────────────────────────────────────

/// Lifecycle state of an AIO request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AioStatus {
    /// Request is queued but not yet started.
    Pending = 0,
    /// Request is currently being executed.
    InProgress = 1,
    /// Request completed successfully.
    Completed = 2,
    /// Request completed with an error.
    Error = 3,
    /// Request was canceled before execution.
    Canceled = 4,
}

impl core::fmt::Display for AioStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::InProgress => write!(f, "IN_PROGRESS"),
            Self::Completed => write!(f, "COMPLETED"),
            Self::Error => write!(f, "ERROR"),
            Self::Canceled => write!(f, "CANCELED"),
        }
    }
}

// ── SigEvent notification ───────────────────────────────────────

/// Signal event notification method.
///
/// Determines how the calling process is notified when an AIO
/// request completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigEvNotify {
    /// No notification.
    None = 0,
    /// Deliver a signal.
    Signal = 1,
    /// Invoke a callback in a new thread (user-space integration).
    Thread = 2,
}

/// Signal event descriptor (simplified `struct sigevent`).
///
/// POSIX `sigevent` controls how completion notification is
/// delivered. This structure stores the notification method and
/// the signal number (if applicable).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SigEvent {
    /// Notification method.
    pub notify: SigEvNotify,
    /// Signal number (meaningful when `notify == Signal`).
    pub signo: i32,
    /// Opaque value passed to signal handler or thread.
    pub value: u64,
}

impl SigEvent {
    /// Create a no-notification sigevent.
    pub const fn none() -> Self {
        Self {
            notify: SigEvNotify::None,
            signo: 0,
            value: 0,
        }
    }

    /// Create a signal-notification sigevent.
    pub const fn signal(signo: i32, value: u64) -> Self {
        Self {
            notify: SigEvNotify::Signal,
            signo,
            value,
        }
    }

    /// Create a thread-notification sigevent.
    pub const fn thread(value: u64) -> Self {
        Self {
            notify: SigEvNotify::Thread,
            signo: 0,
            value,
        }
    }
}

// ── AioCb ─────────────────────────────────────────────────────

/// Asynchronous I/O control block.
///
/// This is the kernel-internal representation of the POSIX
/// `struct aiocb`. User space fills in the fields and passes it
/// to `aio_read`, `aio_write`, `aio_fsync`, or `lio_listio`.
///
/// # Fields
///
/// - `aio_fildes`  — file descriptor for the I/O operation
/// - `aio_offset`  — file offset for read/write (ignored for fsync)
/// - `aio_buf`     — user-space buffer address
/// - `aio_nbytes`  — number of bytes to transfer
/// - `aio_opcode`  — operation type
/// - `aio_reqprio` — priority adjustment (lower = higher priority)
/// - `aio_sigevent` — completion notification method
/// - `aio_status`  — current request status (set by kernel)
/// - `aio_result`  — bytes transferred or negative errno
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AioCb {
    /// File descriptor.
    pub aio_fildes: i32,
    /// File offset for the I/O operation.
    pub aio_offset: i64,
    /// User-space buffer pointer (opaque to kernel, validated later).
    pub aio_buf: usize,
    /// Number of bytes to transfer.
    pub aio_nbytes: usize,
    /// Operation type.
    pub aio_opcode: AioOpcode,
    /// Request priority offset (POSIX `aio_reqprio`).
    ///
    /// Added to the calling process's scheduling priority. A value
    /// of 0 means default priority. Negative values increase
    /// priority, positive values decrease it.
    pub aio_reqprio: i32,
    /// Completion notification settings.
    pub aio_sigevent: SigEvent,
    /// Current status of this request (managed by kernel).
    pub aio_status: AioStatus,
    /// Result: bytes transferred on success, negative errno on error.
    pub aio_result: isize,
}

impl AioCb {
    /// Create a new AIO control block for a read operation.
    pub const fn new_read(fd: i32, offset: i64, buf: usize, nbytes: usize) -> Self {
        Self {
            aio_fildes: fd,
            aio_offset: offset,
            aio_buf: buf,
            aio_nbytes: nbytes,
            aio_opcode: AioOpcode::Read,
            aio_reqprio: DEFAULT_PRIORITY,
            aio_sigevent: SigEvent::none(),
            aio_status: AioStatus::Pending,
            aio_result: 0,
        }
    }

    /// Create a new AIO control block for a write operation.
    pub const fn new_write(fd: i32, offset: i64, buf: usize, nbytes: usize) -> Self {
        Self {
            aio_fildes: fd,
            aio_offset: offset,
            aio_buf: buf,
            aio_nbytes: nbytes,
            aio_opcode: AioOpcode::Write,
            aio_reqprio: DEFAULT_PRIORITY,
            aio_sigevent: SigEvent::none(),
            aio_status: AioStatus::Pending,
            aio_result: 0,
        }
    }

    /// Create a new AIO control block for an fsync operation.
    pub const fn new_fsync(fd: i32) -> Self {
        Self {
            aio_fildes: fd,
            aio_offset: 0,
            aio_buf: 0,
            aio_nbytes: 0,
            aio_opcode: AioOpcode::Fsync,
            aio_reqprio: DEFAULT_PRIORITY,
            aio_sigevent: SigEvent::none(),
            aio_status: AioStatus::Pending,
            aio_result: 0,
        }
    }

    /// Create a no-op AIO control block.
    pub const fn nop() -> Self {
        Self {
            aio_fildes: -1,
            aio_offset: 0,
            aio_buf: 0,
            aio_nbytes: 0,
            aio_opcode: AioOpcode::Nop,
            aio_reqprio: DEFAULT_PRIORITY,
            aio_sigevent: SigEvent::none(),
            aio_status: AioStatus::Completed,
            aio_result: 0,
        }
    }

    /// Returns `true` if the request has finished.
    pub fn is_done(&self) -> bool {
        matches!(
            self.aio_status,
            AioStatus::Completed | AioStatus::Error | AioStatus::Canceled
        )
    }
}

// ── AioRequest ────────────────────────────────────────────────

/// Internal request wrapper around an [`AioCb`].
///
/// Adds kernel-managed metadata: a unique request ID, the
/// submitting process's PID, and an effective priority computed
/// from the base process priority plus `aio_reqprio`.
#[derive(Debug, Clone, Copy)]
pub struct AioRequest {
    /// Unique request identifier within the context.
    pub id: u64,
    /// PID of the submitting process.
    pub pid: u64,
    /// The AIO control block.
    pub cb: AioCb,
    /// Effective priority (base_priority + aio_reqprio).
    /// Lower values are executed first.
    pub effective_priority: i32,
}

// ── CompletionEntry ─────────────────────────────────────────

/// A single entry in the completion ring.
///
/// Contains the result of a completed (or failed / canceled) AIO
/// request. The user-space caller retrieves these via `aio_return`
/// or `aio_suspend`.
#[derive(Debug, Clone, Copy)]
pub struct CompletionEntry {
    /// Request ID that completed.
    pub request_id: u64,
    /// PID of the process that submitted the request.
    pub pid: u64,
    /// File descriptor the operation targeted.
    pub fd: i32,
    /// Operation that was performed.
    pub opcode: AioOpcode,
    /// Final status.
    pub status: AioStatus,
    /// Bytes transferred (or negative errno).
    pub result: isize,
    /// Sigevent for notification delivery.
    pub sigevent: SigEvent,
    /// Whether this entry is active (occupied).
    pub active: bool,
}

impl CompletionEntry {
    /// Create an empty (inactive) completion entry.
    const fn empty() -> Self {
        Self {
            request_id: 0,
            pid: 0,
            fd: 0,
            opcode: AioOpcode::Nop,
            status: AioStatus::Pending,
            result: 0,
            sigevent: SigEvent::none(),
            active: false,
        }
    }
}

// ── AioContext ───────────────────────────────────────────────

/// AIO context managing a submission queue and completion ring.
///
/// Each context supports up to [`MAX_AIO_REQUESTS`] in-flight
/// requests. Requests are ordered by effective priority and
/// processed in priority order by [`AioContext::process_queue`].
pub struct AioContext {
    /// Maximum number of events this context can hold.
    max_events: usize,
    /// Submission queue (priority-ordered on insertion).
    submit_queue: [Option<AioRequest>; MAX_AIO_REQUESTS],
    /// Number of requests in the submit queue.
    submit_count: usize,
    /// Completion ring buffer.
    completions: [CompletionEntry; MAX_COMPLETIONS],
    /// Write index into the completion ring.
    comp_write: usize,
    /// Number of active entries in the completion ring.
    comp_count: usize,
    /// Monotonically increasing request ID counter.
    next_id: u64,
    /// Total requests submitted over the lifetime of this context.
    total_submitted: u64,
    /// Total requests completed over the lifetime of this context.
    total_completed: u64,
}

impl Default for AioContext {
    fn default() -> Self {
        Self::new(MAX_AIO_REQUESTS)
    }
}

impl AioContext {
    /// Create a new AIO context with the given maximum event count.
    ///
    /// `max_events` is clamped to [`MAX_AIO_REQUESTS`].
    pub fn new(max_events: usize) -> Self {
        const NONE_REQ: Option<AioRequest> = None;
        Self {
            max_events: if max_events > MAX_AIO_REQUESTS {
                MAX_AIO_REQUESTS
            } else if max_events == 0 {
                1
            } else {
                max_events
            },
            submit_queue: [NONE_REQ; MAX_AIO_REQUESTS],
            submit_count: 0,
            completions: [CompletionEntry::empty(); MAX_COMPLETIONS],
            comp_write: 0,
            comp_count: 0,
            next_id: 1,
            total_submitted: 0,
            total_completed: 0,
        }
    }

    /// Submit an AIO request.
    ///
    /// The request is inserted into the submission queue ordered by
    /// effective priority (lower value = higher priority). Equal
    /// priorities are ordered FIFO.
    ///
    /// # Arguments
    ///
    /// - `pid` — PID of the submitting process
    /// - `cb` — the AIO control block describing the operation
    /// - `base_priority` — the process's base scheduling priority
    ///
    /// # Returns
    ///
    /// The unique request ID assigned to this submission.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — submit queue is full
    /// - [`Error::InvalidArgument`] — invalid fd or opcode
    pub fn submit(&mut self, pid: u64, mut cb: AioCb, base_priority: i32) -> Result<u64> {
        if cb.aio_fildes < 0 && cb.aio_opcode != AioOpcode::Nop {
            return Err(Error::InvalidArgument);
        }
        if self.submit_count >= self.max_events {
            return Err(Error::OutOfMemory);
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        cb.aio_status = AioStatus::Pending;
        cb.aio_result = 0;

        let effective_priority = base_priority.saturating_add(cb.aio_reqprio);

        let request = AioRequest {
            id,
            pid,
            cb,
            effective_priority,
        };

        // Find insertion point: first slot with higher priority value.
        let mut insert_idx = self.submit_count;
        for i in 0..self.submit_count {
            if let Some(existing) = &self.submit_queue[i] {
                if existing.effective_priority > effective_priority {
                    insert_idx = i;
                    break;
                }
            }
        }

        // Shift elements right to make room at insert_idx.
        let mut j = self.submit_count;
        while j > insert_idx {
            self.submit_queue[j] = self.submit_queue[j - 1].take();
            j -= 1;
        }

        self.submit_queue[insert_idx] = Some(request);
        self.submit_count += 1;
        self.total_submitted += 1;

        Ok(id)
    }

    /// Process pending requests in the submission queue.
    ///
    /// Dequeues requests in priority order (lowest effective_priority
    /// first) and invokes the handler function for each. The handler
    /// returns `Ok(bytes_transferred)` on success or `Err(error)` on
    /// failure.
    ///
    /// If `max_batch` is 0, all pending requests are processed.
    ///
    /// Returns the number of requests processed.
    pub fn process_queue<F>(&mut self, max_batch: usize, mut handler: F) -> usize
    where
        F: FnMut(&AioRequest) -> Result<isize>,
    {
        let limit = if max_batch == 0 {
            self.submit_count
        } else {
            max_batch.min(self.submit_count)
        };

        let mut processed = 0;

        for _ in 0..limit {
            let request = match self.take_first_request() {
                Some(r) => r,
                None => break,
            };

            let mut completed_req = request;
            completed_req.cb.aio_status = AioStatus::InProgress;

            match handler(&completed_req) {
                Ok(bytes) => {
                    completed_req.cb.aio_status = AioStatus::Completed;
                    completed_req.cb.aio_result = bytes;
                }
                Err(_) => {
                    completed_req.cb.aio_status = AioStatus::Error;
                    completed_req.cb.aio_result = -1;
                }
            }

            self.post_completion(&completed_req);
            processed += 1;
        }

        processed
    }

    /// Query the error status of a request (POSIX `aio_error`).
    ///
    /// - Returns `0` if completed successfully
    /// - Returns [`AIO_EINPROGRESS`] if still pending
    /// - Returns a positive error number on failure
    pub fn aio_error(&self, request_id: u64) -> Result<i32> {
        // Check submit queue.
        for slot in &self.submit_queue {
            if let Some(req) = slot {
                if req.id == request_id {
                    return Ok(AIO_EINPROGRESS);
                }
            }
        }

        // Check completion ring.
        for entry in &self.completions {
            if entry.active && entry.request_id == request_id {
                return match entry.status {
                    AioStatus::Completed => Ok(0),
                    AioStatus::Error => Ok(entry.result as i32),
                    AioStatus::Canceled => Ok(AIO_CANCELED),
                    _ => Ok(AIO_EINPROGRESS),
                };
            }
        }

        Err(Error::InvalidArgument)
    }

    /// Retrieve the return value of a completed request.
    ///
    /// POSIX `aio_return` semantics. The completion entry is
    /// consumed after this call.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — unknown request ID
    /// - [`Error::WouldBlock`] — request not yet completed
    pub fn aio_return(&mut self, request_id: u64) -> Result<isize> {
        for entry in &mut self.completions {
            if entry.active && entry.request_id == request_id {
                match entry.status {
                    AioStatus::Completed | AioStatus::Error | AioStatus::Canceled => {
                        let result = entry.result;
                        entry.active = false;
                        self.comp_count = self.comp_count.saturating_sub(1);
                        self.total_completed += 1;
                        return Ok(result);
                    }
                    _ => return Err(Error::WouldBlock),
                }
            }
        }

        // Check if still pending in submit queue.
        for slot in &self.submit_queue {
            if let Some(req) = slot {
                if req.id == request_id {
                    return Err(Error::WouldBlock);
                }
            }
        }

        Err(Error::InvalidArgument)
    }

    /// Wait for at least one request from `list` to complete.
    ///
    /// Returns `Ok(())` if at least one has completed, or
    /// `Err(WouldBlock)` if none have (caller should retry/sleep).
    ///
    /// # Errors
    ///
    /// - [`Error::WouldBlock`] — no requests have completed yet
    /// - [`Error::InvalidArgument`] — empty list
    pub fn aio_suspend(&self, list: &[u64]) -> Result<()> {
        if list.is_empty() {
            return Err(Error::InvalidArgument);
        }

        for &req_id in list {
            if req_id == 0 {
                continue;
            }
            for entry in &self.completions {
                if entry.active && entry.request_id == req_id {
                    match entry.status {
                        AioStatus::Completed | AioStatus::Error | AioStatus::Canceled => {
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }

        Err(Error::WouldBlock)
    }

    /// Cancel AIO request(s).
    ///
    /// If `request_id` is 0, cancel all requests for `fd`.
    /// Otherwise cancel the specific request.
    ///
    /// # Returns
    ///
    /// - [`AIO_CANCELED`] — all targeted requests were canceled
    /// - [`AIO_NOTCANCELED`] — some could not be canceled
    /// - [`AIO_ALLDONE`] — all targeted requests already completed
    pub fn aio_cancel(&mut self, fd: i32, request_id: u64) -> Result<i32> {
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }

        let cancel_all = request_id == 0;
        let mut canceled = 0u32;
        let mut not_canceled = 0u32;
        let mut found = false;

        // Collect indices to cancel to avoid double-borrow issues.
        let mut cancel_indices = [false; MAX_AIO_REQUESTS];
        let mut inprogress_indices = [false; MAX_AIO_REQUESTS];

        for i in 0..MAX_AIO_REQUESTS {
            if let Some(req) = &self.submit_queue[i] {
                let matches = if cancel_all {
                    req.cb.aio_fildes == fd
                } else {
                    req.id == request_id
                };

                if !matches {
                    continue;
                }
                found = true;

                match req.cb.aio_status {
                    AioStatus::Pending => {
                        cancel_indices[i] = true;
                    }
                    AioStatus::InProgress => {
                        inprogress_indices[i] = true;
                    }
                    _ => {}
                }

                if !cancel_all {
                    break;
                }
            }
        }

        // Process cancellations.
        for i in 0..MAX_AIO_REQUESTS {
            if cancel_indices[i] {
                if let Some(req) = self.submit_queue[i].take() {
                    let mut canceled_req = req;
                    canceled_req.cb.aio_status = AioStatus::Canceled;
                    canceled_req.cb.aio_result = -1;
                    self.post_completion(&canceled_req);
                    self.submit_count = self.submit_count.saturating_sub(1);
                    canceled += 1;
                }
            }
            if inprogress_indices[i] {
                not_canceled += 1;
            }
        }

        if !found && !cancel_all {
            for entry in &self.completions {
                if entry.active && entry.request_id == request_id {
                    return Ok(AIO_ALLDONE);
                }
            }
            return Err(Error::InvalidArgument);
        }

        if not_canceled > 0 {
            Ok(AIO_NOTCANCELED)
        } else if canceled > 0 {
            Ok(AIO_CANCELED)
        } else {
            Ok(AIO_ALLDONE)
        }
    }

    /// Get a specific completion result by request ID without
    /// consuming it.
    pub fn get_result(&self, request_id: u64) -> Option<&CompletionEntry> {
        for entry in &self.completions {
            if entry.active && entry.request_id == request_id {
                return Some(entry);
            }
        }
        None
    }

    /// Return the number of pending requests in the submit queue.
    pub fn pending_count(&self) -> usize {
        self.submit_count
    }

    /// Return the number of active completion entries.
    pub fn completion_count(&self) -> usize {
        self.comp_count
    }

    /// Return total requests submitted over the context lifetime.
    pub fn total_submitted(&self) -> u64 {
        self.total_submitted
    }

    /// Return total requests completed over the context lifetime.
    pub fn total_completed(&self) -> u64 {
        self.total_completed
    }

    /// Return the maximum number of events for this context.
    pub fn max_events(&self) -> usize {
        self.max_events
    }

    /// Compact the completion ring, removing consumed entries.
    pub fn compact_completions(&mut self) {
        let mut write_idx = 0;
        for read_idx in 0..MAX_COMPLETIONS {
            if self.completions[read_idx].active {
                if write_idx != read_idx {
                    self.completions[write_idx] = self.completions[read_idx];
                    self.completions[read_idx] = CompletionEntry::empty();
                }
                write_idx += 1;
            }
        }
        self.comp_write = write_idx;
    }

    /// Drain completed notifications for signal delivery.
    ///
    /// Returns up to `max` completion entries that have pending
    /// signal notifications, along with the count of valid entries.
    pub fn drain_notifications(
        &mut self,
        max: usize,
    ) -> ([CompletionEntry; MAX_COMPLETIONS], usize) {
        let mut result = [CompletionEntry::empty(); MAX_COMPLETIONS];
        let mut count = 0;
        let limit = max.min(MAX_COMPLETIONS);

        for entry in &mut self.completions {
            if count >= limit {
                break;
            }
            if entry.active
                && entry.sigevent.notify != SigEvNotify::None
                && matches!(
                    entry.status,
                    AioStatus::Completed | AioStatus::Error | AioStatus::Canceled
                )
            {
                result[count] = *entry;
                count += 1;
                // Clear sigevent to prevent re-delivery.
                entry.sigevent = SigEvent::none();
            }
        }

        (result, count)
    }

    // ── Private helpers ───────────────────────────────────────

    /// Take the first (highest priority) request from the queue.
    fn take_first_request(&mut self) -> Option<AioRequest> {
        if self.submit_count == 0 {
            return None;
        }

        // First entry is always highest priority due to sorted
        // insertion.
        let req = self.submit_queue[0].take();

        // Shift remaining entries left.
        let mut j = 0;
        while j + 1 < self.submit_count {
            self.submit_queue[j] = self.submit_queue[j + 1].take();
            j += 1;
        }
        self.submit_count -= 1;

        req
    }

    /// Post a completed request to the completion ring.
    fn post_completion(&mut self, req: &AioRequest) {
        // Find a free slot, or overwrite at comp_write.
        let mut slot_idx = None;
        for i in 0..MAX_COMPLETIONS {
            if !self.completions[i].active {
                slot_idx = Some(i);
                break;
            }
        }

        let idx = match slot_idx {
            Some(i) => i,
            None => {
                // Ring full — overwrite at write pointer.
                let i = self.comp_write % MAX_COMPLETIONS;
                if self.completions[i].active {
                    self.comp_count = self.comp_count.saturating_sub(1);
                }
                i
            }
        };

        self.completions[idx] = CompletionEntry {
            request_id: req.id,
            pid: req.pid,
            fd: req.cb.aio_fildes,
            opcode: req.cb.aio_opcode,
            status: req.cb.aio_status,
            result: req.cb.aio_result,
            sigevent: req.cb.aio_sigevent,
            active: true,
        };

        self.comp_write = (idx + 1) % MAX_COMPLETIONS;
        self.comp_count += 1;
    }
}

// ── Public API functions (POSIX interface) ───────────────────

/// Submit an asynchronous read request.
///
/// POSIX `aio_read()`: enqueues a read operation described by `cb`.
/// The file descriptor `cb.aio_fildes` is read starting at offset
/// `cb.aio_offset` for `cb.aio_nbytes` bytes.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd or opcode mismatch
/// - [`Error::OutOfMemory`] — submission queue full
pub fn aio_read(ctx: &mut AioContext, pid: u64, cb: AioCb, base_priority: i32) -> Result<u64> {
    if cb.aio_opcode != AioOpcode::Read {
        return Err(Error::InvalidArgument);
    }
    if cb.aio_nbytes == 0 {
        return Err(Error::InvalidArgument);
    }
    ctx.submit(pid, cb, base_priority)
}

/// Submit an asynchronous write request.
///
/// POSIX `aio_write()`: enqueues a write operation described by
/// `cb`. The buffer at `cb.aio_buf` is written to file descriptor
/// `cb.aio_fildes` starting at offset `cb.aio_offset`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd or opcode mismatch
/// - [`Error::OutOfMemory`] — submission queue full
pub fn aio_write(ctx: &mut AioContext, pid: u64, cb: AioCb, base_priority: i32) -> Result<u64> {
    if cb.aio_opcode != AioOpcode::Write {
        return Err(Error::InvalidArgument);
    }
    if cb.aio_nbytes == 0 {
        return Err(Error::InvalidArgument);
    }
    ctx.submit(pid, cb, base_priority)
}

/// Submit an asynchronous fsync request.
///
/// POSIX `aio_fsync()`: enqueues a file synchronization operation
/// for `cb.aio_fildes`.
///
/// # Arguments
///
/// - `op` — `O_SYNC` for full sync, `O_DSYNC` for data-only sync
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd or opcode mismatch
/// - [`Error::OutOfMemory`] — submission queue full
pub fn aio_fsync(
    ctx: &mut AioContext,
    pid: u64,
    cb: AioCb,
    _op: i32,
    base_priority: i32,
) -> Result<u64> {
    if cb.aio_opcode != AioOpcode::Fsync {
        return Err(Error::InvalidArgument);
    }
    ctx.submit(pid, cb, base_priority)
}

/// Query the error status of an AIO request.
///
/// POSIX `aio_error()` semantics.
pub fn aio_error(ctx: &AioContext, request_id: u64) -> Result<i32> {
    ctx.aio_error(request_id)
}

/// Retrieve the return value of a completed request.
///
/// POSIX `aio_return()` semantics. May only be called once per
/// completed request.
pub fn aio_return(ctx: &mut AioContext, request_id: u64) -> Result<isize> {
    ctx.aio_return(request_id)
}

/// Wait for completion of one or more AIO requests.
///
/// POSIX `aio_suspend()` semantics. Returns `Err(WouldBlock)` if
/// none of the listed requests have completed.
pub fn aio_suspend(ctx: &AioContext, list: &[u64]) -> Result<()> {
    ctx.aio_suspend(list)
}

/// Cancel one or more AIO requests.
///
/// POSIX `aio_cancel()` semantics. If `request_id` is 0, cancel all
/// pending requests on `fd`.
pub fn aio_cancel(ctx: &mut AioContext, fd: i32, request_id: u64) -> Result<i32> {
    ctx.aio_cancel(fd, request_id)
}

/// Submit a batch of AIO requests atomically.
///
/// POSIX `lio_listio()`: submits up to [`MAX_LIO_BATCH`] requests
/// in a single call.
///
/// # Arguments
///
/// - `mode` — [`LIO_WAIT`] or [`LIO_NOWAIT`]
/// - `list` — slice of AIO control blocks to submit
/// - `pid` — PID of the submitting process
/// - `base_priority` — base scheduling priority
///
/// # Returns
///
/// Array of request IDs and count of successful submissions.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid mode or list too large
/// - [`Error::OutOfMemory`] — submission queue capacity exceeded
pub fn lio_listio(
    ctx: &mut AioContext,
    mode: i32,
    list: &[AioCb],
    pid: u64,
    base_priority: i32,
) -> Result<([u64; MAX_LIO_BATCH], usize)> {
    if mode != LIO_WAIT && mode != LIO_NOWAIT {
        return Err(Error::InvalidArgument);
    }
    if list.len() > MAX_LIO_BATCH {
        return Err(Error::InvalidArgument);
    }

    let mut ids = [0u64; MAX_LIO_BATCH];
    let mut submitted = 0;
    let mut first_err: Option<Error> = None;

    for (i, cb) in list.iter().enumerate() {
        if cb.aio_opcode == AioOpcode::Nop {
            continue;
        }

        match ctx.submit(pid, *cb, base_priority) {
            Ok(id) => {
                ids[i] = id;
                submitted += 1;
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    if submitted == 0 {
        if let Some(e) = first_err {
            return Err(e);
        }
    }

    // In LIO_WAIT mode, the caller should loop on aio_suspend
    // for all submitted IDs until complete.

    Ok((ids, submitted))
}
