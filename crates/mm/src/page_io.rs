// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page I/O subsystem — swap read/write and anonymous page I/O.
//!
//! Manages the submission and completion of I/O requests for pages being
//! swapped out to or read back from swap storage. The subsystem provides:
//!
//! - **Swap write** — serialise a page's contents into a swap slot
//! - **Swap read** — deserialise a page's contents from a swap slot
//! - **I/O completion** — handle finished I/O requests and wake waiters
//! - **Error accounting** — track swap I/O errors per device
//!
//! The `PageIo` type acts as the central dispatcher, maintaining a queue
//! of in-flight requests and a completion ring for finished ones. Actual
//! block-device I/O is abstracted behind an [`IoBackend`] trait so tests
//! can inject a mock implementation.
//!
//! # Types
//!
//! - [`IoDirection`] — read (swap-in) or write (swap-out)
//! - [`IoStatus`] — pending, in-flight, completed, or errored
//! - [`PageIoRequest`] — one unit of page I/O work
//! - [`IoCompletion`] — result of a finished request
//! - [`PageIoStats`] — aggregate I/O counters
//! - [`PageIo`] — the central I/O dispatcher
//!
//! Reference: Linux `mm/page_io.c`, `mm/swap_state.c`, `include/linux/swap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Maximum number of in-flight page I/O requests.
const MAX_INFLIGHT: usize = 64;

/// Maximum number of completed requests in the ring buffer.
const COMPLETION_RING_SIZE: usize = 128;

/// Maximum number of I/O error records stored.
const MAX_ERROR_RECORDS: usize = 16;

/// Timeout in ticks before an in-flight request is considered stale.
const IO_TIMEOUT_TICKS: u64 = 5000;

// -------------------------------------------------------------------
// IoDirection
// -------------------------------------------------------------------

/// Direction of a page I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    /// Read from swap storage into memory (swap-in / page-in).
    Read,
    /// Write from memory to swap storage (swap-out / page-out).
    Write,
}

// -------------------------------------------------------------------
// IoStatus
// -------------------------------------------------------------------

/// Status of a page I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IoStatus {
    /// Request has been created but not yet submitted.
    #[default]
    Pending,
    /// Request has been submitted and is in-flight.
    InFlight,
    /// Request completed successfully.
    Completed,
    /// Request failed with an error.
    Error,
    /// Request was cancelled before submission.
    Cancelled,
}

// -------------------------------------------------------------------
// PageIoRequest
// -------------------------------------------------------------------

/// A single page I/O request.
///
/// Represents one unit of work: reading or writing one page of data
/// to/from a swap slot identified by `(device_id, slot_index)`.
#[derive(Debug, Clone)]
pub struct PageIoRequest {
    /// Unique request identifier.
    pub id: u64,
    /// I/O direction.
    pub direction: IoDirection,
    /// Swap device identifier.
    pub device_id: u32,
    /// Slot index within the swap device.
    pub slot_index: u64,
    /// Physical frame number of the source/destination page.
    pub pfn: u64,
    /// Current status.
    pub status: IoStatus,
    /// Monotonic tick when the request was submitted.
    pub submit_tick: u64,
    /// Monotonic tick when the request completed.
    pub complete_tick: u64,
    /// I/O error code (0 = no error).
    pub error_code: i32,
    /// Page data buffer.
    pub data: [u8; PAGE_SIZE],
}

impl PageIoRequest {
    /// Creates a new page I/O request.
    pub fn new(id: u64, direction: IoDirection, device_id: u32, slot_index: u64, pfn: u64) -> Self {
        Self {
            id,
            direction,
            device_id,
            slot_index,
            pfn,
            status: IoStatus::Pending,
            submit_tick: 0,
            complete_tick: 0,
            error_code: 0,
            data: [0u8; PAGE_SIZE],
        }
    }

    /// Returns `true` if the request is still active (not yet done).
    pub fn is_active(&self) -> bool {
        matches!(self.status, IoStatus::Pending | IoStatus::InFlight)
    }
}

// -------------------------------------------------------------------
// IoCompletion
// -------------------------------------------------------------------

/// The result of a completed page I/O request.
#[derive(Debug, Clone, Copy)]
pub struct IoCompletion {
    /// Request identifier this completion belongs to.
    pub request_id: u64,
    /// Whether the I/O succeeded.
    pub success: bool,
    /// Error code on failure (0 = no error).
    pub error_code: i32,
    /// Tick at which completion was recorded.
    pub tick: u64,
    /// Physical frame number of the completed page.
    pub pfn: u64,
    /// I/O direction that completed.
    pub direction: IoDirection,
}

// -------------------------------------------------------------------
// PageIoStats
// -------------------------------------------------------------------

/// Aggregate page I/O statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct PageIoStats {
    /// Total read requests submitted.
    pub reads_submitted: u64,
    /// Total write requests submitted.
    pub writes_submitted: u64,
    /// Read requests completed successfully.
    pub reads_completed: u64,
    /// Write requests completed successfully.
    pub writes_completed: u64,
    /// Read requests that failed.
    pub read_errors: u64,
    /// Write requests that failed.
    pub write_errors: u64,
    /// Requests cancelled.
    pub cancellations: u64,
    /// Requests that timed out.
    pub timeouts: u64,
}

impl PageIoStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            reads_submitted: 0,
            writes_submitted: 0,
            reads_completed: 0,
            writes_completed: 0,
            read_errors: 0,
            write_errors: 0,
            cancellations: 0,
            timeouts: 0,
        }
    }

    /// Total I/O errors (reads + writes).
    pub fn total_errors(&self) -> u64 {
        self.read_errors.saturating_add(self.write_errors)
    }

    /// Total completed I/O requests.
    pub fn total_completed(&self) -> u64 {
        self.reads_completed.saturating_add(self.writes_completed)
    }
}

// -------------------------------------------------------------------
// IoErrorRecord
// -------------------------------------------------------------------

/// Record of an I/O error for post-mortem analysis.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoErrorRecord {
    request_id: u64,
    device_id: u32,
    slot_index: u64,
    error_code: i32,
    direction: Option<IoDirection>,
    tick: u64,
}

// -------------------------------------------------------------------
// CompletionSlot
// -------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct CompletionSlot {
    occupied: bool,
    completion: Option<IoCompletion>,
}

// -------------------------------------------------------------------
// PageIo
// -------------------------------------------------------------------

/// Central page I/O dispatcher.
///
/// Manages up to [`MAX_INFLIGHT`] concurrent in-flight requests and
/// a ring of [`COMPLETION_RING_SIZE`] completed results available for
/// polling. Request slots are reused after completion.
pub struct PageIo {
    /// In-flight request pool.
    requests: [Option<PageIoRequest>; MAX_INFLIGHT],
    /// Number of currently active (in-flight + pending) requests.
    inflight_count: usize,
    /// Completion ring (circular).
    completions: [CompletionSlot; COMPLETION_RING_SIZE],
    /// Write index into the completion ring.
    completion_write: usize,
    /// Read index into the completion ring.
    completion_read: usize,
    /// Number of completions available to drain.
    completion_count: usize,
    /// I/O error records (most recent `MAX_ERROR_RECORDS`).
    errors: [IoErrorRecord; MAX_ERROR_RECORDS],
    /// Number of valid error records.
    error_count: usize,
    /// Monotonic tick counter.
    clock: u64,
    /// Next request ID.
    next_id: u64,
    /// Aggregate statistics.
    stats: PageIoStats,
}

impl PageIo {
    /// Creates a new page I/O dispatcher.
    pub const fn new() -> Self {
        Self {
            requests: [const { None }; MAX_INFLIGHT],
            inflight_count: 0,
            completions: [const {
                CompletionSlot {
                    occupied: false,
                    completion: None,
                }
            }; COMPLETION_RING_SIZE],
            completion_write: 0,
            completion_read: 0,
            completion_count: 0,
            errors: [const {
                IoErrorRecord {
                    request_id: 0,
                    device_id: 0,
                    slot_index: 0,
                    error_code: 0,
                    direction: None,
                    tick: 0,
                }
            }; MAX_ERROR_RECORDS],
            error_count: 0,
            clock: 0,
            next_id: 1,
            stats: PageIoStats::new(),
        }
    }

    /// Ticks the internal clock.
    pub fn tick(&mut self) {
        self.clock = self.clock.wrapping_add(1);
    }

    /// Submits a swap-read request for `pfn` from `(device_id, slot_index)`.
    ///
    /// Returns the request ID on success.
    ///
    /// # Errors
    ///
    /// - `Busy` — the in-flight request queue is full.
    pub fn submit_read(&mut self, device_id: u32, slot_index: u64, pfn: u64) -> Result<u64> {
        self.submit(IoDirection::Read, device_id, slot_index, pfn)
    }

    /// Submits a swap-write request for `pfn` to `(device_id, slot_index)`.
    ///
    /// Returns the request ID on success.
    pub fn submit_write(&mut self, device_id: u32, slot_index: u64, pfn: u64) -> Result<u64> {
        self.submit(IoDirection::Write, device_id, slot_index, pfn)
    }

    /// Copies data into a pending write request's buffer.
    ///
    /// Must be called before the request transitions to `InFlight`.
    pub fn set_write_data(&mut self, request_id: u64, data: &[u8; PAGE_SIZE]) -> Result<()> {
        for slot in self.requests.iter_mut() {
            if let Some(req) = slot {
                if req.id == request_id && req.direction == IoDirection::Write {
                    req.data.copy_from_slice(data);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Simulates completion of request `request_id`.
    ///
    /// In a real kernel this is driven by interrupt / DMA callback.
    /// `success` indicates whether the device reported success.
    pub fn complete_request(&mut self, request_id: u64, success: bool) -> Result<()> {
        let idx = self
            .requests
            .iter()
            .position(|s| s.as_ref().map(|r| r.id == request_id).unwrap_or(false))
            .ok_or(Error::NotFound)?;

        let req = self.requests[idx].as_mut().ok_or(Error::NotFound)?;
        let direction = req.direction;
        let pfn = req.pfn;
        let device_id = req.device_id;
        let slot_index = req.slot_index;
        let error_code: i32 = if success { 0 } else { -5 }; // EIO = 5

        req.status = if success {
            IoStatus::Completed
        } else {
            IoStatus::Error
        };
        req.complete_tick = self.clock;
        req.error_code = error_code;

        // Update stats
        match direction {
            IoDirection::Read => {
                if success {
                    self.stats.reads_completed += 1;
                } else {
                    self.stats.read_errors += 1;
                }
            }
            IoDirection::Write => {
                if success {
                    self.stats.writes_completed += 1;
                } else {
                    self.stats.write_errors += 1;
                }
            }
        }

        // Record error
        if !success {
            self.record_error(request_id, device_id, slot_index, error_code, direction);
        }

        // Push completion
        let completion = IoCompletion {
            request_id,
            success,
            error_code,
            tick: self.clock,
            pfn,
            direction,
        };
        self.push_completion(completion);

        // Free slot
        self.requests[idx] = None;
        self.inflight_count = self.inflight_count.saturating_sub(1);

        Ok(())
    }

    /// Cancels a pending (not yet in-flight) request.
    pub fn cancel_request(&mut self, request_id: u64) -> Result<()> {
        for slot in self.requests.iter_mut() {
            if let Some(req) = slot {
                if req.id == request_id {
                    if req.status == IoStatus::InFlight {
                        return Err(Error::Busy);
                    }
                    self.inflight_count = self.inflight_count.saturating_sub(1);
                    self.stats.cancellations += 1;
                    *slot = None;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Drains completed results into `out`, returning the count drained.
    pub fn drain_completions(&mut self, out: &mut [IoCompletion]) -> usize {
        let mut count = 0;
        while count < out.len() && self.completion_count > 0 {
            let slot = &mut self.completions[self.completion_read];
            if slot.occupied {
                if let Some(c) = slot.completion.take() {
                    out[count] = c;
                    count += 1;
                }
                slot.occupied = false;
                self.completion_read = (self.completion_read + 1) % COMPLETION_RING_SIZE;
                self.completion_count -= 1;
            }
        }
        count
    }

    /// Expires requests that have been in-flight beyond `IO_TIMEOUT_TICKS`.
    ///
    /// Returns the number of timed-out requests marked as errored.
    pub fn expire_stale(&mut self) -> usize {
        let clock = self.clock;
        let mut expired = 0usize;
        let mut to_expire: [u64; MAX_INFLIGHT] = [0u64; MAX_INFLIGHT];
        let mut n = 0usize;

        for slot in self.requests.iter() {
            if let Some(req) = slot {
                if req.status == IoStatus::InFlight
                    && clock.wrapping_sub(req.submit_tick) > IO_TIMEOUT_TICKS
                {
                    if n < MAX_INFLIGHT {
                        to_expire[n] = req.id;
                        n += 1;
                    }
                }
            }
        }

        for i in 0..n {
            if self.complete_request(to_expire[i], false).is_ok() {
                self.stats.timeouts += 1;
                expired += 1;
            }
        }
        expired
    }

    /// Returns the number of active in-flight requests.
    pub fn inflight_count(&self) -> usize {
        self.inflight_count
    }

    /// Returns a snapshot of I/O statistics.
    pub fn stats(&self) -> PageIoStats {
        self.stats
    }

    /// Returns the most recent I/O error records (up to `MAX_ERROR_RECORDS`).
    pub fn error_records(&self) -> &[IoErrorRecord] {
        &self.errors[..self.error_count]
    }

    // --- private helpers ---

    fn submit(
        &mut self,
        direction: IoDirection,
        device_id: u32,
        slot_index: u64,
        pfn: u64,
    ) -> Result<u64> {
        if self.inflight_count >= MAX_INFLIGHT {
            return Err(Error::Busy);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut req = PageIoRequest::new(id, direction, device_id, slot_index, pfn);
        req.status = IoStatus::InFlight;
        req.submit_tick = self.clock;

        for slot in self.requests.iter_mut() {
            if slot.is_none() {
                *slot = Some(req);
                self.inflight_count += 1;
                match direction {
                    IoDirection::Read => self.stats.reads_submitted += 1,
                    IoDirection::Write => self.stats.writes_submitted += 1,
                }
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn push_completion(&mut self, completion: IoCompletion) {
        if self.completion_count < COMPLETION_RING_SIZE {
            self.completions[self.completion_write] = CompletionSlot {
                occupied: true,
                completion: Some(completion),
            };
            self.completion_write = (self.completion_write + 1) % COMPLETION_RING_SIZE;
            self.completion_count += 1;
        }
        // If ring is full, oldest completion is silently dropped (overrun).
    }

    fn record_error(
        &mut self,
        request_id: u64,
        device_id: u32,
        slot_index: u64,
        error_code: i32,
        direction: IoDirection,
    ) {
        if self.error_count < MAX_ERROR_RECORDS {
            self.errors[self.error_count] = IoErrorRecord {
                request_id,
                device_id,
                slot_index,
                error_code,
                direction: Some(direction),
                tick: self.clock,
            };
            self.error_count += 1;
        } else {
            // Rotate: drop oldest, shift left, append.
            for i in 0..MAX_ERROR_RECORDS - 1 {
                self.errors[i] = self.errors[i + 1];
            }
            self.errors[MAX_ERROR_RECORDS - 1] = IoErrorRecord {
                request_id,
                device_id,
                slot_index,
                error_code,
                direction: Some(direction),
                tick: self.clock,
            };
        }
    }
}

impl Default for PageIo {
    fn default() -> Self {
        Self::new()
    }
}
