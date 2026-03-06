// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory balloon operations.
//!
//! Implements the operational interface for virtio/Hyper-V memory
//! balloons: inflate, deflate, free-page-hinting, and statistics
//! reporting. Coordinates with the hypervisor to dynamically adjust
//! guest memory.
//!
//! - [`BalloonOp`] — balloon operation type
//! - [`BalloonRequest`] — a pending balloon operation
//! - [`BalloonOpStats`] — operation statistics
//! - [`MemoryBalloonOps`] — the balloon operations manager
//!
//! Reference: Linux `drivers/virtio/virtio_balloon.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages per operation.
const MAX_PAGES_PER_OP: usize = 256;

/// Maximum pending requests.
const MAX_REQUESTS: usize = 64;

/// Maximum free-page hints.
const MAX_FREE_HINTS: usize = 128;

// -------------------------------------------------------------------
// BalloonOp
// -------------------------------------------------------------------

/// Balloon operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalloonOp {
    /// Inflate — take pages from guest.
    #[default]
    Inflate,
    /// Deflate — return pages to guest.
    Deflate,
    /// Free-page hinting — hint to host about free pages.
    FreePageHint,
    /// Reporting — report statistics to host.
    Report,
}

// -------------------------------------------------------------------
// BalloonRequest
// -------------------------------------------------------------------

/// A pending balloon operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonRequest {
    /// Operation type.
    pub op: BalloonOp,
    /// Number of pages requested.
    pub nr_pages: u64,
    /// Pages completed.
    pub pages_done: u64,
    /// Whether the request is complete.
    pub complete: bool,
    /// Whether this entry is active.
    pub active: bool,
}

impl BalloonRequest {
    /// Creates a new request.
    pub fn new(op: BalloonOp, nr_pages: u64) -> Self {
        Self {
            op,
            nr_pages,
            pages_done: 0,
            complete: false,
            active: true,
        }
    }

    /// Returns the progress ratio (per-mille).
    pub fn progress(&self) -> u32 {
        if self.nr_pages == 0 {
            return 1000;
        }
        ((self.pages_done * 1000) / self.nr_pages) as u32
    }
}

// -------------------------------------------------------------------
// FreePageHint
// -------------------------------------------------------------------

/// A free-page hint for the hypervisor.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreePageHint {
    /// PFN of the free page.
    pub pfn: u64,
    /// Order (number of contiguous pages = 2^order).
    pub order: u32,
    /// Whether this hint has been sent.
    pub sent: bool,
}

// -------------------------------------------------------------------
// BalloonOpStats
// -------------------------------------------------------------------

/// Balloon operation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonOpStats {
    /// Total inflate operations.
    pub inflates: u64,
    /// Total deflate operations.
    pub deflates: u64,
    /// Total pages inflated.
    pub pages_inflated: u64,
    /// Total pages deflated.
    pub pages_deflated: u64,
    /// Free-page hints sent.
    pub hints_sent: u64,
    /// Current balloon size (inflated pages).
    pub current_size: u64,
}

impl BalloonOpStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// MemoryBalloonOps
// -------------------------------------------------------------------

/// The balloon operations manager.
pub struct MemoryBalloonOps {
    /// Pending requests.
    requests: [BalloonRequest; MAX_REQUESTS],
    /// Number of requests.
    request_count: usize,
    /// Free-page hints.
    hints: [FreePageHint; MAX_FREE_HINTS],
    /// Number of hints.
    hint_count: usize,
    /// Statistics.
    stats: BalloonOpStats,
}

impl Default for MemoryBalloonOps {
    fn default() -> Self {
        Self {
            requests: [BalloonRequest::default(); MAX_REQUESTS],
            request_count: 0,
            hints: [FreePageHint::default(); MAX_FREE_HINTS],
            hint_count: 0,
            stats: BalloonOpStats::default(),
        }
    }
}

impl MemoryBalloonOps {
    /// Creates a new balloon operations manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submits an inflate request.
    pub fn inflate(&mut self, nr_pages: u64) -> Result<usize> {
        if self.request_count >= MAX_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.request_count;
        self.requests[idx] = BalloonRequest::new(BalloonOp::Inflate, nr_pages);
        self.request_count += 1;
        Ok(idx)
    }

    /// Submits a deflate request.
    pub fn deflate(&mut self, nr_pages: u64) -> Result<usize> {
        if self.request_count >= MAX_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.request_count;
        self.requests[idx] = BalloonRequest::new(BalloonOp::Deflate, nr_pages);
        self.request_count += 1;
        Ok(idx)
    }

    /// Processes a pending request.
    pub fn process(&mut self, idx: usize) -> Result<u64> {
        if idx >= self.request_count || !self.requests[idx].active {
            return Err(Error::NotFound);
        }
        if self.requests[idx].complete {
            return Ok(0);
        }

        let remaining = self.requests[idx]
            .nr_pages
            .saturating_sub(self.requests[idx].pages_done);
        let batch = remaining.min(MAX_PAGES_PER_OP as u64);
        self.requests[idx].pages_done += batch;

        if self.requests[idx].pages_done >= self.requests[idx].nr_pages {
            self.requests[idx].complete = true;
        }

        match self.requests[idx].op {
            BalloonOp::Inflate => {
                self.stats.inflates += 1;
                self.stats.pages_inflated += batch;
                self.stats.current_size += batch;
            }
            BalloonOp::Deflate => {
                self.stats.deflates += 1;
                self.stats.pages_deflated += batch;
                self.stats.current_size = self.stats.current_size.saturating_sub(batch);
            }
            _ => {}
        }

        Ok(batch)
    }

    /// Adds a free-page hint.
    pub fn add_hint(&mut self, pfn: u64, order: u32) -> Result<()> {
        if self.hint_count >= MAX_FREE_HINTS {
            return Err(Error::OutOfMemory);
        }
        self.hints[self.hint_count] = FreePageHint {
            pfn,
            order,
            sent: false,
        };
        self.hint_count += 1;
        Ok(())
    }

    /// Sends unsent hints.
    pub fn send_hints(&mut self) -> usize {
        let mut sent = 0;
        for i in 0..self.hint_count {
            if !self.hints[i].sent {
                self.hints[i].sent = true;
                sent += 1;
            }
        }
        self.stats.hints_sent += sent as u64;
        sent
    }

    /// Returns the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.requests[..self.request_count]
            .iter()
            .filter(|r| r.active && !r.complete)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &BalloonOpStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
