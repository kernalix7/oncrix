// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Deferred page structure initialization.
//!
//! At boot time, initializing every `struct page` for all physical memory
//! is expensive and delays the kernel reaching a functional state. This
//! module implements deferred initialization: only a minimal set of pages
//! needed for early boot are initialized synchronously; the rest are
//! initialized lazily in a background pass.
//!
//! # Design
//!
//! ```text
//!  Boot
//!   │
//!   ├─ early_init(): init pages for zone DMA + first 64 MiB
//!   │
//!   ├─ kernel enters scheduler
//!   │
//!   └─ DeferredInitWorker::run()
//!         │
//!         ├─ for each uninit range ─▶ init struct pages
//!         ├─ free pages to buddy allocator
//!         └─ update zone free counts
//! ```
//!
//! # Key Types
//!
//! - [`DeferredRange`] — a range of PFNs pending initialisation
//! - [`DeferredInitState`] — global deferred-init state machine
//! - [`DeferredInitWorker`] — the background worker
//!
//! Reference: Linux `mm/page_alloc.c` (`deferred_init_memmap`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum deferred ranges we track.
const MAX_DEFERRED_RANGES: usize = 64;

/// Pages initialised per batch before yielding.
const BATCH_SIZE: usize = 256;

/// Maximum PFN value (4 TiB physical at 4 KiB pages).
const MAX_PFN: u64 = 1 << 40 >> 12;

// -------------------------------------------------------------------
// DeferredRange
// -------------------------------------------------------------------

/// A contiguous range of page frame numbers awaiting initialization.
#[derive(Debug, Clone, Copy)]
pub struct DeferredRange {
    /// Start PFN (inclusive).
    start_pfn: u64,
    /// End PFN (exclusive).
    end_pfn: u64,
    /// NUMA node this range belongs to.
    node_id: u32,
    /// Whether this range has been fully initialised.
    completed: bool,
}

impl DeferredRange {
    /// Create a new deferred range.
    pub const fn new(start_pfn: u64, end_pfn: u64, node_id: u32) -> Self {
        Self {
            start_pfn,
            end_pfn,
            node_id,
            completed: false,
        }
    }

    /// Return the start PFN.
    pub const fn start_pfn(&self) -> u64 {
        self.start_pfn
    }

    /// Return the end PFN.
    pub const fn end_pfn(&self) -> u64 {
        self.end_pfn
    }

    /// Return the NUMA node identifier.
    pub const fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Return the number of pages in this range.
    pub const fn page_count(&self) -> u64 {
        self.end_pfn - self.start_pfn
    }

    /// Check whether initialisation for this range has completed.
    pub const fn is_completed(&self) -> bool {
        self.completed
    }

    /// Mark the range as completed.
    pub fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Default for DeferredRange {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// DeferredInitState
// -------------------------------------------------------------------

/// State of the deferred initialisation system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitPhase {
    /// Early boot — only synchronous init has run.
    Early,
    /// Background initialisation is in progress.
    Running,
    /// All pages have been initialised.
    Complete,
}

impl Default for InitPhase {
    fn default() -> Self {
        Self::Early
    }
}

/// Global deferred-init bookkeeping.
pub struct DeferredInitState {
    /// Pending ranges.
    ranges: [DeferredRange; MAX_DEFERRED_RANGES],
    /// Number of valid entries in `ranges`.
    count: usize,
    /// Current processing index.
    cursor: usize,
    /// Total pages still pending.
    pending_pages: u64,
    /// Current phase.
    phase: InitPhase,
}

impl DeferredInitState {
    /// Create a new empty state.
    pub const fn new() -> Self {
        Self {
            ranges: [const { DeferredRange::new(0, 0, 0) }; MAX_DEFERRED_RANGES],
            count: 0,
            cursor: 0,
            pending_pages: 0,
            phase: InitPhase::Early,
        }
    }

    /// Add a range to the deferred list.
    pub fn add_range(&mut self, start_pfn: u64, end_pfn: u64, node_id: u32) -> Result<()> {
        if self.count >= MAX_DEFERRED_RANGES {
            return Err(Error::OutOfMemory);
        }
        if start_pfn >= end_pfn || end_pfn > MAX_PFN {
            return Err(Error::InvalidArgument);
        }
        self.ranges[self.count] = DeferredRange::new(start_pfn, end_pfn, node_id);
        self.pending_pages += end_pfn - start_pfn;
        self.count += 1;
        Ok(())
    }

    /// Return the current phase.
    pub const fn phase(&self) -> InitPhase {
        self.phase
    }

    /// Return total pending pages.
    pub const fn pending_pages(&self) -> u64 {
        self.pending_pages
    }

    /// Return total ranges registered.
    pub const fn range_count(&self) -> usize {
        self.count
    }

    /// Transition to the running phase.
    pub fn start(&mut self) -> Result<()> {
        if self.phase != InitPhase::Early {
            return Err(Error::InvalidArgument);
        }
        self.phase = InitPhase::Running;
        Ok(())
    }

    /// Check whether all ranges have been completed.
    pub fn is_all_complete(&self) -> bool {
        if self.count == 0 {
            return true;
        }
        for idx in 0..self.count {
            if !self.ranges[idx].is_completed() {
                return false;
            }
        }
        true
    }

    /// Mark the phase complete.
    pub fn finish(&mut self) {
        self.phase = InitPhase::Complete;
        self.pending_pages = 0;
    }
}

impl Default for DeferredInitState {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// DeferredInitWorker
// -------------------------------------------------------------------

/// Background worker that initialises deferred page structures.
pub struct DeferredInitWorker {
    /// Number of pages initialised so far.
    pages_done: u64,
    /// Batch size per iteration.
    batch_size: usize,
}

impl DeferredInitWorker {
    /// Create a new worker with the default batch size.
    pub const fn new() -> Self {
        Self {
            pages_done: 0,
            batch_size: BATCH_SIZE,
        }
    }

    /// Create a worker with a custom batch size.
    pub const fn with_batch_size(batch_size: usize) -> Self {
        Self {
            pages_done: 0,
            batch_size,
        }
    }

    /// Return the number of pages initialised by this worker.
    pub const fn pages_done(&self) -> u64 {
        self.pages_done
    }

    /// Process one batch from the given state.
    ///
    /// Returns the number of pages initialised in this batch.
    pub fn process_batch(&mut self, state: &mut DeferredInitState) -> Result<u64> {
        if state.phase() != InitPhase::Running {
            return Err(Error::InvalidArgument);
        }

        let mut initialised: u64 = 0;
        let batch = self.batch_size as u64;

        while initialised < batch && state.cursor < state.count {
            let idx = state.cursor;
            let range = &state.ranges[idx];
            if range.is_completed() {
                state.cursor += 1;
                continue;
            }
            let remaining = range.page_count();
            let to_init = if remaining > (batch - initialised) {
                batch - initialised
            } else {
                remaining
            };
            initialised += to_init;
            if to_init >= remaining {
                state.ranges[idx].mark_completed();
                state.cursor += 1;
            }
        }

        self.pages_done += initialised;
        if state.pending_pages >= initialised {
            state.pending_pages -= initialised;
        } else {
            state.pending_pages = 0;
        }

        if state.is_all_complete() {
            state.finish();
        }

        Ok(initialised)
    }
}

impl Default for DeferredInitWorker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a deferred init state with a single memory range.
pub fn create_single_range(
    start_pfn: u64,
    end_pfn: u64,
    node_id: u32,
) -> Result<DeferredInitState> {
    let mut state = DeferredInitState::new();
    state.add_range(start_pfn, end_pfn, node_id)?;
    Ok(state)
}

/// Run deferred initialisation to completion.
pub fn run_to_completion(state: &mut DeferredInitState) -> Result<u64> {
    state.start()?;
    let mut worker = DeferredInitWorker::new();
    loop {
        let done = worker.process_batch(state)?;
        if done == 0 || state.phase() == InitPhase::Complete {
            break;
        }
    }
    Ok(worker.pages_done())
}

/// Return a summary string for deferred init progress.
pub fn progress_summary(state: &DeferredInitState) -> &'static str {
    match state.phase() {
        InitPhase::Early => "deferred init: early (not started)",
        InitPhase::Running => "deferred init: running",
        InitPhase::Complete => "deferred init: complete",
    }
}
