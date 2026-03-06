// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! brk/sbrk heap expansion.
//!
//! Implements the `brk` system call which manages the program break —
//! the end of the process data segment (heap). The break can be
//! expanded or contracted. New pages are zero-filled and checked
//! against RLIMIT_DATA. The heap VMA is expanded in-place when
//! possible.
//!
//! - [`BrkState`] — per-process break state
//! - [`BrkConfig`] — brk limits and configuration
//! - [`BrkResult`] — outcome of a brk operation
//! - [`BrkManager`] — the brk/sbrk handler
//!
//! Reference: `.kernelORG/` — `mm/mmap.c` (`do_brk_flags`), `brk(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page mask for alignment.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Default RLIMIT_DATA (256 MiB).
const DEFAULT_RLIMIT_DATA: u64 = 256 * 1024 * 1024;

/// Maximum brk expansion in a single call (128 MiB).
const MAX_BRK_EXPANSION: u64 = 128 * 1024 * 1024;

/// Minimum heap size (one page).
const MIN_HEAP_SIZE: u64 = PAGE_SIZE;

/// Maximum tracked brk operations.
const MAX_PROCESSES: usize = 128;

/// VMA flags for the heap: read + write.
const BRK_VMA_FLAGS: u32 = 0x3; // VM_READ | VM_WRITE

// -------------------------------------------------------------------
// BrkState
// -------------------------------------------------------------------

/// Per-process break state.
///
/// Tracks the start of the heap, the current break, and the maximum
/// break value ever reached (for accounting).
#[derive(Debug, Clone, Copy)]
pub struct BrkState {
    /// Start of the heap region (page-aligned).
    pub start_brk: u64,
    /// Current break (end of heap, page-aligned).
    pub brk: u64,
    /// Maximum break value ever reached.
    pub brk_max: u64,
    /// Process ID owning this state.
    pub pid: u32,
    /// Whether the state is active.
    pub active: bool,
}

impl BrkState {
    /// Creates a new break state.
    pub fn new(pid: u32, start_brk: u64) -> Self {
        let aligned = page_align_up(start_brk);
        Self {
            start_brk: aligned,
            brk: aligned,
            brk_max: aligned,
            pid,
            active: true,
        }
    }

    /// Returns the current heap size in bytes.
    pub fn heap_size(&self) -> u64 {
        self.brk.saturating_sub(self.start_brk)
    }

    /// Returns the current heap size in pages.
    pub fn heap_pages(&self) -> u64 {
        self.heap_size() / PAGE_SIZE
    }

    /// Returns the amount of expansion from start.
    pub fn expansion(&self) -> u64 {
        self.brk.saturating_sub(self.start_brk)
    }
}

impl Default for BrkState {
    fn default() -> Self {
        Self {
            start_brk: 0,
            brk: 0,
            brk_max: 0,
            pid: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// BrkConfig
// -------------------------------------------------------------------

/// Configuration and limits for brk operations.
#[derive(Debug, Clone, Copy)]
pub struct BrkConfig {
    /// RLIMIT_DATA: maximum data segment size.
    pub rlimit_data: u64,
    /// Maximum single expansion.
    pub max_expansion: u64,
    /// Whether to zero-fill new pages.
    pub zero_fill: bool,
    /// VMA flags for heap mappings.
    pub vma_flags: u32,
}

impl BrkConfig {
    /// Creates default brk configuration.
    pub fn new() -> Self {
        Self {
            rlimit_data: DEFAULT_RLIMIT_DATA,
            max_expansion: MAX_BRK_EXPANSION,
            zero_fill: true,
            vma_flags: BRK_VMA_FLAGS,
        }
    }
}

impl Default for BrkConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// BrkResult
// -------------------------------------------------------------------

/// Outcome of a brk operation.
#[derive(Debug, Clone, Copy)]
pub struct BrkResult {
    /// The new break value (page-aligned).
    pub new_brk: u64,
    /// Number of new pages allocated.
    pub pages_allocated: u64,
    /// Number of pages freed (if brk decreased).
    pub pages_freed: u64,
    /// Whether the operation succeeded.
    pub success: bool,
}

impl BrkResult {
    /// Creates a successful result.
    fn success(new_brk: u64, pages_allocated: u64, pages_freed: u64) -> Self {
        Self {
            new_brk,
            pages_allocated,
            pages_freed,
            success: true,
        }
    }

    /// Creates a failure result (returns current brk).
    fn failure(current_brk: u64) -> Self {
        Self {
            new_brk: current_brk,
            pages_allocated: 0,
            pages_freed: 0,
            success: false,
        }
    }
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Aligns an address up to the next page boundary.
fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & PAGE_MASK
}

/// Aligns an address down to the current page boundary.
fn page_align_down(addr: u64) -> u64 {
    addr & PAGE_MASK
}

// -------------------------------------------------------------------
// BrkManager
// -------------------------------------------------------------------

/// Manages brk/sbrk for multiple processes.
///
/// Each process has its own [`BrkState`] tracking the program break.
/// The manager validates requests against RLIMIT_DATA and handles
/// page alignment.
pub struct BrkManager {
    /// Per-process break states.
    states: [BrkState; MAX_PROCESSES],
    /// Number of active states.
    nr_active: usize,
    /// Configuration.
    config: BrkConfig,
    /// Total pages allocated via brk.
    total_pages_allocated: u64,
    /// Total pages freed via brk.
    total_pages_freed: u64,
}

impl BrkManager {
    /// Creates a new brk manager.
    pub fn new(config: BrkConfig) -> Self {
        Self {
            states: [BrkState::default(); MAX_PROCESSES],
            nr_active: 0,
            config,
            total_pages_allocated: 0,
            total_pages_freed: 0,
        }
    }

    /// Initializes brk state for a process.
    pub fn init_brk(&mut self, pid: u32, start_brk: u64) -> Result<()> {
        // Find a free slot.
        for state in &mut self.states {
            if !state.active {
                *state = BrkState::new(pid, start_brk);
                self.nr_active += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes brk state for a process (on exit).
    pub fn remove_brk(&mut self, pid: u32) -> Result<()> {
        for state in &mut self.states {
            if state.active && state.pid == pid {
                let freed_pages = state.heap_pages();
                state.active = false;
                self.nr_active -= 1;
                self.total_pages_freed += freed_pages;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Handles the `sys_brk` system call.
    ///
    /// If `new_brk` is 0, returns the current break.
    /// If `new_brk` < current break, shrinks the heap.
    /// If `new_brk` > current break, expands the heap (with checks).
    pub fn sys_brk(&mut self, pid: u32, new_brk: u64) -> BrkResult {
        let state_idx = match self.find_state(pid) {
            Some(idx) => idx,
            None => return BrkResult::failure(0),
        };

        let current_brk = self.states[state_idx].brk;

        // Query: return current break.
        if new_brk == 0 {
            return BrkResult::success(current_brk, 0, 0);
        }

        let aligned_new = page_align_up(new_brk);

        // No change.
        if aligned_new == current_brk {
            return BrkResult::success(current_brk, 0, 0);
        }

        // Shrink.
        if aligned_new < current_brk {
            return self.shrink_brk(state_idx, aligned_new);
        }

        // Expand.
        self.expand_brk(state_idx, aligned_new)
    }

    /// Implements `do_brk_flags` — expands the heap VMA.
    fn expand_brk(&mut self, idx: usize, new_brk: u64) -> BrkResult {
        let state = &self.states[idx];
        let current_brk = state.brk;
        let start_brk = state.start_brk;

        // Check against RLIMIT_DATA.
        let new_size = new_brk.saturating_sub(start_brk);
        if new_size > self.config.rlimit_data {
            return BrkResult::failure(current_brk);
        }

        // Check maximum single expansion.
        let expansion = new_brk.saturating_sub(current_brk);
        if expansion > self.config.max_expansion {
            return BrkResult::failure(current_brk);
        }

        // Cannot go below start.
        if new_brk < start_brk {
            return BrkResult::failure(current_brk);
        }

        let new_pages = expansion / PAGE_SIZE;

        // Update state.
        self.states[idx].brk = new_brk;
        if new_brk > self.states[idx].brk_max {
            self.states[idx].brk_max = new_brk;
        }
        self.total_pages_allocated += new_pages;

        BrkResult::success(new_brk, new_pages, 0)
    }

    /// Shrinks the heap.
    fn shrink_brk(&mut self, idx: usize, new_brk: u64) -> BrkResult {
        let state = &self.states[idx];
        let current_brk = state.brk;
        let start_brk = state.start_brk;

        // Cannot shrink below start.
        let clamped = new_brk.max(start_brk);
        let freed = current_brk.saturating_sub(clamped);
        let freed_pages = freed / PAGE_SIZE;

        self.states[idx].brk = clamped;
        self.total_pages_freed += freed_pages;

        BrkResult::success(clamped, 0, freed_pages)
    }

    /// Finds the state index for a PID.
    fn find_state(&self, pid: u32) -> Option<usize> {
        self.states.iter().position(|s| s.active && s.pid == pid)
    }

    /// Returns the brk state for a process.
    pub fn get_state(&self, pid: u32) -> Option<&BrkState> {
        self.find_state(pid).map(|idx| &self.states[idx])
    }

    /// Returns the configuration.
    pub fn config(&self) -> &BrkConfig {
        &self.config
    }

    /// Updates the RLIMIT_DATA for a specific process.
    pub fn set_rlimit(&mut self, _pid: u32, limit: u64) {
        self.config.rlimit_data = limit;
    }

    /// Returns total pages allocated via brk.
    pub fn total_pages_allocated(&self) -> u64 {
        self.total_pages_allocated
    }

    /// Returns total pages freed via brk.
    pub fn total_pages_freed(&self) -> u64 {
        self.total_pages_freed
    }

    /// Returns the number of active processes.
    pub fn nr_active(&self) -> usize {
        self.nr_active
    }
}

impl Default for BrkManager {
    fn default() -> Self {
        Self::new(BrkConfig::new())
    }
}
