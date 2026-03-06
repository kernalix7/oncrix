// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel stack allocator.
//!
//! Manages fixed-size kernel stacks for threads. Each thread gets a
//! stack of `THREAD_SIZE` bytes with guard pages at both ends to
//! detect overflow. The allocator tracks stack usage watermarks for
//! debugging.
//!
//! # Stack Layout
//!
//! ```text
//! ┌────────────────────────────┐ high address
//! │ Guard page (unmapped)      │
//! ├────────────────────────────┤
//! │                            │
//! │   Usable stack area        │ ← sp grows downward
//! │   (THREAD_SIZE - 2*PAGE)   │
//! │                            │
//! ├────────────────────────────┤
//! │ thread_info / task_struct  │ ← base of stack
//! ├────────────────────────────┤
//! │ Guard page (unmapped)      │
//! └────────────────────────────┘ low address
//! ```
//!
//! # Reference
//!
//! Linux `kernel/fork.c` (alloc_thread_stack_node),
//! `include/linux/sched/task_stack.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Thread stack size (16 KiB = 4 pages).
pub const THREAD_SIZE: usize = 4 * PAGE_SIZE;

/// Guard page size (one page each end).
const GUARD_SIZE: usize = PAGE_SIZE;

/// Usable stack area (excluding guard pages and thread_info).
const _USABLE_STACK: usize = THREAD_SIZE - 2 * GUARD_SIZE;

/// Maximum number of stacks in the pool.
const MAX_STACKS: usize = 512;

/// Stack canary value for overflow detection.
const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Watermark check interval (bytes from bottom to check usage).
const _WATERMARK_CHECK_INTERVAL: usize = 256;

/// Minimum free stack space before warning (bytes).
const STACK_WARN_THRESHOLD: usize = 1024;

// ======================================================================
// Stack state
// ======================================================================

/// State of a kernel stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackState {
    /// Free and available for allocation.
    Free,
    /// Allocated and in use by a thread.
    InUse,
    /// Poisoned (overflow detected).
    Poisoned,
}

// ======================================================================
// Stack descriptor
// ======================================================================

/// Describes a single kernel stack.
#[derive(Debug, Clone, Copy)]
pub struct StackDescriptor {
    /// Stack index in the pool.
    index: u32,
    /// Base virtual address of the stack (low end).
    base_addr: u64,
    /// Current state.
    state: StackState,
    /// Thread ID that owns this stack (0 if free).
    owner_tid: u32,
    /// Stack canary value (written at the bottom of usable area).
    canary: u64,
    /// Highest observed stack usage (bytes from top).
    watermark: usize,
    /// Total size of the stack (including guards).
    total_size: usize,
    /// Number of times this stack has been allocated.
    alloc_count: u32,
}

impl StackDescriptor {
    /// Creates a new free stack descriptor.
    pub const fn new() -> Self {
        Self {
            index: 0,
            base_addr: 0,
            state: StackState::Free,
            owner_tid: 0,
            canary: STACK_CANARY,
            watermark: 0,
            total_size: THREAD_SIZE,
            alloc_count: 0,
        }
    }

    /// Returns the stack index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Returns the base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the top address (initial SP value).
    pub fn top_addr(&self) -> u64 {
        self.base_addr + (self.total_size - GUARD_SIZE) as u64
    }

    /// Returns the usable bottom address (above lower guard).
    pub fn usable_bottom(&self) -> u64 {
        self.base_addr + GUARD_SIZE as u64
    }

    /// Returns the current state.
    pub fn state(&self) -> StackState {
        self.state
    }

    /// Returns the owner TID.
    pub fn owner_tid(&self) -> u32 {
        self.owner_tid
    }

    /// Returns the stack usage watermark (bytes from top).
    pub fn watermark(&self) -> usize {
        self.watermark
    }

    /// Returns the remaining free stack space based on watermark.
    pub fn free_space(&self) -> usize {
        let usable = self.total_size - 2 * GUARD_SIZE;
        usable.saturating_sub(self.watermark)
    }

    /// Returns whether the stack is in a low-space warning state.
    pub fn is_low(&self) -> bool {
        self.free_space() < STACK_WARN_THRESHOLD
    }

    /// Checks the stack canary for overflow.
    pub fn check_canary(&self) -> bool {
        self.canary == STACK_CANARY
    }

    /// Updates the watermark with a new observed SP value.
    pub fn update_watermark(&mut self, current_sp: u64) {
        let top = self.top_addr();
        if current_sp < top {
            let used = (top - current_sp) as usize;
            if used > self.watermark {
                self.watermark = used;
            }
        }
    }
}

// ======================================================================
// Stack pool
// ======================================================================

/// Pool of pre-allocated kernel stacks.
pub struct StackPool {
    /// Stack descriptors.
    stacks: [StackDescriptor; MAX_STACKS],
    /// Number of allocated stacks.
    allocated: usize,
    /// Total stacks in the pool.
    total: usize,
    /// Base address for the stack region.
    region_base: u64,
    /// Number of overflow events detected.
    overflow_count: u64,
    /// Whether the pool is initialized.
    initialized: bool,
}

impl StackPool {
    /// Creates a new uninitialized stack pool.
    pub const fn new() -> Self {
        Self {
            stacks: [const { StackDescriptor::new() }; MAX_STACKS],
            allocated: 0,
            total: 0,
            region_base: 0,
            overflow_count: 0,
            initialized: false,
        }
    }

    /// Initializes the stack pool with a given memory region.
    pub fn init(&mut self, region_base: u64, nr_stacks: usize) -> Result<()> {
        if nr_stacks == 0 || nr_stacks > MAX_STACKS {
            return Err(Error::InvalidArgument);
        }
        self.region_base = region_base;
        self.total = nr_stacks;
        for i in 0..nr_stacks {
            self.stacks[i].index = i as u32;
            self.stacks[i].base_addr = region_base + (i * THREAD_SIZE) as u64;
            self.stacks[i].state = StackState::Free;
            self.stacks[i].canary = STACK_CANARY;
            self.stacks[i].watermark = 0;
            self.stacks[i].total_size = THREAD_SIZE;
        }
        self.initialized = true;
        Ok(())
    }

    /// Returns the number of allocated stacks.
    pub fn allocated(&self) -> usize {
        self.allocated
    }

    /// Returns the number of free stacks.
    pub fn free_count(&self) -> usize {
        self.total.saturating_sub(self.allocated)
    }

    /// Returns the total number of stacks.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Returns the overflow event count.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Allocates a stack for a thread.
    pub fn alloc_stack(&mut self, tid: u32) -> Result<&StackDescriptor> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        let slot = self.stacks[..self.total]
            .iter()
            .position(|s| s.state == StackState::Free)
            .ok_or(Error::OutOfMemory)?;
        self.stacks[slot].state = StackState::InUse;
        self.stacks[slot].owner_tid = tid;
        self.stacks[slot].watermark = 0;
        self.stacks[slot].canary = STACK_CANARY;
        self.stacks[slot].alloc_count += 1;
        self.allocated += 1;
        Ok(&self.stacks[slot])
    }

    /// Frees a stack.
    pub fn free_stack(&mut self, index: u32) -> Result<()> {
        let idx = index as usize;
        if idx >= self.total {
            return Err(Error::InvalidArgument);
        }
        if self.stacks[idx].state != StackState::InUse {
            return Err(Error::InvalidArgument);
        }
        // Check canary before freeing.
        if !self.stacks[idx].check_canary() {
            self.stacks[idx].state = StackState::Poisoned;
            self.overflow_count = self.overflow_count.saturating_add(1);
            return Err(Error::IoError);
        }
        self.stacks[idx].state = StackState::Free;
        self.stacks[idx].owner_tid = 0;
        self.allocated = self.allocated.saturating_sub(1);
        Ok(())
    }

    /// Returns a stack descriptor by index.
    pub fn get(&self, index: u32) -> Result<&StackDescriptor> {
        let idx = index as usize;
        if idx >= self.total {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.stacks[idx])
    }

    /// Finds a stack by owner TID.
    pub fn find_by_tid(&self, tid: u32) -> Option<&StackDescriptor> {
        self.stacks[..self.total]
            .iter()
            .find(|s| s.state == StackState::InUse && s.owner_tid == tid)
    }

    /// Checks all allocated stacks for overflow (canary check).
    pub fn check_all_canaries(&mut self) -> usize {
        let mut poisoned = 0;
        for i in 0..self.total {
            if self.stacks[i].state == StackState::InUse && !self.stacks[i].check_canary() {
                self.stacks[i].state = StackState::Poisoned;
                poisoned += 1;
                self.overflow_count = self.overflow_count.saturating_add(1);
            }
        }
        poisoned
    }

    /// Updates the watermark for a stack given a current SP value.
    pub fn update_watermark(&mut self, index: u32, current_sp: u64) -> Result<()> {
        let idx = index as usize;
        if idx >= self.total {
            return Err(Error::InvalidArgument);
        }
        self.stacks[idx].update_watermark(current_sp);
        Ok(())
    }

    /// Returns the maximum watermark across all allocated stacks.
    pub fn max_watermark(&self) -> usize {
        let mut max = 0;
        for i in 0..self.total {
            if self.stacks[i].state == StackState::InUse && self.stacks[i].watermark > max {
                max = self.stacks[i].watermark;
            }
        }
        max
    }

    /// Returns the number of stacks with low free space.
    pub fn count_low_stacks(&self) -> usize {
        self.stacks[..self.total]
            .iter()
            .filter(|s| s.state == StackState::InUse && s.is_low())
            .count()
    }
}
