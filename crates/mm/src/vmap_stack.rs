// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtually mapped kernel stacks.
//!
//! This module manages kernel thread stacks that are backed by virtual
//! memory mappings with guard pages. Unlike physically contiguous stacks,
//! vmap stacks place unmapped guard pages immediately above and below each
//! stack so that stack overflows are caught as page faults rather than
//! silently corrupting adjacent kernel memory.
//!
//! # Architecture
//!
//! ```text
//! High address
//! ┌──────────────────┐  ← stack_top (aligned to STACK_ALIGN)
//! │    Guard Page    │  (unmapped, catches overflow from above)
//! ├──────────────────┤
//! │                  │
//! │   Stack Region   │  VMAP_STACK_SIZE bytes
//! │   (grows down)   │
//! │                  │
//! ├──────────────────┤
//! │    Guard Page    │  (unmapped, catches overflow from below)
//! └──────────────────┘
//! Low address
//! ```
//!
//! # Key types
//!
//! - [`VmapStack`] — a single virtually mapped kernel stack
//! - [`VmapStackCache`] — per-CPU free-list cache of stack objects
//! - [`VmapStackAllocator`] — global allocator that manages the vmalloc
//!   range used for kernel stacks
//! - [`VmapStackStats`] — allocation and fault statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Size of a kernel stack in bytes (16 KiB, two pages wide).
pub const VMAP_STACK_SIZE: usize = 16 * 1024;

/// Size of a guard page in bytes.
pub const GUARD_PAGE_SIZE: usize = 4096;

/// Required alignment for stack base addresses.
pub const STACK_ALIGN: usize = 16;

/// Total virtual-address window per stack including both guard pages.
pub const VMAP_STACK_WINDOW: usize = GUARD_PAGE_SIZE + VMAP_STACK_SIZE + GUARD_PAGE_SIZE;

/// Maximum number of stacks held per-CPU in the free-list cache.
pub const VMAP_STACK_CACHE_SIZE: usize = 4;

/// Maximum number of stacks that the global allocator can track.
pub const VMAP_STACK_MAX: usize = 1024;

/// Poison value written to freed stacks when debug mode is active.
pub const STACK_POISON: u8 = 0xDE;

// -------------------------------------------------------------------
// VmapStackState
// -------------------------------------------------------------------

/// Lifecycle state of a [`VmapStack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmapStackState {
    /// The stack object exists but its virtual region is unmapped.
    #[default]
    Free,
    /// The stack is currently in use by a kernel thread.
    InUse,
    /// The stack is on a per-CPU free-list awaiting reuse.
    Cached,
    /// The stack is being torn down and its VA range freed.
    TearingDown,
}

// -------------------------------------------------------------------
// VmapStack
// -------------------------------------------------------------------

/// A virtually mapped kernel stack with guard pages.
#[derive(Debug)]
pub struct VmapStack {
    /// Virtual address of the lower guard page (base of the window).
    lower_guard_va: u64,
    /// Virtual address of the first usable stack byte.
    stack_va: u64,
    /// Virtual address of the upper guard page.
    upper_guard_va: u64,
    /// Lifecycle state.
    state: VmapStackState,
    /// Which CPU's cache this stack is associated with, if any.
    cpu_affinity: Option<u32>,
    /// Unique identifier for this stack object.
    id: u32,
}

impl VmapStack {
    /// Allocate a new [`VmapStack`] starting at the given virtual address window.
    ///
    /// The caller must ensure `window_va` is suitably aligned and that the
    /// full `VMAP_STACK_WINDOW` range is reserved in the vmalloc address space.
    pub fn new(window_va: u64, id: u32) -> Self {
        Self {
            lower_guard_va: window_va,
            stack_va: window_va + GUARD_PAGE_SIZE as u64,
            upper_guard_va: window_va + (GUARD_PAGE_SIZE + VMAP_STACK_SIZE) as u64,
            state: VmapStackState::Free,
            cpu_affinity: None,
            id,
        }
    }

    /// Return the stack pointer value suitable for use as SP on entry to a
    /// new kernel thread (points to the top of the usable region).
    pub fn initial_sp(&self) -> u64 {
        // Stack grows downward; SP starts at the top of the usable region,
        // aligned to STACK_ALIGN.
        let top = self.stack_va + VMAP_STACK_SIZE as u64;
        top & !(STACK_ALIGN as u64 - 1)
    }

    /// Returns the virtual address of the lower guard page.
    pub fn lower_guard_va(&self) -> u64 {
        self.lower_guard_va
    }

    /// Returns the virtual address of the upper guard page.
    pub fn upper_guard_va(&self) -> u64 {
        self.upper_guard_va
    }

    /// Returns the base virtual address of the usable stack region.
    pub fn stack_va(&self) -> u64 {
        self.stack_va
    }

    /// Returns the current lifecycle state.
    pub fn state(&self) -> VmapStackState {
        self.state
    }

    /// Returns the stack's unique identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Mark this stack as in-use by a kernel thread.
    pub fn acquire(&mut self) -> Result<()> {
        if self.state != VmapStackState::Free && self.state != VmapStackState::Cached {
            return Err(Error::Busy);
        }
        self.state = VmapStackState::InUse;
        Ok(())
    }

    /// Return this stack to the free state.
    pub fn release(&mut self) {
        self.state = VmapStackState::Free;
        self.cpu_affinity = None;
    }

    /// Check whether a faulting virtual address falls within a guard page.
    pub fn is_guard_fault(&self, fault_va: u64) -> bool {
        let in_lower = fault_va >= self.lower_guard_va
            && fault_va < self.lower_guard_va + GUARD_PAGE_SIZE as u64;
        let in_upper = fault_va >= self.upper_guard_va
            && fault_va < self.upper_guard_va + GUARD_PAGE_SIZE as u64;
        in_lower || in_upper
    }
}

// -------------------------------------------------------------------
// VmapStackCache
// -------------------------------------------------------------------

/// Per-CPU free-list cache of [`VmapStack`] objects.
///
/// Avoids contention on the global allocator for the common case of
/// thread creation and destruction on the same CPU.
#[derive(Debug)]
pub struct VmapStackCache {
    /// CPU index this cache belongs to.
    cpu_id: u32,
    /// Cached stack IDs (index into the global pool).
    cached_ids: [u32; VMAP_STACK_CACHE_SIZE],
    /// Number of valid entries in `cached_ids`.
    count: usize,
    /// Total stacks handed out from this cache.
    allocs: u64,
    /// Total stacks returned to this cache.
    frees: u64,
}

impl VmapStackCache {
    /// Create a new empty per-CPU stack cache.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            cached_ids: [0; VMAP_STACK_CACHE_SIZE],
            count: 0,
            allocs: 0,
            frees: 0,
        }
    }

    /// Pop a stack ID from the cache, if available.
    pub fn pop(&mut self) -> Option<u32> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        let id = self.cached_ids[self.count];
        self.allocs += 1;
        Some(id)
    }

    /// Push a stack ID back into the cache.
    ///
    /// Returns `Err(InvalidArgument)` if the cache is full.
    pub fn push(&mut self, id: u32) -> Result<()> {
        if self.count >= VMAP_STACK_CACHE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.cached_ids[self.count] = id;
        self.count += 1;
        self.frees += 1;
        Ok(())
    }

    /// Returns the number of stacks currently cached.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the CPU ID for this cache.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns allocation statistics.
    pub fn stats(&self) -> (u64, u64) {
        (self.allocs, self.frees)
    }
}

// -------------------------------------------------------------------
// VmapStackStats
// -------------------------------------------------------------------

/// Aggregate statistics for the vmap-stack subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmapStackStats {
    /// Total number of stacks allocated from the global pool.
    pub total_allocs: u64,
    /// Total number of stacks returned to the global pool.
    pub total_frees: u64,
    /// Number of allocations served from a per-CPU cache.
    pub cache_hits: u64,
    /// Number of allocations that required a new vmalloc mapping.
    pub cache_misses: u64,
    /// Number of guard-page faults detected.
    pub guard_faults: u64,
    /// Current number of stacks in use.
    pub in_use: u64,
    /// Current number of stacks in per-CPU caches.
    pub cached: u64,
}

// -------------------------------------------------------------------
// VmapStackAllocator
// -------------------------------------------------------------------

/// Global allocator for virtually mapped kernel stacks.
///
/// Manages a pool of [`VmapStack`] objects and assigns virtual address
/// windows from a dedicated region of the kernel vmalloc address space.
#[derive(Debug)]
pub struct VmapStackAllocator {
    /// Base virtual address of the stack VA range.
    base_va: u64,
    /// Size of the stack VA range in bytes.
    range_size: u64,
    /// Next free VA offset within the range.
    next_offset: u64,
    /// Pool of stack descriptors.
    pool: [Option<VmapStack>; VMAP_STACK_MAX],
    /// Index of the next free slot in `pool`.
    next_id: u32,
    /// Aggregate statistics.
    stats: VmapStackStats,
    /// Whether the allocator has been initialized.
    initialized: bool,
}

impl VmapStackAllocator {
    /// Create a new, uninitialized allocator.
    pub const fn new() -> Self {
        Self {
            base_va: 0,
            range_size: 0,
            next_offset: 0,
            pool: [const { None }; VMAP_STACK_MAX],
            next_id: 0,
            stats: VmapStackStats {
                total_allocs: 0,
                total_frees: 0,
                cache_hits: 0,
                cache_misses: 0,
                guard_faults: 0,
                in_use: 0,
                cached: 0,
            },
            initialized: false,
        }
    }

    /// Initialize the allocator with a virtual address range.
    ///
    /// # Arguments
    ///
    /// * `base_va` — start of the reserved vmalloc range for stacks.
    /// * `range_size` — total size of the range in bytes.
    pub fn init(&mut self, base_va: u64, range_size: u64) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        if range_size < VMAP_STACK_WINDOW as u64 {
            return Err(Error::InvalidArgument);
        }
        self.base_va = base_va;
        self.range_size = range_size;
        self.next_offset = 0;
        self.initialized = true;
        Ok(())
    }

    /// Allocate a new vmap stack and return its ID.
    pub fn alloc(&mut self) -> Result<u32> {
        if !self.initialized {
            return Err(Error::NotFound);
        }
        if self.next_id as usize >= VMAP_STACK_MAX {
            return Err(Error::OutOfMemory);
        }
        let window_size = VMAP_STACK_WINDOW as u64;
        if self.next_offset + window_size > self.range_size {
            return Err(Error::OutOfMemory);
        }
        let window_va = self.base_va + self.next_offset;
        self.next_offset += window_size;

        let id = self.next_id;
        let mut stack = VmapStack::new(window_va, id);
        stack.acquire()?;
        self.pool[id as usize] = Some(stack);
        self.next_id += 1;

        self.stats.total_allocs += 1;
        self.stats.cache_misses += 1;
        self.stats.in_use += 1;
        Ok(id)
    }

    /// Free a stack back to the global pool.
    pub fn free(&mut self, id: u32) -> Result<()> {
        let slot = self
            .pool
            .get_mut(id as usize)
            .ok_or(Error::InvalidArgument)?;
        match slot {
            Some(s) => {
                s.release();
                self.stats.total_frees += 1;
                self.stats.in_use = self.stats.in_use.saturating_sub(1);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Return an immutable reference to a stack descriptor by ID.
    pub fn get(&self, id: u32) -> Option<&VmapStack> {
        self.pool.get(id as usize)?.as_ref()
    }

    /// Record a guard-page fault for statistics.
    pub fn record_guard_fault(&mut self, fault_va: u64) -> bool {
        for slot in self.pool.iter().flatten() {
            if slot.is_guard_fault(fault_va) {
                self.stats.guard_faults += 1;
                return true;
            }
        }
        false
    }

    /// Return a snapshot of allocation statistics.
    pub fn stats(&self) -> &VmapStackStats {
        &self.stats
    }

    /// Returns true if the allocator has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for VmapStackAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_sp_aligned() {
        let stack = VmapStack::new(0x1000_0000, 0);
        let sp = stack.initial_sp();
        assert_eq!(sp % STACK_ALIGN as u64, 0);
    }

    #[test]
    fn test_guard_fault_detection() {
        let stack = VmapStack::new(0x2000_0000, 1);
        // Lower guard: 0x2000_0000 .. 0x2000_1000
        assert!(stack.is_guard_fault(0x2000_0000));
        assert!(stack.is_guard_fault(0x2000_0FFF));
        // Stack region should NOT be a guard fault
        assert!(!stack.is_guard_fault(0x2000_1000));
        // Upper guard: 0x2000_5000 .. 0x2000_6000
        assert!(stack.is_guard_fault(0x2000_5000));
    }

    #[test]
    fn test_cache_push_pop() {
        let mut cache = VmapStackCache::new(0);
        assert!(cache.is_empty());
        cache.push(42).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.pop(), Some(42));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_allocator_init_and_alloc() {
        let mut alloc = VmapStackAllocator::new();
        alloc.init(0x8000_0000, 64 * 1024 * 1024).unwrap();
        let id = alloc.alloc().unwrap();
        assert_eq!(id, 0);
        assert!(alloc.get(id).is_some());
        assert_eq!(alloc.stats().in_use, 1);
    }
}
