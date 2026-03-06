// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KFENCE — Kernel Electric Fence memory error detector.
//!
//! A sampling-based memory error detector that catches common
//! heap corruption bugs such as out-of-bounds accesses,
//! use-after-free, and double-free. Inspired by the Linux
//! `mm/kfence/` subsystem.
//!
//! KFENCE works by placing guard pages around a pool of dedicated
//! allocations. When a buggy access hits a guard page, the
//! resulting page fault is caught and diagnosed.
//!
//! - [`KfenceAllocator`] — main allocator with guard-page checking
//! - [`KfencePool`] — fixed pool of guarded objects
//! - [`KfenceError`] — detected memory error descriptors
//! - [`KfenceStats`] — running statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of objects managed by the KFENCE pool.
const KFENCE_POOL_SIZE: usize = 256;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default sampling interval in timer ticks.
const DEFAULT_SAMPLE_INTERVAL: u64 = 100;

// -------------------------------------------------------------------
// KfenceState
// -------------------------------------------------------------------

/// Runtime state of the KFENCE subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KfenceState {
    /// KFENCE is disabled and not intercepting allocations.
    #[default]
    Disabled,
    /// KFENCE is armed and ready to sample the next allocation.
    Armed,
    /// KFENCE has been triggered and is servicing a sampled
    /// allocation.
    Triggered,
}

// -------------------------------------------------------------------
// KfenceObject
// -------------------------------------------------------------------

/// Metadata for a single KFENCE-guarded allocation object.
#[derive(Debug, Clone, Copy, Default)]
pub struct KfenceObject {
    /// Virtual address of the object (within the KFENCE pool).
    pub addr: u64,
    /// Requested size in bytes.
    pub size: u64,
    /// Whether the object is currently allocated.
    pub allocated: bool,
    /// Whether the object has been freed (for UAF detection).
    pub freed: bool,
    /// Captured instruction pointer at allocation time.
    pub alloc_stack: u64,
    /// Captured instruction pointer at free time.
    pub free_stack: u64,
}

// -------------------------------------------------------------------
// KfenceError
// -------------------------------------------------------------------

/// Describes a memory error detected by KFENCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfenceError {
    /// Out-of-bounds access detected.
    OutOfBounds {
        /// Faulting address.
        addr: u64,
        /// Base address of the owning object.
        object_addr: u64,
        /// Size of the owning object.
        object_size: u64,
    },
    /// Use-after-free access detected.
    UseAfterFree {
        /// Faulting address.
        addr: u64,
        /// Base address of the freed object.
        object_addr: u64,
    },
    /// Object was freed twice.
    DoubleFree {
        /// Address of the doubly-freed object.
        addr: u64,
    },
    /// Address does not belong to any KFENCE object.
    InvalidFree {
        /// Address passed to free.
        addr: u64,
    },
}

// -------------------------------------------------------------------
// KfenceStats
// -------------------------------------------------------------------

/// Running statistics for the KFENCE allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct KfenceStats {
    /// Total allocations serviced through KFENCE.
    pub total_allocs: u64,
    /// Total frees serviced through KFENCE.
    pub total_frees: u64,
    /// Total number of errors detected.
    pub errors_detected: u64,
    /// Out-of-bounds errors detected.
    pub oob_count: u64,
    /// Use-after-free errors detected.
    pub uaf_count: u64,
}

// -------------------------------------------------------------------
// KfencePool
// -------------------------------------------------------------------

/// Pool of KFENCE-guarded objects with interleaved guard pages.
///
/// The pool is laid out as alternating guard and object pages:
///
/// ```text
/// [guard][object 0][guard][object 1][guard]...[guard]
/// ```
///
/// Each object occupies a single page, with inaccessible guard
/// pages on both sides to catch off-by-one and overflow accesses.
pub struct KfencePool {
    /// Object metadata array.
    objects: [KfenceObject; KFENCE_POOL_SIZE],
    /// Number of currently allocated objects.
    allocated_count: usize,
    /// Sampling interval in timer ticks.
    sample_interval: u64,
    /// Base virtual address of the pool region.
    base_addr: u64,
    /// Whether the pool has been initialised.
    active: bool,
}

impl Default for KfencePool {
    fn default() -> Self {
        Self::new()
    }
}

impl KfencePool {
    /// Creates a new, uninitialised KFENCE pool.
    pub const fn new() -> Self {
        const EMPTY: KfenceObject = KfenceObject {
            addr: 0,
            size: 0,
            allocated: false,
            freed: false,
            alloc_stack: 0,
            free_stack: 0,
        };
        Self {
            objects: [EMPTY; KFENCE_POOL_SIZE],
            allocated_count: 0,
            sample_interval: DEFAULT_SAMPLE_INTERVAL,
            base_addr: 0,
            active: false,
        }
    }

    /// Initialise the pool at the given base address.
    ///
    /// The caller must ensure that the region starting at
    /// `base_addr` is large enough to hold all objects and
    /// their interleaved guard pages:
    /// `(2 * KFENCE_POOL_SIZE + 1) * PAGE_SIZE` bytes.
    pub fn init(&mut self, base_addr: u64) {
        self.base_addr = base_addr;
        for (i, obj) in self.objects.iter_mut().enumerate() {
            // Each object sits at: base + (2*i + 1) * PAGE_SIZE
            // (skip guard page at offset 2*i * PAGE_SIZE).
            obj.addr = base_addr + (2 * i as u64 + 1) * PAGE_SIZE;
            obj.size = 0;
            obj.allocated = false;
            obj.freed = false;
            obj.alloc_stack = 0;
            obj.free_stack = 0;
        }
        self.allocated_count = 0;
        self.active = true;
    }

    /// Sets the sampling interval (in timer ticks).
    pub fn set_sample_interval(&mut self, ticks: u64) {
        self.sample_interval = ticks;
    }

    /// Returns the configured sampling interval.
    pub fn sample_interval(&self) -> u64 {
        self.sample_interval
    }

    /// Returns the number of currently allocated objects.
    pub fn allocated_count(&self) -> usize {
        self.allocated_count
    }

    /// Returns the number of available (free) object slots.
    pub fn available(&self) -> usize {
        KFENCE_POOL_SIZE - self.allocated_count
    }

    /// Returns `true` if the pool has been initialised.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the base address of the pool region.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Pool capacity (always [`KFENCE_POOL_SIZE`]).
    pub fn capacity(&self) -> usize {
        KFENCE_POOL_SIZE
    }

    /// Check whether `addr` falls within the pool region.
    pub fn contains(&self, addr: u64) -> bool {
        if !self.active {
            return false;
        }
        let pool_end = self.base_addr + (2 * KFENCE_POOL_SIZE as u64 + 1) * PAGE_SIZE;
        addr >= self.base_addr && addr < pool_end
    }

    /// Find the object index for a given address, if any.
    fn find_object(&self, addr: u64) -> Option<usize> {
        for (i, obj) in self.objects.iter().enumerate() {
            if obj.addr != 0 && addr >= obj.addr && addr < obj.addr + PAGE_SIZE {
                return Some(i);
            }
        }
        None
    }

    /// Find the nearest object to a faulting address (for
    /// out-of-bounds diagnostics).
    fn find_nearest(&self, addr: u64) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_dist = u64::MAX;
        for (i, obj) in self.objects.iter().enumerate() {
            if !obj.allocated && !obj.freed {
                continue;
            }
            let dist = addr.abs_diff(obj.addr);
            if dist < best_dist {
                best_dist = dist;
                best = Some(i);
            }
        }
        best
    }
}

// -------------------------------------------------------------------
// KfenceAllocator
// -------------------------------------------------------------------

/// KFENCE allocator — sampling-based memory error detector.
///
/// Wraps a [`KfencePool`] and provides allocation, deallocation,
/// and error-reporting capabilities.
pub struct KfenceAllocator {
    /// The underlying guarded pool.
    pool: KfencePool,
    /// Current state of the detector.
    state: KfenceState,
    /// Running statistics.
    stats: KfenceStats,
    /// Accumulated error reports (ring buffer, newest overwrites
    /// oldest).
    errors: [Option<KfenceError>; 64],
    /// Next write index in the error ring buffer.
    error_idx: usize,
}

impl Default for KfenceAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl KfenceAllocator {
    /// Creates a new, disabled KFENCE allocator.
    pub const fn new() -> Self {
        const NONE_ERR: Option<KfenceError> = None;
        Self {
            pool: KfencePool::new(),
            state: KfenceState::Disabled,
            stats: KfenceStats {
                total_allocs: 0,
                total_frees: 0,
                errors_detected: 0,
                oob_count: 0,
                uaf_count: 0,
            },
            errors: [NONE_ERR; 64],
            error_idx: 0,
        }
    }

    /// Initialise and enable the KFENCE allocator.
    ///
    /// `base_addr` is the start of the reserved virtual region
    /// for the KFENCE pool. See [`KfencePool::init`] for size
    /// requirements.
    pub fn enable(&mut self, base_addr: u64) {
        self.pool.init(base_addr);
        self.state = KfenceState::Armed;
    }

    /// Disable the KFENCE allocator.
    ///
    /// Outstanding allocations remain valid but no new
    /// allocations will be intercepted.
    pub fn disable(&mut self) {
        self.state = KfenceState::Disabled;
    }

    /// Returns the current state of the allocator.
    pub fn state(&self) -> KfenceState {
        self.state
    }

    /// Allocate a KFENCE-guarded object of `size` bytes.
    ///
    /// `alloc_stack` is the caller-captured instruction pointer
    /// for diagnostic reporting.
    ///
    /// Returns the virtual address of the allocated object.
    pub fn alloc(&mut self, size: u64, alloc_stack: u64) -> Result<u64> {
        if self.state == KfenceState::Disabled {
            return Err(Error::NotImplemented);
        }
        if size == 0 || size > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.pool.is_active() {
            return Err(Error::NotFound);
        }

        // Find a free slot.
        let slot = self
            .pool
            .objects
            .iter()
            .position(|o| !o.allocated && !o.freed)
            .ok_or(Error::OutOfMemory)?;

        let obj = &mut self.pool.objects[slot];
        obj.size = size;
        obj.allocated = true;
        obj.freed = false;
        obj.alloc_stack = alloc_stack;
        obj.free_stack = 0;

        self.pool.allocated_count += 1;
        self.stats.total_allocs += 1;
        self.state = KfenceState::Armed;

        Ok(obj.addr)
    }

    /// Free a KFENCE-guarded object.
    ///
    /// `free_stack` is the caller-captured instruction pointer
    /// for diagnostic reporting.
    ///
    /// Returns `Ok(())` on success. If the free is invalid
    /// (double-free, invalid address), the error is recorded
    /// and an appropriate [`Error`] is returned.
    pub fn free(&mut self, addr: u64, free_stack: u64) -> Result<()> {
        if self.state == KfenceState::Disabled {
            return Err(Error::NotImplemented);
        }

        let slot = match self.pool.find_object(addr) {
            Some(s) => s,
            None => {
                self.report_error(KfenceError::InvalidFree { addr });
                return Err(Error::InvalidArgument);
            }
        };

        let obj = &mut self.pool.objects[slot];

        // Double-free detection.
        if obj.freed {
            self.report_error(KfenceError::DoubleFree { addr });
            return Err(Error::InvalidArgument);
        }

        // Not currently allocated (should not happen if freed is
        // false, but be defensive).
        if !obj.allocated {
            self.report_error(KfenceError::InvalidFree { addr });
            return Err(Error::InvalidArgument);
        }

        obj.allocated = false;
        obj.freed = true;
        obj.free_stack = free_stack;

        self.pool.allocated_count = self.pool.allocated_count.saturating_sub(1);
        self.stats.total_frees += 1;

        Ok(())
    }

    /// Handle a page fault at `fault_addr`.
    ///
    /// Determines whether the fault is KFENCE-related and, if
    /// so, diagnoses the error. Returns `Some(error)` for a
    /// KFENCE fault or `None` if the address is outside the
    /// pool.
    pub fn handle_fault(&mut self, fault_addr: u64) -> Option<KfenceError> {
        if !self.pool.contains(fault_addr) {
            return None;
        }

        // Check if the address is inside an object page.
        if let Some(idx) = self.pool.find_object(fault_addr) {
            let obj = &self.pool.objects[idx];
            if obj.freed {
                let err = KfenceError::UseAfterFree {
                    addr: fault_addr,
                    object_addr: obj.addr,
                };
                self.report_error(err);
                return Some(err);
            }
            // Fault inside a live object is not a KFENCE error
            // (forward to the normal fault handler).
            return None;
        }

        // Fault is in a guard page — find the nearest object
        // for OOB diagnosis.
        if let Some(idx) = self.pool.find_nearest(fault_addr) {
            let obj = &self.pool.objects[idx];
            if obj.freed {
                let err = KfenceError::UseAfterFree {
                    addr: fault_addr,
                    object_addr: obj.addr,
                };
                self.report_error(err);
                return Some(err);
            }
            let err = KfenceError::OutOfBounds {
                addr: fault_addr,
                object_addr: obj.addr,
                object_size: obj.size,
            };
            self.report_error(err);
            return Some(err);
        }

        None
    }

    /// Record a detected error into the ring buffer and update
    /// statistics.
    pub fn report_error(&mut self, error: KfenceError) {
        self.errors[self.error_idx] = Some(error);
        self.error_idx = (self.error_idx + 1) % self.errors.len();
        self.stats.errors_detected += 1;

        match error {
            KfenceError::OutOfBounds { .. } => {
                self.stats.oob_count += 1;
            }
            KfenceError::UseAfterFree { .. } => {
                self.stats.uaf_count += 1;
            }
            KfenceError::DoubleFree { .. } | KfenceError::InvalidFree { .. } => {}
        }
    }

    /// Returns a snapshot of the current statistics.
    pub fn stats(&self) -> KfenceStats {
        self.stats
    }

    /// Returns an immutable reference to the underlying pool.
    pub fn pool(&self) -> &KfencePool {
        &self.pool
    }

    /// Returns the number of errors recorded in the ring buffer.
    pub fn error_count(&self) -> usize {
        self.errors.iter().filter(|e| e.is_some()).count()
    }

    /// Returns the most recently reported error, if any.
    pub fn last_error(&self) -> Option<KfenceError> {
        let prev = if self.error_idx == 0 {
            self.errors.len() - 1
        } else {
            self.error_idx - 1
        };
        self.errors[prev]
    }
}
