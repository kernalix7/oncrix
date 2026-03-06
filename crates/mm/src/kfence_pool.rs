// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KFENCE sampling-based memory error detector — pool management.
//!
//! This module implements the KFENCE pool: a fixed set of guarded memory
//! objects used by the KFENCE subsystem to detect common heap-corruption
//! bugs (out-of-bounds, use-after-free, double-free) at runtime with low
//! overhead.
//!
//! # Design
//!
//! Each object in the pool occupies exactly one page of virtual memory,
//! flanked by unmapped guard pages:
//!
//! ```text
//! ┌──────────────┐ ← guard_before_va (unmapped)
//! ├──────────────┤ ← object_va       (mapped, contains the allocation)
//! ├──────────────┤ ← guard_after_va  (unmapped)
//! └──────────────┘
//! ```
//!
//! A background sampler decides probabilistically whether an incoming
//! `kmalloc` call should be redirected to the KFENCE pool. If an
//! out-of-bounds access hits a guard page, a page fault is raised and
//! the KFENCE subsystem produces a detailed error report.
//!
//! # Key types
//!
//! - [`KfenceObject`] — a single guarded pool slot
//! - [`KfencePool`] — the complete pool of guarded objects
//! - [`KfencePoolError`] — error report produced on a detected violation
//! - [`KfencePoolStats`] — aggregate statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of objects in the KFENCE pool.
pub const KFENCE_POOL_OBJECTS: usize = 256;

/// Page size used by KFENCE (4 KiB).
pub const KFENCE_PAGE_SIZE: usize = 4096;

/// Size of each guard page (one page).
pub const KFENCE_GUARD_SIZE: usize = KFENCE_PAGE_SIZE;

/// Virtual-address window per object (guard + object + guard).
pub const KFENCE_OBJECT_WINDOW: usize = KFENCE_GUARD_SIZE + KFENCE_PAGE_SIZE + KFENCE_GUARD_SIZE;

/// Poison byte written to freed objects.
pub const KFENCE_FREE_POISON: u8 = 0xCC;

/// Default sampling interval (allocations between KFENCE redirections).
pub const KFENCE_DEFAULT_SAMPLE_INTERVAL: u32 = 100;

/// Maximum allocation size that KFENCE can service (one page minus header).
pub const KFENCE_MAX_OBJECT_SIZE: usize = KFENCE_PAGE_SIZE - core::mem::size_of::<KfenceHeader>();

// -------------------------------------------------------------------
// KfenceObjectState
// -------------------------------------------------------------------

/// State of a single KFENCE pool object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KfenceObjectState {
    /// Object is available for allocation.
    #[default]
    Free,
    /// Object is currently allocated and in use.
    Allocated,
    /// Object has been freed; memory is poisoned for UAF detection.
    Freed,
    /// Object is quarantined after a detected violation.
    Quarantined,
}

// -------------------------------------------------------------------
// KfenceErrorKind
// -------------------------------------------------------------------

/// Classification of a KFENCE-detected memory error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfenceErrorKind {
    /// Access beyond the end of the allocation (right OOB).
    OutOfBoundsRight,
    /// Access before the start of the allocation (left OOB).
    OutOfBoundsLeft,
    /// Access to memory that has already been freed.
    UseAfterFree,
    /// Allocation-size metadata mismatch (possible corruption).
    InvalidAccess,
}

// -------------------------------------------------------------------
// KfenceHeader
// -------------------------------------------------------------------

/// Metadata stored at the start of each KFENCE object page.
#[derive(Debug, Clone, Copy)]
pub struct KfenceHeader {
    /// Size of the user allocation in bytes.
    pub alloc_size: u32,
    /// Allocation sequence number for ordering.
    pub seq: u64,
    /// CPU that performed the allocation.
    pub alloc_cpu: u32,
    /// CPU that performed the free (0 while allocated).
    pub free_cpu: u32,
    /// Object state.
    pub state: KfenceObjectState,
    /// Whether right guard is active (object is page-right-aligned).
    pub right_redzone: bool,
}

impl KfenceHeader {
    /// Create a new header for an allocation of `size` bytes.
    pub const fn new(size: u32, seq: u64, cpu: u32) -> Self {
        Self {
            alloc_size: size,
            seq,
            alloc_cpu: cpu,
            free_cpu: 0,
            state: KfenceObjectState::Allocated,
            right_redzone: false,
        }
    }
}

// -------------------------------------------------------------------
// KfenceObject
// -------------------------------------------------------------------

/// A single KFENCE pool slot with its guard-page geometry.
#[derive(Debug)]
pub struct KfenceObject {
    /// Virtual address of the before-guard page (unmapped).
    guard_before_va: u64,
    /// Virtual address of the object page.
    object_va: u64,
    /// Virtual address of the after-guard page (unmapped).
    guard_after_va: u64,
    /// Index of this object within the pool.
    index: u32,
    /// Current lifecycle state.
    state: KfenceObjectState,
    /// Allocation size stored at last `alloc()` call.
    alloc_size: u32,
    /// Monotonic sequence number of last allocation.
    seq: u64,
}

impl KfenceObject {
    /// Construct a new [`KfenceObject`] at the given window virtual address.
    pub fn new(window_va: u64, index: u32) -> Self {
        Self {
            guard_before_va: window_va,
            object_va: window_va + KFENCE_GUARD_SIZE as u64,
            guard_after_va: window_va + (KFENCE_GUARD_SIZE + KFENCE_PAGE_SIZE) as u64,
            index,
            state: KfenceObjectState::Free,
            alloc_size: 0,
            seq: 0,
        }
    }

    /// Attempt to allocate this object for a request of `size` bytes.
    ///
    /// Returns the virtual address of the usable data area.
    pub fn alloc(&mut self, size: usize, seq: u64) -> Result<u64> {
        if self.state != KfenceObjectState::Free {
            return Err(Error::Busy);
        }
        if size > KFENCE_MAX_OBJECT_SIZE || size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.state = KfenceObjectState::Allocated;
        self.alloc_size = size as u32;
        self.seq = seq;
        Ok(self.object_va)
    }

    /// Free this object and poison the page for UAF detection.
    pub fn free(&mut self) -> Result<()> {
        if self.state != KfenceObjectState::Allocated {
            return Err(Error::InvalidArgument);
        }
        self.state = KfenceObjectState::Freed;
        Ok(())
    }

    /// Check whether `va` falls within a guard page of this object.
    pub fn is_guard_access(&self, va: u64) -> bool {
        let in_before =
            va >= self.guard_before_va && va < self.guard_before_va + KFENCE_GUARD_SIZE as u64;
        let in_after =
            va >= self.guard_after_va && va < self.guard_after_va + KFENCE_GUARD_SIZE as u64;
        in_before || in_after
    }

    /// Check whether `va` is within the allocated object region.
    pub fn is_object_access(&self, va: u64) -> bool {
        va >= self.object_va && va < self.object_va + KFENCE_PAGE_SIZE as u64
    }

    /// Classify a faulting access and produce a [`KfencePoolError`] if the
    /// access is anomalous.
    pub fn classify_access(&self, va: u64) -> Option<KfenceErrorKind> {
        if va >= self.guard_after_va && va < self.guard_after_va + KFENCE_GUARD_SIZE as u64 {
            return Some(KfenceErrorKind::OutOfBoundsRight);
        }
        if va >= self.guard_before_va && va < self.guard_before_va + KFENCE_GUARD_SIZE as u64 {
            return Some(KfenceErrorKind::OutOfBoundsLeft);
        }
        if self.state == KfenceObjectState::Freed && self.is_object_access(va) {
            return Some(KfenceErrorKind::UseAfterFree);
        }
        None
    }

    /// Returns the current state of the object.
    pub fn state(&self) -> KfenceObjectState {
        self.state
    }

    /// Returns the object page virtual address.
    pub fn object_va(&self) -> u64 {
        self.object_va
    }

    /// Returns the pool index of this object.
    pub fn index(&self) -> u32 {
        self.index
    }
}

// -------------------------------------------------------------------
// KfencePoolError
// -------------------------------------------------------------------

/// An error report produced by the KFENCE pool upon detecting a violation.
#[derive(Debug, Clone, Copy)]
pub struct KfencePoolError {
    /// The kind of error detected.
    pub kind: KfenceErrorKind,
    /// Faulting virtual address.
    pub fault_va: u64,
    /// Pool object index involved.
    pub object_index: u32,
    /// Allocation size at the time of the violation.
    pub alloc_size: u32,
    /// Sequence number of the allocation.
    pub seq: u64,
}

// -------------------------------------------------------------------
// KfencePoolStats
// -------------------------------------------------------------------

/// Aggregate statistics for the KFENCE pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct KfencePoolStats {
    /// Total number of allocations redirected to the KFENCE pool.
    pub total_allocs: u64,
    /// Total number of frees processed by the KFENCE pool.
    pub total_frees: u64,
    /// Number of guard-page faults detected.
    pub oob_faults: u64,
    /// Number of use-after-free accesses detected.
    pub uaf_faults: u64,
    /// Number of objects currently allocated.
    pub in_use: u32,
    /// Number of objects currently in the freed/poisoned state.
    pub freed_count: u32,
    /// Number of objects currently quarantined.
    pub quarantined: u32,
}

// -------------------------------------------------------------------
// KfencePool
// -------------------------------------------------------------------

/// The KFENCE object pool.
///
/// Manages a fixed set of [`KfenceObject`] entries and tracks the
/// sampling counter that governs when the next allocation should be
/// intercepted.
#[derive(Debug)]
pub struct KfencePool {
    /// All pool objects.
    objects: [Option<KfenceObject>; KFENCE_POOL_OBJECTS],
    /// Base virtual address of the pool window.
    base_va: u64,
    /// Whether the pool has been initialized.
    initialized: bool,
    /// Current allocation sequence counter.
    seq: u64,
    /// Sampling interval: every N normal allocations, one is redirected.
    sample_interval: u32,
    /// Countdown until the next KFENCE allocation.
    sample_countdown: u32,
    /// Aggregate statistics.
    stats: KfencePoolStats,
}

impl KfencePool {
    /// Create an empty, uninitialized pool.
    pub const fn new() -> Self {
        Self {
            objects: [const { None }; KFENCE_POOL_OBJECTS],
            base_va: 0,
            initialized: false,
            seq: 0,
            sample_interval: KFENCE_DEFAULT_SAMPLE_INTERVAL,
            sample_countdown: KFENCE_DEFAULT_SAMPLE_INTERVAL,
            stats: KfencePoolStats {
                total_allocs: 0,
                total_frees: 0,
                oob_faults: 0,
                uaf_faults: 0,
                in_use: 0,
                freed_count: 0,
                quarantined: 0,
            },
        }
    }

    /// Initialize the pool at virtual address `base_va`.
    ///
    /// Constructs all [`KfenceObject`] entries with their guard-page
    /// geometry derived from `base_va`.
    pub fn init(&mut self, base_va: u64) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.base_va = base_va;
        for i in 0..KFENCE_POOL_OBJECTS {
            let window_va = base_va + (i * KFENCE_OBJECT_WINDOW) as u64;
            self.objects[i] = Some(KfenceObject::new(window_va, i as u32));
        }
        self.initialized = true;
        Ok(())
    }

    /// Determine whether the current allocation should be sampled.
    ///
    /// Returns `true` if the caller should redirect this allocation to
    /// the KFENCE pool.
    pub fn should_sample(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        if self.sample_countdown == 0 {
            self.sample_countdown = self.sample_interval;
            return true;
        }
        self.sample_countdown -= 1;
        false
    }

    /// Allocate a KFENCE-guarded object of `size` bytes.
    ///
    /// Returns the virtual address of the data area, or an error if no
    /// free slot is available.
    pub fn alloc(&mut self, size: usize) -> Result<u64> {
        if !self.initialized {
            return Err(Error::NotFound);
        }
        self.seq += 1;
        let seq = self.seq;
        for slot in self.objects.iter_mut().flatten() {
            if slot.state() == KfenceObjectState::Free {
                let va = slot.alloc(size, seq)?;
                self.stats.total_allocs += 1;
                self.stats.in_use += 1;
                return Ok(va);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free the KFENCE object whose data virtual address is `va`.
    pub fn free(&mut self, va: u64) -> Result<()> {
        for slot in self.objects.iter_mut().flatten() {
            if slot.object_va() == va {
                slot.free()?;
                self.stats.total_frees += 1;
                self.stats.in_use = self.stats.in_use.saturating_sub(1);
                self.stats.freed_count += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Handle a page fault at `fault_va`.
    ///
    /// Returns an error report if the fault is attributed to a KFENCE
    /// guard violation, or `None` if the fault is unrelated to the pool.
    pub fn handle_fault(&mut self, fault_va: u64) -> Option<KfencePoolError> {
        for slot in self.objects.iter().flatten() {
            if let Some(kind) = slot.classify_access(fault_va) {
                match kind {
                    KfenceErrorKind::UseAfterFree => self.stats.uaf_faults += 1,
                    _ => self.stats.oob_faults += 1,
                }
                return Some(KfencePoolError {
                    kind,
                    fault_va,
                    object_index: slot.index(),
                    alloc_size: 0,
                    seq: self.seq,
                });
            }
        }
        None
    }

    /// Return a snapshot of pool statistics.
    pub fn stats(&self) -> &KfencePoolStats {
        &self.stats
    }

    /// Set the sampling interval (minimum 1).
    pub fn set_sample_interval(&mut self, interval: u32) {
        self.sample_interval = interval.max(1);
        self.sample_countdown = self.sample_interval;
    }

    /// Returns true if the pool has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for KfencePool {
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
    fn test_object_guard_detection() {
        let obj = KfenceObject::new(0x1000_0000, 0);
        // Before guard: 0x1000_0000..0x1000_1000
        assert!(obj.is_guard_access(0x1000_0000));
        // Object page: 0x1000_1000..0x1000_2000
        assert!(!obj.is_guard_access(0x1000_1000));
        assert!(obj.is_object_access(0x1000_1000));
        // After guard: 0x1000_2000..0x1000_3000
        assert!(obj.is_guard_access(0x1000_2000));
    }

    #[test]
    fn test_pool_alloc_free() {
        let mut pool = KfencePool::new();
        pool.init(0x8000_0000).unwrap();
        let va = pool.alloc(64).unwrap();
        assert_eq!(pool.stats().in_use, 1);
        pool.free(va).unwrap();
        assert_eq!(pool.stats().freed_count, 1);
    }

    #[test]
    fn test_double_init_fails() {
        let mut pool = KfencePool::new();
        pool.init(0x8000_0000).unwrap();
        assert!(pool.init(0x9000_0000).is_err());
    }
}
