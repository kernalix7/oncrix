// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Guard page management.
//!
//! Implements guard pages — unmapped pages placed at the boundaries of
//! stack, heap, and vmap regions to catch overflows. Accessing a guard
//! page triggers a page fault that is converted to a SIGSEGV delivery.
//!
//! - [`GuardType`] — classification of guard region
//! - [`GuardRegion`] — a single guard page region
//! - [`GuardFaultResult`] — outcome of a guard page fault
//! - [`GuardPageManager`] — the guard page manager
//!
//! Reference: `.kernelORG/` — `mm/mmap.c`, `arch/x86/mm/fault.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default guard region size (1 page).
const DEFAULT_GUARD_SIZE: u64 = PAGE_SIZE;

/// Maximum guard regions.
const MAX_GUARD_REGIONS: usize = 512;

/// Signal number for segmentation fault (SIGSEGV).
const SIGSEGV: u32 = 11;

/// Signal sub-code: address not mapped.
const SEGV_MAPERR: u32 = 1;

/// Signal sub-code: stack overflow (guard hit).
const SEGV_STACKFLOW: u32 = 3;

// -------------------------------------------------------------------
// GuardType
// -------------------------------------------------------------------

/// Classification of a guard region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuardType {
    /// Stack guard (below stack VMA).
    #[default]
    Stack,
    /// Heap guard (above brk region).
    Heap,
    /// Vmap guard (between vmap areas in kernel space).
    Vmap,
    /// Module guard (between loaded kernel modules).
    Module,
    /// Custom guard (user-defined).
    Custom,
}

impl GuardType {
    /// Returns a human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            GuardType::Stack => "stack",
            GuardType::Heap => "heap",
            GuardType::Vmap => "vmap",
            GuardType::Module => "module",
            GuardType::Custom => "custom",
        }
    }

    /// Returns the signal sub-code for this guard type.
    pub fn signal_code(self) -> u32 {
        match self {
            GuardType::Stack => SEGV_STACKFLOW,
            _ => SEGV_MAPERR,
        }
    }
}

// -------------------------------------------------------------------
// GuardRegion
// -------------------------------------------------------------------

/// A guard page region.
///
/// Represents one or more contiguous unmapped pages used as a barrier
/// to detect overflow or underflow.
#[derive(Debug, Clone, Copy)]
pub struct GuardRegion {
    /// Start address of the guard region (page-aligned).
    pub start: u64,
    /// Size of the guard region in bytes.
    pub size: u64,
    /// Type of guard.
    pub guard_type: GuardType,
    /// Process ID that owns this guard (0 = kernel).
    pub pid: u32,
    /// Associated VMA start address.
    pub vma_start: u64,
    /// Associated VMA end address.
    pub vma_end: u64,
    /// Whether this guard is active.
    pub active: bool,
}

impl GuardRegion {
    /// Creates a new guard region.
    pub fn new(start: u64, size: u64, guard_type: GuardType, pid: u32) -> Self {
        Self {
            start: start & !(PAGE_SIZE - 1),
            size: ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE,
            guard_type,
            pid,
            vma_start: 0,
            vma_end: 0,
            active: true,
        }
    }

    /// Returns the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Returns the number of guard pages.
    pub fn nr_pages(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Checks if an address falls within this guard region.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end()
    }

    /// Associates the guard with a VMA.
    pub fn set_vma(&mut self, vma_start: u64, vma_end: u64) {
        self.vma_start = vma_start;
        self.vma_end = vma_end;
    }
}

impl Default for GuardRegion {
    fn default() -> Self {
        Self {
            start: 0,
            size: 0,
            guard_type: GuardType::Stack,
            pid: 0,
            vma_start: 0,
            vma_end: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// GuardFaultResult
// -------------------------------------------------------------------

/// Outcome of a guard page fault.
#[derive(Debug, Clone, Copy)]
pub struct GuardFaultResult {
    /// The guard region that was hit.
    pub guard_type: GuardType,
    /// Faulting address.
    pub fault_addr: u64,
    /// Signal to deliver.
    pub signal: u32,
    /// Signal sub-code.
    pub signal_code: u32,
    /// Process ID to signal.
    pub target_pid: u32,
}

impl GuardFaultResult {
    /// Creates a fault result.
    pub fn new(guard_type: GuardType, fault_addr: u64, pid: u32) -> Self {
        Self {
            guard_type,
            fault_addr,
            signal: SIGSEGV,
            signal_code: guard_type.signal_code(),
            target_pid: pid,
        }
    }
}

// -------------------------------------------------------------------
// GuardStats
// -------------------------------------------------------------------

/// Guard page statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardStats {
    /// Total guard regions registered.
    pub total_registered: u64,
    /// Total guard regions removed.
    pub total_removed: u64,
    /// Guard faults caught.
    pub faults_caught: u64,
    /// Stack guard hits.
    pub stack_hits: u64,
    /// Heap guard hits.
    pub heap_hits: u64,
    /// Vmap guard hits.
    pub vmap_hits: u64,
}

// -------------------------------------------------------------------
// GuardPageManager
// -------------------------------------------------------------------

/// Manages guard pages across the system.
///
/// Maintains a registry of guard regions and handles fault detection.
pub struct GuardPageManager {
    /// Guard regions.
    regions: [GuardRegion; MAX_GUARD_REGIONS],
    /// Number of active regions.
    nr_active: usize,
    /// Statistics.
    stats: GuardStats,
}

impl GuardPageManager {
    /// Creates a new guard page manager.
    pub fn new() -> Self {
        Self {
            regions: [GuardRegion::default(); MAX_GUARD_REGIONS],
            nr_active: 0,
            stats: GuardStats::default(),
        }
    }

    /// Inserts a new guard region.
    pub fn insert_guard(
        &mut self,
        start: u64,
        size: u64,
        guard_type: GuardType,
        pid: u32,
    ) -> Result<usize> {
        // Check for overlap with existing guards.
        let end = start + size;
        for region in &self.regions {
            if region.active && pid == region.pid {
                if start < region.end() && end > region.start {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        // Find a free slot.
        for (i, region) in self.regions.iter_mut().enumerate() {
            if !region.active {
                *region = GuardRegion::new(start, size, guard_type, pid);
                self.nr_active += 1;
                self.stats.total_registered += 1;
                return Ok(i);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Removes a guard region.
    pub fn remove_guard(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_GUARD_REGIONS || !self.regions[idx].active {
            return Err(Error::NotFound);
        }
        self.regions[idx].active = false;
        self.nr_active = self.nr_active.saturating_sub(1);
        self.stats.total_removed += 1;
        Ok(())
    }

    /// Removes all guards for a process.
    pub fn remove_guards_for_pid(&mut self, pid: u32) -> usize {
        let mut removed = 0;
        for region in &mut self.regions {
            if region.active && region.pid == pid {
                region.active = false;
                removed += 1;
            }
        }
        self.nr_active = self.nr_active.saturating_sub(removed);
        self.stats.total_removed += removed as u64;
        removed
    }

    /// Handles a page fault: checks if the address hits a guard.
    ///
    /// Returns the fault result if a guard was hit, or `None` if the
    /// address does not belong to any guard region.
    pub fn guard_page_fault_handler(
        &mut self,
        fault_addr: u64,
        pid: u32,
    ) -> Option<GuardFaultResult> {
        for region in &self.regions {
            if region.contains(fault_addr) && (region.pid == pid || region.pid == 0) {
                self.stats.faults_caught += 1;
                match region.guard_type {
                    GuardType::Stack => self.stats.stack_hits += 1,
                    GuardType::Heap => self.stats.heap_hits += 1,
                    GuardType::Vmap => self.stats.vmap_hits += 1,
                    _ => {}
                }
                return Some(GuardFaultResult::new(region.guard_type, fault_addr, pid));
            }
        }
        None
    }

    /// Checks if an address is a guard page.
    pub fn is_guard_page(&self, addr: u64, pid: u32) -> bool {
        self.regions
            .iter()
            .any(|r| r.contains(addr) && (r.pid == pid || r.pid == 0))
    }

    /// Returns the guard region at the given index.
    pub fn get_region(&self, idx: usize) -> Option<&GuardRegion> {
        if idx >= MAX_GUARD_REGIONS || !self.regions[idx].active {
            return None;
        }
        Some(&self.regions[idx])
    }

    /// Returns statistics.
    pub fn stats(&self) -> &GuardStats {
        &self.stats
    }

    /// Returns the number of active guard regions.
    pub fn nr_active(&self) -> usize {
        self.nr_active
    }
}

impl Default for GuardPageManager {
    fn default() -> Self {
        Self::new()
    }
}
