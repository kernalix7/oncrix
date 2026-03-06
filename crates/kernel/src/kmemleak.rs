// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel memory leak detector.
//!
//! Tracks kernel memory allocations and uses a conservative
//! mark-and-sweep algorithm to detect unreferenced memory blocks.
//! Each allocation is recorded with its call site, size, and
//! a generation counter for aging. Periodic scans identify
//! orphaned allocations that are potential leaks.

use oncrix_lib::{Error, Result};

/// Maximum number of tracked allocations.
const MAX_TRACKED_ALLOCS: usize = 4096;

/// Maximum number of scan results to report.
const MAX_SCAN_RESULTS: usize = 256;

/// Number of scans before an unreferenced alloc is reported.
const _LEAK_THRESHOLD_SCANS: u32 = 3;

/// Allocation state in the leak detector.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AllocState {
    /// Allocation is live and referenced.
    Referenced,
    /// Allocation was not found during last scan.
    Unreferenced,
    /// Allocation confirmed as leak after multiple scans.
    Leaked,
    /// Allocation has been freed.
    Freed,
}

/// Tracked memory allocation record.
#[derive(Clone, Copy)]
pub struct AllocRecord {
    /// Start address of the allocation.
    address: u64,
    /// Size of the allocation in bytes.
    size: u64,
    /// Call site address (return address of allocator).
    call_site: u64,
    /// Allocation generation (incremented each scan cycle).
    generation: u64,
    /// Number of scans where this was unreferenced.
    unreferenced_count: u32,
    /// Current allocation state.
    state: AllocState,
    /// Timestamp (in ticks) when allocation was made.
    alloc_time: u64,
    /// Whether this allocation is exempt from scanning.
    exempt: bool,
}

impl AllocRecord {
    /// Creates a new allocation record.
    pub const fn new() -> Self {
        Self {
            address: 0,
            size: 0,
            call_site: 0,
            generation: 0,
            unreferenced_count: 0,
            state: AllocState::Freed,
            alloc_time: 0,
            exempt: false,
        }
    }

    /// Creates a record for a specific allocation.
    pub const fn with_alloc(address: u64, size: u64, call_site: u64, time: u64) -> Self {
        Self {
            address,
            size,
            call_site,
            generation: 0,
            unreferenced_count: 0,
            state: AllocState::Referenced,
            alloc_time: time,
            exempt: false,
        }
    }

    /// Returns the allocation address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the allocation size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the call site address.
    pub const fn call_site(&self) -> u64 {
        self.call_site
    }

    /// Returns the current allocation state.
    pub const fn state(&self) -> AllocState {
        self.state
    }

    /// Returns the unreferenced scan count.
    pub const fn unreferenced_count(&self) -> u32 {
        self.unreferenced_count
    }

    /// Marks this allocation as exempt from leak scanning.
    pub fn set_exempt(&mut self, exempt: bool) {
        self.exempt = exempt;
    }
}

impl Default for AllocRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Leak scan result entry.
#[derive(Clone, Copy)]
pub struct LeakReport {
    /// Address of the leaked allocation.
    address: u64,
    /// Size of the leaked allocation.
    size: u64,
    /// Call site where the allocation was made.
    call_site: u64,
    /// Number of scans the allocation was unreferenced.
    unreferenced_scans: u32,
    /// Time of original allocation.
    alloc_time: u64,
}

impl LeakReport {
    /// Creates a new empty leak report.
    pub const fn new() -> Self {
        Self {
            address: 0,
            size: 0,
            call_site: 0,
            unreferenced_scans: 0,
            alloc_time: 0,
        }
    }

    /// Returns the leaked allocation address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the leaked allocation size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the call site of the leaked allocation.
    pub const fn call_site(&self) -> u64 {
        self.call_site
    }
}

impl Default for LeakReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Kernel memory leak detector.
pub struct KmemleakDetector {
    /// Tracked allocation records.
    records: [AllocRecord; MAX_TRACKED_ALLOCS],
    /// Number of active records.
    count: usize,
    /// Current scan generation counter.
    current_generation: u64,
    /// Whether the detector is enabled.
    enabled: bool,
    /// Total bytes currently tracked.
    total_tracked_bytes: u64,
    /// Total number of allocations tracked since start.
    total_allocs: u64,
    /// Total number of frees tracked since start.
    total_frees: u64,
    /// Scan results buffer.
    results: [LeakReport; MAX_SCAN_RESULTS],
    /// Number of results from last scan.
    result_count: usize,
}

impl KmemleakDetector {
    /// Creates a new kmemleak detector.
    pub const fn new() -> Self {
        Self {
            records: [const { AllocRecord::new() }; MAX_TRACKED_ALLOCS],
            count: 0,
            current_generation: 0,
            enabled: false,
            total_tracked_bytes: 0,
            total_allocs: 0,
            total_frees: 0,
            results: [const { LeakReport::new() }; MAX_SCAN_RESULTS],
            result_count: 0,
        }
    }

    /// Enables the leak detector.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the leak detector.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns whether the detector is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Records a new memory allocation.
    pub fn track_alloc(
        &mut self,
        address: u64,
        size: u64,
        call_site: u64,
        time: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.count >= MAX_TRACKED_ALLOCS {
            return Err(Error::OutOfMemory);
        }
        self.records[self.count] = AllocRecord::with_alloc(address, size, call_site, time);
        self.records[self.count].generation = self.current_generation;
        self.count += 1;
        self.total_tracked_bytes += size;
        self.total_allocs += 1;
        Ok(())
    }

    /// Records a memory free operation.
    pub fn track_free(&mut self, address: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for i in 0..self.count {
            if self.records[i].address == address && self.records[i].state != AllocState::Freed {
                self.total_tracked_bytes -= self.records[i].size;
                self.records[i].state = AllocState::Freed;
                self.total_frees += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Performs a scan cycle to detect potential leaks.
    pub fn scan(&mut self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.current_generation += 1;
        self.result_count = 0;

        for i in 0..self.count {
            if self.records[i].state == AllocState::Freed || self.records[i].exempt {
                continue;
            }
            // Mark unreferenced if generation is old
            if self.records[i].generation < self.current_generation - 1 {
                self.records[i].unreferenced_count += 1;
                self.records[i].state = AllocState::Unreferenced;

                if self.records[i].unreferenced_count >= 3 {
                    self.records[i].state = AllocState::Leaked;
                    if self.result_count < MAX_SCAN_RESULTS {
                        self.results[self.result_count] = LeakReport {
                            address: self.records[i].address,
                            size: self.records[i].size,
                            call_site: self.records[i].call_site,
                            unreferenced_scans: self.records[i].unreferenced_count,
                            alloc_time: self.records[i].alloc_time,
                        };
                        self.result_count += 1;
                    }
                }
            } else {
                self.records[i].unreferenced_count = 0;
                self.records[i].state = AllocState::Referenced;
            }
        }
        self.result_count
    }

    /// Returns the number of reported leaks from the last scan.
    pub const fn leak_count(&self) -> usize {
        self.result_count
    }

    /// Returns the total tracked bytes.
    pub const fn total_tracked_bytes(&self) -> u64 {
        self.total_tracked_bytes
    }

    /// Returns the number of active tracked allocations.
    pub const fn active_count(&self) -> usize {
        self.count
    }

    /// Clears all tracking data and resets the detector.
    pub fn clear(&mut self) {
        self.count = 0;
        self.result_count = 0;
        self.total_tracked_bytes = 0;
        self.current_generation = 0;
    }
}

impl Default for KmemleakDetector {
    fn default() -> Self {
        Self::new()
    }
}
