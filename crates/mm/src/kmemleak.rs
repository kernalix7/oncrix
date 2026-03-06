// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel memory leak detector.
//!
//! Tracks all kernel memory allocations and periodically scans them
//! to find objects that are no longer referenced by any other tracked
//! allocation.  Unreferenced objects are likely leaks.
//!
//! Inspired by the Linux `mm/kmemleak.c` subsystem.
//!
//! # Design
//!
//! Every call to `track_alloc` registers an object in the
//! [`ObjectTable`].  `track_free` removes it.  When a scan is
//! triggered (`scan_memory`), every tracked object is searched for
//! pointer-sized values that point into other tracked objects.
//! Objects that are never pointed to by any other object are
//! considered **orphans** and reported as potential leaks.
//!
//! - [`TrackedObject`] — per-allocation metadata
//! - [`ObjectTable`] — hash-table of tracked allocations
//! - [`LeakReport`] — describes a single potential leak
//! - [`MemleakScanner`] — top-level scanner combining tracking and
//!   scanning

use oncrix_lib::Result;

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of tracked objects.
const MAX_TRACKED_OBJECTS: usize = 4096;

/// Maximum number of leak reports retained after a scan.
const MAX_LEAK_REPORTS: usize = 256;

/// Size of a pointer in the target architecture (bytes).
const PTR_SIZE: usize = 8;

// -------------------------------------------------------------------
// ScanState
// -------------------------------------------------------------------

/// State of the memory leak scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanState {
    /// No scan is in progress.
    #[default]
    Idle,
    /// A scan is currently running.
    Scanning,
    /// The most recent scan has completed; results are available.
    Complete,
}

// -------------------------------------------------------------------
// TrackedObject
// -------------------------------------------------------------------

/// Metadata for a single tracked kernel allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrackedObject {
    /// Virtual address of the allocation.
    pub addr: u64,
    /// Size of the allocation in bytes.
    pub size: u64,
    /// Monotonically increasing allocation identifier.
    pub allocation_id: u64,
    /// Incoming reference count (set during scans).
    pub ref_count: u32,
    /// Whether this object appears to be an orphan (unreferenced).
    pub is_orphan: bool,
    /// Whether this slot is occupied.
    occupied: bool,
}

// -------------------------------------------------------------------
// ObjectTable
// -------------------------------------------------------------------

/// Fixed-capacity hash table of tracked kernel allocations.
///
/// Uses open addressing with linear probing.  The hash function is
/// a simple multiplicative hash on the allocation address.
pub struct ObjectTable {
    /// Flat storage for tracked objects.
    objects: [TrackedObject; MAX_TRACKED_OBJECTS],
    /// Number of occupied slots.
    count: usize,
    /// Monotonically increasing allocation identifier generator.
    next_id: u64,
}

impl Default for ObjectTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectTable {
    /// Creates a new, empty object table.
    pub const fn new() -> Self {
        const EMPTY: TrackedObject = TrackedObject {
            addr: 0,
            size: 0,
            allocation_id: 0,
            ref_count: 0,
            is_orphan: false,
            occupied: false,
        };
        Self {
            objects: [EMPTY; MAX_TRACKED_OBJECTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Hash an address to a table index.
    fn hash(addr: u64) -> usize {
        // Multiplicative hash (Knuth variant).
        let h = addr.wrapping_mul(0x517c_c1b7_2722_0a95);
        (h >> 48) as usize % MAX_TRACKED_OBJECTS
    }

    /// Register a new allocation for tracking.
    ///
    /// Returns the allocation identifier assigned to this object,
    /// or an error if the table is full.
    pub fn track_alloc(&mut self, addr: u64, size: u64) -> Result<u64> {
        if self.count >= MAX_TRACKED_OBJECTS {
            return Err(oncrix_lib::Error::OutOfMemory);
        }

        let mut idx = Self::hash(addr);
        for _ in 0..MAX_TRACKED_OBJECTS {
            if !self.objects[idx].occupied {
                let id = self.next_id;
                self.next_id += 1;
                self.objects[idx] = TrackedObject {
                    addr,
                    size,
                    allocation_id: id,
                    ref_count: 0,
                    is_orphan: false,
                    occupied: true,
                };
                self.count += 1;
                return Ok(id);
            }
            idx = (idx + 1) % MAX_TRACKED_OBJECTS;
        }

        Err(oncrix_lib::Error::OutOfMemory)
    }

    /// Remove a tracked allocation by address.
    ///
    /// Returns `Ok(())` if the object was found and removed, or
    /// `Err(NotFound)` if no allocation with that address is tracked.
    pub fn track_free(&mut self, addr: u64) -> Result<()> {
        let mut idx = Self::hash(addr);
        for _ in 0..MAX_TRACKED_OBJECTS {
            let obj = &self.objects[idx];
            if !obj.occupied {
                return Err(oncrix_lib::Error::NotFound);
            }
            if obj.addr == addr {
                self.objects[idx].occupied = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
            idx = (idx + 1) % MAX_TRACKED_OBJECTS;
        }
        Err(oncrix_lib::Error::NotFound)
    }

    /// Look up a tracked object by address.
    pub fn find(&self, addr: u64) -> Option<&TrackedObject> {
        let mut idx = Self::hash(addr);
        for _ in 0..MAX_TRACKED_OBJECTS {
            let obj = &self.objects[idx];
            if !obj.occupied {
                return None;
            }
            if obj.addr == addr {
                return Some(obj);
            }
            idx = (idx + 1) % MAX_TRACKED_OBJECTS;
        }
        None
    }

    /// Returns the number of tracked objects.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if no objects are tracked.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check whether `ptr` falls within any tracked allocation.
    fn contains_ptr(&self, ptr: u64) -> bool {
        for obj in &self.objects {
            if obj.occupied && ptr >= obj.addr && ptr < obj.addr + obj.size {
                return true;
            }
        }
        false
    }

    /// Reset all reference counts and orphan flags in preparation
    /// for a new scan pass.
    fn reset_refs(&mut self) {
        for obj in &mut self.objects {
            if obj.occupied {
                obj.ref_count = 0;
                obj.is_orphan = false;
            }
        }
    }

    /// Increment the reference count of the object that contains
    /// `ptr`, if any.
    fn add_ref_for_ptr(&mut self, ptr: u64) {
        for obj in &mut self.objects {
            if obj.occupied && ptr >= obj.addr && ptr < obj.addr + obj.size {
                obj.ref_count = obj.ref_count.saturating_add(1);
                return;
            }
        }
    }

    /// Iterate over all occupied objects.
    fn iter_occupied(&self) -> impl Iterator<Item = &TrackedObject> {
        self.objects.iter().filter(|o| o.occupied)
    }
}

// -------------------------------------------------------------------
// LeakReport
// -------------------------------------------------------------------

/// Describes a single potential memory leak.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeakReport {
    /// Virtual address of the unreferenced allocation.
    pub addr: u64,
    /// Size of the allocation in bytes.
    pub size: u64,
    /// Allocation identifier.
    pub allocation_id: u64,
    /// Age of the allocation (number of scans it has survived as
    /// orphan).
    pub age: u32,
}

// -------------------------------------------------------------------
// MemleakScanner
// -------------------------------------------------------------------

/// Top-level kernel memory leak scanner.
///
/// Combines an [`ObjectTable`] for tracking allocations with a
/// scanning engine that searches for inter-object pointers to
/// identify unreferenced (leaked) objects.
pub struct MemleakScanner {
    /// Tracked allocations.
    table: ObjectTable,
    /// Leak reports from the most recent scan.
    reports: [LeakReport; MAX_LEAK_REPORTS],
    /// Number of valid reports.
    report_count: usize,
    /// Current scanner state.
    state: ScanState,
    /// Whether the scanner is globally enabled.
    enabled: bool,
    /// Number of scans completed.
    scan_count: u64,
}

impl Default for MemleakScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MemleakScanner {
    /// Creates a new, disabled scanner.
    pub const fn new() -> Self {
        const EMPTY_REPORT: LeakReport = LeakReport {
            addr: 0,
            size: 0,
            allocation_id: 0,
            age: 0,
        };
        Self {
            table: ObjectTable::new(),
            reports: [EMPTY_REPORT; MAX_LEAK_REPORTS],
            report_count: 0,
            state: ScanState::Idle,
            enabled: false,
            scan_count: 0,
        }
    }

    /// Enable the scanner.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the scanner.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns `true` if the scanner is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the current scanner state.
    pub fn state(&self) -> ScanState {
        self.state
    }

    /// Register an allocation for tracking.
    ///
    /// See [`ObjectTable::track_alloc`].
    pub fn track_alloc(&mut self, addr: u64, size: u64) -> Result<u64> {
        if !self.enabled {
            return Err(oncrix_lib::Error::NotImplemented);
        }
        self.table.track_alloc(addr, size)
    }

    /// Deregister an allocation.
    ///
    /// See [`ObjectTable::track_free`].
    pub fn track_free(&mut self, addr: u64) -> Result<()> {
        if !self.enabled {
            return Err(oncrix_lib::Error::NotImplemented);
        }
        self.table.track_free(addr)
    }

    /// Run a full memory scan.
    ///
    /// This is an O(n^2) operation over all tracked objects. Each
    /// object's memory region is searched for pointer-sized values
    /// that reference other tracked objects.  Objects with zero
    /// incoming references after the scan are marked as orphans.
    ///
    /// # Safety
    ///
    /// In a real kernel this would dereference raw pointers to scan
    /// memory contents. In this stub implementation we simulate the
    /// scan by checking address containment only, without reading
    /// actual memory contents. The unsafe marker documents that the
    /// production version will require unsafe reads.
    pub fn scan_memory(&mut self) {
        if !self.enabled {
            return;
        }

        self.state = ScanState::Scanning;
        self.table.reset_refs();

        // Collect addresses and sizes of all tracked objects so we
        // can iterate them while mutating ref counts.
        let mut addrs: [u64; MAX_TRACKED_OBJECTS] = [0; MAX_TRACKED_OBJECTS];
        let mut sizes: [u64; MAX_TRACKED_OBJECTS] = [0; MAX_TRACKED_OBJECTS];
        let mut n = 0;
        for obj in self.table.iter_occupied() {
            if n >= MAX_TRACKED_OBJECTS {
                break;
            }
            addrs[n] = obj.addr;
            sizes[n] = obj.size;
            n += 1;
        }

        // For each tracked object, walk its address range at
        // pointer-sized steps. Simulated: treat each aligned address
        // within the object as a potential pointer value and check if
        // it falls inside another tracked object.
        for i in 0..n {
            let obj_addr = addrs[i];
            let obj_size = sizes[i];
            let mut offset: u64 = 0;
            while offset + PTR_SIZE as u64 <= obj_size {
                // In a real implementation we would read the pointer
                // value from memory. Here we simulate by computing a
                // candidate pointer from the object's address range.
                let candidate = obj_addr + offset;
                if self.table.contains_ptr(candidate) {
                    self.table.add_ref_for_ptr(candidate);
                }
                offset += PTR_SIZE as u64;
            }
        }

        // Mark unreferenced objects as orphans and build reports.
        self.report_count = 0;
        for obj in &mut self.table.objects {
            if !obj.occupied {
                continue;
            }
            if obj.ref_count == 0 {
                obj.is_orphan = true;
                if self.report_count < MAX_LEAK_REPORTS {
                    self.reports[self.report_count] = LeakReport {
                        addr: obj.addr,
                        size: obj.size,
                        allocation_id: obj.allocation_id,
                        age: 1,
                    };
                    self.report_count += 1;
                }
            }
        }

        self.scan_count += 1;
        self.state = ScanState::Complete;
    }

    /// Returns the leak reports from the most recent scan.
    pub fn find_leaks(&self) -> &[LeakReport] {
        &self.reports[..self.report_count]
    }

    /// Clear all scan results.
    pub fn clear_results(&mut self) {
        self.report_count = 0;
        self.state = ScanState::Idle;
    }

    /// Trigger a new scan (convenience alias for [`scan_memory`]).
    pub fn trigger_scan(&mut self) {
        self.scan_memory();
    }

    /// Returns the number of completed scans.
    pub fn scan_count(&self) -> u64 {
        self.scan_count
    }

    /// Returns an immutable reference to the object table.
    pub fn table(&self) -> &ObjectTable {
        &self.table
    }
}
