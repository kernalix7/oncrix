// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Secret memory area management.
//!
//! Secret memory areas are memory regions created via
//! `memfd_secret(2)` that are removed from the kernel's direct map,
//! preventing even the kernel from reading the contents. This module
//! manages the lifecycle of secret areas: allocation, direct-map
//! removal, access control, and cleanup.
//!
//! # Design
//!
//! ```text
//!  memfd_secret(flags)
//!     │
//!     ├─ allocate pages
//!     ├─ remove pages from kernel direct map
//!     ├─ create VMA with VM_LOCKED | VM_IO
//!     └─ on close: restore direct map, free pages
//! ```
//!
//! # Key Types
//!
//! - [`SecretArea`] — a single secret memory area
//! - [`SecretAreaTable`] — tracks all secret areas
//! - [`SecretAreaStats`] — allocation statistics
//!
//! Reference: Linux `mm/secretmem.c`, `memfd_secret(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum secret areas.
const MAX_SECRET_AREAS: usize = 256;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum secret area size in pages.
const MAX_AREA_PAGES: u64 = 1024;

// -------------------------------------------------------------------
// SecretArea
// -------------------------------------------------------------------

/// A single secret memory area.
#[derive(Debug, Clone, Copy)]
pub struct SecretArea {
    /// Area ID.
    area_id: u64,
    /// File descriptor.
    fd: u64,
    /// Owner PID.
    owner_pid: u64,
    /// Start physical frame number.
    start_pfn: u64,
    /// Number of pages.
    page_count: u64,
    /// Whether the area is active (direct map removed).
    active: bool,
    /// Whether pages are locked in memory.
    locked: bool,
    /// Timestamp of creation.
    created_at: u64,
    /// Number of page faults.
    fault_count: u64,
}

impl SecretArea {
    /// Create a new secret area.
    pub const fn new(
        area_id: u64,
        fd: u64,
        owner_pid: u64,
        start_pfn: u64,
        page_count: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            area_id,
            fd,
            owner_pid,
            start_pfn,
            page_count,
            active: true,
            locked: true,
            created_at: timestamp,
            fault_count: 0,
        }
    }

    /// Return the area ID.
    pub const fn area_id(&self) -> u64 {
        self.area_id
    }

    /// Return the file descriptor.
    pub const fn fd(&self) -> u64 {
        self.fd
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return the start PFN.
    pub const fn start_pfn(&self) -> u64 {
        self.start_pfn
    }

    /// Return the page count.
    pub const fn page_count(&self) -> u64 {
        self.page_count
    }

    /// Return the size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.page_count * PAGE_SIZE
    }

    /// Check whether the area is active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Check whether pages are locked.
    pub const fn locked(&self) -> bool {
        self.locked
    }

    /// Return the fault count.
    pub const fn fault_count(&self) -> u64 {
        self.fault_count
    }

    /// Record a page fault.
    pub fn record_fault(&mut self) {
        self.fault_count = self.fault_count.saturating_add(1);
    }

    /// Deactivate (restore direct map, mark for cleanup).
    pub fn deactivate(&mut self) {
        self.active = false;
        self.locked = false;
    }

    /// Check whether a PFN belongs to this area.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.start_pfn + self.page_count
    }
}

impl Default for SecretArea {
    fn default() -> Self {
        Self {
            area_id: 0,
            fd: 0,
            owner_pid: 0,
            start_pfn: 0,
            page_count: 0,
            active: false,
            locked: false,
            created_at: 0,
            fault_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// SecretAreaStats
// -------------------------------------------------------------------

/// Secret area statistics.
#[derive(Debug, Clone, Copy)]
pub struct SecretAreaStats {
    /// Total areas created.
    pub total_created: u64,
    /// Total areas destroyed.
    pub total_destroyed: u64,
    /// Total pages allocated for secrets.
    pub total_pages: u64,
    /// Total page faults.
    pub total_faults: u64,
    /// Creation failures.
    pub create_failures: u64,
}

impl SecretAreaStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_created: 0,
            total_destroyed: 0,
            total_pages: 0,
            total_faults: 0,
            create_failures: 0,
        }
    }

    /// Active area count.
    pub const fn active_count(&self) -> u64 {
        self.total_created - self.total_destroyed
    }
}

impl Default for SecretAreaStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SecretAreaTable
// -------------------------------------------------------------------

/// Tracks all secret memory areas.
pub struct SecretAreaTable {
    /// Areas.
    areas: [SecretArea; MAX_SECRET_AREAS],
    /// Number of areas.
    count: usize,
    /// Next area ID.
    next_id: u64,
    /// Statistics.
    stats: SecretAreaStats,
}

impl SecretAreaTable {
    /// Create a new table.
    pub const fn new() -> Self {
        Self {
            areas: [const {
                SecretArea {
                    area_id: 0,
                    fd: 0,
                    owner_pid: 0,
                    start_pfn: 0,
                    page_count: 0,
                    active: false,
                    locked: false,
                    created_at: 0,
                    fault_count: 0,
                }
            }; MAX_SECRET_AREAS],
            count: 0,
            next_id: 1,
            stats: SecretAreaStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &SecretAreaStats {
        &self.stats
    }

    /// Return the number of areas.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Create a secret area.
    pub fn create(
        &mut self,
        fd: u64,
        owner_pid: u64,
        start_pfn: u64,
        page_count: u64,
        timestamp: u64,
    ) -> Result<u64> {
        if page_count == 0 || page_count > MAX_AREA_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_SECRET_AREAS {
            self.stats.create_failures += 1;
            return Err(Error::OutOfMemory);
        }
        let aid = self.next_id;
        self.areas[self.count] =
            SecretArea::new(aid, fd, owner_pid, start_pfn, page_count, timestamp);
        self.count += 1;
        self.next_id += 1;
        self.stats.total_created += 1;
        self.stats.total_pages += page_count;
        Ok(aid)
    }

    /// Destroy a secret area.
    pub fn destroy(&mut self, area_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.areas[idx].area_id() == area_id && self.areas[idx].active() {
                self.areas[idx].deactivate();
                self.stats.total_destroyed += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a secret area by ID.
    pub fn find(&self, area_id: u64) -> Option<&SecretArea> {
        for idx in 0..self.count {
            if self.areas[idx].area_id() == area_id {
                return Some(&self.areas[idx]);
            }
        }
        None
    }

    /// Check whether a PFN is in a secret area.
    pub fn is_secret(&self, pfn: u64) -> bool {
        for idx in 0..self.count {
            if self.areas[idx].active() && self.areas[idx].contains_pfn(pfn) {
                return true;
            }
        }
        false
    }

    /// Total secret memory in bytes.
    pub fn total_secret_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for idx in 0..self.count {
            if self.areas[idx].active() {
                total += self.areas[idx].size_bytes();
            }
        }
        total
    }
}

impl Default for SecretAreaTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum secret areas.
pub const fn max_secret_areas() -> usize {
    MAX_SECRET_AREAS
}

/// Return the maximum area size in pages.
pub const fn max_area_pages() -> u64 {
    MAX_AREA_PAGES
}
