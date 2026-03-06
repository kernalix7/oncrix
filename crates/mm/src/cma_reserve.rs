// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMA reservation management.
//!
//! Contiguous Memory Allocator (CMA) reserves large physically
//! contiguous regions at boot time. These regions serve movable
//! allocations normally but can be reclaimed for DMA or huge-page
//! use when contiguous memory is needed. This module manages CMA
//! reservations: setup, activation, and migration of movable pages
//! out of the reserved area when a contiguous allocation is requested.
//!
//! # Design
//!
//! ```text
//!  cma_declare_contiguous(size, alignment)   [boot-time]
//!     │
//!     └─ reserve [base, base+size) as CMA region
//!
//!  cma_alloc(cma, count, align)              [runtime]
//!     │
//!     ├─ find free range in CMA bitmap
//!     ├─ migrate movable pages out of range
//!     └─ return contiguous PFN range
//! ```
//!
//! # Key Types
//!
//! - [`CmaReservation`] — a single CMA reservation
//! - [`CmaReserveManager`] — manages all reservations
//! - [`CmaReserveStats`] — reservation statistics
//!
//! Reference: Linux `mm/cma.c`, `include/linux/cma.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum CMA reservations.
const MAX_RESERVATIONS: usize = 32;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Default alignment (2 MiB).
const DEFAULT_ALIGNMENT: u64 = 2 * 1024 * 1024;

/// Maximum CMA region size in pages.
const MAX_REGION_PAGES: u64 = 1 << 20; // ~4 GiB

// -------------------------------------------------------------------
// CmaReservation
// -------------------------------------------------------------------

/// A single CMA reservation.
#[derive(Debug, Clone, Copy)]
pub struct CmaReservation {
    /// Reservation ID.
    reserve_id: u32,
    /// Base PFN.
    base_pfn: u64,
    /// Size in pages.
    page_count: u64,
    /// Alignment in pages.
    alignment_pages: u64,
    /// Number of pages currently allocated (contiguous allocs).
    allocated_pages: u64,
    /// Number of movable pages using this region.
    movable_pages: u64,
    /// Whether the reservation is active.
    active: bool,
    /// Total allocation requests.
    alloc_requests: u64,
    /// Allocation failures.
    alloc_failures: u64,
}

impl CmaReservation {
    /// Create a new reservation.
    pub const fn new(
        reserve_id: u32,
        base_pfn: u64,
        page_count: u64,
        alignment_pages: u64,
    ) -> Self {
        Self {
            reserve_id,
            base_pfn,
            page_count,
            alignment_pages,
            allocated_pages: 0,
            movable_pages: 0,
            active: true,
            alloc_requests: 0,
            alloc_failures: 0,
        }
    }

    /// Return the reservation ID.
    pub const fn reserve_id(&self) -> u32 {
        self.reserve_id
    }

    /// Return the base PFN.
    pub const fn base_pfn(&self) -> u64 {
        self.base_pfn
    }

    /// Return the page count.
    pub const fn page_count(&self) -> u64 {
        self.page_count
    }

    /// Return the alignment in pages.
    pub const fn alignment_pages(&self) -> u64 {
        self.alignment_pages
    }

    /// Return the allocated pages.
    pub const fn allocated_pages(&self) -> u64 {
        self.allocated_pages
    }

    /// Return the movable pages.
    pub const fn movable_pages(&self) -> u64 {
        self.movable_pages
    }

    /// Check whether active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.page_count * PAGE_SIZE
    }

    /// Free pages available for contiguous allocation.
    pub const fn free_pages(&self) -> u64 {
        self.page_count - self.allocated_pages
    }

    /// Utilization as percent.
    pub const fn utilization_pct(&self) -> u64 {
        if self.page_count == 0 {
            return 0;
        }
        self.allocated_pages * 100 / self.page_count
    }

    /// Allocate contiguous pages.
    pub fn alloc(&mut self, pages: u64) -> Result<u64> {
        self.alloc_requests += 1;
        if pages > self.free_pages() {
            self.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }
        let pfn = self.base_pfn + self.allocated_pages;
        self.allocated_pages += pages;
        Ok(pfn)
    }

    /// Free contiguous pages.
    pub fn free(&mut self, pages: u64) -> Result<()> {
        if pages > self.allocated_pages {
            return Err(Error::InvalidArgument);
        }
        self.allocated_pages -= pages;
        Ok(())
    }

    /// Set movable page count.
    pub fn set_movable_pages(&mut self, count: u64) {
        self.movable_pages = count;
    }
}

impl Default for CmaReservation {
    fn default() -> Self {
        Self {
            reserve_id: 0,
            base_pfn: 0,
            page_count: 0,
            alignment_pages: 0,
            allocated_pages: 0,
            movable_pages: 0,
            active: false,
            alloc_requests: 0,
            alloc_failures: 0,
        }
    }
}

// -------------------------------------------------------------------
// CmaReserveStats
// -------------------------------------------------------------------

/// Reservation statistics.
#[derive(Debug, Clone, Copy)]
pub struct CmaReserveStats {
    /// Total reservations created.
    pub total_reservations: u64,
    /// Total pages reserved.
    pub total_reserved_pages: u64,
    /// Total allocation requests.
    pub total_alloc_requests: u64,
    /// Total allocation failures.
    pub total_alloc_failures: u64,
    /// Total pages allocated.
    pub total_allocated_pages: u64,
}

impl CmaReserveStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_reservations: 0,
            total_reserved_pages: 0,
            total_alloc_requests: 0,
            total_alloc_failures: 0,
            total_allocated_pages: 0,
        }
    }

    /// Success rate as percent.
    pub const fn success_pct(&self) -> u64 {
        if self.total_alloc_requests == 0 {
            return 100;
        }
        (self.total_alloc_requests - self.total_alloc_failures) * 100 / self.total_alloc_requests
    }
}

impl Default for CmaReserveStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CmaReserveManager
// -------------------------------------------------------------------

/// Manages all CMA reservations.
pub struct CmaReserveManager {
    /// Reservations.
    reservations: [CmaReservation; MAX_RESERVATIONS],
    /// Number of reservations.
    count: usize,
    /// Next reservation ID.
    next_id: u32,
    /// Statistics.
    stats: CmaReserveStats,
}

impl CmaReserveManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            reservations: [const {
                CmaReservation {
                    reserve_id: 0,
                    base_pfn: 0,
                    page_count: 0,
                    alignment_pages: 0,
                    allocated_pages: 0,
                    movable_pages: 0,
                    active: false,
                    alloc_requests: 0,
                    alloc_failures: 0,
                }
            }; MAX_RESERVATIONS],
            count: 0,
            next_id: 1,
            stats: CmaReserveStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &CmaReserveStats {
        &self.stats
    }

    /// Return the count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Declare a contiguous reservation.
    pub fn declare(&mut self, base_pfn: u64, page_count: u64, alignment_pages: u64) -> Result<u32> {
        if page_count == 0 || page_count > MAX_REGION_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_RESERVATIONS {
            return Err(Error::OutOfMemory);
        }
        let rid = self.next_id;
        self.reservations[self.count] =
            CmaReservation::new(rid, base_pfn, page_count, alignment_pages);
        self.count += 1;
        self.next_id += 1;
        self.stats.total_reservations += 1;
        self.stats.total_reserved_pages += page_count;
        Ok(rid)
    }

    /// Allocate from a reservation.
    pub fn alloc(&mut self, reserve_id: u32, pages: u64) -> Result<u64> {
        for idx in 0..self.count {
            if self.reservations[idx].reserve_id() == reserve_id && self.reservations[idx].active()
            {
                let pfn = self.reservations[idx].alloc(pages)?;
                self.stats.total_alloc_requests += 1;
                self.stats.total_allocated_pages += pages;
                return Ok(pfn);
            }
        }
        Err(Error::NotFound)
    }

    /// Free to a reservation.
    pub fn free(&mut self, reserve_id: u32, pages: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.reservations[idx].reserve_id() == reserve_id {
                return self.reservations[idx].free(pages);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a reservation.
    pub fn find(&self, reserve_id: u32) -> Option<&CmaReservation> {
        for idx in 0..self.count {
            if self.reservations[idx].reserve_id() == reserve_id {
                return Some(&self.reservations[idx]);
            }
        }
        None
    }

    /// Total reserved bytes.
    pub fn total_reserved_bytes(&self) -> u64 {
        self.stats.total_reserved_pages * PAGE_SIZE
    }
}

impl Default for CmaReserveManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum reservations.
pub const fn max_reservations() -> usize {
    MAX_RESERVATIONS
}

/// Return the default alignment.
pub const fn default_alignment() -> u64 {
    DEFAULT_ALIGNMENT
}
