// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hugetlb reservation accounting.
//!
//! When a user requests a hugetlb-backed mmap the kernel must
//! guarantee that enough huge pages will be available at fault time.
//! This module tracks reservation counts per huge page size, validates
//! new reservations against available pool and surplus limits, and
//! manages the lifecycle from reserve → commit → unreserve.
//!
//! # Design
//!
//! ```text
//!  mmap(MAP_HUGETLB) → HugetlbReserve::reserve(size, count)
//!       │
//!       ├─ free_pool >= count   → deduct from pool, add reservation
//!       ├─ surplus allowed      → allocate surplus huge pages
//!       └─ neither              → Err(OutOfMemory)
//!
//!  page fault → commit(reservation_id, pfn)
//!  munmap     → unreserve(reservation_id) → return pages to pool
//! ```
//!
//! # Key Types
//!
//! - [`HugePageSize`] — supported huge page sizes
//! - [`Reservation`] — a single reservation record
//! - [`HugetlbReserve`] — the reservation tracker
//! - [`ReserveStats`] — reservation statistics
//!
//! Reference: Linux `mm/hugetlb.c`, `include/linux/hugetlb.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum active reservations.
const MAX_RESERVATIONS: usize = 512;

/// Default huge page pool size (2 MiB pages).
const DEFAULT_POOL_2M: u64 = 256;

/// Default huge page pool size (1 GiB pages).
const DEFAULT_POOL_1G: u64 = 4;

/// Maximum surplus pages allowed (2 MiB).
const MAX_SURPLUS_2M: u64 = 64;

/// Maximum surplus pages allowed (1 GiB).
const MAX_SURPLUS_1G: u64 = 2;

// -------------------------------------------------------------------
// HugePageSize
// -------------------------------------------------------------------

/// Supported huge page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2 MiB huge page.
    Size2M,
    /// 1 GiB huge page.
    Size1G,
}

impl HugePageSize {
    /// Return the page size in bytes.
    pub const fn bytes(&self) -> u64 {
        match self {
            Self::Size2M => 2 * 1024 * 1024,
            Self::Size1G => 1024 * 1024 * 1024,
        }
    }

    /// Return the number of 4 KiB pages per huge page.
    pub const fn base_pages(&self) -> u64 {
        self.bytes() / 4096
    }

    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Size2M => "2M",
            Self::Size1G => "1G",
        }
    }
}

// -------------------------------------------------------------------
// ReservationState
// -------------------------------------------------------------------

/// State of a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationState {
    /// Reserved but not yet faulted.
    Reserved,
    /// Partially committed (some pages faulted).
    Partial,
    /// Fully committed.
    Committed,
    /// Released back to pool.
    Released,
}

// -------------------------------------------------------------------
// Reservation
// -------------------------------------------------------------------

/// A single huge page reservation record.
#[derive(Debug, Clone, Copy)]
pub struct Reservation {
    /// Reservation identifier.
    id: u64,
    /// Huge page size for this reservation.
    page_size: HugePageSize,
    /// Number of huge pages reserved.
    reserved_count: u64,
    /// Number of huge pages committed (faulted in).
    committed_count: u64,
    /// Virtual address start.
    vaddr: u64,
    /// Owning process identifier.
    owner_pid: u64,
    /// Current state.
    state: ReservationState,
}

impl Reservation {
    /// Create a new reservation.
    pub const fn new(
        id: u64,
        page_size: HugePageSize,
        count: u64,
        vaddr: u64,
        owner_pid: u64,
    ) -> Self {
        Self {
            id,
            page_size,
            reserved_count: count,
            committed_count: 0,
            vaddr,
            owner_pid,
            state: ReservationState::Reserved,
        }
    }

    /// Return the reservation identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the huge page size.
    pub const fn page_size(&self) -> HugePageSize {
        self.page_size
    }

    /// Return the reserved count.
    pub const fn reserved_count(&self) -> u64 {
        self.reserved_count
    }

    /// Return the committed count.
    pub const fn committed_count(&self) -> u64 {
        self.committed_count
    }

    /// Return the remaining uncommitted count.
    pub const fn remaining(&self) -> u64 {
        self.reserved_count - self.committed_count
    }

    /// Return the virtual address.
    pub const fn vaddr(&self) -> u64 {
        self.vaddr
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return the current state.
    pub const fn state(&self) -> ReservationState {
        self.state
    }

    /// Commit one page from this reservation.
    pub fn commit_one(&mut self) -> Result<()> {
        if self.committed_count >= self.reserved_count {
            return Err(Error::InvalidArgument);
        }
        self.committed_count += 1;
        self.state = if self.committed_count >= self.reserved_count {
            ReservationState::Committed
        } else {
            ReservationState::Partial
        };
        Ok(())
    }

    /// Release this reservation.
    pub fn release(&mut self) {
        self.state = ReservationState::Released;
    }

    /// Check whether the reservation is active.
    pub const fn is_active(&self) -> bool {
        matches!(
            self.state,
            ReservationState::Reserved | ReservationState::Partial
        )
    }
}

impl Default for Reservation {
    fn default() -> Self {
        Self {
            id: 0,
            page_size: HugePageSize::Size2M,
            reserved_count: 0,
            committed_count: 0,
            vaddr: 0,
            owner_pid: 0,
            state: ReservationState::Released,
        }
    }
}

// -------------------------------------------------------------------
// ReserveStats
// -------------------------------------------------------------------

/// Reservation statistics.
#[derive(Debug, Clone, Copy)]
pub struct ReserveStats {
    /// Free pool count for 2 MiB pages.
    pub free_2m: u64,
    /// Free pool count for 1 GiB pages.
    pub free_1g: u64,
    /// Reserved (not yet committed) 2 MiB pages.
    pub reserved_2m: u64,
    /// Reserved (not yet committed) 1 GiB pages.
    pub reserved_1g: u64,
    /// Surplus 2 MiB pages.
    pub surplus_2m: u64,
    /// Surplus 1 GiB pages.
    pub surplus_1g: u64,
}

impl ReserveStats {
    /// Create initial stats with default pool sizes.
    pub const fn new() -> Self {
        Self {
            free_2m: DEFAULT_POOL_2M,
            free_1g: DEFAULT_POOL_1G,
            reserved_2m: 0,
            reserved_1g: 0,
            surplus_2m: 0,
            surplus_1g: 0,
        }
    }

    /// Return the available 2 MiB pages (free minus reserved).
    pub const fn available_2m(&self) -> u64 {
        self.free_2m.saturating_sub(self.reserved_2m)
    }

    /// Return the available 1 GiB pages (free minus reserved).
    pub const fn available_1g(&self) -> u64 {
        self.free_1g.saturating_sub(self.reserved_1g)
    }
}

impl Default for ReserveStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// HugetlbReserve
// -------------------------------------------------------------------

/// The hugetlb reservation tracker.
pub struct HugetlbReserve {
    /// Active reservations.
    reservations: [Reservation; MAX_RESERVATIONS],
    /// Number of valid entries.
    count: usize,
    /// Next reservation identifier.
    next_id: u64,
    /// Statistics.
    stats: ReserveStats,
}

impl HugetlbReserve {
    /// Create a new reservation tracker.
    pub const fn new() -> Self {
        Self {
            reservations: [const {
                Reservation {
                    id: 0,
                    page_size: HugePageSize::Size2M,
                    reserved_count: 0,
                    committed_count: 0,
                    vaddr: 0,
                    owner_pid: 0,
                    state: ReservationState::Released,
                }
            }; MAX_RESERVATIONS],
            count: 0,
            next_id: 1,
            stats: ReserveStats::new(),
        }
    }

    /// Return the number of active reservations.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &ReserveStats {
        &self.stats
    }

    /// Reserve huge pages.
    pub fn reserve(
        &mut self,
        page_size: HugePageSize,
        count: u64,
        vaddr: u64,
        owner_pid: u64,
    ) -> Result<u64> {
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_RESERVATIONS {
            return Err(Error::OutOfMemory);
        }

        // Check availability.
        let (avail, max_surplus, surplus) = match page_size {
            HugePageSize::Size2M => (
                self.stats.available_2m(),
                MAX_SURPLUS_2M,
                self.stats.surplus_2m,
            ),
            HugePageSize::Size1G => (
                self.stats.available_1g(),
                MAX_SURPLUS_1G,
                self.stats.surplus_1g,
            ),
        };

        if avail < count {
            let deficit = count - avail;
            if surplus + deficit > max_surplus {
                return Err(Error::OutOfMemory);
            }
            // Allocate surplus.
            match page_size {
                HugePageSize::Size2M => self.stats.surplus_2m += deficit,
                HugePageSize::Size1G => self.stats.surplus_1g += deficit,
            }
        }

        // Add reservation.
        let id = self.next_id;
        self.next_id += 1;
        let reservation = Reservation::new(id, page_size, count, vaddr, owner_pid);

        // Find a free slot.
        for idx in 0..MAX_RESERVATIONS {
            if !self.reservations[idx].is_active()
                && matches!(self.reservations[idx].state(), ReservationState::Released)
            {
                self.reservations[idx] = reservation;
                self.count += 1;
                match page_size {
                    HugePageSize::Size2M => self.stats.reserved_2m += count,
                    HugePageSize::Size1G => self.stats.reserved_1g += count,
                }
                return Ok(id);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Commit one page from a reservation.
    pub fn commit(&mut self, reservation_id: u64) -> Result<()> {
        for idx in 0..MAX_RESERVATIONS {
            if self.reservations[idx].id() == reservation_id && self.reservations[idx].is_active() {
                return self.reservations[idx].commit_one();
            }
        }
        Err(Error::NotFound)
    }

    /// Release a reservation, returning pages to the pool.
    pub fn unreserve(&mut self, reservation_id: u64) -> Result<u64> {
        for idx in 0..MAX_RESERVATIONS {
            if self.reservations[idx].id() == reservation_id && self.reservations[idx].is_active() {
                let remaining = self.reservations[idx].remaining();
                let page_size = self.reservations[idx].page_size();
                self.reservations[idx].release();
                self.count = self.count.saturating_sub(1);
                match page_size {
                    HugePageSize::Size2M => {
                        self.stats.reserved_2m = self.stats.reserved_2m.saturating_sub(remaining);
                    }
                    HugePageSize::Size1G => {
                        self.stats.reserved_1g = self.stats.reserved_1g.saturating_sub(remaining);
                    }
                }
                return Ok(remaining);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a reservation by ID.
    pub fn find(&self, reservation_id: u64) -> Option<&Reservation> {
        for idx in 0..MAX_RESERVATIONS {
            if self.reservations[idx].id() == reservation_id && self.reservations[idx].is_active() {
                return Some(&self.reservations[idx]);
            }
        }
        None
    }
}

impl Default for HugetlbReserve {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether enough huge pages are available for a reservation.
pub fn can_reserve(tracker: &HugetlbReserve, size: HugePageSize, count: u64) -> bool {
    let (avail, max_surplus, surplus) = match size {
        HugePageSize::Size2M => (
            tracker.stats().available_2m(),
            MAX_SURPLUS_2M,
            tracker.stats().surplus_2m,
        ),
        HugePageSize::Size1G => (
            tracker.stats().available_1g(),
            MAX_SURPLUS_1G,
            tracker.stats().surplus_1g,
        ),
    };
    if avail >= count {
        return true;
    }
    let deficit = count - avail;
    surplus + deficit <= max_surplus
}

/// Return the total reserved bytes for a given page size.
pub const fn reserved_bytes(tracker: &HugetlbReserve, size: HugePageSize) -> u64 {
    match size {
        HugePageSize::Size2M => tracker.stats().reserved_2m * size.bytes(),
        HugePageSize::Size1G => tracker.stats().reserved_1g * size.bytes(),
    }
}

/// Return a summary label for reservation state.
pub fn reserve_summary(tracker: &HugetlbReserve) -> &'static str {
    if tracker.count() == 0 {
        "no active reservations"
    } else {
        "reservations active"
    }
}
