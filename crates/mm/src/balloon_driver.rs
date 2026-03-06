// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory ballooning driver for virtual machines.
//!
//! Implements the guest-side memory balloon that allows the hypervisor to
//! reclaim physical pages from the guest OS without a full reboot. The
//! balloon driver maintains a set of inflated pages that are reported to
//! the host as "in use" by the guest but are actually withheld from the
//! guest page allocator.
//!
//! # Protocol
//!
//! 1. Hypervisor sends an "inflate" request via MMIO or virtqueue with a
//!    target balloon size.
//! 2. The driver allocates physical pages from the guest page allocator
//!    and adds them to the balloon set.
//! 3. The driver reports inflated page frame numbers (PFNs) to the
//!    hypervisor so it can reclaim them in the host physical address space.
//! 4. When the hypervisor sends a "deflate" request, the driver releases
//!    balloon pages back to the guest page allocator.
//!
//! # Key types
//!
//! - [`BalloonPage`] — a single page held in the balloon
//! - [`BalloonTarget`] — an inflate/deflate command from the hypervisor
//! - [`BalloonDriver`] — the top-level driver state
//! - [`BalloonStats`] — balloon statistics as reported to the hypervisor

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages the balloon can hold.
pub const BALLOON_MAX_PAGES: usize = 65536; // 256 MiB at 4 KiB/page

/// Page size in bytes.
pub const BALLOON_PAGE_SIZE: u64 = 4096;

/// Default batch size for inflate/deflate operations.
pub const BALLOON_BATCH_SIZE: usize = 256;

/// Feature flag: statistics reporting supported.
pub const BALLOON_F_STATS: u32 = 1 << 0;
/// Feature flag: deflate-on-OOM supported.
pub const BALLOON_F_DEFLATE_ON_OOM: u32 = 1 << 1;
/// Feature flag: free page reporting supported.
pub const BALLOON_F_FREE_PAGE_HINT: u32 = 1 << 2;

// -------------------------------------------------------------------
// BalloonState
// -------------------------------------------------------------------

/// Current operational state of the balloon driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalloonState {
    /// Driver is initialized but the balloon is empty.
    #[default]
    Idle,
    /// The balloon is actively inflating (absorbing pages).
    Inflating,
    /// The balloon is actively deflating (releasing pages).
    Deflating,
    /// The balloon has reached its target size.
    Stable,
    /// The balloon has been suspended by the hypervisor.
    Suspended,
}

// -------------------------------------------------------------------
// BalloonPage
// -------------------------------------------------------------------

/// A single physical page held in the balloon.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonPage {
    /// Guest physical frame number (PFN).
    pub pfn: u64,
    /// Physical address (pfn * PAGE_SIZE).
    pub phys_addr: u64,
    /// Whether this page has been reported to the hypervisor.
    pub reported: bool,
}

impl BalloonPage {
    /// Construct a [`BalloonPage`] from a PFN.
    pub const fn from_pfn(pfn: u64) -> Self {
        Self {
            pfn,
            phys_addr: pfn * BALLOON_PAGE_SIZE,
            reported: false,
        }
    }
}

// -------------------------------------------------------------------
// BalloonTarget
// -------------------------------------------------------------------

/// A request from the hypervisor to adjust the balloon size.
#[derive(Debug, Clone, Copy)]
pub struct BalloonTarget {
    /// Desired balloon size in pages.
    pub target_pages: u64,
    /// Whether the adjustment must be completed immediately.
    pub urgent: bool,
}

impl BalloonTarget {
    /// Create a new balloon target.
    pub const fn new(target_pages: u64, urgent: bool) -> Self {
        Self {
            target_pages,
            urgent,
        }
    }
}

// -------------------------------------------------------------------
// BalloonStats
// -------------------------------------------------------------------

/// Guest memory statistics reported back to the hypervisor.
///
/// Corresponds to the `virtio_balloon_stat` structure in the virtio spec.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonStats {
    /// Total guest memory in pages.
    pub total_pages: u64,
    /// Available (free) guest memory in pages.
    pub available_pages: u64,
    /// Number of pages currently in the balloon.
    pub balloon_pages: u64,
    /// Number of page faults since last report.
    pub page_faults: u64,
    /// Number of major page faults (disk I/O required).
    pub major_faults: u64,
    /// Total inflate operations performed.
    pub inflate_ops: u64,
    /// Total deflate operations performed.
    pub deflate_ops: u64,
    /// Pages freed by the OOM handler during balloon pressure.
    pub oom_pages_freed: u64,
}

// -------------------------------------------------------------------
// BalloonDriver
// -------------------------------------------------------------------

/// Guest-side memory balloon driver.
#[derive(Debug)]
pub struct BalloonDriver {
    /// Pages currently held in the balloon.
    pages: [Option<BalloonPage>; BALLOON_MAX_PAGES],
    /// Number of pages currently in the balloon.
    inflated: usize,
    /// Current target balloon size in pages (set by hypervisor).
    target_pages: u64,
    /// Current driver state.
    state: BalloonState,
    /// Negotiated feature flags.
    features: u32,
    /// Aggregate statistics.
    stats: BalloonStats,
    /// Total guest physical memory in pages (set at init time).
    total_phys_pages: u64,
}

impl BalloonDriver {
    /// Create a new balloon driver with `total_phys_pages` guest pages.
    pub const fn new(total_phys_pages: u64) -> Self {
        Self {
            pages: [const { None }; BALLOON_MAX_PAGES],
            inflated: 0,
            target_pages: 0,
            state: BalloonState::Idle,
            features: 0,
            stats: BalloonStats {
                total_pages: total_phys_pages,
                available_pages: total_phys_pages,
                balloon_pages: 0,
                page_faults: 0,
                major_faults: 0,
                inflate_ops: 0,
                deflate_ops: 0,
                oom_pages_freed: 0,
            },
            total_phys_pages,
        }
    }

    /// Negotiate features with the hypervisor.
    pub fn negotiate_features(&mut self, host_features: u32) {
        self.features =
            host_features & (BALLOON_F_STATS | BALLOON_F_DEFLATE_ON_OOM | BALLOON_F_FREE_PAGE_HINT);
    }

    /// Handle a balloon target adjustment from the hypervisor.
    ///
    /// Sets the desired target size; actual inflation/deflation is
    /// performed by subsequent calls to [`inflate_batch`] or
    /// [`deflate_batch`].
    pub fn set_target(&mut self, target: BalloonTarget) {
        self.target_pages = target.target_pages;
        let current = self.inflated as u64;
        if target.target_pages > current {
            self.state = BalloonState::Inflating;
        } else if target.target_pages < current {
            self.state = BalloonState::Deflating;
        } else {
            self.state = BalloonState::Stable;
        }
    }

    /// Inflate the balloon by adding `pfns` to it.
    ///
    /// Returns the number of pages successfully added.
    pub fn inflate_batch(&mut self, pfns: &[u64]) -> Result<usize> {
        if self.state == BalloonState::Suspended {
            return Err(Error::PermissionDenied);
        }
        let mut added = 0;
        for &pfn in pfns {
            if self.inflated >= BALLOON_MAX_PAGES {
                return Err(Error::OutOfMemory);
            }
            // Find an empty slot.
            let slot = self.pages.iter_mut().find(|s| s.is_none());
            if let Some(s) = slot {
                *s = Some(BalloonPage::from_pfn(pfn));
                self.inflated += 1;
                added += 1;
                self.stats.balloon_pages += 1;
                self.stats.available_pages = self.stats.available_pages.saturating_sub(1);
            }
        }
        self.stats.inflate_ops += 1;
        if self.inflated as u64 >= self.target_pages {
            self.state = BalloonState::Stable;
        }
        Ok(added)
    }

    /// Deflate the balloon by releasing up to `count` pages.
    ///
    /// Returns a list of PFNs that were released.
    pub fn deflate_batch(&mut self, count: usize) -> Result<u64> {
        if self.state == BalloonState::Suspended {
            return Err(Error::PermissionDenied);
        }
        let mut released = 0u64;
        let mut remaining = count;
        for slot in self.pages.iter_mut() {
            if remaining == 0 {
                break;
            }
            if slot.is_some() {
                *slot = None;
                self.inflated = self.inflated.saturating_sub(1);
                self.stats.balloon_pages = self.stats.balloon_pages.saturating_sub(1);
                self.stats.available_pages += 1;
                released += 1;
                remaining -= 1;
            }
        }
        self.stats.deflate_ops += 1;
        if (self.inflated as u64) <= self.target_pages {
            self.state = BalloonState::Stable;
        }
        Ok(released)
    }

    /// Mark all inflated pages as reported to the hypervisor.
    pub fn mark_all_reported(&mut self) {
        for slot in self.pages.iter_mut().flatten() {
            slot.reported = true;
        }
    }

    /// Respond to an OOM event by deflating up to `pages` balloon pages.
    ///
    /// Only effective if `BALLOON_F_DEFLATE_ON_OOM` was negotiated.
    pub fn oom_deflate(&mut self, pages: usize) -> Result<u64> {
        if self.features & BALLOON_F_DEFLATE_ON_OOM == 0 {
            return Err(Error::NotImplemented);
        }
        let released = self.deflate_batch(pages)?;
        self.stats.oom_pages_freed += released;
        Ok(released)
    }

    /// Suspend the balloon (hypervisor is saving VM state).
    pub fn suspend(&mut self) {
        self.state = BalloonState::Suspended;
    }

    /// Resume the balloon after a suspend/restore cycle.
    pub fn resume(&mut self) {
        self.state = BalloonState::Idle;
    }

    /// Return the current driver state.
    pub fn state(&self) -> BalloonState {
        self.state
    }

    /// Return the number of pages currently in the balloon.
    pub fn inflated_pages(&self) -> usize {
        self.inflated
    }

    /// Return the current target balloon size in pages.
    pub fn target_pages(&self) -> u64 {
        self.target_pages
    }

    /// Return a snapshot of balloon statistics.
    pub fn stats(&self) -> &BalloonStats {
        &self.stats
    }

    /// Return the negotiated feature flags.
    pub fn features(&self) -> u32 {
        self.features
    }

    /// Record a page fault (called by the page-fault handler).
    pub fn record_page_fault(&mut self, major: bool) {
        self.stats.page_faults += 1;
        if major {
            self.stats.major_faults += 1;
        }
    }

    /// Collect a statistics snapshot for transmission to the hypervisor.
    pub fn collect_stats(&self) -> BalloonStats {
        self.stats
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_driver() -> BalloonDriver {
        BalloonDriver::new(1024)
    }

    #[test]
    fn test_inflate_deflate() {
        let mut driver = make_driver();
        driver.set_target(BalloonTarget::new(4, false));
        assert_eq!(driver.state(), BalloonState::Inflating);

        let pfns = [1u64, 2, 3, 4];
        let added = driver.inflate_batch(&pfns).unwrap();
        assert_eq!(added, 4);
        assert_eq!(driver.inflated_pages(), 4);
        assert_eq!(driver.state(), BalloonState::Stable);

        driver.set_target(BalloonTarget::new(2, false));
        let released = driver.deflate_batch(2).unwrap();
        assert_eq!(released, 2);
        assert_eq!(driver.inflated_pages(), 2);
    }

    #[test]
    fn test_oom_deflate_without_feature_fails() {
        let mut driver = make_driver();
        let pfns = [1u64, 2];
        driver.inflate_batch(&pfns).unwrap();
        assert!(driver.oom_deflate(1).is_err());
    }

    #[test]
    fn test_oom_deflate_with_feature() {
        let mut driver = make_driver();
        driver.negotiate_features(BALLOON_F_DEFLATE_ON_OOM);
        let pfns = [1u64, 2];
        driver.inflate_batch(&pfns).unwrap();
        let released = driver.oom_deflate(1).unwrap();
        assert_eq!(released, 1);
        assert_eq!(driver.stats().oom_pages_freed, 1);
    }

    #[test]
    fn test_suspend_blocks_ops() {
        let mut driver = make_driver();
        driver.suspend();
        assert!(driver.inflate_batch(&[1]).is_err());
        driver.resume();
        let added = driver.inflate_batch(&[1]).unwrap();
        assert_eq!(added, 1);
    }
}
