// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Balloon inflate and deflate operations.
//!
//! The VM balloon driver adjusts guest memory size dynamically.
//! Inflating the balloon takes pages from the guest and returns them
//! to the host; deflating returns pages to the guest. This module
//! manages the inflate/deflate page lists and coordinates with the
//! hypervisor via virtio-balloon commands.
//!
//! # Design
//!
//! ```text
//!  balloon_inflate(n_pages)
//!     │
//!     ├─ alloc n_pages from guest
//!     ├─ add PFNs to inflate list
//!     └─ send PFN list to hypervisor → host reclaims backing
//!
//!  balloon_deflate(n_pages)
//!     │
//!     ├─ send deflate request to hypervisor
//!     ├─ get PFNs back
//!     └─ free pages to guest allocator
//! ```
//!
//! # Key Types
//!
//! - [`BalloonPage`] — a single page held by the balloon
//! - [`BalloonInflater`] — manages inflate/deflate operations
//! - [`BalloonInflateStats`] — inflate/deflate statistics
//!
//! Reference: Linux `drivers/virtio/virtio_balloon.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages in the balloon.
const MAX_BALLOON_PAGES: usize = 65536;

/// Maximum pages per inflate/deflate batch.
const BATCH_SIZE: usize = 256;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// BalloonPage
// -------------------------------------------------------------------

/// A single page held by the balloon.
#[derive(Debug, Clone, Copy)]
pub struct BalloonPage {
    /// Physical frame number.
    pfn: u64,
    /// Timestamp when added to balloon.
    timestamp: u64,
    /// Whether this entry is active.
    active: bool,
}

impl BalloonPage {
    /// Create a new balloon page.
    pub const fn new(pfn: u64, timestamp: u64) -> Self {
        Self {
            pfn,
            timestamp,
            active: true,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Check whether active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Deactivate (deflated).
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for BalloonPage {
    fn default() -> Self {
        Self {
            pfn: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// BalloonInflateStats
// -------------------------------------------------------------------

/// Inflate/deflate statistics.
#[derive(Debug, Clone, Copy)]
pub struct BalloonInflateStats {
    /// Total inflate operations.
    pub total_inflates: u64,
    /// Total deflate operations.
    pub total_deflates: u64,
    /// Total pages inflated.
    pub pages_inflated: u64,
    /// Total pages deflated.
    pub pages_deflated: u64,
    /// Current balloon size in pages.
    pub current_pages: u64,
    /// Inflate failures.
    pub inflate_failures: u64,
    /// Deflate failures.
    pub deflate_failures: u64,
}

impl BalloonInflateStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_inflates: 0,
            total_deflates: 0,
            pages_inflated: 0,
            pages_deflated: 0,
            current_pages: 0,
            inflate_failures: 0,
            deflate_failures: 0,
        }
    }

    /// Current balloon size in bytes.
    pub const fn current_bytes(&self) -> u64 {
        self.current_pages * PAGE_SIZE
    }

    /// Net pages (inflated - deflated).
    pub const fn net_pages(&self) -> u64 {
        self.pages_inflated - self.pages_deflated
    }
}

impl Default for BalloonInflateStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// BalloonInflater
// -------------------------------------------------------------------

/// Manages balloon inflate/deflate operations.
pub struct BalloonInflater {
    /// Pages currently in the balloon.
    pages: [BalloonPage; MAX_BALLOON_PAGES],
    /// Number of active pages.
    count: usize,
    /// Target size in pages (set by hypervisor).
    target: u64,
    /// Statistics.
    stats: BalloonInflateStats,
}

impl BalloonInflater {
    /// Create a new inflater.
    pub const fn new() -> Self {
        Self {
            pages: [const {
                BalloonPage {
                    pfn: 0,
                    timestamp: 0,
                    active: false,
                }
            }; MAX_BALLOON_PAGES],
            count: 0,
            target: 0,
            stats: BalloonInflateStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &BalloonInflateStats {
        &self.stats
    }

    /// Return the current count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the target.
    pub const fn target(&self) -> u64 {
        self.target
    }

    /// Set the target balloon size.
    pub fn set_target(&mut self, target: u64) {
        self.target = target;
    }

    /// Inflate: add pages to the balloon.
    pub fn inflate(&mut self, pfns: &[u64], timestamp: u64) -> Result<usize> {
        if pfns.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let mut added = 0;
        for pfn in pfns {
            if self.count >= MAX_BALLOON_PAGES {
                self.stats.inflate_failures += 1;
                break;
            }
            self.pages[self.count] = BalloonPage::new(*pfn, timestamp);
            self.count += 1;
            added += 1;
        }
        if added > 0 {
            self.stats.total_inflates += 1;
            self.stats.pages_inflated += added as u64;
            self.stats.current_pages += added as u64;
        }
        Ok(added)
    }

    /// Deflate: remove pages from the balloon.
    pub fn deflate(&mut self, count: usize) -> Result<usize> {
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut removed = 0;
        for _i in 0..count {
            if self.count == 0 {
                break;
            }
            // Remove from the end.
            self.count -= 1;
            self.pages[self.count].deactivate();
            removed += 1;
        }
        if removed > 0 {
            self.stats.total_deflates += 1;
            self.stats.pages_deflated += removed as u64;
            self.stats.current_pages = self.stats.current_pages.saturating_sub(removed as u64);
        } else {
            self.stats.deflate_failures += 1;
        }
        Ok(removed)
    }

    /// Check whether we need to inflate or deflate.
    pub fn adjustment_needed(&self) -> i64 {
        let current = self.count as i64;
        let target = self.target as i64;
        target - current
    }

    /// Balloon memory in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.count as u64 * PAGE_SIZE
    }

    /// Get a balloon page by index.
    pub fn get_page(&self, index: usize) -> Option<&BalloonPage> {
        if index < self.count {
            Some(&self.pages[index])
        } else {
            None
        }
    }
}

impl Default for BalloonInflater {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum balloon pages.
pub const fn max_balloon_pages() -> usize {
    MAX_BALLOON_PAGES
}

/// Return the batch size.
pub const fn batch_size() -> usize {
    BATCH_SIZE
}
