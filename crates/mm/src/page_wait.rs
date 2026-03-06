// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page wait queue management.
//!
//! When a page is under I/O (e.g. read from disk, writeback), threads
//! that need the page must wait for the I/O to complete. This module
//! implements per-page wait queues using a hashed wait table so that
//! threads can sleep on specific page events (locked, writeback, etc.)
//! and be woken when the event completes.
//!
//! # Design
//!
//! ```text
//!  thread needs locked page
//!       → PageWaitTable::wait(pfn, PAGE_LOCKED)
//!       → thread sleeps on hashed bucket
//!
//!  I/O completes
//!       → unlock_page(pfn)
//!       → PageWaitTable::wake(pfn, PAGE_LOCKED)
//!       → wake all threads waiting on that page+event
//! ```
//!
//! # Key Types
//!
//! - [`PageWaitEvent`] — the event type being waited on
//! - [`PageWaiter`] — a single waiter entry
//! - [`PageWaitBucket`] — a hash bucket of waiters
//! - [`PageWaitTable`] — the hashed wait table
//!
//! Reference: Linux `mm/filemap.c` (wait_on_page_bit),
//! `include/linux/pagemap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of hash buckets (power of 2).
const NR_BUCKETS: usize = 64;

/// Maximum waiters per bucket.
const MAX_WAITERS_PER_BUCKET: usize = 32;

/// Total maximum concurrent waiters.
const MAX_TOTAL_WAITERS: usize = NR_BUCKETS * MAX_WAITERS_PER_BUCKET;

// -------------------------------------------------------------------
// PageWaitEvent
// -------------------------------------------------------------------

/// Events that can be waited on for a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageWaitEvent {
    /// Page is locked (PG_locked).
    Locked,
    /// Page is under writeback (PG_writeback).
    Writeback,
    /// Page is being reclaimed.
    Reclaim,
    /// Page is being migrated.
    Migrate,
    /// Page data is not yet up to date.
    UpToDate,
}

impl PageWaitEvent {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Writeback => "writeback",
            Self::Reclaim => "reclaim",
            Self::Migrate => "migrate",
            Self::UpToDate => "uptodate",
        }
    }

    /// Return the bit index for hashing.
    pub const fn bit(&self) -> u64 {
        match self {
            Self::Locked => 0,
            Self::Writeback => 1,
            Self::Reclaim => 2,
            Self::Migrate => 3,
            Self::UpToDate => 4,
        }
    }
}

// -------------------------------------------------------------------
// PageWaiter
// -------------------------------------------------------------------

/// A single thread waiting on a page event.
#[derive(Debug, Clone, Copy)]
pub struct PageWaiter {
    /// Thread identifier.
    thread_id: u64,
    /// The page PFN being waited on.
    pfn: u64,
    /// The event being waited on.
    event: PageWaitEvent,
    /// Whether this waiter is active.
    active: bool,
    /// Whether the waiter has been woken.
    woken: bool,
}

impl PageWaiter {
    /// Create a new waiter.
    pub const fn new(thread_id: u64, pfn: u64, event: PageWaitEvent) -> Self {
        Self {
            thread_id,
            pfn,
            event,
            active: true,
            woken: false,
        }
    }

    /// Return the thread identifier.
    pub const fn thread_id(&self) -> u64 {
        self.thread_id
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the event.
    pub const fn event(&self) -> PageWaitEvent {
        self.event
    }

    /// Check whether the waiter is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Check whether the waiter has been woken.
    pub const fn is_woken(&self) -> bool {
        self.woken
    }

    /// Wake this waiter.
    pub fn wake(&mut self) {
        self.woken = true;
        self.active = false;
    }

    /// Cancel this waiter.
    pub fn cancel(&mut self) {
        self.active = false;
    }
}

impl Default for PageWaiter {
    fn default() -> Self {
        Self {
            thread_id: 0,
            pfn: 0,
            event: PageWaitEvent::Locked,
            active: false,
            woken: false,
        }
    }
}

// -------------------------------------------------------------------
// PageWaitBucket
// -------------------------------------------------------------------

/// A hash bucket containing waiters.
pub struct PageWaitBucket {
    /// Waiters in this bucket.
    waiters: [PageWaiter; MAX_WAITERS_PER_BUCKET],
    /// Number of active waiters.
    count: usize,
}

impl PageWaitBucket {
    /// Create an empty bucket.
    pub const fn new() -> Self {
        Self {
            waiters: [const {
                PageWaiter {
                    thread_id: 0,
                    pfn: 0,
                    event: PageWaitEvent::Locked,
                    active: false,
                    woken: false,
                }
            }; MAX_WAITERS_PER_BUCKET],
            count: 0,
        }
    }

    /// Return the number of active waiters.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add a waiter to this bucket.
    pub fn add(&mut self, waiter: PageWaiter) -> Result<()> {
        if self.count >= MAX_WAITERS_PER_BUCKET {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        for idx in 0..MAX_WAITERS_PER_BUCKET {
            if !self.waiters[idx].is_active() {
                self.waiters[idx] = waiter;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Wake all waiters matching pfn + event.
    pub fn wake(&mut self, pfn: u64, event: PageWaitEvent) -> usize {
        let mut woken = 0;
        for idx in 0..MAX_WAITERS_PER_BUCKET {
            if self.waiters[idx].is_active()
                && self.waiters[idx].pfn() == pfn
                && self.waiters[idx].event() == event
            {
                self.waiters[idx].wake();
                self.count = self.count.saturating_sub(1);
                woken += 1;
            }
        }
        woken
    }

    /// Remove a specific waiter by thread_id.
    pub fn remove(&mut self, thread_id: u64) -> bool {
        for idx in 0..MAX_WAITERS_PER_BUCKET {
            if self.waiters[idx].is_active() && self.waiters[idx].thread_id() == thread_id {
                self.waiters[idx].cancel();
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }
}

impl Default for PageWaitBucket {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageWaitTable
// -------------------------------------------------------------------

/// The hashed page wait table.
pub struct PageWaitTable {
    /// Hash buckets.
    buckets: [PageWaitBucket; NR_BUCKETS],
    /// Total active waiters.
    total_waiters: usize,
    /// Total wake operations performed.
    total_wakes: u64,
}

impl PageWaitTable {
    /// Create a new wait table.
    pub const fn new() -> Self {
        Self {
            buckets: [const {
                PageWaitBucket {
                    waiters: [const {
                        PageWaiter {
                            thread_id: 0,
                            pfn: 0,
                            event: PageWaitEvent::Locked,
                            active: false,
                            woken: false,
                        }
                    }; MAX_WAITERS_PER_BUCKET],
                    count: 0,
                }
            }; NR_BUCKETS],
            total_waiters: 0,
            total_wakes: 0,
        }
    }

    /// Compute the bucket index for a page+event.
    const fn bucket_index(pfn: u64, event: PageWaitEvent) -> usize {
        ((pfn ^ event.bit()) as usize) % NR_BUCKETS
    }

    /// Add a waiter.
    pub fn wait(&mut self, thread_id: u64, pfn: u64, event: PageWaitEvent) -> Result<()> {
        if self.total_waiters >= MAX_TOTAL_WAITERS {
            return Err(Error::OutOfMemory);
        }
        let idx = Self::bucket_index(pfn, event);
        let waiter = PageWaiter::new(thread_id, pfn, event);
        self.buckets[idx].add(waiter)?;
        self.total_waiters += 1;
        Ok(())
    }

    /// Wake all waiters for a page+event.
    pub fn wake(&mut self, pfn: u64, event: PageWaitEvent) -> usize {
        let idx = Self::bucket_index(pfn, event);
        let woken = self.buckets[idx].wake(pfn, event);
        self.total_waiters = self.total_waiters.saturating_sub(woken);
        self.total_wakes += woken as u64;
        woken
    }

    /// Cancel a specific waiter.
    pub fn cancel(&mut self, thread_id: u64, pfn: u64, event: PageWaitEvent) -> bool {
        let idx = Self::bucket_index(pfn, event);
        let removed = self.buckets[idx].remove(thread_id);
        if removed {
            self.total_waiters = self.total_waiters.saturating_sub(1);
        }
        removed
    }

    /// Return the total number of active waiters.
    pub const fn total_waiters(&self) -> usize {
        self.total_waiters
    }

    /// Return the total wake operations.
    pub const fn total_wakes(&self) -> u64 {
        self.total_wakes
    }
}

impl Default for PageWaitTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Wait for a page to be unlocked.
pub fn wait_on_page_locked(table: &mut PageWaitTable, thread_id: u64, pfn: u64) -> Result<()> {
    table.wait(thread_id, pfn, PageWaitEvent::Locked)
}

/// Wake threads waiting for a page unlock.
pub fn wake_up_page_locked(table: &mut PageWaitTable, pfn: u64) -> usize {
    table.wake(pfn, PageWaitEvent::Locked)
}

/// Wait for writeback to complete on a page.
pub fn wait_on_page_writeback(table: &mut PageWaitTable, thread_id: u64, pfn: u64) -> Result<()> {
    table.wait(thread_id, pfn, PageWaitEvent::Writeback)
}
