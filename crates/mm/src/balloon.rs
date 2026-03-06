// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory balloon driver for VM memory management.
//!
//! Implements a virtio-style memory balloon that allows a hypervisor
//! to dynamically reclaim and return memory from/to a guest VM.
//! The balloon inflates by taking pages away from the guest and
//! deflates by returning them.
//!
//! Key components:
//! - [`BalloonPageState`] — lifecycle state of a balloon page
//! - [`BalloonPage`] — a tracked page with PFN, order, and state
//! - [`BalloonStats`] — guest memory statistics with lifetime
//!   counters for total inflated/deflated pages
//! - [`RateLimiter`] — controls pages-per-cycle and cooldown
//! - [`FreePageHint`] — hints about free guest pages for the host
//! - [`BalloonManager`] — the core balloon driver
//! - [`BalloonEventQueue`] — ring buffer for balloon events
//!
//! Reference: Linux `drivers/virtio/virtio_balloon.c`,
//! VIRTIO spec 5.5 (Legacy Interface: Balloon Device).

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of pages the balloon can track.
const MAX_BALLOON_PAGES: usize = 4096;

/// Maximum events in the event queue ring buffer.
const MAX_EVENTS: usize = 64;

/// Default maximum pages per inflate/deflate cycle.
const DEFAULT_MAX_PAGES_PER_CYCLE: usize = 256;

/// Default cooldown period in nanoseconds (100 ms).
const DEFAULT_COOLDOWN_NS: u64 = 100_000_000;

/// Maximum number of free page hints.
const MAX_FREE_PAGE_HINTS: usize = 128;

/// Feature flag: statistics virtqueue is available.
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1 << 0;

/// Feature flag: deflate balloon on OOM.
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 1 << 1;

/// Feature flag: free page hinting is supported.
const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u32 = 1 << 2;

/// Feature flag: page reporting is supported.
const VIRTIO_BALLOON_F_PAGE_REPORTING: u32 = 1 << 3;

// ── BalloonPageState ──────────────────────────────────────────────

/// Lifecycle state of a page tracked by the balloon driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalloonPageState {
    /// Page is free (not tracked by balloon, available to guest).
    #[default]
    Free,
    /// Page has been inflated (reclaimed from guest, held by
    /// balloon for the host).
    Inflated,
    /// Page has been deflated (returned to guest from balloon).
    Deflated,
}

// ── BalloonPage ───────────────────────────────────────────────────

/// A single page tracked by the balloon driver.
///
/// Each page is identified by its page frame number (PFN) and
/// carries an allocation order (0 = single page, 1 = 2 pages,
/// etc.) plus its current lifecycle state.
#[derive(Debug, Clone, Copy)]
pub struct BalloonPage {
    /// Page frame number.
    pub pfn: u64,
    /// Allocation order (0 for a single 4 KiB page, 1 for 8 KiB,
    /// etc.). The number of base pages is `1 << order`.
    pub order: u8,
    /// Current page state.
    pub state: BalloonPageState,
    /// Whether this slot is in use.
    pub active: bool,
}

impl BalloonPage {
    /// Creates an empty, inactive page descriptor.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            order: 0,
            state: BalloonPageState::Free,
            active: false,
        }
    }

    /// Returns the number of base (4 KiB) pages represented.
    pub fn base_pages(&self) -> u64 {
        1u64 << self.order
    }

    /// Returns the size in bytes of this balloon page.
    pub fn size_bytes(&self) -> u64 {
        self.base_pages() * PAGE_SIZE
    }
}

impl Default for BalloonPage {
    fn default() -> Self {
        Self::empty()
    }
}

// ── BalloonStats ──────────────────────────────────────────────────

/// Guest memory statistics reported to the host via the stats
/// virtqueue, plus lifetime inflation/deflation counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonStats {
    /// Current number of pages held by the balloon.
    pub current_pages: u64,
    /// Target number of pages requested by the host.
    pub target_pages: u64,
    /// Total pages inflated since boot (lifetime counter).
    pub total_inflated: u64,
    /// Total pages deflated since boot (lifetime counter).
    pub total_deflated: u64,
    /// Number of free pages in the guest.
    pub free_pages: u64,
    /// Total number of pages in the guest.
    pub total_guest_pages: u64,
    /// Number of available pages (free + reclaimable).
    pub available_pages: u64,
    /// Number of cached pages.
    pub cached_pages: u64,
    /// Cumulative swap-in count.
    pub swap_in: u64,
    /// Cumulative swap-out count.
    pub swap_out: u64,
    /// Major page fault count.
    pub major_faults: u64,
    /// Minor page fault count.
    pub minor_faults: u64,
}

// ── RateLimiter ───────────────────────────────────────────────────

/// Rate limiter for balloon inflate/deflate operations.
///
/// Controls the maximum number of pages processed in a single
/// cycle and enforces a cooldown period between cycles to prevent
/// thrashing.
#[derive(Debug, Clone, Copy)]
pub struct RateLimiter {
    /// Maximum pages per inflate/deflate cycle.
    pub max_pages_per_cycle: usize,
    /// Minimum nanoseconds between cycles.
    pub cooldown_ns: u64,
    /// Timestamp of the last completed cycle.
    pub last_cycle_ns: u64,
    /// Pages processed in the current cycle.
    pub pages_this_cycle: usize,
    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

impl RateLimiter {
    /// Creates a new rate limiter with default settings.
    pub const fn new() -> Self {
        Self {
            max_pages_per_cycle: DEFAULT_MAX_PAGES_PER_CYCLE,
            cooldown_ns: DEFAULT_COOLDOWN_NS,
            last_cycle_ns: 0,
            pages_this_cycle: 0,
            enabled: true,
        }
    }

    /// Checks whether a new cycle can start at the given
    /// timestamp.
    pub fn can_start_cycle(&self, now_ns: u64) -> bool {
        if !self.enabled {
            return true;
        }
        now_ns.saturating_sub(self.last_cycle_ns) >= self.cooldown_ns
    }

    /// Returns the number of pages allowed in the current cycle.
    pub fn remaining_budget(&self) -> usize {
        if !self.enabled {
            return usize::MAX;
        }
        self.max_pages_per_cycle
            .saturating_sub(self.pages_this_cycle)
    }

    /// Records that `count` pages were processed and marks
    /// the cycle timestamp.
    pub fn record_cycle(&mut self, count: usize, now_ns: u64) {
        self.pages_this_cycle += count;
        self.last_cycle_ns = now_ns;
    }

    /// Resets the per-cycle counter for a new cycle.
    pub fn reset_cycle(&mut self) {
        self.pages_this_cycle = 0;
    }

    /// Sets the maximum pages per cycle.
    pub fn set_max_pages(&mut self, max: usize) {
        self.max_pages_per_cycle = max;
    }

    /// Sets the cooldown period in nanoseconds.
    pub fn set_cooldown(&mut self, ns: u64) {
        self.cooldown_ns = ns;
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── FreePageHint ──────────────────────────────────────────────────

/// A free page hint sent to the host.
///
/// Tells the hypervisor that a range of guest physical pages is
/// free and can be reclaimed without inflating the balloon
/// (e.g., for KSM or balloon-less memory reclaim).
#[derive(Debug, Clone, Copy)]
pub struct FreePageHint {
    /// Starting PFN of the free region.
    pub pfn: u64,
    /// Number of contiguous free pages.
    pub nr_pages: u32,
    /// Whether this hint is valid.
    pub active: bool,
}

impl FreePageHint {
    /// Creates an empty, inactive hint.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            nr_pages: 0,
            active: false,
        }
    }

    /// Returns the size in bytes of this hinted region.
    pub fn size_bytes(&self) -> u64 {
        u64::from(self.nr_pages) * PAGE_SIZE
    }
}

// ── BalloonState ──────────────────────────────────────────────────

/// Current operational state of the balloon driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalloonState {
    /// Driver is idle, no inflation/deflation in progress.
    #[default]
    Idle,
    /// Balloon is being inflated (reclaiming guest pages).
    Inflating,
    /// Balloon is being deflated (returning pages to guest).
    Deflating,
    /// An error has occurred.
    Error,
}

// ── BalloonEvent ──────────────────────────────────────────────────

/// An event produced by the balloon driver.
#[derive(Debug, Clone, Copy)]
pub enum BalloonEvent {
    /// Balloon inflated by the given number of pages.
    Inflated(usize),
    /// Balloon deflated by the given number of pages.
    Deflated(usize),
    /// Target changed to the given page count.
    TargetChanged(u64),
    /// OOM deflation was triggered.
    OomDeflate,
    /// Free page hint batch submitted.
    FreePageHintSubmitted(usize),
    /// Rate limiter rejected a request (cooldown active).
    RateLimited,
}

// ── BalloonManager ────────────────────────────────────────────────

/// Core balloon driver managing page inflation/deflation.
///
/// Tracks individual pages with their state and order, enforces
/// rate limiting, and provides free page hinting to the host.
pub struct BalloonManager {
    /// Tracked balloon pages.
    pages: [BalloonPage; MAX_BALLOON_PAGES],
    /// Number of pages currently inflated (held by balloon).
    num_inflated: usize,
    /// Target number of inflated pages requested by host.
    target_pages: u64,
    /// Current driver state.
    state: BalloonState,
    /// Statistics.
    stats: BalloonStats,
    /// Negotiated feature bits.
    features: u32,
    /// Whether to deflate on OOM conditions.
    deflate_on_oom: bool,
    /// Rate limiter for inflate/deflate cycles.
    rate_limiter: RateLimiter,
    /// Free page hints.
    hints: [FreePageHint; MAX_FREE_PAGE_HINTS],
    /// Number of active hints.
    hint_count: usize,
    /// Total number of hint batches submitted.
    total_hint_batches: u64,
}

impl Default for BalloonManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BalloonManager {
    /// Creates a new balloon manager with default settings.
    pub const fn new() -> Self {
        Self {
            pages: [BalloonPage::empty(); MAX_BALLOON_PAGES],
            num_inflated: 0,
            target_pages: 0,
            state: BalloonState::Idle,
            stats: BalloonStats {
                current_pages: 0,
                target_pages: 0,
                total_inflated: 0,
                total_deflated: 0,
                free_pages: 0,
                total_guest_pages: 0,
                available_pages: 0,
                cached_pages: 0,
                swap_in: 0,
                swap_out: 0,
                major_faults: 0,
                minor_faults: 0,
            },
            features: 0,
            deflate_on_oom: false,
            rate_limiter: RateLimiter::new(),
            hints: [FreePageHint::empty(); MAX_FREE_PAGE_HINTS],
            hint_count: 0,
            total_hint_batches: 0,
        }
    }

    // ── Target management ────────────────────────────────────────

    /// Sets the target number of inflated pages.
    ///
    /// The driver will move toward this target during
    /// [`process`](Self::process) calls.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `target` exceeds
    /// the maximum balloon capacity.
    pub fn set_target(&mut self, target: u64) -> Result<()> {
        if target > MAX_BALLOON_PAGES as u64 {
            return Err(Error::InvalidArgument);
        }
        self.target_pages = target;
        self.stats.target_pages = target;
        Ok(())
    }

    // ── Inflate / Deflate ────────────────────────────────────────

    /// Inflates the balloon by up to `count` pages with the
    /// given PFNs and order.
    ///
    /// Each PFN in `pfns` represents a page of size
    /// `(1 << order) * PAGE_SIZE`. The rate limiter is consulted
    /// to cap the number of pages per cycle.
    ///
    /// Returns the number of pages actually inflated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the driver is in an error
    /// state.
    /// Returns [`Error::WouldBlock`] if rate-limited.
    pub fn inflate(&mut self, pfns: &[u64], order: u8, now_ns: u64) -> Result<usize> {
        if self.state == BalloonState::Error {
            return Err(Error::IoError);
        }
        if pfns.is_empty() {
            return Ok(0);
        }

        // Check rate limiter.
        if self.rate_limiter.enabled {
            if !self.rate_limiter.can_start_cycle(now_ns) {
                return Err(Error::WouldBlock);
            }
            self.rate_limiter.reset_cycle();
        }

        let budget = self.rate_limiter.remaining_budget();
        let to_process = pfns.len().min(budget);

        self.state = BalloonState::Inflating;
        let mut inflated = 0;

        for &pfn in pfns.iter().take(to_process) {
            // Find a free slot.
            let slot = match self.pages.iter_mut().find(|p| !p.active) {
                Some(s) => s,
                None => break,
            };

            *slot = BalloonPage {
                pfn,
                order,
                state: BalloonPageState::Inflated,
                active: true,
            };
            inflated += 1;
        }

        self.num_inflated += inflated;
        self.stats.current_pages = self.num_inflated as u64;
        self.stats.total_inflated += inflated as u64;
        self.rate_limiter.record_cycle(inflated, now_ns);
        self.state = BalloonState::Idle;

        Ok(inflated)
    }

    /// Inflates the balloon by sequentially assigning PFNs
    /// starting from `start_pfn`.
    ///
    /// Convenience wrapper for inflate when PFNs are contiguous.
    ///
    /// Returns the number of pages actually inflated.
    ///
    /// # Errors
    ///
    /// Same as [`inflate`](Self::inflate).
    pub fn inflate_range(
        &mut self,
        start_pfn: u64,
        count: usize,
        order: u8,
        now_ns: u64,
    ) -> Result<usize> {
        if self.state == BalloonState::Error {
            return Err(Error::IoError);
        }
        if count == 0 {
            return Ok(0);
        }

        if self.rate_limiter.enabled {
            if !self.rate_limiter.can_start_cycle(now_ns) {
                return Err(Error::WouldBlock);
            }
            self.rate_limiter.reset_cycle();
        }

        let budget = self.rate_limiter.remaining_budget();
        let to_process = count.min(budget);

        self.state = BalloonState::Inflating;
        let mut inflated = 0;

        for i in 0..to_process {
            let slot = match self.pages.iter_mut().find(|p| !p.active) {
                Some(s) => s,
                None => break,
            };

            *slot = BalloonPage {
                pfn: start_pfn + i as u64,
                order,
                state: BalloonPageState::Inflated,
                active: true,
            };
            inflated += 1;
        }

        self.num_inflated += inflated;
        self.stats.current_pages = self.num_inflated as u64;
        self.stats.total_inflated += inflated as u64;
        self.rate_limiter.record_cycle(inflated, now_ns);
        self.state = BalloonState::Idle;

        Ok(inflated)
    }

    /// Deflates the balloon by up to `count` pages.
    ///
    /// Returns the number of pages actually deflated (returned
    /// to the guest).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the driver is in an error
    /// state.
    /// Returns [`Error::WouldBlock`] if rate-limited.
    pub fn deflate(&mut self, count: usize, now_ns: u64) -> Result<usize> {
        if self.state == BalloonState::Error {
            return Err(Error::IoError);
        }
        if count == 0 {
            return Ok(0);
        }

        if self.rate_limiter.enabled {
            if !self.rate_limiter.can_start_cycle(now_ns) {
                return Err(Error::WouldBlock);
            }
            self.rate_limiter.reset_cycle();
        }

        let budget = self.rate_limiter.remaining_budget();
        let to_process = count.min(budget);

        self.state = BalloonState::Deflating;
        let mut deflated = 0;

        for page in &mut self.pages {
            if deflated >= to_process {
                break;
            }
            if page.active && page.state == BalloonPageState::Inflated {
                page.state = BalloonPageState::Deflated;
                page.active = false;
                deflated += 1;
            }
        }

        self.num_inflated = self.num_inflated.saturating_sub(deflated);
        self.stats.current_pages = self.num_inflated as u64;
        self.stats.total_deflated += deflated as u64;
        self.rate_limiter.record_cycle(deflated, now_ns);
        self.state = BalloonState::Idle;

        Ok(deflated)
    }

    /// Deflates a specific page by PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no inflated page with the
    /// given PFN exists.
    pub fn deflate_pfn(&mut self, pfn: u64) -> Result<()> {
        let page = self
            .pages
            .iter_mut()
            .find(|p| p.active && p.pfn == pfn && p.state == BalloonPageState::Inflated)
            .ok_or(Error::NotFound)?;

        page.state = BalloonPageState::Deflated;
        page.active = false;
        self.num_inflated = self.num_inflated.saturating_sub(1);
        self.stats.current_pages = self.num_inflated as u64;
        self.stats.total_deflated += 1;

        Ok(())
    }

    /// Processes the balloon toward its target size.
    ///
    /// If `num_inflated < target`, the driver inflates; if
    /// `num_inflated > target`, it deflates. No-op when already
    /// at target.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if rate-limited.
    pub fn process(&mut self, now_ns: u64) -> Result<()> {
        let current = self.num_inflated as u64;
        if current < self.target_pages {
            let delta = (self.target_pages - current) as usize;
            let start = current;
            self.inflate_range(start, delta, 0, now_ns)?;
        } else if current > self.target_pages {
            let delta = (current - self.target_pages) as usize;
            self.deflate(delta, now_ns)?;
        }
        Ok(())
    }

    // ── OOM handling ────────────────────────────────────────────

    /// Attempts to deflate pages in response to an OOM
    /// condition.
    ///
    /// Only acts if `deflate_on_oom` is enabled. Returns the
    /// number of pages freed, or zero if disabled.
    pub fn oom_deflate(&mut self, now_ns: u64) -> Result<usize> {
        if !self.deflate_on_oom {
            return Ok(0);
        }
        let to_release = self.num_inflated / 2;
        if to_release == 0 {
            return Ok(0);
        }
        self.deflate(to_release, now_ns)
    }

    // ── Free page hinting ────────────────────────────────────────

    /// Adds a free page hint for the host.
    ///
    /// Tells the hypervisor that the guest has freed a
    /// contiguous range of pages that can be reclaimed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if free page hinting is not
    /// supported (feature not negotiated).
    /// Returns [`Error::OutOfMemory`] if the hint table is full.
    /// Returns [`Error::InvalidArgument`] if `nr_pages` is zero.
    pub fn add_free_page_hint(&mut self, pfn: u64, nr_pages: u32) -> Result<()> {
        if self.features & VIRTIO_BALLOON_F_FREE_PAGE_HINT == 0 {
            return Err(Error::Busy);
        }
        if nr_pages == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .hints
            .iter_mut()
            .find(|h| !h.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = FreePageHint {
            pfn,
            nr_pages,
            active: true,
        };
        self.hint_count += 1;

        Ok(())
    }

    /// Submits all pending free page hints to the host.
    ///
    /// In a real implementation, this would write to the
    /// free-page-hint virtqueue. Here we just clear the hints
    /// and record the batch.
    ///
    /// Returns the number of hints submitted.
    pub fn submit_free_page_hints(&mut self) -> usize {
        let count = self.hint_count;
        if count == 0 {
            return 0;
        }

        // Clear all hints.
        for hint in &mut self.hints {
            hint.active = false;
        }
        self.hint_count = 0;
        self.total_hint_batches += 1;

        count
    }

    /// Returns the number of pending free page hints.
    pub fn pending_hints(&self) -> usize {
        self.hint_count
    }

    // ── Statistics ────────────────────────────────────────────────

    /// Updates the guest memory statistics.
    pub fn update_guest_stats(&mut self, free: u64, total: u64, available: u64, cached: u64) {
        self.stats.free_pages = free;
        self.stats.total_guest_pages = total;
        self.stats.available_pages = available;
        self.stats.cached_pages = cached;
    }

    /// Updates the fault statistics.
    pub fn update_fault_stats(&mut self, major: u64, minor: u64) {
        self.stats.major_faults = major;
        self.stats.minor_faults = minor;
    }

    /// Updates the swap statistics.
    pub fn update_swap_stats(&mut self, swap_in: u64, swap_out: u64) {
        self.stats.swap_in = swap_in;
        self.stats.swap_out = swap_out;
    }

    /// Returns a copy of the current balloon statistics.
    pub fn stats(&self) -> BalloonStats {
        self.stats
    }

    // ── Feature negotiation ─────────────────────────────────────

    /// Enables or disables a feature bit.
    pub fn set_feature(&mut self, feature: u32, enabled: bool) {
        if enabled {
            self.features |= feature;
        } else {
            self.features &= !feature;
        }
    }

    /// Checks whether a feature bit is set.
    pub fn has_feature(&self, feature: u32) -> bool {
        self.features & feature != 0
    }

    /// Enables the stats virtqueue feature.
    pub fn enable_stats_vq(&mut self) {
        self.set_feature(VIRTIO_BALLOON_F_STATS_VQ, true);
    }

    /// Enables deflate-on-OOM.
    pub fn enable_deflate_on_oom(&mut self) {
        self.deflate_on_oom = true;
        self.set_feature(VIRTIO_BALLOON_F_DEFLATE_ON_OOM, true);
    }

    /// Enables free page hinting.
    pub fn enable_free_page_hinting(&mut self) {
        self.set_feature(VIRTIO_BALLOON_F_FREE_PAGE_HINT, true);
    }

    /// Enables page reporting.
    pub fn enable_page_reporting(&mut self) {
        self.set_feature(VIRTIO_BALLOON_F_PAGE_REPORTING, true);
    }

    // ── Rate limiter access ─────────────────────────────────────

    /// Returns a reference to the rate limiter.
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    /// Returns a mutable reference to the rate limiter.
    pub fn rate_limiter_mut(&mut self) -> &mut RateLimiter {
        &mut self.rate_limiter
    }

    /// Disables rate limiting.
    pub fn disable_rate_limiting(&mut self) {
        self.rate_limiter.enabled = false;
    }

    // ── Accessors ────────────────────────────────────────────────

    /// Returns the number of currently inflated pages.
    pub fn num_inflated(&self) -> usize {
        self.num_inflated
    }

    /// Returns the current target page count.
    pub fn target(&self) -> u64 {
        self.target_pages
    }

    /// Returns the current driver state.
    pub fn state(&self) -> BalloonState {
        self.state
    }

    /// Returns `true` if deflate-on-OOM is enabled.
    pub fn deflate_on_oom_enabled(&self) -> bool {
        self.deflate_on_oom
    }

    /// Looks up a tracked page by PFN.
    pub fn find_page(&self, pfn: u64) -> Option<&BalloonPage> {
        self.pages.iter().find(|p| p.active && p.pfn == pfn)
    }

    /// Returns the number of active page slots.
    pub fn active_page_count(&self) -> usize {
        self.pages.iter().filter(|p| p.active).count()
    }

    /// Returns `true` if no pages are inflated.
    pub fn is_empty(&self) -> bool {
        self.num_inflated == 0
    }
}

// ── BalloonEventQueue ─────────────────────────────────────────────

/// Ring buffer event queue for balloon driver events.
///
/// Fixed-capacity queue of [`BalloonEvent`] entries with a
/// maximum size of [`MAX_EVENTS`].
pub struct BalloonEventQueue {
    /// Internal ring buffer storage.
    events: [Option<BalloonEvent>; MAX_EVENTS],
    /// Read index.
    head: usize,
    /// Write index.
    tail: usize,
    /// Number of events currently stored.
    count: usize,
}

impl Default for BalloonEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl BalloonEventQueue {
    /// Creates a new empty event queue.
    pub const fn new() -> Self {
        Self {
            events: [None; MAX_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Pushes an event onto the queue.
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn push(&mut self, event: BalloonEvent) -> Result<()> {
        if self.count >= MAX_EVENTS {
            return Err(Error::OutOfMemory);
        }
        self.events[self.tail] = Some(event);
        self.tail = (self.tail + 1) % MAX_EVENTS;
        self.count += 1;
        Ok(())
    }

    /// Pops the oldest event from the queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop(&mut self) -> Option<BalloonEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head].take();
        self.head = (self.head + 1) % MAX_EVENTS;
        self.count -= 1;
        event
    }

    /// Returns the number of events in the queue.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the queue contains no events.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clears all events from the queue.
    pub fn clear(&mut self) {
        for slot in &mut self.events {
            *slot = None;
        }
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}
