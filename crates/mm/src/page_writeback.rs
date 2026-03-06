// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dirty page tracking and writeback subsystem.
//!
//! Manages the lifecycle of dirty (modified) pages from the point they
//! are dirtied until their contents are flushed to backing storage.
//! The subsystem implements:
//!
//! - **Global and per-BDI dirty page ratio tracking** — monitors how
//!   much of physical memory is dirty.
//! - **Writeback thresholds** — `dirty_ratio` and
//!   `dirty_background_ratio` govern when synchronous and asynchronous
//!   writeback begins.
//! - **Balance dirty pages** — throttles writers when dirty pages
//!   exceed the ratio thresholds.
//! - **BDI (backing device info)** — per-device writeback tracking.
//! - **Writeback work queue** — dispatches writeback work items.
//! - **Periodic writeback** — kupdate-style periodic flush of old
//!   dirty pages.
//! - **Write bandwidth estimation** — estimates per-BDI write
//!   throughput for proportional throttling.
//!
//! Modeled after Linux `mm/page-writeback.c`.
//!
//! Reference: `.kernelORG/` — `mm/page-writeback.c`,
//! `include/linux/writeback.h`, `mm/backing-dev.c`.

use oncrix_lib::{Error, Result};

/// Maximum number of backing devices tracked.
const MAX_BDI: usize = 16;

/// Maximum number of work items in the writeback queue.
const MAX_WORK_ITEMS: usize = 64;

/// Maximum number of dirty pages tracked globally.
const MAX_DIRTY_PAGES: usize = 4096;

/// Default dirty ratio (percentage of total pages).
const DEFAULT_DIRTY_RATIO: u32 = 20;

/// Default dirty background ratio (percentage of total pages).
const DEFAULT_DIRTY_BG_RATIO: u32 = 10;

/// Default writeback interval in milliseconds (5 seconds).
const DEFAULT_WRITEBACK_INTERVAL_MS: u64 = 5000;

/// Dirty page age threshold for periodic writeback (30 seconds).
const DEFAULT_DIRTY_EXPIRE_MS: u64 = 30000;

/// Bandwidth estimation window in milliseconds.
const BW_ESTIMATION_WINDOW_MS: u64 = 200;

// ── WritebackReason ───────────────────────────────────────────────

/// Reason a writeback was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackReason {
    /// Background writeback — dirty ratio exceeded background threshold.
    Background,
    /// Synchronous writeback — dirty ratio exceeded foreground threshold.
    Sync,
    /// Periodic flush — dirty pages exceeded age threshold.
    Periodic,
    /// Explicit sync request (fsync / sync).
    ExplicitSync,
    /// Memory pressure — OOM or reclaim triggered writeback.
    Reclaim,
    /// Writeback triggered by umount or filesystem shutdown.
    Shutdown,
}

// ── WritebackWorkItem ─────────────────────────────────────────────

/// A unit of writeback work dispatched to the writeback queue.
#[derive(Debug, Clone, Copy)]
pub struct WritebackWorkItem {
    /// BDI index this work targets (or `u32::MAX` for all BDIs).
    bdi_index: u32,
    /// Number of pages to write back.
    nr_pages: u64,
    /// Reason for this writeback.
    reason: WritebackReason,
    /// Whether this work item is active.
    active: bool,
    /// Timestamp when this work was enqueued (ms since boot).
    enqueued_at: u64,
}

impl WritebackWorkItem {
    const fn empty() -> Self {
        Self {
            bdi_index: 0,
            nr_pages: 0,
            reason: WritebackReason::Background,
            active: false,
            enqueued_at: 0,
        }
    }
}

// ── BdiWritebackInfo ──────────────────────────────────────────────

/// Per-backing-device writeback information.
///
/// Tracks dirty page counts, write bandwidth estimation, and
/// writeback state for a single backing device.
#[derive(Debug, Clone, Copy)]
pub struct BdiWritebackInfo {
    /// BDI identifier.
    pub id: u32,
    /// Human-readable name (truncated to 31 bytes).
    name: [u8; 32],
    /// Whether this BDI slot is active.
    active: bool,
    /// Number of dirty pages attributed to this BDI.
    dirty_pages: u64,
    /// Number of pages currently under writeback.
    writeback_pages: u64,
    /// Total pages written back since BDI creation.
    written_total: u64,
    /// Estimated write bandwidth in pages per second.
    bandwidth_pps: u64,
    /// Timestamp of last bandwidth measurement start (ms).
    bw_start_time: u64,
    /// Pages written since last bandwidth measurement start.
    bw_written: u64,
    /// Proportional dirty limit for this BDI.
    dirty_limit: u64,
    /// Timestamp of last writeback completion (ms).
    last_writeback: u64,
}

impl BdiWritebackInfo {
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; 32],
            active: false,
            dirty_pages: 0,
            writeback_pages: 0,
            written_total: 0,
            bandwidth_pps: 0,
            bw_start_time: 0,
            bw_written: 0,
            dirty_limit: 0,
            last_writeback: 0,
        }
    }
}

// ── DirtyPageEntry ────────────────────────────────────────────────

/// Tracks a single dirty page.
#[derive(Debug, Clone, Copy)]
struct DirtyPageEntry {
    /// Physical frame number of the dirty page.
    frame_number: u64,
    /// BDI index this page belongs to.
    bdi_index: u32,
    /// Timestamp when the page was first dirtied (ms).
    dirtied_at: u64,
    /// Whether this entry is active.
    active: bool,
}

impl DirtyPageEntry {
    const fn empty() -> Self {
        Self {
            frame_number: 0,
            bdi_index: 0,
            dirtied_at: 0,
            active: false,
        }
    }
}

// ── ThrottleState ─────────────────────────────────────────────────

/// Result of a throttle check for a writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleState {
    /// Writer may proceed without delay.
    NoThrottle,
    /// Writer should sleep for the given number of milliseconds.
    Throttle(u64),
    /// Writer should block until writeback completes.
    Block,
}

// ── WritebackStats ────────────────────────────────────────────────

/// Global writeback statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Total dirty pages across all BDIs.
    pub total_dirty: u64,
    /// Total pages currently under writeback.
    pub total_writeback: u64,
    /// Total pages written back since boot.
    pub total_written: u64,
    /// Current dirty ratio (percentage * 100 for precision).
    pub dirty_ratio_pct: u32,
    /// Number of times writers were throttled.
    pub throttle_count: u64,
    /// Number of background writeback triggers.
    pub bg_writeback_count: u64,
    /// Number of sync writeback triggers.
    pub sync_writeback_count: u64,
    /// Number of periodic writeback triggers.
    pub periodic_writeback_count: u64,
    /// Pending work items in the queue.
    pub pending_work_items: usize,
    /// Active BDI count.
    pub active_bdi_count: usize,
}

// ── PageWriteback ─────────────────────────────────────────────────

/// Dirty page tracking and writeback controller.
///
/// Central manager for the writeback subsystem. Tracks global dirty
/// ratios, per-BDI accounting, writeback work queue, and bandwidth
/// estimation.
pub struct PageWriteback {
    /// Total number of physical pages in the system.
    total_pages: u64,
    /// Dirty ratio threshold (percentage, 1-100).
    dirty_ratio: u32,
    /// Dirty background ratio threshold (percentage, 1-100).
    dirty_bg_ratio: u32,
    /// Per-BDI writeback info.
    bdis: [BdiWritebackInfo; MAX_BDI],
    /// Number of active BDIs.
    bdi_count: usize,
    /// Next BDI id to assign.
    next_bdi_id: u32,
    /// Global dirty page tracker.
    dirty_pages: [DirtyPageEntry; MAX_DIRTY_PAGES],
    /// Number of active dirty page entries.
    dirty_count: usize,
    /// Writeback work queue.
    work_queue: [WritebackWorkItem; MAX_WORK_ITEMS],
    /// Number of pending work items.
    work_count: usize,
    /// Writeback interval for periodic flush (ms).
    writeback_interval_ms: u64,
    /// Dirty page expiry for periodic writeback (ms).
    dirty_expire_ms: u64,
    /// Timestamp of last periodic writeback (ms).
    last_periodic_wb: u64,
    /// Number of throttle events.
    throttle_count: u64,
    /// Number of background writeback triggers.
    bg_wb_count: u64,
    /// Number of sync writeback triggers.
    sync_wb_count: u64,
    /// Number of periodic writeback triggers.
    periodic_wb_count: u64,
    /// Total pages written back since boot.
    total_written: u64,
}

impl Default for PageWriteback {
    fn default() -> Self {
        Self::new(0)
    }
}

impl PageWriteback {
    /// Create a new writeback controller for a system with
    /// `total_pages` physical pages.
    pub const fn new(total_pages: u64) -> Self {
        Self {
            total_pages,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            dirty_bg_ratio: DEFAULT_DIRTY_BG_RATIO,
            bdis: [const { BdiWritebackInfo::empty() }; MAX_BDI],
            bdi_count: 0,
            next_bdi_id: 1,
            dirty_pages: [const { DirtyPageEntry::empty() }; MAX_DIRTY_PAGES],
            dirty_count: 0,
            work_queue: [const { WritebackWorkItem::empty() }; MAX_WORK_ITEMS],
            work_count: 0,
            writeback_interval_ms: DEFAULT_WRITEBACK_INTERVAL_MS,
            dirty_expire_ms: DEFAULT_DIRTY_EXPIRE_MS,
            last_periodic_wb: 0,
            throttle_count: 0,
            bg_wb_count: 0,
            sync_wb_count: 0,
            periodic_wb_count: 0,
            total_written: 0,
        }
    }

    // ── Threshold configuration ────────────────────────────────

    /// Set the dirty ratio (percentage, 1-95).
    ///
    /// When dirty pages exceed this ratio of total memory, writers
    /// are synchronously throttled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ratio` is out of range
    /// or less than `dirty_bg_ratio`.
    pub fn set_dirty_ratio(&mut self, ratio: u32) -> Result<()> {
        if ratio == 0 || ratio > 95 {
            return Err(Error::InvalidArgument);
        }
        if ratio < self.dirty_bg_ratio {
            return Err(Error::InvalidArgument);
        }
        self.dirty_ratio = ratio;
        Ok(())
    }

    /// Set the dirty background ratio (percentage, 1-95).
    ///
    /// When dirty pages exceed this ratio, background writeback is
    /// triggered.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ratio` is out of range
    /// or exceeds `dirty_ratio`.
    pub fn set_dirty_bg_ratio(&mut self, ratio: u32) -> Result<()> {
        if ratio == 0 || ratio > 95 {
            return Err(Error::InvalidArgument);
        }
        if ratio > self.dirty_ratio {
            return Err(Error::InvalidArgument);
        }
        self.dirty_bg_ratio = ratio;
        Ok(())
    }

    /// Current dirty ratio threshold.
    pub fn dirty_ratio(&self) -> u32 {
        self.dirty_ratio
    }

    /// Current dirty background ratio threshold.
    pub fn dirty_bg_ratio(&self) -> u32 {
        self.dirty_bg_ratio
    }

    /// Set the periodic writeback interval.
    pub fn set_writeback_interval(&mut self, ms: u64) {
        self.writeback_interval_ms = ms;
    }

    /// Set the dirty page expiry threshold.
    pub fn set_dirty_expire(&mut self, ms: u64) {
        self.dirty_expire_ms = ms;
    }

    /// Update the total page count (e.g. after memory hotplug).
    pub fn set_total_pages(&mut self, total: u64) {
        self.total_pages = total;
    }

    // ── BDI management ─────────────────────────────────────────

    /// Register a backing device.
    ///
    /// Returns the assigned BDI identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the BDI table is full.
    pub fn register_bdi(&mut self, name: &[u8]) -> Result<u32> {
        if self.bdi_count >= MAX_BDI {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .bdis
            .iter_mut()
            .find(|b| !b.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_bdi_id;
        *slot = BdiWritebackInfo::empty();
        slot.id = id;
        slot.active = true;
        let copy_len = name.len().min(31);
        slot.name[..copy_len].copy_from_slice(&name[..copy_len]);

        self.next_bdi_id = self.next_bdi_id.wrapping_add(1);
        self.bdi_count += 1;

        // Recompute per-BDI dirty limits.
        self.recompute_bdi_limits();

        Ok(id)
    }

    /// Unregister a backing device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no BDI with the given `id`
    /// exists.
    /// Returns [`Error::Busy`] if the BDI still has dirty pages.
    pub fn unregister_bdi(&mut self, id: u32) -> Result<()> {
        let slot = self
            .bdis
            .iter_mut()
            .find(|b| b.active && b.id == id)
            .ok_or(Error::NotFound)?;

        if slot.dirty_pages > 0 || slot.writeback_pages > 0 {
            return Err(Error::Busy);
        }

        *slot = BdiWritebackInfo::empty();
        self.bdi_count = self.bdi_count.saturating_sub(1);
        self.recompute_bdi_limits();
        Ok(())
    }

    /// Get information about a BDI by id.
    pub fn bdi_info(&self, id: u32) -> Option<&BdiWritebackInfo> {
        self.bdis.iter().find(|b| b.active && b.id == id)
    }

    /// Recompute per-BDI dirty limits proportionally.
    fn recompute_bdi_limits(&mut self) {
        if self.bdi_count == 0 || self.total_pages == 0 {
            return;
        }
        let global_limit = (self.total_pages * self.dirty_ratio as u64) / 100;
        let per_bdi = global_limit / self.bdi_count as u64;

        for bdi in self.bdis.iter_mut() {
            if bdi.active {
                bdi.dirty_limit = per_bdi;
            }
        }
    }

    // ── Dirty page tracking ────────────────────────────────────

    /// Mark a page as dirty.
    ///
    /// `now_ms` is the current timestamp in milliseconds since boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the BDI is not registered.
    /// Returns [`Error::OutOfMemory`] if the dirty page table is full.
    /// Returns [`Error::AlreadyExists`] if the page is already dirty.
    pub fn set_page_dirty(&mut self, frame_number: u64, bdi_id: u32, now_ms: u64) -> Result<()> {
        // Find the BDI index.
        let bdi_idx = self.bdi_index(bdi_id).ok_or(Error::NotFound)?;

        // Check for duplicate.
        for entry in self.dirty_pages.iter() {
            if entry.active && entry.frame_number == frame_number {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        let slot = self
            .dirty_pages
            .iter_mut()
            .find(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        slot.frame_number = frame_number;
        slot.bdi_index = bdi_idx as u32;
        slot.dirtied_at = now_ms;
        slot.active = true;

        self.dirty_count += 1;
        self.bdis[bdi_idx].dirty_pages += 1;

        Ok(())
    }

    /// Clear the dirty flag on a page (after successful writeback).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the page is not dirty.
    pub fn clear_page_dirty(&mut self, frame_number: u64) -> Result<()> {
        let entry = self
            .dirty_pages
            .iter_mut()
            .find(|e| e.active && e.frame_number == frame_number)
            .ok_or(Error::NotFound)?;

        let bdi_idx = entry.bdi_index as usize;
        entry.active = false;
        entry.frame_number = 0;
        entry.dirtied_at = 0;

        self.dirty_count = self.dirty_count.saturating_sub(1);
        if bdi_idx < MAX_BDI && self.bdis[bdi_idx].active {
            self.bdis[bdi_idx].dirty_pages = self.bdis[bdi_idx].dirty_pages.saturating_sub(1);
        }

        Ok(())
    }

    /// Mark a page as under writeback.
    ///
    /// The page transitions from dirty to writeback state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the page is not dirty.
    pub fn set_page_writeback(&mut self, frame_number: u64) -> Result<()> {
        let entry = self
            .dirty_pages
            .iter()
            .find(|e| e.active && e.frame_number == frame_number)
            .ok_or(Error::NotFound)?;

        let bdi_idx = entry.bdi_index as usize;
        if bdi_idx < MAX_BDI && self.bdis[bdi_idx].active {
            self.bdis[bdi_idx].writeback_pages += 1;
        }
        Ok(())
    }

    /// Complete writeback of a page.
    ///
    /// Removes the page from the dirty tracker and updates BDI
    /// statistics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the page is not dirty.
    pub fn end_page_writeback(&mut self, frame_number: u64, now_ms: u64) -> Result<()> {
        let entry = self
            .dirty_pages
            .iter_mut()
            .find(|e| e.active && e.frame_number == frame_number)
            .ok_or(Error::NotFound)?;

        let bdi_idx = entry.bdi_index as usize;
        entry.active = false;
        entry.frame_number = 0;
        entry.dirtied_at = 0;

        self.dirty_count = self.dirty_count.saturating_sub(1);

        if bdi_idx < MAX_BDI && self.bdis[bdi_idx].active {
            let bdi = &mut self.bdis[bdi_idx];
            bdi.dirty_pages = bdi.dirty_pages.saturating_sub(1);
            bdi.writeback_pages = bdi.writeback_pages.saturating_sub(1);
            bdi.written_total += 1;
            bdi.bw_written += 1;
            bdi.last_writeback = now_ms;
        }

        self.total_written += 1;
        Ok(())
    }

    // ── Balance dirty pages (throttling) ───────────────────────

    /// Check whether a writer should be throttled.
    ///
    /// Returns the throttle decision based on current dirty ratios.
    /// Also enqueues background or sync writeback work if thresholds
    /// are exceeded.
    pub fn balance_dirty_pages(&mut self, bdi_id: u32, now_ms: u64) -> ThrottleState {
        let dirty_pct = self.dirty_percentage();

        if dirty_pct >= self.dirty_ratio {
            // Above foreground threshold — synchronous throttle.
            self.sync_wb_count += 1;
            let _ = self.enqueue_work(
                bdi_id,
                self.dirty_count as u64 / 4,
                WritebackReason::Sync,
                now_ms,
            );
            self.throttle_count += 1;
            return ThrottleState::Block;
        }

        if dirty_pct >= self.dirty_bg_ratio {
            // Above background threshold — mild throttle.
            self.bg_wb_count += 1;
            let _ = self.enqueue_work(
                bdi_id,
                self.dirty_count as u64 / 8,
                WritebackReason::Background,
                now_ms,
            );

            // Proportional throttle: the closer to dirty_ratio, the
            // longer the sleep.
            let range = self.dirty_ratio.saturating_sub(self.dirty_bg_ratio);
            let over = dirty_pct.saturating_sub(self.dirty_bg_ratio);
            let sleep_ms = if range > 0 {
                ((over as u64) * 100) / range as u64
            } else {
                10
            };
            self.throttle_count += 1;
            return ThrottleState::Throttle(sleep_ms.max(1));
        }

        ThrottleState::NoThrottle
    }

    /// Current dirty page percentage (0-100).
    pub fn dirty_percentage(&self) -> u32 {
        if self.total_pages == 0 {
            return 0;
        }
        ((self.dirty_count as u64 * 100) / self.total_pages) as u32
    }

    /// Absolute dirty page threshold (foreground).
    pub fn dirty_threshold(&self) -> u64 {
        (self.total_pages * self.dirty_ratio as u64) / 100
    }

    /// Absolute dirty page threshold (background).
    pub fn dirty_bg_threshold(&self) -> u64 {
        (self.total_pages * self.dirty_bg_ratio as u64) / 100
    }

    // ── Writeback work queue ───────────────────────────────────

    /// Enqueue a writeback work item.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the work queue is full.
    pub fn enqueue_work(
        &mut self,
        bdi_id: u32,
        nr_pages: u64,
        reason: WritebackReason,
        now_ms: u64,
    ) -> Result<()> {
        if self.work_count >= MAX_WORK_ITEMS {
            return Err(Error::OutOfMemory);
        }

        let bdi_index = self.bdi_index(bdi_id).map(|i| i as u32).unwrap_or(u32::MAX);

        let slot = self
            .work_queue
            .iter_mut()
            .find(|w| !w.active)
            .ok_or(Error::OutOfMemory)?;

        slot.bdi_index = bdi_index;
        slot.nr_pages = nr_pages.max(1);
        slot.reason = reason;
        slot.active = true;
        slot.enqueued_at = now_ms;

        self.work_count += 1;
        Ok(())
    }

    /// Dequeue the next writeback work item (FIFO by enqueue time).
    pub fn dequeue_work(&mut self) -> Option<WritebackWorkItem> {
        let mut oldest_idx = None;
        let mut oldest_time = u64::MAX;

        for (i, item) in self.work_queue.iter().enumerate() {
            if item.active && item.enqueued_at < oldest_time {
                oldest_time = item.enqueued_at;
                oldest_idx = Some(i);
            }
        }

        if let Some(idx) = oldest_idx {
            let item = self.work_queue[idx];
            self.work_queue[idx] = WritebackWorkItem::empty();
            self.work_count = self.work_count.saturating_sub(1);
            return Some(item);
        }
        None
    }

    /// Number of pending work items.
    pub fn pending_work_count(&self) -> usize {
        self.work_count
    }

    // ── Periodic writeback ─────────────────────────────────────

    /// Run periodic writeback (kupdate-style).
    ///
    /// Enqueues writeback for dirty pages that have exceeded the
    /// `dirty_expire_ms` age. Should be called periodically by the
    /// writeback timer.
    ///
    /// Returns the number of pages queued for writeback.
    pub fn periodic_writeback(&mut self, now_ms: u64) -> u64 {
        if now_ms.saturating_sub(self.last_periodic_wb) < self.writeback_interval_ms {
            return 0;
        }
        self.last_periodic_wb = now_ms;

        let mut expired_count: u64 = 0;
        for entry in self.dirty_pages.iter() {
            if entry.active && now_ms.saturating_sub(entry.dirtied_at) >= self.dirty_expire_ms {
                expired_count += 1;
            }
        }

        if expired_count > 0 {
            self.periodic_wb_count += 1;
            // Enqueue one work item for all expired pages.
            let _ = self.enqueue_work(
                0, // BDI 0 = all devices
                expired_count,
                WritebackReason::Periodic,
                now_ms,
            );
        }

        expired_count
    }

    /// Collect frame numbers of expired dirty pages.
    ///
    /// Writes up to `buf.len()` expired frame numbers into `buf` and
    /// returns the number written.
    pub fn collect_expired_pages(&self, now_ms: u64, buf: &mut [u64]) -> usize {
        let mut count = 0;
        for entry in self.dirty_pages.iter() {
            if count >= buf.len() {
                break;
            }
            if entry.active && now_ms.saturating_sub(entry.dirtied_at) >= self.dirty_expire_ms {
                buf[count] = entry.frame_number;
                count += 1;
            }
        }
        count
    }

    // ── Bandwidth estimation ───────────────────────────────────

    /// Update bandwidth estimation for a BDI.
    ///
    /// Should be called periodically. Computes pages-per-second
    /// throughput over the estimation window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the BDI is not registered.
    pub fn update_bandwidth(&mut self, bdi_id: u32, now_ms: u64) -> Result<()> {
        let idx = self.bdi_index(bdi_id).ok_or(Error::NotFound)?;
        let bdi = &mut self.bdis[idx];

        let elapsed = now_ms.saturating_sub(bdi.bw_start_time);
        if elapsed < BW_ESTIMATION_WINDOW_MS {
            return Ok(());
        }

        if elapsed > 0 {
            // pages / ms * 1000 = pages / sec
            bdi.bandwidth_pps = (bdi.bw_written * 1000) / elapsed;
        }

        // Reset measurement window.
        bdi.bw_start_time = now_ms;
        bdi.bw_written = 0;

        Ok(())
    }

    /// Get estimated write bandwidth for a BDI (pages per second).
    pub fn bdi_bandwidth(&self, bdi_id: u32) -> Option<u64> {
        self.bdis
            .iter()
            .find(|b| b.active && b.id == bdi_id)
            .map(|b| b.bandwidth_pps)
    }

    // ── Statistics ─────────────────────────────────────────────

    /// Total number of dirty pages.
    pub fn dirty_count(&self) -> usize {
        self.dirty_count
    }

    /// Total pages under writeback.
    pub fn writeback_count(&self) -> u64 {
        let mut total: u64 = 0;
        for bdi in self.bdis.iter() {
            if bdi.active {
                total = total.saturating_add(bdi.writeback_pages);
            }
        }
        total
    }

    /// Aggregate writeback statistics.
    pub fn stats(&self) -> WritebackStats {
        WritebackStats {
            total_dirty: self.dirty_count as u64,
            total_writeback: self.writeback_count(),
            total_written: self.total_written,
            dirty_ratio_pct: self.dirty_percentage(),
            throttle_count: self.throttle_count,
            bg_writeback_count: self.bg_wb_count,
            sync_writeback_count: self.sync_wb_count,
            periodic_writeback_count: self.periodic_wb_count,
            pending_work_items: self.work_count,
            active_bdi_count: self.bdi_count,
        }
    }

    /// Get dirty page count attributed to a specific BDI.
    pub fn bdi_dirty_pages(&self, bdi_id: u32) -> Option<u64> {
        self.bdis
            .iter()
            .find(|b| b.active && b.id == bdi_id)
            .map(|b| b.dirty_pages)
    }

    // ── Internal helpers ───────────────────────────────────────

    /// Find the index of a BDI by its id.
    fn bdi_index(&self, bdi_id: u32) -> Option<usize> {
        self.bdis.iter().position(|b| b.active && b.id == bdi_id)
    }
}
