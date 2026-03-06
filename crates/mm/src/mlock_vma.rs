// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory locking for VMAs (`mlock` / `munlock` VMA-level engine).
//!
//! Implements the VMA-level memory locking engine that pins pages in
//! physical memory to prevent swapout. This module extends the base
//! `mlock` module with fine-grained VMA tracking, per-range lock
//! state management, and integration hooks for the page reclaim
//! subsystem.
//!
//! # Features
//!
//! - **Per-VMA lock tracking** -- each VMA independently tracks its
//!   lock state, including on-fault behavior.
//! - **Populated page accounting** -- tracks how many pages within
//!   a locked VMA are actually resident versus demand-paged.
//! - **RLIMIT_MEMLOCK enforcement** -- respects per-process locked
//!   memory limits with privileged bypass.
//! - **Reclaim integration** -- locked VMAs inform the page reclaim
//!   subsystem to skip their pages.
//! - **Lock migration** -- handles page migration for locked pages
//!   during NUMA rebalancing or compaction.
//!
//! # Architecture
//!
//! - [`MlockFlags`] -- validated flag set for mlock2
//! - [`LockedRange`] -- per-VMA lock state with page accounting
//! - [`MlockState`] -- per-process lock aggregation
//! - [`MlockStats`] -- aggregate statistics
//! - [`MlockVmaManager`] -- the mlock VMA engine
//!
//! # POSIX / Linux Reference
//!
//! - `mlock(2)`, `mlock2(2)`, `munlock(2)` -- POSIX.1-2024
//! - `MLOCK_ONFAULT` -- Linux-specific extension
//! - `RLIMIT_MEMLOCK` -- `getrlimit(2)`
//!
//! Reference: Linux `mm/mlock.c`, `include/linux/mm_types.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Maximum number of locked ranges tracked.
const MAX_LOCKED_RANGES: usize = 256;

/// Maximum number of processes tracked.
const MAX_PROCESSES: usize = 64;

/// Default RLIMIT_MEMLOCK in pages (64 KiB = 16 pages).
const DEFAULT_LIMIT_PAGES: u64 = 16;

/// Maximum pages that can be locked globally (256 MiB).
const MAX_GLOBAL_LOCKED_PAGES: u64 = 65536;

// ── mlock2 flag constants ────────────────────────────────────────

/// Classic mlock behavior -- lock immediately.
pub const MLOCK_NONE: u32 = 0;

/// `MLOCK_ONFAULT` -- lock pages only when faulted in.
pub const MLOCK_ONFAULT: u32 = 1;

/// Valid mlock2 flag mask.
const MLOCK_VALID_MASK: u32 = MLOCK_ONFAULT;

// ── Lock reason enum ────────────────────────────────────────────

/// Reason a VMA was locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// Explicit `mlock` / `mlock2` call.
    ExplicitMlock,
    /// `mlockall(MCL_CURRENT)`.
    MlockallCurrent,
    /// `mlockall(MCL_FUTURE)` -- auto-locked on mapping.
    MlockallFuture,
    /// Locked for real-time scheduling requirements.
    Realtime,
    /// Locked for security (e.g., cryptographic keys).
    Security,
}

impl Default for LockReason {
    fn default() -> Self {
        Self::ExplicitMlock
    }
}

// ── MlockFlags ──────────────────────────────────────────────────

/// Validated flag set for `mlock2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MlockFlags(u32);

impl MlockFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);

    /// Parse raw mlock2 flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !MLOCK_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Raw bitmask.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Whether `MLOCK_ONFAULT` is set.
    pub const fn on_fault(self) -> bool {
        self.0 & MLOCK_ONFAULT != 0
    }
}

// ── LockedRange ─────────────────────────────────────────────────

/// Per-VMA lock state with page accounting.
///
/// Tracks the lock status, resident page count, and fault-in
/// progress for a single virtual memory area.
#[derive(Debug, Clone, Copy)]
pub struct LockedRange {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Whether this range is locked.
    pub locked: bool,
    /// Whether on-fault locking is active.
    pub on_fault: bool,
    /// Reason for locking.
    pub reason: LockReason,
    /// Total pages in this range.
    pub total_pages: u64,
    /// Pages currently resident and locked.
    pub resident_locked: u64,
    /// Pages pending fault-in (for on-fault locking).
    pub pending_faults: u64,
    /// Pages migrated out (temporarily unlocked for migration).
    pub migrating: u64,
    /// Owning process ID.
    pub owner_pid: u64,
    /// Timestamp of when the range was locked (ms since boot).
    pub locked_at: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl LockedRange {
    /// Create an empty, inactive locked range.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            locked: false,
            on_fault: false,
            reason: LockReason::ExplicitMlock,
            total_pages: 0,
            resident_locked: 0,
            pending_faults: 0,
            migrating: 0,
            owner_pid: 0,
            locked_at: 0,
            active: false,
        }
    }

    /// Exclusive end address.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Number of pages in this range.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Whether an address falls within this range.
    pub const fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end()
    }

    /// Whether this range overlaps `[start, start+size)`.
    pub const fn overlaps(&self, start: u64, size: u64) -> bool {
        if !self.active || size == 0 {
            return false;
        }
        let end = start.saturating_add(size);
        self.start < end && self.end() > start
    }

    /// Percentage of pages that are resident and locked.
    pub fn lock_ratio(&self) -> u32 {
        if self.total_pages == 0 {
            return 0;
        }
        ((self.resident_locked * 100) / self.total_pages) as u32
    }
}

// ── MlockState ──────────────────────────────────────────────────

/// Per-process memory lock state.
///
/// Aggregates locked page counts and tracks per-process limits
/// and mlockall state.
#[derive(Debug, Clone, Copy)]
pub struct MlockState {
    /// Process ID.
    pub pid: u64,
    /// Total pages currently locked.
    pub locked_pages: u64,
    /// RLIMIT_MEMLOCK in pages.
    pub limit_pages: u64,
    /// Whether `mlockall(MCL_CURRENT)` is active.
    pub lockall_current: bool,
    /// Whether `mlockall(MCL_FUTURE)` is active.
    pub lockall_future: bool,
    /// Whether `mlockall(MCL_ONFAULT)` is active.
    pub lockall_on_fault: bool,
    /// Whether this process has CAP_IPC_LOCK.
    pub privileged: bool,
    /// Peak locked pages (high-water mark).
    pub peak_locked: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl MlockState {
    /// Create an empty, inactive process state.
    const fn empty() -> Self {
        Self {
            pid: 0,
            locked_pages: 0,
            limit_pages: DEFAULT_LIMIT_PAGES,
            lockall_current: false,
            lockall_future: false,
            lockall_on_fault: false,
            privileged: false,
            peak_locked: 0,
            active: false,
        }
    }

    /// Remaining lockable pages.
    pub fn remaining(&self) -> u64 {
        if self.privileged {
            return u64::MAX;
        }
        self.limit_pages.saturating_sub(self.locked_pages)
    }

    /// Whether this process can lock `count` more pages.
    pub fn can_lock(&self, count: u64) -> bool {
        self.privileged || self.locked_pages + count <= self.limit_pages
    }

    /// Update the peak locked pages if current exceeds it.
    fn update_peak(&mut self) {
        if self.locked_pages > self.peak_locked {
            self.peak_locked = self.locked_pages;
        }
    }
}

// ── MlockStats ──────────────────────────────────────────────────

/// Aggregate mlock VMA statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MlockStats {
    /// Total lock operations.
    pub lock_ops: u64,
    /// Total unlock operations.
    pub unlock_ops: u64,
    /// Pages locked.
    pub pages_locked: u64,
    /// Pages unlocked.
    pub pages_unlocked: u64,
    /// Fault-in pages locked.
    pub fault_locked: u64,
    /// Lock failures due to RLIMIT.
    pub limit_failures: u64,
    /// Lock failures due to global limit.
    pub global_limit_failures: u64,
    /// Migration events for locked pages.
    pub migration_events: u64,
    /// Active locked ranges.
    pub active_locked_ranges: u64,
    /// Global locked page count.
    pub global_locked_pages: u64,
}

// ── MlockVmaManager ────────────────────────────────────────────

/// The mlock VMA engine.
///
/// Manages per-VMA lock state, per-process accounting, and global
/// locked-page limits. Provides lock/unlock operations with
/// RLIMIT_MEMLOCK enforcement.
pub struct MlockVmaManager {
    /// Locked ranges.
    ranges: [LockedRange; MAX_LOCKED_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Per-process mlock state.
    processes: [MlockState; MAX_PROCESSES],
    /// Number of active processes.
    process_count: usize,
    /// Global locked page count.
    global_locked: u64,
    /// Statistics.
    stats: MlockStats,
}

impl Default for MlockVmaManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MlockVmaManager {
    /// Creates a new, empty mlock VMA manager.
    pub const fn new() -> Self {
        Self {
            ranges: [const { LockedRange::empty() }; MAX_LOCKED_RANGES],
            range_count: 0,
            processes: [const { MlockState::empty() }; MAX_PROCESSES],
            process_count: 0,
            global_locked: 0,
            stats: MlockStats {
                lock_ops: 0,
                unlock_ops: 0,
                pages_locked: 0,
                pages_unlocked: 0,
                fault_locked: 0,
                limit_failures: 0,
                global_limit_failures: 0,
                migration_events: 0,
                active_locked_ranges: 0,
                global_locked_pages: 0,
            },
        }
    }

    // ── Process management ──────────────────────────────────────

    /// Register a process for mlock tracking.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] if PID is already registered.
    /// - [`Error::OutOfMemory`] if process table is full.
    pub fn register_process(&mut self, pid: u64, limit_pages: u64, privileged: bool) -> Result<()> {
        if self.find_process(pid).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .processes
            .iter_mut()
            .find(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = MlockState::empty();
        slot.pid = pid;
        slot.limit_pages = limit_pages;
        slot.privileged = privileged;
        slot.active = true;
        self.process_count += 1;
        Ok(())
    }

    /// Unregister a process, unlocking all its ranges.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if PID is not registered.
    pub fn unregister_process(&mut self, pid: u64) -> Result<()> {
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        // Unlock all ranges for this process.
        for range in self.ranges.iter_mut() {
            if range.active && range.owner_pid == pid && range.locked {
                self.global_locked = self.global_locked.saturating_sub(range.resident_locked);
                self.stats.pages_unlocked += range.resident_locked;
                range.locked = false;
                range.resident_locked = 0;
                range.pending_faults = 0;
            }
        }

        self.processes[proc_idx].active = false;
        self.process_count = self.process_count.saturating_sub(1);
        self.update_stats();
        Ok(())
    }

    // ── Range management ────────────────────────────────────────

    /// Register a VMA range for lock tracking.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if addresses not page-aligned
    ///   or size is zero.
    /// - [`Error::OutOfMemory`] if range table is full.
    pub fn register_range(&mut self, start: u64, size: u64, owner_pid: u64) -> Result<()> {
        if start & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .ranges
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = LockedRange {
            start,
            size,
            locked: false,
            on_fault: false,
            reason: LockReason::ExplicitMlock,
            total_pages: size / PAGE_SIZE,
            resident_locked: 0,
            pending_faults: 0,
            migrating: 0,
            owner_pid,
            locked_at: 0,
            active: true,
        };
        self.range_count += 1;

        // Auto-lock if mlockall(MCL_FUTURE) is active.
        if let Some(proc_state) = self.find_process(owner_pid) {
            if proc_state.lockall_future {
                let on_fault = proc_state.lockall_on_fault;
                let _ = self.lock_range_internal(
                    start,
                    size,
                    owner_pid,
                    on_fault,
                    LockReason::MlockallFuture,
                    0,
                );
            }
        }

        Ok(())
    }

    /// Unregister a VMA range, unlocking it first if needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn unregister_range(&mut self, start: u64, owner_pid: u64) -> Result<()> {
        let idx = self
            .ranges
            .iter()
            .position(|r| r.active && r.start == start && r.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        if self.ranges[idx].locked {
            let pages = self.ranges[idx].resident_locked;
            self.global_locked = self.global_locked.saturating_sub(pages);
            if let Some(proc_state) = self.find_process_mut(owner_pid) {
                proc_state.locked_pages = proc_state.locked_pages.saturating_sub(pages);
            }
            self.stats.pages_unlocked += pages;
        }

        self.ranges[idx].active = false;
        self.range_count = self.range_count.saturating_sub(1);
        self.update_stats();
        Ok(())
    }

    // ── Lock / Unlock ───────────────────────────────────────────

    /// Lock a range of pages.
    ///
    /// # Arguments
    ///
    /// - `pid` -- process ID.
    /// - `addr` -- start address (page-aligned).
    /// - `len` -- length in bytes.
    /// - `raw_flags` -- mlock2 flags (`MLOCK_*` bitmask).
    /// - `timestamp` -- current time in ms since boot.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] -- bad alignment or flags.
    /// - [`Error::NotFound`] -- no range covers the address.
    /// - [`Error::PermissionDenied`] -- RLIMIT exceeded.
    pub fn lock_range(
        &mut self,
        pid: u64,
        addr: u64,
        len: u64,
        raw_flags: u32,
        timestamp: u64,
    ) -> Result<u64> {
        self.stats.lock_ops += 1;

        if addr & (PAGE_SIZE - 1) != 0 || len == 0 {
            return Err(Error::InvalidArgument);
        }

        let flags = MlockFlags::from_raw(raw_flags)?;
        let aligned_len = page_align_up(len);

        self.lock_range_internal(
            addr,
            aligned_len,
            pid,
            flags.on_fault(),
            LockReason::ExplicitMlock,
            timestamp,
        )
    }

    /// Internal lock implementation.
    fn lock_range_internal(
        &mut self,
        addr: u64,
        len: u64,
        pid: u64,
        on_fault: bool,
        reason: LockReason,
        timestamp: u64,
    ) -> Result<u64> {
        let pages_needed = len / PAGE_SIZE;

        // Check per-process limit.
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        if !on_fault && !self.processes[proc_idx].can_lock(pages_needed) {
            self.stats.limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        // Check global limit.
        if !on_fault && self.global_locked + pages_needed > MAX_GLOBAL_LOCKED_PAGES {
            self.stats.global_limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        let mut total_locked: u64 = 0;
        let mut found = false;

        for range in self.ranges.iter_mut() {
            if !range.active || range.owner_pid != pid {
                continue;
            }
            if !range.overlaps(addr, len) {
                continue;
            }
            found = true;

            if range.locked {
                range.on_fault = on_fault;
                continue;
            }

            range.locked = true;
            range.on_fault = on_fault;
            range.reason = reason;
            range.locked_at = timestamp;

            if on_fault {
                range.resident_locked = 0;
                range.pending_faults = range.total_pages;
            } else {
                range.resident_locked = range.total_pages;
                range.pending_faults = 0;
                total_locked += range.total_pages;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.processes[proc_idx].locked_pages += total_locked;
        self.processes[proc_idx].update_peak();
        self.global_locked += total_locked;
        self.stats.pages_locked += total_locked;
        self.update_stats();

        Ok(total_locked)
    }

    /// Unlock a range of pages.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] -- bad alignment.
    /// - [`Error::NotFound`] -- no range or process found.
    pub fn unlock_range(&mut self, pid: u64, addr: u64, len: u64) -> Result<u64> {
        self.stats.unlock_ops += 1;

        if addr & (PAGE_SIZE - 1) != 0 || len == 0 {
            return Err(Error::InvalidArgument);
        }

        let aligned_len = page_align_up(len);
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        let mut total_unlocked: u64 = 0;
        let mut found = false;

        for range in self.ranges.iter_mut() {
            if !range.active || range.owner_pid != pid {
                continue;
            }
            if !range.overlaps(addr, aligned_len) {
                continue;
            }
            found = true;

            if !range.locked {
                continue;
            }

            total_unlocked += range.resident_locked;
            range.locked = false;
            range.on_fault = false;
            range.resident_locked = 0;
            range.pending_faults = 0;
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.processes[proc_idx].locked_pages = self.processes[proc_idx]
            .locked_pages
            .saturating_sub(total_unlocked);
        self.global_locked = self.global_locked.saturating_sub(total_unlocked);
        self.stats.pages_unlocked += total_unlocked;
        self.update_stats();

        Ok(total_unlocked)
    }

    // ── Fault-in handling ───────────────────────────────────────

    /// Notify that a page has been faulted in for an on-fault range.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] -- no on-fault locked range at addr.
    /// - [`Error::PermissionDenied`] -- limit exceeded.
    pub fn fault_in_page(&mut self, pid: u64, addr: u64) -> Result<()> {
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        if !self.processes[proc_idx].can_lock(1) {
            self.stats.limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        if self.global_locked >= MAX_GLOBAL_LOCKED_PAGES {
            self.stats.global_limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        let range = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.owner_pid == pid && r.locked && r.on_fault && r.contains(addr))
            .ok_or(Error::NotFound)?;

        range.resident_locked += 1;
        range.pending_faults = range.pending_faults.saturating_sub(1);

        self.processes[proc_idx].locked_pages += 1;
        self.processes[proc_idx].update_peak();
        self.global_locked += 1;
        self.stats.fault_locked += 1;
        self.stats.pages_locked += 1;

        Ok(())
    }

    // ── Migration support ───────────────────────────────────────

    /// Mark a page as migrating (temporarily unlocked).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no locked range at address.
    pub fn begin_migration(&mut self, pid: u64, addr: u64) -> Result<()> {
        let range = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.owner_pid == pid && r.locked && r.contains(addr))
            .ok_or(Error::NotFound)?;

        if range.resident_locked == 0 {
            return Err(Error::InvalidArgument);
        }

        range.resident_locked -= 1;
        range.migrating += 1;
        self.stats.migration_events += 1;
        Ok(())
    }

    /// Complete migration, re-locking the page at its new location.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range with migrating pages.
    pub fn end_migration(&mut self, pid: u64, addr: u64) -> Result<()> {
        let range = self
            .ranges
            .iter_mut()
            .find(|r| {
                r.active && r.owner_pid == pid && r.locked && r.contains(addr) && r.migrating > 0
            })
            .ok_or(Error::NotFound)?;

        range.migrating -= 1;
        range.resident_locked += 1;
        Ok(())
    }

    // ── Query ───────────────────────────────────────────────────

    /// Check whether an address is in a locked range.
    pub fn is_locked(&self, pid: u64, addr: u64) -> bool {
        self.ranges
            .iter()
            .any(|r| r.active && r.owner_pid == pid && r.locked && r.contains(addr))
    }

    /// Get lock ratio for a specific range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range at address.
    pub fn range_lock_ratio(&self, pid: u64, addr: u64) -> Result<u32> {
        let range = self
            .ranges
            .iter()
            .find(|r| r.active && r.owner_pid == pid && r.contains(addr))
            .ok_or(Error::NotFound)?;

        Ok(range.lock_ratio())
    }

    // ── Accessors ───────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &MlockStats {
        &self.stats
    }

    /// Number of active locked ranges.
    pub fn range_count(&self) -> usize {
        self.range_count
    }

    /// Number of active processes.
    pub fn process_count(&self) -> usize {
        self.process_count
    }

    /// Global locked page count.
    pub fn global_locked_pages(&self) -> u64 {
        self.global_locked
    }

    /// Process lock state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if PID not registered.
    pub fn process_state(&self, pid: u64) -> Result<&MlockState> {
        self.processes
            .iter()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)
    }

    /// Iterate over locked ranges for a process.
    pub fn locked_ranges(&self, pid: u64) -> impl Iterator<Item = &LockedRange> {
        self.ranges
            .iter()
            .filter(move |r| r.active && r.owner_pid == pid && r.locked)
    }

    // ── Internal helpers ────────────────────────────────────────

    fn find_process(&self, pid: u64) -> Option<&MlockState> {
        self.processes.iter().find(|p| p.active && p.pid == pid)
    }

    fn find_process_mut(&mut self, pid: u64) -> Option<&mut MlockState> {
        self.processes.iter_mut().find(|p| p.active && p.pid == pid)
    }

    /// Update derived statistics.
    fn update_stats(&mut self) {
        self.stats.active_locked_ranges =
            self.ranges.iter().filter(|r| r.active && r.locked).count() as u64;
        self.stats.global_locked_pages = self.global_locked;
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Align a value up to the next page boundary.
const fn page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & PAGE_MASK
}
