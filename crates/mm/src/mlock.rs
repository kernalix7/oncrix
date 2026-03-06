// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory locking (`mlock` / `mlockall` / `munlock` / `munlockall`).
//!
//! Implements the POSIX memory-locking system calls that prevent
//! pages from being swapped out to disk. Locked pages remain in
//! physical memory, guaranteeing deterministic access latency —
//! critical for real-time, cryptographic, and latency-sensitive
//! workloads.
//!
//! # Supported operations
//!
//! - **`mlock`** — lock a specific address range in memory.
//! - **`mlock2`** — lock with additional flags
//!   (`MLOCK_ONFAULT` — lock pages only when they are faulted in).
//! - **`munlock`** — unlock a specific address range.
//! - **`mlockall`** — lock all current (and optionally future)
//!   mappings for a process.
//! - **`munlockall`** — unlock all mappings for a process.
//!
//! # Resource limits
//!
//! Per-process locked memory is bounded by `RLIMIT_MEMLOCK`.
//! Privileged processes (CAP_IPC_LOCK) may exceed the limit.
//!
//! # Key types
//!
//! - [`MlockFlags`] — parsed flag set for `mlock2`
//! - [`MclFlags`] — parsed flag set for `mlockall`
//! - [`VmaLockState`] — per-VMA lock metadata
//! - [`ProcessMlockState`] — per-process locked-page accounting
//! - [`MlockManager`] — the mlock state machine
//! - [`MlockStats`] — aggregate statistics
//!
//! # POSIX / Linux reference
//!
//! - `mlock(2)`, `mlock2(2)`, `munlock(2)` — POSIX.1-2024 +
//!   Linux extensions
//! - `mlockall(2)`, `munlockall(2)` — POSIX.1-2024
//! - `RLIMIT_MEMLOCK` — `getrlimit(2)`
//!
//! Reference: Linux `mm/mlock.c`, `include/uapi/linux/mman.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// `MLOCK_ONFAULT` — lock pages only when faulted in (mlock2).
pub const MLOCK_ONFAULT: u32 = 1;

/// `MCL_CURRENT` — lock all currently mapped pages.
pub const MCL_CURRENT: u32 = 1;

/// `MCL_FUTURE` — lock all pages mapped in the future.
pub const MCL_FUTURE: u32 = 2;

/// `MCL_ONFAULT` — lock pages only when faulted in (mlockall).
pub const MCL_ONFAULT: u32 = 4;

/// Valid mask for `mlock2` flags.
const MLOCK_VALID_MASK: u32 = MLOCK_ONFAULT;

/// Valid mask for `mlockall` flags.
const MCL_VALID_MASK: u32 = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;

/// Maximum number of VMAs tracked per process.
const MAX_VMAS: usize = 128;

/// Maximum number of processes tracked.
const MAX_PROCESSES: usize = 64;

/// Default RLIMIT_MEMLOCK in pages (64 KiB = 16 pages).
const DEFAULT_MEMLOCK_LIMIT_PAGES: u64 = 16;

// ── MlockFlags ───────────────────────────────────────────────────

/// Parsed and validated flag set for `mlock2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MlockFlags(u32);

impl MlockFlags {
    /// No special flags (classic mlock behavior).
    pub const NONE: Self = Self(0);

    /// Parse raw flags from user space.
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

    /// Raw bitmask value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Whether `MLOCK_ONFAULT` is set.
    pub const fn on_fault(self) -> bool {
        self.0 & MLOCK_ONFAULT != 0
    }
}

// ── MclFlags ─────────────────────────────────────────────────────

/// Parsed and validated flag set for `mlockall`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MclFlags(u32);

impl MclFlags {
    /// Parse raw flags from user space.
    ///
    /// At least one of `MCL_CURRENT` or `MCL_FUTURE` must be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if unknown bits are set
    /// or if neither `MCL_CURRENT` nor `MCL_FUTURE` is present.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !MCL_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & (MCL_CURRENT | MCL_FUTURE) == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Raw bitmask value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Whether `MCL_CURRENT` is set.
    pub const fn current(self) -> bool {
        self.0 & MCL_CURRENT != 0
    }

    /// Whether `MCL_FUTURE` is set.
    pub const fn future(self) -> bool {
        self.0 & MCL_FUTURE != 0
    }

    /// Whether `MCL_ONFAULT` is set.
    pub const fn on_fault(self) -> bool {
        self.0 & MCL_ONFAULT != 0
    }
}

// ── VmaLockState ─────────────────────────────────────────────────

/// Per-VMA memory lock state.
///
/// Tracks the lock status, flags, and page counts for a single
/// virtual memory area.
#[derive(Debug, Clone, Copy)]
pub struct VmaLockState {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Whether this VMA is locked.
    pub locked: bool,
    /// Whether the lock is on-fault only (MLOCK_ONFAULT).
    pub on_fault: bool,
    /// Number of pages currently locked (resident and wired).
    pub locked_pages: u64,
    /// Number of pages in this VMA.
    pub total_pages: u64,
    /// Process ID that owns this VMA.
    pub owner_pid: u64,
    /// Whether this VMA slot is active.
    pub active: bool,
}

impl VmaLockState {
    /// Creates an empty, inactive VMA lock state.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            locked: false,
            on_fault: false,
            locked_pages: 0,
            total_pages: 0,
            owner_pid: 0,
            active: false,
        }
    }

    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Whether an address falls within this VMA.
    pub const fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end()
    }

    /// Whether this VMA overlaps `[start, start+size)`.
    pub const fn overlaps(&self, start: u64, size: u64) -> bool {
        if !self.active || size == 0 {
            return false;
        }
        let end = start.saturating_add(size);
        self.start < end && self.end() > start
    }
}

// ── ProcessMlockState ────────────────────────────────────────────

/// Per-process memory lock accounting.
///
/// Tracks the total locked pages, RLIMIT_MEMLOCK, and
/// `mlockall` flags for a single process.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMlockState {
    /// Process ID.
    pub pid: u64,
    /// Total pages currently locked by this process.
    pub locked_pages: u64,
    /// RLIMIT_MEMLOCK in pages.
    pub limit_pages: u64,
    /// Whether `mlockall(MCL_CURRENT)` is active.
    pub lockall_current: bool,
    /// Whether `mlockall(MCL_FUTURE)` is active.
    pub lockall_future: bool,
    /// Whether `mlockall(MCL_ONFAULT)` is active.
    pub lockall_on_fault: bool,
    /// Whether this process has CAP_IPC_LOCK (unlimited).
    pub privileged: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl ProcessMlockState {
    /// Creates an empty, inactive process state.
    const fn empty() -> Self {
        Self {
            pid: 0,
            locked_pages: 0,
            limit_pages: DEFAULT_MEMLOCK_LIMIT_PAGES,
            lockall_current: false,
            lockall_future: false,
            lockall_on_fault: false,
            privileged: false,
            active: false,
        }
    }

    /// Remaining lockable pages before hitting the limit.
    pub fn remaining_limit(&self) -> u64 {
        if self.privileged {
            return u64::MAX;
        }
        self.limit_pages.saturating_sub(self.locked_pages)
    }

    /// Whether this process can lock `count` more pages.
    pub fn can_lock(&self, count: u64) -> bool {
        self.privileged || self.locked_pages + count <= self.limit_pages
    }
}

// ── MlockStats ───────────────────────────────────────────────────

/// Aggregate memory-locking statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MlockStats {
    /// Total `mlock` / `mlock2` calls.
    pub mlock_calls: u64,
    /// Total `munlock` calls.
    pub munlock_calls: u64,
    /// Total `mlockall` calls.
    pub mlockall_calls: u64,
    /// Total `munlockall` calls.
    pub munlockall_calls: u64,
    /// Pages locked.
    pub pages_locked: u64,
    /// Pages unlocked.
    pub pages_unlocked: u64,
    /// Lock failures due to RLIMIT_MEMLOCK.
    pub limit_failures: u64,
    /// Lock failures for other reasons.
    pub other_failures: u64,
}

// ── MlockManager ─────────────────────────────────────────────────

/// The mlock state machine.
///
/// Manages per-VMA lock state and per-process accounting for
/// memory locking operations. Enforces RLIMIT_MEMLOCK and
/// handles `mlockall` propagation.
pub struct MlockManager {
    /// Per-VMA lock states.
    vmas: [VmaLockState; MAX_VMAS],
    /// Number of active VMAs.
    vma_count: usize,
    /// Per-process mlock accounting.
    processes: [ProcessMlockState; MAX_PROCESSES],
    /// Number of active processes.
    process_count: usize,
    /// Statistics.
    stats: MlockStats,
}

impl Default for MlockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MlockManager {
    /// Creates a new, empty mlock manager.
    pub const fn new() -> Self {
        Self {
            vmas: [VmaLockState::empty(); MAX_VMAS],
            vma_count: 0,
            processes: [ProcessMlockState::empty(); MAX_PROCESSES],
            process_count: 0,
            stats: MlockStats {
                mlock_calls: 0,
                munlock_calls: 0,
                mlockall_calls: 0,
                munlockall_calls: 0,
                pages_locked: 0,
                pages_unlocked: 0,
                limit_failures: 0,
                other_failures: 0,
            },
        }
    }

    // ── Process management ───────────────────────────────────────

    /// Register a process for mlock tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the process table is full.
    /// Returns [`Error::AlreadyExists`] if the PID is already
    /// registered.
    pub fn register_process(&mut self, pid: u64, limit_pages: u64, privileged: bool) -> Result<()> {
        if self.find_process(pid).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .processes
            .iter_mut()
            .find(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = ProcessMlockState::empty();
        slot.pid = pid;
        slot.limit_pages = limit_pages;
        slot.privileged = privileged;
        slot.active = true;
        self.process_count += 1;
        Ok(())
    }

    /// Unregister a process, unlocking all its VMAs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    pub fn unregister_process(&mut self, pid: u64) -> Result<()> {
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        // Unlock all VMAs owned by this process.
        for vma in self.vmas.iter_mut() {
            if vma.active && vma.owner_pid == pid && vma.locked {
                self.stats.pages_unlocked += vma.locked_pages;
                vma.locked = false;
                vma.on_fault = false;
                vma.locked_pages = 0;
            }
        }

        self.processes[proc_idx].active = false;
        self.process_count = self.process_count.saturating_sub(1);
        Ok(())
    }

    /// Set RLIMIT_MEMLOCK for a process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    pub fn set_memlock_limit(&mut self, pid: u64, limit_pages: u64) -> Result<()> {
        let proc_state = self
            .processes
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        proc_state.limit_pages = limit_pages;
        Ok(())
    }

    /// Set CAP_IPC_LOCK privilege for a process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    pub fn set_privileged(&mut self, pid: u64, privileged: bool) -> Result<()> {
        let proc_state = self
            .processes
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        proc_state.privileged = privileged;
        Ok(())
    }

    // ── VMA management ───────────────────────────────────────────

    /// Register a VMA for lock tracking.
    ///
    /// If the owning process has `mlockall(MCL_FUTURE)` active, the
    /// VMA is automatically locked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the VMA table is full.
    /// Returns [`Error::InvalidArgument`] if addresses are not
    /// page-aligned or size is zero.
    pub fn register_vma(&mut self, start: u64, size: u64, owner_pid: u64) -> Result<()> {
        if start & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }

        let total_pages = size / PAGE_SIZE;

        let slot = self
            .vmas
            .iter_mut()
            .find(|v| !v.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = VmaLockState {
            start,
            size,
            locked: false,
            on_fault: false,
            locked_pages: 0,
            total_pages,
            owner_pid,
            active: true,
        };
        self.vma_count += 1;

        // Check mlockall(MCL_FUTURE) for the owning process.
        if let Some(proc_state) = self.find_process(owner_pid) {
            if proc_state.lockall_future {
                let on_fault = proc_state.lockall_on_fault;
                // Auto-lock the newly registered VMA.
                let _ = self.lock_vma_range(start, size, owner_pid, on_fault);
            }
        }

        Ok(())
    }

    /// Unregister a VMA, updating process accounting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching VMA is found.
    pub fn unregister_vma(&mut self, start: u64, owner_pid: u64) -> Result<()> {
        let vma_idx = self
            .vmas
            .iter()
            .position(|v| v.active && v.start == start && v.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        let was_locked = self.vmas[vma_idx].locked;
        let locked_pages = self.vmas[vma_idx].locked_pages;

        if was_locked {
            // Update process accounting.
            if let Some(proc_state) = self.find_process_mut(owner_pid) {
                proc_state.locked_pages = proc_state.locked_pages.saturating_sub(locked_pages);
            }
            self.stats.pages_unlocked += locked_pages;
        }

        self.vmas[vma_idx].active = false;
        self.vma_count = self.vma_count.saturating_sub(1);
        Ok(())
    }

    // ── mlock / mlock2 ──────────────────────────────────────────

    /// Lock a range of memory pages (`mlock` / `mlock2`).
    ///
    /// `addr` and `len` define the range to lock. `flags` may
    /// contain `MLOCK_ONFAULT` for lazy locking.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — address not page-aligned or
    ///   invalid flags.
    /// - [`Error::NotFound`] — no VMA covers the range, or process
    ///   not registered.
    /// - [`Error::PermissionDenied`] — RLIMIT_MEMLOCK exceeded.
    pub fn do_mlock(&mut self, pid: u64, addr: u64, len: u64, flags: u32) -> Result<()> {
        self.stats.mlock_calls += 1;

        if addr & (PAGE_SIZE - 1) != 0 || len == 0 {
            self.stats.other_failures += 1;
            return Err(Error::InvalidArgument);
        }

        let parsed_flags = MlockFlags::from_raw(flags)?;
        let aligned_len = page_align_up(len);

        self.lock_vma_range(addr, aligned_len, pid, parsed_flags.on_fault())
    }

    /// Internal: lock VMAs overlapping `[addr, addr+len)`.
    fn lock_vma_range(&mut self, addr: u64, len: u64, pid: u64, on_fault: bool) -> Result<()> {
        let end = addr.saturating_add(len);
        let pages_to_lock = len / PAGE_SIZE;

        // Check RLIMIT_MEMLOCK.
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        if !self.processes[proc_idx].can_lock(pages_to_lock) {
            self.stats.limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        // Lock all VMAs overlapping the range.
        let mut total_newly_locked: u64 = 0;
        let mut found_any = false;

        for vma in self.vmas.iter_mut() {
            if !vma.active || vma.owner_pid != pid {
                continue;
            }
            if !vma.overlaps(addr, len) {
                continue;
            }
            found_any = true;

            if vma.locked {
                // Already locked — update on_fault if needed.
                vma.on_fault = on_fault;
                continue;
            }

            // Calculate how many pages of this VMA are in the
            // requested range.
            let overlap_start = if vma.start > addr { vma.start } else { addr };
            let overlap_end = if vma.end() < end { vma.end() } else { end };
            let overlap_pages = (overlap_end - overlap_start) / PAGE_SIZE;

            vma.locked = true;
            vma.on_fault = on_fault;
            if on_fault {
                // Pages will be locked on fault — don't count yet.
                vma.locked_pages = 0;
            } else {
                vma.locked_pages = overlap_pages;
                total_newly_locked += overlap_pages;
            }
        }

        if !found_any {
            self.stats.other_failures += 1;
            return Err(Error::NotFound);
        }

        // Update process accounting.
        self.processes[proc_idx].locked_pages += total_newly_locked;
        self.stats.pages_locked += total_newly_locked;

        Ok(())
    }

    // ── munlock ──────────────────────────────────────────────────

    /// Unlock a range of memory pages (`munlock`).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — address not page-aligned or
    ///   len is zero.
    /// - [`Error::NotFound`] — no VMA covers the range, or process
    ///   not registered.
    pub fn do_munlock(&mut self, pid: u64, addr: u64, len: u64) -> Result<()> {
        self.stats.munlock_calls += 1;

        if addr & (PAGE_SIZE - 1) != 0 || len == 0 {
            self.stats.other_failures += 1;
            return Err(Error::InvalidArgument);
        }

        let aligned_len = page_align_up(len);
        self.unlock_vma_range(addr, aligned_len, pid)
    }

    /// Internal: unlock VMAs overlapping `[addr, addr+len)`.
    fn unlock_vma_range(&mut self, addr: u64, len: u64, pid: u64) -> Result<()> {
        let mut total_unlocked: u64 = 0;
        let mut found_any = false;

        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        for vma in self.vmas.iter_mut() {
            if !vma.active || vma.owner_pid != pid {
                continue;
            }
            if !vma.overlaps(addr, len) {
                continue;
            }
            found_any = true;

            if !vma.locked {
                continue;
            }

            total_unlocked += vma.locked_pages;
            vma.locked = false;
            vma.on_fault = false;
            vma.locked_pages = 0;
        }

        if !found_any {
            self.stats.other_failures += 1;
            return Err(Error::NotFound);
        }

        self.processes[proc_idx].locked_pages = self.processes[proc_idx]
            .locked_pages
            .saturating_sub(total_unlocked);
        self.stats.pages_unlocked += total_unlocked;

        Ok(())
    }

    // ── mlockall ─────────────────────────────────────────────────

    /// Lock all current and/or future mappings (`mlockall`).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — invalid flags.
    /// - [`Error::NotFound`] — process not registered.
    /// - [`Error::PermissionDenied`] — RLIMIT_MEMLOCK exceeded
    ///   when locking current mappings.
    pub fn do_mlockall(&mut self, pid: u64, flags: u32) -> Result<()> {
        self.stats.mlockall_calls += 1;

        let parsed = MclFlags::from_raw(flags)?;

        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        // Update process flags.
        if parsed.current() {
            self.processes[proc_idx].lockall_current = true;
        }
        if parsed.future() {
            self.processes[proc_idx].lockall_future = true;
        }
        if parsed.on_fault() {
            self.processes[proc_idx].lockall_on_fault = true;
        }

        // Lock all current VMAs if MCL_CURRENT is set.
        if parsed.current() {
            let on_fault = parsed.on_fault();
            self.lock_all_process_vmas(proc_idx, on_fault)?;
        }

        Ok(())
    }

    /// Internal: lock all VMAs belonging to a process.
    fn lock_all_process_vmas(&mut self, proc_idx: usize, on_fault: bool) -> Result<()> {
        let pid = self.processes[proc_idx].pid;
        let mut total_pages: u64 = 0;

        // First pass: count total pages to check RLIMIT.
        for vma in &self.vmas {
            if vma.active && vma.owner_pid == pid && !vma.locked {
                total_pages += vma.total_pages;
            }
        }

        if !on_fault && !self.processes[proc_idx].can_lock(total_pages) {
            self.stats.limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        // Second pass: lock VMAs.
        let mut newly_locked: u64 = 0;
        for vma in self.vmas.iter_mut() {
            if !vma.active || vma.owner_pid != pid {
                continue;
            }
            if vma.locked {
                vma.on_fault = on_fault;
                continue;
            }

            vma.locked = true;
            vma.on_fault = on_fault;
            if on_fault {
                vma.locked_pages = 0;
            } else {
                vma.locked_pages = vma.total_pages;
                newly_locked += vma.total_pages;
            }
        }

        self.processes[proc_idx].locked_pages += newly_locked;
        self.stats.pages_locked += newly_locked;

        Ok(())
    }

    // ── munlockall ───────────────────────────────────────────────

    /// Unlock all mappings for a process (`munlockall`).
    ///
    /// Clears `mlockall` flags and unlocks all VMAs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the process is not registered.
    pub fn do_munlockall(&mut self, pid: u64) -> Result<()> {
        self.stats.munlockall_calls += 1;

        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        // Clear mlockall flags.
        self.processes[proc_idx].lockall_current = false;
        self.processes[proc_idx].lockall_future = false;
        self.processes[proc_idx].lockall_on_fault = false;

        // Unlock all VMAs.
        let mut total_unlocked: u64 = 0;
        for vma in self.vmas.iter_mut() {
            if vma.active && vma.owner_pid == pid && vma.locked {
                total_unlocked += vma.locked_pages;
                vma.locked = false;
                vma.on_fault = false;
                vma.locked_pages = 0;
            }
        }

        self.processes[proc_idx].locked_pages = 0;
        self.stats.pages_unlocked += total_unlocked;

        Ok(())
    }

    // ── On-fault locking ─────────────────────────────────────────

    /// Notify that a page has been faulted in for an on-fault VMA.
    ///
    /// Increments the locked page count for the VMA and process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no locked on-fault VMA
    /// contains the address.
    /// Returns [`Error::PermissionDenied`] if locking this page
    /// would exceed RLIMIT_MEMLOCK.
    pub fn fault_in_page(&mut self, pid: u64, addr: u64) -> Result<()> {
        let proc_idx = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        // Check limit before locking.
        if !self.processes[proc_idx].can_lock(1) {
            self.stats.limit_failures += 1;
            return Err(Error::PermissionDenied);
        }

        let vma = self
            .vmas
            .iter_mut()
            .find(|v| v.active && v.owner_pid == pid && v.locked && v.on_fault && v.contains(addr))
            .ok_or(Error::NotFound)?;

        vma.locked_pages += 1;
        self.processes[proc_idx].locked_pages += 1;
        self.stats.pages_locked += 1;

        Ok(())
    }

    // ── Accessors ────────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &MlockStats {
        &self.stats
    }

    /// Number of active VMAs.
    pub fn vma_count(&self) -> usize {
        self.vma_count
    }

    /// Number of active processes.
    pub fn process_count(&self) -> usize {
        self.process_count
    }

    /// Look up per-process mlock state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the process is not registered.
    pub fn process_state(&self, pid: u64) -> Result<&ProcessMlockState> {
        self.processes
            .iter()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)
    }

    /// Count total locked pages across all processes.
    pub fn total_locked_pages(&self) -> u64 {
        self.processes
            .iter()
            .filter(|p| p.active)
            .map(|p| p.locked_pages)
            .sum()
    }

    /// Iterate over locked VMAs for a process.
    pub fn locked_vmas(&self, pid: u64) -> impl Iterator<Item = &VmaLockState> {
        self.vmas
            .iter()
            .filter(move |v| v.active && v.owner_pid == pid && v.locked)
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Find a process state by PID.
    fn find_process(&self, pid: u64) -> Option<&ProcessMlockState> {
        self.processes.iter().find(|p| p.active && p.pid == pid)
    }

    /// Find a mutable process state by PID.
    fn find_process_mut(&mut self, pid: u64) -> Option<&mut ProcessMlockState> {
        self.processes.iter_mut().find(|p| p.active && p.pid == pid)
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Align a value up to the next page boundary.
const fn page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & PAGE_MASK
}
