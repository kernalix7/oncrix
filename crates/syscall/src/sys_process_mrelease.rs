// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `process_mrelease(2)` — release memory of a dying process.
//!
//! This syscall allows a privileged process (typically an OOM monitor) to
//! expedite memory reclamation for a process that is in the process of dying.
//! It is designed to accelerate OOM killer throughput by immediately releasing
//! the anonymous pages of a process that has already received SIGKILL.
//!
//! # Syscall signature
//!
//! ```text
//! int process_mrelease(int pidfd, unsigned int flags);
//! ```
//!
//! # Semantics
//!
//! - `pidfd` must be a valid pidfd referring to a process in the process of
//!   exiting (task has received SIGKILL or equivalent fatal signal).
//! - Only anonymous (heap, stack, mmap-anon) pages are released immediately.
//! - File-backed and shared pages are skipped — they are handled by the
//!   normal page cache writeback / eviction path.
//! - If the process is not yet exiting, `EAGAIN` is returned.
//! - `flags` must be 0 (reserved for future use).
//!
//! # Linux reference
//!
//! Linux `mm/oom_kill.c` — `sys_process_mrelease()` (since Linux 5.15,
//! syscall number 448 on x86_64).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86_64 Linux ABI syscall number for `process_mrelease`.
pub const SYS_PROCESS_MRELEASE: u64 = 448;

/// Maximum number of pidfds / process records tracked by the subsystem.
const MAX_PROCS: usize = 128;

/// Maximum pages that can be released in one call (1 GiB / PAGE_SIZE).
const MAX_RELEASE_PAGES: u64 = 1024 * 1024 * 1024 / 4096;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// ProcessState — tracks per-process mrelease bookkeeping
// ---------------------------------------------------------------------------

/// Lifecycle state of a tracked process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLifecycle {
    /// Process is alive and running.
    Running,
    /// Process has received a fatal signal and is in the process of exiting.
    Dying,
    /// Process has fully exited (zombie or fully reaped).
    Dead,
}

/// A record describing one process tracked by the `process_mrelease` subsystem.
#[derive(Debug, Clone, Copy)]
pub struct ProcessRecord {
    /// PID of the process.
    pub pid: u64,
    /// Opaque pidfd handle (in a real kernel: a file descriptor into the
    /// pidfd namespace).
    pub pidfd: u32,
    /// Current lifecycle state.
    pub state: ProcessLifecycle,
    /// Number of anonymous pages owned by this process.
    pub anon_pages: u64,
    /// Number of file-backed pages (not released by `process_mrelease`).
    pub file_pages: u64,
    /// Number of shared-memory pages (not released by `process_mrelease`).
    pub shm_pages: u64,
    /// Total anonymous pages released by `process_mrelease` so far.
    pub released_pages: u64,
    /// Whether this slot is in use.
    pub active: bool,
}

impl ProcessRecord {
    /// Create an empty (inactive) record.
    const fn empty() -> Self {
        Self {
            pid: 0,
            pidfd: 0,
            state: ProcessLifecycle::Running,
            anon_pages: 0,
            file_pages: 0,
            shm_pages: 0,
            released_pages: 0,
            active: false,
        }
    }

    /// Return `true` if this process is eligible for `process_mrelease`.
    ///
    /// A process is eligible only when it is in the `Dying` state (has
    /// received SIGKILL / fatal signal but has not yet fully exited).
    pub const fn is_dying(&self) -> bool {
        matches!(self.state, ProcessLifecycle::Dying)
    }

    /// Return the number of pages that would be released on the next call.
    ///
    /// Only anonymous pages are eligible; shared and file-backed pages are
    /// skipped.
    pub const fn releasable_pages(&self) -> u64 {
        self.anon_pages.saturating_sub(self.released_pages)
    }
}

impl Default for ProcessRecord {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// MreleaseSubsystem — global tracking state
// ---------------------------------------------------------------------------

/// Global subsystem state for `process_mrelease`.
///
/// Tracks all registered processes by their pidfd handle and accumulates
/// release statistics.
pub struct MreleaseSubsystem {
    procs: [ProcessRecord; MAX_PROCS],
    count: usize,
    /// Total anonymous pages released across all calls.
    pub total_released: u64,
    /// Total number of successful `process_mrelease` calls.
    pub release_calls: u64,
    /// Number of calls that returned `EAGAIN` (process not yet dying).
    pub eagain_count: u64,
}

impl MreleaseSubsystem {
    /// Create an empty subsystem state.
    pub const fn new() -> Self {
        Self {
            procs: [const { ProcessRecord::empty() }; MAX_PROCS],
            count: 0,
            total_released: 0,
            release_calls: 0,
            eagain_count: 0,
        }
    }

    /// Register a new process for tracking.
    ///
    /// `pidfd` is the caller-supplied file descriptor.
    /// `anon_pages`, `file_pages`, and `shm_pages` describe the initial
    /// memory footprint.
    ///
    /// Returns `OutOfMemory` if the process table is full, or
    /// `AlreadyExists` if `pidfd` is already registered.
    pub fn register(
        &mut self,
        pidfd: u32,
        pid: u64,
        anon_pages: u64,
        file_pages: u64,
        shm_pages: u64,
    ) -> Result<()> {
        // Reject duplicate pidfds.
        if self.find_by_pidfd(pidfd).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .procs
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        self.procs[slot] = ProcessRecord {
            pid,
            pidfd,
            state: ProcessLifecycle::Running,
            anon_pages,
            file_pages,
            shm_pages,
            released_pages: 0,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Transition a registered process to the `Dying` state.
    ///
    /// This is called by the OOM killer or signal delivery when the process
    /// has been sent a fatal signal.
    pub fn mark_dying(&mut self, pidfd: u32) -> Result<()> {
        let idx = self.find_idx_by_pidfd(pidfd).ok_or(Error::NotFound)?;
        self.procs[idx].state = ProcessLifecycle::Dying;
        Ok(())
    }

    /// Transition a registered process to the `Dead` state.
    pub fn mark_dead(&mut self, pidfd: u32) -> Result<()> {
        let idx = self.find_idx_by_pidfd(pidfd).ok_or(Error::NotFound)?;
        self.procs[idx].state = ProcessLifecycle::Dead;
        Ok(())
    }

    /// Remove a process record (called after the process is fully reaped).
    pub fn remove(&mut self, pidfd: u32) {
        for slot in self.procs.iter_mut() {
            if slot.active && slot.pidfd == pidfd {
                slot.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return a shared reference to a process record by pidfd.
    fn find_by_pidfd(&self, pidfd: u32) -> Option<&ProcessRecord> {
        self.procs.iter().find(|p| p.active && p.pidfd == pidfd)
    }

    /// Return the index of a process record by pidfd.
    fn find_idx_by_pidfd(&self, pidfd: u32) -> Option<usize> {
        self.procs.iter().position(|p| p.active && p.pidfd == pidfd)
    }

    /// Return the number of active process records.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for MreleaseSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `process_mrelease` arguments.
///
/// # Checks
///
/// - `pidfd` must be non-negative (represented as `i32` from the ABI).
/// - `flags` must be 0.
fn validate_args(pidfd: i32, flags: u32) -> Result<()> {
    if pidfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MreleaseResult
// ---------------------------------------------------------------------------

/// Result of a successful `process_mrelease` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MreleaseResult {
    /// Number of anonymous pages released during this call.
    pub pages_released: u64,
    /// Total bytes freed (`pages_released * PAGE_SIZE`).
    pub bytes_freed: u64,
}

// ---------------------------------------------------------------------------
// sys_process_mrelease — primary handler
// ---------------------------------------------------------------------------

/// `process_mrelease(2)` syscall handler.
///
/// Releases the anonymous memory pages of the dying process identified by
/// `pidfd`.  Only processes that are in the `Dying` state (have received a
/// fatal signal) can be acted on; otherwise `WouldBlock` (EAGAIN) is
/// returned.
///
/// File-backed and shared-memory pages are deliberately skipped — they are
/// managed by separate writeback and eviction paths.
///
/// # Arguments
///
/// * `sys`   — Mutable subsystem state.
/// * `pidfd` — Raw pidfd value from the syscall register (may be negative).
/// * `flags` — Must be 0.
///
/// # Returns
///
/// A [`MreleaseResult`] describing the pages freed on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Negative `pidfd` or non-zero `flags`.
/// * [`Error::NotFound`]        — No process registered under `pidfd`.
/// * [`Error::WouldBlock`]      — Process is still alive (not yet dying).
///   Callers should retry after a short delay.
pub fn sys_process_mrelease(
    sys: &mut MreleaseSubsystem,
    pidfd: i32,
    flags: u32,
) -> Result<MreleaseResult> {
    validate_args(pidfd, flags)?;

    let upidfd = pidfd as u32;
    let idx = sys.find_idx_by_pidfd(upidfd).ok_or(Error::NotFound)?;

    // EAGAIN: process has not yet entered the dying state.
    if !sys.procs[idx].is_dying() {
        sys.eagain_count = sys.eagain_count.saturating_add(1);
        return Err(Error::WouldBlock);
    }

    // Determine how many anonymous pages remain to be released.
    let releasable = sys.procs[idx].releasable_pages();
    // Clamp to the per-call maximum to avoid unbounded latency.
    let to_release = releasable.min(MAX_RELEASE_PAGES);

    // Update the record: mark pages as released.
    sys.procs[idx].released_pages = sys.procs[idx].released_pages.saturating_add(to_release);

    // Update global counters.
    sys.total_released = sys.total_released.saturating_add(to_release);
    sys.release_calls = sys.release_calls.saturating_add(1);

    // If all anonymous pages have been released, transition to Dead.
    if sys.procs[idx].releasable_pages() == 0 {
        sys.procs[idx].state = ProcessLifecycle::Dead;
    }

    Ok(MreleaseResult {
        pages_released: to_release,
        bytes_freed: to_release.saturating_mul(PAGE_SIZE),
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sys() -> MreleaseSubsystem {
        MreleaseSubsystem::new()
    }

    fn register_dying(sys: &mut MreleaseSubsystem, pidfd: u32, anon: u64) {
        sys.register(pidfd, pidfd as u64 * 100, anon, 10, 5)
            .unwrap();
        sys.mark_dying(pidfd).unwrap();
    }

    #[test]
    fn validate_negative_pidfd_rejected() {
        let mut s = make_sys();
        assert_eq!(
            sys_process_mrelease(&mut s, -1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_nonzero_flags_rejected() {
        let mut s = make_sys();
        s.register(1, 100, 50, 10, 0).unwrap();
        assert_eq!(
            sys_process_mrelease(&mut s, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_pidfd_returns_not_found() {
        let mut s = make_sys();
        assert_eq!(sys_process_mrelease(&mut s, 42, 0), Err(Error::NotFound));
    }

    #[test]
    fn running_process_returns_eagain() {
        let mut s = make_sys();
        s.register(2, 200, 100, 0, 0).unwrap();
        // Process is still Running — must return WouldBlock (EAGAIN).
        assert_eq!(sys_process_mrelease(&mut s, 2, 0), Err(Error::WouldBlock));
        assert_eq!(s.eagain_count, 1);
    }

    #[test]
    fn dying_process_releases_anon_pages() {
        let mut s = make_sys();
        register_dying(&mut s, 3, 256);
        let res = sys_process_mrelease(&mut s, 3, 0).unwrap();
        assert_eq!(res.pages_released, 256);
        assert_eq!(res.bytes_freed, 256 * PAGE_SIZE);
        assert_eq!(s.total_released, 256);
        assert_eq!(s.release_calls, 1);
    }

    #[test]
    fn dying_process_transitions_to_dead_after_full_release() {
        let mut s = make_sys();
        register_dying(&mut s, 4, 8);
        sys_process_mrelease(&mut s, 4, 0).unwrap();
        // After all pages released the record should be Dead.
        assert_eq!(s.procs[0].state, ProcessLifecycle::Dead);
    }

    #[test]
    fn file_and_shm_pages_not_counted() {
        let mut s = make_sys();
        // Register with 0 anon pages but many file and shm pages.
        s.register(5, 500, 0, 1000, 500).unwrap();
        s.mark_dying(5).unwrap();
        let res = sys_process_mrelease(&mut s, 5, 0).unwrap();
        // No anonymous pages — zero released.
        assert_eq!(res.pages_released, 0);
        assert_eq!(res.bytes_freed, 0);
    }

    #[test]
    fn large_process_clamped_to_max_per_call() {
        let mut s = make_sys();
        // Register with more anon pages than MAX_RELEASE_PAGES.
        let huge = MAX_RELEASE_PAGES + 1024;
        s.register(6, 600, huge, 0, 0).unwrap();
        s.mark_dying(6).unwrap();
        let res = sys_process_mrelease(&mut s, 6, 0).unwrap();
        assert_eq!(res.pages_released, MAX_RELEASE_PAGES);
        // Process still has remaining pages — still Dying.
        assert_eq!(s.procs[0].state, ProcessLifecycle::Dying);
    }

    #[test]
    fn duplicate_pidfd_registration_rejected() {
        let mut s = make_sys();
        s.register(7, 700, 10, 0, 0).unwrap();
        assert_eq!(s.register(7, 701, 10, 0, 0), Err(Error::AlreadyExists));
    }

    #[test]
    fn remove_cleans_up_slot() {
        let mut s = make_sys();
        register_dying(&mut s, 8, 10);
        assert_eq!(s.count(), 1);
        s.remove(8);
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn mark_dead_transitions_state() {
        let mut s = make_sys();
        s.register(9, 900, 5, 0, 0).unwrap();
        s.mark_dying(9).unwrap();
        s.mark_dead(9).unwrap();
        assert_eq!(s.procs[0].state, ProcessLifecycle::Dead);
    }

    #[test]
    fn mark_dying_unknown_pidfd_fails() {
        let mut s = make_sys();
        assert_eq!(s.mark_dying(99), Err(Error::NotFound));
    }

    #[test]
    fn releasable_pages_matches_unreleased_anon() {
        let rec = ProcessRecord {
            pid: 1,
            pidfd: 1,
            state: ProcessLifecycle::Dying,
            anon_pages: 100,
            file_pages: 50,
            shm_pages: 25,
            released_pages: 30,
            active: true,
        };
        assert_eq!(rec.releasable_pages(), 70);
    }
}
