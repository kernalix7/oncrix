// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `tgkill(2)` and `tkill(2)` — thread-directed signal delivery.
//!
//! These Linux syscalls send a signal to a specific thread within a
//! thread group (process).  `tgkill` is the preferred interface because
//! it avoids the race condition inherent in `tkill` where TIDs can be
//! recycled between the caller looking up the TID and the kernel
//! delivering the signal.
//!
//! # Syscalls
//!
//! | Syscall | Number (x86_64) | Handler | Description |
//! |---------|----------------|---------|-------------|
//! | `tgkill` | 234 | [`do_tgkill`] | Send signal to thread in group |
//! | `tkill` | 200 | [`do_tkill`] | Send signal to thread (legacy) |
//!
//! # POSIX Alignment
//!
//! POSIX does not define `tgkill` or `tkill` directly; the portable
//! interface is `kill(2)` and `pthread_kill(3)`.  The POSIX `kill()`
//! spec requires:
//!
//! - `sig == 0`: error checking only, no signal sent.
//! - Permission: real/effective UID of sender must match real/saved-set
//!   UID of receiver, unless the sender has appropriate privileges.
//! - `SIGCONT` to a session member always permitted.
//! - Errors: `EINVAL` (bad signal), `ESRCH` (no such process/thread),
//!   `EPERM` (no permission).
//!
//! See POSIX.1-2024 `kill()`, `<signal.h>`.
//!
//! # References
//!
//! - Linux: `kernel/signal.c` (`do_tkill`, `do_tgkill`)
//! - `man tgkill(2)`, `man tkill(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Signal constants
// ---------------------------------------------------------------------------

/// Maximum valid signal number (real-time signals extend to 64).
pub const SIG_MAX: i32 = 64;

/// `SIGKILL` — cannot be caught, blocked, or ignored.
pub const SIGKILL: i32 = 9;

/// `SIGSTOP` — cannot be caught, blocked, or ignored.
pub const SIGSTOP: i32 = 19;

/// `SIGCONT` — continue a stopped process (special permission rules).
pub const SIGCONT: i32 = 18;

/// `SIGCHLD` — sent to parent when a child stops or terminates.
pub const SIGCHLD: i32 = 17;

// ---------------------------------------------------------------------------
// SignalTarget — where to deliver
// ---------------------------------------------------------------------------

/// Identifies the target of a signal delivery operation.
///
/// Encapsulates the `(tgid, tid)` pair that uniquely identifies a
/// thread in the system.  For `tkill` the tgid is unknown (set to 0),
/// which is why `tgkill` is preferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalTarget {
    /// Thread group ID (process ID).  0 means "any group" (`tkill`).
    pub tgid: u64,
    /// Thread ID within the group.
    pub tid: u64,
}

impl SignalTarget {
    /// Construct a fully-specified target (for `tgkill`).
    pub const fn new(tgid: u64, tid: u64) -> Self {
        Self { tgid, tid }
    }

    /// Construct a target with unknown group (for `tkill`).
    pub const fn tid_only(tid: u64) -> Self {
        Self { tgid: 0, tid }
    }

    /// Return `true` if the group ID was specified.
    pub const fn has_tgid(&self) -> bool {
        self.tgid != 0
    }
}

// ---------------------------------------------------------------------------
// KillFlags — delivery options
// ---------------------------------------------------------------------------

/// Flags controlling signal delivery behaviour.
///
/// These are not part of the `tgkill` ABI (which takes no flags) but
/// are used internally to annotate delivery requests with additional
/// context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillFlags(u32);

impl KillFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);

    /// Forceful delivery: bypass blocked-signal checks.
    /// Used for `SIGKILL` and `SIGSTOP`.
    pub const FORCE: Self = Self(1 << 0);

    /// Informational: the signal is being sent for process-group
    /// operations (`kill(-pgid, sig)`).
    pub const GROUP: Self = Self(1 << 1);

    /// The caller explicitly checked permissions already.
    pub const PERM_CHECKED: Self = Self(1 << 2);

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return `true` if the FORCE flag is set.
    pub const fn is_force(self) -> bool {
        self.0 & 1 != 0
    }

    /// Return `true` if the GROUP flag is set.
    pub const fn is_group(self) -> bool {
        self.0 & 2 != 0
    }

    /// Return `true` if the PERM_CHECKED flag is set.
    pub const fn is_perm_checked(self) -> bool {
        self.0 & 4 != 0
    }
}

impl Default for KillFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// ---------------------------------------------------------------------------
// TgkillInfo — signal delivery metadata
// ---------------------------------------------------------------------------

/// Metadata for a `tgkill`/`tkill` signal delivery.
///
/// Records the sender information and the signal that was (or will
/// be) delivered.  Analogous to a subset of `struct kernel_siginfo`
/// in Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TgkillInfo {
    /// Signal number being sent.
    pub signo: i32,
    /// PID of the sender.
    pub sender_pid: u64,
    /// UID of the sender.
    pub sender_uid: u32,
    /// Target thread.
    pub target: SignalTarget,
    /// Delivery flags.
    pub flags: KillFlags,
    /// Whether the signal was actually delivered (set by the handler).
    pub delivered: bool,
}

impl TgkillInfo {
    /// Construct a new delivery info record.
    pub const fn new(signo: i32, sender_pid: u64, sender_uid: u32, target: SignalTarget) -> Self {
        Self {
            signo,
            sender_pid,
            sender_uid,
            target,
            flags: KillFlags::NONE,
            delivered: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ThreadEntry — per-thread record for the thread table
// ---------------------------------------------------------------------------

/// Per-thread record used by the signal delivery subsystem.
#[derive(Debug, Clone, Copy)]
pub struct ThreadEntry {
    /// Thread ID.
    pub tid: u64,
    /// Thread group ID (leader PID).
    pub tgid: u64,
    /// Owner UID.
    pub uid: u32,
    /// Session ID (for `SIGCONT` permission check).
    pub sid: u64,
    /// Bitmask of blocked signals.
    pub blocked_mask: u64,
    /// Bitmask of pending signals.
    pub pending_mask: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl ThreadEntry {
    /// Create an inactive (empty) slot.
    const fn empty() -> Self {
        Self {
            tid: 0,
            tgid: 0,
            uid: 0,
            sid: 0,
            blocked_mask: 0,
            pending_mask: 0,
            active: false,
        }
    }

    /// Create an active entry.
    pub const fn new(tid: u64, tgid: u64, uid: u32, sid: u64) -> Self {
        Self {
            tid,
            tgid,
            uid,
            sid,
            blocked_mask: 0,
            pending_mask: 0,
            active: true,
        }
    }

    /// Return `true` if signal `sig` is currently blocked.
    pub const fn is_blocked(&self, sig: i32) -> bool {
        if sig < 1 || sig > SIG_MAX {
            return false;
        }
        self.blocked_mask & (1u64 << (sig - 1) as u64) != 0
    }

    /// Return `true` if signal `sig` is currently pending.
    pub const fn is_pending(&self, sig: i32) -> bool {
        if sig < 1 || sig > SIG_MAX {
            return false;
        }
        self.pending_mask & (1u64 << (sig - 1) as u64) != 0
    }

    /// Mark signal `sig` as pending on this thread.
    fn set_pending(&mut self, sig: i32) {
        if sig >= 1 && sig <= SIG_MAX {
            self.pending_mask |= 1u64 << (sig - 1) as u64;
        }
    }
}

// ---------------------------------------------------------------------------
// ThreadTable — flat table of threads
// ---------------------------------------------------------------------------

/// Maximum threads tracked in the table.
const MAX_THREADS: usize = 256;

/// A flat table of threads for signal delivery lookup.
///
/// In a production kernel this would be integrated into the process
/// table and scheduler data structures.  The standalone table is
/// useful for unit testing and early bring-up.
pub struct ThreadTable {
    /// Fixed-size slot array.
    entries: [ThreadEntry; MAX_THREADS],
    /// Number of active entries.
    count: usize,
}

impl ThreadTable {
    /// Create an empty thread table.
    pub const fn new() -> Self {
        Self {
            entries: [const { ThreadEntry::empty() }; MAX_THREADS],
            count: 0,
        }
    }

    /// Return the number of active threads.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the table has no active entries.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register a new thread.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the table is full.
    pub fn register(&mut self, entry: ThreadEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.active {
                *slot = entry;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a thread by TID.
    pub fn unregister(&mut self, tid: u64) {
        for slot in self.entries.iter_mut() {
            if slot.active && slot.tid == tid {
                slot.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Look up a thread by TID.
    pub fn find_by_tid(&self, tid: u64) -> Option<&ThreadEntry> {
        self.entries.iter().find(|e| e.active && e.tid == tid)
    }

    /// Look up a mutable thread by TID.
    fn find_by_tid_mut(&mut self, tid: u64) -> Option<&mut ThreadEntry> {
        self.entries.iter_mut().find(|e| e.active && e.tid == tid)
    }

    /// Look up a thread by (tgid, tid) pair.
    pub fn find_by_tgid_tid(&self, tgid: u64, tid: u64) -> Option<&ThreadEntry> {
        self.entries
            .iter()
            .find(|e| e.active && e.tgid == tgid && e.tid == tid)
    }

    /// Look up a mutable thread by (tgid, tid) pair.
    fn find_by_tgid_tid_mut(&mut self, tgid: u64, tid: u64) -> Option<&mut ThreadEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.active && e.tgid == tgid && e.tid == tid)
    }

    /// Count threads in a specific thread group.
    pub fn count_in_group(&self, tgid: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| e.active && e.tgid == tgid)
            .count()
    }
}

impl Default for ThreadTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a signal number.
///
/// `sig == 0` is valid (null signal for permission checking).
/// Values 1..=[`SIG_MAX`] are valid signal numbers.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] for out-of-range values.
pub fn validate_signal(sig: i32) -> Result<()> {
    if sig < 0 || sig > SIG_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether `sender_uid` has permission to send a signal to the
/// thread described by `target_entry`.
///
/// POSIX permission rule:
/// - Root (uid 0) can always send.
/// - The real or effective UID of the sender must match the real or
///   saved-set UID of the receiver.
/// - `SIGCONT` to a session member is always permitted.
fn check_permission(
    sender_uid: u32,
    sender_sid: u64,
    target: &ThreadEntry,
    sig: i32,
) -> Result<()> {
    // Root can always send.
    if sender_uid == 0 {
        return Ok(());
    }

    // SIGCONT to same-session member always permitted.
    if sig == SIGCONT && sender_sid == target.sid && target.sid != 0 {
        return Ok(());
    }

    // UID-based permission: sender uid must match target uid.
    // (Simplified: in a full implementation we would check
    // real/effective sender UID against real/saved-set target UID.)
    if sender_uid == target.uid {
        return Ok(());
    }

    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// do_tgkill — send signal to specific thread in group
// ---------------------------------------------------------------------------

/// Handler for `tgkill(2)`.
///
/// Sends signal `sig` to thread `tid` in thread group `tgid`.
/// This is the preferred interface over `tkill` because specifying
/// both the group and thread ID eliminates the TID-reuse race.
///
/// # Arguments
///
/// * `table`      - Thread table for lookup.
/// * `tgid`       - Thread group ID (must be > 0).
/// * `tid`        - Thread ID within the group (must be > 0).
/// * `sig`        - Signal number (0 = null signal / check only).
/// * `sender_pid` - PID of the sending process.
/// * `sender_uid` - UID of the sending process.
/// * `sender_sid` - Session ID of the sender (for `SIGCONT` check).
///
/// # Returns
///
/// `Ok(())` on success.  When `sig == 0` no signal is delivered but
/// the target is validated and permission is checked.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  - Bad signal, tgid, or tid.
/// * [`Error::NotFound`]         - No matching thread.
/// * [`Error::PermissionDenied`] - Insufficient privilege.
///
/// # POSIX Conformance
///
/// Linux extension; permission checks follow the POSIX `kill()`
/// permission model (real/effective UID matching).
pub fn do_tgkill(
    table: &mut ThreadTable,
    tgid: u64,
    tid: u64,
    sig: i32,
    sender_pid: u64,
    sender_uid: u32,
    sender_sid: u64,
) -> Result<()> {
    // Validate arguments.
    if tgid == 0 || tid == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_signal(sig)?;

    // Look up the target thread by (tgid, tid).
    let target = table.find_by_tgid_tid(tgid, tid).ok_or(Error::NotFound)?;

    // Permission check.
    check_permission(sender_uid, sender_sid, target, sig)?;

    // sig == 0 is the null signal: validate only, do not deliver.
    if sig == 0 {
        return Ok(());
    }

    // Mark the signal as pending on the target thread.
    // SIGKILL and SIGSTOP cannot be blocked; deliver unconditionally.
    let target_mut = table
        .find_by_tgid_tid_mut(tgid, tid)
        .ok_or(Error::NotFound)?;

    let force = sig == SIGKILL || sig == SIGSTOP;
    if !force && target_mut.is_blocked(sig) {
        // Signal is blocked: set pending but do not deliver yet.
        target_mut.set_pending(sig);
        return Ok(());
    }

    target_mut.set_pending(sig);

    // Stub: in a real kernel we would now wake the thread if it is
    // sleeping and arrange for signal delivery on return to user space.
    let _ = sender_pid;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_tkill — send signal to thread (legacy, no tgid)
// ---------------------------------------------------------------------------

/// Handler for `tkill(2)` (legacy).
///
/// Sends signal `sig` to thread `tid` without specifying the thread
/// group.  This is susceptible to TID-reuse races; prefer
/// [`do_tgkill`] for new code.
///
/// # Arguments
///
/// * `table`      - Thread table.
/// * `tid`        - Thread ID (must be > 0).
/// * `sig`        - Signal number (0 = null signal).
/// * `sender_pid` - PID of the sender.
/// * `sender_uid` - UID of the sender.
/// * `sender_sid` - Session ID of the sender.
///
/// # Errors
///
/// Same as [`do_tgkill`].
pub fn do_tkill(
    table: &mut ThreadTable,
    tid: u64,
    sig: i32,
    sender_pid: u64,
    sender_uid: u32,
    sender_sid: u64,
) -> Result<()> {
    if tid == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_signal(sig)?;

    // Look up by TID only (any group).
    let target = table.find_by_tid(tid).ok_or(Error::NotFound)?;

    check_permission(sender_uid, sender_sid, target, sig)?;

    if sig == 0 {
        return Ok(());
    }

    let target_mut = table.find_by_tid_mut(tid).ok_or(Error::NotFound)?;

    let force = sig == SIGKILL || sig == SIGSTOP;
    if !force && target_mut.is_blocked(sig) {
        target_mut.set_pending(sig);
        return Ok(());
    }

    target_mut.set_pending(sig);
    let _ = sender_pid;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a table with threads for testing.
    ///
    /// Layout:
    /// - tid=10, tgid=5, uid=1000, sid=100
    /// - tid=11, tgid=5, uid=1000, sid=100  (same group)
    /// - tid=20, tgid=6, uid=2000, sid=200
    /// - tid=30, tgid=7, uid=0,    sid=100  (root, same session as 10/11)
    fn make_table() -> ThreadTable {
        let mut t = ThreadTable::new();
        t.register(ThreadEntry::new(10, 5, 1000, 100)).unwrap();
        t.register(ThreadEntry::new(11, 5, 1000, 100)).unwrap();
        t.register(ThreadEntry::new(20, 6, 2000, 200)).unwrap();
        t.register(ThreadEntry::new(30, 7, 0, 100)).unwrap();
        t
    }

    // --- validate_signal ---

    #[test]
    fn signal_zero_valid() {
        assert!(validate_signal(0).is_ok());
    }

    #[test]
    fn signal_max_valid() {
        assert!(validate_signal(SIG_MAX).is_ok());
    }

    #[test]
    fn signal_negative_invalid() {
        assert_eq!(validate_signal(-1), Err(Error::InvalidArgument));
    }

    #[test]
    fn signal_above_max_invalid() {
        assert_eq!(validate_signal(SIG_MAX + 1), Err(Error::InvalidArgument));
    }

    // --- SignalTarget ---

    #[test]
    fn target_new_has_tgid() {
        let t = SignalTarget::new(5, 10);
        assert!(t.has_tgid());
        assert_eq!(t.tgid, 5);
        assert_eq!(t.tid, 10);
    }

    #[test]
    fn target_tid_only_no_tgid() {
        let t = SignalTarget::tid_only(10);
        assert!(!t.has_tgid());
    }

    // --- KillFlags ---

    #[test]
    fn flags_none_all_false() {
        let f = KillFlags::NONE;
        assert!(!f.is_force());
        assert!(!f.is_group());
        assert!(!f.is_perm_checked());
    }

    #[test]
    fn flags_union() {
        let f = KillFlags::FORCE.union(KillFlags::GROUP);
        assert!(f.is_force());
        assert!(f.is_group());
        assert!(!f.is_perm_checked());
    }

    #[test]
    fn flags_default_is_none() {
        assert_eq!(KillFlags::default(), KillFlags::NONE);
    }

    // --- ThreadTable ---

    #[test]
    fn table_register_unregister() {
        let mut t = ThreadTable::new();
        t.register(ThreadEntry::new(1, 1, 0, 1)).unwrap();
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
        t.unregister(1);
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn table_count_in_group() {
        let t = make_table();
        assert_eq!(t.count_in_group(5), 2);
        assert_eq!(t.count_in_group(6), 1);
        assert_eq!(t.count_in_group(999), 0);
    }

    // --- do_tgkill basic ---

    #[test]
    fn tgkill_delivers_signal() {
        let mut t = make_table();
        // uid 1000 sends SIGCHLD to its own thread (tid=10, tgid=5)
        do_tgkill(&mut t, 5, 10, SIGCHLD, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert!(entry.is_pending(SIGCHLD));
    }

    #[test]
    fn tgkill_null_signal_no_delivery() {
        let mut t = make_table();
        do_tgkill(&mut t, 5, 10, 0, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert_eq!(entry.pending_mask, 0);
    }

    #[test]
    fn tgkill_not_found_wrong_tgid() {
        let mut t = make_table();
        // tid=10 is in tgid=5, not tgid=6
        assert_eq!(
            do_tgkill(&mut t, 6, 10, SIGCHLD, 10, 1000, 100),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn tgkill_not_found_bad_tid() {
        let mut t = make_table();
        assert_eq!(
            do_tgkill(&mut t, 5, 999, SIGCHLD, 10, 1000, 100),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn tgkill_zero_tgid_invalid() {
        let mut t = make_table();
        assert_eq!(
            do_tgkill(&mut t, 0, 10, SIGCHLD, 10, 1000, 100),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn tgkill_zero_tid_invalid() {
        let mut t = make_table();
        assert_eq!(
            do_tgkill(&mut t, 5, 0, SIGCHLD, 10, 1000, 100),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn tgkill_bad_signal() {
        let mut t = make_table();
        assert_eq!(
            do_tgkill(&mut t, 5, 10, -1, 10, 1000, 100),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            do_tgkill(&mut t, 5, 10, 65, 10, 1000, 100),
            Err(Error::InvalidArgument)
        );
    }

    // --- Permission checks ---

    #[test]
    fn tgkill_permission_denied() {
        let mut t = make_table();
        // uid 2000 trying to signal tid=10 (uid 1000)
        assert_eq!(
            do_tgkill(&mut t, 5, 10, SIGCHLD, 20, 2000, 200),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn tgkill_root_always_allowed() {
        let mut t = make_table();
        // root (uid 0) can signal anyone
        do_tgkill(&mut t, 5, 10, SIGCHLD, 30, 0, 100).unwrap();
    }

    #[test]
    fn tgkill_sigcont_same_session_allowed() {
        let mut t = make_table();
        // tid=30 (uid 0, sid 100) sends SIGCONT to tid=10 (uid 1000, sid 100)
        // Even if we pretend root is not special, same-session SIGCONT works.
        // But let's test with a non-root sender: tid=10 (uid 1000, sid 100)
        // sending to tid=30 (uid 0, sid 100).
        // uid 1000 != uid 0, but SIGCONT + same session => allowed.
        do_tgkill(&mut t, 7, 30, SIGCONT, 10, 1000, 100).unwrap();
    }

    #[test]
    fn tgkill_sigcont_different_session_denied() {
        let mut t = make_table();
        // uid 1000, sid 100 -> tid=20 (uid 2000, sid 200)
        // Different UID and different session => denied even for SIGCONT.
        assert_eq!(
            do_tgkill(&mut t, 6, 20, SIGCONT, 10, 1000, 100),
            Err(Error::PermissionDenied)
        );
    }

    // --- SIGKILL / SIGSTOP cannot be blocked ---

    #[test]
    fn tgkill_sigkill_delivered_even_if_blocked() {
        let mut t = make_table();
        // Block all signals on tid=10
        let entry = t.find_by_tid_mut(10).unwrap();
        entry.blocked_mask = u64::MAX;

        do_tgkill(&mut t, 5, 10, SIGKILL, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert!(entry.is_pending(SIGKILL));
    }

    #[test]
    fn tgkill_sigstop_delivered_even_if_blocked() {
        let mut t = make_table();
        let entry = t.find_by_tid_mut(10).unwrap();
        entry.blocked_mask = u64::MAX;

        do_tgkill(&mut t, 5, 10, SIGSTOP, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert!(entry.is_pending(SIGSTOP));
    }

    #[test]
    fn tgkill_blocked_signal_goes_pending() {
        let mut t = make_table();
        // Block SIGCHLD on tid=10
        let entry = t.find_by_tid_mut(10).unwrap();
        entry.blocked_mask = 1u64 << (SIGCHLD - 1) as u64;

        do_tgkill(&mut t, 5, 10, SIGCHLD, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert!(entry.is_pending(SIGCHLD));
    }

    // --- do_tkill ---

    #[test]
    fn tkill_delivers_signal() {
        let mut t = make_table();
        do_tkill(&mut t, 10, SIGCHLD, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert!(entry.is_pending(SIGCHLD));
    }

    #[test]
    fn tkill_null_signal() {
        let mut t = make_table();
        do_tkill(&mut t, 10, 0, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert_eq!(entry.pending_mask, 0);
    }

    #[test]
    fn tkill_not_found() {
        let mut t = make_table();
        assert_eq!(
            do_tkill(&mut t, 999, SIGCHLD, 10, 1000, 100),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn tkill_zero_tid_invalid() {
        let mut t = make_table();
        assert_eq!(
            do_tkill(&mut t, 0, SIGCHLD, 10, 1000, 100),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn tkill_permission_denied() {
        let mut t = make_table();
        assert_eq!(
            do_tkill(&mut t, 10, SIGCHLD, 20, 2000, 200),
            Err(Error::PermissionDenied)
        );
    }

    // --- ThreadEntry helpers ---

    #[test]
    fn entry_is_blocked_boundary() {
        let mut e = ThreadEntry::new(1, 1, 0, 1);
        e.blocked_mask = 1 << 0; // signal 1 blocked
        assert!(e.is_blocked(1));
        assert!(!e.is_blocked(2));
        // Invalid signal numbers.
        assert!(!e.is_blocked(0));
        assert!(!e.is_blocked(-1));
        assert!(!e.is_blocked(65));
    }

    #[test]
    fn entry_is_pending_boundary() {
        let mut e = ThreadEntry::new(1, 1, 0, 1);
        e.pending_mask = 1 << (SIG_MAX - 1) as u64;
        assert!(e.is_pending(SIG_MAX));
        assert!(!e.is_pending(1));
    }

    // --- TgkillInfo ---

    #[test]
    fn tgkill_info_construction() {
        let target = SignalTarget::new(5, 10);
        let info = TgkillInfo::new(SIGCHLD, 10, 1000, target);
        assert_eq!(info.signo, SIGCHLD);
        assert_eq!(info.sender_pid, 10);
        assert_eq!(info.sender_uid, 1000);
        assert_eq!(info.target, target);
        assert!(!info.delivered);
    }

    // --- Multiple signals pending ---

    #[test]
    fn multiple_signals_pending() {
        let mut t = make_table();
        do_tgkill(&mut t, 5, 10, SIGCHLD, 10, 1000, 100).unwrap();
        do_tgkill(&mut t, 5, 10, SIGKILL, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(10).unwrap();
        assert!(entry.is_pending(SIGCHLD));
        assert!(entry.is_pending(SIGKILL));
        // Other signals should not be pending.
        assert!(!entry.is_pending(SIGSTOP));
    }

    // --- Send to different thread in same group ---

    #[test]
    fn tgkill_different_thread_same_group() {
        let mut t = make_table();
        // tid=10 sends to tid=11, both in tgid=5
        do_tgkill(&mut t, 5, 11, SIGCHLD, 10, 1000, 100).unwrap();
        let entry = t.find_by_tid(11).unwrap();
        assert!(entry.is_pending(SIGCHLD));
    }
}
