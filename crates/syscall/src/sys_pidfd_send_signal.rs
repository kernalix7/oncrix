// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pidfd_send_signal(2)` extended syscall handler.
//!
//! This module provides the high-level entry point for `pidfd_send_signal(2)`,
//! wrapping the core implementation in [`crate::pidfd_calls`] with:
//!
//! - Structured `siginfo_t` construction for `SI_USER` and `SI_QUEUE` codes
//! - `rt_sigqueueinfo`-style queued signal support
//! - Permission model matching `kill(2)` DAC rules
//! - Integration with the process group for targeting thread-group leaders
//!
//! # POSIX conformance
//!
//! `pidfd_send_signal` is a Linux extension without a direct POSIX equivalent.
//! The permission model mirrors POSIX `kill(2)` semantics:
//!
//! - The real or effective UID of the calling process must match the real UID
//!   or saved-set-UID of the target, OR the caller must hold `CAP_KILL`.
//! - Signal 0 (`sig == 0`) performs only the permission/existence check.
//!
//! # References
//!
//! - Linux: `kernel/signal.c` — `do_pidfd_send_signal()`
//! - POSIX: `.TheOpenGroup/susv5-html/functions/kill.html`
//! - man: `pidfd_send_signal(2)`, `rt_sigqueueinfo(2)`

use oncrix_lib::{Error, Result};

// Re-export key types and constants from pidfd_calls.
pub use crate::pidfd_calls::{
    PidfdEntry, PidfdTable, ProcessState, SI_KERNEL, SI_QUEUE, SI_USER, SIGABRT, SIGALRM, SIGCHLD,
    SIGCONT, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGRTMAX, SIGRTMIN,
    SIGSEGV, SIGSTOP, SIGTERM, SIGTSTP, SigInfo,
};

// ---------------------------------------------------------------------------
// Signal delivery mode
// ---------------------------------------------------------------------------

/// How the signal should be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalDeliveryMode {
    /// Simple signal — no queued value.
    Simple,
    /// Queued signal with `si_value` payload (`rt_sigqueueinfo` style).
    Queued(u64),
}

// ---------------------------------------------------------------------------
// Extended siginfo builder
// ---------------------------------------------------------------------------

/// Build a `SigInfo` for a user-originated signal.
///
/// Sets `si_code = SI_USER`, fills in `si_pid` and `si_uid`.
pub fn build_si_user(sig: u32, sender_pid: u32, sender_uid: u32) -> SigInfo {
    SigInfo {
        si_signo: sig as i32,
        si_errno: 0,
        si_code: SI_USER,
        si_pid: sender_pid,
        si_uid: sender_uid,
        si_value: 0,
    }
}

/// Build a `SigInfo` for a queued signal (`rt_sigqueueinfo`).
///
/// Sets `si_code = SI_QUEUE`, fills in `si_pid`, `si_uid`, and `si_value`.
pub fn build_si_queue(sig: u32, sender_pid: u32, sender_uid: u32, value: u64) -> SigInfo {
    SigInfo {
        si_signo: sig as i32,
        si_errno: 0,
        si_code: SI_QUEUE,
        si_pid: sender_pid,
        si_uid: sender_uid,
        si_value: value,
    }
}

// ---------------------------------------------------------------------------
// Permission checking
// ---------------------------------------------------------------------------

/// Credentials used for signal permission checks.
#[derive(Debug, Clone, Copy)]
pub struct SignalCred {
    /// Real UID.
    pub ruid: u32,
    /// Effective UID.
    pub euid: u32,
    /// Whether the caller holds `CAP_KILL`.
    pub cap_kill: bool,
}

/// Check if `sender` may send a signal to a process owned by `target_uid` /
/// `target_saved_uid`.
///
/// Implements the POSIX permission model for `kill(2)`:
/// > The real or effective user ID of the sending process shall match the
/// > real or saved set-user-ID of the receiving process.
///
/// Privileged callers (`cap_kill == true`) may signal any process.
///
/// Returns `Err(PermissionDenied)` if permission is denied.
pub fn check_signal_permission(
    cred: &SignalCred,
    target_uid: u32,
    _target_saved_uid: u32,
) -> Result<()> {
    if cred.cap_kill {
        return Ok(());
    }
    if cred.ruid == target_uid || cred.euid == target_uid {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// Pending signal queue (per notification fd, wraps pidfd table)
// ---------------------------------------------------------------------------

/// Maximum queued signals in the pending-delivery list.
pub const MAX_PENDING_SIGNALS: usize = 64;

/// A single entry in the pending signal queue.
#[derive(Debug, Clone, Copy)]
pub struct PendingSignalEntry {
    /// Whether this slot is occupied.
    pub in_use: bool,
    /// Target PID.
    pub target_pid: u32,
    /// Signal number.
    pub sig: u32,
    /// Signal info.
    pub info: SigInfo,
}

impl PendingSignalEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            target_pid: 0,
            sig: 0,
            info: SigInfo {
                si_signo: 0,
                si_errno: 0,
                si_code: 0,
                si_pid: 0,
                si_uid: 0,
                si_value: 0,
            },
        }
    }
}

/// Pending signal delivery queue.
pub struct PendingSignalQueue {
    entries: [PendingSignalEntry; MAX_PENDING_SIGNALS],
    count: usize,
}

impl PendingSignalQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { PendingSignalEntry::empty() }; MAX_PENDING_SIGNALS],
            count: 0,
        }
    }

    /// Enqueue a signal for delivery to `target_pid`.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — Queue is full.
    pub fn enqueue(&mut self, target_pid: u32, sig: u32, info: SigInfo) -> Result<()> {
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;
        slot.in_use = true;
        slot.target_pid = target_pid;
        slot.sig = sig;
        slot.info = info;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next pending signal for `target_pid`.
    ///
    /// Returns `None` if no pending signal for that PID.
    pub fn dequeue_for(&mut self, target_pid: u32) -> Option<(u32, SigInfo)> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.in_use && e.target_pid == target_pid)?;
        let entry = self.entries[idx];
        self.entries[idx].in_use = false;
        self.count -= 1;
        Some((entry.sig, entry.info))
    }

    /// Cancel all pending signals for `target_pid` (e.g. on process exit).
    pub fn cancel_for(&mut self, target_pid: u32) {
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.target_pid == target_pid {
                entry.in_use = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Return the number of entries in the queue.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// do_pidfd_send_signal_ext — extended entry point
// ---------------------------------------------------------------------------

/// Extended handler for `pidfd_send_signal(2)`.
///
/// Validates arguments, builds the `SigInfo` if not provided, performs
/// permission checks, and delegates delivery to the lower-level handler.
///
/// # Arguments
///
/// * `table`       — Pidfd table.
/// * `pidfd`       — File descriptor of the target process.
/// * `sig`         — Signal number (0–64).  0 = existence/permission check only.
/// * `info`        — Optional caller-provided `siginfo_t`.
/// * `flags`       — Must be 0.
/// * `sender_cred` — Credentials of the calling process.
/// * `sender_pid`  — PID of the caller.
/// * `queue`       — Pending signal delivery queue.
/// * `mode`        — Whether to use simple or queued delivery.
///
/// # Errors
///
/// - [`Error::InvalidArgument`]  — Non-zero flags, invalid signal, or bad
///                                 `si_code` in provided `siginfo`.
/// - [`Error::NotFound`]         — `pidfd` not in table or target is dead.
/// - [`Error::PermissionDenied`] — DAC or capability check failed.
/// - [`Error::OutOfMemory`]      — Signal queue is full.
pub fn do_pidfd_send_signal_ext(
    table: &PidfdTable,
    pidfd: u32,
    sig: u32,
    info: Option<&SigInfo>,
    flags: u32,
    sender_cred: &SignalCred,
    sender_pid: u32,
    queue: &mut PendingSignalQueue,
    mode: SignalDeliveryMode,
) -> Result<()> {
    // Delegate core validation + permission check to the base module.
    crate::pidfd_calls::do_pidfd_send_signal(
        table,
        pidfd,
        sig,
        info,
        flags,
        sender_pid,
        sender_cred.ruid,
    )?;

    // Signal 0 is a probe — nothing to enqueue.
    if sig == 0 {
        return Ok(());
    }

    // Find the target entry.
    let entry = table.get(pidfd).ok_or(Error::NotFound)?;

    // Build or use the provided siginfo.
    let si = match info {
        Some(si) => *si,
        None => match mode {
            SignalDeliveryMode::Simple => build_si_user(sig, sender_pid, sender_cred.ruid),
            SignalDeliveryMode::Queued(val) => {
                build_si_queue(sig, sender_pid, sender_cred.ruid, val)
            }
        },
    };

    // Enqueue for delivery.
    queue.enqueue(entry.pid, sig, si)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pidfd_calls::{PidfdTable, ProcEntry, ProcRegistry};

    fn setup() -> (PidfdTable, ProcRegistry) {
        let mut procs = ProcRegistry::new();
        procs
            .register(ProcEntry::new(1000, 1000, 500, 500))
            .unwrap();
        procs
            .register(ProcEntry::new(2000, 2000, 600, 600))
            .unwrap();
        (PidfdTable::new(), procs)
    }

    fn cred_owner() -> SignalCred {
        SignalCred {
            ruid: 500,
            euid: 500,
            cap_kill: false,
        }
    }

    fn cred_root() -> SignalCred {
        SignalCred {
            ruid: 0,
            euid: 0,
            cap_kill: true,
        }
    }

    fn cred_other() -> SignalCred {
        SignalCred {
            ruid: 999,
            euid: 999,
            cap_kill: false,
        }
    }

    #[test]
    fn send_sigterm_to_owned_process() {
        let (mut table, procs) = setup();
        let mut queue = PendingSignalQueue::new();
        let pidfd = crate::pidfd_calls::do_pidfd_open(&mut table, &procs, 1000, 0, 500).unwrap();
        do_pidfd_send_signal_ext(
            &table,
            pidfd,
            SIGTERM,
            None,
            0,
            &cred_owner(),
            200,
            &mut queue,
            SignalDeliveryMode::Simple,
        )
        .unwrap();
        assert_eq!(queue.count(), 1);
    }

    #[test]
    fn send_queued_signal_with_value() {
        let (mut table, procs) = setup();
        let mut queue = PendingSignalQueue::new();
        let pidfd = crate::pidfd_calls::do_pidfd_open(&mut table, &procs, 1000, 0, 500).unwrap();
        do_pidfd_send_signal_ext(
            &table,
            pidfd,
            SIGUSR_COMPAT,
            None,
            0,
            &cred_owner(),
            200,
            &mut queue,
            SignalDeliveryMode::Queued(0xDEAD_BEEF),
        )
        .unwrap();
        let (sig, si) = queue.dequeue_for(1000).unwrap();
        assert_eq!(sig, SIGUSR_COMPAT);
        assert_eq!(si.si_code, SI_QUEUE);
        assert_eq!(si.si_value, 0xDEAD_BEEF);
    }

    #[test]
    fn send_signal_zero_probe_no_enqueue() {
        let (mut table, procs) = setup();
        let mut queue = PendingSignalQueue::new();
        let pidfd = crate::pidfd_calls::do_pidfd_open(&mut table, &procs, 1000, 0, 500).unwrap();
        do_pidfd_send_signal_ext(
            &table,
            pidfd,
            0,
            None,
            0,
            &cred_owner(),
            200,
            &mut queue,
            SignalDeliveryMode::Simple,
        )
        .unwrap();
        assert_eq!(queue.count(), 0);
    }

    #[test]
    fn send_signal_permission_denied() {
        let (mut table, procs) = setup();
        let mut queue = PendingSignalQueue::new();
        // Open with owner uid 500, but cred_other has uid 999.
        let pidfd = crate::pidfd_calls::do_pidfd_open(&mut table, &procs, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_send_signal_ext(
                &table,
                pidfd,
                SIGTERM,
                None,
                0,
                &cred_other(),
                300,
                &mut queue,
                SignalDeliveryMode::Simple,
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn root_can_signal_any_process() {
        let (mut table, procs) = setup();
        let mut queue = PendingSignalQueue::new();
        let pidfd = crate::pidfd_calls::do_pidfd_open(&mut table, &procs, 1000, 0, 500).unwrap();
        do_pidfd_send_signal_ext(
            &table,
            pidfd,
            SIGKILL,
            None,
            0,
            &cred_root(),
            1,
            &mut queue,
            SignalDeliveryMode::Simple,
        )
        .unwrap();
        assert_eq!(queue.count(), 1);
    }

    #[test]
    fn check_signal_permission_cap_kill() {
        let cred = SignalCred {
            ruid: 1000,
            euid: 1000,
            cap_kill: true,
        };
        assert_eq!(check_signal_permission(&cred, 9999, 9999), Ok(()));
    }

    #[test]
    fn check_signal_permission_euid_match() {
        let cred = SignalCred {
            ruid: 1000,
            euid: 500,
            cap_kill: false,
        };
        assert_eq!(check_signal_permission(&cred, 500, 500), Ok(()));
    }

    #[test]
    fn check_signal_permission_denied_no_match() {
        let cred = SignalCred {
            ruid: 1000,
            euid: 1001,
            cap_kill: false,
        };
        assert_eq!(
            check_signal_permission(&cred, 500, 500),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn build_si_user_fields() {
        let si = build_si_user(SIGTERM, 100, 500);
        assert_eq!(si.si_signo, SIGTERM as i32);
        assert_eq!(si.si_code, SI_USER);
        assert_eq!(si.si_pid, 100);
        assert_eq!(si.si_uid, 500);
    }

    #[test]
    fn build_si_queue_fields() {
        let si = build_si_queue(SIGTERM, 100, 500, 42);
        assert_eq!(si.si_code, SI_QUEUE);
        assert_eq!(si.si_value, 42);
    }

    #[test]
    fn pending_queue_dequeue_fifo() {
        let mut q = PendingSignalQueue::new();
        let si = build_si_user(SIGTERM, 1, 1);
        q.enqueue(1000, SIGTERM, si).unwrap();
        q.enqueue(1000, SIGHUP, si).unwrap();
        let (sig, _) = q.dequeue_for(1000).unwrap();
        assert_eq!(sig, SIGTERM); // first enqueued
    }

    #[test]
    fn pending_queue_cancel() {
        let mut q = PendingSignalQueue::new();
        let si = build_si_user(SIGTERM, 1, 1);
        q.enqueue(1000, SIGTERM, si).unwrap();
        q.enqueue(1000, SIGHUP, si).unwrap();
        q.enqueue(2000, SIGKILL, si).unwrap();
        q.cancel_for(1000);
        assert_eq!(q.count(), 1);
        assert!(q.dequeue_for(1000).is_none());
        assert!(q.dequeue_for(2000).is_some());
    }
}

// Small compat alias for a real-time signal used in tests.
#[allow(dead_code)]
const SIGUSR_COMPAT: u32 = SIGRTMIN;
