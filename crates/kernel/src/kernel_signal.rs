// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel-internal signal utilities.
//!
//! Provides helper types and functions for generating, queuing, and
//! inspecting signals within the kernel. This module sits between
//! the POSIX signal interface (in `signal_deliver`) and the
//! scheduler / process subsystem.
//!
//! # Signal Representation
//!
//! Signals are represented as entries in a per-task pending queue.
//! Each entry carries the signal number, sender information, and an
//! optional `siginfo_t`-like payload.
//!
//! ```text
//! SignalQueue
//!  ├── pending: [SignalEntry; MAX_PENDING]
//!  ├── blocked_mask: SignalSet
//!  └── nr_pending: u32
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum pending signals per task.
const MAX_PENDING: usize = 64;

/// Total number of signals (1..64 inclusive; 0 is unused).
const NR_SIGNALS: usize = 64;

/// Standard signals range (1..31).
const _SIGRT_MIN: u32 = 32;

// ======================================================================
// Well-known signal numbers
// ======================================================================

/// `SIGKILL` — cannot be caught or ignored.
pub const SIGKILL: u32 = 9;

/// `SIGSTOP` — cannot be caught or ignored.
pub const SIGSTOP: u32 = 19;

/// `SIGCONT` — continue a stopped process.
pub const SIGCONT: u32 = 18;

/// `SIGCHLD` — child process status changed.
pub const _SIGCHLD: u32 = 17;

// ======================================================================
// Types
// ======================================================================

/// A set of signal numbers represented as a bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalSet {
    /// Bitmask: bit N set means signal N is in the set.
    pub bits: u64,
}

impl SignalSet {
    /// Creates an empty signal set.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Creates a full set (all signals present).
    pub const fn full() -> Self {
        Self { bits: u64::MAX }
    }

    /// Adds a signal to the set.
    pub fn add(&mut self, signo: u32) -> Result<()> {
        if signo == 0 || (signo as usize) > NR_SIGNALS {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << (signo - 1);
        Ok(())
    }

    /// Removes a signal from the set.
    pub fn remove(&mut self, signo: u32) -> Result<()> {
        if signo == 0 || (signo as usize) > NR_SIGNALS {
            return Err(Error::InvalidArgument);
        }
        self.bits &= !(1u64 << (signo - 1));
        Ok(())
    }

    /// Tests whether a signal is in the set.
    pub fn contains(&self, signo: u32) -> bool {
        if signo == 0 || (signo as usize) > NR_SIGNALS {
            return false;
        }
        (self.bits & (1u64 << (signo - 1))) != 0
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Returns the intersection of two sets.
    pub fn intersect(&self, other: &SignalSet) -> SignalSet {
        SignalSet {
            bits: self.bits & other.bits,
        }
    }

    /// Returns the complement (signals NOT in this set).
    pub fn complement(&self) -> SignalSet {
        SignalSet { bits: !self.bits }
    }
}

impl Default for SignalSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Origin of a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOrigin {
    /// Sent by a user process via `kill(2)`.
    User,
    /// Sent by the kernel (e.g., SIGSEGV).
    Kernel,
    /// Sent by a timer expiration.
    Timer,
    /// Sent via `sigqueue(2)` with a value.
    SigQueue,
    /// Sent due to async I/O completion.
    AsyncIo,
}

impl Default for SignalOrigin {
    fn default() -> Self {
        Self::Kernel
    }
}

/// A queued signal entry.
#[derive(Debug, Clone, Copy)]
pub struct SignalEntry {
    /// Signal number (1..64).
    pub signo: u32,
    /// PID of the sender.
    pub sender_pid: u64,
    /// Origin of the signal.
    pub origin: SignalOrigin,
    /// Optional integer value (for sigqueue).
    pub si_value: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl SignalEntry {
    /// Creates an empty signal entry.
    pub const fn new() -> Self {
        Self {
            signo: 0,
            sender_pid: 0,
            origin: SignalOrigin::Kernel,
            si_value: 0,
            active: false,
        }
    }
}

impl Default for SignalEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-task signal queue.
pub struct SignalQueue {
    /// Pending signal entries.
    pending: [SignalEntry; MAX_PENDING],
    /// Number of pending signals.
    nr_pending: u32,
    /// Blocked signal mask.
    blocked: SignalSet,
    /// Pending signal set (quick lookup).
    pending_set: SignalSet,
}

impl SignalQueue {
    /// Creates an empty signal queue.
    pub const fn new() -> Self {
        Self {
            pending: [SignalEntry::new(); MAX_PENDING],
            nr_pending: 0,
            blocked: SignalSet::new(),
            pending_set: SignalSet::new(),
        }
    }

    /// Enqueues a signal.
    ///
    /// Standard signals (1-31) are not queued if already pending.
    /// Real-time signals (32-64) are always queued.
    pub fn enqueue(
        &mut self,
        signo: u32,
        sender_pid: u64,
        origin: SignalOrigin,
        si_value: u64,
    ) -> Result<()> {
        if signo == 0 || (signo as usize) > NR_SIGNALS {
            return Err(Error::InvalidArgument);
        }
        // Standard signals: skip if already pending.
        if signo < 32 && self.pending_set.contains(signo) {
            return Ok(());
        }
        if (self.nr_pending as usize) >= MAX_PENDING {
            return Err(Error::OutOfMemory);
        }
        for entry in &mut self.pending {
            if !entry.active {
                *entry = SignalEntry {
                    signo,
                    sender_pid,
                    origin,
                    si_value,
                    active: true,
                };
                self.nr_pending += 1;
                // Ignore the error since we already validated signo.
                let _ = self.pending_set.add(signo);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Dequeues the next deliverable signal.
    ///
    /// Returns the first pending signal that is not blocked.
    /// SIGKILL and SIGSTOP are never blocked.
    pub fn dequeue(&mut self) -> Option<SignalEntry> {
        // SIGKILL/SIGSTOP first (highest priority).
        for priority_sig in [SIGKILL, SIGSTOP] {
            if let Some(idx) = self.find_signal(priority_sig) {
                return Some(self.remove_at(idx));
            }
        }
        // Then any non-blocked signal.
        for i in 0..MAX_PENDING {
            let entry = &self.pending[i];
            if entry.active && !self.blocked.contains(entry.signo) {
                return Some(self.remove_at(i));
            }
        }
        None
    }

    /// Sets the blocked signal mask.
    ///
    /// SIGKILL and SIGSTOP cannot be blocked.
    pub fn set_blocked(&mut self, mut mask: SignalSet) {
        let _ = mask.remove(SIGKILL);
        let _ = mask.remove(SIGSTOP);
        self.blocked = mask;
    }

    /// Returns the current blocked mask.
    pub fn blocked(&self) -> &SignalSet {
        &self.blocked
    }

    /// Returns whether any deliverable signal is pending.
    pub fn has_deliverable(&self) -> bool {
        let deliverable = self.pending_set.intersect(&self.blocked.complement());
        !deliverable.is_empty()
    }

    /// Flushes all pending signals with the given number.
    pub fn flush(&mut self, signo: u32) -> u32 {
        let mut removed = 0u32;
        for entry in &mut self.pending {
            if entry.active && entry.signo == signo {
                entry.active = false;
                self.nr_pending = self.nr_pending.saturating_sub(1);
                removed += 1;
            }
        }
        if removed > 0 {
            let _ = self.pending_set.remove(signo);
        }
        removed
    }

    /// Returns the number of pending signals.
    pub fn nr_pending(&self) -> u32 {
        self.nr_pending
    }

    /// Returns the pending signal set.
    pub fn pending_set(&self) -> &SignalSet {
        &self.pending_set
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_signal(&self, signo: u32) -> Option<usize> {
        self.pending
            .iter()
            .position(|e| e.active && e.signo == signo)
    }

    fn remove_at(&mut self, idx: usize) -> SignalEntry {
        let entry = self.pending[idx];
        self.pending[idx].active = false;
        self.nr_pending = self.nr_pending.saturating_sub(1);

        // Rebuild pending_set bit for this signal.
        let signo = entry.signo;
        let still_pending = self.pending.iter().any(|e| e.active && e.signo == signo);
        if !still_pending {
            let _ = self.pending_set.remove(signo);
        }
        entry
    }
}

impl Default for SignalQueue {
    fn default() -> Self {
        Self::new()
    }
}
