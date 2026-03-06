// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX signal handling.
//!
//! Defines signal numbers, signal actions, and per-process signal state.
//! In the ONCRIX microkernel, signals are delivered asynchronously to
//! threads via the scheduler.

use oncrix_lib::{Error, Result};

/// Signal number type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Signal(pub u8);

impl Signal {
    /// Hangup.
    pub const SIGHUP: Self = Self(1);
    /// Interrupt (Ctrl+C).
    pub const SIGINT: Self = Self(2);
    /// Quit (Ctrl+\).
    pub const SIGQUIT: Self = Self(3);
    /// Illegal instruction.
    pub const SIGILL: Self = Self(4);
    /// Abort.
    pub const SIGABRT: Self = Self(6);
    /// Bus error.
    pub const SIGBUS: Self = Self(7);
    /// Floating point exception.
    pub const SIGFPE: Self = Self(8);
    /// Kill (cannot be caught).
    pub const SIGKILL: Self = Self(9);
    /// Segmentation fault.
    pub const SIGSEGV: Self = Self(11);
    /// Broken pipe.
    pub const SIGPIPE: Self = Self(13);
    /// Alarm clock.
    pub const SIGALRM: Self = Self(14);
    /// Termination.
    pub const SIGTERM: Self = Self(15);
    /// Child process status change.
    pub const SIGCHLD: Self = Self(17);
    /// Continue (from stop).
    pub const SIGCONT: Self = Self(18);
    /// Stop (cannot be caught).
    pub const SIGSTOP: Self = Self(19);
    /// Terminal stop (Ctrl+Z).
    pub const SIGTSTP: Self = Self(20);

    /// Maximum signal number.
    pub const MAX: u8 = 32;
}

impl core::fmt::Display for Signal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SIGHUP => write!(f, "SIGHUP"),
            Self::SIGINT => write!(f, "SIGINT"),
            Self::SIGQUIT => write!(f, "SIGQUIT"),
            Self::SIGILL => write!(f, "SIGILL"),
            Self::SIGABRT => write!(f, "SIGABRT"),
            Self::SIGBUS => write!(f, "SIGBUS"),
            Self::SIGFPE => write!(f, "SIGFPE"),
            Self::SIGKILL => write!(f, "SIGKILL"),
            Self::SIGSEGV => write!(f, "SIGSEGV"),
            Self::SIGPIPE => write!(f, "SIGPIPE"),
            Self::SIGALRM => write!(f, "SIGALRM"),
            Self::SIGTERM => write!(f, "SIGTERM"),
            Self::SIGCHLD => write!(f, "SIGCHLD"),
            Self::SIGCONT => write!(f, "SIGCONT"),
            Self::SIGSTOP => write!(f, "SIGSTOP"),
            Self::SIGTSTP => write!(f, "SIGTSTP"),
            _ => write!(f, "SIG({})", self.0),
        }
    }
}

/// Signal disposition (what to do when a signal is delivered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Default action (terminate, ignore, stop, or continue).
    Default,
    /// Ignore the signal.
    Ignore,
    /// Call a user-space handler at the given address.
    Handler(u64),
}

impl core::fmt::Display for SignalAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Default => write!(f, "SIG_DFL"),
            Self::Ignore => write!(f, "SIG_IGN"),
            Self::Handler(addr) => write!(f, "handler({:#x})", addr),
        }
    }
}

/// Signal mask — a bitset of blocked signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SignalMask(u32);

impl SignalMask {
    /// Empty mask (no signals blocked).
    pub const EMPTY: Self = Self(0);

    /// Block a signal.
    pub fn block(&mut self, sig: Signal) {
        if sig.0 > 0 && sig.0 <= Signal::MAX {
            self.0 |= 1 << (sig.0 - 1);
        }
    }

    /// Unblock a signal.
    pub fn unblock(&mut self, sig: Signal) {
        if sig.0 > 0 && sig.0 <= Signal::MAX {
            self.0 &= !(1 << (sig.0 - 1));
        }
    }

    /// Check if a signal is blocked.
    pub fn is_blocked(&self, sig: Signal) -> bool {
        if sig.0 == 0 || sig.0 > Signal::MAX {
            return false;
        }
        self.0 & (1 << (sig.0 - 1)) != 0
    }
}

/// Pending signal set — signals waiting to be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PendingSignals(u32);

impl PendingSignals {
    /// No pending signals.
    pub const EMPTY: Self = Self(0);

    /// Mark a signal as pending.
    pub fn raise(&mut self, sig: Signal) {
        if sig.0 > 0 && sig.0 <= Signal::MAX {
            self.0 |= 1 << (sig.0 - 1);
        }
    }

    /// Clear a pending signal.
    pub fn clear(&mut self, sig: Signal) {
        if sig.0 > 0 && sig.0 <= Signal::MAX {
            self.0 &= !(1 << (sig.0 - 1));
        }
    }

    /// Check if a signal is pending.
    pub fn is_pending(&self, sig: Signal) -> bool {
        if sig.0 == 0 || sig.0 > Signal::MAX {
            return false;
        }
        self.0 & (1 << (sig.0 - 1)) != 0
    }

    /// Return the lowest-numbered pending, unblocked signal.
    pub fn next_deliverable(&self, mask: &SignalMask) -> Option<Signal> {
        let deliverable = self.0 & !mask.0;
        if deliverable == 0 {
            return None;
        }
        let bit = deliverable.trailing_zeros() as u8;
        Some(Signal(bit + 1))
    }

    /// Check if any signals are pending.
    pub fn any(&self) -> bool {
        self.0 != 0
    }
}

/// Per-process signal state.
#[derive(Debug, Clone, Copy)]
pub struct SignalState {
    /// Signal actions (indexed by signal number - 1).
    actions: [SignalAction; Signal::MAX as usize],
    /// Currently blocked signals.
    pub mask: SignalMask,
    /// Pending signals.
    pub pending: PendingSignals,
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    /// Create a new signal state with all defaults.
    pub const fn new() -> Self {
        Self {
            actions: [SignalAction::Default; Signal::MAX as usize],
            mask: SignalMask::EMPTY,
            pending: PendingSignals::EMPTY,
        }
    }

    /// Get the action for a signal.
    pub fn get_action(&self, sig: Signal) -> SignalAction {
        if sig.0 == 0 || sig.0 > Signal::MAX {
            return SignalAction::Default;
        }
        self.actions[(sig.0 - 1) as usize]
    }

    /// Set the action for a signal.
    ///
    /// SIGKILL and SIGSTOP cannot be caught or ignored.
    pub fn set_action(&mut self, sig: Signal, action: SignalAction) -> Result<()> {
        if sig == Signal::SIGKILL || sig == Signal::SIGSTOP {
            return Err(Error::InvalidArgument);
        }
        if sig.0 == 0 || sig.0 > Signal::MAX {
            return Err(Error::InvalidArgument);
        }
        self.actions[(sig.0 - 1) as usize] = action;
        Ok(())
    }

    /// Deliver a signal: mark it pending.
    pub fn send(&mut self, sig: Signal) {
        self.pending.raise(sig);
    }

    /// Dequeue the next deliverable signal.
    pub fn dequeue(&mut self) -> Option<(Signal, SignalAction)> {
        let sig = self.pending.next_deliverable(&self.mask)?;
        self.pending.clear(sig);
        let action = self.get_action(sig);
        Some((sig, action))
    }
}
