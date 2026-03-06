// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `signalfd(2)` and `signalfd4(2)` syscall handlers.
//!
//! Accept signals via file descriptor.
//!
//! # Key behaviours
//!
//! - A signalfd fd reads pending signals from a caller-defined signal mask.
//! - `read(2)` returns an array of `SigfdSiginfo` structures, one per pending
//!   signal, of size `sizeof(SigfdSiginfo)` = 128 bytes.
//! - `SFD_NONBLOCK` and `SFD_CLOEXEC` are creation flags.
//! - The signal mask passed at creation/update should be blocked (via
//!   `sigprocmask`) by the caller; signalfd consumes those signals.
//! - Passing `u64::MAX` as `fd` creates a new signalfd; otherwise updates the
//!   mask of an existing one.
//!
//! # References
//!
//! - Linux man pages: `signalfd(2)`, `signalfd4(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Non-blocking I/O.
pub const SFD_NONBLOCK: u32 = 0x0000_0800;
/// Close-on-exec.
pub const SFD_CLOEXEC: u32 = 0x0002_0000;

// ---------------------------------------------------------------------------
// Signal range
// ---------------------------------------------------------------------------

/// Maximum real-time signal number.
pub const SIGRTMAX: u32 = 64;

// ---------------------------------------------------------------------------
// sigset_t (simplified 64-bit bitmask)
// ---------------------------------------------------------------------------

/// 64-bit signal set bitmask (signals 1..64).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sigset {
    /// Bitmask: bit N-1 is set if signal N is in the set.
    pub bits: u64,
}

impl Sigset {
    /// Returns `true` if signal `sig` (1-indexed) is in the set.
    pub fn has(&self, sig: u32) -> bool {
        sig >= 1 && sig <= 64 && self.bits & (1u64 << (sig - 1)) != 0
    }

    /// Add signal `sig`.
    pub fn add(&mut self, sig: u32) {
        if sig >= 1 && sig <= 64 {
            self.bits |= 1u64 << (sig - 1);
        }
    }

    /// Remove signal `sig`.
    pub fn remove(&mut self, sig: u32) {
        if sig >= 1 && sig <= 64 {
            self.bits &= !(1u64 << (sig - 1));
        }
    }
}

// ---------------------------------------------------------------------------
// SigfdSiginfo — 128 bytes
// ---------------------------------------------------------------------------

/// `struct signalfd_siginfo` as read from a signalfd fd.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigfdSiginfo {
    /// Signal number.
    pub ssi_signo: u32,
    /// Error number (si_errno).
    pub ssi_errno: i32,
    /// Signal code (si_code).
    pub ssi_code: i32,
    /// PID of sender.
    pub ssi_pid: u32,
    /// UID of sender.
    pub ssi_uid: u32,
    /// File descriptor (for SIGIO).
    pub ssi_fd: i32,
    /// Timer ID (POSIX timers).
    pub ssi_tid: u32,
    /// Band event (SIGIO).
    pub ssi_band: u32,
    /// POSIX timer overrun count.
    pub ssi_overrun: u32,
    /// Trap number that caused signal.
    pub ssi_trapno: u32,
    /// Exit status or signal (SIGCHLD).
    pub ssi_status: i32,
    /// Integer sent by sigqueue.
    pub ssi_int: i32,
    /// Pointer sent by sigqueue.
    pub ssi_ptr: u64,
    /// User CPU time consumed (SIGCHLD).
    pub ssi_utime: u64,
    /// System CPU time consumed (SIGCHLD).
    pub ssi_stime: u64,
    /// Address that generated fault.
    pub ssi_addr: u64,
    /// Address bound to signal.
    pub ssi_addr_lsb: u16,
    /// Padding to 128 bytes.
    pub _pad: [u8; 46],
}

impl Default for SigfdSiginfo {
    fn default() -> Self {
        // SAFETY: SigfdSiginfo is repr(C) with only integer fields; zeroing is valid.
        unsafe { core::mem::zeroed() }
    }
}

const _: () = assert!(core::mem::size_of::<SigfdSiginfo>() == 128);

// ---------------------------------------------------------------------------
// Signalfd instance
// ---------------------------------------------------------------------------

/// Kernel-side signalfd object.
#[derive(Debug, Clone, Copy)]
pub struct Signalfd {
    /// Signal mask: signals this fd is interested in.
    pub mask: Sigset,
    /// Non-blocking flag.
    pub nonblock: bool,
    /// Pending signal queue (ring, max 64 entries).
    queue: [Option<SigfdSiginfo>; 64],
    /// Write pointer.
    head: usize,
    /// Read pointer.
    tail: usize,
    /// Number of pending entries.
    pending: usize,
}

impl Signalfd {
    /// Create a new signalfd.
    pub fn new(mask: Sigset, flags: u32) -> Self {
        Self {
            mask,
            nonblock: flags & SFD_NONBLOCK != 0,
            queue: [const { None }; 64],
            head: 0,
            tail: 0,
            pending: 0,
        }
    }

    /// Enqueue a signal for delivery if it is in the mask.
    pub fn deliver(&mut self, info: SigfdSiginfo) {
        if !self.mask.has(info.ssi_signo) {
            return;
        }
        if self.pending >= 64 {
            return; // Drop oldest (simplification).
        }
        self.queue[self.head] = Some(info);
        self.head = (self.head + 1) % 64;
        self.pending += 1;
    }

    /// Dequeue one pending signal.
    fn dequeue(&mut self) -> Option<SigfdSiginfo> {
        if self.pending == 0 {
            return None;
        }
        let info = self.queue[self.tail].take();
        self.tail = (self.tail + 1) % 64;
        self.pending -= 1;
        info
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `signalfd(2)` — create a new signalfd.
///
/// # Errors
///
/// | `Error`           | Condition                          |
/// |-------------------|------------------------------------|
/// | `InvalidArgument` | Unknown flags                      |
pub fn do_signalfd_create(mask: Sigset, flags: u32) -> Result<Signalfd> {
    let known = SFD_NONBLOCK | SFD_CLOEXEC;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(Signalfd::new(mask, flags))
}

/// Handler for `signalfd(2)` — update the signal mask of an existing signalfd.
pub fn do_signalfd_update_mask(sfd: &mut Signalfd, mask: Sigset) {
    sfd.mask = mask;
}

/// Handler for signalfd `read(2)`.
///
/// Reads up to `out.len()` pending signals into `out`.
/// Returns the number of `SigfdSiginfo` entries written.
///
/// # Errors
///
/// | `Error`      | Condition                                     |
/// |--------------|-----------------------------------------------|
/// | `WouldBlock` | No pending signals and `SFD_NONBLOCK` set     |
/// | `InvalidArgument` | `out` is empty                           |
pub fn do_signalfd_read(sfd: &mut Signalfd, out: &mut [SigfdSiginfo]) -> Result<usize> {
    if out.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if sfd.pending == 0 {
        return Err(Error::WouldBlock);
    }
    let mut written = 0;
    while written < out.len() {
        match sfd.dequeue() {
            Some(info) => {
                out[written] = info;
                written += 1;
            }
            None => break,
        }
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sigset_with(sig: u32) -> Sigset {
        let mut s = Sigset::default();
        s.add(sig);
        s
    }

    #[test]
    fn create_ok() {
        let sfd = do_signalfd_create(sigset_with(9), 0).unwrap();
        assert!(sfd.mask.has(9));
        assert!(!sfd.nonblock);
    }

    #[test]
    fn create_unknown_flags_fails() {
        assert_eq!(
            do_signalfd_create(Sigset::default(), 0xF000_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn deliver_and_read() {
        let mut sfd = do_signalfd_create(sigset_with(15), 0).unwrap();
        let info = SigfdSiginfo {
            ssi_signo: 15,
            ..Default::default()
        };
        sfd.deliver(info);
        let mut out = [SigfdSiginfo::default(); 4];
        let n = do_signalfd_read(&mut sfd, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].ssi_signo, 15);
    }

    #[test]
    fn deliver_unmasked_signal_ignored() {
        let mut sfd = do_signalfd_create(sigset_with(9), 0).unwrap();
        let info = SigfdSiginfo {
            ssi_signo: 15,
            ..Default::default()
        };
        sfd.deliver(info);
        assert_eq!(sfd.pending, 0);
    }

    #[test]
    fn read_no_pending_wouldblock() {
        let mut sfd = do_signalfd_create(sigset_with(9), SFD_NONBLOCK).unwrap();
        let mut out = [SigfdSiginfo::default(); 4];
        assert_eq!(do_signalfd_read(&mut sfd, &mut out), Err(Error::WouldBlock));
    }

    #[test]
    fn update_mask() {
        let mut sfd = do_signalfd_create(sigset_with(9), 0).unwrap();
        let new_mask = sigset_with(15);
        do_signalfd_update_mask(&mut sfd, new_mask);
        assert!(sfd.mask.has(15));
        assert!(!sfd.mask.has(9));
    }
}
