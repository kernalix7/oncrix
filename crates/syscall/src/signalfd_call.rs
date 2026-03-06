// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `signalfd(2)` / `signalfd4(2)` syscall handlers.
//!
//! `signalfd` creates a file descriptor that can be used to receive signals
//! directed at the calling process.  Signals accepted via signalfd are
//! removed from the normal signal-delivery queue, allowing event-loop
//! programs to handle signals using `read(2)`, `select(2)`, `epoll(2)`, etc.
//!
//! # Linux man page
//!
//! `signalfd(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Create signalfd in non-blocking mode.
pub const SFD_NONBLOCK: u32 = 0x0000_0800;
/// Set close-on-exec on the new fd.
pub const SFD_CLOEXEC: u32 = 0x0002_0000;

/// All valid signalfd4 creation flags.
const VALID_FLAGS: u32 = SFD_NONBLOCK | SFD_CLOEXEC;

// ---------------------------------------------------------------------------
// Signal numbers (subset)
// ---------------------------------------------------------------------------

/// Hangup detected on controlling terminal.
pub const SIGHUP: u32 = 1;
/// Keyboard interrupt.
pub const SIGINT: u32 = 2;
/// Quit from keyboard.
pub const SIGQUIT: u32 = 3;
/// Illegal instruction.
pub const SIGILL: u32 = 4;
/// Abort signal.
pub const SIGABRT: u32 = 6;
/// Floating-point exception.
pub const SIGFPE: u32 = 8;
/// Kill signal (cannot be caught or ignored).
pub const SIGKILL: u32 = 9;
/// User-defined signal 1.
pub const SIGUSR1: u32 = 10;
/// Segmentation fault.
pub const SIGSEGV: u32 = 11;
/// User-defined signal 2.
pub const SIGUSR2: u32 = 12;
/// Broken pipe.
pub const SIGPIPE: u32 = 13;
/// Alarm clock.
pub const SIGALRM: u32 = 14;
/// Termination signal.
pub const SIGTERM: u32 = 15;
/// Child stopped or terminated.
pub const SIGCHLD: u32 = 17;
/// Continue if stopped.
pub const SIGCONT: u32 = 18;
/// Stop process (cannot be caught or ignored).
pub const SIGSTOP: u32 = 19;
/// Stop typed at terminal.
pub const SIGTSTP: u32 = 20;
/// Number of standard signals.
pub const SIGRTMIN: u32 = 32;
/// Maximum real-time signal number.
pub const SIGRTMAX: u32 = 64;

// ---------------------------------------------------------------------------
// Signal mask
// ---------------------------------------------------------------------------

/// 64-bit signal mask (one bit per signal number 1..=64).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sigset(pub u64);

impl Sigset {
    /// Create an empty signal set.
    pub fn empty() -> Self {
        Self(0)
    }

    /// Create a signal set with all bits set.
    pub fn full() -> Self {
        Self(u64::MAX)
    }

    /// Add signal `sig` (1-based) to the set.
    pub fn add(&mut self, sig: u32) {
        if sig >= 1 && sig <= 64 {
            self.0 |= 1u64 << (sig - 1);
        }
    }

    /// Remove signal `sig` from the set.
    pub fn remove(&mut self, sig: u32) {
        if sig >= 1 && sig <= 64 {
            self.0 &= !(1u64 << (sig - 1));
        }
    }

    /// Test whether signal `sig` is in the set.
    pub fn contains(&self, sig: u32) -> bool {
        if sig >= 1 && sig <= 64 {
            self.0 & (1u64 << (sig - 1)) != 0
        } else {
            false
        }
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// Signalfd info structure (matches `struct signalfd_siginfo`)
// ---------------------------------------------------------------------------

/// Signal information delivered through a signalfd read.
///
/// Mirrors `struct signalfd_siginfo` from `<sys/signalfd.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignalfdSiginfo {
    /// Signal number.
    pub ssi_signo: u32,
    /// Error number.
    pub ssi_errno: i32,
    /// Signal code.
    pub ssi_code: i32,
    /// PID of sender.
    pub ssi_pid: u32,
    /// UID of sender.
    pub ssi_uid: u32,
    /// File descriptor (SIGIO).
    pub ssi_fd: i32,
    /// Kernel timer ID (POSIX timers).
    pub ssi_tid: u32,
    /// Band event (SIGIO).
    pub ssi_band: u32,
    /// POSIX timer overrun count.
    pub ssi_overrun: u32,
    /// Trap number that caused signal.
    pub ssi_trapno: u32,
    /// Exit status or signal.
    pub ssi_status: i32,
    /// Integer sent by `sigqueue`.
    pub ssi_int: i32,
    /// Pointer sent by `sigqueue`.
    pub ssi_ptr: u64,
    /// User CPU time consumed.
    pub ssi_utime: u64,
    /// System CPU time consumed.
    pub ssi_stime: u64,
    /// Address that generated signal.
    pub ssi_addr: u64,
    /// Padding to 128 bytes.
    pub _pad: [u8; 48],
}

impl Default for SignalfdSiginfo {
    fn default() -> Self {
        // SAFETY: SignalfdSiginfo is repr(C) with only integer fields; zero-init is valid.
        unsafe { core::mem::zeroed() }
    }
}

impl SignalfdSiginfo {
    /// Create a minimal siginfo for the given signal.
    pub fn new(signo: u32, pid: u32, uid: u32) -> Self {
        Self {
            ssi_signo: signo,
            ssi_pid: pid,
            ssi_uid: uid,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Signalfd object
// ---------------------------------------------------------------------------

/// Kernel-side signalfd state.
#[derive(Debug, Clone, Copy)]
pub struct Signalfd {
    /// Set of signals this fd watches.
    pub mask: Sigset,
    /// Non-blocking read mode.
    pub nonblock: bool,
    /// Close-on-exec.
    pub cloexec: bool,
}

impl Signalfd {
    /// Create a new signalfd.
    pub fn new(mask: Sigset, flags: u32) -> Self {
        Self {
            mask,
            nonblock: flags & SFD_NONBLOCK != 0,
            cloexec: flags & SFD_CLOEXEC != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate signalfd creation flags.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` for unknown flags.
pub fn validate_signalfd_flags(flags: u32) -> Result<()> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that the signal mask does not include `SIGKILL` or `SIGSTOP`.
///
/// Those signals cannot be caught or blocked.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if the mask contains uncatchable signals.
pub fn validate_signalfd_mask(mask: &Sigset) -> Result<()> {
    if mask.contains(SIGKILL) || mask.contains(SIGSTOP) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `signalfd4(2)` / `signalfd(2)`.
///
/// Creates or updates a signalfd.  If `fd` is -1 a new fd is created;
/// otherwise the mask of the existing signalfd `fd` is replaced.
///
/// # Arguments
///
/// - `fd`    — existing signalfd to update, or -1 to create a new one
/// - `mask`  — set of signals to watch
/// - `flags` — combination of `SFD_NONBLOCK`, `SFD_CLOEXEC`
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | Unknown flags, mask contains SIGKILL/SIGSTOP   |
pub fn do_signalfd_create(fd: i32, mask: Sigset, flags: u32) -> Result<Signalfd> {
    validate_signalfd_flags(flags)?;
    validate_signalfd_mask(&mask)?;
    if fd != -1 && fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(Signalfd::new(mask, flags))
}

/// Handler for signalfd `read(2)`.
///
/// Fills `out` with one `SignalfdSiginfo` for the first pending signal that
/// is in the fd's mask.  Returns `WouldBlock` if no masked signal is pending.
///
/// In the real kernel implementation `pending` is the process's pending signal
/// set; here we accept it as a `Sigset` parameter.
///
/// # Errors
///
/// | `Error`      | Condition                                    |
/// |--------------|----------------------------------------------|
/// | `WouldBlock` | No pending signal in mask (nonblock mode)    |
pub fn do_signalfd_read(sfd: &Signalfd, pending: &Sigset) -> Result<SignalfdSiginfo> {
    for sig in 1u32..=64 {
        if sfd.mask.contains(sig) && pending.contains(sig) {
            return Ok(SignalfdSiginfo::new(sig, 0, 0));
        }
    }
    Err(Error::WouldBlock)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_ok() {
        let mut mask = Sigset::empty();
        mask.add(SIGTERM);
        mask.add(SIGINT);
        let sfd = do_signalfd_create(-1, mask, SFD_NONBLOCK).unwrap();
        assert!(sfd.mask.contains(SIGTERM));
        assert!(sfd.nonblock);
    }

    #[test]
    fn create_with_sigkill_rejected() {
        let mut mask = Sigset::empty();
        mask.add(SIGKILL);
        assert_eq!(do_signalfd_create(-1, mask, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn create_bad_flags() {
        let mask = Sigset::empty();
        assert_eq!(
            do_signalfd_create(-1, mask, 0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn read_pending_signal() {
        let mut mask = Sigset::empty();
        mask.add(SIGTERM);
        let sfd = do_signalfd_create(-1, mask, 0).unwrap();
        let mut pending = Sigset::empty();
        pending.add(SIGTERM);
        let info = do_signalfd_read(&sfd, &pending).unwrap();
        assert_eq!(info.ssi_signo, SIGTERM);
    }

    #[test]
    fn read_no_pending_wouldblock() {
        let mut mask = Sigset::empty();
        mask.add(SIGTERM);
        let sfd = do_signalfd_create(-1, mask, SFD_NONBLOCK).unwrap();
        let pending = Sigset::empty();
        assert_eq!(do_signalfd_read(&sfd, &pending), Err(Error::WouldBlock));
    }

    #[test]
    fn sigset_contains() {
        let mut s = Sigset::empty();
        s.add(15);
        assert!(s.contains(15));
        s.remove(15);
        assert!(!s.contains(15));
    }

    #[test]
    fn sigset_out_of_range() {
        let mut s = Sigset::empty();
        s.add(0); // invalid
        s.add(65); // invalid
        assert!(!s.contains(0));
        assert!(!s.contains(65));
        assert!(s.is_empty());
    }
}
