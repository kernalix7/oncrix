// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `signalfd4(2)` syscall handler — create a file descriptor for accepting signals.
//!
//! `signalfd4` creates a file descriptor that can be used to accept signals
//! targeted at the caller.  This provides an alternative to signal handlers
//! and `sigwaitinfo(2)`, allowing signals to be handled synchronously through
//! file descriptor I/O.
//!
//! # POSIX reference
//!
//! Linux-specific: `signalfd(2)` man page.  The `4` suffix indicates the
//! internal kernel version (analogous to `epoll_create1` vs `epoll_create`).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set the close-on-exec (`FD_CLOEXEC`) flag.
pub const SFD_CLOEXEC: i32 = 0o2000000;

/// Set the `O_NONBLOCK` flag.
pub const SFD_NONBLOCK: i32 = 0o0004000;

/// All valid `signalfd4` flags.
const VALID_FLAGS: i32 = SFD_CLOEXEC | SFD_NONBLOCK;

/// Special value for the `fd` argument: create a new signalfd.
pub const SIGNALFD_NEW: i32 = -1;

/// Signal mask width in u64 words.
pub const SIGSET_WORDS: usize = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A signal set (bitmask of signals 1..=64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SigSet {
    /// The raw bitmask.  Bit N-1 corresponds to signal N.
    pub bits: u64,
}

impl SigSet {
    /// Create an empty signal set (no signals blocked).
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Add a signal to the set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `sig` is 0 or > 64.
    pub fn add(&mut self, sig: u8) -> Result<()> {
        if sig == 0 || sig > 64 {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << (sig - 1);
        Ok(())
    }

    /// Check whether a signal is in the set.
    pub fn contains(&self, sig: u8) -> bool {
        if sig == 0 || sig > 64 {
            return false;
        }
        self.bits & (1u64 << (sig - 1)) != 0
    }

    /// Return the number of signals in the set.
    pub fn count(&self) -> u32 {
        self.bits.count_ones()
    }
}

/// Parsed `signalfd4` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Signalfd4Flags {
    /// Whether to set `FD_CLOEXEC`.
    pub cloexec: bool,
    /// Whether to set `O_NONBLOCK`.
    pub nonblock: bool,
}

impl Signalfd4Flags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self {
            cloexec: false,
            nonblock: false,
        }
    }

    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are set.
    pub fn from_raw(flags: i32) -> Result<Self> {
        if flags & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cloexec: flags & SFD_CLOEXEC != 0,
            nonblock: flags & SFD_NONBLOCK != 0,
        })
    }
}

/// Validated `signalfd4` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signalfd4Request {
    /// Existing signalfd (`-1` to create a new one).
    pub fd: i32,
    /// Signal mask to monitor.
    pub mask: SigSet,
    /// Parsed flags.
    pub flags: Signalfd4Flags,
}

impl Signalfd4Request {
    /// Construct a new request.
    pub const fn new(fd: i32, mask: SigSet, flags: Signalfd4Flags) -> Self {
        Self { fd, mask, flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `signalfd4(2)`.
///
/// Validates arguments and returns a parsed request.  If `fd` is `SIGNALFD_NEW`
/// (`-1`), the kernel creates a new signalfd.  Otherwise the existing fd has
/// its signal mask updated.
///
/// The `mask_ptr` and `sizemask` describe the user-space `sigset_t`; this
/// handler validates that the size is correct before the kernel reads the mask.
///
/// # Arguments
///
/// - `fd`       — `-1` to create a new signalfd, or an existing signalfd to modify
/// - `mask`     — signal set to monitor
/// - `sizemask` — `sizeof(sigset_t)` (must equal 8 on 64-bit platforms)
/// - `flags`    — combination of `SFD_CLOEXEC`, `SFD_NONBLOCK`
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | Bad flags, wrong sizemask, fd < -1     |
/// | `NotFound`        | `fd` does not refer to a signalfd      |
pub fn do_signalfd4(
    fd: i32,
    mask: SigSet,
    sizemask: usize,
    flags: i32,
) -> Result<Signalfd4Request> {
    if fd < SIGNALFD_NEW {
        return Err(Error::InvalidArgument);
    }
    // On 64-bit the kernel expects sizeof(sigset_t) == 8.
    if sizemask != 8 {
        return Err(Error::InvalidArgument);
    }
    let parsed_flags = Signalfd4Flags::from_raw(flags)?;
    Ok(Signalfd4Request::new(fd, mask, parsed_flags))
}

/// Return `true` if the `fd` argument requests creation of a new signalfd.
pub fn is_new_fd(fd: i32) -> bool {
    fd == SIGNALFD_NEW
}

/// Validate that a signal number is in the range `[1, 64]`.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` for out-of-range signals.
pub fn validate_signal_number(sig: u8) -> Result<()> {
    if sig == 0 || sig > 64 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mask(sigs: &[u8]) -> SigSet {
        let mut m = SigSet::new();
        for &s in sigs {
            m.add(s).unwrap();
        }
        m
    }

    #[test]
    fn new_fd_ok() {
        let mask = make_mask(&[1, 2, 15]);
        let req = do_signalfd4(SIGNALFD_NEW, mask, 8, 0).unwrap();
        assert!(is_new_fd(req.fd));
        assert!(req.mask.contains(1));
        assert!(req.mask.contains(15));
    }

    #[test]
    fn existing_fd_ok() {
        let mask = make_mask(&[9]);
        let req = do_signalfd4(5, mask, 8, SFD_CLOEXEC).unwrap();
        assert_eq!(req.fd, 5);
        assert!(req.flags.cloexec);
    }

    #[test]
    fn bad_sizemask_rejected() {
        let mask = SigSet::new();
        assert_eq!(
            do_signalfd4(SIGNALFD_NEW, mask, 4, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_flags_rejected() {
        let mask = SigSet::new();
        assert_eq!(
            do_signalfd4(SIGNALFD_NEW, mask, 8, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_fd_rejected() {
        let mask = SigSet::new();
        assert_eq!(do_signalfd4(-2, mask, 8, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn signal_set_operations() {
        let mut m = SigSet::new();
        m.add(1).unwrap();
        m.add(64).unwrap();
        assert!(m.contains(1));
        assert!(m.contains(64));
        assert!(!m.contains(2));
        assert_eq!(m.count(), 2);
    }

    #[test]
    fn invalid_signal_number() {
        let mut m = SigSet::new();
        assert_eq!(m.add(0), Err(Error::InvalidArgument));
        assert_eq!(m.add(65), Err(Error::InvalidArgument));
        assert_eq!(validate_signal_number(0), Err(Error::InvalidArgument));
        assert!(validate_signal_number(15).is_ok());
    }
}
