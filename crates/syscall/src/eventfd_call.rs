// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `eventfd(2)` / `eventfd2(2)` syscall handlers.
//!
//! An eventfd provides a lightweight user-kernel / process-process
//! notification mechanism.  It maintains a 64-bit counter; writes add to the
//! counter and reads drain it atomically.  When the counter is non-zero the fd
//! is readable; when it is below `UINT64_MAX - 1` it is writable.
//!
//! `eventfd2` is the Linux extension that allows `EFD_NONBLOCK` and
//! `EFD_CLOEXEC` to be set at creation time.
//!
//! # Linux man page
//!
//! `eventfd(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Create eventfd in non-blocking mode.
pub const EFD_NONBLOCK: u32 = 0x0000_0800;
/// Set close-on-exec on the new fd.
pub const EFD_CLOEXEC: u32 = 0x0002_0000;
/// Semaphore-like semantics: each read decrements the counter by 1.
pub const EFD_SEMAPHORE: u32 = 0x0000_0001;

/// All valid creation flags.
const VALID_FLAGS: u32 = EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum value that can be written to or held in the counter.
pub const EVENTFD_MAX_VAL: u64 = u64::MAX - 1;

// ---------------------------------------------------------------------------
// Eventfd object
// ---------------------------------------------------------------------------

/// Kernel-side eventfd state.
#[derive(Debug, Clone, Copy)]
pub struct Eventfd {
    /// Current counter value.
    pub counter: u64,
    /// Non-blocking I/O mode.
    pub nonblock: bool,
    /// Semaphore mode (read decrements by 1 instead of draining).
    pub semaphore: bool,
    /// Close-on-exec flag (stored for fd-table use).
    pub cloexec: bool,
}

impl Eventfd {
    /// Create a new eventfd with the given initial value and flags.
    pub fn new(initval: u64, flags: u32) -> Self {
        Self {
            counter: initval,
            nonblock: flags & EFD_NONBLOCK != 0,
            semaphore: flags & EFD_SEMAPHORE != 0,
            cloexec: flags & EFD_CLOEXEC != 0,
        }
    }

    /// Returns `true` if the fd is readable (counter > 0).
    pub fn is_readable(&self) -> bool {
        self.counter > 0
    }

    /// Returns `true` if the fd is writable (counter < EVENTFD_MAX_VAL).
    pub fn is_writable(&self) -> bool {
        self.counter < EVENTFD_MAX_VAL
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `eventfd2(2)` / `eventfd(2)`.
///
/// Creates a new eventfd object with the specified initial counter value.
///
/// # Arguments
///
/// - `initval` — initial counter value
/// - `flags`   — combination of `EFD_NONBLOCK`, `EFD_CLOEXEC`, `EFD_SEMAPHORE`
///
/// # Errors
///
/// | `Error`           | Condition                   |
/// |-------------------|-----------------------------|
/// | `InvalidArgument` | Unknown flags or overflow   |
pub fn do_eventfd_create(initval: u64, flags: u32) -> Result<Eventfd> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    if initval > EVENTFD_MAX_VAL {
        return Err(Error::InvalidArgument);
    }
    Ok(Eventfd::new(initval, flags))
}

/// Handler for eventfd `read(2)`.
///
/// In normal mode: returns the current counter and resets it to 0.
/// In semaphore mode: returns 1 and decrements the counter by 1.
///
/// If the counter is 0 and the fd is non-blocking, returns `WouldBlock`.
///
/// # Errors
///
/// | `Error`      | Condition                                  |
/// |--------------|--------------------------------------------|
/// | `WouldBlock` | Counter is 0 and `EFD_NONBLOCK` is set     |
pub fn do_eventfd_read(efd: &mut Eventfd) -> Result<u64> {
    if efd.counter == 0 {
        return Err(Error::WouldBlock);
    }
    if efd.semaphore {
        efd.counter -= 1;
        Ok(1)
    } else {
        let val = efd.counter;
        efd.counter = 0;
        Ok(val)
    }
}

/// Handler for eventfd `write(2)`.
///
/// Adds `val` to the counter.  If the result would exceed `EVENTFD_MAX_VAL`,
/// the call blocks (or returns `WouldBlock` in non-blocking mode).
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | `val` is 0 or `val` is `UINT64_MAX`             |
/// | `WouldBlock`      | Adding would overflow and `EFD_NONBLOCK` is set  |
pub fn do_eventfd_write(efd: &mut Eventfd, val: u64) -> Result<()> {
    if val == 0 || val == u64::MAX {
        return Err(Error::InvalidArgument);
    }
    if efd.counter.saturating_add(val) > EVENTFD_MAX_VAL {
        return Err(Error::WouldBlock);
    }
    efd.counter = efd.counter.saturating_add(val);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ok() {
        let efd = do_eventfd_create(0, 0).unwrap();
        assert_eq!(efd.counter, 0);
        assert!(!efd.nonblock);
        assert!(!efd.semaphore);
    }

    #[test]
    fn create_with_initval() {
        let efd = do_eventfd_create(42, EFD_NONBLOCK).unwrap();
        assert_eq!(efd.counter, 42);
        assert!(efd.nonblock);
    }

    #[test]
    fn create_overflow_rejected() {
        assert_eq!(do_eventfd_create(u64::MAX, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn create_bad_flags() {
        assert_eq!(do_eventfd_create(0, 0xDEAD), Err(Error::InvalidArgument));
    }

    #[test]
    fn read_drains_counter() {
        let mut efd = do_eventfd_create(5, 0).unwrap();
        assert_eq!(do_eventfd_read(&mut efd).unwrap(), 5);
        assert_eq!(efd.counter, 0);
    }

    #[test]
    fn read_empty_wouldblock() {
        let mut efd = do_eventfd_create(0, EFD_NONBLOCK).unwrap();
        assert_eq!(do_eventfd_read(&mut efd), Err(Error::WouldBlock));
    }

    #[test]
    fn semaphore_read_decrements_by_one() {
        let mut efd = do_eventfd_create(3, EFD_SEMAPHORE).unwrap();
        assert_eq!(do_eventfd_read(&mut efd).unwrap(), 1);
        assert_eq!(efd.counter, 2);
    }

    #[test]
    fn write_adds() {
        let mut efd = do_eventfd_create(0, 0).unwrap();
        do_eventfd_write(&mut efd, 10).unwrap();
        assert_eq!(efd.counter, 10);
    }

    #[test]
    fn write_zero_rejected() {
        let mut efd = do_eventfd_create(0, 0).unwrap();
        assert_eq!(do_eventfd_write(&mut efd, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn write_overflow_wouldblock() {
        let mut efd = do_eventfd_create(EVENTFD_MAX_VAL, 0).unwrap();
        assert_eq!(do_eventfd_write(&mut efd, 1), Err(Error::WouldBlock));
    }

    #[test]
    fn readable_writable_states() {
        let mut efd = do_eventfd_create(0, 0).unwrap();
        assert!(!efd.is_readable());
        assert!(efd.is_writable());
        do_eventfd_write(&mut efd, 1).unwrap();
        assert!(efd.is_readable());
    }
}
