// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `eventfd(2)` and `eventfd2(2)` syscall handlers.
//!
//! Create a file descriptor for event notification.
//!
//! # Key behaviours
//!
//! - The counter is a 64-bit unsigned integer (initially `initval`).
//! - `read(2)` returns the counter and resets it to 0; blocks (or returns
//!   `EAGAIN` with `EFD_NONBLOCK`) if the counter is 0.
//! - `write(2)` adds the supplied u64 value; blocks (or returns `EAGAIN`)
//!   if adding would overflow `u64::MAX - 1`.
//! - `EFD_SEMAPHORE` changes read semantics: returns 1 and decrements
//!   counter by 1.
//! - `EFD_CLOEXEC` and `EFD_NONBLOCK` are creation flags.
//!
//! # References
//!
//! - Linux man pages: `eventfd(2)`, `eventfd2(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Non-blocking I/O mode.
pub const EFD_NONBLOCK: u32 = 0x0000_0800;
/// Close-on-exec.
pub const EFD_CLOEXEC: u32 = 0x0002_0000;
/// Semaphore semantics: read returns 1 and decrements by 1.
pub const EFD_SEMAPHORE: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// Eventfd instance
// ---------------------------------------------------------------------------

/// Kernel-side eventfd object.
#[derive(Debug, Clone, Copy)]
pub struct Eventfd {
    /// Current counter value.
    pub counter: u64,
    /// EFD_NONBLOCK flag.
    pub nonblock: bool,
    /// EFD_SEMAPHORE flag.
    pub semaphore: bool,
}

impl Eventfd {
    /// Create a new eventfd with initial value `initval` and flags.
    pub fn new(initval: u32, flags: u32) -> Self {
        Self {
            counter: initval as u64,
            nonblock: flags & EFD_NONBLOCK != 0,
            semaphore: flags & EFD_SEMAPHORE != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `eventfd(2)` / `eventfd2(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                          |
/// |-------------------|------------------------------------|
/// | `InvalidArgument` | Unknown flag bits set              |
pub fn do_eventfd(initval: u32, flags: u32) -> Result<Eventfd> {
    let known = EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(Eventfd::new(initval, flags))
}

/// Handler for eventfd `read(2)`.
///
/// Returns the current counter value (or 1 in semaphore mode).
/// Resets counter to 0 (or decrements by 1 in semaphore mode).
///
/// # Errors
///
/// | `Error`      | Condition                                     |
/// |--------------|-----------------------------------------------|
/// | `WouldBlock` | Counter is 0 and `EFD_NONBLOCK` is set        |
pub fn do_eventfd_read(efd: &mut Eventfd) -> Result<u64> {
    if efd.counter == 0 {
        return Err(Error::WouldBlock);
    }
    let val = if efd.semaphore {
        efd.counter -= 1;
        1u64
    } else {
        let v = efd.counter;
        efd.counter = 0;
        v
    };
    Ok(val)
}

/// Handler for eventfd `write(2)`.
///
/// Adds `val` to the counter.  `val` must not be `u64::MAX`.
///
/// # Errors
///
/// | `Error`           | Condition                                     |
/// |-------------------|-----------------------------------------------|
/// | `InvalidArgument` | `val == u64::MAX`                             |
/// | `WouldBlock`      | Adding `val` would overflow `u64::MAX - 1`    |
pub fn do_eventfd_write(efd: &mut Eventfd, val: u64) -> Result<()> {
    if val == u64::MAX {
        return Err(Error::InvalidArgument);
    }
    // Maximum allowed counter value is u64::MAX - 1.
    let max_counter = u64::MAX - 1;
    if efd.counter > max_counter - val {
        return Err(Error::WouldBlock);
    }
    efd.counter += val;
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
        let efd = do_eventfd(5, 0).unwrap();
        assert_eq!(efd.counter, 5);
        assert!(!efd.semaphore);
        assert!(!efd.nonblock);
    }

    #[test]
    fn create_unknown_flags_fails() {
        assert_eq!(do_eventfd(0, 0x1234_0000), Err(Error::InvalidArgument));
    }

    #[test]
    fn read_resets_counter() {
        let mut efd = do_eventfd(10, 0).unwrap();
        assert_eq!(do_eventfd_read(&mut efd).unwrap(), 10);
        assert_eq!(efd.counter, 0);
    }

    #[test]
    fn read_zero_wouldblock() {
        let mut efd = do_eventfd(0, EFD_NONBLOCK).unwrap();
        assert_eq!(do_eventfd_read(&mut efd), Err(Error::WouldBlock));
    }

    #[test]
    fn semaphore_read_decrements_by_one() {
        let mut efd = do_eventfd(3, EFD_SEMAPHORE).unwrap();
        assert_eq!(do_eventfd_read(&mut efd).unwrap(), 1);
        assert_eq!(efd.counter, 2);
    }

    #[test]
    fn write_adds_value() {
        let mut efd = do_eventfd(0, 0).unwrap();
        do_eventfd_write(&mut efd, 7).unwrap();
        assert_eq!(efd.counter, 7);
    }

    #[test]
    fn write_max_val_fails() {
        let mut efd = do_eventfd(0, 0).unwrap();
        assert_eq!(
            do_eventfd_write(&mut efd, u64::MAX),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn write_overflow_wouldblock() {
        let mut efd = do_eventfd(0, 0).unwrap();
        efd.counter = u64::MAX - 2;
        assert_eq!(do_eventfd_write(&mut efd, 2), Err(Error::WouldBlock));
    }
}
