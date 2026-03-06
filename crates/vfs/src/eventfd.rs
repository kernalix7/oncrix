// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eventfd file descriptor.
//!
//! Implements the eventfd(2) interface for event notification between kernel
//! and user space, or between processes. An eventfd maintains a 64-bit counter
//! that can be incremented (write) and read/cleared (read).

use oncrix_lib::{Error, Result};

/// eventfd creation flags.
pub const EFD_SEMAPHORE: u32 = 0x0001;
pub const EFD_CLOEXEC: u32 = 0x0002;
pub const EFD_NONBLOCK: u32 = 0x0004;

/// Maximum value of the eventfd counter (u64::MAX - 1).
pub const EFD_COUNTER_MAX: u64 = u64::MAX - 1;

/// An eventfd object.
///
/// The counter starts at the `initval` provided at creation. A read
/// atomically returns the current value and resets it to 0. In semaphore
/// mode, each read decrements by 1 and returns 1.
#[derive(Debug)]
pub struct EventFd {
    /// Current counter value.
    counter: u64,
    /// Creation flags.
    pub flags: u32,
}

impl EventFd {
    /// Create a new eventfd with the given initial value and flags.
    pub fn new(initval: u32, flags: u32) -> Result<Self> {
        Ok(Self {
            counter: initval as u64,
            flags,
        })
    }

    /// Return true if semaphore mode is active.
    pub fn is_semaphore(&self) -> bool {
        self.flags & EFD_SEMAPHORE != 0
    }

    /// Return true if non-blocking mode is active.
    pub fn is_nonblock(&self) -> bool {
        self.flags & EFD_NONBLOCK != 0
    }

    /// Write (add) `value` to the counter.
    ///
    /// Returns `WouldBlock` if the addition would overflow `EFD_COUNTER_MAX`.
    pub fn write(&mut self, value: u64) -> Result<usize> {
        if value == u64::MAX {
            return Err(Error::InvalidArgument);
        }
        let new_val = self
            .counter
            .checked_add(value)
            .ok_or(Error::InvalidArgument)?;
        if new_val > EFD_COUNTER_MAX {
            if self.is_nonblock() {
                return Err(Error::WouldBlock);
            }
            // Blocking mode: caller should sleep and retry.
            return Err(Error::WouldBlock);
        }
        self.counter = new_val;
        Ok(8) // eventfd write always transfers 8 bytes
    }

    /// Read the current counter value.
    ///
    /// In normal mode: returns the counter and resets it to 0.
    /// In semaphore mode: decrements by 1 and returns 1.
    /// Returns `WouldBlock` if the counter is 0.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        if self.counter == 0 {
            if self.is_nonblock() {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
        let val = if self.is_semaphore() {
            self.counter -= 1;
            1u64
        } else {
            let v = self.counter;
            self.counter = 0;
            v
        };
        buf[..8].copy_from_slice(&val.to_ne_bytes());
        Ok(8)
    }

    /// Poll readiness: returns true if a read would not block.
    pub fn poll_readable(&self) -> bool {
        self.counter > 0
    }

    /// Poll writability: returns true if a write of 1 would succeed.
    pub fn poll_writable(&self) -> bool {
        self.counter < EFD_COUNTER_MAX
    }

    /// Return the current counter value without consuming it.
    pub fn peek(&self) -> u64 {
        self.counter
    }

    /// Signal the eventfd with value 1 (common shorthand for notifications).
    pub fn signal(&mut self) -> Result<()> {
        self.write(1)?;
        Ok(())
    }
}

/// eventfd file wrapping the event object with an fd number.
#[derive(Debug)]
pub struct EventFdFile {
    /// The underlying eventfd state.
    pub efd: EventFd,
    /// File descriptor number.
    pub fd: i32,
}

impl EventFdFile {
    /// Create a new eventfd file.
    pub fn new(fd: i32, initval: u32, flags: u32) -> Result<Self> {
        Ok(Self {
            efd: EventFd::new(initval, flags)?,
            fd,
        })
    }

    /// Read 8 bytes from the eventfd.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.efd.read(buf)
    }

    /// Write 8-byte value to the eventfd.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        let val = u64::from_ne_bytes(buf[..8].try_into().map_err(|_| Error::InvalidArgument)?);
        self.efd.write(val)
    }
}
