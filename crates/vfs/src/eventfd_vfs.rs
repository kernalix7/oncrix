// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eventfd VFS integration layer.
//!
//! Provides VFS-level integration for eventfd file descriptors. An eventfd
//! is a file descriptor that maintains a 64-bit counter used for event
//! notification between user-space and kernel, or between processes.
//!
//! eventfd fds are readable when the counter is non-zero and writable
//! when the counter is below `u64::MAX - 1`.

use oncrix_lib::{Error, Result};

/// Maximum value of the eventfd counter before write would block.
pub const EVENTFD_MAX: u64 = u64::MAX - 1;

/// Flags for `eventfd2()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventfdFlags(pub u32);

impl EventfdFlags {
    /// Set the close-on-exec flag.
    pub const EFD_CLOEXEC: u32 = 0o2000000;
    /// Set the non-blocking flag.
    pub const EFD_NONBLOCK: u32 = 0o4000;
    /// Enable semaphore-like semantics.
    pub const EFD_SEMAPHORE: u32 = 1;

    /// Check if close-on-exec is set.
    pub fn is_cloexec(self) -> bool {
        self.0 & Self::EFD_CLOEXEC != 0
    }

    /// Check if non-blocking is set.
    pub fn is_nonblock(self) -> bool {
        self.0 & Self::EFD_NONBLOCK != 0
    }

    /// Check if semaphore mode is set.
    pub fn is_semaphore(self) -> bool {
        self.0 & Self::EFD_SEMAPHORE != 0
    }

    /// Validate that only known flags are set.
    pub fn is_valid(self) -> bool {
        self.0 & !(Self::EFD_CLOEXEC | Self::EFD_NONBLOCK | Self::EFD_SEMAPHORE) == 0
    }
}

/// A single eventfd VFS instance.
#[derive(Debug, Clone, Copy)]
pub struct EventfdVfs {
    /// Inode number.
    pub ino: u64,
    /// Current counter value.
    pub counter: u64,
    /// Semaphore mode.
    pub semaphore: bool,
    /// Non-blocking mode.
    pub nonblock: bool,
    /// Close-on-exec.
    pub cloexec: bool,
}

impl EventfdVfs {
    /// Create a new eventfd instance.
    ///
    /// `initval` is the initial counter value.
    pub const fn new(ino: u64, initval: u64, flags: EventfdFlags) -> Self {
        EventfdVfs {
            ino,
            counter: initval,
            semaphore: flags.0 & EventfdFlags::EFD_SEMAPHORE != 0,
            nonblock: flags.0 & EventfdFlags::EFD_NONBLOCK != 0,
            cloexec: flags.0 & EventfdFlags::EFD_CLOEXEC != 0,
        }
    }

    /// Read the counter value.
    ///
    /// In normal mode: reads and resets the counter.
    /// In semaphore mode: decrements the counter by 1 and returns 1.
    ///
    /// Returns `Err(WouldBlock)` if the counter is zero and non-blocking.
    pub fn read(&mut self) -> Result<u64> {
        if self.counter == 0 {
            return Err(Error::WouldBlock);
        }
        if self.semaphore {
            self.counter -= 1;
            Ok(1)
        } else {
            let val = self.counter;
            self.counter = 0;
            Ok(val)
        }
    }

    /// Write (add) a value to the counter.
    ///
    /// Returns `Err(InvalidArgument)` if the value is `u64::MAX`.
    /// Returns `Err(WouldBlock)` if adding would overflow `EVENTFD_MAX`.
    pub fn write(&mut self, val: u64) -> Result<()> {
        if val == u64::MAX {
            return Err(Error::InvalidArgument);
        }
        if self.counter > EVENTFD_MAX - val {
            return Err(Error::WouldBlock);
        }
        self.counter = self.counter.saturating_add(val);
        Ok(())
    }

    /// Check if the fd is readable (counter > 0).
    pub fn is_readable(&self) -> bool {
        self.counter > 0
    }

    /// Check if the fd is writable (counter < EVENTFD_MAX).
    pub fn is_writable(&self) -> bool {
        self.counter < EVENTFD_MAX
    }

    /// Poll events for this eventfd.
    ///
    /// Returns a bitmask of POLLIN/POLLOUT events.
    pub fn poll_events(&self) -> u32 {
        let mut events = 0u32;
        if self.is_readable() {
            events |= 0x001; // POLLIN
        }
        if self.is_writable() {
            events |= 0x004; // POLLOUT
        }
        events
    }
}

/// Table of eventfd VFS instances.
pub struct EventfdVfsTable {
    instances: [Option<EventfdVfs>; 128],
    count: usize,
}

impl EventfdVfsTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        EventfdVfsTable {
            instances: [const { None }; 128],
            count: 0,
        }
    }

    /// Create a new eventfd instance and return its index.
    pub fn create(&mut self, ino: u64, initval: u64, flags: EventfdFlags) -> Result<usize> {
        if !flags.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if initval > EVENTFD_MAX {
            return Err(Error::InvalidArgument);
        }
        for (i, slot) in self.instances.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(EventfdVfs::new(ino, initval, flags));
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get an immutable reference to an instance.
    pub fn get(&self, idx: usize) -> Result<&EventfdVfs> {
        self.instances
            .get(idx)
            .and_then(|s| s.as_ref())
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to an instance.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut EventfdVfs> {
        self.instances
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)
    }

    /// Close an eventfd instance.
    pub fn close(&mut self, idx: usize) -> Result<()> {
        if idx >= 128 || self.instances[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.instances[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return total count of active instances.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for EventfdVfsTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Signal an eventfd from kernel context (interrupt-safe).
///
/// Adds `val` to the counter without blocking semantics (used from
/// kernel drivers that generate events).
pub fn eventfd_signal(table: &mut EventfdVfsTable, idx: usize, val: u64) -> Result<()> {
    let efd = table.get_mut(idx)?;
    if val == 0 {
        return Ok(());
    }
    // In kernel signal context we saturate rather than return WouldBlock.
    efd.counter = efd.counter.saturating_add(val).min(EVENTFD_MAX);
    Ok(())
}

/// Check if an eventfd would generate a POLLIN event.
pub fn eventfd_poll_in(table: &EventfdVfsTable, idx: usize) -> bool {
    table.get(idx).map(|e| e.is_readable()).unwrap_or(false)
}
