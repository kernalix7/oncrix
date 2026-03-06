// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eventfd event notification subsystem.
//!
//! Provides a file-descriptor-based event notification mechanism
//! compatible with the Linux `eventfd` API. An [`EventFd`] holds
//! an unsigned 64-bit counter that can be written to (incremented)
//! and read from (consumed) by user-space processes.
//!
//! # Modes
//!
//! - **Default**: `read` returns the current counter value and resets
//!   it to zero.
//! - **Semaphore** ([`EFD_SEMAPHORE`]): `read` returns 1 and
//!   decrements the counter by 1, acting as a counting semaphore.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              EventFdRegistry                │
//! │  (up to MAX_EVENTFDS eventfd instances)      │
//! │  ┌────────┐ ┌────────┐       ┌────────┐    │
//! │  │ efd 0  │ │ efd 1  │  ...  │ efd N  │    │
//! │  └────────┘ └────────┘       └────────┘    │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # POSIX Reference
//!
//! While eventfd is a Linux extension (not POSIX), ONCRIX provides
//! it for compatibility with software that uses lightweight
//! inter-thread/inter-process signalling (libuv, systemd, etc.).

use oncrix_lib::{Error, Result};

// ── Flags ──────────────────────────────────────────────────────

/// Semaphore mode: `read` returns 1 and decrements instead of
/// returning the full counter and resetting to 0.
pub const EFD_SEMAPHORE: u32 = 1;

/// Non-blocking mode: operations that would block return
/// `WouldBlock` (`EAGAIN`) instead.
pub const EFD_NONBLOCK: u32 = 0x800;

/// Close-on-exec flag: the file descriptor is automatically
/// closed across `execve`.
pub const EFD_CLOEXEC: u32 = 0x80000;

/// Bitmask of all valid eventfd flags.
const EFD_VALID_FLAGS: u32 = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;

/// Maximum value that can be stored in the counter before
/// overflow. Defined as `u64::MAX - 1` per the Linux ABI.
const EVENTFD_MAX: u64 = u64::MAX - 1;

// ── EventFd ────────────────────────────────────────────────────

/// An eventfd instance holding a 64-bit counter.
///
/// Created via [`EventFd::new`] with an initial value and flags.
/// The counter is incremented by [`write`](EventFd::write) and
/// consumed by [`read`](EventFd::read).
pub struct EventFd {
    /// Current counter value.
    counter: u64,
    /// Creation flags (combination of `EFD_*` constants).
    flags: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl EventFd {
    /// Create a new eventfd with the given initial value and flags.
    ///
    /// The initial value is clamped to [`EVENTFD_MAX`] to prevent
    /// immediate overflow on the first write.
    pub const fn new(initval: u64, flags: u32) -> Self {
        let clamped = if initval > EVENTFD_MAX {
            EVENTFD_MAX
        } else {
            initval
        };
        Self {
            counter: clamped,
            flags,
            in_use: false,
        }
    }

    /// Return the current flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the current counter value (for inspection/polling).
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Whether this eventfd operates in semaphore mode.
    const fn is_semaphore(&self) -> bool {
        self.flags & EFD_SEMAPHORE != 0
    }

    /// Whether this eventfd is in non-blocking mode.
    const fn is_nonblock(&self) -> bool {
        self.flags & EFD_NONBLOCK != 0
    }

    /// Add `val` to the counter.
    ///
    /// The write value must be in `1..=EVENTFD_MAX`. If adding
    /// `val` would overflow past [`EVENTFD_MAX`], the call
    /// returns `Err(WouldBlock)` (the caller should retry or
    /// block).
    ///
    /// A write of 0 is silently ignored (returns `Ok(())`).
    pub fn write(&mut self, val: u64) -> Result<()> {
        if val == 0 {
            return Ok(());
        }
        if val > EVENTFD_MAX {
            return Err(Error::InvalidArgument);
        }
        // Check for overflow using checked arithmetic.
        match self.counter.checked_add(val) {
            Some(new_val) if new_val <= EVENTFD_MAX => {
                self.counter = new_val;
                Ok(())
            }
            _ => Err(Error::WouldBlock),
        }
    }

    /// Consume the counter value.
    ///
    /// - **Default mode**: returns the current counter and resets
    ///   it to 0.
    /// - **Semaphore mode** ([`EFD_SEMAPHORE`]): returns 1 and
    ///   decrements the counter by 1.
    ///
    /// If the counter is 0 and the eventfd is non-blocking,
    /// returns `Err(WouldBlock)`. If the counter is 0 and the
    /// eventfd is blocking, the caller should block until a
    /// write occurs (not handled here — requires scheduler
    /// integration).
    pub fn read(&mut self) -> Result<u64> {
        if self.counter == 0 {
            if self.is_nonblock() {
                return Err(Error::WouldBlock);
            }
            // Blocking mode: caller must block and retry.
            return Err(Error::WouldBlock);
        }

        if self.is_semaphore() {
            self.counter = self.counter.saturating_sub(1);
            Ok(1)
        } else {
            let val = self.counter;
            self.counter = 0;
            Ok(val)
        }
    }
}

// ── EventFdRegistry ────────────────────────────────────────────

/// Maximum number of concurrent eventfd instances system-wide.
const MAX_EVENTFDS: usize = 64;

/// Global registry of eventfd instances.
///
/// Manages the creation, lookup, and destruction of [`EventFd`]
/// objects. Each instance is identified by a numeric ID returned
/// by [`create`](EventFdRegistry::create).
pub struct EventFdRegistry {
    /// Fixed array of eventfd slots.
    fds: [EventFd; MAX_EVENTFDS],
}

impl Default for EventFdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EventFdRegistry {
    /// Create an empty registry with no active eventfds.
    pub const fn new() -> Self {
        Self {
            fds: [const { EventFd::new(0, 0) }; MAX_EVENTFDS],
        }
    }

    /// Allocate a new eventfd instance.
    ///
    /// Returns the instance ID on success, or `Err(OutOfMemory)`
    /// if all slots are occupied. Returns `Err(InvalidArgument)`
    /// if `flags` contains unknown bits.
    pub fn create(&mut self, initval: u64, flags: u32) -> Result<usize> {
        if flags & !EFD_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        for (id, efd) in self.fds.iter_mut().enumerate() {
            if !efd.in_use {
                *efd = EventFd::new(initval, flags);
                efd.in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a shared reference to an eventfd by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get(&self, id: usize) -> Result<&EventFd> {
        let efd = self.fds.get(id).ok_or(Error::InvalidArgument)?;
        if !efd.in_use {
            return Err(Error::NotFound);
        }
        Ok(efd)
    }

    /// Get a mutable reference to an eventfd by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get_mut(&mut self, id: usize) -> Result<&mut EventFd> {
        let efd = self.fds.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !efd.in_use {
            return Err(Error::NotFound);
        }
        Ok(efd)
    }

    /// Destroy an eventfd instance, freeing its slot.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let efd = self.fds.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !efd.in_use {
            return Err(Error::NotFound);
        }
        *efd = EventFd::new(0, 0);
        Ok(())
    }
}
