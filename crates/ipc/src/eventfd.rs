// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC-level eventfd for lightweight cross-process event signaling.
//!
//! Provides a Linux-compatible `eventfd` mechanism that allows
//! user-space processes to signal each other through a simple
//! counter-based file descriptor. Supports both counter mode
//! (default) and semaphore mode.
//!
//! This is a kernel-internal implementation; the syscall layer
//! maps `eventfd` / `eventfd2` onto these primitives.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of IPC eventfds in the registry.
const MAX_IPC_EVENTFDS: usize = 64;

/// Flag: operate in semaphore mode.
pub const EFD_SEMAPHORE: u32 = 1;

/// Flag: enable non-blocking I/O.
pub const EFD_NONBLOCK: u32 = 0x800;

/// Flag: set close-on-exec on the descriptor.
pub const _EFD_CLOEXEC: u32 = 0x80000;

/// Maximum counter value (`u64::MAX - 1`).
const EVENTFD_MAX: u64 = u64::MAX - 1;

/// Poll flag: data is available for reading.
pub const _POLLIN: u32 = 0x01;

/// Poll flag: writing will not block.
pub const _POLLOUT: u32 = 0x04;

// -------------------------------------------------------------------
// EventFdMode
// -------------------------------------------------------------------

/// Operating mode for an eventfd.
///
/// In [`Counter`](EventFdMode::Counter) mode, a read returns the
/// full counter value and resets it to zero. In
/// [`Semaphore`](EventFdMode::Semaphore) mode, a read decrements
/// the counter by one and returns 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventFdMode {
    /// Counter mode (default): read returns and resets the counter.
    #[default]
    Counter,
    /// Semaphore mode: read decrements by 1 and returns 1.
    Semaphore,
}

// -------------------------------------------------------------------
// IpcEventFd
// -------------------------------------------------------------------

/// A single eventfd instance.
///
/// Each eventfd holds a 64-bit counter and supports atomic-style
/// read/write semantics for lightweight cross-process signaling.
pub struct IpcEventFd {
    /// Unique identifier for this eventfd.
    id: u32,
    /// The internal counter value.
    counter: u64,
    /// Operating mode (counter or semaphore).
    mode: EventFdMode,
    /// Flags (e.g. `EFD_NONBLOCK`, `EFD_CLOEXEC`).
    flags: u32,
    /// PID of the process that created this eventfd.
    owner_pid: u64,
    /// Number of tasks blocked waiting to read.
    waiters_read: u32,
    /// Number of tasks blocked waiting to write.
    waiters_write: u32,
    /// Whether this eventfd slot is in use.
    active: bool,
}

impl IpcEventFd {
    /// Create an inactive eventfd with zeroed fields.
    const fn new() -> Self {
        Self {
            id: 0,
            counter: 0,
            mode: EventFdMode::Counter,
            flags: 0,
            owner_pid: 0,
            waiters_read: 0,
            waiters_write: 0,
            active: false,
        }
    }

    /// Return the eventfd identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Return the current counter value.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Return the operating mode.
    pub const fn mode(&self) -> EventFdMode {
        self.mode
    }

    /// Return the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return the number of blocked readers.
    pub const fn waiters_read(&self) -> u32 {
        self.waiters_read
    }

    /// Return the number of blocked writers.
    pub const fn waiters_write(&self) -> u32 {
        self.waiters_write
    }

    /// Return whether this eventfd is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

// -------------------------------------------------------------------
// IpcEventFdRegistry
// -------------------------------------------------------------------

/// Registry managing a fixed pool of eventfd instances.
///
/// Holds up to [`MAX_IPC_EVENTFDS`] eventfds. Each eventfd is
/// identified by a unique `u32` ID assigned at creation time.
pub struct IpcEventFdRegistry {
    /// Slot array for eventfd instances.
    fds: [IpcEventFd; MAX_IPC_EVENTFDS],
    /// Next ID to assign.
    next_id: u32,
    /// Number of active eventfds.
    count: usize,
}

impl IpcEventFdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            fds: [const { IpcEventFd::new() }; MAX_IPC_EVENTFDS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active eventfds.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no eventfds are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Create a new eventfd with the given initial counter value
    /// and flags.
    ///
    /// Returns the assigned eventfd ID on success, or
    /// `OutOfMemory` if the registry is full.
    pub fn create(&mut self, initval: u64, flags: u32, pid: u64) -> Result<u32> {
        let slot_idx = self.find_free().ok_or(Error::OutOfMemory)?;

        let mode = if flags & EFD_SEMAPHORE != 0 {
            EventFdMode::Semaphore
        } else {
            EventFdMode::Counter
        };

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let slot = &mut self.fds[slot_idx];
        slot.id = id;
        slot.counter = initval;
        slot.mode = mode;
        slot.flags = flags;
        slot.owner_pid = pid;
        slot.waiters_read = 0;
        slot.waiters_write = 0;
        slot.active = true;

        self.count += 1;
        Ok(id)
    }

    /// Read from an eventfd.
    ///
    /// In counter mode, returns the full counter value and resets
    /// the counter to zero. In semaphore mode, decrements the
    /// counter by one and returns 1.
    ///
    /// Returns `WouldBlock` if the counter is zero and
    /// `EFD_NONBLOCK` is set.
    pub fn read(&mut self, id: u32) -> Result<u64> {
        let fd = self.find_by_id_mut(id)?;

        if fd.counter == 0 {
            if fd.flags & EFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would block here.
            return Err(Error::WouldBlock);
        }

        match fd.mode {
            EventFdMode::Counter => {
                let val = fd.counter;
                fd.counter = 0;
                Ok(val)
            }
            EventFdMode::Semaphore => {
                fd.counter -= 1;
                Ok(1)
            }
        }
    }

    /// Write a value to an eventfd, adding it to the counter.
    ///
    /// Returns `WouldBlock` if the addition would overflow
    /// [`EVENTFD_MAX`] and `EFD_NONBLOCK` is set.
    /// Returns `InvalidArgument` if `val` is `u64::MAX`.
    pub fn write(&mut self, id: u32, val: u64) -> Result<()> {
        if val == u64::MAX {
            return Err(Error::InvalidArgument);
        }

        let fd = self.find_by_id_mut(id)?;

        if fd.counter > EVENTFD_MAX - val {
            if fd.flags & EFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would block here.
            return Err(Error::WouldBlock);
        }

        fd.counter += val;
        Ok(())
    }

    /// Close (deactivate) an eventfd by ID.
    ///
    /// Returns `NotFound` if the ID does not exist or is already
    /// inactive.
    pub fn close(&mut self, id: u32) -> Result<()> {
        let fd = self.find_by_id_mut(id)?;
        fd.active = false;
        fd.counter = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Poll an eventfd for readiness.
    ///
    /// Returns a bitmask of poll flags:
    /// - `POLLIN` (0x01) if the counter is greater than zero
    /// - `POLLOUT` (0x04) if a write of value 1 would not block
    pub fn poll(&self, id: u32) -> Result<u32> {
        let fd = self.find_by_id(id)?;
        let mut flags = 0u32;

        if fd.counter > 0 {
            flags |= _POLLIN;
        }
        if fd.counter < EVENTFD_MAX {
            flags |= _POLLOUT;
        }

        Ok(flags)
    }

    /// Peek at the counter value without consuming it.
    ///
    /// Returns `NotFound` if the ID does not match an active
    /// eventfd.
    pub fn get_counter(&self, id: u32) -> Result<u64> {
        let fd = self.find_by_id(id)?;
        Ok(fd.counter)
    }

    /// Signal an eventfd by writing 1.
    ///
    /// Shorthand for `write(id, 1)`.
    pub fn signal(&mut self, id: u32) -> Result<()> {
        self.write(id, 1)
    }

    /// Close all eventfds owned by the given PID.
    ///
    /// Used during process cleanup to release resources.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for slot in &mut self.fds {
            if slot.active && slot.owner_pid == pid {
                slot.active = false;
                slot.counter = 0;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    // -- helpers ---------------------------------------------------

    /// Find a free (inactive) slot index.
    fn find_free(&self) -> Option<usize> {
        self.fds.iter().position(|fd| !fd.active)
    }

    /// Find an active eventfd by ID (shared reference).
    fn find_by_id(&self, id: u32) -> Result<&IpcEventFd> {
        self.fds
            .iter()
            .find(|fd| fd.active && fd.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active eventfd by ID (mutable reference).
    fn find_by_id_mut(&mut self, id: u32) -> Result<&mut IpcEventFd> {
        self.fds
            .iter_mut()
            .find(|fd| fd.active && fd.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for IpcEventFdRegistry {
    fn default() -> Self {
        Self::new()
    }
}
