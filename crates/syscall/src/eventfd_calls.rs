// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `eventfd(2)` / `eventfd2(2)` — event notification file descriptor.
//!
//! An eventfd provides a lightweight inter-process notification mechanism
//! via a 64-bit counter.  A `write` adds to the counter; a `read`
//! returns the counter value and resets it (counter mode) or decrements
//! by one (semaphore mode).
//!
//! # Modes
//!
//! - **Counter** (default): `read` returns the full counter and resets to 0.
//! - **Semaphore** (`EFD_SEMAPHORE`): `read` decrements by 1 and returns 1.
//!
//! # Overflow protection
//!
//! The counter is capped at `u64::MAX - 1` (`0xFFFF_FFFF_FFFF_FFFE`).
//! Writing a value that would overflow returns `WouldBlock` (non-blocking)
//! or blocks (blocking mode). Writing `u64::MAX` is always rejected.
//!
//! # References
//!
//! - Linux: `fs/eventfd.c`
//! - man page: `eventfd(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of eventfd instances.
const MAX_EVENTFDS: usize = 128;

/// Maximum counter value (`u64::MAX - 1`).
///
/// This is `0xFFFF_FFFF_FFFF_FFFE`. Writing beyond this value would
/// overflow, so writes are blocked or return `WouldBlock`.
pub const EVENTFD_MAX_VAL: u64 = u64::MAX - 1;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set close-on-exec on the eventfd.
pub const EFD_CLOEXEC: u32 = 0x80000;

/// Enable non-blocking I/O on the eventfd.
pub const EFD_NONBLOCK: u32 = 0x800;

/// Enable semaphore mode.
///
/// In semaphore mode, each `read` decrements the counter by 1
/// and returns the value 1, rather than reading the entire counter.
pub const EFD_SEMAPHORE: u32 = 1;

/// All valid `eventfd2` flag bits.
const EFD_VALID_FLAGS: u32 = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;

/// Poll flag: data available for reading (counter > 0).
pub const POLLIN: u32 = 0x01;

/// Poll flag: writing will not block (counter < `EVENTFD_MAX_VAL`).
pub const POLLOUT: u32 = 0x04;

// ---------------------------------------------------------------------------
// EventfdMode
// ---------------------------------------------------------------------------

/// Operating mode for an eventfd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventfdMode {
    /// Counter mode: `read` returns and resets the full counter.
    #[default]
    Counter,
    /// Semaphore mode: `read` decrements by 1 and returns 1.
    Semaphore,
}

// ---------------------------------------------------------------------------
// EventfdInstance
// ---------------------------------------------------------------------------

/// A single eventfd instance.
///
/// Holds a 64-bit counter and supports read/write/poll operations.
pub struct EventfdInstance {
    /// Unique identifier.
    id: u64,
    /// The internal counter.
    counter: u64,
    /// Operating mode.
    mode: EventfdMode,
    /// Creation flags.
    flags: u32,
    /// PID of the creating process.
    owner_pid: u64,
    /// Number of tasks blocked waiting to read.
    read_waiters: u32,
    /// Number of tasks blocked waiting to write.
    write_waiters: u32,
    /// Whether this slot is active.
    active: bool,
}

impl EventfdInstance {
    /// Create an inactive eventfd.
    const fn new() -> Self {
        Self {
            id: 0,
            counter: 0,
            mode: EventfdMode::Counter,
            flags: 0,
            owner_pid: 0,
            read_waiters: 0,
            write_waiters: 0,
            active: false,
        }
    }

    /// Return the eventfd ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the current counter value.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Return the operating mode.
    pub const fn mode(&self) -> EventfdMode {
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
    pub const fn read_waiters(&self) -> u32 {
        self.read_waiters
    }

    /// Return the number of blocked writers.
    pub const fn write_waiters(&self) -> u32 {
        self.write_waiters
    }

    /// Return whether this eventfd is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return `true` if this eventfd is in non-blocking mode.
    pub const fn is_nonblock(&self) -> bool {
        self.flags & EFD_NONBLOCK != 0
    }

    /// Return `true` if this eventfd is in semaphore mode.
    pub const fn is_semaphore(&self) -> bool {
        self.flags & EFD_SEMAPHORE != 0
    }
}

// ---------------------------------------------------------------------------
// EventfdRegistry
// ---------------------------------------------------------------------------

/// Registry managing a pool of eventfd instances.
///
/// Each eventfd is identified by a unique `u64` ID.
pub struct EventfdRegistry {
    /// Slot array.
    fds: [EventfdInstance; MAX_EVENTFDS],
    /// Next ID to assign.
    next_id: u64,
    /// Number of active eventfds.
    count: usize,
}

impl EventfdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            fds: [const { EventfdInstance::new() }; MAX_EVENTFDS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active eventfds.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no eventfds are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ---------------------------------------------------------------
    // Lookup helpers
    // ---------------------------------------------------------------

    /// Find an active eventfd by ID (shared reference).
    fn find(&self, id: u64) -> Result<&EventfdInstance> {
        self.fds
            .iter()
            .find(|f| f.active && f.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active eventfd by ID (mutable reference).
    fn find_mut(&mut self, id: u64) -> Result<&mut EventfdInstance> {
        self.fds
            .iter_mut()
            .find(|f| f.active && f.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find a free slot index.
    fn find_free(&self) -> Option<usize> {
        self.fds.iter().position(|f| !f.active)
    }

    // ---------------------------------------------------------------
    // eventfd / eventfd2 create
    // ---------------------------------------------------------------

    /// Create a new eventfd with the given initial counter and flags.
    fn create(&mut self, initval: u64, flags: u32, pid: u64) -> Result<u64> {
        let idx = self.find_free().ok_or(Error::OutOfMemory)?;

        let mode = if flags & EFD_SEMAPHORE != 0 {
            EventfdMode::Semaphore
        } else {
            EventfdMode::Counter
        };

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let slot = &mut self.fds[idx];
        slot.id = id;
        slot.counter = initval;
        slot.mode = mode;
        slot.flags = flags;
        slot.owner_pid = pid;
        slot.read_waiters = 0;
        slot.write_waiters = 0;
        slot.active = true;

        self.count += 1;
        Ok(id)
    }

    // ---------------------------------------------------------------
    // Read
    // ---------------------------------------------------------------

    /// Read from an eventfd.
    ///
    /// In counter mode: returns the full counter and resets to 0.
    /// In semaphore mode: decrements by 1 and returns 1.
    fn read(&mut self, id: u64) -> Result<u64> {
        let fd = self.find_mut(id)?;

        if fd.counter == 0 {
            if fd.flags & EFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would block here.
            return Err(Error::WouldBlock);
        }

        match fd.mode {
            EventfdMode::Counter => {
                let val = fd.counter;
                fd.counter = 0;
                Ok(val)
            }
            EventfdMode::Semaphore => {
                fd.counter -= 1;
                Ok(1)
            }
        }
    }

    // ---------------------------------------------------------------
    // Write
    // ---------------------------------------------------------------

    /// Write a value to an eventfd, adding it to the counter.
    ///
    /// The value `u64::MAX` is always rejected (`InvalidArgument`).
    /// If the addition would overflow `EVENTFD_MAX_VAL`, returns
    /// `WouldBlock`.
    fn write(&mut self, id: u64, val: u64) -> Result<()> {
        if val == u64::MAX {
            return Err(Error::InvalidArgument);
        }

        let fd = self.find_mut(id)?;

        if fd.counter > EVENTFD_MAX_VAL - val {
            if fd.flags & EFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would block here.
            return Err(Error::WouldBlock);
        }

        fd.counter += val;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Poll
    // ---------------------------------------------------------------

    /// Poll an eventfd for readiness.
    ///
    /// Returns a bitmask:
    /// - `POLLIN` (0x01): counter > 0, read will succeed
    /// - `POLLOUT` (0x04): counter < `EVENTFD_MAX_VAL`, write of 1 will succeed
    fn poll(&self, id: u64) -> Result<u32> {
        let fd = self.find(id)?;
        let mut mask = 0u32;
        if fd.counter > 0 {
            mask |= POLLIN;
        }
        if fd.counter < EVENTFD_MAX_VAL {
            mask |= POLLOUT;
        }
        Ok(mask)
    }

    // ---------------------------------------------------------------
    // Close / cleanup
    // ---------------------------------------------------------------

    /// Close an eventfd by ID.
    fn close(&mut self, id: u64) -> Result<()> {
        let fd = self.find_mut(id)?;
        fd.active = false;
        fd.counter = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Close all eventfds owned by the given PID.
    ///
    /// Called during process cleanup.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for slot in self.fds.iter_mut() {
            if slot.active && slot.owner_pid == pid {
                slot.active = false;
                slot.counter = 0;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    // ---------------------------------------------------------------
    // Peek / signal helpers
    // ---------------------------------------------------------------

    /// Peek at the counter without consuming it.
    fn peek(&self, id: u64) -> Result<u64> {
        let fd = self.find(id)?;
        Ok(fd.counter)
    }

    /// Signal an eventfd by writing 1.
    fn signal(&mut self, id: u64) -> Result<()> {
        self.write(id, 1)
    }
}

impl Default for EventfdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `eventfd(2)` — create an eventfd (original interface, no flags).
///
/// Equivalent to `eventfd2(initval, 0)`.
///
/// # Arguments
///
/// * `registry` — The global eventfd registry.
/// * `initval`  — Initial counter value.
/// * `pid`      — Calling process ID.
///
/// # Returns
///
/// The eventfd ID on success.
///
/// # Errors
///
/// * [`Error::OutOfMemory`] — Registry is full.
pub fn sys_eventfd(registry: &mut EventfdRegistry, initval: u64, pid: u64) -> Result<u64> {
    registry.create(initval, 0, pid)
}

/// `eventfd2(2)` — create an eventfd with flags.
///
/// # Arguments
///
/// * `registry` — The global eventfd registry.
/// * `initval`  — Initial counter value.
/// * `flags`    — `EFD_CLOEXEC`, `EFD_NONBLOCK`, `EFD_SEMAPHORE`.
/// * `pid`      — Calling process ID.
///
/// # Returns
///
/// The eventfd ID on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags.
/// * [`Error::OutOfMemory`] — Registry is full.
pub fn sys_eventfd2(
    registry: &mut EventfdRegistry,
    initval: u64,
    flags: u32,
    pid: u64,
) -> Result<u64> {
    if (flags & !EFD_VALID_FLAGS) != 0 {
        return Err(Error::InvalidArgument);
    }
    registry.create(initval, flags, pid)
}

/// Read from an eventfd.
///
/// In counter mode: returns the counter and resets to 0.
/// In semaphore mode: decrements by 1, returns 1.
///
/// # Errors
///
/// * [`Error::WouldBlock`] — Counter is zero and fd is non-blocking.
/// * [`Error::NotFound`] — Invalid eventfd ID.
pub fn sys_eventfd_read(registry: &mut EventfdRegistry, id: u64) -> Result<u64> {
    registry.read(id)
}

/// Write to an eventfd, adding `val` to the counter.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `val` is `u64::MAX`.
/// * [`Error::WouldBlock`] — Addition would overflow.
/// * [`Error::NotFound`] — Invalid eventfd ID.
pub fn sys_eventfd_write(registry: &mut EventfdRegistry, id: u64, val: u64) -> Result<()> {
    registry.write(id, val)
}

/// Poll an eventfd for readiness.
///
/// Returns a bitmask of `POLLIN` and/or `POLLOUT`.
///
/// # Errors
///
/// * [`Error::NotFound`] — Invalid eventfd ID.
pub fn sys_eventfd_poll(registry: &EventfdRegistry, id: u64) -> Result<u32> {
    registry.poll(id)
}

/// Close an eventfd.
///
/// # Errors
///
/// * [`Error::NotFound`] — Invalid eventfd ID.
pub fn sys_eventfd_close(registry: &mut EventfdRegistry, id: u64) -> Result<()> {
    registry.close(id)
}

/// Peek at the counter without consuming it.
///
/// # Errors
///
/// * [`Error::NotFound`] — Invalid eventfd ID.
pub fn sys_eventfd_peek(registry: &EventfdRegistry, id: u64) -> Result<u64> {
    registry.peek(id)
}

/// Signal an eventfd by writing 1.
///
/// Shorthand for `sys_eventfd_write(registry, id, 1)`.
///
/// # Errors
///
/// * [`Error::WouldBlock`] — Counter at maximum.
/// * [`Error::NotFound`] — Invalid eventfd ID.
pub fn sys_eventfd_signal(registry: &mut EventfdRegistry, id: u64) -> Result<()> {
    registry.signal(id)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eventfd_create_counter_mode() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, 0, 1);
        assert!(id.is_ok());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn eventfd2_create_semaphore_mode() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, 5, EFD_SEMAPHORE, 1).unwrap();
        let fd = r.find(id).unwrap();
        assert_eq!(fd.mode(), EventfdMode::Semaphore);
        assert_eq!(fd.counter(), 5);
    }

    #[test]
    fn eventfd2_invalid_flags_rejected() {
        let mut r = EventfdRegistry::new();
        assert_eq!(
            sys_eventfd2(&mut r, 0, 0xDEAD, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn read_counter_mode() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, 0, EFD_NONBLOCK, 1).unwrap();
        let _ = sys_eventfd_write(&mut r, id, 10);
        let _ = sys_eventfd_write(&mut r, id, 5);
        let val = sys_eventfd_read(&mut r, id).unwrap();
        assert_eq!(val, 15);
        // Counter should be zero after read.
        assert_eq!(sys_eventfd_peek(&r, id), Ok(0));
    }

    #[test]
    fn read_semaphore_mode() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, 3, EFD_SEMAPHORE | EFD_NONBLOCK, 1).unwrap();
        assert_eq!(sys_eventfd_read(&mut r, id), Ok(1));
        assert_eq!(sys_eventfd_peek(&r, id), Ok(2));
        assert_eq!(sys_eventfd_read(&mut r, id), Ok(1));
        assert_eq!(sys_eventfd_peek(&r, id), Ok(1));
    }

    #[test]
    fn read_zero_counter_wouldblock() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, 0, EFD_NONBLOCK, 1).unwrap();
        assert_eq!(sys_eventfd_read(&mut r, id), Err(Error::WouldBlock));
    }

    #[test]
    fn write_overflow_prevention() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, EVENTFD_MAX_VAL, EFD_NONBLOCK, 1).unwrap();
        assert_eq!(sys_eventfd_write(&mut r, id, 1), Err(Error::WouldBlock));
    }

    #[test]
    fn write_u64_max_rejected() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, 0, EFD_NONBLOCK, 1).unwrap();
        assert_eq!(
            sys_eventfd_write(&mut r, id, u64::MAX),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn poll_counter_zero() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, 0, 1).unwrap();
        let mask = sys_eventfd_poll(&r, id).unwrap();
        assert_eq!(mask & POLLIN, 0);
        assert_eq!(mask & POLLOUT, POLLOUT);
    }

    #[test]
    fn poll_counter_nonzero() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, 5, 1).unwrap();
        let mask = sys_eventfd_poll(&r, id).unwrap();
        assert_eq!(mask & POLLIN, POLLIN);
        assert_eq!(mask & POLLOUT, POLLOUT);
    }

    #[test]
    fn poll_counter_at_max() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, EVENTFD_MAX_VAL, 1).unwrap();
        let mask = sys_eventfd_poll(&r, id).unwrap();
        assert_eq!(mask & POLLIN, POLLIN);
        assert_eq!(mask & POLLOUT, 0);
    }

    #[test]
    fn signal_increments_by_one() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, 0, 1).unwrap();
        let _ = sys_eventfd_signal(&mut r, id);
        assert_eq!(sys_eventfd_peek(&r, id), Ok(1));
        let _ = sys_eventfd_signal(&mut r, id);
        assert_eq!(sys_eventfd_peek(&r, id), Ok(2));
    }

    #[test]
    fn close_eventfd() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, 0, 1).unwrap();
        assert_eq!(r.count(), 1);
        assert_eq!(sys_eventfd_close(&mut r, id), Ok(()));
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn close_unknown_id_fails() {
        let mut r = EventfdRegistry::new();
        assert_eq!(sys_eventfd_close(&mut r, 999), Err(Error::NotFound));
    }

    #[test]
    fn cleanup_pid_removes_all() {
        let mut r = EventfdRegistry::new();
        let _ = sys_eventfd(&mut r, 0, 42).unwrap();
        let _ = sys_eventfd(&mut r, 0, 42).unwrap();
        let _ = sys_eventfd(&mut r, 0, 99).unwrap();
        assert_eq!(r.count(), 3);
        r.cleanup_pid(42);
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn instance_properties() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd2(&mut r, 7, EFD_NONBLOCK | EFD_CLOEXEC, 100).unwrap();
        let fd = r.find(id).unwrap();
        assert!(fd.is_nonblock());
        assert!(!fd.is_semaphore());
        assert_eq!(fd.owner_pid(), 100);
        assert_eq!(fd.counter(), 7);
        assert!(fd.is_active());
    }

    #[test]
    fn read_after_close_fails() {
        let mut r = EventfdRegistry::new();
        let id = sys_eventfd(&mut r, 5, 1).unwrap();
        let _ = sys_eventfd_close(&mut r, id);
        assert_eq!(sys_eventfd_read(&mut r, id), Err(Error::NotFound));
    }
}
