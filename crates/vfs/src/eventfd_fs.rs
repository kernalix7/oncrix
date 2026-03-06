// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eventfd file implementation.
//!
//! Implements the eventfd(2) interface:
//! - [`Eventfd`] — kernel object holding a u64 counter and flags
//! - [`eventfd_create`] — allocate a new eventfd with initial count
//! - [`eventfd_read`] — atomically read (and clear) the counter
//! - [`eventfd_write`] — add a value to the counter
//! - [`eventfd_poll`] — check readability/writability
//! - `EFD_SEMAPHORE` mode: read returns 1 and decrements by 1
//! - `EFD_NONBLOCK`: read/write return `Err(WouldBlock)` instead of blocking
//! - `EFD_CLOEXEC`: close-on-exec flag (tracked in descriptor table)
//! - Overflow check: counter saturates at `u64::MAX - 1`
//!
//! # References
//! - Linux `fs/eventfd.c`
//! - POSIX.1-2024 eventfd(2) man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// EFD flags
// ---------------------------------------------------------------------------

/// Semaphore semantics: read always returns 1 and decrements by 1.
pub const EFD_SEMAPHORE: u32 = 1 << 0;
/// Non-blocking I/O.
pub const EFD_NONBLOCK: u32 = 1 << 11;
/// Close-on-exec (stored in file descriptor flags, not the eventfd itself).
pub const EFD_CLOEXEC: u32 = 1 << 19;

/// Maximum eventfd counter value.
pub const EFD_MAX_CNT: u64 = u64::MAX - 1;

/// Maximum eventfd objects.
const MAX_EVENTFDS: usize = 256;

// ---------------------------------------------------------------------------
// Poll readiness bits
// ---------------------------------------------------------------------------

/// Poll mask: readable.
pub const POLL_IN: u32 = 0x0001;
/// Poll mask: writable.
pub const POLL_OUT: u32 = 0x0004;
/// Poll mask: error.
pub const POLL_ERR: u32 = 0x0008;

// ---------------------------------------------------------------------------
// Eventfd
// ---------------------------------------------------------------------------

/// Kernel object backing an eventfd file descriptor.
#[derive(Debug)]
pub struct Eventfd {
    /// The current counter value.
    pub count: u64,
    /// Creation flags (`EFD_SEMAPHORE`, `EFD_NONBLOCK`, `EFD_CLOEXEC`).
    pub flags: u32,
    /// Unique identifier (file-description index in this implementation).
    pub id: u32,
}

impl Eventfd {
    /// Return true if semaphore semantics are enabled.
    pub fn is_semaphore(&self) -> bool {
        self.flags & EFD_SEMAPHORE != 0
    }

    /// Return true if non-blocking mode is enabled.
    pub fn is_nonblock(&self) -> bool {
        self.flags & EFD_NONBLOCK != 0
    }
}

// ---------------------------------------------------------------------------
// EventfdTable — registry of all eventfd objects
// ---------------------------------------------------------------------------

/// Registry of eventfd objects (simulates the kernel's file-description table).
pub struct EventfdTable {
    fds: [Option<Eventfd>; MAX_EVENTFDS],
    count: usize,
    next_id: u32,
}

impl EventfdTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            fds: core::array::from_fn(|_| None),
            count: 0,
            next_id: 1,
        }
    }

    fn find(&self, id: u32) -> Option<usize> {
        for (i, slot) in self.fds[..self.count].iter().enumerate() {
            if let Some(fd) = slot {
                if fd.id == id {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for EventfdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// eventfd_create
// ---------------------------------------------------------------------------

/// Create a new eventfd with initial counter `initval` and the given `flags`.
///
/// Returns the eventfd id (analogous to a file descriptor number).
pub fn eventfd_create(table: &mut EventfdTable, initval: u64, flags: u32) -> Result<u32> {
    if initval > EFD_MAX_CNT {
        return Err(Error::InvalidArgument);
    }
    if table.count >= MAX_EVENTFDS {
        return Err(Error::OutOfMemory);
    }
    let id = table.next_id;
    table.next_id += 1;
    table.fds[table.count] = Some(Eventfd {
        count: initval,
        flags,
        id,
    });
    table.count += 1;
    Ok(id)
}

// ---------------------------------------------------------------------------
// eventfd_read
// ---------------------------------------------------------------------------

/// Read from an eventfd.
///
/// In normal mode: returns the current counter and resets it to 0.
/// In `EFD_SEMAPHORE` mode: returns 1 and decrements the counter by 1.
/// If the counter is 0:
///   - `EFD_NONBLOCK`: returns `Err(WouldBlock)`
///   - otherwise would block (not modelled here; returns `Err(WouldBlock)`)
pub fn eventfd_read(table: &mut EventfdTable, id: u32) -> Result<u64> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;

    if fd.count == 0 {
        return Err(Error::WouldBlock);
    }

    if fd.is_semaphore() {
        fd.count -= 1;
        Ok(1)
    } else {
        let val = fd.count;
        fd.count = 0;
        Ok(val)
    }
}

// ---------------------------------------------------------------------------
// eventfd_write
// ---------------------------------------------------------------------------

/// Write to an eventfd (add `val` to the counter).
///
/// Returns `Err(InvalidArgument)` if `val == u64::MAX`.
/// Returns `Err(WouldBlock)` if the addition would overflow `EFD_MAX_CNT`.
pub fn eventfd_write(table: &mut EventfdTable, id: u32, val: u64) -> Result<()> {
    if val == u64::MAX {
        return Err(Error::InvalidArgument);
    }
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;

    // Check for overflow.
    if EFD_MAX_CNT - fd.count < val {
        if fd.is_nonblock() {
            return Err(Error::WouldBlock);
        }
        return Err(Error::WouldBlock); // would block without nonblock
    }

    fd.count += val;
    Ok(())
}

// ---------------------------------------------------------------------------
// eventfd_poll
// ---------------------------------------------------------------------------

/// Check the poll readiness of an eventfd.
///
/// Returns a bitmask of `POLL_IN` / `POLL_OUT`:
/// - `POLL_IN`: counter > 0 (readable)
/// - `POLL_OUT`: counter < `EFD_MAX_CNT` (writable)
pub fn eventfd_poll(table: &EventfdTable, id: u32) -> Result<u32> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_ref().ok_or(Error::NotFound)?;

    let mut mask = 0u32;
    if fd.count > 0 {
        mask |= POLL_IN;
    }
    if fd.count < EFD_MAX_CNT {
        mask |= POLL_OUT;
    }
    Ok(mask)
}

// ---------------------------------------------------------------------------
// eventfd_close
// ---------------------------------------------------------------------------

/// Close an eventfd, removing it from the table.
pub fn eventfd_close(table: &mut EventfdTable, id: u32) -> Result<()> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    if idx < table.count - 1 {
        table.fds.swap(idx, table.count - 1);
    }
    table.fds[table.count - 1] = None;
    table.count -= 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_read_write() {
        let mut table = EventfdTable::new();
        let id = eventfd_create(&mut table, 0, 0).unwrap();
        eventfd_write(&mut table, id, 5).unwrap();
        let val = eventfd_read(&mut table, id).unwrap();
        assert_eq!(val, 5);
        // Counter is now 0; reading again should return WouldBlock.
        assert!(matches!(
            eventfd_read(&mut table, id),
            Err(Error::WouldBlock)
        ));
    }

    #[test]
    fn test_semaphore_mode() {
        let mut table = EventfdTable::new();
        let id = eventfd_create(&mut table, 3, EFD_SEMAPHORE).unwrap();
        assert_eq!(eventfd_read(&mut table, id).unwrap(), 1);
        assert_eq!(eventfd_read(&mut table, id).unwrap(), 1);
        assert_eq!(eventfd_read(&mut table, id).unwrap(), 1);
        assert!(matches!(
            eventfd_read(&mut table, id),
            Err(Error::WouldBlock)
        ));
    }

    #[test]
    fn test_poll() {
        let mut table = EventfdTable::new();
        let id = eventfd_create(&mut table, 0, 0).unwrap();
        let mask = eventfd_poll(&table, id).unwrap();
        assert_eq!(mask & POLL_IN, 0);
        assert_ne!(mask & POLL_OUT, 0);
        eventfd_write(&mut table, id, 1).unwrap();
        let mask2 = eventfd_poll(&table, id).unwrap();
        assert_ne!(mask2 & POLL_IN, 0);
    }

    #[test]
    fn test_overflow() {
        let mut table = EventfdTable::new();
        let id = eventfd_create(&mut table, EFD_MAX_CNT, EFD_NONBLOCK).unwrap();
        assert!(matches!(
            eventfd_write(&mut table, id, 1),
            Err(Error::WouldBlock)
        ));
    }
}
