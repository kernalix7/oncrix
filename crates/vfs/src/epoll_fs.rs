// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! epoll file implementation.
//!
//! Implements the epoll(7) interface:
//! - [`EpollFd`] — epoll instance (interest list + ready list)
//! - [`epoll_create`] — create an epoll instance
//! - [`epoll_ctl`] — add/modify/delete monitored file descriptors
//! - [`epoll_wait`] — wait for events (non-blocking simulation)
//! - [`EpollEvent`] — event descriptor (events bitmask + user data)
//! - Event flags: EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, EPOLLET, EPOLLONESHOT
//! - Wakeup callback: simulated readiness notification from fd owners
//!
//! # Design
//!
//! This module simulates an epoll instance without blocking primitives.
//! `epoll_wait` returns all currently ready events rather than sleeping.
//!
//! # References
//! - Linux `fs/eventpoll.c`
//! - POSIX.1-2024 epoll(7) man page

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// EPOLL event flags
// ---------------------------------------------------------------------------

/// File descriptor is readable.
pub const EPOLLIN: u32 = 0x0001;
/// File descriptor is writable.
pub const EPOLLOUT: u32 = 0x0004;
/// Error condition on the fd.
pub const EPOLLERR: u32 = 0x0008;
/// Hang-up on the fd.
pub const EPOLLHUP: u32 = 0x0010;
/// There is urgent data to read.
pub const EPOLLPRI: u32 = 0x0002;
/// Edge-triggered mode.
pub const EPOLLET: u32 = 1 << 31;
/// One-shot: disable after one event.
pub const EPOLLONESHOT: u32 = 1 << 30;
/// Wake-up after event (Linux 3.5+).
pub const EPOLLWAKEUP: u32 = 1 << 29;
/// Exclusive wake-up (Linux 4.5+).
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;

// ---------------------------------------------------------------------------
// EPOLL_CTL operations
// ---------------------------------------------------------------------------

/// Add a file descriptor to the interest list.
pub const EPOLL_CTL_ADD: u32 = 1;
/// Modify an existing interest list entry.
pub const EPOLL_CTL_MOD: u32 = 2;
/// Remove a file descriptor from the interest list.
pub const EPOLL_CTL_DEL: u32 = 3;

/// Maximum epoll instances.
const MAX_EPOLL_FDS: usize = 64;
/// Maximum interest list entries per epoll instance.
const MAX_INTEREST_ENTRIES: usize = 1024;
/// Maximum events returned per epoll_wait call.
const MAX_EVENTS_PER_WAIT: usize = 256;

// ---------------------------------------------------------------------------
// EpollEvent
// ---------------------------------------------------------------------------

/// epoll event descriptor.
#[derive(Debug, Clone, Copy)]
pub struct EpollEvent {
    /// Event flags (EPOLLIN | EPOLLOUT | …).
    pub events: u32,
    /// User data associated with this event.
    pub data: u64,
}

impl EpollEvent {
    /// Create a new event.
    pub fn new(events: u32, data: u64) -> Self {
        Self { events, data }
    }
}

// ---------------------------------------------------------------------------
// InterestEntry — one entry in the interest list
// ---------------------------------------------------------------------------

/// An entry in the epoll interest list.
struct InterestEntry {
    /// Monitored file descriptor number.
    fd: i32,
    /// Requested event flags.
    events: u32,
    /// User data.
    data: u64,
    /// Current readiness (set by simulated wakeup callbacks).
    ready_events: u32,
    /// One-shot: disabled after firing once.
    oneshot_disabled: bool,
    /// Edge-triggered: last delivered state.
    et_last_events: u32,
}

// ---------------------------------------------------------------------------
// EpollFd
// ---------------------------------------------------------------------------

/// Kernel object backing an epoll file descriptor.
pub struct EpollFd {
    /// Unique identifier.
    pub id: u32,
    /// Interest list.
    interest: [Option<InterestEntry>; MAX_INTEREST_ENTRIES],
    interest_count: usize,
}

impl EpollFd {
    fn find_interest(&self, fd: i32) -> Option<usize> {
        for (i, slot) in self.interest[..self.interest_count].iter().enumerate() {
            if let Some(e) = slot {
                if e.fd == fd {
                    return Some(i);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// EpollTable
// ---------------------------------------------------------------------------

/// Registry of epoll instances.
pub struct EpollTable {
    fds: [Option<EpollFd>; MAX_EPOLL_FDS],
    count: usize,
    next_id: u32,
}

impl EpollTable {
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

impl Default for EpollTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// epoll_create
// ---------------------------------------------------------------------------

/// Create a new epoll instance.
///
/// `_flags` is reserved for `EPOLL_CLOEXEC` (ignored here).
/// Returns the epoll instance id.
pub fn epoll_create(table: &mut EpollTable, _flags: u32) -> Result<u32> {
    if table.count >= MAX_EPOLL_FDS {
        return Err(Error::OutOfMemory);
    }
    let id = table.next_id;
    table.next_id += 1;
    table.fds[table.count] = Some(EpollFd {
        id,
        interest: core::array::from_fn(|_| None),
        interest_count: 0,
    });
    table.count += 1;
    Ok(id)
}

// ---------------------------------------------------------------------------
// epoll_ctl
// ---------------------------------------------------------------------------

/// Modify the epoll interest list.
///
/// - `EPOLL_CTL_ADD`: add `fd` with `event`.
/// - `EPOLL_CTL_MOD`: replace the existing entry for `fd`.
/// - `EPOLL_CTL_DEL`: remove `fd` from the interest list.
pub fn epoll_ctl(
    table: &mut EpollTable,
    epoll_id: u32,
    op: u32,
    fd: i32,
    event: Option<EpollEvent>,
) -> Result<()> {
    let idx = table.find(epoll_id).ok_or(Error::NotFound)?;
    let efd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;

    match op {
        EPOLL_CTL_ADD => {
            let ev = event.ok_or(Error::InvalidArgument)?;
            if efd.find_interest(fd).is_some() {
                return Err(Error::AlreadyExists);
            }
            if efd.interest_count >= MAX_INTEREST_ENTRIES {
                return Err(Error::OutOfMemory);
            }
            let oneshot = ev.events & EPOLLONESHOT != 0;
            efd.interest[efd.interest_count] = Some(InterestEntry {
                fd,
                events: ev.events,
                data: ev.data,
                ready_events: 0,
                oneshot_disabled: false,
                et_last_events: 0,
            });
            efd.interest_count += 1;
            let _ = oneshot;
            Ok(())
        }
        EPOLL_CTL_MOD => {
            let ev = event.ok_or(Error::InvalidArgument)?;
            let slot_idx = efd.find_interest(fd).ok_or(Error::NotFound)?;
            if let Some(entry) = efd.interest[slot_idx].as_mut() {
                entry.events = ev.events;
                entry.data = ev.data;
                entry.oneshot_disabled = false;
            }
            Ok(())
        }
        EPOLL_CTL_DEL => {
            let slot_idx = efd.find_interest(fd).ok_or(Error::NotFound)?;
            if slot_idx < efd.interest_count - 1 {
                efd.interest.swap(slot_idx, efd.interest_count - 1);
            }
            efd.interest[efd.interest_count - 1] = None;
            efd.interest_count -= 1;
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// epoll_notify — simulate readiness notification
// ---------------------------------------------------------------------------

/// Notify an epoll instance that `fd` has the given `ready_events`.
///
/// In the kernel this is called from `__wake_up_sync_key` / poll callbacks.
/// Here it directly updates the interest entry's `ready_events` field.
pub fn epoll_notify(
    table: &mut EpollTable,
    epoll_id: u32,
    fd: i32,
    ready_events: u32,
) -> Result<()> {
    let idx = table.find(epoll_id).ok_or(Error::NotFound)?;
    let efd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;
    let slot_idx = efd.find_interest(fd).ok_or(Error::NotFound)?;
    if let Some(entry) = efd.interest[slot_idx].as_mut() {
        entry.ready_events |= ready_events;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// epoll_wait
// ---------------------------------------------------------------------------

/// Wait for events on the epoll instance.
///
/// Returns all currently ready events (non-blocking simulation).
/// `maxevents` caps the number of returned events.
/// Returns `Err(WouldBlock)` if no events are ready.
pub fn epoll_wait(
    table: &mut EpollTable,
    epoll_id: u32,
    maxevents: usize,
) -> Result<Vec<EpollEvent>> {
    if maxevents == 0 || maxevents > MAX_EVENTS_PER_WAIT {
        return Err(Error::InvalidArgument);
    }
    let idx = table.find(epoll_id).ok_or(Error::NotFound)?;
    let efd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;

    let mut events = Vec::new();
    for slot in efd.interest[..efd.interest_count].iter_mut().flatten() {
        if events.len() >= maxevents {
            break;
        }
        if slot.oneshot_disabled {
            continue;
        }
        // Compute effective events.
        let reported = slot.ready_events & slot.events;
        if reported == 0 {
            continue;
        }

        // Edge-triggered: only report if events changed since last delivery.
        if slot.events & EPOLLET != 0 {
            let new_bits = reported & !slot.et_last_events;
            if new_bits == 0 {
                continue;
            }
            slot.et_last_events = reported;
        }

        events.push(EpollEvent {
            events: reported,
            data: slot.data,
        });

        // ONESHOT: disable after delivery.
        if slot.events & EPOLLONESHOT != 0 {
            slot.oneshot_disabled = true;
        } else {
            // Level-triggered: clear ready events.
            slot.ready_events = 0;
        }
    }

    if events.is_empty() {
        Err(Error::WouldBlock)
    } else {
        Ok(events)
    }
}

// ---------------------------------------------------------------------------
// epoll_close
// ---------------------------------------------------------------------------

/// Close an epoll instance.
pub fn epoll_close(table: &mut EpollTable, epoll_id: u32) -> Result<()> {
    let idx = table.find(epoll_id).ok_or(Error::NotFound)?;
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
    fn test_add_notify_wait() {
        let mut table = EpollTable::new();
        let epoll_id = epoll_create(&mut table, 0).unwrap();
        epoll_ctl(
            &mut table,
            epoll_id,
            EPOLL_CTL_ADD,
            5,
            Some(EpollEvent::new(EPOLLIN, 42)),
        )
        .unwrap();
        // No events yet.
        assert!(matches!(
            epoll_wait(&mut table, epoll_id, 16),
            Err(Error::WouldBlock)
        ));
        // Simulate fd 5 becoming readable.
        epoll_notify(&mut table, epoll_id, 5, EPOLLIN).unwrap();
        let events = epoll_wait(&mut table, epoll_id, 16).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, 42);
        assert_ne!(events[0].events & EPOLLIN, 0);
    }

    #[test]
    fn test_del() {
        let mut table = EpollTable::new();
        let epoll_id = epoll_create(&mut table, 0).unwrap();
        epoll_ctl(
            &mut table,
            epoll_id,
            EPOLL_CTL_ADD,
            3,
            Some(EpollEvent::new(EPOLLIN, 1)),
        )
        .unwrap();
        epoll_ctl(&mut table, epoll_id, EPOLL_CTL_DEL, 3, None).unwrap();
        epoll_notify(&mut table, epoll_id, 3, EPOLLIN).ok();
        assert!(matches!(
            epoll_wait(&mut table, epoll_id, 16),
            Err(Error::WouldBlock)
        ));
    }

    #[test]
    fn test_oneshot() {
        let mut table = EpollTable::new();
        let epoll_id = epoll_create(&mut table, 0).unwrap();
        epoll_ctl(
            &mut table,
            epoll_id,
            EPOLL_CTL_ADD,
            7,
            Some(EpollEvent::new(EPOLLIN | EPOLLONESHOT, 99)),
        )
        .unwrap();
        epoll_notify(&mut table, epoll_id, 7, EPOLLIN).unwrap();
        let events = epoll_wait(&mut table, epoll_id, 16).unwrap();
        assert_eq!(events.len(), 1);
        // After one-shot, should not fire again without re-arm.
        assert!(matches!(
            epoll_wait(&mut table, epoll_id, 16),
            Err(Error::WouldBlock)
        ));
    }
}
