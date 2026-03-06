// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `epoll_create(2)`, `epoll_create1(2)`, `epoll_ctl(2)`, and `epoll_wait(2)`
//! syscall handlers.
//!
//! Linux I/O event notification facility.
//!
//! # Key behaviours
//!
//! - `epoll_create1(EPOLL_CLOEXEC)` is the modern API; `epoll_create(size)`
//!   is legacy (size is ignored but must be > 0).
//! - `epoll_ctl` manages the interest list: `EPOLL_CTL_ADD`, `EPOLL_CTL_MOD`,
//!   `EPOLL_CTL_DEL`.
//! - `EPOLLET` (edge-triggered) and `EPOLLONESHOT` are supported flags.
//! - `epoll_wait` blocks until events are ready or timeout expires.
//! - Maximum interest list size is bounded by `EPOLL_MAX_EVENTS`.
//!
//! # References
//!
//! - Linux man pages: `epoll_create(2)`, `epoll_ctl(2)`, `epoll_wait(2)`
//! - Linux man pages: `epoll(7)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Flag for `epoll_create1`: close-on-exec for the epoll file descriptor.
pub const EPOLL_CLOEXEC: u32 = 0x0002_0000;

/// Maximum number of file descriptors in the interest list.
pub const EPOLL_MAX_EVENTS: usize = 1024;

// ---------------------------------------------------------------------------
// epoll_ctl operations
// ---------------------------------------------------------------------------

/// Add a file descriptor to the interest list.
pub const EPOLL_CTL_ADD: u32 = 1;
/// Modify the event mask for a registered file descriptor.
pub const EPOLL_CTL_MOD: u32 = 2;
/// Remove a file descriptor from the interest list.
pub const EPOLL_CTL_DEL: u32 = 3;

// ---------------------------------------------------------------------------
// Event flags (EPOLL* bitmask)
// ---------------------------------------------------------------------------

/// Available for read.
pub const EPOLLIN: u32 = 0x0001;
/// Available for write.
pub const EPOLLOUT: u32 = 0x0004;
/// Error condition.
pub const EPOLLERR: u32 = 0x0008;
/// Hang up (peer closed its end).
pub const EPOLLHUP: u32 = 0x0010;
/// Edge-triggered mode.
pub const EPOLLET: u32 = 0x8000_0000;
/// One-shot: disable after delivery.
pub const EPOLLONESHOT: u32 = 0x4000_0000;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

/// `struct epoll_event` — event descriptor passed to `epoll_ctl`/`epoll_wait`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollEvent {
    /// Event mask (combination of `EPOLLIN`, `EPOLLOUT`, etc.).
    pub events: u32,
    /// User data tag (file descriptor, pointer, or arbitrary u64).
    pub data: u64,
}

/// Entry in the epoll interest list.
#[derive(Debug, Clone, Copy)]
struct InterestEntry {
    /// Watched file descriptor.
    fd: i32,
    /// Event mask including EPOLLET/EPOLLONESHOT flags.
    events: u32,
    /// User data returned on event delivery.
    data: u64,
    /// If `EPOLLONESHOT` was set, this entry is disabled after first delivery.
    disabled: bool,
}

/// Kernel-side epoll instance.
pub struct EpollInstance {
    /// Interest list.
    interest: [Option<InterestEntry>; EPOLL_MAX_EVENTS],
    /// Number of active entries.
    count: usize,
}

impl EpollInstance {
    /// Create a new, empty epoll instance.
    pub fn new() -> Self {
        Self {
            interest: [const { None }; EPOLL_MAX_EVENTS],
            count: 0,
        }
    }

    fn find(&self, fd: i32) -> Option<usize> {
        self.interest[..self.count]
            .iter()
            .position(|e| e.map_or(false, |en| en.fd == fd))
    }
}

impl Default for EpollInstance {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `epoll_create(2)` / `epoll_create1(2)`.
///
/// `size` is the legacy hint (must be > 0 for `epoll_create`).
/// `flags` may contain `EPOLL_CLOEXEC` (ignored at this layer).
///
/// Returns a new `EpollInstance`.
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | `size <= 0` for legacy `epoll_create`  |
pub fn do_epoll_create(size: i32) -> Result<EpollInstance> {
    if size <= 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(EpollInstance::new())
}

/// Handler for `epoll_create1(2)`.
///
/// # Errors
///
/// | `Error`           | Condition              |
/// |-------------------|------------------------|
/// | `InvalidArgument` | Unknown flag bits set  |
pub fn do_epoll_create1(flags: u32) -> Result<EpollInstance> {
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(EpollInstance::new())
}

/// Handler for `epoll_ctl(2)`.
///
/// Adds, modifies, or removes an fd in the interest list.
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | Unknown `op`                           |
/// | `AlreadyExists`   | `EPOLL_CTL_ADD` on already-present fd  |
/// | `NotFound`        | `EPOLL_CTL_MOD`/`DEL` on absent fd     |
/// | `OutOfMemory`     | Interest list is full (ADD)            |
pub fn do_epoll_ctl(
    epoll: &mut EpollInstance,
    op: u32,
    fd: i32,
    event: Option<&EpollEvent>,
) -> Result<()> {
    match op {
        EPOLL_CTL_ADD => {
            let ev = event.ok_or(Error::InvalidArgument)?;
            if epoll.find(fd).is_some() {
                return Err(Error::AlreadyExists);
            }
            if epoll.count >= EPOLL_MAX_EVENTS {
                return Err(Error::OutOfMemory);
            }
            let slot = epoll.count;
            epoll.interest[slot] = Some(InterestEntry {
                fd,
                events: ev.events,
                data: ev.data,
                disabled: false,
            });
            epoll.count += 1;
        }
        EPOLL_CTL_MOD => {
            let ev = event.ok_or(Error::InvalidArgument)?;
            let idx = epoll.find(fd).ok_or(Error::NotFound)?;
            if let Some(ref mut entry) = epoll.interest[idx] {
                entry.events = ev.events;
                entry.data = ev.data;
                entry.disabled = false;
            }
        }
        EPOLL_CTL_DEL => {
            let idx = epoll.find(fd).ok_or(Error::NotFound)?;
            // Swap with last active entry to keep list compact.
            let last = epoll.count - 1;
            epoll.interest.swap(idx, last);
            epoll.interest[last] = None;
            epoll.count -= 1;
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

/// Simulated readiness state for a file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct FdReadiness {
    /// File descriptor.
    pub fd: i32,
    /// Currently ready event flags.
    pub ready_events: u32,
}

/// Handler for `epoll_wait(2)`.
///
/// Scans the interest list against `ready_fds` and fills `out_events` with
/// matching entries.  Returns the number of events written.
///
/// `timeout_ms` < 0 means block indefinitely; here we return `WouldBlock`
/// when no events are ready and `timeout_ms == 0`.
///
/// # Errors
///
/// | `Error`           | Condition                                  |
/// |-------------------|--------------------------------------------|
/// | `InvalidArgument` | `max_events <= 0`                          |
/// | `WouldBlock`      | `timeout_ms == 0` and no events are ready  |
pub fn do_epoll_wait(
    epoll: &mut EpollInstance,
    ready_fds: &[FdReadiness],
    out_events: &mut [EpollEvent],
    timeout_ms: i32,
) -> Result<usize> {
    if out_events.is_empty() {
        return Err(Error::InvalidArgument);
    }

    let mut written = 0usize;

    for i in 0..epoll.count {
        if written >= out_events.len() {
            break;
        }
        let entry = match epoll.interest[i] {
            Some(ref e) if !e.disabled => e,
            _ => continue,
        };
        let mask = entry.events;
        let data = entry.data;
        let fd = entry.fd;
        let et = mask & EPOLLET != 0;
        let oneshot = mask & EPOLLONESHOT != 0;

        // Find readiness for this fd.
        let ready = ready_fds
            .iter()
            .find(|r| r.fd == fd)
            .map(|r| r.ready_events)
            .unwrap_or(0);
        let triggered = ready & (mask & !(EPOLLET | EPOLLONESHOT));
        if triggered == 0 {
            continue;
        }

        // Edge-triggered: only report if transition (caller must track).
        // In this model we always report (caller is responsible for edge logic).
        let _ = et;

        out_events[written] = EpollEvent {
            events: triggered,
            data,
        };
        written += 1;

        if oneshot {
            if let Some(ref mut entry_mut) = epoll.interest[i] {
                entry_mut.disabled = true;
            }
        }
    }

    if written == 0 && timeout_ms == 0 {
        return Err(Error::WouldBlock);
    }

    Ok(written)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ok() {
        let epoll = do_epoll_create(1).unwrap();
        assert_eq!(epoll.count, 0);
    }

    #[test]
    fn create_zero_size_fails() {
        assert_eq!(do_epoll_create(0), Err(Error::InvalidArgument));
    }

    #[test]
    fn create1_unknown_flags_fails() {
        assert_eq!(do_epoll_create1(0x1234), Err(Error::InvalidArgument));
    }

    #[test]
    fn ctl_add_and_del() {
        let mut epoll = do_epoll_create1(0).unwrap();
        let ev = EpollEvent {
            events: EPOLLIN,
            data: 5,
        };
        do_epoll_ctl(&mut epoll, EPOLL_CTL_ADD, 5, Some(&ev)).unwrap();
        assert_eq!(epoll.count, 1);
        do_epoll_ctl(&mut epoll, EPOLL_CTL_DEL, 5, None).unwrap();
        assert_eq!(epoll.count, 0);
    }

    #[test]
    fn ctl_add_duplicate_fails() {
        let mut epoll = do_epoll_create1(0).unwrap();
        let ev = EpollEvent {
            events: EPOLLIN,
            data: 3,
        };
        do_epoll_ctl(&mut epoll, EPOLL_CTL_ADD, 3, Some(&ev)).unwrap();
        assert_eq!(
            do_epoll_ctl(&mut epoll, EPOLL_CTL_ADD, 3, Some(&ev)),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn wait_returns_ready_event() {
        let mut epoll = do_epoll_create1(0).unwrap();
        let ev = EpollEvent {
            events: EPOLLIN,
            data: 42,
        };
        do_epoll_ctl(&mut epoll, EPOLL_CTL_ADD, 7, Some(&ev)).unwrap();

        let ready = [FdReadiness {
            fd: 7,
            ready_events: EPOLLIN,
        }];
        let mut out = [EpollEvent::default(); 8];
        let n = do_epoll_wait(&mut epoll, &ready, &mut out, -1).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].data, 42);
    }

    #[test]
    fn wait_no_events_timeout_zero_wouldblock() {
        let mut epoll = do_epoll_create1(0).unwrap();
        let mut out = [EpollEvent::default(); 8];
        assert_eq!(
            do_epoll_wait(&mut epoll, &[], &mut out, 0),
            Err(Error::WouldBlock)
        );
    }
}
