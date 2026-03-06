// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! epoll I/O event notification subsystem.
//!
//! Provides a scalable I/O event notification mechanism compatible
//! with the Linux epoll API. An [`EpollInstance`] watches a set of
//! file descriptors for readiness events and reports them to
//! user space via [`EpollRegistry::epoll_wait`].
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │               EpollRegistry                 │
//! │  (up to 64 epoll instances)                 │
//! │  ┌────────┐ ┌────────┐       ┌────────┐    │
//! │  │ inst 0 │ │ inst 1 │  ...  │ inst N │    │
//! │  └────────┘ └────────┘       └────────┘    │
//! └─────────────────────────────────────────────┘
//!          │
//!          ▼
//! ┌─────────────────────────────────────────────┐
//! │             EpollInstance                    │
//! │  interests: up to 128 watched fds           │
//! │  ready_list: up to 64 ready events          │
//! │  ┌──────────────┐  ┌──────────────┐         │
//! │  │ EpollInterest│  │ EpollInterest│  ...    │
//! │  │ fd=3         │  │ fd=7         │         │
//! │  │ events=IN    │  │ events=OUT   │         │
//! │  │ triggered=no │  │ triggered=yes│         │
//! │  └──────────────┘  └──────────────┘         │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # POSIX Reference
//!
//! While epoll is a Linux extension (not POSIX), ONCRIX provides
//! it for compatibility with the vast ecosystem of software that
//! depends on it (libuv, tokio, nginx, etc.).

use oncrix_lib::{Error, Result};

// ── Event flags (EpollFlags) ─────────────────────────────────

/// File descriptor is ready for reading.
pub const EPOLLIN: u32 = 0x001;

/// File descriptor is ready for writing.
pub const EPOLLOUT: u32 = 0x004;

/// Error condition on the file descriptor.
pub const EPOLLERR: u32 = 0x008;

/// Hang up on the file descriptor.
pub const EPOLLHUP: u32 = 0x010;

/// Peer closed its end of the channel (read half).
///
/// Useful for detecting orderly shutdown of a TCP connection
/// or pipe without consuming an `EPOLLIN` event.
pub const EPOLLRDHUP: u32 = 0x2000;

/// Edge-triggered notification mode.
///
/// When set, events are reported only on state transitions
/// rather than while the condition holds (level-triggered is
/// the default).
pub const EPOLLET: u32 = 1 << 31;

/// One-shot notification mode.
///
/// After an event is reported, the entry is automatically
/// disabled. The user must re-arm it with [`EpollCtlOp::Mod`]
/// to receive further events.
pub const EPOLLONESHOT: u32 = 1 << 30;

// ── EpollEvent ───────────────────────────────────────────────

/// User-facing epoll event, compatible with Linux
/// `struct epoll_event`.
///
/// Passed to `epoll_ctl` (to specify interest) and returned by
/// `epoll_wait` (to report readiness).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EpollEvent {
    /// Bitmask of event flags (`EPOLLIN`, `EPOLLOUT`, etc.).
    pub events: u32,
    /// Opaque user data returned alongside readiness
    /// notifications.
    pub data: u64,
}

/// Placeholder event for array initialisation.
const EMPTY_EVENT: EpollEvent = EpollEvent { events: 0, data: 0 };

// ── EpollCtlOp ───────────────────────────────────────────────

/// Control operations for `epoll_ctl`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum EpollCtlOp {
    /// Register a new file descriptor on the epoll instance.
    #[default]
    Add,
    /// Modify the events mask for an already-registered fd.
    Mod,
    /// Remove a file descriptor from the epoll instance.
    Del,
}

impl EpollCtlOp {
    /// Convert a raw `u32` to an [`EpollCtlOp`].
    ///
    /// Returns `Err(InvalidArgument)` for unknown values.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Add),
            2 => Ok(Self::Mod),
            3 => Ok(Self::Del),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── EpollInterest ────────────────────────────────────────────

/// Maximum number of watched file descriptors per instance.
const MAX_INTERESTS: usize = 128;

/// Maximum number of ready events buffered per instance.
const MAX_READY: usize = 64;

/// Internal bookkeeping for a single watched file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct EpollInterest {
    /// The watched file descriptor number.
    pub fd: i32,
    /// Interest mask set by the user
    /// (`EPOLLIN | EPOLLOUT | ...`).
    pub events: u32,
    /// Opaque user data echoed back in readiness reports.
    pub data: u64,
    /// Additional flags (`EPOLLET`, `EPOLLONESHOT`, etc.).
    pub flags: u32,
    /// Whether this interest has been triggered (ready).
    pub triggered: bool,
    /// Whether this slot is in use.
    active: bool,
}

impl EpollInterest {
    /// Create an inactive (empty) interest slot.
    const fn empty() -> Self {
        Self {
            fd: -1,
            events: 0,
            data: 0,
            flags: 0,
            triggered: false,
            active: false,
        }
    }
}

// ── EpollInstance ─────────────────────────────────────────────

/// Maximum number of concurrent epoll instances system-wide.
const MAX_INSTANCES: usize = 64;

/// An epoll instance that monitors a set of file descriptors
/// for I/O readiness.
///
/// Each instance maintains an array of [`EpollInterest`] slots
/// (up to [`MAX_INTERESTS`]) and a ready list of up to
/// [`MAX_READY`] events. File descriptors are added, modified,
/// and removed via [`EpollRegistry::epoll_ctl`]. Readiness is
/// collected via [`EpollRegistry::epoll_wait`] after being
/// signalled through [`EpollRegistry::notify_fd`].
pub struct EpollInstance {
    /// Unique identifier for this instance.
    id: u64,
    /// Watched file descriptor interests (fixed-size array).
    interests: [EpollInterest; MAX_INTERESTS],
    /// Pre-collected ready events for the next `epoll_wait`.
    ready_list: [EpollEvent; MAX_READY],
    /// Number of events currently in `ready_list`.
    ready_count: usize,
    /// Number of currently registered interests.
    interest_count: usize,
    /// PID of the process that owns this instance.
    owner_pid: u64,
    /// Whether this instance slot is in use.
    in_use: bool,
}

impl EpollInstance {
    /// Create a new, empty epoll instance.
    const fn new() -> Self {
        Self {
            id: 0,
            interests: [const { EpollInterest::empty() }; MAX_INTERESTS],
            ready_list: [EMPTY_EVENT; MAX_READY],
            ready_count: 0,
            interest_count: 0,
            owner_pid: 0,
            in_use: false,
        }
    }

    /// Return the instance identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the owner process PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Register a file descriptor with the given event interest.
    fn add(&mut self, fd: i32, event: &EpollEvent) -> Result<()> {
        // Check for duplicates.
        let dup = self.interests.iter().any(|e| e.active && e.fd == fd);
        if dup {
            return Err(Error::AlreadyExists);
        }

        // Find a free slot.
        let slot = self
            .interests
            .iter_mut()
            .find(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = EpollInterest {
            fd,
            events: event.events & !(EPOLLET | EPOLLONESHOT),
            data: event.data,
            flags: event.events & (EPOLLET | EPOLLONESHOT),
            triggered: false,
            active: true,
        };
        self.interest_count = self.interest_count.saturating_add(1);
        Ok(())
    }

    /// Modify the event interest mask for a registered fd.
    fn modify(&mut self, fd: i32, event: &EpollEvent) -> Result<()> {
        let entry = self
            .interests
            .iter_mut()
            .find(|e| e.active && e.fd == fd)
            .ok_or(Error::NotFound)?;

        entry.events = event.events & !(EPOLLET | EPOLLONESHOT);
        entry.data = event.data;
        entry.flags = event.events & (EPOLLET | EPOLLONESHOT);
        entry.triggered = false;
        Ok(())
    }

    /// Remove a file descriptor from the watch set.
    fn delete(&mut self, fd: i32) -> Result<()> {
        let entry = self
            .interests
            .iter_mut()
            .find(|e| e.active && e.fd == fd)
            .ok_or(Error::NotFound)?;

        *entry = EpollInterest::empty();
        self.interest_count = self.interest_count.saturating_sub(1);
        Ok(())
    }

    /// Collect ready events into the ready list.
    ///
    /// Scans all registered interests and copies up to
    /// `max_events` ready events into the internal ready list.
    /// Returns the number of events collected.
    ///
    /// For entries with [`EPOLLONESHOT`] set, the entry is
    /// disabled after reporting. For edge-triggered entries
    /// ([`EPOLLET`]), the triggered flag is cleared.
    fn collect_ready(&mut self, max_events: usize) -> usize {
        let limit = if max_events > MAX_READY {
            MAX_READY
        } else {
            max_events
        };
        let mut collected: usize = 0;

        for interest in &mut self.interests {
            if collected >= limit {
                break;
            }
            if !interest.active || !interest.triggered {
                continue;
            }

            // Report only events the user is interested in,
            // plus unconditional events (ERR, HUP, RDHUP).
            let mask = interest.events | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
            let reportable = interest.events & mask;
            if reportable == 0 {
                continue;
            }

            self.ready_list[collected] = EpollEvent {
                events: reportable,
                data: interest.data,
            };
            collected = collected.saturating_add(1);

            // Edge-triggered: clear triggered flag.
            if interest.flags & EPOLLET != 0 {
                interest.triggered = false;
            }
            // One-shot: disable entry after report.
            if interest.flags & EPOLLONESHOT != 0 {
                interest.active = false;
                self.interest_count = self.interest_count.saturating_sub(1);
            }
        }

        self.ready_count = collected;
        collected
    }

    /// Signal that a file descriptor has become ready for the
    /// given events.
    ///
    /// Typically called from I/O completion paths (VFS, socket
    /// layer, pipe, etc.) to wake up epoll waiters.
    fn notify(&mut self, fd: i32, events: u32) {
        for interest in &mut self.interests {
            if !interest.active || interest.fd != fd {
                continue;
            }
            let matching = events & (interest.events | EPOLLERR | EPOLLHUP | EPOLLRDHUP);
            if matching != 0 {
                interest.triggered = true;
            }
        }
    }
}

// ── EpollRegistry ────────────────────────────────────────────

/// Global registry of epoll instances.
///
/// Manages the creation, lookup, and destruction of
/// [`EpollInstance`] objects. Each instance is identified by a
/// numeric ID (returned by
/// [`epoll_create`](EpollRegistry::epoll_create) and used as an
/// epoll file descriptor in user space).
pub struct EpollRegistry {
    /// Fixed array of epoll instance slots.
    instances: [EpollInstance; MAX_INSTANCES],
    /// Monotonically increasing ID counter.
    next_id: u64,
    /// Number of active instances.
    count: usize,
}

impl Default for EpollRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EpollRegistry {
    /// Create an empty registry with no active instances.
    pub const fn new() -> Self {
        Self {
            instances: [const { EpollInstance::new() }; MAX_INSTANCES],
            next_id: 1,
            count: 0,
        }
    }

    /// Allocate a new epoll instance owned by `pid`.
    ///
    /// Returns the instance ID (epoll fd) on success, or
    /// `Err(OutOfMemory)` if all slots are occupied.
    pub fn epoll_create(&mut self, pid: u64) -> Result<u64> {
        let slot = self
            .instances
            .iter_mut()
            .find(|inst| !inst.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        *slot = EpollInstance::new();
        slot.id = id;
        slot.owner_pid = pid;
        slot.in_use = true;

        self.count = self.count.saturating_add(1);
        Ok(id)
    }

    /// Perform a control operation on an epoll instance.
    ///
    /// Dispatches to add, modify, or delete based on `op`.
    /// Returns `Err(NotFound)` if `epoll_id` does not exist.
    pub fn epoll_ctl(
        &mut self,
        epoll_id: u64,
        op: EpollCtlOp,
        fd: i32,
        event: &EpollEvent,
    ) -> Result<()> {
        let inst = self.find_mut(epoll_id)?;
        match op {
            EpollCtlOp::Add => inst.add(fd, event),
            EpollCtlOp::Mod => inst.modify(fd, event),
            EpollCtlOp::Del => inst.delete(fd),
        }
    }

    /// Wait for events on an epoll instance.
    ///
    /// Collects up to `max_events` ready events and returns a
    /// reference to the internal ready list together with the
    /// number of events collected.
    ///
    /// Returns `Err(InvalidArgument)` if `max_events` is 0.
    /// Returns `Err(NotFound)` if the instance does not exist.
    pub fn epoll_wait(
        &mut self,
        epoll_id: u64,
        max_events: usize,
    ) -> Result<(&[EpollEvent], usize)> {
        if max_events == 0 {
            return Err(Error::InvalidArgument);
        }
        let inst = self.find_mut(epoll_id)?;
        let n = inst.collect_ready(max_events);
        // Re-borrow as shared to return a slice.
        let inst = self.find(epoll_id)?;
        Ok((&inst.ready_list[..n], n))
    }

    /// Notify an fd across all epoll instances that it is ready
    /// for the given events.
    ///
    /// Called from I/O completion paths (VFS, socket, pipe,
    /// etc.) when a file descriptor becomes ready.
    pub fn notify_fd(&mut self, fd: i32, events: u32) {
        for inst in &mut self.instances {
            if inst.in_use {
                inst.notify(fd, events);
            }
        }
    }

    /// Close and destroy an epoll instance by ID.
    ///
    /// Returns `Err(NotFound)` if the instance does not exist.
    pub fn close(&mut self, epoll_id: u64) -> Result<()> {
        let inst = self.find_mut(epoll_id)?;
        *inst = EpollInstance::new();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of active epoll instances.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry contains no active instances.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Private helpers ──────────────────────────────────────

    /// Find an active instance by ID (shared reference).
    fn find(&self, id: u64) -> Result<&EpollInstance> {
        self.instances
            .iter()
            .find(|inst| inst.in_use && inst.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active instance by ID (mutable reference).
    fn find_mut(&mut self, id: u64) -> Result<&mut EpollInstance> {
        self.instances
            .iter_mut()
            .find(|inst| inst.in_use && inst.id == id)
            .ok_or(Error::NotFound)
    }
}
