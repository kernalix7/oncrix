// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! epoll event polling.
//!
//! Implements the epoll(7) interface for scalable I/O event notification.
//! An epoll instance monitors a set of file descriptors and reports which
//! are ready for I/O using an interest list and a ready list.

use oncrix_lib::{Error, Result};

/// epoll event type flags.
pub const EPOLLIN: u32 = 0x0001;
pub const EPOLLPRI: u32 = 0x0002;
pub const EPOLLOUT: u32 = 0x0004;
pub const EPOLLERR: u32 = 0x0008;
pub const EPOLLHUP: u32 = 0x0010;
pub const EPOLLRDNORM: u32 = 0x0040;
pub const EPOLLRDBAND: u32 = 0x0080;
pub const EPOLLWRNORM: u32 = 0x0100;
pub const EPOLLWRBAND: u32 = 0x0200;
pub const EPOLLMSG: u32 = 0x0400;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

/// epoll control operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EpollCtlOp {
    /// Add a file descriptor to the interest list.
    Add = 1,
    /// Remove a file descriptor from the interest list.
    Del = 2,
    /// Modify the event mask for an existing entry.
    Mod = 3,
}

impl TryFrom<i32> for EpollCtlOp {
    type Error = Error;

    fn try_from(v: i32) -> Result<Self> {
        match v {
            1 => Ok(Self::Add),
            2 => Ok(Self::Del),
            3 => Ok(Self::Mod),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// An epoll event as passed to/from user space.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct EpollEvent {
    /// Bitmask of events.
    pub events: u32,
    /// User data associated with this event.
    pub data: u64,
}

/// Maximum number of file descriptors per epoll instance.
pub const EPOLL_MAX_FDS: usize = 128;

/// Entry in the interest list.
#[derive(Debug, Clone, Copy)]
pub struct EpollEntry {
    /// Monitored file descriptor.
    pub fd: i32,
    /// Requested event mask.
    pub events: u32,
    /// User data tag.
    pub data: u64,
    /// Edge-triggered mode.
    pub edge_triggered: bool,
    /// One-shot mode: remove after first event.
    pub oneshot: bool,
    /// Whether the entry is enabled (not yet consumed for ONESHOT).
    pub enabled: bool,
}

impl EpollEntry {
    /// Create a new interest list entry.
    pub const fn new(fd: i32, events: u32, data: u64) -> Self {
        Self {
            fd,
            events,
            data,
            edge_triggered: events & EPOLLET != 0,
            oneshot: events & EPOLLONESHOT != 0,
            enabled: true,
        }
    }
}

/// epoll instance.
#[derive(Debug)]
pub struct EpollInstance {
    /// Interest list of monitored descriptors.
    interest: [Option<EpollEntry>; EPOLL_MAX_FDS],
    /// Number of active entries.
    pub count: usize,
    /// Ready list (fd indices with pending events).
    ready: [i32; EPOLL_MAX_FDS],
    /// Number of entries in the ready list.
    pub ready_count: usize,
}

impl EpollInstance {
    /// Create a new epoll instance.
    pub const fn new() -> Self {
        Self {
            interest: [const { None }; EPOLL_MAX_FDS],
            count: 0,
            ready: [0i32; EPOLL_MAX_FDS],
            ready_count: 0,
        }
    }

    /// Find the index of an entry for `fd`.
    fn find(&self, fd: i32) -> Option<usize> {
        self.interest
            .iter()
            .position(|e| e.as_ref().map_or(false, |e| e.fd == fd))
    }

    /// Find a free slot.
    fn free_slot(&self) -> Option<usize> {
        self.interest.iter().position(|e| e.is_none())
    }

    /// Add a file descriptor to the interest list.
    pub fn add(&mut self, fd: i32, events: u32, data: u64) -> Result<()> {
        if self.find(fd).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
        self.interest[slot] = Some(EpollEntry::new(fd, events, data));
        self.count += 1;
        Ok(())
    }

    /// Remove a file descriptor from the interest list.
    pub fn del(&mut self, fd: i32) -> Result<()> {
        let idx = self.find(fd).ok_or(Error::NotFound)?;
        self.interest[idx] = None;
        self.count -= 1;
        // Remove from ready list.
        self.ready_count = {
            let mut new_count = 0;
            let mut new_ready = [0i32; EPOLL_MAX_FDS];
            for i in 0..self.ready_count {
                if self.ready[i] != fd {
                    new_ready[new_count] = self.ready[i];
                    new_count += 1;
                }
            }
            self.ready = new_ready;
            new_count
        };
        Ok(())
    }

    /// Modify the event mask for an existing entry.
    pub fn modify(&mut self, fd: i32, events: u32, data: u64) -> Result<()> {
        let idx = self.find(fd).ok_or(Error::NotFound)?;
        self.interest[idx] = Some(EpollEntry::new(fd, events, data));
        Ok(())
    }

    /// Dispatch control operation (EPOLL_CTL_ADD/DEL/MOD).
    pub fn ctl(&mut self, op: EpollCtlOp, fd: i32, event: EpollEvent) -> Result<()> {
        match op {
            EpollCtlOp::Add => self.add(fd, event.events, event.data),
            EpollCtlOp::Del => self.del(fd),
            EpollCtlOp::Mod => self.modify(fd, event.events, event.data),
        }
    }

    /// Notify the epoll instance that `fd` has events `revents`.
    ///
    /// Called by the file's poll/wake mechanism.
    pub fn notify(&mut self, fd: i32, revents: u32) {
        let Some(idx) = self.find(fd) else { return };
        let Some(entry) = self.interest[idx].as_mut() else {
            return;
        };

        if !entry.enabled {
            return;
        }
        if entry.events & revents == 0 {
            return;
        }

        // Add to ready list if not already present.
        if !self.ready[..self.ready_count].contains(&fd) && self.ready_count < EPOLL_MAX_FDS {
            self.ready[self.ready_count] = fd;
            self.ready_count += 1;
        }

        if entry.oneshot {
            entry.enabled = false;
        }
    }

    /// Wait for events, filling `events` with up to `max_events` ready events.
    ///
    /// Returns the number of events collected.
    pub fn wait(&mut self, events: &mut [EpollEvent]) -> usize {
        let max = events.len().min(self.ready_count);
        let mut collected = 0;

        for i in 0..max {
            let fd = self.ready[i];
            if let Some(idx) = self.find(fd) {
                if let Some(entry) = &self.interest[idx] {
                    events[collected] = EpollEvent {
                        events: entry.events,
                        data: entry.data,
                    };
                    collected += 1;
                }
            }
        }

        // Consume the first `collected` entries from the ready list.
        let new_count = self.ready_count - collected;
        for i in 0..new_count {
            self.ready[i] = self.ready[i + collected];
        }
        self.ready_count = new_count;

        collected
    }

    /// Return true if there are pending events.
    pub fn has_events(&self) -> bool {
        self.ready_count > 0
    }
}

impl Default for EpollInstance {
    fn default() -> Self {
        Self::new()
    }
}

/// epoll file — wraps an EpollInstance as a VFS file object.
#[derive(Debug)]
pub struct EpollFile {
    /// The epoll instance.
    pub instance: EpollInstance,
    /// File descriptor number of this epoll fd.
    pub epfd: i32,
}

impl EpollFile {
    /// Create a new epoll file.
    pub const fn new(epfd: i32) -> Self {
        Self {
            instance: EpollInstance::new(),
            epfd,
        }
    }

    /// Perform an epoll_ctl operation.
    pub fn ctl(&mut self, op: EpollCtlOp, fd: i32, event: EpollEvent) -> Result<()> {
        // Prevent adding this epoll fd to itself.
        if fd == self.epfd {
            return Err(Error::InvalidArgument);
        }
        self.instance.ctl(op, fd, event)
    }

    /// Perform an epoll_wait, returning events into the provided buffer.
    pub fn wait(&mut self, events: &mut [EpollEvent]) -> usize {
        self.instance.wait(events)
    }
}
