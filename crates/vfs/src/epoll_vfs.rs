// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! epoll VFS integration layer.
//!
//! Provides the VFS-level interface for epoll file descriptors, connecting
//! the epoll mechanism to the VFS file operations infrastructure.
//! This layer handles the epoll fd's VFS inode, file operations dispatch,
//! and integration with the poll/select subsystem.

use oncrix_lib::{Error, Result};

/// epoll event bit flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollEvents(pub u32);

impl EpollEvents {
    /// File is available to read.
    pub const EPOLLIN: u32 = 0x001;
    /// File is available to write.
    pub const EPOLLOUT: u32 = 0x004;
    /// Error condition on fd.
    pub const EPOLLERR: u32 = 0x008;
    /// Hang-up on fd.
    pub const EPOLLHUP: u32 = 0x010;
    /// Urgent data available.
    pub const EPOLLPRI: u32 = 0x002;
    /// Edge-triggered mode.
    pub const EPOLLET: u32 = 1 << 31;
    /// One-shot mode.
    pub const EPOLLONESHOT: u32 = 1 << 30;
    /// Wake-up source (for eventpoll wakeup chains).
    pub const EPOLLWAKEUP: u32 = 1 << 29;
    /// Exclusive wakeup.
    pub const EPOLLEXCLUSIVE: u32 = 1 << 28;

    /// Check if edge-triggered mode is set.
    pub fn is_et(self) -> bool {
        self.0 & Self::EPOLLET != 0
    }

    /// Check if one-shot mode is set.
    pub fn is_oneshot(self) -> bool {
        self.0 & Self::EPOLLONESHOT != 0
    }

    /// Mask to the event bits (excluding mode flags).
    pub fn event_mask(self) -> u32 {
        self.0 & (Self::EPOLLIN | Self::EPOLLOUT | Self::EPOLLERR | Self::EPOLLHUP | Self::EPOLLPRI)
    }
}

/// epoll control operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollCtlOp {
    /// Add a file descriptor to the epoll instance.
    Add,
    /// Modify the events for an existing fd.
    Mod,
    /// Remove a file descriptor.
    Del,
}

impl EpollCtlOp {
    /// Convert from a raw integer (EPOLL_CTL_* values).
    pub fn from_raw(v: u32) -> Result<Self> {
        match v {
            1 => Ok(Self::Add),
            2 => Ok(Self::Del),
            3 => Ok(Self::Mod),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// An entry in the epoll interest list.
#[derive(Debug, Clone, Copy)]
pub struct EpollEntry {
    /// Monitored file descriptor number.
    pub fd: u32,
    /// Inode number of the monitored file.
    pub ino: u64,
    /// Events to watch for.
    pub events: EpollEvents,
    /// User data associated with this entry.
    pub data: u64,
    /// Whether this entry is in one-shot state (armed=false after first trigger).
    pub armed: bool,
}

impl EpollEntry {
    /// Create a new epoll entry.
    pub const fn new(fd: u32, ino: u64, events: EpollEvents, data: u64) -> Self {
        EpollEntry {
            fd,
            ino,
            events,
            data,
            armed: true,
        }
    }
}

/// VFS-level epoll instance.
///
/// Manages the interest list and ready list for one epoll file descriptor.
pub struct EpollVfs {
    /// Epoll inode number (the epoll fd's inode).
    pub epoll_ino: u64,
    /// Interest list.
    interest: [Option<EpollEntry>; 128],
    /// Count of interest list entries.
    interest_count: usize,
    /// Ready event queue.
    ready: [Option<(u32, u32, u64)>; 64],
    /// Count of ready events.
    ready_count: usize,
}

impl EpollVfs {
    /// Create a new epoll VFS instance.
    pub const fn new(epoll_ino: u64) -> Self {
        EpollVfs {
            epoll_ino,
            interest: [None; 128],
            interest_count: 0,
            ready: [None; 64],
            ready_count: 0,
        }
    }

    /// Add an fd to the interest list (EPOLL_CTL_ADD).
    pub fn add(&mut self, fd: u32, ino: u64, events: EpollEvents, data: u64) -> Result<()> {
        // Detect duplicate.
        for slot in self.interest.iter().flatten() {
            if slot.fd == fd {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.interest {
            if slot.is_none() {
                *slot = Some(EpollEntry::new(fd, ino, events, data));
                self.interest_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Modify an fd's event mask (EPOLL_CTL_MOD).
    pub fn modify(&mut self, fd: u32, events: EpollEvents, data: u64) -> Result<()> {
        for slot in self.interest.iter_mut().flatten() {
            if slot.fd == fd {
                slot.events = events;
                slot.data = data;
                slot.armed = true;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove an fd from the interest list (EPOLL_CTL_DEL).
    pub fn delete(&mut self, fd: u32) -> Result<()> {
        for slot in &mut self.interest {
            if let Some(e) = slot {
                if e.fd == fd {
                    *slot = None;
                    self.interest_count = self.interest_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Signal that events occurred on an inode; add to ready list.
    pub fn signal(&mut self, ino: u64, occurred: EpollEvents) {
        for slot in self.interest.iter_mut().flatten() {
            if slot.ino == ino && slot.armed {
                let matched = slot.events.event_mask() & occurred.event_mask();
                if matched != 0 {
                    if self.ready_count < 64 {
                        self.ready[self.ready_count] = Some((slot.fd, matched, slot.data));
                        self.ready_count += 1;
                    }
                    if slot.events.is_oneshot() {
                        slot.armed = false;
                    }
                }
            }
        }
    }

    /// Drain up to `max` ready events into `out`.
    ///
    /// Returns the number of events written.
    pub fn wait(&mut self, out: &mut [(u32, u32, u64)], max: usize) -> usize {
        let n = self.ready_count.min(max).min(out.len());
        for i in 0..n {
            if let Some(ev) = self.ready[i] {
                out[i] = ev;
            }
        }
        // Shift remaining events.
        for i in 0..(self.ready_count - n) {
            self.ready[i] = self.ready[i + n];
        }
        for i in (self.ready_count - n)..self.ready_count {
            self.ready[i] = None;
        }
        self.ready_count -= n;
        n
    }

    /// Return interest list size.
    pub fn interest_count(&self) -> usize {
        self.interest_count
    }

    /// Return pending ready event count.
    pub fn ready_count(&self) -> usize {
        self.ready_count
    }
}

/// Global epoll VFS instance table (up to 32 epoll fds).
pub struct EpollVfsTable {
    instances: [Option<EpollVfs>; 32],
    count: usize,
}

impl EpollVfsTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        EpollVfsTable {
            instances: [const { None }; 32],
            count: 0,
        }
    }

    /// Create a new epoll instance and return its index.
    pub fn create(&mut self, epoll_ino: u64) -> Result<usize> {
        for (i, slot) in self.instances.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(EpollVfs::new(epoll_ino));
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a mutable reference to an epoll instance.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut EpollVfs> {
        self.instances
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)
    }

    /// Destroy an epoll instance.
    pub fn destroy(&mut self, idx: usize) -> Result<()> {
        if idx >= 32 {
            return Err(Error::InvalidArgument);
        }
        if self.instances[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.instances[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return count of active epoll instances.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for EpollVfsTable {
    fn default() -> Self {
        Self::new()
    }
}
