// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `listen(2)` extended implementation.
//!
//! Validates the backlog argument, manages the transition from a bound socket
//! to a listening socket, and provides backlog-overflow policy helpers.
//!
//! # Syscall signature
//!
//! ```text
//! int listen(int sockfd, int backlog);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §listen — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_listen()`
//! - `listen(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum backlog the kernel will honour (Linux SOMAXCONN).
pub const SOMAXCONN: u32 = 4096;
/// Minimum accepted backlog.
const BACKLOG_MIN: u32 = 1;

// ---------------------------------------------------------------------------
// ListenerState — listening socket lifecycle
// ---------------------------------------------------------------------------

/// State of a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerState {
    /// Created but not yet bound.
    Unbound,
    /// Bound to an address.
    Bound,
    /// Actively listening.
    Listening,
    /// Closed.
    Closed,
}

// ---------------------------------------------------------------------------
// BacklogPolicy — how to handle backlog overflow
// ---------------------------------------------------------------------------

/// Policy for handling new connections when the backlog is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklogPolicy {
    /// Silently drop the new connection (TCP: send RST).
    Drop,
    /// Defer the new connection until space is available.
    Defer,
}

// ---------------------------------------------------------------------------
// ListenRecord — per-fd listen state
// ---------------------------------------------------------------------------

/// Per-fd listen state record.
#[derive(Debug, Clone, Copy)]
pub struct ListenRecord {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Current state.
    pub state: ListenerState,
    /// Effective backlog limit.
    pub backlog: u32,
    /// Number of connections currently queued.
    pub queued: u32,
    /// Overflow policy.
    pub policy: BacklogPolicy,
}

impl ListenRecord {
    /// Create an unbound record.
    pub const fn new(sockfd: i32) -> Self {
        Self {
            sockfd,
            state: ListenerState::Unbound,
            backlog: 0,
            queued: 0,
            policy: BacklogPolicy::Drop,
        }
    }

    /// Return `true` if the backlog is full.
    pub const fn is_full(&self) -> bool {
        self.queued >= self.backlog
    }

    /// Return `true` if the socket is in a state where new connections are accepted.
    pub const fn is_accepting(&self) -> bool {
        matches!(self.state, ListenerState::Listening)
    }

    /// Increment the queued connection count.
    pub fn enqueue(&mut self) -> Result<()> {
        if self.is_full() {
            return Err(Error::Busy);
        }
        self.queued += 1;
        Ok(())
    }

    /// Decrement the queued connection count (connection was accepted).
    pub fn dequeue(&mut self) {
        self.queued = self.queued.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// ListenTable — registry of listening sockets
// ---------------------------------------------------------------------------

/// Maximum tracked listening sockets.
const MAX_SOCKETS: usize = 256;

#[derive(Clone, Copy)]
struct TableEntry {
    record: ListenRecord,
    active: bool,
}

impl TableEntry {
    const fn inactive() -> Self {
        Self {
            record: ListenRecord {
                sockfd: 0,
                state: ListenerState::Unbound,
                backlog: 0,
                queued: 0,
                policy: BacklogPolicy::Drop,
            },
            active: false,
        }
    }
}

/// Table of listening socket records.
pub struct ListenTable {
    entries: [TableEntry; MAX_SOCKETS],
}

impl ListenTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { TableEntry::inactive() }; MAX_SOCKETS],
        }
    }

    /// Register a new socket.
    pub fn register(&mut self, sockfd: i32) -> Result<()> {
        if self
            .entries
            .iter()
            .any(|e| e.active && e.record.sockfd == sockfd)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = TableEntry {
            record: ListenRecord::new(sockfd),
            active: true,
        };
        Ok(())
    }

    /// Look up a record.
    pub fn get(&self, sockfd: i32) -> Option<&ListenRecord> {
        self.entries
            .iter()
            .find(|e| e.active && e.record.sockfd == sockfd)
            .map(|e| &e.record)
    }

    /// Look up a record mutably.
    pub fn get_mut(&mut self, sockfd: i32) -> Option<&mut ListenRecord> {
        self.entries
            .iter_mut()
            .find(|e| e.active && e.record.sockfd == sockfd)
            .map(|e| &mut e.record)
    }

    /// Remove a socket.
    pub fn remove(&mut self, sockfd: i32) -> bool {
        for entry in &mut self.entries {
            if entry.active && entry.record.sockfd == sockfd {
                entry.active = false;
                return true;
            }
        }
        false
    }
}

impl Default for ListenTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Clamp and validate the backlog value.
///
/// Linux caps the backlog at `SOMAXCONN`; negative values are treated
/// as `SOMAXCONN`.
pub fn effective_backlog(backlog: i32) -> u32 {
    if backlog <= 0 {
        SOMAXCONN
    } else {
        (backlog as u32).min(SOMAXCONN)
    }
}

// ---------------------------------------------------------------------------
// sys_listen_ext — extended entry point
// ---------------------------------------------------------------------------

/// Extended handler for `listen(2)`.
///
/// Validates the state transition and applies the backlog limit.
///
/// # Arguments
///
/// * `table`   — Listen table.
/// * `sockfd`  — Socket file descriptor.
/// * `backlog` — Requested backlog (clamped to `SOMAXCONN`).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — socket not in a connectable state.
/// * [`Error::NotFound`]        — fd not registered.
pub fn sys_listen_ext(table: &mut ListenTable, sockfd: i32, backlog: i32) -> Result<u32> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    let rec = table.get_mut(sockfd).ok_or(Error::NotFound)?;

    match rec.state {
        ListenerState::Closed => return Err(Error::InvalidArgument),
        ListenerState::Unbound | ListenerState::Bound | ListenerState::Listening => {}
    }

    let eff = effective_backlog(backlog);
    rec.backlog = eff.max(BACKLOG_MIN);
    rec.state = ListenerState::Listening;
    Ok(rec.backlog)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_transitions_to_listening() {
        let mut t = ListenTable::new();
        t.register(3).unwrap();
        let backlog = sys_listen_ext(&mut t, 3, 5).unwrap();
        assert_eq!(backlog, 5);
        assert_eq!(t.get(3).unwrap().state, ListenerState::Listening);
    }

    #[test]
    fn negative_backlog_becomes_somaxconn() {
        let mut t = ListenTable::new();
        t.register(3).unwrap();
        let backlog = sys_listen_ext(&mut t, 3, -1).unwrap();
        assert_eq!(backlog, SOMAXCONN);
    }

    #[test]
    fn backlog_capped_at_somaxconn() {
        let mut t = ListenTable::new();
        t.register(3).unwrap();
        let backlog = sys_listen_ext(&mut t, 3, 1_000_000).unwrap();
        assert_eq!(backlog, SOMAXCONN);
    }

    #[test]
    fn fd_not_found() {
        let mut t = ListenTable::new();
        assert_eq!(sys_listen_ext(&mut t, 99, 5), Err(Error::NotFound));
    }

    #[test]
    fn negative_sockfd() {
        let mut t = ListenTable::new();
        assert_eq!(sys_listen_ext(&mut t, -1, 5), Err(Error::InvalidArgument));
    }

    #[test]
    fn enqueue_dequeue() {
        let mut t = ListenTable::new();
        t.register(3).unwrap();
        sys_listen_ext(&mut t, 3, 2).unwrap();
        let rec = t.get_mut(3).unwrap();
        rec.enqueue().unwrap();
        rec.enqueue().unwrap();
        assert!(rec.is_full());
        assert_eq!(rec.enqueue(), Err(Error::Busy));
        rec.dequeue();
        assert!(!rec.is_full());
    }

    #[test]
    fn closed_socket_rejected() {
        let mut t = ListenTable::new();
        t.register(3).unwrap();
        t.get_mut(3).unwrap().state = ListenerState::Closed;
        assert_eq!(sys_listen_ext(&mut t, 3, 5), Err(Error::InvalidArgument));
    }
}
