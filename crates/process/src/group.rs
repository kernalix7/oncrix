// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process groups and session management.
//!
//! Provides POSIX-compatible process group and session abstractions
//! for job control. A process group is a collection of related
//! processes (e.g., a pipeline), and a session is a collection of
//! process groups associated with a controlling terminal.

use oncrix_lib::{Error, Result};

/// Maximum number of processes in a single process group.
const MAX_MEMBERS: usize = 64;

/// Maximum number of process groups managed by the system.
const MAX_PROCESS_GROUPS: usize = 64;

/// Maximum number of sessions managed by the system.
const MAX_SESSIONS: usize = 32;

/// A POSIX process group.
///
/// A process group is identified by its PGID and contains a set of
/// member PIDs. The group leader is the process whose PID equals
/// the PGID.
#[derive(Debug)]
pub struct ProcessGroup {
    /// Process group identifier.
    pgid: u64,
    /// PID of the process group leader.
    leader_pid: u64,
    /// Fixed-capacity array of member PIDs.
    member_pids: [u64; MAX_MEMBERS],
    /// Number of active members in the group.
    count: usize,
}

impl ProcessGroup {
    /// Create a new process group with the given leader.
    ///
    /// The leader is automatically added as the first member.
    const fn new(pgid: u64, leader_pid: u64) -> Self {
        let mut members = [0u64; MAX_MEMBERS];
        members[0] = leader_pid;
        Self {
            pgid,
            leader_pid,
            member_pids: members,
            count: 1,
        }
    }

    /// Return the process group ID.
    pub const fn pgid(&self) -> u64 {
        self.pgid
    }

    /// Return the leader PID.
    pub const fn leader_pid(&self) -> u64 {
        self.leader_pid
    }

    /// Return the number of members in this group.
    pub const fn member_count(&self) -> usize {
        self.count
    }

    /// Return a slice of the current member PIDs.
    pub fn members(&self) -> &[u64] {
        &self.member_pids[..self.count]
    }

    /// Add a process to this group.
    ///
    /// Returns `Error::OutOfMemory` if the group is full, or
    /// `Error::AlreadyExists` if the PID is already a member.
    fn add_member(&mut self, pid: u64) -> Result<()> {
        // Check for duplicate.
        let mut i = 0;
        while i < self.count {
            if self.member_pids[i] == pid {
                return Err(Error::AlreadyExists);
            }
            i = i.saturating_add(1);
        }
        if self.count >= MAX_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        self.member_pids[self.count] = pid;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Remove a process from this group.
    ///
    /// Returns `Error::NotFound` if the PID is not a member.
    fn remove_member(&mut self, pid: u64) -> Result<()> {
        let mut i = 0;
        while i < self.count {
            if self.member_pids[i] == pid {
                // Swap with last element to maintain compactness.
                let last = self.count.saturating_sub(1);
                self.member_pids[i] = self.member_pids[last];
                self.member_pids[last] = 0;
                self.count = last;
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }
}

/// A POSIX session.
///
/// A session groups one or more process groups and optionally has
/// a controlling terminal. The session leader is the process that
/// called `setsid()`.
#[derive(Debug)]
pub struct Session {
    /// Session identifier (equals the leader's PID).
    sid: u64,
    /// PID of the session leader.
    leader_pid: u64,
    /// Controlling terminal minor number, if any.
    controlling_tty: Option<u32>,
    /// PGID of the foreground process group.
    foreground_pgid: u64,
}

impl Session {
    /// Create a new session with the given leader.
    ///
    /// The foreground process group is initially set to the
    /// leader's own PGID (which equals the SID).
    const fn new(sid: u64, leader_pid: u64) -> Self {
        Self {
            sid,
            leader_pid,
            controlling_tty: None,
            foreground_pgid: sid,
        }
    }

    /// Return the session ID.
    pub const fn sid(&self) -> u64 {
        self.sid
    }

    /// Return the session leader's PID.
    pub const fn leader_pid(&self) -> u64 {
        self.leader_pid
    }

    /// Return the controlling terminal, if any.
    pub const fn controlling_tty(&self) -> Option<u32> {
        self.controlling_tty
    }

    /// Return the foreground process group ID.
    pub const fn foreground_pgid(&self) -> u64 {
        self.foreground_pgid
    }
}

/// Table managing all process groups in the system.
///
/// Fixed-capacity table holding up to [`MAX_PROCESS_GROUPS`] groups.
pub struct ProcessGroupTable {
    /// Storage for process groups.
    groups: [Option<ProcessGroup>; MAX_PROCESS_GROUPS],
    /// Number of active groups.
    count: usize,
}

impl Default for ProcessGroupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessGroupTable {
    /// Create an empty process group table.
    pub const fn new() -> Self {
        // SAFETY: Option<ProcessGroup> can be None-initialized.
        // We use a const block to build the array since
        // ProcessGroup is not Copy.
        const NONE: Option<ProcessGroup> = None;
        Self {
            groups: [NONE; MAX_PROCESS_GROUPS],
            count: 0,
        }
    }

    /// Create a new process group with the given PGID and leader.
    ///
    /// The leader is automatically added as the first member.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if a group with this PGID already exists
    /// - `OutOfMemory` if the table is full
    pub fn create(&mut self, pgid: u64, leader: u64) -> Result<()> {
        // Check for duplicate PGID.
        let mut i = 0;
        while i < MAX_PROCESS_GROUPS {
            if let Some(ref g) = self.groups[i] {
                if g.pgid == pgid {
                    return Err(Error::AlreadyExists);
                }
            }
            i = i.saturating_add(1);
        }
        if self.count >= MAX_PROCESS_GROUPS {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        let mut slot = 0;
        while slot < MAX_PROCESS_GROUPS {
            if self.groups[slot].is_none() {
                self.groups[slot] = Some(ProcessGroup::new(pgid, leader));
                self.count = self.count.saturating_add(1);
                return Ok(());
            }
            slot = slot.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Add a member to an existing process group.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no group with this PGID exists
    /// - `AlreadyExists` if the PID is already a member
    /// - `OutOfMemory` if the group is full
    pub fn add_member(&mut self, pgid: u64, pid: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_PROCESS_GROUPS {
            if let Some(ref mut g) = self.groups[i] {
                if g.pgid == pgid {
                    return g.add_member(pid);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Remove a member from a process group.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no group with this PGID exists or the PID
    ///   is not a member
    pub fn remove_member(&mut self, pgid: u64, pid: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_PROCESS_GROUPS {
            if let Some(ref mut g) = self.groups[i] {
                if g.pgid == pgid {
                    return g.remove_member(pid);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Look up a process group by PGID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no group with this PGID exists
    pub fn get(&self, pgid: u64) -> Result<&ProcessGroup> {
        let mut i = 0;
        while i < MAX_PROCESS_GROUPS {
            if let Some(ref g) = self.groups[i] {
                if g.pgid == pgid {
                    return Ok(g);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Destroy a process group, removing it from the table.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no group with this PGID exists
    pub fn destroy(&mut self, pgid: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_PROCESS_GROUPS {
            if let Some(ref g) = self.groups[i] {
                if g.pgid == pgid {
                    self.groups[i] = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Return the number of active process groups.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the table contains no process groups.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Table managing all sessions in the system.
///
/// Fixed-capacity table holding up to [`MAX_SESSIONS`] sessions.
pub struct SessionTable {
    /// Storage for sessions.
    sessions: [Option<Session>; MAX_SESSIONS],
    /// Number of active sessions.
    count: usize,
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTable {
    /// Create an empty session table.
    pub const fn new() -> Self {
        const NONE: Option<Session> = None;
        Self {
            sessions: [NONE; MAX_SESSIONS],
            count: 0,
        }
    }

    /// Create a new session with the given SID and leader.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if a session with this SID already exists
    /// - `OutOfMemory` if the table is full
    pub fn create(&mut self, sid: u64, leader: u64) -> Result<()> {
        // Check for duplicate SID.
        let mut i = 0;
        while i < MAX_SESSIONS {
            if let Some(ref s) = self.sessions[i] {
                if s.sid == sid {
                    return Err(Error::AlreadyExists);
                }
            }
            i = i.saturating_add(1);
        }
        if self.count >= MAX_SESSIONS {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        let mut slot = 0;
        while slot < MAX_SESSIONS {
            if self.sessions[slot].is_none() {
                self.sessions[slot] = Some(Session::new(sid, leader));
                self.count = self.count.saturating_add(1);
                return Ok(());
            }
            slot = slot.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a session by SID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no session with this SID exists
    pub fn get(&self, sid: u64) -> Result<&Session> {
        let mut i = 0;
        while i < MAX_SESSIONS {
            if let Some(ref s) = self.sessions[i] {
                if s.sid == sid {
                    return Ok(s);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Set the foreground process group for a session.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no session with this SID exists
    pub fn set_foreground(&mut self, sid: u64, pgid: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_SESSIONS {
            if let Some(ref mut s) = self.sessions[i] {
                if s.sid == sid {
                    s.foreground_pgid = pgid;
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Set the controlling terminal for a session.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no session with this SID exists
    pub fn set_controlling_tty(&mut self, sid: u64, tty: u32) -> Result<()> {
        let mut i = 0;
        while i < MAX_SESSIONS {
            if let Some(ref mut s) = self.sessions[i] {
                if s.sid == sid {
                    s.controlling_tty = Some(tty);
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Return the number of active sessions.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the table contains no sessions.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
