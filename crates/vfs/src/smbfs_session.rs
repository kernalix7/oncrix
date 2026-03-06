// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMB filesystem session and tree connect management.
//!
//! This module implements the session layer for the SMB (Server Message Block)
//! filesystem client. It manages:
//! - SMB2/3 session establishment and authentication tokens.
//! - Tree connections (share mounts) per session.
//! - Session ID allocation and credential binding.
//!
//! # SMB2 Session
//!
//! An SMB2 session is established via `SMB2_NEGOTIATE` → `SMB2_SESSION_SETUP`
//! exchanges. Once established, the session has a 64-bit `SessionId` returned
//! by the server and a set of session flags (guest, anonymous, encrypt-data).
//!
//! # Tree Connect
//!
//! A tree connect links a session to a specific share path (e.g., `\\srv\share`).
//! The server returns a 32-bit `TreeId` used in subsequent SMB2 requests.
//! Multiple tree connects may exist per session.

use oncrix_lib::{Error, Result};

/// Maximum number of active sessions per SMB client instance.
pub const SMB_MAX_SESSIONS: usize = 8;

/// Maximum number of tree connects per session.
pub const SMB_MAX_TREES: usize = 16;

/// Maximum length of a share UNC path (e.g., `\\server\share`).
pub const SMB_MAX_UNC_LEN: usize = 256;

/// Session flags returned by the server in `SMB2_SESSION_SETUP` response.
pub mod session_flags {
    /// Session is authenticated as a guest.
    pub const GUEST: u16 = 0x0001;
    /// Session is anonymous (no credentials).
    pub const ANONYMOUS: u16 = 0x0002;
    /// Session requires encryption.
    pub const ENCRYPT_DATA: u16 = 0x0004;
}

/// Tree connect share type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShareType {
    /// Disk share (files and directories).
    Disk,
    /// Named pipe share (IPC$).
    Pipe,
    /// Printer share.
    Print,
    /// Unknown / unsupported.
    Unknown,
}

impl Default for ShareType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl ShareType {
    /// Parses a share type from the SMB2 `ShareType` byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Disk,
            0x02 => Self::Pipe,
            0x03 => Self::Print,
            _ => Self::Unknown,
        }
    }
}

/// State of an SMB2 session or tree connect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnState {
    /// Not connected.
    Idle,
    /// Negotiating / authenticating.
    InProgress,
    /// Successfully established.
    Connected,
    /// Disconnected or expired.
    Disconnected,
}

impl Default for ConnState {
    fn default() -> Self {
        Self::Idle
    }
}

/// An SMB2 tree connect record.
#[derive(Clone, Copy)]
pub struct TreeConnect {
    /// Tree ID assigned by the server.
    pub tree_id: u32,
    /// Session this tree belongs to.
    pub session_id: u64,
    /// Share type.
    pub share_type: ShareType,
    /// UNC path of the share (ASCII/UTF-8).
    pub unc: [u8; SMB_MAX_UNC_LEN],
    /// Actual length of `unc`.
    pub unc_len: usize,
    /// Connection state.
    pub state: ConnState,
}

impl Default for TreeConnect {
    fn default() -> Self {
        Self {
            tree_id: 0,
            session_id: 0,
            share_type: ShareType::default(),
            unc: [0u8; SMB_MAX_UNC_LEN],
            unc_len: 0,
            state: ConnState::Idle,
        }
    }
}

impl TreeConnect {
    /// Creates a new connected tree.
    pub fn new(session_id: u64, tree_id: u32, share_type: ShareType, unc: &[u8]) -> Result<Self> {
        if unc.len() > SMB_MAX_UNC_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut tc = Self {
            tree_id,
            session_id,
            share_type,
            unc: [0u8; SMB_MAX_UNC_LEN],
            unc_len: unc.len(),
            state: ConnState::Connected,
        };
        tc.unc[..unc.len()].copy_from_slice(unc);
        Ok(tc)
    }

    /// Returns the share UNC path as a byte slice.
    pub fn unc_path(&self) -> &[u8] {
        &self.unc[..self.unc_len]
    }

    /// Marks this tree as disconnected.
    pub fn disconnect(&mut self) {
        self.state = ConnState::Disconnected;
    }
}

/// An SMB2 session.
pub struct SmbSession {
    /// Session ID assigned by the server.
    pub session_id: u64,
    /// Session flags (see [`session_flags`]).
    pub flags: u16,
    /// Connection state.
    pub state: ConnState,
    /// Tree connections within this session.
    trees: [TreeConnect; SMB_MAX_TREES],
    /// Number of active tree connections.
    tree_count: usize,
}

impl Default for SmbSession {
    fn default() -> Self {
        Self {
            session_id: 0,
            flags: 0,
            state: ConnState::Idle,
            trees: [const {
                TreeConnect {
                    tree_id: 0,
                    session_id: 0,
                    share_type: ShareType::Unknown,
                    unc: [0u8; SMB_MAX_UNC_LEN],
                    unc_len: 0,
                    state: ConnState::Idle,
                }
            }; SMB_MAX_TREES],
            tree_count: 0,
        }
    }
}

impl SmbSession {
    /// Creates a new established session.
    pub fn new(session_id: u64, flags: u16) -> Self {
        let mut s = Self::default();
        s.session_id = session_id;
        s.flags = flags;
        s.state = ConnState::Connected;
        s
    }

    /// Returns `true` if the session requires data encryption.
    pub const fn requires_encryption(&self) -> bool {
        self.flags & session_flags::ENCRYPT_DATA != 0
    }

    /// Returns `true` if authenticated as guest.
    pub const fn is_guest(&self) -> bool {
        self.flags & session_flags::GUEST != 0
    }

    /// Adds a tree connect to this session.
    pub fn add_tree(&mut self, tc: TreeConnect) -> Result<()> {
        if self.tree_count >= SMB_MAX_TREES {
            return Err(Error::OutOfMemory);
        }
        self.trees[self.tree_count] = tc;
        self.tree_count += 1;
        Ok(())
    }

    /// Finds a tree connect by `tree_id`.
    pub fn find_tree(&self, tree_id: u32) -> Option<&TreeConnect> {
        self.trees[..self.tree_count]
            .iter()
            .find(|t| t.tree_id == tree_id && t.state == ConnState::Connected)
    }

    /// Removes (disconnects) a tree connect by `tree_id`.
    pub fn remove_tree(&mut self, tree_id: u32) -> Result<()> {
        for t in &mut self.trees[..self.tree_count] {
            if t.tree_id == tree_id {
                t.disconnect();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active (connected) tree connections.
    pub fn connected_tree_count(&self) -> usize {
        self.trees[..self.tree_count]
            .iter()
            .filter(|t| t.state == ConnState::Connected)
            .count()
    }
}

/// Session table for the SMB client.
pub struct SessionTable {
    sessions: [SmbSession; SMB_MAX_SESSIONS],
    count: usize,
}

impl Default for SessionTable {
    fn default() -> Self {
        // Cannot derive Default due to large arrays; initialize manually.
        Self {
            sessions: core::array::from_fn(|_| SmbSession::default()),
            count: 0,
        }
    }
}

impl SessionTable {
    /// Adds a session.
    pub fn add(&mut self, session: SmbSession) -> Result<()> {
        if self.count >= SMB_MAX_SESSIONS {
            return Err(Error::OutOfMemory);
        }
        self.sessions[self.count] = session;
        self.count += 1;
        Ok(())
    }

    /// Finds a session by `session_id`.
    pub fn find(&self, session_id: u64) -> Option<&SmbSession> {
        self.sessions[..self.count]
            .iter()
            .find(|s| s.session_id == session_id && s.state == ConnState::Connected)
    }

    /// Finds a mutable session by `session_id`.
    pub fn find_mut(&mut self, session_id: u64) -> Option<&mut SmbSession> {
        self.sessions[..self.count]
            .iter_mut()
            .find(|s| s.session_id == session_id && s.state == ConnState::Connected)
    }

    /// Removes a session, marking it as disconnected.
    pub fn remove(&mut self, session_id: u64) -> Result<()> {
        for s in &mut self.sessions[..self.count] {
            if s.session_id == session_id {
                s.state = ConnState::Disconnected;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}
