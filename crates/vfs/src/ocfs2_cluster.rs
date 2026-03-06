// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OCFS2 cluster-aware locking subsystem.
//!
//! OCFS2 (Oracle Cluster File System 2) is a shared-disk cluster filesystem.
//! Its correctness depends on a distributed lock manager (DLM) that serialises
//! access to shared resources.  This module models the local node's lock cache,
//! lock-level state machine, and basic DLM message types used to coordinate
//! access between cluster nodes.

use oncrix_lib::{Error, Result};

/// Maximum cluster nodes supported.
pub const OCFS2_MAX_NODES: usize = 32;

/// Maximum number of active DLM locks tracked.
pub const OCFS2_MAX_LOCKS: usize = 4096;

/// OCFS2 lock levels (subset of DLM lock modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockLevel {
    /// No lock.
    None,
    /// Null lock — holder present but no protection.
    Null,
    /// Concurrent read.
    ConcurrentRead,
    /// Concurrent write.
    ConcurrentWrite,
    /// Protected read.
    ProtectedRead,
    /// Protected write.
    ProtectedWrite,
    /// Exclusive.
    Exclusive,
}

impl LockLevel {
    /// Whether this level conflicts with `other` when held concurrently.
    pub fn conflicts_with(self, other: LockLevel) -> bool {
        use LockLevel::*;
        !matches!(
            (self, other),
            (None, _)
                | (_, None)
                | (Null, _)
                | (_, Null)
                | (ConcurrentRead, ConcurrentRead)
                | (ConcurrentRead, ConcurrentWrite)
                | (ConcurrentWrite, ConcurrentRead)
                | (ConcurrentWrite, ConcurrentWrite)
                | (ProtectedRead, ConcurrentRead)
                | (ProtectedRead, ConcurrentWrite)
                | (ProtectedRead, ProtectedRead)
                | (ConcurrentRead, ProtectedRead)
                | (ConcurrentWrite, ProtectedRead)
        )
    }
}

/// DLM lock state for one lock resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Lock is held at the requested level.
    Granted,
    /// Conversion (level change) is in progress.
    Converting,
    /// Waiting for the lock to be granted.
    Blocked,
    /// Lock has been bast (blocked AST) — another node wants a conflicting mode.
    Bast,
}

/// A single OCFS2 DLM lock entry.
#[derive(Debug, Clone)]
pub struct Ocfs2Lock {
    /// Resource name (hash of the lock key, up to 32 bytes).
    pub res_name: [u8; 32],
    pub res_name_len: u8,
    /// Current lock level.
    pub level: LockLevel,
    /// Current state.
    pub state: LockState,
    /// Node that currently holds the master copy.
    pub master_node: u8,
    /// Whether the lock data has been read from the master.
    pub data_valid: bool,
    /// Lock sequence number (for ordering).
    pub seq: u32,
}

impl Ocfs2Lock {
    /// Create a new lock in `Blocked` state.
    pub fn new(res_name: &[u8], level: LockLevel, master_node: u8, seq: u32) -> Result<Self> {
        if res_name.len() > 32 {
            return Err(Error::InvalidArgument);
        }
        let mut name = [0u8; 32];
        name[..res_name.len()].copy_from_slice(res_name);
        Ok(Self {
            res_name: name,
            res_name_len: res_name.len() as u8,
            level,
            state: LockState::Blocked,
            master_node,
            data_valid: false,
            seq,
        })
    }

    /// Transition to `Granted` state.
    pub fn grant(&mut self) {
        self.state = LockState::Granted;
    }

    /// Transition to `Converting` state for a level change.
    pub fn begin_convert(&mut self, new_level: LockLevel) -> Result<()> {
        if self.state != LockState::Granted {
            return Err(Error::Busy);
        }
        self.level = new_level;
        self.state = LockState::Converting;
        Ok(())
    }

    /// Receive a BAST notification — another node wants a conflicting mode.
    pub fn on_bast(&mut self) {
        if self.state == LockState::Granted {
            self.state = LockState::Bast;
        }
    }

    /// Resource name as a byte slice.
    pub fn res_name_bytes(&self) -> &[u8] {
        &self.res_name[..self.res_name_len as usize]
    }
}

/// OCFS2 DLM message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlmMsgType {
    /// Lock request from local to master.
    LockRequest,
    /// Lock grant from master to local.
    LockGrant,
    /// Lock cancel request.
    LockCancel,
    /// Blocking AST (another node needs the lock).
    Bast,
    /// Lock conversion request.
    ConvertRequest,
    /// Lock conversion granted.
    ConvertGrant,
    /// Node join notification.
    NodeJoin,
    /// Node leave notification.
    NodeLeave,
}

/// A DLM network message header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DlmMsgHeader {
    pub msg_type: u16,
    pub node_from: u8,
    pub node_to: u8,
    pub seq: u32,
    pub res_name_len: u8,
    pub lock_level: u8,
    pub _pad: u16,
}

/// Local node's cluster context.
pub struct Ocfs2ClusterContext {
    /// This node's index.
    pub local_node: u8,
    /// Bitmask of live nodes (bit N = node N is alive).
    pub live_nodes: u32,
    /// Lock table.
    locks: [Option<Ocfs2Lock>; OCFS2_MAX_LOCKS],
    lock_count: usize,
    /// Sequence counter for outbound messages.
    seq: u32,
}

impl Ocfs2ClusterContext {
    /// Create a new cluster context for the given local node index.
    pub const fn new(local_node: u8) -> Self {
        Self {
            local_node,
            live_nodes: 0,
            locks: [const { None }; OCFS2_MAX_LOCKS],
            lock_count: 0,
            seq: 0,
        }
    }

    /// Mark a node as alive.
    pub fn node_join(&mut self, node: u8) {
        if (node as usize) < OCFS2_MAX_NODES {
            self.live_nodes |= 1u32 << node;
        }
    }

    /// Mark a node as dead.
    pub fn node_leave(&mut self, node: u8) {
        if (node as usize) < OCFS2_MAX_NODES {
            self.live_nodes &= !(1u32 << node);
        }
    }

    /// Whether a node is currently alive.
    pub fn is_alive(&self, node: u8) -> bool {
        (node as usize) < OCFS2_MAX_NODES && self.live_nodes & (1u32 << node) != 0
    }

    /// Acquire a new sequence number.
    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    /// Add a lock to the local lock table.
    pub fn add_lock(&mut self, lock: Ocfs2Lock) -> Result<()> {
        if self.lock_count >= OCFS2_MAX_LOCKS {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.locks {
            if slot.is_none() {
                *slot = Some(lock);
                self.lock_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a lock by resource name.
    pub fn find_lock(&self, res_name: &[u8]) -> Option<&Ocfs2Lock> {
        self.locks
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|l| l.res_name_bytes() == res_name)
    }

    /// Look up a mutable lock by resource name.
    pub fn find_lock_mut(&mut self, res_name: &[u8]) -> Option<&mut Ocfs2Lock> {
        self.locks
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|l| l.res_name_bytes() == res_name)
    }

    /// Remove a lock from the table.
    pub fn remove_lock(&mut self, res_name: &[u8]) -> Result<()> {
        for slot in &mut self.locks {
            if slot
                .as_ref()
                .map(|l| l.res_name_bytes() == res_name)
                .unwrap_or(false)
            {
                *slot = None;
                self.lock_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Number of locks currently held.
    pub fn lock_count(&self) -> usize {
        self.lock_count
    }
}
