// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OCFS2 distributed lock manager (DLM) glue.
//!
//! OCFS2 (Oracle Cluster Filesystem 2) uses a userspace DLM daemon
//! (`ocfs2_dlm`) to coordinate access to shared resources across cluster
//! nodes.  This module implements the kernel-side glue layer that:
//!
//! - Maintains a table of lock resources (`lockres`), one per protected
//!   object (inode, dentry, superblock, etc.).
//! - Requests lock grants/conversions from the DLM daemon via message
//!   passing.
//! - Invokes AST (Asynchronous Status Callback) and BAST (Blocking AST)
//!   callbacks when lock state changes.
//! - Handles distributed lock recovery on node failure.
//! - Tracks per-resource master election results.
//!
//! # Lock levels
//!
//! ```text
//! NL  < PR (shared)  < EX (exclusive)
//! ```
//!
//! A lock at level NL does not grant any access; PR is a read-lock shared
//! by many holders; EX is an exclusive write-lock.
//!
//! # References
//!
//! - Linux `fs/ocfs2/dlmglue.c`, `fs/ocfs2/dlm/`
//! - OCFS2 cluster design document

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of lock resources tracked per node.
pub const MAX_LOCKRES: usize = 256;

/// Maximum lock resource name length.
pub const LOCKRES_NAME_LEN: usize = 32;

/// Maximum number of cluster nodes.
pub const MAX_NODES: usize = 32;

/// Sentinel node ID meaning "no master elected".
pub const NO_MASTER: u8 = u8::MAX;

// ── LockLevel ─────────────────────────────────────────────────────────────────

/// DLM lock level (mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum LockLevel {
    /// Null lock — no access grant.
    #[default]
    Nl = 0,
    /// Protected read — shared read access.
    Pr = 1,
    /// Exclusive — exclusive write access.
    Ex = 2,
}

impl LockLevel {
    /// Return true if this level is compatible with `other` when held concurrently.
    pub fn compatible_with(self, other: LockLevel) -> bool {
        // NL is always compatible.  PR+PR is compatible.  EX is incompatible with all.
        matches!(
            (self, other),
            (LockLevel::Nl, _) | (_, LockLevel::Nl) | (LockLevel::Pr, LockLevel::Pr)
        )
    }
}

// ── LockState ─────────────────────────────────────────────────────────────────

/// Current state of a lock resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockState {
    /// Not yet initialized.
    #[default]
    Uninit,
    /// Lock is being requested from the DLM.
    Pending,
    /// Lock has been granted at the current level.
    Granted,
    /// Lock conversion is in progress.
    Converting,
    /// Lock is being unlocked / released.
    Freeing,
    /// Lock recovery is in progress following a node failure.
    Recovering,
}

// ── AstKind ───────────────────────────────────────────────────────────────────

/// Kind of DLM callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstKind {
    /// AST: the requested lock level has been granted.
    Grant,
    /// BAST: a conflicting lock request has arrived; downgrade requested.
    Blocking { requested_level: LockLevel },
}

// ── LockResFlags ──────────────────────────────────────────────────────────────

/// Bit-flags for a lock resource.
#[derive(Debug, Clone, Copy, Default)]
pub struct LockResFlags(u32);

impl LockResFlags {
    /// Lock resource has a pending AST callback.
    pub const PENDING_AST: u32 = 1 << 0;
    /// Lock resource has a pending BAST callback.
    pub const PENDING_BAST: u32 = 1 << 1;
    /// Lock resource is being migrated to a new master.
    pub const MIGRATING: u32 = 1 << 2;
    /// Lock recovery is needed for this resource.
    pub const RECOVERY_NEEDED: u32 = 1 << 3;

    /// Set a flag bit.
    pub fn set(&mut self, bit: u32) {
        self.0 |= bit;
    }

    /// Clear a flag bit.
    pub fn clear(&mut self, bit: u32) {
        self.0 &= !bit;
    }

    /// Test a flag bit.
    pub fn has(&self, bit: u32) -> bool {
        self.0 & bit != 0
    }
}

// ── LockRes ───────────────────────────────────────────────────────────────────

/// A single OCFS2 DLM lock resource.
#[derive(Debug)]
pub struct LockRes {
    /// Name identifying this lock resource in the cluster.
    pub name: [u8; LOCKRES_NAME_LEN],
    /// Meaningful bytes in `name`.
    pub name_len: usize,
    /// Currently held lock level.
    pub level: LockLevel,
    /// Lock level being converted to (during conversion).
    pub convert_target: LockLevel,
    /// Current state of this lock resource.
    pub state: LockState,
    /// Node ID of the current master for this lock.
    pub master_node: u8,
    /// This node's ID.
    pub local_node: u8,
    /// Miscellaneous flags.
    pub flags: LockResFlags,
    /// Number of current holders (PR level can have multiple).
    pub holders: u32,
    /// Number of pending AST callbacks waiting to fire.
    pub pending_asts: u32,
    /// DLM-assigned lock identifier.
    pub lock_id: u64,
    /// Whether this entry is in use.
    pub in_use: bool,
}

impl LockRes {
    /// Create an uninitialised, empty lock resource.
    pub const fn new_empty() -> Self {
        Self {
            name: [0u8; LOCKRES_NAME_LEN],
            name_len: 0,
            level: LockLevel::Nl,
            convert_target: LockLevel::Nl,
            state: LockState::Uninit,
            master_node: NO_MASTER,
            local_node: 0,
            flags: LockResFlags(0),
            holders: 0,
            pending_asts: 0,
            lock_id: 0,
            in_use: false,
        }
    }

    /// Initialise a lock resource with the given name and local node ID.
    pub fn init(&mut self, name: &[u8], local_node: u8) -> Result<()> {
        let len = name.len().min(LOCKRES_NAME_LEN);
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
        self.local_node = local_node;
        self.state = LockState::Pending;
        self.in_use = true;
        Ok(())
    }

    /// Handle an AST callback from the DLM.
    pub fn handle_ast(&mut self, kind: AstKind) -> Result<()> {
        match kind {
            AstKind::Grant => {
                self.state = LockState::Granted;
                self.flags.clear(LockResFlags::PENDING_AST);
                self.level = self.convert_target;
                self.pending_asts = self.pending_asts.saturating_sub(1);
                Ok(())
            }
            AstKind::Blocking { requested_level } => {
                // BAST: a remote node wants a lock at `requested_level`.
                // If our level conflicts, downgrade is needed.
                if !self.level.compatible_with(requested_level) {
                    self.flags.set(LockResFlags::PENDING_BAST);
                }
                Ok(())
            }
        }
    }

    /// Request a lock level conversion.
    ///
    /// Returns `Busy` if a conversion is already in progress.
    pub fn request_convert(&mut self, target: LockLevel) -> Result<()> {
        if self.state == LockState::Converting {
            return Err(Error::Busy);
        }
        if self.state != LockState::Granted {
            return Err(Error::InvalidArgument);
        }
        self.convert_target = target;
        self.state = LockState::Converting;
        self.flags.set(LockResFlags::PENDING_AST);
        self.pending_asts += 1;
        Ok(())
    }

    /// Release this lock resource, downgrading to NL.
    pub fn release(&mut self) -> Result<()> {
        if self.holders > 0 {
            self.holders -= 1;
        }
        if self.holders == 0 {
            self.state = LockState::Freeing;
            self.level = LockLevel::Nl;
        }
        Ok(())
    }
}

// ── DlmTable ──────────────────────────────────────────────────────────────────

/// Cluster-wide DLM lock resource table for this node.
pub struct DlmTable {
    /// Fixed-size lock resource pool.
    resources: [LockRes; MAX_LOCKRES],
    /// Number of in-use lock resources.
    count: usize,
    /// This node's cluster ID.
    pub local_node: u8,
    /// Bitmask of live cluster nodes (bit N = node N is alive).
    pub live_nodes: u64,
}

impl DlmTable {
    /// Create an empty DLM table for the given node.
    pub const fn new(local_node: u8) -> Self {
        Self {
            resources: [const { LockRes::new_empty() }; MAX_LOCKRES],
            count: 0,
            local_node,
            live_nodes: 0,
        }
    }

    /// Find a lock resource by name, returning its index.
    pub fn find(&self, name: &[u8]) -> Option<usize> {
        let len = name.len().min(LOCKRES_NAME_LEN);
        self.resources[..self.count]
            .iter()
            .position(|r| r.in_use && r.name_len == len && r.name[..len] == name[..len])
    }

    /// Get a mutable reference to the lock resource at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut LockRes> {
        if idx >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.resources[idx])
    }

    /// Obtain or create a lock resource by name, requesting it at `level`.
    ///
    /// Returns the index of the (possibly newly created) resource.
    pub fn lock(&mut self, name: &[u8], level: LockLevel) -> Result<usize> {
        // Existing?
        if let Some(idx) = self.find(name) {
            let res = &mut self.resources[idx];
            if res.level >= level {
                res.holders += 1;
                return Ok(idx);
            }
            res.request_convert(level)?;
            return Ok(idx);
        }
        // Allocate new.
        if self.count >= MAX_LOCKRES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.resources[idx].init(name, self.local_node)?;
        self.resources[idx].convert_target = level;
        self.resources[idx].holders = 1;
        self.count += 1;
        Ok(idx)
    }

    /// Mark all lock resources as needing recovery for the failed node.
    ///
    /// Called when a cluster node is detected as dead.
    pub fn node_down(&mut self, failed_node: u8) {
        self.live_nodes &= !(1u64 << failed_node);
        for res in self.resources[..self.count].iter_mut() {
            if res.in_use && res.master_node == failed_node {
                res.flags.set(LockResFlags::RECOVERY_NEEDED);
                res.state = LockState::Recovering;
                res.master_node = NO_MASTER;
            }
        }
    }

    /// Elect this node as master for resources whose master failed.
    ///
    /// Returns the number of resources for which this node became master.
    pub fn elect_master_for_recovering(&mut self) -> u32 {
        let mut elected = 0u32;
        for res in self.resources[..self.count].iter_mut() {
            if res.in_use
                && res.flags.has(LockResFlags::RECOVERY_NEEDED)
                && res.master_node == NO_MASTER
            {
                res.master_node = self.local_node;
                res.flags.clear(LockResFlags::RECOVERY_NEEDED);
                res.state = LockState::Granted;
                elected += 1;
            }
        }
        elected
    }

    /// Return the number of lock resources currently tracked.
    pub fn resource_count(&self) -> usize {
        self.count
    }
}
