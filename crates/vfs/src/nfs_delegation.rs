// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS delegation management.
//!
//! NFS delegations allow a client to cache file data and metadata locally
//! without checking with the server on every access. The server grants a
//! delegation (read or write) and can recall it when another client needs
//! conflicting access.
//!
//! # Types
//!
//! - [`DelegationType`] — read or write delegation
//! - [`DelegationState`] — lifecycle: Valid → Returning → Revoked
//! - [`NfsDelegation`] — per-file delegation record
//!
//! # Operations
//!
//! - [`grant_delegation`] — server grants a new delegation
//! - [`recall_delegation`] — server initiates recall
//! - [`return_delegation`] — client returns the delegation
//! - [`test_and_free`] — check and release expired delegations
//!
//! # References
//!
//! - RFC 8881 §10 (NFSv4.1 delegations)
//! - Linux `fs/nfsd/nfs4state.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum concurrent delegations tracked.
pub const MAX_DELEGATIONS: usize = 128;

/// Maximum clients we track.
pub const MAX_CLIENTS: usize = 32;

/// Delegation stateid is 16 bytes (NFSv4 stateid format).
pub const STATEID_LEN: usize = 16;

/// Recall timeout in abstract time units (seconds equivalent).
pub const RECALL_TIMEOUT: u64 = 90;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Type of NFS delegation granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationType {
    /// Read delegation: client may cache reads, no write caching.
    Read,
    /// Write delegation: client may cache both reads and writes.
    Write,
}

/// Lifecycle state of a delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    /// Delegation is active and valid.
    Valid,
    /// Server has sent a recall; waiting for client DELEGRETURN.
    Returning,
    /// Delegation has been revoked by the server.
    Revoked,
    /// Delegation was returned cleanly by the client.
    Returned,
}

/// A single NFS delegation record.
#[derive(Clone)]
pub struct NfsDelegation {
    /// Unique stateid for this delegation (16 bytes, NFSv4 format).
    pub stateid: [u8; STATEID_LEN],
    /// Type of delegation (read or write).
    pub delegation_type: DelegationType,
    /// Current lifecycle state.
    pub state: DelegationState,
    /// Inode number the delegation covers.
    pub inode: u64,
    /// Client ID that holds this delegation.
    pub client_id: u64,
    /// Timestamp when the delegation was granted.
    pub grant_time: u64,
    /// Timestamp when recall was initiated (0 if not recalled).
    pub recall_time: u64,
    /// Slot in use.
    in_use: bool,
}

impl NfsDelegation {
    fn empty() -> Self {
        Self {
            stateid: [0u8; STATEID_LEN],
            delegation_type: DelegationType::Read,
            state: DelegationState::Returned,
            inode: 0,
            client_id: 0,
            grant_time: 0,
            recall_time: 0,
            in_use: false,
        }
    }
}

/// Table of all active delegations.
pub struct DelegationTable {
    entries: [NfsDelegation; MAX_DELEGATIONS],
    count: usize,
    /// Monotonic clock for timestamps.
    clock: u64,
}

impl DelegationTable {
    /// Create an empty delegation table.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| NfsDelegation::empty()),
            count: 0,
            clock: 0,
        }
    }

    /// Advance the internal clock by `ticks`.
    pub fn advance_clock(&mut self, ticks: u64) {
        self.clock += ticks;
    }

    fn find_by_stateid(&self, stateid: &[u8; STATEID_LEN]) -> Option<usize> {
        for i in 0..MAX_DELEGATIONS {
            if self.entries[i].in_use && self.entries[i].stateid == *stateid {
                return Some(i);
            }
        }
        None
    }

    fn find_by_inode_client(&self, inode: u64, client_id: u64) -> Option<usize> {
        for i in 0..MAX_DELEGATIONS {
            if self.entries[i].in_use
                && self.entries[i].inode == inode
                && self.entries[i].client_id == client_id
                && self.entries[i].state == DelegationState::Valid
            {
                return Some(i);
            }
        }
        None
    }

    fn free_slot(&self) -> Option<usize> {
        for i in 0..MAX_DELEGATIONS {
            if !self.entries[i].in_use {
                return Some(i);
            }
        }
        None
    }
}

impl Default for DelegationTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Grant a new delegation to `client_id` for `inode`.
///
/// Conflicts with an existing write delegation from another client cause
/// `Err(Busy)`. Returns the stateid assigned to the delegation.
pub fn grant_delegation(
    table: &mut DelegationTable,
    inode: u64,
    client_id: u64,
    dtype: DelegationType,
    stateid: [u8; STATEID_LEN],
) -> Result<[u8; STATEID_LEN]> {
    // Check for conflicting write delegation from another client.
    for i in 0..MAX_DELEGATIONS {
        if !table.entries[i].in_use {
            continue;
        }
        let d = &table.entries[i];
        if d.inode == inode
            && d.client_id != client_id
            && d.state == DelegationState::Valid
            && (d.delegation_type == DelegationType::Write || dtype == DelegationType::Write)
        {
            return Err(Error::Busy);
        }
    }

    let slot = table.free_slot().ok_or(Error::OutOfMemory)?;
    let now = table.clock;
    table.entries[slot] = NfsDelegation {
        stateid,
        delegation_type: dtype,
        state: DelegationState::Valid,
        inode,
        client_id,
        grant_time: now,
        recall_time: 0,
        in_use: true,
    };
    table.count += 1;
    Ok(stateid)
}

/// Recall a delegation identified by `stateid`.
///
/// Transitions the delegation to `Returning` state. The client must
/// call `return_delegation` within `RECALL_TIMEOUT` ticks.
pub fn recall_delegation(table: &mut DelegationTable, stateid: &[u8; STATEID_LEN]) -> Result<()> {
    let slot = table.find_by_stateid(stateid).ok_or(Error::NotFound)?;
    if table.entries[slot].state != DelegationState::Valid {
        return Err(Error::InvalidArgument);
    }
    table.entries[slot].state = DelegationState::Returning;
    table.entries[slot].recall_time = table.clock;
    Ok(())
}

/// Recall all delegations on `inode` (used when another client opens for write).
///
/// Returns the number of delegations recalled.
pub fn recall_all_on_inode(table: &mut DelegationTable, inode: u64) -> usize {
    let mut recalled = 0;
    let now = table.clock;
    for i in 0..MAX_DELEGATIONS {
        if table.entries[i].in_use
            && table.entries[i].inode == inode
            && table.entries[i].state == DelegationState::Valid
        {
            table.entries[i].state = DelegationState::Returning;
            table.entries[i].recall_time = now;
            recalled += 1;
        }
    }
    recalled
}

/// Return a delegation identified by its stateid (DELEGRETURN from client).
///
/// Frees the slot.
pub fn return_delegation(table: &mut DelegationTable, stateid: &[u8; STATEID_LEN]) -> Result<()> {
    let slot = table.find_by_stateid(stateid).ok_or(Error::NotFound)?;
    let state = table.entries[slot].state;
    if state != DelegationState::Valid && state != DelegationState::Returning {
        return Err(Error::InvalidArgument);
    }
    table.entries[slot].state = DelegationState::Returned;
    table.entries[slot].in_use = false;
    table.count = table.count.saturating_sub(1);
    Ok(())
}

/// Revoke a delegation (server-side unilateral revocation).
pub fn revoke_delegation(table: &mut DelegationTable, stateid: &[u8; STATEID_LEN]) -> Result<()> {
    let slot = table.find_by_stateid(stateid).ok_or(Error::NotFound)?;
    table.entries[slot].state = DelegationState::Revoked;
    table.entries[slot].in_use = false;
    table.count = table.count.saturating_sub(1);
    Ok(())
}

/// Test and free expired delegations.
///
/// Delegations in `Returning` state that have exceeded `RECALL_TIMEOUT` are
/// revoked. Returns the number of delegations freed.
pub fn test_and_free(table: &mut DelegationTable) -> usize {
    let now = table.clock;
    let mut freed = 0;
    for i in 0..MAX_DELEGATIONS {
        if !table.entries[i].in_use {
            continue;
        }
        if table.entries[i].state == DelegationState::Returning {
            let elapsed = now.saturating_sub(table.entries[i].recall_time);
            if elapsed >= RECALL_TIMEOUT {
                table.entries[i].state = DelegationState::Revoked;
                table.entries[i].in_use = false;
                table.count = table.count.saturating_sub(1);
                freed += 1;
            }
        }
    }
    freed
}

/// Look up the delegation for a given `client_id` / `inode` pair.
pub fn find_delegation(
    table: &DelegationTable,
    inode: u64,
    client_id: u64,
) -> Option<&NfsDelegation> {
    let slot = table.find_by_inode_client(inode, client_id)?;
    Some(&table.entries[slot])
}

/// Return the number of active delegations.
pub fn delegation_count(table: &DelegationTable) -> usize {
    table.count
}

/// Collect stateid values of all delegations for `inode` into `out`.
///
/// Returns the number written.
pub fn list_delegations_for_inode(
    table: &DelegationTable,
    inode: u64,
    out: &mut [[u8; STATEID_LEN]],
) -> usize {
    let mut written = 0;
    for i in 0..MAX_DELEGATIONS {
        if written >= out.len() {
            break;
        }
        if table.entries[i].in_use && table.entries[i].inode == inode {
            out[written] = table.entries[i].stateid;
            written += 1;
        }
    }
    written
}
