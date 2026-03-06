// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS write-back — write page cache data to an NFS server.
//!
//! NFS writes are asynchronous: data is first accumulated in the page cache
//! and then flushed to the server via WRITE RPCs. After a WRITE, the server
//! may return UNSTABLE (not yet on stable storage), requiring a COMMIT RPC
//! to ensure durability.
//!
//! # Design
//!
//! - [`StableHow`] — NFS write stability level
//! - [`NfsWriteData`] — per-write operation descriptor
//! - `nfs_write_pages` — flush dirty pages to server
//! - `writeback_done` — handle RPC completion callback
//! - `commit_write` — send COMMIT RPC to promote UNSTABLE → FILE_SYNC
//!
//! # References
//!
//! - RFC 8881 §18.32 (WRITE procedure)
//! - RFC 8881 §18.3  (COMMIT procedure)
//! - Linux `fs/nfs/write.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum concurrent write descriptors.
pub const MAX_WRITE_DESCS: usize = 128;

/// Maximum bytes per NFS write RPC.
pub const NFS_MAX_WRITE_SIZE: usize = 1_048_576; // 1 MiB

/// Maximum retry count for failed writes.
pub const MAX_WRITE_RETRIES: u32 = 3;

/// Write verifier length (8 bytes, server-assigned).
pub const NFS_WRITE_VERIFIER_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// NFS write stability level (how durably the server commits the data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableHow {
    /// Data may be held in server's volatile memory.
    Unstable,
    /// Data must be written to the server's non-volatile storage for the
    /// file's metadata (data may remain in volatile storage).
    DataSync,
    /// Data and metadata must be on stable storage before replying.
    FileSync,
}

impl StableHow {
    /// NFS on-wire value.
    pub fn as_u32(self) -> u32 {
        match self {
            StableHow::Unstable => 0,
            StableHow::DataSync => 1,
            StableHow::FileSync => 2,
        }
    }

    /// Convert from on-wire value.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(StableHow::Unstable),
            1 => Some(StableHow::DataSync),
            2 => Some(StableHow::FileSync),
            _ => None,
        }
    }
}

/// State of an NFS write descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteState {
    /// Pending — not yet sent to server.
    Pending,
    /// In flight — RPC sent, awaiting reply.
    InFlight,
    /// Completed successfully.
    Done,
    /// Failed; may be retried.
    Error,
    /// Committed via COMMIT RPC.
    Committed,
}

/// Descriptor for a single NFS write operation.
#[derive(Clone)]
pub struct NfsWriteData {
    /// Unique descriptor ID.
    pub id: u64,
    /// Inode number being written.
    pub inode: u64,
    /// File offset of this write.
    pub offset: u64,
    /// Number of bytes to write.
    pub count: usize,
    /// Requested stability.
    pub stable_how: StableHow,
    /// Data buffer (up to NFS_MAX_WRITE_SIZE).
    pub data: [u8; 65536], // 64 KiB per descriptor
    /// Actual bytes in `data`.
    pub data_len: usize,
    /// Write verifier returned by server.
    pub verifier: [u8; NFS_WRITE_VERIFIER_LEN],
    /// Stability level actually achieved (from server reply).
    pub committed: StableHow,
    /// Current state.
    pub state: WriteState,
    /// Retry count.
    pub retries: u32,
    /// Error code (if state == Error).
    pub error: i32,
    /// Slot in use.
    in_use: bool,
}

impl NfsWriteData {
    fn empty() -> Self {
        Self {
            id: 0,
            inode: 0,
            offset: 0,
            count: 0,
            stable_how: StableHow::FileSync,
            data: [0u8; 65536],
            data_len: 0,
            verifier: [0u8; NFS_WRITE_VERIFIER_LEN],
            committed: StableHow::Unstable,
            state: WriteState::Pending,
            retries: 0,
            error: 0,
            in_use: false,
        }
    }
}

/// NFS write-back state for a single NFS mount.
pub struct NfsWriteback {
    descs: [NfsWriteData; MAX_WRITE_DESCS],
    count: usize,
    next_id: u64,
    /// Commit verifier (must match across all WRITE → COMMIT pairs).
    pub commit_verifier: [u8; NFS_WRITE_VERIFIER_LEN],
    /// Number of bytes committed but not yet synced.
    pub unstable_bytes: u64,
}

impl NfsWriteback {
    /// Create a new write-back tracker.
    pub fn new() -> Self {
        Self {
            descs: core::array::from_fn(|_| NfsWriteData::empty()),
            count: 0,
            next_id: 1,
            commit_verifier: [0u8; NFS_WRITE_VERIFIER_LEN],
            unstable_bytes: 0,
        }
    }

    fn find(&self, id: u64) -> Option<usize> {
        for i in 0..MAX_WRITE_DESCS {
            if self.descs[i].in_use && self.descs[i].id == id {
                return Some(i);
            }
        }
        None
    }

    fn free_slot(&self) -> Option<usize> {
        for i in 0..MAX_WRITE_DESCS {
            if !self.descs[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl Default for NfsWriteback {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Submit a write of `data` for `inode` at `offset`.
///
/// Returns the write descriptor ID.
pub fn nfs_write_pages(
    wb: &mut NfsWriteback,
    inode: u64,
    offset: u64,
    data: &[u8],
    stable_how: StableHow,
) -> Result<u64> {
    if data.is_empty() || data.len() > NFS_MAX_WRITE_SIZE {
        return Err(Error::InvalidArgument);
    }
    if data.len() > 65536 {
        return Err(Error::InvalidArgument);
    }
    let slot = wb.free_slot().ok_or(Error::OutOfMemory)?;
    let id = wb.alloc_id();

    let mut desc = NfsWriteData::empty();
    desc.id = id;
    desc.inode = inode;
    desc.offset = offset;
    desc.count = data.len();
    desc.stable_how = stable_how;
    desc.data[..data.len()].copy_from_slice(data);
    desc.data_len = data.len();
    desc.state = WriteState::Pending;
    desc.in_use = true;

    wb.descs[slot] = desc;
    wb.count += 1;
    Ok(id)
}

/// Mark a write as in-flight (RPC has been dispatched).
pub fn write_dispatch(wb: &mut NfsWriteback, id: u64) -> Result<()> {
    let slot = wb.find(id).ok_or(Error::NotFound)?;
    if wb.descs[slot].state != WriteState::Pending {
        return Err(Error::InvalidArgument);
    }
    wb.descs[slot].state = WriteState::InFlight;
    Ok(())
}

/// Handle write RPC completion.
///
/// `committed` is the stability level actually achieved. `verifier` is the
/// server's write verifier. On UNSTABLE writes, unstable_bytes is updated.
pub fn writeback_done(
    wb: &mut NfsWriteback,
    id: u64,
    committed: StableHow,
    verifier: &[u8; NFS_WRITE_VERIFIER_LEN],
    error: i32,
) -> Result<()> {
    let slot = wb.find(id).ok_or(Error::NotFound)?;
    if error != 0 {
        wb.descs[slot].state = WriteState::Error;
        wb.descs[slot].error = error;
        return Ok(());
    }
    wb.descs[slot].committed = committed;
    wb.descs[slot].verifier = *verifier;
    wb.descs[slot].state = WriteState::Done;
    if committed == StableHow::Unstable {
        wb.unstable_bytes += wb.descs[slot].count as u64;
    }
    Ok(())
}

/// Retry a failed write descriptor.
///
/// Resets state to Pending and increments retry count.
/// Returns `Err(IoError)` if max retries exceeded.
pub fn retry_write(wb: &mut NfsWriteback, id: u64) -> Result<()> {
    let slot = wb.find(id).ok_or(Error::NotFound)?;
    if wb.descs[slot].state != WriteState::Error {
        return Err(Error::InvalidArgument);
    }
    if wb.descs[slot].retries >= MAX_WRITE_RETRIES {
        return Err(Error::IoError);
    }
    wb.descs[slot].retries += 1;
    wb.descs[slot].error = 0;
    wb.descs[slot].state = WriteState::Pending;
    Ok(())
}

/// Send a COMMIT RPC for inode `inode`.
///
/// Marks all UNSTABLE writes for `inode` as Committed and decrements
/// `unstable_bytes`. Sets the commit verifier.
///
/// Returns the number of bytes committed.
pub fn commit_write(
    wb: &mut NfsWriteback,
    inode: u64,
    verifier: &[u8; NFS_WRITE_VERIFIER_LEN],
) -> Result<u64> {
    let mut committed = 0u64;
    for i in 0..MAX_WRITE_DESCS {
        if !wb.descs[i].in_use {
            continue;
        }
        if wb.descs[i].inode == inode
            && wb.descs[i].state == WriteState::Done
            && wb.descs[i].committed == StableHow::Unstable
        {
            wb.descs[i].state = WriteState::Committed;
            committed += wb.descs[i].count as u64;
        }
    }
    if committed > 0 {
        wb.unstable_bytes = wb.unstable_bytes.saturating_sub(committed);
        wb.commit_verifier = *verifier;
    }
    Ok(committed)
}

/// Free a completed or committed write descriptor.
pub fn free_write(wb: &mut NfsWriteback, id: u64) -> Result<()> {
    let slot = wb.find(id).ok_or(Error::NotFound)?;
    let state = wb.descs[slot].state;
    if state != WriteState::Done && state != WriteState::Committed && state != WriteState::Error {
        return Err(Error::Busy);
    }
    wb.descs[slot] = NfsWriteData::empty();
    wb.count = wb.count.saturating_sub(1);
    Ok(())
}

/// Return the number of pending/in-flight write descriptors.
pub fn pending_write_count(wb: &NfsWriteback) -> usize {
    let mut count = 0;
    for i in 0..MAX_WRITE_DESCS {
        if wb.descs[i].in_use
            && (wb.descs[i].state == WriteState::Pending
                || wb.descs[i].state == WriteState::InFlight)
        {
            count += 1;
        }
    }
    count
}

/// Return the total unstable bytes for a specific inode.
pub fn unstable_bytes_for_inode(wb: &NfsWriteback, inode: u64) -> u64 {
    let mut total = 0u64;
    for i in 0..MAX_WRITE_DESCS {
        if wb.descs[i].in_use
            && wb.descs[i].inode == inode
            && wb.descs[i].state == WriteState::Done
            && wb.descs[i].committed == StableHow::Unstable
        {
            total += wb.descs[i].count as u64;
        }
    }
    total
}
