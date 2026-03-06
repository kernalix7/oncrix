// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CIFS/SMB file operations.
//!
//! Implements the client-side operations for the Common Internet File System
//! (CIFS/SMB2/SMB3) protocol. Handles file open/close/read/write, connection
//! negotiation stubs, and oplock/lease break handling.
//!
//! # Design
//!
//! - [`CifsFileInfo`] — per-open-file state (FID, oplock, pid)
//! - [`OplockLevel`] — oplock level (None/II/Exclusive/Batch/Lease)
//! - `cifs_open` / `cifs_close` — open/close file on server
//! - `cifs_read` / `cifs_write` — data transfer
//! - Negotiation stubs for SMB2_NEGOTIATE, SESSION_SETUP, TREE_CONNECT
//! - Oplock break handling
//! - Durable handle reconnect
//!
//! # References
//!
//! - MS-SMB2 (Open Specification)
//! - Linux `fs/cifs/file.c`, `fs/cifs/smb2ops.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum concurrent open files.
pub const MAX_OPEN_FILES: usize = 512;

/// Maximum CIFS sessions.
pub const MAX_SESSIONS: usize = 32;

/// SMB2 command codes (simplified subset).
pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_LOGOFF: u16 = 0x0002;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_WRITE: u16 = 0x0009;
pub const SMB2_OPLOCK_BREAK: u16 = 0x0012;

/// Maximum file path length.
pub const MAX_PATH_LEN: usize = 512;

/// Maximum data buffer for read/write.
pub const MAX_DATA_BUF: usize = 65536;

/// Durable handle timeout ticks.
pub const DURABLE_HANDLE_TIMEOUT: u64 = 300;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// SMB2 oplock level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OplockLevel {
    /// No oplock.
    None,
    /// Level II (shared, read-only caching).
    LevelII,
    /// Exclusive (exclusive write caching).
    Exclusive,
    /// Batch (exclusive + lazy close).
    Batch,
    /// Lease (SMB2.1+, more granular).
    Lease,
}

impl OplockLevel {
    fn as_u8(self) -> u8 {
        match self {
            OplockLevel::None => 0x00,
            OplockLevel::LevelII => 0x01,
            OplockLevel::Exclusive => 0x08,
            OplockLevel::Batch => 0x09,
            OplockLevel::Lease => 0xFF,
        }
    }
}

/// State of a CIFS open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// File is open and active.
    Open,
    /// Oplock break in progress.
    OplockBreak,
    /// File is being closed.
    Closing,
    /// Durable handle (disconnected but cached for reconnect).
    Durable,
    /// Closed.
    Closed,
}

/// Per-open-file information for a CIFS file.
#[derive(Clone)]
pub struct CifsFileInfo {
    /// File ID (FID) assigned by the server.
    pub fid: u64,
    /// Current oplock level.
    pub oplock_level: OplockLevel,
    /// PID of the process that opened the file.
    pub pid: u32,
    /// Session ID.
    pub session_id: u64,
    /// Tree ID.
    pub tree_id: u32,
    /// File path (UTF-16 stored as bytes, simplified to ASCII here).
    pub path: [u8; MAX_PATH_LEN],
    /// Path length.
    pub path_len: usize,
    /// Desired access flags (read/write/delete).
    pub access: u32,
    /// Share access (none/read/write/delete).
    pub share_access: u32,
    /// File attributes.
    pub file_attrs: u32,
    /// Current state.
    pub state: FileState,
    /// Durable handle ID (for reconnect).
    pub durable_handle: u64,
    /// Timestamp of last activity (for durable handle timeout).
    pub last_activity: u64,
    /// Slot in use.
    in_use: bool,
}

impl CifsFileInfo {
    fn empty() -> Self {
        Self {
            fid: 0,
            oplock_level: OplockLevel::None,
            pid: 0,
            session_id: 0,
            tree_id: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            access: 0,
            share_access: 0,
            file_attrs: 0,
            state: FileState::Closed,
            durable_handle: 0,
            last_activity: 0,
            in_use: false,
        }
    }

    /// Return the file path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// A CIFS session.
#[derive(Clone, Default)]
pub struct CifsSession {
    /// Session ID.
    pub id: u64,
    /// Connection state.
    pub connected: bool,
    /// Server IP (simplified: 4-byte IPv4).
    pub server_addr: [u8; 4],
    /// Tree count.
    pub tree_count: u32,
    /// In use.
    pub in_use: bool,
}

/// CIFS file table.
pub struct CifsFileTable {
    files: [CifsFileInfo; MAX_OPEN_FILES],
    count: usize,
    sessions: [CifsSession; MAX_SESSIONS],
    session_count: usize,
    next_fid: u64,
    clock: u64,
}

impl CifsFileTable {
    /// Create an empty CIFS file table.
    pub fn new() -> Self {
        Self {
            files: core::array::from_fn(|_| CifsFileInfo::empty()),
            count: 0,
            sessions: core::array::from_fn(|_| CifsSession::default()),
            session_count: 0,
            next_fid: 1,
            clock: 0,
        }
    }

    /// Advance the internal clock by `ticks`.
    pub fn advance_clock(&mut self, ticks: u64) {
        self.clock += ticks;
    }

    fn find_file(&self, fid: u64) -> Option<usize> {
        for i in 0..MAX_OPEN_FILES {
            if self.files[i].in_use && self.files[i].fid == fid {
                return Some(i);
            }
        }
        None
    }

    fn free_file_slot(&self) -> Option<usize> {
        for i in 0..MAX_OPEN_FILES {
            if !self.files[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn alloc_fid(&mut self) -> u64 {
        let fid = self.next_fid;
        self.next_fid += 1;
        fid
    }
}

impl Default for CifsFileTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Open a file on the CIFS server.
///
/// Returns the assigned FID.
pub fn cifs_open(
    table: &mut CifsFileTable,
    session_id: u64,
    tree_id: u32,
    path: &[u8],
    access: u32,
    share_access: u32,
    pid: u32,
) -> Result<u64> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(Error::InvalidArgument);
    }
    let slot = table.free_file_slot().ok_or(Error::OutOfMemory)?;
    let fid = table.alloc_fid();
    let now = table.clock;

    let mut info = CifsFileInfo::empty();
    info.fid = fid;
    info.session_id = session_id;
    info.tree_id = tree_id;
    info.path[..path.len()].copy_from_slice(path);
    info.path_len = path.len();
    info.access = access;
    info.share_access = share_access;
    info.pid = pid;
    info.state = FileState::Open;
    info.oplock_level = OplockLevel::None;
    info.last_activity = now;
    info.in_use = true;

    table.files[slot] = info;
    table.count += 1;
    Ok(fid)
}

/// Close a CIFS file.
pub fn cifs_close(table: &mut CifsFileTable, fid: u64) -> Result<()> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    table.files[slot].state = FileState::Closed;
    table.files[slot].in_use = false;
    table.count = table.count.saturating_sub(1);
    Ok(())
}

/// Read from a CIFS file.
///
/// Populates `out` with up to `out.len()` bytes from `offset`.
/// Returns the number of bytes filled (stub: fills with zeros).
pub fn cifs_read(
    table: &mut CifsFileTable,
    fid: u64,
    offset: u64,
    out: &mut [u8],
) -> Result<usize> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    if table.files[slot].state != FileState::Open {
        return Err(Error::InvalidArgument);
    }
    let _ = offset;
    // Stub: zero-fill (real impl would issue SMB2_READ RPC).
    let len = out.len().min(MAX_DATA_BUF);
    for b in out[..len].iter_mut() {
        *b = 0;
    }
    table.files[slot].last_activity = table.clock;
    Ok(len)
}

/// Write to a CIFS file.
///
/// Returns the number of bytes accepted (stub: accepts all).
pub fn cifs_write(table: &mut CifsFileTable, fid: u64, offset: u64, data: &[u8]) -> Result<usize> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    if table.files[slot].state != FileState::Open {
        return Err(Error::InvalidArgument);
    }
    let _ = offset;
    let len = data.len().min(MAX_DATA_BUF);
    table.files[slot].last_activity = table.clock;
    Ok(len)
}

/// Handle an oplock break notification from the server.
///
/// The server is asking the client to downgrade the oplock to `new_level`.
pub fn handle_oplock_break(
    table: &mut CifsFileTable,
    fid: u64,
    new_level: OplockLevel,
) -> Result<()> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    table.files[slot].state = FileState::OplockBreak;
    table.files[slot].oplock_level = new_level;
    Ok(())
}

/// Acknowledge an oplock break (client has flushed caches).
pub fn oplock_break_ack(table: &mut CifsFileTable, fid: u64) -> Result<()> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    if table.files[slot].state != FileState::OplockBreak {
        return Err(Error::InvalidArgument);
    }
    table.files[slot].state = FileState::Open;
    Ok(())
}

/// Transition a file to a durable handle (server disconnect).
pub fn make_durable(table: &mut CifsFileTable, fid: u64, durable_handle: u64) -> Result<()> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    table.files[slot].state = FileState::Durable;
    table.files[slot].durable_handle = durable_handle;
    Ok(())
}

/// Reconnect using a durable handle after server reconnect.
///
/// Returns the new FID.
pub fn reconnect_durable(
    table: &mut CifsFileTable,
    durable_handle: u64,
    new_session_id: u64,
    new_tree_id: u32,
) -> Result<u64> {
    // Find the durable file.
    let mut found_slot = None;
    for i in 0..MAX_OPEN_FILES {
        if table.files[i].in_use
            && table.files[i].state == FileState::Durable
            && table.files[i].durable_handle == durable_handle
        {
            found_slot = Some(i);
            break;
        }
    }
    let slot = found_slot.ok_or(Error::NotFound)?;
    let now = table.clock;
    if now - table.files[slot].last_activity > DURABLE_HANDLE_TIMEOUT {
        table.files[slot].in_use = false;
        table.count = table.count.saturating_sub(1);
        return Err(Error::NotFound);
    }

    let new_fid = table.alloc_fid();
    table.files[slot].fid = new_fid;
    table.files[slot].session_id = new_session_id;
    table.files[slot].tree_id = new_tree_id;
    table.files[slot].state = FileState::Open;
    table.files[slot].durable_handle = 0;
    table.files[slot].last_activity = now;
    Ok(new_fid)
}

/// Stub: SMB2 NEGOTIATE message builder.
///
/// Returns a fixed-length byte buffer with the negotiate header.
pub fn smb2_negotiate_stub(out: &mut [u8; 64]) {
    // Command
    out[0] = (SMB2_NEGOTIATE & 0xFF) as u8;
    out[1] = (SMB2_NEGOTIATE >> 8) as u8;
    // Dialect count = 1 (SMB 3.1.1)
    out[2] = 1;
    out[3] = 0;
    // Dialect = 0x0311
    out[4] = 0x11;
    out[5] = 0x03;
}

/// Stub: SMB2 SESSION_SETUP message builder.
pub fn smb2_session_setup_stub(out: &mut [u8; 64], user: &[u8]) {
    out[0] = (SMB2_SESSION_SETUP & 0xFF) as u8;
    out[1] = (SMB2_SESSION_SETUP >> 8) as u8;
    let copy = user.len().min(32);
    out[4..4 + copy].copy_from_slice(&user[..copy]);
}

/// Stub: SMB2 TREE_CONNECT message builder.
pub fn smb2_tree_connect_stub(out: &mut [u8; 64], share: &[u8]) {
    out[0] = (SMB2_TREE_CONNECT & 0xFF) as u8;
    out[1] = (SMB2_TREE_CONNECT >> 8) as u8;
    let copy = share.len().min(32);
    out[4..4 + copy].copy_from_slice(&share[..copy]);
}

/// Return the oplock level name as a static string.
pub fn oplock_level_name(level: OplockLevel) -> &'static str {
    match level {
        OplockLevel::None => "none",
        OplockLevel::LevelII => "level2",
        OplockLevel::Exclusive => "exclusive",
        OplockLevel::Batch => "batch",
        OplockLevel::Lease => "lease",
    }
}

/// Return the number of open files.
pub fn open_file_count(table: &CifsFileTable) -> usize {
    table.count
}

/// Return the SMB2 command code byte for a given operation.
pub fn smb2_cmd_byte(cmd: u16) -> [u8; 2] {
    [(cmd & 0xFF) as u8, (cmd >> 8) as u8]
}

/// Return file info by FID.
pub fn get_file_info(table: &CifsFileTable, fid: u64) -> Option<&CifsFileInfo> {
    let slot = table.find_file(fid)?;
    Some(&table.files[slot])
}

/// Set the oplock level on an open file.
pub fn set_oplock_level(table: &mut CifsFileTable, fid: u64, level: OplockLevel) -> Result<()> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    table.files[slot].oplock_level = level;
    Ok(())
}

/// Return the on-wire oplock level byte for a file.
pub fn get_oplock_byte(table: &CifsFileTable, fid: u64) -> Result<u8> {
    let slot = table.find_file(fid).ok_or(Error::NotFound)?;
    Ok(table.files[slot].oplock_level.as_u8())
}
