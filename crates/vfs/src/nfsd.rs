// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS server-side export and dispatch.
//!
//! Implements the NFS server (nfsd) infrastructure for exporting local
//! filesystems to remote NFS clients. This module manages the export
//! table, file handle encoding/decoding, and RPC dispatch for NFS v3
//! and v4 operations.
//!
//! # Architecture
//!
//! ```text
//! NfsdSubsystem
//!   ├── ExportTable[0..MAX_EXPORTS]
//!   │     └── NfsdExport (path, flags, client restrictions)
//!   ├── FileHandleTable[0..MAX_FILE_HANDLES]
//!   │     └── FileHandleV4 (export_id, inode, generation)
//!   ├── NfsDispatcher
//!   │     └── NfsProc dispatch (NULL, GETATTR, READ, WRITE, ...)
//!   └── NfsdStats (RPC counters)
//! ```
//!
//! # File Handle Encoding
//!
//! File handles encode the export ID, inode number, and generation
//! counter into a fixed-size opaque token. The server uses these to
//! map incoming NFS requests back to local filesystem objects without
//! maintaining per-client state (v3) or with minimal session state (v4).
//!
//! # References
//!
//! - RFC 1813 — NFS Version 3 Protocol Specification
//! - RFC 7530 — NFS Version 4 Protocol
//! - Linux `fs/nfsd/` — kernel NFS server

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of exports in the export table.
const MAX_EXPORTS: usize = 64;

/// Maximum path length for an export path.
const MAX_EXPORT_PATH: usize = 256;

/// Maximum number of file handles tracked by the server.
const MAX_FILE_HANDLES: usize = 512;

/// File handle size in bytes (opaque wire format).
const FILE_HANDLE_SIZE: usize = 32;

/// Maximum number of allowed clients per export.
const MAX_CLIENTS_PER_EXPORT: usize = 8;

/// Maximum number of pending NFS requests.
const MAX_PENDING_REQUESTS: usize = 128;

/// NFS v3 program number.
pub const NFS_PROGRAM: u32 = 100003;

/// NFS v4 program number (same as v3).
pub const NFS4_PROGRAM: u32 = 100003;

/// MOUNT program number.
pub const MOUNT_PROGRAM: u32 = 100005;

// ── NfsVersion ──────────────────────────────────────────────────

/// NFS protocol version supported by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsVersion {
    /// NFS version 3 (stateless, RFC 1813).
    V3,
    /// NFS version 4.0 (stateful, RFC 7530).
    V4,
    /// NFS version 4.1 (sessions, RFC 5661).
    V41,
}

impl NfsVersion {
    /// Return the numeric version number.
    pub fn number(&self) -> u32 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V41 => 4,
        }
    }

    /// Return the minor version (0 for v3/v4, 1 for v4.1).
    pub fn minor(&self) -> u32 {
        match self {
            Self::V3 | Self::V4 => 0,
            Self::V41 => 1,
        }
    }
}

// ── ExportOptions ───────────────────────────────────────────────

/// Export permission flags for an NFS export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Bitfield of export flags.
    pub flags: u32,
}

impl ExportOptions {
    /// No special flags.
    pub const NONE: u32 = 0;
    /// Export is read-only.
    pub const READ_ONLY: u32 = 1 << 0;
    /// Root squash: map uid 0 to anonymous.
    pub const ROOT_SQUASH: u32 = 1 << 1;
    /// All squash: map all uids to anonymous.
    pub const ALL_SQUASH: u32 = 1 << 2;
    /// Synchronous writes required.
    pub const SYNC: u32 = 1 << 3;
    /// Asynchronous writes allowed.
    pub const ASYNC: u32 = 1 << 4;
    /// Subtree checking enabled.
    pub const SUBTREE_CHECK: u32 = 1 << 5;
    /// Cross-device mounts allowed.
    pub const CROSSMNT: u32 = 1 << 6;

    /// Create options with the given flags.
    pub const fn new(flags: u32) -> Self {
        Self { flags }
    }

    /// Whether the export is read-only.
    pub fn is_read_only(&self) -> bool {
        self.flags & Self::READ_ONLY != 0
    }

    /// Whether root squash is enabled.
    pub fn is_root_squash(&self) -> bool {
        self.flags & Self::ROOT_SQUASH != 0
    }

    /// Whether synchronous writes are required.
    pub fn is_sync(&self) -> bool {
        self.flags & Self::SYNC != 0
    }

    /// Whether a specific flag is set.
    pub fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self::new(Self::ROOT_SQUASH | Self::SYNC)
    }
}

// ── NfsdExport ──────────────────────────────────────────────────

/// An NFS export entry defining which local path is exported and
/// to which clients.
///
/// Each export maps a local filesystem path to a network-accessible
/// share with configurable permissions and client restrictions.
#[derive(Clone)]
pub struct NfsdExport {
    /// Export path (e.g., b"/srv/nfs").
    pub path: [u8; MAX_EXPORT_PATH],
    /// Length of valid bytes in `path`.
    pub path_len: usize,
    /// Export options (read-only, root-squash, etc.).
    pub options: ExportOptions,
    /// Allowed client addresses (IPv4 as u32; 0 = any).
    pub clients: [u32; MAX_CLIENTS_PER_EXPORT],
    /// Number of configured client restrictions.
    pub client_count: usize,
    /// Filesystem ID for this export (unique per export).
    pub fsid: u32,
    /// Whether this export slot is active.
    pub active: bool,
}

impl NfsdExport {
    /// Create an empty (inactive) export slot.
    pub const fn empty() -> Self {
        Self {
            path: [0u8; MAX_EXPORT_PATH],
            path_len: 0,
            options: ExportOptions::new(0),
            clients: [0u32; MAX_CLIENTS_PER_EXPORT],
            client_count: 0,
            fsid: 0,
            active: false,
        }
    }

    /// Create a new export for the given path.
    pub fn new(path: &[u8], fsid: u32, options: ExportOptions) -> Result<Self> {
        if path.len() > MAX_EXPORT_PATH {
            return Err(Error::InvalidArgument);
        }
        let mut export = Self::empty();
        export.path[..path.len()].copy_from_slice(path);
        export.path_len = path.len();
        export.fsid = fsid;
        export.options = options;
        export.active = true;
        Ok(export)
    }

    /// Return the export path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Add a client address to the allowed list.
    pub fn add_client(&mut self, addr: u32) -> Result<()> {
        if self.client_count >= MAX_CLIENTS_PER_EXPORT {
            return Err(Error::OutOfMemory);
        }
        self.clients[self.client_count] = addr;
        self.client_count += 1;
        Ok(())
    }

    /// Check whether a client address is allowed.
    ///
    /// Returns `true` if the client list is empty (any client)
    /// or if the address is in the list.
    pub fn is_client_allowed(&self, addr: u32) -> bool {
        if self.client_count == 0 {
            return true;
        }
        self.clients[..self.client_count].contains(&addr)
    }

    /// Map a UID through root squash rules.
    ///
    /// If root squash is enabled and uid == 0, returns 65534 (nobody).
    /// If all squash is enabled, always returns 65534.
    pub fn squash_uid(&self, uid: u32) -> u32 {
        if self.options.has(ExportOptions::ALL_SQUASH) {
            return 65534;
        }
        if self.options.is_root_squash() && uid == 0 {
            return 65534;
        }
        uid
    }
}

impl core::fmt::Debug for NfsdExport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NfsdExport")
            .field("path_len", &self.path_len)
            .field("fsid", &self.fsid)
            .field("options", &self.options)
            .field("client_count", &self.client_count)
            .field("active", &self.active)
            .finish()
    }
}

// ── FileHandleV4 ────────────────────────────────────────────────

/// Server-side file handle encoding for NFS v3/v4.
///
/// The file handle encodes enough information to identify a
/// filesystem object without per-client state: the export ID,
/// inode number, and generation counter for stale-handle detection.
#[derive(Debug, Clone, Copy)]
pub struct FileHandleV4 {
    /// Export table index this handle belongs to.
    pub export_id: u16,
    /// Inode number within the exported filesystem.
    pub ino: u64,
    /// Inode generation counter (detects stale handles after delete+reuse).
    pub generation: u32,
    /// Handle version (for future format changes).
    pub version: u8,
    /// Whether this handle slot is valid.
    pub valid: bool,
}

impl FileHandleV4 {
    /// Create an empty (invalid) file handle.
    pub const fn empty() -> Self {
        Self {
            export_id: 0,
            ino: 0,
            generation: 0,
            version: 1,
            valid: false,
        }
    }

    /// Create a new file handle.
    pub fn new(export_id: u16, ino: u64, generation: u32) -> Self {
        Self {
            export_id,
            ino,
            generation,
            version: 1,
            valid: true,
        }
    }

    /// Encode the file handle to a 32-byte wire buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < FILE_HANDLE_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf[0] = self.version;
        buf[1] = 0; // reserved
        buf[2..4].copy_from_slice(&self.export_id.to_le_bytes());
        buf[4..12].copy_from_slice(&self.ino.to_le_bytes());
        buf[12..16].copy_from_slice(&self.generation.to_le_bytes());
        // Remaining 16 bytes: zero padding.
        buf[16..FILE_HANDLE_SIZE].fill(0);
        Ok(())
    }

    /// Decode a file handle from a 32-byte wire buffer.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < FILE_HANDLE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let version = buf[0];
        if version != 1 {
            return Err(Error::InvalidArgument);
        }
        let export_id = u16::from_le_bytes([buf[2], buf[3]]);
        let ino = u64::from_le_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let generation = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok(Self {
            export_id,
            ino,
            generation,
            version,
            valid: true,
        })
    }
}

// ── NfsProc ─────────────────────────────────────────────────────

/// NFS procedure codes for RPC dispatch.
///
/// These represent the operations a client can invoke. The server
/// dispatches incoming RPCs based on the procedure number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsProc {
    /// NULL procedure (ping/keepalive).
    Null,
    /// GETATTR — retrieve file attributes.
    Getattr,
    /// SETATTR — set file attributes.
    Setattr,
    /// LOOKUP — resolve a name in a directory.
    Lookup,
    /// ACCESS — check access permissions.
    Access,
    /// READ — read file data.
    Read,
    /// WRITE — write file data.
    Write,
    /// CREATE — create a regular file.
    Create,
    /// MKDIR — create a directory.
    Mkdir,
    /// REMOVE — delete a file.
    Remove,
    /// RMDIR — remove a directory.
    Rmdir,
    /// RENAME — rename/move a file.
    Rename,
    /// READDIR — list directory entries.
    Readdir,
    /// READDIRPLUS — list directory entries with attributes.
    Readdirplus,
    /// FSSTAT — filesystem statistics.
    Fsstat,
    /// FSINFO — filesystem information.
    Fsinfo,
    /// COMMIT — flush buffered writes to stable storage.
    Commit,
}

impl NfsProc {
    /// Parse from a u32 procedure number (v3 numbering).
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::Getattr),
            2 => Some(Self::Setattr),
            3 => Some(Self::Lookup),
            4 => Some(Self::Access),
            6 => Some(Self::Read),
            7 => Some(Self::Write),
            8 => Some(Self::Create),
            9 => Some(Self::Mkdir),
            12 => Some(Self::Remove),
            13 => Some(Self::Rmdir),
            14 => Some(Self::Rename),
            16 => Some(Self::Readdir),
            17 => Some(Self::Readdirplus),
            18 => Some(Self::Fsstat),
            19 => Some(Self::Fsinfo),
            21 => Some(Self::Commit),
            _ => None,
        }
    }

    /// Return the procedure number.
    pub fn number(&self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Getattr => 1,
            Self::Setattr => 2,
            Self::Lookup => 3,
            Self::Access => 4,
            Self::Read => 6,
            Self::Write => 7,
            Self::Create => 8,
            Self::Mkdir => 9,
            Self::Remove => 12,
            Self::Rmdir => 13,
            Self::Rename => 14,
            Self::Readdir => 16,
            Self::Readdirplus => 17,
            Self::Fsstat => 18,
            Self::Fsinfo => 19,
            Self::Commit => 21,
        }
    }
}

// ── NfsdRequest ─────────────────────────────────────────────────

/// State of an NFS server-side request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsdRequestState {
    /// Slot is idle.
    Idle,
    /// Request received, awaiting dispatch.
    Pending,
    /// Request is being processed.
    Processing,
    /// Response is ready for transmission.
    Complete,
    /// Request failed with an error.
    Failed,
}

/// A pending NFS server request.
#[derive(Debug, Clone, Copy)]
pub struct NfsdRequest {
    /// Transaction ID (XID) from the RPC header.
    pub xid: u32,
    /// NFS procedure to invoke.
    pub proc_id: NfsProc,
    /// File handle from the request.
    pub fh: FileHandleV4,
    /// Client IPv4 address.
    pub client_addr: u32,
    /// Byte offset for READ/WRITE.
    pub offset: u64,
    /// Byte count for READ/WRITE.
    pub count: u32,
    /// Request state.
    pub state: NfsdRequestState,
    /// Result code (0 = success, non-zero = NFS error).
    pub result: i32,
}

impl NfsdRequest {
    /// Create an idle request slot.
    pub const fn empty() -> Self {
        Self {
            xid: 0,
            proc_id: NfsProc::Null,
            fh: FileHandleV4::empty(),
            client_addr: 0,
            offset: 0,
            count: 0,
            state: NfsdRequestState::Idle,
            result: 0,
        }
    }
}

// ── NfsdStats ───────────────────────────────────────────────────

/// Cumulative NFS server statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct NfsdStats {
    /// Total RPCs received.
    pub rpcs_received: u64,
    /// Total RPCs completed successfully.
    pub rpcs_completed: u64,
    /// Total RPCs that failed.
    pub rpcs_failed: u64,
    /// Total bytes read by clients.
    pub bytes_read: u64,
    /// Total bytes written by clients.
    pub bytes_written: u64,
    /// Total LOOKUP operations.
    pub lookups: u64,
    /// Total READDIR operations.
    pub readdirs: u64,
}

impl NfsdStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            rpcs_received: 0,
            rpcs_completed: 0,
            rpcs_failed: 0,
            bytes_read: 0,
            bytes_written: 0,
            lookups: 0,
            readdirs: 0,
        }
    }
}

// ── NfsdSubsystem ───────────────────────────────────────────────

/// Top-level NFS server subsystem.
///
/// Manages the export table, file handle table, request queue, and
/// statistics. Provides the public API for exporting filesystems and
/// handling incoming NFS RPCs.
pub struct NfsdSubsystem {
    /// Export table.
    exports: [NfsdExport; MAX_EXPORTS],
    /// Export count.
    export_count: usize,
    /// File handle table.
    handles: [FileHandleV4; MAX_FILE_HANDLES],
    /// Handle count.
    handle_count: usize,
    /// Pending request queue.
    requests: [NfsdRequest; MAX_PENDING_REQUESTS],
    /// Cumulative statistics.
    stats: NfsdStats,
    /// Next FSID for new exports.
    next_fsid: u32,
}

impl NfsdSubsystem {
    /// Create a new NFS server subsystem.
    pub fn new() -> Self {
        Self {
            exports: [const { NfsdExport::empty() }; MAX_EXPORTS],
            export_count: 0,
            handles: [const { FileHandleV4::empty() }; MAX_FILE_HANDLES],
            handle_count: 0,
            requests: [const { NfsdRequest::empty() }; MAX_PENDING_REQUESTS],
            stats: NfsdStats::new(),
            next_fsid: 1,
        }
    }

    /// Add a new export to the server.
    ///
    /// Returns the export table index.
    pub fn add_export(&mut self, path: &[u8], options: ExportOptions) -> Result<usize> {
        if self.export_count >= MAX_EXPORTS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate path.
        for export in &self.exports {
            if export.active && export.path_len == path.len() {
                if &export.path[..export.path_len] == path {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        let fsid = self.next_fsid;
        self.next_fsid = self.next_fsid.wrapping_add(1);
        let export = NfsdExport::new(path, fsid, options)?;
        for (i, slot) in self.exports.iter_mut().enumerate() {
            if !slot.active {
                *slot = export;
                self.export_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove an export by index.
    pub fn remove_export(&mut self, index: usize) -> Result<()> {
        if index >= MAX_EXPORTS || !self.exports[index].active {
            return Err(Error::NotFound);
        }
        self.exports[index] = NfsdExport::empty();
        self.export_count = self.export_count.saturating_sub(1);
        Ok(())
    }

    /// Get an export by index.
    pub fn get_export(&self, index: usize) -> Result<&NfsdExport> {
        if index >= MAX_EXPORTS || !self.exports[index].active {
            return Err(Error::NotFound);
        }
        Ok(&self.exports[index])
    }

    /// Create a file handle for an object in an export.
    pub fn make_fh(&mut self, export_id: u16, ino: u64, generation: u32) -> Result<FileHandleV4> {
        let fh = FileHandleV4::new(export_id, ino, generation);
        // Track in handle table.
        for slot in &mut self.handles {
            if !slot.valid {
                *slot = fh;
                self.handle_count += 1;
                return Ok(fh);
            }
        }
        // Handle table full — still return the handle but don't track.
        Ok(fh)
    }

    /// Validate a file handle against the export table.
    ///
    /// Returns `NotFound` if the export does not exist or the
    /// handle version is wrong.
    pub fn validate_fh(&self, fh: &FileHandleV4) -> Result<()> {
        if !fh.valid || fh.version != 1 {
            return Err(Error::InvalidArgument);
        }
        let export_idx = fh.export_id as usize;
        if export_idx >= MAX_EXPORTS || !self.exports[export_idx].active {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Submit an incoming NFS request for processing.
    ///
    /// Returns the request slot index.
    pub fn submit_request(
        &mut self,
        xid: u32,
        proc_id: NfsProc,
        fh: FileHandleV4,
        client_addr: u32,
    ) -> Result<usize> {
        self.stats.rpcs_received = self.stats.rpcs_received.wrapping_add(1);

        for (i, slot) in self.requests.iter_mut().enumerate() {
            if slot.state == NfsdRequestState::Idle {
                slot.xid = xid;
                slot.proc_id = proc_id;
                slot.fh = fh;
                slot.client_addr = client_addr;
                slot.offset = 0;
                slot.count = 0;
                slot.state = NfsdRequestState::Pending;
                slot.result = 0;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Dispatch pending requests.
    ///
    /// Advances `Pending` requests to `Processing`. In a real
    /// implementation, this would invoke the VFS to service each
    /// request. Returns the number of requests dispatched.
    pub fn dispatch(&mut self) -> u32 {
        let mut dispatched = 0u32;
        for i in 0..MAX_PENDING_REQUESTS {
            if self.requests[i].state != NfsdRequestState::Pending {
                continue;
            }
            let proc_id = self.requests[i].proc_id;
            if proc_id != NfsProc::Null {
                // Validate file handle inline (avoid self-borrow conflict).
                let fh = self.requests[i].fh;
                let fh_valid = fh.valid
                    && fh.version == 1
                    && (fh.export_id as usize) < MAX_EXPORTS
                    && self.exports[fh.export_id as usize].active;
                if !fh_valid {
                    self.requests[i].state = NfsdRequestState::Failed;
                    self.requests[i].result = -1;
                    self.stats.rpcs_failed = self.stats.rpcs_failed.wrapping_add(1);
                    continue;
                }
                // Check client authorization.
                let export_idx = fh.export_id as usize;
                let client_addr = self.requests[i].client_addr;
                if !self.exports[export_idx].is_client_allowed(client_addr) {
                    self.requests[i].state = NfsdRequestState::Failed;
                    self.requests[i].result = -13; // EACCES
                    self.stats.rpcs_failed = self.stats.rpcs_failed.wrapping_add(1);
                    continue;
                }
            }
            self.requests[i].state = NfsdRequestState::Processing;
            dispatched = dispatched.wrapping_add(1);
        }
        dispatched
    }

    /// Complete a request, recording the result.
    pub fn complete_request(&mut self, slot: usize, result: i32, bytes: u64) -> Result<()> {
        if slot >= MAX_PENDING_REQUESTS {
            return Err(Error::InvalidArgument);
        }
        let req = &mut self.requests[slot];
        if req.state != NfsdRequestState::Processing {
            return Err(Error::InvalidArgument);
        }
        req.result = result;
        if result == 0 {
            req.state = NfsdRequestState::Complete;
            self.stats.rpcs_completed = self.stats.rpcs_completed.wrapping_add(1);
            // Update byte counters.
            match req.proc_id {
                NfsProc::Read => {
                    self.stats.bytes_read = self.stats.bytes_read.wrapping_add(bytes);
                }
                NfsProc::Write => {
                    self.stats.bytes_written = self.stats.bytes_written.wrapping_add(bytes);
                }
                NfsProc::Lookup => {
                    self.stats.lookups = self.stats.lookups.wrapping_add(1);
                }
                NfsProc::Readdir | NfsProc::Readdirplus => {
                    self.stats.readdirs = self.stats.readdirs.wrapping_add(1);
                }
                _ => {}
            }
        } else {
            req.state = NfsdRequestState::Failed;
            self.stats.rpcs_failed = self.stats.rpcs_failed.wrapping_add(1);
        }
        Ok(())
    }

    /// Release a completed or failed request slot.
    pub fn release_slot(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PENDING_REQUESTS {
            return Err(Error::InvalidArgument);
        }
        let req = &self.requests[slot];
        match req.state {
            NfsdRequestState::Processing | NfsdRequestState::Pending => {
                return Err(Error::Busy);
            }
            _ => {}
        }
        self.requests[slot] = NfsdRequest::empty();
        Ok(())
    }

    /// Return a snapshot of the server statistics.
    pub fn stats(&self) -> NfsdStats {
        self.stats
    }

    /// Number of active exports.
    pub fn export_count(&self) -> usize {
        self.export_count
    }

    /// Number of tracked file handles.
    pub fn handle_count(&self) -> usize {
        self.handle_count
    }
}

impl Default for NfsdSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
