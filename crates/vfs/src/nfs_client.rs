// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFSv4 client protocol state machine.
//!
//! Implements an NFSv4.0/4.1 client that can mount remote filesystems and issue
//! compound RPC operations (LOOKUP, READ, WRITE, GETATTR, CREATE, REMOVE,
//! RENAME, MKDIR, READDIR).
//!
//! # Architecture
//!
//! ```text
//! User space
//!   │  sys_open / sys_read / ...
//!   ▼
//! VFS layer  ──►  NfsClientSubsystem
//!                   │
//!                   ├── submit_request()  — enqueue NfsRequest
//!                   ├── poll()            — drive state machine, complete ops
//!                   └── complete_request()— move pending → done, deliver result
//!
//! NfsMount (up to 4)
//!   ├── server_addr (IPv4)
//!   ├── root file handle
//!   ├── NfsVersion (V3 / V4 / V41)
//!   └── session_id  (NFSv4.1 only)
//! ```
//!
//! # References
//!
//! - RFC 7530 — Network File System (NFS) Version 4 Protocol
//! - RFC 5661 — NFSv4 Minor Version 1
//! - Linux `fs/nfs/` — client implementation reference

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of simultaneous NFS mounts.
pub const NFS_MAX_MOUNTS: usize = 4;

/// Maximum number of in-flight NFS requests.
pub const NFS_MAX_PENDING: usize = 64;

/// Length of an NFSv4 file handle in bytes.
pub const NFS_FH_MAXSIZE: usize = 128;

/// Data buffer size for NFS read/write operations.
pub const NFS_DATA_BUF: usize = 4096;

/// Maximum length of a single path component for LOOKUP.
pub const NFS_NAME_MAX: usize = 255;

// ── NfsVersion ───────────────────────────────────────────────────────────────

/// NFS protocol version negotiated during mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsVersion {
    /// NFSv3 — stateless, UDP or TCP, RFC 1813.
    V3,
    /// NFSv4.0 — stateful, TCP, RFC 7530.
    V4,
    /// NFSv4.1 — sessions, pNFS, RFC 5661.
    V41,
}

impl NfsVersion {
    /// Returns the minor version number used in EXCHANGE_ID.
    pub const fn minor(&self) -> u32 {
        match self {
            NfsVersion::V3 => 0,
            NfsVersion::V4 => 0,
            NfsVersion::V41 => 1,
        }
    }
}

// ── NfsFileHandle ─────────────────────────────────────────────────────────────

/// Opaque NFS file handle — server-assigned token identifying a file object.
#[derive(Clone, Copy)]
pub struct NfsFileHandle {
    /// Raw handle bytes (up to `NFS_FH_MAXSIZE`).
    pub data: [u8; NFS_FH_MAXSIZE],
    /// Number of valid bytes in `data`.
    pub len: u8,
}

impl NfsFileHandle {
    /// Constructs an empty (zero-length) file handle.
    pub const fn new() -> Self {
        Self {
            data: [0u8; NFS_FH_MAXSIZE],
            len: 0,
        }
    }

    /// Returns whether this handle is non-empty.
    pub fn is_valid(&self) -> bool {
        self.len > 0
    }

    /// Copies bytes from `src` into the handle, truncating to `NFS_FH_MAXSIZE`.
    pub fn set(&mut self, src: &[u8]) {
        let n = src.len().min(NFS_FH_MAXSIZE);
        self.data[..n].copy_from_slice(&src[..n]);
        self.len = n as u8;
    }
}

impl Default for NfsFileHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for NfsFileHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NfsFileHandle(len={})", self.len)
    }
}

// ── NfsMount ─────────────────────────────────────────────────────────────────

/// State for a single mounted NFS export.
#[derive(Debug, Clone, Copy)]
pub struct NfsMount {
    /// Server IPv4 address (network byte order).
    pub server_addr: u32,
    /// Root file handle for the mounted export.
    pub root_fh: NfsFileHandle,
    /// Protocol version in use.
    pub version: NfsVersion,
    /// NFSv4.1 session identifier (zero for V3/V4).
    pub session_id: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl NfsMount {
    /// Constructs an inactive mount slot.
    pub const fn new() -> Self {
        Self {
            server_addr: 0,
            root_fh: NfsFileHandle::new(),
            version: NfsVersion::V4,
            session_id: 0,
            active: false,
        }
    }
}

impl Default for NfsMount {
    fn default() -> Self {
        Self::new()
    }
}

// ── NfsOp ────────────────────────────────────────────────────────────────────

/// The 9 compound operations supported by the client state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsOp {
    /// Look up a name in a directory, returning a new file handle.
    Lookup,
    /// Read data from a regular file.
    Read,
    /// Write data to a regular file.
    Write,
    /// Retrieve file attributes (size, times, mode, nlink).
    Getattr,
    /// Create a new regular file.
    Create,
    /// Remove a directory entry.
    Remove,
    /// Rename (or move) a directory entry.
    Rename,
    /// Create a new directory.
    Mkdir,
    /// Read directory entries.
    Readdir,
}

// ── NfsRequestState ──────────────────────────────────────────────────────────

/// Lifecycle state of a pending NFS request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsRequestState {
    /// Slot is empty.
    Idle,
    /// Request has been submitted and is waiting for RPC transmission.
    Pending,
    /// RPC has been transmitted; awaiting reply.
    InFlight,
    /// Reply received; result is ready.
    Complete,
    /// Request failed with an error.
    Error,
}

// ── NfsRequest ───────────────────────────────────────────────────────────────

/// A single NFS compound request.
pub struct NfsRequest {
    /// Index into `NfsClient::mounts` this request targets.
    pub mount_id: u8,
    /// The operation to perform.
    pub op: NfsOp,
    /// File handle to operate on (source for RENAME).
    pub fh: NfsFileHandle,
    /// Byte offset for READ/WRITE.
    pub offset: u64,
    /// Byte count for READ/WRITE.
    pub length: u32,
    /// Data buffer — payload for WRITE or result storage for READ.
    pub data: [u8; NFS_DATA_BUF],
    /// Name component (null-terminated) for LOOKUP/CREATE/REMOVE/MKDIR.
    pub name: [u8; NFS_NAME_MAX],
    /// Destination file handle (RENAME target directory).
    pub dest_fh: NfsFileHandle,
    /// Destination name (RENAME).
    pub dest_name: [u8; NFS_NAME_MAX],
    /// Current state of this request slot.
    pub state: NfsRequestState,
    /// Sequence number assigned at submission.
    pub xid: u32,
    /// Result code: 0 = success, non-zero = NFS error status.
    pub result: i32,
    /// Number of bytes actually transferred (READ/WRITE).
    pub bytes_transferred: u32,
}

impl NfsRequest {
    /// Constructs an idle (empty) request slot.
    pub const fn new() -> Self {
        Self {
            mount_id: 0,
            op: NfsOp::Getattr,
            fh: NfsFileHandle::new(),
            offset: 0,
            length: 0,
            data: [0u8; NFS_DATA_BUF],
            name: [0u8; NFS_NAME_MAX],
            dest_fh: NfsFileHandle::new(),
            dest_name: [0u8; NFS_NAME_MAX],
            state: NfsRequestState::Idle,
            xid: 0,
            result: 0,
            bytes_transferred: 0,
        }
    }
}

impl Default for NfsRequest {
    fn default() -> Self {
        Self::new()
    }
}

// NfsRequest contains large arrays — implement Debug manually.
impl core::fmt::Debug for NfsRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NfsRequest")
            .field("mount_id", &self.mount_id)
            .field("op", &self.op)
            .field("state", &self.state)
            .field("xid", &self.xid)
            .field("result", &self.result)
            .finish()
    }
}

// ── NfsClient ────────────────────────────────────────────────────────────────

/// Core NFS client state: mounts, pending request queue, and sequence counter.
pub struct NfsClient {
    /// Up to 4 simultaneous mounts.
    pub mounts: [NfsMount; NFS_MAX_MOUNTS],
    /// Ring of in-flight / pending requests.
    pub pending_ops: [NfsRequest; NFS_MAX_PENDING],
    /// Monotonically increasing XID / sequence counter.
    pub sequence_id: u32,
    /// Number of currently active mounts.
    pub mount_count: u8,
}

impl NfsClient {
    /// Constructs an empty NFS client.
    pub const fn new() -> Self {
        Self {
            mounts: [const { NfsMount::new() }; NFS_MAX_MOUNTS],
            pending_ops: [const { NfsRequest::new() }; NFS_MAX_PENDING],
            sequence_id: 1,
            mount_count: 0,
        }
    }

    /// Registers a new NFS mount, returning its index.
    ///
    /// Returns [`Error::OutOfMemory`] when all mount slots are occupied.
    pub fn add_mount(
        &mut self,
        server_addr: u32,
        root_fh: NfsFileHandle,
        version: NfsVersion,
    ) -> Result<usize> {
        for (i, slot) in self.mounts.iter_mut().enumerate() {
            if !slot.active {
                *slot = NfsMount {
                    server_addr,
                    root_fh,
                    version,
                    session_id: 0,
                    active: true,
                };
                self.mount_count = self.mount_count.saturating_add(1);
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes the mount at `index`, freeing the slot.
    pub fn remove_mount(&mut self, index: usize) -> Result<()> {
        if index >= NFS_MAX_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        if !self.mounts[index].active {
            return Err(Error::NotFound);
        }
        self.mounts[index] = NfsMount::new();
        self.mount_count = self.mount_count.saturating_sub(1);
        Ok(())
    }

    /// Allocates a free request slot, returning its index.
    fn alloc_slot(&mut self) -> Option<usize> {
        self.pending_ops
            .iter()
            .position(|r| r.state == NfsRequestState::Idle)
    }

    /// Advances the sequence counter and returns the new XID.
    fn next_xid(&mut self) -> u32 {
        let xid = self.sequence_id;
        self.sequence_id = self.sequence_id.wrapping_add(1);
        xid
    }
}

impl Default for NfsClient {
    fn default() -> Self {
        Self::new()
    }
}

// ── NfsClientStats ────────────────────────────────────────────────────────────

/// Cumulative statistics for the NFS client.
#[derive(Debug, Default, Clone, Copy)]
pub struct NfsClientStats {
    /// Total requests submitted.
    pub requests: u64,
    /// Total requests completed successfully.
    pub completions: u64,
    /// Total requests that resulted in an error.
    pub errors: u64,
    /// Total bytes transferred by READ operations.
    pub bytes_read: u64,
    /// Total bytes transferred by WRITE operations.
    pub bytes_written: u64,
}

impl NfsClientStats {
    /// Constructs zeroed statistics.
    pub const fn new() -> Self {
        Self {
            requests: 0,
            completions: 0,
            errors: 0,
            bytes_read: 0,
            bytes_written: 0,
        }
    }
}

// ── NfsClientSubsystem ───────────────────────────────────────────────────────

/// Top-level NFS client subsystem — exposes the public API used by the VFS.
pub struct NfsClientSubsystem {
    /// Underlying NFS client state.
    pub client: NfsClient,
    /// Cumulative statistics.
    pub stats: NfsClientStats,
}

impl NfsClientSubsystem {
    /// Constructs a new, idle NFS client subsystem.
    pub const fn new() -> Self {
        Self {
            client: NfsClient::new(),
            stats: NfsClientStats::new(),
        }
    }

    /// Submits a READ request and returns the assigned slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `mount_id` out of range or mount inactive.
    /// - [`Error::OutOfMemory`] — all 64 request slots are in use.
    pub fn submit_request(
        &mut self,
        mount_id: u8,
        op: NfsOp,
        fh: NfsFileHandle,
        offset: u64,
        length: u32,
    ) -> Result<usize> {
        let idx = mount_id as usize;
        if idx >= NFS_MAX_MOUNTS || !self.client.mounts[idx].active {
            return Err(Error::InvalidArgument);
        }
        let slot = self.client.alloc_slot().ok_or(Error::OutOfMemory)?;
        let xid = self.client.next_xid();
        let req = &mut self.client.pending_ops[slot];
        req.mount_id = mount_id;
        req.op = op;
        req.fh = fh;
        req.offset = offset;
        req.length = length;
        req.state = NfsRequestState::Pending;
        req.xid = xid;
        req.result = 0;
        req.bytes_transferred = 0;
        self.stats.requests = self.stats.requests.wrapping_add(1);
        Ok(slot)
    }

    /// Marks a request slot as complete, recording the result.
    ///
    /// Called by the RPC layer when a reply arrives.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `slot` out of range.
    /// - [`Error::NotFound`] — slot is not in `InFlight` state.
    pub fn complete_request(&mut self, slot: usize, result: i32, bytes: u32) -> Result<()> {
        if slot >= NFS_MAX_PENDING {
            return Err(Error::InvalidArgument);
        }
        let req = &mut self.client.pending_ops[slot];
        if req.state != NfsRequestState::InFlight && req.state != NfsRequestState::Pending {
            return Err(Error::NotFound);
        }
        req.bytes_transferred = bytes;
        req.result = result;
        if result == 0 {
            req.state = NfsRequestState::Complete;
            self.stats.completions = self.stats.completions.wrapping_add(1);
            match req.op {
                NfsOp::Read => {
                    self.stats.bytes_read = self.stats.bytes_read.wrapping_add(bytes as u64);
                }
                NfsOp::Write => {
                    self.stats.bytes_written = self.stats.bytes_written.wrapping_add(bytes as u64);
                }
                _ => {}
            }
        } else {
            req.state = NfsRequestState::Error;
            self.stats.errors = self.stats.errors.wrapping_add(1);
        }
        Ok(())
    }

    /// Polls all pending slots, advancing `Pending` → `InFlight`.
    ///
    /// In a real system this would hand off to the RPC/socket layer.
    /// Here it simulates transmission by advancing the state.
    ///
    /// Returns the number of requests that transitioned to `InFlight`.
    pub fn poll(&mut self) -> u32 {
        let mut advanced = 0u32;
        for req in self.client.pending_ops.iter_mut() {
            if req.state == NfsRequestState::Pending {
                req.state = NfsRequestState::InFlight;
                advanced = advanced.wrapping_add(1);
            }
        }
        advanced
    }

    /// Frees a completed or errored request slot, returning it to idle.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `slot` out of range.
    /// - [`Error::Busy`] — request is still in-flight.
    pub fn release_slot(&mut self, slot: usize) -> Result<()> {
        if slot >= NFS_MAX_PENDING {
            return Err(Error::InvalidArgument);
        }
        let req = &mut self.client.pending_ops[slot];
        match req.state {
            NfsRequestState::InFlight | NfsRequestState::Pending => {
                return Err(Error::Busy);
            }
            _ => {}
        }
        *req = NfsRequest::new();
        Ok(())
    }

    /// Mounts a remote NFS export.
    ///
    /// Returns the mount index on success.
    pub fn mount(
        &mut self,
        server_addr: u32,
        root_fh: NfsFileHandle,
        version: NfsVersion,
    ) -> Result<usize> {
        self.client.add_mount(server_addr, root_fh, version)
    }

    /// Unmounts the export at `mount_id`.
    pub fn umount(&mut self, mount_id: usize) -> Result<()> {
        self.client.remove_mount(mount_id)
    }

    /// Returns a snapshot of the current statistics.
    pub fn stats(&self) -> NfsClientStats {
        self.stats
    }
}

impl Default for NfsClientSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_fh() -> NfsFileHandle {
        let mut fh = NfsFileHandle::new();
        fh.set(&[0xde, 0xad, 0xbe, 0xef]);
        fh
    }

    #[test]
    fn mount_and_umount() {
        let mut sub = NfsClientSubsystem::new();
        let idx = sub.mount(0xC0A80001, dummy_fh(), NfsVersion::V4).unwrap();
        assert_eq!(idx, 0);
        sub.umount(idx).unwrap();
        assert!(!sub.client.mounts[0].active);
    }

    #[test]
    fn submit_and_complete() {
        let mut sub = NfsClientSubsystem::new();
        let m = sub.mount(0xC0A80001, dummy_fh(), NfsVersion::V41).unwrap();
        let slot = sub
            .submit_request(m as u8, NfsOp::Read, dummy_fh(), 0, 512)
            .unwrap();
        sub.poll();
        sub.complete_request(slot, 0, 512).unwrap();
        assert_eq!(sub.stats().bytes_read, 512);
        sub.release_slot(slot).unwrap();
    }

    #[test]
    fn overflow_mounts() {
        let mut sub = NfsClientSubsystem::new();
        for _ in 0..NFS_MAX_MOUNTS {
            sub.mount(0, dummy_fh(), NfsVersion::V3).unwrap();
        }
        assert!(matches!(
            sub.mount(0, dummy_fh(), NfsVersion::V3),
            Err(Error::OutOfMemory)
        ));
    }
}
