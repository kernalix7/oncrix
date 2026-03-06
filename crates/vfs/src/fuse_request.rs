// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE request handler — kernel-side request lifecycle management.
//!
//! This module implements the full lifecycle of a FUSE request from the
//! moment the VFS calls into a FUSE-mounted filesystem until the daemon's
//! reply is delivered back to the VFS caller.  It complements [`crate::fuse`]
//! (wire types) and [`crate::fuse_dev`] (device I/O) by providing:
//!
//! - A [`FuseReqState`] state machine tracking each request.
//! - A [`FuseReqQueue`] that serialises VFS requests into the submission
//!   queue and matches daemon replies by unique ID.
//! - An [`FuseArgBuf`] carrying typed argument payloads without heap
//!   allocation.
//! - Helpers for building and parsing common request types
//!   (lookup, getattr, read, write, mkdir, unlink, …).
//!
//! # Protocol flow
//!
//! ```text
//! VFS vfs_lookup(name)
//!   → FuseReqQueue::submit(FUSE_LOOKUP, args)
//!     → serialize into FuseWireReq
//!       → daemon reads /dev/fuse (FuseReqQueue::dequeue_pending)
//!         → daemon processes
//!           → daemon writes reply (FuseReqQueue::deliver_reply)
//!             → VFS caller unblocks with FuseReply
//! ```
//!
//! # References
//!
//! - Linux `fs/fuse/dev.c`, `fs/fuse/dir.c`, `fs/fuse/file.c`
//! - FUSE protocol: `include/uapi/linux/fuse.h`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Depth of the pending-request queue.
const REQ_QUEUE_DEPTH: usize = 64;

/// Maximum argument/reply payload in bytes.
pub const FUSE_ARG_MAX: usize = 4096;

/// Maximum filename length.
const FUSE_NAME_MAX: usize = 255;

/// FUSE protocol major version.
const FUSE_MAJOR: u32 = 7;

/// FUSE protocol minor version.
const FUSE_MINOR: u32 = 39;

// ── FUSE opcode constants ────────────────────────────────────────

/// Opcode: look up a directory entry.
pub const FUSE_LOOKUP: u32 = 1;
/// Opcode: forget about an inode (decrement lookup count).
pub const FUSE_FORGET: u32 = 2;
/// Opcode: get file attributes.
pub const FUSE_GETATTR: u32 = 3;
/// Opcode: set file attributes.
pub const FUSE_SETATTR: u32 = 4;
/// Opcode: read symbolic link.
pub const FUSE_READLINK: u32 = 5;
/// Opcode: create symbolic link.
pub const FUSE_SYMLINK: u32 = 6;
/// Opcode: create a regular file.
pub const FUSE_MKNOD: u32 = 8;
/// Opcode: create a directory.
pub const FUSE_MKDIR: u32 = 9;
/// Opcode: remove a file.
pub const FUSE_UNLINK: u32 = 10;
/// Opcode: remove a directory.
pub const FUSE_RMDIR: u32 = 11;
/// Opcode: rename a file.
pub const FUSE_RENAME: u32 = 12;
/// Opcode: create a hard link.
pub const FUSE_LINK: u32 = 13;
/// Opcode: open a file.
pub const FUSE_OPEN: u32 = 14;
/// Opcode: read data from a file.
pub const FUSE_READ: u32 = 15;
/// Opcode: write data to a file.
pub const FUSE_WRITE: u32 = 16;
/// Opcode: get filesystem statistics.
pub const FUSE_STATFS: u32 = 17;
/// Opcode: release an open file handle.
pub const FUSE_RELEASE: u32 = 18;
/// Opcode: synchronize file contents.
pub const FUSE_FSYNC: u32 = 20;
/// Opcode: open a directory.
pub const FUSE_OPENDIR: u32 = 27;
/// Opcode: read directory entries.
pub const FUSE_READDIR: u32 = 28;
/// Opcode: release an open directory handle.
pub const FUSE_RELEASEDIR: u32 = 29;
/// Opcode: perform FUSE handshake.
pub const FUSE_INIT: u32 = 26;

// ── FuseReqState ────────────────────────────────────────────────

/// State machine for a single FUSE request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseReqState {
    /// Slot is available.
    Empty,
    /// Request has been submitted and is waiting for a daemon to read it.
    Pending,
    /// Daemon has read the request and is processing it.
    InFlight,
    /// Daemon has written a reply; the VFS caller can collect it.
    Done,
    /// The request was interrupted before a reply arrived.
    Interrupted,
}

// ── FuseArgBuf ──────────────────────────────────────────────────

/// Fixed-size byte buffer holding argument or reply payload.
#[derive(Clone, Copy)]
pub struct FuseArgBuf {
    data: [u8; FUSE_ARG_MAX],
    len: usize,
}

impl FuseArgBuf {
    /// Creates an empty buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; FUSE_ARG_MAX],
            len: 0,
        }
    }

    /// Copies `src` into the buffer (truncates to `FUSE_ARG_MAX`).
    pub fn write(&mut self, src: &[u8]) {
        let copy_len = src.len().min(FUSE_ARG_MAX);
        self.data[..copy_len].copy_from_slice(&src[..copy_len]);
        self.len = copy_len;
    }

    /// Returns the valid portion of the buffer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns the length of the payload.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the buffer contains no data.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads a `u32` at byte offset `off` (little-endian).
    pub fn read_u32_le(&self, off: usize) -> Option<u32> {
        if off + 4 > self.len {
            return None;
        }
        let b = &self.data[off..off + 4];
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a `u64` at byte offset `off` (little-endian).
    pub fn read_u64_le(&self, off: usize) -> Option<u64> {
        if off + 8 > self.len {
            return None;
        }
        let b = &self.data[off..off + 8];
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

impl core::fmt::Debug for FuseArgBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FuseArgBuf(len={})", self.len)
    }
}

// ── FuseWireReq ─────────────────────────────────────────────────

/// On-wire FUSE request: header + argument payload.
#[derive(Clone, Copy, Debug)]
pub struct FuseWireReq {
    /// Total length of the message (header + args).
    pub len: u32,
    /// Operation code (one of `FUSE_*`).
    pub opcode: u32,
    /// Unique request identifier.
    pub unique: u64,
    /// Inode number of the subject file.
    pub nodeid: u64,
    /// UID of the requesting process.
    pub uid: u32,
    /// GID of the requesting process.
    pub gid: u32,
    /// PID of the requesting process.
    pub pid: u32,
    /// Argument payload.
    pub args: FuseArgBuf,
}

impl FuseWireReq {
    /// Creates a zeroed wire request.
    pub const fn new() -> Self {
        Self {
            len: 0,
            opcode: 0,
            unique: 0,
            nodeid: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            args: FuseArgBuf::new(),
        }
    }
}

// ── FuseWireReply ────────────────────────────────────────────────

/// On-wire FUSE reply: header + reply payload.
#[derive(Clone, Copy, Debug)]
pub struct FuseWireReply {
    /// Total length of the reply (header + data).
    pub len: u32,
    /// Error code (0 = success, negative = errno).
    pub error: i32,
    /// Unique ID matching the original request.
    pub unique: u64,
    /// Reply payload.
    pub data: FuseArgBuf,
}

impl FuseWireReply {
    /// Creates a zeroed wire reply.
    pub const fn new() -> Self {
        Self {
            len: 0,
            error: 0,
            unique: 0,
            data: FuseArgBuf::new(),
        }
    }

    /// Returns `true` if the reply signals success (`error == 0`).
    pub fn is_ok(&self) -> bool {
        self.error == 0
    }

    /// Converts the wire error code to an [`Error`].
    pub fn to_result(&self) -> Result<()> {
        match self.error {
            0 => Ok(()),
            -1 => Err(Error::PermissionDenied),
            -2 => Err(Error::NotFound),
            -12 => Err(Error::OutOfMemory),
            -22 => Err(Error::InvalidArgument),
            -17 => Err(Error::AlreadyExists),
            -16 => Err(Error::Busy),
            _ => Err(Error::IoError),
        }
    }
}

// ── FuseReqSlot ─────────────────────────────────────────────────

/// One slot in the request queue.
#[derive(Clone, Copy, Debug)]
struct FuseReqSlot {
    state: FuseReqState,
    req: FuseWireReq,
    reply: FuseWireReply,
}

impl FuseReqSlot {
    const fn empty() -> Self {
        Self {
            state: FuseReqState::Empty,
            req: FuseWireReq::new(),
            reply: FuseWireReply::new(),
        }
    }
}

// ── FuseReqStats ────────────────────────────────────────────────

/// Per-queue I/O statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseReqStats {
    /// Total requests submitted.
    pub submitted: u64,
    /// Total requests completed successfully.
    pub completed: u64,
    /// Total requests that ended in error.
    pub errors: u64,
    /// Total requests interrupted.
    pub interrupted: u64,
}

// ── FuseReqQueue ────────────────────────────────────────────────

/// Kernel-side FUSE request/reply queue for one mount.
///
/// Manages the full lifecycle of FUSE requests from submission by the
/// VFS to reply delivery from the user-space daemon.
pub struct FuseReqQueue {
    /// Slot array.
    slots: [FuseReqSlot; REQ_QUEUE_DEPTH],
    /// Monotonically increasing unique-ID counter.
    next_unique: u64,
    /// Number of occupied slots.
    pending_count: usize,
    /// Negotiated FUSE protocol minor version.
    minor_version: u32,
    /// Queue statistics.
    pub stats: FuseReqStats,
}

impl FuseReqQueue {
    /// Creates an empty request queue.
    pub const fn new() -> Self {
        Self {
            slots: [const { FuseReqSlot::empty() }; REQ_QUEUE_DEPTH],
            next_unique: 1,
            pending_count: 0,
            minor_version: FUSE_MINOR,
            stats: FuseReqStats {
                submitted: 0,
                completed: 0,
                errors: 0,
                interrupted: 0,
            },
        }
    }

    /// Submits a new request with the given `opcode` and argument `args`.
    ///
    /// Returns the unique ID assigned to this request.
    pub fn submit(
        &mut self,
        opcode: u32,
        nodeid: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        args: &[u8],
    ) -> Result<u64> {
        for i in 0..REQ_QUEUE_DEPTH {
            if self.slots[i].state == FuseReqState::Empty {
                let unique = self.next_unique;
                self.next_unique = self.next_unique.wrapping_add(1);

                let mut arg_buf = FuseArgBuf::new();
                arg_buf.write(args);

                self.slots[i] = FuseReqSlot {
                    state: FuseReqState::Pending,
                    req: FuseWireReq {
                        len: (40 + args.len()) as u32, // 40 = header size
                        opcode,
                        unique,
                        nodeid,
                        uid,
                        gid,
                        pid,
                        args: arg_buf,
                    },
                    reply: FuseWireReply::new(),
                };
                self.pending_count += 1;
                self.stats.submitted += 1;
                return Ok(unique);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Dequeues the next pending request for dispatch to the daemon.
    ///
    /// Returns the wire request and moves the slot to `InFlight`.
    pub fn dequeue_pending(&mut self) -> Option<FuseWireReq> {
        for i in 0..REQ_QUEUE_DEPTH {
            if self.slots[i].state == FuseReqState::Pending {
                self.slots[i].state = FuseReqState::InFlight;
                return Some(self.slots[i].req);
            }
        }
        None
    }

    /// Delivers a daemon reply identified by `unique`.
    ///
    /// Transitions the matching slot from `InFlight` to `Done`.
    pub fn deliver_reply(&mut self, unique: u64, error: i32, data: &[u8]) -> Result<()> {
        for i in 0..REQ_QUEUE_DEPTH {
            if self.slots[i].state == FuseReqState::InFlight && self.slots[i].req.unique == unique {
                let mut data_buf = FuseArgBuf::new();
                data_buf.write(data);
                self.slots[i].reply = FuseWireReply {
                    len: (8 + data.len()) as u32,
                    error,
                    unique,
                    data: data_buf,
                };
                self.slots[i].state = FuseReqState::Done;
                if error == 0 {
                    self.stats.completed += 1;
                } else {
                    self.stats.errors += 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Collects the reply for request `unique` and frees the slot.
    ///
    /// Returns the reply on success.  The slot transitions back to `Empty`.
    pub fn collect_reply(&mut self, unique: u64) -> Result<FuseWireReply> {
        for i in 0..REQ_QUEUE_DEPTH {
            if self.slots[i].state == FuseReqState::Done && self.slots[i].req.unique == unique {
                let reply = self.slots[i].reply;
                self.slots[i].state = FuseReqState::Empty;
                self.pending_count -= 1;
                return Ok(reply);
            }
        }
        Err(Error::WouldBlock)
    }

    /// Interrupts the in-flight request with `unique`.
    pub fn interrupt(&mut self, unique: u64) -> Result<()> {
        for i in 0..REQ_QUEUE_DEPTH {
            if (self.slots[i].state == FuseReqState::Pending
                || self.slots[i].state == FuseReqState::InFlight)
                && self.slots[i].req.unique == unique
            {
                self.slots[i].state = FuseReqState::Interrupted;
                self.stats.interrupted += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of non-empty request slots.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Returns the queue depth (maximum concurrent requests).
    pub fn capacity(&self) -> usize {
        REQ_QUEUE_DEPTH
    }

    /// Returns the negotiated minor version.
    pub fn minor_version(&self) -> u32 {
        self.minor_version
    }

    /// Updates the negotiated minor version after INIT handshake.
    pub fn set_minor_version(&mut self, minor: u32) {
        self.minor_version = minor;
    }
}

// ── Request builder helpers ──────────────────────────────────────

/// Builds a FUSE_LOOKUP argument: null-terminated filename.
///
/// Writes the name into `out` and returns the number of bytes written.
pub fn build_lookup_args(name: &[u8], out: &mut [u8]) -> usize {
    let len = name
        .len()
        .min(FUSE_NAME_MAX)
        .min(out.len().saturating_sub(1));
    out[..len].copy_from_slice(&name[..len]);
    if len < out.len() {
        out[len] = 0;
    }
    len + 1
}

/// Builds a FUSE_GETATTR argument (nodeid already in header; args are empty).
pub fn build_getattr_args(_out: &mut [u8]) -> usize {
    0
}

/// Builds a FUSE_READ argument (nodeid in header; reads need offset + size).
///
/// Layout: `[fh: u64][offset: u64][size: u32][read_flags: u32][lock_owner: u64][flags: u32]`
pub fn build_read_args(fh: u64, offset: u64, size: u32, out: &mut [u8]) -> usize {
    if out.len() < 32 {
        return 0;
    }
    out[0..8].copy_from_slice(&fh.to_le_bytes());
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..20].copy_from_slice(&size.to_le_bytes());
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // read_flags
    out[24..32].copy_from_slice(&0u64.to_le_bytes()); // lock_owner
    32
}

/// Builds a FUSE_WRITE argument header.
///
/// Layout: `[fh: u64][offset: u64][size: u32][write_flags: u32][lock_owner: u64][flags: u32]`
/// followed by data bytes.
pub fn build_write_args(fh: u64, offset: u64, data: &[u8], out: &mut [u8]) -> usize {
    let hdr = 32usize;
    if out.len() < hdr + data.len() {
        return 0;
    }
    out[0..8].copy_from_slice(&fh.to_le_bytes());
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // write_flags
    out[24..32].copy_from_slice(&0u64.to_le_bytes()); // lock_owner
    out[hdr..hdr + data.len()].copy_from_slice(data);
    hdr + data.len()
}

/// Parses a FUSE_GETATTR reply to extract inode size and mode.
///
/// Returns `(size, mode)` or `(0, 0)` if the reply is too short.
pub fn parse_getattr_reply(reply: &FuseWireReply) -> (u64, u32) {
    // attr starts at offset 8 (nodeid u64), size at +8 (u64), mode at +32 (u32)
    let data = reply.data.as_bytes();
    if data.len() < 48 {
        return (0, 0);
    }
    let size = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
    let mode = u32::from_le_bytes(data[32..36].try_into().unwrap_or([0u8; 4]));
    (size, mode)
}

// ── FuseMount ────────────────────────────────────────────────────

/// A single FUSE mount point combining a request queue with mount metadata.
pub struct FuseMount {
    /// Mount identifier.
    pub mount_id: u32,
    /// FUSE node ID of the root inode.
    pub root_nodeid: u64,
    /// Request queue for this mount.
    pub queue: FuseReqQueue,
    /// Whether the INIT handshake is complete.
    pub initialized: bool,
    /// Whether this mount slot is occupied.
    active: bool,
}

impl FuseMount {
    /// Creates an inactive mount slot.
    pub const fn empty() -> Self {
        Self {
            mount_id: 0,
            root_nodeid: 1,
            queue: FuseReqQueue::new(),
            initialized: false,
            active: false,
        }
    }

    /// Activates this mount with the given `mount_id`.
    pub fn activate(&mut self, mount_id: u32) {
        self.mount_id = mount_id;
        self.root_nodeid = 1;
        self.initialized = false;
        self.active = true;
    }

    /// Returns `true` if this mount slot is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Performs the FUSE INIT handshake.
    ///
    /// Submits a `FUSE_INIT` request and stores the negotiated minor version.
    pub fn do_init(&mut self, uid: u32, gid: u32, pid: u32) -> Result<u64> {
        let mut args = [0u8; 16];
        args[0..4].copy_from_slice(&FUSE_MAJOR.to_le_bytes());
        args[4..8].copy_from_slice(&FUSE_MINOR.to_le_bytes());
        args[8..12].copy_from_slice(&4096u32.to_le_bytes()); // max_readahead
        args[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags
        self.queue
            .submit(FUSE_INIT, self.root_nodeid, uid, gid, pid, &args)
    }

    /// Finalises the INIT handshake by consuming the daemon's reply.
    pub fn complete_init(&mut self, unique: u64) -> Result<()> {
        let reply = self.queue.collect_reply(unique)?;
        reply.to_result()?;
        // Extract minor version from reply data[4..8].
        if let Some(minor) = reply.data.read_u32_le(4) {
            self.queue.set_minor_version(minor);
        }
        self.initialized = true;
        Ok(())
    }
}

// ── FuseMountRegistry ────────────────────────────────────────────

/// Maximum number of concurrent FUSE mounts.
const MAX_FUSE_MOUNTS: usize = 8;

/// Global registry of FUSE mounts.
pub struct FuseMountRegistry {
    mounts: [FuseMount; MAX_FUSE_MOUNTS],
    next_id: u32,
    count: usize,
}

impl FuseMountRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            mounts: [const { FuseMount::empty() }; MAX_FUSE_MOUNTS],
            next_id: 1,
            count: 0,
        }
    }

    /// Registers a new FUSE mount and returns its identifier.
    pub fn register(&mut self) -> Result<u32> {
        for i in 0..MAX_FUSE_MOUNTS {
            if !self.mounts[i].is_active() {
                let id = self.next_id;
                self.next_id = self.next_id.saturating_add(1);
                self.mounts[i].activate(id);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Deregisters the mount with `mount_id`.
    pub fn deregister(&mut self, mount_id: u32) -> Result<()> {
        for i in 0..MAX_FUSE_MOUNTS {
            if self.mounts[i].is_active() && self.mounts[i].mount_id == mount_id {
                self.mounts[i].active = false;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to the mount with `mount_id`.
    pub fn get_mount_mut(&mut self, mount_id: u32) -> Option<&mut FuseMount> {
        for i in 0..MAX_FUSE_MOUNTS {
            if self.mounts[i].is_active() && self.mounts[i].mount_id == mount_id {
                return Some(&mut self.mounts[i]);
            }
        }
        None
    }

    /// Returns the number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_dequeue_deliver_collect() {
        let mut q = FuseReqQueue::new();
        let uid = q.submit(FUSE_LOOKUP, 1, 0, 0, 100, b"hello").unwrap();
        let req = q.dequeue_pending().unwrap();
        assert_eq!(req.opcode, FUSE_LOOKUP);
        assert_eq!(req.unique, uid);
        q.deliver_reply(uid, 0, b"reply").unwrap();
        let reply = q.collect_reply(uid).unwrap();
        assert!(reply.is_ok());
        assert_eq!(reply.data.as_bytes(), b"reply");
    }

    #[test]
    fn test_queue_full_returns_error() {
        let mut q = FuseReqQueue::new();
        for _ in 0..REQ_QUEUE_DEPTH {
            q.submit(FUSE_GETATTR, 1, 0, 0, 0, b"").unwrap();
        }
        assert!(matches!(
            q.submit(FUSE_GETATTR, 1, 0, 0, 0, b""),
            Err(Error::OutOfMemory)
        ));
    }

    #[test]
    fn test_interrupt_pending() {
        let mut q = FuseReqQueue::new();
        let uid = q.submit(FUSE_READ, 1, 0, 0, 0, b"").unwrap();
        q.interrupt(uid).unwrap();
        // Interrupted slot: collect should return WouldBlock.
        assert!(matches!(q.collect_reply(uid), Err(Error::WouldBlock)));
    }

    #[test]
    fn test_deliver_unknown_unique() {
        let mut q = FuseReqQueue::new();
        let uid = q.submit(FUSE_GETATTR, 1, 0, 0, 0, b"").unwrap();
        q.dequeue_pending();
        assert!(matches!(
            q.deliver_reply(uid + 1, 0, b""),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn test_wire_reply_to_result() {
        let ok = FuseWireReply {
            error: 0,
            ..FuseWireReply::new()
        };
        assert!(ok.to_result().is_ok());
        let eperm = FuseWireReply {
            error: -1,
            ..FuseWireReply::new()
        };
        assert!(matches!(eperm.to_result(), Err(Error::PermissionDenied)));
    }

    #[test]
    fn test_build_lookup_args() {
        let mut buf = [0u8; 64];
        let len = build_lookup_args(b"test.txt", &mut buf);
        assert_eq!(&buf[..8], b"test.txt");
        assert_eq!(buf[8], 0); // null terminator
        assert_eq!(len, 9);
    }

    #[test]
    fn test_mount_registry() {
        let mut reg = FuseMountRegistry::new();
        let id = reg.register().unwrap();
        assert!(id > 0);
        assert_eq!(reg.count(), 1);
        reg.deregister(id).unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let mut q = FuseReqQueue::new();
        let uid = q.submit(FUSE_GETATTR, 1, 0, 0, 0, b"").unwrap();
        q.dequeue_pending();
        q.deliver_reply(uid, 0, b"").unwrap();
        q.collect_reply(uid).unwrap();
        assert_eq!(q.stats.submitted, 1);
        assert_eq!(q.stats.completed, 1);
        assert_eq!(q.stats.errors, 0);
    }
}
