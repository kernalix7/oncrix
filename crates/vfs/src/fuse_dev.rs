// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `/dev/fuse` character device — FUSE userspace filesystem protocol.
//!
//! This module implements the kernel-side `/dev/fuse` interface that user-space
//! FUSE daemons communicate through.  It sits on top of the protocol layer in
//! [`crate::fuse`] and provides:
//!
//! - A per-mount [`FuseDevChannel`] that serialises VFS requests into
//!   on-wire [`FuseMessage`]s and de-serialises daemon replies.
//! - A global [`FuseDevRegistry`] that maps minor device numbers to channels.
//! - Helper functions for the common VFS → FUSE → reply round-trip.
//!
//! # Protocol flow
//!
//! ```text
//! VFS call
//!   → FuseDevChannel::send_request()     (encode + enqueue)
//!     → daemon reads /dev/fuse            (FuseDevChannel::read_request)
//!       → daemon processes + writes reply (FuseDevChannel::write_reply)
//!         → FuseDevChannel::recv_reply()  (decode + return to VFS)
//! ```
//!
//! # Structures
//!
//! - [`FuseDevOpcode`] — extended opcode set (superset of `fuse.rs`)
//! - [`FuseMessage`] — serialised on-wire message (header + payload)
//! - [`FuseDevChannel`] — per-mount request/reply channel
//! - [`FuseDevRegistry`] — global minor-number → channel mapping (16 slots)
//! - [`FuseInitConfig`] — negotiated capability flags from INIT handshake
//! - [`FuseIoStats`] — per-channel I/O counters for observability

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum on-wire message size (header + payload), in bytes.
const MAX_MSG_SIZE: usize = 65536; // 64 KiB

/// Maximum payload portion of a message.
const MAX_PAYLOAD: usize = MAX_MSG_SIZE - FuseWireHeader::SIZE;

/// Depth of the pending-request queue per channel.
const QUEUE_DEPTH: usize = 64;

/// Maximum number of registered `/dev/fuse` channels (minor numbers).
const MAX_CHANNELS: usize = 16;

/// FUSE protocol major version supported by this implementation.
const FUSE_VERSION_MAJOR: u32 = 7;

/// FUSE protocol minor version supported by this implementation.
const FUSE_VERSION_MINOR: u32 = 39;

// ── FUSE capability flags (INIT bitmask) ────────────────────────

/// Capability: async read (FUSE_ASYNC_READ).
pub const CAP_ASYNC_READ: u32 = 1 << 0;
/// Capability: POSIX locks (FUSE_POSIX_LOCKS).
pub const CAP_POSIX_LOCKS: u32 = 1 << 1;
/// Capability: file handle in release (FUSE_FILE_OPS).
pub const CAP_FILE_OPS: u32 = 1 << 2;
/// Capability: atomic O_TRUNC (FUSE_ATOMIC_O_TRUNC).
pub const CAP_ATOMIC_O_TRUNC: u32 = 1 << 3;
/// Capability: export support (FUSE_EXPORT_SUPPORT).
pub const CAP_EXPORT_SUPPORT: u32 = 1 << 4;
/// Capability: big write (FUSE_BIG_WRITES).
pub const CAP_BIG_WRITES: u32 = 1 << 5;
/// Capability: don't mask umask (FUSE_DONT_MASK).
pub const CAP_DONT_MASK: u32 = 1 << 6;
/// Capability: flock locks (FUSE_FLOCK_LOCKS).
pub const CAP_FLOCK_LOCKS: u32 = 1 << 10;
/// Capability: write-back cache (FUSE_WRITEBACK_CACHE).
pub const CAP_WRITEBACK_CACHE: u32 = 1 << 16;
/// Capability: parallel directory operations (FUSE_PARALLEL_DIROPS).
pub const CAP_PARALLEL_DIROPS: u32 = 1 << 18;

// ── FuseDevOpcode ───────────────────────────────────────────────

/// Extended FUSE opcode set used by the `/dev/fuse` channel layer.
///
/// Extends the basic set in `fuse::FuseOpcode` with additional operations
/// introduced in later FUSE protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseDevOpcode {
    // ── Core file operations ─────────────────────────
    /// Directory entry lookup.
    Lookup = 1,
    /// Decrement inode lookup count.
    Forget = 2,
    /// Get file attributes.
    Getattr = 3,
    /// Set file attributes.
    Setattr = 4,
    /// Read symlink target.
    Readlink = 5,
    /// Create symlink.
    Symlink = 6,
    /// Create device/pipe/socket node.
    Mknod = 8,
    /// Create directory.
    Mkdir = 9,
    /// Remove file.
    Unlink = 10,
    /// Remove directory.
    Rmdir = 11,
    /// Rename file or directory.
    Rename = 12,
    /// Create hard link.
    Link = 13,
    /// Open file.
    Open = 14,
    /// Read from open file.
    Read = 15,
    /// Write to open file.
    Write = 16,
    /// Get filesystem statistics.
    Statfs = 17,
    /// Close open file.
    Release = 18,
    /// Fsync file data.
    Fsync = 20,
    /// Set extended attribute.
    Setxattr = 21,
    /// Get extended attribute.
    Getxattr = 22,
    /// List extended attributes.
    Listxattr = 23,
    /// Remove extended attribute.
    Removexattr = 24,
    /// Flush open file.
    Flush = 25,
    /// Initialise FUSE connection.
    Init = 26,
    /// Open directory.
    Opendir = 27,
    /// Read directory entries.
    Readdir = 28,
    /// Release open directory.
    Releasedir = 29,
    /// Fsync directory.
    Fsyncdir = 30,
    /// Get/set file lock.
    Getlk = 31,
    /// Acquire write lock.
    Setlk = 32,
    /// Acquire write lock (wait).
    Setlkw = 33,
    /// Check file access permissions.
    Access = 34,
    /// Atomic create + open.
    Create = 35,
    /// Interrupt a pending request.
    Interrupt = 36,
    /// Map file block to device block.
    Bmap = 37,
    /// Destroy FUSE connection.
    Destroy = 38,
    /// Poll for I/O readiness.
    Poll = 39,
    /// Notify reply (kernel → daemon).
    NotifyReply = 40,
    /// Batch forget (multiple inodes).
    BatchForget = 41,
    /// Pre-allocate or de-allocate file space.
    Fallocate = 43,
    /// Read directory entries with attributes.
    Readdirplus = 44,
    /// Rename with flags (RENAME2).
    Rename2 = 45,
    /// Seek for hole/data (lseek SEEK_HOLE/SEEK_DATA).
    Lseek = 46,
    /// Copy file range (copy_file_range).
    CopyFileRange = 47,
    /// Set up mapping for direct I/O.
    SetupMapping = 48,
    /// Remove direct I/O mapping.
    RemoveMapping = 49,
    /// Sync filesystem metadata.
    Syncfs = 50,
}

impl FuseDevOpcode {
    /// Convert a raw u32 to a [`FuseDevOpcode`].
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for unknown opcodes.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            1 => Ok(Self::Lookup),
            2 => Ok(Self::Forget),
            3 => Ok(Self::Getattr),
            4 => Ok(Self::Setattr),
            5 => Ok(Self::Readlink),
            6 => Ok(Self::Symlink),
            8 => Ok(Self::Mknod),
            9 => Ok(Self::Mkdir),
            10 => Ok(Self::Unlink),
            11 => Ok(Self::Rmdir),
            12 => Ok(Self::Rename),
            13 => Ok(Self::Link),
            14 => Ok(Self::Open),
            15 => Ok(Self::Read),
            16 => Ok(Self::Write),
            17 => Ok(Self::Statfs),
            18 => Ok(Self::Release),
            20 => Ok(Self::Fsync),
            21 => Ok(Self::Setxattr),
            22 => Ok(Self::Getxattr),
            23 => Ok(Self::Listxattr),
            24 => Ok(Self::Removexattr),
            25 => Ok(Self::Flush),
            26 => Ok(Self::Init),
            27 => Ok(Self::Opendir),
            28 => Ok(Self::Readdir),
            29 => Ok(Self::Releasedir),
            30 => Ok(Self::Fsyncdir),
            31 => Ok(Self::Getlk),
            32 => Ok(Self::Setlk),
            33 => Ok(Self::Setlkw),
            34 => Ok(Self::Access),
            35 => Ok(Self::Create),
            36 => Ok(Self::Interrupt),
            37 => Ok(Self::Bmap),
            38 => Ok(Self::Destroy),
            39 => Ok(Self::Poll),
            40 => Ok(Self::NotifyReply),
            41 => Ok(Self::BatchForget),
            43 => Ok(Self::Fallocate),
            44 => Ok(Self::Readdirplus),
            45 => Ok(Self::Rename2),
            46 => Ok(Self::Lseek),
            47 => Ok(Self::CopyFileRange),
            48 => Ok(Self::SetupMapping),
            49 => Ok(Self::RemoveMapping),
            50 => Ok(Self::Syncfs),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Wire header ─────────────────────────────────────────────────

/// On-wire FUSE message header (request direction: kernel → daemon).
///
/// Every message on `/dev/fuse` starts with this fixed-length header
/// followed by opcode-specific payload bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseWireHeader {
    /// Total message length (this header + payload).
    pub len: u32,
    /// Operation code (`FuseDevOpcode as u32`).
    pub opcode: u32,
    /// Unique request identifier for reply matching.
    pub unique: u64,
    /// Target inode / node-id.
    pub nodeid: u64,
    /// UID of the requesting process.
    pub uid: u32,
    /// GID of the requesting process.
    pub gid: u32,
    /// PID of the requesting process.
    pub pid: u32,
    /// Padding for 8-byte alignment.
    pub _pad: u32,
}

impl FuseWireHeader {
    /// Byte size of the wire header.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Build a new header for a request with no payload.
    pub const fn new(opcode: u32, unique: u64, nodeid: u64, uid: u32, gid: u32, pid: u32) -> Self {
        Self {
            len: Self::SIZE as u32,
            opcode,
            unique,
            nodeid,
            uid,
            gid,
            pid,
            _pad: 0,
        }
    }
}

/// On-wire reply header (response direction: daemon → kernel).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseWireReplyHeader {
    /// Total reply length (this header + payload).
    pub len: u32,
    /// Negative errno on error, 0 on success.
    pub error: i32,
    /// Matches the `unique` field of the request.
    pub unique: u64,
}

impl FuseWireReplyHeader {
    /// Byte size of the reply header.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Build a success reply header with no payload.
    pub const fn ok(unique: u64) -> Self {
        Self {
            len: Self::SIZE as u32,
            error: 0,
            unique,
        }
    }

    /// Build an error reply header.
    pub const fn err(unique: u64, errno: i32) -> Self {
        Self {
            len: Self::SIZE as u32,
            error: errno,
            unique,
        }
    }
}

// ── FuseMessage ─────────────────────────────────────────────────

/// A serialised FUSE message (request or reply) ready for I/O.
///
/// The `payload` buffer holds the opcode-specific bytes that follow the
/// wire header.  For replies, the `reply_header` field is populated.
pub struct FuseMessage {
    /// Request direction header (filled for outgoing requests).
    pub header: FuseWireHeader,
    /// Reply direction header (filled for incoming replies).
    pub reply_header: FuseWireReplyHeader,
    /// Whether this is a reply (true) or a request (false).
    pub is_reply: bool,
    /// Opcode-specific payload.
    pub payload: [u8; MAX_PAYLOAD],
    /// Number of valid bytes in `payload`.
    pub payload_len: usize,
}

impl FuseMessage {
    /// Build an outgoing request message.
    pub fn request(header: FuseWireHeader) -> Self {
        Self {
            header,
            reply_header: FuseWireReplyHeader::ok(0),
            is_reply: false,
            payload: [0u8; MAX_PAYLOAD],
            payload_len: 0,
        }
    }

    /// Build an outgoing request with a payload.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the payload exceeds [`MAX_PAYLOAD`].
    pub fn request_with_payload(header: FuseWireHeader, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        let mut msg = Self::request(header);
        msg.payload[..data.len()].copy_from_slice(data);
        msg.payload_len = data.len();
        Ok(msg)
    }

    /// Build an incoming reply message.
    pub fn reply(rh: FuseWireReplyHeader) -> Self {
        Self {
            header: FuseWireHeader::new(0, 0, 0, 0, 0, 0),
            reply_header: rh,
            is_reply: true,
            payload: [0u8; MAX_PAYLOAD],
            payload_len: 0,
        }
    }

    /// Build an incoming reply with a payload.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the payload exceeds [`MAX_PAYLOAD`].
    pub fn reply_with_payload(rh: FuseWireReplyHeader, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        let mut msg = Self::reply(rh);
        msg.payload[..data.len()].copy_from_slice(data);
        msg.payload_len = data.len();
        Ok(msg)
    }

    /// Return the unique request ID regardless of direction.
    pub fn unique(&self) -> u64 {
        if self.is_reply {
            self.reply_header.unique
        } else {
            self.header.unique
        }
    }

    /// Whether this reply indicates a protocol-level error.
    pub fn is_error(&self) -> bool {
        self.is_reply && self.reply_header.error != 0
    }

    /// Return the payload slice.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }
}

// ── FuseInitConfig ──────────────────────────────────────────────

/// Capability flags and limits negotiated during the FUSE INIT handshake.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseInitConfig {
    /// Protocol major version agreed with the daemon.
    pub major: u32,
    /// Protocol minor version agreed with the daemon.
    pub minor: u32,
    /// Capability bitmask (intersection of kernel and daemon caps).
    pub flags: u32,
    /// Maximum write size the daemon accepts.
    pub max_write: u32,
    /// Maximum read-ahead size.
    pub max_readahead: u32,
    /// Maximum number of background requests.
    pub max_background: u16,
    /// Congestion threshold.
    pub congestion_threshold: u16,
    /// Whether the handshake has completed.
    pub initialized: bool,
}

impl FuseInitConfig {
    /// Default configuration before the INIT handshake.
    pub fn default_config() -> Self {
        Self {
            major: FUSE_VERSION_MAJOR,
            minor: FUSE_VERSION_MINOR,
            flags: CAP_ASYNC_READ | CAP_BIG_WRITES | CAP_WRITEBACK_CACHE,
            max_write: 131072,
            max_readahead: 131072,
            max_background: 12,
            congestion_threshold: 9,
            initialized: false,
        }
    }

    /// Complete the handshake with daemon-supplied values.
    pub fn complete(&mut self, major: u32, minor: u32, flags: u32, max_write: u32) {
        self.major = major;
        self.minor = minor;
        // Only keep capabilities both sides advertise.
        self.flags &= flags;
        self.max_write = max_write;
        self.initialized = true;
    }

    /// Whether a particular capability flag is enabled.
    pub fn has_cap(&self, cap: u32) -> bool {
        self.flags & cap != 0
    }
}

// ── FuseIoStats ─────────────────────────────────────────────────

/// Per-channel I/O counters for observability.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseIoStats {
    /// Total requests enqueued (kernel → daemon).
    pub requests_sent: u64,
    /// Total replies received (daemon → kernel).
    pub replies_received: u64,
    /// Requests that timed out or were interrupted.
    pub errors: u64,
    /// Bytes sent in request payloads.
    pub bytes_sent: u64,
    /// Bytes received in reply payloads.
    pub bytes_received: u64,
    /// Peak queue depth observed.
    pub peak_queue_depth: u32,
}

impl FuseIoStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            requests_sent: 0,
            replies_received: 0,
            errors: 0,
            bytes_sent: 0,
            bytes_received: 0,
            peak_queue_depth: 0,
        }
    }

    /// Record a sent request.
    pub fn record_send(&mut self, payload_bytes: usize, queue_depth: u32) {
        self.requests_sent = self.requests_sent.wrapping_add(1);
        self.bytes_sent = self.bytes_sent.wrapping_add(payload_bytes as u64);
        if queue_depth > self.peak_queue_depth {
            self.peak_queue_depth = queue_depth;
        }
    }

    /// Record a received reply.
    pub fn record_recv(&mut self, payload_bytes: usize) {
        self.replies_received = self.replies_received.wrapping_add(1);
        self.bytes_received = self.bytes_received.wrapping_add(payload_bytes as u64);
    }

    /// Record an error (timeout / interrupt / protocol violation).
    pub fn record_error(&mut self) {
        self.errors = self.errors.wrapping_add(1);
    }
}

// ── Queue slot ──────────────────────────────────────────────────

/// Lifecycle of a queued request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    /// Slot is available for reuse.
    Free,
    /// Request has been enqueued but not yet read by the daemon.
    Pending,
    /// Daemon has read the request; awaiting reply.
    InFlight,
    /// Reply has arrived; waiting for the kernel caller to collect it.
    Done,
}

/// A single slot in the per-channel request queue.
struct QueueSlot {
    state: SlotState,
    unique: u64,
    opcode: u32,
    nodeid: u64,
    /// Request payload (kernel arguments).
    req_payload: [u8; MAX_PAYLOAD],
    req_payload_len: usize,
    /// Reply error code.
    reply_error: i32,
    /// Reply payload (daemon result).
    reply_payload: [u8; MAX_PAYLOAD],
    reply_payload_len: usize,
}

impl QueueSlot {
    const fn empty() -> Self {
        Self {
            state: SlotState::Free,
            unique: 0,
            opcode: 0,
            nodeid: 0,
            req_payload: [0u8; MAX_PAYLOAD],
            req_payload_len: 0,
            reply_error: 0,
            reply_payload: [0u8; MAX_PAYLOAD],
            reply_payload_len: 0,
        }
    }
}

// ── FuseDevChannel ──────────────────────────────────────────────

/// A single `/dev/fuse` channel binding a VFS mount to a user-space daemon.
///
/// Each mounted FUSE filesystem gets one channel.  The kernel enqueues
/// requests via [`Self::send_request`]; the daemon reads them with
/// [`Self::read_request`] and writes replies with [`Self::write_reply`].
/// The kernel collects the reply via [`Self::recv_reply`].
pub struct FuseDevChannel {
    /// Minor device number (identifies this channel in the registry).
    minor: u32,
    /// Whether the channel is open (daemon has opened `/dev/fuse`).
    open: bool,
    /// Negotiated connection configuration.
    config: FuseInitConfig,
    /// I/O statistics.
    stats: FuseIoStats,
    /// Request queue.
    queue: [QueueSlot; QUEUE_DEPTH],
    /// Next unique request ID.
    next_unique: u64,
    /// Current queue depth (pending + in-flight).
    queue_depth: u32,
}

impl FuseDevChannel {
    /// Create a new, closed channel with the given minor number.
    pub fn new(minor: u32) -> Self {
        const EMPTY: QueueSlot = QueueSlot::empty();
        Self {
            minor,
            open: false,
            config: FuseInitConfig::default_config(),
            stats: FuseIoStats::new(),
            queue: [EMPTY; QUEUE_DEPTH],
            next_unique: 1,
            queue_depth: 0,
        }
    }

    /// Open the channel (daemon has opened `/dev/fuse`).
    pub fn open(&mut self) {
        self.open = true;
    }

    /// Close the channel (daemon exited or unmounted).
    pub fn close(&mut self) {
        self.open = false;
    }

    /// Whether the daemon has the channel open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Minor device number.
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// Negotiated connection configuration.
    pub fn config(&self) -> &FuseInitConfig {
        &self.config
    }

    /// Mutable reference to the negotiated configuration.
    pub fn config_mut(&mut self) -> &mut FuseInitConfig {
        &mut self.config
    }

    /// I/O statistics snapshot.
    pub fn stats(&self) -> &FuseIoStats {
        &self.stats
    }

    // ── Kernel-side API ─────────────────────────────────────────

    /// Enqueue a VFS request destined for the user-space daemon.
    ///
    /// Returns the unique request ID assigned to this request, which
    /// callers pass to [`Self::recv_reply`] to collect the result.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the channel is not open or payload too large.
    /// - `OutOfMemory` if the queue is full.
    pub fn send_request(
        &mut self,
        opcode: FuseDevOpcode,
        nodeid: u64,
        payload: &[u8],
    ) -> Result<u64> {
        if !self.open {
            return Err(Error::InvalidArgument);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        if self.queue_depth as usize >= QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }

        let unique = self.next_unique;
        self.next_unique = self.next_unique.wrapping_add(1);

        for slot in self.queue.iter_mut() {
            if slot.state == SlotState::Free {
                slot.state = SlotState::Pending;
                slot.unique = unique;
                slot.opcode = opcode as u32;
                slot.nodeid = nodeid;
                slot.req_payload[..payload.len()].copy_from_slice(payload);
                slot.req_payload_len = payload.len();
                slot.reply_error = 0;
                slot.reply_payload_len = 0;
                self.queue_depth = self.queue_depth.saturating_add(1);
                self.stats.record_send(payload.len(), self.queue_depth);
                return Ok(unique);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Read the next pending request (daemon-side read from `/dev/fuse`).
    ///
    /// Transitions the slot from `Pending` → `InFlight` and returns the
    /// serialised [`FuseMessage`] ready for writing to user-space.
    ///
    /// # Errors
    ///
    /// - `WouldBlock` if no pending requests are available.
    pub fn read_request(&mut self) -> Result<FuseMessage> {
        for slot in self.queue.iter_mut() {
            if slot.state == SlotState::Pending {
                slot.state = SlotState::InFlight;
                let hdr = FuseWireHeader::new(slot.opcode, slot.unique, slot.nodeid, 0, 0, 0);
                let msg = FuseMessage::request_with_payload(
                    hdr,
                    &slot.req_payload[..slot.req_payload_len],
                )?;
                return Ok(msg);
            }
        }
        Err(Error::WouldBlock)
    }

    /// Submit a daemon reply for an in-flight request (daemon-side write).
    ///
    /// Transitions the slot from `InFlight` → `Done`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no in-flight request matches `unique`.
    /// - `InvalidArgument` if `payload` is too large.
    pub fn write_reply(&mut self, unique: u64, error: i32, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        for slot in self.queue.iter_mut() {
            if slot.state == SlotState::InFlight && slot.unique == unique {
                slot.state = SlotState::Done;
                slot.reply_error = error;
                slot.reply_payload[..payload.len()].copy_from_slice(payload);
                slot.reply_payload_len = payload.len();
                self.stats.record_recv(payload.len());
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Collect a completed reply (kernel VFS side).
    ///
    /// Returns the reply [`FuseMessage`] and frees the queue slot.
    ///
    /// # Errors
    ///
    /// - `WouldBlock` if the reply for `unique` is not yet available.
    /// - `NotFound` if `unique` is unknown.
    pub fn recv_reply(&mut self, unique: u64) -> Result<FuseMessage> {
        // Check if known at all.
        let found = self
            .queue
            .iter()
            .any(|s| s.unique == unique && s.state != SlotState::Free);
        if !found {
            return Err(Error::NotFound);
        }

        for slot in self.queue.iter_mut() {
            if slot.unique == unique && slot.state == SlotState::Done {
                let rh = FuseWireReplyHeader {
                    len: (FuseWireReplyHeader::SIZE + slot.reply_payload_len) as u32,
                    error: slot.reply_error,
                    unique,
                };
                let msg = FuseMessage::reply_with_payload(
                    rh,
                    &slot.reply_payload[..slot.reply_payload_len],
                )?;
                // Free the slot.
                *slot = QueueSlot::empty();
                self.queue_depth = self.queue_depth.saturating_sub(1);
                return Ok(msg);
            }
        }

        Err(Error::WouldBlock)
    }

    /// Interrupt (cancel) a pending or in-flight request.
    ///
    /// The slot is freed immediately; the daemon will receive an error
    /// reply with `error = -EINTR` if it tries to complete the request.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `unique` is unknown or already completed.
    pub fn interrupt(&mut self, unique: u64) -> Result<()> {
        for slot in self.queue.iter_mut() {
            if slot.unique == unique
                && (slot.state == SlotState::Pending || slot.state == SlotState::InFlight)
            {
                *slot = QueueSlot::empty();
                self.queue_depth = self.queue_depth.saturating_sub(1);
                self.stats.record_error();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Number of requests currently in the queue (pending + in-flight).
    pub fn queue_depth(&self) -> u32 {
        self.queue_depth
    }

    /// Number of pending (not yet read by daemon) requests.
    pub fn pending_count(&self) -> usize {
        self.queue
            .iter()
            .filter(|s| s.state == SlotState::Pending)
            .count()
    }

    /// Number of in-flight (read by daemon, awaiting reply) requests.
    pub fn in_flight_count(&self) -> usize {
        self.queue
            .iter()
            .filter(|s| s.state == SlotState::InFlight)
            .count()
    }
}

impl Default for FuseDevChannel {
    fn default() -> Self {
        Self::new(0)
    }
}

// ── FuseDevRegistry ─────────────────────────────────────────────

/// Global registry mapping minor device numbers to [`FuseDevChannel`]s.
///
/// When a FUSE filesystem is mounted, the kernel allocates a minor number,
/// creates a channel in this registry, and exposes `/dev/fuse` with that
/// minor to the mounting daemon.
pub struct FuseDevRegistry {
    /// Channel slots indexed by minor number (0 … MAX_CHANNELS-1).
    channels: [Option<FuseDevChannel>; MAX_CHANNELS],
    /// Number of open (allocated) channels.
    count: usize,
    /// Next minor number to assign.
    next_minor: u32,
}

impl Default for FuseDevRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseDevRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        const NONE: Option<FuseDevChannel> = None;
        Self {
            channels: [NONE; MAX_CHANNELS],
            count: 0,
            next_minor: 0,
        }
    }

    /// Allocate a new channel and return its minor number.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if all [`MAX_CHANNELS`] slots are occupied.
    pub fn alloc_channel(&mut self) -> Result<u32> {
        if self.count >= MAX_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        let minor = self.next_minor;
        self.next_minor = self.next_minor.wrapping_add(1);

        for slot in self.channels.iter_mut() {
            if slot.is_none() {
                *slot = Some(FuseDevChannel::new(minor));
                self.count += 1;
                return Ok(minor);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Release a channel by minor number.
    ///
    /// The channel is closed and its slot freed.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no channel with this minor number exists.
    pub fn free_channel(&mut self, minor: u32) -> Result<()> {
        for slot in self.channels.iter_mut() {
            if let Some(ch) = slot {
                if ch.minor() == minor {
                    ch.close();
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get an immutable reference to a channel by minor number.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching channel exists.
    pub fn get(&self, minor: u32) -> Result<&FuseDevChannel> {
        self.channels
            .iter()
            .flatten()
            .find(|ch| ch.minor() == minor)
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a channel by minor number.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching channel exists.
    pub fn get_mut(&mut self, minor: u32) -> Result<&mut FuseDevChannel> {
        self.channels
            .iter_mut()
            .flatten()
            .find(|ch| ch.minor() == minor)
            .ok_or(Error::NotFound)
    }

    /// Number of allocated channels.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether the registry is empty (no channels allocated).
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── Helper — full round-trip ─────────────────────────────────────

/// Convenience wrapper: send a request and immediately collect the reply.
///
/// This is only useful in synchronous test harnesses where the "daemon" is
/// in the same thread.  Real daemons communicate asynchronously via
/// [`FuseDevChannel::read_request`] and [`FuseDevChannel::write_reply`].
///
/// # Errors
///
/// Propagates errors from `send_request`, `read_request`, `write_reply`,
/// and `recv_reply`.
pub fn sync_round_trip(
    channel: &mut FuseDevChannel,
    opcode: FuseDevOpcode,
    nodeid: u64,
    req_payload: &[u8],
    reply_error: i32,
    reply_payload: &[u8],
) -> Result<FuseMessage> {
    // 1. Kernel enqueues request.
    let unique = channel.send_request(opcode, nodeid, req_payload)?;
    // 2. Daemon reads request.
    let _req_msg = channel.read_request()?;
    // 3. Daemon writes reply.
    channel.write_reply(unique, reply_error, reply_payload)?;
    // 4. Kernel collects reply.
    channel.recv_reply(unique)
}
