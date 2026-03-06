// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE (Filesystem in Userspace) protocol support.
//!
//! Implements the kernel side of the FUSE protocol, allowing
//! user-space daemons to serve filesystem requests. The kernel
//! translates VFS operations into FUSE request messages, sends
//! them to the user-space daemon via a [`FuseConnection`], and
//! waits for response messages.
//!
//! # Architecture
//!
//! ```text
//! VFS operation
//!   → FuseMount::dispatch()
//!     → serialize FuseInHeader + args
//!       → enqueue in FuseConnection
//!         → user-space daemon reads /dev/fuse
//!           → processes request
//!             → writes FuseOutHeader + reply
//!               → kernel dequeues response
//!                 → returns result to VFS caller
//! ```
//!
//! # Structures
//!
//! - [`FuseOpcode`] — 22 FUSE operation codes
//! - [`FuseInHeader`] / [`FuseOutHeader`] — repr(C) wire headers
//! - [`FuseAttr`] — repr(C) inode attributes
//! - [`FuseEntryOut`] — repr(C) lookup response
//! - [`FuseRequest`] / [`FuseResponse`] — parsed request/response
//! - [`FuseConnection`] — request/response queue (64 slots)
//! - [`FuseMount`] — mount point with connection and node mapping
//! - [`FuseRegistry`] — global registry of FUSE mount points (8 mounts)

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of pending requests in a FUSE connection.
const MAX_PENDING_REQUESTS: usize = 64;

/// Maximum number of inode-to-nodeid mappings per mount.
const MAX_NODE_MAPPINGS: usize = 256;

/// Maximum number of FUSE mount points in the registry.
const MAX_FUSE_MOUNTS: usize = 8;

/// Maximum mount path length in bytes.
const MAX_MOUNT_PATH: usize = 256;

/// Maximum data payload per FUSE request/response (4 KiB).
const MAX_FUSE_DATA: usize = 4096;

/// FUSE protocol major version.
const FUSE_KERNEL_VERSION: u32 = 7;

/// FUSE protocol minor version.
const FUSE_KERNEL_MINOR_VERSION: u32 = 39;

// ── FuseOpcode ──────────────────────────────────────────────────

/// FUSE operation codes.
///
/// Each variant maps to a FUSE protocol operation that the kernel
/// can request from a user-space filesystem daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseOpcode {
    /// Look up a directory entry by name and get its attributes.
    Lookup = 1,
    /// Forget about an inode (decrement lookup count).
    Forget = 2,
    /// Get file attributes.
    Getattr = 3,
    /// Set file attributes.
    Setattr = 4,
    /// Read symbolic link target.
    Readlink = 5,
    /// Create a special file (device, pipe, socket).
    Mknod = 8,
    /// Create a directory.
    Mkdir = 9,
    /// Remove a file.
    Unlink = 10,
    /// Remove a directory.
    Rmdir = 11,
    /// Rename a file or directory.
    Rename = 12,
    /// Create a hard link.
    Link = 13,
    /// Open a file.
    Open = 14,
    /// Read data from an open file.
    Read = 15,
    /// Write data to an open file.
    Write = 16,
    /// Get filesystem statistics.
    Statfs = 17,
    /// Release an open file (close).
    Release = 18,
    /// Synchronize file contents.
    Fsync = 20,
    /// Open a directory for reading.
    Opendir = 27,
    /// Read directory entries.
    Readdir = 28,
    /// Release an open directory.
    Releasedir = 29,
    /// Initialize the FUSE connection.
    Init = 26,
    /// Clean up and destroy the FUSE connection.
    Destroy = 38,
}

impl FuseOpcode {
    /// Try to convert a raw u32 value to a [`FuseOpcode`].
    pub fn from_u32(val: u32) -> Result<Self> {
        match val {
            1 => Ok(Self::Lookup),
            2 => Ok(Self::Forget),
            3 => Ok(Self::Getattr),
            4 => Ok(Self::Setattr),
            5 => Ok(Self::Readlink),
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
            26 => Ok(Self::Init),
            27 => Ok(Self::Opendir),
            28 => Ok(Self::Readdir),
            29 => Ok(Self::Releasedir),
            38 => Ok(Self::Destroy),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Wire format structures (repr(C)) ───────────────────────────

/// FUSE request header (sent from kernel to user-space daemon).
///
/// Every FUSE request begins with this fixed-size header, followed
/// by opcode-specific arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseInHeader {
    /// Total length of the request (header + arguments + data).
    pub len: u32,
    /// Operation code (see [`FuseOpcode`]).
    pub opcode: u32,
    /// Unique request identifier for matching responses.
    pub unique: u64,
    /// Inode number the operation applies to.
    pub nodeid: u64,
    /// UID of the calling process.
    pub uid: u32,
    /// GID of the calling process.
    pub gid: u32,
    /// PID of the calling process.
    pub pid: u32,
    /// Padding for alignment.
    pub padding: u32,
}

impl FuseInHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new request header.
    pub const fn new(opcode: u32, unique: u64, nodeid: u64, uid: u32, gid: u32, pid: u32) -> Self {
        Self {
            len: Self::SIZE as u32,
            opcode,
            unique,
            nodeid,
            uid,
            gid,
            pid,
            padding: 0,
        }
    }
}

/// FUSE response header (sent from user-space daemon to kernel).
///
/// Every FUSE response begins with this fixed-size header, followed
/// by opcode-specific response data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseOutHeader {
    /// Total length of the response (header + data).
    pub len: u32,
    /// Error code (negative errno, 0 for success).
    pub error: i32,
    /// Unique request identifier (matches the corresponding request).
    pub unique: u64,
}

impl FuseOutHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new response header.
    pub const fn new(unique: u64, error: i32) -> Self {
        Self {
            len: Self::SIZE as u32,
            error,
            unique,
        }
    }
}

/// FUSE inode attributes.
///
/// Represents the on-wire format of inode metadata exchanged
/// between the kernel and the user-space daemon.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseAttr {
    /// Inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time (seconds).
    pub atime: u64,
    /// Last modification time (seconds).
    pub mtime: u64,
    /// Last status change time (seconds).
    pub ctime: u64,
    /// Last access time (nanoseconds).
    pub atimensec: u32,
    /// Last modification time (nanoseconds).
    pub mtimensec: u32,
    /// Last status change time (nanoseconds).
    pub ctimensec: u32,
    /// File mode (type + permissions).
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Device number (for device files).
    pub rdev: u32,
    /// Block size for filesystem I/O.
    pub blksize: u32,
    /// Padding for alignment.
    pub padding: u32,
}

/// FUSE lookup response.
///
/// Returned by the user-space daemon in response to a `Lookup`
/// request. Contains the node ID and cached attributes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseEntryOut {
    /// Inode ID assigned by the user-space daemon.
    pub nodeid: u64,
    /// Inode generation number (for NFS export).
    pub generation: u64,
    /// Cache validity timeout for the entry (seconds).
    pub entry_valid: u64,
    /// Cache validity timeout for the attributes (seconds).
    pub attr_valid: u64,
    /// Cache validity timeout for the entry (nanoseconds).
    pub entry_valid_nsec: u32,
    /// Cache validity timeout for the attributes (nanoseconds).
    pub attr_valid_nsec: u32,
    /// Inode attributes of the looked-up entry.
    pub attr: FuseAttr,
}

// ── Parsed request/response ─────────────────────────────────────

/// A parsed FUSE request ready for dispatch.
///
/// Wraps the wire header with an optional data payload for
/// operations that carry additional arguments (e.g., write data,
/// lookup name).
pub struct FuseRequest {
    /// Request header.
    pub header: FuseInHeader,
    /// Optional data payload (lookup name, write data, etc.).
    pub data: [u8; MAX_FUSE_DATA],
    /// Length of valid data in the payload buffer.
    pub data_len: usize,
}

impl FuseRequest {
    /// Create a new request with no data payload.
    pub fn new(header: FuseInHeader) -> Self {
        Self {
            header,
            data: [0u8; MAX_FUSE_DATA],
            data_len: 0,
        }
    }

    /// Create a request with a data payload.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the data exceeds [`MAX_FUSE_DATA`].
    pub fn with_data(header: FuseInHeader, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_FUSE_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut req = Self::new(header);
        req.data[..data.len()].copy_from_slice(data);
        req.data_len = data.len();
        Ok(req)
    }

    /// Return the parsed opcode for this request.
    pub fn opcode(&self) -> Result<FuseOpcode> {
        FuseOpcode::from_u32(self.header.opcode)
    }
}

/// A parsed FUSE response from the user-space daemon.
///
/// Wraps the response header with an optional data payload
/// containing the operation result.
pub struct FuseResponse {
    /// Response header.
    pub header: FuseOutHeader,
    /// Optional data payload (read data, entry attributes, etc.).
    pub data: [u8; MAX_FUSE_DATA],
    /// Length of valid data in the payload buffer.
    pub data_len: usize,
}

impl FuseResponse {
    /// Create a new response with no data payload.
    pub fn new(header: FuseOutHeader) -> Self {
        Self {
            header,
            data: [0u8; MAX_FUSE_DATA],
            data_len: 0,
        }
    }

    /// Create a successful response with data.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the data exceeds [`MAX_FUSE_DATA`].
    pub fn with_data(header: FuseOutHeader, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_FUSE_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut resp = Self::new(header);
        resp.data[..data.len()].copy_from_slice(data);
        resp.data_len = data.len();
        Ok(resp)
    }

    /// Check whether this response indicates an error.
    pub fn is_error(&self) -> bool {
        self.header.error != 0
    }
}

// ── Connection ──────────────────────────────────────────────────

/// State of a pending FUSE request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestState {
    /// Slot is free.
    Free,
    /// Request has been enqueued, awaiting user-space pickup.
    Pending,
    /// Request has been read by user-space, awaiting response.
    InProgress,
    /// Response has been received.
    Completed,
}

/// A slot in the pending request table.
struct PendingSlot {
    /// Current state of this slot.
    state: RequestState,
    /// Unique request ID stored here for matching.
    unique: u64,
    /// The FUSE opcode for this request.
    opcode: u32,
    /// The node ID this request targets.
    nodeid: u64,
    /// Error code from the response (0 = success, negative = errno).
    error: i32,
    /// Response data buffer.
    response_data: [u8; MAX_FUSE_DATA],
    /// Length of valid response data.
    response_len: usize,
}

impl PendingSlot {
    /// Create an empty pending slot.
    const fn empty() -> Self {
        Self {
            state: RequestState::Free,
            unique: 0,
            opcode: 0,
            nodeid: 0,
            error: 0,
            response_data: [0u8; MAX_FUSE_DATA],
            response_len: 0,
        }
    }
}

/// FUSE connection between the kernel and a user-space daemon.
///
/// Manages a queue of pending requests and tracks their lifecycle
/// from enqueue through completion. The user-space daemon reads
/// requests via `/dev/fuse` and writes responses back.
pub struct FuseConnection {
    /// Pending request slots.
    slots: [PendingSlot; MAX_PENDING_REQUESTS],
    /// Number of slots currently in use (not Free).
    active_count: usize,
    /// Next unique request ID to assign.
    next_unique: u64,
    /// Whether the connection has been initialized (INIT handshake done).
    initialized: bool,
    /// Whether the connection is being destroyed.
    destroying: bool,
    /// FUSE protocol major version negotiated with user-space.
    proto_major: u32,
    /// FUSE protocol minor version negotiated with user-space.
    proto_minor: u32,
}

impl Default for FuseConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseConnection {
    /// Create a new, uninitialized FUSE connection.
    pub fn new() -> Self {
        const EMPTY: PendingSlot = PendingSlot::empty();
        Self {
            slots: [EMPTY; MAX_PENDING_REQUESTS],
            active_count: 0,
            next_unique: 1,
            initialized: false,
            destroying: false,
            proto_major: FUSE_KERNEL_VERSION,
            proto_minor: FUSE_KERNEL_MINOR_VERSION,
        }
    }

    /// Mark the connection as initialized after a successful INIT handshake.
    pub fn set_initialized(&mut self, major: u32, minor: u32) {
        self.initialized = true;
        self.proto_major = major;
        self.proto_minor = minor;
    }

    /// Check whether the INIT handshake has completed.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Check whether the connection is being destroyed.
    pub fn is_destroying(&self) -> bool {
        self.destroying
    }

    /// Mark the connection as destroying (DESTROY sent).
    pub fn set_destroying(&mut self) {
        self.destroying = true;
    }

    /// Enqueue a new FUSE request.
    ///
    /// Returns the unique request ID assigned to this request.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free request slots are available.
    /// - `InvalidArgument` if the connection is not initialized
    ///   (except for Init and Destroy opcodes).
    pub fn enqueue_request(&mut self, opcode: FuseOpcode, nodeid: u64) -> Result<u64> {
        // Allow Init and Destroy even when not initialized.
        if !self.initialized && opcode != FuseOpcode::Init && opcode != FuseOpcode::Destroy {
            return Err(Error::InvalidArgument);
        }
        if self.active_count >= MAX_PENDING_REQUESTS {
            return Err(Error::OutOfMemory);
        }

        let unique = self.next_unique;
        self.next_unique = self.next_unique.wrapping_add(1);

        for slot in self.slots.iter_mut() {
            if slot.state == RequestState::Free {
                slot.state = RequestState::Pending;
                slot.unique = unique;
                slot.opcode = opcode as u32;
                slot.nodeid = nodeid;
                slot.error = 0;
                slot.response_len = 0;
                self.active_count = self.active_count.saturating_add(1);
                return Ok(unique);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Dequeue the next pending request for user-space to process.
    ///
    /// Returns the request header if a pending request is available.
    /// Transitions the slot from `Pending` to `InProgress`.
    ///
    /// # Errors
    ///
    /// - `WouldBlock` if no pending requests are available.
    pub fn dequeue_request(&mut self) -> Result<FuseInHeader> {
        for slot in self.slots.iter_mut() {
            if slot.state == RequestState::Pending {
                slot.state = RequestState::InProgress;
                return Ok(FuseInHeader::new(
                    slot.opcode,
                    slot.unique,
                    slot.nodeid,
                    0, // uid filled by caller
                    0, // gid filled by caller
                    0, // pid filled by caller
                ));
            }
        }
        Err(Error::WouldBlock)
    }

    /// Complete a request by providing the response.
    ///
    /// Matches the response to a pending request by its unique ID
    /// and stores the result.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no in-progress request matches the unique ID.
    /// - `InvalidArgument` if the response data exceeds the buffer.
    pub fn complete_request(&mut self, unique: u64, error: i32, data: &[u8]) -> Result<()> {
        if data.len() > MAX_FUSE_DATA {
            return Err(Error::InvalidArgument);
        }

        for slot in self.slots.iter_mut() {
            if slot.state == RequestState::InProgress && slot.unique == unique {
                slot.state = RequestState::Completed;
                slot.error = error;
                slot.response_data[..data.len()].copy_from_slice(data);
                slot.response_len = data.len();
                return Ok(());
            }
        }

        Err(Error::NotFound)
    }

    /// Collect a completed response by unique ID.
    ///
    /// Returns the error code and copies response data into `buf`.
    /// Frees the slot after collection.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no completed request matches the unique ID.
    /// - `InvalidArgument` if the output buffer is too small.
    pub fn collect_response(&mut self, unique: u64, buf: &mut [u8]) -> Result<(i32, usize)> {
        for slot in self.slots.iter_mut() {
            if slot.state == RequestState::Completed && slot.unique == unique {
                if buf.len() < slot.response_len {
                    return Err(Error::InvalidArgument);
                }
                buf[..slot.response_len].copy_from_slice(&slot.response_data[..slot.response_len]);
                let error = slot.error;
                let len = slot.response_len;

                // Free the slot.
                slot.state = RequestState::Free;
                slot.unique = 0;
                slot.opcode = 0;
                slot.nodeid = 0;
                slot.error = 0;
                slot.response_len = 0;
                self.active_count = self.active_count.saturating_sub(1);

                return Ok((error, len));
            }
        }

        Err(Error::NotFound)
    }

    /// Return the number of active (non-free) request slots.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return the number of pending requests awaiting user-space.
    pub fn pending_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == RequestState::Pending)
            .count()
    }

    /// Return the negotiated FUSE protocol version.
    pub fn protocol_version(&self) -> (u32, u32) {
        (self.proto_major, self.proto_minor)
    }
}

// ── Node mapping ────────────────────────────────────────────────

/// Mapping from a VFS inode number to a FUSE node ID.
///
/// The FUSE daemon assigns its own node IDs which may differ
/// from the kernel's inode numbers. This structure tracks the
/// bidirectional mapping.
#[derive(Debug, Clone, Copy)]
struct NodeMapping {
    /// VFS inode number.
    ino: u64,
    /// FUSE node ID assigned by the daemon.
    nodeid: u64,
    /// Reference count (number of active lookups).
    refcount: u32,
    /// Whether this mapping slot is in use.
    in_use: bool,
}

impl NodeMapping {
    /// Create an empty mapping slot.
    const fn empty() -> Self {
        Self {
            ino: 0,
            nodeid: 0,
            refcount: 0,
            in_use: false,
        }
    }
}

// ── FuseMount ───────────────────────────────────────────────────

/// A FUSE mount point.
///
/// Associates a mount path with a [`FuseConnection`] and maintains
/// the inode-to-nodeid mapping table for this mount.
pub struct FuseMount {
    /// Mount path (e.g., "/mnt/fuse").
    mount_path: [u8; MAX_MOUNT_PATH],
    /// Length of the mount path.
    mount_path_len: usize,
    /// Connection to the user-space daemon.
    connection: FuseConnection,
    /// Inode-to-nodeid mapping table.
    nodes: [NodeMapping; MAX_NODE_MAPPINGS],
    /// Number of active node mappings.
    node_count: usize,
    /// Whether this mount is active.
    active: bool,
}

impl FuseMount {
    /// Create a new FUSE mount at the given path.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the path exceeds [`MAX_MOUNT_PATH`].
    pub fn new(path: &[u8]) -> Result<Self> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        let mut mount_path = [0u8; MAX_MOUNT_PATH];
        mount_path[..path.len()].copy_from_slice(path);

        const EMPTY_NODE: NodeMapping = NodeMapping::empty();

        let mut mount = Self {
            mount_path,
            mount_path_len: path.len(),
            connection: FuseConnection::new(),
            nodes: [EMPTY_NODE; MAX_NODE_MAPPINGS],
            node_count: 0,
            active: true,
        };

        // Root node (nodeid 1) is always mapped.
        mount.nodes[0] = NodeMapping {
            ino: 1,
            nodeid: 1,
            refcount: 1,
            in_use: true,
        };
        mount.node_count = 1;

        Ok(mount)
    }

    /// Return the mount path as a byte slice.
    pub fn mount_path(&self) -> &[u8] {
        &self.mount_path[..self.mount_path_len]
    }

    /// Return a mutable reference to the connection.
    pub fn connection_mut(&mut self) -> &mut FuseConnection {
        &mut self.connection
    }

    /// Return a reference to the connection.
    pub fn connection(&self) -> &FuseConnection {
        &self.connection
    }

    /// Whether this mount is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this mount (e.g., on unmount or DESTROY).
    pub fn deactivate(&mut self) {
        self.active = false;
        self.connection.set_destroying();
    }

    /// Map a VFS inode number to a FUSE node ID.
    ///
    /// If the mapping already exists, increments the reference count.
    /// Otherwise, creates a new mapping.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node mapping table is full.
    pub fn map_node(&mut self, ino: u64, nodeid: u64) -> Result<()> {
        // Check for existing mapping.
        for node in self.nodes.iter_mut() {
            if node.in_use && node.ino == ino && node.nodeid == nodeid {
                node.refcount = node.refcount.saturating_add(1);
                return Ok(());
            }
        }

        // Allocate a new mapping.
        if self.node_count >= MAX_NODE_MAPPINGS {
            return Err(Error::OutOfMemory);
        }

        for node in self.nodes.iter_mut() {
            if !node.in_use {
                *node = NodeMapping {
                    ino,
                    nodeid,
                    refcount: 1,
                    in_use: true,
                };
                self.node_count = self.node_count.saturating_add(1);
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Look up a FUSE node ID for a given VFS inode number.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mapping exists for the inode.
    pub fn lookup_nodeid(&self, ino: u64) -> Result<u64> {
        for node in &self.nodes {
            if node.in_use && node.ino == ino {
                return Ok(node.nodeid);
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a VFS inode number for a given FUSE node ID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mapping exists for the node ID.
    pub fn lookup_ino(&self, nodeid: u64) -> Result<u64> {
        for node in &self.nodes {
            if node.in_use && node.nodeid == nodeid {
                return Ok(node.ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Forget a node mapping (decrement reference count).
    ///
    /// If the reference count reaches zero, the mapping is freed.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mapping exists for the node ID.
    pub fn forget_node(&mut self, nodeid: u64, nlookup: u32) -> Result<()> {
        for node in self.nodes.iter_mut() {
            if node.in_use && node.nodeid == nodeid {
                if node.refcount <= nlookup {
                    node.in_use = false;
                    node.refcount = 0;
                    self.node_count = self.node_count.saturating_sub(1);
                } else {
                    node.refcount -= nlookup;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active node mappings.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Dispatch a FUSE operation for the given node.
    ///
    /// Enqueues a request in the connection and returns the unique
    /// request ID that callers can use to collect the response.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the mount is not active.
    /// - `OutOfMemory` if the request queue is full.
    pub fn dispatch(&mut self, opcode: FuseOpcode, nodeid: u64) -> Result<u64> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        self.connection.enqueue_request(opcode, nodeid)
    }
}

// ── FuseRegistry ────────────────────────────────────────────────

/// Global registry of FUSE mount points.
///
/// Tracks up to [`MAX_FUSE_MOUNTS`] active FUSE filesystems and
/// provides lookup by mount path.
pub struct FuseRegistry {
    /// Mount slots.
    mounts: [Option<FuseMount>; MAX_FUSE_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl Default for FuseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseRegistry {
    /// Create an empty FUSE registry.
    pub fn new() -> Self {
        const NONE: Option<FuseMount> = None;
        Self {
            mounts: [NONE; MAX_FUSE_MOUNTS],
            count: 0,
        }
    }

    /// Register a new FUSE mount.
    ///
    /// Returns the index at which the mount was registered.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the registry is full.
    /// - `AlreadyExists` if a mount with the same path exists.
    /// - `InvalidArgument` if the path is too long.
    pub fn register(&mut self, path: &[u8]) -> Result<usize> {
        // Check for duplicate paths.
        for mount in self.mounts.iter().flatten() {
            if mount.mount_path() == path {
                return Err(Error::AlreadyExists);
            }
        }

        if self.count >= MAX_FUSE_MOUNTS {
            return Err(Error::OutOfMemory);
        }

        let new_mount = FuseMount::new(path)?;

        for (idx, slot) in self.mounts.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(new_mount);
                self.count = self.count.saturating_add(1);
                return Ok(idx);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unregister a FUSE mount by path.
    ///
    /// Deactivates the mount and frees its slot.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mount with the given path exists.
    pub fn unregister(&mut self, path: &[u8]) -> Result<()> {
        for slot in self.mounts.iter_mut() {
            if let Some(mount) = slot {
                if mount.mount_path() == path {
                    mount.deactivate();
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a FUSE mount by path.
    ///
    /// Returns a reference to the mount if found.
    pub fn find(&self, path: &[u8]) -> Option<&FuseMount> {
        self.mounts
            .iter()
            .flatten()
            .find(|m| m.mount_path() == path)
    }

    /// Find a mutable reference to a FUSE mount by path.
    ///
    /// Returns a mutable reference to the mount if found.
    pub fn find_mut(&mut self, path: &[u8]) -> Option<&mut FuseMount> {
        self.mounts
            .iter_mut()
            .flatten()
            .find(|m| m.mount_path() == path)
    }

    /// Return the number of active FUSE mounts.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return a reference to a mount by index.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the index is out of bounds.
    /// - `NotFound` if the slot at the given index is empty.
    pub fn get(&self, index: usize) -> Result<&FuseMount> {
        if index >= MAX_FUSE_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        self.mounts[index].as_ref().ok_or(Error::NotFound)
    }

    /// Return a mutable reference to a mount by index.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the index is out of bounds.
    /// - `NotFound` if the slot at the given index is empty.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut FuseMount> {
        if index >= MAX_FUSE_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        self.mounts[index].as_mut().ok_or(Error::NotFound)
    }
}
