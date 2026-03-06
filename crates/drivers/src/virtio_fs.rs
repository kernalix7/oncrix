// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO filesystem (virtio-fs) device driver.
//!
//! Implements a VirtIO filesystem device (device type 26) using the
//! FUSE protocol over virtqueues. The host exposes a shared filesystem
//! that the guest can mount and access through standard FUSE operations.
//!
//! Communication follows the FUSE wire protocol: each request carries a
//! [`FuseInHeader`] followed by operation-specific data, and each
//! response carries a [`FuseOutHeader`] followed by reply data.
//!
//! The driver maintains a fixed-size ring of pending requests and
//! matches responses by their `unique` identifier.
//!
//! Reference: VirtIO Specification v1.2, §5.11 (File System Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO filesystem device type ID (§5.11).
pub const VIRTIO_FS_DEVICE_ID: u32 = 26;

/// Maximum data payload size per request/response.
const MAX_DATA_SIZE: usize = 4096;

/// Maximum number of in-flight requests.
const MAX_REQUESTS: usize = 32;

/// Maximum filesystem tag length in bytes.
const MAX_TAG_LEN: usize = 36;

/// Maximum number of virtio-fs devices in the registry.
const MAX_DEVICES: usize = 4;

// ---------------------------------------------------------------------------
// FUSE opcodes
// ---------------------------------------------------------------------------

/// FUSE operation codes used in the request header.
///
/// Each opcode corresponds to a filesystem operation that the guest
/// can request from the host via the FUSE protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FuseOpcode {
    /// Look up a directory entry by name.
    Lookup,
    /// Forget about an inode (drop reference count).
    Forget,
    /// Get file attributes.
    Getattr,
    /// Set file attributes.
    Setattr,
    /// Read the target of a symbolic link.
    Readlink,
    /// Open a file.
    Open,
    /// Read data from a file.
    Read,
    /// Write data to a file.
    Write,
    /// Create a directory.
    Mkdir,
    /// Remove a file.
    Unlink,
    /// Remove a directory.
    Rmdir,
    /// Rename a file or directory.
    Rename,
    /// Get filesystem statistics.
    Statfs,
    /// Release (close) an open file.
    Release,
    /// Synchronize file data to storage.
    Fsync,
    /// Read directory entries.
    Readdir,
    /// Create and open a file.
    Create,
    /// Initialize the FUSE connection.
    #[default]
    Init,
    /// Tear down the FUSE connection.
    Destroy,
}

impl FuseOpcode {
    /// Convert this opcode to its `u32` wire representation.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Lookup => 1,
            Self::Forget => 2,
            Self::Getattr => 3,
            Self::Setattr => 4,
            Self::Readlink => 5,
            Self::Open => 14,
            Self::Read => 15,
            Self::Write => 16,
            Self::Mkdir => 9,
            Self::Unlink => 10,
            Self::Rmdir => 11,
            Self::Rename => 12,
            Self::Statfs => 17,
            Self::Release => 18,
            Self::Fsync => 20,
            Self::Readdir => 28,
            Self::Create => 35,
            Self::Init => 26,
            Self::Destroy => 38,
        }
    }

    /// Convert a raw `u32` wire value to a [`FuseOpcode`].
    ///
    /// Returns `None` if the value does not correspond to a known opcode.
    pub fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Lookup),
            2 => Some(Self::Forget),
            3 => Some(Self::Getattr),
            4 => Some(Self::Setattr),
            5 => Some(Self::Readlink),
            14 => Some(Self::Open),
            15 => Some(Self::Read),
            16 => Some(Self::Write),
            9 => Some(Self::Mkdir),
            10 => Some(Self::Unlink),
            11 => Some(Self::Rmdir),
            12 => Some(Self::Rename),
            17 => Some(Self::Statfs),
            18 => Some(Self::Release),
            20 => Some(Self::Fsync),
            28 => Some(Self::Readdir),
            35 => Some(Self::Create),
            26 => Some(Self::Init),
            38 => Some(Self::Destroy),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// FUSE protocol structures
// ---------------------------------------------------------------------------

/// FUSE request header — precedes every request sent to the host.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseInHeader {
    /// Total length of the request (header + body).
    pub len: u32,
    /// Operation code (see [`FuseOpcode`]).
    pub opcode: u32,
    /// Unique request identifier.
    pub unique: u64,
    /// Inode number the operation targets.
    pub nodeid: u64,
    /// User ID of the calling process.
    pub uid: u32,
    /// Group ID of the calling process.
    pub gid: u32,
    /// Process ID of the calling process.
    pub pid: u32,
    /// Padding for alignment.
    pub padding: u32,
}

/// FUSE response header — precedes every response from the host.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseOutHeader {
    /// Total length of the response (header + body).
    pub len: u32,
    /// Error code (0 on success, negative errno on failure).
    pub error: i32,
    /// Unique identifier matching the original request.
    pub unique: u64,
}

/// FUSE file attributes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseAttr {
    /// Inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time (seconds since epoch).
    pub atime: u64,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
    /// Last status change time (seconds since epoch).
    pub ctime: u64,
    /// File type and permissions (e.g., `S_IFREG | 0o644`).
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
}

// ---------------------------------------------------------------------------
// Request / Response buffers
// ---------------------------------------------------------------------------

/// A pending FUSE request with its data payload.
#[derive(Clone)]
pub struct VirtioFsRequest {
    /// Request header.
    pub in_header: FuseInHeader,
    /// Data payload buffer.
    pub data: [u8; MAX_DATA_SIZE],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
    /// Whether this request has been completed.
    pub completed: bool,
}

impl Default for VirtioFsRequest {
    fn default() -> Self {
        Self {
            in_header: FuseInHeader::default(),
            data: [0u8; MAX_DATA_SIZE],
            data_len: 0,
            completed: false,
        }
    }
}

/// A FUSE response with its data payload.
#[derive(Clone)]
pub struct VirtioFsResponse {
    /// Response header.
    pub out_header: FuseOutHeader,
    /// Data payload buffer.
    pub data: [u8; MAX_DATA_SIZE],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl Default for VirtioFsResponse {
    fn default() -> Self {
        Self {
            out_header: FuseOutHeader::default(),
            data: [0u8; MAX_DATA_SIZE],
            data_len: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// VirtIO filesystem device
// ---------------------------------------------------------------------------

/// VirtIO filesystem device driver.
///
/// Manages FUSE-over-virtqueue communication with the host filesystem.
/// Supports up to [`MAX_REQUESTS`] in-flight requests tracked by their
/// unique identifier.
pub struct VirtioFs {
    /// MMIO base address for the device.
    base_addr: u64,
    /// Filesystem tag (UTF-8 name exported by the host).
    tag: [u8; MAX_TAG_LEN],
    /// Number of valid bytes in `tag`.
    tag_len: usize,
    /// Pending request ring buffer.
    requests: [VirtioFsRequest; MAX_REQUESTS],
    /// Response ring buffer.
    responses: [VirtioFsResponse; MAX_REQUESTS],
    /// Request ring head index (next slot to consume).
    req_head: usize,
    /// Request ring tail index (next slot to produce).
    req_tail: usize,
    /// Number of active requests in the ring.
    req_count: usize,
    /// Monotonically increasing unique request identifier.
    next_unique: u64,
    /// Whether the FUSE session has been initialized.
    initialized: bool,
    /// Whether the device is currently in use.
    in_use: bool,
}

impl VirtioFs {
    /// Create a new, uninitialized virtio-fs device.
    pub const fn new() -> Self {
        // Const-compatible initialization without Default trait.
        const DEFAULT_REQ: VirtioFsRequest = VirtioFsRequest {
            in_header: FuseInHeader {
                len: 0,
                opcode: 0,
                unique: 0,
                nodeid: 0,
                uid: 0,
                gid: 0,
                pid: 0,
                padding: 0,
            },
            data: [0u8; MAX_DATA_SIZE],
            data_len: 0,
            completed: false,
        };
        const DEFAULT_RSP: VirtioFsResponse = VirtioFsResponse {
            out_header: FuseOutHeader {
                len: 0,
                error: 0,
                unique: 0,
            },
            data: [0u8; MAX_DATA_SIZE],
            data_len: 0,
        };

        Self {
            base_addr: 0,
            tag: [0u8; MAX_TAG_LEN],
            tag_len: 0,
            requests: [DEFAULT_REQ; MAX_REQUESTS],
            responses: [DEFAULT_RSP; MAX_REQUESTS],
            req_head: 0,
            req_tail: 0,
            req_count: 0,
            next_unique: 1,
            initialized: false,
            in_use: false,
        }
    }

    /// Initialize the virtio-fs device at `base_addr` with the given
    /// filesystem `tag`.
    ///
    /// The tag is a UTF-8 identifier that the host uses to export the
    /// shared filesystem (e.g., `"myfs"`).
    pub fn init(&mut self, base_addr: u64, tag: &[u8]) -> Result<()> {
        if self.in_use {
            return Err(Error::Busy);
        }

        self.base_addr = base_addr;

        // Copy tag, truncating if longer than MAX_TAG_LEN.
        let copy_len = tag.len().min(MAX_TAG_LEN);
        self.tag[..copy_len].copy_from_slice(&tag[..copy_len]);
        self.tag_len = copy_len;

        // Reset request ring.
        self.req_head = 0;
        self.req_tail = 0;
        self.req_count = 0;
        self.next_unique = 1;

        self.initialized = true;
        self.in_use = true;
        Ok(())
    }

    /// Submit a FUSE request with the given opcode, target node, and
    /// optional data payload.
    ///
    /// Returns the unique identifier for this request, which can be
    /// used to match the corresponding response.
    pub fn submit_request(&mut self, opcode: FuseOpcode, nodeid: u64, data: &[u8]) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.req_count >= MAX_REQUESTS {
            return Err(Error::Busy);
        }
        if data.len() > MAX_DATA_SIZE {
            return Err(Error::InvalidArgument);
        }

        let unique = self.next_unique;
        self.next_unique += 1;

        let slot = self.req_tail;
        let header_size = core::mem::size_of::<FuseInHeader>() as u32;

        self.requests[slot].in_header = FuseInHeader {
            len: header_size + data.len() as u32,
            opcode: opcode.as_u32(),
            unique,
            nodeid,
            uid: 0,
            gid: 0,
            pid: 0,
            padding: 0,
        };

        if !data.is_empty() {
            self.requests[slot].data[..data.len()].copy_from_slice(data);
        }
        self.requests[slot].data_len = data.len();
        self.requests[slot].completed = false;

        self.req_tail = (self.req_tail + 1) % MAX_REQUESTS;
        self.req_count += 1;

        Ok(unique)
    }

    /// Record a completed response for the request identified by
    /// `unique`.
    ///
    /// The driver calls this when the device returns a used buffer
    /// from the virtqueue, providing the parsed response.
    pub fn complete_response(&mut self, unique: u64, response: VirtioFsResponse) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        // Find the request slot matching this unique ID.
        let found = self
            .requests
            .iter_mut()
            .enumerate()
            .find(|(_, req)| !req.completed && req.in_header.unique == unique);

        match found {
            Some((idx, req)) => {
                req.completed = true;
                self.responses[idx] = response;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Look up a directory entry by name under `parent`.
    ///
    /// Submits a FUSE LOOKUP request and returns the unique request
    /// identifier. The actual node ID is available once the response
    /// arrives.
    pub fn lookup(&mut self, parent: u64, name: &[u8]) -> Result<u64> {
        self.submit_request(FuseOpcode::Lookup, parent, name)
    }

    /// Get file attributes for the given `nodeid`.
    ///
    /// Returns a default [`FuseAttr`] — the real attributes will be
    /// populated from the host response once it arrives.
    pub fn getattr(&mut self, nodeid: u64) -> Result<FuseAttr> {
        self.submit_request(FuseOpcode::Getattr, nodeid, &[])?;
        Ok(FuseAttr::default())
    }

    /// Read up to `size` bytes from the file at `nodeid` starting at
    /// `offset`.
    ///
    /// Submits a FUSE READ request. Returns the unique request ID.
    /// The actual bytes read are available in the response data once
    /// the request completes.
    pub fn read(&mut self, nodeid: u64, offset: u64, size: u32) -> Result<usize> {
        // Encode offset and size into the data payload.
        let mut payload = [0u8; 12];
        payload[..8].copy_from_slice(&offset.to_le_bytes());
        payload[8..12].copy_from_slice(&size.to_le_bytes());

        self.submit_request(FuseOpcode::Read, nodeid, &payload)?;
        Ok(0)
    }

    /// Write `data` to the file at `nodeid` starting at `offset`.
    ///
    /// Submits a FUSE WRITE request. Returns the number of bytes
    /// queued (always `data.len()` on success; the host may write
    /// fewer, reported in the response).
    pub fn write(&mut self, nodeid: u64, offset: u64, data: &[u8]) -> Result<usize> {
        // Pack offset into the first 8 bytes, then the payload.
        let total_len = 8 + data.len();
        if total_len > MAX_DATA_SIZE {
            return Err(Error::InvalidArgument);
        }

        let mut payload = [0u8; MAX_DATA_SIZE];
        payload[..8].copy_from_slice(&offset.to_le_bytes());
        payload[8..8 + data.len()].copy_from_slice(data);

        self.submit_request(FuseOpcode::Write, nodeid, &payload[..total_len])?;
        Ok(data.len())
    }

    /// Create a directory named `name` under `parent` with the given
    /// `mode`.
    ///
    /// Returns the unique request ID. The new directory's node ID is
    /// available in the response once the request completes.
    pub fn mkdir(&mut self, parent: u64, name: &[u8], mode: u32) -> Result<u64> {
        // Pack mode (4 bytes) followed by the name.
        let total_len = 4 + name.len();
        if total_len > MAX_DATA_SIZE {
            return Err(Error::InvalidArgument);
        }

        let mut payload = [0u8; MAX_DATA_SIZE];
        payload[..4].copy_from_slice(&mode.to_le_bytes());
        payload[4..4 + name.len()].copy_from_slice(name);

        self.submit_request(FuseOpcode::Mkdir, parent, &payload[..total_len])
    }

    /// Remove a file named `name` from the directory `parent`.
    pub fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<()> {
        self.submit_request(FuseOpcode::Unlink, parent, name)?;
        Ok(())
    }

    /// Handle a virtio-fs interrupt.
    ///
    /// Processes completed requests by advancing the head pointer.
    /// Returns the number of completions processed.
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        if !self.in_use {
            return Ok(0);
        }

        let mut processed: u32 = 0;

        // Drain completed requests from the head of the ring.
        while self.req_count > 0 && self.requests[self.req_head].completed {
            self.requests[self.req_head].completed = false;
            self.req_head = (self.req_head + 1) % MAX_REQUESTS;
            self.req_count = self.req_count.saturating_sub(1);
            processed += 1;
        }

        Ok(processed)
    }

    /// Check whether the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Check whether the device is in use.
    pub fn is_in_use(&self) -> bool {
        self.in_use
    }

    /// Return the MMIO base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Return the filesystem tag as a byte slice.
    pub fn tag(&self) -> &[u8] {
        &self.tag[..self.tag_len]
    }

    /// Return the number of active (pending) requests.
    pub fn req_count(&self) -> usize {
        self.req_count
    }
}

impl Default for VirtioFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VirtioFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioFs")
            .field("base_addr", &self.base_addr)
            .field("tag_len", &self.tag_len)
            .field("req_count", &self.req_count)
            .field("next_unique", &self.next_unique)
            .field("initialized", &self.initialized)
            .field("in_use", &self.in_use)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// VirtIO filesystem device registry
// ---------------------------------------------------------------------------

/// Registry for VirtIO filesystem devices.
///
/// Supports up to [`MAX_DEVICES`] devices. Provides registration
/// and lookup by index.
pub struct VirtioFsRegistry {
    /// Registered filesystem devices.
    devices: [VirtioFs; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for VirtioFsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioFsRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [
                VirtioFs::new(),
                VirtioFs::new(),
                VirtioFs::new(),
                VirtioFs::new(),
            ],
            count: 0,
        }
    }

    /// Register a new virtio-fs device, returning its index.
    pub fn register(&mut self, device: VirtioFs) -> Result<usize> {
        if self.count >= MAX_DEVICES {
            return Err(Error::Busy);
        }
        let idx = self.count;
        self.devices[idx] = device;
        self.count += 1;
        Ok(idx)
    }

    /// Get an immutable reference to a registered device by index.
    pub fn get(&self, index: usize) -> Option<&VirtioFs> {
        if index < self.count {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Get a mutable reference to a registered device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut VirtioFs> {
        if index < self.count {
            Some(&mut self.devices[index])
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
