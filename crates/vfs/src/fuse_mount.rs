// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE mount and unmount operations.
//!
//! Implements the kernel-side FUSE lifecycle:
//!
//! - [`FuseConnInfo`] — protocol version negotiation, max_read/write sizes
//! - `fuse_mount` — open /dev/fuse, perform FUSE_INIT handshake
//! - `fuse_umount` — send FUSE_DESTROY, close the connection
//!
//! # FUSE Protocol
//!
//! FUSE uses a simple request/response protocol over the /dev/fuse device.
//! The kernel sends requests; the userspace daemon reads them, processes them,
//! and writes responses. The FUSE_INIT exchange negotiates protocol version
//! and capabilities.
//!
//! # Reference
//!
//! Linux `fs/fuse/inode.c`, `include/uapi/linux/fuse.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// FUSE kernel protocol major version.
const FUSE_KERNEL_VERSION: u32 = 7;

/// FUSE kernel protocol minor version.
const FUSE_KERNEL_MINOR_VERSION: u32 = 38;

/// Minimum supported FUSE minor version.
const FUSE_MIN_MINOR_VERSION: u32 = 12;

/// Default maximum read size (128 KiB).
const FUSE_DEFAULT_MAX_READ: u32 = 131072;

/// Default maximum write size (128 KiB).
const FUSE_DEFAULT_MAX_WRITE: u32 = 131072;

/// Maximum FUSE connections.
const MAX_FUSE_CONNECTIONS: usize = 8;

/// Maximum FUSE request size in bytes.
const FUSE_MAX_REQUEST_SIZE: u32 = 1048576;

/// FUSE capability flags.
const FUSE_CAP_ASYNC_READ: u32 = 1 << 0;
const FUSE_CAP_POSIX_LOCKS: u32 = 1 << 1;
const FUSE_CAP_FILE_OPS: u32 = 1 << 2;
const FUSE_CAP_ATOMIC_O_TRUNC: u32 = 1 << 3;
const FUSE_CAP_EXPORT_SUPPORT: u32 = 1 << 4;
const FUSE_CAP_BIG_WRITES: u32 = 1 << 5;
const FUSE_CAP_DONT_MASK: u32 = 1 << 6;
const FUSE_CAP_SPLICE_WRITE: u32 = 1 << 7;
const FUSE_CAP_SPLICE_READ: u32 = 1 << 8;
const FUSE_CAP_FLOCK_LOCKS: u32 = 1 << 10;
const FUSE_CAP_IOCTL_DIR: u32 = 1 << 11;
const FUSE_CAP_AUTO_INVAL_DATA: u32 = 1 << 12;
const FUSE_CAP_READDIRPLUS: u32 = 1 << 13;
const FUSE_CAP_WRITEBACK_CACHE: u32 = 1 << 16;

// ---------------------------------------------------------------------------
// FUSE opcode
// ---------------------------------------------------------------------------

/// FUSE request opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseOpcode {
    /// Initialize the FUSE connection.
    Init = 26,
    /// Destroy the FUSE connection.
    Destroy = 38,
    /// Lookup a directory entry.
    Lookup = 1,
    /// Open a file.
    Open = 14,
    /// Read data.
    Read = 15,
    /// Write data.
    Write = 16,
    /// Release an open file.
    Release = 18,
    /// Get file attributes.
    Getattr = 3,
}

// ---------------------------------------------------------------------------
// FUSE connection info
// ---------------------------------------------------------------------------

/// FUSE connection information negotiated during FUSE_INIT.
#[derive(Debug, Clone, Copy)]
pub struct FuseConnInfo {
    /// Negotiated protocol major version.
    pub proto_major: u32,
    /// Negotiated protocol minor version.
    pub proto_minor: u32,
    /// Maximum read size (bytes).
    pub max_read: u32,
    /// Maximum write size (bytes).
    pub max_write: u32,
    /// Maximum number of background requests.
    pub max_background: u16,
    /// Congestion threshold for background requests.
    pub congestion_threshold: u16,
    /// Kernel-side capability flags.
    pub capable: u32,
    /// Daemon-requested capability flags (from FUSE_INIT response).
    pub want: u32,
    /// Maximum pages per request.
    pub max_pages: u16,
    /// Whether the connection is initialized.
    pub initialized: bool,
    /// Whether async reads are enabled.
    pub async_read: bool,
    /// Whether writeback cache is active.
    pub writeback_cache: bool,
}

impl FuseConnInfo {
    /// Creates a new connection info with default values.
    pub const fn new() -> Self {
        Self {
            proto_major: FUSE_KERNEL_VERSION,
            proto_minor: FUSE_KERNEL_MINOR_VERSION,
            max_read: FUSE_DEFAULT_MAX_READ,
            max_write: FUSE_DEFAULT_MAX_WRITE,
            max_background: 12,
            congestion_threshold: 9,
            capable: FUSE_CAP_ASYNC_READ
                | FUSE_CAP_POSIX_LOCKS
                | FUSE_CAP_ATOMIC_O_TRUNC
                | FUSE_CAP_BIG_WRITES
                | FUSE_CAP_AUTO_INVAL_DATA
                | FUSE_CAP_READDIRPLUS
                | FUSE_CAP_WRITEBACK_CACHE,
            want: 0,
            max_pages: 32,
            initialized: false,
            async_read: false,
            writeback_cache: false,
        }
    }

    /// Applies daemon capabilities from FUSE_INIT response.
    pub fn apply_want(&mut self, daemon_want: u32) {
        // Only accept capabilities we advertise as capable.
        self.want = daemon_want & self.capable;
        self.async_read = self.want & FUSE_CAP_ASYNC_READ != 0;
        self.writeback_cache = self.want & FUSE_CAP_WRITEBACK_CACHE != 0;
    }

    /// Returns whether a capability is active.
    pub fn has_capability(&self, cap: u32) -> bool {
        self.want & cap != 0
    }
}

impl Default for FuseConnInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FUSE init packet (simplified in-memory representation)
// ---------------------------------------------------------------------------

/// FUSE_INIT request payload.
#[derive(Debug, Clone, Copy)]
pub struct FuseInitIn {
    /// Client major version.
    pub major: u32,
    /// Client minor version.
    pub minor: u32,
    /// Maximum readahead.
    pub max_readahead: u32,
    /// Client capability flags.
    pub flags: u32,
    /// Maximum background requests.
    pub max_background: u16,
    /// Congestion threshold.
    pub congestion_threshold: u16,
    /// Maximum write size.
    pub max_write: u32,
    /// Maximum time granularity.
    pub time_gran: u32,
    /// Maximum pages.
    pub max_pages: u16,
    /// Map alignment.
    pub map_alignment: u16,
    /// Flags2.
    pub flags2: u64,
}

/// FUSE_INIT response payload.
#[derive(Debug, Clone, Copy)]
pub struct FuseInitOut {
    /// Kernel major version.
    pub major: u32,
    /// Kernel minor version.
    pub minor: u32,
    /// Maximum readahead.
    pub max_readahead: u32,
    /// Kernel capability flags.
    pub flags: u32,
    /// Maximum background requests.
    pub max_background: u16,
    /// Congestion threshold.
    pub congestion_threshold: u16,
    /// Maximum write size.
    pub max_write: u32,
    /// Maximum time granularity.
    pub time_gran: u32,
    /// Maximum pages.
    pub max_pages: u16,
    /// Map alignment.
    pub map_alignment: u16,
    /// Flags2.
    pub flags2: u64,
}

// ---------------------------------------------------------------------------
// FUSE connection state
// ---------------------------------------------------------------------------

/// State of a FUSE connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseConnState {
    /// Not yet initialized.
    Uninitialized,
    /// FUSE_INIT sent, awaiting response.
    Initializing,
    /// Fully operational.
    Ready,
    /// Shutting down.
    Destroying,
    /// Connection closed.
    Closed,
}

/// FUSE connection descriptor.
#[derive(Debug)]
pub struct FuseConnection {
    /// Connection information.
    pub conn_info: FuseConnInfo,
    /// Connection state.
    pub state: FuseConnState,
    /// Simulated /dev/fuse file descriptor.
    pub fuse_fd: i32,
    /// Unique connection ID.
    pub conn_id: u32,
    /// Request counter.
    pub req_counter: u64,
    /// Error counter.
    pub error_count: u32,
    /// Whether the daemon supports the DESTROY opcode.
    pub daemon_supports_destroy: bool,
}

impl FuseConnection {
    /// Creates a new FUSE connection in the uninitialized state.
    pub const fn new(conn_id: u32) -> Self {
        Self {
            conn_info: FuseConnInfo::new(),
            state: FuseConnState::Uninitialized,
            fuse_fd: -1,
            conn_id,
            req_counter: 0,
            error_count: 0,
            daemon_supports_destroy: false,
        }
    }

    /// Returns whether the connection is ready for requests.
    pub fn is_ready(&self) -> bool {
        self.state == FuseConnState::Ready
    }
}

// ---------------------------------------------------------------------------
// Mount table
// ---------------------------------------------------------------------------

/// Global FUSE connection table.
pub struct FuseConnTable {
    /// Active connections.
    connections: [Option<FuseConnection>; MAX_FUSE_CONNECTIONS],
    /// Number of active connections.
    count: usize,
    /// Next connection ID.
    next_id: u32,
}

impl FuseConnTable {
    /// Creates an empty connection table.
    pub const fn new() -> Self {
        Self {
            connections: [None, None, None, None, None, None, None, None],
            count: 0,
            next_id: 1,
        }
    }

    /// Returns the number of active connections.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Looks up a connection by ID.
    pub fn get(&self, id: u32) -> Option<&FuseConnection> {
        self.connections.iter().flatten().find(|c| c.conn_id == id)
    }

    /// Mutably looks up a connection by ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut FuseConnection> {
        self.connections
            .iter_mut()
            .flatten()
            .find(|c| c.conn_id == id)
    }

    /// Inserts a connection. Returns the connection ID.
    fn insert(&mut self, conn: FuseConnection) -> Result<u32> {
        if self.count >= MAX_FUSE_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }
        let id = conn.conn_id;
        for slot in &mut self.connections {
            if slot.is_none() {
                *slot = Some(conn);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a connection by ID.
    fn remove(&mut self, id: u32) -> Option<FuseConnection> {
        for slot in &mut self.connections {
            if slot.as_ref().map(|c| c.conn_id) == Some(id) {
                self.count = self.count.saturating_sub(1);
                return slot.take();
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Mount / unmount
// ---------------------------------------------------------------------------

/// Performs a FUSE mount operation.
///
/// 1. Opens the /dev/fuse device (simulated by assigning an fd).
/// 2. Sends a FUSE_INIT request and processes the response.
/// 3. Negotiates protocol version and capabilities.
/// 4. Registers the connection in the table.
///
/// Returns the connection ID on success.
pub fn fuse_mount(table: &mut FuseConnTable, daemon_init: &FuseInitIn) -> Result<u32> {
    // Validate daemon version.
    if daemon_init.major != FUSE_KERNEL_VERSION {
        return Err(Error::InvalidArgument);
    }
    if daemon_init.minor < FUSE_MIN_MINOR_VERSION {
        return Err(Error::InvalidArgument);
    }

    let id = table.next_id;
    table.next_id += 1;

    let mut conn = FuseConnection::new(id);

    // Negotiate minor version.
    conn.conn_info.proto_minor = daemon_init.minor.min(FUSE_KERNEL_MINOR_VERSION);

    // Apply daemon capability requests.
    conn.conn_info.apply_want(daemon_init.flags);

    // Set read/write sizes (bounded by our limits).
    conn.conn_info.max_read = daemon_init.max_readahead.min(FUSE_DEFAULT_MAX_READ);
    conn.conn_info.max_write = daemon_init.max_write.min(FUSE_MAX_REQUEST_SIZE);
    if conn.conn_info.max_write == 0 {
        conn.conn_info.max_write = FUSE_DEFAULT_MAX_WRITE;
    }

    // Simulate opening /dev/fuse (assign synthetic fd).
    conn.fuse_fd = (id as i32) + 100;
    conn.daemon_supports_destroy = daemon_init.minor >= 18;

    conn.state = FuseConnState::Ready;
    conn.conn_info.initialized = true;

    table.insert(conn)
}

/// Performs a FUSE unmount operation.
///
/// Sends FUSE_DESTROY (if supported), flushes pending requests, and
/// removes the connection from the table.
pub fn fuse_umount(table: &mut FuseConnTable, conn_id: u32) -> Result<()> {
    let conn = table.get_mut(conn_id).ok_or(Error::NotFound)?;

    if conn.state == FuseConnState::Closed {
        return Err(Error::InvalidArgument);
    }

    conn.state = FuseConnState::Destroying;

    // Simulate FUSE_DESTROY (would write to conn.fuse_fd in a real impl).
    if conn.daemon_supports_destroy {
        conn.req_counter += 1;
    }

    conn.state = FuseConnState::Closed;
    conn.fuse_fd = -1;

    table.remove(conn_id).ok_or(Error::NotFound)?;
    Ok(())
}

/// Builds a FUSE_INIT response from the negotiated connection info.
pub fn build_init_out(info: &FuseConnInfo) -> FuseInitOut {
    FuseInitOut {
        major: info.proto_major,
        minor: info.proto_minor,
        max_readahead: info.max_read,
        flags: info.want,
        max_background: info.max_background,
        congestion_threshold: info.congestion_threshold,
        max_write: info.max_write,
        time_gran: 1,
        max_pages: info.max_pages,
        map_alignment: 0,
        flags2: 0,
    }
}
