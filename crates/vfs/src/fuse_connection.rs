// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE connection management.
//!
//! Manages the lifecycle of a FUSE filesystem connection between the kernel
//! and a userspace FUSE daemon. Each mount creates one `FuseConnection` that
//! multiplexes requests/replies over a single `/dev/fuse` file descriptor.

use oncrix_lib::{Error, Result};

/// Maximum number of concurrent in-flight FUSE requests.
pub const FUSE_MAX_INFLIGHT: usize = 64;

/// FUSE protocol version constants.
pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 39;

/// Unique request identifier, monotonically increasing per connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FuseRequestId(pub u64);

/// Connection state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseConnState {
    /// Waiting for `FUSE_INIT` handshake.
    Initializing,
    /// Handshake complete — connection is active.
    Connected,
    /// Daemon has disconnected or sent `FUSE_DESTROY`.
    Disconnected,
    /// Fatal error; all pending requests will be failed.
    Aborted,
}

/// Negotiated capability flags between kernel and userspace FUSE daemon.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseConnFlags(pub u32);

impl FuseConnFlags {
    pub const ASYNC_READ: u32 = 1 << 0;
    pub const POSIX_LOCKS: u32 = 1 << 1;
    pub const ATOMIC_O_TRUNC: u32 = 1 << 3;
    pub const EXPORT_SUPPORT: u32 = 1 << 4;
    pub const BIG_WRITES: u32 = 1 << 5;
    pub const DONT_MASK: u32 = 1 << 6;
    pub const WRITEBACK_CACHE: u32 = 1 << 16;
    pub const NO_OPEN_SUPPORT: u32 = 1 << 17;
    pub const PARALLEL_DIROPS: u32 = 1 << 18;
    pub const POSIX_ACL: u32 = 1 << 19;

    /// Check whether a specific capability is set.
    #[inline]
    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Enable a capability.
    #[inline]
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }
}

/// Pending request entry stored while awaiting a reply.
#[derive(Debug)]
pub struct PendingRequest {
    /// Unique request ID assigned by the kernel side.
    pub id: FuseRequestId,
    /// Opcode of the outstanding request (for timeout/abort handling).
    pub opcode: u32,
    /// Whether the request has been interrupted.
    pub interrupted: bool,
}

impl PendingRequest {
    /// Create a new pending request entry.
    pub fn new(id: FuseRequestId, opcode: u32) -> Self {
        Self {
            id,
            opcode,
            interrupted: false,
        }
    }
}

/// In-flight table: fixed-capacity array of optional pending requests.
pub struct InflightTable {
    slots: [Option<PendingRequest>; FUSE_MAX_INFLIGHT],
    count: usize,
}

impl InflightTable {
    /// Create an empty inflight table.
    pub const fn new() -> Self {
        // SAFETY: `None` is a valid `Option<PendingRequest>`.
        Self {
            slots: [const { None }; FUSE_MAX_INFLIGHT],
            count: 0,
        }
    }

    /// Insert a request. Returns `Err(Busy)` when the table is full.
    pub fn insert(&mut self, req: PendingRequest) -> Result<()> {
        if self.count >= FUSE_MAX_INFLIGHT {
            return Err(Error::Busy);
        }
        for slot in &mut self.slots {
            if slot.is_none() {
                *slot = Some(req);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Remove and return the request with the given ID.
    pub fn remove(&mut self, id: FuseRequestId) -> Option<PendingRequest> {
        for slot in &mut self.slots {
            if slot.as_ref().map(|r| r.id) == Some(id) {
                self.count -= 1;
                return slot.take();
            }
        }
        None
    }

    /// Mark a request as interrupted; the next reply will be discarded.
    pub fn interrupt(&mut self, id: FuseRequestId) {
        for slot in &mut self.slots {
            if let Some(req) = slot.as_mut() {
                if req.id == id {
                    req.interrupted = true;
                    return;
                }
            }
        }
    }

    /// Number of currently in-flight requests.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no in-flight requests.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for InflightTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A FUSE connection — one per mounted FUSE filesystem.
pub struct FuseConnection {
    /// Current connection state.
    state: FuseConnState,
    /// Monotonically increasing unique request counter.
    next_req_id: u64,
    /// Negotiated protocol capabilities.
    flags: FuseConnFlags,
    /// Maximum write size the daemon supports.
    pub max_write: u32,
    /// Maximum read size.
    pub max_read: u32,
    /// In-flight request tracking table.
    inflight: InflightTable,
    /// Number of requests processed since connection start.
    total_requests: u64,
}

impl FuseConnection {
    /// Create a new connection in the `Initializing` state.
    pub const fn new() -> Self {
        Self {
            state: FuseConnState::Initializing,
            next_req_id: 1,
            flags: FuseConnFlags(0),
            max_write: 4096,
            max_read: 4096,
            inflight: InflightTable::new(),
            total_requests: 0,
        }
    }

    /// Complete the `FUSE_INIT` handshake and transition to `Connected`.
    ///
    /// Returns `Err(InvalidArgument)` if the daemon reports an unsupported
    /// kernel version.
    pub fn complete_init(
        &mut self,
        daemon_major: u32,
        daemon_minor: u32,
        daemon_flags: u32,
        max_write: u32,
    ) -> Result<()> {
        if self.state != FuseConnState::Initializing {
            return Err(Error::InvalidArgument);
        }
        if daemon_major != FUSE_KERNEL_VERSION {
            return Err(Error::InvalidArgument);
        }
        let _ = daemon_minor; // minor is informational
        self.flags = FuseConnFlags(daemon_flags);
        self.max_write = max_write.max(4096);
        self.state = FuseConnState::Connected;
        Ok(())
    }

    /// Allocate a new unique request ID.
    pub fn alloc_req_id(&mut self) -> Result<FuseRequestId> {
        if self.state != FuseConnState::Connected {
            return Err(Error::IoError);
        }
        let id = FuseRequestId(self.next_req_id);
        self.next_req_id += 1;
        Ok(id)
    }

    /// Submit a new request to the in-flight table.
    pub fn submit_request(&mut self, id: FuseRequestId, opcode: u32) -> Result<()> {
        let req = PendingRequest::new(id, opcode);
        self.inflight.insert(req)?;
        self.total_requests += 1;
        Ok(())
    }

    /// Complete a request by removing it from the in-flight table.
    ///
    /// Returns `None` if the request was already removed (duplicate reply).
    pub fn complete_request(&mut self, id: FuseRequestId) -> Option<PendingRequest> {
        self.inflight.remove(id)
    }

    /// Interrupt an outstanding request.
    pub fn interrupt_request(&mut self, id: FuseRequestId) {
        self.inflight.interrupt(id);
    }

    /// Abort the connection, transitioning to `Aborted`.
    pub fn abort(&mut self) {
        self.state = FuseConnState::Aborted;
    }

    /// Graceful disconnect (daemon sent `FUSE_DESTROY`).
    pub fn disconnect(&mut self) {
        if self.state == FuseConnState::Connected {
            self.state = FuseConnState::Disconnected;
        }
    }

    /// Current connection state.
    #[inline]
    pub fn state(&self) -> FuseConnState {
        self.state
    }

    /// Whether the connection is active and accepts new requests.
    #[inline]
    pub fn is_connected(&self) -> bool {
        self.state == FuseConnState::Connected
    }

    /// Negotiated capability flags.
    #[inline]
    pub fn flags(&self) -> FuseConnFlags {
        self.flags
    }

    /// Total number of requests submitted over this connection's lifetime.
    #[inline]
    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    /// Number of currently in-flight requests.
    #[inline]
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }
}

impl Default for FuseConnection {
    fn default() -> Self {
        Self::new()
    }
}
