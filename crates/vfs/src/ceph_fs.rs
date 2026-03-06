// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ceph distributed filesystem client.
//!
//! Implements a Ceph FS client that manages MDS (Metadata Server)
//! sessions, capability grants, and striped I/O for distributed
//! storage. This module complements [`crate::ceph`] by adding
//! striped extent management, MDS request queuing, and a more
//! complete client state machine suitable for integration with
//! the ONCRIX VFS layer.
//!
//! # Architecture
//!
//! ```text
//! CephClient
//!   ├── MdsSession            — MDS connection state machine
//!   ├── CapTable              — per-inode capability grants
//!   │     └── CephCap[0..N]  — individual cap entries
//!   ├── StripedLayout         — file → object striping parameters
//!   │     └── StripedExtent   — object-level read/write ranges
//!   └── MdsRequestQueue       — pending MDS operations
//!         └── MdsRequest      — single MDS op (lookup, open, ...)
//! ```
//!
//! # Capabilities
//!
//! The Ceph MDS issues capabilities to clients for each inode they
//! access. Capabilities authorize specific operations (read, write,
//! cache) and are revoked when another client needs conflicting access.
//! The client must release caps promptly on revocation to avoid stalls.
//!
//! # Striped I/O
//!
//! Ceph stripes file data across multiple OSD objects. The striping
//! layout (stripe unit, stripe count, object size) determines how
//! logical file offsets map to object IDs and intra-object offsets.
//!
//! # References
//!
//! - Ceph Architecture: https://docs.ceph.com/en/latest/architecture/
//! - Linux `fs/ceph/` — kernel CephFS client
//! - libcephfs / librados documentation

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of capabilities tracked by the client.
const MAX_CAPS: usize = 256;

/// Maximum number of pending MDS requests.
const MAX_MDS_REQUESTS: usize = 64;

/// Maximum file name length in bytes.
const MAX_NAME_LEN: usize = 255;

/// Maximum number of objects in a striped extent calculation.
const MAX_STRIPE_OBJECTS: usize = 16;

/// Default stripe unit size (4 MiB).
const DEFAULT_STRIPE_UNIT: u64 = 4 * 1024 * 1024;

/// Default stripe count (1 = no striping).
const DEFAULT_STRIPE_COUNT: u32 = 1;

/// Default object size (4 MiB).
const DEFAULT_OBJECT_SIZE: u64 = 4 * 1024 * 1024;

// ── MdsSessionState ─────────────────────────────────────────────

/// MDS session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdsSessionState {
    /// Session has not been initiated.
    Closed,
    /// Session creation in progress.
    Opening,
    /// Session is fully operational.
    Open,
    /// Reconnect in progress (after MDS failover).
    Reconnecting,
    /// Session close in progress.
    Closing,
    /// Session has been forcefully evicted by the MDS.
    Stale,
}

// ── MdsSession ──────────────────────────────────────────────────

/// MDS session representing the client's connection to one MDS.
///
/// Each CephFS client maintains one session per active MDS. The
/// session carries a unique ID assigned by the MDS and a sequence
/// number for request correlation.
#[derive(Debug, Clone, Copy)]
pub struct MdsSession {
    /// MDS-assigned session identifier.
    pub session_id: u64,
    /// Current session state.
    pub state: MdsSessionState,
    /// MDS address (encoded as u64 for no_std portability).
    pub mds_addr: u64,
    /// MDS rank (index in the MDS cluster).
    pub mds_rank: u32,
    /// Client-side epoch for reconnection.
    pub epoch: u32,
    /// Request sequence number.
    pub seq: u64,
    /// Number of caps held on this session.
    pub caps_held: u32,
}

impl MdsSession {
    /// Create a new session in the `Closed` state.
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            state: MdsSessionState::Closed,
            mds_addr: 0,
            mds_rank: 0,
            epoch: 0,
            seq: 0,
            caps_held: 0,
        }
    }

    /// Initiate a session to the given MDS.
    pub fn open(&mut self, mds_addr: u64, mds_rank: u32) -> Result<()> {
        if self.state != MdsSessionState::Closed {
            return Err(Error::Busy);
        }
        self.mds_addr = mds_addr;
        self.mds_rank = mds_rank;
        self.state = MdsSessionState::Opening;
        self.seq = 0;
        Ok(())
    }

    /// Confirm the session is open (after MDS reply).
    pub fn confirm_open(&mut self, session_id: u64, epoch: u32) -> Result<()> {
        if self.state != MdsSessionState::Opening && self.state != MdsSessionState::Reconnecting {
            return Err(Error::InvalidArgument);
        }
        self.session_id = session_id;
        self.epoch = epoch;
        self.state = MdsSessionState::Open;
        Ok(())
    }

    /// Begin closing the session.
    pub fn close(&mut self) -> Result<()> {
        if self.state != MdsSessionState::Open {
            return Err(Error::InvalidArgument);
        }
        self.state = MdsSessionState::Closing;
        Ok(())
    }

    /// Finalize the close.
    pub fn finalize_close(&mut self) {
        self.state = MdsSessionState::Closed;
        self.session_id = 0;
        self.caps_held = 0;
    }

    /// Mark the session as stale (evicted by MDS).
    pub fn mark_stale(&mut self) {
        self.state = MdsSessionState::Stale;
    }

    /// Begin reconnection after MDS failover.
    pub fn reconnect(&mut self) -> Result<()> {
        if self.state != MdsSessionState::Open && self.state != MdsSessionState::Stale {
            return Err(Error::InvalidArgument);
        }
        self.state = MdsSessionState::Reconnecting;
        Ok(())
    }

    /// Allocate the next request sequence number.
    pub fn next_seq(&mut self) -> u64 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Whether the session is in the `Open` state.
    pub fn is_open(&self) -> bool {
        self.state == MdsSessionState::Open
    }
}

impl Default for MdsSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── CephCap ─────────────────────────────────────────────────────

/// Capability permission flags.
pub struct CapFlags;

impl CapFlags {
    /// No permissions.
    pub const NONE: u32 = 0;
    /// Authorize shared (read) access to file data.
    pub const AUTH_SHARED: u32 = 1 << 0;
    /// Read file data.
    pub const FILE_RD: u32 = 1 << 1;
    /// Write file data.
    pub const FILE_WR: u32 = 1 << 2;
    /// Cache file data locally.
    pub const FILE_CACHE: u32 = 1 << 3;
    /// Lazy I/O (buffered writes without flush).
    pub const FILE_LAZYIO: u32 = 1 << 4;
    /// Shared metadata access.
    pub const FILE_SHARED: u32 = 1 << 5;
    /// Exclusive metadata access.
    pub const FILE_EXCL: u32 = 1 << 6;
    /// Pin inode in cache.
    pub const PIN: u32 = 1 << 7;
}

/// A single capability grant from the MDS.
///
/// Each cap authorizes specific operations on one inode. Multiple
/// caps may exist for the same inode (from different MDS ranks in
/// a multi-MDS deployment).
#[derive(Debug, Clone, Copy)]
pub struct CephCap {
    /// Inode number this cap applies to.
    pub ino: u64,
    /// MDS-assigned cap identifier.
    pub cap_id: u64,
    /// Bitmask of issued permissions.
    pub issued: u32,
    /// Bitmask of permissions the client is actually using.
    pub implemented: u32,
    /// MDS rank that issued this cap.
    pub mds_rank: u32,
    /// Cap sequence number (for cap update ordering).
    pub seq: u32,
    /// Whether this slot is valid.
    pub valid: bool,
}

impl CephCap {
    /// Create an empty (invalid) cap slot.
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            cap_id: 0,
            issued: 0,
            implemented: 0,
            mds_rank: 0,
            seq: 0,
            valid: false,
        }
    }

    /// Create a new cap.
    pub fn new(ino: u64, cap_id: u64, issued: u32, mds_rank: u32) -> Self {
        Self {
            ino,
            cap_id,
            issued,
            implemented: 0,
            mds_rank,
            seq: 0,
            valid: true,
        }
    }

    /// Whether the given permission is issued.
    pub fn has(&self, flag: u32) -> bool {
        self.valid && (self.issued & flag) == flag
    }

    /// Update the issued permission bitmask.
    pub fn update_issued(&mut self, issued: u32, seq: u32) {
        self.issued = issued;
        self.seq = seq;
    }
}

// ── CapTable ────────────────────────────────────────────────────

/// Per-client capability table tracking all outstanding caps.
pub struct CapTable {
    /// Cap slots.
    caps: [CephCap; MAX_CAPS],
    /// Number of valid caps.
    count: usize,
}

impl CapTable {
    /// Create a new empty cap table.
    pub const fn new() -> Self {
        Self {
            caps: [CephCap::empty(); MAX_CAPS],
            count: 0,
        }
    }

    /// Insert or update a cap.
    pub fn insert(&mut self, cap: CephCap) -> Result<()> {
        // Update existing cap with same cap_id.
        for slot in &mut self.caps {
            if slot.valid && slot.cap_id == cap.cap_id {
                slot.issued = cap.issued;
                slot.seq = cap.seq;
                return Ok(());
            }
        }
        // Insert into empty slot.
        for slot in &mut self.caps {
            if !slot.valid {
                *slot = cap;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Revoke a cap by cap_id.
    pub fn revoke(&mut self, cap_id: u64) -> Result<()> {
        for slot in &mut self.caps {
            if slot.valid && slot.cap_id == cap_id {
                *slot = CephCap::empty();
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Revoke all caps for a given inode.
    pub fn revoke_inode(&mut self, ino: u64) {
        for slot in &mut self.caps {
            if slot.valid && slot.ino == ino {
                *slot = CephCap::empty();
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Check whether any cap on the given inode grants the flag.
    pub fn has_cap(&self, ino: u64, flag: u32) -> bool {
        self.caps
            .iter()
            .any(|c| c.valid && c.ino == ino && (c.issued & flag) == flag)
    }

    /// Get the merged issued bitmask for an inode.
    pub fn issued_for(&self, ino: u64) -> u32 {
        self.caps
            .iter()
            .filter(|c| c.valid && c.ino == ino)
            .fold(0u32, |acc, c| acc | c.issued)
    }

    /// Number of active caps.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── StripedLayout ───────────────────────────────────────────────

/// File striping layout parameters.
///
/// Determines how a file's data is distributed across RADOS objects.
#[derive(Debug, Clone, Copy)]
pub struct StripedLayout {
    /// Size of each stripe unit in bytes.
    pub stripe_unit: u64,
    /// Number of objects across which data is striped.
    pub stripe_count: u32,
    /// Maximum size of each RADOS object.
    pub object_size: u64,
    /// Pool ID where data objects reside.
    pub pool_id: u64,
}

impl StripedLayout {
    /// Create a layout with default parameters.
    pub const fn default_layout() -> Self {
        Self {
            stripe_unit: DEFAULT_STRIPE_UNIT,
            stripe_count: DEFAULT_STRIPE_COUNT,
            object_size: DEFAULT_OBJECT_SIZE,
            pool_id: 0,
        }
    }

    /// Create a custom layout.
    pub fn new(
        stripe_unit: u64,
        stripe_count: u32,
        object_size: u64,
        pool_id: u64,
    ) -> Result<Self> {
        if stripe_unit == 0 || object_size == 0 || stripe_count == 0 {
            return Err(Error::InvalidArgument);
        }
        if object_size % stripe_unit != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            stripe_unit,
            stripe_count,
            object_size,
            pool_id,
        })
    }

    /// Number of stripe units that fit in one object.
    pub fn stripes_per_object(&self) -> u64 {
        if self.stripe_unit == 0 {
            return 0;
        }
        self.object_size / self.stripe_unit
    }
}

impl Default for StripedLayout {
    fn default() -> Self {
        Self::default_layout()
    }
}

// ── StripedExtent ───────────────────────────────────────────────

/// A single extent in a striped I/O operation.
///
/// After mapping a logical file range through the [`StripedLayout`],
/// the result is a set of `StripedExtent`s, each targeting a specific
/// RADOS object at a specific offset.
#[derive(Debug, Clone, Copy)]
pub struct StripedExtent {
    /// RADOS object number (derived from file offset + layout).
    pub object_no: u64,
    /// Byte offset within the object.
    pub object_offset: u64,
    /// Number of bytes in this extent.
    pub length: u64,
    /// Whether this extent is valid.
    pub valid: bool,
}

impl StripedExtent {
    /// Create an empty (invalid) extent.
    pub const fn empty() -> Self {
        Self {
            object_no: 0,
            object_offset: 0,
            length: 0,
            valid: false,
        }
    }
}

/// Map a logical file range to striped extents.
///
/// Given a file offset, length, and layout, computes the set of
/// RADOS object extents needed to cover the range. Returns up to
/// [`MAX_STRIPE_OBJECTS`] extents.
pub fn map_striped_range(
    file_offset: u64,
    length: u64,
    layout: &StripedLayout,
) -> [StripedExtent; MAX_STRIPE_OBJECTS] {
    let mut extents = [StripedExtent::empty(); MAX_STRIPE_OBJECTS];

    if layout.stripe_unit == 0 || layout.object_size == 0 || length == 0 {
        return extents;
    }

    let su = layout.stripe_unit;
    let sc = layout.stripe_count as u64;
    let obj_size = layout.object_size;

    let mut remaining = length;
    let mut pos = file_offset;
    let mut idx = 0usize;

    while remaining > 0 && idx < MAX_STRIPE_OBJECTS {
        // Which stripe unit does `pos` fall in?
        let stripe_no = pos / su;
        // Which object in the stripe set?
        let obj_in_set = stripe_no % sc;
        // Which stripe period (set of stripe_count objects)?
        let period = stripe_no / sc;
        // Object number.
        let object_no = obj_in_set + period * sc;
        // Offset within the stripe unit.
        let offset_in_su = pos % su;
        // Offset within the object.
        let su_in_object = (period * su) % obj_size;
        let object_offset = su_in_object + offset_in_su;
        // Bytes remaining in this stripe unit.
        let bytes_in_su = su - offset_in_su;
        let chunk = remaining.min(bytes_in_su);

        extents[idx] = StripedExtent {
            object_no,
            object_offset,
            length: chunk,
            valid: true,
        };

        pos = pos.saturating_add(chunk);
        remaining = remaining.saturating_sub(chunk);
        idx += 1;
    }

    extents
}

// ── MdsRequestType ──────────────────────────────────────────────

/// MDS operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdsRequestType {
    /// Lookup a name in a directory.
    Lookup,
    /// Open a file.
    Open,
    /// Create a file.
    Create,
    /// Unlink (delete) a file.
    Unlink,
    /// Rename a file.
    Rename,
    /// Make a directory.
    Mkdir,
    /// Remove a directory.
    Rmdir,
    /// Get file attributes (stat).
    Getattr,
    /// Set file attributes.
    Setattr,
    /// Read directory entries.
    Readdir,
}

/// MDS request state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdsRequestState {
    /// Slot is idle.
    Idle,
    /// Request submitted, waiting to send.
    Pending,
    /// Sent to MDS, awaiting reply.
    Sent,
    /// Reply received.
    Complete,
    /// Request failed.
    Failed,
}

/// A pending MDS request.
#[derive(Clone, Copy)]
pub struct MdsRequest {
    /// Operation type.
    pub op: MdsRequestType,
    /// Target inode number.
    pub ino: u64,
    /// Parent inode (for lookup/create/unlink).
    pub parent_ino: u64,
    /// File name bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Sequence number.
    pub seq: u64,
    /// Request state.
    pub state: MdsRequestState,
    /// Result inode (for lookup/create replies).
    pub result_ino: u64,
    /// Error code (0 = success).
    pub error: i32,
}

impl MdsRequest {
    /// Create an idle request slot.
    pub const fn empty() -> Self {
        Self {
            op: MdsRequestType::Lookup,
            ino: 0,
            parent_ino: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            seq: 0,
            state: MdsRequestState::Idle,
            result_ino: 0,
            error: 0,
        }
    }
}

impl core::fmt::Debug for MdsRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MdsRequest")
            .field("op", &self.op)
            .field("ino", &self.ino)
            .field("state", &self.state)
            .field("seq", &self.seq)
            .finish()
    }
}

// ── CephClient ──────────────────────────────────────────────────

/// Top-level Ceph FS client.
///
/// Manages MDS sessions, capability tracking, striped I/O layout,
/// and MDS request queuing. All CephFS VFS operations route through
/// this struct.
pub struct CephClient {
    /// MDS session.
    pub session: MdsSession,
    /// Capability table.
    pub caps: CapTable,
    /// Default striping layout for new files.
    pub default_layout: StripedLayout,
    /// MDS request queue.
    requests: [MdsRequest; MAX_MDS_REQUESTS],
    /// Client identifier (assigned by the monitor).
    pub client_id: u64,
    /// Global filesystem ID.
    pub fsid: u64,
}

impl CephClient {
    /// Create a new disconnected Ceph client.
    pub fn new() -> Self {
        Self {
            session: MdsSession::new(),
            caps: CapTable::new(),
            default_layout: StripedLayout::default_layout(),
            requests: [const { MdsRequest::empty() }; MAX_MDS_REQUESTS],
            client_id: 0,
            fsid: 0,
        }
    }

    /// Connect to the MDS.
    ///
    /// Initiates the session and immediately confirms it for stub
    /// purposes.
    pub fn connect(&mut self, mds_addr: u64, mds_rank: u32) -> Result<()> {
        self.session.open(mds_addr, mds_rank)?;
        let session_id = mds_addr ^ 0xCE90_0000;
        self.session.confirm_open(session_id, 1)?;
        self.client_id = session_id.wrapping_add(1);
        Ok(())
    }

    /// Disconnect from the MDS.
    pub fn disconnect(&mut self) -> Result<()> {
        self.session.close()?;
        self.session.finalize_close();
        Ok(())
    }

    /// Submit a lookup request.
    ///
    /// Returns the request slot index.
    pub fn submit_lookup(&mut self, parent_ino: u64, name: &[u8]) -> Result<usize> {
        if !self.session.is_open() {
            return Err(Error::PermissionDenied);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let seq = self.session.next_seq();
        for (i, slot) in self.requests.iter_mut().enumerate() {
            if slot.state == MdsRequestState::Idle {
                slot.op = MdsRequestType::Lookup;
                slot.parent_ino = parent_ino;
                slot.name[..name.len()].copy_from_slice(name);
                slot.name_len = name.len() as u8;
                slot.seq = seq;
                slot.state = MdsRequestState::Pending;
                slot.error = 0;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Submit a create request.
    pub fn submit_create(&mut self, parent_ino: u64, name: &[u8]) -> Result<usize> {
        if !self.session.is_open() {
            return Err(Error::PermissionDenied);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let seq = self.session.next_seq();
        for (i, slot) in self.requests.iter_mut().enumerate() {
            if slot.state == MdsRequestState::Idle {
                slot.op = MdsRequestType::Create;
                slot.parent_ino = parent_ino;
                slot.name[..name.len()].copy_from_slice(name);
                slot.name_len = name.len() as u8;
                slot.seq = seq;
                slot.state = MdsRequestState::Pending;
                slot.error = 0;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Complete a request with a result.
    pub fn complete_request(&mut self, slot: usize, result_ino: u64, error: i32) -> Result<()> {
        if slot >= MAX_MDS_REQUESTS {
            return Err(Error::InvalidArgument);
        }
        let req = &mut self.requests[slot];
        if req.state != MdsRequestState::Pending && req.state != MdsRequestState::Sent {
            return Err(Error::InvalidArgument);
        }
        req.result_ino = result_ino;
        req.error = error;
        req.state = if error == 0 {
            MdsRequestState::Complete
        } else {
            MdsRequestState::Failed
        };
        Ok(())
    }

    /// Release a completed or failed request slot.
    pub fn release_request(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_MDS_REQUESTS {
            return Err(Error::InvalidArgument);
        }
        let state = self.requests[slot].state;
        match state {
            MdsRequestState::Pending | MdsRequestState::Sent => {
                return Err(Error::Busy);
            }
            _ => {}
        }
        self.requests[slot] = MdsRequest::empty();
        Ok(())
    }

    /// Map a file range through the striping layout.
    pub fn map_range(&self, file_offset: u64, length: u64) -> [StripedExtent; MAX_STRIPE_OBJECTS] {
        map_striped_range(file_offset, length, &self.default_layout)
    }

    /// Grant a capability on an inode.
    pub fn grant_cap(&mut self, cap: CephCap) -> Result<()> {
        self.caps.insert(cap)?;
        self.session.caps_held = self.session.caps_held.saturating_add(1);
        Ok(())
    }

    /// Revoke a capability by cap_id.
    pub fn revoke_cap(&mut self, cap_id: u64) -> Result<()> {
        self.caps.revoke(cap_id)?;
        self.session.caps_held = self.session.caps_held.saturating_sub(1);
        Ok(())
    }

    /// Whether the session is connected.
    pub fn is_connected(&self) -> bool {
        self.session.is_open()
    }

    /// Number of pending MDS requests.
    pub fn pending_requests(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| r.state == MdsRequestState::Pending || r.state == MdsRequestState::Sent)
            .count()
    }
}

impl Default for CephClient {
    fn default() -> Self {
        Self::new()
    }
}
