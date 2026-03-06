// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CIFS/SMB client filesystem implementation.
//!
//! Implements an SMB2/3 client that mounts remote shares and exposes them
//! through the VFS layer. Supports session setup, tree connect, compound
//! request batching, credit management, and durable file handles.
//!
//! # Architecture
//!
//! ```text
//! CifsMount
//!   ├── CifsSession    — SMB2 session negotiation + authentication
//!   ├── CifsTree       — SMB2 tree connect per share
//!   ├── CreditTracker  — SMB2 credit flow control
//!   └── CifsFdTable    — open file handles (durable + non-durable)
//!         └── CifsFileHandle → SMB2 FileId (persistent + volatile)
//! ```
//!
//! # Structures
//!
//! - [`Smb2Command`] — SMB2 command codes
//! - [`Smb2Header`] — SMB2 protocol header (64-byte fixed)
//! - [`NegotiateDialect`] — SMB dialect negotiation values
//! - [`SessionState`] — SMB2 session lifecycle state
//! - [`CifsSession`] — session with credits, signing key, dialect
//! - [`TreeFlags`] — tree-connect capabilities
//! - [`CifsTree`] — per-share tree connection
//! - [`CreditTracker`] — SMB2 credit grant/consume tracking
//! - [`HandleFlags`] — open file handle capability flags
//! - [`Smb2FileId`] — 16-byte SMB2 file identifier
//! - [`CifsFileHandle`] — open handle with durable lease
//! - [`CifsFdTable`] — per-mount open handle table
//! - [`CifsMount`] — top-level mount point
//! - [`CifsRegistry`] — global mount registry

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// SMB2 protocol ID magic bytes (`\xFESMB`).
pub const SMB2_MAGIC: u32 = 0xFE534D42;

/// SMB2 header structure size (fixed 64 bytes).
pub const SMB2_HEADER_SIZE: usize = 64;

/// Maximum number of open file handles per mount.
const MAX_HANDLES: usize = 256;

/// Maximum share path length in bytes.
const MAX_SHARE_PATH: usize = 260;

/// Maximum number of CIFS mounts in the registry.
const MAX_CIFS_MOUNTS: usize = 8;

/// Maximum compound request chain length.
const MAX_COMPOUND_CHAIN: usize = 16;

/// Maximum credits to request per negotiation.
const MAX_CREDITS: u16 = 512;

/// Initial credits granted by server.
const INITIAL_CREDITS: u16 = 1;

/// SMB2 dialect 2.1.
const DIALECT_SMB21: u16 = 0x0210;

/// SMB2 dialect 3.0.
const DIALECT_SMB30: u16 = 0x0300;

/// SMB2 dialect 3.1.1.
const DIALECT_SMB311: u16 = 0x0311;

// ── Smb2Command ──────────────────────────────────────────────────

/// SMB2 command codes for request/response dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    /// SMB2 NEGOTIATE — dialect and capability negotiation.
    Negotiate = 0x0000,
    /// SMB2 SESSION_SETUP — authentication and session establishment.
    SessionSetup = 0x0001,
    /// SMB2 LOGOFF — terminate a session.
    Logoff = 0x0002,
    /// SMB2 TREE_CONNECT — connect to a share.
    TreeConnect = 0x0003,
    /// SMB2 TREE_DISCONNECT — disconnect from a share.
    TreeDisconnect = 0x0004,
    /// SMB2 CREATE — open or create a file.
    Create = 0x0005,
    /// SMB2 CLOSE — close an open file handle.
    Close = 0x0006,
    /// SMB2 FLUSH — flush pending data to the server.
    Flush = 0x0007,
    /// SMB2 READ — read file data.
    Read = 0x0008,
    /// SMB2 WRITE — write file data.
    Write = 0x0009,
    /// SMB2 QUERY_INFO — query file/share/security attributes.
    QueryInfo = 0x0010,
    /// SMB2 SET_INFO — set file/share/security attributes.
    SetInfo = 0x0011,
    /// SMB2 IOCTL — device I/O control.
    Ioctl = 0x000B,
    /// SMB2 CANCEL — cancel a pending request.
    Cancel = 0x000C,
    /// SMB2 ECHO — keep-alive ping.
    Echo = 0x000D,
    /// SMB2 QUERY_DIRECTORY — enumerate directory contents.
    QueryDirectory = 0x000E,
    /// SMB2 CHANGE_NOTIFY — request change notifications.
    ChangeNotify = 0x000F,
    /// SMB2 OPLOCK_BREAK — server-initiated oplock break.
    OplockBreak = 0x0012,
}

// ── Smb2Header ──────────────────────────────────────────────────

/// SMB2 protocol header — fixed 64-byte structure placed at the start
/// of every SMB2 request and response.
///
/// Layout matches the wire format so the header can be cast directly
/// from a network buffer (little-endian byte order on wire).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Smb2Header {
    /// Protocol identifier: must equal [`SMB2_MAGIC`].
    pub protocol_id: u32,
    /// Structure size: always 64.
    pub structure_size: u16,
    /// Number of credits charged (request) or granted (response).
    pub credit_charge: u16,
    /// NT status code in responses; channel sequence in requests.
    pub status_or_channel_seq: u32,
    /// SMB2 command code.
    pub command: u16,
    /// Credits requested (request) or granted (response).
    pub credit_request_response: u16,
    /// Flags (e.g. SMB2_FLAGS_RESPONSE, SMB2_FLAGS_SIGNED).
    pub flags: u32,
    /// Offset from start of this header to the next header in a compound.
    pub next_command: u32,
    /// Client-assigned message ID for matching replies.
    pub message_id: u64,
    /// Process ID (SMB2 async: async_id high 32 bits).
    pub process_id: u32,
    /// Tree ID identifying the connected share.
    pub tree_id: u32,
    /// Session ID identifying the authenticated session.
    pub session_id: u64,
    /// Message signature (16 bytes, zeroed if signing disabled).
    pub signature: [u8; 16],
}

impl Smb2Header {
    /// Construct a new SMB2 request header.
    pub fn new_request(
        command: Smb2Command,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
    ) -> Self {
        Self {
            protocol_id: SMB2_MAGIC,
            structure_size: SMB2_HEADER_SIZE as u16,
            credit_charge: 1,
            status_or_channel_seq: 0,
            command: command as u16,
            credit_request_response: 64,
            flags: 0,
            next_command: 0,
            message_id,
            process_id: 0xFEFF,
            tree_id,
            session_id,
            signature: [0u8; 16],
        }
    }

    /// Return `true` if the response flag is set.
    pub fn is_response(self) -> bool {
        self.flags & 0x0000_0001 != 0
    }

    /// Return `true` if the signed flag is set.
    pub fn is_signed(self) -> bool {
        self.flags & 0x0000_0008 != 0
    }
}

// ── NegotiateDialect ─────────────────────────────────────────────

/// SMB dialect negotiation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateDialect {
    /// SMB 2.1.
    Smb21,
    /// SMB 3.0.
    Smb30,
    /// SMB 3.1.1 (preferred — has pre-auth integrity).
    Smb311,
    /// Unknown or unsupported dialect.
    Unknown(u16),
}

impl NegotiateDialect {
    /// Convert a raw dialect code to the enum variant.
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            DIALECT_SMB21 => Self::Smb21,
            DIALECT_SMB30 => Self::Smb30,
            DIALECT_SMB311 => Self::Smb311,
            other => Self::Unknown(other),
        }
    }

    /// Return the wire-format dialect value.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Smb21 => DIALECT_SMB21,
            Self::Smb30 => DIALECT_SMB30,
            Self::Smb311 => DIALECT_SMB311,
            Self::Unknown(v) => v,
        }
    }
}

// ── SessionState ─────────────────────────────────────────────────

/// SMB2 session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Initial state — no negotiation started.
    #[default]
    Idle,
    /// NEGOTIATE sent, waiting for server dialect selection.
    Negotiating,
    /// SESSION_SETUP in progress (multi-round NTLM/Kerberos).
    Authenticating,
    /// Session fully established and ready for tree connects.
    Active,
    /// Session is being torn down via LOGOFF.
    LoggingOff,
    /// Session terminated.
    Closed,
}

// ── CifsSession ──────────────────────────────────────────────────

/// SMB2 session state.
///
/// Tracks authentication state, negotiated dialect, signing keys,
/// and the credit balance granted by the server.
#[derive(Debug)]
pub struct CifsSession {
    /// Unique 64-bit session identifier assigned by the server.
    pub session_id: u64,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Negotiated SMB dialect.
    pub dialect: NegotiateDialect,
    /// Current credit balance (how many requests can be sent).
    pub credits: u16,
    /// Next message ID to assign (monotonically increasing).
    pub next_message_id: u64,
    /// 16-byte signing key (all zeros if signing disabled).
    pub signing_key: [u8; 16],
    /// Server GUID from NEGOTIATE response (16 bytes).
    pub server_guid: [u8; 16],
    /// Maximum read/write size negotiated.
    pub max_transact_size: u32,
    /// Maximum read size.
    pub max_read_size: u32,
    /// Maximum write size.
    pub max_write_size: u32,
}

impl CifsSession {
    /// Create a new idle session.
    pub fn new() -> Self {
        Self {
            session_id: 0,
            state: SessionState::Idle,
            dialect: NegotiateDialect::Smb311,
            credits: INITIAL_CREDITS,
            next_message_id: 0,
            signing_key: [0u8; 16],
            server_guid: [0u8; 16],
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
        }
    }

    /// Allocate and return the next message ID.
    pub fn alloc_message_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    /// Apply credit delta from a server response.
    pub fn apply_credit_grant(&mut self, granted: u16) {
        self.credits = self.credits.saturating_add(granted);
        if self.credits > MAX_CREDITS {
            self.credits = MAX_CREDITS;
        }
    }

    /// Consume one credit for a request.
    ///
    /// Returns `Err(Error::WouldBlock)` if no credits remain.
    pub fn consume_credit(&mut self) -> Result<()> {
        if self.credits == 0 {
            return Err(Error::WouldBlock);
        }
        self.credits -= 1;
        Ok(())
    }

    /// Transition the session state.
    pub fn set_state(&mut self, new_state: SessionState) {
        self.state = new_state;
    }

    /// Return `true` if the session is active.
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }
}

impl Default for CifsSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── TreeFlags ────────────────────────────────────────────────────

/// SMB2 TREE_CONNECT share capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TreeFlags(pub u32);

impl TreeFlags {
    /// Share supports Distributed File System (DFS) namespaces.
    pub const DFS: Self = Self(0x0000_0001);
    /// Continuous availability — persistent handles survive disconnects.
    pub const CONTINUOUS_AVAILABILITY: Self = Self(0x0000_0010);
    /// Share is encrypted (SMB3).
    pub const ENCRYPT_DATA: Self = Self(0x0000_0080);

    /// Test whether a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    /// Combine two flag sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ── CifsTree ─────────────────────────────────────────────────────

/// SMB2 tree connection — one per mounted share.
#[derive(Debug)]
pub struct CifsTree {
    /// Tree ID assigned by the server.
    pub tree_id: u32,
    /// Share path (UNC format, e.g. `\\server\share`).
    pub share_path: [u8; MAX_SHARE_PATH],
    /// Length of the share path in bytes.
    pub share_path_len: usize,
    /// Share capability flags.
    pub flags: TreeFlags,
    /// Share type (disk / named pipe / printer).
    pub share_type: u8,
}

impl CifsTree {
    /// Create a tree connection record.
    pub fn new(tree_id: u32, share: &[u8], flags: TreeFlags, share_type: u8) -> Self {
        let mut path = [0u8; MAX_SHARE_PATH];
        let len = share.len().min(MAX_SHARE_PATH);
        path[..len].copy_from_slice(&share[..len]);
        Self {
            tree_id,
            share_path: path,
            share_path_len: len,
            flags,
            share_type,
        }
    }

    /// Return the share path as a byte slice.
    pub fn share_path_bytes(&self) -> &[u8] {
        &self.share_path[..self.share_path_len]
    }
}

// ── CreditTracker ────────────────────────────────────────────────

/// SMB2 credit management tracker.
///
/// Enforces the SMB2 flow-control model: the client may only send
/// as many requests as it holds credits. The server grants additional
/// credits in its responses.
#[derive(Debug, Default)]
pub struct CreditTracker {
    /// Current credit balance.
    available: u16,
    /// Cumulative credits consumed (statistics).
    consumed_total: u64,
    /// Cumulative credits granted (statistics).
    granted_total: u64,
}

impl CreditTracker {
    /// Create a tracker with an initial credit balance.
    pub fn new(initial: u16) -> Self {
        Self {
            available: initial,
            consumed_total: 0,
            granted_total: initial as u64,
        }
    }

    /// Consume `charge` credits for one request.
    ///
    /// Returns `Err(Error::WouldBlock)` if insufficient credits.
    pub fn consume(&mut self, charge: u16) -> Result<()> {
        if (self.available as u32) < (charge as u32) {
            return Err(Error::WouldBlock);
        }
        self.available -= charge;
        self.consumed_total += charge as u64;
        Ok(())
    }

    /// Grant `credits` to the tracker from a server response.
    pub fn grant(&mut self, credits: u16) {
        self.available = self.available.saturating_add(credits);
        if self.available > MAX_CREDITS {
            self.available = MAX_CREDITS;
        }
        self.granted_total += credits as u64;
    }

    /// Return the current credit balance.
    pub fn available(&self) -> u16 {
        self.available
    }
}

// ── HandleFlags ──────────────────────────────────────────────────

/// Flags for an open SMB2 file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HandleFlags(pub u32);

impl HandleFlags {
    /// Handle is durable — survives network reconnects.
    pub const DURABLE: Self = Self(0x0000_0001);
    /// Handle holds a batch oplock.
    pub const BATCH_OPLOCK: Self = Self(0x0000_0002);
    /// Handle holds a lease.
    pub const LEASE: Self = Self(0x0000_0004);
    /// Handle was opened as a directory.
    pub const DIRECTORY: Self = Self(0x0000_0008);

    /// Test whether a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }
}

// ── SmB2FileId ───────────────────────────────────────────────────

/// SMB2 file identifier — 16-byte opaque handle returned by CREATE.
///
/// Composed of two 64-bit fields: a persistent part (survives
/// reconnects for durable handles) and a volatile part (per-connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Smb2FileId {
    /// Persistent handle component (valid across reconnects).
    pub persistent: u64,
    /// Volatile handle component (per-connection, invalidated on reconnect).
    pub volatile: u64,
}

impl Smb2FileId {
    /// Create a file ID from its two components.
    pub const fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    /// Return `true` if this is a null/invalid file ID.
    pub fn is_null(self) -> bool {
        self.persistent == u64::MAX && self.volatile == u64::MAX
    }

    /// The canonical null/invalid file ID.
    pub const NULL: Self = Self {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };
}

// ── CifsFileHandle ───────────────────────────────────────────────

/// An open SMB2 file handle on a mounted share.
#[derive(Debug)]
pub struct CifsFileHandle {
    /// SMB2 file identifier.
    pub file_id: Smb2FileId,
    /// Tree ID this handle belongs to.
    pub tree_id: u32,
    /// Handle capability flags.
    pub flags: HandleFlags,
    /// Current byte offset for sequential I/O.
    pub offset: u64,
    /// Granted access mask.
    pub access_mask: u32,
    /// File size at time of open (informational).
    pub end_of_file: u64,
    /// 16-byte lease key for lease-based durable handles.
    pub lease_key: [u8; 16],
}

impl CifsFileHandle {
    /// Create a new file handle record.
    pub fn new(file_id: Smb2FileId, tree_id: u32, flags: HandleFlags, access_mask: u32) -> Self {
        Self {
            file_id,
            tree_id,
            flags,
            offset: 0,
            access_mask,
            end_of_file: 0,
            lease_key: [0u8; 16],
        }
    }

    /// Return `true` if this handle has a durable lease.
    pub fn is_durable(&self) -> bool {
        self.flags.contains(HandleFlags::DURABLE)
    }
}

// ── CifsFdTable ──────────────────────────────────────────────────

/// Per-mount open file handle table.
///
/// Maintains a fixed-size array of [`CifsFileHandle`] slots.
/// Each slot is either vacant (`None`) or occupied.
#[derive(Debug)]
pub struct CifsFdTable {
    handles: [Option<CifsFileHandle>; MAX_HANDLES],
    count: usize,
}

impl CifsFdTable {
    /// Create an empty handle table.
    pub fn new() -> Self {
        Self {
            handles: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Insert a handle and return its local descriptor index.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the table is full.
    pub fn insert(&mut self, handle: CifsFileHandle) -> Result<usize> {
        for (i, slot) in self.handles.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove and return the handle at `index`.
    ///
    /// Returns `Err(Error::NotFound)` if the slot is vacant.
    pub fn remove(&mut self, index: usize) -> Result<CifsFileHandle> {
        if index >= MAX_HANDLES {
            return Err(Error::InvalidArgument);
        }
        match self.handles[index].take() {
            Some(h) => {
                self.count -= 1;
                Ok(h)
            }
            None => Err(Error::NotFound),
        }
    }

    /// Look up a handle by index (immutable).
    pub fn get(&self, index: usize) -> Result<&CifsFileHandle> {
        if index >= MAX_HANDLES {
            return Err(Error::InvalidArgument);
        }
        self.handles[index].as_ref().ok_or(Error::NotFound)
    }

    /// Look up a handle by index (mutable).
    pub fn get_mut(&mut self, index: usize) -> Result<&mut CifsFileHandle> {
        if index >= MAX_HANDLES {
            return Err(Error::InvalidArgument);
        }
        self.handles[index].as_mut().ok_or(Error::NotFound)
    }

    /// Return the number of open handles.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for CifsFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── CompoundRequest ──────────────────────────────────────────────

/// A single command within an SMB2 compound request chain.
#[derive(Debug, Clone, Copy)]
pub struct CompoundEntry {
    /// SMB2 command code for this entry.
    pub command: Smb2Command,
    /// Credit charge for this individual command.
    pub credit_charge: u16,
    /// Whether this entry depends on the previous entry's result.
    pub related: bool,
}

/// An SMB2 compound request: up to [`MAX_COMPOUND_CHAIN`] commands
/// batched into a single network round-trip.
#[derive(Debug)]
pub struct CompoundRequest {
    entries: [Option<CompoundEntry>; MAX_COMPOUND_CHAIN],
    len: usize,
}

impl CompoundRequest {
    /// Create an empty compound request.
    pub fn new() -> Self {
        Self {
            entries: [None; MAX_COMPOUND_CHAIN],
            len: 0,
        }
    }

    /// Append a command to the chain.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the chain is full.
    pub fn push(&mut self, entry: CompoundEntry) -> Result<()> {
        if self.len >= MAX_COMPOUND_CHAIN {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    /// Return the number of entries in the chain.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over the entries in the chain.
    pub fn iter(&self) -> impl Iterator<Item = &CompoundEntry> {
        self.entries[..self.len].iter().filter_map(|e| e.as_ref())
    }

    /// Compute the total credit charge for the compound request.
    pub fn total_credit_charge(&self) -> u16 {
        self.iter()
            .map(|e| e.credit_charge)
            .fold(0u16, |a, b| a.saturating_add(b))
    }
}

impl Default for CompoundRequest {
    fn default() -> Self {
        Self::new()
    }
}

// ── CifsMount ────────────────────────────────────────────────────

/// CIFS/SMB mount point.
///
/// Combines a session, tree connection, credit tracker, and open
/// handle table into a single mount object.
#[derive(Debug)]
pub struct CifsMount {
    /// SMB2 session for this mount.
    pub session: CifsSession,
    /// Tree connection for the mounted share.
    pub tree: Option<CifsTree>,
    /// Credit tracker (mirrors session credits).
    pub credits: CreditTracker,
    /// Open file handle table.
    pub fds: CifsFdTable,
    /// Mount point path (local, e.g. `/mnt/smb`).
    pub mount_path: [u8; MAX_SHARE_PATH],
    /// Length of the mount path.
    pub mount_path_len: usize,
}

impl CifsMount {
    /// Create a new CIFS mount record.
    pub fn new(mount_path: &[u8]) -> Self {
        let mut mp = [0u8; MAX_SHARE_PATH];
        let len = mount_path.len().min(MAX_SHARE_PATH);
        mp[..len].copy_from_slice(&mount_path[..len]);
        Self {
            session: CifsSession::new(),
            tree: None,
            credits: CreditTracker::new(INITIAL_CREDITS),
            fds: CifsFdTable::new(),
            mount_path: mp,
            mount_path_len: len,
        }
    }

    /// Perform SMB2 session setup (sets state to Active).
    ///
    /// In a real driver this would exchange NEGOTIATE/SESSION_SETUP
    /// packets with the server. Here we advance the state machine to
    /// allow higher-level operations to proceed.
    pub fn setup_session(&mut self, session_id: u64, dialect: NegotiateDialect) -> Result<()> {
        if self.session.state != SessionState::Idle {
            return Err(Error::AlreadyExists);
        }
        self.session.session_id = session_id;
        self.session.dialect = dialect;
        self.session.set_state(SessionState::Active);
        self.credits.grant(64);
        Ok(())
    }

    /// Connect to a share (tree connect).
    pub fn tree_connect(&mut self, tree_id: u32, share: &[u8], flags: TreeFlags) -> Result<()> {
        if !self.session.is_active() {
            return Err(Error::PermissionDenied);
        }
        if self.tree.is_some() {
            return Err(Error::AlreadyExists);
        }
        self.tree = Some(CifsTree::new(tree_id, share, flags, 0x01 /* DISK */));
        Ok(())
    }

    /// Open a file on the mounted share and return a local handle index.
    pub fn create_file(&mut self, access_mask: u32, flags: HandleFlags) -> Result<usize> {
        let tree = self.tree.as_ref().ok_or(Error::NotFound)?;
        let tree_id = tree.tree_id;
        self.credits.consume(1)?;
        let mid = self.session.alloc_message_id();
        let file_id = Smb2FileId::new(mid, mid ^ 0xDEAD_BEEF);
        let handle = CifsFileHandle::new(file_id, tree_id, flags, access_mask);
        self.fds.insert(handle)
    }

    /// Read data from an open handle (simulated — returns byte count).
    pub fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize> {
        self.credits.consume(1)?;
        let handle = self.fds.get_mut(fd)?;
        let read_len = buf
            .len()
            .min(handle.end_of_file.saturating_sub(handle.offset) as usize);
        handle.offset += read_len as u64;
        Ok(read_len)
    }

    /// Write data to an open handle (simulated — returns byte count).
    pub fn write_file(&mut self, fd: usize, data: &[u8]) -> Result<usize> {
        self.credits.consume(1)?;
        let handle = self.fds.get_mut(fd)?;
        handle.offset += data.len() as u64;
        if handle.offset > handle.end_of_file {
            handle.end_of_file = handle.offset;
        }
        Ok(data.len())
    }

    /// Close an open file handle.
    pub fn close_file(&mut self, fd: usize) -> Result<()> {
        self.credits.consume(1)?;
        self.fds.remove(fd)?;
        Ok(())
    }

    /// Build an SMB2 compound request from a list of commands.
    pub fn build_compound(&mut self, commands: &[(Smb2Command, bool)]) -> Result<CompoundRequest> {
        let mut req = CompoundRequest::new();
        for &(cmd, related) in commands {
            req.push(CompoundEntry {
                command: cmd,
                credit_charge: 1,
                related,
            })?;
        }
        let total_charge = req.total_credit_charge();
        self.credits.consume(total_charge)?;
        Ok(req)
    }

    /// Return the mount path as a byte slice.
    pub fn mount_path_bytes(&self) -> &[u8] {
        &self.mount_path[..self.mount_path_len]
    }
}

// ── CifsRegistry ─────────────────────────────────────────────────

/// Global CIFS mount registry — tracks up to [`MAX_CIFS_MOUNTS`] mounts.
#[derive(Debug)]
pub struct CifsRegistry {
    mounts: [Option<CifsMount>; MAX_CIFS_MOUNTS],
    count: usize,
}

impl CifsRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            mounts: [const { None }; MAX_CIFS_MOUNTS],
            count: 0,
        }
    }

    /// Register a new CIFS mount and return its index.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the registry is full.
    pub fn register(&mut self, mount: CifsMount) -> Result<usize> {
        for (i, slot) in self.mounts.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(mount);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister the mount at `index`.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CIFS_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        if self.mounts[index].is_none() {
            return Err(Error::NotFound);
        }
        self.mounts[index] = None;
        self.count -= 1;
        Ok(())
    }

    /// Look up a mount by index.
    pub fn get(&self, index: usize) -> Result<&CifsMount> {
        if index >= MAX_CIFS_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        self.mounts[index].as_ref().ok_or(Error::NotFound)
    }

    /// Look up a mount by index (mutable).
    pub fn get_mut(&mut self, index: usize) -> Result<&mut CifsMount> {
        if index >= MAX_CIFS_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        self.mounts[index].as_mut().ok_or(Error::NotFound)
    }

    /// Return the number of registered mounts.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Find the first mount whose local path matches `path`.
    pub fn find_by_path(&self, path: &[u8]) -> Option<(usize, &CifsMount)> {
        for (i, slot) in self.mounts.iter().enumerate() {
            if let Some(m) = slot {
                if m.mount_path_bytes() == path {
                    return Some((i, m));
                }
            }
        }
        None
    }
}

impl Default for CifsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
