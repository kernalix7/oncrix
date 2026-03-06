// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS RPC client operations.
//!
//! Implements the Sun RPC (ONC RPC) client layer used by the NFS client to
//! encode, send, and decode procedure calls against an NFS server.  The
//! implementation covers:
//!
//! - XDR encode/decode for RPC headers and basic scalar types
//! - RPC call record construction (program, version, procedure, credentials)
//! - Reply matching by transaction ID (XID)
//! - Retransmission bookkeeping
//! - Program/version/procedure dispatch table
//!
//! # Architecture
//!
//! ```text
//! Caller
//!   → RpcClient::call(prog, ver, proc, args)
//!     → XdrBuffer::encode_call_header()
//!     → XdrBuffer::encode_args()
//!     → RpcCallTable::dispatch() — look up handler
//!     → RpcClient::send()        — hand off to transport
//!     → RpcClient::recv_reply()  — wait for matching XID
//!     → XdrBuffer::decode_reply_header()
//!     → XdrBuffer::decode_result()
//! ```
//!
//! # Structures
//!
//! - [`RpcAuthFlavor`]  — AUTH_NULL / AUTH_UNIX / AUTH_GSS
//! - [`RpcCredential`]  — serialised credential bytes
//! - [`RpcMsgType`]     — CALL or REPLY
//! - [`RpcReplyStatus`] — MSG_ACCEPTED / MSG_DENIED
//! - [`RpcAcceptStatus`]— SUCCESS / PROG_MISMATCH / PROC_UNAVAIL / …
//! - [`RpcCallHeader`]  — XID + CALL + prog/ver/proc + cred/verf
//! - [`RpcReplyHeader`] — XID + REPLY + accept/deny status
//! - [`XdrBuffer`]      — fixed-capacity encode/decode buffer
//! - [`RpcProcDesc`]    — one procedure in the dispatch table
//! - [`RpcProgDesc`]    — one program in the dispatch table
//! - [`RpcCallTable`]   — static dispatch table (4 programs, 32 procs each)
//! - [`RpcPendingCall`] — an in-flight RPC call with retransmission state
//! - [`RpcClient`]      — stateful RPC client

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum XDR buffer size (8 KiB).
const MAX_XDR_SIZE: usize = 8192;

/// Maximum RPC credential data length in bytes.
const MAX_CRED_LEN: usize = 400;

/// Maximum number of in-flight RPC calls.
const MAX_PENDING_CALLS: usize = 32;

/// Maximum programs in the dispatch table.
const MAX_PROGRAMS: usize = 4;

/// Maximum procedures per program.
const MAX_PROCS: usize = 32;

/// Maximum retransmission attempts before giving up.
const MAX_RETRIES: u32 = 5;

/// Initial retransmit timeout in milliseconds.
const INITIAL_RTO_MS: u64 = 1000;

/// Maximum retransmit timeout (30 s).
const MAX_RTO_MS: u64 = 30_000;

/// NFS program number.
pub const PROG_NFS: u32 = 100003;

/// Mount protocol program number.
pub const PROG_MOUNT: u32 = 100005;

/// RPC standard version.
pub const RPC_VERSION: u32 = 2;

// ── RpcAuthFlavor ────────────────────────────────────────────────────────────

/// Authentication flavor for an RPC credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcAuthFlavor {
    /// No authentication.
    Null = 0,
    /// UNIX-style UID/GID credential.
    Unix = 1,
    /// GSS-API (Kerberos) credential.
    Gss = 6,
}

// ── RpcCredential ────────────────────────────────────────────────────────────

/// A serialised RPC credential (flavor + opaque bytes).
#[derive(Debug, Clone, Copy)]
pub struct RpcCredential {
    /// Authentication flavor.
    pub flavor: RpcAuthFlavor,
    /// Serialised credential body.
    pub body: [u8; MAX_CRED_LEN],
    /// Number of valid bytes in `body`.
    pub body_len: usize,
}

impl RpcCredential {
    /// Create a null credential.
    pub const fn null() -> Self {
        Self {
            flavor: RpcAuthFlavor::Null,
            body: [0u8; MAX_CRED_LEN],
            body_len: 0,
        }
    }

    /// Create a minimal AUTH_UNIX credential for `(uid, gid)`.
    pub fn unix(uid: u32, gid: u32) -> Self {
        let mut cred = Self::null();
        cred.flavor = RpcAuthFlavor::Unix;
        // machine name length = 0, stamp = 0, uid, gid, gids_count = 0.
        let uid_bytes = uid.to_be_bytes();
        let gid_bytes = gid.to_be_bytes();
        // stamp (4) + name_len (4) + uid (4) + gid (4) + gids_count (4) = 20
        cred.body[4..8].copy_from_slice(&uid_bytes);
        cred.body[8..12].copy_from_slice(&gid_bytes);
        cred.body_len = 20;
        cred
    }
}

// ── RpcMsgType ───────────────────────────────────────────────────────────────

/// RPC message type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcMsgType {
    /// Outgoing procedure call.
    Call = 0,
    /// Server reply.
    Reply = 1,
}

// ── RpcReplyStatus ───────────────────────────────────────────────────────────

/// Top-level status in an RPC reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcReplyStatus {
    /// The call was processed (may still carry an application-level error).
    Accepted = 0,
    /// The call was denied (auth failure, RPC version mismatch).
    Denied = 1,
}

// ── RpcAcceptStatus ──────────────────────────────────────────────────────────

/// Accept status within an MSG_ACCEPTED reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcAcceptStatus {
    /// Call executed successfully.
    Success = 0,
    /// Program not available on this server.
    ProgUnavail = 1,
    /// Program version mismatch.
    ProgMismatch = 2,
    /// Procedure not available.
    ProcUnavail = 3,
    /// Arguments could not be decoded.
    GarbageArgs = 4,
    /// System error on the server.
    SystemErr = 5,
}

// ── RpcCallHeader ────────────────────────────────────────────────────────────

/// Encoded fields of an outgoing RPC CALL message.
#[derive(Debug, Clone, Copy)]
pub struct RpcCallHeader {
    /// Transaction ID (XID): unique per outstanding call.
    pub xid: u32,
    /// Always [`RpcMsgType::Call`].
    pub msg_type: RpcMsgType,
    /// Always [`RPC_VERSION`].
    pub rpc_version: u32,
    /// Remote program number.
    pub program: u32,
    /// Program version.
    pub version: u32,
    /// Procedure number.
    pub procedure: u32,
    /// Authentication credential.
    pub credential: RpcCredential,
}

impl RpcCallHeader {
    /// Construct a call header.
    pub fn new(
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        credential: RpcCredential,
    ) -> Self {
        Self {
            xid,
            msg_type: RpcMsgType::Call,
            rpc_version: RPC_VERSION,
            program,
            version,
            procedure,
            credential,
        }
    }
}

// ── RpcReplyHeader ───────────────────────────────────────────────────────────

/// Decoded fields from an incoming RPC REPLY message.
#[derive(Debug, Clone, Copy)]
pub struct RpcReplyHeader {
    /// Transaction ID matching the originating call.
    pub xid: u32,
    /// Always [`RpcMsgType::Reply`].
    pub msg_type: RpcMsgType,
    /// Accepted or denied.
    pub reply_status: RpcReplyStatus,
    /// Accept status (valid when `reply_status == Accepted`).
    pub accept_status: RpcAcceptStatus,
}

impl RpcReplyHeader {
    /// Construct a successful reply header.
    pub const fn success(xid: u32) -> Self {
        Self {
            xid,
            msg_type: RpcMsgType::Reply,
            reply_status: RpcReplyStatus::Accepted,
            accept_status: RpcAcceptStatus::Success,
        }
    }
}

// ── XdrBuffer ────────────────────────────────────────────────────────────────

/// A fixed-capacity XDR encode/decode buffer.
///
/// XDR (External Data Representation) encodes all integers in big-endian
/// network byte order aligned to 4-byte boundaries.
pub struct XdrBuffer {
    /// Raw byte storage.
    data: [u8; MAX_XDR_SIZE],
    /// Write cursor (encode) or read cursor (decode).
    pos: usize,
    /// Number of valid bytes (for decode).
    len: usize,
}

impl XdrBuffer {
    /// Create an empty (encode) buffer.
    pub fn new() -> Self {
        Self {
            data: [0u8; MAX_XDR_SIZE],
            pos: 0,
            len: 0,
        }
    }

    /// Create a decode buffer from a byte slice.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `src.len() > MAX_XDR_SIZE`.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() > MAX_XDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut buf = Self::new();
        buf.data[..src.len()].copy_from_slice(src);
        buf.len = src.len();
        Ok(buf)
    }

    /// Encode a big-endian u32.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the buffer is full.
    pub fn encode_u32(&mut self, val: u32) -> Result<()> {
        if self.pos + 4 > MAX_XDR_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[self.pos..self.pos + 4].copy_from_slice(&val.to_be_bytes());
        self.pos += 4;
        self.len = self.pos;
        Ok(())
    }

    /// Encode a big-endian u64 (two XDR words).
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the buffer is full.
    pub fn encode_u64(&mut self, val: u64) -> Result<()> {
        self.encode_u32((val >> 32) as u32)?;
        self.encode_u32(val as u32)
    }

    /// Encode an opaque byte array with a length prefix and 4-byte padding.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the buffer cannot hold the data.
    pub fn encode_opaque(&mut self, bytes: &[u8]) -> Result<()> {
        self.encode_u32(bytes.len() as u32)?;
        let padded = (bytes.len() + 3) & !3;
        if self.pos + padded > MAX_XDR_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += padded;
        self.len = self.pos;
        Ok(())
    }

    /// Decode the next big-endian u32.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if fewer than 4 bytes remain.
    pub fn decode_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.len {
            return Err(Error::InvalidArgument);
        }
        let val = u32::from_be_bytes(
            self.data[self.pos..self.pos + 4]
                .try_into()
                .map_err(|_| Error::IoError)?,
        );
        self.pos += 4;
        Ok(val)
    }

    /// Decode the next big-endian u64.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if fewer than 8 bytes remain.
    pub fn decode_u64(&mut self) -> Result<u64> {
        let hi = self.decode_u32()? as u64;
        let lo = self.decode_u32()? as u64;
        Ok((hi << 32) | lo)
    }

    /// Encode a complete RPC CALL header.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the buffer overflows.
    pub fn encode_call_header(&mut self, hdr: &RpcCallHeader) -> Result<()> {
        self.encode_u32(hdr.xid)?;
        self.encode_u32(hdr.msg_type as u32)?;
        self.encode_u32(hdr.rpc_version)?;
        self.encode_u32(hdr.program)?;
        self.encode_u32(hdr.version)?;
        self.encode_u32(hdr.procedure)?;
        // Credential.
        self.encode_u32(hdr.credential.flavor as u32)?;
        self.encode_opaque(&hdr.credential.body[..hdr.credential.body_len])?;
        // Null verifier.
        self.encode_u32(RpcAuthFlavor::Null as u32)?;
        self.encode_u32(0)?; // verifier body length = 0
        Ok(())
    }

    /// Decode an RPC REPLY header from this buffer.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the buffer is truncated.
    /// - `IoError` if unexpected field values are encountered.
    pub fn decode_reply_header(&mut self) -> Result<RpcReplyHeader> {
        let xid = self.decode_u32()?;
        let msg_type_raw = self.decode_u32()?;
        if msg_type_raw != RpcMsgType::Reply as u32 {
            return Err(Error::IoError);
        }
        let reply_status = match self.decode_u32()? {
            0 => RpcReplyStatus::Accepted,
            1 => RpcReplyStatus::Denied,
            _ => return Err(Error::IoError),
        };
        // Skip verifier (flavor + opaque length).
        let _verf_flavor = self.decode_u32()?;
        let verf_len = self.decode_u32()? as usize;
        if self.pos + verf_len > self.len {
            return Err(Error::InvalidArgument);
        }
        self.pos += (verf_len + 3) & !3;

        let accept_status = if reply_status == RpcReplyStatus::Accepted {
            match self.decode_u32()? {
                0 => RpcAcceptStatus::Success,
                1 => RpcAcceptStatus::ProgUnavail,
                2 => RpcAcceptStatus::ProgMismatch,
                3 => RpcAcceptStatus::ProcUnavail,
                4 => RpcAcceptStatus::GarbageArgs,
                5 => RpcAcceptStatus::SystemErr,
                _ => return Err(Error::IoError),
            }
        } else {
            RpcAcceptStatus::Success
        };

        Ok(RpcReplyHeader {
            xid,
            msg_type: RpcMsgType::Reply,
            reply_status,
            accept_status,
        })
    }

    /// Return the encoded data as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Reset the buffer for reuse as an encoder.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.len = 0;
    }
}

impl Default for XdrBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Dispatch table ───────────────────────────────────────────────────────────

/// Descriptor for one RPC procedure.
#[derive(Debug, Clone, Copy)]
pub struct RpcProcDesc {
    /// Procedure number.
    pub proc_num: u32,
    /// Human-readable name (up to 32 bytes, NUL-padded).
    pub name: [u8; 32],
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RpcProcDesc {
    /// Create an empty slot.
    pub const fn empty() -> Self {
        Self {
            proc_num: 0,
            name: [0u8; 32],
            in_use: false,
        }
    }

    /// Create a populated proc descriptor.
    pub fn new(proc_num: u32, name: &[u8]) -> Self {
        let mut desc = Self::empty();
        desc.proc_num = proc_num;
        let copy_len = name.len().min(31);
        desc.name[..copy_len].copy_from_slice(&name[..copy_len]);
        desc.in_use = true;
        desc
    }
}

/// Descriptor for one RPC program with its procedures.
#[derive(Debug)]
pub struct RpcProgDesc {
    /// Program number.
    pub prog_num: u32,
    /// Supported version.
    pub version: u32,
    /// Procedure table.
    pub procs: [RpcProcDesc; MAX_PROCS],
    /// Number of registered procedures.
    pub proc_count: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RpcProgDesc {
    /// Create an empty program descriptor.
    pub fn empty() -> Self {
        Self {
            prog_num: 0,
            version: 0,
            procs: [const { RpcProcDesc::empty() }; MAX_PROCS],
            proc_count: 0,
            in_use: false,
        }
    }

    /// Find a procedure by number.
    pub fn find_proc(&self, proc_num: u32) -> Option<&RpcProcDesc> {
        self.procs[..self.proc_count]
            .iter()
            .find(|p| p.in_use && p.proc_num == proc_num)
    }

    /// Register a procedure.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the proc table is full.
    pub fn register_proc(&mut self, desc: RpcProcDesc) -> Result<()> {
        if self.proc_count >= MAX_PROCS {
            return Err(Error::OutOfMemory);
        }
        self.procs[self.proc_count] = desc;
        self.proc_count += 1;
        Ok(())
    }
}

/// Static dispatch table of registered RPC programs.
pub struct RpcCallTable {
    /// Program descriptors.
    programs: [RpcProgDesc; MAX_PROGRAMS],
    /// Number of registered programs.
    prog_count: usize,
}

impl RpcCallTable {
    /// Create an empty call table.
    pub fn new() -> Self {
        Self {
            programs: core::array::from_fn(|_| RpcProgDesc::empty()),
            prog_count: 0,
        }
    }

    /// Register a program.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the program table is full.
    /// - `AlreadyExists` if a program with the same number/version exists.
    pub fn register_program(&mut self, prog: RpcProgDesc) -> Result<()> {
        if self.prog_count >= MAX_PROGRAMS {
            return Err(Error::OutOfMemory);
        }
        if self.programs[..self.prog_count]
            .iter()
            .any(|p| p.in_use && p.prog_num == prog.prog_num && p.version == prog.version)
        {
            return Err(Error::AlreadyExists);
        }
        self.programs[self.prog_count] = prog;
        self.prog_count += 1;
        Ok(())
    }

    /// Validate that `(prog, ver, proc)` is registered.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the program/version/procedure is not registered.
    pub fn dispatch(&self, prog: u32, ver: u32, proc: u32) -> Result<&RpcProcDesc> {
        let prog_desc = self.programs[..self.prog_count]
            .iter()
            .find(|p| p.in_use && p.prog_num == prog && p.version == ver)
            .ok_or(Error::NotFound)?;
        prog_desc.find_proc(proc).ok_or(Error::NotFound)
    }
}

impl Default for RpcCallTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── RpcPendingCall ───────────────────────────────────────────────────────────

/// State for one in-flight RPC call.
#[derive(Debug, Clone, Copy)]
pub struct RpcPendingCall {
    /// Transaction ID.
    pub xid: u32,
    /// Program being called.
    pub program: u32,
    /// Program version.
    pub version: u32,
    /// Procedure number.
    pub procedure: u32,
    /// Number of retransmissions so far.
    pub retry_count: u32,
    /// Current retransmit timeout in milliseconds.
    pub rto_ms: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RpcPendingCall {
    /// Create an empty pending-call slot.
    pub const fn empty() -> Self {
        Self {
            xid: 0,
            program: 0,
            version: 0,
            procedure: 0,
            retry_count: 0,
            rto_ms: INITIAL_RTO_MS,
            in_use: false,
        }
    }

    /// Create a new in-flight call record.
    pub const fn new(xid: u32, program: u32, version: u32, procedure: u32) -> Self {
        Self {
            xid,
            program,
            version,
            procedure,
            retry_count: 0,
            rto_ms: INITIAL_RTO_MS,
            in_use: true,
        }
    }

    /// Apply exponential back-off for the next retransmit.
    ///
    /// Returns `false` if the maximum retry count has been reached.
    pub fn backoff(&mut self) -> bool {
        if self.retry_count >= MAX_RETRIES {
            return false;
        }
        self.retry_count += 1;
        self.rto_ms = (self.rto_ms * 2).min(MAX_RTO_MS);
        true
    }
}

// ── RpcClient ────────────────────────────────────────────────────────────────

/// Stateful NFS RPC client.
///
/// Manages the XID counter, in-flight call table, credential, and dispatch
/// table for a single NFS server connection.
pub struct RpcClient {
    /// Monotonically increasing transaction ID.
    next_xid: u32,
    /// Default credential used for new calls.
    default_cred: RpcCredential,
    /// In-flight calls awaiting a reply.
    pending: [RpcPendingCall; MAX_PENDING_CALLS],
    /// Number of occupied pending slots.
    pending_count: usize,
    /// Dispatch table of registered programs.
    call_table: RpcCallTable,
    /// Encode buffer reused across calls.
    encode_buf: XdrBuffer,
    /// Total calls dispatched.
    call_count: u64,
    /// Total successful replies matched.
    reply_count: u64,
    /// Total retransmissions.
    retransmit_count: u64,
}

impl RpcClient {
    /// Create a new client with `cred` as the default credential.
    pub fn new(cred: RpcCredential) -> Self {
        Self {
            next_xid: 1,
            default_cred: cred,
            pending: [const { RpcPendingCall::empty() }; MAX_PENDING_CALLS],
            pending_count: 0,
            call_table: RpcCallTable::new(),
            encode_buf: XdrBuffer::new(),
            call_count: 0,
            reply_count: 0,
            retransmit_count: 0,
        }
    }

    /// Register a program/version in the dispatch table.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`RpcCallTable::register_program`].
    pub fn register_program(&mut self, prog: RpcProgDesc) -> Result<()> {
        self.call_table.register_program(prog)
    }

    /// Build and encode an RPC call message for `(prog, ver, proc)`.
    ///
    /// Returns the XID assigned to this call.  The caller is responsible
    /// for transmitting `encode_buf.as_bytes()` to the server.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the procedure is not registered.
    /// - `Busy` if the pending-call table is full.
    /// - `OutOfMemory` if the encode buffer overflows.
    pub fn encode_call(&mut self, prog: u32, ver: u32, proc: u32, args: &[u8]) -> Result<u32> {
        // Validate against dispatch table.
        let _desc = self.call_table.dispatch(prog, ver, proc)?;

        if self.pending_count >= MAX_PENDING_CALLS {
            return Err(Error::Busy);
        }

        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);

        let hdr = RpcCallHeader::new(xid, prog, ver, proc, self.default_cred);
        self.encode_buf.reset();
        self.encode_buf.encode_call_header(&hdr)?;
        self.encode_buf.encode_opaque(args)?;

        // Record the in-flight call.
        let slot = self.pending[..MAX_PENDING_CALLS]
            .iter()
            .position(|p| !p.in_use)
            .ok_or(Error::Busy)?;
        self.pending[slot] = RpcPendingCall::new(xid, prog, ver, proc);
        self.pending_count += 1;
        self.call_count += 1;
        Ok(xid)
    }

    /// Process an incoming reply buffer, matching it to a pending call.
    ///
    /// Returns the decoded [`RpcReplyHeader`] on success.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the reply cannot be decoded.
    /// - `NotFound` if no pending call matches the XID.
    /// - `IoError` if the accept status indicates a server error.
    pub fn recv_reply(&mut self, reply_data: &[u8]) -> Result<RpcReplyHeader> {
        let mut buf = XdrBuffer::from_bytes(reply_data)?;
        let hdr = buf.decode_reply_header()?;

        if hdr.accept_status != RpcAcceptStatus::Success {
            return Err(Error::IoError);
        }

        // Find and remove the matching pending call.
        let pos = self.pending[..MAX_PENDING_CALLS]
            .iter()
            .position(|p| p.in_use && p.xid == hdr.xid)
            .ok_or(Error::NotFound)?;
        self.pending[pos] = RpcPendingCall::empty();
        self.pending_count = self.pending_count.saturating_sub(1);
        self.reply_count += 1;
        Ok(hdr)
    }

    /// Perform retransmit back-off for all timed-out pending calls.
    ///
    /// Returns the number of calls that were retransmitted (still within
    /// retry budget) and the number that were abandoned (retry limit hit).
    pub fn retransmit_timeout(&mut self) -> (usize, usize) {
        let mut retransmitted = 0usize;
        let mut abandoned = 0usize;
        for slot in self.pending.iter_mut() {
            if !slot.in_use {
                continue;
            }
            if slot.backoff() {
                retransmitted += 1;
                self.retransmit_count += 1;
            } else {
                slot.in_use = false;
                self.pending_count = self.pending_count.saturating_sub(1);
                abandoned += 1;
            }
        }
        (retransmitted, abandoned)
    }

    /// Total calls dispatched since creation.
    pub fn call_count(&self) -> u64 {
        self.call_count
    }

    /// Total replies matched since creation.
    pub fn reply_count(&self) -> u64 {
        self.reply_count
    }

    /// Total retransmissions since creation.
    pub fn retransmit_count(&self) -> u64 {
        self.retransmit_count
    }

    /// Number of in-flight calls.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Return a reference to the encode buffer (call data ready to send).
    pub fn encode_buf(&self) -> &XdrBuffer {
        &self.encode_buf
    }
}
