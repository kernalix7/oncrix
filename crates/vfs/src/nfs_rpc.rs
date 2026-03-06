// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS RPC transport layer.
//!
//! Implements the Sun RPC (ONC RPC) protocol used by NFSv2/v3/v4 for
//! encoding, transmitting, and decoding remote procedure calls.
//!
//! # Design
//!
//! - [`RpcMsg`] — RPC message header (xid, direction, program, version, proc)
//! - [`AuthFlavor`] — authentication flavours (NONE, SYS, GSS)
//! - [`XdrBuf`] — XDR encode/decode buffer
//! - [`RpcCall`] — builder for outgoing NFS procedure calls
//! - [`RpcReply`] — parsed incoming RPC reply
//! - [`RpcClient`] — pending call table with XID tracking and retransmission

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ───────────────────────────────────────────────────────────────

/// ONC RPC protocol version.
pub const RPC_VERSION: u32 = 2;

/// NFS program number.
pub const NFS_PROGRAM: u32 = 100003;

/// NFS version 3.
pub const NFS_VERSION3: u32 = 3;

/// Maximum XDR buffer size (64 KiB).
const XDR_MAX: usize = 65536;

/// Maximum number of concurrent pending RPC calls.
const MAX_PENDING: usize = 64;

/// Maximum retransmission attempts.
const MAX_RETRIES: u32 = 5;

// ── RPC message direction ───────────────────────────────────────────────────

/// RPC message direction (call or reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// Outgoing call.
    Call = 0,
    /// Incoming reply.
    Reply = 1,
}

// ── Auth flavor ─────────────────────────────────────────────────────────────

/// RPC authentication flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFlavor {
    /// No authentication.
    AuthNone = 0,
    /// Unix-style UID/GID authentication.
    AuthSys = 1,
    /// RPCSEC_GSS (Kerberos, SPKM).
    AuthGss = 6,
}

impl AuthFlavor {
    /// Create from numeric value.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::AuthNone),
            1 => Some(Self::AuthSys),
            6 => Some(Self::AuthGss),
            _ => None,
        }
    }
}

// ── Credential / Verifier ────────────────────────────────────────────────────

/// Unix (AUTH_SYS) credential.
#[derive(Debug, Clone)]
pub struct AuthSysCred {
    /// Stamp (opaque u32, typically a timestamp).
    pub stamp: u32,
    /// Machine name (up to 255 bytes).
    pub machine_name: Vec<u8>,
    /// Effective UID.
    pub uid: u32,
    /// Effective GID.
    pub gid: u32,
    /// Supplementary groups (up to 16).
    pub gids: Vec<u32>,
}

impl AuthSysCred {
    /// Create a simple root credential.
    pub fn root() -> Self {
        Self {
            stamp: 0,
            machine_name: b"oncrix".to_vec(),
            uid: 0,
            gid: 0,
            gids: Vec::new(),
        }
    }

    /// Create a user credential.
    pub fn new(uid: u32, gid: u32, gids: Vec<u32>) -> Self {
        Self {
            stamp: 0,
            machine_name: b"oncrix".to_vec(),
            uid,
            gid,
            gids,
        }
    }
}

/// Opaque verifier (body of AUTH_NONE or GSS verifier).
#[derive(Debug, Clone)]
pub struct OpaqueAuth {
    /// Flavor of this verifier.
    pub flavor: AuthFlavor,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

impl OpaqueAuth {
    /// AUTH_NONE verifier with empty body.
    pub fn none() -> Self {
        Self {
            flavor: AuthFlavor::AuthNone,
            body: Vec::new(),
        }
    }
}

// ── NFS procedure codes ─────────────────────────────────────────────────────

/// NFS v3 procedure numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsProc3 {
    Null = 0,
    Getattr = 1,
    Setattr = 2,
    Lookup = 3,
    Access = 4,
    Readlink = 5,
    Read = 6,
    Write = 7,
    Create = 8,
    Mkdir = 9,
    Symlink = 10,
    Mknod = 11,
    Remove = 12,
    Rmdir = 13,
    Rename = 14,
    Link = 15,
    Readdir = 16,
    Readdirplus = 17,
    Fsstat = 18,
    Fsinfo = 19,
    Pathconf = 20,
    Commit = 21,
}

// ── Reply status ─────────────────────────────────────────────────────────────

/// RPC reply status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyStatus {
    /// Message accepted (may still carry an error in accept_stat).
    MsgAccepted = 0,
    /// Message denied.
    MsgDenied = 1,
}

/// Accepted reply status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptStat {
    /// RPC executed successfully.
    Success = 0,
    /// Remote program unavailable.
    ProgUnavail = 1,
    /// Remote program version mismatch.
    ProgMismatch = 2,
    /// Remote procedure unavailable.
    ProcUnavail = 3,
    /// Garbage arguments.
    GarbageArgs = 4,
    /// System error.
    SystemErr = 5,
}

impl AcceptStat {
    /// Create from numeric value.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Success),
            1 => Some(Self::ProgUnavail),
            2 => Some(Self::ProgMismatch),
            3 => Some(Self::ProcUnavail),
            4 => Some(Self::GarbageArgs),
            5 => Some(Self::SystemErr),
            _ => None,
        }
    }
}

// ── XdrBuf ───────────────────────────────────────────────────────────────────

/// XDR encode/decode buffer.
pub struct XdrBuf {
    data: Vec<u8>,
    pos: usize,
}

impl XdrBuf {
    /// Create a new empty XDR buffer.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            pos: 0,
        }
    }

    /// Create an XDR buffer for decoding from existing bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            data: bytes,
            pos: 0,
        }
    }

    /// Returns the current encoded length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the buffer contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// Encode a u32 (big-endian, 4 bytes).
    pub fn encode_u32(&mut self, v: u32) -> Result<()> {
        if self.data.len() + 4 > XDR_MAX {
            return Err(Error::OutOfMemory);
        }
        self.data.extend_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// Encode a u64 (big-endian, 8 bytes).
    pub fn encode_u64(&mut self, v: u64) -> Result<()> {
        if self.data.len() + 8 > XDR_MAX {
            return Err(Error::OutOfMemory);
        }
        self.data.extend_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// Encode a variable-length opaque byte string (length-prefixed, padded to 4).
    pub fn encode_opaque(&mut self, bytes: &[u8]) -> Result<()> {
        let len = bytes.len() as u32;
        self.encode_u32(len)?;
        let pad = (4 - (bytes.len() % 4)) % 4;
        if self.data.len() + bytes.len() + pad > XDR_MAX {
            return Err(Error::OutOfMemory);
        }
        self.data.extend_from_slice(bytes);
        for _ in 0..pad {
            self.data.push(0);
        }
        Ok(())
    }

    /// Encode a UTF-8 string as XDR opaque.
    pub fn encode_string(&mut self, s: &[u8]) -> Result<()> {
        self.encode_opaque(s)
    }

    // ── Decoding ─────────────────────────────────────────────────────────────

    /// Decode a u32.
    pub fn decode_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::IoError);
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Decode a u64.
    pub fn decode_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(Error::IoError);
        }
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// Decode a variable-length opaque byte string.
    pub fn decode_opaque(&mut self) -> Result<Vec<u8>> {
        let len = self.decode_u32()? as usize;
        let pad = (4 - (len % 4)) % 4;
        if self.pos + len + pad > self.data.len() {
            return Err(Error::IoError);
        }
        let bytes = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len + pad;
        Ok(bytes)
    }

    /// Decode a XDR string.
    pub fn decode_string(&mut self) -> Result<Vec<u8>> {
        self.decode_opaque()
    }

    /// Returns remaining unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

impl Default for XdrBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ── RpcMsg ───────────────────────────────────────────────────────────────────

/// RPC message header.
#[derive(Debug, Clone)]
pub struct RpcMsg {
    /// Transaction ID — unique per outstanding call.
    pub xid: u32,
    /// Direction: Call or Reply.
    pub msg_type: MsgType,
    /// RPC protocol version (always 2).
    pub rpc_vers: u32,
    /// RPC program number.
    pub program: u32,
    /// Program version.
    pub vers: u32,
    /// Procedure number.
    pub proc: u32,
}

impl RpcMsg {
    /// Create a new call message header.
    pub fn call(xid: u32, program: u32, vers: u32, proc: u32) -> Self {
        Self {
            xid,
            msg_type: MsgType::Call,
            rpc_vers: RPC_VERSION,
            program,
            vers,
            proc,
        }
    }

    /// Encode the call header into an XDR buffer.
    pub fn encode_call(
        &self,
        xdr: &mut XdrBuf,
        cred: &OpaqueAuth,
        verf: &OpaqueAuth,
    ) -> Result<()> {
        xdr.encode_u32(self.xid)?;
        xdr.encode_u32(self.msg_type as u32)?;
        xdr.encode_u32(self.rpc_vers)?;
        xdr.encode_u32(self.program)?;
        xdr.encode_u32(self.vers)?;
        xdr.encode_u32(self.proc)?;
        // Credential
        xdr.encode_u32(cred.flavor as u32)?;
        xdr.encode_opaque(&cred.body)?;
        // Verifier
        xdr.encode_u32(verf.flavor as u32)?;
        xdr.encode_opaque(&verf.body)?;
        Ok(())
    }

    /// Encode an AUTH_SYS credential body into XDR.
    pub fn encode_auth_sys(xdr: &mut XdrBuf, cred: &AuthSysCred) -> Result<()> {
        xdr.encode_u32(cred.stamp)?;
        xdr.encode_string(&cred.machine_name)?;
        xdr.encode_u32(cred.uid)?;
        xdr.encode_u32(cred.gid)?;
        xdr.encode_u32(cred.gids.len() as u32)?;
        for &g in &cred.gids {
            xdr.encode_u32(g)?;
        }
        Ok(())
    }
}

// ── RpcCall builder ──────────────────────────────────────────────────────────

/// Builder for outgoing NFS RPC calls.
pub struct RpcCall {
    header: RpcMsg,
    cred: OpaqueAuth,
    verf: OpaqueAuth,
    payload: XdrBuf,
}

impl RpcCall {
    /// Start building an NFS v3 call.
    pub fn nfs3(
        xid: u32,
        proc: NfsProc3,
        auth: AuthFlavor,
        sys_cred: Option<&AuthSysCred>,
    ) -> Result<Self> {
        let header = RpcMsg::call(xid, NFS_PROGRAM, NFS_VERSION3, proc as u32);
        let cred = if auth == AuthFlavor::AuthSys {
            let sc = sys_cred.ok_or(Error::InvalidArgument)?;
            let mut body_xdr = XdrBuf::new();
            RpcMsg::encode_auth_sys(&mut body_xdr, sc)?;
            OpaqueAuth {
                flavor: AuthFlavor::AuthSys,
                body: body_xdr.data,
            }
        } else {
            OpaqueAuth::none()
        };
        Ok(Self {
            header,
            cred,
            verf: OpaqueAuth::none(),
            payload: XdrBuf::new(),
        })
    }

    /// Write a u32 argument.
    pub fn arg_u32(&mut self, v: u32) -> Result<&mut Self> {
        self.payload.encode_u32(v)?;
        Ok(self)
    }

    /// Write a u64 argument.
    pub fn arg_u64(&mut self, v: u64) -> Result<&mut Self> {
        self.payload.encode_u64(v)?;
        Ok(self)
    }

    /// Write an opaque byte argument.
    pub fn arg_opaque(&mut self, b: &[u8]) -> Result<&mut Self> {
        self.payload.encode_opaque(b)?;
        Ok(self)
    }

    /// Write a string argument.
    pub fn arg_string(&mut self, s: &[u8]) -> Result<&mut Self> {
        self.payload.encode_string(s)?;
        Ok(self)
    }

    /// Finalise and return the serialised RPC message bytes.
    pub fn build(mut self) -> Result<Vec<u8>> {
        let mut out = XdrBuf::new();
        self.header.encode_call(&mut out, &self.cred, &self.verf)?;
        out.data.append(&mut self.payload.data);
        Ok(out.data)
    }

    /// XID of this call.
    pub fn xid(&self) -> u32 {
        self.header.xid
    }
}

// ── RpcReply ─────────────────────────────────────────────────────────────────

/// Parsed RPC reply.
#[derive(Debug)]
pub struct RpcReply {
    /// XID matching the call.
    pub xid: u32,
    /// Reply status.
    pub reply_status: ReplyStatus,
    /// Accept status (only valid when reply_status == MsgAccepted).
    pub accept_stat: AcceptStat,
    /// Verifier returned by the server.
    pub verf: OpaqueAuth,
    /// Reply payload (procedure result data).
    pub payload: Vec<u8>,
}

impl RpcReply {
    /// Parse an RPC reply from raw bytes.
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let mut xdr = XdrBuf::from_bytes(bytes);
        let xid = xdr.decode_u32()?;
        let msg_type_raw = xdr.decode_u32()?;
        if msg_type_raw != MsgType::Reply as u32 {
            return Err(Error::InvalidArgument);
        }

        let reply_stat_raw = xdr.decode_u32()?;
        let reply_status = if reply_stat_raw == 0 {
            ReplyStatus::MsgAccepted
        } else {
            ReplyStatus::MsgDenied
        };

        // Verifier
        let verf_flavor_raw = xdr.decode_u32()?;
        let verf_body = xdr.decode_opaque()?;
        let verf_flavor = AuthFlavor::from_u32(verf_flavor_raw).unwrap_or(AuthFlavor::AuthNone);
        let verf = OpaqueAuth {
            flavor: verf_flavor,
            body: verf_body,
        };

        let accept_stat = if reply_status == ReplyStatus::MsgAccepted {
            let stat = xdr.decode_u32()?;
            AcceptStat::from_u32(stat).unwrap_or(AcceptStat::SystemErr)
        } else {
            AcceptStat::SystemErr
        };

        let payload = xdr.data[xdr.pos..].to_vec();
        Ok(Self {
            xid,
            reply_status,
            accept_stat,
            verf,
            payload,
        })
    }

    /// Returns true if the call succeeded.
    pub fn is_ok(&self) -> bool {
        self.reply_status == ReplyStatus::MsgAccepted && self.accept_stat == AcceptStat::Success
    }
}

// ── PendingCall ───────────────────────────────────────────────────────────────

/// A tracked pending RPC call.
#[derive(Debug, Clone)]
struct PendingCall {
    /// Transaction ID.
    xid: u32,
    /// Serialized call bytes for retransmission.
    call_bytes: Vec<u8>,
    /// Number of times this call has been sent.
    retries: u32,
    /// NFS procedure for logging.
    proc: u32,
}

// ── RpcClient ────────────────────────────────────────────────────────────────

/// NFS RPC client: manages XID allocation, pending calls, and retransmission.
pub struct RpcClient {
    pending: [Option<PendingCall>; MAX_PENDING],
    num_pending: usize,
    next_xid: u32,
    /// Total calls sent.
    pub calls_sent: u64,
    /// Total replies received.
    pub replies_received: u64,
    /// Total retransmissions.
    pub retransmits: u64,
}

impl RpcClient {
    /// Create a new RPC client.
    pub fn new() -> Self {
        Self {
            pending: core::array::from_fn(|_| None),
            num_pending: 0,
            next_xid: 1,
            calls_sent: 0,
            replies_received: 0,
            retransmits: 0,
        }
    }

    /// Allocate a fresh XID.
    pub fn alloc_xid(&mut self) -> u32 {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1).max(1);
        xid
    }

    /// Register a sent call for XID tracking.
    pub fn register_call(&mut self, xid: u32, call_bytes: Vec<u8>, proc: u32) -> Result<()> {
        if self.num_pending >= MAX_PENDING {
            return Err(Error::Busy);
        }
        let slot = self
            .pending
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::Busy)?;
        *slot = Some(PendingCall {
            xid,
            call_bytes,
            retries: 0,
            proc,
        });
        self.num_pending += 1;
        self.calls_sent += 1;
        Ok(())
    }

    /// Match an incoming reply XID to a pending call.
    ///
    /// Removes the call from the pending table on success.
    pub fn match_reply(&mut self, xid: u32) -> Option<u32> {
        for slot in &mut self.pending {
            if let Some(pc) = slot {
                if pc.xid == xid {
                    let proc = pc.proc;
                    *slot = None;
                    self.num_pending -= 1;
                    self.replies_received += 1;
                    return Some(proc);
                }
            }
        }
        None
    }

    /// Retransmit calls that have not received a reply.
    ///
    /// Returns a list of (xid, call_bytes) pairs to resend.
    pub fn retransmit_pending(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut to_resend = Vec::new();
        let mut expired_xids = Vec::new();

        for slot in &mut self.pending {
            if let Some(pc) = slot {
                if pc.retries < MAX_RETRIES {
                    pc.retries += 1;
                    self.retransmits += 1;
                    to_resend.push((pc.xid, pc.call_bytes.clone()));
                } else {
                    expired_xids.push(pc.xid);
                }
            }
        }

        // Remove expired calls
        for xid in expired_xids {
            for slot in &mut self.pending {
                if let Some(pc) = slot {
                    if pc.xid == xid {
                        *slot = None;
                        self.num_pending -= 1;
                        break;
                    }
                }
            }
        }

        to_resend
    }

    /// Build an NFS GETATTR call.
    pub fn build_getattr(&mut self, fh: &[u8], sys_cred: &AuthSysCred) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Getattr, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(fh)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Getattr as u32)?;
        Ok(bytes)
    }

    /// Build an NFS LOOKUP call.
    pub fn build_lookup(
        &mut self,
        dir_fh: &[u8],
        name: &[u8],
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Lookup, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(dir_fh)?;
        call.arg_string(name)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Lookup as u32)?;
        Ok(bytes)
    }

    /// Build an NFS READ call.
    pub fn build_read(
        &mut self,
        fh: &[u8],
        offset: u64,
        count: u32,
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Read, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(fh)?;
        call.arg_u64(offset)?;
        call.arg_u32(count)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Read as u32)?;
        Ok(bytes)
    }

    /// Build an NFS WRITE call.
    pub fn build_write(
        &mut self,
        fh: &[u8],
        offset: u64,
        data: &[u8],
        stable: u32,
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Write, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(fh)?;
        call.arg_u64(offset)?;
        call.arg_u32(data.len() as u32)?;
        call.arg_u32(stable)?;
        call.arg_opaque(data)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Write as u32)?;
        Ok(bytes)
    }

    /// Build an NFS CREATE call.
    pub fn build_create(
        &mut self,
        dir_fh: &[u8],
        name: &[u8],
        mode: u32,
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Create, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(dir_fh)?;
        call.arg_string(name)?;
        call.arg_u32(0)?; // CREATE_UNCHECKED
        call.arg_u32(mode)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Create as u32)?;
        Ok(bytes)
    }

    /// Build an NFS REMOVE call.
    pub fn build_remove(
        &mut self,
        dir_fh: &[u8],
        name: &[u8],
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Remove, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(dir_fh)?;
        call.arg_string(name)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Remove as u32)?;
        Ok(bytes)
    }

    /// Build an NFS MKDIR call.
    pub fn build_mkdir(
        &mut self,
        dir_fh: &[u8],
        name: &[u8],
        mode: u32,
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Mkdir, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(dir_fh)?;
        call.arg_string(name)?;
        call.arg_u32(mode)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Mkdir as u32)?;
        Ok(bytes)
    }

    /// Build an NFS RMDIR call.
    pub fn build_rmdir(
        &mut self,
        dir_fh: &[u8],
        name: &[u8],
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Rmdir, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(dir_fh)?;
        call.arg_string(name)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Rmdir as u32)?;
        Ok(bytes)
    }

    /// Build an NFS RENAME call.
    pub fn build_rename(
        &mut self,
        from_dir_fh: &[u8],
        from_name: &[u8],
        to_dir_fh: &[u8],
        to_name: &[u8],
        sys_cred: &AuthSysCred,
    ) -> Result<Vec<u8>> {
        let xid = self.alloc_xid();
        let mut call = RpcCall::nfs3(xid, NfsProc3::Rename, AuthFlavor::AuthSys, Some(sys_cred))?;
        call.arg_opaque(from_dir_fh)?;
        call.arg_string(from_name)?;
        call.arg_opaque(to_dir_fh)?;
        call.arg_string(to_name)?;
        let bytes = call.build()?;
        self.register_call(xid, bytes.clone(), NfsProc3::Rename as u32)?;
        Ok(bytes)
    }

    /// Number of outstanding pending calls.
    pub fn pending_count(&self) -> usize {
        self.num_pending
    }
}

impl Default for RpcClient {
    fn default() -> Self {
        Self::new()
    }
}
