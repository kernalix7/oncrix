// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ceph MDS (Metadata Server) client protocol stubs.
//!
//! The Ceph MDS is responsible for filesystem metadata: inode allocation,
//! namespace operations, and capability management.  This module models
//! the client-side state of an MDS session, including the capability cache,
//! request dispatch, and safe session teardown.

use oncrix_lib::{Error, Result};

/// Maximum number of MDS sessions a single client can open.
pub const CEPH_MAX_MDS_SESSIONS: usize = 64;

/// Maximum number of outstanding MDS requests per session.
pub const CEPH_MAX_MDS_REQUESTS: usize = 256;

/// Ceph MDS capability bit flags.
pub mod cap_bits {
    pub const GID_LIST: u32 = 1 << 0;
    pub const PIN: u32 = 1 << 1;
    pub const AUTH: u32 = 1 << 2;
    pub const LINK: u32 = 1 << 3;
    pub const XATTR: u32 = 1 << 4;
    pub const FILE_RD: u32 = 1 << 5;
    pub const FILE_CACHE: u32 = 1 << 6;
    pub const FILE_WR: u32 = 1 << 7;
    pub const FILE_BUFFER: u32 = 1 << 8;
    pub const FILE_EXCL: u32 = 1 << 9;
    pub const FILE_LAZYIO: u32 = 1 << 10;
}

/// State of a single MDS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdsSessionState {
    /// Not yet connected.
    Closed,
    /// Opening — waiting for `SESSION_OPEN` reply.
    Opening,
    /// Fully open and accepting requests.
    Open,
    /// Hung: no reply for too long.
    Hung,
    /// Reconnecting after MDS restart.
    Reconnecting,
    /// Rejecting new requests (session is closing).
    Closing,
}

/// An in-flight MDS request.
#[derive(Debug, Clone)]
pub struct MdsRequest {
    /// Client-assigned request ID.
    pub tid: u64,
    /// MDS operation code.
    pub op: u32,
    /// Target inode (may be 0 for root operations).
    pub ino: u64,
    /// Whether the request has been sent to the MDS.
    pub sent: bool,
    /// Whether a reply has been received.
    pub replied: bool,
    /// Error code from the reply (0 = success).
    pub reply_err: i32,
}

impl MdsRequest {
    /// Create a new pending MDS request.
    pub fn new(tid: u64, op: u32, ino: u64) -> Self {
        Self {
            tid,
            op,
            ino,
            sent: false,
            replied: false,
            reply_err: 0,
        }
    }
}

/// A cached capability grant for one inode.
#[derive(Debug, Clone, Copy)]
pub struct CephCap {
    /// Inode number this cap covers.
    pub ino: u64,
    /// MDS session index that issued the cap.
    pub session_idx: usize,
    /// Issued capability bits.
    pub issued: u32,
    /// Implemented (locally used) bits.
    pub implemented: u32,
    /// Sequence number for cap renewal.
    pub seq: u32,
    /// Whether this cap has been revoked.
    pub revoked: bool,
}

impl CephCap {
    /// Create a new cap.
    pub fn new(ino: u64, session_idx: usize, issued: u32, seq: u32) -> Self {
        Self {
            ino,
            session_idx,
            issued,
            implemented: issued,
            seq,
            revoked: false,
        }
    }

    /// Whether the cap grants the given bits.
    pub fn has(&self, bits: u32) -> bool {
        !self.revoked && (self.issued & bits) == bits
    }
}

/// Maximum number of cached capabilities.
pub const CEPH_MAX_CAPS: usize = 4096;

/// In-memory MDS session.
pub struct MdsSession {
    /// MDS rank this session is connected to.
    pub mds_rank: u32,
    /// Session state.
    pub state: MdsSessionState,
    /// Session ID assigned by the MDS.
    pub session_id: u64,
    /// Monotonically increasing request TID.
    pub next_tid: u64,
    /// In-flight request table.
    requests: [Option<MdsRequest>; CEPH_MAX_MDS_REQUESTS],
    pub req_count: usize,
}

impl MdsSession {
    /// Create a new closed session for the given MDS rank.
    pub const fn new(mds_rank: u32) -> Self {
        Self {
            mds_rank,
            state: MdsSessionState::Closed,
            session_id: 0,
            next_tid: 1,
            requests: [const { None }; CEPH_MAX_MDS_REQUESTS],
            req_count: 0,
        }
    }

    /// Transition to `Opening` state.
    pub fn open(&mut self) -> Result<()> {
        if self.state != MdsSessionState::Closed {
            return Err(Error::Busy);
        }
        self.state = MdsSessionState::Opening;
        Ok(())
    }

    /// Complete the session open (MDS sent `SESSION_OPEN`).
    pub fn on_open(&mut self, session_id: u64) -> Result<()> {
        if self.state != MdsSessionState::Opening {
            return Err(Error::InvalidArgument);
        }
        self.session_id = session_id;
        self.state = MdsSessionState::Open;
        Ok(())
    }

    /// Submit a new MDS request.
    pub fn submit_request(&mut self, op: u32, ino: u64) -> Result<u64> {
        if self.state != MdsSessionState::Open {
            return Err(Error::IoError);
        }
        if self.req_count >= CEPH_MAX_MDS_REQUESTS {
            return Err(Error::Busy);
        }
        let tid = self.next_tid;
        self.next_tid += 1;
        let mut req = MdsRequest::new(tid, op, ino);
        req.sent = true;
        for slot in &mut self.requests {
            if slot.is_none() {
                *slot = Some(req);
                self.req_count += 1;
                return Ok(tid);
            }
        }
        Err(Error::Busy)
    }

    /// Record a reply from the MDS.
    pub fn on_reply(&mut self, tid: u64, err: i32) -> Result<()> {
        for slot in &mut self.requests {
            if slot.as_ref().map(|r| r.tid) == Some(tid) {
                if let Some(req) = slot.as_mut() {
                    req.replied = true;
                    req.reply_err = err;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a completed request.
    pub fn complete_request(&mut self, tid: u64) -> Result<MdsRequest> {
        for slot in &mut self.requests {
            if slot.as_ref().map(|r| r.tid == tid && r.replied) == Some(true) {
                self.req_count -= 1;
                return Ok(slot.take().unwrap());
            }
        }
        Err(Error::NotFound)
    }

    /// Mark the session as closing.
    pub fn close(&mut self) {
        self.state = MdsSessionState::Closing;
    }
}

/// Client-side MDS connection manager.
pub struct MdsClient {
    sessions: [Option<MdsSession>; CEPH_MAX_MDS_SESSIONS],
    session_count: usize,
    caps: [Option<CephCap>; CEPH_MAX_CAPS],
    cap_count: usize,
}

impl MdsClient {
    /// Create a new MDS client.
    pub const fn new() -> Self {
        Self {
            sessions: [const { None }; CEPH_MAX_MDS_SESSIONS],
            session_count: 0,
            caps: [const { None }; CEPH_MAX_CAPS],
            cap_count: 0,
        }
    }

    /// Open a session to the given MDS rank.
    pub fn open_session(&mut self, rank: u32) -> Result<usize> {
        if self.session_count >= CEPH_MAX_MDS_SESSIONS {
            return Err(Error::OutOfMemory);
        }
        for (idx, slot) in self.sessions.iter_mut().enumerate() {
            if slot.is_none() {
                let mut sess = MdsSession::new(rank);
                sess.open()?;
                *slot = Some(sess);
                self.session_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Complete an open handshake.
    pub fn on_session_open(&mut self, idx: usize, session_id: u64) -> Result<()> {
        match self.sessions.get_mut(idx).and_then(|s| s.as_mut()) {
            Some(sess) => sess.on_open(session_id),
            None => Err(Error::NotFound),
        }
    }

    /// Get a reference to a session by index.
    pub fn session(&self, idx: usize) -> Option<&MdsSession> {
        self.sessions.get(idx).and_then(|s| s.as_ref())
    }

    /// Cache a capability grant.
    pub fn cache_cap(&mut self, cap: CephCap) -> Result<()> {
        if self.cap_count >= CEPH_MAX_CAPS {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.caps {
            if slot.is_none() {
                *slot = Some(cap);
                self.cap_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a cached cap for the given inode.
    pub fn find_cap(&self, ino: u64) -> Option<&CephCap> {
        self.caps
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|c| c.ino == ino)
    }
}

impl Default for MdsClient {
    fn default() -> Self {
        Self::new()
    }
}
