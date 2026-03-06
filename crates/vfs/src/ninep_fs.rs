// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Plan 9 filesystem protocol (9P2000.L) client for the ONCRIX VFS.
//!
//! Implements the VFS-side structures and dispatch for 9P2000.L, the Linux
//! variant of the Plan 9 remote filesystem protocol. Used by QEMU virtio-9p
//! and host-guest file sharing scenarios.

use oncrix_lib::{Error, Result};

/// Maximum message size negotiated during 9P `Tversion`.
pub const NINEP_MAX_MSG_SIZE: u32 = 65536;

/// Maximum path component length in 9P.
pub const NINEP_MAX_WNAME: usize = 256;

/// Maximum number of path components in a single `Twalk`.
pub const NINEP_MAX_WELEM: usize = 16;

/// Maximum number of open fids per connection.
pub const NINEP_MAX_FIDS: usize = 128;

/// 9P message type tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NinepMsgType {
    Tversion = 100,
    Rversion = 101,
    Tattach = 104,
    Rattach = 105,
    Rerror = 107,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Topen = 112,
    Ropen = 113,
    Tcreate = 114,
    Rcreate = 115,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tstat = 124,
    Rstat = 125,
    Twstat = 126,
    Rwstat = 127,
}

/// 9P `qid` — a server-unique file identifier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NinepQid {
    /// File type bits (directory, append-only, etc.).
    pub qtype: u8,
    /// Version counter (incremented on metadata change).
    pub version: u32,
    /// Unique path identifier on the server.
    pub path: u64,
}

impl NinepQid {
    /// Construct a new qid.
    pub const fn new(qtype: u8, version: u32, path: u64) -> Self {
        Self {
            qtype,
            version,
            path,
        }
    }

    /// Returns `true` if this qid represents a directory.
    pub fn is_dir(&self) -> bool {
        self.qtype & 0x80 != 0
    }

    /// Returns `true` if this qid represents a symlink.
    pub fn is_symlink(&self) -> bool {
        self.qtype & 0x02 != 0
    }

    /// Encode into a 13-byte 9P wire representation.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 13 {
            return Err(Error::InvalidArgument);
        }
        buf[0] = self.qtype;
        buf[1..5].copy_from_slice(&self.version.to_le_bytes());
        buf[5..13].copy_from_slice(&self.path.to_le_bytes());
        Ok(())
    }

    /// Decode from a 13-byte 9P wire representation.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 13 {
            return Err(Error::InvalidArgument);
        }
        let qtype = buf[0];
        let version = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let path = u64::from_le_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        Ok(Self {
            qtype,
            version,
            path,
        })
    }
}

/// Open mode flags for 9P `Topen` / `Tcreate`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NinepOpenMode {
    /// Open for reading.
    pub read: bool,
    /// Open for writing.
    pub write: bool,
    /// Truncate on open.
    pub truncate: bool,
    /// Remove on close.
    pub remove_on_close: bool,
}

impl NinepOpenMode {
    /// Encode as a single byte for the 9P wire format.
    pub fn to_byte(&self) -> u8 {
        let mut b = 0u8;
        if self.read && self.write {
            b |= 2;
        } else if self.write {
            b |= 1;
        }
        if self.truncate {
            b |= 0x10;
        }
        if self.remove_on_close {
            b |= 0x40;
        }
        b
    }
}

/// A fid — client-side file reference analogous to a file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct NinepFid {
    /// Fid number assigned by the client.
    pub fid: u32,
    /// Qid of the file this fid points to.
    pub qid: NinepQid,
    /// Open mode (if the fid has been opened).
    pub mode: Option<NinepOpenMode>,
    /// Whether this fid slot is active.
    pub active: bool,
}

impl NinepFid {
    /// Construct an inactive fid slot.
    pub const fn new() -> Self {
        Self {
            fid: 0,
            qid: NinepQid {
                qtype: 0,
                version: 0,
                path: 0,
            },
            mode: None,
            active: false,
        }
    }
}

impl Default for NinepFid {
    fn default() -> Self {
        Self::new()
    }
}

/// Table of active fids for a single 9P connection.
pub struct NinepFidTable {
    fids: [NinepFid; NINEP_MAX_FIDS],
}

impl NinepFidTable {
    /// Create an empty fid table.
    pub const fn new() -> Self {
        Self {
            fids: [const { NinepFid::new() }; NINEP_MAX_FIDS],
        }
    }

    /// Allocate a new fid entry with the given fid number and qid.
    pub fn alloc(&mut self, fid: u32, qid: NinepQid) -> Result<usize> {
        for (i, slot) in self.fids.iter_mut().enumerate() {
            if !slot.active {
                slot.fid = fid;
                slot.qid = qid;
                slot.mode = None;
                slot.active = true;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a fid by its fid number.
    pub fn find(&self, fid: u32) -> Result<usize> {
        for (i, slot) in self.fids.iter().enumerate() {
            if slot.active && slot.fid == fid {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Release a fid by table index (clunk).
    pub fn clunk(&mut self, idx: usize) -> Result<()> {
        if idx >= NINEP_MAX_FIDS {
            return Err(Error::InvalidArgument);
        }
        if !self.fids[idx].active {
            return Err(Error::NotFound);
        }
        self.fids[idx] = NinepFid::new();
        Ok(())
    }

    /// Get an immutable reference to a fid by table index.
    pub fn get(&self, idx: usize) -> Result<&NinepFid> {
        if idx >= NINEP_MAX_FIDS || !self.fids[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.fids[idx])
    }

    /// Get a mutable reference to a fid by table index.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut NinepFid> {
        if idx >= NINEP_MAX_FIDS || !self.fids[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.fids[idx])
    }
}

impl Default for NinepFidTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a `Tversion` message into `buf`.
///
/// Returns the number of bytes written.
pub fn build_tversion(buf: &mut [u8], tag: u16, msize: u32, version: &[u8]) -> Result<usize> {
    // size[4] type[1] tag[2] msize[4] version[s]
    let ver_len = version.len();
    let total = 4 + 1 + 2 + 4 + 2 + ver_len;
    if buf.len() < total {
        return Err(Error::InvalidArgument);
    }
    buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    buf[4] = NinepMsgType::Tversion as u8;
    buf[5..7].copy_from_slice(&tag.to_le_bytes());
    buf[7..11].copy_from_slice(&msize.to_le_bytes());
    buf[11..13].copy_from_slice(&(ver_len as u16).to_le_bytes());
    buf[13..13 + ver_len].copy_from_slice(version);
    Ok(total)
}

/// Parse the size field from the first 4 bytes of a 9P message.
pub fn parse_msg_size(buf: &[u8]) -> Result<u32> {
    if buf.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Parse the message type byte at offset 4.
pub fn parse_msg_type(buf: &[u8]) -> Result<u8> {
    if buf.len() < 5 {
        return Err(Error::InvalidArgument);
    }
    Ok(buf[4])
}
