// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE low-level kernel interface for the ONCRIX VFS.
//!
//! Implements the kernel side of the FUSE (Filesystem in Userspace) low-level
//! ABI. The kernel module communicates with the user-space FUSE daemon via a
//! `/dev/fuse` device; this module handles message framing, opcode dispatch,
//! and reply serialization.

use oncrix_lib::{Error, Result};

/// FUSE kernel ABI version (major).
pub const FUSE_KERNEL_VERSION: u32 = 7;
/// FUSE kernel ABI version (minor) — matches Linux 6.x baseline.
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 39;

/// Maximum number of concurrent outstanding FUSE requests.
pub const FUSE_MAX_INFLIGHT: usize = 64;

/// Size of the FUSE request/reply header in bytes.
pub const FUSE_HEADER_SIZE: usize = 40;

/// FUSE opcode identifiers for kernel→daemon messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseOpcode {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Setxattr = 21,
    Getxattr = 22,
    Listxattr = 23,
    Removexattr = 24,
    Flush = 25,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Fsyncdir = 30,
    Getlk = 31,
    Setlk = 32,
    Access = 34,
    Create = 35,
    Interrupt = 36,
    Bmap = 37,
    Destroy = 38,
    Ioctl = 39,
    Poll = 40,
    BatchForget = 42,
    Fallocate = 43,
    Readdirplus = 44,
    Rename2 = 45,
    Lseek = 46,
    CopyFileRange = 47,
    Setupmapping = 48,
    Removemapping = 49,
}

impl FuseOpcode {
    /// Attempt to convert a raw u32 to a `FuseOpcode`.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            1 => Ok(Self::Lookup),
            2 => Ok(Self::Forget),
            3 => Ok(Self::Getattr),
            4 => Ok(Self::Setattr),
            5 => Ok(Self::Readlink),
            6 => Ok(Self::Symlink),
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
            34 => Ok(Self::Access),
            35 => Ok(Self::Create),
            36 => Ok(Self::Interrupt),
            38 => Ok(Self::Destroy),
            43 => Ok(Self::Fallocate),
            44 => Ok(Self::Readdirplus),
            45 => Ok(Self::Rename2),
            46 => Ok(Self::Lseek),
            47 => Ok(Self::CopyFileRange),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// FUSE request header (kernel→daemon).
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseInHeader {
    /// Total size of the message including this header.
    pub len: u32,
    /// Operation opcode.
    pub opcode: u32,
    /// Unique request ID.
    pub unique: u64,
    /// Inode number of the target file.
    pub nodeid: u64,
    /// User ID of the requesting process.
    pub uid: u32,
    /// Group ID of the requesting process.
    pub gid: u32,
    /// PID of the requesting process.
    pub pid: u32,
    /// Padding.
    pub padding: u32,
}

impl FuseInHeader {
    /// Decode a `FuseInHeader` from the first 40 bytes of a buffer.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < FUSE_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            len: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            opcode: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            unique: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            nodeid: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            uid: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
            gid: u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            pid: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
            padding: u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        })
    }
}

/// FUSE reply header (daemon→kernel).
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseOutHeader {
    /// Total size of the reply including this header.
    pub len: u32,
    /// Negative errno on error, 0 on success.
    pub error: i32,
    /// Must match the `unique` field of the corresponding request.
    pub unique: u64,
}

impl FuseOutHeader {
    /// Encode this header into the first 16 bytes of `buf`.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        buf[0..4].copy_from_slice(&self.len.to_le_bytes());
        buf[4..8].copy_from_slice(&self.error.to_le_bytes());
        buf[8..16].copy_from_slice(&self.unique.to_le_bytes());
        Ok(())
    }
}

/// Tracks an in-flight FUSE request awaiting a daemon reply.
#[derive(Debug, Clone, Copy)]
pub struct FuseRequest {
    /// Unique ID of this request.
    pub unique: u64,
    /// Opcode for this request.
    pub opcode: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl FuseRequest {
    /// Construct a new (inactive) request slot.
    pub const fn new() -> Self {
        Self {
            unique: 0,
            opcode: 0,
            active: false,
        }
    }
}

impl Default for FuseRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Queue of in-flight FUSE requests.
pub struct FuseRequestQueue {
    slots: [FuseRequest; FUSE_MAX_INFLIGHT],
    next_unique: u64,
}

impl FuseRequestQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            slots: [const { FuseRequest::new() }; FUSE_MAX_INFLIGHT],
            next_unique: 1,
        }
    }

    /// Enqueue a new request, returning its unique ID or `Busy` if full.
    pub fn enqueue(&mut self, opcode: u32) -> Result<u64> {
        for slot in self.slots.iter_mut() {
            if !slot.active {
                let unique = self.next_unique;
                self.next_unique = self.next_unique.wrapping_add(1);
                slot.unique = unique;
                slot.opcode = opcode;
                slot.active = true;
                return Ok(unique);
            }
        }
        Err(Error::Busy)
    }

    /// Complete a request by unique ID, returning its opcode.
    pub fn complete(&mut self, unique: u64) -> Result<u32> {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.unique == unique {
                let opcode = slot.opcode;
                *slot = FuseRequest::new();
                return Ok(opcode);
            }
        }
        Err(Error::NotFound)
    }

    /// Abort all in-flight requests (e.g., on daemon disconnect).
    pub fn abort_all(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = FuseRequest::new();
        }
    }

    /// Return the number of active in-flight requests.
    pub fn inflight_count(&self) -> usize {
        self.slots.iter().filter(|s| s.active).count()
    }
}

impl Default for FuseRequestQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a minimal FUSE `Rinit` reply body into `buf`.
///
/// Returns bytes written (36 bytes for the init reply body).
pub fn build_init_reply(buf: &mut [u8], max_write: u32, flags: u32) -> Result<usize> {
    // FUSE init reply body: major[4] minor[4] max_readahead[4] flags[4]
    // max_background[2] congestion_threshold[2] max_write[4] ...
    const INIT_BODY_LEN: usize = 36;
    if buf.len() < INIT_BODY_LEN {
        return Err(Error::InvalidArgument);
    }
    buf[0..4].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
    buf[4..8].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
    // max_readahead
    buf[8..12].copy_from_slice(&65536u32.to_le_bytes());
    buf[12..16].copy_from_slice(&flags.to_le_bytes());
    // max_background
    buf[16..18].copy_from_slice(&(FUSE_MAX_INFLIGHT as u16).to_le_bytes());
    // congestion_threshold
    buf[18..20].copy_from_slice(&(FUSE_MAX_INFLIGHT as u16 / 2).to_le_bytes());
    buf[20..24].copy_from_slice(&max_write.to_le_bytes());
    // Remaining fields zeroed
    for b in &mut buf[24..INIT_BODY_LEN] {
        *b = 0;
    }
    Ok(INIT_BODY_LEN)
}
