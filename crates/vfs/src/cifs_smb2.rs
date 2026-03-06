// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMB2/3 protocol wire encoding and decoding.
//!
//! Implements the low-level SMB2/3 protocol layer used by the CIFS client:
//!
//! - [`Smb2Header`] — fixed 64-byte SMB2 protocol header
//! - [`Smb2Command`] — SMB2 command codes
//! - [`NegotiateRequest`] / [`NegotiateResponse`] — dialect negotiation
//! - [`SessionSetupRequest`] / [`SessionSetupResponse`] — session setup
//! - [`TreeConnectRequest`] / [`TreeConnectResponse`] — share connect
//! - [`CreateRequest`] / [`CreateResponse`] — file open/create
//! - [`ReadRequest`] / [`ReadResponse`] — file read
//! - [`WriteRequest`] / [`WriteResponse`] — file write
//! - [`CloseRequest`] — file close
//! - [`encode_header`] / [`decode_header`] — wire marshaling helpers
//!
//! # SMB2 Header Layout (64 bytes)
//!
//! ```text
//! [0..4]   Protocol ID (0xFE 'S' 'M' 'B')
//! [4..6]   Structure size (always 64)
//! [6..8]   Credit charge
//! [8..12]  Status / Channel sequence
//! [12..14] Command
//! [14..16] Credits requested/granted
//! [16..20] Flags
//! [20..24] Next command offset
//! [24..32] Message ID
//! [32..36] Process ID / Async ID
//! [36..40] Tree ID
//! [40..48] Session ID
//! [48..64] Signature (16 bytes)
//! ```
//!
//! # References
//!
//! - [MS-SMB2]: Server Message Block Protocol, version 2 and 3
//! - Linux `fs/smb/client/smb2pdu.h`, `smb2ops.c`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// SMB2 protocol ID (`\xFESMB` as u32 LE).
pub const SMB2_MAGIC: u32 = 0xFE53_4D42;

/// SMB2 header structure size (always 64).
pub const SMB2_HEADER_SIZE: usize = 64;

/// SMB2 protocol flags.
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;
pub const SMB2_FLAGS_RELATED_OPERATIONS: u32 = 0x0000_0004;
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
pub const SMB2_FLAGS_DFS_OPERATIONS: u32 = 0x1000_0000;

/// Maximum number of dialect values in a negotiate request.
pub const MAX_DIALECTS: usize = 8;

/// Maximum security buffer size for session setup.
pub const MAX_SEC_BUF: usize = 4096;

/// Maximum path length in tree connect.
pub const MAX_TREE_PATH: usize = 256;

/// SMB3.1.1 dialect value.
pub const SMB311_DIALECT: u16 = 0x0311;
/// SMB3.0.2 dialect value.
pub const SMB302_DIALECT: u16 = 0x0302;
/// SMB3.0 dialect value.
pub const SMB300_DIALECT: u16 = 0x0300;
/// SMB2.1 dialect value.
pub const SMB210_DIALECT: u16 = 0x0210;
/// SMB2.0.2 dialect value.
pub const SMB202_DIALECT: u16 = 0x0202;

// ── Command Codes ─────────────────────────────────────────────────────────────

/// SMB2 command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    /// SMB2 NEGOTIATE.
    Negotiate = 0x0000,
    /// SMB2 SESSION_SETUP.
    SessionSetup = 0x0001,
    /// SMB2 LOGOFF.
    Logoff = 0x0002,
    /// SMB2 TREE_CONNECT.
    TreeConnect = 0x0003,
    /// SMB2 TREE_DISCONNECT.
    TreeDisconnect = 0x0004,
    /// SMB2 CREATE.
    Create = 0x0005,
    /// SMB2 CLOSE.
    Close = 0x0006,
    /// SMB2 FLUSH.
    Flush = 0x0007,
    /// SMB2 READ.
    Read = 0x0008,
    /// SMB2 WRITE.
    Write = 0x0009,
    /// SMB2 LOCK.
    Lock = 0x000A,
    /// SMB2 IOCTL.
    Ioctl = 0x000B,
    /// SMB2 CANCEL.
    Cancel = 0x000C,
    /// SMB2 ECHO.
    Echo = 0x000D,
    /// SMB2 QUERY_DIRECTORY.
    QueryDirectory = 0x000E,
    /// SMB2 CHANGE_NOTIFY.
    ChangeNotify = 0x000F,
    /// SMB2 QUERY_INFO.
    QueryInfo = 0x0010,
    /// SMB2 SET_INFO.
    SetInfo = 0x0011,
    /// SMB2 OPLOCK_BREAK.
    OplockBreak = 0x0012,
}

impl Smb2Command {
    /// Construct from raw u16 value.
    pub fn from_raw(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(Self::Negotiate),
            0x0001 => Some(Self::SessionSetup),
            0x0002 => Some(Self::Logoff),
            0x0003 => Some(Self::TreeConnect),
            0x0004 => Some(Self::TreeDisconnect),
            0x0005 => Some(Self::Create),
            0x0006 => Some(Self::Close),
            0x0007 => Some(Self::Flush),
            0x0008 => Some(Self::Read),
            0x0009 => Some(Self::Write),
            0x000A => Some(Self::Lock),
            0x000B => Some(Self::Ioctl),
            0x000C => Some(Self::Cancel),
            0x000D => Some(Self::Echo),
            0x000E => Some(Self::QueryDirectory),
            0x000F => Some(Self::ChangeNotify),
            0x0010 => Some(Self::QueryInfo),
            0x0011 => Some(Self::SetInfo),
            0x0012 => Some(Self::OplockBreak),
            _ => None,
        }
    }
}

// ── SMB2 Header ───────────────────────────────────────────────────────────────

/// Parsed SMB2 protocol header (64 bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct Smb2Header {
    /// Credit charge.
    pub credit_charge: u16,
    /// Status or channel sequence.
    pub status: u32,
    /// Command code.
    pub command: u16,
    /// Credits requested / granted.
    pub credits: u16,
    /// Flags (SMB2_FLAGS_*).
    pub flags: u32,
    /// Byte offset of next command in compound chain (0 = last).
    pub next_command: u32,
    /// Unique message identifier.
    pub message_id: u64,
    /// Process ID (sync) or async ID high (async).
    pub process_id: u32,
    /// Tree ID (0 for pre-tree-connect commands).
    pub tree_id: u32,
    /// Session ID.
    pub session_id: u64,
    /// Request signature (16 bytes, zeroed if not signed).
    pub signature: [u8; 16],
}

/// Encode a [`Smb2Header`] into `dst[0..SMB2_HEADER_SIZE]`.
pub fn encode_header(hdr: &Smb2Header, dst: &mut [u8]) -> Result<()> {
    if dst.len() < SMB2_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    dst[0..4].copy_from_slice(&SMB2_MAGIC.to_le_bytes());
    dst[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
    dst[6..8].copy_from_slice(&hdr.credit_charge.to_le_bytes());
    dst[8..12].copy_from_slice(&hdr.status.to_le_bytes());
    dst[12..14].copy_from_slice(&hdr.command.to_le_bytes());
    dst[14..16].copy_from_slice(&hdr.credits.to_le_bytes());
    dst[16..20].copy_from_slice(&hdr.flags.to_le_bytes());
    dst[20..24].copy_from_slice(&hdr.next_command.to_le_bytes());
    dst[24..32].copy_from_slice(&hdr.message_id.to_le_bytes());
    dst[32..36].copy_from_slice(&hdr.process_id.to_le_bytes());
    dst[36..40].copy_from_slice(&hdr.tree_id.to_le_bytes());
    dst[40..48].copy_from_slice(&hdr.session_id.to_le_bytes());
    dst[48..64].copy_from_slice(&hdr.signature);
    Ok(())
}

/// Decode a [`Smb2Header`] from `src[0..SMB2_HEADER_SIZE]`.
pub fn decode_header(src: &[u8]) -> Result<Smb2Header> {
    if src.len() < SMB2_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let magic = u32::from_le_bytes(src[0..4].try_into().map_err(|_| Error::InvalidArgument)?);
    if magic != SMB2_MAGIC {
        return Err(Error::InvalidArgument);
    }
    let status = u32::from_le_bytes(src[8..12].try_into().map_err(|_| Error::InvalidArgument)?);
    let command = u16::from_le_bytes(src[12..14].try_into().map_err(|_| Error::InvalidArgument)?);
    let credits = u16::from_le_bytes(src[14..16].try_into().map_err(|_| Error::InvalidArgument)?);
    let flags = u32::from_le_bytes(src[16..20].try_into().map_err(|_| Error::InvalidArgument)?);
    let next_command =
        u32::from_le_bytes(src[20..24].try_into().map_err(|_| Error::InvalidArgument)?);
    let message_id =
        u64::from_le_bytes(src[24..32].try_into().map_err(|_| Error::InvalidArgument)?);
    let process_id =
        u32::from_le_bytes(src[32..36].try_into().map_err(|_| Error::InvalidArgument)?);
    let tree_id = u32::from_le_bytes(src[36..40].try_into().map_err(|_| Error::InvalidArgument)?);
    let session_id =
        u64::from_le_bytes(src[40..48].try_into().map_err(|_| Error::InvalidArgument)?);
    let mut signature = [0u8; 16];
    signature.copy_from_slice(&src[48..64]);
    Ok(Smb2Header {
        credit_charge: u16::from_le_bytes(
            src[6..8].try_into().map_err(|_| Error::InvalidArgument)?,
        ),
        status,
        command,
        credits,
        flags,
        next_command,
        message_id,
        process_id,
        tree_id,
        session_id,
        signature,
    })
}

// ── Negotiate ─────────────────────────────────────────────────────────────────

/// SMB2 NEGOTIATE request parameters.
#[derive(Debug, Clone)]
pub struct NegotiateRequest {
    /// Number of dialect values.
    pub dialect_count: u16,
    /// Security mode.
    pub security_mode: u16,
    /// Client capabilities.
    pub capabilities: u32,
    /// Client GUID (16 bytes).
    pub client_guid: [u8; 16],
    /// Dialect values.
    pub dialects: [u16; MAX_DIALECTS],
}

impl NegotiateRequest {
    /// Encode into `buf` (starting after the 64-byte SMB2 header).
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let size = 36 + self.dialect_count as usize * 2;
        if buf.len() < size {
            return Err(Error::InvalidArgument);
        }
        buf[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
        buf[2..4].copy_from_slice(&self.dialect_count.to_le_bytes());
        buf[4..6].copy_from_slice(&self.security_mode.to_le_bytes());
        buf[6..8].fill(0); // Reserved
        buf[8..12].copy_from_slice(&self.capabilities.to_le_bytes());
        buf[12..28].copy_from_slice(&self.client_guid);
        buf[28..36].fill(0); // ClientStartTime or NegotiateContextOffset
        for i in 0..self.dialect_count as usize {
            if i >= MAX_DIALECTS {
                break;
            }
            buf[36 + i * 2..36 + i * 2 + 2].copy_from_slice(&self.dialects[i].to_le_bytes());
        }
        Ok(size)
    }
}

/// SMB2 NEGOTIATE response parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct NegotiateResponse {
    /// Negotiated dialect.
    pub dialect_revision: u16,
    /// Server security mode.
    pub security_mode: u16,
    /// Server capabilities.
    pub capabilities: u32,
    /// Max transact / read / write sizes.
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    /// Server system time.
    pub system_time: u64,
    /// Server start time.
    pub server_start_time: u64,
}

impl NegotiateResponse {
    /// Parse from wire bytes (after SMB2 header).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 64 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            dialect_revision: u16::from_le_bytes(
                buf[4..6].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            security_mode: u16::from_le_bytes(
                buf[2..4].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            capabilities: u32::from_le_bytes(
                buf[12..16].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            max_transact_size: u32::from_le_bytes(
                buf[20..24].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            max_read_size: u32::from_le_bytes(
                buf[24..28].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            max_write_size: u32::from_le_bytes(
                buf[28..32].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            system_time: u64::from_le_bytes(
                buf[40..48].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            server_start_time: u64::from_le_bytes(
                buf[48..56].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
        })
    }
}

// ── Create / Close ─────────────────────────────────────────────────────────────

/// SMB2 CREATE request (open or create a file).
#[derive(Debug, Clone, Copy, Default)]
pub struct CreateRequest {
    /// Desired access (FILE_READ_DATA, etc.).
    pub desired_access: u32,
    /// File attributes.
    pub file_attributes: u32,
    /// Share access (FILE_SHARE_READ, etc.).
    pub share_access: u32,
    /// Create disposition (FILE_OPEN, FILE_CREATE, etc.).
    pub create_disposition: u32,
    /// Create options.
    pub create_options: u32,
}

/// SMB2 CREATE response — contains the allocated SMB2 file ID.
#[derive(Debug, Clone, Copy, Default)]
pub struct CreateResponse {
    /// Oplock level granted.
    pub oplock_level: u8,
    /// Create action (1 = opened, 2 = created, 3 = overwritten).
    pub create_action: u32,
    /// File size.
    pub end_of_file: u64,
    /// File attributes.
    pub file_attributes: u32,
    /// Volatile file ID (lower 8 bytes of SMB2 FileId).
    pub file_id_volatile: u64,
    /// Persistent file ID (upper 8 bytes of SMB2 FileId).
    pub file_id_persistent: u64,
}

impl CreateResponse {
    /// Parse from wire bytes (after SMB2 header).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 88 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            oplock_level: buf[2],
            create_action: u32::from_le_bytes(
                buf[4..8].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            end_of_file: u64::from_le_bytes(
                buf[56..64].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            file_attributes: u32::from_le_bytes(
                buf[64..68].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            file_id_persistent: u64::from_le_bytes(
                buf[72..80].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            file_id_volatile: u64::from_le_bytes(
                buf[80..88].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
        })
    }
}

// ── Read / Write ──────────────────────────────────────────────────────────────

/// SMB2 READ request parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadRequest {
    /// Number of bytes to read.
    pub length: u32,
    /// File offset to read from.
    pub offset: u64,
    /// File ID (volatile).
    pub file_id_volatile: u64,
    /// File ID (persistent).
    pub file_id_persistent: u64,
    /// Minimum bytes to return.
    pub minimum_count: u32,
}

/// SMB2 WRITE request parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteRequest {
    /// File offset to write at.
    pub offset: u64,
    /// File ID (volatile).
    pub file_id_volatile: u64,
    /// File ID (persistent).
    pub file_id_persistent: u64,
    /// Bytes written (response field; 0 in request).
    pub count: u32,
}

/// SMB2 WRITE response.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteResponse {
    /// Number of bytes written.
    pub count: u32,
    /// Remaining bytes (for channel writes).
    pub remaining: u32,
}

impl WriteResponse {
    /// Parse from wire bytes (after SMB2 header).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            count: u32::from_le_bytes(buf[4..8].try_into().map_err(|_| Error::InvalidArgument)?),
            remaining: u32::from_le_bytes(
                buf[8..12].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
        })
    }
}

// ── Message Builder ───────────────────────────────────────────────────────────

/// Builder for constructing SMB2 messages.
pub struct Smb2MessageBuilder {
    /// Pre-allocated buffer.
    buf: [u8; 65536],
    /// Current write position.
    pos: usize,
    /// Current message ID.
    pub message_id: u64,
}

impl Smb2MessageBuilder {
    /// Create a new message builder.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; 65536],
            pos: 0,
            message_id: 1,
        }
    }

    /// Begin a new SMB2 message with the given header fields.
    pub fn begin(&mut self, hdr: &Smb2Header) -> Result<()> {
        self.pos = 0;
        encode_header(hdr, &mut self.buf[0..SMB2_HEADER_SIZE])?;
        self.pos = SMB2_HEADER_SIZE;
        Ok(())
    }

    /// Append bytes to the current message body.
    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        let end = self.pos + data.len();
        if end > self.buf.len() {
            return Err(Error::OutOfMemory);
        }
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    /// Return the complete message as a byte slice.
    pub fn message(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Increment and return the next message ID.
    pub fn next_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }
}

impl Default for Smb2MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}
