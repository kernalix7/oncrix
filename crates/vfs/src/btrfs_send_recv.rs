// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs send/receive operations.
//!
//! The Btrfs send/receive interface allows efficient snapshot replication.
//! A send stream encodes all changes needed to reproduce a snapshot from
//! a known base.  The receiver replays those commands to reconstruct the
//! exact filesystem state.
//!
//! # Send stream structure
//!
//! ```text
//! [stream_header] [cmd]* [end_cmd]
//! ```
//!
//! Each command carries a type tag, a CRC32 checksum, and a variable-length
//! list of typed TLV attributes.
//!
//! # References
//!
//! - Linux `fs/btrfs/send.c`, `fs/btrfs/send.h`
//! - Btrfs send-stream format v1 / v2

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every Btrfs send stream.
pub const BTRFS_SEND_MAGIC: &[u8; 13] = b"btrfs-stream\0";

/// Send-stream format version supported by this implementation.
pub const BTRFS_SEND_VERSION: u32 = 1;

/// Maximum number of commands in the internal command buffer.
pub const MAX_SEND_COMMANDS: usize = 256;

/// Maximum path length in a send command attribute.
pub const MAX_SEND_PATH: usize = 256;

/// Maximum inline data payload per write command (bytes).
pub const MAX_SEND_WRITE_LEN: usize = 4096;

// ── SendCmd ───────────────────────────────────────────────────────────────────

/// Btrfs send-stream command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SendCmd {
    /// Unspecified / invalid command.
    Unspec = 0,
    /// Create a regular file.
    Mkfile = 1,
    /// Create a directory.
    Mkdir = 2,
    /// Create a symbolic link.
    Symlink = 6,
    /// Rename a path.
    Rename = 10,
    /// Hard-link a path.
    Link = 11,
    /// Unlink (remove) a file.
    Unlink = 12,
    /// Remove a directory.
    Rmdir = 13,
    /// Write data to a file range.
    Write = 16,
    /// Clone a file extent from another file.
    Clone = 17,
    /// Set an extended attribute.
    SetXattr = 23,
    /// Remove an extended attribute.
    RemoveXattr = 24,
    /// Truncate a file to a given size.
    Truncate = 25,
    /// Change file permissions (chmod).
    Chmod = 26,
    /// Change file ownership (chown).
    Chown = 27,
    /// Update file timestamps (utimes).
    Utimes = 28,
    /// End of the send stream.
    End = 29,
}

// ── SendAttrKey ───────────────────────────────────────────────────────────────

/// TLV attribute keys carried within a send command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SendAttrKey {
    /// Destination path (NUL-terminated string).
    Path = 1,
    /// Source path for clone/rename/link.
    PathTo = 2,
    /// Byte offset in the file.
    FileOffset = 4,
    /// Inline data payload.
    Data = 5,
    /// Inode number.
    Ino = 6,
    /// File size in bytes.
    Size = 7,
    /// File mode/permissions.
    Mode = 8,
    /// Owner UID.
    Uid = 9,
    /// Owner GID.
    Gid = 10,
    /// Extended attribute name.
    XattrName = 23,
    /// Extended attribute value.
    XattrData = 24,
}

// ── SendAttr ──────────────────────────────────────────────────────────────────

/// A single TLV attribute within a send command.
#[derive(Clone, Copy)]
pub struct SendAttr {
    /// Attribute key.
    pub key: SendAttrKey,
    /// Raw attribute value (up to 256 bytes; length tracked separately).
    pub value: [u8; 256],
    /// Number of meaningful bytes in `value`.
    pub value_len: usize,
}

impl core::fmt::Debug for SendAttr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendAttr")
            .field("key", &self.key)
            .field("value_len", &self.value_len)
            .finish()
    }
}

impl SendAttr {
    /// Create a `u64` attribute.
    pub fn from_u64(key: SendAttrKey, val: u64) -> Self {
        let mut value = [0u8; 256];
        value[..8].copy_from_slice(&val.to_le_bytes());
        Self {
            key,
            value,
            value_len: 8,
        }
    }

    /// Create a path-string attribute (truncated to `MAX_SEND_PATH`).
    pub fn from_path(key: SendAttrKey, path: &[u8]) -> Self {
        let len = path.len().min(255);
        let mut value = [0u8; 256];
        value[..len].copy_from_slice(&path[..len]);
        Self {
            key,
            value,
            value_len: len,
        }
    }

    /// Decode this attribute as a little-endian `u64`.
    pub fn as_u64(&self) -> Result<u64> {
        if self.value_len < 8 {
            return Err(Error::InvalidArgument);
        }
        let bytes: [u8; 8] = self.value[..8]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

// ── SendCommand ───────────────────────────────────────────────────────────────

/// A fully-parsed Btrfs send command with its attributes.
#[derive(Debug)]
pub struct SendCommand {
    /// Command type.
    pub cmd: SendCmd,
    /// CRC32 checksum of the serialized command (0 = not set).
    pub crc: u32,
    /// Attribute list.
    pub attrs: [SendAttr; 8],
    /// Number of populated attributes.
    pub attr_count: usize,
}

impl SendCommand {
    /// Create an empty command of the given type.
    pub const fn new(cmd: SendCmd) -> Self {
        Self {
            cmd,
            crc: 0,
            attrs: [const {
                SendAttr {
                    key: SendAttrKey::Path,
                    value: [0u8; 256],
                    value_len: 0,
                }
            }; 8],
            attr_count: 0,
        }
    }

    /// Append an attribute to this command.  Returns `OutOfMemory` if full.
    pub fn push_attr(&mut self, attr: SendAttr) -> Result<()> {
        if self.attr_count >= 8 {
            return Err(Error::OutOfMemory);
        }
        self.attrs[self.attr_count] = attr;
        self.attr_count += 1;
        Ok(())
    }

    /// Find an attribute by key, returning the first match.
    pub fn find_attr(&self, key: SendAttrKey) -> Option<&SendAttr> {
        self.attrs[..self.attr_count].iter().find(|a| a.key == key)
    }
}

// ── SendStream ────────────────────────────────────────────────────────────────

/// Btrfs send stream — accumulates commands before serialization.
pub struct SendStream {
    /// Buffered commands.
    commands: [SendCommand; MAX_SEND_COMMANDS],
    /// Number of commands written so far.
    count: usize,
    /// Generation number of the source snapshot.
    pub generation: u64,
}

impl SendStream {
    /// Create a new send stream for the given snapshot generation.
    pub const fn new(generation: u64) -> Self {
        Self {
            commands: [const { SendCommand::new(SendCmd::Unspec) }; MAX_SEND_COMMANDS],
            count: 0,
            generation,
        }
    }

    /// Append a command to the stream.  Returns `OutOfMemory` if the
    /// internal buffer is full.
    pub fn emit(&mut self, cmd: SendCommand) -> Result<()> {
        if self.count >= MAX_SEND_COMMANDS {
            return Err(Error::OutOfMemory);
        }
        self.commands[self.count] = cmd;
        self.count += 1;
        Ok(())
    }

    /// Emit a `write` command for a data range.
    pub fn emit_write(&mut self, path: &[u8], offset: u64, data: &[u8]) -> Result<()> {
        let mut cmd = SendCommand::new(SendCmd::Write);
        cmd.push_attr(SendAttr::from_path(SendAttrKey::Path, path))?;
        cmd.push_attr(SendAttr::from_u64(SendAttrKey::FileOffset, offset))?;
        let data_len = data.len().min(MAX_SEND_WRITE_LEN).min(255);
        let mut payload = SendAttr::from_path(SendAttrKey::Data, &data[..data_len]);
        payload.key = SendAttrKey::Data;
        cmd.push_attr(payload)?;
        self.emit(cmd)
    }

    /// Emit a `clone` command referencing another file extent.
    pub fn emit_clone(
        &mut self,
        dst_path: &[u8],
        dst_offset: u64,
        src_path: &[u8],
        src_offset: u64,
        len: u64,
    ) -> Result<()> {
        let mut cmd = SendCommand::new(SendCmd::Clone);
        cmd.push_attr(SendAttr::from_path(SendAttrKey::Path, dst_path))?;
        cmd.push_attr(SendAttr::from_u64(SendAttrKey::FileOffset, dst_offset))?;
        cmd.push_attr(SendAttr::from_path(SendAttrKey::PathTo, src_path))?;
        cmd.push_attr(SendAttr::from_u64(SendAttrKey::Size, len))?;
        cmd.push_attr(SendAttr::from_u64(SendAttrKey::FileOffset, src_offset))?;
        self.emit(cmd)
    }

    /// Finalize the stream with an `End` command.
    pub fn finalize(&mut self) -> Result<()> {
        self.emit(SendCommand::new(SendCmd::End))
    }

    /// Return a slice of all buffered commands.
    pub fn commands(&self) -> &[SendCommand] {
        &self.commands[..self.count]
    }
}

// ── Receiver ──────────────────────────────────────────────────────────────────

/// Statistics collected while replaying a send stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecvStats {
    /// Total commands processed.
    pub commands_processed: u32,
    /// Total bytes of file data written.
    pub bytes_written: u64,
    /// Number of clone operations replayed.
    pub clones: u32,
}

/// Replay a Btrfs send stream, applying each command to the target.
///
/// In a full implementation this drives actual VFS operations.  Here it
/// validates commands and accumulates statistics.
pub fn btrfs_recv_stream(stream: &SendStream) -> Result<RecvStats> {
    let mut stats = RecvStats::default();

    for cmd in stream.commands() {
        match cmd.cmd {
            SendCmd::Unspec => return Err(Error::InvalidArgument),
            SendCmd::End => break,
            SendCmd::Write => {
                if let Some(data_attr) = cmd.find_attr(SendAttrKey::Data) {
                    stats.bytes_written += data_attr.value_len as u64;
                }
                stats.commands_processed += 1;
            }
            SendCmd::Clone => {
                stats.clones += 1;
                stats.commands_processed += 1;
            }
            _ => {
                stats.commands_processed += 1;
            }
        }
    }

    Ok(stats)
}
