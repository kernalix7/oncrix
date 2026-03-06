// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS XDR (External Data Representation) encoding/decoding.
//!
//! NFS v2/v3 use Sun XDR for all on-wire data.  This module provides a
//! minimal XDR writer and reader suitable for encoding NFS RPC arguments
//! and decoding NFS RPC results in a `no_std` environment.

use oncrix_lib::{Error, Result};

/// XDR writer — appends big-endian encoded values to a mutable buffer.
pub struct XdrWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> XdrWriter<'a> {
    /// Create a new writer over `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes written so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Remaining capacity.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Encode a 32-bit unsigned integer.
    pub fn write_u32(&mut self, v: u32) -> Result<()> {
        if self.remaining() < 4 {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_be_bytes());
        self.pos += 4;
        Ok(())
    }

    /// Encode a 64-bit unsigned integer.
    pub fn write_u64(&mut self, v: u64) -> Result<()> {
        if self.remaining() < 8 {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_be_bytes());
        self.pos += 8;
        Ok(())
    }

    /// Encode a 32-bit signed integer.
    pub fn write_i32(&mut self, v: i32) -> Result<()> {
        self.write_u32(v as u32)
    }

    /// Encode a 64-bit signed integer.
    pub fn write_i64(&mut self, v: i64) -> Result<()> {
        self.write_u64(v as u64)
    }

    /// Encode an XDR boolean (true = 1, false = 0).
    pub fn write_bool(&mut self, v: bool) -> Result<()> {
        self.write_u32(if v { 1 } else { 0 })
    }

    /// Encode a fixed-length opaque byte array (no length prefix; no padding).
    pub fn write_opaque_fixed(&mut self, data: &[u8]) -> Result<()> {
        if self.remaining() < data.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        // XDR pads to 4-byte boundary.
        let pad = (4 - data.len() % 4) % 4;
        if self.remaining() < pad {
            return Err(Error::InvalidArgument);
        }
        for i in 0..pad {
            self.buf[self.pos + i] = 0;
        }
        self.pos += pad;
        Ok(())
    }

    /// Encode a variable-length opaque byte array (4-byte length prefix + data + pad).
    pub fn write_opaque(&mut self, data: &[u8]) -> Result<()> {
        self.write_u32(data.len() as u32)?;
        self.write_opaque_fixed(data)
    }

    /// Encode a string as an XDR opaque (length + bytes + padding).
    pub fn write_string(&mut self, s: &[u8]) -> Result<()> {
        self.write_opaque(s)
    }
}

/// XDR reader — decodes big-endian XDR from a byte buffer.
pub struct XdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    /// Create a new reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Remaining bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Decode a 32-bit unsigned integer.
    pub fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(Error::InvalidArgument);
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Decode a 64-bit unsigned integer.
    pub fn read_u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(Error::InvalidArgument);
        }
        let v = u64::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
            self.buf[self.pos + 4],
            self.buf[self.pos + 5],
            self.buf[self.pos + 6],
            self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// Decode a 32-bit signed integer.
    pub fn read_i32(&mut self) -> Result<i32> {
        self.read_u32().map(|v| v as i32)
    }

    /// Decode a 64-bit signed integer.
    pub fn read_i64(&mut self) -> Result<i64> {
        self.read_u64().map(|v| v as i64)
    }

    /// Decode an XDR boolean.
    pub fn read_bool(&mut self) -> Result<bool> {
        match self.read_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Decode a fixed-length opaque blob of `len` bytes.
    ///
    /// Returns a slice into the original buffer and advances past the
    /// 4-byte-aligned data.
    pub fn read_opaque_fixed(&mut self, len: usize) -> Result<&'a [u8]> {
        let pad = (4 - len % 4) % 4;
        let total = len + pad;
        if self.remaining() < total {
            return Err(Error::InvalidArgument);
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += total;
        Ok(slice)
    }

    /// Decode a variable-length opaque blob.
    pub fn read_opaque(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_opaque_fixed(len)
    }

    /// Decode an XDR string.
    pub fn read_string(&mut self) -> Result<&'a [u8]> {
        self.read_opaque()
    }
}

/// NFS3 `fattr3` structure (file attributes).
#[derive(Debug, Clone, Copy, Default)]
pub struct Nfs3Fattr {
    pub ftype: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub fsid: u64,
    pub fileid: u64,
    pub atime_sec: u32,
    pub atime_nsec: u32,
    pub mtime_sec: u32,
    pub mtime_nsec: u32,
    pub ctime_sec: u32,
    pub ctime_nsec: u32,
}

impl Nfs3Fattr {
    /// Encode into an XDR writer.
    pub fn encode(&self, w: &mut XdrWriter<'_>) -> Result<()> {
        w.write_u32(self.ftype)?;
        w.write_u32(self.mode)?;
        w.write_u32(self.nlink)?;
        w.write_u32(self.uid)?;
        w.write_u32(self.gid)?;
        w.write_u64(self.size)?;
        w.write_u64(self.used)?;
        w.write_u32(self.rdev_major)?;
        w.write_u32(self.rdev_minor)?;
        w.write_u64(self.fsid)?;
        w.write_u64(self.fileid)?;
        w.write_u32(self.atime_sec)?;
        w.write_u32(self.atime_nsec)?;
        w.write_u32(self.mtime_sec)?;
        w.write_u32(self.mtime_nsec)?;
        w.write_u32(self.ctime_sec)?;
        w.write_u32(self.ctime_nsec)
    }

    /// Decode from an XDR reader.
    pub fn decode(r: &mut XdrReader<'_>) -> Result<Self> {
        Ok(Self {
            ftype: r.read_u32()?,
            mode: r.read_u32()?,
            nlink: r.read_u32()?,
            uid: r.read_u32()?,
            gid: r.read_u32()?,
            size: r.read_u64()?,
            used: r.read_u64()?,
            rdev_major: r.read_u32()?,
            rdev_minor: r.read_u32()?,
            fsid: r.read_u64()?,
            fileid: r.read_u64()?,
            atime_sec: r.read_u32()?,
            atime_nsec: r.read_u32()?,
            mtime_sec: r.read_u32()?,
            mtime_nsec: r.read_u32()?,
            ctime_sec: r.read_u32()?,
            ctime_nsec: r.read_u32()?,
        })
    }
}
