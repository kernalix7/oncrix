// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS read/write I/O operations.
//!
//! Implements the NFS READ and WRITE RPC procedures plus the supporting
//! infrastructure for I/O buffering, data-server selection, and the
//! commit protocol required by NFS v3/v4 stable-writes.
//!
//! # Architecture
//!
//! ```text
//! VFS read_page / write_page
//!   → NfsIoEngine::read() / write()
//!     → NfsDataServer::select_for_read() / select_for_write()
//!       → NfsIoBuf: encode READ/WRITE args → [XDR bytes]
//!         → send to server (via transport shim)
//!           → NfsIoBuf: decode READ/WRITE result
//!             → NfsWriteback: track unstable writes
//!               → NfsIoEngine::commit() when dirty pages flushed
//! ```
//!
//! # pNFS Layout Interface
//!
//! When a pNFS layout is granted by the server the engine selects a
//! [`DataServer`] from the layout instead of the MDS.  The layout cache
//! is managed by [`LayoutCache`].
//!
//! # Structures
//!
//! - [`NfsStability`]   — UNSTABLE / DATA_SYNC / FILE_SYNC write modes
//! - [`NfsFileHandle`]  — 64-byte opaque file handle
//! - [`NfsReadArgs`]    — READ procedure arguments
//! - [`NfsReadResult`]  — READ procedure result
//! - [`NfsWriteArgs`]   — WRITE procedure arguments
//! - [`NfsWriteResult`] — WRITE procedure result
//! - [`NfsIoBuf`]       — I/O buffer with encode/decode helpers
//! - [`NfsWriteback`]   — dirty write tracking for commit
//! - [`DataServer`]     — pNFS data server descriptor
//! - [`LayoutCache`]    — pNFS layout cache (8 entries)
//! - [`NfsIoEngine`]    — top-level NFS I/O state machine

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────────────

/// NFS file handle size (64 bytes, NFS v4 limit).
const NFS_FH_SIZE: usize = 64;

/// Maximum I/O size per READ/WRITE RPC (1 MiB).
const MAX_IO_SIZE: usize = 1024 * 1024;

/// Maximum pending writeback entries.
const MAX_WRITEBACK: usize = 256;

/// Maximum pNFS data servers per layout.
const MAX_DATA_SERVERS: usize = 8;

/// Maximum layout cache entries.
const MAX_LAYOUTS: usize = 8;

/// NFS READ procedure number (v3).
pub const NFSPROC3_READ: u32 = 6;

/// NFS WRITE procedure number (v3).
pub const NFSPROC3_WRITE: u32 = 7;

/// NFS COMMIT procedure number (v3).
pub const NFSPROC3_COMMIT: u32 = 21;

// ── NfsStability ─────────────────────────────────────────────────────────────

/// Write stability level requested by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum NfsStability {
    /// Server may cache write in volatile storage.
    Unstable = 0,
    /// Server must commit data to stable storage before replying.
    DataSync = 1,
    /// Server must commit data and metadata to stable storage.
    FileSync = 2,
}

// ── NfsFileHandle ────────────────────────────────────────────────────────────

/// An opaque NFS file handle (up to 64 bytes on NFS v4).
#[derive(Debug, Clone, Copy)]
pub struct NfsFileHandle {
    /// Handle bytes.
    pub data: [u8; NFS_FH_SIZE],
    /// Number of valid bytes.
    pub len: usize,
}

impl NfsFileHandle {
    /// Create an empty file handle.
    pub const fn empty() -> Self {
        Self {
            data: [0u8; NFS_FH_SIZE],
            len: 0,
        }
    }

    /// Create a file handle from a slice.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `src.len() > NFS_FH_SIZE`.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() > NFS_FH_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut fh = Self::empty();
        fh.data[..src.len()].copy_from_slice(src);
        fh.len = src.len();
        Ok(fh)
    }

    /// Return the handle as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ── NfsReadArgs ──────────────────────────────────────────────────────────────

/// Arguments for an NFS READ RPC call.
#[derive(Debug, Clone, Copy)]
pub struct NfsReadArgs {
    /// File handle of the target file.
    pub fh: NfsFileHandle,
    /// Byte offset to start reading from.
    pub offset: u64,
    /// Number of bytes to read.
    pub count: u32,
}

impl NfsReadArgs {
    /// Construct read arguments.
    pub const fn new(fh: NfsFileHandle, offset: u64, count: u32) -> Self {
        Self { fh, offset, count }
    }
}

// ── NfsReadResult ────────────────────────────────────────────────────────────

/// Result of an NFS READ RPC call.
#[derive(Debug)]
pub struct NfsReadResult {
    /// Number of bytes actually read.
    pub count: u32,
    /// Whether EOF was reached.
    pub eof: bool,
    /// Data returned by the server.
    pub data: [u8; MAX_IO_SIZE],
    /// Valid bytes in `data`.
    pub data_len: usize,
}

impl NfsReadResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            count: 0,
            eof: false,
            data: [0u8; MAX_IO_SIZE],
            data_len: 0,
        }
    }
}

// ── NfsWriteArgs ─────────────────────────────────────────────────────────────

/// Arguments for an NFS WRITE RPC call.
#[derive(Debug)]
pub struct NfsWriteArgs {
    /// File handle of the target file.
    pub fh: NfsFileHandle,
    /// Byte offset to start writing at.
    pub offset: u64,
    /// Number of bytes to write.
    pub count: u32,
    /// Write stability requested.
    pub stability: NfsStability,
    /// Data to write.
    pub data: [u8; MAX_IO_SIZE],
    /// Valid bytes in `data`.
    pub data_len: usize,
}

impl NfsWriteArgs {
    /// Create empty write arguments.
    pub fn empty() -> Self {
        Self {
            fh: NfsFileHandle::empty(),
            offset: 0,
            count: 0,
            stability: NfsStability::Unstable,
            data: [0u8; MAX_IO_SIZE],
            data_len: 0,
        }
    }

    /// Build write arguments from a slice.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `data.len() > MAX_IO_SIZE`.
    pub fn from_slice(
        fh: NfsFileHandle,
        offset: u64,
        stability: NfsStability,
        data: &[u8],
    ) -> Result<Self> {
        if data.len() > MAX_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut args = Self::empty();
        args.fh = fh;
        args.offset = offset;
        args.count = data.len() as u32;
        args.stability = stability;
        args.data[..data.len()].copy_from_slice(data);
        args.data_len = data.len();
        Ok(args)
    }
}

// ── NfsWriteResult ───────────────────────────────────────────────────────────

/// Result of an NFS WRITE RPC call.
#[derive(Debug, Clone, Copy)]
pub struct NfsWriteResult {
    /// Bytes the server actually wrote.
    pub count: u32,
    /// Stability level the server committed to.
    pub committed: NfsStability,
    /// Write verifier (used to detect server restarts between write and commit).
    pub verf: u64,
}

impl NfsWriteResult {
    /// Create a default result.
    pub const fn new(count: u32, committed: NfsStability, verf: u64) -> Self {
        Self {
            count,
            committed,
            verf,
        }
    }
}

// ── NfsIoBuf ─────────────────────────────────────────────────────────────────

/// A fixed-capacity buffer for encoding NFS READ/WRITE XDR arguments and
/// decoding results.
///
/// This is a simplified XDR layer for NFS-specific types; for full RPC
/// header encode/decode see [`crate::nfs_rpc_clnt::XdrBuffer`].
pub struct NfsIoBuf {
    /// Raw buffer storage (page-size aligned).
    data: [u8; 4096],
    /// Write/read cursor.
    pos: usize,
    /// Valid bytes.
    len: usize,
}

impl NfsIoBuf {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self {
            data: [0u8; 4096],
            pos: 0,
            len: 0,
        }
    }

    /// Encode a u32 in big-endian.
    pub fn put_u32(&mut self, val: u32) -> Result<()> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::OutOfMemory);
        }
        self.data[self.pos..self.pos + 4].copy_from_slice(&val.to_be_bytes());
        self.pos += 4;
        self.len = self.pos;
        Ok(())
    }

    /// Encode a u64 in big-endian (two words).
    pub fn put_u64(&mut self, val: u64) -> Result<()> {
        self.put_u32((val >> 32) as u32)?;
        self.put_u32(val as u32)
    }

    /// Decode a u32 from the current position.
    pub fn get_u32(&mut self) -> Result<u32> {
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

    /// Decode a u64 from the current position.
    pub fn get_u64(&mut self) -> Result<u64> {
        let hi = self.get_u32()? as u64;
        let lo = self.get_u32()? as u64;
        Ok((hi << 32) | lo)
    }

    /// Encode NFS READ arguments into this buffer.
    pub fn encode_read(&mut self, args: &NfsReadArgs) -> Result<()> {
        self.pos = 0;
        self.len = 0;
        // FH opaque (4-byte length prefix + data).
        self.put_u32(args.fh.len as u32)?;
        if self.pos + args.fh.len > self.data.len() {
            return Err(Error::OutOfMemory);
        }
        self.data[self.pos..self.pos + args.fh.len].copy_from_slice(&args.fh.data[..args.fh.len]);
        self.pos += (args.fh.len + 3) & !3;
        self.put_u64(args.offset)?;
        self.put_u32(args.count)?;
        self.len = self.pos;
        Ok(())
    }

    /// Encode NFS WRITE arguments into this buffer (header only; payload
    /// is sent separately to avoid double-copy).
    pub fn encode_write_header(&mut self, args: &NfsWriteArgs) -> Result<()> {
        self.pos = 0;
        self.len = 0;
        self.put_u32(args.fh.len as u32)?;
        if self.pos + args.fh.len > self.data.len() {
            return Err(Error::OutOfMemory);
        }
        self.data[self.pos..self.pos + args.fh.len].copy_from_slice(&args.fh.data[..args.fh.len]);
        self.pos += (args.fh.len + 3) & !3;
        self.put_u64(args.offset)?;
        self.put_u32(args.count)?;
        self.put_u32(args.stability as u32)?;
        self.put_u32(args.data_len as u32)?; // data opaque length
        self.len = self.pos;
        Ok(())
    }

    /// Reset the buffer.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.len = 0;
    }

    /// Return encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Default for NfsIoBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ── NfsWriteback ──────────────────────────────────────────────────────────────

/// A single unstable write that has been sent to the server but not yet
/// committed.
#[derive(Debug, Clone, Copy)]
pub struct NfsWriteback {
    /// File handle of the written file.
    pub fh: NfsFileHandle,
    /// Start offset of the dirty range.
    pub offset: u64,
    /// Number of dirty bytes.
    pub count: u32,
    /// Write verifier returned by the server.
    pub verf: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl NfsWriteback {
    /// Create an empty writeback slot.
    pub const fn empty() -> Self {
        Self {
            fh: NfsFileHandle::empty(),
            offset: 0,
            count: 0,
            verf: 0,
            in_use: false,
        }
    }
}

// ── DataServer ───────────────────────────────────────────────────────────────

/// A pNFS data server entry in a layout.
#[derive(Debug, Clone, Copy)]
pub struct DataServer {
    /// Data server identifier (device ID assigned by the MDS).
    pub dev_id: u64,
    /// IPv4 address of the data server (network byte order).
    pub addr: u32,
    /// TCP port.
    pub port: u16,
    /// Whether this entry is populated.
    pub in_use: bool,
}

impl DataServer {
    /// Create an empty data server slot.
    pub const fn empty() -> Self {
        Self {
            dev_id: 0,
            addr: 0,
            port: 0,
            in_use: false,
        }
    }

    /// Create a populated data server entry.
    pub const fn new(dev_id: u64, addr: u32, port: u16) -> Self {
        Self {
            dev_id,
            addr,
            port,
            in_use: true,
        }
    }
}

// ── LayoutCache ──────────────────────────────────────────────────────────────

/// Cached pNFS layout: maps file byte ranges to data servers.
#[derive(Debug, Clone, Copy)]
pub struct LayoutEntry {
    /// Inode number of the file this layout covers.
    pub ino: u64,
    /// Start offset covered by this layout.
    pub offset: u64,
    /// Length covered.
    pub length: u64,
    /// Index of the primary data server in the data-server table.
    pub primary_ds: usize,
    /// Whether this slot is populated.
    pub in_use: bool,
}

impl LayoutEntry {
    /// Create an empty layout entry.
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            offset: 0,
            length: 0,
            primary_ds: 0,
            in_use: false,
        }
    }
}

/// Fixed-size pNFS layout cache.
pub struct LayoutCache {
    /// Cached layouts.
    entries: [LayoutEntry; MAX_LAYOUTS],
    /// Number of occupied entries.
    count: usize,
    /// Data server pool.
    data_servers: [DataServer; MAX_DATA_SERVERS],
    /// Number of known data servers.
    ds_count: usize,
}

impl LayoutCache {
    /// Create an empty layout cache.
    pub fn new() -> Self {
        Self {
            entries: [const { LayoutEntry::empty() }; MAX_LAYOUTS],
            count: 0,
            data_servers: [const { DataServer::empty() }; MAX_DATA_SERVERS],
            ds_count: 0,
        }
    }

    /// Register a data server.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the data-server table is full.
    pub fn add_data_server(&mut self, ds: DataServer) -> Result<usize> {
        if self.ds_count >= MAX_DATA_SERVERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.ds_count;
        self.data_servers[idx] = ds;
        self.ds_count += 1;
        Ok(idx)
    }

    /// Install a layout entry for `ino` covering `[offset, offset+length)`.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the layout cache is full.
    /// - `InvalidArgument` if `primary_ds` is out of range.
    pub fn install(&mut self, ino: u64, offset: u64, length: u64, primary_ds: usize) -> Result<()> {
        if primary_ds >= self.ds_count {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_LAYOUTS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = LayoutEntry {
            ino,
            offset,
            length,
            primary_ds,
            in_use: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Look up the data server for `(ino, offset)`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no layout covers the given offset.
    pub fn lookup_ds(&self, ino: u64, offset: u64) -> Result<&DataServer> {
        let entry = self.entries[..self.count]
            .iter()
            .find(|e| {
                e.in_use && e.ino == ino && offset >= e.offset && offset < e.offset + e.length
            })
            .ok_or(Error::NotFound)?;
        Ok(&self.data_servers[entry.primary_ds])
    }

    /// Invalidate all layouts for `ino`.
    pub fn invalidate(&mut self, ino: u64) {
        for e in self.entries[..self.count].iter_mut() {
            if e.ino == ino {
                e.in_use = false;
            }
        }
    }
}

impl Default for LayoutCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── NfsIoEngine ──────────────────────────────────────────────────────────────

/// Top-level NFS I/O engine.
///
/// Manages the writeback queue, layout cache, and I/O buffer pool for a
/// single NFS mount.
pub struct NfsIoEngine {
    /// Unstable writeback entries awaiting a COMMIT call.
    writeback: [NfsWriteback; MAX_WRITEBACK],
    /// Number of in-use writeback slots.
    wb_count: usize,
    /// pNFS layout cache.
    layouts: LayoutCache,
    /// Encode buffer (reused per call).
    io_buf: NfsIoBuf,
    /// Write verifier from the last COMMIT reply (used to detect reboots).
    commit_verf: u64,
    /// Total bytes read since mount.
    bytes_read: u64,
    /// Total bytes written since mount.
    bytes_written: u64,
}

impl NfsIoEngine {
    /// Create a new I/O engine.
    pub fn new() -> Self {
        Self {
            writeback: [const { NfsWriteback::empty() }; MAX_WRITEBACK],
            wb_count: 0,
            layouts: LayoutCache::new(),
            io_buf: NfsIoBuf::new(),
            commit_verf: 0,
            bytes_read: 0,
            bytes_written: 0,
        }
    }

    /// Encode a READ request for `(fh, offset, count)` into the internal
    /// buffer, returning the XDR bytes to be transmitted.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `count > MAX_IO_SIZE`.
    /// - `OutOfMemory` from the encode buffer.
    pub fn encode_read<'a>(
        &'a mut self,
        fh: NfsFileHandle,
        offset: u64,
        count: u32,
    ) -> Result<&'a [u8]> {
        if count as usize > MAX_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        let args = NfsReadArgs::new(fh, offset, count);
        self.io_buf.encode_read(&args)?;
        Ok(self.io_buf.as_bytes())
    }

    /// Process an incoming READ reply payload, returning a simulated result.
    ///
    /// In a real driver this would parse the XDR reply into `NfsReadResult`.
    /// Here we validate the count and update accounting.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `count > MAX_IO_SIZE`.
    pub fn process_read_reply(&mut self, count: u32, eof: bool) -> Result<NfsReadResult> {
        if count as usize > MAX_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.bytes_read = self.bytes_read.saturating_add(count as u64);
        let mut res = NfsReadResult::empty();
        res.count = count;
        res.eof = eof;
        res.data_len = count as usize;
        Ok(res)
    }

    /// Encode a WRITE request header, queue the write for commit, and return
    /// the XDR bytes to transmit.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the data length exceeds `MAX_IO_SIZE`.
    /// - `OutOfMemory` if the writeback queue is full.
    pub fn encode_write<'a>(
        &'a mut self,
        fh: NfsFileHandle,
        offset: u64,
        stability: NfsStability,
        data: &[u8],
    ) -> Result<&'a [u8]> {
        let args = NfsWriteArgs::from_slice(fh, offset, stability, data)?;
        self.io_buf.encode_write_header(&args)?;

        // Queue for COMMIT if unstable.
        if stability == NfsStability::Unstable {
            if self.wb_count >= MAX_WRITEBACK {
                return Err(Error::OutOfMemory);
            }
            let slot = self.writeback[..MAX_WRITEBACK]
                .iter()
                .position(|w| !w.in_use)
                .ok_or(Error::OutOfMemory)?;
            self.writeback[slot] = NfsWriteback {
                fh,
                offset,
                count: args.count,
                verf: 0, // filled on WRITE reply
                in_use: true,
            };
            self.wb_count += 1;
        }
        self.bytes_written = self.bytes_written.saturating_add(data.len() as u64);
        Ok(self.io_buf.as_bytes())
    }

    /// Record a WRITE reply: fill in the verifier for the matching writeback.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching writeback entry exists.
    pub fn process_write_reply(&mut self, fh_bytes: &[u8], offset: u64, verf: u64) -> Result<()> {
        let pos = self.writeback[..MAX_WRITEBACK]
            .iter()
            .position(|w| w.in_use && w.offset == offset && w.fh.as_bytes() == fh_bytes)
            .ok_or(Error::NotFound)?;
        self.writeback[pos].verf = verf;
        Ok(())
    }

    /// Issue a COMMIT, flushing all pending unstable writes.
    ///
    /// On success clears the writeback queue and updates the commit verifier.
    ///
    /// # Errors
    ///
    /// - `IoError` if the server verifier changed (indicating a reboot and
    ///   requiring all dirty pages to be re-sent).
    pub fn commit(&mut self, server_verf: u64) -> Result<usize> {
        if self.commit_verf != 0 && server_verf != self.commit_verf {
            // Server rebooted — all unstable data is lost.
            return Err(Error::IoError);
        }
        let flushed = self.wb_count;
        for wb in self.writeback.iter_mut() {
            wb.in_use = false;
        }
        self.wb_count = 0;
        self.commit_verf = server_verf;
        Ok(flushed)
    }

    /// Install a pNFS layout into the layout cache.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`LayoutCache::install`].
    pub fn install_layout(
        &mut self,
        ino: u64,
        offset: u64,
        length: u64,
        primary_ds: usize,
    ) -> Result<()> {
        self.layouts.install(ino, offset, length, primary_ds)
    }

    /// Register a pNFS data server.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`LayoutCache::add_data_server`].
    pub fn add_data_server(&mut self, ds: DataServer) -> Result<usize> {
        self.layouts.add_data_server(ds)
    }

    /// Look up the data server responsible for `(ino, offset)`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no layout covers the offset.
    pub fn lookup_data_server(&self, ino: u64, offset: u64) -> Result<&DataServer> {
        self.layouts.lookup_ds(ino, offset)
    }

    /// Total bytes read through this engine.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Total bytes written through this engine.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Number of pending unstable writeback entries.
    pub fn pending_writebacks(&self) -> usize {
        self.wb_count
    }
}

impl Default for NfsIoEngine {
    fn default() -> Self {
        Self::new()
    }
}
