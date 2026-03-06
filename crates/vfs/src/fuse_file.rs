// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE file operations.
//!
//! Implements the kernel-side FUSE file operation stubs:
//! - [`FuseFileInfo`] — per-open-file state (fh, flags, open_flags)
//! - [`fuse_open`] / [`fuse_release`] — open/close lifecycle
//! - [`fuse_read`] / [`fuse_write`] — data path with request serialisation
//! - [`fuse_flush`] / [`fuse_fsync`] — barrier / durability
//! - [`fuse_lseek`] — seek with SEEK_DATA/SEEK_HOLE support
//! - FOPEN_DIRECT_IO / FOPEN_KEEP_CACHE / FOPEN_NONSEEKABLE flag handling
//! - Splice read/write stubs (zero-copy paths)
//!
//! # FUSE Kernel Interface
//!
//! The kernel sends FUSE requests via the `/dev/fuse` channel. This module
//! models the kernel side: assembling `fuse_open_in/out`, `fuse_read_in`,
//! `fuse_write_in/out` messages and dispatching them.
//!
//! # References
//! - Linux `fs/fuse/file.c`, `include/uapi/linux/fuse.h`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// FOPEN flags
// ---------------------------------------------------------------------------

/// Direct I/O: bypass page cache for this open file.
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;
/// Keep page cache even if page cache was invalidated.
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
/// File is not seekable.
pub const FOPEN_NONSEEKABLE: u32 = 1 << 2;
/// Enable caching of symbolic link target.
pub const FOPEN_CACHE_DIR: u32 = 1 << 3;
/// File is stream-like (no seeking allowed).
pub const FOPEN_STREAM: u32 = 1 << 4;

// ---------------------------------------------------------------------------
// FUSE operation codes (subset)
// ---------------------------------------------------------------------------

/// FUSE opcode: OPEN.
pub const FUSE_OPEN: u32 = 14;
/// FUSE opcode: READ.
pub const FUSE_READ: u32 = 15;
/// FUSE opcode: WRITE.
pub const FUSE_WRITE: u32 = 16;
/// FUSE opcode: RELEASE (close).
pub const FUSE_RELEASE: u32 = 18;
/// FUSE opcode: FLUSH.
pub const FUSE_FLUSH: u32 = 25;
/// FUSE opcode: FSYNC.
pub const FUSE_FSYNC: u32 = 20;
/// FUSE opcode: LSEEK.
pub const FUSE_LSEEK: u32 = 46;

/// Maximum read/write size per FUSE request (128 KiB).
pub const FUSE_MAX_PAGES: usize = 32;
/// Page size (4 KiB).
pub const FUSE_PAGE_SIZE: usize = 4096;
/// Maximum FUSE I/O size.
pub const FUSE_MAX_IO: usize = FUSE_MAX_PAGES * FUSE_PAGE_SIZE;

// ---------------------------------------------------------------------------
// FuseFileInfo
// ---------------------------------------------------------------------------

/// Per-open-file state maintained by the kernel for FUSE files.
///
/// Created in `fuse_open` and destroyed in `fuse_release`.
#[derive(Debug, Clone)]
pub struct FuseFileInfo {
    /// Opaque file handle returned by the daemon on OPEN.
    pub fh: u64,
    /// Open flags originally passed by the user (`O_RDONLY`, etc.).
    pub flags: u32,
    /// Open response flags from the daemon (`FOPEN_*`).
    pub open_flags: u32,
    /// Inode number.
    pub ino: u64,
    /// Write back cache enabled.
    pub writeback: bool,
    /// Lock owner (for POSIX lock tracking).
    pub lock_owner: u64,
}

impl FuseFileInfo {
    /// Create a new file info with default state.
    pub fn new(ino: u64, flags: u32) -> Self {
        Self {
            fh: 0,
            flags,
            open_flags: 0,
            ino,
            writeback: false,
            lock_owner: 0,
        }
    }

    /// Return true if direct I/O is enabled for this open.
    pub fn is_direct_io(&self) -> bool {
        self.open_flags & FOPEN_DIRECT_IO != 0
    }

    /// Return true if the file is non-seekable.
    pub fn is_nonseekable(&self) -> bool {
        self.open_flags & FOPEN_NONSEEKABLE != 0
    }
}

// ---------------------------------------------------------------------------
// FUSE request / response types
// ---------------------------------------------------------------------------

/// FUSE open request body (`fuse_open_in`).
#[derive(Debug, Clone, Copy)]
pub struct FuseOpenIn {
    /// Open flags.
    pub flags: u32,
    /// Padding / unused.
    pub open_flags: u32,
}

/// FUSE open response body (`fuse_open_out`).
#[derive(Debug, Clone, Copy)]
pub struct FuseOpenOut {
    /// Daemon-assigned file handle.
    pub fh: u64,
    /// Open response flags (`FOPEN_*`).
    pub open_flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE read request body (`fuse_read_in`).
#[derive(Debug, Clone, Copy)]
pub struct FuseReadIn {
    /// File handle.
    pub fh: u64,
    /// Byte offset to read from.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: u32,
    /// Read flags.
    pub read_flags: u32,
    /// Lock owner.
    pub lock_owner: u64,
    /// Open flags.
    pub flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE write request body (`fuse_write_in`).
#[derive(Debug, Clone, Copy)]
pub struct FuseWriteIn {
    /// File handle.
    pub fh: u64,
    /// Byte offset to write at.
    pub offset: u64,
    /// Number of bytes to write.
    pub size: u32,
    /// Write flags.
    pub write_flags: u32,
    /// Lock owner.
    pub lock_owner: u64,
    /// Open flags.
    pub flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE write response body (`fuse_write_out`).
#[derive(Debug, Clone, Copy)]
pub struct FuseWriteOut {
    /// Bytes actually written.
    pub size: u32,
    /// Padding.
    pub padding: u32,
}

// ---------------------------------------------------------------------------
// In-memory file data store (for test/simulation purposes)
// ---------------------------------------------------------------------------

/// Simulated in-memory file backing store for FUSE tests.
pub struct FuseFileData {
    pub ino: u64,
    data: Vec<u8>,
}

impl FuseFileData {
    /// Create an empty file.
    pub fn new(ino: u64) -> Self {
        Self {
            ino,
            data: Vec::new(),
        }
    }

    /// Read bytes at `offset`, returning up to `size` bytes.
    pub fn read(&self, offset: u64, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Vec::new();
        }
        let end = (offset + size as usize).min(self.data.len());
        self.data[offset..end].to_vec()
    }

    /// Write `data` at `offset`, extending the file as needed.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> u32 {
        let offset = offset as usize;
        let end = offset + data.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(data);
        data.len() as u32
    }

    /// Return file size.
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

// ---------------------------------------------------------------------------
// fuse_open
// ---------------------------------------------------------------------------

/// Open a FUSE file.
///
/// Builds an OPEN request, dispatches it (simulated here), and stores the
/// returned file handle in `info`. Returns `Err(IoError)` on failure.
pub fn fuse_open(info: &mut FuseFileInfo, _open_in: FuseOpenIn) -> Result<FuseOpenOut> {
    // In a real kernel this sends the request to /dev/fuse and waits.
    // Simulation: assign a deterministic file handle.
    let out = FuseOpenOut {
        fh: info.ino ^ 0xDEAD_0000,
        open_flags: 0,
        padding: 0,
    };
    info.fh = out.fh;
    info.open_flags = out.open_flags;
    Ok(out)
}

// ---------------------------------------------------------------------------
// fuse_release
// ---------------------------------------------------------------------------

/// Release (close) a FUSE file.
///
/// Sends a RELEASE request. Errors from RELEASE are usually ignored by the
/// kernel since the file descriptor is already closed from the user's
/// perspective.
pub fn fuse_release(info: &FuseFileInfo) -> Result<()> {
    if info.fh == 0 {
        return Err(Error::InvalidArgument);
    }
    // Simulation: nothing to tear down without a real daemon.
    Ok(())
}

// ---------------------------------------------------------------------------
// fuse_read
// ---------------------------------------------------------------------------

/// Read from a FUSE file.
///
/// Builds a `FuseReadIn` and dispatches it to the backing store simulation.
/// Returns the data bytes or `Err(IoError)`.
pub fn fuse_read(
    info: &FuseFileInfo,
    file: &FuseFileData,
    offset: u64,
    size: u32,
) -> Result<Vec<u8>> {
    if size as usize > FUSE_MAX_IO {
        return Err(Error::InvalidArgument);
    }
    let read_in = FuseReadIn {
        fh: info.fh,
        offset,
        size,
        read_flags: 0,
        lock_owner: info.lock_owner,
        flags: info.flags,
        padding: 0,
    };
    let _ = read_in;
    Ok(file.read(offset, size))
}

// ---------------------------------------------------------------------------
// fuse_write
// ---------------------------------------------------------------------------

/// Write to a FUSE file.
///
/// Returns the number of bytes written.
pub fn fuse_write(
    info: &FuseFileInfo,
    file: &mut FuseFileData,
    offset: u64,
    data: &[u8],
) -> Result<FuseWriteOut> {
    if data.len() > FUSE_MAX_IO {
        return Err(Error::InvalidArgument);
    }
    let write_in = FuseWriteIn {
        fh: info.fh,
        offset,
        size: data.len() as u32,
        write_flags: 0,
        lock_owner: info.lock_owner,
        flags: info.flags,
        padding: 0,
    };
    let _ = write_in;
    let written = file.write(offset, data);
    Ok(FuseWriteOut {
        size: written,
        padding: 0,
    })
}

// ---------------------------------------------------------------------------
// fuse_flush
// ---------------------------------------------------------------------------

/// Flush (called on close(), not fsync()).
///
/// Used to return any pending errors to the process. In FUSE this triggers
/// a FLUSH request to the daemon.
pub fn fuse_flush(info: &FuseFileInfo) -> Result<()> {
    if info.fh == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// fuse_fsync
// ---------------------------------------------------------------------------

/// Fsync a FUSE file.
///
/// `datasync` = true → FDATASYNC semantics (skip metadata).
pub fn fuse_fsync(info: &FuseFileInfo, _datasync: bool) -> Result<()> {
    if info.fh == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// fuse_lseek
// ---------------------------------------------------------------------------

/// SEEK_SET=0, SEEK_CUR=1, SEEK_END=2, SEEK_DATA=3, SEEK_HOLE=4.
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;
pub const SEEK_DATA: u32 = 3;
pub const SEEK_HOLE: u32 = 4;

/// Seek within a FUSE file.
///
/// Handles SEEK_DATA and SEEK_HOLE by consulting the daemon (stubbed here
/// to return `offset` for SEEK_DATA and `file_size` for SEEK_HOLE).
pub fn fuse_lseek(
    info: &FuseFileInfo,
    file: &FuseFileData,
    offset: i64,
    whence: u32,
) -> Result<i64> {
    if info.is_nonseekable() {
        return Err(Error::InvalidArgument);
    }
    let size = file.size() as i64;
    match whence {
        SEEK_SET => {
            if offset < 0 {
                Err(Error::InvalidArgument)
            } else {
                Ok(offset)
            }
        }
        SEEK_CUR => Ok(offset), // caller must add current position
        SEEK_END => {
            let pos = size + offset;
            if pos < 0 {
                Err(Error::InvalidArgument)
            } else {
                Ok(pos)
            }
        }
        SEEK_DATA => Ok(offset.max(0).min(size)),
        SEEK_HOLE => Ok(size),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Splice stubs
// ---------------------------------------------------------------------------

/// Splice read stub: would transfer from FUSE file to a pipe without copying.
///
/// Full implementation requires integration with the pipe/splice subsystem.
pub fn fuse_splice_read(
    _info: &FuseFileInfo,
    _file: &FuseFileData,
    _offset: u64,
    _len: usize,
) -> Result<usize> {
    Err(Error::NotImplemented)
}

/// Splice write stub: would transfer from a pipe into the FUSE file.
pub fn fuse_splice_write(
    _info: &FuseFileInfo,
    _file: &mut FuseFileData,
    _offset: u64,
    _len: usize,
) -> Result<usize> {
    Err(Error::NotImplemented)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_read_write_release() {
        let mut info = FuseFileInfo::new(42, 0o2);
        let open_in = FuseOpenIn {
            flags: 0o2,
            open_flags: 0,
        };
        fuse_open(&mut info, open_in).unwrap();
        assert_ne!(info.fh, 0);

        let mut file = FuseFileData::new(42);
        fuse_write(&info, &mut file, 0, b"hello fuse").unwrap();
        let data = fuse_read(&info, &file, 0, 10).unwrap();
        assert_eq!(data, b"hello fuse");
        fuse_release(&info).unwrap();
    }

    #[test]
    fn test_lseek_seek_end() {
        let info = FuseFileInfo {
            fh: 1,
            flags: 0,
            open_flags: 0,
            ino: 1,
            writeback: false,
            lock_owner: 0,
        };
        let mut file = FuseFileData::new(1);
        file.write(0, b"abcdef");
        let pos = fuse_lseek(&info, &file, 0, SEEK_END).unwrap();
        assert_eq!(pos, 6);
    }
}
