// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE passthrough I/O.
//!
//! The FUSE passthrough feature allows a FUSE file descriptor to be
//! promoted to "passthrough mode", where read/write operations bypass
//! the FUSE daemon and go directly to the backing file on the host
//! filesystem.  This dramatically reduces latency for I/O-intensive
//! workloads because it eliminates the round-trip through user space.
//!
//! # Architecture
//!
//! ```text
//! VFS read/write
//!   → FusePassthroughFd::io()
//!     → if passthrough enabled and backing fd set:
//!         → transfer data directly from/to backing fd buffer
//!       else:
//!         → normal FUSE request dispatch (slow path)
//! ```
//!
//! # Structures
//!
//! - [`PassthroughMode`]      — disabled / read-only / read-write
//! - [`BackingFile`]          — represents a host-side backing file
//! - [`PassthroughStats`]     — I/O statistics for a passthrough fd
//! - [`FusePassthroughFd`]   — single FUSE fd with passthrough state
//! - [`PassthroughTable`]    — registry of all passthrough fds
//! - [`PassthroughManager`]  — global manager / policy controller
//!
//! # References
//!
//! - Linux `fs/fuse/passthrough.c`, `include/uapi/linux/fuse.h`
//! - `FUSE_PASSTHROUGH` feature flag, `FUSE_DEV_IOC_BACKING_OPEN`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of passthrough file descriptors in the table.
pub const MAX_PASSTHROUGH_FDS: usize = 256;

/// Maximum size of a single passthrough I/O transfer (1 MiB).
pub const MAX_IO_SIZE: usize = 1024 * 1024;

/// Maximum path length of a backing file path.
pub const MAX_BACKING_PATH: usize = 256;

/// Unique handle used to identify passthrough fds.
pub type PassthroughHandle = u32;

// ── PassthroughMode ───────────────────────────────────────────────────────────

/// Operational mode for a passthrough file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PassthroughMode {
    /// Passthrough is disabled; all I/O goes through the FUSE daemon.
    #[default]
    Disabled = 0,
    /// Passthrough reads are allowed; writes still go through daemon.
    ReadOnly = 1,
    /// Both reads and writes bypass the daemon directly.
    ReadWrite = 2,
}

// ── BackingFile ───────────────────────────────────────────────────────────────

/// Represents the host-side backing file for a passthrough fd.
#[derive(Debug, Clone)]
pub struct BackingFile {
    /// Host inode number.
    pub ino: u64,
    /// Host filesystem device number.
    pub dev: u64,
    /// Path to the backing file on the host (informational).
    path: [u8; MAX_BACKING_PATH],
    path_len: usize,
    /// File size in bytes at the time the backing was registered.
    pub size: u64,
    /// Read-only flag — the backing file was opened O_RDONLY.
    pub read_only: bool,
    /// Simulated data buffer (replaces an actual file descriptor).
    pub data: [u8; 4096],
    /// Amount of valid data in the buffer.
    pub data_len: usize,
}

impl Default for BackingFile {
    fn default() -> Self {
        Self {
            ino: 0,
            dev: 0,
            path: [0u8; MAX_BACKING_PATH],
            path_len: 0,
            size: 0,
            read_only: false,
            data: [0u8; 4096],
            data_len: 0,
        }
    }
}

impl BackingFile {
    /// Create a new backing file descriptor.
    pub fn new(ino: u64, dev: u64, path: &[u8], size: u64, read_only: bool) -> Result<Self> {
        if path.len() > MAX_BACKING_PATH {
            return Err(Error::InvalidArgument);
        }
        let mut backing = Self::default();
        backing.ino = ino;
        backing.dev = dev;
        backing.path[..path.len()].copy_from_slice(path);
        backing.path_len = path.len();
        backing.size = size;
        backing.read_only = read_only;
        Ok(backing)
    }

    /// Return the path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Read bytes from the backing buffer starting at `offset`.
    pub fn read(&self, offset: u64, dst: &mut [u8]) -> Result<usize> {
        let start = offset as usize;
        if start >= self.data_len {
            return Ok(0);
        }
        let available = self.data_len - start;
        let to_copy = available.min(dst.len());
        dst[..to_copy].copy_from_slice(&self.data[start..start + to_copy]);
        Ok(to_copy)
    }

    /// Write bytes to the backing buffer starting at `offset`.
    pub fn write(&mut self, offset: u64, src: &[u8]) -> Result<usize> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        let start = offset as usize;
        let end = start + src.len();
        if end > self.data.len() {
            return Err(Error::InvalidArgument);
        }
        self.data[start..end].copy_from_slice(src);
        if end > self.data_len {
            self.data_len = end;
            self.size = self.size.max(end as u64);
        }
        Ok(src.len())
    }
}

// ── PassthroughStats ──────────────────────────────────────────────────────────

/// Per-fd I/O statistics for the passthrough path.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassthroughStats {
    /// Bytes read directly via passthrough.
    pub bytes_read: u64,
    /// Bytes written directly via passthrough.
    pub bytes_written: u64,
    /// Number of read operations.
    pub read_ops: u64,
    /// Number of write operations.
    pub write_ops: u64,
    /// Reads that fell back to the FUSE daemon (passthrough not active).
    pub read_fallbacks: u64,
    /// Writes that fell back to the FUSE daemon.
    pub write_fallbacks: u64,
}

// ── FusePassthroughFd ─────────────────────────────────────────────────────────

/// A FUSE file descriptor with optional passthrough state.
pub struct FusePassthroughFd {
    /// Unique handle for this fd.
    pub handle: PassthroughHandle,
    /// FUSE node ID for the file.
    pub nodeid: u64,
    /// Current passthrough mode.
    pub mode: PassthroughMode,
    /// Whether a backing file is installed.
    has_backing: bool,
    /// The backing file (valid when `has_backing` is true).
    backing: BackingFile,
    /// I/O statistics.
    pub stats: PassthroughStats,
    /// Whether this fd entry is in use.
    active: bool,
}

impl Default for FusePassthroughFd {
    fn default() -> Self {
        Self {
            handle: 0,
            nodeid: 0,
            mode: PassthroughMode::Disabled,
            has_backing: false,
            backing: BackingFile::default(),
            stats: PassthroughStats::default(),
            active: false,
        }
    }
}

impl FusePassthroughFd {
    /// Install a backing file for this fd and enable passthrough mode.
    pub fn set_backing(&mut self, backing: BackingFile, mode: PassthroughMode) -> Result<()> {
        if mode == PassthroughMode::Disabled {
            return Err(Error::InvalidArgument);
        }
        if backing.read_only && mode == PassthroughMode::ReadWrite {
            return Err(Error::PermissionDenied);
        }
        self.backing = backing;
        self.has_backing = true;
        self.mode = mode;
        Ok(())
    }

    /// Remove the backing file, reverting to normal FUSE I/O.
    pub fn clear_backing(&mut self) {
        self.backing = BackingFile::default();
        self.has_backing = false;
        self.mode = PassthroughMode::Disabled;
    }

    /// Read up to `dst.len()` bytes from `offset`.
    ///
    /// Uses the passthrough path when a backing file is installed and the
    /// mode permits reads; otherwise falls back (caller must use FUSE daemon).
    pub fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize> {
        if self.has_backing
            && (self.mode == PassthroughMode::ReadOnly || self.mode == PassthroughMode::ReadWrite)
        {
            let n = self.backing.read(offset, dst)?;
            self.stats.bytes_read += n as u64;
            self.stats.read_ops += 1;
            Ok(n)
        } else {
            self.stats.read_fallbacks += 1;
            Err(Error::WouldBlock)
        }
    }

    /// Write `src` bytes at `offset`.
    ///
    /// Uses the passthrough path when a backing file is installed and the
    /// mode permits writes; otherwise signals fallback to FUSE daemon.
    pub fn write(&mut self, offset: u64, src: &[u8]) -> Result<usize> {
        if self.has_backing && self.mode == PassthroughMode::ReadWrite {
            let n = self.backing.write(offset, src)?;
            self.stats.bytes_written += n as u64;
            self.stats.write_ops += 1;
            Ok(n)
        } else {
            self.stats.write_fallbacks += 1;
            Err(Error::WouldBlock)
        }
    }

    /// Returns `true` if passthrough I/O is currently active.
    pub fn is_passthrough_active(&self) -> bool {
        self.has_backing && self.mode != PassthroughMode::Disabled
    }
}

// ── PassthroughTable ──────────────────────────────────────────────────────────

/// Registry of all open FUSE passthrough file descriptors.
pub struct PassthroughTable {
    entries: [FusePassthroughFd; MAX_PASSTHROUGH_FDS],
    next_handle: PassthroughHandle,
    active_count: usize,
}

impl Default for PassthroughTable {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| FusePassthroughFd::default()),
            next_handle: 1,
            active_count: 0,
        }
    }
}

impl PassthroughTable {
    /// Allocate a new passthrough fd for a given FUSE node ID.
    ///
    /// Returns the handle or [`Error::OutOfMemory`] if the table is full.
    pub fn open(&mut self, nodeid: u64) -> Result<PassthroughHandle> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        let handle = self.next_handle;
        self.next_handle += 1;
        let entry = &mut self.entries[slot];
        entry.handle = handle;
        entry.nodeid = nodeid;
        entry.mode = PassthroughMode::Disabled;
        entry.has_backing = false;
        entry.active = true;
        self.active_count += 1;
        Ok(handle)
    }

    /// Close a passthrough fd.
    ///
    /// Returns [`Error::NotFound`] if the handle is not registered.
    pub fn close(&mut self, handle: PassthroughHandle) -> Result<()> {
        let slot = self
            .entries
            .iter()
            .position(|e| e.active && e.handle == handle)
            .ok_or(Error::NotFound)?;
        self.entries[slot] = FusePassthroughFd::default();
        self.active_count -= 1;
        Ok(())
    }

    /// Get an immutable reference to a passthrough fd.
    pub fn get(&self, handle: PassthroughHandle) -> Result<&FusePassthroughFd> {
        self.entries
            .iter()
            .find(|e| e.active && e.handle == handle)
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a passthrough fd.
    pub fn get_mut(&mut self, handle: PassthroughHandle) -> Result<&mut FusePassthroughFd> {
        self.entries
            .iter_mut()
            .find(|e| e.active && e.handle == handle)
            .ok_or(Error::NotFound)
    }

    /// Number of active passthrough fds.
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

// ── PassthroughManager ────────────────────────────────────────────────────────

/// Global manager controlling FUSE passthrough policy.
pub struct PassthroughManager {
    /// Per-fd table.
    pub table: PassthroughTable,
    /// Whether passthrough is globally enabled.
    pub enabled: bool,
    /// Default mode assigned to newly set-up fds.
    pub default_mode: PassthroughMode,
    /// Aggregate statistics across all fds.
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub total_fallbacks: u64,
}

impl Default for PassthroughManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PassthroughManager {
    /// Create a new manager with passthrough disabled.
    pub fn new() -> Self {
        Self {
            table: PassthroughTable::default(),
            enabled: false,
            default_mode: PassthroughMode::ReadOnly,
            total_bytes_read: 0,
            total_bytes_written: 0,
            total_fallbacks: 0,
        }
    }

    /// Enable passthrough globally.
    pub fn enable(&mut self, mode: PassthroughMode) {
        self.enabled = true;
        self.default_mode = mode;
    }

    /// Disable passthrough — all new I/O goes through the FUSE daemon.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Open a new passthrough fd for `nodeid`.
    pub fn open_fd(&mut self, nodeid: u64) -> Result<PassthroughHandle> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.table.open(nodeid)
    }

    /// Attach a backing file to an existing passthrough fd.
    pub fn attach_backing(
        &mut self,
        handle: PassthroughHandle,
        backing: BackingFile,
        mode: PassthroughMode,
    ) -> Result<()> {
        let fd = self.table.get_mut(handle)?;
        fd.set_backing(backing, mode)
    }

    /// Read via passthrough, returning number of bytes transferred.
    pub fn read(
        &mut self,
        handle: PassthroughHandle,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize> {
        let fd = self.table.get_mut(handle)?;
        match fd.read(offset, dst) {
            Ok(n) => {
                self.total_bytes_read += n as u64;
                Ok(n)
            }
            Err(Error::WouldBlock) => {
                self.total_fallbacks += 1;
                Err(Error::WouldBlock)
            }
            Err(e) => Err(e),
        }
    }

    /// Write via passthrough, returning number of bytes transferred.
    pub fn write(&mut self, handle: PassthroughHandle, offset: u64, src: &[u8]) -> Result<usize> {
        let fd = self.table.get_mut(handle)?;
        match fd.write(offset, src) {
            Ok(n) => {
                self.total_bytes_written += n as u64;
                Ok(n)
            }
            Err(Error::WouldBlock) => {
                self.total_fallbacks += 1;
                Err(Error::WouldBlock)
            }
            Err(e) => Err(e),
        }
    }

    /// Close a passthrough fd.
    pub fn close_fd(&mut self, handle: PassthroughHandle) -> Result<()> {
        self.table.close(handle)
    }
}
