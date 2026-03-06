// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Loop block device driver.
//!
//! Presents a regular file (or memory region) as a block device.
//! Supports offset and size limits, configurable block sizes, and
//! direct I/O mode for bypassing the page cache.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐
//! │  Block I/O      │
//! └───────┬────────┘
//!         │ read/write sectors
//! ┌───────▼────────┐
//! │  Loop Device    │ ← this module
//! └───────┬────────┘
//!         │ read/write at offset
//! ┌───────▼────────┐
//! │  Backing File   │ (VFS)
//! └────────────────┘
//! ```
//!
//! The loop device translates sector-level block I/O requests into
//! byte-level reads and writes against the backing file. It is
//! commonly used for mounting disk images, creating encrypted
//! containers, and testing filesystem code.
//!
//! Reference: Linux `drivers/block/loop.c`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of loop devices.
const MAX_LOOP_DEVICES: usize = 16;

/// Default block size in bytes.
const DEFAULT_BLOCK_SIZE: u32 = 512;

/// Minimum block size.
const MIN_BLOCK_SIZE: u32 = 512;

/// Maximum block size.
const MAX_BLOCK_SIZE: u32 = 4096;

/// Maximum backing file path length.
const MAX_PATH_LEN: usize = 256;

/// Loop device name prefix for `/dev/loopN`.
const _LOOP_PREFIX: &[u8] = b"/dev/loop";

// ── Loop Flags ──────────────────────────────────────────────────

/// Flags controlling loop device behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopFlags(u32);

impl LoopFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Read-only mode.
    pub const READ_ONLY: Self = Self(1 << 0);

    /// Autoclear — detach on last close.
    pub const AUTOCLEAR: Self = Self(1 << 2);

    /// Partition scanning — detect partitions on attach.
    pub const PARTSCAN: Self = Self(1 << 3);

    /// Direct I/O — bypass page cache.
    pub const DIRECT_IO: Self = Self(1 << 4);

    /// Create a new flag set.
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Return whether read-only mode is set.
    pub fn is_read_only(self) -> bool {
        self.0 & Self::READ_ONLY.0 != 0
    }

    /// Return whether autoclear is set.
    pub fn is_autoclear(self) -> bool {
        self.0 & Self::AUTOCLEAR.0 != 0
    }

    /// Return whether direct I/O is enabled.
    pub fn is_direct_io(self) -> bool {
        self.0 & Self::DIRECT_IO.0 != 0
    }

    /// Return the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }
}

impl Default for LoopFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// ── Loop State ──────────────────────────────────────────────────

/// State of a loop device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoopState {
    /// Device is not attached to a backing file.
    #[default]
    Detached,
    /// Device is attached and operational.
    Attached,
    /// Device is suspended (e.g., during resize).
    Suspended,
    /// Device encountered an error.
    Error,
}

// ── Backing File ────────────────────────────────────────────────

/// Describes the backing file for a loop device.
#[derive(Clone, Copy)]
pub struct BackingFile {
    /// File path (NUL-terminated).
    path: [u8; MAX_PATH_LEN],
    /// Length of the path string (not including NUL).
    path_len: usize,
    /// File descriptor or inode reference.
    fd: i32,
    /// Total file size in bytes.
    file_size: u64,
    /// Whether the file supports direct I/O.
    supports_direct_io: bool,
}

impl BackingFile {
    /// Create an empty backing file descriptor.
    const fn empty() -> Self {
        Self {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            fd: -1,
            file_size: 0,
            supports_direct_io: false,
        }
    }

    /// Return the file path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Return the file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Return the total file size.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Return whether direct I/O is supported.
    pub fn supports_direct_io(&self) -> bool {
        self.supports_direct_io
    }
}

// ── Loop Configuration ──────────────────────────────────────────

/// Configuration for attaching a loop device.
#[derive(Debug, Clone, Copy)]
pub struct LoopConfig {
    /// Byte offset into the backing file.
    pub offset: u64,
    /// Size limit in bytes (0 = use entire file).
    pub size_limit: u64,
    /// Block size in bytes.
    pub block_size: u32,
    /// Operational flags.
    pub flags: LoopFlags,
}

impl LoopConfig {
    /// Create a default configuration.
    pub const fn new() -> Self {
        Self {
            offset: 0,
            size_limit: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            flags: LoopFlags::NONE,
        }
    }
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── Loop Status ─────────────────────────────────────────────────

/// Status information for a loop device.
#[derive(Debug, Clone, Copy)]
pub struct LoopStatus {
    /// Loop device index.
    pub index: u8,
    /// Current state.
    pub state: LoopState,
    /// Byte offset into backing file.
    pub offset: u64,
    /// Size limit (0 = no limit).
    pub size_limit: u64,
    /// Effective capacity in bytes.
    pub capacity: u64,
    /// Block size in bytes.
    pub block_size: u32,
    /// Total sectors (capacity / block_size).
    pub sector_count: u64,
    /// Operational flags.
    pub flags: LoopFlags,
    /// Total reads completed.
    pub read_count: u64,
    /// Total writes completed.
    pub write_count: u64,
}

// ── Loop Device ─────────────────────────────────────────────────

/// A loop block device.
///
/// Translates block I/O requests into reads and writes against a
/// backing file. Each loop device is identified by its index
/// (e.g., `/dev/loop0`).
pub struct LoopDevice {
    /// Device index.
    index: u8,
    /// Current state.
    state: LoopState,
    /// Backing file information.
    backing: BackingFile,
    /// Active configuration.
    config: LoopConfig,
    /// Effective capacity in bytes.
    capacity: u64,
    /// Total read operations.
    read_count: u64,
    /// Total write operations.
    write_count: u64,
    /// Total read bytes.
    read_bytes: u64,
    /// Total written bytes.
    write_bytes: u64,
    /// Error count.
    error_count: u32,
}

impl LoopDevice {
    /// Create an uninitialised loop device.
    pub const fn new(index: u8) -> Self {
        Self {
            index,
            state: LoopState::Detached,
            backing: BackingFile::empty(),
            config: LoopConfig::new(),
            capacity: 0,
            read_count: 0,
            write_count: 0,
            read_bytes: 0,
            write_bytes: 0,
            error_count: 0,
        }
    }

    /// Attach the loop device to a backing file.
    ///
    /// # Arguments
    ///
    /// * `path` — path to the backing file.
    /// * `fd` — open file descriptor for the backing file.
    /// * `file_size` — total size of the backing file.
    /// * `config` — loop device configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the device is already attached.
    /// Returns [`Error::InvalidArgument`] if the configuration is
    /// invalid (e.g., offset exceeds file size, block size out of
    /// range).
    pub fn attach(
        &mut self,
        path: &[u8],
        fd: i32,
        file_size: u64,
        config: LoopConfig,
    ) -> Result<()> {
        if self.state != LoopState::Detached {
            return Err(Error::Busy);
        }

        if config.block_size < MIN_BLOCK_SIZE || config.block_size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Verify block size is a power of 2.
        if config.block_size & (config.block_size - 1) != 0 {
            return Err(Error::InvalidArgument);
        }

        if config.offset >= file_size {
            return Err(Error::InvalidArgument);
        }

        // Set up the backing file.
        let copy_len = path.len().min(MAX_PATH_LEN);
        self.backing.path[..copy_len].copy_from_slice(&path[..copy_len]);
        self.backing.path_len = copy_len;
        self.backing.fd = fd;
        self.backing.file_size = file_size;

        // Calculate effective capacity.
        let available = file_size - config.offset;
        self.capacity = if config.size_limit > 0 {
            config.size_limit.min(available)
        } else {
            available
        };

        // Align capacity down to block boundary.
        let block_size_u64 = u64::from(config.block_size);
        self.capacity = (self.capacity / block_size_u64) * block_size_u64;

        self.config = config;
        self.state = LoopState::Attached;
        self.read_count = 0;
        self.write_count = 0;
        self.read_bytes = 0;
        self.write_bytes = 0;
        self.error_count = 0;

        Ok(())
    }

    /// Detach the loop device from its backing file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device is not
    /// attached.
    pub fn detach(&mut self) -> Result<()> {
        if self.state != LoopState::Attached {
            return Err(Error::InvalidArgument);
        }

        self.backing = BackingFile::empty();
        self.config = LoopConfig::new();
        self.capacity = 0;
        self.state = LoopState::Detached;

        Ok(())
    }

    /// Read sectors from the loop device.
    ///
    /// Translates the sector range into a byte read against the
    /// backing file. In a real implementation this would issue
    /// a VFS read; here we validate the request and update stats.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device is not
    /// attached or the read range is out of bounds.
    pub fn read_sectors(
        &mut self,
        start_sector: u64,
        sector_count: u32,
        _buffer: &mut [u8],
    ) -> Result<()> {
        if self.state != LoopState::Attached {
            return Err(Error::InvalidArgument);
        }

        let block_size = u64::from(self.config.block_size);
        let byte_offset = start_sector * block_size + self.config.offset;
        let byte_count = u64::from(sector_count) * block_size;

        if byte_offset + byte_count > self.config.offset + self.capacity {
            return Err(Error::InvalidArgument);
        }

        // In a real implementation:
        // vfs_read(self.backing.fd, byte_offset, buffer, byte_count)

        self.read_count += 1;
        self.read_bytes += byte_count;

        Ok(())
    }

    /// Write sectors to the loop device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device is not
    /// attached, the device is read-only, or the write range is
    /// out of bounds.
    pub fn write_sectors(
        &mut self,
        start_sector: u64,
        sector_count: u32,
        _buffer: &[u8],
    ) -> Result<()> {
        if self.state != LoopState::Attached {
            return Err(Error::InvalidArgument);
        }

        if self.config.flags.is_read_only() {
            return Err(Error::InvalidArgument);
        }

        let block_size = u64::from(self.config.block_size);
        let byte_offset = start_sector * block_size + self.config.offset;
        let byte_count = u64::from(sector_count) * block_size;

        if byte_offset + byte_count > self.config.offset + self.capacity {
            return Err(Error::InvalidArgument);
        }

        // In a real implementation:
        // vfs_write(self.backing.fd, byte_offset, buffer, byte_count)

        self.write_count += 1;
        self.write_bytes += byte_count;

        Ok(())
    }

    /// Update the effective capacity.
    ///
    /// Called after the backing file has been resized.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device is not
    /// attached.
    pub fn set_capacity(&mut self, new_file_size: u64) -> Result<()> {
        if self.state != LoopState::Attached {
            return Err(Error::InvalidArgument);
        }

        self.backing.file_size = new_file_size;

        let available = new_file_size.saturating_sub(self.config.offset);
        let effective = if self.config.size_limit > 0 {
            self.config.size_limit.min(available)
        } else {
            available
        };

        let block_size_u64 = u64::from(self.config.block_size);
        self.capacity = (effective / block_size_u64) * block_size_u64;

        Ok(())
    }

    /// Change the block size.
    ///
    /// The device must be attached but the change takes effect
    /// immediately (no I/O should be in flight).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the block size is not
    /// a valid power of 2 within the supported range.
    pub fn set_block_size(&mut self, block_size: u32) -> Result<()> {
        if block_size < MIN_BLOCK_SIZE || block_size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        if block_size & (block_size - 1) != 0 {
            return Err(Error::InvalidArgument);
        }

        self.config.block_size = block_size;

        // Re-align capacity.
        if self.state == LoopState::Attached {
            let block_size_u64 = u64::from(block_size);
            self.capacity = (self.capacity / block_size_u64) * block_size_u64;
        }

        Ok(())
    }

    /// Return the current status of the loop device.
    pub fn get_status(&self) -> LoopStatus {
        let block_size = u64::from(self.config.block_size);
        let sector_count = if block_size > 0 {
            self.capacity / block_size
        } else {
            0
        };

        LoopStatus {
            index: self.index,
            state: self.state,
            offset: self.config.offset,
            size_limit: self.config.size_limit,
            capacity: self.capacity,
            block_size: self.config.block_size,
            sector_count,
            flags: self.config.flags,
            read_count: self.read_count,
            write_count: self.write_count,
        }
    }

    /// Return the device index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Return the current state.
    pub fn state(&self) -> LoopState {
        self.state
    }

    /// Return the effective capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Return a reference to the backing file info.
    pub fn backing_file(&self) -> &BackingFile {
        &self.backing
    }

    /// Return the active configuration.
    pub fn config(&self) -> &LoopConfig {
        &self.config
    }
}

impl Default for LoopDevice {
    fn default() -> Self {
        Self::new(0)
    }
}

// ── Loop Device Registry ────────────────────────────────────────

/// Registry of loop block devices.
pub struct LoopRegistry {
    /// Registered devices.
    devices: [Option<LoopDevice>; MAX_LOOP_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl LoopRegistry {
    /// Create an empty loop device registry.
    pub const fn new() -> Self {
        const NONE: Option<LoopDevice> = None;
        Self {
            devices: [NONE; MAX_LOOP_DEVICES],
            count: 0,
        }
    }

    /// Register a loop device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: LoopDevice) -> Result<usize> {
        if self.count >= MAX_LOOP_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Return a reference to a device by index.
    pub fn get(&self, index: usize) -> Option<&LoopDevice> {
        if index < self.count {
            self.devices[index].as_ref()
        } else {
            None
        }
    }

    /// Return a mutable reference to a device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut LoopDevice> {
        if index < self.count {
            self.devices[index].as_mut()
        } else {
            None
        }
    }

    /// Find a free (detached) loop device.
    pub fn find_free(&self) -> Option<usize> {
        for i in 0..self.count {
            if let Some(dev) = &self.devices[i] {
                if dev.state == LoopState::Detached {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for LoopRegistry {
    fn default() -> Self {
        Self::new()
    }
}
