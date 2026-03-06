// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RAM disk block device.
//!
//! A RAM disk presents a region of physical memory as a block device.
//! It is used for:
//! - Initial RAM filesystem (initrd / initramfs) loading at boot.
//! - In-memory swap device.
//! - Fast temporary storage during OS development and testing.
//!
//! # Design
//!
//! [`RamDisk`] wraps a caller-supplied physical memory region exposed as a
//! byte-addressable backing store. The caller maps the memory and provides
//! a virtual address + length. All reads and writes are simple `memcopy`
//! operations against the backing store.
//!
//! - Fixed block size (default 512 bytes).
//! - Supports read, write, and flush (no-op).
//! - Optional write-protect mode.
//! - Registry of up to [`MAX_RAMDISKS`] instances.
//!
//! Reference: Linux `drivers/block/brd.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default block size in bytes.
pub const RAMDISK_BLOCK_SIZE: u32 = 512;

/// Maximum number of RAM disk instances.
pub const MAX_RAMDISKS: usize = 8;

// ---------------------------------------------------------------------------
// RamDiskConfig
// ---------------------------------------------------------------------------

/// Configuration for a RAM disk instance.
#[derive(Debug, Clone, Copy)]
pub struct RamDiskConfig {
    /// Virtual base address of the backing memory region.
    pub vaddr: u64,
    /// Size of the backing region in bytes.
    pub size: u64,
    /// Block size in bytes (must be power of two, ≥ 512).
    pub block_size: u32,
    /// If `true`, write operations return `Error::PermissionDenied`.
    pub read_only: bool,
}

impl RamDiskConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if fields are out of range.
    pub fn validate(&self) -> Result<()> {
        if self.vaddr == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.block_size == 0 || !self.block_size.is_power_of_two() || self.block_size < 512 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return the capacity in blocks.
    pub const fn capacity_blocks(&self) -> u64 {
        self.size / self.block_size as u64
    }
}

// ---------------------------------------------------------------------------
// RamDiskStats
// ---------------------------------------------------------------------------

/// I/O statistics for a RAM disk.
#[derive(Debug, Clone, Copy, Default)]
pub struct RamDiskStats {
    /// Read requests served.
    pub reads: u64,
    /// Write requests served.
    pub writes: u64,
    /// Bytes read.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Requests rejected (out of range or write-protected).
    pub errors: u64,
}

// ---------------------------------------------------------------------------
// RamDisk
// ---------------------------------------------------------------------------

/// RAM disk block device.
pub struct RamDisk {
    /// Device configuration.
    config: RamDiskConfig,
    /// I/O statistics.
    stats: RamDiskStats,
    /// Device is online.
    online: bool,
}

impl RamDisk {
    /// Create a new RAM disk from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the configuration is invalid.
    pub fn new(config: RamDiskConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            stats: RamDiskStats::default(),
            online: false,
        })
    }

    /// Bring the device online.
    pub fn init(&mut self) -> Result<()> {
        self.online = true;
        Ok(())
    }

    /// Take the device offline.
    pub fn shutdown(&mut self) {
        self.online = false;
    }

    /// Return `true` if the device is online.
    pub const fn is_online(&self) -> bool {
        self.online
    }

    /// Return `true` if the device is write-protected.
    pub const fn is_read_only(&self) -> bool {
        self.config.read_only
    }

    /// Read `buf.len()` bytes starting at byte `offset`.
    ///
    /// # Errors
    ///
    /// - [`Error::IoError`] if not online.
    /// - [`Error::InvalidArgument`] if the range exceeds device size.
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        let len = buf.len() as u64;
        let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > self.config.size {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }
        let src = (self.config.vaddr + offset) as *const u8;
        // SAFETY: The backing region was validated at construction. The range
        // [offset, offset+len) is within [0, config.size).
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
        }
        self.stats.reads += 1;
        self.stats.bytes_read += len;
        Ok(())
    }

    /// Write `buf` to the device at byte `offset`.
    ///
    /// # Errors
    ///
    /// - [`Error::IoError`] if not online.
    /// - [`Error::PermissionDenied`] if the device is read-only.
    /// - [`Error::InvalidArgument`] if the range exceeds device size.
    pub fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        if self.config.read_only {
            self.stats.errors += 1;
            return Err(Error::PermissionDenied);
        }
        let len = buf.len() as u64;
        let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > self.config.size {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }
        let dst = (self.config.vaddr + offset) as *mut u8;
        // SAFETY: Backing region validated; range is within bounds; not read-only.
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, buf.len());
        }
        self.stats.writes += 1;
        self.stats.bytes_written += len;
        Ok(())
    }

    /// Read one block at LBA `lba` into `buf`.
    ///
    /// `buf` must be exactly `block_size` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf.len() != block_size`.
    pub fn read_block(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        let bs = self.config.block_size as usize;
        if buf.len() != bs {
            return Err(Error::InvalidArgument);
        }
        self.read(lba * bs as u64, buf)
    }

    /// Write one block at LBA `lba` from `buf`.
    ///
    /// `buf` must be exactly `block_size` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf.len() != block_size`.
    pub fn write_block(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        let bs = self.config.block_size as usize;
        if buf.len() != bs {
            return Err(Error::InvalidArgument);
        }
        self.write(lba * bs as u64, buf)
    }

    /// Flush — no-op for RAM disk.
    pub fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Return current statistics.
    pub const fn stats(&self) -> RamDiskStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = RamDiskStats::default();
    }

    /// Return the block size in bytes.
    pub const fn block_size(&self) -> u32 {
        self.config.block_size
    }

    /// Return the device capacity in blocks.
    pub const fn capacity(&self) -> u64 {
        self.config.capacity_blocks()
    }

    /// Return the total size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.config.size
    }

    /// Return the virtual base address of the backing store.
    pub const fn vaddr(&self) -> u64 {
        self.config.vaddr
    }

    /// Set write-protect mode.
    pub fn set_read_only(&mut self, ro: bool) {
        self.config.read_only = ro;
    }
}

// ---------------------------------------------------------------------------
// RamDiskRegistry
// ---------------------------------------------------------------------------

/// Registry of RAM disk instances.
pub struct RamDiskRegistry {
    disks: [Option<RamDisk>; MAX_RAMDISKS],
    count: usize,
}

impl RamDiskRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<RamDisk> = None;
        Self {
            disks: [NONE; MAX_RAMDISKS],
            count: 0,
        }
    }

    /// Register a RAM disk. Returns its device index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, disk: RamDisk) -> Result<usize> {
        if self.count >= MAX_RAMDISKS {
            return Err(Error::OutOfMemory);
        }
        let id = self.count;
        self.disks[id] = Some(disk);
        self.count += 1;
        Ok(id)
    }

    /// Get a reference to a disk by index.
    pub fn get(&self, id: usize) -> Option<&RamDisk> {
        self.disks.get(id)?.as_ref()
    }

    /// Get a mutable reference to a disk by index.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut RamDisk> {
        self.disks.get_mut(id)?.as_mut()
    }

    /// Return the count of registered disks.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no disks are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for RamDiskRegistry {
    fn default() -> Self {
        Self::new()
    }
}
