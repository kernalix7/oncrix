// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Null block device driver.
//!
//! Provides a software-only block device that discards all writes and
//! returns zeroes (or optionally a fixed pattern) for reads.  Useful for:
//!
//! - Performance benchmarking the block I/O stack without hardware I/O overhead
//! - Testing the block layer, scheduler, and request queues in isolation
//! - Acting as a `/dev/null` equivalent at the block level
//!
//! # Design
//!
//! - Configurable block size and device capacity
//! - Optional "zero-read" mode (reads return 0x00) or "pattern" mode
//! - Statistics tracking (read/write request counts, bytes transferred)
//! - Up to [`MAX_NULL_DEVICES`] devices in the registry
//!
//! Reference: Linux `drivers/block/null_blk/` for design inspiration.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of null block devices that can be registered.
pub const MAX_NULL_DEVICES: usize = 8;

/// Default block size in bytes (512 bytes, standard sector size).
pub const DEFAULT_BLOCK_SIZE: u32 = 512;

/// Default device capacity: 1 GiB expressed in blocks of 512 bytes.
pub const DEFAULT_CAPACITY_BLOCKS: u64 = 1024 * 1024 * 1024 / DEFAULT_BLOCK_SIZE as u64;

/// Maximum supported block size (4 MiB).
pub const MAX_BLOCK_SIZE: u32 = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// NullBlkMode
// ---------------------------------------------------------------------------

/// Read-data mode for the null block device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NullBlkMode {
    /// Reads return all zeroes (0x00).
    #[default]
    Zero,
    /// Reads return a repeating single byte pattern.
    Pattern(u8),
    /// Reads return the block number (modulo 256) in each byte.
    BlockAddress,
}

// ---------------------------------------------------------------------------
// NullBlkConfig
// ---------------------------------------------------------------------------

/// Configuration for a null block device.
#[derive(Debug, Clone, Copy)]
pub struct NullBlkConfig {
    /// Block (sector) size in bytes. Must be a power of two, ≥ 512.
    pub block_size: u32,
    /// Capacity in blocks.
    pub capacity: u64,
    /// Data mode for reads.
    pub mode: NullBlkMode,
}

impl Default for NullBlkConfig {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            capacity: DEFAULT_CAPACITY_BLOCKS,
            mode: NullBlkMode::Zero,
        }
    }
}

impl NullBlkConfig {
    /// Validate configuration fields.
    pub fn validate(&self) -> Result<()> {
        if self.block_size == 0
            || !self.block_size.is_power_of_two()
            || self.block_size > MAX_BLOCK_SIZE
        {
            return Err(Error::InvalidArgument);
        }
        if self.capacity == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return total device size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.capacity * self.block_size as u64
    }
}

// ---------------------------------------------------------------------------
// NullBlkStats
// ---------------------------------------------------------------------------

/// I/O statistics for a null block device.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullBlkStats {
    /// Total read requests submitted.
    pub reads: u64,
    /// Total write requests submitted.
    pub writes: u64,
    /// Total bytes read.
    pub bytes_read: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Number of requests that returned an error (out-of-range).
    pub errors: u64,
}

// ---------------------------------------------------------------------------
// NullBlk
// ---------------------------------------------------------------------------

/// Null block device instance.
pub struct NullBlk {
    /// Device configuration.
    config: NullBlkConfig,
    /// I/O statistics.
    stats: NullBlkStats,
    /// Device is operational.
    online: bool,
}

impl NullBlk {
    /// Create a new null block device with the given configuration.
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(config: NullBlkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            stats: NullBlkStats::default(),
            online: false,
        })
    }

    /// Create a null block device with default settings.
    pub fn default_device() -> Result<Self> {
        Self::new(NullBlkConfig::default())
    }

    /// Initialize and bring the device online.
    pub fn init(&mut self) -> Result<()> {
        self.online = true;
        Ok(())
    }

    /// Shut down the device.
    pub fn shutdown(&mut self) {
        self.online = false;
    }

    /// Return true if the device is online.
    pub const fn is_online(&self) -> bool {
        self.online
    }

    /// Read `buf.len()` bytes starting at byte offset `offset`.
    ///
    /// The buffer is filled according to the configured [`NullBlkMode`].
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::InvalidArgument)?;
        if end > self.config.size_bytes() {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }

        match self.config.mode {
            NullBlkMode::Zero => {
                buf.fill(0x00);
            }
            NullBlkMode::Pattern(p) => {
                buf.fill(p);
            }
            NullBlkMode::BlockAddress => {
                let bs = self.config.block_size as u64;
                for (i, slot) in buf.iter_mut().enumerate() {
                    let block = (offset + i as u64) / bs;
                    *slot = (block & 0xFF) as u8;
                }
            }
        }

        self.stats.reads += 1;
        self.stats.bytes_read += buf.len() as u64;
        Ok(())
    }

    /// Write `buf` to the device at byte `offset` (data is discarded).
    pub fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::InvalidArgument)?;
        if end > self.config.size_bytes() {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }
        // Writes are a no-op for the null device
        self.stats.writes += 1;
        self.stats.bytes_written += buf.len() as u64;
        Ok(())
    }

    /// Read one block at logical block address `lba` into `buf`.
    ///
    /// `buf` must be exactly `block_size` bytes.
    pub fn read_block(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        let bs = self.config.block_size as usize;
        if buf.len() != bs {
            return Err(Error::InvalidArgument);
        }
        self.read(lba * bs as u64, buf)
    }

    /// Write one block at logical block address `lba` from `buf`.
    ///
    /// `buf` must be exactly `block_size` bytes.
    pub fn write_block(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        let bs = self.config.block_size as usize;
        if buf.len() != bs {
            return Err(Error::InvalidArgument);
        }
        self.write(lba * bs as u64, buf)
    }

    /// Flush — a no-op for the null device (always returns Ok).
    pub fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Discard (trim) a range — a no-op for the null device.
    pub fn discard(&mut self, offset: u64, len: u64) -> Result<()> {
        let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > self.config.size_bytes() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return a snapshot of the I/O statistics.
    pub const fn stats(&self) -> NullBlkStats {
        self.stats
    }

    /// Reset I/O statistics to zero.
    pub fn reset_stats(&mut self) {
        self.stats = NullBlkStats::default();
    }

    /// Return the device configuration.
    pub const fn config(&self) -> &NullBlkConfig {
        &self.config
    }

    /// Return the block size in bytes.
    pub const fn block_size(&self) -> u32 {
        self.config.block_size
    }

    /// Return the device capacity in blocks.
    pub const fn capacity(&self) -> u64 {
        self.config.capacity
    }
}

// ---------------------------------------------------------------------------
// NullBlkRegistry
// ---------------------------------------------------------------------------

/// Registry of null block devices.
pub struct NullBlkRegistry {
    devices: [Option<NullBlk>; MAX_NULL_DEVICES],
    count: usize,
}

impl NullBlkRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_NULL_DEVICES],
            count: 0,
        }
    }

    /// Register a null block device. Returns its device index.
    pub fn register(&mut self, dev: NullBlk) -> Result<usize> {
        if self.count >= MAX_NULL_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let id = self.count;
        self.devices[id] = Some(dev);
        self.count += 1;
        Ok(id)
    }

    /// Get a shared reference to a device by index.
    pub fn get(&self, id: usize) -> Option<&NullBlk> {
        self.devices.get(id)?.as_ref()
    }

    /// Get an exclusive reference to a device by index.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut NullBlk> {
        self.devices.get_mut(id)?.as_mut()
    }

    /// Return the count of registered devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return true if no devices are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
