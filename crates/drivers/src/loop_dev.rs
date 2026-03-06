// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Loop block device.
//!
//! The loop device allows a regular file (or memory region) to be used
//! as a block device. Common uses:
//! - Mounting disk images (`.img`, `.iso`, `.vhd`).
//! - Encrypted container files.
//! - Disk image creation and testing.
//!
//! # Design
//!
//! [`LoopDevice`] maps a logical block address range to a backing store
//! described by a virtual address + size. It differs from [`RamDisk`]
//! in that it adds:
//! - An optional byte `offset` into the backing store (skip a header).
//! - Optional read-only enforcement.
//! - A `name` field for identifying the backing file path.
//!
//! Since ONCRIX is `no_std`, the backing store is passed as a raw virtual
//! address range (mapped by the VFS layer before calling `attach`).
//!
//! Reference: Linux `drivers/block/loop.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default block size (512 bytes).
pub const LOOP_BLOCK_SIZE: u32 = 512;

/// Maximum backing-store name length.
pub const LOOP_NAME_LEN: usize = 64;

/// Maximum number of loop devices.
pub const MAX_LOOP_DEVICES: usize = 16;

// ---------------------------------------------------------------------------
// LoopState
// ---------------------------------------------------------------------------

/// Lifecycle state of a loop device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoopState {
    /// No backing store attached.
    #[default]
    Detached,
    /// Backing store attached and online.
    Attached,
    /// Device is being torn down.
    Detaching,
}

// ---------------------------------------------------------------------------
// LoopConfig
// ---------------------------------------------------------------------------

/// Configuration for an attached loop device.
#[derive(Debug, Clone, Copy)]
pub struct LoopConfig {
    /// Virtual address of the backing store start.
    pub vaddr: u64,
    /// Total size of the backing store in bytes.
    pub backing_size: u64,
    /// Byte offset into the backing store (e.g., to skip a partition table).
    pub data_offset: u64,
    /// Block size in bytes (must be power of two, ≥ 512).
    pub block_size: u32,
    /// If `true`, write operations are rejected.
    pub read_only: bool,
    /// Human-readable name (e.g., file path), null-terminated.
    pub name: [u8; LOOP_NAME_LEN],
}

impl LoopConfig {
    /// Create a minimal config from a virtual address and size.
    pub fn from_vaddr(vaddr: u64, size: u64) -> Self {
        Self {
            vaddr,
            backing_size: size,
            data_offset: 0,
            block_size: LOOP_BLOCK_SIZE,
            read_only: false,
            name: [0u8; LOOP_NAME_LEN],
        }
    }

    /// Set the name from a byte slice (truncated to `LOOP_NAME_LEN - 1`).
    pub fn set_name(&mut self, name: &[u8]) {
        let copy_len = name.len().min(LOOP_NAME_LEN - 1);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name[copy_len] = 0;
    }

    /// Return the effective data size (backing_size minus data_offset).
    pub const fn data_size(&self) -> u64 {
        self.backing_size.saturating_sub(self.data_offset)
    }

    /// Return the capacity in blocks.
    pub const fn capacity_blocks(&self) -> u64 {
        self.data_size() / self.block_size as u64
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.vaddr == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.data_offset >= self.backing_size {
            return Err(Error::InvalidArgument);
        }
        if self.block_size == 0 || !self.block_size.is_power_of_two() || self.block_size < 512 {
            return Err(Error::InvalidArgument);
        }
        if self.data_size() == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LoopStats
// ---------------------------------------------------------------------------

/// I/O statistics for a loop device.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopStats {
    /// Read requests.
    pub reads: u64,
    /// Write requests.
    pub writes: u64,
    /// Bytes read.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Errors.
    pub errors: u64,
}

// ---------------------------------------------------------------------------
// LoopDevice
// ---------------------------------------------------------------------------

/// Loop block device instance.
pub struct LoopDevice {
    /// Device number (minor number equivalent).
    id: usize,
    /// Current state.
    state: LoopState,
    /// Configuration (valid only when `state == Attached`).
    config: Option<LoopConfig>,
    /// I/O statistics.
    stats: LoopStats,
}

impl LoopDevice {
    /// Create a detached loop device with the given `id`.
    pub const fn new(id: usize) -> Self {
        Self {
            id,
            state: LoopState::Detached,
            config: None,
            stats: LoopStats {
                reads: 0,
                writes: 0,
                bytes_read: 0,
                bytes_written: 0,
                errors: 0,
            },
        }
    }

    /// Attach a backing store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if already attached.
    /// Returns [`Error::InvalidArgument`] if the config is invalid.
    pub fn attach(&mut self, config: LoopConfig) -> Result<()> {
        if self.state != LoopState::Detached {
            return Err(Error::AlreadyExists);
        }
        config.validate()?;
        self.config = Some(config);
        self.state = LoopState::Attached;
        Ok(())
    }

    /// Detach the backing store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not attached.
    pub fn detach(&mut self) -> Result<()> {
        if self.state != LoopState::Attached {
            return Err(Error::IoError);
        }
        self.state = LoopState::Detaching;
        self.config = None;
        self.state = LoopState::Detached;
        Ok(())
    }

    /// Return the current device state.
    pub const fn state(&self) -> LoopState {
        self.state
    }

    /// Return the device id.
    pub const fn id(&self) -> usize {
        self.id
    }

    /// Return a reference to the config if attached.
    pub const fn config(&self) -> Option<&LoopConfig> {
        self.config.as_ref()
    }

    fn require_attached(&self) -> Result<&LoopConfig> {
        self.config.as_ref().ok_or(Error::IoError)
    }

    /// Read `buf.len()` bytes at byte `offset` in the logical address space.
    ///
    /// # Errors
    ///
    /// - [`Error::IoError`] if not attached.
    /// - [`Error::InvalidArgument`] if range exceeds device size.
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let cfg = self.require_attached()?;
        let data_size = cfg.data_size();
        let len = buf.len() as u64;
        let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > data_size {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }
        let backing_offset = cfg.data_offset + offset;
        let src = (cfg.vaddr + backing_offset) as *const u8;
        // SAFETY: Backing region was validated at attach time. Range is within
        // [data_offset, data_offset + data_size).
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
        }
        self.stats.reads += 1;
        self.stats.bytes_read += len;
        Ok(())
    }

    /// Write `buf` at byte `offset` in the logical address space.
    ///
    /// # Errors
    ///
    /// - [`Error::IoError`] if not attached.
    /// - [`Error::PermissionDenied`] if read-only.
    /// - [`Error::InvalidArgument`] if range exceeds device size.
    pub fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let cfg = self.require_attached()?;
        if cfg.read_only {
            self.stats.errors += 1;
            return Err(Error::PermissionDenied);
        }
        let data_size = cfg.data_size();
        let len = buf.len() as u64;
        let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > data_size {
            self.stats.errors += 1;
            return Err(Error::InvalidArgument);
        }
        let backing_offset = cfg.data_offset + offset;
        let dst = (cfg.vaddr + backing_offset) as *mut u8;
        // SAFETY: Range and write-protect validated above.
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, buf.len());
        }
        self.stats.writes += 1;
        self.stats.bytes_written += len;
        Ok(())
    }

    /// Read one block at LBA `lba`.
    ///
    /// `buf` must be exactly `block_size` bytes.
    pub fn read_block(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        let bs = {
            let cfg = self.require_attached()?;
            cfg.block_size as usize
        };
        if buf.len() != bs {
            return Err(Error::InvalidArgument);
        }
        self.read(lba * bs as u64, buf)
    }

    /// Write one block at LBA `lba`.
    ///
    /// `buf` must be exactly `block_size` bytes.
    pub fn write_block(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        let bs = {
            let cfg = self.require_attached()?;
            cfg.block_size as usize
        };
        if buf.len() != bs {
            return Err(Error::InvalidArgument);
        }
        self.write(lba * bs as u64, buf)
    }

    /// Flush — no-op for memory-backed loop device.
    pub fn flush(&self) -> Result<()> {
        if self.state != LoopState::Attached {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Return current I/O statistics.
    pub const fn stats(&self) -> LoopStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = LoopStats::default();
    }

    /// Return capacity in blocks (0 if detached).
    pub fn capacity(&self) -> u64 {
        self.config.as_ref().map_or(0, |c| c.capacity_blocks())
    }

    /// Return block size (0 if detached).
    pub fn block_size(&self) -> u32 {
        self.config.as_ref().map_or(0, |c| c.block_size)
    }
}

// ---------------------------------------------------------------------------
// LoopDeviceRegistry
// ---------------------------------------------------------------------------

/// Registry of loop device instances.
pub struct LoopDeviceRegistry {
    devices: [Option<LoopDevice>; MAX_LOOP_DEVICES],
    count: usize,
}

impl LoopDeviceRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<LoopDevice> = None;
        Self {
            devices: [NONE; MAX_LOOP_DEVICES],
            count: 0,
        }
    }

    /// Register a loop device. Returns its slot index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if full.
    pub fn register(&mut self, dev: LoopDevice) -> Result<usize> {
        let slot = self
            .devices
            .iter()
            .position(|d| d.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.devices[slot] = Some(dev);
        self.count += 1;
        Ok(slot)
    }

    /// Get a reference to a device by index.
    pub fn get(&self, id: usize) -> Option<&LoopDevice> {
        self.devices.get(id)?.as_ref()
    }

    /// Get a mutable reference to a device by index.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut LoopDevice> {
        self.devices.get_mut(id)?.as_mut()
    }

    /// Return the count of registered devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for LoopDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
