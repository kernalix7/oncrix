// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block device abstraction.
//!
//! Provides the kernel-side representation of block devices (`block_device`
//! in Linux). Each block device has a major:minor number, a sector size,
//! a capacity in sectors, and a set of operations.
//!
//! # Device model
//!
//! - `BlockDev` — represents one physical or logical block device.
//! - `BlockDevOps` — trait for device-specific read/write operations.
//! - `BlockDevRegistry` — global registry of registered block devices.
//!
//! Block devices are identified by a `DevNum` (major << 20 | minor).
//!
//! # References
//!
//! - Linux `block_device` struct, `genhd.h`, `blkdev.h`
//! - POSIX.1-2024 `stat` — `st_rdev` field for block devices

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of registered block devices.
pub const MAX_BLOCK_DEVS: usize = 64;

/// Default sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum device name length.
pub const BDEV_NAME_LEN: usize = 32;

// ── DevNum ───────────────────────────────────────────────────────────

/// A device number (major:minor encoded as `u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DevNum(pub u32);

impl DevNum {
    /// Encode `major` and `minor` into a `DevNum`.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self(((major as u32) << 16) | (minor as u32))
    }

    /// Extract the major number.
    pub const fn major(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Extract the minor number.
    pub const fn minor(self) -> u16 {
        self.0 as u16
    }
}

// ── BlockDevOps ──────────────────────────────────────────────────────

/// Operations a block device driver must implement.
pub trait BlockDevOps {
    /// Read `nr_sectors` sectors starting at `sector` into `buf`.
    fn read_sectors(&mut self, sector: u64, nr_sectors: u32, buf: &mut [u8]) -> Result<()>;

    /// Write `nr_sectors` sectors from `buf` starting at `sector`.
    fn write_sectors(&mut self, sector: u64, nr_sectors: u32, buf: &[u8]) -> Result<()>;

    /// Flush the device write cache.
    fn flush(&mut self) -> Result<()>;
}

// ── BlockDevInfo ─────────────────────────────────────────────────────

/// Static information about a block device.
#[derive(Clone, Copy)]
pub struct BlockDevInfo {
    /// Device number.
    pub dev: DevNum,
    /// Device name (null-terminated, up to `BDEV_NAME_LEN` chars).
    pub name: [u8; BDEV_NAME_LEN],
    /// Logical sector size (bytes).
    pub sector_size: u32,
    /// Physical sector size (bytes).
    pub phys_sector_size: u32,
    /// Total capacity in 512-byte sectors.
    pub nr_sectors: u64,
    /// Read-only flag.
    pub read_only: bool,
    /// Whether the device is removable.
    pub removable: bool,
}

impl BlockDevInfo {
    /// Create a new block device info record.
    pub fn new(
        dev: DevNum,
        name: &[u8],
        sector_size: u32,
        nr_sectors: u64,
        read_only: bool,
    ) -> Self {
        let mut name_buf = [0u8; BDEV_NAME_LEN];
        let n = name.len().min(BDEV_NAME_LEN - 1);
        name_buf[..n].copy_from_slice(&name[..n]);
        Self {
            dev,
            name: name_buf,
            sector_size,
            phys_sector_size: sector_size,
            nr_sectors,
            read_only,
            removable: false,
        }
    }

    /// Returns the device capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.nr_sectors * 512
    }

    /// Returns the device name as a byte slice (up to the first null byte).
    pub fn name_str(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(BDEV_NAME_LEN);
        &self.name[..end]
    }
}

// ── BlockDevRegistry ─────────────────────────────────────────────────

/// Global block device registry.
pub struct BlockDevRegistry {
    devices: [Option<BlockDevInfo>; MAX_BLOCK_DEVS],
    count: usize,
}

impl BlockDevRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_BLOCK_DEVS],
            count: 0,
        }
    }

    /// Register a new block device.
    pub fn register(&mut self, info: BlockDevInfo) -> Result<()> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.dev == info.dev {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.count >= MAX_BLOCK_DEVS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(info);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a block device by device number.
    pub fn unregister(&mut self, dev: DevNum) -> Result<()> {
        for slot in self.devices.iter_mut() {
            if let Some(d) = slot {
                if d.dev == dev {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a device by device number.
    pub fn find(&self, dev: DevNum) -> Option<&BlockDevInfo> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.dev == dev {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Look up a device by name (byte slice, null-terminated or exact).
    pub fn find_by_name(&self, name: &[u8]) -> Option<&BlockDevInfo> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.name_str() == name {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Returns the number of registered devices.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all registered devices.
    pub fn iter(&self) -> impl Iterator<Item = &BlockDevInfo> {
        self.devices.iter().filter_map(|s| s.as_ref())
    }
}

impl Default for BlockDevRegistry {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
