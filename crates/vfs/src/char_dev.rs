// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Character device abstraction.
//!
//! Provides the kernel-side character device infrastructure: registration,
//! lookup, and the `CharDevOps` trait that drivers implement to handle
//! `open`, `read`, `write`, `ioctl`, and `close` operations.
//!
//! Character devices are identified by a major:minor `DevNum`. The major
//! number identifies the driver class; the minor number identifies the
//! specific device instance.
//!
//! # Standard major numbers (subset)
//!
//! | Major | Device class |
//! |-------|-------------|
//! | 1 | Memory devices (`/dev/null`, `/dev/zero`, `/dev/random`) |
//! | 4 | TTY devices |
//! | 5 | Alternate TTY (`/dev/tty`, `/dev/console`) |
//! | 10 | Miscellaneous |
//!
//! # References
//!
//! - Linux `cdev.h`, `char_dev.c`
//! - POSIX.1-2024 `open()` — `O_RDONLY`, `O_WRONLY`, `O_RDWR`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of registered character devices.
pub const MAX_CHAR_DEVS: usize = 256;

/// Maximum device name length.
pub const CDEV_NAME_LEN: usize = 32;

/// Major number for memory devices.
pub const MEM_MAJOR: u16 = 1;
/// Major number for TTY devices.
pub const TTY_MAJOR: u16 = 4;
/// Major number for miscellaneous devices.
pub const MISC_MAJOR: u16 = 10;

// ── DevNum ───────────────────────────────────────────────────────────

/// A character device number (major:minor encoded as `u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CDevNum(pub u32);

impl CDevNum {
    /// Encode major and minor into a `CDevNum`.
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

// ── CharDevOps ───────────────────────────────────────────────────────

/// Operations a character device driver must implement.
pub trait CharDevOps {
    /// Open the device. Returns a driver-defined file token.
    fn open(&mut self, flags: u32) -> Result<u64>;

    /// Read up to `buf.len()` bytes; returns bytes read.
    fn read(&mut self, token: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write `buf` to the device; returns bytes written.
    fn write(&mut self, token: u64, buf: &[u8]) -> Result<usize>;

    /// Device-specific control command.
    fn ioctl(&mut self, token: u64, cmd: u32, arg: u64) -> Result<i64>;

    /// Close the device.
    fn close(&mut self, token: u64) -> Result<()>;
}

// ── CharDevInfo ──────────────────────────────────────────────────────

/// Registration record for a character device.
#[derive(Clone, Copy)]
pub struct CharDevInfo {
    /// Device number.
    pub dev: CDevNum,
    /// Human-readable name.
    pub name: [u8; CDEV_NAME_LEN],
    /// Minor number range this registration covers (inclusive).
    pub minor_start: u16,
    /// Last minor number in the range.
    pub minor_end: u16,
}

impl CharDevInfo {
    /// Create a new `CharDevInfo` for a single minor number.
    pub fn new(major: u16, minor: u16, name: &[u8]) -> Self {
        let mut name_buf = [0u8; CDEV_NAME_LEN];
        let n = name.len().min(CDEV_NAME_LEN - 1);
        name_buf[..n].copy_from_slice(&name[..n]);
        Self {
            dev: CDevNum::new(major, minor),
            name: name_buf,
            minor_start: minor,
            minor_end: minor,
        }
    }

    /// Create a registration covering a range of minor numbers.
    pub fn new_range(major: u16, minor_start: u16, minor_end: u16, name: &[u8]) -> Self {
        let mut info = Self::new(major, minor_start, name);
        info.minor_end = minor_end;
        info
    }

    /// Returns `true` if `dev` falls within this registration's range.
    pub fn owns(&self, dev: CDevNum) -> bool {
        dev.major() == self.dev.major()
            && dev.minor() >= self.minor_start
            && dev.minor() <= self.minor_end
    }

    /// Returns the device name as a byte slice.
    pub fn name_str(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(CDEV_NAME_LEN);
        &self.name[..end]
    }
}

// ── CharDevRegistry ──────────────────────────────────────────────────

/// Global character device registry.
pub struct CharDevRegistry {
    devices: [Option<CharDevInfo>; MAX_CHAR_DEVS],
    count: usize,
}

impl CharDevRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_CHAR_DEVS],
            count: 0,
        }
    }

    /// Register a character device.
    ///
    /// Returns `AlreadyExists` if the major:minor range overlaps an existing
    /// registration.
    pub fn register(&mut self, info: CharDevInfo) -> Result<()> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.dev.major() == info.dev.major() {
                    // Check for minor range overlap.
                    if d.minor_start <= info.minor_end && info.minor_start <= d.minor_end {
                        return Err(Error::AlreadyExists);
                    }
                }
            }
        }
        if self.count >= MAX_CHAR_DEVS {
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

    /// Unregister a character device by device number.
    pub fn unregister(&mut self, dev: CDevNum) -> Result<()> {
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

    /// Look up the registration that owns `dev`.
    pub fn find(&self, dev: CDevNum) -> Option<&CharDevInfo> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.owns(dev) {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Look up by name.
    pub fn find_by_name(&self, name: &[u8]) -> Option<&CharDevInfo> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.name_str() == name {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Returns the number of registered character devices.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all registered devices.
    pub fn iter(&self) -> impl Iterator<Item = &CharDevInfo> {
        self.devices.iter().filter_map(|s| s.as_ref())
    }
}

impl Default for CharDevRegistry {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
