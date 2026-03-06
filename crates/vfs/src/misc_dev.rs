// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Miscellaneous device register.
//!
//! The miscellaneous device framework provides a simplified registration
//! path for character devices that share major number `10` and only need
//! a unique minor number. This avoids wasting a whole major number for
//! simple single-instance devices.
//!
//! # Examples of misc devices
//!
//! - `/dev/null` (minor 3)
//! - `/dev/zero` (minor 5)
//! - `/dev/random` (minor 8)
//! - `/dev/urandom` (minor 9)
//! - `/dev/tty` (minor 0)
//! - `/dev/loop-control` (minor 237)
//! - `/dev/fuse` (minor 229)
//!
//! # References
//!
//! - Linux `misc_register(9)`, `miscdevice.h`
//! - Linux `drivers/char/misc.c`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Major number shared by all miscellaneous devices.
pub const MISC_MAJOR: u16 = 10;

/// Maximum number of registered misc devices.
pub const MAX_MISC_DEVS: usize = 128;

/// Maximum device name length.
pub const MISC_NAME_LEN: usize = 32;

/// Dynamically allocated minor number (driver requests any free minor).
pub const MISC_DYNAMIC_MINOR: u16 = 0xFF;

// Well-known minor numbers.

/// Minor for `/dev/mem`.
pub const MEM_MINOR: u16 = 1;
/// Minor for `/dev/null`.
pub const NULL_MINOR: u16 = 3;
/// Minor for `/dev/zero`.
pub const ZERO_MINOR: u16 = 5;
/// Minor for `/dev/random`.
pub const RANDOM_MINOR: u16 = 8;
/// Minor for `/dev/urandom`.
pub const URANDOM_MINOR: u16 = 9;

// ── MiscDevInfo ──────────────────────────────────────────────────────

/// Registration record for a miscellaneous device.
#[derive(Clone, Copy)]
pub struct MiscDevInfo {
    /// Minor number (unique within major 10).
    pub minor: u16,
    /// Human-readable name (populates `/dev/<name>`).
    pub name: [u8; MISC_NAME_LEN],
    /// File mode bits for the devtmpfs entry.
    pub mode: u32,
}

impl MiscDevInfo {
    /// Create a new misc device info record.
    pub fn new(minor: u16, name: &[u8], mode: u32) -> Self {
        let mut name_buf = [0u8; MISC_NAME_LEN];
        let n = name.len().min(MISC_NAME_LEN - 1);
        name_buf[..n].copy_from_slice(&name[..n]);
        Self {
            minor,
            name: name_buf,
            mode,
        }
    }

    /// Returns the device name as a byte slice.
    pub fn name_str(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MISC_NAME_LEN);
        &self.name[..end]
    }
}

// ── MiscDevRegistry ──────────────────────────────────────────────────

/// Global miscellaneous device registry.
pub struct MiscDevRegistry {
    devices: [Option<MiscDevInfo>; MAX_MISC_DEVS],
    count: usize,
    /// Next minor to assign for dynamic allocation (starts at 64).
    next_dynamic: u16,
}

impl MiscDevRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_MISC_DEVS],
            count: 0,
            next_dynamic: 64,
        }
    }

    /// Register a miscellaneous device.
    ///
    /// If `info.minor` is `MISC_DYNAMIC_MINOR`, a free minor is allocated
    /// automatically. Returns the assigned minor number.
    pub fn register(&mut self, mut info: MiscDevInfo) -> Result<u16> {
        if info.minor == MISC_DYNAMIC_MINOR {
            info.minor = self.alloc_minor()?;
        } else {
            for slot in self.devices.iter() {
                if let Some(d) = slot {
                    if d.minor == info.minor {
                        return Err(Error::AlreadyExists);
                    }
                }
            }
        }
        if self.count >= MAX_MISC_DEVS {
            return Err(Error::OutOfMemory);
        }
        let minor = info.minor;
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(info);
                self.count += 1;
                return Ok(minor);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate the next free dynamic minor number.
    fn alloc_minor(&mut self) -> Result<u16> {
        for candidate in self.next_dynamic..=0xFE {
            let taken = self
                .devices
                .iter()
                .any(|s| s.map_or(false, |d| d.minor == candidate));
            if !taken {
                self.next_dynamic = candidate + 1;
                return Ok(candidate);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a device by minor number.
    pub fn unregister(&mut self, minor: u16) -> Result<()> {
        for slot in self.devices.iter_mut() {
            if let Some(d) = slot {
                if d.minor == minor {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a device by minor number.
    pub fn find(&self, minor: u16) -> Option<&MiscDevInfo> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.minor == minor {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Look up a device by name.
    pub fn find_by_name(&self, name: &[u8]) -> Option<&MiscDevInfo> {
        for slot in self.devices.iter() {
            if let Some(d) = slot {
                if d.name_str() == name {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Returns the number of registered miscellaneous devices.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all registered devices.
    pub fn iter(&self) -> impl Iterator<Item = &MiscDevInfo> {
        self.devices.iter().filter_map(|s| s.as_ref())
    }
}

impl Default for MiscDevRegistry {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
