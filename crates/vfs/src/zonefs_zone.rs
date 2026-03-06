// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ZoneFS zone management for zoned block devices.
//!
//! ZoneFS exposes zones of a zoned block device as files in a filesystem.
//! Each zone is mapped to a file: sequential write zones appear as regular
//! files in the `seq/` directory; conventional zones appear in `cnv/`.
//!
//! # Zone Types
//!
//! Zoned block devices (e.g., SMR drives, ZNS SSDs) have three zone types:
//! - **Conventional**: Can be written at any LBA within the zone.
//! - **Sequential Write Required (SWR)**: Must be written sequentially from
//!   the write pointer.
//! - **Sequential Write Preferred (SWP)**: Sequential writes preferred but
//!   random writes are allowed.
//!
//! # Write Pointer
//!
//! Sequential zones maintain a hardware write pointer. The write pointer
//! advances after each successful write. A zone must be reset before it
//! can be rewritten from the beginning.

use oncrix_lib::{Error, Result};

/// Zone type codes as reported by the block device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ZoneType {
    /// Conventional zone (random write allowed).
    Conventional = 0x01,
    /// Sequential write required zone.
    SeqWriteRequired = 0x02,
    /// Sequential write preferred zone.
    SeqWritePreferred = 0x03,
}

impl Default for ZoneType {
    fn default() -> Self {
        Self::Conventional
    }
}

impl ZoneType {
    /// Parses a zone type from its byte value.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::Conventional),
            0x02 => Ok(Self::SeqWriteRequired),
            0x03 => Ok(Self::SeqWritePreferred),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns `true` if this zone requires sequential writes.
    pub const fn is_sequential(&self) -> bool {
        matches!(self, Self::SeqWriteRequired | Self::SeqWritePreferred)
    }
}

/// Zone condition (state of the zone as reported by the device).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ZoneCondition {
    /// Zone is not write-open.
    NotWriteOpen = 0x00,
    /// Zone is empty (write pointer at start of zone).
    Empty = 0x01,
    /// Zone is implicitly open.
    ImplicitlyOpen = 0x02,
    /// Zone is explicitly open.
    ExplicitlyOpen = 0x03,
    /// Zone is closed.
    Closed = 0x04,
    /// Zone is full (write pointer at end of zone).
    Full = 0x0E,
    /// Zone is read-only.
    ReadOnly = 0x0D,
    /// Zone is offline.
    Offline = 0x0F,
}

impl Default for ZoneCondition {
    fn default() -> Self {
        Self::NotWriteOpen
    }
}

impl ZoneCondition {
    /// Parses a zone condition from its nibble value.
    pub fn from_nibble(n: u8) -> Result<Self> {
        match n & 0x0F {
            0x00 => Ok(Self::NotWriteOpen),
            0x01 => Ok(Self::Empty),
            0x02 => Ok(Self::ImplicitlyOpen),
            0x03 => Ok(Self::ExplicitlyOpen),
            0x04 => Ok(Self::Closed),
            0x0D => Ok(Self::ReadOnly),
            0x0E => Ok(Self::Full),
            0x0F => Ok(Self::Offline),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns `true` if the zone can currently accept writes.
    pub const fn is_writable(&self) -> bool {
        matches!(
            self,
            Self::Empty | Self::ImplicitlyOpen | Self::ExplicitlyOpen | Self::Closed
        )
    }
}

/// A zone descriptor as tracked by ZoneFS.
#[derive(Clone, Copy, Default)]
pub struct ZoneDescriptor {
    /// Zone type.
    pub zone_type: ZoneType,
    /// Zone condition.
    pub condition: ZoneCondition,
    /// Starting LBA of the zone (in 512-byte sectors).
    pub start_lba: u64,
    /// Length of the zone in sectors.
    pub length: u64,
    /// Current write pointer (in sectors); only valid for sequential zones.
    pub write_pointer: u64,
    /// Zone capacity (may be less than `length` for ZNS devices).
    pub capacity: u64,
    /// Zone number (index in the device zone list).
    pub zone_no: u32,
}

impl ZoneDescriptor {
    /// Returns the number of bytes written in this zone.
    pub fn bytes_written(&self) -> u64 {
        if self.zone_type.is_sequential() {
            (self.write_pointer - self.start_lba) * 512
        } else {
            0
        }
    }

    /// Returns the remaining capacity in bytes.
    pub fn bytes_remaining(&self) -> u64 {
        let cap_bytes = self.capacity * 512;
        let written = self.bytes_written();
        if cap_bytes > written {
            cap_bytes - written
        } else {
            0
        }
    }

    /// Returns `true` if the zone is full.
    pub const fn is_full(&self) -> bool {
        matches!(self.condition, ZoneCondition::Full)
    }

    /// Returns `true` if this is a conventional zone.
    pub const fn is_conventional(&self) -> bool {
        matches!(self.zone_type, ZoneType::Conventional)
    }

    /// Simulates a zone reset: moves write pointer to start and marks empty.
    pub fn reset(&mut self) -> Result<()> {
        if self.is_conventional() {
            return Err(Error::InvalidArgument);
        }
        self.write_pointer = self.start_lba;
        self.condition = ZoneCondition::Empty;
        Ok(())
    }

    /// Simulates advancing the write pointer after a write of `sectors` sectors.
    pub fn advance_wp(&mut self, sectors: u64) -> Result<()> {
        if !self.zone_type.is_sequential() {
            return Ok(());
        }
        let new_wp = self.write_pointer + sectors;
        let zone_end = self.start_lba + self.capacity;
        if new_wp > zone_end {
            return Err(Error::InvalidArgument);
        }
        self.write_pointer = new_wp;
        if new_wp == zone_end {
            self.condition = ZoneCondition::Full;
        }
        Ok(())
    }
}

/// ZoneFS zone table — tracks all zones for a mounted zoned device.
pub struct ZoneTable {
    zones: [ZoneDescriptor; 256],
    count: usize,
}

impl Default for ZoneTable {
    fn default() -> Self {
        Self {
            zones: [ZoneDescriptor::default(); 256],
            count: 0,
        }
    }
}

impl ZoneTable {
    /// Creates an empty zone table.
    pub const fn new() -> Self {
        Self {
            zones: [ZoneDescriptor {
                zone_type: ZoneType::Conventional,
                condition: ZoneCondition::NotWriteOpen,
                start_lba: 0,
                length: 0,
                write_pointer: 0,
                capacity: 0,
                zone_no: 0,
            }; 256],
            count: 0,
        }
    }

    /// Adds a zone descriptor to the table.
    pub fn add(&mut self, zone: ZoneDescriptor) -> Result<()> {
        if self.count >= 256 {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.count] = zone;
        self.count += 1;
        Ok(())
    }

    /// Looks up a zone by zone number.
    pub fn get(&self, zone_no: u32) -> Option<&ZoneDescriptor> {
        self.zones[..self.count]
            .iter()
            .find(|z| z.zone_no == zone_no)
    }

    /// Returns a mutable reference to a zone by zone number.
    pub fn get_mut(&mut self, zone_no: u32) -> Option<&mut ZoneDescriptor> {
        self.zones[..self.count]
            .iter_mut()
            .find(|z| z.zone_no == zone_no)
    }

    /// Counts the number of conventional zones.
    pub fn conventional_count(&self) -> usize {
        self.zones[..self.count]
            .iter()
            .filter(|z| z.is_conventional())
            .count()
    }

    /// Counts the number of sequential zones.
    pub fn sequential_count(&self) -> usize {
        self.zones[..self.count]
            .iter()
            .filter(|z| z.zone_type.is_sequential())
            .count()
    }
}
