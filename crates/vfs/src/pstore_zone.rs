// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! pstore zone backend — persistent storage zone management.
//!
//! pstore (persistent store) provides a mechanism for preserving kernel
//! crash logs across reboots. The zone backend (`pstore/zone.c` in Linux)
//! uses a raw block device or RAM area divided into fixed-size zones,
//! with a circular write pattern and zone headers to track validity.
//!
//! # Zone Layout
//!
//! Each zone starts with a 16-byte header followed by the payload data.
//! Zones are written sequentially; the oldest zone is overwritten when
//! the backend wraps around.
//!
//! # Record Types
//!
//! pstore records have types: `DMESG`, `CONSOLE`, `FTRACE`, `MCE`,
//! `PPC_RTAS`, `PPC_OF`, `PPC_COMMON`, `PMSG`, `UNKNOWN`.

use oncrix_lib::{Error, Result};

/// pstore record type identifiers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum PstoreType {
    /// Kernel dmesg (oops / panic log).
    Dmesg = 1,
    /// Console output.
    Console = 2,
    /// Ftrace log.
    Ftrace = 3,
    /// Machine Check Exception record.
    Mce = 4,
    /// Power management log.
    Pmsg = 5,
    /// Unknown record type.
    Unknown = 255,
}

impl Default for PstoreType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl PstoreType {
    /// Parses from a u32.
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Dmesg,
            2 => Self::Console,
            3 => Self::Ftrace,
            4 => Self::Mce,
            5 => Self::Pmsg,
            _ => Self::Unknown,
        }
    }
}

/// Compression type for pstore zone payloads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Compression {
    /// No compression.
    None = 0,
    /// LZ4 compression.
    Lz4 = 1,
    /// Zstd compression.
    Zstd = 2,
}

impl Default for Compression {
    fn default() -> Self {
        Self::None
    }
}

/// A pstore zone header (16 bytes on disk).
#[derive(Clone, Copy, Default)]
pub struct ZoneHeader {
    /// Magic value identifying a valid zone.
    pub magic: u32,
    /// Record type.
    pub record_type: PstoreType,
    /// Compression type.
    pub compression: Compression,
    /// Whether this record was written during a panic.
    pub in_panic: bool,
    /// Sequence number for ordering records.
    pub seq: u32,
    /// Actual payload length in bytes.
    pub payload_len: u32,
}

/// Expected magic number for valid pstore zone headers.
pub const PSTORE_ZONE_MAGIC: u32 = 0x50535A4E; // "PSZN"

impl ZoneHeader {
    /// Parses a zone header from 16 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if magic != PSTORE_ZONE_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let rtype = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let flags = b[8];
        Ok(Self {
            magic,
            record_type: PstoreType::from_u32(rtype),
            compression: match flags & 0x0F {
                1 => Compression::Lz4,
                2 => Compression::Zstd,
                _ => Compression::None,
            },
            in_panic: flags & 0x80 != 0,
            seq: u32::from_le_bytes([b[9], b[10], b[11], b[12]]),
            payload_len: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }

    /// Serializes this header to 16 bytes.
    pub fn to_bytes(&self, b: &mut [u8; 16]) {
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..8].copy_from_slice(&(self.record_type as u32).to_le_bytes());
        let flags = (self.compression as u8) | if self.in_panic { 0x80 } else { 0x00 };
        b[8] = flags;
        b[9..13].copy_from_slice(&self.seq.to_le_bytes());
        b[12..16].copy_from_slice(&self.payload_len.to_le_bytes());
    }

    /// Returns `true` if this header is valid.
    pub const fn is_valid(&self) -> bool {
        self.magic == PSTORE_ZONE_MAGIC
    }
}

/// Size of a pstore zone header in bytes.
pub const ZONE_HEADER_SIZE: usize = 16;

/// A pstore zone descriptor (in-memory tracking struct).
#[derive(Clone, Copy, Default)]
pub struct ZoneDescriptor {
    /// Byte offset of this zone in the backend storage.
    pub offset: u64,
    /// Total size of this zone (header + payload capacity).
    pub size: u32,
    /// Whether this zone contains a valid record.
    pub has_record: bool,
    /// Cached zone header (valid if `has_record`).
    pub header: ZoneHeader,
}

impl ZoneDescriptor {
    /// Returns the payload capacity (zone size minus header).
    pub const fn payload_capacity(&self) -> u32 {
        if (self.size as usize) > ZONE_HEADER_SIZE {
            self.size - ZONE_HEADER_SIZE as u32
        } else {
            0
        }
    }

    /// Returns `true` if this zone can hold a payload of `len` bytes.
    pub const fn can_hold(&self, len: u32) -> bool {
        len <= self.payload_capacity()
    }
}

/// pstore zone backend state.
pub struct PstoreZoneState {
    /// Zone descriptors.
    zones: [ZoneDescriptor; 64],
    /// Number of configured zones.
    num_zones: usize,
    /// Index of the next zone to write.
    write_idx: usize,
    /// Monotonically increasing sequence counter.
    next_seq: u32,
}

impl Default for PstoreZoneState {
    fn default() -> Self {
        Self {
            zones: [ZoneDescriptor::default(); 64],
            num_zones: 0,
            write_idx: 0,
            next_seq: 1,
        }
    }
}

impl PstoreZoneState {
    /// Initialises the zone state with `num_zones` zones of `zone_size` bytes each,
    /// starting at `base_offset`.
    pub fn init(&mut self, base_offset: u64, zone_size: u32, num_zones: usize) -> Result<()> {
        if num_zones > 64 {
            return Err(Error::InvalidArgument);
        }
        for i in 0..num_zones {
            self.zones[i] = ZoneDescriptor {
                offset: base_offset + (i as u64) * (zone_size as u64),
                size: zone_size,
                has_record: false,
                header: ZoneHeader::default(),
            };
        }
        self.num_zones = num_zones;
        self.write_idx = 0;
        Ok(())
    }

    /// Claims the next available write zone, returning its descriptor.
    ///
    /// Advances `write_idx` circularly.
    pub fn claim_write_zone(
        &mut self,
        rtype: PstoreType,
        payload_len: u32,
    ) -> Result<&ZoneDescriptor> {
        if self.num_zones == 0 {
            return Err(Error::NotFound);
        }
        let zone = &self.zones[self.write_idx];
        if !zone.can_hold(payload_len) {
            return Err(Error::InvalidArgument);
        }
        self.write_idx = (self.write_idx + 1) % self.num_zones;
        // Write the header into the zone metadata.
        let idx = if self.write_idx == 0 {
            self.num_zones - 1
        } else {
            self.write_idx - 1
        };
        self.zones[idx].header = ZoneHeader {
            magic: PSTORE_ZONE_MAGIC,
            record_type: rtype,
            compression: Compression::None,
            in_panic: false,
            seq: self.next_seq,
            payload_len,
        };
        self.zones[idx].has_record = true;
        self.next_seq += 1;
        Ok(&self.zones[idx])
    }

    /// Iterates over zones with valid records, in sequence number order.
    pub fn iter_records(&self) -> impl Iterator<Item = &ZoneDescriptor> {
        self.zones[..self.num_zones].iter().filter(|z| z.has_record)
    }

    /// Clears a zone (marks it as empty).
    pub fn clear_zone(&mut self, offset: u64) -> Result<()> {
        for z in &mut self.zones[..self.num_zones] {
            if z.offset == offset {
                z.has_record = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}
