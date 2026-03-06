// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe Zoned Namespace (ZNS) driver support.
//!
//! Implements the NVMe ZNS command set (NVM Express Zoned Namespace Command
//! Set Specification 1.1) for drives that expose zoned storage. ZNS drives
//! divide namespace capacity into sequential-write zones, enabling optimised
//! flash management.

use oncrix_lib::{Error, Result};

/// Maximum number of zones tracked in the driver.
pub const ZNS_MAX_ZONES: usize = 256;

/// Zone type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZoneType {
    /// Conventional zone — allows random writes.
    Conventional = 0x1,
    /// Sequential write required zone.
    SequentialWriteRequired = 0x2,
    /// Sequential write preferred zone.
    SequentialWritePreferred = 0x3,
}

/// Zone state machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZoneState {
    /// Zone is empty (SLBA == WP).
    Empty = 0x1,
    /// Implicitly opened by a write.
    ImplicitlyOpen = 0x2,
    /// Explicitly opened via Zone Management Send.
    ExplicitlyOpen = 0x3,
    /// Zone is closed (write pointer advanced but not full).
    Closed = 0x4,
    /// Zone is full (WP == SLBA + zone_size).
    Full = 0xE,
    /// Zone is read-only.
    ReadOnly = 0xD,
    /// Zone is offline.
    Offline = 0xF,
}

/// Zone descriptor as returned by Zone Management Receive (Report Zones).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ZoneDescriptor {
    /// Zone type.
    pub zone_type: u8,
    /// Zone state (high nibble) and zone attributes.
    pub zs_za: u8,
    /// Zone attributes byte 2.
    pub za: u8,
    /// Reserved.
    pub _reserved: [u8; 5],
    /// Zone capacity in LBAs.
    pub zone_cap: u64,
    /// Zone starting LBA.
    pub zslba: u64,
    /// Write pointer LBA.
    pub wp: u64,
    /// Reserved.
    pub _reserved2: [u8; 32],
}

impl ZoneDescriptor {
    /// Returns the zone state extracted from the zs_za field.
    pub fn state(&self) -> ZoneState {
        match (self.zs_za >> 4) & 0xF {
            0x1 => ZoneState::Empty,
            0x2 => ZoneState::ImplicitlyOpen,
            0x3 => ZoneState::ExplicitlyOpen,
            0x4 => ZoneState::Closed,
            0xE => ZoneState::Full,
            0xD => ZoneState::ReadOnly,
            0xF => ZoneState::Offline,
            _ => ZoneState::Offline,
        }
    }

    /// Returns the zone type.
    pub fn zone_type(&self) -> ZoneType {
        match self.zone_type & 0xF {
            0x1 => ZoneType::Conventional,
            0x2 => ZoneType::SequentialWriteRequired,
            _ => ZoneType::SequentialWritePreferred,
        }
    }

    /// Returns remaining writable capacity in LBAs.
    pub fn remaining_lbas(&self) -> u64 {
        if self.wp >= self.zslba + self.zone_cap {
            0
        } else {
            self.zslba + self.zone_cap - self.wp
        }
    }
}

/// Zone Management Action (ZMS send action codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZoneAction {
    /// Close zone.
    Close = 0x1,
    /// Finish zone.
    Finish = 0x2,
    /// Open zone.
    Open = 0x3,
    /// Reset zone write pointer.
    Reset = 0x4,
    /// Offline zone.
    Offline = 0x5,
    /// Reset all zones.
    ResetAll = 0x84,
    /// Finish all zones.
    FinishAll = 0x82,
}

/// ZNS namespace parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZnsParams {
    /// Zone size in LBAs.
    pub zone_size_lba: u64,
    /// Zone capacity in LBAs (may be <= zone_size_lba).
    pub zone_cap_lba: u64,
    /// Maximum number of open zones (hardware limit).
    pub max_open_zones: u32,
    /// Maximum number of active zones (open + closed).
    pub max_active_zones: u32,
    /// Total number of zones.
    pub num_zones: u64,
}

/// ZNS driver for a single namespace.
pub struct ZnsDriver {
    /// Namespace ID.
    pub nsid: u32,
    /// ZNS parameters.
    pub params: ZnsParams,
    /// Cached zone descriptors (subset, up to ZNS_MAX_ZONES).
    pub zones: [ZoneDescriptor; ZNS_MAX_ZONES],
    /// Number of cached zones.
    pub cached_zones: usize,
    /// Number of currently open zones.
    pub open_zones: u32,
}

impl ZnsDriver {
    /// Creates a new ZNS driver for namespace `nsid`.
    pub const fn new(nsid: u32) -> Self {
        Self {
            nsid,
            params: ZnsParams {
                zone_size_lba: 0,
                zone_cap_lba: 0,
                max_open_zones: 0,
                max_active_zones: 0,
                num_zones: 0,
            },
            zones: [const {
                ZoneDescriptor {
                    zone_type: 0,
                    zs_za: 0,
                    za: 0,
                    _reserved: [0u8; 5],
                    zone_cap: 0,
                    zslba: 0,
                    wp: 0,
                    _reserved2: [0u8; 32],
                }
            }; ZNS_MAX_ZONES],
            cached_zones: 0,
            open_zones: 0,
        }
    }

    /// Populates zone parameters (called after parsing ZNS Identify Namespace).
    pub fn set_params(&mut self, params: ZnsParams) {
        self.params = params;
    }

    /// Loads zone descriptors from a Report Zones response buffer.
    ///
    /// `buf` contains the raw Zone Report data (64-byte header + 64-byte-per-zone).
    pub fn load_zones(&mut self, buf: &[u8]) -> Result<usize> {
        const ZONE_DESC_SIZE: usize = 64;
        const HEADER_SIZE: usize = 64;
        if buf.len() < HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        let num_zones_raw = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let num_zones = (num_zones_raw as usize).min(ZNS_MAX_ZONES);
        let available = (buf.len() - HEADER_SIZE) / ZONE_DESC_SIZE;
        let count = num_zones.min(available);
        for i in 0..count {
            let off = HEADER_SIZE + i * ZONE_DESC_SIZE;
            let zd = &mut self.zones[i];
            zd.zone_type = buf[off];
            zd.zs_za = buf[off + 1];
            zd.za = buf[off + 2];
            zd.zone_cap = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap_or([0u8; 8]));
            zd.zslba = u64::from_le_bytes(buf[off + 16..off + 24].try_into().unwrap_or([0u8; 8]));
            zd.wp = u64::from_le_bytes(buf[off + 24..off + 32].try_into().unwrap_or([0u8; 8]));
        }
        self.cached_zones = count;
        Ok(count)
    }

    /// Finds the first empty zone suitable for sequential writing.
    pub fn find_empty_zone(&self) -> Option<usize> {
        for (i, z) in self.zones[..self.cached_zones].iter().enumerate() {
            if z.state() == ZoneState::Empty && z.zone_type() == ZoneType::SequentialWriteRequired {
                return Some(i);
            }
        }
        None
    }

    /// Returns the write pointer for zone `idx`.
    pub fn write_pointer(&self, idx: usize) -> Result<u64> {
        if idx >= self.cached_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(self.zones[idx].wp)
    }

    /// Updates the write pointer for zone `idx` after a successful write.
    pub fn advance_wp(&mut self, idx: usize, lbas_written: u64) -> Result<()> {
        if idx >= self.cached_zones {
            return Err(Error::InvalidArgument);
        }
        self.zones[idx].wp += lbas_written;
        Ok(())
    }

    /// Builds an NVMe Zone Management Send (ZMS) command DWord 10-13.
    ///
    /// Returns `(cdw10, cdw11, cdw12, cdw13)`.
    pub fn build_zms_cdw(
        &self,
        slba: u64,
        action: ZoneAction,
        select_all: bool,
    ) -> (u32, u32, u32, u32) {
        let cdw10 = slba as u32;
        let cdw11 = (slba >> 32) as u32;
        let cdw13 = ((action as u32) << 8) | (if select_all { 1 } else { 0 });
        (cdw10, cdw11, 0, cdw13)
    }

    /// Returns the number of cached zones.
    pub fn num_zones(&self) -> usize {
        self.cached_zones
    }

    /// Returns true if a write to `slba` of `lbas` LBAs is valid for zone `idx`.
    pub fn validate_write(&self, idx: usize, slba: u64, lbas: u64) -> bool {
        if idx >= self.cached_zones {
            return false;
        }
        let z = &self.zones[idx];
        slba == z.wp && lbas <= z.remaining_lbas()
    }
}

impl Default for ZnsDriver {
    fn default() -> Self {
        Self::new(1)
    }
}
