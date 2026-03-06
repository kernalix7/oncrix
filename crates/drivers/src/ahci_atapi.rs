// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AHCI ATAPI (ATA Packet Interface) command driver.
//!
//! ATAPI devices (CD-ROM, DVD, tape) connect via an ATA/SATA interface
//! but use SCSI-like packet commands encapsulated in an ATA PACKET command.
//!
//! This module provides:
//! - `#[repr(C)]` ATAPI command packet structures
//! - Helper constructors for common SCSI commands (READ(10), REQUEST SENSE, INQUIRY)
//! - AHCI-compatible command table building for ATAPI
//!
//! Reference: INCITS 452-2008 (ATA-8 ACS), §7.18 — PACKET command;
//! SCSI Primary Commands-5 (SPC-5), §6.

use oncrix_lib::{Error, Result};

// ── ATAPI Constants ────────────────────────────────────────────────────────

/// ATAPI command packet size (12 or 16 bytes; most devices use 12).
pub const ATAPI_CDB_LEN: usize = 12;
/// ATAPI maximum sense data length.
pub const ATAPI_SENSE_LEN: usize = 18;
/// Default CD-ROM sector size.
pub const CDROM_SECTOR_SIZE: usize = 2048;
/// Maximum sectors per READ(10) command.
pub const MAX_READ_SECTORS: u16 = 255;

// ── SCSI Command Operation Codes ───────────────────────────────────────────

pub mod scsi_op {
    /// TEST UNIT READY.
    pub const TEST_UNIT_READY: u8 = 0x00;
    /// REQUEST SENSE.
    pub const REQUEST_SENSE: u8 = 0x03;
    /// INQUIRY.
    pub const INQUIRY: u8 = 0x12;
    /// READ CAPACITY (10).
    pub const READ_CAPACITY_10: u8 = 0x25;
    /// READ (10).
    pub const READ_10: u8 = 0x28;
    /// START STOP UNIT.
    pub const START_STOP_UNIT: u8 = 0x1B;
    /// PREVENT ALLOW MEDIUM REMOVAL.
    pub const MEDIUM_REMOVAL: u8 = 0x1E;
    /// GET EVENT STATUS NOTIFICATION.
    pub const GET_EVENT_STATUS: u8 = 0x4A;
    /// READ TOC.
    pub const READ_TOC: u8 = 0x43;
}

// ── ATAPI CDB ──────────────────────────────────────────────────────────────

/// ATAPI Command Descriptor Block (12-byte).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AtapiCdb {
    /// Operation code.
    pub op: u8,
    /// Command-specific byte 1.
    pub b1: u8,
    /// Command-specific bytes 2-5 (often LBA for READ/WRITE).
    pub b2: u8,
    pub b3: u8,
    pub b4: u8,
    pub b5: u8,
    /// Transfer length (high byte for READ(10)).
    pub xfer_hi: u8,
    /// Transfer length (low byte for READ(10)).
    pub xfer_lo: u8,
    /// Command-specific bytes 8-11.
    pub b8: u8,
    pub b9: u8,
    pub b10: u8,
    pub control: u8,
}

impl AtapiCdb {
    /// Construct a TEST UNIT READY CDB.
    pub fn test_unit_ready() -> Self {
        let mut cdb = Self::default();
        cdb.op = scsi_op::TEST_UNIT_READY;
        cdb
    }

    /// Construct an INQUIRY CDB for `alloc_len` bytes.
    pub fn inquiry(alloc_len: u8) -> Self {
        let mut cdb = Self::default();
        cdb.op = scsi_op::INQUIRY;
        cdb.xfer_hi = 0;
        cdb.xfer_lo = alloc_len;
        cdb
    }

    /// Construct a REQUEST SENSE CDB.
    pub fn request_sense() -> Self {
        let mut cdb = Self::default();
        cdb.op = scsi_op::REQUEST_SENSE;
        cdb.xfer_lo = ATAPI_SENSE_LEN as u8;
        cdb
    }

    /// Construct a READ CAPACITY (10) CDB.
    pub fn read_capacity_10() -> Self {
        let mut cdb = Self::default();
        cdb.op = scsi_op::READ_CAPACITY_10;
        cdb
    }

    /// Construct a READ (10) CDB for `lba` / `sectors`.
    pub fn read_10(lba: u32, sectors: u16) -> Result<Self> {
        if sectors == 0 || sectors > MAX_READ_SECTORS {
            return Err(Error::InvalidArgument);
        }
        let mut cdb = Self::default();
        cdb.op = scsi_op::READ_10;
        cdb.b2 = (lba >> 24) as u8;
        cdb.b3 = (lba >> 16) as u8;
        cdb.b4 = (lba >> 8) as u8;
        cdb.b5 = lba as u8;
        cdb.xfer_hi = (sectors >> 8) as u8;
        cdb.xfer_lo = sectors as u8;
        Ok(cdb)
    }

    /// Construct a START STOP UNIT CDB (eject = true to eject, false to load).
    pub fn start_stop_unit(start: bool, eject: bool) -> Self {
        let mut cdb = Self::default();
        cdb.op = scsi_op::START_STOP_UNIT;
        cdb.b1 = if start { 0x01 } else { 0x02 };
        if eject {
            cdb.b1 |= 0x02
        }
        cdb
    }

    /// Construct a READ TOC CDB.
    pub fn read_toc(alloc_len: u16) -> Self {
        let mut cdb = Self::default();
        cdb.op = scsi_op::READ_TOC;
        cdb.xfer_hi = (alloc_len >> 8) as u8;
        cdb.xfer_lo = alloc_len as u8;
        cdb
    }

    /// Return the 12-byte CDB as a byte slice.
    pub fn as_bytes(&self) -> &[u8; ATAPI_CDB_LEN] {
        // SAFETY: AtapiCdb is #[repr(C)] with exactly 12 bytes.
        unsafe { &*(self as *const Self as *const [u8; ATAPI_CDB_LEN]) }
    }
}

// ── INQUIRY Response ───────────────────────────────────────────────────────

/// Standard INQUIRY data (36 bytes minimum).
#[repr(C)]
pub struct InquiryData {
    /// Peripheral qualifier and device type.
    pub peripheral: u8,
    /// RMB (removable media bit) + device type modifier.
    pub removable: u8,
    /// Version (SPC version).
    pub version: u8,
    /// Response data format and flags.
    pub response_fmt: u8,
    /// Additional length (total length - 4).
    pub add_len: u8,
    pub flags2: u8,
    pub flags3: u8,
    pub flags4: u8,
    /// Vendor identification (8 ASCII chars).
    pub vendor_id: [u8; 8],
    /// Product identification (16 ASCII chars).
    pub product_id: [u8; 16],
    /// Product revision level (4 ASCII chars).
    pub revision: [u8; 4],
}

impl InquiryData {
    /// Return true if this is a CD-ROM/DVD device (peripheral type 0x05).
    pub fn is_cdrom(&self) -> bool {
        self.peripheral & 0x1F == 0x05
    }

    /// Return true if media is removable.
    pub fn is_removable(&self) -> bool {
        self.removable & 0x80 != 0
    }
}

// ── READ CAPACITY Response ─────────────────────────────────────────────────

/// READ CAPACITY (10) response (8 bytes, big-endian).
#[repr(C)]
pub struct ReadCapacity10 {
    /// Last logical block address (big-endian).
    pub last_lba_be: u32,
    /// Block length in bytes (big-endian).
    pub block_len_be: u32,
}

impl ReadCapacity10 {
    /// Return the last LBA (host byte order).
    pub fn last_lba(&self) -> u32 {
        u32::from_be(self.last_lba_be)
    }

    /// Return the block length (host byte order).
    pub fn block_len(&self) -> u32 {
        u32::from_be(self.block_len_be)
    }

    /// Return the total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        (self.last_lba() as u64 + 1) * self.block_len() as u64
    }
}

// ── SENSE Data ─────────────────────────────────────────────────────────────

/// REQUEST SENSE fixed-format response (18 bytes).
#[repr(C)]
pub struct SenseData {
    pub response_code: u8,
    pub _obsolete: u8,
    /// Sense key (bits 3:0) and flags (ILI, EOM, FILEMARK).
    pub sense_key: u8,
    pub information: [u8; 4],
    /// Additional sense length.
    pub add_sense_len: u8,
    pub command_specific: [u8; 4],
    /// Additional Sense Code (ASC).
    pub asc: u8,
    /// Additional Sense Code Qualifier (ASCQ).
    pub ascq: u8,
    pub fruc: u8,
    pub sense_key_specific: [u8; 3],
}

impl SenseData {
    /// Extract the sense key (4 bits).
    pub fn key(&self) -> u8 {
        self.sense_key & 0x0F
    }

    /// Return true if this is a medium not present error.
    pub fn is_not_ready(&self) -> bool {
        self.key() == 0x02
    }

    /// Return true if media has changed.
    pub fn is_unit_attention(&self) -> bool {
        self.key() == 0x06
    }
}

// ── ATAPI Device State ─────────────────────────────────────────────────────

/// State of an ATAPI device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AtapiState {
    Uninitialized,
    Ready,
    NoMedia,
    MediaChanged,
    Error,
}

/// ATAPI device abstraction.
pub struct AtapiDevice {
    /// AHCI port index this device is on.
    pub port: u8,
    /// Current device state.
    pub state: AtapiState,
    /// Capacity in sectors (from READ CAPACITY).
    pub capacity_sectors: u32,
    /// Sector size in bytes.
    pub sector_size: u32,
    /// Vendor ID string.
    pub vendor: [u8; 8],
    /// Product ID string.
    pub product: [u8; 16],
}

impl AtapiDevice {
    /// Create a new uninitialized ATAPI device on the given port.
    pub fn new(port: u8) -> Self {
        Self {
            port,
            state: AtapiState::Uninitialized,
            capacity_sectors: 0,
            sector_size: CDROM_SECTOR_SIZE as u32,
            vendor: [b' '; 8],
            product: [b' '; 16],
        }
    }

    /// Update the device state from INQUIRY data.
    pub fn update_from_inquiry(&mut self, data: &InquiryData) {
        self.vendor.copy_from_slice(&data.vendor_id);
        self.product.copy_from_slice(&data.product_id);
        self.state = AtapiState::NoMedia;
    }

    /// Update capacity from READ CAPACITY response.
    pub fn update_capacity(&mut self, cap: &ReadCapacity10) {
        self.capacity_sectors = cap.last_lba() + 1;
        self.sector_size = cap.block_len();
        self.state = AtapiState::Ready;
    }

    /// Return total device capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors as u64 * self.sector_size as u64
    }

    /// Process sense data and update device state.
    pub fn process_sense(&mut self, sense: &SenseData) {
        if sense.is_not_ready() {
            self.state = AtapiState::NoMedia;
        } else if sense.is_unit_attention() {
            self.state = AtapiState::MediaChanged;
        } else {
            self.state = AtapiState::Error;
        }
    }
}
