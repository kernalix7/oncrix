// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCSI host adapter framework.
//!
//! Implements the SCSI (Small Computer System Interface) mid-layer
//! that bridges host bus adapters (AHCI, USB Mass Storage, VirtIO-
//! SCSI) and the block I/O layer. Provides:
//!
//! - **Command Descriptor Block (CDB)** — building and parsing for
//!   common SCSI commands (6, 10, 12, 16-byte CDBs)
//! - **Sense data** — decoding of CHECK CONDITION responses
//! - **Device discovery** — scanning SCSI buses for attached devices
//! - **Command dispatch** — routing commands to the correct HBA
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐
//! │  Block I/O   │
//! └──────┬───────┘
//!        │
//! ┌──────▼───────┐
//! │  SCSI Layer  │ ← this module
//! └──────┬───────┘
//!        │
//! ┌──────▼───────┐
//! │  HBA Driver  │ (AHCI, USB, VirtIO-SCSI)
//! └──────────────┘
//! ```
//!
//! Reference: SCSI Primary Commands (SPC-5), SCSI Block Commands
//! (SBC-4), SAM-5 Architecture Model.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum CDB (Command Descriptor Block) size in bytes.
pub const MAX_CDB_SIZE: usize = 16;

/// Maximum sense data size in bytes.
pub const MAX_SENSE_SIZE: usize = 252;

/// Maximum number of SCSI hosts.
const MAX_HOSTS: usize = 8;

/// Maximum number of devices per host.
const MAX_DEVICES_PER_HOST: usize = 16;

/// Maximum total SCSI devices across all hosts.
const MAX_DEVICES: usize = MAX_HOSTS * MAX_DEVICES_PER_HOST;

/// SCSI command timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u32 = 30_000;

/// Maximum retries for transient errors.
const MAX_RETRIES: u32 = 3;

/// Maximum data transfer size per command (256 KiB).
const MAX_TRANSFER_SIZE: usize = 256 * 1024;

/// Standard sector size in bytes.
pub const SECTOR_SIZE: u32 = 512;

/// Vendor string length in INQUIRY data.
const VENDOR_LEN: usize = 8;

/// Product string length in INQUIRY data.
const PRODUCT_LEN: usize = 16;

/// Revision string length in INQUIRY data.
const REVISION_LEN: usize = 4;

// ---------------------------------------------------------------------------
// SCSI opcodes (SPC-5 / SBC-4)
// ---------------------------------------------------------------------------

/// SCSI opcode: TEST UNIT READY (6-byte CDB).
pub const SCSI_TEST_UNIT_READY: u8 = 0x00;

/// SCSI opcode: REQUEST SENSE (6-byte CDB).
pub const SCSI_REQUEST_SENSE: u8 = 0x03;

/// SCSI opcode: INQUIRY (6-byte CDB).
pub const SCSI_INQUIRY: u8 = 0x12;

/// SCSI opcode: MODE SELECT(6) (6-byte CDB).
pub const SCSI_MODE_SELECT_6: u8 = 0x15;

/// SCSI opcode: MODE SENSE(6) (6-byte CDB).
pub const SCSI_MODE_SENSE_6: u8 = 0x1A;

/// SCSI opcode: START STOP UNIT (6-byte CDB).
pub const SCSI_START_STOP_UNIT: u8 = 0x1B;

/// SCSI opcode: READ CAPACITY(10) (10-byte CDB).
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;

/// SCSI opcode: READ(10) (10-byte CDB).
pub const SCSI_READ_10: u8 = 0x28;

/// SCSI opcode: WRITE(10) (10-byte CDB).
pub const SCSI_WRITE_10: u8 = 0x2A;

/// SCSI opcode: SYNCHRONIZE CACHE(10) (10-byte CDB).
pub const SCSI_SYNC_CACHE_10: u8 = 0x35;

/// SCSI opcode: READ(16) (16-byte CDB).
pub const SCSI_READ_16: u8 = 0x88;

/// SCSI opcode: WRITE(16) (16-byte CDB).
pub const SCSI_WRITE_16: u8 = 0x8A;

/// SCSI opcode: READ CAPACITY(16) / SERVICE ACTION IN (16-byte CDB).
pub const SCSI_SERVICE_ACTION_IN_16: u8 = 0x9E;

/// Service action for READ CAPACITY(16).
pub const SAI_READ_CAPACITY_16: u8 = 0x10;

/// SCSI opcode: REPORT LUNS (12-byte CDB).
pub const SCSI_REPORT_LUNS: u8 = 0xA0;

/// SCSI opcode: MODE SELECT(10) (10-byte CDB).
pub const SCSI_MODE_SELECT_10: u8 = 0x55;

/// SCSI opcode: MODE SENSE(10) (10-byte CDB).
pub const SCSI_MODE_SENSE_10: u8 = 0x5A;

// ---------------------------------------------------------------------------
// SCSI status codes (SAM-5)
// ---------------------------------------------------------------------------

/// SCSI status: GOOD — command completed successfully.
pub const STATUS_GOOD: u8 = 0x00;

/// SCSI status: CHECK CONDITION — error; read sense data.
pub const STATUS_CHECK_CONDITION: u8 = 0x02;

/// SCSI status: CONDITION MET.
pub const STATUS_CONDITION_MET: u8 = 0x04;

/// SCSI status: BUSY — device cannot accept command.
pub const STATUS_BUSY: u8 = 0x08;

/// SCSI status: RESERVATION CONFLICT.
pub const STATUS_RESERVATION_CONFLICT: u8 = 0x18;

/// SCSI status: TASK SET FULL.
pub const STATUS_TASK_SET_FULL: u8 = 0x28;

/// SCSI status: ACA ACTIVE.
pub const STATUS_ACA_ACTIVE: u8 = 0x30;

/// SCSI status: TASK ABORTED.
pub const STATUS_TASK_ABORTED: u8 = 0x40;

// ---------------------------------------------------------------------------
// Sense key codes (SPC-5 §4.5)
// ---------------------------------------------------------------------------

/// Sense key: NO SENSE — no specific error.
pub const SENSE_NO_SENSE: u8 = 0x00;

/// Sense key: RECOVERED ERROR — command succeeded with recovery.
pub const SENSE_RECOVERED_ERROR: u8 = 0x01;

/// Sense key: NOT READY — device not ready.
pub const SENSE_NOT_READY: u8 = 0x02;

/// Sense key: MEDIUM ERROR — unrecoverable read/write error.
pub const SENSE_MEDIUM_ERROR: u8 = 0x03;

/// Sense key: HARDWARE ERROR — non-recoverable hardware failure.
pub const SENSE_HARDWARE_ERROR: u8 = 0x04;

/// Sense key: ILLEGAL REQUEST — invalid CDB or parameter.
pub const SENSE_ILLEGAL_REQUEST: u8 = 0x05;

/// Sense key: UNIT ATTENTION — device has been reset/changed.
pub const SENSE_UNIT_ATTENTION: u8 = 0x06;

/// Sense key: DATA PROTECT — write protected.
pub const SENSE_DATA_PROTECT: u8 = 0x07;

/// Sense key: BLANK CHECK — read past end of written data.
pub const SENSE_BLANK_CHECK: u8 = 0x08;

/// Sense key: ABORTED COMMAND — device aborted the command.
pub const SENSE_ABORTED_COMMAND: u8 = 0x0B;

// ---------------------------------------------------------------------------
// SCSI command enum
// ---------------------------------------------------------------------------

/// High-level SCSI command types supported by this framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiCommand {
    /// TEST UNIT READY — check if device is ready.
    TestUnitReady,
    /// INQUIRY — get device identification.
    Inquiry,
    /// READ CAPACITY(10) — get device capacity (32-bit LBA).
    ReadCapacity10,
    /// READ CAPACITY(16) — get device capacity (64-bit LBA).
    ReadCapacity16,
    /// READ(10) — read sectors (32-bit LBA, 16-bit count).
    Read10 {
        /// Starting logical block address.
        lba: u32,
        /// Number of sectors to read.
        count: u16,
    },
    /// READ(16) — read sectors (64-bit LBA, 32-bit count).
    Read16 {
        /// Starting logical block address.
        lba: u64,
        /// Number of sectors to read.
        count: u32,
    },
    /// WRITE(10) — write sectors (32-bit LBA, 16-bit count).
    Write10 {
        /// Starting logical block address.
        lba: u32,
        /// Number of sectors to write.
        count: u16,
    },
    /// WRITE(16) — write sectors (64-bit LBA, 32-bit count).
    Write16 {
        /// Starting logical block address.
        lba: u64,
        /// Number of sectors to write.
        count: u32,
    },
    /// REQUEST SENSE — retrieve sense data after CHECK CONDITION.
    RequestSense,
    /// MODE SENSE(6) — read device parameters.
    ModeSense6 {
        /// Page code to retrieve.
        page: u8,
    },
    /// MODE SENSE(10) — read device parameters (extended).
    ModeSense10 {
        /// Page code to retrieve.
        page: u8,
    },
    /// MODE SELECT(6) — set device parameters.
    ModeSelect6,
    /// MODE SELECT(10) — set device parameters (extended).
    ModeSelect10,
    /// SYNCHRONIZE CACHE — flush device write cache.
    SyncCache,
    /// START STOP UNIT — start, stop, or eject media.
    StartStopUnit {
        /// Start (true) or stop (false).
        start: bool,
        /// Load/eject the medium.
        loej: bool,
    },
    /// REPORT LUNS — list available logical units.
    ReportLuns,
}

// ---------------------------------------------------------------------------
// CDB builder
// ---------------------------------------------------------------------------

/// A Command Descriptor Block ready for submission to an HBA.
#[derive(Debug, Clone)]
pub struct Cdb {
    /// Raw CDB bytes.
    pub bytes: [u8; MAX_CDB_SIZE],
    /// Actual length of the CDB (6, 10, 12, or 16).
    pub len: usize,
}

impl Default for Cdb {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_CDB_SIZE],
            len: 0,
        }
    }
}

impl Cdb {
    /// Build a CDB from a high-level [`ScsiCommand`].
    pub fn build(cmd: ScsiCommand) -> Self {
        let mut cdb = Self::default();
        match cmd {
            ScsiCommand::TestUnitReady => {
                cdb.bytes[0] = SCSI_TEST_UNIT_READY;
                cdb.len = 6;
            }
            ScsiCommand::Inquiry => {
                cdb.bytes[0] = SCSI_INQUIRY;
                // Allocation length: 36 bytes (standard INQUIRY).
                cdb.bytes[3] = 0;
                cdb.bytes[4] = 36;
                cdb.len = 6;
            }
            ScsiCommand::ReadCapacity10 => {
                cdb.bytes[0] = SCSI_READ_CAPACITY_10;
                cdb.len = 10;
            }
            ScsiCommand::ReadCapacity16 => {
                cdb.bytes[0] = SCSI_SERVICE_ACTION_IN_16;
                cdb.bytes[1] = SAI_READ_CAPACITY_16;
                // Allocation length: 32 bytes.
                cdb.bytes[10] = 0;
                cdb.bytes[11] = 0;
                cdb.bytes[12] = 0;
                cdb.bytes[13] = 32;
                cdb.len = 16;
            }
            ScsiCommand::Read10 { lba, count } => {
                cdb.bytes[0] = SCSI_READ_10;
                cdb.bytes[2] = (lba >> 24) as u8;
                cdb.bytes[3] = (lba >> 16) as u8;
                cdb.bytes[4] = (lba >> 8) as u8;
                cdb.bytes[5] = lba as u8;
                cdb.bytes[7] = (count >> 8) as u8;
                cdb.bytes[8] = count as u8;
                cdb.len = 10;
            }
            ScsiCommand::Read16 { lba, count } => {
                cdb.bytes[0] = SCSI_READ_16;
                cdb.bytes[2] = (lba >> 56) as u8;
                cdb.bytes[3] = (lba >> 48) as u8;
                cdb.bytes[4] = (lba >> 40) as u8;
                cdb.bytes[5] = (lba >> 32) as u8;
                cdb.bytes[6] = (lba >> 24) as u8;
                cdb.bytes[7] = (lba >> 16) as u8;
                cdb.bytes[8] = (lba >> 8) as u8;
                cdb.bytes[9] = lba as u8;
                cdb.bytes[10] = (count >> 24) as u8;
                cdb.bytes[11] = (count >> 16) as u8;
                cdb.bytes[12] = (count >> 8) as u8;
                cdb.bytes[13] = count as u8;
                cdb.len = 16;
            }
            ScsiCommand::Write10 { lba, count } => {
                cdb.bytes[0] = SCSI_WRITE_10;
                cdb.bytes[2] = (lba >> 24) as u8;
                cdb.bytes[3] = (lba >> 16) as u8;
                cdb.bytes[4] = (lba >> 8) as u8;
                cdb.bytes[5] = lba as u8;
                cdb.bytes[7] = (count >> 8) as u8;
                cdb.bytes[8] = count as u8;
                cdb.len = 10;
            }
            ScsiCommand::Write16 { lba, count } => {
                cdb.bytes[0] = SCSI_WRITE_16;
                cdb.bytes[2] = (lba >> 56) as u8;
                cdb.bytes[3] = (lba >> 48) as u8;
                cdb.bytes[4] = (lba >> 40) as u8;
                cdb.bytes[5] = (lba >> 32) as u8;
                cdb.bytes[6] = (lba >> 24) as u8;
                cdb.bytes[7] = (lba >> 16) as u8;
                cdb.bytes[8] = (lba >> 8) as u8;
                cdb.bytes[9] = lba as u8;
                cdb.bytes[10] = (count >> 24) as u8;
                cdb.bytes[11] = (count >> 16) as u8;
                cdb.bytes[12] = (count >> 8) as u8;
                cdb.bytes[13] = count as u8;
                cdb.len = 16;
            }
            ScsiCommand::RequestSense => {
                cdb.bytes[0] = SCSI_REQUEST_SENSE;
                // Allocation length: 252 bytes (max sense data).
                cdb.bytes[4] = MAX_SENSE_SIZE as u8;
                cdb.len = 6;
            }
            ScsiCommand::ModeSense6 { page } => {
                cdb.bytes[0] = SCSI_MODE_SENSE_6;
                cdb.bytes[2] = page & 0x3F;
                cdb.bytes[4] = 252; // allocation length
                cdb.len = 6;
            }
            ScsiCommand::ModeSense10 { page } => {
                cdb.bytes[0] = SCSI_MODE_SENSE_10;
                cdb.bytes[2] = page & 0x3F;
                cdb.bytes[7] = 0x01; // allocation length MSB
                cdb.bytes[8] = 0x00; // allocation length LSB (256)
                cdb.len = 10;
            }
            ScsiCommand::ModeSelect6 => {
                cdb.bytes[0] = SCSI_MODE_SELECT_6;
                cdb.bytes[1] = 0x10; // PF (page format) bit
                cdb.len = 6;
            }
            ScsiCommand::ModeSelect10 => {
                cdb.bytes[0] = SCSI_MODE_SELECT_10;
                cdb.bytes[1] = 0x10; // PF (page format) bit
                cdb.len = 10;
            }
            ScsiCommand::SyncCache => {
                cdb.bytes[0] = SCSI_SYNC_CACHE_10;
                cdb.len = 10;
            }
            ScsiCommand::StartStopUnit { start, loej } => {
                cdb.bytes[0] = SCSI_START_STOP_UNIT;
                let mut immed_start: u8 = 0;
                if start {
                    immed_start |= 0x01;
                }
                if loej {
                    immed_start |= 0x02;
                }
                cdb.bytes[4] = immed_start;
                cdb.len = 6;
            }
            ScsiCommand::ReportLuns => {
                cdb.bytes[0] = SCSI_REPORT_LUNS;
                // Allocation length: 256 bytes.
                cdb.bytes[6] = 0;
                cdb.bytes[7] = 0;
                cdb.bytes[8] = 1;
                cdb.bytes[9] = 0;
                cdb.len = 12;
            }
        }
        cdb
    }

    /// Parse the opcode from a raw CDB.
    pub fn opcode(&self) -> u8 {
        self.bytes[0]
    }

    /// Determine the CDB group length from the opcode.
    ///
    /// SCSI opcodes encode the group in bits 7:5:
    /// - 0x00..0x1F → 6-byte CDB
    /// - 0x20..0x3F → 10-byte CDB
    /// - 0x40..0x5F → 10-byte CDB
    /// - 0x60..0x7F → vendor-specific
    /// - 0x80..0x9F → 16-byte CDB
    /// - 0xA0..0xBF → 12-byte CDB
    /// - 0xC0..0xFF → vendor-specific
    pub fn cdb_length_for_opcode(opcode: u8) -> usize {
        match opcode >> 5 {
            0 => 6,
            1 | 2 => 10,
            4 => 16,
            5 => 12,
            _ => 6, // vendor or unknown, assume 6
        }
    }
}

// ---------------------------------------------------------------------------
// Sense data (SPC-5 §4.5)
// ---------------------------------------------------------------------------

/// Parsed SCSI sense data from a CHECK CONDITION status.
#[derive(Debug, Clone, Copy, Default)]
pub struct SenseData {
    /// Response code (0x70 = fixed current, 0x71 = fixed deferred,
    /// 0x72 = descriptor current, 0x73 = descriptor deferred).
    pub response_code: u8,
    /// Sense key (0x00–0x0F).
    pub sense_key: u8,
    /// Additional Sense Code (ASC).
    pub asc: u8,
    /// Additional Sense Code Qualifier (ASCQ).
    pub ascq: u8,
    /// Information field (command-specific).
    pub information: u32,
    /// Additional sense length.
    pub additional_length: u8,
    /// Valid bit (true if information field is valid).
    pub valid: bool,
    /// File mark (for tape devices).
    pub filemark: bool,
    /// End-of-medium.
    pub eom: bool,
    /// Incorrect length indicator.
    pub ili: bool,
}

impl SenseData {
    /// Parse sense data from a raw byte buffer.
    ///
    /// Handles both fixed format (response codes 0x70/0x71) and
    /// descriptor format (0x72/0x73) sense data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let response_code = data[0] & 0x7F;
        let valid = data[0] & 0x80 != 0;

        match response_code {
            // Fixed format (0x70 or 0x71).
            0x70 | 0x71 => {
                if data.len() < 8 {
                    return Err(Error::InvalidArgument);
                }
                let sense_key = data[2] & 0x0F;
                let filemark = data[2] & 0x80 != 0;
                let eom = data[2] & 0x40 != 0;
                let ili = data[2] & 0x20 != 0;

                let information = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);

                let additional_length = data[7];

                let (asc, ascq) = if data.len() >= 14 {
                    (data[12], data[13])
                } else {
                    (0, 0)
                };

                Ok(Self {
                    response_code,
                    sense_key,
                    asc,
                    ascq,
                    information,
                    additional_length,
                    valid,
                    filemark,
                    eom,
                    ili,
                })
            }
            // Descriptor format (0x72 or 0x73).
            0x72 | 0x73 => {
                if data.len() < 8 {
                    return Err(Error::InvalidArgument);
                }
                let sense_key = data[1] & 0x0F;
                let asc = data[2];
                let ascq = data[3];
                let additional_length = data[7];

                Ok(Self {
                    response_code,
                    sense_key,
                    asc,
                    ascq,
                    information: 0,
                    additional_length,
                    valid,
                    filemark: false,
                    eom: false,
                    ili: false,
                })
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns a human-readable description of the sense key.
    pub fn sense_key_name(&self) -> &'static str {
        match self.sense_key {
            SENSE_NO_SENSE => "NO SENSE",
            SENSE_RECOVERED_ERROR => "RECOVERED ERROR",
            SENSE_NOT_READY => "NOT READY",
            SENSE_MEDIUM_ERROR => "MEDIUM ERROR",
            SENSE_HARDWARE_ERROR => "HARDWARE ERROR",
            SENSE_ILLEGAL_REQUEST => "ILLEGAL REQUEST",
            SENSE_UNIT_ATTENTION => "UNIT ATTENTION",
            SENSE_DATA_PROTECT => "DATA PROTECT",
            SENSE_BLANK_CHECK => "BLANK CHECK",
            SENSE_ABORTED_COMMAND => "ABORTED COMMAND",
            _ => "UNKNOWN",
        }
    }

    /// Map this sense data to an ONCRIX error.
    pub fn to_error(&self) -> Error {
        match self.sense_key {
            SENSE_NO_SENSE | SENSE_RECOVERED_ERROR => Error::IoError,
            SENSE_NOT_READY => Error::Busy,
            SENSE_MEDIUM_ERROR | SENSE_HARDWARE_ERROR => Error::IoError,
            SENSE_ILLEGAL_REQUEST => Error::InvalidArgument,
            SENSE_DATA_PROTECT => Error::PermissionDenied,
            SENSE_UNIT_ATTENTION => Error::Busy,
            SENSE_ABORTED_COMMAND => Error::Interrupted,
            _ => Error::IoError,
        }
    }

    /// Returns true if this sense indicates a transient condition
    /// that may succeed on retry.
    pub fn is_retriable(&self) -> bool {
        matches!(
            self.sense_key,
            SENSE_NOT_READY | SENSE_UNIT_ATTENTION | SENSE_ABORTED_COMMAND
        )
    }
}

// ---------------------------------------------------------------------------
// INQUIRY data (SPC-5 §6.4.2)
// ---------------------------------------------------------------------------

/// Parsed INQUIRY response data.
#[derive(Debug, Clone)]
pub struct InquiryData {
    /// Peripheral device type (0x00 = disk, 0x05 = CD-ROM, etc.).
    pub device_type: u8,
    /// Peripheral qualifier.
    pub qualifier: u8,
    /// Removable media bit.
    pub removable: bool,
    /// SCSI version (e.g., 5 = SPC-3).
    pub version: u8,
    /// Response data format (should be 2).
    pub response_data_format: u8,
    /// Vendor identification string (8 bytes, ASCII, space-padded).
    pub vendor: [u8; VENDOR_LEN],
    /// Product identification string (16 bytes, ASCII, space-padded).
    pub product: [u8; PRODUCT_LEN],
    /// Product revision string (4 bytes, ASCII, space-padded).
    pub revision: [u8; REVISION_LEN],
}

impl Default for InquiryData {
    fn default() -> Self {
        Self {
            device_type: 0,
            qualifier: 0,
            removable: false,
            version: 0,
            response_data_format: 0,
            vendor: [b' '; VENDOR_LEN],
            product: [b' '; PRODUCT_LEN],
            revision: [b' '; REVISION_LEN],
        }
    }
}

impl InquiryData {
    /// Parse INQUIRY data from a raw response buffer.
    ///
    /// The buffer must be at least 36 bytes (standard INQUIRY
    /// response length).
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(Error::InvalidArgument);
        }

        let device_type = data[0] & 0x1F;
        let qualifier = (data[0] >> 5) & 0x07;
        let removable = data[1] & 0x80 != 0;
        let version = data[2];
        let response_data_format = data[3] & 0x0F;

        let mut vendor = [b' '; VENDOR_LEN];
        vendor.copy_from_slice(&data[8..16]);

        let mut product = [b' '; PRODUCT_LEN];
        product.copy_from_slice(&data[16..32]);

        let mut revision = [b' '; REVISION_LEN];
        revision.copy_from_slice(&data[32..36]);

        Ok(Self {
            device_type,
            qualifier,
            removable,
            version,
            response_data_format,
            vendor,
            product,
            revision,
        })
    }

    /// Returns `true` if this is a direct-access block device (disk).
    pub fn is_disk(&self) -> bool {
        self.device_type == 0x00
    }

    /// Returns `true` if this is a CD-ROM / DVD device.
    pub fn is_cdrom(&self) -> bool {
        self.device_type == 0x05
    }

    /// Returns `true` if the device is present (qualifier 0).
    pub fn is_present(&self) -> bool {
        self.qualifier == 0
    }
}

// ---------------------------------------------------------------------------
// READ CAPACITY response
// ---------------------------------------------------------------------------

/// Parsed READ CAPACITY(10) response.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadCapacity10Response {
    /// Last logical block address (0-based).
    pub last_lba: u32,
    /// Block (sector) size in bytes.
    pub block_size: u32,
}

impl ReadCapacity10Response {
    /// Parse from an 8-byte response buffer.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Ok(Self {
            last_lba,
            block_size,
        })
    }

    /// Total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        (self.last_lba as u64 + 1) * self.block_size as u64
    }

    /// Total number of sectors.
    pub fn total_sectors(&self) -> u64 {
        self.last_lba as u64 + 1
    }
}

/// Parsed READ CAPACITY(16) response.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadCapacity16Response {
    /// Last logical block address (0-based).
    pub last_lba: u64,
    /// Block (sector) size in bytes.
    pub block_size: u32,
}

impl ReadCapacity16Response {
    /// Parse from a 32-byte response buffer.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        let last_lba = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let block_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        Ok(Self {
            last_lba,
            block_size,
        })
    }

    /// Total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        (self.last_lba + 1) * self.block_size as u64
    }

    /// Total number of sectors.
    pub fn total_sectors(&self) -> u64 {
        self.last_lba + 1
    }
}

// ---------------------------------------------------------------------------
// Data direction
// ---------------------------------------------------------------------------

/// Data transfer direction for a SCSI command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    /// No data transfer.
    None,
    /// Data flows from device to host (read).
    ToHost,
    /// Data flows from host to device (write).
    FromHost,
}

// ---------------------------------------------------------------------------
// SCSI request
// ---------------------------------------------------------------------------

/// A SCSI request ready for submission to an HBA.
#[derive(Debug, Clone)]
pub struct ScsiRequest {
    /// The CDB to send.
    pub cdb: Cdb,
    /// Data direction.
    pub direction: DataDirection,
    /// Data buffer address (physical or virtual depending on HBA).
    pub data_addr: u64,
    /// Data buffer length in bytes.
    pub data_len: usize,
    /// Sense buffer for CHECK CONDITION.
    pub sense: [u8; MAX_SENSE_SIZE],
    /// Sense data length returned by the device.
    pub sense_len: usize,
    /// Timeout in milliseconds.
    pub timeout_ms: u32,
    /// Number of retries remaining.
    pub retries: u32,
    /// SCSI status byte from the device.
    pub status: u8,
    /// Host adapter status (0 = success).
    pub host_status: u8,
}

impl Default for ScsiRequest {
    fn default() -> Self {
        Self {
            cdb: Cdb::default(),
            direction: DataDirection::None,
            data_addr: 0,
            data_len: 0,
            sense: [0u8; MAX_SENSE_SIZE],
            sense_len: 0,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            retries: MAX_RETRIES,
            status: 0,
            host_status: 0,
        }
    }
}

impl ScsiRequest {
    /// Create a new SCSI request from a command.
    pub fn new(cmd: ScsiCommand) -> Self {
        let direction = match cmd {
            ScsiCommand::TestUnitReady
            | ScsiCommand::SyncCache
            | ScsiCommand::StartStopUnit { .. } => DataDirection::None,
            ScsiCommand::Read10 { .. }
            | ScsiCommand::Read16 { .. }
            | ScsiCommand::Inquiry
            | ScsiCommand::ReadCapacity10
            | ScsiCommand::ReadCapacity16
            | ScsiCommand::RequestSense
            | ScsiCommand::ModeSense6 { .. }
            | ScsiCommand::ModeSense10 { .. }
            | ScsiCommand::ReportLuns => DataDirection::ToHost,
            ScsiCommand::Write10 { .. }
            | ScsiCommand::Write16 { .. }
            | ScsiCommand::ModeSelect6
            | ScsiCommand::ModeSelect10 => DataDirection::FromHost,
        };

        Self {
            cdb: Cdb::build(cmd),
            direction,
            ..Self::default()
        }
    }

    /// Returns `true` if the command completed successfully.
    pub fn is_success(&self) -> bool {
        self.status == STATUS_GOOD && self.host_status == 0
    }

    /// Parse sense data from this request's sense buffer.
    pub fn parse_sense(&self) -> Result<SenseData> {
        if self.sense_len == 0 {
            return Err(Error::NotFound);
        }
        SenseData::parse(&self.sense[..self.sense_len])
    }
}

// ---------------------------------------------------------------------------
// SCSI device
// ---------------------------------------------------------------------------

/// A discovered SCSI device.
#[derive(Debug, Clone)]
pub struct ScsiDevice {
    /// Host adapter index.
    pub host_id: u8,
    /// Channel (bus) number.
    pub channel: u8,
    /// Target ID on the bus.
    pub target_id: u8,
    /// Logical Unit Number.
    pub lun: u8,
    /// Vendor string (from INQUIRY).
    pub vendor: [u8; VENDOR_LEN],
    /// Product/model string (from INQUIRY).
    pub model: [u8; PRODUCT_LEN],
    /// Firmware revision string (from INQUIRY).
    pub revision: [u8; REVISION_LEN],
    /// Device type (from INQUIRY, 0x00 = disk).
    pub device_type: u8,
    /// Whether the medium is removable.
    pub removable: bool,
    /// Total capacity in sectors (filled after READ CAPACITY).
    pub capacity_sectors: u64,
    /// Block (sector) size in bytes.
    pub block_size: u32,
    /// Whether the device is online and ready.
    pub online: bool,
}

impl Default for ScsiDevice {
    fn default() -> Self {
        Self {
            host_id: 0,
            channel: 0,
            target_id: 0,
            lun: 0,
            vendor: [b' '; VENDOR_LEN],
            model: [b' '; PRODUCT_LEN],
            revision: [b' '; REVISION_LEN],
            device_type: 0xFF,
            removable: false,
            capacity_sectors: 0,
            block_size: SECTOR_SIZE,
            online: false,
        }
    }
}

impl ScsiDevice {
    /// Returns the SCSI address as (host, channel, target, lun).
    pub fn address(&self) -> (u8, u8, u8, u8) {
        (self.host_id, self.channel, self.target_id, self.lun)
    }

    /// Returns `true` if this is a direct-access block device.
    pub fn is_disk(&self) -> bool {
        self.device_type == 0x00
    }

    /// Returns total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * self.block_size as u64
    }

    /// Populate device info from INQUIRY data.
    pub fn set_inquiry_data(&mut self, inquiry: &InquiryData) {
        self.vendor = inquiry.vendor;
        self.model = inquiry.product;
        self.revision = inquiry.revision;
        self.device_type = inquiry.device_type;
        self.removable = inquiry.removable;
    }

    /// Populate capacity from READ CAPACITY(10) response.
    pub fn set_capacity_10(&mut self, cap: &ReadCapacity10Response) {
        self.capacity_sectors = cap.total_sectors();
        self.block_size = cap.block_size;
    }

    /// Populate capacity from READ CAPACITY(16) response.
    pub fn set_capacity_16(&mut self, cap: &ReadCapacity16Response) {
        self.capacity_sectors = cap.total_sectors();
        self.block_size = cap.block_size;
    }
}

// ---------------------------------------------------------------------------
// SCSI host trait
// ---------------------------------------------------------------------------

/// Trait for SCSI host bus adapters.
///
/// HBA drivers (AHCI, USB BOT, VirtIO-SCSI) implement this trait
/// to provide a unified command submission interface to the SCSI
/// mid-layer.
pub trait ScsiHost {
    /// Submit a SCSI command for execution.
    ///
    /// The HBA builds the hardware-specific command structure from
    /// the request's CDB and data pointer, submits it, and waits
    /// for completion. On return, the request's `status`,
    /// `host_status`, and sense buffer are filled.
    fn queue_command(&mut self, target: u8, lun: u8, request: &mut ScsiRequest) -> Result<()>;

    /// Abort an in-progress command.
    ///
    /// The HBA attempts to cancel the command identified by the
    /// CDB. Returns `Ok(())` if the command was successfully
    /// aborted or was not found.
    fn abort(&mut self, target: u8, lun: u8, request: &ScsiRequest) -> Result<()>;

    /// Reset a specific target device.
    ///
    /// Sends a device reset to the specified target, aborting all
    /// outstanding commands.
    fn reset_device(&mut self, target: u8, lun: u8) -> Result<()>;

    /// Reset the entire SCSI bus / host adapter.
    fn reset_bus(&mut self) -> Result<()>;

    /// Scan the bus for devices.
    ///
    /// Enumerates all targets and LUNs on this host, issuing INQUIRY
    /// commands to discover attached devices.
    fn scan(&mut self, devices: &mut [ScsiDevice]) -> Result<usize>;
}

// ---------------------------------------------------------------------------
// SCSI device registry
// ---------------------------------------------------------------------------

/// Entry in the global device registry.
#[derive(Clone)]
struct DeviceEntry {
    /// Device information.
    device: ScsiDevice,
    /// Whether this slot is occupied.
    active: bool,
}

impl Default for DeviceEntry {
    fn default() -> Self {
        Self {
            device: ScsiDevice::default(),
            active: false,
        }
    }
}

/// Global SCSI device registry.
struct ScsiRegistry {
    /// Registered devices.
    devices: [DeviceEntry; MAX_DEVICES],
    /// Number of active devices.
    count: usize,
}

/// Static SCSI registry.
static mut SCSI_REGISTRY: ScsiRegistry = ScsiRegistry {
    devices: [const {
        DeviceEntry {
            device: ScsiDevice {
                host_id: 0,
                channel: 0,
                target_id: 0,
                lun: 0,
                vendor: [b' '; VENDOR_LEN],
                model: [b' '; PRODUCT_LEN],
                revision: [b' '; REVISION_LEN],
                device_type: 0xFF,
                removable: false,
                capacity_sectors: 0,
                block_size: 512,
                online: false,
            },
            active: false,
        }
    }; MAX_DEVICES],
    count: 0,
};

/// Register a discovered SCSI device.
///
/// # Safety
///
/// The caller must ensure exclusive access (e.g., during device
/// scanning on a single thread).
pub unsafe fn register_device(device: &ScsiDevice) -> Result<usize> {
    // SAFETY: Accessed during single-threaded device scanning.
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(SCSI_REGISTRY) };
    if registry.count >= MAX_DEVICES {
        return Err(Error::OutOfMemory);
    }

    // Check for duplicates.
    for entry in registry.devices.iter() {
        if entry.active
            && entry.device.host_id == device.host_id
            && entry.device.channel == device.channel
            && entry.device.target_id == device.target_id
            && entry.device.lun == device.lun
        {
            return Err(Error::AlreadyExists);
        }
    }

    for (i, entry) in registry.devices.iter_mut().enumerate() {
        if !entry.active {
            entry.device = device.clone();
            entry.active = true;
            registry.count += 1;
            return Ok(i);
        }
    }

    Err(Error::OutOfMemory)
}

/// Unregister a SCSI device by its address.
///
/// # Safety
///
/// The caller must ensure exclusive access.
pub unsafe fn unregister_device(host_id: u8, channel: u8, target_id: u8, lun: u8) -> Result<()> {
    // SAFETY: Accessed with exclusive access.
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(SCSI_REGISTRY) };
    for entry in registry.devices.iter_mut() {
        if entry.active
            && entry.device.host_id == host_id
            && entry.device.channel == channel
            && entry.device.target_id == target_id
            && entry.device.lun == lun
        {
            entry.active = false;
            registry.count = registry.count.saturating_sub(1);
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

/// Get a device from the registry by index.
///
/// # Safety
///
/// The caller must ensure no concurrent modifications.
pub unsafe fn get_device(index: usize) -> Result<ScsiDevice> {
    // SAFETY: Read access to static registry.
    let registry = unsafe { &*core::ptr::addr_of!(SCSI_REGISTRY) };
    if index >= MAX_DEVICES {
        return Err(Error::InvalidArgument);
    }
    let entry = &registry.devices[index];
    if !entry.active {
        return Err(Error::NotFound);
    }
    Ok(entry.device.clone())
}

/// Find a device by its SCSI address.
///
/// # Safety
///
/// The caller must ensure no concurrent modifications.
pub unsafe fn find_device(host_id: u8, channel: u8, target_id: u8, lun: u8) -> Result<ScsiDevice> {
    // SAFETY: Read access to static registry.
    let registry = unsafe { &*core::ptr::addr_of!(SCSI_REGISTRY) };
    for entry in registry.devices.iter() {
        if entry.active
            && entry.device.host_id == host_id
            && entry.device.channel == channel
            && entry.device.target_id == target_id
            && entry.device.lun == lun
        {
            return Ok(entry.device.clone());
        }
    }
    Err(Error::NotFound)
}

/// Number of registered SCSI devices.
///
/// # Safety
///
/// The caller must ensure no concurrent modifications.
pub unsafe fn device_count() -> usize {
    // SAFETY: Read access to static registry.
    let registry = unsafe { &*core::ptr::addr_of!(SCSI_REGISTRY) };
    registry.count
}

/// Check if the registry is empty.
///
/// # Safety
///
/// The caller must ensure no concurrent modifications.
pub unsafe fn is_empty() -> bool {
    // SAFETY: Read access to static registry.
    let registry = unsafe { &*core::ptr::addr_of!(SCSI_REGISTRY) };
    registry.count == 0
}

// ---------------------------------------------------------------------------
// Utility: build common SCSI requests
// ---------------------------------------------------------------------------

/// Build a TEST UNIT READY request.
pub fn build_test_unit_ready() -> ScsiRequest {
    ScsiRequest::new(ScsiCommand::TestUnitReady)
}

/// Build an INQUIRY request with a response buffer.
pub fn build_inquiry(data_addr: u64) -> ScsiRequest {
    let mut req = ScsiRequest::new(ScsiCommand::Inquiry);
    req.data_addr = data_addr;
    req.data_len = 36;
    req
}

/// Build a READ CAPACITY(10) request.
pub fn build_read_capacity_10(data_addr: u64) -> ScsiRequest {
    let mut req = ScsiRequest::new(ScsiCommand::ReadCapacity10);
    req.data_addr = data_addr;
    req.data_len = 8;
    req
}

/// Build a READ CAPACITY(16) request.
pub fn build_read_capacity_16(data_addr: u64) -> ScsiRequest {
    let mut req = ScsiRequest::new(ScsiCommand::ReadCapacity16);
    req.data_addr = data_addr;
    req.data_len = 32;
    req
}

/// Build a READ(10) request.
pub fn build_read_10(lba: u32, count: u16, data_addr: u64) -> ScsiRequest {
    let mut req = ScsiRequest::new(ScsiCommand::Read10 { lba, count });
    req.data_addr = data_addr;
    req.data_len = count as usize * SECTOR_SIZE as usize;
    req
}

/// Build a WRITE(10) request.
pub fn build_write_10(lba: u32, count: u16, data_addr: u64) -> ScsiRequest {
    let mut req = ScsiRequest::new(ScsiCommand::Write10 { lba, count });
    req.data_addr = data_addr;
    req.data_len = count as usize * SECTOR_SIZE as usize;
    req
}

/// Build a REQUEST SENSE request.
pub fn build_request_sense(data_addr: u64) -> ScsiRequest {
    let mut req = ScsiRequest::new(ScsiCommand::RequestSense);
    req.data_addr = data_addr;
    req.data_len = MAX_SENSE_SIZE;
    req
}

/// Build a SYNCHRONIZE CACHE request.
pub fn build_sync_cache() -> ScsiRequest {
    ScsiRequest::new(ScsiCommand::SyncCache)
}
