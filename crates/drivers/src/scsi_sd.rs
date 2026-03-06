// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCSI disk (sd) driver for block I/O.
//!
//! Implements the SCSI disk driver that handles sector-level
//! READ/WRITE operations, capacity detection, and error recovery
//! for SCSI-attached storage devices. Works with any SCSI transport
//! (AHCI/SAS, USB Mass Storage, VirtIO-SCSI, iSCSI).
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐
//! │  Block I/O      │
//! └───────┬────────┘
//!         │ read/write sectors
//! ┌───────▼────────┐
//! │  SCSI sd Driver │ ← this module
//! └───────┬────────┘
//!         │ SCSI CDB
//! ┌───────▼────────┐
//! │  SCSI Mid-Layer │ (crates/drivers/src/scsi.rs)
//! └───────┬────────┘
//!         │
//! ┌───────▼────────┐
//! │  HBA Driver     │ (AHCI, USB, VirtIO-SCSI)
//! └────────────────┘
//! ```
//!
//! The driver uses READ(10)/WRITE(10) for disks up to 2 TiB and
//! READ(16)/WRITE(16) for larger capacities. Error recovery is
//! handled via REQUEST SENSE and automatic retries.
//!
//! Reference: SCSI Block Commands (SBC-4), SCSI Primary Commands
//! (SPC-5), SAM-5 Architecture Model.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of SCSI disks tracked.
const MAX_SCSI_DISKS: usize = 16;

/// Maximum CDB size in bytes.
const MAX_CDB_SIZE: usize = 16;

/// Maximum sense data size in bytes.
const MAX_SENSE_SIZE: usize = 64;

/// Standard sector size in bytes.
pub const SECTOR_SIZE: u32 = 512;

/// Maximum transfer size per command (256 KiB).
const MAX_TRANSFER_SIZE: usize = 256 * 1024;

/// Maximum retries for transient errors.
const MAX_RETRIES: u32 = 3;

/// Default command timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u32 = 30_000;

/// Maximum sectors per READ/WRITE(10) command (16-bit count).
const MAX_SECTORS_10: u32 = 0xFFFF;

/// Maximum sectors per READ/WRITE(16) command.
const MAX_SECTORS_16: u64 = 0xFFFF_FFFF;

/// Threshold LBA above which we use READ/WRITE(16).
const LBA_32BIT_LIMIT: u64 = 0xFFFF_FFFF;

// ── SCSI Opcodes ────────────────────────────────────────────────

/// TEST UNIT READY (6-byte CDB).
pub const SCSI_TEST_UNIT_READY: u8 = 0x00;

/// REQUEST SENSE (6-byte CDB).
pub const SCSI_REQUEST_SENSE: u8 = 0x03;

/// INQUIRY (6-byte CDB).
pub const SCSI_INQUIRY: u8 = 0x12;

/// READ CAPACITY(10) (10-byte CDB).
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;

/// READ(10) (10-byte CDB).
pub const SCSI_READ_10: u8 = 0x28;

/// WRITE(10) (10-byte CDB).
pub const SCSI_WRITE_10: u8 = 0x2A;

/// SYNCHRONIZE CACHE(10) (10-byte CDB).
pub const SCSI_SYNC_CACHE_10: u8 = 0x35;

/// READ(16) (16-byte CDB).
pub const SCSI_READ_16: u8 = 0x88;

/// WRITE(16) (16-byte CDB).
pub const SCSI_WRITE_16: u8 = 0x8A;

/// SERVICE ACTION IN(16) (for READ CAPACITY(16)).
pub const SCSI_SERVICE_ACTION_IN_16: u8 = 0x9E;

/// Service action: READ CAPACITY(16).
pub const SAI_READ_CAPACITY_16: u8 = 0x10;

/// START STOP UNIT (6-byte CDB).
pub const SCSI_START_STOP_UNIT: u8 = 0x1B;

// ── SCSI Status Codes ───────────────────────────────────────────

/// GOOD — command completed successfully.
pub const STATUS_GOOD: u8 = 0x00;

/// CHECK CONDITION — error; see sense data.
pub const STATUS_CHECK_CONDITION: u8 = 0x02;

/// BUSY — device cannot accept command.
pub const STATUS_BUSY: u8 = 0x08;

/// RESERVATION CONFLICT.
pub const STATUS_RESERVATION_CONFLICT: u8 = 0x18;

/// TASK SET FULL — command queue is full.
pub const STATUS_TASK_SET_FULL: u8 = 0x28;

// ── Sense Key ───────────────────────────────────────────────────

/// Sense key values from SPC-5 Table 49.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SenseKey {
    /// No sense — no error.
    #[default]
    NoSense = 0x0,
    /// Recovered error.
    RecoveredError = 0x1,
    /// Not ready (e.g., spinning up).
    NotReady = 0x2,
    /// Medium error (e.g., bad sector).
    MediumError = 0x3,
    /// Hardware error.
    HardwareError = 0x4,
    /// Illegal request (e.g., invalid CDB).
    IllegalRequest = 0x5,
    /// Unit attention (e.g., media changed).
    UnitAttention = 0x6,
    /// Data protect (write-protected).
    DataProtect = 0x7,
    /// Blank check (for sequential devices).
    BlankCheck = 0x8,
    /// Aborted command.
    AbortedCommand = 0xB,
}

impl SenseKey {
    /// Parse a sense key from a raw byte.
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x0F {
            0x0 => Self::NoSense,
            0x1 => Self::RecoveredError,
            0x2 => Self::NotReady,
            0x3 => Self::MediumError,
            0x4 => Self::HardwareError,
            0x5 => Self::IllegalRequest,
            0x6 => Self::UnitAttention,
            0x7 => Self::DataProtect,
            0x8 => Self::BlankCheck,
            0xB => Self::AbortedCommand,
            _ => Self::NoSense,
        }
    }

    /// Return whether this is a transient error worth retrying.
    pub fn is_retriable(self) -> bool {
        matches!(
            self,
            Self::NotReady | Self::UnitAttention | Self::AbortedCommand
        )
    }
}

// ── Sense Data ──────────────────────────────────────────────────

/// Parsed SCSI sense data (fixed format, SPC-5 Section 4.5).
#[derive(Debug, Clone, Copy)]
pub struct SenseData {
    /// Response code (0x70 = current, 0x71 = deferred).
    pub response_code: u8,
    /// Sense key.
    pub sense_key: SenseKey,
    /// Additional Sense Code (ASC).
    pub asc: u8,
    /// Additional Sense Code Qualifier (ASCQ).
    pub ascq: u8,
    /// Information field (LBA for medium errors).
    pub information: u32,
    /// Additional sense length.
    pub additional_length: u8,
    /// Raw sense buffer.
    raw: [u8; MAX_SENSE_SIZE],
    /// Number of valid bytes in raw buffer.
    raw_len: usize,
}

impl SenseData {
    /// Create empty sense data.
    pub const fn empty() -> Self {
        Self {
            response_code: 0,
            sense_key: SenseKey::NoSense,
            asc: 0,
            ascq: 0,
            information: 0,
            additional_length: 0,
            raw: [0u8; MAX_SENSE_SIZE],
            raw_len: 0,
        }
    }

    /// Parse sense data from a raw buffer.
    ///
    /// Handles fixed-format sense data (response code 0x70/0x71).
    pub fn from_raw(data: &[u8]) -> Self {
        let mut sense = Self::empty();

        if data.is_empty() {
            return sense;
        }

        let copy_len = data.len().min(MAX_SENSE_SIZE);
        sense.raw[..copy_len].copy_from_slice(&data[..copy_len]);
        sense.raw_len = copy_len;

        sense.response_code = data[0] & 0x7F;

        if copy_len >= 3 {
            sense.sense_key = SenseKey::from_raw(data[2]);
        }

        if copy_len >= 7 {
            sense.information = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        }

        if copy_len >= 8 {
            sense.additional_length = data[7];
        }

        if copy_len >= 13 {
            sense.asc = data[12];
        }

        if copy_len >= 14 {
            sense.ascq = data[13];
        }

        sense
    }

    /// Return whether this sense data indicates no error.
    pub fn is_ok(&self) -> bool {
        self.sense_key == SenseKey::NoSense || self.sense_key == SenseKey::RecoveredError
    }

    /// Return the raw sense buffer.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw[..self.raw_len]
    }
}

impl Default for SenseData {
    fn default() -> Self {
        Self::empty()
    }
}

// ── SCSI Command ────────────────────────────────────────────────

/// A SCSI Command Descriptor Block (CDB) with associated metadata.
#[derive(Clone, Copy)]
pub struct ScsiCommand {
    /// CDB bytes.
    pub cdb: [u8; MAX_CDB_SIZE],
    /// CDB length (6, 10, 12, or 16).
    pub cdb_len: u8,
    /// Data transfer direction.
    pub direction: DataDirection,
    /// Expected data transfer length in bytes.
    pub transfer_len: u32,
    /// Timeout in milliseconds.
    pub timeout_ms: u32,
}

impl ScsiCommand {
    /// Create an empty SCSI command.
    pub const fn empty() -> Self {
        Self {
            cdb: [0u8; MAX_CDB_SIZE],
            cdb_len: 0,
            direction: DataDirection::None,
            transfer_len: 0,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Build a TEST UNIT READY command.
    pub fn test_unit_ready() -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_TEST_UNIT_READY;
        cmd.cdb_len = 6;
        cmd.direction = DataDirection::None;
        cmd
    }

    /// Build a REQUEST SENSE command.
    pub fn request_sense(alloc_len: u8) -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_REQUEST_SENSE;
        cmd.cdb[4] = alloc_len;
        cmd.cdb_len = 6;
        cmd.direction = DataDirection::FromDevice;
        cmd.transfer_len = u32::from(alloc_len);
        cmd
    }

    /// Build a READ CAPACITY(10) command.
    pub fn read_capacity_10() -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_READ_CAPACITY_10;
        cmd.cdb_len = 10;
        cmd.direction = DataDirection::FromDevice;
        cmd.transfer_len = 8;
        cmd
    }

    /// Build a READ CAPACITY(16) command.
    pub fn read_capacity_16() -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_SERVICE_ACTION_IN_16;
        cmd.cdb[1] = SAI_READ_CAPACITY_16;
        // Allocation length = 32 bytes.
        cmd.cdb[10] = 0;
        cmd.cdb[11] = 0;
        cmd.cdb[12] = 0;
        cmd.cdb[13] = 32;
        cmd.cdb_len = 16;
        cmd.direction = DataDirection::FromDevice;
        cmd.transfer_len = 32;
        cmd
    }

    /// Build a READ(10) command.
    pub fn read_10(lba: u32, sector_count: u16) -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_READ_10;
        cmd.cdb[2] = (lba >> 24) as u8;
        cmd.cdb[3] = (lba >> 16) as u8;
        cmd.cdb[4] = (lba >> 8) as u8;
        cmd.cdb[5] = lba as u8;
        cmd.cdb[7] = (sector_count >> 8) as u8;
        cmd.cdb[8] = sector_count as u8;
        cmd.cdb_len = 10;
        cmd.direction = DataDirection::FromDevice;
        cmd.transfer_len = u32::from(sector_count) * SECTOR_SIZE;
        cmd
    }

    /// Build a WRITE(10) command.
    pub fn write_10(lba: u32, sector_count: u16) -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_WRITE_10;
        cmd.cdb[2] = (lba >> 24) as u8;
        cmd.cdb[3] = (lba >> 16) as u8;
        cmd.cdb[4] = (lba >> 8) as u8;
        cmd.cdb[5] = lba as u8;
        cmd.cdb[7] = (sector_count >> 8) as u8;
        cmd.cdb[8] = sector_count as u8;
        cmd.cdb_len = 10;
        cmd.direction = DataDirection::ToDevice;
        cmd.transfer_len = u32::from(sector_count) * SECTOR_SIZE;
        cmd
    }

    /// Build a READ(16) command.
    pub fn read_16(lba: u64, sector_count: u32) -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_READ_16;
        cmd.cdb[2] = (lba >> 56) as u8;
        cmd.cdb[3] = (lba >> 48) as u8;
        cmd.cdb[4] = (lba >> 40) as u8;
        cmd.cdb[5] = (lba >> 32) as u8;
        cmd.cdb[6] = (lba >> 24) as u8;
        cmd.cdb[7] = (lba >> 16) as u8;
        cmd.cdb[8] = (lba >> 8) as u8;
        cmd.cdb[9] = lba as u8;
        cmd.cdb[10] = (sector_count >> 24) as u8;
        cmd.cdb[11] = (sector_count >> 16) as u8;
        cmd.cdb[12] = (sector_count >> 8) as u8;
        cmd.cdb[13] = sector_count as u8;
        cmd.cdb_len = 16;
        cmd.direction = DataDirection::FromDevice;
        cmd.transfer_len = sector_count * SECTOR_SIZE;
        cmd
    }

    /// Build a WRITE(16) command.
    pub fn write_16(lba: u64, sector_count: u32) -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_WRITE_16;
        cmd.cdb[2] = (lba >> 56) as u8;
        cmd.cdb[3] = (lba >> 48) as u8;
        cmd.cdb[4] = (lba >> 40) as u8;
        cmd.cdb[5] = (lba >> 32) as u8;
        cmd.cdb[6] = (lba >> 24) as u8;
        cmd.cdb[7] = (lba >> 16) as u8;
        cmd.cdb[8] = (lba >> 8) as u8;
        cmd.cdb[9] = lba as u8;
        cmd.cdb[10] = (sector_count >> 24) as u8;
        cmd.cdb[11] = (sector_count >> 16) as u8;
        cmd.cdb[12] = (sector_count >> 8) as u8;
        cmd.cdb[13] = sector_count as u8;
        cmd.cdb_len = 16;
        cmd.direction = DataDirection::ToDevice;
        cmd.transfer_len = sector_count * SECTOR_SIZE;
        cmd
    }

    /// Build a SYNCHRONIZE CACHE(10) command.
    pub fn sync_cache() -> Self {
        let mut cmd = Self::empty();
        cmd.cdb[0] = SCSI_SYNC_CACHE_10;
        cmd.cdb_len = 10;
        cmd.direction = DataDirection::None;
        cmd
    }
}

impl Default for ScsiCommand {
    fn default() -> Self {
        Self::empty()
    }
}

/// Data transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataDirection {
    /// No data transfer.
    #[default]
    None,
    /// Device to host.
    FromDevice,
    /// Host to device.
    ToDevice,
}

// ── Disk Geometry ───────────────────────────────────────────────

/// Disk geometry and capacity information.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskGeometry {
    /// Total number of logical blocks.
    pub total_sectors: u64,
    /// Logical block size in bytes.
    pub sector_size: u32,
    /// Total capacity in bytes.
    pub capacity_bytes: u64,
    /// Whether the disk uses 16-byte commands (capacity > 2 TiB).
    pub use_16byte_cmds: bool,
    /// Physical block size (for 4Kn drives).
    pub physical_block_size: u32,
    /// Alignment offset for logical-to-physical mapping.
    pub alignment_offset: u32,
}

// ── Disk State ──────────────────────────────────────────────────

/// State of a SCSI disk device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiskState {
    /// Device not yet probed.
    #[default]
    Unknown,
    /// Device is online and operational.
    Online,
    /// Device is offline (e.g., removed, error).
    Offline,
    /// Device is being initialised.
    Probing,
    /// Device is spinning up.
    SpinningUp,
}

// ── SCSI Disk ───────────────────────────────────────────────────

/// A SCSI disk device.
///
/// Represents a single SCSI disk target and provides sector-level
/// read/write operations with automatic error recovery.
pub struct ScsiDisk {
    /// SCSI host adapter index.
    host_id: u8,
    /// SCSI channel.
    channel: u8,
    /// SCSI target ID.
    target_id: u8,
    /// SCSI LUN.
    lun: u8,
    /// Disk geometry and capacity.
    geometry: DiskGeometry,
    /// Current disk state.
    state: DiskState,
    /// Last sense data from an error.
    last_sense: SenseData,
    /// Vendor identification (from INQUIRY).
    vendor: [u8; 8],
    /// Product identification (from INQUIRY).
    product: [u8; 16],
    /// Product revision (from INQUIRY).
    revision: [u8; 4],
    /// Whether the disk is write-protected.
    write_protected: bool,
    /// Whether the disk supports FUA (Force Unit Access).
    supports_fua: bool,
    /// Maximum transfer size in sectors.
    max_sectors: u32,
    /// Total read operations.
    read_count: u64,
    /// Total write operations.
    write_count: u64,
    /// Total errors.
    error_count: u32,
    /// Total bytes read.
    read_bytes: u64,
    /// Total bytes written.
    write_bytes: u64,
}

impl ScsiDisk {
    /// Create an uninitialised SCSI disk.
    pub const fn new() -> Self {
        Self {
            host_id: 0,
            channel: 0,
            target_id: 0,
            lun: 0,
            geometry: DiskGeometry {
                total_sectors: 0,
                sector_size: SECTOR_SIZE,
                capacity_bytes: 0,
                use_16byte_cmds: false,
                physical_block_size: SECTOR_SIZE,
                alignment_offset: 0,
            },
            state: DiskState::Unknown,
            last_sense: SenseData::empty(),
            vendor: [0u8; 8],
            product: [0u8; 16],
            revision: [0u8; 4],
            write_protected: false,
            supports_fua: false,
            max_sectors: 256,
            read_count: 0,
            write_count: 0,
            error_count: 0,
            read_bytes: 0,
            write_bytes: 0,
        }
    }

    /// Initialise the SCSI disk with its address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `target_id > 15`.
    pub fn init(&mut self, host_id: u8, channel: u8, target_id: u8, lun: u8) -> Result<()> {
        if target_id > 15 {
            return Err(Error::InvalidArgument);
        }

        self.host_id = host_id;
        self.channel = channel;
        self.target_id = target_id;
        self.lun = lun;
        self.state = DiskState::Probing;

        Ok(())
    }

    /// Build a READ command for the given sector range.
    ///
    /// Automatically selects READ(10) or READ(16) based on
    /// the LBA and sector count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `sector_count` is 0
    /// or the transfer size exceeds the maximum.
    pub fn read_sectors(&mut self, lba: u64, sector_count: u32) -> Result<ScsiCommand> {
        if sector_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let transfer_bytes = (sector_count as usize)
            .checked_mul(self.geometry.sector_size as usize)
            .ok_or(Error::InvalidArgument)?;

        if transfer_bytes > MAX_TRANSFER_SIZE {
            return Err(Error::InvalidArgument);
        }

        if lba + u64::from(sector_count) > self.geometry.total_sectors {
            return Err(Error::InvalidArgument);
        }

        self.read_count += 1;
        self.read_bytes += transfer_bytes as u64;

        if lba > LBA_32BIT_LIMIT || self.geometry.use_16byte_cmds {
            Ok(ScsiCommand::read_16(lba, sector_count))
        } else {
            Ok(ScsiCommand::read_10(lba as u32, sector_count as u16))
        }
    }

    /// Build a WRITE command for the given sector range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `sector_count` is 0,
    /// the transfer exceeds maximum, or the disk is write-protected.
    pub fn write_sectors(&mut self, lba: u64, sector_count: u32) -> Result<ScsiCommand> {
        if sector_count == 0 {
            return Err(Error::InvalidArgument);
        }

        if self.write_protected {
            return Err(Error::InvalidArgument);
        }

        let transfer_bytes = (sector_count as usize)
            .checked_mul(self.geometry.sector_size as usize)
            .ok_or(Error::InvalidArgument)?;

        if transfer_bytes > MAX_TRANSFER_SIZE {
            return Err(Error::InvalidArgument);
        }

        if lba + u64::from(sector_count) > self.geometry.total_sectors {
            return Err(Error::InvalidArgument);
        }

        self.write_count += 1;
        self.write_bytes += transfer_bytes as u64;

        if lba > LBA_32BIT_LIMIT || self.geometry.use_16byte_cmds {
            Ok(ScsiCommand::write_16(lba, sector_count))
        } else {
            Ok(ScsiCommand::write_10(lba as u32, sector_count as u16))
        }
    }

    /// Build a capacity detection command.
    ///
    /// Uses READ CAPACITY(10) for initial probe; if the returned
    /// LBA is 0xFFFFFFFF, the caller should follow up with
    /// READ CAPACITY(16).
    pub fn get_capacity(&self) -> ScsiCommand {
        if self.geometry.use_16byte_cmds {
            ScsiCommand::read_capacity_16()
        } else {
            ScsiCommand::read_capacity_10()
        }
    }

    /// Parse a READ CAPACITY(10) response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the data is too short.
    pub fn parse_capacity_10(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(Error::InvalidArgument);
        }

        let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if last_lba == 0xFFFF_FFFF {
            // Disk is larger than 2 TiB — need READ CAPACITY(16).
            self.geometry.use_16byte_cmds = true;
            return Ok(());
        }

        self.geometry.total_sectors = u64::from(last_lba) + 1;
        self.geometry.sector_size = if block_size > 0 {
            block_size
        } else {
            SECTOR_SIZE
        };
        self.geometry.capacity_bytes =
            self.geometry.total_sectors * u64::from(self.geometry.sector_size);
        self.geometry.physical_block_size = self.geometry.sector_size;

        self.state = DiskState::Online;
        Ok(())
    }

    /// Parse a READ CAPACITY(16) response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the data is too short.
    pub fn parse_capacity_16(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 32 {
            return Err(Error::InvalidArgument);
        }

        let last_lba = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let block_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        self.geometry.total_sectors = last_lba + 1;
        self.geometry.sector_size = if block_size > 0 {
            block_size
        } else {
            SECTOR_SIZE
        };
        self.geometry.capacity_bytes =
            self.geometry.total_sectors * u64::from(self.geometry.sector_size);
        self.geometry.use_16byte_cmds = true;

        // Physical block exponent at byte 13 bits 3:0.
        let phys_exp = data[13] & 0x0F;
        self.geometry.physical_block_size = self.geometry.sector_size << phys_exp;

        // Alignment offset at bytes 14-15 bits 13:0.
        let align_raw = u16::from_be_bytes([data[14], data[15]]) & 0x3FFF;
        self.geometry.alignment_offset = u32::from(align_raw);

        self.state = DiskState::Online;
        Ok(())
    }

    /// Build a TEST UNIT READY command.
    pub fn test_unit_ready(&self) -> ScsiCommand {
        ScsiCommand::test_unit_ready()
    }

    /// Build a REQUEST SENSE command.
    pub fn request_sense(&self) -> ScsiCommand {
        ScsiCommand::request_sense(MAX_SENSE_SIZE as u8)
    }

    /// Store sense data from an error response.
    pub fn set_last_sense(&mut self, data: &[u8]) {
        self.last_sense = SenseData::from_raw(data);
    }

    /// Process a SCSI status byte and decide whether to retry.
    ///
    /// Returns `Ok(true)` if the command should be retried,
    /// `Ok(false)` if the error is permanent, or `Err` if
    /// processing fails.
    pub fn handle_error(&mut self, status: u8, sense: &SenseData) -> Result<bool> {
        self.last_sense = *sense;
        self.error_count += 1;

        match status {
            STATUS_GOOD => Ok(false),
            STATUS_CHECK_CONDITION => Ok(sense.sense_key.is_retriable()),
            STATUS_BUSY | STATUS_TASK_SET_FULL => {
                // Transient — retry after delay.
                Ok(true)
            }
            _ => {
                // Permanent error.
                Ok(false)
            }
        }
    }

    /// Build a SYNCHRONIZE CACHE command.
    pub fn sync_cache(&self) -> ScsiCommand {
        ScsiCommand::sync_cache()
    }

    // ── Accessors ───────────────────────────────────────────

    /// Return the disk geometry.
    pub fn geometry(&self) -> &DiskGeometry {
        &self.geometry
    }

    /// Return the disk state.
    pub fn state(&self) -> DiskState {
        self.state
    }

    /// Return the last sense data.
    pub fn last_sense(&self) -> &SenseData {
        &self.last_sense
    }

    /// Return the vendor string.
    pub fn vendor(&self) -> &[u8; 8] {
        &self.vendor
    }

    /// Return the product string.
    pub fn product(&self) -> &[u8; 16] {
        &self.product
    }

    /// Return the revision string.
    pub fn revision(&self) -> &[u8; 4] {
        &self.revision
    }

    /// Set the vendor/product/revision from INQUIRY data.
    pub fn set_inquiry_data(&mut self, vendor: &[u8], product: &[u8], rev: &[u8]) {
        let vlen = vendor.len().min(8);
        self.vendor[..vlen].copy_from_slice(&vendor[..vlen]);
        let plen = product.len().min(16);
        self.product[..plen].copy_from_slice(&product[..plen]);
        let rlen = rev.len().min(4);
        self.revision[..rlen].copy_from_slice(&rev[..rlen]);
    }

    /// Return whether the disk is write-protected.
    pub fn is_write_protected(&self) -> bool {
        self.write_protected
    }

    /// Set the write-protection state.
    pub fn set_write_protected(&mut self, wp: bool) {
        self.write_protected = wp;
    }

    /// Set the disk state.
    pub fn set_state(&mut self, state: DiskState) {
        self.state = state;
    }

    /// Return the SCSI target address as (host, channel, target, lun).
    pub fn address(&self) -> (u8, u8, u8, u8) {
        (self.host_id, self.channel, self.target_id, self.lun)
    }

    /// Return the total read count.
    pub fn read_count(&self) -> u64 {
        self.read_count
    }

    /// Return the total write count.
    pub fn write_count(&self) -> u64 {
        self.write_count
    }

    /// Return the error count.
    pub fn error_count(&self) -> u32 {
        self.error_count
    }

    /// Return the total bytes read.
    pub fn read_bytes(&self) -> u64 {
        self.read_bytes
    }

    /// Return the total bytes written.
    pub fn write_bytes(&self) -> u64 {
        self.write_bytes
    }

    /// Return the maximum sectors per transfer.
    pub fn max_sectors(&self) -> u32 {
        self.max_sectors
    }

    /// Set the maximum sectors per transfer.
    pub fn set_max_sectors(&mut self, max: u32) {
        self.max_sectors = max;
    }
}

impl Default for ScsiDisk {
    fn default() -> Self {
        Self::new()
    }
}

// ── SCSI Disk Registry ──────────────────────────────────────────

/// Registry of SCSI disk devices.
pub struct ScsiDiskRegistry {
    /// Registered disks.
    devices: [Option<ScsiDisk>; MAX_SCSI_DISKS],
    /// Number of registered disks.
    count: usize,
}

impl ScsiDiskRegistry {
    /// Create an empty SCSI disk registry.
    pub const fn new() -> Self {
        const NONE: Option<ScsiDisk> = None;
        Self {
            devices: [NONE; MAX_SCSI_DISKS],
            count: 0,
        }
    }

    /// Register a SCSI disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, disk: ScsiDisk) -> Result<usize> {
        if self.count >= MAX_SCSI_DISKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(disk);
        self.count += 1;
        Ok(idx)
    }

    /// Return a reference to a disk by index.
    pub fn get(&self, index: usize) -> Option<&ScsiDisk> {
        if index < self.count {
            self.devices[index].as_ref()
        } else {
            None
        }
    }

    /// Return a mutable reference to a disk by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ScsiDisk> {
        if index < self.count {
            self.devices[index].as_mut()
        } else {
            None
        }
    }

    /// Find a disk by SCSI address.
    pub fn find_by_address(
        &self,
        host_id: u8,
        channel: u8,
        target_id: u8,
        lun: u8,
    ) -> Option<&ScsiDisk> {
        for i in 0..self.count {
            if let Some(disk) = &self.devices[i] {
                let (h, c, t, l) = disk.address();
                if h == host_id && c == channel && t == target_id && l == lun {
                    return Some(disk);
                }
            }
        }
        None
    }

    /// Return the number of registered disks.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ScsiDiskRegistry {
    fn default() -> Self {
        Self::new()
    }
}
