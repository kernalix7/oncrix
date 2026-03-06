// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCSI disk driver (equivalent to Linux `sd`).
//!
//! Implements the SCSI block device layer for direct-access devices
//! (TYPE_DISK). Handles READ(10)/WRITE(10)/READ CAPACITY(10)/
//! TEST UNIT READY/INQUIRY commands and maps them to the block I/O layer.
//!
//! # SCSI Command Overview
//!
//! | Command          | Op Code | CDB Size | Description                  |
//! |-----------------|---------|----------|------------------------------|
//! | TEST UNIT READY  | 0x00    | 6        | Check if device is ready     |
//! | INQUIRY          | 0x12    | 6        | Get device identification    |
//! | READ CAPACITY(10)| 0x25    | 10       | Get last LBA + block size    |
//! | READ(10)         | 0x28    | 10       | Read blocks from LBA         |
//! | WRITE(10)        | 0x2A    | 10       | Write blocks to LBA          |
//! | SYNCHRONIZE CACHE| 0x35    | 10       | Flush write cache            |
//! | READ(16)         | 0x88    | 16       | Large LBA read               |
//! | WRITE(16)        | 0x8A    | 16       | Large LBA write              |
//!
//! Reference: SCSI Block Commands 3 (SBC-3), T10/BSR INCITS 514-2014.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of SCSI disk devices.
pub const MAX_SCSI_DISKS: usize = 16;
/// Standard SCSI block size.
pub const SCSI_BLOCK_SIZE: u32 = 512;
/// Maximum transfer length in blocks for READ/WRITE(10).
pub const MAX_TRANSFER_BLOCKS_10: u16 = 0xFFFF;
/// SCSI INQUIRY data length (standard 36 bytes).
pub const INQUIRY_DATA_LEN: usize = 36;

// ---------------------------------------------------------------------------
// SCSI CDB structures
// ---------------------------------------------------------------------------

/// 6-byte CDB.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Cdb6 {
    pub op_code: u8,
    pub lun_lba: u8,
    pub lba_mid: u8,
    pub lba_low: u8,
    pub transfer_length: u8,
    pub control: u8,
}

/// 10-byte CDB.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Cdb10 {
    pub op_code: u8,
    pub flags: u8,
    pub lba: [u8; 4],
    pub group_number: u8,
    pub transfer_length: [u8; 2],
    pub control: u8,
}

impl Cdb10 {
    /// Builds a READ(10) CDB.
    pub fn read10(lba: u32, len: u16) -> Self {
        Self {
            op_code: 0x28,
            flags: 0,
            lba: lba.to_be_bytes(),
            group_number: 0,
            transfer_length: len.to_be_bytes(),
            control: 0,
        }
    }

    /// Builds a WRITE(10) CDB.
    pub fn write10(lba: u32, len: u16) -> Self {
        Self {
            op_code: 0x2A,
            flags: 0,
            lba: lba.to_be_bytes(),
            group_number: 0,
            transfer_length: len.to_be_bytes(),
            control: 0,
        }
    }

    /// Builds a READ CAPACITY(10) CDB.
    pub fn read_capacity10() -> Self {
        Self {
            op_code: 0x25,
            flags: 0,
            lba: [0u8; 4],
            group_number: 0,
            transfer_length: [0u8; 2],
            control: 0,
        }
    }

    /// Builds a SYNCHRONIZE CACHE(10) CDB.
    pub fn sync_cache10(lba: u32, len: u16) -> Self {
        Self {
            op_code: 0x35,
            flags: 0,
            lba: lba.to_be_bytes(),
            group_number: 0,
            transfer_length: len.to_be_bytes(),
            control: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SCSI Sense Key
// ---------------------------------------------------------------------------

/// SCSI sense key values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SenseKey {
    /// No error.
    NoSense = 0x00,
    /// Recovered error.
    RecoveredError = 0x01,
    /// Device not ready.
    NotReady = 0x02,
    /// Medium error.
    MediumError = 0x03,
    /// Hardware error.
    HardwareError = 0x04,
    /// Illegal request (bad CDB).
    IllegalRequest = 0x05,
    /// Unit attention (media change, reset).
    UnitAttention = 0x06,
    /// Data protect (write protected).
    DataProtect = 0x07,
    /// Blank check.
    BlankCheck = 0x08,
    /// Aborted command.
    AbortedCommand = 0x0B,
}

/// Fixed-format SCSI sense data (18 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SenseData {
    /// Response code (0x70 = current, 0x71 = deferred).
    pub response_code: u8,
    pub obsolete: u8,
    /// Sense key [3:0].
    pub sense_key: u8,
    pub information: [u8; 4],
    /// Additional sense length (n - 7).
    pub additional_length: u8,
    pub command_information: [u8; 4],
    /// Additional sense code.
    pub asc: u8,
    /// Additional sense code qualifier.
    pub ascq: u8,
    pub fru_code: u8,
    pub sense_key_specific: [u8; 3],
}

// ---------------------------------------------------------------------------
// INQUIRY response
// ---------------------------------------------------------------------------

/// Standard SCSI INQUIRY data (36 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InquiryData {
    /// Peripheral qualifier [7:5] + device type [4:0].
    pub peripheral: u8,
    /// Removable medium bit [7].
    pub removable: u8,
    /// Version (SPC version compliance).
    pub version: u8,
    /// Response data format [3:0].
    pub response_data_format: u8,
    /// Additional length (n - 4).
    pub additional_length: u8,
    pub scsi_capabilities: u8,
    pub reserved: u8,
    pub flags: u8,
    /// Vendor identification (T10 vendor).
    pub vendor_id: [u8; 8],
    /// Product identification.
    pub product_id: [u8; 16],
    /// Product revision level.
    pub product_rev: [u8; 4],
}

// ---------------------------------------------------------------------------
// ScsiDisk
// ---------------------------------------------------------------------------

/// SCSI disk device state.
pub struct ScsiDisk {
    /// Target ID on the SCSI bus / logical unit number.
    pub target: u8,
    pub lun: u8,
    /// Block size in bytes.
    pub block_size: u32,
    /// Last logical block address (total_blocks - 1).
    pub last_lba: u64,
    /// INQUIRY data.
    pub inquiry: InquiryData,
    /// Whether the device has been probed.
    pub initialized: bool,
    /// Write-cache enabled.
    pub write_cache: bool,
}

impl ScsiDisk {
    /// Creates a new SCSI disk instance.
    pub const fn new(target: u8, lun: u8) -> Self {
        Self {
            target,
            lun,
            block_size: SCSI_BLOCK_SIZE,
            last_lba: 0,
            inquiry: InquiryData {
                peripheral: 0,
                removable: 0,
                version: 0,
                response_data_format: 0,
                additional_length: 0,
                scsi_capabilities: 0,
                reserved: 0,
                flags: 0,
                vendor_id: [0u8; 8],
                product_id: [0u8; 16],
                product_rev: [0u8; 4],
            },
            initialized: false,
            write_cache: false,
        }
    }

    /// Probes the disk: sends INQUIRY and READ CAPACITY(10).
    ///
    /// `send_command` is a closure that sends a SCSI CDB and returns
    /// the response data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if a command fails.
    /// Returns [`Error::NotFound`] if the device does not respond.
    pub fn probe<F>(&mut self, mut send_command: F) -> Result<()>
    where
        F: FnMut(&[u8], &mut [u8]) -> Result<()>,
    {
        // TEST UNIT READY.
        let tur_cdb = [0x00u8, 0, 0, 0, 0, 0];
        let mut dummy = [0u8; 0];
        send_command(&tur_cdb, &mut dummy)?;

        // INQUIRY.
        let inq_cdb = [
            0x12u8, // INQUIRY
            0,
            0,
            0,
            INQUIRY_DATA_LEN as u8,
            0,
        ];
        let mut inq_buf = [0u8; INQUIRY_DATA_LEN];
        send_command(&inq_cdb, &mut inq_buf)?;
        // Parse inquiry response.
        self.inquiry.peripheral = inq_buf[0];
        self.inquiry.removable = inq_buf[1];
        self.inquiry.vendor_id.copy_from_slice(&inq_buf[8..16]);
        self.inquiry.product_id.copy_from_slice(&inq_buf[16..32]);
        self.inquiry.product_rev.copy_from_slice(&inq_buf[32..36]);

        // READ CAPACITY(10).
        let cap10_cdb: [u8; 10] = {
            let mut c = [0u8; 10];
            c[0] = 0x25;
            c
        };
        let mut cap_buf = [0u8; 8];
        send_command(&cap10_cdb, &mut cap_buf)?;
        let last_lba = u32::from_be_bytes([cap_buf[0], cap_buf[1], cap_buf[2], cap_buf[3]]);
        let block_size = u32::from_be_bytes([cap_buf[4], cap_buf[5], cap_buf[6], cap_buf[7]]);
        self.last_lba = last_lba as u64;
        self.block_size = block_size;

        self.initialized = true;
        Ok(())
    }

    /// Returns the total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        (self.last_lba + 1).saturating_mul(self.block_size as u64)
    }

    /// Returns the total number of blocks.
    pub fn total_blocks(&self) -> u64 {
        self.last_lba + 1
    }

    /// Builds a READ(10) CDB for `lba` and `count` blocks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if LBA > u32::MAX or count is zero.
    pub fn build_read10(&self, lba: u64, count: u16) -> Result<Cdb10> {
        if lba > u32::MAX as u64 || count == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Cdb10::read10(lba as u32, count))
    }

    /// Builds a WRITE(10) CDB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if LBA > u32::MAX or count is zero.
    pub fn build_write10(&self, lba: u64, count: u16) -> Result<Cdb10> {
        if lba > u32::MAX as u64 || count == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Cdb10::write10(lba as u32, count))
    }

    /// Returns `true` if the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for ScsiDisk {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Global SCSI disk registry.
pub struct ScsiDiskRegistry {
    disks: [ScsiDisk; MAX_SCSI_DISKS],
    count: usize,
}

impl ScsiDiskRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            disks: [const { ScsiDisk::new(0, 0) }; MAX_SCSI_DISKS],
            count: 0,
        }
    }

    /// Registers a SCSI disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, target: u8, lun: u8) -> Result<usize> {
        if self.count >= MAX_SCSI_DISKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.disks[idx] = ScsiDisk::new(target, lun);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the disk at `index`.
    pub fn get(&self, index: usize) -> Option<&ScsiDisk> {
        if index < self.count {
            Some(&self.disks[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the disk at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ScsiDisk> {
        if index < self.count {
            Some(&mut self.disks[index])
        } else {
            None
        }
    }

    /// Returns the number of registered disks.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no disks are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ScsiDiskRegistry {
    fn default() -> Self {
        Self::new()
    }
}
