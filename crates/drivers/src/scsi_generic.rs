// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCSI generic passthrough driver (sg).
//!
//! Provides a raw SCSI command passthrough interface for user-space tools
//! (e.g., smartctl, sg_utils) that need to send arbitrary SCSI commands.
//! Equivalent to Linux's `/dev/sg*` character devices and the `sg` driver.
//!
//! # Architecture
//!
//! - Each SCSI device gets an `SgDevice` representing the passthrough handle.
//! - Commands are submitted as `SgIoHdr` structures (inspired by Linux sg_io).
//! - Supports CDB sizes 6, 10, 12, 16.
//! - Returns sense data inline on SCSI check condition.
//!
//! # SG_IO Header
//!
//! The `SgIoHdr` mirrors the Linux `sg_io_hdr_t` structure used by the
//! `SG_IO` ioctl. Fields relevant to ONCRIX:
//!
//! | Field         | Description                                   |
//! |---------------|-----------------------------------------------|
//! | `interface_id`| Must be `'S'` (0x53)                         |
//! | `dxfer_direction` | TO_DEV, FROM_DEV, NONE, UNKNOWN          |
//! | `cmd_len`     | CDB length (6, 10, 12, or 16)               |
//! | `mx_sb_len`   | Max sense buffer length                       |
//! | `dxfer_len`   | Data transfer length in bytes                 |
//! | `status`      | SCSI status byte (filled by driver)           |
//! | `masked_status`| status >> 1 (masked)                         |
//! | `info`        | Driver-specific info byte                     |
//! | `sb_len_wr`   | Sense data bytes written (filled by driver)   |
//! | `resid`       | Residual count (filled by driver)             |
//! | `duration`    | Command duration in ms (filled by driver)     |
//!
//! Reference: Linux kernel `sg.h`, SCSI Generic HOWTO.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of SG device handles.
pub const MAX_SG_DEVICES: usize = 32;
/// SG_IO interface ID (must be 'S' = 0x53).
pub const SG_INTERFACE_ID: u8 = b'S';
/// Maximum CDB length.
pub const MAX_CDB_LEN: usize = 16;
/// Maximum sense buffer length.
pub const MAX_SENSE_LEN: usize = 96;
/// Maximum inline data buffer for passthrough.
pub const MAX_SG_DATA_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// Data transfer direction
// ---------------------------------------------------------------------------

/// Data transfer direction for SG passthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgDxferDirection {
    /// No data transfer.
    None,
    /// Data from host to device (write).
    ToDevice,
    /// Data from device to host (read).
    FromDevice,
    /// Unknown direction.
    Unknown,
}

impl Default for SgDxferDirection {
    fn default() -> Self {
        Self::None
    }
}

// ---------------------------------------------------------------------------
// SCSI status byte values
// ---------------------------------------------------------------------------

/// SCSI status: Good.
pub const SCSI_STATUS_GOOD: u8 = 0x00;
/// SCSI status: Check Condition.
pub const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;
/// SCSI status: Condition Met.
pub const SCSI_STATUS_CONDITION_MET: u8 = 0x04;
/// SCSI status: Busy.
pub const SCSI_STATUS_BUSY: u8 = 0x08;
/// SCSI status: Reservation Conflict.
pub const SCSI_STATUS_RESERVATION_CONFLICT: u8 = 0x18;

// ---------------------------------------------------------------------------
// SG I/O header
// ---------------------------------------------------------------------------

/// SCSI generic I/O request header.
///
/// Modeled on Linux `sg_io_hdr_t`.
#[derive(Debug, Clone)]
pub struct SgIoHdr {
    /// Interface ID: must be `SG_INTERFACE_ID` ('S').
    pub interface_id: u8,
    /// Data transfer direction.
    pub dxfer_direction: SgDxferDirection,
    /// CDB length.
    pub cmd_len: u8,
    /// Maximum sense buffer length.
    pub mx_sb_len: u8,
    /// Data transfer length in bytes.
    pub dxfer_len: u32,
    /// CDB bytes (up to 16).
    pub cmdp: [u8; MAX_CDB_LEN],
    /// Sense buffer (filled by driver on Check Condition).
    pub sbp: [u8; MAX_SENSE_LEN],
    /// SCSI status byte (output).
    pub status: u8,
    /// Masked SCSI status (status >> 1).
    pub masked_status: u8,
    /// Driver info byte.
    pub info: u8,
    /// Sense bytes written.
    pub sb_len_wr: u8,
    /// Residual data count.
    pub resid: u32,
    /// Command duration in milliseconds.
    pub duration: u32,
}

impl Default for SgIoHdr {
    fn default() -> Self {
        Self {
            interface_id: 0,
            dxfer_direction: SgDxferDirection::default(),
            cmd_len: 0,
            mx_sb_len: 0,
            dxfer_len: 0,
            cmdp: [0u8; MAX_CDB_LEN],
            sbp: [0u8; MAX_SENSE_LEN],
            status: 0,
            masked_status: 0,
            info: 0,
            sb_len_wr: 0,
            resid: 0,
            duration: 0,
        }
    }
}

impl SgIoHdr {
    /// Creates a new SG I/O header for a read command.
    pub fn new_read(cdb: &[u8], transfer_len: u32) -> Result<Self> {
        if cdb.len() > MAX_CDB_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut hdr = Self::default();
        hdr.interface_id = SG_INTERFACE_ID;
        hdr.dxfer_direction = SgDxferDirection::FromDevice;
        hdr.cmd_len = cdb.len() as u8;
        hdr.mx_sb_len = MAX_SENSE_LEN as u8;
        hdr.dxfer_len = transfer_len;
        hdr.cmdp[..cdb.len()].copy_from_slice(cdb);
        Ok(hdr)
    }

    /// Creates a new SG I/O header for a write command.
    pub fn new_write(cdb: &[u8], transfer_len: u32) -> Result<Self> {
        if cdb.len() > MAX_CDB_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut hdr = Self::default();
        hdr.interface_id = SG_INTERFACE_ID;
        hdr.dxfer_direction = SgDxferDirection::ToDevice;
        hdr.cmd_len = cdb.len() as u8;
        hdr.mx_sb_len = MAX_SENSE_LEN as u8;
        hdr.dxfer_len = transfer_len;
        hdr.cmdp[..cdb.len()].copy_from_slice(cdb);
        Ok(hdr)
    }

    /// Creates a new SG I/O header for a no-data command.
    pub fn new_nodata(cdb: &[u8]) -> Result<Self> {
        if cdb.len() > MAX_CDB_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut hdr = Self::default();
        hdr.interface_id = SG_INTERFACE_ID;
        hdr.dxfer_direction = SgDxferDirection::None;
        hdr.cmd_len = cdb.len() as u8;
        hdr.mx_sb_len = MAX_SENSE_LEN as u8;
        hdr.dxfer_len = 0;
        hdr.cmdp[..cdb.len()].copy_from_slice(cdb);
        Ok(hdr)
    }

    /// Returns `true` if the command completed with Check Condition.
    pub fn has_check_condition(&self) -> bool {
        self.status == SCSI_STATUS_CHECK_CONDITION
    }

    /// Returns the sense key from the sense buffer (if present).
    pub fn sense_key(&self) -> Option<u8> {
        if self.sb_len_wr >= 3 {
            Some(self.sbp[2] & 0x0F)
        } else {
            None
        }
    }

    /// Returns the ASC/ASCQ pair from sense data.
    pub fn sense_asc_ascq(&self) -> Option<(u8, u8)> {
        if self.sb_len_wr >= 14 {
            Some((self.sbp[12], self.sbp[13]))
        } else {
            None
        }
    }

    /// Validates the header fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `interface_id != 'S'` or
    /// `cmd_len` is not 6, 10, 12, or 16.
    pub fn validate(&self) -> Result<()> {
        if self.interface_id != SG_INTERFACE_ID {
            return Err(Error::InvalidArgument);
        }
        match self.cmd_len {
            6 | 10 | 12 | 16 => {}
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SgDevice
// ---------------------------------------------------------------------------

/// A SCSI generic passthrough device handle.
pub struct SgDevice {
    /// SCSI host number.
    pub host: u8,
    /// Channel (bus) on the host.
    pub channel: u8,
    /// Target ID.
    pub target: u8,
    /// LUN.
    pub lun: u8,
    /// Inline data buffer for small transfers.
    pub data_buf: [u8; MAX_SG_DATA_LEN],
    /// Whether this device handle is open.
    pub open: bool,
}

impl SgDevice {
    /// Creates a new SG device handle.
    pub const fn new(host: u8, channel: u8, target: u8, lun: u8) -> Self {
        Self {
            host,
            channel,
            target,
            lun,
            data_buf: [0u8; MAX_SG_DATA_LEN],
            open: false,
        }
    }

    /// Opens the device handle.
    pub fn open(&mut self) {
        self.open = true;
    }

    /// Closes the device handle.
    pub fn close(&mut self) {
        self.open = false;
    }

    /// Submits a SCSI command via the SG I/O header.
    ///
    /// `execute` is a transport-specific function that takes the target
    /// address, CDB, data buffer, and sense buffer, returns the SCSI status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the header is invalid.
    /// Returns [`Error::NotFound`] if the device handle is closed.
    pub fn execute<F>(&mut self, hdr: &mut SgIoHdr, execute: F) -> Result<()>
    where
        F: FnOnce(u8, u8, u8, u8, &[u8], &mut [u8], &mut [u8]) -> Result<(u8, u8, u32)>,
    {
        if !self.open {
            return Err(Error::NotFound);
        }
        hdr.validate()?;

        let cdb = &hdr.cmdp[..hdr.cmd_len as usize];
        let data_len = hdr.dxfer_len as usize;
        let actual_data_len = data_len.min(MAX_SG_DATA_LEN);

        let (status, sb_len, resid) = execute(
            self.host,
            self.channel,
            self.target,
            self.lun,
            cdb,
            &mut self.data_buf[..actual_data_len],
            &mut hdr.sbp,
        )?;

        hdr.status = status;
        hdr.masked_status = status >> 1;
        hdr.sb_len_wr = sb_len;
        hdr.resid = resid;
        Ok(())
    }

    /// Returns `true` if the device is open.
    pub fn is_open(&self) -> bool {
        self.open
    }
}

impl Default for SgDevice {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Global SG device registry.
pub struct SgRegistry {
    devices: [SgDevice; MAX_SG_DEVICES],
    count: usize,
}

impl SgRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { SgDevice::new(0, 0, 0, 0) }; MAX_SG_DEVICES],
            count: 0,
        }
    }

    /// Registers a new SG device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, host: u8, channel: u8, target: u8, lun: u8) -> Result<usize> {
        if self.count >= MAX_SG_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = SgDevice::new(host, channel, target, lun);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the device at `index`.
    pub fn get(&self, index: usize) -> Option<&SgDevice> {
        if index < self.count {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the device at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut SgDevice> {
        if index < self.count {
            Some(&mut self.devices[index])
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for SgRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sg_hdr_validate_ok() {
        let cdb = [0x12u8, 0, 0, 0, 36, 0]; // INQUIRY
        let hdr = SgIoHdr::new_read(&cdb, 36).unwrap();
        assert!(hdr.validate().is_ok());
    }

    #[test]
    fn sg_hdr_validate_bad_interface_id() {
        let cdb = [0x12u8, 0, 0, 0, 36, 0];
        let mut hdr = SgIoHdr::new_read(&cdb, 36).unwrap();
        hdr.interface_id = b'X';
        assert!(hdr.validate().is_err());
    }

    #[test]
    fn sg_hdr_validate_bad_cdb_len() {
        let cdb = [0x12u8, 0, 0, 0, 36, 0];
        let mut hdr = SgIoHdr::new_read(&cdb, 36).unwrap();
        hdr.cmd_len = 7; // invalid
        assert!(hdr.validate().is_err());
    }

    #[test]
    fn sg_registry_operations() {
        let mut reg = SgRegistry::new();
        let idx = reg.register(0, 0, 2, 0).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }
}
