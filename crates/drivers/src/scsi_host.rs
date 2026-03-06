// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCSI host adapter abstraction.
//!
//! Provides the `ScsiHost` type representing a host bus adapter (HBA),
//! `ScsiCmd` for constructing and executing SCSI commands, and a simple
//! command-dispatch and error-handling layer.
//!
//! # Architecture
//!
//! - `ScsiHost` — HBA descriptor with topology limits.
//! - `ScsiCmd` — 16-byte CDB + data buffer + status.
//! - `ScsiStatus` — SAM-4 status byte values.
//! - `ScsiSense` — fixed-format sense data.

extern crate alloc;
use alloc::vec::Vec;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of registered SCSI hosts.
const MAX_HOSTS: usize = 8;

/// Maximum CDB length supported.
const CDB_SIZE: usize = 16;

/// Maximum number of retries on BUSY status.
const MAX_RETRIES: u8 = 3;

// ── SCSI status bytes (SAM-4) ────────────────────────────────────────────────

/// SAM-4 status byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScsiStatus {
    /// Command completed successfully.
    Good = 0x00,
    /// CHECK CONDITION — sense data available.
    CheckCondition = 0x02,
    /// CONDITION MET.
    ConditionMet = 0x04,
    /// Device busy.
    Busy = 0x08,
    /// Task set full (queue full).
    TaskSetFull = 0x28,
    /// ACA active.
    AcaActive = 0x30,
    /// Task aborted.
    TaskAborted = 0x40,
}

impl ScsiStatus {
    /// Decode from a raw status byte.
    pub fn from_raw(v: u8) -> Self {
        match v & 0xFE {
            0x00 => Self::Good,
            0x02 => Self::CheckCondition,
            0x04 => Self::ConditionMet,
            0x08 => Self::Busy,
            0x28 => Self::TaskSetFull,
            0x30 => Self::AcaActive,
            0x40 => Self::TaskAborted,
            _ => Self::CheckCondition,
        }
    }
}

// ── Data transfer direction ───────────────────────────────────────────────────

/// Direction of data transfer for a SCSI command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    /// No data transfer.
    None,
    /// Data from device to host.
    FromDevice,
    /// Data from host to device.
    ToDevice,
    /// Bidirectional (rare).
    Bidirectional,
}

// ── ScsiSense ─────────────────────────────────────────────────────────────────

/// Fixed-format SCSI sense data (18 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ScsiSense {
    /// Response code (0x70 or 0x71).
    pub response_code: u8,
    /// Obsolete.
    pub _reserved: u8,
    /// Sense key (bits 3:0).
    pub sense_key: u8,
    /// Information bytes.
    pub information: [u8; 4],
    /// Additional sense length.
    pub asl: u8,
    /// Command-specific information.
    pub cmd_info: [u8; 4],
    /// Additional Sense Code.
    pub asc: u8,
    /// Additional Sense Code Qualifier.
    pub ascq: u8,
    /// Field Replaceable Unit code.
    pub fru: u8,
    /// Sense key specific.
    pub sks: [u8; 3],
}

// ── ScsiCmd ───────────────────────────────────────────────────────────────────

/// A SCSI command descriptor.
pub struct ScsiCmd {
    /// Command Descriptor Block (16 bytes).
    pub cdb: [u8; CDB_SIZE],
    /// Actual CDB length in use (1–16 bytes).
    pub cdb_len: u8,
    /// Target channel.
    pub channel: u8,
    /// Target ID (SCSI ID on the bus).
    pub target: u8,
    /// Logical Unit Number.
    pub lun: u8,
    /// Data transfer direction.
    pub direction: DataDirection,
    /// Data buffer (host memory).
    pub data: Vec<u8>,
    /// Requested transfer length.
    pub transfer_len: u32,
    /// Actual transferred length after completion.
    pub actual_len: u32,
    /// Status byte after completion.
    pub status: u8,
    /// Sense data after CHECK CONDITION.
    pub sense: ScsiSense,
    /// Retry count remaining.
    pub retries_left: u8,
    /// Command timeout in milliseconds.
    pub timeout_ms: u32,
}

impl ScsiCmd {
    /// Create a new SCSI command.
    pub fn new(channel: u8, target: u8, lun: u8) -> Self {
        Self {
            cdb: [0u8; CDB_SIZE],
            cdb_len: 6,
            channel,
            target,
            lun,
            direction: DataDirection::None,
            data: Vec::new(),
            transfer_len: 0,
            actual_len: 0,
            status: 0,
            sense: ScsiSense::default(),
            retries_left: MAX_RETRIES,
            timeout_ms: 5000,
        }
    }

    /// Set the 6-byte INQUIRY CDB (opcode 0x12).
    pub fn set_inquiry(&mut self, evpd: bool, page_code: u8, alloc_len: u16) {
        self.cdb = [0u8; CDB_SIZE];
        self.cdb[0] = 0x12; // INQUIRY
        self.cdb[1] = if evpd { 0x01 } else { 0x00 };
        self.cdb[2] = page_code;
        self.cdb[3] = (alloc_len >> 8) as u8;
        self.cdb[4] = (alloc_len & 0xFF) as u8;
        self.cdb_len = 6;
        self.direction = DataDirection::FromDevice;
        self.transfer_len = alloc_len as u32;
        self.data.resize(alloc_len as usize, 0);
    }

    /// Set the 10-byte READ(10) CDB (opcode 0x28).
    pub fn set_read10(&mut self, lba: u32, nr_blocks: u16) {
        self.cdb = [0u8; CDB_SIZE];
        self.cdb[0] = 0x28; // READ(10)
        self.cdb[2] = (lba >> 24) as u8;
        self.cdb[3] = (lba >> 16) as u8;
        self.cdb[4] = (lba >> 8) as u8;
        self.cdb[5] = lba as u8;
        self.cdb[7] = (nr_blocks >> 8) as u8;
        self.cdb[8] = nr_blocks as u8;
        self.cdb_len = 10;
        self.direction = DataDirection::FromDevice;
        self.transfer_len = nr_blocks as u32 * 512;
        self.data.resize(self.transfer_len as usize, 0);
    }

    /// Set the 10-byte WRITE(10) CDB (opcode 0x2A).
    pub fn set_write10(&mut self, lba: u32, nr_blocks: u16) {
        self.cdb = [0u8; CDB_SIZE];
        self.cdb[0] = 0x2A; // WRITE(10)
        self.cdb[2] = (lba >> 24) as u8;
        self.cdb[3] = (lba >> 16) as u8;
        self.cdb[4] = (lba >> 8) as u8;
        self.cdb[5] = lba as u8;
        self.cdb[7] = (nr_blocks >> 8) as u8;
        self.cdb[8] = nr_blocks as u8;
        self.cdb_len = 10;
        self.direction = DataDirection::ToDevice;
        self.transfer_len = nr_blocks as u32 * 512;
    }

    /// Set the TEST UNIT READY CDB (opcode 0x00, 6 bytes).
    pub fn set_test_unit_ready(&mut self) {
        self.cdb = [0u8; CDB_SIZE];
        self.cdb_len = 6;
        self.direction = DataDirection::None;
        self.transfer_len = 0;
    }

    /// Return the decoded SCSI status.
    pub fn scsi_status(&self) -> ScsiStatus {
        ScsiStatus::from_raw(self.status)
    }

    /// Return whether the command completed with GOOD status.
    pub fn is_good(&self) -> bool {
        self.scsi_status() == ScsiStatus::Good
    }
}

// ── ScsiHost ──────────────────────────────────────────────────────────────────

/// SCSI host adapter (HBA) descriptor.
pub struct ScsiHost {
    /// Host number (index in the global registry).
    pub host_no: u8,
    /// Maximum number of LUNs per target.
    pub max_lun: u32,
    /// Maximum number of targets on this host.
    pub max_id: u32,
    /// Maximum number of channels.
    pub max_channel: u32,
    /// Maximum scatter-gather segments per command.
    pub sg_tablesize: u32,
    /// Maximum transfer size in bytes.
    pub max_transfer_bytes: u32,
    /// Human-readable host name.
    pub name: [u8; 32],
    /// Whether the host is ready to accept commands.
    pub ready: bool,
    /// Host command dispatch function.
    pub queuecommand: Option<fn(host: &ScsiHost, cmd: &mut ScsiCmd) -> Result<()>>,
    /// Host error recovery function (abort a command).
    pub abort_command: Option<fn(host: &ScsiHost, cmd: &mut ScsiCmd) -> Result<()>>,
    /// Host bus reset function.
    pub host_reset: Option<fn(host: &ScsiHost) -> Result<()>>,
}

impl ScsiHost {
    /// Create a new SCSI host descriptor.
    pub const fn new(host_no: u8) -> Self {
        Self {
            host_no,
            max_lun: 8,
            max_id: 16,
            max_channel: 1,
            sg_tablesize: 32,
            max_transfer_bytes: 512 * 256,
            name: [0u8; 32],
            ready: false,
            queuecommand: None,
            abort_command: None,
            host_reset: None,
        }
    }

    /// Set the host name.
    pub fn set_name(&mut self, name: &str) {
        let b = name.as_bytes();
        let len = b.len().min(31);
        self.name[..len].copy_from_slice(&b[..len]);
    }

    /// Dispatch a command to this host.
    ///
    /// If the command returns `ScsiStatus::Busy` or `TaskSetFull` and
    /// retries remain, the dispatch function is called again.
    ///
    /// # Errors
    ///
    /// - [`Error::NotImplemented`] if no `queuecommand` is registered.
    /// - [`Error::IoError`] after all retries are exhausted.
    pub fn dispatch(&self, cmd: &mut ScsiCmd) -> Result<()> {
        let qc = self.queuecommand.ok_or(Error::NotImplemented)?;
        loop {
            qc(self, cmd)?;
            match cmd.scsi_status() {
                ScsiStatus::Good | ScsiStatus::ConditionMet => return Ok(()),
                ScsiStatus::CheckCondition => return Err(Error::IoError),
                ScsiStatus::Busy | ScsiStatus::TaskSetFull => {
                    if cmd.retries_left == 0 {
                        return Err(Error::IoError);
                    }
                    cmd.retries_left -= 1;
                }
                _ => return Err(Error::IoError),
            }
        }
    }

    /// Abort a command.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if no `abort_command` is registered.
    pub fn abort(&self, cmd: &mut ScsiCmd) -> Result<()> {
        let ab = self.abort_command.ok_or(Error::NotImplemented)?;
        ab(self, cmd)
    }

    /// Reset the SCSI bus.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if no `host_reset` is registered.
    pub fn reset(&self) -> Result<()> {
        let rst = self.host_reset.ok_or(Error::NotImplemented)?;
        rst(self)
    }
}

// ── ScsiHostRegistry ─────────────────────────────────────────────────────────

/// Registry for SCSI hosts.
pub struct ScsiHostRegistry {
    hosts: [Option<ScsiHost>; MAX_HOSTS],
    count: usize,
}

impl ScsiHostRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            hosts: [const { None }; MAX_HOSTS],
            count: 0,
        }
    }

    /// Register a SCSI host.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slots remain.
    pub fn register(&mut self, mut host: ScsiHost) -> Result<u8> {
        if self.count >= MAX_HOSTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        host.host_no = idx as u8;
        host.ready = true;
        self.hosts[idx] = Some(host);
        self.count += 1;
        Ok(idx as u8)
    }

    /// Retrieve a reference to a registered host.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no host at `host_no`.
    pub fn get(&self, host_no: u8) -> Result<&ScsiHost> {
        self.hosts
            .get(host_no as usize)
            .and_then(|h| h.as_ref())
            .ok_or(Error::NotFound)
    }

    /// Return the number of registered hosts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether no hosts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ScsiHostRegistry {
    fn default() -> Self {
        Self::new()
    }
}
