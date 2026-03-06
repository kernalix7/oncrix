// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Mass Storage Class driver — SCSI/BOT protocol layer.
//!
//! Implements the upper-level USB Mass Storage Class (MSC) driver that
//! sits on top of the low-level xHCI host controller. This module
//! handles the complete SCSI-over-BOT protocol stack including:
//!
//! # Architecture
//!
//! - **Transport layer** — Bulk-Only Transport (BOT) command/status wrappers
//! - **SCSI layer** — command set for direct-access block devices
//! - **Error recovery** — reset recovery per BOT §5.3.4 and REQUEST SENSE
//! - **Multi-LUN** — supports devices with multiple logical units
//! - **Registry** — tracks up to [`MAX_MSC_DEVICES`] concurrently attached
//!   devices, each with up to [`MAX_LUNS`] logical units
//!
//! Reference: USB Mass Storage Class — Bulk-Only Transport 1.0 (BOT);
//! SCSI Primary Commands — 4 (SPC-4); SCSI Block Commands — 3 (SBC-3).

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum simultaneously tracked MSC devices.
pub const MAX_MSC_DEVICES: usize = 8;

/// Maximum logical units per device.
pub const MAX_LUNS: usize = 16;

/// CBW signature bytes `USBC` (little-endian u32).
pub const CBW_SIGNATURE: u32 = 0x4342_5355;

/// CSW signature bytes `USBS` (little-endian u32).
pub const CSW_SIGNATURE: u32 = 0x5342_5355;

/// CBW size as defined by the BOT specification.
pub const CBW_SIZE: usize = 31;

/// CSW size as defined by the BOT specification.
pub const CSW_SIZE: usize = 13;

/// CBW flags: data-IN (device-to-host).
pub const CBW_FLAGS_IN: u8 = 0x80;

/// CBW flags: data-OUT (host-to-device).
pub const CBW_FLAGS_OUT: u8 = 0x00;

/// Default logical block size.
pub const DEFAULT_BLOCK_SIZE: u32 = 512;

/// Maximum retry count for reset-recovery.
const MAX_RESET_RETRIES: usize = 3;

// ---------------------------------------------------------------------------
// SCSI opcodes
// ---------------------------------------------------------------------------

const SCSI_OP_TEST_UNIT_READY: u8 = 0x00;
const SCSI_OP_REQUEST_SENSE: u8 = 0x03;
const SCSI_OP_INQUIRY: u8 = 0x12;
const SCSI_OP_MODE_SENSE6: u8 = 0x1A;
const SCSI_OP_START_STOP_UNIT: u8 = 0x1B;
const SCSI_OP_PREVENT_MEDIUM_REMOVAL: u8 = 0x1E;
const SCSI_OP_READ_CAPACITY10: u8 = 0x25;
const SCSI_OP_READ10: u8 = 0x28;
const SCSI_OP_WRITE10: u8 = 0x2A;
const SCSI_OP_SYNCHRONIZE_CACHE10: u8 = 0x35;
const SCSI_OP_READ_CAPACITY16: u8 = 0x9E;
const SCSI_OP_READ16: u8 = 0x88;
const SCSI_OP_WRITE16: u8 = 0x8A;

// ---------------------------------------------------------------------------
// CSW status codes
// ---------------------------------------------------------------------------

/// CSW status: command passed.
pub const CSW_STATUS_PASSED: u8 = 0x00;

/// CSW status: command failed.
pub const CSW_STATUS_FAILED: u8 = 0x01;

/// CSW status: phase error.
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

// ---------------------------------------------------------------------------
// SCSI sense key codes
// ---------------------------------------------------------------------------

/// Sense key: no sense.
pub const SENSE_NO_SENSE: u8 = 0x00;

/// Sense key: not ready.
pub const SENSE_NOT_READY: u8 = 0x02;

/// Sense key: medium error.
pub const SENSE_MEDIUM_ERROR: u8 = 0x03;

/// Sense key: hardware error.
pub const SENSE_HARDWARE_ERROR: u8 = 0x04;

/// Sense key: unit attention.
pub const SENSE_UNIT_ATTENTION: u8 = 0x06;

// ---------------------------------------------------------------------------
// CommandBlockWrapper
// ---------------------------------------------------------------------------

/// USB Mass Storage Command Block Wrapper (CBW).
///
/// Sent on the Bulk-OUT endpoint to issue a SCSI command.
/// Must be exactly [`CBW_SIZE`] (31) bytes per BOT §5.1.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CommandBlockWrapper {
    /// Signature — must be [`CBW_SIGNATURE`].
    pub signature: u32,
    /// Host-assigned tag; echoed in the CSW.
    pub tag: u32,
    /// Expected data-transfer length in bytes.
    pub data_transfer_length: u32,
    /// Bit 7: direction (0 = OUT, 1 = IN); bits 6:0 reserved.
    pub flags: u8,
    /// Target logical unit number (bits 3:0).
    pub lun: u8,
    /// Length of the SCSI CDB (1–16).
    pub cb_length: u8,
    /// SCSI Command Descriptor Block.
    pub cb: [u8; 16],
}

impl CommandBlockWrapper {
    /// Construct a CBW from individual fields.
    ///
    /// `command` is copied (truncated to 16 bytes) into the CDB field.
    pub fn new(tag: u32, data_len: u32, flags: u8, lun: u8, command: &[u8]) -> Self {
        let cb_length = command.len().min(16) as u8;
        let mut cb = [0u8; 16];
        cb[..cb_length as usize].copy_from_slice(&command[..cb_length as usize]);
        Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: data_len,
            flags,
            lun,
            cb_length,
            cb,
        }
    }
}

// ---------------------------------------------------------------------------
// CommandStatusWrapper
// ---------------------------------------------------------------------------

/// USB Mass Storage Command Status Wrapper (CSW).
///
/// Received on the Bulk-IN endpoint after command completion.
/// Must be exactly [`CSW_SIZE`] (13) bytes per BOT §5.2.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct CommandStatusWrapper {
    /// Signature — must be [`CSW_SIGNATURE`].
    pub signature: u32,
    /// Tag from the corresponding CBW.
    pub tag: u32,
    /// Difference between expected and actual data residue.
    pub data_residue: u32,
    /// Command status — 0 pass, 1 fail, 2 phase error.
    pub status: u8,
}

impl CommandStatusWrapper {
    /// Return `true` if this CSW is structurally valid for `expected_tag`.
    pub fn is_valid(&self, expected_tag: u32) -> bool {
        self.signature == CSW_SIGNATURE && self.tag == expected_tag
    }

    /// Return `true` if the SCSI command completed with GOOD status.
    pub fn passed(&self) -> bool {
        self.status == CSW_STATUS_PASSED
    }

    /// Return `true` if a phase error was reported (requires bulk reset).
    pub fn phase_error(&self) -> bool {
        self.status == CSW_STATUS_PHASE_ERROR
    }
}

// ---------------------------------------------------------------------------
// SenseData
// ---------------------------------------------------------------------------

/// SCSI fixed-format sense data (18 bytes).
///
/// Returned in response to a REQUEST SENSE command after a CHECK CONDITION.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SenseData {
    /// Response code and valid bit (byte 0).
    pub response_code: u8,
    /// Obsolete (byte 1).
    pub obsolete: u8,
    /// Sense key (bits 3:0); ILI, EOM, FM flags (bits 7:5).
    pub sense_key: u8,
    /// Information bytes (bytes 3–6).
    pub information: [u8; 4],
    /// Additional sense length (byte 7).
    pub additional_length: u8,
    /// Command-specific information (bytes 8–11).
    pub command_info: [u8; 4],
    /// Additional sense code (byte 12).
    pub asc: u8,
    /// Additional sense code qualifier (byte 13).
    pub ascq: u8,
    /// Field replaceable unit code (byte 14).
    pub fruc: u8,
    /// Sense key specific (bytes 15–17).
    pub sense_key_specific: [u8; 3],
}

impl SenseData {
    /// Extract the sense key (lower nibble of byte 2).
    pub fn key(&self) -> u8 {
        self.sense_key & 0x0F
    }
}

// ---------------------------------------------------------------------------
// InquiryData
// ---------------------------------------------------------------------------

/// Standard SCSI INQUIRY data (36 bytes minimum).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InquiryData {
    /// Peripheral device type (bits 4:0) and qualifier (bits 7:5).
    pub device_type: u8,
    /// Removable medium bit (bit 7).
    pub rmb: u8,
    /// Version of applicable standard.
    pub version: u8,
    /// Response data format.
    pub response_format: u8,
    /// Additional data length.
    pub additional_length: u8,
    /// Flags bytes (SCCS, ACC, TPGS, …).
    pub flags: [u8; 3],
    /// Vendor identification (8 ASCII bytes, space-padded).
    pub vendor_id: [u8; 8],
    /// Product identification (16 ASCII bytes, space-padded).
    pub product_id: [u8; 16],
    /// Product revision level (4 ASCII bytes).
    pub product_rev: [u8; 4],
}

// ---------------------------------------------------------------------------
// LunInfo
// ---------------------------------------------------------------------------

/// Per-logical-unit geometry and state.
#[derive(Clone, Copy, Default)]
pub struct LunInfo {
    /// Logical unit number (0-based).
    pub lun: u8,
    /// Whether this LUN is present and ready.
    pub ready: bool,
    /// Total number of logical blocks on this LUN.
    pub block_count: u64,
    /// Logical block size in bytes.
    pub block_size: u32,
    /// Whether the medium is write-protected.
    pub write_protected: bool,
    /// Vendor identification string.
    pub vendor_id: [u8; 8],
    /// Product identification string.
    pub product_id: [u8; 16],
}

// ---------------------------------------------------------------------------
// Transport stubs (thin wrappers over xHCI)
// ---------------------------------------------------------------------------

/// Submit a Bulk-OUT transfer and wait for completion.
///
/// # Safety
///
/// `data` must be a valid pointer to at least `len` bytes that remains
/// valid for the duration of the transfer.
unsafe fn bulk_out(slot: u8, ep: u8, data: *const u8, len: usize) -> Result<()> {
    // Stub — real implementation queues a Normal TRB on the xHCI
    // Bulk-OUT transfer ring for `slot` and endpoint `ep`.
    let _ = (slot, ep, data, len);
    Ok(())
}

/// Submit a Bulk-IN transfer and wait for completion.
///
/// Returns the number of bytes actually transferred.
///
/// # Safety
///
/// `data` must be a valid pointer to a buffer of at least `len` bytes.
unsafe fn bulk_in(slot: u8, ep: u8, data: *mut u8, len: usize) -> Result<usize> {
    // Stub — real implementation queues a Normal TRB on the xHCI
    // Bulk-IN transfer ring for `slot` and endpoint `ep`.
    let _ = (slot, ep, data, len);
    Ok(len)
}

/// Perform a BOT Bulk-Only Mass Storage Reset (class-specific request).
///
/// # Safety
///
/// The caller must ensure the device is in a state where a reset is safe.
unsafe fn bot_reset(slot: u8) -> Result<()> {
    // Stub — real implementation sends bmRequestType=0x21, bRequest=0xFF,
    // wValue=0, wIndex=interface, wLength=0 via the control endpoint.
    let _ = slot;
    Ok(())
}

/// Clear the HALT feature on a specific bulk endpoint.
///
/// # Safety
///
/// The caller must ensure `slot` and `ep` identify a valid endpoint.
unsafe fn clear_halt(slot: u8, ep: u8) -> Result<()> {
    // Stub — real implementation sends SET_FEATURE(ENDPOINT_HALT) clear
    // to the control endpoint for endpoint `ep`.
    let _ = (slot, ep);
    Ok(())
}

// ---------------------------------------------------------------------------
// UsbMscDevice
// ---------------------------------------------------------------------------

/// A USB Mass Storage Class device instance.
///
/// Manages the BOT transport state and holds per-LUN geometry for
/// a single physically attached USB storage device.
pub struct UsbMscDevice {
    /// xHCI slot assigned during device enumeration.
    pub slot_id: u8,
    /// Bulk-IN endpoint address.
    pub ep_bulk_in: u8,
    /// Bulk-OUT endpoint address.
    pub ep_bulk_out: u8,
    /// Interface number of the Mass Storage interface.
    pub interface: u8,
    /// Maximum LUN index reported by GET_MAX_LUN (0-based).
    pub max_lun: u8,
    /// Per-LUN information (index 0 = LUN 0, …).
    pub luns: [LunInfo; MAX_LUNS],
    /// Monotonically increasing CBW tag counter.
    next_tag: u32,
    /// Number of consecutive reset-recovery attempts.
    reset_count: usize,
    /// Whether the device is currently usable.
    pub online: bool,
}

impl UsbMscDevice {
    /// Create a new `UsbMscDevice` from enumeration data.
    ///
    /// Call [`init`](Self::init) afterwards to query LUN geometry.
    pub fn new(slot_id: u8, ep_bulk_in: u8, ep_bulk_out: u8, interface: u8) -> Self {
        Self {
            slot_id,
            ep_bulk_in,
            ep_bulk_out,
            interface,
            max_lun: 0,
            luns: [LunInfo::default(); MAX_LUNS],
            next_tag: 1,
            reset_count: 0,
            online: false,
        }
    }

    /// Allocate the next CBW tag (wraps at u32::MAX back to 1).
    fn alloc_tag(&mut self) -> u32 {
        let t = self.next_tag;
        self.next_tag = if self.next_tag == u32::MAX {
            1
        } else {
            self.next_tag + 1
        };
        t
    }

    /// Execute one BOT command transaction.
    ///
    /// Sends the CBW, optionally transfers data, then receives the CSW.
    /// On phase error, performs BOT reset recovery (up to
    /// [`MAX_RESET_RETRIES`] times).
    fn execute(
        &mut self,
        cdb: &[u8],
        lun: u8,
        data: Option<(&mut [u8], bool)>,
    ) -> Result<CommandStatusWrapper> {
        let (data_len, flags) = match &data {
            Some((buf, dir_in)) => {
                let f = if *dir_in { CBW_FLAGS_IN } else { CBW_FLAGS_OUT };
                (buf.len() as u32, f)
            }
            None => (0, CBW_FLAGS_OUT),
        };

        let tag = self.alloc_tag();
        let cbw = CommandBlockWrapper::new(tag, data_len, flags, lun, cdb);

        // Send CBW.
        let cbw_ptr = &cbw as *const CommandBlockWrapper as *const u8;
        // SAFETY: cbw is a repr(C, packed) local with size CBW_SIZE; pointer
        // valid for the duration of bulk_out.
        unsafe {
            bulk_out(
                self.slot_id,
                self.ep_bulk_out,
                cbw_ptr,
                core::mem::size_of::<CommandBlockWrapper>(),
            )?;
        }

        // Data phase.
        if let Some((buf, dir_in)) = data {
            if dir_in {
                // SAFETY: buf is a valid mutable slice; length matches data_len.
                unsafe {
                    bulk_in(self.slot_id, self.ep_bulk_in, buf.as_mut_ptr(), buf.len())?;
                }
            } else {
                // SAFETY: buf is a valid slice; length matches data_len.
                unsafe {
                    bulk_out(self.slot_id, self.ep_bulk_out, buf.as_ptr(), buf.len())?;
                }
            }
        }

        // Receive CSW.
        let mut csw = CommandStatusWrapper::default();
        let csw_ptr = &mut csw as *mut CommandStatusWrapper as *mut u8;
        // SAFETY: csw is a repr(C, packed) local; pointer valid for bulk_in.
        unsafe {
            bulk_in(
                self.slot_id,
                self.ep_bulk_in,
                csw_ptr,
                core::mem::size_of::<CommandStatusWrapper>(),
            )?;
        }

        if !csw.is_valid(tag) {
            return Err(Error::IoError);
        }

        if csw.phase_error() {
            // BOT reset recovery per §5.3.4.
            self.reset_count += 1;
            if self.reset_count > MAX_RESET_RETRIES {
                self.online = false;
                return Err(Error::IoError);
            }
            // SAFETY: device is being reset due to protocol error.
            unsafe {
                bot_reset(self.slot_id)?;
                clear_halt(self.slot_id, self.ep_bulk_in)?;
                clear_halt(self.slot_id, self.ep_bulk_out)?;
            }
            return Err(Error::Busy);
        }

        self.reset_count = 0;
        Ok(csw)
    }

    /// Issue TEST UNIT READY to a specific LUN.
    pub fn test_unit_ready(&mut self, lun: u8) -> Result<()> {
        let cdb = [
            SCSI_OP_TEST_UNIT_READY,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let csw = self.execute(&cdb, lun, None)?;
        if !csw.passed() {
            return Err(Error::Busy);
        }
        Ok(())
    }

    /// Issue REQUEST SENSE to a specific LUN.
    pub fn request_sense(&mut self, lun: u8) -> Result<SenseData> {
        let cdb = [
            SCSI_OP_REQUEST_SENSE,
            0,
            0,
            0,
            18,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut buf = [0u8; 18];
        let csw = self.execute(&cdb, lun, Some((&mut buf, true)))?;
        if !csw.passed() {
            return Err(Error::IoError);
        }
        let mut sense = SenseData::default();
        sense.response_code = buf[0];
        sense.obsolete = buf[1];
        sense.sense_key = buf[2];
        sense.information.copy_from_slice(&buf[3..7]);
        sense.additional_length = buf[7];
        sense.command_info.copy_from_slice(&buf[8..12]);
        sense.asc = buf[12];
        sense.ascq = buf[13];
        sense.fruc = buf[14];
        sense.sense_key_specific.copy_from_slice(&buf[15..18]);
        Ok(sense)
    }

    /// Issue INQUIRY to a specific LUN.
    pub fn inquiry(&mut self, lun: u8) -> Result<InquiryData> {
        let cdb = [
            SCSI_OP_INQUIRY,
            0,
            0,
            0,
            36,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut buf = [0u8; 36];
        let csw = self.execute(&cdb, lun, Some((&mut buf, true)))?;
        if !csw.passed() {
            return Err(Error::IoError);
        }
        let mut inq = InquiryData::default();
        inq.device_type = buf[0];
        inq.rmb = buf[1];
        inq.version = buf[2];
        inq.response_format = buf[3];
        inq.additional_length = buf[4];
        inq.flags.copy_from_slice(&buf[5..8]);
        inq.vendor_id.copy_from_slice(&buf[8..16]);
        inq.product_id.copy_from_slice(&buf[16..32]);
        inq.product_rev.copy_from_slice(&buf[32..36]);
        Ok(inq)
    }

    /// Issue READ CAPACITY(10) to a specific LUN.
    pub fn read_capacity10(&mut self, lun: u8) -> Result<(u64, u32)> {
        let cdb = [
            SCSI_OP_READ_CAPACITY10,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut buf = [0u8; 8];
        let csw = self.execute(&cdb, lun, Some((&mut buf, true)))?;
        if !csw.passed() {
            return Err(Error::IoError);
        }
        let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let block_count = u64::from(last_lba) + 1;
        Ok((block_count, block_size))
    }

    /// Issue SYNCHRONIZE CACHE(10) to flush the device write cache.
    pub fn sync_cache(&mut self, lun: u8) -> Result<()> {
        let cdb = [
            SCSI_OP_SYNCHRONIZE_CACHE10,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let csw = self.execute(&cdb, lun, None)?;
        if !csw.passed() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Read `count` blocks from `lba` on `lun` into `buf`.
    ///
    /// Uses READ(10) for LBAs up to `u32::MAX` (blocks ≤ 65535).
    /// `buf` must be at least `count * block_size` bytes.
    pub fn read_blocks(&mut self, lun: u8, lba: u32, count: u16, buf: &mut [u8]) -> Result<()> {
        let lun_info = self.luns[lun as usize];
        if !lun_info.ready {
            return Err(Error::Busy);
        }
        let expected = count as usize * lun_info.block_size as usize;
        if buf.len() < expected {
            return Err(Error::InvalidArgument);
        }

        let lba_bytes = lba.to_be_bytes();
        let count_bytes = count.to_be_bytes();
        let cdb = [
            SCSI_OP_READ10,
            0,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0,
            count_bytes[0],
            count_bytes[1],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        let csw = self.execute(&cdb, lun, Some((&mut buf[..expected], true)))?;
        if !csw.passed() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Write `count` blocks from `buf` to `lba` on `lun`.
    ///
    /// Uses WRITE(10). `buf` must contain at least `count * block_size` bytes.
    pub fn write_blocks(&mut self, lun: u8, lba: u32, count: u16, buf: &mut [u8]) -> Result<()> {
        let lun_info = self.luns[lun as usize];
        if !lun_info.ready {
            return Err(Error::Busy);
        }
        if lun_info.write_protected {
            return Err(Error::PermissionDenied);
        }
        let expected = count as usize * lun_info.block_size as usize;
        if buf.len() < expected {
            return Err(Error::InvalidArgument);
        }

        let lba_bytes = lba.to_be_bytes();
        let count_bytes = count.to_be_bytes();
        let cdb = [
            SCSI_OP_WRITE10,
            0,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0,
            count_bytes[0],
            count_bytes[1],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        let csw = self.execute(&cdb, lun, Some((&mut buf[..expected], false)))?;
        if !csw.passed() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Initialise all LUNs: INQUIRY + READ CAPACITY.
    ///
    /// Populates `self.luns[0..=max_lun]` with geometry and vendor info.
    pub fn init(&mut self) -> Result<()> {
        for lun_idx in 0..=self.max_lun {
            let lun = lun_idx;

            // TEST UNIT READY — ignore transient NOT READY.
            let _ = self.test_unit_ready(lun);

            // INQUIRY.
            let inq = self.inquiry(lun)?;
            self.luns[lun as usize].lun = lun;
            self.luns[lun as usize].vendor_id = inq.vendor_id;
            self.luns[lun as usize].product_id = inq.product_id;

            // READ CAPACITY(10).
            match self.read_capacity10(lun) {
                Ok((block_count, block_size)) => {
                    self.luns[lun as usize].block_count = block_count;
                    self.luns[lun as usize].block_size = block_size;
                    self.luns[lun as usize].ready = true;
                }
                Err(_) => {
                    // LUN may not be populated; leave as not-ready.
                }
            }
        }

        self.online = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UsbMscRegistry
// ---------------------------------------------------------------------------

/// Registry of attached USB Mass Storage Class devices.
///
/// Supports up to [`MAX_MSC_DEVICES`] simultaneously connected devices.
pub struct UsbMscRegistry {
    /// Device slots indexed by position.
    devices: [Option<UsbMscDevice>; MAX_MSC_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for UsbMscRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbMscRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None, None, None, None, None],
            count: 0,
        }
    }

    /// Register a device.
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full and
    /// [`Error::AlreadyExists`] when a device with the same slot ID
    /// is already registered.
    pub fn register(&mut self, device: UsbMscDevice) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.slot_id == device.slot_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a device by slot ID.
    pub fn unregister(&mut self, slot_id: u8) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(d) = slot {
                if d.slot_id == slot_id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a device by slot ID (shared reference).
    pub fn get(&self, slot_id: u8) -> Option<&UsbMscDevice> {
        self.devices
            .iter()
            .find_map(|s| s.as_ref().filter(|d| d.slot_id == slot_id))
    }

    /// Look up a device by slot ID (mutable reference).
    pub fn get_mut(&mut self, slot_id: u8) -> Option<&mut UsbMscDevice> {
        self.devices
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|d| d.slot_id == slot_id))
    }

    /// Number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
