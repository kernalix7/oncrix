// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Mass Storage Class driver (Bulk-Only Transport).
//!
//! Implements the USB Mass Storage Bulk-Only Transport (BOT)
//! protocol for communicating with USB storage devices such as
//! flash drives and external hard disks. The driver wraps SCSI
//! commands inside Command Block Wrappers (CBW) and processes
//! Command Status Wrappers (CSW) returned by the device.
//!
//! # Architecture
//!
//! - **CBW/CSW** — command/status wrappers per BOT spec
//! - **SCSI commands** — INQUIRY, READ CAPACITY, READ/WRITE(10)
//! - **Bulk endpoints** — separate IN and OUT pipes for data
//! - **Registry** — tracks up to 8 attached storage devices
//!
//! Reference: USB Mass Storage Class — Bulk-Only Transport 1.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// USB interface class code for Mass Storage.
pub const MASS_STORAGE_CLASS: u8 = 0x08;

/// SCSI transparent command set subclass.
pub const SCSI_SUBCLASS: u8 = 0x06;

/// Bulk-Only Transport protocol code.
pub const BOT_PROTOCOL: u8 = 0x50;

/// CBW signature: `USBC` in little-endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;

/// CSW signature: `USBS` in little-endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;

/// CBW direction flag: data OUT (host to device).
pub const CBW_OUT: u8 = 0x00;

/// CBW direction flag: data IN (device to host).
pub const CBW_IN: u8 = 0x80;

/// Maximum Logical Unit Number.
const _MAX_LUN: u8 = 15;

/// Maximum number of concurrently tracked USB storage devices.
pub const MAX_USB_STORAGE_DEVICES: usize = 8;

/// Default block size in bytes.
pub const BLOCK_SIZE: u32 = 512;

// ---------------------------------------------------------------------------
// SCSI opcodes
// ---------------------------------------------------------------------------

/// SCSI TEST UNIT READY opcode.
const SCSI_TEST_UNIT_READY: u8 = 0x00;

/// SCSI REQUEST SENSE opcode.
const SCSI_REQUEST_SENSE: u8 = 0x03;

/// SCSI INQUIRY opcode.
const SCSI_INQUIRY: u8 = 0x12;

/// SCSI READ CAPACITY(10) opcode.
const SCSI_READ_CAPACITY_10: u8 = 0x25;

/// SCSI READ(10) opcode.
const SCSI_READ_10: u8 = 0x28;

/// SCSI WRITE(10) opcode.
const SCSI_WRITE_10: u8 = 0x2A;

// ---------------------------------------------------------------------------
// Command Block Wrapper (CBW) — 31 bytes
// ---------------------------------------------------------------------------

/// USB Mass Storage Command Block Wrapper (CBW).
///
/// The CBW is sent on the Bulk-OUT endpoint to issue a command
/// to the device. It is exactly 31 bytes as defined by the
/// Bulk-Only Transport specification.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Cbw {
    /// CBW signature — must be [`CBW_SIGNATURE`].
    pub signature: u32,
    /// Tag sent by the host; the device echoes it in the CSW.
    pub tag: u32,
    /// Number of bytes the host expects to transfer.
    pub data_transfer_length: u32,
    /// Bit 7: direction (0 = OUT, 1 = IN).
    pub flags: u8,
    /// Logical Unit Number (bits 3:0).
    pub lun: u8,
    /// Length of the command block (1–16).
    pub cb_length: u8,
    /// SCSI Command Descriptor Block (CDB).
    pub cb: [u8; 16],
}

impl Cbw {
    /// Create a new CBW from the given parameters.
    ///
    /// `command` is copied into the 16-byte CDB field; remaining
    /// bytes are zero-filled.
    pub fn new(tag: u32, length: u32, flags: u8, lun: u8, command: &[u8]) -> Self {
        let cb_length = if command.len() > 16 {
            16u8
        } else {
            command.len() as u8
        };
        let mut cb = [0u8; 16];
        let copy_len = cb_length as usize;
        cb[..copy_len].copy_from_slice(&command[..copy_len]);
        Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: length,
            flags,
            lun,
            cb_length,
            cb,
        }
    }
}

// ---------------------------------------------------------------------------
// Command Status Wrapper (CSW) — 13 bytes
// ---------------------------------------------------------------------------

/// USB Mass Storage Command Status Wrapper (CSW).
///
/// The CSW is received on the Bulk-IN endpoint after the device
/// has processed a command. It is exactly 13 bytes.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Csw {
    /// CSW signature — must be [`CSW_SIGNATURE`].
    pub signature: u32,
    /// Tag echoed from the corresponding CBW.
    pub tag: u32,
    /// Difference between expected and actual transfer length.
    pub data_residue: u32,
    /// Command status (0 = success, 1 = failed, 2 = phase error).
    pub status: u8,
}

impl Csw {
    /// Check whether this CSW is valid for the given expected tag.
    ///
    /// A CSW is valid when its signature matches [`CSW_SIGNATURE`]
    /// and its tag matches the tag sent in the corresponding CBW.
    pub fn is_valid(&self, expected_tag: u32) -> bool {
        self.signature == CSW_SIGNATURE && self.tag == expected_tag
    }

    /// Return `true` if the command completed successfully.
    pub fn is_success(&self) -> bool {
        self.status == 0
    }
}

// ---------------------------------------------------------------------------
// SCSI command builders
// ---------------------------------------------------------------------------

/// Build a SCSI INQUIRY command block (6 bytes, opcode 0x12).
///
/// Requests standard inquiry data (36 bytes) from the device.
pub fn scsi_inquiry() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_INQUIRY;
    // Allocation length = 36 (standard inquiry data).
    cdb[4] = 36;
    cdb
}

/// Build a SCSI READ CAPACITY(10) command block (opcode 0x25).
///
/// Returns the last LBA and block size of the device.
pub fn scsi_read_capacity10() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_READ_CAPACITY_10;
    cdb
}

/// Build a SCSI READ(10) command block (opcode 0x28).
///
/// Reads `block_count` blocks starting from `lba`.
pub fn scsi_read10(lba: u32, block_count: u16) -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_READ_10;
    // LBA in bytes 2..6 (big-endian).
    let lba_bytes = lba.to_be_bytes();
    cdb[2..6].copy_from_slice(&lba_bytes);
    // Transfer length in bytes 7..9 (big-endian).
    let count_bytes = block_count.to_be_bytes();
    cdb[7..9].copy_from_slice(&count_bytes);
    cdb
}

/// Build a SCSI WRITE(10) command block (opcode 0x2A).
///
/// Writes `block_count` blocks starting from `lba`.
pub fn scsi_write10(lba: u32, block_count: u16) -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_WRITE_10;
    let lba_bytes = lba.to_be_bytes();
    cdb[2..6].copy_from_slice(&lba_bytes);
    let count_bytes = block_count.to_be_bytes();
    cdb[7..9].copy_from_slice(&count_bytes);
    cdb
}

/// Build a SCSI TEST UNIT READY command block (opcode 0x00).
///
/// Checks whether the logical unit is ready to accept commands.
pub fn scsi_test_unit_ready() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_TEST_UNIT_READY;
    cdb
}

/// Build a SCSI REQUEST SENSE command block (opcode 0x03).
///
/// Retrieves sense data (18 bytes) describing the most recent
/// error or condition.
pub fn scsi_request_sense() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_REQUEST_SENSE;
    cdb[4] = 18; // allocation length
    cdb
}

// ---------------------------------------------------------------------------
// InquiryData — 36 bytes
// ---------------------------------------------------------------------------

/// Standard SCSI INQUIRY data (36 bytes).
///
/// Contains device identification information such as vendor,
/// product, and revision strings.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InquiryData {
    /// Peripheral device type (bits 4:0) and qualifier (bits 7:5).
    pub device_type: u8,
    /// Bit 7: removable media indicator.
    pub removable: u8,
    /// SPC version compliance.
    pub version: u8,
    /// Response data format (bits 3:0).
    pub response_format: u8,
    /// Number of additional bytes after this field.
    pub additional_length: u8,
    /// Various capability flags.
    pub flags: [u8; 3],
    /// T10 vendor identification (ASCII, space-padded).
    pub vendor_id: [u8; 8],
    /// Product identification (ASCII, space-padded).
    pub product_id: [u8; 16],
    /// Product revision level (ASCII, space-padded).
    pub product_rev: [u8; 4],
}

// ---------------------------------------------------------------------------
// USB bulk transfer helpers (stubs)
// ---------------------------------------------------------------------------

/// Send a bulk OUT transfer to the device.
///
/// In a real implementation this would program the xHCI transfer
/// ring for the device's Bulk-OUT endpoint.
///
/// # Safety
///
/// `data` must be a valid buffer accessible by the host controller.
unsafe fn bulk_out_transfer(
    _slot_id: u8,
    _endpoint: u8,
    _data: *const u8,
    _len: usize,
) -> Result<()> {
    // Stub — real implementation interacts with xHCI TRBs.
    Ok(())
}

/// Receive a bulk IN transfer from the device.
///
/// # Safety
///
/// `data` must point to a buffer large enough for `len` bytes
/// and accessible by the host controller.
unsafe fn bulk_in_transfer(
    _slot_id: u8,
    _endpoint: u8,
    _data: *mut u8,
    _len: usize,
) -> Result<usize> {
    // Stub — real implementation interacts with xHCI TRBs.
    Ok(_len)
}

// ---------------------------------------------------------------------------
// UsbStorageDevice
// ---------------------------------------------------------------------------

/// A single USB Mass Storage device using Bulk-Only Transport.
///
/// Encapsulates device identification, endpoint configuration,
/// and methods for issuing SCSI commands over USB bulk transfers.
pub struct UsbStorageDevice {
    /// Unique device identifier within the registry.
    pub device_id: u8,
    /// xHCI slot ID assigned during enumeration.
    pub slot_id: u8,
    /// Endpoint address for Bulk-IN transfers.
    pub bulk_in_ep: u8,
    /// Endpoint address for Bulk-OUT transfers.
    pub bulk_out_ep: u8,
    /// Maximum Logical Unit Number reported by the device.
    pub max_lun: u8,
    /// Block (sector) size in bytes.
    pub block_size: u32,
    /// Total number of blocks on the device.
    pub block_count: u64,
    /// Monotonically increasing tag for CBW/CSW matching.
    next_tag: u32,
    /// Whether the device is physically connected.
    pub connected: bool,
    /// Whether the device is ready to accept I/O commands.
    pub ready: bool,
    /// Vendor identification string from INQUIRY data.
    pub vendor: [u8; 8],
    /// Product identification string from INQUIRY data.
    pub product: [u8; 16],
}

impl UsbStorageDevice {
    /// Create a new USB storage device descriptor.
    ///
    /// The device is not yet initialised; call [`init`](Self::init)
    /// to perform the SCSI handshake.
    pub fn new(device_id: u8, slot_id: u8, bulk_in: u8, bulk_out: u8) -> Self {
        Self {
            device_id,
            slot_id,
            bulk_in_ep: bulk_in,
            bulk_out_ep: bulk_out,
            max_lun: 0,
            block_size: BLOCK_SIZE,
            block_count: 0,
            next_tag: 1,
            connected: true,
            ready: false,
            vendor: [0u8; 8],
            product: [0u8; 16],
        }
    }

    /// Allocate the next CBW tag.
    fn alloc_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        tag
    }

    /// Send a CBW, optionally transfer data, then receive a CSW.
    ///
    /// Returns the CSW on success. The caller is responsible for
    /// checking [`Csw::is_success`].
    fn execute_command(
        &mut self,
        cbw: &Cbw,
        data: Option<&mut [u8]>,
        direction_in: bool,
    ) -> Result<Csw> {
        // Send CBW on Bulk-OUT.
        let cbw_ptr = cbw as *const Cbw as *const u8;
        // SAFETY: CBW is a repr(C, packed) struct with known size.
        unsafe {
            bulk_out_transfer(
                self.slot_id,
                self.bulk_out_ep,
                cbw_ptr,
                core::mem::size_of::<Cbw>(),
            )?;
        }

        // Data phase (if any).
        if let Some(buf) = data {
            if direction_in {
                // SAFETY: buf is a valid mutable slice.
                unsafe {
                    bulk_in_transfer(self.slot_id, self.bulk_in_ep, buf.as_mut_ptr(), buf.len())?;
                }
            } else {
                // SAFETY: buf is a valid slice.
                unsafe {
                    bulk_out_transfer(self.slot_id, self.bulk_out_ep, buf.as_ptr(), buf.len())?;
                }
            }
        }

        // Receive CSW on Bulk-IN.
        let mut csw = Csw::default();
        let csw_ptr = &mut csw as *mut Csw as *mut u8;
        // SAFETY: CSW is repr(C, packed) with known size.
        unsafe {
            bulk_in_transfer(
                self.slot_id,
                self.bulk_in_ep,
                csw_ptr,
                core::mem::size_of::<Csw>(),
            )?;
        }

        if !csw.is_valid(cbw.tag) {
            return Err(Error::IoError);
        }

        Ok(csw)
    }

    /// Initialise the device by performing the SCSI handshake.
    ///
    /// Issues TEST UNIT READY, INQUIRY, and READ CAPACITY(10)
    /// commands to populate device metadata.
    pub fn init(&mut self) -> Result<()> {
        if !self.connected {
            return Err(Error::NotFound);
        }

        // TEST UNIT READY
        self.do_test_unit_ready()?;

        // INQUIRY
        self.do_inquiry()?;

        // READ CAPACITY(10)
        self.do_read_capacity()?;

        self.ready = true;
        Ok(())
    }

    /// Issue a TEST UNIT READY command.
    fn do_test_unit_ready(&mut self) -> Result<()> {
        let tag = self.alloc_tag();
        let cdb = scsi_test_unit_ready();
        let cbw = Cbw::new(tag, 0, CBW_OUT, 0, &cdb);
        let csw = self.execute_command(&cbw, None, false)?;
        if !csw.is_success() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Issue an INQUIRY command and store vendor/product info.
    fn do_inquiry(&mut self) -> Result<()> {
        let tag = self.alloc_tag();
        let cdb = scsi_inquiry();
        let cbw = Cbw::new(tag, 36, CBW_IN, 0, &cdb);
        let mut buf = [0u8; 36];
        let csw = self.execute_command(&cbw, Some(&mut buf), true)?;
        if !csw.is_success() {
            return Err(Error::IoError);
        }

        // Parse InquiryData fields manually (avoid packed ref).
        self.vendor.copy_from_slice(&buf[8..16]);
        self.product.copy_from_slice(&buf[16..32]);
        Ok(())
    }

    /// Issue a READ CAPACITY(10) command and store geometry.
    fn do_read_capacity(&mut self) -> Result<()> {
        let tag = self.alloc_tag();
        let cdb = scsi_read_capacity10();
        let cbw = Cbw::new(tag, 8, CBW_IN, 0, &cdb);
        let mut buf = [0u8; 8];
        let csw = self.execute_command(&cbw, Some(&mut buf), true)?;
        if !csw.is_success() {
            return Err(Error::IoError);
        }

        // Last LBA (big-endian u32) in bytes 0..4.
        let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        // Block size (big-endian u32) in bytes 4..8.
        let bs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        self.block_count = u64::from(last_lba) + 1;
        self.block_size = bs;
        Ok(())
    }

    /// Read contiguous blocks from the device into `buf`.
    ///
    /// `lba` is the starting Logical Block Address, and `count`
    /// is the number of blocks to read. The buffer must be large
    /// enough to hold `count * block_size` bytes.
    pub fn read_blocks(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<()> {
        if !self.ready {
            return Err(Error::Busy);
        }
        let total = count as u32 * self.block_size;
        if (buf.len() as u32) < total {
            return Err(Error::InvalidArgument);
        }
        if lba > u64::from(u32::MAX) {
            return Err(Error::InvalidArgument);
        }

        let tag = self.alloc_tag();
        let cdb = scsi_read10(lba as u32, count);
        let cbw = Cbw::new(tag, total, CBW_IN, 0, &cdb);
        let csw = self.execute_command(&cbw, Some(&mut buf[..total as usize]), true)?;
        if !csw.is_success() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Write contiguous blocks from `buf` to the device.
    ///
    /// `lba` is the starting Logical Block Address, and `count`
    /// is the number of blocks to write. The buffer must contain
    /// at least `count * block_size` bytes.
    pub fn write_blocks(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<()> {
        if !self.ready {
            return Err(Error::Busy);
        }
        let total = count as u32 * self.block_size;
        if (buf.len() as u32) < total {
            return Err(Error::InvalidArgument);
        }
        if lba > u64::from(u32::MAX) {
            return Err(Error::InvalidArgument);
        }

        let tag = self.alloc_tag();
        let cdb = scsi_write10(lba as u32, count);
        let cbw = Cbw::new(tag, total, CBW_OUT, 0, &cdb);

        // We need a mutable slice for execute_command, but the
        // data flows OUT so it is not actually modified.
        let mut tmp = [0u8; 0];
        let _ = &mut tmp; // silence unused-mut if needed

        // For write, send data on Bulk-OUT directly.
        let cbw_ptr = &cbw as *const Cbw as *const u8;
        // SAFETY: CBW repr(C, packed) with known size.
        unsafe {
            bulk_out_transfer(
                self.slot_id,
                self.bulk_out_ep,
                cbw_ptr,
                core::mem::size_of::<Cbw>(),
            )?;
        }

        // SAFETY: buf is a valid read-only slice.
        unsafe {
            bulk_out_transfer(self.slot_id, self.bulk_out_ep, buf.as_ptr(), total as usize)?;
        }

        // Receive CSW.
        let mut csw = Csw::default();
        let csw_ptr = &mut csw as *mut Csw as *mut u8;
        // SAFETY: CSW repr(C, packed) with known size.
        unsafe {
            bulk_in_transfer(
                self.slot_id,
                self.bulk_in_ep,
                csw_ptr,
                core::mem::size_of::<Csw>(),
            )?;
        }

        if !csw.is_valid(tag) {
            return Err(Error::IoError);
        }
        if !csw.is_success() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Return the device capacity as `(block_count, block_size)`.
    pub fn capacity(&self) -> (u64, u32) {
        (self.block_count, self.block_size)
    }

    /// Return `true` if the device is ready for I/O.
    pub fn is_ready(&self) -> bool {
        self.ready
    }
}

// ---------------------------------------------------------------------------
// UsbStorageRegistry
// ---------------------------------------------------------------------------

/// Registry of attached USB Mass Storage devices.
///
/// Tracks up to [`MAX_USB_STORAGE_DEVICES`] devices and provides
/// lookup, registration, and removal operations.
pub struct UsbStorageRegistry {
    /// Fixed-size array of device slots.
    devices: [Option<UsbStorageDevice>; MAX_USB_STORAGE_DEVICES],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for UsbStorageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbStorageRegistry {
    /// Create an empty device registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None, None, None, None, None],
            count: 0,
        }
    }

    /// Register a new USB storage device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same
    /// `device_id` is already registered.
    pub fn register(&mut self, device: UsbStorageDevice) -> Result<()> {
        // Check for duplicates.
        for d in self.devices.iter().flatten() {
            if d.device_id == device.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        // Find an empty slot.
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a device by its `device_id`.
    ///
    /// Returns [`Error::NotFound`] if no device with that ID
    /// exists.
    pub fn unregister(&mut self, device_id: u8) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(d) = slot {
                if d.device_id == device_id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get a shared reference to a device by its `device_id`.
    ///
    /// Returns [`None`] if the device is not registered.
    pub fn get(&self, device_id: u8) -> Option<&UsbStorageDevice> {
        self.devices
            .iter()
            .find_map(|slot| slot.as_ref().filter(|d| d.device_id == device_id))
    }

    /// Get a mutable reference to a device by its `device_id`.
    ///
    /// Returns [`None`] if the device is not registered.
    pub fn get_mut(&mut self, device_id: u8) -> Option<&mut UsbStorageDevice> {
        self.devices
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|d| d.device_id == device_id))
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
