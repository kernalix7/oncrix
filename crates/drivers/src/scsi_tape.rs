// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCSI sequential-access (tape) device driver.
//!
//! Implements SCSI commands for sequential-access devices (tape drives):
//!
//! - READ/WRITE variable-length and fixed-length blocks
//! - REWIND, SPACE, ERASE operations
//! - LOAD/UNLOAD media
//! - REQUEST SENSE / MODE SENSE / MODE SELECT
//! - End-of-tape detection
//!
//! Reference: INCITS 520-2014 (SSC-5) — SCSI Stream Commands;
//! INCITS 452-2008 (SPC-5) — SCSI Primary Commands.

use oncrix_lib::{Error, Result};

// ── SCSI Sequential Access Command Codes ───────────────────────────────────

pub mod tape_op {
    /// TEST UNIT READY.
    pub const TEST_UNIT_READY: u8 = 0x00;
    /// REWIND.
    pub const REWIND: u8 = 0x01;
    /// REQUEST SENSE.
    pub const REQUEST_SENSE: u8 = 0x03;
    /// READ (6) — variable/fixed block.
    pub const READ6: u8 = 0x08;
    /// WRITE (6).
    pub const WRITE6: u8 = 0x0A;
    /// SPACE — skip filemarks/blocks.
    pub const SPACE: u8 = 0x11;
    /// INQUIRY.
    pub const INQUIRY: u8 = 0x12;
    /// RECOVER BUFFERED DATA.
    pub const RECOVER_DATA: u8 = 0x14;
    /// MODE SELECT (6).
    pub const MODE_SELECT6: u8 = 0x15;
    /// RESERVE.
    pub const RESERVE: u8 = 0x16;
    /// RELEASE.
    pub const RELEASE: u8 = 0x17;
    /// ERASE.
    pub const ERASE: u8 = 0x19;
    /// MODE SENSE (6).
    pub const MODE_SENSE6: u8 = 0x1A;
    /// LOAD UNLOAD.
    pub const LOAD_UNLOAD: u8 = 0x1B;
    /// LOCATE (10) — position to a block address.
    pub const LOCATE10: u8 = 0x2B;
    /// READ POSITION.
    pub const READ_POSITION: u8 = 0x34;
}

/// SPACE code values (third byte of SPACE CDB).
pub mod space_code {
    /// Blocks.
    pub const BLOCKS: u8 = 0x00;
    /// Filemarks.
    pub const FILEMARKS: u8 = 0x01;
    /// Sequential filemarks.
    pub const SEQ_FILEMARKS: u8 = 0x02;
    /// End-of-data.
    pub const END_OF_DATA: u8 = 0x03;
}

// ── Tape CDB Builder ───────────────────────────────────────────────────────

/// A 6-byte SCSI CDB for tape commands.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TapeCdb6 {
    pub op: u8,
    pub flags: u8,
    pub xfer2: u8,
    pub xfer1: u8,
    pub xfer0: u8,
    pub control: u8,
}

impl TapeCdb6 {
    /// Encode a 3-byte transfer count into bytes 2-4.
    fn encode_count(count: u32) -> (u8, u8, u8) {
        ((count >> 16) as u8, (count >> 8) as u8, count as u8)
    }

    /// TEST UNIT READY CDB.
    pub fn test_unit_ready() -> Self {
        let mut c = Self::default();
        c.op = tape_op::TEST_UNIT_READY;
        c
    }

    /// REWIND CDB. `immed`: return immediately (don't wait for rewind).
    pub fn rewind(immed: bool) -> Self {
        let mut c = Self::default();
        c.op = tape_op::REWIND;
        c.flags = if immed { 0x01 } else { 0x00 };
        c
    }

    /// READ (6) CDB. `fixed`: fixed-length blocks; `count`: block count or byte count.
    pub fn read6(fixed: bool, count: u32) -> Result<Self> {
        if count > 0x00FF_FFFF {
            return Err(Error::InvalidArgument);
        }
        let mut c = Self::default();
        c.op = tape_op::READ6;
        c.flags = if fixed { 0x01 } else { 0x00 };
        let (h, m, l) = Self::encode_count(count);
        c.xfer2 = h;
        c.xfer1 = m;
        c.xfer0 = l;
        Ok(c)
    }

    /// WRITE (6) CDB.
    pub fn write6(fixed: bool, count: u32) -> Result<Self> {
        if count > 0x00FF_FFFF {
            return Err(Error::InvalidArgument);
        }
        let mut c = Self::default();
        c.op = tape_op::WRITE6;
        c.flags = if fixed { 0x01 } else { 0x00 };
        let (h, m, l) = Self::encode_count(count);
        c.xfer2 = h;
        c.xfer1 = m;
        c.xfer0 = l;
        Ok(c)
    }

    /// SPACE CDB. `code`: space type, `count`: number of units (may be negative for backward).
    pub fn space(code: u8, count: i32) -> Self {
        let c_u = count as u32;
        let (h, m, l) = Self::encode_count(c_u & 0x00FF_FFFF);
        Self {
            op: tape_op::SPACE,
            flags: code & 0x0F,
            xfer2: h,
            xfer1: m,
            xfer0: l,
            control: 0,
        }
    }

    /// ERASE CDB. `long_erase`: erase entire tape.
    pub fn erase(long_erase: bool) -> Self {
        let mut c = Self::default();
        c.op = tape_op::ERASE;
        c.flags = if long_erase { 0x01 } else { 0x00 };
        c
    }

    /// LOAD UNLOAD CDB.
    pub fn load_unload(load: bool, retension: bool, eot: bool) -> Self {
        let mut c = Self::default();
        c.op = tape_op::LOAD_UNLOAD;
        let mut flags = 0u8;
        if load {
            flags |= 0x01
        }
        if retension {
            flags |= 0x02
        }
        if eot {
            flags |= 0x04
        }
        c.xfer0 = flags;
        c
    }

    /// Return the CDB as a 6-byte array.
    pub fn as_bytes(&self) -> [u8; 6] {
        [
            self.op,
            self.flags,
            self.xfer2,
            self.xfer1,
            self.xfer0,
            self.control,
        ]
    }
}

// ── Tape Position ──────────────────────────────────────────────────────────

/// READ POSITION short-form response.
#[repr(C)]
pub struct TapePosition {
    /// Flags: BOP (bit 7), EOP (bit 6), BCU (bit 5), BYCU (bit 4), BPU (bit 2).
    pub flags: u8,
    pub _reserved1: u8,
    /// Additional length.
    pub add_len: u8,
    pub _reserved2: u8,
    /// First block location (big-endian).
    pub first_block_be: u32,
    /// Last block location (big-endian).
    pub last_block_be: u32,
    pub _reserved3: u8,
    /// Number of bytes in buffer (3 bytes, big-endian).
    pub buf_bytes: [u8; 3],
}

impl TapePosition {
    /// Return true if positioned at beginning of partition.
    pub fn is_bop(&self) -> bool {
        self.flags & 0x80 != 0
    }

    /// Return true if positioned at end of partition.
    pub fn is_eop(&self) -> bool {
        self.flags & 0x40 != 0
    }

    /// Return the first block location.
    pub fn first_block(&self) -> u32 {
        u32::from_be(self.first_block_be)
    }
}

// ── Tape Device State ──────────────────────────────────────────────────────

/// State of a SCSI tape device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TapeState {
    /// Not yet probed.
    Uninitialized,
    /// Ready with media.
    Ready,
    /// No media loaded.
    NoMedia,
    /// At end of tape (EOT).
    EndOfTape,
    /// Media write protected.
    WriteProtected,
    /// Device error.
    Error,
}

/// Maximum tape drives tracked.
const MAX_TAPE_DRIVES: usize = 8;

/// SCSI tape drive abstraction.
pub struct ScsiTape {
    /// SCSI host adapter index.
    pub host: u8,
    /// SCSI target ID.
    pub target: u8,
    /// SCSI logical unit number.
    pub lun: u8,
    /// Current device state.
    pub state: TapeState,
    /// Fixed block mode: true if using fixed-length blocks.
    pub fixed_block: bool,
    /// Block size in bytes (fixed mode) or 0 (variable).
    pub block_size: u32,
    /// Bytes transferred since last rewind.
    pub bytes_transferred: u64,
    /// Current block address.
    pub block_addr: u32,
    /// Write protected flag.
    pub write_protected: bool,
    /// Product identification string.
    pub product_id: [u8; 16],
}

impl ScsiTape {
    /// Create a new tape device descriptor.
    pub fn new(host: u8, target: u8, lun: u8) -> Self {
        Self {
            host,
            target,
            lun,
            state: TapeState::Uninitialized,
            fixed_block: false,
            block_size: 0,
            bytes_transferred: 0,
            block_addr: 0,
            write_protected: false,
            product_id: [b' '; 16],
        }
    }

    /// Mark device as ready with media.
    pub fn set_ready(&mut self) {
        self.state = TapeState::Ready;
    }

    /// Mark device as having no media.
    pub fn set_no_media(&mut self) {
        self.state = TapeState::NoMedia;
    }

    /// Mark device at end of tape.
    pub fn set_eot(&mut self) {
        self.state = TapeState::EndOfTape;
    }

    /// Record a completed read/write of `bytes` bytes.
    pub fn record_transfer(&mut self, bytes: usize, blocks: u32) {
        self.bytes_transferred += bytes as u64;
        self.block_addr = self.block_addr.wrapping_add(blocks);
    }

    /// Reset transfer statistics (e.g., after rewind).
    pub fn reset_position(&mut self) {
        self.block_addr = 0;
    }

    /// Return true if the device is ready for I/O.
    pub fn is_ready(&self) -> bool {
        self.state == TapeState::Ready
    }

    /// Build a READ CDB appropriate for this device's block mode.
    pub fn build_read_cdb(&self, count: u32) -> Result<TapeCdb6> {
        TapeCdb6::read6(self.fixed_block, count)
    }

    /// Build a WRITE CDB.
    pub fn build_write_cdb(&self, count: u32) -> Result<TapeCdb6> {
        if self.write_protected {
            return Err(Error::PermissionDenied);
        }
        TapeCdb6::write6(self.fixed_block, count)
    }
}

// ── Tape Registry ──────────────────────────────────────────────────────────

/// Registry of SCSI tape drives.
pub struct TapeRegistry {
    drives: [Option<ScsiTape>; MAX_TAPE_DRIVES],
    count: usize,
}

impl TapeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            drives: [const { None }; MAX_TAPE_DRIVES],
            count: 0,
        }
    }

    /// Register a tape drive.
    pub fn register(&mut self, tape: ScsiTape) -> Result<usize> {
        if self.count >= MAX_TAPE_DRIVES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.drives[idx] = Some(tape);
        self.count += 1;
        Ok(idx)
    }

    /// Get a reference to a drive.
    pub fn get(&self, idx: usize) -> Option<&ScsiTape> {
        self.drives.get(idx)?.as_ref()
    }

    /// Get a mutable reference to a drive.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut ScsiTape> {
        self.drives.get_mut(idx)?.as_mut()
    }

    /// Number of registered drives.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if no drives are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for TapeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
