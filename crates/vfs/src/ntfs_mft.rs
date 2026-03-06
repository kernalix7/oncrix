// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NTFS Master File Table (MFT) operations.
//!
//! The MFT is the heart of NTFS: every file, directory, and metadata object
//! is represented as a row (MFT record) in this table. This module provides:
//!
//! - [`MftRecord`] — parsed MFT record with signature and sequence number
//! - [`MftRecordFlags`] — in-use / is-directory flags
//! - [`MftFixup`] — apply/verify update sequence array fixups
//! - [`MftTable`] — in-memory MFT with record lookup and allocation
//! - [`alloc_record`] — find and allocate a free MFT record
//! - [`free_record`] — mark a record as unused
//! - [`read_record`] — read and fixup-verify an MFT record from raw bytes
//!
//! # MFT Record Layout (1024 bytes default)
//!
//! ```text
//! [0..4]   "FILE" signature
//! [4..6]   Update Sequence Array (USA) offset
//! [6..8]   USA size (entries = 1 + sectors_per_record)
//! [8..16]  Log sequence number ($LogFile LSN)
//! [16..18] Sequence number (generation counter)
//! [18..20] Link count
//! [20..22] Attribute list offset
//! [22..24] Flags (in-use, is-directory)
//! [24..28] Used size of MFT record
//! [28..32] Allocated size of MFT record
//! [32..40] Base MFT reference (0 for base records)
//! [40..42] Next attribute ID
//! [42..44] Padding
//! [44..48] MFT record number
//! ```
//!
//! # References
//!
//! - Linux `fs/ntfs/mft.c`, `fs/ntfs3/record.c`
//! - NTFS-3G `libntfs-3g/mft.c`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Signature for a valid MFT record: "FILE" (0x454C_4946 LE).
pub const MFT_RECORD_SIG: u32 = 0x454C_4946;

/// Signature for a "BAAD" (corrupt) MFT record.
pub const MFT_RECORD_BAAD: u32 = 0x44414142;

/// Default MFT record size in bytes.
pub const MFT_RECORD_SIZE: usize = 1024;

/// Default sector size assumed for update sequence array.
pub const SECTOR_SIZE: usize = 512;

/// Number of sectors per default MFT record (1024 / 512 = 2).
pub const SECTORS_PER_RECORD: usize = MFT_RECORD_SIZE / SECTOR_SIZE;

/// Fixed offset of the update sequence array in the default record layout.
pub const USA_OFFSET: usize = 48;

/// USA size: 1 sequence number + 1 entry per sector.
pub const USA_SIZE: usize = SECTORS_PER_RECORD + 1;

/// Maximum MFT records tracked by this in-memory table.
pub const MAX_MFT_RECORDS: usize = 4096;

/// Special MFT record numbers for NTFS system files.
pub const MFT_RECORD_MFT: u64 = 0;
pub const MFT_RECORD_MFTMIRR: u64 = 1;
pub const MFT_RECORD_LOGFILE: u64 = 2;
pub const MFT_RECORD_VOLUME: u64 = 3;
pub const MFT_RECORD_ATTRDEF: u64 = 4;
pub const MFT_RECORD_ROOT: u64 = 5;
pub const MFT_RECORD_BITMAP: u64 = 6;
pub const MFT_RECORD_BOOT: u64 = 7;
pub const MFT_RECORD_BADCLUS: u64 = 8;
pub const MFT_RECORD_SECURE: u64 = 9;
pub const MFT_RECORD_UPCASE: u64 = 10;
pub const MFT_RECORD_EXTEND: u64 = 11;

/// First non-system MFT record.
pub const MFT_FIRST_USER_RECORD: u64 = 16;

// ── Flags ─────────────────────────────────────────────────────────────────────

/// Bitfield flags for MFT record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MftRecordFlags(pub u16);

impl MftRecordFlags {
    /// Record is in use (not free).
    pub const IN_USE: u16 = 1 << 0;
    /// Record represents a directory.
    pub const IS_DIR: u16 = 1 << 1;
    /// Record is an extension (attribute list).
    pub const IS_EXTENSION: u16 = 1 << 2;
    /// Record contains special index entries.
    pub const SPECIAL_INDEX: u16 = 1 << 3;

    /// Return `true` if the in-use bit is set.
    pub fn is_in_use(self) -> bool {
        self.0 & Self::IN_USE != 0
    }

    /// Return `true` if the directory bit is set.
    pub fn is_dir(self) -> bool {
        self.0 & Self::IS_DIR != 0
    }
}

// ── MFT Record ────────────────────────────────────────────────────────────────

/// Parsed in-memory representation of a single MFT record.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// MFT record number (0-based index in the MFT).
    pub record_number: u64,
    /// Log file sequence number.
    pub lsn: u64,
    /// Sequence number (generation counter, incremented on reuse).
    pub sequence_number: u16,
    /// Hard link count.
    pub link_count: u16,
    /// Offset to first attribute.
    pub attr_offset: u16,
    /// Record flags.
    pub flags: MftRecordFlags,
    /// Bytes used in this record.
    pub bytes_in_use: u32,
    /// Bytes allocated for this record.
    pub bytes_allocated: u32,
    /// Base MFT record reference (0 if this is a base record).
    pub base_mft_record: u64,
    /// Next attribute ID to assign.
    pub next_attr_id: u16,
    /// Raw attribute data (everything after the fixed header).
    pub attr_data: [u8; MFT_RECORD_SIZE],
}

impl MftRecord {
    /// Parse an MFT record from a `MFT_RECORD_SIZE`-byte buffer.
    ///
    /// Applies the Update Sequence Array (USA) fixups before returning.
    pub fn parse(raw: &[u8; MFT_RECORD_SIZE], record_number: u64) -> Result<Self> {
        // Check signature.
        let sig = u32::from_le_bytes(raw[0..4].try_into().map_err(|_| Error::InvalidArgument)?);
        if sig != MFT_RECORD_SIG {
            return Err(Error::IoError);
        }
        let usa_off =
            u16::from_le_bytes(raw[4..6].try_into().map_err(|_| Error::InvalidArgument)?) as usize;
        let usa_count =
            u16::from_le_bytes(raw[6..8].try_into().map_err(|_| Error::InvalidArgument)?) as usize;
        let lsn = u64::from_le_bytes(raw[8..16].try_into().map_err(|_| Error::InvalidArgument)?);
        let sequence_number =
            u16::from_le_bytes(raw[16..18].try_into().map_err(|_| Error::InvalidArgument)?);
        let link_count =
            u16::from_le_bytes(raw[18..20].try_into().map_err(|_| Error::InvalidArgument)?);
        let attr_offset =
            u16::from_le_bytes(raw[20..22].try_into().map_err(|_| Error::InvalidArgument)?);
        let flags_raw =
            u16::from_le_bytes(raw[22..24].try_into().map_err(|_| Error::InvalidArgument)?);
        let bytes_in_use =
            u32::from_le_bytes(raw[24..28].try_into().map_err(|_| Error::InvalidArgument)?);
        let bytes_allocated =
            u32::from_le_bytes(raw[28..32].try_into().map_err(|_| Error::InvalidArgument)?);
        let base_mft_record =
            u64::from_le_bytes(raw[32..40].try_into().map_err(|_| Error::InvalidArgument)?);
        let next_attr_id =
            u16::from_le_bytes(raw[40..42].try_into().map_err(|_| Error::InvalidArgument)?);

        // Apply USA fixups.
        let mut data = *raw;
        apply_usa_fixups(&mut data, usa_off, usa_count)?;

        Ok(Self {
            record_number,
            lsn,
            sequence_number,
            link_count,
            attr_offset,
            flags: MftRecordFlags(flags_raw),
            bytes_in_use,
            bytes_allocated,
            base_mft_record,
            next_attr_id,
            attr_data: data,
        })
    }

    /// Return `true` if this record is in use.
    pub fn is_in_use(&self) -> bool {
        self.flags.is_in_use()
    }

    /// Return `true` if this record is a directory.
    pub fn is_dir(&self) -> bool {
        self.flags.is_dir()
    }

    /// Return a slice over the attribute data.
    pub fn attr_bytes(&self) -> &[u8] {
        let off = self.attr_offset as usize;
        let end = (self.bytes_in_use as usize).min(MFT_RECORD_SIZE);
        if off >= end {
            return &[];
        }
        &self.attr_data[off..end]
    }
}

// ── USA Fixups ────────────────────────────────────────────────────────────────

/// Apply NTFS Update Sequence Array fixups to a raw record.
///
/// Each sector's last 2 bytes are replaced by the USA sequence entry;
/// the original values were stored in the USA to allow corruption detection.
///
/// `usa_off` is the byte offset of the USA within the record.
/// `usa_count` is the number of USA entries (1 + sectors_per_record).
fn apply_usa_fixups(
    data: &mut [u8; MFT_RECORD_SIZE],
    usa_off: usize,
    usa_count: usize,
) -> Result<()> {
    if usa_off + usa_count * 2 > MFT_RECORD_SIZE {
        return Err(Error::InvalidArgument);
    }
    // USA[0] is the sequence number; USA[1..] are the sector fixups.
    let seq = u16::from_le_bytes([data[usa_off], data[usa_off + 1]]);
    for i in 1..usa_count {
        let sector_end = i * SECTOR_SIZE - 2;
        if sector_end + 2 > MFT_RECORD_SIZE {
            break;
        }
        // Verify the sector-end words match the sequence number.
        let stored = u16::from_le_bytes([data[sector_end], data[sector_end + 1]]);
        if stored != seq {
            return Err(Error::IoError); // sector mismatch — record corrupted
        }
        // Restore original bytes from USA.
        let usa_idx = usa_off + i * 2;
        data[sector_end] = data[usa_idx];
        data[sector_end + 1] = data[usa_idx + 1];
    }
    Ok(())
}

/// Write NTFS Update Sequence Array fixups before writing a record to disk.
pub fn write_usa_fixups(data: &mut [u8; MFT_RECORD_SIZE], seq: u16) {
    data[USA_OFFSET] = (seq & 0xFF) as u8;
    data[USA_OFFSET + 1] = (seq >> 8) as u8;
    for i in 1..=SECTORS_PER_RECORD {
        let sector_end = i * SECTOR_SIZE - 2;
        if sector_end + 2 > MFT_RECORD_SIZE {
            break;
        }
        let orig = [data[sector_end], data[sector_end + 1]];
        let usa_idx = USA_OFFSET + i * 2;
        data[usa_idx] = orig[0];
        data[usa_idx + 1] = orig[1];
        data[sector_end] = (seq & 0xFF) as u8;
        data[sector_end + 1] = (seq >> 8) as u8;
    }
}

// ── MFT Table ─────────────────────────────────────────────────────────────────

/// In-memory MFT — tracks which record numbers are in use.
pub struct MftTable {
    /// Bitmap of in-use MFT record numbers (bit n = record n).
    bitmap: [u64; MAX_MFT_RECORDS / 64],
    /// Total allocated MFT records.
    pub total_records: usize,
    /// Number of free records.
    pub free_records: usize,
    /// Next-free hint.
    next_free: usize,
}

impl MftTable {
    /// Create a new MFT table with `total_records` entries.
    ///
    /// System records 0..MFT_FIRST_USER_RECORD are pre-marked as in-use.
    pub fn new(total_records: usize) -> Self {
        let count = total_records.min(MAX_MFT_RECORDS);
        let mut t = Self {
            bitmap: [0u64; MAX_MFT_RECORDS / 64],
            total_records: count,
            free_records: count,
            next_free: MFT_FIRST_USER_RECORD as usize,
        };
        // Reserve system records.
        for r in 0..MFT_FIRST_USER_RECORD as usize {
            if r < count {
                t.mark_used(r as u64);
            }
        }
        t
    }

    fn mark_used(&mut self, record: u64) {
        let idx = record as usize / 64;
        let bit = record as usize % 64;
        if idx < self.bitmap.len() {
            self.bitmap[idx] |= 1u64 << bit;
            self.free_records = self.free_records.saturating_sub(1);
        }
    }

    fn mark_free(&mut self, record: u64) {
        let idx = record as usize / 64;
        let bit = record as usize % 64;
        if idx < self.bitmap.len() {
            self.bitmap[idx] &= !(1u64 << bit);
            self.free_records = self.free_records.saturating_add(1);
        }
    }

    fn is_used(&self, record: u64) -> bool {
        let idx = record as usize / 64;
        let bit = record as usize % 64;
        if idx >= self.bitmap.len() {
            return true;
        }
        self.bitmap[idx] & (1u64 << bit) != 0
    }

    /// Allocate a free MFT record number. Returns the record number.
    pub fn alloc_record(&mut self) -> Result<u64> {
        if self.free_records == 0 {
            return Err(Error::OutOfMemory);
        }
        let start = self.next_free;
        for delta in 0..self.total_records {
            let r = (start + delta) % self.total_records;
            if r < MFT_FIRST_USER_RECORD as usize {
                continue;
            }
            if !self.is_used(r as u64) {
                self.mark_used(r as u64);
                self.next_free = r + 1;
                return Ok(r as u64);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free MFT record number `record`.
    pub fn free_record(&mut self, record: u64) -> Result<()> {
        if record < MFT_FIRST_USER_RECORD {
            return Err(Error::InvalidArgument); // cannot free system records
        }
        if !self.is_used(record) {
            return Err(Error::InvalidArgument);
        }
        self.mark_free(record);
        Ok(())
    }

    /// Return `true` if `record` is currently allocated.
    pub fn is_allocated(&self, record: u64) -> bool {
        self.is_used(record)
    }
}
