// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NTFS attribute parsing and access.
//!
//! NTFS stores all file metadata and data as typed *attributes* within an
//! MFT record. This module provides:
//!
//! - [`AttrType`] — well-known NTFS attribute type codes
//! - [`AttrHeader`] — common attribute header (resident + non-resident)
//! - [`ResidentAttr`] — attribute whose value lives inside the MFT record
//! - [`NonResidentAttr`] — attribute whose value lives in data runs on disk
//! - [`DataRun`] — decoded (length, LCN) pair from the run-list encoding
//! - [`AttrIter`] — iterator over all attributes in an MFT record
//! - [`find_attr`] — find the first attribute of a given type
//!
//! # Attribute Header Layout (resident)
//!
//! ```text
//! [0..4]   Attribute type code
//! [4..8]   Record length
//! [8]      Non-resident flag (0 = resident, 1 = non-resident)
//! [9]      Name length (characters; 0 for unnamed)
//! [10..12] Name offset
//! [12..14] Flags
//! [14..16] Attribute ID
//! [16..20] Value length (resident only)
//! [20..22] Value offset (resident only)
//! [22]     Indexed flag
//! [23]     Padding
//! ```
//!
//! # References
//!
//! - Linux `fs/ntfs/attr.c`, `fs/ntfs3/attrib.c`
//! - libntfs-3g `include/ntfs-3g/layout.h`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Attribute Type Codes ──────────────────────────────────────────────────────

/// NTFS attribute type codes (as u32 little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AttrType {
    /// $STANDARD_INFORMATION — timestamps, DOS file attributes.
    StandardInformation = 0x10,
    /// $ATTRIBUTE_LIST — list of additional attribute locations.
    AttributeList = 0x20,
    /// $FILE_NAME — file name(s) in Unicode.
    FileName = 0x30,
    /// $OBJECT_ID — unique 64-bit file identifier.
    ObjectId = 0x40,
    /// $SECURITY_DESCRIPTOR — ACL and owner information.
    SecurityDescriptor = 0x50,
    /// $VOLUME_NAME — volume label.
    VolumeName = 0x60,
    /// $VOLUME_INFORMATION — NTFS version and flags.
    VolumeInformation = 0x70,
    /// $DATA — primary file data stream.
    Data = 0x80,
    /// $INDEX_ROOT — B-tree root for directory index.
    IndexRoot = 0x90,
    /// $INDEX_ALLOCATION — B-tree non-leaf nodes for directory index.
    IndexAllocation = 0xA0,
    /// $BITMAP — bitmap for index allocation.
    Bitmap = 0xB0,
    /// $REPARSE_POINT — reparse data (junctions, symlinks).
    ReparsePoint = 0xC0,
    /// $EA_INFORMATION — extended attributes info.
    EaInformation = 0xD0,
    /// $EA — extended attribute data.
    Ea = 0xE0,
    /// End-of-attributes marker.
    End = 0xFFFF_FFFF,
}

impl AttrType {
    /// Construct from raw u32. Returns `None` for unknown types.
    pub fn from_raw(v: u32) -> Option<Self> {
        match v {
            0x10 => Some(Self::StandardInformation),
            0x20 => Some(Self::AttributeList),
            0x30 => Some(Self::FileName),
            0x40 => Some(Self::ObjectId),
            0x50 => Some(Self::SecurityDescriptor),
            0x60 => Some(Self::VolumeName),
            0x70 => Some(Self::VolumeInformation),
            0x80 => Some(Self::Data),
            0x90 => Some(Self::IndexRoot),
            0xA0 => Some(Self::IndexAllocation),
            0xB0 => Some(Self::Bitmap),
            0xC0 => Some(Self::ReparsePoint),
            0xD0 => Some(Self::EaInformation),
            0xE0 => Some(Self::Ea),
            0xFFFF_FFFF => Some(Self::End),
            _ => None,
        }
    }
}

// ── Attribute Flags ───────────────────────────────────────────────────────────

/// Attribute is compressed.
pub const ATTR_FLAG_COMPRESSED: u16 = 0x0001;

/// Attribute is encrypted.
pub const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;

/// Attribute is sparse.
pub const ATTR_FLAG_SPARSE: u16 = 0x8000;

// ── Attribute Header ──────────────────────────────────────────────────────────

/// Common prefix of every NTFS attribute record.
#[derive(Debug, Clone, Copy)]
pub struct AttrHeader {
    /// Attribute type code.
    pub attr_type: u32,
    /// Total record length (including header + value/runs).
    pub record_length: u32,
    /// `false` = resident; `true` = non-resident.
    pub non_resident: bool,
    /// Length of the attribute name in characters (usually 0).
    pub name_length: u8,
    /// Byte offset of name from start of attribute record.
    pub name_offset: u16,
    /// Attribute flags.
    pub flags: u16,
    /// Attribute instance ID.
    pub attr_id: u16,
}

impl AttrHeader {
    /// Parse the common header from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let attr_type =
            u32::from_le_bytes(buf[0..4].try_into().map_err(|_| Error::InvalidArgument)?);
        let record_length =
            u32::from_le_bytes(buf[4..8].try_into().map_err(|_| Error::InvalidArgument)?);
        let non_resident = buf[8] != 0;
        let name_length = buf[9];
        let name_offset =
            u16::from_le_bytes(buf[10..12].try_into().map_err(|_| Error::InvalidArgument)?);
        let flags = u16::from_le_bytes(buf[12..14].try_into().map_err(|_| Error::InvalidArgument)?);
        let attr_id =
            u16::from_le_bytes(buf[14..16].try_into().map_err(|_| Error::InvalidArgument)?);
        Ok(Self {
            attr_type,
            record_length,
            non_resident,
            name_length,
            name_offset,
            flags,
            attr_id,
        })
    }
}

// ── Resident Attribute ────────────────────────────────────────────────────────

/// A fully parsed resident attribute record.
#[derive(Debug, Clone)]
pub struct ResidentAttr {
    /// Common header.
    pub header: AttrHeader,
    /// Byte length of the attribute value.
    pub value_length: u32,
    /// Offset of the value from the start of the attribute record.
    pub value_offset: u16,
    /// `true` if the attribute value is indexed.
    pub indexed: bool,
    /// Attribute name (empty if unnamed).
    pub name: [u16; 128],
    /// Name length in characters.
    pub name_len: usize,
}

impl ResidentAttr {
    /// Minimum resident attribute header size in bytes.
    const MIN_SIZE: usize = 24;

    /// Parse a resident attribute from `buf` (whole attribute record).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Error::InvalidArgument);
        }
        let header = AttrHeader::parse(buf)?;
        if header.non_resident {
            return Err(Error::InvalidArgument);
        }
        let value_length =
            u32::from_le_bytes(buf[16..20].try_into().map_err(|_| Error::InvalidArgument)?);
        let value_offset =
            u16::from_le_bytes(buf[20..22].try_into().map_err(|_| Error::InvalidArgument)?);
        let indexed = buf[22] != 0;

        // Parse optional name.
        let mut name = [0u16; 128];
        let name_len = header.name_length as usize;
        let name_off = header.name_offset as usize;
        if name_len > 0 && name_off + name_len * 2 <= buf.len() {
            let len = name_len.min(128);
            for i in 0..len {
                name[i] = u16::from_le_bytes([buf[name_off + i * 2], buf[name_off + i * 2 + 1]]);
            }
        }

        Ok(Self {
            header,
            value_length,
            value_offset,
            indexed,
            name,
            name_len,
        })
    }

    /// Return the value bytes from `buf` (the same buffer passed to `parse`).
    pub fn value<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8]> {
        let start = self.value_offset as usize;
        let end = start + self.value_length as usize;
        if end > buf.len() {
            return Err(Error::InvalidArgument);
        }
        Ok(&buf[start..end])
    }
}

// ── Data Runs ─────────────────────────────────────────────────────────────────

/// A decoded data run: `(cluster_count, starting_lcn)`.
///
/// `starting_lcn` is absolute when decoded from the run list.
/// A run with `cluster_count == 0` terminates the run list.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataRun {
    /// Number of clusters in this run.
    pub cluster_count: u64,
    /// Starting Logical Cluster Number (absolute).
    pub start_lcn: i64,
}

/// Decode the NTFS run-list encoding from `buf` into a `Vec<DataRun>`.
///
/// NTFS encodes runs as: `[nibble: len_of_len | nibble: len_of_offset] [length bytes] [offset bytes]`
/// with a `0x00` terminator.
pub fn decode_run_list(buf: &[u8]) -> Result<Vec<DataRun>> {
    let mut runs = Vec::new();
    let mut pos = 0;
    let mut prev_lcn: i64 = 0;
    while pos < buf.len() {
        let byte = buf[pos];
        pos += 1;
        if byte == 0 {
            break; // terminator
        }
        let len_size = (byte & 0x0F) as usize;
        let off_size = ((byte >> 4) & 0x0F) as usize;
        if len_size == 0 || pos + len_size + off_size > buf.len() {
            return Err(Error::InvalidArgument);
        }
        // Read cluster count (unsigned, little-endian).
        let mut cluster_count: u64 = 0;
        for i in 0..len_size {
            cluster_count |= (buf[pos + i] as u64) << (i * 8);
        }
        pos += len_size;
        // Read LCN delta (signed, little-endian).
        let mut delta: i64 = 0;
        if off_size > 0 {
            let mut raw: i64 = 0;
            for i in 0..off_size {
                raw |= (buf[pos + i] as i64) << (i * 8);
            }
            // Sign-extend.
            let sign_bit = (off_size * 8) - 1;
            if raw & (1i64 << sign_bit) != 0 {
                raw |= !((1i64 << (off_size * 8)) - 1);
            }
            delta = raw;
        }
        pos += off_size;
        prev_lcn = prev_lcn.wrapping_add(delta);
        runs.push(DataRun {
            cluster_count,
            start_lcn: prev_lcn,
        });
    }
    Ok(runs)
}

// ── Non-Resident Attribute ────────────────────────────────────────────────────

/// A parsed non-resident attribute.
#[derive(Debug, Clone)]
pub struct NonResidentAttr {
    /// Common header.
    pub header: AttrHeader,
    /// Lowest VCN covered by this attribute record.
    pub lowest_vcn: i64,
    /// Highest VCN covered by this attribute record.
    pub highest_vcn: i64,
    /// Offset of the run list from the start of the attribute record.
    pub run_list_offset: u16,
    /// Compression unit size (0 = not compressed).
    pub compression_unit: u16,
    /// Allocated size (multiple of cluster size).
    pub allocated_size: u64,
    /// Data size (logical end of file).
    pub data_size: u64,
    /// Initialized size (zero-filled past this).
    pub initialized_size: u64,
    /// Decoded data runs.
    pub runs: Vec<DataRun>,
}

impl NonResidentAttr {
    /// Minimum non-resident header size.
    const MIN_SIZE: usize = 64;

    /// Parse a non-resident attribute from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Error::InvalidArgument);
        }
        let header = AttrHeader::parse(buf)?;
        if !header.non_resident {
            return Err(Error::InvalidArgument);
        }
        let lowest_vcn =
            i64::from_le_bytes(buf[16..24].try_into().map_err(|_| Error::InvalidArgument)?);
        let highest_vcn =
            i64::from_le_bytes(buf[24..32].try_into().map_err(|_| Error::InvalidArgument)?);
        let run_list_offset =
            u16::from_le_bytes(buf[32..34].try_into().map_err(|_| Error::InvalidArgument)?);
        let compression_unit =
            u16::from_le_bytes(buf[34..36].try_into().map_err(|_| Error::InvalidArgument)?);
        let allocated_size =
            u64::from_le_bytes(buf[40..48].try_into().map_err(|_| Error::InvalidArgument)?);
        let data_size =
            u64::from_le_bytes(buf[48..56].try_into().map_err(|_| Error::InvalidArgument)?);
        let initialized_size =
            u64::from_le_bytes(buf[56..64].try_into().map_err(|_| Error::InvalidArgument)?);
        let rl_off = run_list_offset as usize;
        let runs = if rl_off < buf.len() {
            decode_run_list(&buf[rl_off..])?
        } else {
            Vec::new()
        };
        Ok(Self {
            header,
            lowest_vcn,
            highest_vcn,
            run_list_offset,
            compression_unit,
            allocated_size,
            data_size,
            initialized_size,
            runs,
        })
    }
}

// ── Attribute Iterator ────────────────────────────────────────────────────────

/// Iterator over attributes in an MFT record's attribute bytes.
pub struct AttrIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> AttrIter<'a> {
    /// Create an iterator over the attribute bytes in `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = (AttrHeader, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 8 > self.buf.len() {
            return None;
        }
        let hdr = AttrHeader::parse(&self.buf[self.pos..]).ok()?;
        if hdr.attr_type == 0xFFFF_FFFF || hdr.record_length == 0 {
            return None; // end-of-attributes
        }
        let end = self.pos + hdr.record_length as usize;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some((hdr, slice))
    }
}

/// Find the first attribute of type `ty` in `attr_bytes`.
///
/// Returns the raw attribute slice, or `None` if not found.
pub fn find_attr(attr_bytes: &[u8], ty: AttrType) -> Option<&[u8]> {
    for (hdr, slice) in AttrIter::new(attr_bytes) {
        if hdr.attr_type == ty as u32 {
            return Some(slice);
        }
    }
    None
}
