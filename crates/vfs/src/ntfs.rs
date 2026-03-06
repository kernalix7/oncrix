// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-only NTFS filesystem driver.
//!
//! Parses NTFS on-disk structures and provides read-only access to
//! files and directories. This is a minimal implementation supporting:
//!
//! - Boot sector / BPB parsing and validation
//! - Master File Table (MFT) record reading
//! - Attribute parsing: `$FILE_NAME`, `$DATA` (resident + non-resident),
//!   `$INDEX_ROOT` / `$INDEX_ALLOCATION` for directory listing
//! - Standard POSIX-style metadata via `$STANDARD_INFORMATION`
//! - Path resolution through the directory tree
//!
//! The driver operates on a byte-level [`NtfsBlockReader`] trait so it
//! can sit on top of any block device abstraction (virtio-blk, ramdisk,
//! ATA, etc.).
//!
//! # Design
//!
//! NTFS represents every on-disk object as a row in the MFT. Each row
//! (MFT record) is typically 1024 bytes and contains a sequence of
//! typed *attributes*. This driver parses attributes sequentially and
//! extracts the data it needs without heap allocation — attribute
//! content is copied into fixed-size stack / static buffers.
//!
//! ## Resident vs. non-resident attributes
//!
//! - **Resident**: the attribute value is stored directly inside the
//!   MFT record.
//! - **Non-resident**: the attribute value is stored in *data runs*
//!   (a compact encoding of `(length, LCN_offset)` pairs). This driver
//!   supports the run-list format used for `$DATA` on regular files.
//!
//! Reference: Linux `fs/ntfs/`, `fs/ntfs3/`;
//! `.kernelORG/` — `filesystems/ntfs3.rst`.

use crate::ext2::BlockReader;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NTFS boot sector signature ("NTFS    " at offset 3).
const NTFS_OEM_ID: u64 = 0x2020_2053_4654_4E; // LE "NTFS   "

/// MFT record signature ("FILE").
const MFT_RECORD_SIG: u32 = 0x454C_4946;

/// Index entry signature ("INDX") on disk.
const INDX_SIG: u32 = 0x58444E49;

/// Attribute type: $STANDARD_INFORMATION.
const ATTR_STANDARD_INFORMATION: u32 = 0x10;

/// Attribute type: $FILE_NAME.
const ATTR_FILE_NAME: u32 = 0x30;

/// Attribute type: $DATA.
const ATTR_DATA: u32 = 0x80;

/// Attribute type: $INDEX_ROOT.
const ATTR_INDEX_ROOT: u32 = 0x90;

/// Attribute type: $INDEX_ALLOCATION.
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;

/// Attribute type end-marker.
const ATTR_END: u32 = 0xFFFF_FFFF;

/// MFT record size — almost universally 1024 bytes.
const MFT_RECORD_SIZE: usize = 1024;

/// Maximum MFT records we cache (one at a time for simplicity).
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file-name byte length (255 UTF-16 code units → at most 510 bytes,
/// we store as raw UTF-16 LE pairs).
const MAX_FILENAME_UTF16: usize = 255;

/// Maximum bytes in a resident attribute value we read.
const MAX_RESIDENT_SIZE: usize = 4096;

/// Maximum data-run segments we parse per attribute.
const MAX_RUN_SEGMENTS: usize = 128;

/// Maximum bytes read per `read_data` call.
const MAX_READ_SIZE: usize = 65536;

/// Well-known MFT record numbers.
const MFT_RECORD_MFT: u64 = 0;
const MFT_RECORD_ROOT: u64 = 5;

// ---------------------------------------------------------------------------
// Block reader adapter
// ---------------------------------------------------------------------------

/// Block reader for NTFS — re-uses the same trait as ext2/fat32.
pub use crate::ext2::BlockReader as NtfsBlockReader;

// ---------------------------------------------------------------------------
// On-disk helper: little-endian reads
// ---------------------------------------------------------------------------

#[inline]
fn read_u8(buf: &[u8], off: usize) -> u8 {
    buf[off]
}

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

// ---------------------------------------------------------------------------
// NTFS Boot Parameter Block (BPB)
// ---------------------------------------------------------------------------

/// Parsed NTFS BPB extracted from the boot sector (sector 0).
#[derive(Debug, Clone, Copy)]
pub struct NtfsBpb {
    /// Bytes per sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Total number of sectors on the volume.
    pub total_sectors: u64,
    /// LCN (logical cluster number) of the MFT.
    pub mft_lcn: u64,
    /// LCN of the MFT mirror.
    pub mft_mirror_lcn: u64,
    /// Clusters per MFT record (if positive) or encoded as negative byte count.
    pub clusters_per_mft_record: i8,
    /// Clusters per index block.
    pub clusters_per_index_block: i8,
}

impl NtfsBpb {
    /// Parse a BPB from the 512-byte boot sector buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 512 {
            return Err(Error::InvalidArgument);
        }
        // OEM ID at offset 3 (8 bytes): "NTFS    "
        let oem = read_u64_le(buf, 3);
        // Compare only the first 7 significant bytes ("NTFS   ")
        if oem & 0x00FF_FFFF_FFFF_FFFF != NTFS_OEM_ID & 0x00FF_FFFF_FFFF_FFFF {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            bytes_per_sector: read_u16_le(buf, 11),
            sectors_per_cluster: read_u8(buf, 13),
            total_sectors: read_u64_le(buf, 40),
            mft_lcn: read_u64_le(buf, 48),
            mft_mirror_lcn: read_u64_le(buf, 56),
            clusters_per_mft_record: buf[64] as i8,
            clusters_per_index_block: buf[68] as i8,
        })
    }

    /// Cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// MFT record size in bytes.
    pub fn mft_record_size(&self) -> u64 {
        if self.clusters_per_mft_record >= 0 {
            self.cluster_size() * self.clusters_per_mft_record as u64
        } else {
            1u64 << (-(self.clusters_per_mft_record as i32)) as u64
        }
    }

    /// Byte offset of LCN `lcn` on the volume.
    pub fn lcn_to_byte(&self, lcn: u64) -> u64 {
        lcn * self.cluster_size()
    }

    /// Byte offset of MFT record `record_no`.
    pub fn mft_record_offset(&self, mft_start_byte: u64, record_no: u64) -> u64 {
        mft_start_byte + record_no * self.mft_record_size()
    }
}

// ---------------------------------------------------------------------------
// MFT Record header
// ---------------------------------------------------------------------------

/// Parsed MFT file record header.
#[derive(Debug, Clone, Copy)]
pub struct MftRecordHeader {
    /// Signature (must equal `MFT_RECORD_SIG`).
    pub signature: u32,
    /// Offset of the update sequence array.
    pub usa_offset: u16,
    /// Size of the update sequence array (in u16 elements).
    pub usa_count: u16,
    /// Log file sequence number.
    pub lsn: u64,
    /// Sequence number of this record.
    pub sequence_number: u16,
    /// Hard link count.
    pub link_count: u16,
    /// Byte offset to the first attribute.
    pub attrs_offset: u16,
    /// Flags (bit 0 = in use, bit 1 = directory).
    pub flags: u16,
    /// Number of bytes used in this record.
    pub bytes_in_use: u32,
    /// Number of bytes allocated for this record.
    pub bytes_allocated: u32,
    /// Base file reference (0 for base records).
    pub base_mft_record: u64,
    /// Next attribute ID.
    pub next_attr_id: u16,
}

impl MftRecordHeader {
    /// Record is in use.
    pub const FLAG_IN_USE: u16 = 0x0001;
    /// Record represents a directory.
    pub const FLAG_DIRECTORY: u16 = 0x0002;

    /// Parse an MFT record header from a 1024-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 48 {
            return Err(Error::InvalidArgument);
        }
        let hdr = Self {
            signature: read_u32_le(buf, 0),
            usa_offset: read_u16_le(buf, 4),
            usa_count: read_u16_le(buf, 6),
            lsn: read_u64_le(buf, 8),
            sequence_number: read_u16_le(buf, 16),
            link_count: read_u16_le(buf, 18),
            attrs_offset: read_u16_le(buf, 20),
            flags: read_u16_le(buf, 22),
            bytes_in_use: read_u32_le(buf, 24),
            bytes_allocated: read_u32_le(buf, 28),
            base_mft_record: read_u64_le(buf, 32),
            next_attr_id: read_u16_le(buf, 40),
        };
        if hdr.signature != MFT_RECORD_SIG {
            return Err(Error::InvalidArgument);
        }
        Ok(hdr)
    }

    /// Is this record in use?
    pub fn is_in_use(&self) -> bool {
        self.flags & Self::FLAG_IN_USE != 0
    }

    /// Is this record a directory?
    pub fn is_directory(&self) -> bool {
        self.flags & Self::FLAG_DIRECTORY != 0
    }
}

// ---------------------------------------------------------------------------
// Attribute header
// ---------------------------------------------------------------------------

/// NTFS attribute header (resident or non-resident).
#[derive(Debug, Clone, Copy)]
pub struct AttrHeader {
    /// Attribute type code.
    pub attr_type: u32,
    /// Total length of this attribute (including header).
    pub length: u32,
    /// Non-resident flag (0 = resident, 1 = non-resident).
    pub non_resident: u8,
    /// Length of the attribute name (in UTF-16 code units).
    pub name_length: u8,
    /// Offset to the attribute name from the start of the attribute.
    pub name_offset: u16,
    /// Attribute flags.
    pub flags: u16,
    /// Attribute ID.
    pub attr_id: u16,
}

impl AttrHeader {
    /// Minimum header size for a resident attribute.
    pub const RESIDENT_HEADER_SIZE: usize = 24;
    /// Minimum header size for a non-resident attribute.
    pub const NON_RESIDENT_HEADER_SIZE: usize = 64;

    /// Parse from a byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            attr_type: read_u32_le(buf, 0),
            length: read_u32_le(buf, 4),
            non_resident: buf[8],
            name_length: buf[9],
            name_offset: read_u16_le(buf, 10),
            flags: read_u16_le(buf, 12),
            attr_id: read_u16_le(buf, 14),
        })
    }
}

// ---------------------------------------------------------------------------
// Resident attribute value accessor
// ---------------------------------------------------------------------------

/// Extracts the resident value from an attribute buffer.
///
/// Returns `(offset_from_attr_start, value_length)` for resident attributes.
fn resident_value_range(attr_buf: &[u8]) -> Result<(usize, usize)> {
    if attr_buf.len() < AttrHeader::RESIDENT_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let value_length = read_u32_le(attr_buf, 16) as usize;
    let value_offset = read_u16_le(attr_buf, 20) as usize;
    Ok((value_offset, value_length))
}

// ---------------------------------------------------------------------------
// Data run decoder
// ---------------------------------------------------------------------------

/// A single decoded data run segment: (length_in_clusters, start_lcn).
#[derive(Debug, Clone, Copy)]
pub struct DataRun {
    /// Number of clusters in this run.
    pub length: u64,
    /// Starting LCN (absolute). For sparse runs this is 0.
    pub lcn: u64,
}

/// Decoded run list for a non-resident attribute.
#[derive(Debug, Clone, Copy)]
pub struct RunList {
    /// Decoded segments.
    pub runs: [DataRun; MAX_RUN_SEGMENTS],
    /// Number of valid entries.
    pub count: usize,
}

impl RunList {
    const EMPTY: Self = Self {
        runs: [DataRun { length: 0, lcn: 0 }; MAX_RUN_SEGMENTS],
        count: 0,
    };

    /// Decode a NTFS run list from `buf`.
    ///
    /// Returns `(run_list, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut rl = Self::EMPTY;
        let mut pos = 0usize;
        let mut prev_lcn: i64 = 0;

        while pos < buf.len() {
            let header = buf[pos];
            if header == 0 {
                break; // end of run list
            }
            pos += 1;

            let len_size = (header & 0x0F) as usize;
            let off_size = ((header >> 4) & 0x0F) as usize;

            if len_size == 0 || pos + len_size + off_size > buf.len() {
                return Err(Error::InvalidArgument);
            }

            // Decode run length (unsigned).
            let mut run_len: u64 = 0;
            for i in 0..len_size {
                run_len |= (buf[pos + i] as u64) << (8 * i);
            }
            pos += len_size;

            // Decode LCN offset (signed, relative to previous).
            let mut lcn_delta: i64 = 0;
            for i in 0..off_size {
                lcn_delta |= (buf[pos + i] as i64) << (8 * i);
            }
            // Sign-extend.
            if off_size > 0 && (buf[pos + off_size - 1] & 0x80) != 0 {
                lcn_delta |= !((1i64 << (8 * off_size)) - 1);
            }
            pos += off_size;

            let abs_lcn = if off_size == 0 {
                // Sparse run — no LCN.
                0u64
            } else {
                prev_lcn += lcn_delta;
                prev_lcn as u64
            };

            if rl.count >= MAX_RUN_SEGMENTS {
                return Err(Error::InvalidArgument);
            }
            rl.runs[rl.count] = DataRun {
                length: run_len,
                lcn: abs_lcn,
            };
            rl.count += 1;
        }
        Ok(rl)
    }

    /// Read `buf.len()` bytes starting at virtual byte offset `offset` from this
    /// run list using `reader` and `cluster_size`.
    pub fn read_at(
        &self,
        reader: &dyn BlockReader,
        cluster_size: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        let mut remaining = buf.len();
        let mut buf_pos = 0usize;
        let mut virt_off = 0u64; // virtual offset at start of current run

        for i in 0..self.count {
            if remaining == 0 {
                break;
            }
            let run = self.runs[i];
            let run_bytes = run.length * cluster_size;
            let run_end = virt_off + run_bytes;

            if run_end <= offset {
                virt_off = run_end;
                continue;
            }
            if virt_off >= offset + remaining as u64 {
                break;
            }

            // How much of this run to read.
            let start_in_run = if offset > virt_off {
                offset - virt_off
            } else {
                0
            };
            let avail_in_run = run_bytes.saturating_sub(start_in_run);
            let to_read = avail_in_run.min(remaining as u64) as usize;

            if run.lcn == 0 {
                // Sparse run — fill with zeros.
                buf[buf_pos..buf_pos + to_read].fill(0);
            } else {
                let phys_off = run.lcn * cluster_size + start_in_run;
                reader.read_bytes(phys_off, &mut buf[buf_pos..buf_pos + to_read])?;
            }

            buf_pos += to_read;
            remaining -= to_read;
            virt_off = run_end;
        }

        Ok(buf_pos)
    }
}

// ---------------------------------------------------------------------------
// $FILE_NAME attribute value
// ---------------------------------------------------------------------------

/// Parsed $FILE_NAME attribute value.
#[derive(Debug, Clone)]
pub struct FileNameAttr {
    /// Parent directory MFT record reference (lower 48 bits = record number).
    pub parent_ref: u64,
    /// Allocated size of the file.
    pub allocated_size: u64,
    /// Real size of the file.
    pub real_size: u64,
    /// File attributes (Windows FILE_ATTRIBUTE_* flags).
    pub file_attrs: u32,
    /// File name in UTF-16LE (up to 255 code units).
    pub name_utf16: [u16; MAX_FILENAME_UTF16],
    /// Number of valid UTF-16 code units.
    pub name_len: u8,
    /// Namespace: 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS.
    pub namespace: u8,
}

impl FileNameAttr {
    const WINDOWS_ATTR_DIRECTORY: u32 = 0x10;

    /// Parse from a resident attribute value buffer (at offset after attr header).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 66 {
            return Err(Error::InvalidArgument);
        }
        let name_len = buf[64] as usize;
        let namespace = buf[65];
        if buf.len() < 66 + name_len * 2 {
            return Err(Error::InvalidArgument);
        }
        let mut name_utf16 = [0u16; MAX_FILENAME_UTF16];
        let copy_len = name_len.min(MAX_FILENAME_UTF16);
        for i in 0..copy_len {
            name_utf16[i] = read_u16_le(buf, 66 + i * 2);
        }
        Ok(Self {
            parent_ref: read_u64_le(buf, 0),
            allocated_size: read_u64_le(buf, 40),
            real_size: read_u64_le(buf, 48),
            file_attrs: read_u32_le(buf, 56),
            name_utf16,
            name_len: name_len.min(MAX_FILENAME_UTF16) as u8,
            namespace,
        })
    }

    /// Parent MFT record number (lower 48 bits).
    pub fn parent_mft_record(&self) -> u64 {
        self.parent_ref & 0x0000_FFFF_FFFF_FFFF
    }

    /// Is this a directory?
    pub fn is_directory(&self) -> bool {
        self.file_attrs & Self::WINDOWS_ATTR_DIRECTORY != 0
    }

    /// Compare name to a UTF-8 string (case-sensitive, ASCII-only comparison).
    pub fn name_matches(&self, s: &str) -> bool {
        let bytes = s.as_bytes();
        if self.name_len as usize != bytes.len() {
            return false;
        }
        for i in 0..self.name_len as usize {
            // Only handles ASCII; non-ASCII UTF-16 won't match.
            if self.name_utf16[i] > 0x7F {
                return false;
            }
            if self.name_utf16[i] as u8 != bytes[i] {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Directory entry (for readdir output)
// ---------------------------------------------------------------------------

/// An NTFS directory entry returned by [`NtfsFs::readdir`].
#[derive(Debug, Clone)]
pub struct NtfsDirEntry {
    /// MFT record number of this entry.
    pub mft_record: u64,
    /// File name in UTF-16LE.
    pub name_utf16: [u16; MAX_FILENAME_UTF16],
    /// Number of valid UTF-16 code units.
    pub name_len: u8,
    /// True if this entry is a directory.
    pub is_directory: bool,
    /// File size in bytes.
    pub file_size: u64,
}

impl NtfsDirEntry {
    const EMPTY: Self = Self {
        mft_record: 0,
        name_utf16: [0; MAX_FILENAME_UTF16],
        name_len: 0,
        is_directory: false,
        file_size: 0,
    };
}

// ---------------------------------------------------------------------------
// NtfsFs — the main driver
// ---------------------------------------------------------------------------

/// NTFS read-only filesystem driver.
///
/// Wraps a [`BlockReader`] and provides inode lookup, directory listing,
/// and file data reading operations.
pub struct NtfsFs<R: BlockReader> {
    reader: R,
    bpb: NtfsBpb,
    /// Byte offset of MFT record 0 on the volume.
    mft_start_byte: u64,
}

impl<R: BlockReader> NtfsFs<R> {
    /// Mount an NTFS volume.
    ///
    /// Reads and validates the boot sector, then locates the MFT.
    pub fn mount(reader: R) -> Result<Self> {
        let mut boot = [0u8; 512];
        reader.read_bytes(0, &mut boot)?;
        let bpb = NtfsBpb::from_bytes(&boot)?;
        let mft_start_byte = bpb.lcn_to_byte(bpb.mft_lcn);
        Ok(Self {
            reader,
            bpb,
            mft_start_byte,
        })
    }

    /// Return a reference to the BPB.
    pub fn bpb(&self) -> &NtfsBpb {
        &self.bpb
    }

    /// Return the MFT record number of the root directory ($. entry).
    pub fn root_record(&self) -> u64 {
        MFT_RECORD_ROOT
    }

    // -----------------------------------------------------------------------
    // MFT record I/O
    // -----------------------------------------------------------------------

    /// Read and validate an MFT record.
    fn read_mft_record(&self, record_no: u64, buf: &mut [u8; MFT_RECORD_SIZE]) -> Result<()> {
        let offset = self.bpb.mft_record_offset(self.mft_start_byte, record_no);
        self.reader.read_bytes(offset, buf)?;
        // Basic fixup: verify signature after reading.
        let sig = read_u32_le(buf, 0);
        if sig != MFT_RECORD_SIG {
            // Try mirror.
            let mirror_start = self.bpb.lcn_to_byte(self.bpb.mft_mirror_lcn);
            let mirror_off = self.bpb.mft_record_offset(mirror_start, record_no);
            self.reader.read_bytes(mirror_off, buf)?;
            let sig2 = read_u32_le(buf, 0);
            if sig2 != MFT_RECORD_SIG {
                return Err(Error::IoError);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Attribute iteration helpers
    // -----------------------------------------------------------------------

    /// Find the first attribute of `attr_type` in an MFT record buffer.
    ///
    /// Returns the byte offset within `mft_buf` at which the attribute starts,
    /// or `Err(NotFound)` if no such attribute exists.
    fn find_attr(&self, mft_buf: &[u8; MFT_RECORD_SIZE], attr_type: u32) -> Result<usize> {
        let hdr = MftRecordHeader::from_bytes(mft_buf)?;
        let mut pos = hdr.attrs_offset as usize;

        while pos + 4 <= mft_buf.len() {
            let ty = read_u32_le(mft_buf, pos);
            if ty == ATTR_END {
                break;
            }
            if ty == attr_type {
                return Ok(pos);
            }
            // Advance by attribute length.
            if pos + 8 > mft_buf.len() {
                break;
            }
            let len = read_u32_le(mft_buf, pos + 4) as usize;
            if len == 0 || pos + len > mft_buf.len() {
                break;
            }
            pos += len;
        }
        Err(Error::NotFound)
    }

    /// Read a resident attribute value into a fixed buffer.
    ///
    /// Returns the number of bytes written to `out`.
    fn read_resident_attr(
        &self,
        mft_buf: &[u8; MFT_RECORD_SIZE],
        attr_type: u32,
        out: &mut [u8; MAX_RESIDENT_SIZE],
    ) -> Result<usize> {
        let attr_off = self.find_attr(mft_buf, attr_type)?;
        let attr_buf = &mft_buf[attr_off..];
        let hdr = AttrHeader::from_bytes(attr_buf)?;
        if hdr.non_resident != 0 {
            return Err(Error::InvalidArgument);
        }
        let (val_off, val_len) = resident_value_range(attr_buf)?;
        let copy_len = val_len.min(MAX_RESIDENT_SIZE);
        if attr_off + val_off + copy_len > MFT_RECORD_SIZE {
            return Err(Error::InvalidArgument);
        }
        out[..copy_len]
            .copy_from_slice(&mft_buf[attr_off + val_off..attr_off + val_off + copy_len]);
        Ok(copy_len)
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Look up a child entry by name within a directory MFT record.
    ///
    /// Searches the `$INDEX_ROOT` attribute (B-tree root node) for a
    /// matching filename. Returns the child's MFT record number.
    pub fn lookup(&self, dir_record: u64, name: &str) -> Result<u64> {
        let mut buf = [0u8; MFT_RECORD_SIZE];
        self.read_mft_record(dir_record, &mut buf)?;

        let hdr = MftRecordHeader::from_bytes(&buf)?;
        if !hdr.is_in_use() {
            return Err(Error::NotFound);
        }
        if !hdr.is_directory() {
            return Err(Error::NotFound);
        }

        // Parse $INDEX_ROOT attribute.
        let attr_off = self.find_attr(&buf, ATTR_INDEX_ROOT)?;
        let attr_buf = &buf[attr_off..];
        let attr_hdr = AttrHeader::from_bytes(attr_buf)?;
        if attr_hdr.non_resident != 0 {
            return Err(Error::InvalidArgument);
        }
        let (val_off, val_len) = resident_value_range(attr_buf)?;
        // $INDEX_ROOT value: 16-byte header + index block header + entries.
        // Index entries start at offset 16 (index root header) + entries_offset.
        if val_len < 32 {
            return Err(Error::InvalidArgument);
        }
        let root_val = &attr_buf[val_off..val_off + val_len.min(MAX_RESIDENT_SIZE)];
        // Byte 16 of index root: index block header starts here.
        // Entries offset within the index block header is at byte 0 of the index header.
        let entries_offset = read_u32_le(root_val, 16) as usize; // offset to first entry (from start of index header)
        let index_header_off = 16usize; // index root header = 16 bytes
        let entry_start = index_header_off + entries_offset;

        self.search_index_entries(root_val, entry_start, name)
    }

    /// Search index entries in a buffer for a filename.
    fn search_index_entries(&self, buf: &[u8], mut pos: usize, name: &str) -> Result<u64> {
        while pos + 16 <= buf.len() {
            // Index entry:
            //   0..8  : file reference (MFT record + seq)
            //   8..10 : entry length
            //   10..12: key length (length of $FILE_NAME attribute value)
            //   12..13: flags (0x02 = last entry in node)
            let entry_len = read_u16_le(buf, pos + 8) as usize;
            if entry_len == 0 {
                break;
            }
            let flags = read_u8(buf, pos + 12);
            let key_len = read_u16_le(buf, pos + 10) as usize;

            // Last entry in node — no file reference.
            let is_last = flags & 0x02 != 0;

            if !is_last && key_len >= 66 && pos + 16 + key_len <= buf.len() {
                // File reference at bytes 0..8.
                let file_ref = read_u64_le(buf, pos);
                let mft_rec = file_ref & 0x0000_FFFF_FFFF_FFFF;

                // $FILE_NAME value starts at byte 16 of the index entry.
                let fn_buf = &buf[pos + 16..pos + 16 + key_len];
                if let Ok(fn_attr) = FileNameAttr::from_bytes(fn_buf) {
                    // Skip . and .. (MFT records 5 and under).
                    if fn_attr.name_matches(name) {
                        return Ok(mft_rec);
                    }
                }
            }

            pos += entry_len;
            if is_last {
                break;
            }
        }
        Err(Error::NotFound)
    }

    /// Resolve a path (components separated by '/') starting from the root.
    ///
    /// Returns the MFT record number of the target.
    pub fn resolve_path(&self, path: &str) -> Result<u64> {
        let mut current = MFT_RECORD_ROOT;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            current = self.lookup(current, component)?;
        }
        Ok(current)
    }

    /// Read directory entries from `dir_record` into `out`.
    ///
    /// Returns the number of entries written.
    pub fn readdir(
        &self,
        dir_record: u64,
        out: &mut [NtfsDirEntry; MAX_DIR_ENTRIES],
    ) -> Result<usize> {
        let mut buf = [0u8; MFT_RECORD_SIZE];
        self.read_mft_record(dir_record, &mut buf)?;

        let hdr = MftRecordHeader::from_bytes(&buf)?;
        if !hdr.is_in_use() || !hdr.is_directory() {
            return Err(Error::NotFound);
        }

        let attr_off = self.find_attr(&buf, ATTR_INDEX_ROOT)?;
        let attr_buf = &buf[attr_off..];
        let attr_hdr = AttrHeader::from_bytes(attr_buf)?;
        if attr_hdr.non_resident != 0 {
            return Err(Error::InvalidArgument);
        }
        let (val_off, val_len) = resident_value_range(attr_buf)?;
        let root_val = &attr_buf[val_off..val_off + val_len.min(MAX_RESIDENT_SIZE)];
        if root_val.len() < 32 {
            return Err(Error::InvalidArgument);
        }

        let entries_offset = read_u32_le(root_val, 16) as usize;
        let index_header_off = 16usize;
        let entry_start = index_header_off + entries_offset;

        let mut count = 0usize;
        let mut pos = entry_start;

        while pos + 16 <= root_val.len() && count < MAX_DIR_ENTRIES {
            let entry_len = read_u16_le(root_val, pos + 8) as usize;
            if entry_len == 0 {
                break;
            }
            let flags = read_u8(root_val, pos + 12);
            let key_len = read_u16_le(root_val, pos + 10) as usize;
            let is_last = flags & 0x02 != 0;

            if !is_last && key_len >= 66 && pos + 16 + key_len <= root_val.len() {
                let file_ref = read_u64_le(root_val, pos);
                let mft_rec = file_ref & 0x0000_FFFF_FFFF_FFFF;
                let fn_buf = &root_val[pos + 16..pos + 16 + key_len];

                if let Ok(fn_attr) = FileNameAttr::from_bytes(fn_buf) {
                    // Skip namespace-duplicate entries (prefer Win32 or POSIX).
                    if fn_attr.namespace != 2 {
                        // skip DOS-only entries
                        let mut ent = NtfsDirEntry::EMPTY;
                        ent.mft_record = mft_rec;
                        ent.name_len = fn_attr.name_len;
                        ent.name_utf16[..fn_attr.name_len as usize]
                            .copy_from_slice(&fn_attr.name_utf16[..fn_attr.name_len as usize]);
                        ent.is_directory = fn_attr.is_directory();
                        ent.file_size = fn_attr.real_size;
                        out[count] = ent;
                        count += 1;
                    }
                }
            }

            pos += entry_len;
            if is_last {
                break;
            }
        }

        Ok(count)
    }

    /// Read file data from an MFT record.
    ///
    /// Supports both resident and non-resident `$DATA` attributes.
    /// Returns the number of bytes read into `buf`.
    pub fn read_data(&self, record_no: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.len() > MAX_READ_SIZE {
            return Err(Error::InvalidArgument);
        }

        let mut mft_buf = [0u8; MFT_RECORD_SIZE];
        self.read_mft_record(record_no, &mut mft_buf)?;

        let hdr = MftRecordHeader::from_bytes(&mft_buf)?;
        if !hdr.is_in_use() {
            return Err(Error::NotFound);
        }

        let attr_off = self.find_attr(&mft_buf, ATTR_DATA)?;
        let attr_buf = &mft_buf[attr_off..];
        let attr_hdr = AttrHeader::from_bytes(attr_buf)?;

        if attr_hdr.non_resident == 0 {
            // Resident data.
            let (val_off, val_len) = resident_value_range(attr_buf)?;
            let start = offset as usize;
            if start >= val_len {
                return Ok(0);
            }
            let avail = val_len - start;
            let to_copy = buf.len().min(avail);
            let data_start = attr_off + val_off + start;
            if data_start + to_copy > MFT_RECORD_SIZE {
                return Err(Error::InvalidArgument);
            }
            buf[..to_copy].copy_from_slice(&mft_buf[data_start..data_start + to_copy]);
            Ok(to_copy)
        } else {
            // Non-resident data — decode run list.
            // Run list offset from start of attribute.
            if attr_buf.len() < AttrHeader::NON_RESIDENT_HEADER_SIZE {
                return Err(Error::InvalidArgument);
            }
            let run_list_offset = read_u16_le(attr_buf, 32) as usize;
            let data_size = read_u64_le(attr_buf, 48); // real (initialised) size

            if offset >= data_size {
                return Ok(0);
            }
            let to_read = buf.len().min((data_size - offset) as usize);

            let run_buf = &attr_buf[run_list_offset..];
            let rl = RunList::decode(run_buf)?;
            rl.read_at(
                &self.reader,
                self.bpb.cluster_size(),
                offset,
                &mut buf[..to_read],
            )
        }
    }

    /// Stat an MFT record: returns `(file_size, is_directory)`.
    pub fn stat(&self, record_no: u64) -> Result<(u64, bool)> {
        let mut buf = [0u8; MFT_RECORD_SIZE];
        self.read_mft_record(record_no, &mut buf)?;

        let hdr = MftRecordHeader::from_bytes(&buf)?;
        if !hdr.is_in_use() {
            return Err(Error::NotFound);
        }
        let is_dir = hdr.is_directory();

        // Try to get file size from $FILE_NAME.
        let mut fn_val = [0u8; MAX_RESIDENT_SIZE];
        let size = if let Ok(n) = self.read_resident_attr(&buf, ATTR_FILE_NAME, &mut fn_val) {
            if n >= 58 { read_u64_le(&fn_val, 48) } else { 0 }
        } else {
            0
        };

        Ok((size, is_dir))
    }
}

// ---------------------------------------------------------------------------
// MFT record well-known numbers (public re-export)
// ---------------------------------------------------------------------------

/// MFT record number of the $MFT file.
pub const NTFS_MFT_RECORD: u64 = MFT_RECORD_MFT;
/// MFT record number of the root directory.
pub const NTFS_ROOT_RECORD: u64 = MFT_RECORD_ROOT;

// ---------------------------------------------------------------------------
// Unit-level smoke tests (compile-only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct ZeroReader;
    impl BlockReader for ZeroReader {
        fn read_bytes(&self, _offset: u64, buf: &mut [u8]) -> oncrix_lib::Result<()> {
            buf.fill(0);
            Ok(())
        }
    }

    #[test]
    fn run_list_decode_empty() {
        let data = [0u8; 1];
        let rl = RunList::decode(&data).unwrap();
        assert_eq!(rl.count, 0);
    }

    #[test]
    fn run_list_decode_single() {
        // Header 0x11: length_size=1, offset_size=1.  Length=4, LCN=10.
        let data = [0x11u8, 4, 10, 0x00];
        let rl = RunList::decode(&data).unwrap();
        assert_eq!(rl.count, 1);
        assert_eq!(rl.runs[0].length, 4);
        assert_eq!(rl.runs[0].lcn, 10);
    }

    #[test]
    fn ntfs_bpb_bad_oem() {
        let mut boot = [0u8; 512];
        // Wrong OEM ID
        boot[3] = b'F';
        boot[4] = b'A';
        boot[5] = b'T';
        assert!(NtfsBpb::from_bytes(&boot).is_err());
    }
}
