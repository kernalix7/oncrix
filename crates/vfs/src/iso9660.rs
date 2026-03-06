// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ISO 9660 CD-ROM filesystem (ECMA-119).
//!
//! Implements read-only access to ISO 9660 images as used on CD-ROMs,
//! DVDs, and disk images. Supports the base ISO 9660 format plus two
//! common extensions:
//!
//! - **Rock Ridge** (SUSP/RRIP) — POSIX file attributes, long names,
//!   symbolic links, and device nodes
//! - **Joliet** — UCS-2 Unicode file names via a supplementary volume
//!   descriptor
//!
//! # On-disk layout
//!
//! ```text
//! Sector 0..15   -- System Area (unused by ISO 9660)
//! Sector 16      -- Primary Volume Descriptor (PVD)
//! Sector 17+     -- Supplementary Volume Descriptors (Joliet, etc.)
//! ...            -- Volume Descriptor Set Terminator (type 255)
//! Root directory  -- Directory records with extent locations
//! Data extents    -- File data (contiguous, no fragmentation)
//! ```
//!
//! # Structures
//!
//! - [`PrimaryVolumeDescriptor`] — PVD parsed from sector 16
//! - [`DirectoryRecord`] — single directory entry on disk
//! - [`PathTableEntry`] — path table entry for fast directory lookup
//! - [`RockRidgeAttrs`] — POSIX attributes from Rock Ridge extensions
//! - [`JolietName`] — decoded UCS-2 filename from Joliet SVD
//! - [`Iso9660Fs`] — mounted filesystem handle
//!
//! # References
//!
//! - ECMA-119 (ISO 9660:1988)
//! - IEEE P1281 / SUSP 1.12 (System Use Sharing Protocol)
//! - IEEE P1282 / RRIP 1.12 (Rock Ridge Interchange Protocol)
//! - ECMA-119 Joliet Extension (Microsoft)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Logical sector size (2048 bytes for CD-ROM media).
pub const SECTOR_SIZE: usize = 2048;

/// Offset of the primary volume descriptor (sector 16).
const PVD_SECTOR: usize = 16;

/// ISO 9660 standard identifier `"CD001"`.
const ISO_STANDARD_ID: [u8; 5] = *b"CD001";

/// Volume descriptor type: Primary.
const VD_TYPE_PRIMARY: u8 = 1;

/// Volume descriptor type: Supplementary (Joliet).
const VD_TYPE_SUPPLEMENTARY: u8 = 2;

/// Volume descriptor type: Set Terminator.
const VD_TYPE_TERMINATOR: u8 = 255;

/// Maximum directory entries returned by [`Iso9660Fs::readdir`].
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum filename length in bytes.
const MAX_NAME_LEN: usize = 255;

/// Maximum path table entries.
const MAX_PATH_TABLE_ENTRIES: usize = 256;

/// Rock Ridge signature: `"PX"` (POSIX attributes).
const RR_SIGNATURE_PX: [u8; 2] = *b"PX";

/// Rock Ridge signature: `"NM"` (alternate name).
const RR_SIGNATURE_NM: [u8; 2] = *b"NM";

/// Rock Ridge signature: `"SL"` (symbolic link).
const RR_SIGNATURE_SL: [u8; 2] = *b"SL";

/// Joliet escape sequence for UCS-2 Level 3 (`%/E`).
const JOLIET_ESCAPE_UCS2_L3: [u8; 3] = [0x25, 0x2F, 0x45];

// ── PrimaryVolumeDescriptor ──────────────────────────────────────

/// ISO 9660 Primary Volume Descriptor (PVD), parsed from sector 16.
///
/// Contains essential filesystem metadata: volume name, block counts,
/// root directory location, and path table pointers.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PrimaryVolumeDescriptor {
    /// Volume descriptor type (1 = primary).
    pub vd_type: u8,
    /// Volume space size in logical blocks.
    pub volume_space_size: u32,
    /// Logical block size in bytes (always 2048 for CD-ROM).
    pub logical_block_size: u16,
    /// Path table size in bytes.
    pub path_table_size: u32,
    /// Location of the L-path table (little-endian occurrence).
    pub path_table_l_location: u32,
    /// Location of the optional L-path table.
    pub path_table_l_opt_location: u32,
    /// Root directory record extent location (LBA).
    pub root_dir_extent: u32,
    /// Root directory record data length in bytes.
    pub root_dir_size: u32,
    /// Volume identifier (32 bytes, space-padded).
    pub volume_id: [u8; 32],
    /// Volume creation date/time (17 bytes, ASCII digits).
    pub creation_date: [u8; 17],
    /// Volume set size.
    pub volume_set_size: u16,
    /// Volume sequence number.
    pub volume_seq_number: u16,
}

impl PrimaryVolumeDescriptor {
    /// Parse a PVD from a 2048-byte sector buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the buffer is too short,
    /// the standard identifier is wrong, or the descriptor type is not
    /// primary.
    pub fn parse(sector: &[u8]) -> Result<Self> {
        if sector.len() < SECTOR_SIZE {
            return Err(Error::InvalidArgument);
        }

        let vd_type = sector[0];
        if vd_type != VD_TYPE_PRIMARY {
            return Err(Error::InvalidArgument);
        }

        // Standard identifier at bytes 1..6 must be "CD001".
        if sector[1..6] != ISO_STANDARD_ID {
            return Err(Error::InvalidArgument);
        }

        let volume_space_size = read_u32_lsb(&sector[80..84]);
        let logical_block_size = read_u16_lsb(&sector[128..130]);
        let path_table_size = read_u32_lsb(&sector[132..136]);
        let path_table_l_location = read_u32_lsb(&sector[140..144]);
        let path_table_l_opt_location = read_u32_lsb(&sector[144..148]);

        // Root directory record starts at byte 156, 34 bytes.
        let root_dir_extent = read_u32_lsb(&sector[158..162]);
        let root_dir_size = read_u32_lsb(&sector[166..170]);

        let mut volume_id = [0u8; 32];
        volume_id.copy_from_slice(&sector[40..72]);

        let mut creation_date = [0u8; 17];
        creation_date.copy_from_slice(&sector[813..830]);

        let volume_set_size = read_u16_lsb(&sector[120..122]);
        let volume_seq_number = read_u16_lsb(&sector[124..126]);

        Ok(Self {
            vd_type,
            volume_space_size,
            logical_block_size,
            path_table_size,
            path_table_l_location,
            path_table_l_opt_location,
            root_dir_extent,
            root_dir_size,
            volume_id,
            creation_date,
            volume_set_size,
            volume_seq_number,
        })
    }

    /// Returns the volume identifier as a trimmed byte slice.
    pub fn volume_name(&self) -> &[u8] {
        let mut end = 32;
        while end > 0 && self.volume_id[end - 1] == b' ' {
            end -= 1;
        }
        &self.volume_id[..end]
    }
}

// ── DirectoryRecord ──────────────────────────────────────────────

/// ISO 9660 directory record (variable length, 33+ bytes).
///
/// Each entry in a directory extent describes one file or subdirectory.
/// The record length byte at offset 0 determines the total size. A
/// zero-length record signals padding to the next sector boundary.
#[derive(Clone, Copy)]
pub struct DirectoryRecord {
    /// Total length of this directory record in bytes.
    pub record_len: u8,
    /// Extended attribute record length.
    pub ext_attr_len: u8,
    /// Location of the extent (LBA).
    pub extent_location: u32,
    /// Data length of the extent in bytes.
    pub data_length: u32,
    /// Recording date/time (7 bytes).
    pub recording_date: [u8; 7],
    /// File flags (bit 1 = directory, bit 0 = hidden).
    pub file_flags: u8,
    /// File unit size (interleave mode).
    pub file_unit_size: u8,
    /// Interleave gap size.
    pub interleave_gap: u8,
    /// Volume sequence number.
    pub volume_seq: u16,
    /// File identifier length.
    pub name_len: u8,
    /// File identifier (name) bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Actual bytes used in `name`.
    pub name_actual_len: usize,
}

impl DirectoryRecord {
    /// Creates an empty directory record.
    pub fn empty() -> Self {
        Self {
            record_len: 0,
            ext_attr_len: 0,
            extent_location: 0,
            data_length: 0,
            recording_date: [0u8; 7],
            file_flags: 0,
            file_unit_size: 0,
            interleave_gap: 0,
            volume_seq: 0,
            name_len: 0,
            name: [0u8; MAX_NAME_LEN],
            name_actual_len: 0,
        }
    }

    /// Parse a directory record from raw bytes.
    ///
    /// Returns `None` if the record length is zero (sector padding).
    /// Returns `Err` if the data is malformed.
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        if data.is_empty() || data[0] == 0 {
            return Ok(None);
        }
        let record_len = data[0];
        if (record_len as usize) < 33 || data.len() < record_len as usize {
            return Err(Error::InvalidArgument);
        }

        let ext_attr_len = data[1];
        let extent_location = read_u32_lsb(&data[2..6]);
        let data_length = read_u32_lsb(&data[10..14]);
        let mut recording_date = [0u8; 7];
        recording_date.copy_from_slice(&data[18..25]);
        let file_flags = data[25];
        let file_unit_size = data[26];
        let interleave_gap = data[27];
        let volume_seq = read_u16_lsb(&data[28..30]);
        let name_len = data[32];

        let actual_name_len = (name_len as usize).min(MAX_NAME_LEN);
        let mut name = [0u8; MAX_NAME_LEN];
        if actual_name_len > 0 && data.len() >= 33 + actual_name_len {
            name[..actual_name_len].copy_from_slice(&data[33..33 + actual_name_len]);
        }

        Ok(Some(Self {
            record_len,
            ext_attr_len,
            extent_location,
            data_length,
            recording_date,
            file_flags,
            file_unit_size,
            interleave_gap,
            volume_seq,
            name_len,
            name,
            name_actual_len: actual_name_len,
        }))
    }

    /// Returns `true` if this record represents a directory.
    pub fn is_directory(&self) -> bool {
        (self.file_flags & 0x02) != 0
    }

    /// Returns `true` if the hidden flag is set.
    pub fn is_hidden(&self) -> bool {
        (self.file_flags & 0x01) != 0
    }

    /// Returns `true` if this is the `.` (current directory) entry.
    pub fn is_dot(&self) -> bool {
        self.name_actual_len == 1 && self.name[0] == 0x00
    }

    /// Returns `true` if this is the `..` (parent directory) entry.
    pub fn is_dotdot(&self) -> bool {
        self.name_actual_len == 1 && self.name[0] == 0x01
    }

    /// Returns the file identifier as a byte slice.
    pub fn file_name(&self) -> &[u8] {
        &self.name[..self.name_actual_len]
    }

    /// Returns the system use area offset within this record.
    ///
    /// The system use area begins after the file identifier and
    /// optional padding byte (identifiers are padded to even length).
    pub fn system_use_offset(&self) -> usize {
        let id_len = self.name_actual_len;
        33 + id_len + (1 - (id_len & 1))
    }

    /// Returns the length of the system use area in bytes.
    pub fn system_use_len(&self) -> usize {
        let su_start = self.system_use_offset();
        if su_start >= self.record_len as usize {
            0
        } else {
            self.record_len as usize - su_start
        }
    }
}

impl core::fmt::Debug for DirectoryRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectoryRecord")
            .field("record_len", &self.record_len)
            .field("extent_location", &self.extent_location)
            .field("data_length", &self.data_length)
            .field("file_flags", &self.file_flags)
            .field("name_len", &self.name_actual_len)
            .finish()
    }
}

// ── PathTableEntry ───────────────────────────────────────────────

/// ISO 9660 path table entry for fast directory lookup.
///
/// The path table provides O(1) access to any directory by its index,
/// avoiding recursive directory traversal. Each entry maps a directory
/// name to its extent location and parent index.
#[derive(Debug, Clone, Copy)]
pub struct PathTableEntry {
    /// Directory identifier length.
    pub name_len: u8,
    /// Extended attribute record length.
    pub ext_attr_len: u8,
    /// Location of the directory extent (LBA).
    pub extent_location: u32,
    /// Index of the parent directory entry (1-based).
    pub parent_dir_index: u16,
    /// Directory name bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Actual name length used.
    pub name_actual_len: usize,
    /// Whether this entry is valid.
    pub active: bool,
}

impl PathTableEntry {
    /// Creates an empty path table entry.
    pub const fn empty() -> Self {
        Self {
            name_len: 0,
            ext_attr_len: 0,
            extent_location: 0,
            parent_dir_index: 0,
            name: [0u8; MAX_NAME_LEN],
            name_actual_len: 0,
            active: false,
        }
    }

    /// Parse a path table entry from raw L-path-table bytes.
    ///
    /// Returns the entry and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        let name_len = data[0];
        let ext_attr_len = data[1];
        let extent_location = read_u32_lsb(&data[2..6]);
        let parent_dir_index = read_u16_lsb(&data[6..8]);

        let nlen = name_len as usize;
        if data.len() < 8 + nlen {
            return Err(Error::InvalidArgument);
        }
        let mut name = [0u8; MAX_NAME_LEN];
        let actual = nlen.min(MAX_NAME_LEN);
        name[..actual].copy_from_slice(&data[8..8 + actual]);

        // Pad byte if name_len is odd.
        let consumed = 8 + nlen + (nlen & 1);

        Ok((
            Self {
                name_len,
                ext_attr_len,
                extent_location,
                parent_dir_index,
                name,
                name_actual_len: actual,
                active: true,
            },
            consumed,
        ))
    }

    /// Returns the directory name as a byte slice.
    pub fn dir_name(&self) -> &[u8] {
        &self.name[..self.name_actual_len]
    }
}

// ── RockRidgeAttrs ───────────────────────────────────────────────

/// POSIX file attributes extracted from Rock Ridge SUSP entries.
///
/// Rock Ridge extensions encode POSIX metadata (mode, uid, gid, nlinks,
/// alternate names, symlink targets) in the System Use area of each
/// directory record.
#[derive(Debug, Clone, Copy)]
pub struct RockRidgeAttrs {
    /// POSIX file mode (permissions + type bits).
    pub mode: u32,
    /// Number of hard links.
    pub nlinks: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Inode serial number.
    pub ino: u32,
    /// Alternate name from NM entry.
    pub alt_name: [u8; MAX_NAME_LEN],
    /// Length of the alternate name.
    pub alt_name_len: usize,
    /// Symbolic link target from SL entry.
    pub symlink_target: [u8; MAX_NAME_LEN],
    /// Length of the symlink target.
    pub symlink_len: usize,
    /// Whether Rock Ridge extensions were found.
    pub present: bool,
}

impl RockRidgeAttrs {
    /// Creates empty attributes with no Rock Ridge data.
    pub const fn empty() -> Self {
        Self {
            mode: 0,
            nlinks: 0,
            uid: 0,
            gid: 0,
            ino: 0,
            alt_name: [0u8; MAX_NAME_LEN],
            alt_name_len: 0,
            symlink_target: [0u8; MAX_NAME_LEN],
            symlink_len: 0,
            present: false,
        }
    }

    /// Parse Rock Ridge attributes from the system use area of a
    /// directory record.
    ///
    /// The system use area begins immediately after the file identifier
    /// (and optional padding byte) in the directory record.
    pub fn parse(system_use: &[u8]) -> Self {
        let mut attrs = Self::empty();
        let mut pos = 0;

        while pos + 4 <= system_use.len() {
            let sig = [system_use[pos], system_use[pos + 1]];
            let entry_len = system_use[pos + 2] as usize;
            if entry_len < 4 || pos + entry_len > system_use.len() {
                break;
            }

            let entry_data = &system_use[pos..pos + entry_len];

            if sig == RR_SIGNATURE_PX && entry_len >= 36 {
                // PX entry: POSIX file attributes.
                attrs.mode = read_u32_lsb(&entry_data[4..8]);
                attrs.nlinks = read_u32_lsb(&entry_data[12..16]);
                attrs.uid = read_u32_lsb(&entry_data[20..24]);
                attrs.gid = read_u32_lsb(&entry_data[28..32]);
                if entry_len >= 44 {
                    attrs.ino = read_u32_lsb(&entry_data[36..40]);
                }
                attrs.present = true;
            } else if sig == RR_SIGNATURE_NM && entry_len > 5 {
                // NM entry: alternate (long) name.
                let name_data = &entry_data[5..];
                let copy_len = name_data.len().min(MAX_NAME_LEN - attrs.alt_name_len);
                attrs.alt_name[attrs.alt_name_len..attrs.alt_name_len + copy_len]
                    .copy_from_slice(&name_data[..copy_len]);
                attrs.alt_name_len += copy_len;
                attrs.present = true;
            } else if sig == RR_SIGNATURE_SL && entry_len > 5 {
                // SL entry: symbolic link target components.
                let mut sl_pos = 5;
                while sl_pos + 2 <= entry_len {
                    let _flags = entry_data[sl_pos];
                    let comp_len = entry_data[sl_pos + 1] as usize;
                    sl_pos += 2;
                    if sl_pos + comp_len > entry_len {
                        break;
                    }
                    if attrs.symlink_len > 0 && attrs.symlink_len < MAX_NAME_LEN {
                        attrs.symlink_target[attrs.symlink_len] = b'/';
                        attrs.symlink_len += 1;
                    }
                    let copy_len = comp_len.min(MAX_NAME_LEN - attrs.symlink_len);
                    attrs.symlink_target[attrs.symlink_len..attrs.symlink_len + copy_len]
                        .copy_from_slice(&entry_data[sl_pos..sl_pos + copy_len]);
                    attrs.symlink_len += copy_len;
                    sl_pos += comp_len;
                }
                attrs.present = true;
            }

            pos += entry_len;
        }

        attrs
    }

    /// Returns the alternate name if present, otherwise `None`.
    pub fn alt_name(&self) -> Option<&[u8]> {
        if self.alt_name_len > 0 {
            Some(&self.alt_name[..self.alt_name_len])
        } else {
            None
        }
    }

    /// Returns the symlink target if present, otherwise `None`.
    pub fn symlink_target(&self) -> Option<&[u8]> {
        if self.symlink_len > 0 {
            Some(&self.symlink_target[..self.symlink_len])
        } else {
            None
        }
    }
}

// ── JolietName ───────────────────────────────────────────────────

/// Decoded Joliet UCS-2 filename.
///
/// Joliet stores filenames as big-endian UCS-2 code units. This
/// structure holds a decoded ASCII approximation (characters outside
/// the Basic Latin block are replaced with `_`).
#[derive(Debug, Clone, Copy)]
pub struct JolietName {
    /// Decoded name bytes (ASCII approximation of UCS-2).
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub len: usize,
}

impl JolietName {
    /// Creates an empty Joliet name.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            len: 0,
        }
    }

    /// Decode a Joliet UCS-2 name from raw big-endian byte pairs.
    ///
    /// Non-ASCII code points are replaced with `_`. Strips the
    /// trailing `;1` version suffix if present.
    pub fn decode(ucs2_data: &[u8]) -> Self {
        let mut result = Self::empty();
        let pair_count = ucs2_data.len() / 2;

        for i in 0..pair_count {
            if result.len >= MAX_NAME_LEN {
                break;
            }
            let hi = ucs2_data[i * 2];
            let lo = ucs2_data[i * 2 + 1];
            if hi == 0 && lo >= 0x20 && lo < 0x7F {
                result.name[result.len] = lo;
            } else {
                result.name[result.len] = b'_';
            }
            result.len += 1;
        }

        // Strip trailing ";1" version suffix.
        if result.len >= 2
            && result.name[result.len - 2] == b';'
            && result.name[result.len - 1] == b'1'
        {
            result.len -= 2;
        }

        result
    }

    /// Returns the decoded name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

// ── Iso9660Fs ────────────────────────────────────────────────────

/// Mounted ISO 9660 filesystem handle.
///
/// Provides read-only access to files and directories on an ISO 9660
/// image. Parses the PVD at mount time and optionally detects Joliet
/// supplementary volume descriptors.
pub struct Iso9660Fs<'a> {
    /// Parsed primary volume descriptor.
    pub pvd: PrimaryVolumeDescriptor,
    /// Whether a Joliet SVD was detected.
    pub has_joliet: bool,
    /// Sector of the Joliet supplementary volume descriptor.
    pub joliet_svd_sector: u32,
    /// Joliet root directory extent location.
    pub joliet_root_extent: u32,
    /// Joliet root directory data length.
    pub joliet_root_size: u32,
    /// Raw image data.
    data: &'a [u8],
    /// Path table entries (parsed at mount time).
    path_table: [PathTableEntry; MAX_PATH_TABLE_ENTRIES],
    /// Number of valid path table entries.
    path_table_count: usize,
}

impl<'a> Iso9660Fs<'a> {
    /// Mount an ISO 9660 filesystem from raw image bytes.
    ///
    /// Parses the primary volume descriptor, scans for Joliet SVD,
    /// and loads the L-path table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the image is too small
    /// or does not contain a valid PVD.
    pub fn mount(data: &'a [u8]) -> Result<Self> {
        let pvd_offset = PVD_SECTOR * SECTOR_SIZE;
        if data.len() < pvd_offset + SECTOR_SIZE {
            return Err(Error::InvalidArgument);
        }

        let pvd = PrimaryVolumeDescriptor::parse(&data[pvd_offset..])?;

        let mut fs = Self {
            pvd,
            has_joliet: false,
            joliet_svd_sector: 0,
            joliet_root_extent: 0,
            joliet_root_size: 0,
            data,
            path_table: [PathTableEntry::empty(); MAX_PATH_TABLE_ENTRIES],
            path_table_count: 0,
        };

        fs.scan_supplementary_vds()?;
        fs.load_path_table()?;

        Ok(fs)
    }

    /// Scan volume descriptors after the PVD for Joliet SVD.
    fn scan_supplementary_vds(&mut self) -> Result<()> {
        let mut sector = PVD_SECTOR + 1;

        loop {
            let offset = sector * SECTOR_SIZE;
            if offset + SECTOR_SIZE > self.data.len() {
                break;
            }

            let vd_type = self.data[offset];
            if vd_type == VD_TYPE_TERMINATOR {
                break;
            }

            if self.data[offset + 1..offset + 6] != ISO_STANDARD_ID {
                sector += 1;
                continue;
            }

            if vd_type == VD_TYPE_SUPPLEMENTARY {
                let esc_area = &self.data[offset + 88..offset + 120];
                if contains_joliet_escape(esc_area) {
                    self.has_joliet = true;
                    self.joliet_svd_sector = sector as u32;
                    self.joliet_root_extent = read_u32_lsb(&self.data[offset + 158..offset + 162]);
                    self.joliet_root_size = read_u32_lsb(&self.data[offset + 166..offset + 170]);
                }
            }

            sector += 1;
        }

        Ok(())
    }

    /// Load the L-path table from the location in the PVD.
    fn load_path_table(&mut self) -> Result<()> {
        let pt_lba = self.pvd.path_table_l_location as usize;
        let pt_size = self.pvd.path_table_size as usize;
        let pt_offset = pt_lba * SECTOR_SIZE;

        if pt_offset + pt_size > self.data.len() {
            return Ok(());
        }

        let pt_data = &self.data[pt_offset..pt_offset + pt_size];
        let mut pos = 0;

        while pos < pt_size && self.path_table_count < MAX_PATH_TABLE_ENTRIES {
            if pos + 8 > pt_size {
                break;
            }
            match PathTableEntry::parse(&pt_data[pos..]) {
                Ok((entry, consumed)) => {
                    self.path_table[self.path_table_count] = entry;
                    self.path_table_count += 1;
                    pos += consumed;
                }
                Err(_) => break,
            }
        }

        Ok(())
    }

    /// Read directory entries at the given extent location and size.
    ///
    /// Returns a fixed-size array and the number of valid entries.
    pub fn readdir(
        &self,
        extent_lba: u32,
        extent_size: u32,
    ) -> Result<([DirectoryRecord; MAX_DIR_ENTRIES], usize)> {
        let offset = extent_lba as usize * SECTOR_SIZE;
        let size = extent_size as usize;
        if offset + size > self.data.len() {
            return Err(Error::IoError);
        }

        let dir_data = &self.data[offset..offset + size];
        let mut entries = [DirectoryRecord::empty(); MAX_DIR_ENTRIES];
        let mut count = 0;
        let mut pos = 0;

        while pos < size && count < MAX_DIR_ENTRIES {
            if dir_data[pos] == 0 {
                let next_sector = ((pos / SECTOR_SIZE) + 1) * SECTOR_SIZE;
                if next_sector > size {
                    break;
                }
                pos = next_sector;
                continue;
            }

            match DirectoryRecord::parse(&dir_data[pos..]) {
                Ok(Some(record)) => {
                    let rlen = record.record_len as usize;
                    entries[count] = record;
                    count += 1;
                    pos += rlen;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        Ok((entries, count))
    }

    /// Read the root directory entries.
    pub fn readdir_root(&self) -> Result<([DirectoryRecord; MAX_DIR_ENTRIES], usize)> {
        self.readdir(self.pvd.root_dir_extent, self.pvd.root_dir_size)
    }

    /// Read file data from a directory record into `buf`.
    ///
    /// Copies up to `buf.len()` bytes from offset `file_offset` within
    /// the file's extent. Returns the number of bytes copied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the extent is beyond the image.
    /// Returns [`Error::InvalidArgument`] if the record is a directory.
    pub fn read_file(
        &self,
        record: &DirectoryRecord,
        file_offset: usize,
        buf: &mut [u8],
    ) -> Result<usize> {
        if record.is_directory() {
            return Err(Error::InvalidArgument);
        }

        let extent_start = record.extent_location as usize * SECTOR_SIZE;
        let file_size = record.data_length as usize;

        if extent_start + file_size > self.data.len() {
            return Err(Error::IoError);
        }

        if file_offset >= file_size {
            return Ok(0);
        }

        let available = file_size - file_offset;
        let to_copy = buf.len().min(available);
        let src_start = extent_start + file_offset;

        buf[..to_copy].copy_from_slice(&self.data[src_start..src_start + to_copy]);
        Ok(to_copy)
    }

    /// Extract Rock Ridge attributes from raw directory extent bytes
    /// for a specific record.
    ///
    /// `dir_extent_data` is the raw bytes of the directory extent
    /// containing the record, and `record_offset` is the byte offset
    /// of the record within that extent.
    pub fn parse_rock_ridge(
        &self,
        dir_extent_data: &[u8],
        record_offset: usize,
        record: &DirectoryRecord,
    ) -> RockRidgeAttrs {
        let su_off = record.system_use_offset();
        let su_len = record.system_use_len();
        if su_len == 0 {
            return RockRidgeAttrs::empty();
        }
        let abs_off = record_offset + su_off;
        if abs_off + su_len > dir_extent_data.len() {
            return RockRidgeAttrs::empty();
        }
        RockRidgeAttrs::parse(&dir_extent_data[abs_off..abs_off + su_len])
    }

    /// Decode a Joliet filename from a directory record.
    pub fn decode_joliet_name(&self, record: &DirectoryRecord) -> JolietName {
        JolietName::decode(&record.name[..record.name_actual_len])
    }

    /// Look up a path table entry by index (0-based).
    pub fn path_table_entry(&self, index: usize) -> Option<&PathTableEntry> {
        if index < self.path_table_count {
            Some(&self.path_table[index])
        } else {
            None
        }
    }

    /// Returns the total number of path table entries.
    pub fn path_table_count(&self) -> usize {
        self.path_table_count
    }

    /// Returns a reference to the raw image data.
    pub fn image(&self) -> &[u8] {
        self.data
    }

    /// Unmount the filesystem (releases the image reference).
    pub fn unmount(self) {
        // Drop self — the image borrow is released.
    }
}

impl core::fmt::Debug for Iso9660Fs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Iso9660Fs")
            .field("volume_space_size", &self.pvd.volume_space_size)
            .field("logical_block_size", &self.pvd.logical_block_size)
            .field("has_joliet", &self.has_joliet)
            .field("path_table_count", &self.path_table_count)
            .finish()
    }
}

// ── Helper functions ─────────────────────────────────────────────

/// Read a little-endian u16 from a 2-byte slice.
fn read_u16_lsb(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

/// Read a little-endian u32 from a 4-byte slice.
fn read_u32_lsb(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Check whether the escape sequence area contains a Joliet marker.
fn contains_joliet_escape(esc_area: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 <= esc_area.len() {
        if esc_area[i] == JOLIET_ESCAPE_UCS2_L3[0]
            && esc_area[i + 1] == JOLIET_ESCAPE_UCS2_L3[1]
            && esc_area[i + 2] == JOLIET_ESCAPE_UCS2_L3[2]
        {
            return true;
        }
        i += 1;
    }
    false
}
