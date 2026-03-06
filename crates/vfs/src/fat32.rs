// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-only FAT32 filesystem driver.
//!
//! Parses FAT32 on-disk structures and provides read-only access to
//! files and directories. This is a minimal implementation supporting:
//! - BIOS Parameter Block (BPB) and FSInfo parsing
//! - FAT table traversal (cluster chains)
//! - 8.3 short name directory entries
//! - VFAT long file name (LFN) entries
//! - File data reading via cluster chains
//! - Path resolution through the directory tree
//!
//! The driver operates on a sector-level [`BlockReader`] trait
//! (reused from [`crate::ext2`]), allowing it to work with any
//! underlying storage (virtio-blk, ramdisk, etc.).
//!
//! Reference: Microsoft FAT32 File System Specification (2000-12-06);
//! `.kernelORG/` — `filesystems/fat.rst`.

use crate::ext2::BlockReader;
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// FAT32 on-disk constants
// -------------------------------------------------------------------

/// FAT32 boot sector signature at offset 510.
const BOOT_SIGNATURE: u16 = 0xAA55;

/// FSInfo sector lead signature.
const FSINFO_LEAD_SIG: u32 = 0x4161_5252;

/// FSInfo struct signature (at offset 484).
const FSINFO_STRUC_SIG: u32 = 0x6141_7272;

/// FSInfo trail signature (at offset 508).
const FSINFO_TRAIL_SIG: u32 = 0xAA55_0000;

/// Mask for the 28-bit cluster number in a FAT entry.
const FAT_ENTRY_MASK: u32 = 0x0FFF_FFFF;

/// Cluster values at or above this mark an end-of-chain.
const EOC_MIN: u32 = 0x0FFF_FFF8;

/// Bad cluster marker.
const BAD_CLUSTER: u32 = 0x0FFF_FFF7;

/// First valid data cluster number.
const FIRST_DATA_CLUSTER: u32 = 2;

/// Directory entry size in bytes.
const DIR_ENTRY_SIZE: usize = 32;

/// Maximum file name length (LFN, in bytes after UTF-8 conversion).
const MAX_NAME_LEN: usize = 255;

/// Maximum directory entries returned from a single readdir.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum cluster chain length we follow (prevents infinite loops).
const MAX_CHAIN_LEN: usize = 1 << 20; // ~1 million clusters

/// Directory entry attribute: read-only.
const ATTR_READ_ONLY: u8 = 0x01;

/// Directory entry attribute: hidden.
const ATTR_HIDDEN: u8 = 0x02;

/// Directory entry attribute: system.
const ATTR_SYSTEM: u8 = 0x04;

/// Directory entry attribute: volume label.
const ATTR_VOLUME_ID: u8 = 0x08;

/// Directory entry attribute: subdirectory.
const ATTR_DIRECTORY: u8 = 0x10;

/// Attribute mask indicating a long file name entry.
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// Marker byte for a deleted directory entry.
const DELETED_MARKER: u8 = 0xE5;

/// Marker byte indicating the first byte is actually 0xE5.
const KANJI_MARKER: u8 = 0x05;

/// LFN sequence number mask (lower 5 bits).
const LFN_SEQ_MASK: u8 = 0x1F;

/// LFN last logical entry flag (bit 6).
const LFN_LAST_LONG_ENTRY: u8 = 0x40;

/// Number of UCS-2 characters per LFN entry.
const LFN_CHARS_PER_ENTRY: usize = 13;

// -------------------------------------------------------------------
// BIOS Parameter Block (BPB)
// -------------------------------------------------------------------

/// FAT32 BIOS Parameter Block.
///
/// Parsed from the first sector (512 bytes) of the FAT32 volume.
/// Contains the geometry and layout parameters needed to locate
/// the FAT, root directory, and data region.
#[derive(Debug, Clone, Copy)]
pub struct Fat32Bpb {
    /// Bytes per logical sector (typically 512).
    pub bytes_per_sector: u16,
    /// Sectors per allocation cluster (power of 2).
    pub sectors_per_cluster: u8,
    /// Number of reserved sectors before the first FAT.
    pub reserved_sectors: u16,
    /// Number of FAT copies (usually 2).
    pub num_fats: u8,
    /// Total sectors on the volume (32-bit field for FAT32).
    pub total_sectors_32: u32,
    /// Sectors per FAT (FAT32 field).
    pub fat_size_32: u32,
    /// Root directory first cluster.
    pub root_cluster: u32,
    /// Sector number of the FSInfo structure.
    pub fs_info_sector: u16,
    /// Sector number of the backup boot sector.
    pub backup_boot_sector: u16,
}

impl Fat32Bpb {
    /// Parse a BPB from a 512-byte boot sector buffer.
    ///
    /// Validates the boot signature and basic sanity checks.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 512 {
            return Err(Error::InvalidArgument);
        }

        // Check boot signature at offset 510.
        let sig = read_u16(buf, 510);
        if sig != BOOT_SIGNATURE {
            return Err(Error::InvalidArgument);
        }

        let bytes_per_sector = read_u16(buf, 11);
        let sectors_per_cluster = buf[13];
        let reserved_sectors = read_u16(buf, 14);
        let num_fats = buf[16];

        // FAT32: root_entry_count at offset 17 must be 0.
        let root_entry_count = read_u16(buf, 17);
        if root_entry_count != 0 {
            return Err(Error::InvalidArgument);
        }

        // total_sectors_16 at offset 19 must be 0 for FAT32.
        let total_sectors_16 = read_u16(buf, 19);
        let total_sectors_32 = read_u32(buf, 32);
        if total_sectors_16 != 0 && total_sectors_32 == 0 {
            return Err(Error::InvalidArgument);
        }

        let fat_size_32 = read_u32(buf, 36);
        let root_cluster = read_u32(buf, 44);
        let fs_info_sector = read_u16(buf, 48);
        let backup_boot_sector = read_u16(buf, 50);

        // Sanity checks.
        if bytes_per_sector == 0
            || !bytes_per_sector.is_power_of_two()
            || sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || num_fats == 0
            || fat_size_32 == 0
            || root_cluster < FIRST_DATA_CLUSTER
        {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors_32,
            fat_size_32,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
        })
    }

    /// Bytes per cluster.
    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    /// First sector of the FAT region.
    pub fn fat_start_sector(&self) -> u32 {
        self.reserved_sectors as u32
    }

    /// First sector of the data region.
    pub fn data_start_sector(&self) -> u32 {
        self.reserved_sectors as u32 + self.num_fats as u32 * self.fat_size_32
    }

    /// Convert a cluster number to its first sector number.
    pub fn cluster_to_sector(&self, cluster: u32) -> Result<u32> {
        if cluster < FIRST_DATA_CLUSTER {
            return Err(Error::InvalidArgument);
        }
        let offset = cluster
            .checked_sub(FIRST_DATA_CLUSTER)
            .ok_or(Error::InvalidArgument)?;
        let sector_offset = offset
            .checked_mul(self.sectors_per_cluster as u32)
            .ok_or(Error::InvalidArgument)?;
        self.data_start_sector()
            .checked_add(sector_offset)
            .ok_or(Error::InvalidArgument)
    }
}

impl Default for Fat32Bpb {
    fn default() -> Self {
        Self {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            reserved_sectors: 32,
            num_fats: 2,
            total_sectors_32: 0,
            fat_size_32: 0,
            root_cluster: 2,
            fs_info_sector: 1,
            backup_boot_sector: 6,
        }
    }
}

// -------------------------------------------------------------------
// FSInfo sector
// -------------------------------------------------------------------

/// FAT32 FSInfo sector.
///
/// Contains hints about free cluster count and the next free cluster.
/// These values are advisory and may be stale.
#[derive(Debug, Clone, Copy)]
pub struct Fat32FsInfo {
    /// Number of free clusters (0xFFFFFFFF if unknown).
    pub free_count: u32,
    /// Next free cluster hint (0xFFFFFFFF if unknown).
    pub next_free: u32,
}

impl Fat32FsInfo {
    /// Parse an FSInfo structure from a 512-byte sector buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 512 {
            return Err(Error::InvalidArgument);
        }

        let lead_sig = read_u32(buf, 0);
        let struc_sig = read_u32(buf, 484);
        let trail_sig = read_u32(buf, 508);

        if lead_sig != FSINFO_LEAD_SIG
            || struc_sig != FSINFO_STRUC_SIG
            || trail_sig != FSINFO_TRAIL_SIG
        {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            free_count: read_u32(buf, 488),
            next_free: read_u32(buf, 492),
        })
    }
}

impl Default for Fat32FsInfo {
    fn default() -> Self {
        Self {
            free_count: 0xFFFF_FFFF,
            next_free: 0xFFFF_FFFF,
        }
    }
}

// -------------------------------------------------------------------
// FAT entry
// -------------------------------------------------------------------

/// Decoded FAT table entry.
///
/// Each entry in the FAT is a 32-bit value (only 28 bits used)
/// that describes the allocation status of a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatEntry {
    /// Cluster is free (value 0).
    Free,
    /// Cluster is in use; value is the next cluster in the chain.
    Used(u32),
    /// Last cluster in a chain (end-of-chain marker).
    EndOfChain,
    /// Bad cluster (defective sectors).
    Bad,
    /// Reserved value (1, or values in the reserved range).
    Reserved,
}

impl FatEntry {
    /// Decode a raw 32-bit FAT entry value.
    pub fn from_raw(raw: u32) -> Self {
        let val = raw & FAT_ENTRY_MASK;
        match val {
            0 => Self::Free,
            1 => Self::Reserved,
            v if v == BAD_CLUSTER => Self::Bad,
            v if v >= EOC_MIN => Self::EndOfChain,
            v if v >= FIRST_DATA_CLUSTER => Self::Used(v),
            _ => Self::Reserved,
        }
    }

    /// Return the next cluster if this entry is `Used`.
    pub fn next_cluster(&self) -> Option<u32> {
        match self {
            Self::Used(c) => Some(*c),
            _ => None,
        }
    }
}

// -------------------------------------------------------------------
// Directory entry (short name, 8.3)
// -------------------------------------------------------------------

/// FAT32 short-name (8.3) directory entry.
///
/// Represents the 32-byte on-disk structure for a standard
/// directory entry with an 8-character name and 3-character extension.
#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    /// File name (8 bytes, space-padded).
    pub name: [u8; 8],
    /// File extension (3 bytes, space-padded).
    pub ext: [u8; 3],
    /// File attributes.
    pub attrs: u8,
    /// Reserved for Windows NT (lowercase flags).
    pub nt_reserved: u8,
    /// Creation time, tenths of a second (0-199).
    pub create_time_tenth: u8,
    /// Creation time (hour/min/sec packed).
    pub create_time: u16,
    /// Creation date (year/month/day packed).
    pub create_date: u16,
    /// Last access date.
    pub last_access_date: u16,
    /// High 16 bits of first cluster number.
    pub first_cluster_hi: u16,
    /// Last modification time.
    pub modify_time: u16,
    /// Last modification date.
    pub modify_date: u16,
    /// Low 16 bits of first cluster number.
    pub first_cluster_lo: u16,
    /// File size in bytes.
    pub file_size: u32,
}

impl DirEntry {
    /// Parse a directory entry from a 32-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < DIR_ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&buf[0..8]);
        let mut ext = [0u8; 3];
        ext.copy_from_slice(&buf[8..11]);

        Ok(Self {
            name,
            ext,
            attrs: buf[11],
            nt_reserved: buf[12],
            create_time_tenth: buf[13],
            create_time: read_u16(buf, 14),
            create_date: read_u16(buf, 16),
            last_access_date: read_u16(buf, 18),
            first_cluster_hi: read_u16(buf, 20),
            modify_time: read_u16(buf, 22),
            modify_date: read_u16(buf, 24),
            first_cluster_lo: read_u16(buf, 26),
            file_size: read_u32(buf, 28),
        })
    }

    /// Combined 32-bit first cluster number.
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | self.first_cluster_lo as u32
    }

    /// Whether this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.attrs & ATTR_DIRECTORY != 0
    }

    /// Whether this entry is a volume label.
    pub fn is_volume_id(&self) -> bool {
        self.attrs & ATTR_VOLUME_ID != 0
    }

    /// Whether this entry marks the end of the directory.
    pub fn is_end(&self) -> bool {
        self.name[0] == 0x00
    }

    /// Whether this entry has been deleted.
    pub fn is_deleted(&self) -> bool {
        self.name[0] == DELETED_MARKER
    }

    /// Whether this is a long file name entry.
    pub fn is_lfn(&self) -> bool {
        (self.attrs & ATTR_LONG_NAME) == ATTR_LONG_NAME
    }

    /// Extract the 8.3 short name as a byte array.
    ///
    /// Returns the number of valid bytes written to `out`.
    /// The name is formatted as `NAME.EXT` with trailing spaces
    /// trimmed. If the extension is empty, the dot is omitted.
    pub fn short_name(&self, out: &mut [u8; 13]) -> usize {
        let mut pos = 0usize;

        // Copy name portion, trimming trailing spaces.
        let mut name_end = 8;
        while name_end > 0 && self.name[name_end - 1] == b' ' {
            name_end -= 1;
        }
        for &b in &self.name[..name_end] {
            if pos < 13 {
                // Handle 0x05 -> 0xE5 Kanji substitution.
                out[pos] = if pos == 0 && b == KANJI_MARKER {
                    DELETED_MARKER
                } else {
                    b
                };
                pos += 1;
            }
        }

        // Copy extension, trimming trailing spaces.
        let mut ext_end = 3;
        while ext_end > 0 && self.ext[ext_end - 1] == b' ' {
            ext_end -= 1;
        }
        if ext_end > 0 {
            if pos < 13 {
                out[pos] = b'.';
                pos += 1;
            }
            for &b in &self.ext[..ext_end] {
                if pos < 13 {
                    out[pos] = b;
                    pos += 1;
                }
            }
        }

        pos
    }
}

// -------------------------------------------------------------------
// Long file name (LFN) entry
// -------------------------------------------------------------------

/// VFAT long file name directory entry.
///
/// Each LFN entry stores up to 13 UCS-2 characters of the long
/// name. Multiple LFN entries precede the corresponding short-name
/// entry in reverse order (highest sequence number first).
#[derive(Debug, Clone, Copy)]
pub struct LongFileName {
    /// Sequence number (1-based, bit 6 set on last entry).
    pub sequence: u8,
    /// First 5 UCS-2 characters.
    pub name1: [u16; 5],
    /// Attributes (always `ATTR_LONG_NAME`).
    pub attrs: u8,
    /// Checksum of the associated short name.
    pub checksum: u8,
    /// Next 6 UCS-2 characters.
    pub name2: [u16; 6],
    /// Last 2 UCS-2 characters.
    pub name3: [u16; 2],
}

impl LongFileName {
    /// Parse an LFN entry from a 32-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < DIR_ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }

        let sequence = buf[0];
        let attrs = buf[11];
        let checksum = buf[13];

        let mut name1 = [0u16; 5];
        for (i, ch) in name1.iter_mut().enumerate() {
            *ch = read_u16(buf, 1 + i * 2);
        }

        let mut name2 = [0u16; 6];
        for (i, ch) in name2.iter_mut().enumerate() {
            *ch = read_u16(buf, 14 + i * 2);
        }

        let mut name3 = [0u16; 2];
        for (i, ch) in name3.iter_mut().enumerate() {
            *ch = read_u16(buf, 28 + i * 2);
        }

        Ok(Self {
            sequence,
            name1,
            attrs,
            checksum,
            name2,
            name3,
        })
    }

    /// Sequence index (0-based, without flags).
    pub fn seq_index(&self) -> u8 {
        (self.sequence & LFN_SEQ_MASK).saturating_sub(1)
    }

    /// Whether this is the last (highest-numbered) LFN entry.
    pub fn is_last(&self) -> bool {
        self.sequence & LFN_LAST_LONG_ENTRY != 0
    }

    /// Extract the 13 UCS-2 characters from this entry into `out`.
    ///
    /// Returns the number of valid characters (stops at NUL or
    /// 0xFFFF padding).
    pub fn chars(&self, out: &mut [u16; LFN_CHARS_PER_ENTRY]) -> usize {
        let mut pos = 0usize;
        for &ch in &self.name1 {
            if ch == 0x0000 || ch == 0xFFFF {
                return pos;
            }
            out[pos] = ch;
            pos += 1;
        }
        for &ch in &self.name2 {
            if ch == 0x0000 || ch == 0xFFFF {
                return pos;
            }
            out[pos] = ch;
            pos += 1;
        }
        for &ch in &self.name3 {
            if ch == 0x0000 || ch == 0xFFFF {
                return pos;
            }
            out[pos] = ch;
            pos += 1;
        }
        pos
    }
}

// -------------------------------------------------------------------
// LFN assembler (stack-based, no alloc)
// -------------------------------------------------------------------

/// Maximum LFN entries per name (20 entries * 13 chars = 260 chars).
const MAX_LFN_ENTRIES: usize = 20;

/// Assembler for collecting LFN entries into a complete name.
struct LfnAssembler {
    /// UCS-2 buffer: `entries[i]` holds the chars for sequence i.
    entries: [[u16; LFN_CHARS_PER_ENTRY]; MAX_LFN_ENTRIES],
    /// Number of valid chars in each entry.
    lengths: [usize; MAX_LFN_ENTRIES],
    /// Expected checksum.
    checksum: u8,
    /// Total number of entries expected.
    total: usize,
    /// Number of entries collected so far.
    collected: usize,
}

impl LfnAssembler {
    fn new() -> Self {
        Self {
            entries: [[0u16; LFN_CHARS_PER_ENTRY]; MAX_LFN_ENTRIES],
            lengths: [0; MAX_LFN_ENTRIES],
            checksum: 0,
            total: 0,
            collected: 0,
        }
    }

    fn reset(&mut self) {
        self.total = 0;
        self.collected = 0;
    }

    /// Push an LFN entry. Returns `true` if it was accepted.
    fn push(&mut self, lfn: &LongFileName) -> bool {
        if lfn.is_last() {
            self.reset();
            let seq = (lfn.sequence & LFN_SEQ_MASK) as usize;
            if seq == 0 || seq > MAX_LFN_ENTRIES {
                return false;
            }
            self.total = seq;
            self.checksum = lfn.checksum;
            self.collected = 0;
        }

        if self.total == 0 {
            return false;
        }

        if lfn.checksum != self.checksum {
            self.reset();
            return false;
        }

        let idx = lfn.seq_index() as usize;
        if idx >= self.total || idx >= MAX_LFN_ENTRIES {
            self.reset();
            return false;
        }

        let mut chars = [0u16; LFN_CHARS_PER_ENTRY];
        let len = lfn.chars(&mut chars);
        self.entries[idx] = chars;
        self.lengths[idx] = len;
        self.collected += 1;
        true
    }

    /// Whether we have collected all expected LFN entries.
    fn is_complete(&self) -> bool {
        self.total > 0 && self.collected == self.total
    }

    /// Assemble the complete long name into a UTF-8 byte buffer.
    ///
    /// Returns the number of bytes written.
    fn assemble(&self, out: &mut [u8; MAX_NAME_LEN]) -> usize {
        let mut pos = 0usize;
        for i in 0..self.total {
            for j in 0..self.lengths[i] {
                let ch = self.entries[i][j];
                // Simple UCS-2 to UTF-8 conversion.
                if ch < 0x80 {
                    if pos < MAX_NAME_LEN {
                        out[pos] = ch as u8;
                        pos += 1;
                    }
                } else if ch < 0x800 {
                    if pos + 1 < MAX_NAME_LEN {
                        out[pos] = 0xC0 | ((ch >> 6) as u8);
                        out[pos + 1] = 0x80 | ((ch & 0x3F) as u8);
                        pos += 2;
                    }
                } else if pos + 2 < MAX_NAME_LEN {
                    out[pos] = 0xE0 | ((ch >> 12) as u8);
                    out[pos + 1] = 0x80 | (((ch >> 6) & 0x3F) as u8);
                    out[pos + 2] = 0x80 | ((ch & 0x3F) as u8);
                    pos += 3;
                }
            }
        }
        pos
    }

    /// Verify the LFN checksum against an 8.3 short name.
    fn verify_checksum(&self, short_name: &[u8; 11]) -> bool {
        let mut sum = 0u8;
        for &b in short_name {
            sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
        }
        sum == self.checksum
    }
}

// -------------------------------------------------------------------
// FAT32 resolved directory entry (combined short + long name)
// -------------------------------------------------------------------

/// A resolved directory entry with both short and long names.
#[derive(Debug, Clone)]
pub struct Fat32DirEntry {
    /// File name bytes (UTF-8, from LFN if available, else 8.3).
    pub name: [u8; MAX_NAME_LEN],
    /// Length of valid bytes in `name`.
    pub name_len: usize,
    /// File attributes.
    pub attrs: u8,
    /// First cluster number.
    pub first_cluster: u32,
    /// File size in bytes (0 for directories).
    pub file_size: u32,
    /// Creation date (FAT packed format).
    pub create_date: u16,
    /// Creation time (FAT packed format).
    pub create_time: u16,
    /// Last modification date.
    pub modify_date: u16,
    /// Last modification time.
    pub modify_time: u16,
}

impl Fat32DirEntry {
    /// File name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Whether this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.attrs & ATTR_DIRECTORY != 0
    }
}

/// Collection of FAT32 directory entries.
pub struct Fat32DirEntries {
    /// Directory entries.
    pub entries: [Option<Fat32DirEntry>; MAX_DIR_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl Fat32DirEntries {
    fn new() -> Self {
        const NONE: Option<Fat32DirEntry> = None;
        Self {
            entries: [NONE; MAX_DIR_ENTRIES],
            count: 0,
        }
    }

    fn push(&mut self, entry: Fat32DirEntry) -> Result<()> {
        if self.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }
}

// -------------------------------------------------------------------
// Fat32Dir — directory iterator
// -------------------------------------------------------------------

/// Directory reader for FAT32.
///
/// Iterates over the raw 32-byte entries in a directory's cluster
/// chain, assembling LFN sequences and yielding resolved entries.
pub struct Fat32Dir {
    /// First cluster of this directory.
    first_cluster: u32,
}

impl Fat32Dir {
    /// Create a directory reader for the given starting cluster.
    pub fn new(first_cluster: u32) -> Self {
        Self { first_cluster }
    }

    /// Read all entries from this directory.
    ///
    /// Skips deleted entries, volume labels, and properly combines
    /// LFN entries with their corresponding short-name entry.
    pub fn read_entries<R: BlockReader>(&self, fs: &Fat32Fs<R>) -> Result<Fat32DirEntries> {
        let mut result = Fat32DirEntries::new();
        let mut lfn = LfnAssembler::new();
        let cluster_size = fs.bpb.cluster_size() as usize;

        // Follow the cluster chain for this directory.
        let mut cluster = self.first_cluster;
        let mut chain_len = 0usize;

        loop {
            if cluster < FIRST_DATA_CLUSTER {
                break;
            }
            if chain_len >= MAX_CHAIN_LEN {
                return Err(Error::IoError);
            }
            chain_len += 1;

            // Read the entire cluster.
            let sector = fs.bpb.cluster_to_sector(cluster)?;
            let byte_offset = sector as u64 * fs.bpb.bytes_per_sector as u64;

            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
            let mut entry_buf = [0u8; DIR_ENTRY_SIZE];

            for i in 0..entries_per_cluster {
                let off = byte_offset + (i * DIR_ENTRY_SIZE) as u64;
                fs.reader.read_bytes(off, &mut entry_buf)?;

                // End-of-directory marker.
                if entry_buf[0] == 0x00 {
                    return Ok(result);
                }

                // Deleted entry.
                if entry_buf[0] == DELETED_MARKER {
                    lfn.reset();
                    continue;
                }

                // Check if LFN entry.
                let attrs = entry_buf[11];
                if (attrs & ATTR_LONG_NAME) == ATTR_LONG_NAME {
                    let lfn_entry = LongFileName::from_bytes(&entry_buf)?;
                    lfn.push(&lfn_entry);
                    continue;
                }

                // Short name entry.
                let de = DirEntry::from_bytes(&entry_buf)?;

                // Skip volume labels.
                if de.is_volume_id() {
                    lfn.reset();
                    continue;
                }

                // Build resolved entry.
                let mut resolved = Fat32DirEntry {
                    name: [0u8; MAX_NAME_LEN],
                    name_len: 0,
                    attrs: de.attrs,
                    first_cluster: de.first_cluster(),
                    file_size: de.file_size,
                    create_date: de.create_date,
                    create_time: de.create_time,
                    modify_date: de.modify_date,
                    modify_time: de.modify_time,
                };

                // Use LFN if complete and checksum matches.
                let mut short_11 = [0u8; 11];
                short_11[..8].copy_from_slice(&de.name);
                short_11[8..11].copy_from_slice(&de.ext);

                if lfn.is_complete() && lfn.verify_checksum(&short_11) {
                    resolved.name_len = lfn.assemble(&mut resolved.name);
                } else {
                    let mut sn = [0u8; 13];
                    let sn_len = de.short_name(&mut sn);
                    resolved.name[..sn_len].copy_from_slice(&sn[..sn_len]);
                    resolved.name_len = sn_len;
                }

                lfn.reset();

                // Ignore push errors (directory full).
                let _ = result.push(resolved);
            }

            // Follow to next cluster.
            match fs.read_fat_entry(cluster)? {
                FatEntry::Used(next) => cluster = next,
                FatEntry::EndOfChain => break,
                _ => break,
            }
        }

        Ok(result)
    }
}

impl Default for Fat32Dir {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// Fat32Fs — filesystem state
// -------------------------------------------------------------------

/// Read-only FAT32 filesystem.
///
/// Operates over a [`BlockReader`] to access the underlying block
/// device. All operations are read-only; write support is not
/// implemented.
pub struct Fat32Fs<R: BlockReader> {
    /// Block reader (storage backend).
    reader: R,
    /// Parsed BIOS Parameter Block.
    bpb: Fat32Bpb,
    /// Parsed FSInfo (may be default if parsing fails).
    fs_info: Fat32FsInfo,
}

impl<R: BlockReader> Fat32Fs<R> {
    /// Mount a FAT32 filesystem from the given block reader.
    ///
    /// Reads and validates the BPB and optionally the FSInfo sector.
    pub fn mount(reader: R) -> Result<Self> {
        // Read the first sector (boot sector / BPB).
        let mut boot_buf = [0u8; 512];
        reader.read_bytes(0, &mut boot_buf)?;
        let bpb = Fat32Bpb::from_bytes(&boot_buf)?;

        // Read FSInfo sector (best-effort).
        let fs_info = if bpb.fs_info_sector > 0 {
            let fs_info_offset = bpb.fs_info_sector as u64 * bpb.bytes_per_sector as u64;
            let mut fi_buf = [0u8; 512];
            if reader.read_bytes(fs_info_offset, &mut fi_buf).is_ok() {
                Fat32FsInfo::from_bytes(&fi_buf).unwrap_or_default()
            } else {
                Fat32FsInfo::default()
            }
        } else {
            Fat32FsInfo::default()
        };

        Ok(Self {
            reader,
            bpb,
            fs_info,
        })
    }

    /// Return the parsed BPB.
    pub fn bpb(&self) -> &Fat32Bpb {
        &self.bpb
    }

    /// Return the parsed FSInfo.
    pub fn fs_info(&self) -> &Fat32FsInfo {
        &self.fs_info
    }

    /// Cluster size in bytes.
    pub fn cluster_size(&self) -> u32 {
        self.bpb.cluster_size()
    }

    /// Read the raw data of a cluster into `buf`.
    ///
    /// `buf` must be at least `cluster_size()` bytes.
    pub fn read_cluster(&self, cluster: u32, buf: &mut [u8]) -> Result<()> {
        let cs = self.cluster_size() as usize;
        if buf.len() < cs {
            return Err(Error::InvalidArgument);
        }
        let sector = self.bpb.cluster_to_sector(cluster)?;
        let offset = sector as u64 * self.bpb.bytes_per_sector as u64;
        self.reader.read_bytes(offset, &mut buf[..cs])
    }

    /// Read a FAT entry for the given cluster.
    pub fn read_fat_entry(&self, cluster: u32) -> Result<FatEntry> {
        let fat_offset = cluster as u64 * 4;
        let fat_sector_offset =
            self.bpb.fat_start_sector() as u64 * self.bpb.bytes_per_sector as u64;
        let byte_offset = fat_sector_offset + fat_offset;

        let mut buf = [0u8; 4];
        self.reader.read_bytes(byte_offset, &mut buf)?;
        let raw = u32::from_le_bytes(buf);
        Ok(FatEntry::from_raw(raw))
    }

    /// Follow the cluster chain starting at `start`, collecting
    /// cluster numbers into `chain`.
    ///
    /// Returns the number of clusters in the chain.
    pub fn follow_chain(&self, start: u32, chain: &mut [u32]) -> Result<usize> {
        if start < FIRST_DATA_CLUSTER {
            return Err(Error::InvalidArgument);
        }
        let mut cluster = start;
        let mut count = 0usize;

        loop {
            if count >= chain.len() {
                return Err(Error::OutOfMemory);
            }
            if count >= MAX_CHAIN_LEN {
                return Err(Error::IoError);
            }
            chain[count] = cluster;
            count += 1;

            match self.read_fat_entry(cluster)? {
                FatEntry::Used(next) => cluster = next,
                FatEntry::EndOfChain => break,
                FatEntry::Bad => {
                    return Err(Error::IoError);
                }
                _ => break,
            }
        }

        Ok(count)
    }

    /// Read directory entries from the root directory.
    pub fn read_root_dir(&self) -> Result<Fat32DirEntries> {
        let dir = Fat32Dir::new(self.bpb.root_cluster);
        dir.read_entries(self)
    }

    /// Look up a single name component in a directory.
    ///
    /// Returns the matching directory entry if found.
    fn lookup_in_dir(&self, dir_cluster: u32, name: &[u8]) -> Result<Fat32DirEntry> {
        let dir = Fat32Dir::new(dir_cluster);
        let entries = dir.read_entries(self)?;

        for entry in entries.entries[..entries.count].iter().flatten() {
            if name_eq_ci(entry.name(), name) {
                return Ok(entry.clone());
            }
        }

        Err(Error::NotFound)
    }
}

impl<R: BlockReader> core::fmt::Debug for Fat32Fs<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fat32Fs")
            .field("bytes_per_sector", &self.bpb.bytes_per_sector)
            .field("sectors_per_cluster", &self.bpb.sectors_per_cluster)
            .field("root_cluster", &self.bpb.root_cluster)
            .field("fat_size_32", &self.bpb.fat_size_32)
            .finish()
    }
}

// -------------------------------------------------------------------
// File reading
// -------------------------------------------------------------------

/// Read file data following a FAT32 cluster chain.
///
/// Reads up to `buf.len()` bytes starting at byte `offset` within
/// the file whose data begins at `first_cluster`. Returns the
/// number of bytes actually read.
///
/// For directories, `file_size` should be `u32::MAX` since FAT32
/// directories do not store their size in the directory entry.
pub fn fat32_read_file<R: BlockReader>(
    fs: &Fat32Fs<R>,
    first_cluster: u32,
    offset: u64,
    buf: &mut [u8],
    file_size: u32,
) -> Result<usize> {
    if first_cluster < FIRST_DATA_CLUSTER {
        return Ok(0);
    }
    if offset >= file_size as u64 {
        return Ok(0);
    }

    let available = (file_size as u64 - offset) as usize;
    let to_read = buf.len().min(available);
    if to_read == 0 {
        return Ok(0);
    }

    let cs = fs.cluster_size() as u64;
    // Which cluster in the chain to start from.
    let start_cluster_idx = offset / cs;
    let mut byte_in_cluster = (offset % cs) as usize;

    // Walk the chain to find the starting cluster.
    let mut cluster = first_cluster;
    let mut idx = 0u64;
    while idx < start_cluster_idx {
        match fs.read_fat_entry(cluster)? {
            FatEntry::Used(next) => cluster = next,
            FatEntry::EndOfChain => return Ok(0),
            FatEntry::Bad => return Err(Error::IoError),
            _ => return Ok(0),
        }
        idx += 1;
        if idx > MAX_CHAIN_LEN as u64 {
            return Err(Error::IoError);
        }
    }

    // Read data cluster by cluster.
    let mut bytes_read = 0usize;
    loop {
        if bytes_read >= to_read {
            break;
        }
        if cluster < FIRST_DATA_CLUSTER {
            break;
        }

        let chunk_size = (cs as usize - byte_in_cluster).min(to_read - bytes_read);
        let sector = fs.bpb.cluster_to_sector(cluster)?;
        let disk_offset = sector as u64 * fs.bpb.bytes_per_sector as u64 + byte_in_cluster as u64;

        fs.reader
            .read_bytes(disk_offset, &mut buf[bytes_read..bytes_read + chunk_size])?;

        bytes_read += chunk_size;
        byte_in_cluster = 0; // subsequent clusters read from start

        // Advance to next cluster.
        if bytes_read < to_read {
            match fs.read_fat_entry(cluster)? {
                FatEntry::Used(next) => cluster = next,
                FatEntry::EndOfChain => break,
                FatEntry::Bad => return Err(Error::IoError),
                _ => break,
            }
        }
    }

    Ok(bytes_read)
}

// -------------------------------------------------------------------
// Path resolution
// -------------------------------------------------------------------

/// Resolve a path through the FAT32 directory tree.
///
/// Path components are separated by `/`. Leading `/` is optional.
/// Returns the directory entry for the final component. Uses
/// case-insensitive comparison as per FAT32 semantics.
pub fn fat32_lookup<R: BlockReader>(fs: &Fat32Fs<R>, path: &[u8]) -> Result<Fat32DirEntry> {
    let mut current_cluster = fs.bpb.root_cluster;
    let mut current_entry: Option<Fat32DirEntry> = None;

    let components = PathComponents::new(path);
    let mut found_any = false;

    for component in components {
        if component.is_empty() {
            continue;
        }
        found_any = true;
        let entry = fs.lookup_in_dir(current_cluster, component)?;
        current_cluster = entry.first_cluster;
        current_entry = Some(entry);
    }

    if !found_any {
        // Root directory requested — synthesize an entry.
        return Ok(Fat32DirEntry {
            name: {
                let mut n = [0u8; MAX_NAME_LEN];
                n[0] = b'/';
                n
            },
            name_len: 1,
            attrs: ATTR_DIRECTORY,
            first_cluster: fs.bpb.root_cluster,
            file_size: 0,
            create_date: 0,
            create_time: 0,
            modify_date: 0,
            modify_time: 0,
        });
    }

    current_entry.ok_or(Error::NotFound)
}

// -------------------------------------------------------------------
// Case-insensitive name comparison
// -------------------------------------------------------------------

/// Compare two byte slices case-insensitively (ASCII only).
fn name_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (&x, &y) in a.iter().zip(b.iter()) {
        if !x.eq_ignore_ascii_case(&y) {
            return false;
        }
    }
    true
}

// -------------------------------------------------------------------
// Path component iterator
// -------------------------------------------------------------------

/// Simple path component iterator (splits on `/`).
struct PathComponents<'a> {
    remaining: &'a [u8],
}

impl<'a> PathComponents<'a> {
    fn new(path: &'a [u8]) -> Self {
        Self { remaining: path }
    }
}

impl<'a> Iterator for PathComponents<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Skip leading slashes.
        while self.remaining.first() == Some(&b'/') {
            self.remaining = &self.remaining[1..];
        }
        if self.remaining.is_empty() {
            return None;
        }
        // Find next slash or end.
        let end = self
            .remaining
            .iter()
            .position(|&b| b == b'/')
            .unwrap_or(self.remaining.len());
        let component = &self.remaining[..end];
        self.remaining = &self.remaining[end..];
        Some(component)
    }
}

// -------------------------------------------------------------------
// Little-endian helpers
// -------------------------------------------------------------------

/// Read a little-endian u16 from `buf` at `offset`.
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read a little-endian u32 from `buf` at `offset`.
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}
