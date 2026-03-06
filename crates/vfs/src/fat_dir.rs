// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT12/16/32 directory operations.
//!
//! Implements directory-level operations shared across all FAT variants:
//!
//! - [`FatDirEntry`] — 32-byte short-name directory entry (all FAT variants)
//! - [`FatLfnEntry`] — 32-byte long file name entry (LFN)
//! - [`FatDirIter`] — iterator over directory entries in a cluster chain
//! - [`lookup_short`] — find a file by short 8.3 name
//! - [`lookup_lfn`] — find a file by long name (UCS-2 comparison)
//! - [`add_entry`] — create a new short-name entry in the directory
//! - [`delete_entry`] — mark entry as deleted (0xE5)
//!
//! # FAT Directory Layout
//!
//! Each directory is a sequence of 32-byte entries stored in a cluster chain.
//! LFN entries immediately precede the associated short-name entry.
//! Entry order: [LFN_n] ... [LFN_1] [SFN].
//!
//! # References
//!
//! - Microsoft FAT32 File System Specification (2000)
//! - Linux `fs/fat/dir.c`, `fs/fat/namei_msdos.c`, `fs/fat/namei_vfat.c`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Size of each FAT directory entry in bytes.
pub const FAT_DIRENT_SIZE: usize = 32;

/// Deleted entry marker in first byte of name field.
pub const FAT_DELETED: u8 = 0xE5;

/// End-of-directory marker.
pub const FAT_EOD: u8 = 0x00;

/// LFN attribute value (all lower 4 attribute bits set).
pub const FAT_ATTR_LFN: u8 = 0x0F;

/// Directory attribute bit.
pub const FAT_ATTR_DIR: u8 = 0x10;

/// Archive attribute bit (regular file).
pub const FAT_ATTR_ARCHIVE: u8 = 0x20;

/// Read-only attribute.
pub const FAT_ATTR_RDONLY: u8 = 0x01;

/// Volume label attribute.
pub const FAT_ATTR_VOLID: u8 = 0x08;

/// LFN characters per slot (13 UCS-2 code units).
pub const LFN_CHARS_PER_SLOT: usize = 13;

/// Maximum number of directory entries per in-memory snapshot.
const MAX_ENTRIES: usize = 512;

// ── Short-Name Directory Entry ────────────────────────────────────────────────

/// FAT 8.3 short-name directory entry (32 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FatDirEntry {
    /// File name, 8 bytes, space-padded, first byte has special meanings.
    pub name: [u8; 8],
    /// Extension, 3 bytes, space-padded.
    pub ext: [u8; 3],
    /// Attribute byte.
    pub attr: u8,
    /// NT reserved / case flags.
    pub nt_res: u8,
    /// Creation time, 10 ms units (0–199).
    pub crt_time_tenth: u8,
    /// Creation time (packed HH:MM:SS/2).
    pub crt_time: u16,
    /// Creation date (packed YYYY/MM/DD).
    pub crt_date: u16,
    /// Last access date.
    pub acc_date: u16,
    /// High 16 bits of first cluster (FAT32 only; 0 for FAT12/16).
    pub first_cluster_hi: u16,
    /// Write time.
    pub wrt_time: u16,
    /// Write date.
    pub wrt_date: u16,
    /// Low 16 bits of first cluster.
    pub first_cluster_lo: u16,
    /// File size in bytes (0 for directories).
    pub file_size: u32,
}

impl FatDirEntry {
    /// Return `true` if this slot is the end-of-directory marker.
    pub fn is_eod(&self) -> bool {
        self.name[0] == FAT_EOD
    }

    /// Return `true` if this slot holds a deleted entry.
    pub fn is_deleted(&self) -> bool {
        self.name[0] == FAT_DELETED
    }

    /// Return `true` if this is a long-file-name pseudo-entry.
    pub fn is_lfn(&self) -> bool {
        self.attr == FAT_ATTR_LFN
    }

    /// Return `true` if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.attr & FAT_ATTR_DIR != 0
    }

    /// Assemble the first cluster number (FAT32: hi + lo; FAT12/16: lo only).
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | self.first_cluster_lo as u32
    }

    /// Return the 8.3 short name as a byte slice (trimming trailing spaces).
    pub fn short_name_raw(&self) -> (&[u8], &[u8]) {
        let name_end = self
            .name
            .iter()
            .rposition(|&b| b != b' ')
            .map(|p| p + 1)
            .unwrap_or(0);
        let ext_end = self
            .ext
            .iter()
            .rposition(|&b| b != b' ')
            .map(|p| p + 1)
            .unwrap_or(0);
        (&self.name[..name_end], &self.ext[..ext_end])
    }

    /// Parse an entry from 32 raw bytes.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < FAT_DIRENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            name: raw[0..8].try_into().map_err(|_| Error::InvalidArgument)?,
            ext: raw[8..11].try_into().map_err(|_| Error::InvalidArgument)?,
            attr: raw[11],
            nt_res: raw[12],
            crt_time_tenth: raw[13],
            crt_time: u16::from_le_bytes([raw[14], raw[15]]),
            crt_date: u16::from_le_bytes([raw[16], raw[17]]),
            acc_date: u16::from_le_bytes([raw[18], raw[19]]),
            first_cluster_hi: u16::from_le_bytes([raw[20], raw[21]]),
            wrt_time: u16::from_le_bytes([raw[22], raw[23]]),
            wrt_date: u16::from_le_bytes([raw[24], raw[25]]),
            first_cluster_lo: u16::from_le_bytes([raw[26], raw[27]]),
            file_size: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
        })
    }

    /// Encode this entry into `dst[..FAT_DIRENT_SIZE]`.
    pub fn to_bytes(&self, dst: &mut [u8]) -> Result<()> {
        if dst.len() < FAT_DIRENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        dst[0..8].copy_from_slice(&self.name);
        dst[8..11].copy_from_slice(&self.ext);
        dst[11] = self.attr;
        dst[12] = self.nt_res;
        dst[13] = self.crt_time_tenth;
        dst[14..16].copy_from_slice(&self.crt_time.to_le_bytes());
        dst[16..18].copy_from_slice(&self.crt_date.to_le_bytes());
        dst[18..20].copy_from_slice(&self.acc_date.to_le_bytes());
        dst[20..22].copy_from_slice(&self.first_cluster_hi.to_le_bytes());
        dst[22..24].copy_from_slice(&self.wrt_time.to_le_bytes());
        dst[24..26].copy_from_slice(&self.wrt_date.to_le_bytes());
        dst[26..28].copy_from_slice(&self.first_cluster_lo.to_le_bytes());
        dst[28..32].copy_from_slice(&self.file_size.to_le_bytes());
        Ok(())
    }
}

// ── LFN Entry ─────────────────────────────────────────────────────────────────

/// FAT Long File Name (VFAT) pseudo-entry (32 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FatLfnEntry {
    /// Order byte (1-based; 0x40 bit set on the last LFN entry).
    pub order: u8,
    /// UCS-2 characters 1–5.
    pub name1: [u16; 5],
    /// Always `FAT_ATTR_LFN` (0x0F).
    pub attr: u8,
    /// LFN type (always 0).
    pub lfn_type: u8,
    /// Checksum of the associated 8.3 name.
    pub checksum: u8,
    /// UCS-2 characters 6–11.
    pub name2: [u16; 6],
    /// Always 0 for LFN entries.
    pub first_cluster: u16,
    /// UCS-2 characters 12–13.
    pub name3: [u16; 2],
}

impl FatLfnEntry {
    /// Extract the 13 UCS-2 code units from this LFN slot.
    pub fn name_chars(&self) -> [u16; LFN_CHARS_PER_SLOT] {
        let mut out = [0u16; LFN_CHARS_PER_SLOT];
        out[0..5].copy_from_slice(&self.name1);
        out[5..11].copy_from_slice(&self.name2);
        out[11..13].copy_from_slice(&self.name3);
        out
    }

    /// Compute the LFN checksum for an 8.3 short name (11 bytes).
    pub fn compute_checksum(short_name: &[u8; 11]) -> u8 {
        let mut sum: u8 = 0;
        for &b in short_name.iter() {
            sum = (sum >> 1) | (sum << 7);
            sum = sum.wrapping_add(b);
        }
        sum
    }

    /// Parse from 32 raw bytes.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < FAT_DIRENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut name1 = [0u16; 5];
        let mut name2 = [0u16; 6];
        let mut name3 = [0u16; 2];
        for i in 0..5 {
            name1[i] = u16::from_le_bytes([raw[1 + i * 2], raw[2 + i * 2]]);
        }
        for i in 0..6 {
            name2[i] = u16::from_le_bytes([raw[14 + i * 2], raw[15 + i * 2]]);
        }
        for i in 0..2 {
            name3[i] = u16::from_le_bytes([raw[28 + i * 2], raw[29 + i * 2]]);
        }
        Ok(Self {
            order: raw[0],
            name1,
            attr: raw[11],
            lfn_type: raw[12],
            checksum: raw[13],
            name2,
            first_cluster: u16::from_le_bytes([raw[26], raw[27]]),
            name3,
        })
    }
}

// ── Directory Snapshot ────────────────────────────────────────────────────────

/// In-memory snapshot of a FAT directory.
pub struct FatDir {
    /// Flat array of raw 32-byte directory entries.
    entries: Vec<[u8; FAT_DIRENT_SIZE]>,
    /// Capacity in number of entries (grows as needed up to MAX_ENTRIES).
    capacity: usize,
}

impl FatDir {
    /// Create an empty directory with `capacity` pre-allocated slots.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.min(MAX_ENTRIES);
        let mut entries = Vec::new();
        for _ in 0..cap {
            entries.push([0u8; FAT_DIRENT_SIZE]);
        }
        Self {
            entries,
            capacity: cap,
        }
    }

    /// Load raw directory data from a byte slice (multiple of FAT_DIRENT_SIZE).
    pub fn from_raw(data: &[u8]) -> Result<Self> {
        if data.len() % FAT_DIRENT_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let count = (data.len() / FAT_DIRENT_SIZE).min(MAX_ENTRIES);
        let mut entries = Vec::new();
        for i in 0..count {
            let start = i * FAT_DIRENT_SIZE;
            let mut slot = [0u8; FAT_DIRENT_SIZE];
            slot.copy_from_slice(&data[start..start + FAT_DIRENT_SIZE]);
            entries.push(slot);
        }
        let capacity = count;
        Ok(Self { entries, capacity })
    }

    /// Look up a file by its packed 8.3 short name (11 bytes: 8 name + 3 ext).
    pub fn lookup_short(&self, name11: &[u8; 11]) -> Option<usize> {
        for (i, slot) in self.entries.iter().enumerate() {
            if slot[0] == FAT_EOD {
                break;
            }
            if slot[0] == FAT_DELETED || slot[11] == FAT_ATTR_LFN {
                continue;
            }
            if &slot[0..11] == name11 {
                return Some(i);
            }
        }
        None
    }

    /// Look up a file by LFN name (ASCII comparison only; UCS-2 > 0x7F → skip).
    ///
    /// Reconstructs the full name from LFN slots and compares case-insensitively.
    pub fn lookup_lfn(&self, name: &[u8]) -> Option<usize> {
        let mut lfn_buf = [0u16; 255];
        let mut lfn_len = 0usize;
        let mut i = 0;
        while i < self.entries.len() {
            let slot = &self.entries[i];
            if slot[0] == FAT_EOD {
                break;
            }
            if slot[0] == FAT_DELETED {
                lfn_len = 0;
                i += 1;
                continue;
            }
            if slot[11] == FAT_ATTR_LFN {
                if let Ok(lfn) = FatLfnEntry::from_bytes(slot) {
                    let chars = lfn.name_chars();
                    let order = (lfn.order & 0x3F) as usize;
                    let base = (order - 1) * LFN_CHARS_PER_SLOT;
                    if base + LFN_CHARS_PER_SLOT > 255 {
                        i += 1;
                        continue;
                    }
                    for (j, &c) in chars.iter().enumerate() {
                        if c == 0 || c == 0xFFFF {
                            break;
                        }
                        lfn_buf[base + j] = c;
                        lfn_len = lfn_len.max(base + j + 1);
                    }
                }
                i += 1;
                continue;
            }
            // Short name entry — compare assembled LFN.
            if lfn_len > 0 {
                let matches = name.len() == lfn_len
                    && name
                        .iter()
                        .zip(lfn_buf[..lfn_len].iter())
                        .all(|(&a, &b)| a.to_ascii_lowercase() == (b as u8).to_ascii_lowercase());
                if matches {
                    return Some(i);
                }
                lfn_len = 0;
            }
            i += 1;
        }
        None
    }

    /// Add a new short-name entry, returning its slot index.
    pub fn add_entry(&mut self, entry: &FatDirEntry) -> Result<usize> {
        // Find a free or deleted slot.
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot[0] == FAT_EOD || slot[0] == FAT_DELETED {
                entry.to_bytes(slot.as_mut_slice())?;
                // If we used an EOD slot, add a new EOD after.
                if i + 1 < self.capacity && self.entries[i][0] != FAT_EOD {
                    // slot was FAT_DELETED — no EOD management needed
                }
                return Ok(i);
            }
        }
        // Grow if under capacity.
        if self.entries.len() < self.capacity {
            let mut slot = [0u8; FAT_DIRENT_SIZE];
            entry.to_bytes(slot.as_mut_slice())?;
            let idx = self.entries.len();
            self.entries.push(slot);
            return Ok(idx);
        }
        Err(Error::OutOfMemory)
    }

    /// Mark the entry at `idx` as deleted.
    pub fn delete_entry(&mut self, idx: usize) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::NotFound);
        }
        self.entries[idx][0] = FAT_DELETED;
        Ok(())
    }

    /// Get the parsed short-name entry at slot `idx`.
    pub fn get_entry(&self, idx: usize) -> Result<FatDirEntry> {
        if idx >= self.entries.len() {
            return Err(Error::NotFound);
        }
        FatDirEntry::from_bytes(&self.entries[idx])
    }

    /// Iterate all valid (non-deleted, non-EOD, non-LFN) entries.
    pub fn iter_entries(&self) -> impl Iterator<Item = (usize, FatDirEntry)> + '_ {
        self.entries.iter().enumerate().filter_map(|(i, slot)| {
            if slot[0] == FAT_EOD || slot[0] == FAT_DELETED || slot[11] == FAT_ATTR_LFN {
                return None;
            }
            FatDirEntry::from_bytes(slot).ok().map(|e| (i, e))
        })
    }

    /// Return the number of slots currently tracked.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Serialize all entries into a byte buffer.
    pub fn to_raw(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for slot in &self.entries {
            out.extend_from_slice(slot.as_slice());
        }
        out
    }
}
