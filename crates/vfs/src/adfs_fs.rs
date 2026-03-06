// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADFS (Acorn Disc Filing System) filesystem support.
//!
//! ADFS was the primary filesystem for Acorn computers (BBC Micro, Archimedes,
//! RISC PC).  Linux supports ADFS read-only.  This module implements the
//! superblock, directory, and inode structures for ADFS "S"/"M"/"L" (old-map)
//! and "D"/"E"/"F" (new-map) disc formats.

use oncrix_lib::{Error, Result};

/// ADFS old-map magic disc record identifier bytes.
pub const ADFS_OLD_MAGIC: u8 = 0xd3;
/// ADFS new-map boot block magic.
pub const ADFS_NEW_MAGIC: u32 = 0xaddf_0000;

/// ADFS disc record size (old-map).
pub const ADFS_DR_SIZE: usize = 60;

/// Maximum filename length in ADFS (old map).
pub const ADFS_OLD_NAME_LEN: usize = 10;
/// Maximum filename length in ADFS (new map / E+/F+).
pub const ADFS_NEW_NAME_LEN: usize = 255;

/// ADFS map format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdfsMapFormat {
    /// Old-map (S, M, L formats): 1-bit interleaved FAM.
    OldMap,
    /// New-map (D, E, F formats): zone-based free-space map.
    NewMap,
}

/// ADFS disc record (old-map).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AdfsDiscRecord {
    /// Log2 of the sector size (usually 8 → 256 bytes/sector, or 9 → 512).
    pub log2_sector_size: u8,
    /// Sectors per track.
    pub sectors_per_track: u8,
    /// Number of heads.
    pub heads: u8,
    /// Density mode.
    pub density: u8,
    /// Log2 of the allocation unit in sectors (0 = 1 sector per AU).
    pub id_len: u8,
    /// Log2 of the map length.
    pub log2_map_size: u8,
    /// Disc end-of-map offset.
    pub disc_end: u32,
    /// Reserved.
    pub _reserved: u8,
    /// Disc size in sectors (lower 24 bits).
    pub disc_size_lo: [u8; 3],
    /// Track size in bytes (usually 1024).
    pub track_size: u16,
    /// Root directory address on disc.
    pub root: u32,
    /// Disc size (upper byte).
    pub disc_size_hi: u32,
    /// Share size / boot option.
    pub share_size: u8,
    /// Big flag: large disc support.
    pub big_flag: u8,
}

impl AdfsDiscRecord {
    /// Sector size in bytes.
    pub fn sector_size(&self) -> usize {
        1usize << self.log2_sector_size
    }

    /// Total disc size in bytes.
    pub fn disc_size_bytes(&self) -> u64 {
        let lo = (self.disc_size_lo[0] as u64)
            | ((self.disc_size_lo[1] as u64) << 8)
            | ((self.disc_size_lo[2] as u64) << 16);
        lo | ((self.disc_size_hi as u64) << 24)
    }
}

/// ADFS object attributes.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdfsAttributes(pub u8);

impl AdfsAttributes {
    pub const READ_OWNER: u8 = 0x01;
    pub const WRITE_OWNER: u8 = 0x02;
    pub const LOCK_OWNER: u8 = 0x04;
    pub const DIR: u8 = 0x08;
    pub const EXECUTE_OWNER: u8 = 0x10;
    pub const READ_PUBLIC: u8 = 0x20;
    pub const WRITE_PUBLIC: u8 = 0x40;
    pub const EXECUTE_PUBLIC: u8 = 0x80;

    pub fn is_dir(&self) -> bool {
        self.0 & Self::DIR != 0
    }

    pub fn owner_readable(&self) -> bool {
        self.0 & Self::READ_OWNER != 0
    }

    pub fn owner_writable(&self) -> bool {
        self.0 & Self::WRITE_OWNER != 0
    }

    /// Convert ADFS attributes to a POSIX-style mode word.
    pub fn to_posix_mode(&self) -> u16 {
        let mut mode: u16 = 0;
        if self.is_dir() {
            mode |= 0o040000;
        } else {
            mode |= 0o100000;
        }
        if self.owner_readable() {
            mode |= 0o400;
        }
        if self.owner_writable() {
            mode |= 0o200;
        }
        if self.0 & Self::EXECUTE_OWNER != 0 {
            mode |= 0o100;
        }
        if self.0 & Self::READ_PUBLIC != 0 {
            mode |= 0o044;
        }
        if self.0 & Self::WRITE_PUBLIC != 0 {
            mode |= 0o022;
        }
        mode
    }
}

/// ADFS old-map directory entry.
#[derive(Debug, Clone, Copy)]
pub struct AdfsOldDirEntry {
    /// Object name (up to 10 characters, NUL-padded).
    pub name: [u8; ADFS_OLD_NAME_LEN],
    pub name_len: u8,
    /// Load address (Acorn-specific; encodes type + timestamp in new formats).
    pub load_addr: u32,
    /// Execution address.
    pub exec_addr: u32,
    /// File size in bytes.
    pub size: u32,
    /// Disc sector address of the object.
    pub sector_addr: u32,
    /// Object attributes.
    pub attrs: AdfsAttributes,
    /// Inode number assigned by the Linux driver.
    pub ino: u64,
}

impl AdfsOldDirEntry {
    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Extract a 5-byte RISC OS timestamp (centiseconds since 1900-01-01)
    /// from the load/exec addresses if the load address has bit 31 set.
    pub fn riscos_timestamp(&self) -> Option<u64> {
        if self.load_addr & 0xfff0_0000 == 0xfff0_0000 {
            let lo = self.exec_addr as u64;
            let hi = (self.load_addr & 0xff) as u64;
            Some((hi << 32) | lo)
        } else {
            None
        }
    }
}

/// In-memory ADFS superblock.
#[derive(Debug, Clone)]
pub struct AdfsSuperblock {
    pub map_format: AdfsMapFormat,
    pub sector_size: usize,
    pub block_size: usize,
    pub total_sectors: u64,
    pub root_sector: u32,
    /// For new-map: disc ID.
    pub disc_id: u32,
    pub boot_option: u8,
}

impl AdfsSuperblock {
    /// Create an old-map superblock from a disc record.
    pub fn from_disc_record(dr: &AdfsDiscRecord) -> Result<Self> {
        let sector_size = dr.sector_size();
        if sector_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let total_bytes = dr.disc_size_bytes();
        let total_sectors = total_bytes / sector_size as u64;
        // Old-map block size: 1 sector for S/M, 2 for L.
        let block_size = sector_size;
        Ok(Self {
            map_format: AdfsMapFormat::OldMap,
            sector_size,
            block_size,
            total_sectors,
            root_sector: dr.root,
            disc_id: 0,
            boot_option: 0,
        })
    }
}

/// Directory entry cache for a single ADFS directory block.
pub struct AdfsDirCache {
    entries: [Option<AdfsOldDirEntry>; 77],
    count: usize,
}

impl AdfsDirCache {
    /// Create an empty directory cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; 77],
            count: 0,
        }
    }

    /// Add an entry to the cache.
    pub fn push(&mut self, entry: AdfsOldDirEntry) -> Result<()> {
        if self.count >= 77 {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Find an entry by name (case-insensitive, as ADFS mandates).
    pub fn find(&self, name: &[u8]) -> Option<&AdfsOldDirEntry> {
        for slot in &self.entries[..self.count] {
            if let Some(entry) = slot.as_ref() {
                let ename = entry.name_bytes();
                if ename.len() == name.len()
                    && ename
                        .iter()
                        .zip(name)
                        .all(|(&a, &b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
                {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate entries.
    pub fn iter(&self) -> impl Iterator<Item = &AdfsOldDirEntry> {
        self.entries[..self.count].iter().filter_map(|s| s.as_ref())
    }
}

impl Default for AdfsDirCache {
    fn default() -> Self {
        Self::new()
    }
}
