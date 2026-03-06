// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT32 directory operations.
//!
//! Implements FAT32 short-name directory entry structures and operations:
//! - [`Fat32DirEntry`] — 32-byte on-disk directory entry
//! - [`iterate_dir`] — walk all valid entries in a directory
//! - [`add_entry`] — write a new short-name entry into free slot
//! - [`remove_entry`] — mark entry as deleted (0xE5 prefix)
//! - Dot and dotdot entry creation for new directories
//!
//! # FAT32 Directory Structure
//!
//! FAT32 directory entries are 32 bytes each. A directory is stored as a
//! chain of clusters. Each cluster holds `cluster_size / 32` entries.
//! Long file names (LFN) use a sequence of preceding LFN entries before
//! the short-name entry; LFN handling lives in `fat32_long_name.rs`.
//!
//! # References
//! - Microsoft FAT32 File System Specification (2000)
//! - Linux `fs/fat/dir.c`, `fs/fat/fatent.c`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of a single FAT32 directory entry.
pub const FAT32_DIRENT_SIZE: usize = 32;

/// FAT32 deleted-entry marker (0xE5 in the first byte of name).
pub const FAT32_DELETED_MARKER: u8 = 0xE5;

/// FAT32 end-of-directory marker (0x00 in the first byte).
pub const FAT32_EOD_MARKER: u8 = 0x00;

/// Maximum short-name entries per simulated directory cluster.
const MAX_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// Attribute flags (di_attr)
// ---------------------------------------------------------------------------

/// Read-only attribute.
pub const FAT_ATTR_READ_ONLY: u8 = 0x01;
/// Hidden attribute.
pub const FAT_ATTR_HIDDEN: u8 = 0x02;
/// System attribute.
pub const FAT_ATTR_SYSTEM: u8 = 0x04;
/// Volume label.
pub const FAT_ATTR_VOLUME_ID: u8 = 0x08;
/// Directory attribute.
pub const FAT_ATTR_DIRECTORY: u8 = 0x10;
/// Archive attribute.
pub const FAT_ATTR_ARCHIVE: u8 = 0x20;
/// LFN entry marker (all four base flags set).
pub const FAT_ATTR_LFN: u8 =
    FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN | FAT_ATTR_SYSTEM | FAT_ATTR_VOLUME_ID;

// ---------------------------------------------------------------------------
// Fat32DirEntry
// ---------------------------------------------------------------------------

/// FAT32 on-disk 32-byte directory entry.
///
/// Short-name entries use an 8.3 name format stored in the `name` field.
#[derive(Debug, Clone, Copy)]
pub struct Fat32DirEntry {
    /// 8.3 name: bytes 0–7 = base name (space-padded), bytes 8–10 = extension.
    pub name: [u8; 11],
    /// File attributes.
    pub attr: u8,
    /// NT reserved field (case bits for Windows extensions).
    pub ntres: u8,
    /// Creation time, 10ms units (0–199).
    pub crt_time_tenth: u8,
    /// Creation time (packed: hour[15:11], min[10:5], sec/2[4:0]).
    pub crt_time: u16,
    /// Creation date (packed: year-1980[15:9], month[8:5], day[4:0]).
    pub crt_date: u16,
    /// Last access date.
    pub acc_date: u16,
    /// High 16 bits of first cluster number.
    pub fst_clus_hi: u16,
    /// Last write time.
    pub wrt_time: u16,
    /// Last write date.
    pub wrt_date: u16,
    /// Low 16 bits of first cluster number.
    pub fst_clus_lo: u16,
    /// File size in bytes (0 for directories).
    pub file_size: u32,
}

impl Fat32DirEntry {
    /// Create a new short-name directory entry.
    ///
    /// `short_name` must be exactly 11 bytes (8.3 uppercase, space-padded).
    pub fn new(short_name: [u8; 11], attr: u8, first_cluster: u32, file_size: u32) -> Self {
        Self {
            name: short_name,
            attr,
            ntres: 0,
            crt_time_tenth: 0,
            crt_time: 0,
            crt_date: 0,
            acc_date: 0,
            fst_clus_hi: (first_cluster >> 16) as u16,
            wrt_time: 0,
            wrt_date: 0,
            fst_clus_lo: (first_cluster & 0xFFFF) as u16,
            file_size,
        }
    }

    /// Create the "." entry for a new directory.
    pub fn dot(self_cluster: u32) -> Self {
        let mut name = [b' '; 11];
        name[0] = b'.';
        Self::new(name, FAT_ATTR_DIRECTORY, self_cluster, 0)
    }

    /// Create the ".." entry for a new directory.
    pub fn dotdot(parent_cluster: u32) -> Self {
        let mut name = [b' '; 11];
        name[0] = b'.';
        name[1] = b'.';
        Self::new(name, FAT_ATTR_DIRECTORY, parent_cluster, 0)
    }

    /// Return the first cluster number (combining hi and lo words).
    pub fn first_cluster(&self) -> u32 {
        (self.fst_clus_hi as u32) << 16 | self.fst_clus_lo as u32
    }

    /// Return true if this entry is deleted.
    pub fn is_deleted(&self) -> bool {
        self.name[0] == FAT32_DELETED_MARKER
    }

    /// Return true if this is the end-of-directory sentinel.
    pub fn is_eod(&self) -> bool {
        self.name[0] == FAT32_EOD_MARKER
    }

    /// Return true if this is a long-filename (LFN) entry.
    pub fn is_lfn(&self) -> bool {
        self.attr == FAT_ATTR_LFN
    }

    /// Return true if this is a normal file or directory entry.
    pub fn is_regular(&self) -> bool {
        !self.is_deleted() && !self.is_eod() && !self.is_lfn()
    }

    /// Mark as deleted.
    pub fn delete(&mut self) {
        self.name[0] = FAT32_DELETED_MARKER;
    }

    /// Return name as trimmed bytes (no trailing spaces, dot separator removed).
    pub fn short_name_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        // Base name (trim trailing spaces).
        let base_end = self.name[..8]
            .iter()
            .rposition(|&c| c != b' ')
            .map(|i| i + 1)
            .unwrap_or(0);
        out[..base_end].copy_from_slice(&self.name[..base_end]);
        let mut len = base_end;
        // Extension (trim trailing spaces).
        let ext_end = self.name[8..11]
            .iter()
            .rposition(|&c| c != b' ')
            .map(|i| i + 1)
            .unwrap_or(0);
        if ext_end > 0 {
            out[len] = b'.';
            len += 1;
            out[len..len + ext_end].copy_from_slice(&self.name[8..8 + ext_end]);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Fat32Dir — a single directory (flat entry array for simulation)
// ---------------------------------------------------------------------------

/// Represents a FAT32 directory's cluster data as a flat entry array.
pub struct Fat32Dir {
    entries: [Option<Fat32DirEntry>; MAX_ENTRIES],
    count: usize,
    /// Cluster number assigned to this directory.
    pub cluster: u32,
    /// Cluster number of the parent directory.
    pub parent_cluster: u32,
}

impl Fat32Dir {
    /// Create a new empty directory with dot/dotdot entries.
    pub fn new(cluster: u32, parent_cluster: u32) -> Self {
        let mut dir = Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            cluster,
            parent_cluster,
        };
        dir.entries[0] = Some(Fat32DirEntry::dot(cluster));
        dir.entries[1] = Some(Fat32DirEntry::dotdot(parent_cluster));
        dir.count = 2;
        dir
    }

    /// Find a free slot (deleted entry or unused slot).
    fn find_free_slot(&self) -> Option<usize> {
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.is_deleted() {
                    return Some(i);
                }
            }
        }
        if self.count < MAX_ENTRIES {
            Some(self.count)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// iterate_dir
// ---------------------------------------------------------------------------

/// Iterate all valid (non-deleted, non-eod, non-lfn) entries in a directory.
///
/// Returns a `Vec` of cloned entries.
pub fn iterate_dir(dir: &Fat32Dir) -> Vec<Fat32DirEntry> {
    let mut result = Vec::new();
    for slot in dir.entries[..dir.count].iter().flatten() {
        if slot.is_regular() {
            result.push(*slot);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// add_entry
// ---------------------------------------------------------------------------

/// Add a new short-name entry to a FAT32 directory.
///
/// Finds a deleted slot or extends the directory. Returns the slot index.
/// Returns `Err(OutOfMemory)` when all entries are in use.
pub fn add_entry(
    dir: &mut Fat32Dir,
    short_name: [u8; 11],
    attr: u8,
    first_cluster: u32,
    file_size: u32,
) -> Result<usize> {
    let slot = dir.find_free_slot().ok_or(Error::OutOfMemory)?;
    if slot == dir.count {
        dir.count += 1;
    }
    dir.entries[slot] = Some(Fat32DirEntry::new(
        short_name,
        attr,
        first_cluster,
        file_size,
    ));
    Ok(slot)
}

// ---------------------------------------------------------------------------
// remove_entry
// ---------------------------------------------------------------------------

/// Remove an entry by matching its 8.3 `name` field (11 bytes).
///
/// Marks the matching entry as deleted (0xE5). Returns `Err(NotFound)` if
/// no matching entry is found.
pub fn remove_entry(dir: &mut Fat32Dir, short_name: &[u8; 11]) -> Result<()> {
    for slot in dir.entries[..dir.count].iter_mut().flatten() {
        if slot.is_regular() && &slot.name == short_name {
            slot.delete();
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

// ---------------------------------------------------------------------------
// lookup_entry
// ---------------------------------------------------------------------------

/// Look up an entry by 8.3 name.
pub fn lookup_entry<'a>(dir: &'a Fat32Dir, short_name: &[u8; 11]) -> Option<&'a Fat32DirEntry> {
    for slot in dir.entries[..dir.count].iter().flatten() {
        if slot.is_regular() && &slot.name == short_name {
            return Some(slot);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a plain ASCII file name into an 8.3 short name (uppercase, space-padded).
///
/// Returns `None` if the name cannot be expressed as a valid 8.3 name.
pub fn encode_short_name(name: &[u8]) -> Option<[u8; 11]> {
    let dot_pos = name.iter().rposition(|&c| c == b'.');
    let (base, ext) = match dot_pos {
        Some(p) => (&name[..p], &name[p + 1..]),
        None => (name, &b""[..]),
    };
    if base.len() > 8 || ext.len() > 3 {
        return None;
    }
    let mut out = [b' '; 11];
    for (i, &c) in base.iter().enumerate() {
        out[i] = c.to_ascii_uppercase();
    }
    for (i, &c) in ext.iter().enumerate() {
        out[8 + i] = c.to_ascii_uppercase();
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_dotdot() {
        let dir = Fat32Dir::new(10, 2);
        let entries = iterate_dir(&dir);
        assert!(entries.iter().any(|e| e.name[0] == b'.'));
    }

    #[test]
    fn test_add_remove_lookup() {
        let mut dir = Fat32Dir::new(10, 2);
        let name = encode_short_name(b"hello.txt").unwrap();
        add_entry(&mut dir, name, FAT_ATTR_ARCHIVE, 100, 1234).unwrap();
        assert!(lookup_entry(&dir, &name).is_some());
        remove_entry(&mut dir, &name).unwrap();
        assert!(lookup_entry(&dir, &name).is_none());
    }

    #[test]
    fn test_encode_short_name() {
        let n = encode_short_name(b"readme.txt").unwrap();
        assert_eq!(&n[..6], b"README");
        assert_eq!(&n[8..11], b"TXT");
    }
}
