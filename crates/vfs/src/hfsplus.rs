// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HFS+ filesystem (Apple HFS Plus).
//!
//! HFS+ (Hierarchical File System Plus) is Apple's primary filesystem from
//! Mac OS 8.1 through macOS Mojave, before APFS replaced it. Key features:
//!
//! - B-tree based catalog (file/directory records)
//! - Unicode filenames (UTF-16BE, case-folded)
//! - 32-bit file IDs (CNID — Catalog Node ID)
//! - Extents overflow B-tree for fragmented files
//! - Journal (HFS+ journaled variant)
//!
//! # Structure
//!
//! ```text
//! [512B boot blocks][Volume Header][Catalog B-tree][Extents B-tree][Attributes B-tree]...[Backup VH]
//! ```
//!
//! # References
//!
//! - Apple Technical Note TN1150: HFS Plus Volume Format
//! - Linux `fs/hfsplus/`

use oncrix_lib::{Error, Result};

/// Maximum HFS+ filename length (in UTF-16 code units).
pub const HFSPLUS_NAME_MAX: usize = 255;
/// HFS+ volume header magic (`H+` → 0x482B).
pub const HFSPLUS_MAGIC: u16 = 0x482B;
/// HFSX (case-sensitive) magic.
pub const HFSX_MAGIC: u16 = 0x4858;
/// HFS+ version.
pub const HFSPLUS_VERSION: u16 = 4;
/// Maximum in-memory catalog entries.
pub const MAX_CATALOG_ENTRIES: usize = 512;

/// Catalog node ID type.
pub type CnId = u32;

/// Well-known catalog IDs.
pub const ROOT_PARENT_ID: CnId = 1;
pub const ROOT_FOLDER_ID: CnId = 2;
pub const EXTENTS_FILE_ID: CnId = 3;
pub const CATALOG_FILE_ID: CnId = 4;
pub const BAD_ALLOC_FILE_ID: CnId = 5;

/// HFS+ file type (catalog record type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfsPlusRecordType {
    Folder,
    File,
    FolderThread,
    FileThread,
}

/// Simplified HFS+ extent descriptor (start block + block count).
#[derive(Debug, Clone, Copy, Default)]
pub struct HfsPlusExtent {
    pub start_block: u32,
    pub block_count: u32,
}

impl HfsPlusExtent {
    /// True if this extent is empty (unallocated).
    pub fn is_empty(&self) -> bool {
        self.block_count == 0
    }
}

/// The 8 inline extents of an HFS+ fork (data or resource).
#[derive(Debug, Clone, Copy, Default)]
pub struct HfsPlusForkData {
    /// Total logical size in bytes.
    pub logical_size: u64,
    /// Clump size (allocation hint) in bytes.
    pub clump_size: u32,
    /// Number of allocated blocks.
    pub total_blocks: u32,
    /// Up to 8 inline extents.
    pub extents: [HfsPlusExtent; 8],
}

impl HfsPlusForkData {
    /// Sum of block counts across all inline extents.
    pub fn inline_block_count(&self) -> u32 {
        self.extents.iter().map(|e| e.block_count).sum()
    }
}

/// An HFS+ filename stored as UTF-16BE code units.
#[derive(Debug, Clone, Copy)]
pub struct HfsPlusName {
    units: [u16; HFSPLUS_NAME_MAX],
    len: u8,
}

impl HfsPlusName {
    /// Create from a raw ASCII slice (for simplicity; production code would use UTF-16).
    pub fn from_ascii(s: &[u8]) -> Result<Self> {
        if s.is_empty() || s.len() > HFSPLUS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut units = [0u16; HFSPLUS_NAME_MAX];
        for (i, &b) in s.iter().enumerate() {
            units[i] = b as u16;
        }
        Ok(Self {
            units,
            len: s.len() as u8,
        })
    }

    /// Length in UTF-16 code units.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// True if name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Compare two HFS+ names (case-insensitive for standard HFS+).
    pub fn eq_case_fold(&self, other: &HfsPlusName) -> bool {
        if self.len != other.len {
            return false;
        }
        // Simple case-folding: A-Z → a-z for ASCII range.
        self.units[..self.len as usize]
            .iter()
            .zip(other.units[..other.len as usize].iter())
            .all(|(a, b)| {
                let af = if *a >= 0x41 && *a <= 0x5A {
                    *a + 0x20
                } else {
                    *a
                };
                let bf = if *b >= 0x41 && *b <= 0x5A {
                    *b + 0x20
                } else {
                    *b
                };
                af == bf
            })
    }
}

/// A catalog record — either file or folder.
#[derive(Debug, Clone)]
pub struct HfsPlusCatalogEntry {
    /// Record type.
    pub rec_type: HfsPlusRecordType,
    /// Catalog node ID.
    pub cnid: CnId,
    /// Parent CNID.
    pub parent_id: CnId,
    /// Entry name.
    pub name: HfsPlusName,
    /// Creation time (Mac HFS time: seconds since 1904-01-01).
    pub create_date: u32,
    /// Modification time.
    pub content_mod_date: u32,
    /// Data fork (for files).
    pub data_fork: HfsPlusForkData,
    /// Resource fork (for files).
    pub rsrc_fork: HfsPlusForkData,
    /// Hard link count (folders: always 1).
    pub link_count: u32,
}

impl HfsPlusCatalogEntry {
    /// Create a new folder entry.
    pub fn new_folder(cnid: CnId, parent_id: CnId, name: HfsPlusName) -> Self {
        Self {
            rec_type: HfsPlusRecordType::Folder,
            cnid,
            parent_id,
            name,
            create_date: 0,
            content_mod_date: 0,
            data_fork: HfsPlusForkData::default(),
            rsrc_fork: HfsPlusForkData::default(),
            link_count: 1,
        }
    }

    /// Create a new file entry.
    pub fn new_file(cnid: CnId, parent_id: CnId, name: HfsPlusName) -> Self {
        Self {
            rec_type: HfsPlusRecordType::File,
            cnid,
            parent_id,
            name,
            create_date: 0,
            content_mod_date: 0,
            data_fork: HfsPlusForkData::default(),
            rsrc_fork: HfsPlusForkData::default(),
            link_count: 1,
        }
    }

    /// True if this is a folder entry.
    pub fn is_folder(&self) -> bool {
        self.rec_type == HfsPlusRecordType::Folder
    }
}

/// In-memory HFS+ catalog (normally a B-tree on disk).
pub struct HfsPlusCatalog {
    entries: [Option<HfsPlusCatalogEntry>; MAX_CATALOG_ENTRIES],
    count: usize,
    next_cnid: CnId,
    /// Case-sensitive mode (HFSX).
    case_sensitive: bool,
}

impl HfsPlusCatalog {
    /// Create a new catalog with a root folder.
    pub fn new(case_sensitive: bool) -> Self {
        Self {
            entries: [const { None }; MAX_CATALOG_ENTRIES],
            count: 0,
            next_cnid: 16, // CNIDs 1-15 are reserved.
            case_sensitive,
        }
    }

    fn alloc_cnid(&mut self) -> CnId {
        let id = self.next_cnid;
        self.next_cnid += 1;
        id
    }

    /// Create a new folder under `parent_id` with ASCII name `name`.
    pub fn mkdir(&mut self, parent_id: CnId, name: &[u8]) -> Result<CnId> {
        let hname = HfsPlusName::from_ascii(name)?;
        if self.lookup_in(parent_id, &hname).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_CATALOG_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let cnid = self.alloc_cnid();
        self.entries[self.count] = Some(HfsPlusCatalogEntry::new_folder(cnid, parent_id, hname));
        self.count += 1;
        Ok(cnid)
    }

    /// Create a new file under `parent_id` with ASCII name `name`.
    pub fn create(&mut self, parent_id: CnId, name: &[u8]) -> Result<CnId> {
        let hname = HfsPlusName::from_ascii(name)?;
        if self.lookup_in(parent_id, &hname).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_CATALOG_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let cnid = self.alloc_cnid();
        self.entries[self.count] = Some(HfsPlusCatalogEntry::new_file(cnid, parent_id, hname));
        self.count += 1;
        Ok(cnid)
    }

    /// Look up an entry by parent and name.
    fn lookup_in(&self, parent_id: CnId, name: &HfsPlusName) -> Option<usize> {
        self.entries[..self.count].iter().position(|e| {
            e.as_ref()
                .map(|e| {
                    e.parent_id == parent_id
                        && if self.case_sensitive {
                            e.name.units[..e.name.len()] == name.units[..name.len()]
                        } else {
                            e.name.eq_case_fold(name)
                        }
                })
                .unwrap_or(false)
        })
    }

    /// Look up entry by parent and ASCII name. Returns CNID or `NotFound`.
    pub fn lookup(&self, parent_id: CnId, name: &[u8]) -> Result<CnId> {
        let hname = HfsPlusName::from_ascii(name)?;
        self.lookup_in(parent_id, &hname)
            .and_then(|idx| self.entries[idx].as_ref().map(|e| e.cnid))
            .ok_or(Error::NotFound)
    }

    /// Remove an entry by CNID.
    pub fn remove(&mut self, cnid: CnId) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.as_ref().map(|e| e.cnid == cnid).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.entries[idx] = self.entries[self.count].take();
                Ok(())
            }
        }
    }

    /// Find entry by CNID.
    pub fn find(&self, cnid: CnId) -> Option<&HfsPlusCatalogEntry> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.cnid == cnid)
    }

    /// Find entry by CNID (mutable).
    pub fn find_mut(&mut self, cnid: CnId) -> Option<&mut HfsPlusCatalogEntry> {
        self.entries[..self.count]
            .iter_mut()
            .filter_map(|e| e.as_mut())
            .find(|e| e.cnid == cnid)
    }

    /// List all direct children of `parent_id`.
    pub fn readdir(&self, parent_id: CnId) -> impl Iterator<Item = &HfsPlusCatalogEntry> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .filter(move |e| e.parent_id == parent_id)
    }
}

/// HFS+ volume header (in-memory representation of the on-disk structure).
#[derive(Debug, Clone, Copy)]
pub struct HfsPlusVolumeHeader {
    pub magic: u16,
    pub version: u16,
    pub attributes: u32,
    pub last_mounted_version: u32,
    pub journal_info_block: u32,
    pub create_date: u32,
    pub modify_date: u32,
    pub backup_date: u32,
    pub checked_date: u32,
    pub file_count: u32,
    pub folder_count: u32,
    pub block_size: u32,
    pub total_blocks: u32,
    pub free_blocks: u32,
}

impl HfsPlusVolumeHeader {
    /// Create a default volume header for a new filesystem.
    pub fn new(total_blocks: u32, block_size: u32) -> Self {
        Self {
            magic: HFSPLUS_MAGIC,
            version: HFSPLUS_VERSION,
            attributes: 0,
            last_mounted_version: 0,
            journal_info_block: 0,
            create_date: 0,
            modify_date: 0,
            backup_date: 0,
            checked_date: 0,
            file_count: 0,
            folder_count: 1, // root folder
            block_size,
            total_blocks,
            free_blocks: total_blocks.saturating_sub(8),
        }
    }

    /// Check magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == HFSPLUS_MAGIC || self.magic == HFSX_MAGIC
    }
}
