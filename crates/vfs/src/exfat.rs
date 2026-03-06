// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! exFAT — Extended File Allocation Table filesystem.
//!
//! exFAT is a lightweight filesystem designed for flash media (SD cards,
//! USB drives) where NTFS is too heavy and FAT32's 4 GiB file-size limit
//! is insufficient.
//!
//! # On-disk layout
//!
//! ```text
//! ┌────────────────┬────────────────┬────────────────┬──────────┐
//! │  Boot Region   │  FAT Region    │ Cluster Bitmap │  Data    │
//! │  (12 sectors)  │  (N sectors)   │  + Upcase Tbl  │ Clusters │
//! └────────────────┴────────────────┴────────────────┴──────────┘
//! ```
//!
//! ## Boot sector
//!
//! The first sector contains the Volume Boot Record (VBR) with device
//! geometry, FAT location, and cluster heap offset.
//!
//! ## FAT chain
//!
//! The File Allocation Table maps cluster numbers to next-cluster links.
//! Special values mark end-of-chain (`0xFFFFFFFF`) and free (`0x00000000`).
//!
//! ## Cluster bitmap
//!
//! A contiguous bitmap tracks free/used state per cluster. One bit per
//! cluster; bit index `i` corresponds to cluster `i + 2`.
//!
//! ## Directory entries
//!
//! Each directory entry is a fixed 32-byte record. File metadata is
//! spread across several entry types: File, Stream Extension, and
//! File Name entries.
//!
//! # Reference
//!
//! Microsoft exFAT specification (2019 public release).

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// exFAT boot signature (at byte offset 510-511 of the VBR).
pub const EXFAT_BOOT_SIGNATURE: u16 = 0xAA55;

/// exFAT filesystem type string.
pub const EXFAT_FS_NAME: &[u8; 8] = b"EXFAT   ";

/// FAT entry: free cluster.
pub const FAT_FREE: u32 = 0x0000_0000;

/// FAT entry: end of chain.
pub const FAT_EOC: u32 = 0xFFFF_FFFF;

/// FAT entry: bad cluster.
pub const FAT_BAD: u32 = 0xFFFF_FFF7;

/// Minimum cluster number (clusters 0 and 1 are reserved).
const MIN_CLUSTER: u32 = 2;

/// Maximum clusters supported in our model.
const MAX_CLUSTERS: usize = 4096;

/// Default bytes per sector (512).
const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Default sectors per cluster (128 = 64 KiB clusters).
const DEFAULT_SECTORS_PER_CLUSTER: u32 = 128;

/// Maximum inodes tracked.
const MAX_INODES: usize = 512;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file data size in bytes.
const MAX_FILE_DATA: usize = 65536;

/// Maximum filename length (exFAT supports up to 255 UTF-16 characters).
const MAX_NAME_LEN: usize = 255;

/// Upcase table entries (first 128 ASCII characters for simplified model).
const UPCASE_TABLE_SIZE: usize = 128;

// ── Directory entry types ────────────────────────────────────────────────────

/// exFAT directory entry type codes (byte 0 of a 32-byte entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    /// End-of-directory marker.
    EndOfDirectory = 0x00,
    /// Allocation bitmap (critical primary).
    AllocationBitmap = 0x81,
    /// Upcase table (critical primary).
    UpcaseTable = 0x82,
    /// Volume label (critical primary).
    VolumeLabel = 0x83,
    /// File entry (critical primary).
    FileEntry = 0x85,
    /// Stream extension (critical secondary).
    StreamExtension = 0xC0,
    /// File name (critical secondary).
    FileName = 0xC1,
}

// ── Boot sector ──────────────────────────────────────────────────────────────

/// exFAT Volume Boot Record (simplified).
///
/// Contains the partition geometry, FAT location, and cluster heap metadata.
#[derive(Debug, Clone, Copy)]
pub struct ExfatBootSector {
    /// Boot signature ([`EXFAT_BOOT_SIGNATURE`]).
    pub signature: u16,
    /// Filesystem name (`"EXFAT   "`).
    pub fs_name: [u8; 8],
    /// Partition offset on the physical device (in sectors).
    pub partition_offset: u64,
    /// Total number of sectors in the volume.
    pub volume_length: u64,
    /// Sector offset where the FAT begins.
    pub fat_offset: u32,
    /// Number of sectors occupied by one FAT.
    pub fat_length: u32,
    /// Sector offset where the cluster heap begins.
    pub cluster_heap_offset: u32,
    /// Total number of clusters in the heap.
    pub cluster_count: u32,
    /// Cluster number of the root directory.
    pub root_dir_cluster: u32,
    /// Volume serial number.
    pub volume_serial: u32,
    /// Log2 of bytes per sector (9 = 512, 12 = 4096).
    pub bytes_per_sector_shift: u8,
    /// Log2 of sectors per cluster.
    pub sectors_per_cluster_shift: u8,
    /// Number of FATs (1 or 2).
    pub number_of_fats: u8,
    /// Volume flags (dirty, media failure, etc.).
    pub volume_flags: u16,
    /// Percent of clusters in use (0..100, or 0xFF for unknown).
    pub percent_in_use: u8,
}

impl ExfatBootSector {
    /// Create a boot sector for a volume of `total_sectors`.
    pub fn new(total_sectors: u64) -> Self {
        let cluster_count = (total_sectors / u64::from(DEFAULT_SECTORS_PER_CLUSTER))
            .min(MAX_CLUSTERS as u64) as u32;
        Self {
            signature: EXFAT_BOOT_SIGNATURE,
            fs_name: *EXFAT_FS_NAME,
            partition_offset: 0,
            volume_length: total_sectors,
            fat_offset: 24,
            fat_length: ((u64::from(cluster_count) * 4 + u64::from(DEFAULT_SECTOR_SIZE) - 1)
                / u64::from(DEFAULT_SECTOR_SIZE)) as u32,
            cluster_heap_offset: 128,
            cluster_count,
            root_dir_cluster: MIN_CLUSTER,
            volume_serial: 0x4F4E_4352, // "ONCR"
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 7,
            number_of_fats: 1,
            volume_flags: 0,
            percent_in_use: 0,
        }
    }

    /// Bytes per sector.
    pub fn bytes_per_sector(&self) -> u32 {
        1u32 << self.bytes_per_sector_shift
    }

    /// Sectors per cluster.
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_shift
    }

    /// Bytes per cluster.
    pub fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector() * self.sectors_per_cluster()
    }

    /// Validate the boot sector.
    pub fn validate(&self) -> Result<()> {
        if self.signature != EXFAT_BOOT_SIGNATURE {
            return Err(Error::InvalidArgument);
        }
        if self.fs_name != *EXFAT_FS_NAME {
            return Err(Error::InvalidArgument);
        }
        if self.cluster_count < 1 {
            return Err(Error::InvalidArgument);
        }
        if self.bytes_per_sector_shift < 9 || self.bytes_per_sector_shift > 12 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── FAT chain ────────────────────────────────────────────────────────────────

/// File Allocation Table: maps cluster N to its next cluster (or EOC).
pub struct FatTable {
    /// FAT entries (index = cluster number).
    entries: Vec<u32>,
}

impl FatTable {
    /// Create a new FAT with `cluster_count + 2` entries.
    fn new(cluster_count: u32) -> Self {
        let total = (cluster_count as usize) + MIN_CLUSTER as usize;
        let mut entries = Vec::with_capacity(total);
        entries.resize(total, FAT_FREE);
        // Clusters 0 and 1 are reserved.
        if total > 0 {
            entries[0] = 0xFFF8_FFF8; // media descriptor
        }
        if total > 1 {
            entries[1] = FAT_EOC;
        }
        Self { entries }
    }

    /// Get the FAT entry for cluster `cluster`.
    fn get(&self, cluster: u32) -> Result<u32> {
        let idx = cluster as usize;
        if idx >= self.entries.len() {
            return Err(Error::InvalidArgument);
        }
        Ok(self.entries[idx])
    }

    /// Set the FAT entry for cluster `cluster`.
    fn set(&mut self, cluster: u32, value: u32) -> Result<()> {
        let idx = cluster as usize;
        if idx >= self.entries.len() {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx] = value;
        Ok(())
    }

    /// Allocate a single free cluster. Returns the cluster number.
    fn alloc_cluster(&mut self) -> Result<u32> {
        for i in MIN_CLUSTER as usize..self.entries.len() {
            if self.entries[i] == FAT_FREE {
                self.entries[i] = FAT_EOC;
                return Ok(i as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a chain starting at `start`. Returns number of freed clusters.
    fn free_chain(&mut self, start: u32) -> Result<u32> {
        let mut current = start;
        let mut freed = 0u32;
        loop {
            let next = self.get(current)?;
            self.set(current, FAT_FREE)?;
            freed += 1;
            if next == FAT_EOC || next == FAT_FREE || next == FAT_BAD {
                break;
            }
            current = next;
        }
        Ok(freed)
    }

    /// Follow a chain and return all cluster numbers.
    fn follow_chain(&self, start: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut current = start;
        loop {
            chain.push(current);
            let next = self.get(current)?;
            if next == FAT_EOC || next == FAT_FREE || next == FAT_BAD {
                break;
            }
            current = next;
            if chain.len() > MAX_CLUSTERS {
                return Err(Error::IoError);
            }
        }
        Ok(chain)
    }

    /// Count free clusters.
    fn free_count(&self) -> u32 {
        self.entries[MIN_CLUSTER as usize..]
            .iter()
            .filter(|&&e| e == FAT_FREE)
            .count() as u32
    }
}

// ── Cluster bitmap ───────────────────────────────────────────────────────────

/// Allocation bitmap tracking per-cluster used/free state.
pub struct ClusterBitmap {
    /// Bitmap storage (bit i => cluster i + 2).
    bits: Vec<u8>,
    /// Number of clusters tracked.
    cluster_count: u32,
}

impl ClusterBitmap {
    /// Create a new bitmap for `cluster_count` clusters.
    fn new(cluster_count: u32) -> Self {
        let bytes = ((cluster_count as usize) + 7) / 8;
        let mut bits = Vec::with_capacity(bytes);
        bits.resize(bytes, 0);
        Self {
            bits,
            cluster_count,
        }
    }

    /// Mark a cluster as used.
    fn set_used(&mut self, cluster: u32) -> Result<()> {
        let idx = cluster
            .checked_sub(MIN_CLUSTER)
            .ok_or(Error::InvalidArgument)?;
        if idx >= self.cluster_count {
            return Err(Error::InvalidArgument);
        }
        let byte_idx = idx as usize / 8;
        let bit_idx = idx as usize % 8;
        self.bits[byte_idx] |= 1 << bit_idx;
        Ok(())
    }

    /// Mark a cluster as free.
    fn set_free(&mut self, cluster: u32) -> Result<()> {
        let idx = cluster
            .checked_sub(MIN_CLUSTER)
            .ok_or(Error::InvalidArgument)?;
        if idx >= self.cluster_count {
            return Err(Error::InvalidArgument);
        }
        let byte_idx = idx as usize / 8;
        let bit_idx = idx as usize % 8;
        self.bits[byte_idx] &= !(1 << bit_idx);
        Ok(())
    }

    /// Check if a cluster is used.
    pub fn is_used(&self, cluster: u32) -> bool {
        let idx = match cluster.checked_sub(MIN_CLUSTER) {
            Some(i) if i < self.cluster_count => i,
            _ => return false,
        };
        let byte_idx = idx as usize / 8;
        let bit_idx = idx as usize % 8;
        (self.bits[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Count used clusters.
    pub fn used_count(&self) -> u32 {
        let mut count = 0u32;
        for &byte in &self.bits {
            count += byte.count_ones();
        }
        count
    }
}

// ── Upcase table ─────────────────────────────────────────────────────────────

/// Upcase table for case-insensitive filename comparison.
///
/// exFAT uses a Unicode upcase table stored on disk.  Our simplified model
/// covers ASCII range only.
pub struct UpcaseTable {
    /// Mapping from lowercase code point to uppercase code point.
    table: [u16; UPCASE_TABLE_SIZE],
}

impl UpcaseTable {
    /// Create the default upcase table (ASCII range).
    fn new() -> Self {
        let mut table = [0u16; UPCASE_TABLE_SIZE];
        for i in 0..UPCASE_TABLE_SIZE {
            table[i] = i as u16;
        }
        // Map a-z to A-Z.
        for i in b'a'..=b'z' {
            table[i as usize] = (i - 32) as u16;
        }
        Self { table }
    }

    /// Convert a character to uppercase using the table.
    pub fn to_upper(&self, ch: u16) -> u16 {
        if (ch as usize) < UPCASE_TABLE_SIZE {
            self.table[ch as usize]
        } else {
            ch
        }
    }

    /// Case-insensitive name comparison.
    pub fn names_equal(&self, a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }
        for (ca, cb) in a.bytes().zip(b.bytes()) {
            if self.to_upper(ca as u16) != self.to_upper(cb as u16) {
                return false;
            }
        }
        true
    }
}

// ── Exfat inode ──────────────────────────────────────────────────────────────

/// In-memory exFAT inode representing a file or directory.
#[derive(Debug, Clone)]
pub struct ExfatInode {
    /// Inode number (synthetic — exFAT has no native inode concept).
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
    /// Permission bits (exFAT does not store POSIX perms; we use defaults).
    pub mode: u16,
    /// File size in bytes.
    pub size: u64,
    /// First cluster of the file data.
    pub start_cluster: u32,
    /// Number of clusters allocated (contiguous hint).
    pub cluster_count: u32,
    /// Attribute flags (read-only, hidden, system, directory, archive).
    pub attributes: ExfatAttributes,
    /// Creation timestamp (100-ns intervals since 1980-01-01).
    pub create_time: u64,
    /// Modification timestamp.
    pub modify_time: u64,
    /// Access timestamp.
    pub access_time: u64,
    /// Hard link count (always 1 for exFAT).
    pub nlink: u32,
}

/// exFAT file attribute flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatAttributes(pub u16);

impl ExfatAttributes {
    /// Read-only file.
    pub const READ_ONLY: Self = Self(0x01);
    /// Hidden file.
    pub const HIDDEN: Self = Self(0x02);
    /// System file.
    pub const SYSTEM: Self = Self(0x04);
    /// Directory.
    pub const DIRECTORY: Self = Self(0x10);
    /// Archive flag.
    pub const ARCHIVE: Self = Self(0x20);

    /// Check if the directory flag is set.
    pub fn is_directory(self) -> bool {
        self.0 & Self::DIRECTORY.0 != 0
    }

    /// Check if the read-only flag is set.
    pub fn is_read_only(self) -> bool {
        self.0 & Self::READ_ONLY.0 != 0
    }
}

impl ExfatInode {
    /// Create a new file inode.
    pub fn new_file(ino: u64, mode: u16) -> Self {
        Self {
            ino,
            file_type: FileType::Regular,
            mode,
            size: 0,
            start_cluster: 0,
            cluster_count: 0,
            attributes: ExfatAttributes(ExfatAttributes::ARCHIVE.0),
            create_time: 0,
            modify_time: 0,
            access_time: 0,
            nlink: 1,
        }
    }

    /// Create a new directory inode.
    pub fn new_dir(ino: u64, mode: u16) -> Self {
        Self {
            ino,
            file_type: FileType::Directory,
            mode,
            size: 0,
            start_cluster: 0,
            cluster_count: 0,
            attributes: ExfatAttributes(ExfatAttributes::DIRECTORY.0),
            create_time: 0,
            modify_time: 0,
            access_time: 0,
            nlink: 1,
        }
    }

    /// Convert to a VFS [`Inode`].
    pub fn to_vfs_inode(&self) -> Inode {
        let mut vfs = Inode::new(InodeNumber(self.ino), self.file_type, FileMode(self.mode));
        vfs.size = self.size;
        vfs.nlink = self.nlink;
        vfs
    }
}

// ── Directory entry (in-memory) ──────────────────────────────────────────────

/// In-memory directory entry.
#[derive(Debug, Clone)]
pub struct ExfatDirEntry {
    /// Inode number of the target.
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
    /// Entry name (UTF-8).
    pub name: String,
}

// ── File data storage ────────────────────────────────────────────────────────

/// In-memory file data blob.
struct ExfatFileData {
    /// Owning inode number.
    ino: u64,
    /// Raw byte content.
    data: Vec<u8>,
}

// ── Mounted filesystem ───────────────────────────────────────────────────────

/// Mounted exFAT filesystem handle.
///
/// Provides the full VFS interface plus exFAT-specific operations for
/// managing the FAT, cluster bitmap, and upcase table.
pub struct ExfatFs {
    /// Boot sector.
    boot: ExfatBootSector,
    /// File allocation table.
    fat: FatTable,
    /// Cluster bitmap.
    bitmap: ClusterBitmap,
    /// Upcase table for case-insensitive comparison.
    upcase: UpcaseTable,
    /// Inode table.
    inodes: Vec<ExfatInode>,
    /// Directory entries (parent_ino, entry).
    dir_entries: Vec<(u64, ExfatDirEntry)>,
    /// File data blobs.
    file_data: Vec<ExfatFileData>,
    /// Next inode number.
    next_ino: u64,
    /// Volume label (up to 11 UTF-16 characters, stored as UTF-8).
    volume_label: String,
}

impl ExfatFs {
    /// Create and mount a new exFAT filesystem.
    pub fn new(total_sectors: u64) -> Result<Self> {
        let boot = ExfatBootSector::new(total_sectors);
        boot.validate()?;

        let fat = FatTable::new(boot.cluster_count);
        let bitmap = ClusterBitmap::new(boot.cluster_count);
        let upcase = UpcaseTable::new();

        let root = ExfatInode::new_dir(1, 0o755);

        let mut fs = Self {
            boot,
            fat,
            bitmap,
            upcase,
            inodes: Vec::new(),
            dir_entries: Vec::new(),
            file_data: Vec::new(),
            next_ino: 2,
            volume_label: String::new(),
        };
        fs.inodes.push(root);
        Ok(fs)
    }

    /// Return a reference to the boot sector.
    pub fn boot_sector(&self) -> &ExfatBootSector {
        &self.boot
    }

    /// Get the volume label.
    pub fn volume_label(&self) -> &str {
        &self.volume_label
    }

    /// Set the volume label.
    pub fn set_volume_label(&mut self, label: &str) -> Result<()> {
        if label.len() > 11 {
            return Err(Error::InvalidArgument);
        }
        self.volume_label = String::from(label);
        Ok(())
    }

    /// Free cluster count.
    pub fn free_clusters(&self) -> u32 {
        self.fat.free_count()
    }

    /// Free space in bytes.
    pub fn free_space(&self) -> u64 {
        u64::from(self.free_clusters()) * u64::from(self.boot.bytes_per_cluster())
    }

    /// Case-insensitive name lookup using the upcase table.
    pub fn names_equal(&self, a: &str, b: &str) -> bool {
        self.upcase.names_equal(a, b)
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Find an inode by number.
    fn find_inode(&self, ino: u64) -> Result<&ExfatInode> {
        self.inodes
            .iter()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Find a mutable inode by number.
    fn find_inode_mut(&mut self, ino: u64) -> Result<&mut ExfatInode> {
        self.inodes
            .iter_mut()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Allocate a new inode number.
    fn alloc_ino(&mut self) -> Result<u64> {
        if self.inodes.len() >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        Ok(ino)
    }

    /// Find a directory entry by parent inode and name (case-insensitive).
    fn find_dir_entry(&self, parent_ino: u64, name: &str) -> Result<&ExfatDirEntry> {
        self.dir_entries
            .iter()
            .find(|(p, e)| *p == parent_ino && self.upcase.names_equal(&e.name, name))
            .map(|(_, e)| e)
            .ok_or(Error::NotFound)
    }

    /// Count directory entries for a parent.
    fn dir_entry_count(&self, parent_ino: u64) -> usize {
        self.dir_entries
            .iter()
            .filter(|(p, _)| *p == parent_ino)
            .count()
    }

    /// Get file data.
    fn get_file_data(&self, ino: u64) -> Option<&ExfatFileData> {
        self.file_data.iter().find(|f| f.ino == ino)
    }

    /// Get or create file data.
    fn get_or_create_file_data(&mut self, ino: u64) -> &mut ExfatFileData {
        if !self.file_data.iter().any(|f| f.ino == ino) {
            self.file_data.push(ExfatFileData {
                ino,
                data: Vec::new(),
            });
        }
        self.file_data.iter_mut().find(|f| f.ino == ino).unwrap()
    }

    /// Allocate clusters for a file, updating FAT and bitmap.
    fn alloc_clusters_for(&mut self, ino: u64, count: u32) -> Result<u32> {
        let mut first = 0u32;
        let mut prev = 0u32;
        for _ in 0..count {
            let c = self.fat.alloc_cluster()?;
            let _ = self.bitmap.set_used(c);
            if first == 0 {
                first = c;
            }
            if prev != 0 {
                self.fat.set(prev, c)?;
            }
            prev = c;
        }
        if let Ok(inode) = self.find_inode_mut(ino) {
            if inode.start_cluster == 0 {
                inode.start_cluster = first;
            }
            inode.cluster_count += count;
        }
        Ok(first)
    }
}

// ── InodeOps implementation ──────────────────────────────────────────────────

impl InodeOps for ExfatFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let entry = self.find_dir_entry(parent.ino.0, name)?;
        let inode = self.find_inode(entry.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.alloc_ino()?;
        let exfat_inode = ExfatInode::new_file(ino, mode.0);
        self.inodes.push(exfat_inode);

        self.dir_entries.push((
            parent.ino.0,
            ExfatDirEntry {
                ino,
                file_type: FileType::Regular,
                name: String::from(name),
            },
        ));

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.alloc_ino()?;
        let exfat_inode = ExfatInode::new_dir(ino, mode.0);
        self.inodes.push(exfat_inode);

        // Allocate one cluster for the directory.
        let _ = self.alloc_clusters_for(ino, 1);

        self.dir_entries.push((
            parent.ino.0,
            ExfatDirEntry {
                ino,
                file_type: FileType::Directory,
                name: String::from(name),
            },
        ));

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type == FileType::Directory {
            return Err(Error::InvalidArgument);
        }

        // Free cluster chain.
        let start = inode.start_cluster;
        if start >= MIN_CLUSTER {
            let _ = self.fat.free_chain(start);
        }

        // Remove directory entry.
        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.ino == entry_ino)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);

        self.inodes.retain(|i| i.ino != entry_ino);
        self.file_data.retain(|f| f.ino != entry_ino);
        Ok(())
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type != FileType::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.dir_entry_count(entry_ino) > 0 {
            return Err(Error::Busy);
        }

        let start = inode.start_cluster;
        if start >= MIN_CLUSTER {
            let _ = self.fat.free_chain(start);
        }

        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.ino == entry_ino)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);
        self.inodes.retain(|i| i.ino != entry_ino);
        Ok(())
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let disk_inode = self.find_inode(inode.ino.0)?;
        if disk_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let fd = match self.get_file_data(inode.ino.0) {
            Some(fd) => fd,
            None => return Ok(0),
        };
        let start = offset as usize;
        if start >= fd.data.len() {
            return Ok(0);
        }
        let available = fd.data.len() - start;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&fd.data[start..start + to_read]);
        Ok(to_read)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let disk_inode = self.find_inode(inode.ino.0)?;
        if disk_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let end = offset as usize + data.len();
        if end > MAX_FILE_DATA {
            return Err(Error::OutOfMemory);
        }

        let ino = inode.ino.0;
        let fd = self.get_or_create_file_data(ino);
        if fd.data.len() < end {
            fd.data.resize(end, 0);
        }
        fd.data[offset as usize..end].copy_from_slice(data);

        let new_size = fd.data.len() as u64;
        // Compute required clusters.
        let bpc = self.boot.bytes_per_cluster() as u64;
        let needed = if new_size == 0 {
            0
        } else {
            ((new_size + bpc - 1) / bpc) as u32
        };

        let inode_mut = self.find_inode_mut(ino)?;
        inode_mut.size = new_size;
        let current_clusters = inode_mut.cluster_count;
        if needed > current_clusters {
            let extra = needed - current_clusters;
            let _ = self.alloc_clusters_for(ino, extra);
        }

        Ok(data.len())
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let disk_inode = self.find_inode(inode.ino.0)?;
        if disk_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        if size as usize > MAX_FILE_DATA {
            return Err(Error::OutOfMemory);
        }

        let ino = inode.ino.0;
        let fd = self.get_or_create_file_data(ino);
        fd.data.resize(size as usize, 0);

        let inode_mut = self.find_inode_mut(ino)?;
        inode_mut.size = size;
        Ok(())
    }
}
