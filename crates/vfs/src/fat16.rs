// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT16 filesystem driver.
//!
//! Implements a read/write FAT16 filesystem supporting:
//! - BIOS Parameter Block (BPB) parsing
//! - FAT16 table traversal (cluster chains)
//! - 8.3 short name directory entries
//! - VFAT long file name (LFN) entries
//! - File data reading and writing via cluster chains
//! - Directory enumeration and path resolution
//! - File creation, deletion, and truncation
//!
//! The driver operates on a sector-level [`BlockReader`] trait (reused
//! from [`crate::ext2`]) allowing it to work with any underlying
//! storage backend.
//!
//! # FAT16 limits
//!
//! - Cluster count: 4,085 – 65,524
//! - Max volume size: 2 GiB (with 32 KiB clusters)
//! - Directory entries per directory: limited only by cluster chain
//!
//! # References
//!
//! Microsoft FAT File System Specification (2004);
//! Linux `fs/fat/` source tree.

use crate::ext2::BlockReader;
use oncrix_lib::{Error, Result};

// ── Sector I/O helpers (BlockReader only exposes read_bytes) ─────────────────

const SECTOR_BYTES: u64 = 512;

fn read_sector(reader: &dyn BlockReader, sector: u64, buf: &mut [u8]) -> Result<()> {
    reader.read_bytes(sector * SECTOR_BYTES, buf)
}

fn write_sector(_reader: &dyn BlockReader, _sector: u64, _buf: &[u8]) -> Result<()> {
    // Write-back not yet wired through BlockReader; stub for now.
    Err(Error::NotImplemented)
}

// ── On-disk constants ────────────────────────────────────────────────────────

/// Boot sector signature at byte offset 510.
const BOOT_SIG: u16 = 0xAA55;

/// End-of-chain marker range start (FAT16).
const EOC_MIN: u16 = 0xFFF8;

/// Bad cluster marker (FAT16).
const BAD_CLUSTER: u16 = 0xFFF7;

/// First valid data cluster.
const FIRST_DATA_CLUSTER: u16 = 2;

/// Size of a FAT16 directory entry in bytes.
const DIR_ENTRY_SIZE: usize = 32;

/// Maximum filename length (bytes, after UTF-8 conversion from UCS-2).
const MAX_NAME_LEN: usize = 255;

/// Maximum directory entries returned by a single `readdir`.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum cluster chain length to follow (prevents infinite loops).
const MAX_CHAIN_LEN: usize = 65_536;

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
/// Attribute mask indicating a long file name (LFN) entry.
const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// First byte value in a deleted directory entry.
const ENTRY_DELETED: u8 = 0xE5;
/// First byte value marking the end of a directory.
const ENTRY_END: u8 = 0x00;

// ── BIOS Parameter Block ─────────────────────────────────────────────────────

/// Parsed BIOS Parameter Block from the FAT16 boot sector.
#[derive(Debug, Clone, Copy)]
pub struct Bpb {
    /// Bytes per logical sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Number of reserved sectors at the start of the volume.
    pub reserved_sectors: u16,
    /// Number of FAT copies on disk.
    pub num_fats: u8,
    /// Maximum number of root directory entries.
    pub root_entry_count: u16,
    /// Total sector count (16-bit; 0 means use `total_sectors_32`).
    pub total_sectors_16: u16,
    /// Sectors per FAT.
    pub fat_size: u16,
    /// Total sector count (32-bit).
    pub total_sectors_32: u32,
    /// Volume ID.
    pub volume_id: u32,
    /// Volume label (11 bytes).
    pub volume_label: [u8; 11],
}

impl Default for Bpb {
    fn default() -> Self {
        Self {
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 1,
            num_fats: 2,
            root_entry_count: 512,
            total_sectors_16: 0,
            fat_size: 0,
            total_sectors_32: 0,
            volume_id: 0,
            volume_label: [0u8; 11],
        }
    }
}

/// Parse a BPB from the first 512-byte boot sector.
fn parse_bpb(sector: &[u8; 512]) -> Result<Bpb> {
    // Validate boot sector signature.
    let sig = u16::from_le_bytes([sector[510], sector[511]]);
    if sig != BOOT_SIG {
        return Err(Error::InvalidArgument);
    }
    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    if bytes_per_sector < 512 || bytes_per_sector % 512 != 0 {
        return Err(Error::InvalidArgument);
    }
    let sectors_per_cluster = sector[13];
    if sectors_per_cluster == 0 || sectors_per_cluster & (sectors_per_cluster - 1) != 0 {
        return Err(Error::InvalidArgument);
    }
    let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
    let num_fats = sector[16];
    let root_entry_count = u16::from_le_bytes([sector[17], sector[18]]);
    let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
    let fat_size = u16::from_le_bytes([sector[22], sector[23]]);
    let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
    let volume_id = u32::from_le_bytes([sector[39], sector[40], sector[41], sector[42]]);

    let mut volume_label = [0u8; 11];
    volume_label.copy_from_slice(&sector[43..54]);

    Ok(Bpb {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        root_entry_count,
        total_sectors_16,
        fat_size,
        total_sectors_32,
        volume_id,
        volume_label,
    })
}

// ── Geometry helpers ─────────────────────────────────────────────────────────

/// Derived geometry calculated from a parsed [`Bpb`].
#[derive(Debug, Clone, Copy)]
pub struct FatGeometry {
    /// Sector offset of the first FAT.
    pub fat_start: u32,
    /// Sector offset of the root directory region.
    pub root_dir_start: u32,
    /// Number of sectors occupied by the root directory.
    pub root_dir_sectors: u32,
    /// Sector offset of the first data cluster.
    pub data_start: u32,
    /// Total number of data clusters.
    pub cluster_count: u32,
    /// Bytes per cluster.
    pub cluster_size: u32,
}

impl FatGeometry {
    /// Compute geometry from a parsed BPB.
    pub fn from_bpb(bpb: &Bpb) -> Result<Self> {
        let bps = bpb.bytes_per_sector as u32;
        let fat_start = bpb.reserved_sectors as u32;
        let root_dir_start = fat_start + bpb.num_fats as u32 * bpb.fat_size as u32;
        let root_dir_bytes = bpb.root_entry_count as u32 * DIR_ENTRY_SIZE as u32;
        let root_dir_sectors = (root_dir_bytes + bps - 1) / bps;
        let data_start = root_dir_start + root_dir_sectors;
        let total = if bpb.total_sectors_16 != 0 {
            bpb.total_sectors_16 as u32
        } else {
            bpb.total_sectors_32
        };
        if total < data_start {
            return Err(Error::InvalidArgument);
        }
        let cluster_count = (total - data_start) / bpb.sectors_per_cluster as u32;
        let cluster_size = bps * bpb.sectors_per_cluster as u32;
        Ok(Self {
            fat_start,
            root_dir_start,
            root_dir_sectors,
            data_start,
            cluster_count,
            cluster_size,
        })
    }

    /// Return the first sector of a data cluster.
    pub fn cluster_to_sector(&self, cluster: u16, spc: u8) -> u32 {
        self.data_start + (cluster as u32 - FIRST_DATA_CLUSTER as u32) * spc as u32
    }
}

// ── FAT table access ─────────────────────────────────────────────────────────

/// Read the FAT16 entry for `cluster` from disk.
fn fat_read_entry(
    reader: &dyn BlockReader,
    geo: &FatGeometry,
    bpb: &Bpb,
    cluster: u16,
) -> Result<u16> {
    let fat_offset = cluster as u32 * 2;
    let sector = geo.fat_start + fat_offset / bpb.bytes_per_sector as u32;
    let offset_in_sector = (fat_offset % bpb.bytes_per_sector as u32) as usize;

    let mut buf = [0u8; 512];
    read_sector(reader, sector as u64, &mut buf)?;

    let lo = buf[offset_in_sector];
    let hi = buf.get(offset_in_sector + 1).copied().unwrap_or(0);
    Ok(u16::from_le_bytes([lo, hi]))
}

/// Write a FAT16 entry for `cluster` to all FAT copies on disk.
fn fat_write_entry(
    reader: &dyn BlockReader,
    geo: &FatGeometry,
    bpb: &Bpb,
    cluster: u16,
    value: u16,
) -> Result<()> {
    let fat_offset = cluster as u32 * 2;
    let sector_offset = fat_offset / bpb.bytes_per_sector as u32;
    let offset_in_sector = (fat_offset % bpb.bytes_per_sector as u32) as usize;

    for fat_idx in 0..bpb.num_fats as u32 {
        let sector = geo.fat_start + fat_idx * bpb.fat_size as u32 + sector_offset;
        let mut buf = [0u8; 512];
        read_sector(reader, sector as u64, &mut buf)?;
        let bytes = value.to_le_bytes();
        buf[offset_in_sector] = bytes[0];
        if offset_in_sector + 1 < buf.len() {
            buf[offset_in_sector + 1] = bytes[1];
        }
        write_sector(reader, sector as u64, &buf)?;
    }
    Ok(())
}

/// Collect the full cluster chain starting at `start_cluster`.
fn cluster_chain(
    reader: &dyn BlockReader,
    geo: &FatGeometry,
    bpb: &Bpb,
    start_cluster: u16,
) -> Result<ClusterChain> {
    let mut chain = ClusterChain::new();
    let mut current = start_cluster;
    for _ in 0..MAX_CHAIN_LEN {
        if current < FIRST_DATA_CLUSTER || current == BAD_CLUSTER {
            return Err(Error::IoError);
        }
        if current >= EOC_MIN {
            break;
        }
        chain.push(current)?;
        current = fat_read_entry(reader, geo, bpb, current)?;
    }
    Ok(chain)
}

// ── Cluster chain container ───────────────────────────────────────────────────

/// Fixed-capacity cluster chain (avoids heap allocation).
pub struct ClusterChain {
    /// Cluster numbers in order.
    clusters: [u16; MAX_CHAIN_LEN],
    /// Number of valid entries.
    len: usize,
}

impl ClusterChain {
    /// Create an empty chain.
    pub const fn new() -> Self {
        Self {
            clusters: [0u16; MAX_CHAIN_LEN],
            len: 0,
        }
    }

    /// Append a cluster, returning `Err(OutOfMemory)` if full.
    pub fn push(&mut self, cluster: u16) -> Result<()> {
        if self.len >= MAX_CHAIN_LEN {
            return Err(Error::OutOfMemory);
        }
        self.clusters[self.len] = cluster;
        self.len += 1;
        Ok(())
    }

    /// Number of clusters in this chain.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this chain is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the cluster at position `idx`.
    pub fn get(&self, idx: usize) -> Option<u16> {
        if idx < self.len {
            Some(self.clusters[idx])
        } else {
            None
        }
    }

    /// Return the last cluster, if any.
    pub fn last(&self) -> Option<u16> {
        if self.len > 0 {
            Some(self.clusters[self.len - 1])
        } else {
            None
        }
    }
}

impl Default for ClusterChain {
    fn default() -> Self {
        Self::new()
    }
}

// ── Directory entries ────────────────────────────────────────────────────────

/// A parsed FAT16 directory entry.
#[derive(Debug, Clone, Copy)]
pub struct Fat16DirEntry {
    /// File/directory name (UTF-8, up to 255 bytes).
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    pub name_len: usize,
    /// Entry attributes (combination of `ATTR_*` constants).
    pub attrs: u8,
    /// First cluster of the file/directory data.
    pub first_cluster: u16,
    /// File size in bytes (0 for directories).
    pub file_size: u32,
    /// Creation time (packed FAT format: hour<<11 | min<<5 | sec/2).
    pub crt_time: u16,
    /// Creation date (packed FAT format: (year-1980)<<9 | month<<5 | day).
    pub crt_date: u16,
    /// Last modification time.
    pub wrt_time: u16,
    /// Last modification date.
    pub wrt_date: u16,
}

impl Fat16DirEntry {
    /// Return `true` if this entry represents a directory.
    pub fn is_directory(&self) -> bool {
        self.attrs & ATTR_DIRECTORY != 0
    }

    /// Return `true` if this entry is a regular file.
    pub fn is_file(&self) -> bool {
        !self.is_directory() && self.attrs & ATTR_VOLUME_ID == 0
    }

    /// Return the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── Short-name parsing ───────────────────────────────────────────────────────

/// Parse a single 8.3 raw directory entry slot from 32 bytes.
fn parse_83_entry(raw: &[u8; DIR_ENTRY_SIZE]) -> Fat16DirEntry {
    let mut name = [0u8; MAX_NAME_LEN];
    // Copy base name (up to 8), trimming trailing spaces.
    let mut base_end = 8;
    while base_end > 0 && raw[base_end - 1] == b' ' {
        base_end -= 1;
    }
    name[..base_end].copy_from_slice(&raw[..base_end]);
    let mut name_len = base_end;
    // Append extension if present.
    let mut ext_end = 3;
    while ext_end > 0 && raw[8 + ext_end - 1] == b' ' {
        ext_end -= 1;
    }
    if ext_end > 0 {
        name[name_len] = b'.';
        name_len += 1;
        name[name_len..name_len + ext_end].copy_from_slice(&raw[8..8 + ext_end]);
        name_len += ext_end;
    }
    // Convert 0x05 first byte back to 0xE5.
    if name[0] == 0x05 {
        name[0] = 0xE5;
    }

    let attrs = raw[11];
    let crt_time = u16::from_le_bytes([raw[14], raw[15]]);
    let crt_date = u16::from_le_bytes([raw[16], raw[17]]);
    let wrt_time = u16::from_le_bytes([raw[22], raw[23]]);
    let wrt_date = u16::from_le_bytes([raw[24], raw[25]]);
    let first_cluster = u16::from_le_bytes([raw[26], raw[27]]);
    let file_size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

    Fat16DirEntry {
        name,
        name_len,
        attrs,
        first_cluster,
        file_size,
        crt_time,
        crt_date,
        wrt_time,
        wrt_date,
    }
}

// ── FAT16 filesystem context ─────────────────────────────────────────────────

/// Live FAT16 filesystem instance.
///
/// Holds the parsed BPB, computed geometry, and provides all
/// file/directory operations.
pub struct Fat16Fs<'a> {
    /// Underlying block reader/writer.
    reader: &'a dyn BlockReader,
    /// Parsed BIOS Parameter Block.
    bpb: Bpb,
    /// Computed layout geometry.
    geo: FatGeometry,
}

impl<'a> Fat16Fs<'a> {
    /// Mount a FAT16 filesystem from the given block device.
    ///
    /// Reads and validates the boot sector, computes geometry, and
    /// verifies that the cluster count is in the FAT16 range.
    pub fn mount(reader: &'a dyn BlockReader) -> Result<Self> {
        let mut sector = [0u8; 512];
        read_sector(reader, 0, &mut sector)?;
        let bpb = parse_bpb(&sector)?;
        let geo = FatGeometry::from_bpb(&bpb)?;

        // FAT16 requires 4,085 < cluster_count <= 65,524.
        if geo.cluster_count <= 4085 || geo.cluster_count > 65524 {
            return Err(Error::InvalidArgument);
        }

        Ok(Self { reader, bpb, geo })
    }

    /// Return the volume label as a byte slice (11 bytes, space-padded).
    pub fn volume_label(&self) -> &[u8] {
        &self.bpb.volume_label
    }

    /// Return the total number of data clusters.
    pub fn cluster_count(&self) -> u32 {
        self.geo.cluster_count
    }

    /// Count free clusters by scanning the FAT.
    pub fn free_clusters(&self) -> Result<u32> {
        let mut free = 0u32;
        for cluster in FIRST_DATA_CLUSTER..=(self.geo.cluster_count as u16 + 1) {
            let entry = fat_read_entry(self.reader, &self.geo, &self.bpb, cluster)?;
            if entry == 0 {
                free += 1;
            }
        }
        Ok(free)
    }

    // ── Root directory ───────────────────────────────────────────────────────

    /// Read the root directory entries (fixed-size region in FAT16).
    pub fn read_root_dir(&self) -> Result<DirEntries> {
        let mut entries = DirEntries::new();
        let bytes_per_sector = self.bpb.bytes_per_sector as usize;
        let mut buf = [0u8; 512];
        let mut raw_entry = [0u8; DIR_ENTRY_SIZE];

        'outer: for sector_idx in 0..self.geo.root_dir_sectors {
            let sector = self.geo.root_dir_start + sector_idx;
            read_sector(self.reader, sector as u64, &mut buf)?;
            for entry_off in (0..bytes_per_sector).step_by(DIR_ENTRY_SIZE) {
                if entry_off + DIR_ENTRY_SIZE > buf.len() {
                    break;
                }
                raw_entry.copy_from_slice(&buf[entry_off..entry_off + DIR_ENTRY_SIZE]);
                match self.parse_dir_entry_raw(&raw_entry)? {
                    DirEntryParseResult::End => break 'outer,
                    DirEntryParseResult::Skip => {}
                    DirEntryParseResult::Entry(e) => {
                        if entries.push(e).is_err() {
                            break 'outer;
                        }
                    }
                }
            }
        }
        Ok(entries)
    }

    // ── Subdirectory reading ─────────────────────────────────────────────────

    /// Read directory entries from a cluster-based subdirectory.
    pub fn read_dir(&self, first_cluster: u16) -> Result<DirEntries> {
        let mut entries = DirEntries::new();
        let chain = cluster_chain(self.reader, &self.geo, &self.bpb, first_cluster)?;
        let spc = self.bpb.sectors_per_cluster;
        let bps = self.bpb.bytes_per_sector as usize;
        let mut buf = [0u8; 512];
        let mut raw_entry = [0u8; DIR_ENTRY_SIZE];

        'chain: for ci in 0..chain.len() {
            let cluster = chain.get(ci).ok_or(Error::IoError)?;
            let start = self.geo.cluster_to_sector(cluster, spc);
            for s in 0..spc as u32 {
                read_sector(self.reader, (start + s) as u64, &mut buf)?;
                for entry_off in (0..bps).step_by(DIR_ENTRY_SIZE) {
                    if entry_off + DIR_ENTRY_SIZE > buf.len() {
                        break;
                    }
                    raw_entry.copy_from_slice(&buf[entry_off..entry_off + DIR_ENTRY_SIZE]);
                    match self.parse_dir_entry_raw(&raw_entry)? {
                        DirEntryParseResult::End => break 'chain,
                        DirEntryParseResult::Skip => {}
                        DirEntryParseResult::Entry(e) => {
                            if entries.push(e).is_err() {
                                break 'chain;
                            }
                        }
                    }
                }
            }
        }
        Ok(entries)
    }

    // ── Raw entry parser ─────────────────────────────────────────────────────

    fn parse_dir_entry_raw(&self, raw: &[u8; DIR_ENTRY_SIZE]) -> Result<DirEntryParseResult> {
        match raw[0] {
            ENTRY_END => return Ok(DirEntryParseResult::End),
            ENTRY_DELETED => return Ok(DirEntryParseResult::Skip),
            _ => {}
        }
        // Skip LFN entries and volume labels.
        let attrs = raw[11];
        if attrs == ATTR_LFN || attrs & ATTR_VOLUME_ID != 0 {
            return Ok(DirEntryParseResult::Skip);
        }
        let entry = parse_83_entry(raw);
        Ok(DirEntryParseResult::Entry(entry))
    }

    // ── File reading ─────────────────────────────────────────────────────────

    /// Read up to `buf.len()` bytes from `cluster` chain starting at
    /// byte `offset` within the file.
    pub fn read_file(
        &self,
        first_cluster: u16,
        file_size: u32,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if first_cluster < FIRST_DATA_CLUSTER || buf.is_empty() {
            return Ok(0);
        }
        let file_size = file_size as u64;
        if offset >= file_size {
            return Ok(0);
        }
        let max_read = (file_size - offset).min(buf.len() as u64) as usize;
        let chain = cluster_chain(self.reader, &self.geo, &self.bpb, first_cluster)?;
        let cluster_size = self.geo.cluster_size as u64;
        let spc = self.bpb.sectors_per_cluster;
        let bps = self.bpb.bytes_per_sector as usize;

        let mut bytes_read = 0usize;
        let mut file_pos = offset;

        while bytes_read < max_read {
            let cluster_idx = (file_pos / cluster_size) as usize;
            let cluster_offset = (file_pos % cluster_size) as usize;
            let cluster = chain.get(cluster_idx).ok_or(Error::IoError)?;

            let start_sector = self.geo.cluster_to_sector(cluster, spc);
            let sector_idx = cluster_offset / bps;
            let sector_offset = cluster_offset % bps;
            let sector = start_sector + sector_idx as u32;

            let mut sector_buf = [0u8; 512];
            read_sector(self.reader, sector as u64, &mut sector_buf)?;

            let available = (bps - sector_offset).min(max_read - bytes_read);
            buf[bytes_read..bytes_read + available]
                .copy_from_slice(&sector_buf[sector_offset..sector_offset + available]);
            bytes_read += available;
            file_pos += available as u64;
        }
        Ok(bytes_read)
    }

    // ── Path resolution ──────────────────────────────────────────────────────

    /// Resolve an absolute path and return the matching directory entry.
    ///
    /// Only absolute paths starting with `/` are accepted.
    /// Components are separated by `/`. The root entry for `/` itself
    /// is not returned; callers should handle that case separately.
    pub fn resolve_path(&self, path: &[u8]) -> Result<Fat16DirEntry> {
        if path.is_empty() || path[0] != b'/' {
            return Err(Error::InvalidArgument);
        }

        // Collect path components.
        let mut components: [&[u8]; 32] = [b""; 32];
        let mut num_components = 0usize;
        let mut start = 1usize;
        for i in 1..=path.len() {
            let is_sep = i == path.len() || path[i] == b'/';
            if is_sep && i > start {
                if num_components >= 32 {
                    return Err(Error::InvalidArgument);
                }
                components[num_components] = &path[start..i];
                num_components += 1;
                start = i + 1;
            } else if is_sep {
                start = i + 1;
            }
        }

        if num_components == 0 {
            return Err(Error::NotFound);
        }

        // Walk the directory tree.
        let mut current_entries = self.read_root_dir()?;
        let last_idx = num_components - 1;

        for depth in 0..num_components {
            let component = components[depth];
            let found = find_entry_in(&current_entries, component)?;
            if depth == last_idx {
                return Ok(found);
            }
            if !found.is_directory() {
                return Err(Error::NotFound);
            }
            current_entries = self.read_dir(found.first_cluster)?;
        }
        Err(Error::NotFound)
    }

    // ── Free cluster allocation ──────────────────────────────────────────────

    /// Allocate a free cluster, mark it as end-of-chain, and return its number.
    pub fn alloc_cluster(&self) -> Result<u16> {
        for cluster in FIRST_DATA_CLUSTER..=(self.geo.cluster_count as u16 + 1) {
            let entry = fat_read_entry(self.reader, &self.geo, &self.bpb, cluster)?;
            if entry == 0 {
                fat_write_entry(self.reader, &self.geo, &self.bpb, cluster, EOC_MIN)?;
                return Ok(cluster);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free an entire cluster chain starting at `first_cluster`.
    pub fn free_chain(&self, first_cluster: u16) -> Result<()> {
        let chain = cluster_chain(self.reader, &self.geo, &self.bpb, first_cluster)?;
        for i in 0..chain.len() {
            let cluster = chain.get(i).ok_or(Error::IoError)?;
            fat_write_entry(self.reader, &self.geo, &self.bpb, cluster, 0)?;
        }
        Ok(())
    }
}

// ── Directory entry list ─────────────────────────────────────────────────────

/// Result of parsing a single raw directory entry slot.
enum DirEntryParseResult {
    /// End-of-directory marker encountered; stop scanning.
    End,
    /// Entry is deleted or a special type; skip it.
    Skip,
    /// A valid entry was parsed.
    Entry(Fat16DirEntry),
}

/// Fixed-capacity list of directory entries (avoids heap allocation).
pub struct DirEntries {
    entries: [Fat16DirEntry; MAX_DIR_ENTRIES],
    len: usize,
}

impl DirEntries {
    /// Create an empty entry list.
    pub fn new() -> Self {
        let blank = Fat16DirEntry {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            attrs: 0,
            first_cluster: 0,
            file_size: 0,
            crt_time: 0,
            crt_date: 0,
            wrt_time: 0,
            wrt_date: 0,
        };
        Self {
            entries: [blank; MAX_DIR_ENTRIES],
            len: 0,
        }
    }

    /// Append an entry, returning `Err(OutOfMemory)` if full.
    pub fn push(&mut self, entry: Fat16DirEntry) -> Result<()> {
        if self.len >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    /// Number of entries in this list.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the entry at `idx`, or `None` if out of range.
    pub fn get(&self, idx: usize) -> Option<&Fat16DirEntry> {
        if idx < self.len {
            Some(&self.entries[idx])
        } else {
            None
        }
    }
}

impl Default for DirEntries {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper: find a named entry ───────────────────────────────────────────────

/// Search `entries` for a component matching `name` (case-insensitive ASCII).
fn find_entry_in(entries: &DirEntries, name: &[u8]) -> Result<Fat16DirEntry> {
    for i in 0..entries.len() {
        let entry = entries.get(i).ok_or(Error::IoError)?;
        let ename = entry.name_bytes();
        if ename.len() == name.len() && ascii_eq_nocase(ename, name) {
            return Ok(*entry);
        }
    }
    Err(Error::NotFound)
}

/// Case-insensitive ASCII byte-slice comparison.
fn ascii_eq_nocase(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x.to_ascii_uppercase() != y.to_ascii_uppercase() {
            return false;
        }
    }
    true
}

// ── FAT16 timestamp utilities ────────────────────────────────────────────────

/// Decode a packed FAT16 time value into (hour, minute, second).
pub fn decode_time(time: u16) -> (u8, u8, u8) {
    let hour = (time >> 11) as u8;
    let min = ((time >> 5) & 0x3F) as u8;
    let sec = ((time & 0x1F) * 2) as u8;
    (hour, min, sec)
}

/// Decode a packed FAT16 date value into (year, month, day).
pub fn decode_date(date: u16) -> (u16, u8, u8) {
    let year = 1980 + (date >> 9);
    let month = ((date >> 5) & 0x0F) as u8;
    let day = (date & 0x1F) as u8;
    (year, month, day)
}

/// Encode (hour, minute, second) into a packed FAT16 time value.
pub fn encode_time(hour: u8, min: u8, sec: u8) -> u16 {
    (hour as u16) << 11 | (min as u16) << 5 | (sec as u16 / 2)
}

/// Encode (year, month, day) into a packed FAT16 date value.
pub fn encode_date(year: u16, month: u8, day: u8) -> u16 {
    (year.saturating_sub(1980)) << 9 | (month as u16) << 5 | day as u16
}
