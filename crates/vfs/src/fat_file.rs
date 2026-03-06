// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT file read/write operations.
//!
//! Implements cluster-chain traversal and file data I/O for FAT12/16/32:
//!
//! - [`FatType`] — filesystem variant (FAT12, FAT16, FAT32)
//! - [`FatTable`] — in-memory FAT (cluster chain table)
//! - [`FatFileHandle`] — open file state (current cluster, position)
//! - [`read_file`] — read bytes from a file via cluster chain
//! - [`write_file`] — write bytes, extending chain as needed
//! - [`truncate_file`] — release cluster chain from a given offset
//!
//! # Cluster Chain
//!
//! Each FAT entry points to the next cluster in a file's chain.
//! Special values mark the end of chain (`EOC`) or free clusters (`0`).
//!
//! # References
//!
//! - Microsoft FAT32 File System Specification (2000)
//! - Linux `fs/fat/file.c`, `fs/fat/fatent.c`, `fs/fat/inode.c`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// FAT12 end-of-chain value.
pub const FAT12_EOC: u32 = 0xFF8;

/// FAT16 end-of-chain value.
pub const FAT16_EOC: u32 = 0xFFF8;

/// FAT32 end-of-chain value (top 4 bits reserved).
pub const FAT32_EOC: u32 = 0x0FFF_FFF8;

/// FAT32 bad-cluster marker.
pub const FAT32_BAD: u32 = 0x0FFF_FFF7;

/// FAT12 bad-cluster marker.
pub const FAT12_BAD: u32 = 0xFF7;

/// FAT16 bad-cluster marker.
pub const FAT16_BAD: u32 = 0xFFF7;

/// FAT32 entry mask (top 4 bits reserved on disk).
pub const FAT32_MASK: u32 = 0x0FFF_FFFF;

/// Maximum clusters tracked in this in-memory FAT.
const MAX_CLUSTERS: usize = 65536;

/// Maximum cluster chain length for a single file traversal.
const MAX_CHAIN: usize = 65536;

// ── FAT Variant ───────────────────────────────────────────────────────────────

/// FAT filesystem variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FatType {
    /// FAT12 (floppy / small media, entries 1.5 bytes).
    Fat12,
    /// FAT16 (older hard drives up to 2 GiB).
    Fat16,
    /// FAT32 (standard for ≥ 512 MiB partitions).
    #[default]
    Fat32,
}

impl FatType {
    /// Return the end-of-chain sentinel for this variant.
    pub fn eoc(self) -> u32 {
        match self {
            Self::Fat12 => FAT12_EOC,
            Self::Fat16 => FAT16_EOC,
            Self::Fat32 => FAT32_EOC,
        }
    }

    /// Return the bad-cluster sentinel.
    pub fn bad(self) -> u32 {
        match self {
            Self::Fat12 => FAT12_BAD,
            Self::Fat16 => FAT16_BAD,
            Self::Fat32 => FAT32_BAD,
        }
    }

    /// Return `true` if `entry` represents an end-of-chain.
    pub fn is_eoc(self, entry: u32) -> bool {
        match self {
            Self::Fat12 => entry >= 0xFF8,
            Self::Fat16 => entry >= 0xFFF8,
            Self::Fat32 => (entry & FAT32_MASK) >= 0x0FFF_FFF8,
        }
    }

    /// Return `true` if `entry` is a free cluster.
    pub fn is_free(self, entry: u32) -> bool {
        entry == 0
    }

    /// Mask an entry to the valid bit width.
    pub fn mask(self, entry: u32) -> u32 {
        match self {
            Self::Fat12 => entry & 0xFFF,
            Self::Fat16 => entry & 0xFFFF,
            Self::Fat32 => entry & FAT32_MASK,
        }
    }
}

// ── FAT Table ─────────────────────────────────────────────────────────────────

/// In-memory representation of a FAT (cluster chain table).
pub struct FatTable {
    /// Flat cluster entry array (index = cluster number).
    entries: Vec<u32>,
    /// Filesystem variant.
    pub fat_type: FatType,
    /// Total number of data clusters.
    pub total_clusters: usize,
    /// Number of free clusters.
    pub free_clusters: usize,
    /// Hint for free cluster search (next-free pointer).
    next_free: usize,
}

impl FatTable {
    /// Create a new all-free FAT table with `total_clusters` data clusters.
    ///
    /// Cluster numbers 0 and 1 are reserved; data starts at 2.
    pub fn new(total_clusters: usize, fat_type: FatType) -> Self {
        let count = (total_clusters + 2).min(MAX_CLUSTERS);
        let mut entries = Vec::new();
        entries.resize(count, 0u32);
        // Reserve cluster 0 (BPB copy) and cluster 1 (EOC for root dir on FAT32).
        if count > 0 {
            entries[0] = 0xFFFF_FF00 | 0xF8; // media byte in low 8 bits
        }
        if count > 1 {
            entries[1] = fat_type.eoc();
        }
        Self {
            free_clusters: total_clusters,
            entries,
            fat_type,
            total_clusters,
            next_free: 2,
        }
    }

    /// Read the FAT entry for cluster `n`.
    pub fn get(&self, n: usize) -> Result<u32> {
        if n >= self.entries.len() {
            return Err(Error::InvalidArgument);
        }
        Ok(self.fat_type.mask(self.entries[n]))
    }

    /// Write the FAT entry for cluster `n`.
    pub fn set(&mut self, n: usize, val: u32) -> Result<()> {
        if n >= self.entries.len() {
            return Err(Error::InvalidArgument);
        }
        self.entries[n] = self.fat_type.mask(val);
        Ok(())
    }

    /// Follow the chain starting at `start`, returning all cluster numbers.
    pub fn read_chain(&self, start: usize) -> Result<Vec<usize>> {
        let mut chain = Vec::new();
        let mut cur = start;
        for _ in 0..MAX_CHAIN {
            if cur < 2 || cur >= self.entries.len() {
                break;
            }
            chain.push(cur);
            let next = self.fat_type.mask(self.entries[cur]) as usize;
            if self.fat_type.is_eoc(next as u32) {
                break;
            }
            if self.fat_type.is_free(next as u32) {
                return Err(Error::IoError); // corrupt chain
            }
            cur = next;
        }
        Ok(chain)
    }

    /// Allocate a free cluster and mark it as EOC, returning its index.
    pub fn alloc_cluster(&mut self) -> Result<usize> {
        let start = self.next_free;
        let len = self.entries.len();
        // Linear scan from hint.
        for delta in 0..len {
            let c = (start + delta) % len;
            if c < 2 {
                continue;
            }
            if self.fat_type.is_free(self.entries[c]) {
                self.entries[c] = self.fat_type.eoc();
                self.next_free = (c + 1) % len;
                self.free_clusters = self.free_clusters.saturating_sub(1);
                return Ok(c);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Extend the chain ending at cluster `tail` with a new cluster.
    /// Returns the new cluster number.
    pub fn extend_chain(&mut self, tail: usize) -> Result<usize> {
        let new_cluster = self.alloc_cluster()?;
        self.set(tail, new_cluster as u32)?;
        Ok(new_cluster)
    }

    /// Free the entire chain starting at `start`.
    pub fn free_chain(&mut self, start: usize) -> Result<()> {
        let chain = self.read_chain(start)?;
        for c in chain {
            self.set(c, 0)?;
            self.free_clusters = self.free_clusters.saturating_add(1);
        }
        Ok(())
    }
}

// ── File Handle ───────────────────────────────────────────────────────────────

/// Open FAT file state for sequential I/O.
#[derive(Debug, Clone)]
pub struct FatFileHandle {
    /// First cluster of the file (0 for empty files).
    pub first_cluster: usize,
    /// File size in bytes.
    pub file_size: u64,
    /// Current byte offset within the file.
    pub position: u64,
    /// Cluster containing the current position.
    pub cur_cluster: usize,
    /// Byte offset of `cur_cluster` start within the file.
    pub cur_cluster_offset: u64,
}

impl FatFileHandle {
    /// Create a new file handle for the file starting at `first_cluster`.
    pub fn new(first_cluster: usize, file_size: u64) -> Self {
        Self {
            first_cluster,
            file_size,
            position: 0,
            cur_cluster: first_cluster,
            cur_cluster_offset: 0,
        }
    }

    /// Return `true` if the file position is at or beyond EOF.
    pub fn is_eof(&self) -> bool {
        self.position >= self.file_size
    }
}

// ── Read ──────────────────────────────────────────────────────────────────────

/// Read `buf.len()` bytes from `file` in the filesystem described by `fat`.
///
/// `cluster_data_fn` must return a slice of `cluster_size` bytes for
/// the given cluster number. Returns the number of bytes actually read.
pub fn read_file(
    file: &mut FatFileHandle,
    fat: &FatTable,
    buf: &mut [u8],
    cluster_size: usize,
    cluster_data_fn: &dyn Fn(usize) -> Result<Vec<u8>>,
) -> Result<usize> {
    if buf.is_empty() || file.is_eof() {
        return Ok(0);
    }
    let to_read = buf.len().min((file.file_size - file.position) as usize);
    let mut read_total = 0usize;

    while read_total < to_read {
        let cluster_index = (file.position / cluster_size as u64) as usize;
        let offset_in_cluster = (file.position % cluster_size as u64) as usize;
        let available_in_cluster = cluster_size - offset_in_cluster;
        let to_copy = (to_read - read_total).min(available_in_cluster);

        // Walk the chain to find the cluster for `cluster_index`.
        let mut cur = file.first_cluster;
        for _ in 0..cluster_index {
            let next = fat.get(cur)? as usize;
            if fat.fat_type.is_eoc(next as u32) || fat.fat_type.is_free(next as u32) {
                return Err(Error::IoError);
            }
            cur = next;
        }

        let cluster_data = cluster_data_fn(cur)?;
        if cluster_data.len() < cluster_size {
            return Err(Error::IoError);
        }
        buf[read_total..read_total + to_copy]
            .copy_from_slice(&cluster_data[offset_in_cluster..offset_in_cluster + to_copy]);
        read_total += to_copy;
        file.position += to_copy as u64;
    }
    Ok(read_total)
}

// ── Write ─────────────────────────────────────────────────────────────────────

/// Write `data` into `file`, extending the cluster chain as needed.
///
/// `write_cluster_fn` must write exactly `cluster_size` bytes to the given
/// cluster (reading first if doing a partial write). Returns bytes written.
pub fn write_file(
    file: &mut FatFileHandle,
    fat: &mut FatTable,
    data: &[u8],
    cluster_size: usize,
    read_cluster_fn: &dyn Fn(usize) -> Result<Vec<u8>>,
    write_cluster_fn: &mut dyn FnMut(usize, &[u8]) -> Result<()>,
) -> Result<usize> {
    if data.is_empty() {
        return Ok(0);
    }
    let mut written = 0usize;

    // Ensure we have at least one cluster.
    if file.first_cluster == 0 {
        let c = fat.alloc_cluster()?;
        file.first_cluster = c;
        file.cur_cluster = c;
    }

    while written < data.len() {
        let cluster_index = (file.position / cluster_size as u64) as usize;
        let offset_in_cluster = (file.position % cluster_size as u64) as usize;
        let space_in_cluster = cluster_size - offset_in_cluster;
        let to_write = (data.len() - written).min(space_in_cluster);

        // Walk / extend chain to reach `cluster_index`.
        let mut cur = file.first_cluster;
        for _ in 0..cluster_index {
            let next = fat.get(cur)? as usize;
            if fat.fat_type.is_eoc(next as u32) {
                // Need a new cluster.
                cur = fat.extend_chain(cur)?;
            } else if fat.fat_type.is_free(next as u32) {
                return Err(Error::IoError);
            } else {
                cur = next;
            }
        }

        // Read-modify-write if partial cluster.
        let mut cluster_buf = if offset_in_cluster != 0 || to_write < cluster_size {
            let mut v = read_cluster_fn(cur)?;
            v.resize(cluster_size, 0);
            v
        } else {
            let mut v = Vec::new();
            v.resize(cluster_size, 0u8);
            v
        };

        cluster_buf[offset_in_cluster..offset_in_cluster + to_write]
            .copy_from_slice(&data[written..written + to_write]);
        write_cluster_fn(cur, &cluster_buf)?;

        written += to_write;
        file.position += to_write as u64;
        if file.position > file.file_size {
            file.file_size = file.position;
        }
    }
    Ok(written)
}

// ── Truncate ──────────────────────────────────────────────────────────────────

/// Truncate a file to `new_size` bytes, freeing excess clusters.
///
/// If `new_size` is 0, the entire chain is freed.
pub fn truncate_file(
    file: &mut FatFileHandle,
    fat: &mut FatTable,
    new_size: u64,
    cluster_size: usize,
) -> Result<()> {
    if new_size >= file.file_size {
        file.file_size = new_size;
        return Ok(());
    }
    let clusters_needed = if new_size == 0 {
        0
    } else {
        ((new_size + cluster_size as u64 - 1) / cluster_size as u64) as usize
    };

    // Walk to the last cluster we want to keep.
    if clusters_needed == 0 {
        if file.first_cluster != 0 {
            fat.free_chain(file.first_cluster)?;
            file.first_cluster = 0;
        }
    } else {
        let mut cur = file.first_cluster;
        for _ in 1..clusters_needed {
            let next = fat.get(cur)? as usize;
            if fat.fat_type.is_eoc(next as u32) {
                break;
            }
            cur = next;
        }
        // Detach and free everything after `cur`.
        let tail = fat.get(cur)? as usize;
        fat.set(cur, fat.fat_type.eoc())?;
        if !fat.fat_type.is_eoc(tail as u32) && !fat.fat_type.is_free(tail as u32) {
            fat.free_chain(tail)?;
        }
    }

    file.file_size = new_size;
    if file.position > new_size {
        file.position = new_size;
    }
    Ok(())
}
