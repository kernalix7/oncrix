// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT32 cluster chain navigation and allocation.
//!
//! FAT32 uses a File Allocation Table to map cluster numbers to their
//! successors in a linked list (cluster chain). Each 32-bit FAT entry
//! holds either the next cluster number, a special marker (free, bad,
//! end-of-chain), or a reserved value.
//!
//! # FAT Entry Values
//!
//! | Value | Meaning |
//! |-------|---------|
//! | 0x00000000 | Free cluster |
//! | 0x00000001 | Reserved |
//! | 0x00000002–0x0FFFFFF6 | Next cluster |
//! | 0x0FFFFFF7 | Bad cluster |
//! | 0x0FFFFFF8–0x0FFFFFFF | End of chain |
//!
//! Note: FAT32 uses only the lower 28 bits; the upper 4 bits are reserved.
//!
//! # Cluster Arithmetic
//!
//! Data starts at cluster 2. Given the root cluster and boot sector fields,
//! the byte offset of any cluster is:
//! `offset = (cluster - 2) * sectors_per_cluster * bytes_per_sector + data_region_offset`

use oncrix_lib::{Error, Result};

/// End-of-chain sentinel (any value ≥ this).
pub const FAT32_EOC: u32 = 0x0FFFFFF8;

/// Free cluster value.
pub const FAT32_FREE: u32 = 0x0000_0000;

/// Bad cluster value.
pub const FAT32_BAD: u32 = 0x0FFF_FFF7;

/// Mask for the lower 28 bits of a FAT32 entry.
pub const FAT32_ENTRY_MASK: u32 = 0x0FFF_FFFF;

/// Returns `true` if `val` is an end-of-chain marker.
pub const fn fat32_is_eoc(val: u32) -> bool {
    (val & FAT32_ENTRY_MASK) >= FAT32_EOC
}

/// Returns `true` if `val` is a free cluster.
pub const fn fat32_is_free(val: u32) -> bool {
    (val & FAT32_ENTRY_MASK) == FAT32_FREE
}

/// Returns `true` if `val` is a valid next-cluster pointer.
pub const fn fat32_is_next(val: u32) -> bool {
    let masked = val & FAT32_ENTRY_MASK;
    masked >= 2 && masked <= 0x0FFF_FFF6
}

/// FAT32 boot sector fields required for cluster arithmetic.
#[derive(Clone, Copy, Default)]
pub struct Fat32BootSector {
    /// Bytes per sector (usually 512).
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Number of reserved sectors (where FATs start).
    pub reserved_sectors: u16,
    /// Number of FAT copies (usually 2).
    pub num_fats: u8,
    /// Sectors per FAT.
    pub fat_size: u32,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// Total sectors in the volume.
    pub total_sectors: u32,
}

impl Fat32BootSector {
    /// Returns the byte offset of the first FAT.
    pub fn fat_start_byte(&self) -> u64 {
        (self.reserved_sectors as u64) * (self.bytes_per_sector as u64)
    }

    /// Returns the byte offset of the data region (cluster 2).
    pub fn data_start_byte(&self) -> u64 {
        let fat_bytes =
            (self.num_fats as u64) * (self.fat_size as u64) * (self.bytes_per_sector as u64);
        self.fat_start_byte() + fat_bytes
    }

    /// Returns the byte size of one cluster.
    pub fn cluster_size_bytes(&self) -> u64 {
        (self.sectors_per_cluster as u64) * (self.bytes_per_sector as u64)
    }

    /// Returns the byte offset of cluster `clus` in the volume.
    pub fn cluster_to_byte(&self, clus: u32) -> Result<u64> {
        if !fat32_is_next(clus) {
            return Err(Error::InvalidArgument);
        }
        let rel = (clus as u64 - 2) * self.cluster_size_bytes();
        Ok(self.data_start_byte() + rel)
    }

    /// Returns the byte offset of the FAT entry for `clus`.
    pub fn fat_entry_byte(&self, clus: u32) -> u64 {
        self.fat_start_byte() + (clus as u64) * 4
    }
}

/// In-memory FAT32 cluster chain representation.
///
/// Stores a chain of cluster numbers for a single file.
pub struct Fat32Chain {
    /// Cluster numbers in chain order.
    clusters: [u32; 512],
    /// Number of clusters in the chain.
    len: usize,
    /// Cached current cluster for sequential access.
    current_idx: usize,
}

impl Default for Fat32Chain {
    fn default() -> Self {
        Self {
            clusters: [0u32; 512],
            len: 0,
            current_idx: 0,
        }
    }
}

impl Fat32Chain {
    /// Creates an empty chain.
    pub const fn new() -> Self {
        Self {
            clusters: [0u32; 512],
            len: 0,
            current_idx: 0,
        }
    }

    /// Appends a cluster to the chain.
    pub fn push(&mut self, clus: u32) -> Result<()> {
        if self.len >= 512 {
            return Err(Error::OutOfMemory);
        }
        self.clusters[self.len] = clus;
        self.len += 1;
        Ok(())
    }

    /// Returns the cluster number at position `idx`.
    pub fn get(&self, idx: usize) -> Option<u32> {
        if idx < self.len {
            Some(self.clusters[idx])
        } else {
            None
        }
    }

    /// Returns the cluster for the logical byte offset `byte_off`.
    ///
    /// `cluster_size` is the number of bytes per cluster.
    pub fn cluster_for_offset(&self, byte_off: u64, cluster_size: u64) -> Option<u32> {
        if cluster_size == 0 {
            return None;
        }
        let idx = (byte_off / cluster_size) as usize;
        self.get(idx)
    }

    /// Returns the number of clusters in the chain.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the chain is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the total size of the chain in bytes.
    pub fn total_bytes(&self, cluster_size: u64) -> u64 {
        (self.len as u64) * cluster_size
    }
}

/// Reads a FAT32 cluster chain from a raw FAT buffer.
///
/// `fat_data` is the entire FAT region. `start_cluster` is the first cluster.
/// Returns the chain, stopping at EOC or bad-cluster.
pub fn read_chain(fat_data: &[u8], start_cluster: u32) -> Result<Fat32Chain> {
    let mut chain = Fat32Chain::new();
    let mut current = start_cluster;

    loop {
        if !fat32_is_next(current) {
            return Err(Error::InvalidArgument);
        }
        chain.push(current)?;

        let off = (current as usize) * 4;
        if off + 4 > fat_data.len() {
            return Err(Error::IoError);
        }
        let next_raw = u32::from_le_bytes([
            fat_data[off],
            fat_data[off + 1],
            fat_data[off + 2],
            fat_data[off + 3],
        ]) & FAT32_ENTRY_MASK;

        if fat32_is_eoc(next_raw) {
            break;
        }
        if !fat32_is_next(next_raw) {
            return Err(Error::IoError);
        }
        current = next_raw;
    }
    Ok(chain)
}
