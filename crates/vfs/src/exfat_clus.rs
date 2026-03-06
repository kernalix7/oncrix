// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! exFAT cluster chain and FAT management.
//!
//! exFAT (Extended File Allocation Table) is Microsoft's successor to FAT32,
//! designed for flash drives and large volumes. It uses a 32-bit cluster
//! allocation table with a simpler structure than FAT32.
//!
//! # Cluster Chain
//!
//! File data is organized in cluster chains. Each cluster number points to
//! the next cluster in the file, or to an end-of-chain marker. exFAT also
//! supports "no-FAT chains" (contiguous runs) for improved performance.
//!
//! # FAT Entry Values
//!
//! | Value range | Meaning |
//! |-------------|---------|
//! | 0x00000000 | Free cluster |
//! | 0x00000001 | Reserved |
//! | 0x00000002–0xFFFFFFF6 | Next cluster in chain |
//! | 0xFFFFFFF7 | Bad cluster |
//! | 0xFFFFFFF8–0xFFFFFFFF | End of chain |

use oncrix_lib::{Error, Result};

/// Minimum valid cluster number in exFAT.
pub const EXFAT_FIRST_CLUSTER: u32 = 2;

/// End-of-chain marker (any value ≥ this is EOC).
pub const EXFAT_EOC: u32 = 0xFFFFFFF8;

/// Free cluster marker.
pub const EXFAT_FREE: u32 = 0x00000000;

/// Bad cluster marker.
pub const EXFAT_BAD: u32 = 0xFFFFFFF7;

/// Maximum cluster count supported by exFAT.
pub const EXFAT_MAX_CLUSTERS: u32 = 0xFFFFFFF5;

/// Returns `true` if `val` is an end-of-chain marker.
pub const fn is_eoc(val: u32) -> bool {
    val >= EXFAT_EOC
}

/// Returns `true` if `val` is a free cluster marker.
pub const fn is_free(val: u32) -> bool {
    val == EXFAT_FREE
}

/// Returns `true` if `val` is a valid next-cluster pointer.
pub const fn is_next(val: u32) -> bool {
    val >= EXFAT_FIRST_CLUSTER && val <= EXFAT_MAX_CLUSTERS
}

/// exFAT boot sector fields needed for cluster arithmetic.
#[derive(Clone, Copy, Default)]
pub struct ExfatBootSector {
    /// Volume length in sectors.
    pub volume_length: u64,
    /// FAT offset from volume start (in sectors).
    pub fat_offset: u32,
    /// FAT length in sectors.
    pub fat_length: u32,
    /// Cluster heap offset from volume start (in sectors).
    pub cluster_heap_offset: u32,
    /// Total number of clusters in the volume.
    pub cluster_count: u32,
    /// First cluster of the root directory.
    pub first_cluster_of_root_dir: u32,
    /// Log₂ of the bytes-per-sector (typically 9 for 512-byte sectors).
    pub bytes_per_sector_shift: u8,
    /// Log₂ of the sectors-per-cluster.
    pub sectors_per_cluster_shift: u8,
}

impl ExfatBootSector {
    /// Returns the number of bytes per cluster.
    pub fn bytes_per_cluster(&self) -> u64 {
        1u64 << (self.bytes_per_sector_shift + self.sectors_per_cluster_shift)
    }

    /// Returns the byte offset on disk for a given cluster number.
    pub fn cluster_to_byte_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < EXFAT_FIRST_CLUSTER || cluster > self.cluster_count + 1 {
            return Err(Error::InvalidArgument);
        }
        let sector = (self.cluster_heap_offset as u64)
            + ((cluster as u64 - EXFAT_FIRST_CLUSTER as u64) << self.sectors_per_cluster_shift);
        Ok(sector << self.bytes_per_sector_shift)
    }

    /// Returns the byte offset of the FAT for `cluster`.
    pub fn fat_entry_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < EXFAT_FIRST_CLUSTER {
            return Err(Error::InvalidArgument);
        }
        let fat_byte_off =
            ((self.fat_offset as u64) << self.bytes_per_sector_shift) + (cluster as u64 * 4);
        Ok(fat_byte_off)
    }
}

/// In-memory FAT cache for a contiguous region of clusters.
///
/// Holds FAT entries for clusters `[base_cluster, base_cluster + len)`.
pub struct FatCache {
    /// FAT entries.
    entries: [u32; 512],
    /// Number of valid entries.
    len: usize,
    /// Cluster number of the first entry.
    base_cluster: u32,
    /// Whether any entry has been modified.
    dirty: bool,
}

impl Default for FatCache {
    fn default() -> Self {
        Self {
            entries: [0u32; 512],
            len: 0,
            base_cluster: EXFAT_FIRST_CLUSTER,
            dirty: false,
        }
    }
}

impl FatCache {
    /// Loads FAT entries from raw bytes (little-endian u32 per entry).
    pub fn load(&mut self, base_cluster: u32, data: &[u8]) -> Result<()> {
        let count = data.len() / 4;
        if count > 512 {
            return Err(Error::InvalidArgument);
        }
        for i in 0..count {
            self.entries[i] = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
        }
        self.len = count;
        self.base_cluster = base_cluster;
        self.dirty = false;
        Ok(())
    }

    /// Returns the FAT entry for `cluster`, if cached.
    pub fn get(&self, cluster: u32) -> Option<u32> {
        let idx = cluster.checked_sub(self.base_cluster)? as usize;
        if idx < self.len {
            Some(self.entries[idx])
        } else {
            None
        }
    }

    /// Sets the FAT entry for `cluster`.
    pub fn set(&mut self, cluster: u32, value: u32) -> Result<()> {
        let idx = cluster
            .checked_sub(self.base_cluster)
            .ok_or(Error::InvalidArgument)? as usize;
        if idx >= self.len {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx] = value;
        self.dirty = true;
        Ok(())
    }

    /// Returns `true` if the cache contains modified entries.
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Serializes the cache back to a byte buffer.
    pub fn serialize(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < self.len * 4 {
            return Err(Error::InvalidArgument);
        }
        for i in 0..self.len {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.entries[i].to_le_bytes());
        }
        Ok(())
    }
}

/// Walks a cluster chain starting at `start_cluster` using a FAT cache.
///
/// Calls `f(cluster)` for each cluster in the chain.
/// Returns the total number of clusters visited.
pub fn walk_chain<F>(cache: &FatCache, start_cluster: u32, mut f: F) -> Result<u32>
where
    F: FnMut(u32) -> Result<()>,
{
    let mut current = start_cluster;
    let mut count = 0u32;

    loop {
        if !is_next(current) {
            return Err(Error::InvalidArgument);
        }
        f(current)?;
        count += 1;

        let next = cache.get(current).ok_or(Error::NotFound)?;
        if is_eoc(next) {
            break;
        }
        if !is_next(next) {
            return Err(Error::IoError);
        }
        current = next;
    }
    Ok(count)
}

/// Bitmap-based free cluster allocator for exFAT.
///
/// exFAT stores an allocation bitmap in the data area. Each bit corresponds
/// to one cluster: 0 = free, 1 = allocated.
pub struct AllocationBitmap {
    /// Bitmap data (bit-packed, 1 bit per cluster).
    bits: [u8; 8192],
    /// Total number of clusters tracked.
    cluster_count: u32,
    /// Index (in bits) of the next allocation hint.
    next_hint: u32,
}

impl Default for AllocationBitmap {
    fn default() -> Self {
        Self {
            bits: [0u8; 8192],
            cluster_count: 0,
            next_hint: 0,
        }
    }
}

impl AllocationBitmap {
    /// Initializes the bitmap from raw data.
    pub fn load(&mut self, data: &[u8], cluster_count: u32) -> Result<()> {
        let bytes_needed = ((cluster_count + 7) / 8) as usize;
        if data.len() < bytes_needed || bytes_needed > 8192 {
            return Err(Error::InvalidArgument);
        }
        self.bits[..bytes_needed].copy_from_slice(&data[..bytes_needed]);
        self.cluster_count = cluster_count;
        self.next_hint = 0;
        Ok(())
    }

    fn is_allocated(&self, cluster: u32) -> bool {
        let idx = cluster as usize;
        (self.bits[idx / 8] >> (idx % 8)) & 1 != 0
    }

    fn set_allocated(&mut self, cluster: u32, allocated: bool) {
        let idx = cluster as usize;
        if allocated {
            self.bits[idx / 8] |= 1 << (idx % 8);
        } else {
            self.bits[idx / 8] &= !(1 << (idx % 8));
        }
    }

    /// Allocates the next free cluster, starting from the hint.
    pub fn allocate(&mut self) -> Result<u32> {
        let start = self.next_hint;
        let mut c = start;
        loop {
            if c >= self.cluster_count {
                c = 0;
            }
            if c == start && c != 0 {
                return Err(Error::OutOfMemory);
            }
            if !self.is_allocated(c) {
                self.set_allocated(c, true);
                self.next_hint = (c + 1) % self.cluster_count;
                return Ok(c + EXFAT_FIRST_CLUSTER);
            }
            c += 1;
        }
    }

    /// Frees a cluster.
    pub fn free(&mut self, cluster: u32) -> Result<()> {
        if cluster < EXFAT_FIRST_CLUSTER || cluster >= self.cluster_count + EXFAT_FIRST_CLUSTER {
            return Err(Error::InvalidArgument);
        }
        let idx = cluster - EXFAT_FIRST_CLUSTER;
        self.set_allocated(idx, false);
        Ok(())
    }
}
