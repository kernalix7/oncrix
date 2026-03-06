// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT32 File Allocation Table operations.
//!
//! The FAT32 FAT is an array of 32-bit entries (only 28 bits are used) where
//! each entry describes the state of the corresponding cluster: free, used
//! (pointing to the next cluster in a chain), bad, or end-of-chain.
//!
//! # Entry encoding
//!
//! | Value range | Meaning |
//! |-------------|---------|
//! | `0x0000_0000` | Free cluster |
//! | `0x0000_0002`–`0x0FFF_FFEF` | Next cluster in chain |
//! | `0x0FFF_FFF0`–`0x0FFF_FFF6` | Reserved |
//! | `0x0FFF_FFF7` | Bad cluster |
//! | `0x0FFF_FFF8`–`0x0FFF_FFFF` | End of chain (EOF) |
//!
//! # Design
//!
//! - [`FatEntry`] — typed FAT entry interpretation
//! - [`FatTable`] — in-memory FAT with read/write/walk operations
//!
//! # References
//!
//! - Microsoft FAT32 File System Specification, December 2000
//! - Linux `fs/fat/fat.h`, `fs/fat/fatent.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum clusters tracked by this in-memory FAT (32 MiB ÷ 4 KiB cluster).
const MAX_CLUSTERS: usize = 8192;

/// FAT32 mask: only the low 28 bits of each entry carry data.
const FAT32_MASK: u32 = 0x0FFF_FFFF;

/// First valid cluster number for file data.
pub const FAT_FIRST_DATA_CLUSTER: u32 = 2;

/// Cluster 0 holds the media type byte + reserved bits.
const FAT_MEDIA_BYTE_CLUSTER: u32 = 0;

/// Cluster 1 holds EOC marker + dirty/clean bits.
const FAT_EOC_MARKER_CLUSTER: u32 = 1;

/// End-of-chain marker (EOF) stored in FAT.
pub const FAT32_EOF: u32 = 0x0FFF_FFFF;

/// Bad cluster marker.
pub const FAT32_BAD: u32 = 0x0FFF_FFF7;

/// Free cluster.
pub const FAT32_FREE: u32 = 0x0000_0000;

// ---------------------------------------------------------------------------
// FatEntry
// ---------------------------------------------------------------------------

/// Typed interpretation of a FAT32 entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatEntry {
    /// Cluster is free.
    Free,
    /// Cluster is allocated; next cluster in chain.
    Next(u32),
    /// Cluster is bad (hardware error).
    Bad,
    /// End of cluster chain.
    EndOfChain,
    /// Reserved (values 0xFFFFFFF0–0xFFFFFFF6).
    Reserved(u32),
}

impl FatEntry {
    /// Decode a raw 32-bit FAT32 entry value.
    pub fn from_raw(raw: u32) -> Self {
        let val = raw & FAT32_MASK;
        match val {
            FAT32_FREE => FatEntry::Free,
            0x0000_0001 => FatEntry::Reserved(val),
            0x0FFF_FFF7 => FatEntry::Bad,
            0x0FFF_FFF8..=0x0FFF_FFFF => FatEntry::EndOfChain,
            0x0FFF_FFF0..=0x0FFF_FFF6 => FatEntry::Reserved(val),
            n => FatEntry::Next(n),
        }
    }

    /// Encode this entry back to a raw 32-bit value.
    pub fn to_raw(self) -> u32 {
        match self {
            FatEntry::Free => FAT32_FREE,
            FatEntry::Next(n) => n & FAT32_MASK,
            FatEntry::Bad => FAT32_BAD,
            FatEntry::EndOfChain => FAT32_EOF,
            FatEntry::Reserved(n) => n & FAT32_MASK,
        }
    }

    /// Return `true` if this entry represents a free cluster.
    pub fn is_free(self) -> bool {
        self == FatEntry::Free
    }

    /// Return `true` if this entry is an end-of-chain marker.
    pub fn is_eof(self) -> bool {
        matches!(self, FatEntry::EndOfChain)
    }
}

// ---------------------------------------------------------------------------
// FatTable
// ---------------------------------------------------------------------------

/// In-memory representation of a FAT32 FAT sector.
///
/// Entries are indexed by cluster number. Clusters 0 and 1 are reserved
/// (media type and EOC marker respectively) and are not used for file data.
pub struct FatTable {
    /// Raw FAT entries (index = cluster number).
    entries: [u32; MAX_CLUSTERS],
    /// Total number of clusters (= entries that could hold data).
    total_clusters: u32,
    /// Next cluster to check during free-cluster scan (hint).
    alloc_hint: u32,
}

impl FatTable {
    /// Create a new FAT table for `total_clusters` data clusters.
    ///
    /// Cluster 0 is set to the media type / clean marker pattern.
    /// Cluster 1 is set to the EOC marker.
    /// All data clusters start as free.
    pub fn new(total_clusters: u32) -> Self {
        let clamped = (total_clusters as usize).min(MAX_CLUSTERS) as u32;
        let mut entries = [FAT32_FREE; MAX_CLUSTERS];
        // Cluster 0: media byte (0x0FFFFF00 | media_type); we use 0xFFFFFFF8.
        entries[FAT_MEDIA_BYTE_CLUSTER as usize] = 0x0FFFF_FF8;
        // Cluster 1: end-of-chain marker, clean bit set.
        entries[FAT_EOC_MARKER_CLUSTER as usize] = FAT32_EOF;
        Self {
            entries,
            total_clusters: clamped,
            alloc_hint: FAT_FIRST_DATA_CLUSTER,
        }
    }

    /// Read the FAT entry for `cluster`.
    ///
    /// Returns `Err(InvalidArgument)` if `cluster >= total_clusters`.
    pub fn read_fat_entry(&self, cluster: u32) -> Result<FatEntry> {
        if cluster as usize >= self.total_clusters as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(FatEntry::from_raw(self.entries[cluster as usize]))
    }

    /// Write a raw value to the FAT entry for `cluster`.
    ///
    /// The high 4 bits are preserved from the current entry (per FAT32 spec).
    ///
    /// Returns `Err(InvalidArgument)` if `cluster >= total_clusters`.
    pub fn write_fat_entry(&mut self, cluster: u32, entry: FatEntry) -> Result<()> {
        if cluster as usize >= self.total_clusters as usize {
            return Err(Error::InvalidArgument);
        }
        // Preserve the top 4 bits of the existing entry.
        let existing_high = self.entries[cluster as usize] & !FAT32_MASK;
        self.entries[cluster as usize] = existing_high | (entry.to_raw() & FAT32_MASK);
        Ok(())
    }

    /// Walk the cluster chain starting at `start_cluster`.
    ///
    /// Calls `f(cluster)` for each cluster in the chain (including the first).
    /// Stops at the end-of-chain marker, a bad cluster, a free cluster, or
    /// when `f` returns `Err`.
    pub fn fat_walk_chain<F>(&self, start_cluster: u32, mut f: F) -> Result<()>
    where
        F: FnMut(u32) -> Result<()>,
    {
        let mut current = start_cluster;
        let mut visited = 0u32;
        loop {
            if current < FAT_FIRST_DATA_CLUSTER || current >= self.total_clusters {
                return Err(Error::InvalidArgument);
            }
            f(current)?;
            visited += 1;
            if visited > self.total_clusters {
                // Cycle detected.
                return Err(Error::IoError);
            }
            match self.read_fat_entry(current)? {
                FatEntry::Next(next) => current = next,
                FatEntry::EndOfChain => return Ok(()),
                FatEntry::Bad => return Err(Error::IoError),
                FatEntry::Free => return Err(Error::InvalidArgument),
                FatEntry::Reserved(_) => return Err(Error::InvalidArgument),
            }
        }
    }

    /// Get the next cluster in the chain after `cluster`.
    ///
    /// Returns `Ok(Some(next))` for a chain continuation, `Ok(None)` at EOC,
    /// or `Err` on error.
    pub fn fat_get_next(&self, cluster: u32) -> Result<Option<u32>> {
        match self.read_fat_entry(cluster)? {
            FatEntry::Next(n) => Ok(Some(n)),
            FatEntry::EndOfChain => Ok(None),
            FatEntry::Bad => Err(Error::IoError),
            FatEntry::Free => Err(Error::InvalidArgument),
            FatEntry::Reserved(_) => Err(Error::InvalidArgument),
        }
    }

    /// Allocate one free cluster.
    ///
    /// Scans from `alloc_hint` for a free slot (linear scan with wrap-around).
    /// Returns the cluster number, or `Err(OutOfMemory)` if all clusters
    /// are in use.
    pub fn alloc_cluster(&mut self) -> Result<u32> {
        let start = self.alloc_hint;
        let total = self.total_clusters;
        let mut n = start;
        for _ in 0..total {
            if n < FAT_FIRST_DATA_CLUSTER {
                n = FAT_FIRST_DATA_CLUSTER;
            }
            if n >= total {
                n = FAT_FIRST_DATA_CLUSTER;
            }
            if FatEntry::from_raw(self.entries[n as usize]).is_free() {
                self.entries[n as usize] = FAT32_EOF; // Mark as EOC.
                self.alloc_hint = if n + 1 < total {
                    n + 1
                } else {
                    FAT_FIRST_DATA_CLUSTER
                };
                return Ok(n);
            }
            n += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Free the cluster chain starting at `start_cluster`.
    ///
    /// Sets each entry in the chain to `FAT32_FREE`.
    pub fn free_cluster_chain(&mut self, start_cluster: u32) -> Result<()> {
        let mut current = start_cluster;
        let mut iters = 0u32;
        loop {
            if current < FAT_FIRST_DATA_CLUSTER || current >= self.total_clusters {
                break;
            }
            let next = self.fat_get_next(current)?;
            self.entries[current as usize] = FAT32_FREE;
            // Update hint to point to newly freed cluster.
            if current < self.alloc_hint {
                self.alloc_hint = current;
            }
            iters += 1;
            if iters > self.total_clusters {
                return Err(Error::IoError);
            }
            match next {
                Some(n) => current = n,
                None => break,
            }
        }
        Ok(())
    }

    /// Count the number of free clusters.
    pub fn free_cluster_count(&self) -> u32 {
        self.entries[FAT_FIRST_DATA_CLUSTER as usize..self.total_clusters as usize]
            .iter()
            .filter(|&&e| e & FAT32_MASK == FAT32_FREE)
            .count() as u32
    }

    /// Return total clusters (including reserved 0 and 1).
    pub fn total_clusters(&self) -> u32 {
        self.total_clusters
    }
}
