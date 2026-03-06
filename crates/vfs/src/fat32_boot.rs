// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT32 boot sector (BPB) parsing.
//!
//! Parses the FAT32 BIOS Parameter Block (BPB) from the first 512-byte
//! sector of a FAT32 volume. Extracts all geometry and layout parameters
//! needed to navigate the filesystem.
//!
//! # Structure
//!
//! - [`BpbFat32`] — raw on-disk boot sector layout (`repr(C, packed)`)
//! - [`Fat32Layout`] — derived layout parameters (computed from BPB fields)
//! - `parse_bpb` — validate magic and copy fields from a raw sector
//! - `compute_layout` — derive sector/cluster/FAT offsets from BPB
//!
//! # Reference
//!
//! Microsoft FAT32 File System Specification, version 1.03.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sector size in bytes (FAT32 only supports 512-byte sectors at boot).
const SECTOR_SIZE: usize = 512;

/// Boot sector signature bytes at offset 510-511.
const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// FAT32 extended boot signature.
const EXTENDED_BOOT_SIG: u8 = 0x29;

/// Minimum bytes per sector (must be 512 for FAT32).
const MIN_BYTES_PER_SECTOR: u16 = 512;

/// Maximum bytes per sector.
const MAX_BYTES_PER_SECTOR: u16 = 4096;

/// FAT32 media descriptor for fixed disk.
const MEDIA_FIXED_DISK: u8 = 0xF8;

/// Root directory first cluster for FAT32 (minimum value).
const MIN_ROOT_CLUSTER: u32 = 2;

/// Reserved cluster numbers.
const CLUSTER_FREE: u32 = 0x00000000;
const CLUSTER_BAD: u32 = 0x0FFFFFF7;
const CLUSTER_END: u32 = 0x0FFFFFF8;

// ---------------------------------------------------------------------------
// BPB structure
// ---------------------------------------------------------------------------

/// FAT32 BIOS Parameter Block — raw on-disk boot sector.
///
/// Fields are laid out exactly as on disk. All multi-byte values are
/// little-endian. The struct is `packed` to avoid padding.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct BpbFat32 {
    /// Jump instruction (3 bytes): e.g., 0xEB 0x58 0x90.
    pub jmp_boot: [u8; 3],
    /// OEM name string (8 bytes).
    pub oem_name: [u8; 8],
    /// Bytes per logical sector (must be 512, 1024, 2048, or 4096).
    pub bytes_per_sector: u16,
    /// Logical sectors per cluster (power of 2, 1..128).
    pub sectors_per_cluster: u8,
    /// Number of reserved sectors (includes boot sector). Typically 32 for FAT32.
    pub reserved_sectors: u16,
    /// Number of FATs (must be 2).
    pub num_fats: u8,
    /// Root entry count — must be 0 for FAT32.
    pub root_entry_count: u16,
    /// Total 16-bit sector count — must be 0 for FAT32.
    pub total_sectors_16: u16,
    /// Media descriptor.
    pub media_type: u8,
    /// Sectors per FAT (16-bit) — must be 0 for FAT32.
    pub fat_size_16: u16,
    /// Sectors per track (geometry).
    pub sectors_per_track: u16,
    /// Number of heads.
    pub num_heads: u16,
    /// Hidden sectors (LBA of the partition).
    pub hidden_sectors: u32,
    /// Total 32-bit sector count.
    pub total_sectors_32: u32,
    // --- FAT32 extended BPB ---
    /// FAT size in sectors (FAT32).
    pub fat_size_32: u32,
    /// Extended flags (active FAT, mirroring).
    pub ext_flags: u16,
    /// File system version (must be 0:0).
    pub fs_version: u16,
    /// First cluster of root directory.
    pub root_cluster: u32,
    /// Sector of FSINFO structure.
    pub fs_info: u16,
    /// Sector of backup boot sector.
    pub backup_boot_sec: u16,
    /// Reserved (must be zero).
    pub reserved: [u8; 12],
    /// Physical drive number.
    pub drive_num: u8,
    /// Reserved1 (must be zero).
    pub reserved1: u8,
    /// Extended boot signature (0x29).
    pub boot_sig: u8,
    /// Volume serial number.
    pub volume_id: u32,
    /// Volume label (11 bytes).
    pub volume_label: [u8; 11],
    /// File system type string (must be "FAT32   ").
    pub fs_type: [u8; 8],
}

/// Asserts the BPB is exactly 90 bytes (boot sector header region).
const _: () = assert!(core::mem::size_of::<BpbFat32>() == 90);

// ---------------------------------------------------------------------------
// Derived layout
// ---------------------------------------------------------------------------

/// Derived FAT32 layout parameters computed from the BPB.
#[derive(Debug, Clone, Copy)]
pub struct Fat32Layout {
    /// Bytes per sector.
    pub bytes_per_sector: u32,
    /// Sectors per cluster.
    pub sectors_per_cluster: u32,
    /// Bytes per cluster.
    pub bytes_per_cluster: u32,
    /// First FAT sector (absolute, after reserved sectors).
    pub fat_start_sector: u32,
    /// Number of sectors per FAT.
    pub fat_size_sectors: u32,
    /// First data sector (after reserved + FATs).
    pub data_start_sector: u32,
    /// Total data sectors.
    pub data_sectors: u32,
    /// Total clusters.
    pub total_clusters: u32,
    /// Root cluster number.
    pub root_cluster: u32,
    /// Total sectors on the volume.
    pub total_sectors: u32,
    /// Number of FATs.
    pub num_fats: u8,
    /// Volume serial number.
    pub volume_id: u32,
}

impl Fat32Layout {
    /// Converts a cluster number to its starting sector.
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_start_sector + (cluster - 2) * self.sectors_per_cluster
    }

    /// Returns whether a cluster number is valid (not free, bad, or reserved).
    pub fn is_valid_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster < CLUSTER_BAD && cluster <= self.total_clusters + 1
    }

    /// Returns whether a cluster number marks end-of-chain.
    pub fn is_end_cluster(&self, cluster: u32) -> bool {
        cluster >= CLUSTER_END
    }

    /// Returns the byte offset of a FAT entry for a given cluster.
    pub fn fat_entry_offset(&self, cluster: u32) -> u64 {
        self.fat_start_sector as u64 * self.bytes_per_sector as u64 + cluster as u64 * 4
    }

    /// Returns the second FAT start sector (for redundancy).
    pub fn fat2_start_sector(&self) -> u32 {
        self.fat_start_sector + self.fat_size_sectors
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses a FAT32 boot sector from a raw 512-byte sector.
///
/// Validates the boot signature (0x55, 0xAA), basic sanity checks on
/// the BPB fields, and returns a copy of the BPB.
pub fn parse_bpb(sector: &[u8; SECTOR_SIZE]) -> Result<BpbFat32> {
    // Check boot signature.
    if sector[510] != BOOT_SIGNATURE[0] || sector[511] != BOOT_SIGNATURE[1] {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: BpbFat32 is repr(C, packed) with no padding; reading from
    // a properly-sized byte slice is safe. We copy field-by-field to
    // avoid any unaligned access issues.
    let bps = u16::from_le_bytes([sector[11], sector[12]]);
    let spc = sector[13];
    let rsvd = u16::from_le_bytes([sector[14], sector[15]]);
    let nfats = sector[16];
    let root_cnt = u16::from_le_bytes([sector[17], sector[18]]);
    let total16 = u16::from_le_bytes([sector[19], sector[20]]);
    let media = sector[21];
    let fat16 = u16::from_le_bytes([sector[22], sector[23]]);
    let spt = u16::from_le_bytes([sector[24], sector[25]]);
    let heads = u16::from_le_bytes([sector[26], sector[27]]);
    let hidden = u32::from_le_bytes([sector[28], sector[29], sector[30], sector[31]]);
    let total32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
    let fat32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
    let ext_flags = u16::from_le_bytes([sector[40], sector[41]]);
    let fs_ver = u16::from_le_bytes([sector[42], sector[43]]);
    let root_clus = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
    let fsinfo = u16::from_le_bytes([sector[48], sector[49]]);
    let backup = u16::from_le_bytes([sector[50], sector[51]]);
    let drive = sector[64];
    let rsv1 = sector[65];
    let boot_sig_byte = sector[66];
    let vol_id = u32::from_le_bytes([sector[67], sector[68], sector[69], sector[70]]);

    let mut jmp = [0u8; 3];
    jmp.copy_from_slice(&sector[0..3]);
    let mut oem = [0u8; 8];
    oem.copy_from_slice(&sector[3..11]);
    let mut rsvd_arr = [0u8; 12];
    rsvd_arr.copy_from_slice(&sector[52..64]);
    let mut vol_label = [0u8; 11];
    vol_label.copy_from_slice(&sector[71..82]);
    let mut fstype = [0u8; 8];
    fstype.copy_from_slice(&sector[82..90]);

    let bpb = BpbFat32 {
        jmp_boot: jmp,
        oem_name: oem,
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        reserved_sectors: rsvd,
        num_fats: nfats,
        root_entry_count: root_cnt,
        total_sectors_16: total16,
        media_type: media,
        fat_size_16: fat16,
        sectors_per_track: spt,
        num_heads: heads,
        hidden_sectors: hidden,
        total_sectors_32: total32,
        fat_size_32: fat32,
        ext_flags,
        fs_version: fs_ver,
        root_cluster: root_clus,
        fs_info: fsinfo,
        backup_boot_sec: backup,
        reserved: rsvd_arr,
        drive_num: drive,
        reserved1: rsv1,
        boot_sig: boot_sig_byte,
        volume_id: vol_id,
        volume_label: vol_label,
        fs_type: fstype,
    };

    validate_bpb(&bpb)?;
    Ok(bpb)
}

/// Validates BPB field consistency.
pub fn validate_bpb(bpb: &BpbFat32) -> Result<()> {
    // FAT32 requirements.
    if bpb.root_entry_count != 0 {
        return Err(Error::InvalidArgument);
    }
    if bpb.total_sectors_16 != 0 {
        return Err(Error::InvalidArgument);
    }
    if bpb.fat_size_16 != 0 {
        return Err(Error::InvalidArgument);
    }
    if bpb.fat_size_32 == 0 {
        return Err(Error::InvalidArgument);
    }
    if bpb.total_sectors_32 == 0 {
        return Err(Error::InvalidArgument);
    }
    // Check bytes per sector.
    if bpb.bytes_per_sector < MIN_BYTES_PER_SECTOR || bpb.bytes_per_sector > MAX_BYTES_PER_SECTOR {
        return Err(Error::InvalidArgument);
    }
    // Check sectors per cluster is power of 2.
    let spc = bpb.sectors_per_cluster;
    if spc == 0 || (spc & (spc - 1)) != 0 || spc > 128 {
        return Err(Error::InvalidArgument);
    }
    // Check num_fats.
    if bpb.num_fats == 0 {
        return Err(Error::InvalidArgument);
    }
    // Check root cluster.
    if bpb.root_cluster < MIN_ROOT_CLUSTER {
        return Err(Error::InvalidArgument);
    }
    // Check reserved sectors.
    if bpb.reserved_sectors == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Computes the derived layout from a valid BPB.
pub fn compute_layout(bpb: &BpbFat32) -> Result<Fat32Layout> {
    let bps = bpb.bytes_per_sector as u32;
    let spc = bpb.sectors_per_cluster as u32;
    let rsvd = bpb.reserved_sectors as u32;
    let nfats = bpb.num_fats as u32;
    let fat_sz = bpb.fat_size_32;
    let total = bpb.total_sectors_32;

    let fat_start = rsvd;
    let data_start = rsvd + nfats * fat_sz;

    if data_start >= total {
        return Err(Error::InvalidArgument);
    }
    let data_secs = total - data_start;
    let total_clusters = data_secs / spc;

    Ok(Fat32Layout {
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        bytes_per_cluster: bps * spc,
        fat_start_sector: fat_start,
        fat_size_sectors: fat_sz,
        data_start_sector: data_start,
        data_sectors: data_secs,
        total_clusters,
        root_cluster: bpb.root_cluster,
        total_sectors: total,
        num_fats: bpb.num_fats,
        volume_id: bpb.volume_id,
    })
}
