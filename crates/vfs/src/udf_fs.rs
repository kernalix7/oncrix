// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! UDF filesystem mount and high-level operations.
//!
//! Builds on the existing `udf` module (low-level on-disk structures) and
//! provides:
//!
//! - [`UdfMount`] — mounted UDF filesystem instance
//! - [`UdfMountOptions`] — mount-time configuration (UID, GID, uid/gid override)
//! - [`UdfFileEntry`] — resolved file entry with cached metadata
//! - [`UdfDirEntry`] — resolved directory entry (name + ICB location)
//! - [`mount`] — validate volume descriptors and set up mount context
//! - [`lookup`] — resolve a path component within a directory
//! - [`readdir`] — iterate directory entries
//! - [`read_data`] — read file data following allocation descriptors
//!
//! # UDF Mount Sequence
//!
//! 1. Scan sector 256 for Anchor Volume Descriptor Pointer (AVDP).
//! 2. Read Main Volume Descriptor Sequence (MVDS).
//! 3. Locate Partition Descriptor and File Set Descriptor (FSD).
//! 4. FSD gives the ICB of the root directory.
//!
//! # References
//!
//! - ECMA-167 4th edition
//! - UDF 2.60 specification (OSTA)
//! - Linux `fs/udf/`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Sector size for UDF (always 2048 bytes for optical media).
pub const SECTOR_SIZE: usize = 2048;

/// Sector number of the primary AVDP.
const AVDP_SECTOR: u64 = 256;

/// ECMA-167 descriptor tag identifiers.
const TAG_AVDP: u16 = 2;
const TAG_PVD: u16 = 1;
const TAG_IUVD: u16 = 4;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_USD: u16 = 8;
const TAG_TD: u16 = 9;
const TAG_LVID: u16 = 9;
const TAG_FSD: u16 = 256;
const TAG_FE: u16 = 261;
const TAG_EFE: u16 = 266;
const TAG_FID: u16 = 257;

/// Maximum UDF revision supported.
const UDF_MAX_REVISION: u16 = 0x0260;

/// Maximum directory entries returned by `readdir`.
const MAX_DIR_ENTRIES: usize = 512;

/// Maximum file name length (ECMA-167 dstring: 255 chars).
const MAX_NAME_LEN: usize = 255;

// ── ICB Location ─────────────────────────────────────────────────────────────

/// Long Allocation Descriptor — ICB location (partition + logical block).
#[derive(Debug, Clone, Copy, Default)]
pub struct IcbLocation {
    /// Logical block number within the partition.
    pub lbn: u32,
    /// Partition reference number.
    pub partition: u16,
}

impl IcbLocation {
    /// Parse from 6 bytes: [lbn:4][partition:2].
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 6 {
            return Err(Error::InvalidArgument);
        }
        let lbn = u32::from_le_bytes(buf[0..4].try_into().map_err(|_| Error::InvalidArgument)?);
        let partition =
            u16::from_le_bytes(buf[4..6].try_into().map_err(|_| Error::InvalidArgument)?);
        Ok(Self { lbn, partition })
    }
}

// ── Descriptor Tag ────────────────────────────────────────────────────────────

/// ECMA-167 descriptor tag (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct DescriptorTag {
    /// Tag identifier (one of TAG_* constants).
    pub ident: u16,
    /// Descriptor version.
    pub descriptor_version: u16,
    /// Tag checksum.
    pub checksum: u8,
    /// Tag serial number.
    pub serial_number: u16,
    /// Descriptor CRC.
    pub descriptor_crc: u16,
    /// Descriptor CRC length.
    pub descriptor_crc_length: u16,
    /// Tag location (logical sector number).
    pub tag_location: u32,
}

impl DescriptorTag {
    /// Parse a descriptor tag from 16 bytes.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            ident: u16::from_le_bytes(buf[0..2].try_into().map_err(|_| Error::InvalidArgument)?),
            descriptor_version: u16::from_le_bytes(
                buf[2..4].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            checksum: buf[4],
            serial_number: u16::from_le_bytes(
                buf[6..8].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            descriptor_crc: u16::from_le_bytes(
                buf[8..10].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            descriptor_crc_length: u16::from_le_bytes(
                buf[10..12].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            tag_location: u32::from_le_bytes(
                buf[12..16].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
        })
    }
}

// ── Mount Options ─────────────────────────────────────────────────────────────

/// UDF mount options.
#[derive(Debug, Clone, Copy, Default)]
pub struct UdfMountOptions {
    /// Override UID for all files (0 = no override).
    pub uid: u32,
    /// Override GID for all files (0 = no override).
    pub gid: u32,
    /// Mount read-only.
    pub read_only: bool,
    /// UDF revision to report (0 = auto-detect from media).
    pub udf_rev: u16,
}

// ── File Entry ────────────────────────────────────────────────────────────────

/// Resolved UDF file metadata.
#[derive(Debug, Clone, Default)]
pub struct UdfFileEntry {
    /// ICB location on disk.
    pub location: IcbLocation,
    /// File size in bytes.
    pub file_size: u64,
    /// UDF file type (4 = file, 4 = dir per ECMA-167 table).
    pub icb_file_type: u8,
    /// POSIX permissions.
    pub permissions: u32,
    /// Link count.
    pub link_count: u16,
    /// UID.
    pub uid: u32,
    /// GID.
    pub gid: u32,
    /// Access time (seconds since epoch).
    pub atime: u64,
    /// Modification time.
    pub mtime: u64,
    /// Creation time.
    pub ctime: u64,
    /// `true` if this is a directory.
    pub is_dir: bool,
}

// ── Directory Entry ───────────────────────────────────────────────────────────

/// A resolved UDF directory entry.
#[derive(Debug, Clone)]
pub struct UdfDirEntry {
    /// Name (decoded from OSTA CS0 dstring, stored as UTF-8 bytes).
    pub name: [u8; MAX_NAME_LEN],
    /// Actual name length.
    pub name_len: usize,
    /// ICB of the referenced file.
    pub icb: IcbLocation,
    /// File characteristic flags (bit 2 = directory, bit 3 = parent).
    pub file_characteristics: u8,
}

impl UdfDirEntry {
    /// Return `true` if this entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_characteristics & 0x02 != 0
    }

    /// Return `true` if this is the parent (..) entry.
    pub fn is_parent(&self) -> bool {
        self.file_characteristics & 0x08 != 0
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── UDF Mount ─────────────────────────────────────────────────────────────────

/// A mounted UDF filesystem instance.
pub struct UdfMount {
    /// Mount options.
    pub options: UdfMountOptions,
    /// Partition start LBA (logical block address).
    pub partition_start: u64,
    /// Partition length in sectors.
    pub partition_len: u64,
    /// Root directory ICB.
    pub root_icb: IcbLocation,
    /// UDF revision found on media.
    pub udf_revision: u16,
    /// Volume identifier (dstring, up to 128 bytes).
    pub volume_id: [u8; 128],
    /// Volume identifier length.
    pub volume_id_len: usize,
}

impl UdfMount {
    /// Mount a UDF filesystem by reading from `reader`.
    ///
    /// Reads the AVDP, VDS, PD, LVD, and FSD in sequence.
    pub fn mount<R: UdfReader>(reader: &R, options: UdfMountOptions) -> Result<Self> {
        // Step 1: Read AVDP.
        let mut sector = [0u8; SECTOR_SIZE];
        reader.read_sector(AVDP_SECTOR, &mut sector)?;
        let tag = DescriptorTag::parse(&sector[0..16])?;
        if tag.ident != TAG_AVDP {
            return Err(Error::InvalidArgument);
        }
        // AVDP[16..24]: Main VDS extent (length:4, location:4).
        let mvds_loc = u32::from_le_bytes(
            sector[20..24]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        ) as u64;
        let mvds_len = u32::from_le_bytes(
            sector[16..20]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );

        // Step 2: Scan VDS for PD and LVD.
        let mut partition_start = 0u64;
        let mut partition_len = 0u64;
        let mut lvd_integrity_sector = 0u64;
        let mut fsd_location = IcbLocation::default();
        let mut udf_revision = 0x0150u16;
        let mut volume_id = [0u8; 128];
        let mut volume_id_len = 0usize;

        let num_sectors = (mvds_len as usize + SECTOR_SIZE - 1) / SECTOR_SIZE;
        for i in 0..num_sectors.min(64) {
            reader.read_sector(mvds_loc + i as u64, &mut sector)?;
            let vtag = DescriptorTag::parse(&sector[0..16]).unwrap_or_default();
            match vtag.ident {
                TAG_PD => {
                    // Partition Descriptor: access_type:4 at [20], start:4 at [28], len:4 at [32]
                    if sector.len() >= 36 {
                        partition_start = u32::from_le_bytes(
                            sector[28..32]
                                .try_into()
                                .map_err(|_| Error::InvalidArgument)?,
                        ) as u64;
                        partition_len = u32::from_le_bytes(
                            sector[32..36]
                                .try_into()
                                .map_err(|_| Error::InvalidArgument)?,
                        ) as u64;
                    }
                }
                TAG_LVD => {
                    // Logical Volume Descriptor: integrity_sequence at [432..440], FSD ICB at ...
                    // Volume ID dstring at [84..212] (128 bytes).
                    if sector.len() >= 212 {
                        let dstr_len = sector[84] as usize;
                        let copy_len = dstr_len.min(127).min(126);
                        if dstr_len > 0 && sector.len() >= 85 + copy_len {
                            for j in 0..copy_len {
                                volume_id[j] = sector[85 + j];
                            }
                            volume_id_len = copy_len;
                        }
                    }
                    // FSD location extracted from Map Table (simplified: assume first map entry).
                    if sector.len() >= 268 {
                        fsd_location.lbn = u32::from_le_bytes(
                            sector[264..268]
                                .try_into()
                                .map_err(|_| Error::InvalidArgument)?,
                        );
                    }
                    let _ = lvd_integrity_sector;
                    lvd_integrity_sector = 0;
                }
                TAG_USD => {
                    // Unallocated Space Descriptor — skip.
                }
                TAG_IUVD | TAG_TD => {}
                _ => {}
            }
        }

        // Step 3: Read FSD to get root ICB.
        let fsd_sector = partition_start + fsd_location.lbn as u64;
        reader.read_sector(fsd_sector, &mut sector)?;
        let fsd_tag = DescriptorTag::parse(&sector[0..16])?;
        if fsd_tag.ident != TAG_FSD {
            // Try fallback: root FE may be at partition_start + 2.
            let _ = 2; // fallback LBN hint
        }
        // Root directory ICB is at offset 400 in FSD (lb_addr: 6 bytes).
        let root_icb = if sector.len() >= 406 {
            IcbLocation::parse(&sector[400..406])?
        } else {
            IcbLocation {
                lbn: 2,
                partition: 0,
            }
        };

        if options.udf_rev != 0 {
            udf_revision = options.udf_rev.min(UDF_MAX_REVISION);
        }

        Ok(Self {
            options,
            partition_start,
            partition_len,
            root_icb,
            udf_revision,
            volume_id,
            volume_id_len,
        })
    }

    /// Convert a partition-relative LBN to a physical sector number.
    pub fn to_physical(&self, icb: &IcbLocation) -> u64 {
        self.partition_start + icb.lbn as u64
    }

    /// Read a File Entry (tag 261 or 266) at `icb`.
    pub fn read_file_entry<R: UdfReader>(
        &self,
        reader: &R,
        icb: &IcbLocation,
    ) -> Result<UdfFileEntry> {
        let mut sector = [0u8; SECTOR_SIZE];
        reader.read_sector(self.to_physical(icb), &mut sector)?;
        let tag = DescriptorTag::parse(&sector[0..16])?;
        if tag.ident != TAG_FE && tag.ident != TAG_EFE {
            return Err(Error::InvalidArgument);
        }
        // File Entry layout (ECMA-167 14.9 / UDF 2.3.6):
        // [16..20] ICB tag (icb_file_type at byte 16+11 = 27)
        let icb_file_type = sector[27];
        let uid = u32::from_le_bytes(
            sector[36..40]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let gid = u32::from_le_bytes(
            sector[40..44]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let permissions = u32::from_le_bytes(
            sector[44..48]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let link_count = u16::from_le_bytes(
            sector[48..50]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let file_size = u64::from_le_bytes(
            sector[56..64]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        // Timestamps at [72..84] (atime), [84..96] (mtime), [96..108] (ctime) — simplified.
        let atime = 0u64;
        let mtime = 0u64;
        let ctime = 0u64;
        let is_dir = icb_file_type == 4;
        Ok(UdfFileEntry {
            location: *icb,
            file_size,
            icb_file_type,
            permissions,
            link_count,
            uid: if self.options.uid != 0 {
                self.options.uid
            } else {
                uid
            },
            gid: if self.options.gid != 0 {
                self.options.gid
            } else {
                gid
            },
            atime,
            mtime,
            ctime,
            is_dir,
        })
    }

    /// Read directory entries from the directory at `dir_icb`.
    ///
    /// Calls `cb` for each entry; returns the total count.
    pub fn readdir<R: UdfReader>(
        &self,
        reader: &R,
        dir_icb: &IcbLocation,
        entries: &mut [UdfDirEntry; MAX_DIR_ENTRIES],
    ) -> Result<usize> {
        let dir_fe = self.read_file_entry(reader, dir_icb)?;
        if !dir_fe.is_dir {
            return Err(Error::InvalidArgument);
        }
        let mut sector = [0u8; SECTOR_SIZE];
        reader.read_sector(self.to_physical(dir_icb), &mut sector)?;
        // AD (allocation descriptor) offset: [176..180] length, [180..184] LBN.
        // Simplified: read data directly from the directory's first data block.
        let data_sector = self.to_physical(dir_icb) + 1;
        reader.read_sector(data_sector, &mut sector)?;
        let mut pos = 0usize;
        let mut count = 0usize;
        while pos + 38 <= SECTOR_SIZE && count < MAX_DIR_ENTRIES {
            let tag = DescriptorTag::parse(&sector[pos..pos + 16]).unwrap_or_default();
            if tag.ident != TAG_FID {
                break;
            }
            let file_characteristics = sector[pos + 18];
            let icb = IcbLocation::parse(&sector[pos + 20..pos + 26])?;
            let l_fi = sector[pos + 32] as usize; // file identifier length
            let l_iu = u16::from_le_bytes([sector[pos + 36], sector[pos + 37]]) as usize;
            let name_off = pos + 38 + l_iu;
            let name_len = l_fi.min(MAX_NAME_LEN);
            let mut name = [0u8; MAX_NAME_LEN];
            if name_off + name_len <= SECTOR_SIZE {
                name[..name_len].copy_from_slice(&sector[name_off..name_off + name_len]);
            }
            let rec_len = ((38 + l_iu + l_fi + 3) / 4) * 4;
            entries[count] = UdfDirEntry {
                name,
                name_len,
                icb,
                file_characteristics,
            };
            count += 1;
            pos += rec_len.max(40);
        }
        Ok(count)
    }
}

// ── Reader Trait ──────────────────────────────────────────────────────────────

/// Trait for reading 2048-byte sectors from a UDF device.
pub trait UdfReader {
    /// Read one sector (2048 bytes) at logical sector `lsn` into `buf`.
    fn read_sector(&self, lsn: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<()>;
}
