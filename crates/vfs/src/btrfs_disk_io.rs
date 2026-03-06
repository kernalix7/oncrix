// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! btrfs disk I/O and checksumming.
//!
//! Provides the low-level I/O primitives used by all btrfs subsystems:
//!
//! - [`BtrfsChecksum`] — checksum algorithm selection and computation
//! - [`ChecksumType`] — CRC32C, xxHash, SHA-256, Blake2b
//! - [`DiskHeader`] — 65-byte on-disk header (magic + csum + UUID + gen)
//! - [`BtrfsDiskReader`] — trait for block device read/write
//! - [`read_tree_block`] — read and verify a tree block from disk
//! - [`write_tree_block`] — write a tree block with freshly computed checksum
//! - [`verify_header`] — validate a raw disk header
//!
//! # Checksum Design
//!
//! btrfs checksums all metadata and (optionally) data using one of four
//! algorithms selectable at mkfs time. The checksum occupies the first 32
//! bytes of every tree block header.
//!
//! # References
//!
//! - Linux `fs/btrfs/disk-io.c`, `fs/btrfs/check-integrity.c`
//! - btrfs specification: `Documentation/filesystems/btrfs/`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// btrfs superblock magic (`_BHRfS_M` little-endian).
pub const BTRFS_MAGIC: u64 = 0x4D5F_5346_5248_425F;

/// Size of a btrfs tree block (default nodesize = 16 KiB).
pub const BTRFS_NODESIZE: usize = 16_384;

/// Checksum field size in every on-disk header (bytes).
pub const BTRFS_CSUM_SIZE: usize = 32;

/// Offset of the UUID field in the disk header.
const UUID_OFFSET: usize = 32;

/// UUID size in bytes.
const UUID_SIZE: usize = 16;

/// Generation field offset (after UUID).
const GEN_OFFSET: usize = UUID_OFFSET + UUID_SIZE;

/// Bytenr (physical address) offset.
const BYTENR_OFFSET: usize = GEN_OFFSET + 8;

/// Flags offset.
const FLAGS_OFFSET: usize = BYTENR_OFFSET + 8;

/// Backref rev offset.
const BACKREF_REV_OFFSET: usize = FLAGS_OFFSET + 8;

/// Header size (sum of fields above + 1-byte type).
pub const DISK_HEADER_SIZE: usize = BACKREF_REV_OFFSET + 8 + 1;

/// Maximum block read size for a single I/O operation.
const MAX_READ_SIZE: usize = BTRFS_NODESIZE;

// ── Checksum Types ────────────────────────────────────────────────────────────

/// btrfs supported checksum algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum ChecksumType {
    /// CRC32C (default, fastest, 4-byte output, zero-padded to 32 bytes).
    #[default]
    Crc32c = 0,
    /// xxHash (fast, 8-byte output).
    XxHash = 1,
    /// SHA-256 (32-byte output, FIPS 140).
    Sha256 = 2,
    /// Blake2b-256 (32-byte output).
    Blake2b = 3,
}

impl ChecksumType {
    /// Construct from raw u16 value.
    pub fn from_raw(v: u16) -> Self {
        match v {
            0 => Self::Crc32c,
            1 => Self::XxHash,
            2 => Self::Sha256,
            3 => Self::Blake2b,
            _ => Self::Crc32c,
        }
    }
}

// ── Checksum State ────────────────────────────────────────────────────────────

/// Checksum engine for a specific algorithm.
pub struct BtrfsChecksum {
    algo: ChecksumType,
}

impl BtrfsChecksum {
    /// Create a new checksum engine for the given algorithm.
    pub const fn new(algo: ChecksumType) -> Self {
        Self { algo }
    }

    /// Compute the checksum of `data` and write the result into `out[..32]`.
    ///
    /// For CRC32C the 4-byte result is stored at `out[0..4]`, rest zeroed.
    pub fn compute(&self, data: &[u8], out: &mut [u8; BTRFS_CSUM_SIZE]) {
        *out = [0u8; BTRFS_CSUM_SIZE];
        match self.algo {
            ChecksumType::Crc32c => {
                let crc = crc32c(data);
                out[0..4].copy_from_slice(&crc.to_le_bytes());
            }
            ChecksumType::XxHash => {
                let h = xxhash64(data);
                out[0..8].copy_from_slice(&h.to_le_bytes());
            }
            ChecksumType::Sha256 | ChecksumType::Blake2b => {
                // Simplified stub: XOR-fold into 32 bytes.
                for (i, &b) in data.iter().enumerate() {
                    out[i % BTRFS_CSUM_SIZE] ^= b;
                }
            }
        }
    }

    /// Verify that the first `BTRFS_CSUM_SIZE` bytes of `block` are a valid
    /// checksum of `block[BTRFS_CSUM_SIZE..]`.
    pub fn verify(&self, block: &[u8]) -> bool {
        if block.len() < BTRFS_CSUM_SIZE {
            return false;
        }
        let mut expected = [0u8; BTRFS_CSUM_SIZE];
        self.compute(&block[BTRFS_CSUM_SIZE..], &mut expected);
        block[..BTRFS_CSUM_SIZE] == expected
    }
}

impl Default for BtrfsChecksum {
    fn default() -> Self {
        Self::new(ChecksumType::Crc32c)
    }
}

// ── CRC32C stub ───────────────────────────────────────────────────────────────

/// Software CRC32C (Castagnoli polynomial, reversed bit order).
fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Simplified xxHash64 (FNV-style stub for no_std compatibility).
fn xxhash64(data: &[u8]) -> u64 {
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15;
    for &b in data {
        h = h.wrapping_add(b as u64);
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        h ^= h >> 33;
    }
    h
}

// ── On-disk Header ────────────────────────────────────────────────────────────

/// Parsed btrfs on-disk tree block header.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskHeader {
    /// Checksum bytes [0..32].
    pub csum: [u8; BTRFS_CSUM_SIZE],
    /// Filesystem UUID [32..48].
    pub fsid: [u8; UUID_SIZE],
    /// Generation number (transaction ID when last written).
    pub generation: u64,
    /// Physical byte offset of this block on disk.
    pub bytenr: u64,
    /// Block flags (leaf/node, level, etc.).
    pub flags: u64,
    /// Back-reference revision.
    pub backref_rev: u64,
    /// Block type: 1 = leaf, 0 = internal node.
    pub level: u8,
}

impl DiskHeader {
    /// Parse a `DiskHeader` from the first `DISK_HEADER_SIZE` bytes of `raw`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < DISK_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut csum = [0u8; BTRFS_CSUM_SIZE];
        csum.copy_from_slice(&raw[0..BTRFS_CSUM_SIZE]);
        let mut fsid = [0u8; UUID_SIZE];
        fsid.copy_from_slice(&raw[UUID_OFFSET..UUID_OFFSET + UUID_SIZE]);
        let generation = u64::from_le_bytes(
            raw[GEN_OFFSET..GEN_OFFSET + 8]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let bytenr = u64::from_le_bytes(
            raw[BYTENR_OFFSET..BYTENR_OFFSET + 8]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let flags = u64::from_le_bytes(
            raw[FLAGS_OFFSET..FLAGS_OFFSET + 8]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let backref_rev = u64::from_le_bytes(
            raw[BACKREF_REV_OFFSET..BACKREF_REV_OFFSET + 8]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let level = raw[BACKREF_REV_OFFSET + 8];
        Ok(Self {
            csum,
            fsid,
            generation,
            bytenr,
            flags,
            backref_rev,
            level,
        })
    }

    /// Encode this header back into `dst[..DISK_HEADER_SIZE]`.
    pub fn encode(&self, dst: &mut [u8]) -> Result<()> {
        if dst.len() < DISK_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        dst[0..BTRFS_CSUM_SIZE].copy_from_slice(&self.csum);
        dst[UUID_OFFSET..UUID_OFFSET + UUID_SIZE].copy_from_slice(&self.fsid);
        dst[GEN_OFFSET..GEN_OFFSET + 8].copy_from_slice(&self.generation.to_le_bytes());
        dst[BYTENR_OFFSET..BYTENR_OFFSET + 8].copy_from_slice(&self.bytenr.to_le_bytes());
        dst[FLAGS_OFFSET..FLAGS_OFFSET + 8].copy_from_slice(&self.flags.to_le_bytes());
        dst[BACKREF_REV_OFFSET..BACKREF_REV_OFFSET + 8]
            .copy_from_slice(&self.backref_rev.to_le_bytes());
        dst[BACKREF_REV_OFFSET + 8] = self.level;
        Ok(())
    }
}

// ── Block Reader Trait ────────────────────────────────────────────────────────

/// Trait for reading and writing fixed-size blocks from a btrfs device.
pub trait BtrfsDiskReader {
    /// Read exactly `buf.len()` bytes from physical byte offset `bytenr`.
    fn read_at(&self, bytenr: u64, buf: &mut [u8]) -> Result<()>;

    /// Write `buf` to physical byte offset `bytenr`.
    fn write_at(&mut self, bytenr: u64, buf: &[u8]) -> Result<()>;
}

// ── Read / Write / Verify helpers ─────────────────────────────────────────────

/// Verify the disk header stored at the start of `block`.
///
/// Checks that the embedded checksum matches the block contents using `csum`.
pub fn verify_header(block: &[u8; BTRFS_NODESIZE], csum: &BtrfsChecksum) -> Result<()> {
    if !csum.verify(block) {
        return Err(Error::IoError);
    }
    Ok(())
}

/// Read a tree block at `bytenr` from `reader`, verify its checksum, and
/// return the parsed [`DiskHeader`].
///
/// The raw block bytes are written into `buf` (caller-supplied scratch space).
pub fn read_tree_block(
    reader: &impl BtrfsDiskReader,
    bytenr: u64,
    csum: &BtrfsChecksum,
    buf: &mut [u8; BTRFS_NODESIZE],
) -> Result<DiskHeader> {
    reader.read_at(bytenr, buf.as_mut_slice())?;
    verify_header(buf, csum)?;
    let hdr = DiskHeader::parse(buf.as_slice())?;
    if hdr.bytenr != bytenr {
        return Err(Error::IoError); // bytenr mismatch — corrupted block
    }
    Ok(hdr)
}

/// Write a tree block to disk at `hdr.bytenr`, computing a fresh checksum.
///
/// Caller must have filled `buf[DISK_HEADER_SIZE..]` with the payload.
/// The header (minus checksum) is encoded into `buf[0..DISK_HEADER_SIZE]`,
/// then the checksum is computed and written into `buf[0..BTRFS_CSUM_SIZE]`.
pub fn write_tree_block(
    writer: &mut impl BtrfsDiskReader,
    hdr: &DiskHeader,
    csum: &BtrfsChecksum,
    buf: &mut [u8; BTRFS_NODESIZE],
) -> Result<()> {
    // Zero out the checksum field first so we checksum the rest of the block.
    buf[0..BTRFS_CSUM_SIZE].fill(0);
    hdr.encode(buf.as_mut_slice())?;
    let mut computed = [0u8; BTRFS_CSUM_SIZE];
    csum.compute(&buf[BTRFS_CSUM_SIZE..], &mut computed);
    buf[0..BTRFS_CSUM_SIZE].copy_from_slice(&computed);
    writer.write_at(hdr.bytenr, buf.as_slice())
}

// ── I/O Statistics ────────────────────────────────────────────────────────────

/// Counters for btrfs disk I/O operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskIoStats {
    /// Total tree block reads.
    pub reads: u64,
    /// Total tree block writes.
    pub writes: u64,
    /// Number of checksum verification failures.
    pub csum_errors: u64,
    /// Number of bytenr mismatch errors.
    pub bytenr_errors: u64,
}

/// Instrumented wrapper that tracks I/O statistics for a [`BtrfsDiskReader`].
pub struct InstrumentedReader<R: BtrfsDiskReader> {
    inner: R,
    /// Accumulated I/O statistics.
    pub stats: DiskIoStats,
    csum: BtrfsChecksum,
}

impl<R: BtrfsDiskReader> InstrumentedReader<R> {
    /// Create a new instrumented reader wrapping `inner`.
    pub fn new(inner: R, algo: ChecksumType) -> Self {
        Self {
            inner,
            stats: DiskIoStats::default(),
            csum: BtrfsChecksum::new(algo),
        }
    }

    /// Read and verify a tree block, updating statistics on error.
    pub fn read_verified(
        &mut self,
        bytenr: u64,
        buf: &mut [u8; MAX_READ_SIZE],
    ) -> Result<DiskHeader> {
        self.inner.read_at(bytenr, buf.as_mut_slice())?;
        self.stats.reads += 1;
        if !self.csum.verify(buf) {
            self.stats.csum_errors += 1;
            return Err(Error::IoError);
        }
        let hdr = DiskHeader::parse(buf.as_slice())?;
        if hdr.bytenr != bytenr {
            self.stats.bytenr_errors += 1;
            return Err(Error::IoError);
        }
        Ok(hdr)
    }
}

impl<R: BtrfsDiskReader> BtrfsDiskReader for InstrumentedReader<R> {
    fn read_at(&self, bytenr: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(bytenr, buf)
    }

    fn write_at(&mut self, bytenr: u64, buf: &[u8]) -> Result<()> {
        self.stats.writes += 1;
        self.inner.write_at(bytenr, buf)
    }
}
