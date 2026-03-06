// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ZoneFS — filesystem for zoned block devices (SMR/ZNS).
//!
//! ZoneFS exposes each zone of a zoned block device as a regular file.
//! Zones are partitioned into two groups:
//!
//! - **Conventional zones**: random read/write like a normal block device.
//! - **Sequential zones**: append-only writes from the write pointer.
//!
//! The filesystem is not formatted in a traditional sense — it derives
//! its structure directly from the zone layout reported by the device.
//!
//! # Directory layout
//!
//! ```text
//! /cnv/          ← conventional zone files (zone0, zone1, ...)
//! /seq/          ← sequential zone files   (zone0, zone1, ...)
//! ```
//!
//! Each zone file has a fixed size equal to the zone capacity.  Reads
//! and writes are translated directly into block I/O for the underlying
//! zone.
//!
//! # Reference
//!
//! Linux `fs/zonefs/`, kernel documentation `Documentation/filesystems/zonefs.rst`.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// ZoneFS magic number (same as Linux, `0x5a4f4653` == "ZOFS").
pub const ZONEFS_MAGIC: u32 = 0x5a4f4653;

/// ZoneFS on-disk version.
pub const ZONEFS_VERSION: u32 = 1;

/// Maximum number of zones supported.
const MAX_ZONES: usize = 128;

/// Maximum simultaneous open sequential zones (kernel default is 128).
const MAX_OPEN_ZONES: usize = 16;

/// Zone data capacity in bytes (128 MiB per zone for modelling purposes).
const ZONE_CAPACITY: u64 = 128 * 1024 * 1024;

/// Zone data buffer size kept in memory for simulation (4 KiB per zone).
const ZONE_BUF_SIZE: usize = 4096;

/// Maximum filename length.
const MAX_NAME_LEN: usize = 64;

// ── Zone types and conditions ─────────────────────────────────────────────────

/// Zone type as reported by the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    /// Conventional zone: supports random read/write.
    Conventional,
    /// Sequential write required zone: append-only writes.
    Sequential,
}

/// Zone condition (state machine for sequential zones).
///
/// Conventional zones always stay in [`ZoneCondition::NotWritePointer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneCondition {
    /// Zone has no write pointer (conventional zone).
    NotWritePointer,
    /// Zone is empty — write pointer at the start of the zone.
    Empty,
    /// Zone is implicitly open (received a write without OPEN command).
    ImplicitlyOpen,
    /// Zone was explicitly opened with a zone management command.
    ExplicitlyOpen,
    /// Zone is closed — write pointer somewhere between start and end.
    Closed,
    /// Zone is full — write pointer at the end of the zone.
    Full,
    /// Zone is read-only.
    ReadOnly,
    /// Zone is offline (hardware failure).
    Offline,
}

impl ZoneCondition {
    /// Return `true` if the zone is currently open (can accept writes).
    pub fn is_open(self) -> bool {
        matches!(self, Self::ImplicitlyOpen | Self::ExplicitlyOpen)
    }

    /// Return `true` if the zone can be written to.
    pub fn is_writable(self) -> bool {
        matches!(
            self,
            Self::Empty | Self::ImplicitlyOpen | Self::ExplicitlyOpen | Self::Closed
        )
    }
}

// ── Per-zone descriptor ───────────────────────────────────────────────────────

/// On-device zone descriptor.
#[derive(Debug, Clone, Copy)]
pub struct ZoneInfo {
    /// Zone index (0-based).
    pub index: u32,
    /// Zone type.
    pub zone_type: ZoneType,
    /// Zone condition.
    pub condition: ZoneCondition,
    /// Start LBA of the zone.
    pub start_lba: u64,
    /// Capacity of the zone in bytes.
    pub capacity: u64,
    /// Current write pointer offset from zone start (sequential zones).
    pub wp_offset: u64,
}

impl ZoneInfo {
    /// Create a conventional zone descriptor.
    pub const fn conventional(index: u32, start_lba: u64) -> Self {
        Self {
            index,
            zone_type: ZoneType::Conventional,
            condition: ZoneCondition::NotWritePointer,
            start_lba,
            capacity: ZONE_CAPACITY,
            wp_offset: 0,
        }
    }

    /// Create an empty sequential zone descriptor.
    pub const fn sequential(index: u32, start_lba: u64) -> Self {
        Self {
            index,
            zone_type: ZoneType::Sequential,
            condition: ZoneCondition::Empty,
            start_lba,
            capacity: ZONE_CAPACITY,
            wp_offset: 0,
        }
    }

    /// Available space remaining (sequential zone only).
    pub fn available_capacity(&self) -> u64 {
        self.capacity.saturating_sub(self.wp_offset)
    }

    /// Whether the zone file is effectively read-only from the VFS side.
    pub fn is_read_only(&self) -> bool {
        matches!(
            self.condition,
            ZoneCondition::Full | ZoneCondition::ReadOnly | ZoneCondition::Offline
        )
    }
}

// ── Zone data buffer ─────────────────────────────────────────────────────────

/// In-memory buffer holding the simulated data for a single zone.
#[derive(Clone, Copy)]
struct ZoneBuf {
    data: [u8; ZONE_BUF_SIZE],
    /// Number of valid bytes in the buffer.
    len: usize,
}

impl ZoneBuf {
    const fn new() -> Self {
        Self {
            data: [0u8; ZONE_BUF_SIZE],
            len: 0,
        }
    }
}

// ── Zone file inode table entry ───────────────────────────────────────────────

/// A zone file entry mapping a zone to an inode number.
#[derive(Debug, Clone, Copy)]
struct ZoneFile {
    /// Zone descriptor.
    zone: ZoneInfo,
    /// Inode number for this zone file.
    ino: InodeNumber,
    /// Name of the file (e.g. "zone0").
    name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    name_len: usize,
}

impl ZoneFile {
    /// Return the file name as a byte slice.
    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── ZoneFS superblock ─────────────────────────────────────────────────────────

/// ZoneFS superblock — persisted on a conventional zone at LBA 0.
#[derive(Debug, Clone, Copy)]
pub struct ZonefsSuperblock {
    /// Magic number identifying ZoneFS.
    pub magic: u32,
    /// Filesystem version.
    pub version: u32,
    /// Total number of zones on the device.
    pub nr_zones: u32,
    /// Number of conventional zones.
    pub nr_conv_zones: u32,
    /// Number of sequential zones.
    pub nr_seq_zones: u32,
    /// UUID identifying this filesystem instance (simplified as a u128).
    pub uuid: u128,
    /// Flags (reserved, 0 for now).
    pub flags: u32,
}

impl ZonefsSuperblock {
    /// Create a new superblock for the given zone layout.
    pub fn new(nr_conv: u32, nr_seq: u32, uuid: u128) -> Self {
        Self {
            magic: ZONEFS_MAGIC,
            version: ZONEFS_VERSION,
            nr_zones: nr_conv + nr_seq,
            nr_conv_zones: nr_conv,
            nr_seq_zones: nr_seq,
            uuid,
            flags: 0,
        }
    }

    /// Validate the magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == ZONEFS_MAGIC && self.version == ZONEFS_VERSION
    }
}

// ── ZoneFS filesystem ─────────────────────────────────────────────────────────

/// ZoneFS filesystem state.
///
/// Maintains the zone table, per-zone data buffers, and inode numbering.
/// The filesystem root contains two directories: `cnv/` and `seq/`.
pub struct ZoneFs {
    /// Superblock metadata.
    superblock: ZonefsSuperblock,
    /// Zone file table for conventional zones.
    conv_zones: [Option<ZoneFile>; MAX_ZONES],
    /// Zone file table for sequential zones.
    seq_zones: [Option<ZoneFile>; MAX_ZONES],
    /// Number of conventional zone files registered.
    nr_conv: usize,
    /// Number of sequential zone files registered.
    nr_seq: usize,
    /// Data buffers indexed by inode number (ino.0 as index).
    bufs: [ZoneBuf; MAX_ZONES * 2],
    /// Next inode number to assign.
    next_ino: u64,
    /// Number of currently open sequential zones.
    open_seq_count: usize,
}

/// Well-known inode numbers for the pseudo-directory entries.
const INO_ROOT: u64 = 1;
const INO_CNV_DIR: u64 = 2;
const INO_SEQ_DIR: u64 = 3;
/// Zone file inodes start at this offset.
const INO_ZONE_BASE: u64 = 4;

impl ZoneFs {
    /// Create a new ZoneFS instance from a zone layout.
    ///
    /// `conv_starts` is the list of start LBAs for conventional zones.
    /// `seq_starts` is the list of start LBAs for sequential zones.
    pub fn new(conv_starts: &[u64], seq_starts: &[u64], uuid: u128) -> Result<Self> {
        if conv_starts.len() + seq_starts.len() > MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        let sb = ZonefsSuperblock::new(conv_starts.len() as u32, seq_starts.len() as u32, uuid);

        const NONE_ZONE: Option<ZoneFile> = None;
        let mut fs = Self {
            superblock: sb,
            conv_zones: [NONE_ZONE; MAX_ZONES],
            seq_zones: [NONE_ZONE; MAX_ZONES],
            nr_conv: 0,
            nr_seq: 0,
            bufs: [ZoneBuf::new(); MAX_ZONES * 2],
            next_ino: INO_ZONE_BASE,
            open_seq_count: 0,
        };

        for (i, &lba) in conv_starts.iter().enumerate() {
            fs.register_zone(ZoneInfo::conventional(i as u32, lba))?;
        }
        for (i, &lba) in seq_starts.iter().enumerate() {
            fs.register_zone(ZoneInfo::sequential(i as u32, lba))?;
        }
        Ok(fs)
    }

    /// Register a zone and assign it an inode and name.
    fn register_zone(&mut self, zone: ZoneInfo) -> Result<()> {
        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        // Build name like "zone0", "zone1", etc.
        let mut name = [0u8; MAX_NAME_LEN];
        let idx = match zone.zone_type {
            ZoneType::Conventional => self.nr_conv,
            ZoneType::Sequential => self.nr_seq,
        };
        let name_len = write_zone_name(&mut name, idx)?;

        let zf = ZoneFile {
            zone,
            ino,
            name,
            name_len,
        };

        match zone.zone_type {
            ZoneType::Conventional => {
                if self.nr_conv >= MAX_ZONES {
                    return Err(Error::OutOfMemory);
                }
                self.conv_zones[self.nr_conv] = Some(zf);
                self.nr_conv += 1;
            }
            ZoneType::Sequential => {
                if self.nr_seq >= MAX_ZONES {
                    return Err(Error::OutOfMemory);
                }
                self.seq_zones[self.nr_seq] = Some(zf);
                self.nr_seq += 1;
            }
        }
        Ok(())
    }

    /// Return the root directory inode.
    pub fn root_inode(&self) -> Inode {
        Inode::new(
            InodeNumber(INO_ROOT),
            FileType::Directory,
            FileMode::DIR_DEFAULT,
        )
    }

    /// Look up the `cnv` or `seq` directory.
    fn lookup_dir(&self, name: &str) -> Option<Inode> {
        match name {
            "cnv" => Some(Inode::new(
                InodeNumber(INO_CNV_DIR),
                FileType::Directory,
                FileMode::DIR_DEFAULT,
            )),
            "seq" => Some(Inode::new(
                InodeNumber(INO_SEQ_DIR),
                FileType::Directory,
                FileMode(0o444),
            )),
            _ => None,
        }
    }

    /// Find a zone file by parent directory inode and name.
    fn find_zone_file(&self, parent_ino: u64, name: &str) -> Option<&ZoneFile> {
        let table: &[Option<ZoneFile>] = if parent_ino == INO_CNV_DIR {
            &self.conv_zones[..self.nr_conv]
        } else if parent_ino == INO_SEQ_DIR {
            &self.seq_zones[..self.nr_seq]
        } else {
            return None;
        };

        let name_bytes = name.as_bytes();
        for entry in table.iter().flatten() {
            if entry.name_bytes() == name_bytes {
                return Some(entry);
            }
        }
        None
    }

    /// Find a zone file (mutable) by parent directory inode and name.
    fn find_zone_file_mut(&mut self, parent_ino: u64, name: &str) -> Option<&mut ZoneFile> {
        let name_bytes = name.as_bytes();

        if parent_ino == INO_CNV_DIR {
            let nr = self.nr_conv;
            for entry in self.conv_zones[..nr].iter_mut().flatten() {
                if entry.name_bytes() == name_bytes {
                    return Some(entry);
                }
            }
        } else if parent_ino == INO_SEQ_DIR {
            let nr = self.nr_seq;
            for entry in self.seq_zones[..nr].iter_mut().flatten() {
                if entry.name_bytes() == name_bytes {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Build an `Inode` struct from a `ZoneFile`.
    fn zone_file_inode(zf: &ZoneFile) -> Inode {
        let mode = if zf.zone.is_read_only() {
            FileMode(0o444)
        } else if zf.zone.zone_type == ZoneType::Conventional {
            FileMode::FILE_DEFAULT
        } else {
            // Sequential zone: append-only — no random write from user perspective.
            FileMode(0o644)
        };
        let mut inode = Inode::new(zf.ino, FileType::Regular, mode);
        inode.size = zf.zone.capacity;
        inode
    }

    /// Read data from a zone file.
    ///
    /// For sequential zones the readable region is `[0, wp_offset)`.
    pub fn zone_read(&self, ino: InodeNumber, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let buf_idx = self.ino_to_buf_idx(ino)?;
        let zone = self.ino_to_zone(ino)?;

        // Determine readable size.
        let readable = match zone.zone_type {
            ZoneType::Conventional => zone.capacity,
            ZoneType::Sequential => zone.wp_offset,
        };

        if offset >= readable {
            return Ok(0);
        }

        let available = (readable - offset) as usize;
        let to_read = buf
            .len()
            .min(available)
            .min(ZONE_BUF_SIZE.saturating_sub(offset as usize));
        if to_read == 0 {
            return Ok(0);
        }

        let src = &self.bufs[buf_idx].data[offset as usize..offset as usize + to_read];
        buf[..to_read].copy_from_slice(src);
        Ok(to_read)
    }

    /// Write data to a zone file.
    ///
    /// Conventional zones: random writes permitted.
    /// Sequential zones: only append writes at the current write pointer.
    pub fn zone_write(&mut self, ino: InodeNumber, offset: u64, data: &[u8]) -> Result<usize> {
        let buf_idx = self.ino_to_buf_idx(ino)?;
        let zone_idx = self.ino_to_zone_idx(ino)?;
        let zone_info = self.get_zone_info(zone_idx)?;

        if zone_info.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        match zone_info.zone_type {
            ZoneType::Conventional => self.write_conventional(buf_idx, zone_idx, offset, data),
            ZoneType::Sequential => self.write_sequential(buf_idx, zone_idx, offset, data),
        }
    }

    /// Perform a random write on a conventional zone.
    fn write_conventional(
        &mut self,
        buf_idx: usize,
        zone_idx: ZoneIdx,
        offset: u64,
        data: &[u8],
    ) -> Result<usize> {
        let off = offset as usize;
        if off >= ZONE_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        let to_write = data.len().min(ZONE_BUF_SIZE - off);
        self.bufs[buf_idx].data[off..off + to_write].copy_from_slice(&data[..to_write]);
        let new_len = (off + to_write).max(self.bufs[buf_idx].len);
        self.bufs[buf_idx].len = new_len;

        // Update zone info size tracking (no write pointer for conventional).
        match zone_idx {
            ZoneIdx::Conv(i) => {
                if let Some(zf) = &mut self.conv_zones[i] {
                    zf.zone.wp_offset = new_len as u64;
                }
            }
            ZoneIdx::Seq(_) => unreachable!(),
        }
        Ok(to_write)
    }

    /// Perform an append write on a sequential zone.
    fn write_sequential(
        &mut self,
        buf_idx: usize,
        zone_idx: ZoneIdx,
        offset: u64,
        data: &[u8],
    ) -> Result<usize> {
        let i = match zone_idx {
            ZoneIdx::Seq(i) => i,
            ZoneIdx::Conv(_) => unreachable!(),
        };

        let wp = self.seq_zones[i]
            .as_ref()
            .ok_or(Error::NotFound)?
            .zone
            .wp_offset;

        // Sequential writes must start exactly at the write pointer.
        if offset != wp {
            return Err(Error::InvalidArgument);
        }

        let capacity = self.seq_zones[i]
            .as_ref()
            .ok_or(Error::NotFound)?
            .zone
            .capacity;
        let remaining = capacity.saturating_sub(wp) as usize;
        let wp_usize = wp as usize;

        if wp_usize >= ZONE_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }

        let to_write = data.len().min(remaining).min(ZONE_BUF_SIZE - wp_usize);
        self.bufs[buf_idx].data[wp_usize..wp_usize + to_write].copy_from_slice(&data[..to_write]);
        self.bufs[buf_idx].len = wp_usize + to_write;

        let zf = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
        zf.zone.wp_offset += to_write as u64;

        // Transition condition: implicitly open if empty, full if zone filled.
        if zf.zone.condition == ZoneCondition::Empty {
            zf.zone.condition = ZoneCondition::ImplicitlyOpen;
            if self.open_seq_count >= MAX_OPEN_ZONES {
                // Cannot open more zones; undo.
                let zf2 = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
                zf2.zone.wp_offset -= to_write as u64;
                zf2.zone.condition = ZoneCondition::Empty;
                return Err(Error::Busy);
            }
            self.open_seq_count += 1;
        }

        // Check if zone is now full.
        let zf3 = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
        if zf3.zone.wp_offset >= zf3.zone.capacity {
            if zf3.zone.condition.is_open() {
                self.open_seq_count = self.open_seq_count.saturating_sub(1);
            }
            zf3.zone.condition = ZoneCondition::Full;
        }

        Ok(to_write)
    }

    /// Reset (erase) a sequential zone, setting write pointer back to zero.
    pub fn zone_reset(&mut self, ino: InodeNumber) -> Result<()> {
        let zone_idx = self.ino_to_zone_idx(ino)?;
        let buf_idx = self.ino_to_buf_idx(ino)?;

        let i = match zone_idx {
            ZoneIdx::Seq(i) => i,
            ZoneIdx::Conv(_) => return Err(Error::InvalidArgument),
        };

        let zf = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
        if zf.zone.condition.is_open() {
            self.open_seq_count = self.open_seq_count.saturating_sub(1);
        }
        zf.zone.wp_offset = 0;
        zf.zone.condition = ZoneCondition::Empty;
        self.bufs[buf_idx] = ZoneBuf::new();
        Ok(())
    }

    /// Explicitly open a sequential zone (zone management command).
    pub fn zone_open(&mut self, ino: InodeNumber) -> Result<()> {
        let zone_idx = self.ino_to_zone_idx(ino)?;
        let i = match zone_idx {
            ZoneIdx::Seq(i) => i,
            ZoneIdx::Conv(_) => return Err(Error::InvalidArgument),
        };

        let zf = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
        if zf.zone.condition == ZoneCondition::Full {
            return Err(Error::InvalidArgument);
        }
        if zf.zone.condition == ZoneCondition::ExplicitlyOpen {
            return Ok(()); // Already open.
        }
        if !zf.zone.condition.is_open() {
            if self.open_seq_count >= MAX_OPEN_ZONES {
                return Err(Error::Busy);
            }
            self.open_seq_count += 1;
        }
        let zf2 = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
        zf2.zone.condition = ZoneCondition::ExplicitlyOpen;
        Ok(())
    }

    /// Explicitly close a sequential zone (zone management command).
    pub fn zone_close(&mut self, ino: InodeNumber) -> Result<()> {
        let zone_idx = self.ino_to_zone_idx(ino)?;
        let i = match zone_idx {
            ZoneIdx::Seq(i) => i,
            ZoneIdx::Conv(_) => return Err(Error::InvalidArgument),
        };

        let zf = self.seq_zones[i].as_mut().ok_or(Error::NotFound)?;
        if zf.zone.condition.is_open() {
            self.open_seq_count = self.open_seq_count.saturating_sub(1);
            zf.zone.condition = ZoneCondition::Closed;
        }
        Ok(())
    }

    /// Return information about the zone backing the given inode.
    pub fn zone_info(&self, ino: InodeNumber) -> Result<ZoneInfo> {
        self.ino_to_zone(ino).copied()
    }

    /// Return the superblock.
    pub fn superblock(&self) -> &ZonefsSuperblock {
        &self.superblock
    }

    /// Return statistics: (nr_conv, nr_seq, open_seq).
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.nr_conv, self.nr_seq, self.open_seq_count)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Resolve an inode number to a `ZoneInfo` reference.
    fn ino_to_zone(&self, ino: InodeNumber) -> Result<&ZoneInfo> {
        for entry in self.conv_zones[..self.nr_conv].iter().flatten() {
            if entry.ino == ino {
                return Ok(&entry.zone);
            }
        }
        for entry in self.seq_zones[..self.nr_seq].iter().flatten() {
            if entry.ino == ino {
                return Ok(&entry.zone);
            }
        }
        Err(Error::NotFound)
    }

    /// Resolve an inode number to a `ZoneIdx`.
    fn ino_to_zone_idx(&self, ino: InodeNumber) -> Result<ZoneIdx> {
        for (i, entry) in self.conv_zones[..self.nr_conv].iter().enumerate() {
            if entry.as_ref().map(|e| e.ino) == Some(ino) {
                return Ok(ZoneIdx::Conv(i));
            }
        }
        for (i, entry) in self.seq_zones[..self.nr_seq].iter().enumerate() {
            if entry.as_ref().map(|e| e.ino) == Some(ino) {
                return Ok(ZoneIdx::Seq(i));
            }
        }
        Err(Error::NotFound)
    }

    /// Map an inode to a buffer slot index.
    fn ino_to_buf_idx(&self, ino: InodeNumber) -> Result<usize> {
        let offset = ino
            .0
            .checked_sub(INO_ZONE_BASE)
            .ok_or(Error::InvalidArgument)?;
        let idx = offset as usize;
        if idx >= MAX_ZONES * 2 {
            return Err(Error::InvalidArgument);
        }
        Ok(idx)
    }

    /// Return the mutable `ZoneInfo` for the given `ZoneIdx`.
    fn get_zone_info(&self, idx: ZoneIdx) -> Result<ZoneInfo> {
        match idx {
            ZoneIdx::Conv(i) => self.conv_zones[i]
                .as_ref()
                .map(|e| e.zone)
                .ok_or(Error::NotFound),
            ZoneIdx::Seq(i) => self.seq_zones[i]
                .as_ref()
                .map(|e| e.zone)
                .ok_or(Error::NotFound),
        }
    }
}

/// Internal zone index variant to avoid borrowing conflicts.
#[derive(Clone, Copy)]
enum ZoneIdx {
    Conv(usize),
    Seq(usize),
}

/// Write a zone file name (e.g., "zone0") into a fixed buffer.
///
/// Returns the length of the written name.
fn write_zone_name(buf: &mut [u8; MAX_NAME_LEN], index: usize) -> Result<usize> {
    // Format: "zone" + decimal index, max is "zone9999" (8 chars).
    let prefix = b"zone";
    if buf.len() < prefix.len() + 5 {
        return Err(Error::InvalidArgument);
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();

    // Write decimal digits.
    let mut digits = [0u8; 10];
    let mut n = index;
    let mut d = 0;
    if n == 0 {
        digits[0] = b'0';
        d = 1;
    } else {
        while n > 0 {
            digits[d] = b'0' + (n % 10) as u8;
            n /= 10;
            d += 1;
        }
        // Reverse digits.
        digits[..d].reverse();
    }

    if pos + d > MAX_NAME_LEN {
        return Err(Error::InvalidArgument);
    }
    buf[pos..pos + d].copy_from_slice(&digits[..d]);
    pos += d;
    Ok(pos)
}

// ── InodeOps implementation ───────────────────────────────────────────────────

impl InodeOps for ZoneFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        match parent.ino.0 {
            INO_ROOT => self.lookup_dir(name).ok_or(Error::NotFound),
            INO_CNV_DIR | INO_SEQ_DIR => {
                let zf = self
                    .find_zone_file(parent.ino.0, name)
                    .ok_or(Error::NotFound)?;
                Ok(Self::zone_file_inode(zf))
            }
            _ => Err(Error::NotFound),
        }
    }

    fn create(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        // ZoneFS does not support creating arbitrary files.
        Err(Error::PermissionDenied)
    }

    fn mkdir(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn rmdir(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.zone_read(inode.ino, offset, buf)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        self.zone_write(inode.ino, offset, data)
    }

    fn truncate(&mut self, inode: &Inode, _size: u64) -> Result<()> {
        // Truncate maps to zone reset for sequential zones.
        self.zone_reset(inode.ino)
    }
}

// ── ZoneFS registry ───────────────────────────────────────────────────────────

/// Maximum number of mounted ZoneFS instances.
const MAX_ZONEFS_INSTANCES: usize = 4;

/// Registry of active ZoneFS mounts.
pub struct ZoneFsRegistry {
    instances: [Option<ZoneFs>; MAX_ZONEFS_INSTANCES],
    count: usize,
}

impl ZoneFsRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<ZoneFs> = None;
        Self {
            instances: [NONE; MAX_ZONEFS_INSTANCES],
            count: 0,
        }
    }

    /// Register a new ZoneFS instance.
    ///
    /// Returns the instance index on success.
    pub fn register(&mut self, fs: ZoneFs) -> Result<usize> {
        if self.count >= MAX_ZONEFS_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.instances[idx] = Some(fs);
        self.count += 1;
        Ok(idx)
    }

    /// Look up an instance by index.
    pub fn get(&self, idx: usize) -> Option<&ZoneFs> {
        self.instances.get(idx)?.as_ref()
    }

    /// Look up a mutable instance by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut ZoneFs> {
        self.instances.get_mut(idx)?.as_mut()
    }

    /// Return the number of registered instances.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for ZoneFsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Directory listing helpers ─────────────────────────────────────────────────

/// Entry returned from a ZoneFS directory listing.
#[derive(Debug, Clone, Copy)]
pub struct ZoneDirEntry {
    /// Inode number.
    pub ino: InodeNumber,
    /// File type.
    pub file_type: FileType,
    /// Name length.
    pub name_len: usize,
    /// Name bytes.
    pub name: [u8; MAX_NAME_LEN],
}

impl ZoneDirEntry {
    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Maximum directory entries in a single listing result.
const MAX_LISTING: usize = MAX_ZONES + 2;

/// Result of listing a ZoneFS directory.
pub struct ZoneDirListing {
    entries: [Option<ZoneDirEntry>; MAX_LISTING],
    count: usize,
}

impl ZoneDirListing {
    fn new() -> Self {
        const NONE: Option<ZoneDirEntry> = None;
        Self {
            entries: [NONE; MAX_LISTING],
            count: 0,
        }
    }

    fn push(&mut self, entry: ZoneDirEntry) -> Result<()> {
        if self.count >= MAX_LISTING {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the listing is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the entry at the given index.
    pub fn get(&self, idx: usize) -> Option<&ZoneDirEntry> {
        self.entries.get(idx)?.as_ref()
    }
}

impl ZoneFs {
    /// List the contents of a directory inode.
    pub fn readdir(&self, parent: &Inode) -> Result<ZoneDirListing> {
        let mut listing = ZoneDirListing::new();

        match parent.ino.0 {
            INO_ROOT => {
                // Emit "cnv" and "seq" subdirectories.
                for (name_str, ino) in [("cnv", INO_CNV_DIR), ("seq", INO_SEQ_DIR)] {
                    let bytes = name_str.as_bytes();
                    let mut name = [0u8; MAX_NAME_LEN];
                    name[..bytes.len()].copy_from_slice(bytes);
                    listing.push(ZoneDirEntry {
                        ino: InodeNumber(ino),
                        file_type: FileType::Directory,
                        name_len: bytes.len(),
                        name,
                    })?;
                }
            }
            INO_CNV_DIR => {
                for entry in self.conv_zones[..self.nr_conv].iter().flatten() {
                    listing.push(ZoneDirEntry {
                        ino: entry.ino,
                        file_type: FileType::Regular,
                        name_len: entry.name_len,
                        name: entry.name,
                    })?;
                }
            }
            INO_SEQ_DIR => {
                for entry in self.seq_zones[..self.nr_seq].iter().flatten() {
                    listing.push(ZoneDirEntry {
                        ino: entry.ino,
                        file_type: FileType::Regular,
                        name_len: entry.name_len,
                        name: entry.name,
                    })?;
                }
            }
            _ => return Err(Error::InvalidArgument),
        }

        Ok(listing)
    }
}
