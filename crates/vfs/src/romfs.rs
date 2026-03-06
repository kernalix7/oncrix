// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-only ROM filesystem (ROMFS) driver.
//!
//! ROMFS is a simple, compact, read-only filesystem used in embedded systems
//! and Linux initramfs images. It stores files sequentially with minimal
//! overhead — no block allocation tables, no journals, just a flat list of
//! file headers followed by file data.
//!
//! # Architecture
//!
//! ```text
//! RomfsSuperblock  (bytes 0..512)
//!   magic "-rom1fs-" (8 bytes)
//!   full_size (4 bytes)
//!   checksum  (4 bytes)
//!   volume_name (NUL-terminated, padded to 16-byte boundary)
//!
//! RomfsFileHeader  (repeated, 16-byte aligned)
//!   next_hdr  (28 bits: offset, 4 bits: file type)
//!   spec_info (4 bytes: device/target/first-file)
//!   size      (4 bytes: file data size)
//!   checksum  (4 bytes: header checksum)
//!   name      (NUL-terminated, padded to 16-byte boundary)
//!   data      (file contents, padded to 16-byte boundary)
//! ```
//!
//! # Structures
//!
//! - [`RomfsFileType`] — file type discriminant (regular, dir, symlink, etc.)
//! - [`RomfsSuperblock`] — parsed superblock with magic and volume name
//! - [`RomfsFileHeader`] — parsed file entry header
//! - [`RomfsEntry`] — combined header + cached metadata for iteration
//! - [`RomfsFs`] — mounted filesystem handle with read operations
//! - [`RomfsRegistry`] — global mount registry (8 slots)

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// ROMFS magic number: "-rom1fs-" as bytes.
pub const ROMFS_MAGIC: [u8; 8] = *b"-rom1fs-";

/// Minimum superblock size: magic(8) + full_size(4) + checksum(4) = 16 bytes.
const MIN_SUPERBLOCK_SIZE: usize = 16;

/// Alignment boundary for all ROMFS structures.
const ROMFS_ALIGN: usize = 16;

/// Maximum volume name length.
const MAX_VOLUME_NAME: usize = 128;

/// Maximum file name length.
const MAX_NAME_LEN: usize = 256;

/// Maximum number of directory entries returned by readdir.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum number of ROMFS mounts.
const MAX_ROMFS_MOUNTS: usize = 8;

/// Maximum mount path length.
const MAX_MOUNT_PATH: usize = 256;

/// Maximum image size we support (16 MiB).
const MAX_IMAGE_SIZE: usize = 16 * 1024 * 1024;

/// File header fixed fields: next_hdr(4) + spec_info(4) + size(4) + checksum(4) = 16.
const FILE_HEADER_FIXED: usize = 16;

/// Mask for the next-header offset (top 28 bits of the next_hdr field).
const NEXT_HDR_MASK: u32 = 0xFFFF_FFF0;

/// Mask for file type bits (low 4 bits of the next_hdr field).
const FILE_TYPE_MASK: u32 = 0x0000_000F;

/// Bit indicating the file is executable.
const EXEC_BIT: u32 = 0x08;

// ── RomfsFileType ───────────────────────────────────────────────

/// ROMFS file type codes (stored in the low 3 bits of the next_hdr field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RomfsFileType {
    /// Hard link to another file.
    HardLink = 0,
    /// Directory.
    Directory = 1,
    /// Regular file.
    RegularFile = 2,
    /// Symbolic link.
    Symlink = 3,
    /// Block device.
    BlockDevice = 4,
    /// Character device.
    CharDevice = 5,
    /// Unix domain socket.
    Socket = 6,
    /// Named pipe (FIFO).
    Fifo = 7,
}

impl RomfsFileType {
    /// Parse a file type from the low 3 bits of the next_hdr field.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::HardLink),
            1 => Some(Self::Directory),
            2 => Some(Self::RegularFile),
            3 => Some(Self::Symlink),
            4 => Some(Self::BlockDevice),
            5 => Some(Self::CharDevice),
            6 => Some(Self::Socket),
            7 => Some(Self::Fifo),
            _ => None,
        }
    }

    /// Check if this type represents a directory.
    pub fn is_dir(self) -> bool {
        matches!(self, Self::Directory)
    }

    /// Check if this type represents a regular file.
    pub fn is_file(self) -> bool {
        matches!(self, Self::RegularFile)
    }

    /// Check if this type represents a symlink.
    pub fn is_symlink(self) -> bool {
        matches!(self, Self::Symlink)
    }
}

// ── Helper functions ────────────────────────────────────────────

/// Round up a value to the next ROMFS alignment boundary (16 bytes).
const fn align_up(val: usize) -> usize {
    (val + ROMFS_ALIGN - 1) & !(ROMFS_ALIGN - 1)
}

/// Read a big-endian u32 from a byte slice at the given offset.
///
/// ROMFS uses big-endian byte ordering (network byte order).
fn read_be_u32(data: &[u8], offset: usize) -> Result<u32> {
    if data.len() < offset + 4 {
        return Err(Error::IoError);
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Compute the ROMFS checksum over a range of bytes.
///
/// The checksum is a simple sum of all big-endian u32 words in the range.
/// The result should be zero when the checksum field is included.
fn compute_checksum(data: &[u8], offset: usize, len: usize) -> u32 {
    let end = if offset + len > data.len() {
        data.len()
    } else {
        offset + len
    };
    let mut sum: u32 = 0;
    let mut pos = offset;
    while pos + 4 <= end {
        let word = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        sum = sum.wrapping_add(word);
        pos += 4;
    }
    sum
}

/// Read a NUL-terminated string from the image at the given offset.
///
/// Returns the string bytes (without NUL) and the padded size (aligned to 16).
fn read_name(data: &[u8], offset: usize, max_len: usize) -> Result<(usize, usize)> {
    let limit = if offset + max_len > data.len() {
        data.len()
    } else {
        offset + max_len
    };
    let mut end = offset;
    while end < limit {
        if data[end] == 0 {
            let name_len = end - offset;
            // Padded to 16-byte boundary (name + NUL included in padding calc).
            let padded = align_up(name_len + 1);
            return Ok((name_len, padded));
        }
        end += 1;
    }
    Err(Error::InvalidArgument)
}

// ── RomfsSuperblock ─────────────────────────────────────────────

/// Parsed ROMFS superblock.
///
/// Located at byte offset 0 of the ROMFS image. Contains the magic
/// number, total image size, checksum, and volume name.
#[derive(Debug, Clone)]
pub struct RomfsSuperblock {
    /// Total size of the ROMFS image in bytes.
    pub full_size: u32,
    /// Superblock checksum (sum of first 512 bytes should be 0).
    pub checksum: u32,
    /// Volume name (NUL-terminated).
    pub volume_name: [u8; MAX_VOLUME_NAME],
    /// Length of the volume name.
    pub volume_name_len: usize,
    /// Byte offset where file headers begin (after padded volume name).
    pub first_file_offset: usize,
}

impl RomfsSuperblock {
    /// Parse a superblock from the beginning of a ROMFS image.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_SUPERBLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Verify magic number.
        let mut i = 0;
        while i < 8 {
            if data[i] != ROMFS_MAGIC[i] {
                return Err(Error::InvalidArgument);
            }
            i += 1;
        }
        let full_size = read_be_u32(data, 8)?;
        let checksum = read_be_u32(data, 12)?;

        // Validate image size.
        if full_size as usize > MAX_IMAGE_SIZE || (full_size as usize) < MIN_SUPERBLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Verify superblock checksum (first 512 bytes or full_size, whichever smaller).
        let check_len = if (full_size as usize) < 512 {
            full_size as usize
        } else {
            512
        };
        if data.len() >= check_len {
            let sum = compute_checksum(data, 0, check_len);
            if sum != 0 {
                return Err(Error::IoError);
            }
        }

        // Read volume name starting at offset 16.
        let (name_len, padded_name_size) = read_name(data, 16, MAX_VOLUME_NAME)?;
        let mut volume_name = [0u8; MAX_VOLUME_NAME];
        let copy_len = if name_len > MAX_VOLUME_NAME {
            MAX_VOLUME_NAME
        } else {
            name_len
        };
        volume_name[..copy_len].copy_from_slice(&data[16..16 + copy_len]);

        let first_file_offset = 16 + padded_name_size;

        Ok(Self {
            full_size,
            checksum,
            volume_name,
            volume_name_len: name_len,
            first_file_offset,
        })
    }

    /// Get the volume name as a byte slice.
    pub fn volume_name(&self) -> &[u8] {
        &self.volume_name[..self.volume_name_len]
    }
}

// ── RomfsFileHeader ─────────────────────────────────────────────

/// Parsed ROMFS file entry header.
///
/// Each file in a ROMFS image is described by a fixed header followed
/// by a NUL-terminated name (padded to 16 bytes) and then the file data
/// (also padded to 16 bytes).
#[derive(Debug, Clone)]
pub struct RomfsFileHeader {
    /// Byte offset of this header in the image.
    pub offset: usize,
    /// Byte offset of the next sibling file header (0 = last entry).
    pub next_hdr: usize,
    /// File type.
    pub file_type: RomfsFileType,
    /// Whether the executable bit is set.
    pub executable: bool,
    /// Spec info field (interpretation depends on file type).
    /// - Directory: offset of first child file header.
    /// - Hard link: offset of linked file header.
    /// - Device: device number (major << 8 | minor).
    /// - Symlink: unused (target stored in data).
    pub spec_info: u32,
    /// File data size in bytes.
    pub size: u32,
    /// Header checksum.
    pub checksum: u32,
    /// File name.
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the file name.
    pub name_len: usize,
    /// Byte offset where file data begins.
    pub data_offset: usize,
}

impl RomfsFileHeader {
    /// Parse a file header from the image at the given byte offset.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < offset + FILE_HEADER_FIXED {
            return Err(Error::IoError);
        }

        let next_field = read_be_u32(data, offset)?;
        let spec_info = read_be_u32(data, offset + 4)?;
        let size = read_be_u32(data, offset + 8)?;
        let checksum = read_be_u32(data, offset + 12)?;

        let next_hdr = (next_field & NEXT_HDR_MASK) as usize;
        let type_bits = next_field & FILE_TYPE_MASK;
        let file_type = RomfsFileType::from_u32(type_bits).ok_or(Error::InvalidArgument)?;
        let executable = (type_bits & EXEC_BIT) != 0;

        // Read file name starting after the fixed header.
        let name_offset = offset + FILE_HEADER_FIXED;
        let (name_len, padded_name_size) = read_name(data, name_offset, MAX_NAME_LEN)?;
        let mut name = [0u8; MAX_NAME_LEN];
        let copy_len = if name_len > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            name_len
        };
        name[..copy_len].copy_from_slice(&data[name_offset..name_offset + copy_len]);

        let data_offset = name_offset + padded_name_size;

        // Verify header checksum (sum of header + name bytes should be 0).
        let check_len = data_offset - offset;
        let sum = compute_checksum(data, offset, check_len);
        if sum != 0 {
            return Err(Error::IoError);
        }

        Ok(Self {
            offset,
            next_hdr,
            file_type,
            executable,
            spec_info,
            size,
            checksum,
            name,
            name_len,
            data_offset,
        })
    }

    /// Get the file name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Check whether this entry represents the "." or ".." pseudo-entries.
    pub fn is_dot_entry(&self) -> bool {
        (self.name_len == 1 && self.name[0] == b'.')
            || (self.name_len == 2 && self.name[0] == b'.' && self.name[1] == b'.')
    }
}

// ── RomfsEntry ──────────────────────────────────────────────────

/// A directory entry returned by [`RomfsFs::readdir`].
///
/// Combines the file header metadata with a stable offset for iteration.
#[derive(Debug, Clone)]
pub struct RomfsEntry {
    /// File name.
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the file name.
    pub name_len: usize,
    /// File type.
    pub file_type: RomfsFileType,
    /// File size in bytes.
    pub size: u32,
    /// Byte offset of this entry's header in the image.
    pub header_offset: usize,
    /// Whether the executable bit is set.
    pub executable: bool,
}

impl RomfsEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            file_type: RomfsFileType::RegularFile,
            size: 0,
            header_offset: 0,
            executable: false,
        }
    }

    /// Get the file name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── RomfsFs ─────────────────────────────────────────────────────

/// Mounted ROMFS filesystem handle.
///
/// Holds a reference to the in-memory image and the parsed superblock.
/// All operations are read-only since ROMFS is immutable.
pub struct RomfsFs {
    /// Parsed superblock.
    superblock: RomfsSuperblock,
    /// Total image size (for bounds checking).
    image_size: usize,
    /// Mount path.
    mount_path: [u8; MAX_MOUNT_PATH],
    /// Length of the mount path.
    mount_path_len: usize,
    /// Whether the filesystem is currently mounted.
    mounted: bool,
}

impl RomfsFs {
    /// Create a new unmounted ROMFS handle.
    pub const fn new() -> Self {
        Self {
            superblock: RomfsSuperblock {
                full_size: 0,
                checksum: 0,
                volume_name: [0; MAX_VOLUME_NAME],
                volume_name_len: 0,
                first_file_offset: 0,
            },
            image_size: 0,
            mount_path: [0; MAX_MOUNT_PATH],
            mount_path_len: 0,
            mounted: false,
        }
    }

    /// Mount a ROMFS image.
    ///
    /// Parses the superblock and validates the image. The caller must
    /// ensure that `image_data` remains valid for the lifetime of the mount.
    pub fn mount(&mut self, image_data: &[u8], mount_path: &[u8]) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        if mount_path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        let sb = RomfsSuperblock::parse(image_data)?;
        if sb.full_size as usize > image_data.len() {
            return Err(Error::InvalidArgument);
        }
        self.superblock = sb;
        self.image_size = image_data.len();
        self.mount_path[..mount_path.len()].copy_from_slice(mount_path);
        self.mount_path_len = mount_path.len();
        self.mounted = true;
        Ok(())
    }

    /// Unmount the filesystem.
    pub fn unmount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.mounted = false;
        self.image_size = 0;
        self.mount_path_len = 0;
        Ok(())
    }

    /// Check if the filesystem is mounted.
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// Get the superblock.
    pub fn superblock(&self) -> &RomfsSuperblock {
        &self.superblock
    }

    /// Get the offset of the first file entry.
    pub fn first_file_offset(&self) -> usize {
        self.superblock.first_file_offset
    }

    /// Look up a file by name within a directory.
    ///
    /// `dir_offset` is the byte offset of the first child header (from
    /// the directory's `spec_info` field). Scans the sibling chain.
    pub fn lookup(
        &self,
        image_data: &[u8],
        dir_offset: usize,
        name: &[u8],
    ) -> Result<RomfsFileHeader> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let mut offset = dir_offset;
        while offset != 0 && offset < self.image_size {
            let hdr = RomfsFileHeader::parse(image_data, offset)?;
            if hdr.name_len == name.len() {
                let mut matches = true;
                let mut i = 0;
                while i < name.len() {
                    if hdr.name[i] != name[i] {
                        matches = false;
                        break;
                    }
                    i += 1;
                }
                if matches {
                    return Ok(hdr);
                }
            }
            offset = hdr.next_hdr;
        }
        Err(Error::NotFound)
    }

    /// Resolve a path from the root of the filesystem.
    ///
    /// Path components are separated by `/`. Leading `/` is optional.
    pub fn resolve_path(&self, image_data: &[u8], path: &[u8]) -> Result<RomfsFileHeader> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        // Parse root directory first.
        let root_hdr = RomfsFileHeader::parse(image_data, self.superblock.first_file_offset)?;
        if path.is_empty() || (path.len() == 1 && path[0] == b'/') {
            return Ok(root_hdr);
        }

        let mut current = root_hdr;
        let mut start = 0;
        // Skip leading slash.
        if !path.is_empty() && path[0] == b'/' {
            start = 1;
        }

        while start < path.len() {
            // Find end of current component.
            let mut end = start;
            while end < path.len() && path[end] != b'/' {
                end += 1;
            }
            if end == start {
                start = end + 1;
                continue;
            }
            let component = &path[start..end];

            // Current must be a directory.
            if !current.file_type.is_dir() {
                return Err(Error::NotFound);
            }

            // Look up in the directory's children.
            current = self.lookup(image_data, current.spec_info as usize, component)?;
            start = end + 1;
        }
        Ok(current)
    }

    /// Read data from a regular file.
    ///
    /// `hdr` must refer to a regular file. Reads up to `buf.len()` bytes
    /// starting at `offset` within the file.
    ///
    /// Returns the number of bytes actually read.
    pub fn read(
        &self,
        image_data: &[u8],
        hdr: &RomfsFileHeader,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if !hdr.file_type.is_file() {
            return Err(Error::InvalidArgument);
        }
        let file_size = hdr.size as u64;
        if offset >= file_size {
            return Ok(0);
        }
        let available = (file_size - offset) as usize;
        let to_read = if buf.len() < available {
            buf.len()
        } else {
            available
        };
        let src_start = hdr.data_offset + offset as usize;
        let src_end = src_start + to_read;
        if src_end > image_data.len() {
            return Err(Error::IoError);
        }
        buf[..to_read].copy_from_slice(&image_data[src_start..src_end]);
        Ok(to_read)
    }

    /// Read the target of a symbolic link.
    ///
    /// Returns the number of bytes written to `buf`.
    pub fn readlink(
        &self,
        image_data: &[u8],
        hdr: &RomfsFileHeader,
        buf: &mut [u8],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if !hdr.file_type.is_symlink() {
            return Err(Error::InvalidArgument);
        }
        self.read(
            image_data,
            &RomfsFileHeader {
                file_type: RomfsFileType::RegularFile,
                ..hdr.clone()
            },
            0,
            buf,
        )
    }

    /// List directory contents.
    ///
    /// `dir_hdr` must refer to a directory. Returns the entries found
    /// (up to [`MAX_DIR_ENTRIES`]) and the total count.
    pub fn readdir(
        &self,
        image_data: &[u8],
        dir_hdr: &RomfsFileHeader,
    ) -> Result<([RomfsEntry; MAX_DIR_ENTRIES], usize)> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if !dir_hdr.file_type.is_dir() {
            return Err(Error::InvalidArgument);
        }
        let mut entries = [const { RomfsEntry::empty() }; MAX_DIR_ENTRIES];
        let mut count = 0;
        let mut offset = dir_hdr.spec_info as usize;

        while offset != 0 && offset < self.image_size && count < MAX_DIR_ENTRIES {
            let hdr = RomfsFileHeader::parse(image_data, offset)?;
            // Skip . and .. pseudo-entries.
            if !hdr.is_dot_entry() {
                entries[count].name[..hdr.name_len].copy_from_slice(&hdr.name[..hdr.name_len]);
                entries[count].name_len = hdr.name_len;
                entries[count].file_type = hdr.file_type;
                entries[count].size = hdr.size;
                entries[count].header_offset = hdr.offset;
                entries[count].executable = hdr.executable;
                count += 1;
            }
            offset = hdr.next_hdr;
        }
        Ok((entries, count))
    }

    /// Get file metadata (stat-like) for a file header.
    ///
    /// Returns (file_type, size, executable, data_offset).
    pub fn stat(&self, hdr: &RomfsFileHeader) -> Result<(RomfsFileType, u32, bool, usize)> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        Ok((hdr.file_type, hdr.size, hdr.executable, hdr.data_offset))
    }

    /// Verify the checksum of a file header.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if corrupted.
    pub fn verify_header_checksum(&self, image_data: &[u8], hdr: &RomfsFileHeader) -> Result<bool> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let check_end = hdr.data_offset;
        if check_end > image_data.len() || hdr.offset >= check_end {
            return Err(Error::IoError);
        }
        let check_len = check_end - hdr.offset;
        let sum = compute_checksum(image_data, hdr.offset, check_len);
        Ok(sum == 0)
    }
}

// ── RomfsRegistry ───────────────────────────────────────────────

/// Global registry of ROMFS mount points.
///
/// Tracks up to [`MAX_ROMFS_MOUNTS`] active mounts with their paths.
pub struct RomfsRegistry {
    /// Mount paths.
    paths: [[u8; MAX_MOUNT_PATH]; MAX_ROMFS_MOUNTS],
    /// Path lengths.
    path_lens: [usize; MAX_ROMFS_MOUNTS],
    /// Whether each slot is active.
    active: [bool; MAX_ROMFS_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl RomfsRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            paths: [[0; MAX_MOUNT_PATH]; MAX_ROMFS_MOUNTS],
            path_lens: [0; MAX_ROMFS_MOUNTS],
            active: [false; MAX_ROMFS_MOUNTS],
            count: 0,
        }
    }

    /// Register a new ROMFS mount point.
    ///
    /// Returns the slot index.
    pub fn mount(&mut self, path: &[u8]) -> Result<usize> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        let mut i = 0;
        while i < MAX_ROMFS_MOUNTS {
            if self.active[i]
                && self.path_lens[i] == path.len()
                && self.paths[i][..path.len()] == *path
            {
                return Err(Error::AlreadyExists);
            }
            i += 1;
        }
        // Find a free slot.
        i = 0;
        while i < MAX_ROMFS_MOUNTS {
            if !self.active[i] {
                self.paths[i][..path.len()].copy_from_slice(path);
                self.path_lens[i] = path.len();
                self.active[i] = true;
                self.count += 1;
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Unmount by slot index.
    pub fn unmount(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_ROMFS_MOUNTS || !self.active[slot] {
            return Err(Error::NotFound);
        }
        self.active[slot] = false;
        self.path_lens[slot] = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Look up a mount by path.
    pub fn lookup(&self, path: &[u8]) -> Result<usize> {
        let mut i = 0;
        while i < MAX_ROMFS_MOUNTS {
            if self.active[i]
                && self.path_lens[i] == path.len()
                && self.paths[i][..path.len()] == *path
            {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Return the number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}
