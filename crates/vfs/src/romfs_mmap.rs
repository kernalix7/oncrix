// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! romfs memory-mapped read support for the ONCRIX VFS.
//!
//! romfs is a simple, read-only, linear-layout filesystem used during initrd
//! and early boot. This module implements the page-granular mmap interface
//! that allows romfs file data to be faulted in directly from the image
//! without an intermediate copy buffer.

use oncrix_lib::{Error, Result};

/// romfs magic string (8 bytes) at offset 0 of the image.
pub const ROMFS_MAGIC: &[u8; 8] = b"-rom1fs-";

/// romfs header checksum covers the first 512 bytes of the image.
pub const ROMFS_HEADER_CHECK_LEN: usize = 512;

/// Maximum file name length stored in a romfs directory entry.
pub const ROMFS_MAX_NAME: usize = 128;

/// File type bits stored in the low 3 bits of the inode mode word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RomfsFileType {
    /// Hard link.
    HardLink = 0,
    /// Regular directory.
    Directory = 1,
    /// Regular file.
    RegularFile = 2,
    /// Symbolic link.
    SymLink = 3,
    /// Block device.
    BlockDev = 4,
    /// Character device.
    CharDev = 5,
    /// Socket.
    Socket = 6,
    /// FIFO/pipe.
    Fifo = 7,
}

impl RomfsFileType {
    /// Parse the type from the low 3 bits of the raw header word.
    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw & 0x07 {
            0 => Ok(Self::HardLink),
            1 => Ok(Self::Directory),
            2 => Ok(Self::RegularFile),
            3 => Ok(Self::SymLink),
            4 => Ok(Self::BlockDev),
            5 => Ok(Self::CharDev),
            6 => Ok(Self::Socket),
            7 => Ok(Self::Fifo),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// An on-disk romfs inode header (32 bytes before the file name).
#[derive(Debug, Clone, Copy)]
pub struct RomfsDirent {
    /// Byte offset of the next directory entry (0 = last entry).
    pub next_offset: u32,
    /// Spec field: device number for dev nodes, target inode for hard links.
    pub spec: u32,
    /// Size of the file data in bytes.
    pub size: u32,
    /// Checksum of this header.
    pub checksum: u32,
}

impl RomfsDirent {
    /// Parse a directory entry from a 16-byte raw header slice.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            next_offset: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            spec: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            size: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            checksum: u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]),
        })
    }

    /// Return the raw `next_offset` with type bits masked out.
    pub fn next_entry_offset(&self) -> u32 {
        self.next_offset & !0xfu32
    }

    /// Return the file type encoded in the low 4 bits of `next_offset`.
    pub fn file_type(&self) -> Result<RomfsFileType> {
        RomfsFileType::from_raw((self.next_offset & 0x07) as u8)
    }

    /// Return `true` if the executable bit is set (bit 3 of next_offset).
    pub fn is_executable(&self) -> bool {
        self.next_offset & 0x08 != 0
    }
}

impl Default for RomfsDirent {
    fn default() -> Self {
        Self {
            next_offset: 0,
            spec: 0,
            size: 0,
            checksum: 0,
        }
    }
}

/// Describes a single mmap mapping window into a romfs image.
#[derive(Debug, Clone, Copy)]
pub struct RomfsMmapWindow {
    /// Physical or virtual base address of the romfs image.
    pub image_base: usize,
    /// Byte offset within the image where this file's data begins.
    pub data_offset: usize,
    /// Total size of the file's data in bytes.
    pub data_size: usize,
    /// Page-aligned start of the mmap region.
    pub mmap_start: usize,
    /// Length of the mmap region in bytes (page-aligned up).
    pub mmap_len: usize,
}

impl RomfsMmapWindow {
    /// Create a new mmap window descriptor.
    pub const fn new(image_base: usize, data_offset: usize, data_size: usize) -> Self {
        let page_size = 4096usize;
        let mmap_start = data_offset & !(page_size - 1);
        let end = data_offset + data_size;
        let mmap_end = (end + page_size - 1) & !(page_size - 1);
        Self {
            image_base,
            data_offset,
            data_size,
            mmap_start,
            mmap_len: mmap_end - mmap_start,
        }
    }

    /// Compute the address of a byte at `file_offset` within this window.
    ///
    /// Returns `InvalidArgument` if `file_offset` is out of range.
    pub fn byte_address(&self, file_offset: usize) -> Result<usize> {
        if file_offset >= self.data_size {
            return Err(Error::InvalidArgument);
        }
        Ok(self.image_base + self.data_offset + file_offset)
    }

    /// Return a reference to a byte slice of `len` bytes starting at `file_offset`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `image_base` points to a valid, mapped, read-only
    /// region of at least `data_offset + data_size` bytes.
    pub unsafe fn slice(&self, file_offset: usize, len: usize) -> Result<&'static [u8]> {
        if file_offset + len > self.data_size {
            return Err(Error::InvalidArgument);
        }
        let ptr = (self.image_base + self.data_offset + file_offset) as *const u8;
        // SAFETY: Caller guarantees the image region is valid and stable.
        Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
    }
}

impl Default for RomfsMmapWindow {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Table of mmap windows for all files in a mounted romfs image.
pub struct RomfsMmapTable {
    windows: [RomfsMmapWindow; 64],
    count: usize,
}

impl RomfsMmapTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            windows: [const { RomfsMmapWindow::new(0, 0, 0) }; 64],
            count: 0,
        }
    }

    /// Insert a new window, returning `OutOfMemory` if the table is full.
    pub fn insert(&mut self, window: RomfsMmapWindow) -> Result<usize> {
        if self.count >= 64 {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.windows[idx] = window;
        self.count += 1;
        Ok(idx)
    }

    /// Look up a window by index.
    pub fn get(&self, idx: usize) -> Result<&RomfsMmapWindow> {
        if idx >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&self.windows[idx])
    }

    /// Return the number of registered windows.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no windows are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for RomfsMmapTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify the romfs magic bytes at the start of an image buffer.
pub fn verify_magic(buf: &[u8]) -> Result<()> {
    if buf.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    if &buf[..8] == ROMFS_MAGIC.as_ref() {
        Ok(())
    } else {
        Err(Error::InvalidArgument)
    }
}

/// Compute the page-aligned size needed to map `byte_size` bytes starting at `offset`.
pub fn mmap_aligned_size(offset: usize, byte_size: usize) -> usize {
    const PAGE_SIZE: usize = 4096;
    let aligned_start = offset & !(PAGE_SIZE - 1);
    let end = offset + byte_size;
    let aligned_end = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    aligned_end - aligned_start
}

/// Round a byte offset up to the next 16-byte boundary (romfs alignment).
pub fn romfs_align(offset: usize) -> usize {
    (offset + 15) & !15
}
