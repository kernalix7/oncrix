// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! cramfs — Compressed ROM Filesystem.
//!
//! cramfs is a simple, space-efficient, read-only filesystem designed for
//! embedded systems and initramfs images.  It uses zlib compression for
//! file data while keeping metadata uncompressed for fast access.
//!
//! # On-disk layout
//!
//! ```text
//! ┌──────────────────────┬────────────────────┬────────────────────┐
//! │  Superblock (76 B)   │  Packed inodes     │  Compressed data   │
//! │  magic, size, crc    │  (12 B each)       │  (zlib blocks)     │
//! └──────────────────────┴────────────────────┴────────────────────┘
//! ```
//!
//! ## Superblock
//!
//! The superblock is 76 bytes and contains the magic number, filesystem
//! size, feature flags, and a CRC32 checksum over the entire image.
//!
//! ## Packed inodes
//!
//! Each inode is packed into 12 bytes containing:
//! - mode (16 bits), uid (16 bits), size (24 bits), gid (8 bits)
//! - namelen (6 bits), offset (26 bits)
//!
//! The limited bit widths impose hard limits: max file size 16 MiB,
//! max uid/gid 65535, max name length 63 bytes.
//!
//! ## Compressed data
//!
//! File data is compressed in 4 KiB page blocks.  Each file's data
//! area starts with a block pointer table (one u32 per page), followed
//! by the compressed page data.
//!
//! # Page cache integration
//!
//! cramfs decompresses pages on demand and caches them in the VFS page
//! cache.  Repeated reads of the same page avoid re-decompression.
//!
//! # Reference
//!
//! Linux `fs/cramfs/`, cramfs specification (Linus Torvalds, 1999).

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// cramfs magic number (`0x28cd3d45`).
pub const CRAMFS_MAGIC: u32 = 0x28cd3d45;

/// cramfs signature string.
pub const CRAMFS_SIGNATURE: &[u8; 16] = b"Compressed ROMFS";

/// Superblock size in bytes.
const SUPERBLOCK_SIZE: usize = 76;

/// Packed inode size in bytes.
const PACKED_INODE_SIZE: usize = 12;

/// Page size for compression blocks.
const PAGE_SIZE: usize = 4096;

/// Maximum file size (24-bit size field = 16 MiB).
const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum filename length (6-bit namelen * 4 = 252).
const MAX_NAME_LEN: usize = 252;

/// Maximum inode count.
const MAX_INODES: usize = 1024;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 256;

/// Maximum compressed data tracked in the page cache.
const MAX_CACHED_PAGES: usize = 512;

/// Maximum file data size for our in-memory model.
const MAX_MODEL_DATA: usize = 65536;

/// Compression ratio estimate for simulated compression.
const COMPRESSION_RATIO_NUM: usize = 1;
/// Compression ratio denominator (50% compression = 1/2).
const COMPRESSION_RATIO_DEN: usize = 2;

// ── Superblock ───────────────────────────────────────────────────────────────

/// cramfs superblock (76 bytes on disk).
#[derive(Debug, Clone, Copy)]
pub struct CramfsSuperblock {
    /// Magic number ([`CRAMFS_MAGIC`]).
    pub magic: u32,
    /// Total filesystem size in bytes.
    pub size: u32,
    /// Feature flags.
    pub flags: CramfsFlags,
    /// Reserved (future version info).
    pub future: u32,
    /// Signature ([`CRAMFS_SIGNATURE`]).
    pub signature: [u8; 16],
    /// CRC32 checksum of the entire image.
    pub crc: u32,
    /// Edition number (versioning).
    pub edition: u32,
    /// Number of blocks in the filesystem.
    pub blocks: u32,
    /// Number of files (inodes).
    pub files: u32,
    /// Volume name (first 16 bytes).
    pub name: [u8; 16],
}

/// cramfs feature flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CramfsFlags(pub u32);

impl CramfsFlags {
    /// Filesystem uses sorted directories.
    pub const SORTED_DIRS: Self = Self(0x0001);
    /// Filesystem includes holes (sparse files).
    pub const HOLES: Self = Self(0x0100);
    /// Shifted root offset (extended cramfs).
    pub const SHIFTED_ROOT: Self = Self(0x0200);

    /// Check if sorted directories are used.
    pub fn sorted_dirs(self) -> bool {
        self.0 & Self::SORTED_DIRS.0 != 0
    }
}

impl CramfsSuperblock {
    /// Create a new superblock for an image containing `files` files
    /// totalling `size` bytes.
    pub fn new(size: u32, files: u32) -> Self {
        let blocks = (size + PAGE_SIZE as u32 - 1) / PAGE_SIZE as u32;
        let mut name = [0u8; 16];
        let label = b"oncrix-cramfs";
        let copy_len = label.len().min(16);
        name[..copy_len].copy_from_slice(&label[..copy_len]);
        Self {
            magic: CRAMFS_MAGIC,
            size,
            flags: CramfsFlags(CramfsFlags::SORTED_DIRS.0),
            future: 0,
            signature: *CRAMFS_SIGNATURE,
            crc: 0,
            edition: 1,
            blocks,
            files,
            name,
        }
    }

    /// Validate superblock fields.
    pub fn validate(&self) -> Result<()> {
        if self.magic != CRAMFS_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.signature != *CRAMFS_SIGNATURE {
            return Err(Error::InvalidArgument);
        }
        if self.size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Volume label as a string.
    pub fn volume_name(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}

// ── Packed inode ─────────────────────────────────────────────────────────────

/// cramfs packed inode (12 bytes on disk).
///
/// Fields are packed into bitfields for maximum space efficiency.
#[derive(Debug, Clone, Copy)]
pub struct CramfsPackedInode {
    /// File mode (permissions + type), 16 bits.
    pub mode: u16,
    /// User ID (16 bits, max 65535).
    pub uid: u16,
    /// File size (24 bits, max 16 MiB).
    pub size: u32,
    /// Group ID (8 bits, max 255).
    pub gid: u8,
    /// Name length in 4-byte units (6 bits, max 63 * 4 = 252 chars).
    pub namelen: u8,
    /// Data offset in 4-byte units (26 bits).
    pub offset: u32,
}

impl CramfsPackedInode {
    /// Maximum representable file size.
    pub const MAX_SIZE: u32 = (1 << 24) - 1;

    /// Maximum representable offset.
    pub const MAX_OFFSET: u32 = (1 << 26) - 1;

    /// Create a packed inode for a regular file.
    pub fn new_file(mode: u16, size: u32) -> Self {
        Self {
            mode,
            uid: 0,
            size: size & Self::MAX_SIZE,
            gid: 0,
            namelen: 0,
            offset: 0,
        }
    }

    /// Create a packed inode for a directory.
    pub fn new_dir(mode: u16, size: u32) -> Self {
        // Directories encode size as the total size of child inodes.
        Self {
            mode: mode | 0o040000, // S_IFDIR
            uid: 0,
            size: size & Self::MAX_SIZE,
            gid: 0,
            namelen: 0,
            offset: 0,
        }
    }

    /// Filename length in bytes.
    pub fn name_length(&self) -> usize {
        (self.namelen as usize) * 4
    }

    /// Data offset in bytes.
    pub fn data_offset(&self) -> usize {
        (self.offset as usize) * 4
    }

    /// Extract the file type from the mode field.
    pub fn file_type(&self) -> FileType {
        match self.mode & 0o170000 {
            0o100000 => FileType::Regular,
            0o040000 => FileType::Directory,
            0o120000 => FileType::Symlink,
            0o020000 => FileType::CharDevice,
            0o060000 => FileType::BlockDevice,
            0o010000 => FileType::Fifo,
            0o140000 => FileType::Socket,
            _ => FileType::Regular,
        }
    }
}

// ── In-memory inode ──────────────────────────────────────────────────────────

/// In-memory cramfs inode with expanded metadata.
#[derive(Debug, Clone)]
pub struct CramfsInode {
    /// Inode number.
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
    /// Permission bits (lower 12 bits of mode).
    pub mode: u16,
    /// File size in bytes.
    pub size: u32,
    /// User ID.
    pub uid: u16,
    /// Group ID.
    pub gid: u8,
    /// Hard link count (always 1 for cramfs).
    pub nlink: u32,
    /// Data offset in the image.
    pub data_offset: u32,
    /// Name (for directory entries).
    pub name: String,
}

impl CramfsInode {
    /// Create from a packed inode.
    pub fn from_packed(ino: u64, packed: &CramfsPackedInode, name: &str) -> Self {
        Self {
            ino,
            file_type: packed.file_type(),
            mode: packed.mode & 0o7777,
            size: packed.size,
            uid: packed.uid,
            gid: packed.gid,
            nlink: 1,
            data_offset: packed.offset,
            name: String::from(name),
        }
    }

    /// Create a root directory inode.
    pub fn root() -> Self {
        Self {
            ino: 1,
            file_type: FileType::Directory,
            mode: 0o755,
            size: 0,
            uid: 0,
            gid: 0,
            nlink: 2,
            data_offset: 0,
            name: String::new(),
        }
    }

    /// Convert to a VFS [`Inode`].
    pub fn to_vfs_inode(&self) -> Inode {
        let mut vfs = Inode::new(InodeNumber(self.ino), self.file_type, FileMode(self.mode));
        vfs.size = u64::from(self.size);
        vfs.nlink = self.nlink;
        vfs.uid = u32::from(self.uid);
        vfs.gid = u32::from(self.gid);
        vfs
    }
}

// ── Page cache ───────────────────────────────────────────────────────────────

/// A cached decompressed page.
#[derive(Debug, Clone)]
pub struct CachedPage {
    /// Inode number this page belongs to.
    pub ino: u64,
    /// Page index within the file.
    pub page_index: u32,
    /// Decompressed page data (up to PAGE_SIZE bytes).
    pub data: Vec<u8>,
    /// Whether this page has been accessed (for LRU eviction).
    pub accessed: bool,
}

/// Simple page cache for decompressed cramfs pages.
pub struct CramfsPageCache {
    /// Cached pages.
    pages: Vec<CachedPage>,
    /// Maximum number of cached pages.
    max_pages: usize,
    /// Cache hit count.
    pub hits: u64,
    /// Cache miss count.
    pub misses: u64,
}

impl CramfsPageCache {
    /// Create a new page cache.
    pub fn new(max_pages: usize) -> Self {
        Self {
            pages: Vec::new(),
            max_pages,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a cached page.
    pub fn get(&mut self, ino: u64, page_index: u32) -> Option<&CachedPage> {
        if let Some(pos) = self
            .pages
            .iter()
            .position(|p| p.ino == ino && p.page_index == page_index)
        {
            self.pages[pos].accessed = true;
            self.hits += 1;
            Some(&self.pages[pos])
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a page, evicting LRU if necessary.
    pub fn insert(&mut self, page: CachedPage) {
        // Evict if at capacity.
        if self.pages.len() >= self.max_pages {
            // Find a non-accessed page to evict.
            if let Some(pos) = self.pages.iter().position(|p| !p.accessed) {
                self.pages.remove(pos);
            } else {
                // All accessed — reset flags and evict first.
                for p in &mut self.pages {
                    p.accessed = false;
                }
                if !self.pages.is_empty() {
                    self.pages.remove(0);
                }
            }
        }
        self.pages.push(page);
    }

    /// Invalidate all pages for an inode.
    pub fn invalidate(&mut self, ino: u64) {
        self.pages.retain(|p| p.ino != ino);
    }

    /// Number of cached pages.
    pub fn cached_count(&self) -> usize {
        self.pages.len()
    }

    /// Cache hit rate as a percentage.
    pub fn hit_rate_percent(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        ((self.hits * 100) / total) as u32
    }
}

// ── Simulated decompression ──────────────────────────────────────────────────

/// Simulated zlib decompression.
///
/// In a real kernel this would call into a zlib or deflate implementation.
/// For modelling we store data uncompressed and simulate the decompression
/// step by copying.
fn decompress_page(compressed: &[u8], output: &mut [u8]) -> Result<usize> {
    // Simulated: compressed data IS the uncompressed data (identity).
    let len = compressed.len().min(output.len());
    output[..len].copy_from_slice(&compressed[..len]);
    Ok(len)
}

/// Simulated zlib compression.
fn compress_page(input: &[u8]) -> Vec<u8> {
    // Simulated: store a prefix to indicate "compression".
    // Real implementation would produce deflate output.
    let compressed_len = (input.len() * COMPRESSION_RATIO_NUM) / COMPRESSION_RATIO_DEN;
    let len = compressed_len.max(1);
    Vec::from(&input[..len.min(input.len())])
}

// ── Directory entry ──────────────────────────────────────────────────────────

/// In-memory directory entry.
#[derive(Debug, Clone)]
struct CramfsDirEntry {
    /// Target inode number.
    ino: u64,
    /// File type.
    file_type: FileType,
    /// Entry name.
    name: String,
}

// ── File data storage ────────────────────────────────────────────────────────

/// Compressed file data stored in the image.
struct CramfsFileData {
    /// Owning inode number.
    ino: u64,
    /// Uncompressed file data (for our model; real cramfs stores compressed).
    data: Vec<u8>,
    /// Compressed block sizes (one per page).
    block_sizes: Vec<u32>,
}

// ── Mounted filesystem ───────────────────────────────────────────────────────

/// Mounted cramfs filesystem handle.
///
/// Provides a read-only filesystem with compressed data and a page cache
/// for decompressed pages.
pub struct CramfsFs {
    /// Superblock.
    sb: CramfsSuperblock,
    /// Inode table.
    inodes: Vec<CramfsInode>,
    /// Directory entries (parent_ino, entry).
    dir_entries: Vec<(u64, CramfsDirEntry)>,
    /// Compressed file data.
    file_data: Vec<CramfsFileData>,
    /// Page cache.
    page_cache: CramfsPageCache,
    /// Next inode number (for building the image).
    next_ino: u64,
}

impl CramfsFs {
    /// Create a new cramfs filesystem image.
    ///
    /// After creation, populate with [`add_file`] and [`add_directory`],
    /// then use `finalize` to set the superblock size.
    pub fn new() -> Self {
        let root = CramfsInode::root();
        let sb = CramfsSuperblock::new(SUPERBLOCK_SIZE as u32, 0);
        Self {
            sb,
            inodes: alloc::vec![root],
            dir_entries: Vec::new(),
            file_data: Vec::new(),
            page_cache: CramfsPageCache::new(MAX_CACHED_PAGES),
            next_ino: 2,
        }
    }

    /// Return a reference to the superblock.
    pub fn superblock(&self) -> &CramfsSuperblock {
        &self.sb
    }

    /// Return the page cache.
    pub fn page_cache(&self) -> &CramfsPageCache {
        &self.page_cache
    }

    /// Add a file to the filesystem image.
    pub fn add_file(&mut self, parent_ino: u64, name: &str, mode: u16, data: &[u8]) -> Result<u64> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_FILE_SIZE {
            return Err(Error::OutOfMemory);
        }
        if self.inodes.len() >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate name.
        if self
            .dir_entries
            .iter()
            .any(|(p, e)| *p == parent_ino && e.name == name)
        {
            return Err(Error::AlreadyExists);
        }

        let ino = self.next_ino;
        self.next_ino += 1;

        let packed = CramfsPackedInode::new_file(mode, data.len() as u32);
        let inode = CramfsInode::from_packed(ino, &packed, name);
        self.inodes.push(inode);

        // Compute compressed block sizes.
        let mut block_sizes = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + PAGE_SIZE).min(data.len());
            let compressed = compress_page(&data[offset..end]);
            block_sizes.push(compressed.len() as u32);
            offset = end;
        }

        self.file_data.push(CramfsFileData {
            ino,
            data: Vec::from(data),
            block_sizes,
        });

        self.dir_entries.push((
            parent_ino,
            CramfsDirEntry {
                ino,
                file_type: FileType::Regular,
                name: String::from(name),
            },
        ));

        self.sb.files += 1;
        Ok(ino)
    }

    /// Add a directory to the filesystem image.
    pub fn add_directory(&mut self, parent_ino: u64, name: &str, mode: u16) -> Result<u64> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.inodes.len() >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        if self
            .dir_entries
            .iter()
            .any(|(p, e)| *p == parent_ino && e.name == name)
        {
            return Err(Error::AlreadyExists);
        }

        let ino = self.next_ino;
        self.next_ino += 1;

        let packed = CramfsPackedInode::new_dir(mode, 0);
        let inode = CramfsInode::from_packed(ino, &packed, name);
        self.inodes.push(inode);

        self.dir_entries.push((
            parent_ino,
            CramfsDirEntry {
                ino,
                file_type: FileType::Directory,
                name: String::from(name),
            },
        ));

        self.sb.files += 1;
        Ok(ino)
    }

    /// Finalize the image by computing the total size and CRC.
    pub fn finalize(&mut self) {
        let total_data: usize = self.file_data.iter().map(|f| f.data.len()).sum();
        let inode_area = self.inodes.len() * PACKED_INODE_SIZE;
        let total = SUPERBLOCK_SIZE + inode_area + total_data;
        self.sb.size = total as u32;
        self.sb.blocks = ((total + PAGE_SIZE - 1) / PAGE_SIZE) as u32;
        // CRC is left as 0 for the model — real cramfs computes CRC32.
    }

    /// Read a page from a file, using the page cache.
    fn read_page(&mut self, ino: u64, page_index: u32) -> Result<Vec<u8>> {
        // Check page cache first.
        if let Some(cached) = self.page_cache.get(ino, page_index) {
            return Ok(cached.data.clone());
        }

        // Cache miss — decompress from stored data.
        let fd = self
            .file_data
            .iter()
            .find(|f| f.ino == ino)
            .ok_or(Error::NotFound)?;

        let start = page_index as usize * PAGE_SIZE;
        if start >= fd.data.len() {
            return Ok(Vec::new());
        }
        let end = (start + PAGE_SIZE).min(fd.data.len());
        let compressed = &fd.data[start..end];

        let mut output = alloc::vec![0u8; PAGE_SIZE];
        let decompressed_len = decompress_page(compressed, &mut output)?;
        output.truncate(decompressed_len);

        // Insert into cache.
        self.page_cache.insert(CachedPage {
            ino,
            page_index,
            data: output.clone(),
            accessed: true,
        });

        Ok(output)
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Find an inode by number.
    fn find_inode(&self, ino: u64) -> Result<&CramfsInode> {
        self.inodes
            .iter()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Find a directory entry by parent and name.
    fn find_dir_entry(&self, parent_ino: u64, name: &str) -> Result<&CramfsDirEntry> {
        self.dir_entries
            .iter()
            .find(|(p, e)| *p == parent_ino && e.name == name)
            .map(|(_, e)| e)
            .ok_or(Error::NotFound)
    }
}

// ── InodeOps implementation (read-only) ──────────────────────────────────────

impl InodeOps for CramfsFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let entry = self.find_dir_entry(parent.ino.0, name)?;
        let inode = self.find_inode(entry.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn create(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        // Read-only filesystem.
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
        let cramfs_inode = self.find_inode(inode.ino.0)?;
        if cramfs_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let fd = self
            .file_data
            .iter()
            .find(|f| f.ino == inode.ino.0)
            .ok_or(Error::NotFound)?;

        let start = offset as usize;
        if start >= fd.data.len() {
            return Ok(0);
        }
        let available = fd.data.len() - start;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&fd.data[start..start + to_read]);
        Ok(to_read)
    }

    fn write(&mut self, _inode: &Inode, _offset: u64, _data: &[u8]) -> Result<usize> {
        // Read-only filesystem.
        Err(Error::PermissionDenied)
    }

    fn truncate(&mut self, _inode: &Inode, _size: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }
}
