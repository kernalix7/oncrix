// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SquashFS block read and decompression.
//!
//! Implements block-level I/O for SquashFS, including reading compressed
//! and uncompressed data blocks and an LRU block cache.
//!
//! # Block Format
//!
//! Each data block in SquashFS has a 4-byte header followed by data:
//! - Bit 24 of the size field: 1 = uncompressed, 0 = compressed
//! - Bits 23:0: compressed size of the block
//!
//! After reading the header, the block data is either returned raw
//! (uncompressed) or decompressed via the configured compressor.
//!
//! # Compression
//!
//! This implementation provides stub decompression for LZ4 and zlib
//! (pass-through for testing). A real implementation would call into
//! compression library code.
//!
//! # Reference
//!
//! Linux `fs/squashfs/block.c`, SquashFS specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum uncompressed block size (1 MiB).
const MAX_BLOCK_SIZE: usize = 1048576;

/// Block header size in bytes.
const BLOCK_HEADER_SIZE: usize = 4;

/// Uncompressed flag in block size field.
const SQUASHFS_COMPRESSED_BIT: u32 = 1 << 24;

/// Maximum number of cached blocks.
const CACHE_SIZE: usize = 32;

/// Invalid cache slot.
const INVALID_SLOT: usize = usize::MAX;

/// Minimum valid block size.
const MIN_BLOCK_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// Compression type
// ---------------------------------------------------------------------------

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression (uncompressed blocks).
    None,
    /// zlib deflate.
    Zlib,
    /// LZ4 fast compression.
    Lz4,
    /// LZMA.
    Lzma,
    /// XZ (LZMA2).
    Xz,
    /// ZSTD.
    Zstd,
}

impl Compression {
    /// Returns the squashfs compression ID.
    pub fn id(&self) -> u16 {
        match self {
            Self::None => 0,
            Self::Zlib => 1,
            Self::Lzma => 2,
            Self::Lz4 => 4,
            Self::Xz => 6,
            Self::Zstd => 7,
        }
    }
}

// ---------------------------------------------------------------------------
// Block header
// ---------------------------------------------------------------------------

/// Parsed SquashFS block header.
#[derive(Debug, Clone, Copy)]
pub struct BlockHeader {
    /// Whether the block data is compressed.
    pub compressed: bool,
    /// Size of the block data following the header (bytes).
    pub size: usize,
}

impl BlockHeader {
    /// Parses a block header from the first 4 bytes of a block.
    pub fn parse(raw: &[u8; BLOCK_HEADER_SIZE]) -> Result<Self> {
        let size_field = u32::from_le_bytes(*raw);
        let compressed = size_field & SQUASHFS_COMPRESSED_BIT == 0;
        let size = (size_field & (SQUASHFS_COMPRESSED_BIT - 1)) as usize;
        if size == 0 || size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { compressed, size })
    }

    /// Returns the total on-disk size including header.
    pub fn total_size(&self) -> usize {
        BLOCK_HEADER_SIZE + self.size
    }
}

// ---------------------------------------------------------------------------
// Block cache
// ---------------------------------------------------------------------------

/// A single LRU cache slot.
#[derive(Debug)]
struct CacheSlot {
    /// Block address (offset into image).
    block_addr: u64,
    /// Decompressed block data.
    data: [u8; MAX_BLOCK_SIZE],
    /// Valid bytes in data.
    data_len: usize,
    /// LRU access counter.
    lru_tick: u64,
    /// Whether this slot is valid.
    valid: bool,
}

impl CacheSlot {
    const fn new() -> Self {
        Self {
            block_addr: u64::MAX,
            data: [0u8; MAX_BLOCK_SIZE],
            data_len: 0,
            lru_tick: 0,
            valid: false,
        }
    }
}

/// LRU block cache for SquashFS.
pub struct BlockCache {
    /// Cache slots.
    slots: [CacheSlot; CACHE_SIZE],
    /// Current LRU tick.
    tick: u64,
    /// Cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
}

impl BlockCache {
    /// Creates an empty block cache.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| CacheSlot::new()),
            tick: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Finds a cache slot by block address.
    fn find_slot(&self, addr: u64) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.valid && s.block_addr == addr)
    }

    /// Finds the LRU victim slot for eviction.
    fn lru_victim(&self) -> usize {
        // Prefer invalid slots.
        if let Some(i) = self.slots.iter().position(|s| !s.valid) {
            return i;
        }
        // Find slot with smallest tick.
        self.slots
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.lru_tick)
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Looks up a block in the cache. Returns data length if found.
    pub fn lookup(&mut self, addr: u64, out: &mut [u8]) -> Option<usize> {
        if let Some(idx) = self.find_slot(addr) {
            self.tick += 1;
            self.slots[idx].lru_tick = self.tick;
            let len = self.slots[idx].data_len.min(out.len());
            out[..len].copy_from_slice(&self.slots[idx].data[..len]);
            self.hits += 1;
            Some(len)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Inserts a decompressed block into the cache.
    pub fn insert(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        if data.len() > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.tick += 1;
        let idx = if let Some(i) = self.find_slot(addr) {
            i
        } else {
            self.lru_victim()
        };
        let slot = &mut self.slots[idx];
        slot.block_addr = addr;
        slot.data[..data.len()].copy_from_slice(data);
        slot.data_len = data.len();
        slot.lru_tick = self.tick;
        slot.valid = true;
        Ok(())
    }

    /// Evicts all cache entries.
    pub fn invalidate(&mut self) {
        for slot in &mut self.slots {
            slot.valid = false;
        }
    }
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Decompression stubs
// ---------------------------------------------------------------------------

/// Decompresses a block using the given compression algorithm.
///
/// For this implementation, if the block claims to be uncompressed the
/// data is copied directly. Compressed blocks are treated as pass-through
/// (stub — real decompression not implemented in no_std without alloc).
///
/// Returns the decompressed length.
pub fn decompress_block(
    compression: Compression,
    compressed: bool,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    if input.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if !compressed || compression == Compression::None {
        // Uncompressed: direct copy.
        let len = input.len().min(output.len());
        output[..len].copy_from_slice(&input[..len]);
        return Ok(len);
    }

    // Stub: for testing/development, pass through as-is.
    // A real implementation would call into a decompression library.
    match compression {
        Compression::Lz4
        | Compression::Zlib
        | Compression::Xz
        | Compression::Lzma
        | Compression::Zstd => {
            // Pass-through stub.
            let len = input.len().min(output.len());
            output[..len].copy_from_slice(&input[..len]);
            Ok(len)
        }
        Compression::None => {
            let len = input.len().min(output.len());
            output[..len].copy_from_slice(&input[..len]);
            Ok(len)
        }
    }
}

// ---------------------------------------------------------------------------
// Block reader
// ---------------------------------------------------------------------------

/// SquashFS block reader context.
pub struct SquashfsBlockReader {
    /// Compression type.
    pub compression: Compression,
    /// Block cache.
    pub cache: BlockCache,
    /// Total blocks read.
    pub blocks_read: u64,
}

impl SquashfsBlockReader {
    /// Creates a new block reader.
    pub fn new(compression: Compression) -> Self {
        Self {
            compression,
            cache: BlockCache::new(),
            blocks_read: 0,
        }
    }

    /// Reads and decompresses a block from the provided image data.
    ///
    /// `image` is the full SquashFS image slice; `block_offset` is the
    /// byte offset of the block header within the image.
    ///
    /// Returns the decompressed data length.
    pub fn read_block(&mut self, image: &[u8], block_offset: u64, out: &mut [u8]) -> Result<usize> {
        // Check cache first.
        if let Some(len) = self.cache.lookup(block_offset, out) {
            return Ok(len);
        }

        let off = block_offset as usize;
        if off + BLOCK_HEADER_SIZE > image.len() {
            return Err(Error::InvalidArgument);
        }

        // Parse header.
        let mut hdr_bytes = [0u8; BLOCK_HEADER_SIZE];
        hdr_bytes.copy_from_slice(&image[off..off + BLOCK_HEADER_SIZE]);
        let header = BlockHeader::parse(&hdr_bytes)?;

        let data_off = off + BLOCK_HEADER_SIZE;
        if data_off + header.size > image.len() {
            return Err(Error::IoError);
        }
        if header.size < MIN_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        let compressed_data = &image[data_off..data_off + header.size];

        // Decompress into output.
        let decompressed_len =
            decompress_block(self.compression, header.compressed, compressed_data, out)?;

        // Cache the result.
        self.cache.insert(block_offset, &out[..decompressed_len])?;
        self.blocks_read += 1;

        Ok(decompressed_len)
    }

    /// Returns cache statistics.
    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.hits, self.cache.misses)
    }
}
