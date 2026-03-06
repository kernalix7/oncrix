// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs compression support.
//!
//! Btrfs can transparently compress file data extents using LZO, ZLIB, or
//! ZSTD.  Small files may be stored inline with the inode item and compressed
//! in-place.  This module implements the policy and bookkeeping layer:
//! algorithm selection, workspace management, compressed extent tracking, and
//! the incompressibility heuristic that prevents wasted effort on already-
//! compressed data.
//!
//! # Design
//!
//! - [`CompressionAlgo`] — algorithm selector with on-disk encoding
//! - [`CompressWorkspace`] — fixed-size scratch buffers (no heap allocation)
//! - [`CompressedExtent`] — metadata for one compressed on-disk extent
//! - `compress_heuristic` — entropy sample to decide whether to attempt compression
//! - `compress_extent` / `decompress_extent` — stub compress/decompress paths
//! - [`InlineCompress`] — inline-data compression for small files
//!
//! # References
//!
//! - Linux `fs/btrfs/compression.c`, `fs/btrfs/compression.h`
//! - `include/uapi/linux/btrfs.h` (BTRFS_COMPRESS_* constants)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Btrfs page size (4 KiB).
pub const BTRFS_PAGE_SIZE: usize = 4096;

/// Maximum pages handled in one compression pass.
pub const MAX_COMPRESS_PAGES: usize = 16;

/// Workspace buffer capacity in bytes.
pub const WORKSPACE_BYTES: usize = BTRFS_PAGE_SIZE * MAX_COMPRESS_PAGES;

/// Minimum compressed size ratio (out of 100) to accept the result.
/// A value of 85 means the compressed form must be ≤ 85 % of the original.
pub const MIN_RATIO_ACCEPT: usize = 85;

/// Entropy sample length for the incompressibility heuristic.
pub const ENTROPY_SAMPLE_LEN: usize = 512;

/// Maximum inline data size eligible for compression (256 bytes).
pub const MAX_INLINE_SIZE: usize = 256;

/// Btrfs on-disk compression type: none.
pub const BTRFS_COMPRESS_NONE: u8 = 0;
/// Btrfs on-disk compression type: ZLIB.
pub const BTRFS_COMPRESS_ZLIB: u8 = 1;
/// Btrfs on-disk compression type: LZO.
pub const BTRFS_COMPRESS_LZO: u8 = 2;
/// Btrfs on-disk compression type: ZSTD.
pub const BTRFS_COMPRESS_ZSTD: u8 = 3;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Compression algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionAlgo {
    /// No compression; data is stored verbatim.
    #[default]
    None,
    /// ZLIB deflate (moderate speed, good ratio).
    Zlib,
    /// LZO (very fast, moderate ratio).
    Lzo,
    /// ZSTD (excellent ratio, configurable speed via level).
    Zstd,
}

impl CompressionAlgo {
    /// Convert to the Btrfs on-disk type byte.
    pub fn as_u8(self) -> u8 {
        match self {
            CompressionAlgo::None => BTRFS_COMPRESS_NONE,
            CompressionAlgo::Zlib => BTRFS_COMPRESS_ZLIB,
            CompressionAlgo::Lzo => BTRFS_COMPRESS_LZO,
            CompressionAlgo::Zstd => BTRFS_COMPRESS_ZSTD,
        }
    }

    /// Construct from the Btrfs on-disk type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            BTRFS_COMPRESS_NONE => Some(CompressionAlgo::None),
            BTRFS_COMPRESS_ZLIB => Some(CompressionAlgo::Zlib),
            BTRFS_COMPRESS_LZO => Some(CompressionAlgo::Lzo),
            BTRFS_COMPRESS_ZSTD => Some(CompressionAlgo::Zstd),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            CompressionAlgo::None => "none",
            CompressionAlgo::Zlib => "zlib",
            CompressionAlgo::Lzo => "lzo",
            CompressionAlgo::Zstd => "zstd",
        }
    }
}

/// Scratch workspace for one compression or decompression pass.
///
/// The buffers are stack/static rather than heap-allocated; `WORKSPACE_BYTES`
/// must fit in the kernel stack budget for the calling context.
pub struct CompressWorkspace {
    /// Input data buffer.
    pub input: [u8; WORKSPACE_BYTES],
    /// Output data buffer.
    pub output: [u8; WORKSPACE_BYTES],
    /// Number of valid bytes in `input`.
    pub input_len: usize,
    /// Number of valid bytes in `output` after a compress/decompress call.
    pub output_len: usize,
    /// Algorithm this workspace is configured for.
    pub algo: CompressionAlgo,
    /// ZSTD compression level (1–22); ignored for other algorithms.
    pub zstd_level: i32,
}

impl Default for CompressWorkspace {
    fn default() -> Self {
        Self {
            input: [0u8; WORKSPACE_BYTES],
            output: [0u8; WORKSPACE_BYTES],
            input_len: 0,
            output_len: 0,
            algo: CompressionAlgo::None,
            zstd_level: 3,
        }
    }
}

impl CompressWorkspace {
    /// Create a new workspace for `algo`.
    pub fn new(algo: CompressionAlgo) -> Self {
        Self {
            algo,
            ..Self::default()
        }
    }

    /// Load input data from `src`.  Returns [`Error::InvalidArgument`] if `src`
    /// is larger than `WORKSPACE_BYTES`.
    pub fn load_input(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > WORKSPACE_BYTES {
            return Err(Error::InvalidArgument);
        }
        self.input[..src.len()].copy_from_slice(src);
        self.input_len = src.len();
        Ok(())
    }
}

/// Metadata describing one compressed extent on disk.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressedExtent {
    /// Logical byte offset within the file.
    pub file_offset: u64,
    /// Uncompressed length in bytes.
    pub uncompressed_len: u64,
    /// Compressed length in bytes (as stored on disk).
    pub compressed_len: u64,
    /// Compression algorithm used.
    pub algo: CompressionAlgo,
    /// Physical block address of the compressed data.
    pub disk_bytenr: u64,
    /// Whether this extent is stored inline in the inode item.
    pub is_inline: bool,
}

impl CompressedExtent {
    /// Compute the compression ratio (compressed / uncompressed) in percent.
    /// Returns 100 if the uncompressed length is zero.
    pub fn ratio_pct(&self) -> usize {
        if self.uncompressed_len == 0 {
            return 100;
        }
        ((self.compressed_len * 100) / self.uncompressed_len) as usize
    }

    /// Returns `true` if the ratio is good enough to be worth storing.
    pub fn is_worthwhile(&self) -> bool {
        self.ratio_pct() <= MIN_RATIO_ACCEPT
    }
}

/// Inline-compressed data for small files stored within the inode item.
#[derive(Debug)]
pub struct InlineCompress {
    /// Compressed bytes (up to `MAX_INLINE_SIZE`).
    data: [u8; MAX_INLINE_SIZE],
    /// Number of valid bytes in `data`.
    pub len: usize,
    /// Uncompressed size of the original data.
    pub uncompressed_size: usize,
    /// Algorithm used.
    pub algo: CompressionAlgo,
}

impl Default for InlineCompress {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_INLINE_SIZE],
            len: 0,
            uncompressed_size: 0,
            algo: CompressionAlgo::None,
        }
    }
}

impl InlineCompress {
    /// Store `compressed` as inline data.  Returns [`Error::InvalidArgument`]
    /// when `compressed` exceeds `MAX_INLINE_SIZE`.
    pub fn store(
        &mut self,
        compressed: &[u8],
        original_size: usize,
        algo: CompressionAlgo,
    ) -> Result<()> {
        if compressed.len() > MAX_INLINE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..compressed.len()].copy_from_slice(compressed);
        self.len = compressed.len();
        self.uncompressed_size = original_size;
        self.algo = algo;
        Ok(())
    }

    /// Read out the compressed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ---------------------------------------------------------------------------
// Heuristic
// ---------------------------------------------------------------------------

/// Estimate data entropy from the first `ENTROPY_SAMPLE_LEN` bytes of `data`.
///
/// Counts distinct byte values in the sample.  If ≥ 200 distinct bytes appear,
/// the data is considered incompressible and `true` is returned.
pub fn is_incompressible(data: &[u8]) -> bool {
    let sample = if data.len() > ENTROPY_SAMPLE_LEN {
        &data[..ENTROPY_SAMPLE_LEN]
    } else {
        data
    };
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in sample {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    distinct >= 200
}

// ---------------------------------------------------------------------------
// Compress / decompress stubs
// ---------------------------------------------------------------------------

/// Attempt to compress the data in `ws.input[..ws.input_len]`.
///
/// On success the compressed bytes are placed in `ws.output` and
/// `ws.output_len` is updated.  Returns [`Error::InvalidArgument`] if the
/// input is empty or an incompressibility check fires, [`Error::NotImplemented`]
/// if the algorithm is `None`.
pub fn compress_extent(ws: &mut CompressWorkspace) -> Result<()> {
    if ws.algo == CompressionAlgo::None {
        return Err(Error::NotImplemented);
    }
    if ws.input_len == 0 {
        return Err(Error::InvalidArgument);
    }
    if is_incompressible(&ws.input[..ws.input_len]) {
        return Err(Error::InvalidArgument);
    }
    // Stub: copy input to output, shrink by 10 % to simulate compression.
    let out_len = (ws.input_len * 9 / 10).max(1);
    let copy_len = out_len.min(ws.input_len);
    ws.output[..copy_len].copy_from_slice(&ws.input[..copy_len]);
    ws.output_len = out_len;
    Ok(())
}

/// Decompress `ws.input[..ws.input_len]` into `ws.output`.
///
/// The caller must set `ws.input_len` to the compressed byte count and
/// ensure that the workspace `algo` matches the stored extent algorithm.
/// Returns [`Error::IoError`] on a decompression fault.
pub fn decompress_extent(ws: &mut CompressWorkspace, expected_len: usize) -> Result<()> {
    if ws.algo == CompressionAlgo::None {
        return Err(Error::NotImplemented);
    }
    if ws.input_len == 0 || expected_len == 0 {
        return Err(Error::InvalidArgument);
    }
    if expected_len > WORKSPACE_BYTES {
        return Err(Error::InvalidArgument);
    }
    // Stub: expand compressed bytes back into output.
    let copy_len = ws.input_len.min(expected_len);
    ws.output[..copy_len].copy_from_slice(&ws.input[..copy_len]);
    if expected_len > copy_len {
        ws.output[copy_len..expected_len].fill(0);
    }
    ws.output_len = expected_len;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algo_roundtrip() {
        for algo in [
            CompressionAlgo::None,
            CompressionAlgo::Zlib,
            CompressionAlgo::Lzo,
            CompressionAlgo::Zstd,
        ] {
            assert_eq!(CompressionAlgo::from_u8(algo.as_u8()), Some(algo));
        }
    }

    #[test]
    fn compress_reduces_size() {
        let mut ws = CompressWorkspace::new(CompressionAlgo::Zlib);
        let input = [b'A'; 1000];
        ws.load_input(&input).unwrap();
        compress_extent(&mut ws).unwrap();
        assert!(ws.output_len < 1000);
    }

    #[test]
    fn incompressible_heuristic() {
        // A buffer with every possible byte value.
        let mut data = [0u8; 256];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert!(is_incompressible(&data));
    }

    #[test]
    fn extent_ratio() {
        let extent = CompressedExtent {
            uncompressed_len: 4096,
            compressed_len: 3000,
            algo: CompressionAlgo::Zstd,
            ..Default::default()
        };
        assert_eq!(extent.ratio_pct(), 73);
        assert!(extent.is_worthwhile());
    }
}
