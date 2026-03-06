// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EROFS compressed data support.
//!
//! EROFS supports several compression algorithms applied at the
//! cluster granularity.  A compressed file is divided into fixed-size
//! logical clusters; each cluster maps to one or more physical
//! compressed clusters that are stored contiguously on disk.
//!
//! # Compression algorithms
//!
//! | ID  | Algorithm       | Notes                         |
//! |-----|-----------------|-------------------------------|
//! | 0   | None (raw)      | No decompression needed       |
//! | 1   | LZ4             | Default fast algorithm        |
//! | 2   | LZMA            | Higher ratio                  |
//! | 3   | Deflate (zlib)  | Wide compatibility            |
//! | 4   | Zstd            | Best ratio + speed trade-off  |
//!
//! # Architecture
//!
//! ```text
//! ErofsCompressedFile
//!   → cluster_index[]  (CompressedCluster descriptors)
//!     → on-disk physical clusters (raw bytes in block device)
//!       → decompressor (LZ4 / LZMA / Deflate / Zstd stub)
//!         → page cache / output buffer
//! ```
//!
//! # Structures
//!
//! - [`CompressionAlgo`]   — algorithm identifier
//! - [`ClusterType`]       — plain / head / nonhead cluster
//! - [`CompressedCluster`] — cluster descriptor
//! - [`DecompressCtx`]     — decompression working context
//! - [`ErofsCompressedFile`] — file handle with cluster index
//! - [`CompressionStats`]  — aggregate decompression statistics
//!
//! # References
//!
//! - Linux `fs/erofs/compress.c`, `fs/erofs/zdata.c`
//! - EROFS on-disk format documentation

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of logical clusters per file.
pub const MAX_CLUSTERS_PER_FILE: usize = 512;

/// Default logical cluster size (4 KiB).
pub const DEFAULT_CLUSTER_SIZE: usize = 4096;

/// Maximum decompressed cluster output size (64 KiB).
pub const MAX_DECOMPRESSED_SIZE: usize = 65536;

/// Maximum raw compressed input size (64 KiB).
pub const MAX_COMPRESSED_SIZE: usize = 65536;

/// Minimum block address (clusters 0..RESERVED_BLKS are for superblock).
pub const RESERVED_BLKS: u32 = 1;

// ── CompressionAlgo ───────────────────────────────────────────────────────────

/// Compression algorithm used for a cluster or an entire file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CompressionAlgo {
    /// No compression — data is stored verbatim.
    #[default]
    None = 0,
    /// LZ4 block compression.
    Lz4 = 1,
    /// LZMA compression.
    Lzma = 2,
    /// Deflate (zlib) compression.
    Deflate = 3,
    /// Zstandard compression.
    Zstd = 4,
}

impl CompressionAlgo {
    /// Construct from the on-disk algorithm ID byte.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::Lzma),
            3 => Ok(Self::Deflate),
            4 => Ok(Self::Zstd),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── ClusterType ───────────────────────────────────────────────────────────────

/// EROFS compressed cluster type, as stored in the cluster descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ClusterType {
    /// Plain (uncompressed) cluster.
    #[default]
    Plain = 0,
    /// Head of a compressed extent.
    Head1 = 1,
    /// Non-head cluster: shares physical block with the preceding head.
    NonHead = 2,
    /// Head of a compressed extent, version 2 (EROFS v1.1+).
    Head2 = 3,
}

impl ClusterType {
    /// Construct from the two-bit `type` field in an on-disk cluster entry.
    pub fn from_bits(bits: u8) -> Result<Self> {
        match bits & 0x03 {
            0 => Ok(Self::Plain),
            1 => Ok(Self::Head1),
            2 => Ok(Self::NonHead),
            3 => Ok(Self::Head2),
            _ => unreachable!(),
        }
    }
}

// ── CompressedCluster ─────────────────────────────────────────────────────────

/// Descriptor for a single logical cluster.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressedCluster {
    /// Logical cluster index within the file.
    pub lcn: u32,
    /// Cluster type.
    pub cluster_type: ClusterType,
    /// Physical block address of the compressed data (for Head clusters).
    pub blkaddr: u32,
    /// Byte offset within the physical block where compressed data starts.
    pub block_offset: u16,
    /// Decompressed byte offset within the logical cluster.
    pub logical_offset: u16,
    /// Size of the compressed data on disk in bytes (0 for NonHead).
    pub compressed_size: u32,
    /// Expected decompressed size in bytes.
    pub decompressed_size: u32,
    /// Algorithm used for this cluster.
    pub algo: CompressionAlgo,
}

impl CompressedCluster {
    /// Returns `true` if this cluster needs decompression.
    pub fn needs_decompression(&self) -> bool {
        self.algo != CompressionAlgo::None
            && (self.cluster_type == ClusterType::Head1 || self.cluster_type == ClusterType::Head2)
    }
}

// ── DecompressCtx ─────────────────────────────────────────────────────────────

/// Working context for a single decompression operation.
pub struct DecompressCtx {
    /// Algorithm being used.
    pub algo: CompressionAlgo,
    /// Compressed input buffer.
    input: [u8; MAX_COMPRESSED_SIZE],
    /// Input data length.
    pub input_len: usize,
    /// Decompressed output buffer.
    output: [u8; MAX_DECOMPRESSED_SIZE],
    /// Valid output bytes after decompression.
    pub output_len: usize,
}

impl Default for DecompressCtx {
    fn default() -> Self {
        Self {
            algo: CompressionAlgo::None,
            input: [0u8; MAX_COMPRESSED_SIZE],
            input_len: 0,
            output: [0u8; MAX_DECOMPRESSED_SIZE],
            output_len: 0,
        }
    }
}

impl DecompressCtx {
    /// Load compressed input data.
    pub fn load_input(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_COMPRESSED_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.input[..data.len()].copy_from_slice(data);
        self.input_len = data.len();
        Ok(())
    }

    /// Decompress the loaded input into the output buffer.
    ///
    /// For `CompressionAlgo::None`, data is copied verbatim.
    /// For other algorithms, this is a stub that returns [`Error::NotImplemented`]
    /// until a real decompressor is wired in.
    pub fn decompress(&mut self) -> Result<usize> {
        match self.algo {
            CompressionAlgo::None => {
                let len = self.input_len;
                self.output[..len].copy_from_slice(&self.input[..len]);
                self.output_len = len;
                Ok(len)
            }
            CompressionAlgo::Lz4 => self.decompress_lz4(),
            CompressionAlgo::Lzma => Err(Error::NotImplemented),
            CompressionAlgo::Deflate => Err(Error::NotImplemented),
            CompressionAlgo::Zstd => Err(Error::NotImplemented),
        }
    }

    /// LZ4 block decompression stub.
    ///
    /// A real implementation would call an LZ4 decompressor here.
    /// For now we implement the trivial case where the LZ4 stream
    /// is a literal copy (no back-references), which is valid LZ4.
    fn decompress_lz4(&mut self) -> Result<usize> {
        // Minimal LZ4 block decode: process token sequences.
        let input = &self.input[..self.input_len];
        let mut src = 0usize;
        let mut dst = 0usize;

        while src < input.len() {
            let token = input[src] as usize;
            src += 1;

            // Literal length from upper nibble.
            let mut lit_len = token >> 4;
            if lit_len == 15 {
                loop {
                    if src >= input.len() {
                        return Err(Error::IoError);
                    }
                    let extra = input[src] as usize;
                    src += 1;
                    lit_len += extra;
                    if extra != 255 {
                        break;
                    }
                }
            }

            // Copy literals.
            if src + lit_len > input.len() {
                return Err(Error::IoError);
            }
            if dst + lit_len > MAX_DECOMPRESSED_SIZE {
                return Err(Error::InvalidArgument);
            }
            self.output[dst..dst + lit_len].copy_from_slice(&input[src..src + lit_len]);
            src += lit_len;
            dst += lit_len;

            // End-of-block check (last sequence has no match).
            if src >= input.len() {
                break;
            }

            // Match offset (little-endian 16-bit).
            if src + 1 >= input.len() {
                return Err(Error::IoError);
            }
            let offset = (input[src] as usize) | ((input[src + 1] as usize) << 8);
            src += 2;
            if offset == 0 {
                return Err(Error::IoError);
            }

            // Match length from lower nibble + 4 minimum.
            let mut match_len = (token & 0x0F) + 4;
            if match_len - 4 == 15 {
                loop {
                    if src >= input.len() {
                        return Err(Error::IoError);
                    }
                    let extra = input[src] as usize;
                    src += 1;
                    match_len += extra;
                    if extra != 255 {
                        break;
                    }
                }
            }

            if dst < offset {
                return Err(Error::IoError);
            }
            let match_src = dst - offset;
            for i in 0..match_len {
                if dst >= MAX_DECOMPRESSED_SIZE {
                    return Err(Error::InvalidArgument);
                }
                self.output[dst] = self.output[match_src + i];
                dst += 1;
            }
        }

        self.output_len = dst;
        Ok(dst)
    }

    /// Return a slice of the decompressed output.
    pub fn output(&self) -> &[u8] {
        &self.output[..self.output_len]
    }
}

// ── ClusterIndex ──────────────────────────────────────────────────────────────

/// Index of cluster descriptors for a single file.
pub struct ClusterIndex {
    clusters: [CompressedCluster; MAX_CLUSTERS_PER_FILE],
    count: usize,
}

impl Default for ClusterIndex {
    fn default() -> Self {
        Self {
            clusters: [CompressedCluster::default(); MAX_CLUSTERS_PER_FILE],
            count: 0,
        }
    }
}

impl ClusterIndex {
    /// Append a cluster descriptor to the index.
    pub fn push(&mut self, cluster: CompressedCluster) -> Result<()> {
        if self.count >= MAX_CLUSTERS_PER_FILE {
            return Err(Error::OutOfMemory);
        }
        self.clusters[self.count] = cluster;
        self.count += 1;
        Ok(())
    }

    /// Look up the cluster containing logical byte offset `offset`.
    pub fn lookup(&self, cluster_size: usize, offset: u64) -> Result<&CompressedCluster> {
        if cluster_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let lcn = (offset / cluster_size as u64) as u32;
        self.clusters[..self.count]
            .iter()
            .find(|c| c.lcn == lcn)
            .ok_or(Error::NotFound)
    }

    /// Return the number of clusters indexed.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no clusters are indexed.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all clusters.
    pub fn iter(&self) -> impl Iterator<Item = &CompressedCluster> {
        self.clusters[..self.count].iter()
    }
}

// ── ErofsCompressedFile ───────────────────────────────────────────────────────

/// Handle for a compressed EROFS file.
pub struct ErofsCompressedFile {
    /// Inode number.
    pub ino: u64,
    /// Total uncompressed file size in bytes.
    pub size: u64,
    /// Logical cluster size (must be a power of two).
    pub cluster_size: usize,
    /// Algorithm for the entire file (may be overridden per-cluster).
    pub algo: CompressionAlgo,
    /// Cluster descriptor index.
    pub index: ClusterIndex,
    /// Whether the cluster index has been fully loaded.
    pub index_loaded: bool,
}

impl Default for ErofsCompressedFile {
    fn default() -> Self {
        Self {
            ino: 0,
            size: 0,
            cluster_size: DEFAULT_CLUSTER_SIZE,
            algo: CompressionAlgo::None,
            index: ClusterIndex::default(),
            index_loaded: false,
        }
    }
}

impl ErofsCompressedFile {
    /// Create a new compressed file handle.
    pub fn new(ino: u64, size: u64, cluster_size: usize, algo: CompressionAlgo) -> Self {
        Self {
            ino,
            size,
            cluster_size,
            algo,
            index: ClusterIndex::default(),
            index_loaded: false,
        }
    }

    /// Add a cluster descriptor during index loading.
    pub fn add_cluster(&mut self, cluster: CompressedCluster) -> Result<()> {
        self.index.push(cluster)
    }

    /// Mark the cluster index as fully loaded.
    pub fn finish_index(&mut self) {
        self.index_loaded = true;
    }

    /// Read `dst.len()` bytes starting at `offset`.
    ///
    /// This locates the correct cluster, fetches the compressed data from
    /// the given `block_reader` slice, decompresses it, and returns the
    /// requested subrange.
    pub fn read<F>(&self, offset: u64, dst: &mut [u8], block_reader: F) -> Result<usize>
    where
        F: Fn(u32, u16, &mut [u8]) -> Result<usize>,
    {
        if !self.index_loaded {
            return Err(Error::Busy);
        }
        if offset >= self.size {
            return Ok(0);
        }

        let cluster = self.index.lookup(self.cluster_size, offset)?;
        let cluster_offset = offset % self.cluster_size as u64;

        if cluster.cluster_type == ClusterType::Plain || cluster.algo == CompressionAlgo::None {
            // Plain (uncompressed) cluster — read directly.
            let mut buf = [0u8; MAX_DECOMPRESSED_SIZE];
            let n = block_reader(cluster.blkaddr, cluster.block_offset, &mut buf)?;
            let available = n.saturating_sub(cluster_offset as usize);
            let to_copy = available.min(dst.len());
            dst[..to_copy]
                .copy_from_slice(&buf[cluster_offset as usize..cluster_offset as usize + to_copy]);
            return Ok(to_copy);
        }

        // Compressed cluster: decompress then slice.
        let mut ctx = DecompressCtx::default();
        ctx.algo = cluster.algo;
        let mut compressed = [0u8; MAX_COMPRESSED_SIZE];
        let n = block_reader(cluster.blkaddr, cluster.block_offset, &mut compressed)?;
        ctx.load_input(&compressed[..n.min(cluster.compressed_size as usize)])?;
        ctx.decompress()?;

        let decompressed = ctx.output();
        let available = decompressed.len().saturating_sub(cluster_offset as usize);
        let to_copy = available.min(dst.len());
        dst[..to_copy].copy_from_slice(
            &decompressed[cluster_offset as usize..cluster_offset as usize + to_copy],
        );
        Ok(to_copy)
    }
}

// ── CompressionStats ──────────────────────────────────────────────────────────

/// Aggregate statistics for all EROFS decompression activity.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionStats {
    /// Total clusters decompressed.
    pub clusters_decompressed: u64,
    /// Total clusters served from the plain (no-op) path.
    pub clusters_plain: u64,
    /// Total input (compressed) bytes consumed.
    pub compressed_bytes: u64,
    /// Total output (decompressed) bytes produced.
    pub decompressed_bytes: u64,
    /// Decompression failures.
    pub errors: u64,
}

impl CompressionStats {
    /// Record a successful decompression of `compressed` → `decompressed` bytes.
    pub fn record_decompress(&mut self, compressed: u64, decompressed: u64) {
        self.clusters_decompressed += 1;
        self.compressed_bytes += compressed;
        self.decompressed_bytes += decompressed;
    }

    /// Record a plain (uncompressed) cluster read.
    pub fn record_plain(&mut self, bytes: u64) {
        self.clusters_plain += 1;
        self.decompressed_bytes += bytes;
    }

    /// Record a decompression error.
    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    /// Compression ratio (compressed / decompressed), scaled ×1000.
    ///
    /// Returns 0 if no decompressed bytes have been produced.
    pub fn ratio_permille(&self) -> u64 {
        if self.decompressed_bytes == 0 {
            return 0;
        }
        self.compressed_bytes * 1000 / self.decompressed_bytes
    }
}
