// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ZRAM compression backend management.
//!
//! Manages compression algorithms and buffers for the ZRAM block
//! device. Each ZRAM disk can use a different compression algorithm,
//! and this module handles algorithm selection, per-CPU compression
//! streams, and compression statistics.
//!
//! - [`CompAlgorithm`] — supported compression algorithms
//! - [`CompStream`] — a compression stream (per-CPU)
//! - [`CompResult`] — compression operation result
//! - [`ZramCompStats`] — compression statistics
//! - [`ZramCompressor`] — the compression manager
//!
//! Reference: Linux `drivers/block/zram/zcomp.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum compression streams (per-CPU).
const MAX_STREAMS: usize = 32;

/// Maximum compressed page size (must be less than PAGE_SIZE).
const MAX_COMP_SIZE: usize = 4096;

/// Compression ratio threshold for storing uncompressed (per-mille).
const COMP_RATIO_THRESHOLD: u32 = 900;

// -------------------------------------------------------------------
// CompAlgorithm
// -------------------------------------------------------------------

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompAlgorithm {
    /// LZO (default).
    #[default]
    Lzo,
    /// LZ4.
    Lz4,
    /// ZSTD.
    Zstd,
    /// LZ4HC (high compression).
    Lz4Hc,
    /// Deflate.
    Deflate,
    /// No compression (store raw).
    None,
}

impl CompAlgorithm {
    /// Returns the algorithm name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Lzo => "lzo",
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
            Self::Lz4Hc => "lz4hc",
            Self::Deflate => "deflate",
            Self::None => "none",
        }
    }

    /// Returns the expected compression ratio (per-mille).
    pub fn expected_ratio(self) -> u32 {
        match self {
            Self::Lzo => 550,
            Self::Lz4 => 600,
            Self::Zstd => 450,
            Self::Lz4Hc => 500,
            Self::Deflate => 400,
            Self::None => 1000,
        }
    }
}

// -------------------------------------------------------------------
// CompStream
// -------------------------------------------------------------------

/// A per-CPU compression stream.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompStream {
    /// Stream ID (CPU number).
    pub stream_id: u32,
    /// Algorithm used.
    pub algorithm: CompAlgorithm,
    /// Whether this stream is in use.
    pub busy: bool,
    /// Total compressions performed.
    pub comp_count: u64,
    /// Total decompressions performed.
    pub decomp_count: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl CompStream {
    /// Creates a new stream.
    pub fn new(stream_id: u32, algorithm: CompAlgorithm) -> Self {
        Self {
            stream_id,
            algorithm,
            busy: false,
            comp_count: 0,
            decomp_count: 0,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// CompResult
// -------------------------------------------------------------------

/// Result of a compression operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompResult {
    /// Original size in bytes.
    pub original_size: usize,
    /// Compressed size in bytes.
    pub compressed_size: usize,
    /// Whether the data was stored uncompressed.
    pub stored_raw: bool,
}

impl CompResult {
    /// Returns the compression ratio (per-mille).
    pub fn ratio(&self) -> u32 {
        if self.original_size == 0 {
            return 1000;
        }
        ((self.compressed_size as u64 * 1000) / self.original_size as u64) as u32
    }

    /// Returns the space saved in bytes.
    pub fn saved(&self) -> usize {
        self.original_size.saturating_sub(self.compressed_size)
    }
}

// -------------------------------------------------------------------
// ZramCompStats
// -------------------------------------------------------------------

/// ZRAM compression statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZramCompStats {
    /// Total compressions.
    pub compressions: u64,
    /// Total decompressions.
    pub decompressions: u64,
    /// Total original bytes.
    pub original_bytes: u64,
    /// Total compressed bytes.
    pub compressed_bytes: u64,
    /// Pages stored uncompressed.
    pub pages_stored_raw: u64,
    /// Compression failures.
    pub comp_failures: u64,
}

impl ZramCompStats {
    /// Returns the overall compression ratio (per-mille).
    pub fn overall_ratio(&self) -> u32 {
        if self.original_bytes == 0 {
            return 1000;
        }
        ((self.compressed_bytes * 1000) / self.original_bytes) as u32
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// ZramCompressor
// -------------------------------------------------------------------

/// The ZRAM compression manager.
pub struct ZramCompressor {
    /// Compression streams.
    streams: [CompStream; MAX_STREAMS],
    /// Number of active streams.
    nr_streams: usize,
    /// Active algorithm.
    algorithm: CompAlgorithm,
    /// Statistics.
    stats: ZramCompStats,
}

impl Default for ZramCompressor {
    fn default() -> Self {
        Self {
            streams: [CompStream::default(); MAX_STREAMS],
            nr_streams: 0,
            algorithm: CompAlgorithm::Lzo,
            stats: ZramCompStats::default(),
        }
    }
}

impl ZramCompressor {
    /// Creates a new compressor with the given algorithm.
    pub fn new(algorithm: CompAlgorithm, nr_cpus: usize) -> Result<Self> {
        if nr_cpus == 0 || nr_cpus > MAX_STREAMS {
            return Err(Error::InvalidArgument);
        }
        let mut comp = Self {
            algorithm,
            ..Self::default()
        };
        for i in 0..nr_cpus {
            comp.streams[i] = CompStream::new(i as u32, algorithm);
            comp.nr_streams += 1;
        }
        Ok(comp)
    }

    /// Simulates compressing a page.
    pub fn compress(&mut self, cpu: usize, page_size: usize) -> Result<CompResult> {
        if cpu >= self.nr_streams {
            return Err(Error::InvalidArgument);
        }
        if self.streams[cpu].busy {
            return Err(Error::Busy);
        }

        self.streams[cpu].busy = true;

        // Simulate compression with expected ratio.
        let ratio = self.algorithm.expected_ratio();
        let compressed_size = ((page_size as u64 * ratio as u64) / 1000) as usize;
        let stored_raw = ratio >= COMP_RATIO_THRESHOLD;

        let result = CompResult {
            original_size: page_size,
            compressed_size: if stored_raw {
                page_size
            } else {
                compressed_size
            },
            stored_raw,
        };

        self.streams[cpu].comp_count += 1;
        self.streams[cpu].busy = false;
        self.stats.compressions += 1;
        self.stats.original_bytes += page_size as u64;
        self.stats.compressed_bytes += result.compressed_size as u64;
        if stored_raw {
            self.stats.pages_stored_raw += 1;
        }
        Ok(result)
    }

    /// Simulates decompressing a page.
    pub fn decompress(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.nr_streams {
            return Err(Error::InvalidArgument);
        }
        self.streams[cpu].decomp_count += 1;
        self.stats.decompressions += 1;
        Ok(())
    }

    /// Changes the compression algorithm (requires no active streams).
    pub fn set_algorithm(&mut self, algorithm: CompAlgorithm) -> Result<()> {
        for i in 0..self.nr_streams {
            if self.streams[i].busy {
                return Err(Error::Busy);
            }
        }
        self.algorithm = algorithm;
        for i in 0..self.nr_streams {
            self.streams[i].algorithm = algorithm;
        }
        Ok(())
    }

    /// Returns the current algorithm.
    pub fn algorithm(&self) -> CompAlgorithm {
        self.algorithm
    }

    /// Returns the number of streams.
    pub fn nr_streams(&self) -> usize {
        self.nr_streams
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ZramCompStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
