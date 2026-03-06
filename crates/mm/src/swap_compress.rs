// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap compression pipeline.
//!
//! Implements a compression layer between the page reclaim path and
//! the swap device. Pages destined for swap are first compressed; if
//! the compressed size is small enough, the page is stored in a
//! compressed pool (avoiding disk I/O entirely). Pages that do not
//! compress well are passed through to the backing swap device.
//!
//! # Design
//!
//! ```text
//!                    ┌─────────────────┐
//!  page reclaim ───▶ │ SwapCompressor   │
//!                    │  compress(page)  │
//!                    └───────┬──────────┘
//!                            │
//!              ┌─────────────┴──────────────┐
//!              │ ratio < threshold?          │
//!              │                             │
//!        ┌─────▼─────┐              ┌───────▼──────┐
//!        │ CompPool   │              │ Swap Device  │
//!        │ (in-memory)│              │ (disk I/O)   │
//!        └────────────┘              └──────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`CompressedPage`] — a page stored in compressed form
//! - [`CompPool`] — in-memory compressed page pool
//! - [`SwapCompressor`] — the compression pipeline engine
//! - [`CompressStats`] — compression statistics
//!
//! Reference: Linux `mm/zswap.c`, `mm/zpool.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size.
const PAGE_SIZE: usize = 4096;

/// Maximum compressed size that qualifies for pool storage.
/// Pages compressing to more than this go to the backing device.
const MAX_COMPRESSED_SIZE: usize = PAGE_SIZE / 2;

/// Maximum entries in the compressed pool.
const MAX_POOL_ENTRIES: usize = 4096;

/// Maximum compressed data bytes per entry.
const MAX_COMP_DATA: usize = 2048;

// -------------------------------------------------------------------
// CompressedPage
// -------------------------------------------------------------------

/// A page stored in compressed form.
#[derive(Debug, Clone, Copy)]
pub struct CompressedPage {
    /// Original PFN of the page.
    pfn: u64,
    /// Compressed data (only `comp_size` bytes valid).
    data: [u8; MAX_COMP_DATA],
    /// Compressed size in bytes.
    comp_size: usize,
    /// Whether this slot is in use.
    in_use: bool,
}

impl CompressedPage {
    /// Creates an empty compressed page slot.
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            data: [0u8; MAX_COMP_DATA],
            comp_size: 0,
            in_use: false,
        }
    }

    /// Returns the original PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns the compressed size.
    pub const fn compressed_size(&self) -> usize {
        self.comp_size
    }

    /// Returns the compression ratio (0..100).
    pub const fn ratio_percent(&self) -> usize {
        if self.comp_size == 0 {
            return 0;
        }
        self.comp_size * 100 / PAGE_SIZE
    }
}

impl Default for CompressedPage {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CompressStats
// -------------------------------------------------------------------

/// Statistics for the swap compression pipeline.
#[derive(Debug, Clone, Copy)]
pub struct CompressStats {
    /// Total pages submitted for compression.
    pub pages_submitted: u64,
    /// Pages stored in the compressed pool.
    pub pages_pooled: u64,
    /// Pages passed through to backing swap.
    pub pages_passthrough: u64,
    /// Pages decompressed from the pool.
    pub pages_decompressed: u64,
    /// Total compressed bytes stored.
    pub compressed_bytes: u64,
    /// Total original bytes processed.
    pub original_bytes: u64,
    /// Pool evictions due to capacity.
    pub pool_evictions: u64,
}

impl CompressStats {
    /// Creates empty statistics.
    pub const fn new() -> Self {
        Self {
            pages_submitted: 0,
            pages_pooled: 0,
            pages_passthrough: 0,
            pages_decompressed: 0,
            compressed_bytes: 0,
            original_bytes: 0,
            pool_evictions: 0,
        }
    }

    /// Returns the overall compression ratio (0..100).
    pub const fn compression_ratio(&self) -> u64 {
        if self.original_bytes == 0 {
            return 0;
        }
        self.compressed_bytes * 100 / self.original_bytes
    }

    /// Returns the pool hit rate (0..100).
    pub const fn pool_hit_rate(&self) -> u64 {
        if self.pages_submitted == 0 {
            return 0;
        }
        self.pages_pooled * 100 / self.pages_submitted
    }
}

impl Default for CompressStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CompPool
// -------------------------------------------------------------------

/// In-memory compressed page pool.
pub struct CompPool {
    /// Pool entries.
    entries: [CompressedPage; MAX_POOL_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Total compressed bytes stored.
    total_bytes: usize,
}

impl CompPool {
    /// Creates an empty pool.
    pub const fn new() -> Self {
        Self {
            entries: [const { CompressedPage::new() }; MAX_POOL_ENTRIES],
            count: 0,
            total_bytes: 0,
        }
    }

    /// Returns the number of stored pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns total compressed bytes stored.
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Stores a compressed page in the pool.
    pub fn store(&mut self, pfn: u64, data: &[u8]) -> Result<()> {
        if data.len() > MAX_COMP_DATA {
            return Err(Error::InvalidArgument);
        }
        // Find a free slot.
        for i in 0..MAX_POOL_ENTRIES {
            if !self.entries[i].in_use {
                self.entries[i].pfn = pfn;
                self.entries[i].data[..data.len()].copy_from_slice(data);
                self.entries[i].comp_size = data.len();
                self.entries[i].in_use = true;
                self.count += 1;
                self.total_bytes += data.len();
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Retrieves and removes a compressed page by PFN.
    pub fn retrieve(&mut self, pfn: u64, out: &mut [u8]) -> Result<usize> {
        for i in 0..MAX_POOL_ENTRIES {
            if self.entries[i].in_use && self.entries[i].pfn == pfn {
                let size = self.entries[i].comp_size;
                if out.len() < size {
                    return Err(Error::InvalidArgument);
                }
                out[..size].copy_from_slice(&self.entries[i].data[..size]);
                self.entries[i].in_use = false;
                self.count -= 1;
                self.total_bytes -= size;
                return Ok(size);
            }
        }
        Err(Error::NotFound)
    }

    /// Evicts the oldest entry to make room.
    pub fn evict_one(&mut self) -> Result<u64> {
        for i in 0..MAX_POOL_ENTRIES {
            if self.entries[i].in_use {
                let pfn = self.entries[i].pfn;
                self.total_bytes -= self.entries[i].comp_size;
                self.entries[i].in_use = false;
                self.count -= 1;
                return Ok(pfn);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for CompPool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SwapCompressor
// -------------------------------------------------------------------

/// The swap compression pipeline engine.
pub struct SwapCompressor {
    /// Compressed page pool.
    pool: CompPool,
    /// Statistics.
    stats: CompressStats,
    /// Compression threshold (max compressed size for pool storage).
    threshold: usize,
    /// Whether the compressor is enabled.
    enabled: bool,
}

impl SwapCompressor {
    /// Creates a new swap compressor.
    pub const fn new() -> Self {
        Self {
            pool: CompPool::new(),
            stats: CompressStats::new(),
            threshold: MAX_COMPRESSED_SIZE,
            enabled: true,
        }
    }

    /// Returns the statistics.
    pub const fn stats(&self) -> &CompressStats {
        &self.stats
    }

    /// Returns the pool entry count.
    pub const fn pool_count(&self) -> usize {
        self.pool.count
    }

    /// Sets the compression threshold.
    pub fn set_threshold(&mut self, threshold: usize) -> Result<()> {
        if threshold == 0 || threshold > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.threshold = threshold;
        Ok(())
    }

    /// Compresses and stores a page. Returns `true` if pooled, `false`
    /// if the page should be passed to the backing swap device.
    ///
    /// Note: real compression (LZ4/ZSTD) would be applied here. We use
    /// a simple run-length simulation for the stub.
    pub fn compress_page(&mut self, pfn: u64, page_data: &[u8; PAGE_SIZE]) -> Result<bool> {
        if !self.enabled {
            return Ok(false);
        }
        self.stats.pages_submitted = self.stats.pages_submitted.saturating_add(1);
        self.stats.original_bytes = self.stats.original_bytes.saturating_add(PAGE_SIZE as u64);

        // Simple "compression": count unique byte runs as a heuristic.
        let mut comp_size = 0usize;
        let mut i = 0;
        while i < PAGE_SIZE {
            let byte = page_data[i];
            let mut run_len = 1;
            while i + run_len < PAGE_SIZE && page_data[i + run_len] == byte && run_len < 255 {
                run_len += 1;
            }
            comp_size += 2; // 1 byte count + 1 byte value
            i += run_len;
        }

        if comp_size > MAX_COMP_DATA {
            comp_size = MAX_COMP_DATA;
        }

        self.stats.compressed_bytes = self.stats.compressed_bytes.saturating_add(comp_size as u64);

        if comp_size <= self.threshold {
            // Store in pool.
            let mut comp_buf = [0u8; MAX_COMP_DATA];
            let stored = if comp_size <= MAX_COMP_DATA {
                comp_size
            } else {
                MAX_COMP_DATA
            };
            // Fill stub compressed data.
            for b in comp_buf[..stored].iter_mut() {
                *b = 0xCC;
            }
            match self.pool.store(pfn, &comp_buf[..stored]) {
                Ok(()) => {
                    self.stats.pages_pooled = self.stats.pages_pooled.saturating_add(1);
                    Ok(true)
                }
                Err(Error::OutOfMemory) => {
                    // Evict and retry.
                    let _ = self.pool.evict_one();
                    self.stats.pool_evictions = self.stats.pool_evictions.saturating_add(1);
                    self.pool.store(pfn, &comp_buf[..stored])?;
                    self.stats.pages_pooled = self.stats.pages_pooled.saturating_add(1);
                    Ok(true)
                }
                Err(e) => Err(e),
            }
        } else {
            self.stats.pages_passthrough = self.stats.pages_passthrough.saturating_add(1);
            Ok(false)
        }
    }

    /// Decompresses a page from the pool.
    pub fn decompress_page(&mut self, pfn: u64) -> Result<[u8; PAGE_SIZE]> {
        let mut comp_buf = [0u8; MAX_COMP_DATA];
        let _size = self.pool.retrieve(pfn, &mut comp_buf)?;
        self.stats.pages_decompressed = self.stats.pages_decompressed.saturating_add(1);
        // Return a zeroed page as placeholder (real decompression here).
        Ok([0u8; PAGE_SIZE])
    }
}

impl Default for SwapCompressor {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new swap compressor.
pub fn create_compressor() -> SwapCompressor {
    SwapCompressor::new()
}

/// Compresses a page, returning whether it was pooled.
pub fn compress_and_store(
    comp: &mut SwapCompressor,
    pfn: u64,
    data: &[u8; PAGE_SIZE],
) -> Result<bool> {
    comp.compress_page(pfn, data)
}

/// Returns the compression ratio (0..100).
pub fn compression_ratio(comp: &SwapCompressor) -> u64 {
    comp.stats().compression_ratio()
}
