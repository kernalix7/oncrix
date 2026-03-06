// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Compressed swap cache (zswap) for the ONCRIX operating system.
//!
//! Provides a compressed in-memory cache that sits between the
//! swap subsystem and real swap devices, reducing I/O by storing
//! compressed page data in a fixed-size pool. Pages that compress
//! well are kept in the zswap pool; pages that do not compress
//! below [`MAX_COMPRESSED_SIZE`] are rejected and written directly
//! to the backing swap device.
//!
//! Key components:
//! - [`ZswapCompressor`] — compression algorithm selector
//! - [`ZswapEntry`] — a single compressed page in the pool
//! - [`ZswapPool`] — the compressed page pool with LRU eviction
//! - [`ZswapStats`] — pool usage and compression statistics
//!
//! Reference: `.kernelORG/` — `mm/zswap.c`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of compressed entries in the zswap pool.
pub const MAX_ZSWAP_ENTRIES: usize = 1024;

/// Maximum compressed page size in bytes (half a page).
///
/// Pages that do not compress below this threshold are rejected
/// from the pool and written directly to the backing swap device.
pub const MAX_COMPRESSED_SIZE: usize = 2048;

/// Standard page size in bytes.
const _PAGE_SIZE: usize = 4096;

/// Maximum number of pool pages available for zswap storage.
const _MAX_POOL_PAGES: usize = 512;

/// Compression ratio threshold as a percentage.
///
/// Pages whose compressed size exceeds this ratio of the original
/// size are rejected from the pool.
const _COMPRESSION_RATIO_THRESHOLD: u64 = 75;

// ── ZswapCompressor ─────────────────────────────────────────────

/// Compression algorithm used by the zswap pool.
///
/// Currently only stub compression is implemented; the enum
/// records the intended algorithm for future implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZswapCompressor {
    /// LZO compression.
    Lzo,
    /// LZ4 compression (default).
    #[default]
    Lz4,
    /// Zstandard compression.
    Zstd,
    /// No compression (pass-through).
    None,
}

// ── ZswapEntry ──────────────────────────────────────────────────

/// A single compressed page stored in the zswap pool.
///
/// Each entry holds the compressed representation of a 4 KiB page,
/// identified by its swap offset, along with metadata for LRU
/// tracking and integrity verification.
#[derive(Clone, Copy)]
pub struct ZswapEntry {
    /// Swap offset identifying the original page.
    swap_offset: u64,
    /// Buffer holding compressed page data.
    compressed_data: [u8; MAX_COMPRESSED_SIZE],
    /// Number of valid bytes in `compressed_data`.
    compressed_len: usize,
    /// Original (uncompressed) page size in bytes.
    original_len: usize,
    /// Simple checksum of the original page data.
    checksum: u32,
    /// Compression algorithm used for this entry.
    compressor: ZswapCompressor,
    /// Whether this entry slot is occupied.
    active: bool,
    /// Number of times this entry has been accessed.
    access_count: u32,
    /// Timestamp of the last access in nanoseconds.
    last_access_ns: u64,
}

impl ZswapEntry {
    /// Create an empty (inactive) zswap entry.
    const fn empty() -> Self {
        Self {
            swap_offset: 0,
            compressed_data: [0u8; MAX_COMPRESSED_SIZE],
            compressed_len: 0,
            original_len: 0,
            checksum: 0,
            compressor: ZswapCompressor::Lz4,
            active: false,
            access_count: 0,
            last_access_ns: 0,
        }
    }
}

// ── ZswapStats ──────────────────────────────────────────────────

/// Usage and compression statistics for the zswap pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZswapStats {
    /// Number of pages currently stored in the pool.
    pub stored_pages: u64,
    /// Total bytes of compressed data in the pool.
    pub compressed_bytes: u64,
    /// Total bytes of original (uncompressed) data represented.
    pub original_bytes: u64,
    /// Current compression ratio as a percentage.
    pub compression_ratio: u64,
    /// Number of pages rejected from the pool.
    pub reject_count: u64,
    /// Number of pages written back to the backing swap device.
    pub writeback_count: u64,
}

// ── Helper ──────────────────────────────────────────────────────

/// Compute a simple checksum by summing all bytes.
///
/// This is not cryptographically secure; it is used only for
/// basic integrity verification of cached page data.
pub fn simple_checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &b in data {
        sum = sum.wrapping_add(u32::from(b));
    }
    sum
}

// ── ZswapPool ───────────────────────────────────────────────────

/// Compressed swap cache pool.
///
/// Maintains up to [`MAX_ZSWAP_ENTRIES`] compressed page entries
/// with LRU eviction. Pages are identified by their swap offset
/// and stored with stub compression (copy up to
/// [`MAX_COMPRESSED_SIZE`] bytes).
pub struct ZswapPool {
    /// Pool entries.
    entries: [ZswapEntry; MAX_ZSWAP_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Maximum number of entries allowed.
    max_entries: usize,
    /// Current compression algorithm.
    compressor: ZswapCompressor,
    /// Total number of pages stored (lifetime counter).
    total_stored: u64,
    /// Total compressed bytes across all active entries.
    total_compressed_bytes: u64,
    /// Total original bytes across all active entries.
    total_original_bytes: u64,
    /// Number of pages rejected (too large after compression).
    reject_count: u64,
    /// Number of pages written back to the backing device.
    writeback_count: u64,
    /// Whether the zswap pool is enabled.
    enabled: bool,
}

impl ZswapPool {
    /// Create a new empty zswap pool.
    pub const fn new() -> Self {
        Self {
            entries: [ZswapEntry::empty(); MAX_ZSWAP_ENTRIES],
            count: 0,
            max_entries: MAX_ZSWAP_ENTRIES,
            compressor: ZswapCompressor::Lz4,
            total_stored: 0,
            total_compressed_bytes: 0,
            total_original_bytes: 0,
            reject_count: 0,
            writeback_count: 0,
            enabled: true,
        }
    }

    /// Store a page in the compressed swap cache.
    ///
    /// Performs stub compression by copying up to
    /// [`MAX_COMPRESSED_SIZE`] bytes from `page_data` and
    /// computing a simple checksum. If the page data exceeds
    /// `MAX_COMPRESSED_SIZE` and cannot be "compressed" to fit,
    /// the entry is rejected.
    ///
    /// If the pool is full, the least recently used entry is
    /// evicted to make room.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — `page_data` is empty.
    /// - `OutOfMemory` — pool is full and eviction failed.
    /// - `Busy` — pool is disabled.
    pub fn store(&mut self, swap_offset: u64, page_data: &[u8], now_ns: u64) -> Result<()> {
        if !self.enabled {
            return Err(Error::Busy);
        }
        if page_data.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Stub compression: copy up to MAX_COMPRESSED_SIZE bytes.
        let compressed_len = page_data.len().min(MAX_COMPRESSED_SIZE);
        if page_data.len() > MAX_COMPRESSED_SIZE {
            // Page does not compress well enough.
            self.reject_count += 1;
            return Err(Error::OutOfMemory);
        }

        let checksum = simple_checksum(page_data);

        // Check if an entry for this offset already exists.
        for entry in &mut self.entries {
            if entry.active && entry.swap_offset == swap_offset {
                entry.compressed_data[..compressed_len]
                    .copy_from_slice(&page_data[..compressed_len]);
                entry.compressed_len = compressed_len;
                entry.original_len = page_data.len();
                entry.checksum = checksum;
                entry.compressor = self.compressor;
                entry.access_count += 1;
                entry.last_access_ns = now_ns;
                // Update byte counters for the replacement.
                return Ok(());
            }
        }

        // Evict LRU if pool is at capacity.
        if self.count >= self.max_entries && self.writeback_lru().is_none() {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        slot.swap_offset = swap_offset;
        slot.compressed_data[..compressed_len].copy_from_slice(&page_data[..compressed_len]);
        slot.compressed_len = compressed_len;
        slot.original_len = page_data.len();
        slot.checksum = checksum;
        slot.compressor = self.compressor;
        slot.active = true;
        slot.access_count = 1;
        slot.last_access_ns = now_ns;

        self.count += 1;
        self.total_stored += 1;
        self.total_compressed_bytes += compressed_len as u64;
        self.total_original_bytes += page_data.len() as u64;

        Ok(())
    }

    /// Load a page from the compressed swap cache.
    ///
    /// Performs stub decompression by copying the compressed data
    /// back into `buf`. Returns the original data size on success.
    ///
    /// # Errors
    ///
    /// - `NotFound` — no entry for the given swap offset.
    /// - `InvalidArgument` — `buf` is too small for the data.
    pub fn load(&mut self, swap_offset: u64, buf: &mut [u8]) -> Result<usize> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.swap_offset == swap_offset)
            .ok_or(Error::NotFound)?;

        if buf.len() < entry.compressed_len {
            return Err(Error::InvalidArgument);
        }

        let len = entry.compressed_len;
        buf[..len].copy_from_slice(&entry.compressed_data[..len]);
        entry.access_count += 1;

        Ok(entry.original_len)
    }

    /// Invalidate (remove) an entry from the pool.
    ///
    /// # Errors
    ///
    /// - `NotFound` — no entry for the given swap offset.
    pub fn invalidate(&mut self, swap_offset: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.swap_offset == swap_offset)
            .ok_or(Error::NotFound)?;

        self.total_compressed_bytes = self
            .total_compressed_bytes
            .saturating_sub(entry.compressed_len as u64);
        self.total_original_bytes = self
            .total_original_bytes
            .saturating_sub(entry.original_len as u64);

        entry.active = false;
        self.count = self.count.saturating_sub(1);

        Ok(())
    }

    /// Check whether the pool contains an entry for the given
    /// swap offset.
    pub fn contains(&self, swap_offset: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.active && e.swap_offset == swap_offset)
    }

    /// Find the least recently used entry and mark it for
    /// writeback to the backing swap device.
    ///
    /// Returns the swap offset of the evicted entry, or `None`
    /// if the pool is empty.
    pub fn writeback_lru(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        let mut min_ns = u64::MAX;
        let mut min_idx = None;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.active && entry.last_access_ns < min_ns {
                min_ns = entry.last_access_ns;
                min_idx = Some(i);
            }
        }

        let idx = min_idx?;
        let entry = &mut self.entries[idx];
        let offset = entry.swap_offset;

        self.total_compressed_bytes = self
            .total_compressed_bytes
            .saturating_sub(entry.compressed_len as u64);
        self.total_original_bytes = self
            .total_original_bytes
            .saturating_sub(entry.original_len as u64);

        entry.active = false;
        self.count = self.count.saturating_sub(1);
        self.writeback_count += 1;

        Some(offset)
    }

    /// Evict LRU entries until the pool count is at or below
    /// `target`.
    ///
    /// Returns the number of entries evicted.
    pub fn shrink(&mut self, target: usize) -> usize {
        let mut evicted = 0;
        while self.count > target {
            if self.writeback_lru().is_none() {
                break;
            }
            evicted += 1;
        }
        evicted
    }

    /// Return current pool statistics.
    pub fn stats(&self) -> ZswapStats {
        ZswapStats {
            stored_pages: self.count as u64,
            compressed_bytes: self.total_compressed_bytes,
            original_bytes: self.total_original_bytes,
            compression_ratio: self.compression_ratio(),
            reject_count: self.reject_count,
            writeback_count: self.writeback_count,
        }
    }

    /// Set the compression algorithm for new entries.
    pub fn set_compressor(&mut self, c: ZswapCompressor) {
        self.compressor = c;
    }

    /// Set the maximum number of entries in the pool.
    ///
    /// If the new maximum is lower than the current count,
    /// excess entries are not immediately evicted; use
    /// [`shrink`](Self::shrink) to enforce the new limit.
    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
    }

    /// Current compression ratio as a percentage.
    ///
    /// Returns `(compressed / original) * 100`. Returns 0 if
    /// no data is stored.
    pub fn compression_ratio(&self) -> u64 {
        if self.total_original_bytes == 0 {
            return 0;
        }
        self.total_compressed_bytes * 100 / self.total_original_bytes
    }

    /// Number of active entries in the pool.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the pool contains no active entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ZswapPool {
    fn default() -> Self {
        Self::new()
    }
}
