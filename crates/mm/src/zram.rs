// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! zram — compressed RAM block device.
//!
//! Provides a block device backed by compressed pages in RAM,
//! commonly used as a swap device to avoid disk I/O entirely.
//! Pages written to zram are compressed (LZO/LZ4 simulation) and
//! stored in fixed-size slots. Identical pages are merged via
//! same-page detection (all-zero optimisation).
//!
//! # Architecture
//!
//! - [`ZramCompAlgo`] — compression algorithm selector
//! - [`ZramPageSlot`] — per-page compressed storage slot
//! - [`ZramDevice`] — the compressed RAM block device
//! - [`ZramStats`] — device statistics and memory tracking
//!
//! # Compression Simulation
//!
//! Real compression is not implemented in no_std. Instead, a
//! deterministic size reduction heuristic is used: the "compressed"
//! size is derived from the data entropy, producing realistic
//! compression ratios for testing.
//!
//! # Same-Page Merging
//!
//! Pages whose contents are all zeroes are detected and stored
//! as a flag rather than occupying a compressed slot, saving
//! memory for sparse workloads.
//!
//! Reference: Linux `drivers/block/zram/zram_drv.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum compressed page size (75% of page).
const MAX_COMPRESSED_SIZE: usize = 3072;

/// Maximum number of pages the zram device can hold.
const MAX_ZRAM_PAGES: usize = 4096;

/// Default disk size in bytes (16 MiB).
const DEFAULT_DISKSIZE: u64 = 16 * 1024 * 1024;

/// Maximum disk size in bytes (1 GiB).
const MAX_DISKSIZE: u64 = 1024 * 1024 * 1024;

/// FNV-1a offset basis for hashing.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a prime for hashing.
const FNV_PRIME: u64 = 0x0100_0000_01b3;

// -------------------------------------------------------------------
// ZramCompAlgo
// -------------------------------------------------------------------

/// Compression algorithm for zram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZramCompAlgo {
    /// LZO compression.
    Lzo,
    /// LZ4 compression (default, fastest).
    #[default]
    Lz4,
    /// Zstandard compression (best ratio).
    Zstd,
    /// LZ4HC (high compression variant of LZ4).
    Lz4Hc,
}

impl ZramCompAlgo {
    /// Simulated compression ratio as a percentage.
    ///
    /// Returns the expected compressed size as a fraction of the
    /// original, used by the compression simulator.
    const fn ratio_pct(self) -> usize {
        match self {
            Self::Lzo => 55,
            Self::Lz4 => 60,
            Self::Zstd => 40,
            Self::Lz4Hc => 50,
        }
    }
}

// -------------------------------------------------------------------
// ZramPageFlags
// -------------------------------------------------------------------

/// Per-page flags for zram storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZramPageFlags {
    /// Slot is empty / unused.
    #[default]
    Empty,
    /// Page is compressed and stored.
    Compressed,
    /// Page is a same-page (all zeroes) — no data stored.
    SamePage,
    /// Page has been written back to a backing device.
    WrittenBack,
}

// -------------------------------------------------------------------
// ZramPageSlot
// -------------------------------------------------------------------

/// Per-page compressed storage slot.
///
/// Each slot holds the compressed representation of a single
/// 4 KiB page, or a flag indicating that the page is all zeroes.
#[derive(Clone, Copy)]
pub struct ZramPageSlot {
    /// Compressed page data buffer.
    data: [u8; MAX_COMPRESSED_SIZE],
    /// Number of valid compressed bytes (0 for same-page).
    compressed_len: usize,
    /// Original (uncompressed) size in bytes.
    orig_size: usize,
    /// Page flags.
    flags: ZramPageFlags,
    /// Access counter for statistics.
    access_count: u32,
    /// Content hash for same-page detection.
    hash: u64,
}

impl ZramPageSlot {
    /// Create an empty page slot.
    const fn empty() -> Self {
        Self {
            data: [0u8; MAX_COMPRESSED_SIZE],
            compressed_len: 0,
            orig_size: 0,
            flags: ZramPageFlags::Empty,
            access_count: 0,
            hash: 0,
        }
    }

    /// Whether this slot holds data (compressed or same-page).
    pub fn is_occupied(&self) -> bool {
        !matches!(self.flags, ZramPageFlags::Empty)
    }

    /// The compressed size in bytes, or 0 for same-pages.
    pub fn compressed_size(&self) -> usize {
        self.compressed_len
    }

    /// The original uncompressed size.
    pub fn original_size(&self) -> usize {
        self.orig_size
    }

    /// Current page flags.
    pub fn flags(&self) -> ZramPageFlags {
        self.flags
    }
}

impl Default for ZramPageSlot {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// ZramStats
// -------------------------------------------------------------------

/// zram device statistics and memory tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZramStats {
    /// Total bytes of compressed data stored.
    pub compr_data_size: u64,
    /// Total bytes of original (uncompressed) data.
    pub orig_data_size: u64,
    /// Total memory used by the zram device (metadata + data).
    pub mem_used_total: u64,
    /// Number of pages currently stored.
    pub pages_stored: u64,
    /// Number of same-page (all-zero) pages.
    pub same_pages: u64,
    /// Total read requests.
    pub num_reads: u64,
    /// Total write requests.
    pub num_writes: u64,
    /// Number of failed reads (page not found).
    pub failed_reads: u64,
    /// Number of failed writes (device full or compression failure).
    pub failed_writes: u64,
    /// Number of pages written back to backing device.
    pub pages_written_back: u64,
    /// Number of invalid I/O requests.
    pub invalid_io: u64,
    /// Maximum memory usage observed.
    pub mem_used_max: u64,
    /// Number of pages that were merged (same content).
    pub pages_merged: u64,
}

// -------------------------------------------------------------------
// Compression helpers
// -------------------------------------------------------------------

/// Compute FNV-1a hash of a byte slice.
fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Check if a page is all zeroes.
fn is_zero_page(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

/// Simulate compression by producing a deterministic reduced-size
/// output. The "compressed" data is derived from a hash-based
/// permutation of the input, producing a result whose length
/// approximates real compression.
fn simulate_compress(data: &[u8], algo: ZramCompAlgo, out: &mut [u8]) -> usize {
    if data.is_empty() {
        return 0;
    }

    // Calculate simulated compressed size.
    let ratio = algo.ratio_pct();
    let target_len = (data.len() * ratio / 100).max(1).min(out.len());

    // Produce deterministic output by XOR-folding the input.
    let mut hash = FNV_OFFSET;
    for (i, slot) in out.iter_mut().enumerate().take(target_len) {
        let src_idx = i % data.len();
        hash ^= data[src_idx] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        *slot = (hash & 0xFF) as u8;
    }

    target_len
}

/// Simulate decompression by reconstructing the original data
/// from the compressed form. Since our "compression" is a
/// simulation, decompression produces deterministic output based
/// on the compressed data and the original size.
fn simulate_decompress(compressed: &[u8], compressed_len: usize, out: &mut [u8], orig_size: usize) {
    let write_len = orig_size.min(out.len());
    let src = &compressed[..compressed_len.min(compressed.len())];

    let mut hash = FNV_OFFSET;
    for (i, slot) in out.iter_mut().enumerate().take(write_len) {
        let src_idx = i % src.len().max(1);
        hash ^= src[src_idx] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        *slot = (hash & 0xFF) as u8;
    }
}

// -------------------------------------------------------------------
// ZramDevice
// -------------------------------------------------------------------

/// zram compressed RAM block device.
///
/// Provides a block device interface where each "sector" is a 4 KiB
/// page. Pages are compressed and stored in memory, with same-page
/// detection for all-zero pages.
///
/// # Disk Size
///
/// The `disksize` parameter controls the logical device size. Pages
/// beyond `disksize / PAGE_SIZE` are rejected. The physical memory
/// used depends on compression ratios.
pub struct ZramDevice {
    /// Per-page storage slots.
    slots: [ZramPageSlot; MAX_ZRAM_PAGES],
    /// Logical disk size in bytes.
    disksize: u64,
    /// Number of logical pages (disksize / PAGE_SIZE).
    num_pages: usize,
    /// Compression algorithm.
    comp_algo: ZramCompAlgo,
    /// Device statistics.
    stats: ZramStats,
    /// Whether the device is initialised and accepting I/O.
    initialised: bool,
    /// Maximum memory limit in bytes (0 = unlimited).
    mem_limit: u64,
}

impl ZramDevice {
    /// Create a new zram device with default settings.
    ///
    /// The device must be initialised with [`set_disksize`] before
    /// use.
    ///
    /// [`set_disksize`]: ZramDevice::set_disksize
    pub const fn new() -> Self {
        Self {
            slots: [const { ZramPageSlot::empty() }; MAX_ZRAM_PAGES],
            disksize: 0,
            num_pages: 0,
            comp_algo: ZramCompAlgo::Lz4,
            stats: ZramStats {
                compr_data_size: 0,
                orig_data_size: 0,
                mem_used_total: 0,
                pages_stored: 0,
                same_pages: 0,
                num_reads: 0,
                num_writes: 0,
                failed_reads: 0,
                failed_writes: 0,
                pages_written_back: 0,
                invalid_io: 0,
                mem_used_max: 0,
                pages_merged: 0,
            },
            initialised: false,
            mem_limit: 0,
        }
    }

    /// Set the logical disk size and initialise the device.
    ///
    /// `size` is rounded down to a page boundary. Must be called
    /// before any I/O operations. The device cannot be resized
    /// while it holds data.
    pub fn set_disksize(&mut self, size: u64) -> Result<()> {
        if size == 0 || size > MAX_DISKSIZE {
            return Err(Error::InvalidArgument);
        }
        if self.initialised && self.stats.pages_stored > 0 {
            return Err(Error::Busy);
        }

        let aligned = size & !(PAGE_SIZE as u64 - 1);
        if aligned == 0 {
            return Err(Error::InvalidArgument);
        }

        self.disksize = aligned;
        self.num_pages = (aligned as usize / PAGE_SIZE).min(MAX_ZRAM_PAGES);
        self.initialised = true;
        Ok(())
    }

    /// Set the compression algorithm.
    ///
    /// Can only be changed when the device holds no data.
    pub fn set_comp_algorithm(&mut self, algo: ZramCompAlgo) -> Result<()> {
        if self.stats.pages_stored > 0 {
            return Err(Error::Busy);
        }
        self.comp_algo = algo;
        Ok(())
    }

    /// Set the maximum memory limit.
    ///
    /// A limit of 0 means unlimited. When the limit is reached,
    /// further writes fail with `OutOfMemory`.
    pub fn set_mem_limit(&mut self, limit: u64) {
        self.mem_limit = limit;
    }

    /// Return the logical disk size in bytes.
    pub fn disksize(&self) -> u64 {
        self.disksize
    }

    /// Return the number of logical pages.
    pub fn num_pages(&self) -> usize {
        self.num_pages
    }

    /// Return the current compression algorithm.
    pub fn comp_algorithm(&self) -> ZramCompAlgo {
        self.comp_algo
    }

    /// Write (make_request) a page to the zram device.
    ///
    /// `page_index` identifies the logical page. `data` must be
    /// exactly `PAGE_SIZE` bytes.
    pub fn write_page(&mut self, page_index: usize, data: &[u8]) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        if page_index >= self.num_pages {
            self.stats.invalid_io += 1;
            return Err(Error::InvalidArgument);
        }
        if data.len() != PAGE_SIZE {
            self.stats.invalid_io += 1;
            return Err(Error::InvalidArgument);
        }

        self.stats.num_writes += 1;

        // Check memory limit before writing.
        if self.mem_limit > 0 && self.stats.mem_used_total >= self.mem_limit {
            self.stats.failed_writes += 1;
            return Err(Error::OutOfMemory);
        }

        // Free existing slot data if overwriting.
        let slot = &self.slots[page_index];
        if slot.is_occupied() {
            let old_compr = slot.compressed_len as u64;
            let old_orig = slot.orig_size as u64;
            self.stats.compr_data_size = self.stats.compr_data_size.saturating_sub(old_compr);
            self.stats.orig_data_size = self.stats.orig_data_size.saturating_sub(old_orig);
            self.stats.mem_used_total = self.stats.mem_used_total.saturating_sub(old_compr);
            if slot.flags == ZramPageFlags::SamePage {
                self.stats.same_pages = self.stats.same_pages.saturating_sub(1);
            }
            self.stats.pages_stored = self.stats.pages_stored.saturating_sub(1);
        }

        // Same-page detection (all zeroes).
        if is_zero_page(data) {
            let new_slot = &mut self.slots[page_index];
            new_slot.flags = ZramPageFlags::SamePage;
            new_slot.compressed_len = 0;
            new_slot.orig_size = PAGE_SIZE;
            new_slot.access_count += 1;
            new_slot.hash = 0;
            self.stats.same_pages += 1;
            self.stats.pages_stored += 1;
            self.stats.orig_data_size += PAGE_SIZE as u64;
            return Ok(());
        }

        // Compress the page.
        let mut comp_buf = [0u8; MAX_COMPRESSED_SIZE];
        let comp_len = simulate_compress(data, self.comp_algo, &mut comp_buf);

        if comp_len == 0 || comp_len > MAX_COMPRESSED_SIZE {
            self.stats.failed_writes += 1;
            return Err(Error::IoError);
        }

        // Check memory limit with new compressed data.
        if self.mem_limit > 0 && self.stats.mem_used_total + comp_len as u64 > self.mem_limit {
            self.stats.failed_writes += 1;
            return Err(Error::OutOfMemory);
        }

        let hash = fnv1a_hash(data);

        // Check for same-content pages (merge opportunity).
        let mut merged = false;
        for (i, existing) in self.slots.iter().enumerate() {
            if i == page_index {
                continue;
            }
            if existing.flags == ZramPageFlags::Compressed
                && existing.hash == hash
                && existing.orig_size == PAGE_SIZE
            {
                // Same content — record as merged.
                self.stats.pages_merged += 1;
                merged = true;
                break;
            }
        }
        let _ = merged; // Merge detection is informational.

        let new_slot = &mut self.slots[page_index];
        new_slot.data[..comp_len].copy_from_slice(&comp_buf[..comp_len]);
        new_slot.compressed_len = comp_len;
        new_slot.orig_size = PAGE_SIZE;
        new_slot.flags = ZramPageFlags::Compressed;
        new_slot.access_count += 1;
        new_slot.hash = hash;

        self.stats.compr_data_size += comp_len as u64;
        self.stats.orig_data_size += PAGE_SIZE as u64;
        self.stats.mem_used_total += comp_len as u64;
        self.stats.pages_stored += 1;

        if self.stats.mem_used_total > self.stats.mem_used_max {
            self.stats.mem_used_max = self.stats.mem_used_total;
        }

        Ok(())
    }

    /// Read (make_request) a page from the zram device.
    ///
    /// `page_index` identifies the logical page. `buf` must be at
    /// least `PAGE_SIZE` bytes.
    pub fn read_page(&mut self, page_index: usize, buf: &mut [u8]) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        if page_index >= self.num_pages {
            self.stats.invalid_io += 1;
            return Err(Error::InvalidArgument);
        }
        if buf.len() < PAGE_SIZE {
            self.stats.invalid_io += 1;
            return Err(Error::InvalidArgument);
        }

        self.stats.num_reads += 1;

        let slot = &self.slots[page_index];
        match slot.flags {
            ZramPageFlags::Empty => {
                // Unwritten page reads as zeroes.
                for byte in buf.iter_mut().take(PAGE_SIZE) {
                    *byte = 0;
                }
                Ok(())
            }
            ZramPageFlags::SamePage => {
                // All-zero page.
                for byte in buf.iter_mut().take(PAGE_SIZE) {
                    *byte = 0;
                }
                self.slots[page_index].access_count += 1;
                Ok(())
            }
            ZramPageFlags::Compressed => {
                let comp_len = slot.compressed_len;
                let orig_size = slot.orig_size;
                simulate_decompress(&slot.data, comp_len, buf, orig_size);
                self.slots[page_index].access_count += 1;
                Ok(())
            }
            ZramPageFlags::WrittenBack => {
                // Written-back pages are not in RAM.
                self.stats.failed_reads += 1;
                Err(Error::NotFound)
            }
        }
    }

    /// Mark a page as written back to the backing device.
    ///
    /// The compressed data is freed from RAM.
    pub fn writeback_page(&mut self, page_index: usize) -> Result<()> {
        if page_index >= self.num_pages {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.slots[page_index];
        if !matches!(slot.flags, ZramPageFlags::Compressed) {
            return Err(Error::InvalidArgument);
        }

        let freed = slot.compressed_len as u64;
        let orig = slot.orig_size as u64;

        self.slots[page_index].flags = ZramPageFlags::WrittenBack;
        self.slots[page_index].compressed_len = 0;

        self.stats.compr_data_size = self.stats.compr_data_size.saturating_sub(freed);
        self.stats.mem_used_total = self.stats.mem_used_total.saturating_sub(freed);
        self.stats.orig_data_size = self.stats.orig_data_size.saturating_sub(orig);
        self.stats.pages_written_back += 1;
        self.stats.pages_stored = self.stats.pages_stored.saturating_sub(1);
        Ok(())
    }

    /// Discard (TRIM) a page from the device.
    ///
    /// Frees the compressed data and marks the slot as empty.
    pub fn discard_page(&mut self, page_index: usize) -> Result<()> {
        if page_index >= self.num_pages {
            return Err(Error::InvalidArgument);
        }

        let slot = &self.slots[page_index];
        if !slot.is_occupied() {
            return Ok(());
        }

        let freed_compr = slot.compressed_len as u64;
        let freed_orig = slot.orig_size as u64;
        let was_same = matches!(slot.flags, ZramPageFlags::SamePage);

        self.slots[page_index] = ZramPageSlot::empty();

        self.stats.compr_data_size = self.stats.compr_data_size.saturating_sub(freed_compr);
        self.stats.orig_data_size = self.stats.orig_data_size.saturating_sub(freed_orig);
        self.stats.mem_used_total = self.stats.mem_used_total.saturating_sub(freed_compr);
        self.stats.pages_stored = self.stats.pages_stored.saturating_sub(1);
        if was_same {
            self.stats.same_pages = self.stats.same_pages.saturating_sub(1);
        }
        Ok(())
    }

    /// Reset the device, discarding all data.
    pub fn reset(&mut self) -> Result<()> {
        for slot in &mut self.slots {
            *slot = ZramPageSlot::empty();
        }
        self.stats = ZramStats::default();
        self.initialised = false;
        self.disksize = 0;
        self.num_pages = 0;
        Ok(())
    }

    /// Return device statistics.
    pub fn stats(&self) -> &ZramStats {
        &self.stats
    }

    /// Return the compression ratio as a percentage.
    ///
    /// Returns 100 if no data is stored (no compression).
    pub fn compression_ratio(&self) -> u64 {
        if self.stats.orig_data_size == 0 {
            return 100;
        }
        self.stats.compr_data_size * 100 / self.stats.orig_data_size
    }

    /// Whether the device is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Return the memory limit.
    pub fn mem_limit(&self) -> u64 {
        self.mem_limit
    }
}

impl Default for ZramDevice {
    fn default() -> Self {
        Self::new()
    }
}
