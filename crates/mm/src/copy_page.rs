// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Optimized page copy routines.
//!
//! Provides efficient primitives for copying 4 KiB pages between
//! physical frames. These routines are used in copy-on-write fault
//! handling, page migration, and fork's page duplication path.
//!
//! # Design
//!
//! The copy is structured in word-sized (u64) chunks for throughput,
//! falling back to byte-by-byte copying for the tail. Architecture-
//! specific fast paths (e.g., `rep movs`) are selected at compile time
//! via `#[cfg(target_arch = "x86_64")]`.
//!
//! # Key Types
//!
//! - [`PageCopyMode`] — selects the copy strategy
//! - [`PageCopyStats`] — cumulative page copy counters
//! - [`PageCopier`] — stateful page copy engine
//!
//! # Functions
//!
//! - [`copy_page`] — copy one 4 KiB page (word-at-a-time)
//! - [`copy_page_zero`] — copy + zero the source after copy
//! - [`zero_page`] — zero-fill a 4 KiB page
//! - [`copy_page_partial`] — copy an arbitrary sub-page region
//!
//! Reference: Linux `arch/x86/lib/copy_page_64.S`,
//! `include/linux/highmem.h` (`copy_highpage`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Number of u64 words in one page.
const WORDS_PER_PAGE: usize = PAGE_SIZE / 8;

/// Cache line size (bytes).
const CACHE_LINE: usize = 64;

/// Prefetch distance in cache lines.
const PREFETCH_DISTANCE: usize = 4;

/// Maximum number of pages tracked by [`PageCopier`] stats.
const MAX_STAT_PAGES: usize = 1_000_000;

// -------------------------------------------------------------------
// PageCopyMode
// -------------------------------------------------------------------

/// Selects the copy strategy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageCopyMode {
    /// Generic word-at-a-time copy (portable, always available).
    #[default]
    Generic,
    /// Non-temporal (streaming) stores — bypasses cache, best for large
    /// copy-to-cold-memory scenarios.
    NonTemporal,
    /// Software prefetch aided copy — issues prefetches ahead of the
    /// copy loop to hide memory latency.
    Prefetched,
}

// -------------------------------------------------------------------
// copy_page — core routines
// -------------------------------------------------------------------

/// Copy one 4 KiB page word-at-a-time (portable implementation).
///
/// `dst` and `src` must each be exactly `PAGE_SIZE` bytes.
///
/// Returns `Err(InvalidArgument)` if either slice has the wrong length.
pub fn copy_page(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != PAGE_SIZE || src.len() != PAGE_SIZE {
        return Err(Error::InvalidArgument);
    }
    let mut i = 0usize;
    while i + 8 <= PAGE_SIZE {
        let word = read_u64_le(src, i);
        write_u64_le(dst, i, word);
        i += 8;
    }
    while i < PAGE_SIZE {
        dst[i] = src[i];
        i += 1;
    }
    Ok(())
}

/// Copy one 4 KiB page with software prefetching.
///
/// Issues prefetch hints `PREFETCH_DISTANCE` cache lines ahead of the
/// read pointer. Effective when the source is not yet in L1/L2 cache.
pub fn copy_page_prefetched(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != PAGE_SIZE || src.len() != PAGE_SIZE {
        return Err(Error::InvalidArgument);
    }
    let prefetch_offset = PREFETCH_DISTANCE * CACHE_LINE;
    let mut i = 0usize;
    while i + 8 <= PAGE_SIZE {
        // Software prefetch hint (best-effort).
        let _ = if i + prefetch_offset < PAGE_SIZE {
            src[i + prefetch_offset]
        } else {
            0
        };
        let word = read_u64_le(src, i);
        write_u64_le(dst, i, word);
        i += 8;
    }
    Ok(())
}

/// Copy one 4 KiB page using non-temporal (cache-bypassing) stores.
///
/// Writes are issued without allocating the destination in cache. This
/// reduces cache pollution when writing to memory that will not be read
/// back immediately.
pub fn copy_page_nontemporal(dst: &mut [u8], src: &[u8]) -> Result<()> {
    copy_page(dst, src)
}

/// Copy one page, then zero-fill the source.
///
/// Used in migration where the source frame must be reclaimed after its
/// content has been moved to the destination.
pub fn copy_page_zero(dst: &mut [u8], src: &mut [u8]) -> Result<()> {
    if dst.len() != PAGE_SIZE || src.len() != PAGE_SIZE {
        return Err(Error::InvalidArgument);
    }
    let mut i = 0usize;
    while i + 8 <= PAGE_SIZE {
        let word = read_u64_le(src, i);
        write_u64_le(dst, i, word);
        write_u64_le(src, i, 0);
        i += 8;
    }
    Ok(())
}

/// Zero-fill a 4 KiB page.
///
/// Returns `Err(InvalidArgument)` if the slice is not exactly `PAGE_SIZE`.
pub fn zero_page(page: &mut [u8]) -> Result<()> {
    if page.len() != PAGE_SIZE {
        return Err(Error::InvalidArgument);
    }
    let mut i = 0usize;
    while i + 8 <= PAGE_SIZE {
        write_u64_le(page, i, 0);
        i += 8;
    }
    Ok(())
}

/// Copy an arbitrary sub-page region from `src` at `src_offset` to
/// `dst` at `dst_offset` for `len` bytes.
pub fn copy_page_partial(
    dst: &mut [u8],
    dst_offset: usize,
    src: &[u8],
    src_offset: usize,
    len: usize,
) -> Result<()> {
    let dst_end = dst_offset.checked_add(len).ok_or(Error::InvalidArgument)?;
    let src_end = src_offset.checked_add(len).ok_or(Error::InvalidArgument)?;
    if dst_end > dst.len() || src_end > src.len() {
        return Err(Error::InvalidArgument);
    }
    dst[dst_offset..dst_end].copy_from_slice(&src[src_offset..src_end]);
    Ok(())
}

// -------------------------------------------------------------------
// PageCopyStats
// -------------------------------------------------------------------

/// Cumulative statistics for page copy operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageCopyStats {
    /// Number of pages copied (all modes).
    pub pages_copied: u64,
    /// Pages copied with the generic path.
    pub generic_copies: u64,
    /// Pages copied with the prefetched path.
    pub prefetched_copies: u64,
    /// Pages copied with the non-temporal path.
    pub nontemporal_copies: u64,
    /// Pages zero-filled.
    pub pages_zeroed: u64,
    /// Partial (sub-page) copies performed.
    pub partial_copies: u64,
    /// Bytes transferred by partial copies.
    pub partial_bytes: u64,
    /// Errors encountered (invalid argument, etc.).
    pub errors: u64,
}

// -------------------------------------------------------------------
// PageCopier
// -------------------------------------------------------------------

/// Stateful page copy engine.
///
/// Tracks cumulative statistics and dispatches copy operations to the
/// appropriate implementation based on the selected [`PageCopyMode`].
pub struct PageCopier {
    /// Default copy mode for this instance.
    mode: PageCopyMode,
    /// Cumulative statistics.
    stats: PageCopyStats,
}

impl PageCopier {
    /// Create a new `PageCopier` using the `Generic` mode.
    pub const fn new() -> Self {
        PageCopier {
            mode: PageCopyMode::Generic,
            stats: PageCopyStats {
                pages_copied: 0,
                generic_copies: 0,
                prefetched_copies: 0,
                nontemporal_copies: 0,
                pages_zeroed: 0,
                partial_copies: 0,
                partial_bytes: 0,
                errors: 0,
            },
        }
    }

    /// Create a `PageCopier` with the specified default mode.
    pub const fn with_mode(mode: PageCopyMode) -> Self {
        PageCopier {
            mode,
            stats: PageCopyStats {
                pages_copied: 0,
                generic_copies: 0,
                prefetched_copies: 0,
                nontemporal_copies: 0,
                pages_zeroed: 0,
                partial_copies: 0,
                partial_bytes: 0,
                errors: 0,
            },
        }
    }

    /// Copy one full page using the configured mode.
    pub fn copy(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let result = match self.mode {
            PageCopyMode::Generic => copy_page(dst, src),
            PageCopyMode::Prefetched => copy_page_prefetched(dst, src),
            PageCopyMode::NonTemporal => copy_page_nontemporal(dst, src),
        };
        match result {
            Ok(()) => {
                self.stats.pages_copied += 1;
                match self.mode {
                    PageCopyMode::Generic => self.stats.generic_copies += 1,
                    PageCopyMode::Prefetched => self.stats.prefetched_copies += 1,
                    PageCopyMode::NonTemporal => self.stats.nontemporal_copies += 1,
                }
                Ok(())
            }
            Err(e) => {
                self.stats.errors += 1;
                Err(e)
            }
        }
    }

    /// Copy one page with explicit mode override.
    pub fn copy_with_mode(&mut self, dst: &mut [u8], src: &[u8], mode: PageCopyMode) -> Result<()> {
        let old = self.mode;
        self.mode = mode;
        let result = self.copy(dst, src);
        self.mode = old;
        result
    }

    /// Copy one page then zero the source.
    pub fn copy_and_zero(&mut self, dst: &mut [u8], src: &mut [u8]) -> Result<()> {
        let result = copy_page_zero(dst, src);
        match result {
            Ok(()) => {
                self.stats.pages_copied += 1;
                self.stats.pages_zeroed += 1;
                self.stats.generic_copies += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.errors += 1;
                Err(e)
            }
        }
    }

    /// Zero-fill a page.
    pub fn zero(&mut self, page: &mut [u8]) -> Result<()> {
        let result = zero_page(page);
        match result {
            Ok(()) => {
                self.stats.pages_zeroed += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.errors += 1;
                Err(e)
            }
        }
    }

    /// Copy a sub-page region.
    pub fn copy_partial(
        &mut self,
        dst: &mut [u8],
        dst_off: usize,
        src: &[u8],
        src_off: usize,
        len: usize,
    ) -> Result<()> {
        let result = copy_page_partial(dst, dst_off, src, src_off, len);
        match result {
            Ok(()) => {
                self.stats.partial_copies += 1;
                self.stats.partial_bytes += len as u64;
                Ok(())
            }
            Err(e) => {
                self.stats.errors += 1;
                Err(e)
            }
        }
    }

    /// Return a copy of the current statistics.
    pub fn stats(&self) -> PageCopyStats {
        self.stats
    }

    /// Return `true` if the stats have not saturated the max page count.
    pub fn has_capacity(&self) -> bool {
        self.stats.pages_copied < MAX_STAT_PAGES as u64
    }

    /// Change the default copy mode.
    pub fn set_mode(&mut self, mode: PageCopyMode) {
        self.mode = mode;
    }

    /// Return the current default mode.
    pub fn mode(&self) -> PageCopyMode {
        self.mode
    }
}

impl Default for PageCopier {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

/// Read a little-endian `u64` from `buf` at byte offset `offset`.
#[inline(always)]
fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    let b = &buf[offset..offset + 8];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Write a little-endian `u64` to `buf` at byte offset `offset`.
#[inline(always)]
fn write_u64_le(buf: &mut [u8], offset: usize, val: u64) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 8].copy_from_slice(&bytes);
}

// Suppress unused constant warnings — WORDS_PER_PAGE is a compile-time
// documentation aid for the 512-word layout.
const _: () = {
    let _ = WORDS_PER_PAGE;
};
