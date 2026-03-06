// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `cachestat(2)` syscall handler — query page-cache statistics for a file range.
//!
//! `cachestat` was introduced in Linux 6.5 (syscall number 451 on x86_64).
//! It allows user space to inspect how many pages in a file's byte range are
//! currently resident in the page cache, dirty, under writeback, or have
//! been evicted since the file was opened.
//!
//! # Syscall signature
//!
//! ```text
//! int cachestat(unsigned int fd,
//!               struct cachestat_range *cstat_range,
//!               struct cachestat *cstat,
//!               unsigned int flags);
//! ```
//!
//! # Structures
//!
//! ```text
//! struct cachestat_range { uint64_t off; uint64_t len; };
//!
//! struct cachestat {
//!     uint64_t nr_cache;
//!     uint64_t nr_dirty;
//!     uint64_t nr_writeback;
//!     uint64_t nr_evicted;
//!     uint64_t nr_recently_evicted;
//! };
//! ```
//!
//! `len == 0` means "from `off` to the end of the file".
//! `flags` must be 0.
//!
//! # Linux reference
//!
//! `mm/filemap.c` — `do_sys_cachestat()`, `fincore_cache_count()`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86_64 Linux ABI syscall number for `cachestat`.
pub const SYS_CACHESTAT: u64 = 451;

/// Page size (4 KiB on all ONCRIX targets).
const PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// ABI structures
// ---------------------------------------------------------------------------

/// Byte-range specification for `cachestat`.
///
/// ABI-compatible with `struct cachestat_range` from
/// `include/uapi/linux/mman.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CachestatRange {
    /// Byte offset from which to start (need not be page-aligned).
    pub off: u64,
    /// Number of bytes to inspect (0 = from `off` to end of file).
    pub len: u64,
}

impl CachestatRange {
    /// Construct a full-file range.
    pub const fn full() -> Self {
        Self { off: 0, len: 0 }
    }

    /// Construct a range `[off, off+len)`.
    pub const fn new(off: u64, len: u64) -> Self {
        Self { off, len }
    }
}

/// Page-cache statistics returned by `cachestat`.
///
/// ABI-compatible with `struct cachestat` from
/// `include/uapi/linux/mman.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CachestatOut {
    /// Pages in the range that are currently resident in the page cache.
    pub nr_cache: u64,
    /// Resident pages that are dirty (modified, not yet written to storage).
    pub nr_dirty: u64,
    /// Resident pages that are currently under writeback to storage.
    pub nr_writeback: u64,
    /// Pages that have been evicted from the cache since the file was opened.
    pub nr_evicted: u64,
    /// Evicted pages that are still in the second-chance/recently-evicted window.
    pub nr_recently_evicted: u64,
}

impl CachestatOut {
    /// Return the total number of pages tracked (cache + evicted).
    pub const fn total(&self) -> u64 {
        self.nr_cache.saturating_add(self.nr_evicted)
    }

    /// Return `true` if no cache information is available for the range.
    pub const fn is_empty(&self) -> bool {
        self.nr_cache == 0 && self.nr_evicted == 0
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `cachestat` arguments.
///
/// # Checks
///
/// - `fd` is non-negative.
/// - `flags` is 0.
/// - When `len != 0`: `off + len` does not overflow `u64`.
pub fn validate_cachestat_args(fd: i32, range: &CachestatRange, flags: u32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if range.len != 0 {
        range
            .off
            .checked_add(range.len)
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Page range computation
// ---------------------------------------------------------------------------

/// Compute the first and last page indices for `[off, off+len)` within a file.
///
/// If `len == 0` the range extends to `file_size`.  Returns `None` when the
/// effective range is empty (off >= file_size or file_size == 0).
fn page_range(off: u64, len: u64, file_size: u64) -> Option<(u64, u64)> {
    let end = if len == 0 {
        file_size
    } else {
        off.saturating_add(len).min(file_size)
    };
    if end <= off || file_size == 0 {
        return None;
    }
    let first = off / PAGE_SIZE;
    let last = (end - 1) / PAGE_SIZE;
    Some((first, last))
}

/// Count pages in `[off, off+len)` clamped to `file_size`.
pub fn count_pages(off: u64, len: u64, file_size: u64) -> u64 {
    match page_range(off, len, file_size) {
        None => 0,
        Some((first, last)) => last - first + 1,
    }
}

// ---------------------------------------------------------------------------
// CachestatQuery — query context
// ---------------------------------------------------------------------------

/// A query context built from validated `cachestat` arguments.
///
/// In a real kernel this holds a reference to the inode's `address_space`
/// and walks the XArray to enumerate page flags.  This stub uses simple
/// heuristics based on the file size and a provided cache-hit ratio.
#[derive(Debug, Clone, Copy)]
pub struct CachestatQuery {
    /// File descriptor.
    pub fd: i32,
    /// First page index in the queried range.
    pub first_page: u64,
    /// Number of pages in the queried range.
    pub page_count: u64,
    /// Fraction of pages estimated to be cache-resident (0..=100).
    pub cache_pct: u64,
    /// Fraction of resident pages estimated to be dirty (0..=100).
    pub dirty_pct: u64,
}

impl CachestatQuery {
    /// Construct a query from validated arguments.
    ///
    /// `file_size` is the inode size in bytes.
    /// `cache_pct` is the estimated cache residency percentage (0-100).
    /// `dirty_pct` is the estimated dirty-page percentage of cached pages
    /// (0-100).
    pub fn new(
        fd: i32,
        range: &CachestatRange,
        file_size: u64,
        cache_pct: u64,
        dirty_pct: u64,
    ) -> Self {
        let first_page = range.off / PAGE_SIZE;
        let page_count = count_pages(range.off, range.len, file_size);
        Self {
            fd,
            first_page,
            page_count,
            cache_pct: cache_pct.min(100),
            dirty_pct: dirty_pct.min(100),
        }
    }

    /// Execute the query and return a [`CachestatOut`].
    ///
    /// Uses the `cache_pct` and `dirty_pct` fields to produce a plausible
    /// result.  Replace with a real XArray walk when the mm crate exposes
    /// the page-cache API.
    pub fn execute(&self) -> CachestatOut {
        let cached = self.page_count * self.cache_pct / 100;
        let dirty = cached * self.dirty_pct / 100;
        CachestatOut {
            nr_cache: cached,
            nr_dirty: dirty,
            nr_writeback: 0,
            nr_evicted: self.page_count.saturating_sub(cached),
            nr_recently_evicted: self.page_count.saturating_sub(cached) / 4,
        }
    }
}

// ---------------------------------------------------------------------------
// sys_cachestat — primary handler
// ---------------------------------------------------------------------------

/// `cachestat(2)` syscall handler.
///
/// Queries the page-cache state for the byte range `[range.off, range.off+range.len)`
/// of the file open on `fd`.
///
/// # Arguments
///
/// * `fd`         — Open file descriptor (non-negative).
/// * `range`      — Byte range to inspect.
/// * `file_size`  — Current file size in bytes (from the inode).
/// * `cache_pct`  — Estimated percentage of pages resident in cache (0-100).
/// * `dirty_pct`  — Estimated percentage of cached pages that are dirty (0-100).
/// * `flags`      — Must be 0.
///
/// # Returns
///
/// A populated [`CachestatOut`] on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Negative `fd`, non-zero `flags`, or
///   `off + len` overflows `u64`.
pub fn sys_cachestat(
    fd: i32,
    range: &CachestatRange,
    file_size: u64,
    cache_pct: u64,
    dirty_pct: u64,
    flags: u32,
) -> Result<CachestatOut> {
    validate_cachestat_args(fd, range, flags)?;
    let q = CachestatQuery::new(fd, range, file_size, cache_pct, dirty_pct);
    Ok(q.execute())
}

// ---------------------------------------------------------------------------
// Mincore bit-array helper
// ---------------------------------------------------------------------------

/// Convert a `CachestatOut` into a mincore-style residency bit array.
///
/// Each byte in `out` corresponds to one page starting at `first_page`.
/// A value of `1` indicates the page is resident; `0` indicates it is not.
/// The first `nr_cache` pages are marked resident; the rest are not.
pub fn to_mincore_bits(stat: &CachestatOut, out: &mut [u8]) {
    let resident = stat.nr_cache.min(out.len() as u64) as usize;
    for b in out[..resident].iter_mut() {
        *b = 1;
    }
    for b in out[resident..].iter_mut() {
        *b = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ok() {
        let r = CachestatRange::new(0, 4096);
        assert_eq!(validate_cachestat_args(3, &r, 0), Ok(()));
    }

    #[test]
    fn validate_negative_fd_rejected() {
        let r = CachestatRange::full();
        assert_eq!(
            validate_cachestat_args(-1, &r, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_nonzero_flags_rejected() {
        let r = CachestatRange::new(0, 4096);
        assert_eq!(
            validate_cachestat_args(3, &r, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_range_overflow_rejected() {
        let r = CachestatRange::new(u64::MAX - 10, 100);
        assert_eq!(
            validate_cachestat_args(3, &r, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn count_pages_basic() {
        // 2-page range in a 4-page file.
        assert_eq!(count_pages(0, 2 * PAGE_SIZE, 4 * PAGE_SIZE), 2);
    }

    #[test]
    fn count_pages_full_file() {
        // len == 0 → full file.
        assert_eq!(count_pages(0, 0, 3 * PAGE_SIZE), 3);
    }

    #[test]
    fn count_pages_partial_page() {
        // 1 byte into first page, 1 byte into third page → 3 pages.
        assert_eq!(count_pages(1, 2 * PAGE_SIZE, 4 * PAGE_SIZE), 3);
    }

    #[test]
    fn count_pages_beyond_eof_clamped() {
        assert_eq!(count_pages(0, 100 * PAGE_SIZE, 2 * PAGE_SIZE), 2);
    }

    #[test]
    fn count_pages_empty_file() {
        assert_eq!(count_pages(0, 0, 0), 0);
    }

    #[test]
    fn sys_cachestat_all_cached() {
        let r = CachestatRange::new(0, 4 * PAGE_SIZE);
        let out = sys_cachestat(5, &r, 4 * PAGE_SIZE, 100, 0, 0).unwrap();
        assert_eq!(out.nr_cache, 4);
        assert_eq!(out.nr_dirty, 0);
        assert_eq!(out.nr_writeback, 0);
        assert_eq!(out.nr_evicted, 0);
    }

    #[test]
    fn sys_cachestat_none_cached() {
        let r = CachestatRange::new(0, 4 * PAGE_SIZE);
        let out = sys_cachestat(5, &r, 4 * PAGE_SIZE, 0, 0, 0).unwrap();
        assert_eq!(out.nr_cache, 0);
        assert_eq!(out.nr_evicted, 4);
    }

    #[test]
    fn sys_cachestat_partial_cache() {
        let r = CachestatRange::new(0, 10 * PAGE_SIZE);
        let out = sys_cachestat(7, &r, 10 * PAGE_SIZE, 50, 20, 0).unwrap();
        assert_eq!(out.nr_cache, 5);
        assert_eq!(out.nr_dirty, 1); // 20% of 5
        assert_eq!(out.nr_evicted, 5);
    }

    #[test]
    fn sys_cachestat_zero_len_means_full_file() {
        let r = CachestatRange::full(); // off=0, len=0
        let out = sys_cachestat(3, &r, 8 * PAGE_SIZE, 100, 0, 0).unwrap();
        assert_eq!(out.nr_cache, 8);
    }

    #[test]
    fn cache_stat_out_total() {
        let s = CachestatOut {
            nr_cache: 10,
            nr_dirty: 2,
            nr_writeback: 0,
            nr_evicted: 5,
            nr_recently_evicted: 1,
        };
        assert_eq!(s.total(), 15);
    }

    #[test]
    fn to_mincore_bits_all_resident() {
        let s = CachestatOut {
            nr_cache: 4,
            ..CachestatOut::default()
        };
        let mut bits = [0u8; 4];
        to_mincore_bits(&s, &mut bits);
        assert_eq!(bits, [1, 1, 1, 1]);
    }

    #[test]
    fn to_mincore_bits_partial() {
        let s = CachestatOut {
            nr_cache: 2,
            ..CachestatOut::default()
        };
        let mut bits = [0u8; 4];
        to_mincore_bits(&s, &mut bits);
        assert_eq!(bits, [1, 1, 0, 0]);
    }

    #[test]
    fn cache_stat_out_is_empty() {
        let s = CachestatOut::default();
        assert!(s.is_empty());
        let s2 = CachestatOut {
            nr_cache: 1,
            ..CachestatOut::default()
        };
        assert!(!s2.is_empty());
    }

    #[test]
    fn query_new_correct_first_page() {
        let r = CachestatRange::new(2 * PAGE_SIZE, 3 * PAGE_SIZE);
        let q = CachestatQuery::new(1, &r, 10 * PAGE_SIZE, 100, 0);
        assert_eq!(q.first_page, 2);
        assert_eq!(q.page_count, 3);
    }
}
