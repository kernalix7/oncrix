// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `cachestat` syscall — query page cache status for a file range.
//!
//! Implements the Linux `cachestat(2)` syscall (number 451), which reports
//! how many pages in a file's byte range are currently resident in the page
//! cache, dirty, writeback, evicted, or recently evicted.
//!
//! # Syscall signature
//!
//! ```text
//! int cachestat(unsigned int fd, struct cachestat_range *cstat_range,
//!               struct cachestat *cstat, unsigned int flags);
//! ```
//!
//! The kernel fills `*cstat` with counts for the requested byte range.
//! `flags` must be 0 (reserved for future use).
//!
//! # Reference
//!
//! Linux kernel `mm/filemap.c`: `do_sys_cachestat` (v6.5+).

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Syscall number
// ---------------------------------------------------------------------------

/// x86_64 Linux ABI syscall number for `cachestat`.
pub const SYS_CACHESTAT: u64 = 451;

// ---------------------------------------------------------------------------
// Structures (ABI — must match Linux uapi)
// ---------------------------------------------------------------------------

/// Specifies a byte range within a file for the `cachestat` query.
///
/// `off` is the start offset and `len` is the byte count.  `len == 0`
/// means "from `off` to end of file".
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CachestatRange {
    /// Start offset in bytes (need not be page-aligned).
    pub off: u64,
    /// Number of bytes to query (0 = to end of file).
    pub len: u64,
}

/// Page cache statistics returned by `cachestat`.
///
/// All counts are in units of pages (typically 4 KiB each).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cachestat {
    /// Number of pages in the range that are currently in the page cache
    /// (resident = can be served without a disk read).
    pub nr_cache: u64,
    /// Number of resident pages that have been modified since they were
    /// last written to backing store (dirty pages awaiting writeback).
    pub nr_dirty: u64,
    /// Number of resident pages currently being written back to backing
    /// store by the writeback daemon.
    pub nr_writeback: u64,
    /// Number of pages in the range that were evicted from the cache
    /// since the file was last opened (requires kernel swap accounting).
    pub nr_evicted: u64,
    /// Number of pages that were recently evicted but could quickly be
    /// re-loaded (i.e., they are in the second-chance / clock hand window).
    pub nr_recently_evicted: u64,
}

// ---------------------------------------------------------------------------
// CachestatError
// ---------------------------------------------------------------------------

/// Error codes specific to cachestat validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachestatError {
    /// fd is negative or otherwise invalid.
    BadFd,
    /// The byte range overflows (off + len wraps u64).
    RangeOverflow,
    /// `flags` argument is non-zero (reserved bits).
    InvalidFlags,
}

impl From<CachestatError> for Error {
    fn from(e: CachestatError) -> Self {
        match e {
            CachestatError::BadFd => Error::InvalidArgument,
            CachestatError::RangeOverflow => Error::InvalidArgument,
            CachestatError::InvalidFlags => Error::InvalidArgument,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Maximum plausible file size / offset (128 TiB).
const MAX_FILE_OFFSET: u64 = 1u64 << 47;

/// Validate `cachestat` syscall arguments.
///
/// Returns `Err` if `fd` is negative, `flags` is non-zero, or the
/// `[off, off+len)` byte range overflows `u64`.
fn validate_args(fd: i32, range: &CachestatRange, flags: u32) -> Result<()> {
    if fd < 0 {
        return Err(CachestatError::BadFd.into());
    }
    if flags != 0 {
        return Err(CachestatError::InvalidFlags.into());
    }
    // Check overflow only when len is non-zero.
    if range.len != 0 {
        range
            .off
            .checked_add(range.len)
            .ok_or(Error::from(CachestatError::RangeOverflow))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Page-range computation
// ---------------------------------------------------------------------------

/// Page size on all supported ONCRIX targets (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Compute the number of pages covered by the byte range `[off, off+len)`.
///
/// When `len == 0` the range extends to `end_of_file`; if `end_of_file` is
/// also 0 (empty file) the result is 0.
fn pages_in_range(off: u64, len: u64, file_size: u64) -> u64 {
    let end = if len == 0 {
        file_size
    } else {
        off.saturating_add(len).min(file_size)
    };
    if end <= off {
        return 0;
    }
    let first_page = off / PAGE_SIZE;
    let last_page = (end - 1) / PAGE_SIZE;
    last_page - first_page + 1
}

// ---------------------------------------------------------------------------
// CachestatQuery — internal query context
// ---------------------------------------------------------------------------

/// A resolved query context built from validated syscall arguments.
///
/// In a real kernel this would hold a reference to the inode's address
/// space and the radix-tree/XArray cursor.  Here we use a stub that
/// returns plausible (but synthetic) statistics.
#[derive(Debug, Clone, Copy)]
pub struct CachestatQuery {
    /// File descriptor index.
    pub fd: i32,
    /// First page index of the queried range.
    pub first_page: u64,
    /// Number of pages in the queried range.
    pub page_count: u64,
}

impl CachestatQuery {
    /// Build a query from validated arguments.
    ///
    /// `file_size` is the current size of the file in bytes (obtained from
    /// the inode); it is used to clamp the range to the actual file extent.
    pub fn new(fd: i32, range: &CachestatRange, file_size: u64) -> Self {
        let count = pages_in_range(range.off, range.len, file_size);
        let first_page = range.off / PAGE_SIZE;
        Self {
            fd,
            first_page,
            page_count: count,
        }
    }

    /// Execute the query and produce a [`Cachestat`] result.
    ///
    /// In a production kernel this walks the inode's page cache radix tree
    /// (or XArray) between `first_page` and `first_page + page_count - 1`,
    /// counting pages by their state flags.
    ///
    /// This implementation returns a stub answer that assumes all pages in
    /// the range are resident, 10 % are dirty, and nothing is in writeback
    /// or evicted state.  Replace with real XArray walk when the MM crate
    /// exposes the page-cache API.
    pub fn execute(&self) -> Cachestat {
        let total = self.page_count;
        // Stub heuristics — real implementation queries page flags.
        let nr_dirty = total / 10;
        Cachestat {
            nr_cache: total,
            nr_dirty,
            nr_writeback: 0,
            nr_evicted: 0,
            nr_recently_evicted: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// sys_cachestat — primary syscall handler
// ---------------------------------------------------------------------------

/// `cachestat` syscall handler.
///
/// Queries page-cache residency statistics for the byte range
/// `[range.off, range.off + range.len)` of the file open on `fd`.
///
/// # Arguments
///
/// * `fd`        — open file descriptor
/// * `range`     — byte range to inspect
/// * `file_size` — current file size in bytes (caller obtains from inode)
/// * `flags`     — must be 0
///
/// # Returns
///
/// A [`Cachestat`] populated with page counts on success.
///
/// # Errors
///
/// * `InvalidArgument` — negative fd, non-zero flags, or range overflow
pub fn sys_cachestat(
    fd: i32,
    range: &CachestatRange,
    file_size: u64,
    flags: u32,
) -> Result<Cachestat> {
    validate_args(fd, range, flags)?;
    let query = CachestatQuery::new(fd, range, file_size);
    Ok(query.execute())
}

// ---------------------------------------------------------------------------
// Mincore-style bit-array helper
// ---------------------------------------------------------------------------

/// Maximum number of pages whose residency bits can be returned in a single
/// call to [`cachestat_to_mincore_bits`].
pub const MINCORE_MAX_PAGES: usize = 512;

/// Convert a [`Cachestat`] result into a mincore-style bit array.
///
/// Each bit in the output slice corresponds to one page starting at the
/// query's `first_page`.  Bit `i` is set (1) if page `first_page + i` is
/// resident in the cache.
///
/// This is a simplified stub: it marks the first `nr_cache` pages as
/// resident.  A real implementation would mark exactly the pages that the
/// XArray walk found to be resident.
///
/// # Panics
///
/// Does not panic — `nr_cache` is clamped to `output.len()`.
pub fn cachestat_to_mincore_bits(stat: &Cachestat, output: &mut [u8]) {
    let resident = stat.nr_cache.min(output.len() as u64) as usize;
    for byte in output[..resident].iter_mut() {
        *byte = 1;
    }
    for byte in output[resident..].iter_mut() {
        *byte = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bad_fd() {
        let range = CachestatRange { off: 0, len: 4096 };
        assert_eq!(
            sys_cachestat(-1, &range, 4096, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_validate_nonzero_flags() {
        let range = CachestatRange { off: 0, len: 4096 };
        assert_eq!(
            sys_cachestat(3, &range, 4096, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_validate_range_overflow() {
        let range = CachestatRange {
            off: u64::MAX - 10,
            len: 100,
        };
        assert_eq!(
            sys_cachestat(3, &range, u64::MAX, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pages_in_range_basic() {
        // 8 KiB range starting at 0, file is 16 KiB → 2 pages.
        assert_eq!(pages_in_range(0, 8192, 16384), 2);
    }

    #[test]
    fn test_pages_in_range_zero_len() {
        // len == 0 → extend to file_size (4 pages).
        assert_eq!(pages_in_range(0, 0, 4 * PAGE_SIZE), 4);
    }

    #[test]
    fn test_pages_in_range_partial_page() {
        // off = 1 byte into first page, len = 1 byte into third page.
        assert_eq!(pages_in_range(1, 2 * PAGE_SIZE, 4 * PAGE_SIZE), 3);
    }

    #[test]
    fn test_pages_in_range_beyond_file() {
        // Range extends past file end — clamped to file size.
        assert_eq!(pages_in_range(0, 100 * PAGE_SIZE, 4 * PAGE_SIZE), 4);
    }

    #[test]
    fn test_pages_in_range_empty_file() {
        assert_eq!(pages_in_range(0, 0, 0), 0);
    }

    #[test]
    fn test_sys_cachestat_ok() {
        let range = CachestatRange {
            off: 0,
            len: 4 * PAGE_SIZE,
        };
        let stat = sys_cachestat(3, &range, 8 * PAGE_SIZE, 0).unwrap();
        assert_eq!(stat.nr_cache, 4);
        assert_eq!(stat.nr_writeback, 0);
        assert_eq!(stat.nr_evicted, 0);
    }

    #[test]
    fn test_sys_cachestat_zero_len_full_file() {
        let range = CachestatRange { off: 0, len: 0 };
        let stat = sys_cachestat(5, &range, 10 * PAGE_SIZE, 0).unwrap();
        assert_eq!(stat.nr_cache, 10);
    }

    #[test]
    fn test_mincore_bits_all_resident() {
        let stat = Cachestat {
            nr_cache: 4,
            nr_dirty: 0,
            nr_writeback: 0,
            nr_evicted: 0,
            nr_recently_evicted: 0,
        };
        let mut bits = [0u8; 4];
        cachestat_to_mincore_bits(&stat, &mut bits);
        assert_eq!(bits, [1, 1, 1, 1]);
    }

    #[test]
    fn test_mincore_bits_partial_resident() {
        let stat = Cachestat {
            nr_cache: 2,
            nr_dirty: 0,
            nr_writeback: 0,
            nr_evicted: 0,
            nr_recently_evicted: 0,
        };
        let mut bits = [0u8; 4];
        cachestat_to_mincore_bits(&stat, &mut bits);
        assert_eq!(bits, [1, 1, 0, 0]);
    }

    #[test]
    fn test_cachestat_query_new() {
        let range = CachestatRange {
            off: PAGE_SIZE,
            len: 3 * PAGE_SIZE,
        };
        let q = CachestatQuery::new(1, &range, 10 * PAGE_SIZE);
        assert_eq!(q.first_page, 1);
        assert_eq!(q.page_count, 3);
    }
}
