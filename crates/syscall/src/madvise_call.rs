// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `madvise(2)` syscall dispatch layer.
//!
//! Gives the kernel an advisory hint about the intended usage pattern of
//! a range of virtual memory `[addr, addr+len)`.  The kernel may use this
//! information to optimise paging, prefetching, or reclaim decisions.
//!
//! # Syscall signature
//!
//! ```text
//! int madvise(void *addr, size_t length, int advice);
//! ```
//!
//! `addr` must be page-aligned.  `length` is rounded up to the next page.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `posix_madvise()` in `<sys/mman.h>`
//! - Linux extension: `madvise(2)` adds many Linux-specific advice values.
//!
//! # References
//!
//! - Linux: `mm/madvise.c` (`do_madvise`)
//! - `madvise(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Advice constants (POSIX + Linux extensions)
// ---------------------------------------------------------------------------

/// No special treatment (default).
pub const MADV_NORMAL: i32 = 0;
/// Expect random access pattern; disable read-ahead.
pub const MADV_RANDOM: i32 = 1;
/// Expect sequential access; aggressively read-ahead.
pub const MADV_SEQUENTIAL: i32 = 2;
/// Expect access soon; start read-ahead.
pub const MADV_WILLNEED: i32 = 3;
/// Do not expect access soon; release pages on pressure.
pub const MADV_DONTNEED: i32 = 4;
/// Pages may be freed and zero-filled on next access.
pub const MADV_FREE: i32 = 8;
/// Remove the mapping and return memory to OS (anonymous only).
pub const MADV_REMOVE: i32 = 9;
/// Do not dump this range in core files.
pub const MADV_DONTDUMP: i32 = 16;
/// Re-enable core dumping for this range.
pub const MADV_DODUMP: i32 = 17;
/// Enable transparent huge pages for this range.
pub const MADV_HUGEPAGE: i32 = 14;
/// Disable transparent huge pages for this range.
pub const MADV_NOHUGEPAGE: i32 = 15;
/// Mark range as not needed; kernel may reclaim it.
pub const MADV_COLD: i32 = 20;
/// Proactively reclaim pages in range.
pub const MADV_PAGEOUT: i32 = 21;
/// Populate pages for read.
pub const MADV_POPULATE_READ: i32 = 22;
/// Populate pages for write.
pub const MADV_POPULATE_WRITE: i32 = 23;

/// System page size (assumed 4 KiB for validation purposes).
const PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `advice` is a recognised advice value.
pub fn is_valid_advice(advice: i32) -> bool {
    matches!(
        advice,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_FREE
            | MADV_REMOVE
            | MADV_DONTDUMP
            | MADV_DODUMP
            | MADV_HUGEPAGE
            | MADV_NOHUGEPAGE
            | MADV_COLD
            | MADV_PAGEOUT
            | MADV_POPULATE_READ
            | MADV_POPULATE_WRITE
    )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `madvise(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `addr` is not page-aligned, `length` is 0,
///   or `advice` is unknown.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_madvise(addr: u64, length: usize, advice: i32) -> Result<i64> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_advice(advice) {
        return Err(Error::InvalidArgument);
    }
    let _ = (addr, length, advice);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_madvise_call(addr: u64, length: usize, advice: i32) -> Result<i64> {
    sys_madvise(addr, length, advice)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unaligned_addr_rejected() {
        assert_eq!(
            sys_madvise(0x1001, 4096, MADV_NORMAL).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_length_rejected() {
        assert_eq!(
            sys_madvise(0x1000, 0, MADV_NORMAL).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_advice_rejected() {
        assert_eq!(
            sys_madvise(0x1000, 4096, 99).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_madvise(0x1000, 4096, MADV_DONTNEED);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
