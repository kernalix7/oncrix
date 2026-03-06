// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `posix_fadvise(2)` syscall handler — file access pattern advisory hints.
//!
//! Implements the Linux `posix_fadvise(2)` system call which allows
//! applications to declare their expected access pattern for a file region.
//! The kernel may use this information to optimize I/O scheduling, readahead,
//! and page cache eviction.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 specifies `posix_fadvise` in:
//! `.TheOpenGroup/susv5-html/functions/posix_fadvise.html`
//!
//! # Advice values
//!
//! | Value            | Meaning                                          |
//! |------------------|--------------------------------------------------|
//! | `POSIX_FADV_NORMAL`    | No special advice (default behavior)      |
//! | `POSIX_FADV_SEQUENTIAL`| Access will be sequential — increase readahead |
//! | `POSIX_FADV_RANDOM`    | Access will be random — disable readahead  |
//! | `POSIX_FADV_NOREUSE`   | Data will not be reused — evict after use  |
//! | `POSIX_FADV_WILLNEED`  | Will need data — start prefetching         |
//! | `POSIX_FADV_DONTNEED`  | Do not need data — evict from cache        |
//!
//! # Implementation note
//!
//! The effect stubs here record the hint in the `FadviseState` table and
//! update statistics.  In a real kernel the hints would be passed to the
//! page cache and block I/O subsystem.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously tracked per-fd hints.
pub const FADVISE_MAX_HINTS: usize = 64;

/// Syscall number for `posix_fadvise` (x86_64 Linux ABI).
pub const SYS_FADVISE64: u64 = 221;

/// Number of distinct advice values (Normal..DontNeed).
pub const ADVICE_COUNT: usize = 6;

// ---------------------------------------------------------------------------
// FadviseAdvice
// ---------------------------------------------------------------------------

/// Access-pattern advice for `posix_fadvise`.
///
/// Matches the POSIX.1-2024 `POSIX_FADV_*` constants and Linux values.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FadviseAdvice {
    /// Normal access pattern — no specific optimization.
    Normal = 0,
    /// Sequential access — increase readahead window.
    Sequential = 1,
    /// Random access — disable readahead.
    Random = 2,
    /// Data will not be reused — evict pages after use.
    NoReuse = 3,
    /// Will access region soon — start prefetch.
    WillNeed = 4,
    /// Will not access region — evict from page cache.
    DontNeed = 5,
}

impl FadviseAdvice {
    /// Parse from a raw `u32`.  Returns `InvalidArgument` for unknown values.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Sequential),
            2 => Ok(Self::Random),
            3 => Ok(Self::NoReuse),
            4 => Ok(Self::WillNeed),
            5 => Ok(Self::DontNeed),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw `u32` value.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Return the index into per-advice statistics arrays.
    pub const fn index(self) -> usize {
        self as usize
    }
}

// ---------------------------------------------------------------------------
// FadviseHint — a recorded hint entry
// ---------------------------------------------------------------------------

/// A recorded `fadvise` hint for a specific file region.
///
/// Tracks the file descriptor, byte range, and advice type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FadviseHint {
    /// File descriptor this hint applies to.
    pub fd: i32,
    /// Start offset within the file (bytes).
    pub offset: u64,
    /// Length of the region in bytes (0 means "to end of file").
    pub length: u64,
    /// The access pattern advice.
    pub advice: FadviseAdvice,
}

impl FadviseHint {
    /// Construct a new hint.
    pub const fn new(fd: i32, offset: u64, length: u64, advice: FadviseAdvice) -> Self {
        Self {
            fd,
            offset,
            length,
            advice,
        }
    }

    /// Return the end offset of this hint's region.
    ///
    /// Returns `None` if the hint covers to end-of-file (`length == 0`).
    pub const fn end_offset(&self) -> Option<u64> {
        if self.length == 0 {
            None
        } else {
            self.offset.checked_add(self.length)
        }
    }
}

// ---------------------------------------------------------------------------
// FadviseStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the `fadvise` subsystem.
#[derive(Debug, Clone, Copy)]
pub struct FadviseStats {
    /// Total number of `posix_fadvise` calls.
    pub total_calls: u64,
    /// Per-advice-type call counts (`[Normal, Sequential, Random, NoReuse, WillNeed, DontNeed]`).
    pub per_advice_counts: [u64; ADVICE_COUNT],
}

impl FadviseStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_calls: 0,
            per_advice_counts: [0u64; ADVICE_COUNT],
        }
    }
}

impl Default for FadviseStats {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FadviseState — per-fd hint table
// ---------------------------------------------------------------------------

/// Per-system `fadvise` hint table.
///
/// Records the most-recent hint per file descriptor (up to
/// `FADVISE_MAX_HINTS` distinct descriptors tracked simultaneously).
/// When the table is full, the oldest entry is evicted (FIFO).
#[derive(Debug)]
pub struct FadviseState {
    /// Hint slots; `None` means the slot is free.
    hints: [Option<FadviseHint>; FADVISE_MAX_HINTS],
    /// Next eviction index (FIFO rotation).
    next_evict: usize,
    /// Number of active hints.
    active_count: usize,
}

impl FadviseState {
    /// Create an empty hint table.
    pub const fn new() -> Self {
        Self {
            hints: [const { None }; FADVISE_MAX_HINTS],
            next_evict: 0,
            active_count: 0,
        }
    }

    /// Record a hint, replacing any existing hint for `fd`.
    ///
    /// If the fd already has an entry it is updated in-place; otherwise a
    /// free slot is used.  When no free slot is available the oldest entry
    /// (tracked by `next_evict`) is overwritten.
    pub fn record(&mut self, hint: FadviseHint) {
        // Update existing entry for this fd.
        for slot in self.hints.iter_mut() {
            if let Some(h) = slot {
                if h.fd == hint.fd {
                    *h = hint;
                    return;
                }
            }
        }

        // Find a free slot.
        for slot in self.hints.iter_mut() {
            if slot.is_none() {
                *slot = Some(hint);
                self.active_count += 1;
                return;
            }
        }

        // Evict the oldest slot (FIFO).
        self.hints[self.next_evict] = Some(hint);
        self.next_evict = (self.next_evict + 1) % FADVISE_MAX_HINTS;
    }

    /// Look up the most-recent hint for `fd`.
    pub fn last_hint(&self, fd: i32) -> Option<FadviseHint> {
        self.hints.iter().find_map(|s| s.filter(|h| h.fd == fd))
    }

    /// Remove all hints for `fd` (called on file close).
    pub fn remove_fd(&mut self, fd: i32) {
        for slot in self.hints.iter_mut() {
            if slot.map_or(false, |h| h.fd == fd) {
                if slot.is_some() {
                    self.active_count = self.active_count.saturating_sub(1);
                }
                *slot = None;
            }
        }
    }

    /// Return the number of currently active hints.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for FadviseState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `fadvise` arguments.
///
/// Checks:
/// - `fd` is non-negative.
/// - `offset + length` does not overflow.
/// - `advice` is a known value.
///
/// Returns the validated `FadviseAdvice` on success.
fn validate_fadvise_args(
    fd: i32,
    offset: u64,
    length: u64,
    advice_raw: u32,
) -> Result<FadviseAdvice> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    // Overflow check: offset + length must not overflow u64.
    if length > 0 {
        offset.checked_add(length).ok_or(Error::InvalidArgument)?;
    }
    FadviseAdvice::from_raw(advice_raw)
}

// ---------------------------------------------------------------------------
// Effect stubs
// ---------------------------------------------------------------------------

/// Apply the advisory effect for `Sequential` — increase readahead.
///
/// In a real kernel this would notify the readahead subsystem to extend
/// the readahead window for pages in `[offset, offset+length)`.
fn effect_sequential(_fd: i32, _offset: u64, _length: u64) {
    // Stub: would call `file_ra_state` adjustment in VFS layer.
}

/// Apply the advisory effect for `Random` — disable readahead.
fn effect_random(_fd: i32, _offset: u64, _length: u64) {
    // Stub: would set `ra_pages = 0` in the file's readahead state.
}

/// Apply the advisory effect for `NoReuse` — mark pages as disposable.
fn effect_noreuse(_fd: i32, _offset: u64, _length: u64) {
    // Stub: would mark the page-cache pages with PG_reclaim.
}

/// Apply the advisory effect for `WillNeed` — trigger prefetch.
fn effect_willneed(_fd: i32, _offset: u64, _length: u64) {
    // Stub: would submit readahead I/O for the region.
}

/// Apply the advisory effect for `DontNeed` — evict from page cache.
fn effect_dontneed(_fd: i32, _offset: u64, _length: u64) {
    // Stub: would call `invalidate_mapping_pages` for the region.
}

// ---------------------------------------------------------------------------
// do_fadvise
// ---------------------------------------------------------------------------

/// Core handler for `posix_fadvise(2)`.
///
/// Records the advisory hint and applies any relevant I/O optimization stub.
///
/// # Arguments
///
/// * `state`       — Mutable hint table.
/// * `stats`       — Mutable statistics accumulator.
/// * `fd`          — Open file descriptor.
/// * `offset`      — Start offset of the advisory region (bytes).
/// * `length`      — Length of the region (`0` means to end-of-file).
/// * `advice_raw`  — Raw advice constant (`POSIX_FADV_*`).
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// * `InvalidArgument` — Negative `fd`, overflow in `offset+length`,
///   or unknown `advice` value.
///
/// # POSIX conformance
///
/// Per POSIX.1-2024, `posix_fadvise` returns 0 on success and an error
/// number on failure (not −1 with errno).  The function may be a no-op
/// on platforms that do not support the advice; our implementation records
/// the hint and applies stubs.
pub fn do_fadvise(
    state: &mut FadviseState,
    stats: &mut FadviseStats,
    fd: i32,
    offset: u64,
    length: u64,
    advice_raw: u32,
) -> Result<()> {
    let advice = validate_fadvise_args(fd, offset, length, advice_raw)?;

    // Record the hint.
    state.record(FadviseHint::new(fd, offset, length, advice));

    // Apply the advisory effect stub.
    match advice {
        FadviseAdvice::Normal => {}
        FadviseAdvice::Sequential => effect_sequential(fd, offset, length),
        FadviseAdvice::Random => effect_random(fd, offset, length),
        FadviseAdvice::NoReuse => effect_noreuse(fd, offset, length),
        FadviseAdvice::WillNeed => effect_willneed(fd, offset, length),
        FadviseAdvice::DontNeed => effect_dontneed(fd, offset, length),
    }

    // Update statistics.
    stats.total_calls += 1;
    stats.per_advice_counts[advice.index()] += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall entry point (raw register values)
// ---------------------------------------------------------------------------

/// Process a raw `posix_fadvise` syscall.
///
/// Converts raw register-width arguments and delegates to [`do_fadvise`].
///
/// # Arguments
///
/// * `state`       — Mutable hint table.
/// * `stats`       — Mutable statistics accumulator.
/// * `fd`          — Raw `fd` argument (must fit in `i32`).
/// * `offset`      — Raw `offset` argument.
/// * `length`      — Raw `len` argument.
/// * `advice_raw`  — Raw `advice` argument (must fit in `u32`).
pub fn sys_fadvise(
    state: &mut FadviseState,
    stats: &mut FadviseStats,
    fd: u64,
    offset: u64,
    length: u64,
    advice_raw: u64,
) -> Result<()> {
    let fd_i32 = i32::try_from(fd).map_err(|_| Error::InvalidArgument)?;
    let adv_u32 = u32::try_from(advice_raw).map_err(|_| Error::InvalidArgument)?;
    do_fadvise(state, stats, fd_i32, offset, length, adv_u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advice_from_raw_valid() {
        assert_eq!(FadviseAdvice::from_raw(0).unwrap(), FadviseAdvice::Normal);
        assert_eq!(
            FadviseAdvice::from_raw(1).unwrap(),
            FadviseAdvice::Sequential
        );
        assert_eq!(FadviseAdvice::from_raw(2).unwrap(), FadviseAdvice::Random);
        assert_eq!(FadviseAdvice::from_raw(3).unwrap(), FadviseAdvice::NoReuse);
        assert_eq!(FadviseAdvice::from_raw(4).unwrap(), FadviseAdvice::WillNeed);
        assert_eq!(FadviseAdvice::from_raw(5).unwrap(), FadviseAdvice::DontNeed);
    }

    #[test]
    fn test_advice_from_raw_invalid() {
        assert_eq!(FadviseAdvice::from_raw(6), Err(Error::InvalidArgument));
        assert_eq!(FadviseAdvice::from_raw(0xFF), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_validate_negative_fd() {
        assert_eq!(
            validate_fadvise_args(-1, 0, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_validate_overflow() {
        assert_eq!(
            validate_fadvise_args(3, u64::MAX, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_do_fadvise_normal() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        do_fadvise(&mut state, &mut stats, 3, 0, 4096, 0).unwrap();
        assert_eq!(stats.total_calls, 1);
        assert_eq!(stats.per_advice_counts[FadviseAdvice::Normal.index()], 1);
    }

    #[test]
    fn test_do_fadvise_sequential() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        do_fadvise(
            &mut state,
            &mut stats,
            5,
            0,
            65536,
            FadviseAdvice::Sequential.as_u32(),
        )
        .unwrap();
        let hint = state.last_hint(5).unwrap();
        assert_eq!(hint.advice, FadviseAdvice::Sequential);
        assert_eq!(stats.per_advice_counts[1], 1);
    }

    #[test]
    fn test_do_fadvise_dontneed() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        do_fadvise(
            &mut state,
            &mut stats,
            7,
            4096,
            8192,
            FadviseAdvice::DontNeed.as_u32(),
        )
        .unwrap();
        assert_eq!(stats.per_advice_counts[FadviseAdvice::DontNeed.index()], 1);
    }

    #[test]
    fn test_do_fadvise_willneed() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        do_fadvise(
            &mut state,
            &mut stats,
            2,
            0,
            0,
            FadviseAdvice::WillNeed.as_u32(),
        )
        .unwrap();
        let hint = state.last_hint(2).unwrap();
        assert_eq!(hint.length, 0); // 0 = to end of file
    }

    #[test]
    fn test_hint_update_same_fd() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        do_fadvise(
            &mut state,
            &mut stats,
            10,
            0,
            1024,
            FadviseAdvice::Normal.as_u32(),
        )
        .unwrap();
        do_fadvise(
            &mut state,
            &mut stats,
            10,
            0,
            2048,
            FadviseAdvice::Random.as_u32(),
        )
        .unwrap();
        let hint = state.last_hint(10).unwrap();
        assert_eq!(hint.advice, FadviseAdvice::Random);
        assert_eq!(hint.length, 2048);
    }

    #[test]
    fn test_remove_fd() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        do_fadvise(
            &mut state,
            &mut stats,
            4,
            0,
            512,
            FadviseAdvice::Normal.as_u32(),
        )
        .unwrap();
        assert!(state.last_hint(4).is_some());
        state.remove_fd(4);
        assert!(state.last_hint(4).is_none());
    }

    #[test]
    fn test_hint_end_offset() {
        let hint = FadviseHint::new(1, 1024, 4096, FadviseAdvice::Sequential);
        assert_eq!(hint.end_offset(), Some(5120));

        let eof_hint = FadviseHint::new(1, 1024, 0, FadviseAdvice::WillNeed);
        assert_eq!(eof_hint.end_offset(), None);
    }

    #[test]
    fn test_sys_fadvise_raw() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        sys_fadvise(&mut state, &mut stats, 3, 0, 4096, 1).unwrap();
        assert_eq!(stats.per_advice_counts[1], 1);
    }

    #[test]
    fn test_fadvise_table_eviction() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        // Fill the table completely with distinct fds.
        for fd in 0..FADVISE_MAX_HINTS as i32 {
            do_fadvise(&mut state, &mut stats, fd, 0, 64, 0).unwrap();
        }
        // Adding one more fd should evict the oldest entry.
        do_fadvise(&mut state, &mut stats, FADVISE_MAX_HINTS as i32, 0, 64, 0).unwrap();
        assert_eq!(stats.total_calls, FADVISE_MAX_HINTS as u64 + 1);
    }

    #[test]
    fn test_all_advice_stats() {
        let mut state = FadviseState::new();
        let mut stats = FadviseStats::new();
        for advice in 0u32..ADVICE_COUNT as u32 {
            do_fadvise(&mut state, &mut stats, advice as i32, 0, 0, advice).unwrap();
        }
        assert_eq!(stats.total_calls, ADVICE_COUNT as u64);
        for count in stats.per_advice_counts.iter() {
            assert_eq!(*count, 1);
        }
    }
}
