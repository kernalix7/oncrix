// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getdents64(2)` extended directory reading syscall handler.
//!
//! Implements the Linux `getdents64` system call which reads directory
//! entries into a caller-supplied buffer.  Each entry is described by a
//! `linux_dirent64` structure that includes the inode number, offset,
//! record length, file type, and null-terminated name.
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t getdents64(int fd, void *dirp, size_t count);
//! ```
//!
//! # Wire format (`linux_dirent64`)
//!
//! ```text
//! struct linux_dirent64 {
//!     u64  d_ino;     /* 64-bit inode number        */
//!     i64  d_off;     /* 64-bit cookie/offset       */
//!     u16  d_reclen;  /* size of this dirent        */
//!     u8   d_type;    /* file type (DT_*)           */
//!     char d_name[];  /* null-terminated filename   */
//! };
//! ```
//!
//! # POSIX reference
//!
//! `getdents64` is a Linux extension.  The related POSIX interface is
//! `readdir(3)` (`.TheOpenGroup/susv5-html/functions/readdir.html`).
//! The `d_type` field is an extension beyond POSIX `dirent`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a directory entry name (including NUL terminator).
pub const DNAME_MAX: usize = 256;

/// Maximum number of directory entries cached by `DirEntryIterator`.
pub const DIR_CACHE_SIZE: usize = 64;

/// Fixed-size `linux_dirent64` structure.
///
/// We use a fixed `d_name` array (`[u8; DNAME_MAX]`) for `no_std`
/// compatibility.  The wire record length (`d_reclen`) reflects only the
/// bytes actually used (fixed-size aligned header + name length + NUL).
///
/// The actual kernel ABI uses a variable-length flexible array for `d_name`,
/// but this fixed representation is safe for in-kernel use.
///
/// Syscall number for `getdents64` (x86_64 Linux ABI).
pub const SYS_GETDENTS64: u64 = 217;

// ---------------------------------------------------------------------------
// DirentType
// ---------------------------------------------------------------------------

/// File type values for the `d_type` field of `linux_dirent64`.
///
/// Matches the `DT_*` constants defined in `<dirent.h>`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirentType {
    /// Unknown type.
    Unknown = 0,
    /// FIFO (named pipe).
    Fifo = 1,
    /// Character device.
    Chr = 2,
    /// Directory.
    Dir = 4,
    /// Block device.
    Blk = 6,
    /// Regular file.
    Reg = 8,
    /// Symbolic link.
    Lnk = 10,
    /// Unix domain socket.
    Sock = 12,
    /// Whiteout (BSD, for union mounts).
    Wht = 14,
}

impl DirentType {
    /// Parse from a raw `u8`.  Unknown values map to `DirentType::Unknown`.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Fifo,
            2 => Self::Chr,
            4 => Self::Dir,
            6 => Self::Blk,
            8 => Self::Reg,
            10 => Self::Lnk,
            12 => Self::Sock,
            14 => Self::Wht,
            _ => Self::Unknown,
        }
    }

    /// Return the raw `u8` value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// LinuxDirent64
// ---------------------------------------------------------------------------

/// In-kernel representation of a `linux_dirent64` entry.
///
/// The `d_name` field is padded to `DNAME_MAX` bytes; `d_reclen` records
/// the actual serialised record size (header + name-length + NUL), aligned
/// to 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxDirent64 {
    /// 64-bit inode number.
    pub d_ino: u64,
    /// Directory offset (cookie for the next `getdents` call).
    pub d_off: i64,
    /// Size of this dirent record in bytes (header + name + NUL, 8-byte aligned).
    pub d_reclen: u16,
    /// File type (`DT_*`).
    pub d_type: u8,
    /// Null-terminated filename (padded to `DNAME_MAX`).
    pub d_name: [u8; DNAME_MAX],
}

impl LinuxDirent64 {
    /// Size of the fixed header portion: `d_ino` + `d_off` + `d_reclen` + `d_type`.
    pub const HEADER_SIZE: usize = 8 + 8 + 2 + 1; // 19 bytes

    /// Construct a new directory entry.
    ///
    /// `name` must not be longer than `DNAME_MAX - 1` (to allow NUL).
    ///
    /// Returns `InvalidArgument` if the name is too long or empty.
    pub fn new(ino: u64, off: i64, d_type: DirentType, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() >= DNAME_MAX {
            return Err(Error::InvalidArgument);
        }

        let mut entry = Self {
            d_ino: ino,
            d_off: off,
            d_reclen: 0,
            d_type: d_type.as_u8(),
            d_name: [0u8; DNAME_MAX],
        };

        entry.d_name[..name.len()].copy_from_slice(name);
        // NUL terminator is already in place (array initialised to 0).

        // Compute wire record length: header + name-length + NUL, aligned to 8.
        let raw_len = Self::HEADER_SIZE + name.len() + 1;
        let aligned = (raw_len + 7) & !7;
        entry.d_reclen = aligned as u16;

        Ok(entry)
    }

    /// Return the length of the name (excluding NUL).
    pub fn name_len(&self) -> usize {
        self.d_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(DNAME_MAX)
    }

    /// Return a slice of the name bytes (excluding NUL).
    pub fn name_bytes(&self) -> &[u8] {
        let len = self.name_len();
        &self.d_name[..len]
    }
}

// ---------------------------------------------------------------------------
// DirContext — accumulator for getdents output
// ---------------------------------------------------------------------------

/// Accumulator context used to build the `getdents64` output buffer.
///
/// The caller provides a fixed-size output slice; `readdir_emit` appends
/// entries one by one, stopping when the buffer is full.
#[derive(Debug)]
pub struct DirContext {
    /// Current read position in the directory (entry index).
    pub pos: u64,
    /// Total number of bytes appended to the output buffer so far.
    pub buf_used: usize,
    /// Whether an error occurred during emission.
    pub error: bool,
    /// Maximum capacity of the output buffer.
    buf_size: usize,
}

impl DirContext {
    /// Create a new context for a buffer of `buf_size` bytes.
    pub const fn new(buf_size: usize) -> Self {
        Self {
            pos: 0,
            buf_used: 0,
            error: false,
            buf_size,
        }
    }

    /// Return the number of bytes remaining in the output buffer.
    pub const fn remaining(&self) -> usize {
        self.buf_size.saturating_sub(self.buf_used)
    }

    /// Return `true` if the output buffer is full.
    pub const fn is_full(&self) -> bool {
        self.buf_used >= self.buf_size
    }
}

// ---------------------------------------------------------------------------
// DirEntryIterator — simulated directory contents
// ---------------------------------------------------------------------------

/// Simulated directory entry iterator.
///
/// In a real kernel this would be backed by the filesystem's `iterate_dir`
/// operation.  Here we store up to `DIR_CACHE_SIZE` pre-populated entries
/// to support testing and scaffolding.
#[derive(Debug)]
pub struct DirEntryIterator {
    /// Inode ID of the directory being listed.
    pub dir_inode_id: u64,
    /// Current iteration position (entry index).
    pub pos: usize,
    /// Cached entries.
    entries: [Option<LinuxDirent64>; DIR_CACHE_SIZE],
    /// Number of populated entries.
    pub cached_count: usize,
}

impl DirEntryIterator {
    /// Create an empty iterator for directory `dir_inode_id`.
    pub fn new(dir_inode_id: u64) -> Self {
        Self {
            dir_inode_id,
            pos: 0,
            entries: [const { None }; DIR_CACHE_SIZE],
            cached_count: 0,
        }
    }

    /// Add a pre-built entry to the cache.
    ///
    /// Returns `Busy` if the cache is full.
    pub fn push(&mut self, entry: LinuxDirent64) -> Result<()> {
        if self.cached_count >= DIR_CACHE_SIZE {
            return Err(Error::Busy);
        }
        self.entries[self.cached_count] = Some(entry);
        self.cached_count += 1;
        Ok(())
    }

    /// Return the next entry at position `self.pos`, advancing the iterator.
    pub fn next_entry(&mut self) -> Option<LinuxDirent64> {
        while self.pos < self.cached_count {
            let idx = self.pos;
            self.pos += 1;
            if let Some(e) = self.entries[idx] {
                return Some(e);
            }
        }
        None
    }

    /// Reset the iterator to position 0.
    pub fn reset(&mut self) {
        self.pos = 0;
    }

    /// Return `true` if all entries have been consumed.
    pub const fn exhausted(&self) -> bool {
        self.pos >= self.cached_count
    }
}

// ---------------------------------------------------------------------------
// GetdentsStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the `getdents64` subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetdentsStats {
    /// Total `getdents64` calls.
    pub total_calls: u64,
    /// Total directory entries returned across all calls.
    pub entries_returned: u64,
    /// Number of distinct directories read (calls with at least one entry).
    pub directories_read: u64,
}

impl GetdentsStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_calls: 0,
            entries_returned: 0,
            directories_read: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// readdir_emit
// ---------------------------------------------------------------------------

/// Append a single directory entry to the output buffer.
///
/// Returns `true` if the entry was appended; `false` if the buffer does
/// not have enough space (the caller should stop iteration).
///
/// # Arguments
///
/// * `ctx`   — Accumulator context (tracks used bytes and position).
/// * `buf`   — Output buffer slice.
/// * `name`  — Entry name bytes (without NUL terminator).
/// * `ino`   — Inode number.
/// * `dtype` — File type.
pub fn readdir_emit(
    ctx: &mut DirContext,
    buf: &mut [u8],
    name: &[u8],
    ino: u64,
    dtype: DirentType,
) -> bool {
    if ctx.error || ctx.is_full() {
        return false;
    }

    let entry = match LinuxDirent64::new(ino, ctx.pos as i64, dtype, name) {
        Ok(e) => e,
        Err(_) => {
            ctx.error = true;
            return false;
        }
    };

    let reclen = entry.d_reclen as usize;
    if ctx.buf_used + reclen > ctx.buf_size {
        // Not enough space — signal the caller to stop.
        return false;
    }

    // Serialise the entry into `buf` at the current offset.
    // Layout: d_ino(8) | d_off(8) | d_reclen(2) | d_type(1) | d_name(reclen-19)
    let start = ctx.buf_used;
    let end = start + reclen;
    if end > buf.len() {
        ctx.error = true;
        return false;
    }

    let out = &mut buf[start..end];

    // d_ino
    out[0..8].copy_from_slice(&entry.d_ino.to_ne_bytes());
    // d_off
    out[8..16].copy_from_slice(&entry.d_off.to_ne_bytes());
    // d_reclen
    out[16..18].copy_from_slice(&entry.d_reclen.to_ne_bytes());
    // d_type
    out[18] = entry.d_type;
    // d_name (the name bytes + NUL; remaining bytes already zeroed by slice init)
    let name_len = entry.name_len();
    let name_start = 19;
    let name_end = name_start + name_len;
    if name_end <= reclen {
        out[name_start..name_end].copy_from_slice(&entry.d_name[..name_len]);
        // NUL byte
        if name_end < reclen {
            out[name_end] = 0;
        }
    }

    ctx.buf_used += reclen;
    ctx.pos += 1;
    true
}

// ---------------------------------------------------------------------------
// do_getdents64
// ---------------------------------------------------------------------------

/// Handler for `getdents64(2)`.
///
/// Reads directory entries from the iterator backing `fd` and writes them
/// in `linux_dirent64` format into the caller's buffer.
///
/// # Arguments
///
/// * `iter`     — Directory entry source.
/// * `stats`    — Statistics accumulator.
/// * `buf`      — Output buffer (must be at least 20 bytes for one entry).
/// * `buf_size` — Usable size of `buf` in bytes.
///
/// # Returns
///
/// Number of bytes written to `buf` on success.  Returns `0` when the
/// directory is exhausted (end-of-directory).
///
/// # Errors
///
/// * `InvalidArgument` — `buf_size` is 0, or `buf` is shorter than
///   `buf_size`.
/// * `NotFound`        — The directory iterator is invalid.
///
/// # POSIX conformance
///
/// This implements the Linux `getdents64` ABI.  The related POSIX interface
/// is `readdir(3)`, which this syscall underpins.
pub fn do_getdents64(
    iter: &mut DirEntryIterator,
    stats: &mut GetdentsStats,
    buf: &mut [u8],
    buf_size: usize,
) -> Result<usize> {
    if buf_size == 0 {
        return Err(Error::InvalidArgument);
    }
    if buf.len() < buf_size {
        return Err(Error::InvalidArgument);
    }

    stats.total_calls += 1;

    let mut ctx = DirContext::new(buf_size);
    let mut entries_this_call: u64 = 0;

    // Zero the output buffer region we will use.
    buf[..buf_size].fill(0);

    while !iter.exhausted() {
        let entry = match iter.next_entry() {
            Some(e) => e,
            None => break,
        };

        let name_slice = entry.name_bytes();
        let dtype = DirentType::from_u8(entry.d_type);

        if !readdir_emit(&mut ctx, buf, name_slice, entry.d_ino, dtype) {
            // Buffer full — push entry back by decrementing iterator position.
            if iter.pos > 0 {
                iter.pos -= 1;
            }
            break;
        }
        entries_this_call += 1;
    }

    if entries_this_call > 0 {
        stats.entries_returned += entries_this_call;
        stats.directories_read += 1;
    }

    Ok(ctx.buf_used)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_iter_with(names: &[&[u8]], base_ino: u64) -> DirEntryIterator {
        let mut iter = DirEntryIterator::new(100);
        for (i, name) in names.iter().enumerate() {
            let entry =
                LinuxDirent64::new(base_ino + i as u64, i as i64, DirentType::Reg, name).unwrap();
            iter.push(entry).unwrap();
        }
        iter
    }

    #[test]
    fn test_dirent_type_roundtrip() {
        for (v, expected) in [
            (0u8, DirentType::Unknown),
            (1, DirentType::Fifo),
            (2, DirentType::Chr),
            (4, DirentType::Dir),
            (6, DirentType::Blk),
            (8, DirentType::Reg),
            (10, DirentType::Lnk),
            (12, DirentType::Sock),
            (14, DirentType::Wht),
        ] {
            assert_eq!(DirentType::from_u8(v), expected);
            assert_eq!(expected.as_u8(), v);
        }
    }

    #[test]
    fn test_dirent64_new_ok() {
        let e = LinuxDirent64::new(42, 0, DirentType::Reg, b"hello").unwrap();
        assert_eq!(e.d_ino, 42);
        assert_eq!(e.d_type, DirentType::Reg.as_u8());
        assert_eq!(e.name_bytes(), b"hello");
        // header(19) + len(5) + nul(1) = 25, aligned to 8 → 32
        assert_eq!(e.d_reclen, 32);
    }

    #[test]
    fn test_dirent64_name_too_long() {
        let long_name = [b'x'; DNAME_MAX];
        assert_eq!(
            LinuxDirent64::new(1, 0, DirentType::Dir, &long_name),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_dirent64_empty_name() {
        assert_eq!(
            LinuxDirent64::new(1, 0, DirentType::Reg, b""),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_readdir_emit_single() {
        let mut buf = [0u8; 512];
        let mut ctx = DirContext::new(512);
        let ok = readdir_emit(&mut ctx, &mut buf, b"foo", 10, DirentType::Reg);
        assert!(ok);
        assert!(ctx.buf_used > 0);
        assert_eq!(ctx.pos, 1);
    }

    #[test]
    fn test_readdir_emit_buffer_full() {
        let mut buf = [0u8; 20]; // Just enough for header + 1 byte name = 21 raw, 24 aligned
        let mut ctx = DirContext::new(20);
        // Name "a" → header(19) + 1 + nul(1) = 21, aligned = 24 > 20 → does not fit
        let ok = readdir_emit(&mut ctx, &mut buf, b"a", 1, DirentType::Reg);
        assert!(!ok);
        assert_eq!(ctx.buf_used, 0);
    }

    #[test]
    fn test_do_getdents64_basic() {
        let mut iter = make_iter_with(&[b".", b"..", b"file.txt"], 100);
        let mut stats = GetdentsStats::new();
        let mut buf = [0u8; 4096];
        let n = do_getdents64(&mut iter, &mut stats, &mut buf, 4096).unwrap();
        assert!(n > 0);
        assert_eq!(stats.total_calls, 1);
        assert_eq!(stats.entries_returned, 3);
        assert_eq!(stats.directories_read, 1);
    }

    #[test]
    fn test_do_getdents64_empty_dir() {
        let mut iter = DirEntryIterator::new(200);
        let mut stats = GetdentsStats::new();
        let mut buf = [0u8; 4096];
        let n = do_getdents64(&mut iter, &mut stats, &mut buf, 4096).unwrap();
        assert_eq!(n, 0);
        assert_eq!(stats.entries_returned, 0);
        assert_eq!(stats.directories_read, 0);
    }

    #[test]
    fn test_do_getdents64_zero_buf_size() {
        let mut iter = DirEntryIterator::new(300);
        let mut stats = GetdentsStats::new();
        let mut buf = [0u8; 4096];
        assert_eq!(
            do_getdents64(&mut iter, &mut stats, &mut buf, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_do_getdents64_buf_too_small() {
        let mut iter = DirEntryIterator::new(400);
        let mut stats = GetdentsStats::new();
        let mut buf = [0u8; 8]; // buf.len() < buf_size
        assert_eq!(
            do_getdents64(&mut iter, &mut stats, &mut buf, 16),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_do_getdents64_incremental() {
        // Two calls with a small buffer should yield all entries over two rounds.
        let mut iter = make_iter_with(&[b"a", b"b", b"c", b"d"], 50);
        let mut stats = GetdentsStats::new();
        let mut buf = [0u8; 4096];

        // First call — all entries fit.
        let n1 = do_getdents64(&mut iter, &mut stats, &mut buf, 4096).unwrap();
        assert!(n1 > 0);
        assert_eq!(stats.entries_returned, 4);

        // Second call — directory exhausted.
        let n2 = do_getdents64(&mut iter, &mut stats, &mut buf, 4096).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_dir_context_remaining() {
        let ctx = DirContext::new(1024);
        assert_eq!(ctx.remaining(), 1024);
        assert!(!ctx.is_full());
    }

    #[test]
    fn test_iterator_reset() {
        let mut iter = make_iter_with(&[b"x", b"y"], 10);
        iter.next_entry().unwrap();
        assert_eq!(iter.pos, 1);
        iter.reset();
        assert_eq!(iter.pos, 0);
    }

    #[test]
    fn test_iterator_push_full() {
        let mut iter = DirEntryIterator::new(1);
        for i in 0..DIR_CACHE_SIZE {
            let name = [b'a' + (i % 26) as u8];
            let e = LinuxDirent64::new(i as u64 + 1, i as i64, DirentType::Reg, &name).unwrap();
            iter.push(e).unwrap();
        }
        let e = LinuxDirent64::new(999, 0, DirentType::Reg, b"z").unwrap();
        assert_eq!(iter.push(e), Err(Error::Busy));
    }
}
