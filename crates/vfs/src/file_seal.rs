// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File sealing (`F_ADD_SEALS` / `F_GET_SEALS`).
//!
//! File seals are one-way restrictions attached to a file descriptor (typically
//! a `memfd`).  Once a seal is added it cannot be removed, and each seal
//! restricts a different class of modification:
//!
//! | Seal | Constant | Effect |
//! |------|----------|--------|
//! | `SEAL_SEAL`   | `F_SEAL_SEAL`   | No more seals can be added |
//! | `SEAL_SHRINK` | `F_SEAL_SHRINK` | `ftruncate` cannot reduce the file size |
//! | `SEAL_GROW`   | `F_SEAL_GROW`   | `ftruncate` / `write` cannot increase the file size |
//! | `SEAL_WRITE`  | `F_SEAL_WRITE`  | `write` and `mmap(PROT_WRITE,MAP_SHARED)` are blocked |
//! | `SEAL_FUTURE_WRITE` | `F_SEAL_FUTURE_WRITE` | Future write-mappings are blocked |
//!
//! # Usage pattern (memfd)
//!
//! ```text
//! fd = memfd_create("name", MFD_ALLOW_SEALING)
//! write(fd, data, len)
//! fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)
//! // fd can now be safely shared — no further mutations possible
//! ```
//!
//! # References
//!
//! - Linux `memfd_create(2)`, `fcntl(2)` — `F_ADD_SEALS`/`F_GET_SEALS`
//! - POSIX.1-2024 `fcntl()` (no seal extension yet — Linux-specific)

use oncrix_lib::{Error, Result};

// ── Seal bitmask constants ─────────────────────────────────────────────────

/// Prevent further seals from being added to the file.
pub const F_SEAL_SEAL: u32 = 0x0001;

/// Prevent the file from being shrunk with `ftruncate`.
pub const F_SEAL_SHRINK: u32 = 0x0002;

/// Prevent the file from being grown with `ftruncate` or `write`.
pub const F_SEAL_GROW: u32 = 0x0004;

/// Prevent any writes to the file (blocks `write(2)` and
/// `mmap(PROT_WRITE | MAP_SHARED)`).
pub const F_SEAL_WRITE: u32 = 0x0008;

/// Prevent future `mmap(PROT_WRITE | MAP_SHARED)` mappings while
/// still allowing existing write mappings.
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;

/// All defined seal bits (mask for validation).
pub const F_SEAL_ALL: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

// ── memfd_create flags ─────────────────────────────────────────────────────

/// Allow seals to be added to the `memfd` file descriptor.
pub const MFD_ALLOW_SEALING: u32 = 0x0002;

/// Create a huge-page backed `memfd` (hint only).
pub const MFD_HUGETLB: u32 = 0x0004;

// ── SealSet — the per-file seal state ──────────────────────────────────────

/// Tracks the set of seals applied to a single file.
///
/// Seals are monotonically accumulated; bits are never cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SealSet {
    /// Active seal bitmask.
    bits: u32,
}

impl SealSet {
    /// Create a new, empty seal set (no seals applied).
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Return the raw bitmask of active seals.
    #[inline]
    pub fn get(&self) -> u32 {
        self.bits
    }

    /// Return `true` if the given seal bit(s) are all active.
    #[inline]
    pub fn has(&self, seal: u32) -> bool {
        self.bits & seal == seal
    }

    /// Attempt to add one or more seals.
    ///
    /// Returns `Err(PermissionDenied)` if `F_SEAL_SEAL` is already active.
    /// Returns `Err(InvalidArgument)` if `seals` contains unknown bits.
    pub fn add(&mut self, seals: u32) -> Result<()> {
        if seals & !F_SEAL_ALL != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.has(F_SEAL_SEAL) {
            return Err(Error::PermissionDenied);
        }
        self.bits |= seals;
        Ok(())
    }

    /// Check whether a `write` of `count` bytes at the current file size
    /// `current_size` is permitted.
    ///
    /// - `F_SEAL_WRITE` blocks all writes.
    /// - `F_SEAL_GROW` blocks writes that extend the file beyond `current_size`.
    pub fn check_write(&self, current_size: u64, write_end: u64) -> Result<()> {
        if self.has(F_SEAL_WRITE) {
            return Err(Error::PermissionDenied);
        }
        if self.has(F_SEAL_GROW) && write_end > current_size {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Check whether `ftruncate(new_size)` is permitted given `current_size`.
    ///
    /// - `F_SEAL_SHRINK` blocks size reductions.
    /// - `F_SEAL_GROW`   blocks size increases.
    pub fn check_truncate(&self, current_size: u64, new_size: u64) -> Result<()> {
        if new_size < current_size && self.has(F_SEAL_SHRINK) {
            return Err(Error::PermissionDenied);
        }
        if new_size > current_size && self.has(F_SEAL_GROW) {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Check whether adding a `PROT_WRITE | MAP_SHARED` mapping is permitted.
    ///
    /// - `F_SEAL_WRITE` blocks the mapping unconditionally.
    /// - `F_SEAL_FUTURE_WRITE` blocks new write-shared mappings.
    pub fn check_mmap_write_shared(&self) -> Result<()> {
        if self.has(F_SEAL_WRITE) || self.has(F_SEAL_FUTURE_WRITE) {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }
}

// ── SealedFile — a memfd-style file with seal support ─────────────────────

/// Maximum number of simultaneously open sealed files.
pub const MAX_SEALED_FILES: usize = 256;

/// Name length limit for `memfd_create`.
pub const MEMFD_NAME_MAX: usize = 249;

/// Inline content buffer for a sealed file.
///
/// In a real kernel this would be backed by anonymous pages; here we
/// use a fixed-size buffer to stay `no_std` / allocation-free.
pub const SEALED_FILE_DATA_MAX: usize = 65536;

/// A single memfd-style file with sealing support.
#[derive(Debug)]
pub struct SealedFile {
    /// Human-readable name (set at `memfd_create` time, for debugging only).
    name: [u8; MEMFD_NAME_MAX],
    name_len: usize,

    /// File contents (fixed-size inline buffer).
    data: [u8; SEALED_FILE_DATA_MAX],

    /// Logical file size (≤ `SEALED_FILE_DATA_MAX`).
    size: usize,

    /// Active seal bitmask.
    seals: SealSet,

    /// Whether sealing is enabled for this file (`MFD_ALLOW_SEALING`).
    sealing_allowed: bool,

    /// File is open / in use.
    in_use: bool,
}

impl SealedFile {
    const fn empty() -> Self {
        Self {
            name: [0u8; MEMFD_NAME_MAX],
            name_len: 0,
            data: [0u8; SEALED_FILE_DATA_MAX],
            size: 0,
            seals: SealSet::new(),
            sealing_allowed: false,
            in_use: false,
        }
    }

    /// Initialise as a newly created memfd.
    pub fn init(&mut self, name: &[u8], flags: u32) {
        let copy_len = name.len().min(MEMFD_NAME_MAX);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;
        self.data = [0u8; SEALED_FILE_DATA_MAX];
        self.size = 0;
        self.seals = SealSet::new();
        self.sealing_allowed = flags & MFD_ALLOW_SEALING != 0;
        self.in_use = true;
    }

    /// Return the active seal bitmask (`F_GET_SEALS`).
    pub fn get_seals(&self) -> Result<u32> {
        if !self.sealing_allowed {
            return Err(Error::InvalidArgument);
        }
        Ok(self.seals.get())
    }

    /// Add seals (`F_ADD_SEALS`).
    pub fn add_seals(&mut self, seals: u32) -> Result<()> {
        if !self.sealing_allowed {
            return Err(Error::InvalidArgument);
        }
        self.seals.add(seals)
    }

    /// Write `buf` at `offset`.
    pub fn write(&mut self, offset: usize, buf: &[u8]) -> Result<usize> {
        let write_end = offset
            .checked_add(buf.len())
            .ok_or(Error::InvalidArgument)?;
        if write_end > SEALED_FILE_DATA_MAX {
            return Err(Error::InvalidArgument);
        }
        self.seals.check_write(self.size as u64, write_end as u64)?;
        self.data[offset..write_end].copy_from_slice(buf);
        if write_end > self.size {
            self.size = write_end;
        }
        Ok(buf.len())
    }

    /// Read `buf.len()` bytes from `offset`.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let available = self.size - offset;
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&self.data[offset..offset + to_copy]);
        Ok(to_copy)
    }

    /// Truncate (or extend) the file to `new_size`.
    pub fn truncate(&mut self, new_size: usize) -> Result<()> {
        if new_size > SEALED_FILE_DATA_MAX {
            return Err(Error::InvalidArgument);
        }
        self.seals
            .check_truncate(self.size as u64, new_size as u64)?;
        if new_size > self.size {
            // Zero-fill the gap.
            self.data[self.size..new_size].fill(0);
        }
        self.size = new_size;
        Ok(())
    }

    /// Return the current file size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the file name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── FileSealTable — global table of sealed files ───────────────────────────

/// Global table of sealed (memfd) files.
pub struct FileSealTable {
    files: [SealedFile; MAX_SEALED_FILES],
}

impl FileSealTable {
    const fn new() -> Self {
        // SAFETY: SealedFile is fully initialised by `empty()`.
        #[allow(clippy::declare_interior_mutable_const)]
        const EMPTY: SealedFile = SealedFile::empty();
        Self {
            files: [EMPTY; MAX_SEALED_FILES],
        }
    }

    /// Allocate a new sealed file; returns the slot index (used as fd key).
    pub fn create(&mut self, name: &[u8], flags: u32) -> Result<usize> {
        for (idx, slot) in self.files.iter_mut().enumerate() {
            if !slot.in_use {
                slot.init(name, flags);
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Release a sealed file slot.
    pub fn close(&mut self, idx: usize) -> Result<()> {
        let slot = self.files.get_mut(idx).ok_or(Error::InvalidArgument)?;
        if !slot.in_use {
            return Err(Error::NotFound);
        }
        slot.in_use = false;
        Ok(())
    }

    /// Return a shared reference to a sealed file by index.
    pub fn get(&self, idx: usize) -> Option<&SealedFile> {
        let f = self.files.get(idx)?;
        if f.in_use { Some(f) } else { None }
    }

    /// Return a mutable reference to a sealed file by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut SealedFile> {
        let f = self.files.get_mut(idx)?;
        if f.in_use { Some(f) } else { None }
    }

    /// `F_GET_SEALS` — return active seal bitmask for file at `idx`.
    pub fn fcntl_get_seals(&self, idx: usize) -> Result<u32> {
        self.get(idx).ok_or(Error::NotFound)?.get_seals()
    }

    /// `F_ADD_SEALS` — add seals to the file at `idx`.
    pub fn fcntl_add_seals(&mut self, idx: usize, seals: u32) -> Result<()> {
        self.get_mut(idx).ok_or(Error::NotFound)?.add_seals(seals)
    }
}

// ── Global singleton ───────────────────────────────────────────────────────

static mut FILE_SEAL_TABLE: Option<FileSealTable> = None;

/// Initialise the global `FileSealTable`.
///
/// # Safety
///
/// Must be called exactly once during VFS initialisation, before any
/// concurrent access.
pub unsafe fn file_seal_init() {
    // SAFETY: called once during single-threaded init.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(FILE_SEAL_TABLE);
        (*ptr) = Some(FileSealTable::new());
    }
}

/// Return a shared reference to the global `FileSealTable`.
pub fn file_seal_table() -> Option<&'static FileSealTable> {
    // SAFETY: initialised by `file_seal_init` before use.
    unsafe { (*core::ptr::addr_of!(FILE_SEAL_TABLE)).as_ref() }
}

/// Return a mutable reference to the global `FileSealTable`.
///
/// # Safety
///
/// The caller must ensure no other concurrent access to the table.
pub unsafe fn file_seal_table_mut() -> Option<&'static mut FileSealTable> {
    // SAFETY: caller ensures exclusive access.
    unsafe { (*core::ptr::addr_of_mut!(FILE_SEAL_TABLE)).as_mut() }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> FileSealTable {
        FileSealTable::new()
    }

    #[test]
    fn seal_set_basics() {
        let mut s = SealSet::new();
        assert_eq!(s.get(), 0);
        s.add(F_SEAL_SHRINK | F_SEAL_GROW).unwrap();
        assert!(s.has(F_SEAL_SHRINK));
        assert!(s.has(F_SEAL_GROW));
        assert!(!s.has(F_SEAL_WRITE));
    }

    #[test]
    fn seal_seal_prevents_more_seals() {
        let mut s = SealSet::new();
        s.add(F_SEAL_SEAL).unwrap();
        assert!(s.add(F_SEAL_WRITE).is_err());
    }

    #[test]
    fn invalid_seal_bits_rejected() {
        let mut s = SealSet::new();
        assert!(s.add(0x8000).is_err());
    }

    #[test]
    fn write_blocked_by_seal_write() {
        let mut t = make_table();
        let idx = t.create(b"test", MFD_ALLOW_SEALING).unwrap();
        t.fcntl_add_seals(idx, F_SEAL_WRITE).unwrap();
        let f = t.get_mut(idx).unwrap();
        assert!(f.write(0, b"hello").is_err());
    }

    #[test]
    fn grow_blocked_by_seal_grow() {
        let mut t = make_table();
        let idx = t.create(b"grow", MFD_ALLOW_SEALING).unwrap();
        {
            let f = t.get_mut(idx).unwrap();
            f.write(0, b"initial").unwrap();
        }
        t.fcntl_add_seals(idx, F_SEAL_GROW).unwrap();
        let f = t.get_mut(idx).unwrap();
        // Writing within existing range is allowed.
        f.write(0, b"replace").unwrap();
        // Growing beyond current size is blocked.
        assert!(f.write(0, b"this is longer than initial").is_err());
    }

    #[test]
    fn truncate_blocked_by_seals() {
        let mut t = make_table();
        let idx = t.create(b"trunc", MFD_ALLOW_SEALING).unwrap();
        {
            let f = t.get_mut(idx).unwrap();
            f.write(0, b"hello world").unwrap();
        }
        t.fcntl_add_seals(idx, F_SEAL_SHRINK | F_SEAL_GROW).unwrap();
        let f = t.get_mut(idx).unwrap();
        let sz = f.size();
        assert!(f.truncate(sz - 1).is_err()); // shrink blocked
        assert!(f.truncate(sz + 1).is_err()); // grow blocked
        assert!(f.truncate(sz).is_ok()); // same size ok
    }

    #[test]
    fn get_seals_requires_mfd_allow_sealing() {
        let mut t = make_table();
        let idx = t.create(b"noseals", 0).unwrap();
        assert!(t.fcntl_get_seals(idx).is_err());
    }

    #[test]
    fn read_write_round_trip() {
        let mut t = make_table();
        let idx = t.create(b"rw", MFD_ALLOW_SEALING).unwrap();
        let f = t.get_mut(idx).unwrap();
        f.write(0, b"hello").unwrap();
        let mut buf = [0u8; 5];
        let n = f.read(0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }
}
