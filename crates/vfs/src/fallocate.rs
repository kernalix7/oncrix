// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fallocate(2)` — file space preallocation and manipulation.
//!
//! This module implements the kernel-side logic for the `fallocate`
//! system call, which allows user-space applications to manipulate
//! allocated disk space for a file without actually writing data.
//!
//! # Supported modes
//!
//! | Mode | Effect |
//! |------|--------|
//! | `0` (default) | Allocate space (ensure `[offset, offset+len)` is backed) |
//! | `KEEP_SIZE` | Allocate space without extending the file size |
//! | `PUNCH_HOLE` | Deallocate space (create a hole) — must combine with `KEEP_SIZE` |
//! | `COLLAPSE_RANGE` | Remove a range and shift subsequent data down |
//! | `ZERO_RANGE` | Zero a range without deallocating blocks |
//! | `INSERT_RANGE` | Insert a hole, shifting subsequent data up |
//! | `UNSHARE_RANGE` | Unshare shared extents (CoW breakup) |
//!
//! # Architecture
//!
//! ```text
//! sys_fallocate(fd, mode, offset, len)
//!   │
//!   ▼
//! do_fallocate()
//!   │
//!   ├── validate mode/offset/len
//!   ├── check file locks for conflicts
//!   │
//!   ├── mode == 0 ──────────────────► handle_allocate()
//!   ├── mode & PUNCH_HOLE ──────────► handle_punch_hole()
//!   ├── mode & COLLAPSE_RANGE ──────► handle_collapse_range()
//!   ├── mode & ZERO_RANGE ──────────► handle_zero_range()
//!   ├── mode & INSERT_RANGE ────────► handle_insert_range()
//!   └── mode & UNSHARE_RANGE ───────► handle_unshare_range()
//! ```
//!
//! # References
//!
//! - Linux `fs/open.c` — `do_fallocate()`
//! - Linux `include/uapi/linux/falloc.h` — mode flag definitions
//! - `man 2 fallocate`

use oncrix_lib::{Error, Result};

// ── FallocateMode — mode flag constants ─────────────────────────────────

/// `fallocate` mode flag: do not extend the file size even if the
/// allocated region exceeds the current EOF.
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;

/// `fallocate` mode flag: deallocate space (punch a hole).
/// Must be combined with `FALLOC_FL_KEEP_SIZE`.
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

/// `fallocate` mode flag: do not hide allocated but unwritten
/// extents (used by ext4 for `EXT4_IOC_ALLOC_DA_BLKS`).
pub const FALLOC_FL_NO_HIDE_STALE: u32 = 0x04;

/// `fallocate` mode flag: remove a byte range, collapsing the
/// file by shifting all data after the range downward.
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;

/// `fallocate` mode flag: zero a byte range. Blocks within the
/// range are converted to unwritten extents (or zeroed in place).
pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;

/// `fallocate` mode flag: insert a byte range of zeros, shifting
/// all data at and after the offset upward.
pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;

/// `fallocate` mode flag: break up shared (CoW) extents so each
/// file gets its own private copy of the blocks.
pub const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;

/// Bitmask of all valid fallocate mode flags.
pub const FALLOC_FL_ALL: u32 = FALLOC_FL_KEEP_SIZE
    | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_NO_HIDE_STALE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE;

// ── FallocateMode bitflags type ─────────────────────────────────────────

/// Parsed `fallocate` mode flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FallocateMode(pub u32);

impl FallocateMode {
    /// Create from a raw bitmask after validation.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !FALLOC_FL_ALL != 0 {
            return Err(Error::InvalidArgument);
        }
        // PUNCH_HOLE requires KEEP_SIZE.
        if raw & FALLOC_FL_PUNCH_HOLE != 0 && raw & FALLOC_FL_KEEP_SIZE == 0 {
            return Err(Error::InvalidArgument);
        }
        // COLLAPSE_RANGE is mutually exclusive with other flags.
        if raw & FALLOC_FL_COLLAPSE_RANGE != 0 && raw & !FALLOC_FL_COLLAPSE_RANGE != 0 {
            return Err(Error::InvalidArgument);
        }
        // INSERT_RANGE is mutually exclusive with other flags.
        if raw & FALLOC_FL_INSERT_RANGE != 0 && raw & !FALLOC_FL_INSERT_RANGE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Create a default (allocate) mode.
    pub const fn allocate() -> Self {
        Self(0)
    }

    /// Create a keep-size allocation mode.
    pub const fn keep_size() -> Self {
        Self(FALLOC_FL_KEEP_SIZE)
    }

    /// Create a punch-hole mode.
    pub const fn punch_hole() -> Self {
        Self(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)
    }

    /// Create a collapse-range mode.
    pub const fn collapse_range() -> Self {
        Self(FALLOC_FL_COLLAPSE_RANGE)
    }

    /// Create a zero-range mode.
    pub const fn zero_range() -> Self {
        Self(FALLOC_FL_ZERO_RANGE)
    }

    /// Create a zero-range-keep-size mode.
    pub const fn zero_range_keep_size() -> Self {
        Self(FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE)
    }

    /// Create an insert-range mode.
    pub const fn insert_range() -> Self {
        Self(FALLOC_FL_INSERT_RANGE)
    }

    /// Create an unshare-range mode.
    pub const fn unshare_range() -> Self {
        Self(FALLOC_FL_UNSHARE_RANGE)
    }

    /// Check whether `KEEP_SIZE` is set.
    pub fn keep_size_set(&self) -> bool {
        self.0 & FALLOC_FL_KEEP_SIZE != 0
    }

    /// Check whether `PUNCH_HOLE` is set.
    pub fn punch_hole_set(&self) -> bool {
        self.0 & FALLOC_FL_PUNCH_HOLE != 0
    }

    /// Check whether `COLLAPSE_RANGE` is set.
    pub fn collapse_range_set(&self) -> bool {
        self.0 & FALLOC_FL_COLLAPSE_RANGE != 0
    }

    /// Check whether `ZERO_RANGE` is set.
    pub fn zero_range_set(&self) -> bool {
        self.0 & FALLOC_FL_ZERO_RANGE != 0
    }

    /// Check whether `INSERT_RANGE` is set.
    pub fn insert_range_set(&self) -> bool {
        self.0 & FALLOC_FL_INSERT_RANGE != 0
    }

    /// Check whether `UNSHARE_RANGE` is set.
    pub fn unshare_range_set(&self) -> bool {
        self.0 & FALLOC_FL_UNSHARE_RANGE != 0
    }

    /// Check whether this is a plain allocation (no special flags).
    pub fn is_allocate(&self) -> bool {
        self.0 == 0
    }

    /// Return the raw flag bitmask.
    pub fn raw(&self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for FallocateMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_allocate() {
            return write!(f, "ALLOCATE");
        }
        let mut first = true;
        let mut flag = |name: &str, set: bool| -> core::fmt::Result {
            if set {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
            Ok(())
        };
        flag("KEEP_SIZE", self.keep_size_set())?;
        flag("PUNCH_HOLE", self.punch_hole_set())?;
        flag("COLLAPSE_RANGE", self.collapse_range_set())?;
        flag("ZERO_RANGE", self.zero_range_set())?;
        flag("INSERT_RANGE", self.insert_range_set())?;
        flag("UNSHARE_RANGE", self.unshare_range_set())?;
        Ok(())
    }
}

// ── FallocateRequest ────────────────────────────────────────────────────

/// A parsed `fallocate` request ready for dispatch.
#[derive(Debug, Clone, Copy)]
pub struct FallocateRequest {
    /// Target file descriptor.
    pub fd: i32,
    /// Validated mode flags.
    pub mode: FallocateMode,
    /// Starting byte offset.
    pub offset: u64,
    /// Length of the region in bytes.
    pub len: u64,
}

impl FallocateRequest {
    /// Create and validate a new fallocate request.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — invalid mode flags, or
    ///   offset/len would overflow, or len is zero, or fd is negative.
    pub fn new(fd: i32, mode: u32, offset: u64, len: u64) -> Result<Self> {
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for overflow.
        offset.checked_add(len).ok_or(Error::InvalidArgument)?;

        let mode = FallocateMode::from_raw(mode)?;
        Ok(Self {
            fd,
            mode,
            offset,
            len,
        })
    }

    /// Return the end offset (exclusive) of the region.
    pub fn end(&self) -> u64 {
        // Validated in `new()` — no overflow.
        self.offset + self.len
    }
}

// ── Extent tracking ─────────────────────────────────────────────────────

/// Maximum number of extents per file in the fallocate table.
const MAX_EXTENTS_PER_FILE: usize = 128;

/// Maximum number of files tracked by the fallocate subsystem.
const MAX_FALLOCATE_FILES: usize = 64;

/// Block size for extent alignment (4 KiB).
const BLOCK_SIZE: u64 = 4096;

/// An extent (contiguous region of allocated blocks) within a file.
#[derive(Debug, Clone, Copy)]
pub struct Extent {
    /// Logical byte offset of the extent start.
    pub offset: u64,
    /// Length of the extent in bytes.
    pub length: u64,
    /// Whether this extent is physically allocated.
    pub allocated: bool,
    /// Whether this extent has been written (vs. prealloc/unwritten).
    pub written: bool,
    /// Whether this extent is shared (CoW).
    pub shared: bool,
}

impl Extent {
    /// Create a new extent.
    pub const fn new(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            allocated: true,
            written: true,
            shared: false,
        }
    }

    /// Create an unwritten (preallocated) extent.
    pub const fn unwritten(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            allocated: true,
            written: false,
            shared: false,
        }
    }

    /// Create a hole (unallocated) extent.
    pub const fn hole(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            allocated: false,
            written: false,
            shared: false,
        }
    }

    /// End offset (exclusive).
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    /// Check whether this extent overlaps with `[off, off+len)`.
    pub fn overlaps(&self, off: u64, len: u64) -> bool {
        let other_end = off.saturating_add(len);
        self.offset < other_end && off < self.end()
    }
}

impl Default for Extent {
    fn default() -> Self {
        Self::hole(0, 0)
    }
}

// ── FileExtentMap — per-file extent tracking ────────────────────────────

/// Per-file extent map tracking allocated, unwritten, and hole regions.
pub struct FileExtentMap {
    /// Inode number of the file.
    pub inode: u64,
    /// Logical file size.
    pub size: u64,
    /// Extent array.
    extents: [Extent; MAX_EXTENTS_PER_FILE],
    /// Number of active extents.
    extent_count: usize,
    /// Whether this file slot is in use.
    pub in_use: bool,
}

impl FileExtentMap {
    /// Create an empty (inactive) file extent map.
    const fn empty() -> Self {
        Self {
            inode: 0,
            size: 0,
            extents: [Extent::hole(0, 0); MAX_EXTENTS_PER_FILE],
            extent_count: 0,
            in_use: false,
        }
    }

    /// Initialise for a new file with the given inode and size.
    pub fn init(&mut self, inode: u64, size: u64) {
        self.inode = inode;
        self.size = size;
        self.extent_count = 0;
        self.in_use = true;
    }

    /// Add an extent to the map.
    pub fn add_extent(&mut self, ext: Extent) -> Result<()> {
        if self.extent_count >= MAX_EXTENTS_PER_FILE {
            return Err(Error::OutOfMemory);
        }
        self.extents[self.extent_count] = ext;
        self.extent_count += 1;
        Ok(())
    }

    /// Return the number of extents.
    pub fn extent_count(&self) -> usize {
        self.extent_count
    }

    /// Get a shared reference to an extent by index.
    pub fn get_extent(&self, idx: usize) -> Option<&Extent> {
        if idx < self.extent_count {
            Some(&self.extents[idx])
        } else {
            None
        }
    }

    /// Find all extents overlapping `[offset, offset+len)`.
    ///
    /// Returns the number of matching extents copied into `out`.
    pub fn find_overlapping(&self, offset: u64, len: u64, out: &mut [Extent]) -> usize {
        let mut count = 0;
        for i in 0..self.extent_count {
            if count >= out.len() {
                break;
            }
            if self.extents[i].overlaps(offset, len) {
                out[count] = self.extents[i];
                count += 1;
            }
        }
        count
    }

    /// Check whether any extent in `[offset, offset+len)` is shared.
    pub fn has_shared_extents(&self, offset: u64, len: u64) -> bool {
        for i in 0..self.extent_count {
            if self.extents[i].overlaps(offset, len) && self.extents[i].shared {
                return true;
            }
        }
        false
    }

    /// Mark all extents in `[offset, offset+len)` as unshared.
    pub fn unshare_extents(&mut self, offset: u64, len: u64) {
        for i in 0..self.extent_count {
            if self.extents[i].overlaps(offset, len) {
                self.extents[i].shared = false;
            }
        }
    }

    /// Remove extents in `[offset, offset+len)` (punch hole).
    ///
    /// Extents fully within the range are marked as holes.
    /// Partial overlaps are split (if capacity allows).
    pub fn punch_extents(&mut self, offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        for i in 0..self.extent_count {
            let ext = &mut self.extents[i];
            if !ext.overlaps(offset, len) {
                continue;
            }
            if ext.offset >= offset && ext.end() <= end {
                // Fully contained — convert to hole.
                ext.allocated = false;
                ext.written = false;
            } else if ext.offset < offset && ext.end() > end {
                // Extent spans the punch range — split would be
                // needed. For simplicity, just mark unwritten.
                ext.written = false;
            } else if ext.offset < offset {
                // Overlaps at the end — truncate.
                ext.length = offset - ext.offset;
            } else {
                // Overlaps at the beginning — shift start.
                let shift = end - ext.offset;
                ext.offset = end;
                ext.length = ext.length.saturating_sub(shift);
            }
        }
    }

    /// Zero extents in `[offset, offset+len)`.
    pub fn zero_extents(&mut self, offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        for i in 0..self.extent_count {
            let ext = &mut self.extents[i];
            if ext.overlaps(offset, len) && ext.offset >= offset && ext.end() <= end {
                ext.written = false;
            }
        }
    }

    /// Collapse (remove) a range, shifting extents after it down.
    pub fn collapse_extents(&mut self, offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        // Remove extents fully within the range.
        let mut write_idx = 0;
        for read_idx in 0..self.extent_count {
            let ext = self.extents[read_idx];
            if ext.offset >= offset && ext.end() <= end {
                // Skip (removed).
                continue;
            }
            let mut shifted = ext;
            if shifted.offset >= end {
                shifted.offset -= len;
            }
            self.extents[write_idx] = shifted;
            write_idx += 1;
        }
        self.extent_count = write_idx;
        // Adjust file size.
        self.size = self.size.saturating_sub(len);
    }

    /// Insert a hole at `offset`, shifting extents at and after it up.
    pub fn insert_extent_gap(&mut self, offset: u64, len: u64) {
        for i in 0..self.extent_count {
            if self.extents[i].offset >= offset {
                self.extents[i].offset += len;
            }
        }
        self.size += len;
    }
}

// ── Lock conflict checking ──────────────────────────────────────────────

/// Maximum number of active file locks to check against.
const MAX_LOCK_CHECK: usize = 64;

/// Simplified file lock for conflict checking.
#[derive(Debug, Clone, Copy)]
pub struct FallocLock {
    /// Inode of the locked file.
    pub inode: u64,
    /// Lock owner PID.
    pub pid: u64,
    /// Start of the locked byte range.
    pub start: u64,
    /// Length of the locked range (0 = to EOF).
    pub len: u64,
    /// Whether this is an exclusive (write) lock.
    pub exclusive: bool,
}

impl FallocLock {
    /// End offset (exclusive). 0 len means to EOF (u64::MAX).
    fn end(&self) -> u64 {
        if self.len == 0 {
            u64::MAX
        } else {
            self.start.saturating_add(self.len)
        }
    }
}

/// Check whether a fallocate request conflicts with any lock in the
/// provided lock set.
///
/// Fallocate operations that modify file data (punch hole, collapse,
/// insert, zero range) conflict with exclusive locks held by other
/// PIDs on overlapping ranges.
///
/// Plain allocation and keep-size allocation do not conflict because
/// they do not modify existing data.
pub fn check_lock_conflict(
    req: &FallocateRequest,
    inode: u64,
    caller_pid: u64,
    locks: &[FallocLock],
) -> Result<()> {
    // Allocate-only modes do not conflict with locks.
    if req.mode.is_allocate() || req.mode.raw() == FALLOC_FL_KEEP_SIZE {
        return Ok(());
    }

    let req_end = req.end();
    for lock in locks {
        if lock.inode != inode {
            continue;
        }
        if lock.pid == caller_pid {
            continue;
        }
        if !lock.exclusive {
            continue;
        }
        // Check range overlap.
        let lock_end = lock.end();
        if req.offset < lock_end && lock.start < req_end {
            return Err(Error::Busy);
        }
    }
    Ok(())
}

// ── FallocateContext — main dispatch engine ──────────────────────────────

/// Global context for fallocate operations.
///
/// Manages file extent maps and dispatches fallocate requests to
/// the appropriate per-mode handler.
pub struct FallocateContext {
    /// Per-file extent maps.
    files: [FileExtentMap; MAX_FALLOCATE_FILES],
    /// Lock set for conflict checking.
    locks: [Option<FallocLock>; MAX_LOCK_CHECK],
    /// Number of active locks.
    lock_count: usize,
    /// Statistics: total fallocate calls.
    pub total_calls: u64,
    /// Statistics: total bytes allocated.
    pub total_allocated: u64,
    /// Statistics: total bytes punched.
    pub total_punched: u64,
    /// Statistics: total bytes zeroed.
    pub total_zeroed: u64,
}

impl FallocateContext {
    /// Create a new, empty context.
    pub const fn new() -> Self {
        const NONE_LOCK: Option<FallocLock> = None;
        Self {
            files: [const { FileExtentMap::empty() }; MAX_FALLOCATE_FILES],
            locks: [NONE_LOCK; MAX_LOCK_CHECK],
            lock_count: 0,
            total_calls: 0,
            total_allocated: 0,
            total_punched: 0,
            total_zeroed: 0,
        }
    }

    // ── File management ─────────────────────────────────────────────

    /// Register a file for fallocate tracking.
    pub fn register_file(&mut self, inode: u64, size: u64) -> Result<usize> {
        for (idx, f) in self.files.iter_mut().enumerate() {
            if !f.in_use {
                f.init(inode, size);
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a file.
    pub fn unregister_file(&mut self, idx: usize) -> Result<()> {
        let f = self.files.get_mut(idx).ok_or(Error::InvalidArgument)?;
        if !f.in_use {
            return Err(Error::NotFound);
        }
        *f = FileExtentMap::empty();
        Ok(())
    }

    /// Find a file by inode number.
    pub fn find_file(&self, inode: u64) -> Option<usize> {
        for (idx, f) in self.files.iter().enumerate() {
            if f.in_use && f.inode == inode {
                return Some(idx);
            }
        }
        None
    }

    /// Get a shared reference to a file extent map.
    pub fn get_file(&self, idx: usize) -> Option<&FileExtentMap> {
        let f = self.files.get(idx)?;
        if f.in_use { Some(f) } else { None }
    }

    /// Get a mutable reference to a file extent map.
    pub fn get_file_mut(&mut self, idx: usize) -> Option<&mut FileExtentMap> {
        let f = self.files.get_mut(idx)?;
        if f.in_use { Some(f) } else { None }
    }

    // ── Lock management ─────────────────────────────────────────────

    /// Add a lock for conflict checking.
    pub fn add_lock(&mut self, lock: FallocLock) -> Result<()> {
        if self.lock_count >= MAX_LOCK_CHECK {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.locks {
            if slot.is_none() {
                *slot = Some(lock);
                self.lock_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove all locks for a given PID.
    pub fn remove_locks(&mut self, pid: u64) {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.pid == pid {
                    *slot = None;
                    self.lock_count = self.lock_count.saturating_sub(1);
                }
            }
        }
    }

    /// Collect active locks into a flat slice for conflict checking.
    fn collect_locks(&self, out: &mut [FallocLock]) -> usize {
        let mut count = 0;
        for slot in &self.locks {
            if count >= out.len() {
                break;
            }
            if let Some(lock) = slot {
                out[count] = *lock;
                count += 1;
            }
        }
        count
    }

    // ── Main dispatch ───────────────────────────────────────────────

    /// Execute a `fallocate` request.
    ///
    /// Validates the request, checks for lock conflicts, and
    /// dispatches to the appropriate per-mode handler.
    ///
    /// # Arguments
    ///
    /// - `req` — the validated fallocate request
    /// - `inode` — inode of the target file
    /// - `caller_pid` — PID of the calling process
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — bad request parameters
    /// - [`Error::NotFound`] — file not registered
    /// - [`Error::Busy`] — conflicting lock exists
    /// - [`Error::OutOfMemory`] — no space for new extents
    pub fn do_fallocate(
        &mut self,
        req: &FallocateRequest,
        inode: u64,
        caller_pid: u64,
    ) -> Result<u64> {
        // Find the file.
        let file_idx = self.find_file(inode).ok_or(Error::NotFound)?;

        // Check lock conflicts.
        let mut lock_buf = [FallocLock {
            inode: 0,
            pid: 0,
            start: 0,
            len: 0,
            exclusive: false,
        }; MAX_LOCK_CHECK];
        let nlock = self.collect_locks(&mut lock_buf);
        check_lock_conflict(req, inode, caller_pid, &lock_buf[..nlock])?;

        self.total_calls += 1;

        // Dispatch by mode.
        if req.mode.is_allocate() {
            self.handle_allocate(file_idx, req)
        } else if req.mode.punch_hole_set() {
            self.handle_punch_hole(file_idx, req)
        } else if req.mode.collapse_range_set() {
            self.handle_collapse_range(file_idx, req)
        } else if req.mode.zero_range_set() {
            self.handle_zero_range(file_idx, req)
        } else if req.mode.insert_range_set() {
            self.handle_insert_range(file_idx, req)
        } else if req.mode.unshare_range_set() {
            self.handle_unshare_range(file_idx, req)
        } else if req.mode.keep_size_set() {
            // Pure KEEP_SIZE without other flags = allocate w/o
            // extending size.
            self.handle_allocate_keep_size(file_idx, req)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    // ── Per-mode handlers ───────────────────────────────────────────

    /// Default allocation: ensure `[offset, offset+len)` is backed
    /// by allocated blocks. Extends the file size if the range
    /// exceeds the current EOF.
    fn handle_allocate(&mut self, file_idx: usize, req: &FallocateRequest) -> Result<u64> {
        let file = &mut self.files[file_idx];
        let alloc_end = req.end();

        // Align to block boundaries.
        let aligned_offset = req.offset & !(BLOCK_SIZE - 1);
        let aligned_end = (alloc_end + BLOCK_SIZE - 1) & !(BLOCK_SIZE - 1);
        let aligned_len = aligned_end - aligned_offset;

        // Add an unwritten extent for the allocated region.
        file.add_extent(Extent::unwritten(aligned_offset, aligned_len))?;

        // Extend file size if needed.
        if alloc_end > file.size {
            file.size = alloc_end;
        }

        self.total_allocated += aligned_len;
        Ok(aligned_len)
    }

    /// Allocate without extending the file size (`KEEP_SIZE`).
    fn handle_allocate_keep_size(
        &mut self,
        file_idx: usize,
        req: &FallocateRequest,
    ) -> Result<u64> {
        let file = &mut self.files[file_idx];

        let aligned_offset = req.offset & !(BLOCK_SIZE - 1);
        let aligned_end = (req.end() + BLOCK_SIZE - 1) & !(BLOCK_SIZE - 1);
        let aligned_len = aligned_end - aligned_offset;

        file.add_extent(Extent::unwritten(aligned_offset, aligned_len))?;

        // Do NOT extend file size.
        self.total_allocated += aligned_len;
        Ok(aligned_len)
    }

    /// Punch a hole: deallocate blocks in `[offset, offset+len)`.
    /// The file size is not changed (requires `KEEP_SIZE`).
    fn handle_punch_hole(&mut self, file_idx: usize, req: &FallocateRequest) -> Result<u64> {
        let file = &mut self.files[file_idx];

        // Punch must not extend beyond current file size.
        let punch_end = req.end().min(file.size);
        if req.offset >= punch_end {
            return Ok(0);
        }
        let punch_len = punch_end - req.offset;

        file.punch_extents(req.offset, punch_len);

        self.total_punched += punch_len;
        Ok(punch_len)
    }

    /// Collapse a range: remove `[offset, offset+len)` and shift
    /// all subsequent data down. Both offset and len must be
    /// block-aligned.
    fn handle_collapse_range(&mut self, file_idx: usize, req: &FallocateRequest) -> Result<u64> {
        // Alignment check.
        if req.offset % BLOCK_SIZE != 0 || req.len % BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let file = &mut self.files[file_idx];

        // Range must not extend beyond EOF.
        if req.end() > file.size {
            return Err(Error::InvalidArgument);
        }

        file.collapse_extents(req.offset, req.len);
        Ok(req.len)
    }

    /// Zero a range: convert `[offset, offset+len)` to unwritten
    /// extents (data reads as zeros). Optionally extend the file
    /// if `KEEP_SIZE` is not set.
    fn handle_zero_range(&mut self, file_idx: usize, req: &FallocateRequest) -> Result<u64> {
        let file = &mut self.files[file_idx];

        file.zero_extents(req.offset, req.len);

        // Add an unwritten extent covering the zeroed range.
        let aligned_offset = req.offset & !(BLOCK_SIZE - 1);
        let aligned_end = (req.end() + BLOCK_SIZE - 1) & !(BLOCK_SIZE - 1);
        file.add_extent(Extent::unwritten(
            aligned_offset,
            aligned_end - aligned_offset,
        ))?;

        if !req.mode.keep_size_set() && req.end() > file.size {
            file.size = req.end();
        }

        self.total_zeroed += req.len;
        Ok(req.len)
    }

    /// Insert a range: insert `len` bytes of zeros at `offset`,
    /// shifting all data at and after offset upward. Both offset
    /// and len must be block-aligned.
    fn handle_insert_range(&mut self, file_idx: usize, req: &FallocateRequest) -> Result<u64> {
        // Alignment check.
        if req.offset % BLOCK_SIZE != 0 || req.len % BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let file = &mut self.files[file_idx];

        // Offset must be within the current file.
        if req.offset > file.size {
            return Err(Error::InvalidArgument);
        }

        file.insert_extent_gap(req.offset, req.len);
        self.total_allocated += req.len;
        Ok(req.len)
    }

    /// Unshare shared extents: break CoW sharing in `[offset, len)`.
    fn handle_unshare_range(&mut self, file_idx: usize, req: &FallocateRequest) -> Result<u64> {
        let file = &mut self.files[file_idx];

        if !file.has_shared_extents(req.offset, req.len) {
            // Nothing to unshare — success with 0 bytes affected.
            return Ok(0);
        }

        file.unshare_extents(req.offset, req.len);
        Ok(req.len)
    }

    /// Count active file registrations.
    pub fn active_files(&self) -> usize {
        self.files.iter().filter(|f| f.in_use).count()
    }
}

impl Default for FallocateContext {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for FallocateContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FallocateContext")
            .field("active_files", &self.active_files())
            .field("total_calls", &self.total_calls)
            .field("total_allocated", &self.total_allocated)
            .field("total_punched", &self.total_punched)
            .field("total_zeroed", &self.total_zeroed)
            .finish()
    }
}

// ── Global singleton ────────────────────────────────────────────────────

static mut FALLOCATE_CTX: FallocateContext = FallocateContext::new();

/// Initialise the global fallocate context.
///
/// # Safety
///
/// Must be called once during single-threaded kernel initialisation.
pub unsafe fn fallocate_init() {
    // SAFETY: Single-threaded init; no concurrent access.
    unsafe {
        *core::ptr::addr_of_mut!(FALLOCATE_CTX) = FallocateContext::new();
    }
}

/// Obtain a shared reference to the global fallocate context.
pub fn fallocate_ctx() -> &'static FallocateContext {
    // SAFETY: Read-only after init; never moved.
    unsafe { &*core::ptr::addr_of!(FALLOCATE_CTX) }
}

/// Obtain a mutable reference to the global fallocate context.
///
/// # Safety
///
/// Caller must ensure no other reference is live.
pub unsafe fn fallocate_ctx_mut() -> &'static mut FallocateContext {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { &mut *core::ptr::addr_of_mut!(FALLOCATE_CTX) }
}

// ── Convenience wrappers ────────────────────────────────────────────────

/// Top-level `fallocate` entry point.
///
/// Parses the raw syscall arguments, constructs a [`FallocateRequest`],
/// and dispatches via the global [`FallocateContext`].
///
/// # Safety
///
/// Caller must ensure exclusive access to the global context.
pub unsafe fn sys_fallocate(
    fd: i32,
    mode: u32,
    offset: u64,
    len: u64,
    inode: u64,
    pid: u64,
) -> Result<u64> {
    let req = FallocateRequest::new(fd, mode, offset, len)?;
    // SAFETY: Caller ensures exclusive access.
    let ctx = unsafe { fallocate_ctx_mut() };
    ctx.do_fallocate(&req, inode, pid)
}
