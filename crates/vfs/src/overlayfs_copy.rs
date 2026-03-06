// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OverlayFS copy-up mechanism.
//!
//! When a process modifies a file that lives only in a lower (read-only) layer
//! of an overlay mount, the file must first be *copied up* to the upper
//! (writable) layer.  This module provides the copy-up state machine, progress
//! tracking, and flag-based copy control.
//!
//! # Copy-up pipeline
//!
//! ```text
//! Lower layer (RO)          Upper layer (RW)
//! ┌─────────────┐           ┌──────────────┐
//! │ source file  │──copy──►│ work/.tmp_ino │──rename──►│ upper/file │
//! │ (inode, data,│  data    │ (staging)     │ atomic    │ (final)    │
//! │  xattr, mode)│          └──────────────┘           └────────────┘
//! └─────────────┘
//! ```
//!
//! # Features
//!
//! - **Full copy-up** — data + metadata + xattrs copied atomically.
//! - **Metacopy** — metadata-only copy; data reads fall through to lower layer
//!   until the first write triggers data promotion.
//! - **Progress tracking** — per-operation byte-level progress for large files.
//! - **Interruptible** — operations can be paused and resumed across context
//!   switches.
//!
//! # Reference
//!
//! Linux `fs/overlayfs/copy_up.c`, `fs/overlayfs/ovl_entry.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum path component length for overlay entries.
const MAX_NAME_LEN: usize = 255;

/// Maximum number of xattr pairs carried during copy-up.
const MAX_XATTR_PAIRS: usize = 16;

/// Maximum xattr name length.
const MAX_XATTR_NAME: usize = 128;

/// Maximum xattr value length.
const MAX_XATTR_VALUE: usize = 256;

/// Maximum number of tracked copy-up entries in a context.
const MAX_ENTRIES: usize = 128;

/// Default block size for chunked copy progress.
const DEFAULT_BLOCK_SIZE: u64 = 4096;

/// Maximum file size supported for in-kernel copy-up (64 MiB).
const MAX_COPY_SIZE: u64 = 64 * 1024 * 1024;

// ── CopyUpState ───────────────────────────────────────────────────────────────

/// The phase of a copy-up operation.
///
/// State transitions follow a linear pipeline:
/// `Idle` -> `Preparing` -> `CopyingData` -> `CopyingMeta` -> `Committing`
/// -> `Done`.  Any phase can transition to `Failed` on error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyUpState {
    /// Slot is unused.
    Idle,
    /// Gathering metadata from the lower inode.
    Preparing,
    /// File data is being copied block-by-block.
    CopyingData,
    /// Metadata (mode, timestamps, xattrs) is being reproduced.
    CopyingMeta,
    /// Atomic rename from staging area to upper layer in progress.
    Committing,
    /// Copy-up completed successfully.
    Done,
    /// Copy-up failed; entry is available for retry.
    Failed,
}

// ── CopyUpFlags ───────────────────────────────────────────────────────────────

/// Bit flags controlling copy-up behaviour.
///
/// Multiple flags can be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyUpFlags(u32);

impl CopyUpFlags {
    /// No special behaviour.
    pub const NONE: Self = Self(0);
    /// Perform metadata-only copy (defer data).
    pub const METACOPY: Self = Self(1 << 0);
    /// Preserve POSIX ACLs during copy.
    pub const PRESERVE_ACL: Self = Self(1 << 1);
    /// Preserve security xattrs (e.g., SELinux labels).
    pub const PRESERVE_SECURITY: Self = Self(1 << 2);
    /// Use direct I/O for data copy (bypass page cache).
    pub const DIRECT_IO: Self = Self(1 << 3);
    /// Skip capability xattrs during copy.
    pub const SKIP_CAPS: Self = Self(1 << 4);
    /// Force synchronous data flush after copy.
    pub const SYNC_DATA: Self = Self(1 << 5);

    /// Create flags from a raw u32 value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw u32 value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Check whether a particular flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ── CopyProgress ──────────────────────────────────────────────────────────────

/// Tracks byte-level progress for a copy-up operation on a large file.
///
/// The copy proceeds in `block_size`-byte chunks.  The progress structure
/// allows the operation to be paused and resumed.
#[derive(Debug, Clone, Copy)]
pub struct CopyProgress {
    /// Total file size in bytes.
    pub total_bytes: u64,
    /// Number of bytes successfully copied so far.
    pub copied_bytes: u64,
    /// Block size for chunked copy (typically 4096).
    pub block_size: u64,
    /// Number of blocks completed.
    pub blocks_done: u64,
    /// Total blocks needed (ceil(total_bytes / block_size)).
    pub blocks_total: u64,
    /// Whether the copy has been paused for resumption.
    pub paused: bool,
    /// Last error code if the copy stalled.
    pub last_error: Option<Error>,
}

impl CopyProgress {
    /// Create a new progress tracker for a file of the given size.
    pub fn new(total_bytes: u64, block_size: u64) -> Result<Self> {
        if block_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if total_bytes > MAX_COPY_SIZE {
            return Err(Error::InvalidArgument);
        }
        let blocks_total = (total_bytes + block_size - 1) / block_size;
        Ok(Self {
            total_bytes,
            copied_bytes: 0,
            block_size,
            blocks_done: 0,
            blocks_total,
            paused: false,
            last_error: None,
        })
    }

    /// Create a zero-sized progress (for metadata-only copy).
    pub const fn zero() -> Self {
        Self {
            total_bytes: 0,
            copied_bytes: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            blocks_done: 0,
            blocks_total: 0,
            paused: false,
            last_error: None,
        }
    }

    /// Record that `n` bytes were successfully copied.
    pub fn advance(&mut self, n: u64) {
        self.copied_bytes = self.copied_bytes.saturating_add(n);
        self.blocks_done = self.copied_bytes / self.block_size;
    }

    /// Return the percentage complete (0..=100).
    pub fn percent(&self) -> u8 {
        if self.total_bytes == 0 {
            return 100;
        }
        let pct = (self.copied_bytes * 100) / self.total_bytes;
        pct.min(100) as u8
    }

    /// Return whether the copy is finished.
    pub fn is_complete(&self) -> bool {
        self.copied_bytes >= self.total_bytes
    }

    /// Pause the copy for later resumption.
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume a paused copy.
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Record a copy error.
    pub fn set_error(&mut self, err: Error) {
        self.last_error = Some(err);
    }

    /// Return the byte offset where the next copy should resume.
    pub fn resume_offset(&self) -> u64 {
        self.copied_bytes
    }

    /// Return how many bytes remain.
    pub fn remaining(&self) -> u64 {
        self.total_bytes.saturating_sub(self.copied_bytes)
    }
}

// ── XattrPair ─────────────────────────────────────────────────────────────────

/// A single extended attribute name-value pair to be copied.
#[derive(Clone, Copy)]
struct XattrPair {
    name: [u8; MAX_XATTR_NAME],
    name_len: usize,
    value: [u8; MAX_XATTR_VALUE],
    value_len: usize,
}

impl XattrPair {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_XATTR_NAME],
            name_len: 0,
            value: [0u8; MAX_XATTR_VALUE],
            value_len: 0,
        }
    }

    fn set(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        if name.len() > MAX_XATTR_NAME || value.len() > MAX_XATTR_VALUE {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        self.value[..value.len()].copy_from_slice(value);
        self.value_len = value.len();
        Ok(())
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

impl core::fmt::Debug for XattrPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XattrPair")
            .field("name_len", &self.name_len)
            .field("value_len", &self.value_len)
            .finish()
    }
}

// ── OverlayEntry ──────────────────────────────────────────────────────────────

/// An overlay entry undergoing or awaiting copy-up.
///
/// Represents a single file or directory in a lower layer that needs to be
/// promoted to the upper layer before a write can proceed.
pub struct OverlayEntry {
    /// Source inode number (in the lower layer).
    pub source_ino: u64,
    /// Destination inode number (in the upper layer, assigned after commit).
    pub dest_ino: u64,
    /// Layer index of the source (0 = lowest).
    pub source_layer: u32,
    /// File type (regular, directory, symlink, ...).
    pub file_type: u8,
    /// Permission mode bits (POSIX).
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes (for regular files).
    pub size: u64,
    /// Modification time (seconds since epoch).
    pub mtime: u64,
    /// Entry name in the parent directory.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Copy-up flags.
    pub flags: CopyUpFlags,
    /// Current state.
    pub state: CopyUpState,
    /// Data copy progress.
    pub progress: CopyProgress,
    /// Extended attributes to carry over.
    xattrs: [XattrPair; MAX_XATTR_PAIRS],
    /// Number of populated xattr pairs.
    xattr_count: usize,
    /// Whether this slot is in use.
    pub in_use: bool,
    /// Generation counter (incremented on reuse).
    pub generation: u64,
}

impl OverlayEntry {
    /// Create an empty, unused entry.
    const fn empty() -> Self {
        Self {
            source_ino: 0,
            dest_ino: 0,
            source_layer: 0,
            file_type: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            flags: CopyUpFlags::NONE,
            state: CopyUpState::Idle,
            progress: CopyProgress::zero(),
            xattrs: [const { XattrPair::empty() }; MAX_XATTR_PAIRS],
            xattr_count: 0,
            in_use: false,
            generation: 0,
        }
    }

    /// Return the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the entry name.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Add an extended attribute to carry during copy-up.
    pub fn add_xattr(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        if self.xattr_count >= MAX_XATTR_PAIRS {
            return Err(Error::OutOfMemory);
        }
        // Replace if exists.
        for i in 0..self.xattr_count {
            if self.xattrs[i].name_bytes() == name {
                self.xattrs[i].set(name, value)?;
                return Ok(());
            }
        }
        self.xattrs[self.xattr_count].set(name, value)?;
        self.xattr_count += 1;
        Ok(())
    }

    /// Look up an xattr by name.
    pub fn get_xattr(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.xattr_count {
            if self.xattrs[i].name_bytes() == name {
                return Some(self.xattrs[i].value_bytes());
            }
        }
        None
    }

    /// Return the number of xattr pairs.
    pub fn xattr_count(&self) -> usize {
        self.xattr_count
    }

    /// Return whether the entry is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, CopyUpState::Done | CopyUpState::Failed)
    }

    /// Return whether this is a metacopy entry (metadata only, no data).
    pub fn is_metacopy(&self) -> bool {
        self.flags.contains(CopyUpFlags::METACOPY)
    }
}

impl core::fmt::Debug for OverlayEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OverlayEntry")
            .field("source_ino", &self.source_ino)
            .field("dest_ino", &self.dest_ino)
            .field("state", &self.state)
            .field("generation", &self.generation)
            .finish()
    }
}

// ── CopyUpStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics for the copy-up subsystem.
#[derive(Debug, Clone, Copy)]
pub struct CopyUpStats {
    /// Total copy-up operations started.
    pub total_started: u64,
    /// Total copy-up operations completed successfully.
    pub total_completed: u64,
    /// Total copy-up operations that failed.
    pub total_failed: u64,
    /// Total metacopy operations (metadata-only).
    pub metacopy_count: u64,
    /// Total bytes copied across all operations.
    pub bytes_copied: u64,
    /// Currently active copy-up operations.
    pub active_count: u32,
}

impl CopyUpStats {
    const fn new() -> Self {
        Self {
            total_started: 0,
            total_completed: 0,
            total_failed: 0,
            metacopy_count: 0,
            bytes_copied: 0,
            active_count: 0,
        }
    }
}

// ── OverlayCopyUp (main manager) ──────────────────────────────────────────────

/// The overlay copy-up manager.
///
/// Maintains a pool of [`OverlayEntry`] slots and drives them through the
/// copy-up state machine.  The manager is per-overlay-mount.
pub struct OverlayCopyUp {
    /// Pool of overlay entries.
    entries: [OverlayEntry; MAX_ENTRIES],
    /// Generation counter for slot reuse.
    generation: u64,
    /// Aggregate statistics.
    stats: CopyUpStats,
}

impl OverlayCopyUp {
    /// Create a new, empty copy-up manager.
    pub fn new() -> Self {
        Self {
            entries: [const { OverlayEntry::empty() }; MAX_ENTRIES],
            generation: 1,
            stats: CopyUpStats::new(),
        }
    }

    /// Begin a copy-up for a lower-layer inode.
    ///
    /// Returns the slot index on success.
    pub fn begin(
        &mut self,
        source_ino: u64,
        source_layer: u32,
        name: &[u8],
        file_type: u8,
        mode: u16,
        uid: u32,
        gid: u32,
        size: u64,
        flags: CopyUpFlags,
    ) -> Result<usize> {
        // Check if already tracked.
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.in_use && entry.source_ino == source_ino && !entry.is_terminal() {
                return Ok(idx);
            }
        }

        let (idx, slot) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, e)| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.source_ino = source_ino;
        slot.dest_ino = 0;
        slot.source_layer = source_layer;
        slot.file_type = file_type;
        slot.mode = mode;
        slot.uid = uid;
        slot.gid = gid;
        slot.size = size;
        slot.mtime = 0;
        slot.name_len = 0;
        slot.set_name(name)?;
        slot.flags = flags;
        slot.state = CopyUpState::Preparing;
        slot.xattr_count = 0;
        slot.in_use = true;
        slot.generation = self.generation;
        self.generation += 1;

        // Set up progress tracker.
        if flags.contains(CopyUpFlags::METACOPY) || size == 0 {
            slot.progress = CopyProgress::zero();
        } else {
            slot.progress = CopyProgress::new(size, DEFAULT_BLOCK_SIZE)?;
        }

        self.stats.total_started += 1;
        self.stats.active_count += 1;
        if flags.contains(CopyUpFlags::METACOPY) {
            self.stats.metacopy_count += 1;
        }

        Ok(idx)
    }

    /// Transition an entry to the data-copying phase.
    pub fn start_data_copy(&mut self, idx: usize) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if entry.state != CopyUpState::Preparing {
            return Err(Error::InvalidArgument);
        }
        if entry.flags.contains(CopyUpFlags::METACOPY) {
            // Skip data copy for metacopy.
            entry.state = CopyUpState::CopyingMeta;
        } else {
            entry.state = CopyUpState::CopyingData;
        }
        Ok(())
    }

    /// Record that `n` bytes of data have been copied for entry `idx`.
    pub fn advance_data(&mut self, idx: usize, n: u64) -> Result<()> {
        // Use index-based access to avoid holding &mut self via get_mut.
        if idx >= MAX_ENTRIES || !self.entries[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if self.entries[idx].state != CopyUpState::CopyingData {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx].progress.advance(n);
        self.stats.bytes_copied += n;

        if self.entries[idx].progress.is_complete() {
            self.entries[idx].state = CopyUpState::CopyingMeta;
        }
        Ok(())
    }

    /// Transition an entry to the committing phase (after metadata copy).
    pub fn start_commit(&mut self, idx: usize) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if entry.state != CopyUpState::CopyingMeta {
            return Err(Error::InvalidArgument);
        }
        entry.state = CopyUpState::Committing;
        Ok(())
    }

    /// Complete the copy-up, assigning the upper-layer inode number.
    pub fn commit(&mut self, idx: usize, dest_ino: u64) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if entry.state != CopyUpState::Committing {
            return Err(Error::InvalidArgument);
        }
        entry.dest_ino = dest_ino;
        entry.state = CopyUpState::Done;
        self.stats.total_completed += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        Ok(())
    }

    /// Mark an entry as failed.
    pub fn fail(&mut self, idx: usize) -> Result<()> {
        let entry = self.get_mut(idx)?;
        entry.state = CopyUpState::Failed;
        entry.progress.set_error(Error::IoError);
        self.stats.total_failed += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        Ok(())
    }

    /// Pause data copy for an entry (for preemption / context switch).
    pub fn pause(&mut self, idx: usize) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if entry.state != CopyUpState::CopyingData {
            return Err(Error::InvalidArgument);
        }
        entry.progress.pause();
        Ok(())
    }

    /// Resume a paused data copy.
    pub fn resume(&mut self, idx: usize) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if entry.state != CopyUpState::CopyingData || !entry.progress.paused {
            return Err(Error::InvalidArgument);
        }
        entry.progress.resume();
        Ok(())
    }

    /// Promote a metacopy entry to full copy-up (data write triggered).
    pub fn promote(&mut self, idx: usize, file_size: u64) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if !entry.is_metacopy() || entry.state != CopyUpState::Done {
            return Err(Error::InvalidArgument);
        }
        entry.flags = CopyUpFlags::from_raw(entry.flags.raw() & !CopyUpFlags::METACOPY.raw());
        entry.size = file_size;
        entry.progress = CopyProgress::new(file_size, DEFAULT_BLOCK_SIZE)?;
        entry.state = CopyUpState::CopyingData;
        self.stats.active_count += 1;
        Ok(())
    }

    /// Release a completed or failed entry slot.
    pub fn release(&mut self, idx: usize) -> Result<()> {
        let entry = self.get_mut(idx)?;
        if !entry.is_terminal() {
            return Err(Error::Busy);
        }
        entry.in_use = false;
        entry.state = CopyUpState::Idle;
        entry.xattr_count = 0;
        Ok(())
    }

    /// Find the entry index for a given source inode.
    pub fn find_by_source(&self, source_ino: u64) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.in_use && e.source_ino == source_ino)
            .map(|(i, _)| i)
    }

    /// Check whether a source inode has been successfully copied up.
    pub fn is_copied_up(&self, source_ino: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.in_use && e.source_ino == source_ino && e.state == CopyUpState::Done)
    }

    /// Get the upper inode number for a copied-up source inode.
    pub fn upper_ino(&self, source_ino: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.source_ino == source_ino && e.state == CopyUpState::Done)
            .map(|e| e.dest_ino)
    }

    /// Get a reference to an entry by index.
    pub fn get(&self, idx: usize) -> Result<&OverlayEntry> {
        if idx >= MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        let entry = &self.entries[idx];
        if !entry.in_use {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> CopyUpStats {
        self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = CopyUpStats::new();
        // Re-count active entries.
        let active = self
            .entries
            .iter()
            .filter(|e| e.in_use && !e.is_terminal())
            .count() as u32;
        self.stats.active_count = active;
    }

    /// Return the number of active (non-terminal, in-use) entries.
    pub fn active_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.in_use && !e.is_terminal())
            .count()
    }

    /// Return the number of completed entries still held.
    pub fn completed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.in_use && e.state == CopyUpState::Done)
            .count()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn get_mut(&mut self, idx: usize) -> Result<&mut OverlayEntry> {
        if idx >= MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[idx];
        if !entry.in_use {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }
}

impl Default for OverlayCopyUp {
    fn default() -> Self {
        Self::new()
    }
}

// ── Determine copy-up necessity ───────────────────────────────────────────────

/// Access types that may trigger a copy-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayAccess {
    /// Read-only access (never triggers copy-up).
    Read,
    /// Write access (triggers full copy-up).
    Write,
    /// Truncate (triggers full copy-up).
    Truncate,
    /// Metadata update (triggers metacopy).
    SetAttr,
    /// Extended attribute write (triggers metacopy).
    SetXattr,
}

/// Determine the [`CopyUpFlags`] required for a given access kind.
///
/// Returns `None` if no copy-up is needed (read-only access).
pub fn flags_for_access(access: OverlayAccess) -> Option<CopyUpFlags> {
    match access {
        OverlayAccess::Read => None,
        OverlayAccess::Write | OverlayAccess::Truncate => Some(CopyUpFlags::NONE),
        OverlayAccess::SetAttr | OverlayAccess::SetXattr => Some(CopyUpFlags::METACOPY),
    }
}

/// Determine whether a metacopy entry needs promotion for the given access.
pub fn needs_promotion(access: OverlayAccess) -> bool {
    matches!(access, OverlayAccess::Write | OverlayAccess::Truncate)
}
