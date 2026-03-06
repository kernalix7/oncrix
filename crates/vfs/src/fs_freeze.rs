// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem freeze/thaw subsystem.
//!
//! Provides the ability to quiesce a mounted filesystem so that consistent
//! snapshots can be taken (e.g. for backup or live-migration). Follows the
//! Linux `freeze_super()`/`thaw_super()` model and exports the `FIFREEZE`
//! and `FITHAW` ioctl codes for user-space coordination.
//!
//! # Freeze Levels
//!
//! The freeze is applied in multiple ordered stages so that each layer of
//! the kernel's write path is quiesced before the one below it:
//!
//! ```text
//! SB_FREEZE_WRITE   (1) — block new write system calls
//! SB_FREEZE_PAGEFAULT (2) — block page-fault paths that extend files
//! SB_FREEZE_FS      (3) — call filesystem's ->freeze_fs() callback
//! SB_FREEZE_COMPLETE (4) — fully frozen, snapshot safe
//! ```
//!
//! Thaw reverses the order.
//!
//! # Architecture
//!
//! - [`FreezeLevel`] — ordered freeze stage enum
//! - [`FreezeState`] — per-superblock freeze counter and level
//! - [`FsSnapshot`] — lightweight snapshot token issued when fully frozen
//! - [`FreezeRegistry`] — global registry of freezeable superblocks
//!
//! # IOCTL Codes
//!
//! - `FIFREEZE` — freeze the filesystem identified by the ioctl fd
//! - `FITHAW`   — thaw a previously frozen filesystem

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ── IOCTL Constants ──────────────────────────────────────────────

/// `FIFREEZE` ioctl number — freeze the filesystem (Linux-compatible).
pub const FIFREEZE: u32 = 0xC000_1601;

/// `FITHAW` ioctl number — thaw the filesystem (Linux-compatible).
pub const FITHAW: u32 = 0xC000_1602;

// ── Capacity Constants ───────────────────────────────────────────

/// Maximum number of superblocks tracked by the freeze registry.
const MAX_FREEZE_ENTRIES: usize = 32;

/// Maximum nesting depth for recursive freeze calls.
const MAX_FREEZE_DEPTH: u32 = 8;

// ── FreezeLevel ──────────────────────────────────────────────────

/// Ordered freeze stages applied from lowest to highest.
///
/// Each stage blocks a broader class of write activity. Thaw reverses
/// the order: `Complete → Fs → PageFault → Write → None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum FreezeLevel {
    /// Filesystem is fully thawed — normal I/O permitted.
    #[default]
    None = 0,
    /// Stage 1: new write system calls are blocked.
    Write = 1,
    /// Stage 2: page-fault paths that extend files are blocked.
    PageFault = 2,
    /// Stage 3: filesystem `freeze_fs()` callback has been called.
    Fs = 3,
    /// Stage 4: fully frozen — safe for snapshotting.
    Complete = 4,
}

impl FreezeLevel {
    /// Advance to the next freeze level.
    ///
    /// Returns `None` if already at `Complete`.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::None => Some(Self::Write),
            Self::Write => Some(Self::PageFault),
            Self::PageFault => Some(Self::Fs),
            Self::Fs => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    /// Retreat to the previous freeze level (for thaw).
    ///
    /// Returns `None` if already at `None`.
    pub fn prev(self) -> Option<Self> {
        match self {
            Self::Complete => Some(Self::Fs),
            Self::Fs => Some(Self::PageFault),
            Self::PageFault => Some(Self::Write),
            Self::Write => Some(Self::None),
            Self::None => None,
        }
    }

    /// Return `true` if write system calls should be blocked.
    pub fn blocks_write(self) -> bool {
        self >= Self::Write
    }

    /// Return `true` if page-fault paths should be blocked.
    pub fn blocks_pagefault(self) -> bool {
        self >= Self::PageFault
    }

    /// Return `true` if the filesystem is fully frozen.
    pub fn is_complete(self) -> bool {
        self == Self::Complete
    }
}

// ── FreezeFlags ──────────────────────────────────────────────────

/// Control flags for a freeze operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FreezeFlags(pub u32);

impl FreezeFlags {
    /// Flush dirty pages to disk before freezing (sync-before-freeze).
    pub const SYNC: Self = Self(0x0000_0001);
    /// Freeze all children of a union/overlay mount recursively.
    pub const RECURSIVE: Self = Self(0x0000_0002);
    /// Allow nested (stacked) freeze calls from the same owner.
    pub const ALLOW_NEST: Self = Self(0x0000_0004);

    /// Test whether a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    /// Combine two flag sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ── FreezeState ──────────────────────────────────────────────────

/// Per-superblock freeze state.
///
/// Tracks the current freeze level and a nesting counter so that
/// multiple callers can safely co-operate (`freeze_super()` is
/// reference-counted: it only freezes on the first call and only
/// thaws when the counter reaches zero again).
#[derive(Debug, Default)]
pub struct FreezeState {
    /// Current freeze level for this superblock.
    pub level: FreezeLevel,
    /// Number of outstanding freeze holders (nesting counter).
    pub depth: u32,
    /// Superblock ID this state belongs to (opaque handle).
    pub sb_id: u64,
    /// Pending dirty-page flush required before the next freeze stage.
    pub sync_pending: bool,
    /// Writer-exclusion counter: how many writers are currently inside.
    pub writer_count: u32,
    /// Total number of completed freeze operations (statistics).
    pub freeze_count: u64,
    /// Total number of completed thaw operations (statistics).
    pub thaw_count: u64,
}

impl FreezeState {
    /// Create a new, thawed freeze state for the given superblock ID.
    pub fn new(sb_id: u64) -> Self {
        Self {
            level: FreezeLevel::None,
            depth: 0,
            sb_id,
            sync_pending: false,
            writer_count: 0,
            freeze_count: 0,
            thaw_count: 0,
        }
    }

    /// Return `true` if the superblock is at any freeze level above `None`.
    pub fn is_frozen(&self) -> bool {
        self.level > FreezeLevel::None
    }

    /// Return `true` if the superblock is fully frozen.
    pub fn is_complete(&self) -> bool {
        self.level.is_complete()
    }

    /// Attempt to block a new writer.
    ///
    /// Returns `Err(Error::Busy)` if the filesystem is frozen at or above
    /// the `Write` stage.
    pub fn enter_writer(&mut self) -> Result<()> {
        if self.level.blocks_write() {
            return Err(Error::Busy);
        }
        self.writer_count += 1;
        Ok(())
    }

    /// Release a writer that previously called [`FreezeState::enter_writer`].
    pub fn exit_writer(&mut self) {
        self.writer_count = self.writer_count.saturating_sub(1);
    }

    /// Begin a freeze operation.
    ///
    /// If `flags` contains `FreezeFlags::ALLOW_NEST` and the filesystem is
    /// already frozen, the depth counter is incremented and `Ok(false)` is
    /// returned (caller should not repeat the freeze sequence). Otherwise
    /// the first freeze starts and `Ok(true)` is returned.
    pub fn begin_freeze(&mut self, flags: FreezeFlags) -> Result<bool> {
        if self.depth >= MAX_FREEZE_DEPTH {
            return Err(Error::Busy);
        }
        if self.depth > 0 {
            if flags.contains(FreezeFlags::ALLOW_NEST) {
                self.depth += 1;
                return Ok(false);
            }
            return Err(Error::AlreadyExists);
        }
        if self.writer_count > 0 {
            return Err(Error::Busy);
        }
        self.depth = 1;
        if flags.contains(FreezeFlags::SYNC) {
            self.sync_pending = true;
        }
        Ok(true)
    }

    /// Advance the freeze level by one stage.
    ///
    /// Returns `Ok(new_level)`. Returns `Err(Error::InvalidArgument)` if
    /// already at `Complete`.
    pub fn advance_level(&mut self) -> Result<FreezeLevel> {
        match self.level.next() {
            Some(next) => {
                self.level = next;
                if next == FreezeLevel::Complete {
                    self.freeze_count += 1;
                }
                Ok(next)
            }
            None => Err(Error::InvalidArgument),
        }
    }

    /// Begin a thaw operation.
    ///
    /// Decrements the nesting counter. Returns `Ok(true)` when the counter
    /// reaches zero (caller should run the full thaw sequence).
    pub fn begin_thaw(&mut self) -> Result<bool> {
        if self.depth == 0 {
            return Err(Error::InvalidArgument);
        }
        self.depth -= 1;
        Ok(self.depth == 0)
    }

    /// Retreat the freeze level by one stage.
    ///
    /// Returns `Ok(new_level)`. Returns `Err(Error::InvalidArgument)` if
    /// already at `None`.
    pub fn retreat_level(&mut self) -> Result<FreezeLevel> {
        match self.level.prev() {
            Some(prev) => {
                self.level = prev;
                if prev == FreezeLevel::None {
                    self.thaw_count += 1;
                }
                Ok(prev)
            }
            None => Err(Error::InvalidArgument),
        }
    }

    /// Fully freeze the superblock in one call (advances all levels).
    pub fn freeze_all(&mut self, flags: FreezeFlags) -> Result<()> {
        self.begin_freeze(flags)?;
        while self.level < FreezeLevel::Complete {
            self.advance_level()?;
        }
        Ok(())
    }

    /// Fully thaw the superblock in one call (retreats all levels).
    pub fn thaw_all(&mut self) -> Result<()> {
        let do_thaw = self.begin_thaw()?;
        if !do_thaw {
            return Ok(());
        }
        while self.level > FreezeLevel::None {
            self.retreat_level()?;
        }
        Ok(())
    }
}

// ── FsSnapshot ───────────────────────────────────────────────────

/// A lightweight snapshot token issued when a filesystem is fully frozen.
///
/// Holds the superblock ID and a sequence number so that snapshot
/// management layers can identify and order snapshots. The snapshot
/// is not automatically released — the caller must invoke the thaw
/// path separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSnapshot {
    /// Superblock this snapshot belongs to.
    pub sb_id: u64,
    /// Monotonically increasing snapshot sequence number.
    pub sequence: u64,
    /// Timestamp (ticks) when the snapshot was taken.
    pub taken_at: u64,
}

impl FsSnapshot {
    /// Create a new snapshot token.
    pub const fn new(sb_id: u64, sequence: u64, taken_at: u64) -> Self {
        Self {
            sb_id,
            sequence,
            taken_at,
        }
    }
}

// ── IoctlFreezeRequest ───────────────────────────────────────────

/// Parameters passed from user space for a `FIFREEZE` ioctl.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoctlFreezeRequest {
    /// Flags controlling the freeze behavior.
    pub flags: FreezeFlags,
    /// Optional explicit level to target (0 = full freeze).
    pub target_level: u8,
}

/// Parameters passed from user space for a `FITHAW` ioctl.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoctlThawRequest {
    /// Flags controlling the thaw behavior.
    pub flags: FreezeFlags,
}

// ── FreezeRegistry ───────────────────────────────────────────────

/// Global registry of freezeable superblocks.
///
/// Maintains a fixed-size array of [`FreezeState`] entries, one per
/// registered superblock. `FIFREEZE` / `FITHAW` ioctl handlers look up
/// the superblock ID here and delegate to the per-state methods.
#[derive(Debug)]
pub struct FreezeRegistry {
    entries: [Option<FreezeState>; MAX_FREEZE_ENTRIES],
    count: usize,
    /// Running snapshot counter (global, across all superblocks).
    snapshot_seq: u64,
}

impl FreezeRegistry {
    /// Create an empty freeze registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_FREEZE_ENTRIES],
            count: 0,
            snapshot_seq: 0,
        }
    }

    /// Register a superblock with the freeze subsystem.
    ///
    /// Returns the slot index assigned to the superblock.
    /// Returns `Err(Error::OutOfMemory)` if the registry is full.
    /// Returns `Err(Error::AlreadyExists)` if `sb_id` is already registered.
    pub fn register(&mut self, sb_id: u64) -> Result<usize> {
        if self.find_slot(sb_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FreezeState::new(sb_id));
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a superblock.
    ///
    /// Fails with `Err(Error::Busy)` if the superblock is currently frozen.
    pub fn unregister(&mut self, sb_id: u64) -> Result<()> {
        let slot = self.find_slot(sb_id).ok_or(Error::NotFound)?;
        if self.entries[slot].as_ref().map_or(false, |s| s.is_frozen()) {
            return Err(Error::Busy);
        }
        self.entries[slot] = None;
        self.count -= 1;
        Ok(())
    }

    /// Process a `FIFREEZE` ioctl for the given superblock.
    ///
    /// Performs a synchronous full freeze and returns an [`FsSnapshot`] token.
    pub fn fifreeze(
        &mut self,
        sb_id: u64,
        req: IoctlFreezeRequest,
        now: u64,
    ) -> Result<FsSnapshot> {
        let slot = self.find_slot(sb_id).ok_or(Error::NotFound)?;
        let state = self.entries[slot].as_mut().ok_or(Error::NotFound)?;
        state.freeze_all(req.flags)?;
        self.snapshot_seq += 1;
        Ok(FsSnapshot::new(sb_id, self.snapshot_seq, now))
    }

    /// Process a `FITHAW` ioctl for the given superblock.
    pub fn fithaw(&mut self, sb_id: u64, _req: IoctlThawRequest) -> Result<()> {
        let slot = self.find_slot(sb_id).ok_or(Error::NotFound)?;
        let state = self.entries[slot].as_mut().ok_or(Error::NotFound)?;
        state.thaw_all()
    }

    /// Return the current freeze level for a superblock.
    pub fn freeze_level(&self, sb_id: u64) -> Option<FreezeLevel> {
        let slot = self.find_slot(sb_id)?;
        self.entries[slot].as_ref().map(|s| s.level)
    }

    /// Enter the writer path for a superblock.
    ///
    /// Blocks if the filesystem is frozen at or above `SB_FREEZE_WRITE`.
    pub fn enter_writer(&mut self, sb_id: u64) -> Result<()> {
        let slot = self.find_slot(sb_id).ok_or(Error::NotFound)?;
        self.entries[slot]
            .as_mut()
            .ok_or(Error::NotFound)?
            .enter_writer()
    }

    /// Exit the writer path for a superblock.
    pub fn exit_writer(&mut self, sb_id: u64) -> Result<()> {
        let slot = self.find_slot(sb_id).ok_or(Error::NotFound)?;
        self.entries[slot]
            .as_mut()
            .ok_or(Error::NotFound)?
            .exit_writer();
        Ok(())
    }

    /// Return the number of registered superblocks.
    pub fn count(&self) -> usize {
        self.count
    }

    // ── Internal ──────────────────────────────────────────────────

    fn find_slot(&self, sb_id: u64) -> Option<usize> {
        for (i, slot) in self.entries.iter().enumerate() {
            if let Some(s) = slot {
                if s.sb_id == sb_id {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for FreezeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
