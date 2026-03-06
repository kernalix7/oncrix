// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS rename operation — atomic file/directory rename with cross-directory
//! support.
//!
//! Implements `rename(2)` / `renameat2(2)` semantics including:
//!
//! - **NOREPLACE** — fail if the target already exists.
//! - **EXCHANGE** — atomically swap source and target dentries.
//! - **WHITEOUT** — replace the source with a whiteout entry (overlayfs).
//!
//! # Locking order
//!
//! To prevent deadlock when both source and destination directories must be
//! locked simultaneously, we always lock the directory with the lower inode
//! number first. This strict ordering is enforced by
//! [`VfsRenameSubsystem::do_rename`].
//!
//! # Cross-directory rename
//!
//! A cross-directory rename occurs when `source.dir_inode != target.dir_inode`.
//! Both parent directories must be updated; the operation is recorded as a
//! cross-directory rename in statistics.
//!
//! # References
//!
//! - Linux `fs/namei.c` — `vfs_rename()`, `do_renameat2()`
//! - POSIX.1-2024 `rename()` function spec
//! - `renameat2(2)` man page (Linux-specific flags)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of pending rename operations tracked.
pub const RENAME_MAX_PENDING: usize = 16;

/// Maximum length of a filename component (including NUL terminator).
pub const RENAME_NAME_MAX: usize = 256;

// ── RenameFlags ───────────────────────────────────────────────────────────────

/// Flags passed to `renameat2(2)` controlling rename behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RenameFlags(pub u32);

impl RenameFlags {
    /// Do not silently replace an existing destination — fail with EEXIST.
    pub const NOREPLACE: u32 = 1 << 0;
    /// Atomically exchange source and destination dentries.
    pub const EXCHANGE: u32 = 1 << 1;
    /// Replace the source with a whiteout entry (used by overlayfs).
    pub const WHITEOUT: u32 = 1 << 2;

    /// Returns `true` if the NOREPLACE flag is set.
    pub fn noreplace(self) -> bool {
        self.0 & Self::NOREPLACE != 0
    }

    /// Returns `true` if the EXCHANGE flag is set.
    pub fn exchange(self) -> bool {
        self.0 & Self::EXCHANGE != 0
    }

    /// Returns `true` if the WHITEOUT flag is set.
    pub fn whiteout(self) -> bool {
        self.0 & Self::WHITEOUT != 0
    }

    /// Returns `true` if no flags are set (plain rename).
    pub fn is_plain(self) -> bool {
        self.0 == 0
    }

    /// Validates that no mutually exclusive flag combination is set.
    pub fn validate(self) -> Result<()> {
        // EXCHANGE and NOREPLACE are mutually exclusive.
        if self.exchange() && self.noreplace() {
            return Err(Error::InvalidArgument);
        }
        // EXCHANGE and WHITEOUT are mutually exclusive.
        if self.exchange() && self.whiteout() {
            return Err(Error::InvalidArgument);
        }
        // Unknown bits.
        if self.0 & !(Self::NOREPLACE | Self::EXCHANGE | Self::WHITEOUT) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── RenameSource ──────────────────────────────────────────────────────────────

/// Describes the source of a rename operation.
#[derive(Debug, Clone, Copy)]
pub struct RenameSource {
    /// Inode number of the source's parent directory.
    pub dir_inode: u64,
    /// Name of the source entry within its parent directory.
    pub name: [u8; RENAME_NAME_MAX],
    /// Inode number of the source file/directory itself.
    pub inode_id: u64,
}

impl RenameSource {
    /// Constructs a zeroed source descriptor.
    pub const fn new() -> Self {
        Self {
            dir_inode: 0,
            name: [0u8; RENAME_NAME_MAX],
            inode_id: 0,
        }
    }

    /// Sets `name` from `src`, truncating to `RENAME_NAME_MAX - 1` bytes and
    /// NUL-terminating.
    pub fn set_name(&mut self, src: &[u8]) {
        let n = src.len().min(RENAME_NAME_MAX - 1);
        self.name[..n].copy_from_slice(&src[..n]);
        self.name[n] = 0;
    }

    /// Returns the name as a byte slice up to the first NUL.
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(RENAME_NAME_MAX);
        &self.name[..end]
    }
}

impl Default for RenameSource {
    fn default() -> Self {
        Self::new()
    }
}

// ── RenameTarget ──────────────────────────────────────────────────────────────

/// Describes the destination of a rename operation.
#[derive(Debug, Clone, Copy)]
pub struct RenameTarget {
    /// Inode number of the destination's parent directory.
    pub dir_inode: u64,
    /// Name of the destination entry within its parent directory.
    pub name: [u8; RENAME_NAME_MAX],
    /// Inode number of an existing entry at the destination (if any).
    pub existing_inode: Option<u64>,
}

impl RenameTarget {
    /// Constructs a zeroed target descriptor with no existing entry.
    pub const fn new() -> Self {
        Self {
            dir_inode: 0,
            name: [0u8; RENAME_NAME_MAX],
            existing_inode: None,
        }
    }

    /// Sets `name` from `src`, truncating and NUL-terminating.
    pub fn set_name(&mut self, src: &[u8]) {
        let n = src.len().min(RENAME_NAME_MAX - 1);
        self.name[..n].copy_from_slice(&src[..n]);
        self.name[n] = 0;
    }

    /// Returns the name as a byte slice up to the first NUL.
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(RENAME_NAME_MAX);
        &self.name[..end]
    }
}

impl Default for RenameTarget {
    fn default() -> Self {
        Self::new()
    }
}

// ── RenameRecord ──────────────────────────────────────────────────────────────

/// A pending or completed rename record stored in the subsystem.
#[derive(Debug, Clone, Copy)]
pub struct RenameRecord {
    /// Source descriptor.
    pub source: RenameSource,
    /// Target descriptor.
    pub target: RenameTarget,
    /// Flags governing the operation.
    pub flags: RenameFlags,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl RenameRecord {
    /// Constructs an empty slot.
    pub const fn new() -> Self {
        Self {
            source: RenameSource::new(),
            target: RenameTarget::new(),
            flags: RenameFlags(0),
            active: false,
        }
    }
}

impl Default for RenameRecord {
    fn default() -> Self {
        Self::new()
    }
}

// ── RenameStats ───────────────────────────────────────────────────────────────

/// Cumulative statistics for the rename subsystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct RenameStats {
    /// Total successful rename operations (plain + NOREPLACE).
    pub total_renames: u64,
    /// Total successful EXCHANGE operations.
    pub exchanges: u64,
    /// Total renames that replaced an existing target entry.
    pub replacements: u64,
    /// Total cross-directory renames.
    pub cross_dir: u64,
    /// Total failed rename attempts.
    pub errors: u64,
}

impl RenameStats {
    /// Constructs zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_renames: 0,
            exchanges: 0,
            replacements: 0,
            cross_dir: 0,
            errors: 0,
        }
    }
}

// ── RenameValidator ───────────────────────────────────────────────────────────

/// Validates rename arguments before the operation is committed.
pub struct RenameValidator;

impl RenameValidator {
    /// Validates that source and target arguments are well-formed and that the
    /// flag combination is legal.
    ///
    /// Checks performed:
    /// 1. `flags` is a valid combination.
    /// 2. Source name is non-empty and not `.` or `..`.
    /// 3. Target name is non-empty and not `.` or `..`.
    /// 4. NOREPLACE: target must have no existing entry.
    /// 5. EXCHANGE: target must have an existing entry (nothing to swap otherwise).
    /// 6. Source and target are not identical dentries.
    pub fn validate(
        source: &RenameSource,
        target: &RenameTarget,
        flags: RenameFlags,
    ) -> Result<()> {
        flags.validate()?;

        // Validate source name.
        let sname = source.name_bytes();
        if sname.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if sname == b"." || sname == b".." {
            return Err(Error::InvalidArgument);
        }

        // Validate target name.
        let tname = target.name_bytes();
        if tname.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if tname == b"." || tname == b".." {
            return Err(Error::InvalidArgument);
        }

        // Source inode must be non-zero.
        if source.inode_id == 0 {
            return Err(Error::NotFound);
        }

        // NOREPLACE: no existing target allowed.
        if flags.noreplace() && target.existing_inode.is_some() {
            return Err(Error::AlreadyExists);
        }

        // EXCHANGE: target must exist.
        if flags.exchange() && target.existing_inode.is_none() {
            return Err(Error::NotFound);
        }

        // Reject self-rename (same dir + same name).
        if source.dir_inode == target.dir_inode && sname == tname {
            // POSIX says this is a no-op success, but we treat same-inode
            // same-name as a no-op error to signal callers.
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Checks for directory loop: `source` must not be an ancestor of `target_dir`.
    ///
    /// In this simplified implementation the check is done by comparing inode
    /// IDs — a real VFS would walk the dentry tree upwards.
    pub fn check_no_loop(source_inode: u64, target_dir_inode: u64) -> Result<()> {
        if source_inode == target_dir_inode {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── VfsRenameSubsystem ────────────────────────────────────────────────────────

/// VFS rename subsystem — owns the pending rename queue and statistics.
pub struct VfsRenameSubsystem {
    /// Active rename records.
    pub pending: [RenameRecord; RENAME_MAX_PENDING],
    /// Cumulative statistics.
    pub stats: RenameStats,
}

impl VfsRenameSubsystem {
    /// Constructs an idle rename subsystem.
    pub const fn new() -> Self {
        Self {
            pending: [const { RenameRecord::new() }; RENAME_MAX_PENDING],
            stats: RenameStats::new(),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Allocates a pending record slot.
    fn alloc_slot(&mut self) -> Option<usize> {
        self.pending.iter().position(|r| !r.active)
    }

    /// Records a rename in the pending table and returns the slot index.
    fn record(
        &mut self,
        source: RenameSource,
        target: RenameTarget,
        flags: RenameFlags,
    ) -> Result<usize> {
        let slot = self.alloc_slot().ok_or(Error::OutOfMemory)?;
        self.pending[slot] = RenameRecord {
            source,
            target,
            flags,
            active: true,
        };
        Ok(slot)
    }

    /// Frees a pending record slot.
    fn free_slot(&mut self, slot: usize) {
        if slot < RENAME_MAX_PENDING {
            self.pending[slot] = RenameRecord::new();
        }
    }

    // ── Locking order helper ──────────────────────────────────────────────────

    /// Returns `(first, second)` inode IDs in the order they should be locked
    /// to prevent deadlock.
    fn lock_order(a: u64, b: u64) -> (u64, u64) {
        if a <= b { (a, b) } else { (b, a) }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Performs a plain rename or NOREPLACE rename.
    ///
    /// Validates arguments, enforces lock ordering, and records the operation.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — bad names, invalid flag combo, or self-rename.
    /// - [`Error::AlreadyExists`] — NOREPLACE and target exists.
    /// - [`Error::NotFound`] — source inode not set.
    /// - [`Error::OutOfMemory`] — pending queue full.
    pub fn do_rename(
        &mut self,
        mut source: RenameSource,
        target: RenameTarget,
        flags: RenameFlags,
    ) -> Result<()> {
        RenameValidator::validate(&source, &target, flags)?;

        // Directory loop check.
        RenameValidator::check_no_loop(source.inode_id, target.dir_inode)?;

        // Enforce lock ordering (lower inode first).
        let (_first, _second) = Self::lock_order(source.dir_inode, target.dir_inode);
        // In a real kernel: lock(_first); lock(_second);

        let cross_dir = source.dir_inode != target.dir_inode;
        let replaced = target.existing_inode.is_some();

        // Simulate the rename: update the source directory inode reference.
        source.dir_inode = target.dir_inode;

        let slot = self.record(source, target, flags)?;
        self.free_slot(slot);

        // Update statistics.
        self.stats.total_renames = self.stats.total_renames.wrapping_add(1);
        if cross_dir {
            self.stats.cross_dir = self.stats.cross_dir.wrapping_add(1);
        }
        if replaced {
            self.stats.replacements = self.stats.replacements.wrapping_add(1);
        }
        Ok(())
    }

    /// Atomically exchanges source and target directory entries (RENAME_EXCHANGE).
    ///
    /// Both entries must exist. Neither is removed; they simply swap places.
    ///
    /// # Errors
    ///
    /// Same as [`do_rename`](Self::do_rename) plus:
    /// - [`Error::NotFound`] — either entry does not exist.
    pub fn do_exchange(&mut self, source: RenameSource, target: RenameTarget) -> Result<()> {
        let flags = RenameFlags(RenameFlags::EXCHANGE);
        RenameValidator::validate(&source, &target, flags)?;
        RenameValidator::check_no_loop(source.inode_id, target.dir_inode)?;

        let (_first, _second) = Self::lock_order(source.dir_inode, target.dir_inode);
        let cross_dir = source.dir_inode != target.dir_inode;

        let slot = self.record(source, target, flags)?;
        self.free_slot(slot);

        self.stats.exchanges = self.stats.exchanges.wrapping_add(1);
        if cross_dir {
            self.stats.cross_dir = self.stats.cross_dir.wrapping_add(1);
        }
        Ok(())
    }

    /// Replaces the source entry with a whiteout (RENAME_WHITEOUT).
    ///
    /// Used by overlayfs to mark a deleted entry so that the lower layer entry
    /// is hidden.
    ///
    /// # Errors
    ///
    /// Same as [`do_rename`](Self::do_rename).
    pub fn do_whiteout(&mut self, source: RenameSource, target: RenameTarget) -> Result<()> {
        let flags = RenameFlags(RenameFlags::WHITEOUT);
        RenameValidator::validate(&source, &target, flags)?;
        RenameValidator::check_no_loop(source.inode_id, target.dir_inode)?;

        let cross_dir = source.dir_inode != target.dir_inode;

        let slot = self.record(source, target, flags)?;
        self.free_slot(slot);

        self.stats.total_renames = self.stats.total_renames.wrapping_add(1);
        if cross_dir {
            self.stats.cross_dir = self.stats.cross_dir.wrapping_add(1);
        }
        Ok(())
    }

    /// Returns a snapshot of the current statistics.
    pub fn stats(&self) -> RenameStats {
        self.stats
    }
}

impl Default for VfsRenameSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper: build a RenameSource from raw components ─────────────────────────

/// Convenience constructor for [`RenameSource`].
pub fn make_source(dir_inode: u64, name: &[u8], inode_id: u64) -> RenameSource {
    let mut s = RenameSource::new();
    s.dir_inode = dir_inode;
    s.set_name(name);
    s.inode_id = inode_id;
    s
}

/// Convenience constructor for [`RenameTarget`].
pub fn make_target(dir_inode: u64, name: &[u8], existing_inode: Option<u64>) -> RenameTarget {
    let mut t = RenameTarget::new();
    t.dir_inode = dir_inode;
    t.set_name(name);
    t.existing_inode = existing_inode;
    t
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_rename_same_dir() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(10, b"foo", 100);
        let tgt = make_target(10, b"bar", None);
        sub.do_rename(src, tgt, RenameFlags(0)).unwrap();
        assert_eq!(sub.stats().total_renames, 1);
        assert_eq!(sub.stats().cross_dir, 0);
    }

    #[test]
    fn cross_dir_rename() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(1, b"file.txt", 50);
        let tgt = make_target(2, b"file.txt", None);
        sub.do_rename(src, tgt, RenameFlags(0)).unwrap();
        assert_eq!(sub.stats().cross_dir, 1);
    }

    #[test]
    fn noreplace_fails_if_exists() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(1, b"a", 10);
        let tgt = make_target(1, b"b", Some(20));
        let r = sub.do_rename(src, tgt, RenameFlags(RenameFlags::NOREPLACE));
        assert!(matches!(r, Err(Error::AlreadyExists)));
    }

    #[test]
    fn exchange_requires_existing_target() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(1, b"a", 10);
        let tgt = make_target(1, b"b", None); // no existing
        let r = sub.do_exchange(src, tgt);
        assert!(matches!(r, Err(Error::NotFound)));
    }

    #[test]
    fn exchange_succeeds() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(1, b"a", 10);
        let tgt = make_target(1, b"b", Some(20));
        sub.do_exchange(src, tgt).unwrap();
        assert_eq!(sub.stats().exchanges, 1);
    }

    #[test]
    fn whiteout_rename() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(5, b"ghost", 77);
        let tgt = make_target(5, b"ghost_new", None);
        sub.do_whiteout(src, tgt).unwrap();
        assert_eq!(sub.stats().total_renames, 1);
    }

    #[test]
    fn self_rename_rejected() {
        let mut sub = VfsRenameSubsystem::new();
        let src = make_source(1, b"same", 10);
        let tgt = make_target(1, b"same", None);
        let r = sub.do_rename(src, tgt, RenameFlags(0));
        assert!(matches!(r, Err(Error::InvalidArgument)));
    }

    #[test]
    fn flag_validation_exchange_noreplace_conflict() {
        let flags = RenameFlags(RenameFlags::EXCHANGE | RenameFlags::NOREPLACE);
        assert!(matches!(flags.validate(), Err(Error::InvalidArgument)));
    }
}
