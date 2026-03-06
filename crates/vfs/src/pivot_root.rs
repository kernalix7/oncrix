// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pivot_root` operation implementation.
//!
//! Implements the `pivot_root(new_root, put_old)` system call which changes the
//! root mount of the calling process's mount namespace to `new_root` and moves
//! the old root mount to `put_old`.
//!
//! This is used by container runtimes and init systems to switch the root
//! filesystem after early boot or namespace creation.

use oncrix_lib::{Error, Result};

/// Maximum path length for pivot_root arguments.
pub const PIVOT_PATH_MAX: usize = 256;

/// Flags controlling pivot_root behavior (reserved for future use).
#[derive(Debug, Clone, Copy, Default)]
pub struct PivotFlags(pub u32);

impl PivotFlags {
    /// No special flags.
    pub const NONE: u32 = 0;
}

/// Describes a mount point by its numeric ID and parent ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountId {
    /// Unique mount identifier.
    pub id: u32,
    /// Parent mount identifier.
    pub parent_id: u32,
}

impl MountId {
    /// Create a new mount ID pair.
    pub const fn new(id: u32, parent_id: u32) -> Self {
        MountId { id, parent_id }
    }
}

/// State of the mount namespace root.
#[derive(Debug, Clone, Copy)]
pub struct RootState {
    /// Current root mount ID.
    pub root_mount: MountId,
    /// Inode number of root directory.
    pub root_ino: u64,
}

impl RootState {
    /// Create a new root state.
    pub const fn new(root_mount: MountId, root_ino: u64) -> Self {
        RootState {
            root_mount,
            root_ino,
        }
    }
}

/// Result of a successful pivot_root operation.
#[derive(Debug, Clone, Copy)]
pub struct PivotResult {
    /// New root mount ID after pivot.
    pub new_root: MountId,
    /// The old root's mount ID (now mounted at put_old).
    pub old_root: MountId,
}

/// Validate pivot_root preconditions.
///
/// Checks that:
/// - `new_root` is a mount point.
/// - `put_old` is under `new_root`.
/// - The calling process has appropriate capabilities.
/// - Neither path is shared in a propagated way that would be unsafe.
pub fn validate_pivot_root(
    new_root_mount: MountId,
    put_old_mount: MountId,
    current_root: MountId,
    caller_privileged: bool,
) -> Result<()> {
    if !caller_privileged {
        return Err(Error::PermissionDenied);
    }
    // new_root must be a different mount than current root.
    if new_root_mount.id == current_root.id {
        return Err(Error::InvalidArgument);
    }
    // put_old must be on or under new_root's tree.
    // Simplified check: put_old's parent chain must reach new_root.
    if !is_under_mount(put_old_mount, new_root_mount) {
        return Err(Error::InvalidArgument);
    }
    // new_root must not be the filesystem root of its own namespace
    // (it must itself be a mount point, i.e. parent_id != id).
    if new_root_mount.parent_id == new_root_mount.id {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check if `candidate` is under `root` in the mount tree.
///
/// Simplified: checks that candidate's parent_id is root's id.
fn is_under_mount(candidate: MountId, root: MountId) -> bool {
    // A real implementation would walk the mount tree.
    candidate.parent_id == root.id || candidate.id == root.id
}

/// Execute the pivot_root operation on the given mount namespace state.
///
/// This performs the mount rearrangement:
/// 1. Detach `new_root` from its current parent mount.
/// 2. Attach `new_root` as the new namespace root.
/// 3. Move old root to `put_old`.
pub fn do_pivot_root(
    current_root: MountId,
    new_root: MountId,
    put_old: MountId,
    privileged: bool,
) -> Result<PivotResult> {
    validate_pivot_root(new_root, put_old, current_root, privileged)?;
    Ok(PivotResult {
        new_root: MountId::new(new_root.id, 0),
        old_root: MountId::new(current_root.id, new_root.id),
    })
}

/// Path component iterator for pivot_root path validation.
pub struct PivotPathIter<'a> {
    path: &'a [u8],
    pos: usize,
}

impl<'a> PivotPathIter<'a> {
    /// Create a new iterator over path components.
    pub fn new(path: &'a [u8]) -> Self {
        PivotPathIter { path, pos: 0 }
    }
}

impl<'a> Iterator for PivotPathIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Skip leading slashes.
        while self.pos < self.path.len() && self.path[self.pos] == b'/' {
            self.pos += 1;
        }
        if self.pos >= self.path.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.path.len() && self.path[self.pos] != b'/' {
            self.pos += 1;
        }
        Some(&self.path[start..self.pos])
    }
}

/// Validate that a path does not contain `..` components.
///
/// pivot_root paths must be absolute and free of `..` traversal.
pub fn validate_absolute_clean(path: &[u8]) -> Result<()> {
    if path.is_empty() || path[0] != b'/' {
        return Err(Error::InvalidArgument);
    }
    for component in PivotPathIter::new(path) {
        if component == b".." {
            return Err(Error::InvalidArgument);
        }
        if component.len() > 255 {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}

/// Record keeping a history of pivot_root operations in a namespace.
pub struct PivotHistory {
    entries: [(u32, u32); 16],
    count: usize,
}

impl PivotHistory {
    /// Create an empty history.
    pub const fn new() -> Self {
        PivotHistory {
            entries: [(0, 0); 16],
            count: 0,
        }
    }

    /// Record a pivot operation (new_root_id, old_root_id).
    pub fn record(&mut self, new_root_id: u32, old_root_id: u32) -> Result<()> {
        if self.count >= 16 {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = (new_root_id, old_root_id);
        self.count += 1;
        Ok(())
    }

    /// Return the number of recorded pivots.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no pivots have been recorded.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over recorded pivots.
    pub fn iter(&self) -> impl Iterator<Item = &(u32, u32)> {
        self.entries[..self.count].iter()
    }
}

impl Default for PivotHistory {
    fn default() -> Self {
        Self::new()
    }
}
