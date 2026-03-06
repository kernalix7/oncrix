// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Path walk — step-by-step directory traversal with mount crossing.
//!
//! Provides a higher-level walk engine over `namei`-style component
//! iteration that handles mount point crossing, symlink following,
//! and permission checking hooks.

use oncrix_lib::{Error, Result};

/// Maximum path component length.
const NAME_MAX: usize = 255;

/// Maximum symlink follow depth.
const MAX_SYMLINK: usize = 40;

/// Maximum path components per walk.
const MAX_COMPONENTS: usize = 64;

/// Accumulated walk state for a multi-step path traversal.
#[derive(Debug, Clone, Copy)]
pub struct WalkState {
    /// Current superblock ID.
    pub sb_id: u64,
    /// Current inode number (directory being searched).
    pub ino: u64,
    /// Parent superblock ID.
    pub parent_sb_id: u64,
    /// Parent inode number.
    pub parent_ino: u64,
    /// Number of symlinks followed.
    pub symlink_depth: u8,
    /// Total components processed.
    pub components_processed: u8,
    /// Whether the walk crossed at least one mount point.
    pub crossed_mount: bool,
}

impl WalkState {
    /// Create an initial walk state rooted at `(sb_id, ino)`.
    pub const fn new(sb_id: u64, ino: u64) -> Self {
        Self {
            sb_id,
            ino,
            parent_sb_id: sb_id,
            parent_ino: ino,
            symlink_depth: 0,
            components_processed: 0,
            crossed_mount: false,
        }
    }

    /// Move into a child entry.
    pub fn enter(&mut self, child_sb_id: u64, child_ino: u64) {
        self.parent_sb_id = self.sb_id;
        self.parent_ino = self.ino;
        self.sb_id = child_sb_id;
        self.ino = child_ino;
        self.components_processed = self.components_processed.saturating_add(1);
    }

    /// Cross a mount point into a new filesystem.
    pub fn cross_mount(&mut self, mount_sb_id: u64, mount_root_ino: u64) {
        self.sb_id = mount_sb_id;
        self.ino = mount_root_ino;
        self.crossed_mount = true;
    }

    /// Follow a symlink, incrementing depth.
    pub fn follow_symlink(&mut self) -> Result<()> {
        if self.symlink_depth as usize >= MAX_SYMLINK {
            return Err(Error::IoError);
        }
        self.symlink_depth += 1;
        Ok(())
    }
}

/// Result of a single component lookup step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    /// Component resolved to a regular file or directory.
    Found { sb_id: u64, ino: u64 },
    /// Component is a symlink — caller should re-walk the link target.
    Symlink { sb_id: u64, ino: u64 },
    /// Component was not found.
    NotFound,
    /// Component resolved to a mount point — need to cross to child mount.
    MountPoint { sb_id: u64, ino: u64 },
}

/// Callback set for a path walk.
pub struct WalkCallbacks<'a> {
    /// Look up a name in a directory.
    ///
    /// `(sb_id, dir_ino, name) -> Ok(Some((sb_id, ino, is_symlink, is_mountpoint)))`
    pub lookup: &'a dyn Fn(u64, u64, &[u8]) -> Result<Option<(u64, u64, bool, bool)>>,

    /// Resolve a mount point to the root of the child filesystem.
    ///
    /// `(sb_id, ino) -> Ok((child_sb_id, child_root_ino))`
    pub cross_mount: &'a dyn Fn(u64, u64) -> Result<(u64, u64)>,

    /// Check read-execute permission on a directory.
    ///
    /// Returns `Err(PermissionDenied)` if access is not allowed.
    pub check_access: &'a dyn Fn(u64, u64) -> Result<()>,
}

/// Walk a single path component, returning the step result.
pub fn walk_component(
    state: &mut WalkState,
    name: &[u8],
    callbacks: &WalkCallbacks<'_>,
) -> Result<StepResult> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(Error::InvalidArgument);
    }

    // Permission check on current directory.
    (callbacks.check_access)(state.sb_id, state.ino)?;

    // Dot — stay.
    if name == b"." {
        return Ok(StepResult::Found {
            sb_id: state.sb_id,
            ino: state.ino,
        });
    }

    // Dotdot — move to parent.
    if name == b".." {
        let pino = state.parent_ino;
        let psb = state.parent_sb_id;
        state.enter(psb, pino);
        return Ok(StepResult::Found {
            sb_id: psb,
            ino: pino,
        });
    }

    // Ordinary lookup.
    match (callbacks.lookup)(state.sb_id, state.ino, name)? {
        None => Ok(StepResult::NotFound),
        Some((sb, ino, is_symlink, is_mount)) => {
            if is_symlink {
                state.follow_symlink()?;
                Ok(StepResult::Symlink { sb_id: sb, ino })
            } else if is_mount {
                let (msb, mino) = (callbacks.cross_mount)(sb, ino)?;
                state.cross_mount(msb, mino);
                Ok(StepResult::MountPoint {
                    sb_id: msb,
                    ino: mino,
                })
            } else {
                state.enter(sb, ino);
                Ok(StepResult::Found { sb_id: sb, ino })
            }
        }
    }
}

/// Walk an entire path byte-slice using the provided callbacks.
///
/// Returns the final `WalkState` on success.
pub fn walk_path(
    initial_state: WalkState,
    path: &[u8],
    callbacks: &WalkCallbacks<'_>,
) -> Result<WalkState> {
    let mut state = initial_state;
    let mut pos = 0usize;
    let mut comp_count = 0usize;

    // Skip leading slashes (absolute path handling done by caller).
    while pos < path.len() && path[pos] == b'/' {
        pos += 1;
    }

    while pos < path.len() {
        // Skip intermediate slashes.
        while pos < path.len() && path[pos] == b'/' {
            pos += 1;
        }
        if pos >= path.len() {
            break;
        }

        // Extract component.
        let start = pos;
        while pos < path.len() && path[pos] != b'/' {
            pos += 1;
        }
        let component = &path[start..pos];

        comp_count += 1;
        if comp_count > MAX_COMPONENTS {
            return Err(Error::InvalidArgument);
        }

        match walk_component(&mut state, component, callbacks)? {
            StepResult::NotFound => {
                // If there are remaining components, fail with ENOENT.
                let more = path[pos..].iter().any(|&b| b != b'/');
                if more {
                    return Err(Error::NotFound);
                }
                // Final component not found — return state pointing at parent.
                return Ok(state);
            }
            StepResult::Found { sb_id, ino } => {
                state.sb_id = sb_id;
                state.ino = ino;
            }
            StepResult::MountPoint { sb_id, ino } => {
                state.sb_id = sb_id;
                state.ino = ino;
            }
            StepResult::Symlink { sb_id: _, ino: _ } => {
                // Symlink following is the caller's responsibility in a full
                // implementation. Here we treat it as a found entry.
            }
        }
    }

    Ok(state)
}

/// Compute the directory depth of a path string (number of non-root components).
///
/// "/" => 0, "/foo" => 1, "/foo/bar" => 2, etc.
pub fn path_depth(path: &[u8]) -> usize {
    path.iter()
        .filter(|&&b| b == b'/')
        .count()
        .saturating_sub(if path.first() == Some(&b'/') { 1 } else { 0 })
}

/// Extract the final component (basename) of a path.
///
/// Returns an empty slice for paths that end with '/'.
pub fn path_basename(path: &[u8]) -> &[u8] {
    let end = path
        .iter()
        .rposition(|&b| b != b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let start = path[..end]
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    &path[start..end]
}

/// Extract the directory part (dirname) of a path.
///
/// Returns b"/" for top-level paths.
pub fn path_dirname(path: &[u8]) -> &[u8] {
    let end = path
        .iter()
        .rposition(|&b| b != b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let dir_end = path[..end].iter().rposition(|&b| b == b'/').unwrap_or(0);
    if dir_end == 0 { b"/" } else { &path[..dir_end] }
}
