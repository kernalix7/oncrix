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

/// Maximum length used when resolving a symlink target during walk.
const WALK_SYMLINK_BUF: usize = 512;

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
    /// Root superblock ID — the confinement root (chroot / bind-mount anchor).
    pub root_sb_id: u64,
    /// Root inode number — the confinement root.
    pub root_ino: u64,
    /// Number of symlinks followed.
    pub symlink_depth: u8,
    /// Total components processed.
    pub components_processed: u8,
    /// Whether the walk crossed at least one mount point.
    pub crossed_mount: bool,
}

impl WalkState {
    /// Create an initial walk state rooted at `(sb_id, ino)`.
    ///
    /// The root anchor is initialised to the same `(sb_id, ino)` so that
    /// `..` at the walk root stays put (POSIX chroot semantics).
    pub const fn new(sb_id: u64, ino: u64) -> Self {
        Self {
            sb_id,
            ino,
            parent_sb_id: sb_id,
            parent_ino: ino,
            root_sb_id: sb_id,
            root_ino: ino,
            symlink_depth: 0,
            components_processed: 0,
            crossed_mount: false,
        }
    }

    /// Create a walk state with an explicit confinement root distinct from the
    /// starting directory (e.g. process chroot != cwd).
    pub const fn new_with_root(sb_id: u64, ino: u64, root_sb_id: u64, root_ino: u64) -> Self {
        Self {
            sb_id,
            ino,
            parent_sb_id: sb_id,
            parent_ino: ino,
            root_sb_id,
            root_ino,
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
    ///
    /// The parent fields are updated to the mount-point inode (on the host
    /// filesystem) so that a subsequent `..` from the mount root returns to
    /// the correct host-side directory rather than jumping to the pre-cross
    /// parent.
    pub fn cross_mount(&mut self, mount_sb_id: u64, mount_root_ino: u64) {
        // Record the current (mount-point) inode as the parent so that `..`
        // immediately after crossing a mount correctly ascends back to the
        // mount-point directory on the host filesystem.
        self.parent_sb_id = self.sb_id;
        self.parent_ino = self.ino;
        self.sb_id = mount_sb_id;
        self.ino = mount_root_ino;
        self.crossed_mount = true;
    }

    /// Follow a symlink, incrementing depth.
    ///
    /// POSIX MAXSYMLINKS is 40; `> MAX_SYMLINK` allows exactly 40 follows
    /// before returning `ELOOP`.  Using `>=` would have incorrectly rejected
    /// the 40th follow, making the effective limit 39.
    pub fn follow_symlink(&mut self) -> Result<()> {
        if self.symlink_depth as usize > MAX_SYMLINK {
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

    /// Read the target of a symbolic link.
    ///
    /// `(sb_id, ino, buf) -> Ok(len)` where `buf[..len]` holds the target
    /// path bytes.  Used by `walk_path` to expand intermediate symlinks
    /// in-place rather than treating them as resolved inodes.
    pub readlink: &'a dyn Fn(u64, u64, &mut [u8]) -> Result<usize>,
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

    // Dotdot — ascend to parent with root-boundary enforcement.
    //
    // SECURITY: If the current position is the confinement root we must NOT
    // delegate to the filesystem's ".." entry — doing so would allow escape
    // from a chroot / bind-mount jail.  When at root, ".." is a no-op (clamp).
    //
    // CORRECTNESS: Do NOT use `state.enter()` here.  `enter()` is a
    // forward-descent helper; it sets `parent_ino = current.ino` (the
    // directory being left), which corrupts grandparent tracking for
    // multi-level `..` sequences — e.g. `../../` would oscillate back
    // to the child instead of continuing to ascend.
    //
    // Instead, ask the filesystem for `".."` authoritatively.  The
    // filesystem returns the real parent inode stored on disk.  After
    // resolving the real parent, update `state` by shifting the current
    // (now-leaving) inode into the parent slot, then placing the
    // filesystem-returned parent inode into the current slot.  This keeps
    // the parent chain correct for any subsequent `..`.
    if name == b".." {
        if state.sb_id == state.root_sb_id && state.ino == state.root_ino {
            // Already at root — ".." stays put (chroot / bind-mount clamp).
            return Ok(StepResult::Found {
                sb_id: state.sb_id,
                ino: state.ino,
            });
        }

        // Ask the filesystem for the real parent entry.
        match (callbacks.lookup)(state.sb_id, state.ino, b"..")? {
            None => {
                // Filesystem has no ".." entry — stay put (safe fallback).
                return Ok(StepResult::Found {
                    sb_id: state.sb_id,
                    ino: state.ino,
                });
            }
            Some((par_sb, par_ino, _is_symlink, _is_mount)) => {
                // Clamp again: the filesystem must not hand us a parent that
                // escapes the confinement root.  This covers the edge case
                // where the on-disk ".." of the root's direct child still
                // points to the root itself.
                let (clamped_sb, clamped_ino) =
                    if par_sb == state.root_sb_id && par_ino == state.root_ino {
                        (state.root_sb_id, state.root_ino)
                    } else {
                        (par_sb, par_ino)
                    };

                // Shift: what was current becomes the new parent; the
                // filesystem-returned parent becomes the new current.
                // This preserves a correct single-level parent for the
                // next `..` without the forward-descent corruption that
                // `enter()` would introduce.
                state.parent_sb_id = state.sb_id;
                state.parent_ino = state.ino;
                state.sb_id = clamped_sb;
                state.ino = clamped_ino;
                state.components_processed = state.components_processed.saturating_add(1);

                return Ok(StepResult::Found {
                    sb_id: clamped_sb,
                    ino: clamped_ino,
                });
            }
        }
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
///
/// Intermediate symlinks are resolved inline: the target replaces the
/// remaining path suffix and the walk restarts from the current directory,
/// consuming from the shared `symlink_depth` budget.  A terminal symlink
/// (the very last component) is left unresolved; the caller receives the
/// symlink inode in the state and can follow it at its discretion.
///
/// `StepResult::Symlink` is no longer silently treated as `Found` — this
/// previously caused path confusion by using a symlink inode as if it were
/// a directory for subsequent components.
pub fn walk_path(
    initial_state: WalkState,
    path: &[u8],
    callbacks: &WalkCallbacks<'_>,
) -> Result<WalkState> {
    if path.len() > 4096 {
        return Err(Error::InvalidArgument);
    }

    let mut state = initial_state;

    // We maintain a small on-stack path buffer.  When a symlink is
    // encountered mid-walk its target replaces the tail of `work[pos..]`
    // and we continue from `pos`.
    let mut work = [0u8; WALK_SYMLINK_BUF];
    let copy_len = path.len().min(WALK_SYMLINK_BUF);
    work[..copy_len].copy_from_slice(&path[..copy_len]);
    if path.len() > WALK_SYMLINK_BUF {
        return Err(Error::InvalidArgument);
    }
    let mut work_len = copy_len;
    let mut pos = 0usize;
    let mut comp_count = 0usize;

    // Skip leading slashes (absolute path handling done by caller).
    while pos < work_len && work[pos] == b'/' {
        pos += 1;
    }

    while pos < work_len {
        // Skip intermediate slashes.
        while pos < work_len && work[pos] == b'/' {
            pos += 1;
        }
        if pos >= work_len {
            break;
        }

        // Extract component.
        let start = pos;
        while pos < work_len && work[pos] != b'/' {
            pos += 1;
        }
        let comp_end = pos;
        // Peek at the remaining path to detect whether this is terminal.
        let has_more_components = work[pos..work_len].iter().any(|&b| b != b'/');

        // Enforce component count bound.
        comp_count = comp_count.checked_add(1).ok_or(Error::InvalidArgument)?;
        if comp_count > MAX_COMPONENTS {
            return Err(Error::InvalidArgument);
        }

        // Copy the component name to a local buffer so we can mutate `work`
        // below without aliasing.
        let comp_len = comp_end - start;
        if comp_len == 0 {
            continue;
        }
        let mut name_buf = [0u8; NAME_MAX + 1];
        if comp_len > NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        name_buf[..comp_len].copy_from_slice(&work[start..comp_end]);
        let name = &name_buf[..comp_len];

        match walk_component(&mut state, name, callbacks)? {
            StepResult::NotFound => {
                // If there are remaining components, fail with ENOENT.
                if has_more_components {
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
            StepResult::Symlink { sb_id, ino } => {
                // SECURITY: An intermediate symlink inode must NOT be used as a
                // directory for subsequent components — that is path confusion /
                // TOCTOU.  Read the target and substitute it into the remaining
                // suffix of `work`, then continue from the current position.
                //
                // A terminal symlink (no more components) is left unresolved;
                // the caller decides whether to follow it (O_NOFOLLOW etc.).
                if !has_more_components {
                    // Terminal symlink — surface it to the caller.
                    state.sb_id = sb_id;
                    state.ino = ino;
                    break;
                }

                // Intermediate symlink: read target, splice into work buffer.
                let mut target_buf = [0u8; WALK_SYMLINK_BUF];
                let tlen = (callbacks.readlink)(sb_id, ino, &mut target_buf)?;
                if tlen == 0 || tlen > WALK_SYMLINK_BUF {
                    return Err(Error::InvalidArgument);
                }
                let target = &target_buf[..tlen];

                // Remaining suffix: everything after `comp_end`.
                let suffix_start = comp_end;
                let suffix_len = if suffix_start < work_len {
                    work_len - suffix_start
                } else {
                    0
                };

                // Compute the length of the substituted path.
                // If target is absolute, the remaining prefix is just the target.
                // If relative, the current directory is already in `state`.
                let new_len = tlen
                    .checked_add(if suffix_len > 0 { 1 + suffix_len } else { 0 })
                    .ok_or(Error::InvalidArgument)?;
                if new_len > WALK_SYMLINK_BUF {
                    return Err(Error::InvalidArgument);
                }

                // Build the substituted path in a temporary buffer, then copy
                // it back into `work`.
                let mut tmp = [0u8; WALK_SYMLINK_BUF];
                tmp[..tlen].copy_from_slice(target);
                if suffix_len > 0 {
                    tmp[tlen] = b'/';
                    tmp[tlen + 1..tlen + 1 + suffix_len]
                        .copy_from_slice(&work[suffix_start..suffix_start + suffix_len]);
                }
                work[..new_len].copy_from_slice(&tmp[..new_len]);
                work_len = new_len;

                // If the target is absolute, restart from the root of `work`.
                if target[0] == b'/' {
                    pos = 0;
                    // Reset to the walk root (absolute symlink target ignores cwd).
                    state.sb_id = state.root_sb_id;
                    state.ino = state.root_ino;
                    state.parent_sb_id = state.root_sb_id;
                    state.parent_ino = state.root_ino;
                } else {
                    // Relative: continue from `pos` (start of target in work).
                    pos = 0;
                }
                // Reset component counter for the new sub-path (the symlink
                // depth counter in state already guards against cycles).
                comp_count = 0;
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
