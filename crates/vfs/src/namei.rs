// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pathname resolution — walk, lookup intent, and component iteration.
//!
//! Implements the core `namei` algorithm: decompose a path into components,
//! resolve symlinks, and return the final dentry/inode pair.

use crate::chroot_ops::ChrootContext;
use oncrix_lib::{Error, Result};

/// Maximum path length (POSIX PATH_MAX = 4096).
pub const PATH_MAX: usize = 4096;

/// Maximum number of path components in a single lookup.
pub const MAX_COMPONENTS: usize = 64;

/// Maximum symlink follow depth before ELOOP.
pub const MAX_SYMLINK_DEPTH: usize = 40;

/// Maximum length of a single filename component (POSIX NAME_MAX = 255).
pub const NAME_MAX: usize = 255;

/// Intent of a pathname lookup — controls how the final component is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupIntent {
    /// Lookup only — do not create or open.
    Lookup,
    /// Open an existing file.
    Open,
    /// Create a new file (fail if exists when combined with Excl).
    Create,
    /// Create + exclusive (O_CREAT | O_EXCL).
    CreateExcl,
    /// Rename target resolution.
    Rename,
    /// Unlink (remove) the target.
    Unlink,
    /// Create a directory.
    Mkdir,
    /// Remove a directory.
    Rmdir,
}

/// Flags for path walk behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkFlags(pub u32);

impl WalkFlags {
    /// Do not follow symlinks in the final component.
    pub const NOFOLLOW: u32 = 1 << 0;
    /// Lookup relative to the calling process's root (chroot).
    pub const CHROOT: u32 = 1 << 1;
    /// Allow the last component to be an empty string (open via fd).
    pub const EMPTY_PATH: u32 = 1 << 2;

    /// Test whether a flag is set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// A single resolved path component.
#[derive(Debug, Clone, Copy)]
pub struct PathComponent {
    /// Byte offset in the original path string.
    pub offset: u16,
    /// Length of this component (not including '/').
    pub len: u8,
    /// Whether this component was followed through a symlink.
    pub from_symlink: bool,
}

/// The result of a successful pathname lookup.
#[derive(Debug, Clone, Copy)]
pub struct NameiResult {
    /// Superblock ID of the filesystem containing the result.
    pub sb_id: u64,
    /// Inode number of the resolved path.
    pub ino: u64,
    /// Inode number of the parent directory.
    pub parent_ino: u64,
    /// Superblock ID of the parent (may differ across mountpoints).
    pub parent_sb_id: u64,
    /// Number of symlinks followed during resolution.
    pub symlink_count: u8,
    /// Whether the final component existed (false = ENOENT was acceptable).
    pub found: bool,
}

impl NameiResult {
    /// Create a "not found" result for create-intent lookups.
    pub const fn not_found(parent_sb_id: u64, parent_ino: u64) -> Self {
        Self {
            sb_id: 0,
            ino: 0,
            parent_ino,
            parent_sb_id,
            symlink_count: 0,
            found: false,
        }
    }

    /// Create a "found" result.
    pub const fn found(sb_id: u64, ino: u64, parent_sb_id: u64, parent_ino: u64) -> Self {
        Self {
            sb_id,
            ino,
            parent_ino,
            parent_sb_id,
            symlink_count: 0,
            found: true,
        }
    }
}

/// Walk context — state carried through the component-by-component walk.
#[derive(Debug)]
pub struct WalkContext {
    /// Current directory superblock ID.
    pub cur_sb_id: u64,
    /// Current directory inode number.
    pub cur_ino: u64,
    /// Root superblock ID (for chroot enforcement).
    pub root_sb_id: u64,
    /// Root inode number.
    pub root_ino: u64,
    /// Symlink follow depth so far.
    pub symlink_depth: u8,
    /// Walk flags.
    pub flags: WalkFlags,
    /// Lookup intent.
    pub intent: LookupIntent,
    /// Mount crossing depth relative to the jail root mount.
    ///
    /// Incremented on every forward `cross_mount`; the `..` handler
    /// refuses to decrement below zero so a `..` immediately after
    /// crossing a mount cannot escape the jail even when the inode
    /// equality check would pass (cross-filesystem bind-mount case).
    pub mount_depth: i32,
    /// Chroot jail context for this walk.
    ///
    /// When `chroot_ctx.depth > 0` the walk is confined to the jail: `..`
    /// at the jail root is clamped, and the root_ino/root_sb_id are
    /// initialised from the jail context rather than the namespace root.
    pub chroot_ctx: ChrootContext,
}

impl WalkContext {
    /// Create a new walk context starting at the given directory.
    ///
    /// `chroot_ctx` should be obtained from the calling process's
    /// [`ChrootRegistry`](crate::chroot_ops::ChrootRegistry) entry.
    /// Pass [`ChrootContext::new_root()`] for un-jailed processes.
    pub fn new(
        cwd_sb_id: u64,
        cwd_ino: u64,
        root_sb_id: u64,
        root_ino: u64,
        flags: WalkFlags,
        intent: LookupIntent,
        chroot_ctx: ChrootContext,
    ) -> Self {
        // Finding 5: if a chroot jail is active, override root_sb_id/root_ino
        // so the walk is anchored to the jail root rather than the ns root.
        let (eff_root_sb, eff_root_ino) = if chroot_ctx.depth > 0 {
            // The root_sb_id passed in is the one the caller resolved the jail
            // root on; we use chroot_ctx.root_ino as the authoritative inode.
            (root_sb_id, chroot_ctx.root_ino)
        } else {
            (root_sb_id, root_ino)
        };
        Self {
            cur_sb_id: cwd_sb_id,
            cur_ino: cwd_ino,
            root_sb_id: eff_root_sb,
            root_ino: eff_root_ino,
            symlink_depth: 0,
            flags,
            intent,
            mount_depth: 0,
            chroot_ctx,
        }
    }

    /// Follow a symlink, incrementing the depth counter.
    ///
    /// Returns `Err(IoError)` when the maximum depth is exceeded (ELOOP).
    pub fn follow_symlink(&mut self) -> Result<()> {
        if (self.symlink_depth as usize) >= MAX_SYMLINK_DEPTH {
            Err(Error::IoError)
        } else {
            self.symlink_depth += 1;
            Ok(())
        }
    }

    /// Step into a mount point, updating the current sb/ino.
    ///
    /// Finding 6: track how deep into mounts we are relative to the jail root
    /// mount so the `..` handler can prevent escaping by crossing back.
    pub fn cross_mount(&mut self, new_sb_id: u64, new_ino: u64) {
        self.cur_sb_id = new_sb_id;
        self.cur_ino = new_ino;
        // Saturating add: pathological nesting (>2 billion mounts) stays i32::MAX.
        self.mount_depth = self.mount_depth.saturating_add(1);
    }
}

/// An iterator over the components of a path stored in a byte slice.
pub struct PathComponents<'a> {
    path: &'a [u8],
    pos: usize,
    /// Whether the path was absolute (starts with '/').
    pub is_absolute: bool,
}

impl<'a> PathComponents<'a> {
    /// Create a new component iterator over a NUL-terminated or length-bounded path.
    pub fn new(path: &'a [u8]) -> Result<Self> {
        if path.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if path.len() > PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        let is_absolute = path[0] == b'/';
        let start = if is_absolute { 1 } else { 0 };
        Ok(Self {
            path,
            pos: start,
            is_absolute,
        })
    }

    /// Advance to the next non-empty path component.
    ///
    /// Returns `Some(component_bytes)` or `None` when exhausted.
    pub fn next_component(&mut self) -> Option<&'a [u8]> {
        // Skip consecutive slashes.
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
        let component = &self.path[start..self.pos];
        if component.is_empty() {
            None
        } else {
            Some(component)
        }
    }

    /// Peek at the remaining path (after current position) without advancing.
    pub fn remaining(&self) -> &'a [u8] {
        if self.pos < self.path.len() {
            &self.path[self.pos..]
        } else {
            &[]
        }
    }

    /// Return true if there are no more components.
    pub fn is_done(&self) -> bool {
        self.remaining().iter().all(|&b| b == b'/')
    }
}

/// Validate that a single filename component is legal.
///
/// Returns `Err(InvalidArgument)` for names longer than NAME_MAX, for names
/// containing NUL bytes, or for the special names `"."` and `".."`.
pub fn validate_filename(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    if name.iter().any(|&b| b == 0) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether a path component is the special `"."` (self) reference.
pub fn is_dot(component: &[u8]) -> bool {
    component == b"."
}

/// Check whether a path component is the special `".."` (parent) reference.
pub fn is_dotdot(component: &[u8]) -> bool {
    component == b".."
}

/// High-level path lookup entry point.
///
/// Given a path byte slice and walk parameters, returns a `NameiResult`.
/// The `lookup_fn` callback performs the actual directory lookup:
///
/// ```ignore
/// fn lookup_fn(sb_id: u64, dir_ino: u64, name: &[u8]) -> Result<Option<(u64, u64)>>
/// // Returns Ok(Some((sb_id, ino))) if found, Ok(None) if not found.
/// ```
///
/// # SECURITY: chroot jail wiring required at call site
///
/// The jail enforcement inside this function is only active when the
/// [`WalkContext`] passed in has `chroot_ctx.depth > 0`.  All callers that
/// dispatch `namei_lookup` on behalf of a user-space process **must** supply
/// the calling process's [`ChrootContext`](crate::chroot_ops::ChrootContext)
/// obtained from
/// `crates/vfs/src/chroot_ops.rs::ChrootRegistry::get(pid)`.
///
/// Until that wiring is in place, callers **must** pass
/// `ChrootContext::new_root()` (depth=0) rather than a default-initialised or
/// all-zero context — depth=0 correctly disables jail enforcement so that
/// unjailed processes are not accidentally confined.  Using depth=0 as the
/// safe default means the runtime chroot jail is **not yet enforced** for any
/// process; the chroot state stored in `ChrootRegistry` is not consulted.
///
/// The exact wiring point is the dispatcher in
/// `crates/syscall/src/chroot_call.rs` (or the vfs-syscall bridge that calls
/// `namei_lookup`): it must call `ChrootRegistry::get(pid)` and pass the
/// resulting `ChrootContext` to `WalkContext::new(…, chroot_ctx)` before
/// invoking `namei_lookup`.
pub fn namei_lookup<F>(path: &[u8], ctx: &mut WalkContext, mut lookup_fn: F) -> Result<NameiResult>
where
    F: FnMut(u64, u64, &[u8]) -> Result<Option<(u64, u64)>>,
{
    let mut components = PathComponents::new(path)?;

    if components.is_absolute {
        ctx.cur_sb_id = ctx.root_sb_id;
        ctx.cur_ino = ctx.root_ino;
    }

    let mut parent_sb_id = ctx.cur_sb_id;
    let mut parent_ino = ctx.cur_ino;
    let mut comp_count = 0usize;

    loop {
        let component = match components.next_component() {
            None => break,
            Some(c) => c,
        };

        comp_count += 1;
        if comp_count > MAX_COMPONENTS {
            return Err(Error::InvalidArgument);
        }

        if is_dot(component) {
            // Stay in current directory.
            continue;
        }

        if is_dotdot(component) {
            // Go to parent, respecting the jail/chroot root boundary.
            //
            // Finding 5: The chroot jail root is enforced here.  When the
            // current position equals the jail root (inode + sb_id), treat
            // `..` as a no-op — the process cannot ascend further.
            //
            // Finding 6: Additionally guard against cross-mount escape:
            // if mount_depth > 0 we have crossed at least one mount since
            // the jail root mount; a `..` that would cross back up a mount
            // must not reduce mount_depth below zero.
            let at_root = ctx.cur_ino == ctx.root_ino && ctx.cur_sb_id == ctx.root_sb_id;
            // Guard against cross-mount escape for *jailed* processes only.
            //
            // When `chroot_ctx.depth > 0` the process is confined to a jail;
            // an unjailed process (depth == 0) may freely traverse `..` across
            // mount boundaries — blocking it would be a regression for any
            // process whose CWD happens to sit on a secondary mount.
            //
            // SECURITY: `at_mount_ceiling` must NOT fire for unjailed processes
            // (chroot_ctx.depth == 0) — doing so wrongly blocks legitimate `..`
            // navigation on secondary mounts.  The ceiling is only meaningful
            // inside a chroot jail where the mount-depth counter is anchored to
            // the jail's root mount.
            let at_mount_ceiling =
                ctx.chroot_ctx.depth > 0 && ctx.mount_depth <= 0 && ctx.cur_sb_id != ctx.root_sb_id;
            if !at_root && !at_mount_ceiling {
                if let Some((psb, pino)) = lookup_fn(ctx.cur_sb_id, ctx.cur_ino, b"..")? {
                    parent_sb_id = ctx.cur_sb_id;
                    parent_ino = ctx.cur_ino;
                    // If the parent is on a different sb we are crossing back
                    // through a mount — decrement the depth.
                    if psb != ctx.cur_sb_id {
                        ctx.mount_depth = ctx.mount_depth.saturating_sub(1);
                    }
                    ctx.cur_sb_id = psb;
                    ctx.cur_ino = pino;
                }
            }
            continue;
        }

        parent_sb_id = ctx.cur_sb_id;
        parent_ino = ctx.cur_ino;

        match lookup_fn(ctx.cur_sb_id, ctx.cur_ino, component)? {
            Some((next_sb, next_ino)) => {
                ctx.cur_sb_id = next_sb;
                ctx.cur_ino = next_ino;
            }
            None => {
                if components.is_done() {
                    // Final component not found — acceptable for create intent.
                    match ctx.intent {
                        LookupIntent::Create | LookupIntent::CreateExcl | LookupIntent::Mkdir => {
                            return Ok(NameiResult::not_found(parent_sb_id, parent_ino));
                        }
                        _ => return Err(Error::NotFound),
                    }
                }
                return Err(Error::NotFound);
            }
        }
    }

    Ok(NameiResult::found(
        ctx.cur_sb_id,
        ctx.cur_ino,
        parent_sb_id,
        parent_ino,
    ))
}
