// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Path resolution utilities.
//!
//! Provides allocation-free path parsing and component iteration utilities
//! used by the VFS path resolution engine. These functions handle POSIX
//! path semantics including `.` and `..` components, trailing slashes,
//! and symlink depth tracking.

use oncrix_lib::{Error, Result};

/// Maximum number of path components in a single resolution.
pub const MAX_PATH_COMPONENTS: usize = 64;
/// Maximum symlink depth allowed during path resolution (POSIX SYMLOOP_MAX).
pub const SYMLOOP_MAX: usize = 40;
/// Maximum length of a path component (POSIX NAME_MAX).
pub const NAME_MAX: usize = 255;

/// A single path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component<'a> {
    /// Root component (`/` at the start of an absolute path).
    Root,
    /// Current directory (`.`).
    CurrentDir,
    /// Parent directory (`..`).
    ParentDir,
    /// Normal name component.
    Normal(&'a [u8]),
}

impl<'a> Component<'a> {
    /// Return the byte representation.
    pub fn as_bytes(self) -> &'a [u8] {
        match self {
            Component::Root => b"/",
            Component::CurrentDir => b".",
            Component::ParentDir => b"..",
            Component::Normal(s) => s,
        }
    }

    /// Check if this component requires directory traversal.
    pub fn is_traversal(self) -> bool {
        matches!(self, Component::ParentDir)
    }
}

/// Iterator over path components.
pub struct ComponentIter<'a> {
    path: &'a [u8],
    pos: usize,
    root_emitted: bool,
}

impl<'a> ComponentIter<'a> {
    /// Create a new component iterator.
    pub fn new(path: &'a [u8]) -> Self {
        ComponentIter {
            path,
            pos: 0,
            root_emitted: false,
        }
    }
}

impl<'a> Iterator for ComponentIter<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == 0 && !self.root_emitted && self.path.first() == Some(&b'/') {
            self.root_emitted = true;
            self.pos = 1;
            return Some(Component::Root);
        }
        // Skip slashes.
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
        let part = &self.path[start..self.pos];
        Some(match part {
            b"." => Component::CurrentDir,
            b".." => Component::ParentDir,
            other => Component::Normal(other),
        })
    }
}

/// Path resolution flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolveFlags(pub u32);

impl ResolveFlags {
    /// Do not follow the final symlink (for lstat, lchown, etc.).
    pub const NO_FOLLOW_FINAL: u32 = 1 << 0;
    /// Return an error if the final component does not exist.
    pub const REQUIRE_EXIST: u32 = 1 << 1;
    /// Target must be a directory.
    pub const REQUIRE_DIR: u32 = 1 << 2;
    /// Prevent escaping the starting mount point.
    pub const IN_ROOT: u32 = 1 << 3;

    /// Check if NO_FOLLOW_FINAL is set.
    pub fn no_follow_final(self) -> bool {
        self.0 & Self::NO_FOLLOW_FINAL != 0
    }

    /// Check if REQUIRE_EXIST is set.
    pub fn require_exist(self) -> bool {
        self.0 & Self::REQUIRE_EXIST != 0
    }

    /// Check if REQUIRE_DIR is set.
    pub fn require_dir(self) -> bool {
        self.0 & Self::REQUIRE_DIR != 0
    }
}

/// Resolved path state returned by the path walker.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedPath {
    /// Inode number of the resolved target.
    pub ino: u64,
    /// Mount ID of the resolved target.
    pub mount_id: u32,
    /// Whether the target is a directory.
    pub is_dir: bool,
    /// Whether the last component was a symlink (before following).
    pub was_symlink: bool,
    /// Number of symlinks traversed during resolution.
    pub symlink_count: usize,
}

impl ResolvedPath {
    /// Create a new resolved path.
    pub const fn new(ino: u64, mount_id: u32, is_dir: bool) -> Self {
        ResolvedPath {
            ino,
            mount_id,
            is_dir,
            was_symlink: false,
            symlink_count: 0,
        }
    }
}

/// Symlink depth tracker.
#[derive(Debug, Clone, Copy, Default)]
pub struct SymlinkDepth {
    count: usize,
}

impl SymlinkDepth {
    /// Create a new tracker.
    pub const fn new() -> Self {
        SymlinkDepth { count: 0 }
    }

    /// Increment and check symlink depth.
    pub fn follow(&mut self) -> Result<()> {
        self.count += 1;
        if self.count > SYMLOOP_MAX {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Return current depth.
    pub fn depth(&self) -> usize {
        self.count
    }
}

/// Validate a path component name.
///
/// Returns `Err(InvalidArgument)` for names that are too long or
/// contain NUL bytes.
pub fn validate_component(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if name.len() > NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    if name.contains(&0u8) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Normalize a path by resolving `.` and collapsing multiple slashes.
///
/// Writes the normalized path into `out` and returns the length.
/// Does NOT resolve `..` (that requires inode knowledge).
pub fn normalize_path(path: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut pos = 0;
    let is_absolute = path.first() == Some(&b'/');
    if is_absolute {
        if pos >= out.len() {
            return Err(Error::InvalidArgument);
        }
        out[pos] = b'/';
        pos += 1;
    }
    let mut first = true;
    for component in ComponentIter::new(path) {
        match component {
            Component::Root | Component::CurrentDir => continue,
            Component::ParentDir => {
                // Write literally; caller handles inode-level resolution.
                let bytes = b"..";
                if !first {
                    if pos >= out.len() {
                        return Err(Error::InvalidArgument);
                    }
                    out[pos] = b'/';
                    pos += 1;
                }
                if pos + bytes.len() > out.len() {
                    return Err(Error::InvalidArgument);
                }
                out[pos..pos + bytes.len()].copy_from_slice(bytes);
                pos += bytes.len();
                first = false;
            }
            Component::Normal(name) => {
                if !first {
                    if pos >= out.len() {
                        return Err(Error::InvalidArgument);
                    }
                    out[pos] = b'/';
                    pos += 1;
                }
                if pos + name.len() > out.len() {
                    return Err(Error::InvalidArgument);
                }
                out[pos..pos + name.len()].copy_from_slice(name);
                pos += name.len();
                first = false;
            }
        }
    }
    if pos == 0 {
        if pos >= out.len() {
            return Err(Error::InvalidArgument);
        }
        out[pos] = b'.';
        pos += 1;
    }
    Ok(pos)
}

/// Split a path into its directory part and final component.
///
/// Returns `(dir, name)` slices.
/// For `/foo/bar`, returns (`/foo`, `bar`).
/// For `/foo`, returns (`/`, `foo`).
pub fn split_path(path: &[u8]) -> (&[u8], &[u8]) {
    // Find last slash.
    let last_slash = path.iter().rposition(|&b| b == b'/');
    match last_slash {
        None => (b".", path),
        Some(0) => (&path[..1], &path[1..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
    }
}
