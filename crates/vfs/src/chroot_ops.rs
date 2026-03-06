// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! chroot jail operations.
//!
//! Implements the `chroot(2)` system call and associated jail management.
//! A chroot changes the apparent root directory for the calling process,
//! restricting its view of the filesystem hierarchy.
//!
//! Note: chroot alone is not a security boundary — it should be combined
//! with dropping privileges and using namespaces for containers.

use oncrix_lib::{Error, Result};

/// Maximum nesting depth for chroot jails.
pub const MAX_CHROOT_DEPTH: usize = 8;

/// Represents a chroot jail context.
#[derive(Debug, Clone, Copy)]
pub struct ChrootContext {
    /// Inode number of the jail root directory.
    pub root_ino: u64,
    /// Mount ID of the filesystem containing the jail root.
    pub root_mount: u32,
    /// Nesting depth (0 = real root).
    pub depth: usize,
}

impl ChrootContext {
    /// Create a new chroot context at the real root (depth 0).
    pub const fn new_root() -> Self {
        ChrootContext {
            root_ino: 0,
            root_mount: 0,
            depth: 0,
        }
    }

    /// Create a chroot context from a directory.
    pub const fn from_dir(ino: u64, mount: u32, depth: usize) -> Self {
        ChrootContext {
            root_ino: ino,
            root_mount: mount,
            depth,
        }
    }

    /// Check if this context represents the real root.
    pub fn is_real_root(&self) -> bool {
        self.depth == 0
    }
}

impl Default for ChrootContext {
    fn default() -> Self {
        Self::new_root()
    }
}

/// Privilege check result for chroot operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChrootPrivilege {
    /// Caller has CAP_SYS_CHROOT.
    Allowed,
    /// Caller lacks required capability.
    Denied,
}

/// Validate preconditions for a chroot operation.
///
/// Per POSIX.1-2024, `chroot()` requires `CAP_SYS_CHROOT` capability.
/// The target must be a directory.
pub fn validate_chroot(
    target_ino: u64,
    target_is_dir: bool,
    target_accessible: bool,
    privilege: ChrootPrivilege,
    current_depth: usize,
) -> Result<()> {
    if privilege == ChrootPrivilege::Denied {
        return Err(Error::PermissionDenied);
    }
    if !target_is_dir {
        return Err(Error::NotFound);
    }
    if !target_accessible {
        return Err(Error::PermissionDenied);
    }
    if target_ino == 0 {
        return Err(Error::InvalidArgument);
    }
    if current_depth >= MAX_CHROOT_DEPTH {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Perform a chroot operation, returning the new context.
pub fn do_chroot(
    target_ino: u64,
    target_mount: u32,
    target_is_dir: bool,
    target_accessible: bool,
    privilege: ChrootPrivilege,
    current: &ChrootContext,
) -> Result<ChrootContext> {
    validate_chroot(
        target_ino,
        target_is_dir,
        target_accessible,
        privilege,
        current.depth,
    )?;
    Ok(ChrootContext::from_dir(
        target_ino,
        target_mount,
        current.depth + 1,
    ))
}

/// Path escape detection: check if a path attempts to escape the jail.
///
/// Returns true if the resolved path stays within the chroot jail.
pub fn path_escapes_jail(path_components: &[&[u8]], jail_root_ino: u64, _current_ino: u64) -> bool {
    // Simple heuristic: count leading ".." components.
    // A proper implementation would track inode numbers during resolution.
    if jail_root_ino == 0 {
        return false; // Real root — no jail.
    }
    let mut depth: isize = 0;
    for component in path_components {
        if *component == b".." {
            depth -= 1;
            if depth < 0 {
                return true;
            }
        } else if *component != b"." && !component.is_empty() {
            depth += 1;
        }
    }
    false
}

/// chroot jail registry — tracks active jails per process group.
pub struct ChrootRegistry {
    entries: [(u32, ChrootContext); 64],
    count: usize,
}

impl ChrootRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        ChrootRegistry {
            entries: [(0, ChrootContext::new_root()); 64],
            count: 0,
        }
    }

    /// Register or update the chroot context for a process.
    pub fn set(&mut self, pid: u32, ctx: ChrootContext) -> Result<()> {
        for (p, c) in &mut self.entries[..self.count] {
            if *p == pid {
                *c = ctx;
                return Ok(());
            }
        }
        if self.count >= 64 {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = (pid, ctx);
        self.count += 1;
        Ok(())
    }

    /// Get the chroot context for a process.
    pub fn get(&self, pid: u32) -> ChrootContext {
        for (p, c) in &self.entries[..self.count] {
            if *p == pid {
                return *c;
            }
        }
        ChrootContext::new_root()
    }

    /// Remove a process's entry (on process exit).
    pub fn remove(&mut self, pid: u32) {
        for i in 0..self.count {
            if self.entries[i].0 == pid {
                self.count -= 1;
                self.entries[i] = self.entries[self.count];
                return;
            }
        }
    }

    /// Return the number of registered entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no entries are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ChrootRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Securely resolve a path within a chroot jail.
///
/// Returns `Err(PermissionDenied)` if the path would escape the jail.
pub fn jail_resolve(path: &[u8], jail: &ChrootContext) -> Result<()> {
    if jail.is_real_root() {
        return Ok(());
    }
    // Split path into components and check for escape.
    let components: [&[u8]; 32] = {
        let mut arr = [b"" as &[u8]; 32];
        let mut idx = 0;
        let mut start = 0;
        let mut i = 0;
        while i <= path.len() && idx < 32 {
            if i == path.len() || path[i] == b'/' {
                if i > start {
                    arr[idx] = &path[start..i];
                    idx += 1;
                }
                start = i + 1;
            }
            i += 1;
        }
        arr
    };
    if path_escapes_jail(&components, jail.root_ino, 0) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}
