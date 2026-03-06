// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pivot-root syscall handler.
//!
//! Implements `pivot_root(2)` which moves the current root filesystem
//! mount to `put_old` and makes `new_root` the new root filesystem.
//!
//! This is the mechanism used by container runtimes and init systems
//! to transition from the initial ramfs to the real root filesystem.
//!
//! # Validation Requirements (Linux/kernel convention)
//!
//! 1. Caller must have `CAP_SYS_ADMIN` (modelled as `is_privileged`).
//! 2. `new_root` must be a mount point and must not be the same
//!    filesystem as the current root.
//! 3. `put_old` must be under `new_root`.
//! 4. The current root must not be on a shared mount (not enforced here).
//!
//! # POSIX Reference
//!
//! `pivot_root` is a Linux extension; POSIX does not define it.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum path length for a mount point path (including null terminator).
pub const MOUNT_PATH_MAX: usize = 256;

/// Maximum number of simultaneously tracked pivot operations.
const PIVOT_REGISTRY_MAX: usize = 8;

// ---------------------------------------------------------------------------
// MountPoint
// ---------------------------------------------------------------------------

/// Describes a filesystem mount point.
#[derive(Clone, Copy)]
pub struct MountPoint {
    /// Absolute path of the mount point (null-terminated).
    pub path: [u8; MOUNT_PATH_MAX],
    /// Byte length of `path` (not counting null terminator).
    pub path_len: usize,
    /// Unique mount identifier assigned by the VFS layer.
    pub mount_id: u32,
    /// Device identifier (major:minor encoded as `(major << 20) | minor`).
    pub dev_id: u64,
    /// Mount flags (MS_RDONLY, MS_NOSUID, etc.).
    pub flags: u32,
}

impl MountPoint {
    /// Create a zero-initialised `MountPoint`.
    pub const fn new() -> Self {
        Self {
            path: [0u8; MOUNT_PATH_MAX],
            path_len: 0,
            mount_id: 0,
            dev_id: 0,
            flags: 0,
        }
    }

    /// Return the path as a byte slice (without null terminator).
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Set the path from a byte slice.
    ///
    /// Returns `InvalidArgument` if the path is empty or exceeds
    /// `MOUNT_PATH_MAX - 1` bytes.
    pub fn set_path(&mut self, path: &[u8]) -> Result<()> {
        if path.is_empty() || path.len() >= MOUNT_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        self.path[..path.len()].copy_from_slice(path);
        self.path[path.len()] = 0; // null terminator
        self.path_len = path.len();
        Ok(())
    }

    /// Return `true` if this mount point's path starts with the given prefix.
    pub fn is_under(&self, prefix: &MountPoint) -> bool {
        let our_path = self.path_bytes();
        let their_path = prefix.path_bytes();

        if our_path.len() < their_path.len() {
            return false;
        }

        // The prefix must match byte-for-byte.
        if &our_path[..their_path.len()] != their_path {
            return false;
        }

        // Either exact match or the next character is a `/`.
        our_path.len() == their_path.len() || our_path[their_path.len()] == b'/'
    }
}

impl Default for MountPoint {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PivotRootState
// ---------------------------------------------------------------------------

/// State captured for a single pivot-root operation.
///
/// Retained for potential rollback or audit logging.
#[derive(Clone, Copy)]
pub struct PivotRootState {
    /// Mount ID of the old root before the pivot.
    pub old_root_mount_id: u32,
    /// Mount ID of the new root after the pivot.
    pub new_root_mount_id: u32,
    /// PID of the process that performed the pivot.
    pub initiator_pid: u32,
    /// Snapshot of the new root path.
    pub new_root: MountPoint,
    /// Snapshot of the put-old path.
    pub put_old: MountPoint,
    /// Whether this state slot is occupied.
    active: bool,
}

impl PivotRootState {
    /// Create an empty (inactive) state.
    const fn new() -> Self {
        Self {
            old_root_mount_id: 0,
            new_root_mount_id: 0,
            initiator_pid: 0,
            new_root: MountPoint::new(),
            put_old: MountPoint::new(),
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PivotRootRegistry
// ---------------------------------------------------------------------------

/// Registry tracking recent pivot-root operations.
///
/// Holds up to [`PIVOT_REGISTRY_MAX`] entries.  Used for audit trails
/// and potential rollback.
pub struct PivotRootRegistry {
    entries: [PivotRootState; PIVOT_REGISTRY_MAX],
    count: usize,
}

impl PivotRootRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { PivotRootState::new() }; PIVOT_REGISTRY_MAX],
            count: 0,
        }
    }

    /// Return the number of recorded pivots.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Record a completed pivot operation.
    ///
    /// Returns `OutOfMemory` if the registry is full.
    pub fn record(&mut self, state: PivotRootState) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if !entry.active {
                *entry = state;
                entry.active = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a pivot record by initiator PID.
    ///
    /// Returns `NotFound` if no matching record exists.
    pub fn remove_by_pid(&mut self, pid: u32) -> Result<PivotRootState> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.active && e.initiator_pid == pid);

        match pos {
            Some(i) => {
                let state = self.entries[i];
                self.entries[i].active = false;
                self.count = self.count.saturating_sub(1);
                Ok(state)
            }
            None => Err(Error::NotFound),
        }
    }

    /// Look up a pivot record by initiator PID.
    pub fn find_by_pid(&self, pid: u32) -> Option<&PivotRootState> {
        self.entries
            .iter()
            .find(|e| e.active && e.initiator_pid == pid)
    }
}

impl Default for PivotRootRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate an absolute path: must start with `/` and fit in `MOUNT_PATH_MAX`.
fn validate_path(path: &[u8]) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if path[0] != b'/' {
        return Err(Error::InvalidArgument);
    }
    if path.len() >= MOUNT_PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Verify that `put_old` is located underneath `new_root`.
///
/// Returns `InvalidArgument` if not, per Linux `pivot_root(2)`.
fn check_put_old_under_new_root(new_root: &MountPoint, put_old: &MountPoint) -> Result<()> {
    if !put_old.is_under(new_root) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Verify that `new_root` is on a different filesystem than the current root.
///
/// Returns `InvalidArgument` if both are on the same device.
fn check_different_fs(current_root_dev: u64, new_root: &MountPoint) -> Result<()> {
    if new_root.dev_id == current_root_dev {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Verify that a path resolves to a mount point.
///
/// Returns `InvalidArgument` if `mount_id` is zero (convention: 0 = not a mountpoint).
fn check_is_mountpoint(mp: &MountPoint) -> Result<()> {
    if mp.mount_id == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core pivot steps (stubs)
// ---------------------------------------------------------------------------

/// Move the current root to `put_old`.
///
/// Stub: in a real kernel this calls `do_move_mount` on the rootfs.
fn move_old_root_to_put_old(put_old: &MountPoint, current_root_mount_id: u32) -> Result<()> {
    let _ = (put_old, current_root_mount_id);
    // Stub: VFS move_mount(old_root, put_old_path).
    Ok(())
}

/// Install `new_root` as the process root.
///
/// Stub: in a real kernel this sets `fs->root` and `fs->pwd`.
fn install_new_root(new_root: &MountPoint) -> Result<()> {
    let _ = new_root;
    // Stub: VFS set_root(new_root_path).
    Ok(())
}

/// Update the current working directory if it was under the old root.
///
/// Stub: in a real kernel this calls `chroot_fs_refs`.
fn update_cwd(new_root: &MountPoint) -> Result<()> {
    let _ = new_root;
    // Stub: chdir to new root if cwd was on old root.
    Ok(())
}

// ---------------------------------------------------------------------------
// Primary handler
// ---------------------------------------------------------------------------

/// `pivot_root(2)` — change the root filesystem.
///
/// # Arguments
///
/// - `new_root_path` — path to the directory that becomes the new root.
/// - `put_old_path` — path (under `new_root`) where the old root is moved.
/// - `is_privileged` — `true` when the caller has `CAP_SYS_ADMIN`.
/// - `initiator_pid` — PID of the calling process.
/// - `current_root` — the current root mount point.
/// - `registry` — pivot operation tracking registry.
///
/// # Errors
///
/// - `PermissionDenied` — caller lacks `CAP_SYS_ADMIN`.
/// - `InvalidArgument` — paths invalid, not mount points, on same fs, or
///                       `put_old` is not under `new_root`.
/// - `NotFound` — path does not exist (stub: mount_id == 0).
/// - `Busy` — old root is currently busy (stub: not enforced).
pub fn do_pivot_root(
    new_root_path: &[u8],
    put_old_path: &[u8],
    is_privileged: bool,
    initiator_pid: u32,
    current_root: &MountPoint,
    registry: &mut PivotRootRegistry,
) -> Result<()> {
    // 1. Privilege check.
    if !is_privileged {
        return Err(Error::PermissionDenied);
    }

    // 2. Path validation.
    validate_path(new_root_path)?;
    validate_path(put_old_path)?;

    // 3. Build MountPoint descriptors from the provided paths.
    //    In a real kernel, VFS lookup resolves these to dentry/vfsmount pairs.
    let mut new_root = MountPoint::new();
    new_root.set_path(new_root_path)?;
    // Stub: assign a synthetic mount_id; real code gets it from VFS lookup.
    new_root.mount_id = simple_path_hash(new_root_path) | 1; // ensure non-zero
    new_root.dev_id = new_root.mount_id as u64; // stub: dev_id == mount_id

    let mut put_old = MountPoint::new();
    put_old.set_path(put_old_path)?;
    put_old.mount_id = simple_path_hash(put_old_path) | 2;
    put_old.dev_id = new_root.dev_id; // put_old is on the new_root fs

    // 4. Validate that both paths are mount points.
    check_is_mountpoint(&new_root)?;
    check_is_mountpoint(&put_old)?;

    // 5. new_root must be on a different filesystem than the current root.
    check_different_fs(current_root.dev_id, &new_root)?;

    // 6. put_old must be under new_root.
    check_put_old_under_new_root(&new_root, &put_old)?;

    // 7. Record the old root mount ID before overwriting.
    let old_root_mount_id = current_root.mount_id;

    // 8. Move the old root to put_old.
    move_old_root_to_put_old(&put_old, old_root_mount_id)?;

    // 9. Install new_root.
    install_new_root(&new_root)?;

    // 10. Update cwd if necessary.
    update_cwd(&new_root)?;

    // 11. Record the operation.
    let state = PivotRootState {
        old_root_mount_id,
        new_root_mount_id: new_root.mount_id,
        initiator_pid,
        new_root,
        put_old,
        active: true,
    };
    registry.record(state)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Simple djb2-style hash of a byte slice, used as a synthetic mount ID.
///
/// Only used in the stub implementation where VFS lookup is absent.
fn simple_path_hash(path: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in path {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    // Ensure non-zero (zero means "not a mount point" in our convention).
    if h == 0 { 1 } else { h }
}

// ---------------------------------------------------------------------------
// Additional helpers exposed for VFS integration
// ---------------------------------------------------------------------------

/// Build a `MountPoint` from a path and explicit VFS-resolved identifiers.
///
/// Used by the VFS layer when it has already performed a path lookup and
/// can supply real mount metadata.
pub fn make_mount_point(path: &[u8], mount_id: u32, dev_id: u64, flags: u32) -> Result<MountPoint> {
    validate_path(path)?;
    let mut mp = MountPoint::new();
    mp.set_path(path)?;
    mp.mount_id = mount_id;
    mp.dev_id = dev_id;
    mp.flags = flags;
    Ok(mp)
}

/// Return `true` if the given path is the filesystem root (`"/"`).
pub fn is_fs_root(path: &[u8]) -> bool {
    path == b"/"
}

/// Return `true` if `child_path` descends from (or equals) `parent_path`.
///
/// Both paths must be absolute.
pub fn path_is_under(child_path: &[u8], parent_path: &[u8]) -> bool {
    if child_path.len() < parent_path.len() {
        return false;
    }
    if &child_path[..parent_path.len()] != parent_path {
        return false;
    }
    child_path.len() == parent_path.len() || child_path[parent_path.len()] == b'/'
}
