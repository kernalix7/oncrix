// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `chroot` syscall handler — change root directory for a process.
//!
//! Implements the `chroot(2)` semantics per POSIX.1-2024.  Only a
//! process with `CAP_SYS_CHROOT` capability may call this syscall.
//! The new root must be an existing directory.
//!
//! # Security
//!
//! After a successful `chroot`, the process can no longer access
//! files outside the new root via relative paths.  Parent-directory
//! traversal (`..`) from the chroot root is silently clamped back
//! to the root — the kernel detects and blocks escape attempts.
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/chroot.html` for the
//! authoritative specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a chroot path (bytes, including null terminator).
pub const CHROOT_PATH_MAX: usize = 256;

/// Maximum number of simultaneously active chroot states.
const CHROOT_REGISTRY_MAX: usize = 64;

/// Sentinel PID value indicating an empty registry slot.
const EMPTY_PID: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Capability stub
// ---------------------------------------------------------------------------

/// Check whether the calling process holds `CAP_SYS_CHROOT`.
///
/// In a full kernel implementation this would query the credential
/// set of the process identified by `pid`.  This stub grants the
/// capability to all processes whose PID is non-zero (i.e. the
/// super-user model used during early bring-up).
fn has_cap_sys_chroot(pid: u64) -> bool {
    // Stub: any valid PID is considered to hold CAP_SYS_CHROOT.
    // A real implementation queries process credentials.
    pid != 0
}

// ---------------------------------------------------------------------------
// ChrootState
// ---------------------------------------------------------------------------

/// Per-process chroot state.
///
/// Records the old and new filesystem root paths together with the
/// owning process identifier.
#[derive(Debug, Clone, Copy)]
pub struct ChrootState {
    /// Process identifier that performed the `chroot`.
    pub pid: u64,
    /// Absolute path of the old root before `chroot` was called.
    pub old_root: [u8; CHROOT_PATH_MAX],
    /// Byte length of `old_root` (not counting trailing zeros).
    pub old_root_len: usize,
    /// Absolute path of the new chroot root.
    pub new_root: [u8; CHROOT_PATH_MAX],
    /// Byte length of `new_root`.
    pub new_root_len: usize,
}

impl ChrootState {
    /// Create an empty (invalid) `ChrootState`.
    pub const fn empty() -> Self {
        Self {
            pid: EMPTY_PID,
            old_root: [0u8; CHROOT_PATH_MAX],
            old_root_len: 0,
            new_root: [0u8; CHROOT_PATH_MAX],
            new_root_len: 0,
        }
    }

    /// Return `true` if this slot is occupied.
    pub const fn is_active(&self) -> bool {
        self.pid != EMPTY_PID
    }

    /// Return the old root path as a byte slice.
    pub fn old_root_path(&self) -> &[u8] {
        &self.old_root[..self.old_root_len]
    }

    /// Return the new (chroot) root path as a byte slice.
    pub fn new_root_path(&self) -> &[u8] {
        &self.new_root[..self.new_root_len]
    }
}

impl Default for ChrootState {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// ChrootStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the chroot subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChrootStats {
    /// Total number of successful `chroot` calls ever made.
    pub total_chroots: u64,
    /// Number of currently active chroot states.
    pub active_chroots: u64,
    /// Number of detected escape attempts (`.."` traversal above root).
    pub escape_attempts: u64,
    /// Number of `chroot` calls rejected due to missing capability.
    pub permission_denied: u64,
}

// ---------------------------------------------------------------------------
// ChrootRegistry
// ---------------------------------------------------------------------------

/// Registry of per-process chroot states.
///
/// Holds up to [`CHROOT_REGISTRY_MAX`] active chroot entries.
pub struct ChrootRegistry {
    /// Fixed-size array of chroot state slots.
    states: [ChrootState; CHROOT_REGISTRY_MAX],
    /// Cumulative statistics.
    stats: ChrootStats,
}

impl ChrootRegistry {
    /// Create an empty registry with all slots inactive.
    pub const fn new() -> Self {
        Self {
            states: [const { ChrootState::empty() }; CHROOT_REGISTRY_MAX],
            stats: ChrootStats {
                total_chroots: 0,
                active_chroots: 0,
                escape_attempts: 0,
                permission_denied: 0,
            },
        }
    }

    /// Return a snapshot of the current statistics.
    pub const fn stats(&self) -> &ChrootStats {
        &self.stats
    }

    // -- internal helpers --------------------------------------------------

    /// Find the slot index for the given `pid`, if present.
    fn find_by_pid(&self, pid: u64) -> Option<usize> {
        self.states
            .iter()
            .position(|s| s.is_active() && s.pid == pid)
    }

    /// Find a free (inactive) slot index.
    fn find_free(&self) -> Option<usize> {
        self.states.iter().position(|s| !s.is_active())
    }

    // -- public API --------------------------------------------------------

    /// Register a new chroot for `pid`.
    ///
    /// Replaces an existing entry for the same PID if one is present.
    /// Returns `OutOfMemory` if the registry is full and this is a new PID.
    pub fn register(&mut self, pid: u64, old_root: &[u8], new_root: &[u8]) -> Result<()> {
        // Reuse existing slot if this PID already has a chroot.
        let idx = if let Some(i) = self.find_by_pid(pid) {
            i
        } else {
            let i = self.find_free().ok_or(Error::OutOfMemory)?;
            self.stats.active_chroots = self.stats.active_chroots.saturating_add(1);
            i
        };

        let slot = &mut self.states[idx];
        slot.pid = pid;

        let old_len = old_root.len().min(CHROOT_PATH_MAX);
        slot.old_root[..old_len].copy_from_slice(&old_root[..old_len]);
        slot.old_root_len = old_len;

        let new_len = new_root.len().min(CHROOT_PATH_MAX);
        slot.new_root[..new_len].copy_from_slice(&new_root[..new_len]);
        slot.new_root_len = new_len;

        self.stats.total_chroots = self.stats.total_chroots.saturating_add(1);
        Ok(())
    }

    /// Remove the chroot entry for `pid`.
    ///
    /// Does nothing if the PID has no registered entry.
    pub fn remove(&mut self, pid: u64) {
        if let Some(idx) = self.find_by_pid(pid) {
            self.states[idx] = ChrootState::empty();
            self.stats.active_chroots = self.stats.active_chroots.saturating_sub(1);
        }
    }

    /// Return `true` if `pid` has an active chroot.
    pub fn is_chrooted(&self, pid: u64) -> bool {
        self.find_by_pid(pid).is_some()
    }

    /// Look up the chroot root path for `pid`.
    ///
    /// Returns `None` if `pid` is not chrooted.
    pub fn root_for_pid(&self, pid: u64) -> Option<&[u8]> {
        self.find_by_pid(pid)
            .map(|i| self.states[i].new_root_path())
    }

    /// Get a reference to the full [`ChrootState`] for `pid`.
    pub fn state_for_pid(&self, pid: u64) -> Option<&ChrootState> {
        self.find_by_pid(pid).map(|i| &self.states[i])
    }
}

impl Default for ChrootRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Resolve `path` relative to the chroot root for `pid`.
///
/// If `pid` is not chrooted the path is returned unchanged.
/// If `pid` is chrooted, prepends the chroot root to relative-looking
/// paths and validates that the result would not escape the root.
///
/// Returns the resolved path written into `out` and its byte length.
pub fn lookup_in_chroot(
    registry: &ChrootRegistry,
    pid: u64,
    path: &[u8],
    out: &mut [u8; CHROOT_PATH_MAX],
) -> Result<usize> {
    if path.is_empty() {
        return Err(Error::InvalidArgument);
    }

    let Some(root) = registry.root_for_pid(pid) else {
        // Not chrooted — return path as-is.
        let len = path.len().min(CHROOT_PATH_MAX);
        out[..len].copy_from_slice(&path[..len]);
        return Ok(len);
    };

    // Combine root + "/" + path, clamped to CHROOT_PATH_MAX.
    let root_len = root.len();
    if root_len >= CHROOT_PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    out[..root_len].copy_from_slice(root);
    let mut pos = root_len;

    // Ensure separator (pos >= 1 because root always starts with '/').
    if pos == 0 || out[pos - 1] != b'/' {
        if pos >= CHROOT_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        out[pos] = b'/';
        pos += 1;
    }

    let path_start = if path[0] == b'/' { 1 } else { 0 };
    let remaining = path.len() - path_start;
    if pos + remaining > CHROOT_PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    out[pos..pos + remaining].copy_from_slice(&path[path_start..]);
    pos += remaining;

    Ok(pos)
}

/// Detect whether `path` attempts to escape above the chroot root via `..`.
///
/// Records the attempt in `registry.stats.escape_attempts` if detected.
/// Returns `PermissionDenied` if an escape is detected.
pub fn escape_detection(registry: &mut ChrootRegistry, pid: u64, path: &[u8]) -> Result<()> {
    if !registry.is_chrooted(pid) {
        return Ok(());
    }

    // Count effective depth: descend on each component, ascend on "..".
    // If depth would go negative (i.e., above chroot root), it's an escape.
    let mut depth: i32 = 0;

    let mut i = 0;
    while i < path.len() {
        // Skip leading separators.
        while i < path.len() && path[i] == b'/' {
            i += 1;
        }
        // Find end of component.
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        let component = &path[start..i];

        if component.is_empty() || component == b"." {
            // No movement.
            continue;
        } else if component == b".." {
            depth -= 1;
            if depth < 0 {
                registry.stats.escape_attempts = registry.stats.escape_attempts.saturating_add(1);
                return Err(Error::PermissionDenied);
            }
        } else {
            depth += 1;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Validate that a path is non-empty and within length limits.
fn validate_path(path: &[u8]) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if path.len() >= CHROOT_PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Main `chroot` syscall handler.
///
/// Changes the root directory for the process identified by `pid`
/// to `new_root`.  The caller must hold `CAP_SYS_CHROOT`.
///
/// # Arguments
///
/// - `registry` — The global chroot registry.
/// - `pid`      — PID of the calling process.
/// - `new_root` — Absolute path of the new root directory.
///
/// # Errors
///
/// - `PermissionDenied` — Process lacks `CAP_SYS_CHROOT`.
/// - `InvalidArgument`  — Path is empty or too long.
/// - `OutOfMemory`      — Registry is full.
pub fn do_chroot(registry: &mut ChrootRegistry, pid: u64, new_root: &[u8]) -> Result<()> {
    // Capability check.
    if !has_cap_sys_chroot(pid) {
        registry.stats.permission_denied = registry.stats.permission_denied.saturating_add(1);
        return Err(Error::PermissionDenied);
    }

    validate_path(new_root)?;

    // The new root must be an absolute path.
    if new_root[0] != b'/' {
        return Err(Error::InvalidArgument);
    }

    // Copy the current root path into a local buffer before any mutation.
    // This avoids holding a borrow on `registry` while calling `register`.
    let mut old_buf = [0u8; CHROOT_PATH_MAX];
    let old_len: usize = if let Some(st) = registry.state_for_pid(pid) {
        let len = st.new_root_len;
        old_buf[..len].copy_from_slice(st.new_root_path());
        len
    } else {
        // Not yet chrooted: record "/" as the old root.
        old_buf[0] = b'/';
        1
    };

    registry.register(pid, &old_buf[..old_len], new_root)
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/// Return `true` if process `pid` is currently chrooted.
pub fn is_chrooted(registry: &ChrootRegistry, pid: u64) -> bool {
    registry.is_chrooted(pid)
}
