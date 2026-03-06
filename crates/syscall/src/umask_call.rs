// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `umask` syscall handler — file creation mask management.
//!
//! Implements `umask(2)` per POSIX.1-2024.  Each process has an
//! independent file creation mask.  The mask is applied whenever a
//! file or directory is created: `effective_mode = requested_mode & ~umask`.
//!
//! The default mask is `0o022` (turn off write permission for group
//! and others), which is the conventional POSIX default.
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/umask.html` for the
//! authoritative specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum per-PID entries in the umask table.
const UMASK_TABLE_MAX: usize = 256;

/// Sentinel PID value indicating an empty table slot.
const EMPTY_PID: u64 = u64::MAX;

/// Default file creation mask (octal 022).
pub const UMASK_DEFAULT: u16 = 0o022;

/// Maximum valid umask value (all permission bits set).
pub const UMASK_MAX: u16 = 0o777;

// ---------------------------------------------------------------------------
// FileModeMask
// ---------------------------------------------------------------------------

/// A POSIX file creation mask.
///
/// Represents the `umask` value — bits that are always cleared from
/// the `mode` argument of `open(2)`, `mkdir(2)`, etc.
/// Only the low 9 bits (octal 0777) are meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileModeMask {
    /// The raw mask value (bits 0..8 only).
    pub mask: u16,
}

impl FileModeMask {
    /// Create a new `FileModeMask`.
    ///
    /// Returns `InvalidArgument` if `mask > 0o777`.
    pub fn new(mask: u16) -> Result<Self> {
        if mask > UMASK_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { mask })
    }

    /// Create the default mask (0o022) without validation.
    pub const fn default_mask() -> Self {
        Self {
            mask: UMASK_DEFAULT,
        }
    }

    /// Apply this mask to a file `mode`.
    ///
    /// Returns `mode & ~self.mask`, clamped to 12 bits (including
    /// the setuid/setgid/sticky bits in bits 9..11).
    pub const fn apply(self, mode: u16) -> u16 {
        mode & !(self.mask)
    }

    /// Return the raw mask value.
    pub const fn raw(self) -> u16 {
        self.mask
    }
}

impl Default for FileModeMask {
    fn default() -> Self {
        Self::default_mask()
    }
}

// ---------------------------------------------------------------------------
// UmaskEntry — internal table entry
// ---------------------------------------------------------------------------

/// Internal per-process entry in the [`UmaskTable`].
#[derive(Debug, Clone, Copy)]
struct UmaskEntry {
    /// Process identifier.
    pid: u64,
    /// Current file creation mask.
    mask: FileModeMask,
}

impl UmaskEntry {
    /// Create an empty (invalid) entry.
    const fn empty() -> Self {
        Self {
            pid: EMPTY_PID,
            mask: FileModeMask::default_mask(),
        }
    }

    /// Return `true` if this slot is occupied.
    const fn is_active(&self) -> bool {
        self.pid != EMPTY_PID
    }
}

impl Default for UmaskEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// UmaskStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the umask subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct UmaskStats {
    /// Total number of `umask` syscall invocations.
    pub total_calls: u64,
    /// Number of times the mask was actually changed (not just queried).
    pub mask_changes: u64,
}

// ---------------------------------------------------------------------------
// UmaskTable
// ---------------------------------------------------------------------------

/// Per-process file creation mask table.
///
/// Holds up to [`UMASK_TABLE_MAX`] entries.  Processes not present
/// in the table use [`UMASK_DEFAULT`].
pub struct UmaskTable {
    /// Fixed-size array of umask entries.
    entries: [UmaskEntry; UMASK_TABLE_MAX],
    /// Cumulative statistics.
    stats: UmaskStats,
}

impl UmaskTable {
    /// Create an empty table with all slots inactive.
    pub const fn new() -> Self {
        Self {
            entries: [const { UmaskEntry::empty() }; UMASK_TABLE_MAX],
            stats: UmaskStats {
                total_calls: 0,
                mask_changes: 0,
            },
        }
    }

    /// Return a snapshot of the current statistics.
    pub const fn stats(&self) -> &UmaskStats {
        &self.stats
    }

    // -- internal helpers --------------------------------------------------

    /// Find the slot index for `pid`, if present.
    fn find_by_pid(&self, pid: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_active() && e.pid == pid)
    }

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.is_active())
    }

    // -- public API --------------------------------------------------------

    /// Return the current umask for `pid`.
    ///
    /// Returns [`UMASK_DEFAULT`] if `pid` has no registered entry.
    pub fn get_umask(&self, pid: u64) -> u16 {
        self.find_by_pid(pid)
            .map(|i| self.entries[i].mask.raw())
            .unwrap_or(UMASK_DEFAULT)
    }

    /// Apply the umask of `pid` to `mode`.
    ///
    /// Equivalent to `mode & ~umask(pid)`.
    pub fn apply_umask(&self, pid: u64, mode: u16) -> u16 {
        let mask = self
            .find_by_pid(pid)
            .map(|i| self.entries[i].mask)
            .unwrap_or(FileModeMask::default_mask());
        mask.apply(mode)
    }

    /// Set a new umask for `pid`, returning the previous value.
    ///
    /// Creates a new entry if `pid` is not yet present.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — `new_mask > 0o777`.
    /// - `OutOfMemory`     — Table is full and `pid` is new.
    fn set_umask(&mut self, pid: u64, new_mask: u16) -> Result<u16> {
        let old_mask = self.get_umask(pid);

        let validated = FileModeMask::new(new_mask)?;

        let idx = if let Some(i) = self.find_by_pid(pid) {
            i
        } else {
            self.find_free().ok_or(Error::OutOfMemory)?
        };

        self.entries[idx] = UmaskEntry {
            pid,
            mask: validated,
        };

        if new_mask != old_mask {
            self.stats.mask_changes = self.stats.mask_changes.saturating_add(1);
        }

        Ok(old_mask)
    }
}

impl Default for UmaskTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Main `umask` syscall handler.
///
/// Sets the file creation mask for process `pid` to `new_mask` and
/// returns the **previous** mask value.
///
/// Per POSIX, `umask` always succeeds; however, this implementation
/// validates the range and returns an error for out-of-range values
/// to catch programming errors early.
///
/// # Arguments
///
/// - `table`    — The global umask table.
/// - `pid`      — PID of the calling process.
/// - `new_mask` — Desired new umask (must be <= `0o777`).
///
/// # Returns
///
/// The previous umask value.
///
/// # Errors
///
/// - `InvalidArgument` — `new_mask > 0o777`.
/// - `OutOfMemory`     — Table is full (first call for this PID).
pub fn do_umask(table: &mut UmaskTable, pid: u64, new_mask: u16) -> Result<u16> {
    table.stats.total_calls = table.stats.total_calls.saturating_add(1);
    table.set_umask(pid, new_mask)
}

/// Read the current umask for process `pid` without modifying it.
///
/// Returns [`UMASK_DEFAULT`] if `pid` has no registered entry.
pub fn get_umask(table: &UmaskTable, pid: u64) -> u16 {
    table.get_umask(pid)
}

/// Apply the umask of process `pid` to a file creation `mode`.
///
/// Returns `mode & ~umask`, which is the effective mode after
/// the creation mask has been applied.
pub fn apply_umask(table: &UmaskTable, pid: u64, mode: u16) -> u16 {
    table.apply_umask(pid, mode)
}
