// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clone flags for `clone()` / `fork()` process/thread creation.
//!
//! These flags control which resources the new task shares with the
//! calling task, following the Linux/POSIX `clone(2)` convention.
//!
//! Reference: POSIX.1-2024 does not define `clone()`; these flags
//! follow the Linux ABI for compatibility.

use core::fmt;

/// Bitmask of clone flags.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CloneFlags(u64);

impl CloneFlags {
    /// Share virtual memory (threads within the same process).
    pub const CLONE_VM: Self = Self(0x0000_0100);

    /// Share filesystem information (root dir, cwd, umask).
    pub const CLONE_FS: Self = Self(0x0000_0200);

    /// Share the file descriptor table.
    pub const CLONE_FILES: Self = Self(0x0000_0400);

    /// Share signal handlers.
    pub const CLONE_SIGHAND: Self = Self(0x0000_0800);

    /// Set TLS for the child (the `tls` argument is the new TLS base).
    pub const CLONE_SETTLS: Self = Self(0x0008_0000);

    /// Store child TID at `child_tidptr` in child memory.
    pub const CLONE_CHILD_SETTID: Self = Self(0x0100_0000);

    /// Clear child TID at `child_tidptr` on child exit (for futex wake).
    pub const CLONE_CHILD_CLEARTID: Self = Self(0x0020_0000);

    /// Store child TID at `parent_tidptr` in parent memory.
    pub const CLONE_PARENT_SETTID: Self = Self(0x0010_0000);

    /// Create a new thread (combines VM + FS + FILES + SIGHAND + THREAD).
    pub const CLONE_THREAD: Self = Self(0x0001_0000);

    /// Share the signal handler table and blocked-signal mask.
    pub const CLONE_SIGNAL: Self = Self(0x0000_0800);

    /// Empty flags (plain fork semantics — copy everything).
    pub const EMPTY: Self = Self(0);

    /// Typical flags for `pthread_create()`:
    /// `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
    ///  | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID`.
    pub const PTHREAD_DEFAULT: Self = Self(
        Self::CLONE_VM.0
            | Self::CLONE_FS.0
            | Self::CLONE_FILES.0
            | Self::CLONE_SIGHAND.0
            | Self::CLONE_THREAD.0
            | Self::CLONE_SETTLS.0
            | Self::CLONE_PARENT_SETTID.0
            | Self::CLONE_CHILD_CLEARTID.0,
    );

    /// Create from a raw bitmask value.
    pub const fn from_raw(bits: u64) -> Self {
        Self(bits)
    }

    /// Return the raw bitmask value.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Test whether a specific flag is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for CloneFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let flags = [
            (Self::CLONE_VM, "VM"),
            (Self::CLONE_FS, "FS"),
            (Self::CLONE_FILES, "FILES"),
            (Self::CLONE_SIGHAND, "SIGHAND"),
            (Self::CLONE_THREAD, "THREAD"),
            (Self::CLONE_SETTLS, "SETTLS"),
            (Self::CLONE_PARENT_SETTID, "PARENT_SETTID"),
            (Self::CLONE_CHILD_SETTID, "CHILD_SETTID"),
            (Self::CLONE_CHILD_CLEARTID, "CHILD_CLEARTID"),
        ];
        write!(f, "CloneFlags(")?;
        for (flag, name) in flags {
            if self.contains(flag) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        if first {
            write!(f, "0")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for CloneFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// `arch_prctl()` sub-commands (x86_64).
///
/// Used to set/get the FS and GS segment bases for TLS.
pub mod arch_prctl {
    /// Set the FS base address (used for TLS by glibc/musl).
    pub const ARCH_SET_FS: u64 = 0x1002;
    /// Get the FS base address.
    pub const ARCH_GET_FS: u64 = 0x1003;
    /// Set the GS base address.
    pub const ARCH_SET_GS: u64 = 0x1001;
    /// Get the GS base address.
    pub const ARCH_GET_GS: u64 = 0x1004;
}
