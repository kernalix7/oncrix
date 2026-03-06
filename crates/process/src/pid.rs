// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process and thread identifier newtypes.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

/// Process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Pid(u64);

impl Pid {
    /// The kernel process (PID 0).
    pub const KERNEL: Self = Self(0);

    /// Create a PID from a raw value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw PID value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PID({})", self.0)
    }
}

/// Thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Tid(u64);

impl Tid {
    /// Create a TID from a raw value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw TID value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TID({})", self.0)
    }
}

/// Atomic counter for generating unique PIDs.
static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// Atomic counter for generating unique TIDs.
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new unique PID.
///
/// # Panics
///
/// Panics if the PID space is exhausted (after 2^63 allocations).
/// In practice this is unreachable on any real system.
pub fn alloc_pid() -> Pid {
    let id = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    assert!(id < u64::MAX / 2, "PID space exhausted");
    Pid(id)
}

/// Allocate a new unique TID.
///
/// # Panics
///
/// Panics if the TID space is exhausted (after 2^63 allocations).
pub fn alloc_tid() -> Tid {
    let id = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    assert!(id < u64::MAX / 2, "TID space exhausted");
    Tid(id)
}
