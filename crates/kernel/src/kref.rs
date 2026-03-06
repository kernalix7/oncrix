// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel reference counting.
//!
//! `Kref` is a simple reference counter embedded in kernel
//! objects. When the count drops to zero, a release callback is
//! logically invoked to free the object. The implementation
//! includes saturation protection to prevent overflow.
//!
//! # Design
//!
//! ```text
//!   +--------+
//!   |  Kref  |
//!   |--------|
//!   | count  |  u32, starts at 1
//!   +--------+
//!
//!   kref_get() → count++
//!   kref_put() → count--; if 0 → release
//! ```
//!
//! # Saturation
//!
//! If `kref_get()` would overflow `u32::MAX`, the count is
//! saturated and a warning is recorded. This prevents wraparound
//! to zero which would cause a premature release.
//!
//! # Reference
//!
//! Linux `include/linux/kref.h`, `lib/kref.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Saturation limit (one below u32::MAX to detect overflow).
const SATURATION_LIMIT: u32 = u32::MAX - 1;

/// Maximum managed kref objects.
const MAX_KREFS: usize = 1024;

/// Maximum name length.
const _MAX_NAME_LEN: usize = 32;

// ======================================================================
// Kref
// ======================================================================

/// Kernel reference counter.
///
/// Starts at 1 on initialization. When decremented to 0, the
/// object should be released.
#[derive(Debug, Clone, Copy)]
pub struct Kref {
    /// Reference count.
    refcount: u32,
    /// Whether this kref is initialized.
    initialized: bool,
    /// Whether saturation has been reached.
    saturated: bool,
    /// Statistics: total get calls.
    stats_gets: u64,
    /// Statistics: total put calls.
    stats_puts: u64,
}

impl Kref {
    /// Creates a new uninitialized kref.
    pub const fn new() -> Self {
        Self {
            refcount: 0,
            initialized: false,
            saturated: false,
            stats_gets: 0,
            stats_puts: 0,
        }
    }

    /// Initializes the kref (sets count to 1).
    pub fn kref_init(&mut self) {
        self.refcount = 1;
        self.initialized = true;
        self.saturated = false;
        self.stats_gets = 0;
        self.stats_puts = 0;
    }

    /// Increments the reference count.
    ///
    /// Saturates at `SATURATION_LIMIT` to prevent overflow.
    pub fn kref_get(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.refcount == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.refcount >= SATURATION_LIMIT {
            self.saturated = true;
            return Ok(());
        }
        self.refcount += 1;
        self.stats_gets += 1;
        Ok(())
    }

    /// Increments the reference count only if it is not zero.
    ///
    /// Returns `true` if incremented, `false` if already zero.
    pub fn kref_get_unless_zero(&mut self) -> bool {
        if !self.initialized || self.refcount == 0 {
            return false;
        }
        if self.refcount >= SATURATION_LIMIT {
            self.saturated = true;
            return true;
        }
        self.refcount += 1;
        self.stats_gets += 1;
        true
    }

    /// Decrements the reference count.
    ///
    /// Returns `true` if the count reached zero (object should
    /// be released).
    pub fn kref_put(&mut self) -> Result<bool> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.refcount == 0 {
            return Err(Error::InvalidArgument);
        }
        // Saturated refs never reach zero.
        if self.saturated {
            return Ok(false);
        }
        self.refcount -= 1;
        self.stats_puts += 1;
        Ok(self.refcount == 0)
    }

    /// Reads the current reference count.
    pub fn kref_read(&self) -> u32 {
        self.refcount
    }

    /// Returns whether the kref is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether saturation has been reached.
    pub fn is_saturated(&self) -> bool {
        self.saturated
    }

    /// Returns total get calls.
    pub fn stats_gets(&self) -> u64 {
        self.stats_gets
    }

    /// Returns total put calls.
    pub fn stats_puts(&self) -> u64 {
        self.stats_puts
    }
}

// ======================================================================
// KrefTable — global registry
// ======================================================================

/// Global table of kref-tracked objects.
pub struct KrefTable {
    /// Entries.
    entries: [KrefEntry; MAX_KREFS],
    /// Number of active entries.
    count: usize,
}

/// Entry in the kref table.
struct KrefEntry {
    /// The kref.
    kref: Kref,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Name (for debugging).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Associated data.
    data: u64,
}

impl KrefEntry {
    const fn new() -> Self {
        Self {
            kref: Kref::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
            data: 0,
        }
    }
}

impl KrefTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { KrefEntry::new() }; MAX_KREFS],
            count: 0,
        }
    }

    /// Allocates a new kref-tracked object.
    pub fn alloc(&mut self, name: &[u8], data: u64) -> Result<usize> {
        if self.count >= MAX_KREFS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].allocated = true;
        self.entries[idx].kref.kref_init();
        self.entries[idx].data = data;
        let copy_len = name.len().min(32);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Increments the refcount of an entry.
    pub fn get_ref(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_KREFS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx].kref.kref_get()
    }

    /// Decrements the refcount. If it reaches zero, the entry
    /// is freed and `Ok(true)` is returned.
    pub fn put_ref(&mut self, idx: usize) -> Result<bool> {
        if idx >= MAX_KREFS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        let released = self.entries[idx].kref.kref_put()?;
        if released {
            self.entries[idx] = KrefEntry::new();
            self.count -= 1;
        }
        Ok(released)
    }

    /// Reads the refcount.
    pub fn read_ref(&self, idx: usize) -> Result<u32> {
        if idx >= MAX_KREFS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(self.entries[idx].kref.kref_read())
    }

    /// Returns the data associated with an entry.
    pub fn data(&self, idx: usize) -> Result<u64> {
        if idx >= MAX_KREFS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(self.entries[idx].data)
    }

    /// Returns the number of active entries.
    pub fn count(&self) -> usize {
        self.count
    }
}
