// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Security identifier (SecID) allocator.
//!
//! Assigns unique, monotonically increasing 32-bit identifiers to
//! security labels (SELinux contexts, SMACK labels, AppArmor profiles,
//! etc.). Multiple LSMs share the same SecID space so that a single
//! ID can tag an inode, socket, or IPC object regardless of which
//! LSM originally created it.
//!
//! # Design
//!
//! ```text
//! SecIdAllocator
//!  ├── entries: [SecIdEntry; MAX_ENTRIES]
//!  ├── next_id: u32
//!  └── nr_allocated: usize
//!
//! SecIdEntry
//!  ├── sec_id: u32
//!  ├── label_hash: u64
//!  ├── lsm: LsmType
//!  └── ref_count: u32
//! ```
//!
//! The allocator de-duplicates: requesting a SecID for an already
//! known label returns the existing ID and increments its reference
//! count.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum security ID entries.
const MAX_ENTRIES: usize = 4096;

/// Invalid / unassigned SecID.
const SECID_INVALID: u32 = 0;

/// First valid SecID value.
const SECID_FIRST: u32 = 1;

// ======================================================================
// Types
// ======================================================================

/// Linux Security Module type that owns a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmType {
    /// SELinux.
    SeLinux,
    /// SMACK.
    Smack,
    /// AppArmor.
    AppArmor,
    /// TOMOYO.
    Tomoyo,
    /// Landlock.
    Landlock,
    /// Integrity Measurement Architecture.
    Ima,
    /// Unspecified / generic.
    Generic,
}

impl Default for LsmType {
    fn default() -> Self {
        Self::Generic
    }
}

/// A single SecID allocation entry.
#[derive(Debug, Clone, Copy)]
pub struct SecIdEntry {
    /// The allocated security identifier.
    pub sec_id: u32,
    /// Hash of the security label string.
    pub label_hash: u64,
    /// LSM that owns this label.
    pub lsm: LsmType,
    /// Reference count (number of objects using this SecID).
    pub ref_count: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl SecIdEntry {
    /// Creates an empty entry.
    pub const fn new() -> Self {
        Self {
            sec_id: SECID_INVALID,
            label_hash: 0,
            lsm: LsmType::Generic,
            ref_count: 0,
            active: false,
        }
    }
}

impl Default for SecIdEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Lookup result for a SecID query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    /// Found an existing entry; SecID returned.
    Found(u32),
    /// No entry matched.
    NotFound,
}

impl Default for LookupResult {
    fn default() -> Self {
        Self::NotFound
    }
}

/// The SecID allocator.
pub struct SecIdAllocator {
    /// Allocation table.
    entries: [SecIdEntry; MAX_ENTRIES],
    /// Next SecID to allocate.
    next_id: u32,
    /// Number of active allocations.
    nr_allocated: usize,
}

impl SecIdAllocator {
    /// Creates a new SecID allocator.
    pub const fn new() -> Self {
        Self {
            entries: [SecIdEntry::new(); MAX_ENTRIES],
            next_id: SECID_FIRST,
            nr_allocated: 0,
        }
    }

    /// Allocates or reuses a SecID for the given label hash.
    ///
    /// If `label_hash` already has a SecID, increments the reference
    /// count and returns the existing ID. Otherwise allocates a new
    /// one.
    pub fn allocate(&mut self, label_hash: u64, lsm: LsmType) -> Result<u32> {
        // De-duplicate: check if this label already exists.
        if let Some(idx) = self.find_by_hash(label_hash, lsm) {
            self.entries[idx].ref_count += 1;
            return Ok(self.entries[idx].sec_id);
        }

        if self.nr_allocated >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let sec_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == SECID_INVALID {
            self.next_id = SECID_FIRST;
        }

        for entry in &mut self.entries {
            if !entry.active {
                *entry = SecIdEntry {
                    sec_id,
                    label_hash,
                    lsm,
                    ref_count: 1,
                    active: true,
                };
                self.nr_allocated += 1;
                return Ok(sec_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Releases a reference to a SecID.
    ///
    /// When the reference count drops to zero the entry is freed.
    pub fn release(&mut self, sec_id: u32) -> Result<()> {
        let idx = self.find_by_id(sec_id).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        entry.ref_count = entry.ref_count.saturating_sub(1);
        if entry.ref_count == 0 {
            entry.active = false;
            self.nr_allocated = self.nr_allocated.saturating_sub(1);
        }
        Ok(())
    }

    /// Looks up a SecID by label hash and LSM type.
    pub fn lookup(&self, label_hash: u64, lsm: LsmType) -> LookupResult {
        match self.find_by_hash(label_hash, lsm) {
            Some(idx) => LookupResult::Found(self.entries[idx].sec_id),
            None => LookupResult::NotFound,
        }
    }

    /// Looks up an entry by SecID and returns its label hash.
    pub fn get_label_hash(&self, sec_id: u32) -> Result<u64> {
        let idx = self.find_by_id(sec_id).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].label_hash)
    }

    /// Returns the LSM type that owns a SecID.
    pub fn get_lsm_type(&self, sec_id: u32) -> Result<LsmType> {
        let idx = self.find_by_id(sec_id).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].lsm)
    }

    /// Returns the reference count of a SecID.
    pub fn ref_count(&self, sec_id: u32) -> Result<u32> {
        let idx = self.find_by_id(sec_id).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].ref_count)
    }

    /// Returns the number of active allocations.
    pub fn nr_allocated(&self) -> usize {
        self.nr_allocated
    }

    /// Returns the next ID that will be allocated.
    pub fn next_id(&self) -> u32 {
        self.next_id
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_by_hash(&self, label_hash: u64, lsm: LsmType) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.label_hash == label_hash && e.lsm == lsm)
    }

    fn find_by_id(&self, sec_id: u32) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.sec_id == sec_id)
    }
}

impl Default for SecIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}
