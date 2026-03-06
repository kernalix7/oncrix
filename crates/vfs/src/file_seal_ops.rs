// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File sealing operations for anonymous files and memfd.
//!
//! File seals prevent certain operations from being performed on a file
//! descriptor after the seal is applied. This is used by `memfd_create`
//! to allow a process to hand off a memory buffer that the receiver cannot
//! tamper with.
//!
//! Seals are additive — once applied they cannot be removed.

use oncrix_lib::{Error, Result};

/// File seal flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileSeal(pub u32);

impl FileSeal {
    /// Prevent adding new seals.
    pub const F_SEAL_SEAL: u32 = 0x0001;
    /// Prevent shrinking the file.
    pub const F_SEAL_SHRINK: u32 = 0x0002;
    /// Prevent growing the file.
    pub const F_SEAL_GROW: u32 = 0x0004;
    /// Prevent any writes to the file.
    pub const F_SEAL_WRITE: u32 = 0x0008;
    /// Prevent future write mappings.
    pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;

    /// All known seal bits.
    pub const ALL_KNOWN: u32 = 0x001F;

    /// Check if the seal-of-seals is set.
    pub fn has_seal_seal(self) -> bool {
        self.0 & Self::F_SEAL_SEAL != 0
    }

    /// Check if shrink seal is set.
    pub fn has_shrink(self) -> bool {
        self.0 & Self::F_SEAL_SHRINK != 0
    }

    /// Check if grow seal is set.
    pub fn has_grow(self) -> bool {
        self.0 & Self::F_SEAL_GROW != 0
    }

    /// Check if write seal is set.
    pub fn has_write(self) -> bool {
        self.0 & Self::F_SEAL_WRITE != 0
    }

    /// Check if future-write seal is set.
    pub fn has_future_write(self) -> bool {
        self.0 & Self::F_SEAL_FUTURE_WRITE != 0
    }

    /// Return the union of two seal sets.
    pub fn union(self, other: FileSeal) -> FileSeal {
        FileSeal(self.0 | other.0)
    }
}

/// Seal state for a single file.
#[derive(Debug, Clone, Copy, Default)]
pub struct SealState {
    /// Current set of active seals.
    pub seals: FileSeal,
    /// Number of writable memory mappings (prevents adding F_SEAL_WRITE
    /// while any such mapping exists).
    pub writable_maps: u32,
}

impl SealState {
    /// Create a new seal state with no seals.
    pub const fn new() -> Self {
        SealState {
            seals: FileSeal(0),
            writable_maps: 0,
        }
    }

    /// Attempt to apply new seals.
    ///
    /// Returns `Err(PermissionDenied)` if `F_SEAL_SEAL` is already set.
    /// Returns `Err(Busy)` if trying to apply `F_SEAL_WRITE` while writable
    /// mappings exist.
    pub fn add_seals(&mut self, new_seals: FileSeal) -> Result<()> {
        if new_seals.0 & !FileSeal::ALL_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.seals.has_seal_seal() {
            return Err(Error::PermissionDenied);
        }
        if new_seals.has_write() && self.writable_maps > 0 {
            return Err(Error::Busy);
        }
        self.seals = self.seals.union(new_seals);
        Ok(())
    }

    /// Get the current set of seals.
    pub fn get_seals(&self) -> FileSeal {
        self.seals
    }

    /// Check if a write of size `delta` to a file of current size `size`
    /// is permitted by the seals.
    pub fn check_write(&self, current_size: u64, new_size: u64) -> Result<()> {
        if self.seals.has_write() {
            return Err(Error::PermissionDenied);
        }
        if new_size < current_size && self.seals.has_shrink() {
            return Err(Error::PermissionDenied);
        }
        if new_size > current_size && self.seals.has_grow() {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Check if creating a new writable mapping is allowed.
    pub fn check_new_writable_map(&self) -> Result<()> {
        if self.seals.has_write() || self.seals.has_future_write() {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Track a new writable mapping.
    pub fn add_writable_map(&mut self) -> Result<()> {
        self.check_new_writable_map()?;
        self.writable_maps = self.writable_maps.saturating_add(1);
        Ok(())
    }

    /// Remove a writable mapping reference.
    pub fn remove_writable_map(&mut self) {
        self.writable_maps = self.writable_maps.saturating_sub(1);
    }
}

/// Registry of seal states indexed by inode number.
pub struct SealRegistry {
    entries: [(u64, SealState); 64],
    count: usize,
}

impl SealRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        SealRegistry {
            entries: [(0, SealState::new()); 64],
            count: 0,
        }
    }

    /// Get or create the seal state for an inode.
    fn get_or_create(&mut self, ino: u64) -> Result<&mut SealState> {
        // Look for existing.
        for (i, ino_ref) in self.entries[..self.count].iter().enumerate() {
            if ino_ref.0 == ino {
                return Ok(&mut self.entries[i].1);
            }
        }
        // Create new.
        if self.count >= 64 {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = (ino, SealState::new());
        let idx = self.count;
        self.count += 1;
        Ok(&mut self.entries[idx].1)
    }

    /// Get the seal state for an inode.
    pub fn get(&self, ino: u64) -> Option<&SealState> {
        self.entries[..self.count]
            .iter()
            .find(|(i, _)| *i == ino)
            .map(|(_, s)| s)
    }

    /// Apply seals to an inode.
    pub fn add_seals(&mut self, ino: u64, seals: FileSeal) -> Result<()> {
        let state = self.get_or_create(ino)?;
        state.add_seals(seals)
    }

    /// Query seals for an inode.
    pub fn get_seals(&self, ino: u64) -> FileSeal {
        self.get(ino).map(|s| s.seals).unwrap_or(FileSeal(0))
    }

    /// Remove an inode from the registry (on file close/eviction).
    pub fn remove(&mut self, ino: u64) {
        for i in 0..self.count {
            if self.entries[i].0 == ino {
                self.count -= 1;
                self.entries[i] = self.entries[self.count];
                return;
            }
        }
    }
}

impl Default for SealRegistry {
    fn default() -> Self {
        Self::new()
    }
}
