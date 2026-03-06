// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ID Allocator (IDR/IDA) — radix-tree based integer ID allocation.
//!
//! `Idr` maps integer IDs to pointer-sized values. IDs are allocated from
//! a configurable range `[min_id, max_id]` and can be freed back to the pool.
//!
//! `Ida` is a simpler variant that only allocates IDs without storing values.
//!
//! These map to Linux's `idr_alloc` / `idr_find` / `idr_remove` family.

use oncrix_lib::{Error, Result};

/// Maximum number of IDs that can be allocated simultaneously.
pub const IDR_MAX_IDS: usize = 1024;

/// Sentinel value indicating an unused slot.
const IDR_EMPTY: u64 = u64::MAX;

/// An ID-to-value mapping entry.
#[derive(Clone, Copy)]
struct IdrEntry {
    id: u32,
    value: u64,
    used: bool,
}

impl IdrEntry {
    const fn empty() -> Self {
        Self {
            id: 0,
            value: IDR_EMPTY,
            used: false,
        }
    }
}

/// Integer ID allocator with associated values.
pub struct Idr {
    entries: [IdrEntry; IDR_MAX_IDS],
    min_id: u32,
    max_id: u32,
    count: usize,
    next_hint: u32,
}

impl Idr {
    /// Creates a new `Idr` allocating IDs in `[min_id, max_id]`.
    pub const fn new(min_id: u32, max_id: u32) -> Self {
        Self {
            entries: [const { IdrEntry::empty() }; IDR_MAX_IDS],
            min_id,
            max_id,
            count: 0,
            next_hint: 0,
        }
    }

    /// Allocates the next available ID and associates it with `value`.
    ///
    /// Returns the allocated ID on success.
    pub fn alloc(&mut self, value: u64) -> Result<u32> {
        if self.count >= IDR_MAX_IDS {
            return Err(Error::OutOfMemory);
        }

        // Find a free ID starting from next_hint.
        let range = (self.next_hint..=self.max_id).chain(self.min_id..self.next_hint);

        for candidate in range {
            if candidate < self.min_id || candidate > self.max_id {
                continue;
            }
            if !self.entries[..self.count].iter().any(|e| e.id == candidate) {
                let slot = self.count;
                self.entries[slot] = IdrEntry {
                    id: candidate,
                    value,
                    used: true,
                };
                self.count += 1;
                self.next_hint = candidate.wrapping_add(1);
                if self.next_hint > self.max_id {
                    self.next_hint = self.min_id;
                }
                return Ok(candidate);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocates a specific `id` and associates it with `value`.
    ///
    /// Returns `Err(AlreadyExists)` if the ID is already in use.
    pub fn alloc_specific(&mut self, id: u32, value: u64) -> Result<()> {
        if id < self.min_id || id > self.max_id {
            return Err(Error::InvalidArgument);
        }
        if self.count >= IDR_MAX_IDS {
            return Err(Error::OutOfMemory);
        }
        if self.entries[..self.count].iter().any(|e| e.id == id) {
            return Err(Error::AlreadyExists);
        }
        let slot = self.count;
        self.entries[slot] = IdrEntry {
            id,
            value,
            used: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Looks up the value associated with `id`.
    pub fn find(&self, id: u32) -> Option<u64> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.value)
    }

    /// Replaces the value for an existing `id`. Returns `Err(NotFound)` if absent.
    pub fn replace(&mut self, id: u32, new_value: u64) -> Result<u64> {
        let entry = self.entries[..self.count]
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        let old = entry.value;
        entry.value = new_value;
        Ok(old)
    }

    /// Frees the given `id` and returns its associated value.
    pub fn remove(&mut self, id: u32) -> Result<u64> {
        let idx = self.entries[..self.count]
            .iter()
            .position(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        let value = self.entries[idx].value;
        // Swap-remove to keep array compact.
        let last = self.count - 1;
        self.entries.swap(idx, last);
        self.entries[last] = IdrEntry::empty();
        self.count -= 1;
        Ok(value)
    }

    /// Returns the number of allocated IDs.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no IDs are allocated.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates all (id, value) pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.entries[..self.count].iter().map(|e| (e.id, e.value))
    }
}

/// Bitmap-based ID allocator — allocates IDs only, no associated values.
pub struct Ida {
    /// Bit-per-ID bitmap (1 = allocated).
    bitmap: [u64; IDR_MAX_IDS / 64],
    min_id: u32,
    max_id: u32,
    count: usize,
}

impl Ida {
    /// Creates a new `Ida` allocating IDs in `[min_id, max_id]`.
    pub const fn new(min_id: u32, max_id: u32) -> Self {
        Self {
            bitmap: [0u64; IDR_MAX_IDS / 64],
            min_id,
            max_id,
            count: 0,
        }
    }

    /// Allocates the next available ID.
    pub fn alloc(&mut self) -> Result<u32> {
        for id in self.min_id..=self.max_id {
            let offset = (id - self.min_id) as usize;
            if offset >= IDR_MAX_IDS {
                break;
            }
            let word = offset / 64;
            let bit = offset % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                self.bitmap[word] |= 1u64 << bit;
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Frees a previously allocated `id`.
    pub fn free(&mut self, id: u32) -> Result<()> {
        if id < self.min_id || id > self.max_id {
            return Err(Error::InvalidArgument);
        }
        let offset = (id - self.min_id) as usize;
        if offset >= IDR_MAX_IDS {
            return Err(Error::InvalidArgument);
        }
        let word = offset / 64;
        let bit = offset % 64;
        if self.bitmap[word] & (1u64 << bit) == 0 {
            return Err(Error::NotFound);
        }
        self.bitmap[word] &= !(1u64 << bit);
        self.count -= 1;
        Ok(())
    }

    /// Returns `true` if `id` is currently allocated.
    pub fn is_allocated(&self, id: u32) -> bool {
        if id < self.min_id || id > self.max_id {
            return false;
        }
        let offset = (id - self.min_id) as usize;
        if offset >= IDR_MAX_IDS {
            return false;
        }
        self.bitmap[offset / 64] & (1u64 << (offset % 64)) != 0
    }

    /// Returns the number of allocated IDs.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }
}
