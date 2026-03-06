// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! E820 memory map parsing and management.
//!
//! The BIOS E820 memory map (INT 15h, AX=E820h) describes the physical
//! memory layout of the system. Each entry describes a contiguous range
//! of physical addresses and its type (usable, reserved, ACPI, etc.).
//!
//! On UEFI systems the memory map is obtained via `GetMemoryMap()` and
//! can be converted to the E820 format for uniform handling.
//!
//! # Entry Types
//!
//! | Value | Type                     |
//! |-------|--------------------------|
//! |   1   | Usable RAM               |
//! |   2   | Reserved                 |
//! |   3   | ACPI Reclaimable         |
//! |   4   | ACPI NVS                 |
//! |   5   | Bad Memory               |
//! |  12   | Persistent Memory (PMEM) |
//!
//! Reference: ACPI Specification 6.5 §15, Linux `arch/x86/kernel/e820.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// E820 memory type constants
// ---------------------------------------------------------------------------

/// E820 memory type: usable RAM.
pub const E820_TYPE_RAM: u32 = 1;
/// E820 memory type: reserved (firmware, hardware, etc.).
pub const E820_TYPE_RESERVED: u32 = 2;
/// E820 memory type: ACPI reclaimable memory.
pub const E820_TYPE_ACPI: u32 = 3;
/// E820 memory type: ACPI NVS (Non-Volatile Storage).
pub const E820_TYPE_NVS: u32 = 4;
/// E820 memory type: unusable (bad) memory.
pub const E820_TYPE_UNUSABLE: u32 = 5;
/// E820 memory type: persistent memory (PMEM/NVDIMM).
pub const E820_TYPE_PMEM: u32 = 12;

/// Maximum number of E820 entries we track.
pub const MAX_E820_ENTRIES: usize = 128;

// ---------------------------------------------------------------------------
// E820Entry
// ---------------------------------------------------------------------------

/// A single E820 memory map entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct E820Entry {
    /// Base physical address of the region.
    pub base: u64,
    /// Length of the region in bytes.
    pub length: u64,
    /// Memory type (see `E820_TYPE_*` constants).
    pub mem_type: u32,
}

impl E820Entry {
    /// Creates a new E820 entry.
    pub const fn new(base: u64, length: u64, mem_type: u32) -> Self {
        Self {
            base,
            length,
            mem_type,
        }
    }

    /// Returns the exclusive end address of this region.
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }

    /// Whether this region is usable RAM.
    pub fn is_usable(&self) -> bool {
        self.mem_type == E820_TYPE_RAM
    }

    /// Whether this region is reserved.
    pub fn is_reserved(&self) -> bool {
        self.mem_type == E820_TYPE_RESERVED
    }

    /// Whether this entry overlaps `[start, start+len)`.
    pub fn overlaps(&self, start: u64, len: u64) -> bool {
        self.base < start.saturating_add(len) && start < self.end()
    }
}

// ---------------------------------------------------------------------------
// E820Map
// ---------------------------------------------------------------------------

/// A parsed E820 memory map.
pub struct E820Map {
    entries: [E820Entry; MAX_E820_ENTRIES],
    count: usize,
}

impl Default for E820Map {
    fn default() -> Self {
        Self::new()
    }
}

impl E820Map {
    /// Creates an empty E820 map.
    pub const fn new() -> Self {
        Self {
            entries: [E820Entry {
                base: 0,
                length: 0,
                mem_type: 0,
            }; MAX_E820_ENTRIES],
            count: 0,
        }
    }

    /// Adds an entry to the map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the map is full.
    pub fn add(&mut self, base: u64, length: u64, mem_type: u32) -> Result<()> {
        if self.count >= MAX_E820_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = E820Entry::new(base, length, mem_type);
        self.count += 1;
        Ok(())
    }

    /// Returns a slice of all entries.
    pub fn entries(&self) -> &[E820Entry] {
        &self.entries[..self.count]
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total amount of usable RAM in bytes.
    pub fn total_usable_bytes(&self) -> u64 {
        self.entries()
            .iter()
            .filter(|e| e.is_usable())
            .map(|e| e.length)
            .fold(0u64, |acc, l| acc.saturating_add(l))
    }

    /// Returns the highest physical address present in any entry.
    pub fn max_addr(&self) -> u64 {
        self.entries().iter().map(|e| e.end()).max().unwrap_or(0)
    }

    /// Sorts entries by base address (insertion sort — map is typically small).
    pub fn sort(&mut self) {
        let n = self.count;
        for i in 1..n {
            let key = self.entries[i];
            let mut j = i;
            while j > 0 && self.entries[j - 1].base > key.base {
                self.entries[j] = self.entries[j - 1];
                j -= 1;
            }
            self.entries[j] = key;
        }
    }

    /// Parses an E820 map from a raw byte array.
    ///
    /// `data` is a flat array of 20-byte E820 entries (base: u64, length: u64, type: u32).
    /// `count` is the number of valid entries in `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short for `count` entries.
    pub fn parse_raw(data: &[u8], count: usize) -> Result<Self> {
        const ENTRY_SIZE: usize = 20;
        if data.len() < count * ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut map = Self::new();
        for i in 0..count.min(MAX_E820_ENTRIES) {
            let off = i * ENTRY_SIZE;
            let base = u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ]);
            let length = u64::from_le_bytes([
                data[off + 8],
                data[off + 9],
                data[off + 10],
                data[off + 11],
                data[off + 12],
                data[off + 13],
                data[off + 14],
                data[off + 15],
            ]);
            let mem_type = u32::from_le_bytes([
                data[off + 16],
                data[off + 17],
                data[off + 18],
                data[off + 19],
            ]);
            map.entries[i] = E820Entry::new(base, length, mem_type);
            map.count += 1;
        }
        Ok(map)
    }

    /// Returns the first usable RAM entry that covers or follows `min_addr`.
    pub fn find_usable_above(&self, min_addr: u64) -> Option<&E820Entry> {
        self.entries()
            .iter()
            .filter(|e| e.is_usable() && e.end() > min_addr)
            .min_by_key(|e| e.base)
    }
}
