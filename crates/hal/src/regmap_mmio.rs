// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Register map MMIO backend.
//!
//! Provides an abstracted register read/write layer over MMIO that supports:
//! - Flat register cache (reduces unnecessary bus traffic on re-reads)
//! - Bulk sequential read/write operations
//! - Register field extraction with mask/shift helpers
//! - Big-endian and little-endian byte-order handling
//! - Register range validation against a configurable window
//!
//! # Design
//!
//! [`RegmapMmio`] wraps a contiguous MMIO window described by a base address
//! and byte size. Individual registers are addressed by their byte offset.
//! All accesses are performed via volatile pointers to prevent compiler
//! reordering. An optional cache layer stores the last value written to each
//! 32-bit register slot; cache hits skip the MMIO read.
//!
//! Reference: Linux `drivers/base/regmap/regmap-mmio.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of 32-bit register slots held in the flat cache.
const CACHE_SLOTS: usize = 256;

// ---------------------------------------------------------------------------
// Endianness
// ---------------------------------------------------------------------------

/// Byte order used when accessing MMIO registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little-endian (x86 native).
    Little,
    /// Big-endian (some ARM/MIPS peripherals).
    Big,
}

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// A single flat-cache entry storing the last seen register value.
#[derive(Clone, Copy)]
struct CacheEntry {
    /// Byte offset of the register within the MMIO window.
    offset: u32,
    /// Cached register value.
    value: u32,
    /// Whether this cache slot is valid.
    valid: bool,
}

/// Constant empty cache entry.
const EMPTY_CACHE_ENTRY: CacheEntry = CacheEntry {
    offset: 0,
    value: 0,
    valid: false,
};

// ---------------------------------------------------------------------------
// RegmapMmio
// ---------------------------------------------------------------------------

/// MMIO register map with flat cache and field helpers.
///
/// All register accesses are byte-offset based within a fixed MMIO window.
/// The cache holds the most recently read or written value for up to
/// [`CACHE_SLOTS`] distinct register offsets.
pub struct RegmapMmio {
    /// Base physical address of the MMIO window.
    base: u64,
    /// Size of the MMIO window in bytes.
    window_size: usize,
    /// Byte order for register accesses.
    endianness: Endianness,
    /// Flat register cache.
    cache: [CacheEntry; CACHE_SLOTS],
    /// Number of occupied cache slots.
    cache_len: usize,
    /// Whether caching is enabled.
    cache_enabled: bool,
}

impl RegmapMmio {
    /// Creates a new MMIO register map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base` is zero or
    /// `window_size` is zero.
    pub fn new(base: u64, window_size: usize, endianness: Endianness) -> Result<Self> {
        if base == 0 || window_size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            base,
            window_size,
            endianness,
            cache: [EMPTY_CACHE_ENTRY; CACHE_SLOTS],
            cache_len: 0,
            cache_enabled: false,
        })
    }

    /// Enables or disables the register cache.
    pub fn set_cache_enabled(&mut self, enabled: bool) {
        self.cache_enabled = enabled;
    }

    /// Returns whether caching is currently enabled.
    pub fn cache_enabled(&self) -> bool {
        self.cache_enabled
    }

    /// Invalidates all cache entries.
    pub fn cache_invalidate(&mut self) {
        for entry in &mut self.cache[..self.cache_len] {
            entry.valid = false;
        }
    }

    // -- Range validation ---------------------------------------------------

    /// Validates that `offset` and a 4-byte access fit within the window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on out-of-range access.
    fn check_range(&self, offset: u32) -> Result<()> {
        let end = (offset as usize)
            .checked_add(4)
            .ok_or(Error::InvalidArgument)?;
        if end > self.window_size {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    // -- Cache helpers ------------------------------------------------------

    fn cache_lookup(&self, offset: u32) -> Option<u32> {
        if !self.cache_enabled {
            return None;
        }
        for entry in &self.cache[..self.cache_len] {
            if entry.valid && entry.offset == offset {
                return Some(entry.value);
            }
        }
        None
    }

    fn cache_update(&mut self, offset: u32, value: u32) {
        if !self.cache_enabled {
            return;
        }
        // Check for existing slot first.
        for entry in &mut self.cache[..self.cache_len] {
            if entry.offset == offset {
                entry.value = value;
                entry.valid = true;
                return;
            }
        }
        // Allocate a new slot if room is available.
        if self.cache_len < CACHE_SLOTS {
            self.cache[self.cache_len] = CacheEntry {
                offset,
                value,
                valid: true,
            };
            self.cache_len += 1;
        }
        // When the cache is full, the new value is not cached (eviction policy:
        // no-evict; callers may call cache_invalidate() to reset).
    }

    // -- Raw MMIO access ----------------------------------------------------

    /// Performs a raw 32-bit volatile MMIO read at `offset`.
    fn raw_read32(&self, offset: u32) -> u32 {
        let addr = (self.base + u64::from(offset)) as *const u32;
        // SAFETY: offset has been validated by check_range; addr is a valid
        // aligned MMIO address within the mapped window.
        let raw = unsafe { core::ptr::read_volatile(addr) };
        match self.endianness {
            Endianness::Little => raw,
            Endianness::Big => raw.swap_bytes(),
        }
    }

    /// Performs a raw 32-bit volatile MMIO write at `offset`.
    fn raw_write32(&self, offset: u32, value: u32) {
        let wire_val = match self.endianness {
            Endianness::Little => value,
            Endianness::Big => value.swap_bytes(),
        };
        let addr = (self.base + u64::from(offset)) as *mut u32;
        // SAFETY: offset has been validated by check_range; addr is a valid
        // aligned MMIO address within the mapped window.
        unsafe { core::ptr::write_volatile(addr, wire_val) }
    }

    // -- Public register access --------------------------------------------

    /// Reads a 32-bit register at `offset`.
    ///
    /// If the cache is enabled and the slot is valid, returns the cached value
    /// without performing an MMIO read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn read32(&mut self, offset: u32) -> Result<u32> {
        self.check_range(offset)?;
        if let Some(cached) = self.cache_lookup(offset) {
            return Ok(cached);
        }
        let val = self.raw_read32(offset);
        self.cache_update(offset, val);
        Ok(val)
    }

    /// Writes `value` to the 32-bit register at `offset`.
    ///
    /// Also updates the cache entry when caching is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn write32(&mut self, offset: u32, value: u32) -> Result<()> {
        self.check_range(offset)?;
        self.raw_write32(offset, value);
        self.cache_update(offset, value);
        Ok(())
    }

    /// Performs a read-modify-write on a 32-bit register.
    ///
    /// Reads the current value, clears the bits in `mask`, ORs in
    /// `value & mask`, and writes back.
    ///
    /// # Errors
    ///
    /// Propagates errors from `read32` / `write32`.
    pub fn update32(&mut self, offset: u32, mask: u32, value: u32) -> Result<()> {
        let current = self.read32(offset)?;
        let updated = (current & !mask) | (value & mask);
        self.write32(offset, updated)
    }

    /// Reads a contiguous run of `count` 32-bit registers starting at
    /// `start_offset` into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the range overflows the window
    /// or `buf` is too small.
    pub fn bulk_read32(&mut self, start_offset: u32, buf: &mut [u32]) -> Result<()> {
        let count = buf.len();
        for i in 0..count {
            let off = start_offset
                .checked_add((i * 4) as u32)
                .ok_or(Error::InvalidArgument)?;
            buf[i] = self.read32(off)?;
        }
        Ok(())
    }

    /// Writes `buf` to `count` contiguous 32-bit registers starting at
    /// `start_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the range overflows the window.
    pub fn bulk_write32(&mut self, start_offset: u32, buf: &[u32]) -> Result<()> {
        let count = buf.len();
        for i in 0..count {
            let off = start_offset
                .checked_add((i * 4) as u32)
                .ok_or(Error::InvalidArgument)?;
            self.write32(off, buf[i])?;
        }
        Ok(())
    }

    // -- Field helpers ------------------------------------------------------

    /// Extracts a bit field `[msb:lsb]` from `val`.
    ///
    /// Both `msb` and `lsb` are bit indices into a 32-bit value (0 = LSB).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `msb < lsb` or `msb >= 32`.
    pub fn field_get(val: u32, msb: u8, lsb: u8) -> Result<u32> {
        if msb >= 32 || msb < lsb {
            return Err(Error::InvalidArgument);
        }
        let width = msb - lsb + 1;
        let mask = if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        };
        Ok((val >> lsb) & mask)
    }

    /// Inserts `field_val` into `val` at bit field `[msb:lsb]`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `msb < lsb` or `msb >= 32`.
    pub fn field_set(val: u32, msb: u8, lsb: u8, field_val: u32) -> Result<u32> {
        if msb >= 32 || msb < lsb {
            return Err(Error::InvalidArgument);
        }
        let width = msb - lsb + 1;
        let mask = if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        };
        Ok((val & !(mask << lsb)) | ((field_val & mask) << lsb))
    }

    // -- Accessors ----------------------------------------------------------

    /// Returns the MMIO base address.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the window size in bytes.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Returns the configured byte order.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the number of valid cache slots.
    pub fn cache_len(&self) -> usize {
        self.cache[..self.cache_len]
            .iter()
            .filter(|e| e.valid)
            .count()
    }
}
