// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bitfield manipulation.
//!
//! Provides helper functions for extracting and inserting fields
//! within integer values using bit offset and width. Equivalent
//! to Linux's `FIELD_GET`, `FIELD_PREP`, and `GENMASK` macros.
//!
//! # Design
//!
//! ```text
//!   value:   [63 ............... 0]
//!                    |<--width-->|
//!                    ^
//!                  offset
//!
//!   GENMASK(7, 4) = 0b1111_0000
//!   FIELD_GET(val, mask) = (val & mask) >> offset
//!   FIELD_SET(val, mask, field) = (val & ~mask) | (field << offset)
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/bitfield.h`,
//! `include/linux/bits.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of managed bitfield specs.
const MAX_SPECS: usize = 256;

/// Maximum field width.
const MAX_WIDTH: u32 = 64;

// ======================================================================
// Core functions
// ======================================================================

/// Generates a contiguous bitmask from bit `hi` down to `lo`.
///
/// Equivalent to Linux's `GENMASK(hi, lo)`.
///
/// # Examples
///
/// ```text
/// gen_mask(7, 4) = 0xF0
/// gen_mask(3, 0) = 0x0F
/// gen_mask(63, 0) = u64::MAX
/// ```
pub fn gen_mask(hi: u32, lo: u32) -> Result<u64> {
    if hi > 63 || lo > hi {
        return Err(Error::InvalidArgument);
    }
    let width = hi - lo + 1;
    if width == 64 {
        return Ok(u64::MAX);
    }
    let mask = ((1u64 << width) - 1) << lo;
    Ok(mask)
}

/// Extracts a bitfield from `value` at `offset` with `width`.
///
/// Equivalent to `FIELD_GET`.
pub fn bitfield_get(value: u64, offset: u32, width: u32) -> Result<u64> {
    if offset >= MAX_WIDTH || width == 0 || offset + width > MAX_WIDTH {
        return Err(Error::InvalidArgument);
    }
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    Ok((value >> offset) & mask)
}

/// Inserts a field value into `value` at `offset` with `width`.
///
/// Equivalent to `FIELD_PREP` + merge.
pub fn bitfield_set(value: u64, offset: u32, width: u32, field: u64) -> Result<u64> {
    if offset >= MAX_WIDTH || width == 0 || offset + width > MAX_WIDTH {
        return Err(Error::InvalidArgument);
    }
    let field_mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let shifted_mask = field_mask << offset;
    let cleared = value & !shifted_mask;
    let inserted = (field & field_mask) << offset;
    Ok(cleared | inserted)
}

/// Extracts a field using a precomputed mask.
///
/// The mask must be a contiguous set of bits.
pub fn field_get(value: u64, mask: u64) -> u64 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    (value & mask) >> shift
}

/// Prepares a field value for insertion using a mask.
///
/// Returns the value shifted into position (not yet merged).
pub fn field_prep(field: u64, mask: u64) -> u64 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let width = mask.count_ones();
    let field_mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    (field & field_mask) << shift
}

// ======================================================================
// BitfieldSpec
// ======================================================================

/// Specification of a named bitfield within a register.
#[derive(Debug, Clone, Copy)]
pub struct BitfieldSpec {
    /// Field name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Bit offset (LSB position).
    offset: u32,
    /// Bit width.
    width: u32,
    /// Precomputed mask.
    mask: u64,
    /// Whether this spec is active.
    active: bool,
}

impl BitfieldSpec {
    /// Creates a new empty spec.
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            offset: 0,
            width: 0,
            mask: 0,
            active: false,
        }
    }

    /// Creates a spec with the given parameters.
    pub fn create(name: &[u8], offset: u32, width: u32) -> Result<Self> {
        if offset >= MAX_WIDTH || width == 0 || offset + width > MAX_WIDTH {
            return Err(Error::InvalidArgument);
        }
        let mask = if width == 64 {
            u64::MAX
        } else {
            ((1u64 << width) - 1) << offset
        };
        let mut spec = Self {
            name: [0u8; 32],
            name_len: 0,
            offset,
            width,
            mask,
            active: true,
        };
        let copy_len = name.len().min(32);
        spec.name[..copy_len].copy_from_slice(&name[..copy_len]);
        spec.name_len = copy_len;
        Ok(spec)
    }

    /// Extracts this field from a value.
    pub fn get(&self, value: u64) -> u64 {
        field_get(value, self.mask)
    }

    /// Prepares a field value for insertion.
    pub fn prep(&self, field: u64) -> u64 {
        field_prep(field, self.mask)
    }

    /// Returns the offset.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the width.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Returns the precomputed mask.
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Returns whether this spec is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ======================================================================
// BitfieldRegistry — global registry
// ======================================================================

/// Global registry of bitfield specifications.
pub struct BitfieldRegistry {
    /// Specs.
    specs: [BitfieldSpec; MAX_SPECS],
    /// Number of active specs.
    count: usize,
}

impl BitfieldRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            specs: [const { BitfieldSpec::new() }; MAX_SPECS],
            count: 0,
        }
    }

    /// Registers a new bitfield spec.
    pub fn register(&mut self, name: &[u8], offset: u32, width: u32) -> Result<usize> {
        if self.count >= MAX_SPECS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .specs
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        self.specs[idx] = BitfieldSpec::create(name, offset, width)?;
        self.count += 1;
        Ok(idx)
    }

    /// Unregisters a spec by index.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_SPECS || !self.specs[idx].active {
            return Err(Error::NotFound);
        }
        self.specs[idx] = BitfieldSpec::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to a spec.
    pub fn get(&self, idx: usize) -> Result<&BitfieldSpec> {
        if idx >= MAX_SPECS || !self.specs[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.specs[idx])
    }

    /// Returns the number of active specs.
    pub fn count(&self) -> usize {
        self.count
    }
}
