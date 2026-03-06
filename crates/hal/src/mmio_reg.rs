// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Type-safe MMIO register abstraction.
//!
//! Provides zero-cost, type-safe wrappers for memory-mapped I/O registers.
//! Registers are parameterized by their access mode (read-only, write-only,
//! read-write) and value type, preventing accidental misuse at compile time.
//!
//! # Design
//!
//! - [`MmioRo<T>`] — read-only register
//! - [`MmioWo<T>`] — write-only register
//! - [`MmioRw<T>`] — read-write register
//! - [`MmioBlock`] — typed register block backed by an MMIO base address
//!
//! All accesses use `core::ptr::read_volatile` / `write_volatile` to prevent
//! the compiler from reordering or optimizing away hardware register accesses.
//!
//! # Usage
//!
//! ```ignore
//! // Define a 32-bit read-write register at fixed offset.
//! let ctrl: MmioRw<u32> = unsafe { MmioRw::from_ptr(0xFEDC_0000 as *mut u32) };
//! let val = ctrl.read();
//! ctrl.write(val | 0x1);
//! ```

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Access marker types
// ---------------------------------------------------------------------------

/// Marker: register is readable.
pub struct Readable;
/// Marker: register is writable.
pub struct Writable;

// ---------------------------------------------------------------------------
// MmioRo — read-only register
// ---------------------------------------------------------------------------

/// A read-only MMIO register of type `T`.
pub struct MmioRo<T: Copy> {
    ptr: *const T,
}

impl<T: Copy> MmioRo<T> {
    /// Creates a read-only register from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid MMIO register of type `T`. The pointer
    /// must remain valid for the lifetime of this struct and must be
    /// naturally aligned for `T`.
    pub const unsafe fn from_ptr(ptr: *const T) -> Self {
        Self { ptr }
    }

    /// Creates a read-only register from a base address and byte offset.
    ///
    /// # Safety
    ///
    /// `base + offset` must be a valid, aligned MMIO address for type `T`.
    pub unsafe fn from_base_offset(base: u64, offset: u64) -> Self {
        Self {
            ptr: (base + offset) as *const T,
        }
    }

    /// Reads the current value of the register (volatile read).
    pub fn read(&self) -> T {
        // SAFETY: ptr is a valid MMIO address; volatile read prevents
        // the compiler from caching or reordering the access.
        unsafe { core::ptr::read_volatile(self.ptr) }
    }

    /// Returns the raw pointer.
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }
}

// SAFETY: MMIO registers are inherently thread-unsafe, but marking them
// Send allows moving across thread boundaries (single-threaded kernel contexts).
unsafe impl<T: Copy> Send for MmioRo<T> {}

// ---------------------------------------------------------------------------
// MmioWo — write-only register
// ---------------------------------------------------------------------------

/// A write-only MMIO register of type `T`.
pub struct MmioWo<T: Copy> {
    ptr: *mut T,
}

impl<T: Copy> MmioWo<T> {
    /// Creates a write-only register from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid, aligned MMIO register of type `T`.
    pub const unsafe fn from_ptr(ptr: *mut T) -> Self {
        Self { ptr }
    }

    /// Creates a write-only register from a base address and byte offset.
    ///
    /// # Safety
    ///
    /// `base + offset` must be a valid, aligned MMIO address for type `T`.
    pub unsafe fn from_base_offset(base: u64, offset: u64) -> Self {
        Self {
            ptr: (base + offset) as *mut T,
        }
    }

    /// Writes `val` to the register (volatile write).
    pub fn write(&self, val: T) {
        // SAFETY: ptr is a valid MMIO address; volatile write ensures
        // the hardware sees the value immediately.
        unsafe { core::ptr::write_volatile(self.ptr, val) }
    }

    /// Returns the raw mutable pointer.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }
}

// SAFETY: See MmioRo.
unsafe impl<T: Copy> Send for MmioWo<T> {}

// ---------------------------------------------------------------------------
// MmioRw — read-write register
// ---------------------------------------------------------------------------

/// A read-write MMIO register of type `T`.
pub struct MmioRw<T: Copy> {
    ptr: *mut T,
}

impl<T: Copy> MmioRw<T> {
    /// Creates a read-write register from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid, aligned MMIO register of type `T`.
    pub const unsafe fn from_ptr(ptr: *mut T) -> Self {
        Self { ptr }
    }

    /// Creates a read-write register from a base address and byte offset.
    ///
    /// # Safety
    ///
    /// `base + offset` must be a valid, aligned MMIO address for type `T`.
    pub unsafe fn from_base_offset(base: u64, offset: u64) -> Self {
        Self {
            ptr: (base + offset) as *mut T,
        }
    }

    /// Reads the current value of the register.
    pub fn read(&self) -> T {
        // SAFETY: ptr is a valid MMIO address; volatile read prevents optimization.
        unsafe { core::ptr::read_volatile(self.ptr) }
    }

    /// Writes `val` to the register.
    pub fn write(&self, val: T) {
        // SAFETY: ptr is a valid MMIO address; volatile write ensures hardware visibility.
        unsafe { core::ptr::write_volatile(self.ptr, val) }
    }

    /// Returns the raw mutable pointer.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Returns a read-only view of this register.
    pub fn as_ro(&self) -> MmioRo<T> {
        // SAFETY: Downgrading to read-only uses the same valid pointer.
        unsafe { MmioRo::from_ptr(self.ptr as *const T) }
    }
}

// SAFETY: See MmioRo.
unsafe impl<T: Copy> Send for MmioRw<T> {}

// ---------------------------------------------------------------------------
// Bit-field helpers for u32 registers
// ---------------------------------------------------------------------------

/// Reads a bit field from `val` at `[msb:lsb]`.
pub const fn field_get(val: u32, msb: u32, lsb: u32) -> u32 {
    let mask = (1u32 << (msb - lsb + 1)) - 1;
    (val >> lsb) & mask
}

/// Sets a bit field in `val` at `[msb:lsb]` to `field_val`.
pub const fn field_set(val: u32, msb: u32, lsb: u32, field_val: u32) -> u32 {
    let mask = ((1u32 << (msb - lsb + 1)) - 1) << lsb;
    (val & !mask) | ((field_val << lsb) & mask)
}

// ---------------------------------------------------------------------------
// MmioBlock — a typed register block
// ---------------------------------------------------------------------------

/// A typed MMIO register block.
///
/// Represents a contiguous block of MMIO registers at a given base address.
/// Provides typed read/write access by byte offset within the block.
pub struct MmioBlock {
    base: u64,
    size: usize,
}

impl MmioBlock {
    /// Creates a new MMIO block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base` is zero or `size` is zero.
    pub fn new(base: u64, size: usize) -> Result<Self> {
        if base == 0 || size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { base, size })
    }

    /// Reads a `u32` register at byte `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 4 > size`.
    pub fn read32(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + offset as u64) as *const u32;
        // SAFETY: offset is within the block's size bound, and addr is a
        // valid aligned MMIO address for u32.
        Ok(unsafe { core::ptr::read_volatile(addr) })
    }

    /// Writes a `u32` value to byte `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 4 > size`.
    pub fn write32(&self, offset: usize, val: u32) -> Result<()> {
        if offset + 4 > self.size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + offset as u64) as *mut u32;
        // SAFETY: offset is within bounds and addr is a valid aligned MMIO address.
        unsafe { core::ptr::write_volatile(addr, val) }
        Ok(())
    }

    /// Reads a `u64` register at byte `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 8 > size`.
    pub fn read64(&self, offset: usize) -> Result<u64> {
        if offset + 8 > self.size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + offset as u64) as *const u64;
        // SAFETY: offset is within bounds; addr is valid aligned MMIO for u64.
        Ok(unsafe { core::ptr::read_volatile(addr) })
    }

    /// Writes a `u64` value to byte `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 8 > size`.
    pub fn write64(&self, offset: usize, val: u64) -> Result<()> {
        if offset + 8 > self.size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + offset as u64) as *mut u64;
        // SAFETY: offset is within bounds; addr is valid aligned MMIO for u64.
        unsafe { core::ptr::write_volatile(addr, val) }
        Ok(())
    }

    /// Reads a `u8` register at byte `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset >= size`.
    pub fn read8(&self, offset: usize) -> Result<u8> {
        if offset >= self.size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + offset as u64) as *const u8;
        // SAFETY: offset is within bounds; addr is valid MMIO for u8.
        Ok(unsafe { core::ptr::read_volatile(addr) })
    }

    /// Writes a `u8` value to byte `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset >= size`.
    pub fn write8(&self, offset: usize, val: u8) -> Result<()> {
        if offset >= self.size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + offset as u64) as *mut u8;
        // SAFETY: offset is within bounds; addr is valid MMIO for u8.
        unsafe { core::ptr::write_volatile(addr, val) }
        Ok(())
    }

    /// Performs a read-modify-write on a `u32` register.
    ///
    /// Reads the current value, applies `f`, and writes the result.
    ///
    /// # Errors
    ///
    /// Propagates errors from `read32` / `write32`.
    pub fn modify32(&self, offset: usize, f: impl FnOnce(u32) -> u32) -> Result<()> {
        let val = self.read32(offset)?;
        self.write32(offset, f(val))
    }

    /// Returns the base address.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the block size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_get_set() {
        let val: u32 = 0b1111_0000;
        assert_eq!(field_get(val, 7, 4), 0xF);
        assert_eq!(field_get(val, 3, 0), 0x0);
        let new = field_set(0, 7, 4, 0xA);
        assert_eq!(field_get(new, 7, 4), 0xA);
    }

    #[test]
    fn mmio_block_bounds() {
        // Can't test real MMIO in unit tests, just verify bounds checking.
        // Create a block backed by a local array (not real MMIO, but safe for tests).
        static REGS: [u32; 4] = [0x1234_5678, 0xDEAD_BEEF, 0, 0];
        let base = REGS.as_ptr() as u64;
        let block = MmioBlock::new(base, core::mem::size_of_val(&REGS)).unwrap();
        // Out-of-bounds access should fail.
        assert!(block.read32(16).is_err());
        assert!(block.write32(16, 0).is_err());
    }

    #[test]
    fn mmio_block_zero_base() {
        assert!(MmioBlock::new(0, 256).is_err());
        assert!(MmioBlock::new(0x1000, 0).is_err());
    }
}
