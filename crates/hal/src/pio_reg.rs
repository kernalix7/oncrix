// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Type-safe Port I/O (PIO) register abstraction.
//!
//! Provides zero-cost, type-safe wrappers for x86 I/O port registers.
//! Port I/O uses the `in`/`out` instructions rather than memory-mapped
//! addresses, and is restricted to 8-, 16-, and 32-bit access widths.
//!
//! # Design
//!
//! - [`PioRo<T>`] — read-only port register
//! - [`PioWo<T>`] — write-only port register
//! - [`PioRw<T>`] — read-write port register
//! - [`PioBlock`] — a range of consecutive port registers
//!
//! All access functions are gated on `#[cfg(target_arch = "x86_64")]`.
//! Non-x86_64 targets receive stub implementations that return 0 / do nothing.
//!
//! # Usage
//!
//! ```ignore
//! let status: PioRo<u8> = PioRo::new(0x64); // PS/2 status port
//! if status.read() & 0x01 != 0 {
//!     let data: PioRo<u8> = PioRo::new(0x60);
//!     let scancode = data.read();
//! }
//! ```

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Low-level port I/O primitives
// ---------------------------------------------------------------------------

/// Reads a byte from I/O port `port`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Reading an I/O port is a privileged instruction; caller must
    // ensure the port is valid and access is permitted by the I/O permission
    // bitmap (IOPB).
    unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack)) };
    val
}

/// Stub returning 0 on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn inb(_port: u16) -> u8 {
    0
}

/// Writes a byte to I/O port `port`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn outb(port: u16, val: u8) {
    // SAFETY: Writing an I/O port is a privileged instruction; caller must
    // ensure the port is valid and access is permitted.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack)) };
}

/// Stub on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn outb(_port: u16, _val: u8) {}

/// Reads a 16-bit word from I/O port `port`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: 16-bit port read; see `inb` safety notes.
    unsafe { core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack)) };
    val
}

/// Stub returning 0 on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn inw(_port: u16) -> u16 {
    0
}

/// Writes a 16-bit word to I/O port `port`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn outw(port: u16, val: u16) {
    // SAFETY: 16-bit port write; see `outb` safety notes.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack)) };
}

/// Stub on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn outw(_port: u16, _val: u16) {}

/// Reads a 32-bit dword from I/O port `port`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: 32-bit port read; see `inb` safety notes.
    unsafe {
        core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack))
    };
    val
}

/// Stub returning 0 on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn inl(_port: u16) -> u32 {
    0
}

/// Writes a 32-bit dword to I/O port `port`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn outl(port: u16, val: u32) {
    // SAFETY: 32-bit port write; see `outb` safety notes.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack))
    };
}

/// Stub on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn outl(_port: u16, _val: u32) {}

/// Inserts a short I/O delay by writing to port 0x80 (POST code port).
///
/// Used after I/O port writes to slow peripherals that need settle time.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn io_delay() {
    // SAFETY: Port 0x80 is the POST diagnostic port; writing to it is safe
    // and only causes a brief bus cycle delay.
    unsafe { core::arch::asm!("out 0x80, al", in("al") 0u8, options(nomem, nostack)) };
}

/// Stub on non-x86_64.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn io_delay() {}

// ---------------------------------------------------------------------------
// PioRo — read-only port register
// ---------------------------------------------------------------------------

/// A read-only I/O port register.
///
/// `T` must be `u8`, `u16`, or `u32`.
pub struct PioRo<T: PioWidth> {
    port: u16,
    _phantom: core::marker::PhantomData<T>,
}

impl<T: PioWidth> PioRo<T> {
    /// Creates a read-only port register at `port`.
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Reads the port.
    pub fn read(&self) -> T {
        T::read(self.port)
    }

    /// Returns the port address.
    pub fn port(&self) -> u16 {
        self.port
    }
}

// ---------------------------------------------------------------------------
// PioWo — write-only port register
// ---------------------------------------------------------------------------

/// A write-only I/O port register.
pub struct PioWo<T: PioWidth> {
    port: u16,
    _phantom: core::marker::PhantomData<T>,
}

impl<T: PioWidth> PioWo<T> {
    /// Creates a write-only port register at `port`.
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Writes `val` to the port.
    pub fn write(&self, val: T) {
        T::write(self.port, val);
    }

    /// Returns the port address.
    pub fn port(&self) -> u16 {
        self.port
    }
}

// ---------------------------------------------------------------------------
// PioRw — read-write port register
// ---------------------------------------------------------------------------

/// A read-write I/O port register.
pub struct PioRw<T: PioWidth> {
    port: u16,
    _phantom: core::marker::PhantomData<T>,
}

impl<T: PioWidth> PioRw<T> {
    /// Creates a read-write port register at `port`.
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Reads the port.
    pub fn read(&self) -> T {
        T::read(self.port)
    }

    /// Writes `val` to the port.
    pub fn write(&self, val: T) {
        T::write(self.port, val);
    }

    /// Performs a read-modify-write cycle.
    pub fn modify(&self, f: impl FnOnce(T) -> T) {
        let val = self.read();
        self.write(f(val));
    }

    /// Returns the port address.
    pub fn port(&self) -> u16 {
        self.port
    }
}

// ---------------------------------------------------------------------------
// PioWidth trait — sealed trait for u8/u16/u32
// ---------------------------------------------------------------------------

/// Sealed trait for PIO-accessible types (`u8`, `u16`, `u32`).
pub trait PioWidth: Copy + Sized {
    /// Reads from `port`.
    fn read(port: u16) -> Self;
    /// Writes `val` to `port`.
    fn write(port: u16, val: Self);
}

impl PioWidth for u8 {
    fn read(port: u16) -> Self {
        inb(port)
    }

    fn write(port: u16, val: Self) {
        outb(port, val);
    }
}

impl PioWidth for u16 {
    fn read(port: u16) -> Self {
        inw(port)
    }

    fn write(port: u16, val: Self) {
        outw(port, val);
    }
}

impl PioWidth for u32 {
    fn read(port: u16) -> Self {
        inl(port)
    }

    fn write(port: u16, val: Self) {
        outl(port, val);
    }
}

// ---------------------------------------------------------------------------
// PioBlock — a contiguous range of port registers
// ---------------------------------------------------------------------------

/// A contiguous block of I/O port registers.
///
/// Provides bounds-checked byte-offset access within a port address range.
pub struct PioBlock {
    base: u16,
    len: u16,
}

impl PioBlock {
    /// Creates a new port block.
    ///
    /// `base` — first port in the range.
    /// `len` — number of ports in the range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `len` is zero or if
    /// `base + len` overflows.
    pub fn new(base: u16, len: u16) -> Result<Self> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        if base.checked_add(len).is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { base, len })
    }

    /// Reads a byte from port at `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset >= len`.
    pub fn read8(&self, offset: u16) -> Result<u8> {
        if offset >= self.len {
            return Err(Error::InvalidArgument);
        }
        Ok(inb(self.base + offset))
    }

    /// Writes a byte to port at `offset` within the block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset >= len`.
    pub fn write8(&self, offset: u16, val: u8) -> Result<()> {
        if offset >= self.len {
            return Err(Error::InvalidArgument);
        }
        outb(self.base + offset, val);
        Ok(())
    }

    /// Reads a 16-bit word from port at `offset` (must be even-aligned).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 2 > len`.
    pub fn read16(&self, offset: u16) -> Result<u16> {
        if offset.saturating_add(2) > self.len {
            return Err(Error::InvalidArgument);
        }
        Ok(inw(self.base + offset))
    }

    /// Writes a 16-bit word to port at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 2 > len`.
    pub fn write16(&self, offset: u16, val: u16) -> Result<()> {
        if offset.saturating_add(2) > self.len {
            return Err(Error::InvalidArgument);
        }
        outw(self.base + offset, val);
        Ok(())
    }

    /// Reads a 32-bit dword from port at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 4 > len`.
    pub fn read32(&self, offset: u16) -> Result<u32> {
        if offset.saturating_add(4) > self.len {
            return Err(Error::InvalidArgument);
        }
        Ok(inl(self.base + offset))
    }

    /// Writes a 32-bit dword to port at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + 4 > len`.
    pub fn write32(&self, offset: u16, val: u32) -> Result<()> {
        if offset.saturating_add(4) > self.len {
            return Err(Error::InvalidArgument);
        }
        outl(self.base + offset, val);
        Ok(())
    }

    /// Returns the base port address.
    pub fn base(&self) -> u16 {
        self.base
    }

    /// Returns the block length in ports.
    pub fn len(&self) -> u16 {
        self.len
    }

    /// Returns `true` if the block has zero length (always false for valid blocks).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pio_block_bounds() {
        let block = PioBlock::new(0x3F8, 8).unwrap();
        assert_eq!(block.base(), 0x3F8);
        assert_eq!(block.len(), 8);
        assert!(block.read8(8).is_err());
        assert!(block.write8(8, 0).is_err());
    }

    #[test]
    fn pio_block_invalid() {
        assert!(PioBlock::new(0x3F8, 0).is_err());
        assert!(PioBlock::new(0xFFFF, 2).is_err());
    }

    #[test]
    fn pio_rw_new() {
        let reg: PioRw<u8> = PioRw::new(0x3F8);
        assert_eq!(reg.port(), 0x3F8);
    }
}
