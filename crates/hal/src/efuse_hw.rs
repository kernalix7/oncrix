// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eFuse (one-time programmable OTP) hardware abstraction.
//!
//! eFuses are one-time-programmable bits embedded in silicon, used to store:
//!
//! - Device identity and serial numbers
//! - Security keys and certificate digests
//! - Boot configuration (secure boot enable, debug disable)
//! - Manufacturing calibration data
//!
//! Once programmed (blown), an eFuse bit cannot be reset to 0.
//!
//! # Architecture
//!
//! eFuse controllers are accessed via MMIO. The typical flow is:
//! 1. Apply VPP programming voltage (hardware-managed on modern SoCs)
//! 2. Write the fuse address and data
//! 3. Issue a program command
//! 4. Poll for completion
//! 5. Readback and verify
//!
//! This module provides read-only access by default; write (blow) operations
//! are explicitly gated behind `unsafe` with strong invariant documentation.
//!
//! Reference: TI Sitara AM64x eFuse; Qualcomm QFPROM; NXP OCOTP.

use oncrix_lib::{Error, Result};

/// Maximum number of 32-bit fuse words.
pub const MAX_FUSE_WORDS: usize = 256;
/// Number of fuse banks.
pub const MAX_FUSE_BANKS: usize = 8;
/// Words per bank.
pub const WORDS_PER_BANK: usize = 32;

// ── eFuse Register Offsets (generic OCOTP-style layout) ────────────────────

/// Control register offset.
const EFUSE_CTRL: u32 = 0x000;
/// Timing register offset.
const EFUSE_TIMING: u32 = 0x004;
/// Data register offset (word to program).
const EFUSE_DATA: u32 = 0x008;
/// Address register offset.
const EFUSE_ADDR: u32 = 0x00C;
/// Read data register.
const EFUSE_READ_DATA: u32 = 0x020;
/// Status register.
const EFUSE_STATUS: u32 = 0x030;

// ── Control register bits ──────────────────────────────────────────────────

/// CTRL: Program fuse (write 1 to trigger program cycle).
const EFUSE_CTRL_PROG: u32 = 1 << 0;
/// CTRL: Read fuse from shadow registers.
const EFUSE_CTRL_RD: u32 = 1 << 1;
/// CTRL: Reload shadow registers from fuse.
const EFUSE_CTRL_RELOAD: u32 = 1 << 2;
/// STATUS: Busy bit.
const EFUSE_STATUS_BUSY: u32 = 1 << 0;
/// STATUS: Error bit.
const EFUSE_STATUS_ERR: u32 = 1 << 2;

// ── MMIO helpers ───────────────────────────────────────────────────────────

#[inline]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

#[inline]
unsafe fn write32(base: usize, offset: u32, val: u32) {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

// ── Fuse Row Metadata ──────────────────────────────────────────────────────

/// A named fuse field with bit-level granularity within a word.
#[derive(Clone, Copy)]
pub struct FuseField {
    /// Word index (0-based) within the fuse array.
    pub word: u32,
    /// Bit offset within the word.
    pub bit_offset: u8,
    /// Number of bits in this field.
    pub bit_width: u8,
    /// Human-readable name.
    pub name: &'static str,
}

impl FuseField {
    /// Create a new fuse field descriptor.
    pub const fn new(word: u32, bit_offset: u8, bit_width: u8, name: &'static str) -> Self {
        Self {
            word,
            bit_offset,
            bit_width,
            name,
        }
    }

    /// Extract this field's value from a word.
    pub fn extract(&self, word_val: u32) -> u32 {
        let mask = if self.bit_width >= 32 {
            u32::MAX
        } else {
            (1u32 << self.bit_width) - 1
        };
        (word_val >> self.bit_offset) & mask
    }
}

// ── eFuse Controller ───────────────────────────────────────────────────────

/// eFuse controller hardware interface.
pub struct EfuseController {
    base: usize,
    /// Shadow (read-cached) fuse words.
    shadow: [u32; MAX_FUSE_WORDS],
    /// Number of valid words.
    num_words: usize,
    /// True if the shadow has been loaded from hardware.
    shadow_valid: bool,
}

impl EfuseController {
    /// Create an eFuse controller handle.
    ///
    /// # Safety
    /// `base` must be the MMIO base of a valid eFuse controller, mapped
    /// with non-cacheable device memory attributes.
    pub unsafe fn new(base: usize, num_words: usize) -> Self {
        Self {
            base,
            shadow: [0u32; MAX_FUSE_WORDS],
            num_words: num_words.min(MAX_FUSE_WORDS),
            shadow_valid: false,
        }
    }

    /// Poll until the controller is idle or timeout.
    fn wait_idle(&self) -> Result<()> {
        for _ in 0..100_000 {
            // SAFETY: self.base is valid MMIO.
            let status = unsafe { read32(self.base, EFUSE_STATUS) };
            if status & EFUSE_STATUS_ERR != 0 {
                return Err(Error::IoError);
            }
            if status & EFUSE_STATUS_BUSY == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Load shadow registers from the physical fuse array.
    pub fn reload_shadow(&mut self) -> Result<()> {
        // SAFETY: self.base valid MMIO; RELOAD triggers fuse→shadow copy.
        unsafe { write32(self.base, EFUSE_CTRL, EFUSE_CTRL_RELOAD) }
        self.wait_idle()?;
        // Read all shadow words into cache.
        for i in 0..self.num_words {
            // Shadow registers start at offset 0x400 (OCOTP-style).
            let offset = 0x400u32 + (i as u32) * 0x10;
            // SAFETY: offset within OCOTP shadow range.
            self.shadow[i] = unsafe { read32(self.base, offset) };
        }
        self.shadow_valid = true;
        Ok(())
    }

    /// Read a fuse word from the shadow registers.
    pub fn read_word(&mut self, word_idx: u32) -> Result<u32> {
        if word_idx as usize >= self.num_words {
            return Err(Error::InvalidArgument);
        }
        if !self.shadow_valid {
            self.reload_shadow()?;
        }
        Ok(self.shadow[word_idx as usize])
    }

    /// Read a specific fuse field.
    pub fn read_field(&mut self, field: &FuseField) -> Result<u32> {
        let word = self.read_word(field.word)?;
        Ok(field.extract(word))
    }

    /// Check if a fuse word is non-zero (blown).
    pub fn is_blown(&mut self, word_idx: u32) -> Result<bool> {
        let val = self.read_word(word_idx)?;
        Ok(val != 0)
    }

    /// Read the device serial number from words 0-1 (platform convention).
    pub fn read_serial(&mut self) -> Result<u64> {
        let lo = self.read_word(0)? as u64;
        let hi = self.read_word(1)? as u64;
        Ok((hi << 32) | lo)
    }

    /// Blow a fuse word.
    ///
    /// # Safety
    /// eFuse programming is **irreversible**. This function must only be
    /// called during factory provisioning under controlled conditions.
    /// Incorrect programming can permanently disable device functionality.
    /// VPP voltage must be present (guaranteed by the platform before calling).
    pub unsafe fn blow_word(&mut self, word_idx: u32, value: u32) -> Result<()> {
        if word_idx as usize >= self.num_words {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: writing to ADDR and DATA followed by PROG triggers an
        // irreversible fuse-blow cycle. All safety preconditions documented above.
        unsafe {
            write32(self.base, EFUSE_ADDR, word_idx);
            write32(self.base, EFUSE_DATA, value);
            write32(self.base, EFUSE_CTRL, EFUSE_CTRL_PROG);
        }
        self.wait_idle()?;
        // Verify by reading back.
        unsafe { write32(self.base, EFUSE_CTRL, EFUSE_CTRL_RD) }
        self.wait_idle()?;
        let readback = unsafe { read32(self.base, EFUSE_READ_DATA) };
        // All bits that were programmed must be set in readback.
        if (readback & value) != value {
            return Err(Error::IoError);
        }
        // Invalidate shadow cache.
        self.shadow_valid = false;
        Ok(())
    }

    /// Return the number of fuse words.
    pub fn num_words(&self) -> usize {
        self.num_words
    }
}

// ── Well-known Fuse Fields ─────────────────────────────────────────────────

/// Secure boot enable fuse (word 2, bit 0).
pub const FUSE_SECURE_BOOT: FuseField = FuseField::new(2, 0, 1, "secure_boot_enable");
/// JTAG disable fuse (word 2, bit 1).
pub const FUSE_JTAG_DISABLE: FuseField = FuseField::new(2, 1, 1, "jtag_disable");
/// Device lifecycle state (word 2, bits 4-7).
pub const FUSE_LIFECYCLE: FuseField = FuseField::new(2, 4, 4, "lifecycle");
/// Manufacturing lot ID (word 4, bits 0-15).
pub const FUSE_LOT_ID: FuseField = FuseField::new(4, 0, 16, "lot_id");
