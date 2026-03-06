// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! One-Time Programmable (OTP) / eFuse hardware abstraction.
//!
//! Manages access to OTP fuses and eFuse banks found in SoCs and FPGAs.
//! OTP cells can be read many times but written only once, making them
//! ideal for storing cryptographic keys, device identifiers, and boot configuration.
//!
//! # OTP Write Protocol
//!
//! Writing OTP typically requires elevated voltage and follows a strict sequence:
//! 1. Assert write enable
//! 2. Select the fuse address
//! 3. Apply write voltage for a specified time window
//! 4. De-assert write enable and verify
//!
//! # Security Note
//!
//! OTP write operations are irreversible. Incorrect writes permanently
//! alter device behavior. Callers must validate data before writing.

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// OTP bank identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtpBank(pub u32);

/// OTP fuse location (bank + bit offset within the bank).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtpFuse {
    /// Bank containing this fuse.
    pub bank: OtpBank,
    /// Word offset within the bank.
    pub word: u32,
    /// Bit position within the word.
    pub bit: u8,
}

impl OtpFuse {
    /// Creates a new OTP fuse location.
    pub const fn new(bank: u32, word: u32, bit: u8) -> Self {
        Self {
            bank: OtpBank(bank),
            word,
            bit,
        }
    }
}

/// Well-known OTP fuse names for common SoC fields.
pub mod fuse_names {
    /// Device unique ID (64-bit).
    pub const UNIQUE_ID: &str = "unique_id";
    /// Secure boot enable fuse.
    pub const SECURE_BOOT: &str = "secure_boot";
    /// JTAG disable fuse.
    pub const JTAG_DISABLE: &str = "jtag_disable";
    /// Encryption key hash.
    pub const KEY_HASH: &str = "key_hash";
    /// Manufacturing revision.
    pub const REVISION: &str = "revision";
    /// MAC address.
    pub const MAC_ADDR: &str = "mac_address";
}

/// OTP fuse field descriptor.
#[derive(Debug, Clone, Copy)]
pub struct OtpField {
    /// Human-readable field name.
    pub name: &'static str,
    /// Starting fuse location.
    pub start: OtpFuse,
    /// Number of bits in this field.
    pub num_bits: u32,
    /// Whether this field is security-sensitive (restricted read access).
    pub secret: bool,
}

impl OtpField {
    /// Creates a new OTP field descriptor.
    pub const fn new(name: &'static str, bank: u32, word: u32, bit: u8, num_bits: u32) -> Self {
        Self {
            name,
            start: OtpFuse::new(bank, word, bit),
            num_bits,
            secret: false,
        }
    }

    /// Returns whether the field spans multiple words.
    pub fn is_multi_word(&self) -> bool {
        let end_bit = self.start.bit as u32 + self.num_bits;
        end_bit > 32
    }
}

/// OTP hardware access status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpStatus {
    /// Fuse is unprogrammed (reads as 0).
    Unprogrammed,
    /// Fuse is programmed (reads as 1).
    Programmed,
    /// Fuse is locked (cannot be read or written).
    Locked,
}

/// Trait for OTP/eFuse hardware implementations.
pub trait OtpHal {
    /// Returns the number of banks available.
    fn num_banks(&self) -> u32;

    /// Returns the number of 32-bit words per bank.
    fn words_per_bank(&self) -> u32;

    /// Reads a 32-bit word from OTP.
    fn read_word(&self, bank: OtpBank, word: u32) -> Result<u32>;

    /// Programs (burns) specific bits in an OTP word.
    ///
    /// # Arguments
    ///
    /// * `bank` - Target OTP bank
    /// * `word` - Word offset within the bank
    /// * `bits` - Bitmask of bits to set (bits already set are unchanged)
    ///
    /// # Safety
    ///
    /// This operation is irreversible. Once bits are set, they cannot be cleared.
    fn program_bits(&mut self, bank: OtpBank, word: u32, bits: u32) -> Result<()>;

    /// Reads a multi-bit OTP field value.
    fn read_field(&self, field: &OtpField) -> Result<u64> {
        let bank = field.start.bank;
        let word_data = self.read_word(bank, field.start.word)?;
        let shifted = word_data >> field.start.bit;
        let mask = if field.num_bits >= 32 {
            u32::MAX
        } else {
            (1u32 << field.num_bits) - 1
        };
        Ok((shifted & mask) as u64)
    }

    /// Reads the device unique ID (assumes standard fuse layout).
    fn read_unique_id(&self) -> Result<u64> {
        let lo = self.read_word(OtpBank(0), 0)? as u64;
        let hi = self.read_word(OtpBank(0), 1)? as u64;
        Ok((hi << 32) | lo)
    }

    /// Checks whether secure boot is enabled.
    fn is_secure_boot(&self) -> bool {
        self.read_word(OtpBank(0), 2).map_or(false, |w| w & 1 != 0)
    }

    /// Validates a word/bank address.
    fn validate_addr(&self, bank: OtpBank, word: u32) -> Result<()> {
        if bank.0 >= self.num_banks() {
            return Err(Error::InvalidArgument);
        }
        if word >= self.words_per_bank() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// MMIO-based OTP controller.
pub struct MmioOtpController {
    /// Base MMIO address.
    base: usize,
    /// Number of OTP banks.
    num_banks: u32,
    /// Words per bank.
    words_per_bank: u32,
}

impl MmioOtpController {
    /// Creates a new MMIO OTP controller.
    pub const fn new(base: usize, num_banks: u32, words_per_bank: u32) -> Self {
        Self {
            base,
            num_banks,
            words_per_bank,
        }
    }

    fn reg_offset(bank: OtpBank, word: u32) -> usize {
        (bank.0 as usize * 0x100) + (word as usize * 4)
    }
}

impl OtpHal for MmioOtpController {
    fn num_banks(&self) -> u32 {
        self.num_banks
    }

    fn words_per_bank(&self) -> u32 {
        self.words_per_bank
    }

    fn read_word(&self, bank: OtpBank, word: u32) -> Result<u32> {
        self.validate_addr(bank, word)?;
        let offset = Self::reg_offset(bank, word);
        let addr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid OTP MMIO region, and the offset is within bounds
        // (validated above). Volatile read is required for hardware register access.
        Ok(unsafe { addr.read_volatile() })
    }

    fn program_bits(&mut self, bank: OtpBank, word: u32, bits: u32) -> Result<()> {
        self.validate_addr(bank, word)?;
        let offset = Self::reg_offset(bank, word);
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid OTP MMIO region. Writing to OTP registers
        // programs fuses; the controller hardware enforces write-once semantics.
        // The write enable and voltage sequencing are assumed to be handled
        // by the hardware before this function is called.
        unsafe { addr.write_volatile(bits) }
        Ok(())
    }
}

impl Default for MmioOtpController {
    fn default() -> Self {
        Self::new(0, 4, 32)
    }
}
