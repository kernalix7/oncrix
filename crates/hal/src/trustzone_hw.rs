// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM TrustZone hardware abstraction.
//!
//! Manages ARM TrustZone security extensions, which partition hardware resources
//! between Secure World (trusted execution environment) and Non-Secure World
//! (normal OS). Provides an interface for memory region assignment, peripheral
//! security configuration, and world switching.
//!
//! # TrustZone Security Model
//!
//! - **Secure World**: Runs trusted firmware (e.g., OP-TEE), handles secrets
//! - **Non-Secure World**: Runs normal OS (e.g., Linux, ONCRIX), untrusted code
//! - **Monitor Mode**: EL3 firmware mediates between worlds via SMC
//!
//! # References
//!
//! - ARM Security Technology: Building a Secure System using TrustZone Technology
//! - ARM Architecture Reference Manual, Chapter D1 (Security Extensions)

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// TrustZone world identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TzWorld {
    /// Secure world: trusted execution environment.
    Secure,
    /// Non-secure world: normal operating system.
    NonSecure,
}

/// TrustZone security state of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemSecurity {
    /// Region is accessible from Secure world only.
    SecureOnly,
    /// Region is accessible from both worlds.
    NonSecure,
    /// Region is accessible from Non-Secure world only (Secure world reads 0xFF).
    NonSecureOnly,
}

/// TZASC (TrustZone Address Space Controller) region configuration.
///
/// The TZASC partitions the physical address space into regions with
/// configurable security attributes.
#[derive(Debug, Clone, Copy)]
pub struct TzascRegion {
    /// Base physical address of the region.
    pub base: u64,
    /// Size of the region in bytes (must be power of 2).
    pub size: u64,
    /// Security attribute for this region.
    pub security: MemSecurity,
    /// Whether the region is enabled.
    pub enabled: bool,
}

impl TzascRegion {
    /// Creates a non-secure memory region.
    pub const fn non_secure(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            security: MemSecurity::NonSecure,
            enabled: true,
        }
    }

    /// Creates a secure-only memory region.
    pub const fn secure_only(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            security: MemSecurity::SecureOnly,
            enabled: true,
        }
    }

    /// Validates the region configuration (size must be power of 2, >= 4 KB).
    pub fn validate(&self) -> Result<()> {
        if self.size < 4096 || !self.size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if self.base & (self.size - 1) != 0 {
            return Err(Error::InvalidArgument); // Base must be size-aligned
        }
        Ok(())
    }
}

/// TZPC (TrustZone Protection Controller) register set.
///
/// Controls which peripherals are accessible from Secure vs. Non-Secure world.
pub struct TzpcController {
    /// MMIO base of the TZPC.
    base: usize,
    /// Number of decode protection registers (8 peripherals per register).
    num_decode_regs: u8,
}

impl TzpcController {
    /// Creates a new TZPC controller instance.
    pub const fn new(base: usize, num_decode_regs: u8) -> Self {
        Self {
            base,
            num_decode_regs,
        }
    }

    /// Sets peripheral security: if `non_secure` is true, the peripheral is
    /// accessible from Non-Secure world; otherwise it is Secure-only.
    pub fn set_peripheral_security(&self, peripheral_index: u8, non_secure: bool) -> Result<()> {
        let reg = peripheral_index / 8;
        let bit = peripheral_index % 8;
        if reg >= self.num_decode_regs {
            return Err(Error::InvalidArgument);
        }
        let reg_offset = 0x800 + (reg as usize * 4);
        let addr = (self.base + reg_offset) as *mut u32;
        // SAFETY: base is a valid TZPC MMIO region. Writing the decode protection
        // registers configures peripheral security. This affects system security
        // policy and should only be called during Secure World initialization.
        unsafe {
            let cur = (addr as *const u32).read_volatile();
            let new_val = if non_secure {
                cur | (1 << bit)
            } else {
                cur & !(1 << bit)
            };
            addr.write_volatile(new_val);
        }
        Ok(())
    }

    /// Reads the secure size register (TZPC_R0SIZE), defining the first N KB
    /// of physical memory as Secure-only.
    pub fn read_secure_size_kb(&self) -> u32 {
        let addr = self.base as *const u32;
        // SAFETY: base is a valid TZPC MMIO region. The first register (offset 0)
        // is the R0SIZE register, read-only during Non-Secure access.
        let val = unsafe { addr.read_volatile() };
        val & 0x1FF // 9-bit field
    }
}

/// TZASC (TrustZone Address Space Controller) driver.
pub struct TzascController {
    /// MMIO base of the TZASC.
    base: usize,
    /// Number of region registers.
    num_regions: u8,
}

// TZASC register offsets
const TZASC_BUILD_CONFIG: usize = 0x00;
const TZASC_ACTION: usize = 0x04;
const TZASC_REGION_BASE_LO: usize = 0x100;
const TZASC_REGION_ATTRS: usize = 0x108;
const TZASC_REGION_STRIDE: usize = 0x10;

impl TzascController {
    /// Creates a new TZASC controller.
    pub const fn new(base: usize) -> Self {
        Self {
            base,
            num_regions: 0,
        }
    }

    /// Initializes the TZASC by reading capabilities.
    pub fn init(&mut self) -> Result<()> {
        let build_config = self.read32(TZASC_BUILD_CONFIG);
        self.num_regions = ((build_config >> 8) & 0x7F) as u8 + 1;
        Ok(())
    }

    /// Configures a memory region.
    pub fn configure_region(&self, index: u8, region: &TzascRegion) -> Result<()> {
        if index >= self.num_regions {
            return Err(Error::InvalidArgument);
        }
        region.validate()?;

        let base_offset = TZASC_REGION_BASE_LO + (index as usize * TZASC_REGION_STRIDE);
        let attrs_offset = TZASC_REGION_ATTRS + (index as usize * TZASC_REGION_STRIDE);

        self.write32(base_offset, region.base as u32);
        // Write upper bits if available (for TZASC with 64-bit addressing)
        self.write32(base_offset + 4, (region.base >> 32) as u32);

        let ns_bits = match region.security {
            MemSecurity::SecureOnly => 0u32,
            MemSecurity::NonSecure => 0x3 << 16,
            MemSecurity::NonSecureOnly => 0x2 << 16,
        };
        let size_field = region.size.trailing_zeros().saturating_sub(1) as u32;
        let attrs = ns_bits | (size_field << 1) | if region.enabled { 1 } else { 0 };
        self.write32(attrs_offset, attrs);

        Ok(())
    }

    /// Returns the number of configurable regions.
    pub fn num_regions(&self) -> u8 {
        self.num_regions
    }

    fn read32(&self, offset: usize) -> u32 {
        let addr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid TZASC MMIO region. Volatile read is required
        // to prevent the compiler from caching hardware register values.
        unsafe { addr.read_volatile() }
    }

    fn write32(&self, offset: usize, val: u32) {
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid TZASC MMIO region. Volatile write is required
        // to ensure the security configuration is applied to hardware immediately.
        unsafe { addr.write_volatile(val) }
    }
}

impl Default for TzascController {
    fn default() -> Self {
        Self::new(0)
    }
}
