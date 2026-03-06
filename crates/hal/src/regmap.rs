// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Register map abstraction for MMIO, I2C, and SPI register access.
//!
//! Provides a unified interface to access hardware registers regardless of the
//! underlying bus (MMIO, I2C, SPI). Drivers use `RegMap` to read/write device
//! registers in a bus-agnostic manner, simplifying porting across platforms.

use oncrix_lib::{Error, Result};

/// Maximum number of cached register values for debugging.
const REGMAP_CACHE_SIZE: usize = 64;

/// Register width supported by the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegWidth {
    /// 8-bit registers.
    Bits8,
    /// 16-bit registers.
    Bits16,
    /// 32-bit registers.
    Bits32,
}

/// Bus type underlying a [`RegMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusType {
    /// Memory-mapped I/O.
    Mmio,
    /// I2C serial bus.
    I2c,
    /// SPI serial bus.
    Spi,
}

/// Configuration for creating a register map.
#[derive(Debug, Clone, Copy)]
pub struct RegMapConfig {
    /// Width of each register.
    pub reg_width: RegWidth,
    /// Bus type used to access registers.
    pub bus: BusType,
    /// Base address (MMIO base or device address on I2C/SPI).
    pub base: u64,
    /// Total number of registers.
    pub num_regs: usize,
    /// Enable read-back caching (reduces bus traffic).
    pub cache_enabled: bool,
}

impl RegMapConfig {
    /// Creates a new MMIO register map config.
    pub const fn mmio(base: u64, num_regs: usize, reg_width: RegWidth) -> Self {
        Self {
            reg_width,
            bus: BusType::Mmio,
            base,
            num_regs,
            cache_enabled: false,
        }
    }

    /// Creates a new I2C register map config.
    pub const fn i2c(device_addr: u64, num_regs: usize, reg_width: RegWidth) -> Self {
        Self {
            reg_width,
            bus: BusType::I2c,
            base: device_addr,
            num_regs,
            cache_enabled: true,
        }
    }
}

impl Default for RegMapConfig {
    fn default() -> Self {
        Self::mmio(0, 0, RegWidth::Bits32)
    }
}

/// Cached register entry.
#[derive(Debug, Clone, Copy, Default)]
struct CacheEntry {
    /// Register offset.
    offset: u32,
    /// Cached value.
    value: u32,
    /// Whether this entry is valid.
    valid: bool,
}

/// Bus-agnostic register map.
///
/// # Safety
///
/// MMIO access uses raw pointer arithmetic. Callers must ensure the base address
/// is valid and the region is mapped before constructing a `RegMap`.
pub struct RegMap {
    config: RegMapConfig,
    cache: [CacheEntry; REGMAP_CACHE_SIZE],
}

impl RegMap {
    /// Creates a new register map.
    ///
    /// # Arguments
    ///
    /// * `config` — Register map configuration.
    pub const fn new(config: RegMapConfig) -> Self {
        Self {
            config,
            cache: [const {
                CacheEntry {
                    offset: 0,
                    value: 0,
                    valid: false,
                }
            }; REGMAP_CACHE_SIZE],
        }
    }

    /// Returns the bus type.
    pub fn bus_type(&self) -> BusType {
        self.config.bus
    }

    /// Reads a 32-bit register at `offset` (in register units).
    ///
    /// For MMIO the physical offset in bytes is `offset * sizeof(reg)`.
    pub fn read(&self, offset: u32) -> Result<u32> {
        if (offset as usize) >= self.config.num_regs {
            return Err(Error::InvalidArgument);
        }
        if self.config.cache_enabled {
            if let Some(v) = self.cache_lookup(offset) {
                return Ok(v);
            }
        }
        match self.config.bus {
            BusType::Mmio => Ok(self.mmio_read(offset)),
            BusType::I2c | BusType::Spi => {
                // Bus transactions would be issued here via the bus driver.
                Err(Error::NotImplemented)
            }
        }
    }

    /// Writes a 32-bit value to register at `offset`.
    pub fn write(&mut self, offset: u32, value: u32) -> Result<()> {
        if (offset as usize) >= self.config.num_regs {
            return Err(Error::InvalidArgument);
        }
        match self.config.bus {
            BusType::Mmio => {
                self.mmio_write(offset, value);
            }
            BusType::I2c | BusType::Spi => {
                return Err(Error::NotImplemented);
            }
        }
        if self.config.cache_enabled {
            self.cache_update(offset, value);
        }
        Ok(())
    }

    /// Performs a read-modify-write: clears `mask` bits then ORs in `bits`.
    pub fn update_bits(&mut self, offset: u32, mask: u32, bits: u32) -> Result<()> {
        let val = self.read(offset)?;
        self.write(offset, (val & !mask) | (bits & mask))
    }

    /// Performs a bulk write of `count` consecutive registers starting at `offset`.
    pub fn bulk_write(&mut self, offset: u32, values: &[u32]) -> Result<()> {
        for (i, &v) in values.iter().enumerate() {
            self.write(offset + i as u32, v)?;
        }
        Ok(())
    }

    /// Returns the number of registers in this map.
    pub fn num_regs(&self) -> usize {
        self.config.num_regs
    }

    // ---- private helpers ----

    fn byte_offset(&self, reg_offset: u32) -> usize {
        let sz = match self.config.reg_width {
            RegWidth::Bits8 => 1,
            RegWidth::Bits16 => 2,
            RegWidth::Bits32 => 4,
        };
        (reg_offset as usize) * sz
    }

    fn mmio_read(&self, offset: u32) -> u32 {
        let byte_off = self.byte_offset(offset);
        let ptr = (self.config.base as usize + byte_off) as *const u32;
        // SAFETY: Caller guarantees the MMIO region is mapped and accessible;
        // volatile read prevents the compiler from eliding hardware reads.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn mmio_write(&self, offset: u32, value: u32) {
        let byte_off = self.byte_offset(offset);
        let ptr = (self.config.base as usize + byte_off) as *mut u32;
        // SAFETY: Same guarantee as mmio_read; volatile write prevents caching.
        unsafe { core::ptr::write_volatile(ptr, value) }
    }

    fn cache_lookup(&self, offset: u32) -> Option<u32> {
        for entry in &self.cache {
            if entry.valid && entry.offset == offset {
                return Some(entry.value);
            }
        }
        None
    }

    fn cache_update(&mut self, offset: u32, value: u32) {
        // Update existing entry if present.
        for entry in self.cache.iter_mut() {
            if entry.valid && entry.offset == offset {
                entry.value = value;
                return;
            }
        }
        // Find an empty slot.
        for entry in self.cache.iter_mut() {
            if !entry.valid {
                entry.offset = offset;
                entry.value = value;
                entry.valid = true;
                return;
            }
        }
        // Cache is full — evict slot 0 (simple FIFO eviction).
        self.cache[0] = CacheEntry {
            offset,
            value,
            valid: true,
        };
    }
}

impl Default for RegMap {
    fn default() -> Self {
        Self::new(RegMapConfig::default())
    }
}

/// Trait for devices that expose a register map.
pub trait RegMapDevice {
    /// Returns an immutable reference to the device's register map.
    fn regmap(&self) -> &RegMap;

    /// Returns a mutable reference to the device's register map.
    fn regmap_mut(&mut self) -> &mut RegMap;
}

/// Reads a named register from a `RegMapDevice`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `offset` is out of bounds.
pub fn regmap_read(dev: &impl RegMapDevice, offset: u32) -> Result<u32> {
    dev.regmap().read(offset)
}

/// Writes a named register on a `RegMapDevice`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `offset` is out of bounds.
pub fn regmap_write(dev: &mut impl RegMapDevice, offset: u32, value: u32) -> Result<()> {
    dev.regmap_mut().write(offset, value)
}

/// Applies a bitmask update to a register on a `RegMapDevice`.
pub fn regmap_update_bits(
    dev: &mut impl RegMapDevice,
    offset: u32,
    mask: u32,
    bits: u32,
) -> Result<()> {
    dev.regmap_mut().update_bits(offset, mask, bits)
}
