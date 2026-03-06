// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GPIO chip operations.
//!
//! Provides a GPIO chip abstraction supporting line direction control,
//! value get/set, open-drain/open-source modes, active-low handling,
//! and per-line IRQ configuration.
//!
//! # Architecture
//!
//! A [`GpioChip`] represents one GPIO controller with up to
//! [`MAX_GPIO_LINES`] lines. Each line has an associated
//! [`GpioLineConfig`] describing its mode. The chip exports
//! standard operations through [`GpioChip`] methods.
//!
//! # GPIO Modes
//!
//! - **Input** — tri-state; value is read from the pin.
//! - **OutputPushPull** — driven high or low.
//! - **OutputOpenDrain** — asserts low, releases to high-Z for high.
//! - **OutputOpenSource** — asserts high, releases to high-Z for low.
//!
//! Reference: Linux `drivers/gpio/gpiolib.c`, `include/linux/gpio/driver.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum GPIO lines per chip.
const MAX_GPIO_LINES: usize = 64;

/// Maximum registered GPIO chips.
const MAX_GPIO_CHIPS: usize = 8;

/// Sentinel value meaning "no IRQ assigned".
const NO_IRQ: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// GPIO Direction
// ---------------------------------------------------------------------------

/// Direction of a GPIO line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioDirection {
    /// Line is configured as an input.
    Input,
    /// Line is configured as a push-pull output.
    OutputPushPull,
    /// Line is configured as an open-drain output (assert-low only).
    OutputOpenDrain,
    /// Line is configured as an open-source output (assert-high only).
    OutputOpenSource,
}

// ---------------------------------------------------------------------------
// GPIO IRQ Trigger
// ---------------------------------------------------------------------------

/// IRQ trigger type for a GPIO input line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioIrqTrigger {
    /// No interrupt configured.
    None,
    /// Trigger on rising edge.
    RisingEdge,
    /// Trigger on falling edge.
    FallingEdge,
    /// Trigger on both edges.
    BothEdges,
    /// Trigger while line is at logical high level.
    LevelHigh,
    /// Trigger while line is at logical low level.
    LevelLow,
}

// ---------------------------------------------------------------------------
// GPIO Line Configuration
// ---------------------------------------------------------------------------

/// Configuration for a single GPIO line.
#[derive(Debug, Clone, Copy)]
pub struct GpioLineConfig {
    /// Direction of the line.
    pub direction: GpioDirection,
    /// Whether the logical value is inverted (active-low).
    pub active_low: bool,
    /// Interrupt trigger type (only valid when `direction == Input`).
    pub irq_trigger: GpioIrqTrigger,
    /// System IRQ number assigned to this line, or [`NO_IRQ`].
    pub irq_number: u32,
    /// Current output value (cached; 0 or 1).
    pub output_value: u8,
    /// Whether the line is currently requested/allocated.
    pub requested: bool,
    /// Human-readable label for the line (up to 15 chars + NUL).
    pub label: [u8; 16],
}

impl Default for GpioLineConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl GpioLineConfig {
    /// Create a default line configuration (input, no IRQ, normal polarity).
    pub const fn new() -> Self {
        Self {
            direction: GpioDirection::Input,
            active_low: false,
            irq_trigger: GpioIrqTrigger::None,
            irq_number: NO_IRQ,
            output_value: 0,
            requested: false,
            label: [0u8; 16],
        }
    }

    /// Set the ASCII label for this line (truncated to 15 characters).
    pub fn set_label(&mut self, label: &[u8]) {
        let copy_len = label.len().min(15);
        self.label[..copy_len].copy_from_slice(&label[..copy_len]);
        self.label[copy_len] = 0;
    }
}

// ---------------------------------------------------------------------------
// GPIO Chip
// ---------------------------------------------------------------------------

/// A GPIO chip controller with up to [`MAX_GPIO_LINES`] lines.
///
/// Drives underlying hardware via the `read_reg` / `write_reg` callbacks
/// passed to [`GpioChip::new`]. In practice these would call into an
/// MMIO-mapped GPIO controller register block.
pub struct GpioChip {
    /// Unique chip identifier.
    pub chip_id: u32,
    /// Base GPIO number in the system-wide GPIO number space.
    pub base: u32,
    /// Number of GPIO lines this chip controls.
    pub num_lines: usize,
    /// Per-line configuration.
    lines: [GpioLineConfig; MAX_GPIO_LINES],
    /// MMIO base address of the GPIO controller.
    mmio_base: u64,
    /// Whether the chip has been successfully initialised.
    initialized: bool,
}

impl GpioChip {
    /// Create a new GPIO chip.
    ///
    /// # Arguments
    ///
    /// - `chip_id` — unique ID for this chip.
    /// - `base` — first GPIO number in the system space.
    /// - `num_lines` — number of lines (clamped to [`MAX_GPIO_LINES`]).
    /// - `mmio_base` — MMIO address of the GPIO controller registers.
    pub fn new(chip_id: u32, base: u32, num_lines: usize, mmio_base: u64) -> Self {
        let clamped = num_lines.min(MAX_GPIO_LINES);
        Self {
            chip_id,
            base,
            num_lines: clamped,
            lines: [const { GpioLineConfig::new() }; MAX_GPIO_LINES],
            mmio_base,
            initialized: false,
        }
    }

    /// Initialise the GPIO chip.
    ///
    /// Verifies the MMIO base is non-zero and marks all lines as input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mmio_base` is zero or
    /// `num_lines` is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 || self.num_lines == 0 {
            return Err(Error::InvalidArgument);
        }
        // Default all lines to input, normal polarity.
        for line in self.lines[..self.num_lines].iter_mut() {
            line.direction = GpioDirection::Input;
            line.active_low = false;
            line.irq_trigger = GpioIrqTrigger::None;
            line.irq_number = NO_IRQ;
            line.requested = false;
        }
        self.initialized = true;
        Ok(())
    }

    // ----- Private MMIO helpers -----

    /// Read a 32-bit MMIO register at `offset` bytes from `mmio_base`.
    fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base is the GPIO controller's MMIO BAR, mapped
        // into kernel virtual space. The offset is within the register
        // block (< 4 KiB for all known controllers).
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a 32-bit value to an MMIO register at `offset`.
    fn write_reg(&self, offset: u32, val: u32) {
        // SAFETY: same as read_reg — valid MMIO address within controller.
        unsafe {
            core::ptr::write_volatile((self.mmio_base + offset as u64) as *mut u32, val);
        }
    }

    // ----- Line validation -----

    fn check_line(&self, line: usize) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if line >= self.num_lines {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    // ----- Public API -----

    /// Request (allocate) a GPIO line for use.
    ///
    /// Sets a human-readable label on the line. Returns
    /// [`Error::Busy`] if already requested, [`Error::InvalidArgument`]
    /// if the line index is out of range.
    pub fn request_line(&mut self, line: usize, label: &[u8]) -> Result<()> {
        self.check_line(line)?;
        if self.lines[line].requested {
            return Err(Error::Busy);
        }
        self.lines[line].requested = true;
        self.lines[line].set_label(label);
        Ok(())
    }

    /// Release a previously requested GPIO line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the line was not requested.
    pub fn free_line(&mut self, line: usize) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        self.lines[line] = GpioLineConfig::new();
        Ok(())
    }

    /// Configure a line as an input.
    ///
    /// Clears the corresponding bit in the direction register (offset 0x04).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `line` is out of range, or
    /// [`Error::NotFound`] if the line has not been requested.
    pub fn direction_input(&mut self, line: usize) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        // Direction register at offset 0x04; 0-bit = input, 1-bit = output.
        // Each 32-bit register covers 32 lines.
        let reg_off = 0x04u32 + (line as u32 / 32) * 4;
        let bit = 1u32 << (line % 32);
        let cur = self.read_reg(reg_off);
        self.write_reg(reg_off, cur & !bit);
        self.lines[line].direction = GpioDirection::Input;
        Ok(())
    }

    /// Configure a line as an output and drive it to `value`.
    ///
    /// Sets the direction bit in the direction register (offset 0x04)
    /// and writes `value` to the output data register (offset 0x00).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `line` is out of range, or
    /// [`Error::NotFound`] if not requested.
    pub fn direction_output(&mut self, line: usize, value: u8) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        let reg_off_dir = 0x04u32 + (line as u32 / 32) * 4;
        let reg_off_dat = 0x00u32 + (line as u32 / 32) * 4;
        let bit = 1u32 << (line % 32);
        // Set direction bit → output.
        let dir = self.read_reg(reg_off_dir);
        self.write_reg(reg_off_dir, dir | bit);
        // Set/clear data bit.
        let dat = self.read_reg(reg_off_dat);
        let logical = self.apply_active_low(line, value);
        if logical != 0 {
            self.write_reg(reg_off_dat, dat | bit);
        } else {
            self.write_reg(reg_off_dat, dat & !bit);
        }
        self.lines[line].direction = GpioDirection::OutputPushPull;
        self.lines[line].output_value = value & 1;
        Ok(())
    }

    /// Read the current logical value of a GPIO input line.
    ///
    /// Reads the input data register (offset 0x08) and applies
    /// active-low inversion if configured.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `line` is out of range,
    /// [`Error::NotFound`] if not requested.
    pub fn get_value(&self, line: usize) -> Result<u8> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        let reg_off = 0x08u32 + (line as u32 / 32) * 4;
        let raw = self.read_reg(reg_off);
        let bit = (raw >> (line % 32)) & 1;
        let logical = if self.lines[line].active_low {
            bit ^ 1
        } else {
            bit
        };
        Ok(logical as u8)
    }

    /// Drive an output GPIO line to the logical value `value`.
    ///
    /// For push-pull outputs, writes directly to the data register.
    /// For open-drain, only drives low; releases the line for high.
    /// For open-source, only drives high; releases for low.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the line is not configured
    /// as an output.
    pub fn set_value(&mut self, line: usize, value: u8) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        match self.lines[line].direction {
            GpioDirection::Input => return Err(Error::InvalidArgument),
            GpioDirection::OutputOpenDrain => {
                // Open-drain: drive low to assert, input mode for high.
                if value == 0 {
                    self.drive_low(line)?;
                } else {
                    // Release: switch to input (high-Z).
                    self.direction_input(line)?;
                    self.lines[line].direction = GpioDirection::OutputOpenDrain;
                }
            }
            GpioDirection::OutputOpenSource => {
                // Open-source: drive high to assert, input for low.
                if value != 0 {
                    self.drive_high(line)?;
                } else {
                    self.direction_input(line)?;
                    self.lines[line].direction = GpioDirection::OutputOpenSource;
                }
            }
            GpioDirection::OutputPushPull => {
                let reg_off = 0x00u32 + (line as u32 / 32) * 4;
                let bit = 1u32 << (line % 32);
                let logical = self.apply_active_low(line, value);
                let dat = self.read_reg(reg_off);
                if logical != 0 {
                    self.write_reg(reg_off, dat | bit);
                } else {
                    self.write_reg(reg_off, dat & !bit);
                }
                self.lines[line].output_value = value & 1;
            }
        }
        Ok(())
    }

    /// Configure the IRQ trigger type for an input line.
    ///
    /// Writes to the interrupt type register (offset 0x30) and edge
    /// registers (offset 0x34, 0x38).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the line is not an input.
    pub fn set_irq_type(&mut self, line: usize, trigger: GpioIrqTrigger) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        if self.lines[line].direction != GpioDirection::Input {
            return Err(Error::InvalidArgument);
        }
        // IRQ type registers: offset 0x30 = level vs edge,
        // 0x34 = rising edge enable, 0x38 = falling edge enable.
        let reg_base = 0x30u32 + (line as u32 / 32) * 12;
        let bit = 1u32 << (line % 32);
        match trigger {
            GpioIrqTrigger::None => {
                let cur = self.read_reg(reg_base);
                self.write_reg(reg_base, cur & !bit);
            }
            GpioIrqTrigger::RisingEdge => {
                let cur = self.read_reg(reg_base);
                self.write_reg(reg_base, cur & !bit); // edge mode
                let re = self.read_reg(reg_base + 4);
                self.write_reg(reg_base + 4, re | bit);
                let fe = self.read_reg(reg_base + 8);
                self.write_reg(reg_base + 8, fe & !bit);
            }
            GpioIrqTrigger::FallingEdge => {
                let cur = self.read_reg(reg_base);
                self.write_reg(reg_base, cur & !bit);
                let re = self.read_reg(reg_base + 4);
                self.write_reg(reg_base + 4, re & !bit);
                let fe = self.read_reg(reg_base + 8);
                self.write_reg(reg_base + 8, fe | bit);
            }
            GpioIrqTrigger::BothEdges => {
                let cur = self.read_reg(reg_base);
                self.write_reg(reg_base, cur & !bit);
                let re = self.read_reg(reg_base + 4);
                self.write_reg(reg_base + 4, re | bit);
                let fe = self.read_reg(reg_base + 8);
                self.write_reg(reg_base + 8, fe | bit);
            }
            GpioIrqTrigger::LevelHigh => {
                let cur = self.read_reg(reg_base);
                self.write_reg(reg_base, cur | bit); // level mode
                let re = self.read_reg(reg_base + 4);
                self.write_reg(reg_base + 4, re | bit); // high
            }
            GpioIrqTrigger::LevelLow => {
                let cur = self.read_reg(reg_base);
                self.write_reg(reg_base, cur | bit);
                let re = self.read_reg(reg_base + 4);
                self.write_reg(reg_base + 4, re & !bit); // low
            }
        }
        self.lines[line].irq_trigger = trigger;
        Ok(())
    }

    /// Assign a system IRQ number to a GPIO line.
    pub fn set_irq_number(&mut self, line: usize, irq: u32) -> Result<()> {
        self.check_line(line)?;
        self.lines[line].irq_number = irq;
        Ok(())
    }

    /// Configure a line for open-drain mode and set initial value.
    pub fn set_open_drain(&mut self, line: usize, value: u8) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        self.lines[line].direction = GpioDirection::OutputOpenDrain;
        self.set_value(line, value)
    }

    /// Configure a line for open-source mode and set initial value.
    pub fn set_open_source(&mut self, line: usize, value: u8) -> Result<()> {
        self.check_line(line)?;
        if !self.lines[line].requested {
            return Err(Error::NotFound);
        }
        self.lines[line].direction = GpioDirection::OutputOpenSource;
        self.set_value(line, value)
    }

    /// Set the active-low flag for a line.
    pub fn set_active_low(&mut self, line: usize, active_low: bool) -> Result<()> {
        self.check_line(line)?;
        self.lines[line].active_low = active_low;
        Ok(())
    }

    /// Return a reference to the configuration for a line.
    pub fn line_config(&self, line: usize) -> Option<&GpioLineConfig> {
        if line < self.num_lines {
            Some(&self.lines[line])
        } else {
            None
        }
    }

    /// Return whether the chip is initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ----- Internal helpers -----

    fn apply_active_low(&self, line: usize, logical: u8) -> u8 {
        if self.lines[line].active_low {
            logical ^ 1
        } else {
            logical
        }
    }

    fn drive_low(&self, line: usize) -> Result<()> {
        let reg_off_dir = 0x04u32 + (line as u32 / 32) * 4;
        let reg_off_dat = 0x00u32 + (line as u32 / 32) * 4;
        let bit = 1u32 << (line % 32);
        let dir = self.read_reg(reg_off_dir);
        self.write_reg(reg_off_dir, dir | bit);
        let dat = self.read_reg(reg_off_dat);
        self.write_reg(reg_off_dat, dat & !bit);
        Ok(())
    }

    fn drive_high(&self, line: usize) -> Result<()> {
        let reg_off_dir = 0x04u32 + (line as u32 / 32) * 4;
        let reg_off_dat = 0x00u32 + (line as u32 / 32) * 4;
        let bit = 1u32 << (line % 32);
        let dir = self.read_reg(reg_off_dir);
        self.write_reg(reg_off_dir, dir | bit);
        let dat = self.read_reg(reg_off_dat);
        self.write_reg(reg_off_dat, dat | bit);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GPIO Chip Registry
// ---------------------------------------------------------------------------

/// System-wide registry of GPIO chips.
pub struct GpioChipRegistry {
    /// Registered chips.
    chips: [Option<GpioChip>; MAX_GPIO_CHIPS],
    /// Number of registered chips.
    count: usize,
}

impl Default for GpioChipRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GpioChipRegistry {
    /// Create an empty GPIO chip registry.
    pub const fn new() -> Self {
        Self {
            chips: [const { None }; MAX_GPIO_CHIPS],
            count: 0,
        }
    }

    /// Register a GPIO chip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, chip: GpioChip) -> Result<usize> {
        if self.count >= MAX_GPIO_CHIPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.chips[idx] = Some(chip);
        self.count += 1;
        Ok(idx)
    }

    /// Get a reference to a chip by index.
    pub fn get(&self, idx: usize) -> Option<&GpioChip> {
        if idx < self.count {
            self.chips[idx].as_ref()
        } else {
            None
        }
    }

    /// Get a mutable reference to a chip by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut GpioChip> {
        if idx < self.count {
            self.chips[idx].as_mut()
        } else {
            None
        }
    }

    /// Return the number of registered chips.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Resolve a global GPIO number to (chip index, line index).
    pub fn resolve_gpio(&self, gpio: u32) -> Option<(usize, usize)> {
        for (i, chip) in self.chips[..self.count].iter().enumerate() {
            if let Some(c) = chip {
                if gpio >= c.base && (gpio - c.base) < c.num_lines as u32 {
                    return Some((i, (gpio - c.base) as usize));
                }
            }
        }
        None
    }
}
