// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GPIO pin controller driver.
//!
//! Provides a GPIO subsystem supporting multiple chips with pin
//! request/free, direction control, value read/write, edge
//! detection, and interrupt type configuration.
//!
//! # Architecture
//!
//! - **GpioDirection** — input or output pin direction.
//! - **GpioLevel** — logical low or high level.
//! - **GpioEdge** — edge detection mode for interrupt generation.
//! - **GpioIrqType** — interrupt trigger type (edge or level).
//! - **GpioPin** — state descriptor for a single GPIO line.
//! - **GpioChip** — a GPIO controller managing up to
//!   [`MAX_PINS_PER_CHIP`] pins.
//! - **GpioRegistry** — manages up to [`MAX_GPIO_CHIPS`]
//!   controllers.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of GPIO chip controllers.
const MAX_GPIO_CHIPS: usize = 4;

/// Maximum number of pins per GPIO chip.
const _MAX_PINS_PER_CHIP: usize = 64;

/// Line flag: active-low polarity.
const _GPIO_LINE_FLAG_ACTIVE_LOW: u32 = 0x04;

/// Line flag: open-drain output mode.
const _GPIO_LINE_FLAG_OPEN_DRAIN: u32 = 0x08;

/// Line flag: open-source output mode.
const _GPIO_LINE_FLAG_OPEN_SOURCE: u32 = 0x10;

// -------------------------------------------------------------------
// GpioDirection
// -------------------------------------------------------------------

/// GPIO pin direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioDirection {
    /// Pin configured as input.
    #[default]
    Input,
    /// Pin configured as output.
    Output,
}

// -------------------------------------------------------------------
// GpioLevel
// -------------------------------------------------------------------

/// GPIO pin logical level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioLevel {
    /// Logical low (0).
    #[default]
    Low,
    /// Logical high (1).
    High,
}

// -------------------------------------------------------------------
// GpioEdge
// -------------------------------------------------------------------

/// GPIO edge detection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioEdge {
    /// No edge detection.
    #[default]
    None,
    /// Detect rising edges only.
    Rising,
    /// Detect falling edges only.
    Falling,
    /// Detect both rising and falling edges.
    Both,
}

// -------------------------------------------------------------------
// GpioIrqType
// -------------------------------------------------------------------

/// GPIO interrupt trigger type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioIrqType {
    /// No interrupt configured.
    #[default]
    None,
    /// Interrupt on rising edge.
    EdgeRising,
    /// Interrupt on falling edge.
    EdgeFalling,
    /// Interrupt on both edges.
    EdgeBoth,
    /// Interrupt while level is high.
    LevelHigh,
    /// Interrupt while level is low.
    LevelLow,
}

// -------------------------------------------------------------------
// GpioPin
// -------------------------------------------------------------------

/// State descriptor for a single GPIO line.
pub struct GpioPin {
    /// Pin number within the chip.
    pub number: u16,
    /// Current direction (input or output).
    pub direction: GpioDirection,
    /// Current logical level.
    pub level: GpioLevel,
    /// Edge detection mode.
    pub edge: GpioEdge,
    /// Interrupt trigger type.
    pub irq_type: GpioIrqType,
    /// Line configuration flags (see `GPIO_LINE_FLAG_*`).
    pub flags: u32,
    /// Whether the pin uses active-low polarity.
    pub active_low: bool,
    /// Whether the pin has been requested by a consumer.
    pub requested: bool,
    /// Human-readable label (UTF-8, not NUL-terminated).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Number of interrupts handled on this pin.
    pub irq_count: u64,
}

// -------------------------------------------------------------------
// GpioChip
// -------------------------------------------------------------------

/// A GPIO chip controller.
///
/// Manages up to 64 GPIO pins and provides request/free,
/// direction control, value read/write, edge detection, and
/// interrupt type configuration.
pub struct GpioChip {
    /// Chip identifier.
    id: u8,
    /// First GPIO number managed by this chip.
    base: u16,
    /// Number of GPIO lines provided by this chip.
    ngpio: u16,
    /// Base address for memory-mapped I/O registers.
    mmio_base: u64,
    /// Pin state descriptors.
    pins: [GpioPin; 64],
    /// Human-readable chip label (UTF-8, not NUL-terminated).
    label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    label_len: usize,
    /// Whether this chip is active (initialised).
    active: bool,
}

/// Constant empty pin for array initialisation.
const EMPTY_PIN: GpioPin = GpioPin {
    number: 0,
    direction: GpioDirection::Input,
    level: GpioLevel::Low,
    edge: GpioEdge::None,
    irq_type: GpioIrqType::None,
    flags: 0,
    active_low: false,
    requested: false,
    label: [0u8; 32],
    label_len: 0,
    irq_count: 0,
};

impl GpioChip {
    /// Creates a new GPIO chip with the given identifier, base GPIO
    /// number, pin count, and MMIO base address.
    pub fn new(id: u8, base: u16, ngpio: u16, mmio_base: u64) -> Self {
        let mut pins = [EMPTY_PIN; 64];
        let count = (ngpio as usize).min(64);
        let mut i = 0;
        while i < count {
            pins[i].number = base + i as u16;
            i += 1;
        }
        Self {
            id,
            base,
            ngpio,
            mmio_base,
            pins,
            label: [0u8; 32],
            label_len: 0,
            active: true,
        }
    }

    /// Validates that `pin` is within this chip's range and returns
    /// the index into the `pins` array.
    fn pin_index(&self, pin: u16) -> Result<usize> {
        if pin < self.base {
            return Err(Error::InvalidArgument);
        }
        let idx = (pin - self.base) as usize;
        if idx >= self.ngpio as usize || idx >= 64 {
            return Err(Error::InvalidArgument);
        }
        Ok(idx)
    }

    /// Requests a GPIO pin for use with the given label and
    /// direction.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range or `label` is empty, and [`Error::Busy`] when the
    /// pin is already requested.
    pub fn request(&mut self, pin: u16, label: &[u8], dir: GpioDirection) -> Result<()> {
        if label.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let idx = self.pin_index(pin)?;
        if self.pins[idx].requested {
            return Err(Error::Busy);
        }
        let copy_len = label.len().min(32);
        let mut pin_label = [0u8; 32];
        pin_label[..copy_len].copy_from_slice(&label[..copy_len]);
        self.pins[idx].requested = true;
        self.pins[idx].direction = dir;
        self.pins[idx].label = pin_label;
        self.pins[idx].label_len = copy_len;
        Ok(())
    }

    /// Releases a previously requested GPIO pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range, and [`Error::NotFound`] when the pin is not
    /// currently requested.
    pub fn free(&mut self, pin: u16) -> Result<()> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        self.pins[idx].requested = false;
        self.pins[idx].direction = GpioDirection::Input;
        self.pins[idx].level = GpioLevel::Low;
        self.pins[idx].edge = GpioEdge::None;
        self.pins[idx].irq_type = GpioIrqType::None;
        self.pins[idx].flags = 0;
        self.pins[idx].active_low = false;
        self.pins[idx].label = [0u8; 32];
        self.pins[idx].label_len = 0;
        Ok(())
    }

    /// Sets the direction of a requested GPIO pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range, and [`Error::NotFound`] when the pin is not
    /// currently requested.
    pub fn set_direction(&mut self, pin: u16, dir: GpioDirection) -> Result<()> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        self.pins[idx].direction = dir;
        Ok(())
    }

    /// Returns the current logical level of a requested GPIO pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range, and [`Error::NotFound`] when the pin is not
    /// currently requested.
    pub fn get_value(&self, pin: u16) -> Result<GpioLevel> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        Ok(self.pins[idx].level)
    }

    /// Sets the logical level of a requested output GPIO pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range or the pin is configured as input, and
    /// [`Error::NotFound`] when the pin is not currently requested.
    pub fn set_value(&mut self, pin: u16, level: GpioLevel) -> Result<()> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        if self.pins[idx].direction == GpioDirection::Input {
            return Err(Error::InvalidArgument);
        }
        self.pins[idx].level = level;
        Ok(())
    }

    /// Configures edge detection on a requested GPIO pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range, and [`Error::NotFound`] when the pin is not
    /// currently requested.
    pub fn set_edge(&mut self, pin: u16, edge: GpioEdge) -> Result<()> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        self.pins[idx].edge = edge;
        Ok(())
    }

    /// Configures the interrupt trigger type on a requested GPIO
    /// pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range, and [`Error::NotFound`] when the pin is not
    /// currently requested.
    pub fn set_irq_type(&mut self, pin: u16, irq: GpioIrqType) -> Result<()> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        self.pins[idx].irq_type = irq;
        Ok(())
    }

    /// Configures active-low polarity on a requested GPIO pin.
    ///
    /// Returns [`Error::InvalidArgument`] when `pin` is out of
    /// range, and [`Error::NotFound`] when the pin is not
    /// currently requested.
    pub fn set_active_low(&mut self, pin: u16, active_low: bool) -> Result<()> {
        let idx = self.pin_index(pin)?;
        if !self.pins[idx].requested {
            return Err(Error::NotFound);
        }
        self.pins[idx].active_low = active_low;
        Ok(())
    }

    /// Handles an interrupt on the given pin by incrementing its
    /// IRQ counter.
    ///
    /// Silently ignored if `pin` is out of range or not requested.
    pub fn handle_irq(&mut self, pin: u16) {
        if let Ok(idx) = self.pin_index(pin) {
            if self.pins[idx].requested {
                self.pins[idx].irq_count += 1;
            }
        }
    }

    /// Returns the MMIO base address of this controller.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Returns the chip label as a byte slice.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }

    /// Sets the chip label.
    pub fn set_label(&mut self, name: &[u8]) {
        let copy_len = name.len().min(32);
        self.label = [0u8; 32];
        self.label[..copy_len].copy_from_slice(&name[..copy_len]);
        self.label_len = copy_len;
    }

    /// Returns whether this chip is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the number of GPIO lines provided by this chip.
    pub fn pin_count(&self) -> u16 {
        self.ngpio
    }
}

// -------------------------------------------------------------------
// GpioRegistry
// -------------------------------------------------------------------

/// Registry of GPIO chip controllers.
///
/// Manages up to [`MAX_GPIO_CHIPS`] chip instances, providing
/// registration, lookup, and pin export/unexport operations.
pub struct GpioRegistry {
    /// Registered chip controllers.
    chips: [Option<GpioChip>; MAX_GPIO_CHIPS],
    /// Number of registered chips.
    count: usize,
}

impl Default for GpioRegistry {
    fn default() -> Self {
        const NONE: Option<GpioChip> = None;
        Self {
            chips: [NONE; MAX_GPIO_CHIPS],
            count: 0,
        }
    }
}

impl GpioRegistry {
    /// Registers a chip in the first available slot.
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full or
    /// [`Error::AlreadyExists`] when a chip with the same id is
    /// already registered.
    pub fn register(&mut self, chip: GpioChip) -> Result<()> {
        for c in self.chips.iter().flatten() {
            if c.id == chip.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.chips {
            if slot.is_none() {
                *slot = Some(chip);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns an immutable reference to the chip with `id`.
    pub fn get(&self, id: u8) -> Result<&GpioChip> {
        for c in self.chips.iter().flatten() {
            if c.id == id {
                return Ok(c);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to the chip with `id`.
    pub fn get_mut(&mut self, id: u8) -> Result<&mut GpioChip> {
        for c in self.chips.iter_mut().flatten() {
            if c.id == id {
                return Ok(c);
            }
        }
        Err(Error::NotFound)
    }

    /// Exports a GPIO pin on the specified chip, making it
    /// available for use.
    ///
    /// This requests the pin with a default label and direction
    /// (input). Returns [`Error::NotFound`] when the chip is not
    /// registered, and propagates errors from
    /// [`GpioChip::request`].
    pub fn export(&mut self, chip_id: u8, pin: u16) -> Result<()> {
        let chip = self.get_mut(chip_id)?;
        chip.request(pin, b"exported", GpioDirection::Input)
    }

    /// Unexports a GPIO pin on the specified chip, releasing it.
    ///
    /// Returns [`Error::NotFound`] when the chip is not registered,
    /// and propagates errors from [`GpioChip::free`].
    pub fn unexport(&mut self, chip_id: u8, pin: u16) -> Result<()> {
        let chip = self.get_mut(chip_id)?;
        chip.free(pin)
    }

    /// Returns the number of registered chips.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no chips are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
