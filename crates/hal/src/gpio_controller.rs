// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GPIO controller framework for the ONCRIX hardware abstraction layer.
//!
//! Provides a comprehensive GPIO subsystem with support for multiple
//! controller chips, pin direction control, value read/write, interrupt
//! edge/level triggering, debounce configuration, pull resistor settings,
//! pin ranges, and per-pin descriptors.
//!
//! # Architecture
//!
//! - **GpioDirection** — input or output pin direction
//! - **GpioValue** — logical low or high value
//! - **GpioEdge** — edge detection mode (none/rising/falling/both)
//! - **GpioLevel** — level-sensitive interrupt mode (low/high)
//! - **GpioPull** — internal pull resistor configuration
//! - **GpioDescriptor** — per-pin configuration and state descriptor
//! - **GpioRange** — contiguous range of GPIO pins with a base offset
//! - **GpioChip** — a GPIO controller managing a set of pins
//! - **GpioControllerRegistry** — manages up to [`MAX_CHIPS`] controllers
//!
//! Reference: Linux `drivers/gpio/`, `include/linux/gpio/driver.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of GPIO controller chips in the registry.
const MAX_CHIPS: usize = 8;

/// Maximum number of pins per GPIO chip.
const MAX_PINS: usize = 64;

/// Maximum number of pin ranges per chip.
const MAX_RANGES: usize = 4;

/// Maximum debounce period in microseconds.
const MAX_DEBOUNCE_US: u32 = 1_000_000;

/// Default debounce period in microseconds.
const DEFAULT_DEBOUNCE_US: u32 = 0;

// ---------------------------------------------------------------------------
// GpioDirection
// ---------------------------------------------------------------------------

/// GPIO pin direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioDirection {
    /// Pin configured as input.
    #[default]
    Input,
    /// Pin configured as output.
    Output,
}

// ---------------------------------------------------------------------------
// GpioValue
// ---------------------------------------------------------------------------

/// GPIO pin logical value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioValue {
    /// Logical low (0).
    #[default]
    Low,
    /// Logical high (1).
    High,
}

// ---------------------------------------------------------------------------
// GpioEdge
// ---------------------------------------------------------------------------

/// GPIO edge detection mode for interrupt generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioEdge {
    /// No edge detection.
    #[default]
    None,
    /// Trigger on rising edge (low-to-high transition).
    Rising,
    /// Trigger on falling edge (high-to-low transition).
    Falling,
    /// Trigger on both edges.
    Both,
}

// ---------------------------------------------------------------------------
// GpioLevel
// ---------------------------------------------------------------------------

/// GPIO level-sensitive interrupt mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioLevel {
    /// Not level-sensitive (edge-triggered or disabled).
    #[default]
    None,
    /// Trigger while pin is low.
    Low,
    /// Trigger while pin is high.
    High,
}

// ---------------------------------------------------------------------------
// GpioPull
// ---------------------------------------------------------------------------

/// Internal pull resistor configuration for a GPIO pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioPull {
    /// No pull resistor (floating).
    #[default]
    None,
    /// Pull-up resistor enabled.
    Up,
    /// Pull-down resistor enabled.
    Down,
}

// ---------------------------------------------------------------------------
// GpioDescriptor
// ---------------------------------------------------------------------------

/// Per-pin configuration and state descriptor.
///
/// Each pin in a [`GpioChip`] has an associated descriptor that tracks
/// its current direction, value, interrupt configuration, debounce
/// setting, and pull resistor state.
#[derive(Debug, Clone, Copy)]
pub struct GpioDescriptor {
    /// Pin offset within the chip (0-based).
    pub offset: u32,
    /// Current direction.
    pub direction: GpioDirection,
    /// Current logical value.
    pub value: GpioValue,
    /// Edge detection mode.
    pub edge: GpioEdge,
    /// Level-sensitive interrupt mode.
    pub level: GpioLevel,
    /// Pull resistor configuration.
    pub pull: GpioPull,
    /// Debounce period in microseconds (0 = disabled).
    pub debounce_us: u32,
    /// Whether the pin is currently requested (in use).
    pub requested: bool,
    /// Whether the pin is active-low (inverts logical value).
    pub active_low: bool,
    /// Human-readable label for the consumer (UTF-8).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
}

/// Constant empty descriptor for array initialisation.
const EMPTY_DESC: GpioDescriptor = GpioDescriptor {
    offset: 0,
    direction: GpioDirection::Input,
    value: GpioValue::Low,
    edge: GpioEdge::None,
    level: GpioLevel::None,
    pull: GpioPull::None,
    debounce_us: 0,
    requested: false,
    active_low: false,
    label: [0u8; 32],
    label_len: 0,
};

impl GpioDescriptor {
    /// Creates a new descriptor for the given pin offset.
    pub const fn new(offset: u32) -> Self {
        GpioDescriptor {
            offset,
            ..EMPTY_DESC
        }
    }

    /// Returns the effective value, accounting for active-low inversion.
    pub fn effective_value(&self) -> GpioValue {
        if self.active_low {
            match self.value {
                GpioValue::Low => GpioValue::High,
                GpioValue::High => GpioValue::Low,
            }
        } else {
            self.value
        }
    }
}

// ---------------------------------------------------------------------------
// GpioRange
// ---------------------------------------------------------------------------

/// A contiguous range of GPIO pins within a chip.
///
/// Ranges allow mapping a subset of chip pins to a pin controller
/// or other subsystem with a base offset translation.
#[derive(Debug, Clone, Copy)]
pub struct GpioRange {
    /// Name of the range (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// First GPIO pin offset in this range.
    pub base: u32,
    /// First pin controller pin number.
    pub pin_base: u32,
    /// Number of pins in the range.
    pub count: u32,
}

/// Constant empty range for array initialisation.
const EMPTY_RANGE: GpioRange = GpioRange {
    name: [0u8; 32],
    name_len: 0,
    base: 0,
    pin_base: 0,
    count: 0,
};

impl GpioRange {
    /// Creates a new GPIO range.
    pub fn new(name: &[u8], base: u32, pin_base: u32, count: u32) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            name: buf,
            name_len: copy_len,
            base,
            pin_base,
            count,
        }
    }

    /// Returns whether the given pin offset falls within this range.
    pub fn contains(&self, offset: u32) -> bool {
        offset >= self.base && offset < self.base.saturating_add(self.count)
    }

    /// Translates a GPIO offset to a pin controller pin number.
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is not in range.
    pub fn translate(&self, offset: u32) -> Result<u32> {
        if !self.contains(offset) {
            return Err(Error::InvalidArgument);
        }
        Ok(self.pin_base + (offset - self.base))
    }
}

// ---------------------------------------------------------------------------
// GpioChip
// ---------------------------------------------------------------------------

/// A GPIO controller managing a set of pins.
///
/// Each chip has a unique identifier, a base GPIO number for global
/// numbering, and a set of per-pin descriptors. The chip tracks pin
/// ranges for pin controller integration and provides methods for
/// requesting, configuring, and reading/writing pins.
pub struct GpioChip {
    /// Unique chip identifier.
    pub id: u32,
    /// Human-readable chip label (UTF-8).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Base GPIO number for global numbering.
    pub base: u32,
    /// Number of GPIO lines managed by this chip.
    pub ngpio: u32,
    /// Per-pin descriptors.
    pub descs: [GpioDescriptor; MAX_PINS],
    /// Pin ranges for pin controller mapping.
    pub ranges: [GpioRange; MAX_RANGES],
    /// Number of registered pin ranges.
    pub range_count: usize,
    /// Whether this chip is registered and active.
    pub active: bool,
    /// MMIO base address for the GPIO controller registers.
    pub mmio_base: usize,
}

impl GpioChip {
    /// Creates a new GPIO chip with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ngpio` exceeds [`MAX_PINS`].
    pub fn new(id: u32, label: &[u8], base: u32, ngpio: u32) -> Result<Self> {
        if ngpio as usize > MAX_PINS {
            return Err(Error::InvalidArgument);
        }
        let copy_len = label.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&label[..copy_len]);

        let mut descs = [EMPTY_DESC; MAX_PINS];
        let pin_count = ngpio as usize;
        for (i, desc) in descs.iter_mut().enumerate().take(pin_count) {
            desc.offset = i as u32;
        }

        Ok(Self {
            id,
            label: buf,
            label_len: copy_len,
            base,
            ngpio,
            descs,
            ranges: [EMPTY_RANGE; MAX_RANGES],
            range_count: 0,
            active: false,
            mmio_base: 0,
        })
    }

    /// Sets the MMIO base address for the controller registers.
    pub fn set_mmio_base(&mut self, base: usize) {
        self.mmio_base = base;
    }

    /// Requests a pin for use by a consumer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range,
    /// or [`Error::Busy`] if the pin is already requested.
    pub fn request_pin(&mut self, offset: u32, label: &[u8]) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        if self.descs[idx].requested {
            return Err(Error::Busy);
        }
        self.descs[idx].requested = true;
        let copy_len = label.len().min(32);
        self.descs[idx].label[..copy_len].copy_from_slice(&label[..copy_len]);
        self.descs[idx].label_len = copy_len;
        Ok(())
    }

    /// Releases a previously requested pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn free_pin(&mut self, offset: u32) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        self.descs[idx].requested = false;
        self.descs[idx].label = [0u8; 32];
        self.descs[idx].label_len = 0;
        self.descs[idx].edge = GpioEdge::None;
        self.descs[idx].level = GpioLevel::None;
        self.descs[idx].debounce_us = DEFAULT_DEBOUNCE_US;
        Ok(())
    }

    /// Sets the direction of a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range,
    /// or [`Error::Busy`] if the pin is not requested.
    pub fn set_direction(&mut self, offset: u32, dir: GpioDirection) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        if !self.descs[idx].requested {
            return Err(Error::Busy);
        }
        self.descs[idx].direction = dir;
        Ok(())
    }

    /// Gets the direction of a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn get_direction(&self, offset: u32) -> Result<GpioDirection> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(self.descs[idx].direction)
    }

    /// Sets the output value of a pin.
    ///
    /// The pin must be configured as output. The value is stored
    /// accounting for active-low inversion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range
    /// or the pin is not configured as output.
    pub fn set_value(&mut self, offset: u32, value: GpioValue) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        if self.descs[idx].direction != GpioDirection::Output {
            return Err(Error::InvalidArgument);
        }
        let stored = if self.descs[idx].active_low {
            match value {
                GpioValue::Low => GpioValue::High,
                GpioValue::High => GpioValue::Low,
            }
        } else {
            value
        };
        self.descs[idx].value = stored;
        Ok(())
    }

    /// Gets the current value of a pin.
    ///
    /// For input pins, returns the last sampled value. For output pins,
    /// returns the currently driven value. Active-low inversion is applied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn get_value(&self, offset: u32) -> Result<GpioValue> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(self.descs[idx].effective_value())
    }

    /// Configures edge detection for interrupt generation on a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn set_edge(&mut self, offset: u32, edge: GpioEdge) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        self.descs[idx].edge = edge;
        // Clear level when setting edge mode
        if edge != GpioEdge::None {
            self.descs[idx].level = GpioLevel::None;
        }
        Ok(())
    }

    /// Configures level-sensitive interrupt mode on a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn set_level(&mut self, offset: u32, level: GpioLevel) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        self.descs[idx].level = level;
        // Clear edge when setting level mode
        if level != GpioLevel::None {
            self.descs[idx].edge = GpioEdge::None;
        }
        Ok(())
    }

    /// Sets the debounce period for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range
    /// or the debounce period exceeds [`MAX_DEBOUNCE_US`].
    pub fn set_debounce(&mut self, offset: u32, debounce_us: u32) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        if debounce_us > MAX_DEBOUNCE_US {
            return Err(Error::InvalidArgument);
        }
        self.descs[idx].debounce_us = debounce_us;
        Ok(())
    }

    /// Sets the pull resistor configuration for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn set_pull(&mut self, offset: u32, pull: GpioPull) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        self.descs[idx].pull = pull;
        Ok(())
    }

    /// Sets the active-low flag for a pin.
    ///
    /// When active-low, the logical value is inverted relative to the
    /// physical pin state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn set_active_low(&mut self, offset: u32, active_low: bool) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        self.descs[idx].active_low = active_low;
        Ok(())
    }

    /// Adds a pin range to the chip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all [`MAX_RANGES`] slots are used.
    pub fn add_range(&mut self, range: GpioRange) -> Result<()> {
        if self.range_count >= MAX_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.range_count] = range;
        self.range_count += 1;
        Ok(())
    }

    /// Returns a reference to the descriptor for the given pin offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of range.
    pub fn get_descriptor(&self, offset: u32) -> Result<&GpioDescriptor> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.descs[idx])
    }

    /// Returns the number of requested (in-use) pins.
    pub fn requested_count(&self) -> usize {
        let n = self.ngpio as usize;
        self.descs[..n].iter().filter(|d| d.requested).count()
    }

    /// Returns the interrupt status for all pins as a bitmask.
    ///
    /// Bit N is set if pin N has an interrupt trigger configured
    /// (either edge or level) and the pin is requested.
    pub fn irq_pending_mask(&self) -> u64 {
        let mut mask: u64 = 0;
        let n = self.ngpio as usize;
        for (i, desc) in self.descs[..n].iter().enumerate() {
            if !desc.requested {
                continue;
            }
            let has_irq = desc.edge != GpioEdge::None || desc.level != GpioLevel::None;
            if has_irq {
                mask |= 1u64 << i;
            }
        }
        mask
    }
}

// ---------------------------------------------------------------------------
// GpioInterruptEvent
// ---------------------------------------------------------------------------

/// An interrupt event from a GPIO pin.
#[derive(Debug, Clone, Copy)]
pub struct GpioInterruptEvent {
    /// Chip identifier that generated the event.
    pub chip_id: u32,
    /// Pin offset within the chip.
    pub offset: u32,
    /// Edge that triggered the event.
    pub edge: GpioEdge,
    /// Timestamp in nanoseconds (from system timer).
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// GpioControllerRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CHIPS`] GPIO controller chips.
///
/// Provides chip registration, lookup by ID or global GPIO number,
/// and iteration over registered chips.
pub struct GpioControllerRegistry {
    /// Registered GPIO chips.
    chips: [Option<GpioChip>; MAX_CHIPS],
    /// Number of registered chips.
    count: usize,
}

impl GpioControllerRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            chips: [const { None }; MAX_CHIPS],
            count: 0,
        }
    }

    /// Registers a GPIO chip in the registry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a chip with the same ID is
    /// already registered.
    pub fn register(&mut self, mut chip: GpioChip) -> Result<()> {
        // Check for duplicate ID
        for slot in self.chips.iter().flatten() {
            if slot.id == chip.id {
                return Err(Error::AlreadyExists);
            }
        }
        // Find an empty slot
        for slot in self.chips.iter_mut() {
            if slot.is_none() {
                chip.active = true;
                *slot = Some(chip);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a GPIO chip by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no chip with the given ID exists.
    pub fn unregister(&mut self, chip_id: u32) -> Result<()> {
        for slot in self.chips.iter_mut() {
            let matches = slot.as_ref().is_some_and(|c| c.id == chip_id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a chip by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, chip_id: u32) -> Result<&GpioChip> {
        for slot in self.chips.iter().flatten() {
            if slot.id == chip_id && slot.active {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a chip by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, chip_id: u32) -> Result<&mut GpioChip> {
        for slot in self.chips.iter_mut() {
            if let Some(c) = slot {
                if c.id == chip_id && c.active {
                    return Ok(c);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Finds the chip and pin offset for a global GPIO number.
    ///
    /// The global number is translated to a chip-relative offset
    /// using the chip's base number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no chip covers the given number.
    pub fn find_by_global(&self, gpio_num: u32) -> Result<(&GpioChip, u32)> {
        for chip in self.chips.iter().flatten() {
            if !chip.active {
                continue;
            }
            if gpio_num >= chip.base && gpio_num < chip.base.saturating_add(chip.ngpio) {
                let offset = gpio_num - chip.base;
                return Ok((chip, offset));
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered chips.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no chips are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
