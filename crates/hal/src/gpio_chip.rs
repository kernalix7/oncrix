// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GPIO chip controller abstraction.
//!
//! Provides a GPIO controller model for pin multiplexing, direction
//! configuration, value read/write, interrupt generation (edge/level),
//! debounce, and pull resistor control. Multiple chips can coexist
//! and are tracked by a [`GpioChipRegistry`].
//!
//! # Architecture
//!
//! - [`PinDirection`] -- input or output configuration.
//! - [`PinValue`] -- logical low or high.
//! - [`GpioIrqMode`] -- interrupt trigger mode (edge/level).
//! - [`GpioIrq`] -- an interrupt event from a GPIO pin.
//! - [`GpioPin`] -- per-pin configuration and state.
//! - [`GpioChip`] -- a GPIO controller managing a set of pins.
//! - [`GpioChipRegistry`] -- manages up to [`MAX_CHIPS`] controllers.
//!
//! This module provides a second-generation GPIO API that improves
//! upon [`crate::gpio_controller`] with explicit IRQ event types and
//! a mux-function selector per pin.
//!
//! Reference: Linux `drivers/gpio/gpiolib.c`,
//!            `include/linux/gpio/driver.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of GPIO chips in the registry.
const MAX_CHIPS: usize = 8;

/// Maximum number of pins per chip.
const MAX_PINS: usize = 64;

/// Maximum debounce period in microseconds.
const MAX_DEBOUNCE_US: u32 = 1_000_000;

/// Maximum number of mux functions per pin.
const MAX_MUX_FUNCS: usize = 8;

/// Maximum length of a chip or pin label.
const MAX_LABEL_LEN: usize = 32;

/// Maximum pending IRQ events in the event queue.
const MAX_IRQ_EVENTS: usize = 32;

// ---------------------------------------------------------------------------
// PinDirection
// ---------------------------------------------------------------------------

/// GPIO pin direction configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinDirection {
    /// Pin configured as input.
    #[default]
    Input,
    /// Pin configured as output.
    Output,
    /// Pin configured for an alternate/mux function.
    AltFunc,
}

// ---------------------------------------------------------------------------
// PinValue
// ---------------------------------------------------------------------------

/// GPIO pin logical value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinValue {
    /// Logical low (0).
    #[default]
    Low,
    /// Logical high (1).
    High,
}

// ---------------------------------------------------------------------------
// PinPull
// ---------------------------------------------------------------------------

/// Internal pull resistor configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinPull {
    /// No pull resistor (floating).
    #[default]
    None,
    /// Pull-up resistor enabled.
    Up,
    /// Pull-down resistor enabled.
    Down,
    /// Bus-hold (keeper) mode.
    BusHold,
}

// ---------------------------------------------------------------------------
// GpioIrqMode
// ---------------------------------------------------------------------------

/// Interrupt trigger mode for a GPIO pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpioIrqMode {
    /// Interrupts disabled for this pin.
    #[default]
    Disabled,
    /// Trigger on rising edge.
    RisingEdge,
    /// Trigger on falling edge.
    FallingEdge,
    /// Trigger on both edges.
    BothEdges,
    /// Trigger while level is low.
    LevelLow,
    /// Trigger while level is high.
    LevelHigh,
}

// ---------------------------------------------------------------------------
// GpioIrq
// ---------------------------------------------------------------------------

/// An interrupt event from a GPIO pin.
#[derive(Debug, Clone, Copy, Default)]
pub struct GpioIrq {
    /// Chip identifier that generated the event.
    pub chip_id: u32,
    /// Pin offset within the chip.
    pub pin_offset: u32,
    /// Trigger mode that fired this event.
    pub mode: GpioIrqMode,
    /// Timestamp in nanoseconds (from system timer).
    pub timestamp_ns: u64,
    /// Sequence number (monotonically increasing per chip).
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// GpioPin
// ---------------------------------------------------------------------------

/// Per-pin configuration and state within a [`GpioChip`].
#[derive(Debug, Clone, Copy)]
pub struct GpioPin {
    /// Pin offset within the chip (0-based).
    pub offset: u32,
    /// Current direction.
    pub direction: PinDirection,
    /// Current logical value.
    pub value: PinValue,
    /// Interrupt trigger mode.
    pub irq_mode: GpioIrqMode,
    /// Pull resistor configuration.
    pub pull: PinPull,
    /// Debounce period in microseconds (0 = disabled).
    pub debounce_us: u32,
    /// Whether the pin is requested (in use by a consumer).
    pub requested: bool,
    /// Whether the pin is active-low (inverts logical value).
    pub active_low: bool,
    /// Current mux function index (0 = default GPIO).
    pub mux_func: u8,
    /// Consumer label.
    pub label: [u8; MAX_LABEL_LEN],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
}

/// Constant empty pin for array initialisation.
const EMPTY_PIN: GpioPin = GpioPin {
    offset: 0,
    direction: PinDirection::Input,
    value: PinValue::Low,
    irq_mode: GpioIrqMode::Disabled,
    pull: PinPull::None,
    debounce_us: 0,
    requested: false,
    active_low: false,
    mux_func: 0,
    label: [0u8; MAX_LABEL_LEN],
    label_len: 0,
};

impl GpioPin {
    /// Creates a new pin descriptor for the given offset.
    pub const fn new(offset: u32) -> Self {
        GpioPin {
            offset,
            ..EMPTY_PIN
        }
    }

    /// Returns the effective value accounting for active-low inversion.
    pub fn effective_value(&self) -> PinValue {
        if self.active_low {
            match self.value {
                PinValue::Low => PinValue::High,
                PinValue::High => PinValue::Low,
            }
        } else {
            self.value
        }
    }

    /// Returns `true` if this pin has an interrupt mode configured.
    pub fn has_irq(&self) -> bool {
        self.irq_mode != GpioIrqMode::Disabled
    }
}

// ---------------------------------------------------------------------------
// MuxFunction
// ---------------------------------------------------------------------------

/// A pin multiplexing function descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MuxFunction {
    /// Function index (0 = default GPIO).
    pub index: u8,
    /// Human-readable function name.
    pub name: [u8; MAX_LABEL_LEN],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
}

/// Constant empty mux function for array initialisation.
const EMPTY_MUX: MuxFunction = MuxFunction {
    index: 0,
    name: [0u8; MAX_LABEL_LEN],
    name_len: 0,
};

impl MuxFunction {
    /// Creates a new mux function descriptor.
    pub fn new(index: u8, name: &[u8]) -> Self {
        let copy_len = name.len().min(MAX_LABEL_LEN);
        let mut buf = [0u8; MAX_LABEL_LEN];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            index,
            name: buf,
            name_len: copy_len,
        }
    }
}

// ---------------------------------------------------------------------------
// GpioChip
// ---------------------------------------------------------------------------

/// A GPIO controller managing a set of pins.
///
/// Each chip has a unique identifier, a base GPIO number for global
/// numbering, per-pin descriptors, mux function definitions, and an
/// IRQ event queue.
pub struct GpioChip {
    /// Unique chip identifier.
    pub id: u32,
    /// Human-readable chip label.
    pub label: [u8; MAX_LABEL_LEN],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Base GPIO number for global numbering.
    pub base: u32,
    /// Number of GPIO lines managed by this chip.
    pub ngpio: u32,
    /// Per-pin descriptors.
    pins: [GpioPin; MAX_PINS],
    /// Mux function definitions.
    mux_funcs: [MuxFunction; MAX_MUX_FUNCS],
    /// Number of registered mux functions.
    mux_func_count: usize,
    /// IRQ event queue (ring buffer).
    irq_events: [GpioIrq; MAX_IRQ_EVENTS],
    /// Write index into the IRQ event queue.
    irq_head: usize,
    /// Read index into the IRQ event queue.
    irq_tail: usize,
    /// Monotonic IRQ sequence counter.
    irq_seq: u64,
    /// MMIO base address for the GPIO controller registers.
    pub mmio_base: usize,
    /// Whether this chip is registered and active.
    pub active: bool,
}

impl GpioChip {
    /// Creates a new GPIO chip with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ngpio` exceeds
    /// [`MAX_PINS`] or the label is empty.
    pub fn new(id: u32, label: &[u8], base: u32, ngpio: u32) -> Result<Self> {
        if ngpio as usize > MAX_PINS || ngpio == 0 {
            return Err(Error::InvalidArgument);
        }
        if label.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let copy_len = label.len().min(MAX_LABEL_LEN);
        let mut label_buf = [0u8; MAX_LABEL_LEN];
        label_buf[..copy_len].copy_from_slice(&label[..copy_len]);

        let mut pins = [EMPTY_PIN; MAX_PINS];
        let pin_count = ngpio as usize;
        for (i, pin) in pins.iter_mut().enumerate().take(pin_count) {
            pin.offset = i as u32;
        }

        Ok(Self {
            id,
            label: label_buf,
            label_len: copy_len,
            base,
            ngpio,
            pins,
            mux_funcs: [EMPTY_MUX; MAX_MUX_FUNCS],
            mux_func_count: 0,
            irq_events: [GpioIrq::default(); MAX_IRQ_EVENTS],
            irq_head: 0,
            irq_tail: 0,
            irq_seq: 0,
            mmio_base: 0,
            active: false,
        })
    }

    /// Sets the MMIO base address.
    pub fn set_mmio_base(&mut self, base: usize) {
        self.mmio_base = base;
    }

    /// Registers a mux function for this chip's pins.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the mux function table is full.
    pub fn add_mux_function(&mut self, func: MuxFunction) -> Result<()> {
        if self.mux_func_count >= MAX_MUX_FUNCS {
            return Err(Error::OutOfMemory);
        }
        self.mux_funcs[self.mux_func_count] = func;
        self.mux_func_count += 1;
        Ok(())
    }

    /// Requests a pin for use by a consumer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range,
    /// or [`Error::Busy`] if the pin is already requested.
    pub fn request_pin(&mut self, offset: u32, label: &[u8]) -> Result<()> {
        let idx = self.pin_index(offset)?;
        if self.pins[idx].requested {
            return Err(Error::Busy);
        }
        self.pins[idx].requested = true;
        let copy_len = label.len().min(MAX_LABEL_LEN);
        self.pins[idx].label[..copy_len].copy_from_slice(&label[..copy_len]);
        self.pins[idx].label_len = copy_len;
        Ok(())
    }

    /// Releases a previously requested pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn free_pin(&mut self, offset: u32) -> Result<()> {
        let idx = self.pin_index(offset)?;
        self.pins[idx].requested = false;
        self.pins[idx].label = [0u8; MAX_LABEL_LEN];
        self.pins[idx].label_len = 0;
        self.pins[idx].irq_mode = GpioIrqMode::Disabled;
        self.pins[idx].debounce_us = 0;
        self.pins[idx].mux_func = 0;
        Ok(())
    }

    /// Sets the direction of a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range,
    /// or [`Error::Busy`] if the pin is not requested.
    pub fn set_direction(&mut self, offset: u32, dir: PinDirection) -> Result<()> {
        let idx = self.pin_index(offset)?;
        if !self.pins[idx].requested {
            return Err(Error::Busy);
        }
        self.pins[idx].direction = dir;
        Ok(())
    }

    /// Gets the direction of a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn get_direction(&self, offset: u32) -> Result<PinDirection> {
        let idx = self.pin_index(offset)?;
        Ok(self.pins[idx].direction)
    }

    /// Sets the output value of a pin.
    ///
    /// The pin must be configured as output. Active-low inversion is
    /// applied before storing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range
    /// or the pin is not configured as output.
    pub fn set_value(&mut self, offset: u32, value: PinValue) -> Result<()> {
        let idx = self.pin_index(offset)?;
        if self.pins[idx].direction != PinDirection::Output {
            return Err(Error::InvalidArgument);
        }
        let stored = if self.pins[idx].active_low {
            match value {
                PinValue::Low => PinValue::High,
                PinValue::High => PinValue::Low,
            }
        } else {
            value
        };
        self.pins[idx].value = stored;
        Ok(())
    }

    /// Gets the current value of a pin (with active-low inversion).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn get_value(&self, offset: u32) -> Result<PinValue> {
        let idx = self.pin_index(offset)?;
        Ok(self.pins[idx].effective_value())
    }

    /// Configures the interrupt mode for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn set_irq_mode(&mut self, offset: u32, mode: GpioIrqMode) -> Result<()> {
        let idx = self.pin_index(offset)?;
        self.pins[idx].irq_mode = mode;
        Ok(())
    }

    /// Sets the debounce period for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range
    /// or `debounce_us` exceeds [`MAX_DEBOUNCE_US`].
    pub fn set_debounce(&mut self, offset: u32, debounce_us: u32) -> Result<()> {
        let idx = self.pin_index(offset)?;
        if debounce_us > MAX_DEBOUNCE_US {
            return Err(Error::InvalidArgument);
        }
        self.pins[idx].debounce_us = debounce_us;
        Ok(())
    }

    /// Sets the pull resistor configuration for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn set_pull(&mut self, offset: u32, pull: PinPull) -> Result<()> {
        let idx = self.pin_index(offset)?;
        self.pins[idx].pull = pull;
        Ok(())
    }

    /// Sets the active-low flag for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn set_active_low(&mut self, offset: u32, active_low: bool) -> Result<()> {
        let idx = self.pin_index(offset)?;
        self.pins[idx].active_low = active_low;
        Ok(())
    }

    /// Sets the mux function for a pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range
    /// or `func_index` is not a registered mux function.
    pub fn set_mux_function(&mut self, offset: u32, func_index: u8) -> Result<()> {
        let idx = self.pin_index(offset)?;
        // Validate that the function index is registered (or 0 = GPIO).
        if func_index != 0 {
            let found = self.mux_funcs[..self.mux_func_count]
                .iter()
                .any(|f| f.index == func_index);
            if !found {
                return Err(Error::InvalidArgument);
            }
        }
        self.pins[idx].mux_func = func_index;
        if func_index != 0 {
            self.pins[idx].direction = PinDirection::AltFunc;
        }
        Ok(())
    }

    /// Pushes an IRQ event into the event queue.
    ///
    /// If the queue is full, the oldest event is overwritten.
    pub fn push_irq_event(&mut self, pin_offset: u32, mode: GpioIrqMode, timestamp_ns: u64) {
        self.irq_seq += 1;
        let event = GpioIrq {
            chip_id: self.id,
            pin_offset,
            mode,
            timestamp_ns,
            sequence: self.irq_seq,
        };
        self.irq_events[self.irq_head] = event;
        self.irq_head = (self.irq_head + 1) % MAX_IRQ_EVENTS;
        if self.irq_head == self.irq_tail {
            // Queue full: advance tail (drop oldest).
            self.irq_tail = (self.irq_tail + 1) % MAX_IRQ_EVENTS;
        }
    }

    /// Pops the oldest IRQ event from the queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop_irq_event(&mut self) -> Option<GpioIrq> {
        if self.irq_head == self.irq_tail {
            return None;
        }
        let event = self.irq_events[self.irq_tail];
        self.irq_tail = (self.irq_tail + 1) % MAX_IRQ_EVENTS;
        Some(event)
    }

    /// Returns the number of pending IRQ events.
    pub fn irq_event_count(&self) -> usize {
        if self.irq_head >= self.irq_tail {
            self.irq_head - self.irq_tail
        } else {
            MAX_IRQ_EVENTS - self.irq_tail + self.irq_head
        }
    }

    /// Returns a reference to a pin descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset` is out of range.
    pub fn get_pin(&self, offset: u32) -> Result<&GpioPin> {
        let idx = self.pin_index(offset)?;
        Ok(&self.pins[idx])
    }

    /// Returns the number of requested (in-use) pins.
    pub fn requested_count(&self) -> usize {
        let n = self.ngpio as usize;
        self.pins[..n].iter().filter(|p| p.requested).count()
    }

    /// Returns the IRQ-pending bitmask for all pins.
    ///
    /// Bit N is set if pin N has an interrupt mode enabled and is
    /// requested.
    pub fn irq_pending_mask(&self) -> u64 {
        let mut mask: u64 = 0;
        let n = self.ngpio as usize;
        for (i, pin) in self.pins[..n].iter().enumerate() {
            if pin.requested && pin.has_irq() {
                mask |= 1u64 << i;
            }
        }
        mask
    }

    // -- internal ---------------------------------------------------------

    fn pin_index(&self, offset: u32) -> Result<usize> {
        let idx = offset as usize;
        if idx >= self.ngpio as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(idx)
    }
}

// ---------------------------------------------------------------------------
// GpioChipRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CHIPS`] GPIO chip controllers.
pub struct GpioChipRegistry {
    /// Registered chips (stored as Option for sparse removal).
    chips: [Option<GpioChip>; MAX_CHIPS],
    /// Number of registered chips.
    count: usize,
}

impl GpioChipRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            chips: [const { None }; MAX_CHIPS],
            count: 0,
        }
    }

    /// Registers a GPIO chip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a chip with the same ID exists.
    pub fn register(&mut self, mut chip: GpioChip) -> Result<()> {
        for slot in self.chips.iter().flatten() {
            if slot.id == chip.id {
                return Err(Error::AlreadyExists);
            }
        }
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

    /// Returns a reference to a chip by ID.
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

    /// Returns a mutable reference to a chip by ID.
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

impl Default for GpioChipRegistry {
    fn default() -> Self {
        Self::new()
    }
}
