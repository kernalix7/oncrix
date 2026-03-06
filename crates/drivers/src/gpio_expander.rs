// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GPIO expander driver framework.
//!
//! Provides a generic abstraction for I2C/SPI GPIO expander chips such as
//! the NXP PCA9535, TI TCA9534, and Microchip MCP23017. These chips
//! extend the available GPIO lines via a serial bus interface.

use oncrix_lib::{Error, Result};

/// Maximum number of pins a single expander can provide.
pub const MAX_PINS: usize = 32;

/// GPIO pin direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinDirection {
    /// Pin is configured as an input.
    Input,
    /// Pin is configured as an output.
    Output,
}

/// GPIO pin state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinState {
    /// Logic low.
    Low,
    /// Logic high.
    High,
}

impl PinState {
    /// Convert a boolean (true = High).
    pub fn from_bool(v: bool) -> PinState {
        if v { PinState::High } else { PinState::Low }
    }

    /// Convert to a boolean.
    pub fn as_bool(self) -> bool {
        self == PinState::High
    }
}

/// Interrupt trigger mode for an input pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqTrigger {
    /// No interrupt.
    None,
    /// Rising edge.
    Rising,
    /// Falling edge.
    Falling,
    /// Both edges.
    BothEdges,
    /// Level high.
    LevelHigh,
    /// Level low.
    LevelLow,
}

/// Per-pin configuration.
#[derive(Clone, Copy, Debug)]
pub struct PinConfig {
    /// Pin direction.
    pub direction: PinDirection,
    /// Pull-up enabled.
    pub pull_up: bool,
    /// Pull-down enabled.
    pub pull_down: bool,
    /// Interrupt trigger mode.
    pub irq_trigger: IrqTrigger,
}

impl Default for PinConfig {
    fn default() -> Self {
        Self {
            direction: PinDirection::Input,
            pull_up: false,
            pull_down: false,
            irq_trigger: IrqTrigger::None,
        }
    }
}

/// Generic GPIO expander trait.
///
/// Hardware-specific drivers implement this trait and register with the
/// gpio_expander framework for unified pin access.
pub trait GpioExpander {
    /// Return the number of GPIO pins this expander provides.
    fn num_pins(&self) -> usize;

    /// Configure a single pin.
    fn configure_pin(&mut self, pin: usize, config: PinConfig) -> Result<()>;

    /// Read the state of a single input pin.
    fn get_pin(&self, pin: usize) -> Result<PinState>;

    /// Set the state of a single output pin.
    fn set_pin(&mut self, pin: usize, state: PinState) -> Result<()>;

    /// Read all pins as a bitmask (bit 0 = pin 0).
    fn get_all(&self) -> Result<u32>;

    /// Write all output pins from a bitmask.
    fn set_all(&mut self, mask: u32) -> Result<()>;

    /// Handle an interrupt from the expander (read + clear interrupt flags).
    ///
    /// Returns a bitmask of pins that triggered an interrupt.
    fn handle_interrupt(&mut self) -> Result<u32>;
}

/// Software-emulated GPIO expander backed by in-memory state.
/// Useful for simulation and testing without real hardware.
pub struct SoftGpioExpander {
    /// Number of emulated pins.
    num_pins: usize,
    /// Per-pin configuration.
    config: [PinConfig; MAX_PINS],
    /// Pin output values (for output-configured pins).
    output: u32,
    /// Pin input values (for input-configured pins, set by test harness).
    input: u32,
    /// Pending interrupt flags.
    irq_pending: u32,
}

impl SoftGpioExpander {
    /// Create a software expander with `n` pins (max `MAX_PINS`).
    pub fn new(n: usize) -> Self {
        let num_pins = n.min(MAX_PINS);
        Self {
            num_pins,
            config: [const {
                PinConfig {
                    direction: PinDirection::Input,
                    pull_up: false,
                    pull_down: false,
                    irq_trigger: IrqTrigger::None,
                }
            }; MAX_PINS],
            output: 0,
            input: 0,
            irq_pending: 0,
        }
    }

    /// Simulate an external input change (for testing).
    pub fn set_input_pin(&mut self, pin: usize, state: PinState) {
        if pin >= self.num_pins {
            return;
        }
        let prev = (self.input >> pin) & 1;
        let new = if state == PinState::High { 1u32 } else { 0u32 };
        if prev != new {
            self.input = (self.input & !(1 << pin)) | (new << pin);
            // Check interrupt trigger.
            let trigger = self.config[pin].irq_trigger;
            let fire = match trigger {
                IrqTrigger::Rising => new == 1,
                IrqTrigger::Falling => new == 0,
                IrqTrigger::BothEdges => true,
                IrqTrigger::LevelHigh => new == 1,
                IrqTrigger::LevelLow => new == 0,
                IrqTrigger::None => false,
            };
            if fire {
                self.irq_pending |= 1 << pin;
            }
        }
    }
}

impl GpioExpander for SoftGpioExpander {
    fn num_pins(&self) -> usize {
        self.num_pins
    }

    fn configure_pin(&mut self, pin: usize, config: PinConfig) -> Result<()> {
        if pin >= self.num_pins {
            return Err(Error::InvalidArgument);
        }
        self.config[pin] = config;
        Ok(())
    }

    fn get_pin(&self, pin: usize) -> Result<PinState> {
        if pin >= self.num_pins {
            return Err(Error::InvalidArgument);
        }
        if self.config[pin].direction == PinDirection::Input {
            Ok(PinState::from_bool((self.input >> pin) & 1 != 0))
        } else {
            Ok(PinState::from_bool((self.output >> pin) & 1 != 0))
        }
    }

    fn set_pin(&mut self, pin: usize, state: PinState) -> Result<()> {
        if pin >= self.num_pins {
            return Err(Error::InvalidArgument);
        }
        if self.config[pin].direction != PinDirection::Output {
            return Err(Error::InvalidArgument);
        }
        if state == PinState::High {
            self.output |= 1 << pin;
        } else {
            self.output &= !(1 << pin);
        }
        Ok(())
    }

    fn get_all(&self) -> Result<u32> {
        let output_mask: u32 = (0..self.num_pins)
            .filter(|&p| self.config[p].direction == PinDirection::Output)
            .fold(0u32, |acc, p| acc | (1 << p));
        Ok((self.input & !output_mask) | (self.output & output_mask))
    }

    fn set_all(&mut self, mask: u32) -> Result<()> {
        for pin in 0..self.num_pins {
            if self.config[pin].direction == PinDirection::Output {
                if (mask >> pin) & 1 != 0 {
                    self.output |= 1 << pin;
                } else {
                    self.output &= !(1 << pin);
                }
            }
        }
        Ok(())
    }

    fn handle_interrupt(&mut self) -> Result<u32> {
        let pending = self.irq_pending;
        self.irq_pending = 0;
        Ok(pending)
    }
}

/// Registry entry for a GPIO expander.
pub struct GpioExpanderEntry {
    /// Base pin number in the global GPIO numbering space.
    pub base: usize,
    /// Number of pins.
    pub count: usize,
    /// Driver name.
    pub name: &'static str,
}

/// Fixed-size registry of registered GPIO expanders.
const MAX_EXPANDERS: usize = 8;

/// Global GPIO expander registry.
pub struct GpioExpanderRegistry {
    entries: [Option<GpioExpanderEntry>; MAX_EXPANDERS],
    count: usize,
}

impl GpioExpanderRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
            ],
            count: 0,
        }
    }

    /// Register a new expander. Returns the assigned base GPIO number.
    pub fn register(&mut self, count: usize, name: &'static str) -> Result<usize> {
        if self.count >= MAX_EXPANDERS {
            return Err(Error::OutOfMemory);
        }
        let base = self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref().map(|x| x.base + x.count))
            .max()
            .unwrap_or(0);
        self.entries[self.count] = Some(GpioExpanderEntry { base, count, name });
        self.count += 1;
        Ok(base)
    }

    /// Return the number of registered expanders.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no expanders are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for GpioExpanderRegistry {
    fn default() -> Self {
        Self::new()
    }
}
