// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI GPIO controller abstraction.
//!
//! Parses and manages GPIO resources described in ACPI tables (GpioIo,
//! GpioInt resource descriptors from _CRS method). Provides mapping between
//! ACPI GPIO pin numbers and the HAL GPIO chip abstraction.
//!
//! # ACPI GPIO Resources
//!
//! ACPI 5.0 introduced GPIO resource descriptors that allow ACPI methods to
//! control GPIO pins without platform-specific drivers. The kernel GPIO subsystem
//! maps ACPI GPIO references to HAL GPIO chips.
//!
//! # References
//!
//! - ACPI Specification 6.5, Section 6.4.3.8 (GPIO Connection Descriptor)

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// ACPI GPIO pin connection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiGpioType {
    /// GPIO used as interrupt source.
    Interrupt,
    /// GPIO used for I/O (input or output).
    Io,
}

/// ACPI GPIO interrupt polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiGpioPolarity {
    /// Active high.
    ActiveHigh,
    /// Active low.
    ActiveLow,
    /// Active on both edges.
    BothEdges,
}

/// ACPI GPIO trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiGpioTrigger {
    /// Edge-triggered.
    Edge,
    /// Level-triggered.
    Level,
}

/// Pull configuration for an ACPI GPIO pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiGpioPull {
    /// Default (platform-defined pull).
    Default,
    /// No pull resistor.
    None,
    /// Pull-up resistor.
    Up,
    /// Pull-down resistor.
    Down,
}

/// ACPI GPIO resource descriptor (parsed from _CRS GpioIo/GpioInt).
#[derive(Debug, Clone, Copy)]
pub struct AcpiGpioResource {
    /// Resource type.
    pub gpio_type: AcpiGpioType,
    /// GPIO controller path hash (simplified; normally a full ACPI path).
    pub controller_id: u32,
    /// Pin number within the GPIO controller.
    pub pin: u16,
    /// For interrupt GPIOs: polarity.
    pub polarity: AcpiGpioPolarity,
    /// For interrupt GPIOs: trigger mode.
    pub trigger: AcpiGpioTrigger,
    /// Pull configuration.
    pub pull: AcpiGpioPull,
    /// Initial drive value (for I/O GPIOs configured as output).
    pub drive_strength_ua: u32,
    /// Shared vs. exclusive resource.
    pub shared: bool,
}

impl AcpiGpioResource {
    /// Creates a basic ACPI interrupt GPIO resource.
    pub const fn interrupt(
        controller_id: u32,
        pin: u16,
        polarity: AcpiGpioPolarity,
        trigger: AcpiGpioTrigger,
    ) -> Self {
        Self {
            gpio_type: AcpiGpioType::Interrupt,
            controller_id,
            pin,
            polarity,
            trigger,
            pull: AcpiGpioPull::Default,
            drive_strength_ua: 0,
            shared: false,
        }
    }

    /// Creates a basic ACPI I/O GPIO resource.
    pub const fn io(controller_id: u32, pin: u16) -> Self {
        Self {
            gpio_type: AcpiGpioType::Io,
            controller_id,
            pin,
            polarity: AcpiGpioPolarity::ActiveHigh,
            trigger: AcpiGpioTrigger::Edge,
            pull: AcpiGpioPull::Default,
            drive_strength_ua: 0,
            shared: false,
        }
    }
}

/// Maximum ACPI GPIO resources tracked per device.
pub const ACPI_GPIO_MAX_RESOURCES: usize = 32;

/// ACPI GPIO resource table for a single ACPI device node.
pub struct AcpiGpioTable {
    resources: [Option<AcpiGpioResource>; ACPI_GPIO_MAX_RESOURCES],
    count: usize,
}

impl AcpiGpioTable {
    /// Creates an empty ACPI GPIO table.
    pub const fn new() -> Self {
        const NONE: Option<AcpiGpioResource> = None;
        Self {
            resources: [NONE; ACPI_GPIO_MAX_RESOURCES],
            count: 0,
        }
    }

    /// Adds a GPIO resource to the table.
    pub fn add(&mut self, resource: AcpiGpioResource) -> Result<usize> {
        if self.count >= ACPI_GPIO_MAX_RESOURCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.resources[idx] = Some(resource);
        self.count += 1;
        Ok(idx)
    }

    /// Returns the resource at the given index.
    pub fn get(&self, index: usize) -> Option<&AcpiGpioResource> {
        self.resources.get(index)?.as_ref()
    }

    /// Finds an interrupt GPIO by pin number.
    pub fn find_interrupt(&self, pin: u16) -> Option<&AcpiGpioResource> {
        self.resources[..self.count].iter().find_map(|r| {
            r.as_ref()
                .filter(|res| res.gpio_type == AcpiGpioType::Interrupt && res.pin == pin)
        })
    }

    /// Finds an I/O GPIO by pin number.
    pub fn find_io(&self, pin: u16) -> Option<&AcpiGpioResource> {
        self.resources[..self.count].iter().find_map(|r| {
            r.as_ref()
                .filter(|res| res.gpio_type == AcpiGpioType::Io && res.pin == pin)
        })
    }

    /// Returns the number of resources.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over all GPIO resources.
    pub fn iter(&self) -> impl Iterator<Item = &AcpiGpioResource> {
        self.resources[..self.count]
            .iter()
            .filter_map(|r| r.as_ref())
    }
}

impl Default for AcpiGpioTable {
    fn default() -> Self {
        Self::new()
    }
}

/// ACPI GPIO lookup key used by drivers to request a named GPIO.
#[derive(Debug, Clone, Copy)]
pub struct AcpiGpioLookup {
    /// ACPI device path identifier hash.
    pub device_id: u32,
    /// Connection index (nth GPIO connection in _CRS).
    pub index: u8,
}

impl AcpiGpioLookup {
    /// Creates a GPIO lookup key.
    pub const fn new(device_id: u32, index: u8) -> Self {
        Self { device_id, index }
    }
}
