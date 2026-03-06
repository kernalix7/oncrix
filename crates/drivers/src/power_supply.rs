// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power supply class driver.
//!
//! Provides a Linux-style power_supply framework adapted for a no_std microkernel.
//! Power supplies include batteries, AC mains adapters, USB chargers, and UPS units.
//!
//! # Architecture
//!
//! - [`PowerSupplyType`] — classification of the supply (battery, mains, USB, UPS).
//! - [`PowerSupplyStatus`] — charging/discharging/full/unknown status.
//! - [`PowerSupplyHealth`] — health assessment of a battery.
//! - [`PowerSupplyProperty`] — enumeration of 30+ measurable/configurable properties.
//! - [`PropertyValue`] — typed value returned when reading a property.
//! - [`PowerSupplyDesc`] — static descriptor for a supply (name, type, supported props).
//! - [`PowerSupplyDevice`] — runtime state with current property values.
//! - [`PowerSupplyRegistry`] — manages up to [`MAX_SUPPLIES`] power supply devices.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of power supply devices in the registry.
const MAX_SUPPLIES: usize = 8;

/// Maximum number of properties that can be reported per device.
const MAX_PROPERTIES: usize = 40;

// -------------------------------------------------------------------
// PowerSupplyType
// -------------------------------------------------------------------

/// Classification of a power supply device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerSupplyType {
    /// Rechargeable battery (primary power source).
    #[default]
    Battery,
    /// Uninterruptible power supply.
    Ups,
    /// AC mains power adapter.
    Mains,
    /// USB bus power (5 V / USB-PD).
    Usb,
    /// USB dual-role device (can source or sink power).
    UsbDrd,
    /// Wireless charging pad.
    WirelessCharger,
}

// -------------------------------------------------------------------
// PowerSupplyStatus
// -------------------------------------------------------------------

/// Charging/discharging status of a power supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerSupplyStatus {
    /// Status cannot be determined.
    #[default]
    Unknown,
    /// Supply is currently charging.
    Charging,
    /// Supply is currently discharging.
    Discharging,
    /// Supply is not charging (external power connected, charge full or paused).
    NotCharging,
    /// Battery is fully charged.
    Full,
}

// -------------------------------------------------------------------
// PowerSupplyHealth
// -------------------------------------------------------------------

/// Health assessment of a battery or power supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerSupplyHealth {
    /// Health cannot be determined.
    #[default]
    Unknown,
    /// Supply is in good condition.
    Good,
    /// Battery is overheated.
    Overheat,
    /// Battery is dead (not functional).
    Dead,
    /// Voltage is outside acceptable range.
    OverVoltage,
    /// Unspecified failure.
    UnspecFailure,
    /// Battery temperature is too cold for charging.
    Cold,
    /// Watchdog timer expired.
    WatchdogTimerExpire,
    /// Safety timer expired during charging.
    SafetyTimerExpire,
    /// Battery is calibrating.
    Calibration,
}

// -------------------------------------------------------------------
// PowerSupplyCapacityLevel
// -------------------------------------------------------------------

/// Coarse capacity level descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapacityLevel {
    /// Level is unknown.
    #[default]
    Unknown,
    /// Battery is critically low.
    Critical,
    /// Battery level is low.
    Low,
    /// Battery is at normal operating level.
    Normal,
    /// Battery level is high.
    High,
    /// Battery is completely full.
    Full,
}

// -------------------------------------------------------------------
// PowerSupplyProperty
// -------------------------------------------------------------------

/// Enumeration of measurable and configurable power supply properties.
///
/// Mirrors the Linux `POWER_SUPPLY_PROP_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSupplyProperty {
    /// Charging/discharging status.
    Status,
    /// Charge type (trickle, fast, etc.) — stored as u32 code.
    ChargeType,
    /// Health assessment.
    Health,
    /// Whether a battery is physically present.
    Present,
    /// Whether the supply is online (connected to external power).
    Online,
    /// Whether the supply is enabled.
    Authentic,
    /// Technology type (Li-ion, NiMH, etc.) — stored as u32 code.
    Technology,
    /// Battery cycle count (charge/discharge cycles).
    CycleCount,
    /// Voltage maximum design value in microvolts.
    VoltageMaxDesign,
    /// Voltage minimum design value in microvolts.
    VoltageMinDesign,
    /// Voltage at full charge in microvolts.
    VoltageFull,
    /// Open-circuit voltage in microvolts.
    VoltageNow,
    /// Average voltage (filtered) in microvolts.
    VoltageAvg,
    /// Ocv (open circuit voltage) in microvolts.
    VoltageOcv,
    /// Current (positive = charging) in microamperes.
    CurrentNow,
    /// Average current in microamperes.
    CurrentAvg,
    /// Peak current limit in microamperes.
    CurrentMax,
    /// Current through the supply from the power source in microamperes.
    CurrentBoot,
    /// Power draw in microwatts.
    PowerNow,
    /// Average power in microwatts.
    PowerAvg,
    /// Charge design capacity in microampere-hours.
    ChargeFullDesign,
    /// Charge empty design capacity in microampere-hours.
    ChargeEmptyDesign,
    /// Current full-charge capacity in microampere-hours.
    ChargeFull,
    /// Current empty capacity in microampere-hours.
    ChargeEmpty,
    /// Current charge level in microampere-hours.
    ChargeNow,
    /// Average charge rate in microamperes.
    ChargeAvg,
    /// Counter of charge since reset in microampere-hours.
    ChargeCounter,
    /// Constant charge current limit in microamperes.
    ConstantChargeCurrent,
    /// Constant charge current maximum in microamperes.
    ConstantChargeCurrentMax,
    /// Constant charge voltage limit in microvolts.
    ConstantChargeVoltage,
    /// Constant charge voltage maximum in microvolts.
    ConstantChargeVoltageMax,
    /// Charge control limit percentage (0–100).
    ChargeControlLimit,
    /// Charge control limit maximum percentage.
    ChargeControlLimitMax,
    /// Charge control start threshold percentage.
    ChargeControlStartThreshold,
    /// Charge control end threshold percentage.
    ChargeControlEndThreshold,
    /// Energy design capacity in microwatt-hours.
    EnergyFullDesign,
    /// Energy empty design capacity in microwatt-hours.
    EnergyEmptyDesign,
    /// Current full-charge energy in microwatt-hours.
    EnergyFull,
    /// Current empty energy in microwatt-hours.
    EnergyEmpty,
    /// Current energy level in microwatt-hours.
    EnergyNow,
    /// Average energy consumption in microwatts.
    EnergyAvg,
    /// Remaining capacity as percentage (0–100).
    Capacity,
    /// Alert threshold for low capacity percentage.
    CapacityAlertMin,
    /// Alert threshold for full capacity percentage.
    CapacityAlertMax,
    /// Coarse capacity level.
    CapacityLevel,
    /// Battery temperature in tenths of a degree Celsius.
    Temp,
    /// Maximum battery temperature in tenths of a degree Celsius.
    TempMax,
    /// Minimum battery temperature in tenths of a degree Celsius.
    TempMin,
    /// Battery temperature alert upper limit in tenths of a degree Celsius.
    TempAlertMax,
    /// Battery temperature alert lower limit in tenths of a degree Celsius.
    TempAlertMin,
    /// Ambient temperature in tenths of a degree Celsius.
    TempAmbient,
    /// Estimated time to empty at current draw (seconds).
    TimeToEmpty,
    /// Estimated time to full charge (seconds).
    TimeToFull,
    /// Type of supply.
    Type,
    /// USB device type — stored as u32 code.
    UsbType,
    /// Scope — system or device — stored as u32 code.
    Scope,
    /// Precharge current in microamperes.
    PrechargeCurrentMax,
    /// Charge termination current in microamperes.
    ChargeTermCurrentMax,
    /// Calibration required flag.
    CalibrationRequired,
    /// Input voltage limit in microvolts.
    InputVoltageLimit,
    /// Input current limit in microamperes.
    InputCurrentLimit,
    /// Input power limit in microwatts.
    InputPowerLimit,
}

// -------------------------------------------------------------------
// PropertyValue
// -------------------------------------------------------------------

/// Typed value returned when reading a power supply property.
#[derive(Debug, Clone, Copy)]
pub enum PropertyValue {
    /// Integer measurement value (µV, µA, µWh, %, seconds, etc.).
    Int(i64),
    /// Unsigned integer value.
    Uint(u64),
    /// Boolean flag.
    Bool(bool),
    /// Charging status enumeration.
    Status(PowerSupplyStatus),
    /// Health enumeration.
    Health(PowerSupplyHealth),
    /// Capacity level enumeration.
    CapacityLevel(CapacityLevel),
    /// Supply type enumeration.
    Type(PowerSupplyType),
}

// -------------------------------------------------------------------
// PropEntry
// -------------------------------------------------------------------

/// Internal storage for a property-value pair.
#[derive(Clone, Copy)]
struct PropEntry {
    prop: PowerSupplyProperty,
    value: PropertyValue,
}

// -------------------------------------------------------------------
// PowerSupplyDesc
// -------------------------------------------------------------------

/// Static descriptor for a power supply device.
#[derive(Debug, Clone, Copy)]
pub struct PowerSupplyDesc {
    /// Unique supply identifier.
    pub id: u32,
    /// Human-readable name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Type of power supply.
    pub supply_type: PowerSupplyType,
}

impl PowerSupplyDesc {
    /// Creates a new power supply descriptor.
    ///
    /// `name` is truncated to 32 bytes if longer.
    pub fn new(id: u32, name: &[u8], supply_type: PowerSupplyType) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            supply_type,
        }
    }
}

// -------------------------------------------------------------------
// PowerSupplyDevice
// -------------------------------------------------------------------

/// Runtime state of a power supply device.
pub struct PowerSupplyDevice {
    /// Static descriptor.
    pub desc: PowerSupplyDesc,
    /// Cached property values.
    props: [Option<PropEntry>; MAX_PROPERTIES],
    /// Number of stored properties.
    prop_count: usize,
    /// Whether the supply is currently active/present.
    pub active: bool,
}

impl PowerSupplyDevice {
    /// Creates a new power supply device with the given descriptor.
    pub fn new(desc: PowerSupplyDesc) -> Self {
        Self {
            desc,
            props: [const { None }; MAX_PROPERTIES],
            prop_count: 0,
            active: true,
        }
    }

    /// Stores or updates the value of a property.
    ///
    /// Returns [`Error::OutOfMemory`] if all property slots are
    /// occupied and the property is not already stored.
    pub fn set_property(&mut self, prop: PowerSupplyProperty, value: PropertyValue) -> Result<()> {
        // Update existing entry if present.
        for slot in self.props.iter_mut().flatten() {
            if slot.prop == prop {
                slot.value = value;
                return Ok(());
            }
        }
        // Find an empty slot.
        for slot in &mut self.props {
            if slot.is_none() {
                *slot = Some(PropEntry { prop, value });
                self.prop_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Reads the value of a property.
    ///
    /// Returns [`Error::NotFound`] if the property has not been set.
    pub fn get_property(&self, prop: PowerSupplyProperty) -> Result<PropertyValue> {
        self.props
            .iter()
            .flatten()
            .find(|e| e.prop == prop)
            .map(|e| e.value)
            .ok_or(Error::NotFound)
    }

    /// Removes a property, freeing its slot.
    ///
    /// Returns [`Error::NotFound`] if the property is not set.
    pub fn clear_property(&mut self, prop: PowerSupplyProperty) -> Result<()> {
        for slot in &mut self.props {
            if slot.as_ref().is_some_and(|e| e.prop == prop) {
                *slot = None;
                self.prop_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of properties currently stored.
    pub fn property_count(&self) -> usize {
        self.prop_count
    }

    /// Convenience: returns the current charge capacity percentage (0–100).
    ///
    /// Returns [`Error::NotFound`] if [`PowerSupplyProperty::Capacity`] is
    /// not set.
    pub fn capacity_percent(&self) -> Result<i64> {
        match self.get_property(PowerSupplyProperty::Capacity)? {
            PropertyValue::Int(v) => Ok(v),
            PropertyValue::Uint(v) => Ok(v as i64),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convenience: returns the current charging status.
    ///
    /// Returns [`Error::NotFound`] if [`PowerSupplyProperty::Status`] is
    /// not set.
    pub fn status(&self) -> Result<PowerSupplyStatus> {
        match self.get_property(PowerSupplyProperty::Status)? {
            PropertyValue::Status(s) => Ok(s),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convenience: returns the current health.
    ///
    /// Returns [`Error::NotFound`] if [`PowerSupplyProperty::Health`] is
    /// not set.
    pub fn health(&self) -> Result<PowerSupplyHealth> {
        match self.get_property(PowerSupplyProperty::Health)? {
            PropertyValue::Health(h) => Ok(h),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convenience: returns the battery temperature in tenths of Celsius.
    ///
    /// Returns [`Error::NotFound`] if [`PowerSupplyProperty::Temp`] is
    /// not set.
    pub fn temperature_dc(&self) -> Result<i64> {
        match self.get_property(PowerSupplyProperty::Temp)? {
            PropertyValue::Int(v) => Ok(v),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// PowerSupplyRegistry
// -------------------------------------------------------------------

/// Registry managing up to [`MAX_SUPPLIES`] power supply devices.
pub struct PowerSupplyRegistry {
    /// Registered supply devices.
    devices: [Option<PowerSupplyDevice>; MAX_SUPPLIES],
    /// Number of registered devices.
    count: usize,
}

impl Default for PowerSupplyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerSupplyRegistry {
    /// Creates a new, empty power supply registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_SUPPLIES],
            count: 0,
        }
    }

    /// Registers a power supply device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, dev: PowerSupplyDevice) -> Result<()> {
        for d in self.devices.iter().flatten() {
            if d.desc.id == dev.desc.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(dev);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters the supply with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no supply with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.devices {
            let matches = slot.as_ref().is_some_and(|d| d.desc.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns an immutable reference to the supply with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&PowerSupplyDevice> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.desc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the supply with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut PowerSupplyDevice> {
        self.devices
            .iter_mut()
            .flatten()
            .find(|d| d.desc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Sets a property on the supply with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered, or
    /// [`Error::OutOfMemory`] if the device has no free property slots.
    pub fn set_property(
        &mut self,
        id: u32,
        prop: PowerSupplyProperty,
        value: PropertyValue,
    ) -> Result<()> {
        self.get_mut(id)?.set_property(prop, value)
    }

    /// Reads a property from the supply with `id`.
    ///
    /// Returns [`Error::NotFound`] if the device or property is not found.
    pub fn get_property(&self, id: u32, prop: PowerSupplyProperty) -> Result<PropertyValue> {
        self.get(id)?.get_property(prop)
    }

    /// Updates the `Capacity` and `Status` properties of supply `id` atomically.
    ///
    /// This is a convenience method for the common battery update path.
    ///
    /// Returns [`Error::NotFound`] if the device is not registered.
    pub fn update_charge(
        &mut self,
        id: u32,
        capacity_pct: i64,
        status: PowerSupplyStatus,
    ) -> Result<()> {
        let dev = self.get_mut(id)?;
        dev.set_property(
            PowerSupplyProperty::Capacity,
            PropertyValue::Int(capacity_pct),
        )?;
        dev.set_property(PowerSupplyProperty::Status, PropertyValue::Status(status))
    }

    /// Returns the number of registered supplies.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no supplies are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
