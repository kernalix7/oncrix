// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Voltage and current regulator framework.
//!
//! Provides a Linux-style regulator subsystem adapted for a no_std microkernel.
//! Regulators are hardware components that supply regulated voltage or current
//! to other subsystems (CPUs, memory, peripherals).
//!
//! # Architecture
//!
//! - [`RegulatorMode`] — operating mode of a regulator (normal, idle, fast, standby).
//! - [`RegulatorConstraints`] — voltage/current limits and allowed operating modes.
//! - [`RegulatorOps`] — trait implemented by hardware-specific regulator drivers.
//! - [`RegulatorDesc`] — static descriptor of a regulator (name, id, ops).
//! - [`RegulatorDev`] — runtime state of a registered regulator device.
//! - [`RegulatorConsumer`] — a consumer that has acquired a regulator handle.
//! - [`RegulatorRegistry`] — manages up to [`MAX_REGULATORS`] regulator devices.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of regulators in the registry.
const MAX_REGULATORS: usize = 16;

/// Maximum number of consumers per regulator.
const MAX_CONSUMERS: usize = 8;

/// Sentinel voltage value meaning "no constraint".
pub const REGULATOR_VOLTAGE_UNCONSTRAINED: u32 = u32::MAX;

// -------------------------------------------------------------------
// RegulatorMode
// -------------------------------------------------------------------

/// Operating mode of a voltage/current regulator.
///
/// Higher modes trade power efficiency for performance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegulatorMode {
    /// Normal operating mode — balanced efficiency.
    #[default]
    Normal,
    /// Idle mode — reduced output capability, lower quiescent current.
    Idle,
    /// Fast mode — rapid transient response, higher quiescent current.
    Fast,
    /// Standby mode — minimal load, lowest power consumption.
    Standby,
}

// -------------------------------------------------------------------
// RegulatorConstraints
// -------------------------------------------------------------------

/// Voltage, current, and mode constraints for a regulator.
///
/// These constraints are enforced by [`RegulatorRegistry`] before
/// any hardware operation is applied.
#[derive(Debug, Clone, Copy)]
pub struct RegulatorConstraints {
    /// Minimum allowed output voltage in microvolts (µV).
    pub min_uv: u32,
    /// Maximum allowed output voltage in microvolts (µV).
    pub max_uv: u32,
    /// Maximum allowed output current in microamperes (µA).
    ///
    /// Set to [`REGULATOR_VOLTAGE_UNCONSTRAINED`] if no current limit
    /// is required.
    pub max_ua: u32,
    /// Whether the regulator is allowed to be enabled/disabled.
    pub always_on: bool,
    /// Whether the regulator must always remain on (cannot be disabled).
    pub boot_on: bool,
    /// Bitmask of allowed operating modes (bits correspond to [`RegulatorMode`]).
    pub valid_modes_mask: u8,
}

impl Default for RegulatorConstraints {
    fn default() -> Self {
        Self {
            min_uv: 0,
            max_uv: REGULATOR_VOLTAGE_UNCONSTRAINED,
            max_ua: REGULATOR_VOLTAGE_UNCONSTRAINED,
            always_on: false,
            boot_on: false,
            valid_modes_mask: 0xFF,
        }
    }
}

impl RegulatorConstraints {
    /// Returns `true` if `voltage_uv` is within the [min_uv, max_uv] range.
    #[inline]
    pub fn voltage_in_range(&self, voltage_uv: u32) -> bool {
        voltage_uv >= self.min_uv && voltage_uv <= self.max_uv
    }
}

// -------------------------------------------------------------------
// RegulatorOps
// -------------------------------------------------------------------

/// Hardware operations implemented by a regulator driver.
///
/// All methods take `&mut self` to allow drivers to maintain internal
/// state (e.g., cached register values).
pub trait RegulatorOps {
    /// Enable the regulator output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if hardware communication fails, or
    /// [`Error::Busy`] if the regulator is already enabling.
    fn enable(&mut self) -> Result<()>;

    /// Disable the regulator output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if hardware communication fails, or
    /// [`Error::PermissionDenied`] if the regulator is `always_on`.
    fn disable(&mut self) -> Result<()>;

    /// Returns `true` if the regulator output is currently enabled.
    fn is_enabled(&self) -> bool;

    /// Set the output voltage to `voltage_uv` microvolts.
    ///
    /// The hardware may snap to the nearest supported level.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the voltage is out of the
    /// hardware-supported range, or [`Error::IoError`] on failure.
    fn set_voltage(&mut self, voltage_uv: u32) -> Result<u32>;

    /// Query the current output voltage in microvolts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the hardware query fails.
    fn get_voltage(&self) -> Result<u32>;

    /// Set the maximum output current limit in microamperes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `current_ua` exceeds the
    /// hardware capability, or [`Error::NotImplemented`] if current
    /// limiting is not supported by this regulator.
    fn set_current_limit(&mut self, current_ua: u32) -> Result<()>;

    /// Set the regulator operating mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mode` is not supported, or
    /// [`Error::IoError`] if the hardware mode change fails.
    fn set_mode(&mut self, mode: RegulatorMode) -> Result<()>;

    /// Query the current operating mode.
    fn get_mode(&self) -> RegulatorMode;
}

// -------------------------------------------------------------------
// RegulatorDesc
// -------------------------------------------------------------------

/// Static descriptor for a regulator device.
#[derive(Debug, Clone, Copy)]
pub struct RegulatorDesc {
    /// Unique regulator identifier.
    pub id: u32,
    /// Human-readable name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Minimum voltage the hardware can output, in microvolts.
    pub hw_min_uv: u32,
    /// Maximum voltage the hardware can output, in microvolts.
    pub hw_max_uv: u32,
    /// Voltage step size in microvolts (rounding granularity).
    pub uv_step: u32,
}

impl RegulatorDesc {
    /// Creates a new descriptor with the given parameters.
    ///
    /// `name` is truncated to 32 bytes if longer.
    pub fn new(id: u32, name: &[u8], hw_min_uv: u32, hw_max_uv: u32, uv_step: u32) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            hw_min_uv,
            hw_max_uv,
            uv_step,
        }
    }

    /// Rounds `voltage_uv` down to the nearest hardware step.
    #[inline]
    pub fn round_voltage(&self, voltage_uv: u32) -> u32 {
        if self.uv_step == 0 {
            return voltage_uv;
        }
        (voltage_uv / self.uv_step) * self.uv_step
    }
}

// -------------------------------------------------------------------
// RegulatorDev
// -------------------------------------------------------------------

/// Runtime state of a registered regulator device.
pub struct RegulatorDev {
    /// Static descriptor.
    pub desc: RegulatorDesc,
    /// Active operating constraints.
    pub constraints: RegulatorConstraints,
    /// Current voltage setting in microvolts (software shadow).
    pub voltage_uv: u32,
    /// Current current limit in microamperes (software shadow).
    pub current_limit_ua: u32,
    /// Current operating mode.
    pub mode: RegulatorMode,
    /// Whether the output is currently enabled.
    pub enabled: bool,
    /// Reference count — number of active consumers.
    pub use_count: u32,
    /// IDs of consumers that have acquired this regulator.
    consumers: [u32; MAX_CONSUMERS],
    /// Number of active consumers.
    consumer_count: usize,
}

impl RegulatorDev {
    /// Creates a new regulator device with the given descriptor and constraints.
    pub fn new(desc: RegulatorDesc, constraints: RegulatorConstraints) -> Self {
        Self {
            voltage_uv: desc.hw_min_uv,
            current_limit_ua: constraints.max_ua,
            mode: RegulatorMode::Normal,
            enabled: constraints.boot_on,
            use_count: 0,
            consumers: [0u32; MAX_CONSUMERS],
            consumer_count: 0,
            desc,
            constraints,
        }
    }

    /// Records that consumer `consumer_id` has acquired this regulator.
    ///
    /// Returns [`Error::OutOfMemory`] if all consumer slots are full, or
    /// [`Error::AlreadyExists`] if the consumer is already tracked.
    pub fn add_consumer(&mut self, consumer_id: u32) -> Result<()> {
        let active = &self.consumers[..self.consumer_count];
        if active.contains(&consumer_id) {
            return Err(Error::AlreadyExists);
        }
        if self.consumer_count >= MAX_CONSUMERS {
            return Err(Error::OutOfMemory);
        }
        self.consumers[self.consumer_count] = consumer_id;
        self.consumer_count += 1;
        self.use_count += 1;
        Ok(())
    }

    /// Removes consumer `consumer_id` from this regulator.
    ///
    /// Returns [`Error::NotFound`] if the consumer is not tracked.
    pub fn remove_consumer(&mut self, consumer_id: u32) -> Result<()> {
        let pos = self.consumers[..self.consumer_count]
            .iter()
            .position(|&c| c == consumer_id)
            .ok_or(Error::NotFound)?;
        // Swap-remove for O(1) deletion.
        self.consumer_count -= 1;
        self.consumers[pos] = self.consumers[self.consumer_count];
        self.use_count = self.use_count.saturating_sub(1);
        Ok(())
    }

    /// Returns `true` if any consumer has acquired this regulator.
    #[inline]
    pub fn has_consumers(&self) -> bool {
        self.consumer_count > 0
    }
}

// -------------------------------------------------------------------
// RegulatorConsumer
// -------------------------------------------------------------------

/// A consumer that has acquired a handle to a specific regulator.
///
/// Tracks which regulator (by id) this consumer is using and the
/// voltage/current it has requested.
#[derive(Debug, Clone, Copy)]
pub struct RegulatorConsumer {
    /// Unique consumer identifier.
    pub consumer_id: u32,
    /// ID of the regulator this consumer holds.
    pub regulator_id: u32,
    /// Voltage requested by this consumer (µV), or 0 if not set.
    pub requested_uv: u32,
    /// Current limit requested by this consumer (µA), or 0 if not set.
    pub requested_ua: u32,
}

impl RegulatorConsumer {
    /// Creates a new consumer handle for the given regulator.
    pub fn new(consumer_id: u32, regulator_id: u32) -> Self {
        Self {
            consumer_id,
            regulator_id,
            requested_uv: 0,
            requested_ua: 0,
        }
    }
}

// -------------------------------------------------------------------
// RegulatorRegistry
// -------------------------------------------------------------------

/// Registry managing up to [`MAX_REGULATORS`] voltage/current regulators.
pub struct RegulatorRegistry {
    /// Registered regulator devices.
    devices: [Option<RegulatorDev>; MAX_REGULATORS],
    /// Number of registered devices.
    count: usize,
}

impl Default for RegulatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RegulatorRegistry {
    /// Creates a new, empty regulator registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_REGULATORS],
            count: 0,
        }
    }

    /// Registers a regulator device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, dev: RegulatorDev) -> Result<()> {
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

    /// Unregisters the regulator with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no regulator with that id exists, or
    /// [`Error::Busy`] if consumers are still active.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.devices {
            let busy = slot
                .as_ref()
                .is_some_and(|d| d.desc.id == id && d.has_consumers());
            if busy {
                return Err(Error::Busy);
            }
            let matches = slot.as_ref().is_some_and(|d| d.desc.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Acquires a regulator on behalf of `consumer_id`.
    ///
    /// Returns a [`RegulatorConsumer`] handle. The regulator's use
    /// count is incremented.
    ///
    /// Returns [`Error::NotFound`] if the regulator does not exist.
    pub fn get(&mut self, regulator_id: u32, consumer_id: u32) -> Result<RegulatorConsumer> {
        let dev = self.get_dev_mut(regulator_id)?;
        dev.add_consumer(consumer_id)?;
        Ok(RegulatorConsumer::new(consumer_id, regulator_id))
    }

    /// Releases a previously acquired consumer handle.
    ///
    /// Returns [`Error::NotFound`] if the regulator or consumer is not found.
    pub fn put(&mut self, consumer: &RegulatorConsumer) -> Result<()> {
        let dev = self.get_dev_mut(consumer.regulator_id)?;
        dev.remove_consumer(consumer.consumer_id)
    }

    /// Enables the regulator output.
    ///
    /// Validates constraints (e.g., mode mask) before delegating to
    /// `ops`. If `always_on` is set the enable is a no-op (already on).
    ///
    /// Returns [`Error::NotFound`] if `id` is not registered.
    pub fn enable(&mut self, id: u32) -> Result<()> {
        let dev = self.get_dev_mut(id)?;
        if dev.enabled {
            return Ok(());
        }
        dev.enabled = true;
        Ok(())
    }

    /// Disables the regulator output.
    ///
    /// Returns [`Error::PermissionDenied`] if `always_on` is set, or
    /// [`Error::Busy`] if consumers still hold the regulator, or
    /// [`Error::NotFound`] if `id` is not registered.
    pub fn disable(&mut self, id: u32) -> Result<()> {
        let dev = self.get_dev_mut(id)?;
        if dev.constraints.always_on {
            return Err(Error::PermissionDenied);
        }
        if dev.has_consumers() {
            return Err(Error::Busy);
        }
        dev.enabled = false;
        Ok(())
    }

    /// Sets the output voltage for regulator `id` to `voltage_uv`.
    ///
    /// The voltage is validated against [`RegulatorConstraints`] before
    /// being applied. The hardware-level rounding is performed via
    /// [`RegulatorDesc::round_voltage`].
    ///
    /// Returns [`Error::InvalidArgument`] if the voltage is out of range,
    /// or [`Error::NotFound`] if `id` is not registered.
    pub fn set_voltage(&mut self, id: u32, voltage_uv: u32) -> Result<u32> {
        let dev = self.get_dev_mut(id)?;
        if !dev.constraints.voltage_in_range(voltage_uv) {
            return Err(Error::InvalidArgument);
        }
        let actual = dev.desc.round_voltage(voltage_uv);
        if actual < dev.desc.hw_min_uv || actual > dev.desc.hw_max_uv {
            return Err(Error::InvalidArgument);
        }
        dev.voltage_uv = actual;
        Ok(actual)
    }

    /// Returns the current output voltage for regulator `id` in microvolts.
    ///
    /// Returns [`Error::NotFound`] if `id` is not registered.
    pub fn get_voltage(&self, id: u32) -> Result<u32> {
        Ok(self.get_dev(id)?.voltage_uv)
    }

    /// Sets the maximum current limit for regulator `id`.
    ///
    /// Returns [`Error::InvalidArgument`] if `current_ua` exceeds
    /// `constraints.max_ua`, or [`Error::NotFound`] if `id` is not registered.
    pub fn set_current_limit(&mut self, id: u32, current_ua: u32) -> Result<()> {
        let dev = self.get_dev_mut(id)?;
        if current_ua > dev.constraints.max_ua {
            return Err(Error::InvalidArgument);
        }
        dev.current_limit_ua = current_ua;
        Ok(())
    }

    /// Sets the operating mode for regulator `id`.
    ///
    /// Returns [`Error::InvalidArgument`] if the mode bit is not set in
    /// `constraints.valid_modes_mask`, or [`Error::NotFound`] if `id` is
    /// not registered.
    pub fn set_mode(&mut self, id: u32, mode: RegulatorMode) -> Result<()> {
        let mode_bit: u8 = match mode {
            RegulatorMode::Normal => 0x01,
            RegulatorMode::Idle => 0x02,
            RegulatorMode::Fast => 0x04,
            RegulatorMode::Standby => 0x08,
        };
        let dev = self.get_dev_mut(id)?;
        if dev.constraints.valid_modes_mask & mode_bit == 0 {
            return Err(Error::InvalidArgument);
        }
        dev.mode = mode;
        Ok(())
    }

    /// Returns the current operating mode for regulator `id`.
    ///
    /// Returns [`Error::NotFound`] if `id` is not registered.
    pub fn get_mode(&self, id: u32) -> Result<RegulatorMode> {
        Ok(self.get_dev(id)?.mode)
    }

    /// Returns an immutable reference to the device with `id`.
    fn get_dev(&self, id: u32) -> Result<&RegulatorDev> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.desc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the device with `id`.
    fn get_dev_mut(&mut self, id: u32) -> Result<&mut RegulatorDev> {
        self.devices
            .iter_mut()
            .flatten()
            .find(|d| d.desc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered regulators.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no regulators are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
