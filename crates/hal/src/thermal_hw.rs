// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware thermal monitoring subsystem.
//!
//! Provides abstractions for thermal zones, trip points, and cooling
//! devices. On x86_64 this interfaces with:
//! - Intel DTS (Digital Thermal Sensor) via MSR_IA32_THERM_STATUS
//! - ACPI thermal zones (read via ACPI thermal table)
//! - Fan/frequency cooling devices
//!
//! # Design
//!
//! Each [`ThermalZone`] has up to [`MAX_TRIP_POINTS`] trip points at
//! which the kernel takes action (fan ramp, frequency throttle, shutdown).
//! Temperatures are represented in milli-Celsius (1/1000 °C) to avoid
//! floating point.
//!
//! Reference: ACPI Specification 6.5, Section 11 (Thermal Management)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of trip points per thermal zone.
const MAX_TRIP_POINTS: usize = 8;

/// Maximum number of thermal zones.
const MAX_THERMAL_ZONES: usize = 8;

/// Maximum number of cooling devices.
const MAX_COOLING_DEVICES: usize = 8;

/// Maximum number of cooling device bindings per trip point.
const MAX_BINDINGS: usize = 4;

/// Temperature value indicating "not available" or sensor fault.
pub const THERMAL_TEMP_INVALID: i32 = i32::MIN;

/// Minimum valid temperature in milli-Celsius (-273_150 = absolute zero).
pub const THERMAL_TEMP_ABS_ZERO_MC: i32 = -273_150;

// ── MSR constants ────────────────────────────────────────────────────────────

/// IA32_THERM_STATUS MSR address.
const MSR_IA32_THERM_STATUS: u32 = 0x019C;
/// IA32_TEMPERATURE_TARGET MSR address (Tj_max).
const MSR_TEMPERATURE_TARGET: u32 = 0x01A2;
/// IA32_PACKAGE_THERM_STATUS MSR address (package-level).
const MSR_IA32_PKG_THERM_STATUS: u32 = 0x01B1;

/// Bit mask for "reading valid" in IA32_THERM_STATUS.
const THERM_STATUS_VALID: u64 = 1 << 31;
/// Bits 22:16 — Digital Readout (temperature below Tj_max).
const THERM_STATUS_READOUT_MASK: u64 = 0x7F << 16;
const THERM_STATUS_READOUT_SHIFT: u32 = 16;
/// Bits 23:16 in TEMPERATURE_TARGET — Tj_max in °C.
const TEMP_TARGET_TJMAX_MASK: u64 = 0xFF << 16;
const TEMP_TARGET_TJMAX_SHIFT: u32 = 16;

// ── TripType ─────────────────────────────────────────────────────────────────

/// Classification of a thermal trip point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripType {
    /// Active cooling point — triggers fan spin-up.
    Active,
    /// Passive cooling point — triggers frequency throttling.
    Passive,
    /// Hot point — triggers aggressive thermal mitigation.
    Hot,
    /// Critical point — triggers emergency shutdown.
    Critical,
}

// ── TripPoint ────────────────────────────────────────────────────────────────

/// A single thermal trip point.
#[derive(Debug, Clone, Copy)]
pub struct TripPoint {
    /// Temperature (in milli-Celsius) at which this trip is triggered.
    pub temperature_mc: i32,
    /// Type of action triggered at this trip.
    pub trip_type: TripType,
    /// Whether this trip point is currently active (temperature exceeded).
    pub triggered: bool,
    /// Hysteresis in milli-Celsius (trip clears at temp - hysteresis).
    pub hysteresis_mc: i32,
    /// IDs of cooling devices bound to this trip point.
    pub cooling_device_ids: [u8; MAX_BINDINGS],
    /// Number of bound cooling devices.
    pub num_bindings: u8,
}

impl TripPoint {
    /// Create a new trip point.
    pub const fn new(temperature_mc: i32, trip_type: TripType, hysteresis_mc: i32) -> Self {
        Self {
            temperature_mc,
            trip_type,
            triggered: false,
            hysteresis_mc,
            cooling_device_ids: [0u8; MAX_BINDINGS],
            num_bindings: 0,
        }
    }

    /// Bind a cooling device to this trip point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the binding table is full.
    pub fn bind_cooling_device(&mut self, device_id: u8) -> Result<()> {
        if self.num_bindings as usize >= MAX_BINDINGS {
            return Err(Error::OutOfMemory);
        }
        self.cooling_device_ids[self.num_bindings as usize] = device_id;
        self.num_bindings += 1;
        Ok(())
    }

    /// Update triggered state based on the current temperature.
    ///
    /// Returns `true` if the triggered state changed.
    pub fn update(&mut self, current_mc: i32) -> bool {
        let was_triggered = self.triggered;
        if !self.triggered && current_mc >= self.temperature_mc {
            self.triggered = true;
        } else if self.triggered
            && current_mc < self.temperature_mc.saturating_sub(self.hysteresis_mc)
        {
            self.triggered = false;
        }
        self.triggered != was_triggered
    }
}

// ── CoolingType ──────────────────────────────────────────────────────────────

/// Type of thermal cooling device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoolingType {
    /// Fan speed control (0 = min speed, max_state = max speed).
    Fan,
    /// CPU frequency scaling (0 = min freq, max_state = max freq).
    CpuFreq,
    /// Generic platform-specific cooling.
    Platform,
}

// ── ThermalCoolingDevice ─────────────────────────────────────────────────────

/// A thermal cooling device that can be actuated at discrete states.
pub struct ThermalCoolingDevice {
    /// Unique ID of this cooling device.
    pub id: u8,
    /// Human-readable name (e.g. "fan0", "cpu0-freq").
    pub name: [u8; 16],
    /// Number of valid characters in `name`.
    pub name_len: usize,
    /// Type of cooling action.
    pub cooling_type: CoolingType,
    /// Current state (0 = minimum cooling).
    pub cur_state: u32,
    /// Maximum state (maximum cooling).
    pub max_state: u32,
    /// Whether this device is active.
    pub active: bool,
}

impl ThermalCoolingDevice {
    /// Create a new cooling device.
    pub fn new(id: u8, name: &[u8], cooling_type: CoolingType, max_state: u32) -> Self {
        let mut name_buf = [0u8; 16];
        let len = name.len().min(16);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            id,
            name: name_buf,
            name_len: len,
            cooling_type,
            cur_state: 0,
            max_state,
            active: false,
        }
    }

    /// Set the cooling state (0..=max_state).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `state > max_state`.
    pub fn set_state(&mut self, state: u32) -> Result<()> {
        if state > self.max_state {
            return Err(Error::InvalidArgument);
        }
        self.cur_state = state;
        self.active = state > 0;
        Ok(())
    }

    /// Return the name as a byte slice.
    pub fn name_str(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── ThermalZone ──────────────────────────────────────────────────────────────

/// A hardware thermal zone with one sensor and up to [`MAX_TRIP_POINTS`] trips.
pub struct ThermalZone {
    /// Zone name.
    pub name: [u8; 16],
    /// Number of valid characters in `name`.
    pub name_len: usize,
    /// Current temperature in milli-Celsius.
    current_temp_mc: i32,
    /// Trip points for this zone.
    trip_points: [Option<TripPoint>; MAX_TRIP_POINTS],
    /// Number of registered trip points.
    trip_count: usize,
    /// Zone identifier (ACPI path index or DTS core index).
    pub zone_id: u32,
    /// Whether the zone is enabled for active thermal management.
    pub enabled: bool,
    /// Passive cooling delay in milliseconds.
    pub passive_delay_ms: u32,
    /// Temperature polling interval in milliseconds.
    pub polling_delay_ms: u32,
}

impl ThermalZone {
    /// Create a new thermal zone.
    pub fn new(zone_id: u32, name: &[u8]) -> Self {
        let mut name_buf = [0u8; 16];
        let len = name.len().min(16);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            name: name_buf,
            name_len: len,
            current_temp_mc: THERMAL_TEMP_INVALID,
            trip_points: [const { None }; MAX_TRIP_POINTS],
            trip_count: 0,
            zone_id,
            enabled: false,
            passive_delay_ms: 1000,
            polling_delay_ms: 2000,
        }
    }

    /// Add a trip point to this zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the trip table is full.
    pub fn add_trip_point(&mut self, trip: TripPoint) -> Result<()> {
        if self.trip_count >= MAX_TRIP_POINTS {
            return Err(Error::OutOfMemory);
        }
        self.trip_points[self.trip_count] = Some(trip);
        self.trip_count += 1;
        Ok(())
    }

    /// Update the zone with a new temperature reading (in milli-Celsius).
    ///
    /// Returns a bitmask of trip point indices that changed state.
    pub fn update_temperature(&mut self, temp_mc: i32) -> u32 {
        self.current_temp_mc = temp_mc;
        let mut changed = 0u32;
        for (i, slot) in self.trip_points[..self.trip_count].iter_mut().enumerate() {
            if let Some(trip) = slot {
                if trip.update(temp_mc) {
                    changed |= 1 << i;
                }
            }
        }
        changed
    }

    /// Return the current temperature in milli-Celsius.
    pub fn temperature_mc(&self) -> i32 {
        self.current_temp_mc
    }

    /// Return the highest active trip type, or `None` if none triggered.
    pub fn active_trip_type(&self) -> Option<TripType> {
        let mut result = None;
        for slot in &self.trip_points[..self.trip_count] {
            if let Some(trip) = slot {
                if trip.triggered {
                    result = match (result, trip.trip_type) {
                        (None, t) => Some(t),
                        (Some(TripType::Critical), _) | (_, TripType::Critical) => {
                            Some(TripType::Critical)
                        }
                        (Some(TripType::Hot), _) | (_, TripType::Hot) => Some(TripType::Hot),
                        (Some(TripType::Passive), _) | (_, TripType::Passive) => {
                            Some(TripType::Passive)
                        }
                        (Some(TripType::Active), TripType::Active) => Some(TripType::Active),
                    };
                }
            }
        }
        result
    }

    /// Return the trip point at `index`.
    pub fn trip_point(&self, index: usize) -> Option<&TripPoint> {
        self.trip_points.get(index)?.as_ref()
    }

    /// Return the number of trip points.
    pub fn trip_count(&self) -> usize {
        self.trip_count
    }

    /// Return the zone name as bytes.
    pub fn name_str(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── Intel DTS sensor ─────────────────────────────────────────────────────────

/// Read the Intel DTS (Digital Thermal Sensor) temperature for the
/// current logical CPU.
///
/// Returns the temperature in milli-Celsius, or `THERMAL_TEMP_INVALID`
/// if the sensor reading is not valid.
#[cfg(target_arch = "x86_64")]
pub fn dts_read_temp_mc() -> i32 {
    // SAFETY: RDMSR with known-safe MSR addresses on Intel processors.
    let (therm_status, temp_target) = unsafe {
        let lo_ts: u32;
        let hi_ts: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_IA32_THERM_STATUS,
            out("eax") lo_ts,
            out("edx") hi_ts,
            options(nostack, preserves_flags),
        );
        let ts = ((hi_ts as u64) << 32) | lo_ts as u64;

        let lo_tt: u32;
        let hi_tt: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_TEMPERATURE_TARGET,
            out("eax") lo_tt,
            out("edx") hi_tt,
            options(nostack, preserves_flags),
        );
        let tt = ((hi_tt as u64) << 32) | lo_tt as u64;
        (ts, tt)
    };

    if therm_status & THERM_STATUS_VALID == 0 {
        return THERMAL_TEMP_INVALID;
    }

    let readout = ((therm_status & THERM_STATUS_READOUT_MASK) >> THERM_STATUS_READOUT_SHIFT) as i32;
    let tjmax = ((temp_target & TEMP_TARGET_TJMAX_MASK) >> TEMP_TARGET_TJMAX_SHIFT) as i32;

    if tjmax == 0 {
        return THERMAL_TEMP_INVALID;
    }

    // Temp = (Tj_max - readout) × 1000 milli-Celsius
    (tjmax - readout) * 1000
}

/// Stub for non-x86_64 targets.
#[cfg(not(target_arch = "x86_64"))]
pub fn dts_read_temp_mc() -> i32 {
    THERMAL_TEMP_INVALID
}

/// Read the Intel package-level thermal status.
///
/// Returns the package temperature in milli-Celsius.
#[cfg(target_arch = "x86_64")]
pub fn pkg_dts_read_temp_mc() -> i32 {
    // SAFETY: Reading package thermal MSR on Intel x86_64.
    let (pkg_status, temp_target) = unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_IA32_PKG_THERM_STATUS,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
        let pkg = ((hi as u64) << 32) | lo as u64;

        let lo_tt: u32;
        let hi_tt: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_TEMPERATURE_TARGET,
            out("eax") lo_tt,
            out("edx") hi_tt,
            options(nostack, preserves_flags),
        );
        let tt = ((hi_tt as u64) << 32) | lo_tt as u64;
        (pkg, tt)
    };

    if pkg_status & THERM_STATUS_VALID == 0 {
        return THERMAL_TEMP_INVALID;
    }

    let readout = ((pkg_status & THERM_STATUS_READOUT_MASK) >> THERM_STATUS_READOUT_SHIFT) as i32;
    let tjmax = ((temp_target & TEMP_TARGET_TJMAX_MASK) >> TEMP_TARGET_TJMAX_SHIFT) as i32;

    if tjmax == 0 {
        return THERMAL_TEMP_INVALID;
    }
    (tjmax - readout) * 1000
}

/// Stub for non-x86_64 targets.
#[cfg(not(target_arch = "x86_64"))]
pub fn pkg_dts_read_temp_mc() -> i32 {
    THERMAL_TEMP_INVALID
}

// ── ThermalManager ───────────────────────────────────────────────────────────

/// Global thermal subsystem manager.
pub struct ThermalManager {
    /// Registered thermal zones.
    zones: [Option<ThermalZone>; MAX_THERMAL_ZONES],
    /// Registered cooling devices.
    cooling_devs: [Option<ThermalCoolingDevice>; MAX_COOLING_DEVICES],
    /// Number of registered zones.
    zone_count: usize,
    /// Number of registered cooling devices.
    cooling_count: usize,
}

impl ThermalManager {
    /// Create a new thermal manager.
    pub const fn new() -> Self {
        Self {
            zones: [const { None }; MAX_THERMAL_ZONES],
            cooling_devs: [const { None }; MAX_COOLING_DEVICES],
            zone_count: 0,
            cooling_count: 0,
        }
    }

    /// Register a thermal zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the zone table is full.
    pub fn register_zone(&mut self, zone: ThermalZone) -> Result<u8> {
        if self.zone_count >= MAX_THERMAL_ZONES {
            return Err(Error::OutOfMemory);
        }
        let id = self.zone_count;
        self.zones[id] = Some(zone);
        self.zone_count += 1;
        Ok(id as u8)
    }

    /// Register a cooling device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the cooling device table is full.
    pub fn register_cooling_device(&mut self, dev: ThermalCoolingDevice) -> Result<u8> {
        if self.cooling_count >= MAX_COOLING_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let id = self.cooling_count;
        self.cooling_devs[id] = Some(dev);
        self.cooling_count += 1;
        Ok(id as u8)
    }

    /// Poll all thermal zones and update temperatures.
    ///
    /// For DTS zones (zone_id == 0), reads MSR directly. For others,
    /// the caller must supply temperatures via `update_zone_temp`.
    pub fn poll_dts_zones(&mut self) {
        let temp = dts_read_temp_mc();
        if temp == THERMAL_TEMP_INVALID {
            return;
        }
        for slot in &mut self.zones[..self.zone_count] {
            if let Some(zone) = slot {
                if zone.zone_id == 0 && zone.enabled {
                    zone.update_temperature(temp);
                }
            }
        }
    }

    /// Update a specific zone with a temperature reading.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone ID is invalid.
    pub fn update_zone_temp(&mut self, zone_id: u32, temp_mc: i32) -> Result<u32> {
        for slot in &mut self.zones[..self.zone_count] {
            if let Some(zone) = slot {
                if zone.zone_id == zone_id {
                    let changed = zone.update_temperature(temp_mc);
                    return Ok(changed);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Set a cooling device state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device ID is invalid.
    pub fn set_cooling_state(&mut self, device_id: u8, state: u32) -> Result<()> {
        let slot = self
            .cooling_devs
            .get_mut(device_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        slot.set_state(state)
    }

    /// Return the current temperature of a zone in milli-Celsius.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone is not found.
    pub fn zone_temp(&self, zone_id: u32) -> Result<i32> {
        self.zones[..self.zone_count]
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|z| z.zone_id == zone_id)
            .map(|z| z.temperature_mc())
            .ok_or(Error::NotFound)
    }

    /// Return the number of registered zones.
    pub fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Return the number of registered cooling devices.
    pub fn cooling_count(&self) -> usize {
        self.cooling_count
    }
}

impl Default for ThermalManager {
    fn default() -> Self {
        Self::new()
    }
}
