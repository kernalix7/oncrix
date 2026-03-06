// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thermal sensor and thermal zone driver.
//!
//! Provides a thermal management subsystem that monitors temperature
//! sensors, evaluates trip points, and coordinates cooling devices
//! to maintain safe operating temperatures.
//!
//! # Architecture
//!
//! - **ThermalTripType** — classification of a thermal trip point
//!   (active, passive, hot, critical).
//! - **ThermalTripPoint** — a temperature threshold with hysteresis
//!   that triggers a thermal policy action.
//! - **ThermalGovernor** — thermal policy algorithm that decides how
//!   to react when a trip point is crossed.
//! - **CoolingType** — classification of a cooling device (fan,
//!   processor throttle, memory throttle).
//! - **ThermalCoolingDevice** — a device that can reduce heat
//!   output (fan, CPU throttle, etc.).
//! - **ThermalZone** — a thermal sensor with associated trip points
//!   and bound cooling devices.
//! - **ThermalRegistry** — manages up to [`MAX_ZONES`] thermal
//!   zones and [`MAX_COOLING_DEVICES`] cooling devices.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of thermal zones in the registry.
const MAX_ZONES: usize = 16;

/// Maximum number of cooling devices in the registry.
const MAX_COOLING_DEVICES: usize = 32;

/// Maximum number of trip points per thermal zone.
const MAX_TRIP_POINTS: usize = 8;

/// Maximum number of cooling devices bound to a single zone.
const MAX_ZONE_COOLING: usize = 4;

// -------------------------------------------------------------------
// ThermalTripType
// -------------------------------------------------------------------

/// Classification of a thermal trip point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThermalTripType {
    /// Active cooling engaged (e.g., fan speed increase).
    #[default]
    Active,
    /// Passive cooling engaged (e.g., CPU frequency reduction).
    Passive,
    /// System is hot; OS should take corrective action.
    Hot,
    /// Critical temperature; immediate shutdown required.
    Critical,
}

// -------------------------------------------------------------------
// ThermalTripPoint
// -------------------------------------------------------------------

/// A temperature threshold that triggers a thermal policy action.
#[derive(Debug, Clone, Copy)]
pub struct ThermalTripPoint {
    /// Type of trip point.
    pub trip_type: ThermalTripType,
    /// Temperature threshold in millicelsius.
    pub temperature_mc: i32,
    /// Hysteresis in millicelsius applied when deactivating.
    pub hysteresis_mc: i32,
}

/// Constant empty trip point for array initialisation.
const EMPTY_TRIP: ThermalTripPoint = ThermalTripPoint {
    trip_type: ThermalTripType::Active,
    temperature_mc: 0,
    hysteresis_mc: 0,
};

// -------------------------------------------------------------------
// ThermalGovernor
// -------------------------------------------------------------------

/// Thermal policy algorithm for a thermal zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThermalGovernor {
    /// Incremental step-wise cooling adjustment (default).
    #[default]
    StepWise,
    /// On/off cooling control.
    BangBang,
    /// User-space driven thermal policy.
    UserSpace,
    /// Power-budget-based cooling allocation.
    PowerAllocator,
}

// -------------------------------------------------------------------
// CoolingType
// -------------------------------------------------------------------

/// Classification of a cooling device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoolingType {
    /// Fan-based cooling.
    #[default]
    Fan,
    /// Processor frequency/voltage throttling.
    Processor,
    /// Memory bandwidth throttling.
    Memory,
}

// -------------------------------------------------------------------
// ThermalCoolingDevice
// -------------------------------------------------------------------

/// A device capable of reducing thermal output.
#[derive(Debug, Clone, Copy)]
pub struct ThermalCoolingDevice {
    /// Unique cooling device identifier.
    pub id: u32,
    /// Human-readable name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Maximum cooling state (higher = more cooling).
    pub max_state: u32,
    /// Current cooling state.
    pub cur_state: u32,
    /// Type of cooling mechanism.
    pub cooling_type: CoolingType,
    /// Whether this device is registered and active.
    pub active: bool,
}

impl ThermalCoolingDevice {
    /// Creates a new cooling device with the given parameters.
    pub fn new(id: u32, name: &[u8], max_state: u32, cooling_type: CoolingType) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            max_state,
            cur_state: 0,
            cooling_type,
            active: true,
        }
    }

    /// Sets the current cooling state.
    ///
    /// Returns [`Error::InvalidArgument`] if `state` exceeds
    /// [`max_state`](Self::max_state).
    pub fn set_state(&mut self, state: u32) -> Result<()> {
        if state > self.max_state {
            return Err(Error::InvalidArgument);
        }
        self.cur_state = state;
        Ok(())
    }
}

// -------------------------------------------------------------------
// ThermalZone
// -------------------------------------------------------------------

/// A thermal sensor zone with trip points and bound cooling devices.
#[derive(Debug, Clone)]
pub struct ThermalZone {
    /// Unique zone identifier.
    pub id: u32,
    /// Human-readable name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Current temperature reading in millicelsius.
    pub temperature_mc: i32,
    /// Configured trip points.
    pub trip_points: [ThermalTripPoint; MAX_TRIP_POINTS],
    /// Number of active trip points.
    pub trip_count: usize,
    /// Thermal policy governor for this zone.
    pub governor: ThermalGovernor,
    /// IDs of cooling devices bound to this zone.
    pub cooling_devices: [u32; MAX_ZONE_COOLING],
    /// Number of bound cooling devices.
    pub cooling_count: usize,
    /// Whether this zone is enabled and being monitored.
    pub enabled: bool,
}

impl ThermalZone {
    /// Creates a new thermal zone with the given `id` and `name`.
    pub fn new(id: u32, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            temperature_mc: 0,
            trip_points: [EMPTY_TRIP; MAX_TRIP_POINTS],
            trip_count: 0,
            governor: ThermalGovernor::StepWise,
            cooling_devices: [0u32; MAX_ZONE_COOLING],
            cooling_count: 0,
            enabled: true,
        }
    }

    /// Adds a trip point to this zone.
    ///
    /// Returns [`Error::OutOfMemory`] if all [`MAX_TRIP_POINTS`]
    /// slots are occupied.
    pub fn add_trip(&mut self, trip: ThermalTripPoint) -> Result<()> {
        if self.trip_count >= MAX_TRIP_POINTS {
            return Err(Error::OutOfMemory);
        }
        self.trip_points[self.trip_count] = trip;
        self.trip_count += 1;
        Ok(())
    }

    /// Binds a cooling device (by id) to this zone.
    ///
    /// Returns [`Error::OutOfMemory`] if all [`MAX_ZONE_COOLING`]
    /// slots are occupied, or [`Error::AlreadyExists`] if the
    /// cooling device is already bound.
    pub fn bind_cooling(&mut self, cooling_id: u32) -> Result<()> {
        let bound = &self.cooling_devices[..self.cooling_count];
        if bound.contains(&cooling_id) {
            return Err(Error::AlreadyExists);
        }
        if self.cooling_count >= MAX_ZONE_COOLING {
            return Err(Error::OutOfMemory);
        }
        self.cooling_devices[self.cooling_count] = cooling_id;
        self.cooling_count += 1;
        Ok(())
    }

    /// Returns the trip points that the current temperature
    /// exceeds.
    ///
    /// Writes matching trip point indices into `out` and returns
    /// how many were written.
    pub fn tripped_points(&self, out: &mut [usize]) -> usize {
        let mut written = 0;
        for (i, tp) in self.trip_points[..self.trip_count].iter().enumerate() {
            if written >= out.len() {
                break;
            }
            if self.temperature_mc >= tp.temperature_mc {
                out[written] = i;
                written += 1;
            }
        }
        written
    }
}

// -------------------------------------------------------------------
// ThermalRegistry
// -------------------------------------------------------------------

/// Registry managing thermal zones and cooling devices.
///
/// Supports up to [`MAX_ZONES`] thermal zones and
/// [`MAX_COOLING_DEVICES`] cooling devices.
pub struct ThermalRegistry {
    /// Registered thermal zones.
    zones: [Option<ThermalZone>; MAX_ZONES],
    /// Number of registered zones.
    zone_count: usize,
    /// Registered cooling devices.
    cooling: [Option<ThermalCoolingDevice>; MAX_COOLING_DEVICES],
    /// Number of registered cooling devices.
    cooling_count: usize,
}

impl Default for ThermalRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ThermalRegistry {
    /// Creates a new, empty thermal registry.
    pub const fn new() -> Self {
        Self {
            zones: [const { None }; MAX_ZONES],
            zone_count: 0,
            cooling: [const { None }; MAX_COOLING_DEVICES],
            cooling_count: 0,
        }
    }

    /// Registers a thermal zone.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a zone with the same id exists.
    pub fn register_zone(&mut self, zone: ThermalZone) -> Result<()> {
        for z in self.zones.iter().flatten() {
            if z.id == zone.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.zones {
            if slot.is_none() {
                *slot = Some(zone);
                self.zone_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters the thermal zone with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no zone with that id exists.
    pub fn unregister_zone(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.zones {
            let matches = slot.as_ref().is_some_and(|z| z.id == id);
            if matches {
                *slot = None;
                self.zone_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Registers a cooling device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id
    /// exists.
    pub fn register_cooling(&mut self, device: ThermalCoolingDevice) -> Result<()> {
        for c in self.cooling.iter().flatten() {
            if c.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.cooling {
            if slot.is_none() {
                *slot = Some(device);
                self.cooling_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Binds a cooling device to a thermal zone.
    ///
    /// Returns [`Error::NotFound`] if the zone or cooling device
    /// is not registered.
    pub fn bind_cooling(&mut self, zone_id: u32, cooling_id: u32) -> Result<()> {
        // Verify the cooling device exists.
        let exists = self.cooling.iter().flatten().any(|c| c.id == cooling_id);
        if !exists {
            return Err(Error::NotFound);
        }
        let zone = self.get_zone_mut(zone_id)?;
        zone.bind_cooling(cooling_id)
    }

    /// Updates the temperature reading for a thermal zone.
    ///
    /// Returns [`Error::NotFound`] if the zone is not registered,
    /// or [`Error::IoError`] if the zone is disabled.
    pub fn update_temperature(&mut self, zone_id: u32, temperature_mc: i32) -> Result<()> {
        let zone = self.get_zone_mut(zone_id)?;
        if !zone.enabled {
            return Err(Error::IoError);
        }
        zone.temperature_mc = temperature_mc;
        Ok(())
    }

    /// Checks all trip points for the given zone and returns
    /// indices of tripped points.
    ///
    /// Returns [`Error::NotFound`] if the zone is not registered.
    pub fn check_trips(&self, zone_id: u32, out: &mut [usize]) -> Result<usize> {
        let zone = self.get_zone(zone_id)?;
        Ok(zone.tripped_points(out))
    }

    /// Returns an immutable reference to the zone with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_zone(&self, id: u32) -> Result<&ThermalZone> {
        self.zones
            .iter()
            .flatten()
            .find(|z| z.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the zone with `id`.
    fn get_zone_mut(&mut self, id: u32) -> Result<&mut ThermalZone> {
        self.zones
            .iter_mut()
            .flatten()
            .find(|z| z.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns an immutable reference to the cooling device
    /// with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_cooling(&self, id: u32) -> Result<&ThermalCoolingDevice> {
        self.cooling
            .iter()
            .flatten()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered thermal zones.
    pub fn len(&self) -> usize {
        self.zone_count
    }

    /// Returns `true` if no thermal zones are registered.
    pub fn is_empty(&self) -> bool {
        self.zone_count == 0
    }
}
