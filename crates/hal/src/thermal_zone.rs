// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thermal zone management framework for the ONCRIX hardware abstraction layer.
//!
//! Provides thermal monitoring with temperature reading, trip points
//! (passive/active/hot/critical), cooling device binding, thermal governors
//! (step-wise/bang-bang/power-allocator), event generation, and hysteresis
//! support.
//!
//! # Architecture
//!
//! - **ThermalTripType** — classification of trip points
//! - **ThermalTripPoint** — temperature threshold with hysteresis
//! - **ThermalGovernorType** — thermal policy algorithm selection
//! - **ThermalGovernor** — governor state and policy evaluation
//! - **CoolingDeviceType** — classification of cooling devices
//! - **CoolingDevice** — a device that reduces thermal output
//! - **ThermalEvent** — notification of temperature threshold crossing
//! - **ThermalZone** — sensor zone with trip points and cooling bindings
//! - **ThermalZoneRegistry** — manages zones and cooling devices
//!
//! Reference: Linux `drivers/thermal/`, `include/linux/thermal.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of thermal zones in the registry.
const MAX_ZONES: usize = 16;

/// Maximum number of cooling devices in the registry.
const MAX_COOLING_DEVICES: usize = 32;

/// Maximum trip points per thermal zone.
const MAX_TRIP_POINTS: usize = 12;

/// Maximum cooling devices bound to a single zone.
const MAX_ZONE_BINDINGS: usize = 8;

/// Maximum pending thermal events.
const MAX_EVENTS: usize = 32;

/// Temperature value indicating sensor read failure (millicelsius).
const THERMAL_TEMP_INVALID: i32 = i32::MIN;

/// Absolute zero in millicelsius (-273150 mC).
const _THERMAL_ABSOLUTE_ZERO_MC: i32 = -273_150;

// ---------------------------------------------------------------------------
// ThermalTripType
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ThermalTripPoint
// ---------------------------------------------------------------------------

/// A temperature threshold that triggers a thermal policy action.
///
/// The trip point fires when the zone temperature reaches or exceeds
/// `temperature_mc`. When cooling brings the temperature below
/// `temperature_mc - hysteresis_mc`, the trip point is deactivated.
#[derive(Debug, Clone, Copy)]
pub struct ThermalTripPoint {
    /// Type of trip point.
    pub trip_type: ThermalTripType,
    /// Temperature threshold in millicelsius.
    pub temperature_mc: i32,
    /// Hysteresis in millicelsius applied when deactivating.
    pub hysteresis_mc: i32,
    /// Whether this trip point is currently active (temperature exceeded).
    pub active: bool,
}

/// Constant empty trip point for array initialisation.
const EMPTY_TRIP: ThermalTripPoint = ThermalTripPoint {
    trip_type: ThermalTripType::Active,
    temperature_mc: 0,
    hysteresis_mc: 0,
    active: false,
};

impl ThermalTripPoint {
    /// Creates a new trip point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `hysteresis_mc` is negative.
    pub fn new(
        trip_type: ThermalTripType,
        temperature_mc: i32,
        hysteresis_mc: i32,
    ) -> Result<Self> {
        if hysteresis_mc < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            trip_type,
            temperature_mc,
            hysteresis_mc,
            active: false,
        })
    }

    /// Returns the deactivation temperature (threshold minus hysteresis).
    pub fn deactivation_temp(&self) -> i32 {
        self.temperature_mc.saturating_sub(self.hysteresis_mc)
    }

    /// Evaluates this trip point against the current temperature.
    ///
    /// Returns `true` if the trip state changed (activated or deactivated).
    pub fn evaluate(&mut self, current_mc: i32) -> bool {
        let prev = self.active;
        if !self.active && current_mc >= self.temperature_mc {
            self.active = true;
        } else if self.active && current_mc < self.deactivation_temp() {
            self.active = false;
        }
        self.active != prev
    }
}

// ---------------------------------------------------------------------------
// ThermalGovernorType
// ---------------------------------------------------------------------------

/// Thermal policy algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThermalGovernorType {
    /// Incremental step-wise cooling adjustment (default).
    #[default]
    StepWise,
    /// On/off cooling control with hysteresis.
    BangBang,
    /// Power-budget-based cooling allocation.
    PowerAllocator,
    /// User-space driven thermal policy.
    UserSpace,
}

// ---------------------------------------------------------------------------
// ThermalGovernor
// ---------------------------------------------------------------------------

/// Thermal governor state and policy evaluation.
///
/// The governor determines how cooling devices should be adjusted
/// in response to temperature changes and trip point crossings.
#[derive(Debug, Clone, Copy)]
pub struct ThermalGovernor {
    /// Governor algorithm type.
    pub gov_type: ThermalGovernorType,
    /// Power budget in milliwatts (for PowerAllocator).
    pub power_budget_mw: u32,
    /// Step size for StepWise governor (cooling state increment).
    pub step_size: u32,
}

impl ThermalGovernor {
    /// Creates a new governor with the given type.
    pub fn new(gov_type: ThermalGovernorType) -> Self {
        Self {
            gov_type,
            power_budget_mw: 0,
            step_size: 1,
        }
    }

    /// Computes the desired cooling state for a device based on the
    /// current temperature and trip point state.
    ///
    /// Returns a cooling state value between 0 and `max_state`.
    pub fn compute_target(
        &self,
        current_mc: i32,
        trip_temp_mc: i32,
        current_state: u32,
        max_state: u32,
    ) -> u32 {
        match self.gov_type {
            ThermalGovernorType::StepWise => {
                if current_mc >= trip_temp_mc {
                    let new = current_state.saturating_add(self.step_size);
                    new.min(max_state)
                } else {
                    current_state.saturating_sub(self.step_size)
                }
            }
            ThermalGovernorType::BangBang => {
                if current_mc >= trip_temp_mc {
                    max_state
                } else {
                    0
                }
            }
            ThermalGovernorType::PowerAllocator => {
                // Proportional allocation based on temperature overshoot
                if trip_temp_mc == 0 || current_mc <= trip_temp_mc {
                    return 0;
                }
                let overshoot = (current_mc - trip_temp_mc) as u32;
                let range = trip_temp_mc.unsigned_abs().max(1);
                let ratio = (overshoot * max_state) / range;
                ratio.min(max_state)
            }
            ThermalGovernorType::UserSpace => {
                // No automatic adjustment; user-space controls cooling
                current_state
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CoolingDeviceType
// ---------------------------------------------------------------------------

/// Classification of a cooling device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoolingDeviceType {
    /// Fan-based active cooling.
    #[default]
    Fan,
    /// Processor frequency/voltage throttling.
    Processor,
    /// Memory bandwidth throttling.
    Memory,
    /// Power supply limiting.
    Power,
}

// ---------------------------------------------------------------------------
// CoolingDevice
// ---------------------------------------------------------------------------

/// A device capable of reducing thermal output.
#[derive(Debug, Clone, Copy)]
pub struct CoolingDevice {
    /// Unique cooling device identifier.
    pub id: u32,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Type of cooling mechanism.
    pub dev_type: CoolingDeviceType,
    /// Maximum cooling state (higher = more cooling).
    pub max_state: u32,
    /// Current cooling state.
    pub cur_state: u32,
    /// Whether this device is registered and operational.
    pub active: bool,
}

/// Constant empty cooling device for array initialisation.
const EMPTY_COOLING: CoolingDevice = CoolingDevice {
    id: 0,
    name: [0u8; 32],
    name_len: 0,
    dev_type: CoolingDeviceType::Fan,
    max_state: 0,
    cur_state: 0,
    active: false,
};

impl CoolingDevice {
    /// Creates a new cooling device.
    pub fn new(id: u32, name: &[u8], dev_type: CoolingDeviceType, max_state: u32) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            dev_type,
            max_state,
            cur_state: 0,
            active: true,
        }
    }

    /// Sets the current cooling state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `state` exceeds `max_state`.
    pub fn set_state(&mut self, state: u32) -> Result<()> {
        if state > self.max_state {
            return Err(Error::InvalidArgument);
        }
        self.cur_state = state;
        Ok(())
    }

    /// Returns the current cooling state as a percentage (0–100).
    pub fn state_percent(&self) -> u32 {
        if self.max_state == 0 {
            return 0;
        }
        (self.cur_state * 100) / self.max_state
    }
}

// ---------------------------------------------------------------------------
// CoolingBinding
// ---------------------------------------------------------------------------

/// A binding between a cooling device and a trip point within a zone.
#[derive(Debug, Clone, Copy)]
pub struct CoolingBinding {
    /// Cooling device identifier.
    pub cooling_id: u32,
    /// Trip point index within the zone.
    pub trip_index: usize,
    /// Minimum cooling state for this binding.
    pub lower: u32,
    /// Maximum cooling state for this binding.
    pub upper: u32,
}

/// Constant empty binding for array initialisation.
const EMPTY_BINDING: CoolingBinding = CoolingBinding {
    cooling_id: 0,
    trip_index: 0,
    lower: 0,
    upper: 0,
};

// ---------------------------------------------------------------------------
// ThermalEventType
// ---------------------------------------------------------------------------

/// Type of thermal event notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalEventType {
    /// Temperature crossed a trip point upward.
    TripCrossedUp,
    /// Temperature crossed a trip point downward (with hysteresis).
    TripCrossedDown,
    /// Critical temperature reached; system must shut down.
    CriticalTemperature,
    /// Hot temperature reached; corrective action needed.
    HotTemperature,
}

// ---------------------------------------------------------------------------
// ThermalEvent
// ---------------------------------------------------------------------------

/// A thermal event notification.
#[derive(Debug, Clone, Copy)]
pub struct ThermalEvent {
    /// Zone that generated the event.
    pub zone_id: u32,
    /// Type of thermal event.
    pub event_type: ThermalEventType,
    /// Trip point index (if applicable).
    pub trip_index: usize,
    /// Temperature at the time of the event (millicelsius).
    pub temperature_mc: i32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// Constant empty event for array initialisation.
const EMPTY_EVENT: ThermalEvent = ThermalEvent {
    zone_id: 0,
    event_type: ThermalEventType::TripCrossedUp,
    trip_index: 0,
    temperature_mc: 0,
    timestamp_ns: 0,
};

// ---------------------------------------------------------------------------
// ThermalZone
// ---------------------------------------------------------------------------

/// A thermal sensor zone with trip points, governor, and cooling bindings.
///
/// Represents a single thermal sensor with associated trip points and
/// bound cooling devices. The zone periodically reads its temperature
/// sensor, evaluates trip points, and invokes the governor to adjust
/// cooling device states.
pub struct ThermalZone {
    /// Unique zone identifier.
    pub id: u32,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Current temperature reading in millicelsius.
    pub temperature_mc: i32,
    /// Last valid temperature reading.
    pub last_temperature_mc: i32,
    /// Configured trip points.
    pub trips: [ThermalTripPoint; MAX_TRIP_POINTS],
    /// Number of active trip points.
    pub trip_count: usize,
    /// Thermal governor for this zone.
    pub governor: ThermalGovernor,
    /// Cooling device bindings.
    pub bindings: [CoolingBinding; MAX_ZONE_BINDINGS],
    /// Number of cooling bindings.
    pub binding_count: usize,
    /// Whether this zone is enabled and being monitored.
    pub enabled: bool,
    /// Polling interval in milliseconds (0 = event-driven only).
    pub polling_ms: u32,
    /// Whether the sensor has reported a valid temperature.
    pub sensor_valid: bool,
}

impl ThermalZone {
    /// Creates a new thermal zone.
    pub fn new(id: u32, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            temperature_mc: THERMAL_TEMP_INVALID,
            last_temperature_mc: THERMAL_TEMP_INVALID,
            trips: [EMPTY_TRIP; MAX_TRIP_POINTS],
            trip_count: 0,
            governor: ThermalGovernor::new(ThermalGovernorType::StepWise),
            bindings: [EMPTY_BINDING; MAX_ZONE_BINDINGS],
            binding_count: 0,
            enabled: true,
            polling_ms: 1000,
            sensor_valid: false,
        }
    }

    /// Adds a trip point to this zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all trip point slots are used.
    pub fn add_trip(&mut self, trip: ThermalTripPoint) -> Result<usize> {
        if self.trip_count >= MAX_TRIP_POINTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.trip_count;
        self.trips[idx] = trip;
        self.trip_count += 1;
        Ok(idx)
    }

    /// Removes a trip point by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn remove_trip(&mut self, index: usize) -> Result<()> {
        if index >= self.trip_count {
            return Err(Error::InvalidArgument);
        }
        // Shift remaining entries
        let remaining = self.trip_count - index - 1;
        for i in 0..remaining {
            self.trips[index + i] = self.trips[index + i + 1];
        }
        self.trip_count -= 1;
        Ok(())
    }

    /// Binds a cooling device to a trip point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all binding slots are used,
    /// [`Error::InvalidArgument`] if the trip index is out of range,
    /// or [`Error::AlreadyExists`] if the cooling device is already
    /// bound to this trip point.
    pub fn bind_cooling(
        &mut self,
        cooling_id: u32,
        trip_index: usize,
        lower: u32,
        upper: u32,
    ) -> Result<()> {
        if trip_index >= self.trip_count {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate
        for b in &self.bindings[..self.binding_count] {
            if b.cooling_id == cooling_id && b.trip_index == trip_index {
                return Err(Error::AlreadyExists);
            }
        }
        if self.binding_count >= MAX_ZONE_BINDINGS {
            return Err(Error::OutOfMemory);
        }
        self.bindings[self.binding_count] = CoolingBinding {
            cooling_id,
            trip_index,
            lower,
            upper,
        };
        self.binding_count += 1;
        Ok(())
    }

    /// Unbinds a cooling device from a trip point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the binding does not exist.
    pub fn unbind_cooling(&mut self, cooling_id: u32, trip_index: usize) -> Result<()> {
        let pos = self.bindings[..self.binding_count]
            .iter()
            .position(|b| b.cooling_id == cooling_id && b.trip_index == trip_index);
        match pos {
            Some(i) => {
                let remaining = self.binding_count - i - 1;
                for j in 0..remaining {
                    self.bindings[i + j] = self.bindings[i + j + 1];
                }
                self.binding_count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Updates the zone temperature and evaluates trip points.
    ///
    /// Returns the number of trip points whose state changed.
    pub fn update_temperature(&mut self, new_temp_mc: i32) -> usize {
        self.last_temperature_mc = self.temperature_mc;
        self.temperature_mc = new_temp_mc;
        self.sensor_valid = true;

        let mut changes = 0;
        for trip in &mut self.trips[..self.trip_count] {
            if trip.evaluate(new_temp_mc) {
                changes += 1;
            }
        }
        changes
    }

    /// Sets the governor type for this zone.
    pub fn set_governor(&mut self, gov_type: ThermalGovernorType) {
        self.governor = ThermalGovernor::new(gov_type);
    }

    /// Returns the indices of currently active (tripped) trip points.
    ///
    /// Writes indices into `out` and returns how many were written.
    pub fn active_trips(&self, out: &mut [usize]) -> usize {
        let mut written = 0;
        for (i, trip) in self.trips[..self.trip_count].iter().enumerate() {
            if written >= out.len() {
                break;
            }
            if trip.active {
                out[written] = i;
                written += 1;
            }
        }
        written
    }

    /// Returns the highest-priority active trip type, if any.
    ///
    /// Priority order: Critical > Hot > Passive > Active.
    pub fn highest_active_trip(&self) -> Option<ThermalTripType> {
        let mut highest: Option<ThermalTripType> = None;
        for trip in &self.trips[..self.trip_count] {
            if !trip.active {
                continue;
            }
            let priority = match trip.trip_type {
                ThermalTripType::Critical => 3,
                ThermalTripType::Hot => 2,
                ThermalTripType::Passive => 1,
                ThermalTripType::Active => 0,
            };
            let cur_priority = highest.map_or(-1, |t| match t {
                ThermalTripType::Critical => 3,
                ThermalTripType::Hot => 2,
                ThermalTripType::Passive => 1,
                ThermalTripType::Active => 0,
            });
            if priority > cur_priority {
                highest = Some(trip.trip_type);
            }
        }
        highest
    }
}

// ---------------------------------------------------------------------------
// ThermalZoneRegistry
// ---------------------------------------------------------------------------

/// Registry managing thermal zones, cooling devices, and events.
pub struct ThermalZoneRegistry {
    /// Registered thermal zones.
    zones: [Option<ThermalZone>; MAX_ZONES],
    /// Number of registered zones.
    zone_count: usize,
    /// Registered cooling devices.
    cooling: [CoolingDevice; MAX_COOLING_DEVICES],
    /// Number of registered cooling devices.
    cooling_count: usize,
    /// Pending thermal events (ring buffer).
    events: [ThermalEvent; MAX_EVENTS],
    /// Next write position in the event ring.
    event_head: usize,
    /// Number of pending events.
    event_count: usize,
}

impl ThermalZoneRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            zones: [const { None }; MAX_ZONES],
            zone_count: 0,
            cooling: [EMPTY_COOLING; MAX_COOLING_DEVICES],
            cooling_count: 0,
            events: [EMPTY_EVENT; MAX_EVENTS],
            event_head: 0,
            event_count: 0,
        }
    }

    /// Registers a thermal zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a zone with the same ID exists.
    pub fn register_zone(&mut self, zone: ThermalZone) -> Result<()> {
        for slot in self.zones.iter().flatten() {
            if slot.id == zone.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.zones.iter_mut() {
            if slot.is_none() {
                *slot = Some(zone);
                self.zone_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a thermal zone by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no zone with the given ID exists.
    pub fn unregister_zone(&mut self, zone_id: u32) -> Result<()> {
        for slot in self.zones.iter_mut() {
            let matches = slot.as_ref().is_some_and(|z| z.id == zone_id);
            if matches {
                *slot = None;
                self.zone_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a zone by ID.
    pub fn get_zone(&self, zone_id: u32) -> Result<&ThermalZone> {
        for slot in self.zones.iter().flatten() {
            if slot.id == zone_id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a zone by ID.
    pub fn get_zone_mut(&mut self, zone_id: u32) -> Result<&mut ThermalZone> {
        for slot in self.zones.iter_mut() {
            if let Some(z) = slot {
                if z.id == zone_id {
                    return Ok(z);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Registers a cooling device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same ID exists.
    pub fn register_cooling(&mut self, device: CoolingDevice) -> Result<()> {
        for d in &self.cooling[..self.cooling_count] {
            if d.id == device.id && d.active {
                return Err(Error::AlreadyExists);
            }
        }
        if self.cooling_count >= MAX_COOLING_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.cooling[self.cooling_count] = device;
        self.cooling_count += 1;
        Ok(())
    }

    /// Returns a reference to a cooling device by ID.
    pub fn get_cooling(&self, cooling_id: u32) -> Result<&CoolingDevice> {
        for d in &self.cooling[..self.cooling_count] {
            if d.id == cooling_id && d.active {
                return Ok(d);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a cooling device by ID.
    pub fn get_cooling_mut(&mut self, cooling_id: u32) -> Result<&mut CoolingDevice> {
        for d in &mut self.cooling[..self.cooling_count] {
            if d.id == cooling_id && d.active {
                return Ok(d);
            }
        }
        Err(Error::NotFound)
    }

    /// Pushes a thermal event into the event ring buffer.
    pub fn push_event(&mut self, event: ThermalEvent) {
        self.events[self.event_head] = event;
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        if self.event_count < MAX_EVENTS {
            self.event_count += 1;
        }
    }

    /// Pops the oldest thermal event from the ring buffer.
    ///
    /// Returns `None` if no events are pending.
    pub fn pop_event(&mut self) -> Option<ThermalEvent> {
        if self.event_count == 0 {
            return None;
        }
        let tail = if self.event_head >= self.event_count {
            self.event_head - self.event_count
        } else {
            MAX_EVENTS - (self.event_count - self.event_head)
        };
        self.event_count -= 1;
        Some(self.events[tail])
    }

    /// Returns the number of registered zones.
    pub fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Returns the number of registered cooling devices.
    pub fn cooling_count(&self) -> usize {
        self.cooling_count
    }

    /// Returns the number of pending events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Returns `true` if no zones are registered.
    pub fn is_empty(&self) -> bool {
        self.zone_count == 0
    }
}
