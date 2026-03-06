// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thermal cooling device interface.
//!
//! Manages thermal zone cooling devices such as CPU frequency throttling
//! and fan speed control for temperature management.  The thermal
//! framework monitors zone temperatures and activates cooling devices
//! when trip points are crossed.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ Thermal Zone                                                 │
//! │   temperature sensor  →  current_temp                        │
//! │   trip points: [passive_trip, active_trip, critical_trip]     │
//! │                                                              │
//! │   ┌────────────────────────────────────────────────────────┐ │
//! │   │ Cooling Policy                                         │ │
//! │   │   step_wise / bang_bang / power_allocator               │ │
//! │   └─────────────┬──────────────────────────────────────────┘ │
//! │                 │                                            │
//! │                 ▼                                            │
//! │   ┌────────────────────────────┐  ┌───────────────────────┐ │
//! │   │ CoolingDevice (CPU freq)   │  │ CoolingDevice (Fan)   │ │
//! │   │  cur_state / max_state     │  │  cur_state / max_state│ │
//! │   │  throttle CPU frequency    │  │  control fan speed    │ │
//! │   └────────────────────────────┘  └───────────────────────┘ │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Trip points
//!
//! - **Passive**: Reduce performance (CPU throttle).
//! - **Active**: Engage active cooling (fans).
//! - **Hot**: Warning threshold — log alert.
//! - **Critical**: Emergency shutdown to prevent hardware damage.
//!
//! # Cooling states
//!
//! Each cooling device has a `cur_state` (0 = no cooling) up to
//! `max_state` (maximum cooling effort).  For CPU freq, higher state
//! means lower frequency.  For fans, higher state means faster RPM.
//!
//! # Reference
//!
//! Linux `drivers/thermal/`, `include/linux/thermal.h`,
//! `Documentation/driver-api/thermal/`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of cooling devices in the system.
const MAX_COOLING_DEVICES: usize = 32;

/// Maximum number of thermal zones.
const MAX_THERMAL_ZONES: usize = 16;

/// Maximum number of trip points per zone.
const MAX_TRIPS_PER_ZONE: usize = 8;

/// Maximum number of cooling devices bound to a single zone.
const MAX_BINDINGS_PER_ZONE: usize = 8;

/// Maximum device name length.
const MAX_NAME_LEN: usize = 64;

/// Temperature value indicating "not available" (millidegrees Celsius).
pub const THERMAL_TEMP_INVALID: i32 = i32::MIN;

/// Default polling interval in milliseconds.
pub const DEFAULT_POLL_MS: u32 = 1000;

// ── CoolingType ───────────────────────────────────────────────────────────────

/// Type of cooling mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoolingType {
    /// CPU frequency throttling (DVFS).
    CpuFreq,
    /// Fan speed control.
    Fan,
    /// Power capping (Intel RAPL / platform).
    PowerCap,
    /// Device clock throttling (GPU, etc.).
    DevFreq,
    /// Passive cooling (no active actuator, just performance reduction).
    Passive,
}

// ── TripType ──────────────────────────────────────────────────────────────────

/// Type of a thermal trip point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripType {
    /// Active cooling trip (e.g., turn on fan).
    Active,
    /// Passive cooling trip (e.g., CPU throttle).
    Passive,
    /// Hot warning (log, but no emergency).
    Hot,
    /// Critical — initiate orderly shutdown.
    Critical,
}

// ── ThermalTrip ───────────────────────────────────────────────────────────────

/// A thermal trip point definition.
///
/// When the zone temperature crosses `temp_mc`, the thermal framework
/// activates cooling devices bound to this trip.
#[derive(Debug, Clone, Copy)]
pub struct ThermalTrip {
    /// Trip point type.
    pub trip_type: TripType,
    /// Temperature threshold in millidegrees Celsius.
    pub temp_mc: i32,
    /// Hysteresis in millidegrees Celsius (must cool below
    /// `temp_mc - hysteresis` before deactivating).
    pub hysteresis: i32,
    /// Whether this trip point is currently active (temperature exceeded).
    pub active: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl ThermalTrip {
    /// Create an empty, unused trip point.
    const fn empty() -> Self {
        Self {
            trip_type: TripType::Active,
            temp_mc: 0,
            hysteresis: 0,
            active: false,
            in_use: false,
        }
    }

    /// Create a new trip point.
    pub const fn new(trip_type: TripType, temp_mc: i32, hysteresis: i32) -> Self {
        Self {
            trip_type,
            temp_mc,
            hysteresis,
            active: false,
            in_use: true,
        }
    }

    /// Check whether the temperature has crossed this trip upward.
    pub fn check_rising(&mut self, temp_mc: i32) -> bool {
        if !self.in_use {
            return false;
        }
        if !self.active && temp_mc >= self.temp_mc {
            self.active = true;
            return true;
        }
        false
    }

    /// Check whether the temperature has fallen below the hysteresis band.
    pub fn check_falling(&mut self, temp_mc: i32) -> bool {
        if !self.in_use {
            return false;
        }
        if self.active && temp_mc < (self.temp_mc - self.hysteresis) {
            self.active = false;
            return true;
        }
        false
    }
}

// ── CoolingState ──────────────────────────────────────────────────────────────

/// Represents the operating state of a cooling device.
#[derive(Debug, Clone, Copy)]
pub struct CoolingState {
    /// Current cooling state (0 = no cooling).
    pub cur_state: u32,
    /// Maximum cooling state.
    pub max_state: u32,
    /// Requested state (may differ from `cur_state` during transitions).
    pub requested: u32,
    /// Whether the device is enabled.
    pub enabled: bool,
}

impl CoolingState {
    /// Create a new cooling state.
    pub const fn new(max_state: u32) -> Self {
        Self {
            cur_state: 0,
            max_state,
            requested: 0,
            enabled: true,
        }
    }

    /// Set the requested cooling state, clamping to max.
    pub fn set_requested(&mut self, state: u32) {
        self.requested = state.min(self.max_state);
    }

    /// Apply the requested state as the current state.
    pub fn apply(&mut self) {
        if self.enabled {
            self.cur_state = self.requested;
        }
    }

    /// Return the cooling effort as a percentage (0..100).
    pub fn percent(&self) -> u8 {
        if self.max_state == 0 {
            return 0;
        }
        ((self.cur_state as u64 * 100) / self.max_state as u64).min(100) as u8
    }
}

// ── CoolingDevice ─────────────────────────────────────────────────────────────

/// A thermal cooling device.
///
/// Each device has a type, a name, and a state range.  The thermal
/// framework adjusts `cur_state` based on the zone temperature and
/// the cooling policy.
pub struct CoolingDevice {
    /// Unique device ID.
    pub id: u32,
    /// Device name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Cooling mechanism type.
    pub cooling_type: CoolingType,
    /// Current operating state.
    pub state: CoolingState,
    /// Thermal zone this device is bound to (index, or u32::MAX if unbound).
    pub bound_zone: u32,
    /// Which trip index within the zone this device is bound to.
    pub bound_trip: u32,
    /// Weight for power-allocator governor (0..100).
    pub weight: u32,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl CoolingDevice {
    /// Create an empty, unused cooling device slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            cooling_type: CoolingType::Passive,
            state: CoolingState::new(0),
            bound_zone: u32::MAX,
            bound_trip: u32::MAX,
            weight: 0,
            in_use: false,
        }
    }

    /// Return the device name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the device name.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Increase the cooling state by one step.
    pub fn step_up(&mut self) {
        let new_state = self.state.cur_state.saturating_add(1);
        self.state.set_requested(new_state);
        self.state.apply();
    }

    /// Decrease the cooling state by one step.
    pub fn step_down(&mut self) {
        let new_state = self.state.cur_state.saturating_sub(1);
        self.state.set_requested(new_state);
        self.state.apply();
    }

    /// Set the cooling state directly.
    pub fn set_state(&mut self, state: u32) -> Result<()> {
        if state > self.state.max_state {
            return Err(Error::InvalidArgument);
        }
        self.state.set_requested(state);
        self.state.apply();
        Ok(())
    }
}

impl core::fmt::Debug for CoolingDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CoolingDevice")
            .field("id", &self.id)
            .field("type", &self.cooling_type)
            .field("cur_state", &self.state.cur_state)
            .field("max_state", &self.state.max_state)
            .finish()
    }
}

// ── ThermalZone ───────────────────────────────────────────────────────────────

/// A thermal zone with trip points and bound cooling devices.
struct ThermalZone {
    /// Zone ID.
    id: u32,
    /// Zone name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Current temperature in millidegrees Celsius.
    temp_mc: i32,
    /// Trip points.
    trips: [ThermalTrip; MAX_TRIPS_PER_ZONE],
    /// Number of active trip points.
    trip_count: usize,
    /// Indices of cooling devices bound to this zone.
    bindings: [u32; MAX_BINDINGS_PER_ZONE],
    /// Number of bindings.
    binding_count: usize,
    /// Polling interval in milliseconds.
    poll_interval_ms: u32,
    /// Whether this zone slot is in use.
    in_use: bool,
}

impl ThermalZone {
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            temp_mc: THERMAL_TEMP_INVALID,
            trips: [const { ThermalTrip::empty() }; MAX_TRIPS_PER_ZONE],
            trip_count: 0,
            bindings: [u32::MAX; MAX_BINDINGS_PER_ZONE],
            binding_count: 0,
            poll_interval_ms: DEFAULT_POLL_MS,
            in_use: false,
        }
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── ThermalStats ──────────────────────────────────────────────────────────────

/// Statistics for the thermal subsystem.
#[derive(Debug, Clone, Copy)]
pub struct ThermalStats {
    /// Total temperature readings taken.
    pub readings: u64,
    /// Total trip point crossings (rising).
    pub trip_crossings: u64,
    /// Total cooling state changes.
    pub state_changes: u64,
    /// Number of critical events.
    pub critical_events: u64,
    /// Peak temperature observed (millidegrees C).
    pub peak_temp_mc: i32,
}

impl ThermalStats {
    const fn new() -> Self {
        Self {
            readings: 0,
            trip_crossings: 0,
            state_changes: 0,
            critical_events: 0,
            peak_temp_mc: THERMAL_TEMP_INVALID,
        }
    }
}

// ── ThermalManager ────────────────────────────────────────────────────────────

/// The thermal cooling device manager.
///
/// Manages thermal zones, trip points, and cooling devices.  Processes
/// temperature updates and adjusts cooling states accordingly.
pub struct ThermalManager {
    /// Cooling devices.
    devices: [CoolingDevice; MAX_COOLING_DEVICES],
    /// Next device ID.
    next_device_id: u32,
    /// Thermal zones.
    zones: [ThermalZone; MAX_THERMAL_ZONES],
    /// Next zone ID.
    next_zone_id: u32,
    /// Statistics.
    stats: ThermalStats,
}

impl ThermalManager {
    /// Create a new, empty thermal manager.
    pub fn new() -> Self {
        Self {
            devices: [const { CoolingDevice::empty() }; MAX_COOLING_DEVICES],
            next_device_id: 1,
            zones: [const { ThermalZone::empty() }; MAX_THERMAL_ZONES],
            next_zone_id: 1,
            stats: ThermalStats::new(),
        }
    }

    // ── Cooling device management ─────────────────────────────────────────

    /// Register a new cooling device.
    ///
    /// Returns the device ID.
    pub fn register_device(
        &mut self,
        name: &[u8],
        cooling_type: CoolingType,
        max_state: u32,
    ) -> Result<u32> {
        let (_, slot) = self
            .devices
            .iter_mut()
            .enumerate()
            .find(|(_, d)| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_device_id;
        self.next_device_id += 1;

        slot.id = id;
        slot.set_name(name)?;
        slot.cooling_type = cooling_type;
        slot.state = CoolingState::new(max_state);
        slot.bound_zone = u32::MAX;
        slot.bound_trip = u32::MAX;
        slot.weight = 0;
        slot.in_use = true;

        Ok(id)
    }

    /// Unregister a cooling device.
    pub fn unregister_device(&mut self, device_id: u32) -> Result<()> {
        let dev = self
            .devices
            .iter_mut()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)?;

        // Unbind from any zone.
        let zone_id = dev.bound_zone;
        dev.in_use = false;

        if zone_id != u32::MAX {
            if let Some(zone) = self.zones.iter_mut().find(|z| z.in_use && z.id == zone_id) {
                if let Some(pos) = zone.bindings[..zone.binding_count]
                    .iter()
                    .position(|&b| b == device_id)
                {
                    zone.binding_count -= 1;
                    zone.bindings[pos] = zone.bindings[zone.binding_count];
                    zone.bindings[zone.binding_count] = u32::MAX;
                }
            }
        }

        Ok(())
    }

    /// Get a reference to a cooling device by ID.
    pub fn get_device(&self, device_id: u32) -> Result<&CoolingDevice> {
        self.devices
            .iter()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a cooling device by ID.
    pub fn get_device_mut(&mut self, device_id: u32) -> Result<&mut CoolingDevice> {
        self.devices
            .iter_mut()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)
    }

    // ── Thermal zone management ───────────────────────────────────────────

    /// Register a new thermal zone.
    ///
    /// Returns the zone ID.
    pub fn register_zone(&mut self, name: &[u8], poll_interval_ms: u32) -> Result<u32> {
        let slot = self
            .zones
            .iter_mut()
            .find(|z| !z.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_zone_id;
        self.next_zone_id += 1;

        slot.id = id;
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.temp_mc = THERMAL_TEMP_INVALID;
        slot.trip_count = 0;
        slot.binding_count = 0;
        slot.poll_interval_ms = if poll_interval_ms == 0 {
            DEFAULT_POLL_MS
        } else {
            poll_interval_ms
        };
        slot.in_use = true;

        Ok(id)
    }

    /// Add a trip point to a thermal zone.
    pub fn add_trip(
        &mut self,
        zone_id: u32,
        trip_type: TripType,
        temp_mc: i32,
        hysteresis: i32,
    ) -> Result<usize> {
        let zone = self
            .zones
            .iter_mut()
            .find(|z| z.in_use && z.id == zone_id)
            .ok_or(Error::NotFound)?;

        if zone.trip_count >= MAX_TRIPS_PER_ZONE {
            return Err(Error::OutOfMemory);
        }

        let idx = zone.trip_count;
        zone.trips[idx] = ThermalTrip::new(trip_type, temp_mc, hysteresis);
        zone.trip_count += 1;
        Ok(idx)
    }

    /// Bind a cooling device to a thermal zone and trip point.
    pub fn bind_device(
        &mut self,
        zone_id: u32,
        device_id: u32,
        trip_idx: u32,
        weight: u32,
    ) -> Result<()> {
        // Validate device.
        let dev = self
            .devices
            .iter_mut()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)?;

        dev.bound_zone = zone_id;
        dev.bound_trip = trip_idx;
        dev.weight = weight;

        // Add binding to zone.
        let zone = self
            .zones
            .iter_mut()
            .find(|z| z.in_use && z.id == zone_id)
            .ok_or(Error::NotFound)?;

        if zone.binding_count >= MAX_BINDINGS_PER_ZONE {
            return Err(Error::OutOfMemory);
        }

        zone.bindings[zone.binding_count] = device_id;
        zone.binding_count += 1;
        Ok(())
    }

    // ── Temperature update and policy ─────────────────────────────────────

    /// Update the temperature reading for a zone and evaluate trip points.
    ///
    /// Returns the number of trip crossings detected.
    pub fn update_temperature(&mut self, zone_id: u32, temp_mc: i32) -> Result<u32> {
        self.stats.readings += 1;
        if temp_mc > self.stats.peak_temp_mc || self.stats.peak_temp_mc == THERMAL_TEMP_INVALID {
            self.stats.peak_temp_mc = temp_mc;
        }

        let zone = self
            .zones
            .iter_mut()
            .find(|z| z.in_use && z.id == zone_id)
            .ok_or(Error::NotFound)?;

        zone.temp_mc = temp_mc;
        let mut crossings = 0u32;

        // Evaluate trip points.
        for i in 0..zone.trip_count {
            let trip = &mut zone.trips[i];
            if trip.check_rising(temp_mc) {
                crossings += 1;
                if trip.trip_type == TripType::Critical {
                    self.stats.critical_events += 1;
                }
            } else if trip.check_falling(temp_mc) {
                crossings += 1;
            }
        }

        self.stats.trip_crossings += crossings as u64;
        Ok(crossings)
    }

    /// Apply step-wise cooling policy for a zone.
    ///
    /// For each active trip, increase the cooling state of bound devices
    /// by one step.  For each inactive trip, decrease by one step.
    pub fn apply_stepwise_policy(&mut self, zone_id: u32) -> Result<u32> {
        // Gather trip states and bindings.
        let zone = self
            .zones
            .iter()
            .find(|z| z.in_use && z.id == zone_id)
            .ok_or(Error::NotFound)?;

        let mut adjustments = [(0u32, false); MAX_BINDINGS_PER_ZONE];
        let binding_count = zone.binding_count;

        for bi in 0..binding_count {
            let device_id = zone.bindings[bi];
            // Find the trip this device is bound to.
            let dev_trip = self
                .devices
                .iter()
                .find(|d| d.in_use && d.id == device_id)
                .map(|d| d.bound_trip)
                .unwrap_or(u32::MAX);

            if (dev_trip as usize) < zone.trip_count {
                adjustments[bi] = (device_id, zone.trips[dev_trip as usize].active);
            }
        }

        let mut changes = 0u32;
        for &(device_id, trip_active) in &adjustments[..binding_count] {
            if device_id == 0 {
                continue;
            }
            if let Some(dev) = self
                .devices
                .iter_mut()
                .find(|d| d.in_use && d.id == device_id)
            {
                let old_state = dev.state.cur_state;
                if trip_active {
                    dev.step_up();
                } else {
                    dev.step_down();
                }
                if dev.state.cur_state != old_state {
                    changes += 1;
                }
            }
        }

        self.stats.state_changes += changes as u64;
        Ok(changes)
    }

    // ── Query helpers ─────────────────────────────────────────────────────

    /// Get the current temperature of a zone.
    pub fn zone_temperature(&self, zone_id: u32) -> Result<i32> {
        let zone = self
            .zones
            .iter()
            .find(|z| z.in_use && z.id == zone_id)
            .ok_or(Error::NotFound)?;
        Ok(zone.temp_mc)
    }

    /// Get the zone name as a byte slice.
    pub fn zone_name(&self, zone_id: u32) -> Result<&[u8]> {
        let zone = self
            .zones
            .iter()
            .find(|z| z.in_use && z.id == zone_id)
            .ok_or(Error::NotFound)?;
        Ok(zone.name_bytes())
    }

    /// Count active cooling devices.
    pub fn active_device_count(&self) -> usize {
        self.devices.iter().filter(|d| d.in_use).count()
    }

    /// Count active thermal zones.
    pub fn active_zone_count(&self) -> usize {
        self.zones.iter().filter(|z| z.in_use).count()
    }

    /// Return thermal statistics.
    pub fn stats(&self) -> ThermalStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = ThermalStats::new();
    }
}

impl Default for ThermalManager {
    fn default() -> Self {
        Self::new()
    }
}
