// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thermal zone management — temperature monitoring and throttling.
//!
//! Manages thermal sensors and cooling devices to prevent hardware
//! damage from overheating.  Each thermal zone has trip points that
//! trigger throttling or shutdown actions.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   ThermalSubsystem                           │
//! │                                                              │
//! │  ThermalZone[0..MAX_ZONES]                                   │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  zone_id: u16                                          │  │
//! │  │  temp_mc: i32       (millidegrees Celsius)             │  │
//! │  │  trips: [TripPoint; MAX_TRIPS_PER_ZONE]                │  │
//! │  │  trip_count: usize                                     │  │
//! │  │  policy: ThermalPolicy                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  CoolingDevice[0..MAX_COOLING_DEVICES]                       │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  device_type: CoolingType                              │  │
//! │  │  cur_state: u32                                        │  │
//! │  │  max_state: u32                                        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `drivers/thermal/`, `include/linux/thermal.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum thermal zones.
const MAX_ZONES: usize = 32;

/// Maximum trip points per zone.
const MAX_TRIPS_PER_ZONE: usize = 8;

/// Maximum cooling devices.
const MAX_COOLING_DEVICES: usize = 32;

/// Temperature indicating sensor failure.
const _TEMP_INVALID: i32 = -274_000;

// ══════════════════════════════════════════════════════════════
// TripType
// ══════════════════════════════════════════════════════════════

/// Type of thermal trip point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TripType {
    /// Active cooling (fan speed increase).
    Active = 0,
    /// Passive cooling (CPU/GPU frequency throttling).
    Passive = 1,
    /// Hot threshold (aggressive throttling).
    Hot = 2,
    /// Critical threshold (emergency shutdown).
    Critical = 3,
}

impl TripType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::Hot => "hot",
            Self::Critical => "critical",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ThermalPolicy
// ══════════════════════════════════════════════════════════════

/// Thermal governor policy for a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThermalPolicy {
    /// Step-wise governor (default).
    StepWise = 0,
    /// Fair-share governor.
    FairShare = 1,
    /// Power-allocator governor.
    PowerAllocator = 2,
    /// User-space controlled.
    UserSpace = 3,
}

// ══════════════════════════════════════════════════════════════
// CoolingType
// ══════════════════════════════════════════════════════════════

/// Type of cooling device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoolingType {
    /// Processor frequency scaling.
    CpuFreq = 0,
    /// Fan.
    Fan = 1,
    /// GPU throttling.
    Gpu = 2,
    /// Generic cooling device.
    Generic = 3,
}

// ══════════════════════════════════════════════════════════════
// TripPoint
// ══════════════════════════════════════════════════════════════

/// A thermal trip point.
#[derive(Debug, Clone, Copy)]
pub struct TripPoint {
    /// Trip type.
    pub trip_type: TripType,
    /// Temperature threshold in millidegrees Celsius.
    pub temp_mc: i32,
    /// Hysteresis in millidegrees Celsius.
    pub hysteresis_mc: i32,
    /// Whether this trip point is active.
    pub active: bool,
    /// Whether the trip has been triggered.
    pub triggered: bool,
}

impl TripPoint {
    /// Create an inactive trip point.
    const fn empty() -> Self {
        Self {
            trip_type: TripType::Active,
            temp_mc: 0,
            hysteresis_mc: 0,
            active: false,
            triggered: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ThermalZone
// ══════════════════════════════════════════════════════════════

/// A thermal zone with sensor and trip points.
#[derive(Debug, Clone, Copy)]
pub struct ThermalZone {
    /// Zone identifier.
    pub zone_id: u16,
    /// Current temperature in millidegrees Celsius.
    pub temp_mc: i32,
    /// Last temperature reading.
    pub last_temp_mc: i32,
    /// Trip points.
    pub trips: [TripPoint; MAX_TRIPS_PER_ZONE],
    /// Number of active trip points.
    pub trip_count: usize,
    /// Thermal governor policy.
    pub policy: ThermalPolicy,
    /// Whether the zone is registered.
    pub registered: bool,
    /// Polling interval in milliseconds (0 = event-driven).
    pub polling_interval_ms: u32,
}

impl ThermalZone {
    /// Create an empty zone.
    const fn empty() -> Self {
        Self {
            zone_id: 0,
            temp_mc: 0,
            last_temp_mc: 0,
            trips: [const { TripPoint::empty() }; MAX_TRIPS_PER_ZONE],
            trip_count: 0,
            policy: ThermalPolicy::StepWise,
            registered: false,
            polling_interval_ms: 1000,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CoolingDevice
// ══════════════════════════════════════════════════════════════

/// A cooling device that can reduce temperature.
#[derive(Debug, Clone, Copy)]
pub struct CoolingDevice {
    /// Cooling device type.
    pub device_type: CoolingType,
    /// Current cooling state (0 = no cooling).
    pub cur_state: u32,
    /// Maximum cooling state.
    pub max_state: u32,
    /// Whether the device is registered.
    pub registered: bool,
    /// Bound thermal zone ID (0 = unbound).
    pub bound_zone_id: u16,
}

impl CoolingDevice {
    const fn empty() -> Self {
        Self {
            device_type: CoolingType::Generic,
            cur_state: 0,
            max_state: 0,
            registered: false,
            bound_zone_id: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ThermalStats
// ══════════════════════════════════════════════════════════════

/// Thermal subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct ThermalStats {
    /// Total temperature updates.
    pub total_updates: u64,
    /// Total trip point triggers.
    pub total_trips_triggered: u64,
    /// Total cooling state changes.
    pub total_cooling_changes: u64,
    /// Maximum temperature observed (millidegrees Celsius).
    pub max_temp_mc: i32,
}

impl ThermalStats {
    const fn new() -> Self {
        Self {
            total_updates: 0,
            total_trips_triggered: 0,
            total_cooling_changes: 0,
            max_temp_mc: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ThermalSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level thermal management subsystem.
pub struct ThermalSubsystem {
    /// Thermal zones.
    zones: [ThermalZone; MAX_ZONES],
    /// Cooling devices.
    cooling: [CoolingDevice; MAX_COOLING_DEVICES],
    /// Statistics.
    stats: ThermalStats,
    /// Next zone ID.
    next_zone_id: u16,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for ThermalSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ThermalSubsystem {
    /// Create a new thermal subsystem.
    pub const fn new() -> Self {
        Self {
            zones: [const { ThermalZone::empty() }; MAX_ZONES],
            cooling: [const { CoolingDevice::empty() }; MAX_COOLING_DEVICES],
            stats: ThermalStats::new(),
            next_zone_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Zone management ──────────────────────────────────────

    /// Register a new thermal zone.
    ///
    /// Returns the zone slot index.
    pub fn register_zone(&mut self, policy: ThermalPolicy) -> Result<usize> {
        let slot = self
            .zones
            .iter()
            .position(|z| !z.registered)
            .ok_or(Error::OutOfMemory)?;

        let zone_id = self.next_zone_id;
        self.next_zone_id += 1;

        self.zones[slot] = ThermalZone::empty();
        self.zones[slot].zone_id = zone_id;
        self.zones[slot].policy = policy;
        self.zones[slot].registered = true;
        Ok(slot)
    }

    /// Add a trip point to a zone.
    pub fn add_trip(
        &mut self,
        slot: usize,
        trip_type: TripType,
        temp_mc: i32,
        hysteresis_mc: i32,
    ) -> Result<()> {
        if slot >= MAX_ZONES || !self.zones[slot].registered {
            return Err(Error::InvalidArgument);
        }
        let idx = self.zones[slot].trip_count;
        if idx >= MAX_TRIPS_PER_ZONE {
            return Err(Error::OutOfMemory);
        }

        self.zones[slot].trips[idx] = TripPoint {
            trip_type,
            temp_mc,
            hysteresis_mc,
            active: true,
            triggered: false,
        };
        self.zones[slot].trip_count += 1;
        Ok(())
    }

    /// Update the temperature of a thermal zone.
    ///
    /// Returns trip points that were newly triggered.
    pub fn update_temp(&mut self, slot: usize, temp_mc: i32) -> Result<usize> {
        if slot >= MAX_ZONES || !self.zones[slot].registered {
            return Err(Error::InvalidArgument);
        }

        self.zones[slot].last_temp_mc = self.zones[slot].temp_mc;
        self.zones[slot].temp_mc = temp_mc;
        self.stats.total_updates += 1;

        if temp_mc > self.stats.max_temp_mc {
            self.stats.max_temp_mc = temp_mc;
        }

        // Check trip points.
        let mut newly_triggered = 0usize;
        let trip_count = self.zones[slot].trip_count;
        for i in 0..trip_count {
            let trip = &self.zones[slot].trips[i];
            if !trip.active {
                continue;
            }
            let was_triggered = trip.triggered;
            if temp_mc >= trip.temp_mc && !was_triggered {
                self.zones[slot].trips[i].triggered = true;
                newly_triggered += 1;
                self.stats.total_trips_triggered += 1;
            } else if was_triggered && temp_mc < (trip.temp_mc - trip.hysteresis_mc) {
                self.zones[slot].trips[i].triggered = false;
            }
        }

        Ok(newly_triggered)
    }

    // ── Cooling device management ────────────────────────────

    /// Register a cooling device.
    pub fn register_cooling(&mut self, device_type: CoolingType, max_state: u32) -> Result<usize> {
        let slot = self
            .cooling
            .iter()
            .position(|c| !c.registered)
            .ok_or(Error::OutOfMemory)?;

        self.cooling[slot] = CoolingDevice {
            device_type,
            cur_state: 0,
            max_state,
            registered: true,
            bound_zone_id: 0,
        };
        Ok(slot)
    }

    /// Set the cooling state of a device.
    pub fn set_cooling_state(&mut self, slot: usize, state: u32) -> Result<()> {
        if slot >= MAX_COOLING_DEVICES || !self.cooling[slot].registered {
            return Err(Error::InvalidArgument);
        }
        if state > self.cooling[slot].max_state {
            return Err(Error::InvalidArgument);
        }
        self.cooling[slot].cur_state = state;
        self.stats.total_cooling_changes += 1;
        Ok(())
    }

    /// Bind a cooling device to a thermal zone.
    pub fn bind_cooling(&mut self, cooling_slot: usize, zone_slot: usize) -> Result<()> {
        if cooling_slot >= MAX_COOLING_DEVICES || !self.cooling[cooling_slot].registered {
            return Err(Error::InvalidArgument);
        }
        if zone_slot >= MAX_ZONES || !self.zones[zone_slot].registered {
            return Err(Error::InvalidArgument);
        }
        self.cooling[cooling_slot].bound_zone_id = self.zones[zone_slot].zone_id;
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return a thermal zone.
    pub fn zone(&self, slot: usize) -> Result<&ThermalZone> {
        if slot >= MAX_ZONES || !self.zones[slot].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.zones[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> ThermalStats {
        self.stats
    }

    /// Return the number of registered zones.
    pub fn zone_count(&self) -> usize {
        self.zones.iter().filter(|z| z.registered).count()
    }

    /// Return the number of registered cooling devices.
    pub fn cooling_count(&self) -> usize {
        self.cooling.iter().filter(|c| c.registered).count()
    }
}
