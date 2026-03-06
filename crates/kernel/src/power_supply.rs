// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power supply subsystem — battery and AC adapter management.
//!
//! Provides a unified interface for monitoring and managing power
//! sources: batteries, AC adapters, USB power delivery, and
//! uninterruptible power supplies.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  PowerSupplySubsystem                        │
//! │                                                              │
//! │  PowerSource[0..MAX_SOURCES]  (registered power sources)     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  source_type: PowerSourceType                          │  │
//! │  │  status: PowerStatus                                   │  │
//! │  │  capacity_pct: u8                                      │  │
//! │  │  voltage_uv: u32                                       │  │
//! │  │  current_ua: i32                                       │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `drivers/power/supply/`, `include/linux/power_supply.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered power sources.
const MAX_SOURCES: usize = 16;

/// Maximum name length for a power source.
const MAX_NAME_LEN: usize = 32;

/// Low battery threshold percentage.
const LOW_BATTERY_THRESHOLD: u8 = 15;

/// Critical battery threshold percentage.
const CRITICAL_BATTERY_THRESHOLD: u8 = 5;

// ══════════════════════════════════════════════════════════════
// PowerSourceType
// ══════════════════════════════════════════════════════════════

/// Type of power source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerSourceType {
    /// Battery (rechargeable).
    Battery = 0,
    /// AC mains adapter.
    Mains = 1,
    /// USB power delivery.
    Usb = 2,
    /// Uninterruptible power supply (UPS).
    Ups = 3,
}

impl PowerSourceType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Battery => "battery",
            Self::Mains => "mains",
            Self::Usb => "usb",
            Self::Ups => "ups",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PowerStatus
// ══════════════════════════════════════════════════════════════

/// Status of a power source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerStatus {
    /// Unknown status.
    Unknown = 0,
    /// Charging.
    Charging = 1,
    /// Discharging.
    Discharging = 2,
    /// Not charging (plugged in but full).
    NotCharging = 3,
    /// Fully charged.
    Full = 4,
    /// Offline / not present.
    Offline = 5,
}

impl PowerStatus {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Charging => "charging",
            Self::Discharging => "discharging",
            Self::NotCharging => "not_charging",
            Self::Full => "full",
            Self::Offline => "offline",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PowerHealth
// ══════════════════════════════════════════════════════════════

/// Health state of a battery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerHealth {
    /// Good condition.
    Good = 0,
    /// Overheat detected.
    Overheat = 1,
    /// Dead / end of life.
    Dead = 2,
    /// Over voltage.
    OverVoltage = 3,
    /// Cold temperature.
    Cold = 4,
    /// Unknown.
    Unknown = 5,
}

// ══════════════════════════════════════════════════════════════
// PowerSource
// ══════════════════════════════════════════════════════════════

/// A registered power source.
#[derive(Debug, Clone, Copy)]
pub struct PowerSource {
    /// Name of the power source.
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    pub name_len: usize,
    /// Source type.
    pub source_type: PowerSourceType,
    /// Current status.
    pub status: PowerStatus,
    /// Battery health.
    pub health: PowerHealth,
    /// Capacity as percentage (0-100).
    pub capacity_pct: u8,
    /// Voltage in microvolts.
    pub voltage_uv: u32,
    /// Current in microamps (negative = discharging).
    pub current_ua: i32,
    /// Temperature in tenths of degree Celsius.
    pub temp_tenths_c: i16,
    /// Design capacity in microamp-hours.
    pub charge_full_design_uah: u32,
    /// Current full capacity in microamp-hours.
    pub charge_full_uah: u32,
    /// Current charge in microamp-hours.
    pub charge_now_uah: u32,
    /// Whether the source is registered.
    pub registered: bool,
    /// Whether the source is online.
    pub online: bool,
}

impl PowerSource {
    /// Create an empty power source slot.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            source_type: PowerSourceType::Battery,
            status: PowerStatus::Unknown,
            health: PowerHealth::Unknown,
            capacity_pct: 0,
            voltage_uv: 0,
            current_ua: 0,
            temp_tenths_c: 0,
            charge_full_design_uah: 0,
            charge_full_uah: 0,
            charge_now_uah: 0,
            registered: false,
            online: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PowerEvent
// ══════════════════════════════════════════════════════════════

/// Power supply event for notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerEvent {
    /// A power source was connected.
    SourceConnected = 0,
    /// A power source was disconnected.
    SourceDisconnected = 1,
    /// Battery level changed.
    CapacityChanged = 2,
    /// Battery reached low threshold.
    LowBattery = 3,
    /// Battery reached critical threshold.
    CriticalBattery = 4,
    /// Charging started.
    ChargingStarted = 5,
    /// Charging stopped.
    ChargingStopped = 6,
}

// ══════════════════════════════════════════════════════════════
// PowerSupplyStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the power supply subsystem.
#[derive(Debug, Clone, Copy)]
pub struct PowerSupplyStats {
    /// Total events generated.
    pub total_events: u64,
    /// Total property updates.
    pub total_updates: u64,
    /// Total low battery warnings.
    pub total_low_battery: u64,
    /// Total critical battery warnings.
    pub total_critical_battery: u64,
}

impl PowerSupplyStats {
    const fn new() -> Self {
        Self {
            total_events: 0,
            total_updates: 0,
            total_low_battery: 0,
            total_critical_battery: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PowerSupplySubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level power supply subsystem.
pub struct PowerSupplySubsystem {
    /// Registered power sources.
    sources: [PowerSource; MAX_SOURCES],
    /// Statistics.
    stats: PowerSupplyStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for PowerSupplySubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerSupplySubsystem {
    /// Create a new power supply subsystem.
    pub const fn new() -> Self {
        Self {
            sources: [const { PowerSource::empty() }; MAX_SOURCES],
            stats: PowerSupplyStats::new(),
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

    // ── Registration ─────────────────────────────────────────

    /// Register a new power source.
    ///
    /// Returns the source index.
    pub fn register(&mut self, name: &[u8], source_type: PowerSourceType) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .sources
            .iter()
            .position(|s| !s.registered)
            .ok_or(Error::OutOfMemory)?;

        self.sources[slot] = PowerSource::empty();
        self.sources[slot].name[..name.len()].copy_from_slice(name);
        self.sources[slot].name_len = name.len();
        self.sources[slot].source_type = source_type;
        self.sources[slot].registered = true;

        self.stats.total_events += 1;
        Ok(slot)
    }

    /// Unregister a power source.
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_SOURCES {
            return Err(Error::InvalidArgument);
        }
        if !self.sources[slot].registered {
            return Err(Error::NotFound);
        }
        self.sources[slot] = PowerSource::empty();
        Ok(())
    }

    // ── Property updates ─────────────────────────────────────

    /// Update the status of a power source.
    pub fn update_status(&mut self, slot: usize, status: PowerStatus) -> Result<()> {
        if slot >= MAX_SOURCES || !self.sources[slot].registered {
            return Err(Error::InvalidArgument);
        }
        self.sources[slot].status = status;
        self.sources[slot].online = !matches!(status, PowerStatus::Offline);
        self.stats.total_updates += 1;
        Ok(())
    }

    /// Update the capacity of a battery source.
    ///
    /// Returns the power event if a threshold was crossed.
    pub fn update_capacity(&mut self, slot: usize, capacity_pct: u8) -> Result<Option<PowerEvent>> {
        if slot >= MAX_SOURCES || !self.sources[slot].registered {
            return Err(Error::InvalidArgument);
        }
        if capacity_pct > 100 {
            return Err(Error::InvalidArgument);
        }

        let old = self.sources[slot].capacity_pct;
        self.sources[slot].capacity_pct = capacity_pct;
        self.stats.total_updates += 1;

        // Check threshold crossings.
        if capacity_pct <= CRITICAL_BATTERY_THRESHOLD && old > CRITICAL_BATTERY_THRESHOLD {
            self.stats.total_critical_battery += 1;
            self.stats.total_events += 1;
            return Ok(Some(PowerEvent::CriticalBattery));
        }
        if capacity_pct <= LOW_BATTERY_THRESHOLD && old > LOW_BATTERY_THRESHOLD {
            self.stats.total_low_battery += 1;
            self.stats.total_events += 1;
            return Ok(Some(PowerEvent::LowBattery));
        }

        Ok(Some(PowerEvent::CapacityChanged))
    }

    /// Update voltage and current readings.
    pub fn update_readings(&mut self, slot: usize, voltage_uv: u32, current_ua: i32) -> Result<()> {
        if slot >= MAX_SOURCES || !self.sources[slot].registered {
            return Err(Error::InvalidArgument);
        }
        self.sources[slot].voltage_uv = voltage_uv;
        self.sources[slot].current_ua = current_ua;
        self.stats.total_updates += 1;
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return a power source by index.
    pub fn source(&self, slot: usize) -> Result<&PowerSource> {
        if slot >= MAX_SOURCES {
            return Err(Error::InvalidArgument);
        }
        if !self.sources[slot].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.sources[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> PowerSupplyStats {
        self.stats
    }

    /// Return the number of registered sources.
    pub fn source_count(&self) -> usize {
        self.sources.iter().filter(|s| s.registered).count()
    }

    /// Return the number of online sources.
    pub fn online_count(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| s.registered && s.online)
            .count()
    }
}
