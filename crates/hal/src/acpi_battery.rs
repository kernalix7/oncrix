// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI battery and AC adapter status.
//!
//! Parses ACPI _BST (Battery Status) and _BIF (Battery Information) data
//! from fixed byte arrays, provides battery state, charge estimation,
//! and remaining time calculation.
//!
//! # ACPI Battery Methods
//!
//! - **_BIF**: Battery static information (capacity, voltage, chemistry...)
//! - **_BST**: Battery dynamic status (current rate, remaining capacity...)
//! - **_PSR**: Power source (AC adapter online/offline)
//!
//! Reference: ACPI Specification 6.5, Section 10.2.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ACPI _BIF Package Layout (offsets in DWORDs)
// ---------------------------------------------------------------------------

/// _BIF[0]: Power unit (0=mWh, 1=mAh).
pub const BIF_POWER_UNIT: usize = 0;
/// _BIF[1]: Design capacity in mWh or mAh.
pub const BIF_DESIGN_CAPACITY: usize = 1;
/// _BIF[2]: Last full charge capacity.
pub const BIF_LAST_FULL_CHARGE: usize = 2;
/// _BIF[3]: Battery technology (0=primary, 1=secondary/rechargeable).
pub const BIF_TECHNOLOGY: usize = 3;
/// _BIF[4]: Design voltage in mV.
pub const BIF_DESIGN_VOLTAGE: usize = 4;
/// _BIF[5]: Design capacity of warning level.
pub const BIF_WARN_CAPACITY: usize = 5;
/// _BIF[6]: Design capacity of low level.
pub const BIF_LOW_CAPACITY: usize = 6;
/// _BIF[7]: Battery capacity granularity 1 (low-warn).
pub const BIF_GRANULARITY_1: usize = 7;
/// _BIF[8]: Battery capacity granularity 2 (warn-full).
pub const BIF_GRANULARITY_2: usize = 8;
/// Number of integer fields in _BIF.
pub const BIF_INT_FIELDS: usize = 9;

// ---------------------------------------------------------------------------
// ACPI _BST Package Layout (offsets in DWORDs)
// ---------------------------------------------------------------------------

/// _BST[0]: Battery state bitmask.
pub const BST_STATE: usize = 0;
/// _BST[1]: Battery present rate (mW or mA, 0xFFFF_FFFF = unknown).
pub const BST_PRESENT_RATE: usize = 1;
/// _BST[2]: Remaining capacity (mWh or mAh).
pub const BST_REMAINING_CAPACITY: usize = 2;
/// _BST[3]: Present voltage in mV.
pub const BST_PRESENT_VOLTAGE: usize = 3;
/// Number of integer fields in _BST.
pub const BST_INT_FIELDS: usize = 4;

// ---------------------------------------------------------------------------
// _BST State Bits
// ---------------------------------------------------------------------------

/// _BST state bit: battery is discharging.
pub const BST_STATE_DISCHARGING: u32 = 1 << 0;

/// _BST state bit: battery is charging.
pub const BST_STATE_CHARGING: u32 = 1 << 1;

/// _BST state bit: battery at critically low level.
pub const BST_STATE_CRITICAL: u32 = 1 << 2;

/// _BST state bit: charge limiting is active.
pub const BST_STATE_CHARGE_LIMITING: u32 = 1 << 3;

/// Sentinel value meaning "unknown" in ACPI integer fields.
pub const ACPI_BATTERY_UNKNOWN: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// String field lengths
// ---------------------------------------------------------------------------

/// Maximum length for battery model/serial/chemistry strings.
pub const BATTERY_STRING_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Battery State Enum
// ---------------------------------------------------------------------------

/// Battery operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatteryState {
    /// Battery is charging from AC power.
    Charging,
    /// Battery is discharging (on battery power).
    Discharging,
    /// Battery is full and idle (on AC, not charging).
    Full,
    /// No battery present in the slot.
    NotPresent,
    /// Battery is at a critically low charge level.
    Critical,
}

impl BatteryState {
    /// Returns a human-readable description.
    pub fn description(self) -> &'static str {
        match self {
            BatteryState::Charging => "Charging",
            BatteryState::Discharging => "Discharging",
            BatteryState::Full => "Full",
            BatteryState::NotPresent => "Not Present",
            BatteryState::Critical => "Critical",
        }
    }
}

// ---------------------------------------------------------------------------
// Battery Information (_BIF result)
// ---------------------------------------------------------------------------

/// Static battery information parsed from ACPI _BIF.
#[derive(Debug, Clone)]
pub struct BatteryInfo {
    /// Whether the capacity is reported in mAh (true) or mWh (false).
    pub power_unit_ma: bool,
    /// Design capacity in mWh or mAh.
    pub design_capacity: u32,
    /// Last measured full-charge capacity.
    pub last_full_charge: u32,
    /// Whether the battery is rechargeable.
    pub rechargeable: bool,
    /// Design voltage in mV.
    pub design_voltage_mv: u32,
    /// Warning capacity threshold.
    pub warn_capacity: u32,
    /// Low capacity threshold.
    pub low_capacity: u32,
    /// Capacity granularity between low and warning levels.
    pub granularity_1: u32,
    /// Capacity granularity between warning and full levels.
    pub granularity_2: u32,
    /// Manufacturer model string (ASCII, null-padded).
    pub model: [u8; BATTERY_STRING_LEN],
    /// Serial number string (ASCII, null-padded).
    pub serial: [u8; BATTERY_STRING_LEN],
    /// Battery chemistry string (e.g., "LiON", "NiMH").
    pub chemistry: [u8; BATTERY_STRING_LEN],
    /// Cycle count (from extended data, 0 if unavailable).
    pub cycle_count: u32,
}

impl BatteryInfo {
    /// Creates a zeroed (unknown) battery info record.
    pub fn new() -> Self {
        Self {
            power_unit_ma: false,
            design_capacity: 0,
            last_full_charge: 0,
            rechargeable: true,
            design_voltage_mv: 0,
            warn_capacity: 0,
            low_capacity: 0,
            granularity_1: 0,
            granularity_2: 0,
            model: [0u8; BATTERY_STRING_LEN],
            serial: [0u8; BATTERY_STRING_LEN],
            chemistry: [0u8; BATTERY_STRING_LEN],
            cycle_count: 0,
        }
    }

    /// Parses a _BIF integer field array into this struct.
    ///
    /// `fields` must contain at least `BIF_INT_FIELDS` (9) DWORDs.
    pub fn parse_bif(&mut self, fields: &[u32]) -> Result<()> {
        if fields.len() < BIF_INT_FIELDS {
            return Err(Error::InvalidArgument);
        }
        self.power_unit_ma = fields[BIF_POWER_UNIT] != 0;
        self.design_capacity = fields[BIF_DESIGN_CAPACITY];
        self.last_full_charge = fields[BIF_LAST_FULL_CHARGE];
        self.rechargeable = fields[BIF_TECHNOLOGY] != 0;
        self.design_voltage_mv = fields[BIF_DESIGN_VOLTAGE];
        self.warn_capacity = fields[BIF_WARN_CAPACITY];
        self.low_capacity = fields[BIF_LOW_CAPACITY];
        self.granularity_1 = fields[BIF_GRANULARITY_1];
        self.granularity_2 = fields[BIF_GRANULARITY_2];
        Ok(())
    }

    /// Sets the model string from a byte slice (truncated to BATTERY_STRING_LEN).
    pub fn set_model(&mut self, model: &[u8]) {
        let len = model.len().min(BATTERY_STRING_LEN);
        self.model[..len].copy_from_slice(&model[..len]);
    }

    /// Sets the serial string from a byte slice.
    pub fn set_serial(&mut self, serial: &[u8]) {
        let len = serial.len().min(BATTERY_STRING_LEN);
        self.serial[..len].copy_from_slice(&serial[..len]);
    }

    /// Sets the chemistry string from a byte slice.
    pub fn set_chemistry(&mut self, chemistry: &[u8]) {
        let len = chemistry.len().min(BATTERY_STRING_LEN);
        self.chemistry[..len].copy_from_slice(&chemistry[..len]);
    }

    /// Returns the design capacity in mWh (normalizes mAh using design voltage).
    pub fn design_capacity_mwh(&self) -> u32 {
        if self.power_unit_ma && self.design_voltage_mv > 0 {
            (self.design_capacity as u64 * self.design_voltage_mv as u64 / 1000) as u32
        } else {
            self.design_capacity
        }
    }

    /// Returns the wear level percentage (last full / design * 100).
    pub fn wear_level_percent(&self) -> u8 {
        if self.design_capacity == 0 {
            return 0;
        }
        let ratio = (self.last_full_charge as u64 * 100) / self.design_capacity as u64;
        ratio.min(100) as u8
    }
}

// ---------------------------------------------------------------------------
// Battery Status (_BST result)
// ---------------------------------------------------------------------------

/// Dynamic battery status parsed from ACPI _BST.
#[derive(Debug, Clone, Copy)]
pub struct BatteryStatus {
    /// Current battery state.
    pub state: BatteryState,
    /// Present charge/discharge rate (mW or mA, or 0 if unknown).
    pub present_rate: u32,
    /// Remaining capacity (mWh or mAh).
    pub remaining_capacity: u32,
    /// Present voltage in mV.
    pub present_voltage_mv: u32,
    /// Raw state bitmask from ACPI.
    pub raw_state: u32,
}

impl BatteryStatus {
    /// Creates a zeroed (unknown) battery status.
    pub const fn new() -> Self {
        Self {
            state: BatteryState::NotPresent,
            present_rate: 0,
            remaining_capacity: 0,
            present_voltage_mv: 0,
            raw_state: 0,
        }
    }

    /// Parses a _BST integer field array into this struct.
    ///
    /// `fields` must contain at least `BST_INT_FIELDS` (4) DWORDs.
    pub fn parse_bst(&mut self, fields: &[u32]) -> Result<()> {
        if fields.len() < BST_INT_FIELDS {
            return Err(Error::InvalidArgument);
        }
        self.raw_state = fields[BST_STATE];

        // Determine state from bitmask.
        self.state = if self.raw_state == 0 {
            BatteryState::Full
        } else if self.raw_state & BST_STATE_CRITICAL != 0 {
            BatteryState::Critical
        } else if self.raw_state & BST_STATE_CHARGING != 0 {
            BatteryState::Charging
        } else if self.raw_state & BST_STATE_DISCHARGING != 0 {
            BatteryState::Discharging
        } else {
            BatteryState::Full
        };

        let rate = fields[BST_PRESENT_RATE];
        self.present_rate = if rate == ACPI_BATTERY_UNKNOWN {
            0
        } else {
            rate
        };
        self.remaining_capacity = fields[BST_REMAINING_CAPACITY];
        let volt = fields[BST_PRESENT_VOLTAGE];
        self.present_voltage_mv = if volt == ACPI_BATTERY_UNKNOWN {
            0
        } else {
            volt
        };

        Ok(())
    }

    /// Returns the charge percentage given the last full charge capacity.
    pub fn charge_percent(&self, last_full_charge: u32) -> u8 {
        if last_full_charge == 0 {
            return 0;
        }
        let pct = (self.remaining_capacity as u64 * 100) / last_full_charge as u64;
        pct.min(100) as u8
    }
}

// ---------------------------------------------------------------------------
// AC Adapter State
// ---------------------------------------------------------------------------

/// AC adapter (power source) state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcAdapterState {
    /// AC adapter is online (wall power present).
    Online,
    /// AC adapter is offline (running on battery).
    Offline,
    /// AC adapter state is unknown.
    Unknown,
}

impl AcAdapterState {
    /// Parses from ACPI _PSR return value (0=offline, 1=online).
    pub fn from_psr(val: u32) -> Self {
        match val {
            0 => AcAdapterState::Offline,
            1 => AcAdapterState::Online,
            _ => AcAdapterState::Unknown,
        }
    }

    /// Returns true if AC power is present.
    pub fn is_online(self) -> bool {
        self == AcAdapterState::Online
    }
}

// ---------------------------------------------------------------------------
// Battery Device
// ---------------------------------------------------------------------------

/// An ACPI battery device combining static info and dynamic status.
pub struct BatteryDevice {
    /// ACPI namespace path (e.g., "\_SB.BAT0"), stored as byte array.
    namespace_path: [u8; 32],
    /// Namespace path length.
    path_len: usize,
    /// Static battery information from _BIF.
    pub info: BatteryInfo,
    /// Dynamic battery status from _BST.
    pub status: BatteryStatus,
    /// AC adapter state.
    pub ac_state: AcAdapterState,
    /// Whether the battery slot has a battery.
    pub present: bool,
    /// ACPI slot index.
    pub slot: u8,
}

impl BatteryDevice {
    /// Creates a new battery device for the given ACPI slot.
    pub fn new(slot: u8) -> Self {
        Self {
            namespace_path: [0u8; 32],
            path_len: 0,
            info: BatteryInfo::new(),
            status: BatteryStatus::new(),
            ac_state: AcAdapterState::Unknown,
            present: false,
            slot,
        }
    }

    /// Sets the ACPI namespace path for this battery.
    pub fn set_namespace_path(&mut self, path: &[u8]) {
        let len = path.len().min(32);
        self.namespace_path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    /// Returns the namespace path bytes.
    pub fn namespace_path(&self) -> &[u8] {
        &self.namespace_path[..self.path_len]
    }

    /// Updates static info from a raw _BIF field array.
    pub fn update_info(&mut self, bif_fields: &[u32]) -> Result<()> {
        self.info.parse_bif(bif_fields)?;
        self.present = bif_fields[BIF_DESIGN_CAPACITY] != ACPI_BATTERY_UNKNOWN
            && bif_fields[BIF_DESIGN_CAPACITY] != 0;
        Ok(())
    }

    /// Updates dynamic status from a raw _BST field array.
    pub fn update_status(&mut self, bst_fields: &[u32]) -> Result<()> {
        self.status.parse_bst(bst_fields)
    }

    /// Updates AC adapter state from a _PSR return value.
    pub fn update_ac_state(&mut self, psr_val: u32) {
        self.ac_state = AcAdapterState::from_psr(psr_val);
    }

    /// Calculates estimated remaining time in minutes.
    ///
    /// Returns `None` if the battery is charging, full, or the rate is unknown.
    pub fn remaining_time_minutes(&self) -> Option<u32> {
        if self.status.state != BatteryState::Discharging {
            return None;
        }
        if self.status.present_rate == 0 {
            return None;
        }
        // remaining_capacity (mWh) / present_rate (mW) * 60 = minutes
        // Use 64-bit arithmetic to avoid overflow.
        let minutes =
            (self.status.remaining_capacity as u64 * 60) / self.status.present_rate as u64;
        Some(minutes as u32)
    }

    /// Returns the current charge percentage.
    pub fn charge_percent(&self) -> u8 {
        self.status.charge_percent(self.info.last_full_charge)
    }

    /// Returns the battery health as a wear level percentage.
    pub fn health_percent(&self) -> u8 {
        self.info.wear_level_percent()
    }

    /// Returns a sysfs-compatible "status" string for the battery.
    pub fn status_str(&self) -> &'static str {
        self.status.state.description()
    }

    /// Returns whether the system is on AC power.
    pub fn on_ac_power(&self) -> bool {
        self.ac_state.is_online()
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Maximum number of battery slots tracked.
pub const MAX_BATTERIES: usize = 4;

/// Global ACPI battery registry.
pub struct BatteryRegistry {
    batteries: [Option<BatteryDevice>; MAX_BATTERIES],
    count: usize,
}

impl BatteryRegistry {
    /// Creates an empty battery registry.
    pub const fn new() -> Self {
        const EMPTY: Option<BatteryDevice> = None;
        Self {
            batteries: [EMPTY; MAX_BATTERIES],
            count: 0,
        }
    }

    /// Registers a new battery device.
    pub fn register(&mut self, battery: BatteryDevice) -> Result<usize> {
        if self.count >= MAX_BATTERIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.batteries[idx] = Some(battery);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the battery at `index`.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut BatteryDevice> {
        self.batteries[index].as_mut().ok_or(Error::NotFound)
    }

    /// Returns a reference to the battery at `index`.
    pub fn get(&self, index: usize) -> Result<&BatteryDevice> {
        self.batteries[index].as_ref().ok_or(Error::NotFound)
    }

    /// Returns the number of registered batteries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no batteries are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the overall charge percentage across all present batteries.
    pub fn aggregate_charge_percent(&self) -> u8 {
        let mut total_remaining = 0u64;
        let mut total_full = 0u64;
        for entry in self.batteries[..self.count].iter() {
            if let Some(b) = entry {
                if b.present {
                    total_remaining += b.status.remaining_capacity as u64;
                    total_full += b.info.last_full_charge as u64;
                }
            }
        }
        if total_full == 0 {
            return 0;
        }
        ((total_remaining * 100) / total_full).min(100) as u8
    }
}
