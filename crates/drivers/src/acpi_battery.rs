// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI battery driver.
//!
//! Reads battery status, capacity, and charge rate from ACPI control
//! method battery (CMB) devices as defined in the ACPI specification.
//! Provides a unified battery interface for system power management.

/// Maximum number of batteries supported.
pub const MAX_BATTERIES: usize = 4;

/// Battery status flags (from ACPI _BST method).
pub const BATT_DISCHARGING: u32 = 1 << 0;
pub const BATT_CHARGING: u32 = 1 << 1;
pub const BATT_CRITICAL: u32 = 1 << 2;
pub const BATT_CHARGE_LIMITING: u32 = 1 << 3;

/// Battery technology type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatteryTech {
    /// Non-rechargeable.
    Primary,
    /// Rechargeable (Li-Ion, NiMH, etc.).
    Secondary,
}

/// Battery information from ACPI _BIF / _BIX method.
#[derive(Clone, Copy, Debug)]
pub struct BatteryInfo {
    /// Technology type.
    pub tech: BatteryTech,
    /// Design capacity (mWh or mAh depending on unit).
    pub design_capacity: u32,
    /// Last full charge capacity.
    pub last_full_capacity: u32,
    /// Design voltage in millivolts.
    pub design_voltage_mv: u32,
    /// Capacity warning threshold.
    pub capacity_warning: u32,
    /// Capacity low threshold.
    pub capacity_low: u32,
    /// Cycle count (0 if not supported).
    pub cycle_count: u32,
    /// Measurement unit: 0 = mWh, 1 = mAh.
    pub unit_is_mah: bool,
    /// Battery model number.
    pub model: [u8; 32],
    /// Manufacturer name.
    pub manufacturer: [u8; 32],
}

impl Default for BatteryInfo {
    fn default() -> Self {
        Self {
            tech: BatteryTech::Secondary,
            design_capacity: 0,
            last_full_capacity: 0,
            design_voltage_mv: 0,
            capacity_warning: 0,
            capacity_low: 0,
            cycle_count: 0,
            unit_is_mah: false,
            model: [0u8; 32],
            manufacturer: [0u8; 32],
        }
    }
}

/// Real-time battery status from ACPI _BST method.
#[derive(Clone, Copy, Debug, Default)]
pub struct BatteryStatus {
    /// Status flags (BATT_DISCHARGING, BATT_CHARGING, etc.).
    pub flags: u32,
    /// Rate of energy flow (mW or mA). 0xFFFFFFFF = unknown.
    pub rate: u32,
    /// Remaining capacity (mWh or mAh).
    pub remaining: u32,
    /// Present voltage in millivolts.
    pub voltage_mv: u32,
}

impl BatteryStatus {
    /// Return battery charge as a percentage of last_full_capacity.
    pub fn charge_percent(&self, last_full: u32) -> u8 {
        if last_full == 0 {
            return 0;
        }
        let pct = (self.remaining as u64 * 100 / last_full as u64).min(100) as u8;
        pct
    }

    /// Return true if discharging.
    pub fn is_discharging(&self) -> bool {
        (self.flags & BATT_DISCHARGING) != 0
    }

    /// Return true if charging.
    pub fn is_charging(&self) -> bool {
        (self.flags & BATT_CHARGING) != 0
    }

    /// Return true if critically low.
    pub fn is_critical(&self) -> bool {
        (self.flags & BATT_CRITICAL) != 0
    }
}

/// Estimated time remaining (minutes) for current charge/discharge.
pub fn estimate_time_remaining(status: &BatteryStatus, info: &BatteryInfo) -> Option<u32> {
    if status.rate == 0 || status.rate == 0xFFFF_FFFF {
        return None;
    }
    if status.is_discharging() {
        // Time to empty in minutes.
        let mins = (status.remaining as u64 * 60) / status.rate as u64;
        Some(mins as u32)
    } else if status.is_charging() {
        // Time to full in minutes.
        let to_full = info.last_full_capacity.saturating_sub(status.remaining);
        let mins = (to_full as u64 * 60) / status.rate as u64;
        Some(mins as u32)
    } else {
        None
    }
}

/// ACPI battery driver state for one battery slot.
pub struct AcpiBattery {
    /// Slot index (0-based).
    pub slot: usize,
    /// Battery is physically present.
    pub present: bool,
    /// Static battery information (from _BIF/_BIX).
    pub info: BatteryInfo,
    /// Last-read dynamic status (from _BST).
    pub status: BatteryStatus,
    /// Number of status polls since init.
    pub poll_count: u64,
}

impl AcpiBattery {
    /// Create a new battery driver for the given slot.
    pub const fn new(slot: usize) -> Self {
        Self {
            slot,
            present: false,
            info: BatteryInfo {
                tech: BatteryTech::Secondary,
                design_capacity: 0,
                last_full_capacity: 0,
                design_voltage_mv: 0,
                capacity_warning: 0,
                capacity_low: 0,
                cycle_count: 0,
                unit_is_mah: false,
                model: [0u8; 32],
                manufacturer: [0u8; 32],
            },
            status: BatteryStatus {
                flags: 0,
                rate: 0,
                remaining: 0,
                voltage_mv: 0,
            },
            poll_count: 0,
        }
    }

    /// Update battery info from ACPI method results.
    pub fn update_info(&mut self, info: BatteryInfo) {
        self.info = info;
        self.present = info.design_capacity > 0;
    }

    /// Update battery status from ACPI _BST results.
    pub fn update_status(&mut self, status: BatteryStatus) {
        self.status = status;
        self.poll_count += 1;
    }

    /// Return the current charge percentage.
    pub fn charge_percent(&self) -> u8 {
        self.status.charge_percent(self.info.last_full_capacity)
    }

    /// Return estimated time remaining in minutes.
    pub fn time_remaining_mins(&self) -> Option<u32> {
        if !self.present {
            return None;
        }
        estimate_time_remaining(&self.status, &self.info)
    }
}

/// ACPI battery manager for all battery slots.
pub struct AcpiBatteryManager {
    batteries: [AcpiBattery; MAX_BATTERIES],
    num_slots: usize,
}

impl AcpiBatteryManager {
    /// Create a new battery manager.
    pub fn new(num_slots: usize) -> Self {
        let ns = num_slots.min(MAX_BATTERIES);
        Self {
            batteries: core::array::from_fn(|i| AcpiBattery::new(i)),
            num_slots: ns,
        }
    }

    /// Return a reference to a battery by slot.
    pub fn battery(&self, slot: usize) -> Option<&AcpiBattery> {
        if slot < self.num_slots {
            Some(&self.batteries[slot])
        } else {
            None
        }
    }

    /// Return a mutable reference to a battery by slot.
    pub fn battery_mut(&mut self, slot: usize) -> Option<&mut AcpiBattery> {
        if slot < self.num_slots {
            Some(&mut self.batteries[slot])
        } else {
            None
        }
    }

    /// Return the system's overall charge level (average of present batteries).
    pub fn system_charge_percent(&self) -> u8 {
        let mut total = 0u32;
        let mut count = 0u32;
        for bat in &self.batteries[..self.num_slots] {
            if bat.present {
                total += bat.charge_percent() as u32;
                count += 1;
            }
        }
        if count == 0 {
            100
        } else {
            (total / count) as u8
        }
    }

    /// Return true if any battery is critically low.
    pub fn any_critical(&self) -> bool {
        self.batteries[..self.num_slots]
            .iter()
            .any(|b| b.present && b.status.is_critical())
    }

    /// Return the number of battery slots.
    pub fn num_slots(&self) -> usize {
        self.num_slots
    }
}
