// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware Monitoring (hwmon) sensor framework.
//!
//! Provides a unified framework for reading temperature, voltage,
//! current, power, fan speed, humidity, and intrusion sensors from
//! platform monitoring chips (LM75, IT8720, Nuvoton NCT6xx, etc.).
//!
//! # Architecture
//!
//! - **HwmonSensor** — one logical sensor: type, channel, value,
//!   and threshold limits.
//! - **HwmonChip** — a physical monitoring chip owning up to 16
//!   sensors.
//! - **HwmonAlarm** — a threshold violation event record.
//! - **HwmonSubsystem** — top-level registry of up to 8 chips and
//!   64 alarm entries; drives periodic `update_all` polling.
//!
//! # Units
//!
//! | Sensor Type | Unit of `value` |
//! |-------------|-----------------|
//! | Temperature | millidegrees Celsius (m°C) |
//! | Voltage     | millivolts (mV) |
//! | Current     | milliamps (mA) |
//! | Power       | microwatts (µW) |
//! | Fan         | RPM |
//! | Humidity    | milli-percent RH |
//! | Intrusion   | 0 = normal, 1 = intrusion detected |
//!
//! Reference: Linux hwmon sysfs interface documentation.

use oncrix_lib::{Error, Result};

// ── Sensor type ───────────────────────────────────────────────

/// Type of hardware monitoring sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwmonSensorType {
    /// Temperature sensor (m°C).
    Temperature,
    /// Voltage sensor (mV).
    Voltage,
    /// Current sensor (mA).
    Current,
    /// Power sensor (µW).
    Power,
    /// Fan speed sensor (RPM).
    Fan,
    /// Relative humidity sensor (milli-% RH).
    Humidity,
    /// Chassis intrusion sensor (0=closed, 1=open).
    Intrusion,
}

// ── Alarm type ────────────────────────────────────────────────

/// Kind of threshold alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwmonAlarmKind {
    /// Reading fell below the minimum threshold.
    BelowMin,
    /// Reading exceeded the critical threshold.
    AboveCrit,
    /// Fan sensor reported zero RPM (stalled/absent).
    FanFault,
}

// ── Sensor ────────────────────────────────────────────────────

/// Maximum label length including NUL terminator.
const LABEL_MAX: usize = 32;

/// A single hardware monitoring sensor.
///
/// Each sensor has a type, a channel index (0-based within its
/// type group on the chip), a human-readable label, and threshold
/// limits for alarm generation.
#[derive(Debug, Clone, Copy)]
pub struct HwmonSensor {
    /// Sensor type.
    pub sensor_type: HwmonSensorType,
    /// Channel index within the type group on the parent chip.
    pub channel: u8,
    /// Null-terminated label string.
    pub label: [u8; LABEL_MAX],
    /// Current reading in type-specific units.
    pub value: i32,
    /// Minimum threshold; readings below this raise `BelowMin`.
    pub min: i32,
    /// Maximum threshold (informational; does not raise alarm).
    pub max: i32,
    /// Critical threshold; readings above this raise `AboveCrit`.
    pub crit: i32,
    /// Whether this sensor slot is in use.
    pub active: bool,
}

impl Default for HwmonSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl HwmonSensor {
    /// Create an empty (inactive) sensor entry.
    pub const fn new() -> Self {
        Self {
            sensor_type: HwmonSensorType::Temperature,
            channel: 0,
            label: [0u8; LABEL_MAX],
            value: 0,
            min: i32::MIN,
            max: i32::MAX,
            crit: i32::MAX,
            active: false,
        }
    }

    /// Return `true` if the current reading is below `min`.
    pub fn is_below_min(&self) -> bool {
        self.min != i32::MIN && self.value < self.min
    }

    /// Return `true` if the current reading exceeds `crit`.
    pub fn is_above_crit(&self) -> bool {
        self.crit != i32::MAX && self.value > self.crit
    }

    /// Return `true` if this is a Fan sensor reporting zero RPM.
    pub fn is_fan_fault(&self) -> bool {
        self.sensor_type == HwmonSensorType::Fan && self.value == 0
    }
}

// ── Chip ──────────────────────────────────────────────────────

/// Maximum sensors per chip.
const MAX_SENSORS_PER_CHIP: usize = 16;

/// Name length including NUL.
const CHIP_NAME_MAX: usize = 32;

/// A physical hardware monitoring chip.
///
/// Each chip owns up to [`MAX_SENSORS_PER_CHIP`] (16) sensor
/// channels and is polled at `update_interval_ms` milliseconds.
pub struct HwmonChip {
    /// Chip name (e.g. "nct6776", "it8720f").
    pub name: [u8; CHIP_NAME_MAX],
    /// Sensor array.
    sensors: [HwmonSensor; MAX_SENSORS_PER_CHIP],
    /// Number of active sensors.
    sensor_count: usize,
    /// Polling interval in milliseconds.
    pub update_interval_ms: u32,
    /// Whether this chip slot is occupied.
    pub active: bool,
}

impl Default for HwmonChip {
    fn default() -> Self {
        Self::new()
    }
}

impl HwmonChip {
    /// Create an empty monitoring chip.
    pub const fn new() -> Self {
        Self {
            name: [0u8; CHIP_NAME_MAX],
            sensors: [const { HwmonSensor::new() }; MAX_SENSORS_PER_CHIP],
            sensor_count: 0,
            update_interval_ms: 1000,
            active: false,
        }
    }

    /// Create a chip with the given name and polling interval.
    ///
    /// The `name` slice is copied into the fixed array (truncated
    /// to `CHIP_NAME_MAX - 1` bytes).
    pub fn with_name(name: &[u8], update_interval_ms: u32) -> Self {
        let mut chip = Self::new();
        let copy_len = name.len().min(CHIP_NAME_MAX - 1);
        chip.name[..copy_len].copy_from_slice(&name[..copy_len]);
        chip.update_interval_ms = update_interval_ms;
        chip
    }

    /// Add a sensor to this chip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the chip has reached its
    /// sensor limit.
    pub fn add_sensor(&mut self, sensor: HwmonSensor) -> Result<usize> {
        if self.sensor_count >= MAX_SENSORS_PER_CHIP {
            return Err(Error::OutOfMemory);
        }
        let idx = self.sensor_count;
        self.sensors[idx] = sensor;
        self.sensors[idx].active = true;
        self.sensor_count += 1;
        Ok(idx)
    }

    /// Return a reference to sensor `idx`.
    pub fn get_sensor(&self, idx: usize) -> Option<&HwmonSensor> {
        if idx < self.sensor_count && self.sensors[idx].active {
            Some(&self.sensors[idx])
        } else {
            None
        }
    }

    /// Return a mutable reference to sensor `idx`.
    pub fn get_sensor_mut(&mut self, idx: usize) -> Option<&mut HwmonSensor> {
        if idx < self.sensor_count && self.sensors[idx].active {
            Some(&mut self.sensors[idx])
        } else {
            None
        }
    }

    /// Return the number of active sensors.
    pub fn sensor_count(&self) -> usize {
        self.sensor_count
    }

    /// Check all sensors on this chip for threshold violations.
    ///
    /// Returns an iterator-style approach: fills `alarms` with any
    /// violations found, up to `alarms.len()` entries. Returns the
    /// number of alarms written.
    pub fn check_thresholds(&self, chip_id: u8, alarms: &mut [HwmonAlarm]) -> usize {
        let mut written = 0usize;
        let mut i = 0usize;
        while i < self.sensor_count && written < alarms.len() {
            let s = &self.sensors[i];
            if !s.active {
                i += 1;
                continue;
            }
            if s.is_below_min() {
                alarms[written] = HwmonAlarm {
                    chip_id,
                    sensor_idx: i as u8,
                    alarm_kind: HwmonAlarmKind::BelowMin,
                    tick: 0,
                };
                written += 1;
            } else if s.is_above_crit() && written < alarms.len() {
                alarms[written] = HwmonAlarm {
                    chip_id,
                    sensor_idx: i as u8,
                    alarm_kind: HwmonAlarmKind::AboveCrit,
                    tick: 0,
                };
                written += 1;
            } else if s.is_fan_fault() && written < alarms.len() {
                alarms[written] = HwmonAlarm {
                    chip_id,
                    sensor_idx: i as u8,
                    alarm_kind: HwmonAlarmKind::FanFault,
                    tick: 0,
                };
                written += 1;
            }
            i += 1;
        }
        written
    }
}

// ── Alarm ─────────────────────────────────────────────────────

/// A threshold violation event.
#[derive(Debug, Clone, Copy)]
pub struct HwmonAlarm {
    /// Index of the chip that generated the alarm.
    pub chip_id: u8,
    /// Index of the sensor within the chip.
    pub sensor_idx: u8,
    /// Kind of alarm.
    pub alarm_kind: HwmonAlarmKind,
    /// Monotonic tick at which the alarm was recorded.
    pub tick: u64,
}

impl HwmonAlarm {
    /// Create a zeroed alarm entry.
    pub const fn new() -> Self {
        Self {
            chip_id: 0,
            sensor_idx: 0,
            alarm_kind: HwmonAlarmKind::BelowMin,
            tick: 0,
        }
    }
}

impl Default for HwmonAlarm {
    fn default() -> Self {
        Self::new()
    }
}

// ── Statistics ────────────────────────────────────────────────

/// Operational statistics for the hwmon subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct HwmonStats {
    /// Total sensor readings taken.
    pub readings: u64,
    /// Total alarms raised.
    pub alarms_raised: u64,
    /// Total threshold violations recorded.
    pub threshold_violations: u64,
}

// ── Subsystem ─────────────────────────────────────────────────

/// Maximum chips in the hwmon subsystem.
const MAX_HWMON_CHIPS: usize = 8;

/// Maximum alarms in the alarm ring buffer.
const MAX_ALARMS: usize = 64;

/// Hardware Monitoring subsystem.
///
/// Manages up to [`MAX_HWMON_CHIPS`] (8) monitoring chips and
/// maintains a circular buffer of up to [`MAX_ALARMS`] (64) alarm
/// entries.
pub struct HwmonSubsystem {
    /// Registered chips.
    chips: [HwmonChip; MAX_HWMON_CHIPS],
    /// Number of registered chips.
    chip_count: usize,
    /// Alarm ring buffer.
    alarms: [HwmonAlarm; MAX_ALARMS],
    /// Write index into the alarm ring buffer.
    alarm_head: usize,
    /// Total alarms ever written (may wrap).
    alarm_total: usize,
    /// Statistics.
    stats: HwmonStats,
    /// Global tick counter (incremented on each `update_all`).
    tick: u64,
}

impl Default for HwmonSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl HwmonSubsystem {
    /// Create an empty hwmon subsystem.
    pub fn new() -> Self {
        Self {
            chips: [const { HwmonChip::new() }; MAX_HWMON_CHIPS],
            chip_count: 0,
            alarms: [const { HwmonAlarm::new() }; MAX_ALARMS],
            alarm_head: 0,
            alarm_total: 0,
            stats: HwmonStats::default(),
            tick: 0,
        }
    }

    /// Register a monitoring chip.
    ///
    /// Returns the chip index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the chip table is full.
    pub fn register_chip(&mut self, mut chip: HwmonChip) -> Result<usize> {
        if self.chip_count >= MAX_HWMON_CHIPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.chip_count;
        chip.active = true;
        self.chips[idx] = chip;
        self.chip_count += 1;
        Ok(idx)
    }

    /// Unregister a chip by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `idx` is out of range.
    pub fn unregister_chip(&mut self, idx: usize) -> Result<()> {
        if idx >= self.chip_count || !self.chips[idx].active {
            return Err(Error::NotFound);
        }
        self.chips[idx].active = false;
        Ok(())
    }

    /// Read the current value of sensor `sensor_idx` on chip
    /// `chip_idx`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `chip_idx` or `sensor_idx` are
    ///   out of range or inactive.
    pub fn read_sensor(&mut self, chip_idx: usize, sensor_idx: usize) -> Result<i32> {
        if chip_idx >= self.chip_count || !self.chips[chip_idx].active {
            return Err(Error::NotFound);
        }
        let sensor = self.chips[chip_idx]
            .get_sensor(sensor_idx)
            .ok_or(Error::NotFound)?;
        let val = sensor.value;
        self.stats.readings += 1;
        Ok(val)
    }

    /// Update the reading for sensor `sensor_idx` on chip
    /// `chip_idx`.
    ///
    /// In a real driver this would trigger a hardware read and store
    /// the result. Here the caller provides the new reading directly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the chip or sensor is invalid.
    pub fn update_sensor(
        &mut self,
        chip_idx: usize,
        sensor_idx: usize,
        new_value: i32,
    ) -> Result<()> {
        if chip_idx >= self.chip_count || !self.chips[chip_idx].active {
            return Err(Error::NotFound);
        }
        let sensor = self.chips[chip_idx]
            .get_sensor_mut(sensor_idx)
            .ok_or(Error::NotFound)?;
        sensor.value = new_value;
        self.stats.readings += 1;
        Ok(())
    }

    /// Poll all active chips and check for threshold violations.
    ///
    /// For each chip, the method calls `check_thresholds` and
    /// appends any alarms to the ring buffer.
    pub fn update_all(&mut self) {
        self.tick += 1;
        let tick = self.tick;

        let mut i = 0usize;
        while i < self.chip_count {
            if !self.chips[i].active {
                i += 1;
                continue;
            }
            // Collect up to 4 alarms per chip per cycle.
            let mut local_alarms = [HwmonAlarm::default(); 4];
            let count = self.chips[i].check_thresholds(i as u8, &mut local_alarms);
            let mut j = 0usize;
            while j < count {
                local_alarms[j].tick = tick;
                self.push_alarm(local_alarms[j]);
                j += 1;
            }
            i += 1;
        }
    }

    /// Append an alarm to the ring buffer.
    fn push_alarm(&mut self, alarm: HwmonAlarm) {
        self.alarms[self.alarm_head] = alarm;
        self.alarm_head = (self.alarm_head + 1) % MAX_ALARMS;
        self.alarm_total = self.alarm_total.saturating_add(1);
        self.stats.alarms_raised += 1;
        self.stats.threshold_violations += 1;
    }

    /// Return the most recently written alarm, if any.
    pub fn latest_alarm(&self) -> Option<&HwmonAlarm> {
        if self.alarm_total == 0 {
            return None;
        }
        // The last written entry is one behind alarm_head.
        let last = if self.alarm_head == 0 {
            MAX_ALARMS - 1
        } else {
            self.alarm_head - 1
        };
        Some(&self.alarms[last])
    }

    /// Return the alarm at ring-buffer position `pos` (0 = oldest
    /// still retained, up to `min(alarm_total, MAX_ALARMS) - 1`).
    pub fn get_alarm(&self, pos: usize) -> Option<&HwmonAlarm> {
        let retained = self.alarm_total.min(MAX_ALARMS);
        if pos >= retained {
            return None;
        }
        let start = if self.alarm_total > MAX_ALARMS {
            self.alarm_head
        } else {
            0
        };
        let idx = (start + pos) % MAX_ALARMS;
        Some(&self.alarms[idx])
    }

    /// Return a reference to the chip at `index`.
    pub fn get_chip(&self, index: usize) -> Option<&HwmonChip> {
        if index < self.chip_count && self.chips[index].active {
            Some(&self.chips[index])
        } else {
            None
        }
    }

    /// Return a mutable reference to the chip at `index`.
    pub fn get_chip_mut(&mut self, index: usize) -> Option<&mut HwmonChip> {
        if index < self.chip_count && self.chips[index].active {
            Some(&mut self.chips[index])
        } else {
            None
        }
    }

    /// Return the number of registered chips.
    pub fn chip_count(&self) -> usize {
        self.chip_count
    }

    /// Return the number of alarms retained in the ring buffer.
    pub fn alarm_count(&self) -> usize {
        self.alarm_total.min(MAX_ALARMS)
    }

    /// Return the operational statistics.
    pub fn stats(&self) -> &HwmonStats {
        &self.stats
    }

    /// Return the current tick counter.
    pub fn tick(&self) -> u64 {
        self.tick
    }
}
