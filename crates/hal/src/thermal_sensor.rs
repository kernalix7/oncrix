// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thermal sensor hardware abstraction.
//!
//! Provides a unified interface for reading temperature data from hardware
//! thermal sensors including CPU package sensors, PCH sensors, and on-die
//! thermal diodes. Supports threshold configuration and thermal trip points.

use oncrix_lib::{Error, Result};

/// Maximum number of thermal sensors supported.
pub const MAX_THERMAL_SENSORS: usize = 16;

/// Maximum number of trip points per sensor.
pub const MAX_TRIP_POINTS: usize = 4;

/// Type of thermal sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorType {
    /// CPU package thermal sensor (on-die).
    CpuPackage,
    /// CPU core thermal sensor (per-core).
    CpuCore,
    /// Platform Controller Hub (PCH/southbridge) sensor.
    Pch,
    /// System board ambient temperature sensor.
    Ambient,
    /// GPU thermal sensor.
    Gpu,
    /// Memory thermal sensor.
    Memory,
    /// Generic external thermistor.
    External,
}

/// A thermal trip point that triggers an action when crossed.
#[derive(Debug, Clone, Copy)]
pub struct TripPoint {
    /// Temperature threshold in milli-Celsius.
    pub temp_mc: i32,
    /// Type of action triggered at this trip point.
    pub trip_type: TripType,
    /// Whether this trip point is active.
    pub enabled: bool,
}

/// Type of action triggered at a thermal trip point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripType {
    /// Passive cooling — reduce performance.
    Passive,
    /// Active cooling — engage fans.
    Active,
    /// Critical — emergency shutdown.
    Critical,
    /// Hot — aggressive throttling.
    Hot,
}

impl TripPoint {
    /// Creates a new trip point.
    pub const fn new(temp_mc: i32, trip_type: TripType) -> Self {
        Self {
            temp_mc,
            trip_type,
            enabled: true,
        }
    }
}

impl Default for TripPoint {
    fn default() -> Self {
        Self::new(100_000, TripType::Critical)
    }
}

/// A hardware thermal sensor.
#[derive(Debug)]
pub struct ThermalSensor {
    /// Sensor identifier.
    id: u8,
    /// Sensor type.
    sensor_type: SensorType,
    /// MMIO base address for sensor registers.
    base_addr: u64,
    /// Configured trip points.
    trip_points: [TripPoint; MAX_TRIP_POINTS],
    /// Number of active trip points.
    trip_count: usize,
    /// Calibration offset in milli-Celsius.
    calibration_offset: i32,
}

impl ThermalSensor {
    /// Creates a new thermal sensor.
    ///
    /// # Arguments
    /// * `id` — Unique sensor identifier.
    /// * `sensor_type` — Type of thermal sensor.
    /// * `base_addr` — MMIO base address for sensor registers.
    pub const fn new(id: u8, sensor_type: SensorType, base_addr: u64) -> Self {
        Self {
            id,
            sensor_type,
            base_addr,
            trip_points: [const { TripPoint::new(100_000, TripType::Critical) }; MAX_TRIP_POINTS],
            trip_count: 0,
            calibration_offset: 0,
        }
    }

    /// Returns the sensor ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the sensor type.
    pub fn sensor_type(&self) -> SensorType {
        self.sensor_type
    }

    /// Sets the calibration offset in milli-Celsius.
    pub fn set_calibration_offset(&mut self, offset_mc: i32) {
        self.calibration_offset = offset_mc;
    }

    /// Adds a trip point to this sensor.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the trip point array is full.
    pub fn add_trip_point(&mut self, trip: TripPoint) -> Result<()> {
        if self.trip_count >= MAX_TRIP_POINTS {
            return Err(Error::OutOfMemory);
        }
        self.trip_points[self.trip_count] = trip;
        self.trip_count += 1;
        Ok(())
    }

    /// Reads the current temperature in milli-Celsius.
    ///
    /// # Errors
    /// Returns `Error::IoError` if the sensor cannot be read.
    pub fn read_temp_mc(&self) -> Result<i32> {
        if self.base_addr == 0 {
            return Err(Error::IoError);
        }
        // SAFETY: MMIO read from thermal sensor temperature register.
        // base_addr is validated to be non-zero.
        let raw = unsafe {
            let temp_reg = self.base_addr as *const u32;
            temp_reg.read_volatile()
        };
        // Convert raw register value to milli-Celsius.
        // Encoding: raw value in units of 0.5°C, offset from -40°C.
        let temp_mc = (raw as i32) * 500 - 40_000 + self.calibration_offset;
        Ok(temp_mc)
    }

    /// Checks whether any trip point has been exceeded.
    ///
    /// Returns the first triggered trip type, or `None` if all are within limits.
    ///
    /// # Errors
    /// Returns `Error::IoError` if the sensor cannot be read.
    pub fn check_trips(&self) -> Result<Option<TripType>> {
        let temp = self.read_temp_mc()?;
        for trip in &self.trip_points[..self.trip_count] {
            if trip.enabled && temp >= trip.temp_mc {
                return Ok(Some(trip.trip_type));
            }
        }
        Ok(None)
    }

    /// Returns the trip points slice.
    pub fn trip_points(&self) -> &[TripPoint] {
        &self.trip_points[..self.trip_count]
    }
}

impl Default for ThermalSensor {
    fn default() -> Self {
        Self::new(0, SensorType::Ambient, 0)
    }
}

/// Registry managing all system thermal sensors.
pub struct ThermalSensorRegistry {
    sensors: [ThermalSensor; MAX_THERMAL_SENSORS],
    count: usize,
}

impl ThermalSensorRegistry {
    /// Creates a new empty sensor registry.
    pub fn new() -> Self {
        Self {
            sensors: [
                ThermalSensor::new(0, SensorType::Ambient, 0),
                ThermalSensor::new(1, SensorType::Ambient, 0),
                ThermalSensor::new(2, SensorType::Ambient, 0),
                ThermalSensor::new(3, SensorType::Ambient, 0),
                ThermalSensor::new(4, SensorType::Ambient, 0),
                ThermalSensor::new(5, SensorType::Ambient, 0),
                ThermalSensor::new(6, SensorType::Ambient, 0),
                ThermalSensor::new(7, SensorType::Ambient, 0),
                ThermalSensor::new(8, SensorType::Ambient, 0),
                ThermalSensor::new(9, SensorType::Ambient, 0),
                ThermalSensor::new(10, SensorType::Ambient, 0),
                ThermalSensor::new(11, SensorType::Ambient, 0),
                ThermalSensor::new(12, SensorType::Ambient, 0),
                ThermalSensor::new(13, SensorType::Ambient, 0),
                ThermalSensor::new(14, SensorType::Ambient, 0),
                ThermalSensor::new(15, SensorType::Ambient, 0),
            ],
            count: 0,
        }
    }

    /// Registers a thermal sensor.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, sensor: ThermalSensor) -> Result<()> {
        if self.count >= MAX_THERMAL_SENSORS {
            return Err(Error::OutOfMemory);
        }
        self.sensors[self.count] = sensor;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered sensors.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no sensors are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a reference to the sensor at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get(&self, index: usize) -> Result<&ThermalSensor> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&self.sensors[index])
    }

    /// Reads the maximum temperature across all registered sensors (milli-Celsius).
    ///
    /// # Errors
    /// Returns `Error::NotFound` if no sensors are registered.
    pub fn max_temp_mc(&self) -> Result<i32> {
        if self.count == 0 {
            return Err(Error::NotFound);
        }
        let mut max = i32::MIN;
        for sensor in &self.sensors[..self.count] {
            if let Ok(t) = sensor.read_temp_mc() {
                if t > max {
                    max = t;
                }
            }
        }
        Ok(max)
    }

    /// Scans all sensors for trip point violations.
    ///
    /// Returns the most severe trip type found, or `None` if all are within limits.
    pub fn scan_trips(&self) -> Option<TripType> {
        let mut worst: Option<TripType> = None;
        for sensor in &self.sensors[..self.count] {
            if let Ok(Some(trip)) = sensor.check_trips() {
                worst = Some(match (worst, trip) {
                    (None, t) => t,
                    (Some(TripType::Critical), _) => TripType::Critical,
                    (_, TripType::Critical) => TripType::Critical,
                    (Some(TripType::Hot), _) => TripType::Hot,
                    (_, TripType::Hot) => TripType::Hot,
                    (Some(t), _) => t,
                });
            }
        }
        worst
    }
}

impl Default for ThermalSensorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts milli-Celsius to milli-Fahrenheit.
pub fn mc_to_mf(temp_mc: i32) -> i32 {
    temp_mc * 9 / 5 + 32_000
}

/// Converts milli-Celsius to milli-Kelvin.
pub fn mc_to_mk(temp_mc: i32) -> i32 {
    temp_mc + 273_150
}

/// Returns a human-readable string label for a sensor type.
pub fn sensor_type_name(sensor_type: SensorType) -> &'static str {
    match sensor_type {
        SensorType::CpuPackage => "cpu-package",
        SensorType::CpuCore => "cpu-core",
        SensorType::Pch => "pch",
        SensorType::Ambient => "ambient",
        SensorType::Gpu => "gpu",
        SensorType::Memory => "memory",
        SensorType::External => "external",
    }
}
