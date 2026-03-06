// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power supply and battery HAL for the ONCRIX operating system.
//!
//! Provides a platform-independent abstraction for battery status reporting,
//! AC adapter detection, charge level monitoring, voltage/current measurement,
//! and health assessment. Designed to work with ACPI battery objects (x86_64)
//! and MMIO-based fuel gauges (ARM/RISC-V).
//!
//! # Architecture
//!
//! - **SupplyType** — classification of the power supply (battery, AC, USB)
//! - **ChargeState** — current charging status
//! - **HealthState** — battery health assessment
//! - **BatteryChemistry** — battery chemistry type (Li-ion, LiPo, etc.)
//! - **BatteryInfo** — detailed battery information snapshot
//! - **PowerSupplyConfig** — hardware configuration
//! - **PowerSupply** — a single power supply device
//! - **PowerSupplyEvent** — power supply state change notification
//! - **PowerSupplyRegistry** — manages up to [`MAX_SUPPLIES`] power supply devices
//!
//! # Reference
//!
//! Linux: `drivers/power/supply/`, `include/linux/power_supply.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of power supply devices in the registry.
const MAX_SUPPLIES: usize = 8;

/// Maximum number of pending events.
const MAX_EVENTS: usize = 16;

/// Battery capacity indicating unknown/unsupported.
const CAPACITY_UNKNOWN: u8 = 255;

/// Temperature indicating sensor failure (millicelsius).
const TEMP_UNKNOWN: i32 = i32::MIN;

/// Voltage indicating unknown (microvolts).
const VOLTAGE_UNKNOWN: u32 = 0;

/// Current indicating unknown (microamperes).
const CURRENT_UNKNOWN: i32 = 0;

// ---------------------------------------------------------------------------
// ACPI battery register offsets (via Embedded Controller or CRS)
// ---------------------------------------------------------------------------

/// ACPI _BST (Battery Status) method result indices.
const BST_STATE_IDX: usize = 0;
/// Battery present rate (discharge/charge rate in mW or mA).
const BST_RATE_IDX: usize = 1;
/// Battery remaining capacity (mWh or mAh).
const BST_REMAINING_IDX: usize = 2;
/// Battery present voltage (mV).
const BST_VOLTAGE_IDX: usize = 3;

/// ACPI _BIF (Battery Information) design capacity index.
const BIF_DESIGN_CAP_IDX: usize = 1;
/// ACPI _BIF last full charge capacity index.
const BIF_LAST_FULL_IDX: usize = 2;
/// ACPI _BIF design voltage index.
const BIF_DESIGN_VOLTAGE_IDX: usize = 4;

// ---------------------------------------------------------------------------
// MMIO fuel gauge register offsets (generic, e.g. MAX17048/BQ27xxx)
// ---------------------------------------------------------------------------

/// Fuel gauge SOC (State of Charge) register offset.
const FG_SOC_OFF: usize = 0x04;

/// Fuel gauge voltage register offset.
const FG_VCELL_OFF: usize = 0x02;

/// Fuel gauge current register offset.
const FG_CURRENT_OFF: usize = 0x10;

/// Fuel gauge temperature register offset.
const FG_TEMP_OFF: usize = 0x08;

/// Fuel gauge status register offset.
const FG_STATUS_OFF: usize = 0x1A;

/// Fuel gauge configuration register offset.
const FG_CONFIG_OFF: usize = 0x0C;

// ---------------------------------------------------------------------------
// SupplyType
// ---------------------------------------------------------------------------

/// Classification of a power supply device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SupplyType {
    /// Primary battery.
    #[default]
    Battery,
    /// Secondary / auxiliary battery.
    BatteryAux,
    /// AC mains adapter.
    Mains,
    /// USB power delivery.
    Usb,
    /// Wireless charging.
    Wireless,
    /// Unknown supply type.
    Unknown,
}

// ---------------------------------------------------------------------------
// ChargeState
// ---------------------------------------------------------------------------

/// Current charging status of a power supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChargeState {
    /// Not charging (battery discharging or AC disconnected).
    #[default]
    Discharging,
    /// Charging (constant current or constant voltage phase).
    Charging,
    /// Fully charged (trickle/maintenance charge).
    Full,
    /// Charge state unknown or not applicable.
    NotCharging,
    /// Critical — battery level critically low.
    Critical,
}

// ---------------------------------------------------------------------------
// HealthState
// ---------------------------------------------------------------------------

/// Battery health assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthState {
    /// Battery health is good (normal degradation).
    #[default]
    Good,
    /// Battery is overheating.
    Overheat,
    /// Battery is too cold for normal operation.
    Cold,
    /// Battery voltage is above safe limits.
    Overvoltage,
    /// Battery capacity has degraded significantly.
    Degraded,
    /// Unrecoverable battery failure.
    Dead,
    /// Health state unknown.
    Unknown,
}

// ---------------------------------------------------------------------------
// BatteryChemistry
// ---------------------------------------------------------------------------

/// Battery chemistry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BatteryChemistry {
    /// Lithium-ion.
    #[default]
    LiIon,
    /// Lithium polymer.
    LiPo,
    /// Nickel-metal hydride.
    NiMh,
    /// Nickel-cadmium.
    NiCd,
    /// Lead-acid.
    LeadAcid,
    /// Unknown chemistry.
    Unknown,
}

// ---------------------------------------------------------------------------
// BatteryInfo
// ---------------------------------------------------------------------------

/// Detailed battery information snapshot.
///
/// Contains both static properties (design capacity, chemistry) and
/// dynamic measurements (current voltage, temperature, remaining capacity).
#[derive(Debug, Clone, Copy)]
pub struct BatteryInfo {
    /// Battery chemistry.
    pub chemistry: BatteryChemistry,
    /// Design capacity in microwatt-hours (uWh).
    pub design_capacity_uwh: u32,
    /// Last full charge capacity in microwatt-hours (uWh).
    pub last_full_capacity_uwh: u32,
    /// Remaining capacity in microwatt-hours (uWh).
    pub remaining_capacity_uwh: u32,
    /// Design voltage in microvolts (uV).
    pub design_voltage_uv: u32,
    /// Current voltage in microvolts (uV).
    pub voltage_uv: u32,
    /// Current current in microamperes (uA, negative = discharging).
    pub current_ua: i32,
    /// Battery temperature in millicelsius (mC).
    pub temperature_mc: i32,
    /// Capacity percentage (0-100, or [`CAPACITY_UNKNOWN`]).
    pub capacity_percent: u8,
    /// Charge/discharge rate in microwatts (uW).
    pub power_uw: u32,
    /// Estimated time to empty in seconds (0 = unknown).
    pub time_to_empty_secs: u32,
    /// Estimated time to full in seconds (0 = unknown).
    pub time_to_full_secs: u32,
    /// Cycle count (number of full charge/discharge cycles).
    pub cycle_count: u32,
    /// Whether the battery is present (physically connected).
    pub present: bool,
}

impl BatteryInfo {
    /// Creates a default battery info with all fields at their unknown/zero values.
    pub const fn new() -> Self {
        Self {
            chemistry: BatteryChemistry::LiIon,
            design_capacity_uwh: 0,
            last_full_capacity_uwh: 0,
            remaining_capacity_uwh: 0,
            design_voltage_uv: 0,
            voltage_uv: VOLTAGE_UNKNOWN,
            current_ua: CURRENT_UNKNOWN,
            temperature_mc: TEMP_UNKNOWN,
            capacity_percent: CAPACITY_UNKNOWN,
            power_uw: 0,
            time_to_empty_secs: 0,
            time_to_full_secs: 0,
            cycle_count: 0,
            present: false,
        }
    }

    /// Computes the capacity percentage from remaining and last-full capacity.
    pub fn compute_capacity_percent(&mut self) {
        if self.last_full_capacity_uwh == 0 {
            self.capacity_percent = CAPACITY_UNKNOWN;
            return;
        }
        let percent =
            (self.remaining_capacity_uwh as u64 * 100) / self.last_full_capacity_uwh as u64;
        self.capacity_percent = percent.min(100) as u8;
    }

    /// Returns the battery health based on capacity degradation.
    pub fn infer_health(&self) -> HealthState {
        if self.design_capacity_uwh == 0 {
            return HealthState::Unknown;
        }
        if self.temperature_mc != TEMP_UNKNOWN {
            if self.temperature_mc > 60_000 {
                return HealthState::Overheat;
            }
            if self.temperature_mc < -10_000 {
                return HealthState::Cold;
            }
        }
        let ratio = (self.last_full_capacity_uwh as u64 * 100) / self.design_capacity_uwh as u64;
        if ratio < 30 {
            HealthState::Dead
        } else if ratio < 60 {
            HealthState::Degraded
        } else {
            HealthState::Good
        }
    }
}

// ---------------------------------------------------------------------------
// PowerSupplyConfig
// ---------------------------------------------------------------------------

/// Hardware configuration for a power supply device.
#[derive(Debug, Clone, Copy)]
pub struct PowerSupplyConfig {
    /// MMIO base address for fuel gauge registers (0 for ACPI).
    pub mmio_base: usize,
    /// MMIO region size in bytes.
    pub mmio_size: usize,
    /// Supply type.
    pub supply_type: SupplyType,
    /// Whether this supply uses ACPI methods (x86_64).
    pub use_acpi: bool,
    /// IRQ number for status change notifications (0 = polling).
    pub irq: u32,
    /// Polling interval in milliseconds (0 = event-driven).
    pub poll_ms: u32,
}

impl Default for PowerSupplyConfig {
    fn default() -> Self {
        Self {
            mmio_base: 0,
            mmio_size: 0,
            supply_type: SupplyType::Battery,
            use_acpi: true,
            irq: 0,
            poll_ms: 30_000, // 30 seconds
        }
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn read_mmio32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Writes a 32-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn write_mmio32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

/// Reads a 16-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn read_mmio16(base: usize, offset: usize) -> u16 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u16) }
}

// ---------------------------------------------------------------------------
// PowerSupplyEventType
// ---------------------------------------------------------------------------

/// Type of power supply event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSupplyEventType {
    /// AC adapter connected.
    AcConnected,
    /// AC adapter disconnected.
    AcDisconnected,
    /// Battery inserted.
    BatteryInserted,
    /// Battery removed.
    BatteryRemoved,
    /// Charge state changed.
    ChargeStateChanged,
    /// Capacity threshold crossed (low battery, critical).
    CapacityThreshold,
    /// Temperature alert.
    TemperatureAlert,
    /// Health state changed.
    HealthChanged,
}

// ---------------------------------------------------------------------------
// PowerSupplyEvent
// ---------------------------------------------------------------------------

/// A power supply state change notification.
#[derive(Debug, Clone, Copy)]
pub struct PowerSupplyEvent {
    /// Device ID that generated the event.
    pub device_id: u32,
    /// Event type.
    pub event_type: PowerSupplyEventType,
    /// Capacity percentage at time of event.
    pub capacity_percent: u8,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// Constant empty event for array initialisation.
const EMPTY_EVENT: PowerSupplyEvent = PowerSupplyEvent {
    device_id: 0,
    event_type: PowerSupplyEventType::ChargeStateChanged,
    capacity_percent: 0,
    timestamp_ns: 0,
};

// ---------------------------------------------------------------------------
// PowerSupply
// ---------------------------------------------------------------------------

/// A single power supply device (battery, AC adapter, USB, etc.).
///
/// Manages status reporting, capacity measurement, and health monitoring
/// for a single power source.
pub struct PowerSupply {
    /// Unique device identifier.
    pub id: u32,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Hardware configuration.
    pub config: PowerSupplyConfig,
    /// Current charge state.
    pub charge_state: ChargeState,
    /// Current health state.
    pub health: HealthState,
    /// Battery information (meaningful for Battery supply type).
    pub battery: BatteryInfo,
    /// Whether the supply is currently online (connected/present).
    pub online: bool,
    /// Last update timestamp in nanoseconds.
    pub last_update_ns: u64,
    /// Number of status updates performed.
    pub update_count: u64,
    /// Low battery threshold percentage (generates event when crossed).
    pub low_threshold: u8,
    /// Critical battery threshold percentage.
    pub critical_threshold: u8,
    /// Whether the device is registered and active.
    pub active: bool,
}

impl PowerSupply {
    /// Creates a new power supply device.
    pub fn new(id: u32, name: &[u8], config: PowerSupplyConfig) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            config,
            charge_state: ChargeState::Discharging,
            health: HealthState::Unknown,
            battery: BatteryInfo::new(),
            online: false,
            last_update_ns: 0,
            update_count: 0,
            low_threshold: 15,
            critical_threshold: 5,
            active: false,
        }
    }

    /// Initialises the power supply hardware.
    ///
    /// For MMIO fuel gauges, reads the initial configuration register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if hardware access fails.
    pub fn init(&mut self) -> Result<()> {
        match self.config.supply_type {
            SupplyType::Battery | SupplyType::BatteryAux => {
                if self.config.mmio_base != 0 {
                    // Read fuel gauge config to verify communication.
                    // SAFETY: mmio_base non-zero; CONFIG is 32-bit RO.
                    let config_val = unsafe { read_mmio32(self.config.mmio_base, FG_CONFIG_OFF) };
                    // A non-zero config value indicates a responsive device.
                    if config_val == 0 && !self.config.use_acpi {
                        return Err(Error::IoError);
                    }
                }
                self.battery.present = true;
                self.online = true;
            }
            SupplyType::Mains | SupplyType::Usb | SupplyType::Wireless => {
                // AC/USB supplies are always considered present if registered.
                self.online = true;
            }
            SupplyType::Unknown => {}
        }
        self.active = true;
        Ok(())
    }

    /// Returns the current charge/discharge status.
    pub fn get_status(&self) -> ChargeState {
        self.charge_state
    }

    /// Returns the current capacity percentage (0-100).
    ///
    /// Returns [`CAPACITY_UNKNOWN`] if the capacity cannot be determined.
    pub fn get_capacity(&self) -> u8 {
        self.battery.capacity_percent
    }

    /// Returns the current battery voltage in microvolts.
    pub fn get_voltage(&self) -> u32 {
        self.battery.voltage_uv
    }

    /// Returns the current battery health.
    pub fn get_health(&self) -> HealthState {
        self.health
    }

    /// Returns `true` if the supply is currently charging.
    pub fn is_charging(&self) -> bool {
        self.charge_state == ChargeState::Charging
    }

    /// Returns `true` if the supply is online (connected).
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Returns a reference to the battery info.
    pub fn battery_info(&self) -> &BatteryInfo {
        &self.battery
    }

    /// Updates the power supply status from hardware.
    ///
    /// Reads the current voltage, current, temperature, and capacity
    /// from the hardware and updates internal state. Generates events
    /// for threshold crossings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not active.
    pub fn update_status(&mut self, now_ns: u64) -> Result<Option<PowerSupplyEvent>> {
        if !self.active {
            return Err(Error::IoError);
        }

        let prev_capacity = self.battery.capacity_percent;
        let prev_charge_state = self.charge_state;

        if self.config.mmio_base != 0 {
            self.read_mmio_status();
        }

        // Update derived fields.
        self.battery.compute_capacity_percent();
        self.health = self.battery.infer_health();
        self.last_update_ns = now_ns;
        self.update_count += 1;

        // Determine charge state from current direction.
        self.charge_state = if self.battery.current_ua > 0 {
            ChargeState::Charging
        } else if self.battery.capacity_percent >= 100 {
            ChargeState::Full
        } else if self.battery.capacity_percent != CAPACITY_UNKNOWN
            && self.battery.capacity_percent <= self.critical_threshold
        {
            ChargeState::Critical
        } else {
            ChargeState::Discharging
        };

        // Generate events for state changes.
        let event = if self.charge_state != prev_charge_state {
            Some(PowerSupplyEvent {
                device_id: self.id,
                event_type: PowerSupplyEventType::ChargeStateChanged,
                capacity_percent: self.battery.capacity_percent,
                timestamp_ns: now_ns,
            })
        } else if prev_capacity != CAPACITY_UNKNOWN
            && self.battery.capacity_percent != CAPACITY_UNKNOWN
            && prev_capacity > self.low_threshold
            && self.battery.capacity_percent <= self.low_threshold
        {
            Some(PowerSupplyEvent {
                device_id: self.id,
                event_type: PowerSupplyEventType::CapacityThreshold,
                capacity_percent: self.battery.capacity_percent,
                timestamp_ns: now_ns,
            })
        } else {
            None
        };

        Ok(event)
    }

    /// Sets the ACPI _BST (Battery Status) results.
    ///
    /// Called by the ACPI subsystem after evaluating the _BST method.
    pub fn set_acpi_bst(&mut self, state: u32, rate: u32, remaining: u32, voltage: u32) {
        // State bits: 0=discharging, 1=charging, 2=critical
        if state & 0x01 != 0 {
            self.charge_state = ChargeState::Discharging;
        }
        if state & 0x02 != 0 {
            self.charge_state = ChargeState::Charging;
        }
        if state & 0x04 != 0 {
            self.charge_state = ChargeState::Critical;
        }

        // Rate is in mW; convert to uW.
        self.battery.power_uw = rate.saturating_mul(1000);

        // Remaining capacity in mWh; convert to uWh.
        self.battery.remaining_capacity_uwh = remaining.saturating_mul(1000);

        // Voltage in mV; convert to uV.
        self.battery.voltage_uv = voltage.saturating_mul(1000);

        self.battery.compute_capacity_percent();
    }

    /// Sets the ACPI _BIF (Battery Information) static properties.
    pub fn set_acpi_bif(&mut self, design_cap: u32, last_full_cap: u32, design_voltage: u32) {
        // Design capacity in mWh; convert to uWh.
        self.battery.design_capacity_uwh = design_cap.saturating_mul(1000);
        self.battery.last_full_capacity_uwh = last_full_cap.saturating_mul(1000);
        // Design voltage in mV; convert to uV.
        self.battery.design_voltage_uv = design_voltage.saturating_mul(1000);
    }

    /// Sets battery thresholds for event generation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `critical >= low` or values
    /// exceed 100.
    pub fn set_thresholds(&mut self, low: u8, critical: u8) -> Result<()> {
        if critical >= low || low > 100 || critical > 100 {
            return Err(Error::InvalidArgument);
        }
        self.low_threshold = low;
        self.critical_threshold = critical;
        Ok(())
    }

    /// Reads status from MMIO fuel gauge registers.
    fn read_mmio_status(&mut self) {
        let base = self.config.mmio_base;
        if base == 0 {
            return;
        }

        // Read SOC (State of Charge) as a percentage (upper byte).
        // SAFETY: mmio_base valid; FG_SOC_OFF is a 16-bit RO register.
        let soc_raw = unsafe { read_mmio16(base, FG_SOC_OFF) };
        self.battery.capacity_percent = (soc_raw >> 8) as u8;

        // Read voltage (units of 78.125 uV per LSB for MAX17048).
        // SAFETY: mmio_base valid; FG_VCELL_OFF is a 16-bit RO register.
        let vcell = unsafe { read_mmio16(base, FG_VCELL_OFF) };
        // Convert: voltage_uv = vcell * 78125 / 1000 (approximate).
        self.battery.voltage_uv = (vcell as u32).saturating_mul(78);

        // Read current (signed, in microamperes).
        // SAFETY: mmio_base valid; FG_CURRENT_OFF is a 32-bit RO register.
        let current_raw = unsafe { read_mmio32(base, FG_CURRENT_OFF) };
        self.battery.current_ua = current_raw as i32;

        // Read temperature (units of 0.0625 deg C per LSB).
        // SAFETY: mmio_base valid; FG_TEMP_OFF is a 16-bit RO register.
        let temp_raw = unsafe { read_mmio16(base, FG_TEMP_OFF) };
        // Convert to millicelsius: temp_mc = raw * 62.5 / 1000 * 1000.
        self.battery.temperature_mc = (temp_raw as i32 * 625) / 10;
    }
}

// ---------------------------------------------------------------------------
// PowerSupplyRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_SUPPLIES`] power supply devices.
pub struct PowerSupplyRegistry {
    /// Registered power supply devices.
    devices: [Option<PowerSupply>; MAX_SUPPLIES],
    /// Number of registered devices.
    count: usize,
    /// Pending events.
    events: [PowerSupplyEvent; MAX_EVENTS],
    /// Number of pending events.
    event_count: usize,
}

impl Default for PowerSupplyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerSupplyRegistry {
    /// Creates a new, empty power supply registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_SUPPLIES],
            count: 0,
            events: [EMPTY_EVENT; MAX_EVENTS],
            event_count: 0,
        }
    }

    /// Registers a power supply device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, device: PowerSupply) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a power supply by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.devices.iter_mut() {
            let matches = slot.as_ref().is_some_and(|d| d.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a device by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&PowerSupply> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a device by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut PowerSupply> {
        self.devices
            .iter_mut()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Updates all registered devices and collects events.
    ///
    /// Iterates over all active devices, calls `update_status`, and
    /// pushes any generated events into the event queue.
    pub fn update_all(&mut self, now_ns: u64) {
        // Collect events in a temporary buffer to avoid double borrow.
        let mut pending: [Option<PowerSupplyEvent>; MAX_SUPPLIES] = [const { None }; MAX_SUPPLIES];
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if let Some(dev) = slot {
                if !dev.active {
                    continue;
                }
                if let Ok(Some(event)) = dev.update_status(now_ns) {
                    pending[i] = Some(event);
                }
            }
        }
        for evt in pending.into_iter().flatten() {
            self.push_event(evt);
        }
    }

    /// Pushes an event into the event queue.
    fn push_event(&mut self, event: PowerSupplyEvent) {
        if self.event_count < MAX_EVENTS {
            self.events[self.event_count] = event;
            self.event_count += 1;
        }
    }

    /// Pops the oldest event from the queue.
    pub fn pop_event(&mut self) -> Option<PowerSupplyEvent> {
        if self.event_count == 0 {
            return None;
        }
        let event = self.events[0];
        let remaining = self.event_count - 1;
        for i in 0..remaining {
            self.events[i] = self.events[i + 1];
        }
        self.event_count -= 1;
        Some(event)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of pending events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Returns `true` if any AC adapter is online.
    pub fn ac_online(&self) -> bool {
        self.devices
            .iter()
            .flatten()
            .any(|d| d.config.supply_type == SupplyType::Mains && d.online)
    }

    /// Returns the lowest battery capacity percentage across all batteries.
    ///
    /// Returns [`CAPACITY_UNKNOWN`] if no batteries are registered.
    pub fn lowest_battery_capacity(&self) -> u8 {
        let mut min = CAPACITY_UNKNOWN;
        for dev in self.devices.iter().flatten() {
            let is_battery = matches!(
                dev.config.supply_type,
                SupplyType::Battery | SupplyType::BatteryAux
            );
            if is_battery
                && dev.active
                && dev.battery.capacity_percent != CAPACITY_UNKNOWN
                && dev.battery.capacity_percent < min
            {
                min = dev.battery.capacity_percent;
            }
        }
        min
    }
}
