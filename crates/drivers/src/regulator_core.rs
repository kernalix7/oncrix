// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Voltage/current regulator framework for the ONCRIX operating system.
//!
//! Provides a generic power-regulator subsystem modelled after the Linux
//! regulator API. Supports fixed-voltage, adjustable-voltage, and
//! current-limiting regulators. Tracks consumer reference counts, voltage
//! constraints, enable/disable control, and supply chain relationships.
//!
//! # Architecture
//!
//! - **RegulatorType** — fixed-voltage, adjustable-voltage, or current
//! - **RegulatorMode** — operating mode (fast/normal/idle/standby)
//! - **RegulatorConstraints** — hardware-enforced voltage/current limits
//! - **RegulatorDesc** — descriptor linking a regulator to its supply
//! - **Regulator** — a single power regulator instance with state tracking
//! - **RegulatorRegistry** — manages up to [`MAX_REGULATORS`] regulators
//!
//! # Reference
//!
//! Linux: `drivers/regulator/core.c`, `include/linux/regulator/consumer.h`,
//! `include/linux/regulator/driver.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of regulators in the registry.
const MAX_REGULATORS: usize = 32;

/// Maximum number of consumers per regulator.
const MAX_CONSUMERS: usize = 8;

/// Maximum regulator name length.
const MAX_NAME_LEN: usize = 32;

/// Maximum number of voltage table entries.
const MAX_VOLT_TABLE: usize = 32;

/// Special value for an unconstrained (unlimited) maximum.
pub const REGULATOR_NO_LIMIT: i64 = i64::MAX;

// ---------------------------------------------------------------------------
// RegulatorType
// ---------------------------------------------------------------------------

/// Classification of a voltage/current regulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegulatorType {
    /// Fixed-output voltage regulator (e.g. LDO with fixed rail).
    #[default]
    FixedVoltage,
    /// Adjustable-voltage regulator (e.g. Buck/Boost DC-DC converter).
    AdjustableVoltage,
    /// Fixed-output current source.
    FixedCurrent,
    /// Adjustable current limiter/source.
    AdjustableCurrent,
}

// ---------------------------------------------------------------------------
// RegulatorMode
// ---------------------------------------------------------------------------

/// Operating mode of a regulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegulatorMode {
    /// Fast mode: highest performance, may increase quiescent current.
    Fast,
    /// Normal mode: balanced performance and efficiency.
    #[default]
    Normal,
    /// Idle mode: reduced load, lower quiescent current.
    Idle,
    /// Standby mode: minimal quiescent current, slow transient response.
    Standby,
}

// ---------------------------------------------------------------------------
// RegulatorConstraints
// ---------------------------------------------------------------------------

/// Hardware-enforced voltage and current constraints for a regulator.
///
/// The regulator framework will reject any request that violates these
/// limits, protecting hardware from over-voltage or under-voltage conditions.
#[derive(Debug, Clone, Copy)]
pub struct RegulatorConstraints {
    /// Minimum allowed output voltage in microvolts (µV).
    pub min_uv: i64,
    /// Maximum allowed output voltage in microvolts (µV).
    pub max_uv: i64,
    /// Minimum allowed output current in microamps (µA).
    pub min_ua: i64,
    /// Maximum allowed output current in microamps (µA).
    pub max_ua: i64,
    /// Whether enable/disable is software-controllable.
    pub software_enabled: bool,
    /// Whether the voltage is software-adjustable.
    pub voltage_adjustable: bool,
    /// Whether the current limit is software-adjustable.
    pub current_adjustable: bool,
    /// Whether this regulator must always be on (critical supply).
    pub always_on: bool,
    /// Whether to enable the regulator at boot.
    pub boot_on: bool,
    /// Minimum hardware settling time in microseconds after enable.
    pub enable_time_us: u32,
    /// Minimum hardware settling time in microseconds after voltage change.
    pub ramp_delay_us: u32,
}

impl Default for RegulatorConstraints {
    fn default() -> Self {
        Self {
            min_uv: 0,
            max_uv: REGULATOR_NO_LIMIT,
            min_ua: 0,
            max_ua: REGULATOR_NO_LIMIT,
            software_enabled: true,
            voltage_adjustable: false,
            current_adjustable: false,
            always_on: false,
            boot_on: false,
            enable_time_us: 0,
            ramp_delay_us: 0,
        }
    }
}

impl RegulatorConstraints {
    /// Creates constraints for a fixed-voltage regulator at `fixed_uv`.
    pub fn fixed_voltage(fixed_uv: i64) -> Self {
        Self {
            min_uv: fixed_uv,
            max_uv: fixed_uv,
            software_enabled: true,
            ..Self::default()
        }
    }

    /// Creates constraints for an adjustable regulator.
    pub fn adjustable(min_uv: i64, max_uv: i64) -> Self {
        Self {
            min_uv,
            max_uv,
            voltage_adjustable: true,
            software_enabled: true,
            ..Self::default()
        }
    }

    /// Returns `true` if `uv` is within the voltage constraints.
    pub fn voltage_in_range(&self, uv: i64) -> bool {
        uv >= self.min_uv && (self.max_uv == REGULATOR_NO_LIMIT || uv <= self.max_uv)
    }

    /// Returns `true` if `ua` is within the current constraints.
    pub fn current_in_range(&self, ua: i64) -> bool {
        ua >= self.min_ua && (self.max_ua == REGULATOR_NO_LIMIT || ua <= self.max_ua)
    }
}

// ---------------------------------------------------------------------------
// RegulatorVoltageTable
// ---------------------------------------------------------------------------

/// A discrete voltage table for regulators with fixed voltage steps.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegulatorVoltageTable {
    /// Voltage values in µV (sorted ascending).
    pub voltages: [i64; MAX_VOLT_TABLE],
    /// Number of valid entries.
    pub count: usize,
}

impl RegulatorVoltageTable {
    /// Creates an empty voltage table.
    pub const fn new() -> Self {
        Self {
            voltages: [0i64; MAX_VOLT_TABLE],
            count: 0,
        }
    }

    /// Adds a voltage entry to the table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add(&mut self, uv: i64) -> Result<()> {
        if self.count >= MAX_VOLT_TABLE {
            return Err(Error::OutOfMemory);
        }
        self.voltages[self.count] = uv;
        self.count += 1;
        Ok(())
    }

    /// Returns the nearest valid voltage to `target_uv`.
    ///
    /// Returns `None` if the table is empty.
    pub fn nearest(&self, target_uv: i64) -> Option<i64> {
        if self.count == 0 {
            return None;
        }
        let mut best = self.voltages[0];
        let mut best_diff = (best - target_uv).unsigned_abs();
        for &v in &self.voltages[1..self.count] {
            let diff = (v - target_uv).unsigned_abs();
            if diff < best_diff {
                best = v;
                best_diff = diff;
            }
        }
        Some(best)
    }
}

// ---------------------------------------------------------------------------
// RegulatorConsumer
// ---------------------------------------------------------------------------

/// A registered consumer of a regulator.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegulatorConsumer {
    /// Consumer name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Whether this consumer slot is occupied.
    pub active: bool,
    /// Requested minimum voltage in µV (0 = no preference).
    pub req_min_uv: i64,
    /// Requested maximum voltage in µV (0 = no preference).
    pub req_max_uv: i64,
}

impl RegulatorConsumer {
    /// Creates a new consumer descriptor.
    pub fn new(name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut consumer = Self::default();
        consumer.name[..copy_len].copy_from_slice(&name[..copy_len]);
        consumer.name_len = copy_len;
        consumer.active = true;
        consumer
    }
}

// ---------------------------------------------------------------------------
// Regulator
// ---------------------------------------------------------------------------

/// A single power regulator instance.
///
/// Tracks the regulator's type, constraints, current operating voltage,
/// enable reference count, consumer list, and optional supply chain
/// (parent regulator index within the registry).
pub struct Regulator {
    /// Unique regulator identifier.
    pub id: u32,
    /// Human-readable name (UTF-8).
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Regulator type.
    pub reg_type: RegulatorType,
    /// Operating mode.
    pub mode: RegulatorMode,
    /// Hardware constraints.
    pub constraints: RegulatorConstraints,
    /// Current output voltage in µV.
    pub current_uv: i64,
    /// Current output current limit in µA.
    pub current_ua: i64,
    /// Enable reference count (0 = disabled, >0 = enabled).
    pub enable_count: u32,
    /// Whether the hardware is currently enabled.
    pub hw_enabled: bool,
    /// Whether this regulator is registered and valid.
    pub valid: bool,
    /// Registered consumers.
    pub consumers: [Option<RegulatorConsumer>; MAX_CONSUMERS],
    /// Number of registered consumers.
    pub consumer_count: usize,
    /// Optional supply (parent) regulator ID (0 = no parent).
    pub supply_id: u32,
    /// Optional voltage table for discrete-step regulators.
    pub volt_table: RegulatorVoltageTable,
    /// MMIO base address for the regulator control registers (0 if none).
    pub mmio_base: usize,
}

impl Regulator {
    /// Creates a new regulator.
    pub fn new(
        id: u32,
        name: &[u8],
        reg_type: RegulatorType,
        constraints: RegulatorConstraints,
    ) -> Self {
        let copy_len = name.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        // Set initial voltage to minimum constraint
        let current_uv = constraints.min_uv;

        Self {
            id,
            name: name_buf,
            name_len: copy_len,
            reg_type,
            mode: RegulatorMode::Normal,
            current_uv,
            current_ua: constraints.min_ua,
            enable_count: 0,
            hw_enabled: constraints.always_on || constraints.boot_on,
            valid: true,
            consumers: [const { None }; MAX_CONSUMERS],
            consumer_count: 0,
            supply_id: 0,
            volt_table: RegulatorVoltageTable::new(),
            mmio_base: 0,
            constraints,
        }
    }

    /// Returns the regulator name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Enables the regulator (increments enable reference count).
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the constraints do not allow
    /// software enable control.
    pub fn enable(&mut self) -> Result<()> {
        if !self.constraints.software_enabled && !self.constraints.always_on {
            return Err(Error::PermissionDenied);
        }
        self.enable_count = self.enable_count.saturating_add(1);
        self.hw_enabled = true;
        Ok(())
    }

    /// Disables the regulator (decrements enable reference count).
    ///
    /// The hardware is only actually disabled when the reference count
    /// reaches zero and `always_on` is not set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the regulator is `always_on`.
    /// Returns [`Error::InvalidArgument`] if already disabled.
    pub fn disable(&mut self) -> Result<()> {
        if self.constraints.always_on {
            return Err(Error::PermissionDenied);
        }
        if self.enable_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.enable_count -= 1;
        if self.enable_count == 0 {
            self.hw_enabled = false;
        }
        Ok(())
    }

    /// Returns `true` if the regulator is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.hw_enabled || self.enable_count > 0
    }

    /// Sets the output voltage.
    ///
    /// Finds the nearest valid voltage if a voltage table is configured.
    /// Validates against constraints before applying.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if voltage is not adjustable, or
    /// [`Error::InvalidArgument`] if `uv` is outside constraints.
    pub fn set_voltage(&mut self, uv: i64) -> Result<()> {
        if !self.constraints.voltage_adjustable {
            return Err(Error::PermissionDenied);
        }

        // Use voltage table if available
        let target_uv = if self.volt_table.count > 0 {
            self.volt_table.nearest(uv).ok_or(Error::InvalidArgument)?
        } else {
            uv
        };

        if !self.constraints.voltage_in_range(target_uv) {
            return Err(Error::InvalidArgument);
        }
        self.current_uv = target_uv;
        Ok(())
    }

    /// Returns the current output voltage in µV.
    pub fn get_voltage(&self) -> i64 {
        self.current_uv
    }

    /// Sets the current limit in µA.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if current is not adjustable, or
    /// [`Error::InvalidArgument`] if `ua` is outside constraints.
    pub fn set_current_limit(&mut self, ua: i64) -> Result<()> {
        if !self.constraints.current_adjustable {
            return Err(Error::PermissionDenied);
        }
        if !self.constraints.current_in_range(ua) {
            return Err(Error::InvalidArgument);
        }
        self.current_ua = ua;
        Ok(())
    }

    /// Returns the current limit in µA.
    pub fn get_current_limit(&self) -> i64 {
        self.current_ua
    }

    /// Sets the operating mode.
    pub fn set_mode(&mut self, mode: RegulatorMode) {
        self.mode = mode;
    }

    /// Registers a consumer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the consumer table is full.
    pub fn register_consumer(&mut self, consumer: RegulatorConsumer) -> Result<()> {
        if self.consumer_count >= MAX_CONSUMERS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.consumers.iter_mut() {
            if slot.is_none() {
                *slot = Some(consumer);
                self.consumer_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a consumer by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the consumer is not found.
    pub fn unregister_consumer(&mut self, name: &[u8]) -> Result<()> {
        let copy_len = name.len().min(32);
        for slot in self.consumers.iter_mut() {
            let matches = slot.as_ref().is_some_and(|c| {
                c.name_len == copy_len && c.name[..c.name_len] == name[..copy_len]
            });
            if matches {
                *slot = None;
                self.consumer_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Computes the optimal voltage satisfying all registered consumer requests.
    ///
    /// Returns the highest `req_min_uv` across all consumers that is still
    /// within the regulator's constraints. Returns `current_uv` if no
    /// consumers have preferences.
    pub fn resolve_consumer_voltage(&self) -> i64 {
        let mut best = self.current_uv;
        for consumer in self.consumers.iter().flatten() {
            if consumer.req_min_uv > best {
                best = consumer.req_min_uv;
            }
        }
        // Clamp to constraints
        if best < self.constraints.min_uv {
            best = self.constraints.min_uv;
        }
        if self.constraints.max_uv != REGULATOR_NO_LIMIT && best > self.constraints.max_uv {
            best = self.constraints.max_uv;
        }
        best
    }
}

// ---------------------------------------------------------------------------
// RegulatorRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_REGULATORS`] power regulators.
///
/// Supports registration, lookup by ID or name, enable/disable, voltage
/// and current queries, and supply-chain resolution.
pub struct RegulatorRegistry {
    /// Regulator storage.
    regulators: [Option<Regulator>; MAX_REGULATORS],
    /// Number of registered regulators.
    count: usize,
}

impl Default for RegulatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RegulatorRegistry {
    /// Creates a new, empty regulator registry.
    pub const fn new() -> Self {
        Self {
            regulators: [const { None }; MAX_REGULATORS],
            count: 0,
        }
    }

    /// Registers a regulator.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a regulator with the same `id` exists.
    pub fn register(&mut self, reg: Regulator) -> Result<()> {
        for slot in self.regulators.iter().flatten() {
            if slot.id == reg.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.regulators.iter_mut() {
            if slot.is_none() {
                *slot = Some(reg);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a regulator by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the regulator still has consumers, or
    /// [`Error::NotFound`] if not registered.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.regulators.iter_mut() {
            let matches = slot.as_ref().is_some_and(|r| r.id == id);
            if matches {
                let busy = slot.as_ref().is_some_and(|r| r.consumer_count > 0);
                if busy {
                    return Err(Error::Busy);
                }
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to a regulator by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&Regulator> {
        self.regulators
            .iter()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a regulator by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut Regulator> {
        self.regulators
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)
    }

    /// Looks up a regulator handle by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching regulator is registered.
    pub fn find_by_name(&self, name: &[u8]) -> Result<u32> {
        let copy_len = name.len().min(MAX_NAME_LEN);
        for reg in self.regulators.iter().flatten() {
            if reg.name_len == copy_len && reg.name[..reg.name_len] == name[..copy_len] {
                return Ok(reg.id);
            }
        }
        Err(Error::NotFound)
    }

    /// Enables a regulator by `id`.
    ///
    /// Also enables any supply (parent) regulator in the chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or propagates enable errors.
    pub fn enable(&mut self, id: u32) -> Result<()> {
        // Enable the supply chain first
        let supply_id = self
            .regulators
            .iter()
            .flatten()
            .find(|r| r.id == id)
            .map(|r| r.supply_id)
            .ok_or(Error::NotFound)?;

        if supply_id != 0 {
            self.enable(supply_id)?;
        }

        let reg = self
            .regulators
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        reg.enable()
    }

    /// Disables a regulator by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or propagates disable errors.
    pub fn disable(&mut self, id: u32) -> Result<()> {
        let reg = self
            .regulators
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        reg.disable()
    }

    /// Sets the voltage of a regulator by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or propagates set_voltage errors.
    pub fn set_voltage(&mut self, id: u32, uv: i64) -> Result<()> {
        let reg = self
            .regulators
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        reg.set_voltage(uv)
    }

    /// Returns the current voltage of a regulator by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_voltage(&self, id: u32) -> Result<i64> {
        Ok(self.get(id)?.current_uv)
    }

    /// Returns the number of registered regulators.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no regulators are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Applies `always_on` / `boot_on` constraints for all registered regulators.
    ///
    /// Should be called once during platform initialisation to ensure
    /// critical regulators are enabled before any driver brings up devices.
    pub fn apply_boot_constraints(&mut self) {
        for slot in self.regulators.iter_mut().flatten() {
            if slot.constraints.always_on || slot.constraints.boot_on {
                slot.hw_enabled = true;
                slot.enable_count = slot.enable_count.saturating_add(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RegulatorSummary
// ---------------------------------------------------------------------------

/// Snapshot of a regulator's current state for diagnostics.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegulatorSummary {
    /// Regulator ID.
    pub id: u32,
    /// Current voltage in µV.
    pub current_uv: i64,
    /// Current limit in µA.
    pub current_ua: i64,
    /// Enable reference count.
    pub enable_count: u32,
    /// Whether hardware is enabled.
    pub hw_enabled: bool,
    /// Number of consumers.
    pub consumer_count: usize,
}

impl RegulatorSummary {
    /// Creates a summary snapshot from a `Regulator`.
    pub fn from_regulator(reg: &Regulator) -> Self {
        Self {
            id: reg.id,
            current_uv: reg.current_uv,
            current_ua: reg.current_ua,
            enable_count: reg.enable_count,
            hw_enabled: reg.hw_enabled,
            consumer_count: reg.consumer_count,
        }
    }
}
