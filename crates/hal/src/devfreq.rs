// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device frequency scaling (devfreq) subsystem.
//!
//! Provides a Linux-inspired devfreq framework for dynamic voltage and
//! frequency scaling (DVFS) of hardware devices. Each device registers
//! a set of operating performance points (OPPs), a governor selects the
//! target frequency based on load, and the HAL applies the new OPP.
//!
//! # Architecture
//!
//! ```text
//! Monitoring timer / IRQ
//!       │  update_utilization()
//!       ▼
//! DevfreqDevice
//!       │  governor.target_freq(util, opps)
//!       ▼
//! OppTable → find_best_opp()
//!       │  apply_opp()  (platform callback)
//!       ▼
//! hardware clock / voltage regulator
//! ```
//!
//! # Governors
//!
//! Three governors are provided:
//! - **Performance**: always selects the highest OPP.
//! - **PowerSave**: always selects the lowest OPP.
//! - **SimpleOndemand**: scales up when utilization exceeds
//!   `upthreshold` and scales down when it falls below
//!   `downthreshold`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────

/// Maximum operating performance points per device.
const MAX_OPPS: usize = 16;
/// Maximum devfreq devices in the system.
const MAX_DEVFREQ_DEVICES: usize = 8;
/// Utilization scale (100 = fully loaded).
const UTIL_SCALE: u32 = 100;

// ── Operating Performance Point ───────────────────────────────

/// A single operating performance point (OPP).
///
/// Describes a hardware state combining a frequency in Hz and
/// a voltage in millivolts. The platform DVFS callback uses both
/// values to transition the hardware.
#[derive(Debug, Clone, Copy)]
pub struct Opp {
    /// Operating frequency in Hz (e.g., 1_000_000_000 for 1 GHz).
    pub freq_hz: u64,
    /// Supply voltage in millivolts (e.g., 1000 for 1.0 V).
    pub voltage_mv: u32,
    /// Whether this OPP is currently enabled/available.
    pub enabled: bool,
}

impl Default for Opp {
    fn default() -> Self {
        Self::new()
    }
}

impl Opp {
    /// Create a disabled OPP with zero frequency and voltage.
    pub const fn new() -> Self {
        Self {
            freq_hz: 0,
            voltage_mv: 0,
            enabled: false,
        }
    }

    /// Create an enabled OPP with the given frequency and voltage.
    pub const fn with_values(freq_hz: u64, voltage_mv: u32) -> Self {
        Self {
            freq_hz,
            voltage_mv,
            enabled: true,
        }
    }
}

// ── OPP Table ─────────────────────────────────────────────────

/// Sorted table of operating performance points for a device.
///
/// OPPs are stored in ascending order of frequency. The table is
/// populated at device registration time and remains fixed
/// thereafter.
#[derive(Debug)]
pub struct OppTable {
    /// OPP entries (sorted ascending by `freq_hz`).
    opps: [Opp; MAX_OPPS],
    /// Number of valid OPP entries.
    count: usize,
}

impl Default for OppTable {
    fn default() -> Self {
        Self::new()
    }
}

impl OppTable {
    /// Create an empty OPP table.
    pub const fn new() -> Self {
        Self {
            opps: [const { Opp::new() }; MAX_OPPS],
            count: 0,
        }
    }

    /// Add an OPP to the table.
    ///
    /// OPPs must be added in ascending frequency order.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::InvalidArgument`] if `freq_hz` is zero or if the new
    ///   OPP is not higher than the last-added OPP.
    pub fn add_opp(&mut self, freq_hz: u64, voltage_mv: u32) -> Result<()> {
        if freq_hz == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count > 0 && freq_hz <= self.opps[self.count - 1].freq_hz {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_OPPS {
            return Err(Error::OutOfMemory);
        }
        self.opps[self.count] = Opp::with_values(freq_hz, voltage_mv);
        self.count += 1;
        Ok(())
    }

    /// Find the lowest OPP whose frequency is >= `target_hz`.
    ///
    /// Returns `None` if the table is empty or `target_hz` exceeds
    /// the maximum available frequency.
    pub fn find_ceil(&self, target_hz: u64) -> Option<&Opp> {
        self.opps[..self.count]
            .iter()
            .find(|o| o.enabled && o.freq_hz >= target_hz)
    }

    /// Find the highest OPP whose frequency is <= `target_hz`.
    ///
    /// Returns `None` if `target_hz` is below the lowest OPP.
    pub fn find_floor(&self, target_hz: u64) -> Option<&Opp> {
        self.opps[..self.count]
            .iter()
            .rev()
            .find(|o| o.enabled && o.freq_hz <= target_hz)
    }

    /// Return the minimum (lowest-frequency) enabled OPP.
    pub fn min_opp(&self) -> Option<&Opp> {
        self.opps[..self.count].iter().find(|o| o.enabled)
    }

    /// Return the maximum (highest-frequency) enabled OPP.
    pub fn max_opp(&self) -> Option<&Opp> {
        self.opps[..self.count].iter().rev().find(|o| o.enabled)
    }

    /// Return the number of OPPs in the table.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return a slice of all OPPs (enabled and disabled).
    pub fn all_opps(&self) -> &[Opp] {
        &self.opps[..self.count]
    }
}

// ── Governor ──────────────────────────────────────────────────

/// Devfreq governor identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorKind {
    /// Always use the maximum available frequency.
    Performance,
    /// Always use the minimum available frequency.
    PowerSave,
    /// Scale based on measured device utilization.
    SimpleOndemand,
}

/// Governor-specific tuning parameters.
#[derive(Debug, Clone, Copy)]
pub struct GovernorParams {
    /// Utilization threshold (0–100) above which frequency is raised.
    /// Only used by [`GovernorKind::SimpleOndemand`].
    pub upthreshold: u32,
    /// Utilization threshold (0–100) below which frequency is lowered.
    /// Only used by [`GovernorKind::SimpleOndemand`].
    pub downthreshold: u32,
}

impl Default for GovernorParams {
    fn default() -> Self {
        Self {
            upthreshold: 80,
            downthreshold: 20,
        }
    }
}

impl GovernorParams {
    /// Create default governor parameters.
    pub const fn new() -> Self {
        Self {
            upthreshold: 80,
            downthreshold: 20,
        }
    }
}

// ── Devfreq Statistics ────────────────────────────────────────

/// Per-device frequency scaling statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DevfreqStats {
    /// Number of frequency transitions performed.
    pub transitions: u64,
    /// Number of transitions that increased frequency.
    pub scale_ups: u64,
    /// Number of transitions that decreased frequency.
    pub scale_downs: u64,
    /// Number of times the frequency was left unchanged.
    pub no_changes: u64,
    /// Total utilization samples collected.
    pub samples: u64,
}

// ── Devfreq Device ────────────────────────────────────────────

/// A devfreq-managed device.
///
/// Tracks the current operating frequency, available OPPs,
/// governor settings, and utilization history for a single
/// hardware device.
pub struct DevfreqDevice {
    /// Unique device identifier (e.g., PCI BDF or platform ID).
    device_id: u32,
    /// Human-readable device name (null-terminated, up to 31 chars).
    name: [u8; 32],
    /// OPP table for this device.
    opp_table: OppTable,
    /// Active governor kind.
    governor: GovernorKind,
    /// Governor tuning parameters.
    governor_params: GovernorParams,
    /// Current operating frequency in Hz.
    current_freq: u64,
    /// Current supply voltage in millivolts.
    current_voltage_mv: u32,
    /// Latest measured utilization (0–100).
    utilization: u32,
    /// Whether DVFS is currently enabled for this device.
    enabled: bool,
    /// Whether the device has been fully initialized.
    initialized: bool,
    /// Accumulated frequency-scaling statistics.
    stats: DevfreqStats,
}

impl DevfreqDevice {
    /// Create a new devfreq device with the given ID and name.
    ///
    /// The device starts disabled; call [`DevfreqDevice::init`] to
    /// populate the OPP table and enable scaling.
    pub fn new(device_id: u32, name: &[u8]) -> Self {
        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(31);
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        Self {
            device_id,
            name: name_buf,
            opp_table: OppTable::new(),
            governor: GovernorKind::SimpleOndemand,
            governor_params: GovernorParams::new(),
            current_freq: 0,
            current_voltage_mv: 0,
            utilization: 0,
            enabled: false,
            initialized: false,
            stats: DevfreqStats::default(),
        }
    }

    /// Initialize the device and set the initial frequency to the
    /// minimum available OPP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the OPP table is empty.
    pub fn init(&mut self) -> Result<()> {
        let min = self.opp_table.min_opp().ok_or(Error::NotFound)?;
        self.current_freq = min.freq_hz;
        self.current_voltage_mv = min.voltage_mv;
        self.initialized = true;
        self.enabled = true;
        Ok(())
    }

    /// Add an operating performance point to this device.
    ///
    /// Must be called before [`DevfreqDevice::init`].
    ///
    /// # Errors
    ///
    /// Propagates errors from [`OppTable::add_opp`].
    pub fn add_opp(&mut self, freq_hz: u64, voltage_mv: u32) -> Result<()> {
        self.opp_table.add_opp(freq_hz, voltage_mv)
    }

    /// Update the device utilization and trigger a governor decision.
    ///
    /// The `utilization` parameter should be in the range 0–100.
    /// If the governor selects a different OPP, `new_freq_hz` in the
    /// returned [`FreqTransition`] will differ from `current_freq`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the device is not enabled.
    /// Returns [`Error::NotFound`] if no suitable OPP is found.
    pub fn update_utilization(&mut self, utilization: u32) -> Result<FreqTransition> {
        if !self.enabled || !self.initialized {
            return Err(Error::Busy);
        }

        self.utilization = utilization.min(UTIL_SCALE);
        self.stats.samples += 1;

        let target_freq = self.governor_target_freq()?;
        let prev_freq = self.current_freq;

        if target_freq == prev_freq {
            self.stats.no_changes += 1;
            return Ok(FreqTransition {
                prev_freq,
                new_freq: target_freq,
                voltage_mv: self.current_voltage_mv,
                changed: false,
            });
        }

        // Find the OPP for the target frequency.
        let opp = self
            .opp_table
            .find_ceil(target_freq)
            .or_else(|| self.opp_table.max_opp())
            .ok_or(Error::NotFound)?;

        let new_freq = opp.freq_hz;
        let new_voltage = opp.voltage_mv;

        if new_freq > prev_freq {
            self.stats.scale_ups += 1;
        } else {
            self.stats.scale_downs += 1;
        }
        self.stats.transitions += 1;

        self.current_freq = new_freq;
        self.current_voltage_mv = new_voltage;

        Ok(FreqTransition {
            prev_freq,
            new_freq,
            voltage_mv: new_voltage,
            changed: true,
        })
    }

    /// Calculate the target frequency according to the active governor.
    fn governor_target_freq(&self) -> Result<u64> {
        match self.governor {
            GovernorKind::Performance => {
                Ok(self.opp_table.max_opp().ok_or(Error::NotFound)?.freq_hz)
            }
            GovernorKind::PowerSave => Ok(self.opp_table.min_opp().ok_or(Error::NotFound)?.freq_hz),
            GovernorKind::SimpleOndemand => {
                let util = self.utilization;
                let params = &self.governor_params;
                if util >= params.upthreshold {
                    Ok(self.opp_table.max_opp().ok_or(Error::NotFound)?.freq_hz)
                } else if util <= params.downthreshold {
                    Ok(self.opp_table.min_opp().ok_or(Error::NotFound)?.freq_hz)
                } else {
                    // Scale linearly between min and max.
                    let min_freq = self.opp_table.min_opp().ok_or(Error::NotFound)?.freq_hz;
                    let max_freq = self.opp_table.max_opp().ok_or(Error::NotFound)?.freq_hz;
                    let range = max_freq - min_freq;
                    let target = min_freq + (range * util as u64) / UTIL_SCALE as u64;
                    Ok(target)
                }
            }
        }
    }

    /// Change the active governor.
    pub fn set_governor(&mut self, governor: GovernorKind) {
        self.governor = governor;
    }

    /// Update governor tuning parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `upthreshold <= downthreshold`
    /// or either value exceeds 100.
    pub fn set_governor_params(&mut self, params: GovernorParams) -> Result<()> {
        if params.upthreshold > UTIL_SCALE
            || params.downthreshold > UTIL_SCALE
            || params.upthreshold <= params.downthreshold
        {
            return Err(Error::InvalidArgument);
        }
        self.governor_params = params;
        Ok(())
    }

    /// Force the device to a specific frequency, bypassing the governor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no OPP at or above `freq_hz` exists.
    pub fn set_freq(&mut self, freq_hz: u64) -> Result<()> {
        let opp = self
            .opp_table
            .find_ceil(freq_hz)
            .or_else(|| self.opp_table.max_opp())
            .ok_or(Error::NotFound)?;

        self.current_freq = opp.freq_hz;
        self.current_voltage_mv = opp.voltage_mv;
        self.stats.transitions += 1;
        Ok(())
    }

    /// Enable or disable DVFS for this device.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Return the current operating frequency in Hz.
    pub const fn current_freq(&self) -> u64 {
        self.current_freq
    }

    /// Return the current supply voltage in millivolts.
    pub const fn current_voltage_mv(&self) -> u32 {
        self.current_voltage_mv
    }

    /// Return the latest utilization value (0–100).
    pub const fn utilization(&self) -> u32 {
        self.utilization
    }

    /// Return whether DVFS is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return a reference to the OPP table.
    pub const fn opp_table(&self) -> &OppTable {
        &self.opp_table
    }

    /// Return accumulated statistics.
    pub const fn stats(&self) -> &DevfreqStats {
        &self.stats
    }

    /// Return the device ID.
    pub const fn device_id(&self) -> u32 {
        self.device_id
    }

    /// Return the device name as a byte slice (null-terminated).
    pub fn name(&self) -> &[u8] {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(32);
        &self.name[..end]
    }

    /// Return the active governor kind.
    pub const fn governor(&self) -> GovernorKind {
        self.governor
    }
}

// ── Frequency Transition ──────────────────────────────────────

/// Describes a frequency transition resulting from a governor decision.
#[derive(Debug, Clone, Copy)]
pub struct FreqTransition {
    /// Frequency before the transition (Hz).
    pub prev_freq: u64,
    /// Frequency after the transition (Hz).
    pub new_freq: u64,
    /// Supply voltage after the transition (mV).
    pub voltage_mv: u32,
    /// Whether the frequency actually changed.
    pub changed: bool,
}

// ── Devfreq Registry ──────────────────────────────────────────

/// Registry of all devfreq-managed devices.
pub struct DevfreqRegistry {
    /// Device slots.
    devices: [Option<DevfreqDevice>; MAX_DEVFREQ_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for DevfreqRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DevfreqRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None, None, None, None, None],
            count: 0,
        }
    }

    /// Register a devfreq device.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a device with the same ID exists.
    pub fn register(&mut self, device: DevfreqDevice) -> Result<usize> {
        let id = device.device_id();
        let exists = self.devices[..self.count]
            .iter()
            .flatten()
            .any(|d| d.device_id() == id);
        if exists {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_DEVFREQ_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a device by its ID.
    pub fn get_mut_by_id(&mut self, device_id: u32) -> Option<&mut DevfreqDevice> {
        self.devices[..self.count]
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|d| d.device_id() == device_id)
    }

    /// Get a shared reference to a device by its ID.
    pub fn get_by_id(&self, device_id: u32) -> Option<&DevfreqDevice> {
        self.devices[..self.count]
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|d| d.device_id() == device_id)
    }

    /// Return the number of registered devices.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Update all registered devices with the latest utilization data.
    ///
    /// `util_fn` is called with each device's ID and expected to return
    /// a utilization value (0–100) or an error.
    pub fn update_all<F>(&mut self, mut util_fn: F)
    where
        F: FnMut(u32) -> u32,
    {
        for slot in &mut self.devices[..self.count] {
            if let Some(dev) = slot.as_mut() {
                let util = util_fn(dev.device_id());
                let _ = dev.update_utilization(util);
            }
        }
    }
}
