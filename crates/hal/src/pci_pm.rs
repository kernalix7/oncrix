// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI Power Management (PCI-PM) state machine and wake support.
//!
//! Implements the PCI Bus Power Management Interface Specification
//! rev 1.2. Each device progresses through five power states:
//! D0 (fully on) through D3cold (fully off), with intermediate
//! states D1, D2, and D3hot providing graduated power savings.
//!
//! # Architecture
//!
//! - **PciPowerState** — the five PCI-PM states.
//! - **PmCapability** — parsed capability from PCI config space
//!   (capability ID 0x01).
//! - **PciPmDevice** — per-device state machine with transition
//!   validation, PME support, and wake arming.
//! - **PciPmSubsystem** — registry of up to 64 PM-managed devices.
//!
//! # Transition Rules
//!
//! ```text
//! D0  →  D1 | D2 | D3hot | D3cold   (if supported)
//! D1  →  D0 | D2 | D3hot | D3cold
//! D2  →  D0 | D3hot | D3cold
//! D3hot → D0 (via re-init)
//! D3cold → D0 (full re-initialisation required)
//! ```
//!
//! Reference: PCI Bus Power Management Interface Specification,
//!            Revision 1.2 (2004).

use oncrix_lib::{Error, Result};

// ── PME support mask bits ────────────────────────────────────

/// PME# can be asserted from D0.
pub const PME_FROM_D0: u16 = 1 << 0;
/// PME# can be asserted from D1.
pub const PME_FROM_D1: u16 = 1 << 1;
/// PME# can be asserted from D2.
pub const PME_FROM_D2: u16 = 1 << 2;
/// PME# can be asserted from D3hot.
pub const PME_FROM_D3HOT: u16 = 1 << 3;
/// PME# can be asserted from D3cold.
pub const PME_FROM_D3COLD: u16 = 1 << 4;

// ── Registry limits ───────────────────────────────────────────

/// Maximum number of PCI PM devices tracked by the subsystem.
const MAX_PM_DEVICES: usize = 64;

// ── Power state ───────────────────────────────────────────────

/// PCI device power states as defined by PCI-PM rev 1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciPowerState {
    /// D0: fully on; device is fully operational.
    D0,
    /// D1: light sleep; context preserved, clock gated.
    /// Only valid if `PmCapability::d1_support` is true.
    D1,
    /// D2: deeper sleep; some context may be lost.
    /// Only valid if `PmCapability::d2_support` is true.
    D2,
    /// D3hot: deep sleep, main power present, aux power optional.
    D3hot,
    /// D3cold: power removed; requires full re-initialisation.
    D3cold,
}

impl PciPowerState {
    /// Return the 2-bit power state field value for the PM Control
    /// register (PMCS bits 1:0).
    pub fn pmcs_bits(self) -> u16 {
        match self {
            Self::D0 => 0b00,
            Self::D1 => 0b01,
            Self::D2 => 0b10,
            Self::D3hot | Self::D3cold => 0b11,
        }
    }

    /// Decode a power state from PMCS bits 1:0.
    ///
    /// Returns `None` for values outside 0b00..=0b11 (impossible
    /// in practice for a 2-bit field, but present for safety).
    pub fn from_pmcs_bits(bits: u16) -> Option<Self> {
        match bits & 0x03 {
            0b00 => Some(Self::D0),
            0b01 => Some(Self::D1),
            0b10 => Some(Self::D2),
            0b11 => Some(Self::D3hot),
            _ => None,
        }
    }

    /// Return true if a full device re-initialisation is required
    /// when transitioning from this state to D0.
    pub fn requires_reinit_to_d0(self) -> bool {
        matches!(self, Self::D3cold)
    }
}

// ── PM capability ────────────────────────────────────────────

/// Parsed PCI Power Management Capability structure.
///
/// Decoded from the PCI configuration space capability block
/// at the device's PM capability offset.
#[derive(Debug, Clone, Copy)]
pub struct PmCapability {
    /// PM capability structure version (must be 2 or 3 for PCI-PM
    /// 1.2 compliance).
    pub version: u8,
    /// Bitmask of D-states from which PME# can be asserted.
    /// See `PME_FROM_D*` constants.
    pub pme_support_mask: u16,
    /// Auxiliary current drawn in D3cold (mA), encoded in 3 bits.
    pub aux_current_ma: u16,
    /// Whether D1 power state is supported.
    pub d1_support: bool,
    /// Whether D2 power state is supported.
    pub d2_support: bool,
    /// Whether the No Soft Reset bit is set (D3hot→D0 w/o reset).
    pub no_soft_reset: bool,
}

impl Default for PmCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl PmCapability {
    /// Create a zeroed PM capability record.
    pub const fn new() -> Self {
        Self {
            version: 0,
            pme_support_mask: 0,
            aux_current_ma: 0,
            d1_support: false,
            d2_support: false,
            no_soft_reset: false,
        }
    }

    /// Parse a PM capability record from the raw 32-bit PM
    /// Capabilities register (offset 0x02 in the capability block).
    ///
    /// Layout (PCI-PM 1.2 §3.1.1):
    /// - bits 2:0  — version
    /// - bit  3    — PME clock (ignored here)
    /// - bit  4    — Immediate readiness on return to D0
    /// - bit  5    — Device specific initialisation
    /// - bits 8:6  — Aux current
    /// - bit  9    — D1 support
    /// - bit  10   — D2 support
    /// - bits 15:11 — PME support
    pub fn from_register(pmcap: u16) -> Self {
        let version = (pmcap & 0x07) as u8;
        let aux_raw = (pmcap >> 6) & 0x07;
        // Aux current decode table (mA): 0=0,1=55,2=100,3=160,4=220,5=270,6=320,7=375
        let aux_current_ma = match aux_raw {
            0 => 0,
            1 => 55,
            2 => 100,
            3 => 160,
            4 => 220,
            5 => 270,
            6 => 320,
            7 => 375,
            _ => 0,
        };
        let d1_support = pmcap & (1 << 9) != 0;
        let d2_support = pmcap & (1 << 10) != 0;
        let pme_support_mask = (pmcap >> 11) as u16 & 0x1F;
        Self {
            version,
            pme_support_mask,
            aux_current_ma,
            d1_support,
            d2_support,
            no_soft_reset: false, // decoded from PMCS, not PMCAP
        }
    }

    /// Return true if PME# can be asserted from `state`.
    pub fn pme_capable_from(&self, state: PciPowerState) -> bool {
        let bit = match state {
            PciPowerState::D0 => PME_FROM_D0,
            PciPowerState::D1 => PME_FROM_D1,
            PciPowerState::D2 => PME_FROM_D2,
            PciPowerState::D3hot => PME_FROM_D3HOT,
            PciPowerState::D3cold => PME_FROM_D3COLD,
        };
        self.pme_support_mask & bit != 0
    }
}

// ── PCI PM device ────────────────────────────────────────────

/// A PCI device under power management control.
///
/// Tracks the device's current power state, PM capability, PME
/// enable flag, and wake arming status.
pub struct PciPmDevice {
    /// PCI device identifier (`bus << 8 | devfn`).
    pub device_id: u16,
    /// Current PCI power state.
    pub current_state: PciPowerState,
    /// Parsed PM capability.
    pub capabilities: PmCapability,
    /// Whether PME# assertion is enabled for this device.
    pub pme_enabled: bool,
    /// Whether the device is armed for wake events.
    pub wake_armed: bool,
    /// Total power-state transition count.
    pub transition_count: u64,
    /// Total PME# events detected.
    pub pme_events: u64,
    /// Total wake events generated.
    pub wake_events: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl Default for PciPmDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl PciPmDevice {
    /// Create an inactive PM device record.
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            current_state: PciPowerState::D0,
            capabilities: PmCapability::new(),
            pme_enabled: false,
            wake_armed: false,
            transition_count: 0,
            pme_events: 0,
            wake_events: 0,
            active: false,
        }
    }

    /// Validate whether a transition from the current state to
    /// `target` is permitted given the device's capabilities.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the target state is not
    ///   reachable from the current state (e.g. D2→D1).
    /// - [`Error::NotImplemented`] if the device does not support
    ///   the target D1 or D2 state.
    pub fn validate_transition(&self, target: PciPowerState) -> Result<()> {
        // Transitions to the same state are always allowed.
        if self.current_state == target {
            return Ok(());
        }

        // Check D1/D2 hardware support.
        match target {
            PciPowerState::D1 if !self.capabilities.d1_support => {
                return Err(Error::NotImplemented);
            }
            PciPowerState::D2 if !self.capabilities.d2_support => {
                return Err(Error::NotImplemented);
            }
            _ => {}
        }

        // Enforce the PCI-PM transition rules.
        // D2 cannot transition to D1.
        if self.current_state == PciPowerState::D2 && target == PciPowerState::D1 {
            return Err(Error::InvalidArgument);
        }
        // D3hot/D3cold can only go to D0.
        if matches!(
            self.current_state,
            PciPowerState::D3hot | PciPowerState::D3cold
        ) && target != PciPowerState::D0
        {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Detect a pending PME# event and clear it.
    ///
    /// Returns `true` if a PME# was pending.
    pub fn pme_detect(&mut self) -> bool {
        // In a real driver this would read the PMCS PME_Status bit.
        // We track the event in the counter.
        let pending = self.pme_enabled;
        if pending {
            self.pme_events += 1;
        }
        pending
    }

    /// Clear the PME# status bit.
    pub fn pme_clear(&mut self) {
        // Write 1 to PME_Status bit to clear it (RW1C).
        // Modelled here as a no-op on internal state.
    }

    /// Arm the device for wake events.
    ///
    /// Enables PME# assertion from the current power state if the
    /// device supports it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the device cannot
    /// assert PME# from its current state.
    pub fn arm_wake(&mut self) -> Result<()> {
        if !self.capabilities.pme_capable_from(self.current_state) {
            return Err(Error::NotImplemented);
        }
        self.wake_armed = true;
        Ok(())
    }

    /// Disarm the device, preventing it from asserting PME#.
    pub fn disarm_wake(&mut self) {
        self.wake_armed = false;
    }
}

// ── PM subsystem statistics ───────────────────────────────────

/// Aggregate power management statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PciPmStats {
    /// Total power state transitions across all devices.
    pub transitions: u64,
    /// Total PME# events detected.
    pub pme_events: u64,
    /// Total wake events generated.
    pub wake_events: u64,
}

// ── PCI PM subsystem ─────────────────────────────────────────

/// PCI Power Management subsystem.
///
/// Manages up to [`MAX_PM_DEVICES`] (64) PCI devices, providing
/// power-state transitions, PME event detection, and wake arming.
pub struct PciPmSubsystem {
    /// Registered PM devices.
    devices: [PciPmDevice; MAX_PM_DEVICES],
    /// Number of registered devices.
    count: usize,
    /// Aggregate statistics.
    stats: PciPmStats,
}

impl Default for PciPmSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl PciPmSubsystem {
    /// Create an empty PCI PM subsystem.
    pub fn new() -> Self {
        Self {
            devices: [const { PciPmDevice::new() }; MAX_PM_DEVICES],
            count: 0,
            stats: PciPmStats::default(),
        }
    }

    /// Register a PCI device with the PM subsystem.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the device table is full.
    /// - [`Error::AlreadyExists`] if `device_id` is already registered.
    pub fn register(&mut self, device_id: u16, caps: PmCapability) -> Result<usize> {
        // Duplicate check.
        if self.devices[..self.count]
            .iter()
            .any(|d| d.active && d.device_id == device_id)
        {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_PM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx].device_id = device_id;
        self.devices[idx].capabilities = caps;
        self.devices[idx].current_state = PciPowerState::D0;
        self.devices[idx].pme_enabled = false;
        self.devices[idx].wake_armed = false;
        self.devices[idx].transition_count = 0;
        self.devices[idx].pme_events = 0;
        self.devices[idx].wake_events = 0;
        self.devices[idx].active = true;
        self.count += 1;
        Ok(idx)
    }

    /// Find a device index by `device_id`.
    fn find(&self, device_id: u16) -> Option<usize> {
        self.devices[..self.count]
            .iter()
            .position(|d| d.active && d.device_id == device_id)
    }

    /// Transition `device_id` to `target` power state.
    ///
    /// Validates the transition against the device's capabilities
    /// and updates the internal state.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `device_id` is not registered.
    /// - [`Error::InvalidArgument`] / [`Error::NotImplemented`] on
    ///   invalid transitions (see [`PciPmDevice::validate_transition`]).
    pub fn set_power_state(&mut self, device_id: u16, target: PciPowerState) -> Result<()> {
        let idx = self.find(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].validate_transition(target)?;
        self.devices[idx].current_state = target;
        self.devices[idx].transition_count += 1;
        self.stats.transitions += 1;
        Ok(())
    }

    /// Return the current power state of `device_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `device_id` is not registered.
    pub fn get_power_state(&self, device_id: u16) -> Result<PciPowerState> {
        self.find(device_id)
            .map(|idx| self.devices[idx].current_state)
            .ok_or(Error::NotFound)
    }

    /// Enable PME# assertion for `device_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `device_id` is not registered.
    /// - [`Error::NotImplemented`] if the device has no PME support
    ///   in any state.
    pub fn enable_pme(&mut self, device_id: u16) -> Result<()> {
        let idx = self.find(device_id).ok_or(Error::NotFound)?;
        if self.devices[idx].capabilities.pme_support_mask == 0 {
            return Err(Error::NotImplemented);
        }
        self.devices[idx].pme_enabled = true;
        Ok(())
    }

    /// Disable PME# assertion for `device_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `device_id` is not registered.
    pub fn disable_pme(&mut self, device_id: u16) -> Result<()> {
        let idx = self.find(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].pme_enabled = false;
        Ok(())
    }

    /// Detect and clear a PME# event for `device_id`.
    ///
    /// Returns `true` if a PME was pending.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `device_id` is not registered.
    pub fn pme_detect(&mut self, device_id: u16) -> Result<bool> {
        let idx = self.find(device_id).ok_or(Error::NotFound)?;
        let pending = self.devices[idx].pme_detect();
        if pending {
            self.stats.pme_events += 1;
            self.devices[idx].pme_clear();
        }
        Ok(pending)
    }

    /// Arm `device_id` for wake events.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `device_id` is not registered.
    /// - [`Error::NotImplemented`] if PME# is not supported from the
    ///   current power state.
    pub fn arm_wake(&mut self, device_id: u16) -> Result<()> {
        let idx = self.find(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].arm_wake()?;
        self.stats.wake_events += 1;
        Ok(())
    }

    /// Disarm `device_id` from wake events.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `device_id` is not registered.
    pub fn disarm_wake(&mut self, device_id: u16) -> Result<()> {
        let idx = self.find(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].disarm_wake();
        Ok(())
    }

    /// Return a reference to the device at `index`.
    pub fn get(&self, index: usize) -> Option<&PciPmDevice> {
        if index < self.count && self.devices[index].active {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the aggregate statistics.
    pub fn stats(&self) -> &PciPmStats {
        &self.stats
    }
}
