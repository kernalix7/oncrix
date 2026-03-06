// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Enhanced ACPI power management.
//!
//! Extends the base ACPI power management with fine-grained device
//! power states (D0–D3cold), sleep state transitions (S0–S5),
//! General Purpose Event (GPE) management, and PM timer access.
//!
//! This module manages device power lifecycles, wake-capable device
//! tracking, and SCI (System Control Interrupt) handling for the
//! ACPI subsystem.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────

/// Maximum number of managed ACPI devices.
const MAX_DEVICES: usize = 64;

/// Maximum number of General Purpose Events.
const MAX_GPES: usize = 32;

/// PM timer frequency: 3.579545 MHz (ACPI-defined).
const PM_TIMER_FREQUENCY: u32 = 3_579_545;

/// Maximum device name length in bytes.
const DEVICE_NAME_LEN: usize = 16;

// ── Sleep States ──────────────────────────────────────────────

/// ACPI system sleep states (S0–S5).
///
/// Represents the global system power states defined by the ACPI
/// specification. The default state is [`AcpiSleepState::S0Working`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AcpiSleepState {
    /// S0 — Working (fully running).
    #[default]
    S0Working,
    /// S1 — Standby (CPU stopped, context retained).
    S1Standby,
    /// S2 — Standby (CPU off, caches flushed).
    S2Standby,
    /// S3 — Suspend to RAM (context saved in memory).
    S3Suspend,
    /// S4 — Hibernate (context saved to disk).
    S4Hibernate,
    /// S5 — Soft-off (mechanical off, except wake logic).
    S5SoftOff,
}

// ── Device Power States ───────────────────────────────────────

/// ACPI device power states (D0–D3cold).
///
/// Represents per-device power states as defined by the ACPI
/// specification. The default state is [`AcpiDeviceState::D0Full`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AcpiDeviceState {
    /// D0 — Fully operational.
    #[default]
    D0Full,
    /// D1 — Light sleep (device-defined).
    D1Light,
    /// D2 — Low-power (more savings than D1).
    D2Low,
    /// D3hot — Software-visible low-power state.
    D3Hot,
    /// D3cold — Power removed from device.
    D3Cold,
}

// ── GPE ───────────────────────────────────────────────────────

/// ACPI General Purpose Event descriptor.
///
/// Tracks the state and configuration of a single GPE, including
/// whether it is enabled, has been triggered, and whether it can
/// wake the system from a sleep state.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiGpe {
    /// GPE number (0-based index in the GPE block).
    pub gpe_number: u32,
    /// Whether this GPE is currently enabled.
    pub enabled: bool,
    /// Whether this GPE has been triggered since last clear.
    pub triggered: bool,
    /// Identifier of the handler registered for this GPE.
    pub handler_id: u64,
    /// Whether this GPE can wake the system.
    pub wake_capable: bool,
}

// ── PM Timer ──────────────────────────────────────────────────

/// ACPI PM timer configuration.
///
/// The PM timer ticks at exactly 3.579545 MHz and is either 24-bit
/// or 32-bit wide. Used for precision microsecond-level timing.
#[derive(Debug, Clone, Copy)]
pub struct AcpiPmTimer {
    /// I/O port address for the PM timer.
    pub port: u16,
    /// Whether the timer is 32-bit (vs. 24-bit).
    pub is_32bit: bool,
    /// Timer frequency in Hz (always 3_579_545).
    pub frequency: u32,
}

impl Default for AcpiPmTimer {
    fn default() -> Self {
        Self {
            port: 0,
            is_32bit: false,
            frequency: PM_TIMER_FREQUENCY,
        }
    }
}

// ── PM Registers ──────────────────────────────────────────────

/// ACPI PM1 register block layout.
///
/// Mirrors the hardware register layout for the PM1 event, enable,
/// and control registers (both A and B blocks) plus the PM timer.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct AcpiPmRegisters {
    /// PM1a status register.
    pub pm1a_status: u16,
    /// PM1a enable register.
    pub pm1a_enable: u16,
    /// PM1a control register.
    pub pm1a_control: u16,
    /// PM1b status register.
    pub pm1b_status: u16,
    /// PM1b enable register.
    pub pm1b_enable: u16,
    /// PM1b control register.
    pub pm1b_control: u16,
    /// PM timer current value.
    pub pm_timer: u32,
}

// ── Device Info ───────────────────────────────────────────────

/// ACPI device information entry.
///
/// Tracks a managed device's identity, current power state, wake
/// capability, and whether it is currently in active use.
#[derive(Debug, Clone, Copy)]
pub struct AcpiDeviceInfo {
    /// Unique device identifier.
    pub id: u64,
    /// Device name (UTF-8, zero-padded).
    pub name: [u8; DEVICE_NAME_LEN],
    /// Length of the valid portion of `name`.
    pub name_len: usize,
    /// Current device power state.
    pub state: AcpiDeviceState,
    /// Whether this device can wake the system.
    pub wake_capable: bool,
    /// Whether this device slot is in use.
    pub in_use: bool,
}

impl Default for AcpiDeviceInfo {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0u8; DEVICE_NAME_LEN],
            name_len: 0,
            state: AcpiDeviceState::D0Full,
            wake_capable: false,
            in_use: false,
        }
    }
}

// ── Power Manager ─────────────────────────────────────────────

/// Enhanced ACPI power manager.
///
/// Coordinates system sleep states, per-device power management,
/// GPE handling, and PM timer access. Supports up to 64 managed
/// devices and 32 GPE sources.
pub struct AcpiPowerManager {
    /// Current system sleep state.
    sleep_state: AcpiSleepState,
    /// PM register block snapshot.
    pm_regs: AcpiPmRegisters,
    /// Registered device table.
    devices: [AcpiDeviceInfo; MAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// GPE descriptor table.
    gpes: [AcpiGpe; MAX_GPES],
    /// Number of registered GPEs.
    gpe_count: usize,
    /// PM timer configuration.
    #[allow(dead_code)]
    timer: AcpiPmTimer,
    /// Whether SCI (System Control Interrupt) is enabled.
    sci_enabled: bool,
}

impl Default for AcpiPowerManager {
    fn default() -> Self {
        Self {
            sleep_state: AcpiSleepState::default(),
            pm_regs: AcpiPmRegisters::default(),
            devices: [AcpiDeviceInfo::default(); MAX_DEVICES],
            device_count: 0,
            gpes: [AcpiGpe::default(); MAX_GPES],
            gpe_count: 0,
            timer: AcpiPmTimer::default(),
            sci_enabled: false,
        }
    }
}

impl AcpiPowerManager {
    /// Create a new power manager with default (idle) state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Transition the system to the specified sleep state.
    ///
    /// Validates the requested state and updates the internal
    /// sleep state tracking. Actual hardware programming of
    /// PM1x_CNT registers is architecture-specific and deferred
    /// to the platform HAL layer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the transition from
    /// the current state to the requested state is not permitted.
    pub fn enter_sleep_state(&mut self, state: AcpiSleepState) -> Result<()> {
        // S5 (soft-off) cannot transition back to any running state.
        if self.sleep_state == AcpiSleepState::S5SoftOff {
            return Err(Error::InvalidArgument);
        }

        // Cannot transition to the same state.
        if self.sleep_state == state {
            return Err(Error::InvalidArgument);
        }

        self.sleep_state = state;
        Ok(())
    }

    /// Set the power state of a registered device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with the given ID
    /// is registered.
    pub fn set_device_state(&mut self, device_id: u64, state: AcpiDeviceState) -> Result<()> {
        let device = self
            .devices
            .iter_mut()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)?;

        device.state = state;
        Ok(())
    }

    /// Register a new device with the power manager.
    ///
    /// Returns the assigned device ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full.
    pub fn register_device(&mut self, name: &[u8], wake_capable: bool) -> Result<u64> {
        let slot = self
            .devices
            .iter_mut()
            .find(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.device_count as u64 + 1;
        let copy_len = name.len().min(DEVICE_NAME_LEN);

        let mut dev_name = [0u8; DEVICE_NAME_LEN];
        dev_name[..copy_len].copy_from_slice(&name[..copy_len]);

        *slot = AcpiDeviceInfo {
            id,
            name: dev_name,
            name_len: copy_len,
            state: AcpiDeviceState::D0Full,
            wake_capable,
            in_use: true,
        };

        self.device_count += 1;
        Ok(id)
    }

    /// Unregister a device from the power manager.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with the given ID
    /// is registered.
    pub fn unregister_device(&mut self, id: u64) -> Result<()> {
        let device = self
            .devices
            .iter_mut()
            .find(|d| d.in_use && d.id == id)
            .ok_or(Error::NotFound)?;

        *device = AcpiDeviceInfo::default();
        self.device_count = self.device_count.saturating_sub(1);
        Ok(())
    }

    /// Enable a General Purpose Event and associate a handler.
    ///
    /// If the GPE number already exists, it is re-enabled with the
    /// new handler ID. Otherwise a new GPE entry is created.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the GPE table is full and
    /// the requested GPE number is not already registered.
    pub fn enable_gpe(&mut self, gpe_num: u32, handler_id: u64) -> Result<()> {
        // Check if GPE already exists.
        if let Some(gpe) = self
            .gpes
            .iter_mut()
            .take(self.gpe_count)
            .find(|g| g.gpe_number == gpe_num)
        {
            gpe.enabled = true;
            gpe.handler_id = handler_id;
            return Ok(());
        }

        // Allocate a new GPE slot.
        if self.gpe_count >= MAX_GPES {
            return Err(Error::OutOfMemory);
        }

        self.gpes[self.gpe_count] = AcpiGpe {
            gpe_number: gpe_num,
            enabled: true,
            triggered: false,
            handler_id,
            wake_capable: false,
        };
        self.gpe_count += 1;
        Ok(())
    }

    /// Disable a General Purpose Event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no GPE with the given number
    /// is registered.
    pub fn disable_gpe(&mut self, gpe_num: u32) -> Result<()> {
        let gpe = self
            .gpes
            .iter_mut()
            .take(self.gpe_count)
            .find(|g| g.gpe_number == gpe_num)
            .ok_or(Error::NotFound)?;

        gpe.enabled = false;
        Ok(())
    }

    /// Handle a System Control Interrupt.
    ///
    /// Scans all enabled GPEs and returns a bitmask indicating
    /// which GPEs have been triggered. Each bit position corresponds
    /// to the GPE's index in the internal table. Triggered GPEs are
    /// marked and cleared after processing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if SCI handling is not
    /// enabled.
    pub fn handle_sci(&mut self) -> Result<u32> {
        if !self.sci_enabled {
            return Err(Error::InvalidArgument);
        }

        let mut bitmask: u32 = 0;

        for (i, gpe) in self.gpes.iter_mut().take(self.gpe_count).enumerate() {
            if gpe.enabled && gpe.triggered {
                if i < 32 {
                    bitmask |= 1 << i;
                }
                gpe.triggered = false;
            }
        }

        Ok(bitmask)
    }

    /// Read the current PM timer value.
    ///
    /// Returns the raw timer register value from the cached PM
    /// register block. For actual hardware reads, the caller should
    /// update `pm_regs.pm_timer` via port I/O first.
    pub fn read_pm_timer(&self) -> u32 {
        self.pm_regs.pm_timer
    }

    /// Enable wake capability for a device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with the given ID
    /// is registered.
    pub fn enable_wake(&mut self, device_id: u64) -> Result<()> {
        let device = self
            .devices
            .iter_mut()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)?;

        device.wake_capable = true;
        Ok(())
    }

    /// Disable wake capability for a device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with the given ID
    /// is registered.
    pub fn disable_wake(&mut self, device_id: u64) -> Result<()> {
        let device = self
            .devices
            .iter_mut()
            .find(|d| d.in_use && d.id == device_id)
            .ok_or(Error::NotFound)?;

        device.wake_capable = false;
        Ok(())
    }

    /// Look up a device by its ID.
    ///
    /// Returns `None` if no device with the given ID is registered.
    pub fn get_device(&self, id: u64) -> Option<&AcpiDeviceInfo> {
        self.devices.iter().find(|d| d.in_use && d.id == id)
    }

    /// Return the current system sleep state.
    pub fn current_sleep_state(&self) -> AcpiSleepState {
        self.sleep_state
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.device_count
    }

    /// Return whether the device table is empty.
    pub fn is_empty(&self) -> bool {
        self.device_count == 0
    }

    /// Return a reference to the PM timer configuration.
    pub fn timer(&self) -> &AcpiPmTimer {
        &self.timer
    }
}
