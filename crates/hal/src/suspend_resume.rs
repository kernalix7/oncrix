// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System suspend and resume flow.
//!
//! Implements the ACPI-defined sleep states (S0..S5) for system power
//! management. The suspend path:
//!
//! 1. Freeze userspace
//! 2. Call device `suspend` callbacks in reverse registration order
//! 3. Invoke platform `enter` (e.g., write ACPI sleep register)
//! 4. On resume: call device `resume` callbacks in registration order
//! 5. Thaw userspace
//!
//! Wakeup sources can be registered to indicate which events can wake
//! the system from a given sleep state.
//!
//! Reference: ACPI Specification 6.5, Section 7 (Power Management)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of devices with suspend/resume callbacks.
const MAX_SUSPEND_DEVS: usize = 32;

/// Maximum number of wakeup sources.
const MAX_WAKEUP_SOURCES: usize = 16;

/// Maximum device name length.
const DEV_NAME_LEN: usize = 24;

// ── SuspendState ─────────────────────────────────────────────────────────────

/// ACPI sleep states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendState {
    /// S0 — fully running (not a sleep state; used for runtime PM).
    S0,
    /// S1 — power-on suspend: CPU stops but remains powered.
    S1,
    /// S3 — suspend to RAM: CPU and devices powered off, RAM retained.
    S3,
    /// S4 — suspend to disk (hibernate): all state saved to disk.
    S4,
    /// S5 — soft off: system powered down, needs cold boot.
    S5,
}

impl SuspendState {
    /// Return the ACPI `SLP_TYP` field value for this state.
    ///
    /// These are platform-specific; the values here are for QEMU/OVMF.
    pub fn slp_typ(self) -> u8 {
        match self {
            SuspendState::S0 => 0,
            SuspendState::S1 => 1,
            SuspendState::S3 => 3,
            SuspendState::S4 => 4,
            SuspendState::S5 => 5,
        }
    }

    /// Return whether this is a sleep state (not S0).
    pub fn is_sleep(self) -> bool {
        !matches!(self, SuspendState::S0)
    }

    /// Return whether devices need to be suspended for this state.
    pub fn requires_device_suspend(self) -> bool {
        matches!(self, SuspendState::S3 | SuspendState::S4 | SuspendState::S5)
    }
}

// ── SuspendCallbacks ─────────────────────────────────────────────────────────

/// Function pointer type for device suspend callback.
///
/// Called with the target sleep state. Returns `Ok(())` on success or
/// an error if the device cannot be suspended.
pub type SuspendFn = fn(state: SuspendState) -> Result<()>;

/// Function pointer type for device resume callback.
pub type ResumeFn = fn(state: SuspendState) -> Result<()>;

/// Suspend/resume callback registration for a single device.
#[derive(Clone, Copy)]
pub struct SuspendDevEntry {
    /// Device name for diagnostics.
    pub name: [u8; DEV_NAME_LEN],
    /// Number of valid chars in `name`.
    pub name_len: usize,
    /// Suspend callback (called in reverse registration order).
    pub suspend: Option<SuspendFn>,
    /// Resume callback (called in registration order).
    pub resume: Option<ResumeFn>,
    /// Whether this entry is occupied.
    pub valid: bool,
    /// Minimum sleep state this device supports.
    pub min_state: SuspendState,
}

impl SuspendDevEntry {
    /// Create a new suspend device entry.
    pub fn new(name: &[u8], suspend: Option<SuspendFn>, resume: Option<ResumeFn>) -> Self {
        let mut name_buf = [0u8; DEV_NAME_LEN];
        let len = name.len().min(DEV_NAME_LEN);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            name: name_buf,
            name_len: len,
            suspend,
            resume,
            valid: true,
            min_state: SuspendState::S1,
        }
    }
}

// ── WakeupSource ─────────────────────────────────────────────────────────────

/// A registered wakeup source.
///
/// Wakeup sources represent hardware/software events that can wake the
/// system from a sleep state (e.g., power button, RTC alarm, network).
#[derive(Clone, Copy)]
pub struct WakeupSource {
    /// Source name.
    pub name: [u8; DEV_NAME_LEN],
    /// Number of valid chars in `name`.
    pub name_len: usize,
    /// Wakeup event count since last clear.
    pub event_count: u64,
    /// Whether this source is enabled for wakeup.
    pub enabled: bool,
    /// Whether this source triggered the last resume.
    pub triggered: bool,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl WakeupSource {
    /// Create a new wakeup source.
    pub fn new(name: &[u8]) -> Self {
        let mut name_buf = [0u8; DEV_NAME_LEN];
        let len = name.len().min(DEV_NAME_LEN);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            name: name_buf,
            name_len: len,
            event_count: 0,
            enabled: false,
            triggered: false,
            valid: true,
        }
    }

    /// Signal that a wakeup event occurred.
    pub fn signal(&mut self) {
        self.event_count = self.event_count.saturating_add(1);
        self.triggered = true;
    }

    /// Return the name as bytes.
    pub fn name_str(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── PlatformSuspendOps ───────────────────────────────────────────────────────

/// Platform-specific suspend operations.
///
/// The platform implements `enter` to write the ACPI sleep register
/// and `valid` to indicate which states are supported.
pub trait PlatformSuspendOps {
    /// Return whether the platform supports the given sleep state.
    fn valid(&self, state: SuspendState) -> bool;

    /// Enter the sleep state (writes hardware registers).
    ///
    /// This function must only return on resume from S1; for S3/S4/S5
    /// the system will resume via a cold boot path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the state is not supported.
    fn enter(&self, state: SuspendState) -> Result<()>;

    /// Pre-suspend platform preparation (disable watchdogs, save regs).
    fn prepare(&self) -> Result<()> {
        Ok(())
    }

    /// Post-resume platform restore.
    fn finish(&self) {}
}

// ── AcpiSuspendOps ───────────────────────────────────────────────────────────

/// ACPI-based suspend operations via PM1 registers.
pub struct AcpiSuspendOps {
    /// Physical address of PM1a_CNT (ACPI sleep control register A).
    pub pm1a_cnt_addr: u16,
    /// Physical address of PM1b_CNT (optional second sleep register).
    pub pm1b_cnt_addr: u16,
    /// SLP_TYP values for S1/S3/S4/S5 for register A.
    pub slp_typ_a: [u8; 6],
    /// SLP_TYP values for S1/S3/S4/S5 for register B.
    pub slp_typ_b: [u8; 6],
}

impl AcpiSuspendOps {
    /// Create a new ACPI suspend ops with the given PM1a register address.
    pub const fn new(pm1a_cnt_addr: u16) -> Self {
        Self {
            pm1a_cnt_addr,
            pm1b_cnt_addr: 0,
            slp_typ_a: [0, 1, 0, 3, 4, 5],
            slp_typ_b: [0, 1, 0, 3, 4, 5],
        }
    }
}

impl PlatformSuspendOps for AcpiSuspendOps {
    fn valid(&self, state: SuspendState) -> bool {
        matches!(
            state,
            SuspendState::S1 | SuspendState::S3 | SuspendState::S5
        )
    }

    fn enter(&self, state: SuspendState) -> Result<()> {
        if !self.valid(state) {
            return Err(Error::NotImplemented);
        }

        #[cfg(not(target_arch = "x86_64"))]
        return Err(Error::NotImplemented);

        #[cfg(target_arch = "x86_64")]
        {
            let slp_typ = state.slp_typ();
            // SLP_EN bit: bit 13; SLP_TYP: bits 12:10.
            let pm1_val: u16 = (1 << 13) | ((slp_typ as u16 & 0x7) << 10);

            // SAFETY: Writing ACPI PM1 CNT register to enter sleep.
            unsafe {
                core::arch::asm!(
                    "out dx, ax",
                    in("dx") self.pm1a_cnt_addr,
                    in("ax") pm1_val,
                    options(nostack, preserves_flags),
                );
                if self.pm1b_cnt_addr != 0 {
                    core::arch::asm!(
                        "out dx, ax",
                        in("dx") self.pm1b_cnt_addr,
                        in("ax") pm1_val,
                        options(nostack, preserves_flags),
                    );
                }
            }
            // S1 returns here; S3/S4/S5 do not (handled by cold boot).
            Ok(())
        }
    }
}

// ── SuspendResult ────────────────────────────────────────────────────────────

/// Result of a suspend operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendResult {
    /// Successfully entered and returned from sleep state.
    Success,
    /// Suspend was aborted before entering sleep.
    Aborted,
    /// An error occurred during device suspend.
    DeviceError,
}

// ── SuspendManager ───────────────────────────────────────────────────────────

/// System suspend/resume coordinator.
///
/// Manages device callbacks, wakeup sources, and delegates platform
/// entry to a [`PlatformSuspendOps`] implementation.
pub struct SuspendManager {
    /// Registered device suspend/resume entries.
    devs: [Option<SuspendDevEntry>; MAX_SUSPEND_DEVS],
    /// Number of registered devices.
    dev_count: usize,
    /// Registered wakeup sources.
    wakeup_sources: [Option<WakeupSource>; MAX_WAKEUP_SOURCES],
    /// Number of registered wakeup sources.
    wakeup_count: usize,
    /// Current system suspend state.
    current_state: SuspendState,
    /// Number of successful suspends.
    suspend_count: u64,
    /// Whether suspend is in progress.
    in_progress: bool,
}

impl SuspendManager {
    /// Create a new suspend manager.
    pub const fn new() -> Self {
        Self {
            devs: [const { None }; MAX_SUSPEND_DEVS],
            wakeup_sources: [const { None }; MAX_WAKEUP_SOURCES],
            dev_count: 0,
            wakeup_count: 0,
            current_state: SuspendState::S0,
            suspend_count: 0,
            in_progress: false,
        }
    }

    /// Register a device for suspend/resume callbacks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full.
    pub fn register_device(
        &mut self,
        name: &[u8],
        suspend: Option<SuspendFn>,
        resume: Option<ResumeFn>,
    ) -> Result<usize> {
        if self.dev_count >= MAX_SUSPEND_DEVS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.dev_count;
        self.devs[idx] = Some(SuspendDevEntry::new(name, suspend, resume));
        self.dev_count += 1;
        Ok(idx)
    }

    /// Register a wakeup source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the wakeup source table is full.
    pub fn register_wakeup_source(&mut self, name: &[u8]) -> Result<usize> {
        if self.wakeup_count >= MAX_WAKEUP_SOURCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.wakeup_count;
        self.wakeup_sources[idx] = Some(WakeupSource::new(name));
        self.wakeup_count += 1;
        Ok(idx)
    }

    /// Enable or disable a wakeup source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the source index is invalid.
    pub fn set_wakeup_enabled(&mut self, source_id: usize, enabled: bool) -> Result<()> {
        self.wakeup_sources
            .get_mut(source_id)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?
            .enabled = enabled;
        Ok(())
    }

    /// Signal a wakeup event from the given source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the source index is invalid.
    pub fn signal_wakeup(&mut self, source_id: usize) -> Result<()> {
        self.wakeup_sources
            .get_mut(source_id)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?
            .signal();
        Ok(())
    }

    /// Execute the full suspend sequence for the given state.
    ///
    /// Steps: `platform.prepare()` → suspend devices (reverse order) →
    /// `platform.enter()` → resume devices (forward order) → `platform.finish()`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a suspend is already in progress,
    /// [`Error::NotImplemented`] if the platform doesn't support the state.
    pub fn suspend<P: PlatformSuspendOps>(
        &mut self,
        state: SuspendState,
        platform: &P,
    ) -> Result<SuspendResult> {
        if self.in_progress {
            return Err(Error::Busy);
        }
        if !platform.valid(state) {
            return Err(Error::NotImplemented);
        }

        self.in_progress = true;
        self.current_state = state;

        // Platform prepare.
        if let Err(_e) = platform.prepare() {
            self.in_progress = false;
            return Ok(SuspendResult::Aborted);
        }

        // Suspend devices in reverse registration order.
        if state.requires_device_suspend() {
            for i in (0..self.dev_count).rev() {
                if let Some(dev) = &self.devs[i] {
                    if let Some(suspend_fn) = dev.suspend {
                        if suspend_fn(state).is_err() {
                            // Resume already-suspended devices and abort.
                            self.resume_devices_from(state, i + 1);
                            platform.finish();
                            self.in_progress = false;
                            return Ok(SuspendResult::DeviceError);
                        }
                    }
                }
            }
        }

        // Enter sleep state.
        let entered = platform.enter(state);

        // Resume devices (if we returned from S1 or enter failed).
        if state.requires_device_suspend() {
            self.resume_devices_from(state, 0);
        }

        platform.finish();

        self.in_progress = false;
        self.suspend_count = self.suspend_count.saturating_add(1);
        self.current_state = SuspendState::S0;

        match entered {
            Ok(()) => Ok(SuspendResult::Success),
            Err(_) => Ok(SuspendResult::Aborted),
        }
    }

    /// Resume devices starting from the given index (forward order).
    fn resume_devices_from(&self, state: SuspendState, from: usize) {
        for i in from..self.dev_count {
            if let Some(dev) = &self.devs[i] {
                if let Some(resume_fn) = dev.resume {
                    let _ = resume_fn(state);
                }
            }
        }
    }

    /// Return the current suspend state.
    pub fn current_state(&self) -> SuspendState {
        self.current_state
    }

    /// Return the number of successful suspends.
    pub fn suspend_count(&self) -> u64 {
        self.suspend_count
    }

    /// Return whether a wakeup source triggered the last resume.
    pub fn was_wakeup_triggered(&self, source_id: usize) -> bool {
        self.wakeup_sources
            .get(source_id)
            .and_then(|s| s.as_ref())
            .map(|s| s.triggered)
            .unwrap_or(false)
    }

    /// Clear all wakeup-triggered flags.
    pub fn clear_wakeup_triggers(&mut self) {
        for slot in &mut self.wakeup_sources[..self.wakeup_count] {
            if let Some(src) = slot {
                src.triggered = false;
            }
        }
    }

    /// Return the number of registered devices.
    pub fn dev_count(&self) -> usize {
        self.dev_count
    }

    /// Return the number of registered wakeup sources.
    pub fn wakeup_count(&self) -> usize {
        self.wakeup_count
    }
}

impl Default for SuspendManager {
    fn default() -> Self {
        Self::new()
    }
}
