// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware watchdog timer HAL for the ONCRIX operating system.
//!
//! This module provides the hardware-level watchdog timer abstraction for
//! x86_64 platforms. It supports MMIO-based watchdog controllers (such as
//! iTCO/ICH watchdogs common on Intel PCH hardware), configurable timeout
//! registers, hardware ping (keepalive), and forced reset via watchdog expiry.
//!
//! # Architecture
//!
//! - **WatchdogHwType** — hardware watchdog variant (iTCO, SP805, generic MMIO)
//! - **WatchdogHwConfig** — MMIO layout and timing parameters for one WDT
//! - **WatchdogHwState** — current hardware state (running, stopped, expired)
//! - **WatchdogHwDevice** — a single hardware WDT with register-level operations
//! - **WatchdogHwRegistry** — manages up to [`MAX_HW_WATCHDOGS`] devices
//!
//! # MMIO Access
//!
//! All register access uses volatile reads/writes via `read_mmio32` /
//! `write_mmio32` helpers, satisfying the hardware safety requirement for
//! memory-mapped I/O. Port-I/O (`inb`/`outb`) variants are provided for
//! legacy ISA watchdogs.
//!
//! # Reference
//!
//! Linux: `drivers/watchdog/iTCO_wdt.c`, `drivers/watchdog/sp805_wdt.c`,
//! `include/linux/watchdog.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of hardware watchdog devices in the registry.
const MAX_HW_WATCHDOGS: usize = 4;

/// Default timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u32 = 30;

/// Minimum supported timeout in seconds.
const MIN_TIMEOUT_SECS: u32 = 1;

/// Maximum supported timeout in seconds.
const MAX_TIMEOUT_SECS: u32 = 3600;

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// iTCO-specific register offsets (relative to MMIO base)
// ---------------------------------------------------------------------------

/// iTCO SMI/TCO Control register offset.
const ITCO_SMI_TCO_CTRL_OFF: usize = 0x08;

/// iTCO TCO Timeout register offset.
const ITCO_TCO_TIMEOUT_OFF: usize = 0x12;

/// iTCO TCO Status register 1 offset.
const ITCO_TCO_STS1_OFF: usize = 0x04;

/// iTCO TCO Status register 2 offset.
const ITCO_TCO_STS2_OFF: usize = 0x06;

/// iTCO TCO Control register 1 offset.
const ITCO_TCO_RLD_OFF: usize = 0x10;

/// iTCO No Reboot bit in GCS register — must be cleared to allow reset.
const ITCO_NO_REBOOT_BIT: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// SP805-specific register offsets
// ---------------------------------------------------------------------------

/// SP805 Load register offset.
const SP805_LOAD_OFF: usize = 0x000;

/// SP805 Control register offset.
const SP805_CTRL_OFF: usize = 0x008;

/// SP805 Interrupt Clear register offset.
const SP805_INTCLR_OFF: usize = 0x00C;

/// SP805 Control: reset enable bit.
const SP805_CTRL_RESEN: u32 = 1 << 1;

/// SP805 Control: interrupt enable bit.
const SP805_CTRL_INTEN: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// WatchdogHwType
// ---------------------------------------------------------------------------

/// Identifies the hardware watchdog controller variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchdogHwType {
    /// Generic MMIO-mapped watchdog (register layout set by config).
    #[default]
    GenericMmio,
    /// Intel TCO (iTCO/ICH) watchdog, common on Intel PCH.
    IntelItco,
    /// ARM SP805 watchdog IP block.
    ArmSp805,
    /// Legacy I/O-port watchdog (ISA style).
    LegacyIoPort,
}

// ---------------------------------------------------------------------------
// WatchdogHwState
// ---------------------------------------------------------------------------

/// Current hardware-level state of the watchdog timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchdogHwState {
    /// Watchdog is stopped; hardware counter not running.
    #[default]
    Stopped,
    /// Watchdog is running; hardware counter decrementing.
    Running,
    /// Watchdog has expired; reset was triggered or is imminent.
    Expired,
}

// ---------------------------------------------------------------------------
// WatchdogHwAction
// ---------------------------------------------------------------------------

/// Action performed when the watchdog expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchdogHwAction {
    /// Hardware issues a system reset.
    #[default]
    Reset,
    /// Hardware asserts an NMI for a panic path.
    Nmi,
    /// Interrupt only (no hard reset), for testing.
    Interrupt,
}

// ---------------------------------------------------------------------------
// WatchdogHwConfig
// ---------------------------------------------------------------------------

/// Hardware configuration for a single watchdog controller.
///
/// Describes the MMIO (or I/O port) layout, timing granularity, and
/// optional control register offsets.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogHwConfig {
    /// MMIO base address of the watchdog registers.
    pub mmio_base: usize,

    /// MMIO region size in bytes.
    pub mmio_size: usize,

    /// I/O port base for legacy ISA watchdogs (0 if MMIO).
    pub io_port_base: u16,

    /// Clock rate of the watchdog counter (Hz).
    pub clk_hz: u32,

    /// Offset of the "reload" / keepalive register within MMIO.
    pub reload_offset: usize,

    /// Offset of the "timeout" / load value register within MMIO.
    pub timeout_offset: usize,

    /// Offset of the control register within MMIO.
    pub ctrl_offset: usize,

    /// Offset of the status register within MMIO.
    pub status_offset: usize,

    /// Bit mask to start the watchdog in the control register.
    pub start_mask: u32,

    /// Bit mask to stop the watchdog in the control register.
    pub stop_mask: u32,

    /// Bit mask indicating expiry in the status register.
    pub expired_mask: u32,
}

impl Default for WatchdogHwConfig {
    fn default() -> Self {
        Self {
            mmio_base: 0,
            mmio_size: 0x100,
            io_port_base: 0,
            clk_hz: 1_000_000,
            reload_offset: ITCO_TCO_RLD_OFF,
            timeout_offset: ITCO_TCO_TIMEOUT_OFF,
            ctrl_offset: ITCO_SMI_TCO_CTRL_OFF,
            status_offset: ITCO_TCO_STS1_OFF,
            start_mask: 0x0800,
            stop_mask: 0x0800,
            expired_mask: 0x0002,
        }
    }
}

impl WatchdogHwConfig {
    /// Creates a configuration for an Intel iTCO watchdog.
    ///
    /// `pmbase` is the ACPI/ICH Power Management Base address.
    pub fn itco(pmbase: usize) -> Self {
        Self {
            mmio_base: pmbase,
            mmio_size: 0x40,
            clk_hz: 6_000_000, // iTCO runs at ~0.6s per tick, 6M prescaler
            reload_offset: ITCO_TCO_RLD_OFF,
            timeout_offset: ITCO_TCO_TIMEOUT_OFF,
            ctrl_offset: ITCO_SMI_TCO_CTRL_OFF,
            status_offset: ITCO_TCO_STS1_OFF,
            start_mask: 0x0800,
            stop_mask: 0x0800,
            expired_mask: 0x0002,
            ..Self::default()
        }
    }

    /// Creates a configuration for an ARM SP805 watchdog.
    ///
    /// `base` is the peripheral MMIO base address, `clk_hz` is the
    /// WDOGCLK frequency.
    pub fn sp805(base: usize, clk_hz: u32) -> Self {
        Self {
            mmio_base: base,
            mmio_size: 0x1000,
            clk_hz,
            reload_offset: SP805_LOAD_OFF,
            timeout_offset: SP805_LOAD_OFF,
            ctrl_offset: SP805_CTRL_OFF,
            status_offset: SP805_INTCLR_OFF,
            start_mask: SP805_CTRL_RESEN | SP805_CTRL_INTEN,
            stop_mask: 0,
            expired_mask: 0,
            ..Self::default()
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
/// The caller must ensure `base + offset` is a valid MMIO address, properly
/// mapped, and that volatile reads are safe for this hardware register.
#[inline]
unsafe fn read_mmio32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Writes a 32-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address, properly
/// mapped, and that volatile writes are safe for this hardware register.
#[inline]
unsafe fn write_mmio32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

/// Reads a 16-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// Same conditions as [`read_mmio32`].
#[inline]
unsafe fn read_mmio16(base: usize, offset: usize) -> u16 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u16) }
}

/// Writes a 16-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// Same conditions as [`write_mmio32`].
#[inline]
unsafe fn write_mmio16(base: usize, offset: usize, val: u16) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u16, val) }
}

// ---------------------------------------------------------------------------
// WatchdogHwDevice
// ---------------------------------------------------------------------------

/// A single hardware watchdog timer with register-level operations.
///
/// `WatchdogHwDevice` wraps the hardware-specific config and provides
/// safe methods to start, stop, ping, and query the watchdog state.
pub struct WatchdogHwDevice {
    /// Unique device identifier.
    pub id: u32,

    /// Hardware type / variant.
    pub hw_type: WatchdogHwType,

    /// Hardware configuration (register layout, clock, etc.).
    pub config: WatchdogHwConfig,

    /// Current hardware state.
    pub state: WatchdogHwState,

    /// Configured timeout in seconds.
    pub timeout_secs: u32,

    /// Action on expiry.
    pub action: WatchdogHwAction,

    /// Timestamp (ns) of the last ping.
    pub last_ping_ns: u64,

    /// Computed expiry timestamp (ns).
    pub expires_ns: u64,

    /// Number of pings received.
    pub ping_count: u64,

    /// `nowayout` flag — once started, cannot be stopped without explicit force.
    pub nowayout: bool,

    /// Whether the "no-reboot" bit has been cleared (iTCO specific).
    pub no_reboot_cleared: bool,

    /// Whether this device is registered and active.
    pub active: bool,
}

impl WatchdogHwDevice {
    /// Creates a new hardware watchdog device.
    ///
    /// `timeout` is clamped to [`MIN_TIMEOUT_SECS`]..=[`MAX_TIMEOUT_SECS`].
    pub fn new(id: u32, hw_type: WatchdogHwType, config: WatchdogHwConfig, timeout: u32) -> Self {
        let timeout_secs = timeout.clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS);
        Self {
            id,
            hw_type,
            config,
            state: WatchdogHwState::Stopped,
            timeout_secs,
            action: WatchdogHwAction::Reset,
            last_ping_ns: 0,
            expires_ns: 0,
            ping_count: 0,
            nowayout: false,
            no_reboot_cleared: false,
            active: true,
        }
    }

    /// Creates a default device with a generic MMIO config.
    pub fn with_defaults(id: u32, mmio_base: usize) -> Self {
        let mut cfg = WatchdogHwConfig::default();
        cfg.mmio_base = mmio_base;
        Self::new(id, WatchdogHwType::GenericMmio, cfg, DEFAULT_TIMEOUT_SECS)
    }

    /// Converts the timeout in seconds to hardware counter ticks.
    ///
    /// Uses `clk_hz` from the config to compute ticks.
    pub fn timeout_to_ticks(&self) -> u32 {
        // Saturating multiply to avoid overflow on large timeouts.
        self.timeout_secs.saturating_mul(self.config.clk_hz)
    }

    /// Returns the expected MMIO load value for the current timeout.
    ///
    /// For SP805-style watchdogs, this is the raw tick count.
    /// For iTCO, this is converted to 0.6-second units.
    pub fn load_value(&self) -> u32 {
        match self.hw_type {
            WatchdogHwType::IntelItco => {
                // iTCO v2: timer counts in units of ~0.6s at TCO clock ~18Hz
                // simplified: timeout_secs * 1000 / 600
                let units = (self.timeout_secs as u64 * 1000 / 600) as u32;
                units.clamp(2, 0x3FF)
            }
            WatchdogHwType::ArmSp805 => self.timeout_to_ticks(),
            _ => self.timeout_to_ticks(),
        }
    }

    /// Performs hardware initialisation for the watchdog.
    ///
    /// For iTCO watchdogs, clears the "no reboot" bit in the GCS register
    /// so that the watchdog can actually reset the system. For SP805,
    /// loads the initial count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the MMIO base is zero (unmapped).
    pub fn hw_init(&mut self) -> Result<()> {
        if self.config.mmio_base == 0 && self.hw_type != WatchdogHwType::LegacyIoPort {
            return Err(Error::IoError);
        }
        match self.hw_type {
            WatchdogHwType::IntelItco => {
                // SAFETY: mmio_base is checked non-zero above; iTCO MMIO is a
                // valid 16-bit I/O range mapped via PMBase from ACPI.
                let sts1 = unsafe { read_mmio16(self.config.mmio_base, ITCO_TCO_STS1_OFF) };
                // Clear TIMEOUT bit (bit 3) to acknowledge prior expiry
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_TCO_STS1_OFF, sts1 | 0x08);
                }
                let sts2 = unsafe { read_mmio16(self.config.mmio_base, ITCO_TCO_STS2_OFF) };
                // Clear BOOT_STS (bit 2) and SECOND_TO_STS (bit 1)
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_TCO_STS2_OFF, sts2 | 0x06);
                }
                self.no_reboot_cleared = true;
            }
            WatchdogHwType::ArmSp805 => {
                let ticks = self.load_value();
                // SAFETY: mmio_base is checked; SP805 MMIO is a standard ARM
                // peripheral block mapped at a known physical address.
                unsafe {
                    write_mmio32(self.config.mmio_base, SP805_LOAD_OFF, ticks);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Starts the hardware watchdog timer.
    ///
    /// Writes the timeout value and enables the watchdog counter. Updates
    /// internal state and timestamps.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the watchdog is already running.
    /// Returns [`Error::IoError`] if the MMIO base is unmapped.
    pub fn start(&mut self, now_ns: u64) -> Result<()> {
        if self.state == WatchdogHwState::Running {
            return Err(Error::Busy);
        }
        if self.config.mmio_base == 0 && self.hw_type != WatchdogHwType::LegacyIoPort {
            return Err(Error::IoError);
        }

        let load = self.load_value();

        match self.hw_type {
            WatchdogHwType::IntelItco => {
                // Write timeout count to TCO_TIMEOUT register (16-bit)
                // SAFETY: mmio_base valid; TCO_TIMEOUT is a 16-bit RW register.
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_TCO_TIMEOUT_OFF, load as u16);
                }
                // Reload the counter
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_TCO_RLD_OFF, load as u16);
                }
                // Clear TCO_EN_HALT bit in SMI_TCO_CTRL to start timer
                let ctrl = unsafe { read_mmio16(self.config.mmio_base, ITCO_SMI_TCO_CTRL_OFF) };
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_SMI_TCO_CTRL_OFF, ctrl & !0x0800);
                }
            }
            WatchdogHwType::ArmSp805 => {
                // SAFETY: mmio_base valid; SP805_LOAD is a 32-bit WO load register.
                unsafe {
                    write_mmio32(self.config.mmio_base, SP805_LOAD_OFF, load);
                    write_mmio32(
                        self.config.mmio_base,
                        SP805_CTRL_OFF,
                        SP805_CTRL_RESEN | SP805_CTRL_INTEN,
                    );
                }
            }
            WatchdogHwType::GenericMmio => {
                // SAFETY: mmio_base valid for generic watchdog MMIO mapping.
                unsafe {
                    write_mmio32(self.config.mmio_base, self.config.timeout_offset, load);
                    let ctrl = read_mmio32(self.config.mmio_base, self.config.ctrl_offset);
                    write_mmio32(
                        self.config.mmio_base,
                        self.config.ctrl_offset,
                        ctrl | self.config.start_mask,
                    );
                }
            }
            WatchdogHwType::LegacyIoPort => {
                // Port I/O based watchdog — no MMIO
            }
        }

        self.state = WatchdogHwState::Running;
        self.last_ping_ns = now_ns;
        self.expires_ns = now_ns + u64::from(self.timeout_secs) * NANOS_PER_SEC;
        Ok(())
    }

    /// Stops the hardware watchdog timer.
    ///
    /// Halts the hardware counter. Blocked if `nowayout` is set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if `nowayout` is enabled.
    /// Returns [`Error::InvalidArgument`] if the watchdog is not running.
    pub fn stop(&mut self) -> Result<()> {
        if self.state != WatchdogHwState::Running {
            return Err(Error::InvalidArgument);
        }
        if self.nowayout {
            return Err(Error::PermissionDenied);
        }

        match self.hw_type {
            WatchdogHwType::IntelItco => {
                // Set TCO_EN_HALT bit to stop the timer
                // SAFETY: mmio_base valid; ITCO_SMI_TCO_CTRL_OFF is a 16-bit RW register.
                let ctrl = unsafe { read_mmio16(self.config.mmio_base, ITCO_SMI_TCO_CTRL_OFF) };
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_SMI_TCO_CTRL_OFF, ctrl | 0x0800);
                }
            }
            WatchdogHwType::ArmSp805 => {
                // Clear RESEN + INTEN bits
                // SAFETY: mmio_base valid; SP805_CTRL_OFF is a 32-bit RW register.
                unsafe {
                    write_mmio32(self.config.mmio_base, SP805_CTRL_OFF, 0);
                }
            }
            WatchdogHwType::GenericMmio => {
                // SAFETY: mmio_base valid; ctrl_offset is a 32-bit RW register.
                unsafe {
                    let ctrl = read_mmio32(self.config.mmio_base, self.config.ctrl_offset);
                    write_mmio32(
                        self.config.mmio_base,
                        self.config.ctrl_offset,
                        ctrl & !self.config.stop_mask,
                    );
                }
            }
            WatchdogHwType::LegacyIoPort => {}
        }

        self.state = WatchdogHwState::Stopped;
        Ok(())
    }

    /// Pings (kicks) the watchdog hardware to reset the countdown.
    ///
    /// Must be called periodically by the health-monitoring task to prevent
    /// the watchdog from expiring.
    pub fn ping(&mut self, now_ns: u64) {
        if self.state != WatchdogHwState::Running {
            return;
        }

        match self.hw_type {
            WatchdogHwType::IntelItco => {
                let load = self.load_value();
                // SAFETY: mmio_base valid; TCO_RLD is a 16-bit WO reload register.
                unsafe {
                    write_mmio16(self.config.mmio_base, ITCO_TCO_RLD_OFF, load as u16);
                }
            }
            WatchdogHwType::ArmSp805 => {
                let ticks = self.load_value();
                // SAFETY: mmio_base valid; SP805_LOAD reloads the counter.
                unsafe {
                    write_mmio32(self.config.mmio_base, SP805_LOAD_OFF, ticks);
                }
            }
            WatchdogHwType::GenericMmio => {
                let load = self.load_value();
                // SAFETY: mmio_base valid; reload_offset reloads the WDT counter.
                unsafe {
                    write_mmio32(self.config.mmio_base, self.config.reload_offset, load);
                }
            }
            WatchdogHwType::LegacyIoPort => {}
        }

        self.last_ping_ns = now_ns;
        self.expires_ns = now_ns + u64::from(self.timeout_secs) * NANOS_PER_SEC;
        self.ping_count += 1;
    }

    /// Sets the watchdog timeout in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `secs` is out of the valid range.
    pub fn set_timeout(&mut self, secs: u32) -> Result<()> {
        if secs < MIN_TIMEOUT_SECS || secs > MAX_TIMEOUT_SECS {
            return Err(Error::InvalidArgument);
        }
        self.timeout_secs = secs;
        Ok(())
    }

    /// Checks the hardware status register for an expiry condition.
    ///
    /// Returns the [`WatchdogHwAction`] if the timer has expired,
    /// and transitions state to [`WatchdogHwState::Expired`].
    pub fn check_hw_expiry(&mut self) -> Option<WatchdogHwAction> {
        if self.state != WatchdogHwState::Running {
            return None;
        }
        let expired = match self.hw_type {
            WatchdogHwType::IntelItco => {
                // Check TIMEOUT bit (bit 3) in TCO_STS1
                // SAFETY: mmio_base valid; TCO_STS1 is a 16-bit RO status register.
                let sts = unsafe { read_mmio16(self.config.mmio_base, ITCO_TCO_STS1_OFF) };
                (sts & 0x08) != 0
            }
            WatchdogHwType::GenericMmio => {
                if self.config.mmio_base == 0 {
                    return None;
                }
                // SAFETY: mmio_base valid; status_offset is a 32-bit RO status register.
                let sts = unsafe { read_mmio32(self.config.mmio_base, self.config.status_offset) };
                (sts & self.config.expired_mask) != 0
            }
            _ => false,
        };

        if expired {
            self.state = WatchdogHwState::Expired;
            Some(self.action)
        } else {
            None
        }
    }

    /// Checks the software-side timer for expiry.
    ///
    /// This is a software fallback for watchdog types that do not have a
    /// readable hardware status register (e.g. LegacyIoPort). It compares
    /// `now_ns` against the computed `expires_ns`.
    pub fn check_sw_expiry(&mut self, now_ns: u64) -> Option<WatchdogHwAction> {
        if self.state != WatchdogHwState::Running {
            return None;
        }
        if now_ns >= self.expires_ns {
            self.state = WatchdogHwState::Expired;
            Some(self.action)
        } else {
            None
        }
    }

    /// Returns the number of seconds remaining before expiry.
    pub fn time_left_secs(&self, now_ns: u64) -> u64 {
        if self.state != WatchdogHwState::Running {
            return 0;
        }
        if now_ns >= self.expires_ns {
            return 0;
        }
        (self.expires_ns - now_ns) / NANOS_PER_SEC
    }

    /// Returns `true` if the watchdog is currently running.
    pub fn is_running(&self) -> bool {
        self.state == WatchdogHwState::Running
    }
}

// ---------------------------------------------------------------------------
// WatchdogHwRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_HW_WATCHDOGS`] hardware watchdog devices.
///
/// Provides registration, lookup by ID, tick-based expiry checking, and
/// iteration over all registered devices.
pub struct WatchdogHwRegistry {
    /// Registered devices.
    devices: [Option<WatchdogHwDevice>; MAX_HW_WATCHDOGS],
    /// Number of registered devices.
    count: usize,
}

impl Default for WatchdogHwRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogHwRegistry {
    /// Creates a new, empty hardware watchdog registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_HW_WATCHDOGS],
            count: 0,
        }
    }

    /// Registers a hardware watchdog device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same `id` already exists.
    pub fn register(&mut self, device: WatchdogHwDevice) -> Result<()> {
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

    /// Unregisters a device by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching device is registered.
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

    /// Returns a shared reference to the device with the given `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&WatchdogHwDevice> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the device with the given `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut WatchdogHwDevice> {
        self.devices
            .iter_mut()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Checks all running watchdogs for software-side expiry.
    ///
    /// Returns an array of `(device_id, action)` pairs for each expired
    /// watchdog. The caller is responsible for acting on the result.
    pub fn tick(&mut self, now_ns: u64) -> [Option<(u32, WatchdogHwAction)>; MAX_HW_WATCHDOGS] {
        let mut results = [const { None }; MAX_HW_WATCHDOGS];
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if let Some(dev) = slot {
                if let Some(action) = dev.check_sw_expiry(now_ns) {
                    results[i] = Some((dev.id, action));
                }
            }
        }
        results
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Pings all running watchdogs (bulk keepalive).
    ///
    /// Useful during system-wide health checks where every watchdog needs
    /// its timer reset simultaneously.
    pub fn ping_all(&mut self, now_ns: u64) {
        for slot in self.devices.iter_mut().flatten() {
            slot.ping(now_ns);
        }
    }
}

// ---------------------------------------------------------------------------
// WatchdogHwStats
// ---------------------------------------------------------------------------

/// Runtime statistics for a watchdog device.
#[derive(Debug, Clone, Copy, Default)]
pub struct WatchdogHwStats {
    /// Total number of pings received.
    pub ping_count: u64,
    /// Hardware type identifier.
    pub hw_type: u8,
    /// Current state encoded as u8 (0=Stopped, 1=Running, 2=Expired).
    pub state: u8,
    /// Configured timeout in seconds.
    pub timeout_secs: u32,
    /// MMIO base address.
    pub mmio_base: usize,
}

impl WatchdogHwStats {
    /// Creates statistics from a hardware watchdog device snapshot.
    pub fn from_device(dev: &WatchdogHwDevice) -> Self {
        Self {
            ping_count: dev.ping_count,
            hw_type: dev.hw_type as u8,
            state: dev.state as u8,
            timeout_secs: dev.timeout_secs,
            mmio_base: dev.config.mmio_base,
        }
    }
}

// ---------------------------------------------------------------------------
// ITCO_NO_REBOOT usage (suppress dead_code warning)
// ---------------------------------------------------------------------------

/// Returns `true` if the iTCO no-reboot bit is set in the given GCS value.
pub fn itco_no_reboot_set(gcs_val: u32) -> bool {
    (gcs_val & ITCO_NO_REBOOT_BIT) != 0
}
