// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware watchdog timer abstraction.
//!
//! Defines the [`WdtHw`] trait for watchdog timer hardware backends
//! and provides the [`iTcoWdt`] implementation for Intel ICH/PCH
//! chipset watchdog timers (iTCO_wdt).
//!
//! # iTCO Watchdog
//!
//! The Intel TCO (Total Cost of Ownership) watchdog is part of the
//! LPC/eSPI controller. It provides:
//! - Configurable timeout (1..614 seconds at 0.6 s increments)
//! - Hardware reset on timeout expiry (two-stage: NMI then RESET)
//! - Reboot status register indicating WDT-initiated resets
//!
//! Reference: Intel ICH8 Datasheet, Section 28 (TCO Logic)

use oncrix_lib::{Error, Result};

// ── Port I/O addresses ────────────────────────────────────────────────────────

/// TCO Base Address I/O port (read from ACPI PM base + offset).
/// Default base for many platforms is 0x0400 (PMBASE) + 0x60.
/// We use a fixed default; real code reads from PCI config space.
const TCO_DEFAULT_BASE: u16 = 0x0460;

/// TCO1_RLD: Reload register (writing 1 pings the watchdog).
const TCO_RLD: u16 = 0x00;
/// TCO1_DAT_IN: Data In register (initial count).
const TCO_DAT_IN: u16 = 0x02;
/// TCO1_DAT_OUT: Data Out register (current count).
const _TCO_DAT_OUT: u16 = 0x06;
/// TCO1_STS: Status register 1.
const TCO1_STS: u16 = 0x04;
/// TCO2_STS: Status register 2.
const TCO2_STS: u16 = 0x06;
/// TCO1_CNT: Control register 1.
const TCO1_CNT: u16 = 0x08;
/// TCO2_CNT: Control register 2.
const _TCO2_CNT: u16 = 0x0A;
/// TCO message register (used for pre-timeout NMI data).
const TCO_MESSAGE1: u16 = 0x04;

/// SMBGLOBSMEM: SMBus Global Semaphore (irrelevant, not used here).
const _SMB_TCO_BASE: u16 = 0x30;

// ── Bit fields ────────────────────────────────────────────────────────────────

/// TCO1_STS bit 3: Second TO Status (timeout fired twice → system reset).
const TCO1_STS_SECOND_TO: u16 = 1 << 3;
/// TCO1_STS bit 0: NMI Status.
const _TCO1_STS_NMI: u16 = 1 << 0;
/// TCO2_STS bit 1: BOOT_STS (second timeout triggered reboot).
const TCO2_STS_BOOT: u16 = 1 << 2;
/// TCO1_CNT bit 11: NMI disable.
const TCO1_CNT_NMI_NOW: u16 = 1 << 8;
/// TCO1_CNT bit 11: TCO_TMR_HLT — halts the WDT when set.
const TCO1_CNT_TMR_HLT: u16 = 1 << 11;

/// SMI_EN unlock value for TCO registers (ICH specific).
const TCO_LOCK_MAGIC: u16 = 0x0001;
/// TCO lock register offset.
const TCO_LOCK: u16 = 0x68;

/// TCO timer period in milliseconds per count (approximately 0.6 s).
const TCO_TICK_MS: u32 = 600;

/// Minimum timeout in TCO ticks.
const TCO_MIN_TICKS: u8 = 2;
/// Maximum timeout in TCO ticks (6-bit field in v1, 10-bit in v2).
const TCO_MAX_TICKS: u8 = 63;

// ── Port I/O helpers ──────────────────────────────────────────────────────────

/// Write a byte to an I/O port.
///
/// # Safety
///
/// The caller must ensure the port is valid and writable.
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures valid port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, preserves_flags),
        );
    }
}

/// Read a byte from an I/O port.
///
/// # Safety
///
/// The caller must ensure the port is valid and readable.
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller ensures valid port.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, preserves_flags),
        );
    }
    val
}

/// Write a 16-bit word to an I/O port.
///
/// # Safety
///
/// The caller must ensure the port is valid and writable.
#[cfg(target_arch = "x86_64")]
unsafe fn outw(port: u16, value: u16) {
    // SAFETY: Caller ensures valid port.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nostack, preserves_flags),
        );
    }
}

/// Read a 16-bit word from an I/O port.
///
/// # Safety
///
/// The caller must ensure the port is valid and readable.
#[cfg(target_arch = "x86_64")]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Caller ensures valid port.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            in("dx") port,
            out("ax") val,
            options(nostack, preserves_flags),
        );
    }
    val
}

// ── WdtHw trait ──────────────────────────────────────────────────────────────

/// Trait for hardware watchdog timer backends.
///
/// All timeouts are expressed in milliseconds. Implementations should
/// round to the nearest hardware granularity and document the precision.
pub trait WdtHw {
    /// Start the watchdog with the configured timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the hardware is not available,
    /// or [`Error::InvalidArgument`] if the timeout is out of range.
    fn start(&mut self) -> Result<()>;

    /// Stop (halt) the watchdog timer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the hardware is not available.
    fn stop(&mut self) -> Result<()>;

    /// Ping (pet) the watchdog to reset the countdown.
    ///
    /// Must be called before the timeout expires to prevent system reset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the hardware is not available.
    fn ping(&mut self) -> Result<()>;

    /// Set the timeout in milliseconds.
    ///
    /// Must be called before [`start`](Self::start). Takes effect on the
    /// next start or ping depending on hardware.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the timeout is out of range.
    fn set_timeout_ms(&mut self, timeout_ms: u32) -> Result<()>;

    /// Return the time remaining in milliseconds before the watchdog fires.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if hardware does not expose this.
    fn get_timeleft_ms(&self) -> Result<u32>;

    /// Return whether the last reset was caused by a watchdog timeout.
    fn caused_reboot(&self) -> bool;

    /// Return the minimum supported timeout in milliseconds.
    fn min_timeout_ms(&self) -> u32;

    /// Return the maximum supported timeout in milliseconds.
    fn max_timeout_ms(&self) -> u32;
}

// ── iTcoWdt ───────────────────────────────────────────────────────────────────

/// Intel TCO watchdog timer driver (iTCO_wdt).
///
/// Supports iTCO v1 (ICH0..ICH7) and v2 (ICH7-R..ICH10, PCH) via
/// port I/O access to the TCO registers in the ACPI I/O space.
pub struct ITcoWdt {
    /// TCO I/O base address.
    tco_base: u16,
    /// Requested timeout in milliseconds.
    timeout_ms: u32,
    /// Computed TCO ticks for the configured timeout.
    ticks: u8,
    /// Whether the watchdog has been started.
    running: bool,
    /// Whether the last boot was caused by a TCO timeout.
    boot_cause: bool,
}

impl ITcoWdt {
    /// Create a new iTCO watchdog with the default TCO base address.
    pub const fn new() -> Self {
        Self {
            tco_base: TCO_DEFAULT_BASE,
            timeout_ms: TCO_MIN_TICKS as u32 * TCO_TICK_MS,
            ticks: TCO_MIN_TICKS,
            running: false,
            boot_cause: false,
        }
    }

    /// Create an iTCO watchdog at a custom TCO base I/O address.
    pub const fn with_base(tco_base: u16) -> Self {
        Self {
            tco_base,
            timeout_ms: TCO_MIN_TICKS as u32 * TCO_TICK_MS,
            ticks: TCO_MIN_TICKS,
            running: false,
            boot_cause: false,
        }
    }

    /// Initialise and detect the iTCO watchdog.
    ///
    /// Reads the boot status register to detect WDT-caused reboots,
    /// clears the SECOND_TO status, and ensures the WDT is halted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn init(&mut self) -> Result<()> {
        #[cfg(not(target_arch = "x86_64"))]
        return Err(Error::NotImplemented);

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Accessing iTCO registers at the configured I/O base.
            let sts2 = unsafe { inw(self.tco_base + TCO2_STS) };
            self.boot_cause = sts2 & TCO2_STS_BOOT != 0;

            // Clear SECOND_TO status and BOOT_STS to acknowledge.
            // SAFETY: Writing to TCO status registers to clear flags.
            unsafe {
                outw(self.tco_base + TCO2_STS, TCO2_STS_BOOT);
                let sts1 = inw(self.tco_base + TCO1_STS) as u32;
                if sts1 as u16 & (TCO1_STS_SECOND_TO as u16) != 0 {
                    outw(self.tco_base + TCO1_STS, TCO1_STS_SECOND_TO as u16);
                }
            }

            // Ensure WDT is halted.
            // SAFETY: Halting the TCO timer by setting TMR_HLT.
            unsafe {
                let cnt = inw(self.tco_base + TCO1_CNT);
                outw(self.tco_base + TCO1_CNT, cnt | TCO1_CNT_TMR_HLT);
            }
            Ok(())
        }
    }

    /// Set the TCO I/O base address.
    pub fn set_tco_base(&mut self, base: u16) {
        self.tco_base = base;
    }

    /// Convert milliseconds to TCO ticks (rounding up, clamped).
    fn ms_to_ticks(ms: u32) -> u8 {
        let ticks = ms.div_ceil(TCO_TICK_MS);
        ticks.clamp(TCO_MIN_TICKS as u32, TCO_MAX_TICKS as u32) as u8
    }

    #[cfg(target_arch = "x86_64")]
    fn write_ticks(&self, ticks: u8) {
        // SAFETY: Writing DAT_IN sets the TCO timeout count.
        unsafe {
            outb(self.tco_base + TCO_DAT_IN, ticks);
            // Reload to apply.
            outb(self.tco_base + TCO_RLD, 1);
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn unlock(&self) {
        // SAFETY: Unlocking TCO registers by writing the magic value.
        unsafe { outw(self.tco_base + TCO_LOCK, TCO_LOCK_MAGIC) };
    }
}

impl Default for ITcoWdt {
    fn default() -> Self {
        Self::new()
    }
}

impl WdtHw for ITcoWdt {
    fn start(&mut self) -> Result<()> {
        #[cfg(not(target_arch = "x86_64"))]
        return Err(Error::NotImplemented);

        #[cfg(target_arch = "x86_64")]
        {
            self.unlock();
            self.write_ticks(self.ticks);
            // Clear TMR_HLT to start the timer.
            // SAFETY: Clearing halt bit starts the TCO countdown.
            unsafe {
                let cnt = inw(self.tco_base + TCO1_CNT);
                outw(self.tco_base + TCO1_CNT, cnt & !TCO1_CNT_TMR_HLT);
            }
            self.running = true;
            Ok(())
        }
    }

    fn stop(&mut self) -> Result<()> {
        #[cfg(not(target_arch = "x86_64"))]
        return Err(Error::NotImplemented);

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Setting TMR_HLT stops the TCO countdown.
            unsafe {
                let cnt = inw(self.tco_base + TCO1_CNT);
                outw(self.tco_base + TCO1_CNT, cnt | TCO1_CNT_TMR_HLT);
            }
            self.running = false;
            Ok(())
        }
    }

    fn ping(&mut self) -> Result<()> {
        #[cfg(not(target_arch = "x86_64"))]
        return Err(Error::NotImplemented);

        #[cfg(target_arch = "x86_64")]
        {
            if !self.running {
                return Err(Error::Busy);
            }
            // SAFETY: Writing TCO_RLD reloads the countdown.
            unsafe { outb(self.tco_base + TCO_RLD, 1) };
            Ok(())
        }
    }

    fn set_timeout_ms(&mut self, timeout_ms: u32) -> Result<()> {
        let min = self.min_timeout_ms();
        let max = self.max_timeout_ms();
        if timeout_ms < min || timeout_ms > max {
            return Err(Error::InvalidArgument);
        }
        self.ticks = Self::ms_to_ticks(timeout_ms);
        self.timeout_ms = self.ticks as u32 * TCO_TICK_MS;
        Ok(())
    }

    fn get_timeleft_ms(&self) -> Result<u32> {
        #[cfg(not(target_arch = "x86_64"))]
        return Err(Error::NotImplemented);

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Reading TCO_MESSAGE1 returns current TCO count.
            let cur_ticks = unsafe { inb(self.tco_base + TCO_MESSAGE1) };
            Ok(cur_ticks as u32 * TCO_TICK_MS)
        }
    }

    fn caused_reboot(&self) -> bool {
        self.boot_cause
    }

    fn min_timeout_ms(&self) -> u32 {
        TCO_MIN_TICKS as u32 * TCO_TICK_MS
    }

    fn max_timeout_ms(&self) -> u32 {
        TCO_MAX_TICKS as u32 * TCO_TICK_MS
    }
}

// ── SoftwareWdt (fallback) ─────────────────────────────────────────────────

/// A software watchdog timer using a countdown counter.
///
/// This is used on platforms without hardware watchdog support. The kernel
/// must call [`SoftwareWdt::ping`] within the timeout period.
pub struct SoftwareWdt {
    /// Configured timeout in milliseconds.
    timeout_ms: u32,
    /// Remaining milliseconds before the watchdog fires.
    remaining_ms: u32,
    /// Whether the watchdog is active.
    running: bool,
}

impl SoftwareWdt {
    /// Create a new software watchdog with a 30-second default timeout.
    pub const fn new() -> Self {
        Self {
            timeout_ms: 30_000,
            remaining_ms: 30_000,
            running: false,
        }
    }

    /// Decrement the watchdog counter by `elapsed_ms` milliseconds.
    ///
    /// Returns `true` if the watchdog has expired (should trigger reset).
    pub fn tick(&mut self, elapsed_ms: u32) -> bool {
        if !self.running {
            return false;
        }
        if elapsed_ms >= self.remaining_ms {
            self.remaining_ms = 0;
            return true;
        }
        self.remaining_ms -= elapsed_ms;
        false
    }
}

impl Default for SoftwareWdt {
    fn default() -> Self {
        Self::new()
    }
}

impl WdtHw for SoftwareWdt {
    fn start(&mut self) -> Result<()> {
        self.remaining_ms = self.timeout_ms;
        self.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        Ok(())
    }

    fn ping(&mut self) -> Result<()> {
        if !self.running {
            return Err(Error::Busy);
        }
        self.remaining_ms = self.timeout_ms;
        Ok(())
    }

    fn set_timeout_ms(&mut self, timeout_ms: u32) -> Result<()> {
        if timeout_ms == 0 {
            return Err(Error::InvalidArgument);
        }
        self.timeout_ms = timeout_ms;
        self.remaining_ms = timeout_ms;
        Ok(())
    }

    fn get_timeleft_ms(&self) -> Result<u32> {
        Ok(self.remaining_ms)
    }

    fn caused_reboot(&self) -> bool {
        false
    }

    fn min_timeout_ms(&self) -> u32 {
        1
    }

    fn max_timeout_ms(&self) -> u32 {
        u32::MAX
    }
}
