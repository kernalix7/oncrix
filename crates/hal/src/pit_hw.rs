// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! 8254 PIT (Programmable Interval Timer) hardware abstraction.
//!
//! The Intel 8254 (and compatible) PIT provides three independent 16-bit
//! down-counters clocked at approximately 1.193182 MHz.
//!
//! | Channel | Port  | Purpose                         |
//! |---------|-------|---------------------------------|
//! |    0    | 0x40  | System timer tick (IRQ 0)       |
//! |    1    | 0x41  | DRAM refresh (legacy, avoid)    |
//! |    2    | 0x42  | Speaker / APIC calibration      |
//!
//! This module wraps `pit_8254.rs` functions with higher-level abstractions
//! suitable for use by the HAL timer layer and APIC calibration code.
//!
//! Reference: Intel 8254 Programmable Interval Timer Datasheet (1993).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PIT input oscillator frequency in Hz (14.31818 MHz / 12).
pub const PIT_HZ: u32 = 1_193_182;

/// PIT data port for Channel 0 (system timer, IRQ 0).
pub const PIT_PORT_CH0: u16 = 0x40;

/// PIT data port for Channel 2 (speaker / calibration).
pub const PIT_PORT_CH2: u16 = 0x42;

/// PIT Mode/Command register port.
pub const PIT_PORT_CMD: u16 = 0x43;

/// System control port B — gate and output status for channel 2.
pub const PIT_PORT_CTRL_B: u16 = 0x61;

/// Mask for gate signal (bit 0) of port 0x61.
pub const CTRL_B_GATE2: u8 = 0x01;

/// Mask for speaker enable (bit 1) of port 0x61.
pub const CTRL_B_SPEAKER: u8 = 0x02;

/// Mask for OUT2 output (bit 5) of port 0x61.
pub const CTRL_B_OUT2: u8 = 0x20;

/// Operating mode 2: Rate Generator (periodic divide-by-N).
pub const MODE_RATE_GEN: u8 = 0x04;

/// Operating mode 3: Square wave generator (50% duty cycle).
pub const MODE_SQUARE: u8 = 0x06;

/// Operating mode 0: Interrupt on terminal count (one-shot).
pub const MODE_ONESHOT: u8 = 0x00;

/// Access mode: lo byte then hi byte (most common).
pub const ACCESS_LOHI: u8 = 0x30;

/// Channel 0 select bits.
pub const SEL_CH0: u8 = 0x00;

/// Channel 2 select bits.
pub const SEL_CH2: u8 = 0x80;

/// Latch count command (access field = 00).
pub const ACCESS_LATCH: u8 = 0x00;

// ---------------------------------------------------------------------------
// Port I/O primitives
// ---------------------------------------------------------------------------

/// Writes a byte to an I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid PIT I/O port and this is ring 0.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O; caller ensures port/privilege level are correct.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem));
    }
}

/// Reads a byte from an I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid PIT I/O port and this is ring 0.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: Port I/O; caller ensures port/privilege level are correct.
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nostack, nomem));
    }
    v
}

// ---------------------------------------------------------------------------
// PitMode
// ---------------------------------------------------------------------------

/// Selectable operating mode for a PIT channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PitMode {
    /// One-shot: counter counts to zero then stops (mode 0).
    Oneshot,
    /// Rate generator: reloads automatically, output low for one tick (mode 2).
    #[default]
    RateGenerator,
    /// Square wave: reloads automatically, 50 % duty cycle (mode 3).
    SquareWave,
}

impl PitMode {
    const fn to_cmd_bits(self) -> u8 {
        match self {
            PitMode::Oneshot => MODE_ONESHOT,
            PitMode::RateGenerator => MODE_RATE_GEN,
            PitMode::SquareWave => MODE_SQUARE,
        }
    }
}

// ---------------------------------------------------------------------------
// PitHw
// ---------------------------------------------------------------------------

/// Hardware wrapper for the 8254 PIT.
///
/// Provides channel programming, latch-read, and delay functions
/// with architecture-guarded implementations.
pub struct PitHw;

impl PitHw {
    /// Create a new `PitHw` instance (stateless; just a namespace).
    pub const fn new() -> Self {
        Self
    }

    /// Program channel 0 for periodic system tick at `freq_hz`.
    ///
    /// This configures IRQ 0 to fire at approximately `freq_hz` Hz.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    /// Returns [`Error::InvalidArgument`] if `freq_hz` is zero.
    pub fn init_system_timer(&self, freq_hz: u32) -> Result<()> {
        if freq_hz == 0 {
            return Err(Error::InvalidArgument);
        }
        #[cfg(target_arch = "x86_64")]
        {
            let divisor = (PIT_HZ / freq_hz.min(PIT_HZ)).max(1) as u16;
            // SAFETY: Programming PIT channel 0 for rate-generator mode.
            unsafe {
                let cmd = SEL_CH0 | ACCESS_LOHI | MODE_RATE_GEN;
                outb(PIT_PORT_CMD, cmd);
                outb(PIT_PORT_CH0, (divisor & 0xFF) as u8);
                outb(PIT_PORT_CH0, (divisor >> 8) as u8);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = freq_hz;
            Err(Error::NotImplemented)
        }
    }

    /// Program channel 0 with a raw 16-bit `divisor` and given `mode`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn program_channel0(&self, divisor: u16, mode: PitMode) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Programming PIT channel 0 with specified mode.
            unsafe {
                let cmd = SEL_CH0 | ACCESS_LOHI | mode.to_cmd_bits();
                outb(PIT_PORT_CMD, cmd);
                outb(PIT_PORT_CH0, (divisor & 0xFF) as u8);
                outb(PIT_PORT_CH0, (divisor >> 8) as u8);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (divisor, mode);
            Err(Error::NotImplemented)
        }
    }

    /// Program channel 2 as a one-shot countdown with `divisor`.
    ///
    /// Used during APIC timer calibration. After calling this, enable the
    /// gate with [`Self::ch2_gate_enable`] and poll [`Self::ch2_done`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn program_channel2_oneshot(&self, divisor: u16) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Programming PIT channel 2 in one-shot mode.
            unsafe {
                let cmd = SEL_CH2 | ACCESS_LOHI | MODE_ONESHOT;
                outb(PIT_PORT_CMD, cmd);
                outb(PIT_PORT_CH2, (divisor & 0xFF) as u8);
                outb(PIT_PORT_CH2, (divisor >> 8) as u8);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = divisor;
            Err(Error::NotImplemented)
        }
    }

    /// Enable the gate for channel 2 (bit 0 of port 0x61).
    ///
    /// This starts counting. Call after [`Self::program_channel2_oneshot`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn ch2_gate_enable(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Modifying port 0x61 gate/speaker bits.
            unsafe {
                let v = inb(PIT_PORT_CTRL_B);
                outb(PIT_PORT_CTRL_B, (v | CTRL_B_GATE2) & !CTRL_B_SPEAKER);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    /// Disable the gate for channel 2.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn ch2_gate_disable(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Modifying port 0x61 gate bit.
            unsafe {
                let v = inb(PIT_PORT_CTRL_B);
                outb(PIT_PORT_CTRL_B, v & !CTRL_B_GATE2);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    /// Returns `true` when channel 2 has reached terminal count (OUT2 high).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn ch2_done(&self) -> Result<bool> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Read-only port I/O to system control port B.
            let v = unsafe { inb(PIT_PORT_CTRL_B) };
            Ok(v & CTRL_B_OUT2 != 0)
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    /// Read the current counter value from channel 0 using a counter latch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn read_ch0_count(&self) -> Result<u16> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Counter latch command followed by two reads.
            unsafe {
                let latch_cmd = SEL_CH0 | ACCESS_LATCH;
                outb(PIT_PORT_CMD, latch_cmd);
                let lo = inb(PIT_PORT_CH0);
                let hi = inb(PIT_PORT_CH0);
                Ok(u16::from(lo) | (u16::from(hi) << 8))
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    /// Mask (silence) channel 0 by loading a zero divisor in one-shot mode.
    ///
    /// Useful when handing off the system timer to the APIC timer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn mask_channel0(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Stops channel 0 by writing mode 0 with a zero reload.
            unsafe {
                outb(PIT_PORT_CMD, SEL_CH0 | ACCESS_LOHI | MODE_ONESHOT);
                outb(PIT_PORT_CH0, 0);
                outb(PIT_PORT_CH0, 0);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    /// Convert a desired frequency in Hz to a PIT 16-bit divisor.
    ///
    /// Returns 0xFFFF if `freq_hz` is too small (< 19 Hz).
    pub const fn freq_to_divisor(freq_hz: u32) -> u16 {
        if freq_hz == 0 {
            return 0xFFFF;
        }
        let d = PIT_HZ / freq_hz;
        if d > 0xFFFF { 0xFFFF } else { d as u16 }
    }

    /// Convert a PIT divisor to approximate frequency in Hz.
    pub const fn divisor_to_freq(divisor: u16) -> u32 {
        if divisor == 0 {
            PIT_HZ
        } else {
            PIT_HZ / divisor as u32
        }
    }
}

impl Default for PitHw {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CalibrationResult
// ---------------------------------------------------------------------------

/// Result of a PIT-based timer calibration measurement.
#[derive(Debug, Clone, Copy, Default)]
pub struct PitCalibrationResult {
    /// The PIT divisor used for the measurement window.
    pub divisor: u16,
    /// Duration of the measurement window in nanoseconds.
    pub window_ns: u64,
    /// Number of ticks counted in the target timer during the window.
    pub ticks_counted: u64,
    /// Derived frequency of the target timer in Hz.
    pub derived_freq_hz: u64,
}

impl PitCalibrationResult {
    /// Build a calibration result from the PIT divisor and measured tick delta.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `divisor` is zero.
    pub fn from_measurement(divisor: u16, ticks_counted: u64) -> Result<Self> {
        if divisor == 0 {
            return Err(Error::InvalidArgument);
        }
        let window_ns = (divisor as u64 * 1_000_000_000) / PIT_HZ as u64;
        let derived_freq_hz = if window_ns == 0 {
            0
        } else {
            (ticks_counted as u128 * 1_000_000_000 / window_ns as u128) as u64
        };
        Ok(Self {
            divisor,
            window_ns,
            ticks_counted,
            derived_freq_hz,
        })
    }
}
