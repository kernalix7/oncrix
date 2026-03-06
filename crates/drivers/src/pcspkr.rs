// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PC speaker driver.
//!
//! Controls the system PC speaker found on all PC-compatible hardware via
//! the PIT (Programmable Interval Timer) channel 2 and port 0x61 speaker gate.
//! Produces simple square-wave tones at arbitrary frequencies.

use oncrix_lib::{Error, Result};

/// PIT I/O ports.
const PIT_CHANNEL2_DATA: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;

/// PC speaker gate control port (also used for NMI, memory parity, etc.).
const PORT_B: u16 = 0x61;

/// Port B bit definitions.
const PORTB_SPEAKER_ENABLE: u8 = 1 << 1; // Connect speaker to PIT channel 2
const PORTB_GATE2: u8 = 1 << 0; // Gate for PIT channel 2

/// PIT command byte for channel 2, square-wave mode.
/// Channel 2 (bits 7:6 = 10), lo/hi access (bits 5:4 = 11),
/// square-wave mode (bits 3:1 = 011), binary counter (bit 0 = 0).
const PIT_CMD_CH2_SQUARE: u8 = 0b1011_0110;

/// PIT base clock frequency (1193182 Hz).
const PIT_FREQ_HZ: u32 = 1_193_182;

/// Minimum and maximum supported frequencies.
const FREQ_MIN: u32 = 20; // 20 Hz (lower limit of human hearing)
const FREQ_MAX: u32 = 20_000; // 20 kHz (upper limit)

/// Compute the PIT divisor for a given frequency in Hz.
///
/// Returns `Err(InvalidArgument)` if the frequency is outside the supported range.
fn freq_to_divisor(freq_hz: u32) -> Result<u16> {
    if freq_hz < FREQ_MIN || freq_hz > FREQ_MAX {
        return Err(Error::InvalidArgument);
    }
    let divisor = PIT_FREQ_HZ / freq_hz;
    // Clamp to 16-bit range; PIT divisor of 0 means 65536.
    Ok(divisor.min(0xFFFF) as u16)
}

/// PC speaker driver.
pub struct PcSpeaker {
    /// Current tone frequency in Hz (0 = silent).
    current_freq: u32,
    /// Speaker is currently on.
    active: bool,
}

impl PcSpeaker {
    /// Create a new PC speaker driver.
    pub const fn new() -> Self {
        Self {
            current_freq: 0,
            active: false,
        }
    }

    /// Emit a tone at the given frequency. Turns the speaker on if it was off.
    ///
    /// # Arguments
    /// - `freq_hz`: tone frequency in Hz (20–20000 Hz)
    pub fn beep(&mut self, freq_hz: u32) -> Result<()> {
        let divisor = freq_to_divisor(freq_hz)?;
        self.program_pit(divisor);
        self.speaker_on();
        self.current_freq = freq_hz;
        self.active = true;
        Ok(())
    }

    /// Stop the speaker.
    pub fn stop(&mut self) {
        self.speaker_off();
        self.current_freq = 0;
        self.active = false;
    }

    /// Return whether the speaker is currently emitting a tone.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Return the current tone frequency (0 if silent).
    pub fn current_frequency(&self) -> u32 {
        self.current_freq
    }

    /// Program PIT channel 2 with the given 16-bit divisor.
    fn program_pit(&mut self, divisor: u16) {
        // SAFETY: PIT_COMMAND (0x43) and PIT_CHANNEL2_DATA (0x42) are
        // standard x86 PC timer ports present on all PC-compatible hardware.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // Send mode command.
            core::arch::asm!(
                "out dx, al",
                in("dx") PIT_COMMAND,
                in("al") PIT_CMD_CH2_SQUARE,
                options(nomem, nostack)
            );
            // Send low byte of divisor.
            core::arch::asm!(
                "out dx, al",
                in("dx") PIT_CHANNEL2_DATA,
                in("al") (divisor & 0xFF) as u8,
                options(nomem, nostack)
            );
            // Send high byte of divisor.
            core::arch::asm!(
                "out dx, al",
                in("dx") PIT_CHANNEL2_DATA,
                in("al") ((divisor >> 8) & 0xFF) as u8,
                options(nomem, nostack)
            );
        }
    }

    /// Enable the PC speaker (connect channel 2 output to speaker).
    fn speaker_on(&mut self) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: PORT_B (0x61) is the standard PC speaker gate/control port.
        // We read the current value and OR in only the two speaker bits,
        // preserving all other bits (NMI, memory parity, etc.).
        unsafe {
            let val: u8;
            core::arch::asm!(
                "in al, dx",
                in("dx") PORT_B,
                out("al") val,
                options(nomem, nostack)
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") PORT_B,
                in("al") val | PORTB_SPEAKER_ENABLE | PORTB_GATE2,
                options(nomem, nostack)
            );
        }
    }

    /// Disable the PC speaker (disconnect channel 2 output from speaker).
    fn speaker_off(&mut self) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: PORT_B is the standard speaker gate port; we clear only
        // the two speaker bits, leaving all other bits intact.
        unsafe {
            let val: u8;
            core::arch::asm!(
                "in al, dx",
                in("dx") PORT_B,
                out("al") val,
                options(nomem, nostack)
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") PORT_B,
                in("al") val & !(PORTB_SPEAKER_ENABLE | PORTB_GATE2),
                options(nomem, nostack)
            );
        }
    }
}

impl Default for PcSpeaker {
    fn default() -> Self {
        Self::new()
    }
}
