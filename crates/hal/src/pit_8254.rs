// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel 8254 Programmable Interval Timer (PIT) driver.
//!
//! The 8254 PIT provides three independent timer channels:
//! - **Channel 0**: System timer tick (IRQ 0). Used for OS tick and APIC calibration.
//! - **Channel 1**: DRAM refresh (legacy; do not touch).
//! - **Channel 2**: PC speaker / one-shot delay / APIC frequency calibration.
//!
//! The PIT input clock is `PIT_FREQ` ≈ 1.193182 MHz (derived from 14.31818 MHz / 12).
//!
//! # Programming sequence
//! 1. Write the Mode/Command byte to port 0x43.
//! 2. Write the 16-bit initial count to the channel's data port (low byte then high byte).
//!
//! Reference: Intel 8254 Programmable Interval Timer Datasheet.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PIT input clock frequency in Hz (14.318180 MHz / 12).
pub const PIT_FREQ: u32 = 1_193_182;

/// Channel 0 data port (system timer).
const PIT_CH0_PORT: u16 = 0x40;
/// Channel 1 data port (DRAM refresh — legacy).
const PIT_CH1_PORT: u16 = 0x41;
/// Channel 2 data port (speaker / calibration).
const PIT_CH2_PORT: u16 = 0x42;
/// PIT Mode/Command register port.
const PIT_CMD_PORT: u16 = 0x43;
/// Port 0x61 — System control: bit 0 = gate for channel 2, bit 1 = speaker enable.
const PIT_CTRL_PORT: u16 = 0x61;

// ---------------------------------------------------------------------------
// Mode/Command byte encoding
// ---------------------------------------------------------------------------

/// Channel select: Channel 0.
const SEL_CH0: u8 = 0x00 << 6;
/// Channel select: Channel 1.
const SEL_CH1: u8 = 0x01 << 6;
/// Channel select: Channel 2.
const SEL_CH2: u8 = 0x02 << 6;
/// Channel select: Read-back command.
const _SEL_READBACK: u8 = 0x03 << 6;

/// Access mode: Low byte only.
const ACCESS_LO: u8 = 0x01 << 4;
/// Access mode: High byte only.
const _ACCESS_HI: u8 = 0x02 << 4;
/// Access mode: Low byte then high byte.
const ACCESS_LOHI: u8 = 0x03 << 4;

/// Operating mode 0: Interrupt on terminal count.
const _MODE0: u8 = 0x00 << 1;
/// Operating mode 2: Rate generator (periodic, divide-by-N).
pub const MODE_RATE_GEN: u8 = 0x02 << 1;
/// Operating mode 3: Square wave generator (periodic, 50% duty cycle).
pub const MODE_SQUARE: u8 = 0x03 << 1;
/// Operating mode 1: Hardware one-shot.
pub const MODE_ONESHOT: u8 = 0x01 << 1;
/// Operating mode 4: Software triggered strobe.
const _MODE4: u8 = 0x04 << 1;

/// BCD counting mode (1 = BCD, 0 = binary). Always use binary (0).
const BCD_BINARY: u8 = 0x00;

// ---------------------------------------------------------------------------
// Port I/O
// ---------------------------------------------------------------------------

/// Writes to an I/O port.
///
/// # Safety
/// Writing to I/O ports can have hardware side effects. Caller must ensure
/// `port` is the correct PIT port.
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O; caller ensures port is valid.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

/// Reads from an I/O port.
///
/// # Safety
/// See `outb`.
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Port I/O read; caller ensures port is valid.
    unsafe {
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    }
    val
}

// ---------------------------------------------------------------------------
// PIT Channel
// ---------------------------------------------------------------------------

/// Represents a single PIT channel.
#[derive(Clone, Copy, Debug)]
pub struct PitChannel {
    /// Data port for this channel.
    port: u16,
    /// Channel select bits for the mode/command register.
    sel: u8,
}

impl PitChannel {
    /// PIT Channel 0 (system timer, IRQ 0).
    pub const CH0: PitChannel = PitChannel {
        port: PIT_CH0_PORT,
        sel: SEL_CH0,
    };
    /// PIT Channel 1 (DRAM refresh — do not program).
    pub const CH1: PitChannel = PitChannel {
        port: PIT_CH1_PORT,
        sel: SEL_CH1,
    };
    /// PIT Channel 2 (PC speaker / calibration).
    pub const CH2: PitChannel = PitChannel {
        port: PIT_CH2_PORT,
        sel: SEL_CH2,
    };
}

// ---------------------------------------------------------------------------
// Programming API
// ---------------------------------------------------------------------------

/// Programs a PIT channel to fire at the requested `freq_hz` using the
/// specified operating `mode` (e.g., `MODE_RATE_GEN` or `MODE_SQUARE`).
///
/// # Parameters
/// - `channel`: Which PIT channel to configure.
/// - `freq_hz`: Desired output frequency. Clamped to [1, PIT_FREQ].
/// - `mode`: PIT operating mode byte (e.g., `MODE_RATE_GEN`).
///
/// # Safety
/// Must only be called from ring 0. Modifying channel 1 (DRAM refresh) may
/// cause system instability on old hardware.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_set_frequency(channel: PitChannel, freq_hz: u32, mode: u8) {
    let freq_hz = freq_hz.max(1).min(PIT_FREQ);
    let divisor = (PIT_FREQ / freq_hz) as u16;
    // SAFETY: Programming a PIT channel via its mode byte and data port.
    unsafe {
        let cmd = channel.sel | ACCESS_LOHI | mode | BCD_BINARY;
        outb(PIT_CMD_PORT, cmd);
        outb(channel.port, (divisor & 0xFF) as u8);
        outb(channel.port, (divisor >> 8) as u8);
    }
}

/// Reads the current counter value from a PIT channel using a latch read.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_read_count(channel: PitChannel) -> u16 {
    // SAFETY: Counter latch command then two data reads.
    unsafe {
        // Counter latch command: access mode = 00
        let latch_cmd = channel.sel | 0x00 | BCD_BINARY;
        outb(PIT_CMD_PORT, latch_cmd);
        let lo = inb(channel.port);
        let hi = inb(channel.port);
        (lo as u16) | ((hi as u16) << 8)
    }
}

/// Configures channel 0 as a periodic interrupt at the given frequency.
///
/// This is the standard OS tick setup. IRQ 0 fires at `freq_hz` Hz.
///
/// # Safety
/// See `pit_set_frequency`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_init_timer(freq_hz: u32) {
    // SAFETY: Programs channel 0 for periodic interrupts.
    unsafe { pit_set_frequency(PitChannel::CH0, freq_hz, MODE_RATE_GEN) }
}

/// Configures channel 2 in one-shot mode with the given divisor.
///
/// Used for APIC timer calibration: read the counter before and after a known
/// wall-clock interval to derive the APIC timer frequency.
///
/// # Safety
/// See `pit_set_frequency`. Must not be called concurrently with code using
/// the PC speaker.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_oneshot(divisor: u16) {
    // SAFETY: Programs channel 2 one-shot mode; gate is enabled separately.
    unsafe {
        let cmd = SEL_CH2 | ACCESS_LOHI | MODE_ONESHOT | BCD_BINARY;
        outb(PIT_CMD_PORT, cmd);
        outb(PIT_CH2_PORT, (divisor & 0xFF) as u8);
        outb(PIT_CH2_PORT, (divisor >> 8) as u8);
    }
}

/// Enables channel 2's gate (bit 0 of port 0x61) to start counting.
///
/// # Safety
/// Caller must have programmed channel 2 first. May briefly enable
/// the PC speaker if bit 1 of port 0x61 is also set.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_ch2_gate_enable() {
    // SAFETY: Port 0x61 bit 0 controls the PIT ch2 gate.
    unsafe {
        let v = inb(PIT_CTRL_PORT);
        outb(PIT_CTRL_PORT, (v | 0x01) & !0x02);
    }
}

/// Disables channel 2's gate (bit 0 of port 0x61).
///
/// # Safety
/// See `pit_ch2_gate_enable`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_ch2_gate_disable() {
    // SAFETY: Clears PIT ch2 gate bit.
    unsafe {
        let v = inb(PIT_CTRL_PORT);
        outb(PIT_CTRL_PORT, v & !0x01);
    }
}

/// Returns `true` when channel 2's output has gone low (terminal count reached).
///
/// Polls bit 5 of port 0x61.
///
/// # Safety
/// Must have started channel 2 via `pit_ch2_gate_enable`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pit_ch2_done() -> bool {
    // SAFETY: Read from port 0x61 is safe on x86 PCs.
    unsafe { inb(PIT_CTRL_PORT) & 0x20 != 0 }
}

/// Converts a desired frequency (Hz) to the PIT divisor value.
pub const fn freq_to_divisor(freq_hz: u32) -> u16 {
    if freq_hz == 0 {
        0
    } else {
        let d = PIT_FREQ / freq_hz;
        if d > 0xFFFF { 0xFFFF } else { d as u16 }
    }
}

/// Converts a PIT divisor back to approximate frequency.
pub const fn divisor_to_freq(divisor: u16) -> u32 {
    if divisor == 0 {
        PIT_FREQ
    } else {
        PIT_FREQ / (divisor as u32)
    }
}
