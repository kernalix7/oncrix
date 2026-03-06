// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Local APIC (Advanced Programmable Interrupt Controller) timer driver.
//!
//! The Local APIC timer is a per-CPU timer built into the processor.
//! It replaces the legacy 8254 PIT for scheduling ticks, offering
//! higher precision and per-core timer interrupts.
//!
//! The APIC is memory-mapped, typically at `0xFEE0_0000`. This driver
//! supports one-shot and periodic modes.

use crate::timer::Timer;
use oncrix_lib::Result;

/// Default Local APIC base address (identity-mapped).
pub const APIC_BASE: u64 = 0xFEE0_0000;

/// APIC register offsets.
mod reg {
    /// APIC ID Register.
    pub const ID: u32 = 0x020;
    /// APIC Version Register.
    pub const VERSION: u32 = 0x030;
    /// Task Priority Register.
    pub const TPR: u32 = 0x080;
    /// End-Of-Interrupt Register.
    pub const EOI: u32 = 0x0B0;
    /// Spurious Interrupt Vector Register.
    pub const SIVR: u32 = 0x0F0;
    /// Timer Local Vector Table entry.
    pub const LVT_TIMER: u32 = 0x320;
    /// Timer Initial Count Register.
    pub const TIMER_INIT_COUNT: u32 = 0x380;
    /// Timer Current Count Register.
    pub const TIMER_CURRENT_COUNT: u32 = 0x390;
    /// Timer Divide Configuration Register.
    pub const TIMER_DIVIDE: u32 = 0x3E0;
}

/// LVT timer mode bits (bits 17-18).
mod timer_mode {
    /// One-shot: fires once, then stops.
    pub const ONE_SHOT: u32 = 0b00 << 17;
    /// Periodic: auto-reloads after each interrupt.
    pub const PERIODIC: u32 = 0b01 << 17;
}

/// LVT mask bit (bit 16). When set, the interrupt is masked.
const LVT_MASKED: u32 = 1 << 16;

/// Spurious Interrupt Vector Register: APIC software enable (bit 8).
const SIVR_APIC_ENABLE: u32 = 1 << 8;

/// Divide configuration values.
/// Maps to divide-by values: 1, 2, 4, 8, 16, 32, 64, 128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TimerDivide {
    /// Divide by 1.
    By1 = 0b1011,
    /// Divide by 2.
    By2 = 0b0000,
    /// Divide by 4.
    By4 = 0b0001,
    /// Divide by 8.
    By8 = 0b0010,
    /// Divide by 16.
    By16 = 0b0011,
    /// Divide by 32.
    By32 = 0b1000,
    /// Divide by 64.
    By64 = 0b1001,
    /// Divide by 128.
    By128 = 0b1010,
}

/// Local APIC timer driver.
pub struct LocalApicTimer {
    /// Base virtual address of the APIC MMIO registers.
    base: u64,
    /// Timer interrupt vector (e.g., 48 to avoid PIC range 32-47).
    vector: u8,
    /// Calibrated frequency in Hz (bus clock / divider).
    frequency: u64,
    /// Software tick counter (incremented by IRQ handler).
    ticks: u64,
    /// Current divide configuration.
    divide: TimerDivide,
}

impl LocalApicTimer {
    /// Create a new Local APIC timer (not yet enabled).
    ///
    /// `vector` is the IDT vector number for timer interrupts.
    /// Typically 48 (right after the PIC range 32-47).
    pub const fn new(base: u64, vector: u8) -> Self {
        Self {
            base,
            vector,
            frequency: 0,
            ticks: 0,
            divide: TimerDivide::By16,
        }
    }

    /// Read a 32-bit APIC register.
    fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: APIC MMIO region is identity-mapped in kernel space.
        // Reads from well-known register offsets.
        unsafe {
            let addr = (self.base + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    /// Write a 32-bit APIC register.
    fn write_reg(&self, offset: u32, value: u32) {
        // SAFETY: APIC MMIO region is identity-mapped in kernel space.
        // Writes to well-known register offsets.
        unsafe {
            let addr = (self.base + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    /// Enable the Local APIC (set software enable bit in SIVR).
    ///
    /// The spurious vector is set to 0xFF (a common choice).
    pub fn enable_apic(&self) {
        let sivr = self.read_reg(reg::SIVR);
        self.write_reg(reg::SIVR, sivr | SIVR_APIC_ENABLE | 0xFF);
    }

    /// Send an End-Of-Interrupt signal.
    pub fn send_eoi(&self) {
        self.write_reg(reg::EOI, 0);
    }

    /// Get the APIC ID of the current processor.
    pub fn id(&self) -> u8 {
        (self.read_reg(reg::ID) >> 24) as u8
    }

    /// Get the APIC version.
    pub fn version(&self) -> u32 {
        self.read_reg(reg::VERSION) & 0xFF
    }

    /// Set the timer divide configuration.
    pub fn set_divide(&mut self, divide: TimerDivide) {
        self.divide = divide;
        self.write_reg(reg::TIMER_DIVIDE, divide as u32);
    }

    /// Calibrate the APIC timer frequency using the PIT as a reference.
    ///
    /// This programs the PIT for a known duration and measures how
    /// many APIC ticks elapse. Must be called before using the APIC
    /// timer for scheduling.
    ///
    /// Returns the calibrated frequency in Hz.
    pub fn calibrate_with_pit(&mut self) -> u64 {
        // Set divide configuration.
        self.write_reg(reg::TIMER_DIVIDE, self.divide as u32);

        // Set initial count to max, one-shot, masked (don't fire IRQ yet).
        self.write_reg(
            reg::LVT_TIMER,
            LVT_MASKED | timer_mode::ONE_SHOT | self.vector as u32,
        );
        self.write_reg(reg::TIMER_INIT_COUNT, u32::MAX);

        // Wait ~10ms using PIT channel 2.
        // PIT frequency = 1,193,182 Hz; 10ms ≈ 11932 ticks.
        pit_sleep_10ms();

        // Read how many ticks elapsed.
        let remaining = self.read_reg(reg::TIMER_CURRENT_COUNT);
        let elapsed = u32::MAX - remaining;

        // Stop the timer.
        self.write_reg(reg::TIMER_INIT_COUNT, 0);

        // elapsed ticks in ~10ms → frequency = elapsed * 100.
        self.frequency = elapsed as u64 * 100;
        self.frequency
    }

    /// Set a calibrated frequency directly (e.g., from CPUID or ACPI).
    pub fn set_frequency(&mut self, freq: u64) {
        self.frequency = freq;
    }

    /// Increment the tick counter. Called from the timer IRQ handler.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
    }

    /// Read the current APIC timer count-down value.
    pub fn current_count(&self) -> u32 {
        self.read_reg(reg::TIMER_CURRENT_COUNT)
    }

    /// Return the configured interrupt vector.
    pub fn vector(&self) -> u8 {
        self.vector
    }

    /// Set the task priority register (for interrupt priority filtering).
    pub fn set_task_priority(&self, priority: u8) {
        self.write_reg(reg::TPR, priority as u32);
    }
}

impl Timer for LocalApicTimer {
    fn frequency_hz(&self) -> u64 {
        self.frequency
    }

    fn current_ticks(&self) -> u64 {
        self.ticks
    }

    fn set_oneshot(&mut self, ticks: u64) -> Result<()> {
        let count = ticks.min(u32::MAX as u64) as u32;
        if count == 0 {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.write_reg(reg::TIMER_DIVIDE, self.divide as u32);
        self.write_reg(reg::LVT_TIMER, timer_mode::ONE_SHOT | self.vector as u32);
        self.write_reg(reg::TIMER_INIT_COUNT, count);
        Ok(())
    }

    fn set_periodic(&mut self, ticks: u64) -> Result<()> {
        let count = ticks.min(u32::MAX as u64) as u32;
        if count == 0 {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.write_reg(reg::TIMER_DIVIDE, self.divide as u32);
        self.write_reg(reg::LVT_TIMER, timer_mode::PERIODIC | self.vector as u32);
        self.write_reg(reg::TIMER_INIT_COUNT, count);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        // Mask the timer LVT entry and zero the count.
        self.write_reg(reg::LVT_TIMER, LVT_MASKED);
        self.write_reg(reg::TIMER_INIT_COUNT, 0);
        Ok(())
    }
}

/// Sleep approximately 10ms using the PIT channel 2 (speaker gate).
///
/// This is a calibration helper — reads PIT status in a busy loop.
/// Only used once during early boot for APIC timer calibration.
fn pit_sleep_10ms() {
    // PIT channel 2, mode 0 (one-shot), lo/hi byte.
    const PIT_CH2_DATA: u16 = 0x42;
    const PIT_COMMAND: u16 = 0x43;
    const PIT_CH2_GATE: u16 = 0x61;

    // ~10ms at 1,193,182 Hz ≈ 11932 ticks.
    const COUNT: u16 = 11932;

    // SAFETY: Port I/O during calibration in Ring 0.
    unsafe {
        use super::io::{inb, outb};

        // Disable speaker, enable gate for channel 2.
        let gate = inb(PIT_CH2_GATE);
        outb(PIT_CH2_GATE, (gate & 0xFD) | 0x01);

        // Channel 2, mode 0, lo/hi byte access.
        outb(PIT_COMMAND, 0xB0);
        outb(PIT_CH2_DATA, (COUNT & 0xFF) as u8);
        outb(PIT_CH2_DATA, (COUNT >> 8) as u8);

        // Reset the gate to start counting.
        let gate = inb(PIT_CH2_GATE);
        outb(PIT_CH2_GATE, gate & 0xFE);
        outb(PIT_CH2_GATE, gate | 0x01);

        // Wait for OUT pin (bit 5 of port 0x61) to go high.
        loop {
            if inb(PIT_CH2_GATE) & 0x20 != 0 {
                break;
            }
        }
    }
}
