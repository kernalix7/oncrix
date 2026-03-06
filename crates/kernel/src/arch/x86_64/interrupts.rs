// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 hardware interrupt (IRQ) handlers.
//!
//! These handlers are installed for PIC-mapped IRQs (vectors 32-47).
//! Each handler acknowledges the interrupt via the PIC and performs
//! minimal work before returning.

use oncrix_hal::arch::x86_64::idt::InterruptStackFrame;
use oncrix_hal::arch::x86_64::pic::PIC_MASTER_OFFSET;
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::interrupt::{InterruptController, InterruptVector};
use oncrix_hal::serial::SerialPort;
use oncrix_hal::timer::Timer;

use super::init::PIC;

/// IRQ 0 — Timer interrupt (PIT).
pub extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    // Increment the PIT tick counter.
    // SAFETY: Single-threaded access; interrupts are disabled by gate type.
    unsafe {
        let pit_ptr = &raw mut super::init::PIT_TIMER;
        (*pit_ptr).tick();
    }

    // Run the scheduler on each timer tick.
    // SAFETY: Raw pointer to static mut, accessed only in interrupt context
    // with interrupts disabled (interrupt gate).
    unsafe {
        let sched_ptr = &raw mut super::init::SCHEDULER;
        let _ = (*sched_ptr).schedule();
    }

    // Acknowledge IRQ 0 via PIC.
    // SAFETY: Raw pointer to static mut, interrupt context.
    unsafe {
        let pic_ptr = &raw mut PIC;
        let _ = (*pic_ptr).acknowledge(InterruptVector(PIC_MASTER_OFFSET));
    }
}

/// IRQ 1 — Keyboard interrupt (stub).
pub extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
    // Read scancode to clear the keyboard buffer.
    // SAFETY: Reading keyboard data port in Ring 0.
    let _scancode = unsafe { oncrix_hal::arch::x86_64::io::inb(0x60) };

    // Acknowledge IRQ 1 via PIC.
    // SAFETY: Raw pointer to static mut, single-threaded boot context.
    unsafe {
        let pic_ptr = &raw mut PIC;
        let _ = (*pic_ptr).acknowledge(InterruptVector(PIC_MASTER_OFFSET + 1));
    }
}

/// Spurious IRQ handler (IRQ 7 / IRQ 15).
///
/// The PIC can generate spurious interrupts. For IRQ 7 (master),
/// we do NOT send EOI. For IRQ 15 (slave), we send EOI only to master.
pub extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {
    // No EOI for spurious interrupts from master PIC.
}

/// Debug: print the current tick count to serial.
pub fn print_tick_count() {
    let ticks = unsafe {
        let pit_ptr = &raw const super::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    };
    let mut serial = Uart16550::new(COM1);
    let _ = serial.write_str("[ONCRIX] PIT ticks: ");
    print_u64(&mut serial, ticks);
    let _ = serial.write_str("\n");
}

/// Write a u64 as decimal to serial.
fn print_u64(serial: &mut Uart16550, mut n: u64) {
    if n == 0 {
        let _ = serial.write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        let _ = serial.write_byte(buf[i]);
    }
}
