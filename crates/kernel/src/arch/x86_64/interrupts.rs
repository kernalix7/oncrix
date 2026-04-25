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

/// IRQ 0 -- Timer interrupt (PIT).
///
/// Acknowledges the interrupt (EOI) before running the scheduler
/// so that higher-priority interrupts are not blocked during
/// scheduling. The interrupt gate guarantees IF=0 (interrupts
/// disabled) on entry.
pub extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    // Increment the PIT tick counter.
    // SAFETY: Accessed only in interrupt context with IF=0
    // (interrupt gate); no concurrent mutation.
    unsafe {
        let pit_ptr = &raw mut super::init::PIT_TIMER;
        (*pit_ptr).tick();
    }

    // Acknowledge IRQ 0 via PIC *before* running the scheduler.
    // Sending EOI first allows higher-priority interrupts to be
    // serviced if the scheduler re-enables interrupts.
    // SAFETY: Raw pointer to static mut, interrupt context with
    // IF=0. EOI is idempotent for the current vector.
    unsafe {
        let pic_ptr = &raw mut PIC;
        let _ = (*pic_ptr).acknowledge(InterruptVector(PIC_MASTER_OFFSET));
    }

    // Phase 11: the round-robin scheduler is driven cooperatively by
    // explicit `yield_now()` from the syscall layer. Calling
    // `schedule()` here would rewrite `SCHEDULER.current` behind the
    // back of any in-flight `prepare_switch`/`switch_context` pair,
    // which corrupts the "prev" pointer and clobbers the outgoing
    // thread's saved kernel-stack frame. Preemptive scheduling will
    // be re-enabled once we track saved IRQ frames per-thread.
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

/// Execute a closure with interrupts disabled, restoring the
/// previous interrupt state on return.
///
/// Saves RFLAGS (including IF), disables interrupts with `cli`,
/// runs the closure, then restores IF only if it was previously
/// set. This prevents nested enable/disable mismatches.
///
/// # Safety
///
/// The closure must not enable interrupts itself. The caller
/// must ensure that disabling interrupts for the duration of `f`
/// does not cause missed deadlines.
#[inline]
unsafe fn with_interrupts_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let flags: u64;
    // SAFETY: `pushfq` saves RFLAGS and `cli` disables
    // interrupts. This is a standard critical-section pattern.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) flags,
            options(preserves_flags),
        );
    }
    let result = f();
    if flags & 0x200 != 0 {
        // IF was set before we disabled -- restore it.
        // SAFETY: `sti` re-enables interrupts. We verified
        // that IF was previously set, so this is safe.
        unsafe {
            core::arch::asm!("sti", options(preserves_flags, nomem, nostack),);
        }
    }
    result
}

/// Debug: print the current tick count to serial.
///
/// Disables interrupts while reading `PIT_TIMER` to prevent a
/// torn read if the timer interrupt fires mid-access.
pub fn print_tick_count() {
    // SAFETY: Interrupts are disabled for the duration of the
    // read, preventing concurrent mutation by the timer handler.
    let ticks = unsafe {
        with_interrupts_disabled(|| {
            let pit_ptr = &raw const super::init::PIT_TIMER;
            (*pit_ptr).current_ticks()
        })
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
