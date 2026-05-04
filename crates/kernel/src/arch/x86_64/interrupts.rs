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
///
/// # Phase 20 — preemptive scheduling
///
/// When the IRQ fires from ring 3 the CPU loads the per-thread
/// kernel stack from `TSS.RSP0` and pushes the user iretq frame
/// onto that stack. We can therefore reuse the cooperative path
/// (`sched_yield_once`): it merely swaps the kernel `RSP` between
/// `CpuContext`s, leaving each thread's iretq frame untouched on
/// its own private kstack. When the outgoing thread is resumed,
/// `switch_context` returns into this handler's epilogue, which
/// runs `iretq` against the still-intact frame and resumes user
/// mode at the preempted `RIP/RSP/RFLAGS`.
///
/// Cooperative `yield_now()` callers (syscall layer) run with
/// `IF=0` (FMASK clears it on `SYSCALL` entry), so an in-flight
/// `prepare_switch` / `switch_context` pair can never be raced by
/// this handler.
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

    // Skip the switch when only the idle thread is runnable —
    // `prepare_switch` would return `None` anyway, but checking
    // up front keeps the hot-path branch-predictor friendly and
    // avoids touching the SYSCALL atomics on every tick.
    // SAFETY: single-CPU + IF=0 (interrupt gate) guarantees the
    // scheduler is not concurrently mutated.
    let should_switch = unsafe {
        #[allow(static_mut_refs)]
        let sched = &crate::arch::x86_64::init::SCHEDULER;
        sched.ready_count() > 0
    };
    if !should_switch {
        return;
    }

    // SAFETY: IRQ entry guarantees IF=0 (interrupt gate); we hold
    // no scheduler borrow. `sched_yield_once` is documented to
    // require both. On return, the previously-current thread has
    // been re-elected (after some other thread ran) and the iretq
    // frame still on top of its kernel stack is restored by the
    // x86-interrupt epilogue.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::x86_64::init::SCHEDULER;
        let _ = crate::arch::x86_64::sched_glue::sched_yield_once(sched);
    }

    // Poll COM1 UART RX as a fallback: drain all available bytes into
    // STDIN_BUF even if the IRQ 4 path misses them. This handles QEMU
    // stdio delivery that does not assert the UART interrupt line.
    //
    // SAFETY: IRQ 0 context, IF=0, single CPU — same invariant as the
    // uart_handler and console_push_byte callers.
    unsafe {
        loop {
            let lsr = oncrix_hal::arch::x86_64::io::inb(0x3FD);
            if lsr & 0x01 == 0 {
                break;
            }
            let raw = oncrix_hal::arch::x86_64::io::inb(0x3F8);
            let byte = if raw == 0x0D { 0x0A } else { raw };
            crate::console::console_push_byte(byte);
            // Echo back to TX so the user sees what they typed.
            let mut serial = Uart16550::new(COM1);
            let _ = serial.write_byte(byte);
        }
    }
}

/// IRQ 1 -- PS/2 keyboard interrupt.
///
/// Reads the raw scancode, EOIs the PIC, dispatches [`crate::console::translate`]
/// to decode the event, updates modifier state, and pushes printable ASCII
/// bytes onto the stdin ring buffer with echo to COM1.
pub extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
    // SAFETY: Reading PS/2 data port (0x60) in Ring 0 is standard.
    let scancode = unsafe { oncrix_hal::arch::x86_64::io::inb(0x60) };

    // SAFETY: Raw pointer to `static mut PIC`; single-CPU IF=0 context.
    unsafe {
        let pic_ptr = &raw mut PIC;
        let _ = (*pic_ptr).acknowledge(InterruptVector(PIC_MASTER_OFFSET + 1));
    }

    // SAFETY: IRQ 1 context, IF=0, single CPU — matches translate()'s contract.
    let event = unsafe { crate::console::translate(scancode) };

    // SAFETY: Modifier state update; same IF=0 single-CPU guarantee.
    unsafe {
        #[allow(static_mut_refs)]
        let mods = &mut crate::console::KBD_MODS;
        match event {
            crate::console::KbdEvent::ShiftDown => mods.shift = true,
            crate::console::KbdEvent::ShiftUp => mods.shift = false,
            crate::console::KbdEvent::CapsToggle => mods.caps = !mods.caps,
            crate::console::KbdEvent::CtrlDown => mods.ctrl = true,
            crate::console::KbdEvent::CtrlUp => mods.ctrl = false,
            crate::console::KbdEvent::Ascii(ascii) => {
                // SAFETY: IRQ context, IF=0; ring buffer invariant upheld.
                crate::console::console_push_byte(ascii);
                if ascii == b'\n' || (0x20..=0x7E).contains(&ascii) {
                    let mut serial = Uart16550::new(COM1);
                    let _ = serial.write_byte(ascii);
                }
            }
            crate::console::KbdEvent::Ignore => {}
        }
    }
}

/// IRQ 4 -- COM1 UART receive interrupt.
///
/// Reads all available bytes from the UART RBR while LSR indicates
/// Data Ready, pushes each byte into STDIN_BUF, echoes it back to
/// TX, and translates CR (0x0D) to LF (0x0A) so Enter produces a
/// newline in the shell's read_line loop.
pub extern "x86-interrupt" fn uart_handler(_frame: InterruptStackFrame) {
    // SAFETY: Accessing UART I/O ports in Ring 0 with IF=0 (interrupt gate).
    unsafe {
        let lsr = oncrix_hal::arch::x86_64::io::inb(0x3FD);
        if lsr & 0x01 == 0 {
            // No data ready; send EOI and return.
            let pic_ptr = &raw mut PIC;
            let _ = (*pic_ptr).acknowledge(InterruptVector(PIC_MASTER_OFFSET + 4));
            return;
        }
        let raw_byte = oncrix_hal::arch::x86_64::io::inb(0x3F8);

        // SAFETY: Raw pointer to `static mut PIC`; single-CPU IF=0 context.
        let pic_ptr = &raw mut PIC;
        let _ = (*pic_ptr).acknowledge(InterruptVector(PIC_MASTER_OFFSET + 4));

        let byte = if raw_byte == 0x0D { 0x0A } else { raw_byte };

        // SAFETY: IRQ 4 context, IF=0, single CPU — same invariant as console_push_byte.
        crate::console::console_push_byte(byte);

        // Echo the byte back to UART TX.
        let mut serial = Uart16550::new(COM1);
        let _ = serial.write_byte(byte);
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
