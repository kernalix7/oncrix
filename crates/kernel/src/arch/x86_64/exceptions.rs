// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 CPU exception handlers.
//!
//! These are minimal handlers installed during early boot. They print
//! diagnostic information to the serial console and halt the system.

use oncrix_hal::arch::x86_64::idt::InterruptStackFrame;
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;

/// Helper: write a string to COM1 (best-effort, ignores errors).
fn serial_print(s: &str) {
    let mut serial = Uart16550::new(COM1);
    let _ = serial.write_str(s);
}

/// Helper: write a u64 as hex to COM1.
fn serial_print_hex(value: u64) {
    let mut serial = Uart16550::new(COM1);
    let _ = serial.write_str("0x");
    let mut buf = [0u8; 16];
    let mut n = value;
    for byte in buf.iter_mut().rev() {
        let digit = (n & 0xF) as u8;
        *byte = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        n >>= 4;
    }
    // Skip leading zeros but always print at least one digit.
    let start = buf.iter().position(|&b| b != b'0').unwrap_or(15);
    for &byte in &buf[start..] {
        let _ = serial.write_byte(byte);
    }
}

/// Print an interrupt stack frame to serial.
fn print_stack_frame(frame: &InterruptStackFrame) {
    serial_print("  RIP: ");
    serial_print_hex(frame.rip);
    serial_print("\n  CS:  ");
    serial_print_hex(frame.cs);
    serial_print("\n  RSP: ");
    serial_print_hex(frame.rsp);
    serial_print("\n  SS:  ");
    serial_print_hex(frame.ss);
    serial_print("\n  RFLAGS: ");
    serial_print_hex(frame.rflags);
    serial_print("\n");
}

// ── Exception handlers ──────────────────────────────────────────

/// #DE — Divide Error (vector 0).
pub extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    serial_print("\n!!! EXCEPTION: Divide Error (#DE) !!!\n");
    print_stack_frame(&frame);
    halt();
}

/// #UD — Invalid Opcode (vector 6).
pub extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    serial_print("\n!!! EXCEPTION: Invalid Opcode (#UD) !!!\n");
    print_stack_frame(&frame);
    halt();
}

/// #DF — Double Fault (vector 8), with error code.
pub extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, error_code: u64) {
    serial_print("\n!!! EXCEPTION: Double Fault (#DF) !!!\n");
    serial_print("  Error code: ");
    serial_print_hex(error_code);
    serial_print("\n");
    print_stack_frame(&frame);
    halt();
}

/// #GP — General Protection Fault (vector 13), with error code.
pub extern "x86-interrupt" fn general_protection_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_print("\n!!! EXCEPTION: General Protection Fault (#GP) !!!\n");
    serial_print("  Error code: ");
    serial_print_hex(error_code);
    serial_print("\n");
    print_stack_frame(&frame);
    halt();
}

/// #PF — Page Fault (vector 14), with error code.
///
/// Splits on the originating privilege level:
///
/// * **Ring 3** (`frame.cs & 0x3 == 0x3`) — the user process tried to
///   touch an unmapped or improperly-permissioned address. POSIX-1.2024
///   maps this to `SIGSEGV` on the offending process. We raise the
///   pending bit on the current pid and invoke
///   [`crate::signal_dispatch::deliver_pending_signals`], which applies
///   the kernel-default Terminate action and never returns.
/// * **Ring 0** (`frame.cs & 0x3 == 0x0`) — the kernel itself faulted.
///   That's a real bug; print diagnostics and `halt()` so the failure
///   mode is unambiguous.
///
/// # Why call `deliver_pending_signals` from an interrupt handler
///
/// `deliver_pending_signals` is documented to require single-CPU +
/// interrupts-effectively-off; an x86-interrupt handler entered through
/// an interrupt gate satisfies both (CPU clears `IF` on entry). The
/// terminate path calls `sys_exit(139)` which `yield_now` loops without
/// returning, so the iretq epilogue this `extern "x86-interrupt"` fn
/// would otherwise execute is never reached — that is by design.
pub extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, error_code: u64) {
    // Read CR2 to get the faulting address.
    let cr2: u64;
    // SAFETY: Reading CR2 is safe in Ring 0 and only reads the
    // faulting linear address.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));
    }

    if frame.cs & 0x3 == 0x3 {
        // Ring 3 fault: convert to SIGSEGV on the current process.
        serial_print("[#PF] ring 3 fault → SIGSEGV (cr2=");
        serial_print_hex(cr2);
        serial_print(", rip=");
        serial_print_hex(frame.rip);
        serial_print(", err=");
        serial_print_hex(error_code);
        serial_print(")\n");

        // SAFETY: interrupt-gate entry guarantees IF=0; single-CPU
        // build means no concurrent access to the process table or
        // signal state. The borrow is dropped before
        // `deliver_pending_signals` walks the table.
        unsafe {
            if let Some(pid) = crate::current::current_pid()
                && let Some(entry) = crate::fork_dispatch::process_table_mut().get_mut(pid)
            {
                entry
                    .signals
                    .pending
                    .raise(oncrix_process::signal::Signal::SIGSEGV);
            }
        }

        // Apply the kernel-default Terminate action — sys_exit(139)
        // marks the thread Exited and yields forever; never returns.
        // SAFETY: same single-CPU + IF=0 contract as above.
        unsafe { crate::signal_dispatch::deliver_pending_signals(core::ptr::null_mut()) };

        // Defensive: should be unreachable. Halt the CPU rather than
        // try to iretq back into a dead user context.
        serial_print("[#PF] deliver_pending_signals returned unexpectedly — halting\n");
        halt();
    } else {
        // Ring 0 fault: kernel bug. Diagnose and stop.
        serial_print("\n!!! EXCEPTION: Page Fault (#PF) !!!\n");
        serial_print("  Error code: ");
        serial_print_hex(error_code);
        serial_print("\n  CR2 (fault address): ");
        serial_print_hex(cr2);
        serial_print("\n");
        print_stack_frame(&frame);
        halt();
    }
}

/// Halt the CPU permanently.
fn halt() -> ! {
    loop {
        // SAFETY: `hlt` halts the CPU until the next interrupt.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
