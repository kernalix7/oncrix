// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX microkernel entry point.
//!
//! This is the first Rust code that executes after the bootloader
//! transfers control. It initializes core subsystems and enters
//! the scheduler loop.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

#[cfg(target_arch = "x86_64")]
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
#[cfg(target_arch = "x86_64")]
use oncrix_hal::serial::SerialPort;

/// Kernel entry point, called by the bootloader.
///
/// # Safety
///
/// This function is called exactly once by the bootloader with a valid
/// stack pointer. No Rust runtime is available at this point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    kernel_main();
}

/// Main kernel initialization sequence.
fn kernel_main() -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        // Phase 1: Early serial console
        let mut serial = Uart16550::new(COM1);
        serial.init();
        let _ = serial.write_str("[ONCRIX] Kernel booting...\n");
        let _ = serial.write_str("[ONCRIX] Serial console initialized (COM1, 115200 8N1)\n");

        // Phase 2: GDT (segments + TSS)
        // SAFETY: Called exactly once during single-threaded boot.
        unsafe {
            oncrix_kernel::arch::x86_64::init::init_gdt();
        }

        // Phase 3: IDT (exception handlers)
        // SAFETY: Called after GDT, before enabling interrupts.
        unsafe {
            oncrix_kernel::arch::x86_64::init::init_idt();
        }

        // Phase 4: Kernel heap
        // SAFETY: Called exactly once before any heap allocation.
        unsafe {
            oncrix_kernel::arch::x86_64::init::init_heap();
        }

        // Phase 5: Scheduler (idle thread)
        // SAFETY: Called after heap init, before enabling interrupts.
        unsafe {
            oncrix_kernel::arch::x86_64::init::init_scheduler();
        }

        // Phase 6: SYSCALL/SYSRET setup
        // SAFETY: Called after GDT, configures MSRs for fast syscalls.
        unsafe {
            oncrix_kernel::arch::x86_64::syscall_entry::init_syscall();
        }

        // Phase 7: PIC + PIT timer (enables interrupts)
        // SAFETY: Called after scheduler init, enables interrupts.
        unsafe {
            oncrix_kernel::arch::x86_64::init::init_pic_and_timer();
        }

        let _ = serial.write_str("[ONCRIX] All early initialization complete.\n");
        let _ = serial.write_str("[ONCRIX] Entering halt loop.\n");
    }

    halt_loop();
}

/// Halt the CPU in an infinite loop.
///
/// Used as the final fallback when there is nothing left to schedule
/// or after an unrecoverable error.
fn halt_loop() -> ! {
    loop {
        // SAFETY: `hlt` halts the CPU until the next interrupt.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi");
        }

        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Panic handler — prints diagnostic info and halts.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        let mut serial = Uart16550::new(COM1);
        let _ = serial.write_str("\n!!! KERNEL PANIC !!!\n");
        if let Some(location) = info.location() {
            let _ = serial.write_str("  at ");
            let _ = serial.write_str(location.file());
            let _ = serial.write_str(":");
            let _ = write_u32(&mut serial, location.line());
            let _ = serial.write_str("\n");
        }
        let _ = serial.write_str("System halted.\n");
    }
    halt_loop();
}

/// Write a u32 as decimal digits to a serial port.
#[cfg(target_arch = "x86_64")]
fn write_u32(serial: &mut Uart16550, mut n: u32) -> oncrix_lib::Result<()> {
    if n == 0 {
        return serial.write_byte(b'0');
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        serial.write_byte(buf[i])?;
    }
    Ok(())
}
