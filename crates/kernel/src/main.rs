// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX microkernel entry point.
//!
//! On x86_64, the actual entry point (`_start32`) is defined in
//! `crates/kernel/src/arch/x86_64/boot.S`.  On aarch64, `_start` is emitted
//! by the `global_asm!` block in `crates/hal/src/arch/aarch64/boot.rs`.
//! Both stubs set up early CPU state and call [`kernel_main`].

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

#[cfg(target_arch = "x86_64")]
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
#[cfg(target_arch = "x86_64")]
use oncrix_hal::serial::SerialPort;

#[cfg(target_arch = "aarch64")]
use oncrix_hal::arch::aarch64::pl011::{PL011_BASE, Pl011};
#[cfg(target_arch = "aarch64")]
use oncrix_hal::serial::SerialPort as _;

#[cfg(target_arch = "riscv64")]
use oncrix_hal::arch::riscv64::ns16550::{NS16550_BASE, Ns16550};
#[cfg(target_arch = "riscv64")]
use oncrix_hal::serial::SerialPort as _;

// Boot stub: Multiboot1 header, PVH ELF Note, and 32-bit → 64-bit
// long-mode trampoline. Must be compiled into the binary (not stripped)
// so the linker finds `_start32` and the Xen PVH note.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("arch/x86_64/boot.S"), options(att_syntax));

// AArch64 boot stub: CPU 0 check, BSS zero, stack, VBAR_EL1, MMU enable.
// The global_asm! is emitted by the HAL crate at build time when
// oncrix-hal is compiled for aarch64.  The kernel binary links against it
// because oncrix-hal is in [dependencies].
//
// No additional global_asm! is needed here; the HAL's boot.rs provides _start.

/// Main kernel initialization sequence.
///
/// Called from the 64-bit trampoline in `boot.S` after the 32-bit stub
/// has enabled long mode, loaded page tables, and jumped to the
/// higher-half virtual address.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
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

        // Allocate unified kernel state on the heap.
        let mut state = alloc::boxed::Box::new(oncrix_kernel::state::KernelState::new());

        // Phase 8: Root filesystem (ramfs + standard dirs)
        let _ = serial.write_str("[ONCRIX] Mounting root filesystem...\n");
        match state.init_rootfs() {
            Ok(()) => {
                let _ = serial.write_str("[ONCRIX] Root filesystem mounted (ramfs on /)\n");
                let _ = serial.write_str("[ONCRIX] Created /dev /proc /tmp /sbin\n");
            }
            Err(_) => {
                let _ = serial.write_str("[ONCRIX] WARNING: Root filesystem mount failed\n");
            }
        }

        // Phase 9: IPC channels for core services
        let _ = serial.write_str("[ONCRIX] Initializing IPC channels...\n");
        match state.init_ipc() {
            Ok(()) => {
                let _ = serial.write_str(
                    "[ONCRIX] IPC channels ready (kernel<->console, \
                     kernel<->devmgr, kernel<->netd)\n",
                );
            }
            Err(_) => {
                let _ = serial.write_str("[ONCRIX] WARNING: IPC initialization failed\n");
            }
        }

        // Phase 10: Process table + service manager boot
        let _ = serial.write_str("[ONCRIX] Starting service manager...\n");
        match state.init_services() {
            Ok(()) => {
                let _ = serial.write_str("[ONCRIX] Service manager boot complete\n");
            }
            Err(_) => {
                let _ = serial.write_str("[ONCRIX] WARNING: Service manager boot failed\n");
            }
        }

        // Keep kernel state alive — leaked into a static reference
        // so subsystems can access it after kernel_main returns to
        // the halt loop. Publish through the global accessor in
        // state.rs so IPC dispatch and other subsystems can reach it.
        let state = alloc::boxed::Box::leak(state);
        // SAFETY: `state` is a valid, heap-allocated KernelState
        // that will live for the kernel's lifetime. Called exactly
        // once during single-threaded boot.
        unsafe {
            oncrix_kernel::state::set_global(state as *mut oncrix_kernel::state::KernelState);
        }

        // Phase 11: Ring 0 → Ring 3 transition.
        // Prefer the embedded `init` ELF (built with the `embed-init` feature);
        // fall back to the hello-world smoke-test stub for incremental builds.
        let _ = serial.write_str("[ONCRIX] Launching userspace (ring 3)...\n");

        // Install TSS.RSP0 so any ring 3 → 0 interrupt lands on a valid
        // kernel stack. Without this any fault (page fault, timer IRQ,
        // etc.) from ring 3 would triple-fault.
        //
        // SAFETY: GDT has been installed by phase 2; single-threaded boot.
        unsafe {
            oncrix_kernel::arch::x86_64::init::init_tss_rsp0();
        }

        // SAFETY: Single-threaded boot. GDT, IDT, and SYSCALL MSRs have been
        // fully initialized in phases 2–6. USER_LOAD_REGION is unaliased.
        let entry = unsafe { oncrix_kernel::arch::x86_64::init_embed::load_init_elf() };

        // If the embedded init loaded successfully, launch it with a
        // user-mapped RSP inside its own VMA. Otherwise fall back to the
        // in-kernel smoke-test stub (works only because it never touches
        // the fallback user stack before issuing `syscall`).
        unsafe {
            let (entry_ptr, user_rsp) = match entry {
                Some(e) => (e, oncrix_kernel::arch::x86_64::init_embed::user_init_rsp()),
                None => (
                    oncrix_kernel::arch::x86_64::usermode::usermode_test_entry as *const () as u64,
                    oncrix_kernel::arch::x86_64::usermode::fallback_user_stack_top(),
                ),
            };
            oncrix_kernel::arch::x86_64::usermode::jump_to_usermode(entry_ptr, user_rsp);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Phase 1: Early serial console via PL011.
        let mut serial = Pl011::new(PL011_BASE);
        serial.init();
        let _ = serial.write_str("[ONCRIX/aarch64] Kernel booting...\n");
        let _ = serial.write_str("[ONCRIX/aarch64] PL011 UART initialized (115200 8N1)\n");

        // Phase 2: Kernel heap.
        // SAFETY: Called exactly once during single-threaded boot.
        unsafe {
            oncrix_kernel::arch::aarch64::init_heap();
        }

        // Phase 3: GICv3 interrupt controller.
        // SAFETY: Called after heap init, GIC MMIO is mapped by identity paging.
        unsafe {
            let _ = oncrix_kernel::arch::aarch64::init_gic();
        }

        // Phase 4: Generic physical timer (10 ms tick).
        // SAFETY: Called after GIC is initialized.
        unsafe {
            let _ = oncrix_kernel::arch::aarch64::init_timer();
        }

        let _ = serial.write_str("[ONCRIX/aarch64] All early initialization complete.\n");
        let _ = serial.write_str("[ONCRIX/aarch64] Entering halt loop.\n");
    }

    #[cfg(target_arch = "riscv64")]
    {
        // Phase 1: Early serial console via NS16550.
        let mut serial = Ns16550::new(NS16550_BASE);
        serial.init();
        let _ = serial.write_str("[ONCRIX/riscv64] Kernel booting...\n");
        let _ = serial.write_str("[ONCRIX/riscv64] NS16550 UART initialized (115200 8N1)\n");

        // Phase 2: Kernel heap.
        // SAFETY: Called exactly once during single-threaded boot.
        unsafe {
            oncrix_kernel::arch::riscv64::init_heap();
        }

        // Phase 3: PLIC interrupt controller.
        // SAFETY: Called after heap init, PLIC MMIO is identity-mapped.
        unsafe {
            let _ = oncrix_kernel::arch::riscv64::init_plic();
        }

        // Phase 4: Timer (SBI extension, 10 ms tick).
        // SAFETY: Called after PLIC init.
        unsafe {
            let _ = oncrix_kernel::arch::riscv64::init_timer();
        }

        let _ = serial.write_str("[ONCRIX/riscv64] All early initialization complete.\n");
        let _ = serial.write_str("[ONCRIX/riscv64] Entering halt loop.\n");
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

        // SAFETY: `wfi` (Wait For Interrupt) halts the CPU until
        // the next interrupt and does not corrupt any state.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi");
        }

        // SAFETY: `wfi` (Wait For Interrupt) halts the CPU until
        // the next interrupt and does not corrupt any state.
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
    #[cfg(target_arch = "aarch64")]
    {
        let mut serial = Pl011::new(PL011_BASE);
        let _ = serial.write_str("\n!!! KERNEL PANIC !!!\n");
        if let Some(location) = info.location() {
            let _ = serial.write_str("  at ");
            let _ = serial.write_str(location.file());
            let _ = serial.write_str("\n");
        }
        let _ = serial.write_str("System halted.\n");
    }
    #[cfg(target_arch = "riscv64")]
    {
        let mut serial = Ns16550::new(NS16550_BASE);
        let _ = serial.write_str("\n!!! KERNEL PANIC !!!\n");
        if let Some(location) = info.location() {
            let _ = serial.write_str("  at ");
            let _ = serial.write_str(location.file());
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
