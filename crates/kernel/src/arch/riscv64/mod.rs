// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit kernel initialization.
//!
//! Mirrors the structure of `crates/kernel/src/arch/x86_64/` for riscv64.
//! RISC-V uses supervisor-mode CSRs (stvec, sie, satp) instead of x86
//! GDT/IDT.  Exception/interrupt routing is via the trap vector installed
//! in boot.rs (HAL).

use oncrix_hal::arch::riscv64::ns16550::{NS16550_BASE, Ns16550};
use oncrix_hal::arch::riscv64::plic::{PLIC_BASE, Plic};
use oncrix_hal::arch::riscv64::timer::RiscvTimer;
use oncrix_hal::serial::SerialPort;
use oncrix_hal::timer::Timer;
use oncrix_lib::Result;

/// Kernel heap size (16 MiB).
const KERNEL_HEAP_SIZE: usize = 16 * 1024 * 1024;

/// Static heap storage (BSS).
static mut KERNEL_HEAP: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

/// Global allocator.
#[global_allocator]
static ALLOCATOR: oncrix_mm::heap::LinkedListAllocator =
    oncrix_mm::heap::LinkedListAllocator::empty();

/// Initialize the kernel heap allocator.
///
/// # Safety
///
/// Must be called exactly once during single-threaded boot.
pub unsafe fn init_heap() {
    // SAFETY: Single-threaded boot; KERNEL_HEAP accessed only here.
    unsafe {
        let heap_start = (&raw mut KERNEL_HEAP) as *mut u8;
        ALLOCATOR.init(heap_start, KERNEL_HEAP_SIZE);
    }
    let mut serial = Ns16550::new(NS16550_BASE);
    let _ = serial.write_str("[ONCRIX/riscv64] Heap initialized (16 MiB)\n");
}

/// Initialize the PLIC interrupt controller.
///
/// # Safety
///
/// Must be called once during single-threaded boot.
pub unsafe fn init_plic() -> Result<()> {
    let plic = Plic::new(PLIC_BASE);
    plic.init()?;
    let mut serial = Ns16550::new(NS16550_BASE);
    let _ = serial.write_str("[ONCRIX/riscv64] PLIC initialized\n");
    Ok(())
}

/// Initialize the CLINT/SBI timer with a 10 ms tick.
///
/// # Safety
///
/// Must be called after PLIC init.
pub unsafe fn init_timer() -> Result<()> {
    let mut timer = RiscvTimer::new();
    let ticks_10ms = timer.nanos_to_ticks(10_000_000);
    timer.set_oneshot(ticks_10ms)?;
    let mut serial = Ns16550::new(NS16550_BASE);
    let _ = serial.write_str("[ONCRIX/riscv64] Timer armed (10 ms via SBI)\n");
    Ok(())
}
