// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 kernel initialization.
//!
//! Mirrors the structure of `crates/kernel/src/arch/x86_64/` for the
//! aarch64 target.  AArch64 has no GDT; exception vectors are installed
//! via VBAR_EL1 in the HAL boot stub (`crates/hal/src/arch/aarch64/boot.rs`).
//! This module provides the Rust-side init functions called from `kernel_main`.
//!
//! The `context`, `kthread`, and `sched_glue` submodules are functional
//! for **kernel-thread cooperative scheduling** (the [`switch_context`]
//! primitive plus a seeded-stack spawn path). The `clone`, `init_embed`,
//! and `syscall_entry` submodules remain aarch64 build stubs that mirror
//! the x86_64 public API so architecture-neutral kernel code type-checks;
//! the userspace/EL0 transition they need is not written yet.
//!
//! [`switch_context`]: context::switch_context

pub mod clone;
pub mod context;
pub mod init;
pub mod init_embed;
pub mod irq;
pub mod kthread;
pub mod sched_glue;
pub mod syscall_entry;

use oncrix_hal::arch::aarch64::gic::{GICD_BASE, GICR_BASE, Gicv3};
use oncrix_hal::arch::aarch64::pl011::{PL011_BASE, Pl011};
use oncrix_hal::arch::aarch64::timer::AArch64Timer;
use oncrix_hal::serial::SerialPort;
use oncrix_hal::timer::Timer;
use oncrix_lib::Result;

/// Kernel heap size (16 MiB).
const KERNEL_HEAP_SIZE: usize = 16 * 1024 * 1024;

/// Static heap storage (zeroed BSS).
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
    // SAFETY: Single-threaded boot context; KERNEL_HEAP is used only here.
    unsafe {
        let heap_start = (&raw mut KERNEL_HEAP) as *mut u8;
        ALLOCATOR.init(heap_start, KERNEL_HEAP_SIZE);
    }
    let mut serial = Pl011::new(PL011_BASE);
    let _ = serial.write_str("[ONCRIX/aarch64] Heap initialized (16 MiB)\n");
}

/// Initialize the GICv3 interrupt controller.
///
/// # Safety
///
/// Must be called once during single-threaded boot after the MMU is on.
pub unsafe fn init_gic() -> Result<()> {
    let gic = Gicv3::new(GICD_BASE, GICR_BASE);
    gic.init()?;
    let mut serial = Pl011::new(PL011_BASE);
    let _ = serial.write_str("[ONCRIX/aarch64] GICv3 initialized\n");
    Ok(())
}

/// Initialize the generic physical timer with a 10 ms tick period.
///
/// # Safety
///
/// Must be called after `init_gic`.
pub unsafe fn init_timer() -> Result<()> {
    let mut timer = AArch64Timer::new();
    // Set a one-shot tick at 10 ms intervals.  The interrupt handler
    // re-arms the timer each time it fires.
    let ticks_10ms = timer.nanos_to_ticks(10_000_000);
    timer.set_oneshot(ticks_10ms)?;
    let mut serial = Pl011::new(PL011_BASE);
    let _ = serial.write_str("[ONCRIX/aarch64] Generic timer armed (10 ms)\n");
    Ok(())
}
