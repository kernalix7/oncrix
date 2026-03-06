// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 early initialization: GDT, IDT, heap.

use core::mem::size_of;

use oncrix_hal::arch::x86_64::gdt::{self, GdtEntry, GdtPointer, Tss, selector};
use oncrix_hal::arch::x86_64::idt::{self, GateType, Idt, IdtPointer, exception};
use oncrix_hal::arch::x86_64::pic::{PIC_MASTER_OFFSET, Pic8259};
use oncrix_hal::arch::x86_64::pit::Pit;
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::interrupt::{InterruptController, InterruptVector};
use oncrix_hal::serial::SerialPort;
use oncrix_hal::timer::Timer;
use oncrix_mm::heap::LinkedListAllocator;
use oncrix_process::pid::{Pid, alloc_tid};
use oncrix_process::scheduler::RoundRobinScheduler;
use oncrix_process::thread::{Priority, Thread};

use super::{exceptions, interrupts};

/// Kernel heap size (256 KiB).
const KERNEL_HEAP_SIZE: usize = 256 * 1024;

/// Static storage for the kernel heap (BSS, does not bloat the image).
static mut KERNEL_HEAP: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

/// Global allocator for the kernel.
#[global_allocator]
static ALLOCATOR: LinkedListAllocator = LinkedListAllocator::empty();

// ── GDT ─────────────────────────────────────────────────────────

/// Static GDT: null + kernel code/data + user data/code + TSS (2 slots).
static mut GDT: [u64; 7] = [0; 7];

/// Static TSS.
static mut TSS: Tss = Tss::new();

/// Double-fault IST stack (16 KiB).
static mut DOUBLE_FAULT_STACK: [u8; 16384] = [0; 16384];

/// Initialize the GDT with kernel/user segments and a TSS.
///
/// # Safety
///
/// Must be called exactly once during early boot, before enabling
/// interrupts. No other code may access the static GDT/TSS concurrently.
pub unsafe fn init_gdt() {
    let mut serial = Uart16550::new(COM1);

    // SAFETY: Single-threaded boot context. We use raw pointers to
    // avoid creating references to `static mut` (Rust 2024 rules).
    unsafe {
        let stack_base = &raw const DOUBLE_FAULT_STACK as *const u8;
        let stack_top = stack_base as u64 + 16384;
        let tss_ptr = &raw mut TSS;
        (*tss_ptr).ist[0] = stack_top;

        let gdt_ptr = &raw mut GDT;
        (*gdt_ptr)[0] = GdtEntry::NULL.as_u64();
        (*gdt_ptr)[1] = GdtEntry::KERNEL_CODE.as_u64();
        (*gdt_ptr)[2] = GdtEntry::KERNEL_DATA.as_u64();
        (*gdt_ptr)[3] = GdtEntry::USER_DATA.as_u64();
        (*gdt_ptr)[4] = GdtEntry::USER_CODE.as_u64();

        let tss_desc = gdt::tss_descriptor(&*tss_ptr);
        (*gdt_ptr)[5] = tss_desc[0];
        (*gdt_ptr)[6] = tss_desc[1];

        let descriptor = GdtPointer {
            limit: (7 * size_of::<u64>() - 1) as u16,
            base: gdt_ptr as u64,
        };

        gdt::load_gdt(&descriptor);
        gdt::reload_segments(selector::KERNEL_CODE, selector::KERNEL_DATA);
        gdt::load_tss(selector::TSS);
    }

    let _ = serial.write_str("[ONCRIX] GDT initialized\n");
}

// ── IDT ─────────────────────────────────────────────────────────

/// Static IDT.
static mut IDT: Idt = Idt::new();

/// Helper: cast a function pointer to u64 via `*const ()`.
macro_rules! handler_addr {
    ($fn:expr) => {
        $fn as *const () as u64
    };
}

/// Initialize the IDT with exception handlers.
///
/// # Safety
///
/// Must be called after `init_gdt` and before enabling interrupts.
pub unsafe fn init_idt() {
    let mut serial = Uart16550::new(COM1);

    // SAFETY: Single-threaded boot context. Raw pointer to avoid
    // reference to `static mut`.
    unsafe {
        let idt_ptr = &raw mut IDT;

        (*idt_ptr).set_handler(
            exception::DIVIDE_ERROR,
            handler_addr!(exceptions::divide_error_handler),
            selector::KERNEL_CODE,
            GateType::Trap,
        );

        (*idt_ptr).set_handler(
            exception::INVALID_OPCODE,
            handler_addr!(exceptions::invalid_opcode_handler),
            selector::KERNEL_CODE,
            GateType::Trap,
        );

        (*idt_ptr).set_handler_ist(
            exception::DOUBLE_FAULT,
            handler_addr!(exceptions::double_fault_handler),
            selector::KERNEL_CODE,
            GateType::Trap,
            1,
        );

        (*idt_ptr).set_handler(
            exception::GENERAL_PROTECTION,
            handler_addr!(exceptions::general_protection_handler),
            selector::KERNEL_CODE,
            GateType::Trap,
        );

        (*idt_ptr).set_handler(
            exception::PAGE_FAULT,
            handler_addr!(exceptions::page_fault_handler),
            selector::KERNEL_CODE,
            GateType::Trap,
        );

        let descriptor = IdtPointer {
            limit: (size_of::<Idt>() - 1) as u16,
            base: idt_ptr as u64,
        };
        idt::load_idt(&descriptor);
    }

    let _ = serial.write_str("[ONCRIX] IDT initialized (5 exception handlers)\n");
}

// ── PIC + PIT ───────────────────────────────────────────────────

/// Static PIC instance.
pub static mut PIC: Pic8259 = Pic8259::new();

/// Static PIT timer instance.
pub static mut PIT_TIMER: Pit = Pit::new();

/// Initialize the 8259 PIC, install IRQ handlers, and start the PIT.
///
/// # Safety
///
/// Must be called after `init_idt` and before enabling interrupts.
pub unsafe fn init_pic_and_timer() {
    let mut serial = Uart16550::new(COM1);

    // SAFETY: Single-threaded boot context. Raw pointers to static mut.
    unsafe {
        // Initialize PIC (remap IRQs to vectors 32-47).
        let pic_ptr = &raw mut PIC;
        (*pic_ptr).init();

        // Install IRQ handlers in the IDT.
        let idt_ptr = &raw mut IDT;

        // IRQ 0 — Timer (vector 32).
        (*idt_ptr).set_handler(
            PIC_MASTER_OFFSET,
            handler_addr!(interrupts::timer_handler),
            selector::KERNEL_CODE,
            GateType::Interrupt,
        );

        // IRQ 1 — Keyboard (vector 33).
        (*idt_ptr).set_handler(
            PIC_MASTER_OFFSET + 1,
            handler_addr!(interrupts::keyboard_handler),
            selector::KERNEL_CODE,
            GateType::Interrupt,
        );

        // IRQ 7 — Spurious (vector 39).
        (*idt_ptr).set_handler(
            PIC_MASTER_OFFSET + 7,
            handler_addr!(interrupts::spurious_handler),
            selector::KERNEL_CODE,
            GateType::Interrupt,
        );

        // Reload IDT with new entries.
        let descriptor = IdtPointer {
            limit: (size_of::<Idt>() - 1) as u16,
            base: idt_ptr as u64,
        };
        idt::load_idt(&descriptor);

        // Enable IRQ 0 (timer).
        let _ = (*pic_ptr).enable(InterruptVector(PIC_MASTER_OFFSET));

        // Configure PIT: ~100 Hz (divisor = 1193182 / 100 ≈ 11932).
        let pit_ptr = &raw mut PIT_TIMER;
        let _ = (*pit_ptr).set_periodic(11932);

        // Enable CPU interrupts.
        (*pic_ptr).enable_all();
    }

    let _ = serial.write_str("[ONCRIX] PIC initialized, PIT running at ~100 Hz\n");
}

// ── Heap ────────────────────────────────────────────────────────

/// Initialize the kernel heap allocator.
///
/// # Safety
///
/// Must be called exactly once before any heap allocation.
pub unsafe fn init_heap() {
    let mut serial = Uart16550::new(COM1);

    // SAFETY: Raw pointer to `static mut` KERNEL_HEAP. Called once
    // during single-threaded boot.
    unsafe {
        let heap_ptr = &raw mut KERNEL_HEAP as *mut u8;
        ALLOCATOR.init(heap_ptr, KERNEL_HEAP_SIZE);
    }

    let _ = serial.write_str("[ONCRIX] Kernel heap initialized (256 KiB)\n");
}

// ── Scheduler ───────────────────────────────────────────────────

/// Global round-robin scheduler.
pub static mut SCHEDULER: RoundRobinScheduler = RoundRobinScheduler::new();

/// Initialize the scheduler with an idle thread.
///
/// The idle thread runs at the lowest priority and simply halts the
/// CPU until the next interrupt.
///
/// # Safety
///
/// Must be called after `init_heap` and before `init_pic_and_timer`.
pub unsafe fn init_scheduler() {
    let mut serial = Uart16550::new(COM1);

    // SAFETY: Single-threaded boot context.
    unsafe {
        let sched_ptr = &raw mut SCHEDULER;

        // Create idle thread (TID 0 equivalent, kernel PID, lowest priority).
        let idle_tid = alloc_tid();
        let idle_thread = Thread::new(idle_tid, Pid::KERNEL, Priority::IDLE);
        let _ = (*sched_ptr).add(idle_thread);
    }

    let _ = serial.write_str("[ONCRIX] Scheduler initialized (idle thread ready)\n");
}
