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

/// Kernel heap size (16 MiB).
///
/// Sized to accommodate the full `KernelState` allocation: `Ramfs`
/// alone is ~512 KiB (128 × 4 KiB file buffers), and future subsystem
/// expansion (service manager, IPC channel backlogs, process table)
/// is expected to grow the working set further.
const KERNEL_HEAP_SIZE: usize = 16 * 1024 * 1024;

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

/// Ring 0 stack used when the CPU traps from ring 3 to ring 0.
///
/// Installed into `TSS.RSP0` by [`init_tss_rsp0`]. Without this any
/// interrupt or exception taken while at ring 3 would try to push the
/// iretq frame at RSP=0 and triple-fault.
static mut RING0_STACK: [u8; 32768] = [0; 32768];

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

/// Install [`RING0_STACK`] as the TSS ring-0 stack (`TSS.RSP0`).
///
/// Required before any ring 3 → ring 0 transition (interrupt, exception,
/// or IRETQ fallback from a non-canonical SYSRET). The SYSCALL fast path
/// uses its own dedicated kernel stack and is not affected.
///
/// # Safety
///
/// Must be called after [`init_gdt`] and before enabling interrupts or
/// transitioning to ring 3.
pub unsafe fn init_tss_rsp0() {
    let mut serial = Uart16550::new(COM1);

    // SAFETY: Single-threaded boot; TSS is not concurrently accessed.
    unsafe {
        let stack_base = &raw const RING0_STACK as *const u8;
        let stack_top = stack_base as u64 + 32768;
        let tss_ptr = &raw mut TSS;
        (*tss_ptr).privilege_stacks[0] = stack_top;
    }

    let _ = serial.write_str("[ONCRIX] TSS.RSP0 installed (ring 0 trap stack)\n");
}

/// Return the global bootstrap ring-0 stack top.
///
/// Used as a fallback when the currently running thread does not
/// own a private kernel stack (e.g. the idle thread still running
/// on boot storage). Consumers should prefer the per-thread stack
/// returned by the scheduler.
pub fn bootstrap_ring0_stack_top() -> u64 {
    // SAFETY: Reading the base address of a fixed-size static
    // array and adding its known size is a pure arithmetic
    // operation; no dereference happens.
    let base = &raw const RING0_STACK as *const u8 as u64;
    base + 32768
}

/// Update `TSS.RSP0` to `top_of_stack`.
///
/// Called on every context switch before returning to a user-mode
/// thread so that the next ring 3 → 0 trap (interrupt, exception,
/// or syscall IRETQ fallback) lands on the newly-scheduled thread's
/// private 16 KiB kernel stack.
///
/// Passing `0` is treated as "restore the global bootstrap stack",
/// which lets idle / early-boot threads share the static buffer.
///
/// # Safety
///
/// `top_of_stack` must either be `0` or the highest address (+1)
/// of a currently-live, writable, 16-byte aligned 16 KiB region
/// owned by the incoming thread. Installing a dangling pointer
/// will cause the *next* trap to triple-fault.
///
/// Must be called with interrupts disabled so the switch does not
/// race with an IRQ that would observe a half-updated TSS.
pub unsafe fn switch_tss_rsp0(top_of_stack: u64) {
    let resolved = if top_of_stack == 0 {
        bootstrap_ring0_stack_top()
    } else {
        top_of_stack
    };
    // SAFETY: Writing to a single aligned `u64` field of a
    // properly-aligned `Tss` via a raw pointer. The TSS is a
    // `static mut` whose exclusive access is guaranteed by the
    // "interrupts disabled" contract documented above; the CPU
    // only reads `RSP0` during a privilege transition, which
    // will not happen while interrupts are off.
    unsafe {
        let tss_ptr = &raw mut TSS;
        (*tss_ptr).privilege_stacks[0] = resolved;
    }
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

    let _ = serial.write_str("[ONCRIX] Kernel heap initialized (16 MiB)\n");
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
