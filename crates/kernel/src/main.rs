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

/// Calls the scheduler once from the naked cooperative SIMD verifier.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
extern "C" fn aarch64_cooperative_simd_yield() {
    // SAFETY: the verifier is called with DAIF masked and holds no scheduler
    // borrow. Its naked frame keeps the caller's ABI state valid.
    unsafe {
        let _ = oncrix_kernel::current::yield_now();
    }
}

/// Seeds and verifies `d8-d15` across a real cooperative switch round trip.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn verify_cooperative_simd_state() -> u64 {
    core::arch::naked_asm!(
        // Preserve the caller's ABI state and link register around the test.
        "sub sp, sp, #80",
        "stp x29, x30, [sp, #0]",
        "stp d8, d9, [sp, #16]",
        "stp d10, d11, [sp, #32]",
        "stp d12, d13, [sp, #48]",
        "stp d14, d15, [sp, #64]",
        // Give each callee-saved SIMD register a distinct 64-bit pattern.
        "movz x9, #0x7700",
        "movk x9, #0x5566, lsl #16",
        "movk x9, #0x3344, lsl #32",
        "movk x9, #0x1122, lsl #48",
        "fmov d8, x9",
        "add x9, x9, #1",
        "fmov d9, x9",
        "add x9, x9, #1",
        "fmov d10, x9",
        "add x9, x9, #1",
        "fmov d11, x9",
        "add x9, x9, #1",
        "fmov d12, x9",
        "add x9, x9, #1",
        "fmov d13, x9",
        "add x9, x9, #1",
        "fmov d14, x9",
        "add x9, x9, #1",
        "fmov d15, x9",
        "bl aarch64_cooperative_simd_yield",
        // Recreate and compare the expected sequence after switching back.
        "movz x9, #0x7700",
        "movk x9, #0x5566, lsl #16",
        "movk x9, #0x3344, lsl #32",
        "movk x9, #0x1122, lsl #48",
        "fmov x10, d8",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d9",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d10",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d11",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d12",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d13",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d14",
        "cmp x9, x10",
        "b.ne 1f",
        "add x9, x9, #1",
        "fmov x10, d15",
        "cmp x9, x10",
        "b.ne 1f",
        "mov x0, #1",
        "b 2f",
        "1:",
        "mov x0, xzr",
        "2:",
        "ldp d14, d15, [sp, #64]",
        "ldp d12, d13, [sp, #48]",
        "ldp d10, d11, [sp, #32]",
        "ldp d8, d9, [sp, #16]",
        "ldp x29, x30, [sp, #0]",
        "add sp, sp, #80",
        "ret",
    );
}

/// Reports an AArch64 runtime-proof failure and parks at EL1.
#[cfg(target_arch = "aarch64")]
fn aarch64_bringup_fail(serial: &mut Pl011, marker: &str) -> ! {
    let _ = serial.write_str(marker);
    // SAFETY: a local fail-stop intentionally prevents further bring-up after
    // a preservation invariant has failed.
    unsafe {
        core::arch::asm!("b .", options(noreturn, nostack));
    }
}

/// AArch64 cooperative-scheduler bring-up demo: kernel thread A.
///
/// Prints a marker proving it executed, then cooperatively yields back
/// to the scheduler. Never returns — parks in `wfi` if it is ever
/// resumed a second time.
#[cfg(target_arch = "aarch64")]
extern "C" fn demo_thread_a() -> ! {
    use core::sync::atomic::Ordering;

    let mut serial = Pl011::new(PL011_BASE);
    let _ = serial.write_str("[ONCRIX/aarch64] cooperative scheduler: thread A ran\n");
    // Make a missing d8-d15 switch frame observable to the boot-thread probe.
    // SAFETY: these are AAPCS64 callee-saved registers; this non-returning
    // thread deliberately gives each one a distinct low-64-bit pattern.
    unsafe {
        core::arch::asm!(
            "movi v8.8b, #0xa8",
            "movi v9.8b, #0xa9",
            "movi v10.8b, #0xaa",
            "movi v11.8b, #0xab",
            "movi v12.8b, #0xac",
            "movi v13.8b, #0xad",
            "movi v14.8b, #0xae",
            "movi v15.8b, #0xaf",
            lateout("v8") _,
            lateout("v9") _,
            lateout("v10") _,
            lateout("v11") _,
            lateout("v12") _,
            lateout("v13") _,
            lateout("v14") _,
            lateout("v15") _,
            options(nomem, nostack),
        );
    }
    COOPERATIVE_A_RAN.store(true, Ordering::Release);
    // Hand control back exactly once (interrupts still masked here), then
    // park. It must NOT call yield_now again: once the preemptive phase
    // unmasks IRQs, sched_yield_once's interrupts-off contract would be
    // violated. `wfi` with IRQs on simply waits for the next tick.
    // SAFETY: interrupts are masked during the cooperative hand-off and no
    // scheduler borrow is held across the yield.
    unsafe {
        let _ = oncrix_kernel::current::yield_now();
    }
    // When the preemptive phase later re-elects this thread, it resumes here
    // from inside a timer-IRQ context, so it inherits DAIF.I = 1 (masked).
    // Unmask so the CPU can take the next tick and preempt us again; without
    // this the wfi below would wait for an interrupt that can never arrive.
    // SAFETY: kernel thread at EL1; clearing DAIF.I only enables IRQ delivery.
    unsafe {
        core::arch::asm!("msr daifclr, #0b0010", options(nostack));
    }
    loop {
        // SAFETY: `wfi` parks the CPU until an interrupt; harmless at EL1.
        unsafe {
            core::arch::asm!("wfi", options(nostack));
        }
    }
}

/// AArch64 cooperative-scheduler bring-up demo: kernel thread B.
///
/// Counterpart to [`demo_thread_a`]; prints its own marker then yields.
#[cfg(target_arch = "aarch64")]
extern "C" fn demo_thread_b() -> ! {
    use core::sync::atomic::Ordering;

    let mut serial = Pl011::new(PL011_BASE);
    let _ = serial.write_str("[ONCRIX/aarch64] cooperative scheduler: thread B ran\n");
    // Use a second distinct register set so the boot state cannot survive by
    // accident when the low-level switch omits callee-saved SIMD state.
    // SAFETY: see `demo_thread_a`; this thread never returns to an ABI caller.
    unsafe {
        core::arch::asm!(
            "movi v8.8b, #0xb8",
            "movi v9.8b, #0xb9",
            "movi v10.8b, #0xba",
            "movi v11.8b, #0xbb",
            "movi v12.8b, #0xbc",
            "movi v13.8b, #0xbd",
            "movi v14.8b, #0xbe",
            "movi v15.8b, #0xbf",
            lateout("v8") _,
            lateout("v9") _,
            lateout("v10") _,
            lateout("v11") _,
            lateout("v12") _,
            lateout("v13") _,
            lateout("v14") _,
            lateout("v15") _,
            options(nomem, nostack),
        );
    }
    COOPERATIVE_B_RAN.store(true, Ordering::Release);
    // SAFETY: see `demo_thread_a` — single cooperative hand-off, then park.
    unsafe {
        let _ = oncrix_kernel::current::yield_now();
    }
    // SAFETY: see `demo_thread_a` — unmask IRQs so preemption can resume.
    unsafe {
        core::arch::asm!("msr daifclr, #0b0010", options(nostack));
    }
    loop {
        // SAFETY: `wfi` parks the CPU until an interrupt; harmless at EL1.
        unsafe {
            core::arch::asm!("wfi", options(nostack));
        }
    }
}

/// Whether each cooperative thread reached its deliberate SIMD overwrite.
#[cfg(target_arch = "aarch64")]
static COOPERATIVE_A_RAN: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(target_arch = "aarch64")]
static COOPERATIVE_B_RAN: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Number of times each preemptive busy thread has announced itself.
///
/// Written by [`demo_preempt_c`]/[`demo_preempt_d`] and polled by the boot
/// thread. Because those threads NEVER yield, any progress by both of them
/// proves the generic timer preempted one to run the other.
#[cfg(target_arch = "aarch64")]
static PREEMPT_C_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(target_arch = "aarch64")]
static PREEMPT_D_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Busy-spin duration between announcements (arbitrary, tuned so a 10 ms
/// timer tick lands mid-spin and forces a preemptive switch, while still
/// letting the boot thread be re-elected to report success promptly).
#[cfg(target_arch = "aarch64")]
const PREEMPT_SPIN: u32 = 4_000_000;

/// AArch64 preemptive-scheduling demo: busy thread C.
///
/// Unlike the cooperative demo threads, this NEVER yields — it only
/// busy-spins and prints. The only way control leaves it is a timer IRQ
/// preempting it (via `aarch64_handle_irq` → `sched_yield_once`). It runs
/// with IRQs unmasked (inherited from the preempting switch), announces
/// itself a bounded number of times, then parks in `wfi`.
#[cfg(target_arch = "aarch64")]
extern "C" fn demo_preempt_c() -> ! {
    use core::sync::atomic::Ordering;
    // This thread is first entered from a timer-IRQ context (DAIF.I = 1).
    // Unmask so the timer can preempt us mid-spin — the whole point of the
    // demo. SAFETY: kernel thread at EL1; only enables IRQ delivery.
    unsafe {
        core::arch::asm!("msr daifclr, #0b0010", options(nostack));
    }
    let mut serial = Pl011::new(PL011_BASE);
    while PREEMPT_C_HITS.load(Ordering::Relaxed) < 3 {
        // Busy work — deliberately no yield. A timer tick will preempt us.
        for _ in 0..PREEMPT_SPIN {
            core::hint::spin_loop();
        }
        PREEMPT_C_HITS.fetch_add(1, Ordering::Relaxed);
        let _ = serial.write_str("[ONCRIX/aarch64] preemptive: thread C scheduled\n");
    }
    loop {
        // SAFETY: `wfi` parks until an interrupt; harmless at EL1.
        unsafe {
            core::arch::asm!("wfi", options(nostack));
        }
    }
}

/// AArch64 preemptive-scheduling demo: busy thread D. See [`demo_preempt_c`].
#[cfg(target_arch = "aarch64")]
extern "C" fn demo_preempt_d() -> ! {
    use core::sync::atomic::Ordering;
    // SAFETY: see `demo_preempt_c` — unmask IRQs so the timer can preempt us.
    unsafe {
        core::arch::asm!("msr daifclr, #0b0010", options(nostack));
    }
    let mut serial = Pl011::new(PL011_BASE);
    while PREEMPT_D_HITS.load(Ordering::Relaxed) < 3 {
        for _ in 0..PREEMPT_SPIN {
            core::hint::spin_loop();
        }
        PREEMPT_D_HITS.fetch_add(1, Ordering::Relaxed);
        let _ = serial.write_str("[ONCRIX/aarch64] preemptive: thread D scheduled\n");
    }
    loop {
        // SAFETY: `wfi` parks until an interrupt; harmless at EL1.
        unsafe {
            core::arch::asm!("wfi", options(nostack));
        }
    }
}

/// RISC-V cooperative-scheduler bring-up demo: kernel thread A.
///
/// Prints a marker proving it executed, then cooperatively yields back
/// to the scheduler. Never returns — parks in `wfi` if it is ever
/// resumed a second time.
#[cfg(target_arch = "riscv64")]
extern "C" fn demo_thread_a() -> ! {
    let mut serial = Ns16550::new(NS16550_BASE);
    let _ = serial.write_str("[ONCRIX/riscv64] cooperative scheduler: thread A ran\n");
    // Hand control back exactly once (interrupts still masked here), then
    // park. It must NOT call yield_now again: once the preemptive phase
    // enables SIE, sched_yield_once's interrupts-off contract would be
    // violated. `wfi` with SIE set simply waits for the next tick.
    // SAFETY: interrupts are masked during the cooperative hand-off and no
    // scheduler borrow is held across the yield.
    unsafe {
        let _ = oncrix_kernel::current::yield_now();
    }
    // When the preemptive phase later re-elects this thread, it resumes here
    // from inside a timer-trap context, so it inherits sstatus.SIE = 0
    // (masked). Set SIE so the CPU can take the next tick and preempt us
    // again; without this the wfi below would wait for an interrupt that can
    // never arrive.
    // SAFETY: kernel thread in S-mode; setting sstatus.SIE only enables IRQ
    // delivery. No nomem: the SIE set is cli/sti-class and must act as a
    // compiler barrier.
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2", options(nostack));
    }
    loop {
        // SAFETY: `wfi` parks the CPU until an interrupt; harmless in S-mode.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}

/// RISC-V cooperative-scheduler bring-up demo: kernel thread B.
///
/// Counterpart to [`demo_thread_a`]; prints its own marker then yields.
#[cfg(target_arch = "riscv64")]
extern "C" fn demo_thread_b() -> ! {
    let mut serial = Ns16550::new(NS16550_BASE);
    let _ = serial.write_str("[ONCRIX/riscv64] cooperative scheduler: thread B ran\n");
    // SAFETY: see `demo_thread_a` — single cooperative hand-off, then park.
    unsafe {
        let _ = oncrix_kernel::current::yield_now();
    }
    // SAFETY: see `demo_thread_a` — set SIE so preemption can resume us.
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2", options(nostack));
    }
    loop {
        // SAFETY: `wfi` parks the CPU until an interrupt; harmless in S-mode.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}

/// Number of times each preemptive busy thread has announced itself.
///
/// Written by [`demo_preempt_c`]/[`demo_preempt_d`] and polled by the boot
/// thread. Because those threads NEVER yield, any progress by both of them
/// proves the SBI timer preempted one to run the other.
#[cfg(target_arch = "riscv64")]
static PREEMPT_C_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(target_arch = "riscv64")]
static PREEMPT_D_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Busy-spin duration between announcements (arbitrary, tuned so a 10 ms
/// timer tick lands mid-spin and forces a preemptive switch, while still
/// letting the boot thread be re-elected to report success promptly).
#[cfg(target_arch = "riscv64")]
const PREEMPT_SPIN: u32 = 4_000_000;

/// RISC-V preemptive-scheduling demo: busy thread C.
///
/// Unlike the cooperative demo threads, this NEVER yields — it only
/// busy-spins and prints. The only way control leaves it is a timer
/// interrupt preempting it (via `riscv_handle_trap` → `sched_yield_once`).
/// It runs with SIE set (enabled on entry), announces itself a bounded
/// number of times, then parks in `wfi`.
#[cfg(target_arch = "riscv64")]
extern "C" fn demo_preempt_c() -> ! {
    use core::sync::atomic::Ordering;
    // This thread is first entered from a timer-trap context (sstatus.SIE=0).
    // Set SIE so the timer can preempt us mid-spin — the whole point of the
    // demo. SAFETY: kernel thread in S-mode; setting sstatus.SIE only enables
    // IRQ delivery. No nomem: the SIE set is cli/sti-class and must act as a
    // compiler barrier.
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2", options(nostack));
    }
    let mut serial = Ns16550::new(NS16550_BASE);
    while PREEMPT_C_HITS.load(Ordering::Relaxed) < 3 {
        // Busy work — deliberately no yield. A timer tick will preempt us.
        for _ in 0..PREEMPT_SPIN {
            core::hint::spin_loop();
        }
        PREEMPT_C_HITS.fetch_add(1, Ordering::Relaxed);
        let _ = serial.write_str("[ONCRIX/riscv64] preemptive: thread C scheduled\n");
    }
    loop {
        // SAFETY: `wfi` parks until an interrupt; harmless in S-mode.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}

/// RISC-V preemptive-scheduling demo: busy thread D. See [`demo_preempt_c`].
#[cfg(target_arch = "riscv64")]
extern "C" fn demo_preempt_d() -> ! {
    use core::sync::atomic::Ordering;
    // SAFETY: see `demo_preempt_c` — set SIE so the timer can preempt us.
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2", options(nostack));
    }
    let mut serial = Ns16550::new(NS16550_BASE);
    while PREEMPT_D_HITS.load(Ordering::Relaxed) < 3 {
        for _ in 0..PREEMPT_SPIN {
            core::hint::spin_loop();
        }
        PREEMPT_D_HITS.fetch_add(1, Ordering::Relaxed);
        let _ = serial.write_str("[ONCRIX/riscv64] preemptive: thread D scheduled\n");
    }
    loop {
        // SAFETY: `wfi` parks until an interrupt; harmless in S-mode.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}

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
                let _ = serial.write_str("[ONCRIX] Created /dev /proc /tmp /sbin /etc\n");
                let _ = serial.write_str("[ONCRIX] Created /etc/motd\n");
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

        // Phase 11/13: Ring 0 → Ring 3 transition.
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

        // Phase 13: bring up the global frame allocator BEFORE we build
        // the init process's UserAddressSpace.
        //
        // SAFETY: Single-threaded boot; FRAME_ALLOC is not yet aliased.
        unsafe {
            oncrix_kernel::frame_alloc::init();
        }

        // Phase 13: build a per-process UserAddressSpace for `init` and
        // load the embedded ELF into its private 2 MiB region.
        //
        // SAFETY: Single-threaded boot. GDT, IDT, and SYSCALL MSRs have been
        // fully initialized in phases 2–6. The frame allocator was just
        // initialised above, and no other code can race against
        // FRAME_ALLOC or the boot page tables.
        let entry = unsafe {
            let init_elf = oncrix_kernel::arch::x86_64::init_embed::embedded_init_elf();
            init_elf.and_then(|elf_bytes| {
                let alloc = oncrix_kernel::frame_alloc::frame_alloc();
                let mut uas = oncrix_mm::address_space::UserAddressSpace::new_empty(
                    alloc,
                    oncrix_kernel::frame_alloc::phys_to_virt,
                )
                .ok()?;
                let entry = uas.map_elf_segments(elf_bytes).ok()?;

                // Patch PD_0_1G[2] to point at the init UAS's PT and
                // flush the TLB so the previous huge-page mapping is
                // dropped.
                oncrix_kernel::arch::x86_64::init::install_user_pt(uas.user_pt_phys().as_u64());

                // Stash the address space on the current (init) thread so
                // every future context switch can route through it.
                if let Some(thread) = oncrix_kernel::current::current_thread_mut() {
                    thread.user_address_space = Some(uas);
                }

                Some(entry)
            })
        };

        // Install standard I/O file descriptors (0=stdin, 1=stdout, 2=stderr)
        // on the init thread's per-thread fd table. Each forked child inherits
        // a deep copy; dup2 in the child affects only the child's own table.
        //
        // SAFETY: single-threaded boot; the init thread is current at this point.
        unsafe {
            oncrix_kernel::fd_table::install_stdio();
        }

        // If the embedded init loaded successfully, launch it with a
        // user-mapped RSP inside its own VMA. Otherwise fall back to the
        // in-kernel smoke-test stub (works only because it never touches
        // the fallback user stack before issuing `syscall`).
        unsafe {
            let (entry_ptr, user_rsp) = match entry {
                Some(e) => (e, oncrix_kernel::arch::x86_64::init::USER_INIT_RSP),
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

        // ─── Cooperative kernel-thread scheduling bring-up demo ───
        //
        // Proves the aarch64 `switch_context` (#139) actually schedules
        // real kernel threads at runtime. Sequence:
        //   1. Mask DAIF — `switch_context`/`sched_yield_once` require
        //      interrupts masked, and a cooperative hand-off must not be
        //      preempted by the generic timer.
        //   2. Register the running boot context as a schedulable thread
        //      and promote it to Running, so `prepare_switch` has a slot
        //      to save the outgoing state into.
        //   3. Spawn two kernel threads. `spawn_kthread` seeds each
        //      stack's 96-byte switch frame (x30 = entry) plus a parallel
        //      `CpuContext`; copy that context into the scheduler-owned
        //      `Thread` before registering it.
        //   4. Yield. Control flows boot → A → B → boot (round-robin), so
        //      both thread bodies print before preemption and EL0 smoke run.
        {
            use oncrix_kernel::arch::aarch64::kthread::{kthread_context, spawn_kthread};
            use oncrix_kernel::arch::init::SCHEDULER;
            use oncrix_kernel::current::spawn_thread;
            use oncrix_process::pid::{Pid, alloc_tid};
            use oncrix_process::thread::{Priority, Thread};

            // Step 1: mask all interrupts for the whole sequence.
            // SAFETY: ring-0 (EL1) boot context; masking interrupts is the
            // documented precondition of the switch/yield primitives.
            unsafe {
                core::arch::asm!("msr daifset, #0b1111", options(nostack));
            }

            let _ =
                serial.write_str("[ONCRIX/aarch64] cooperative scheduler: bring-up demo start\n");

            // Step 2: register + promote the boot thread.
            // SAFETY: single-threaded boot; SCHEDULER is not aliased here,
            // and each access below is a distinct, non-overlapping borrow.
            unsafe {
                let boot = Thread::new(alloc_tid(), Pid::KERNEL, Priority::NORMAL);
                let _ = spawn_thread(boot);
                let sched = &raw mut SCHEDULER;
                let _ = (*sched).schedule();
            }

            // Step 3: spawn the two demo kernel threads and copy each
            // seeded context into the scheduler-owned `Thread`.
            // SAFETY: entry fns are valid `extern "C" fn() -> !`; single
            // CPU with interrupts masked keeps the pool + scheduler
            // exclusive to this code.
            unsafe {
                if let Ok((kt, mut thread)) = spawn_kthread(demo_thread_a, Priority::NORMAL) {
                    thread.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(thread);
                }
                if let Ok((kt, mut thread)) = spawn_kthread(demo_thread_b, Priority::NORMAL) {
                    thread.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(thread);
                }
            }

            // Step 4: seed d8-d15 and hand the CPU to both demo threads. Each
            // thread overwrites d8-d15 before yielding, so only a real saved
            // boot-thread switch frame can restore the seeded values.
            // SAFETY: interrupts are masked and no scheduler borrow is held.
            let simd_preserved = unsafe { verify_cooperative_simd_state() != 0 };
            if !simd_preserved
                || !COOPERATIVE_A_RAN.load(core::sync::atomic::Ordering::Acquire)
                || !COOPERATIVE_B_RAN.load(core::sync::atomic::Ordering::Acquire)
            {
                aarch64_bringup_fail(
                    &mut serial,
                    "[ONCRIX/aarch64] callee-saved SIMD state preservation FAILED\n",
                );
            }

            let _ = serial.write_str(
                "[ONCRIX/aarch64] callee-saved SIMD state preserved across context switch\n",
            );

            let _ = serial.write_str(
                "[ONCRIX/aarch64] cooperative scheduler: thread A/B ran, back on boot thread\n",
            );
        }

        // Preemptive scheduling demo: spawn two BUSY kernel threads that
        // never yield, then re-arm the timer and unmask IRQs. Because C and
        // D only busy-spin, the sole way both make progress is the generic
        // timer preempting one to run the other (aarch64_handle_irq →
        // sched_yield_once). The boot thread polls their atomic counters and
        // reports success once both have printed — proving preemption, not
        // just that interrupts arrive.
        {
            use core::sync::atomic::Ordering;
            use oncrix_hal::arch::aarch64::timer::AArch64Timer;
            use oncrix_hal::timer::Timer;
            use oncrix_kernel::arch::aarch64::kthread::{kthread_context, spawn_kthread};
            use oncrix_kernel::current::spawn_thread;
            use oncrix_process::thread::Priority;

            // Spawn C and D while interrupts are still masked.
            // SAFETY: single CPU, interrupts masked → pool + scheduler are
            // exclusive to this code; entry fns are valid extern "C" fn()->!.
            unsafe {
                if let Ok((kt, mut t)) = spawn_kthread(demo_preempt_c, Priority::NORMAL) {
                    t.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(t);
                }
                if let Ok((kt, mut t)) = spawn_kthread(demo_preempt_d, Priority::NORMAL) {
                    t.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(t);
                }
            }

            // Re-arm the timer and unmask IRQs. From here the generic timer
            // rotates among the runnable threads.
            // SAFETY: GICv3 CPU interface + timer PPI were initialized above;
            // arming the timer and clearing DAIF.I are the documented steps
            // to enable interrupt delivery.
            unsafe {
                let mut timer = AArch64Timer::new();
                let ticks = timer.nanos_to_ticks(10_000_000);
                let _ = timer.set_oneshot(ticks);
                core::arch::asm!("msr daifclr, #0b0010", options(nostack)); // unmask IRQ (I)
            }
            let _ = serial.write_str(
                "[ONCRIX/aarch64] IRQs unmasked; preemptive scheduler armed (threads C, D).\n",
            );

            // Poll until both busy threads have run under preemption. Each
            // timer tick that fires while the boot thread is current will
            // preempt it into C or D; this loop re-checks after each wakeup.
            while PREEMPT_C_HITS.load(Ordering::Relaxed) < 3
                || PREEMPT_D_HITS.load(Ordering::Relaxed) < 3
            {
                // SAFETY: `wfi` parks until the next timer IRQ; harmless.
                unsafe {
                    core::arch::asm!("wfi", options(nostack));
                }
            }
            let _ = serial.write_str(
                "[ONCRIX/aarch64] preemptive: C and D both ran — timer preemption verified.\n",
            );
        }

        // Deliberately overwrite representative kernel SIMD/FP state in one
        // timer handler and prove the IRQ exception frame restores it.
        {
            use oncrix_hal::arch::aarch64::timer::AArch64Timer;
            use oncrix_hal::timer::Timer;
            use oncrix_kernel::arch::aarch64::irq::{
                arm_simd_fp_clobber_on_next_timer_irq, simd_fp_clobber_was_consumed,
            };

            // Stop timer IRQ delivery while arming the one-shot probe. No
            // `nomem`: changing DAIF.I is a compiler barrier around shared
            // armed/consumed state and the WFI exception round trip below.
            // SAFETY: EL1 boot context; only masks IRQ delivery on this CPU.
            unsafe {
                core::arch::asm!("msr daifset, #0b0010", options(nostack));
            }

            let mut timer = AArch64Timer::new();
            let ticks = timer.nanos_to_ticks(10_000_000);
            let _ = timer.set_oneshot(ticks);
            arm_simd_fp_clobber_on_next_timer_irq();

            let simd_fp_preserved: u64;
            // Seed and validate within one asm block so the compiler cannot
            // reuse the probe registers around IRQ unmask/WFI. Deliberately
            // omit `nomem`: IRQ delivery and its atomic consumed marker are
            // observable memory side effects and ordering barriers.
            // SAFETY: FP/SIMD and the timer PPI are enabled at EL1. The IRQ
            // handler restores this state before execution resumes after WFI.
            unsafe {
                core::arch::asm!(
                    "movz x9, #0x6677",
                    "movk x9, #0x4455, lsl #16",
                    "movk x9, #0x2233, lsl #32",
                    "movk x9, #0x0011, lsl #48",
                    "mov v0.d[0], x9",
                    "add x9, x9, #1",
                    "mov v0.d[1], x9",
                    "add x9, x9, #1",
                    "mov v15.d[0], x9",
                    "add x9, x9, #1",
                    "mov v15.d[1], x9",
                    "add x9, x9, #1",
                    "mov v31.d[0], x9",
                    "add x9, x9, #1",
                    "mov v31.d[1], x9",
                    "movz x11, #0x0040, lsl #16",
                    "msr fpcr, x11",
                    "movz x11, #0x0011",
                    "movk x11, #0x0800, lsl #16",
                    "msr fpsr, x11",
                    "msr daifclr, #0b0010",
                    "isb",
                    "wfi",
                    "msr daifset, #0b0010",
                    "movz x9, #0x6677",
                    "movk x9, #0x4455, lsl #16",
                    "movk x9, #0x2233, lsl #32",
                    "movk x9, #0x0011, lsl #48",
                    "mov x10, v0.d[0]",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "add x9, x9, #1",
                    "mov x10, v0.d[1]",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "add x9, x9, #1",
                    "mov x10, v15.d[0]",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "add x9, x9, #1",
                    "mov x10, v15.d[1]",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "add x9, x9, #1",
                    "mov x10, v31.d[0]",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "add x9, x9, #1",
                    "mov x10, v31.d[1]",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "mrs x10, fpcr",
                    "movz x9, #0x0040, lsl #16",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "mrs x10, fpsr",
                    "movz x9, #0x0011",
                    "movk x9, #0x0800, lsl #16",
                    "cmp x9, x10",
                    "b.ne 1f",
                    "mov x0, #1",
                    "b 2f",
                    "1:",
                    "mov x0, xzr",
                    "2:",
                    lateout("x0") simd_fp_preserved,
                    lateout("x9") _,
                    lateout("x10") _,
                    lateout("x11") _,
                    lateout("v0") _,
                    lateout("v15") _,
                    lateout("v31") _,
                    options(nostack),
                );
            }

            if simd_fp_preserved == 0 || !simd_fp_clobber_was_consumed() {
                aarch64_bringup_fail(
                    &mut serial,
                    "[ONCRIX/aarch64] kernel SIMD/FP state across timer IRQ FAILED\n",
                );
            }
            let _ = serial
                .write_str("[ONCRIX/aarch64] kernel SIMD/FP state preserved across timer IRQ\n");
        }

        // ─── EL0 (userspace) smoke test ───
        //
        // Prove the EL1->EL0 transition on a dedicated 4KiB RX code page,
        // followed by an invalid guard page and four RW/NX stack pages.
        // The EL0 payload issues an SVC #7 canary, resumes after the vector's
        // `eret`, dispatches Linux AArch64 getpid through SVC #0, validates the
        // returned x0, then issues SVC #8. After the proof EL0 idles, so this is
        // the last action on the aarch64 path.
        {
            use oncrix_hal::arch::aarch64::timer::AArch64Timer;
            use oncrix_hal::timer::Timer;
            use oncrix_kernel::arch::aarch64::usermode::{
                EL0_ENTRY_VA, EL0_STACK_TOP_VA, jump_to_el0,
            };

            // Mask DAIF before stopping the timer so a pending IRQ cannot land
            // in the shutdown window. Intentionally omit `nomem`: the mask must
            // be a compiler barrier so the timer stop cannot move ahead of it.
            // SAFETY: EL1 boot context; nothing after this point needs interrupts.
            unsafe {
                core::arch::asm!("msr daifset, #0b1111", options(nostack));
            }

            // Disarm the generic timer after masking DAIF. EL0 PSTATE cannot
            // mask a physical IRQ routed to EL1, so both steps are required for
            // a deterministic smoke-only round-trip.
            let mut timer = AArch64Timer::new();
            let _ = timer.stop();

            let _ = serial
                .write_str("[ONCRIX/aarch64] entering EL0 (dedicated-page getpid smoke)...\n");

            // SAFETY: the boot tables map `EL0_ENTRY_VA` as the dedicated 4KiB
            // RX code page and `EL0_STACK_TOP_VA` above four RW/NX stack pages,
            // with an invalid guard page between them. The stack top is
            // 16-byte aligned; `jump_to_el0` drops via `eret` and never returns.
            unsafe {
                jump_to_el0(EL0_ENTRY_VA, EL0_STACK_TOP_VA);
            }
        }
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

        // ─── Cooperative kernel-thread scheduling bring-up demo ───
        //
        // Proves the riscv64 `switch_context` actually schedules real kernel
        // threads at runtime. Sequence:
        //   1. Mask sstatus.SIE — `switch_context`/`sched_yield_once` require
        //      interrupts masked, and a cooperative hand-off must not be
        //      preempted by the SBI timer.
        //   2. Register the running boot context as a schedulable thread and
        //      promote it to Running, so `prepare_switch` has a slot to save
        //      the outgoing state into.
        //   3. Spawn two kernel threads. `spawn_kthread` seeds each stack's
        //      112-byte switch frame (ra = entry) plus a parallel
        //      `CpuContext`; copy that context into the scheduler-owned
        //      `Thread` before registering it.
        //   4. Yield. Control flows boot → A → B → boot (round-robin), so
        //      both thread bodies print before we return here.
        {
            use oncrix_kernel::arch::init::SCHEDULER;
            use oncrix_kernel::arch::riscv64::kthread::{kthread_context, spawn_kthread};
            use oncrix_kernel::current::{spawn_thread, yield_now};
            use oncrix_process::pid::{Pid, alloc_tid};
            use oncrix_process::thread::{Priority, Thread};

            // Step 1: mask supervisor interrupts for the whole sequence.
            // SAFETY: ring-0 (S-mode) boot context; masking interrupts is the
            // documented precondition of the switch/yield primitives. No
            // nomem: the SIE clear is cli/sti-class and must act as a compiler
            // barrier.
            unsafe {
                core::arch::asm!("csrci sstatus, 0x2", options(nostack));
            }

            let _ =
                serial.write_str("[ONCRIX/riscv64] cooperative scheduler: bring-up demo start\n");

            // Step 2: register + promote the boot thread.
            // SAFETY: single-threaded boot; SCHEDULER is not aliased here, and
            // each access below is a distinct, non-overlapping borrow.
            unsafe {
                let boot = Thread::new(alloc_tid(), Pid::KERNEL, Priority::NORMAL);
                let _ = spawn_thread(boot);
                let sched = &raw mut SCHEDULER;
                let _ = (*sched).schedule();
            }

            // Step 3: spawn the two demo kernel threads and copy each seeded
            // context into the scheduler-owned `Thread`.
            // SAFETY: entry fns are valid `extern "C" fn() -> !`; single CPU
            // with interrupts masked keeps the pool + scheduler exclusive to
            // this code.
            unsafe {
                if let Ok((kt, mut thread)) = spawn_kthread(demo_thread_a, Priority::NORMAL) {
                    thread.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(thread);
                }
                if let Ok((kt, mut thread)) = spawn_kthread(demo_thread_b, Priority::NORMAL) {
                    thread.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(thread);
                }
            }

            // Step 4: hand the CPU to the demo threads; returns once both A
            // and B have run and yielded back to the boot thread.
            // SAFETY: interrupts masked above; no scheduler borrow held.
            unsafe {
                let _ = yield_now();
            }

            let _ = serial.write_str(
                "[ONCRIX/riscv64] cooperative scheduler: thread A/B ran, back on boot thread\n",
            );
        }

        // Preemptive scheduling demo: spawn two BUSY kernel threads that never
        // yield, then re-arm the timer and set sstatus.SIE. Because C and D
        // only busy-spin, the sole way both make progress is the SBI timer
        // preempting one to run the other (riscv_handle_trap →
        // sched_yield_once). The boot thread polls their atomic counters and
        // reports success once both have printed — proving preemption, not
        // just that interrupts arrive.
        {
            use core::sync::atomic::Ordering;
            use oncrix_hal::arch::riscv64::timer::RiscvTimer;
            use oncrix_hal::timer::Timer;
            use oncrix_kernel::arch::riscv64::kthread::{kthread_context, spawn_kthread};
            use oncrix_kernel::current::spawn_thread;
            use oncrix_process::thread::Priority;

            // Spawn C and D while interrupts are still masked.
            // SAFETY: single CPU, interrupts masked → pool + scheduler are
            // exclusive to this code; entry fns are valid extern "C" fn()->!.
            unsafe {
                if let Ok((kt, mut t)) = spawn_kthread(demo_preempt_c, Priority::NORMAL) {
                    t.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(t);
                }
                if let Ok((kt, mut t)) = spawn_kthread(demo_preempt_d, Priority::NORMAL) {
                    t.set_cpu_context(*kthread_context(kt.slot));
                    let _ = spawn_thread(t);
                }
            }

            // Re-arm the timer and set the global interrupt enable. From here
            // the SBI timer rotates among the runnable threads. `set_oneshot`
            // sets sie.STIE (the per-source enable); sstatus.SIE is the global
            // gate.
            // SAFETY: PLIC + SBI timer were initialized above; arming the
            // timer and setting sstatus.SIE are the documented steps to enable
            // interrupt delivery. No nomem on the SIE set: it is cli/sti-class
            // and must act as a compiler barrier.
            unsafe {
                let mut timer = RiscvTimer::new();
                let ticks = timer.nanos_to_ticks(10_000_000);
                let _ = timer.set_oneshot(ticks);
                core::arch::asm!("csrsi sstatus, 0x2", options(nostack)); // set SIE
            }
            let _ = serial.write_str(
                "[ONCRIX/riscv64] IRQs unmasked; preemptive scheduler armed (threads C, D).\n",
            );

            // Poll until both busy threads have run under preemption. Each
            // timer tick that fires while the boot thread is current will
            // preempt it into C or D; this loop re-checks after each wakeup.
            while PREEMPT_C_HITS.load(Ordering::Relaxed) < 3
                || PREEMPT_D_HITS.load(Ordering::Relaxed) < 3
            {
                // SAFETY: `wfi` parks until the next timer interrupt; harmless.
                unsafe {
                    core::arch::asm!("wfi", options(nomem, nostack));
                }
            }
            let _ = serial.write_str(
                "[ONCRIX/riscv64] preemptive: C and D both ran — timer preemption verified.\n",
            );
        }

        let _ = serial.write_str("[ONCRIX/riscv64] Entering halt loop.\n");
    }

    // x86_64 and riscv64 fall through to the shared halt loop. On aarch64,
    // control descended to EL0 in the block above via `jump_to_el0` (`-> !`)
    // and never reaches here, so the call is compiled out to avoid an
    // unreachable-code warning; `halt_loop` stays live via the panic handler.
    #[cfg(not(target_arch = "aarch64"))]
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
