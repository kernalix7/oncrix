// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit trap dispatch (timer tick + preemption).
//!
//! The HAL S-mode trap vector (installed via `stvec` in
//! `crates/hal/src/arch/riscv64/boot.rs`) saves the caller-saved GPRs plus
//! `sepc`/`sstatus`, then `call`s [`riscv_handle_trap`] for every trap. This
//! module owns the Rust-side handling: it reads `scause`, services the
//! supervisor-timer interrupt (re-arm + tick + preempt), and returns so the
//! trap vector can restore state and `sret`.
//!
//! Mirrors the aarch64 [`aarch64_handle_irq`](crate::arch::aarch64::irq) but
//! stays deliberately minimal: the riscv64 bring-up port runs kernel threads
//! only (no itimers/timerfd wiring yet), so the handler charges a tick and
//! attempts one cooperative context switch.
//!
//! Unlike the aarch64 GICv3 path there is **no** end-of-interrupt write: on
//! RISC-V, re-arming the SBI timer with a fresh future deadline is what clears
//! the pending supervisor-timer bit (`sip.STIP`).

use oncrix_hal::arch::riscv64::ns16550::{NS16550_BASE, Ns16550};
use oncrix_hal::arch::riscv64::timer::RiscvTimer;
use oncrix_hal::serial::SerialPort as _;
use oncrix_hal::timer::Timer;

/// `scause` value for a supervisor-mode timer interrupt.
///
/// Interrupts set the high bit (bit 63) of `scause`; the S-mode timer
/// interrupt code is 5, giving `0x8000_0000_0000_0005`.
const SUPERVISOR_TIMER_INTERRUPT: u64 = 0x8000_0000_0000_0005;

/// Tick period for the one-shot timer re-arm (10 ms in nanoseconds).
const TICK_PERIOD_NS: u64 = 10_000_000;

/// Number of timer interrupts announced on the console during bring-up.
///
/// Bounded so the boot log shows interrupts are being delivered without
/// flooding. Accessed only from [`riscv_handle_trap`] (single-CPU trap
/// context, `sstatus.SIE = 0` on entry), so a plain `static mut` counter is
/// race-free.
static mut TICK_LOG_COUNT: u32 = 0;

/// S-mode trap handler entry point.
///
/// Called from the HAL trap vector (`call riscv_handle_trap`) after the
/// caller-saved GPRs plus `sepc`/`sstatus` have been stacked and with
/// supervisor interrupts masked by the hardware on trap entry
/// (`sstatus.SIE = 0`). Reads `scause`; on the supervisor-timer interrupt it
/// re-arms the SBI timer (which clears the pending bit and keeps `sie.STIE`
/// set), charges a tick to the current thread, and attempts one preemptive
/// kernel-thread switch. Any other trap cause returns immediately, letting the
/// vector `sret` back to the interrupted context.
#[unsafe(no_mangle)]
pub extern "C" fn riscv_handle_trap() {
    let scause: u64;
    // SAFETY: `csrr scause` is a side-effect-free read of the trap-cause CSR;
    // `nomem`/`nostack` are correct for a pure CSR read.
    unsafe {
        core::arch::asm!("csrr {0}, scause", out(reg) scause, options(nomem, nostack));
    }

    // Only the supervisor-timer interrupt drives preemption during bring-up.
    if scause != SUPERVISOR_TIMER_INTERRUPT {
        return;
    }

    // Re-arm the one-shot timer for the next 10 ms tick. RISC-V has no
    // hardware periodic mode, so each tick is re-armed here; setting a fresh
    // future deadline via SBI is also what clears the pending `sip.STIP`
    // (there is no GIC-style EOI). `set_oneshot` additionally keeps
    // `sie.STIE` enabled.
    let mut timer = RiscvTimer::new();
    let ticks = timer.nanos_to_ticks(TICK_PERIOD_NS);
    let _ = timer.set_oneshot(ticks);

    // Bring-up visibility: announce the first few timer interrupts so a QEMU
    // boot log shows interrupts are actually being delivered and handled in
    // S-mode. Bounded so it does not flood the console.
    // SAFETY: single-CPU trap context (`sstatus.SIE = 0`); TICK_LOG_COUNT is
    // only touched here, so the read-modify-write is race-free.
    unsafe {
        if TICK_LOG_COUNT < 3 {
            TICK_LOG_COUNT += 1;
            let mut serial = Ns16550::new(NS16550_BASE);
            let _ = serial.write_str("[ONCRIX/riscv64] timer IRQ received (preemptive)\n");
        }
    }

    // Charge one tick of CPU time to the currently running thread, before the
    // switch, so it lands on the thread that consumed the slice.
    // SAFETY: trap context with `sstatus.SIE = 0` on a single CPU — the
    // scheduler is not concurrently mutated, so this `&mut` borrow is
    // exclusive and is dropped before the switch below takes its own borrow.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::riscv64::init::SCHEDULER;
        if let Some(t) = sched.current_mut() {
            t.charge_tick();
        }
    }

    // Skip the switch when only the idle/current thread is runnable —
    // `prepare_switch` would return `None` anyway, but the up-front check
    // avoids touching the scheduler internals on every tick.
    // SAFETY: single-CPU + `sstatus.SIE = 0` guarantees the scheduler is not
    // concurrently mutated; this is a shared read-only borrow.
    let should_switch = unsafe {
        #[allow(static_mut_refs)]
        let sched = &crate::arch::riscv64::init::SCHEDULER;
        sched.ready_count() > 0
    };
    if !should_switch {
        return;
    }

    // Attempt one preemptive kernel-thread switch. This is acceptable from
    // trap context during bring-up: the interrupted thread resumes when it is
    // re-elected, at which point `switch_context` returns into this handler's
    // epilogue and the trap vector's `sret` restores the preempted state
    // (the vector stacked `sepc`/`sstatus` for exactly this reason).
    // SAFETY: trap entry guarantees interrupts are masked (`sstatus.SIE = 0`)
    // and we hold no scheduler borrow here; `sched_yield_once` documents both
    // as its contract. Single-CPU, so the `&mut` borrow is exclusive.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::riscv64::init::SCHEDULER;
        let _ = crate::arch::riscv64::sched_glue::sched_yield_once(sched);
    }
}
