// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 IRQ dispatch (timer tick + preemption).
//!
//! The HAL exception vector table (installed via `VBAR_EL1` in
//! `crates/hal/src/arch/aarch64/boot.rs`) branches to
//! [`aarch64_handle_irq`] for the EL1 IRQ entry. This module owns the
//! Rust-side handling: it acknowledges the interrupt at the GICv3 CPU
//! interface, services the physical-timer PPI (re-arm + tick + preempt),
//! and signals end-of-interrupt.
//!
//! Mirrors the x86_64 [`timer_handler`](crate::arch::x86_64::interrupts)
//! but stays deliberately minimal: the aarch64 bring-up port runs
//! kernel threads only (no PIT, no itimers/timerfd wiring yet), so the
//! handler charges a tick and attempts one cooperative context switch.

use oncrix_hal::arch::aarch64::gic::{GICD_BASE, GICR_BASE, Gicv3, SPURIOUS_INTID};
use oncrix_hal::arch::aarch64::timer::AArch64Timer;
use oncrix_hal::timer::Timer;

use core::sync::atomic::{AtomicBool, Ordering};

/// Physical (non-secure) EL1 timer PPI INTID.
///
/// The CNTP interrupt is delivered as private peripheral interrupt 30,
/// enabled in `GICR_ISENABLER0` during redistributor init.
const TIMER_PPI: u32 = 30;

/// Tick period for the one-shot timer re-arm (10 ms in nanoseconds).
const TICK_PERIOD_NS: u64 = 10_000_000;

/// Number of timer IRQs announced on the console during bring-up.
///
/// Bounded so the boot log shows interrupts are being delivered without
/// flooding. Accessed only from [`aarch64_handle_irq`] (single-CPU IRQ
/// context), so a plain `static mut` counter is race-free.
static mut TICK_LOG_COUNT: u32 = 0;

/// Whether the next timer IRQ must deliberately overwrite representative
/// SIMD/FP state before the exception epilogue restores its saved frame.
static SIMD_FP_CLOBBER_ARMED: AtomicBool = AtomicBool::new(false);

/// Set only after the armed timer handler has performed the deliberate
/// overwrite, preventing the runtime probe from passing on an unrelated IRQ.
static SIMD_FP_CLOBBER_CONSUMED: AtomicBool = AtomicBool::new(false);

/// Arms one deliberate SIMD/FP overwrite in the next timer IRQ handler.
///
/// This bring-up-only hook is consumed once. Callers should mask IRQs while
/// arming it and seeding the state that the exception frame must preserve.
pub fn arm_simd_fp_clobber_on_next_timer_irq() {
    SIMD_FP_CLOBBER_CONSUMED.store(false, Ordering::Release);
    SIMD_FP_CLOBBER_ARMED.store(true, Ordering::Release);
}

/// Reports whether the armed timer handler performed its deliberate overwrite.
pub fn simd_fp_clobber_was_consumed() -> bool {
    SIMD_FP_CLOBBER_CONSUMED.load(Ordering::Acquire)
}

/// EL1 IRQ handler entry point.
///
/// Called from the HAL exception vector (`bl aarch64_handle_irq`) with
/// interrupts masked by the CPU on entry (`DAIF.I = 1`). Acknowledges the
/// pending Group 1 IRQ at the GIC, dispatches the timer PPI, and issues
/// end-of-interrupt. Spurious acknowledgements ([`SPURIOUS_INTID`]) are
/// ignored without an EOI.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_handle_irq() {
    let gic = Gicv3::new(GICD_BASE, GICR_BASE);
    let intid = gic.ack_irq();
    let mut simd_fp_clobbered = false;

    // No IRQ was actually pending — nothing to service or EOI.
    if intid == SPURIOUS_INTID {
        return;
    }

    if intid == TIMER_PPI {
        // Re-arm the one-shot timer for the next 10 ms tick. The generic
        // timer has no hardware periodic mode, so each tick is re-armed
        // here before the switch, and this write clears the pending PPI.
        let mut timer = AArch64Timer::new();
        let ticks = timer.nanos_to_ticks(TICK_PERIOD_NS);
        let _ = timer.set_oneshot(ticks);

        if SIMD_FP_CLOBBER_ARMED.swap(false, Ordering::AcqRel) {
            // Deliberately destroy the exact state classes checked by the
            // bring-up probe. The exception frame must undo these writes.
            // SAFETY: FP/SIMD is enabled at EL1. All overwritten registers
            // are caller-saved here or explicitly declared as asm outputs.
            unsafe {
                core::arch::asm!(
                    "movi v0.16b, #0xa5",
                    "movi v15.16b, #0x5a",
                    "movi v31.16b, #0x3c",
                    "msr fpcr, {fpcr}",
                    "msr fpsr, {fpsr}",
                    fpcr = in(reg) 0x0080_0000u64,
                    fpsr = in(reg) 0x0800_0080u64,
                    lateout("v0") _,
                    lateout("v15") _,
                    lateout("v31") _,
                    options(nostack),
                );
            }
            SIMD_FP_CLOBBER_CONSUMED.store(true, Ordering::Release);
            simd_fp_clobbered = true;
        }

        // Bring-up visibility: announce the first few timer IRQs so a QEMU
        // boot log shows interrupts are actually being delivered, acked, and
        // handled at EL1. Bounded so it does not flood the console.
        // SAFETY: single-CPU IRQ context (DAIF.I=1); TICK_LOG_COUNT is only
        // touched here, so the read-modify-write is race-free.
        unsafe {
            if TICK_LOG_COUNT < 3 {
                TICK_LOG_COUNT += 1;
                let mut serial = oncrix_hal::arch::aarch64::pl011::Pl011::new(
                    oncrix_hal::arch::aarch64::pl011::PL011_BASE,
                );
                use oncrix_hal::serial::SerialPort as _;
                let _ = serial.write_str("[ONCRIX/aarch64] timer IRQ received (preemptive)\n");
            }
        }

        // Charge one tick of CPU time to the currently running thread,
        // before the switch, so it lands on the thread that consumed the
        // slice.
        // SAFETY: IRQ context with DAIF.I=1 (interrupts masked on entry)
        // on a single CPU — the scheduler is not concurrently mutated, so
        // this &mut borrow is exclusive and is dropped before the switch
        // below takes its own borrow.
        unsafe {
            #[allow(static_mut_refs)]
            let sched = &mut crate::arch::aarch64::init::SCHEDULER;
            if let Some(t) = sched.current_mut() {
                t.charge_tick();
            }
        }
    }

    // End-of-interrupt AFTER re-arm, matching x86 which EOIs before the
    // context switch so a re-enabled higher-priority IRQ can be serviced.
    // SAFETY: `intid` was returned by ack_irq() above and is not spurious,
    // so it names a currently-active IRQ that must be de-activated.
    gic.eoi_irq(intid);

    if intid != TIMER_PPI {
        return;
    }

    // Keep the preservation probe scoped to the IRQ exception frame rather
    // than combining it with a scheduler switch on the same timer tick.
    if simd_fp_clobbered {
        return;
    }

    // Skip the switch when only the idle/current thread is runnable —
    // `prepare_switch` would return `None` anyway, but the up-front check
    // avoids touching the scheduler internals on every tick.
    // SAFETY: single-CPU + DAIF.I=1 guarantees the scheduler is not
    // concurrently mutated; this is a shared read-only borrow.
    let should_switch = unsafe {
        #[allow(static_mut_refs)]
        let sched = &crate::arch::aarch64::init::SCHEDULER;
        sched.ready_count() > 0
    };
    if !should_switch {
        return;
    }

    // Attempt one preemptive kernel-thread switch. This is acceptable from
    // IRQ context during bring-up: the interrupted thread resumes when it
    // is re-elected, at which point `switch_context` returns into this
    // handler's epilogue and the exception vector's `eret` restores the
    // preempted state.
    // SAFETY: IRQ entry guarantees interrupts are masked (DAIF.I=1) and we
    // hold no scheduler borrow here; `sched_yield_once` documents both as
    // its contract. Single-CPU, so the &mut borrow is exclusive.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::aarch64::init::SCHEDULER;
        let _ = crate::arch::aarch64::sched_glue::sched_yield_once(sched);
    }
}
