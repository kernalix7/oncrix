// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit scheduler plumbing (context-switch driver).
//!
//! riscv64 build stub — not yet functional.
//!
//! Mirrors the public API of [`crate::arch::x86_64::sched_glue`] so the
//! architecture-neutral `current`/fork glue type-checks on riscv64. Real
//! preemption requires the riscv64 [`switch_context`](super::context)
//! implementation, which is not written yet.

use oncrix_process::context::Cr3Frame;
use oncrix_process::scheduler::RoundRobinScheduler;

/// Attempt one round-robin preemption.
///
/// riscv64 build stub — not yet functional; always reports "no switch
/// happened" so callers fall through without touching CPU state.
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op that returns
/// `false`.
pub unsafe fn sched_yield_once(_sched: &mut RoundRobinScheduler) -> bool {
    false
}

/// Read the active address-space root.
///
/// riscv64 build stub — not yet functional; returns [`Cr3Frame::NONE`]. On
/// riscv64 the real implementation would read the `satp` CSR.
///
/// # Safety
///
/// Safe to call from any ring-0 context. Currently returns a placeholder.
pub unsafe fn read_cr3() -> Cr3Frame {
    Cr3Frame::NONE
}
