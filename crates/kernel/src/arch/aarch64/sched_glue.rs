// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 scheduler plumbing (context-switch driver).
//!
//! aarch64 build stub — not yet functional.
//!
//! Mirrors the public API of [`crate::arch::x86_64::sched_glue`] so the
//! architecture-neutral `current`/fork glue type-checks on aarch64. Real
//! preemption requires the aarch64 [`switch_context`](super::context)
//! implementation, which is not written yet.

use oncrix_process::context::Cr3Frame;
use oncrix_process::scheduler::RoundRobinScheduler;

/// Attempt one round-robin preemption.
///
/// aarch64 build stub — not yet functional; always reports "no switch
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
/// aarch64 build stub — not yet functional; returns [`Cr3Frame::NONE`]. On
/// aarch64 the real implementation would read `TTBR0_EL1`.
///
/// # Safety
///
/// Safe to call from any ring-0 context. Currently returns a placeholder.
pub unsafe fn read_cr3() -> Cr3Frame {
    Cr3Frame::NONE
}
