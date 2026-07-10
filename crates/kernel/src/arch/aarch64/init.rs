// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 scheduler / timer statics and per-switch glue.
//!
//! aarch64 build stub — not yet functional.
//!
//! Provides the architecture statics ([`SCHEDULER`], [`PIT_TIMER`]) and the
//! per-context-switch hooks that architecture-neutral kernel code reaches
//! through the [`crate::arch::init`] facade. The statics are real (the
//! scheduler and timer types are shared across architectures); the
//! page-table / trap-stack hooks are no-ops until the aarch64 MMU and
//! exception-return paths are wired up.

use oncrix_hal::arch::aarch64::timer::AArch64Timer;
use oncrix_process::scheduler::RoundRobinScheduler;

/// Global round-robin scheduler (the same type used on every architecture).
pub static mut SCHEDULER: RoundRobinScheduler = RoundRobinScheduler::new();

/// Global monotonic tick source.
///
/// Named `PIT_TIMER` for parity with the x86_64 port; on aarch64 it is
/// backed by the ARM generic timer (CNTPCT_EL0) rather than an 8254 PIT.
/// Architecture-neutral time syscalls read `current_ticks()` from it via
/// the [`oncrix_hal::timer::Timer`] trait.
pub static mut PIT_TIMER: AArch64Timer = AArch64Timer::new();

/// Update the incoming thread's kernel trap stack.
///
/// aarch64 build stub — not yet functional. AArch64 selects the EL1 stack
/// via `SPSel`/`SP_EL1` rather than an x86 TSS `RSP0` field, so this is a
/// no-op until the exception-vector stack switch is implemented.
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op.
pub unsafe fn switch_tss_rsp0(_top_of_stack: u64) {}

/// Install the incoming thread's user page table into the active tables.
///
/// aarch64 build stub — not yet functional. On aarch64 the user tables are
/// selected through `TTBR0_EL1`; until per-process address spaces are wired
/// up this is a no-op.
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op.
pub unsafe fn install_user_pt(_pt_phys: u64) {}

/// Install the incoming thread's mmap page table into the active tables.
///
/// aarch64 build stub — not yet functional. See [`install_user_pt`].
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op.
pub unsafe fn install_user_mmap_pt(_pt_phys: Option<u64>) {}
