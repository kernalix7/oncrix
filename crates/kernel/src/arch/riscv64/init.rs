// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit scheduler / timer statics and per-switch glue.
//!
//! riscv64 build stub — not yet functional.
//!
//! Provides the architecture statics ([`SCHEDULER`], [`PIT_TIMER`]) and the
//! per-context-switch hooks that architecture-neutral kernel code reaches
//! through the [`crate::arch::init`] facade. The statics are real (the
//! scheduler and timer types are shared across architectures); the
//! page-table / trap-stack hooks are no-ops until the riscv64 MMU (Sv39/
//! Sv48 via `satp`) and trap-return paths are wired up.

use oncrix_hal::arch::riscv64::timer::RiscvTimer;
use oncrix_process::scheduler::RoundRobinScheduler;

/// Global round-robin scheduler (the same type used on every architecture).
pub static mut SCHEDULER: RoundRobinScheduler = RoundRobinScheduler::new();

/// Global monotonic tick source.
///
/// Named `PIT_TIMER` for parity with the x86_64 port; on riscv64 it is
/// backed by the SBI/CLINT timer (`mtime` + `sbi_set_timer`) rather than
/// an 8254 PIT. Architecture-neutral time syscalls read `current_ticks()`
/// from it via the [`oncrix_hal::timer::Timer`] trait.
pub static mut PIT_TIMER: RiscvTimer = RiscvTimer::new();

/// Update the incoming thread's kernel trap stack.
///
/// riscv64 build stub — not yet functional. RISC-V selects the S-mode
/// trap-handler stack via `sscratch` rather than an x86 TSS `RSP0` field,
/// so this is a no-op until the trap-vector stack switch is implemented.
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op.
pub unsafe fn switch_tss_rsp0(_top_of_stack: u64) {}

/// Install the incoming thread's user page table into the active tables.
///
/// riscv64 build stub — not yet functional. On riscv64 the user tables
/// are selected through the `satp` CSR; until per-process address spaces
/// are wired up this is a no-op.
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op.
pub unsafe fn install_user_pt(_pt_phys: u64) {}

/// Install the incoming thread's mmap page table into the active tables.
///
/// riscv64 build stub — not yet functional. See [`install_user_pt`].
///
/// # Safety
///
/// Must be called with interrupts disabled. Currently a no-op.
pub unsafe fn install_user_mmap_pt(_pt_phys: Option<u64>) {}
