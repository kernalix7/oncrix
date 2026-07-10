// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 low-level context switch.
//!
//! aarch64 build stub — not yet functional.
//!
//! The CPU register block is defined once in
//! [`oncrix_process::context::CpuContext`]; this module only needs to
//! re-export it and provide a signature-compatible `switch_context` so
//! that architecture-neutral scheduler plumbing type-checks on aarch64.

pub use oncrix_process::context::CpuContext;

/// Perform a context switch from `old` to `new`.
///
/// aarch64 build stub — not yet functional. The real implementation must
/// save/restore the callee-saved GPRs (x19–x30), `SP`, and `PSTATE` per
/// the AArch64 procedure call standard; until then this panics if called.
///
/// # Safety
///
/// Never call on aarch64: the context switch is not implemented. When
/// implemented, both pointers must reference valid [`CpuContext`] values
/// and interrupts must be disabled.
pub unsafe extern "C" fn switch_context(_old: *mut CpuContext, _new: *const CpuContext) {
    unimplemented!("aarch64: switch_context not yet implemented")
}
