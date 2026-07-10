// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 `fork(2)`/`clone(2)` architecture glue.
//!
//! aarch64 build stub — not yet functional.
//!
//! Mirrors the public API of [`crate::arch::x86_64::clone`] so that the
//! architecture-neutral fork/exec dispatch and `current` accessors
//! type-check when the kernel is compiled for aarch64. The runtime
//! bodies are placeholders: the aarch64 context switch and the ring 0 →
//! EL0 transition that a real fork requires are not implemented yet.

use oncrix_lib::Result;
use oncrix_process::context::Cr3Frame;
use oncrix_process::pid::Pid;
use oncrix_process::thread::{Priority, Thread};

/// Flags-register reserved bit 1 (always 1). Kept for parity with the
/// x86_64 `RFLAGS` sanitizer so the shared snapshot logic is identical.
const RFLAGS_RESERVED: u64 = 1 << 1;
/// Flags-register interrupt-enable bit. Kept for parity with x86_64.
const RFLAGS_IF: u64 = 1 << 9;

/// Parent context snapshot used to build a forked child.
///
/// Field-for-field identical to the x86_64 [`ForkSnapshot`] so the shared
/// fork/exec dispatch code constructs it identically on every target.
///
/// [`ForkSnapshot`]: crate::arch::x86_64::clone::ForkSnapshot
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ForkSnapshot {
    /// Parent's user-mode instruction pointer.
    pub user_rip: u64,
    /// Parent's user-mode stack pointer.
    pub user_rsp: u64,
    /// Parent's user-mode flags register.
    pub user_rflags: u64,
    /// Child's priority (inherited from the parent).
    pub priority: Priority,
    /// Child's address-space root.
    pub child_cr3: Cr3Frame,
    /// Child's pre-allocated PID.
    pub child_pid: Pid,
}

impl ForkSnapshot {
    /// Sanitize the flags register for a return to user mode.
    ///
    /// Keeps only the arithmetic/direction status flags and force-sets the
    /// reserved bit and the interrupt-enable bit — matching the x86_64
    /// implementation so a hostile user cannot smuggle privileged flag
    /// bits across a fork.
    pub const fn sanitized_rflags(&self) -> u64 {
        // CF(0)|PF(2)|AF(4)|ZF(6)|SF(7)|DF(10)|OF(11) = 0x0000_0CD5.
        const SAFE_MASK: u64 = 0x0000_0CD5;
        (self.user_rflags & SAFE_MASK) | RFLAGS_RESERVED | RFLAGS_IF
    }
}

/// Build the child thread for a fork-like clone.
///
/// aarch64 build stub — not yet functional. The signature matches the
/// x86_64 implementation so shared dispatch code type-checks; calling it
/// currently panics because the aarch64 thread-bootstrap path is unwritten.
pub fn arch_clone_thread(_parent: &Thread, _snapshot: &ForkSnapshot) -> Result<Thread> {
    unimplemented!("aarch64: arch_clone_thread not yet implemented")
}

/// Return an untyped pointer to the fork trampoline.
///
/// aarch64 build stub — not yet functional; returns `0` (no trampoline
/// has been assembled for aarch64 yet).
pub fn fork_trampoline_addr() -> u64 {
    0
}
