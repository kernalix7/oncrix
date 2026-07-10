// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 SYSCALL-entry saved-register mirrors.
//!
//! aarch64 build stub — not yet functional.
//!
//! Provides the saved-user-register atomics and accessors that
//! architecture-neutral fork/exec/signal dispatch reads, mirroring
//! [`crate::arch::x86_64::syscall_entry`]. The atomics themselves are real
//! (they are plain shared storage); what is missing is the aarch64 `svc`
//! exception vector that would populate them on a real syscall entry.

use core::sync::atomic::{AtomicU64, Ordering};

/// Saved user stack pointer during syscall execution.
pub static SYSCALL_SAVED_USER_RSP: AtomicU64 = AtomicU64::new(0);

/// Saved user program counter during syscall execution.
pub static SYSCALL_SAVED_USER_RIP: AtomicU64 = AtomicU64::new(0);

/// Saved user flags register during syscall execution.
pub static SYSCALL_SAVED_USER_RFLAGS: AtomicU64 = AtomicU64::new(0);

/// Read the saved user program counter.
pub fn saved_user_rip() -> u64 {
    SYSCALL_SAVED_USER_RIP.load(Ordering::Relaxed)
}

/// Read the saved user flags register.
pub fn saved_user_rflags() -> u64 {
    SYSCALL_SAVED_USER_RFLAGS.load(Ordering::Relaxed)
}

/// Read the saved user stack pointer.
pub fn saved_user_rsp() -> u64 {
    SYSCALL_SAVED_USER_RSP.load(Ordering::Relaxed)
}

/// Overwrite the saved user program counter.
pub fn set_saved_user_rip(rip: u64) {
    SYSCALL_SAVED_USER_RIP.store(rip, Ordering::Relaxed);
}

/// Overwrite the saved user flags register.
pub fn set_saved_user_rflags(rflags: u64) {
    SYSCALL_SAVED_USER_RFLAGS.store(rflags, Ordering::Relaxed);
}

/// Overwrite the saved user stack pointer.
pub fn set_saved_user_rsp(rsp: u64) {
    SYSCALL_SAVED_USER_RSP.store(rsp, Ordering::Relaxed);
}
