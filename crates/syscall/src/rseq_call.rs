// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `rseq` (restartable sequences) syscall implementation.
//!
//! Restartable sequences provide a user-space mechanism to execute short
//! critical sections that can be rolled back and restarted if interrupted
//! by a signal or preemption. This enables lock-free per-CPU operations
//! (e.g., lockless ring-buffer updates).
//!
//! Linux-specific (since 4.18). Not in POSIX.

use oncrix_lib::{Error, Result};

/// rseq ABI version 0 (the only version as of Linux 6.x).
pub const RSEQ_ABI_VERSION: u32 = 0;

/// Flag: unregister this thread's rseq ABI structure.
pub const RSEQ_FLAG_UNREGISTER: u32 = 1 << 0;

/// CPU_ID indicating no CPU affinity has been set yet.
pub const RSEQ_CPU_ID_UNINITIALIZED: i32 = -1;

/// CPU_ID indicating the rseq ABI has not been registered.
pub const RSEQ_CPU_ID_REGISTRATION_FAILED: i32 = -2;

/// Size of the rseq structure in the current ABI.
pub const RSEQ_STRUCT_SIZE: u32 = 32;

/// Kernel-managed rseq ABI structure shared with user space via TLS.
///
/// The kernel writes `cpu_id_start` and `cpu_id` on every context switch.
/// User space reads `cpu_id_start` before the critical section and `cpu_id`
/// after; if they differ, the section was interrupted and must be restarted.
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct RseqAbi {
    /// CPU number at the start of the rseq critical section.
    pub cpu_id_start: u32,
    /// Current CPU number (updated by the kernel on context switch).
    pub cpu_id: i32,
    /// Pointer to the rseq critical section abort IP and flags.
    pub rseq_cs: u64,
    /// Flags (currently unused; must be 0).
    pub flags: u32,
    /// Padding to reach 32-byte alignment.
    pub _pad: u32,
}

impl RseqAbi {
    /// Create an uninitialized rseq ABI structure.
    pub const fn new() -> Self {
        Self {
            cpu_id_start: 0,
            cpu_id: RSEQ_CPU_ID_UNINITIALIZED,
            rseq_cs: 0,
            flags: 0,
            _pad: 0,
        }
    }

    /// Return true if the CPU has not changed since cpu_id_start was read.
    pub fn is_cpu_stable(&self) -> bool {
        self.cpu_id_start == (self.cpu_id as u32)
    }
}

impl Default for RseqAbi {
    fn default() -> Self {
        Self::new()
    }
}

/// Rseq critical section descriptor written by user space.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RseqCs {
    /// Version of the descriptor format.
    pub version: u32,
    /// Flags (must be 0 in the current ABI).
    pub flags: u32,
    /// Start of the critical section (virtual address).
    pub start_ip: u64,
    /// Post-commit offset: bytes past start_ip where the section commits.
    pub post_commit_offset: u64,
    /// Abort handler virtual address.
    pub abort_ip: u64,
}

/// Arguments for the `rseq` syscall.
#[derive(Debug)]
pub struct RseqArgs {
    /// Pointer to the per-thread rseq ABI structure in user space.
    pub rseq_ptr: usize,
    /// Size of the structure as seen by user space.
    pub rseq_len: u32,
    /// Flags (0 = register, RSEQ_FLAG_UNREGISTER = unregister).
    pub flags: u32,
    /// Signature: a 32-bit magic value placed before each abort handler.
    pub sig: u32,
}

/// Validate rseq syscall arguments.
///
/// Checks that rseq_ptr is aligned and non-null, rseq_len matches the
/// expected ABI size, and only known flags are set.
pub fn validate_rseq_args(args: &RseqArgs) -> Result<()> {
    if args.rseq_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // The rseq structure must be 32-byte aligned.
    if args.rseq_ptr % 32 != 0 {
        return Err(Error::InvalidArgument);
    }
    if args.rseq_len < RSEQ_STRUCT_SIZE {
        return Err(Error::InvalidArgument);
    }
    let known_flags = RSEQ_FLAG_UNREGISTER;
    if args.flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `rseq` syscall.
///
/// Registers or unregisters the per-thread rseq ABI structure at `rseq_ptr`.
/// Only one registration is allowed per thread; a second registration
/// returns `Err(AlreadyExists)` (EINVAL in Linux).
///
/// On registration, the kernel stores `rseq_ptr` and `sig` in the thread's
/// task_struct and updates `cpu_id` on every context switch.
///
/// Returns 0 on success, or an error.
pub fn sys_rseq(args: &RseqArgs) -> Result<i64> {
    validate_rseq_args(args)?;

    if (args.flags & RSEQ_FLAG_UNREGISTER) != 0 {
        return sys_rseq_unregister(args);
    }
    sys_rseq_register(args)
}

/// Register the rseq ABI structure for the current thread.
fn sys_rseq_register(args: &RseqArgs) -> Result<i64> {
    // Stub: real implementation would:
    // 1. Check thread has no existing rseq registration (EINVAL if so).
    // 2. Validate the abort handler signature at rseq_ptr - 4.
    // 3. Store rseq_ptr and sig in current->rseq / current->rseq_sig.
    // 4. Write cpu_id to the user-space structure via copy_to_user.
    let _ = args;
    Err(Error::NotImplemented)
}

/// Unregister the rseq ABI structure for the current thread.
fn sys_rseq_unregister(args: &RseqArgs) -> Result<i64> {
    // Stub: real implementation would:
    // 1. Verify rseq_ptr and sig match the current registration.
    // 2. Clear current->rseq.
    // 3. Write RSEQ_CPU_ID_REGISTRATION_FAILED to the structure.
    let _ = args;
    Err(Error::NotImplemented)
}

/// Check whether the current thread has a registered rseq structure.
pub fn is_rseq_registered() -> bool {
    // Stub: queries current->rseq != NULL.
    false
}

/// Validate the abort handler signature placed before the abort IP.
///
/// The kernel verifies that the 4 bytes at (abort_ip - 4) match `sig`.
pub fn validate_abort_signature(abort_ip: u64, sig: u32) -> Result<()> {
    if abort_ip < 4 {
        return Err(Error::InvalidArgument);
    }
    // Stub: real validation reads from user space via copy_from_user.
    let _ = sig;
    Err(Error::NotImplemented)
}
