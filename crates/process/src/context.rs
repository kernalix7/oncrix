// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-thread CPU context.
//!
//! Holds the architecture-specific register state saved on context
//! switch. On x86_64 this is the System V callee-saved set plus the
//! stack pointer, instruction pointer, RFLAGS, and CR3 (address space
//! root). The scheduler reads/writes this structure when swapping
//! threads; the initial content is installed by architecture-specific
//! code (`arch_clone_thread`, `init_user_context`, etc.).
//!
//! On non-x86_64 targets the struct is a minimal placeholder so that
//! the process crate still builds.

/// Address space root frame (value loaded into the page-table base
/// register on context switch).
///
/// On x86_64 this is the physical address programmed into `CR3`.
/// On other architectures the semantics are analogous (TTBR0/TTBR1
/// on AArch64, `satp.ppn` on RISC-V); the field is kept as a raw
/// 64-bit value to stay arch-agnostic in `no_std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Cr3Frame(u64);

impl Cr3Frame {
    /// Sentinel value used when no address space is installed yet.
    pub const NONE: Self = Self(0);

    /// Wrap a raw page-table base physical address.
    pub const fn new(phys: u64) -> Self {
        Self(phys)
    }

    /// Return the raw physical address.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Return `true` if this context has no address space installed.
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

impl Default for Cr3Frame {
    fn default() -> Self {
        Self::NONE
    }
}

// ── x86_64 ──────────────────────────────────────────────────────

/// CPU register context saved across a thread switch (x86_64).
///
/// Only the callee-saved set (System V AMD64 ABI) is stored
/// explicitly; caller-saved registers are preserved by the compiler
/// at the call site. `rsp` captures the rest of the pending execution
/// (return address, locals) on the owning kernel stack. `cr3` selects
/// the user address space to install when this thread runs.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuContext {
    /// Saved RBX (callee-saved).
    pub rbx: u64,
    /// Saved RBP (callee-saved frame pointer).
    pub rbp: u64,
    /// Saved R12 (callee-saved).
    pub r12: u64,
    /// Saved R13 (callee-saved).
    pub r13: u64,
    /// Saved R14 (callee-saved).
    pub r14: u64,
    /// Saved R15 (callee-saved).
    pub r15: u64,
    /// Saved RSP (kernel stack pointer for this thread).
    pub rsp: u64,
    /// Saved RIP (resume address — usually a trampoline entry).
    pub rip: u64,
    /// Saved RFLAGS.
    pub rflags: u64,
    /// Address space root (physical `CR3` value).
    pub cr3: Cr3Frame,
}

#[cfg(target_arch = "x86_64")]
impl CpuContext {
    /// RFLAGS with the reserved bit 1 set and IF=1 (interrupts
    /// enabled when this thread resumes to user mode).
    pub const DEFAULT_USER_RFLAGS: u64 = (1 << 1) | (1 << 9);

    /// Create a fully zeroed context (no address space, no entry).
    pub const fn empty() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
            rflags: 0,
            cr3: Cr3Frame::NONE,
        }
    }

    /// Create a kernel-thread context that will resume at `entry`
    /// with `stack_top` as RSP. The address space is left unset;
    /// kernel threads keep running on the current CR3.
    pub const fn new_kernel(entry: u64, stack_top: u64) -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: stack_top,
            rip: entry,
            rflags: Self::DEFAULT_USER_RFLAGS,
            cr3: Cr3Frame::NONE,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Default for CpuContext {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Non-x86_64 placeholder ──────────────────────────────────────

/// CPU register context — minimal placeholder on non-x86_64 targets.
#[cfg(not(target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CpuContext {
    /// Saved stack pointer.
    pub sp: u64,
    /// Saved program counter.
    pub pc: u64,
    /// Address space root.
    pub cr3: Cr3Frame,
}

#[cfg(not(target_arch = "x86_64"))]
impl CpuContext {
    /// Create a zeroed context.
    pub const fn empty() -> Self {
        Self {
            sp: 0,
            pc: 0,
            cr3: Cr3Frame::NONE,
        }
    }
}
