// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-thread kernel state (thread_info).
//!
//! Each thread has a `ThreadInfo` structure at the base of its kernel
//! stack, containing low-level flags that are checked on every
//! syscall return, interrupt exit, and scheduling decision.
//!
//! # Flag Checks
//!
//! ```text
//!   return-to-user path:
//!     if TIF_SIGPENDING   → do_signal()
//!     if TIF_NEED_RESCHED → schedule()
//!     if TIF_SYSCALL_TRACE → ptrace notification
//!     if TIF_NOTIFY_RESUME → task_work_run()
//! ```
//!
//! # Preempt Count
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ preempt_count (u32)                              │
//! │                                                  │
//! │ Bits  0-7:  preemption disable depth             │
//! │ Bits  8-15: softirq disable depth                │
//! │ Bits 16-19: hardirq nesting count                │
//! │ Bit  20:    NMI context                          │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `arch/x86/include/asm/thread_info.h`,
//! `include/linux/thread_info.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of threads tracked.
const MAX_THREADS: usize = 1024;

// --- Thread info flags (TIF_*) ---

/// Syscall trace active.
pub const TIF_SYSCALL_TRACE: u32 = 1 << 0;
/// Signal pending.
pub const TIF_SIGPENDING: u32 = 1 << 1;
/// Need reschedule.
pub const TIF_NEED_RESCHED: u32 = 1 << 2;
/// Single-step mode.
pub const TIF_SINGLESTEP: u32 = 1 << 3;
/// Notify resume (task_work pending).
pub const TIF_NOTIFY_RESUME: u32 = 1 << 4;
/// Restore signal mask on return.
pub const TIF_RESTORE_SIGMASK: u32 = 1 << 5;
/// In 32-bit compatibility mode.
pub const TIF_32BIT: u32 = 1 << 6;
/// Seccomp filter active.
pub const TIF_SECCOMP: u32 = 1 << 7;
/// Polling NRFLAG (idle loop).
pub const TIF_POLLING_NRFLAG: u32 = 1 << 8;
/// Memory protection keys in use.
pub const TIF_NEED_FPU_LOAD: u32 = 1 << 9;
/// Syscall audit active.
pub const TIF_SYSCALL_AUDIT: u32 = 1 << 10;
/// Block step (ptrace).
pub const TIF_BLOCKSTEP: u32 = 1 << 11;
/// Address limit changed.
pub const TIF_ADDR_LIMIT: u32 = 1 << 12;
/// Memdie (OOM victim).
pub const TIF_MEMDIE: u32 = 1 << 13;
/// Lazy FPU restore pending.
pub const TIF_LAZY_MMU_UPDATES: u32 = 1 << 14;
/// Patched (live patching applied).
pub const TIF_PATCH_PENDING: u32 = 1 << 15;

/// Flags that must be checked on syscall return.
const _WORK_SYSCALL_EXIT: u32 =
    TIF_SYSCALL_TRACE | TIF_SYSCALL_AUDIT | TIF_SINGLESTEP | TIF_SECCOMP;

/// Flags that trigger work on return to user space.
const _WORK_NOTIFY_MASK: u32 =
    TIF_SIGPENDING | TIF_NEED_RESCHED | TIF_NOTIFY_RESUME | TIF_PATCH_PENDING;

// --- Preempt count bit positions ---

/// Mask for preemption disable depth (bits 0-7).
const PREEMPT_MASK: u32 = 0xFF;

/// Mask for softirq disable depth (bits 8-15).
const SOFTIRQ_MASK: u32 = 0xFF00;

/// Shift for softirq bits.
const SOFTIRQ_SHIFT: u32 = 8;

/// Mask for hardirq nesting (bits 16-19).
const HARDIRQ_MASK: u32 = 0xF_0000;

/// Shift for hardirq bits.
const HARDIRQ_SHIFT: u32 = 16;

/// NMI context bit (bit 20).
const NMI_BIT: u32 = 1 << 20;

// ======================================================================
// Address limit
// ======================================================================

/// User-space address limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrLimit {
    /// Normal user address limit (e.g., 0x0000_7FFF_FFFF_FFFF).
    User,
    /// Kernel address limit (full address space).
    Kernel,
}

impl AddrLimit {
    /// Returns the numeric limit.
    pub fn value(&self) -> u64 {
        match self {
            Self::User => 0x0000_7FFF_FFFF_FFFF,
            Self::Kernel => u64::MAX,
        }
    }
}

// ======================================================================
// Thread info
// ======================================================================

/// Per-thread kernel state.
#[derive(Debug, Clone, Copy)]
pub struct ThreadInfo {
    /// Thread ID.
    tid: u32,
    /// Flag bitmask (TIF_*).
    flags: u32,
    /// Preempt count (combined preempt/softirq/hardirq/NMI).
    preempt_count: u32,
    /// Address limit.
    addr_limit: AddrLimit,
    /// CPU this thread is currently running on.
    cpu: u32,
    /// Status (running, sleeping, etc.).
    status: u32,
    /// Whether this entry is active.
    active: bool,
    /// System call number being executed (0 if none).
    syscall_nr: u32,
    /// Saved return value from last syscall.
    syscall_ret: i64,
}

impl ThreadInfo {
    /// Creates a new empty thread info.
    pub const fn new() -> Self {
        Self {
            tid: 0,
            flags: 0,
            preempt_count: 0,
            addr_limit: AddrLimit::User,
            cpu: 0,
            status: 0,
            active: false,
            syscall_nr: 0,
            syscall_ret: 0,
        }
    }

    /// Returns the thread ID.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Returns the flags bitmask.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the current CPU.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Returns the address limit.
    pub fn addr_limit(&self) -> AddrLimit {
        self.addr_limit
    }

    /// Returns the preempt count.
    pub fn preempt_count(&self) -> u32 {
        self.preempt_count
    }

    /// Returns the preemption disable depth.
    pub fn preempt_depth(&self) -> u32 {
        self.preempt_count & PREEMPT_MASK
    }

    /// Returns the softirq disable depth.
    pub fn softirq_depth(&self) -> u32 {
        (self.preempt_count & SOFTIRQ_MASK) >> SOFTIRQ_SHIFT
    }

    /// Returns the hardirq nesting count.
    pub fn hardirq_count(&self) -> u32 {
        (self.preempt_count & HARDIRQ_MASK) >> HARDIRQ_SHIFT
    }

    /// Returns whether we are in NMI context.
    pub fn in_nmi(&self) -> bool {
        (self.preempt_count & NMI_BIT) != 0
    }

    /// Returns whether preemption is disabled.
    pub fn preempt_disabled(&self) -> bool {
        self.preempt_depth() > 0
    }

    /// Returns whether we are in interrupt context.
    pub fn in_interrupt(&self) -> bool {
        (self.preempt_count & (HARDIRQ_MASK | SOFTIRQ_MASK | NMI_BIT)) != 0
    }

    // --- Flag operations ---

    /// Sets a flag.
    pub fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }

    /// Clears a flag.
    pub fn clear_flag(&mut self, flag: u32) {
        self.flags &= !flag;
    }

    /// Tests a flag.
    pub fn test_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    /// Tests and sets a flag (returns old value).
    pub fn test_and_set_flag(&mut self, flag: u32) -> bool {
        let was_set = self.test_flag(flag);
        self.set_flag(flag);
        was_set
    }

    /// Tests and clears a flag (returns old value).
    pub fn test_and_clear_flag(&mut self, flag: u32) -> bool {
        let was_set = self.test_flag(flag);
        self.clear_flag(flag);
        was_set
    }

    // --- Preempt count operations ---

    /// Disables preemption.
    pub fn preempt_disable(&mut self) {
        let depth = self.preempt_count & PREEMPT_MASK;
        if depth < 255 {
            self.preempt_count += 1;
        }
    }

    /// Enables preemption.
    pub fn preempt_enable(&mut self) {
        let depth = self.preempt_count & PREEMPT_MASK;
        if depth > 0 {
            self.preempt_count -= 1;
        }
    }

    /// Enters softirq context.
    pub fn softirq_enter(&mut self) {
        self.preempt_count += 1 << SOFTIRQ_SHIFT;
    }

    /// Exits softirq context.
    pub fn softirq_exit(&mut self) {
        let depth = self.softirq_depth();
        if depth > 0 {
            self.preempt_count -= 1 << SOFTIRQ_SHIFT;
        }
    }

    /// Enters hardirq context.
    pub fn hardirq_enter(&mut self) {
        self.preempt_count += 1 << HARDIRQ_SHIFT;
    }

    /// Exits hardirq context.
    pub fn hardirq_exit(&mut self) {
        let count = self.hardirq_count();
        if count > 0 {
            self.preempt_count -= 1 << HARDIRQ_SHIFT;
        }
    }

    /// Enters NMI context.
    pub fn nmi_enter(&mut self) {
        self.preempt_count |= NMI_BIT;
    }

    /// Exits NMI context.
    pub fn nmi_exit(&mut self) {
        self.preempt_count &= !NMI_BIT;
    }

    // --- Convenience queries ---

    /// Returns whether rescheduling is needed.
    pub fn need_resched(&self) -> bool {
        self.test_flag(TIF_NEED_RESCHED)
    }

    /// Returns whether signals are pending.
    pub fn sigpending(&self) -> bool {
        self.test_flag(TIF_SIGPENDING)
    }

    /// Returns whether syscall tracing is active.
    pub fn syscall_traced(&self) -> bool {
        self.test_flag(TIF_SYSCALL_TRACE)
    }

    /// Sets the current CPU.
    pub fn set_cpu(&mut self, cpu: u32) {
        self.cpu = cpu;
    }

    /// Sets the address limit.
    pub fn set_addr_limit(&mut self, limit: AddrLimit) {
        self.addr_limit = limit;
        if matches!(limit, AddrLimit::Kernel) {
            self.set_flag(TIF_ADDR_LIMIT);
        } else {
            self.clear_flag(TIF_ADDR_LIMIT);
        }
    }
}

// ======================================================================
// Thread info table
// ======================================================================

/// Manages thread_info for all threads.
pub struct ThreadInfoTable {
    /// Per-thread info entries.
    entries: [ThreadInfo; MAX_THREADS],
    /// Number of active threads.
    count: usize,
}

impl ThreadInfoTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { ThreadInfo::new() }; MAX_THREADS],
            count: 0,
        }
    }

    /// Returns the number of active threads.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Allocates a thread info entry.
    pub fn alloc(&mut self, tid: u32, cpu: u32) -> Result<usize> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = ThreadInfo::new();
        self.entries[slot].tid = tid;
        self.entries[slot].cpu = cpu;
        self.entries[slot].active = true;
        self.count += 1;
        Ok(slot)
    }

    /// Frees a thread info entry.
    pub fn free(&mut self, tid: u32) -> Result<()> {
        let slot = self.find(tid)?;
        self.entries[slot].active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns a reference to a thread info by TID.
    pub fn get(&self, tid: u32) -> Result<&ThreadInfo> {
        let slot = self.find(tid)?;
        Ok(&self.entries[slot])
    }

    /// Returns a mutable reference to a thread info by TID.
    pub fn get_mut(&mut self, tid: u32) -> Result<&mut ThreadInfo> {
        let slot = self.find(tid)?;
        Ok(&mut self.entries[slot])
    }

    /// Finds all threads with a given flag set.
    pub fn count_with_flag(&self, flag: u32) -> usize {
        self.entries
            .iter()
            .filter(|e| e.active && e.test_flag(flag))
            .count()
    }

    /// Sets a flag on a thread by TID.
    pub fn set_flag(&mut self, tid: u32, flag: u32) -> Result<()> {
        let slot = self.find(tid)?;
        self.entries[slot].set_flag(flag);
        Ok(())
    }

    /// Clears a flag on a thread by TID.
    pub fn clear_flag(&mut self, tid: u32, flag: u32) -> Result<()> {
        let slot = self.find(tid)?;
        self.entries[slot].clear_flag(flag);
        Ok(())
    }

    /// Finds a thread slot by TID.
    fn find(&self, tid: u32) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)
    }
}
