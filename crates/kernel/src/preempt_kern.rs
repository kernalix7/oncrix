// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Preemption control subsystem.
//!
//! Tracks the per-CPU preemption state using a combined counter
//! that encodes preempt-disable depth, softirq nesting, hardirq
//! nesting, and NMI context. Used by the scheduler and locking
//! subsystems to determine whether context switches are safe.
//!
//! # Preempt Count Layout
//!
//! ```text
//! ┌───────────┬──────────┬──────────┬──────────┬──────────┐
//! │ bit 24    │ bits     │ bits     │ bits     │ bits     │
//! │ NMI (1b)  │ 20-23    │ 16-19    │ 8-15     │ 0-7      │
//! │           │ HARDIRQ  │ SOFTIRQ  │ SOFTIRQ  │ PREEMPT  │
//! │           │ count    │ disable  │ count    │ depth    │
//! └───────────┴──────────┴──────────┴──────────┴──────────┘
//! ```
//!
//! # Key Checks
//!
//! - `preemptible()` — preempt_count == 0
//! - `in_interrupt()` — hardirq + softirq > 0
//! - `in_softirq()` — softirq count > 0
//! - `in_hardirq()` — hardirq count > 0
//! - `in_nmi()` — NMI bit set
//!
//! # Reference
//!
//! Linux `include/linux/preempt.h`, `include/asm-generic/preempt.h`,
//! `kernel/sched/core.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Preempt disable depth occupies bits 0..7.
const PREEMPT_MASK: u32 = 0x0000_00FF;
/// Preempt bit shift.
const _PREEMPT_SHIFT: u32 = 0;

/// Softirq count occupies bits 8..15.
const SOFTIRQ_MASK: u32 = 0x0000_FF00;
/// Softirq bit shift.
const SOFTIRQ_SHIFT: u32 = 8;

/// Softirq disable occupies bits 16..19.
const SOFTIRQ_DISABLE_MASK: u32 = 0x000F_0000;
/// Softirq disable shift.
const SOFTIRQ_DISABLE_SHIFT: u32 = 16;

/// Hardirq count occupies bits 20..23.
const HARDIRQ_MASK: u32 = 0x00F0_0000;
/// Hardirq bit shift.
const HARDIRQ_SHIFT: u32 = 20;

/// NMI flag is bit 24.
const NMI_MASK: u32 = 0x0100_0000;

/// Interrupt mask (hardirq + softirq).
const IRQ_MASK: u32 = HARDIRQ_MASK | SOFTIRQ_MASK;

/// Maximum preempt disable nesting depth.
const MAX_PREEMPT_DEPTH: u32 = 255;

/// Maximum softirq nesting.
const MAX_SOFTIRQ_DEPTH: u32 = 255;

/// Maximum hardirq nesting.
const MAX_HARDIRQ_DEPTH: u32 = 15;

// ── PreemptCount ────────────────────────────────────────────

/// Combined preemption counter for a single CPU.
///
/// Encodes preempt-disable depth, softirq nesting, hardirq
/// nesting, and NMI state in a single u32.
#[derive(Debug, Clone, Copy)]
pub struct PreemptCount {
    /// Raw counter value.
    raw: u32,
}

impl PreemptCount {
    /// Create a zero preempt count (fully preemptible).
    pub const fn new() -> Self {
        Self { raw: 0 }
    }

    /// Create from a raw value.
    pub const fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    /// Get the raw value.
    pub const fn raw(self) -> u32 {
        self.raw
    }

    /// Preempt-disable depth (0 = preemptible).
    pub const fn preempt_depth(self) -> u32 {
        self.raw & PREEMPT_MASK
    }

    /// Softirq nesting count.
    pub const fn softirq_count(self) -> u32 {
        (self.raw & SOFTIRQ_MASK) >> SOFTIRQ_SHIFT
    }

    /// Softirq disable count.
    pub const fn softirq_disable_count(self) -> u32 {
        (self.raw & SOFTIRQ_DISABLE_MASK) >> SOFTIRQ_DISABLE_SHIFT
    }

    /// Hardirq nesting count.
    pub const fn hardirq_count(self) -> u32 {
        (self.raw & HARDIRQ_MASK) >> HARDIRQ_SHIFT
    }

    /// Whether in NMI context.
    pub const fn in_nmi(self) -> bool {
        (self.raw & NMI_MASK) != 0
    }

    /// Whether preemption is enabled (count == 0).
    pub const fn preemptible(self) -> bool {
        self.raw == 0
    }

    /// Whether in any interrupt context (hardirq or softirq).
    pub const fn in_interrupt(self) -> bool {
        (self.raw & IRQ_MASK) != 0
    }

    /// Whether in softirq context.
    pub const fn in_softirq(self) -> bool {
        (self.raw & SOFTIRQ_MASK) != 0
    }

    /// Whether in hardirq context.
    pub const fn in_hardirq(self) -> bool {
        (self.raw & HARDIRQ_MASK) != 0
    }

    /// Whether in atomic context (preempt disabled or in IRQ).
    pub const fn in_atomic(self) -> bool {
        self.raw != 0
    }

    /// Whether scheduling is safe.
    pub const fn can_schedule(self) -> bool {
        self.raw == 0
    }

    /// Increment preempt-disable depth.
    pub fn preempt_disable(&mut self) -> Result<()> {
        let depth = self.preempt_depth();
        if depth >= MAX_PREEMPT_DEPTH {
            return Err(Error::InvalidArgument);
        }
        self.raw += 1;
        Ok(())
    }

    /// Decrement preempt-disable depth.
    pub fn preempt_enable(&mut self) -> Result<()> {
        let depth = self.preempt_depth();
        if depth == 0 {
            return Err(Error::InvalidArgument);
        }
        self.raw -= 1;
        Ok(())
    }

    /// Enter softirq context.
    pub fn softirq_enter(&mut self) -> Result<()> {
        let count = self.softirq_count();
        if count >= MAX_SOFTIRQ_DEPTH {
            return Err(Error::InvalidArgument);
        }
        self.raw += 1 << SOFTIRQ_SHIFT;
        Ok(())
    }

    /// Exit softirq context.
    pub fn softirq_exit(&mut self) -> Result<()> {
        let count = self.softirq_count();
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.raw -= 1 << SOFTIRQ_SHIFT;
        Ok(())
    }

    /// Disable softirq processing.
    pub fn local_bh_disable(&mut self) -> Result<()> {
        let count = self.softirq_disable_count();
        if count >= 15 {
            return Err(Error::InvalidArgument);
        }
        self.raw += 1 << SOFTIRQ_DISABLE_SHIFT;
        Ok(())
    }

    /// Enable softirq processing.
    pub fn local_bh_enable(&mut self) -> Result<()> {
        let count = self.softirq_disable_count();
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.raw -= 1 << SOFTIRQ_DISABLE_SHIFT;
        Ok(())
    }

    /// Enter hardirq context.
    pub fn hardirq_enter(&mut self) -> Result<()> {
        let count = self.hardirq_count();
        if count >= MAX_HARDIRQ_DEPTH {
            return Err(Error::InvalidArgument);
        }
        self.raw += 1 << HARDIRQ_SHIFT;
        Ok(())
    }

    /// Exit hardirq context.
    pub fn hardirq_exit(&mut self) -> Result<()> {
        let count = self.hardirq_count();
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.raw -= 1 << HARDIRQ_SHIFT;
        Ok(())
    }

    /// Enter NMI context.
    pub fn nmi_enter(&mut self) {
        self.raw |= NMI_MASK;
    }

    /// Exit NMI context.
    pub fn nmi_exit(&mut self) {
        self.raw &= !NMI_MASK;
    }
}

impl Default for PreemptCount {
    fn default() -> Self {
        Self::new()
    }
}

// ── PerCpuPreempt ───────────────────────────────────────────

/// Per-CPU preemption state.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuPreempt {
    /// CPU ID.
    cpu_id: u32,
    /// Preemption counter.
    count: PreemptCount,
    /// Whether initialized.
    initialized: bool,
    /// Number of preempt_disable calls.
    disable_calls: u64,
    /// Number of preempt_enable calls.
    enable_calls: u64,
    /// Number of times preemption was needed but blocked.
    need_resched_blocked: u64,
    /// Whether a reschedule is needed.
    need_resched: bool,
}

impl PerCpuPreempt {
    /// Create uninitialized per-CPU state.
    const fn new() -> Self {
        Self {
            cpu_id: 0,
            count: PreemptCount::new(),
            initialized: false,
            disable_calls: 0,
            enable_calls: 0,
            need_resched_blocked: 0,
            need_resched: false,
        }
    }

    /// CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Preemption count.
    pub fn count(&self) -> &PreemptCount {
        &self.count
    }

    /// Whether a reschedule is needed.
    pub fn need_resched(&self) -> bool {
        self.need_resched
    }
}

// ── PreemptStats ────────────────────────────────────────────

/// Preemption subsystem statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PreemptStats {
    /// Total preempt_disable calls.
    pub total_disables: u64,
    /// Total preempt_enable calls.
    pub total_enables: u64,
    /// Total softirq enters.
    pub softirq_enters: u64,
    /// Total hardirq enters.
    pub hardirq_enters: u64,
    /// Total NMI enters.
    pub nmi_enters: u64,
    /// Total blocked reschedules.
    pub blocked_reschedules: u64,
    /// Number of initialized CPUs.
    pub cpu_count: u32,
}

// ── PreemptSubsystem ────────────────────────────────────────

/// Global preemption control subsystem.
pub struct PreemptSubsystem {
    /// Per-CPU preemption state.
    per_cpu: [PerCpuPreempt; MAX_CPUS],
    /// Number of initialized CPUs.
    cpu_count: u32,
    /// Whether initialized.
    initialized: bool,
}

impl PreemptSubsystem {
    /// Create a new preemption subsystem.
    pub const fn new() -> Self {
        Self {
            per_cpu: [const { PerCpuPreempt::new() }; MAX_CPUS],
            cpu_count: 0,
            initialized: false,
        }
    }

    /// Initialize.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a CPU.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].cpu_id = cpu_id;
        self.per_cpu[idx].initialized = true;
        self.cpu_count += 1;
        Ok(())
    }

    /// Disable preemption on a CPU.
    pub fn preempt_disable(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.preempt_disable()?;
        self.per_cpu[idx].disable_calls += 1;
        Ok(())
    }

    /// Enable preemption on a CPU.
    pub fn preempt_enable(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.preempt_enable()?;
        self.per_cpu[idx].enable_calls += 1;

        // Check for pending reschedule.
        if self.per_cpu[idx].count.preemptible() && self.per_cpu[idx].need_resched {
            // In real kernel: call schedule().
            self.per_cpu[idx].need_resched = false;
        }
        Ok(())
    }

    /// Enter softirq context.
    pub fn softirq_enter(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.softirq_enter()
    }

    /// Exit softirq context.
    pub fn softirq_exit(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.softirq_exit()
    }

    /// Enter hardirq context.
    pub fn hardirq_enter(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.hardirq_enter()
    }

    /// Exit hardirq context.
    pub fn hardirq_exit(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.hardirq_exit()
    }

    /// Enter NMI context.
    pub fn nmi_enter(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.nmi_enter();
        Ok(())
    }

    /// Exit NMI context.
    pub fn nmi_exit(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].count.nmi_exit();
        Ok(())
    }

    /// Set the need_resched flag on a CPU.
    pub fn set_need_resched(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].need_resched = true;
        if !self.per_cpu[idx].count.preemptible() {
            self.per_cpu[idx].need_resched_blocked += 1;
        }
        Ok(())
    }

    /// Clear the need_resched flag.
    pub fn clear_need_resched(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].need_resched = false;
        Ok(())
    }

    /// Query the preemption state of a CPU.
    pub fn get_state(&self, cpu: u32) -> Result<&PerCpuPreempt> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[idx])
    }

    /// Whether a CPU is preemptible.
    pub fn is_preemptible(&self, cpu: u32) -> Result<bool> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[idx].count.preemptible())
    }

    /// Whether a CPU is in interrupt context.
    pub fn in_interrupt(&self, cpu: u32) -> Result<bool> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[idx].count.in_interrupt())
    }

    /// Get statistics.
    pub fn stats(&self) -> PreemptStats {
        let mut stats = PreemptStats::default();
        stats.cpu_count = self.cpu_count;

        for cpu in &self.per_cpu {
            if !cpu.initialized {
                continue;
            }
            stats.total_disables += cpu.disable_calls;
            stats.total_enables += cpu.enable_calls;
            stats.blocked_reschedules += cpu.need_resched_blocked;
        }
        stats
    }
}

impl Default for PreemptSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
