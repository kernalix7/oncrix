// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hard interrupt request (IRQ) management.
//!
//! Manages hardware interrupt contexts including preemption
//! counting, IRQ nesting depth tracking, and interrupt entry/exit
//! bookkeeping. Provides the hardirq context abstraction that
//! tracks whether the CPU is currently servicing a hardware
//! interrupt versus running in softirq or process context.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum nesting depth for hardware interrupts.
const MAX_IRQ_NESTING: u32 = 16;

/// Maximum number of IRQ statistics entries.
const MAX_IRQ_STATS: usize = 256;

/// Execution context of the current CPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecContext {
    /// Running in process/thread context.
    Process,
    /// Running in software interrupt context.
    SoftIrq,
    /// Running in hardware interrupt context.
    HardIrq,
    /// Running in NMI context.
    Nmi,
}

impl ExecContext {
    /// Returns whether the context allows sleeping.
    pub const fn can_sleep(&self) -> bool {
        matches!(self, Self::Process)
    }

    /// Returns whether the context is an interrupt context.
    pub const fn is_interrupt(&self) -> bool {
        matches!(self, Self::SoftIrq | Self::HardIrq | Self::Nmi)
    }
}

/// Per-CPU preemption and IRQ tracking state.
#[derive(Clone, Copy)]
pub struct HardirqState {
    /// CPU identifier.
    cpu_id: u32,
    /// Hardware IRQ nesting depth.
    hardirq_count: u32,
    /// Software IRQ nesting depth.
    softirq_count: u32,
    /// NMI nesting depth.
    nmi_count: u32,
    /// Preempt disable count.
    preempt_count: u32,
    /// Current execution context.
    context: ExecContext,
    /// Whether preemption is needed (set by scheduler).
    need_resched: bool,
    /// Timestamp of last hardirq entry.
    last_hardirq_entry_ns: u64,
    /// Timestamp of last hardirq exit.
    last_hardirq_exit_ns: u64,
    /// Total time spent in hardirq context.
    total_hardirq_time_ns: u64,
}

impl HardirqState {
    /// Creates a new hardirq state for a CPU.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            hardirq_count: 0,
            softirq_count: 0,
            nmi_count: 0,
            preempt_count: 0,
            context: ExecContext::Process,
            need_resched: false,
            last_hardirq_entry_ns: 0,
            last_hardirq_exit_ns: 0,
            total_hardirq_time_ns: 0,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the current execution context.
    pub const fn context(&self) -> ExecContext {
        self.context
    }

    /// Returns whether we are in hardirq context.
    pub const fn in_hardirq(&self) -> bool {
        self.hardirq_count > 0
    }

    /// Returns whether we are in softirq context.
    pub const fn in_softirq(&self) -> bool {
        self.softirq_count > 0
    }

    /// Returns whether we are in NMI context.
    pub const fn in_nmi(&self) -> bool {
        self.nmi_count > 0
    }

    /// Returns whether we are in any interrupt context.
    pub const fn in_interrupt(&self) -> bool {
        self.hardirq_count > 0 || self.softirq_count > 0 || self.nmi_count > 0
    }

    /// Returns the preempt disable count.
    pub const fn preempt_count(&self) -> u32 {
        self.preempt_count
    }

    /// Returns whether preemption is enabled.
    pub const fn preemptible(&self) -> bool {
        self.preempt_count == 0
            && self.hardirq_count == 0
            && self.softirq_count == 0
            && self.nmi_count == 0
    }

    /// Returns whether rescheduling is needed.
    pub const fn need_resched(&self) -> bool {
        self.need_resched
    }

    /// Returns the total hardirq time in nanoseconds.
    pub const fn total_hardirq_time_ns(&self) -> u64 {
        self.total_hardirq_time_ns
    }
}

impl Default for HardirqState {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-IRQ statistics.
#[derive(Clone, Copy)]
pub struct IrqStat {
    /// IRQ number.
    irq_num: u32,
    /// Number of times this IRQ has been serviced.
    count: u64,
    /// Total time spent handling this IRQ in nanoseconds.
    total_time_ns: u64,
    /// Maximum single-handler time in nanoseconds.
    max_time_ns: u64,
    /// Last servicing timestamp.
    last_time_ns: u64,
}

impl IrqStat {
    /// Creates a new IRQ statistics entry.
    pub const fn new() -> Self {
        Self {
            irq_num: 0,
            count: 0,
            total_time_ns: 0,
            max_time_ns: 0,
            last_time_ns: 0,
        }
    }

    /// Returns the IRQ number.
    pub const fn irq_num(&self) -> u32 {
        self.irq_num
    }

    /// Returns the number of times this IRQ was serviced.
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the maximum handler duration.
    pub const fn max_time_ns(&self) -> u64 {
        self.max_time_ns
    }

    /// Returns the average handler time.
    pub const fn avg_time_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_time_ns / self.count
        }
    }
}

impl Default for IrqStat {
    fn default() -> Self {
        Self::new()
    }
}

/// Hard IRQ management subsystem.
pub struct HardirqManager {
    /// Per-CPU hardirq state.
    cpu_states: [HardirqState; MAX_CPUS],
    /// Number of managed CPUs.
    cpu_count: usize,
    /// Per-IRQ statistics.
    irq_stats: [IrqStat; MAX_IRQ_STATS],
    /// Number of tracked IRQs.
    irq_count: usize,
    /// Global IRQ disable flag.
    irqs_disabled: bool,
}

impl HardirqManager {
    /// Creates a new hardirq manager.
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { HardirqState::new() }; MAX_CPUS],
            cpu_count: 0,
            irq_stats: [const { IrqStat::new() }; MAX_IRQ_STATS],
            irq_count: 0,
            irqs_disabled: false,
        }
    }

    /// Registers a CPU for IRQ tracking.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        self.cpu_states[self.cpu_count].cpu_id = cpu_id;
        self.cpu_count += 1;
        Ok(())
    }

    /// Enters hardirq context on a CPU.
    pub fn hardirq_enter(&mut self, cpu_id: u32, now_ns: u64) -> Result<()> {
        let state = self.find_cpu_mut(cpu_id)?;
        if state.hardirq_count >= MAX_IRQ_NESTING {
            return Err(Error::Busy);
        }
        state.hardirq_count += 1;
        state.context = ExecContext::HardIrq;
        state.last_hardirq_entry_ns = now_ns;
        Ok(())
    }

    /// Exits hardirq context on a CPU.
    pub fn hardirq_exit(&mut self, cpu_id: u32, now_ns: u64) -> Result<()> {
        let state = self.find_cpu_mut(cpu_id)?;
        if state.hardirq_count == 0 {
            return Err(Error::InvalidArgument);
        }
        state.hardirq_count -= 1;
        let elapsed = now_ns.saturating_sub(state.last_hardirq_entry_ns);
        state.total_hardirq_time_ns += elapsed;
        state.last_hardirq_exit_ns = now_ns;

        if state.hardirq_count == 0 {
            state.context = if state.softirq_count > 0 {
                ExecContext::SoftIrq
            } else {
                ExecContext::Process
            };
        }
        Ok(())
    }

    /// Disables preemption on a CPU.
    pub fn preempt_disable(&mut self, cpu_id: u32) -> Result<()> {
        let state = self.find_cpu_mut(cpu_id)?;
        state.preempt_count += 1;
        Ok(())
    }

    /// Enables preemption on a CPU.
    pub fn preempt_enable(&mut self, cpu_id: u32) -> Result<()> {
        let state = self.find_cpu_mut(cpu_id)?;
        if state.preempt_count == 0 {
            return Err(Error::InvalidArgument);
        }
        state.preempt_count -= 1;
        Ok(())
    }

    /// Records an IRQ servicing event.
    pub fn record_irq(&mut self, irq_num: u32, duration_ns: u64, now_ns: u64) -> Result<()> {
        // Find or create IRQ stat entry
        for i in 0..self.irq_count {
            if self.irq_stats[i].irq_num == irq_num {
                self.irq_stats[i].count += 1;
                self.irq_stats[i].total_time_ns += duration_ns;
                if duration_ns > self.irq_stats[i].max_time_ns {
                    self.irq_stats[i].max_time_ns = duration_ns;
                }
                self.irq_stats[i].last_time_ns = now_ns;
                return Ok(());
            }
        }
        if self.irq_count >= MAX_IRQ_STATS {
            return Err(Error::OutOfMemory);
        }
        self.irq_stats[self.irq_count] = IrqStat {
            irq_num,
            count: 1,
            total_time_ns: duration_ns,
            max_time_ns: duration_ns,
            last_time_ns: now_ns,
        };
        self.irq_count += 1;
        Ok(())
    }

    /// Returns the number of tracked CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns the number of tracked IRQs.
    pub const fn irq_count(&self) -> usize {
        self.irq_count
    }

    /// Finds a CPU state mutably by ID.
    fn find_cpu_mut(&mut self, cpu_id: u32) -> Result<&mut HardirqState> {
        self.cpu_states[..self.cpu_count]
            .iter_mut()
            .find(|c| c.cpu_id == cpu_id)
            .ok_or(Error::NotFound)
    }
}

impl Default for HardirqManager {
    fn default() -> Self {
        Self::new()
    }
}
