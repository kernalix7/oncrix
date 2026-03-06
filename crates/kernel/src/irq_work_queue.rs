// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IRQ work queue — deferred work from interrupt/NMI context.
//!
//! The IRQ work queue allows code running in hard interrupt or NMI
//! context to schedule work that executes at the next safe point
//! (typically in softirq context or a self-IPI).
//!
//! # Reference
//!
//! Linux `kernel/irq_work.c`, `include/linux/irq_work.h`.

use oncrix_lib::{Error, Result};

const MAX_WORK_ITEMS: usize = 512;
const MAX_CPUS: usize = 64;
const MAX_PER_CPU_QUEUE: usize = 32;

/// State of an IRQ work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkState {
    /// Slot is free.
    Free = 0,
    /// Work item is registered but not queued.
    Idle = 1,
    /// Work item is queued for execution.
    Queued = 2,
    /// Work item is currently executing.
    Running = 3,
}

/// Flags for IRQ work items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkFlags {
    /// Normal IRQ work (run in softirq/self-IPI context).
    Normal = 0,
    /// Lazy IRQ work (can be batched with tick processing).
    Lazy = 1,
    /// Hard IRQ work (must run before returning from interrupt).
    Hard = 2,
}

/// IRQ work callback function.
pub type IrqWorkFn = fn(u64);

/// An IRQ work item.
#[derive(Debug, Clone, Copy)]
pub struct IrqWorkItem {
    /// Work item ID.
    pub work_id: u64,
    /// Callback function.
    pub handler: Option<IrqWorkFn>,
    /// Opaque data.
    pub data: u64,
    /// Current state.
    pub state: WorkState,
    /// Flags.
    pub flags: WorkFlags,
    /// Number of times executed.
    pub exec_count: u64,
}

impl IrqWorkItem {
    const fn empty() -> Self {
        Self {
            work_id: 0,
            handler: None,
            data: 0,
            state: WorkState::Free,
            flags: WorkFlags::Normal,
            exec_count: 0,
        }
    }

    /// Returns `true` if the slot is in use.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, WorkState::Free)
    }
}

/// Per-CPU IRQ work queue.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuIrqQueue {
    /// Queued work item indices.
    pub queue: [u16; MAX_PER_CPU_QUEUE],
    /// Number of queued items.
    pub count: usize,
    /// Total items processed.
    pub processed: u64,
    /// Whether a self-IPI is pending for this CPU.
    pub ipi_pending: bool,
}

impl PerCpuIrqQueue {
    const fn new() -> Self {
        Self {
            queue: [0u16; MAX_PER_CPU_QUEUE],
            count: 0,
            processed: 0,
            ipi_pending: false,
        }
    }
}

/// Statistics for the IRQ work queue.
#[derive(Debug, Clone, Copy)]
pub struct IrqWorkQueueStats {
    /// Total work items queued.
    pub total_queued: u64,
    /// Total work items executed.
    pub total_executed: u64,
    /// Total self-IPIs raised.
    pub total_ipis: u64,
    /// Total lazy items deferred to tick.
    pub total_lazy_deferred: u64,
}

impl IrqWorkQueueStats {
    const fn new() -> Self {
        Self {
            total_queued: 0,
            total_executed: 0,
            total_ipis: 0,
            total_lazy_deferred: 0,
        }
    }
}

/// Top-level IRQ work queue subsystem.
pub struct IrqWorkQueue {
    /// Registered work items.
    items: [IrqWorkItem; MAX_WORK_ITEMS],
    /// Per-CPU queues.
    per_cpu: [PerCpuIrqQueue; MAX_CPUS],
    /// Statistics.
    stats: IrqWorkQueueStats,
    /// Next work ID.
    next_work_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for IrqWorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqWorkQueue {
    /// Create a new IRQ work queue.
    pub const fn new() -> Self {
        Self {
            items: [const { IrqWorkItem::empty() }; MAX_WORK_ITEMS],
            per_cpu: [const { PerCpuIrqQueue::new() }; MAX_CPUS],
            stats: IrqWorkQueueStats::new(),
            next_work_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a work item.
    pub fn register(&mut self, handler: IrqWorkFn, data: u64, flags: WorkFlags) -> Result<u64> {
        let slot = self
            .items
            .iter()
            .position(|i| matches!(i.state, WorkState::Free))
            .ok_or(Error::OutOfMemory)?;

        let work_id = self.next_work_id;
        self.next_work_id += 1;

        self.items[slot] = IrqWorkItem {
            work_id,
            handler: Some(handler),
            data,
            state: WorkState::Idle,
            flags,
            exec_count: 0,
        };
        Ok(work_id)
    }

    /// Queue a work item on a CPU.
    pub fn queue(&mut self, work_id: u64, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_item(work_id)?;

        if matches!(self.items[slot].state, WorkState::Queued) {
            return Ok(()); // Already queued.
        }

        self.items[slot].state = WorkState::Queued;

        let idx = self.per_cpu[cpu].count;
        if idx < MAX_PER_CPU_QUEUE {
            self.per_cpu[cpu].queue[idx] = slot as u16;
            self.per_cpu[cpu].count += 1;
        }

        // Signal IPI for non-lazy work.
        if !matches!(self.items[slot].flags, WorkFlags::Lazy) {
            self.per_cpu[cpu].ipi_pending = true;
            self.stats.total_ipis += 1;
        } else {
            self.stats.total_lazy_deferred += 1;
        }

        self.stats.total_queued += 1;
        Ok(())
    }

    /// Process all queued work on a CPU.
    pub fn process(&mut self, cpu: usize) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let count = self.per_cpu[cpu].count;
        let mut executed = 0usize;

        for i in 0..count {
            let slot = self.per_cpu[cpu].queue[i] as usize;
            if slot >= MAX_WORK_ITEMS {
                continue;
            }
            if !matches!(self.items[slot].state, WorkState::Queued) {
                continue;
            }

            self.items[slot].state = WorkState::Running;
            if let Some(handler) = self.items[slot].handler {
                let data = self.items[slot].data;
                handler(data);
            }
            self.items[slot].exec_count += 1;
            self.items[slot].state = WorkState::Idle;
            executed += 1;
        }

        self.per_cpu[cpu].count = 0;
        self.per_cpu[cpu].ipi_pending = false;
        self.per_cpu[cpu].processed += executed as u64;
        self.stats.total_executed += executed as u64;
        Ok(executed)
    }

    /// Unregister a work item.
    pub fn unregister(&mut self, work_id: u64) -> Result<()> {
        let slot = self.find_item(work_id)?;
        if matches!(
            self.items[slot].state,
            WorkState::Queued | WorkState::Running
        ) {
            return Err(Error::Busy);
        }
        self.items[slot] = IrqWorkItem::empty();
        Ok(())
    }

    /// Return statistics.
    pub fn stats(&self) -> IrqWorkQueueStats {
        self.stats
    }

    /// Return the number of registered work items.
    pub fn registered_count(&self) -> usize {
        self.items.iter().filter(|i| i.is_active()).count()
    }

    /// Check if a CPU has pending work.
    pub fn has_pending(&self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu].count > 0)
    }

    fn find_item(&self, work_id: u64) -> Result<usize> {
        self.items
            .iter()
            .position(|i| i.is_active() && i.work_id == work_id)
            .ok_or(Error::NotFound)
    }
}
