// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IRQ-safe deferred work queues.
//!
//! `irq_work` provides a mechanism for queuing small work items from
//! contexts where most kernel services are unavailable — in particular,
//! from NMI handlers and hard-interrupt handlers.  Once queued, items
//! are processed at the next safe point (typically the return-from-
//! interrupt path or a self-IPI).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   IrqWorkSubsystem                           │
//! │                                                              │
//! │  IrqWorkQueue[0..MAX_CPUS]  (per-CPU work queues)           │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  entries: [IrqWorkEntry; MAX_ENTRIES_PER_CPU]          │  │
//! │  │  head / tail / count                                   │  │
//! │  │  processing: bool                                      │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  IrqWorkStats (global counters)                              │
//! │  - queued, processed, self_ipi_count, overflow_count         │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/irq_work.c`, `include/linux/irq_work.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Maximum entries per CPU queue.
const MAX_ENTRIES_PER_CPU: usize = 64;

// ══════════════════════════════════════════════════════════════
// IrqWorkFlags — work item state machine
// ══════════════════════════════════════════════════════════════

/// Bitflags that track the lifecycle of an [`IrqWorkEntry`].
///
/// Multiple flags may be set simultaneously.  The transition order is:
/// free → PENDING → BUSY → (callback runs) → free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqWorkFlags(u32);

impl IrqWorkFlags {
    /// No flags set — entry is free.
    pub const NONE: Self = Self(0);
    /// Work has been queued but not yet claimed for execution.
    pub const PENDING: Self = Self(1 << 0);
    /// Work is currently being executed.
    pub const BUSY: Self = Self(1 << 1);
    /// The entry has been claimed by a CPU for execution.
    pub const CLAIM: Self = Self(1 << 2);
    /// The entry was raised from IRQ context (needs self-IPI).
    pub const IRQ: Self = Self(1 << 3);

    /// Create flags from a raw u32 value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw u32 value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Test whether the given flag bit(s) are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set the given flag bit(s).
    pub const fn set(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Clear the given flag bit(s).
    pub const fn clear(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns `true` if no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ══════════════════════════════════════════════════════════════
// IrqWorkFn — callback signature
// ══════════════════════════════════════════════════════════════

/// Callback function type for irq work items.
///
/// The `u64` parameter is an opaque context value supplied when the
/// work item was queued.
pub type IrqWorkFn = fn(u64);

// ══════════════════════════════════════════════════════════════
// IrqWorkEntry — single work item
// ══════════════════════════════════════════════════════════════

/// A single irq-work item stored in a per-CPU queue.
#[derive(Clone, Copy)]
pub struct IrqWorkEntry {
    /// Callback to invoke when the work is processed.
    pub callback: Option<IrqWorkFn>,
    /// Opaque context passed to the callback.
    pub context: u64,
    /// Lifecycle flags.
    pub flags: IrqWorkFlags,
    /// Sequence number for ordering / debugging.
    pub seq: u64,
}

impl core::fmt::Debug for IrqWorkEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrqWorkEntry")
            .field("context", &self.context)
            .field("flags", &self.flags)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl IrqWorkEntry {
    /// Create an empty (free) work entry.
    const fn empty() -> Self {
        Self {
            callback: None,
            context: 0,
            flags: IrqWorkFlags::NONE,
            seq: 0,
        }
    }

    /// Returns `true` if this entry is free.
    pub const fn is_free(&self) -> bool {
        self.flags.is_empty() && self.callback.is_none()
    }

    /// Returns `true` if this entry is pending execution.
    pub const fn is_pending(&self) -> bool {
        self.flags.contains(IrqWorkFlags::PENDING)
    }

    /// Returns `true` if this entry is currently executing.
    pub const fn is_busy(&self) -> bool {
        self.flags.contains(IrqWorkFlags::BUSY)
    }
}

// ══════════════════════════════════════════════════════════════
// IrqWorkQueue — per-CPU circular queue
// ══════════════════════════════════════════════════════════════

/// Per-CPU circular queue of irq work items.
#[derive(Debug)]
pub struct IrqWorkQueue {
    /// Fixed-size ring buffer of work entries.
    entries: [IrqWorkEntry; MAX_ENTRIES_PER_CPU],
    /// Index of the next entry to dequeue.
    head: usize,
    /// Index of the next free slot for enqueue.
    tail: usize,
    /// Number of queued items.
    count: usize,
    /// `true` while this queue is being drained.
    processing: bool,
    /// Monotonically increasing sequence counter.
    next_seq: u64,
}

impl IrqWorkQueue {
    /// Create an empty queue.
    const fn new() -> Self {
        Self {
            entries: [const { IrqWorkEntry::empty() }; MAX_ENTRIES_PER_CPU],
            head: 0,
            tail: 0,
            count: 0,
            processing: false,
            next_seq: 1,
        }
    }

    /// Returns `true` if the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` if the queue is full.
    pub const fn is_full(&self) -> bool {
        self.count >= MAX_ENTRIES_PER_CPU
    }

    /// Number of queued items.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Enqueue a work item.  Returns the assigned sequence number.
    fn enqueue(&mut self, callback: IrqWorkFn, context: u64, from_irq: bool) -> Result<u64> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let seq = self.next_seq;
        self.next_seq += 1;

        let mut flags = IrqWorkFlags::PENDING;
        if from_irq {
            flags = flags.set(IrqWorkFlags::IRQ);
        }

        self.entries[self.tail] = IrqWorkEntry {
            callback: Some(callback),
            context,
            flags,
            seq,
        };
        self.tail = (self.tail + 1) % MAX_ENTRIES_PER_CPU;
        self.count += 1;
        Ok(seq)
    }

    /// Dequeue the next pending work item, if any.
    fn dequeue(&mut self) -> Option<(IrqWorkFn, u64)> {
        if self.is_empty() {
            return None;
        }
        let entry = &self.entries[self.head];
        let callback = entry.callback?;
        let context = entry.context;

        // Mark entry as busy, then free it after we've extracted
        // the callback and context.
        self.entries[self.head] = IrqWorkEntry::empty();
        self.head = (self.head + 1) % MAX_ENTRIES_PER_CPU;
        self.count -= 1;
        Some((callback, context))
    }
}

// ══════════════════════════════════════════════════════════════
// IrqWorkStats — global statistics
// ══════════════════════════════════════════════════════════════

/// Global irq-work statistics.
#[derive(Debug, Clone, Copy)]
pub struct IrqWorkStats {
    /// Total work items queued.
    pub queued: u64,
    /// Total work items processed (callback invoked).
    pub processed: u64,
    /// Number of self-IPI raises (arch hook invocations).
    pub self_ipi_count: u64,
    /// Number of queue overflows (work dropped).
    pub overflow_count: u64,
}

impl IrqWorkStats {
    /// Create zero-initialised stats.
    const fn new() -> Self {
        Self {
            queued: 0,
            processed: 0,
            self_ipi_count: 0,
            overflow_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// IrqWorkSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level irq-work subsystem managing per-CPU queues.
pub struct IrqWorkSubsystem {
    /// Per-CPU work queues.
    queues: [IrqWorkQueue; MAX_CPUS],
    /// Global statistics.
    stats: IrqWorkStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for IrqWorkSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqWorkSubsystem {
    /// Create a new, uninitialised irq-work subsystem.
    pub const fn new() -> Self {
        Self {
            queues: [const { IrqWorkQueue::new() }; MAX_CPUS],
            stats: IrqWorkStats::new(),
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

    // ── Queueing work ────────────────────────────────────────

    /// Queue a work item on the specified CPU.
    ///
    /// # Arguments
    ///
    /// * `cpu` — target CPU index.
    /// * `callback` — function to invoke.
    /// * `context` — opaque value passed to `callback`.
    /// * `from_irq` — `true` if called from IRQ context.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range or subsystem
    ///   is not initialised.
    /// - `OutOfMemory` if the per-CPU queue is full.
    pub fn queue_work(
        &mut self,
        cpu: usize,
        callback: IrqWorkFn,
        context: u64,
        from_irq: bool,
    ) -> Result<u64> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        match self.queues[cpu].enqueue(callback, context, from_irq) {
            Ok(seq) => {
                self.stats.queued += 1;
                if from_irq {
                    // In a real kernel we would send a self-IPI here
                    // to ensure the work is processed promptly.
                    arch_irq_work_raise(cpu);
                    self.stats.self_ipi_count += 1;
                }
                Ok(seq)
            }
            Err(e) => {
                self.stats.overflow_count += 1;
                Err(e)
            }
        }
    }

    /// Queue work on the local CPU (convenience wrapper).
    pub fn queue_work_local(
        &mut self,
        local_cpu: usize,
        callback: IrqWorkFn,
        context: u64,
        from_irq: bool,
    ) -> Result<u64> {
        self.queue_work(local_cpu, callback, context, from_irq)
    }

    // ── Processing work ──────────────────────────────────────

    /// Process all queued work on the specified CPU.
    ///
    /// Returns the number of work items executed.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    /// - `Busy` if the queue is already being processed.
    pub fn process_work(&mut self, cpu: usize) -> Result<u64> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.queues[cpu].processing {
            return Err(Error::Busy);
        }

        self.queues[cpu].processing = true;
        let mut count = 0u64;

        while let Some((callback, context)) = self.queues[cpu].dequeue() {
            callback(context);
            count += 1;
            self.stats.processed += 1;
        }

        self.queues[cpu].processing = false;
        Ok(count)
    }

    /// Synchronously drain all work on the given CPU, blocking
    /// until the queue is empty.
    ///
    /// In a preemptible kernel this would spin-wait if another
    /// context is already processing.  Here we simply process
    /// once and report.
    pub fn sync_work(&mut self, cpu: usize) -> Result<u64> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        // If already processing, return WouldBlock rather than
        // spinning.
        if self.queues[cpu].processing {
            return Err(Error::WouldBlock);
        }
        self.process_work(cpu)
    }

    // ── Query / diagnostics ──────────────────────────────────

    /// Return global statistics.
    pub fn stats(&self) -> IrqWorkStats {
        self.stats
    }

    /// Return the number of queued items on the given CPU.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn queue_len(&self, cpu: usize) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.queues[cpu].len())
    }

    /// Return `true` if the given CPU's queue is empty.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn is_empty(&self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.queues[cpu].is_empty())
    }

    /// Return `true` if the given CPU's queue is being processed.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn is_processing(&self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.queues[cpu].processing)
    }

    /// Dump per-CPU queue depths.
    pub fn dump_queue_depths(&self) -> [usize; MAX_CPUS] {
        let mut depths = [0usize; MAX_CPUS];
        for (i, queue) in self.queues.iter().enumerate() {
            depths[i] = queue.len();
        }
        depths
    }
}

// ══════════════════════════════════════════════════════════════
// Architecture hook — self-IPI placeholder
// ══════════════════════════════════════════════════════════════

/// Architecture-specific hook to raise a self-IPI on the target CPU.
///
/// In a real kernel this would write to the APIC ICR register (x86)
/// or the GIC SGI register (ARM) to interrupt the target CPU so it
/// processes queued irq-work promptly.
///
/// This is a no-op placeholder in the current implementation.
fn arch_irq_work_raise(_cpu: usize) {
    // TODO: Implement per-arch self-IPI.
    // x86: write APIC_ICR with SELF | FIXED | IRQ_WORK_VECTOR
    // ARM: write GICD_SGIR with target CPU mask
}
