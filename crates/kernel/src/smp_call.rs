// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMP cross-CPU function calls.
//!
//! Provides the mechanism for one CPU to request another CPU (or a
//! set of CPUs) to execute a function. This is implemented via
//! inter-processor interrupts (IPIs) in real hardware; here we
//! model the queueing and dispatch logic.
//!
//! # Architecture
//!
//! ```text
//! SmpCallSubsystem
//! ├── per_cpu_queue: [CallQueue; MAX_CPUS]
//! │   ├── pending: [CallSingleData; MAX_PENDING]
//! │   └── head / tail / count
//! ├── stats: SmpCallStats
//! └── Functions:
//!     ├── smp_call_function_single(target, fn, data, wait)
//!     ├── smp_call_function_many(mask, fn, data, wait)
//!     └── process_pending(cpu)  — called on IPI receipt
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let mut smp = SmpCallSubsystem::new();
//! smp.init()?;
//! smp.call_function_single(1, my_fn, 42, true)?;
//! smp.process_pending(1)?;  // target CPU processes
//! ```
//!
//! # Reference
//!
//! Linux `kernel/smp.c`, `include/linux/smp.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum pending calls per CPU.
const MAX_PENDING: usize = 64;

/// Maximum mask words (matches cpu_mask).
const MASK_WORDS: usize = 4;

/// Bits per mask word.
const _BITS_PER_WORD: usize = 64;

// ── SmpCallFn ───────────────────────────────────────────────

/// Function type for SMP cross-CPU calls.
///
/// The `u64` parameter is an opaque data value.
pub type SmpCallFn = fn(u64);

// ── CallFlags ───────────────────────────────────────────────

/// Flags for a cross-CPU function call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallFlags(u32);

impl CallFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Caller waits for completion.
    pub const WAIT: Self = Self(1 << 0);
    /// Call is synchronous (blocks target).
    pub const SYNC: Self = Self(1 << 1);
    /// Call is from IRQ context.
    pub const IRQ: Self = Self(1 << 2);

    /// Create from raw value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Test if flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub const fn set(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ── CallState ───────────────────────────────────────────────

/// State of a single cross-CPU call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallState {
    /// Slot is free.
    #[default]
    Free,
    /// Call is pending delivery.
    Pending,
    /// Call is being executed on the target CPU.
    Running,
    /// Call has completed.
    Completed,
    /// Call failed.
    Failed,
}

// ── CallSingleData ──────────────────────────────────────────

/// A single cross-CPU function call request.
#[derive(Clone, Copy)]
pub struct CallSingleData {
    /// Callback function.
    func: Option<SmpCallFn>,
    /// Opaque data passed to the function.
    data: u64,
    /// Source CPU that originated the call.
    src_cpu: u32,
    /// Target CPU.
    dst_cpu: u32,
    /// Call flags.
    flags: CallFlags,
    /// Current state.
    state: CallState,
    /// Sequence number.
    seq: u64,
}

impl core::fmt::Debug for CallSingleData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallSingleData")
            .field("src_cpu", &self.src_cpu)
            .field("dst_cpu", &self.dst_cpu)
            .field("data", &self.data)
            .field("flags", &self.flags)
            .field("state", &self.state)
            .field("seq", &self.seq)
            .finish()
    }
}

impl CallSingleData {
    /// Create an empty call data.
    const fn empty() -> Self {
        Self {
            func: None,
            data: 0,
            src_cpu: 0,
            dst_cpu: 0,
            flags: CallFlags::NONE,
            state: CallState::Free,
            seq: 0,
        }
    }

    /// Whether this slot is free.
    pub fn is_free(&self) -> bool {
        self.state == CallState::Free
    }

    /// The call state.
    pub fn state(&self) -> CallState {
        self.state
    }

    /// The sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Source CPU.
    pub fn src_cpu(&self) -> u32 {
        self.src_cpu
    }

    /// Target CPU.
    pub fn dst_cpu(&self) -> u32 {
        self.dst_cpu
    }
}

// ── CallQueue ───────────────────────────────────────────────

/// Per-CPU queue of pending cross-CPU calls.
struct CallQueue {
    /// Pending calls.
    entries: [CallSingleData; MAX_PENDING],
    /// Ring buffer head.
    head: usize,
    /// Ring buffer tail.
    tail: usize,
    /// Number of pending calls.
    count: usize,
    /// Whether the queue is being processed.
    processing: bool,
    /// Sequence counter.
    next_seq: u64,
}

impl CallQueue {
    /// Create an empty queue.
    const fn new() -> Self {
        Self {
            entries: [const { CallSingleData::empty() }; MAX_PENDING],
            head: 0,
            tail: 0,
            count: 0,
            processing: false,
            next_seq: 1,
        }
    }

    /// Enqueue a call. Returns the sequence number.
    fn enqueue(
        &mut self,
        func: SmpCallFn,
        data: u64,
        src_cpu: u32,
        dst_cpu: u32,
        flags: CallFlags,
    ) -> Result<u64> {
        if self.count >= MAX_PENDING {
            return Err(Error::OutOfMemory);
        }
        let seq = self.next_seq;
        self.next_seq += 1;

        self.entries[self.tail] = CallSingleData {
            func: Some(func),
            data,
            src_cpu,
            dst_cpu,
            flags,
            state: CallState::Pending,
            seq,
        };
        self.tail = (self.tail + 1) % MAX_PENDING;
        self.count += 1;
        Ok(seq)
    }

    /// Dequeue the next pending call.
    fn dequeue(&mut self) -> Option<(SmpCallFn, u64, u64)> {
        if self.count == 0 {
            return None;
        }
        let entry = &self.entries[self.head];
        let func = entry.func?;
        let data = entry.data;
        let seq = entry.seq;

        self.entries[self.head] = CallSingleData::empty();
        self.head = (self.head + 1) % MAX_PENDING;
        self.count -= 1;
        Some((func, data, seq))
    }

    /// Number of pending calls.
    fn len(&self) -> usize {
        self.count
    }

    /// Whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── CpuMask (local) ────────────────────────────────────────

/// Simplified CPU bitmask for SMP targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmpCpuMask {
    /// Bit storage.
    bits: [u64; MASK_WORDS],
}

impl SmpCpuMask {
    /// Create an empty mask.
    pub const fn empty() -> Self {
        Self {
            bits: [0; MASK_WORDS],
        }
    }

    /// Set a CPU.
    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }

    /// Test a CPU.
    pub fn test(&self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        (self.bits[cpu / 64] & (1u64 << (cpu % 64))) != 0
    }

    /// Count set CPUs.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }
}

impl Default for SmpCpuMask {
    fn default() -> Self {
        Self::empty()
    }
}

// ── SmpCallStats ────────────────────────────────────────────

/// Statistics for the SMP call subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmpCallStats {
    /// Total single-CPU calls issued.
    pub single_calls: u64,
    /// Total many-CPU calls issued.
    pub many_calls: u64,
    /// Total individual IPIs sent.
    pub ipis_sent: u64,
    /// Total calls processed.
    pub calls_processed: u64,
    /// Total calls that failed to enqueue.
    pub enqueue_failures: u64,
}

impl SmpCallStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            single_calls: 0,
            many_calls: 0,
            ipis_sent: 0,
            calls_processed: 0,
            enqueue_failures: 0,
        }
    }
}

// ── SmpCallSubsystem ────────────────────────────────────────

/// Cross-CPU function call subsystem.
pub struct SmpCallSubsystem {
    /// Per-CPU call queues.
    queues: [CallQueue; MAX_CPUS],
    /// Online CPU bitmap.
    online: SmpCpuMask,
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Statistics.
    stats: SmpCallStats,
    /// Whether initialized.
    initialized: bool,
}

impl SmpCallSubsystem {
    /// Create a new SMP call subsystem.
    pub const fn new() -> Self {
        Self {
            queues: [const { CallQueue::new() }; MAX_CPUS],
            online: SmpCpuMask::empty(),
            nr_cpus: 0,
            stats: SmpCallStats::new(),
            initialized: false,
        }
    }

    /// Initialize the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a CPU as online.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.online.test(idx) {
            return Err(Error::AlreadyExists);
        }
        self.online.set(idx);
        self.nr_cpus += 1;
        Ok(())
    }

    /// Send a function call to a single CPU.
    ///
    /// # Arguments
    ///
    /// * `src_cpu` - Calling CPU.
    /// * `dst_cpu` - Target CPU.
    /// * `func` - Function to execute on target.
    /// * `data` - Opaque data passed to function.
    /// * `wait` - Whether to wait for completion.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if target CPU is out of range or offline.
    /// - `OutOfMemory` if the target queue is full.
    pub fn call_function_single(
        &mut self,
        src_cpu: u32,
        dst_cpu: u32,
        func: SmpCallFn,
        data: u64,
        wait: bool,
    ) -> Result<u64> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let idx = dst_cpu as usize;
        if idx >= MAX_CPUS || !self.online.test(idx) {
            return Err(Error::InvalidArgument);
        }

        let mut flags = CallFlags::NONE;
        if wait {
            flags = flags.set(CallFlags::WAIT);
        }

        match self.queues[idx].enqueue(func, data, src_cpu, dst_cpu, flags) {
            Ok(seq) => {
                self.stats.single_calls += 1;
                self.stats.ipis_sent += 1;
                // In real kernel: send IPI to dst_cpu.
                arch_send_ipi(dst_cpu);
                Ok(seq)
            }
            Err(e) => {
                self.stats.enqueue_failures += 1;
                Err(e)
            }
        }
    }

    /// Send a function call to multiple CPUs.
    ///
    /// Iterates the mask and enqueues the call on each target CPU.
    /// Returns the number of CPUs that were successfully targeted.
    pub fn call_function_many(
        &mut self,
        src_cpu: u32,
        mask: &SmpCpuMask,
        func: SmpCallFn,
        data: u64,
        wait: bool,
    ) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        let mut flags = CallFlags::NONE;
        if wait {
            flags = flags.set(CallFlags::WAIT);
        }

        let mut targeted = 0u32;
        for cpu in 0..MAX_CPUS {
            if !mask.test(cpu) || !self.online.test(cpu) {
                continue;
            }
            if cpu == src_cpu as usize {
                continue; // Skip self.
            }
            match self.queues[cpu].enqueue(func, data, src_cpu, cpu as u32, flags) {
                Ok(_) => {
                    targeted += 1;
                    self.stats.ipis_sent += 1;
                    arch_send_ipi(cpu as u32);
                }
                Err(_) => {
                    self.stats.enqueue_failures += 1;
                }
            }
        }

        self.stats.many_calls += 1;
        Ok(targeted)
    }

    /// Process pending calls on the current CPU.
    ///
    /// Called from the IPI handler on the target CPU.
    /// Returns the number of calls processed.
    pub fn process_pending(&mut self, cpu: u32) -> Result<u64> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.queues[idx].processing {
            return Err(Error::Busy);
        }

        self.queues[idx].processing = true;
        let mut count = 0u64;

        while let Some((func, data, _seq)) = self.queues[idx].dequeue() {
            func(data);
            count += 1;
            self.stats.calls_processed += 1;
        }

        self.queues[idx].processing = false;
        Ok(count)
    }

    /// Return the number of pending calls on a CPU.
    pub fn pending_count(&self, cpu: u32) -> Result<usize> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.queues[idx].len())
    }

    /// Whether a CPU has pending calls.
    pub fn has_pending(&self, cpu: u32) -> Result<bool> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(!self.queues[idx].is_empty())
    }

    /// Return statistics.
    pub fn stats(&self) -> &SmpCallStats {
        &self.stats
    }

    /// Number of online CPUs.
    pub fn nr_cpus(&self) -> u32 {
        self.nr_cpus
    }
}

impl Default for SmpCallSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Architecture hook ───────────────────────────────────────

/// Send an IPI to the target CPU (placeholder).
fn arch_send_ipi(_cpu: u32) {
    // In real kernel: write APIC ICR (x86) or GIC SGI (ARM).
}
