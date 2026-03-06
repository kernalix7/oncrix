// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMP cross-CPU function call via IPI.
//!
//! Allows one CPU to request a specific CPU (or a set of CPUs) to
//! execute a function. The request is delivered via an inter-processor
//! interrupt (IPI). Both synchronous (caller waits for completion)
//! and asynchronous (fire-and-forget) modes are supported.
//!
//! # Architecture
//!
//! ```text
//! SmpCallFuncSubsystem
//! ├── per_cpu_queues[MAX_CPUS]
//! │   ├── csd_ring[CSD_RING_SIZE]   call-single-data entries
//! │   ├── head / tail / count
//! │   └── lock_flag                 CSD lock state
//! ├── stats: SmpCallFuncStats
//! └── Methods:
//!     ├── call_function_single(target, fn, data, wait)
//!     ├── call_function_many(mask, fn, data, wait)
//!     ├── handle_ipi(cpu)           IPI handler (target side)
//!     ├── csd_lock(cpu)
//!     └── csd_unlock(cpu)
//! ```
//!
//! # CSD (Call Single Data)
//!
//! Each enqueued function call is wrapped in a CSD entry that holds
//! the function pointer, opaque data argument, completion flag, and
//! source CPU. The target CPU dequeues and invokes CSD entries when
//! it receives the IPI.
//!
//! # Reference
//!
//! Linux `kernel/smp.c` (`smp_call_function_single`,
//! `smp_call_function_many`, `flush_smp_call_function_queue`),
//! `include/linux/smp.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// CSD ring entries per CPU.
const CSD_RING_SIZE: usize = 64;

/// CSD ring mask for fast modulo.
const CSD_RING_MASK: usize = CSD_RING_SIZE - 1;

/// CPU mask words (256 CPUs / 64 bits).
const MASK_WORDS: usize = 4;

/// Bits per mask word.
const BITS_PER_WORD: usize = 64;

// ══════════════════════════════════════════════════════════════
// SmpCallFn
// ══════════════════════════════════════════════════════════════

/// Function type for cross-CPU calls.
///
/// The `u64` parameter is an opaque data value passed by the caller.
pub type SmpCallFn = fn(u64);

// ══════════════════════════════════════════════════════════════
// CsdState
// ══════════════════════════════════════════════════════════════

/// State of a CSD (Call Single Data) entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CsdState {
    /// Slot is free.
    #[default]
    Free = 0,
    /// Entry is enqueued and awaiting execution.
    Pending = 1,
    /// Entry is currently being executed by the target CPU.
    Running = 2,
    /// Execution completed.
    Completed = 3,
}

// ══════════════════════════════════════════════════════════════
// CsdEntry
// ══════════════════════════════════════════════════════════════

/// A single call-single-data entry.
#[derive(Clone, Copy)]
struct CsdEntry {
    /// Function to execute on the target CPU.
    func: Option<SmpCallFn>,
    /// Opaque data argument.
    data: u64,
    /// CPU that originated the call.
    source_cpu: u32,
    /// Whether the caller is waiting for completion.
    wait: bool,
    /// Current state.
    state: CsdState,
    /// Monotonic sequence number.
    seq: u64,
}

impl CsdEntry {
    const fn empty() -> Self {
        Self {
            func: None,
            data: 0,
            source_cpu: 0,
            wait: false,
            state: CsdState::Free,
            seq: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CpuMask
// ══════════════════════════════════════════════════════════════

/// Bitmask identifying a set of CPUs.
#[derive(Debug, Clone, Copy)]
pub struct CpuMask {
    /// Mask words.
    words: [u64; MASK_WORDS],
}

impl CpuMask {
    /// Empty mask (no CPUs selected).
    pub const fn empty() -> Self {
        Self {
            words: [0u64; MASK_WORDS],
        }
    }

    /// Set a CPU bit.
    pub fn set(&mut self, cpu: u32) {
        let word = (cpu as usize) / BITS_PER_WORD;
        let bit = (cpu as usize) % BITS_PER_WORD;
        if word < MASK_WORDS {
            self.words[word] |= 1u64 << bit;
        }
    }

    /// Clear a CPU bit.
    pub fn clear(&mut self, cpu: u32) {
        let word = (cpu as usize) / BITS_PER_WORD;
        let bit = (cpu as usize) % BITS_PER_WORD;
        if word < MASK_WORDS {
            self.words[word] &= !(1u64 << bit);
        }
    }

    /// Test whether a CPU bit is set.
    pub fn test(&self, cpu: u32) -> bool {
        let word = (cpu as usize) / BITS_PER_WORD;
        let bit = (cpu as usize) % BITS_PER_WORD;
        if word < MASK_WORDS {
            (self.words[word] & (1u64 << bit)) != 0
        } else {
            false
        }
    }

    /// Count the number of set bits.
    pub fn count(&self) -> u32 {
        let mut n = 0u32;
        for w in &self.words {
            n += w.count_ones();
        }
        n
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuCsdQueue
// ══════════════════════════════════════════════════════════════

/// Per-CPU ring of pending CSD entries.
struct PerCpuCsdQueue {
    /// Circular CSD ring.
    ring: [CsdEntry; CSD_RING_SIZE],
    /// Read head (next to process).
    head: usize,
    /// Write tail (next to insert).
    tail: usize,
    /// Number of pending (non-free) entries.
    count: u32,
    /// Whether the CSD lock is held (prevents concurrent
    /// modification of this queue).
    locked: bool,
    /// Total entries enqueued on this CPU.
    total_enqueued: u64,
    /// Total entries executed on this CPU.
    total_executed: u64,
    /// IPI triggers received.
    ipi_count: u64,
}

impl PerCpuCsdQueue {
    const fn new() -> Self {
        Self {
            ring: [const { CsdEntry::empty() }; CSD_RING_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            locked: false,
            total_enqueued: 0,
            total_executed: 0,
            ipi_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SmpCallFuncStats
// ══════════════════════════════════════════════════════════════

/// Aggregate statistics for the SMP call function subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmpCallFuncStats {
    /// Total single-CPU calls issued.
    pub single_calls: u64,
    /// Total many-CPU calls issued.
    pub many_calls: u64,
    /// Total individual CSD entries enqueued.
    pub csd_enqueued: u64,
    /// Total CSD entries executed.
    pub csd_executed: u64,
    /// IPIs triggered.
    pub ipis_sent: u64,
    /// IPI handler invocations.
    pub ipis_received: u64,
    /// Synchronous waits completed.
    pub sync_waits: u64,
    /// Enqueue failures (queue full).
    pub enqueue_failures: u64,
}

// ══════════════════════════════════════════════════════════════
// SmpCallFuncSubsystem
// ══════════════════════════════════════════════════════════════

/// Cross-CPU function call subsystem using IPI delivery.
pub struct SmpCallFuncSubsystem {
    /// Per-CPU CSD queues.
    queues: [PerCpuCsdQueue; MAX_CPUS],
    /// Number of online CPUs.
    online_cpus: u32,
    /// Monotonic sequence counter.
    next_seq: u64,
    /// Stats.
    stats: SmpCallFuncStats,
    /// Initialised flag.
    initialised: bool,
}

impl Default for SmpCallFuncSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SmpCallFuncSubsystem {
    /// Create a new, uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            queues: [const { PerCpuCsdQueue::new() }; MAX_CPUS],
            online_cpus: 1,
            next_seq: 1,
            stats: SmpCallFuncStats {
                single_calls: 0,
                many_calls: 0,
                csd_enqueued: 0,
                csd_executed: 0,
                ipis_sent: 0,
                ipis_received: 0,
                sync_waits: 0,
                enqueue_failures: 0,
            },
            initialised: false,
        }
    }

    /// Initialise the subsystem with the given CPU count.
    pub fn init(&mut self, online_cpus: u32) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        if online_cpus == 0 || online_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.online_cpus = online_cpus;
        self.initialised = true;
        Ok(())
    }

    /// Send a function call to a single target CPU.
    ///
    /// `source_cpu` is the calling CPU, `target_cpu` is the
    /// destination. If `wait` is true, the function models a
    /// synchronous call (the CSD is immediately processed).
    pub fn call_function_single(
        &mut self,
        source_cpu: u32,
        target_cpu: u32,
        func: SmpCallFn,
        data: u64,
        wait: bool,
    ) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        if target_cpu >= self.online_cpus || (target_cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.stats.single_calls += 1;

        self.enqueue_csd(target_cpu, source_cpu, func, data, wait)?;

        // Model the IPI trigger.
        self.stats.ipis_sent += 1;

        // For synchronous calls, process immediately.
        if wait {
            self.handle_ipi(target_cpu)?;
            self.stats.sync_waits += 1;
        }

        Ok(())
    }

    /// Send a function call to multiple CPUs identified by a mask.
    ///
    /// The calling CPU (`source_cpu`) is automatically excluded
    /// from the mask.
    pub fn call_function_many(
        &mut self,
        source_cpu: u32,
        mask: &CpuMask,
        func: SmpCallFn,
        data: u64,
        wait: bool,
    ) -> Result<u32> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }

        self.stats.many_calls += 1;

        let mut enqueued: u32 = 0;

        for cpu in 0..self.online_cpus {
            if cpu == source_cpu {
                continue;
            }
            if !mask.test(cpu) {
                continue;
            }
            match self.enqueue_csd(cpu, source_cpu, func, data, wait) {
                Ok(()) => {
                    self.stats.ipis_sent += 1;
                    enqueued += 1;
                }
                Err(_) => {
                    // Queue was full for this CPU; skip.
                    self.stats.enqueue_failures += 1;
                }
            }
        }

        // For synchronous calls, process all target CPUs.
        if wait {
            for cpu in 0..self.online_cpus {
                if cpu == source_cpu || !mask.test(cpu) {
                    continue;
                }
                let _ = self.handle_ipi(cpu);
            }
            self.stats.sync_waits += 1;
        }

        Ok(enqueued)
    }

    /// IPI handler — invoked on the target CPU when the IPI fires.
    ///
    /// Dequeues and executes all pending CSD entries on `cpu`.
    /// Returns the number of entries executed.
    pub fn handle_ipi(&mut self, cpu: u32) -> Result<u32> {
        if (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.stats.ipis_received += 1;
        let q = &mut self.queues[cpu as usize];
        q.ipi_count += 1;

        let mut executed: u32 = 0;

        while q.head < q.tail {
            let slot = q.head & CSD_RING_MASK;
            let entry = &mut q.ring[slot];

            if entry.state != CsdState::Pending {
                q.head += 1;
                q.count = q.count.saturating_sub(1);
                continue;
            }

            entry.state = CsdState::Running;

            if let Some(func) = entry.func {
                func(entry.data);
            }

            entry.state = CsdState::Completed;
            q.head += 1;
            q.count = q.count.saturating_sub(1);
            q.total_executed += 1;
            self.stats.csd_executed += 1;
            executed += 1;
        }

        Ok(executed)
    }

    /// Acquire the CSD lock for a specific CPU queue.
    pub fn csd_lock(&mut self, cpu: u32) -> Result<()> {
        if (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let q = &mut self.queues[cpu as usize];
        if q.locked {
            return Err(Error::Busy);
        }
        q.locked = true;
        Ok(())
    }

    /// Release the CSD lock for a specific CPU queue.
    pub fn csd_unlock(&mut self, cpu: u32) -> Result<()> {
        if (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let q = &mut self.queues[cpu as usize];
        if !q.locked {
            return Err(Error::InvalidArgument);
        }
        q.locked = false;
        Ok(())
    }

    /// Return the number of pending CSD entries on a CPU.
    pub fn pending_count(&self, cpu: u32) -> Result<u32> {
        if (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.queues[cpu as usize].count)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &SmpCallFuncStats {
        &self.stats
    }

    /// Return the number of online CPUs.
    pub fn online_cpus(&self) -> u32 {
        self.online_cpus
    }

    // ── internal helpers ─────────────────────────────────────

    /// Enqueue a CSD entry on the target CPU's queue.
    fn enqueue_csd(
        &mut self,
        target_cpu: u32,
        source_cpu: u32,
        func: SmpCallFn,
        data: u64,
        wait: bool,
    ) -> Result<()> {
        let q = &mut self.queues[target_cpu as usize];

        if q.count as usize >= CSD_RING_SIZE {
            self.stats.enqueue_failures += 1;
            return Err(Error::OutOfMemory);
        }

        let slot = q.tail & CSD_RING_MASK;
        q.ring[slot] = CsdEntry {
            func: Some(func),
            data,
            source_cpu,
            wait,
            state: CsdState::Pending,
            seq: self.next_seq,
        };

        q.tail += 1;
        q.count += 1;
        q.total_enqueued += 1;
        self.next_seq += 1;
        self.stats.csd_enqueued += 1;

        Ok(())
    }
}
