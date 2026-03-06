// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU counter accumulation.
//!
//! A `PercpuCounter` is a scalable counter that avoids cache-line
//! bouncing by maintaining a per-CPU delta and a global sum. Updates
//! are fast (per-CPU local), while reads can be approximate (read
//! global only) or precise (sum all per-CPU deltas).
//!
//! # Design
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │ PercpuCounter                             │
//! │                                          │
//! │  global_count: 1000                       │
//! │                                          │
//! │  per_cpu[0]:  +15   (not yet flushed)    │
//! │  per_cpu[1]:  -3                         │
//! │  per_cpu[2]:  +28   → exceeds batch      │
//! │  per_cpu[3]:  +7    → flush to global    │
//! │                                          │
//! │  Precise sum: 1000 + 15 - 3 + 28 + 7    │
//! │             = 1047                       │
//! │                                          │
//! │  When |per_cpu[i]| > batch_threshold:    │
//! │    global += per_cpu[i]                  │
//! │    per_cpu[i] = 0                        │
//! └──────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `lib/percpu_counter.c`, `include/linux/percpu_counter.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of CPUs.
const MAX_CPUS: usize = 64;

/// Default batch threshold for flushing per-CPU counts.
const DEFAULT_BATCH: i64 = 32;

/// Maximum number of managed counters.
const MAX_COUNTERS: usize = 128;

// ======================================================================
// Per-CPU counter
// ======================================================================

/// A scalable per-CPU counter.
pub struct PercpuCounter {
    /// Global count (sum of all flushed per-CPU counts).
    global_count: i64,
    /// Per-CPU deltas.
    per_cpu: [i64; MAX_CPUS],
    /// Batch threshold for flushing.
    batch: i64,
    /// Number of CPUs.
    nr_cpus: u32,
    /// Whether the counter is initialized.
    initialized: bool,
    /// Number of flushes performed.
    flush_count: u64,
}

impl PercpuCounter {
    /// Creates a new uninitialized per-CPU counter.
    pub const fn new() -> Self {
        Self {
            global_count: 0,
            per_cpu: [0i64; MAX_CPUS],
            batch: DEFAULT_BATCH,
            nr_cpus: 0,
            initialized: false,
            flush_count: 0,
        }
    }

    /// Initializes the counter with the given number of CPUs.
    pub fn init(&mut self, nr_cpus: u32, initial: i64) -> Result<()> {
        if nr_cpus == 0 || nr_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.global_count = initial;
        self.per_cpu = [0i64; MAX_CPUS];
        self.nr_cpus = nr_cpus;
        self.batch = DEFAULT_BATCH;
        self.initialized = true;
        Ok(())
    }

    /// Initializes with a custom batch size.
    pub fn init_with_batch(&mut self, nr_cpus: u32, initial: i64, batch: i64) -> Result<()> {
        self.init(nr_cpus, initial)?;
        if batch <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.batch = batch;
        Ok(())
    }

    /// Returns the batch threshold.
    pub fn batch(&self) -> i64 {
        self.batch
    }

    /// Sets the batch threshold.
    pub fn set_batch(&mut self, batch: i64) -> Result<()> {
        if batch <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.batch = batch;
        Ok(())
    }

    /// Returns the number of flushes.
    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }

    /// Adds a value to the counter from a specific CPU.
    pub fn add(&mut self, cpu: u32, amount: i64) -> Result<()> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = cpu as usize;
        self.per_cpu[idx] = self.per_cpu[idx].saturating_add(amount);
        // Check if we need to flush.
        if self.per_cpu[idx].abs() >= self.batch {
            self.flush_cpu(idx);
        }
        Ok(())
    }

    /// Subtracts a value from the counter.
    pub fn sub(&mut self, cpu: u32, amount: i64) -> Result<()> {
        self.add(cpu, -amount)
    }

    /// Reads the approximate value (global only, fast).
    pub fn read(&self) -> i64 {
        self.global_count
    }

    /// Reads the precise value (global + all per-CPU, slow).
    pub fn sum(&self) -> i64 {
        let mut total = self.global_count;
        for i in 0..self.nr_cpus as usize {
            total = total.saturating_add(self.per_cpu[i]);
        }
        total
    }

    /// Returns whether the precise sum is positive.
    pub fn sum_positive(&self) -> bool {
        self.sum() > 0
    }

    /// Returns the per-CPU delta for a specific CPU.
    pub fn cpu_delta(&self, cpu: u32) -> i64 {
        if cpu as usize >= MAX_CPUS {
            return 0;
        }
        self.per_cpu[cpu as usize]
    }

    /// Flushes all per-CPU deltas to the global count.
    pub fn sync(&mut self) {
        for i in 0..self.nr_cpus as usize {
            self.flush_cpu(i);
        }
    }

    /// Sets the counter to a specific value (resets all per-CPU).
    pub fn set(&mut self, value: i64) {
        self.global_count = value;
        for delta in &mut self.per_cpu[..self.nr_cpus as usize] {
            *delta = 0;
        }
    }

    /// Flushes a single CPU's delta to the global count.
    fn flush_cpu(&mut self, cpu_idx: usize) {
        if cpu_idx < self.nr_cpus as usize {
            self.global_count = self.global_count.saturating_add(self.per_cpu[cpu_idx]);
            self.per_cpu[cpu_idx] = 0;
            self.flush_count = self.flush_count.saturating_add(1);
        }
    }
}

// ======================================================================
// Counter manager
// ======================================================================

/// Manages multiple per-CPU counters.
pub struct PercpuCounterManager {
    /// Counters.
    counters: [PercpuCounter; MAX_COUNTERS],
    /// Which slots are occupied.
    occupied: [bool; MAX_COUNTERS],
    /// Counter IDs.
    ids: [u32; MAX_COUNTERS],
    /// Number of active counters.
    count: usize,
    /// Next counter ID.
    next_id: u32,
    /// Default number of CPUs.
    nr_cpus: u32,
}

impl PercpuCounterManager {
    /// Creates a new counter manager.
    pub const fn new() -> Self {
        Self {
            counters: [const { PercpuCounter::new() }; MAX_COUNTERS],
            occupied: [false; MAX_COUNTERS],
            ids: [0; MAX_COUNTERS],
            count: 0,
            next_id: 1,
            nr_cpus: 0,
        }
    }

    /// Initializes the manager with the number of CPUs.
    pub fn init(&mut self, nr_cpus: u32) -> Result<()> {
        if nr_cpus == 0 || nr_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr_cpus;
        Ok(())
    }

    /// Returns the number of active counters.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Creates a new counter and returns its ID.
    pub fn create(&mut self, initial: i64) -> Result<u32> {
        if self.nr_cpus == 0 {
            return Err(Error::NotImplemented);
        }
        let slot = self
            .occupied
            .iter()
            .position(|&o| !o)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.counters[slot].init(self.nr_cpus, initial)?;
        self.ids[slot] = id;
        self.occupied[slot] = true;
        self.count += 1;
        Ok(id)
    }

    /// Destroys a counter.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let slot = self.find(id)?;
        self.occupied[slot] = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Adds to a counter from a CPU.
    pub fn add(&mut self, id: u32, cpu: u32, amount: i64) -> Result<()> {
        let slot = self.find(id)?;
        self.counters[slot].add(cpu, amount)
    }

    /// Reads a counter (approximate).
    pub fn read(&self, id: u32) -> Result<i64> {
        let slot = self.find(id)?;
        Ok(self.counters[slot].read())
    }

    /// Reads a counter (precise sum).
    pub fn sum(&self, id: u32) -> Result<i64> {
        let slot = self.find(id)?;
        Ok(self.counters[slot].sum())
    }

    /// Synchronizes all counters.
    pub fn sync_all(&mut self) {
        for i in 0..MAX_COUNTERS {
            if self.occupied[i] {
                self.counters[i].sync();
            }
        }
    }

    /// Finds a slot by counter ID.
    fn find(&self, id: u32) -> Result<usize> {
        for i in 0..MAX_COUNTERS {
            if self.occupied[i] && self.ids[i] == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
