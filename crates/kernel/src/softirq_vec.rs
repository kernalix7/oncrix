// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Softirq vector management — dynamic softirq vector allocation.
//!
//! Extends the static softirq vector model with dynamic vector
//! allocation for subsystems that need deferred interrupt processing
//! without consuming one of the fixed 10 softirq slots.
//!
//! # Reference
//!
//! Linux `kernel/softirq.c`, extension for modular softirq vectors.

use oncrix_lib::{Error, Result};

const MAX_VECTORS: usize = 32;
const MAX_NAME_LEN: usize = 32;
const MAX_CPUS: usize = 64;

/// Priority of a softirq vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum VecPriority {
    /// Highest priority (timer, scheduler).
    High = 0,
    /// Normal priority (networking, block).
    Normal = 1,
    /// Low priority (RCU, tasklets).
    Low = 2,
}

/// Handler function for a softirq vector.
pub type VecHandler = fn(u64);

/// A dynamic softirq vector.
#[derive(Debug, Clone, Copy)]
pub struct SoftirqVec {
    /// Vector name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Vector ID.
    pub vec_id: u16,
    /// Handler function.
    pub handler: Option<VecHandler>,
    /// Priority.
    pub priority: VecPriority,
    /// Whether the vector is registered.
    pub registered: bool,
    /// Invocation count.
    pub invoke_count: u64,
    /// Total execution ticks.
    pub total_ticks: u64,
}

impl SoftirqVec {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            vec_id: 0,
            handler: None,
            priority: VecPriority::Normal,
            registered: false,
            invoke_count: 0,
            total_ticks: 0,
        }
    }
}

/// Per-CPU pending mask for dynamic vectors.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuPending {
    /// Bitmask of pending dynamic vectors.
    pub pending: u32,
    /// Total vectors processed.
    pub processed: u64,
}

impl PerCpuPending {
    const fn new() -> Self {
        Self {
            pending: 0,
            processed: 0,
        }
    }
}

/// Statistics for the vector subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SoftirqVecStats {
    /// Total vectors raised.
    pub total_raised: u64,
    /// Total vectors processed.
    pub total_processed: u64,
    /// Total registered vectors.
    pub registered_count: u32,
}

impl SoftirqVecStats {
    const fn new() -> Self {
        Self {
            total_raised: 0,
            total_processed: 0,
            registered_count: 0,
        }
    }
}

/// Top-level dynamic softirq vector manager.
pub struct SoftirqVecManager {
    /// Registered vectors.
    vectors: [SoftirqVec; MAX_VECTORS],
    /// Per-CPU pending masks.
    per_cpu: [PerCpuPending; MAX_CPUS],
    /// Statistics.
    stats: SoftirqVecStats,
    /// Next vector ID.
    next_vec_id: u16,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for SoftirqVecManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftirqVecManager {
    /// Create a new softirq vector manager.
    pub const fn new() -> Self {
        Self {
            vectors: [const { SoftirqVec::empty() }; MAX_VECTORS],
            per_cpu: [const { PerCpuPending::new() }; MAX_CPUS],
            stats: SoftirqVecStats::new(),
            next_vec_id: 1,
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

    /// Register a new softirq vector.
    pub fn register(
        &mut self,
        name: &[u8],
        priority: VecPriority,
        handler: VecHandler,
    ) -> Result<u16> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .vectors
            .iter()
            .position(|v| !v.registered)
            .ok_or(Error::OutOfMemory)?;

        let vec_id = self.next_vec_id;
        self.next_vec_id += 1;

        self.vectors[slot] = SoftirqVec::empty();
        self.vectors[slot].name[..name.len()].copy_from_slice(name);
        self.vectors[slot].name_len = name.len();
        self.vectors[slot].vec_id = vec_id;
        self.vectors[slot].handler = Some(handler);
        self.vectors[slot].priority = priority;
        self.vectors[slot].registered = true;

        self.stats.registered_count += 1;
        Ok(vec_id)
    }

    /// Unregister a vector.
    pub fn unregister(&mut self, vec_id: u16) -> Result<()> {
        let slot = self.find_vec(vec_id)?;
        self.vectors[slot] = SoftirqVec::empty();
        self.stats.registered_count = self.stats.registered_count.saturating_sub(1);
        Ok(())
    }

    /// Raise a vector on a CPU.
    pub fn raise(&mut self, cpu: usize, vec_id: u16) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_vec(vec_id)?;
        self.per_cpu[cpu].pending |= 1u32 << slot;
        self.stats.total_raised += 1;
        Ok(())
    }

    /// Process pending vectors on a CPU.
    pub fn process(&mut self, cpu: usize) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let pending = self.per_cpu[cpu].pending;
        if pending == 0 {
            return Ok(0);
        }
        self.per_cpu[cpu].pending = 0;

        let mut processed = 0usize;
        for bit in 0..MAX_VECTORS {
            if pending & (1u32 << bit) == 0 {
                continue;
            }
            if self.vectors[bit].registered {
                if let Some(handler) = self.vectors[bit].handler {
                    handler(0);
                    self.vectors[bit].invoke_count += 1;
                    processed += 1;
                }
            }
        }

        self.per_cpu[cpu].processed += processed as u64;
        self.stats.total_processed += processed as u64;
        Ok(processed)
    }

    /// Return statistics.
    pub fn stats(&self) -> SoftirqVecStats {
        self.stats
    }

    /// Return the number of registered vectors.
    pub fn registered_count(&self) -> u32 {
        self.stats.registered_count
    }

    /// Check if a CPU has pending vectors.
    pub fn has_pending(&self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu].pending != 0)
    }

    fn find_vec(&self, vec_id: u16) -> Result<usize> {
        self.vectors
            .iter()
            .position(|v| v.registered && v.vec_id == vec_id)
            .ok_or(Error::NotFound)
    }
}
