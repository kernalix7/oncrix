// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IRQ CPU affinity management.
//!
//! Distributes hardware interrupts across CPUs for load balancing and
//! NUMA locality. Manages per-IRQ affinity masks and provides an
//! automatic IRQ balancing algorithm.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                     IrqAffinitySubsystem                         │
//! │                                                                  │
//! │  [IrqAffinity; MAX_IRQS]  — per-IRQ affinity records            │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  IrqAffinity                                               │  │
//! │  │    irq_num: u32          — hardware IRQ number              │  │
//! │  │    mask: AffinityMask    — which CPUs may service this IRQ  │  │
//! │  │    effective_cpu: u32    — CPU currently handling the IRQ    │  │
//! │  │    spread: SpreadPolicy  — how to distribute across CPUs    │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  IrqBalance — automatic rebalancing engine                       │
//! │  IrqAffinityStats — global counters                              │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Spread Policies
//!
//! - **Single**: All interrupts for this IRQ go to one CPU.
//! - **RoundRobin**: Rotate through the affinity mask on each balance.
//! - **NumaLocal**: Prefer CPUs in the same NUMA node as the device.
//! - **Managed**: Affinity is managed by the device driver; kernel
//!   does not rebalance.
//!
//! # Reference
//!
//! Linux `kernel/irq/affinity.c`, `include/linux/irq.h`,
//! `Documentation/core-api/irq/irq-affinity.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum IRQ lines tracked.
const MAX_IRQS: usize = 256;

/// Maximum CPUs in an affinity mask.
const MAX_CPUS: usize = 64;

/// Words needed for a CPU bitmask (64 CPUs / 64 bits per word).
const MASK_WORDS: usize = (MAX_CPUS + 63) / 64;

/// Rebalance interval threshold in interrupt counts.
const REBALANCE_THRESHOLD: u64 = 10_000;

// ── SpreadPolicy ────────────────────────────────────────────────────────────

/// Policy for distributing an IRQ across CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpreadPolicy {
    /// Route all interrupts to a single CPU.
    Single,
    /// Rotate the target CPU through the affinity mask on each
    /// rebalance cycle.
    RoundRobin,
    /// Prefer CPUs that are NUMA-local to the device.
    NumaLocal,
    /// Affinity is driver-managed; the kernel does not rebalance.
    Managed,
}

impl Default for SpreadPolicy {
    fn default() -> Self {
        Self::Single
    }
}

// ── AffinityMask ────────────────────────────────────────────────────────────

/// CPU bitmask identifying which CPUs may service an IRQ.
///
/// Internally stored as an array of `u64` words, each representing
/// 64 CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffinityMask {
    /// Bitmask words.
    bits: [u64; MASK_WORDS],
}

impl Default for AffinityMask {
    fn default() -> Self {
        Self::none()
    }
}

impl AffinityMask {
    /// No CPUs set.
    pub const fn none() -> Self {
        Self {
            bits: [0u64; MASK_WORDS],
        }
    }

    /// All CPUs set.
    pub const fn all() -> Self {
        Self {
            bits: [u64::MAX; MASK_WORDS],
        }
    }

    /// Create a mask with a single CPU set.
    pub fn single(cpu: u32) -> Result<Self> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let mut mask = Self::none();
        mask.set(cpu);
        Ok(mask)
    }

    /// Set CPU `cpu` in the mask.
    pub fn set(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            let word = cpu as usize / 64;
            let bit = cpu as usize % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Clear CPU `cpu` from the mask.
    pub fn clear(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            let word = cpu as usize / 64;
            let bit = cpu as usize % 64;
            self.bits[word] &= !(1u64 << bit);
        }
    }

    /// Test whether CPU `cpu` is set.
    pub fn is_set(&self, cpu: u32) -> bool {
        if cpu as usize >= MAX_CPUS {
            return false;
        }
        let word = cpu as usize / 64;
        let bit = cpu as usize % 64;
        (self.bits[word] & (1u64 << bit)) != 0
    }

    /// Return the total number of CPUs set in the mask.
    pub fn count(&self) -> u32 {
        let mut total = 0u32;
        for word in &self.bits {
            total += word.count_ones();
        }
        total
    }

    /// Return `true` if no CPUs are set.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// Return the lowest-numbered CPU that is set.
    pub fn first_set(&self) -> Option<u32> {
        for (wi, word) in self.bits.iter().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros();
                let cpu = wi as u32 * 64 + bit;
                if cpu < MAX_CPUS as u32 {
                    return Some(cpu);
                }
            }
        }
        None
    }

    /// Return the Nth set CPU (0-indexed).
    pub fn nth_set(&self, n: u32) -> Option<u32> {
        let mut seen = 0u32;
        for (wi, word) in self.bits.iter().enumerate() {
            let ones = word.count_ones();
            if seen + ones > n {
                // The target bit is in this word.
                let mut w = *word;
                let mut remaining = n - seen;
                while remaining > 0 {
                    w &= w - 1; // clear lowest set bit
                    remaining -= 1;
                }
                let bit = w.trailing_zeros();
                let cpu = wi as u32 * 64 + bit;
                return Some(cpu);
            }
            seen += ones;
        }
        None
    }

    /// Intersect two masks.
    pub fn intersect(&self, other: &AffinityMask) -> Self {
        let mut result = Self::none();
        for (i, (a, b)) in self.bits.iter().zip(other.bits.iter()).enumerate() {
            result.bits[i] = a & b;
        }
        result
    }

    /// Union two masks.
    pub fn union(&self, other: &AffinityMask) -> Self {
        let mut result = Self::none();
        for (i, (a, b)) in self.bits.iter().zip(other.bits.iter()).enumerate() {
            result.bits[i] = a | b;
        }
        result
    }
}

// ── IrqAffinity ─────────────────────────────────────────────────────────────

/// Per-IRQ affinity record.
///
/// Tracks which CPUs may handle a given IRQ, the current effective
/// CPU assignment, and interrupt statistics.
#[derive(Debug, Clone, Copy)]
pub struct IrqAffinity {
    /// Hardware IRQ number.
    pub irq_num: u32,
    /// Affinity mask (which CPUs may service this IRQ).
    pub mask: AffinityMask,
    /// CPU currently handling this IRQ.
    pub effective_cpu: u32,
    /// Spread policy for rebalancing.
    pub spread: SpreadPolicy,
    /// Whether this entry is active.
    pub active: bool,
    /// Total interrupts delivered on this IRQ.
    pub interrupt_count: u64,
    /// Interrupts since last rebalance.
    pub count_since_rebalance: u64,
    /// NUMA node hint (u32::MAX if unknown).
    pub numa_node: u32,
    /// Round-robin index (for RoundRobin policy).
    rr_index: u32,
}

impl Default for IrqAffinity {
    fn default() -> Self {
        Self {
            irq_num: 0,
            mask: AffinityMask::none(),
            effective_cpu: 0,
            spread: SpreadPolicy::Single,
            active: false,
            interrupt_count: 0,
            count_since_rebalance: 0,
            numa_node: u32::MAX,
            rr_index: 0,
        }
    }
}

// ── IrqBalance ──────────────────────────────────────────────────────────────

/// Automatic IRQ load balancing state.
///
/// Periodically rebalances IRQ assignments across CPUs to avoid
/// hotspots. Only IRQs with `SpreadPolicy::RoundRobin` or
/// `SpreadPolicy::NumaLocal` are candidates.
#[derive(Debug, Clone, Copy)]
pub struct IrqBalance {
    /// Whether auto-balancing is enabled.
    pub enabled: bool,
    /// Per-CPU interrupt count since last rebalance.
    pub cpu_load: [u64; MAX_CPUS],
    /// Number of online CPUs.
    pub online_cpus: u32,
    /// Total rebalance cycles performed.
    pub cycles: u64,
    /// Total IRQ migrations performed.
    pub migrations: u64,
}

impl Default for IrqBalance {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_load: [0u64; MAX_CPUS],
            online_cpus: 1,
            cycles: 0,
            migrations: 0,
        }
    }
}

impl IrqBalance {
    /// Create a new balancer with `online_cpus` available.
    pub fn new(online_cpus: u32) -> Self {
        Self {
            online_cpus: if online_cpus == 0 { 1 } else { online_cpus },
            ..Self::default()
        }
    }

    /// Find the least-loaded CPU in `mask`.
    pub fn least_loaded_in(&self, mask: &AffinityMask) -> Option<u32> {
        let mut best_cpu: Option<u32> = None;
        let mut best_load = u64::MAX;
        for cpu in 0..self.online_cpus {
            if mask.is_set(cpu) && self.cpu_load[cpu as usize] < best_load {
                best_load = self.cpu_load[cpu as usize];
                best_cpu = Some(cpu);
            }
        }
        best_cpu
    }

    /// Record that `cpu` handled an interrupt.
    pub fn account(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            self.cpu_load[cpu as usize] += 1;
        }
    }

    /// Reset per-CPU load counters after a rebalance cycle.
    pub fn reset_loads(&mut self) {
        self.cpu_load = [0u64; MAX_CPUS];
        self.cycles += 1;
    }
}

// ── IrqAffinityStats ────────────────────────────────────────────────────────

/// Global statistics for IRQ affinity management.
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqAffinityStats {
    /// Number of active IRQ affinity entries.
    pub active_irqs: u64,
    /// Total affinity set operations.
    pub affinity_sets: u64,
    /// Total rebalance cycles.
    pub rebalance_cycles: u64,
    /// Total IRQ migrations.
    pub migrations: u64,
    /// Total interrupts processed.
    pub total_interrupts: u64,
}

// ── IrqAffinitySubsystem ───────────────────────────────────────────────────

/// System-wide IRQ affinity manager.
///
/// Manages per-IRQ CPU affinity masks, automatic load balancing,
/// and interrupt accounting.
pub struct IrqAffinitySubsystem {
    /// Per-IRQ affinity records.
    irqs: [IrqAffinity; MAX_IRQS],
    /// Number of active IRQ entries.
    active_count: usize,
    /// Automatic balancer state.
    pub balancer: IrqBalance,
    /// Global statistics.
    stats: IrqAffinityStats,
}

impl Default for IrqAffinitySubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqAffinitySubsystem {
    /// Create a new, empty IRQ affinity subsystem.
    pub const fn new() -> Self {
        const EMPTY: IrqAffinity = IrqAffinity {
            irq_num: 0,
            mask: AffinityMask {
                bits: [0u64; MASK_WORDS],
            },
            effective_cpu: 0,
            spread: SpreadPolicy::Single,
            active: false,
            interrupt_count: 0,
            count_since_rebalance: 0,
            numa_node: u32::MAX,
            rr_index: 0,
        };
        Self {
            irqs: [EMPTY; MAX_IRQS],
            active_count: 0,
            balancer: IrqBalance {
                enabled: true,
                cpu_load: [0u64; MAX_CPUS],
                online_cpus: 1,
                cycles: 0,
                migrations: 0,
            },
            stats: IrqAffinityStats {
                active_irqs: 0,
                affinity_sets: 0,
                rebalance_cycles: 0,
                migrations: 0,
                total_interrupts: 0,
            },
        }
    }

    /// Register an IRQ for affinity management.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] if `irq_num` is already registered.
    /// - [`Error::OutOfMemory`] if the IRQ table is full.
    pub fn register(
        &mut self,
        irq_num: u32,
        mask: AffinityMask,
        spread: SpreadPolicy,
    ) -> Result<()> {
        // Check for duplicate.
        if self.irqs.iter().any(|i| i.active && i.irq_num == irq_num) {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .irqs
            .iter()
            .position(|i| !i.active)
            .ok_or(Error::OutOfMemory)?;

        let effective = mask.first_set().unwrap_or(0);

        self.irqs[slot] = IrqAffinity {
            irq_num,
            mask,
            effective_cpu: effective,
            spread,
            active: true,
            interrupt_count: 0,
            count_since_rebalance: 0,
            numa_node: u32::MAX,
            rr_index: 0,
        };

        self.active_count += 1;
        self.stats.active_irqs = self.active_count as u64;
        Ok(())
    }

    /// Unregister an IRQ.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    pub fn unregister(&mut self, irq_num: u32) -> Result<()> {
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        self.irqs[idx] = IrqAffinity::default();
        self.active_count -= 1;
        self.stats.active_irqs = self.active_count as u64;
        Ok(())
    }

    /// Set the affinity mask for an IRQ.
    ///
    /// The effective CPU is updated to the first CPU in the new mask.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    /// - [`Error::InvalidArgument`] if `mask` is empty.
    pub fn set_affinity(&mut self, irq_num: u32, mask: AffinityMask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        self.irqs[idx].mask = mask;
        // Update effective CPU to a valid CPU in the new mask.
        if !mask.is_set(self.irqs[idx].effective_cpu) {
            self.irqs[idx].effective_cpu = mask.first_set().unwrap_or(0);
        }
        self.stats.affinity_sets += 1;
        Ok(())
    }

    /// Set the spread policy for an IRQ.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    pub fn set_spread_policy(&mut self, irq_num: u32, policy: SpreadPolicy) -> Result<()> {
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        self.irqs[idx].spread = policy;
        Ok(())
    }

    /// Set the NUMA node hint for an IRQ.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    pub fn set_numa_node(&mut self, irq_num: u32, node: u32) -> Result<()> {
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        self.irqs[idx].numa_node = node;
        Ok(())
    }

    /// Record that an interrupt was delivered on `irq_num`.
    ///
    /// Also accounts the interrupt to the effective CPU in the
    /// balancer.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    pub fn record_interrupt(&mut self, irq_num: u32) -> Result<u32> {
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        let irq = &mut self.irqs[idx];
        irq.interrupt_count += 1;
        irq.count_since_rebalance += 1;
        let cpu = irq.effective_cpu;
        self.balancer.account(cpu);
        self.stats.total_interrupts += 1;
        Ok(cpu)
    }

    /// Get the effective CPU for an IRQ.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    pub fn effective_cpu(&self, irq_num: u32) -> Result<u32> {
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        Ok(self.irqs[idx].effective_cpu)
    }

    /// Get the affinity mask for an IRQ.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `irq_num` is not registered.
    pub fn get_affinity(&self, irq_num: u32) -> Result<&AffinityMask> {
        let idx = self.find_index(irq_num).ok_or(Error::NotFound)?;
        Ok(&self.irqs[idx].mask)
    }

    /// Run one automatic rebalance cycle.
    ///
    /// For each IRQ whose `count_since_rebalance` exceeds the
    /// threshold, pick a new effective CPU according to the IRQ's
    /// spread policy.
    ///
    /// Returns the number of IRQ migrations performed.
    pub fn rebalance(&mut self) -> u32 {
        if !self.balancer.enabled {
            return 0;
        }

        let mut migrations = 0u32;

        for irq in &mut self.irqs {
            if !irq.active {
                continue;
            }
            if irq.spread == SpreadPolicy::Managed {
                continue;
            }
            if irq.count_since_rebalance < REBALANCE_THRESHOLD {
                continue;
            }

            let new_cpu = match irq.spread {
                SpreadPolicy::Single => {
                    // No migration for single-CPU policy.
                    None
                }
                SpreadPolicy::RoundRobin => {
                    let n = irq.mask.count();
                    if n <= 1 {
                        None
                    } else {
                        irq.rr_index = (irq.rr_index + 1) % n;
                        irq.mask.nth_set(irq.rr_index)
                    }
                }
                SpreadPolicy::NumaLocal => {
                    // Use the least-loaded CPU in the mask
                    // as a NUMA-aware heuristic.
                    self.balancer.least_loaded_in(&irq.mask)
                }
                SpreadPolicy::Managed => None,
            };

            if let Some(cpu) = new_cpu {
                if cpu != irq.effective_cpu {
                    irq.effective_cpu = cpu;
                    migrations += 1;
                }
            }
            irq.count_since_rebalance = 0;
        }

        self.balancer.reset_loads();
        self.balancer.migrations += migrations as u64;
        self.stats.rebalance_cycles += 1;
        self.stats.migrations += migrations as u64;

        migrations
    }

    /// Return a snapshot of global statistics.
    pub fn stats(&self) -> &IrqAffinityStats {
        &self.stats
    }

    /// Return the number of active IRQ entries.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Find the table index for `irq_num`.
    fn find_index(&self, irq_num: u32) -> Option<usize> {
        self.irqs
            .iter()
            .position(|i| i.active && i.irq_num == irq_num)
    }
}
