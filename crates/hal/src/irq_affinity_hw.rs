// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware-level interrupt affinity management.
//!
//! Manages the routing of hardware interrupts to specific CPUs by programming
//! interrupt controller registers (IOAPIC ITARGETSR, GICD_ITARGETSR, etc.).
//!
//! # Affinity Mask
//!
//! An affinity mask is a bitmask of logical CPU IDs to which an interrupt
//! may be routed. The interrupt controller selects one CPU from the mask
//! based on its routing policy (lowest priority, round-robin, etc.).

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum logical CPUs tracked by the affinity subsystem.
pub const IRQ_AFFINITY_MAX_CPUS: usize = 64;

/// Affinity mask for interrupt routing (bitmask of logical CPU IDs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffinityMask(pub u64);

impl AffinityMask {
    /// Creates a mask targeting a single CPU.
    pub const fn single(cpu: u32) -> Self {
        if cpu < 64 { Self(1 << cpu) } else { Self(0) }
    }

    /// Creates a mask targeting all CPUs.
    pub const fn all() -> Self {
        Self(u64::MAX)
    }

    /// Creates an empty (no CPU) mask.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Returns whether the given CPU is in the mask.
    pub fn contains(self, cpu: u32) -> bool {
        cpu < 64 && (self.0 >> cpu) & 1 != 0
    }

    /// Adds a CPU to the mask.
    pub fn add(&mut self, cpu: u32) {
        if cpu < 64 {
            self.0 |= 1 << cpu;
        }
    }

    /// Removes a CPU from the mask.
    pub fn remove(&mut self, cpu: u32) {
        if cpu < 64 {
            self.0 &= !(1 << cpu);
        }
    }

    /// Returns whether the mask is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the first CPU in the mask.
    pub fn first(self) -> Option<u32> {
        if self.is_empty() {
            None
        } else {
            Some(self.0.trailing_zeros())
        }
    }

    /// Returns the number of CPUs in the mask.
    pub fn count(self) -> u32 {
        self.0.count_ones()
    }
}

/// Per-IRQ affinity record.
#[derive(Debug, Clone, Copy)]
pub struct IrqAffinityRecord {
    /// IRQ number.
    pub irq: u32,
    /// Current effective affinity.
    pub affinity: AffinityMask,
    /// Whether affinity is managed automatically by the kernel.
    pub managed: bool,
}

/// Maximum number of IRQs tracked.
pub const IRQ_AFFINITY_MAX_IRQS: usize = 256;

/// Interrupt affinity database.
pub struct IrqAffinityDb {
    records: [Option<IrqAffinityRecord>; IRQ_AFFINITY_MAX_IRQS],
    count: usize,
}

impl IrqAffinityDb {
    /// Creates an empty affinity database.
    pub const fn new() -> Self {
        const NONE: Option<IrqAffinityRecord> = None;
        Self {
            records: [NONE; IRQ_AFFINITY_MAX_IRQS],
            count: 0,
        }
    }

    /// Registers an IRQ with an initial affinity.
    pub fn register(&mut self, irq: u32, affinity: AffinityMask) -> Result<()> {
        if self.count >= IRQ_AFFINITY_MAX_IRQS {
            return Err(Error::OutOfMemory);
        }
        if self.find(irq).is_some() {
            return Err(Error::AlreadyExists);
        }
        self.records[self.count] = Some(IrqAffinityRecord {
            irq,
            affinity,
            managed: true,
        });
        self.count += 1;
        Ok(())
    }

    /// Sets the affinity for an IRQ.
    pub fn set_affinity(&mut self, irq: u32, affinity: AffinityMask) -> Result<()> {
        if affinity.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let rec = self.find_mut(irq).ok_or(Error::NotFound)?;
        rec.affinity = affinity;
        Ok(())
    }

    /// Returns the affinity for an IRQ.
    pub fn get_affinity(&self, irq: u32) -> Option<AffinityMask> {
        self.find(irq).map(|r| r.affinity)
    }

    /// Spreads IRQs in a range across CPUs in a round-robin fashion.
    ///
    /// Used during MSI-X interrupt vector assignment.
    pub fn spread_affinity(
        &mut self,
        irq_start: u32,
        irq_count: u32,
        cpu_mask: AffinityMask,
    ) -> Result<()> {
        if cpu_mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let num_cpus = cpu_mask.count();
        let mut cpu_bits: [u32; 64] = [0u32; 64];
        let mut n = 0usize;
        for i in 0u32..64 {
            if cpu_mask.contains(i) {
                cpu_bits[n] = i;
                n += 1;
                if n >= num_cpus as usize {
                    break;
                }
            }
        }
        for i in 0..irq_count {
            let cpu = cpu_bits[(i as usize) % n];
            let affinity = AffinityMask::single(cpu);
            self.set_affinity(irq_start + i, affinity).ok();
        }
        Ok(())
    }

    fn find(&self, irq: u32) -> Option<&IrqAffinityRecord> {
        self.records[..self.count]
            .iter()
            .find_map(|r| r.as_ref().filter(|rec| rec.irq == irq))
    }

    fn find_mut(&mut self, irq: u32) -> Option<&mut IrqAffinityRecord> {
        self.records[..self.count]
            .iter_mut()
            .find_map(|r| r.as_mut().filter(|rec| rec.irq == irq))
    }

    /// Returns the number of registered IRQ affinity records.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether no IRQs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IrqAffinityDb {
    fn default() -> Self {
        Self::new()
    }
}
