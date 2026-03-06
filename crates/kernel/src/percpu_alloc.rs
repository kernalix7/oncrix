// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU memory allocator.
//!
//! Manages per-CPU data areas where each CPU gets its own copy of
//! shared data structures. Eliminates cache-line bouncing for
//! frequently accessed per-CPU variables like statistics counters
//! and scheduling state.
//!
//! # Architecture
//!
//! ```text
//! PerCpuAllocator
//!  ├── areas[MAX_CPUS]
//!  │    ├── allocations[MAX_ALLOCS_PER_CPU]
//!  │    │    ├── offset, size
//!  │    │    └── active
//!  │    └── used_bytes, total_bytes
//!  └── stats: PerCpuAllocStats
//! ```
//!
//! # Reference
//!
//! Linux `mm/percpu.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum allocations per CPU area.
const MAX_ALLOCS_PER_CPU: usize = 128;

/// Per-CPU area size in bytes.
const AREA_SIZE: usize = 64 * 1024; // 64 KiB per CPU

/// Minimum allocation alignment.
const MIN_ALIGN: usize = 8;

// ══════════════════════════════════════════════════════════════
// PerCpuAllocation
// ══════════════════════════════════════════════════════════════

/// A single allocation within a per-CPU area.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuAllocation {
    /// Symbolic allocation ID.
    pub alloc_id: u32,
    /// Offset within the per-CPU area.
    pub offset: usize,
    /// Size of the allocation in bytes.
    pub size: usize,
    /// Whether this allocation is active.
    pub active: bool,
}

impl PerCpuAllocation {
    /// Create an inactive allocation.
    const fn empty() -> Self {
        Self {
            alloc_id: 0,
            offset: 0,
            size: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CpuArea — per-CPU area metadata
// ══════════════════════════════════════════════════════════════

/// Metadata for a single CPU's per-CPU area.
pub struct CpuArea {
    /// Allocations in this area.
    allocs: [PerCpuAllocation; MAX_ALLOCS_PER_CPU],
    /// Number of active allocations.
    pub nr_allocs: u32,
    /// Bytes used.
    pub used_bytes: usize,
    /// Total area size.
    pub total_bytes: usize,
    /// Whether this CPU area is initialised.
    pub initialised: bool,
}

impl CpuArea {
    /// Create an uninitialised area.
    const fn new() -> Self {
        Self {
            allocs: [const { PerCpuAllocation::empty() }; MAX_ALLOCS_PER_CPU],
            nr_allocs: 0,
            used_bytes: 0,
            total_bytes: AREA_SIZE,
            initialised: false,
        }
    }

    /// Find free space of the given size (first-fit).
    fn find_free_offset(&self, size: usize) -> Option<usize> {
        // Collect allocated ranges and find a gap.
        let mut offset = 0usize;
        // Gather active ranges sorted by offset.
        let mut ranges = [(0usize, 0usize); MAX_ALLOCS_PER_CPU];
        let mut count = 0;
        for alloc in &self.allocs {
            if alloc.active {
                ranges[count] = (alloc.offset, alloc.size);
                count += 1;
            }
        }
        // Simple bubble sort by offset (small N).
        for i in 0..count {
            for j in (i + 1)..count {
                if ranges[j].0 < ranges[i].0 {
                    ranges.swap(i, j);
                }
            }
        }
        // First-fit search.
        for i in 0..count {
            let aligned = (offset + MIN_ALIGN - 1) & !(MIN_ALIGN - 1);
            if aligned + size <= ranges[i].0 {
                return Some(aligned);
            }
            offset = ranges[i].0 + ranges[i].1;
        }
        let aligned = (offset + MIN_ALIGN - 1) & !(MIN_ALIGN - 1);
        if aligned + size <= self.total_bytes {
            Some(aligned)
        } else {
            None
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuAllocStats
// ══════════════════════════════════════════════════════════════

/// Allocator statistics.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuAllocStats {
    /// Total allocations made.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total bytes allocated.
    pub total_bytes_alloc: u64,
    /// Total bytes freed.
    pub total_bytes_freed: u64,
}

impl PerCpuAllocStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_allocs: 0,
            total_frees: 0,
            total_bytes_alloc: 0,
            total_bytes_freed: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuAllocator
// ══════════════════════════════════════════════════════════════

/// Per-CPU memory allocator.
pub struct PerCpuAllocator {
    /// Per-CPU areas.
    areas: [CpuArea; MAX_CPUS],
    /// Next allocation ID.
    next_alloc_id: u32,
    /// Number of initialised CPUs.
    nr_cpus: u32,
    /// Statistics.
    stats: PerCpuAllocStats,
}

impl PerCpuAllocator {
    /// Create a new per-CPU allocator.
    pub const fn new() -> Self {
        Self {
            areas: [const { CpuArea::new() }; MAX_CPUS],
            next_alloc_id: 1,
            nr_cpus: 0,
            stats: PerCpuAllocStats::new(),
        }
    }

    /// Initialise the per-CPU area for a CPU.
    pub fn init_cpu(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.areas[c].initialised = true;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Allocate space in per-CPU areas (same offset on every CPU).
    ///
    /// Returns the allocation ID and offset.
    pub fn alloc(&mut self, size: usize) -> Result<(u32, usize)> {
        if size == 0 || size > AREA_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Find a free offset that works on CPU 0 (all CPUs have same layout).
        let offset = if self.nr_cpus > 0 {
            self.areas[0]
                .find_free_offset(size)
                .ok_or(Error::OutOfMemory)?
        } else {
            return Err(Error::InvalidArgument);
        };

        let alloc_id = self.next_alloc_id;
        self.next_alloc_id += 1;

        // Record the allocation on all initialised CPUs.
        for c in 0..self.nr_cpus as usize {
            if !self.areas[c].initialised {
                continue;
            }
            let slot = self.areas[c]
                .allocs
                .iter()
                .position(|a| !a.active)
                .ok_or(Error::OutOfMemory)?;
            self.areas[c].allocs[slot] = PerCpuAllocation {
                alloc_id,
                offset,
                size,
                active: true,
            };
            self.areas[c].nr_allocs += 1;
            self.areas[c].used_bytes += size;
        }
        self.stats.total_allocs += 1;
        self.stats.total_bytes_alloc += size as u64;
        Ok((alloc_id, offset))
    }

    /// Free a per-CPU allocation by ID.
    pub fn free(&mut self, alloc_id: u32) -> Result<()> {
        let mut found = false;
        let mut freed_size = 0usize;
        for c in 0..self.nr_cpus as usize {
            if let Some(slot) = self.areas[c]
                .allocs
                .iter()
                .position(|a| a.active && a.alloc_id == alloc_id)
            {
                freed_size = self.areas[c].allocs[slot].size;
                self.areas[c].allocs[slot] = PerCpuAllocation::empty();
                self.areas[c].nr_allocs = self.areas[c].nr_allocs.saturating_sub(1);
                self.areas[c].used_bytes = self.areas[c].used_bytes.saturating_sub(freed_size);
                found = true;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }
        self.stats.total_frees += 1;
        self.stats.total_bytes_freed += freed_size as u64;
        Ok(())
    }

    /// Return the per-CPU area usage for a CPU.
    pub fn cpu_usage(&self, cpu: u32) -> Result<(usize, usize)> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.areas[c].initialised {
            return Err(Error::InvalidArgument);
        }
        Ok((self.areas[c].used_bytes, self.areas[c].total_bytes))
    }

    /// Return statistics.
    pub fn stats(&self) -> PerCpuAllocStats {
        self.stats
    }
}
