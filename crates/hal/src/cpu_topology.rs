// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU topology discovery and representation.
//!
//! Parses and represents the physical CPU topology including packages (sockets),
//! cores, and hardware threads (SMT/hyperthreads). Used by the scheduler for
//! NUMA-aware task placement and power management.
//!
//! # Topology Hierarchy
//!
//! ```text
//! System
//! └── Package (socket)
//!     └── Core
//!         └── Thread (logical CPU / hardware thread)
//! ```

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum number of logical CPUs supported.
pub const MAX_LOGICAL_CPUS: usize = 256;

/// Maximum number of CPU packages (sockets).
pub const MAX_PACKAGES: usize = 8;

/// Maximum cores per package.
pub const MAX_CORES_PER_PACKAGE: usize = 64;

/// CPU identifier (logical CPU index, 0-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuId(pub u32);

/// A logical CPU (hardware thread) descriptor.
#[derive(Debug, Clone, Copy)]
pub struct LogicalCpu {
    /// Logical CPU ID.
    pub id: CpuId,
    /// Package (socket) index.
    pub package: u8,
    /// Core index within the package.
    pub core: u8,
    /// Thread index within the core (0 for first SMT thread).
    pub thread: u8,
    /// APIC ID (x86) or MPIDR (ARM).
    pub hw_id: u32,
    /// Whether this CPU is online.
    pub online: bool,
}

impl LogicalCpu {
    /// Returns whether this CPU is a primary thread (not a sibling SMT thread).
    pub fn is_primary_thread(&self) -> bool {
        self.thread == 0
    }
}

/// A CPU core descriptor (may have multiple SMT threads).
#[derive(Debug, Clone, Copy)]
pub struct CpuCore {
    /// Package index.
    pub package: u8,
    /// Core index within the package.
    pub index: u8,
    /// Number of hardware threads on this core.
    pub num_threads: u8,
    /// Whether this core supports hyperthreading/SMT.
    pub has_smt: bool,
}

/// CPU topology database.
pub struct CpuTopology {
    /// All logical CPUs.
    cpus: [Option<LogicalCpu>; MAX_LOGICAL_CPUS],
    /// Number of logical CPUs.
    num_cpus: usize,
    /// Number of packages.
    num_packages: u32,
    /// Cores per package (assumes uniform topology).
    cores_per_package: u32,
    /// Threads per core.
    threads_per_core: u32,
}

impl CpuTopology {
    /// Creates an empty topology database.
    pub const fn new() -> Self {
        Self {
            cpus: [None; MAX_LOGICAL_CPUS],
            num_cpus: 0,
            num_packages: 0,
            cores_per_package: 0,
            threads_per_core: 0,
        }
    }

    /// Registers a logical CPU.
    pub fn register_cpu(&mut self, cpu: LogicalCpu) -> Result<()> {
        if self.num_cpus >= MAX_LOGICAL_CPUS {
            return Err(Error::OutOfMemory);
        }
        self.cpus[self.num_cpus] = Some(cpu);
        self.num_cpus += 1;
        // Update aggregate counts
        if cpu.package as u32 + 1 > self.num_packages {
            self.num_packages = cpu.package as u32 + 1;
        }
        Ok(())
    }

    /// Finalizes topology by computing cores/threads per package.
    pub fn finalize(&mut self) {
        if self.num_packages == 0 {
            return;
        }
        let mut max_core = 0u32;
        let mut max_thread = 0u32;
        for cpu in self.cpus[..self.num_cpus].iter().flatten() {
            if cpu.core as u32 > max_core {
                max_core = cpu.core as u32;
            }
            if cpu.thread as u32 > max_thread {
                max_thread = cpu.thread as u32;
            }
        }
        self.cores_per_package = max_core + 1;
        self.threads_per_core = max_thread + 1;
    }

    /// Returns the logical CPU descriptor by ID.
    pub fn get_cpu(&self, id: CpuId) -> Option<&LogicalCpu> {
        self.cpus[..self.num_cpus]
            .iter()
            .find_map(|c| c.as_ref().filter(|cpu| cpu.id == id))
    }

    /// Returns all CPUs in a given package.
    pub fn package_cpus(&self, package: u8) -> impl Iterator<Item = &LogicalCpu> {
        self.cpus[..self.num_cpus]
            .iter()
            .filter_map(move |c| c.as_ref().filter(|cpu| cpu.package == package))
    }

    /// Returns all SMT siblings of a given CPU (same core, different thread).
    pub fn smt_siblings<'a>(&'a self, cpu: &'a LogicalCpu) -> impl Iterator<Item = &'a LogicalCpu> {
        let pkg = cpu.package;
        let core = cpu.core;
        let id = cpu.id;
        self.cpus[..self.num_cpus].iter().filter_map(move |c| {
            c.as_ref()
                .filter(|c| c.package == pkg && c.core == core && c.id != id)
        })
    }

    /// Returns the number of logical CPUs.
    pub fn num_cpus(&self) -> usize {
        self.num_cpus
    }

    /// Returns the number of packages.
    pub fn num_packages(&self) -> u32 {
        self.num_packages
    }

    /// Returns cores per package.
    pub fn cores_per_package(&self) -> u32 {
        self.cores_per_package
    }

    /// Returns threads per core.
    pub fn threads_per_core(&self) -> u32 {
        self.threads_per_core
    }

    /// Returns whether the system has SMT (hyperthreading).
    pub fn has_smt(&self) -> bool {
        self.threads_per_core > 1
    }

    /// Returns whether the system has multiple packages (is multi-socket).
    pub fn is_multi_socket(&self) -> bool {
        self.num_packages > 1
    }
}

impl Default for CpuTopology {
    fn default() -> Self {
        Self::new()
    }
}

/// Detects and populates CPU topology from CPUID (x86) or MPIDR (ARM).
pub fn detect_topology() -> CpuTopology {
    let mut topo = CpuTopology::new();
    #[cfg(target_arch = "x86_64")]
    {
        detect_x86_topology(&mut topo);
    }
    topo.finalize();
    topo
}

#[cfg(target_arch = "x86_64")]
fn detect_x86_topology(topo: &mut CpuTopology) {
    // Use CPUID leaf 0x1E / 0xB for topology enumeration.
    // Simplified: assume a single package with CPUID.1:EBX[23:16] logical CPUs.
    let ebx: u64;
    // SAFETY: CPUID with EAX=1 returns basic processor info including logical CPU count.
    // rbx is reserved by LLVM; save/restore via xchg with a general-purpose register.
    unsafe {
        core::arch::asm!(
            "xchg rbx, {tmp}",
            "cpuid",
            "xchg rbx, {tmp}",
            tmp = out(reg) ebx,
            inlateout("eax") 1u32 => _,
            out("ecx") _,
            out("edx") _,
            options(nostack, nomem)
        );
    }
    let logical_count = ((ebx as u32) >> 16) & 0xFF;
    let logical_count = if logical_count == 0 { 1 } else { logical_count };
    for i in 0..logical_count.min(MAX_LOGICAL_CPUS as u32) {
        let cpu = LogicalCpu {
            id: CpuId(i),
            package: 0,
            core: (i / 2) as u8,
            thread: (i % 2) as u8,
            hw_id: i,
            online: true,
        };
        let _ = topo.register_cpu(cpu);
    }
}
