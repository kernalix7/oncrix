// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug state machine and lifecycle management.
//!
//! Provides the infrastructure for online/offline transitions of CPU cores
//! in a SMP system:
//!
//! - [`CpuState`] — the per-CPU power/online state
//! - [`CpuHotplug`] — the hotplug coordinator managing CPU state transitions
//! - Callbacks for bring-up and teardown sequences
//!
//! # Hotplug Sequence
//!
//! **Online (off → on)**:
//! 1. Mark CPU as `BringingUp`
//! 2. Architecture layer starts the secondary CPU (INIT/SIPI on x86, PSCI CPU_ON on ARM)
//! 3. Secondary CPU runs startup code, signals `Online` when ready
//!
//! **Offline (on → off)**:
//! 1. Mark CPU as `GoingOffline`
//! 2. Migrate tasks and IRQs away from the CPU
//! 3. CPU executes `cpu_idle()` then calls CPU_OFF/mwait
//! 4. Mark as `Offline`
//!
//! Reference: Linux kernel Documentation/core-api/cpu_hotplug.rst

use oncrix_lib::{Error, Result};

/// Maximum CPUs supported by the hotplug manager.
pub const MAX_CPUS: usize = 256;

// ── CPU State ──────────────────────────────────────────────────────────────

/// Online/offline lifecycle state of a single CPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CpuState {
    /// CPU is not present (not enumerated or removed).
    NotPresent,
    /// CPU is present but offline (powered down).
    Offline,
    /// CPU is in the process of being brought online.
    BringingUp,
    /// CPU is fully online and scheduling tasks.
    Online,
    /// CPU is being taken offline (tasks being migrated).
    GoingOffline,
}

impl CpuState {
    /// Returns true if the CPU is available for scheduling.
    pub fn is_online(self) -> bool {
        self == CpuState::Online
    }

    /// Returns true if the CPU is in a transition state.
    pub fn is_transitioning(self) -> bool {
        matches!(self, CpuState::BringingUp | CpuState::GoingOffline)
    }
}

// ── CPU Descriptor ─────────────────────────────────────────────────────────

/// Per-CPU descriptor in the hotplug manager.
#[derive(Clone, Copy)]
pub struct CpuDescriptor {
    /// Current state.
    pub state: CpuState,
    /// Architecture-specific affinity ID (MPIDR on ARM, APIC ID on x86).
    pub affinity_id: u32,
    /// NUMA node this CPU belongs to.
    pub numa_node: u8,
    /// Number of times this CPU has been brought online.
    pub online_count: u32,
    /// Number of hotplug failures on this CPU.
    pub failure_count: u32,
}

impl CpuDescriptor {
    const fn absent() -> Self {
        Self {
            state: CpuState::NotPresent,
            affinity_id: 0,
            numa_node: 0,
            online_count: 0,
            failure_count: 0,
        }
    }
}

// ── Hotplug Event ──────────────────────────────────────────────────────────

/// A hotplug lifecycle event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HotplugEvent {
    /// CPU is being prepared for online (pre-bring-up).
    PreOnline(usize),
    /// CPU has come online.
    PostOnline(usize),
    /// CPU is preparing to go offline.
    PreOffline(usize),
    /// CPU has gone offline.
    PostOffline(usize),
}

// ── Hotplug Error ──────────────────────────────────────────────────────────

/// CPU hotplug coordinator.
pub struct CpuHotplug {
    cpus: [CpuDescriptor; MAX_CPUS],
    /// Number of CPUs registered (present).
    present_count: usize,
    /// Bitmask of online CPUs (up to 256 bits = 4 × u64).
    online_mask: [u64; 4],
    /// Boot CPU index.
    boot_cpu: usize,
}

impl CpuHotplug {
    /// Create a new hotplug coordinator with no CPUs registered.
    pub fn new() -> Self {
        Self {
            cpus: [const { CpuDescriptor::absent() }; MAX_CPUS],
            present_count: 0,
            online_mask: [0u64; 4],
            boot_cpu: 0,
        }
    }

    /// Register a CPU as present.
    pub fn register_cpu(&mut self, cpu: usize, affinity_id: u32, numa_node: u8) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[cpu].state != CpuState::NotPresent {
            return Err(Error::AlreadyExists);
        }
        self.cpus[cpu] = CpuDescriptor {
            state: CpuState::Offline,
            affinity_id,
            numa_node,
            online_count: 0,
            failure_count: 0,
        };
        self.present_count += 1;
        Ok(())
    }

    /// Mark the boot CPU as online (it was never offline).
    pub fn set_boot_cpu(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS || self.cpus[cpu].state == CpuState::NotPresent {
            return Err(Error::InvalidArgument);
        }
        self.boot_cpu = cpu;
        self.cpus[cpu].state = CpuState::Online;
        self.cpus[cpu].online_count += 1;
        self.set_online_bit(cpu, true);
        Ok(())
    }

    /// Begin bringing a CPU online (transition to BringingUp).
    pub fn begin_online(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        match self.cpus[cpu].state {
            CpuState::Offline => {
                self.cpus[cpu].state = CpuState::BringingUp;
                Ok(())
            }
            CpuState::Online => Err(Error::AlreadyExists),
            CpuState::NotPresent => Err(Error::NotFound),
            _ => Err(Error::Busy),
        }
    }

    /// Confirm a CPU has come online successfully.
    pub fn complete_online(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS || self.cpus[cpu].state != CpuState::BringingUp {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu].state = CpuState::Online;
        self.cpus[cpu].online_count += 1;
        self.set_online_bit(cpu, true);
        Ok(())
    }

    /// Report that a CPU failed to come online.
    pub fn fail_online(&mut self, cpu: usize) {
        if cpu < MAX_CPUS && self.cpus[cpu].state == CpuState::BringingUp {
            self.cpus[cpu].state = CpuState::Offline;
            self.cpus[cpu].failure_count += 1;
        }
    }

    /// Begin taking a CPU offline.
    pub fn begin_offline(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if cpu == self.boot_cpu {
            return Err(Error::PermissionDenied);
        }
        match self.cpus[cpu].state {
            CpuState::Online => {
                self.cpus[cpu].state = CpuState::GoingOffline;
                Ok(())
            }
            CpuState::Offline => Err(Error::InvalidArgument),
            CpuState::NotPresent => Err(Error::NotFound),
            _ => Err(Error::Busy),
        }
    }

    /// Confirm a CPU has gone offline.
    pub fn complete_offline(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS || self.cpus[cpu].state != CpuState::GoingOffline {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu].state = CpuState::Offline;
        self.set_online_bit(cpu, false);
        Ok(())
    }

    /// Return the state of a CPU.
    pub fn state(&self, cpu: usize) -> Option<CpuState> {
        if cpu < MAX_CPUS && self.cpus[cpu].state != CpuState::NotPresent {
            Some(self.cpus[cpu].state)
        } else {
            None
        }
    }

    /// Return a reference to a CPU descriptor.
    pub fn descriptor(&self, cpu: usize) -> Option<&CpuDescriptor> {
        if cpu < MAX_CPUS && self.cpus[cpu].state != CpuState::NotPresent {
            Some(&self.cpus[cpu])
        } else {
            None
        }
    }

    /// Return the number of CPUs currently online.
    pub fn online_count(&self) -> usize {
        let mut n = 0;
        for &word in &self.online_mask {
            n += word.count_ones() as usize;
        }
        n
    }

    /// Return the total number of present CPUs.
    pub fn present_count(&self) -> usize {
        self.present_count
    }

    /// Check if a specific CPU is online.
    pub fn is_online(&self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        let word = cpu / 64;
        let bit = cpu % 64;
        self.online_mask[word] & (1u64 << bit) != 0
    }

    fn set_online_bit(&mut self, cpu: usize, online: bool) {
        let word = cpu / 64;
        let bit = cpu % 64;
        if online {
            self.online_mask[word] |= 1u64 << bit;
        } else {
            self.online_mask[word] &= !(1u64 << bit);
        }
    }
}

impl Default for CpuHotplug {
    fn default() -> Self {
        Self::new()
    }
}
