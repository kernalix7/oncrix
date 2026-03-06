// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PMU (Performance Monitoring Unit) event abstraction.
//!
//! Provides a HAL-level interface for programming hardware performance
//! counters using architecture-specific PMU events. The PMU is used to
//! count microarchitectural events (cache misses, branch mispredictions,
//! instruction counts, etc.) for profiling and tuning.

use oncrix_lib::{Error, Result};

/// Maximum number of hardware PMU counters per CPU.
pub const PMU_MAX_COUNTERS: usize = 8;

/// Common architectural event types (subset of ARM/x86 events).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmuEventType {
    /// Retired instructions.
    Instructions,
    /// CPU clock cycles.
    CpuCycles,
    /// Level-1 data cache misses.
    L1dCacheMiss,
    /// Level-1 instruction cache misses.
    L1iCacheMiss,
    /// Branch instructions retired.
    BranchInstructions,
    /// Branch mispredictions.
    BranchMispredict,
    /// Last-level cache misses.
    LlcMiss,
    /// TLB miss (data).
    DtlbMiss,
    /// TLB miss (instruction).
    ItlbMiss,
    /// Bus/memory accesses.
    MemoryAccess,
    /// Stall cycles (front-end).
    StalledCyclesFrontend,
    /// Stall cycles (back-end).
    StalledCyclesBackend,
    /// Raw event code (architecture-specific).
    Raw(u64),
}

/// PMU counter configuration.
#[derive(Debug, Clone, Copy)]
pub struct PmuCounterConfig {
    /// Event to count.
    pub event: PmuEventType,
    /// Whether to count in user mode.
    pub user_mode: bool,
    /// Whether to count in kernel mode.
    pub kernel_mode: bool,
    /// Whether to count in hypervisor mode.
    pub hyp_mode: bool,
    /// Initial counter value (for overflow interrupts).
    pub initial_value: u64,
}

impl Default for PmuCounterConfig {
    fn default() -> Self {
        Self {
            event: PmuEventType::Instructions,
            user_mode: true,
            kernel_mode: true,
            hyp_mode: false,
            initial_value: 0,
        }
    }
}

/// State of a single PMU counter.
#[derive(Debug, Clone, Copy)]
pub struct PmuCounter {
    /// Counter index.
    pub index: usize,
    /// Configuration (if programmed).
    pub config: Option<PmuCounterConfig>,
    /// Accumulated count (updated on read).
    pub count: u64,
    /// Whether this counter is currently running.
    pub running: bool,
}

impl PmuCounter {
    /// Creates a new empty counter.
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            config: None,
            count: 0,
            running: false,
        }
    }
}

/// x86 MSR addresses for the PMU.
#[cfg(target_arch = "x86_64")]
mod x86_pmu {
    /// IA32_PERF_GLOBAL_CTRL MSR.
    pub const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
    /// IA32_PERF_GLOBAL_STATUS MSR.
    pub const IA32_PERF_GLOBAL_STATUS: u32 = 0x38E;
    /// IA32_PERFEVTSEL0 MSR base (one per counter).
    pub const IA32_PERFEVTSEL_BASE: u32 = 0x186;
    /// IA32_PMC0 MSR base (one per counter).
    pub const IA32_PMC_BASE: u32 = 0xC1;

    /// PERFEVTSEL bit: user mode.
    pub const USR: u64 = 1 << 16;
    /// PERFEVTSEL bit: OS mode.
    pub const OS: u64 = 1 << 17;
    /// PERFEVTSEL bit: enable.
    pub const EN: u64 = 1 << 22;
}

/// PMU driver.
pub struct PmuDriver {
    /// CPU index this driver manages.
    pub cpu: u32,
    /// Number of programmable counters.
    pub num_counters: usize,
    /// Counter state.
    pub counters: [PmuCounter; PMU_MAX_COUNTERS],
}

impl PmuDriver {
    /// Creates a new PMU driver for `cpu`.
    pub const fn new(cpu: u32, num_counters: usize) -> Self {
        Self {
            cpu,
            num_counters,
            counters: [const {
                PmuCounter {
                    index: 0,
                    config: None,
                    count: 0,
                    running: false,
                }
            }; PMU_MAX_COUNTERS],
        }
    }

    /// Initialises the PMU: disables all counters and clears counts.
    pub fn init(&mut self) -> Result<()> {
        if self.num_counters > PMU_MAX_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        for i in 0..PMU_MAX_COUNTERS {
            self.counters[i].index = i;
        }
        self.disable_all();
        Ok(())
    }

    /// Programs counter `idx` with configuration `cfg`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx >= num_counters`.
    /// Returns [`Error::Busy`] if the counter is already running.
    pub fn program(&mut self, idx: usize, cfg: PmuCounterConfig) -> Result<()> {
        if idx >= self.num_counters {
            return Err(Error::InvalidArgument);
        }
        if self.counters[idx].running {
            return Err(Error::Busy);
        }
        self.counters[idx].config = Some(cfg);
        self.counters[idx].count = cfg.initial_value;
        #[cfg(target_arch = "x86_64")]
        self.x86_program_counter(idx, &cfg);
        Ok(())
    }

    /// Starts counter `idx`.
    pub fn start(&mut self, idx: usize) -> Result<()> {
        if idx >= self.num_counters || self.counters[idx].config.is_none() {
            return Err(Error::InvalidArgument);
        }
        self.counters[idx].running = true;
        #[cfg(target_arch = "x86_64")]
        self.x86_enable_counter(idx);
        Ok(())
    }

    /// Stops counter `idx` and returns the current count.
    pub fn stop(&mut self, idx: usize) -> Result<u64> {
        if idx >= self.num_counters {
            return Err(Error::InvalidArgument);
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.x86_disable_counter(idx);
            self.counters[idx].count = self.x86_read_counter(idx);
        }
        self.counters[idx].running = false;
        Ok(self.counters[idx].count)
    }

    /// Reads the current value of counter `idx` without stopping it.
    pub fn read(&mut self, idx: usize) -> Result<u64> {
        if idx >= self.num_counters {
            return Err(Error::InvalidArgument);
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.counters[idx].count = self.x86_read_counter(idx);
        }
        Ok(self.counters[idx].count)
    }

    /// Disables all counters.
    pub fn disable_all(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Disabling all performance counters via IA32_PERF_GLOBAL_CTRL.
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") x86_pmu::IA32_PERF_GLOBAL_CTRL,
                    in("eax") 0u32,
                    in("edx") 0u32,
                    options(nostack, nomem),
                );
            }
        }
        for c in self.counters.iter_mut() {
            c.running = false;
        }
    }

    // ---- x86-specific helpers ----

    #[cfg(target_arch = "x86_64")]
    fn event_select(event: PmuEventType) -> u64 {
        // Encode as (umask << 8) | event_sel per Intel Vol. 3B Table 18-1.
        match event {
            PmuEventType::Instructions => 0x00C0,
            PmuEventType::CpuCycles => 0x003C,
            PmuEventType::L1dCacheMiss => 0x0151,
            PmuEventType::L1iCacheMiss => 0x0280,
            PmuEventType::BranchInstructions => 0x00C4,
            PmuEventType::BranchMispredict => 0x00C5,
            PmuEventType::LlcMiss => 0x412E,
            PmuEventType::DtlbMiss => 0x0149,
            PmuEventType::ItlbMiss => 0x0285,
            PmuEventType::MemoryAccess => 0x43D0,
            PmuEventType::StalledCyclesFrontend => 0x019C,
            PmuEventType::StalledCyclesBackend => 0x029C,
            PmuEventType::Raw(code) => code,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn x86_program_counter(&self, idx: usize, cfg: &PmuCounterConfig) {
        let mut evtsel = Self::event_select(cfg.event) | x86_pmu::EN;
        if cfg.user_mode {
            evtsel |= x86_pmu::USR;
        }
        if cfg.kernel_mode {
            evtsel |= x86_pmu::OS;
        }
        let msr = x86_pmu::IA32_PERFEVTSEL_BASE + idx as u32;
        // SAFETY: Writing IA32_PERFEVTSELn MSR to program the event selector.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") (evtsel & 0xFFFF_FFFF) as u32,
                in("edx") (evtsel >> 32) as u32,
                options(nostack, nomem),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn x86_enable_counter(&self, idx: usize) {
        let bit: u64 = 1 << idx;
        // SAFETY: Enabling specific PMU counter via IA32_PERF_GLOBAL_CTRL.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") x86_pmu::IA32_PERF_GLOBAL_CTRL,
                in("eax") (bit & 0xFFFF_FFFF) as u32,
                in("edx") (bit >> 32) as u32,
                options(nostack, nomem),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn x86_disable_counter(&self, idx: usize) {
        let msr = x86_pmu::IA32_PERFEVTSEL_BASE + idx as u32;
        // SAFETY: Disabling specific PMU counter event selector.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, nomem),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn x86_read_counter(&self, idx: usize) -> u64 {
        let msr = x86_pmu::IA32_PMC_BASE + idx as u32;
        let lo: u32;
        let hi: u32;
        // SAFETY: Reading IA32_PMCn MSR for the counter value.
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
}

impl Default for PmuDriver {
    fn default() -> Self {
        Self::new(0, 4)
    }
}
