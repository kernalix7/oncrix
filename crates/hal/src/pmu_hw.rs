// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware Performance Monitoring Unit (PMU) abstraction.
//!
//! Provides a platform-independent interface for configuring and reading
//! hardware performance counters. Supports CPU cycle counts, instruction
//! retirement, cache events, and branch prediction statistics.

use oncrix_lib::{Error, Result};

/// Maximum number of hardware performance counters.
pub const MAX_PMU_COUNTERS: usize = 8;

/// PMU event types for hardware performance monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PmuEvent {
    /// CPU clock cycles elapsed.
    CpuCycles = 0x0011,
    /// Instructions retired (completed).
    InstructionsRetired = 0x00C0,
    /// L1 data cache references.
    L1DcacheReferences = 0x0143,
    /// L1 data cache misses.
    L1DcacheMisses = 0x0144,
    /// LLC (last-level cache) references.
    LlcReferences = 0x4F2E,
    /// LLC misses.
    LlcMisses = 0x412E,
    /// Branch instructions retired.
    BranchInstructions = 0x00C4,
    /// Branch mispredictions retired.
    BranchMisses = 0x00C5,
    /// TLB flushes.
    TlbFlushes = 0x0108,
    /// Context switches.
    ContextSwitches = 0x0001,
}

/// Configuration for a single PMU counter.
#[derive(Debug, Clone, Copy)]
pub struct PmuCounterConfig {
    /// The event this counter tracks.
    pub event: PmuEvent,
    /// Whether to count in user mode.
    pub user_mode: bool,
    /// Whether to count in kernel mode.
    pub kernel_mode: bool,
    /// Whether to enable interrupt on overflow.
    pub overflow_interrupt: bool,
    /// Sample period (0 = continuous).
    pub sample_period: u64,
}

impl PmuCounterConfig {
    /// Creates a new counter configuration for the given event.
    pub const fn new(event: PmuEvent) -> Self {
        Self {
            event,
            user_mode: true,
            kernel_mode: true,
            overflow_interrupt: false,
            sample_period: 0,
        }
    }

    /// Enables overflow interrupts with the given sample period.
    pub const fn with_sampling(mut self, period: u64) -> Self {
        self.overflow_interrupt = true;
        self.sample_period = period;
        self
    }
}

impl Default for PmuCounterConfig {
    fn default() -> Self {
        Self::new(PmuEvent::CpuCycles)
    }
}

/// A hardware PMU counter.
#[derive(Debug)]
pub struct PmuCounter {
    /// Counter index (0..MAX_PMU_COUNTERS).
    index: usize,
    /// Configuration applied to this counter.
    config: PmuCounterConfig,
    /// Whether this counter is currently active.
    active: bool,
    /// Accumulated overflow count.
    overflow_count: u64,
}

impl PmuCounter {
    /// Creates a new PMU counter at the given index.
    pub const fn new(index: usize, config: PmuCounterConfig) -> Self {
        Self {
            index,
            config,
            active: false,
            overflow_count: 0,
        }
    }

    /// Returns the counter index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the counter configuration.
    pub fn config(&self) -> &PmuCounterConfig {
        &self.config
    }

    /// Returns whether this counter is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the overflow count.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Increments the overflow count.
    pub(crate) fn record_overflow(&mut self) {
        self.overflow_count = self.overflow_count.saturating_add(1);
    }
}

impl Default for PmuCounter {
    fn default() -> Self {
        Self::new(0, PmuCounterConfig::default())
    }
}

/// Snapshot of all PMU counter values at a point in time.
#[derive(Debug, Clone, Copy, Default)]
pub struct PmuSnapshot {
    /// Raw counter values indexed by counter index.
    pub values: [u64; MAX_PMU_COUNTERS],
    /// Number of active counters in this snapshot.
    pub active_count: usize,
}

impl PmuSnapshot {
    /// Creates a new zeroed snapshot.
    pub const fn new() -> Self {
        Self {
            values: [0u64; MAX_PMU_COUNTERS],
            active_count: 0,
        }
    }
}

/// Hardware PMU controller managing all performance counters.
pub struct PmuController {
    /// Base MMIO address of the PMU registers.
    base_addr: u64,
    /// Individual counter states.
    counters: [PmuCounter; MAX_PMU_COUNTERS],
    /// Number of counters currently configured.
    counter_count: usize,
    /// Whether the PMU has been initialized.
    initialized: bool,
}

impl PmuController {
    /// Creates a new PMU controller.
    ///
    /// # Arguments
    /// * `base_addr` — MMIO base address of the PMU register block.
    pub fn new(base_addr: u64) -> Self {
        Self {
            base_addr,
            counters: [
                PmuCounter::new(0, PmuCounterConfig::default()),
                PmuCounter::new(1, PmuCounterConfig::default()),
                PmuCounter::new(2, PmuCounterConfig::default()),
                PmuCounter::new(3, PmuCounterConfig::default()),
                PmuCounter::new(4, PmuCounterConfig::default()),
                PmuCounter::new(5, PmuCounterConfig::default()),
                PmuCounter::new(6, PmuCounterConfig::default()),
                PmuCounter::new(7, PmuCounterConfig::default()),
            ],
            counter_count: 0,
            initialized: false,
        }
    }

    /// Initializes the PMU hardware.
    ///
    /// Must be called before configuring or reading any counters.
    ///
    /// # Errors
    /// Returns `Error::IoError` if hardware initialization fails.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to PMU global control register at known-valid base_addr.
        unsafe {
            let ctrl = self.base_addr as *mut u64;
            ctrl.write_volatile(0); // Disable all counters first
        }
        self.initialized = true;
        Ok(())
    }

    /// Configures a performance counter.
    ///
    /// # Arguments
    /// * `index` — Counter index (0..MAX_PMU_COUNTERS).
    /// * `config` — Counter configuration.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if index is out of range.
    /// Returns `Error::Busy` if the PMU has not been initialized.
    pub fn configure_counter(&mut self, index: usize, config: PmuCounterConfig) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if index >= MAX_PMU_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        self.counters[index] = PmuCounter::new(index, config);

        // SAFETY: MMIO write to PMU event selection register. base_addr is valid
        // and index is bounds-checked above.
        unsafe {
            let evtsel = (self.base_addr + 0x400 + (index as u64) * 8) as *mut u32;
            let mut evtsel_val = config.event as u32;
            if config.user_mode {
                evtsel_val |= 1 << 16;
            }
            if config.kernel_mode {
                evtsel_val |= 1 << 17;
            }
            if config.overflow_interrupt {
                evtsel_val |= 1 << 20;
            }
            evtsel_val |= 1 << 22; // Enable bit
            evtsel.write_volatile(evtsel_val);
        }

        if index >= self.counter_count {
            self.counter_count = index + 1;
        }
        Ok(())
    }

    /// Enables all configured performance counters.
    ///
    /// # Errors
    /// Returns `Error::Busy` if the PMU has not been initialized.
    pub fn enable_all(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to PMU global enable register. base_addr is valid
        // and was checked during init().
        unsafe {
            let ctrl = self.base_addr as *mut u64;
            let current = ctrl.read_volatile();
            ctrl.write_volatile(current | 0x1); // Set global enable bit
        }
        for c in self.counters[..self.counter_count].iter_mut() {
            c.active = true;
        }
        Ok(())
    }

    /// Disables all performance counters.
    pub fn disable_all(&mut self) {
        if !self.initialized {
            return;
        }
        // SAFETY: MMIO write to PMU global enable register. base_addr is valid.
        unsafe {
            let ctrl = self.base_addr as *mut u64;
            let current = ctrl.read_volatile();
            ctrl.write_volatile(current & !0x1);
        }
        for c in self.counters[..self.counter_count].iter_mut() {
            c.active = false;
        }
    }

    /// Reads the current value of a specific counter.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if index is out of range.
    /// Returns `Error::Busy` if the PMU has not been initialized.
    pub fn read_counter(&self, index: usize) -> Result<u64> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if index >= MAX_PMU_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO read from PMU counter data register. base_addr is valid
        // and index is bounds-checked above.
        let val = unsafe {
            let ctr = (self.base_addr + 0x300 + (index as u64) * 8) as *const u64;
            ctr.read_volatile()
        };
        Ok(val)
    }

    /// Takes a snapshot of all active counter values.
    ///
    /// # Errors
    /// Returns `Error::Busy` if the PMU has not been initialized.
    pub fn snapshot(&self) -> Result<PmuSnapshot> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let mut snap = PmuSnapshot::new();
        snap.active_count = self.counter_count;
        for i in 0..self.counter_count {
            snap.values[i] = self.read_counter(i)?;
        }
        Ok(snap)
    }

    /// Resets all counter values to zero.
    ///
    /// # Errors
    /// Returns `Error::Busy` if the PMU has not been initialized.
    pub fn reset_counters(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO writes to PMU counter reset registers. base_addr is valid.
        unsafe {
            let ctrl = self.base_addr as *mut u64;
            let current = ctrl.read_volatile();
            ctrl.write_volatile(current | (1 << 1)); // Counter reset bit
            ctrl.write_volatile(current & !(1 << 1));
        }
        Ok(())
    }
}

impl Default for PmuController {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Reads the CPU cycle counter using architecture-specific instructions.
///
/// On x86_64 uses the RDTSC instruction. Returns raw counter value.
pub fn read_cpu_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC is a safe read-only instruction available in user and kernel mode.
        unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
            ((hi as u64) << 32) | lo as u64
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    0u64
}

/// Reads the instruction-retired counter from MSR (x86_64 only).
///
/// # Errors
/// Returns `Error::NotImplemented` on non-x86_64 architectures.
pub fn read_instructions_retired() -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDMSR reads MSR 0xC0000096 (FIXED_CTR0 - instructions retired).
        // Must be executed at ring 0.
        let val = unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!(
                "rdmsr",
                in("ecx") 0xC0000096u32,
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
            ((hi as u64) << 32) | lo as u64
        };
        Ok(val)
    }
    #[cfg(not(target_arch = "x86_64"))]
    Err(Error::NotImplemented)
}

/// Computes instructions-per-cycle (IPC) from a before/after snapshot pair.
///
/// Returns 0.0 represented as a fixed-point value (value * 1000) if cycles == 0.
pub fn compute_ipc_fixed(instructions: u64, cycles: u64) -> u64 {
    if cycles == 0 {
        return 0;
    }
    (instructions * 1000) / cycles
}
