// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Performance Monitoring Unit (PMU) abstraction.
//!
//! Provides access to hardware performance counters and events available
//! on x86_64 CPUs via the Performance Monitoring Unit. Implements a
//! Linux-style perf subsystem adapted for a no_std microkernel.
//!
//! # Architecture
//!
//! - [`PmuEvent`] — named hardware event (cycles, instructions, cache misses…)
//! - [`PmuCounter`] — a single programmable performance counter
//! - [`PmuConfig`] — counter configuration (event, user/kernel mode, edge…)
//! - [`PmuState`] — global PMU state for one logical CPU
//! - [`PmuRegistry`] — manages PMU state for up to [`MAX_CPUS`] CPUs
//!
//! # x86_64 MSR layout
//!
//! - `IA32_PERFEVTSELx` (0x186 + n) — event select MSRs (one per counter)
//! - `IA32_PMCx` (0xC1 + n) — counter MSRs (one per counter)
//! - `IA32_FIXED_CTR_CTRL` (0x38D) — fixed counter control
//! - `IA32_FIXED_CTRx` (0x309–0x30B) — fixed-function counters
//! - `IA32_PERF_GLOBAL_CTRL` (0x38F) — enable/disable all counters
//! - `IA32_PERF_GLOBAL_STATUS` (0x38E) — overflow status
//! - `IA32_PERF_GLOBAL_OVF_CTRL` (0x390) — clear overflow bits
//!
//! Reference: Intel 64 and IA-32 Architecture Software Developer's Manual,
//! Volume 3B, Chapter 19 (Performance Monitoring).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum programmable counters per CPU (architectural PMU v3+).
pub const MAX_GP_COUNTERS: usize = 4;

/// Maximum fixed-function counters per CPU.
pub const MAX_FIXED_COUNTERS: usize = 3;

/// Maximum number of CPUs tracked.
const MAX_CPUS: usize = 64;

/// Maximum length of a counter label.
pub const MAX_LABEL_LEN: usize = 64;

// ---------------------------------------------------------------------------
// x86_64 MSR addresses
// ---------------------------------------------------------------------------

/// MSR base for event-select registers (`IA32_PERFEVTSELx`).
const MSR_PERFEVTSEL_BASE: u32 = 0x186;

/// MSR base for general-purpose counter values (`IA32_PMCx`).
const MSR_PMC_BASE: u32 = 0xC1;

/// MSR for fixed-counter control (`IA32_FIXED_CTR_CTRL`).
const MSR_FIXED_CTR_CTRL: u32 = 0x38D;

/// MSR base for fixed-function counters.
const MSR_FIXED_CTR_BASE: u32 = 0x309;

/// MSR for global counter enable (`IA32_PERF_GLOBAL_CTRL`).
const MSR_PERF_GLOBAL_CTRL: u32 = 0x38F;

/// MSR for global overflow status (`IA32_PERF_GLOBAL_STATUS`).
const MSR_PERF_GLOBAL_STATUS: u32 = 0x38E;

/// MSR for clearing overflow bits (`IA32_PERF_GLOBAL_OVF_CTRL`).
const MSR_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

// ---------------------------------------------------------------------------
// PERFEVTSEL bit fields (Intel SDM Vol. 3B §19.2.2)
// ---------------------------------------------------------------------------

/// Enable counting in user mode (CPL > 0).
const EVTSEL_USR: u32 = 1 << 16;

/// Enable counting in kernel mode (CPL = 0).
const EVTSEL_OS: u32 = 1 << 17;

/// Count on rising edge (edge detect).
const EVTSEL_EDGE: u32 = 1 << 18;

/// Enable APIC interrupt on overflow.
const EVTSEL_INT: u32 = 1 << 20;

/// Enable this counter.
const EVTSEL_EN: u32 = 1 << 22;

/// Invert the CMASK comparison.
const EVTSEL_INV: u32 = 1 << 23;

// ---------------------------------------------------------------------------
// PmuEvent
// ---------------------------------------------------------------------------

/// Named hardware performance event.
///
/// Each variant corresponds to an architectural or model-specific
/// performance event that can be programmed into a general-purpose
/// counter via `IA32_PERFEVTSELx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmuEvent {
    /// CPU cycles (unhalted reference cycles).
    Cycles,
    /// Retired instructions.
    Instructions,
    /// Last-level cache references.
    LlcReferences,
    /// Last-level cache misses.
    LlcMisses,
    /// Branch instructions retired.
    BranchInstructions,
    /// Branch mispredictions retired.
    BranchMisses,
    /// Bus cycles (reference clock).
    BusCycles,
    /// All stalls (front-end + back-end).
    StalledCycles,
    /// Custom event specified by raw (event_select, umask) pair.
    Raw {
        /// PERFEVTSEL[7:0] event select byte.
        event_select: u8,
        /// PERFEVTSEL[15:8] unit mask byte.
        umask: u8,
    },
}

impl PmuEvent {
    /// Returns the `(event_select, umask)` pair for this event.
    ///
    /// Architectural events from Intel SDM Vol. 3B Table 19-1.
    pub const fn event_umask(self) -> (u8, u8) {
        match self {
            PmuEvent::Cycles => (0x3C, 0x00),
            PmuEvent::Instructions => (0xC0, 0x00),
            PmuEvent::LlcReferences => (0x2E, 0x4F),
            PmuEvent::LlcMisses => (0x2E, 0x41),
            PmuEvent::BranchInstructions => (0xC4, 0x00),
            PmuEvent::BranchMisses => (0xC5, 0x00),
            PmuEvent::BusCycles => (0x3C, 0x01),
            PmuEvent::StalledCycles => (0x0E, 0x01),
            PmuEvent::Raw {
                event_select,
                umask,
            } => (event_select, umask),
        }
    }
}

// ---------------------------------------------------------------------------
// FixedEvent
// ---------------------------------------------------------------------------

/// Fixed-function hardware counter event.
///
/// These counters (IA32_FIXED_CTR0–2) count predefined events and
/// cannot be reprogrammed to other events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedEvent {
    /// Fixed counter 0: Instructions retired.
    InstructionsRetired,
    /// Fixed counter 1: Unhalted core cycles.
    UnhaltedCoreCycles,
    /// Fixed counter 2: Unhalted reference cycles.
    UnhaltedReferenceCycles,
}

impl FixedEvent {
    /// Returns the zero-based index of this fixed counter.
    pub const fn index(self) -> usize {
        match self {
            FixedEvent::InstructionsRetired => 0,
            FixedEvent::UnhaltedCoreCycles => 1,
            FixedEvent::UnhaltedReferenceCycles => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// CounterMode
// ---------------------------------------------------------------------------

/// Privilege-level filter for performance counter sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CounterMode {
    /// Count events in both user and kernel modes.
    #[default]
    All,
    /// Count events only in user mode (CPL > 0).
    UserOnly,
    /// Count events only in kernel mode (CPL = 0).
    KernelOnly,
}

// ---------------------------------------------------------------------------
// PmuConfig
// ---------------------------------------------------------------------------

/// Configuration for a single general-purpose PMU counter.
#[derive(Debug, Clone, Copy)]
pub struct PmuConfig {
    /// The hardware event to count.
    pub event: PmuEvent,
    /// Privilege-level filter.
    pub mode: CounterMode,
    /// Enable edge detection (count transitions, not levels).
    pub edge_detect: bool,
    /// Enable overflow interrupt.
    pub overflow_int: bool,
    /// CMASK: minimum count per cycle (0 = disabled).
    pub cmask: u8,
    /// Invert the CMASK comparison.
    pub invert: bool,
    /// Initial counter value (useful for sampling with a large negative value).
    pub initial_value: i64,
    /// Human-readable label for this counter slot.
    pub label: [u8; MAX_LABEL_LEN],
    /// Number of valid bytes in `label`.
    pub label_len: usize,
}

impl PmuConfig {
    /// Create a minimal config for `event` counting all privilege levels.
    pub fn new(event: PmuEvent) -> Self {
        Self {
            event,
            mode: CounterMode::All,
            edge_detect: false,
            overflow_int: false,
            cmask: 0,
            invert: false,
            initial_value: 0,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
        }
    }

    /// Build the `IA32_PERFEVTSELx` 64-bit value from this config.
    pub fn evtsel_value(&self) -> u64 {
        let (ev, um) = self.event.event_umask();
        let mut val = (ev as u32) | ((um as u32) << 8);
        match self.mode {
            CounterMode::All => val |= EVTSEL_USR | EVTSEL_OS,
            CounterMode::UserOnly => val |= EVTSEL_USR,
            CounterMode::KernelOnly => val |= EVTSEL_OS,
        }
        if self.edge_detect {
            val |= EVTSEL_EDGE;
        }
        if self.overflow_int {
            val |= EVTSEL_INT;
        }
        if self.cmask != 0 {
            val |= (self.cmask as u32) << 24;
        }
        if self.invert {
            val |= EVTSEL_INV;
        }
        val |= EVTSEL_EN;
        val as u64
    }
}

// ---------------------------------------------------------------------------
// PmuCounter
// ---------------------------------------------------------------------------

/// State of a single general-purpose performance counter.
#[derive(Debug, Clone, Copy)]
pub struct PmuCounter {
    /// Zero-based counter index (0..`MAX_GP_COUNTERS`).
    pub index: usize,
    /// Whether this counter is currently active.
    pub active: bool,
    /// Current configuration.
    pub config: Option<PmuConfig>,
    /// Accumulated count (from previous start/stop cycles).
    pub accumulated: u64,
    /// Value read at the last `start()` call.
    pub start_value: u64,
    /// Number of overflow events detected.
    pub overflow_count: u64,
}

impl PmuCounter {
    const fn new(index: usize) -> Self {
        Self {
            index,
            active: false,
            config: None,
            accumulated: 0,
            start_value: 0,
            overflow_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PmuFixedCounter
// ---------------------------------------------------------------------------

/// State of a fixed-function performance counter.
#[derive(Debug, Clone, Copy)]
pub struct PmuFixedCounter {
    /// Which fixed event this counter measures.
    pub event: Option<FixedEvent>,
    /// Whether counting is enabled.
    pub active: bool,
    /// Accumulated count.
    pub accumulated: u64,
    /// Value read at the last start.
    pub start_value: u64,
}

impl PmuFixedCounter {
    const fn new() -> Self {
        Self {
            event: None,
            active: false,
            accumulated: 0,
            start_value: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// OverflowStatus
// ---------------------------------------------------------------------------

/// Bitmask of counters that have overflowed since the last clear.
///
/// Bits 0..`MAX_GP_COUNTERS` correspond to general-purpose counters;
/// bits 32..35 correspond to fixed counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct OverflowStatus {
    /// Raw `IA32_PERF_GLOBAL_STATUS` value.
    pub raw: u64,
}

impl OverflowStatus {
    /// Returns `true` if general-purpose counter `n` has overflowed.
    pub fn gp_overflow(&self, n: usize) -> bool {
        n < MAX_GP_COUNTERS && (self.raw >> n) & 1 != 0
    }

    /// Returns `true` if fixed counter `n` has overflowed.
    pub fn fixed_overflow(&self, n: usize) -> bool {
        n < MAX_FIXED_COUNTERS && (self.raw >> (32 + n)) & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// PmuState (per-CPU)
// ---------------------------------------------------------------------------

/// Per-CPU PMU state.
pub struct PmuState {
    /// Logical CPU this state belongs to.
    pub cpu_id: u32,
    /// General-purpose counter slots.
    pub counters: [PmuCounter; MAX_GP_COUNTERS],
    /// Fixed-function counter slots.
    pub fixed: [PmuFixedCounter; MAX_FIXED_COUNTERS],
    /// Whether the PMU has been initialized on this CPU.
    pub initialized: bool,
}

impl PmuState {
    /// Create a new, uninitialised PMU state for `cpu_id`.
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            counters: [
                PmuCounter::new(0),
                PmuCounter::new(1),
                PmuCounter::new(2),
                PmuCounter::new(3),
            ],
            fixed: [
                PmuFixedCounter::new(),
                PmuFixedCounter::new(),
                PmuFixedCounter::new(),
            ],
            initialized: false,
        }
    }

    /// Initialize the PMU on this CPU.
    ///
    /// Disables all counters and clears overflow status.
    ///
    /// # Safety
    ///
    /// Must be called from the CPU identified by `cpu_id`. Writes to
    /// model-specific registers via `wrmsr`.
    pub fn init(&mut self) -> Result<()> {
        // Disable all counters via global control.
        // SAFETY: Writing IA32_PERF_GLOBAL_CTRL=0 disables all counters.
        // This is safe to call from any privilege level.
        unsafe { wrmsr(MSR_PERF_GLOBAL_CTRL, 0) };

        // Clear all event-select MSRs.
        for i in 0..MAX_GP_COUNTERS {
            // SAFETY: Writing 0 to IA32_PERFEVTSELx disables the counter.
            unsafe { wrmsr(MSR_PERFEVTSEL_BASE + i as u32, 0) };
        }

        // Disable fixed counters.
        // SAFETY: Writing 0 to IA32_FIXED_CTR_CTRL disables all fixed counters.
        unsafe { wrmsr(MSR_FIXED_CTR_CTRL, 0) };

        // Clear overflow status.
        // SAFETY: Writing 1s to OVF_CTRL clears corresponding overflow bits.
        unsafe { wrmsr(MSR_PERF_GLOBAL_OVF_CTRL, 0xFFFF_FFFF_FFFF_FFFF) };

        self.initialized = true;
        Ok(())
    }

    /// Program general-purpose counter `n` with `config`.
    ///
    /// Returns [`Error::InvalidArgument`] if `n >= MAX_GP_COUNTERS`.
    /// Returns [`Error::Busy`] if the counter is already active.
    pub fn program(&mut self, n: usize, config: PmuConfig) -> Result<()> {
        if n >= MAX_GP_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.counters[n].active {
            return Err(Error::Busy);
        }
        // Write event-select MSR (counter disabled until global enable).
        // SAFETY: MSR_PERFEVTSEL_BASE + n is a valid PERFEVTSEL MSR for n < 4.
        unsafe { wrmsr(MSR_PERFEVTSEL_BASE + n as u32, config.evtsel_value()) };
        // Set initial counter value.
        let init = config.initial_value as u64;
        // SAFETY: MSR_PMC_BASE + n is a valid PMC MSR for n < 4.
        unsafe { wrmsr(MSR_PMC_BASE + n as u32, init) };
        self.counters[n].config = Some(config);
        self.counters[n].accumulated = 0;
        self.counters[n].overflow_count = 0;
        Ok(())
    }

    /// Enable (start) general-purpose counter `n`.
    ///
    /// Activates the counter by enabling its bit in `IA32_PERF_GLOBAL_CTRL`.
    pub fn start(&mut self, n: usize) -> Result<()> {
        if n >= MAX_GP_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        if !self.initialized || self.counters[n].config.is_none() {
            return Err(Error::IoError);
        }
        // Read current PMC value.
        // SAFETY: MSR_PMC_BASE + n is valid for n < MAX_GP_COUNTERS.
        let start_val = unsafe { rdmsr(MSR_PMC_BASE + n as u32) };
        self.counters[n].start_value = start_val;
        self.counters[n].active = true;

        // Enable this counter in global control.
        // SAFETY: Reading then writing IA32_PERF_GLOBAL_CTRL to set bit n.
        let ctrl = unsafe { rdmsr(MSR_PERF_GLOBAL_CTRL) };
        // SAFETY: Writing back with the counter's enable bit set.
        unsafe { wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl | (1u64 << n)) };
        Ok(())
    }

    /// Disable (stop) general-purpose counter `n` and accumulate the delta.
    ///
    /// Returns the total accumulated count since `program()`.
    pub fn stop(&mut self, n: usize) -> Result<u64> {
        if n >= MAX_GP_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        if !self.initialized || !self.counters[n].active {
            return Err(Error::IoError);
        }
        // Disable this counter in global control.
        // SAFETY: Clearing bit n in IA32_PERF_GLOBAL_CTRL stops the counter.
        let ctrl = unsafe { rdmsr(MSR_PERF_GLOBAL_CTRL) };
        // SAFETY: Writing back with the counter's enable bit cleared.
        unsafe { wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl & !(1u64 << n)) };

        // Read current value and compute delta.
        // SAFETY: MSR_PMC_BASE + n is valid for n < MAX_GP_COUNTERS.
        let cur = unsafe { rdmsr(MSR_PMC_BASE + n as u32) };
        let delta = cur.wrapping_sub(self.counters[n].start_value);
        self.counters[n].accumulated = self.counters[n].accumulated.wrapping_add(delta);
        self.counters[n].active = false;
        Ok(self.counters[n].accumulated)
    }

    /// Read the current value of general-purpose counter `n` without stopping it.
    pub fn read(&self, n: usize) -> Result<u64> {
        if n >= MAX_GP_COUNTERS {
            return Err(Error::InvalidArgument);
        }
        if !self.initialized {
            return Err(Error::IoError);
        }
        // SAFETY: MSR_PMC_BASE + n is valid for n < MAX_GP_COUNTERS.
        let raw = unsafe { rdmsr(MSR_PMC_BASE + n as u32) };
        if self.counters[n].active {
            let delta = raw.wrapping_sub(self.counters[n].start_value);
            Ok(self.counters[n].accumulated.wrapping_add(delta))
        } else {
            Ok(self.counters[n].accumulated)
        }
    }

    /// Enable a fixed-function counter for `event`.
    ///
    /// Enables both user and kernel-mode counting.
    pub fn enable_fixed(&mut self, event: FixedEvent) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let idx = event.index();
        if self.fixed[idx].active {
            return Err(Error::Busy);
        }
        // Fixed counter ctrl: 2 bits per counter, bits[1:0] = 0b11 (usr+os), bit[3] = PMI enable.
        // SAFETY: Reading IA32_FIXED_CTR_CTRL to update the field for this counter.
        let ctrl = unsafe { rdmsr(MSR_FIXED_CTR_CTRL) };
        let shift = idx * 4;
        let new_ctrl = (ctrl & !(0xF << shift)) | (0x3u64 << shift);
        // SAFETY: Writing updated IA32_FIXED_CTR_CTRL.
        unsafe { wrmsr(MSR_FIXED_CTR_CTRL, new_ctrl) };

        // Enable in global control (fixed counters occupy bits 32+idx).
        // SAFETY: Reading IA32_PERF_GLOBAL_CTRL to set the fixed counter enable bit.
        let gctrl = unsafe { rdmsr(MSR_PERF_GLOBAL_CTRL) };
        // SAFETY: Writing back with fixed counter enable bit set.
        unsafe { wrmsr(MSR_PERF_GLOBAL_CTRL, gctrl | (1u64 << (32 + idx))) };

        // SAFETY: MSR_FIXED_CTR_BASE + idx is valid for idx < MAX_FIXED_COUNTERS.
        let start_val = unsafe { rdmsr(MSR_FIXED_CTR_BASE + idx as u32) };
        self.fixed[idx].event = Some(event);
        self.fixed[idx].start_value = start_val;
        self.fixed[idx].active = true;
        Ok(())
    }

    /// Read the accumulated value of a fixed counter.
    pub fn read_fixed(&self, event: FixedEvent) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let idx = event.index();
        if !self.fixed[idx].active {
            return Err(Error::IoError);
        }
        // SAFETY: MSR_FIXED_CTR_BASE + idx is valid for idx < MAX_FIXED_COUNTERS.
        let raw = unsafe { rdmsr(MSR_FIXED_CTR_BASE + idx as u32) };
        let delta = raw.wrapping_sub(self.fixed[idx].start_value);
        Ok(self.fixed[idx].accumulated.wrapping_add(delta))
    }

    /// Read and clear the overflow status register.
    pub fn read_overflow(&self) -> OverflowStatus {
        // SAFETY: IA32_PERF_GLOBAL_STATUS is a read-only status MSR.
        let raw = unsafe { rdmsr(MSR_PERF_GLOBAL_STATUS) };
        OverflowStatus { raw }
    }

    /// Clear overflow status bits for all overflowed counters.
    pub fn clear_overflow(&self) {
        // SAFETY: Writing 1s to OVF_CTRL clears the corresponding overflow bits.
        unsafe { wrmsr(MSR_PERF_GLOBAL_OVF_CTRL, 0xFFFF_FFFF_FFFF_FFFF) };
    }

    /// Reset all counters and accumulated values to zero.
    pub fn reset_all(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        // Disable all.
        // SAFETY: Writing 0 to IA32_PERF_GLOBAL_CTRL disables all counters.
        unsafe { wrmsr(MSR_PERF_GLOBAL_CTRL, 0) };
        for i in 0..MAX_GP_COUNTERS {
            // SAFETY: Writing 0 to IA32_PERFEVTSELx disables counter i.
            unsafe { wrmsr(MSR_PERFEVTSEL_BASE + i as u32, 0) };
            // SAFETY: Writing 0 to IA32_PMCx clears counter i.
            unsafe { wrmsr(MSR_PMC_BASE + i as u32, 0) };
            self.counters[i].active = false;
            self.counters[i].accumulated = 0;
            self.counters[i].overflow_count = 0;
            self.counters[i].config = None;
        }
        for i in 0..MAX_FIXED_COUNTERS {
            // SAFETY: Writing 0 to IA32_FIXED_CTRx clears fixed counter i.
            unsafe { wrmsr(MSR_FIXED_CTR_BASE + i as u32, 0) };
            self.fixed[i].active = false;
            self.fixed[i].accumulated = 0;
            self.fixed[i].event = None;
        }
        // SAFETY: Clearing IA32_FIXED_CTR_CTRL disables all fixed counters.
        unsafe { wrmsr(MSR_FIXED_CTR_CTRL, 0) };
        // SAFETY: Clearing overflow status bits.
        unsafe { wrmsr(MSR_PERF_GLOBAL_OVF_CTRL, 0xFFFF_FFFF_FFFF_FFFF) };
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PmuRegistry
// ---------------------------------------------------------------------------

/// Global PMU registry managing per-CPU [`PmuState`].
pub struct PmuRegistry {
    /// Per-CPU PMU state; `None` when the CPU has not been registered.
    states: [Option<PmuState>; MAX_CPUS],
    /// Number of registered CPUs.
    count: usize,
}

impl Default for PmuRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PmuRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            states: [const { None }; MAX_CPUS],
            count: 0,
        }
    }

    /// Register and initialize the PMU for `cpu_id`.
    ///
    /// Returns [`Error::AlreadyExists`] if the CPU is already registered,
    /// or [`Error::InvalidArgument`] if `cpu_id >= MAX_CPUS`.
    pub fn register(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.states[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        let mut state = PmuState::new(cpu_id);
        state.init()?;
        self.states[idx] = Some(state);
        self.count += 1;
        Ok(())
    }

    /// Unregister and reset the PMU for `cpu_id`.
    ///
    /// Returns [`Error::NotFound`] if the CPU is not registered.
    pub fn unregister(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || self.states[idx].is_none() {
            return Err(Error::NotFound);
        }
        if let Some(ref mut state) = self.states[idx] {
            let _ = state.reset_all();
        }
        self.states[idx] = None;
        self.count -= 1;
        Ok(())
    }

    /// Get a shared reference to the PMU state for `cpu_id`.
    pub fn get(&self, cpu_id: u32) -> Result<&PmuState> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS {
            self.states[idx].as_ref().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Get an exclusive reference to the PMU state for `cpu_id`.
    pub fn get_mut(&mut self, cpu_id: u32) -> Result<&mut PmuState> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS {
            self.states[idx].as_mut().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Number of registered CPUs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no CPUs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// x86_64 MSR helpers
// ---------------------------------------------------------------------------

/// Write a 64-bit value to a model-specific register.
///
/// # Safety
///
/// The caller must ensure `msr` is a valid, writable MSR address and
/// that `value` is within the range permitted by that MSR's specification.
/// This instruction is ring-0 only; executing it at CPL > 0 causes #GP.
#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: Caller guarantees valid MSR and ring-0 context.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// Read a 64-bit value from a model-specific register.
///
/// # Safety
///
/// The caller must ensure `msr` is a valid, readable MSR address.
/// This instruction is ring-0 only; executing it at CPL > 0 causes #GP.
#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Caller guarantees valid MSR and ring-0 context.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    (hi as u64) << 32 | lo as u64
}

// Stub implementations for non-x86_64 targets to allow cross-compilation.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn wrmsr(_msr: u32, _value: u64) {}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn rdmsr(_msr: u32) -> u64 {
    0
}
