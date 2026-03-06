// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Return probes for function exit tracing.
//!
//! Kretprobes allow instrumenting the return path of kernel functions.
//! When a probed function is called, the return address is saved and
//! replaced with a trampoline. On function return the trampoline
//! invokes the registered handler before resuming normal execution.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of simultaneous kretprobe registrations.
const MAX_KRETPROBES: usize = 128;

/// Maximum return instances per probe.
const MAX_RETURN_INSTANCES: usize = 64;

/// Default number of pre-allocated return instances.
const DEFAULT_MAXACTIVE: u32 = 16;

/// Kretprobe instance state flags.
const INSTANCE_STATE_FREE: u8 = 0;
const INSTANCE_STATE_ACTIVE: u8 = 1;
const INSTANCE_STATE_RETIRED: u8 = 2;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a kretprobe registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KretprobeId(u64);

impl KretprobeId {
    /// Creates a new kretprobe identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A single return instance tracking an in-flight function call.
#[derive(Debug, Clone)]
pub struct ReturnInstance {
    /// Owning kretprobe identifier.
    probe_id: KretprobeId,
    /// Original return address that was replaced.
    original_ret_addr: u64,
    /// Address of the probed function entry.
    entry_addr: u64,
    /// Timestamp when the function was entered (in nanoseconds).
    entry_timestamp_ns: u64,
    /// Task (PID) that hit the probe.
    task_pid: u64,
    /// Instance state.
    state: u8,
}

impl ReturnInstance {
    /// Creates a new return instance.
    pub const fn new(probe_id: KretprobeId, original_ret_addr: u64, entry_addr: u64) -> Self {
        Self {
            probe_id,
            original_ret_addr,
            entry_addr,
            entry_timestamp_ns: 0,
            task_pid: 0,
            state: INSTANCE_STATE_FREE,
        }
    }

    /// Returns the original return address.
    pub const fn original_ret_addr(&self) -> u64 {
        self.original_ret_addr
    }

    /// Returns whether this instance is currently active.
    pub const fn is_active(&self) -> bool {
        self.state == INSTANCE_STATE_ACTIVE
    }
}

/// Registration record for a single kretprobe.
#[derive(Debug)]
pub struct KretprobeRegistration {
    /// Probe identifier.
    id: KretprobeId,
    /// Address of the probed function.
    function_addr: u64,
    /// Symbol name of the probed function (truncated).
    symbol_name: [u8; 64],
    /// Length of valid bytes in symbol_name.
    symbol_len: usize,
    /// Maximum number of concurrent active instances.
    maxactive: u32,
    /// Number of currently active instances.
    active_count: u32,
    /// Total number of times the entry handler fired.
    entry_hits: u64,
    /// Total number of times the return handler fired.
    return_hits: u64,
    /// Number of missed probes (no free instance).
    missed_count: u64,
    /// Whether this probe is currently enabled.
    enabled: bool,
}

impl KretprobeRegistration {
    /// Creates a new kretprobe registration.
    pub const fn new(id: KretprobeId, function_addr: u64, maxactive: u32) -> Self {
        Self {
            id,
            function_addr,
            symbol_name: [0u8; 64],
            symbol_len: 0,
            maxactive,
            active_count: 0,
            entry_hits: 0,
            return_hits: 0,
            missed_count: 0,
            enabled: false,
        }
    }

    /// Returns the probed function address.
    pub const fn function_addr(&self) -> u64 {
        self.function_addr
    }

    /// Returns whether this probe is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the number of missed probes.
    pub const fn missed_count(&self) -> u64 {
        self.missed_count
    }
}

/// Statistics for the kretprobe subsystem.
#[derive(Debug, Clone)]
pub struct KretprobeStats {
    /// Total registered probes.
    pub total_registered: u32,
    /// Total active probes.
    pub total_enabled: u32,
    /// Total entry handler invocations across all probes.
    pub total_entry_hits: u64,
    /// Total return handler invocations across all probes.
    pub total_return_hits: u64,
    /// Total missed probes across all registrations.
    pub total_missed: u64,
}

impl Default for KretprobeStats {
    fn default() -> Self {
        Self::new()
    }
}

impl KretprobeStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_registered: 0,
            total_enabled: 0,
            total_entry_hits: 0,
            total_return_hits: 0,
            total_missed: 0,
        }
    }
}

/// Central kretprobe manager.
#[derive(Debug)]
pub struct KretprobeManager {
    /// Registered probes.
    probes: [Option<KretprobeRegistration>; MAX_KRETPROBES],
    /// Number of registered probes.
    probe_count: usize,
    /// Next probe identifier to assign.
    next_id: u64,
    /// Whether the subsystem is initialized.
    initialized: bool,
}

impl Default for KretprobeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KretprobeManager {
    /// Creates a new kretprobe manager.
    pub const fn new() -> Self {
        Self {
            probes: [const { None }; MAX_KRETPROBES],
            probe_count: 0,
            next_id: 1,
            initialized: false,
        }
    }

    /// Initializes the kretprobe subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Registers a new kretprobe on a function address.
    pub fn register(&mut self, function_addr: u64, maxactive: u32) -> Result<KretprobeId> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.probe_count >= MAX_KRETPROBES {
            return Err(Error::OutOfMemory);
        }
        let effective_max = if maxactive == 0 {
            DEFAULT_MAXACTIVE
        } else {
            maxactive
        };
        let id = KretprobeId::new(self.next_id);
        self.next_id += 1;
        let reg = KretprobeRegistration::new(id, function_addr, effective_max);
        if let Some(slot) = self.probes.iter_mut().find(|s| s.is_none()) {
            *slot = Some(reg);
            self.probe_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Enables a registered kretprobe.
    pub fn enable(&mut self, id: KretprobeId) -> Result<()> {
        let reg = self
            .probes
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        if reg.enabled {
            return Ok(());
        }
        reg.enabled = true;
        Ok(())
    }

    /// Disables a registered kretprobe.
    pub fn disable(&mut self, id: KretprobeId) -> Result<()> {
        let reg = self
            .probes
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        reg.enabled = false;
        Ok(())
    }

    /// Records an entry hit for the given probe.
    pub fn record_entry(&mut self, id: KretprobeId) -> Result<()> {
        let reg = self
            .probes
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        if !reg.enabled {
            return Err(Error::InvalidArgument);
        }
        if reg.active_count >= reg.maxactive {
            reg.missed_count += 1;
            return Err(Error::Busy);
        }
        reg.active_count += 1;
        reg.entry_hits += 1;
        Ok(())
    }

    /// Records a return hit for the given probe.
    pub fn record_return(&mut self, id: KretprobeId) -> Result<()> {
        let reg = self
            .probes
            .iter_mut()
            .flatten()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        if reg.active_count == 0 {
            return Err(Error::InvalidArgument);
        }
        reg.active_count -= 1;
        reg.return_hits += 1;
        Ok(())
    }

    /// Unregisters a kretprobe.
    pub fn unregister(&mut self, id: KretprobeId) -> Result<()> {
        let slot = self
            .probes
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |r| r.id == id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.probe_count -= 1;
        Ok(())
    }

    /// Collects aggregate statistics.
    pub fn stats(&self) -> KretprobeStats {
        let mut s = KretprobeStats::new();
        for reg in self.probes.iter().flatten() {
            s.total_registered += 1;
            if reg.enabled {
                s.total_enabled += 1;
            }
            s.total_entry_hits += reg.entry_hits;
            s.total_return_hits += reg.return_hits;
            s.total_missed += reg.missed_count;
        }
        s
    }

    /// Returns the number of registered probes.
    pub const fn probe_count(&self) -> usize {
        self.probe_count
    }
}
