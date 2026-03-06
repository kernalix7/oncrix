// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tracepoint iteration — enumerating and managing registered tracepoints.
//!
//! Provides mechanisms to iterate over all registered tracepoints in
//! the kernel for inspection, enabling, disabling, and probe
//! attachment.  Used by ftrace, perf, and BPF subsystems.
//!
//! # Reference
//!
//! Linux `kernel/tracepoint.c`, `include/linux/tracepoint.h`.

use oncrix_lib::{Error, Result};

const MAX_TRACEPOINTS: usize = 512;
const MAX_NAME_LEN: usize = 64;
const MAX_PROBES_PER_TP: usize = 8;

/// State of a tracepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TpState {
    /// Slot is free.
    Free = 0,
    /// Registered but disabled.
    Disabled = 1,
    /// Registered and enabled.
    Enabled = 2,
}

/// Probe function type.
pub type ProbeFn = fn(u64);

/// A registered tracepoint.
#[derive(Debug, Clone, Copy)]
pub struct Tracepoint {
    /// Tracepoint name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// State.
    pub state: TpState,
    /// Registered probe handlers.
    pub probes: [Option<ProbeFn>; MAX_PROBES_PER_TP],
    /// Number of registered probes.
    pub probe_count: usize,
    /// Number of times this tracepoint fired.
    pub fire_count: u64,
    /// Tracepoint identifier.
    pub tp_id: u64,
}

impl Tracepoint {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: TpState::Free,
            probes: [None; MAX_PROBES_PER_TP],
            probe_count: 0,
            fire_count: 0,
            tp_id: 0,
        }
    }

    /// Returns `true` if the tracepoint is active.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, TpState::Free)
    }

    /// Returns `true` if the tracepoint is enabled.
    pub const fn is_enabled(&self) -> bool {
        matches!(self.state, TpState::Enabled)
    }
}

/// Statistics for tracepoint iteration.
#[derive(Debug, Clone, Copy)]
pub struct TracepointIterStats {
    /// Total tracepoints registered.
    pub total_registered: u64,
    /// Total probes attached.
    pub total_probes_attached: u64,
    /// Total tracepoint fires.
    pub total_fires: u64,
    /// Total iteration scans.
    pub total_iterations: u64,
}

impl TracepointIterStats {
    const fn new() -> Self {
        Self {
            total_registered: 0,
            total_probes_attached: 0,
            total_fires: 0,
            total_iterations: 0,
        }
    }
}

/// Top-level tracepoint iteration subsystem.
pub struct TracepointIter {
    /// Registered tracepoints.
    tracepoints: [Tracepoint; MAX_TRACEPOINTS],
    /// Statistics.
    stats: TracepointIterStats,
    /// Next tracepoint ID.
    next_tp_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for TracepointIter {
    fn default() -> Self {
        Self::new()
    }
}

impl TracepointIter {
    /// Create a new tracepoint iterator subsystem.
    pub const fn new() -> Self {
        Self {
            tracepoints: [const { Tracepoint::empty() }; MAX_TRACEPOINTS],
            stats: TracepointIterStats::new(),
            next_tp_id: 1,
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

    /// Register a tracepoint.
    pub fn register(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .tracepoints
            .iter()
            .position(|t| matches!(t.state, TpState::Free))
            .ok_or(Error::OutOfMemory)?;

        let tp_id = self.next_tp_id;
        self.next_tp_id += 1;

        self.tracepoints[slot] = Tracepoint::empty();
        self.tracepoints[slot].name[..name.len()].copy_from_slice(name);
        self.tracepoints[slot].name_len = name.len();
        self.tracepoints[slot].state = TpState::Disabled;
        self.tracepoints[slot].tp_id = tp_id;

        self.stats.total_registered += 1;
        Ok(tp_id)
    }

    /// Enable a tracepoint.
    pub fn enable(&mut self, tp_id: u64) -> Result<()> {
        let slot = self.find_tp(tp_id)?;
        self.tracepoints[slot].state = TpState::Enabled;
        Ok(())
    }

    /// Disable a tracepoint.
    pub fn disable(&mut self, tp_id: u64) -> Result<()> {
        let slot = self.find_tp(tp_id)?;
        self.tracepoints[slot].state = TpState::Disabled;
        Ok(())
    }

    /// Attach a probe to a tracepoint.
    pub fn attach_probe(&mut self, tp_id: u64, probe: ProbeFn) -> Result<()> {
        let slot = self.find_tp(tp_id)?;
        let idx = self.tracepoints[slot].probe_count;
        if idx >= MAX_PROBES_PER_TP {
            return Err(Error::OutOfMemory);
        }
        self.tracepoints[slot].probes[idx] = Some(probe);
        self.tracepoints[slot].probe_count += 1;
        self.stats.total_probes_attached += 1;
        Ok(())
    }

    /// Fire a tracepoint (invoke all attached probes).
    pub fn fire(&mut self, tp_id: u64, data: u64) -> Result<()> {
        let slot = self.find_tp(tp_id)?;
        if !self.tracepoints[slot].is_enabled() {
            return Ok(());
        }

        let probe_count = self.tracepoints[slot].probe_count;
        for i in 0..probe_count {
            if let Some(probe) = self.tracepoints[slot].probes[i] {
                probe(data);
            }
        }

        self.tracepoints[slot].fire_count += 1;
        self.stats.total_fires += 1;
        Ok(())
    }

    /// Count all registered tracepoints.
    pub fn count(&self) -> usize {
        self.tracepoints.iter().filter(|t| t.is_active()).count()
    }

    /// Count enabled tracepoints.
    pub fn enabled_count(&self) -> usize {
        self.tracepoints.iter().filter(|t| t.is_enabled()).count()
    }

    /// Return statistics.
    pub fn stats(&self) -> TracepointIterStats {
        self.stats
    }

    /// Iterate over all active tracepoints, returning their IDs.
    pub fn list_active(&mut self) -> [Option<u64>; MAX_TRACEPOINTS] {
        self.stats.total_iterations += 1;
        let mut out = [None; MAX_TRACEPOINTS];
        for (i, tp) in self.tracepoints.iter().enumerate() {
            if tp.is_active() {
                out[i] = Some(tp.tp_id);
            }
        }
        out
    }

    fn find_tp(&self, tp_id: u64) -> Result<usize> {
        self.tracepoints
            .iter()
            .position(|t| t.is_active() && t.tp_id == tp_id)
            .ok_or(Error::NotFound)
    }
}
