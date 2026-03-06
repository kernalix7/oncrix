// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kprobe core — dynamic kernel probing infrastructure.
//!
//! Allows placement of breakpoint-based probes at arbitrary kernel
//! addresses. When a probed instruction is executed, the probe
//! handler is invoked for tracing, profiling, or debugging.
//!
//! # Architecture
//!
//! ```text
//! KprobeManager
//!  ├── probes[MAX_PROBES]
//!  │    ├── addr, symbol_offset
//!  │    ├── state: ProbeState
//!  │    ├── hit_count, miss_count
//!  │    └── pre_handler_id, post_handler_id
//!  └── stats: KprobeStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/kprobes.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered kprobes.
const MAX_PROBES: usize = 256;

/// Maximum symbol name length.
const MAX_SYMBOL_LEN: usize = 64;

// ══════════════════════════════════════════════════════════════
// ProbeState
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a kprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeState {
    /// Slot is free.
    Free = 0,
    /// Probe is registered but not yet armed.
    Registered = 1,
    /// Probe is armed (breakpoint inserted).
    Armed = 2,
    /// Probe is temporarily disabled.
    Disabled = 3,
    /// Probe has been unregistered and is pending cleanup.
    Gone = 4,
}

// ══════════════════════════════════════════════════════════════
// KprobeEntry — single probe
// ══════════════════════════════════════════════════════════════

/// A single kprobe registration.
#[derive(Clone, Copy)]
pub struct KprobeEntry {
    /// Probed virtual address.
    pub addr: u64,
    /// Symbol name (zero-padded).
    pub symbol: [u8; MAX_SYMBOL_LEN],
    /// Symbol name length.
    pub symbol_len: usize,
    /// Offset from symbol start.
    pub symbol_offset: u32,
    /// Original instruction bytes (saved before breakpoint).
    pub saved_insn: [u8; 16],
    /// Length of saved instruction.
    pub insn_len: u8,
    /// Probe state.
    pub state: ProbeState,
    /// Pre-handler callback ID (0 = none).
    pub pre_handler_id: u64,
    /// Post-handler callback ID (0 = none).
    pub post_handler_id: u64,
    /// Number of times this probe fired.
    pub hit_count: u64,
    /// Number of times the handler was skipped (e.g., filtered).
    pub miss_count: u64,
}

impl KprobeEntry {
    /// Create an empty probe slot.
    const fn empty() -> Self {
        Self {
            addr: 0,
            symbol: [0u8; MAX_SYMBOL_LEN],
            symbol_len: 0,
            symbol_offset: 0,
            saved_insn: [0u8; 16],
            insn_len: 0,
            state: ProbeState::Free,
            pre_handler_id: 0,
            post_handler_id: 0,
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Returns `true` if the probe is active.
    pub const fn is_active(&self) -> bool {
        matches!(
            self.state,
            ProbeState::Registered | ProbeState::Armed | ProbeState::Disabled
        )
    }
}

// ══════════════════════════════════════════════════════════════
// KprobeStats
// ══════════════════════════════════════════════════════════════

/// Kprobe subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct KprobeStats {
    /// Total probes registered.
    pub total_registered: u64,
    /// Total probes unregistered.
    pub total_unregistered: u64,
    /// Total probe hits across all probes.
    pub total_hits: u64,
    /// Total probe misses.
    pub total_misses: u64,
    /// Number of currently armed probes.
    pub armed_count: u32,
}

impl KprobeStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_registered: 0,
            total_unregistered: 0,
            total_hits: 0,
            total_misses: 0,
            armed_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KprobeManager
// ══════════════════════════════════════════════════════════════

/// Manages dynamic kernel probes.
pub struct KprobeManager {
    /// Probe table.
    probes: [KprobeEntry; MAX_PROBES],
    /// Statistics.
    stats: KprobeStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl KprobeManager {
    /// Create a new kprobe manager.
    pub const fn new() -> Self {
        Self {
            probes: [const { KprobeEntry::empty() }; MAX_PROBES],
            stats: KprobeStats::new(),
            enabled: true,
        }
    }

    /// Register a kprobe at the given address.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free slots.
    /// - `NotImplemented` if kprobes are disabled.
    /// - `AlreadyExists` if a probe at this address already exists.
    pub fn register(
        &mut self,
        addr: u64,
        symbol: &[u8],
        offset: u32,
        pre_handler: u64,
    ) -> Result<usize> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // Check for duplicate address.
        if self.probes.iter().any(|p| p.is_active() && p.addr == addr) {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .probes
            .iter()
            .position(|p| matches!(p.state, ProbeState::Free))
            .ok_or(Error::OutOfMemory)?;
        let sym_len = symbol.len().min(MAX_SYMBOL_LEN);
        self.probes[slot] = KprobeEntry::empty();
        self.probes[slot].addr = addr;
        self.probes[slot].symbol[..sym_len].copy_from_slice(&symbol[..sym_len]);
        self.probes[slot].symbol_len = sym_len;
        self.probes[slot].symbol_offset = offset;
        self.probes[slot].pre_handler_id = pre_handler;
        self.probes[slot].state = ProbeState::Registered;
        self.stats.total_registered += 1;
        Ok(slot)
    }

    /// Arm a registered probe (insert breakpoint).
    pub fn arm(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PROBES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.probes[slot].state, ProbeState::Registered) {
            return Err(Error::InvalidArgument);
        }
        self.probes[slot].state = ProbeState::Armed;
        self.stats.armed_count += 1;
        Ok(())
    }

    /// Disable an armed probe without removing it.
    pub fn disable(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PROBES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.probes[slot].state, ProbeState::Armed) {
            return Err(Error::InvalidArgument);
        }
        self.probes[slot].state = ProbeState::Disabled;
        self.stats.armed_count = self.stats.armed_count.saturating_sub(1);
        Ok(())
    }

    /// Unregister a probe.
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PROBES {
            return Err(Error::InvalidArgument);
        }
        if !self.probes[slot].is_active() {
            return Err(Error::NotFound);
        }
        if matches!(self.probes[slot].state, ProbeState::Armed) {
            self.stats.armed_count = self.stats.armed_count.saturating_sub(1);
        }
        self.probes[slot].state = ProbeState::Free;
        self.stats.total_unregistered += 1;
        Ok(())
    }

    /// Record a probe hit.
    pub fn record_hit(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PROBES {
            return Err(Error::InvalidArgument);
        }
        self.probes[slot].hit_count += 1;
        self.stats.total_hits += 1;
        Ok(())
    }

    /// Find a probe by address.
    pub fn find_by_addr(&self, addr: u64) -> Option<usize> {
        self.probes
            .iter()
            .position(|p| p.is_active() && p.addr == addr)
    }

    /// Return probe entry.
    pub fn get(&self, slot: usize) -> Result<&KprobeEntry> {
        if slot >= MAX_PROBES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.probes[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> KprobeStats {
        self.stats
    }
}
