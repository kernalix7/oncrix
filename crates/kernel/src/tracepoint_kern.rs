// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tracepoint infrastructure.
//!
//! Tracepoints are lightweight hooks placed at strategic locations
//! in the kernel. When activated, they call registered probe
//! callbacks with event-specific data. When inactive, they cost
//! nearly nothing (a static-key-guarded NOP).
//!
//! # Architecture
//!
//! ```text
//! TracepointSubsystem
//! ├── tracepoints: [Tracepoint; MAX_TRACEPOINTS]
//! │   ├── name, key_enabled
//! │   └── probes: [ProbeEntry; MAX_PROBES_PER_TP]
//! └── stats: TracepointStats
//!
//! Execution path:
//!   trace_<event>(...) → static_branch_unlikely(key)
//!     → if enabled: for_each_probe → probe_fn(data)
//! ```
//!
//! # Reference
//!
//! Linux `kernel/tracepoint.c`, `include/linux/tracepoint.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of tracepoints.
const MAX_TRACEPOINTS: usize = 256;

/// Maximum probes per tracepoint.
const MAX_PROBES_PER_TP: usize = 16;

/// Maximum tracepoint name length.
const MAX_NAME_LEN: usize = 64;

/// Maximum number of tracepoint groups.
const MAX_GROUPS: usize = 32;

/// Maximum group name length.
const MAX_GROUP_NAME_LEN: usize = 32;

// ── ProbeFn ─────────────────────────────────────────────────

/// Probe callback function signature.
///
/// Parameters: (event_data_ptr, probe_private_data)
pub type ProbeFn = fn(u64, u64);

// ── ProbeEntry ──────────────────────────────────────────────

/// A registered probe on a tracepoint.
#[derive(Clone, Copy)]
pub struct ProbeEntry {
    /// Unique probe ID.
    id: u32,
    /// Probe callback.
    func: Option<ProbeFn>,
    /// Private data passed to the callback.
    private_data: u64,
    /// Priority (higher = called first).
    priority: i32,
    /// Whether active.
    active: bool,
}

impl core::fmt::Debug for ProbeEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProbeEntry")
            .field("id", &self.id)
            .field("priority", &self.priority)
            .field("active", &self.active)
            .finish()
    }
}

impl ProbeEntry {
    /// Create an empty probe.
    const fn empty() -> Self {
        Self {
            id: 0,
            func: None,
            private_data: 0,
            priority: 0,
            active: false,
        }
    }

    /// Probe ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }
}

// ── Tracepoint ──────────────────────────────────────────────

/// A single tracepoint with registered probes.
pub struct Tracepoint {
    /// Unique tracepoint ID.
    id: u32,
    /// Tracepoint name (e.g., "sched:sched_switch").
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Group ID this tracepoint belongs to.
    group_id: u32,
    /// Whether the tracepoint is enabled (static key).
    enabled: bool,
    /// Registered probes.
    probes: [ProbeEntry; MAX_PROBES_PER_TP],
    /// Number of active probes.
    probe_count: usize,
    /// Total number of times this tracepoint has fired.
    fire_count: u64,
    /// Next probe ID.
    next_probe_id: u32,
    /// Whether this slot is active.
    active: bool,
}

impl Tracepoint {
    /// Create an empty tracepoint.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            group_id: 0,
            enabled: false,
            probes: [ProbeEntry::empty(); MAX_PROBES_PER_TP],
            probe_count: 0,
            fire_count: 0,
            next_probe_id: 1,
            active: false,
        }
    }

    /// Tracepoint ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Tracepoint name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Whether the tracepoint is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of registered probes.
    pub fn probe_count(&self) -> usize {
        self.probe_count
    }

    /// Total fire count.
    pub fn fire_count(&self) -> u64 {
        self.fire_count
    }

    /// Register a probe.
    fn register_probe(&mut self, func: ProbeFn, private_data: u64, priority: i32) -> Result<u32> {
        let slot = self
            .probes
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);

        self.probes[slot] = ProbeEntry {
            id,
            func: Some(func),
            private_data,
            priority,
            active: true,
        };
        self.probe_count += 1;

        // Auto-enable when first probe is registered.
        if self.probe_count == 1 {
            self.enabled = true;
        }

        // Sort probes by priority descending.
        self.sort_probes();
        Ok(id)
    }

    /// Unregister a probe.
    fn unregister_probe(&mut self, probe_id: u32) -> Result<()> {
        let probe = self
            .probes
            .iter_mut()
            .find(|p| p.active && p.id == probe_id)
            .ok_or(Error::NotFound)?;
        probe.active = false;
        probe.func = None;
        self.probe_count = self.probe_count.saturating_sub(1);

        // Auto-disable when no probes remain.
        if self.probe_count == 0 {
            self.enabled = false;
        }
        Ok(())
    }

    /// Fire the tracepoint, invoking all registered probes.
    fn fire(&mut self, event_data: u64) -> u32 {
        if !self.enabled {
            return 0;
        }
        self.fire_count = self.fire_count.saturating_add(1);
        let mut called = 0u32;

        for probe in &self.probes {
            if !probe.active {
                continue;
            }
            if let Some(func) = probe.func {
                func(event_data, probe.private_data);
                called += 1;
            }
        }
        called
    }

    /// Sort probes by priority descending.
    fn sort_probes(&mut self) {
        for i in 0..MAX_PROBES_PER_TP {
            for j in (i + 1)..MAX_PROBES_PER_TP {
                let pri_i = if self.probes[i].active {
                    self.probes[i].priority
                } else {
                    i32::MIN
                };
                let pri_j = if self.probes[j].active {
                    self.probes[j].priority
                } else {
                    i32::MIN
                };
                if pri_j > pri_i {
                    self.probes.swap(i, j);
                }
            }
        }
    }
}

// ── TracepointGroup ─────────────────────────────────────────

/// A group of related tracepoints (e.g., "sched", "irq", "net").
#[derive(Debug, Clone, Copy)]
pub struct TracepointGroup {
    /// Group ID.
    id: u32,
    /// Group name.
    name: [u8; MAX_GROUP_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Number of tracepoints in this group.
    tp_count: u32,
    /// Whether active.
    active: bool,
}

impl TracepointGroup {
    /// Create an empty group.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_GROUP_NAME_LEN],
            name_len: 0,
            tp_count: 0,
            active: false,
        }
    }

    /// Group name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_GROUP_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

// ── TracepointStats ─────────────────────────────────────────

/// Global tracepoint statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracepointStats {
    /// Total tracepoints registered.
    pub registered: u64,
    /// Total probes registered.
    pub probes_registered: u64,
    /// Total probes unregistered.
    pub probes_unregistered: u64,
    /// Total tracepoint fires.
    pub total_fires: u64,
    /// Total probe invocations.
    pub total_probe_calls: u64,
}

// ── TracepointSubsystem ─────────────────────────────────────

/// Global tracepoint subsystem.
pub struct TracepointSubsystem {
    /// Tracepoints.
    tracepoints: [Tracepoint; MAX_TRACEPOINTS],
    /// Groups.
    groups: [TracepointGroup; MAX_GROUPS],
    /// Number of active tracepoints.
    tp_count: usize,
    /// Number of active groups.
    group_count: usize,
    /// Next TP ID.
    next_tp_id: u32,
    /// Next group ID.
    next_group_id: u32,
    /// Statistics.
    stats: TracepointStats,
    /// Whether initialized.
    initialized: bool,
}

impl TracepointSubsystem {
    /// Create a new tracepoint subsystem.
    pub const fn new() -> Self {
        Self {
            tracepoints: [const { Tracepoint::empty() }; MAX_TRACEPOINTS],
            groups: [TracepointGroup::empty(); MAX_GROUPS],
            tp_count: 0,
            group_count: 0,
            next_tp_id: 1,
            next_group_id: 1,
            stats: TracepointStats {
                registered: 0,
                probes_registered: 0,
                probes_unregistered: 0,
                total_fires: 0,
                total_probe_calls: 0,
            },
            initialized: false,
        }
    }

    /// Initialize.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Create a tracepoint group. Returns the group ID.
    pub fn create_group(&mut self, name: &str) -> Result<u32> {
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);

        let mut name_buf = [0u8; MAX_GROUP_NAME_LEN];
        let copy_len = name.len().min(MAX_GROUP_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        self.groups[slot] = TracepointGroup {
            id,
            name: name_buf,
            name_len: copy_len,
            tp_count: 0,
            active: true,
        };
        self.group_count += 1;
        Ok(id)
    }

    /// Register a tracepoint. Returns the tracepoint ID.
    pub fn register(&mut self, name: &str, group_id: u32) -> Result<u32> {
        let slot = self
            .tracepoints
            .iter()
            .position(|tp| !tp.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_tp_id;
        self.next_tp_id = self.next_tp_id.wrapping_add(1);

        self.tracepoints[slot] = Tracepoint::empty();
        self.tracepoints[slot].id = id;
        self.tracepoints[slot].group_id = group_id;
        self.tracepoints[slot].active = true;

        let copy_len = name.len().min(MAX_NAME_LEN);
        self.tracepoints[slot].name[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        self.tracepoints[slot].name_len = copy_len;

        // Update group count.
        if let Some(g) = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
        {
            g.tp_count += 1;
        }

        self.tp_count += 1;
        self.stats.registered += 1;
        Ok(id)
    }

    /// Register a probe on a tracepoint.
    pub fn register_probe(
        &mut self,
        tp_id: u32,
        func: ProbeFn,
        private_data: u64,
        priority: i32,
    ) -> Result<u32> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        let probe_id = tp.register_probe(func, private_data, priority)?;
        self.stats.probes_registered += 1;
        Ok(probe_id)
    }

    /// Unregister a probe from a tracepoint.
    pub fn unregister_probe(&mut self, tp_id: u32, probe_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.unregister_probe(probe_id)?;
        self.stats.probes_unregistered += 1;
        Ok(())
    }

    /// Fire a tracepoint with event data.
    pub fn fire(&mut self, tp_id: u32, event_data: u64) -> Result<u32> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        let called = tp.fire(event_data);
        self.stats.total_fires += 1;
        self.stats.total_probe_calls += called as u64;
        Ok(called)
    }

    /// Enable a tracepoint manually.
    pub fn enable(&mut self, tp_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.enabled = true;
        Ok(())
    }

    /// Disable a tracepoint.
    pub fn disable(&mut self, tp_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.enabled = false;
        Ok(())
    }

    /// Look up a tracepoint by name.
    pub fn find_by_name(&self, name: &str) -> Option<u32> {
        self.tracepoints
            .iter()
            .find(|tp| tp.active && tp.name_str() == name)
            .map(|tp| tp.id)
    }

    /// Get a tracepoint reference.
    pub fn get(&self, tp_id: u32) -> Result<&Tracepoint> {
        self.tracepoints
            .iter()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)
    }

    /// Number of active tracepoints.
    pub fn tp_count(&self) -> usize {
        self.tp_count
    }

    /// Statistics.
    pub fn stats(&self) -> &TracepointStats {
        &self.stats
    }
}

impl Default for TracepointSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
