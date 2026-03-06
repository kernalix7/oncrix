// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel tracepoint infrastructure.
//!
//! Provides static tracing hooks for kernel events. Tracepoints are
//! named instrumentation sites embedded in kernel code paths that
//! can be individually enabled or disabled at runtime. When enabled,
//! registered callbacks are invoked to record or process the event.
//! Modeled after Linux's `include/linux/tracepoint.h` and
//! `kernel/tracepoint.c`.
//!
//! # Architecture
//!
//! ```text
//!   kernel code path
//!        │
//!        ▼
//!   tracepoint site ──► is_enabled()?
//!                            │ yes
//!                            ▼
//!                    invoke callbacks[] ──► TraceEntry
//! ```
//!
//! # Subsystem-Callback Model
//!
//! Each tracepoint can have multiple registered callbacks. When
//! the tracepoint fires, all registered callbacks are invoked in
//! priority order. Callbacks are identified by a `func_id` /
//! `data` pair (function pointer replacement for `no_std`).
//!
//! # Performance
//!
//! Disabled tracepoints have near-zero overhead — only a single
//! branch check. This module is designed to integrate with the
//! [`crate::jump_label`] infrastructure for branch-free fast
//! paths when tracepoints are disabled.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of tracepoints.
const MAX_TRACEPOINTS: usize = 256;

/// Maximum callbacks per tracepoint.
const MAX_CALLBACKS_PER_TP: usize = 8;

/// Maximum name length for a tracepoint.
const MAX_TP_NAME_LEN: usize = 64;

/// Maximum number of trace entries in the log buffer.
const MAX_TRACE_ENTRIES: usize = 2048;

/// Maximum subsystem name length.
const MAX_SUBSYSTEM_LEN: usize = 32;

// ── TracepointState ──────────────────────────────────────────

/// State of a tracepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TracepointState {
    /// Tracepoint is registered but not enabled.
    #[default]
    Disabled,
    /// Tracepoint is enabled and will fire callbacks.
    Enabled,
}

// ── TraceCallback ────────────────────────────────────────────

/// A callback registered on a tracepoint.
///
/// When the tracepoint fires, all active callbacks are invoked
/// in priority order (lower value = higher priority).
#[derive(Debug, Clone, Copy)]
pub struct TraceCallback {
    /// Unique callback ID.
    pub id: u32,
    /// Function identifier for the callback.
    pub func_id: u64,
    /// Opaque data passed to the callback.
    pub data: u64,
    /// Priority (lower = invoked first).
    pub priority: i32,
    /// Whether this callback slot is active.
    pub active: bool,
}

impl TraceCallback {
    /// Create an empty callback for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            func_id: 0,
            data: 0,
            priority: 0,
            active: false,
        }
    }
}

impl Default for TraceCallback {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Tracepoint ───────────────────────────────────────────────

/// A single tracepoint definition.
///
/// A tracepoint is a named instrumentation point in the kernel
/// that can have callbacks attached. When the tracepoint fires,
/// all registered callbacks are invoked.
#[derive(Clone)]
pub struct Tracepoint {
    /// Unique tracepoint ID.
    pub id: u32,
    /// Human-readable name.
    name: [u8; MAX_TP_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Subsystem this tracepoint belongs to.
    subsystem: [u8; MAX_SUBSYSTEM_LEN],
    /// Valid length of `subsystem`.
    subsystem_len: usize,
    /// Current state.
    pub state: TracepointState,
    /// Registered callbacks.
    callbacks: [TraceCallback; MAX_CALLBACKS_PER_TP],
    /// Number of active callbacks.
    pub callback_count: usize,
    /// Next callback ID for this tracepoint.
    next_cb_id: u32,
    /// Total number of times this tracepoint has fired.
    pub fire_count: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl Tracepoint {
    /// Create an empty tracepoint for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_TP_NAME_LEN],
            name_len: 0,
            subsystem: [0u8; MAX_SUBSYSTEM_LEN],
            subsystem_len: 0,
            state: TracepointState::Disabled,
            callbacks: [TraceCallback::empty(); MAX_CALLBACKS_PER_TP],
            callback_count: 0,
            next_cb_id: 1,
            fire_count: 0,
            active: false,
        }
    }

    /// Return the tracepoint name as a string slice.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_TP_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Return the subsystem name as a string slice.
    pub fn subsystem_str(&self) -> &str {
        let len = self.subsystem_len.min(MAX_SUBSYSTEM_LEN);
        core::str::from_utf8(&self.subsystem[..len]).unwrap_or("<invalid>")
    }

    /// Return `true` if the tracepoint is enabled.
    pub fn is_enabled(&self) -> bool {
        self.state == TracepointState::Enabled
    }

    /// Enable the tracepoint.
    pub fn enable(&mut self) {
        self.state = TracepointState::Enabled;
    }

    /// Disable the tracepoint.
    pub fn disable(&mut self) {
        self.state = TracepointState::Disabled;
    }

    /// Register a callback on this tracepoint.
    ///
    /// Returns the callback ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the callback table is
    /// full.
    pub fn register_callback(&mut self, func_id: u64, data: u64, priority: i32) -> Result<u32> {
        let slot = self
            .callbacks
            .iter()
            .position(|cb| !cb.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_cb_id;
        self.next_cb_id = self.next_cb_id.wrapping_add(1);

        self.callbacks[slot] = TraceCallback {
            id,
            func_id,
            data,
            priority,
            active: true,
        };
        self.callback_count += 1;
        Ok(id)
    }

    /// Unregister a callback by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no callback with the given
    /// ID exists.
    pub fn unregister_callback(&mut self, cb_id: u32) -> Result<()> {
        let cb = self
            .callbacks
            .iter_mut()
            .find(|cb| cb.active && cb.id == cb_id)
            .ok_or(Error::NotFound)?;
        cb.active = false;
        self.callback_count = self.callback_count.saturating_sub(1);
        Ok(())
    }

    /// Fire the tracepoint — invoke all registered callbacks.
    ///
    /// Returns the number of callbacks invoked. Does nothing if
    /// the tracepoint is disabled.
    pub fn fire(&mut self) -> usize {
        if self.state != TracepointState::Enabled {
            return 0;
        }
        self.fire_count = self.fire_count.wrapping_add(1);

        // In a real kernel we would sort by priority and
        // call each function. Here we count invocations.
        let mut invoked = 0usize;
        for cb in &self.callbacks {
            if cb.active {
                invoked += 1;
            }
        }
        invoked
    }

    /// Return the number of active callbacks.
    pub fn num_callbacks(&self) -> usize {
        self.callback_count
    }
}

impl Default for Tracepoint {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for Tracepoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tracepoint")
            .field("id", &self.id)
            .field("name", &self.name_str())
            .field("subsystem", &self.subsystem_str())
            .field("state", &self.state)
            .field("callback_count", &self.callback_count)
            .field("fire_count", &self.fire_count)
            .finish()
    }
}

// ── TraceEntry ───────────────────────────────────────────────

/// A single recorded trace event from a tracepoint firing.
#[derive(Debug, Clone, Copy)]
pub struct TraceEntry {
    /// Tracepoint ID that fired.
    pub tracepoint_id: u32,
    /// Timestamp (kernel ticks or nanoseconds).
    pub timestamp: u64,
    /// CPU that fired the tracepoint.
    pub cpu_id: u32,
    /// Process ID associated with the event.
    pub pid: u64,
    /// First event-specific argument.
    pub arg0: u64,
    /// Second event-specific argument.
    pub arg1: u64,
    /// Third event-specific argument.
    pub arg2: u64,
}

impl TraceEntry {
    /// Create an empty trace entry.
    pub const fn empty() -> Self {
        Self {
            tracepoint_id: 0,
            timestamp: 0,
            cpu_id: 0,
            pid: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
        }
    }

    /// Create a new trace entry with the given parameters.
    pub const fn new(
        tracepoint_id: u32,
        timestamp: u64,
        cpu_id: u32,
        pid: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
    ) -> Self {
        Self {
            tracepoint_id,
            timestamp,
            cpu_id,
            pid,
            arg0,
            arg1,
            arg2,
        }
    }
}

impl Default for TraceEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ── TraceLog ─────────────────────────────────────────────────

/// Ring buffer of trace entries recorded from tracepoint
/// firings.
pub struct TraceLog {
    /// Entry storage.
    entries: [TraceEntry; MAX_TRACE_ENTRIES],
    /// Write position (monotonically increasing).
    write_idx: usize,
    /// Total entries ever written.
    total: u64,
}

impl TraceLog {
    /// Create an empty trace log.
    pub const fn new() -> Self {
        Self {
            entries: [TraceEntry::empty(); MAX_TRACE_ENTRIES],
            write_idx: 0,
            total: 0,
        }
    }

    /// Record a trace entry.
    ///
    /// When the buffer is full, the oldest entry is overwritten.
    pub fn record(&mut self, entry: TraceEntry) {
        let idx = self.write_idx % MAX_TRACE_ENTRIES;
        self.entries[idx] = entry;
        self.write_idx += 1;
        self.total += 1;
    }

    /// Read the entry at the given logical index (0 = oldest).
    pub fn read(&self, index: usize) -> Option<&TraceEntry> {
        let count = self.count();
        if index >= count {
            return None;
        }
        let start = self.write_idx.saturating_sub(count);
        let physical = (start + index) % MAX_TRACE_ENTRIES;
        Some(&self.entries[physical])
    }

    /// Number of entries currently stored.
    pub fn count(&self) -> usize {
        self.write_idx.min(MAX_TRACE_ENTRIES)
    }

    /// Total entries ever written.
    pub fn total_written(&self) -> u64 {
        self.total
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.write_idx = 0;
        self.total = 0;
    }

    /// Return `true` if the buffer has wrapped.
    pub fn has_wrapped(&self) -> bool {
        self.write_idx > MAX_TRACE_ENTRIES
    }
}

impl Default for TraceLog {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for TraceLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TraceLog")
            .field("count", &self.count())
            .field("capacity", &MAX_TRACE_ENTRIES)
            .field("total", &self.total)
            .finish()
    }
}

// ── TracepointManager ────────────────────────────────────────

/// Central manager for all kernel tracepoints.
///
/// Provides the kernel-facing API for registering, enabling,
/// and firing tracepoints.
pub struct TracepointManager {
    /// Registered tracepoints.
    tracepoints: [Tracepoint; MAX_TRACEPOINTS],
    /// Trace entry log.
    log: TraceLog,
    /// Number of active tracepoints.
    tp_count: usize,
    /// Next tracepoint ID.
    next_tp_id: u32,
    /// Global enable flag (master switch).
    global_enabled: bool,
}

impl TracepointManager {
    /// Create a new, empty tracepoint manager.
    #[allow(clippy::large_stack_frames)]
    pub fn new() -> Self {
        const EMPTY: Tracepoint = Tracepoint::empty();
        Self {
            tracepoints: [EMPTY; MAX_TRACEPOINTS],
            log: TraceLog::new(),
            tp_count: 0,
            next_tp_id: 1,
            global_enabled: true,
        }
    }

    /// Register a new tracepoint.
    ///
    /// Returns the tracepoint ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tracepoint table
    /// is full.
    /// Returns [`Error::AlreadyExists`] if a tracepoint with
    /// the same name already exists.
    pub fn register(&mut self, name: &str, subsystem: &str) -> Result<u32> {
        // Check for duplicate name.
        let exists = self
            .tracepoints
            .iter()
            .any(|tp| tp.active && tp.name_str() == name);
        if exists {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .tracepoints
            .iter()
            .position(|tp| !tp.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_tp_id;
        self.next_tp_id = self.next_tp_id.wrapping_add(1);

        let mut name_buf = [0u8; MAX_TP_NAME_LEN];
        let name_copy = name.len().min(MAX_TP_NAME_LEN);
        name_buf[..name_copy].copy_from_slice(&name.as_bytes()[..name_copy]);

        let mut sub_buf = [0u8; MAX_SUBSYSTEM_LEN];
        let sub_copy = subsystem.len().min(MAX_SUBSYSTEM_LEN);
        sub_buf[..sub_copy].copy_from_slice(&subsystem.as_bytes()[..sub_copy]);

        self.tracepoints[slot] = Tracepoint {
            id,
            name: name_buf,
            name_len: name_copy,
            subsystem: sub_buf,
            subsystem_len: sub_copy,
            state: TracepointState::Disabled,
            callbacks: [TraceCallback::empty(); MAX_CALLBACKS_PER_TP],
            callback_count: 0,
            next_cb_id: 1,
            fire_count: 0,
            active: true,
        };
        self.tp_count += 1;
        Ok(id)
    }

    /// Unregister a tracepoint by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tracepoint with the
    /// given ID exists.
    pub fn unregister(&mut self, tp_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.active = false;
        self.tp_count = self.tp_count.saturating_sub(1);
        Ok(())
    }

    /// Enable a tracepoint by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tracepoint with the
    /// given ID exists.
    pub fn enable(&mut self, tp_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.enable();
        Ok(())
    }

    /// Disable a tracepoint by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tracepoint with the
    /// given ID exists.
    pub fn disable(&mut self, tp_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.disable();
        Ok(())
    }

    /// Register a callback on a tracepoint.
    ///
    /// Returns the callback ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tracepoint does not
    /// exist.
    /// Returns [`Error::OutOfMemory`] if the callback table is
    /// full.
    pub fn register_callback(
        &mut self,
        tp_id: u32,
        func_id: u64,
        data: u64,
        priority: i32,
    ) -> Result<u32> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.register_callback(func_id, data, priority)
    }

    /// Unregister a callback from a tracepoint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tracepoint or
    /// callback does not exist.
    pub fn unregister_callback(&mut self, tp_id: u32, cb_id: u32) -> Result<()> {
        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;
        tp.unregister_callback(cb_id)
    }

    /// Fire a tracepoint, invoking all callbacks and logging a
    /// trace entry.
    ///
    /// Does nothing if global tracing is disabled or the
    /// tracepoint is not enabled.
    ///
    /// Returns the number of callbacks invoked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tracepoint does not
    /// exist.
    pub fn fire(
        &mut self,
        tp_id: u32,
        timestamp: u64,
        cpu_id: u32,
        pid: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
    ) -> Result<usize> {
        if !self.global_enabled {
            return Ok(0);
        }

        let tp = self
            .tracepoints
            .iter_mut()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)?;

        let invoked = tp.fire();

        if invoked > 0 {
            let entry = TraceEntry::new(tp_id, timestamp, cpu_id, pid, arg0, arg1, arg2);
            self.log.record(entry);
        }

        Ok(invoked)
    }

    /// Look up a tracepoint by name.
    ///
    /// Returns the tracepoint ID, or `None` if not found.
    pub fn find_by_name(&self, name: &str) -> Option<u32> {
        self.tracepoints
            .iter()
            .find(|tp| tp.active && tp.name_str() == name)
            .map(|tp| tp.id)
    }

    /// Iterate over all active tracepoints.
    ///
    /// Calls the provided closure for each active tracepoint.
    /// Returns the number of tracepoints visited.
    pub fn for_each_tracepoint<F>(&self, mut f: F) -> usize
    where
        F: FnMut(&Tracepoint),
    {
        let mut count = 0usize;
        for tp in &self.tracepoints {
            if tp.active {
                f(tp);
                count += 1;
            }
        }
        count
    }

    /// Enable all tracepoints matching the given subsystem.
    ///
    /// Returns the number of tracepoints enabled.
    pub fn enable_subsystem(&mut self, subsystem: &str) -> usize {
        let mut count = 0usize;
        for tp in &mut self.tracepoints {
            if tp.active && tp.subsystem_str() == subsystem {
                tp.enable();
                count += 1;
            }
        }
        count
    }

    /// Disable all tracepoints matching the given subsystem.
    ///
    /// Returns the number of tracepoints disabled.
    pub fn disable_subsystem(&mut self, subsystem: &str) -> usize {
        let mut count = 0usize;
        for tp in &mut self.tracepoints {
            if tp.active && tp.subsystem_str() == subsystem {
                tp.disable();
                count += 1;
            }
        }
        count
    }

    /// Set the global enable/disable flag.
    pub fn set_global_enabled(&mut self, enabled: bool) {
        self.global_enabled = enabled;
    }

    /// Return whether global tracing is enabled.
    pub fn is_global_enabled(&self) -> bool {
        self.global_enabled
    }

    /// Return a reference to the trace log.
    pub fn log(&self) -> &TraceLog {
        &self.log
    }

    /// Clear the trace log.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Return the number of active tracepoints.
    pub fn count(&self) -> usize {
        self.tp_count
    }

    /// Return `true` if no tracepoints are registered.
    pub fn is_empty(&self) -> bool {
        self.tp_count == 0
    }

    /// Return a reference to a tracepoint by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tracepoint with the
    /// given ID exists.
    pub fn get(&self, tp_id: u32) -> Result<&Tracepoint> {
        self.tracepoints
            .iter()
            .find(|tp| tp.active && tp.id == tp_id)
            .ok_or(Error::NotFound)
    }
}

impl Default for TracepointManager {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for TracepointManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TracepointManager")
            .field("tp_count", &self.tp_count)
            .field("global_enabled", &self.global_enabled)
            .field("log", &self.log)
            .finish()
    }
}
