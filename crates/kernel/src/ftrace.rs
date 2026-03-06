// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ftrace-style function tracer.
//!
//! Provides per-function instrumentation: each function can be
//! individually registered, enabled/disabled, and filtered.
//! When a traced function is called, an [`FtraceEntry`] is
//! recorded into a fixed-size ring buffer for later inspection.
//!
//! # Architecture
//!
//! ```text
//!  function entry ──► is_traced(addr)?
//!                          │ yes
//!                          ▼
//!                  FtraceFilter::matches()?
//!                          │ yes
//!                          ▼
//!                  FtraceBuffer::write(entry)
//! ```
//!
//! # Filter Modes
//!
//! - **AllExceptExcluded**: Trace all registered functions
//!   except those on the exclude list.
//! - **OnlyIncluded**: Trace only functions on the include
//!   list.
//!
//! Reference: Linux `kernel/trace/ftrace.c`,
//! `include/linux/ftrace.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of functions in the global function table.
const MAX_FUNCTIONS: usize = 512;

/// Maximum number of addresses in each filter list.
const MAX_FILTER_LIST: usize = 128;

/// Ring buffer capacity for trace entries.
const FTRACE_BUFFER_SIZE: usize = 2048;

/// Maximum length of a function symbol name in bytes.
const MAX_SYMBOL_LEN: usize = 64;

// -------------------------------------------------------------------
// FtraceFunc
// -------------------------------------------------------------------

/// A single function registered for ftrace instrumentation.
#[derive(Clone, Copy)]
pub struct FtraceFunc {
    /// Virtual address of the function entry point.
    pub addr: u64,
    /// Symbol name (fixed-size byte array).
    symbol_name: [u8; MAX_SYMBOL_LEN],
    /// Length of the valid portion of `symbol_name`.
    symbol_len: usize,
    /// Number of times this function has been called while
    /// tracing was active.
    pub hit_count: u64,
    /// Whether tracing is enabled for this function.
    pub enabled: bool,
    /// Whether this slot is in use.
    pub active: bool,
}

impl FtraceFunc {
    /// Return the symbol name as a byte slice.
    pub fn symbol_name(&self) -> &[u8] {
        &self.symbol_name[..self.symbol_len]
    }
}

/// Compile-time initializer for empty function slots.
const EMPTY_FUNC: FtraceFunc = FtraceFunc {
    addr: 0,
    symbol_name: [0; MAX_SYMBOL_LEN],
    symbol_len: 0,
    hit_count: 0,
    enabled: false,
    active: false,
};

// -------------------------------------------------------------------
// FtraceFilterMode
// -------------------------------------------------------------------

/// Determines how the include/exclude lists are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FtraceFilterMode {
    /// Trace all registered functions except those in the
    /// exclude list.
    #[default]
    AllExceptExcluded,
    /// Trace only functions present in the include list.
    OnlyIncluded,
}

// -------------------------------------------------------------------
// FtraceFilter
// -------------------------------------------------------------------

/// Include/exclude filter for function tracing.
///
/// Maintains two address lists and a mode that determines which
/// functions pass the filter.
pub struct FtraceFilter {
    /// Addresses to include (used in `OnlyIncluded` mode).
    include: [u64; MAX_FILTER_LIST],
    /// Number of valid entries in the include list.
    include_count: usize,
    /// Addresses to exclude (used in `AllExceptExcluded` mode).
    exclude: [u64; MAX_FILTER_LIST],
    /// Number of valid entries in the exclude list.
    exclude_count: usize,
    /// Current filter mode.
    pub mode: FtraceFilterMode,
}

impl Default for FtraceFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceFilter {
    /// Create a new filter in `AllExceptExcluded` mode with
    /// empty lists.
    pub const fn new() -> Self {
        Self {
            include: [0; MAX_FILTER_LIST],
            include_count: 0,
            exclude: [0; MAX_FILTER_LIST],
            exclude_count: 0,
            mode: FtraceFilterMode::AllExceptExcluded,
        }
    }

    /// Add an address to the include list.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the include list is full.
    /// - [`Error::AlreadyExists`] if the address is already
    ///   present.
    pub fn add_include(&mut self, addr: u64) -> Result<()> {
        if self.include[..self.include_count].contains(&addr) {
            return Err(Error::AlreadyExists);
        }
        if self.include_count >= MAX_FILTER_LIST {
            return Err(Error::OutOfMemory);
        }
        self.include[self.include_count] = addr;
        self.include_count += 1;
        Ok(())
    }

    /// Add an address to the exclude list.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the exclude list is full.
    /// - [`Error::AlreadyExists`] if the address is already
    ///   present.
    pub fn add_exclude(&mut self, addr: u64) -> Result<()> {
        if self.exclude[..self.exclude_count].contains(&addr) {
            return Err(Error::AlreadyExists);
        }
        if self.exclude_count >= MAX_FILTER_LIST {
            return Err(Error::OutOfMemory);
        }
        self.exclude[self.exclude_count] = addr;
        self.exclude_count += 1;
        Ok(())
    }

    /// Remove an address from the include list.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the address is not present.
    pub fn remove_include(&mut self, addr: u64) -> Result<()> {
        let pos = self.include[..self.include_count]
            .iter()
            .position(|a| *a == addr)
            .ok_or(Error::NotFound)?;
        self.include[pos] = self.include[self.include_count - 1];
        self.include_count -= 1;
        Ok(())
    }

    /// Remove an address from the exclude list.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the address is not present.
    pub fn remove_exclude(&mut self, addr: u64) -> Result<()> {
        let pos = self.exclude[..self.exclude_count]
            .iter()
            .position(|a| *a == addr)
            .ok_or(Error::NotFound)?;
        self.exclude[pos] = self.exclude[self.exclude_count - 1];
        self.exclude_count -= 1;
        Ok(())
    }

    /// Clear both filter lists.
    pub fn clear(&mut self) {
        self.include_count = 0;
        self.exclude_count = 0;
    }

    /// Test whether a function at `addr` passes the filter.
    pub fn matches(&self, addr: u64) -> bool {
        match self.mode {
            FtraceFilterMode::AllExceptExcluded => {
                !self.exclude[..self.exclude_count].contains(&addr)
            }
            FtraceFilterMode::OnlyIncluded => self.include[..self.include_count].contains(&addr),
        }
    }
}

// -------------------------------------------------------------------
// FtraceEntry
// -------------------------------------------------------------------

/// A single recorded function-call event.
#[derive(Debug, Clone, Copy)]
pub struct FtraceEntry {
    /// Timestamp (tick counter or TSC value).
    pub timestamp: u64,
    /// Address of the traced function.
    pub func_addr: u64,
    /// Address of the caller (return address).
    pub caller_addr: u64,
    /// Logical CPU that executed the call.
    pub cpu_id: u8,
    /// PID of the running process.
    pub pid: u64,
}

/// Compile-time initializer for empty buffer slots.
const EMPTY_ENTRY: FtraceEntry = FtraceEntry {
    timestamp: 0,
    func_addr: 0,
    caller_addr: 0,
    cpu_id: 0,
    pid: 0,
};

// -------------------------------------------------------------------
// FtraceBuffer
// -------------------------------------------------------------------

/// Fixed-size ring buffer for [`FtraceEntry`] records.
///
/// Holds up to [`FTRACE_BUFFER_SIZE`] entries. When full, new
/// entries overwrite the oldest.
pub struct FtraceBuffer {
    /// Entry storage.
    entries: [FtraceEntry; FTRACE_BUFFER_SIZE],
    /// Next write position (monotonically increasing).
    write_idx: usize,
    /// Total entries ever written (including overwritten).
    total_written: u64,
    /// Number of times the buffer has wrapped.
    pub overflow_count: u64,
}

impl Default for FtraceBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceBuffer {
    /// Create an empty trace buffer.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; FTRACE_BUFFER_SIZE],
            write_idx: 0,
            total_written: 0,
            overflow_count: 0,
        }
    }

    /// Append an entry to the ring buffer.
    ///
    /// Returns `true` if an older entry was overwritten.
    pub fn write(&mut self, entry: FtraceEntry) -> bool {
        let wrapped = self.write_idx >= FTRACE_BUFFER_SIZE;
        let idx = self.write_idx % FTRACE_BUFFER_SIZE;
        self.entries[idx] = entry;
        self.write_idx += 1;
        self.total_written += 1;
        if wrapped {
            self.overflow_count += 1;
        }
        wrapped
    }

    /// Read the entry at the given logical index (0 = oldest).
    ///
    /// Returns `None` if the index is out of range.
    pub fn read(&self, index: usize) -> Option<&FtraceEntry> {
        let count = self.count();
        if index >= count {
            return None;
        }
        let start = self.write_idx.saturating_sub(count);
        let physical = (start + index) % FTRACE_BUFFER_SIZE;
        Some(&self.entries[physical])
    }

    /// Number of entries currently stored (up to capacity).
    pub fn count(&self) -> usize {
        self.write_idx.min(FTRACE_BUFFER_SIZE)
    }

    /// Remove all entries from the buffer.
    pub fn clear(&mut self) {
        self.write_idx = 0;
        self.total_written = 0;
        self.overflow_count = 0;
    }

    /// Total entries ever written (including overwritten ones).
    pub fn total_written(&self) -> u64 {
        self.total_written
    }
}

impl core::fmt::Debug for FtraceBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FtraceBuffer")
            .field("entries", &self.count())
            .field("capacity", &FTRACE_BUFFER_SIZE)
            .field("total_written", &self.total_written)
            .field("overflow_count", &self.overflow_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// FtraceStats
// -------------------------------------------------------------------

/// Cumulative statistics for the function tracer.
#[derive(Debug, Clone, Copy, Default)]
pub struct FtraceStats {
    /// Total function calls that were recorded.
    pub total_calls: u64,
    /// Calls that were skipped due to filtering.
    pub filtered_calls: u64,
    /// Number of ring buffer overflows (overwrites).
    pub buffer_overflows: u64,
    /// Number of unique functions that have been hit at least
    /// once.
    pub unique_functions: u64,
}

// -------------------------------------------------------------------
// FtraceState
// -------------------------------------------------------------------

/// Global state for the function tracer.
///
/// Combines the function table, filter, ring buffer, and
/// statistics into a single top-level structure.
pub struct FtraceState {
    /// Whether ftrace is globally enabled.
    enabled: bool,
    /// Table of registered functions.
    functions: [FtraceFunc; MAX_FUNCTIONS],
    /// Number of active function registrations.
    func_count: usize,
    /// Current filter configuration.
    filter: FtraceFilter,
    /// Ring buffer for recorded call entries.
    buffer: FtraceBuffer,
    /// Cumulative statistics.
    stats: FtraceStats,
}

impl Default for FtraceState {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceState {
    /// Create a new disabled ftrace state.
    pub const fn new() -> Self {
        Self {
            enabled: false,
            functions: [EMPTY_FUNC; MAX_FUNCTIONS],
            func_count: 0,
            filter: FtraceFilter::new(),
            buffer: FtraceBuffer::new(),
            stats: FtraceStats {
                total_calls: 0,
                filtered_calls: 0,
                buffer_overflows: 0,
                unique_functions: 0,
            },
        }
    }

    /// Record a function call if tracing is enabled and the
    /// function passes the filter.
    ///
    /// Returns `true` if the call was recorded.
    pub fn record_call(
        &mut self,
        func_addr: u64,
        caller_addr: u64,
        cpu_id: u8,
        pid: u64,
        timestamp: u64,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        // Look up the function in the table.
        let func = self
            .functions
            .iter_mut()
            .find(|f| f.active && f.addr == func_addr);
        let func = match func {
            Some(f) => f,
            None => return false,
        };

        if !func.enabled {
            self.stats.filtered_calls += 1;
            return false;
        }

        if !self.filter.matches(func_addr) {
            self.stats.filtered_calls += 1;
            return false;
        }

        // First hit for this function: count it as unique.
        if func.hit_count == 0 {
            self.stats.unique_functions += 1;
        }
        func.hit_count += 1;

        let entry = FtraceEntry {
            timestamp,
            func_addr,
            caller_addr,
            cpu_id,
            pid,
        };
        let overflowed = self.buffer.write(entry);
        self.stats.total_calls += 1;
        if overflowed {
            self.stats.buffer_overflows += 1;
        }
        true
    }

    /// Check whether a specific function address is currently
    /// being traced (registered, enabled, and passes filter).
    pub fn is_traced(&self, addr: u64) -> bool {
        if !self.enabled {
            return false;
        }
        let func = self.functions.iter().find(|f| f.active && f.addr == addr);
        match func {
            Some(f) => f.enabled && self.filter.matches(addr),
            None => false,
        }
    }

    /// Return a snapshot of the current statistics.
    pub fn stats(&self) -> &FtraceStats {
        &self.stats
    }

    /// Return a reference to the ring buffer.
    pub fn buffer(&self) -> &FtraceBuffer {
        &self.buffer
    }

    /// Return whether ftrace is globally enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// -------------------------------------------------------------------
// FtraceRegistry
// -------------------------------------------------------------------

/// High-level interface for controlling the function tracer.
pub struct FtraceRegistry {
    /// Underlying ftrace state.
    state: FtraceState,
}

impl Default for FtraceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceRegistry {
    /// Create a new, disabled ftrace registry.
    pub const fn new() -> Self {
        Self {
            state: FtraceState::new(),
        }
    }

    /// Enable the function tracer globally.
    pub fn enable(&mut self) {
        self.state.enabled = true;
    }

    /// Disable the function tracer globally.
    pub fn disable(&mut self) {
        self.state.enabled = false;
    }

    /// Set the filter configuration.
    pub fn set_filter(&mut self, filter: FtraceFilter) {
        self.state.filter = filter;
    }

    /// Return a reference to the current filter.
    pub fn filter(&self) -> &FtraceFilter {
        &self.state.filter
    }

    /// Return a mutable reference to the current filter.
    pub fn filter_mut(&mut self) -> &mut FtraceFilter {
        &mut self.state.filter
    }

    /// Register a function for tracing.
    ///
    /// The function is enabled by default upon registration.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the function table is full.
    /// - [`Error::AlreadyExists`] if a function at `addr` is
    ///   already registered.
    /// - [`Error::InvalidArgument`] if `symbol_name` exceeds
    ///   [`MAX_SYMBOL_LEN`].
    pub fn register_func(&mut self, addr: u64, symbol_name: &[u8]) -> Result<()> {
        if symbol_name.len() > MAX_SYMBOL_LEN {
            return Err(Error::InvalidArgument);
        }
        let dup = self
            .state
            .functions
            .iter()
            .any(|f| f.active && f.addr == addr);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .state
            .functions
            .iter_mut()
            .find(|f| !f.active)
            .ok_or(Error::OutOfMemory)?;

        slot.addr = addr;
        slot.symbol_name = [0; MAX_SYMBOL_LEN];
        slot.symbol_name[..symbol_name.len()].copy_from_slice(symbol_name);
        slot.symbol_len = symbol_name.len();
        slot.hit_count = 0;
        slot.enabled = true;
        slot.active = true;
        self.state.func_count += 1;
        Ok(())
    }

    /// Unregister a function by address.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no function at `addr` is
    ///   registered.
    pub fn unregister_func(&mut self, addr: u64) -> Result<()> {
        let func = self
            .state
            .functions
            .iter_mut()
            .find(|f| f.active && f.addr == addr)
            .ok_or(Error::NotFound)?;

        func.active = false;
        func.enabled = false;
        self.state.func_count = self.state.func_count.saturating_sub(1);
        Ok(())
    }

    /// Return a reference to the ring buffer.
    pub fn get_buffer(&self) -> &FtraceBuffer {
        self.state.buffer()
    }

    /// Take a snapshot: return the current entry count and
    /// overflow count.
    pub fn snapshot(&self) -> (usize, u64) {
        (self.state.buffer.count(), self.state.buffer.overflow_count)
    }

    /// Record a function call through the tracer.
    ///
    /// Returns `true` if the call was recorded.
    pub fn record_call(
        &mut self,
        func_addr: u64,
        caller_addr: u64,
        cpu_id: u8,
        pid: u64,
        timestamp: u64,
    ) -> bool {
        self.state
            .record_call(func_addr, caller_addr, cpu_id, pid, timestamp)
    }

    /// Check whether a function is currently being traced.
    pub fn is_traced(&self, addr: u64) -> bool {
        self.state.is_traced(addr)
    }

    /// Return a snapshot of the cumulative statistics.
    pub fn stats(&self) -> &FtraceStats {
        self.state.stats()
    }

    /// Return the number of registered functions.
    pub fn func_count(&self) -> usize {
        self.state.func_count
    }

    /// Return whether the tracer is globally enabled.
    pub fn is_enabled(&self) -> bool {
        self.state.is_enabled()
    }
}
