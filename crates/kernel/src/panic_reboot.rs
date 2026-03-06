// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Panic-triggered reboot handling.
//!
//! Manages the system behavior after a kernel panic, including
//! configurable reboot timeouts, crash dump coordination, and
//! notification chain invocation. Supports multiple reboot modes
//! (warm reboot, cold reboot, kexec into crash kernel).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of panic reboot callbacks.
const MAX_CALLBACKS: usize = 32;

/// Maximum number of recorded panic events.
const MAX_PANIC_LOG: usize = 16;

/// Default reboot timeout in seconds (0 = immediate, -1 = never).
const DEFAULT_PANIC_TIMEOUT_SECS: i64 = -1;

/// Maximum panic message length.
const MAX_PANIC_MSG_LEN: usize = 256;

// ── Types ────────────────────────────────────────────────────────────

/// Reboot mode after panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicRebootMode {
    /// Warm reboot (preserve some state).
    Warm,
    /// Cold reboot (full reset).
    Cold,
    /// Kexec into crash kernel.
    Kexec,
    /// Halt (power off).
    Halt,
    /// Hang (do nothing, for debugging).
    Hang,
}

impl Default for PanicRebootMode {
    fn default() -> Self {
        Self::Hang
    }
}

/// Phase during panic handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicPhase {
    /// Panic just occurred.
    Initial,
    /// Notifiers are being called.
    Notifying,
    /// Crash dump is being saved.
    DumpingCrash,
    /// System is about to reboot.
    Rebooting,
    /// Panic handling is complete.
    Complete,
}

impl Default for PanicPhase {
    fn default() -> Self {
        Self::Initial
    }
}

/// A registered panic reboot callback.
#[derive(Debug, Clone)]
pub struct PanicRebootCallback {
    /// Callback identifier.
    callback_id: u64,
    /// Priority (lower = earlier execution).
    priority: u32,
    /// Phase at which this callback fires.
    phase: PanicPhase,
    /// Whether this callback is enabled.
    enabled: bool,
    /// Number of times invoked.
    invocation_count: u64,
    /// Description bytes.
    description: [u8; 64],
    /// Description length.
    desc_len: usize,
}

impl PanicRebootCallback {
    /// Creates a new callback.
    pub const fn new(callback_id: u64, priority: u32, phase: PanicPhase) -> Self {
        Self {
            callback_id,
            priority,
            phase,
            enabled: true,
            invocation_count: 0,
            description: [0u8; 64],
            desc_len: 0,
        }
    }

    /// Returns the callback identifier.
    pub const fn callback_id(&self) -> u64 {
        self.callback_id
    }

    /// Returns the priority.
    pub const fn priority(&self) -> u32 {
        self.priority
    }
}

/// Record of a panic event.
#[derive(Debug, Clone)]
pub struct PanicRecord {
    /// Panic sequence number.
    sequence: u64,
    /// Panic message (truncated).
    message: [u8; MAX_PANIC_MSG_LEN],
    /// Message length.
    msg_len: usize,
    /// CPU that panicked.
    cpu: u32,
    /// Reboot mode selected.
    reboot_mode: PanicRebootMode,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
    /// Whether reboot was initiated.
    rebooted: bool,
}

impl PanicRecord {
    /// Creates a new panic record.
    pub const fn new(sequence: u64, cpu: u32, reboot_mode: PanicRebootMode) -> Self {
        Self {
            sequence,
            message: [0u8; MAX_PANIC_MSG_LEN],
            msg_len: 0,
            cpu,
            reboot_mode,
            timestamp_ns: 0,
            rebooted: false,
        }
    }

    /// Returns the panic sequence number.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Panic reboot configuration.
#[derive(Debug, Clone)]
pub struct PanicRebootConfig {
    /// Timeout before rebooting (-1 = never, 0 = immediate).
    pub timeout_secs: i64,
    /// Reboot mode.
    pub mode: PanicRebootMode,
    /// Whether to print stack trace before reboot.
    pub print_stack: bool,
    /// Whether to save a crash dump.
    pub save_crash_dump: bool,
    /// Whether to invoke the notifier chain.
    pub invoke_notifiers: bool,
}

impl Default for PanicRebootConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicRebootConfig {
    /// Creates a default panic reboot configuration.
    pub const fn new() -> Self {
        Self {
            timeout_secs: DEFAULT_PANIC_TIMEOUT_SECS,
            mode: PanicRebootMode::Hang,
            print_stack: true,
            save_crash_dump: false,
            invoke_notifiers: true,
        }
    }
}

/// Panic reboot statistics.
#[derive(Debug, Clone)]
pub struct PanicRebootStats {
    /// Total panics handled.
    pub total_panics: u64,
    /// Total reboots initiated.
    pub total_reboots: u64,
    /// Total callbacks invoked.
    pub total_callbacks_invoked: u64,
    /// Total crash dumps saved.
    pub crash_dumps_saved: u64,
    /// Number of registered callbacks.
    pub callback_count: u32,
}

impl Default for PanicRebootStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicRebootStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_panics: 0,
            total_reboots: 0,
            total_callbacks_invoked: 0,
            crash_dumps_saved: 0,
            callback_count: 0,
        }
    }
}

/// Central panic reboot handler.
#[derive(Debug)]
pub struct PanicRebootHandler {
    /// Configuration.
    config: PanicRebootConfig,
    /// Registered callbacks.
    callbacks: [Option<PanicRebootCallback>; MAX_CALLBACKS],
    /// Panic event log.
    panic_log: [Option<PanicRecord>; MAX_PANIC_LOG],
    /// Log write position.
    log_pos: usize,
    /// Callback count.
    callback_count: usize,
    /// Next callback identifier.
    next_id: u64,
    /// Current panic phase.
    current_phase: PanicPhase,
    /// Current panic sequence number.
    panic_sequence: u64,
    /// Whether a panic is currently being handled.
    handling_panic: bool,
    /// Total panics handled.
    total_panics: u64,
    /// Total reboots.
    total_reboots: u64,
    /// Total callbacks invoked.
    total_cb_invoked: u64,
}

impl Default for PanicRebootHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicRebootHandler {
    /// Creates a new panic reboot handler.
    pub const fn new() -> Self {
        Self {
            config: PanicRebootConfig::new(),
            callbacks: [const { None }; MAX_CALLBACKS],
            panic_log: [const { None }; MAX_PANIC_LOG],
            log_pos: 0,
            callback_count: 0,
            next_id: 1,
            current_phase: PanicPhase::Initial,
            panic_sequence: 0,
            handling_panic: false,
            total_panics: 0,
            total_reboots: 0,
            total_cb_invoked: 0,
        }
    }

    /// Updates the configuration.
    pub fn set_config(&mut self, config: PanicRebootConfig) {
        self.config = config;
    }

    /// Registers a callback.
    pub fn register_callback(&mut self, priority: u32, phase: PanicPhase) -> Result<u64> {
        if self.callback_count >= MAX_CALLBACKS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        let cb = PanicRebootCallback::new(id, priority, phase);
        if let Some(slot) = self.callbacks.iter_mut().find(|s| s.is_none()) {
            *slot = Some(cb);
            self.callback_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Unregisters a callback.
    pub fn unregister_callback(&mut self, callback_id: u64) -> Result<()> {
        let slot = self
            .callbacks
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |cb| cb.callback_id == callback_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.callback_count -= 1;
        Ok(())
    }

    /// Handles a panic event.
    pub fn handle_panic(&mut self, cpu: u32) -> Result<PanicRebootMode> {
        if self.handling_panic {
            return Err(Error::Busy);
        }
        self.handling_panic = true;
        self.panic_sequence += 1;
        self.total_panics += 1;
        self.current_phase = PanicPhase::Initial;
        let record = PanicRecord::new(self.panic_sequence, cpu, self.config.mode);
        self.panic_log[self.log_pos] = Some(record);
        self.log_pos = (self.log_pos + 1) % MAX_PANIC_LOG;
        // Invoke notifiers.
        if self.config.invoke_notifiers {
            self.current_phase = PanicPhase::Notifying;
            for cb in self.callbacks.iter_mut().flatten() {
                if cb.enabled {
                    cb.invocation_count += 1;
                    self.total_cb_invoked += 1;
                }
            }
        }
        self.current_phase = PanicPhase::Complete;
        self.handling_panic = false;
        Ok(self.config.mode)
    }

    /// Initiates a reboot after panic.
    pub fn initiate_reboot(&mut self) -> Result<PanicRebootMode> {
        self.current_phase = PanicPhase::Rebooting;
        self.total_reboots += 1;
        Ok(self.config.mode)
    }

    /// Returns the current panic phase.
    pub const fn current_phase(&self) -> PanicPhase {
        self.current_phase
    }

    /// Returns statistics.
    pub fn stats(&self) -> PanicRebootStats {
        PanicRebootStats {
            total_panics: self.total_panics,
            total_reboots: self.total_reboots,
            total_callbacks_invoked: self.total_cb_invoked,
            crash_dumps_saved: 0,
            callback_count: self.callback_count as u32,
        }
    }

    /// Returns the number of registered callbacks.
    pub const fn callback_count(&self) -> usize {
        self.callback_count
    }
}
