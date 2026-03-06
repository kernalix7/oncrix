// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Magic SysRq key handler — emergency kernel debugging facility.
//!
//! SysRq provides a set of keyboard shortcuts (Alt+SysRq+<key>) that
//! are always available regardless of system state, allowing operators
//! to perform emergency operations such as syncing filesystems,
//! rebooting, or dumping diagnostic information.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    SysrqSubsystem                            │
//! │                                                              │
//! │  handlers: [Option<SysrqHandler>; 26]   (a..z key slots)    │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  action:       SysrqAction                             │  │
//! │  │  key:          u8 (ASCII 'a'..'z')                     │  │
//! │  │  description:  &'static str                            │  │
//! │  │  handler_fn:   SysrqHandlerFn                          │  │
//! │  │  invoke_count: u64                                     │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  enabled_mask: u32 — bitmask of enabled action categories   │
//! │  global_enabled: bool — master enable/disable switch        │
//! │  SysrqStats: total triggers, per-key counts                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Default Key Bindings
//!
//! | Key | Action        | Description                        |
//! |-----|---------------|------------------------------------|
//! | b   | Reboot        | Immediately reboot the system      |
//! | c   | Crash         | Trigger a kernel panic             |
//! | e   | Terminate     | Send SIGTERM to all processes      |
//! | f   | OomKill       | Invoke the OOM killer              |
//! | h   | Help          | Display SysRq help                 |
//! | i   | Signal        | Send SIGKILL to all processes      |
//! | k   | Secure        | Kill all processes on current VT   |
//! | l   | Backtrace     | Show backtrace of all CPUs         |
//! | m   | ShowMem       | Dump memory information            |
//! | o   | PowerOff      | Power off the system               |
//! | p   | Registers     | Dump CPU registers                 |
//! | s   | Sync          | Emergency filesystem sync          |
//! | t   | ShowTasks     | Dump all task information          |
//! | u   | Umount        | Remount all filesystems read-only  |
//!
//! # Reference
//!
//! Linux `drivers/tty/sysrq.c`, `include/linux/sysrq.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Number of handler slots (one per lowercase letter a–z).
const NUM_SLOTS: usize = 26;

/// Maximum entries in the trigger log.
const MAX_LOG_ENTRIES: usize = 128;

// ══════════════════════════════════════════════════════════════
// SysrqAction — action categories
// ══════════════════════════════════════════════════════════════

/// Enumeration of all supported SysRq actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysrqAction {
    /// Emergency filesystem sync (flush dirty buffers).
    Sync,
    /// Remount all filesystems read-only.
    Umount,
    /// Immediate reboot (no clean shutdown).
    Reboot,
    /// Deliberately trigger a kernel panic for debugging.
    Crash,
    /// Display memory usage information.
    ShowMem,
    /// Display all running tasks.
    ShowTasks,
    /// Display backtrace of all active CPUs.
    ShowBacktrace,
    /// Change the kernel log level.
    Loglevel,
    /// Invoke the OOM killer to free memory.
    OomKill,
    /// Power off the machine.
    PowerOff,
    /// Display timer information.
    ShowTimers,
    /// Display lock information.
    ShowLocks,
    /// Send SIGTERM to all user processes.
    Terminate,
    /// Send SIGKILL to all user processes.
    SignalAll,
    /// Secure Attention Key — kill all procs on current VT.
    SecureAttention,
    /// Dump CPU registers.
    ShowRegisters,
    /// Display help (list available SysRq commands).
    Help,
}

impl SysrqAction {
    /// Human-readable name for this action.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Umount => "umount",
            Self::Reboot => "reboot",
            Self::Crash => "crash",
            Self::ShowMem => "show-memory",
            Self::ShowTasks => "show-tasks",
            Self::ShowBacktrace => "show-backtrace",
            Self::Loglevel => "loglevel",
            Self::OomKill => "oom-kill",
            Self::PowerOff => "poweroff",
            Self::ShowTimers => "show-timers",
            Self::ShowLocks => "show-locks",
            Self::Terminate => "terminate-all",
            Self::SignalAll => "signal-all",
            Self::SecureAttention => "secure-attention",
            Self::ShowRegisters => "show-registers",
            Self::Help => "help",
        }
    }

    /// Bitmask category for enable/disable filtering.
    ///
    /// Groups are assigned so that operators can enable subsets of
    /// SysRq functionality.
    pub const fn category_mask(self) -> u32 {
        match self {
            Self::Help => 0x0001,
            Self::Loglevel => 0x0002,
            Self::Sync | Self::Umount => 0x0004,
            Self::ShowMem
            | Self::ShowTasks
            | Self::ShowBacktrace
            | Self::ShowTimers
            | Self::ShowLocks
            | Self::ShowRegisters => 0x0008,
            Self::Reboot | Self::PowerOff => 0x0010,
            Self::Terminate | Self::SignalAll => 0x0020,
            Self::OomKill => 0x0040,
            Self::Crash => 0x0080,
            Self::SecureAttention => 0x0100,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SysrqHandlerFn — callback signature
// ══════════════════════════════════════════════════════════════

/// Handler function type for SysRq actions.
///
/// The `u8` parameter is the triggering key code.
pub type SysrqHandlerFn = fn(u8);

// ══════════════════════════════════════════════════════════════
// SysrqHandler — per-key handler descriptor
// ══════════════════════════════════════════════════════════════

/// Descriptor for a registered SysRq key handler.
#[derive(Clone, Copy)]
pub struct SysrqHandler {
    /// The action performed by this handler.
    pub action: SysrqAction,
    /// The key character that activates this handler ('a'..'z').
    pub key: u8,
    /// Human-readable description for help output.
    pub description: &'static str,
    /// Handler callback function.
    pub handler_fn: SysrqHandlerFn,
    /// Number of times this handler has been invoked.
    pub invoke_count: u64,
}

impl core::fmt::Debug for SysrqHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysrqHandler")
            .field("action", &self.action)
            .field("key", &(self.key as char))
            .field("description", &self.description)
            .field("invoke_count", &self.invoke_count)
            .finish_non_exhaustive()
    }
}

impl SysrqHandler {
    /// Create a new handler descriptor.
    pub const fn new(
        action: SysrqAction,
        key: u8,
        description: &'static str,
        handler_fn: SysrqHandlerFn,
    ) -> Self {
        Self {
            action,
            key,
            description,
            handler_fn,
            invoke_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SysrqLogEntry — trigger event log
// ══════════════════════════════════════════════════════════════

/// A logged SysRq trigger event.
#[derive(Debug, Clone, Copy)]
pub struct SysrqLogEntry {
    /// Tick at which the trigger occurred.
    pub tick: u64,
    /// Key that was pressed.
    pub key: u8,
    /// The action that was dispatched.
    pub action: SysrqAction,
    /// Whether the handler succeeded.
    pub success: bool,
}

impl SysrqLogEntry {
    /// Empty log entry for array initialisation.
    const fn empty() -> Self {
        Self {
            tick: 0,
            key: 0,
            action: SysrqAction::Help,
            success: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SysrqStats — statistics
// ══════════════════════════════════════════════════════════════

/// Global SysRq statistics.
#[derive(Debug, Clone, Copy)]
pub struct SysrqStats {
    /// Total number of SysRq triggers (valid key presses).
    pub total_triggers: u64,
    /// Number of triggers that matched a registered handler.
    pub dispatched: u64,
    /// Number of triggers for unregistered keys.
    pub unhandled: u64,
    /// Number of triggers blocked by the enabled mask.
    pub filtered: u64,
    /// Number of registered handlers.
    pub registered_handlers: u32,
}

impl SysrqStats {
    /// Create zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_triggers: 0,
            dispatched: 0,
            unhandled: 0,
            filtered: 0,
            registered_handlers: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TriggerResult — outcome of a trigger
// ══════════════════════════════════════════════════════════════

/// Result of a `sysrq_trigger` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerResult {
    /// The handler was found and dispatched successfully.
    Dispatched,
    /// The key was valid but no handler is registered.
    Unhandled,
    /// The handler's action category is currently disabled.
    Filtered,
    /// The SysRq subsystem is globally disabled.
    Disabled,
    /// The key is outside the 'a'..'z' range.
    InvalidKey,
}

// ══════════════════════════════════════════════════════════════
// SysrqSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level Magic SysRq subsystem.
///
/// Manages 26 handler slots (a–z), an enable/disable bitmask, and
/// a trigger log.
pub struct SysrqSubsystem {
    /// Handler slots indexed by `key - b'a'`.
    handlers: [Option<SysrqHandler>; NUM_SLOTS],
    /// Bitmask of enabled action categories.  All bits set = all
    /// actions enabled.  See [`SysrqAction::category_mask`].
    enabled_mask: u32,
    /// Master enable/disable switch.
    global_enabled: bool,
    /// Trigger event log (circular).
    log: [SysrqLogEntry; MAX_LOG_ENTRIES],
    /// Next write position in the log.
    log_head: usize,
    /// Number of entries written (saturates at `MAX_LOG_ENTRIES`).
    log_count: usize,
    /// Statistics.
    stats: SysrqStats,
}

impl Default for SysrqSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SysrqSubsystem {
    /// Create a new SysRq subsystem with all slots empty and
    /// all categories enabled.
    pub const fn new() -> Self {
        Self {
            handlers: [const { None }; NUM_SLOTS],
            enabled_mask: 0xFFFF_FFFF,
            global_enabled: true,
            log: [const { SysrqLogEntry::empty() }; MAX_LOG_ENTRIES],
            log_head: 0,
            log_count: 0,
            stats: SysrqStats::new(),
        }
    }

    // ── Handler registration ─────────────────────────────────

    /// Register a handler for the given key.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key` is not in `b'a'..=b'z'`.
    /// - `AlreadyExists` if a handler is already registered for
    ///   that key.
    pub fn register(&mut self, handler: SysrqHandler) -> Result<()> {
        let idx = Self::key_to_index(handler.key)?;
        if self.handlers[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.handlers[idx] = Some(handler);
        self.stats.registered_handlers += 1;
        Ok(())
    }

    /// Unregister the handler for the given key.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key` is not in `b'a'..=b'z'`.
    /// - `NotFound` if no handler is registered for the key.
    pub fn unregister(&mut self, key: u8) -> Result<()> {
        let idx = Self::key_to_index(key)?;
        if self.handlers[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.handlers[idx] = None;
        self.stats.registered_handlers = self.stats.registered_handlers.saturating_sub(1);
        Ok(())
    }

    // ── Trigger / dispatch ───────────────────────────────────

    /// Handle a SysRq key press.
    ///
    /// This is the main entry point, typically called from the
    /// keyboard driver when Alt+SysRq+<key> is detected.
    pub fn trigger(&mut self, key: u8, tick: u64) -> TriggerResult {
        let lower = key.to_ascii_lowercase();
        let idx = match Self::key_to_index(lower) {
            Ok(i) => i,
            Err(_) => return TriggerResult::InvalidKey,
        };

        self.stats.total_triggers += 1;

        if !self.global_enabled {
            return TriggerResult::Disabled;
        }

        let handler = match &self.handlers[idx] {
            Some(h) => *h,
            None => {
                self.stats.unhandled += 1;
                return TriggerResult::Unhandled;
            }
        };

        // Check whether this action's category is enabled.
        if (self.enabled_mask & handler.action.category_mask()) == 0 {
            self.stats.filtered += 1;
            return TriggerResult::Filtered;
        }

        // Invoke the handler.
        (handler.handler_fn)(lower);

        // Update per-handler stats.
        if let Some(h) = &mut self.handlers[idx] {
            h.invoke_count += 1;
        }
        self.stats.dispatched += 1;

        // Log the event.
        self.log_event(tick, lower, handler.action, true);

        TriggerResult::Dispatched
    }

    /// Programmatic trigger (e.g., from `/proc/sysrq-trigger`).
    pub fn sysrq_trigger(&mut self, key: u8, tick: u64) -> TriggerResult {
        self.trigger(key, tick)
    }

    // ── Enable / disable ─────────────────────────────────────

    /// Enable or disable the SysRq subsystem globally.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.global_enabled = enabled;
    }

    /// Returns `true` if SysRq is globally enabled.
    pub const fn is_enabled(&self) -> bool {
        self.global_enabled
    }

    /// Set the enabled bitmask (controls which action categories
    /// are permitted).
    pub fn set_enabled_mask(&mut self, mask: u32) {
        self.enabled_mask = mask;
    }

    /// Return the current enabled bitmask.
    pub const fn enabled_mask(&self) -> u32 {
        self.enabled_mask
    }

    // ── Query / diagnostics ──────────────────────────────────

    /// Look up the handler for a given key.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key` is outside `b'a'..=b'z'`.
    pub fn handler_for(&self, key: u8) -> Result<Option<&SysrqHandler>> {
        let idx = Self::key_to_index(key)?;
        Ok(self.handlers[idx].as_ref())
    }

    /// Return a snapshot of statistics.
    pub fn stats(&self) -> SysrqStats {
        self.stats
    }

    /// Return the number of registered handlers.
    pub fn registered_count(&self) -> u32 {
        self.stats.registered_handlers
    }

    /// Generate a help listing of all registered handlers.
    ///
    /// Returns an array of `(key, description)` for each
    /// registered handler, plus the number of valid entries.
    pub fn help_listing(&self) -> ([Option<(u8, &'static str)>; NUM_SLOTS], usize) {
        let mut out = [None; NUM_SLOTS];
        let mut count = 0;
        for (i, slot) in self.handlers.iter().enumerate() {
            if let Some(h) = slot {
                out[i] = Some((h.key, h.description));
                count += 1;
            }
        }
        (out, count)
    }

    /// Return recent trigger log entries (most recent first).
    ///
    /// Returns up to `max` entries and the actual count returned.
    pub fn recent_log(&self, max: usize) -> ([SysrqLogEntry; MAX_LOG_ENTRIES], usize) {
        let count = if max < self.log_count {
            max
        } else {
            self.log_count
        };
        let mut out = [const { SysrqLogEntry::empty() }; MAX_LOG_ENTRIES];
        for i in 0..count {
            let idx = (self.log_head + MAX_LOG_ENTRIES - 1 - i) % MAX_LOG_ENTRIES;
            out[i] = self.log[idx];
        }
        (out, count)
    }

    // ── Internals ────────────────────────────────────────────

    /// Convert a key byte to a handler table index.
    fn key_to_index(key: u8) -> Result<usize> {
        if key < b'a' || key > b'z' {
            return Err(Error::InvalidArgument);
        }
        Ok((key - b'a') as usize)
    }

    /// Append an event to the circular log.
    fn log_event(&mut self, tick: u64, key: u8, action: SysrqAction, success: bool) {
        self.log[self.log_head] = SysrqLogEntry {
            tick,
            key,
            action,
            success,
        };
        self.log_head = (self.log_head + 1) % MAX_LOG_ENTRIES;
        if self.log_count < MAX_LOG_ENTRIES {
            self.log_count += 1;
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Default handler stubs
// ══════════════════════════════════════════════════════════════

/// Placeholder handler for SysRq 'b' (reboot).
pub fn sysrq_handle_reboot(_key: u8) {
    // In a real kernel: write to ACPI reset register or
    // triple-fault the CPU.
}

/// Placeholder handler for SysRq 'c' (crash / panic).
pub fn sysrq_handle_crash(_key: u8) {
    // In a real kernel: invoke panic!() or BUG().
}

/// Placeholder handler for SysRq 'e' (terminate all).
pub fn sysrq_handle_terminate(_key: u8) {
    // Send SIGTERM to all user processes.
}

/// Placeholder handler for SysRq 'f' (OOM kill).
pub fn sysrq_handle_oom_kill(_key: u8) {
    // Invoke the OOM killer.
}

/// Placeholder handler for SysRq 'h' (help).
pub fn sysrq_handle_help(_key: u8) {
    // Print registered SysRq keys and descriptions.
}

/// Placeholder handler for SysRq 'i' (signal all).
pub fn sysrq_handle_signal_all(_key: u8) {
    // Send SIGKILL to all user processes.
}

/// Placeholder handler for SysRq 'k' (secure attention key).
pub fn sysrq_handle_sak(_key: u8) {
    // Kill all processes on the current virtual terminal.
}

/// Placeholder handler for SysRq 'l' (backtrace).
pub fn sysrq_handle_backtrace(_key: u8) {
    // Dump stack backtrace for all CPUs.
}

/// Placeholder handler for SysRq 'm' (show memory).
pub fn sysrq_handle_show_mem(_key: u8) {
    // Dump memory usage information.
}

/// Placeholder handler for SysRq 'o' (power off).
pub fn sysrq_handle_poweroff(_key: u8) {
    // In a real kernel: ACPI S5 / EFI ResetSystem(Shutdown).
}

/// Placeholder handler for SysRq 'p' (show registers).
pub fn sysrq_handle_show_regs(_key: u8) {
    // Dump CPU registers for all CPUs.
}

/// Placeholder handler for SysRq 's' (sync).
pub fn sysrq_handle_sync(_key: u8) {
    // Emergency sync: flush all dirty filesystem buffers.
}

/// Placeholder handler for SysRq 't' (show tasks).
pub fn sysrq_handle_show_tasks(_key: u8) {
    // Dump information about all tasks.
}

/// Placeholder handler for SysRq 'u' (umount).
pub fn sysrq_handle_umount(_key: u8) {
    // Remount all filesystems read-only.
}

/// Register the default set of SysRq handlers.
///
/// Call this during boot after the SysRq subsystem is created.
pub fn register_default_handlers(sys: &mut SysrqSubsystem) -> Result<()> {
    let defaults: &[(u8, SysrqAction, &str, SysrqHandlerFn)] = &[
        (b'b', SysrqAction::Reboot, "reboot", sysrq_handle_reboot),
        (b'c', SysrqAction::Crash, "crash", sysrq_handle_crash),
        (
            b'e',
            SysrqAction::Terminate,
            "terminate-all-tasks",
            sysrq_handle_terminate,
        ),
        (
            b'f',
            SysrqAction::OomKill,
            "oom-kill",
            sysrq_handle_oom_kill,
        ),
        (b'h', SysrqAction::Help, "help", sysrq_handle_help),
        (
            b'i',
            SysrqAction::SignalAll,
            "kill-all-tasks",
            sysrq_handle_signal_all,
        ),
        (
            b'k',
            SysrqAction::SecureAttention,
            "secure-attention-key",
            sysrq_handle_sak,
        ),
        (
            b'l',
            SysrqAction::ShowBacktrace,
            "show-backtrace",
            sysrq_handle_backtrace,
        ),
        (
            b'm',
            SysrqAction::ShowMem,
            "show-memory",
            sysrq_handle_show_mem,
        ),
        (
            b'o',
            SysrqAction::PowerOff,
            "poweroff",
            sysrq_handle_poweroff,
        ),
        (
            b'p',
            SysrqAction::ShowRegisters,
            "show-registers",
            sysrq_handle_show_regs,
        ),
        (b's', SysrqAction::Sync, "sync", sysrq_handle_sync),
        (
            b't',
            SysrqAction::ShowTasks,
            "show-tasks",
            sysrq_handle_show_tasks,
        ),
        (
            b'u',
            SysrqAction::Umount,
            "remount-read-only",
            sysrq_handle_umount,
        ),
    ];

    for &(key, action, desc, handler_fn) in defaults {
        sys.register(SysrqHandler::new(action, key, desc, handler_fn))?;
    }
    Ok(())
}
