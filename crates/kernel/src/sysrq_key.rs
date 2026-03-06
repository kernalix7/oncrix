// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SysRq key registration — registering handlers for magic SysRq keys.
//!
//! The SysRq mechanism allows kernel subsystems to register handlers
//! for specific key presses that trigger diagnostic or recovery
//! actions when the system is unresponsive.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   SysrqKeyRegistry                           │
//! │                                                              │
//! │  KeyHandler[0..MAX_KEYS]  (registered key handlers)          │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  key: u8                                               │  │
//! │  │  handler: fn(u8)                                       │  │
//! │  │  help_msg: &'static str                                │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `drivers/tty/sysrq.c`, `include/linux/sysrq.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registerable key handlers (a-z, 0-9).
const MAX_KEYS: usize = 36;

/// SysRq enable mask: allow all operations.
const SYSRQ_ENABLE_ALL: u16 = 0xFFFF;

// ══════════════════════════════════════════════════════════════
// SysrqMask — bitmask of enabled SysRq operations
// ══════════════════════════════════════════════════════════════

/// Bitmask for enabling/disabling SysRq operation categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SysrqCategory {
    /// Enable control of logging level.
    LogLevel = 1 << 0,
    /// Enable keyboard control (SAK, unraw).
    Keyboard = 1 << 1,
    /// Enable debugging dumps.
    DumpDebug = 1 << 2,
    /// Enable sync command.
    Sync = 1 << 3,
    /// Enable remount read-only.
    Remount = 1 << 4,
    /// Enable signalling of processes (term, kill, oom-kill).
    Signal = 1 << 5,
    /// Enable reboot/poweroff.
    Reboot = 1 << 6,
    /// Enable nicing of RT tasks.
    NiceRt = 1 << 7,
}

// ══════════════════════════════════════════════════════════════
// SysrqFn — handler type
// ══════════════════════════════════════════════════════════════

/// SysRq key handler function.
pub type SysrqFn = fn(u8);

// ══════════════════════════════════════════════════════════════
// KeyHandler
// ══════════════════════════════════════════════════════════════

/// A registered SysRq key handler.
#[derive(Debug, Clone, Copy)]
pub struct KeyHandler {
    /// The key character (e.g., b'b' for reboot).
    pub key: u8,
    /// Handler function.
    pub handler: Option<SysrqFn>,
    /// Help message for this key.
    pub help_msg: &'static str,
    /// Action name for logging.
    pub action_name: &'static str,
    /// Category mask bit.
    pub category: u16,
    /// Whether this handler is registered.
    pub registered: bool,
    /// Number of times this key has been triggered.
    pub trigger_count: u64,
}

impl KeyHandler {
    /// Create an empty handler slot.
    const fn empty() -> Self {
        Self {
            key: 0,
            handler: None,
            help_msg: "",
            action_name: "",
            category: 0,
            registered: false,
            trigger_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SysrqStats
// ══════════════════════════════════════════════════════════════

/// Statistics for SysRq key handling.
#[derive(Debug, Clone, Copy)]
pub struct SysrqStats {
    /// Total SysRq key presses handled.
    pub total_triggers: u64,
    /// Total key presses with no registered handler.
    pub total_unhandled: u64,
    /// Total key presses blocked by mask.
    pub total_blocked: u64,
}

impl SysrqStats {
    const fn new() -> Self {
        Self {
            total_triggers: 0,
            total_unhandled: 0,
            total_blocked: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SysrqKeyRegistry
// ══════════════════════════════════════════════════════════════

/// Top-level SysRq key handler registry.
pub struct SysrqKeyRegistry {
    /// Registered key handlers.
    handlers: [KeyHandler; MAX_KEYS],
    /// Bitmask of enabled SysRq categories.
    enable_mask: u16,
    /// Statistics.
    stats: SysrqStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for SysrqKeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SysrqKeyRegistry {
    /// Create a new SysRq key registry.
    pub const fn new() -> Self {
        Self {
            handlers: [const { KeyHandler::empty() }; MAX_KEYS],
            enable_mask: SYSRQ_ENABLE_ALL,
            stats: SysrqStats::new(),
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

    /// Set the enable mask.
    pub fn set_enable_mask(&mut self, mask: u16) {
        self.enable_mask = mask;
    }

    /// Return the current enable mask.
    pub fn enable_mask(&self) -> u16 {
        self.enable_mask
    }

    // ── Registration ─────────────────────────────────────────

    /// Register a SysRq key handler.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if the key already has a handler.
    /// - `OutOfMemory` if no handler slots remain.
    pub fn register(
        &mut self,
        key: u8,
        handler: SysrqFn,
        help_msg: &'static str,
        action_name: &'static str,
        category: u16,
    ) -> Result<()> {
        // Check for duplicate key.
        if self.handlers.iter().any(|h| h.registered && h.key == key) {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .handlers
            .iter()
            .position(|h| !h.registered)
            .ok_or(Error::OutOfMemory)?;

        self.handlers[slot] = KeyHandler {
            key,
            handler: Some(handler),
            help_msg,
            action_name,
            category,
            registered: true,
            trigger_count: 0,
        };
        Ok(())
    }

    /// Unregister a SysRq key handler.
    pub fn unregister(&mut self, key: u8) -> Result<()> {
        let slot = self
            .handlers
            .iter()
            .position(|h| h.registered && h.key == key)
            .ok_or(Error::NotFound)?;
        self.handlers[slot] = KeyHandler::empty();
        Ok(())
    }

    // ── Key handling ─────────────────────────────────────────

    /// Handle a SysRq key press.
    ///
    /// Returns `true` if the key was handled.
    pub fn handle_key(&mut self, key: u8) -> Result<bool> {
        self.stats.total_triggers += 1;

        let slot = match self
            .handlers
            .iter()
            .position(|h| h.registered && h.key == key)
        {
            Some(s) => s,
            None => {
                self.stats.total_unhandled += 1;
                return Ok(false);
            }
        };

        // Check enable mask.
        let category = self.handlers[slot].category;
        if (self.enable_mask & category) == 0 {
            self.stats.total_blocked += 1;
            return Ok(false);
        }

        if let Some(handler) = self.handlers[slot].handler {
            handler(key);
        }

        self.handlers[slot].trigger_count += 1;
        Ok(true)
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> SysrqStats {
        self.stats
    }

    /// Return the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.iter().filter(|h| h.registered).count()
    }

    /// Return the handler for a given key.
    pub fn get_handler(&self, key: u8) -> Option<&KeyHandler> {
        self.handlers.iter().find(|h| h.registered && h.key == key)
    }

    /// Return all registered help messages.
    pub fn help_messages(&self) -> [Option<(u8, &'static str)>; MAX_KEYS] {
        let mut out = [None; MAX_KEYS];
        for (i, h) in self.handlers.iter().enumerate() {
            if h.registered {
                out[i] = Some((h.key, h.help_msg));
            }
        }
        out
    }
}
