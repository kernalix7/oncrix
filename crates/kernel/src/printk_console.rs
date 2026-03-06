// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Console driver registration and log output subsystem.
//!
//! Manages a list of registered console backends (serial, framebuffer,
//! netconsole, etc.). When printk emits a message, it is fanned out
//! to every registered console whose log-level gate permits it.
//! An early console ("earlycon") mechanism allows output before the
//! full console subsystem is initialised.
//!
//! # Architecture
//!
//! ```text
//! ConsoleSubsystem
//! ├── consoles[MAX_CONSOLES]       registered backends
//! │   ├── name, flags, priority
//! │   └── write_fn: fn(&[u8])      callback
//! ├── earlycon: Option<index>      early console index
//! ├── default_loglevel             gate for message emission
//! ├── stats: ConsoleStats
//! └── Methods:
//!     ├── register_console(desc)
//!     ├── unregister_console(name)
//!     ├── emit(level, msg)         fan-out to all consoles
//!     ├── set_earlycon(name)
//!     └── disable_earlycon()
//! ```
//!
//! # Reference
//!
//! Linux `kernel/printk/printk.c` (console_drivers),
//! `include/linux/console.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of simultaneously registered consoles.
const MAX_CONSOLES: usize = 16;

/// Maximum console name length (bytes).
const MAX_NAME_LEN: usize = 32;

/// Maximum log message length fed to a console write callback.
const MAX_MSG_LEN: usize = 512;

/// Log-level values (syslog-compatible, 0 = most severe).
const _LOGLEVEL_EMERG: u8 = 0;
const _LOGLEVEL_ALERT: u8 = 1;
const _LOGLEVEL_CRIT: u8 = 2;
const _LOGLEVEL_ERR: u8 = 3;
const LOGLEVEL_WARN: u8 = 4;
const _LOGLEVEL_NOTICE: u8 = 5;
const _LOGLEVEL_INFO: u8 = 6;
const _LOGLEVEL_DEBUG: u8 = 7;

// ══════════════════════════════════════════════════════════════
// ConsoleFlags
// ══════════════════════════════════════════════════════════════

/// Bit-flags describing console capabilities and state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleFlags(u32);

impl ConsoleFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Console supports hardware output.
    pub const CON_PRINTBUFFER: Self = Self(1 << 0);
    /// Console is enabled for output.
    pub const CON_ENABLED: Self = Self(1 << 1);
    /// Console was registered as early console.
    pub const CON_BOOT: Self = Self(1 << 2);
    /// Console supports ANSI colour codes.
    pub const CON_ANSI: Self = Self(1 << 3);
    /// Console is a BRaille reader backend.
    pub const CON_BRL: Self = Self(1 << 4);

    /// Combine two flag sets.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Test whether `flag` is present in this set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Return raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

// ══════════════════════════════════════════════════════════════
// ConsolePriority
// ══════════════════════════════════════════════════════════════

/// Priority used to determine preferred console.
///
/// When multiple consoles compete for "preferred" status, the
/// one with the highest priority wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum ConsolePriority {
    /// Lowest — fallback only.
    #[default]
    Low = 0,
    /// Normal driver-registered console.
    Normal = 1,
    /// High — explicitly requested by the user (console=).
    High = 2,
    /// Maximum — early boot console.
    Boot = 3,
}

// ══════════════════════════════════════════════════════════════
// ConsoleWriteFn
// ══════════════════════════════════════════════════════════════

/// Write callback type for a console backend.
///
/// Receives a byte slice of the formatted message. The callback
/// must not panic and should be as fast as possible (may run
/// in NMI or interrupt context during panic).
pub type ConsoleWriteFn = fn(&[u8]);

// ══════════════════════════════════════════════════════════════
// ConsoleEntry — one registered console
// ══════════════════════════════════════════════════════════════

/// Descriptor for a single registered console backend.
#[derive(Clone)]
pub struct ConsoleEntry {
    /// Short name (e.g. "ttyS0", "fb0", "netcon").
    name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    name_len: usize,
    /// Console capability / state flags.
    flags: ConsoleFlags,
    /// Priority for preferred-console election.
    priority: ConsolePriority,
    /// Per-console log-level gate. Messages with a numeric
    /// severity greater than this value are suppressed.
    loglevel: u8,
    /// Write callback.
    write_fn: Option<ConsoleWriteFn>,
    /// Monotonic index (order of registration).
    index: u32,
    /// Whether this slot is occupied.
    active: bool,
    /// Number of messages successfully written.
    write_count: u64,
    /// Number of write errors (callback returned without
    /// completing; for our model we just count invocations).
    error_count: u64,
}

impl ConsoleEntry {
    /// Create an empty (inactive) console entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            flags: ConsoleFlags::NONE,
            priority: ConsolePriority::Low,
            loglevel: LOGLEVEL_WARN,
            write_fn: None,
            index: 0,
            active: false,
            write_count: 0,
            error_count: 0,
        }
    }

    /// Return the console name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the console flags.
    pub fn flags(&self) -> ConsoleFlags {
        self.flags
    }

    /// Return the console priority.
    pub fn priority(&self) -> ConsolePriority {
        self.priority
    }

    /// Return the number of successful writes.
    pub fn write_count(&self) -> u64 {
        self.write_count
    }
}

// ══════════════════════════════════════════════════════════════
// ConsoleStats
// ══════════════════════════════════════════════════════════════

/// Aggregate statistics for the console subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsoleStats {
    /// Total emit calls received.
    pub total_emits: u64,
    /// Total individual console writes performed.
    pub total_writes: u64,
    /// Messages suppressed by the default log-level gate.
    pub suppressed: u64,
    /// Messages suppressed by per-console log-level gate.
    pub per_console_suppressed: u64,
    /// Number of consoles currently registered.
    pub registered_count: u32,
}

// ══════════════════════════════════════════════════════════════
// ConsoleDescriptor — registration input
// ══════════════════════════════════════════════════════════════

/// Input descriptor used to register a new console.
pub struct ConsoleDescriptor<'a> {
    /// Console name (will be truncated to [`MAX_NAME_LEN`]).
    pub name: &'a [u8],
    /// Console flags.
    pub flags: ConsoleFlags,
    /// Priority.
    pub priority: ConsolePriority,
    /// Per-console log-level gate (0..7).
    pub loglevel: u8,
    /// Write callback.
    pub write_fn: ConsoleWriteFn,
}

// ══════════════════════════════════════════════════════════════
// ConsoleSubsystem
// ══════════════════════════════════════════════════════════════

/// Manages registered console backends and fans log messages
/// out to each active console.
pub struct ConsoleSubsystem {
    /// Registered console slots.
    consoles: [ConsoleEntry; MAX_CONSOLES],
    /// Next index counter for registration ordering.
    next_index: u32,
    /// Default log-level gate applied before per-console gates.
    default_loglevel: u8,
    /// Index of the early console (if set).
    earlycon_idx: Option<usize>,
    /// Aggregate statistics.
    stats: ConsoleStats,
    /// Whether the subsystem has been initialised.
    initialised: bool,
}

impl Default for ConsoleSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleSubsystem {
    /// Create the console subsystem in its initial (uninitialised)
    /// state. Call [`init`] to activate.
    pub const fn new() -> Self {
        Self {
            consoles: [const { ConsoleEntry::empty() }; MAX_CONSOLES],
            next_index: 0,
            default_loglevel: _LOGLEVEL_INFO,
            earlycon_idx: None,
            stats: ConsoleStats {
                total_emits: 0,
                total_writes: 0,
                suppressed: 0,
                per_console_suppressed: 0,
                registered_count: 0,
            },
            initialised: false,
        }
    }

    /// Initialise the console subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a new console backend.
    ///
    /// Returns the internal slot index assigned to the console.
    pub fn register_console(&mut self, desc: &ConsoleDescriptor<'_>) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }

        // Reject duplicate names.
        let name_len = desc.name.len().min(MAX_NAME_LEN);
        let target = &desc.name[..name_len];
        if self.find_console(target).is_some() {
            return Err(Error::AlreadyExists);
        }

        // Find a free slot.
        let slot = self
            .consoles
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        let entry = &mut self.consoles[slot];
        entry.name[..name_len].copy_from_slice(target);
        entry.name_len = name_len;
        entry.flags = desc.flags;
        entry.priority = desc.priority;
        entry.loglevel = desc.loglevel.min(7);
        entry.write_fn = Some(desc.write_fn);
        entry.index = self.next_index;
        entry.active = true;
        entry.write_count = 0;
        entry.error_count = 0;

        self.next_index += 1;
        self.stats.registered_count += 1;

        Ok(slot)
    }

    /// Unregister a console by name.
    ///
    /// Returns the slot index that was freed.
    pub fn unregister_console(&mut self, name: &[u8]) -> Result<usize> {
        let slot = self.find_console(name).ok_or(Error::NotFound)?;

        // If this was the early console, clear that too.
        if self.earlycon_idx == Some(slot) {
            self.earlycon_idx = None;
        }

        self.consoles[slot].active = false;
        self.consoles[slot].write_fn = None;
        self.stats.registered_count = self.stats.registered_count.saturating_sub(1);

        Ok(slot)
    }

    /// Designate an already-registered console as the early
    /// console. Only one earlycon may be active at a time.
    pub fn set_earlycon(&mut self, name: &[u8]) -> Result<()> {
        let slot = self.find_console(name).ok_or(Error::NotFound)?;

        self.consoles[slot].flags = self.consoles[slot].flags.or(ConsoleFlags::CON_BOOT);

        self.earlycon_idx = Some(slot);
        Ok(())
    }

    /// Disable and unregister the early console (typically done
    /// once the full console subsystem is ready).
    pub fn disable_earlycon(&mut self) -> Result<()> {
        let slot = self.earlycon_idx.ok_or(Error::NotFound)?;

        self.consoles[slot].active = false;
        self.consoles[slot].write_fn = None;
        self.earlycon_idx = None;
        self.stats.registered_count = self.stats.registered_count.saturating_sub(1);

        Ok(())
    }

    /// Emit a log message at the given severity level to all
    /// consoles that accept it.
    ///
    /// Returns the number of consoles that received the message.
    pub fn emit(&mut self, level: u8, message: &[u8]) -> Result<u32> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }

        self.stats.total_emits += 1;

        // Global log-level gate.
        if level > self.default_loglevel {
            self.stats.suppressed += 1;
            return Ok(0);
        }

        let msg_len = message.len().min(MAX_MSG_LEN);
        let msg = &message[..msg_len];

        let mut delivered: u32 = 0;

        for console in &mut self.consoles {
            if !console.active {
                continue;
            }
            if !console.flags.contains(ConsoleFlags::CON_ENABLED)
                && !console.flags.contains(ConsoleFlags::CON_BOOT)
            {
                continue;
            }
            // Per-console log-level gate.
            if level > console.loglevel {
                self.stats.per_console_suppressed += 1;
                continue;
            }
            if let Some(write_fn) = console.write_fn {
                write_fn(msg);
                console.write_count += 1;
                self.stats.total_writes += 1;
                delivered += 1;
            }
        }

        Ok(delivered)
    }

    /// Set the default (global) log-level gate.
    pub fn set_default_loglevel(&mut self, level: u8) {
        self.default_loglevel = level.min(7);
    }

    /// Return the current default log-level gate.
    pub fn default_loglevel(&self) -> u8 {
        self.default_loglevel
    }

    /// Return the number of currently registered consoles.
    pub fn console_count(&self) -> u32 {
        self.stats.registered_count
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &ConsoleStats {
        &self.stats
    }

    /// Look up a console by name and return a reference if found.
    pub fn get_console(&self, name: &[u8]) -> Option<&ConsoleEntry> {
        let slot = self.find_console(name)?;
        Some(&self.consoles[slot])
    }

    /// Determine the "preferred" console — the active console
    /// with the highest priority. Ties broken by registration
    /// order (lower index wins).
    pub fn preferred_console(&self) -> Option<&ConsoleEntry> {
        let mut best: Option<usize> = None;

        for (i, c) in self.consoles.iter().enumerate() {
            if !c.active {
                continue;
            }
            match best {
                None => best = Some(i),
                Some(b) => {
                    let bc = &self.consoles[b];
                    if c.priority > bc.priority || (c.priority == bc.priority && c.index < bc.index)
                    {
                        best = Some(i);
                    }
                }
            }
        }

        best.map(|i| &self.consoles[i])
    }

    // ── internal helpers ─────────────────────────────────────

    /// Find the slot index for the console with the given name.
    fn find_console(&self, name: &[u8]) -> Option<usize> {
        self.consoles
            .iter()
            .position(|c| c.active && c.name_len == name.len() && c.name[..c.name_len] == *name)
    }
}
