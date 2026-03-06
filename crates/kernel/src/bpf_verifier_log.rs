// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF verifier logging — structured logging for BPF program verification.
//!
//! When the BPF verifier rejects a program, detailed logs explain why.
//! This module manages the log buffer, log levels, and formatting of
//! verifier diagnostic messages.
//!
//! # Reference
//!
//! Linux `kernel/bpf/verifier.c` (verbose/log functions).

use oncrix_lib::{Error, Result};

const MAX_LOG_ENTRIES: usize = 1024;
const MAX_MSG_LEN: usize = 128;

/// Log severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    /// Errors only.
    Error = 0,
    /// Warnings and errors.
    Warn = 1,
    /// Informational messages.
    Info = 2,
    /// Verbose debug output.
    Debug = 3,
}

/// Category of verifier log message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogCategory {
    /// Register state tracking.
    Register = 0,
    /// Memory access verification.
    Memory = 1,
    /// Control flow analysis.
    ControlFlow = 2,
    /// Helper function call validation.
    HelperCall = 3,
    /// Map access verification.
    MapAccess = 4,
    /// Type safety check.
    TypeCheck = 5,
    /// Instruction limit.
    InsnLimit = 6,
    /// Stack depth.
    StackDepth = 7,
}

impl LogCategory {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Memory => "memory",
            Self::ControlFlow => "control_flow",
            Self::HelperCall => "helper_call",
            Self::MapAccess => "map_access",
            Self::TypeCheck => "type_check",
            Self::InsnLimit => "insn_limit",
            Self::StackDepth => "stack_depth",
        }
    }
}

/// A single verifier log entry.
#[derive(Debug, Clone, Copy)]
pub struct LogEntry {
    /// Log level.
    pub level: LogLevel,
    /// Category.
    pub category: LogCategory,
    /// BPF instruction offset.
    pub insn_offset: u32,
    /// Program ID being verified.
    pub prog_id: u64,
    /// Message bytes.
    pub msg: [u8; MAX_MSG_LEN],
    /// Message length.
    pub msg_len: usize,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl LogEntry {
    const fn empty() -> Self {
        Self {
            level: LogLevel::Error,
            category: LogCategory::Register,
            insn_offset: 0,
            prog_id: 0,
            msg: [0u8; MAX_MSG_LEN],
            msg_len: 0,
            valid: false,
        }
    }
}

/// Statistics for verifier logging.
#[derive(Debug, Clone, Copy)]
pub struct VerifierLogStats {
    /// Total log entries written.
    pub total_entries: u64,
    /// Entries dropped (buffer full, no overwrite).
    pub total_dropped: u64,
    /// Total error-level entries.
    pub total_errors: u64,
    /// Total warning-level entries.
    pub total_warnings: u64,
    /// Total programs that produced logs.
    pub total_programs_logged: u64,
}

impl VerifierLogStats {
    const fn new() -> Self {
        Self {
            total_entries: 0,
            total_dropped: 0,
            total_errors: 0,
            total_warnings: 0,
            total_programs_logged: 0,
        }
    }
}

/// Top-level BPF verifier log subsystem.
pub struct BpfVerifierLog {
    /// Log entries (ring buffer).
    entries: [LogEntry; MAX_LOG_ENTRIES],
    /// Statistics.
    stats: VerifierLogStats,
    /// Write cursor.
    write_cursor: usize,
    /// Minimum log level to record.
    min_level: LogLevel,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Whether to overwrite old entries.
    overwrite: bool,
}

impl Default for BpfVerifierLog {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfVerifierLog {
    /// Create a new verifier log subsystem.
    pub const fn new() -> Self {
        Self {
            entries: [const { LogEntry::empty() }; MAX_LOG_ENTRIES],
            stats: VerifierLogStats::new(),
            write_cursor: 0,
            min_level: LogLevel::Error,
            initialised: false,
            overwrite: true,
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

    /// Set the minimum log level.
    pub fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    /// Set overwrite mode.
    pub fn set_overwrite(&mut self, overwrite: bool) {
        self.overwrite = overwrite;
    }

    /// Write a log entry.
    pub fn log(
        &mut self,
        level: LogLevel,
        category: LogCategory,
        prog_id: u64,
        insn_offset: u32,
        msg: &[u8],
    ) -> Result<()> {
        if (level as u8) > (self.min_level as u8) {
            return Ok(());
        }

        let slot = if self.overwrite {
            let s = self.write_cursor;
            self.write_cursor = (self.write_cursor + 1) % MAX_LOG_ENTRIES;
            s
        } else {
            match self.entries.iter().position(|e| !e.valid) {
                Some(s) => s,
                None => {
                    self.stats.total_dropped += 1;
                    return Err(Error::OutOfMemory);
                }
            }
        };

        let copy_len = msg.len().min(MAX_MSG_LEN);
        self.entries[slot] = LogEntry::empty();
        self.entries[slot].level = level;
        self.entries[slot].category = category;
        self.entries[slot].prog_id = prog_id;
        self.entries[slot].insn_offset = insn_offset;
        self.entries[slot].msg[..copy_len].copy_from_slice(&msg[..copy_len]);
        self.entries[slot].msg_len = copy_len;
        self.entries[slot].valid = true;

        self.stats.total_entries += 1;
        match level {
            LogLevel::Error => self.stats.total_errors += 1,
            LogLevel::Warn => self.stats.total_warnings += 1,
            _ => {}
        }

        Ok(())
    }

    /// Count entries for a specific program.
    pub fn count_for_prog(&self, prog_id: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| e.valid && e.prog_id == prog_id)
            .count()
    }

    /// Clear all entries for a program.
    pub fn clear_prog(&mut self, prog_id: u64) {
        for entry in &mut self.entries {
            if entry.valid && entry.prog_id == prog_id {
                *entry = LogEntry::empty();
            }
        }
    }

    /// Clear all log entries.
    pub fn clear_all(&mut self) {
        for entry in &mut self.entries {
            *entry = LogEntry::empty();
        }
        self.write_cursor = 0;
    }

    /// Return the total number of valid entries.
    pub fn entry_count(&self) -> usize {
        self.entries.iter().filter(|e| e.valid).count()
    }

    /// Return statistics.
    pub fn stats(&self) -> VerifierLogStats {
        self.stats
    }
}
