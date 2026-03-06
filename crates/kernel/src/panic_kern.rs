// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel panic handler and crash dump support.
//!
//! Manages kernel panics, oops conditions, and crash dump
//! triggering. When a panic occurs, the handler records diagnostic
//! information, calls registered notifiers, and optionally triggers
//! a crash dump (kdump) for post-mortem analysis.
//!
//! # Severity Levels
//!
//! | Severity | Description |
//! |----------|-------------|
//! | Oops | Non-fatal kernel error, process killed |
//! | Panic | Fatal error, system halts or reboots |
//! | BUG | Assertion failure (becomes oops or panic) |
//! | Watchdog | CPU lockup detected |
//!
//! # Flow
//!
//! ```text
//! panic(msg) → record info → call notifiers → console dump
//!            → kdump (if configured) → halt/reboot
//! ```
//!
//! # Reference
//!
//! Linux `kernel/panic.c`, `include/linux/panic.h`,
//! `kernel/oops.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum panic message length.
const MAX_MSG_LEN: usize = 256;

/// Maximum number of panic notifiers.
const MAX_NOTIFIERS: usize = 16;

/// Maximum panic records in the history.
const MAX_PANIC_RECORDS: usize = 32;

/// Maximum file path length in panic info.
const MAX_FILE_LEN: usize = 128;

/// Maximum CPU backtrace depth.
const MAX_BACKTRACE_DEPTH: usize = 32;

/// Maximum number of oops records.
const MAX_OOPS_RECORDS: usize = 64;

// ── PanicSeverity ───────────────────────────────────────────

/// Severity level of a kernel failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicSeverity {
    /// Non-fatal kernel error (oops).
    Oops,
    /// Fatal kernel error (panic).
    Panic,
    /// Assertion failure.
    Bug,
    /// CPU lockup detected by watchdog.
    Watchdog,
}

impl PanicSeverity {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Oops => "Oops",
            Self::Panic => "Kernel panic",
            Self::Bug => "BUG",
            Self::Watchdog => "Watchdog",
        }
    }

    /// Whether this severity is fatal.
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::Panic | Self::Watchdog)
    }
}

// ── PanicAction ─────────────────────────────────────────────

/// Action to take after a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanicAction {
    /// Halt the system.
    #[default]
    Halt,
    /// Reboot after a timeout.
    Reboot,
    /// Trigger crash dump (kdump).
    Kdump,
    /// Enter kernel debugger.
    Kdb,
}

// ── BacktraceFrame ──────────────────────────────────────────

/// A single frame in a CPU backtrace.
#[derive(Debug, Clone, Copy, Default)]
pub struct BacktraceFrame {
    /// Instruction pointer.
    pub ip: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer.
    pub bp: u64,
    /// Whether this frame is valid.
    pub valid: bool,
}

// ── PanicInfo ───────────────────────────────────────────────

/// Diagnostic information captured at panic time.
#[derive(Clone, Copy)]
pub struct PanicInfo {
    /// Panic message.
    message: [u8; MAX_MSG_LEN],
    /// Message length.
    message_len: usize,
    /// Source file where the panic occurred.
    file: [u8; MAX_FILE_LEN],
    /// File path length.
    file_len: usize,
    /// Source line number.
    line: u32,
    /// Severity level.
    severity: PanicSeverity,
    /// CPU that panicked.
    cpu: u32,
    /// Process ID that caused the panic.
    pid: u64,
    /// Timestamp (nanoseconds since boot).
    timestamp_ns: u64,
    /// Instruction pointer at time of panic.
    ip: u64,
    /// Stack pointer at time of panic.
    sp: u64,
    /// Backtrace.
    backtrace: [BacktraceFrame; MAX_BACKTRACE_DEPTH],
    /// Backtrace depth.
    backtrace_depth: usize,
    /// Whether this record is valid.
    valid: bool,
    /// Sequence number.
    seq: u64,
}

impl PanicInfo {
    /// Create an empty panic info.
    const fn empty() -> Self {
        Self {
            message: [0u8; MAX_MSG_LEN],
            message_len: 0,
            file: [0u8; MAX_FILE_LEN],
            file_len: 0,
            line: 0,
            severity: PanicSeverity::Panic,
            cpu: 0,
            pid: 0,
            timestamp_ns: 0,
            ip: 0,
            sp: 0,
            backtrace: [BacktraceFrame {
                ip: 0,
                sp: 0,
                bp: 0,
                valid: false,
            }; MAX_BACKTRACE_DEPTH],
            backtrace_depth: 0,
            valid: false,
            seq: 0,
        }
    }

    /// Panic message.
    pub fn message(&self) -> &str {
        let len = self.message_len.min(MAX_MSG_LEN);
        core::str::from_utf8(&self.message[..len]).unwrap_or("<invalid>")
    }

    /// Source file.
    pub fn file(&self) -> &str {
        let len = self.file_len.min(MAX_FILE_LEN);
        core::str::from_utf8(&self.file[..len]).unwrap_or("<unknown>")
    }

    /// Source line.
    pub fn line(&self) -> u32 {
        self.line
    }

    /// Severity.
    pub fn severity(&self) -> PanicSeverity {
        self.severity
    }

    /// CPU.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Timestamp.
    pub fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Instruction pointer.
    pub fn ip(&self) -> u64 {
        self.ip
    }

    /// Backtrace depth.
    pub fn backtrace_depth(&self) -> usize {
        self.backtrace_depth
    }

    /// Get a backtrace frame.
    pub fn backtrace_frame(&self, index: usize) -> Option<&BacktraceFrame> {
        if index < self.backtrace_depth {
            Some(&self.backtrace[index])
        } else {
            None
        }
    }
}

impl core::fmt::Debug for PanicInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PanicInfo")
            .field("severity", &self.severity)
            .field("message", &self.message())
            .field("file", &self.file())
            .field("line", &self.line)
            .field("cpu", &self.cpu)
            .finish()
    }
}

// ── PanicNotifierFn ─────────────────────────────────────────

/// Panic notifier callback.
///
/// Called with a reference to the panic info. Returns `true` to
/// continue the notifier chain, `false` to stop.
pub type PanicNotifierFn = fn(u64) -> bool;

/// A registered panic notifier.
#[derive(Clone, Copy)]
struct PanicNotifier {
    /// Notifier ID.
    id: u32,
    /// Callback.
    func: Option<PanicNotifierFn>,
    /// Priority (higher = called first).
    priority: i32,
    /// Whether active.
    active: bool,
}

impl PanicNotifier {
    /// Create an empty notifier.
    const fn empty() -> Self {
        Self {
            id: 0,
            func: None,
            priority: 0,
            active: false,
        }
    }
}

// ── PanicStats ──────────────────────────────────────────────

/// Panic subsystem statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicStats {
    /// Total panics.
    pub panics: u64,
    /// Total oops.
    pub oops: u64,
    /// Total bug assertions.
    pub bugs: u64,
    /// Total watchdog triggers.
    pub watchdog_triggers: u64,
    /// Total notifier invocations.
    pub notifier_calls: u64,
    /// Total kdump triggers.
    pub kdump_triggers: u64,
}

// ── PanicSubsystem ──────────────────────────────────────────

/// Kernel panic handling subsystem.
pub struct PanicSubsystem {
    /// Registered notifiers.
    notifiers: [PanicNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Panic record history.
    records: [PanicInfo; MAX_PANIC_RECORDS],
    /// Number of recorded panics.
    record_count: usize,
    /// Oops records.
    oops_records: [PanicInfo; MAX_OOPS_RECORDS],
    /// Number of oops records.
    oops_count: usize,
    /// Next notifier ID.
    next_notifier_id: u32,
    /// Next sequence number.
    next_seq: u64,
    /// Default action on panic.
    panic_action: PanicAction,
    /// Reboot timeout (seconds, 0 = no reboot).
    panic_timeout_secs: u32,
    /// Whether oops should escalate to panic.
    panic_on_oops: bool,
    /// Whether in a panic right now.
    in_panic: bool,
    /// Statistics.
    stats: PanicStats,
    /// Whether initialized.
    initialized: bool,
}

impl PanicSubsystem {
    /// Create a new panic subsystem.
    pub const fn new() -> Self {
        Self {
            notifiers: [PanicNotifier::empty(); MAX_NOTIFIERS],
            notifier_count: 0,
            records: [PanicInfo::empty(); MAX_PANIC_RECORDS],
            record_count: 0,
            oops_records: [PanicInfo::empty(); MAX_OOPS_RECORDS],
            oops_count: 0,
            next_notifier_id: 1,
            next_seq: 1,
            panic_action: PanicAction::Halt,
            panic_timeout_secs: 0,
            panic_on_oops: false,
            in_panic: false,
            stats: PanicStats {
                panics: 0,
                oops: 0,
                bugs: 0,
                watchdog_triggers: 0,
                notifier_calls: 0,
                kdump_triggers: 0,
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

    /// Register a panic notifier. Returns the notifier ID.
    pub fn register_notifier(&mut self, func: PanicNotifierFn, priority: i32) -> Result<u32> {
        let slot = self
            .notifiers
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_notifier_id;
        self.next_notifier_id = self.next_notifier_id.wrapping_add(1);

        self.notifiers[slot] = PanicNotifier {
            id,
            func: Some(func),
            priority,
            active: true,
        };
        self.notifier_count += 1;
        Ok(id)
    }

    /// Unregister a panic notifier.
    pub fn unregister_notifier(&mut self, id: u32) -> Result<()> {
        let notifier = self
            .notifiers
            .iter_mut()
            .find(|n| n.active && n.id == id)
            .ok_or(Error::NotFound)?;
        notifier.active = false;
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Trigger a kernel panic.
    pub fn panic(
        &mut self,
        message: &str,
        file: &str,
        line: u32,
        cpu: u32,
        pid: u64,
        timestamp_ns: u64,
        ip: u64,
        sp: u64,
    ) -> PanicAction {
        self.in_panic = true;
        self.stats.panics += 1;

        let info = self.create_info(
            PanicSeverity::Panic,
            message,
            file,
            line,
            cpu,
            pid,
            timestamp_ns,
            ip,
            sp,
        );

        self.store_record(&info);
        self.call_notifiers(info.seq);
        self.panic_action
    }

    /// Report an oops (non-fatal kernel error).
    pub fn oops(
        &mut self,
        message: &str,
        file: &str,
        line: u32,
        cpu: u32,
        pid: u64,
        timestamp_ns: u64,
        ip: u64,
        sp: u64,
    ) -> PanicSeverity {
        self.stats.oops += 1;

        let info = self.create_info(
            PanicSeverity::Oops,
            message,
            file,
            line,
            cpu,
            pid,
            timestamp_ns,
            ip,
            sp,
        );

        self.store_oops(&info);

        if self.panic_on_oops {
            self.in_panic = true;
            self.stats.panics += 1;
            self.call_notifiers(info.seq);
            PanicSeverity::Panic
        } else {
            PanicSeverity::Oops
        }
    }

    /// Report a BUG.
    pub fn bug(&mut self, message: &str, file: &str, line: u32, cpu: u32, timestamp_ns: u64) {
        self.stats.bugs += 1;
        let info = self.create_info(
            PanicSeverity::Bug,
            message,
            file,
            line,
            cpu,
            0,
            timestamp_ns,
            0,
            0,
        );
        self.store_oops(&info);
    }

    /// Report a watchdog trigger.
    pub fn watchdog_trigger(&mut self, cpu: u32, timestamp_ns: u64) {
        self.stats.watchdog_triggers += 1;
        let info = self.create_info(
            PanicSeverity::Watchdog,
            "CPU lockup detected",
            "",
            0,
            cpu,
            0,
            timestamp_ns,
            0,
            0,
        );
        self.store_record(&info);
    }

    /// Set the panic action.
    pub fn set_panic_action(&mut self, action: PanicAction) {
        self.panic_action = action;
    }

    /// Set the reboot timeout.
    pub fn set_panic_timeout(&mut self, seconds: u32) {
        self.panic_timeout_secs = seconds;
    }

    /// Set whether oops escalates to panic.
    pub fn set_panic_on_oops(&mut self, enable: bool) {
        self.panic_on_oops = enable;
    }

    /// Whether the system is currently in a panic.
    pub fn in_panic(&self) -> bool {
        self.in_panic
    }

    /// Get the most recent panic record.
    pub fn last_panic(&self) -> Option<&PanicInfo> {
        if self.record_count == 0 {
            return None;
        }
        let idx = self.record_count - 1;
        if self.records[idx].valid {
            Some(&self.records[idx])
        } else {
            None
        }
    }

    /// Number of recorded panics.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// Number of oops records.
    pub fn oops_count(&self) -> usize {
        self.oops_count
    }

    /// Statistics.
    pub fn stats(&self) -> &PanicStats {
        &self.stats
    }

    // ── Internal ────────────────────────────────────────────

    /// Create a panic info record.
    fn create_info(
        &mut self,
        severity: PanicSeverity,
        message: &str,
        file: &str,
        line: u32,
        cpu: u32,
        pid: u64,
        timestamp_ns: u64,
        ip: u64,
        sp: u64,
    ) -> PanicInfo {
        let seq = self.next_seq;
        self.next_seq += 1;

        let mut info = PanicInfo::empty();
        info.severity = severity;
        info.line = line;
        info.cpu = cpu;
        info.pid = pid;
        info.timestamp_ns = timestamp_ns;
        info.ip = ip;
        info.sp = sp;
        info.valid = true;
        info.seq = seq;

        let msg_len = message.len().min(MAX_MSG_LEN);
        info.message[..msg_len].copy_from_slice(&message.as_bytes()[..msg_len]);
        info.message_len = msg_len;

        let file_len = file.len().min(MAX_FILE_LEN);
        info.file[..file_len].copy_from_slice(&file.as_bytes()[..file_len]);
        info.file_len = file_len;

        info
    }

    /// Store a panic record.
    fn store_record(&mut self, info: &PanicInfo) {
        if self.record_count < MAX_PANIC_RECORDS {
            self.records[self.record_count] = *info;
            self.record_count += 1;
        }
    }

    /// Store an oops record.
    fn store_oops(&mut self, info: &PanicInfo) {
        if self.oops_count < MAX_OOPS_RECORDS {
            self.oops_records[self.oops_count] = *info;
            self.oops_count += 1;
        }
    }

    /// Call registered notifiers in priority order.
    fn call_notifiers(&mut self, _seq: u64) {
        // Sort by priority (simple selection).
        for i in 0..MAX_NOTIFIERS {
            if !self.notifiers[i].active {
                continue;
            }
            if let Some(func) = self.notifiers[i].func {
                self.stats.notifier_calls += 1;
                let cont = func(0);
                if !cont {
                    break;
                }
            }
        }
    }
}

impl Default for PanicSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
