// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel oops/panic handling — capture CPU state, stack traces,
//! and invoke notifier chains on fatal kernel errors.
//!
//! When the kernel encounters a fatal error (NULL-pointer deref,
//! assertion failure, stack overflow, etc.) it produces an "oops"
//! record. The oops handler captures the full CPU register state,
//! collects a stack backtrace, invokes any registered oops
//! notifiers, and finally executes the configured die action
//! (halt, reboot, or continue with tainted state).
//!
//! # Architecture
//!
//! ```text
//! Exception / BUG() / panic!()
//!       │
//!       ▼
//!  OopsHandler::oops()
//!       ├── capture CpuRegState
//!       ├── capture StackFrame[]
//!       ├── build OopsRecord
//!       ├── invoke OopsNotifier chain (priority ordered)
//!       ├── increment oops_count
//!       └── execute DieAction
//! ```
//!
//! # Notifier Chain
//!
//! Subsystems register [`OopsNotifier`] callbacks to be invoked
//! before the die action. Notifiers run in priority order (lower
//! numeric priority runs first) and can request to suppress the
//! die action (e.g. a debug agent might want to halt instead of
//! rebooting).
//!
//! Reference: Linux `kernel/panic.c`,
//! `arch/x86/kernel/dumpstack.c`, `arch/x86/kernel/traps.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum oops records kept in the ring.
const MAX_OOPS_RECORDS: usize = 16;

/// Maximum stack frames captured per oops.
const MAX_STACK_FRAMES: usize = 32;

/// Maximum oops message length (bytes).
const MAX_OOPS_MSG_LEN: usize = 256;

/// Maximum notifier callbacks.
const MAX_NOTIFIERS: usize = 16;

/// Maximum notifier name length (bytes).
const MAX_NOTIFIER_NAME_LEN: usize = 32;

/// Maximum module name length that can be blamed.
const MAX_MODULE_NAME_LEN: usize = 32;

// ══════════════════════════════════════════════════════════════
// DieAction
// ══════════════════════════════════════════════════════════════

/// Action to take after an oops is fully processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DieAction {
    /// Halt the CPU (triple fault on x86).
    #[default]
    Halt = 0,
    /// Attempt warm reboot.
    Reboot = 1,
    /// Spin forever with interrupts disabled.
    Spin = 2,
    /// Mark kernel tainted and attempt to continue.
    Continue = 3,
}

// ══════════════════════════════════════════════════════════════
// OopsReason
// ══════════════════════════════════════════════════════════════

/// Classification of the oops cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OopsReason {
    /// Software bug / assertion failure.
    Bug = 0,
    /// NULL pointer dereference.
    NullDeref = 1,
    /// General protection fault.
    GeneralProtection = 2,
    /// Page fault in kernel mode.
    PageFault = 3,
    /// Stack overflow.
    StackOverflow = 4,
    /// Undefined instruction / invalid opcode.
    InvalidOpcode = 5,
    /// Division by zero.
    DivideByZero = 6,
    /// Explicit kernel panic call.
    ExplicitPanic = 7,
    /// Watchdog timeout (NMI or soft lockup).
    WatchdogTimeout = 8,
    /// Unknown / other.
    #[default]
    Unknown = 255,
}

// ══════════════════════════════════════════════════════════════
// CpuRegState — captured register file
// ══════════════════════════════════════════════════════════════

/// Snapshot of x86-64 CPU registers at the point of the oops.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuRegState {
    /// Instruction pointer.
    pub rip: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Base pointer (frame pointer).
    pub rbp: u64,
    /// Flags register.
    pub rflags: u64,
    /// General purpose registers rax..r15.
    pub gpr: [u64; 16],
    /// Code segment selector.
    pub cs: u16,
    /// Stack segment selector.
    pub ss: u16,
    /// Data segment selector.
    pub ds: u16,
    /// Extra segment selector.
    pub es: u16,
    /// FS segment base.
    pub fs_base: u64,
    /// GS segment base.
    pub gs_base: u64,
    /// CR2 — page fault linear address.
    pub cr2: u64,
    /// CR3 — page table root.
    pub cr3: u64,
    /// Error code pushed by the CPU (if applicable).
    pub error_code: u64,
}

impl Default for CpuRegState {
    fn default() -> Self {
        Self::empty()
    }
}

impl CpuRegState {
    /// Create a zeroed register state.
    pub const fn empty() -> Self {
        Self {
            rip: 0,
            rsp: 0,
            rbp: 0,
            rflags: 0,
            gpr: [0u64; 16],
            cs: 0,
            ss: 0,
            ds: 0,
            es: 0,
            fs_base: 0,
            gs_base: 0,
            cr2: 0,
            cr3: 0,
            error_code: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// StackFrame
// ══════════════════════════════════════════════════════════════

/// A single stack frame captured during backtrace.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackFrame {
    /// Return address.
    pub return_addr: u64,
    /// Frame pointer (rbp) at this frame.
    pub frame_ptr: u64,
    /// Stack pointer (rsp) at this frame.
    pub stack_ptr: u64,
}

impl StackFrame {
    /// Create an empty stack frame.
    const fn empty() -> Self {
        Self {
            return_addr: 0,
            frame_ptr: 0,
            stack_ptr: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// OopsRecord
// ══════════════════════════════════════════════════════════════

/// A complete oops record capturing the full crash context.
pub struct OopsRecord {
    /// Monotonic oops index.
    pub oops_id: u64,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// CPU on which the oops occurred.
    pub cpu: u32,
    /// Process ID of the running task.
    pub pid: u64,
    /// Reason classification.
    pub reason: OopsReason,
    /// CPU register state at the point of the fault.
    pub regs: CpuRegState,
    /// Captured stack frames.
    frames: [StackFrame; MAX_STACK_FRAMES],
    /// Number of valid frames.
    frame_count: usize,
    /// Human-readable oops message.
    message: [u8; MAX_OOPS_MSG_LEN],
    /// Message length.
    message_len: usize,
    /// Name of the module suspected of the fault.
    module: [u8; MAX_MODULE_NAME_LEN],
    /// Module name length.
    module_len: usize,
    /// Whether this record slot is occupied.
    occupied: bool,
}

impl OopsRecord {
    /// Create an empty record.
    const fn empty() -> Self {
        Self {
            oops_id: 0,
            timestamp_ns: 0,
            cpu: 0,
            pid: 0,
            reason: OopsReason::Unknown,
            regs: CpuRegState::empty(),
            frames: [const { StackFrame::empty() }; MAX_STACK_FRAMES],
            frame_count: 0,
            message: [0u8; MAX_OOPS_MSG_LEN],
            message_len: 0,
            module: [0u8; MAX_MODULE_NAME_LEN],
            module_len: 0,
            occupied: false,
        }
    }

    /// Return the oops message as a byte slice.
    pub fn message(&self) -> &[u8] {
        &self.message[..self.message_len]
    }

    /// Return the blamed module name as a byte slice.
    pub fn module_name(&self) -> &[u8] {
        &self.module[..self.module_len]
    }

    /// Return captured stack frames.
    pub fn stack_frames(&self) -> &[StackFrame] {
        &self.frames[..self.frame_count]
    }
}

// ══════════════════════════════════════════════════════════════
// NotifierAction
// ══════════════════════════════════════════════════════════════

/// Return value from an oops notifier callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierAction {
    /// Continue processing the notifier chain.
    Continue,
    /// Stop processing and suppress the die action.
    Suppress,
}

// ══════════════════════════════════════════════════════════════
// OopsNotifier
// ══════════════════════════════════════════════════════════════

/// A registered oops notifier callback.
pub struct OopsNotifier {
    /// Human-readable name.
    name: [u8; MAX_NOTIFIER_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Priority (lower runs first).
    pub priority: i32,
    /// Callback function pointer.
    pub callback: fn(&OopsRecord) -> NotifierAction,
    /// Whether this slot is in use.
    active: bool,
}

impl OopsNotifier {
    /// Create an empty notifier slot.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NOTIFIER_NAME_LEN],
            name_len: 0,
            priority: 0,
            callback: |_| NotifierAction::Continue,
            active: false,
        }
    }

    /// Return the notifier name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ══════════════════════════════════════════════════════════════
// OopsHandler
// ══════════════════════════════════════════════════════════════

/// Parameters for recording an oops event.
pub struct OopsParams<'a> {
    /// Reason classification.
    pub reason: OopsReason,
    /// CPU register state at the point of the fault.
    pub regs: &'a CpuRegState,
    /// Captured stack frames.
    pub frames: &'a [StackFrame],
    /// Human-readable oops message.
    pub message: &'a [u8],
    /// Name of the module suspected of the fault.
    pub module: &'a [u8],
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// CPU on which the oops occurred.
    pub cpu: u32,
    /// Process ID of the running task.
    pub pid: u64,
}

/// Kernel oops handler — records oops events and manages the
/// notifier chain and die action policy.
pub struct OopsHandler {
    /// Ring of oops records.
    records: [OopsRecord; MAX_OOPS_RECORDS],
    /// Total number of oops recorded since boot.
    oops_count: u64,
    /// Write cursor into the records ring.
    write_idx: usize,
    /// Registered notifiers.
    notifiers: [OopsNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Action to take after processing an oops.
    die_action: DieAction,
    /// Whether the kernel is considered tainted.
    tainted: bool,
    /// Taint flags bitmask.
    taint_flags: u64,
}

impl Default for OopsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl OopsHandler {
    /// Create a new oops handler with default configuration.
    pub const fn new() -> Self {
        Self {
            records: [const { OopsRecord::empty() }; MAX_OOPS_RECORDS],
            oops_count: 0,
            write_idx: 0,
            notifiers: [const { OopsNotifier::empty() }; MAX_NOTIFIERS],
            notifier_count: 0,
            die_action: DieAction::Halt,
            tainted: false,
            taint_flags: 0,
        }
    }

    /// Set the die action policy.
    pub fn set_die_action(&mut self, action: DieAction) {
        self.die_action = action;
    }

    /// Return the current die action.
    pub fn die_action(&self) -> DieAction {
        self.die_action
    }

    /// Return the total number of oops events since boot.
    pub fn oops_count(&self) -> u64 {
        self.oops_count
    }

    /// Return whether the kernel is tainted.
    pub fn is_tainted(&self) -> bool {
        self.tainted
    }

    /// Return the taint flags bitmask.
    pub fn taint_flags(&self) -> u64 {
        self.taint_flags
    }

    /// Register an oops notifier callback.
    ///
    /// Returns the notifier index on success.
    pub fn register_notifier(
        &mut self,
        name: &[u8],
        priority: i32,
        callback: fn(&OopsRecord) -> NotifierAction,
    ) -> Result<usize> {
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let pos = self
            .notifiers
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        let notifier = &mut self.notifiers[pos];
        let nlen = name.len().min(MAX_NOTIFIER_NAME_LEN);
        notifier.name[..nlen].copy_from_slice(&name[..nlen]);
        notifier.name_len = nlen;
        notifier.priority = priority;
        notifier.callback = callback;
        notifier.active = true;

        self.notifier_count += 1;
        Ok(pos)
    }

    /// Unregister an oops notifier by index.
    pub fn unregister_notifier(&mut self, index: usize) -> Result<()> {
        if index >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }

        let notifier = &mut self.notifiers[index];
        if !notifier.active {
            return Err(Error::NotFound);
        }

        notifier.active = false;
        notifier.name_len = 0;
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Record an oops event. Captures CPU state, builds the
    /// record, invokes notifiers, and returns the die action
    /// that should be executed by the caller.
    ///
    /// The caller is responsible for executing the returned
    /// `DieAction` (halting, rebooting, etc.).
    pub fn oops(&mut self, params: &OopsParams<'_>) -> DieAction {
        let record_id = self.oops_count;
        let idx = self.write_idx;

        // Build the record.
        let record = &mut self.records[idx];
        record.oops_id = record_id;
        record.timestamp_ns = params.timestamp_ns;
        record.cpu = params.cpu;
        record.pid = params.pid;
        record.reason = params.reason;
        record.regs = *params.regs;
        record.occupied = true;

        let fcount = params.frames.len().min(MAX_STACK_FRAMES);
        record.frames[..fcount].copy_from_slice(&params.frames[..fcount]);
        record.frame_count = fcount;

        let mlen = params.message.len().min(MAX_OOPS_MSG_LEN);
        record.message[..mlen].copy_from_slice(&params.message[..mlen]);
        record.message_len = mlen;

        let modlen = params.module.len().min(MAX_MODULE_NAME_LEN);
        record.module[..modlen].copy_from_slice(&params.module[..modlen]);
        record.module_len = modlen;

        self.oops_count += 1;
        self.write_idx = (idx + 1) % MAX_OOPS_RECORDS;

        // Invoke notifier chain in priority order.
        let action = self.invoke_notifiers(record_id);

        // Set tainted if die_action is Continue.
        if self.die_action == DieAction::Continue {
            self.tainted = true;
            self.taint_flags |= 1 << (params.reason as u8);
        }

        if action == NotifierAction::Suppress {
            DieAction::Halt
        } else {
            self.die_action
        }
    }

    /// Invoke registered notifiers in priority order for the
    /// oops record identified by `record_id`.
    fn invoke_notifiers(&self, record_id: u64) -> NotifierAction {
        // Collect active notifier indices sorted by priority.
        let mut order = [0usize; MAX_NOTIFIERS];
        let mut count = 0;

        for (i, notifier) in self.notifiers.iter().enumerate() {
            if notifier.active {
                order[count] = i;
                count += 1;
            }
        }

        // Insertion sort by priority (small list).
        for i in 1..count {
            let key = order[i];
            let key_prio = self.notifiers[key].priority;
            let mut j = i;
            while j > 0 && self.notifiers[order[j - 1]].priority > key_prio {
                order[j] = order[j - 1];
                j -= 1;
            }
            order[j] = key;
        }

        // Find the record by id.
        let record = self
            .records
            .iter()
            .find(|r| r.occupied && r.oops_id == record_id);

        let record = match record {
            Some(r) => r,
            None => return NotifierAction::Continue,
        };

        // Invoke callbacks.
        for &idx in &order[..count] {
            let cb = self.notifiers[idx].callback;
            if cb(record) == NotifierAction::Suppress {
                return NotifierAction::Suppress;
            }
        }

        NotifierAction::Continue
    }

    /// Return the most recent oops record, if any.
    pub fn last_oops(&self) -> Option<&OopsRecord> {
        if self.oops_count == 0 {
            return None;
        }
        let idx = if self.write_idx == 0 {
            MAX_OOPS_RECORDS - 1
        } else {
            self.write_idx - 1
        };
        let record = &self.records[idx];
        if record.occupied { Some(record) } else { None }
    }

    /// Return a reference to an oops record by ring index.
    pub fn get_record(&self, index: usize) -> Result<&OopsRecord> {
        if index >= MAX_OOPS_RECORDS {
            return Err(Error::InvalidArgument);
        }
        let record = &self.records[index];
        if !record.occupied {
            return Err(Error::NotFound);
        }
        Ok(record)
    }

    /// Return the number of active notifiers.
    pub fn notifier_count(&self) -> usize {
        self.notifier_count
    }
}
