// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel panic handling and crash dump management.
//!
//! Provides the infrastructure for handling kernel panics, capturing
//! register state, producing crash dumps, and performing recovery
//! actions (halt or reboot). This module extends the raw panic
//! diagnostics in [`crate::panic_info`] with policy and recovery
//! logic, modeled after Linux's `kernel/panic.c`.
//!
//! # Architecture
//!
//! ```text
//!   panic!() / exception
//!         │
//!         ▼
//!   PanicHandler::on_panic()
//!         │
//!         ├── capture RegisterState
//!         ├── write CrashDump entry
//!         ├── invoke notifier chain
//!         └── execute PanicAction (halt / reboot / spin)
//! ```
//!
//! # Notifier Chain
//!
//! Subsystems can register [`PanicNotifier`] callbacks that are
//! invoked in priority order before the final panic action. This
//! allows drivers to flush buffers, save persistent state, or
//! emit diagnostic information.
//!
//! # Crash Dump
//!
//! Up to [`MAX_CRASH_DUMPS`] crash records are kept in a ring
//! buffer. Each record contains the full register state, a stack
//! dump of up to [`MAX_STACK_WORDS`] words, the panic message,
//! and a timestamp.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum crash dump records in the ring buffer.
const MAX_CRASH_DUMPS: usize = 8;

/// Maximum words in the stack dump.
const MAX_STACK_WORDS: usize = 64;

/// Maximum panic message length in bytes.
const MAX_MESSAGE_LEN: usize = 256;

/// Maximum file path length in bytes.
const MAX_FILE_LEN: usize = 128;

/// Maximum number of panic notifier callbacks.
const MAX_NOTIFIERS: usize = 16;

/// Maximum notifier name length in bytes.
const MAX_NOTIFIER_NAME_LEN: usize = 32;

/// Kernel virtual address space lower bound (x86_64 canonical).
const _KERNEL_ADDR_START: u64 = 0xFFFF_8000_0000_0000;

// ── PanicAction ──────────────────────────────────────────────

/// Action to take after a kernel panic has been recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanicAction {
    /// Halt the system (freeze all CPUs).
    #[default]
    Halt,
    /// Attempt a system reboot.
    Reboot,
    /// Spin in a tight loop (useful for debugging via JTAG).
    Spin,
    /// Invoke kexec to load a crash kernel.
    Kexec,
}

impl PanicAction {
    /// Create from a raw u32 value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Halt),
            1 => Some(Self::Reboot),
            2 => Some(Self::Spin),
            3 => Some(Self::Kexec),
            _ => None,
        }
    }
}

// ── RegisterState ────────────────────────────────────────────

/// Full x86_64 register snapshot captured at panic time.
///
/// This is the public, policy-level register dump. For the
/// low-level crash-time capture see [`crate::panic_info`].
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RegisterState {
    /// General-purpose register RAX.
    pub rax: u64,
    /// General-purpose register RBX.
    pub rbx: u64,
    /// General-purpose register RCX.
    pub rcx: u64,
    /// General-purpose register RDX.
    pub rdx: u64,
    /// General-purpose register RSI.
    pub rsi: u64,
    /// General-purpose register RDI.
    pub rdi: u64,
    /// Frame pointer register RBP.
    pub rbp: u64,
    /// Stack pointer register RSP.
    pub rsp: u64,
    /// Extended register R8.
    pub r8: u64,
    /// Extended register R9.
    pub r9: u64,
    /// Extended register R10.
    pub r10: u64,
    /// Extended register R11.
    pub r11: u64,
    /// Extended register R12.
    pub r12: u64,
    /// Extended register R13.
    pub r13: u64,
    /// Extended register R14.
    pub r14: u64,
    /// Extended register R15.
    pub r15: u64,
    /// Instruction pointer at panic time.
    pub rip: u64,
    /// CPU flags register.
    pub rflags: u64,
    /// Control register CR2 (page-fault address).
    pub cr2: u64,
    /// Control register CR3 (page-table base).
    pub cr3: u64,
}

impl RegisterState {
    /// Create a zeroed register state.
    pub const fn zero() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cr2: 0,
            cr3: 0,
        }
    }

    /// Format the registers into a human-readable dump.
    ///
    /// Writes the register dump into `buf` and returns the
    /// number of bytes written.
    pub fn dump_to(&self, buf: &mut [u8]) -> usize {
        let mut w = BufWriter::new(buf);
        w.write_str("Register dump:\n");
        w.write_str("  RAX=");
        w.write_hex(self.rax);
        w.write_str("  RBX=");
        w.write_hex(self.rbx);
        w.write_str("\n");
        w.write_str("  RCX=");
        w.write_hex(self.rcx);
        w.write_str("  RDX=");
        w.write_hex(self.rdx);
        w.write_str("\n");
        w.write_str("  RSI=");
        w.write_hex(self.rsi);
        w.write_str("  RDI=");
        w.write_hex(self.rdi);
        w.write_str("\n");
        w.write_str("  RBP=");
        w.write_hex(self.rbp);
        w.write_str("  RSP=");
        w.write_hex(self.rsp);
        w.write_str("\n");
        w.write_str("   R8=");
        w.write_hex(self.r8);
        w.write_str("   R9=");
        w.write_hex(self.r9);
        w.write_str("\n");
        w.write_str("  R10=");
        w.write_hex(self.r10);
        w.write_str("  R11=");
        w.write_hex(self.r11);
        w.write_str("\n");
        w.write_str("  R12=");
        w.write_hex(self.r12);
        w.write_str("  R13=");
        w.write_hex(self.r13);
        w.write_str("\n");
        w.write_str("  R14=");
        w.write_hex(self.r14);
        w.write_str("  R15=");
        w.write_hex(self.r15);
        w.write_str("\n");
        w.write_str("  RIP=");
        w.write_hex(self.rip);
        w.write_str("  RFLAGS=");
        w.write_hex(self.rflags);
        w.write_str("\n");
        w.write_str("  CR2=");
        w.write_hex(self.cr2);
        w.write_str("  CR3=");
        w.write_hex(self.cr3);
        w.write_str("\n");
        w.pos
    }
}

// ── PanicInfo ────────────────────────────────────────────────

/// Describes the immediate cause of a kernel panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicCause {
    /// Explicit `panic!()` invocation.
    ExplicitPanic,
    /// Null pointer dereference.
    NullDeref,
    /// Stack overflow detected.
    StackOverflow,
    /// Double fault (unrecoverable CPU exception).
    DoubleFault,
    /// Out of memory in a critical allocation.
    Oom,
    /// Assertion failure.
    AssertionFailed,
    /// Watchdog timeout (hung task).
    WatchdogTimeout,
    /// Hardware error (machine check, NMI, etc.).
    HardwareError,
}

impl PanicCause {
    /// Human-readable description of the cause.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExplicitPanic => "explicit panic",
            Self::NullDeref => "null pointer dereference",
            Self::StackOverflow => "stack overflow",
            Self::DoubleFault => "double fault",
            Self::Oom => "out of memory",
            Self::AssertionFailed => "assertion failed",
            Self::WatchdogTimeout => "watchdog timeout",
            Self::HardwareError => "hardware error",
        }
    }
}

/// Information about a kernel panic event.
#[derive(Debug, Clone, Copy)]
pub struct PanicInfo {
    /// The cause of the panic.
    pub cause: PanicCause,
    /// CPU ID where the panic occurred.
    pub cpu_id: u32,
    /// Monotonic tick count at panic time.
    pub tick: u64,
    /// Whether the panic occurred in interrupt context.
    pub in_interrupt: bool,
    /// Nesting depth of preemption disabling.
    pub preempt_count: u32,
}

impl PanicInfo {
    /// Create a new panic info record.
    pub const fn new(cause: PanicCause) -> Self {
        Self {
            cause,
            cpu_id: 0,
            tick: 0,
            in_interrupt: false,
            preempt_count: 0,
        }
    }
}

// ── CrashDump ────────────────────────────────────────────────

/// A complete crash dump record for one panic event.
///
/// Contains everything needed for post-mortem analysis:
/// register state, partial stack dump, panic message, source
/// location, and timing information.
#[derive(Clone, Copy)]
pub struct CrashDump {
    /// Register state at panic time.
    pub registers: RegisterState,
    /// Stack memory snapshot (up to 64 words from RSP).
    pub stack_words: [u64; MAX_STACK_WORDS],
    /// Number of valid words in `stack_words`.
    pub stack_depth: usize,
    /// Panic message (UTF-8 bytes).
    pub message: [u8; MAX_MESSAGE_LEN],
    /// Valid length of `message`.
    pub message_len: usize,
    /// Source file path where the panic originated.
    pub file: [u8; MAX_FILE_LEN],
    /// Valid length of `file`.
    pub file_len: usize,
    /// Source line number.
    pub line: u32,
    /// Panic info metadata.
    pub info: PanicInfo,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl CrashDump {
    /// Create an empty crash dump for array initialisation.
    const fn empty() -> Self {
        Self {
            registers: RegisterState::zero(),
            stack_words: [0u64; MAX_STACK_WORDS],
            stack_depth: 0,
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
            file: [0u8; MAX_FILE_LEN],
            file_len: 0,
            line: 0,
            info: PanicInfo::new(PanicCause::ExplicitPanic),
            valid: false,
        }
    }

    /// Return the panic message as a string slice.
    pub fn message_str(&self) -> &str {
        let len = self.message_len.min(MAX_MESSAGE_LEN);
        core::str::from_utf8(&self.message[..len]).unwrap_or("<invalid utf-8>")
    }

    /// Return the file path as a string slice.
    pub fn file_str(&self) -> &str {
        let len = self.file_len.min(MAX_FILE_LEN);
        core::str::from_utf8(&self.file[..len]).unwrap_or("<invalid utf-8>")
    }

    /// Set the panic message from a string slice.
    pub fn set_message(&mut self, msg: &str) {
        let bytes = msg.as_bytes();
        let len = bytes.len().min(MAX_MESSAGE_LEN);
        self.message[..len].copy_from_slice(&bytes[..len]);
        self.message_len = len;
    }

    /// Set the source file from a string slice.
    pub fn set_file(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_FILE_LEN);
        self.file[..len].copy_from_slice(&bytes[..len]);
        self.file_len = len;
    }

    /// Capture a stack memory snapshot starting from `rsp`.
    ///
    /// Reads up to [`MAX_STACK_WORDS`] 64-bit words from the
    /// stack pointer address. Each address is validated before
    /// reading.
    ///
    /// # Safety
    ///
    /// The caller must ensure `rsp` points to a valid, mapped
    /// kernel stack region.
    pub unsafe fn capture_stack(&mut self, rsp: u64) {
        self.stack_depth = 0;
        let mut addr = rsp;
        while self.stack_depth < MAX_STACK_WORDS {
            if addr == 0 || addr & 0x7 != 0 {
                break;
            }
            // SAFETY: Caller guarantees rsp is valid mapped
            // kernel stack memory.
            let word = unsafe { core::ptr::read_volatile(addr as *const u64) };
            self.stack_words[self.stack_depth] = word;
            self.stack_depth += 1;
            addr = addr.wrapping_add(8);
        }
    }

    /// Format the crash dump into a buffer for console output.
    ///
    /// Returns the number of bytes written.
    pub fn format_to(&self, buf: &mut [u8]) -> usize {
        let mut w = BufWriter::new(buf);
        w.write_str("===== ONCRIX CRASH DUMP =====\n");
        w.write_str("Cause: ");
        w.write_str(self.info.cause.as_str());
        w.write_str("\n");
        if self.message_len > 0 {
            w.write_str("Message: ");
            w.write_str(self.message_str());
            w.write_str("\n");
        }
        if self.file_len > 0 {
            w.write_str("  at ");
            w.write_str(self.file_str());
            w.write_str(":");
            w.write_u32(self.line);
            w.write_str("\n");
        }
        w.write_str("CPU: ");
        w.write_u32(self.info.cpu_id);
        w.write_str("  Tick: ");
        w.write_u64(self.info.tick);
        w.write_str("\n");
        if self.info.in_interrupt {
            w.write_str("  [in interrupt context]\n");
        }
        w.write_str("\n");

        // Registers — drop writer to release borrow, then reborrow
        let pos_before_regs = w.pos;
        drop(w);
        let reg_len = self.registers.dump_to(&mut buf[pos_before_regs..]);
        let mut w = BufWriter {
            buf,
            pos: pos_before_regs + reg_len,
        };

        // Stack dump
        w.write_str("\nStack dump (");
        w.write_u32(self.stack_depth as u32);
        w.write_str(" words):\n");
        let mut i = 0;
        while i < self.stack_depth {
            w.write_str("  [");
            w.write_u32(i as u32);
            w.write_str("] ");
            w.write_hex(self.stack_words[i]);
            w.write_str("\n");
            i += 1;
        }
        w.write_str("=============================\n");
        w.pos
    }
}

impl core::fmt::Debug for CrashDump {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CrashDump")
            .field("valid", &self.valid)
            .field("cause", &self.info.cause)
            .field("cpu_id", &self.info.cpu_id)
            .field("message_len", &self.message_len)
            .field("stack_depth", &self.stack_depth)
            .finish()
    }
}

// ── PanicNotifier ────────────────────────────────────────────

/// A callback registered to be invoked during a panic.
///
/// Notifiers are invoked in priority order (lower value = higher
/// priority) before the final panic action is taken.
#[derive(Debug, Clone, Copy)]
pub struct PanicNotifier {
    /// Unique notifier identifier.
    pub id: u32,
    /// Human-readable name.
    name: [u8; MAX_NOTIFIER_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Priority (lower = called first).
    pub priority: i32,
    /// Callback function identifier.
    pub func_id: u64,
    /// Opaque data for the callback.
    pub data: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl PanicNotifier {
    /// Create an empty notifier for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NOTIFIER_NAME_LEN],
            name_len: 0,
            priority: 0,
            func_id: 0,
            data: 0,
            active: false,
        }
    }

    /// Return the notifier name as a string slice.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NOTIFIER_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

impl Default for PanicNotifier {
    fn default() -> Self {
        Self::empty()
    }
}

// ── PanicHandler ─────────────────────────────────────────────

/// Central panic handler managing crash dumps, notifiers, and
/// recovery actions.
///
/// This is the primary entry point for kernel panic handling.
/// Typical usage:
///
/// ```ignore
/// let mut handler = PanicHandler::new();
/// handler.set_action(PanicAction::Halt);
/// handler.register_notifier("console", 0, 1, 0)?;
///
/// // On panic:
/// handler.on_panic(info, &regs, "message", "file.rs", 42)?;
/// ```
pub struct PanicHandler {
    /// Ring buffer of crash dump records.
    dumps: [CrashDump; MAX_CRASH_DUMPS],
    /// Total number of panics recorded (wraps around).
    dump_count: usize,
    /// Registered panic notifiers.
    notifiers: [PanicNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Next notifier ID.
    next_notifier_id: u32,
    /// Action to take after recording the panic.
    action: PanicAction,
    /// Whether the handler is currently processing a panic
    /// (recursion guard).
    in_panic: bool,
    /// Timeout in ticks before forced reboot (0 = no timeout).
    pub reboot_timeout: u64,
    /// Whether to dump registers to console on panic.
    pub dump_registers: bool,
    /// Whether to capture stack memory.
    pub capture_stack: bool,
}

impl PanicHandler {
    /// Create a new panic handler with default settings.
    pub const fn new() -> Self {
        Self {
            dumps: [CrashDump::empty(); MAX_CRASH_DUMPS],
            dump_count: 0,
            notifiers: [PanicNotifier::empty(); MAX_NOTIFIERS],
            notifier_count: 0,
            next_notifier_id: 1,
            action: PanicAction::Halt,
            in_panic: false,
            reboot_timeout: 0,
            dump_registers: true,
            capture_stack: true,
        }
    }

    /// Set the action to take after a panic.
    pub fn set_action(&mut self, action: PanicAction) {
        self.action = action;
    }

    /// Return the currently configured panic action.
    pub fn action(&self) -> PanicAction {
        self.action
    }

    /// Handle a kernel panic.
    ///
    /// This is the main entry point called when a panic occurs.
    /// It captures the crash dump, invokes notifiers, and returns
    /// the action to take.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a panic is already being
    /// processed (recursive panic).
    pub fn on_panic(
        &mut self,
        info: PanicInfo,
        regs: &RegisterState,
        message: &str,
        file: &str,
        line: u32,
    ) -> Result<PanicAction> {
        // Recursion guard.
        if self.in_panic {
            return Err(Error::Busy);
        }
        self.in_panic = true;

        // Create crash dump.
        let mut dump = CrashDump::empty();
        dump.registers = *regs;
        dump.info = info;
        dump.line = line;
        dump.valid = true;
        dump.set_message(message);
        dump.set_file(file);

        // Store in ring buffer.
        let idx = self.dump_count % MAX_CRASH_DUMPS;
        self.dumps[idx] = dump;
        self.dump_count = self.dump_count.wrapping_add(1);

        // Invoke notifiers (sorted by priority would be ideal,
        // but we invoke in registration order for simplicity).
        let _ = self.invoke_notifiers();

        let action = self.action;
        self.in_panic = false;
        Ok(action)
    }

    /// Write a crash dump record directly.
    ///
    /// Used when the caller has already assembled a full
    /// [`CrashDump`].
    pub fn write_crashdump(&mut self, dump: CrashDump) {
        let idx = self.dump_count % MAX_CRASH_DUMPS;
        self.dumps[idx] = dump;
        self.dump_count = self.dump_count.wrapping_add(1);
    }

    /// Retrieve the most recent crash dump, if any.
    pub fn last_dump(&self) -> Option<&CrashDump> {
        if self.dump_count == 0 {
            return None;
        }
        let idx = self.dump_count.wrapping_sub(1) % MAX_CRASH_DUMPS;
        let dump = &self.dumps[idx];
        if dump.valid { Some(dump) } else { None }
    }

    /// Return the total number of panics recorded.
    pub fn dump_count(&self) -> usize {
        self.dump_count
    }

    /// Retrieve a crash dump by ring buffer index.
    ///
    /// Index 0 is the oldest available record.
    pub fn dump_at(&self, index: usize) -> Option<&CrashDump> {
        let stored = self.dump_count.min(MAX_CRASH_DUMPS);
        if index >= stored {
            return None;
        }
        let start = if self.dump_count > MAX_CRASH_DUMPS {
            self.dump_count % MAX_CRASH_DUMPS
        } else {
            0
        };
        let physical = (start + index) % MAX_CRASH_DUMPS;
        let dump = &self.dumps[physical];
        if dump.valid { Some(dump) } else { None }
    }

    /// Register a panic notifier callback.
    ///
    /// Returns the notifier ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the notifier table is
    /// full.
    pub fn register_notifier(
        &mut self,
        name: &str,
        priority: i32,
        func_id: u64,
        data: u64,
    ) -> Result<u32> {
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .notifiers
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_notifier_id;
        self.next_notifier_id = self.next_notifier_id.wrapping_add(1);

        let mut name_buf = [0u8; MAX_NOTIFIER_NAME_LEN];
        let copy_len = name.len().min(MAX_NOTIFIER_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        self.notifiers[slot] = PanicNotifier {
            id,
            name: name_buf,
            name_len: copy_len,
            priority,
            func_id,
            data,
            active: true,
        };
        self.notifier_count += 1;
        Ok(id)
    }

    /// Unregister a panic notifier by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no notifier with the given
    /// ID exists.
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

    /// Return the number of active notifiers.
    pub fn notifier_count(&self) -> usize {
        self.notifier_count
    }

    /// Simulate halting the system.
    ///
    /// In a real kernel this would disable interrupts and enter
    /// an infinite `hlt` loop. Here it returns the halt action
    /// for the caller to act upon.
    pub fn halt_system(&self) -> PanicAction {
        PanicAction::Halt
    }

    /// Simulate a system reboot request.
    ///
    /// In a real kernel this would trigger a platform reset.
    /// Here it returns the reboot action for the caller.
    pub fn reboot_system(&self) -> PanicAction {
        PanicAction::Reboot
    }

    /// Check whether the handler is currently processing a
    /// panic.
    pub fn is_in_panic(&self) -> bool {
        self.in_panic
    }

    // ── internal helpers ─────────────────────────────────────

    /// Invoke all active notifiers in registration order.
    ///
    /// Returns the number of notifiers invoked.
    fn invoke_notifiers(&self) -> usize {
        let mut count = 0usize;
        for notifier in &self.notifiers {
            if notifier.active {
                // In a real kernel we would call the function
                // identified by notifier.func_id with
                // notifier.data as the argument.
                // Here we just count the invocation.
                count += 1;
            }
        }
        count
    }
}

impl Default for PanicHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PanicHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PanicHandler")
            .field("dump_count", &self.dump_count)
            .field("notifier_count", &self.notifier_count)
            .field("action", &self.action)
            .field("in_panic", &self.in_panic)
            .finish()
    }
}

// ── PanicStats ───────────────────────────────────────────────

/// Statistics about kernel panics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicStats {
    /// Total number of panics.
    pub total_panics: u64,
    /// Number of panics that resulted in halt.
    pub halts: u64,
    /// Number of panics that resulted in reboot.
    pub reboots: u64,
    /// Number of recursive panics detected.
    pub recursive_panics: u64,
    /// Number of notifier invocation failures.
    pub notifier_failures: u64,
}

impl PanicStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_panics: 0,
            halts: 0,
            reboots: 0,
            recursive_panics: 0,
            notifier_failures: 0,
        }
    }
}

// ── BufWriter ────────────────────────────────────────────────

/// Minimal buffer writer for `no_std` formatting.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.remaining());
        if len > 0 {
            self.buf[self.pos..self.pos + len].copy_from_slice(&bytes[..len]);
            self.pos += len;
        }
    }

    fn write_hex(&mut self, val: u64) {
        let mut tmp = [0u8; 18];
        tmp[0] = b'0';
        tmp[1] = b'x';
        let mut v = val;
        let mut i: usize = 17;
        loop {
            let nibble = (v & 0xF) as u8;
            tmp[i] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            v >>= 4;
            if i == 2 {
                break;
            }
            i -= 1;
        }
        // SAFETY: tmp contains only ASCII hex characters.
        let s = unsafe { core::str::from_utf8_unchecked(&tmp) };
        self.write_str(s);
    }

    fn write_u32(&mut self, val: u32) {
        if val == 0 {
            self.write_str("0");
            return;
        }
        let mut tmp = [0u8; 10];
        let mut v = val;
        let mut i: usize = 9;
        while v > 0 {
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let start = if val > 0 && i == 0 { 0 } else { i + 1 };
        // SAFETY: tmp contains only ASCII digit characters.
        let s = unsafe { core::str::from_utf8_unchecked(&tmp[start..]) };
        self.write_str(s);
    }

    fn write_u64(&mut self, val: u64) {
        if val == 0 {
            self.write_str("0");
            return;
        }
        let mut tmp = [0u8; 20];
        let mut v = val;
        let mut i: usize = 19;
        while v > 0 {
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let start = if val > 0 && i == 0 { 0 } else { i + 1 };
        // SAFETY: tmp contains only ASCII digit characters.
        let s = unsafe { core::str::from_utf8_unchecked(&tmp[start..]) };
        self.write_str(s);
    }
}
