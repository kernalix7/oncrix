// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel panic diagnostics: stack unwinding, register dumps, and
//! crash logging.
//!
//! Provides infrastructure for capturing full CPU state at the time
//! of a kernel panic or exception, walking the call stack via frame
//! pointers, and storing crash records in a ring buffer for
//! post-mortem analysis.

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of frames in a stack trace.
const MAX_STACK_FRAMES: usize = 32;

/// Maximum length of the panic message stored in a record.
const MAX_MESSAGE_LEN: usize = 256;

/// Maximum length of the file path stored in a record.
const MAX_FILE_LEN: usize = 128;

/// Number of entries in the crash log ring buffer.
const CRASH_LOG_SIZE: usize = 8;

/// Start of the kernel virtual address space.
const KERNEL_ADDR_START: u64 = 0xFFFF_8000_0000_0000;

/// All x86_64 registers captured at crash time.
///
/// Includes general-purpose registers, instruction pointer,
/// flags, segment selectors, and control registers needed
/// for full crash diagnostics.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CrashRegisters {
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
    /// Instruction pointer at crash time.
    pub rip: u64,
    /// CPU flags register at crash time.
    pub rflags: u64,
    /// Code segment selector.
    pub cs: u16,
    /// Stack segment selector.
    pub ss: u16,
    /// Data segment selector.
    pub ds: u16,
    /// Extra segment selector.
    pub es: u16,
    /// FS segment selector.
    pub fs: u16,
    /// GS segment selector.
    pub gs: u16,
    /// Control register 0 (protected mode, paging flags).
    pub cr0: u64,
    /// Control register 2 (page-fault linear address).
    pub cr2: u64,
    /// Control register 3 (page-table base address).
    pub cr3: u64,
    /// Control register 4 (extension flags).
    pub cr4: u64,
}

impl CrashRegisters {
    /// Create a zeroed `CrashRegisters` instance.
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
            cs: 0,
            ss: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            cr0: 0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
        }
    }
}

/// A single frame in a stack trace.
///
/// Represents one level of the call stack, identified by the
/// return address and the frame pointer at that level.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct StackFrame {
    /// Return address — the instruction following the `call`.
    pub return_addr: u64,
    /// Frame pointer value at this stack level.
    pub frame_ptr: u64,
}

impl StackFrame {
    /// Create a zeroed stack frame.
    const fn zero() -> Self {
        Self {
            return_addr: 0,
            frame_ptr: 0,
        }
    }
}

/// A captured stack trace of up to 32 frames.
///
/// Built by walking the frame-pointer chain starting from a
/// given RBP value. Each frame is validated to be in the
/// kernel address range before being recorded.
#[derive(Debug, Clone, Copy)]
pub struct StackTrace {
    /// Recorded stack frames.
    frames: [StackFrame; MAX_STACK_FRAMES],
    /// Number of valid frames in `frames`.
    depth: usize,
}

impl StackTrace {
    /// Create an empty stack trace.
    pub const fn empty() -> Self {
        Self {
            frames: [StackFrame::zero(); MAX_STACK_FRAMES],
            depth: 0,
        }
    }

    /// Walk the frame-pointer chain starting at `rbp` and
    /// capture up to 32 frames.
    ///
    /// Each frame pointer is validated to lie within the kernel
    /// address range (`0xFFFF_8000_0000_0000..=
    /// 0xFFFF_FFFF_FFFF_FFFF`). The walk stops when a null or
    /// invalid frame pointer is encountered, or when the
    /// maximum depth is reached.
    ///
    /// # Safety
    ///
    /// This function reads memory through raw pointers derived
    /// from `rbp`. The caller must ensure that `rbp` points to
    /// a valid, mapped frame-pointer chain. Typically this is
    /// only called during a panic or exception handler where
    /// the kernel stack is still intact.
    pub unsafe fn capture(rbp: u64) -> Self {
        let mut trace = Self::empty();
        let mut fp = rbp;

        while trace.depth < MAX_STACK_FRAMES {
            if !is_kernel_address(fp) {
                break;
            }

            // Frame pointer must be 8-byte aligned.
            if fp & 0x7 != 0 {
                break;
            }

            // On x86_64 with frame pointers:
            //   [rbp]     = previous rbp (caller's frame pointer)
            //   [rbp + 8] = return address
            let prev_fp = unsafe { core::ptr::read_volatile(fp as *const u64) };
            let ret_addr = unsafe { core::ptr::read_volatile((fp as *const u64).add(1)) };

            if ret_addr == 0 {
                break;
            }

            trace.frames[trace.depth] = StackFrame {
                return_addr: ret_addr,
                frame_ptr: fp,
            };
            trace.depth = trace.depth.saturating_add(1);

            // Move to the previous frame.
            if prev_fp == 0 || prev_fp == fp {
                break;
            }
            fp = prev_fp;
        }

        trace
    }

    /// Get the frame at the given index, if it exists.
    pub fn get(&self, index: usize) -> Option<&StackFrame> {
        if index < self.depth {
            Some(&self.frames[index])
        } else {
            None
        }
    }

    /// Return the number of captured frames.
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// Record of a single kernel panic or oops event.
///
/// Contains all information needed for post-mortem analysis:
/// CPU registers, stack trace, panic message, source location,
/// CPU identity, and a monotonic tick count.
#[derive(Debug, Clone, Copy)]
pub struct PanicRecord {
    /// CPU registers at the time of the panic.
    pub registers: CrashRegisters,
    /// Stack trace captured from the panic site.
    pub stack_trace: StackTrace,
    /// Panic message bytes (UTF-8, not null-terminated).
    pub message: [u8; MAX_MESSAGE_LEN],
    /// Length of valid bytes in `message`.
    pub message_len: usize,
    /// Source file path bytes (UTF-8, not null-terminated).
    pub panic_file: [u8; MAX_FILE_LEN],
    /// Length of valid bytes in `panic_file`.
    pub file_len: usize,
    /// Source line number where the panic originated.
    pub panic_line: u32,
    /// Logical CPU ID that experienced the panic.
    pub cpu_id: u32,
    /// Monotonic tick count at the time of the panic.
    pub tick_count: u64,
}

impl PanicRecord {
    /// Create a zeroed panic record.
    pub const fn empty() -> Self {
        Self {
            registers: CrashRegisters::zero(),
            stack_trace: StackTrace::empty(),
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
            panic_file: [0u8; MAX_FILE_LEN],
            file_len: 0,
            panic_line: 0,
            cpu_id: 0,
            tick_count: 0,
        }
    }

    /// Return the panic message as a string slice.
    pub fn message_str(&self) -> &str {
        let len = if self.message_len > MAX_MESSAGE_LEN {
            MAX_MESSAGE_LEN
        } else {
            self.message_len
        };
        core::str::from_utf8(&self.message[..len]).unwrap_or("<invalid utf-8>")
    }

    /// Return the panic file path as a string slice.
    pub fn file_str(&self) -> &str {
        let len = if self.file_len > MAX_FILE_LEN {
            MAX_FILE_LEN
        } else {
            self.file_len
        };
        core::str::from_utf8(&self.panic_file[..len]).unwrap_or("<invalid utf-8>")
    }
}

/// Ring buffer holding the last 8 crash records.
///
/// Used to persist panic information across soft reboots or
/// for inspection by a debugger. Thread-safe via an atomic
/// write index.
pub struct CrashLog {
    /// Ring buffer of panic records.
    entries: [PanicRecord; CRASH_LOG_SIZE],
    /// Total number of records ever written (not capped).
    total: AtomicUsize,
}

impl Default for CrashLog {
    fn default() -> Self {
        Self::new()
    }
}

impl CrashLog {
    /// Create an empty crash log.
    pub const fn new() -> Self {
        Self {
            entries: [PanicRecord::empty(); CRASH_LOG_SIZE],
            total: AtomicUsize::new(0),
        }
    }

    /// Record a panic in the ring buffer.
    ///
    /// If the buffer is full, the oldest entry is overwritten.
    pub fn log(&mut self, record: PanicRecord) {
        let idx = self.total.load(Ordering::Relaxed) % CRASH_LOG_SIZE;
        self.entries[idx] = record;
        // Use wrapping add to avoid overflow on the counter.
        let prev = self.total.load(Ordering::Relaxed);
        self.total.store(prev.wrapping_add(1), Ordering::Release);
    }

    /// Return the most recently logged panic record, if any.
    pub fn last(&self) -> Option<&PanicRecord> {
        let total = self.total.load(Ordering::Acquire);
        if total == 0 {
            return None;
        }
        let idx = total.wrapping_sub(1) % CRASH_LOG_SIZE;
        Some(&self.entries[idx])
    }

    /// Return the number of records stored (capped at
    /// `CRASH_LOG_SIZE`).
    pub fn count(&self) -> usize {
        let total = self.total.load(Ordering::Acquire);
        if total > CRASH_LOG_SIZE {
            CRASH_LOG_SIZE
        } else {
            total
        }
    }

    /// Return an iterator over stored panic records, oldest
    /// first.
    pub fn iter(&self) -> CrashLogIter<'_> {
        let total = self.total.load(Ordering::Acquire);
        let count = if total > CRASH_LOG_SIZE {
            CRASH_LOG_SIZE
        } else {
            total
        };
        let start = if total > CRASH_LOG_SIZE {
            total % CRASH_LOG_SIZE
        } else {
            0
        };
        CrashLogIter {
            log: self,
            start,
            count,
            pos: 0,
        }
    }
}

/// Iterator over crash log entries, oldest first.
pub struct CrashLogIter<'a> {
    log: &'a CrashLog,
    start: usize,
    count: usize,
    pos: usize,
}

impl<'a> Iterator for CrashLogIter<'a> {
    type Item = &'a PanicRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = (self.start.wrapping_add(self.pos)) % CRASH_LOG_SIZE;
        self.pos = self.pos.saturating_add(1);
        Some(&self.log.entries[idx])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

/// Classification of kernel exceptions (oops events).
///
/// Each variant captures exception-specific context needed
/// for diagnostics.
#[derive(Debug, Clone, Copy)]
pub enum KernelOops {
    /// Page fault with the faulting address and error code.
    PageFault {
        /// The linear address that caused the fault.
        addr: u64,
        /// CPU-provided page-fault error code.
        error_code: u64,
    },
    /// General protection fault with its error code.
    GeneralProtection {
        /// CPU-provided GP error code.
        error_code: u64,
    },
    /// Double fault — unrecoverable.
    DoubleFault,
    /// Invalid opcode at the given instruction pointer.
    InvalidOpcode {
        /// RIP where the invalid opcode was encountered.
        rip: u64,
    },
    /// Integer divide-by-zero or division overflow.
    DivideError,
    /// Stack segment fault or stack overflow detected.
    StackOverflow,
    /// Any other exception identified by its vector number.
    Other {
        /// Interrupt vector number.
        vector: u8,
    },
}

impl fmt::Display for KernelOops {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PageFault { addr, error_code } => {
                write!(f, "page fault at {:#018x} (err {:#x})", addr, error_code,)
            }
            Self::GeneralProtection { error_code } => {
                write!(f, "general protection fault (err {:#x})", error_code,)
            }
            Self::DoubleFault => {
                write!(f, "double fault")
            }
            Self::InvalidOpcode { rip } => {
                write!(f, "invalid opcode at {:#018x}", rip,)
            }
            Self::DivideError => {
                write!(f, "divide error")
            }
            Self::StackOverflow => {
                write!(f, "stack overflow")
            }
            Self::Other { vector } => {
                write!(f, "exception vector {}", vector)
            }
        }
    }
}

/// Create a [`PanicRecord`] from a kernel exception.
///
/// Formats the oops description into the record's message
/// buffer and captures a stack trace from the register state.
///
/// # Safety
///
/// Internally calls [`StackTrace::capture`] which reads memory
/// through the frame-pointer chain in `regs.rbp`. The caller
/// must ensure the kernel stack is still valid and mapped.
pub unsafe fn handle_kernel_oops(oops: KernelOops, regs: &CrashRegisters) -> PanicRecord {
    let mut record = PanicRecord::empty();
    record.registers = *regs;

    // Capture stack trace from the crash-time RBP.
    record.stack_trace = unsafe { StackTrace::capture(regs.rbp) };

    // Format the oops description into the message buffer.
    let msg_len = format_oops_message(&oops, &mut record.message);
    record.message_len = msg_len;

    record
}

/// Format a human-readable representation of a panic record
/// into the provided buffer.
///
/// Returns the number of bytes written. The output is UTF-8
/// and suitable for serial console output.
pub fn format_panic_record(record: &PanicRecord, buf: &mut [u8]) -> usize {
    let mut writer = BufWriter::new(buf);

    writer.write_str("===== ONCRIX KERNEL PANIC =====\n");

    // Message
    writer.write_str("Panic: ");
    writer.write_str(record.message_str());
    writer.write_str("\n");

    // Location
    if record.file_len > 0 {
        writer.write_str("  at ");
        writer.write_str(record.file_str());
        writer.write_str(":");
        writer.write_u32(record.panic_line);
        writer.write_str("\n");
    }

    // CPU and tick
    writer.write_str("CPU: ");
    writer.write_u32(record.cpu_id);
    writer.write_str("  Tick: ");
    writer.write_u64(record.tick_count);
    writer.write_str("\n\n");

    // Registers
    writer.write_str("Registers:\n");
    write_reg_line(
        &mut writer,
        "  RAX=",
        record.registers.rax,
        " RBX=",
        record.registers.rbx,
    );
    write_reg_line(
        &mut writer,
        "  RCX=",
        record.registers.rcx,
        " RDX=",
        record.registers.rdx,
    );
    write_reg_line(
        &mut writer,
        "  RSI=",
        record.registers.rsi,
        " RDI=",
        record.registers.rdi,
    );
    write_reg_line(
        &mut writer,
        "  RBP=",
        record.registers.rbp,
        " RSP=",
        record.registers.rsp,
    );
    write_reg_line(
        &mut writer,
        "   R8=",
        record.registers.r8,
        "  R9=",
        record.registers.r9,
    );
    write_reg_line(
        &mut writer,
        "  R10=",
        record.registers.r10,
        " R11=",
        record.registers.r11,
    );
    write_reg_line(
        &mut writer,
        "  R12=",
        record.registers.r12,
        " R13=",
        record.registers.r13,
    );
    write_reg_line(
        &mut writer,
        "  R14=",
        record.registers.r14,
        " R15=",
        record.registers.r15,
    );
    writer.write_str("  RIP=");
    writer.write_hex_u64(record.registers.rip);
    writer.write_str(" RFLAGS=");
    writer.write_hex_u64(record.registers.rflags);
    writer.write_str("\n");

    writer.write_str("  CR0=");
    writer.write_hex_u64(record.registers.cr0);
    writer.write_str(" CR2=");
    writer.write_hex_u64(record.registers.cr2);
    writer.write_str("\n");
    writer.write_str("  CR3=");
    writer.write_hex_u64(record.registers.cr3);
    writer.write_str(" CR4=");
    writer.write_hex_u64(record.registers.cr4);
    writer.write_str("\n");

    writer.write_str("  CS=");
    writer.write_hex_u16(record.registers.cs);
    writer.write_str(" SS=");
    writer.write_hex_u16(record.registers.ss);
    writer.write_str(" DS=");
    writer.write_hex_u16(record.registers.ds);
    writer.write_str(" ES=");
    writer.write_hex_u16(record.registers.es);
    writer.write_str(" FS=");
    writer.write_hex_u16(record.registers.fs);
    writer.write_str(" GS=");
    writer.write_hex_u16(record.registers.gs);
    writer.write_str("\n\n");

    // Stack trace
    writer.write_str("Stack trace:\n");
    let depth = record.stack_trace.depth();
    if depth == 0 {
        writer.write_str("  <no frames captured>\n");
    } else {
        let mut i = 0;
        while i < depth {
            if let Some(frame) = record.stack_trace.get(i) {
                writer.write_str("  #");
                writer.write_usize(i);
                writer.write_str(" ");
                writer.write_hex_u64(frame.return_addr);
                writer.write_str(" (fp=");
                writer.write_hex_u64(frame.frame_ptr);
                writer.write_str(")\n");
            }
            i = i.saturating_add(1);
        }
    }

    writer.write_str("===============================\n");

    writer.pos
}

// ── Internal helpers ────────────────────────────────────────

/// Check whether an address is in the kernel address range.
fn is_kernel_address(addr: u64) -> bool {
    addr >= KERNEL_ADDR_START
}

/// Format a `KernelOops` description into a byte buffer.
/// Returns the number of bytes written.
fn format_oops_message(oops: &KernelOops, buf: &mut [u8; MAX_MESSAGE_LEN]) -> usize {
    let mut writer = BufWriter::new(buf);
    match oops {
        KernelOops::PageFault { addr, error_code } => {
            writer.write_str("page fault at ");
            writer.write_hex_u64(*addr);
            writer.write_str(" (err ");
            writer.write_hex_u64(*error_code);
            writer.write_str(")");
        }
        KernelOops::GeneralProtection { error_code } => {
            writer.write_str("general protection (err ");
            writer.write_hex_u64(*error_code);
            writer.write_str(")");
        }
        KernelOops::DoubleFault => {
            writer.write_str("double fault");
        }
        KernelOops::InvalidOpcode { rip } => {
            writer.write_str("invalid opcode at ");
            writer.write_hex_u64(*rip);
        }
        KernelOops::DivideError => {
            writer.write_str("divide error");
        }
        KernelOops::StackOverflow => {
            writer.write_str("stack overflow");
        }
        KernelOops::Other { vector } => {
            writer.write_str("exception vector ");
            writer.write_u32(u32::from(*vector));
        }
    }
    writer.pos
}

/// Write a pair of labelled hex registers on one line.
fn write_reg_line(w: &mut BufWriter<'_>, label_a: &str, val_a: u64, label_b: &str, val_b: u64) {
    w.write_str(label_a);
    w.write_hex_u64(val_a);
    w.write_str(label_b);
    w.write_hex_u64(val_b);
    w.write_str("\n");
}

/// Minimal buffer writer for `no_std` formatting without
/// allocations.
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
        let len = if bytes.len() > self.remaining() {
            self.remaining()
        } else {
            bytes.len()
        };
        if len > 0 {
            self.buf[self.pos..self.pos.wrapping_add(len)].copy_from_slice(&bytes[..len]);
            self.pos = self.pos.saturating_add(len);
        }
    }

    fn write_hex_u64(&mut self, val: u64) {
        // "0x" + up to 16 hex digits = 18 bytes max
        let mut tmp = [0u8; 18];
        tmp[0] = b'0';
        tmp[1] = b'x';
        let mut v = val;
        // Always write 16 hex digits (zero-padded).
        let mut i: usize = 17;
        loop {
            let nibble = (v & 0xF) as u8;
            tmp[i] = if nibble < 10 {
                b'0'.wrapping_add(nibble)
            } else {
                b'a'.wrapping_add(nibble.wrapping_sub(10))
            };
            v >>= 4;
            if i == 2 {
                break;
            }
            i = i.saturating_sub(1);
        }
        self.write_str(
            // SAFETY: tmp contains only ASCII hex characters.
            unsafe { core::str::from_utf8_unchecked(&tmp) },
        );
    }

    fn write_hex_u16(&mut self, val: u16) {
        // "0x" + 4 hex digits = 6 bytes
        let mut tmp = [0u8; 6];
        tmp[0] = b'0';
        tmp[1] = b'x';
        let mut v = val;
        let mut i: usize = 5;
        loop {
            let nibble = (v & 0xF) as u8;
            tmp[i] = if nibble < 10 {
                b'0'.wrapping_add(nibble)
            } else {
                b'a'.wrapping_add(nibble.wrapping_sub(10))
            };
            v >>= 4;
            if i == 2 {
                break;
            }
            i = i.saturating_sub(1);
        }
        self.write_str(unsafe { core::str::from_utf8_unchecked(&tmp) });
    }

    fn write_u32(&mut self, val: u32) {
        if val == 0 {
            self.write_str("0");
            return;
        }
        let mut tmp = [0u8; 10]; // max u32 is 10 digits
        let mut v = val;
        let mut i: usize = 9;
        while v > 0 {
            tmp[i] = b'0'.wrapping_add((v % 10) as u8);
            v /= 10;
            if i == 0 {
                break;
            }
            i = i.saturating_sub(1);
        }
        let start = i.saturating_add(if val > 0 { 1 } else { 0 });
        // Edge case: when the loop ends with i > 0, start is
        // i+1. When i == 0, last digit was written at 0, so
        // start should be 0.
        let actual_start = if val > 0 && i == 0 { 0 } else { start };
        self.write_str(unsafe { core::str::from_utf8_unchecked(&tmp[actual_start..]) });
    }

    fn write_u64(&mut self, val: u64) {
        if val == 0 {
            self.write_str("0");
            return;
        }
        let mut tmp = [0u8; 20]; // max u64 is 20 digits
        let mut v = val;
        let mut i: usize = 19;
        while v > 0 {
            tmp[i] = b'0'.wrapping_add((v % 10) as u8);
            v /= 10;
            if i == 0 {
                break;
            }
            i = i.saturating_sub(1);
        }
        let start = if val > 0 && i == 0 {
            0
        } else {
            i.saturating_add(1)
        };
        self.write_str(unsafe { core::str::from_utf8_unchecked(&tmp[start..]) });
    }

    fn write_usize(&mut self, val: usize) {
        // On x86_64, usize == u64.
        self.write_u64(val as u64);
    }
}
