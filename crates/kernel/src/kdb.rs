// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel debugger/monitor (KDB).
//!
//! Provides an interactive debugger that can be entered on demand
//! (e.g., via a magic SysRq key or programmatic breakpoint). The
//! debugger supports register inspection, memory dumps, breakpoint
//! management, and single-stepping.
//!
//! # Architecture
//!
//! ```text
//!  serial/console input
//!        │
//!        ▼
//!  CommandParser::parse() ──► KdbCommand
//!        │
//!        ▼
//!  Kdb::process_command() ──► KdbOutputBuffer
//!        │
//!        ▼
//!  serial/console output
//! ```
//!
//! Reference: Linux `kernel/debug/kdb/`,
//! `include/linux/kdb.h`.

use oncrix_lib::Error;

/// Maximum number of hardware/software breakpoints.
const MAX_BREAKPOINTS: usize = 16;

/// Output buffer size (4 KiB).
const OUTPUT_BUFFER_SIZE: usize = 4096;

/// Number of bytes displayed per hex dump line.
const HEX_LINE_WIDTH: usize = 16;

/// Maximum length of a single input command.
const MAX_CMD_LEN: usize = 256;

// -----------------------------------------------------------------------
// KdbCommand
// -----------------------------------------------------------------------

/// Commands recognized by the kernel debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbCommand {
    /// Display help text listing available commands.
    Help,
    /// Print a stack backtrace from the current frame pointer.
    Backtrace,
    /// Display all CPU registers.
    Registers,
    /// Dump memory starting at `addr` for `len` bytes.
    Memory {
        /// Starting virtual address.
        addr: u64,
        /// Number of bytes to dump.
        len: usize,
    },
    /// Set or display a breakpoint at the given address.
    Breakpoint {
        /// Virtual address for the breakpoint.
        addr: u64,
    },
    /// Resume execution after a debugger stop.
    Continue,
    /// Execute a single instruction and re-enter the debugger.
    Step,
    /// List all processes.
    ProcessList,
    /// List all threads.
    ThreadList,
    /// Exit the debugger entirely.
    Quit,
}

// -----------------------------------------------------------------------
// KdbState
// -----------------------------------------------------------------------

/// Whether the kernel debugger is active or inactive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbActivity {
    /// The debugger is not active; normal execution proceeds.
    Inactive,
    /// The debugger is active and processing commands.
    Active,
}

/// Runtime state of the kernel debugger.
///
/// Tracks whether the debugger is active, the saved register set
/// from the point of entry, and single-step mode.
#[derive(Debug, Clone, Copy)]
pub struct KdbState {
    /// Current activity state.
    pub activity: KdbActivity,
    /// Saved CPU registers at debugger entry.
    pub saved_regs: KdbRegisters,
    /// Whether single-step mode is enabled.
    pub single_step: bool,
}

impl Default for KdbState {
    fn default() -> Self {
        Self::new()
    }
}

impl KdbState {
    /// Create a new inactive debugger state.
    pub const fn new() -> Self {
        Self {
            activity: KdbActivity::Inactive,
            saved_regs: KdbRegisters::zero(),
            single_step: false,
        }
    }

    /// Check whether the debugger is currently active.
    pub fn is_active(&self) -> bool {
        self.activity == KdbActivity::Active
    }
}

// -----------------------------------------------------------------------
// KdbRegisters
// -----------------------------------------------------------------------

/// Saved x86_64 register set for the kernel debugger.
///
/// Captures all general-purpose registers plus segment selectors
/// at the point the debugger was entered.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KdbRegisters {
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
    /// Instruction pointer.
    pub rip: u64,
    /// CPU flags register.
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
}

impl KdbRegisters {
    /// Create a zeroed register set.
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
        }
    }
}

impl Default for KdbRegisters {
    fn default() -> Self {
        Self::zero()
    }
}

// -----------------------------------------------------------------------
// CommandParser
// -----------------------------------------------------------------------

/// Parses text input into [`KdbCommand`] values.
///
/// Supports short mnemonics common in kernel debuggers:
/// - `help`, `h`, `?` — Help
/// - `bt`, `backtrace` — Backtrace
/// - `regs`, `registers` — Registers
/// - `x <addr> [len]`, `mem <addr> [len]` — Memory dump
/// - `bp <addr>`, `breakpoint <addr>` — Set breakpoint
/// - `c`, `continue`, `go` — Continue
/// - `s`, `step`, `si` — Single step
/// - `ps`, `proclist` — Process list
/// - `threads`, `threadlist` — Thread list
/// - `q`, `quit`, `exit` — Quit
pub struct CommandParser {
    /// Internal buffer for the current command line.
    buf: [u8; MAX_CMD_LEN],
    /// Number of valid bytes in `buf`.
    len: usize,
}

impl Default for CommandParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandParser {
    /// Create a new, empty command parser.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_CMD_LEN],
            len: 0,
        }
    }

    /// Parse a command string into a [`KdbCommand`].
    ///
    /// Returns `Err(Error::InvalidArgument)` if the input is
    /// empty or not recognized.
    pub fn parse(&mut self, input: &[u8]) -> Result<KdbCommand, Error> {
        let trimmed = trim_ascii(input);
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Copy into internal buffer for splitting.
        let copy_len = trimmed.len().min(MAX_CMD_LEN);
        self.buf[..copy_len].copy_from_slice(&trimmed[..copy_len]);
        self.len = copy_len;

        let (cmd, rest) = split_first_token(&self.buf[..self.len]);

        match cmd {
            b"help" | b"h" | b"?" => Ok(KdbCommand::Help),
            b"bt" | b"backtrace" => Ok(KdbCommand::Backtrace),
            b"regs" | b"registers" => Ok(KdbCommand::Registers),
            b"x" | b"mem" => self.parse_memory(rest),
            b"bp" | b"breakpoint" => self.parse_breakpoint(rest),
            b"c" | b"continue" | b"go" => Ok(KdbCommand::Continue),
            b"s" | b"step" | b"si" => Ok(KdbCommand::Step),
            b"ps" | b"proclist" => Ok(KdbCommand::ProcessList),
            b"threads" | b"threadlist" => Ok(KdbCommand::ThreadList),
            b"q" | b"quit" | b"exit" => Ok(KdbCommand::Quit),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Parse the arguments for a memory dump command.
    fn parse_memory(&self, args: &[u8]) -> Result<KdbCommand, Error> {
        let args = trim_ascii(args);
        if args.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let (addr_tok, rest) = split_first_token(args);
        let addr = parse_hex_u64(addr_tok).ok_or(Error::InvalidArgument)?;
        let rest = trim_ascii(rest);
        let len = if rest.is_empty() {
            // Default to 64 bytes when no length given.
            64
        } else {
            let (len_tok, _) = split_first_token(rest);
            parse_usize_decimal(len_tok).ok_or(Error::InvalidArgument)?
        };
        Ok(KdbCommand::Memory { addr, len })
    }

    /// Parse the arguments for a breakpoint command.
    fn parse_breakpoint(&self, args: &[u8]) -> Result<KdbCommand, Error> {
        let args = trim_ascii(args);
        if args.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let (addr_tok, _) = split_first_token(args);
        let addr = parse_hex_u64(addr_tok).ok_or(Error::InvalidArgument)?;
        Ok(KdbCommand::Breakpoint { addr })
    }
}

// -----------------------------------------------------------------------
// KdbBreakpoint
// -----------------------------------------------------------------------

/// A single software breakpoint.
///
/// On x86_64, breakpoints are implemented by replacing the first
/// byte of an instruction with `INT3` (`0xCC`). The original byte
/// is saved so it can be restored when the breakpoint is removed.
#[derive(Debug, Clone, Copy)]
pub struct KdbBreakpoint {
    /// Virtual address of the breakpoint.
    pub addr: u64,
    /// Whether this breakpoint is currently active.
    pub enabled: bool,
    /// The original byte at `addr` before `INT3` was written.
    pub original_byte: u8,
}

impl KdbBreakpoint {
    /// Create a new breakpoint at the given address.
    pub const fn new(addr: u64, original_byte: u8) -> Self {
        Self {
            addr,
            enabled: true,
            original_byte,
        }
    }
}

// -----------------------------------------------------------------------
// BreakpointTable
// -----------------------------------------------------------------------

/// Table of up to [`MAX_BREAKPOINTS`] software breakpoints.
pub struct BreakpointTable {
    /// Breakpoint slots (`None` = unused).
    slots: [Option<KdbBreakpoint>; MAX_BREAKPOINTS],
}

impl Default for BreakpointTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakpointTable {
    /// Create an empty breakpoint table.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_BREAKPOINTS],
        }
    }

    /// Add a breakpoint. Returns the slot index on success, or
    /// `Err(Error::OutOfMemory)` if the table is full.
    pub fn add(&mut self, bp: KdbBreakpoint) -> Result<usize, Error> {
        // Check for duplicate address first.
        let mut i = 0;
        while i < MAX_BREAKPOINTS {
            if let Some(ref existing) = self.slots[i] {
                if existing.addr == bp.addr {
                    return Err(Error::AlreadyExists);
                }
            }
            i = i.saturating_add(1);
        }

        // Find a free slot.
        let mut j = 0;
        while j < MAX_BREAKPOINTS {
            if self.slots[j].is_none() {
                self.slots[j] = Some(bp);
                return Ok(j);
            }
            j = j.saturating_add(1);
        }

        Err(Error::OutOfMemory)
    }

    /// Remove the breakpoint at the given address.
    ///
    /// Returns the removed breakpoint, or `Err(Error::NotFound)`
    /// if no breakpoint exists at that address.
    pub fn remove(&mut self, addr: u64) -> Result<KdbBreakpoint, Error> {
        let mut i = 0;
        while i < MAX_BREAKPOINTS {
            if let Some(ref bp) = self.slots[i] {
                if bp.addr == addr {
                    let removed = *bp;
                    self.slots[i] = None;
                    return Ok(removed);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Find a breakpoint by address.
    pub fn find(&self, addr: u64) -> Option<&KdbBreakpoint> {
        let mut i = 0;
        while i < MAX_BREAKPOINTS {
            if let Some(ref bp) = self.slots[i] {
                if bp.addr == addr {
                    return Some(bp);
                }
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Return the number of active breakpoints.
    pub fn count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0;
        while i < MAX_BREAKPOINTS {
            if self.slots[i].is_some() {
                n = n.saturating_add(1);
            }
            i = i.saturating_add(1);
        }
        n
    }

    /// Get a reference to the breakpoint in slot `index`.
    pub fn get(&self, index: usize) -> Option<&KdbBreakpoint> {
        if index < MAX_BREAKPOINTS {
            self.slots[index].as_ref()
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------
// KdbOutputBuffer
// -----------------------------------------------------------------------

/// Fixed 4 KiB buffer for debugger output formatting.
///
/// All debugger output is written here before being flushed to
/// the console/serial port. This avoids heap allocation in the
/// debugger path.
pub struct KdbOutputBuffer {
    /// Raw byte storage.
    data: [u8; OUTPUT_BUFFER_SIZE],
    /// Number of valid bytes written.
    pos: usize,
}

impl Default for KdbOutputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl KdbOutputBuffer {
    /// Create an empty output buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; OUTPUT_BUFFER_SIZE],
            pos: 0,
        }
    }

    /// Reset the buffer, discarding all content.
    pub fn clear(&mut self) {
        self.pos = 0;
    }

    /// Return the valid content as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.pos]
    }

    /// Return the valid content as a string slice, if valid
    /// UTF-8.
    pub fn as_str(&self) -> &str {
        // SAFETY: We only write ASCII via write_str / write_hex,
        // so this is always valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.data[..self.pos]) }
    }

    /// Number of bytes currently in the buffer.
    pub fn len(&self) -> usize {
        self.pos
    }

    /// Check whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Remaining capacity in bytes.
    fn remaining(&self) -> usize {
        OUTPUT_BUFFER_SIZE.saturating_sub(self.pos)
    }

    /// Append a string slice to the buffer.
    fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.remaining());
        if len > 0 {
            self.data[self.pos..self.pos.wrapping_add(len)].copy_from_slice(&bytes[..len]);
            self.pos = self.pos.saturating_add(len);
        }
    }

    /// Append a single byte to the buffer.
    fn write_byte(&mut self, b: u8) {
        if self.pos < OUTPUT_BUFFER_SIZE {
            self.data[self.pos] = b;
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// Write a zero-padded 16-digit hex value with `0x` prefix.
    fn write_hex_u64(&mut self, val: u64) {
        let mut tmp = [0u8; 18];
        tmp[0] = b'0';
        tmp[1] = b'x';
        let mut v = val;
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
            // SAFETY: tmp is pure ASCII hex.
            unsafe { core::str::from_utf8_unchecked(&tmp) },
        );
    }

    /// Write a zero-padded 4-digit hex value with `0x` prefix.
    fn write_hex_u16(&mut self, val: u16) {
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
        self.write_str(
            // SAFETY: tmp is pure ASCII hex.
            unsafe { core::str::from_utf8_unchecked(&tmp) },
        );
    }

    /// Write a two-digit zero-padded hex byte (no prefix).
    fn write_hex_byte(&mut self, val: u8) {
        let hi = val >> 4;
        let lo = val & 0x0F;
        let c_hi = if hi < 10 {
            b'0'.wrapping_add(hi)
        } else {
            b'a'.wrapping_add(hi.wrapping_sub(10))
        };
        let c_lo = if lo < 10 {
            b'0'.wrapping_add(lo)
        } else {
            b'a'.wrapping_add(lo.wrapping_sub(10))
        };
        self.write_byte(c_hi);
        self.write_byte(c_lo);
    }

    /// Write a decimal usize value.
    fn write_usize(&mut self, val: usize) {
        if val == 0 {
            self.write_str("0");
            return;
        }
        let mut tmp = [0u8; 20];
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
        self.write_str(
            // SAFETY: tmp is pure ASCII digits.
            unsafe { core::str::from_utf8_unchecked(&tmp[start..]) },
        );
    }
}

// -----------------------------------------------------------------------
// Kdb — main debugger struct
// -----------------------------------------------------------------------

/// The ONCRIX kernel debugger.
///
/// Provides an interactive command-line monitor for inspecting
/// kernel state, setting breakpoints, single-stepping, and
/// examining memory. All output is formatted into an internal
/// [`KdbOutputBuffer`].
pub struct Kdb {
    /// Current debugger state.
    pub state: KdbState,
    /// Command parser.
    pub parser: CommandParser,
    /// Software breakpoint table.
    pub breakpoints: BreakpointTable,
    /// Output buffer for formatted results.
    pub output: KdbOutputBuffer,
}

impl Default for Kdb {
    fn default() -> Self {
        Self::new()
    }
}

impl Kdb {
    /// Create a new, inactive kernel debugger instance.
    pub const fn new() -> Self {
        Self {
            state: KdbState::new(),
            parser: CommandParser::new(),
            breakpoints: BreakpointTable::new(),
            output: KdbOutputBuffer::new(),
        }
    }

    /// Enter the debugger, saving the current register state.
    ///
    /// Returns `Err(Error::Busy)` if the debugger is already
    /// active.
    pub fn enter(&mut self, regs: &KdbRegisters) -> Result<(), Error> {
        if self.state.is_active() {
            return Err(Error::Busy);
        }
        self.state.activity = KdbActivity::Active;
        self.state.saved_regs = *regs;
        self.state.single_step = false;
        self.output.clear();
        self.output
            .write_str("ONCRIX KDB: Entering kernel debugger.\n");
        self.output.write_str("Type 'help' for commands.\n");
        Ok(())
    }

    /// Exit the debugger and resume normal execution.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the debugger is
    /// not active.
    pub fn exit(&mut self) -> Result<(), Error> {
        if !self.state.is_active() {
            return Err(Error::InvalidArgument);
        }
        self.state.activity = KdbActivity::Inactive;
        self.state.single_step = false;
        Ok(())
    }

    /// Process a raw command line from the user.
    ///
    /// Parses the input and dispatches to the appropriate handler.
    /// Output is written to the internal [`KdbOutputBuffer`] and
    /// can be retrieved via [`Kdb::output`].
    pub fn process_command(&mut self, input: &[u8]) -> Result<(), Error> {
        if !self.state.is_active() {
            return Err(Error::InvalidArgument);
        }
        self.output.clear();

        let cmd = self.parser.parse(input)?;
        match cmd {
            KdbCommand::Help => self.cmd_help(),
            KdbCommand::Backtrace => self.cmd_backtrace(),
            KdbCommand::Registers => self.cmd_registers(),
            KdbCommand::Memory { addr, len } => self.cmd_memory(addr, len),
            KdbCommand::Breakpoint { addr } => self.cmd_breakpoint(addr),
            KdbCommand::Continue => self.cmd_continue(),
            KdbCommand::Step => self.cmd_step(),
            KdbCommand::ProcessList => self.cmd_process_list(),
            KdbCommand::ThreadList => self.cmd_thread_list(),
            KdbCommand::Quit => self.cmd_quit(),
        }
    }

    // ---------------------------------------------------------------
    // Command handlers
    // ---------------------------------------------------------------

    /// Display help text.
    fn cmd_help(&mut self) -> Result<(), Error> {
        self.output.write_str("ONCRIX KDB Commands:\n");
        self.output
            .write_str("  help (h, ?)        Show this help\n");
        self.output
            .write_str("  bt (backtrace)     Stack backtrace\n");
        self.output
            .write_str("  regs (registers)   Display registers\n");
        self.output
            .write_str("  x <addr> [len]     Memory dump (hex+ASCII)\n");
        self.output
            .write_str("  bp <addr>          Set breakpoint\n");
        self.output
            .write_str("  c (continue, go)   Resume execution\n");
        self.output.write_str("  s (step, si)       Single step\n");
        self.output
            .write_str("  ps (proclist)      List processes\n");
        self.output.write_str("  threads            List threads\n");
        self.output
            .write_str("  q (quit, exit)     Exit debugger\n");
        Ok(())
    }

    /// Display a stack backtrace from the saved RBP.
    fn cmd_backtrace(&mut self) -> Result<(), Error> {
        self.output.write_str("Stack backtrace:\n");
        self.output.write_str("  RIP: ");
        self.output.write_hex_u64(self.state.saved_regs.rip);
        self.output.write_str("\n");
        self.output.write_str("  RBP: ");
        self.output.write_hex_u64(self.state.saved_regs.rbp);
        self.output.write_str("\n");
        self.output.write_str("  RSP: ");
        self.output.write_hex_u64(self.state.saved_regs.rsp);
        self.output.write_str("\n");
        self.output
            .write_str("  (Full frame walk requires live memory access)\n");
        Ok(())
    }

    /// Format and display all x86_64 registers.
    fn cmd_registers(&mut self) -> Result<(), Error> {
        let r = self.state.saved_regs;
        self.output.write_str("Registers:\n");
        self.write_reg_pair("  RAX=", r.rax, " RBX=", r.rbx);
        self.write_reg_pair("  RCX=", r.rcx, " RDX=", r.rdx);
        self.write_reg_pair("  RSI=", r.rsi, " RDI=", r.rdi);
        self.write_reg_pair("  RBP=", r.rbp, " RSP=", r.rsp);
        self.write_reg_pair("   R8=", r.r8, "  R9=", r.r9);
        self.write_reg_pair("  R10=", r.r10, " R11=", r.r11);
        self.write_reg_pair("  R12=", r.r12, " R13=", r.r13);
        self.write_reg_pair("  R14=", r.r14, " R15=", r.r15);

        self.output.write_str("  RIP=");
        self.output.write_hex_u64(r.rip);
        self.output.write_str(" RFLAGS=");
        self.output.write_hex_u64(r.rflags);
        self.output.write_str("\n");

        self.output.write_str("  CS=");
        self.output.write_hex_u16(r.cs);
        self.output.write_str(" SS=");
        self.output.write_hex_u16(r.ss);
        self.output.write_str(" DS=");
        self.output.write_hex_u16(r.ds);
        self.output.write_str(" ES=");
        self.output.write_hex_u16(r.es);
        self.output.write_str(" FS=");
        self.output.write_hex_u16(r.fs);
        self.output.write_str(" GS=");
        self.output.write_hex_u16(r.gs);
        self.output.write_str("\n");
        Ok(())
    }

    /// Dump memory in hex + ASCII format.
    ///
    /// Formats 16 bytes per line with the address prefix,
    /// hex bytes, and printable ASCII representation.
    ///
    /// Internally reads raw memory at the given address via
    /// volatile pointer reads. The debugger context guarantees
    /// the kernel address space is fully mapped.
    fn cmd_memory(&mut self, addr: u64, len: usize) -> Result<(), Error> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        // Cap length to avoid buffer overflow in output.
        let max_lines = self.output.remaining() / 80; // ~80 chars per line
        let max_bytes = max_lines.saturating_mul(HEX_LINE_WIDTH);
        let actual_len = len.min(max_bytes);

        self.output.write_str("Memory dump at ");
        self.output.write_hex_u64(addr);
        self.output.write_str(", ");
        self.output.write_usize(actual_len);
        self.output.write_str(" bytes:\n");

        let mut offset: usize = 0;
        while offset < actual_len {
            let line_addr = addr.wrapping_add(offset as u64);
            self.output.write_hex_u64(line_addr);
            self.output.write_str(": ");

            let line_len = HEX_LINE_WIDTH.min(actual_len.saturating_sub(offset));

            // Hex bytes
            let mut col: usize = 0;
            while col < HEX_LINE_WIDTH {
                if col < line_len {
                    // SAFETY: The caller guarantees the address
                    // range is mapped. We read one byte at a time
                    // using volatile reads to prevent optimization.
                    let byte = unsafe {
                        core::ptr::read_volatile(line_addr.wrapping_add(col as u64) as *const u8)
                    };
                    self.output.write_hex_byte(byte);
                } else {
                    self.output.write_str("  ");
                }
                self.output.write_str(" ");
                // Extra space at the midpoint for readability.
                if col == 7 {
                    self.output.write_str(" ");
                }
                col = col.saturating_add(1);
            }

            // ASCII column
            self.output.write_str("|");
            col = 0;
            while col < line_len {
                let byte = unsafe {
                    core::ptr::read_volatile(line_addr.wrapping_add(col as u64) as *const u8)
                };
                if (0x20..=0x7E).contains(&byte) {
                    self.output.write_byte(byte);
                } else {
                    self.output.write_byte(b'.');
                }
                col = col.saturating_add(1);
            }
            // Pad ASCII column if short line
            while col < HEX_LINE_WIDTH {
                self.output.write_byte(b' ');
                col = col.saturating_add(1);
            }
            self.output.write_str("|\n");

            offset = offset.saturating_add(HEX_LINE_WIDTH);
        }
        Ok(())
    }

    /// Set a breakpoint at the given address.
    fn cmd_breakpoint(&mut self, addr: u64) -> Result<(), Error> {
        // Read the original byte at the target address.
        // SAFETY: Breakpoint insertion requires reading the
        // instruction byte. The caller must ensure the address is
        // in mapped kernel text.
        let original = unsafe { core::ptr::read_volatile(addr as *const u8) };
        let bp = KdbBreakpoint::new(addr, original);
        match self.breakpoints.add(bp) {
            Ok(slot) => {
                self.output.write_str("Breakpoint #");
                self.output.write_usize(slot);
                self.output.write_str(" set at ");
                self.output.write_hex_u64(addr);
                self.output.write_str(" (original byte 0x");
                self.output.write_hex_byte(original);
                self.output.write_str(")\n");
                Ok(())
            }
            Err(e) => {
                self.output.write_str("Failed to set breakpoint: ");
                match e {
                    Error::AlreadyExists => {
                        self.output.write_str("already exists\n");
                    }
                    Error::OutOfMemory => {
                        self.output.write_str("table full\n");
                    }
                    _ => {
                        self.output.write_str("unknown\n");
                    }
                }
                Err(e)
            }
        }
    }

    /// Resume execution.
    fn cmd_continue(&mut self) -> Result<(), Error> {
        self.state.single_step = false;
        self.output.write_str("Continuing execution.\n");
        self.state.activity = KdbActivity::Inactive;
        Ok(())
    }

    /// Enable single-step mode and resume for one instruction.
    fn cmd_step(&mut self) -> Result<(), Error> {
        self.state.single_step = true;
        self.output.write_str("Single stepping (TF will be set).\n");
        self.state.activity = KdbActivity::Inactive;
        Ok(())
    }

    /// List processes (stub — real implementation requires
    /// integration with the process subsystem).
    fn cmd_process_list(&mut self) -> Result<(), Error> {
        self.output.write_str("Process list:\n");
        self.output
            .write_str("  (not yet connected to process subsystem)\n");
        Ok(())
    }

    /// List threads (stub — real implementation requires
    /// integration with the scheduler).
    fn cmd_thread_list(&mut self) -> Result<(), Error> {
        self.output.write_str("Thread list:\n");
        self.output
            .write_str("  (not yet connected to scheduler)\n");
        Ok(())
    }

    /// Exit the kernel debugger.
    fn cmd_quit(&mut self) -> Result<(), Error> {
        self.output.write_str("Exiting KDB.\n");
        self.state.activity = KdbActivity::Inactive;
        self.state.single_step = false;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Write a pair of labelled hex register values on one line.
    fn write_reg_pair(&mut self, label_a: &str, val_a: u64, label_b: &str, val_b: u64) {
        self.output.write_str(label_a);
        self.output.write_hex_u64(val_a);
        self.output.write_str(label_b);
        self.output.write_hex_u64(val_b);
        self.output.write_str("\n");
    }
}

// -----------------------------------------------------------------------
// Format helpers: register display
// -----------------------------------------------------------------------

/// Format all x86_64 general-purpose and segment registers into
/// the provided output buffer.
///
/// This is a standalone function for use outside the `Kdb` struct
/// (e.g., from exception handlers that want a register dump
/// without entering full KDB).
pub fn format_registers(regs: &KdbRegisters, buf: &mut KdbOutputBuffer) {
    buf.write_str("Registers:\n");
    buf.write_str("  RAX=");
    buf.write_hex_u64(regs.rax);
    buf.write_str(" RBX=");
    buf.write_hex_u64(regs.rbx);
    buf.write_str("\n");

    buf.write_str("  RCX=");
    buf.write_hex_u64(regs.rcx);
    buf.write_str(" RDX=");
    buf.write_hex_u64(regs.rdx);
    buf.write_str("\n");

    buf.write_str("  RSI=");
    buf.write_hex_u64(regs.rsi);
    buf.write_str(" RDI=");
    buf.write_hex_u64(regs.rdi);
    buf.write_str("\n");

    buf.write_str("  RBP=");
    buf.write_hex_u64(regs.rbp);
    buf.write_str(" RSP=");
    buf.write_hex_u64(regs.rsp);
    buf.write_str("\n");

    buf.write_str("   R8=");
    buf.write_hex_u64(regs.r8);
    buf.write_str("  R9=");
    buf.write_hex_u64(regs.r9);
    buf.write_str("\n");

    buf.write_str("  R10=");
    buf.write_hex_u64(regs.r10);
    buf.write_str(" R11=");
    buf.write_hex_u64(regs.r11);
    buf.write_str("\n");

    buf.write_str("  R12=");
    buf.write_hex_u64(regs.r12);
    buf.write_str(" R13=");
    buf.write_hex_u64(regs.r13);
    buf.write_str("\n");

    buf.write_str("  R14=");
    buf.write_hex_u64(regs.r14);
    buf.write_str(" R15=");
    buf.write_hex_u64(regs.r15);
    buf.write_str("\n");

    buf.write_str("  RIP=");
    buf.write_hex_u64(regs.rip);
    buf.write_str(" RFLAGS=");
    buf.write_hex_u64(regs.rflags);
    buf.write_str("\n");

    buf.write_str("  CS=");
    buf.write_hex_u16(regs.cs);
    buf.write_str(" SS=");
    buf.write_hex_u16(regs.ss);
    buf.write_str(" DS=");
    buf.write_hex_u16(regs.ds);
    buf.write_str(" ES=");
    buf.write_hex_u16(regs.es);
    buf.write_str(" FS=");
    buf.write_hex_u16(regs.fs);
    buf.write_str(" GS=");
    buf.write_hex_u16(regs.gs);
    buf.write_str("\n");
}

/// Format a hex + ASCII memory dump into the provided output
/// buffer.
///
/// Displays `len` bytes starting at `data`, 16 bytes per line,
/// with address offsets, hex values, and printable ASCII.
pub fn format_memory_dump(base_addr: u64, data: &[u8], buf: &mut KdbOutputBuffer) {
    let len = data.len();
    let mut offset: usize = 0;
    while offset < len {
        let line_addr = base_addr.wrapping_add(offset as u64);
        buf.write_hex_u64(line_addr);
        buf.write_str(": ");

        let line_len = HEX_LINE_WIDTH.min(len.saturating_sub(offset));

        // Hex bytes
        let mut col: usize = 0;
        while col < HEX_LINE_WIDTH {
            if col < line_len {
                buf.write_hex_byte(data[offset.wrapping_add(col)]);
            } else {
                buf.write_str("  ");
            }
            buf.write_str(" ");
            if col == 7 {
                buf.write_str(" ");
            }
            col = col.saturating_add(1);
        }

        // ASCII column
        buf.write_str("|");
        col = 0;
        while col < line_len {
            let b = data[offset.wrapping_add(col)];
            if (0x20..=0x7E).contains(&b) {
                buf.write_byte(b);
            } else {
                buf.write_byte(b'.');
            }
            col = col.saturating_add(1);
        }
        while col < HEX_LINE_WIDTH {
            buf.write_byte(b' ');
            col = col.saturating_add(1);
        }
        buf.write_str("|\n");

        offset = offset.saturating_add(HEX_LINE_WIDTH);
    }
}

// -----------------------------------------------------------------------
// Parsing helpers (no_std, no alloc)
// -----------------------------------------------------------------------

/// Trim leading and trailing ASCII whitespace from a byte slice.
fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && is_ascii_whitespace(s[start]) {
        start = start.saturating_add(1);
    }
    let mut end = s.len();
    while end > start && is_ascii_whitespace(s[end - 1]) {
        end = end.saturating_sub(1);
    }
    &s[start..end]
}

/// Check whether a byte is ASCII whitespace.
const fn is_ascii_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Split a byte slice at the first whitespace boundary.
///
/// Returns `(first_token, rest)` where `rest` is everything
/// after the whitespace delimiter (untrimmed).
fn split_first_token(s: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < s.len() && !is_ascii_whitespace(s[i]) {
        i = i.saturating_add(1);
    }
    let token = &s[..i];
    let rest = if i < s.len() {
        &s[i.saturating_add(1)..]
    } else {
        &s[s.len()..]
    };
    (token, rest)
}

/// Parse a hexadecimal u64 value, with optional `0x` prefix.
fn parse_hex_u64(s: &[u8]) -> Option<u64> {
    let s = trim_ascii(s);
    if s.is_empty() {
        return None;
    }

    let digits = if s.len() >= 2 && s[0] == b'0' && matches!(s[1], b'x' | b'X') {
        &s[2..]
    } else {
        s
    };

    if digits.is_empty() || digits.len() > 16 {
        return None;
    }

    let mut result: u64 = 0;
    let mut i = 0;
    while i < digits.len() {
        let nibble = match digits[i] {
            b'0'..=b'9' => digits[i].wrapping_sub(b'0'),
            b'a'..=b'f' => digits[i].wrapping_sub(b'a').wrapping_add(10),
            b'A'..=b'F' => digits[i].wrapping_sub(b'A').wrapping_add(10),
            _ => return None,
        };
        result = result.checked_shl(4)?.wrapping_add(u64::from(nibble));
        i = i.saturating_add(1);
    }
    Some(result)
}

/// Parse a decimal usize value.
fn parse_usize_decimal(s: &[u8]) -> Option<usize> {
    let s = trim_ascii(s);
    if s.is_empty() {
        return None;
    }
    let mut result: usize = 0;
    let mut i = 0;
    while i < s.len() {
        let digit = match s[i] {
            b'0'..=b'9' => s[i].wrapping_sub(b'0') as usize,
            _ => return None,
        };
        result = result.checked_mul(10)?.checked_add(digit)?;
        i = i.saturating_add(1);
    }
    Some(result)
}
