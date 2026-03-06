// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel debugger GDB remote stub support.
//!
//! Implements the GDB Remote Serial Protocol (RSP) state machine so that
//! a host GDB can attach to the ONCRIX kernel over a serial/UART link.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                        KgdbState                                 │
//! │                                                                  │
//! │  protocol_state ── Disconnected / Connected / Stopped / Running  │
//! │  register_ctx   ── X86_64RegisterContext (rax..ss)               │
//! │  breakpoints    ── [Breakpoint; MAX_BREAKPOINTS]                 │
//! │  packet_buf     ── encode/decode ring                            │
//! │                                                                  │
//! │  ┌───────────────┐  serial byte stream  ┌───────────────┐       │
//! │  │  Host GDB     │ ◄──────────────────► │  kgdb stub    │       │
//! │  │  (gdb-remote) │   $pkt#XX / +/-      │  (this module)│       │
//! │  └───────────────┘                      └───────────────┘       │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Protocol Overview
//!
//! The GDB RSP uses `$payload#XX` framing where `XX` is a two-digit hex
//! checksum. Acknowledgement is `+` (ok) or `-` (resend). Key commands:
//!
//! | Cmd | Meaning |
//! |-----|---------|
//! | `g` | Read all general registers |
//! | `G` | Write all general registers |
//! | `m` | Read memory |
//! | `M` | Write memory |
//! | `s` | Single step |
//! | `c` | Continue |
//! | `Z` | Insert breakpoint |
//! | `z` | Remove breakpoint |
//! | `?` | Query stop reason |
//! | `q` | General query |
//! | `H` | Set thread for subsequent operations |
//!
//! # Reference
//!
//! Linux `kernel/debug/gdbstub.c`, `kernel/debug/debug_core.c`,
//! GDB Remote Serial Protocol specification.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of breakpoints (software + hardware).
const MAX_BREAKPOINTS: usize = 64;

/// Maximum number of hardware breakpoints (x86_64 DR0-DR3).
const MAX_HW_BREAKPOINTS: usize = 4;

/// Maximum GDB packet payload size.
const MAX_PACKET_SIZE: usize = 4096;

/// Maximum number of threads tracked for thread-aware debugging.
const MAX_THREADS: usize = 256;

/// Maximum length of a query response string.
const MAX_QUERY_RESPONSE: usize = 512;

/// GDB RSP start-of-packet marker.
const PACKET_START: u8 = b'$';

/// GDB RSP end-of-packet marker (before checksum).
const PACKET_END: u8 = b'#';

/// GDB RSP positive acknowledgement.
const ACK_OK: u8 = b'+';

/// GDB RSP negative acknowledgement (resend requested).
const ACK_RESEND: u8 = b'-';

/// Number of general-purpose registers in x86_64 GDB target description.
const X86_64_NUM_REGS: usize = 24;

/// Signal number for SIGTRAP.
const SIGTRAP: u8 = 5;

/// Signal number for SIGINT.
const _SIGINT: u8 = 2;

/// Signal number for SIGSEGV.
const _SIGSEGV: u8 = 11;

// ── Protocol State ──────────────────────────────────────────────────────────

/// Protocol connection state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    /// No GDB session is active.
    Disconnected,
    /// GDB is connected and the target is running.
    Connected,
    /// Target is stopped (breakpoint, signal, etc.).
    Stopped,
    /// Target is running after a continue/step command.
    Running,
    /// Detach requested, cleaning up.
    Detaching,
}

/// Reason the target stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Software breakpoint hit.
    Breakpoint,
    /// Hardware watchpoint triggered.
    Watchpoint,
    /// Single-step completed.
    SingleStep,
    /// Signal received (e.g., SIGSEGV).
    Signal(u8),
    /// Explicit halt from GDB (Ctrl-C).
    GdbHalt,
    /// Kernel panic.
    Panic,
}

/// Type of breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointType {
    /// Software breakpoint (INT3 on x86_64).
    Software,
    /// Hardware execution breakpoint (DR0-DR3).
    HardwareExec,
    /// Hardware write watchpoint.
    HardwareWrite,
    /// Hardware read watchpoint.
    HardwareRead,
    /// Hardware access (read+write) watchpoint.
    HardwareAccess,
}

/// Packet parser state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketParseState {
    /// Waiting for `$`.
    WaitStart,
    /// Accumulating payload bytes.
    Payload,
    /// Reading first hex digit of checksum.
    Checksum1,
    /// Reading second hex digit of checksum.
    Checksum2,
}

// ── Data Structures ─────────────────────────────────────────────────────────

/// x86_64 register context as seen by GDB.
///
/// Register ordering follows the GDB x86_64 target description:
/// rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
/// r8-r15, rip, eflags, cs, ss, ds, es, fs, gs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct X86_64RegisterContext {
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
    /// Base pointer register RBP.
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
    /// Flags register (RFLAGS).
    pub rflags: u64,
    /// Code segment selector.
    pub cs: u32,
    /// Stack segment selector.
    pub ss: u32,
    /// Data segment selector.
    pub ds: u32,
    /// Extra segment selector.
    pub es: u32,
    /// FS segment selector.
    pub fs: u32,
    /// GS segment selector.
    pub gs: u32,
}

impl X86_64RegisterContext {
    /// Create a zeroed register context.
    pub const fn new() -> Self {
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

    /// Encode all registers as a hex string into `buf`.
    ///
    /// GDB expects registers in order, each as little-endian hex.
    /// Returns the number of bytes written.
    pub fn encode_hex(&self, buf: &mut [u8]) -> Result<usize> {
        let regs_64 = [
            self.rax,
            self.rbx,
            self.rcx,
            self.rdx,
            self.rsi,
            self.rdi,
            self.rbp,
            self.rsp,
            self.r8,
            self.r9,
            self.r10,
            self.r11,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.rip,
            self.rflags,
        ];
        let regs_32 = [self.cs, self.ss, self.ds, self.es, self.fs, self.gs];
        let needed = regs_64.len() * 16 + regs_32.len() * 8;
        if buf.len() < needed {
            return Err(Error::InvalidArgument);
        }
        let mut pos = 0;
        for &val in &regs_64 {
            encode_u64_le_hex(val, &mut buf[pos..pos + 16]);
            pos += 16;
        }
        for &val in &regs_32 {
            encode_u32_le_hex(val, &mut buf[pos..pos + 8]);
            pos += 8;
        }
        Ok(pos)
    }

    /// Decode registers from a GDB hex string.
    pub fn decode_hex(&mut self, data: &[u8]) -> Result<()> {
        let needed = 18 * 16 + 6 * 8;
        if data.len() < needed {
            return Err(Error::InvalidArgument);
        }
        let mut pos = 0;
        let mut regs_64 = [0u64; 18];
        for reg in &mut regs_64 {
            *reg = decode_u64_le_hex(&data[pos..pos + 16])?;
            pos += 16;
        }
        self.rax = regs_64[0];
        self.rbx = regs_64[1];
        self.rcx = regs_64[2];
        self.rdx = regs_64[3];
        self.rsi = regs_64[4];
        self.rdi = regs_64[5];
        self.rbp = regs_64[6];
        self.rsp = regs_64[7];
        self.r8 = regs_64[8];
        self.r9 = regs_64[9];
        self.r10 = regs_64[10];
        self.r11 = regs_64[11];
        self.r12 = regs_64[12];
        self.r13 = regs_64[13];
        self.r14 = regs_64[14];
        self.r15 = regs_64[15];
        self.rip = regs_64[16];
        self.rflags = regs_64[17];

        let mut regs_32 = [0u32; 6];
        for reg in &mut regs_32 {
            *reg = decode_u32_le_hex(&data[pos..pos + 8])?;
            pos += 8;
        }
        self.cs = regs_32[0];
        self.ss = regs_32[1];
        self.ds = regs_32[2];
        self.es = regs_32[3];
        self.fs = regs_32[4];
        self.gs = regs_32[5];
        Ok(())
    }
}

/// A single breakpoint entry.
#[derive(Debug, Clone, Copy)]
pub struct Breakpoint {
    /// Whether this slot is in use.
    pub active: bool,
    /// Type of breakpoint.
    pub bp_type: BreakpointType,
    /// Address of the breakpoint.
    pub address: u64,
    /// Length in bytes (1/2/4/8 for watchpoints, 1 for sw bp).
    pub length: u32,
    /// Original byte at the breakpoint address (for software bp).
    pub original_byte: u8,
    /// Hardware breakpoint register index (0-3, valid for hw bp).
    pub hw_reg: u8,
}

impl Breakpoint {
    /// Create an empty (inactive) breakpoint slot.
    pub const fn new() -> Self {
        Self {
            active: false,
            bp_type: BreakpointType::Software,
            address: 0,
            length: 0,
            original_byte: 0,
            hw_reg: 0,
        }
    }
}

/// Thread descriptor for multi-threaded debugging.
#[derive(Debug, Clone, Copy)]
pub struct ThreadInfo {
    /// Whether this slot is in use.
    pub active: bool,
    /// Thread / task ID.
    pub tid: u64,
    /// Whether this thread is currently stopped.
    pub stopped: bool,
    /// Stop reason if stopped.
    pub stop_reason: StopReason,
}

impl ThreadInfo {
    /// Create an empty thread info slot.
    pub const fn new() -> Self {
        Self {
            active: false,
            tid: 0,
            stopped: false,
            stop_reason: StopReason::Breakpoint,
        }
    }
}

/// Packet buffer for parsing and assembling GDB RSP packets.
#[derive(Debug)]
pub struct PacketBuffer {
    /// Raw payload data (between $ and #).
    data: [u8; MAX_PACKET_SIZE],
    /// Current write position in the payload.
    length: usize,
    /// Parser state machine.
    parse_state: PacketParseState,
    /// Running checksum during parsing.
    running_checksum: u8,
    /// Received checksum (first nibble).
    recv_checksum_hi: u8,
    /// Whether a complete packet is available.
    complete: bool,
}

impl PacketBuffer {
    /// Create a new empty packet buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_PACKET_SIZE],
            length: 0,
            parse_state: PacketParseState::WaitStart,
            running_checksum: 0,
            recv_checksum_hi: 0,
            complete: false,
        }
    }

    /// Reset the packet buffer for a new packet.
    pub fn reset(&mut self) {
        self.length = 0;
        self.parse_state = PacketParseState::WaitStart;
        self.running_checksum = 0;
        self.recv_checksum_hi = 0;
        self.complete = false;
    }

    /// Feed a single byte from the serial stream.
    ///
    /// Returns `true` when a complete, checksum-verified packet is ready.
    pub fn feed_byte(&mut self, byte: u8) -> bool {
        match self.parse_state {
            PacketParseState::WaitStart => {
                if byte == PACKET_START {
                    self.length = 0;
                    self.running_checksum = 0;
                    self.parse_state = PacketParseState::Payload;
                }
                // Ignore ACK bytes and other noise
            }
            PacketParseState::Payload => {
                if byte == PACKET_END {
                    self.parse_state = PacketParseState::Checksum1;
                } else if self.length < MAX_PACKET_SIZE {
                    self.data[self.length] = byte;
                    self.length += 1;
                    self.running_checksum = self.running_checksum.wrapping_add(byte);
                }
            }
            PacketParseState::Checksum1 => {
                self.recv_checksum_hi = hex_char_to_nibble(byte);
                self.parse_state = PacketParseState::Checksum2;
            }
            PacketParseState::Checksum2 => {
                let recv_lo = hex_char_to_nibble(byte);
                let recv_sum = (self.recv_checksum_hi << 4) | recv_lo;
                self.complete = recv_sum == self.running_checksum;
                self.parse_state = PacketParseState::WaitStart;
                return self.complete;
            }
        }
        false
    }

    /// Get the parsed payload data.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.length]
    }

    /// Whether the last parsed packet had a valid checksum.
    pub fn is_valid(&self) -> bool {
        self.complete
    }

    /// Encode a response payload into `$payload#XX` format.
    ///
    /// Returns the number of bytes written to `out`.
    pub fn encode_packet(payload: &[u8], out: &mut [u8]) -> Result<usize> {
        // Need: $ + payload + # + 2 hex chars
        let needed = 1 + payload.len() + 3;
        if out.len() < needed {
            return Err(Error::InvalidArgument);
        }
        out[0] = PACKET_START;
        let mut checksum: u8 = 0;
        for (i, &b) in payload.iter().enumerate() {
            out[1 + i] = b;
            checksum = checksum.wrapping_add(b);
        }
        let pos = 1 + payload.len();
        out[pos] = PACKET_END;
        out[pos + 1] = nibble_to_hex_char(checksum >> 4);
        out[pos + 2] = nibble_to_hex_char(checksum & 0x0f);
        Ok(needed)
    }
}

// ── Main KGDB State ─────────────────────────────────────────────────────────

/// Main KGDB debugger state.
///
/// Holds all state for a single GDB debug session: protocol state,
/// register contexts, breakpoints, and thread tracking.
pub struct KgdbState {
    /// Current protocol state.
    state: ProtocolState,
    /// Reason the target last stopped.
    stop_reason: StopReason,
    /// Saved register context at stop point.
    register_ctx: X86_64RegisterContext,
    /// Breakpoint table.
    breakpoints: [Breakpoint; MAX_BREAKPOINTS],
    /// Number of active breakpoints.
    bp_count: usize,
    /// Number of active hardware breakpoints.
    hw_bp_count: usize,
    /// Thread tracking table.
    threads: [ThreadInfo; MAX_THREADS],
    /// Number of active threads.
    thread_count: usize,
    /// Currently selected thread for g/G/m/M commands.
    current_thread: u64,
    /// Packet receive buffer.
    rx_buf: PacketBuffer,
    /// Packet transmit staging area.
    tx_buf: [u8; MAX_PACKET_SIZE],
    /// Whether no-ack mode is enabled (QStartNoAckMode).
    no_ack_mode: bool,
    /// Statistics: packets received.
    stats_rx_packets: u64,
    /// Statistics: packets transmitted.
    stats_tx_packets: u64,
    /// Statistics: checksum errors.
    stats_checksum_errors: u64,
}

impl KgdbState {
    /// Create a new KGDB state in disconnected mode.
    pub const fn new() -> Self {
        Self {
            state: ProtocolState::Disconnected,
            stop_reason: StopReason::Breakpoint,
            register_ctx: X86_64RegisterContext::new(),
            breakpoints: [const { Breakpoint::new() }; MAX_BREAKPOINTS],
            bp_count: 0,
            hw_bp_count: 0,
            threads: [const { ThreadInfo::new() }; MAX_THREADS],
            thread_count: 0,
            current_thread: 0,
            rx_buf: PacketBuffer::new(),
            tx_buf: [0u8; MAX_PACKET_SIZE],
            no_ack_mode: false,
            stats_rx_packets: 0,
            stats_tx_packets: 0,
            stats_checksum_errors: 0,
        }
    }

    /// Get the current protocol state.
    pub fn protocol_state(&self) -> ProtocolState {
        self.state
    }

    /// Get the current stop reason.
    pub fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    /// Get a reference to the saved register context.
    pub fn register_context(&self) -> &X86_64RegisterContext {
        &self.register_ctx
    }

    /// Get a mutable reference to the register context.
    pub fn register_context_mut(&mut self) -> &mut X86_64RegisterContext {
        &mut self.register_ctx
    }

    /// Get the number of active breakpoints.
    pub fn breakpoint_count(&self) -> usize {
        self.bp_count
    }

    /// Get the number of active hardware breakpoints.
    pub fn hw_breakpoint_count(&self) -> usize {
        self.hw_bp_count
    }

    /// Whether no-ack mode is active.
    pub fn is_no_ack_mode(&self) -> bool {
        self.no_ack_mode
    }

    /// Handle a GDB connection event.
    pub fn connect(&mut self) -> Result<()> {
        if self.state != ProtocolState::Disconnected {
            return Err(Error::Busy);
        }
        self.state = ProtocolState::Connected;
        self.no_ack_mode = false;
        self.stats_rx_packets = 0;
        self.stats_tx_packets = 0;
        self.stats_checksum_errors = 0;
        Ok(())
    }

    /// Transition to stopped state with a given reason.
    pub fn enter_stopped(&mut self, reason: StopReason) {
        self.state = ProtocolState::Stopped;
        self.stop_reason = reason;
    }

    /// Transition to running state (after continue or step).
    pub fn enter_running(&mut self) {
        self.state = ProtocolState::Running;
    }

    /// Initiate disconnection.
    pub fn disconnect(&mut self) {
        self.state = ProtocolState::Disconnected;
        self.no_ack_mode = false;
    }

    /// Feed a received byte into the packet parser.
    ///
    /// Returns `Ok(true)` if a complete packet is ready for dispatch,
    /// `Ok(false)` if more bytes are needed.
    pub fn feed_byte(&mut self, byte: u8) -> Result<bool> {
        if self.state == ProtocolState::Disconnected {
            return Err(Error::InvalidArgument);
        }
        let complete = self.rx_buf.feed_byte(byte);
        if complete {
            if self.rx_buf.is_valid() {
                self.stats_rx_packets += 1;
            } else {
                self.stats_checksum_errors += 1;
                self.rx_buf.reset();
            }
        }
        Ok(complete && self.rx_buf.is_valid())
    }

    /// Dispatch the currently buffered packet command.
    ///
    /// Returns `Ok(n)` where `n` is the number of bytes written to
    /// the internal tx_buf for the response.
    pub fn dispatch_command(&mut self) -> Result<usize> {
        let plen = self.rx_buf.payload().len();
        if plen == 0 {
            return self.encode_empty_response();
        }
        // Copy payload to local buffer to release borrow on self.rx_buf.
        let mut local_buf = [0u8; MAX_PACKET_SIZE];
        local_buf[..plen].copy_from_slice(self.rx_buf.payload());
        let cmd = local_buf[0];
        let args = &local_buf[1..plen];
        let resp_len = match cmd {
            b'?' => self.handle_stop_reason_query()?,
            b'g' => self.handle_read_registers()?,
            b'G' => self.handle_write_registers(args)?,
            b'm' => self.handle_read_memory(args)?,
            b'M' => self.handle_write_memory(args)?,
            b's' => self.handle_single_step(args)?,
            b'c' => self.handle_continue(args)?,
            b'Z' => self.handle_insert_breakpoint(args)?,
            b'z' => self.handle_remove_breakpoint(args)?,
            b'H' => self.handle_set_thread(args)?,
            b'q' => self.handle_query(args)?,
            b'Q' => self.handle_set_query(args)?,
            b'D' => self.handle_detach()?,
            b'k' => self.handle_kill()?,
            _ => self.encode_empty_response()?,
        };
        self.rx_buf.reset();
        self.stats_tx_packets += 1;
        Ok(resp_len)
    }

    /// Get the response data after dispatch.
    pub fn response_data(&self) -> &[u8] {
        &self.tx_buf
    }

    /// Handle `?` — report stop reason.
    fn handle_stop_reason_query(&mut self) -> Result<usize> {
        let sig = match self.stop_reason {
            StopReason::Breakpoint | StopReason::SingleStep => SIGTRAP,
            StopReason::Watchpoint => SIGTRAP,
            StopReason::Signal(s) => s,
            StopReason::GdbHalt => SIGTRAP,
            StopReason::Panic => SIGTRAP,
        };
        // Format: S<signal-hex>
        let mut resp = [0u8; 3];
        resp[0] = b'S';
        resp[1] = nibble_to_hex_char(sig >> 4);
        resp[2] = nibble_to_hex_char(sig & 0x0f);
        self.encode_response(&resp)
    }

    /// Handle `g` — read all registers.
    fn handle_read_registers(&mut self) -> Result<usize> {
        let mut hex_buf = [0u8; X86_64_NUM_REGS * 16];
        let len = self.register_ctx.encode_hex(&mut hex_buf)?;
        self.encode_response(&hex_buf[..len])
    }

    /// Handle `G` — write all registers.
    fn handle_write_registers(&mut self, data: &[u8]) -> Result<usize> {
        self.register_ctx.decode_hex(data)?;
        self.encode_ok_response()
    }

    /// Handle `m addr,length` — read memory.
    fn handle_read_memory(&mut self, args: &[u8]) -> Result<usize> {
        let (addr, len) = parse_addr_length(args)?;
        // Validate address range (basic kernel address check)
        if addr == 0 || len == 0 || len > MAX_PACKET_SIZE / 2 {
            return self.encode_error_response(0x01);
        }
        // In a real implementation, we would read kernel memory here.
        // For now, produce a zero-filled response.
        let hex_len = len * 2;
        if hex_len > self.tx_buf.len() - 4 {
            return self.encode_error_response(0x01);
        }
        let mut resp = [0u8; MAX_PACKET_SIZE];
        for i in 0..hex_len {
            resp[i] = b'0';
        }
        self.encode_response(&resp[..hex_len])
    }

    /// Handle `M addr,length:data` — write memory.
    fn handle_write_memory(&mut self, args: &[u8]) -> Result<usize> {
        let colon_pos = args
            .iter()
            .position(|&b| b == b':')
            .ok_or(Error::InvalidArgument)?;
        let (addr, len) = parse_addr_length(&args[..colon_pos])?;
        let hex_data = &args[colon_pos + 1..];
        if hex_data.len() != len * 2 {
            return self.encode_error_response(0x01);
        }
        if addr == 0 {
            return self.encode_error_response(0x01);
        }
        // In a real implementation, we would write kernel memory here.
        self.encode_ok_response()
    }

    /// Handle `s [addr]` — single step.
    fn handle_single_step(&mut self, args: &[u8]) -> Result<usize> {
        if !args.is_empty() {
            let addr = parse_hex_u64(args)?;
            self.register_ctx.rip = addr;
        }
        self.enter_running();
        // Signal: step completed (will be sent as stop reply later)
        self.encode_ok_response()
    }

    /// Handle `c [addr]` — continue execution.
    fn handle_continue(&mut self, args: &[u8]) -> Result<usize> {
        if !args.is_empty() {
            let addr = parse_hex_u64(args)?;
            self.register_ctx.rip = addr;
        }
        self.enter_running();
        self.encode_ok_response()
    }

    /// Handle `Z type,addr,kind` — insert breakpoint.
    fn handle_insert_breakpoint(&mut self, args: &[u8]) -> Result<usize> {
        if args.is_empty() {
            return self.encode_error_response(0x01);
        }
        let bp_type_byte = args[0];
        let rest = if args.len() > 2 { &args[2..] } else { &[] };
        let (addr, kind) = parse_addr_length(rest)?;
        let bp_type = match bp_type_byte {
            b'0' => BreakpointType::Software,
            b'1' => BreakpointType::HardwareExec,
            b'2' => BreakpointType::HardwareWrite,
            b'3' => BreakpointType::HardwareRead,
            b'4' => BreakpointType::HardwareAccess,
            _ => return self.encode_error_response(0x01),
        };
        self.insert_breakpoint(bp_type, addr, kind as u32)?;
        self.encode_ok_response()
    }

    /// Handle `z type,addr,kind` — remove breakpoint.
    fn handle_remove_breakpoint(&mut self, args: &[u8]) -> Result<usize> {
        if args.is_empty() {
            return self.encode_error_response(0x01);
        }
        let bp_type_byte = args[0];
        let rest = if args.len() > 2 { &args[2..] } else { &[] };
        let (addr, _kind) = parse_addr_length(rest)?;
        let bp_type = match bp_type_byte {
            b'0' => BreakpointType::Software,
            b'1' => BreakpointType::HardwareExec,
            b'2' => BreakpointType::HardwareWrite,
            b'3' => BreakpointType::HardwareRead,
            b'4' => BreakpointType::HardwareAccess,
            _ => return self.encode_error_response(0x01),
        };
        self.remove_breakpoint(bp_type, addr)?;
        self.encode_ok_response()
    }

    /// Handle `H op,thread-id` — set thread.
    fn handle_set_thread(&mut self, args: &[u8]) -> Result<usize> {
        if args.len() < 2 {
            return self.encode_error_response(0x01);
        }
        // args[0] is 'c' (continue) or 'g' (other ops)
        let tid = parse_hex_u64(&args[1..])?;
        if tid != 0 {
            self.current_thread = tid;
        }
        self.encode_ok_response()
    }

    /// Handle `q...` — query commands.
    fn handle_query(&mut self, args: &[u8]) -> Result<usize> {
        if starts_with(args, b"Supported") {
            let features = b"PacketSize=1000;QStartNoAckMode+";
            return self.encode_response(features);
        }
        if starts_with(args, b"Attached") {
            // 1 = attached to existing process
            return self.encode_response(b"1");
        }
        if starts_with(args, b"C") {
            // Current thread ID
            let mut resp = [0u8; MAX_QUERY_RESPONSE];
            resp[0] = b'Q';
            resp[1] = b'C';
            let len = encode_hex_u64(self.current_thread, &mut resp[2..]);
            return self.encode_response(&resp[..2 + len]);
        }
        if starts_with(args, b"fThreadInfo") {
            return self.handle_thread_info_first();
        }
        if starts_with(args, b"sThreadInfo") {
            return self.encode_response(b"l");
        }
        self.encode_empty_response()
    }

    /// Handle `Q...` — set commands.
    fn handle_set_query(&mut self, args: &[u8]) -> Result<usize> {
        if starts_with(args, b"StartNoAckMode") {
            self.no_ack_mode = true;
            return self.encode_ok_response();
        }
        self.encode_empty_response()
    }

    /// Handle `D` — detach.
    fn handle_detach(&mut self) -> Result<usize> {
        self.state = ProtocolState::Detaching;
        let resp_len = self.encode_ok_response()?;
        self.disconnect();
        Ok(resp_len)
    }

    /// Handle `k` — kill.
    fn handle_kill(&mut self) -> Result<usize> {
        self.disconnect();
        self.encode_ok_response()
    }

    /// Handle `qfThreadInfo` — first batch of thread IDs.
    fn handle_thread_info_first(&mut self) -> Result<usize> {
        let mut resp = [0u8; MAX_QUERY_RESPONSE];
        resp[0] = b'm';
        let mut pos = 1;
        let mut first = true;
        for i in 0..MAX_THREADS {
            if !self.threads[i].active {
                continue;
            }
            if !first && pos < MAX_QUERY_RESPONSE - 1 {
                resp[pos] = b',';
                pos += 1;
            }
            let tid = self.threads[i].tid;
            let written = encode_hex_u64(tid, &mut resp[pos..]);
            pos += written;
            first = false;
        }
        if first {
            // No threads — send "l" (end of list)
            return self.encode_response(b"l");
        }
        self.encode_response(&resp[..pos])
    }

    // ── Breakpoint management ───────────────────────────────────────

    /// Insert a new breakpoint.
    pub fn insert_breakpoint(
        &mut self,
        bp_type: BreakpointType,
        address: u64,
        length: u32,
    ) -> Result<()> {
        // Check for duplicate
        for i in 0..MAX_BREAKPOINTS {
            if self.breakpoints[i].active
                && self.breakpoints[i].address == address
                && matches!(
                    (&self.breakpoints[i].bp_type, &bp_type),
                    (a, b) if core::mem::discriminant(a)
                        == core::mem::discriminant(b)
                )
            {
                return Err(Error::AlreadyExists);
            }
        }
        // Check hardware bp limits
        if !matches!(bp_type, BreakpointType::Software) && self.hw_bp_count >= MAX_HW_BREAKPOINTS {
            return Err(Error::OutOfMemory);
        }
        // Find free slot
        let slot = (0..MAX_BREAKPOINTS)
            .find(|&i| !self.breakpoints[i].active)
            .ok_or(Error::OutOfMemory)?;
        self.breakpoints[slot].active = true;
        self.breakpoints[slot].bp_type = bp_type;
        self.breakpoints[slot].address = address;
        self.breakpoints[slot].length = length;
        self.breakpoints[slot].original_byte = 0;
        self.breakpoints[slot].hw_reg = if !matches!(bp_type, BreakpointType::Software) {
            self.hw_bp_count as u8
        } else {
            0
        };
        self.bp_count += 1;
        if !matches!(bp_type, BreakpointType::Software) {
            self.hw_bp_count += 1;
        }
        Ok(())
    }

    /// Remove a breakpoint by type and address.
    pub fn remove_breakpoint(&mut self, bp_type: BreakpointType, address: u64) -> Result<()> {
        let slot = (0..MAX_BREAKPOINTS)
            .find(|&i| {
                self.breakpoints[i].active
                    && self.breakpoints[i].address == address
                    && core::mem::discriminant(&self.breakpoints[i].bp_type)
                        == core::mem::discriminant(&bp_type)
            })
            .ok_or(Error::NotFound)?;
        let is_hw = !matches!(self.breakpoints[slot].bp_type, BreakpointType::Software);
        self.breakpoints[slot].active = false;
        self.bp_count = self.bp_count.saturating_sub(1);
        if is_hw {
            self.hw_bp_count = self.hw_bp_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Look up a breakpoint by address.
    pub fn find_breakpoint(&self, address: u64) -> Option<&Breakpoint> {
        self.breakpoints[..MAX_BREAKPOINTS]
            .iter()
            .find(|bp| bp.active && bp.address == address)
    }

    // ── Thread management ───────────────────────────────────────────

    /// Register a thread for debugging.
    pub fn register_thread(&mut self, tid: u64) -> Result<()> {
        if self.thread_count >= MAX_THREADS {
            return Err(Error::OutOfMemory);
        }
        let slot = (0..MAX_THREADS)
            .find(|&i| !self.threads[i].active)
            .ok_or(Error::OutOfMemory)?;
        self.threads[slot].active = true;
        self.threads[slot].tid = tid;
        self.threads[slot].stopped = false;
        self.thread_count += 1;
        Ok(())
    }

    /// Unregister a thread.
    pub fn unregister_thread(&mut self, tid: u64) -> Result<()> {
        let slot = (0..MAX_THREADS)
            .find(|&i| self.threads[i].active && self.threads[i].tid == tid)
            .ok_or(Error::NotFound)?;
        self.threads[slot].active = false;
        self.thread_count = self.thread_count.saturating_sub(1);
        Ok(())
    }

    /// Mark a thread as stopped with a given reason.
    pub fn stop_thread(&mut self, tid: u64, reason: StopReason) -> Result<()> {
        let slot = (0..MAX_THREADS)
            .find(|&i| self.threads[i].active && self.threads[i].tid == tid)
            .ok_or(Error::NotFound)?;
        self.threads[slot].stopped = true;
        self.threads[slot].stop_reason = reason;
        Ok(())
    }

    // ── Response encoding helpers ───────────────────────────────────

    /// Encode a response payload into the tx buffer.
    fn encode_response(&mut self, payload: &[u8]) -> Result<usize> {
        PacketBuffer::encode_packet(payload, &mut self.tx_buf)
    }

    /// Encode an "OK" response.
    fn encode_ok_response(&mut self) -> Result<usize> {
        self.encode_response(b"OK")
    }

    /// Encode an empty response (unsupported command).
    fn encode_empty_response(&mut self) -> Result<usize> {
        self.encode_response(b"")
    }

    /// Encode an error response with a two-digit error code.
    fn encode_error_response(&mut self, code: u8) -> Result<usize> {
        let resp = [
            b'E',
            nibble_to_hex_char(code >> 4),
            nibble_to_hex_char(code & 0x0f),
        ];
        self.encode_response(&resp)
    }

    // ── Statistics ──────────────────────────────────────────────────

    /// Get total packets received.
    pub fn stats_rx(&self) -> u64 {
        self.stats_rx_packets
    }

    /// Get total packets transmitted.
    pub fn stats_tx(&self) -> u64 {
        self.stats_tx_packets
    }

    /// Get total checksum errors.
    pub fn stats_errors(&self) -> u64 {
        self.stats_checksum_errors
    }
}

// ── Hex Encoding/Decoding Helpers ───────────────────────────────────────────

/// Convert a nibble (0-15) to a hex ASCII character.
fn nibble_to_hex_char(nibble: u8) -> u8 {
    let n = nibble & 0x0f;
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

/// Convert a hex ASCII character to a nibble value.
fn hex_char_to_nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => 0,
    }
}

/// Encode a u64 as little-endian hex (16 chars) into `buf`.
fn encode_u64_le_hex(val: u64, buf: &mut [u8]) {
    let bytes = val.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        buf[i * 2] = nibble_to_hex_char(b >> 4);
        buf[i * 2 + 1] = nibble_to_hex_char(b & 0x0f);
    }
}

/// Encode a u32 as little-endian hex (8 chars) into `buf`.
fn encode_u32_le_hex(val: u32, buf: &mut [u8]) {
    let bytes = val.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        buf[i * 2] = nibble_to_hex_char(b >> 4);
        buf[i * 2 + 1] = nibble_to_hex_char(b & 0x0f);
    }
}

/// Decode a u64 from little-endian hex (16 chars).
fn decode_u64_le_hex(data: &[u8]) -> Result<u64> {
    if data.len() < 16 {
        return Err(Error::InvalidArgument);
    }
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        let hi = hex_char_to_nibble(data[i * 2]);
        let lo = hex_char_to_nibble(data[i * 2 + 1]);
        bytes[i] = (hi << 4) | lo;
    }
    Ok(u64::from_le_bytes(bytes))
}

/// Decode a u32 from little-endian hex (8 chars).
fn decode_u32_le_hex(data: &[u8]) -> Result<u32> {
    if data.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        let hi = hex_char_to_nibble(data[i * 2]);
        let lo = hex_char_to_nibble(data[i * 2 + 1]);
        bytes[i] = (hi << 4) | lo;
    }
    Ok(u32::from_le_bytes(bytes))
}

/// Parse a hex u64 from a byte slice.
fn parse_hex_u64(data: &[u8]) -> Result<u64> {
    let mut val: u64 = 0;
    for &ch in data {
        let nibble = match ch {
            b'0'..=b'9' => (ch - b'0') as u64,
            b'a'..=b'f' => (ch - b'a' + 10) as u64,
            b'A'..=b'F' => (ch - b'A' + 10) as u64,
            _ => return Err(Error::InvalidArgument),
        };
        val = val.checked_shl(4).ok_or(Error::InvalidArgument)?;
        val |= nibble;
    }
    Ok(val)
}

/// Encode a u64 as big-endian hex into `buf`. Returns chars written.
fn encode_hex_u64(val: u64, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    // Count hex digits
    let bits = 64 - val.leading_zeros() as usize;
    let digits = (bits + 3) / 4;
    if buf.len() < digits {
        return 0;
    }
    for i in 0..digits {
        let nibble = ((val >> ((digits - 1 - i) * 4)) & 0x0f) as u8;
        buf[i] = nibble_to_hex_char(nibble);
    }
    digits
}

/// Parse `addr,length` from a GDB command argument.
fn parse_addr_length(data: &[u8]) -> Result<(u64, usize)> {
    let comma_pos = data
        .iter()
        .position(|&b| b == b',')
        .ok_or(Error::InvalidArgument)?;
    let addr = parse_hex_u64(&data[..comma_pos])?;
    let length = parse_hex_u64(&data[comma_pos + 1..])? as usize;
    Ok((addr, length))
}

/// Check if `data` starts with `prefix`.
fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    data.len() >= prefix.len() && &data[..prefix.len()] == prefix
}
