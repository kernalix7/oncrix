// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX termios terminal control layer.
//!
//! Implements the terminal I/O interface as specified by
//! POSIX.1-2024 (IEEE Std 1003.1-2024, `<termios.h>`). This module
//! provides the [`Termios`] structure, flag constants for input,
//! output, control, and local modes, baud rate definitions, control
//! character indices, and the [`LineEditor`] for canonical-mode line
//! editing.
//!
//! # References
//!
//! - POSIX.1-2024, Base Definitions, `<termios.h>`
//! - POSIX.1-2024, General Terminal Interface (Chapter 11)

use oncrix_lib::{Error, Result};

// ── Type aliases (POSIX cc_t, tcflag_t, speed_t) ─────────────────

/// Terminal special character type (POSIX `cc_t`).
pub type CcT = u8;

/// Terminal mode flag type (POSIX `tcflag_t`).
pub type TcFlagT = u32;

/// Terminal baud rate type (POSIX `speed_t`).
pub type SpeedT = u32;

// ── NCCS ─────────────────────────────────────────────────────────

/// Size of the `c_cc` control character array.
pub const NCCS: usize = 16;

// ── Control character indices (c_cc subscripts) ──────────────────

/// Index into `c_cc` for the EOF character (canonical mode).
pub const VEOF: usize = 0;

/// Index into `c_cc` for the EOL character (canonical mode).
pub const VEOL: usize = 1;

/// Index into `c_cc` for the ERASE character (canonical mode).
pub const VERASE: usize = 2;

/// Index into `c_cc` for the INTR character.
pub const VINTR: usize = 3;

/// Index into `c_cc` for the KILL character (canonical mode).
pub const VKILL: usize = 4;

/// Index into `c_cc` for the MIN value (non-canonical mode).
pub const VMIN: usize = 5;

/// Index into `c_cc` for the QUIT character.
pub const VQUIT: usize = 6;

/// Index into `c_cc` for the START character (flow control).
pub const VSTART: usize = 7;

/// Index into `c_cc` for the STOP character (flow control).
pub const VSTOP: usize = 8;

/// Index into `c_cc` for the SUSP character.
pub const VSUSP: usize = 9;

/// Index into `c_cc` for the TIME value (non-canonical mode).
pub const VTIME: usize = 10;

// ── Input flags (c_iflag) ────────────────────────────────────────

/// Ignore BREAK condition.
pub const IGNBRK: TcFlagT = 0x0001;

/// Signal interrupt on BREAK.
pub const BRKINT: TcFlagT = 0x0002;

/// Ignore characters with parity errors.
pub const IGNPAR: TcFlagT = 0x0004;

/// Mark parity and framing errors.
pub const PARMRK: TcFlagT = 0x0008;

/// Enable input parity checking.
pub const INPCK: TcFlagT = 0x0010;

/// Strip eighth bit off input characters.
pub const ISTRIP: TcFlagT = 0x0020;

/// Map NL to CR on input.
pub const INLCR: TcFlagT = 0x0040;

/// Ignore CR on input.
pub const IGNCR: TcFlagT = 0x0080;

/// Map CR to NL on input.
pub const ICRNL: TcFlagT = 0x0100;

/// Enable start/stop output control.
pub const IXON: TcFlagT = 0x0200;

/// Enable start/stop input control.
pub const IXOFF: TcFlagT = 0x0400;

/// Enable any character to restart output.
pub const IXANY: TcFlagT = 0x0800;

// ── Output flags (c_oflag) ───────────────────────────────────────

/// Post-process output.
pub const OPOST: TcFlagT = 0x0001;

/// Map NL to CR-NL on output.
pub const ONLCR: TcFlagT = 0x0002;

/// Map CR to NL on output.
pub const OCRNL: TcFlagT = 0x0004;

/// No CR output at column 0.
pub const ONOCR: TcFlagT = 0x0008;

/// NL performs CR function.
pub const ONLRET: TcFlagT = 0x0010;

/// Use fill characters for delay.
pub const OFILL: TcFlagT = 0x0020;

// ── Control flags (c_cflag) ──────────────────────────────────────

/// Character size mask.
pub const CSIZE: TcFlagT = 0x0030;

/// 5-bit characters.
pub const CS5: TcFlagT = 0x0000;

/// 6-bit characters.
pub const CS6: TcFlagT = 0x0010;

/// 7-bit characters.
pub const CS7: TcFlagT = 0x0020;

/// 8-bit characters.
pub const CS8: TcFlagT = 0x0030;

/// Send two stop bits (else one).
pub const CSTOPB: TcFlagT = 0x0040;

/// Enable receiver.
pub const CREAD: TcFlagT = 0x0080;

/// Parity enable.
pub const PARENB: TcFlagT = 0x0100;

/// Odd parity (else even).
pub const PARODD: TcFlagT = 0x0200;

/// Hang up on last close.
pub const HUPCL: TcFlagT = 0x0400;

/// Ignore modem status lines.
pub const CLOCAL: TcFlagT = 0x0800;

// ── Local flags (c_lflag) ────────────────────────────────────────

/// Enable signals (INTR, QUIT, SUSP).
pub const ISIG: TcFlagT = 0x0001;

/// Canonical input (erase and kill processing).
pub const ICANON: TcFlagT = 0x0002;

/// Enable echo.
pub const ECHO: TcFlagT = 0x0004;

/// Echo ERASE as backspace-space-backspace.
pub const ECHOE: TcFlagT = 0x0008;

/// Echo KILL by erasing each character on the line.
pub const ECHOK: TcFlagT = 0x0010;

/// Echo NL even if ECHO is off.
pub const ECHONL: TcFlagT = 0x0020;

/// Disable flush after interrupt or quit.
pub const NOFLSH: TcFlagT = 0x0040;

/// Send SIGTTOU for background output.
pub const TOSTOP: TcFlagT = 0x0080;

/// Enable implementation-defined input processing.
pub const IEXTEN: TcFlagT = 0x0100;

// ── BaudRate ─────────────────────────────────────────────────────

/// Standard baud rates as defined by POSIX.
///
/// Each variant maps to a symbolic constant (`B0` through
/// `B115200`). Use [`BaudRate::to_speed`] to obtain the numeric
/// bits-per-second value, or [`BaudRate::from_speed`] to convert
/// back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BaudRate {
    /// Hang up (0 bps).
    B0 = 0,
    /// 50 bps.
    B50 = 1,
    /// 75 bps.
    B75 = 2,
    /// 110 bps.
    B110 = 3,
    /// 134 bps.
    B134 = 4,
    /// 150 bps.
    B150 = 5,
    /// 200 bps.
    B200 = 6,
    /// 300 bps.
    B300 = 7,
    /// 600 bps.
    B600 = 8,
    /// 1200 bps.
    B1200 = 9,
    /// 1800 bps.
    B1800 = 10,
    /// 2400 bps.
    B2400 = 11,
    /// 4800 bps.
    B4800 = 12,
    /// 9600 bps.
    B9600 = 13,
    /// 19200 bps.
    B19200 = 14,
    /// 38400 bps.
    B38400 = 15,
    /// 57600 bps.
    B57600 = 16,
    /// 115200 bps.
    B115200 = 17,
}

impl BaudRate {
    /// Convert a baud rate variant to its numeric speed in bps.
    pub const fn to_speed(self) -> SpeedT {
        match self {
            Self::B0 => 0,
            Self::B50 => 50,
            Self::B75 => 75,
            Self::B110 => 110,
            Self::B134 => 134,
            Self::B150 => 150,
            Self::B200 => 200,
            Self::B300 => 300,
            Self::B600 => 600,
            Self::B1200 => 1200,
            Self::B1800 => 1800,
            Self::B2400 => 2400,
            Self::B4800 => 4800,
            Self::B9600 => 9600,
            Self::B19200 => 19200,
            Self::B38400 => 38400,
            Self::B57600 => 57600,
            Self::B115200 => 115200,
        }
    }

    /// Convert a numeric bps value to a [`BaudRate`] variant.
    ///
    /// Returns `InvalidArgument` if the speed does not match any
    /// standard rate.
    pub const fn from_speed(speed: SpeedT) -> Result<Self> {
        match speed {
            0 => Ok(Self::B0),
            50 => Ok(Self::B50),
            75 => Ok(Self::B75),
            110 => Ok(Self::B110),
            134 => Ok(Self::B134),
            150 => Ok(Self::B150),
            200 => Ok(Self::B200),
            300 => Ok(Self::B300),
            600 => Ok(Self::B600),
            1200 => Ok(Self::B1200),
            1800 => Ok(Self::B1800),
            2400 => Ok(Self::B2400),
            4800 => Ok(Self::B4800),
            9600 => Ok(Self::B9600),
            19200 => Ok(Self::B19200),
            38400 => Ok(Self::B38400),
            57600 => Ok(Self::B57600),
            115200 => Ok(Self::B115200),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── TcSetAction ──────────────────────────────────────────────────

/// Optional actions for [`tcsetattr`].
///
/// Determines when attribute changes take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TcSetAction {
    /// Changes take effect immediately.
    Now = 0,
    /// Changes take effect after all output has been transmitted.
    Drain = 1,
    /// Changes take effect after all output has been transmitted;
    /// all input that has been received but not read is discarded.
    Flush = 2,
}

impl TcSetAction {
    /// Convert a raw integer to a [`TcSetAction`].
    ///
    /// Returns `InvalidArgument` if the value is not 0, 1, or 2.
    pub const fn from_raw(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::Now),
            1 => Ok(Self::Drain),
            2 => Ok(Self::Flush),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── FlushSelector ────────────────────────────────────────────────

/// Queue selector for [`tcflush`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlushSelector {
    /// Flush data received but not read.
    Input = 0,
    /// Flush data written but not transmitted.
    Output = 1,
    /// Flush both input and output queues.
    Both = 2,
}

impl FlushSelector {
    /// Convert a raw integer to a [`FlushSelector`].
    ///
    /// Returns `InvalidArgument` for unrecognised values.
    pub const fn from_raw(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::Input),
            1 => Ok(Self::Output),
            2 => Ok(Self::Both),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── FlowAction ───────────────────────────────────────────────────

/// Action selector for [`tcflow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlowAction {
    /// Suspend output (TCOOFF).
    SuspendOutput = 0,
    /// Resume output (TCOON).
    ResumeOutput = 1,
    /// Transmit STOP character (TCIOFF).
    TransmitStop = 2,
    /// Transmit START character (TCION).
    TransmitStart = 3,
}

impl FlowAction {
    /// Convert a raw integer to a [`FlowAction`].
    ///
    /// Returns `InvalidArgument` for unrecognised values.
    pub const fn from_raw(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::SuspendOutput),
            1 => Ok(Self::ResumeOutput),
            2 => Ok(Self::TransmitStop),
            3 => Ok(Self::TransmitStart),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Termios ──────────────────────────────────────────────────────

/// POSIX `termios` structure.
///
/// Holds the complete set of terminal attributes: input, output,
/// control, and local mode flags, the control character array, and
/// input/output baud rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Termios {
    /// Input mode flags.
    pub c_iflag: TcFlagT,
    /// Output mode flags.
    pub c_oflag: TcFlagT,
    /// Control mode flags.
    pub c_cflag: TcFlagT,
    /// Local mode flags.
    pub c_lflag: TcFlagT,
    /// Control characters.
    pub c_cc: [CcT; NCCS],
    /// Input baud rate.
    pub c_ispeed: SpeedT,
    /// Output baud rate.
    pub c_ospeed: SpeedT,
}

/// Default control characters matching traditional Unix defaults.
const DEFAULT_CC: [CcT; NCCS] = {
    let mut cc = [0u8; NCCS];
    cc[VEOF] = 0x04; // Ctrl-D
    cc[VEOL] = 0x00; // disabled
    cc[VERASE] = 0x7F; // DEL
    cc[VINTR] = 0x03; // Ctrl-C
    cc[VKILL] = 0x15; // Ctrl-U
    cc[VMIN] = 1;
    cc[VQUIT] = 0x1C; // Ctrl-backslash
    cc[VSTART] = 0x11; // Ctrl-Q
    cc[VSTOP] = 0x13; // Ctrl-S
    cc[VSUSP] = 0x1A; // Ctrl-Z
    cc[VTIME] = 0;
    cc
};

impl Termios {
    /// Create a new `Termios` with sensible defaults.
    ///
    /// The defaults mirror a typical Unix interactive terminal:
    /// - Input: `ICRNL | IXON`
    /// - Output: `OPOST | ONLCR`
    /// - Control: `CS8 | CREAD | CLOCAL`
    /// - Local: `ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN`
    /// - Baud: 9600 bps in both directions
    pub const fn new() -> Self {
        Self {
            c_iflag: ICRNL | IXON,
            c_oflag: OPOST | ONLCR,
            c_cflag: CS8 | CREAD | CLOCAL,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN,
            c_cc: DEFAULT_CC,
            c_ispeed: 9600,
            c_ospeed: 9600,
        }
    }

    /// Return `true` if canonical mode (`ICANON`) is enabled.
    pub const fn is_canonical(&self) -> bool {
        self.c_lflag & ICANON != 0
    }

    /// Return `true` if echo (`ECHO`) is enabled.
    pub const fn is_echo(&self) -> bool {
        self.c_lflag & ECHO != 0
    }

    /// Return `true` if signal generation (`ISIG`) is enabled.
    pub const fn is_signal(&self) -> bool {
        self.c_lflag & ISIG != 0
    }

    /// Set the input baud rate.
    ///
    /// Returns `InvalidArgument` if the rate is not a standard
    /// baud rate.
    pub fn set_ispeed(&mut self, rate: BaudRate) -> Result<()> {
        self.c_ispeed = rate.to_speed();
        Ok(())
    }

    /// Set the output baud rate.
    ///
    /// Returns `InvalidArgument` if the rate is not a standard
    /// baud rate.
    pub fn set_ospeed(&mut self, rate: BaudRate) -> Result<()> {
        self.c_ospeed = rate.to_speed();
        Ok(())
    }

    /// Get the input baud rate as a [`BaudRate`].
    pub fn get_ispeed(&self) -> Result<BaudRate> {
        BaudRate::from_speed(self.c_ispeed)
    }

    /// Get the output baud rate as a [`BaudRate`].
    pub fn get_ospeed(&self) -> Result<BaudRate> {
        BaudRate::from_speed(self.c_ospeed)
    }
}

impl Default for Termios {
    fn default() -> Self {
        Self::new()
    }
}

// ── tcgetattr / tcsetattr / tcsendbreak / tcdrain / tcflush / tcflow

/// File descriptor type used by terminal control functions.
pub type Fd = i32;

/// Get the current terminal attributes for file descriptor `fd`.
///
/// This is the POSIX `tcgetattr()` entry point. The actual
/// attribute retrieval depends on the underlying terminal driver;
/// this function signature serves as the syscall interface
/// contract.
///
/// # Errors
///
/// - `IoError` if `fd` does not refer to a terminal.
/// - `InvalidArgument` if `fd` is negative.
pub fn tcgetattr(fd: Fd, termios_out: &mut Termios) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: real implementation will query the tty driver
    // associated with `fd` and populate `termios_out`.
    let _ = termios_out;
    Err(Error::NotImplemented)
}

/// Set the terminal attributes for file descriptor `fd`.
///
/// The `action` parameter controls when the change takes effect
/// (see [`TcSetAction`]).
///
/// # Errors
///
/// - `IoError` if `fd` does not refer to a terminal.
/// - `InvalidArgument` if `fd` is negative or `action` is invalid.
pub fn tcsetattr(fd: Fd, action: TcSetAction, termios_in: &Termios) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (action, termios_in);
    Err(Error::NotImplemented)
}

/// Transmit a continuous stream of zero-valued bits for a
/// specified duration.
///
/// If `duration` is zero, the break lasts between 0.25 and 0.5
/// seconds. A non-zero `duration` is implementation-defined.
///
/// # Errors
///
/// - `IoError` if `fd` does not refer to a terminal.
pub fn tcsendbreak(fd: Fd, duration: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = duration;
    Err(Error::NotImplemented)
}

/// Wait until all output written to `fd` has been transmitted.
///
/// # Errors
///
/// - `IoError` if `fd` does not refer to a terminal.
/// - `Interrupted` if interrupted by a signal.
pub fn tcdrain(fd: Fd) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

/// Discard data written to or received from the terminal
/// referenced by `fd`.
///
/// The `selector` chooses which queue(s) to flush.
///
/// # Errors
///
/// - `IoError` if `fd` does not refer to a terminal.
/// - `InvalidArgument` if `selector` is invalid.
pub fn tcflush(fd: Fd, selector: FlushSelector) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = selector;
    Err(Error::NotImplemented)
}

/// Suspend or restart transmission or reception of data.
///
/// # Errors
///
/// - `IoError` if `fd` does not refer to a terminal.
/// - `InvalidArgument` if `action` is invalid.
pub fn tcflow(fd: Fd, action: FlowAction) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = action;
    Err(Error::NotImplemented)
}

// ── LineEditor ───────────────────────────────────────────────────

/// Maximum canonical-mode line buffer size.
const LINE_BUF_SIZE: usize = 1024;

/// Canonical-mode line editor.
///
/// Buffers input characters until a line delimiter (NL or EOF) is
/// received, supporting ERASE (delete last character) and KILL
/// (delete entire line) editing. The completed line can then be
/// read by the application.
///
/// The editor honours the control characters configured in the
/// associated [`Termios`] structure (specifically `c_cc[VERASE]`,
/// `c_cc[VKILL]`, and `c_cc[VEOF]`).
pub struct LineEditor {
    /// Internal line buffer.
    buf: [u8; LINE_BUF_SIZE],
    /// Number of valid bytes in `buf`.
    len: usize,
    /// Whether the current line is complete (NL or EOF received).
    complete: bool,
    /// Whether EOF was signalled (Ctrl-D on empty line).
    eof: bool,
}

/// Result of processing a single character through the line editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEditResult {
    /// Character was buffered; line is not yet complete.
    Pending,
    /// A complete line is available for reading.
    LineReady,
    /// EOF was signalled on an empty line.
    Eof,
}

impl LineEditor {
    /// Create a new, empty line editor.
    pub const fn new() -> Self {
        Self {
            buf: [0; LINE_BUF_SIZE],
            len: 0,
            complete: false,
            eof: false,
        }
    }

    /// Process a single input character according to the given
    /// terminal attributes.
    ///
    /// Handles ERASE, KILL, EOF, and newline characters as defined
    /// by `termios.c_cc`. All other characters are appended to the
    /// line buffer (if space remains).
    ///
    /// Returns a [`LineEditResult`] indicating whether a complete
    /// line is now available.
    pub fn process_char(&mut self, ch: u8, termios: &Termios) -> LineEditResult {
        let erase = termios.c_cc[VERASE];
        let kill = termios.c_cc[VKILL];
        let eof_char = termios.c_cc[VEOF];

        // ERASE: delete the last character.
        if ch == erase {
            if self.len > 0 {
                self.len -= 1;
            }
            return LineEditResult::Pending;
        }

        // KILL: discard the entire line.
        if ch == kill {
            self.len = 0;
            return LineEditResult::Pending;
        }

        // EOF (typically Ctrl-D): if the buffer is empty, signal
        // EOF; otherwise treat as a line delimiter without storing
        // the character itself.
        if ch == eof_char {
            if self.len == 0 {
                self.eof = true;
                self.complete = true;
                return LineEditResult::Eof;
            }
            self.complete = true;
            return LineEditResult::LineReady;
        }

        // Newline: terminate the line (the NL is included in the
        // buffer so the reader sees it).
        if ch == b'\n' {
            if self.len < LINE_BUF_SIZE {
                self.buf[self.len] = ch;
                self.len += 1;
            }
            self.complete = true;
            return LineEditResult::LineReady;
        }

        // Ordinary character: append if space permits.
        if self.len < LINE_BUF_SIZE {
            self.buf[self.len] = ch;
            self.len += 1;
        }
        LineEditResult::Pending
    }

    /// Read the completed line into `dst`.
    ///
    /// Returns the number of bytes copied. After a successful read
    /// the editor is reset for the next line. Returns `WouldBlock`
    /// if no complete line is available yet.
    pub fn read_line(&mut self, dst: &mut [u8]) -> Result<usize> {
        if !self.complete {
            return Err(Error::WouldBlock);
        }

        let to_copy = self.len.min(dst.len());
        let mut i = 0;
        while i < to_copy {
            dst[i] = self.buf[i];
            i += 1;
        }

        let copied = to_copy;
        self.reset();
        Ok(copied)
    }

    /// Return `true` if a complete line is available.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Return `true` if EOF was signalled.
    pub const fn is_eof(&self) -> bool {
        self.eof
    }

    /// Return the number of bytes currently in the buffer.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the buffer is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reset the editor for a new line.
    pub fn reset(&mut self) {
        self.len = 0;
        self.complete = false;
        self.eof = false;
    }
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for LineEditor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LineEditor")
            .field("len", &self.len)
            .field("complete", &self.complete)
            .field("eof", &self.eof)
            .finish()
    }
}
