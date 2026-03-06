// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TTY line discipline subsystem.
//!
//! Provides the `LdiscOps` trait for implementing TTY line disciplines
//! and an `NTty` (N_TTY) default implementation supporting canonical
//! and raw input modes, local echo, and simple line editing.
//!
//! # Architecture
//!
//! The TTY layer sits between the underlying serial hardware driver and
//! the user-space read/write path.  The line discipline transforms raw
//! character streams into higher-level semantics (line editing, echo,
//! signal generation).
//!
//! # N_TTY behaviour
//!
//! - **Canonical mode**: input buffered until newline; line editing
//!   characters (BS, DEL, ^U) are processed.
//! - **Raw mode**: bytes passed through immediately without processing.
//! - **Echo**: characters echoed back via the `write` path if enabled.

extern crate alloc;
use alloc::vec::Vec;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum line discipline number (N_TTY = 0).
const LDISC_MAX: usize = 16;

/// N_TTY line discipline number.
pub const N_TTY: usize = 0;

/// Canonical input buffer size.
const CANON_BUF_SIZE: usize = 4096;

/// Maximum read chunk.
const MAX_READ: usize = 4096;

// ── Control characters ───────────────────────────────────────────────────────

/// ASCII Backspace (0x08).
const BS: u8 = 0x08;
/// ASCII Delete (0x7F).
const DEL: u8 = 0x7F;
/// ^U — kill entire line.
const CTRL_U: u8 = 0x15;
/// ^C — generate SIGINT.
const CTRL_C: u8 = 0x03;
/// ^D — EOF.
const CTRL_D: u8 = 0x04;
/// Carriage return / newline.
const CR: u8 = b'\r';
/// Newline.
const NL: u8 = b'\n';

// ── TermiosFlags ─────────────────────────────────────────────────────────────

/// Simplified terminal flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct TermiosFlags {
    /// Canonical (line-buffered) mode.
    pub icanon: bool,
    /// Local echo.
    pub echo: bool,
    /// Translate CR to NL on input.
    pub icrnl: bool,
    /// Map NL to CR+NL on output.
    pub onlcr: bool,
    /// Enable signal-generating characters (^C etc.).
    pub isig: bool,
}

// ── LdiscOps ─────────────────────────────────────────────────────────────────

/// TTY line discipline operations.
///
/// Implementors provide the full line discipline lifecycle and data paths.
pub trait LdiscOps {
    /// Open the line discipline on a TTY.
    ///
    /// Called when the discipline is attached (e.g. on `tcsetattr`).
    ///
    /// # Errors
    ///
    /// Return an error to reject the open.
    fn open(&mut self) -> Result<()>;

    /// Close the line discipline.
    fn close(&mut self);

    /// Read up to `buf.len()` bytes of processed input into `buf`.
    ///
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Return [`Error::WouldBlock`] if no data is available and
    /// `O_NONBLOCK` is in effect.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Write `buf` bytes through the line discipline to the hardware.
    ///
    /// Applies output processing (e.g. CR→NL translation).
    ///
    /// # Errors
    ///
    /// Propagates hardware write errors.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Process bytes received from the hardware (RX interrupt path).
    ///
    /// Called with raw bytes from the UART/serial driver.  The
    /// discipline performs input processing and buffers the result.
    fn receive_buf(&mut self, buf: &[u8]);

    /// Called when the hardware TX buffer is drained.
    ///
    /// May be used to flush pending echo data.
    fn write_wakeup(&mut self);

    /// Handle a TTY ioctl command.
    ///
    /// # Errors
    ///
    /// Return [`Error::NotImplemented`] for unknown commands.
    fn ioctl(&mut self, cmd: u32, arg: usize) -> Result<usize>;
}

// ── NTty ─────────────────────────────────────────────────────────────────────

/// N_TTY default line discipline.
pub struct NTty {
    /// Terminal flags.
    pub flags: TermiosFlags,
    /// Canonical input buffer.
    read_buf: Vec<u8>,
    /// Number of complete lines in `read_buf`.
    line_count: usize,
    /// Echo buffer (pending echo bytes for the TX path).
    echo_buf: Vec<u8>,
    /// Hardware write callback (injected at construction).
    hw_write: Option<fn(buf: &[u8]) -> Result<usize>>,
    /// Whether the discipline is open.
    opened: bool,
}

impl NTty {
    /// Create a new N_TTY discipline.
    pub fn new() -> Self {
        Self {
            flags: TermiosFlags {
                icanon: true,
                echo: true,
                icrnl: true,
                onlcr: true,
                isig: true,
            },
            read_buf: Vec::new(),
            line_count: 0,
            echo_buf: Vec::new(),
            hw_write: None,
            opened: false,
        }
    }

    /// Set the hardware write callback.
    ///
    /// The callback is called when echo data or user writes need to be
    /// pushed to the underlying hardware.
    pub fn set_hw_write(&mut self, cb: fn(buf: &[u8]) -> Result<usize>) {
        self.hw_write = Some(cb);
    }

    /// Return whether any complete lines are available for reading.
    pub fn has_data(&self) -> bool {
        if self.flags.icanon {
            self.line_count > 0
        } else {
            !self.read_buf.is_empty()
        }
    }

    /// Process a single received character.
    fn process_char(&mut self, c: u8) {
        if self.flags.icrnl && c == CR {
            let nl = NL;
            self.process_char(nl);
            return;
        }

        if self.flags.icanon {
            match c {
                BS | DEL => {
                    // Erase last character.
                    if !self.read_buf.is_empty() {
                        self.read_buf.pop();
                        if self.flags.echo {
                            self.echo_buf.extend_from_slice(b"\x08 \x08");
                        }
                    }
                    return;
                }
                CTRL_U => {
                    // Kill line.
                    self.read_buf.clear();
                    if self.flags.echo {
                        self.echo_buf.push(b'\n');
                    }
                    return;
                }
                CTRL_C if self.flags.isig => {
                    // Signal pending — in a real system this would deliver SIGINT.
                    if self.flags.echo {
                        self.echo_buf.extend_from_slice(b"^C\n");
                    }
                    return;
                }
                CTRL_D => {
                    // EOF — push an empty "line".
                    self.line_count += 1;
                    return;
                }
                NL => {
                    self.read_buf.push(NL);
                    self.line_count += 1;
                    if self.flags.echo {
                        self.echo_buf.push(NL);
                        if self.flags.onlcr {
                            self.echo_buf.insert(self.echo_buf.len() - 1, CR);
                        }
                    }
                    return;
                }
                _ => {}
            }
        }

        if self.read_buf.len() < CANON_BUF_SIZE {
            self.read_buf.push(c);
        }
        if self.flags.echo {
            self.echo_buf.push(c);
        }
        if !self.flags.icanon {
            // Raw mode: every byte is immediately available.
        }
    }

    /// Flush all pending echo bytes to the hardware.
    fn flush_echo(&mut self) {
        if self.echo_buf.is_empty() {
            return;
        }
        if let Some(cb) = self.hw_write {
            let _ = cb(&self.echo_buf);
        }
        self.echo_buf.clear();
    }
}

impl Default for NTty {
    fn default() -> Self {
        Self::new()
    }
}

impl LdiscOps for NTty {
    fn open(&mut self) -> Result<()> {
        self.opened = true;
        self.read_buf.clear();
        self.echo_buf.clear();
        self.line_count = 0;
        Ok(())
    }

    fn close(&mut self) {
        self.opened = false;
        self.read_buf.clear();
        self.echo_buf.clear();
        self.line_count = 0;
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.opened {
            return Err(Error::InvalidArgument);
        }
        if self.flags.icanon {
            if self.line_count == 0 {
                return Err(Error::WouldBlock);
            }
            // Find the first newline and return up to (and including) it.
            let nl_pos = self
                .read_buf
                .iter()
                .position(|&b| b == NL)
                .map(|p| p + 1)
                .unwrap_or(self.read_buf.len());
            let to_copy = nl_pos.min(buf.len());
            buf[..to_copy].copy_from_slice(&self.read_buf[..to_copy]);
            self.read_buf.drain(..to_copy);
            if to_copy > 0 && self.line_count > 0 {
                self.line_count -= 1;
            }
            Ok(to_copy)
        } else {
            if self.read_buf.is_empty() {
                return Err(Error::WouldBlock);
            }
            let to_copy = buf.len().min(self.read_buf.len()).min(MAX_READ);
            buf[..to_copy].copy_from_slice(&self.read_buf[..to_copy]);
            self.read_buf.drain(..to_copy);
            Ok(to_copy)
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.opened {
            return Err(Error::InvalidArgument);
        }
        // Apply output processing: NL → CR+NL if onlcr.
        if self.flags.onlcr {
            let mut processed = Vec::with_capacity(buf.len() * 2);
            for &b in buf {
                if b == NL {
                    processed.push(CR);
                }
                processed.push(b);
            }
            if let Some(cb) = self.hw_write {
                cb(&processed)?;
            }
        } else if let Some(cb) = self.hw_write {
            cb(buf)?;
        }
        Ok(buf.len())
    }

    fn receive_buf(&mut self, buf: &[u8]) {
        for &c in buf {
            self.process_char(c);
        }
        self.flush_echo();
    }

    fn write_wakeup(&mut self) {
        self.flush_echo();
    }

    fn ioctl(&mut self, _cmd: u32, _arg: usize) -> Result<usize> {
        Err(Error::NotImplemented)
    }
}

// ── LdiscRegistry ─────────────────────────────────────────────────────────────

/// Line discipline factory function type.
pub type LdiscFactory = fn() -> alloc::boxed::Box<dyn LdiscOps>;

/// Registry mapping discipline numbers to factory functions.
pub struct LdiscRegistry {
    entries: [Option<LdiscFactory>; LDISC_MAX],
}

impl LdiscRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; LDISC_MAX],
        }
    }

    /// Register a line discipline factory at `n`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `n >= LDISC_MAX` or
    /// [`Error::AlreadyExists`] if the slot is already occupied.
    pub fn register(&mut self, n: usize, factory: LdiscFactory) -> Result<()> {
        if n >= LDISC_MAX {
            return Err(Error::InvalidArgument);
        }
        if self.entries[n].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.entries[n] = Some(factory);
        Ok(())
    }

    /// Deregister a line discipline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn deregister(&mut self, n: usize) -> Result<()> {
        if n >= LDISC_MAX || self.entries[n].is_none() {
            return Err(Error::NotFound);
        }
        self.entries[n] = None;
        Ok(())
    }

    /// Create an instance of line discipline `n`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn instantiate(&self, n: usize) -> Result<alloc::boxed::Box<dyn LdiscOps>> {
        let factory = self
            .entries
            .get(n)
            .and_then(|e| *e)
            .ok_or(Error::NotFound)?;
        Ok(factory())
    }
}

impl Default for LdiscRegistry {
    fn default() -> Self {
        Self::new()
    }
}
