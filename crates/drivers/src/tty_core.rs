// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TTY core subsystem for the ONCRIX operating system.
//!
//! Provides the terminal device infrastructure including tty_struct,
//! tty_driver, N_TTY line discipline with canonical and raw modes,
//! open/close/read/write/ioctl operations, flip buffers for interrupt-
//! to-process data transfer, echo handling, special character processing,
//! tty_port abstraction, and hangup signalling.
//!
//! # Architecture
//!
//! - **TtyMode** — canonical (cooked) vs raw input mode
//! - **TtySpecialChar** — special control character definitions
//! - **TtyFlipBuffer** — double-buffered interrupt-to-process transfer
//! - **TtyLineDiscipline** — N_TTY line discipline state
//! - **TtyPort** — hardware port abstraction
//! - **TtyStruct** — per-open TTY instance state
//! - **TtyDriver** — driver managing a set of TTY devices
//! - **TtyRegistry** — manages multiple TTY drivers
//!
//! Reference: Linux `drivers/tty/tty_io.c`, `include/linux/tty.h`,
//! `drivers/tty/n_tty.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum TTY drivers in the registry.
const MAX_DRIVERS: usize = 8;

/// Maximum TTY devices per driver.
const MAX_DEVICES: usize = 16;

/// Size of the input (read) buffer in bytes.
const INPUT_BUF_SIZE: usize = 4096;

/// Size of the flip buffer in bytes.
const FLIP_BUF_SIZE: usize = 512;

/// Size of the output (write) buffer in bytes.
const OUTPUT_BUF_SIZE: usize = 4096;

/// Size of the echo buffer.
const ECHO_BUF_SIZE: usize = 256;

/// Maximum line length for canonical mode.
const MAX_CANON: usize = 255;

// ---------------------------------------------------------------------------
// Special characters
// ---------------------------------------------------------------------------

/// End-of-file character (Ctrl-D).
const CHAR_EOF: u8 = 0x04;

/// End-of-line character (newline).
const CHAR_EOL: u8 = b'\n';

/// Erase character (backspace / Ctrl-H).
const CHAR_ERASE: u8 = 0x7F;

/// Kill (line erase) character (Ctrl-U).
const CHAR_KILL: u8 = 0x15;

/// Interrupt character (Ctrl-C).
const CHAR_INTR: u8 = 0x03;

/// Quit character (Ctrl-\\).
const CHAR_QUIT: u8 = 0x1C;

/// Suspend character (Ctrl-Z).
const CHAR_SUSP: u8 = 0x1A;

/// Start output character (Ctrl-Q).
const _CHAR_START: u8 = 0x11;

/// Stop output character (Ctrl-S).
const _CHAR_STOP: u8 = 0x13;

/// Carriage return.
const CHAR_CR: u8 = b'\r';

// ---------------------------------------------------------------------------
// TtyMode
// ---------------------------------------------------------------------------

/// TTY input processing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TtyMode {
    /// Canonical (cooked) mode: line-buffered with editing.
    #[default]
    Canonical,
    /// Raw mode: character-at-a-time, no processing.
    Raw,
    /// CBreak mode: character-at-a-time, signals processed.
    CBreak,
}

// ---------------------------------------------------------------------------
// TtySpecialChar
// ---------------------------------------------------------------------------

/// Special control character configuration for a TTY.
#[derive(Debug, Clone, Copy)]
pub struct TtySpecialChar {
    /// End-of-file character.
    pub eof: u8,
    /// End-of-line character.
    pub eol: u8,
    /// Erase (backspace) character.
    pub erase: u8,
    /// Kill (line erase) character.
    pub kill: u8,
    /// Interrupt character.
    pub intr: u8,
    /// Quit character.
    pub quit: u8,
    /// Suspend character.
    pub susp: u8,
}

impl Default for TtySpecialChar {
    fn default() -> Self {
        Self {
            eof: CHAR_EOF,
            eol: CHAR_EOL,
            erase: CHAR_ERASE,
            kill: CHAR_KILL,
            intr: CHAR_INTR,
            quit: CHAR_QUIT,
            susp: CHAR_SUSP,
        }
    }
}

// ---------------------------------------------------------------------------
// TtyFlipBuffer
// ---------------------------------------------------------------------------

/// Double-buffered flip buffer for interrupt-to-process data transfer.
///
/// The hardware interrupt handler writes into the active buffer, then
/// flips. The process reader consumes from the inactive buffer.
pub struct TtyFlipBuffer {
    /// Double buffer storage.
    bufs: [[u8; FLIP_BUF_SIZE]; 2],
    /// Number of valid bytes in each buffer.
    lens: [usize; 2],
    /// Index of the active (write) buffer (0 or 1).
    active: usize,
}

impl TtyFlipBuffer {
    /// Creates a new empty flip buffer.
    pub const fn new() -> Self {
        Self {
            bufs: [[0u8; FLIP_BUF_SIZE]; 2],
            lens: [0; 2],
            active: 0,
        }
    }

    /// Pushes a byte into the active buffer.
    ///
    /// Returns `false` if the active buffer is full.
    pub fn push(&mut self, byte: u8) -> bool {
        let idx = self.active;
        if self.lens[idx] >= FLIP_BUF_SIZE {
            return false;
        }
        self.bufs[idx][self.lens[idx]] = byte;
        self.lens[idx] += 1;
        true
    }

    /// Pushes a slice of bytes into the active buffer.
    ///
    /// Returns the number of bytes actually pushed.
    pub fn push_slice(&mut self, data: &[u8]) -> usize {
        let idx = self.active;
        let avail = FLIP_BUF_SIZE - self.lens[idx];
        let count = data.len().min(avail);
        let start = self.lens[idx];
        self.bufs[idx][start..start + count].copy_from_slice(&data[..count]);
        self.lens[idx] += count;
        count
    }

    /// Flips the active buffer, making the current one available
    /// for reading.
    pub fn flip(&mut self) {
        self.active ^= 1;
        self.lens[self.active] = 0;
    }

    /// Returns the inactive (readable) buffer contents.
    pub fn readable(&self) -> &[u8] {
        let idx = self.active ^ 1;
        &self.bufs[idx][..self.lens[idx]]
    }

    /// Clears the inactive buffer after reading.
    pub fn clear_readable(&mut self) {
        let idx = self.active ^ 1;
        self.lens[idx] = 0;
    }
}

// ---------------------------------------------------------------------------
// TtyLineDiscipline
// ---------------------------------------------------------------------------

/// N_TTY line discipline state.
///
/// Implements canonical (cooked) mode line editing and raw mode
/// pass-through. Handles echo, special character processing, and
/// line buffering.
pub struct TtyLineDiscipline {
    /// Current input mode.
    pub mode: TtyMode,
    /// Special character definitions.
    pub special: TtySpecialChar,
    /// Input (read) ring buffer.
    input_buf: [u8; INPUT_BUF_SIZE],
    /// Number of valid bytes in the input buffer.
    input_len: usize,
    /// Current canonical line being edited.
    canon_buf: [u8; MAX_CANON],
    /// Length of current canonical line.
    canon_len: usize,
    /// Whether a complete line is ready to be read.
    canon_ready: bool,
    /// Echo buffer for characters to echo back.
    echo_buf: [u8; ECHO_BUF_SIZE],
    /// Number of bytes pending in echo buffer.
    echo_len: usize,
    /// Whether echo is enabled.
    pub echo_enabled: bool,
    /// Whether ICRNL (CR to NL) is enabled.
    pub icrnl: bool,
    /// Whether ISIG (signal characters) is enabled.
    pub isig: bool,
    /// Pending signal (0 = none, CHAR_INTR, CHAR_QUIT, CHAR_SUSP).
    pub pending_signal: u8,
}

impl TtyLineDiscipline {
    /// Creates a new N_TTY line discipline in canonical mode.
    pub const fn new() -> Self {
        Self {
            mode: TtyMode::Canonical,
            special: TtySpecialChar {
                eof: CHAR_EOF,
                eol: CHAR_EOL,
                erase: CHAR_ERASE,
                kill: CHAR_KILL,
                intr: CHAR_INTR,
                quit: CHAR_QUIT,
                susp: CHAR_SUSP,
            },
            input_buf: [0u8; INPUT_BUF_SIZE],
            input_len: 0,
            canon_buf: [0u8; MAX_CANON],
            canon_len: 0,
            canon_ready: false,
            echo_buf: [0u8; ECHO_BUF_SIZE],
            echo_len: 0,
            echo_enabled: true,
            icrnl: true,
            isig: true,
            pending_signal: 0,
        }
    }

    /// Processes a received character through the line discipline.
    ///
    /// In canonical mode, characters are buffered until a line
    /// delimiter is received. In raw mode, characters are passed
    /// through directly.
    pub fn receive_char(&mut self, ch: u8) {
        // CR-to-NL translation
        let ch = if self.icrnl && ch == CHAR_CR {
            CHAR_EOL
        } else {
            ch
        };

        // Signal character handling
        if self.isig {
            if ch == self.special.intr || ch == self.special.quit || ch == self.special.susp {
                self.pending_signal = ch;
                // Flush current line in canonical mode
                if self.mode == TtyMode::Canonical {
                    self.canon_len = 0;
                    self.canon_ready = false;
                }
                return;
            }
        }

        match self.mode {
            TtyMode::Canonical => self.receive_canonical(ch),
            TtyMode::Raw | TtyMode::CBreak => self.receive_raw(ch),
        }
    }

    /// Processes a character in canonical mode.
    fn receive_canonical(&mut self, ch: u8) {
        if ch == self.special.erase {
            // Backspace: remove last character
            if self.canon_len > 0 {
                self.canon_len -= 1;
                if self.echo_enabled {
                    self.echo_erase();
                }
            }
            return;
        }

        if ch == self.special.kill {
            // Kill: erase entire line
            if self.echo_enabled {
                for _ in 0..self.canon_len {
                    self.echo_erase();
                }
            }
            self.canon_len = 0;
            return;
        }

        if ch == self.special.eof {
            // EOF: signal end-of-file, make empty line available
            self.canon_ready = true;
            return;
        }

        // Add character to canonical buffer
        if self.canon_len < MAX_CANON {
            self.canon_buf[self.canon_len] = ch;
            self.canon_len += 1;

            if self.echo_enabled {
                self.echo_char(ch);
            }
        }

        // Check for line delimiter
        if ch == self.special.eol {
            // Complete line: copy to input buffer
            let copy_len = self.canon_len.min(INPUT_BUF_SIZE - self.input_len);
            let dst_start = self.input_len;
            self.input_buf[dst_start..dst_start + copy_len]
                .copy_from_slice(&self.canon_buf[..copy_len]);
            self.input_len += copy_len;
            self.canon_len = 0;
            self.canon_ready = true;
        }
    }

    /// Processes a character in raw mode.
    fn receive_raw(&mut self, ch: u8) {
        if self.input_len < INPUT_BUF_SIZE {
            self.input_buf[self.input_len] = ch;
            self.input_len += 1;
        }
        if self.echo_enabled {
            self.echo_char(ch);
        }
    }

    /// Adds a character to the echo buffer.
    fn echo_char(&mut self, ch: u8) {
        if self.echo_len < ECHO_BUF_SIZE {
            self.echo_buf[self.echo_len] = ch;
            self.echo_len += 1;
        }
    }

    /// Adds a backspace-space-backspace sequence to the echo buffer.
    fn echo_erase(&mut self) {
        if self.echo_len + 3 <= ECHO_BUF_SIZE {
            self.echo_buf[self.echo_len] = 0x08; // BS
            self.echo_buf[self.echo_len + 1] = b' ';
            self.echo_buf[self.echo_len + 2] = 0x08; // BS
            self.echo_len += 3;
        }
    }

    /// Reads processed input into the user buffer.
    ///
    /// In canonical mode, returns data only when a complete line is
    /// available. In raw mode, returns any available data.
    ///
    /// Returns the number of bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        match self.mode {
            TtyMode::Canonical => {
                if !self.canon_ready {
                    return 0;
                }
                let count = self.input_len.min(buf.len());
                buf[..count].copy_from_slice(&self.input_buf[..count]);
                // Shift remaining data
                let remaining = self.input_len - count;
                for i in 0..remaining {
                    self.input_buf[i] = self.input_buf[count + i];
                }
                self.input_len = remaining;
                if self.input_len == 0 {
                    self.canon_ready = false;
                }
                count
            }
            TtyMode::Raw | TtyMode::CBreak => {
                let count = self.input_len.min(buf.len());
                buf[..count].copy_from_slice(&self.input_buf[..count]);
                let remaining = self.input_len - count;
                for i in 0..remaining {
                    self.input_buf[i] = self.input_buf[count + i];
                }
                self.input_len = remaining;
                count
            }
        }
    }

    /// Returns echo data to be written back to the terminal.
    ///
    /// Returns the number of bytes copied.
    pub fn drain_echo(&mut self, buf: &mut [u8]) -> usize {
        let count = self.echo_len.min(buf.len());
        buf[..count].copy_from_slice(&self.echo_buf[..count]);
        let remaining = self.echo_len - count;
        for i in 0..remaining {
            self.echo_buf[i] = self.echo_buf[count + i];
        }
        self.echo_len = remaining;
        count
    }

    /// Returns the number of bytes available for reading.
    pub fn available(&self) -> usize {
        match self.mode {
            TtyMode::Canonical => {
                if self.canon_ready {
                    self.input_len
                } else {
                    0
                }
            }
            TtyMode::Raw | TtyMode::CBreak => self.input_len,
        }
    }

    /// Sets the input mode.
    pub fn set_mode(&mut self, mode: TtyMode) {
        self.mode = mode;
        // Flush canonical state when switching to raw
        if mode != TtyMode::Canonical {
            self.canon_len = 0;
            self.canon_ready = false;
        }
    }
}

// ---------------------------------------------------------------------------
// TtyPortState
// ---------------------------------------------------------------------------

/// State of a TTY hardware port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TtyPortState {
    /// Port is not initialised.
    #[default]
    Uninitialised,
    /// Port is initialised but not open.
    Initialised,
    /// Port is open and active.
    Active,
    /// Port has been hung up.
    HungUp,
}

// ---------------------------------------------------------------------------
// TtyPort
// ---------------------------------------------------------------------------

/// Hardware port abstraction for a TTY device.
///
/// Tracks the port state, open count, and hardware parameters
/// (baud rate, data bits, parity, stop bits).
#[derive(Debug, Clone, Copy)]
pub struct TtyPort {
    /// Port index.
    pub index: u32,
    /// Current port state.
    pub state: TtyPortState,
    /// Number of times this port is open.
    pub open_count: u32,
    /// Baud rate.
    pub baud_rate: u32,
    /// Data bits (5, 6, 7, or 8).
    pub data_bits: u8,
    /// Parity: 0=none, 1=odd, 2=even.
    pub parity: u8,
    /// Stop bits (1 or 2).
    pub stop_bits: u8,
}

/// Constant empty port for array initialisation.
const EMPTY_PORT: TtyPort = TtyPort {
    index: 0,
    state: TtyPortState::Uninitialised,
    open_count: 0,
    baud_rate: 115200,
    data_bits: 8,
    parity: 0,
    stop_bits: 1,
};

impl TtyPort {
    /// Creates a new port with default serial parameters.
    pub fn new(index: u32) -> Self {
        TtyPort {
            index,
            state: TtyPortState::Initialised,
            ..EMPTY_PORT
        }
    }

    /// Opens the port, incrementing the open count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the port is hung up.
    pub fn open(&mut self) -> Result<()> {
        if self.state == TtyPortState::HungUp {
            return Err(Error::IoError);
        }
        self.state = TtyPortState::Active;
        self.open_count = self.open_count.saturating_add(1);
        Ok(())
    }

    /// Closes the port, decrementing the open count.
    pub fn close(&mut self) {
        self.open_count = self.open_count.saturating_sub(1);
        if self.open_count == 0 {
            self.state = TtyPortState::Initialised;
        }
    }

    /// Signals a hangup on this port.
    pub fn hangup(&mut self) {
        self.state = TtyPortState::HungUp;
        self.open_count = 0;
    }

    /// Sets the baud rate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the baud rate is zero.
    pub fn set_baud_rate(&mut self, rate: u32) -> Result<()> {
        if rate == 0 {
            return Err(Error::InvalidArgument);
        }
        self.baud_rate = rate;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TtyStruct
// ---------------------------------------------------------------------------

/// Per-open TTY instance state.
///
/// Contains the line discipline, flip buffer, output buffer,
/// port reference, and device identification.
pub struct TtyStruct {
    /// Device index within the driver.
    pub index: u32,
    /// Line discipline.
    pub ldisc: TtyLineDiscipline,
    /// Flip buffer for interrupt-to-process transfer.
    pub flip: TtyFlipBuffer,
    /// Output buffer.
    output_buf: [u8; OUTPUT_BUF_SIZE],
    /// Number of valid bytes in the output buffer.
    output_len: usize,
    /// Port state.
    pub port: TtyPort,
    /// Whether the device is open.
    pub opened: bool,
    /// Whether the device is hung up.
    pub hung_up: bool,
}

impl TtyStruct {
    /// Creates a new TTY instance.
    pub fn new(index: u32) -> Self {
        Self {
            index,
            ldisc: TtyLineDiscipline::new(),
            flip: TtyFlipBuffer::new(),
            output_buf: [0u8; OUTPUT_BUF_SIZE],
            output_len: 0,
            port: TtyPort::new(index),
            opened: false,
            hung_up: false,
        }
    }

    /// Opens the TTY device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already open, or [`Error::IoError`]
    /// if the port is hung up.
    pub fn open(&mut self) -> Result<()> {
        if self.opened {
            return Err(Error::Busy);
        }
        if self.hung_up {
            return Err(Error::IoError);
        }
        self.port.open()?;
        self.opened = true;
        Ok(())
    }

    /// Closes the TTY device.
    pub fn close(&mut self) {
        self.port.close();
        self.opened = false;
    }

    /// Reads from the TTY into the user buffer.
    ///
    /// Data flows: flip buffer -> line discipline -> user buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is hung up, or
    /// [`Error::WouldBlock`] if no data is available.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.hung_up {
            return Err(Error::IoError);
        }

        // First, transfer flip buffer data to ldisc
        let flip_data = self.flip.readable();
        for &byte in flip_data {
            self.ldisc.receive_char(byte);
        }
        self.flip.clear_readable();

        // Read from line discipline
        let count = self.ldisc.read(buf);
        if count == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(count)
    }

    /// Writes to the TTY output buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is hung up, or
    /// [`Error::WouldBlock`] if the output buffer is full.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.hung_up {
            return Err(Error::IoError);
        }
        let avail = OUTPUT_BUF_SIZE - self.output_len;
        if avail == 0 {
            return Err(Error::WouldBlock);
        }
        let count = data.len().min(avail);
        let start = self.output_len;
        self.output_buf[start..start + count].copy_from_slice(&data[..count]);
        self.output_len += count;
        Ok(count)
    }

    /// Drains the output buffer, returning the data to send to hardware.
    ///
    /// Returns the number of bytes copied.
    pub fn drain_output(&mut self, buf: &mut [u8]) -> usize {
        let count = self.output_len.min(buf.len());
        buf[..count].copy_from_slice(&self.output_buf[..count]);
        let remaining = self.output_len - count;
        for i in 0..remaining {
            self.output_buf[i] = self.output_buf[count + i];
        }
        self.output_len = remaining;
        count
    }

    /// Signals a hangup on this TTY.
    pub fn hangup(&mut self) {
        self.hung_up = true;
        self.port.hangup();
    }
}

// ---------------------------------------------------------------------------
// TtyDriver
// ---------------------------------------------------------------------------

/// A TTY driver managing a set of TTY device instances.
pub struct TtyDriver {
    /// Driver identifier.
    pub id: u32,
    /// Driver name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in name.
    pub name_len: usize,
    /// Device name prefix (e.g., "ttyS" for serial).
    pub dev_prefix: [u8; 16],
    /// Number of valid bytes in dev_prefix.
    pub prefix_len: usize,
    /// Major device number.
    pub major: u32,
    /// Minor device number base.
    pub minor_start: u32,
    /// TTY device instances.
    devices: [Option<TtyStruct>; MAX_DEVICES],
    /// Number of registered devices.
    pub device_count: usize,
}

impl TtyDriver {
    /// Creates a new TTY driver.
    pub fn new(id: u32, name: &[u8], prefix: &[u8], major: u32) -> Self {
        let name_len = name.len().min(32);
        let mut name_buf = [0u8; 32];
        name_buf[..name_len].copy_from_slice(&name[..name_len]);

        let prefix_len = prefix.len().min(16);
        let mut prefix_buf = [0u8; 16];
        prefix_buf[..prefix_len].copy_from_slice(&prefix[..prefix_len]);

        Self {
            id,
            name: name_buf,
            name_len,
            dev_prefix: prefix_buf,
            prefix_len,
            major,
            minor_start: 0,
            devices: [const { None }; MAX_DEVICES],
            device_count: 0,
        }
    }

    /// Registers a TTY device with the driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all device slots are used, or
    /// [`Error::AlreadyExists`] if the index is taken.
    pub fn register_device(&mut self, index: u32) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.index == index {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(TtyStruct::new(index));
                self.device_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a TTY device by index.
    pub fn get_device(&self, index: u32) -> Result<&TtyStruct> {
        for slot in self.devices.iter().flatten() {
            if slot.index == index {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a TTY device by index.
    pub fn get_device_mut(&mut self, index: u32) -> Result<&mut TtyStruct> {
        for slot in self.devices.iter_mut() {
            if let Some(dev) = slot {
                if dev.index == index {
                    return Ok(dev);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Opens a TTY device by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device is not registered.
    pub fn open(&mut self, index: u32) -> Result<()> {
        let dev = self.get_device_mut(index)?;
        dev.open()
    }

    /// Closes a TTY device by index.
    pub fn close(&mut self, index: u32) -> Result<()> {
        let dev = self.get_device_mut(index)?;
        dev.close();
        Ok(())
    }

    /// Hangs up all devices in this driver.
    pub fn hangup_all(&mut self) {
        for slot in self.devices.iter_mut().flatten() {
            slot.hangup();
        }
    }
}

// ---------------------------------------------------------------------------
// TtyRegistry
// ---------------------------------------------------------------------------

/// Registry managing multiple TTY drivers.
pub struct TtyRegistry {
    /// Registered TTY drivers.
    drivers: [Option<TtyDriver>; MAX_DRIVERS],
    /// Number of registered drivers.
    count: usize,
}

impl TtyRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            drivers: [const { None }; MAX_DRIVERS],
            count: 0,
        }
    }

    /// Registers a TTY driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a driver with the same ID exists.
    pub fn register(&mut self, driver: TtyDriver) -> Result<()> {
        for slot in self.drivers.iter().flatten() {
            if slot.id == driver.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.drivers.iter_mut() {
            if slot.is_none() {
                *slot = Some(driver);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a driver by ID.
    pub fn get(&self, driver_id: u32) -> Result<&TtyDriver> {
        for slot in self.drivers.iter().flatten() {
            if slot.id == driver_id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a driver by ID.
    pub fn get_mut(&mut self, driver_id: u32) -> Result<&mut TtyDriver> {
        for slot in self.drivers.iter_mut() {
            if let Some(d) = slot {
                if d.id == driver_id {
                    return Ok(d);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered drivers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no drivers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
