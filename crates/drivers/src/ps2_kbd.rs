// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PS/2 keyboard controller driver.
//!
//! Manages the Intel 8042-compatible PS/2 keyboard controller, handling
//! scancode set 2 translation, key repeat configuration, and keyboard
//! LED control. This driver communicates with the keyboard controller
//! via x86 I/O ports 0x60 (data) and 0x64 (command/status).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐  scancode  ┌─────────────┐  IRQ 1  ┌───────────┐
//! │ Keyboard │───────────>│ 8042 / PS2  │────────>│  CPU      │
//! └──────────┘            │ Controller  │         └───────────┘
//!                         └─────────────┘
//! ```
//!
//! The PS/2 controller uses two I/O ports:
//! - **Port 0x60** — data port (read scancode, write commands to device).
//! - **Port 0x64** — status/command port (read status, write controller cmd).
//!
//! # Scancode Sets
//!
//! This driver works with scancode set 2 (the default set used by most
//! PS/2 keyboards). Extended keys are prefixed with 0xE0. Break codes
//! are prefixed with 0xF0.
//!
//! Reference: IBM Technical Reference — Keyboard/Auxiliary Device
//! Controller (8042); PS/2 System Reference.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O port addresses
// ---------------------------------------------------------------------------

/// PS/2 data port (read: scancode, write: device command).
const PS2_DATA_PORT: u16 = 0x60;

/// PS/2 status/command port (read: status, write: controller command).
const PS2_CMD_PORT: u16 = 0x64;

// ---------------------------------------------------------------------------
// Status register bits (port 0x64 read)
// ---------------------------------------------------------------------------

/// Status bit 0: Output Buffer Full — data available to read from 0x60.
const STATUS_OBF: u8 = 1 << 0;

/// Status bit 1: Input Buffer Full — controller busy, do not write.
const STATUS_IBF: u8 = 1 << 1;

/// Status bit 2: System Flag — set after self-test pass.
const _STATUS_SYS: u8 = 1 << 2;

/// Status bit 3: Command/Data — 0 = data written to 0x60, 1 = command.
const _STATUS_CMD: u8 = 1 << 3;

/// Status bit 5: Auxiliary output buffer full (mouse data).
const STATUS_AUX: u8 = 1 << 5;

/// Status bit 6: Timeout error.
const _STATUS_TIMEOUT: u8 = 1 << 6;

/// Status bit 7: Parity error.
const _STATUS_PARITY: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Controller commands (write to port 0x64)
// ---------------------------------------------------------------------------

/// Read controller configuration byte.
const CMD_READ_CONFIG: u8 = 0x20;

/// Write controller configuration byte.
const CMD_WRITE_CONFIG: u8 = 0x60;

/// Disable second PS/2 port (mouse).
const CMD_DISABLE_PORT2: u8 = 0xA7;

/// Enable second PS/2 port (mouse).
const _CMD_ENABLE_PORT2: u8 = 0xA8;

/// Test second PS/2 port.
const _CMD_TEST_PORT2: u8 = 0xA9;

/// Controller self-test (result: 0x55 = pass).
const CMD_SELF_TEST: u8 = 0xAA;

/// Test first PS/2 port (result: 0x00 = pass).
const CMD_TEST_PORT1: u8 = 0xAB;

/// Disable first PS/2 port.
const CMD_DISABLE_PORT1: u8 = 0xAD;

/// Enable first PS/2 port.
const CMD_ENABLE_PORT1: u8 = 0xAE;

// ---------------------------------------------------------------------------
// Device commands (write to port 0x60)
// ---------------------------------------------------------------------------

/// Set keyboard LEDs (followed by LED bitmask byte).
const DEV_CMD_SET_LEDS: u8 = 0xED;

/// Set scancode set (followed by set number: 1, 2, or 3).
const DEV_CMD_SET_SCANCODE: u8 = 0xF0;

/// Set typematic rate/delay (followed by rate byte).
const DEV_CMD_SET_TYPEMATIC: u8 = 0xF3;

/// Enable keyboard scanning.
const DEV_CMD_ENABLE_SCAN: u8 = 0xF4;

/// Disable keyboard scanning.
const DEV_CMD_DISABLE_SCAN: u8 = 0xF5;

/// Reset keyboard (self-test).
const DEV_CMD_RESET: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Device responses
// ---------------------------------------------------------------------------

/// Acknowledge — device accepted the command.
const DEV_ACK: u8 = 0xFA;

/// Resend — device wants the last command re-sent.
const _DEV_RESEND: u8 = 0xFE;

/// Self-test passed (after reset).
const DEV_SELF_TEST_OK: u8 = 0xAA;

/// Controller self-test passed.
const CTRL_SELF_TEST_OK: u8 = 0x55;

// ---------------------------------------------------------------------------
// Configuration byte bits
// ---------------------------------------------------------------------------

/// Bit 0: Port 1 interrupt enable.
const CFG_PORT1_IRQ: u8 = 1 << 0;

/// Bit 1: Port 2 interrupt enable.
const _CFG_PORT2_IRQ: u8 = 1 << 1;

/// Bit 4: Port 1 clock disable.
const CFG_PORT1_CLOCK_DISABLE: u8 = 1 << 4;

/// Bit 5: Port 2 clock disable.
const _CFG_PORT2_CLOCK_DISABLE: u8 = 1 << 5;

/// Bit 6: Port 1 translation (scancode set 1 translation).
const CFG_TRANSLATION: u8 = 1 << 6;

// ---------------------------------------------------------------------------
// LED bitmask
// ---------------------------------------------------------------------------

/// LED bit: Scroll Lock.
const LED_SCROLL_LOCK: u8 = 1 << 0;

/// LED bit: Num Lock.
const LED_NUM_LOCK: u8 = 1 << 1;

/// LED bit: Caps Lock.
const LED_CAPS_LOCK: u8 = 1 << 2;

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

/// Maximum iterations to wait for controller readiness.
const POLL_TIMEOUT: u32 = 100_000;

// ---------------------------------------------------------------------------
// Scancode set 2 — key identifiers
// ---------------------------------------------------------------------------

/// Key state for tracking press/release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Key was pressed (make code).
    Pressed,
    /// Key was released (break code).
    Released,
}

/// A decoded keyboard event from scancode set 2.
#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    /// The scancode that generated this event.
    pub scancode: Scancode,
    /// Whether the key was pressed or released.
    pub state: KeyState,
    /// Whether the key was from an extended (0xE0) sequence.
    pub extended: bool,
}

/// Scancode identifier for scancode set 2 keys.
///
/// Only the most commonly used keys are enumerated; others are
/// represented by [`Scancode::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scancode {
    /// Escape key.
    Escape,
    /// F1 through F12 function keys.
    F(u8),
    /// Digit row: 1-9, 0.
    Digit(u8),
    /// Minus key.
    Minus,
    /// Equals key.
    Equals,
    /// Backspace key.
    Backspace,
    /// Tab key.
    Tab,
    /// Letter key (a-z, lowercase canonical).
    Letter(u8),
    /// Enter / Return key.
    Enter,
    /// Left Shift key.
    LShift,
    /// Right Shift key.
    RShift,
    /// Left Control key.
    LCtrl,
    /// Right Control key (extended).
    RCtrl,
    /// Left Alt key.
    LAlt,
    /// Right Alt key (extended).
    RAlt,
    /// Space bar.
    Space,
    /// Caps Lock key.
    CapsLock,
    /// Num Lock key.
    NumLock,
    /// Scroll Lock key.
    ScrollLock,
    /// Arrow Up (extended).
    Up,
    /// Arrow Down (extended).
    Down,
    /// Arrow Left (extended).
    Left,
    /// Arrow Right (extended).
    Right,
    /// Home (extended).
    Home,
    /// End (extended).
    End,
    /// Page Up (extended).
    PageUp,
    /// Page Down (extended).
    PageDown,
    /// Insert (extended).
    Insert,
    /// Delete (extended).
    Delete,
    /// Open bracket `[`.
    LBracket,
    /// Close bracket `]`.
    RBracket,
    /// Semicolon `;`.
    Semicolon,
    /// Apostrophe `'`.
    Apostrophe,
    /// Backslash `\`.
    Backslash,
    /// Comma `,`.
    Comma,
    /// Period `.`.
    Period,
    /// Slash `/`.
    Slash,
    /// Backtick `` ` ``.
    Backtick,
    /// Unknown or unrecognized scancode.
    Unknown(u8),
}

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

/// Read a byte from an x86 I/O port.
#[cfg(target_arch = "x86_64")]
fn port_inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Reading from PS/2 controller ports (0x60, 0x64) is a
    // standard x86 operation available in ring 0. These are well-known
    // legacy I/O ports that do not cause undefined behavior.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
    val
}

/// Write a byte to an x86 I/O port.
#[cfg(target_arch = "x86_64")]
fn port_outb(port: u16, val: u8) {
    // SAFETY: Writing to PS/2 controller ports (0x60, 0x64) is a
    // standard x86 operation available in ring 0. These are well-known
    // legacy I/O ports that do not cause undefined behavior.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Stub for non-x86 targets — always returns 0.
#[cfg(not(target_arch = "x86_64"))]
fn port_inb(_port: u16) -> u8 {
    0
}

/// Stub for non-x86 targets — no-op.
#[cfg(not(target_arch = "x86_64"))]
fn port_outb(_port: u16, _val: u8) {}

// ---------------------------------------------------------------------------
// Controller I/O
// ---------------------------------------------------------------------------

/// Wait until the input buffer is empty (ready to accept a command).
fn wait_input_ready() -> Result<()> {
    let mut timeout = POLL_TIMEOUT;
    while port_inb(PS2_CMD_PORT) & STATUS_IBF != 0 {
        timeout = timeout.saturating_sub(1);
        if timeout == 0 {
            return Err(Error::Busy);
        }
    }
    Ok(())
}

/// Wait until the output buffer is full (data available to read).
fn wait_output_ready() -> Result<()> {
    let mut timeout = POLL_TIMEOUT;
    while port_inb(PS2_CMD_PORT) & STATUS_OBF == 0 {
        timeout = timeout.saturating_sub(1);
        if timeout == 0 {
            return Err(Error::Busy);
        }
    }
    Ok(())
}

/// Send a command byte to the controller (port 0x64).
fn send_controller_cmd(cmd: u8) -> Result<()> {
    wait_input_ready()?;
    port_outb(PS2_CMD_PORT, cmd);
    Ok(())
}

/// Send a data byte to the device (port 0x60).
fn send_data(data: u8) -> Result<()> {
    wait_input_ready()?;
    port_outb(PS2_DATA_PORT, data);
    Ok(())
}

/// Read a response byte from the data port (port 0x60).
fn read_data() -> Result<u8> {
    wait_output_ready()?;
    Ok(port_inb(PS2_DATA_PORT))
}

/// Flush any pending data in the output buffer.
fn flush_output_buffer() {
    let mut attempts = 256u32;
    while port_inb(PS2_CMD_PORT) & STATUS_OBF != 0 && attempts > 0 {
        let _ = port_inb(PS2_DATA_PORT);
        attempts -= 1;
    }
}

// ---------------------------------------------------------------------------
// Scancode set 2 translation
// ---------------------------------------------------------------------------

/// Translate a scancode set 2 make code to a [`Scancode`].
fn translate_set2(code: u8) -> Scancode {
    match code {
        0x76 => Scancode::Escape,
        0x05 => Scancode::F(1),
        0x06 => Scancode::F(2),
        0x04 => Scancode::F(3),
        0x0C => Scancode::F(4),
        0x03 => Scancode::F(5),
        0x0B => Scancode::F(6),
        0x83 => Scancode::F(7),
        0x0A => Scancode::F(8),
        0x01 => Scancode::F(9),
        0x09 => Scancode::F(10),
        0x78 => Scancode::F(11),
        0x07 => Scancode::F(12),
        0x16 => Scancode::Digit(b'1'),
        0x1E => Scancode::Digit(b'2'),
        0x26 => Scancode::Digit(b'3'),
        0x25 => Scancode::Digit(b'4'),
        0x2E => Scancode::Digit(b'5'),
        0x36 => Scancode::Digit(b'6'),
        0x3D => Scancode::Digit(b'7'),
        0x3E => Scancode::Digit(b'8'),
        0x46 => Scancode::Digit(b'9'),
        0x45 => Scancode::Digit(b'0'),
        0x4E => Scancode::Minus,
        0x55 => Scancode::Equals,
        0x66 => Scancode::Backspace,
        0x0D => Scancode::Tab,
        0x15 => Scancode::Letter(b'q'),
        0x1D => Scancode::Letter(b'w'),
        0x24 => Scancode::Letter(b'e'),
        0x2D => Scancode::Letter(b'r'),
        0x2C => Scancode::Letter(b't'),
        0x35 => Scancode::Letter(b'y'),
        0x3C => Scancode::Letter(b'u'),
        0x43 => Scancode::Letter(b'i'),
        0x44 => Scancode::Letter(b'o'),
        0x4D => Scancode::Letter(b'p'),
        0x54 => Scancode::LBracket,
        0x5B => Scancode::RBracket,
        0x5A => Scancode::Enter,
        0x14 => Scancode::LCtrl,
        0x1C => Scancode::Letter(b'a'),
        0x1B => Scancode::Letter(b's'),
        0x23 => Scancode::Letter(b'd'),
        0x2B => Scancode::Letter(b'f'),
        0x34 => Scancode::Letter(b'g'),
        0x33 => Scancode::Letter(b'h'),
        0x3B => Scancode::Letter(b'j'),
        0x42 => Scancode::Letter(b'k'),
        0x4B => Scancode::Letter(b'l'),
        0x4C => Scancode::Semicolon,
        0x52 => Scancode::Apostrophe,
        0x0E => Scancode::Backtick,
        0x12 => Scancode::LShift,
        0x5D => Scancode::Backslash,
        0x1A => Scancode::Letter(b'z'),
        0x22 => Scancode::Letter(b'x'),
        0x21 => Scancode::Letter(b'c'),
        0x2A => Scancode::Letter(b'v'),
        0x32 => Scancode::Letter(b'b'),
        0x31 => Scancode::Letter(b'n'),
        0x3A => Scancode::Letter(b'm'),
        0x41 => Scancode::Comma,
        0x49 => Scancode::Period,
        0x4A => Scancode::Slash,
        0x59 => Scancode::RShift,
        0x11 => Scancode::LAlt,
        0x29 => Scancode::Space,
        0x58 => Scancode::CapsLock,
        0x77 => Scancode::NumLock,
        0x7E => Scancode::ScrollLock,
        other => Scancode::Unknown(other),
    }
}

/// Translate an extended (0xE0-prefixed) scancode set 2 code.
fn translate_set2_extended(code: u8) -> Scancode {
    match code {
        0x75 => Scancode::Up,
        0x72 => Scancode::Down,
        0x6B => Scancode::Left,
        0x74 => Scancode::Right,
        0x6C => Scancode::Home,
        0x69 => Scancode::End,
        0x7D => Scancode::PageUp,
        0x7A => Scancode::PageDown,
        0x70 => Scancode::Insert,
        0x71 => Scancode::Delete,
        0x14 => Scancode::RCtrl,
        0x11 => Scancode::RAlt,
        0x5A => Scancode::Enter,
        other => Scancode::Unknown(other),
    }
}

// ---------------------------------------------------------------------------
// Ps2Kbd — PS/2 keyboard driver
// ---------------------------------------------------------------------------

/// PS/2 keyboard controller driver.
///
/// Manages the 8042 PS/2 controller and provides scancode-to-key
/// translation for scancode set 2. Tracks the multi-byte state
/// machine for extended and break code sequences.
///
/// # Usage
///
/// ```ignore
/// let mut kbd = Ps2Kbd::new();
/// kbd.init()?;
///
/// // In IRQ1 handler:
/// if let Some(event) = kbd.handle_irq() {
///     // Process key event
/// }
/// ```
pub struct Ps2Kbd {
    /// Whether we are in an extended (0xE0) sequence.
    in_extended: bool,
    /// Whether we are in a break (0xF0) sequence.
    in_break: bool,
    /// LED state bitmask (scroll lock, num lock, caps lock).
    led_state: u8,
    /// Whether the device has been initialized.
    initialized: bool,
    /// Event ring buffer.
    event_buf: [Option<KeyEvent>; Self::EVENT_BUF_SIZE],
    /// Ring buffer write index.
    buf_head: usize,
    /// Ring buffer read index.
    buf_tail: usize,
    /// Number of buffered events.
    buf_count: usize,
}

impl Ps2Kbd {
    /// Size of the internal event ring buffer.
    const EVENT_BUF_SIZE: usize = 64;

    /// Create a new PS/2 keyboard driver.
    pub const fn new() -> Self {
        Self {
            in_extended: false,
            in_break: false,
            led_state: 0,
            initialized: false,
            event_buf: [None; Self::EVENT_BUF_SIZE],
            buf_head: 0,
            buf_tail: 0,
            buf_count: 0,
        }
    }

    /// Initialize the PS/2 keyboard controller.
    ///
    /// Performs the standard 8042 initialization sequence:
    /// 1. Disable both PS/2 ports.
    /// 2. Flush the output buffer.
    /// 3. Set the controller configuration.
    /// 4. Run controller self-test.
    /// 5. Test the first PS/2 port.
    /// 6. Enable the first PS/2 port.
    /// 7. Reset and enable the keyboard device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the self-test or port test fails.
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Disable both ports.
        send_controller_cmd(CMD_DISABLE_PORT1)?;
        send_controller_cmd(CMD_DISABLE_PORT2)?;

        // Step 2: Flush output buffer.
        flush_output_buffer();

        // Step 3: Read and modify controller configuration.
        send_controller_cmd(CMD_READ_CONFIG)?;
        let config = read_data()?;
        // Disable IRQs and translation during setup.
        let new_config = (config & !(CFG_PORT1_IRQ | CFG_TRANSLATION)) | CFG_PORT1_CLOCK_DISABLE;
        send_controller_cmd(CMD_WRITE_CONFIG)?;
        send_data(new_config)?;

        // Step 4: Controller self-test.
        send_controller_cmd(CMD_SELF_TEST)?;
        let test_result = read_data()?;
        if test_result != CTRL_SELF_TEST_OK {
            return Err(Error::IoError);
        }

        // Restore configuration after self-test (some controllers reset it).
        send_controller_cmd(CMD_WRITE_CONFIG)?;
        send_data(new_config)?;

        // Step 5: Test first PS/2 port.
        send_controller_cmd(CMD_TEST_PORT1)?;
        let port_test = read_data()?;
        if port_test != 0x00 {
            return Err(Error::IoError);
        }

        // Step 6: Enable first PS/2 port.
        send_controller_cmd(CMD_ENABLE_PORT1)?;

        // Enable port 1 IRQ and keep translation off (scancode set 2).
        let final_config = (new_config & !CFG_PORT1_CLOCK_DISABLE) | CFG_PORT1_IRQ;
        send_controller_cmd(CMD_WRITE_CONFIG)?;
        send_data(final_config)?;

        // Step 7: Reset the keyboard device.
        flush_output_buffer();
        send_data(DEV_CMD_RESET)?;
        // Wait for ACK + self-test result.
        let ack = read_data()?;
        if ack != DEV_ACK {
            // Some keyboards skip the ACK; check if this is the self-test.
            if ack != DEV_SELF_TEST_OK {
                return Err(Error::IoError);
            }
        } else {
            let self_test = read_data()?;
            if self_test != DEV_SELF_TEST_OK {
                return Err(Error::IoError);
            }
        }

        // Enable scanning.
        send_data(DEV_CMD_ENABLE_SCAN)?;
        let scan_ack = read_data()?;
        if scan_ack != DEV_ACK {
            return Err(Error::IoError);
        }

        self.initialized = true;
        Ok(())
    }

    /// Handle an IRQ1 interrupt from the PS/2 keyboard.
    ///
    /// Reads the scancode byte from the data port and processes it
    /// through the scancode set 2 state machine. Returns a decoded
    /// [`KeyEvent`] if a complete key event was assembled, or `None`
    /// if the byte was part of a multi-byte sequence.
    pub fn handle_irq(&mut self) -> Option<KeyEvent> {
        if !self.initialized {
            return None;
        }

        // Check that data is from keyboard (not mouse).
        let status = port_inb(PS2_CMD_PORT);
        if status & STATUS_OBF == 0 {
            return None;
        }
        if status & STATUS_AUX != 0 {
            // Mouse data — discard.
            let _ = port_inb(PS2_DATA_PORT);
            return None;
        }

        let byte = port_inb(PS2_DATA_PORT);
        self.process_byte(byte)
    }

    /// Process a single scancode byte through the state machine.
    ///
    /// Handles extended (0xE0) and break (0xF0) prefixes and translates
    /// the final make/break code into a [`KeyEvent`].
    fn process_byte(&mut self, byte: u8) -> Option<KeyEvent> {
        // Extended prefix.
        if byte == 0xE0 {
            self.in_extended = true;
            return None;
        }

        // Break prefix.
        if byte == 0xF0 {
            self.in_break = true;
            return None;
        }

        let extended = self.in_extended;
        let state = if self.in_break {
            KeyState::Released
        } else {
            KeyState::Pressed
        };

        // Reset state machine.
        self.in_extended = false;
        self.in_break = false;

        let scancode = if extended {
            translate_set2_extended(byte)
        } else {
            translate_set2(byte)
        };

        let event = KeyEvent {
            scancode,
            state,
            extended,
        };

        // Buffer the event.
        self.push_event(event);

        Some(event)
    }

    /// Push an event into the internal ring buffer.
    fn push_event(&mut self, event: KeyEvent) {
        if self.buf_count >= Self::EVENT_BUF_SIZE {
            // Buffer full — drop oldest.
            self.buf_tail = (self.buf_tail + 1) % Self::EVENT_BUF_SIZE;
            self.buf_count -= 1;
        }
        self.event_buf[self.buf_head] = Some(event);
        self.buf_head = (self.buf_head + 1) % Self::EVENT_BUF_SIZE;
        self.buf_count += 1;
    }

    /// Dequeue the oldest buffered key event.
    pub fn read_event(&mut self) -> Option<KeyEvent> {
        if self.buf_count == 0 {
            return None;
        }
        let event = self.event_buf[self.buf_tail].take();
        self.buf_tail = (self.buf_tail + 1) % Self::EVENT_BUF_SIZE;
        self.buf_count -= 1;
        event
    }

    /// Return the number of buffered events.
    pub fn buffered_count(&self) -> usize {
        self.buf_count
    }

    /// Check if the event buffer is empty.
    pub fn is_buffer_empty(&self) -> bool {
        self.buf_count == 0
    }

    // -- LED control -------------------------------------------------------

    /// Set the keyboard LED state.
    ///
    /// The `leds` bitmask uses:
    /// - Bit 0: Scroll Lock
    /// - Bit 1: Num Lock
    /// - Bit 2: Caps Lock
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device does not acknowledge.
    pub fn set_leds(&mut self, leds: u8) -> Result<()> {
        send_data(DEV_CMD_SET_LEDS)?;
        let ack = read_data()?;
        if ack != DEV_ACK {
            return Err(Error::IoError);
        }
        send_data(leds & 0x07)?;
        let ack2 = read_data()?;
        if ack2 != DEV_ACK {
            return Err(Error::IoError);
        }
        self.led_state = leds & 0x07;
        Ok(())
    }

    /// Toggle Scroll Lock LED.
    pub fn toggle_scroll_lock(&mut self) -> Result<()> {
        self.led_state ^= LED_SCROLL_LOCK;
        self.set_leds(self.led_state)
    }

    /// Toggle Num Lock LED.
    pub fn toggle_num_lock(&mut self) -> Result<()> {
        self.led_state ^= LED_NUM_LOCK;
        self.set_leds(self.led_state)
    }

    /// Toggle Caps Lock LED.
    pub fn toggle_caps_lock(&mut self) -> Result<()> {
        self.led_state ^= LED_CAPS_LOCK;
        self.set_leds(self.led_state)
    }

    /// Return the current LED state bitmask.
    pub fn led_state(&self) -> u8 {
        self.led_state
    }

    // -- Typematic rate ----------------------------------------------------

    /// Set the typematic (key repeat) rate and delay.
    ///
    /// `rate_delay` encodes both values in a single byte:
    /// - Bits 4:0: repeat rate (0 = 30 Hz, 0x1F = 2 Hz).
    /// - Bits 6:5: delay before repeat (0 = 250ms, 3 = 1000ms).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device does not acknowledge.
    pub fn set_typematic(&mut self, rate_delay: u8) -> Result<()> {
        send_data(DEV_CMD_SET_TYPEMATIC)?;
        let ack = read_data()?;
        if ack != DEV_ACK {
            return Err(Error::IoError);
        }
        send_data(rate_delay & 0x7F)?;
        let ack2 = read_data()?;
        if ack2 != DEV_ACK {
            return Err(Error::IoError);
        }
        Ok(())
    }

    // -- Scanning control --------------------------------------------------

    /// Enable keyboard scanning (device starts sending scancodes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device does not acknowledge.
    pub fn enable_scanning(&mut self) -> Result<()> {
        send_data(DEV_CMD_ENABLE_SCAN)?;
        let ack = read_data()?;
        if ack != DEV_ACK {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Disable keyboard scanning (device stops sending scancodes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device does not acknowledge.
    pub fn disable_scanning(&mut self) -> Result<()> {
        send_data(DEV_CMD_DISABLE_SCAN)?;
        let ack = read_data()?;
        if ack != DEV_ACK {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Set the active scancode set.
    ///
    /// `set_number`: 1, 2, or 3.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for invalid set numbers.
    /// Returns [`Error::IoError`] if the device does not acknowledge.
    pub fn set_scancode_set(&mut self, set_number: u8) -> Result<()> {
        if set_number == 0 || set_number > 3 {
            return Err(Error::InvalidArgument);
        }
        send_data(DEV_CMD_SET_SCANCODE)?;
        let ack = read_data()?;
        if ack != DEV_ACK {
            return Err(Error::IoError);
        }
        send_data(set_number)?;
        let ack2 = read_data()?;
        if ack2 != DEV_ACK {
            return Err(Error::IoError);
        }
        Ok(())
    }

    // -- Accessors ---------------------------------------------------------

    /// Return whether the driver has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for Ps2Kbd {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Ps2Kbd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ps2Kbd")
            .field("initialized", &self.initialized)
            .field("led_state", &self.led_state)
            .field("in_extended", &self.in_extended)
            .field("in_break", &self.in_break)
            .field("buffered", &self.buf_count)
            .finish()
    }
}
