// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PS/2 mouse driver and input subsystem.
//!
//! Provides 3-byte PS/2 mouse packet decoding, button state tracking,
//! movement accumulation, and a ring-buffer event queue for the
//! ONCRIX microkernel. Uses port I/O at 0x60 (data) and 0x64
//! (command/status) for PS/2 controller communication.

use oncrix_lib::{Error, Result};

// ── PS/2 port constants ─────────────────────────────────────────

/// PS/2 data port (read mouse data bytes).
const DATA_PORT: u16 = 0x60;

/// PS/2 command/status port.
const CMD_PORT: u16 = 0x64;

/// Command: enable auxiliary (mouse) device.
const CMD_ENABLE_AUX: u8 = 0xA8;

/// Command: write to auxiliary device input buffer.
const CMD_WRITE_AUX: u8 = 0xD4;

/// Mouse command: enable data reporting.
const MOUSE_CMD_ENABLE: u8 = 0xF4;

/// Mouse command: set sample rate.
const MOUSE_CMD_SET_RATE: u8 = 0xF3;

/// Mouse command: set defaults.
const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;

/// Mouse acknowledgement byte.
const MOUSE_ACK: u8 = 0xFA;

/// Status register: output buffer full bit.
const STATUS_OUTPUT_FULL: u8 = 1;

/// Status register: auxiliary data bit (bit 5).
const STATUS_AUX_DATA: u8 = 1 << 5;

/// Status register: input buffer full bit (bit 1).
const STATUS_INPUT_FULL: u8 = 1 << 1;

/// Maximum number of polling iterations when waiting for the
/// PS/2 controller to become ready.
const IO_WAIT_LIMIT: u32 = 100_000;

// ── MouseButton ─────────────────────────────────────────────────

/// Physical mouse button identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// Left mouse button.
    Left,
    /// Right mouse button.
    Right,
    /// Middle (scroll wheel) mouse button.
    Middle,
}

// ── MouseEvent ──────────────────────────────────────────────────

/// A single mouse input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEvent {
    /// Relative pointer movement (dx, dy).
    Move(i16, i16),
    /// A mouse button was pressed.
    ButtonPress(MouseButton),
    /// A mouse button was released.
    ButtonRelease(MouseButton),
}

// ── MousePacket ─────────────────────────────────────────────────

/// Decoded 3-byte PS/2 mouse packet.
///
/// Byte 0 layout (standard PS/2 mouse):
/// - bit 0: left button
/// - bit 1: right button
/// - bit 2: middle button
/// - bit 3: always 1 (alignment)
/// - bit 4: X sign bit
/// - bit 5: Y sign bit
/// - bit 6: X overflow
/// - bit 7: Y overflow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MousePacket {
    /// Left button is pressed.
    pub left: bool,
    /// Right button is pressed.
    pub right: bool,
    /// Middle button is pressed.
    pub middle: bool,
    /// Relative X movement (sign-extended).
    pub dx: i16,
    /// Relative Y movement (sign-extended).
    pub dy: i16,
    /// X axis overflowed (movement too fast).
    pub x_overflow: bool,
    /// Y axis overflowed (movement too fast).
    pub y_overflow: bool,
}

impl MousePacket {
    /// Decode a 3-byte PS/2 mouse packet.
    ///
    /// Returns `None` if byte 0 does not have bit 3 set (the
    /// "always 1" alignment bit), which indicates a desynchronised
    /// stream.
    pub fn decode(bytes: [u8; 3]) -> Option<Self> {
        let flags = bytes[0];

        // Bit 3 must be set in a valid PS/2 packet.
        if flags & 0x08 == 0 {
            return None;
        }

        let left = flags & 0x01 != 0;
        let right = flags & 0x02 != 0;
        let middle = flags & 0x04 != 0;
        let x_sign = flags & 0x10 != 0;
        let y_sign = flags & 0x20 != 0;
        let x_overflow = flags & 0x40 != 0;
        let y_overflow = flags & 0x80 != 0;

        // Sign-extend the 9-bit delta values.
        let dx = if x_sign {
            bytes[1] as i16 | -256_i16 // 0xFF00
        } else {
            bytes[1] as i16
        };

        let dy = if y_sign {
            bytes[2] as i16 | -256_i16 // 0xFF00
        } else {
            bytes[2] as i16
        };

        Some(Self {
            left,
            right,
            middle,
            dx,
            dy,
            x_overflow,
            y_overflow,
        })
    }
}

// ── MouseState ──────────────────────────────────────────────────

/// Tracks the current mouse button state and accumulated movement.
#[derive(Debug, Clone, Copy)]
pub struct MouseState {
    /// Left button currently held.
    pub left: bool,
    /// Right button currently held.
    pub right: bool,
    /// Middle button currently held.
    pub middle: bool,
    /// Accumulated X movement since last read.
    pub acc_dx: i32,
    /// Accumulated Y movement since last read.
    pub acc_dy: i32,
}

impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseState {
    /// Create a new mouse state with all buttons released and
    /// zero accumulated movement.
    pub const fn new() -> Self {
        Self {
            left: false,
            right: false,
            middle: false,
            acc_dx: 0,
            acc_dy: 0,
        }
    }

    /// Accumulate movement deltas from a decoded packet.
    pub fn accumulate(&mut self, dx: i16, dy: i16) {
        self.acc_dx = self.acc_dx.saturating_add(dx as i32);
        self.acc_dy = self.acc_dy.saturating_add(dy as i32);
    }

    /// Drain accumulated movement, resetting to zero.
    pub fn drain(&mut self) -> (i32, i32) {
        let dx = self.acc_dx;
        let dy = self.acc_dy;
        self.acc_dx = 0;
        self.acc_dy = 0;
        (dx, dy)
    }
}

// ── MouseEventQueue ─────────────────────────────────────────────

/// Fixed-capacity ring buffer holding up to 64 [`MouseEvent`]s.
pub struct MouseEventQueue {
    /// Internal storage.
    buf: [Option<MouseEvent>; Self::CAPACITY],
    /// Read index.
    head: usize,
    /// Write index.
    tail: usize,
    /// Current number of events stored.
    count: usize,
}

impl Default for MouseEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseEventQueue {
    /// Maximum number of events the queue can hold.
    const CAPACITY: usize = 64;

    /// Create an empty event queue.
    pub const fn new() -> Self {
        Self {
            buf: [None; Self::CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push a mouse event into the queue.
    ///
    /// Returns [`Error::WouldBlock`] if the queue is full.
    pub fn push(&mut self, event: MouseEvent) -> Result<()> {
        if self.count >= Self::CAPACITY {
            return Err(Error::WouldBlock);
        }
        self.buf[self.tail] = Some(event);
        self.tail = (self.tail + 1) % Self::CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Remove and return the oldest event, or `None` if empty.
    pub fn pop(&mut self) -> Option<MouseEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.buf[self.head].take();
        self.head = (self.head + 1) % Self::CAPACITY;
        self.count -= 1;
        event
    }

    /// Peek at the oldest event without removing it.
    pub fn peek(&self) -> Option<&MouseEvent> {
        if self.count == 0 {
            return None;
        }
        self.buf[self.head].as_ref()
    }

    /// Returns `true` if the queue contains no events.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of events currently in the queue.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Discard all queued events.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        let mut i = 0;
        while i < Self::CAPACITY {
            self.buf[i] = None;
            i += 1;
        }
    }
}

// ── Packet assembly FSM ─────────────────────────────────────────

/// Byte position within the 3-byte PS/2 mouse packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketPhase {
    /// Waiting for byte 0 (flags).
    Byte0,
    /// Waiting for byte 1 (X delta).
    Byte1,
    /// Waiting for byte 2 (Y delta).
    Byte2,
}

// ── Port I/O helpers ────────────────────────────────────────────

/// Wait until the PS/2 controller output buffer is full (data
/// ready to read), or return an error after the polling limit.
#[cfg(target_arch = "x86_64")]
fn wait_output_ready() -> Result<()> {
    let mut retries = IO_WAIT_LIMIT;
    while retries > 0 {
        let status = oncrix_hal::power::inb(CMD_PORT);
        if status & STATUS_OUTPUT_FULL != 0 {
            return Ok(());
        }
        retries -= 1;
    }
    Err(Error::IoError)
}

/// Wait until the PS/2 controller input buffer is empty (ready
/// to accept a command byte), or return an error.
#[cfg(target_arch = "x86_64")]
fn wait_input_ready() -> Result<()> {
    let mut retries = IO_WAIT_LIMIT;
    while retries > 0 {
        let status = oncrix_hal::power::inb(CMD_PORT);
        if status & STATUS_INPUT_FULL == 0 {
            return Ok(());
        }
        retries -= 1;
    }
    Err(Error::IoError)
}

/// Send a command byte to the PS/2 controller command port.
#[cfg(target_arch = "x86_64")]
fn ps2_write_cmd(cmd: u8) -> Result<()> {
    wait_input_ready()?;
    oncrix_hal::power::outb(CMD_PORT, cmd);
    Ok(())
}

/// Send a command byte to the auxiliary (mouse) device and wait
/// for the ACK response.
#[cfg(target_arch = "x86_64")]
fn mouse_write(cmd: u8) -> Result<()> {
    ps2_write_cmd(CMD_WRITE_AUX)?;
    wait_input_ready()?;
    oncrix_hal::power::outb(DATA_PORT, cmd);

    // Wait for ACK.
    wait_output_ready()?;
    let ack = oncrix_hal::power::inb(DATA_PORT);
    if ack != MOUSE_ACK {
        return Err(Error::IoError);
    }
    Ok(())
}

/// Set the PS/2 mouse sample rate.
#[cfg(target_arch = "x86_64")]
fn set_sample_rate(rate: u8) -> Result<()> {
    mouse_write(MOUSE_CMD_SET_RATE)?;
    mouse_write(rate)?;
    Ok(())
}

// ── MouseDriver ─────────────────────────────────────────────────

/// PS/2 mouse driver.
///
/// Handles hardware initialisation, 3-byte packet assembly via
/// a finite state machine, and event generation. Feed raw IRQ12
/// bytes into [`MouseDriver::process_byte`] from the interrupt
/// handler.
pub struct MouseDriver {
    /// Packet assembly state machine phase.
    phase: PacketPhase,
    /// Packet bytes collected so far.
    packet_buf: [u8; 3],
    /// Current button and movement state.
    pub state: MouseState,
    /// Buffered event queue.
    pub queue: MouseEventQueue,
}

impl Default for MouseDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseDriver {
    /// Create a new mouse driver (not yet initialised with
    /// hardware).
    pub const fn new() -> Self {
        Self {
            phase: PacketPhase::Byte0,
            packet_buf: [0; 3],
            state: MouseState::new(),
            queue: MouseEventQueue::new(),
        }
    }

    /// Initialise the PS/2 mouse hardware.
    ///
    /// Enables the auxiliary device on the PS/2 controller, sets
    /// the default sample rate (100 samples/sec), and enables
    /// data reporting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the PS/2 controller does not
    /// respond within the polling timeout.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        // Enable the auxiliary (mouse) device.
        ps2_write_cmd(CMD_ENABLE_AUX)?;

        // Set defaults (clears any leftover state).
        mouse_write(MOUSE_CMD_SET_DEFAULTS)?;

        // Set sample rate to 100 samples/sec.
        set_sample_rate(100)?;

        // Enable data reporting.
        mouse_write(MOUSE_CMD_ENABLE)?;

        // Reset packet FSM.
        self.phase = PacketPhase::Byte0;
        self.packet_buf = [0; 3];

        Ok(())
    }

    /// Process a single byte received from the PS/2 data port
    /// (typically called from the IRQ12 handler).
    ///
    /// Assembles 3-byte packets, decodes them, and enqueues the
    /// resulting [`MouseEvent`]s. If the queue is full, events
    /// are silently dropped.
    pub fn process_byte(&mut self, byte: u8) {
        match self.phase {
            PacketPhase::Byte0 => {
                // Bit 3 must be set in a valid first byte.
                if byte & 0x08 == 0 {
                    // Desynchronised — stay in Byte0 phase.
                    return;
                }
                self.packet_buf[0] = byte;
                self.phase = PacketPhase::Byte1;
            }
            PacketPhase::Byte1 => {
                self.packet_buf[1] = byte;
                self.phase = PacketPhase::Byte2;
            }
            PacketPhase::Byte2 => {
                self.packet_buf[2] = byte;
                self.phase = PacketPhase::Byte0;
                self.handle_packet();
            }
        }
    }

    /// Called from the IRQ12 handler with the raw byte read from
    /// port 0x60.
    ///
    /// Delegates to [`process_byte`](Self::process_byte) after
    /// verifying the status register indicates auxiliary data.
    #[cfg(target_arch = "x86_64")]
    pub fn handle_irq(&mut self) {
        let status = oncrix_hal::power::inb(CMD_PORT);
        if status & STATUS_OUTPUT_FULL == 0 {
            return;
        }
        if status & STATUS_AUX_DATA == 0 {
            // Not mouse data — keyboard or spurious.
            return;
        }
        let byte = oncrix_hal::power::inb(DATA_PORT);
        self.process_byte(byte);
    }

    /// Dequeue the next mouse event, if any.
    pub fn read_event(&mut self) -> Option<MouseEvent> {
        self.queue.pop()
    }

    /// Decode a complete 3-byte packet and generate events.
    fn handle_packet(&mut self) {
        let packet = match MousePacket::decode(self.packet_buf) {
            Some(p) => p,
            None => {
                // Invalid packet — discard.
                return;
            }
        };

        // Skip overflow packets — the delta values are unreliable.
        if packet.x_overflow || packet.y_overflow {
            return;
        }

        // Generate button press/release events.
        self.check_button(packet.left, self.state.left, MouseButton::Left);
        self.check_button(packet.right, self.state.right, MouseButton::Right);
        self.check_button(packet.middle, self.state.middle, MouseButton::Middle);

        // Update button state.
        self.state.left = packet.left;
        self.state.right = packet.right;
        self.state.middle = packet.middle;

        // Generate movement event.
        if packet.dx != 0 || packet.dy != 0 {
            self.state.accumulate(packet.dx, packet.dy);
            let _ = self.queue.push(MouseEvent::Move(packet.dx, packet.dy));
        }
    }

    /// Compare old and new button state, enqueuing press/release
    /// events as needed.
    fn check_button(&mut self, new: bool, old: bool, button: MouseButton) {
        if new && !old {
            let _ = self.queue.push(MouseEvent::ButtonPress(button));
        } else if !new && old {
            let _ = self.queue.push(MouseEvent::ButtonRelease(button));
        }
    }
}
