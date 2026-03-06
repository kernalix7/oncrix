// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! i8042 PS/2 keyboard and mouse controller driver.
//!
//! The Intel 8042 (i8042) is a microcontroller that bridges one or two PS/2
//! devices (keyboard on port 1, mouse on port 2) to the host CPU. It is
//! accessed via two I/O ports: a data port (0x60) and a command/status port
//! (0x64).
//!
//! # Architecture
//!
//! - **Data port (0x60)** — read data from output buffer; write data/params
//! - **Command port (0x64)** — write commands; **Status port** — read status
//! - **Output buffer** — holds data from keyboard/mouse/controller
//! - **Input buffer** — holds data written by the host (not yet consumed)
//! - **Controller configuration byte (CCB)** — controls interrupts, translation
//!
//! # Interrupt Lines
//!
//! - IRQ 1 → keyboard (PS/2 port 1)
//! - IRQ 12 → mouse (PS/2 port 2)
//!
//! # Scan Code Sets
//!
//! The keyboard normally speaks scan code set 2; the i8042 translates it to
//! set 1 if translation is enabled in the CCB. This driver operates with
//! translation enabled (the default) for compatibility.
//!
//! Reference: Adam Chapweske "The PS/2 Mouse/Keyboard Protocol"; OSDev Wiki.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Port Addresses
// ---------------------------------------------------------------------------

/// PS/2 data port (read: output buffer data; write: device or param data).
const PS2_DATA_PORT: u16 = 0x60;

/// PS/2 status/command port (read: status byte; write: controller command).
const PS2_CMD_PORT: u16 = 0x64;

// ---------------------------------------------------------------------------
// Controller Status Register Bits (read from 0x64)
// ---------------------------------------------------------------------------

/// Status: Output Buffer Status — 1 = data available to read from 0x60.
const STATUS_OBF: u8 = 1 << 0;
/// Status: Input Buffer Status — 1 = controller not yet consumed our write.
const STATUS_IBF: u8 = 1 << 1;
/// Status: System flag (POST result).
const _STATUS_SYS: u8 = 1 << 2;
/// Status: Command/Data flag (0 = data, 1 = command was last written).
const _STATUS_CMD_DATA: u8 = 1 << 3;
/// Status: Keyboard lock (0 = locked, 1 = unlocked).
const _STATUS_KEYLOCK: u8 = 1 << 4;
/// Status: Output buffer full from second (mouse) port.
const STATUS_MOUSE_OBF: u8 = 1 << 5;
/// Status: Timeout error.
const _STATUS_TIMEOUT: u8 = 1 << 6;
/// Status: Parity error.
const _STATUS_PARITY: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Controller Commands (written to 0x64)
// ---------------------------------------------------------------------------

/// Command: Read controller configuration byte.
const CMD_READ_CCB: u8 = 0x20;
/// Command: Write controller configuration byte (follow with byte to 0x60).
const CMD_WRITE_CCB: u8 = 0x60;
/// Command: Disable PS/2 port 2 (mouse).
const CMD_DISABLE_PORT2: u8 = 0xA7;
/// Command: Enable PS/2 port 2 (mouse).
const CMD_ENABLE_PORT2: u8 = 0xA8;
/// Command: Test PS/2 port 2.
const CMD_TEST_PORT2: u8 = 0xA9;
/// Command: Test controller (self-test).
const CMD_SELF_TEST: u8 = 0xAA;
/// Command: Test PS/2 port 1.
const CMD_TEST_PORT1: u8 = 0xAB;
/// Command: Disable PS/2 port 1 (keyboard).
const CMD_DISABLE_PORT1: u8 = 0xAD;
/// Command: Enable PS/2 port 1 (keyboard).
const CMD_ENABLE_PORT1: u8 = 0xAE;
/// Command: Write next byte to second PS/2 port (mouse).
const CMD_WRITE_PORT2: u8 = 0xD4;

// ---------------------------------------------------------------------------
// Controller Configuration Byte (CCB) Bits
// ---------------------------------------------------------------------------

/// CCB: Port 1 interrupt enable (IRQ 1).
const CCB_PORT1_INT: u8 = 1 << 0;
/// CCB: Port 2 interrupt enable (IRQ 12).
const CCB_PORT2_INT: u8 = 1 << 1;
/// CCB: System flag (pass-through of Status.SYS).
const _CCB_SYS_FLAG: u8 = 1 << 2;
/// CCB: Port 1 clock disable.
const _CCB_PORT1_CLK_DIS: u8 = 1 << 4;
/// CCB: Port 2 clock disable.
const _CCB_PORT2_CLK_DIS: u8 = 1 << 5;
/// CCB: Port 1 translation enable (scan code set 2 → set 1).
const CCB_PORT1_TRANSLATE: u8 = 1 << 6;

// ---------------------------------------------------------------------------
// Device Commands (written to 0x60, forwarded to the device)
// ---------------------------------------------------------------------------

/// Device: Identify device type.
const _DEV_IDENTIFY: u8 = 0xF2;
/// Device: Enable scanning/reporting.
const DEV_ENABLE_SCAN: u8 = 0xF4;
/// Device: Disable scanning/reporting.
const _DEV_DISABLE_SCAN: u8 = 0xF5;
/// Device: Reset and self-test.
const DEV_RESET: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Device Response Bytes
// ---------------------------------------------------------------------------

/// Device response: ACK.
const DEV_ACK: u8 = 0xFA;
/// Device response: NACK / resend.
const _DEV_RESEND: u8 = 0xFE;
/// Device response: Self-test pass.
const DEV_SELF_TEST_PASS: u8 = 0xAA;
/// Controller self-test pass code.
const CTRL_SELF_TEST_PASS: u8 = 0x55;
/// Controller port test pass code.
const PORT_TEST_PASS: u8 = 0x00;

// ---------------------------------------------------------------------------
// Timeout constants
// ---------------------------------------------------------------------------

/// Maximum poll iterations waiting for input buffer empty (write ready).
const IBF_POLL_MAX: u32 = 1_000_000;
/// Maximum poll iterations waiting for output buffer full (data ready).
const OBF_POLL_MAX: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Key event ring buffer size
// ---------------------------------------------------------------------------

/// Number of key events that can be buffered.
const KEY_BUFFER_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Scan code special values
// ---------------------------------------------------------------------------

/// Scan code: extended key prefix.
const SCAN_EXTENDED: u8 = 0xE0;
/// Scan code: break (key-up) bit.
const SCAN_BREAK_BIT: u8 = 0x80;

// ---------------------------------------------------------------------------
// KeyEvent
// ---------------------------------------------------------------------------

/// A decoded keyboard event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Raw scan code (set 1, as translated by the controller).
    pub scan_code: u8,
    /// `true` if this is a key-down (make) event.
    pub pressed: bool,
    /// `true` if this was an extended (0xE0-prefixed) key.
    pub extended: bool,
}

// ---------------------------------------------------------------------------
// MouseEvent
// ---------------------------------------------------------------------------

/// A decoded PS/2 mouse event (three-byte packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseEvent {
    /// Button state: bit 0 = left, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
    /// Signed X displacement.
    pub dx: i8,
    /// Signed Y displacement.
    pub dy: i8,
}

// ---------------------------------------------------------------------------
// Keyboard state
// ---------------------------------------------------------------------------

/// Modifier key state tracked by the driver.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModifierState {
    /// Left or right Shift is held.
    pub shift: bool,
    /// Left or right Ctrl is held.
    pub ctrl: bool,
    /// Left or right Alt is held.
    pub alt: bool,
    /// Caps Lock is active.
    pub caps_lock: bool,
    /// Num Lock is active.
    pub num_lock: bool,
}

// ---------------------------------------------------------------------------
// i8042 Controller Driver
// ---------------------------------------------------------------------------

/// Driver for the Intel 8042 PS/2 controller.
///
/// Manages controller initialisation, port enable/disable, and keyboard/mouse
/// event decoding.
pub struct I8042Controller {
    /// Whether the controller has been successfully initialised.
    initialized: bool,
    /// Whether a PS/2 port 2 (mouse) was detected.
    has_mouse: bool,
    /// Cached controller configuration byte.
    ccb: u8,
    /// Keyboard ring buffer.
    key_buf: [KeyEvent; KEY_BUFFER_SIZE],
    key_head: usize,
    key_tail: usize,
    key_count: usize,
    /// Extended prefix pending.
    extended_pending: bool,
    /// Current modifier state.
    modifiers: ModifierState,
    /// Mouse packet accumulator (3 bytes).
    mouse_packet: [u8; 3],
    mouse_byte_idx: usize,
}

impl I8042Controller {
    /// Creates a new (uninitialised) controller driver.
    pub const fn new() -> Self {
        Self {
            initialized: false,
            has_mouse: false,
            ccb: 0,
            key_buf: [KeyEvent {
                scan_code: 0,
                pressed: false,
                extended: false,
            }; KEY_BUFFER_SIZE],
            key_head: 0,
            key_tail: 0,
            key_count: 0,
            extended_pending: false,
            modifiers: ModifierState {
                shift: false,
                ctrl: false,
                alt: false,
                caps_lock: false,
                num_lock: false,
            },
            mouse_packet: [0u8; 3],
            mouse_byte_idx: 0,
        }
    }

    /// Initialises the i8042 controller.
    ///
    /// Steps performed:
    /// 1. Disable both PS/2 ports to prevent spurious data.
    /// 2. Flush the output buffer.
    /// 3. Read and modify the CCB (enable interrupts, enable translation).
    /// 4. Perform controller self-test.
    /// 5. Test and optionally enable PS/2 port 2.
    /// 6. Reset and enable both devices.
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Disable ports.
        self.write_command(CMD_DISABLE_PORT1)?;
        self.write_command(CMD_DISABLE_PORT2)?;

        // Step 2: Flush output buffer.
        self.flush_output_buffer();

        // Step 3: Read and modify CCB.
        self.write_command(CMD_READ_CCB)?;
        let ccb = self.read_data_timeout()?;
        let new_ccb = (ccb | CCB_PORT1_INT | CCB_PORT1_TRANSLATE) & !CCB_PORT2_INT;
        self.write_command(CMD_WRITE_CCB)?;
        self.write_data(new_ccb)?;
        self.ccb = new_ccb;

        // Step 4: Controller self-test.
        self.write_command(CMD_SELF_TEST)?;
        let result = self.read_data_timeout()?;
        if result != CTRL_SELF_TEST_PASS {
            return Err(Error::IoError);
        }

        // Step 5: Test port 2 and enable mouse if present.
        self.write_command(CMD_TEST_PORT2)?;
        let port2_result = self.read_data_timeout().unwrap_or(0xFF);
        if port2_result == PORT_TEST_PASS {
            self.has_mouse = true;
            self.write_command(CMD_ENABLE_PORT2)?;
            // Enable port 2 interrupt.
            let ccb2 = self.ccb | CCB_PORT2_INT;
            self.write_command(CMD_WRITE_CCB)?;
            self.write_data(ccb2)?;
            self.ccb = ccb2;
        }

        // Step 6: Test port 1.
        self.write_command(CMD_TEST_PORT1)?;
        let port1_result = self.read_data_timeout()?;
        if port1_result != PORT_TEST_PASS {
            return Err(Error::IoError);
        }

        // Enable ports and reset/enable devices.
        self.write_command(CMD_ENABLE_PORT1)?;
        self.reset_device(false)?;
        self.enable_device(false)?;

        if self.has_mouse {
            self.reset_device(true)?;
            self.enable_device(true)?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Returns whether a PS/2 mouse was detected on port 2.
    pub fn has_mouse(&self) -> bool {
        self.has_mouse
    }

    /// Handles an IRQ 1 (keyboard) interrupt.
    ///
    /// Reads a scan code byte from the data port and enqueues a [`KeyEvent`].
    /// Returns `true` if a complete key event was enqueued.
    pub fn handle_keyboard_irq(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        let status = self.read_status();
        if status & STATUS_OBF == 0 {
            return false;
        }
        // Make sure it's not mouse data.
        if status & STATUS_MOUSE_OBF != 0 {
            return false;
        }
        let byte = self.read_data();
        self.process_keyboard_byte(byte)
    }

    /// Handles an IRQ 12 (mouse) interrupt.
    ///
    /// Reads a mouse data byte and accumulates the 3-byte packet.
    /// Returns `Some(MouseEvent)` when a complete packet is available.
    pub fn handle_mouse_irq(&mut self) -> Option<MouseEvent> {
        if !self.initialized || !self.has_mouse {
            return None;
        }
        let status = self.read_status();
        if status & STATUS_OBF == 0 {
            return None;
        }
        // Should be from mouse port.
        if status & STATUS_MOUSE_OBF == 0 {
            return None;
        }
        let byte = self.read_data();
        self.process_mouse_byte(byte)
    }

    /// Dequeues the next keyboard event, if any.
    pub fn dequeue_key(&mut self) -> Option<KeyEvent> {
        if self.key_count == 0 {
            return None;
        }
        let ev = self.key_buf[self.key_head];
        self.key_head = (self.key_head + 1) % KEY_BUFFER_SIZE;
        self.key_count -= 1;
        Some(ev)
    }

    /// Returns the current modifier state.
    pub fn modifiers(&self) -> &ModifierState {
        &self.modifiers
    }

    // -----------------------------------------------------------------------
    // Private: keyboard processing
    // -----------------------------------------------------------------------

    fn process_keyboard_byte(&mut self, byte: u8) -> bool {
        if byte == SCAN_EXTENDED {
            self.extended_pending = true;
            return false;
        }
        let extended = self.extended_pending;
        self.extended_pending = false;

        let pressed = byte & SCAN_BREAK_BIT == 0;
        let scan_code = byte & !SCAN_BREAK_BIT;

        self.update_modifiers(scan_code, extended, pressed);

        let ev = KeyEvent {
            scan_code,
            pressed,
            extended,
        };
        self.enqueue_key(ev);
        true
    }

    fn enqueue_key(&mut self, ev: KeyEvent) {
        if self.key_count < KEY_BUFFER_SIZE {
            self.key_buf[self.key_tail] = ev;
            self.key_tail = (self.key_tail + 1) % KEY_BUFFER_SIZE;
            self.key_count += 1;
        }
        // Drop event if buffer full.
    }

    fn update_modifiers(&mut self, scan_code: u8, extended: bool, pressed: bool) {
        match (extended, scan_code) {
            // Left Shift: 0x2A, Right Shift: 0x36
            (false, 0x2A) | (false, 0x36) => self.modifiers.shift = pressed,
            // Left Ctrl: 0x1D, Right Ctrl: extended 0x1D
            (false, 0x1D) | (true, 0x1D) => self.modifiers.ctrl = pressed,
            // Left Alt: 0x38, Right Alt (AltGr): extended 0x38
            (false, 0x38) | (true, 0x38) => self.modifiers.alt = pressed,
            // Caps Lock: 0x3A (toggle on press)
            (false, 0x3A) if pressed => self.modifiers.caps_lock = !self.modifiers.caps_lock,
            // Num Lock: 0x45 (toggle on press)
            (false, 0x45) if pressed => self.modifiers.num_lock = !self.modifiers.num_lock,
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Private: mouse processing
    // -----------------------------------------------------------------------

    fn process_mouse_byte(&mut self, byte: u8) -> Option<MouseEvent> {
        self.mouse_packet[self.mouse_byte_idx] = byte;
        self.mouse_byte_idx += 1;
        if self.mouse_byte_idx < 3 {
            return None;
        }
        self.mouse_byte_idx = 0;

        let flags = self.mouse_packet[0];
        // Bit 3 must always be set; if not, the packet is out of sync.
        if flags & 0x08 == 0 {
            return None;
        }
        // Sign-extend the 9-bit displacement values.
        let raw_dx = self.mouse_packet[1] as i16 | if flags & 0x10 != 0 { -256i16 } else { 0 };
        let raw_dy = self.mouse_packet[2] as i16 | if flags & 0x20 != 0 { -256i16 } else { 0 };

        let dx = raw_dx.clamp(i8::MIN as i16, i8::MAX as i16) as i8;
        let dy = raw_dy.clamp(i8::MIN as i16, i8::MAX as i16) as i8;

        Some(MouseEvent {
            buttons: flags & 0x07,
            dx,
            dy,
        })
    }

    // -----------------------------------------------------------------------
    // Private: device control
    // -----------------------------------------------------------------------

    fn reset_device(&mut self, mouse: bool) -> Result<()> {
        if mouse {
            self.write_command(CMD_WRITE_PORT2)?;
        }
        self.write_data(DEV_RESET)?;
        let ack = self.read_data_timeout()?;
        if ack != DEV_ACK {
            // Some implementations skip ACK on reset; be lenient.
            if ack != DEV_SELF_TEST_PASS {
                let second = self.read_data_timeout()?;
                if second != DEV_SELF_TEST_PASS {
                    return Err(Error::IoError);
                }
            }
            return Ok(());
        }
        let pass = self.read_data_timeout()?;
        if pass != DEV_SELF_TEST_PASS {
            return Err(Error::IoError);
        }
        Ok(())
    }

    fn enable_device(&mut self, mouse: bool) -> Result<()> {
        if mouse {
            self.write_command(CMD_WRITE_PORT2)?;
        }
        self.write_data(DEV_ENABLE_SCAN)?;
        let ack = self.read_data_timeout()?;
        if ack != DEV_ACK {
            return Err(Error::IoError);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private: port I/O primitives
    // -----------------------------------------------------------------------

    /// Reads the status register (0x64).
    fn read_status(&self) -> u8 {
        port_inb(PS2_CMD_PORT)
    }

    /// Reads a byte from the data port (0x60) without checking status.
    fn read_data(&self) -> u8 {
        port_inb(PS2_DATA_PORT)
    }

    /// Reads a byte from the data port, spinning until the OBF flag is set.
    fn read_data_timeout(&self) -> Result<u8> {
        for _ in 0..OBF_POLL_MAX {
            if self.read_status() & STATUS_OBF != 0 {
                return Ok(self.read_data());
            }
        }
        Err(Error::Busy)
    }

    /// Waits for the input buffer to be empty, then writes `cmd` to 0x64.
    fn write_command(&self, cmd: u8) -> Result<()> {
        self.wait_input_empty()?;
        port_outb(PS2_CMD_PORT, cmd);
        Ok(())
    }

    /// Waits for the input buffer to be empty, then writes `data` to 0x60.
    fn write_data(&self, data: u8) -> Result<()> {
        self.wait_input_empty()?;
        port_outb(PS2_DATA_PORT, data);
        Ok(())
    }

    /// Spins until the input buffer empty (IBF clear).
    fn wait_input_empty(&self) -> Result<()> {
        for _ in 0..IBF_POLL_MAX {
            if self.read_status() & STATUS_IBF == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Drains any stale data from the output buffer.
    fn flush_output_buffer(&self) {
        for _ in 0..16 {
            if self.read_status() & STATUS_OBF == 0 {
                break;
            }
            let _ = self.read_data();
        }
    }
}

impl Default for I8042Controller {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

fn port_inb(port: u16) -> u8 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Reading from PS/2 I/O ports (0x60, 0x64) is a well-defined
        // x86 platform operation on all supported hardware.
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags),
        );
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = port;
        0
    }
}

fn port_outb(port: u16, value: u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Writing to PS/2 I/O ports (0x60, 0x64) is a well-defined
        // x86 platform operation on all supported hardware.
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (port, value);
    }
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

/// Maximum number of i8042 controllers tracked.
const MAX_PS2_CONTROLLERS: usize = 1;

/// Registry of i8042 PS/2 controllers.
pub struct Ps2Registry {
    controllers: [I8042Controller; MAX_PS2_CONTROLLERS],
    count: usize,
}

impl Ps2Registry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { I8042Controller::new() }; MAX_PS2_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers and initialises an i8042 controller.
    ///
    /// Returns the assigned index, or `Err(OutOfMemory)` if the registry is
    /// full.
    pub fn register(&mut self, mut ctrl: I8042Controller) -> Result<usize> {
        if self.count >= MAX_PS2_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        ctrl.init()?;
        let idx = self.count;
        self.controllers[idx] = ctrl;
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the controller at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut I8042Controller> {
        if index < self.count {
            Some(&mut self.controllers[index])
        } else {
            None
        }
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for Ps2Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_event_defaults() {
        let ev = KeyEvent {
            scan_code: 0x1E,
            pressed: true,
            extended: false,
        };
        assert_eq!(ev.scan_code, 0x1E);
        assert!(ev.pressed);
        assert!(!ev.extended);
    }

    #[test]
    fn mouse_event_default() {
        let ev = MouseEvent::default();
        assert_eq!(ev.buttons, 0);
        assert_eq!(ev.dx, 0);
        assert_eq!(ev.dy, 0);
    }

    #[test]
    fn controller_initial_state() {
        let ctrl = I8042Controller::new();
        assert!(!ctrl.initialized);
        assert!(!ctrl.has_mouse);
    }

    #[test]
    fn registry_empty() {
        let reg = Ps2Registry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn modifier_state_default() {
        let mods = ModifierState::default();
        assert!(!mods.shift);
        assert!(!mods.ctrl);
        assert!(!mods.alt);
        assert!(!mods.caps_lock);
        assert!(!mods.num_lock);
    }
}
