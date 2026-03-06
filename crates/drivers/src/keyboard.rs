// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PS/2 keyboard driver and input subsystem.
//!
//! Provides scan code set 1 translation, key event generation,
//! modifier tracking, and a ring-buffer input queue for the
//! ONCRIX microkernel.

use oncrix_lib::{Error, Result};

// ── Scan code set 1 translation table ───────────────────────────

/// Lookup table mapping scan code set 1 make codes (index 0x00–0x58)
/// to their unshifted ASCII representation. Non-printable keys map
/// to `0`.
#[rustfmt::skip]
static SCANCODE_TO_ASCII: [u8; 89] = [
    //  0x00
    0,
    //  0x01  ESC
    0x1B,
    //  0x02  1!   0x03  2@   0x04  3#   0x05  4$
    b'1', b'2', b'3', b'4',
    //  0x06  5%   0x07  6^   0x08  7&   0x09  8*
    b'5', b'6', b'7', b'8',
    //  0x0A  9(   0x0B  0)   0x0C  -_   0x0D  =+
    b'9', b'0', b'-', b'=',
    //  0x0E  Backspace   0x0F  Tab
    0x08, 0x09,
    //  0x10  Q   0x11  W   0x12  E   0x13  R
    b'q', b'w', b'e', b'r',
    //  0x14  T   0x15  Y   0x16  U   0x17  I
    b't', b'y', b'u', b'i',
    //  0x18  O   0x19  P   0x1A  [{   0x1B  ]}
    b'o', b'p', b'[', b']',
    //  0x1C  Enter
    b'\n',
    //  0x1D  Left Ctrl
    0,
    //  0x1E  A   0x1F  S   0x20  D   0x21  F
    b'a', b's', b'd', b'f',
    //  0x22  G   0x23  H   0x24  J   0x25  K
    b'g', b'h', b'j', b'k',
    //  0x26  L   0x27  ;:   0x28  '"   0x29  `~
    b'l', b';', b'\'', b'`',
    //  0x2A  Left Shift
    0,
    //  0x2B  \|
    b'\\',
    //  0x2C  Z   0x2D  X   0x2E  C   0x2F  V
    b'z', b'x', b'c', b'v',
    //  0x30  B   0x31  N   0x32  M   0x33  ,<
    b'b', b'n', b'm', b',',
    //  0x34  .>   0x35  /?
    b'.', b'/',
    //  0x36  Right Shift
    0,
    //  0x37  Keypad *
    b'*',
    //  0x38  Left Alt
    0,
    //  0x39  Space
    b' ',
    //  0x3A  CapsLock
    0,
    //  0x3B  F1   0x3C  F2   0x3D  F3   0x3E  F4
    0, 0, 0, 0,
    //  0x3F  F5   0x40  F6   0x41  F7   0x42  F8
    0, 0, 0, 0,
    //  0x43  F9   0x44  F10
    0, 0,
    //  0x45  NumLock   0x46  ScrollLock
    0, 0,
    //  0x47  Keypad 7/Home   0x48  Keypad 8/Up
    b'7', b'8',
    //  0x49  Keypad 9/PgUp   0x4A  Keypad -
    b'9', b'-',
    //  0x4B  Keypad 4/Left   0x4C  Keypad 5
    b'4', b'5',
    //  0x4D  Keypad 6/Right  0x4E  Keypad +
    b'6', b'+',
    //  0x4F  Keypad 1/End    0x50  Keypad 2/Down
    b'1', b'2',
    //  0x51  Keypad 3/PgDn   0x52  Keypad 0/Ins
    b'3', b'0',
    //  0x53  Keypad ./Del
    b'.',
    //  0x54–0x56  unused
    0, 0, 0,
    //  0x57  F11   0x58  F12
    0, 0,
];

/// Shifted ASCII for keys that change character under Shift.
/// Same indexing as [`SCANCODE_TO_ASCII`].
#[rustfmt::skip]
pub static SCANCODE_TO_ASCII_SHIFTED: [u8; 89] = [
    0,
    0x1B,
    b'!', b'@', b'#', b'$',
    b'%', b'^', b'&', b'*',
    b'(', b')', b'_', b'+',
    0x08, 0x09,
    b'Q', b'W', b'E', b'R',
    b'T', b'Y', b'U', b'I',
    b'O', b'P', b'{', b'}',
    b'\n',
    0,
    b'A', b'S', b'D', b'F',
    b'G', b'H', b'J', b'K',
    b'L', b':', b'"', b'~',
    0,
    b'|',
    b'Z', b'X', b'C', b'V',
    b'B', b'N', b'M', b'<',
    b'>', b'?',
    0,
    b'*',
    0,
    b' ',
    0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0,
    0, 0,
    b'7', b'8',
    b'9', b'-',
    b'4', b'5',
    b'6', b'+',
    b'1', b'2',
    b'3', b'0',
    b'.',
    0, 0, 0,
    0, 0,
];

// ── KeyCode ─────────────────────────────────────────────────────

/// Logical key identifier produced by scan code translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    /// Escape key.
    Escape,
    /// Backspace key.
    Backspace,
    /// Tab key.
    Tab,
    /// Enter / Return key.
    Enter,
    /// Left Shift key.
    LShift,
    /// Right Shift key.
    RShift,
    /// Left Control key.
    LCtrl,
    /// Right Control key.
    RCtrl,
    /// Left Alt key.
    LAlt,
    /// Right Alt key.
    RAlt,
    /// Caps Lock toggle key.
    CapsLock,
    /// Function key F1.
    F1,
    /// Function key F2.
    F2,
    /// Function key F3.
    F3,
    /// Function key F4.
    F4,
    /// Function key F5.
    F5,
    /// Function key F6.
    F6,
    /// Function key F7.
    F7,
    /// Function key F8.
    F8,
    /// Function key F9.
    F9,
    /// Function key F10.
    F10,
    /// Function key F11.
    F11,
    /// Function key F12.
    F12,
    /// Num Lock toggle key.
    NumLock,
    /// Scroll Lock toggle key.
    ScrollLock,
    /// Arrow Up.
    Up,
    /// Arrow Down.
    Down,
    /// Arrow Left.
    Left,
    /// Arrow Right.
    Right,
    /// Home key.
    Home,
    /// End key.
    End,
    /// Page Up key.
    PageUp,
    /// Page Down key.
    PageDown,
    /// Insert key.
    Insert,
    /// Delete key.
    Delete,
    /// A key that produces a printable ASCII character.
    Printable(u8),
}

// ── Modifiers ───────────────────────────────────────────────────

/// Active keyboard modifier state stored as a bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modifiers(u8);

impl Modifiers {
    /// Shift modifier bit.
    pub const SHIFT: u8 = 1;
    /// Control modifier bit.
    pub const CTRL: u8 = 2;
    /// Alt modifier bit.
    pub const ALT: u8 = 4;
    /// Caps Lock toggle bit.
    pub const CAPS_LOCK: u8 = 8;
    /// Num Lock toggle bit.
    pub const NUM_LOCK: u8 = 16;

    /// Create an empty modifier set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if the Shift modifier is active.
    pub const fn shift(self) -> bool {
        self.0 & Self::SHIFT != 0
    }

    /// Returns `true` if the Ctrl modifier is active.
    pub const fn ctrl(self) -> bool {
        self.0 & Self::CTRL != 0
    }

    /// Returns `true` if the Alt modifier is active.
    pub const fn alt(self) -> bool {
        self.0 & Self::ALT != 0
    }

    /// Returns `true` if Caps Lock is toggled on.
    pub const fn caps(self) -> bool {
        self.0 & Self::CAPS_LOCK != 0
    }

    /// Returns `true` if Num Lock is toggled on.
    pub const fn num_lock(self) -> bool {
        self.0 & Self::NUM_LOCK != 0
    }

    /// Set a modifier bit.
    fn set(&mut self, bit: u8) {
        self.0 |= bit;
    }

    /// Clear a modifier bit.
    fn clear(&mut self, bit: u8) {
        self.0 &= !bit;
    }

    /// Toggle a modifier bit.
    fn toggle(&mut self, bit: u8) {
        self.0 ^= bit;
    }
}

// ── KeyEvent ────────────────────────────────────────────────────

/// A single keyboard event (key press or release).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// The logical key that was pressed or released.
    pub keycode: KeyCode,
    /// `true` for a make (press) event, `false` for break (release).
    pub pressed: bool,
    /// Modifier state at the time of the event.
    pub modifiers: Modifiers,
}

// ── KeyboardState ───────────────────────────────────────────────

/// Tracks the current state of the keyboard including modifiers
/// and multi-byte scan code sequences.
pub struct KeyboardState {
    /// Currently active modifiers.
    pub modifiers: Modifiers,
    /// `true` when the previous byte was the 0xE0 extended prefix.
    pub extended: bool,
}

impl Default for KeyboardState {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyboardState {
    /// Create a new keyboard state with no modifiers active.
    pub const fn new() -> Self {
        Self {
            modifiers: Modifiers::empty(),
            extended: false,
        }
    }

    /// Process a single scan code byte and return a [`KeyEvent`]
    /// if a complete key event was decoded.
    ///
    /// Handles the 0xE0 extended prefix, break codes (bit 7 set),
    /// and modifier/toggle key state updates.
    pub fn process_scancode(&mut self, scancode: u8) -> Option<KeyEvent> {
        // Extended prefix — remember and wait for the next byte.
        if scancode == 0xE0 {
            self.extended = true;
            return None;
        }

        let pressed = scancode & 0x80 == 0;
        let code = scancode & 0x7F;
        let extended = self.extended;
        self.extended = false;

        let keycode = if extended {
            Self::translate_extended(code)?
        } else {
            Self::translate_normal(code)?
        };

        // Update modifier state.
        self.update_modifiers(&keycode, pressed);

        Some(KeyEvent {
            keycode,
            pressed,
            modifiers: self.modifiers,
        })
    }

    /// Translate a normal (non-extended) scan code to a [`KeyCode`].
    fn translate_normal(code: u8) -> Option<KeyCode> {
        match code {
            0x01 => Some(KeyCode::Escape),
            0x0E => Some(KeyCode::Backspace),
            0x0F => Some(KeyCode::Tab),
            0x1C => Some(KeyCode::Enter),
            0x1D => Some(KeyCode::LCtrl),
            0x2A => Some(KeyCode::LShift),
            0x36 => Some(KeyCode::RShift),
            0x38 => Some(KeyCode::LAlt),
            0x3A => Some(KeyCode::CapsLock),
            0x3B => Some(KeyCode::F1),
            0x3C => Some(KeyCode::F2),
            0x3D => Some(KeyCode::F3),
            0x3E => Some(KeyCode::F4),
            0x3F => Some(KeyCode::F5),
            0x40 => Some(KeyCode::F6),
            0x41 => Some(KeyCode::F7),
            0x42 => Some(KeyCode::F8),
            0x43 => Some(KeyCode::F9),
            0x44 => Some(KeyCode::F10),
            0x45 => Some(KeyCode::NumLock),
            0x46 => Some(KeyCode::ScrollLock),
            0x57 => Some(KeyCode::F11),
            0x58 => Some(KeyCode::F12),
            // Printable keys via the lookup table.
            c if (c as usize) < SCANCODE_TO_ASCII.len() => {
                let ascii = SCANCODE_TO_ASCII[c as usize];
                if ascii != 0 {
                    Some(KeyCode::Printable(ascii))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Translate an extended (0xE0-prefixed) scan code to a
    /// [`KeyCode`].
    fn translate_extended(code: u8) -> Option<KeyCode> {
        match code {
            0x1D => Some(KeyCode::RCtrl),
            0x38 => Some(KeyCode::RAlt),
            0x47 => Some(KeyCode::Home),
            0x48 => Some(KeyCode::Up),
            0x49 => Some(KeyCode::PageUp),
            0x4B => Some(KeyCode::Left),
            0x4D => Some(KeyCode::Right),
            0x4F => Some(KeyCode::End),
            0x50 => Some(KeyCode::Down),
            0x51 => Some(KeyCode::PageDown),
            0x52 => Some(KeyCode::Insert),
            0x53 => Some(KeyCode::Delete),
            _ => None,
        }
    }

    /// Update the modifier bitmask after a key event.
    fn update_modifiers(&mut self, keycode: &KeyCode, pressed: bool) {
        match keycode {
            KeyCode::LShift | KeyCode::RShift => {
                if pressed {
                    self.modifiers.set(Modifiers::SHIFT);
                } else {
                    self.modifiers.clear(Modifiers::SHIFT);
                }
            }
            KeyCode::LCtrl | KeyCode::RCtrl => {
                if pressed {
                    self.modifiers.set(Modifiers::CTRL);
                } else {
                    self.modifiers.clear(Modifiers::CTRL);
                }
            }
            KeyCode::LAlt | KeyCode::RAlt => {
                if pressed {
                    self.modifiers.set(Modifiers::ALT);
                } else {
                    self.modifiers.clear(Modifiers::ALT);
                }
            }
            KeyCode::CapsLock if pressed => {
                self.modifiers.toggle(Modifiers::CAPS_LOCK);
            }
            KeyCode::NumLock if pressed => {
                self.modifiers.toggle(Modifiers::NUM_LOCK);
            }
            _ => {}
        }
    }
}

// ── InputQueue ──────────────────────────────────────────────────

/// Fixed-capacity ring buffer holding up to 128 [`KeyEvent`]s.
pub struct InputQueue {
    /// Internal storage.
    buf: [Option<KeyEvent>; Self::CAPACITY],
    /// Read index.
    head: usize,
    /// Write index.
    tail: usize,
    /// Current number of events stored.
    count: usize,
}

impl Default for InputQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl InputQueue {
    /// Maximum number of events the queue can hold.
    const CAPACITY: usize = 128;

    /// Create an empty input queue.
    pub const fn new() -> Self {
        Self {
            buf: [None; Self::CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push a key event into the queue.
    ///
    /// Returns [`Error::WouldBlock`] if the queue is full.
    pub fn push(&mut self, event: KeyEvent) -> Result<()> {
        if self.count >= Self::CAPACITY {
            return Err(Error::WouldBlock);
        }
        self.buf[self.tail] = Some(event);
        self.tail = (self.tail + 1) % Self::CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Remove and return the oldest event, or `None` if empty.
    pub fn pop(&mut self) -> Option<KeyEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.buf[self.head].take();
        self.head = (self.head + 1) % Self::CAPACITY;
        self.count -= 1;
        event
    }

    /// Peek at the oldest event without removing it.
    pub fn peek(&self) -> Option<&KeyEvent> {
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
        // Zero out slots so stale data is not leaked.
        let mut i = 0;
        while i < Self::CAPACITY {
            self.buf[i] = None;
            i += 1;
        }
    }
}

// ── ASCII conversion ────────────────────────────────────────────

/// Convert a [`KeyCode`] and current [`Modifiers`] to an ASCII
/// byte, applying Shift and Caps Lock transformations.
///
/// Returns `None` for non-printable keys.
pub fn to_ascii(keycode: KeyCode, modifiers: Modifiers) -> Option<u8> {
    match keycode {
        KeyCode::Printable(base) => {
            let shift = modifiers.shift();
            let caps = modifiers.caps();

            // Letters: Shift XOR CapsLock toggles case.
            if base.is_ascii_lowercase() {
                let upper = shift ^ caps;
                if upper {
                    Some(base.to_ascii_uppercase())
                } else {
                    Some(base)
                }
            } else {
                // Non-letter printables: only Shift applies.
                if shift {
                    shifted_symbol(base)
                } else {
                    Some(base)
                }
            }
        }
        KeyCode::Enter => Some(b'\n'),
        KeyCode::Tab => Some(b'\t'),
        KeyCode::Backspace => Some(0x08),
        KeyCode::Escape => Some(0x1B),
        _ => None,
    }
}

/// Map an unshifted symbol/digit to its shifted counterpart.
fn shifted_symbol(ch: u8) -> Option<u8> {
    let out = match ch {
        b'1' => b'!',
        b'2' => b'@',
        b'3' => b'#',
        b'4' => b'$',
        b'5' => b'%',
        b'6' => b'^',
        b'7' => b'&',
        b'8' => b'*',
        b'9' => b'(',
        b'0' => b')',
        b'-' => b'_',
        b'=' => b'+',
        b'[' => b'{',
        b']' => b'}',
        b'\\' => b'|',
        b';' => b':',
        b'\'' => b'"',
        b'`' => b'~',
        b',' => b'<',
        b'.' => b'>',
        b'/' => b'?',
        b' ' => b' ',
        other => other,
    };
    Some(out)
}

// ── InputSubsystem ──────────────────────────────────────────────

/// Top-level input subsystem combining the keyboard state machine
/// and event queue.
pub struct InputSubsystem {
    /// Keyboard scan code translator and modifier tracker.
    pub keyboard: KeyboardState,
    /// Buffered event queue.
    pub queue: InputQueue,
}

impl Default for InputSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl InputSubsystem {
    /// Create a new input subsystem with default state.
    pub const fn new() -> Self {
        Self {
            keyboard: KeyboardState::new(),
            queue: InputQueue::new(),
        }
    }

    /// Called from the IRQ1 handler with the raw scan code byte
    /// read from port 0x60.
    ///
    /// Translates the scan code, updates modifier state, and
    /// enqueues the resulting event. If the queue is full the
    /// event is silently dropped.
    pub fn handle_irq(&mut self, scancode: u8) {
        if let Some(event) = self.keyboard.process_scancode(scancode) {
            // Best-effort push — drop on overflow.
            let _ = self.queue.push(event);
        }
    }

    /// Dequeue the next key event, if any.
    pub fn read_event(&mut self) -> Option<KeyEvent> {
        self.queue.pop()
    }

    /// Dequeue events until a printable ASCII character is found,
    /// applying Shift and Caps Lock. Non-printable events are
    /// consumed and discarded.
    ///
    /// Returns `None` when the queue is exhausted without finding
    /// a printable character.
    pub fn read_char(&mut self) -> Option<u8> {
        while let Some(event) = self.queue.pop() {
            if !event.pressed {
                continue;
            }
            if let Some(ch) = to_ascii(event.keycode, event.modifiers) {
                return Some(ch);
            }
        }
        None
    }
}
