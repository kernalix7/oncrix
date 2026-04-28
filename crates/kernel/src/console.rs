// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Console stdin ring buffer.
//!
//! A small fixed-size ASCII ring buffer that bridges the keyboard IRQ
//! producer (single-CPU, IF=0) and the SYSCALL `read(2)` consumer.
//!
//! # Synchronisation
//!
//! Phase 14 only supports a single CPU. The producer (IRQ 1 keyboard
//! handler) executes with interrupts disabled, and the consumer
//! ([`crate::fd_table::dispatch_read`]) runs in SYSCALL context where
//! the FMASK MSR clears IF on entry. Neither side can be preempted by
//! the other, so a plain non-atomic ring buffer is sufficient.
//!
//! All public helpers carry an `unsafe fn` marker mirroring the
//! convention used by [`crate::fd_table`] for `static mut` access.
//! Each call site is annotated with `#[allow(static_mut_refs)]` so the
//! 2024 edition lint does not fire.
//!
//! # POSIX.1-2024 line discipline
//!
//! Phase 14 keeps termios out of scope: stdin is "cooked" with the
//! kernel hard-coding line mode + echo. The ring buffer stores raw
//! bytes; line termination on `'\n'` is enforced by
//! [`crate::fd_table::dispatch_read`] when servicing
//! [`crate::fd_table::FileBackend::Console`].

// ── Keyboard modifier state ───────────────────────────────────────

/// Live modifier-key state updated by the IRQ 1 handler.
///
/// All fields are plain `bool`; the struct carries no padding. It is
/// stored in a `static mut` because the IRQ 1 handler is the sole
/// writer and runs with IF=0 (interrupt gate), so no synchronisation
/// primitive is needed on a single-CPU kernel.
pub struct KbdModifiers {
    /// Either left- or right-shift key is currently held.
    pub shift: bool,
    /// Caps-Lock logical state (toggled on each CapsLock make).
    pub caps: bool,
    /// Left-control key is currently held.
    pub ctrl: bool,
}

// SAFETY: Single-CPU kernel; all access occurs in IRQ 1 context with
// IF=0. There is no concurrent reader or writer.
pub static mut KBD_MODS: KbdModifiers = KbdModifiers {
    shift: false,
    caps: false,
    ctrl: false,
};

// ── KbdEvent ──────────────────────────────────────────────────────

/// Decoded result of a single PS/2 scancode-set-1 byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbdEvent {
    /// A printable ASCII byte (already modifier-adjusted).
    Ascii(u8),
    /// Left or right Shift key pressed.
    ShiftDown,
    /// Left or right Shift key released.
    ShiftUp,
    /// CapsLock key pressed (toggle semantics).
    CapsToggle,
    /// Left-Ctrl key pressed.
    CtrlDown,
    /// Left-Ctrl key released.
    CtrlUp,
    /// Scancode has no mapping we care about; caller should discard.
    Ignore,
}

/// Translate a PS/2 scancode-set-1 byte into a [`KbdEvent`].
///
/// The function consults the current [`KBD_MODS`] state to produce the
/// correct ASCII casing and Ctrl-modified bytes. It does **not** mutate
/// `KBD_MODS`; the caller updates modifier state after receiving a
/// `ShiftDown`/`ShiftUp`/`CapsToggle`/`CtrlDown`/`CtrlUp` event.
///
/// # Safety
///
/// Must be called from IRQ 1 context (IF=0, single CPU) because it
/// reads `KBD_MODS` without a lock.
pub unsafe fn translate(scancode: u8) -> KbdEvent {
    // ── Modifier make/break events ─────────────────────────────────
    match scancode {
        0x2A | 0x36 => return KbdEvent::ShiftDown, // L-Shift / R-Shift make
        0xAA | 0xB6 => return KbdEvent::ShiftUp,   // L-Shift / R-Shift break
        0x3A => return KbdEvent::CapsToggle,       // CapsLock make
        0x1D => return KbdEvent::CtrlDown,         // L-Ctrl make
        0x9D => return KbdEvent::CtrlUp,           // L-Ctrl break
        _ => {}
    }

    // Drop all other releases (bit 7 set) and the extended prefix.
    if scancode == 0xE0 || scancode & 0x80 != 0 {
        return KbdEvent::Ignore;
    }

    // ── Map make code to base ASCII ────────────────────────────────
    let base: u8 = match scancode {
        // Top digit row.
        0x02 => b'1',
        0x03 => b'2',
        0x04 => b'3',
        0x05 => b'4',
        0x06 => b'5',
        0x07 => b'6',
        0x08 => b'7',
        0x09 => b'8',
        0x0A => b'9',
        0x0B => b'0',
        0x0C => b'-',
        0x0D => b'=',
        0x0E => 0x08, // Backspace
        0x0F => b'\t',
        // QWERTY row.
        0x10 => b'q',
        0x11 => b'w',
        0x12 => b'e',
        0x13 => b'r',
        0x14 => b't',
        0x15 => b'y',
        0x16 => b'u',
        0x17 => b'i',
        0x18 => b'o',
        0x19 => b'p',
        0x1A => b'[',
        0x1B => b']',
        0x1C => b'\n', // Enter
        // ASDF row.
        0x1E => b'a',
        0x1F => b's',
        0x20 => b'd',
        0x21 => b'f',
        0x22 => b'g',
        0x23 => b'h',
        0x24 => b'j',
        0x25 => b'k',
        0x26 => b'l',
        0x27 => b';',
        0x28 => b'\'',
        0x29 => b'`',
        0x2B => b'\\',
        // ZXCV row.
        0x2C => b'z',
        0x2D => b'x',
        0x2E => b'c',
        0x2F => b'v',
        0x30 => b'b',
        0x31 => b'n',
        0x32 => b'm',
        0x33 => b',',
        0x34 => b'.',
        0x35 => b'/',
        // Space.
        0x39 => b' ',
        _ => return KbdEvent::Ignore,
    };

    // ── Read current modifier state ────────────────────────────────
    // SAFETY: IF=0, single-CPU; no concurrent mutation.
    let mods = unsafe {
        #[allow(static_mut_refs)]
        &KBD_MODS
    };

    // ── Ctrl takes priority: Ctrl+letter → ETX / Ctrl+X ──────────
    if mods.ctrl && base.is_ascii_alphabetic() {
        // Map 'a'/'A' → 0x01 … 'z'/'Z' → 0x1A; Ctrl-C → 0x03 (ETX).
        return KbdEvent::Ascii(base.to_ascii_lowercase() - b'a' + 1);
    }

    // ── Shift / Caps for letters ───────────────────────────────────
    let shifted = mods.shift ^ mods.caps; // XOR: caps + shift → lower
    if base.is_ascii_lowercase() {
        return if shifted {
            KbdEvent::Ascii(base.to_ascii_uppercase())
        } else {
            KbdEvent::Ascii(base)
        };
    }

    // ── Shift for punctuation / digits ────────────────────────────
    if mods.shift {
        let shifted_byte: u8 = match base {
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
            b';' => b':',
            b'\'' => b'"',
            b'`' => b'~',
            b'\\' => b'|',
            b',' => b'<',
            b'.' => b'>',
            b'/' => b'?',
            other => other, // e.g. Space, Enter, Tab, BS — pass through
        };
        return KbdEvent::Ascii(shifted_byte);
    }

    KbdEvent::Ascii(base)
}

// ── Constants ─────────────────────────────────────────────────────

/// Capacity of the stdin ring buffer in bytes.
///
/// 256 is plenty for the longest interactive line a user can type
/// before issuing `read(2)` (which drains the buffer). Sized to a
/// power of two so that any future masking-based index arithmetic
/// stays trivial; current implementation uses modulo for clarity.
pub const STDIN_RING_CAPACITY: usize = 256;

// ── ConsoleRing ───────────────────────────────────────────────────

/// Fixed-capacity, single-producer / single-consumer byte ring buffer.
///
/// Used as the kernel-side staging area for keyboard input destined
/// for the console stdin file descriptor.
///
/// On overflow the oldest byte is dropped to make room for the newest
/// one. This trades message integrity for forward progress under fast
/// typing, mirroring Linux's `tty_buffer` strategy when a slow reader
/// cannot keep up.
pub struct ConsoleRing {
    /// Storage for buffered bytes.
    buf: [u8; STDIN_RING_CAPACITY],
    /// Producer index (next write position).
    head: usize,
    /// Consumer index (next read position).
    tail: usize,
    /// Number of valid bytes currently buffered.
    count: usize,
}

impl ConsoleRing {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; STDIN_RING_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push `b` at the head. On overflow the oldest byte is dropped.
    fn push(&mut self, b: u8) {
        if self.count == STDIN_RING_CAPACITY {
            // Buffer full — advance tail (drop oldest) before overwriting.
            self.tail = (self.tail + 1) % STDIN_RING_CAPACITY;
            self.count -= 1;
        }
        self.buf[self.head] = b;
        self.head = (self.head + 1) % STDIN_RING_CAPACITY;
        self.count += 1;
    }

    /// Pop the oldest buffered byte, if any.
    fn pop(&mut self) -> Option<u8> {
        if self.count == 0 {
            return None;
        }
        let b = self.buf[self.tail];
        self.tail = (self.tail + 1) % STDIN_RING_CAPACITY;
        self.count -= 1;
        Some(b)
    }

    /// Return `true` if at least one byte is buffered.
    fn has_byte(&self) -> bool {
        self.count != 0
    }
}

impl Default for ConsoleRing {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global stdin buffer ───────────────────────────────────────────

/// Global stdin ring buffer.
///
/// # Safety invariant
///
/// Accessed exclusively from:
///
/// 1. The IRQ 1 keyboard handler (single CPU, IF=0 from interrupt gate).
/// 2. The SYSCALL `read(2)` dispatch path (single CPU, FMASK clears IF).
///
/// Neither path can preempt the other on a uniprocessor with the gate
/// configured as an `Interrupt` gate. SMP support will require either a
/// per-CPU buffer or atomic head/tail counters.
// SAFETY: see the module-level note. Single producer (IRQ) + single
// consumer (SYSCALL), both with IF=0.
pub static mut STDIN_BUF: ConsoleRing = ConsoleRing::new();

/// Push byte `b` onto the stdin ring buffer.
///
/// Called from the IRQ 1 keyboard handler after translating a make
/// scancode to ASCII. Drops the oldest buffered byte on overflow.
///
/// # Safety
///
/// Caller must guarantee single-CPU + interrupts-disabled context
/// (the IRQ 1 handler is installed as an `Interrupt` gate, which
/// satisfies this).
pub unsafe fn console_push_byte(b: u8) {
    // SAFETY: see the module-level note.
    unsafe {
        #[allow(static_mut_refs)]
        STDIN_BUF.push(b);
    }
}

/// Pop the oldest buffered byte, returning `None` if the buffer is
/// empty.
///
/// Called from [`crate::fd_table::dispatch_read`] when servicing a
/// `read(2)` on the console stdin file descriptor.
///
/// # Safety
///
/// Same single-CPU + IF=0 contract as [`console_push_byte`].
pub unsafe fn console_pop_byte() -> Option<u8> {
    // SAFETY: see the module-level note.
    unsafe {
        #[allow(static_mut_refs)]
        STDIN_BUF.pop()
    }
}

/// Return `true` if the stdin ring buffer has at least one byte.
///
/// # Safety
///
/// Same single-CPU + IF=0 contract as [`console_push_byte`].
pub unsafe fn console_has_byte() -> bool {
    // SAFETY: see the module-level note.
    unsafe {
        #[allow(static_mut_refs)]
        STDIN_BUF.has_byte()
    }
}

// ── Optional pre-fill (off by default) ────────────────────────────

/// Pre-fill the stdin ring buffer with `bytes`.
///
/// Used by debug-only smoke tests to demonstrate the keyboard →
/// `read(2)` round trip without requiring an interactive QEMU
/// session. Off by default; callers must opt in by invoking this
/// helper directly from a build-time-gated path. Production builds
/// must NOT call this.
///
/// # Safety
///
/// Same single-CPU + IF=0 contract as [`console_push_byte`]. Must
/// be called before user-space starts issuing `read(2)` so the
/// ordering of "pre-pushed bytes vs first read" is well-defined.
pub unsafe fn debug_prefill(bytes: &[u8]) {
    for &b in bytes {
        // SAFETY: forwarded; caller upholds the invariant.
        unsafe { console_push_byte(b) };
    }
}
