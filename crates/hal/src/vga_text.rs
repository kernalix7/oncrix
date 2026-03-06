// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VGA text-mode console driver.
//!
//! Provides a simple 80×25 VGA text-mode console using the memory-mapped
//! framebuffer at physical address 0xB8000. Each character cell is 2 bytes:
//! the low byte is the ASCII character, the high byte is the attribute
//! (foreground and background color).
//!
//! # Attribute byte layout
//!
//! ```text
//! Bits 7:   Blink (or bright background)
//! Bits 6:4: Background color (0–7)
//! Bits 3:0: Foreground color (0–15)
//! ```
//!
//! Reference: OSDev Wiki — VGA Text Mode.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Physical address of the VGA text framebuffer.
pub const VGA_BUFFER_PHYS: u64 = 0xB8000;

/// Number of columns in the standard VGA text mode.
pub const VGA_COLS: usize = 80;

/// Number of rows in the standard VGA text mode.
pub const VGA_ROWS: usize = 25;

/// Total number of character cells.
pub const VGA_CELLS: usize = VGA_COLS * VGA_ROWS;

/// VGA CRT controller index port.
pub const VGA_CRTC_INDEX: u16 = 0x3D4;

/// VGA CRT controller data port.
pub const VGA_CRTC_DATA: u16 = 0x3D5;

/// CRTC register: cursor location high byte.
pub const CRTC_CURSOR_HIGH: u8 = 0x0E;

/// CRTC register: cursor location low byte.
pub const CRTC_CURSOR_LOW: u8 = 0x0F;

// ---------------------------------------------------------------------------
// VGA color constants
// ---------------------------------------------------------------------------

/// VGA color: black.
pub const COLOR_BLACK: u8 = 0;
/// VGA color: blue.
pub const COLOR_BLUE: u8 = 1;
/// VGA color: green.
pub const COLOR_GREEN: u8 = 2;
/// VGA color: cyan.
pub const COLOR_CYAN: u8 = 3;
/// VGA color: red.
pub const COLOR_RED: u8 = 4;
/// VGA color: magenta.
pub const COLOR_MAGENTA: u8 = 5;
/// VGA color: brown.
pub const COLOR_BROWN: u8 = 6;
/// VGA color: light grey.
pub const COLOR_LIGHT_GREY: u8 = 7;
/// VGA color: dark grey.
pub const COLOR_DARK_GREY: u8 = 8;
/// VGA color: light blue.
pub const COLOR_LIGHT_BLUE: u8 = 9;
/// VGA color: light green.
pub const COLOR_LIGHT_GREEN: u8 = 10;
/// VGA color: light cyan.
pub const COLOR_LIGHT_CYAN: u8 = 11;
/// VGA color: light red.
pub const COLOR_LIGHT_RED: u8 = 12;
/// VGA color: light magenta.
pub const COLOR_LIGHT_MAGENTA: u8 = 13;
/// VGA color: yellow.
pub const COLOR_YELLOW: u8 = 14;
/// VGA color: white.
pub const COLOR_WHITE: u8 = 15;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constructs a VGA attribute byte from foreground and background colors.
pub const fn vga_attr(fg: u8, bg: u8) -> u8 {
    ((bg & 0x7) << 4) | (fg & 0xF)
}

/// Constructs a VGA character cell (lo = char, hi = attribute).
pub const fn vga_cell(ch: u8, attr: u8) -> u16 {
    (attr as u16) << 8 | (ch as u16)
}

// ---------------------------------------------------------------------------
// VgaTextConsole
// ---------------------------------------------------------------------------

/// VGA text-mode console backed by a memory-mapped framebuffer.
pub struct VgaTextConsole {
    /// Virtual address of the VGA framebuffer (mapped by caller).
    buf_virt: u64,
    /// Current cursor column.
    pub col: usize,
    /// Current cursor row.
    pub row: usize,
    /// Default text attribute (foreground + background).
    pub attr: u8,
}

impl VgaTextConsole {
    /// Creates a new VGA console at the given virtual address.
    ///
    /// `buf_virt` must be the virtual address of the 80×25 VGA framebuffer
    /// (typically identity-mapped from 0xB8000).
    pub const fn new(buf_virt: u64) -> Self {
        Self {
            buf_virt,
            col: 0,
            row: 0,
            attr: vga_attr(COLOR_LIGHT_GREY, COLOR_BLACK),
        }
    }

    /// Writes a 16-bit cell to the buffer at (row, col).
    fn write_cell(&self, row: usize, col: usize, cell: u16) {
        let offset = (row * VGA_COLS + col) * 2;
        let addr = (self.buf_virt + offset as u64) as *mut u16;
        // SAFETY: buf_virt is the caller-mapped VGA framebuffer; volatile write required.
        unsafe { core::ptr::write_volatile(addr, cell) };
    }

    /// Reads the 16-bit cell at (row, col).
    fn read_cell(&self, row: usize, col: usize) -> u16 {
        let offset = (row * VGA_COLS + col) * 2;
        let addr = (self.buf_virt + offset as u64) as *const u16;
        // SAFETY: buf_virt is the caller-mapped VGA framebuffer; volatile read required.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Clears the screen with spaces using the current attribute.
    pub fn clear(&mut self) {
        let blank = vga_cell(b' ', self.attr);
        for row in 0..VGA_ROWS {
            for col in 0..VGA_COLS {
                self.write_cell(row, col, blank);
            }
        }
        self.col = 0;
        self.row = 0;
    }

    /// Scrolls the display up by one row, clearing the bottom row.
    pub fn scroll_up(&mut self) {
        for row in 1..VGA_ROWS {
            for col in 0..VGA_COLS {
                let cell = self.read_cell(row, col);
                self.write_cell(row - 1, col, cell);
            }
        }
        let blank = vga_cell(b' ', self.attr);
        for col in 0..VGA_COLS {
            self.write_cell(VGA_ROWS - 1, col, blank);
        }
    }

    /// Advances the cursor to the next row, scrolling if necessary.
    fn newline(&mut self) {
        self.col = 0;
        self.row += 1;
        if self.row >= VGA_ROWS {
            self.scroll_up();
            self.row = VGA_ROWS - 1;
        }
    }

    /// Writes a single byte to the console at the current cursor position.
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.col = 0,
            b'\t' => {
                let next_tab = (self.col / 8 + 1) * 8;
                self.col = next_tab.min(VGA_COLS - 1);
            }
            _ => {
                self.write_cell(self.row, self.col, vga_cell(byte, self.attr));
                self.col += 1;
                if self.col >= VGA_COLS {
                    self.newline();
                }
            }
        }
    }

    /// Writes a byte slice to the console.
    pub fn write_bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.write_byte(b);
        }
    }

    /// Writes a string slice to the console.
    pub fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    /// Moves the hardware cursor to the current (row, col) position.
    ///
    /// Uses port I/O to update the CRTC cursor registers.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0. Port I/O to 0x3D4/0x3D5.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn update_cursor(&self) {
        let pos = (self.row * VGA_COLS + self.col) as u16;
        // SAFETY: CRTC port I/O is valid from ring 0.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") VGA_CRTC_INDEX,
                in("al") CRTC_CURSOR_HIGH,
                options(nomem, nostack),
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") VGA_CRTC_DATA,
                in("al") ((pos >> 8) as u8),
                options(nomem, nostack),
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") VGA_CRTC_INDEX,
                in("al") CRTC_CURSOR_LOW,
                options(nomem, nostack),
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") VGA_CRTC_DATA,
                in("al") (pos as u8),
                options(nomem, nostack),
            );
        }
    }

    /// Sets the text attribute for subsequent writes.
    pub fn set_attr(&mut self, fg: u8, bg: u8) {
        self.attr = vga_attr(fg, bg);
    }

    /// Returns the current cursor position as `(row, col)`.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Sets the cursor to `(row, col)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the position is out of bounds.
    pub fn set_cursor(&mut self, row: usize, col: usize) -> Result<()> {
        if row >= VGA_ROWS || col >= VGA_COLS {
            return Err(Error::InvalidArgument);
        }
        self.row = row;
        self.col = col;
        Ok(())
    }

    /// Writes a character with explicit attribute at a given position.
    pub fn put_char_at(&self, row: usize, col: usize, ch: u8, attr: u8) -> Result<()> {
        if row >= VGA_ROWS || col >= VGA_COLS {
            return Err(Error::InvalidArgument);
        }
        self.write_cell(row, col, vga_cell(ch, attr));
        Ok(())
    }
}
