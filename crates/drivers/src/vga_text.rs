// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VGA text mode driver.
//!
//! Implements the classic 80x25 VGA text mode interface present on all
//! PC-compatible systems. The text buffer is memory-mapped at physical
//! address 0xB8000 and provides 16 foreground and background colors.
//! Hardware cursor position is controlled via the VGA CRT controller.

use oncrix_lib::{Error, Result};

/// Physical address of the VGA text framebuffer.
pub const VGA_BUFFER_PHYS: usize = 0x000B_8000;

/// Standard VGA text mode dimensions.
pub const VGA_COLS: usize = 80;
pub const VGA_ROWS: usize = 25;
pub const VGA_CELLS: usize = VGA_COLS * VGA_ROWS;

/// VGA CRT Controller I/O ports.
const VGA_CRTC_INDEX: u16 = 0x3D4;
const VGA_CRTC_DATA: u16 = 0x3D5;

/// CRT Controller register indices.
const CRTC_CURSOR_HIGH: u8 = 0x0E;
const CRTC_CURSOR_LOW: u8 = 0x0F;
const CRTC_START_HIGH: u8 = 0x0C;
const CRTC_START_LOW: u8 = 0x0D;
const CRTC_CURSOR_START: u8 = 0x0A;
const CRTC_CURSOR_END: u8 = 0x0B;

/// Cursor start/end values for a standard underline cursor.
const CURSOR_SCANLINE_START: u8 = 14;
const CURSOR_SCANLINE_END: u8 = 15;
const CURSOR_ENABLE: u8 = 0x00; // Bit 5 = 0 enables cursor
const CURSOR_DISABLE: u8 = 0x20; // Bit 5 = 1 disables cursor

/// VGA color codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// A VGA character cell: character byte + attribute byte.
/// Attribute byte = (background << 4) | foreground.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VgaCell {
    /// ASCII character.
    pub character: u8,
    /// Color attribute.
    pub attribute: u8,
}

impl VgaCell {
    /// Create a new VGA cell with the given character and colors.
    pub const fn new(character: u8, fg: Color, bg: Color) -> Self {
        Self {
            character,
            attribute: ((bg as u8) << 4) | (fg as u8),
        }
    }

    /// Blank cell (space, default colors).
    pub const fn blank() -> Self {
        Self::new(b' ', Color::LightGray, Color::Black)
    }
}

impl Default for VgaCell {
    fn default() -> Self {
        Self::blank()
    }
}

/// VGA text mode driver.
pub struct VgaText {
    /// Pointer to the VGA framebuffer (mapped at VGA_BUFFER_PHYS).
    buffer: *mut VgaCell,
    /// Current cursor column (0-based).
    col: usize,
    /// Current cursor row (0-based).
    row: usize,
    /// Default foreground color.
    fg: Color,
    /// Default background color.
    bg: Color,
}

// SAFETY: VgaText only holds a raw pointer to hardware-mapped memory.
// All accesses are through volatile writes, and the driver is intended for
// single-threaded early-boot or console use.
unsafe impl Send for VgaText {}

impl VgaText {
    /// Create a new VGA text driver using the standard physical buffer address.
    ///
    /// # Safety
    /// Caller must ensure the VGA framebuffer is accessible at `VGA_BUFFER_PHYS`.
    /// On x86_64 systems this is always the case in the first 1 MiB identity map.
    pub unsafe fn new(buffer_virt: usize) -> Self {
        Self {
            // SAFETY: Caller guarantees buffer_virt maps to a valid VGA framebuffer.
            buffer: buffer_virt as *mut VgaCell,
            col: 0,
            row: 0,
            fg: Color::LightGray,
            bg: Color::Black,
        }
    }

    /// Initialize the driver: clear screen, enable cursor.
    pub fn init(&mut self) {
        self.clear();
        self.enable_cursor();
        self.update_hw_cursor();
    }

    /// Set the default text colors.
    pub fn set_colors(&mut self, fg: Color, bg: Color) {
        self.fg = fg;
        self.bg = bg;
    }

    /// Write a single character to the current cursor position.
    pub fn write_char(&mut self, c: char) {
        match c {
            '\n' => self.newline(),
            '\r' => {
                self.col = 0;
            }
            '\t' => {
                let next_tab = (self.col + 8) & !7;
                for _ in self.col..next_tab.min(VGA_COLS) {
                    self.put_cell(b' ');
                }
            }
            '\x08' => {
                // Backspace
                if self.col > 0 {
                    self.col -= 1;
                    self.put_char_at(b' ', self.row, self.col);
                }
            }
            _ => {
                let byte = if (c as u32) < 128 { c as u8 } else { b'?' };
                self.put_cell(byte);
            }
        }
        self.update_hw_cursor();
    }

    /// Write a string slice to the terminal.
    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.write_char(c);
        }
    }

    /// Clear the entire screen with the current background color.
    pub fn clear(&mut self) {
        for row in 0..VGA_ROWS {
            for col in 0..VGA_COLS {
                self.put_char_at(b' ', row, col);
            }
        }
        self.col = 0;
        self.row = 0;
    }

    /// Move the cursor to a specific position.
    pub fn set_cursor(&mut self, row: usize, col: usize) -> Result<()> {
        if row >= VGA_ROWS || col >= VGA_COLS {
            return Err(Error::InvalidArgument);
        }
        self.row = row;
        self.col = col;
        self.update_hw_cursor();
        Ok(())
    }

    /// Return the current cursor position as (row, col).
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Enable the hardware blinking underline cursor.
    pub fn enable_cursor(&mut self) {
        self.crtc_write(CRTC_CURSOR_START, CURSOR_ENABLE | CURSOR_SCANLINE_START);
        self.crtc_write(CRTC_CURSOR_END, CURSOR_SCANLINE_END);
    }

    /// Disable (hide) the hardware cursor.
    pub fn disable_cursor(&mut self) {
        self.crtc_write(CRTC_CURSOR_START, CURSOR_DISABLE);
    }

    /// Put a single ASCII byte at the current position and advance cursor.
    fn put_cell(&mut self, byte: u8) {
        if self.col >= VGA_COLS {
            self.newline();
        }
        let (row, col) = (self.row, self.col);
        self.put_char_at(byte, row, col);
        self.col += 1;
    }

    /// Write a character to a specific (row, col) using the current colors.
    fn put_char_at(&mut self, byte: u8, row: usize, col: usize) {
        let cell = VgaCell::new(byte, self.fg, self.bg);
        let index = row * VGA_COLS + col;
        // SAFETY: index is within [0, VGA_CELLS); buffer points to a
        // hardware-mapped VGA framebuffer requiring volatile writes.
        unsafe {
            core::ptr::write_volatile(self.buffer.add(index), cell);
        }
    }

    /// Advance to the next line, scrolling if necessary.
    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < VGA_ROWS {
            self.row += 1;
        } else {
            self.scroll_up();
        }
    }

    /// Scroll all lines up by one, clearing the bottom line.
    fn scroll_up(&mut self) {
        for row in 1..VGA_ROWS {
            for col in 0..VGA_COLS {
                let src = row * VGA_COLS + col;
                let dst = (row - 1) * VGA_COLS + col;
                // SAFETY: Both src and dst are within [0, VGA_CELLS) and
                // the buffer is a valid hardware-mapped framebuffer.
                let cell = unsafe { core::ptr::read_volatile(self.buffer.add(src)) };
                unsafe { core::ptr::write_volatile(self.buffer.add(dst), cell) };
            }
        }
        // Clear the last line.
        for col in 0..VGA_COLS {
            let dst = (VGA_ROWS - 1) * VGA_COLS + col;
            // SAFETY: dst is within [0, VGA_CELLS).
            unsafe { core::ptr::write_volatile(self.buffer.add(dst), VgaCell::blank()) };
        }
        self.row = VGA_ROWS - 1;
    }

    /// Synchronize the hardware cursor register with the current position.
    fn update_hw_cursor(&mut self) {
        let pos = self.row * VGA_COLS + self.col;
        self.crtc_write(CRTC_CURSOR_HIGH, ((pos >> 8) & 0xFF) as u8);
        self.crtc_write(CRTC_CURSOR_LOW, (pos & 0xFF) as u8);
    }

    /// Write to a VGA CRT Controller register.
    fn crtc_write(&mut self, index: u8, value: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: VGA_CRTC_INDEX (0x3D4) and VGA_CRTC_DATA (0x3D5) are
        // standard VGA CRT controller ports present on all PC hardware.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") VGA_CRTC_INDEX,
                in("al") index,
                options(nomem, nostack)
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") VGA_CRTC_DATA,
                in("al") value,
                options(nomem, nostack)
            );
        }
    }
}
