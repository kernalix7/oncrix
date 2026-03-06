// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic framebuffer abstraction layer.
//!
//! Provides a hardware-independent framebuffer interface with support
//! for multiple pixel formats, basic 2D drawing primitives, and a
//! registry for managing up to [`_MAX_FRAMEBUFFERS`] framebuffer
//! instances.
//!
//! This module is intended as the common abstraction consumed by
//! higher-level graphics subsystems (console, window manager) while
//! concrete drivers (VESA, virtio-gpu, etc.) populate [`FbInfo`]
//! from hardware-specific discovery.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of framebuffers the registry can hold.
const _MAX_FRAMEBUFFERS: usize = 4;

/// Maximum framebuffer size in bytes (16 MiB).
const _MAX_FB_SIZE: usize = 16 * 1024 * 1024;

/// Default display DPI (dots per inch).
const _DEFAULT_DPI: u32 = 96;

/// Size of the inline pixel buffer used for testing.
const INLINE_BUF_SIZE: usize = 4096;

// -------------------------------------------------------------------
// PixelFormat
// -------------------------------------------------------------------

/// Pixel encoding format for a framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PixelFormat {
    /// 24-bit RGB, 8 bits per channel.
    #[default]
    Rgb888,
    /// 24-bit BGR, 8 bits per channel.
    Bgr888,
    /// 32-bit RGBA, 8 bits per channel.
    Rgba8888,
    /// 32-bit BGRA, 8 bits per channel.
    Bgra8888,
    /// 16-bit RGB (5-6-5 layout).
    Rgb565,
    /// 8-bit indexed (palette) color.
    Indexed8,
}

impl PixelFormat {
    /// Return the number of bytes required per pixel.
    pub const fn bytes_per_pixel(&self) -> usize {
        match self {
            Self::Rgb888 | Self::Bgr888 => 3,
            Self::Rgba8888 | Self::Bgra8888 => 4,
            Self::Rgb565 => 2,
            Self::Indexed8 => 1,
        }
    }
}

// -------------------------------------------------------------------
// Color
// -------------------------------------------------------------------

/// An RGBA color with 8-bit components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha component (0 = transparent, 255 = opaque).
    pub a: u8,
}

impl Default for Color {
    fn default() -> Self {
        Self::black()
    }
}

impl Color {
    /// Create an opaque color from RGB components.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 0xFF }
    }

    /// Create a color from RGBA components.
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Return an opaque black color.
    pub const fn black() -> Self {
        Self {
            r: 0,
            g: 0,
            b: 0,
            a: 0xFF,
        }
    }

    /// Return an opaque white color.
    pub const fn white() -> Self {
        Self {
            r: 0xFF,
            g: 0xFF,
            b: 0xFF,
            a: 0xFF,
        }
    }

    /// Encode the color as a 3-byte RGB888 array.
    pub const fn to_rgb888(&self) -> [u8; 3] {
        [self.r, self.g, self.b]
    }

    /// Encode the color as a 4-byte RGBA8888 array.
    pub const fn to_rgba8888(&self) -> [u8; 4] {
        [self.r, self.g, self.b, self.a]
    }

    /// Encode the color as a 16-bit RGB565 value.
    ///
    /// Layout: `RRRRR_GGGGGG_BBBBB` (5-6-5 bits).
    pub const fn to_rgb565(&self) -> u16 {
        let r = (self.r as u16 >> 3) & 0x1F;
        let g = (self.g as u16 >> 2) & 0x3F;
        let b = (self.b as u16 >> 3) & 0x1F;
        (r << 11) | (g << 5) | b
    }
}

// -------------------------------------------------------------------
// FbMode
// -------------------------------------------------------------------

/// Framebuffer display mode descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FbMode {
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Bytes per scan line (may exceed width * bpp / 8).
    pub pitch: u32,
    /// Pixel encoding format.
    pub pixel_format: PixelFormat,
    /// Bits per pixel.
    pub bpp: u8,
}

impl FbMode {
    /// Total framebuffer size in bytes (`pitch * height`).
    pub const fn framebuffer_size(&self) -> usize {
        (self.pitch as usize).saturating_mul(self.height as usize)
    }
}

// -------------------------------------------------------------------
// FbInfo
// -------------------------------------------------------------------

/// Framebuffer information block.
///
/// Describes a single framebuffer device including its display mode,
/// memory addresses, and identification.
#[derive(Debug, Clone, Copy, Default)]
pub struct FbInfo {
    /// Current display mode.
    pub mode: FbMode,
    /// Physical base address of the framebuffer memory.
    pub phys_addr: u64,
    /// Virtual base address of the mapped framebuffer memory.
    pub virt_addr: u64,
    /// Size of the framebuffer region in bytes.
    pub size: u64,
    /// Numeric identifier (0-based).
    pub id: u8,
    /// Human-readable name (UTF-8 fragment, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Whether this framebuffer is currently active.
    pub active: bool,
}

// -------------------------------------------------------------------
// Framebuffer
// -------------------------------------------------------------------

/// A generic framebuffer with an inline pixel buffer for testing.
///
/// The inline buffer is [`INLINE_BUF_SIZE`] bytes (4 KiB). Drawing
/// operations that would exceed the buffer are silently clipped.
pub struct Framebuffer {
    /// Framebuffer metadata.
    info: FbInfo,
    /// Inline pixel storage (stub for testing).
    buffer: [u8; INLINE_BUF_SIZE],
    /// Whether the buffer has been modified since the last
    /// [`mark_clean`](Self::mark_clean) call.
    dirty: bool,
    /// Text cursor X position (pixels).
    cursor_x: u32,
    /// Text cursor Y position (pixels).
    cursor_y: u32,
}

impl Framebuffer {
    /// Create a new framebuffer from the given info descriptor.
    pub fn new(info: FbInfo) -> Self {
        Self {
            info,
            buffer: [0u8; INLINE_BUF_SIZE],
            dirty: false,
            cursor_x: 0,
            cursor_y: 0,
        }
    }

    /// Write a single pixel at `(x, y)`.
    ///
    /// Returns `Err(InvalidArgument)` if the coordinates are
    /// outside the framebuffer dimensions.
    pub fn put_pixel(&mut self, x: u32, y: u32, color: Color) -> Result<()> {
        let w = self.info.mode.width;
        let h = self.info.mode.height;
        if x >= w || y >= h {
            return Err(Error::InvalidArgument);
        }

        let bpp = self.info.mode.pixel_format.bytes_per_pixel();
        let offset = (y as usize)
            .saturating_mul(self.info.mode.pitch as usize)
            .saturating_add((x as usize).saturating_mul(bpp));

        self.write_pixel(offset, &color);
        self.dirty = true;
        Ok(())
    }

    /// Fill a rectangle starting at `(x, y)` with size `w x h`.
    ///
    /// Returns `Err(InvalidArgument)` if the rectangle origin is
    /// outside the framebuffer dimensions.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) -> Result<()> {
        let fb_w = self.info.mode.width;
        let fb_h = self.info.mode.height;
        if x >= fb_w || y >= fb_h {
            return Err(Error::InvalidArgument);
        }
        let x_end = x.saturating_add(w).min(fb_w);
        let y_end = y.saturating_add(h).min(fb_h);

        let mut cy = y;
        while cy < y_end {
            let mut cx = x;
            while cx < x_end {
                let bpp = self.info.mode.pixel_format.bytes_per_pixel();
                let off = (cy as usize)
                    .saturating_mul(self.info.mode.pitch as usize)
                    .saturating_add((cx as usize).saturating_mul(bpp));
                self.write_pixel(off, &color);
                cx += 1;
            }
            cy += 1;
        }
        self.dirty = true;
        Ok(())
    }

    /// Clear the entire framebuffer to the given color.
    pub fn clear(&mut self, color: Color) {
        let w = self.info.mode.width;
        let h = self.info.mode.height;
        if w == 0 || h == 0 {
            return;
        }
        // Fill every pixel row by row.
        let bpp = self.info.mode.pixel_format.bytes_per_pixel();
        let pitch = self.info.mode.pitch as usize;
        let mut y: u32 = 0;
        while y < h {
            let mut x: u32 = 0;
            while x < w {
                let off = (y as usize)
                    .saturating_mul(pitch)
                    .saturating_add((x as usize).saturating_mul(bpp));
                self.write_pixel(off, &color);
                x += 1;
            }
            y += 1;
        }
        self.dirty = true;
    }

    /// Scroll the framebuffer content up by `lines` pixel rows.
    ///
    /// The vacated bottom rows are filled with black.
    pub fn scroll_up(&mut self, lines: u32) {
        let h = self.info.mode.height;
        if lines == 0 || h == 0 {
            return;
        }
        if lines >= h {
            self.clear(Color::black());
            return;
        }
        let pitch = self.info.mode.pitch as usize;
        let shift = (lines as usize).saturating_mul(pitch);
        let total = (h as usize).saturating_mul(pitch);
        let copy_len = total.saturating_sub(shift);

        if copy_len > 0 && shift < total && total <= INLINE_BUF_SIZE {
            // Copy rows forward within the inline buffer.
            let mut i: usize = 0;
            while i < copy_len {
                if i < INLINE_BUF_SIZE && i + shift < INLINE_BUF_SIZE {
                    self.buffer[i] = self.buffer[i + shift];
                }
                i += 1;
            }
            // Zero the vacated region.
            let clear_start = copy_len;
            let mut j = clear_start;
            while j < total && j < INLINE_BUF_SIZE {
                self.buffer[j] = 0;
                j += 1;
            }
        }
        self.dirty = true;
    }

    /// Copy a rectangular region within the framebuffer.
    ///
    /// Copies the `w x h` rectangle at `(src_x, src_y)` to
    /// `(dst_x, dst_y)`. Both source and destination must be
    /// within bounds.
    pub fn copy_rect(
        &mut self,
        src_x: u32,
        src_y: u32,
        dst_x: u32,
        dst_y: u32,
        w: u32,
        h: u32,
    ) -> Result<()> {
        let fb_w = self.info.mode.width;
        let fb_h = self.info.mode.height;

        if src_x.saturating_add(w) > fb_w
            || src_y.saturating_add(h) > fb_h
            || dst_x.saturating_add(w) > fb_w
            || dst_y.saturating_add(h) > fb_h
        {
            return Err(Error::InvalidArgument);
        }

        let bpp = self.info.mode.pixel_format.bytes_per_pixel();
        let pitch = self.info.mode.pitch as usize;

        // Use a temporary row buffer to handle overlapping regions.
        // We process one row at a time; max row payload is bounded
        // by the inline buffer width which is small for testing.
        let row_bytes = (w as usize).saturating_mul(bpp);

        // Determine row iteration order for safe overlap handling.
        let (row_start, row_end, row_step_fwd) = if dst_y > src_y {
            // Copy bottom-to-top.
            (h.saturating_sub(1), 0u32, false)
        } else {
            (0u32, h.saturating_sub(1), true)
        };

        let mut row = row_start;
        loop {
            let sy = src_y.saturating_add(row) as usize;
            let dy = dst_y.saturating_add(row) as usize;
            let src_off = sy
                .saturating_mul(pitch)
                .saturating_add((src_x as usize).saturating_mul(bpp));
            let dst_off = dy
                .saturating_mul(pitch)
                .saturating_add((dst_x as usize).saturating_mul(bpp));

            // Copy via temporary storage to handle overlap.
            let mut tmp = [0u8; 128];
            let copy_len = row_bytes.min(tmp.len());
            let mut i = 0;
            while i < copy_len {
                let si = src_off.saturating_add(i);
                if si < INLINE_BUF_SIZE {
                    tmp[i] = self.buffer[si];
                }
                i += 1;
            }
            i = 0;
            while i < copy_len {
                let di = dst_off.saturating_add(i);
                if di < INLINE_BUF_SIZE {
                    self.buffer[di] = tmp[i];
                }
                i += 1;
            }

            if row == row_end {
                break;
            }
            if row_step_fwd {
                row += 1;
            } else {
                row -= 1;
            }
        }

        self.dirty = true;
        Ok(())
    }

    /// Return the current display mode.
    pub const fn mode(&self) -> &FbMode {
        &self.info.mode
    }

    /// Return whether the framebuffer has been modified.
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Reset the dirty flag to `false`.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    /// Write pixel data at `offset` into the inline buffer.
    fn write_pixel(&mut self, offset: usize, color: &Color) {
        match self.info.mode.pixel_format {
            PixelFormat::Rgb888 => {
                let bytes = color.to_rgb888();
                self.write_bytes(offset, &bytes);
            }
            PixelFormat::Bgr888 => {
                let bytes = [color.b, color.g, color.r];
                self.write_bytes(offset, &bytes);
            }
            PixelFormat::Rgba8888 => {
                let bytes = color.to_rgba8888();
                self.write_bytes(offset, &bytes);
            }
            PixelFormat::Bgra8888 => {
                let bytes = [color.b, color.g, color.r, color.a];
                self.write_bytes(offset, &bytes);
            }
            PixelFormat::Rgb565 => {
                let val = color.to_rgb565();
                let bytes = val.to_le_bytes();
                self.write_bytes(offset, &bytes);
            }
            PixelFormat::Indexed8 => {
                self.write_bytes(offset, &[color.r]);
            }
        }
    }

    /// Write a byte slice into the inline buffer at `offset`,
    /// silently clipping if the write would exceed the buffer.
    fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let pos = offset.saturating_add(i);
            if pos < INLINE_BUF_SIZE {
                self.buffer[pos] = data[i];
            }
            i += 1;
        }
    }
}

impl core::fmt::Debug for Framebuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Framebuffer")
            .field("info", &self.info)
            .field("dirty", &self.dirty)
            .field("cursor_x", &self.cursor_x)
            .field("cursor_y", &self.cursor_y)
            .finish()
    }
}

// -------------------------------------------------------------------
// FbRegistry
// -------------------------------------------------------------------

/// Registry of framebuffer devices.
///
/// Holds up to [`_MAX_FRAMEBUFFERS`] [`Framebuffer`] instances and
/// provides lookup by index.
pub struct FbRegistry {
    /// Storage for registered framebuffers.
    fbs: [Option<Framebuffer>; _MAX_FRAMEBUFFERS],
    /// Number of registered framebuffers.
    count: usize,
}

impl FbRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            fbs: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a new framebuffer.
    ///
    /// Returns `Err(OutOfMemory)` if the registry is full.
    /// Returns `Err(AlreadyExists)` if a framebuffer with the
    /// same `id` is already registered.
    pub fn register(&mut self, fb: Framebuffer) -> Result<()> {
        // Check for duplicate id.
        let mut i = 0;
        while i < _MAX_FRAMEBUFFERS {
            if let Some(ref existing) = self.fbs[i] {
                if existing.info.id == fb.info.id {
                    return Err(Error::AlreadyExists);
                }
            }
            i += 1;
        }

        // Find a free slot.
        let mut j = 0;
        while j < _MAX_FRAMEBUFFERS {
            if self.fbs[j].is_none() {
                self.fbs[j] = Some(fb);
                self.count += 1;
                return Ok(());
            }
            j += 1;
        }

        Err(Error::OutOfMemory)
    }

    /// Return a reference to the framebuffer at the given index.
    ///
    /// Returns `Err(NotFound)` if no framebuffer occupies that
    /// slot.
    pub fn get(&self, index: usize) -> Result<&Framebuffer> {
        if index >= _MAX_FRAMEBUFFERS {
            return Err(Error::InvalidArgument);
        }
        self.fbs[index].as_ref().ok_or(Error::NotFound)
    }

    /// Return a mutable reference to the framebuffer at the given
    /// index.
    ///
    /// Returns `Err(NotFound)` if no framebuffer occupies that
    /// slot.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut Framebuffer> {
        if index >= _MAX_FRAMEBUFFERS {
            return Err(Error::InvalidArgument);
        }
        self.fbs[index].as_mut().ok_or(Error::NotFound)
    }

    /// Return a reference to the first active framebuffer.
    ///
    /// Returns `Err(NotFound)` if no active framebuffer exists.
    pub fn primary(&self) -> Result<&Framebuffer> {
        let mut i = 0;
        while i < _MAX_FRAMEBUFFERS {
            if let Some(ref fb) = self.fbs[i] {
                if fb.info.active {
                    return Ok(fb);
                }
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered framebuffers.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no framebuffers are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for FbRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for FbRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FbRegistry")
            .field("count", &self.count)
            .finish()
    }
}
