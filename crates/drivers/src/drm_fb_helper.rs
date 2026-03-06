// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM framebuffer helper (drm_fb_helper).
//!
//! Provides a generic framebuffer helper layer inspired by the Linux
//! DRM fbdev emulation (`drm_fb_helper`). Bridges DRM-managed display
//! hardware to a simple framebuffer interface used by the early console
//! and splash-screen subsystems before a full compositor is available.
//!
//! # Architecture
//!
//! ```text
//! Early console / splash screen
//!       │  blit / fill / draw_char
//!       ▼
//! DrmFbHelper
//!       │  flush_rect() → DrmFramebuffer (VRAM mapping)
//!       ▼
//! DRM plane / CRTC commit
//!       ▼
//! Display hardware (HDMI / DP / eDP)
//! ```
//!
//! # Pixel Format Support
//!
//! - `Xrgb8888` — 32-bit, blue in byte 0, alpha ignored.
//! - `Argb8888` — 32-bit, premultiplied alpha.
//! - `Rgb565`  — 16-bit packed RGB.
//!
//! # Usage
//!
//! ```ignore
//! let mut helper = DrmFbHelper::new(fb_vaddr, width, height, pitch, PixelFormat::Xrgb8888);
//! helper.fill_rect(0, 0, width, height, 0x001F_1F1F)?; // dark background
//! helper.draw_char(8, 8, b'A', 0x00FF_FFFF, 0x0000_0000)?;
//! helper.flush_rect(0, 0, width, height)?;
//! ```

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────

/// Width of the built-in 8×16 font glyph in pixels.
const FONT_WIDTH: u32 = 8;
/// Height of the built-in 8×16 font glyph in pixels.
const FONT_HEIGHT: u32 = 16;
/// Number of characters in the built-in font (ASCII 32–127).
const FONT_CHARS: usize = 96;
/// Maximum framebuffers managed by a single helper.
const MAX_FRAMEBUFFERS: usize = 4;

// ── Pixel Format ──────────────────────────────────────────────

/// Framebuffer pixel format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit XRGB8888 (byte order: B G R X).
    Xrgb8888,
    /// 32-bit ARGB8888 (byte order: B G R A).
    Argb8888,
    /// 16-bit RGB565 (5R 6G 5B packed, big-endian).
    Rgb565,
}

impl PixelFormat {
    /// Return the number of bytes per pixel.
    pub const fn bytes_per_pixel(&self) -> u32 {
        match self {
            Self::Xrgb8888 | Self::Argb8888 => 4,
            Self::Rgb565 => 2,
        }
    }

    /// Encode an XRGB color `(0x00RRGGBB)` into the native pixel value.
    pub const fn encode(&self, color: u32) -> u32 {
        match self {
            Self::Xrgb8888 | Self::Argb8888 => color,
            Self::Rgb565 => {
                let r = (color >> 16) & 0xFF;
                let g = (color >> 8) & 0xFF;
                let b = color & 0xFF;
                ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            }
        }
    }
}

// ── Framebuffer Descriptor ────────────────────────────────────

/// Describes a single DRM-backed framebuffer.
#[derive(Debug, Clone, Copy)]
pub struct DrmFramebuffer {
    /// Kernel virtual address of the framebuffer pixel data.
    pub vaddr: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pitch (stride) in bytes per scanline.
    pub pitch: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Whether this framebuffer slot is occupied.
    pub occupied: bool,
}

impl Default for DrmFramebuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DrmFramebuffer {
    /// Create an empty (unoccupied) framebuffer descriptor.
    pub const fn new() -> Self {
        Self {
            vaddr: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Xrgb8888,
            occupied: false,
        }
    }

    /// Compute the total framebuffer size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.pitch as u64 * self.height as u64
    }

    /// Return whether the given rectangle is within bounds.
    pub const fn rect_in_bounds(&self, x: u32, y: u32, w: u32, h: u32) -> bool {
        x + w <= self.width && y + h <= self.height
    }
}

// ── Dirty Rectangle Tracking ──────────────────────────────────

/// Axis-aligned bounding rectangle for dirty region tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyRect {
    /// Left edge (inclusive).
    pub x1: u32,
    /// Top edge (inclusive).
    pub y1: u32,
    /// Right edge (exclusive).
    pub x2: u32,
    /// Bottom edge (exclusive).
    pub y2: u32,
    /// Whether the dirty rectangle is non-empty.
    pub valid: bool,
}

impl DirtyRect {
    /// Expand the dirty rectangle to include the given region.
    pub fn expand(&mut self, x: u32, y: u32, w: u32, h: u32) {
        if !self.valid {
            self.x1 = x;
            self.y1 = y;
            self.x2 = x + w;
            self.y2 = y + h;
            self.valid = true;
        } else {
            if x < self.x1 {
                self.x1 = x;
            }
            if y < self.y1 {
                self.y1 = y;
            }
            if x + w > self.x2 {
                self.x2 = x + w;
            }
            if y + h > self.y2 {
                self.y2 = y + h;
            }
        }
    }

    /// Clear the dirty rectangle.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Return the width of the dirty region.
    pub const fn width(&self) -> u32 {
        self.x2.saturating_sub(self.x1)
    }

    /// Return the height of the dirty region.
    pub const fn height(&self) -> u32 {
        self.y2.saturating_sub(self.y1)
    }
}

// ── Helper Statistics ─────────────────────────────────────────

/// Per-helper rendering statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FbHelperStats {
    /// Total fill_rect calls.
    pub fill_rects: u64,
    /// Total copy_rect calls.
    pub copy_rects: u64,
    /// Total draw_char calls.
    pub draw_chars: u64,
    /// Total flush_rect calls.
    pub flushes: u64,
    /// Total pixels written.
    pub pixels_written: u64,
}

// ── Built-In 8×16 Font ────────────────────────────────────────

/// Minimal 8×16 bitmap font for ASCII 32–127.
///
/// Each character is stored as 16 bytes, one byte per scanline
/// (bit 7 = leftmost pixel, bit 0 = rightmost).
/// This is a subset covering printable ASCII for early console use.
static FONT_DATA: [[u8; 16]; FONT_CHARS] = generate_font();

const fn generate_font() -> [[u8; 16]; FONT_CHARS] {
    // Minimal stub font — all zeros except space and a few characters.
    // A real implementation would embed a full VGA font bitmap here.
    let mut f = [[0u8; 16]; FONT_CHARS];

    // 'A' (ASCII 65, index 33 in font)
    f[33] = [
        0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    // 'B' (ASCII 66, index 34)
    f[34] = [
        0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    // '0' (ASCII 48, index 16)
    f[16] = [
        0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    f
}

// ── DRM FB Helper ─────────────────────────────────────────────

/// DRM framebuffer helper for early display and fbdev emulation.
///
/// Wraps a linear framebuffer and provides high-level drawing
/// operations (fill, copy, text rendering). Tracks a dirty
/// rectangle for efficient flushing.
pub struct DrmFbHelper {
    /// Registered framebuffer descriptors.
    framebuffers: [DrmFramebuffer; MAX_FRAMEBUFFERS],
    /// Number of registered framebuffers.
    fb_count: usize,
    /// Index of the active (primary) framebuffer.
    active_fb: usize,
    /// Accumulated dirty rectangle since the last flush.
    dirty: DirtyRect,
    /// Rendering statistics.
    stats: FbHelperStats,
}

impl DrmFbHelper {
    /// Create a new DRM framebuffer helper with a single initial
    /// framebuffer.
    ///
    /// # Arguments
    ///
    /// * `vaddr` — Kernel virtual address of the framebuffer.
    /// * `width` — Width in pixels.
    /// * `height` — Height in pixels.
    /// * `pitch` — Pitch (stride) in bytes per scanline.
    /// * `format` — Pixel format.
    pub fn new(vaddr: u64, width: u32, height: u32, pitch: u32, format: PixelFormat) -> Self {
        let mut fbs = [DrmFramebuffer::new(); MAX_FRAMEBUFFERS];
        fbs[0] = DrmFramebuffer {
            vaddr,
            width,
            height,
            pitch,
            format,
            occupied: true,
        };
        Self {
            framebuffers: fbs,
            fb_count: 1,
            active_fb: 0,
            dirty: DirtyRect::default(),
            stats: FbHelperStats::default(),
        }
    }

    /// Register an additional framebuffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// framebuffers is already registered.
    pub fn register_fb(
        &mut self,
        vaddr: u64,
        width: u32,
        height: u32,
        pitch: u32,
        format: PixelFormat,
    ) -> Result<usize> {
        if self.fb_count >= MAX_FRAMEBUFFERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.fb_count;
        self.framebuffers[idx] = DrmFramebuffer {
            vaddr,
            width,
            height,
            pitch,
            format,
            occupied: true,
        };
        self.fb_count += 1;
        Ok(idx)
    }

    /// Switch to a different framebuffer as the active one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn set_active_fb(&mut self, idx: usize) -> Result<()> {
        if idx >= self.fb_count || !self.framebuffers[idx].occupied {
            return Err(Error::InvalidArgument);
        }
        self.active_fb = idx;
        Ok(())
    }

    /// Fill a rectangle with a solid color.
    ///
    /// # Arguments
    ///
    /// * `x`, `y` — Top-left corner of the rectangle.
    /// * `w`, `h` — Width and height in pixels.
    /// * `color` — Fill color in 0x00RRGGBB format.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the rectangle extends
    /// outside the framebuffer bounds.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) -> Result<()> {
        let fb = &self.framebuffers[self.active_fb];
        if !fb.rect_in_bounds(x, y, w, h) {
            return Err(Error::InvalidArgument);
        }

        let encoded = fb.format.encode(color);
        let bpp = fb.format.bytes_per_pixel();
        let vaddr = fb.vaddr;
        let pitch = fb.pitch;

        for row in 0..h {
            let line_off = (y + row) as u64 * pitch as u64 + x as u64 * bpp as u64;
            for col in 0..w {
                let off = line_off + col as u64 * bpp as u64;
                self.write_pixel(vaddr + off, encoded, bpp);
            }
        }

        self.dirty.expand(x, y, w, h);
        self.stats.fill_rects += 1;
        self.stats.pixels_written += (w * h) as u64;
        Ok(())
    }

    /// Copy a rectangular region within the framebuffer.
    ///
    /// Handles overlapping source and destination by choosing
    /// direction (ascending or descending scan order).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if either rectangle is out
    /// of bounds.
    pub fn copy_rect(
        &mut self,
        dst_x: u32,
        dst_y: u32,
        src_x: u32,
        src_y: u32,
        w: u32,
        h: u32,
    ) -> Result<()> {
        let fb = &self.framebuffers[self.active_fb];
        if !fb.rect_in_bounds(dst_x, dst_y, w, h) || !fb.rect_in_bounds(src_x, src_y, w, h) {
            return Err(Error::InvalidArgument);
        }

        let bpp = fb.format.bytes_per_pixel() as u64;
        let pitch = fb.pitch as u64;
        let vaddr = fb.vaddr;

        if dst_y <= src_y {
            for row in 0..h {
                let src_off = (src_y + row) as u64 * pitch + src_x as u64 * bpp;
                let dst_off = (dst_y + row) as u64 * pitch + dst_x as u64 * bpp;
                for col in 0..w {
                    let pix = self.read_pixel(vaddr + src_off + col as u64 * bpp, bpp as u32);
                    self.write_pixel(vaddr + dst_off + col as u64 * bpp, pix, bpp as u32);
                }
            }
        } else {
            for row in (0..h).rev() {
                let src_off = (src_y + row) as u64 * pitch + src_x as u64 * bpp;
                let dst_off = (dst_y + row) as u64 * pitch + dst_x as u64 * bpp;
                for col in (0..w).rev() {
                    let pix = self.read_pixel(vaddr + src_off + col as u64 * bpp, bpp as u32);
                    self.write_pixel(vaddr + dst_off + col as u64 * bpp, pix, bpp as u32);
                }
            }
        }

        self.dirty.expand(dst_x, dst_y, w, h);
        self.stats.copy_rects += 1;
        self.stats.pixels_written += (w * h) as u64;
        Ok(())
    }

    /// Draw a single ASCII character using the built-in 8×16 font.
    ///
    /// # Arguments
    ///
    /// * `x`, `y` — Top-left corner of the glyph cell.
    /// * `ch` — ASCII character byte (32–127; others rendered as space).
    /// * `fg` — Foreground color (0x00RRGGBB).
    /// * `bg` — Background color (0x00RRGGBB).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the glyph cell extends
    /// outside the framebuffer.
    pub fn draw_char(&mut self, x: u32, y: u32, ch: u8, fg: u32, bg: u32) -> Result<()> {
        let fb = &self.framebuffers[self.active_fb];
        if !fb.rect_in_bounds(x, y, FONT_WIDTH, FONT_HEIGHT) {
            return Err(Error::InvalidArgument);
        }

        let font_idx = if ch >= 32 && ch < 128 {
            (ch - 32) as usize
        } else {
            0
        };
        let glyph = &FONT_DATA[font_idx];

        let fg_enc = fb.format.encode(fg);
        let bg_enc = fb.format.encode(bg);
        let bpp = fb.format.bytes_per_pixel();
        let pitch = fb.pitch as u64;
        let vaddr = fb.vaddr;

        for row in 0..FONT_HEIGHT {
            let bits = glyph[row as usize];
            let line_off = (y + row) as u64 * pitch + x as u64 * bpp as u64;
            for col in 0..FONT_WIDTH {
                let set = bits & (0x80 >> col) != 0;
                let pix = if set { fg_enc } else { bg_enc };
                let off = line_off + col as u64 * bpp as u64;
                self.write_pixel(vaddr + off, pix, bpp);
            }
        }

        self.dirty.expand(x, y, FONT_WIDTH, FONT_HEIGHT);
        self.stats.draw_chars += 1;
        self.stats.pixels_written += (FONT_WIDTH * FONT_HEIGHT) as u64;
        Ok(())
    }

    /// Draw a string of ASCII characters starting at `(x, y)`.
    ///
    /// Advances `x` by `FONT_WIDTH` for each character. Does not
    /// wrap lines. Characters that would fall out of bounds are
    /// silently skipped.
    pub fn draw_string(&mut self, x: u32, y: u32, s: &[u8], fg: u32, bg: u32) {
        let mut cx = x;
        for &ch in s {
            if cx + FONT_WIDTH > self.active_fb_width() {
                break;
            }
            let _ = self.draw_char(cx, y, ch, fg, bg);
            cx += FONT_WIDTH;
        }
    }

    /// Acknowledge a display flush for the given rectangle.
    ///
    /// In a real DRM driver this would trigger a plane update and
    /// CRTC commit. Here it clears the corresponding dirty region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the rectangle is out of
    /// bounds.
    pub fn flush_rect(&mut self, x: u32, y: u32, w: u32, h: u32) -> Result<()> {
        let fb = &self.framebuffers[self.active_fb];
        if !fb.rect_in_bounds(x, y, w, h) {
            return Err(Error::InvalidArgument);
        }
        // Clear dirty tracking for the flushed region (simplified: clear all).
        self.dirty.clear();
        self.stats.flushes += 1;
        Ok(())
    }

    /// Flush the entire accumulated dirty rectangle.
    ///
    /// No-op if nothing is dirty.
    pub fn flush_dirty(&mut self) {
        if !self.dirty.valid {
            return;
        }
        let x = self.dirty.x1;
        let y = self.dirty.y1;
        let w = self.dirty.width();
        let h = self.dirty.height();
        let _ = self.flush_rect(x, y, w, h);
    }

    // ── Private helpers ────────────────────────────────────────

    fn write_pixel(&self, addr: u64, value: u32, bpp: u32) {
        match bpp {
            4 => {
                // SAFETY: addr is within the framebuffer VRAM mapping, which is
                // a kernel virtual address backed by display memory. Writes are
                // 32-bit volatile to prevent the compiler from coalescing them.
                unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
            }
            2 => {
                // SAFETY: same as above; 16-bit write for RGB565.
                unsafe { core::ptr::write_volatile(addr as *mut u16, value as u16) }
            }
            _ => {}
        }
    }

    fn read_pixel(&self, addr: u64, bpp: u32) -> u32 {
        match bpp {
            4 => {
                // SAFETY: addr is within the framebuffer VRAM mapping. Volatile
                // read prevents the compiler from caching the value.
                unsafe { core::ptr::read_volatile(addr as *const u32) }
            }
            2 => {
                // SAFETY: same as above; 16-bit volatile read.
                unsafe { core::ptr::read_volatile(addr as *const u16) as u32 }
            }
            _ => 0,
        }
    }

    fn active_fb_width(&self) -> u32 {
        self.framebuffers[self.active_fb].width
    }

    // ── Accessors ──────────────────────────────────────────────

    /// Return a reference to the active framebuffer descriptor.
    pub fn active_framebuffer(&self) -> &DrmFramebuffer {
        &self.framebuffers[self.active_fb]
    }

    /// Return the accumulated dirty rectangle.
    pub const fn dirty_rect(&self) -> &DirtyRect {
        &self.dirty
    }

    /// Return accumulated rendering statistics.
    pub const fn stats(&self) -> &FbHelperStats {
        &self.stats
    }

    /// Return the number of registered framebuffers.
    pub const fn fb_count(&self) -> usize {
        self.fb_count
    }

    /// Return the index of the active framebuffer.
    pub const fn active_fb_index(&self) -> usize {
        self.active_fb
    }
}
