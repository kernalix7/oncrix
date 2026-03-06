// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Framebuffer `/dev/fb0` driver.
//!
//! Provides a generic linear framebuffer abstraction over a memory-mapped
//! display buffer. Supports pixel formats RGB888 and ARGB8888, and provides
//! basic operations: fill_rect, copy_area, and image blit.
//!
//! # Pixel Formats
//!
//! | Format   | Bits/pixel | Layout (byte order, little-endian) |
//! |----------|-----------|-------------------------------------|
//! | RGB888   | 24        | R[7:0] G[7:0] B[7:0] (3 bytes)     |
//! | ARGB8888 | 32        | B G R A (4 bytes, little-endian)    |
//!
//! # Usage
//!
//! ```ignore
//! let mut fb = Framebuffer::new(info, buffer_phys);
//! fb.clear(Color::BLACK);
//! fb.fill_rect(10, 10, 100, 50, Color::RED);
//! ```
//!
//! Reference: Linux kernel `linux/fb.h`, fbdev API.

use oncrix_lib::{Error, Result};

// ── Pixel format ──────────────────────────────────────────────────────────────

/// Pixel color format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 24-bit RGB, packed as [R, G, B] per pixel.
    Rgb888,
    /// 32-bit ARGB, stored as 0xAARRGGBB (native endian).
    Argb8888,
}

impl PixelFormat {
    /// Bytes per pixel.
    pub fn bytes_per_pixel(self) -> usize {
        match self {
            PixelFormat::Rgb888 => 3,
            PixelFormat::Argb8888 => 4,
        }
    }

    /// Bits per pixel.
    pub fn bits_per_pixel(self) -> u32 {
        (self.bytes_per_pixel() * 8) as u32
    }
}

// ── Color ─────────────────────────────────────────────────────────────────────

/// 32-bit ARGB color (alpha, red, green, blue).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    /// Alpha channel (0 = transparent, 255 = opaque).
    pub a: u8,
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
}

impl Color {
    /// Create an opaque color.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { a: 0xFF, r, g, b }
    }

    /// Create an ARGB color.
    pub const fn argb(a: u8, r: u8, g: u8, b: u8) -> Self {
        Self { a, r, g, b }
    }

    /// Encode the color as a native-endian u32 (0xAARRGGBB).
    pub const fn as_argb32(self) -> u32 {
        ((self.a as u32) << 24) | ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Black (opaque).
    pub const BLACK: Self = Self::rgb(0, 0, 0);
    /// White (opaque).
    pub const WHITE: Self = Self::rgb(0xFF, 0xFF, 0xFF);
    /// Red (opaque).
    pub const RED: Self = Self::rgb(0xFF, 0, 0);
    /// Green (opaque).
    pub const GREEN: Self = Self::rgb(0, 0xFF, 0);
    /// Blue (opaque).
    pub const BLUE: Self = Self::rgb(0, 0, 0xFF);
}

// ── Framebuffer info ──────────────────────────────────────────────────────────

/// Framebuffer geometry and format information.
#[derive(Clone, Copy, Debug)]
pub struct FbInfo {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Bytes per scan line (stride). May be larger than `width * bpp`.
    pub stride: u32,
}

impl FbInfo {
    /// Create framebuffer info with tightly-packed stride.
    pub fn new(width: u32, height: u32, format: PixelFormat) -> Self {
        let bpp = format.bytes_per_pixel() as u32;
        Self {
            width,
            height,
            format,
            stride: width * bpp,
        }
    }

    /// Total framebuffer size in bytes.
    pub fn buffer_size(&self) -> usize {
        (self.stride as usize) * (self.height as usize)
    }

    /// Byte offset of pixel (x, y).
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        let bpp = self.format.bytes_per_pixel() as u32;
        (y * self.stride + x * bpp) as usize
    }
}

// ── Framebuffer ───────────────────────────────────────────────────────────────

/// Linear framebuffer backed by a physical memory-mapped buffer.
pub struct Framebuffer {
    info: FbInfo,
    /// Physical base address of the framebuffer memory.
    phys_base: u64,
}

impl Framebuffer {
    /// Create a framebuffer handle.
    ///
    /// `phys_base` is the physical address of the mapped display memory.
    /// The caller must ensure the region is accessible and mapped.
    pub fn new(info: FbInfo, phys_base: u64) -> Self {
        Self { info, phys_base }
    }

    /// Return the virtual (identity-mapped) pointer to the pixel at (x, y).
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region.
    #[inline]
    unsafe fn pixel_ptr(&self, x: u32, y: u32) -> *mut u8 {
        // SAFETY: caller guarantees phys_base is a valid mapped region.
        unsafe { (self.phys_base as *mut u8).add(self.info.pixel_offset(x, y)) }
    }

    /// Write a single pixel at (x, y) with `color`.
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region.
    pub unsafe fn write_pixel(&mut self, x: u32, y: u32, color: Color) -> Result<()> {
        if x >= self.info.width || y >= self.info.height {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: bounds checked above; phys_base is valid.
        unsafe {
            let ptr = self.pixel_ptr(x, y);
            match self.info.format {
                PixelFormat::Rgb888 => {
                    core::ptr::write_volatile(ptr, color.r);
                    core::ptr::write_volatile(ptr.add(1), color.g);
                    core::ptr::write_volatile(ptr.add(2), color.b);
                }
                PixelFormat::Argb8888 => {
                    let val = color.as_argb32();
                    core::ptr::write_volatile(ptr as *mut u32, val);
                }
            }
        }
        Ok(())
    }

    /// Fill a rectangle with `color`.
    ///
    /// Clips to framebuffer bounds.
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region.
    pub unsafe fn fill_rect(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        color: Color,
    ) -> Result<()> {
        let x_end = (x + width).min(self.info.width);
        let y_end = (y + height).min(self.info.height);
        if x >= self.info.width || y >= self.info.height {
            return Ok(());
        }
        for row in y..y_end {
            for col in x..x_end {
                // SAFETY: bounds checked; phys_base is valid.
                unsafe {
                    self.write_pixel(col, row, color)?;
                }
            }
        }
        Ok(())
    }

    /// Clear the entire framebuffer to `color`.
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region.
    pub unsafe fn clear(&mut self, color: Color) -> Result<()> {
        let w = self.info.width;
        let h = self.info.height;
        // SAFETY: phys_base is valid; fill_rect handles bounds.
        unsafe { self.fill_rect(0, 0, w, h, color) }
    }

    /// Copy a rectangular region from (src_x, src_y) to (dst_x, dst_y).
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region.
    pub unsafe fn copy_area(
        &mut self,
        src_x: u32,
        src_y: u32,
        dst_x: u32,
        dst_y: u32,
        width: u32,
        height: u32,
    ) -> Result<()> {
        if src_x + width > self.info.width
            || src_y + height > self.info.height
            || dst_x + width > self.info.width
            || dst_y + height > self.info.height
        {
            return Err(Error::InvalidArgument);
        }
        let bpp = self.info.format.bytes_per_pixel();
        let row_bytes = width as usize * bpp;
        let base = self.phys_base as *mut u8;

        // SAFETY: all coordinates are bounds-checked; base is valid.
        unsafe {
            // Copy direction: top-to-bottom if dst_y <= src_y, else bottom-to-top.
            if dst_y <= src_y {
                for row in 0..height {
                    let src_off = self.info.pixel_offset(src_x, src_y + row);
                    let dst_off = self.info.pixel_offset(dst_x, dst_y + row);
                    core::ptr::copy(base.add(src_off), base.add(dst_off), row_bytes);
                }
            } else {
                for row in (0..height).rev() {
                    let src_off = self.info.pixel_offset(src_x, src_y + row);
                    let dst_off = self.info.pixel_offset(dst_x, dst_y + row);
                    core::ptr::copy(base.add(src_off), base.add(dst_off), row_bytes);
                }
            }
        }
        Ok(())
    }

    /// Blit a packed RGB888 or ARGB8888 image at (dst_x, dst_y).
    ///
    /// `image_data` must have `width * height` pixels in the framebuffer's
    /// native format. Clips to display bounds.
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region; `image_data`
    /// must contain at least `img_width * img_height * bpp` bytes.
    pub unsafe fn image_blit(
        &mut self,
        dst_x: u32,
        dst_y: u32,
        img_width: u32,
        img_height: u32,
        image_data: &[u8],
    ) -> Result<()> {
        let bpp = self.info.format.bytes_per_pixel();
        let expected = img_width as usize * img_height as usize * bpp;
        if image_data.len() < expected {
            return Err(Error::InvalidArgument);
        }

        let copy_w = img_width.min(self.info.width.saturating_sub(dst_x));
        let copy_h = img_height.min(self.info.height.saturating_sub(dst_y));
        let row_bytes = copy_w as usize * bpp;
        let src_stride = img_width as usize * bpp;

        let base = self.phys_base as *mut u8;

        for row in 0..copy_h {
            let src_off = (row as usize) * src_stride;
            let dst_off = self.info.pixel_offset(dst_x, dst_y + row);
            // SAFETY: bounds checked; base and image_data are valid.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    image_data.as_ptr().add(src_off),
                    base.add(dst_off),
                    row_bytes,
                );
            }
        }
        Ok(())
    }

    /// Framebuffer geometry information.
    pub fn info(&self) -> &FbInfo {
        &self.info
    }

    /// Physical base address of the buffer.
    pub fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Width in pixels.
    pub fn width(&self) -> u32 {
        self.info.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u32 {
        self.info.height
    }

    /// Bytes per scan line.
    pub fn stride(&self) -> u32 {
        self.info.stride
    }

    /// Pixel format.
    pub fn format(&self) -> PixelFormat {
        self.info.format
    }

    /// Total buffer size in bytes.
    pub fn buffer_size(&self) -> usize {
        self.info.buffer_size()
    }
}

// ── FbRegistry ────────────────────────────────────────────────────────────────

/// Maximum number of framebuffer devices.
pub const MAX_FRAMEBUFFERS: usize = 4;

/// Registry of framebuffer devices (fb0..fbN).
pub struct FbRegistry {
    entries: [Option<Framebuffer>; MAX_FRAMEBUFFERS],
    count: usize,
}

impl FbRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_FRAMEBUFFERS],
            count: 0,
        }
    }

    /// Register a framebuffer. Returns the assigned fb index.
    pub fn register(&mut self, fb: Framebuffer) -> Result<usize> {
        if self.count >= MAX_FRAMEBUFFERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = Some(fb);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to fb at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Framebuffer> {
        self.entries.get_mut(index)?.as_mut()
    }

    /// Number of registered framebuffers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no framebuffers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
