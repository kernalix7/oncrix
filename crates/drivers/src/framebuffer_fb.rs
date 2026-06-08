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
    ///
    /// Returns `Err(InvalidArgument)` if the geometry would overflow or if `bpp` is zero
    /// (degenerate mode that would make every pixel alias offset 0).
    // SECURITY: firmware/GOP may supply crafted width/height/bpp; reject zero bpp (degenerate
    // stride=0 means all pixels alias the same address) and reject width*bpp overflow before
    // storing the stride.
    pub fn new(width: u32, height: u32, format: PixelFormat) -> Result<Self> {
        let bpp = format.bytes_per_pixel() as u32;
        // bpp is derived from the enum so it is always 3 or 4; the check is a safety net in case
        // the enum grows a zero-byte variant.
        if bpp == 0 {
            return Err(Error::InvalidArgument);
        }
        // SECURITY: checked_mul prevents width*bpp overflow from producing a truncated stride
        // that would later cause pixel_offset to compute an in-bounds-looking but wrong offset.
        let stride = width.checked_mul(bpp).ok_or(Error::InvalidArgument)?;
        Ok(Self {
            width,
            height,
            format,
            stride,
        })
    }

    /// Total framebuffer size in bytes.
    ///
    /// Returns `Err(InvalidArgument)` if `stride * height` overflows `usize`.
    // SECURITY: firmware/GOP-supplied stride and height may each be up to u32::MAX; their
    // product can overflow usize on 32-bit targets or with malicious values on 64-bit targets.
    pub fn buffer_size(&self) -> Result<usize> {
        (self.stride as usize)
            .checked_mul(self.height as usize)
            .ok_or(Error::InvalidArgument)
    }

    /// Byte offset of pixel (x, y).
    ///
    /// Returns `Err(InvalidArgument)` on arithmetic overflow or if `(x, y)` is out of bounds.
    // SECURITY: each intermediate product (y*stride, x*bpp) can overflow independently even
    // when x < width and y < height for large firmware-supplied strides.
    pub fn pixel_offset(&self, x: u32, y: u32) -> Result<usize> {
        if x >= self.width || y >= self.height {
            return Err(Error::InvalidArgument);
        }
        let bpp = self.format.bytes_per_pixel() as usize;
        let row = (y as usize)
            .checked_mul(self.stride as usize)
            .ok_or(Error::InvalidArgument)?;
        let col = (x as usize)
            .checked_mul(bpp)
            .ok_or(Error::InvalidArgument)?;
        row.checked_add(col).ok_or(Error::InvalidArgument)
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
    /// `phys_base` must be a valid mapped framebuffer region and `(x, y)` must
    /// be within framebuffer bounds (enforced by the `Result` return).
    #[inline]
    unsafe fn pixel_ptr(&self, x: u32, y: u32) -> Result<*mut u8> {
        let off = self.info.pixel_offset(x, y)?;
        // SAFETY: caller guarantees phys_base is a valid mapped region; offset is bounds-checked.
        Ok(unsafe { (self.phys_base as *mut u8).add(off) })
    }

    /// Write a single pixel at (x, y) with `color`.
    ///
    /// # Safety
    /// `phys_base` must be a valid mapped framebuffer region.
    pub unsafe fn write_pixel(&mut self, x: u32, y: u32, color: Color) -> Result<()> {
        // pixel_ptr performs bounds + overflow checks internally.
        // SAFETY: phys_base is valid; pixel_ptr returns Ok only if offset is within bounds.
        unsafe {
            let ptr = self.pixel_ptr(x, y)?;
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
    /// Clips to framebuffer bounds. Returns early (no-op) if the rectangle
    /// origin is outside the framebuffer.
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
        if x >= self.info.width || y >= self.info.height {
            return Ok(());
        }
        // SECURITY: saturating_add prevents x+width / y+height overflow before the .min() clamp;
        // a crafted large width/height would otherwise wrap to a small value and pass the clamp.
        let x_end = x.saturating_add(width).min(self.info.width);
        let y_end = y.saturating_add(height).min(self.info.height);
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
    /// Returns `Err(InvalidArgument)` if any corner of either rectangle lies outside
    /// the framebuffer or if arithmetic overflows.
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
        // SECURITY: checked_add prevents src_x+width / src_y+height overflow that would produce
        // a small value passing the > comparison and allowing an out-of-bounds memcpy.
        let src_x_end = src_x.checked_add(width).ok_or(Error::InvalidArgument)?;
        let src_y_end = src_y.checked_add(height).ok_or(Error::InvalidArgument)?;
        let dst_x_end = dst_x.checked_add(width).ok_or(Error::InvalidArgument)?;
        let dst_y_end = dst_y.checked_add(height).ok_or(Error::InvalidArgument)?;
        if src_x_end > self.info.width
            || src_y_end > self.info.height
            || dst_x_end > self.info.width
            || dst_y_end > self.info.height
        {
            return Err(Error::InvalidArgument);
        }
        let bpp = self.info.format.bytes_per_pixel();
        // SECURITY: width is bounded by framebuffer width (max ~8K pixels); bpp is 3 or 4;
        // product fits in usize.  Use checked_mul anyway to be defensive.
        let row_bytes = (width as usize)
            .checked_mul(bpp)
            .ok_or(Error::InvalidArgument)?;
        let base = self.phys_base as *mut u8;

        // SAFETY: all coordinates are bounds-checked; pixel_offset returns Ok only for valid
        // in-bounds positions; base is a valid mapped framebuffer region.
        unsafe {
            // Copy direction: top-to-bottom if dst_y <= src_y, else bottom-to-top.
            if dst_y <= src_y {
                for row in 0..height {
                    let src_off = self.info.pixel_offset(src_x, src_y + row)?;
                    let dst_off = self.info.pixel_offset(dst_x, dst_y + row)?;
                    core::ptr::copy(base.add(src_off), base.add(dst_off), row_bytes);
                }
            } else {
                for row in (0..height).rev() {
                    let src_off = self.info.pixel_offset(src_x, src_y + row)?;
                    let dst_off = self.info.pixel_offset(dst_x, dst_y + row)?;
                    core::ptr::copy(base.add(src_off), base.add(dst_off), row_bytes);
                }
            }
        }
        Ok(())
    }

    /// Blit a packed RGB888 or ARGB8888 image at (dst_x, dst_y).
    ///
    /// `image_data` must have `img_width * img_height` pixels in the framebuffer's
    /// native format. The region is clipped to display bounds.
    ///
    /// Returns `Err(InvalidArgument)` if `image_data` is shorter than the computed
    /// expected size, or if any geometry product overflows.
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
        // SECURITY: img_width * img_height * bpp can overflow usize when firmware/GOP supplies
        // large crafted image dimensions.  Use chained checked_mul to reject overflow before
        // using the product as a slice-length guard.
        let expected = (img_width as usize)
            .checked_mul(img_height as usize)
            .and_then(|n| n.checked_mul(bpp))
            .ok_or(Error::InvalidArgument)?;
        if image_data.len() < expected {
            return Err(Error::InvalidArgument);
        }

        let copy_w = img_width.min(self.info.width.saturating_sub(dst_x));
        let copy_h = img_height.min(self.info.height.saturating_sub(dst_y));
        // SECURITY: row_bytes and src_stride computed with checked_mul; both are bounded by the
        // expected-size check above, but we re-check defensively.
        let row_bytes = (copy_w as usize)
            .checked_mul(bpp)
            .ok_or(Error::InvalidArgument)?;
        let src_stride = (img_width as usize)
            .checked_mul(bpp)
            .ok_or(Error::InvalidArgument)?;

        let base = self.phys_base as *mut u8;

        for row in 0..copy_h {
            // SECURITY: row * src_stride checked to prevent overflow in the source index.
            let src_off = (row as usize)
                .checked_mul(src_stride)
                .ok_or(Error::InvalidArgument)?;
            let dst_off = self.info.pixel_offset(dst_x, dst_y + row)?;
            // SAFETY: src_off + row_bytes <= expected <= image_data.len(); dst_off is within
            // the mapped framebuffer region (pixel_offset enforces bounds).
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
    ///
    /// Returns `Err(InvalidArgument)` if `stride * height` overflows `usize`.
    pub fn buffer_size(&self) -> Result<usize> {
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
