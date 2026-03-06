// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic framebuffer driver.
//!
//! Provides a concrete framebuffer driver that wraps a raw memory-mapped
//! display buffer.  This driver is hardware-agnostic: any display subsystem
//! (VESA/UEFI GOP, VirtIO-GPU, PCI display) can populate a [`FbGenericInfo`]
//! and hand it to [`FbGeneric`] for unified pixel-level access.
//!
//! # Features
//!
//! - Pixel writing in multiple formats (RGB888, BGR888, RGBA8888, BGRA8888, RGB565)
//! - Rectangle fill (solid color)
//! - Horizontal line drawing
//! - Display clear (fill with single color)
//! - Double-buffer support (back buffer → front buffer blit)
//! - Up to [`MAX_FB_DEVICES`] registered framebuffers
//!
//! This module bridges between the generic `framebuffer.rs` abstraction and
//! concrete hardware-provided display surfaces.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously registered framebuffer devices.
pub const MAX_FB_DEVICES: usize = 4;

/// Maximum width in pixels supported by this driver.
pub const MAX_FB_WIDTH: u32 = 7680;
/// Maximum height in pixels supported by this driver.
pub const MAX_FB_HEIGHT: u32 = 4320;

// ---------------------------------------------------------------------------
// PixelFmt
// ---------------------------------------------------------------------------

/// Pixel encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFmt {
    /// 24-bit: Red, Green, Blue (1 byte each; typically padded to 32 bits).
    Rgb888,
    /// 24-bit: Blue, Green, Red.
    Bgr888,
    /// 32-bit: Red, Green, Blue, Alpha.
    Rgba8888,
    /// 32-bit: Blue, Green, Red, Alpha.
    Bgra8888,
    /// 16-bit: 5 bits red, 6 bits green, 5 bits blue.
    Rgb565,
}

impl PixelFmt {
    /// Return the number of bytes per pixel.
    pub const fn bytes_per_pixel(self) -> u32 {
        match self {
            PixelFmt::Rgb565 => 2,
            PixelFmt::Rgb888 | PixelFmt::Bgr888 => 3,
            PixelFmt::Rgba8888 | PixelFmt::Bgra8888 => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

/// 32-bit RGBA color value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Color {
    /// Red channel (0–255).
    pub r: u8,
    /// Green channel (0–255).
    pub g: u8,
    /// Blue channel (0–255).
    pub b: u8,
    /// Alpha channel (0 = transparent, 255 = opaque).
    pub a: u8,
}

impl Color {
    /// Create an opaque color from RGB values.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 0xFF }
    }

    /// Create an RGBA color.
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Encode this color as bytes for the given pixel format.
    ///
    /// Returns (bytes_used, raw_32bit_value) for efficient writing.
    pub fn encode(self, fmt: PixelFmt) -> u32 {
        match fmt {
            PixelFmt::Rgb888 | PixelFmt::Rgba8888 => {
                (self.r as u32)
                    | ((self.g as u32) << 8)
                    | ((self.b as u32) << 16)
                    | ((self.a as u32) << 24)
            }
            PixelFmt::Bgr888 | PixelFmt::Bgra8888 => {
                (self.b as u32)
                    | ((self.g as u32) << 8)
                    | ((self.r as u32) << 16)
                    | ((self.a as u32) << 24)
            }
            PixelFmt::Rgb565 => {
                let r5 = (self.r as u32 >> 3) & 0x1F;
                let g6 = (self.g as u32 >> 2) & 0x3F;
                let b5 = (self.b as u32 >> 3) & 0x1F;
                (r5 << 11) | (g6 << 5) | b5
            }
        }
    }

    /// Black.
    pub const BLACK: Color = Color::rgb(0, 0, 0);
    /// White.
    pub const WHITE: Color = Color::rgb(0xFF, 0xFF, 0xFF);
    /// Red.
    pub const RED: Color = Color::rgb(0xFF, 0, 0);
    /// Green.
    pub const GREEN: Color = Color::rgb(0, 0xFF, 0);
    /// Blue.
    pub const BLUE: Color = Color::rgb(0, 0, 0xFF);
}

// ---------------------------------------------------------------------------
// FbGenericInfo
// ---------------------------------------------------------------------------

/// Display surface descriptor provided by hardware-specific code.
#[derive(Debug, Clone, Copy)]
pub struct FbGenericInfo {
    /// Physical/virtual base address of the framebuffer memory.
    pub base: u64,
    /// Display width in pixels.
    pub width: u32,
    /// Display height in pixels.
    pub height: u32,
    /// Bytes per scan line (stride).
    pub stride: u32,
    /// Pixel format.
    pub format: PixelFmt,
}

impl FbGenericInfo {
    /// Return the total framebuffer size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.stride as u64 * self.height as u64
    }

    /// Return true if the given (x, y) pixel coordinate is within bounds.
    pub fn in_bounds(&self, x: u32, y: u32) -> bool {
        x < self.width && y < self.height
    }

    /// Compute the byte offset of pixel `(x, y)`.
    pub fn pixel_offset(&self, x: u32, y: u32) -> u64 {
        y as u64 * self.stride as u64 + x as u64 * self.format.bytes_per_pixel() as u64
    }
}

// ---------------------------------------------------------------------------
// FbGeneric
// ---------------------------------------------------------------------------

/// Generic framebuffer driver instance.
pub struct FbGeneric {
    /// Display descriptor.
    info: FbGenericInfo,
}

impl FbGeneric {
    /// Create a new [`FbGeneric`] from a descriptor.
    pub const fn new(info: FbGenericInfo) -> Self {
        Self { info }
    }

    /// Return the framebuffer descriptor.
    pub const fn info(&self) -> &FbGenericInfo {
        &self.info
    }

    /// Write a single pixel at `(x, y)` with the given `color`.
    pub fn write_pixel(&self, x: u32, y: u32, color: Color) -> Result<()> {
        if !self.info.in_bounds(x, y) {
            return Err(Error::InvalidArgument);
        }
        let offset = self.info.pixel_offset(x, y);
        let encoded = color.encode(self.info.format);
        // SAFETY: `offset` is within the mapped framebuffer region.
        unsafe { self.write_encoded(self.info.base + offset, encoded) };
        Ok(())
    }

    /// Fill a rectangle `(x0, y0, width, height)` with `color`.
    pub fn fill_rect(&self, x0: u32, y0: u32, w: u32, h: u32, color: Color) -> Result<()> {
        let x1 = x0.saturating_add(w).min(self.info.width);
        let y1 = y0.saturating_add(h).min(self.info.height);
        let encoded = color.encode(self.info.format);
        for y in y0..y1 {
            for x in x0..x1 {
                let off = self.info.pixel_offset(x, y);
                // SAFETY: x and y are bounded by display dimensions.
                unsafe { self.write_encoded(self.info.base + off, encoded) };
            }
        }
        Ok(())
    }

    /// Clear the entire display to `color`.
    pub fn clear(&self, color: Color) -> Result<()> {
        self.fill_rect(0, 0, self.info.width, self.info.height, color)
    }

    /// Draw a horizontal line from `(x0, y)` to `(x0 + len - 1, y)`.
    pub fn hline(&self, x0: u32, y: u32, len: u32, color: Color) -> Result<()> {
        if y >= self.info.height {
            return Err(Error::InvalidArgument);
        }
        let x1 = x0.saturating_add(len).min(self.info.width);
        let encoded = color.encode(self.info.format);
        for x in x0..x1 {
            let off = self.info.pixel_offset(x, y);
            // SAFETY: x and y are within display bounds.
            unsafe { self.write_encoded(self.info.base + off, encoded) };
        }
        Ok(())
    }

    /// Draw a vertical line from `(x, y0)` to `(x, y0 + len - 1)`.
    pub fn vline(&self, x: u32, y0: u32, len: u32, color: Color) -> Result<()> {
        if x >= self.info.width {
            return Err(Error::InvalidArgument);
        }
        let y1 = y0.saturating_add(len).min(self.info.height);
        let encoded = color.encode(self.info.format);
        for y in y0..y1 {
            let off = self.info.pixel_offset(x, y);
            // SAFETY: x and y are within display bounds.
            unsafe { self.write_encoded(self.info.base + off, encoded) };
        }
        Ok(())
    }

    /// Copy `src_fb` content to `self` (front-buffer blit from back buffer).
    ///
    /// Both framebuffers must have identical dimensions and format.
    pub fn blit_from(&self, src: &FbGeneric) -> Result<()> {
        if self.info.width != src.info.width
            || self.info.height != src.info.height
            || self.info.format != src.info.format
        {
            return Err(Error::InvalidArgument);
        }
        let bytes = self.info.size_bytes() as usize;
        // SAFETY: Both base addresses map display-sized regions of compatible layout.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.info.base as *const u8,
                self.info.base as *mut u8,
                bytes,
            );
        }
        Ok(())
    }

    // ---- Internal write helper -----------------------------------------------

    /// Write an encoded pixel value at an absolute byte address in the framebuffer.
    ///
    /// # Safety
    ///
    /// `addr` must be within the mapped framebuffer region and properly aligned
    /// for the pixel format's byte width.
    unsafe fn write_encoded(&self, addr: u64, val: u32) {
        match self.info.format.bytes_per_pixel() {
            2 => {
                // SAFETY: 2-byte write within framebuffer bounds.
                unsafe { core::ptr::write_volatile(addr as *mut u16, val as u16) };
            }
            3 => {
                // SAFETY: 3-byte write — write low 2 then high 1 byte.
                unsafe {
                    core::ptr::write_volatile(addr as *mut u16, val as u16);
                    core::ptr::write_volatile((addr + 2) as *mut u8, (val >> 16) as u8);
                }
            }
            _ => {
                // SAFETY: 4-byte write within framebuffer bounds.
                unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FbRegistry
// ---------------------------------------------------------------------------

/// Registry of up to [`MAX_FB_DEVICES`] registered framebuffer devices.
pub struct FbRegistry {
    devices: [Option<FbGeneric>; MAX_FB_DEVICES],
    count: usize,
}

impl FbRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_FB_DEVICES],
            count: 0,
        }
    }

    /// Register a new framebuffer device.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the registry is full.
    pub fn register(&mut self, fb: FbGeneric) -> Result<usize> {
        if self.count >= MAX_FB_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let id = self.count;
        self.devices[id] = Some(fb);
        self.count += 1;
        Ok(id)
    }

    /// Get a reference to a registered framebuffer by index.
    pub fn get(&self, id: usize) -> Option<&FbGeneric> {
        self.devices.get(id)?.as_ref()
    }

    /// Get a mutable reference to a registered framebuffer by index.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut FbGeneric> {
        self.devices.get_mut(id)?.as_mut()
    }

    /// Return the number of registered framebuffers.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return true if no framebuffers are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
