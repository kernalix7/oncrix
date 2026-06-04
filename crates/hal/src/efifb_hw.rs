// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EFI framebuffer hardware abstraction.
//!
//! Provides access to the linear framebuffer set up by UEFI GOP
//! (Graphics Output Protocol) before the OS takes over. The framebuffer
//! remains usable until a native GPU driver takes control.

use oncrix_lib::{Error, Result};

/// Pixel format reported by UEFI GOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit: 0xRRGGBBxx (red high).
    Rgbx32,
    /// 32-bit: 0xBBGGRRxx (blue high, common on most x86 hardware).
    Bgrx32,
    /// Custom bitmask format.
    BitMask,
    /// No pixel output (headless or unsupported).
    BltOnly,
}

/// Pixel bitmask (used when `PixelFormat::BitMask` is reported).
#[derive(Debug, Clone, Copy, Default)]
pub struct PixelBitmask {
    /// Red channel mask.
    pub red: u32,
    /// Green channel mask.
    pub green: u32,
    /// Blue channel mask.
    pub blue: u32,
    /// Reserved bits.
    pub reserved: u32,
}

/// EFI framebuffer descriptor passed from the bootloader.
#[derive(Debug, Clone, Copy)]
pub struct EfiFbInfo {
    /// Physical base address of the framebuffer.
    pub fb_base: u64,
    /// Total framebuffer size in bytes.
    pub fb_size: usize,
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Pixels per scan-line (may be > width for alignment).
    pub stride: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Bitmask (valid when format == BitMask).
    pub bitmask: PixelBitmask,
}

impl Default for EfiFbInfo {
    fn default() -> Self {
        Self {
            fb_base: 0,
            fb_size: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: PixelFormat::Bgrx32,
            bitmask: PixelBitmask::default(),
        }
    }
}

/// A packed BGRA pixel (4 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Pixel {
    /// Blue channel.
    pub b: u8,
    /// Green channel.
    pub g: u8,
    /// Red channel.
    pub r: u8,
    /// Unused / alpha (ignored).
    pub x: u8,
}

impl Pixel {
    /// Creates a pixel from RGB values.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, x: 0 }
    }

    /// Encodes this pixel to a 32-bit word according to `format`.
    pub fn encode(self, format: PixelFormat) -> u32 {
        match format {
            PixelFormat::Rgbx32 => {
                ((self.r as u32) << 24) | ((self.g as u32) << 16) | ((self.b as u32) << 8)
            }
            PixelFormat::Bgrx32 | PixelFormat::BitMask | PixelFormat::BltOnly => {
                ((self.b as u32) << 16) | ((self.g as u32) << 8) | (self.r as u32)
            }
        }
    }
}

/// EFI framebuffer driver.
pub struct EfiFb {
    info: EfiFbInfo,
}

impl EfiFb {
    /// Creates a new EFI framebuffer driver from the given info.
    pub const fn new(info: EfiFbInfo) -> Self {
        Self { info }
    }

    /// Returns the framebuffer info.
    pub fn info(&self) -> &EfiFbInfo {
        &self.info
    }

    /// Returns the framebuffer width × height in pixels.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.info.width, self.info.height)
    }

    /// Returns the total framebuffer size in bytes.
    pub fn fb_size(&self) -> usize {
        self.info.fb_size
    }

    /// Writes a single pixel at `(x, y)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the coordinate is out of bounds,
    /// if any offset arithmetic overflows, or if the computed write range
    /// exceeds the declared framebuffer size (possible when `stride > width`).
    pub fn put_pixel(&self, x: u32, y: u32, pixel: Pixel) -> Result<()> {
        if x >= self.info.width || y >= self.info.height {
            return Err(Error::InvalidArgument);
        }
        // Widen to usize before multiplying to prevent u32 overflow.
        let row_start = (y as usize)
            .checked_mul(self.info.stride as usize)
            .ok_or(Error::InvalidArgument)?;
        let pixel_off = row_start
            .checked_add(x as usize)
            .ok_or(Error::InvalidArgument)?;
        let byte_off = pixel_off.checked_mul(4).ok_or(Error::InvalidArgument)?;
        // Guard the write against the real framebuffer byte length.
        // stride > width is a valid GOP configuration and means x < width does
        // NOT guarantee byte_off + 4 <= fb_size.
        let write_end = byte_off.checked_add(4).ok_or(Error::InvalidArgument)?;
        if write_end > self.info.fb_size {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.info.fb_base as usize)
            .checked_add(byte_off)
            .ok_or(Error::InvalidArgument)?;
        let ptr = addr as *mut u32;
        // SAFETY: fb_base is a valid mapped framebuffer. byte_off + 4 <= fb_size
        // (checked above) guarantees the write stays within the mapped region.
        unsafe { core::ptr::write_volatile(ptr, pixel.encode(self.info.format)) };
        Ok(())
    }

    /// Fills a rectangle with `pixel`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the rectangle is out of bounds,
    /// if any offset arithmetic overflows, or if any computed write range
    /// exceeds the declared framebuffer size (possible when `stride > width`).
    pub fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, pixel: Pixel) -> Result<()> {
        // Use saturating_add in the guard so that x + w or y + h cannot wrap around
        // and silently pass a rectangle that extends beyond the framebuffer edge.
        if x.saturating_add(w) > self.info.width || y.saturating_add(h) > self.info.height {
            return Err(Error::InvalidArgument);
        }
        let encoded = pixel.encode(self.info.format);
        for row in y..y + h {
            for col in x..x + w {
                // Widen to usize before multiplying to prevent u32 overflow.
                let row_start = (row as usize)
                    .checked_mul(self.info.stride as usize)
                    .ok_or(Error::InvalidArgument)?;
                let pixel_off = row_start
                    .checked_add(col as usize)
                    .ok_or(Error::InvalidArgument)?;
                let byte_off = pixel_off.checked_mul(4).ok_or(Error::InvalidArgument)?;
                // Guard the write against the real framebuffer byte length.
                // stride > width is a valid GOP config; dimension checks alone
                // do not prevent writes past fb_size.
                let write_end = byte_off.checked_add(4).ok_or(Error::InvalidArgument)?;
                if write_end > self.info.fb_size {
                    return Err(Error::InvalidArgument);
                }
                let addr = (self.info.fb_base as usize)
                    .checked_add(byte_off)
                    .ok_or(Error::InvalidArgument)?;
                let ptr = addr as *mut u32;
                // SAFETY: fb_base is a valid mapped framebuffer. byte_off + 4 <=
                // fb_size (checked above) guarantees the write stays within the
                // mapped region.
                unsafe { core::ptr::write_volatile(ptr, encoded) };
            }
        }
        Ok(())
    }

    /// Clears the entire framebuffer to `pixel`.
    pub fn clear(&self, pixel: Pixel) -> Result<()> {
        self.fill_rect(0, 0, self.info.width, self.info.height, pixel)
    }

    /// Copies a row of pixels from `src` (BGRX format) into the framebuffer.
    ///
    /// `src` must have exactly `width` elements.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `y` is out of bounds, `src` length
    /// does not match the framebuffer width, any offset arithmetic overflows, or
    /// any write range exceeds the declared framebuffer size.
    pub fn blit_row(&self, y: u32, src: &[Pixel]) -> Result<()> {
        if y >= self.info.height {
            return Err(Error::InvalidArgument);
        }
        if src.len() != self.info.width as usize {
            return Err(Error::InvalidArgument);
        }
        for (x, &px) in src.iter().enumerate() {
            // Widen to usize before multiplying to prevent u32 overflow.
            let row_start = (y as usize)
                .checked_mul(self.info.stride as usize)
                .ok_or(Error::InvalidArgument)?;
            let pixel_off = row_start.checked_add(x).ok_or(Error::InvalidArgument)?;
            let byte_off = pixel_off.checked_mul(4).ok_or(Error::InvalidArgument)?;
            // Guard the write against the real framebuffer byte length.
            // stride > width is a valid GOP config; src.len() == width alone
            // does not prevent writes past fb_size.
            let write_end = byte_off.checked_add(4).ok_or(Error::InvalidArgument)?;
            if write_end > self.info.fb_size {
                return Err(Error::InvalidArgument);
            }
            let addr = (self.info.fb_base as usize)
                .checked_add(byte_off)
                .ok_or(Error::InvalidArgument)?;
            let ptr = addr as *mut u32;
            // SAFETY: fb_base is a valid mapped framebuffer. byte_off + 4 <=
            // fb_size (checked above) guarantees the write stays within the
            // mapped region.
            unsafe { core::ptr::write_volatile(ptr, px.encode(self.info.format)) };
        }
        Ok(())
    }

    /// Returns a raw mutable pointer to the start of the framebuffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that all accesses are within the framebuffer
    /// bounds (`fb_size()` bytes from the returned pointer).
    pub unsafe fn raw_ptr(&self) -> *mut u8 {
        self.info.fb_base as *mut u8
    }
}

impl Default for EfiFb {
    fn default() -> Self {
        Self::new(EfiFbInfo::default())
    }
}

/// Returns a human-readable string for a [`PixelFormat`].
pub fn pixel_format_name(fmt: PixelFormat) -> &'static str {
    match fmt {
        PixelFormat::Rgbx32 => "RGBX32",
        PixelFormat::Bgrx32 => "BGRX32",
        PixelFormat::BitMask => "BitMask",
        PixelFormat::BltOnly => "BltOnly",
    }
}
