// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VESA/VBE framebuffer driver.
//!
//! Implements a VESA BIOS Extensions (VBE 2.0+) framebuffer driver for
//! display output. The driver operates on a linear framebuffer that has
//! been configured by the bootloader during real-mode initialization.
//!
//! This module provides:
//! - VBE controller and mode information blocks
//! - A linear framebuffer abstraction with pixel/rect/blit/scroll ops
//! - A text console rendered via an 8x16 bitmap font
//! - Double buffering for tear-free rendering
//!
//! Reference: VESA BIOS Extensions Core Functions Standard v3.0.

use oncrix_lib::{Error, Result};

use crate::virtio_gpu::{FONT_8X16, FONT_HEIGHT, FONT_WIDTH, Framebuffer, PixelFormat};

// -----------------------------------------------------------------------
// Standard VBE video mode constants
// -----------------------------------------------------------------------

/// VBE mode number for 640x480 at 8 bpp (indexed color).
pub const VBE_MODE_640X480X8: u16 = 0x101;

/// VBE mode number for 800x600 at 8 bpp (indexed color).
pub const VBE_MODE_800X600X8: u16 = 0x103;

/// VBE mode number for 1024x768 at 8 bpp (indexed color).
pub const VBE_MODE_1024X768X8: u16 = 0x105;

/// VBE mode number for 1280x1024 at 8 bpp (indexed color).
pub const VBE_MODE_1280X1024X8: u16 = 0x107;

/// VBE mode number for 640x480 at 16 bpp.
pub const VBE_MODE_640X480X16: u16 = 0x111;

/// VBE mode number for 800x600 at 16 bpp.
pub const VBE_MODE_800X600X16: u16 = 0x114;

/// VBE mode number for 1024x768 at 16 bpp.
pub const VBE_MODE_1024X768X16: u16 = 0x117;

/// VBE mode number for 1280x1024 at 16 bpp.
pub const VBE_MODE_1280X1024X16: u16 = 0x11A;

/// VBE mode number for 640x480 at 24 bpp.
pub const VBE_MODE_640X480X24: u16 = 0x112;

/// VBE mode number for 800x600 at 24 bpp.
pub const VBE_MODE_800X600X24: u16 = 0x115;

/// VBE mode number for 1024x768 at 24 bpp.
pub const VBE_MODE_1024X768X24: u16 = 0x118;

/// VBE mode number for 1280x1024 at 24 bpp.
pub const VBE_MODE_1280X1024X24: u16 = 0x11B;

/// VBE signature bytes: `VESA` in ASCII.
pub const VBE_SIGNATURE: [u8; 4] = [b'V', b'E', b'S', b'A'];

/// Maximum number of mode entries we track in [`VbeInfoBlock`].
const MAX_VIDEO_MODES: usize = 64;

// -----------------------------------------------------------------------
// VbePixelFormat — VESA-specific pixel format enumeration
// -----------------------------------------------------------------------

/// Pixel format for VESA framebuffer modes.
///
/// Extends the basic [`PixelFormat`] with additional formats
/// relevant to VBE mode information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VbePixelFormat {
    /// 24-bit RGB (red, green, blue), 8 bits each.
    #[default]
    Rgb888,
    /// 24-bit BGR (blue, green, red), 8 bits each.
    Bgr888,
    /// 32-bit RGBA (red, green, blue, alpha), 8 bits each.
    Rgba8888,
    /// 32-bit BGRA (blue, green, red, alpha), 8 bits each.
    Bgra8888,
    /// 8-bit indexed (palette) color.
    Indexed,
}

impl VbePixelFormat {
    /// Return the number of bytes per pixel for this format.
    pub const fn bytes_per_pixel(self) -> u32 {
        match self {
            Self::Rgb888 | Self::Bgr888 => 3,
            Self::Rgba8888 | Self::Bgra8888 => 4,
            Self::Indexed => 1,
        }
    }

    /// Convert to the common [`PixelFormat`] used by the framebuffer.
    ///
    /// Returns `Err(InvalidArgument)` for formats that have no direct
    /// mapping (e.g., `Indexed`).
    pub const fn to_pixel_format(self) -> Result<PixelFormat> {
        match self {
            Self::Rgb888 => Ok(PixelFormat::Rgb888),
            Self::Rgba8888 => Ok(PixelFormat::Rgba8888),
            Self::Bgra8888 | Self::Bgr888 => Ok(PixelFormat::Bgra8888),
            Self::Indexed => Err(Error::InvalidArgument),
        }
    }
}

// -----------------------------------------------------------------------
// Color
// -----------------------------------------------------------------------

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
        Self::new()
    }
}

impl Color {
    /// Create a new fully-transparent black color.
    pub const fn new() -> Self {
        Self {
            r: 0,
            g: 0,
            b: 0,
            a: 0,
        }
    }

    /// Create an opaque color from RGB components.
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 0xFF }
    }

    /// Create a color from RGBA components.
    pub const fn from_rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Pack the color into a `u32` in RGBA byte order: `0xRRGGBBAA`.
    ///
    /// This matches the pixel encoding expected by [`Framebuffer`].
    pub const fn to_u32(self) -> u32 {
        (self.r as u32) << 24 | (self.g as u32) << 16 | (self.b as u32) << 8 | self.a as u32
    }

    /// Unpack a `u32` in `0xRRGGBBAA` format into a [`Color`].
    pub const fn from_u32(val: u32) -> Self {
        Self {
            r: (val >> 24) as u8,
            g: (val >> 16) as u8,
            b: (val >> 8) as u8,
            a: val as u8,
        }
    }
}

// -----------------------------------------------------------------------
// VbeInfoBlock — VBE controller information (512 bytes)
// -----------------------------------------------------------------------

/// VBE controller information block.
///
/// Returned by VBE Function 00h (Return VBE Controller Information).
/// This is a 512-byte structure starting with the `VESA` signature.
///
/// In ONCRIX, the bootloader populates this block during early
/// initialization and passes it to the kernel via the boot info
/// structure.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct VbeInfoBlock {
    /// VBE signature, must be `VESA` (`[0x56, 0x45, 0x53, 0x41]`).
    pub signature: [u8; 4],
    /// VBE version (BCD). 0x0300 = VBE 3.0, 0x0200 = VBE 2.0.
    pub version: u16,
    /// Reserved field (originally far pointer to OEM string).
    pub oem_string_off: u16,
    /// Reserved field (segment of OEM string pointer).
    pub oem_string_seg: u16,
    /// Capability flags (bit 0: DAC width switchable).
    pub capabilities: u32,
    /// Reserved field (originally far pointer to mode list).
    pub video_mode_list_off: u16,
    /// Reserved field (segment of mode list pointer).
    pub video_mode_list_seg: u16,
    /// Total memory in 64 KiB blocks.
    pub total_memory_64k: u16,
    /// Software revision level.
    pub software_rev: u16,
    /// Reserved bytes to pad to 512 bytes total.
    pub reserved: [u8; 488],
}

impl Default for VbeInfoBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl VbeInfoBlock {
    /// Create a zeroed VBE info block (no valid signature).
    pub const fn new() -> Self {
        Self {
            signature: [0u8; 4],
            version: 0,
            oem_string_off: 0,
            oem_string_seg: 0,
            capabilities: 0,
            video_mode_list_off: 0,
            video_mode_list_seg: 0,
            total_memory_64k: 0,
            software_rev: 0,
            reserved: [0u8; 488],
        }
    }

    /// Check whether the signature is valid (`VESA`).
    pub const fn is_valid(&self) -> bool {
        self.signature[0] == b'V'
            && self.signature[1] == b'E'
            && self.signature[2] == b'S'
            && self.signature[3] == b'A'
    }

    /// Return the VBE major version number.
    pub const fn version_major(&self) -> u8 {
        (self.version >> 8) as u8
    }

    /// Return the VBE minor version number.
    pub const fn version_minor(&self) -> u8 {
        self.version as u8
    }

    /// Total video memory in bytes.
    pub const fn total_memory_bytes(&self) -> usize {
        (self.total_memory_64k as usize)
            .saturating_mul(64)
            .saturating_mul(1024)
    }
}

impl core::fmt::Debug for VbeInfoBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VbeInfoBlock")
            .field("signature", &self.signature)
            .field("version", &self.version)
            .field("capabilities", &self.capabilities)
            .field("total_memory_64k", &self.total_memory_64k)
            .finish()
    }
}

// Compile-time size assertion.
const _: () = {
    assert!(core::mem::size_of::<VbeInfoBlock>() == 512);
};

// -----------------------------------------------------------------------
// VbeModeInfo — VBE mode information block (256 bytes)
// -----------------------------------------------------------------------

/// VBE mode information block.
///
/// Returned by VBE Function 01h (Return VBE Mode Information).
/// Contains resolution, color depth, framebuffer address, pitch,
/// and pixel format details for a given VBE video mode.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct VbeModeInfo {
    /// Mode attributes (bit 7 = linear framebuffer supported).
    pub attributes: u16,
    /// Window A attributes.
    pub window_a_attrs: u8,
    /// Window B attributes.
    pub window_b_attrs: u8,
    /// Window granularity in KiB.
    pub window_granularity: u16,
    /// Window size in KiB.
    pub window_size: u16,
    /// Window A segment.
    pub window_a_segment: u16,
    /// Window B segment.
    pub window_b_segment: u16,
    /// Far pointer to window function (real-mode).
    pub window_func_ptr: u32,
    /// Bytes per scan line (pitch).
    pub pitch: u16,
    /// Horizontal resolution in pixels.
    pub width: u16,
    /// Vertical resolution in pixels.
    pub height: u16,
    /// Character cell width.
    pub char_width: u8,
    /// Character cell height.
    pub char_height: u8,
    /// Number of memory planes.
    pub planes: u8,
    /// Bits per pixel.
    pub bpp: u8,
    /// Number of banks.
    pub banks: u8,
    /// Memory model type.
    pub memory_model: u8,
    /// Bank size in KiB.
    pub bank_size: u8,
    /// Number of image pages.
    pub image_pages: u8,
    /// Reserved (VBE 1.x compatibility).
    pub reserved0: u8,
    /// Red mask size (bits).
    pub red_mask_size: u8,
    /// Red field position (bit offset).
    pub red_field_position: u8,
    /// Green mask size (bits).
    pub green_mask_size: u8,
    /// Green field position (bit offset).
    pub green_field_position: u8,
    /// Blue mask size (bits).
    pub blue_mask_size: u8,
    /// Blue field position (bit offset).
    pub blue_field_position: u8,
    /// Reserved mask size (alpha, bits).
    pub reserved_mask_size: u8,
    /// Reserved field position (alpha, bit offset).
    pub reserved_field_position: u8,
    /// Direct color mode info.
    pub direct_color_mode_info: u8,
    /// Physical address of the linear framebuffer.
    pub framebuffer_addr: u32,
    /// Reserved (off-screen memory offset in VBE 2.0).
    pub reserved1: u32,
    /// Reserved (off-screen memory size in VBE 2.0).
    pub reserved2: u16,
    /// Padding to 256 bytes.
    pub reserved3: [u8; 206],
}

impl Default for VbeModeInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl VbeModeInfo {
    /// Create a zeroed mode info block.
    pub const fn new() -> Self {
        Self {
            attributes: 0,
            window_a_attrs: 0,
            window_b_attrs: 0,
            window_granularity: 0,
            window_size: 0,
            window_a_segment: 0,
            window_b_segment: 0,
            window_func_ptr: 0,
            pitch: 0,
            width: 0,
            height: 0,
            char_width: 0,
            char_height: 0,
            planes: 0,
            bpp: 0,
            banks: 0,
            memory_model: 0,
            bank_size: 0,
            image_pages: 0,
            reserved0: 0,
            red_mask_size: 0,
            red_field_position: 0,
            green_mask_size: 0,
            green_field_position: 0,
            blue_mask_size: 0,
            blue_field_position: 0,
            reserved_mask_size: 0,
            reserved_field_position: 0,
            direct_color_mode_info: 0,
            framebuffer_addr: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: [0u8; 206],
        }
    }

    /// Check whether this mode supports a linear framebuffer.
    pub const fn has_linear_framebuffer(&self) -> bool {
        self.attributes & (1 << 7) != 0
    }

    /// Determine the [`VbePixelFormat`] from the mode's color fields.
    pub const fn pixel_format(&self) -> VbePixelFormat {
        if self.bpp == 8 {
            return VbePixelFormat::Indexed;
        }
        // Check field positions to distinguish RGB vs BGR ordering.
        if self.red_field_position == 0 && self.bpp == 24 {
            return VbePixelFormat::Rgb888;
        }
        if self.blue_field_position == 0 && self.bpp == 24 {
            return VbePixelFormat::Bgr888;
        }
        if self.red_field_position == 0 && self.reserved_mask_size == 8 && self.bpp == 32 {
            return VbePixelFormat::Rgba8888;
        }
        if self.blue_field_position == 0 && self.reserved_mask_size == 8 && self.bpp == 32 {
            return VbePixelFormat::Bgra8888;
        }
        // Fallback heuristics based on common BIOS layouts.
        if self.red_field_position > self.blue_field_position {
            if self.bpp >= 32 {
                VbePixelFormat::Bgra8888
            } else {
                VbePixelFormat::Bgr888
            }
        } else if self.bpp >= 32 {
            VbePixelFormat::Rgba8888
        } else {
            VbePixelFormat::Rgb888
        }
    }

    /// Total framebuffer size in bytes for this mode.
    pub const fn framebuffer_size(&self) -> usize {
        (self.pitch as usize).saturating_mul(self.height as usize)
    }
}

impl core::fmt::Debug for VbeModeInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VbeModeInfo")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bpp", &self.bpp)
            .field("pitch", &self.pitch)
            .field("framebuffer_addr", &self.framebuffer_addr)
            .field("pixel_format", &self.pixel_format())
            .finish()
    }
}

// Compile-time size assertion.
const _: () = {
    assert!(core::mem::size_of::<VbeModeInfo>() == 256);
};

// -----------------------------------------------------------------------
// LinearFramebuffer — direct memory-mapped framebuffer access
// -----------------------------------------------------------------------

/// Direct access to a linear (memory-mapped) VESA framebuffer.
///
/// Unlike the software [`Framebuffer`] which uses an internal
/// buffer, this struct writes directly to the hardware framebuffer
/// at the physical address provided by VBE mode info.
///
/// All drawing operations perform bounds checking and silently clip
/// out-of-bounds pixels.
pub struct LinearFramebuffer {
    /// Base virtual address of the mapped framebuffer.
    base: usize,
    /// Display width in pixels.
    width: u32,
    /// Display height in pixels.
    height: u32,
    /// Bytes per scan line (may be larger than width * bpp).
    pitch: u32,
    /// Bits per pixel.
    bpp: u32,
    /// Pixel format derived from the VBE mode info.
    format: VbePixelFormat,
}

impl core::fmt::Debug for LinearFramebuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinearFramebuffer")
            .field("base", &self.base)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("pitch", &self.pitch)
            .field("bpp", &self.bpp)
            .field("format", &self.format)
            .finish()
    }
}

impl LinearFramebuffer {
    /// Create a new linear framebuffer from VBE mode information.
    ///
    /// `base_vaddr` is the virtual address to which the physical
    /// framebuffer has been mapped. The caller must ensure that
    /// the mapping covers at least `pitch * height` bytes and that
    /// the memory is valid for the lifetime of this struct.
    ///
    /// Returns `Err(InvalidArgument)` if the mode has zero
    /// dimensions or does not support a linear framebuffer.
    pub fn from_mode_info(mode: &VbeModeInfo, base_vaddr: usize) -> Result<Self> {
        if mode.width == 0 || mode.height == 0 || mode.bpp == 0 {
            return Err(Error::InvalidArgument);
        }
        if !mode.has_linear_framebuffer() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            base: base_vaddr,
            width: mode.width as u32,
            height: mode.height as u32,
            pitch: mode.pitch as u32,
            bpp: mode.bpp as u32,
            format: mode.pixel_format(),
        })
    }

    /// Display width in pixels.
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Display height in pixels.
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Bytes per scan line.
    pub const fn pitch(&self) -> u32 {
        self.pitch
    }

    /// Bits per pixel.
    pub const fn bpp(&self) -> u32 {
        self.bpp
    }

    /// The pixel format of this framebuffer.
    pub const fn format(&self) -> VbePixelFormat {
        self.format
    }

    /// Total framebuffer size in bytes.
    pub const fn size(&self) -> usize {
        (self.pitch as usize).saturating_mul(self.height as usize)
    }

    /// Write a single pixel at `(x, y)` using an RGBA-packed color.
    ///
    /// The color is encoded as `0xRRGGBBAA`. Out-of-bounds
    /// coordinates are silently ignored.
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let bytes_pp = self.format.bytes_per_pixel() as usize;
        let offset = (y as usize)
            .saturating_mul(self.pitch as usize)
            .saturating_add((x as usize).saturating_mul(bytes_pp));

        // SAFETY: The caller of `from_mode_info` guarantees that the
        // base address is a valid mapping covering pitch * height
        // bytes. We have bounds-checked (x, y) above.
        let ptr = self.base.saturating_add(offset) as *mut u8;

        match self.format {
            VbePixelFormat::Rgb888 => unsafe {
                ptr.write((color >> 24) as u8);
                ptr.add(1).write((color >> 16) as u8);
                ptr.add(2).write((color >> 8) as u8);
            },
            VbePixelFormat::Bgr888 => unsafe {
                ptr.write((color >> 8) as u8);
                ptr.add(1).write((color >> 16) as u8);
                ptr.add(2).write((color >> 24) as u8);
            },
            VbePixelFormat::Rgba8888 => unsafe {
                ptr.write((color >> 24) as u8);
                ptr.add(1).write((color >> 16) as u8);
                ptr.add(2).write((color >> 8) as u8);
                ptr.add(3).write(color as u8);
            },
            VbePixelFormat::Bgra8888 => unsafe {
                ptr.write((color >> 8) as u8);
                ptr.add(1).write((color >> 16) as u8);
                ptr.add(2).write((color >> 24) as u8);
                ptr.add(3).write(color as u8);
            },
            VbePixelFormat::Indexed => unsafe {
                // For indexed mode, use the red channel as index.
                ptr.write((color >> 24) as u8);
            },
        }
    }

    /// Fill a rectangular region with a solid RGBA color.
    ///
    /// Pixels outside the framebuffer are clipped.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let x_start = x.min(self.width);
        let y_start = y.min(self.height);
        let x_end = x.saturating_add(w).min(self.width);
        let y_end = y.saturating_add(h).min(self.height);
        let mut cy = y_start;
        while cy < y_end {
            let mut cx = x_start;
            while cx < x_end {
                self.put_pixel(cx, cy, color);
                cx = cx.saturating_add(1);
            }
            cy = cy.saturating_add(1);
        }
    }

    /// Copy a rectangular region from a source buffer into the
    /// framebuffer at position `(dst_x, dst_y)`.
    ///
    /// `src` is a row-major RGBA pixel buffer. `src_width` is the
    /// width of the source rectangle. The source buffer must contain
    /// at least `src_width * src_height * 4` bytes.
    ///
    /// Out-of-bounds destination pixels are clipped.
    pub fn blit(&mut self, dst_x: u32, dst_y: u32, src: &[u8], src_width: u32, src_height: u32) {
        let mut sy: u32 = 0;
        while sy < src_height {
            let dy = dst_y.saturating_add(sy);
            if dy >= self.height {
                break;
            }
            let mut sx: u32 = 0;
            while sx < src_width {
                let dx = dst_x.saturating_add(sx);
                if dx >= self.width {
                    break;
                }
                let src_off = ((sy as usize)
                    .saturating_mul(src_width as usize)
                    .saturating_add(sx as usize))
                .saturating_mul(4);
                if let Some(px) = src.get(src_off..src_off + 4) {
                    let c = (px[0] as u32) << 24
                        | (px[1] as u32) << 16
                        | (px[2] as u32) << 8
                        | px[3] as u32;
                    self.put_pixel(dx, dy, c);
                }
                sx = sx.saturating_add(1);
            }
            sy = sy.saturating_add(1);
        }
    }

    /// Scroll the framebuffer contents up by `lines` pixel rows.
    ///
    /// The vacated bottom rows are filled with `bg_color`.
    pub fn scroll_up(&mut self, lines: u32, bg_color: u32) {
        if lines == 0 {
            return;
        }
        if lines >= self.height {
            self.clear(bg_color);
            return;
        }
        let pitch = self.pitch as usize;
        let shift = (lines as usize).saturating_mul(pitch);
        let total = (self.height as usize).saturating_mul(pitch);
        let copy_len = total.saturating_sub(shift);

        // SAFETY: Both source and destination are within the mapped
        // framebuffer region. Forward copy is correct because
        // destination < source.
        if copy_len > 0 && shift < total {
            let ptr = self.base as *mut u8;
            unsafe {
                core::ptr::copy(ptr.add(shift), ptr, copy_len);
            }
        }

        let clear_y = self.height.saturating_sub(lines);
        self.fill_rect(0, clear_y, self.width, lines, bg_color);
    }

    /// Clear the entire framebuffer to a solid color.
    pub fn clear(&mut self, color: u32) {
        self.fill_rect(0, 0, self.width, self.height, color);
    }
}

// -----------------------------------------------------------------------
// VesaConsole — text console on top of the linear framebuffer
// -----------------------------------------------------------------------

/// Number of text columns for a standard 80-column console.
pub const CONSOLE_COLS: u32 = 80;

/// Number of text rows for a standard 25-row console.
pub const CONSOLE_ROWS: u32 = 25;

/// Text-mode console rendered on a [`LinearFramebuffer`].
///
/// Provides an 80x25-style character grid rendered via the shared
/// 8x16 bitmap font from [`crate::virtio_gpu`]. Handles printable
/// ASCII, newlines, carriage returns, tabs, and automatic scrolling.
pub struct VesaConsole {
    /// Underlying linear framebuffer.
    fb: LinearFramebuffer,
    /// Current cursor column (0-based).
    cursor_x: u32,
    /// Current cursor row (0-based).
    cursor_y: u32,
    /// Number of text columns.
    cols: u32,
    /// Number of text rows.
    rows: u32,
    /// Foreground (text) color in RGBA-packed format.
    fg_color: u32,
    /// Background color in RGBA-packed format.
    bg_color: u32,
}

impl core::fmt::Debug for VesaConsole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VesaConsole")
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("cursor", &(self.cursor_x, self.cursor_y))
            .field("fg_color", &self.fg_color)
            .field("bg_color", &self.bg_color)
            .finish()
    }
}

impl VesaConsole {
    /// Create a new VESA text console on the given framebuffer.
    ///
    /// Calculates columns and rows from the framebuffer dimensions
    /// and the 8x16 font size.
    pub fn new(fb: LinearFramebuffer) -> Self {
        let cols = fb.width() / FONT_WIDTH;
        let rows = fb.height() / FONT_HEIGHT;
        Self {
            fb,
            cursor_x: 0,
            cursor_y: 0,
            cols,
            rows,
            fg_color: 0xFFFF_FFFF, // white opaque
            bg_color: 0x0000_00FF, // black opaque
        }
    }

    /// Return a reference to the underlying framebuffer.
    pub const fn framebuffer(&self) -> &LinearFramebuffer {
        &self.fb
    }

    /// Return a mutable reference to the underlying framebuffer.
    pub fn framebuffer_mut(&mut self) -> &mut LinearFramebuffer {
        &mut self.fb
    }

    /// Current cursor column.
    pub const fn cursor_x(&self) -> u32 {
        self.cursor_x
    }

    /// Current cursor row.
    pub const fn cursor_y(&self) -> u32 {
        self.cursor_y
    }

    /// Number of text columns.
    pub const fn cols(&self) -> u32 {
        self.cols
    }

    /// Number of text rows.
    pub const fn rows(&self) -> u32 {
        self.rows
    }

    /// Set the foreground (text) color.
    pub fn set_fg_color(&mut self, color: Color) {
        self.fg_color = color.to_u32();
    }

    /// Set the background color.
    pub fn set_bg_color(&mut self, color: Color) {
        self.bg_color = color.to_u32();
    }

    /// Render a single 8x16 character at pixel position `(px, py)`.
    fn draw_char(&mut self, px: u32, py: u32, ch: u8, fg: u32, bg: u32) {
        let glyph_idx = if (32..=126).contains(&ch) {
            (ch - 32) as usize
        } else {
            0 // fallback to space
        };
        let glyph_off = glyph_idx * (FONT_HEIGHT as usize);
        let mut row: u32 = 0;
        while row < FONT_HEIGHT {
            let font_byte = FONT_8X16
                .get(glyph_off + row as usize)
                .copied()
                .unwrap_or(0);
            let mut col: u32 = 0;
            while col < FONT_WIDTH {
                let mask = 0x80u8 >> (col as u8);
                let c = if font_byte & mask != 0 { fg } else { bg };
                self.fb
                    .put_pixel(px.saturating_add(col), py.saturating_add(row), c);
                col = col.saturating_add(1);
            }
            row = row.saturating_add(1);
        }
    }

    /// Write a single byte to the console.
    ///
    /// Handles printable ASCII, `\n` (newline), `\r` (carriage
    /// return), and `\t` (tab, 4-column stops). Other control
    /// characters are silently ignored.
    pub fn write_char(&mut self, ch: u8) {
        match ch {
            b'\n' => self.newline(),
            b'\r' => {
                self.cursor_x = 0;
            }
            b'\t' => {
                let next = (self.cursor_x / 4).saturating_add(1).saturating_mul(4);
                let spaces = next.saturating_sub(self.cursor_x);
                let mut i: u32 = 0;
                while i < spaces {
                    self.write_char(b' ');
                    i = i.saturating_add(1);
                }
            }
            0x20..=0x7E => {
                if self.cursor_x >= self.cols {
                    self.newline();
                }
                let px = self.cursor_x.saturating_mul(FONT_WIDTH);
                let py = self.cursor_y.saturating_mul(FONT_HEIGHT);
                self.draw_char(px, py, ch, self.fg_color, self.bg_color);
                self.cursor_x = self.cursor_x.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Write a byte slice to the console.
    pub fn write_bytes(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            self.write_char(data[i]);
            i += 1;
        }
    }

    /// Advance the cursor to the next line, scrolling if needed.
    pub fn newline(&mut self) {
        self.cursor_x = 0;
        if self.cursor_y.saturating_add(1) < self.rows {
            self.cursor_y = self.cursor_y.saturating_add(1);
        } else {
            self.fb.scroll_up(FONT_HEIGHT, self.bg_color);
        }
    }

    /// Clear the screen and reset the cursor to (0, 0).
    pub fn clear_screen(&mut self) {
        self.fb.clear(self.bg_color);
        self.cursor_x = 0;
        self.cursor_y = 0;
    }
}

// -----------------------------------------------------------------------
// VesaDriver — high-level driver interface
// -----------------------------------------------------------------------

/// VESA driver state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VesaDriverState {
    /// Driver has not been initialized.
    #[default]
    Uninitialized,
    /// Driver has detected a valid VBE controller.
    Detected,
    /// A video mode is active.
    Active,
}

/// High-level VESA/VBE driver.
///
/// Manages VBE controller information, the current mode, and
/// provides a thin API for mode detection and framebuffer access.
///
/// In ONCRIX, the bootloader sets the desired video mode via VBE
/// Function 02h before entering protected/long mode. The kernel
/// driver reads the pre-configured mode info and exposes the
/// framebuffer.
pub struct VesaDriver {
    /// VBE controller information block.
    info: VbeInfoBlock,
    /// Currently active mode information.
    mode_info: VbeModeInfo,
    /// Current mode number (0xFFFF if none).
    current_mode: u16,
    /// Cached list of available mode numbers.
    modes: [u16; MAX_VIDEO_MODES],
    /// Number of valid entries in `modes`.
    mode_count: usize,
    /// Driver state.
    state: VesaDriverState,
}

impl Default for VesaDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VesaDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VesaDriver")
            .field("state", &self.state)
            .field("current_mode", &self.current_mode)
            .field("mode_count", &self.mode_count)
            .finish()
    }
}

impl VesaDriver {
    /// Create an uninitialized VESA driver.
    pub const fn new() -> Self {
        Self {
            info: VbeInfoBlock::new(),
            mode_info: VbeModeInfo::new(),
            current_mode: 0xFFFF,
            modes: [0u16; MAX_VIDEO_MODES],
            mode_count: 0,
            state: VesaDriverState::Uninitialized,
        }
    }

    /// Initialize the driver from a bootloader-provided VBE info
    /// block.
    ///
    /// Returns `Err(InvalidArgument)` if the signature is invalid.
    pub fn init(&mut self, info: &VbeInfoBlock) -> Result<()> {
        if !info.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.info = *info;
        self.state = VesaDriverState::Detected;
        Ok(())
    }

    /// Register a list of available mode numbers.
    ///
    /// The bootloader typically provides this list. At most
    /// [`MAX_VIDEO_MODES`] entries are stored; excess entries are
    /// silently dropped.
    pub fn set_mode_list(&mut self, modes: &[u16]) {
        let count = modes.len().min(MAX_VIDEO_MODES);
        let mut i = 0;
        while i < count {
            self.modes[i] = modes[i];
            i += 1;
        }
        self.mode_count = count;
    }

    /// Set the current mode from bootloader-provided mode info.
    ///
    /// This does NOT invoke VBE Function 02h (which requires
    /// real-mode). Instead, it records the mode that the bootloader
    /// has already configured.
    ///
    /// Returns `Err(InvalidArgument)` if the mode info describes
    /// zero dimensions.
    pub fn set_current_mode(&mut self, mode_number: u16, mode_info: &VbeModeInfo) -> Result<()> {
        if mode_info.width == 0 || mode_info.height == 0 {
            return Err(Error::InvalidArgument);
        }
        self.mode_info = *mode_info;
        self.current_mode = mode_number;
        self.state = VesaDriverState::Active;
        Ok(())
    }

    /// Return the current driver state.
    pub const fn state(&self) -> VesaDriverState {
        self.state
    }

    /// Return the VBE controller info block.
    pub const fn info(&self) -> &VbeInfoBlock {
        &self.info
    }

    /// Return the current mode info, if a mode is active.
    ///
    /// Returns `Err(NotFound)` if no mode has been set.
    pub const fn current_mode_info(&self) -> Result<&VbeModeInfo> {
        match self.state {
            VesaDriverState::Active => Ok(&self.mode_info),
            _ => Err(Error::NotFound),
        }
    }

    /// Return the current VBE mode number.
    ///
    /// Returns `Err(NotFound)` if no mode has been set.
    pub const fn current_mode_number(&self) -> Result<u16> {
        match self.state {
            VesaDriverState::Active => Ok(self.current_mode),
            _ => Err(Error::NotFound),
        }
    }

    /// Return the number of registered video modes.
    pub const fn mode_count(&self) -> usize {
        self.mode_count
    }

    /// Return the mode number at the given index.
    ///
    /// Returns `Err(InvalidArgument)` if `index >= mode_count`.
    pub const fn mode_at(&self, index: usize) -> Result<u16> {
        if index >= self.mode_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.modes[index])
    }
}

// -----------------------------------------------------------------------
// DoubleBuffer — tear-free rendering via back buffer + flip
// -----------------------------------------------------------------------

/// Double-buffered rendering wrapper.
///
/// Maintains a software back buffer ([`Framebuffer`]) and copies
/// (flips) it to the hardware [`LinearFramebuffer`] when requested.
/// This prevents tearing caused by drawing directly to video memory
/// during the display refresh cycle.
pub struct DoubleBuffer {
    /// Software back buffer for off-screen rendering.
    back: Framebuffer,
    /// Hardware front buffer (linear framebuffer).
    front: LinearFramebuffer,
}

impl core::fmt::Debug for DoubleBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DoubleBuffer")
            .field("back", &self.back)
            .field("front", &self.front)
            .finish()
    }
}

impl DoubleBuffer {
    /// Create a double buffer for the given hardware framebuffer.
    ///
    /// The back buffer pixel format is derived from the hardware
    /// framebuffer's [`VbePixelFormat`]. Returns `Err` if the
    /// pixel format is unsupported (e.g., indexed) or the back
    /// buffer allocation fails.
    pub fn new(front: LinearFramebuffer) -> Result<Self> {
        let px_fmt = front.format().to_pixel_format()?;
        let back = Framebuffer::new(front.width(), front.height(), px_fmt)?;
        Ok(Self { back, front })
    }

    /// Return a reference to the software back buffer.
    pub const fn back_buffer(&self) -> &Framebuffer {
        &self.back
    }

    /// Return a mutable reference to the software back buffer.
    ///
    /// Draw to this buffer, then call [`flip`](Self::flip) to
    /// present the result.
    pub fn back_buffer_mut(&mut self) -> &mut Framebuffer {
        &mut self.back
    }

    /// Return a reference to the hardware front buffer.
    pub const fn front_buffer(&self) -> &LinearFramebuffer {
        &self.front
    }

    /// Copy the back buffer contents to the front (hardware)
    /// framebuffer.
    ///
    /// This performs a byte-for-byte copy of the used portion of
    /// the back buffer into video memory. For best performance,
    /// the pitch of both buffers should match.
    pub fn flip(&mut self) {
        let h = self.front.height() as usize;
        let front_pitch = self.front.pitch() as usize;
        let back_stride = self.back.stride as usize;
        let copy_width = front_pitch.min(back_stride);

        let dst_base = self.front.base as *mut u8;
        let src = &self.back.buffer;

        let mut row: usize = 0;
        while row < h {
            let dst_off = row.saturating_mul(front_pitch);
            let src_off = row.saturating_mul(back_stride);
            if src_off.saturating_add(copy_width) > src.len() {
                break;
            }
            // SAFETY: `dst_base` points to a valid framebuffer
            // mapping of at least `front_pitch * height` bytes.
            // `src` is a bounded slice. We copy at most
            // `copy_width` bytes per row within both buffers.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(src_off),
                    dst_base.add(dst_off),
                    copy_width,
                );
            }
            row = row.saturating_add(1);
        }
    }

    /// Clear the back buffer and flip.
    pub fn clear(&mut self, color: u32) {
        self.back.clear(color);
        self.flip();
    }
}

// -----------------------------------------------------------------------
// Convenience re-exports and helper constructors
// -----------------------------------------------------------------------

/// Create a [`VesaConsole`] from bootloader-provided VBE mode info.
///
/// `base_vaddr` is the virtual address of the mapped framebuffer.
///
/// Returns `Err` if the mode info is invalid.
pub fn create_console(mode: &VbeModeInfo, base_vaddr: usize) -> Result<VesaConsole> {
    let fb = LinearFramebuffer::from_mode_info(mode, base_vaddr)?;
    Ok(VesaConsole::new(fb))
}

/// Create a [`DoubleBuffer`] from bootloader-provided VBE mode info.
///
/// `base_vaddr` is the virtual address of the mapped framebuffer.
///
/// Returns `Err` if the mode info is invalid or the pixel format
/// is unsupported.
pub fn create_double_buffer(mode: &VbeModeInfo, base_vaddr: usize) -> Result<DoubleBuffer> {
    let fb = LinearFramebuffer::from_mode_info(mode, base_vaddr)?;
    DoubleBuffer::new(fb)
}
