// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO GPU framebuffer driver.
//!
//! Implements a VirtIO GPU device (device type 16) for display output
//! with a software framebuffer, bitmap font rendering, and a text
//! console overlay.
//!
//! The driver supports 2D operations via the VirtIO GPU command
//! protocol: display info queries, resource creation, scanout
//! configuration, host transfers, and flushes.
//!
//! Reference: VirtIO Specification v1.1, Section 5.7 (GPU Device).

use oncrix_lib::{Error, Result};

// -----------------------------------------------------------------------
// VirtIO GPU command types (Section 5.7.6)
// -----------------------------------------------------------------------

/// Get display information from the device.
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x100;

/// Create a 2D resource on the host.
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x101;

/// Attach a scanout to a resource for display.
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x103;

/// Flush a resource region to the display.
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x104;

/// Transfer a rectangle from guest to host resource.
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x105;

/// Attach backing pages to a resource.
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x106;

/// Response with no data payload (success).
pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;

/// Response containing display information.
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

// -----------------------------------------------------------------------
// GPU control header (Section 5.7.6.7)
// -----------------------------------------------------------------------

/// Common header for all GPU control messages.
///
/// Every request and response starts with this 24-byte header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GpuCtrlHeader {
    /// Command or response type.
    pub ctrl_type: u32,
    /// Flags (bit 0 = fence).
    pub flags: u32,
    /// Fence ID for synchronization.
    pub fence_id: u64,
    /// 3D rendering context ID (0 for 2D operations).
    pub ctx_id: u32,
    /// Reserved padding.
    pub padding: u32,
}

impl GpuCtrlHeader {
    /// Create a new header for the given command type.
    pub const fn new(ctrl_type: u32) -> Self {
        Self {
            ctrl_type,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            padding: 0,
        }
    }
}

// -----------------------------------------------------------------------
// GPU rectangle
// -----------------------------------------------------------------------

/// A rectangle in GPU coordinate space.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GpuRect {
    /// X offset in pixels.
    pub x: u32,
    /// Y offset in pixels.
    pub y: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl GpuRect {
    /// Create a new rectangle.
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

// -----------------------------------------------------------------------
// Display info
// -----------------------------------------------------------------------

/// Information about a single display/scanout.
#[derive(Debug, Clone, Copy)]
pub struct DisplayInfo {
    /// The display rectangle (position and resolution).
    pub rect: GpuRect,
    /// Whether this display is enabled.
    pub enabled: bool,
}

impl Default for DisplayInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl DisplayInfo {
    /// Create a disabled display info with zero dimensions.
    pub const fn new() -> Self {
        Self {
            rect: GpuRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            enabled: false,
        }
    }
}

// -----------------------------------------------------------------------
// Pixel format
// -----------------------------------------------------------------------

/// Framebuffer pixel format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit RGBA (red, green, blue, alpha), 8 bits each.
    Rgba8888,
    /// 32-bit BGRA (blue, green, red, alpha), 8 bits each.
    Bgra8888,
    /// 24-bit RGB (red, green, blue), 8 bits each.
    Rgb888,
}

impl PixelFormat {
    /// Return the number of bytes per pixel for this format.
    pub const fn bytes_per_pixel(self) -> u32 {
        match self {
            Self::Rgba8888 | Self::Bgra8888 => 4,
            Self::Rgb888 => 3,
        }
    }
}

// -----------------------------------------------------------------------
// Font data — 8x16 bitmap font for ASCII 32..=126
// -----------------------------------------------------------------------

/// Character width in pixels.
pub const FONT_WIDTH: u32 = 8;

/// Character height in pixels.
pub const FONT_HEIGHT: u32 = 16;

/// Number of glyphs in the font (ASCII 32..=126 inclusive).
const FONT_GLYPH_COUNT: usize = 95;

/// 8x16 bitmap font covering printable ASCII (32..=126).
///
/// Each glyph is 16 bytes, one byte per row, MSB = leftmost pixel.
/// Total size: 95 glyphs x 16 bytes = 1520 bytes.
#[rustfmt::skip]
#[allow(clippy::identity_op)]
pub static FONT_8X16: [u8; FONT_GLYPH_COUNT * 16] = {
    let mut data = [0u8; FONT_GLYPH_COUNT * 16];

    // Helper indices: glyph index = (ascii - 32) * 16
    // We build the array procedurally at compile time using a
    // const-evaluable block. Because const for loops are stable
    // since Rust 1.46+ (with const fn), we set individual bytes.

    // --- Space (32) is all zeros, already set ---

    // ! (33)
    data[1*16+ 2]=0x18; data[1*16+ 3]=0x18; data[1*16+ 4]=0x18;
    data[1*16+ 5]=0x18; data[1*16+ 6]=0x18; data[1*16+ 7]=0x18;
    data[1*16+ 8]=0x18; data[1*16+ 9]=0x00; data[1*16+10]=0x00;
    data[1*16+11]=0x18; data[1*16+12]=0x18;

    // " (34)
    data[2*16+ 2]=0x6C; data[2*16+ 3]=0x6C; data[2*16+ 4]=0x6C;

    // # (35)
    data[3*16+ 2]=0x6C; data[3*16+ 3]=0x6C; data[3*16+ 4]=0xFE;
    data[3*16+ 5]=0x6C; data[3*16+ 6]=0xFE; data[3*16+ 7]=0x6C;
    data[3*16+ 8]=0x6C;

    // $ (36)
    data[4*16+ 1]=0x10; data[4*16+ 2]=0x7C; data[4*16+ 3]=0xD6;
    data[4*16+ 4]=0xD0; data[4*16+ 5]=0x7C; data[4*16+ 6]=0x16;
    data[4*16+ 7]=0xD6; data[4*16+ 8]=0x7C; data[4*16+ 9]=0x10;

    // % (37)
    data[5*16+ 2]=0x00; data[5*16+ 3]=0xC6; data[5*16+ 4]=0xCC;
    data[5*16+ 5]=0x18; data[5*16+ 6]=0x30; data[5*16+ 7]=0x66;
    data[5*16+ 8]=0xC6;

    // & (38)
    data[6*16+ 2]=0x38; data[6*16+ 3]=0x6C; data[6*16+ 4]=0x38;
    data[6*16+ 5]=0x76; data[6*16+ 6]=0xDC; data[6*16+ 7]=0xCC;
    data[6*16+ 8]=0x76;

    // ' (39)
    data[7*16+ 2]=0x18; data[7*16+ 3]=0x18; data[7*16+ 4]=0x30;

    // ( (40)
    data[8*16+ 2]=0x0C; data[8*16+ 3]=0x18; data[8*16+ 4]=0x30;
    data[8*16+ 5]=0x30; data[8*16+ 6]=0x30; data[8*16+ 7]=0x18;
    data[8*16+ 8]=0x0C;

    // ) (41)
    data[9*16+ 2]=0x30; data[9*16+ 3]=0x18; data[9*16+ 4]=0x0C;
    data[9*16+ 5]=0x0C; data[9*16+ 6]=0x0C; data[9*16+ 7]=0x18;
    data[9*16+ 8]=0x30;

    // * (42)
    data[10*16+ 3]=0x66; data[10*16+ 4]=0x3C; data[10*16+ 5]=0xFF;
    data[10*16+ 6]=0x3C; data[10*16+ 7]=0x66;

    // + (43)
    data[11*16+ 4]=0x18; data[11*16+ 5]=0x18; data[11*16+ 6]=0x7E;
    data[11*16+ 7]=0x18; data[11*16+ 8]=0x18;

    // , (44)
    data[12*16+10]=0x18; data[12*16+11]=0x18; data[12*16+12]=0x30;

    // - (45)
    data[13*16+ 6]=0x7E;

    // . (46)
    data[14*16+10]=0x18; data[14*16+11]=0x18;

    // / (47)
    data[15*16+ 2]=0x06; data[15*16+ 3]=0x0C; data[15*16+ 4]=0x18;
    data[15*16+ 5]=0x30; data[15*16+ 6]=0x60; data[15*16+ 7]=0xC0;

    // 0 (48)
    data[16*16+ 2]=0x7C; data[16*16+ 3]=0xC6; data[16*16+ 4]=0xCE;
    data[16*16+ 5]=0xDE; data[16*16+ 6]=0xF6; data[16*16+ 7]=0xE6;
    data[16*16+ 8]=0x7C;

    // 1 (49)
    data[17*16+ 2]=0x18; data[17*16+ 3]=0x38; data[17*16+ 4]=0x18;
    data[17*16+ 5]=0x18; data[17*16+ 6]=0x18; data[17*16+ 7]=0x18;
    data[17*16+ 8]=0x7E;

    // 2 (50)
    data[18*16+ 2]=0x7C; data[18*16+ 3]=0xC6; data[18*16+ 4]=0x06;
    data[18*16+ 5]=0x3C; data[18*16+ 6]=0x60; data[18*16+ 7]=0xC0;
    data[18*16+ 8]=0xFE;

    // 3 (51)
    data[19*16+ 2]=0x7C; data[19*16+ 3]=0xC6; data[19*16+ 4]=0x06;
    data[19*16+ 5]=0x3C; data[19*16+ 6]=0x06; data[19*16+ 7]=0xC6;
    data[19*16+ 8]=0x7C;

    // 4 (52)
    data[20*16+ 2]=0x0C; data[20*16+ 3]=0x1C; data[20*16+ 4]=0x3C;
    data[20*16+ 5]=0x6C; data[20*16+ 6]=0xFE; data[20*16+ 7]=0x0C;
    data[20*16+ 8]=0x0C;

    // 5 (53)
    data[21*16+ 2]=0xFE; data[21*16+ 3]=0xC0; data[21*16+ 4]=0xFC;
    data[21*16+ 5]=0x06; data[21*16+ 6]=0x06; data[21*16+ 7]=0xC6;
    data[21*16+ 8]=0x7C;

    // 6 (54)
    data[22*16+ 2]=0x3C; data[22*16+ 3]=0x60; data[22*16+ 4]=0xC0;
    data[22*16+ 5]=0xFC; data[22*16+ 6]=0xC6; data[22*16+ 7]=0xC6;
    data[22*16+ 8]=0x7C;

    // 7 (55)
    data[23*16+ 2]=0xFE; data[23*16+ 3]=0x06; data[23*16+ 4]=0x0C;
    data[23*16+ 5]=0x18; data[23*16+ 6]=0x30; data[23*16+ 7]=0x30;
    data[23*16+ 8]=0x30;

    // 8 (56)
    data[24*16+ 2]=0x7C; data[24*16+ 3]=0xC6; data[24*16+ 4]=0xC6;
    data[24*16+ 5]=0x7C; data[24*16+ 6]=0xC6; data[24*16+ 7]=0xC6;
    data[24*16+ 8]=0x7C;

    // 9 (57)
    data[25*16+ 2]=0x7C; data[25*16+ 3]=0xC6; data[25*16+ 4]=0xC6;
    data[25*16+ 5]=0x7E; data[25*16+ 6]=0x06; data[25*16+ 7]=0x0C;
    data[25*16+ 8]=0x78;

    // : (58)
    data[26*16+ 4]=0x18; data[26*16+ 5]=0x18; data[26*16+ 8]=0x18;
    data[26*16+ 9]=0x18;

    // ; (59)
    data[27*16+ 4]=0x18; data[27*16+ 5]=0x18; data[27*16+ 8]=0x18;
    data[27*16+ 9]=0x18; data[27*16+10]=0x30;

    // < (60)
    data[28*16+ 3]=0x0C; data[28*16+ 4]=0x18; data[28*16+ 5]=0x30;
    data[28*16+ 6]=0x60; data[28*16+ 7]=0x30; data[28*16+ 8]=0x18;
    data[28*16+ 9]=0x0C;

    // = (61)
    data[29*16+ 5]=0x7E; data[29*16+ 7]=0x7E;

    // > (62)
    data[30*16+ 3]=0x60; data[30*16+ 4]=0x30; data[30*16+ 5]=0x18;
    data[30*16+ 6]=0x0C; data[30*16+ 7]=0x18; data[30*16+ 8]=0x30;
    data[30*16+ 9]=0x60;

    // ? (63)
    data[31*16+ 2]=0x7C; data[31*16+ 3]=0xC6; data[31*16+ 4]=0x06;
    data[31*16+ 5]=0x0C; data[31*16+ 6]=0x18; data[31*16+ 7]=0x00;
    data[31*16+ 8]=0x18;

    // @ (64)
    data[32*16+ 2]=0x7C; data[32*16+ 3]=0xC6; data[32*16+ 4]=0xDE;
    data[32*16+ 5]=0xDE; data[32*16+ 6]=0xDE; data[32*16+ 7]=0xC0;
    data[32*16+ 8]=0x7C;

    // A (65)
    data[33*16+ 2]=0x38; data[33*16+ 3]=0x6C; data[33*16+ 4]=0xC6;
    data[33*16+ 5]=0xC6; data[33*16+ 6]=0xFE; data[33*16+ 7]=0xC6;
    data[33*16+ 8]=0xC6;

    // B (66)
    data[34*16+ 2]=0xFC; data[34*16+ 3]=0xC6; data[34*16+ 4]=0xC6;
    data[34*16+ 5]=0xFC; data[34*16+ 6]=0xC6; data[34*16+ 7]=0xC6;
    data[34*16+ 8]=0xFC;

    // C (67)
    data[35*16+ 2]=0x7C; data[35*16+ 3]=0xC6; data[35*16+ 4]=0xC0;
    data[35*16+ 5]=0xC0; data[35*16+ 6]=0xC0; data[35*16+ 7]=0xC6;
    data[35*16+ 8]=0x7C;

    // D (68)
    data[36*16+ 2]=0xF8; data[36*16+ 3]=0xCC; data[36*16+ 4]=0xC6;
    data[36*16+ 5]=0xC6; data[36*16+ 6]=0xC6; data[36*16+ 7]=0xCC;
    data[36*16+ 8]=0xF8;

    // E (69)
    data[37*16+ 2]=0xFE; data[37*16+ 3]=0xC0; data[37*16+ 4]=0xC0;
    data[37*16+ 5]=0xFC; data[37*16+ 6]=0xC0; data[37*16+ 7]=0xC0;
    data[37*16+ 8]=0xFE;

    // F (70)
    data[38*16+ 2]=0xFE; data[38*16+ 3]=0xC0; data[38*16+ 4]=0xC0;
    data[38*16+ 5]=0xFC; data[38*16+ 6]=0xC0; data[38*16+ 7]=0xC0;
    data[38*16+ 8]=0xC0;

    // G (71)
    data[39*16+ 2]=0x7C; data[39*16+ 3]=0xC6; data[39*16+ 4]=0xC0;
    data[39*16+ 5]=0xCE; data[39*16+ 6]=0xC6; data[39*16+ 7]=0xC6;
    data[39*16+ 8]=0x7E;

    // H (72)
    data[40*16+ 2]=0xC6; data[40*16+ 3]=0xC6; data[40*16+ 4]=0xC6;
    data[40*16+ 5]=0xFE; data[40*16+ 6]=0xC6; data[40*16+ 7]=0xC6;
    data[40*16+ 8]=0xC6;

    // I (73)
    data[41*16+ 2]=0x7E; data[41*16+ 3]=0x18; data[41*16+ 4]=0x18;
    data[41*16+ 5]=0x18; data[41*16+ 6]=0x18; data[41*16+ 7]=0x18;
    data[41*16+ 8]=0x7E;

    // J (74)
    data[42*16+ 2]=0x1E; data[42*16+ 3]=0x06; data[42*16+ 4]=0x06;
    data[42*16+ 5]=0x06; data[42*16+ 6]=0xC6; data[42*16+ 7]=0xC6;
    data[42*16+ 8]=0x7C;

    // K (75)
    data[43*16+ 2]=0xC6; data[43*16+ 3]=0xCC; data[43*16+ 4]=0xD8;
    data[43*16+ 5]=0xF0; data[43*16+ 6]=0xD8; data[43*16+ 7]=0xCC;
    data[43*16+ 8]=0xC6;

    // L (76)
    data[44*16+ 2]=0xC0; data[44*16+ 3]=0xC0; data[44*16+ 4]=0xC0;
    data[44*16+ 5]=0xC0; data[44*16+ 6]=0xC0; data[44*16+ 7]=0xC0;
    data[44*16+ 8]=0xFE;

    // M (77)
    data[45*16+ 2]=0xC6; data[45*16+ 3]=0xEE; data[45*16+ 4]=0xFE;
    data[45*16+ 5]=0xD6; data[45*16+ 6]=0xC6; data[45*16+ 7]=0xC6;
    data[45*16+ 8]=0xC6;

    // N (78)
    data[46*16+ 2]=0xC6; data[46*16+ 3]=0xE6; data[46*16+ 4]=0xF6;
    data[46*16+ 5]=0xDE; data[46*16+ 6]=0xCE; data[46*16+ 7]=0xC6;
    data[46*16+ 8]=0xC6;

    // O (79)
    data[47*16+ 2]=0x7C; data[47*16+ 3]=0xC6; data[47*16+ 4]=0xC6;
    data[47*16+ 5]=0xC6; data[47*16+ 6]=0xC6; data[47*16+ 7]=0xC6;
    data[47*16+ 8]=0x7C;

    // P (80)
    data[48*16+ 2]=0xFC; data[48*16+ 3]=0xC6; data[48*16+ 4]=0xC6;
    data[48*16+ 5]=0xFC; data[48*16+ 6]=0xC0; data[48*16+ 7]=0xC0;
    data[48*16+ 8]=0xC0;

    // Q (81)
    data[49*16+ 2]=0x7C; data[49*16+ 3]=0xC6; data[49*16+ 4]=0xC6;
    data[49*16+ 5]=0xC6; data[49*16+ 6]=0xD6; data[49*16+ 7]=0xDE;
    data[49*16+ 8]=0x7C; data[49*16+ 9]=0x0E;

    // R (82)
    data[50*16+ 2]=0xFC; data[50*16+ 3]=0xC6; data[50*16+ 4]=0xC6;
    data[50*16+ 5]=0xFC; data[50*16+ 6]=0xD8; data[50*16+ 7]=0xCC;
    data[50*16+ 8]=0xC6;

    // S (83)
    data[51*16+ 2]=0x7C; data[51*16+ 3]=0xC6; data[51*16+ 4]=0xC0;
    data[51*16+ 5]=0x7C; data[51*16+ 6]=0x06; data[51*16+ 7]=0xC6;
    data[51*16+ 8]=0x7C;

    // T (84)
    data[52*16+ 2]=0x7E; data[52*16+ 3]=0x18; data[52*16+ 4]=0x18;
    data[52*16+ 5]=0x18; data[52*16+ 6]=0x18; data[52*16+ 7]=0x18;
    data[52*16+ 8]=0x18;

    // U (85)
    data[53*16+ 2]=0xC6; data[53*16+ 3]=0xC6; data[53*16+ 4]=0xC6;
    data[53*16+ 5]=0xC6; data[53*16+ 6]=0xC6; data[53*16+ 7]=0xC6;
    data[53*16+ 8]=0x7C;

    // V (86)
    data[54*16+ 2]=0xC6; data[54*16+ 3]=0xC6; data[54*16+ 4]=0xC6;
    data[54*16+ 5]=0x6C; data[54*16+ 6]=0x6C; data[54*16+ 7]=0x38;
    data[54*16+ 8]=0x10;

    // W (87)
    data[55*16+ 2]=0xC6; data[55*16+ 3]=0xC6; data[55*16+ 4]=0xC6;
    data[55*16+ 5]=0xD6; data[55*16+ 6]=0xFE; data[55*16+ 7]=0xEE;
    data[55*16+ 8]=0xC6;

    // X (88)
    data[56*16+ 2]=0xC6; data[56*16+ 3]=0x6C; data[56*16+ 4]=0x38;
    data[56*16+ 5]=0x38; data[56*16+ 6]=0x6C; data[56*16+ 7]=0xC6;
    data[56*16+ 8]=0xC6;  // Fixed: was missing semicolon style

    // Y (89)
    data[57*16+ 2]=0x66; data[57*16+ 3]=0x66; data[57*16+ 4]=0x3C;
    data[57*16+ 5]=0x18; data[57*16+ 6]=0x18; data[57*16+ 7]=0x18;
    data[57*16+ 8]=0x18;

    // Z (90)
    data[58*16+ 2]=0xFE; data[58*16+ 3]=0x0C; data[58*16+ 4]=0x18;
    data[58*16+ 5]=0x30; data[58*16+ 6]=0x60; data[58*16+ 7]=0xC0;
    data[58*16+ 8]=0xFE;

    // [ (91)
    data[59*16+ 2]=0x3C; data[59*16+ 3]=0x30; data[59*16+ 4]=0x30;
    data[59*16+ 5]=0x30; data[59*16+ 6]=0x30; data[59*16+ 7]=0x30;
    data[59*16+ 8]=0x3C;

    // \ (92)
    data[60*16+ 2]=0xC0; data[60*16+ 3]=0x60; data[60*16+ 4]=0x30;
    data[60*16+ 5]=0x18; data[60*16+ 6]=0x0C; data[60*16+ 7]=0x06;

    // ] (93)
    data[61*16+ 2]=0x3C; data[61*16+ 3]=0x0C; data[61*16+ 4]=0x0C;
    data[61*16+ 5]=0x0C; data[61*16+ 6]=0x0C; data[61*16+ 7]=0x0C;
    data[61*16+ 8]=0x3C;

    // ^ (94)
    data[62*16+ 2]=0x10; data[62*16+ 3]=0x38; data[62*16+ 4]=0x6C;
    data[62*16+ 5]=0xC6;

    // _ (95)
    data[63*16+13]=0xFE;

    // ` (96)
    data[64*16+ 2]=0x30; data[64*16+ 3]=0x18;

    // a (97)
    data[65*16+ 4]=0x7C; data[65*16+ 5]=0x06; data[65*16+ 6]=0x7E;
    data[65*16+ 7]=0xC6; data[65*16+ 8]=0x7E;

    // b (98)
    data[66*16+ 2]=0xC0; data[66*16+ 3]=0xC0; data[66*16+ 4]=0xFC;
    data[66*16+ 5]=0xC6; data[66*16+ 6]=0xC6; data[66*16+ 7]=0xC6;
    data[66*16+ 8]=0xFC;

    // c (99)
    data[67*16+ 4]=0x7C; data[67*16+ 5]=0xC6; data[67*16+ 6]=0xC0;
    data[67*16+ 7]=0xC6; data[67*16+ 8]=0x7C;

    // d (100)
    data[68*16+ 2]=0x06; data[68*16+ 3]=0x06; data[68*16+ 4]=0x7E;
    data[68*16+ 5]=0xC6; data[68*16+ 6]=0xC6; data[68*16+ 7]=0xC6;
    data[68*16+ 8]=0x7E;

    // e (101)
    data[69*16+ 4]=0x7C; data[69*16+ 5]=0xC6; data[69*16+ 6]=0xFE;
    data[69*16+ 7]=0xC0; data[69*16+ 8]=0x7C;

    // f (102)
    data[70*16+ 2]=0x1C; data[70*16+ 3]=0x30; data[70*16+ 4]=0x7C;
    data[70*16+ 5]=0x30; data[70*16+ 6]=0x30; data[70*16+ 7]=0x30;
    data[70*16+ 8]=0x30;

    // g (103)
    data[71*16+ 4]=0x7E; data[71*16+ 5]=0xC6; data[71*16+ 6]=0xC6;
    data[71*16+ 7]=0x7E; data[71*16+ 8]=0x06; data[71*16+ 9]=0x7C;

    // h (104)
    data[72*16+ 2]=0xC0; data[72*16+ 3]=0xC0; data[72*16+ 4]=0xFC;
    data[72*16+ 5]=0xC6; data[72*16+ 6]=0xC6; data[72*16+ 7]=0xC6;
    data[72*16+ 8]=0xC6;

    // i (105)
    data[73*16+ 2]=0x18; data[73*16+ 3]=0x00; data[73*16+ 4]=0x38;
    data[73*16+ 5]=0x18; data[73*16+ 6]=0x18; data[73*16+ 7]=0x18;
    data[73*16+ 8]=0x3C;

    // j (106)
    data[74*16+ 2]=0x06; data[74*16+ 3]=0x00; data[74*16+ 4]=0x06;
    data[74*16+ 5]=0x06; data[74*16+ 6]=0x06; data[74*16+ 7]=0x06;
    data[74*16+ 8]=0xC6; data[74*16+ 9]=0x7C;

    // k (107)
    data[75*16+ 2]=0xC0; data[75*16+ 3]=0xC0; data[75*16+ 4]=0xCC;
    data[75*16+ 5]=0xD8; data[75*16+ 6]=0xF0; data[75*16+ 7]=0xD8;
    data[75*16+ 8]=0xCC;

    // l (108)
    data[76*16+ 2]=0x38; data[76*16+ 3]=0x18; data[76*16+ 4]=0x18;
    data[76*16+ 5]=0x18; data[76*16+ 6]=0x18; data[76*16+ 7]=0x18;
    data[76*16+ 8]=0x3C;

    // m (109)
    data[77*16+ 4]=0xCC; data[77*16+ 5]=0xFE; data[77*16+ 6]=0xD6;
    data[77*16+ 7]=0xC6; data[77*16+ 8]=0xC6;

    // n (110)
    data[78*16+ 4]=0xFC; data[78*16+ 5]=0xC6; data[78*16+ 6]=0xC6;
    data[78*16+ 7]=0xC6; data[78*16+ 8]=0xC6;

    // o (111)
    data[79*16+ 4]=0x7C; data[79*16+ 5]=0xC6; data[79*16+ 6]=0xC6;
    data[79*16+ 7]=0xC6; data[79*16+ 8]=0x7C;

    // p (112)
    data[80*16+ 4]=0xFC; data[80*16+ 5]=0xC6; data[80*16+ 6]=0xC6;
    data[80*16+ 7]=0xFC; data[80*16+ 8]=0xC0; data[80*16+ 9]=0xC0;

    // q (113)
    data[81*16+ 4]=0x7E; data[81*16+ 5]=0xC6; data[81*16+ 6]=0xC6;
    data[81*16+ 7]=0x7E; data[81*16+ 8]=0x06; data[81*16+ 9]=0x06;

    // r (114)
    data[82*16+ 4]=0xDC; data[82*16+ 5]=0xE0; data[82*16+ 6]=0xC0;
    data[82*16+ 7]=0xC0; data[82*16+ 8]=0xC0;

    // s (115)
    data[83*16+ 4]=0x7E; data[83*16+ 5]=0xC0; data[83*16+ 6]=0x7C;
    data[83*16+ 7]=0x06; data[83*16+ 8]=0xFC;

    // t (116)
    data[84*16+ 2]=0x30; data[84*16+ 3]=0x30; data[84*16+ 4]=0x7C;
    data[84*16+ 5]=0x30; data[84*16+ 6]=0x30; data[84*16+ 7]=0x30;
    data[84*16+ 8]=0x1C;

    // u (117)
    data[85*16+ 4]=0xC6; data[85*16+ 5]=0xC6; data[85*16+ 6]=0xC6;
    data[85*16+ 7]=0xC6; data[85*16+ 8]=0x7E;

    // v (118)
    data[86*16+ 4]=0xC6; data[86*16+ 5]=0xC6; data[86*16+ 6]=0x6C;
    data[86*16+ 7]=0x38; data[86*16+ 8]=0x10;

    // w (119)
    data[87*16+ 4]=0xC6; data[87*16+ 5]=0xC6; data[87*16+ 6]=0xD6;
    data[87*16+ 7]=0xFE; data[87*16+ 8]=0x6C;

    // x (120)
    data[88*16+ 4]=0xC6; data[88*16+ 5]=0x6C; data[88*16+ 6]=0x38;
    data[88*16+ 7]=0x6C; data[88*16+ 8]=0xC6;

    // y (121)
    data[89*16+ 4]=0xC6; data[89*16+ 5]=0xC6; data[89*16+ 6]=0x7E;
    data[89*16+ 7]=0x06; data[89*16+ 8]=0x7C;

    // z (122)
    data[90*16+ 4]=0xFE; data[90*16+ 5]=0x0C; data[90*16+ 6]=0x38;
    data[90*16+ 7]=0x60; data[90*16+ 8]=0xFE;

    // { (123)
    data[91*16+ 2]=0x0E; data[91*16+ 3]=0x18; data[91*16+ 4]=0x18;
    data[91*16+ 5]=0x70; data[91*16+ 6]=0x18; data[91*16+ 7]=0x18;
    data[91*16+ 8]=0x0E;

    // | (124)
    data[92*16+ 2]=0x18; data[92*16+ 3]=0x18; data[92*16+ 4]=0x18;
    data[92*16+ 5]=0x18; data[92*16+ 6]=0x18; data[92*16+ 7]=0x18;
    data[92*16+ 8]=0x18;

    // } (125)
    data[93*16+ 2]=0x70; data[93*16+ 3]=0x18; data[93*16+ 4]=0x18;
    data[93*16+ 5]=0x0E; data[93*16+ 6]=0x18; data[93*16+ 7]=0x18;
    data[93*16+ 8]=0x70;

    // ~ (126)
    data[94*16+ 4]=0x76; data[94*16+ 5]=0xDC;

    data
};

// -----------------------------------------------------------------------
// Framebuffer
// -----------------------------------------------------------------------

/// Framebuffer size: 4096 * 256 = 1 MiB (enough for ~512x512 RGBA).
const FRAMEBUFFER_SIZE: usize = 4096 * 256;

/// Software framebuffer for 2D rendering.
///
/// Provides pixel-level access and higher-level drawing primitives
/// (rectangles, character rendering, scrolling) on a contiguous
/// memory buffer that can be transferred to a VirtIO GPU resource.
pub struct Framebuffer {
    /// Display width in pixels.
    pub width: u32,
    /// Display height in pixels.
    pub height: u32,
    /// Bytes per row (width * bytes_per_pixel, possibly padded).
    pub stride: u32,
    /// Pixel format of the framebuffer.
    pub format: PixelFormat,
    /// Raw pixel data buffer (1 MiB).
    pub buffer: [u8; FRAMEBUFFER_SIZE],
}

impl Framebuffer {
    /// Create a new framebuffer with the given dimensions and format.
    ///
    /// Returns `Err(InvalidArgument)` if the required buffer size
    /// exceeds the 1 MiB internal buffer.
    pub fn new(width: u32, height: u32, format: PixelFormat) -> Result<Self> {
        let bpp = format.bytes_per_pixel();
        let stride = width.checked_mul(bpp).ok_or(Error::InvalidArgument)?;
        let total = (stride as usize)
            .checked_mul(height as usize)
            .ok_or(Error::InvalidArgument)?;
        if total > FRAMEBUFFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            width,
            height,
            stride,
            format,
            buffer: [0u8; FRAMEBUFFER_SIZE],
        })
    }

    /// Write a single RGBA pixel at `(x, y)`.
    ///
    /// `color` is packed as `0xRRGGBBAA` regardless of the underlying
    /// pixel format; the method converts internally.
    ///
    /// Out-of-bounds coordinates are silently ignored.
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let bpp = self.format.bytes_per_pixel();
        let offset = (y as usize)
            .saturating_mul(self.stride as usize)
            .saturating_add((x as usize).saturating_mul(bpp as usize));
        match self.format {
            PixelFormat::Rgba8888 => {
                if let Some(px) = self.buffer.get_mut(offset..offset + 4) {
                    px[0] = (color >> 24) as u8; // R
                    px[1] = (color >> 16) as u8; // G
                    px[2] = (color >> 8) as u8; // B
                    px[3] = color as u8; // A
                }
            }
            PixelFormat::Bgra8888 => {
                if let Some(px) = self.buffer.get_mut(offset..offset + 4) {
                    px[0] = (color >> 8) as u8; // B
                    px[1] = (color >> 16) as u8; // G
                    px[2] = (color >> 24) as u8; // R
                    px[3] = color as u8; // A
                }
            }
            PixelFormat::Rgb888 => {
                if let Some(px) = self.buffer.get_mut(offset..offset + 3) {
                    px[0] = (color >> 24) as u8; // R
                    px[1] = (color >> 16) as u8; // G
                    px[2] = (color >> 8) as u8; // B
                }
            }
        }
    }

    /// Read the RGBA-packed pixel value at `(x, y)`.
    ///
    /// Returns `0` for out-of-bounds coordinates.
    pub fn get_pixel(&self, x: u32, y: u32) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        let bpp = self.format.bytes_per_pixel();
        let offset = (y as usize)
            .saturating_mul(self.stride as usize)
            .saturating_add((x as usize).saturating_mul(bpp as usize));
        match self.format {
            PixelFormat::Rgba8888 => {
                if let Some(px) = self.buffer.get(offset..offset + 4) {
                    (px[0] as u32) << 24 | (px[1] as u32) << 16 | (px[2] as u32) << 8 | px[3] as u32
                } else {
                    0
                }
            }
            PixelFormat::Bgra8888 => {
                if let Some(px) = self.buffer.get(offset..offset + 4) {
                    (px[2] as u32) << 24 | (px[1] as u32) << 16 | (px[0] as u32) << 8 | px[3] as u32
                } else {
                    0
                }
            }
            PixelFormat::Rgb888 => {
                if let Some(px) = self.buffer.get(offset..offset + 3) {
                    (px[0] as u32) << 24 | (px[1] as u32) << 16 | (px[2] as u32) << 8 | 0xFF
                } else {
                    0
                }
            }
        }
    }

    /// Fill a rectangular region with a solid color.
    ///
    /// Pixels outside the framebuffer are clipped.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let x_end = (x.saturating_add(w)).min(self.width);
        let y_end = (y.saturating_add(h)).min(self.height);
        let x_start = x.min(self.width);
        let y_start = y.min(self.height);
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

    /// Clear the entire framebuffer to a solid color.
    pub fn clear(&mut self, color: u32) {
        self.fill_rect(0, 0, self.width, self.height, color);
    }

    /// Render an 8x16 bitmap font character at pixel position `(x, y)`.
    ///
    /// `ch` is an ASCII byte; characters outside 32..=126 render as
    /// a solid block. `fg` and `bg` are RGBA-packed colors.
    pub fn draw_char(&mut self, x: u32, y: u32, ch: u8, fg: u32, bg: u32) {
        let glyph_idx = if (32..=126).contains(&ch) {
            (ch - 32) as usize
        } else {
            0 // fallback to space for non-printable
        };
        let glyph_offset = glyph_idx * (FONT_HEIGHT as usize);
        let mut row: u32 = 0;
        while row < FONT_HEIGHT {
            let font_byte = if let Some(&b) = FONT_8X16.get(glyph_offset + row as usize) {
                b
            } else {
                0
            };
            let mut col: u32 = 0;
            while col < FONT_WIDTH {
                let mask = 0x80u8 >> (col as u8);
                let color = if font_byte & mask != 0 { fg } else { bg };
                self.put_pixel(x.saturating_add(col), y.saturating_add(row), color);
                col = col.saturating_add(1);
            }
            row = row.saturating_add(1);
        }
    }

    /// Scroll the framebuffer up by `lines` pixel rows.
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
        let stride = self.stride as usize;
        let shift_bytes = (lines as usize).saturating_mul(stride);
        let total_bytes = (self.height as usize).saturating_mul(stride);
        let copy_bytes = total_bytes.saturating_sub(shift_bytes);

        // Copy rows upward within the buffer.
        // SAFETY: `src` and `dst` are within `self.buffer` and we
        // handle the overlapping copy direction manually (forward
        // copy is correct when dst < src).
        if copy_bytes > 0 && shift_bytes < total_bytes {
            let ptr = self.buffer.as_mut_ptr();
            unsafe {
                core::ptr::copy(ptr.add(shift_bytes), ptr, copy_bytes);
            }
        }

        // Fill the vacated bottom region.
        let clear_y = self.height.saturating_sub(lines);
        self.fill_rect(0, clear_y, self.width, lines, bg_color);
    }
}

impl core::fmt::Debug for Framebuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Framebuffer")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("format", &self.format)
            .finish()
    }
}

// -----------------------------------------------------------------------
// Text console
// -----------------------------------------------------------------------

/// Text-mode console rendered on top of a [`Framebuffer`].
///
/// Maps a grid of character cells (columns x rows) to pixel
/// positions, handles line wrapping, newlines, tabs, and scrolling.
pub struct TextConsole {
    /// Underlying framebuffer for rendering.
    pub fb: Framebuffer,
    /// Current cursor column (0-based, in character cells).
    pub cursor_x: u32,
    /// Current cursor row (0-based, in character cells).
    pub cursor_y: u32,
    /// Number of text columns.
    pub cols: u32,
    /// Number of text rows.
    pub rows: u32,
    /// Foreground (text) color in RGBA-packed format.
    pub fg_color: u32,
    /// Background color in RGBA-packed format.
    pub bg_color: u32,
}

impl TextConsole {
    /// Create a new text console on the given framebuffer.
    ///
    /// Calculates columns and rows from the framebuffer dimensions
    /// and the 8x16 font size.
    pub fn new(fb: Framebuffer) -> Self {
        let cols = fb.width / FONT_WIDTH;
        let rows = fb.height / FONT_HEIGHT;
        Self {
            fb,
            cursor_x: 0,
            cursor_y: 0,
            cols,
            rows,
            fg_color: 0xFFFFFFFF, // white
            bg_color: 0x000000FF, // black
        }
    }

    /// Write a single byte to the console.
    ///
    /// Handles printable ASCII, `\n` (0x0A), `\r` (0x0D), and
    /// `\t` (0x09, expands to 4-space tab stops). Non-printable
    /// bytes outside these are silently ignored.
    pub fn write_char(&mut self, ch: u8) {
        match ch {
            b'\n' => self.newline(),
            b'\r' => {
                self.cursor_x = 0;
            }
            b'\t' => {
                // Tab stop every 4 columns.
                let next_tab = (self.cursor_x / 4).saturating_add(1).saturating_mul(4);
                let spaces = next_tab.saturating_sub(self.cursor_x);
                let mut i: u32 = 0;
                while i < spaces {
                    self.write_char(b' ');
                    i = i.saturating_add(1);
                }
            }
            0x20..=0x7E => {
                // Wrap if at end of line.
                if self.cursor_x >= self.cols {
                    self.newline();
                }
                let px = self.cursor_x.saturating_mul(FONT_WIDTH);
                let py = self.cursor_y.saturating_mul(FONT_HEIGHT);
                self.fb.draw_char(px, py, ch, self.fg_color, self.bg_color);
                self.cursor_x = self.cursor_x.saturating_add(1);
            }
            _ => {} // ignore other control chars
        }
    }

    /// Write a byte slice to the console.
    pub fn write_str(&mut self, s: &[u8]) {
        let mut i = 0;
        while i < s.len() {
            self.write_char(s[i]);
            i += 1;
        }
    }

    /// Advance the cursor to the start of the next line.
    ///
    /// If the cursor is already on the last row, the framebuffer
    /// scrolls up by one text line.
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

impl core::fmt::Debug for TextConsole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TextConsole")
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("cursor", &(self.cursor_x, self.cursor_y))
            .field("fg_color", &self.fg_color)
            .field("bg_color", &self.bg_color)
            .finish()
    }
}
