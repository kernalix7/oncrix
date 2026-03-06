// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM/KMS (Direct Rendering Manager / Kernel Mode Setting) subsystem.
//!
//! Implements the Kernel Mode Setting layer: connector detection,
//! CRTC/encoder/plane management, mode enumeration, and display
//! pipeline configuration. The DRM core provides the object model;
//! specific hardware drivers (VESA, virtio-GPU, platform display)
//! plug in via the [`DrmDriver`] trait.
//!
//! # Architecture
//!
//! The DRM/KMS object hierarchy follows the Linux DRM model:
//!
//! ```text
//! Connector ──► Encoder ──► CRTC ──► Plane (framebuffer)
//! ```
//!
//! - **Connector** — physical output (HDMI, DP, VGA, LVDS, DSI).
//!   Detects hotplug and reads EDID to enumerate supported modes.
//! - **Encoder** — converts pixel data to an output signal format
//!   (TMDS for HDMI/DVI, LVDS, eDP, DAC for VGA).
//! - **CRTC** (Cathode Ray Tube Controller) — scans a framebuffer
//!   out through timing generators. Controls refresh rate, blanking,
//!   and mode timings.
//! - **Plane** — represents a hardware layer that feeds a CRTC.
//!   Primary planes carry the main framebuffer; overlay planes
//!   are used for hardware cursor or video overlay.
//! - **Framebuffer** — a memory-backed pixel buffer attached to a
//!   plane. Described by width, height, pitch, and pixel format.
//!
//! # Mode Setting Flow
//!
//! 1. Enumerate connectors and read EDID → build mode list.
//! 2. Select a mode (e.g., preferred or highest resolution).
//! 3. Attach an encoder to the connector.
//! 4. Configure the CRTC with the mode timings.
//! 5. Allocate a framebuffer and attach it to the primary plane.
//! 6. Commit the atomic state: CRTC + plane + connector.
//!
//! Reference: Linux DRM/KMS documentation,
//!            VESA Monitor Timing Standard,
//!            HDMI 2.1 specification.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ── Limits ────────────────────────────────────────────────────────

/// Maximum number of connectors per DRM device.
const MAX_CONNECTORS: usize = 8;

/// Maximum number of encoders per DRM device.
const MAX_ENCODERS: usize = 8;

/// Maximum number of CRTCs per DRM device.
const MAX_CRTCS: usize = 4;

/// Maximum number of planes per DRM device.
const MAX_PLANES: usize = 16;

/// Maximum number of display modes per connector.
const MAX_MODES: usize = 32;

/// Maximum number of DRM devices in the registry.
const MAX_DEVICES: usize = 4;

/// EDID block size in bytes.
const EDID_BLOCK_SIZE: usize = 128;

// ── Pixel Formats ────────────────────────────────────────────────

/// Pixel format (fourcc-style encoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PixelFormat {
    /// 24-bit RGB (8 bits per channel, no alpha).
    #[default]
    Rgb888,
    /// 32-bit XRGB (8 bits per channel, 8-bit padding).
    Xrgb8888,
    /// 32-bit ARGB (8 bits per channel, 8-bit alpha).
    Argb8888,
    /// 16-bit RGB565.
    Rgb565,
    /// 16-bit YUV 4:2:2 (YUYV interleaved).
    Yuyv,
    /// 32-bit XBGR (big-endian byte order).
    Xbgr8888,
}

impl PixelFormat {
    /// Return the bits per pixel for this format.
    pub fn bpp(self) -> u32 {
        match self {
            PixelFormat::Rgb888 => 24,
            PixelFormat::Xrgb8888 | PixelFormat::Argb8888 | PixelFormat::Xbgr8888 => 32,
            PixelFormat::Rgb565 | PixelFormat::Yuyv => 16,
        }
    }

    /// Return the bytes per pixel (rounded up).
    pub fn bytes_per_pixel(self) -> u32 {
        (self.bpp() + 7) / 8
    }
}

// ── Display Mode ─────────────────────────────────────────────────

/// A display mode (timing specification).
///
/// All timing values are in pixels (horizontal) or lines (vertical).
/// Blanking = front porch + sync + back porch.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayMode {
    /// Pixel clock in kHz (e.g., 148500 for 1920×1080@60).
    pub pixel_clock_khz: u32,
    /// Horizontal active pixels.
    pub hdisplay: u16,
    /// Horizontal front porch (pixels before sync).
    pub hsync_start: u16,
    /// Horizontal sync end.
    pub hsync_end: u16,
    /// Total horizontal pixels (active + blanking).
    pub htotal: u16,
    /// Vertical active lines.
    pub vdisplay: u16,
    /// Vertical front porch.
    pub vsync_start: u16,
    /// Vertical sync end.
    pub vsync_end: u16,
    /// Total vertical lines.
    pub vtotal: u16,
    /// Mode flags (see `MODE_FLAG_*`).
    pub flags: u32,
    /// Human-readable name (e.g., "1920x1080").
    pub name: [u8; 20],
    /// Whether this is the connector's preferred mode.
    pub preferred: bool,
}

/// Positive horizontal sync polarity.
pub const MODE_FLAG_PHSYNC: u32 = 1 << 0;
/// Negative horizontal sync polarity.
pub const MODE_FLAG_NHSYNC: u32 = 1 << 1;
/// Positive vertical sync polarity.
pub const MODE_FLAG_PVSYNC: u32 = 1 << 2;
/// Negative vertical sync polarity.
pub const MODE_FLAG_NVSYNC: u32 = 1 << 3;
/// Interlaced scan mode.
pub const MODE_FLAG_INTERLACE: u32 = 1 << 4;

impl DisplayMode {
    /// Compute the vertical refresh rate in Hz (integer approximation).
    pub fn vrefresh(&self) -> u32 {
        if self.htotal == 0 || self.vtotal == 0 {
            return 0;
        }
        let pixels_per_frame = self.htotal as u64 * self.vtotal as u64;
        (self.pixel_clock_khz as u64 * 1000 / pixels_per_frame) as u32
    }

    /// Build a standard 1920×1080@60 Hz CEA mode.
    pub fn cea_1080p60() -> Self {
        let mut name = [0u8; 20];
        for (i, &b) in b"1920x1080".iter().enumerate() {
            name[i] = b;
        }
        Self {
            pixel_clock_khz: 148_500,
            hdisplay: 1920,
            hsync_start: 2008,
            hsync_end: 2052,
            htotal: 2200,
            vdisplay: 1080,
            vsync_start: 1084,
            vsync_end: 1089,
            vtotal: 1125,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            name,
            preferred: true,
        }
    }

    /// Build a standard 1280×720@60 Hz CEA mode.
    pub fn cea_720p60() -> Self {
        let mut name = [0u8; 20];
        for (i, &b) in b"1280x720".iter().enumerate() {
            name[i] = b;
        }
        Self {
            pixel_clock_khz: 74_250,
            hdisplay: 1280,
            hsync_start: 1390,
            hsync_end: 1430,
            htotal: 1650,
            vdisplay: 720,
            vsync_start: 725,
            vsync_end: 730,
            vtotal: 750,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            name,
            preferred: false,
        }
    }

    /// Build an 800×600@60 Hz VESA mode.
    pub fn vesa_800x600_60() -> Self {
        let mut name = [0u8; 20];
        for (i, &b) in b"800x600".iter().enumerate() {
            name[i] = b;
        }
        Self {
            pixel_clock_khz: 40_000,
            hdisplay: 800,
            hsync_start: 840,
            hsync_end: 968,
            htotal: 1056,
            vdisplay: 600,
            vsync_start: 601,
            vsync_end: 605,
            vtotal: 628,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            name,
            preferred: false,
        }
    }
}

// ── Connector ────────────────────────────────────────────────────

/// Connector output type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectorType {
    /// Unknown or platform-specific output.
    #[default]
    Unknown,
    /// VGA (analog D-Sub).
    Vga,
    /// DVI-D (digital).
    DviD,
    /// HDMI Type A.
    HdmiA,
    /// DisplayPort.
    DisplayPort,
    /// Low-Voltage Differential Signaling (flat panel).
    Lvds,
    /// Embedded DisplayPort (laptop panel).
    Edp,
    /// Display Serial Interface (mobile).
    Dsi,
    /// Virtual connector (hypervisor/virtio display).
    Virtual,
}

/// Connector connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectorStatus {
    /// A display is connected and responding.
    #[default]
    Connected,
    /// No display is connected.
    Disconnected,
    /// Connection status is unknown.
    Unknown,
}

/// A DRM connector — represents a physical output port.
#[derive(Debug)]
pub struct Connector {
    /// Connector ID (unique within the DRM device).
    pub id: u32,
    /// Connector type.
    pub connector_type: ConnectorType,
    /// Connection status.
    pub status: ConnectorStatus,
    /// Supported display modes.
    pub modes: [Option<DisplayMode>; MAX_MODES],
    /// Number of valid modes.
    pub mode_count: usize,
    /// Currently active mode (index into `modes`).
    pub active_mode: Option<usize>,
    /// Physical size of the connected display in millimetres.
    pub width_mm: u32,
    pub height_mm: u32,
    /// Encoder currently bound to this connector.
    pub encoder_id: Option<u32>,
    /// Whether this connector supports EDID.
    pub has_edid: bool,
}

impl Connector {
    /// Create a new connector.
    pub fn new(id: u32, connector_type: ConnectorType) -> Self {
        Self {
            id,
            connector_type,
            status: ConnectorStatus::Unknown,
            modes: [None; MAX_MODES],
            mode_count: 0,
            active_mode: None,
            width_mm: 0,
            height_mm: 0,
            encoder_id: None,
            has_edid: false,
        }
    }

    /// Add a display mode to this connector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the mode list is full.
    pub fn add_mode(&mut self, mode: DisplayMode) -> Result<()> {
        if self.mode_count >= MAX_MODES {
            return Err(Error::OutOfMemory);
        }
        self.modes[self.mode_count] = Some(mode);
        self.mode_count += 1;
        Ok(())
    }

    /// Return the preferred mode (if any).
    pub fn preferred_mode(&self) -> Option<&DisplayMode> {
        for m in &self.modes[..self.mode_count] {
            if let Some(mode) = m {
                if mode.preferred {
                    return Some(mode);
                }
            }
        }
        None
    }

    /// Return the mode with the highest total pixel count.
    pub fn best_mode(&self) -> Option<&DisplayMode> {
        let mut best: Option<&DisplayMode> = None;
        let mut best_pixels = 0u32;
        for m in &self.modes[..self.mode_count] {
            if let Some(mode) = m {
                let pixels = mode.hdisplay as u32 * mode.vdisplay as u32;
                if pixels > best_pixels {
                    best_pixels = pixels;
                    best = Some(mode);
                }
            }
        }
        best
    }

    /// Populate default modes for a virtual/unknown connector.
    pub fn populate_default_modes(&mut self) {
        let _ = self.add_mode(DisplayMode::cea_1080p60());
        let _ = self.add_mode(DisplayMode::cea_720p60());
        let _ = self.add_mode(DisplayMode::vesa_800x600_60());
        self.status = ConnectorStatus::Connected;
    }

    /// Attempt to parse EDID and add modes.
    ///
    /// `edid` must be exactly 128 bytes (one EDID block).
    /// On parse failure, falls back to default modes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `edid.len() != 128` or
    /// the EDID magic bytes are wrong.
    pub fn parse_edid(&mut self, edid: &[u8]) -> Result<()> {
        if edid.len() != EDID_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Verify EDID magic: 00 FF FF FF FF FF FF 00.
        let magic = [0x00u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        if edid[..8] != magic {
            return Err(Error::InvalidArgument);
        }

        // Physical dimensions: bytes[21:22] = width cm, height cm.
        self.width_mm = edid[21] as u32 * 10;
        self.height_mm = edid[22] as u32 * 10;

        // Parse up to 4 detailed timing descriptors (bytes[54..126]).
        // Each descriptor is 18 bytes. Pixel clock at bytes[0:1] (10 kHz units).
        for i in 0..4usize {
            let base = 54 + i * 18;
            let pclk_lo = edid[base] as u32;
            let pclk_hi = edid[base + 1] as u32;
            let pixel_clock_khz = (pclk_hi << 8 | pclk_lo) * 10;

            if pixel_clock_khz == 0 {
                // Monitor/range descriptor, not a timing descriptor.
                continue;
            }

            let hdisplay = (edid[base + 2] as u16) | (((edid[base + 4] as u16) & 0xF0) << 4);
            let hblank = (edid[base + 3] as u16) | (((edid[base + 4] as u16) & 0x0F) << 8);
            let htotal = hdisplay + hblank;

            let vdisplay = (edid[base + 5] as u16) | (((edid[base + 7] as u16) & 0xF0) << 4);
            let vblank = (edid[base + 6] as u16) | (((edid[base + 7] as u16) & 0x0F) << 8);
            let vtotal = vdisplay + vblank;

            let hfp = (edid[base + 8] as u16) | (((edid[base + 11] as u16) >> 6) << 8);
            let hsw = (edid[base + 9] as u16) | ((((edid[base + 11] as u16) >> 4) & 0x3) << 8);
            let vfp =
                ((edid[base + 10] as u16) >> 4) | ((((edid[base + 11] as u16) >> 2) & 0x3) << 4);
            let vsw = (edid[base + 10] as u16) & 0xF | (((edid[base + 11] as u16) & 0x3) << 4);

            let flags_byte = edid[base + 17];
            let mut flags = 0u32;
            if flags_byte & (1 << 1) != 0 {
                flags |= MODE_FLAG_PHSYNC;
            } else {
                flags |= MODE_FLAG_NHSYNC;
            }
            if flags_byte & (1 << 2) != 0 {
                flags |= MODE_FLAG_PVSYNC;
            } else {
                flags |= MODE_FLAG_NVSYNC;
            }

            let mut name = [0u8; 20];
            // Simple name: "{hdisplay}x{vdisplay}" (approximate).
            let _ = write_u16_to(&mut name, 0, hdisplay);

            let mode = DisplayMode {
                pixel_clock_khz,
                hdisplay,
                hsync_start: hdisplay + hfp,
                hsync_end: hdisplay + hfp + hsw,
                htotal,
                vdisplay,
                vsync_start: vdisplay + vfp,
                vsync_end: vdisplay + vfp + vsw,
                vtotal,
                flags,
                name,
                preferred: i == 0, // First detailed timing is preferred.
            };
            let _ = self.add_mode(mode);
        }

        if self.mode_count == 0 {
            self.populate_default_modes();
        }

        self.has_edid = true;
        self.status = ConnectorStatus::Connected;
        Ok(())
    }
}

/// Write a u16 decimal value into a byte buffer at `offset`.
/// Returns the number of bytes written.
fn write_u16_to(buf: &mut [u8], offset: usize, mut val: u16) -> usize {
    if offset >= buf.len() {
        return 0;
    }
    if val == 0 {
        buf[offset] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 5];
    let mut len = 0usize;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let mut written = 0usize;
    for i in (0..len).rev() {
        if offset + written >= buf.len() {
            break;
        }
        buf[offset + written] = tmp[i];
        written += 1;
    }
    written
}

// ── Encoder ───────────────────────────────────────────────────────

/// Encoder type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncoderType {
    /// No encoder (pass-through).
    #[default]
    None,
    /// DAC encoder (VGA analog).
    Dac,
    /// TMDS encoder (HDMI/DVI digital).
    Tmds,
    /// LVDS encoder.
    Lvds,
    /// Virtual encoder.
    Virtual,
}

/// A DRM encoder — converts pixel data to an output format.
#[derive(Debug)]
pub struct Encoder {
    /// Encoder ID.
    pub id: u32,
    /// Encoder type.
    pub encoder_type: EncoderType,
    /// CRTC this encoder is currently bound to.
    pub crtc_id: Option<u32>,
    /// Bitmask of possible CRTCs (bit N = CRTC index N).
    pub possible_crtcs: u32,
    /// Bitmask of possible clones (sibling encoders for dual-head).
    pub possible_clones: u32,
}

impl Encoder {
    /// Create a new encoder.
    pub fn new(id: u32, encoder_type: EncoderType, possible_crtcs: u32) -> Self {
        Self {
            id,
            encoder_type,
            crtc_id: None,
            possible_crtcs,
            possible_clones: 0,
        }
    }
}

// ── Framebuffer ───────────────────────────────────────────────────

/// A DRM framebuffer — a memory-backed pixel buffer.
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    /// Framebuffer ID.
    pub id: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row (stride/pitch).
    pub pitch: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Physical base address of the framebuffer memory.
    pub paddr: u64,
    /// Size of the framebuffer in bytes.
    pub size: u64,
}

impl Framebuffer {
    /// Compute the minimum pitch for the given width and format.
    pub fn min_pitch(width: u32, format: PixelFormat) -> u32 {
        width * format.bytes_per_pixel()
    }

    /// Compute the minimum framebuffer size in bytes.
    pub fn min_size(width: u32, height: u32, format: PixelFormat) -> u64 {
        Self::min_pitch(width, format) as u64 * height as u64
    }
}

// ── Plane ─────────────────────────────────────────────────────────

/// Plane type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlaneType {
    /// Primary plane (main display buffer).
    #[default]
    Primary,
    /// Cursor plane (hardware cursor sprite).
    Cursor,
    /// Overlay plane (video or UI overlay).
    Overlay,
}

/// A DRM plane — a hardware scanout layer feeding a CRTC.
#[derive(Debug)]
pub struct Plane {
    /// Plane ID.
    pub id: u32,
    /// Plane type.
    pub plane_type: PlaneType,
    /// CRTC this plane is currently attached to.
    pub crtc_id: Option<u32>,
    /// Framebuffer currently attached to this plane.
    pub fb_id: Option<u32>,
    /// Bitmask of possible CRTCs.
    pub possible_crtcs: u32,
    /// Supported pixel formats.
    pub formats: [Option<PixelFormat>; 8],
    /// Number of supported formats.
    pub format_count: usize,
    /// Source x offset in the framebuffer (in 16.16 fixed point).
    pub src_x: u32,
    /// Source y offset.
    pub src_y: u32,
    /// Source width (16.16 fixed point).
    pub src_w: u32,
    /// Source height (16.16 fixed point).
    pub src_h: u32,
    /// Destination x in display coordinates (pixels).
    pub dst_x: i32,
    /// Destination y.
    pub dst_y: i32,
    /// Destination width.
    pub dst_w: u32,
    /// Destination height.
    pub dst_h: u32,
}

impl Plane {
    /// Create a new plane.
    pub fn new(id: u32, plane_type: PlaneType, possible_crtcs: u32) -> Self {
        Self {
            id,
            plane_type,
            crtc_id: None,
            fb_id: None,
            possible_crtcs,
            formats: [None; 8],
            format_count: 0,
            src_x: 0,
            src_y: 0,
            src_w: 0,
            src_h: 0,
            dst_x: 0,
            dst_y: 0,
            dst_w: 0,
            dst_h: 0,
        }
    }

    /// Add a supported pixel format.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the format list is full.
    pub fn add_format(&mut self, fmt: PixelFormat) -> Result<()> {
        if self.format_count >= 8 {
            return Err(Error::OutOfMemory);
        }
        self.formats[self.format_count] = Some(fmt);
        self.format_count += 1;
        Ok(())
    }

    /// Return `true` if the plane supports the given pixel format.
    pub fn supports_format(&self, fmt: PixelFormat) -> bool {
        self.formats[..self.format_count]
            .iter()
            .any(|f| *f == Some(fmt))
    }
}

// ── CRTC ─────────────────────────────────────────────────────────

/// CRTC state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrtcState {
    /// CRTC is disabled.
    #[default]
    Disabled,
    /// CRTC is enabled and actively scanning out.
    Enabled,
}

/// A CRTC (display controller) instance.
#[derive(Debug)]
pub struct Crtc {
    /// CRTC ID.
    pub id: u32,
    /// CRTC index (position in the device's CRTC array).
    pub index: u32,
    /// Current CRTC state.
    pub state: CrtcState,
    /// Active display mode.
    pub mode: Option<DisplayMode>,
    /// Primary plane ID.
    pub primary_plane_id: Option<u32>,
    /// Cursor plane ID.
    pub cursor_plane_id: Option<u32>,
    /// Current framebuffer ID.
    pub fb_id: Option<u32>,
    /// X offset in the framebuffer.
    pub x: u32,
    /// Y offset in the framebuffer.
    pub y: u32,
    /// VBLANK counter.
    pub vblank_count: u64,
    /// Gamma LUT size (number of entries per colour channel).
    pub gamma_size: u32,
}

impl Crtc {
    /// Create a new CRTC.
    pub fn new(id: u32, index: u32) -> Self {
        Self {
            id,
            index,
            state: CrtcState::Disabled,
            mode: None,
            primary_plane_id: None,
            cursor_plane_id: None,
            fb_id: None,
            x: 0,
            y: 0,
            vblank_count: 0,
            gamma_size: 256,
        }
    }

    /// Check if the given mode is valid (non-zero timings).
    pub fn mode_valid(mode: &DisplayMode) -> bool {
        mode.hdisplay > 0
            && mode.vdisplay > 0
            && mode.htotal >= mode.hdisplay
            && mode.vtotal >= mode.vdisplay
            && mode.pixel_clock_khz > 0
    }

    /// Enable the CRTC with the given mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the mode is invalid.
    pub fn enable(&mut self, mode: DisplayMode) -> Result<()> {
        if !Self::mode_valid(&mode) {
            return Err(Error::InvalidArgument);
        }
        self.mode = Some(mode);
        self.state = CrtcState::Enabled;
        Ok(())
    }

    /// Disable the CRTC.
    pub fn disable(&mut self) {
        self.state = CrtcState::Disabled;
        self.mode = None;
        self.fb_id = None;
    }

    /// Increment the vblank counter (called from interrupt handler).
    pub fn vblank(&mut self) {
        self.vblank_count = self.vblank_count.wrapping_add(1);
    }

    /// Return `true` if the CRTC is actively scanning out.
    pub fn is_active(&self) -> bool {
        self.state == CrtcState::Enabled
    }
}

// ── DRM Driver Trait ─────────────────────────────────────────────

/// Trait implemented by hardware-specific DRM drivers.
///
/// The driver is responsible for programming the physical display
/// pipeline registers when the KMS layer commits a new atomic state.
pub trait DrmDriver {
    /// Program the CRTC with the given mode and framebuffer.
    ///
    /// Called by the KMS atomic commit path.
    fn crtc_set_mode(&mut self, crtc: &Crtc, mode: &DisplayMode, fb: &Framebuffer) -> Result<()>;

    /// Disable the CRTC output.
    fn crtc_disable(&mut self, crtc: &Crtc) -> Result<()>;

    /// Flush a framebuffer update (page flip).
    fn plane_update(&mut self, plane: &Plane, fb: &Framebuffer) -> Result<()>;

    /// Detect connector state and populate modes.
    fn connector_detect(&mut self, connector: &mut Connector) -> ConnectorStatus;

    /// Read EDID data for a connector.
    ///
    /// Fills `edid` with up to 128 bytes of EDID data.
    /// Returns the number of bytes read.
    fn read_edid(&mut self, connector: &Connector, edid: &mut [u8]) -> usize;
}

// ── DRM Device ───────────────────────────────────────────────────

/// A DRM device — the top-level KMS object.
///
/// Owns all KMS resources: connectors, encoders, CRTCs, and planes.
/// Hardware drivers interact with the device through the [`DrmDriver`]
/// trait.
pub struct DrmDevice {
    /// Device index.
    pub index: usize,
    /// Connectors.
    connectors: [Option<Connector>; MAX_CONNECTORS],
    connector_count: usize,
    /// Encoders.
    encoders: [Option<Encoder>; MAX_ENCODERS],
    encoder_count: usize,
    /// CRTCs.
    crtcs: [Option<Crtc>; MAX_CRTCS],
    crtc_count: usize,
    /// Planes.
    planes: [Option<Plane>; MAX_PLANES],
    plane_count: usize,
    /// Next ID to assign to a new KMS object.
    next_id: u32,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl DrmDevice {
    /// Create a new, empty DRM device.
    pub fn new(index: usize) -> Self {
        Self {
            index,
            connectors: core::array::from_fn(|_| None),
            connector_count: 0,
            encoders: core::array::from_fn(|_| None),
            encoder_count: 0,
            crtcs: core::array::from_fn(|_| None),
            crtc_count: 0,
            planes: core::array::from_fn(|_| None),
            plane_count: 0,
            next_id: 1,
            initialized: false,
        }
    }

    /// Allocate the next unique KMS object ID.
    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Add a connector to the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the connector table is full.
    pub fn add_connector(&mut self, conn_type: ConnectorType) -> Result<u32> {
        if self.connector_count >= MAX_CONNECTORS {
            return Err(Error::OutOfMemory);
        }
        let id = self.alloc_id();
        self.connectors[self.connector_count] = Some(Connector::new(id, conn_type));
        self.connector_count += 1;
        Ok(id)
    }

    /// Add an encoder to the device.
    ///
    /// `possible_crtcs` is a bitmask of CRTC indices this encoder
    /// can be connected to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the encoder table is full.
    pub fn add_encoder(&mut self, enc_type: EncoderType, possible_crtcs: u32) -> Result<u32> {
        if self.encoder_count >= MAX_ENCODERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.alloc_id();
        self.encoders[self.encoder_count] = Some(Encoder::new(id, enc_type, possible_crtcs));
        self.encoder_count += 1;
        Ok(id)
    }

    /// Add a CRTC to the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the CRTC table is full.
    pub fn add_crtc(&mut self) -> Result<u32> {
        if self.crtc_count >= MAX_CRTCS {
            return Err(Error::OutOfMemory);
        }
        let id = self.alloc_id();
        let index = self.crtc_count as u32;
        self.crtcs[self.crtc_count] = Some(Crtc::new(id, index));
        self.crtc_count += 1;
        Ok(id)
    }

    /// Add a plane to the device.
    ///
    /// `possible_crtcs` is a bitmask of CRTC indices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the plane table is full.
    pub fn add_plane(&mut self, plane_type: PlaneType, possible_crtcs: u32) -> Result<u32> {
        if self.plane_count >= MAX_PLANES {
            return Err(Error::OutOfMemory);
        }
        let id = self.alloc_id();
        self.planes[self.plane_count] = Some(Plane::new(id, plane_type, possible_crtcs));
        self.plane_count += 1;
        Ok(id)
    }

    /// Look up a connector by ID.
    pub fn connector_mut(&mut self, id: u32) -> Option<&mut Connector> {
        self.connectors[..self.connector_count]
            .iter_mut()
            .find_map(|c| c.as_mut().filter(|c| c.id == id))
    }

    /// Look up a CRTC by ID.
    pub fn crtc_mut(&mut self, id: u32) -> Option<&mut Crtc> {
        self.crtcs[..self.crtc_count]
            .iter_mut()
            .find_map(|c| c.as_mut().filter(|c| c.id == id))
    }

    /// Look up a plane by ID.
    pub fn plane_mut(&mut self, id: u32) -> Option<&mut Plane> {
        self.planes[..self.plane_count]
            .iter_mut()
            .find_map(|p| p.as_mut().filter(|p| p.id == id))
    }

    /// Look up an encoder by ID.
    pub fn encoder_mut(&mut self, id: u32) -> Option<&mut Encoder> {
        self.encoders[..self.encoder_count]
            .iter_mut()
            .find_map(|e| e.as_mut().filter(|e| e.id == id))
    }

    /// Perform a simple mode-set on a CRTC.
    ///
    /// Associates `connector_id` → `encoder_id` → `crtc_id`, sets
    /// the mode, and attaches the framebuffer to the primary plane.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if any ID is not found, or
    /// [`Error::InvalidArgument`] if the mode is invalid.
    pub fn mode_set(
        &mut self,
        crtc_id: u32,
        connector_id: u32,
        encoder_id: u32,
        mode: DisplayMode,
        fb: Framebuffer,
    ) -> Result<()> {
        // Bind connector → encoder.
        {
            let conn = self.connector_mut(connector_id).ok_or(Error::NotFound)?;
            conn.encoder_id = Some(encoder_id);
        }

        // Bind encoder → CRTC.
        {
            let enc = self.encoder_mut(encoder_id).ok_or(Error::NotFound)?;
            enc.crtc_id = Some(crtc_id);
        }

        // Enable CRTC with the mode.
        {
            let crtc = self.crtc_mut(crtc_id).ok_or(Error::NotFound)?;
            crtc.enable(mode)?;
            crtc.fb_id = Some(fb.id);
        }

        Ok(())
    }

    /// Detect all connectors and populate their mode lists.
    ///
    /// Calls the driver's `connector_detect` for each connector.
    pub fn detect_connectors<D: DrmDriver>(&mut self, driver: &mut D) {
        for slot in self.connectors[..self.connector_count].iter_mut() {
            if let Some(conn) = slot {
                let status = driver.connector_detect(conn);
                conn.status = status;
                if status == ConnectorStatus::Connected && conn.mode_count == 0 {
                    // Read EDID and try to parse modes.
                    let mut edid = [0u8; EDID_BLOCK_SIZE];
                    let len = driver.read_edid(conn, &mut edid);
                    if len == EDID_BLOCK_SIZE {
                        let _ = conn.parse_edid(&edid);
                    }
                    if conn.mode_count == 0 {
                        conn.populate_default_modes();
                    }
                }
            }
        }
    }

    /// Perform an atomic commit using the driver.
    ///
    /// For each active CRTC that has an associated framebuffer, calls
    /// the driver's `crtc_set_mode`. For each enabled plane, calls
    /// `plane_update`.
    ///
    /// # Errors
    ///
    /// Returns the first driver error encountered.
    pub fn atomic_commit<D: DrmDriver>(&mut self, driver: &mut D, fb: &Framebuffer) -> Result<()> {
        for slot in self.crtcs[..self.crtc_count].iter() {
            if let Some(crtc) = slot {
                if crtc.is_active() {
                    if let Some(mode) = &crtc.mode {
                        driver.crtc_set_mode(crtc, mode, fb)?;
                    }
                }
            }
        }

        for slot in self.planes[..self.plane_count].iter() {
            if let Some(plane) = slot {
                if plane.fb_id.is_some() {
                    driver.plane_update(plane, fb)?;
                }
            }
        }

        Ok(())
    }

    /// Handle a VBLANK interrupt on a CRTC.
    ///
    /// Increments the VBLANK counter for the given CRTC.
    pub fn handle_vblank(&mut self, crtc_id: u32) {
        if let Some(crtc) = self.crtc_mut(crtc_id) {
            crtc.vblank();
        }
    }

    /// Return the number of connectors.
    pub fn connector_count(&self) -> usize {
        self.connector_count
    }

    /// Return the number of CRTCs.
    pub fn crtc_count(&self) -> usize {
        self.crtc_count
    }

    /// Return the number of planes.
    pub fn plane_count(&self) -> usize {
        self.plane_count
    }

    /// Return `true` if the device has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Mark the device as initialized.
    pub fn set_initialized(&mut self) {
        self.initialized = true;
    }

    /// Initialize a minimal single-output display pipeline.
    ///
    /// Creates one connector, one encoder, one CRTC, and one primary
    /// plane. Suitable for simple virtual or emulated displays.
    ///
    /// Returns `(connector_id, encoder_id, crtc_id, plane_id)`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`add_connector`], [`add_encoder`],
    /// [`add_crtc`], and [`add_plane`].
    pub fn init_simple_pipeline(
        &mut self,
        conn_type: ConnectorType,
        enc_type: EncoderType,
    ) -> Result<(u32, u32, u32, u32)> {
        let conn_id = self.add_connector(conn_type)?;
        let crtc_id = self.add_crtc()?;
        let enc_id = self.add_encoder(enc_type, 0x1)?;
        let plane_id = self.add_plane(PlaneType::Primary, 0x1)?;

        // Attach primary plane to CRTC.
        if let Some(crtc) = self.crtc_mut(crtc_id) {
            crtc.primary_plane_id = Some(plane_id);
        }

        self.set_initialized();
        Ok((conn_id, enc_id, crtc_id, plane_id))
    }
}

// ── Registry ─────────────────────────────────────────────────────

/// Registry for DRM devices.
pub struct DrmRegistry {
    /// MMIO base addresses of registered DRM devices.
    devices: [Option<usize>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for DrmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DrmRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None; MAX_DEVICES],
            count: 0,
        }
    }

    /// Register a DRM device by its MMIO base address.
    ///
    /// Returns the assigned device index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: usize) -> Result<usize> {
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Get the MMIO base address of a registered device.
    pub fn get(&self, index: usize) -> Option<usize> {
        if index < self.count {
            self.devices[index]
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
