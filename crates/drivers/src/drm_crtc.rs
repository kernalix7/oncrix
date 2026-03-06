// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM CRTC (CRT Controller) display pipeline abstraction.
//!
//! Implements the DRM CRTC subsystem for managing display pipelines,
//! mode setting, and vblank events. Each CRTC scans a framebuffer
//! through timing generators that drive the display output.
//!
//! # Architecture
//!
//! - [`DisplayMode`] -- a display timing mode (resolution, refresh
//!   rate, blanking intervals, sync polarities).
//! - [`CrtcState`] -- the current state of a CRTC (enabled, mode,
//!   framebuffer reference, gamma LUT).
//! - [`VblankEvent`] -- a vertical blanking interrupt event.
//! - [`PlaneType`] -- primary, overlay, or cursor plane classification.
//! - [`DrmPlane`] -- a hardware plane feeding a CRTC.
//! - [`DrmCrtc`] -- a single CRTC display pipeline.
//! - [`DrmCrtcRegistry`] -- manages up to [`MAX_CRTCS`] controllers.
//!
//! # Mode Setting Flow
//!
//! 1. Select a [`DisplayMode`] from the connector's mode list.
//! 2. Configure the CRTC with the mode via [`DrmCrtc::set_mode`].
//! 3. Attach a framebuffer to the primary plane via
//!    [`DrmCrtc::set_primary_fb`].
//! 4. Enable the CRTC via [`DrmCrtc::enable`].
//! 5. Optionally register for vblank events.
//!
//! Reference: Linux DRM/KMS subsystem,
//!            VESA Monitor Timing Standard,
//!            HDMI 2.1 specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CRTCs in the registry.
const MAX_CRTCS: usize = 8;

/// Maximum display modes per CRTC.
const MAX_MODES: usize = 32;

/// Maximum planes per CRTC.
const MAX_PLANES: usize = 8;

/// Maximum pending vblank events.
const MAX_VBLANK_EVENTS: usize = 16;

/// Gamma LUT entries per channel.
const GAMMA_LUT_SIZE: usize = 256;

/// Maximum CRTC name length.
const MAX_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// PixelFormat
// ---------------------------------------------------------------------------

/// Pixel format (fourcc-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PixelFormat {
    /// 24-bit RGB (8 bits per channel, no alpha).
    Rgb888,
    /// 32-bit XRGB (8 bits per channel, 8-bit padding).
    #[default]
    Xrgb8888,
    /// 32-bit ARGB (8 bits per channel, 8-bit alpha).
    Argb8888,
    /// 16-bit RGB565.
    Rgb565,
    /// 32-bit XBGR (big-endian byte order).
    Xbgr8888,
}

impl PixelFormat {
    /// Returns bits per pixel for this format.
    pub fn bpp(self) -> u32 {
        match self {
            Self::Rgb888 => 24,
            Self::Xrgb8888 | Self::Argb8888 | Self::Xbgr8888 => 32,
            Self::Rgb565 => 16,
        }
    }

    /// Returns bytes per pixel (rounded up).
    pub fn bytes_per_pixel(self) -> u32 {
        (self.bpp() + 7) / 8
    }
}

// ---------------------------------------------------------------------------
// SyncPolarity
// ---------------------------------------------------------------------------

/// Horizontal/vertical sync polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncPolarity {
    /// Positive sync pulse.
    #[default]
    Positive,
    /// Negative sync pulse.
    Negative,
}

// ---------------------------------------------------------------------------
// DisplayMode
// ---------------------------------------------------------------------------

/// A display timing mode.
///
/// Contains the complete timing parameters needed to drive a display:
/// pixel clock, active area, blanking intervals, sync widths, and
/// sync polarities.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayMode {
    /// Pixel clock in kHz.
    pub clock_khz: u32,
    /// Horizontal active pixels.
    pub hdisplay: u16,
    /// Horizontal sync start.
    pub hsync_start: u16,
    /// Horizontal sync end.
    pub hsync_end: u16,
    /// Horizontal total pixels.
    pub htotal: u16,
    /// Vertical active lines.
    pub vdisplay: u16,
    /// Vertical sync start.
    pub vsync_start: u16,
    /// Vertical sync end.
    pub vsync_end: u16,
    /// Vertical total lines.
    pub vtotal: u16,
    /// Horizontal sync polarity.
    pub hsync_polarity: SyncPolarity,
    /// Vertical sync polarity.
    pub vsync_polarity: SyncPolarity,
    /// Whether this is an interlaced mode.
    pub interlaced: bool,
    /// Refresh rate in millihertz (e.g., 60000 = 60.000 Hz).
    pub refresh_mhz: u32,
    /// Mode flags (vendor-specific).
    pub flags: u32,
}

impl DisplayMode {
    /// Computes the refresh rate in millihertz from timing parameters.
    ///
    /// `refresh_mhz = clock_khz * 1_000_000 / (htotal * vtotal)`
    pub fn compute_refresh(&self) -> u32 {
        let total = self.htotal as u64 * self.vtotal as u64;
        if total == 0 {
            return 0;
        }
        let rate = self.clock_khz as u64 * 1_000_000 / total;
        rate as u32
    }

    /// Returns the horizontal blanking period in pixels.
    pub fn hblank(&self) -> u16 {
        self.htotal.saturating_sub(self.hdisplay)
    }

    /// Returns the vertical blanking period in lines.
    pub fn vblank(&self) -> u16 {
        self.vtotal.saturating_sub(self.vdisplay)
    }

    /// Returns `true` if this mode has valid timing parameters.
    pub fn is_valid(&self) -> bool {
        self.hdisplay > 0
            && self.vdisplay > 0
            && self.htotal >= self.hdisplay
            && self.vtotal >= self.vdisplay
            && self.hsync_start >= self.hdisplay
            && self.hsync_end >= self.hsync_start
            && self.htotal >= self.hsync_end
            && self.vsync_start >= self.vdisplay
            && self.vsync_end >= self.vsync_start
            && self.vtotal >= self.vsync_end
            && self.clock_khz > 0
    }

    /// Computes the required pitch (bytes per scanline) for a given
    /// pixel format.
    pub fn pitch(&self, format: PixelFormat) -> u32 {
        self.hdisplay as u32 * format.bytes_per_pixel()
    }

    /// Computes the framebuffer size in bytes for a given format.
    pub fn framebuffer_size(&self, format: PixelFormat) -> usize {
        self.pitch(format) as usize * self.vdisplay as usize
    }
}

// ---------------------------------------------------------------------------
// CrtcState
// ---------------------------------------------------------------------------

/// Current state of a CRTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrtcPowerState {
    /// CRTC is disabled (no output).
    #[default]
    Disabled,
    /// CRTC is enabled and scanning.
    Enabled,
    /// CRTC is in DPMS standby.
    Standby,
    /// CRTC is in DPMS suspend.
    Suspend,
    /// CRTC is in DPMS off.
    Off,
}

/// Full state of a CRTC.
#[derive(Debug, Clone, Copy)]
pub struct CrtcState {
    /// Power/DPMS state.
    pub power: CrtcPowerState,
    /// Active display mode (if enabled).
    pub mode: DisplayMode,
    /// Whether a mode is set.
    pub mode_valid: bool,
    /// Pixel format of the primary framebuffer.
    pub format: PixelFormat,
    /// Primary framebuffer base address.
    pub fb_base: u64,
    /// Primary framebuffer pitch (bytes per scanline).
    pub fb_pitch: u32,
    /// Connector ID this CRTC is routed to (0 = none).
    pub connector_id: u32,
    /// Encoder ID this CRTC is routed through (0 = none).
    pub encoder_id: u32,
    /// Vblank count since CRTC was enabled.
    pub vblank_count: u64,
}

/// Constant empty CRTC state for initialisation.
const EMPTY_STATE: CrtcState = CrtcState {
    power: CrtcPowerState::Disabled,
    mode: DisplayMode {
        clock_khz: 0,
        hdisplay: 0,
        hsync_start: 0,
        hsync_end: 0,
        htotal: 0,
        vdisplay: 0,
        vsync_start: 0,
        vsync_end: 0,
        vtotal: 0,
        hsync_polarity: SyncPolarity::Positive,
        vsync_polarity: SyncPolarity::Positive,
        interlaced: false,
        refresh_mhz: 0,
        flags: 0,
    },
    mode_valid: false,
    format: PixelFormat::Xrgb8888,
    fb_base: 0,
    fb_pitch: 0,
    connector_id: 0,
    encoder_id: 0,
    vblank_count: 0,
};

// ---------------------------------------------------------------------------
// VblankEvent
// ---------------------------------------------------------------------------

/// A vertical blanking interrupt event from a CRTC.
#[derive(Debug, Clone, Copy, Default)]
pub struct VblankEvent {
    /// CRTC identifier that generated the event.
    pub crtc_id: u32,
    /// Vblank sequence number.
    pub sequence: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// PlaneType
// ---------------------------------------------------------------------------

/// Classification of a hardware display plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlaneType {
    /// Primary plane (main framebuffer).
    #[default]
    Primary,
    /// Overlay plane (video overlay, HW sprite).
    Overlay,
    /// Cursor plane (hardware cursor).
    Cursor,
}

// ---------------------------------------------------------------------------
// DrmPlane
// ---------------------------------------------------------------------------

/// A hardware display plane feeding a CRTC.
///
/// Each CRTC has at least one primary plane. Overlay and cursor
/// planes are optional hardware features.
#[derive(Debug, Clone, Copy)]
pub struct DrmPlane {
    /// Unique plane identifier.
    pub id: u32,
    /// Plane type.
    pub plane_type: PlaneType,
    /// Framebuffer base address.
    pub fb_base: u64,
    /// Source X offset (for panning/cropping).
    pub src_x: u32,
    /// Source Y offset.
    pub src_y: u32,
    /// Source width.
    pub src_w: u32,
    /// Source height.
    pub src_h: u32,
    /// Destination X offset on the CRTC.
    pub dst_x: i32,
    /// Destination Y offset on the CRTC.
    pub dst_y: i32,
    /// Destination width.
    pub dst_w: u32,
    /// Destination height.
    pub dst_h: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Whether this plane is enabled.
    pub enabled: bool,
    /// Z-order (lower = behind).
    pub zpos: u32,
}

/// Constant empty plane for array initialisation.
const EMPTY_PLANE: DrmPlane = DrmPlane {
    id: 0,
    plane_type: PlaneType::Primary,
    fb_base: 0,
    src_x: 0,
    src_y: 0,
    src_w: 0,
    src_h: 0,
    dst_x: 0,
    dst_y: 0,
    dst_w: 0,
    dst_h: 0,
    format: PixelFormat::Xrgb8888,
    enabled: false,
    zpos: 0,
};

// ---------------------------------------------------------------------------
// DrmCrtc
// ---------------------------------------------------------------------------

/// A single CRTC display pipeline.
///
/// Manages display mode setting, plane configuration, vblank events,
/// and gamma correction for one display output.
pub struct DrmCrtc {
    /// Unique CRTC identifier.
    pub id: u32,
    /// CRTC name.
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in name.
    pub name_len: usize,
    /// MMIO base address for CRTC registers.
    pub mmio_base: usize,
    /// Current CRTC state.
    pub state: CrtcState,
    /// Available display modes.
    modes: [DisplayMode; MAX_MODES],
    /// Number of available modes.
    mode_count: usize,
    /// Hardware planes.
    planes: [DrmPlane; MAX_PLANES],
    /// Number of planes.
    plane_count: usize,
    /// Vblank event queue (ring buffer).
    vblank_events: [VblankEvent; MAX_VBLANK_EVENTS],
    /// Write index.
    vblank_head: usize,
    /// Read index.
    vblank_tail: usize,
    /// Gamma red LUT.
    gamma_red: [u16; GAMMA_LUT_SIZE],
    /// Gamma green LUT.
    gamma_green: [u16; GAMMA_LUT_SIZE],
    /// Gamma blue LUT.
    gamma_blue: [u16; GAMMA_LUT_SIZE],
    /// Whether gamma correction is enabled.
    pub gamma_enabled: bool,
    /// Whether this CRTC is registered and active.
    pub active: bool,
}

impl DrmCrtc {
    /// Creates a new CRTC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty.
    pub fn new(id: u32, name: &[u8]) -> Result<Self> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let copy_len = name.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        Ok(Self {
            id,
            name: name_buf,
            name_len: copy_len,
            mmio_base: 0,
            state: EMPTY_STATE,
            modes: [DisplayMode::default(); MAX_MODES],
            mode_count: 0,
            planes: [EMPTY_PLANE; MAX_PLANES],
            plane_count: 0,
            vblank_events: [VblankEvent::default(); MAX_VBLANK_EVENTS],
            vblank_head: 0,
            vblank_tail: 0,
            gamma_red: [0u16; GAMMA_LUT_SIZE],
            gamma_green: [0u16; GAMMA_LUT_SIZE],
            gamma_blue: [0u16; GAMMA_LUT_SIZE],
            gamma_enabled: false,
            active: false,
        })
    }

    /// Sets the MMIO base address.
    pub fn set_mmio_base(&mut self, base: usize) {
        self.mmio_base = base;
    }

    /// Adds a display mode to the available mode list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the mode list is full, or
    /// [`Error::InvalidArgument`] if the mode is not valid.
    pub fn add_mode(&mut self, mode: DisplayMode) -> Result<()> {
        if self.mode_count >= MAX_MODES {
            return Err(Error::OutOfMemory);
        }
        if !mode.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.modes[self.mode_count] = mode;
        self.mode_count += 1;
        Ok(())
    }

    /// Returns the slice of available display modes.
    pub fn modes(&self) -> &[DisplayMode] {
        &self.modes[..self.mode_count]
    }

    /// Returns the number of available modes.
    pub fn mode_count(&self) -> usize {
        self.mode_count
    }

    /// Sets the active display mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the mode is not valid.
    pub fn set_mode(&mut self, mode: DisplayMode) -> Result<()> {
        if !mode.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.state.mode = mode;
        self.state.mode_valid = true;
        self.state.fb_pitch = mode.pitch(self.state.format);
        Ok(())
    }

    /// Sets the primary framebuffer address.
    pub fn set_primary_fb(&mut self, base: u64, format: PixelFormat) {
        self.state.fb_base = base;
        self.state.format = format;
        if self.state.mode_valid {
            self.state.fb_pitch = self.state.mode.pitch(format);
        }
    }

    /// Enables the CRTC and starts scanning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no mode is set or no
    /// framebuffer is configured.
    pub fn enable(&mut self) -> Result<()> {
        if !self.state.mode_valid {
            return Err(Error::InvalidArgument);
        }
        if self.state.fb_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.state.power = CrtcPowerState::Enabled;
        self.active = true;
        Ok(())
    }

    /// Disables the CRTC.
    pub fn disable(&mut self) {
        self.state.power = CrtcPowerState::Disabled;
        self.active = false;
    }

    /// Sets the DPMS power state.
    pub fn set_dpms(&mut self, state: CrtcPowerState) {
        self.state.power = state;
    }

    /// Adds a hardware plane.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the plane array is full.
    pub fn add_plane(&mut self, plane: DrmPlane) -> Result<()> {
        if self.plane_count >= MAX_PLANES {
            return Err(Error::OutOfMemory);
        }
        self.planes[self.plane_count] = plane;
        self.plane_count += 1;
        Ok(())
    }

    /// Returns the slice of planes.
    pub fn planes(&self) -> &[DrmPlane] {
        &self.planes[..self.plane_count]
    }

    /// Returns a mutable reference to a plane by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn plane_mut(&mut self, plane_id: u32) -> Result<&mut DrmPlane> {
        self.planes[..self.plane_count]
            .iter_mut()
            .find(|p| p.id == plane_id)
            .ok_or(Error::NotFound)
    }

    /// Handles a vblank interrupt.
    ///
    /// Increments the vblank counter and pushes an event.
    pub fn handle_vblank(&mut self, timestamp_ns: u64) {
        self.state.vblank_count += 1;
        let event = VblankEvent {
            crtc_id: self.id,
            sequence: self.state.vblank_count,
            timestamp_ns,
        };
        self.vblank_events[self.vblank_head] = event;
        self.vblank_head = (self.vblank_head + 1) % MAX_VBLANK_EVENTS;
        if self.vblank_head == self.vblank_tail {
            self.vblank_tail = (self.vblank_tail + 1) % MAX_VBLANK_EVENTS;
        }
    }

    /// Pops the oldest vblank event.
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop_vblank_event(&mut self) -> Option<VblankEvent> {
        if self.vblank_head == self.vblank_tail {
            return None;
        }
        let event = self.vblank_events[self.vblank_tail];
        self.vblank_tail = (self.vblank_tail + 1) % MAX_VBLANK_EVENTS;
        Some(event)
    }

    /// Sets the gamma LUT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the LUT slices are not
    /// exactly [`GAMMA_LUT_SIZE`] entries.
    pub fn set_gamma(&mut self, red: &[u16], green: &[u16], blue: &[u16]) -> Result<()> {
        if red.len() != GAMMA_LUT_SIZE
            || green.len() != GAMMA_LUT_SIZE
            || blue.len() != GAMMA_LUT_SIZE
        {
            return Err(Error::InvalidArgument);
        }
        self.gamma_red.copy_from_slice(red);
        self.gamma_green.copy_from_slice(green);
        self.gamma_blue.copy_from_slice(blue);
        self.gamma_enabled = true;
        Ok(())
    }

    /// Returns the current vblank count.
    pub fn vblank_count(&self) -> u64 {
        self.state.vblank_count
    }

    /// Routes this CRTC to a connector and encoder.
    pub fn set_routing(&mut self, connector_id: u32, encoder_id: u32) {
        self.state.connector_id = connector_id;
        self.state.encoder_id = encoder_id;
    }
}

// ---------------------------------------------------------------------------
// DrmCrtcRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CRTCS`] display pipelines.
pub struct DrmCrtcRegistry {
    /// Registered CRTCs.
    crtcs: [Option<DrmCrtc>; MAX_CRTCS],
    /// Number of registered CRTCs.
    count: usize,
}

impl DrmCrtcRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            crtcs: [const { None }; MAX_CRTCS],
            count: 0,
        }
    }

    /// Registers a CRTC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a CRTC with the same ID exists.
    pub fn register(&mut self, crtc: DrmCrtc) -> Result<()> {
        for slot in self.crtcs.iter().flatten() {
            if slot.id == crtc.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.crtcs.iter_mut() {
            if slot.is_none() {
                *slot = Some(crtc);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a CRTC by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&DrmCrtc> {
        for slot in self.crtcs.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a CRTC by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut DrmCrtc> {
        for slot in self.crtcs.iter_mut() {
            if let Some(c) = slot {
                if c.id == id {
                    return Ok(c);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered CRTCs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no CRTCs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DrmCrtcRegistry {
    fn default() -> Self {
        Self::new()
    }
}
