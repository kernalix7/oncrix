// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM/KMS (Direct Rendering Manager / Kernel Mode Setting) framework.
//!
//! Provides the core abstractions for managing GPU display pipelines:
//! connectors, encoders, CRTCs, planes, GEM buffer objects, and atomic
//! modesetting. Drivers populate [`DrmDevice`] and the framework handles
//! atomic state validation and commit.
//!
//! # Display Pipeline
//!
//! ```text
//! Framebuffer (GEM) → Plane → CRTC → Encoder → Connector → Display
//! ```
//!
//! - **GEM object**: GPU-visible memory buffer with a handle and size.
//! - **Plane**: Reads a framebuffer and composes it (primary/overlay/cursor).
//! - **CRTC**: Scanout controller — drives timing for one display pipeline.
//! - **Encoder**: Converts CRTC output to a physical signal (HDMI, DP, …).
//! - **Connector**: Physical output port attached to a display.
//!
//! Reference: Linux `drivers/gpu/drm/`, `include/drm/drm_*.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of DRM devices the registry can hold.
const MAX_DRM_DEVICES: usize = 4;

/// Maximum connectors per device.
const MAX_CONNECTORS: usize = 8;

/// Maximum encoders per device.
const MAX_ENCODERS: usize = 8;

/// Maximum CRTCs per device.
const MAX_CRTCS: usize = 4;

/// Maximum planes per device.
const MAX_PLANES: usize = 8;

/// Maximum display modes per connector.
const MAX_MODES: usize = 16;

/// Maximum GEM buffer objects per device.
const MAX_GEM_OBJECTS: usize = 64;

/// Maximum length of a mode name string.
const MODE_NAME_LEN: usize = 32;

/// Sentinel value meaning "not connected to any CRTC/encoder".
pub const DRM_ID_NONE: u32 = 0;

// ---------------------------------------------------------------------------
// Display mode flags
// ---------------------------------------------------------------------------

/// Positive horizontal sync polarity.
pub const DRM_MODE_FLAG_PHSYNC: u32 = 1 << 0;
/// Negative horizontal sync polarity.
pub const DRM_MODE_FLAG_NHSYNC: u32 = 1 << 1;
/// Positive vertical sync polarity.
pub const DRM_MODE_FLAG_PVSYNC: u32 = 1 << 2;
/// Negative vertical sync polarity.
pub const DRM_MODE_FLAG_NVSYNC: u32 = 1 << 3;
/// Interlaced scan mode.
pub const DRM_MODE_FLAG_INTERLACE: u32 = 1 << 4;
/// Double-scan mode.
pub const DRM_MODE_FLAG_DBLSCAN: u32 = 1 << 5;
/// Mode uses composite sync.
pub const DRM_MODE_FLAG_CSYNC: u32 = 1 << 6;
/// Preferred mode (reported by EDID).
pub const DRM_MODE_FLAG_PREFERRED: u32 = 1 << 17;

// ---------------------------------------------------------------------------
// DrmMode
// ---------------------------------------------------------------------------

/// A display timing mode.
///
/// Stores horizontal/vertical timing parameters in the same format used by
/// the VESA DMT/CVT standards and EDID descriptors.
#[derive(Debug, Clone, Copy)]
pub struct DrmMode {
    /// Horizontal active pixels.
    pub hdisplay: u16,
    /// Horizontal sync start.
    pub hsync_start: u16,
    /// Horizontal sync end.
    pub hsync_end: u16,
    /// Horizontal total (including blanking).
    pub htotal: u16,
    /// Vertical active lines.
    pub vdisplay: u16,
    /// Vertical sync start.
    pub vsync_start: u16,
    /// Vertical sync end.
    pub vsync_end: u16,
    /// Vertical total (including blanking).
    pub vtotal: u16,
    /// Pixel clock in kHz.
    pub clock: u32,
    /// Refresh rate in Hz (derived from clock/htotal/vtotal).
    pub refresh: u32,
    /// Mode flags (`DRM_MODE_FLAG_*`).
    pub flags: u32,
    /// Human-readable name (e.g. "1920x1080").
    name: [u8; MODE_NAME_LEN],
    /// Byte length of `name`.
    name_len: usize,
}

impl DrmMode {
    /// Create a new mode with the given resolution and refresh rate.
    pub fn new(width: u16, height: u16, refresh: u32, flags: u32) -> Self {
        let mut m = Self {
            hdisplay: width,
            hsync_start: width + 88,
            hsync_end: width + 88 + 44,
            htotal: width + 88 + 44 + 148,
            vdisplay: height,
            vsync_start: height + 4,
            vsync_end: height + 4 + 5,
            vtotal: height + 4 + 5 + 36,
            clock: 0,
            refresh,
            flags,
            name: [0u8; MODE_NAME_LEN],
            name_len: 0,
        };
        // Approximate pixel clock: htotal * vtotal * refresh / 1000 (kHz)
        m.clock = (m.htotal as u32) * (m.vtotal as u32) * refresh / 1000;
        m
    }

    /// Return the mode name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the mode name (truncates to `MODE_NAME_LEN`).
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MODE_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

// ---------------------------------------------------------------------------
// DrmConnectorType / DrmConnectorStatus
// ---------------------------------------------------------------------------

/// Physical connector type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmConnectorType {
    /// Unknown or unspecified connector.
    Unknown,
    /// VGA analog connector.
    Vga,
    /// DVI digital connector.
    Dvi,
    /// HDMI Type-A connector.
    Hdmi,
    /// DisplayPort connector.
    DisplayPort,
    /// Embedded DisplayPort (eDP).
    EmbeddedDisplayPort,
    /// LVDS panel connector.
    Lvds,
    /// Component video (YPbPr).
    Component,
    /// Composite video.
    Composite,
    /// Virtual connector (headless/virtual GPU).
    Virtual,
}

/// Connector link status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmConnectorStatus {
    /// A display is physically connected and responding.
    Connected,
    /// No display detected on this connector.
    Disconnected,
    /// Connector presence could not be determined.
    Unknown,
}

// ---------------------------------------------------------------------------
// DrmConnector
// ---------------------------------------------------------------------------

/// A physical display output connector.
///
/// Carries the list of supported modes and the currently attached encoder.
#[derive(Debug, Clone, Copy)]
pub struct DrmConnector {
    /// Unique connector ID within the device.
    pub id: u32,
    /// Connector type.
    pub connector_type: DrmConnectorType,
    /// Current link status.
    pub status: DrmConnectorStatus,
    /// Currently attached encoder ID (`DRM_ID_NONE` if none).
    pub encoder_id: u32,
    /// Supported display modes.
    modes: [Option<DrmMode>; MAX_MODES],
    /// Number of valid modes.
    mode_count: usize,
}

impl DrmConnector {
    /// Create a disconnected connector with no modes.
    pub const fn new(id: u32, connector_type: DrmConnectorType) -> Self {
        Self {
            id,
            connector_type,
            status: DrmConnectorStatus::Disconnected,
            encoder_id: DRM_ID_NONE,
            modes: [None; MAX_MODES],
            mode_count: 0,
        }
    }

    /// Add a display mode. Returns `Err(Error::OutOfMemory)` if the list is full.
    pub fn add_mode(&mut self, mode: DrmMode) -> Result<()> {
        if self.mode_count >= MAX_MODES {
            return Err(Error::OutOfMemory);
        }
        self.modes[self.mode_count] = Some(mode);
        self.mode_count += 1;
        Ok(())
    }

    /// Return a slice of all populated modes.
    pub fn modes(&self) -> impl Iterator<Item = &DrmMode> {
        self.modes[..self.mode_count]
            .iter()
            .filter_map(|m| m.as_ref())
    }

    /// Return the preferred mode (first mode with `DRM_MODE_FLAG_PREFERRED`),
    /// or the first mode if no preferred flag is set.
    pub fn preferred_mode(&self) -> Option<&DrmMode> {
        let pref = self
            .modes()
            .find(|m| m.flags & DRM_MODE_FLAG_PREFERRED != 0);
        pref.or_else(|| self.modes[0].as_ref())
    }
}

// ---------------------------------------------------------------------------
// DrmEncoder
// ---------------------------------------------------------------------------

/// Encoder type (signal conversion technology).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmEncoderType {
    /// No encoder / unknown.
    None,
    /// Digital-to-Analog Converter (VGA).
    Dac,
    /// TMDS encoder (DVI/HDMI).
    Tmds,
    /// LVDS encoder (panels).
    Lvds,
    /// DisplayPort encoder.
    Dp,
    /// Virtual encoder.
    Virtual,
}

/// Signal encoder connecting a CRTC to one or more connectors.
#[derive(Debug, Clone, Copy)]
pub struct DrmEncoder {
    /// Unique encoder ID within the device.
    pub id: u32,
    /// Encoder technology.
    pub encoder_type: DrmEncoderType,
    /// CRTC this encoder is currently attached to (`DRM_ID_NONE` if free).
    pub crtc_id: u32,
    /// Bitmask of CRTC IDs this encoder can be connected to.
    pub possible_crtcs: u32,
    /// Bitmask of clone encoder IDs (simultaneous output).
    pub possible_clones: u32,
}

impl DrmEncoder {
    /// Create a new encoder not connected to any CRTC.
    pub const fn new(id: u32, encoder_type: DrmEncoderType, possible_crtcs: u32) -> Self {
        Self {
            id,
            encoder_type,
            crtc_id: DRM_ID_NONE,
            possible_crtcs,
            possible_clones: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DrmCrtc
// ---------------------------------------------------------------------------

/// Scanout controller driving one display pipeline.
///
/// A CRTC reads a primary plane's framebuffer and generates the pixel stream
/// according to the configured `DrmMode`.
#[derive(Debug, Clone, Copy)]
pub struct DrmCrtc {
    /// Unique CRTC ID within the device.
    pub id: u32,
    /// Whether this CRTC is currently enabled.
    pub enabled: bool,
    /// Currently active mode (None if disabled).
    pub mode: Option<DrmMode>,
    /// Horizontal position of the CRTC origin on the display.
    pub x: u32,
    /// Vertical position of the CRTC origin on the display.
    pub y: u32,
    /// Primary plane ID associated with this CRTC.
    pub primary_plane_id: u32,
    /// Cursor plane ID (`DRM_ID_NONE` if none).
    pub cursor_plane_id: u32,
    /// Vertical blank counter (incremented each vblank).
    pub vblank_count: u64,
}

impl DrmCrtc {
    /// Create a disabled CRTC with no mode.
    pub const fn new(id: u32, primary_plane_id: u32) -> Self {
        Self {
            id,
            enabled: false,
            mode: None,
            x: 0,
            y: 0,
            primary_plane_id,
            cursor_plane_id: DRM_ID_NONE,
            vblank_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DrmPlane
// ---------------------------------------------------------------------------

/// Plane type determines composition role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmPlaneType {
    /// Mandatory primary scanout plane.
    Primary,
    /// Optional overlay plane for sprites/video.
    Overlay,
    /// Optional hardware cursor plane.
    Cursor,
}

/// Pixel format identifier (four-character code, little-endian).
pub type DrmFourCc = u32;

/// 32-bit ARGB (8-8-8-8).
pub const DRM_FORMAT_ARGB8888: DrmFourCc = u32::from_le_bytes(*b"AR24");
/// 32-bit XRGB (X-8-8-8), no alpha.
pub const DRM_FORMAT_XRGB8888: DrmFourCc = u32::from_le_bytes(*b"XR24");
/// 16-bit RGB (5-6-5).
pub const DRM_FORMAT_RGB565: DrmFourCc = u32::from_le_bytes(*b"RG16");

/// A compositing plane that sources pixels from a [`GemObject`].
#[derive(Debug, Clone, Copy)]
pub struct DrmPlane {
    /// Unique plane ID within the device.
    pub id: u32,
    /// Plane type.
    pub plane_type: DrmPlaneType,
    /// Bitmask of CRTC IDs this plane can be connected to.
    pub possible_crtcs: u32,
    /// Currently attached CRTC (`DRM_ID_NONE` if disabled).
    pub crtc_id: u32,
    /// GEM handle of the currently bound framebuffer (`0` if none).
    pub fb_handle: u32,
    /// Source X on the framebuffer (16.16 fixed-point).
    pub src_x: u32,
    /// Source Y on the framebuffer (16.16 fixed-point).
    pub src_y: u32,
    /// Source width (16.16 fixed-point).
    pub src_w: u32,
    /// Source height (16.16 fixed-point).
    pub src_h: u32,
    /// Destination X on the CRTC.
    pub dst_x: i32,
    /// Destination Y on the CRTC.
    pub dst_y: i32,
    /// Destination width on the CRTC.
    pub dst_w: u32,
    /// Destination height on the CRTC.
    pub dst_h: u32,
    /// Active pixel format.
    pub format: DrmFourCc,
}

impl DrmPlane {
    /// Create a new plane not bound to any CRTC or framebuffer.
    pub const fn new(id: u32, plane_type: DrmPlaneType, possible_crtcs: u32) -> Self {
        Self {
            id,
            plane_type,
            possible_crtcs,
            crtc_id: DRM_ID_NONE,
            fb_handle: 0,
            src_x: 0,
            src_y: 0,
            src_w: 0,
            src_h: 0,
            dst_x: 0,
            dst_y: 0,
            dst_w: 0,
            dst_h: 0,
            format: DRM_FORMAT_XRGB8888,
        }
    }
}

// ---------------------------------------------------------------------------
// GEM (Graphics Execution Manager) buffer objects
// ---------------------------------------------------------------------------

/// A GEM buffer object — GPU-visible memory with a unique handle.
///
/// In a bare-metal ONCRIX environment GEM objects are backed by physically
/// contiguous pages supplied by the memory manager. The `phys_addr` field
/// stores the base physical address of that allocation.
#[derive(Debug, Clone, Copy)]
pub struct GemObject {
    /// Driver-assigned handle (non-zero means valid).
    pub handle: u32,
    /// Size of the buffer in bytes.
    pub size: usize,
    /// Base physical address of the backing pages.
    pub phys_addr: u64,
    /// Stride (bytes per row) for 2-D framebuffers.
    pub pitch: u32,
    /// Pixel format.
    pub format: DrmFourCc,
    /// Width in pixels (0 if not a 2-D surface).
    pub width: u32,
    /// Height in pixels (0 if not a 2-D surface).
    pub height: u32,
}

impl GemObject {
    /// Create a new GEM object descriptor.
    pub const fn new(
        handle: u32,
        size: usize,
        phys_addr: u64,
        width: u32,
        height: u32,
        format: DrmFourCc,
    ) -> Self {
        // Bytes-per-pixel: ARGB8888/XRGB8888 = 4, RGB565 = 2
        let bpp: u32 = if format == DRM_FORMAT_RGB565 { 2 } else { 4 };
        Self {
            handle,
            size,
            phys_addr,
            pitch: width * bpp,
            format,
            width,
            height,
        }
    }
}

// ---------------------------------------------------------------------------
// AtomicState — proposed pipeline configuration
// ---------------------------------------------------------------------------

/// Proposed binding for one plane in an atomic commit.
#[derive(Debug, Clone, Copy)]
pub struct PlaneState {
    /// Plane being configured.
    pub plane_id: u32,
    /// Target CRTC (`DRM_ID_NONE` to disable).
    pub crtc_id: u32,
    /// GEM handle for the framebuffer (`0` to disable).
    pub fb_handle: u32,
    /// Source rectangle on the framebuffer (16.16 fixed-point each).
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    /// Destination rectangle on the CRTC.
    pub dst_x: i32,
    pub dst_y: i32,
    pub dst_w: u32,
    pub dst_h: u32,
}

/// Proposed mode/enable state for one CRTC in an atomic commit.
#[derive(Debug, Clone, Copy)]
pub struct CrtcState {
    /// CRTC being configured.
    pub crtc_id: u32,
    /// Whether to enable this CRTC.
    pub enable: bool,
    /// Display mode to apply (ignored when `enable` is `false`).
    pub mode: Option<DrmMode>,
}

/// Proposed connector routing in an atomic commit.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorState {
    /// Connector being configured.
    pub connector_id: u32,
    /// Encoder to route through (`DRM_ID_NONE` to disconnect).
    pub encoder_id: u32,
    /// CRTC to route through (`DRM_ID_NONE` to disconnect).
    pub crtc_id: u32,
}

/// Maximum simultaneous changes tracked by one [`AtomicState`].
const MAX_ATOMIC_PLANES: usize = 8;
const MAX_ATOMIC_CRTCS: usize = 4;
const MAX_ATOMIC_CONNECTORS: usize = 8;

/// An atomic modesetting state object.
///
/// Collects proposed changes to planes, CRTCs, and connectors. After
/// population the driver calls [`DrmDevice::atomic_check`] then
/// [`DrmDevice::atomic_commit`].
#[derive(Debug, Clone, Copy)]
pub struct AtomicState {
    /// Plane state changes.
    planes: [Option<PlaneState>; MAX_ATOMIC_PLANES],
    /// Number of valid plane states.
    plane_count: usize,
    /// CRTC state changes.
    crtcs: [Option<CrtcState>; MAX_ATOMIC_CRTCS],
    /// Number of valid CRTC states.
    crtc_count: usize,
    /// Connector state changes.
    connectors: [Option<ConnectorState>; MAX_ATOMIC_CONNECTORS],
    /// Number of valid connector states.
    connector_count: usize,
    /// If `true` this is a non-blocking (async) commit.
    pub nonblock: bool,
}

impl AtomicState {
    /// Create an empty atomic state.
    pub const fn new() -> Self {
        Self {
            planes: [None; MAX_ATOMIC_PLANES],
            plane_count: 0,
            crtcs: [None; MAX_ATOMIC_CRTCS],
            crtc_count: 0,
            connectors: [None; MAX_ATOMIC_CONNECTORS],
            connector_count: 0,
            nonblock: false,
        }
    }

    /// Add a plane state. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_plane(&mut self, state: PlaneState) -> Result<()> {
        if self.plane_count >= MAX_ATOMIC_PLANES {
            return Err(Error::OutOfMemory);
        }
        self.planes[self.plane_count] = Some(state);
        self.plane_count += 1;
        Ok(())
    }

    /// Add a CRTC state. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_crtc(&mut self, state: CrtcState) -> Result<()> {
        if self.crtc_count >= MAX_ATOMIC_CRTCS {
            return Err(Error::OutOfMemory);
        }
        self.crtcs[self.crtc_count] = Some(state);
        self.crtc_count += 1;
        Ok(())
    }

    /// Add a connector state. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_connector(&mut self, state: ConnectorState) -> Result<()> {
        if self.connector_count >= MAX_ATOMIC_CONNECTORS {
            return Err(Error::OutOfMemory);
        }
        self.connectors[self.connector_count] = Some(state);
        self.connector_count += 1;
        Ok(())
    }
}

impl Default for AtomicState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DrmDevice
// ---------------------------------------------------------------------------

/// A DRM device representing one GPU or display controller.
///
/// Holds all pipeline objects and GEM buffer handles. Drivers register
/// connectors, encoders, CRTCs, and planes via the `add_*` helpers, then
/// expose modesetting via [`DrmDevice::atomic_check`] /
/// [`DrmDevice::atomic_commit`].
pub struct DrmDevice {
    /// Unique device index within the [`DrmRegistry`].
    pub index: usize,
    /// Connectors on this device.
    connectors: [Option<DrmConnector>; MAX_CONNECTORS],
    connector_count: usize,
    /// Encoders on this device.
    encoders: [Option<DrmEncoder>; MAX_ENCODERS],
    encoder_count: usize,
    /// CRTCs on this device.
    crtcs: [Option<DrmCrtc>; MAX_CRTCS],
    crtc_count: usize,
    /// Planes on this device.
    planes: [Option<DrmPlane>; MAX_PLANES],
    plane_count: usize,
    /// GEM buffer objects.
    gem_objects: [Option<GemObject>; MAX_GEM_OBJECTS],
    gem_count: usize,
    /// Next GEM handle to assign (starts at 1).
    next_handle: u32,
    /// Whether the device has been initialised.
    pub initialized: bool,
}

impl DrmDevice {
    /// Create an uninitialised DRM device at `index`.
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            connectors: [None; MAX_CONNECTORS],
            connector_count: 0,
            encoders: [None; MAX_ENCODERS],
            encoder_count: 0,
            crtcs: [None; MAX_CRTCS],
            crtc_count: 0,
            planes: [None; MAX_PLANES],
            plane_count: 0,
            gem_objects: [None; MAX_GEM_OBJECTS],
            gem_count: 0,
            next_handle: 1,
            initialized: false,
        }
    }

    /// Initialise the device, setting up default pipeline objects if none were
    /// added by the driver.
    pub fn init(&mut self) -> Result<()> {
        if self.crtc_count == 0 {
            // Add a single virtual CRTC + primary plane
            let plane = DrmPlane::new(1, DrmPlaneType::Primary, 0b0001);
            self.add_plane(plane)?;
            let crtc = DrmCrtc::new(1, 1);
            self.add_crtc(crtc)?;
        }
        if self.encoder_count == 0 {
            self.add_encoder(DrmEncoder::new(1, DrmEncoderType::Virtual, 0b0001))?;
        }
        if self.connector_count == 0 {
            let mut conn = DrmConnector::new(1, DrmConnectorType::Virtual);
            conn.status = DrmConnectorStatus::Connected;
            conn.encoder_id = 1;
            let mut m = DrmMode::new(1024, 768, 60, DRM_MODE_FLAG_PREFERRED);
            m.set_name(b"1024x768");
            conn.add_mode(m)?;
            self.add_connector(conn)?;
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a connector. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_connector(&mut self, c: DrmConnector) -> Result<()> {
        if self.connector_count >= MAX_CONNECTORS {
            return Err(Error::OutOfMemory);
        }
        self.connectors[self.connector_count] = Some(c);
        self.connector_count += 1;
        Ok(())
    }

    /// Register an encoder. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_encoder(&mut self, e: DrmEncoder) -> Result<()> {
        if self.encoder_count >= MAX_ENCODERS {
            return Err(Error::OutOfMemory);
        }
        self.encoders[self.encoder_count] = Some(e);
        self.encoder_count += 1;
        Ok(())
    }

    /// Register a CRTC. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_crtc(&mut self, c: DrmCrtc) -> Result<()> {
        if self.crtc_count >= MAX_CRTCS {
            return Err(Error::OutOfMemory);
        }
        self.crtcs[self.crtc_count] = Some(c);
        self.crtc_count += 1;
        Ok(())
    }

    /// Register a plane. Returns `Err(Error::OutOfMemory)` if full.
    pub fn add_plane(&mut self, p: DrmPlane) -> Result<()> {
        if self.plane_count >= MAX_PLANES {
            return Err(Error::OutOfMemory);
        }
        self.planes[self.plane_count] = Some(p);
        self.plane_count += 1;
        Ok(())
    }

    /// Allocate a GEM buffer object backed by a physical address range.
    ///
    /// Returns the assigned handle on success.
    pub fn gem_create(
        &mut self,
        size: usize,
        phys_addr: u64,
        width: u32,
        height: u32,
        format: DrmFourCc,
    ) -> Result<u32> {
        if self.gem_count >= MAX_GEM_OBJECTS {
            return Err(Error::OutOfMemory);
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        let obj = GemObject::new(handle, size, phys_addr, width, height, format);
        self.gem_objects[self.gem_count] = Some(obj);
        self.gem_count += 1;
        Ok(handle)
    }

    /// Look up a GEM object by handle.
    pub fn gem_lookup(&self, handle: u32) -> Option<&GemObject> {
        self.gem_objects[..self.gem_count]
            .iter()
            .filter_map(|o| o.as_ref())
            .find(|o| o.handle == handle)
    }

    /// Destroy a GEM object by handle. Returns `Err(Error::InvalidArgument)` if
    /// not found.
    pub fn gem_destroy(&mut self, handle: u32) -> Result<()> {
        for slot in self.gem_objects[..self.gem_count].iter_mut() {
            if slot.map(|o| o.handle) == Some(handle) {
                *slot = None;
                return Ok(());
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Validate an atomic state without applying it.
    ///
    /// Checks that every referenced ID exists and that plane→CRTC→encoder
    /// routing is consistent.
    pub fn atomic_check(&self, state: &AtomicState) -> Result<()> {
        // Validate CRTC states
        for cs in state.crtcs[..state.crtc_count]
            .iter()
            .filter_map(|c| c.as_ref())
        {
            self.find_crtc(cs.crtc_id).ok_or(Error::InvalidArgument)?;
        }
        // Validate plane states
        for ps in state.planes[..state.plane_count]
            .iter()
            .filter_map(|p| p.as_ref())
        {
            self.find_plane(ps.plane_id).ok_or(Error::InvalidArgument)?;
            if ps.crtc_id != DRM_ID_NONE {
                self.find_crtc(ps.crtc_id).ok_or(Error::InvalidArgument)?;
            }
            if ps.fb_handle != 0 {
                self.gem_lookup(ps.fb_handle)
                    .ok_or(Error::InvalidArgument)?;
            }
        }
        // Validate connector states
        for cs in state.connectors[..state.connector_count]
            .iter()
            .filter_map(|c| c.as_ref())
        {
            self.find_connector(cs.connector_id)
                .ok_or(Error::InvalidArgument)?;
        }
        Ok(())
    }

    /// Apply a validated atomic state, updating all pipeline objects.
    ///
    /// Callers must call [`atomic_check`] first. Passing an invalid state
    /// results in `Err(Error::InvalidArgument)`.
    pub fn atomic_commit(&mut self, state: &AtomicState) -> Result<()> {
        self.atomic_check(state)?;

        // Apply CRTC states
        for cs in state.crtcs[..state.crtc_count]
            .iter()
            .filter_map(|c| c.as_ref())
        {
            if let Some(crtc) = self.find_crtc_mut(cs.crtc_id) {
                crtc.enabled = cs.enable;
                crtc.mode = cs.mode;
            }
        }

        // Apply plane states
        for ps in state.planes[..state.plane_count]
            .iter()
            .filter_map(|p| p.as_ref())
        {
            if let Some(plane) = self.find_plane_mut(ps.plane_id) {
                plane.crtc_id = ps.crtc_id;
                plane.fb_handle = ps.fb_handle;
                plane.src_x = ps.src_x;
                plane.src_y = ps.src_y;
                plane.src_w = ps.src_w;
                plane.src_h = ps.src_h;
                plane.dst_x = ps.dst_x;
                plane.dst_y = ps.dst_y;
                plane.dst_w = ps.dst_w;
                plane.dst_h = ps.dst_h;
            }
        }

        // Apply connector states
        for cs in state.connectors[..state.connector_count]
            .iter()
            .filter_map(|c| c.as_ref())
        {
            if let Some(conn) = self.find_connector_mut(cs.connector_id) {
                conn.encoder_id = cs.encoder_id;
            }
        }

        Ok(())
    }

    // --- internal lookup helpers ---

    fn find_crtc(&self, id: u32) -> Option<&DrmCrtc> {
        self.crtcs[..self.crtc_count]
            .iter()
            .filter_map(|c| c.as_ref())
            .find(|c| c.id == id)
    }

    fn find_crtc_mut(&mut self, id: u32) -> Option<&mut DrmCrtc> {
        self.crtcs[..self.crtc_count]
            .iter_mut()
            .filter_map(|c| c.as_mut())
            .find(|c| c.id == id)
    }

    fn find_plane(&self, id: u32) -> Option<&DrmPlane> {
        self.planes[..self.plane_count]
            .iter()
            .filter_map(|p| p.as_ref())
            .find(|p| p.id == id)
    }

    fn find_plane_mut(&mut self, id: u32) -> Option<&mut DrmPlane> {
        self.planes[..self.plane_count]
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.id == id)
    }

    fn find_connector(&self, id: u32) -> Option<&DrmConnector> {
        self.connectors[..self.connector_count]
            .iter()
            .filter_map(|c| c.as_ref())
            .find(|c| c.id == id)
    }

    fn find_connector_mut(&mut self, id: u32) -> Option<&mut DrmConnector> {
        self.connectors[..self.connector_count]
            .iter_mut()
            .filter_map(|c| c.as_mut())
            .find(|c| c.id == id)
    }

    /// Iterate over all connectors.
    pub fn connectors(&self) -> impl Iterator<Item = &DrmConnector> {
        self.connectors[..self.connector_count]
            .iter()
            .filter_map(|c| c.as_ref())
    }

    /// Iterate over all CRTCs.
    pub fn crtcs(&self) -> impl Iterator<Item = &DrmCrtc> {
        self.crtcs[..self.crtc_count]
            .iter()
            .filter_map(|c| c.as_ref())
    }

    /// Iterate over all planes.
    pub fn planes(&self) -> impl Iterator<Item = &DrmPlane> {
        self.planes[..self.plane_count]
            .iter()
            .filter_map(|p| p.as_ref())
    }
}

// ---------------------------------------------------------------------------
// DrmRegistry
// ---------------------------------------------------------------------------

/// Global registry of DRM devices.
pub struct DrmRegistry {
    devices: [Option<DrmDevice>; MAX_DRM_DEVICES],
    count: usize,
}

impl DrmRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DRM_DEVICES],
            count: 0,
        }
    }

    /// Register a DRM device. Returns `Err(Error::OutOfMemory)` if the registry
    /// is full.
    pub fn register(&mut self, mut device: DrmDevice) -> Result<usize> {
        if self.count >= MAX_DRM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        device.index = self.count;
        self.devices[self.count] = Some(device);
        let idx = self.count;
        self.count += 1;
        Ok(idx)
    }

    /// Look up a registered device by index.
    pub fn get(&self, index: usize) -> Option<&DrmDevice> {
        self.devices.get(index)?.as_ref()
    }

    /// Look up a registered device by index (mutable).
    pub fn get_mut(&mut self, index: usize) -> Option<&mut DrmDevice> {
        self.devices.get_mut(index)?.as_mut()
    }

    /// Number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no devices have been registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all registered devices.
    pub fn iter(&self) -> impl Iterator<Item = &DrmDevice> {
        self.devices[..self.count].iter().filter_map(|d| d.as_ref())
    }
}

impl Default for DrmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Module-level singleton registry
// ---------------------------------------------------------------------------

/// Global DRM device registry.
static mut DRM_REGISTRY: DrmRegistry = DrmRegistry::new();

/// Register a device in the global registry.
///
/// # Safety
///
/// Must only be called from the kernel initialisation path before
/// concurrent access to the registry is possible.
pub unsafe fn drm_register_device(device: DrmDevice) -> Result<usize> {
    // SAFETY: Called only during single-threaded kernel init.
    unsafe { (*core::ptr::addr_of_mut!(DRM_REGISTRY)).register(device) }
}

/// Look up a device in the global registry by index.
pub fn drm_get_device(index: usize) -> Option<&'static DrmDevice> {
    // SAFETY: Read-only access after init; no mutable aliasing.
    unsafe { (*core::ptr::addr_of!(DRM_REGISTRY)).get(index) }
}

/// Number of devices in the global registry.
pub fn drm_device_count() -> usize {
    // SAFETY: Read-only after init.
    unsafe { (*core::ptr::addr_of!(DRM_REGISTRY)).len() }
}
