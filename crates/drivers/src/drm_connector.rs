// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM display connector abstraction.
//!
//! Models display connectors (HDMI, DisplayPort, LVDS, VGA, etc.) including
//! connector type, status, EDID parsing, mode validation, and HPD handling.
//!
//! # Overview
//!
//! A connector represents a physical output port on a GPU. Each connector
//! has a connection status, a list of supported display modes (parsed from
//! EDID), and DPMS power state. Hot-plug detection (HPD) events trigger
//! re-reading of EDID and mode list.
//!
//! Reference: DRM kernel documentation, VESA EDID 1.4 specification.

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Connector Types
// ---------------------------------------------------------------------------

/// DRM display connector type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorType {
    /// VGA analog connector.
    Vga,
    /// DVI-I (combined analog + digital).
    DviI,
    /// DVI-D (digital only).
    DviD,
    /// DVI-A (analog only).
    DviA,
    /// Composite video.
    Composite,
    /// S-Video connector.
    SVideo,
    /// LVDS (internal laptop panel).
    Lvds,
    /// Component video (YPbPr).
    Component,
    /// DisplayPort.
    DisplayPort,
    /// HDMI type A.
    HdmiA,
    /// HDMI type B (dual-link).
    HdmiB,
    /// Embedded DisplayPort (eDP, internal panel).
    EDp,
    /// MIPI DSI (display serial interface).
    Dsi,
    /// Unknown / undetected type.
    Unknown,
}

impl ConnectorType {
    /// Returns the canonical name string for this connector type.
    pub fn name(self) -> &'static str {
        match self {
            ConnectorType::Vga => "VGA",
            ConnectorType::DviI => "DVI-I",
            ConnectorType::DviD => "DVI-D",
            ConnectorType::DviA => "DVI-A",
            ConnectorType::Composite => "Composite",
            ConnectorType::SVideo => "S-Video",
            ConnectorType::Lvds => "LVDS",
            ConnectorType::Component => "Component",
            ConnectorType::DisplayPort => "DisplayPort",
            ConnectorType::HdmiA => "HDMI-A",
            ConnectorType::HdmiB => "HDMI-B",
            ConnectorType::EDp => "eDP",
            ConnectorType::Dsi => "DSI",
            ConnectorType::Unknown => "Unknown",
        }
    }

    /// Returns whether this connector supports hot-plug detection.
    pub fn supports_hpd(self) -> bool {
        matches!(
            self,
            ConnectorType::DisplayPort
                | ConnectorType::HdmiA
                | ConnectorType::HdmiB
                | ConnectorType::EDp
        )
    }
}

// ---------------------------------------------------------------------------
// Connector Status
// ---------------------------------------------------------------------------

/// Physical connection status of a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorStatus {
    /// A display is connected and detected.
    Connected,
    /// No display is connected.
    Disconnected,
    /// Connection status could not be determined.
    Unknown,
}

// ---------------------------------------------------------------------------
// DPMS State
// ---------------------------------------------------------------------------

/// DPMS (Display Power Management Signaling) power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpmsState {
    /// Normal operation (display powered on).
    On,
    /// Horizontal sync off, vertical sync on.
    Standby,
    /// Horizontal sync on, vertical sync off.
    Suspend,
    /// Both syncs off (display powered off).
    Off,
}

// ---------------------------------------------------------------------------
// Scaling Mode
// ---------------------------------------------------------------------------

/// Panel scaling mode for sub-native resolutions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalingMode {
    /// No scaling — output pixel-for-pixel.
    None,
    /// Stretch to fill the entire panel.
    Fullscreen,
    /// Scale preserving aspect ratio with black borders.
    AspectRatio,
    /// Center image without scaling.
    Center,
}

// ---------------------------------------------------------------------------
// Content Type
// ---------------------------------------------------------------------------

/// Content type hint (HDMI InfoFrame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// No content type specified.
    NoData,
    /// Graphics / desktop content.
    Graphics,
    /// Photographic content.
    Photo,
    /// Cinema content.
    Cinema,
    /// Game content.
    Game,
}

// ---------------------------------------------------------------------------
// Display Mode
// ---------------------------------------------------------------------------

/// Mode flags bit definitions.
pub const MODE_FLAG_PHSYNC: u32 = 1 << 0;
/// Negative horizontal sync polarity.
pub const MODE_FLAG_NHSYNC: u32 = 1 << 1;
/// Positive vertical sync polarity.
pub const MODE_FLAG_PVSYNC: u32 = 1 << 2;
/// Negative vertical sync polarity.
pub const MODE_FLAG_NVSYNC: u32 = 1 << 3;
/// Interlaced mode.
pub const MODE_FLAG_INTERLACE: u32 = 1 << 4;
/// Double-scan mode.
pub const MODE_FLAG_DBLSCAN: u32 = 1 << 5;
/// Mode is from EDID preferred timing.
pub const MODE_FLAG_PREFERRED: u32 = 1 << 6;
/// Mode is user-specified.
pub const MODE_FLAG_USERDEF: u32 = 1 << 7;

/// A display timing mode.
///
/// All timing values are in pixels or lines (not time units).
/// Clock is in kHz.
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    /// Horizontal active pixels.
    pub hdisplay: u16,
    /// Vertical active lines.
    pub vdisplay: u16,
    /// Horizontal total pixels (active + blanking).
    pub htotal: u16,
    /// Vertical total lines (active + blanking).
    pub vtotal: u16,
    /// Pixel clock in kHz.
    pub clock_khz: u32,
    /// Horizontal sync start.
    pub hsync_start: u16,
    /// Horizontal sync end.
    pub hsync_end: u16,
    /// Vertical sync start.
    pub vsync_start: u16,
    /// Vertical sync end.
    pub vsync_end: u16,
    /// Mode flags (see MODE_FLAG_* constants).
    pub flags: u32,
}

impl DisplayMode {
    /// Returns the refresh rate in milliHz (integer arithmetic).
    pub fn refresh_rate_mhz(&self) -> u32 {
        if self.htotal == 0 || self.vtotal == 0 {
            return 0;
        }
        let total_pixels = self.htotal as u64 * self.vtotal as u64;
        if total_pixels == 0 {
            return 0;
        }
        (self.clock_khz as u64 * 1_000_000 / total_pixels) as u32
    }

    /// Returns the refresh rate in Hz (rounded).
    pub fn refresh_hz(&self) -> u32 {
        (self.refresh_rate_mhz() + 500) / 1000
    }

    /// Returns true if this is an interlaced mode.
    pub fn is_interlaced(&self) -> bool {
        self.flags & MODE_FLAG_INTERLACE != 0
    }

    /// Returns true if this is the preferred EDID mode.
    pub fn is_preferred(&self) -> bool {
        self.flags & MODE_FLAG_PREFERRED != 0
    }

    /// Returns true if the mode parameters are within valid bounds.
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
}

// ---------------------------------------------------------------------------
// EDID Parsing
// ---------------------------------------------------------------------------

/// EDID block size in bytes.
pub const EDID_BLOCK_SIZE: usize = 128;

/// EDID header magic bytes (first 8 bytes).
pub const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// EDID manufacturer ID offset.
pub const EDID_MANUFACTURER_OFFSET: usize = 8;

/// EDID product code offset.
pub const EDID_PRODUCT_OFFSET: usize = 10;

/// EDID serial number offset (4 bytes).
pub const EDID_SERIAL_OFFSET: usize = 12;

/// EDID manufacture week offset.
pub const EDID_WEEK_OFFSET: usize = 16;

/// EDID manufacture year offset.
pub const EDID_YEAR_OFFSET: usize = 17;

/// EDID version offset.
pub const EDID_VERSION_OFFSET: usize = 18;

/// EDID revision offset.
pub const EDID_REVISION_OFFSET: usize = 19;

/// EDID input parameters offset.
pub const EDID_INPUT_OFFSET: usize = 20;

/// EDID detailed timing descriptor start offset.
pub const EDID_DTD_START: usize = 54;

/// EDID detailed timing descriptor size in bytes.
pub const EDID_DTD_SIZE: usize = 18;

/// EDID number of extension blocks offset.
pub const EDID_EXTENSIONS_OFFSET: usize = 126;

/// Parsed EDID data from a 128-byte EDID block.
#[derive(Debug, Clone, Copy)]
pub struct EdidData {
    /// Manufacturer ID (3-character EISA code packed in 2 bytes).
    pub manufacturer_id: u16,
    /// Product code.
    pub product_code: u16,
    /// Serial number (0 if not present).
    pub serial_number: u32,
    /// Manufacture week (1-53, 0xFF = model year).
    pub manufacture_week: u8,
    /// Manufacture year (relative to 1990).
    pub manufacture_year: u8,
    /// EDID version number.
    pub version: u8,
    /// EDID revision number.
    pub revision: u8,
    /// Whether the input is digital (true) or analog (false).
    pub digital_input: bool,
    /// Number of EDID extension blocks.
    pub num_extensions: u8,
    /// Preferred timing from first detailed timing descriptor.
    pub preferred_mode: Option<DisplayMode>,
}

impl EdidData {
    /// Parses a 128-byte EDID block.
    ///
    /// Returns `Err(InvalidArgument)` if the header magic or checksum is invalid.
    pub fn parse(block: &[u8; EDID_BLOCK_SIZE]) -> Result<Self> {
        // Validate EDID header.
        if block[..8] != EDID_HEADER {
            return Err(Error::InvalidArgument);
        }

        // Validate checksum: sum of all 128 bytes must be 0 mod 256.
        let checksum: u8 = block.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if checksum != 0 {
            return Err(Error::InvalidArgument);
        }

        let manufacturer_id = ((block[EDID_MANUFACTURER_OFFSET] as u16) << 8)
            | block[EDID_MANUFACTURER_OFFSET + 1] as u16;
        let product_code =
            (block[EDID_PRODUCT_OFFSET] as u16) | ((block[EDID_PRODUCT_OFFSET + 1] as u16) << 8);
        let serial_number = u32::from_le_bytes([
            block[EDID_SERIAL_OFFSET],
            block[EDID_SERIAL_OFFSET + 1],
            block[EDID_SERIAL_OFFSET + 2],
            block[EDID_SERIAL_OFFSET + 3],
        ]);
        let digital_input = block[EDID_INPUT_OFFSET] & 0x80 != 0;
        let preferred_mode = parse_dtd(&block[EDID_DTD_START..EDID_DTD_START + EDID_DTD_SIZE]);

        Ok(Self {
            manufacturer_id,
            product_code,
            serial_number,
            manufacture_week: block[EDID_WEEK_OFFSET],
            manufacture_year: block[EDID_YEAR_OFFSET],
            version: block[EDID_VERSION_OFFSET],
            revision: block[EDID_REVISION_OFFSET],
            digital_input,
            num_extensions: block[EDID_EXTENSIONS_OFFSET],
            preferred_mode,
        })
    }

    /// Decodes the 3-character manufacturer ID from the packed 2-byte field.
    ///
    /// Returns three ASCII characters as a `[u8; 3]`.
    pub fn manufacturer_chars(&self) -> [u8; 3] {
        let id = self.manufacturer_id;
        let c1 = ((id >> 10) & 0x1F) as u8 + b'A' - 1;
        let c2 = ((id >> 5) & 0x1F) as u8 + b'A' - 1;
        let c3 = (id & 0x1F) as u8 + b'A' - 1;
        [c1, c2, c3]
    }
}

/// Parses an 18-byte EDID Detailed Timing Descriptor (DTD).
///
/// Returns `Some(DisplayMode)` if the DTD is a valid timing descriptor
/// (not a monitor descriptor block).
fn parse_dtd(dtd: &[u8]) -> Option<DisplayMode> {
    if dtd.len() < EDID_DTD_SIZE {
        return None;
    }
    // Monitor descriptor blocks have bytes 0-1 = 0x0000.
    let pixel_clock = (dtd[0] as u32) | ((dtd[1] as u32) << 8);
    if pixel_clock == 0 {
        return None;
    }

    let clock_khz = pixel_clock * 10; // DTD encodes in units of 10 kHz.
    let hdisplay = ((dtd[2] as u16) | (((dtd[4] as u16) & 0xF0) << 4)) as u16;
    let hblank = ((dtd[3] as u16) | (((dtd[4] as u16) & 0x0F) << 8)) as u16;
    let vdisplay = ((dtd[5] as u16) | (((dtd[7] as u16) & 0xF0) << 4)) as u16;
    let vblank = ((dtd[6] as u16) | (((dtd[7] as u16) & 0x0F) << 8)) as u16;

    let hsync_off = ((dtd[8] as u16) | (((dtd[11] as u16) & 0xC0) << 2)) as u16;
    let hsync_width = ((dtd[9] as u16) | (((dtd[11] as u16) & 0x30) << 4)) as u16;
    let vsync_off = (((dtd[10] >> 4) as u16) | (((dtd[11] as u16) & 0x0C) << 2)) as u16;
    let vsync_width = ((dtd[10] & 0x0F) as u16 | (((dtd[11] as u16) & 0x03) << 4)) as u16;

    let flags_byte = dtd[17];
    let mut flags = 0u32;
    if flags_byte & 0x04 != 0 {
        flags |= MODE_FLAG_PVSYNC;
    } else {
        flags |= MODE_FLAG_NVSYNC;
    }
    if flags_byte & 0x02 != 0 {
        flags |= MODE_FLAG_PHSYNC;
    } else {
        flags |= MODE_FLAG_NHSYNC;
    }
    if flags_byte & 0x80 != 0 {
        flags |= MODE_FLAG_INTERLACE;
    }
    flags |= MODE_FLAG_PREFERRED;

    let htotal = hdisplay + hblank;
    let vtotal = vdisplay + vblank;
    let hsync_start = hdisplay + hsync_off;
    let hsync_end = hsync_start + hsync_width;
    let vsync_start = vdisplay + vsync_off;
    let vsync_end = vsync_start + vsync_width;

    let mode = DisplayMode {
        hdisplay,
        vdisplay,
        htotal,
        vtotal,
        clock_khz,
        hsync_start,
        hsync_end,
        vsync_start,
        vsync_end,
        flags,
    };
    if mode.is_valid() { Some(mode) } else { None }
}

// ---------------------------------------------------------------------------
// Maximum modes per connector
// ---------------------------------------------------------------------------

/// Maximum display modes stored per connector.
pub const MAX_MODES_PER_CONNECTOR: usize = 32;

// ---------------------------------------------------------------------------
// Connector State
// ---------------------------------------------------------------------------

/// Complete state of a DRM connector.
pub struct ConnectorState {
    /// Current DPMS power state.
    pub dpms: DpmsState,
    /// Content type hint.
    pub content_type: ContentType,
    /// Panel scaling mode.
    pub scaling_mode: ScalingMode,
    /// Currently active mode (if any).
    pub active_mode: Option<DisplayMode>,
}

impl ConnectorState {
    /// Creates a default connector state (on, no scaling, no mode).
    pub const fn default() -> Self {
        Self {
            dpms: DpmsState::Off,
            content_type: ContentType::NoData,
            scaling_mode: ScalingMode::None,
            active_mode: None,
        }
    }
}

// ---------------------------------------------------------------------------
// DRM Connector
// ---------------------------------------------------------------------------

/// A DRM display connector.
///
/// Tracks connector type, status, EDID, supported modes, and connector state.
pub struct DrmConnector {
    /// Unique connector ID within the DRM subsystem.
    pub connector_id: u32,
    /// Physical connector type.
    pub connector_type: ConnectorType,
    /// Index of this connector type (for multi-connector GPUs).
    pub type_index: u32,
    /// Current connection status.
    pub status: ConnectorStatus,
    /// Parsed EDID data (if connected and EDID is readable).
    pub edid: Option<EdidData>,
    /// List of supported display modes.
    pub modes: Vec<DisplayMode>,
    /// Current connector state.
    pub state: ConnectorState,
    /// HPD (hot-plug detect) counter.
    pub hpd_count: u32,
}

impl DrmConnector {
    /// Creates a new DRM connector.
    pub fn new(connector_id: u32, connector_type: ConnectorType, type_index: u32) -> Self {
        Self {
            connector_id,
            connector_type,
            type_index,
            status: ConnectorStatus::Unknown,
            edid: None,
            modes: Vec::new(),
            state: ConnectorState::default(),
            hpd_count: 0,
        }
    }

    /// Processes a hot-plug detect event.
    ///
    /// Updates status and clears stale mode list and EDID.
    pub fn handle_hpd(&mut self, connected: bool) {
        self.hpd_count = self.hpd_count.saturating_add(1);
        if connected {
            self.status = ConnectorStatus::Connected;
        } else {
            self.status = ConnectorStatus::Disconnected;
            self.edid = None;
            self.modes.clear();
            self.state.active_mode = None;
        }
    }

    /// Loads and parses a 128-byte EDID block.
    ///
    /// On success, adds the preferred timing to the mode list.
    pub fn load_edid(&mut self, block: &[u8; EDID_BLOCK_SIZE]) -> Result<()> {
        let edid = EdidData::parse(block)?;
        if let Some(mode) = edid.preferred_mode {
            // Insert preferred mode at front, removing any duplicate.
            self.modes.retain(|m| {
                !(m.hdisplay == mode.hdisplay
                    && m.vdisplay == mode.vdisplay
                    && m.refresh_hz() == mode.refresh_hz())
            });
            self.modes.insert(0, mode);
        }
        self.edid = Some(edid);
        self.status = ConnectorStatus::Connected;
        Ok(())
    }

    /// Adds a display mode to the supported modes list.
    ///
    /// Modes beyond `MAX_MODES_PER_CONNECTOR` are silently dropped.
    pub fn add_mode(&mut self, mode: DisplayMode) -> Result<()> {
        if !mode.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if self.modes.len() >= MAX_MODES_PER_CONNECTOR {
            return Err(Error::OutOfMemory);
        }
        self.modes.push(mode);
        Ok(())
    }

    /// Validates and sets the active display mode.
    pub fn set_mode(&mut self, mode: DisplayMode) -> Result<()> {
        if !mode.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.state.active_mode = Some(mode);
        Ok(())
    }

    /// Sets the DPMS power state.
    pub fn set_dpms(&mut self, dpms: DpmsState) {
        self.state.dpms = dpms;
    }

    /// Sets the scaling mode.
    pub fn set_scaling_mode(&mut self, mode: ScalingMode) {
        self.state.scaling_mode = mode;
    }

    /// Sets the content type hint.
    pub fn set_content_type(&mut self, content_type: ContentType) {
        self.state.content_type = content_type;
    }

    /// Returns the preferred display mode from the mode list.
    pub fn preferred_mode(&self) -> Option<&DisplayMode> {
        self.modes.iter().find(|m| m.is_preferred())
    }

    /// Returns the connector name string (e.g., "HDMI-A-1").
    pub fn name_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let type_name = self.connector_type.name().as_bytes();
        let len = type_name.len().min(14);
        buf[..len].copy_from_slice(&type_name[..len]);
        // Append "-N" suffix (type index as single digit).
        if len < 15 {
            buf[len] = b'-';
            buf[len + 1] = b'0' + (self.type_index as u8 % 10);
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Maximum number of DRM connectors per device.
pub const MAX_CONNECTORS: usize = 16;

/// DRM connector registry for a single GPU.
pub struct ConnectorRegistry {
    connectors: Vec<DrmConnector>,
    next_id: u32,
}

impl ConnectorRegistry {
    /// Creates an empty connector registry.
    pub fn new() -> Self {
        Self {
            connectors: Vec::new(),
            next_id: 1,
        }
    }

    /// Registers a new connector of the given type.
    ///
    /// Returns the assigned connector ID.
    pub fn register(&mut self, connector_type: ConnectorType, type_index: u32) -> Result<u32> {
        if self.connectors.len() >= MAX_CONNECTORS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.connectors
            .push(DrmConnector::new(id, connector_type, type_index));
        Ok(id)
    }

    /// Returns a mutable reference to the connector with the given ID.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut DrmConnector> {
        self.connectors
            .iter_mut()
            .find(|c| c.connector_id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a reference to the connector with the given ID.
    pub fn get(&self, id: u32) -> Result<&DrmConnector> {
        self.connectors
            .iter()
            .find(|c| c.connector_id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered connectors.
    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    /// Returns true if no connectors are registered.
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }

    /// Returns the count of connectors in connected state.
    pub fn connected_count(&self) -> usize {
        self.connectors
            .iter()
            .filter(|c| c.status == ConnectorStatus::Connected)
            .count()
    }
}
