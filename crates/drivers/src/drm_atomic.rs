// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM atomic modesetting subsystem.
//!
//! Implements atomic display configuration for the DRM (Direct Rendering
//! Manager) stack. Unlike legacy KMS, atomic modesetting updates the
//! entire display pipeline in a single transactional commit: all plane,
//! CRTC, and connector changes are validated first (`atomic_check`) and
//! then applied atomically (`atomic_commit`). Failed commits roll back
//! without disturbing the active display.
//!
//! # Architecture
//!
//! ```text
//! Connector ──► CRTC ──► Plane (framebuffer)
//! ```
//!
//! - [`DrmPlaneType`] — Primary / Overlay / Cursor
//! - [`DrmPlaneState`] — per-plane pending configuration
//! - [`DrmCrtcState`] — per-CRTC pending mode/gamma
//! - [`DrmConnectorState`] — per-connector pending DPMS/CRTC binding
//! - [`AtomicState`] — combined pending state for one commit
//! - [`CommitFlags`] — flags controlling commit behaviour
//! - [`AtomicCommit`] — an in-flight commit with flags and state snapshot
//! - [`DrmAtomicSubsystem`] — the core coordinator
//!
//! Reference: Linux `drivers/gpu/drm/drm_atomic.c`,
//!            `Documentation/gpu/drm-kms.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of planes in the subsystem.
const MAX_PLANES: usize = 4;

/// Maximum number of CRTCs.
const MAX_CRTCS: usize = 4;

/// Maximum number of connectors.
const MAX_CONNECTORS: usize = 4;

/// Maximum gamma LUT size (number of entries).
const MAX_GAMMA_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// DrmPlaneType
// ---------------------------------------------------------------------------

/// Functional role of a DRM plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DrmPlaneType {
    /// Primary plane — carries the main framebuffer. Every CRTC has exactly one.
    #[default]
    Primary,
    /// Overlay plane — hardware video or graphics overlay.
    Overlay,
    /// Cursor plane — hardware cursor sprite.
    Cursor,
}

// ---------------------------------------------------------------------------
// DpmsMode
// ---------------------------------------------------------------------------

/// Display Power Management Signaling (DPMS) state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DpmsMode {
    /// Display fully on.
    #[default]
    On,
    /// Display in standby (short wake time).
    Standby,
    /// Display in suspend (longer wake time).
    Suspend,
    /// Display fully off.
    Off,
}

// ---------------------------------------------------------------------------
// DrmRect
// ---------------------------------------------------------------------------

/// A 2-D rectangle with pixel coordinates.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DrmRect {
    /// Left edge (inclusive), in pixels.
    pub x1: i32,
    /// Top edge (inclusive), in pixels.
    pub y1: i32,
    /// Right edge (exclusive), in pixels.
    pub x2: i32,
    /// Bottom edge (exclusive), in pixels.
    pub y2: i32,
}

impl DrmRect {
    /// Creates a rectangle from position and size.
    pub const fn from_size(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x1: x,
            y1: y,
            x2: x + width as i32,
            y2: y + height as i32,
        }
    }

    /// Returns the width in pixels.
    pub fn width(&self) -> u32 {
        self.x2.saturating_sub(self.x1) as u32
    }

    /// Returns the height in pixels.
    pub fn height(&self) -> u32 {
        self.y2.saturating_sub(self.y1) as u32
    }

    /// Returns `true` if this rectangle has no area.
    pub fn is_empty(&self) -> bool {
        self.x2 <= self.x1 || self.y2 <= self.y1
    }
}

// ---------------------------------------------------------------------------
// DrmDisplayMode
// ---------------------------------------------------------------------------

/// A display timing mode (modeline).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DrmDisplayMode {
    /// Horizontal active pixels.
    pub hdisplay: u16,
    /// Vertical active lines.
    pub vdisplay: u16,
    /// Refresh rate in Hz.
    pub refresh_rate: u8,
    /// Pixel clock in kHz.
    pub pixel_clock_khz: u32,
    /// Horizontal total (active + blanking).
    pub htotal: u16,
    /// Vertical total (active + blanking).
    pub vtotal: u16,
}

impl DrmDisplayMode {
    /// Creates a mode with the given active resolution and refresh rate.
    pub const fn new(hdisplay: u16, vdisplay: u16, refresh_rate: u8) -> Self {
        // Approximate pixel clock: W × H × refresh × 1.35 (blanking factor)
        let pixel_clock_khz =
            (hdisplay as u32) * (vdisplay as u32) * (refresh_rate as u32) * 135 / 100 / 1000;
        Self {
            hdisplay,
            vdisplay,
            refresh_rate,
            pixel_clock_khz,
            htotal: hdisplay + hdisplay / 5,
            vtotal: vdisplay + vdisplay / 10,
        }
    }

    /// Returns `true` if this mode has no resolution set.
    pub fn is_empty(&self) -> bool {
        self.hdisplay == 0 || self.vdisplay == 0
    }
}

// ---------------------------------------------------------------------------
// DrmPlaneState
// ---------------------------------------------------------------------------

/// Pending configuration for one DRM plane.
#[derive(Debug, Clone, Copy, Default)]
pub struct DrmPlaneState {
    /// CRTC this plane feeds into (0 = disabled).
    pub crtc_id: u32,
    /// Framebuffer object ID (0 = no buffer).
    pub fb_id: u32,
    /// Source rectangle in the framebuffer (fixed-point 16.16, pixels here simplified).
    pub src_rect: DrmRect,
    /// Destination rectangle on the CRTC scanout area.
    pub dst_rect: DrmRect,
    /// Rotation flags (0 = no rotation).
    pub rotation: u32,
    /// Plane alpha (0 = transparent, 255 = opaque).
    pub alpha: u8,
    /// Z-order position (lower = behind).
    pub zpos: u8,
    /// Whether this plane is visible.
    pub visible: bool,
    /// Plane type.
    pub plane_type: DrmPlaneType,
}

impl DrmPlaneState {
    /// Creates a disabled plane state.
    pub const fn new(plane_type: DrmPlaneType) -> Self {
        Self {
            crtc_id: 0,
            fb_id: 0,
            src_rect: DrmRect {
                x1: 0,
                y1: 0,
                x2: 0,
                y2: 0,
            },
            dst_rect: DrmRect {
                x1: 0,
                y1: 0,
                x2: 0,
                y2: 0,
            },
            rotation: 0,
            alpha: 255,
            zpos: 0,
            visible: false,
            plane_type,
        }
    }

    /// Returns `true` if this plane is actively displaying content.
    pub fn is_active(&self) -> bool {
        self.visible && self.crtc_id != 0 && self.fb_id != 0
    }
}

// ---------------------------------------------------------------------------
// DrmCrtcState
// ---------------------------------------------------------------------------

/// Pending configuration for one CRTC.
#[derive(Debug, Clone, Copy, Default)]
pub struct DrmCrtcState {
    /// Whether the CRTC is active (enabled).
    pub active: bool,
    /// Display mode to program.
    pub mode: DrmDisplayMode,
    /// Whether the mode has changed and needs reprogramming.
    pub mode_changed: bool,
    /// Gamma LUT size (0 = gamma not supported).
    pub gamma_size: u16,
    /// Whether active state changed (for connector routing updates).
    pub active_changed: bool,
    /// Connector mask: bitmask of connectors driven by this CRTC.
    pub connector_mask: u32,
    /// Plane mask: bitmask of planes attached to this CRTC.
    pub plane_mask: u32,
}

impl DrmCrtcState {
    /// Creates an inactive CRTC state.
    pub const fn new() -> Self {
        Self {
            active: false,
            mode: DrmDisplayMode {
                hdisplay: 0,
                vdisplay: 0,
                refresh_rate: 0,
                pixel_clock_khz: 0,
                htotal: 0,
                vtotal: 0,
            },
            mode_changed: false,
            gamma_size: MAX_GAMMA_SIZE as u16,
            active_changed: false,
            connector_mask: 0,
            plane_mask: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DrmConnectorState
// ---------------------------------------------------------------------------

/// Pending configuration for one connector (HDMI, DP, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct DrmConnectorState {
    /// CRTC driving this connector (0 = disconnected from pipeline).
    pub crtc_id: u32,
    /// Whether a display is physically connected.
    pub connected: bool,
    /// DPMS power mode.
    pub dpms: DpmsMode,
    /// Self-refresh / Panel Self Refresh enabled.
    pub self_refresh_aware: bool,
    /// Content protection level (0 = off).
    pub content_protection: u8,
}

impl DrmConnectorState {
    /// Creates a disconnected connector state.
    pub const fn new() -> Self {
        Self {
            crtc_id: 0,
            connected: false,
            dpms: DpmsMode::Off,
            self_refresh_aware: false,
            content_protection: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// AtomicState
// ---------------------------------------------------------------------------

/// Combined pending state snapshot for one atomic commit.
///
/// Contains up to [`MAX_PLANES`] plane states, [`MAX_CRTCS`] CRTC states,
/// and [`MAX_CONNECTORS`] connector states. All modifications are made to
/// this object; the current hardware state is left untouched until
/// `atomic_commit` succeeds.
#[derive(Default)]
pub struct AtomicState {
    /// Pending plane states.
    pub planes: [DrmPlaneState; MAX_PLANES],
    /// Which plane slots are dirty (modified in this state).
    pub planes_dirty: [bool; MAX_PLANES],
    /// Pending CRTC states.
    pub crtcs: [DrmCrtcState; MAX_CRTCS],
    /// Which CRTC slots are dirty.
    pub crtcs_dirty: [bool; MAX_CRTCS],
    /// Pending connector states.
    pub connectors: [DrmConnectorState; MAX_CONNECTORS],
    /// Which connector slots are dirty.
    pub connectors_dirty: [bool; MAX_CONNECTORS],
}

impl AtomicState {
    /// Creates a blank atomic state with all entries at their defaults.
    pub fn new() -> Self {
        Self {
            planes: [
                DrmPlaneState::new(DrmPlaneType::Primary),
                DrmPlaneState::new(DrmPlaneType::Primary),
                DrmPlaneState::new(DrmPlaneType::Primary),
                DrmPlaneState::new(DrmPlaneType::Primary),
            ],
            planes_dirty: [false; MAX_PLANES],
            crtcs: [
                DrmCrtcState::new(),
                DrmCrtcState::new(),
                DrmCrtcState::new(),
                DrmCrtcState::new(),
            ],
            crtcs_dirty: [false; MAX_CRTCS],
            connectors: [
                DrmConnectorState::new(),
                DrmConnectorState::new(),
                DrmConnectorState::new(),
                DrmConnectorState::new(),
            ],
            connectors_dirty: [false; MAX_CONNECTORS],
        }
    }

    /// Sets a plane state, marking it dirty.
    pub fn set_plane(&mut self, index: usize, state: DrmPlaneState) -> Result<()> {
        if index >= MAX_PLANES {
            return Err(Error::InvalidArgument);
        }
        self.planes[index] = state;
        self.planes_dirty[index] = true;
        Ok(())
    }

    /// Sets a CRTC state, marking it dirty.
    pub fn set_crtc(&mut self, index: usize, state: DrmCrtcState) -> Result<()> {
        if index >= MAX_CRTCS {
            return Err(Error::InvalidArgument);
        }
        self.crtcs[index] = state;
        self.crtcs_dirty[index] = true;
        Ok(())
    }

    /// Sets a connector state, marking it dirty.
    pub fn set_connector(&mut self, index: usize, state: DrmConnectorState) -> Result<()> {
        if index >= MAX_CONNECTORS {
            return Err(Error::InvalidArgument);
        }
        self.connectors[index] = state;
        self.connectors_dirty[index] = true;
        Ok(())
    }

    /// Returns `true` if any state in this snapshot has been modified.
    pub fn has_changes(&self) -> bool {
        self.planes_dirty.iter().any(|&d| d)
            || self.crtcs_dirty.iter().any(|&d| d)
            || self.connectors_dirty.iter().any(|&d| d)
    }

    /// Clears all dirty flags (after a successful commit).
    pub fn clear_dirty(&mut self) {
        self.planes_dirty = [false; MAX_PLANES];
        self.crtcs_dirty = [false; MAX_CRTCS];
        self.connectors_dirty = [false; MAX_CONNECTORS];
    }
}

// ---------------------------------------------------------------------------
// CommitFlags
// ---------------------------------------------------------------------------

/// Flags that control how an atomic commit is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitFlags(u32);

impl CommitFlags {
    /// No special behaviour — blocking commit.
    pub const NONE: Self = Self(0);
    /// Allow full modesetting (not just page flips).
    pub const ALLOW_MODESET: Self = Self(1 << 0);
    /// Validate the state but do not apply it to hardware.
    pub const TEST_ONLY: Self = Self(1 << 1);
    /// Non-blocking commit (return immediately, complete asynchronously).
    pub const NONBLOCK: Self = Self(1 << 2);

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if modesetting (clock/timing changes) is allowed.
    pub fn allows_modeset(self) -> bool {
        self.0 & Self::ALLOW_MODESET.0 != 0
    }

    /// Returns `true` if this is a test-only validation commit.
    pub fn test_only(self) -> bool {
        self.0 & Self::TEST_ONLY.0 != 0
    }

    /// Returns `true` if non-blocking operation is requested.
    pub fn nonblock(self) -> bool {
        self.0 & Self::NONBLOCK.0 != 0
    }

    /// Combines two flag sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ---------------------------------------------------------------------------
// AtomicCommit
// ---------------------------------------------------------------------------

/// An in-flight atomic display commit.
///
/// Carries the commit flags and a copy of the state snapshot at the
/// time the commit was submitted. On success the snapshot becomes the
/// new current state; on failure the subsystem retains the previous state.
pub struct AtomicCommit {
    /// Commit control flags.
    pub flags: CommitFlags,
    /// State snapshot for this commit.
    pub state: AtomicState,
    /// Sequence number for ordering commits.
    pub seqno: u64,
    /// Whether the commit has been applied.
    pub completed: bool,
}

impl AtomicCommit {
    /// Creates a new commit from a state snapshot and flags.
    pub fn new(state: AtomicState, flags: CommitFlags, seqno: u64) -> Self {
        Self {
            flags,
            state,
            seqno,
            completed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DrmAtomicSubsystem
// ---------------------------------------------------------------------------

/// DRM atomic modesetting coordinator.
///
/// Maintains the current hardware state and a pending state. Clients
/// modify the pending state via `set_property`, validate it with
/// `atomic_check`, and apply it with `atomic_commit`. Failed commits
/// call `rollback` to restore the previous state.
pub struct DrmAtomicSubsystem {
    /// Active (currently programmed) state.
    current_state: AtomicState,
    /// Pending state being built for the next commit.
    pending_state: AtomicState,
    /// Commit sequence counter.
    next_seqno: u64,
}

impl Default for DrmAtomicSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl DrmAtomicSubsystem {
    /// Creates a new atomic subsystem with blank current and pending states.
    pub fn new() -> Self {
        Self {
            current_state: AtomicState::new(),
            pending_state: AtomicState::new(),
            next_seqno: 1,
        }
    }

    // ── Property setters ─────────────────────────────────────────────

    /// Sets a plane property in the pending state.
    pub fn set_plane_state(&mut self, plane_idx: usize, state: DrmPlaneState) -> Result<()> {
        self.pending_state.set_plane(plane_idx, state)
    }

    /// Sets a CRTC property in the pending state.
    pub fn set_crtc_state(&mut self, crtc_idx: usize, state: DrmCrtcState) -> Result<()> {
        self.pending_state.set_crtc(crtc_idx, state)
    }

    /// Sets a connector property in the pending state.
    pub fn set_connector_state(&mut self, conn_idx: usize, state: DrmConnectorState) -> Result<()> {
        self.pending_state.set_connector(conn_idx, state)
    }

    // ── Property getters ─────────────────────────────────────────────

    /// Returns the current (active) plane state.
    pub fn get_plane_state(&self, plane_idx: usize) -> Result<&DrmPlaneState> {
        if plane_idx >= MAX_PLANES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.current_state.planes[plane_idx])
    }

    /// Returns the current CRTC state.
    pub fn get_crtc_state(&self, crtc_idx: usize) -> Result<&DrmCrtcState> {
        if crtc_idx >= MAX_CRTCS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.current_state.crtcs[crtc_idx])
    }

    /// Returns the current connector state.
    pub fn get_connector_state(&self, conn_idx: usize) -> Result<&DrmConnectorState> {
        if conn_idx >= MAX_CONNECTORS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.current_state.connectors[conn_idx])
    }

    // ── Check ─────────────────────────────────────────────────────────

    /// Validates the pending state without touching hardware.
    ///
    /// Checks that:
    /// - Every active plane references a valid CRTC.
    /// - Every active CRTC has a non-empty display mode (unless being disabled).
    /// - Modesetting changes are only present when `ALLOW_MODESET` is set.
    pub fn atomic_check(&self, flags: CommitFlags) -> Result<()> {
        // Validate plane → CRTC references
        for i in 0..MAX_PLANES {
            if !self.pending_state.planes_dirty[i] {
                continue;
            }
            let plane = &self.pending_state.planes[i];
            if plane.is_active() {
                let crtc_idx = (plane.crtc_id as usize).saturating_sub(1);
                if crtc_idx >= MAX_CRTCS {
                    return Err(Error::InvalidArgument);
                }
            }
        }

        // Validate CRTC modes
        for i in 0..MAX_CRTCS {
            if !self.pending_state.crtcs_dirty[i] {
                continue;
            }
            let crtc = &self.pending_state.crtcs[i];
            if crtc.active && crtc.mode.is_empty() {
                return Err(Error::InvalidArgument);
            }
            // Mode changes require ALLOW_MODESET
            if crtc.mode_changed && !flags.allows_modeset() {
                return Err(Error::PermissionDenied);
            }
        }

        // Validate connector → CRTC references
        for i in 0..MAX_CONNECTORS {
            if !self.pending_state.connectors_dirty[i] {
                continue;
            }
            let conn = &self.pending_state.connectors[i];
            if conn.crtc_id != 0 {
                let crtc_idx = (conn.crtc_id as usize).saturating_sub(1);
                if crtc_idx >= MAX_CRTCS {
                    return Err(Error::InvalidArgument);
                }
            }
        }

        Ok(())
    }

    // ── Commit ────────────────────────────────────────────────────────

    /// Validates and commits the pending state to hardware.
    ///
    /// If `TEST_ONLY` is set the state is validated but not applied.
    /// Returns the commit sequence number on success.
    pub fn atomic_commit(&mut self, flags: CommitFlags) -> Result<u64> {
        if !self.pending_state.has_changes() {
            return Err(Error::InvalidArgument);
        }

        // Phase 1: check
        self.atomic_check(flags)?;

        let seqno = self.next_seqno;
        self.next_seqno = self.next_seqno.wrapping_add(1);

        if flags.test_only() {
            // Discard pending changes without applying
            self.pending_state = AtomicState::new();
            return Ok(seqno);
        }

        // Phase 2: apply — copy dirty state into current state
        for i in 0..MAX_PLANES {
            if self.pending_state.planes_dirty[i] {
                self.current_state.planes[i] = self.pending_state.planes[i];
                self.current_state.planes_dirty[i] = true;
            }
        }
        for i in 0..MAX_CRTCS {
            if self.pending_state.crtcs_dirty[i] {
                self.current_state.crtcs[i] = self.pending_state.crtcs[i];
                self.current_state.crtcs_dirty[i] = true;
            }
        }
        for i in 0..MAX_CONNECTORS {
            if self.pending_state.connectors_dirty[i] {
                self.current_state.connectors[i] = self.pending_state.connectors[i];
                self.current_state.connectors_dirty[i] = true;
            }
        }

        // Reset pending state for the next commit
        self.pending_state = AtomicState::new();
        Ok(seqno)
    }

    /// Rolls back the pending state, discarding all uncommitted changes.
    pub fn rollback(&mut self) {
        self.pending_state = AtomicState::new();
    }

    /// Returns the current display mode for the given CRTC index.
    pub fn current_mode(&self, crtc_idx: usize) -> Result<DrmDisplayMode> {
        if crtc_idx >= MAX_CRTCS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.current_state.crtcs[crtc_idx].mode)
    }

    /// Returns `true` if the given CRTC is currently active.
    pub fn crtc_active(&self, crtc_idx: usize) -> bool {
        if crtc_idx >= MAX_CRTCS {
            return false;
        }
        self.current_state.crtcs[crtc_idx].active
    }

    /// Returns `true` if the given connector is reported as connected.
    pub fn connector_connected(&self, conn_idx: usize) -> bool {
        if conn_idx >= MAX_CONNECTORS {
            return false;
        }
        self.current_state.connectors[conn_idx].connected
    }
}
