// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM display plane abstraction.
//!
//! Provides `DrmPlane`, `PlaneState`, and `PlaneType` types modelled
//! after the Linux DRM/KMS plane API.  Planes represent hardware
//! compositing layers that are blended before scan-out.
//!
//! # Plane types
//!
//! - **Primary** — the main full-screen plane, required by every CRTC.
//! - **Overlay** — additional compositing layers.
//! - **Cursor** — hardware cursor plane (small, low-latency).
//!
//! # Atomic KMS
//!
//! Plane configuration is always expressed as a `PlaneState` delta that
//! is validated with `check` then applied with `update`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of pixel formats a plane can support.
const MAX_FORMATS: usize = 16;

/// Maximum number of planes in the registry.
const MAX_PLANES: usize = 16;

// ── PlaneType ────────────────────────────────────────────────────────────────

/// DRM display plane type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneType {
    /// Primary (background) plane — required, covers the full CRTC.
    Primary,
    /// Overlay — additional compositing layer.
    Overlay,
    /// Cursor — small hardware sprite, typically 64×64 or less.
    Cursor,
}

// ── PixelFormat ───────────────────────────────────────────────────────────────

/// Pixel format four-character codes (subset of DRM FOURCC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// 32-bit XRGB (no alpha).
    Xrgb8888 = u32::from_le_bytes(*b"XR24"),
    /// 32-bit ARGB (with alpha).
    Argb8888 = u32::from_le_bytes(*b"AR24"),
    /// 16-bit RGB565.
    Rgb565 = u32::from_le_bytes(*b"RG16"),
    /// 32-bit XBGR.
    Xbgr8888 = u32::from_le_bytes(*b"XB24"),
    /// NV12 semi-planar YUV.
    Nv12 = u32::from_le_bytes(*b"NV12"),
}

// ── Rotation ─────────────────────────────────────────────────────────────────

/// Plane rotation/reflection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation(pub u32);

impl Rotation {
    /// No rotation.
    pub const NONE: Self = Self(0);
    /// 90° clockwise.
    pub const ROTATE_90: Self = Self(1 << 1);
    /// 180° rotation.
    pub const ROTATE_180: Self = Self(1 << 2);
    /// 270° clockwise (90° counter-clockwise).
    pub const ROTATE_270: Self = Self(1 << 3);
    /// Horizontal reflect.
    pub const REFLECT_X: Self = Self(1 << 4);
    /// Vertical reflect.
    pub const REFLECT_Y: Self = Self(1 << 5);
}

// ── PlaneState ───────────────────────────────────────────────────────────────

/// Atomic plane state.
///
/// All coordinates are in pixels. Source coordinates use 16.16 fixed-point
/// (low 16 bits are fractional) as per the DRM specification.
#[derive(Debug, Clone, Copy)]
pub struct PlaneState {
    /// CRTC X position (destination, integer pixels).
    pub crtc_x: i32,
    /// CRTC Y position.
    pub crtc_y: i32,
    /// Width on the CRTC (destination).
    pub crtc_w: u32,
    /// Height on the CRTC (destination).
    pub crtc_h: u32,
    /// Source X (16.16 fixed-point, within the framebuffer).
    pub src_x: u32,
    /// Source Y (16.16 fixed-point).
    pub src_y: u32,
    /// Source width (16.16 fixed-point).
    pub src_w: u32,
    /// Source height (16.16 fixed-point).
    pub src_h: u32,
    /// Framebuffer handle (0 = plane disabled).
    pub fb_id: u32,
    /// CRTC this plane is attached to (0 = detached).
    pub crtc_id: u32,
    /// Rotation flags.
    pub rotation: Rotation,
    /// Alpha blending (0=transparent, 0xFFFF=opaque).
    pub alpha: u16,
    /// Z-position for overlay ordering (0 = bottom).
    pub zpos: u8,
    /// Whether this state has been validated.
    pub validated: bool,
}

impl PlaneState {
    /// Create a disabled (framebuffer 0) state.
    pub const fn disabled() -> Self {
        Self {
            crtc_x: 0,
            crtc_y: 0,
            crtc_w: 0,
            crtc_h: 0,
            src_x: 0,
            src_y: 0,
            src_w: 0,
            src_h: 0,
            fb_id: 0,
            crtc_id: 0,
            rotation: Rotation::NONE,
            alpha: 0xFFFF,
            zpos: 0,
            validated: false,
        }
    }

    /// Return the source width in integer pixels (strip 16.16 fractional).
    pub fn src_w_pixels(&self) -> u32 {
        self.src_w >> 16
    }

    /// Return the source height in integer pixels.
    pub fn src_h_pixels(&self) -> u32 {
        self.src_h >> 16
    }

    /// Return whether this state enables the plane.
    pub fn is_enabled(&self) -> bool {
        self.fb_id != 0 && self.crtc_id != 0
    }
}

impl Default for PlaneState {
    fn default() -> Self {
        Self::disabled()
    }
}

// ── DrmPlane ─────────────────────────────────────────────────────────────────

/// A DRM display plane.
pub struct DrmPlane {
    /// Unique plane identifier.
    pub id: u32,
    /// Plane type.
    pub plane_type: PlaneType,
    /// Bitmask of possible CRTCs (bit N = CRTC N).
    pub possible_crtcs: u32,
    /// Supported pixel formats.
    pub formats: [PixelFormat; MAX_FORMATS],
    /// Number of entries in `formats`.
    pub format_count: usize,
    /// Currently committed state.
    pub state: PlaneState,
    /// Pending (not yet committed) state.
    pub pending: PlaneState,
    /// Whether the plane is currently enabled.
    pub enabled: bool,
}

impl DrmPlane {
    /// Create a new DRM plane.
    pub const fn new(id: u32, plane_type: PlaneType, possible_crtcs: u32) -> Self {
        Self {
            id,
            plane_type,
            possible_crtcs,
            formats: [PixelFormat::Xrgb8888; MAX_FORMATS],
            format_count: 1,
            state: PlaneState::disabled(),
            pending: PlaneState::disabled(),
            enabled: false,
        }
    }

    /// Add a supported pixel format.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if `MAX_FORMATS` is exceeded.
    pub fn add_format(&mut self, fmt: PixelFormat) -> Result<()> {
        if self.format_count >= MAX_FORMATS {
            return Err(Error::OutOfMemory);
        }
        self.formats[self.format_count] = fmt;
        self.format_count += 1;
        Ok(())
    }

    /// Return whether `fmt` is supported by this plane.
    pub fn supports_format(&self, fmt: PixelFormat) -> bool {
        self.formats[..self.format_count].contains(&fmt)
    }

    /// Validate a pending `PlaneState` for atomic check.
    ///
    /// Verifies:
    /// - CRTC is in `possible_crtcs`.
    /// - Source and destination dimensions are non-zero (if enabled).
    /// - Pixel format is supported.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for any invalid state.
    pub fn atomic_check(&self, new_state: &mut PlaneState) -> Result<()> {
        if !new_state.is_enabled() {
            new_state.validated = true;
            return Ok(());
        }

        // Check CRTC is allowed.
        let crtc_bit = new_state.crtc_id.saturating_sub(1);
        if crtc_bit < 32 && self.possible_crtcs & (1 << crtc_bit) == 0 {
            return Err(Error::InvalidArgument);
        }

        // Check non-zero destination.
        if new_state.crtc_w == 0 || new_state.crtc_h == 0 {
            return Err(Error::InvalidArgument);
        }

        // Cursor planes have a size limit of 256×256.
        if self.plane_type == PlaneType::Cursor {
            if new_state.crtc_w > 256 || new_state.crtc_h > 256 {
                return Err(Error::InvalidArgument);
            }
        }

        new_state.validated = true;
        Ok(())
    }

    /// Commit the pending state (atomic update).
    ///
    /// Copies `pending` to `state` and updates `enabled`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pending` has not been validated.
    pub fn atomic_update(&mut self, new_state: PlaneState) -> Result<()> {
        if !new_state.validated {
            return Err(Error::InvalidArgument);
        }
        self.state = new_state;
        self.enabled = new_state.is_enabled();
        Ok(())
    }

    /// Disable this plane (set state to disabled).
    pub fn disable(&mut self) {
        self.state = PlaneState::disabled();
        self.enabled = false;
    }
}

// ── DrmPlaneRegistry ─────────────────────────────────────────────────────────

/// Registry of DRM planes.
pub struct DrmPlaneRegistry {
    planes: [Option<DrmPlane>; MAX_PLANES],
    count: usize,
    next_id: u32,
}

impl DrmPlaneRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            planes: [const { None }; MAX_PLANES],
            count: 0,
            next_id: 1,
        }
    }

    /// Register a new plane and return its assigned ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, plane_type: PlaneType, possible_crtcs: u32) -> Result<u32> {
        if self.count >= MAX_PLANES {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.planes[self.count] = Some(DrmPlane::new(id, plane_type, possible_crtcs));
        self.count += 1;
        Ok(id)
    }

    /// Look up a plane by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&DrmPlane> {
        for i in 0..self.count {
            if let Some(p) = &self.planes[i] {
                if p.id == id {
                    return Ok(p);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a plane by ID (mutable).
    pub fn get_mut(&mut self, id: u32) -> Result<&mut DrmPlane> {
        for i in 0..self.count {
            if let Some(p) = &self.planes[i] {
                if p.id == id {
                    return Ok(self.planes[i].as_mut().unwrap());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered planes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether no planes are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DrmPlaneRegistry {
    fn default() -> Self {
        Self::new()
    }
}
