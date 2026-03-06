// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM (Direct Rendering Manager) framebuffer subsystem.
//!
//! Provides framebuffer creation, destruction, dirty-rect tracking, and
//! format information. This module implements the DRM framebuffer layer used
//! by display drivers to manage render targets.
//!
//! # DrmFb lifecycle
//! 1. Allocate a GEM buffer handle (driver-specific, not in this module).
//! 2. Call `DrmFb::create()` with the buffer handle and display parameters.
//! 3. Register the fb with a CRTC via `DrmFbHelper`.
//! 4. On scanout completion, call `mark_clean()`.
//! 5. Destroy with `DrmFb::destroy()` when no longer needed.
//!
//! Reference: Linux DRM/KMS Driver Writer's Guide (kernel.org).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Pixel Format Identifiers
// ---------------------------------------------------------------------------

/// DRM pixel format: 32-bit XRGB (X=unused, R, G, B — 8 bits each).
pub const DRM_FORMAT_XRGB8888: u32 = 0x3458_5258; // "XR24"
/// DRM pixel format: 32-bit ARGB (A, R, G, B — 8 bits each).
pub const DRM_FORMAT_ARGB8888: u32 = 0x3441_5258; // "AR24"
/// DRM pixel format: 32-bit XBGR (X=unused, B, G, R — 8 bits each).
pub const DRM_FORMAT_XBGR8888: u32 = 0x3458_4742; // "XB24"
/// DRM pixel format: 32-bit ABGR (A, B, G, R — 8 bits each).
pub const DRM_FORMAT_ABGR8888: u32 = 0x3441_4742; // "AB24"
/// DRM pixel format: 24-bit RGB (no alpha, R, G, B — 8 bits each, packed).
pub const DRM_FORMAT_RGB888: u32 = 0x3433_4752; // "RG24"
/// DRM pixel format: 16-bit RGB 5:6:5.
pub const DRM_FORMAT_RGB565: u32 = 0x3631_4752; // "RG16"

/// Maximum number of framebuffer planes (ONCRIX supports single-plane only).
pub const DRM_FB_MAX_PLANES: usize = 1;

/// Maximum framebuffer width in pixels.
pub const DRM_FB_MAX_WIDTH: u32 = 7680; // 8K
/// Maximum framebuffer height in pixels.
pub const DRM_FB_MAX_HEIGHT: u32 = 4320;
/// Maximum framebuffer bits per pixel.
pub const DRM_FB_MAX_BPP: u8 = 32;

/// Maximum number of framebuffers tracked.
const MAX_FRAMEBUFFERS: usize = 8;

// ---------------------------------------------------------------------------
// Dirty Rectangle Tracking
// ---------------------------------------------------------------------------

/// A rectangle specifying a dirty region that needs to be flushed to hardware.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirtyRect {
    /// Left edge (inclusive, in pixels).
    pub x1: u32,
    /// Top edge (inclusive, in pixels).
    pub y1: u32,
    /// Right edge (exclusive, in pixels).
    pub x2: u32,
    /// Bottom edge (exclusive, in pixels).
    pub y2: u32,
}

impl DirtyRect {
    /// Creates a rectangle covering the entire framebuffer.
    pub const fn full(width: u32, height: u32) -> Self {
        Self {
            x1: 0,
            y1: 0,
            x2: width,
            y2: height,
        }
    }

    /// Returns `true` if this is an empty (zero-area) rectangle.
    pub const fn is_empty(&self) -> bool {
        self.x1 >= self.x2 || self.y1 >= self.y2
    }

    /// Extends this rectangle to also cover `other`.
    pub fn union_with(&mut self, other: &DirtyRect) {
        if other.is_empty() {
            return;
        }
        if self.is_empty() {
            *self = *other;
        } else {
            self.x1 = self.x1.min(other.x1);
            self.y1 = self.y1.min(other.y1);
            self.x2 = self.x2.max(other.x2);
            self.y2 = self.y2.max(other.y2);
        }
    }
}

// ---------------------------------------------------------------------------
// Pixel Format Information
// ---------------------------------------------------------------------------

/// Describes per-format metadata for a DRM pixel format.
#[derive(Clone, Copy, Debug)]
pub struct DrmFormatInfo {
    /// DRM format fourcc code.
    pub format: u32,
    /// Bits per pixel.
    pub bpp: u8,
    /// Bytes per pixel.
    pub cpp: u8,
    /// `true` if the format has an alpha channel.
    pub has_alpha: bool,
    /// Human-readable format name.
    pub name: &'static str,
}

/// Returns format metadata for a known DRM pixel format.
///
/// Returns `None` for unknown/unsupported formats.
pub fn format_info(format: u32) -> Option<DrmFormatInfo> {
    match format {
        DRM_FORMAT_XRGB8888 => Some(DrmFormatInfo {
            format,
            bpp: 32,
            cpp: 4,
            has_alpha: false,
            name: "XRGB8888",
        }),
        DRM_FORMAT_ARGB8888 => Some(DrmFormatInfo {
            format,
            bpp: 32,
            cpp: 4,
            has_alpha: true,
            name: "ARGB8888",
        }),
        DRM_FORMAT_XBGR8888 => Some(DrmFormatInfo {
            format,
            bpp: 32,
            cpp: 4,
            has_alpha: false,
            name: "XBGR8888",
        }),
        DRM_FORMAT_ABGR8888 => Some(DrmFormatInfo {
            format,
            bpp: 32,
            cpp: 4,
            has_alpha: true,
            name: "ABGR8888",
        }),
        DRM_FORMAT_RGB888 => Some(DrmFormatInfo {
            format,
            bpp: 24,
            cpp: 3,
            has_alpha: false,
            name: "RGB888",
        }),
        DRM_FORMAT_RGB565 => Some(DrmFormatInfo {
            format,
            bpp: 16,
            cpp: 2,
            has_alpha: false,
            name: "RGB565",
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DrmFb
// ---------------------------------------------------------------------------

/// A DRM framebuffer object.
///
/// Tracks the display mode, pitch, format, GEM handle, and current dirty region.
#[derive(Clone, Debug)]
pub struct DrmFb {
    /// Unique framebuffer ID (assigned by registry).
    pub id: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Stride in bytes (bytes per scanline).
    pub pitch: u32,
    /// Color depth in bits (e.g., 24 for RGB888).
    pub depth: u8,
    /// Bits per pixel (e.g., 32 for XRGB8888).
    pub bpp: u8,
    /// DRM format fourcc code.
    pub format: u32,
    /// GEM buffer handle (opaque driver handle for the backing buffer).
    pub handle: u32,
    /// Current accumulated dirty region.
    pub dirty: DirtyRect,
    /// `true` if the framebuffer has been allocated and is valid.
    pub active: bool,
}

impl DrmFb {
    /// Creates a new DRM framebuffer.
    ///
    /// # Parameters
    /// - `id`: Unique ID for this framebuffer.
    /// - `width`, `height`: Dimensions in pixels.
    /// - `format`: DRM format fourcc.
    /// - `handle`: GEM buffer handle.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` for out-of-range dimensions or unsupported format.
    pub fn create(id: u32, width: u32, height: u32, format: u32, handle: u32) -> Result<Self> {
        if width == 0 || width > DRM_FB_MAX_WIDTH {
            return Err(Error::InvalidArgument);
        }
        if height == 0 || height > DRM_FB_MAX_HEIGHT {
            return Err(Error::InvalidArgument);
        }
        let info = format_info(format).ok_or(Error::InvalidArgument)?;
        let pitch = width * info.cpp as u32;
        Ok(Self {
            id,
            width,
            height,
            pitch,
            depth: info.bpp,
            bpp: info.bpp,
            format,
            handle,
            dirty: DirtyRect::default(),
            active: true,
        })
    }

    /// Destroys this framebuffer, marking it inactive.
    pub fn destroy(&mut self) {
        self.active = false;
        self.handle = 0;
    }

    /// Marks the rectangle `rect` as dirty (needing hardware flush).
    ///
    /// Unions `rect` with the existing dirty region.
    pub fn mark_dirty(&mut self, rect: DirtyRect) {
        self.dirty.union_with(&rect);
    }

    /// Marks the entire framebuffer as dirty.
    pub fn mark_dirty_all(&mut self) {
        self.dirty = DirtyRect::full(self.width, self.height);
    }

    /// Clears the dirty region after a successful hardware flush.
    pub fn mark_clean(&mut self) {
        self.dirty = DirtyRect::default();
    }

    /// Returns `true` if any region is dirty.
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// Returns the total framebuffer size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.pitch as u64 * self.height as u64
    }

    /// Returns the pixel offset in bytes of pixel (x, y).
    pub fn pixel_offset(&self, x: u32, y: u32) -> Option<u64> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let cpp = format_info(self.format)?.cpp as u64;
        Some(y as u64 * self.pitch as u64 + x as u64 * cpp)
    }
}

// ---------------------------------------------------------------------------
// DrmFbHelper
// ---------------------------------------------------------------------------

/// Preferred display mode for a `DrmFbHelper`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreferredMode {
    /// Preferred width in pixels.
    pub width: u32,
    /// Preferred height in pixels.
    pub height: u32,
    /// Preferred refresh rate in Hz.
    pub refresh_hz: u32,
}

/// Helper for managing the primary framebuffer and display properties.
pub struct DrmFbHelper {
    /// Current primary framebuffer ID.
    pub fb_id: u32,
    /// Preferred display mode.
    pub preferred_mode: PreferredMode,
    /// Current pan X offset (for double-buffering or scrolling).
    pub pan_x: u32,
    /// Current pan Y offset.
    pub pan_y: u32,
}

impl DrmFbHelper {
    /// Creates a new `DrmFbHelper`.
    ///
    /// # Parameters
    /// - `fb_id`: The primary framebuffer ID.
    /// - `preferred_mode`: The preferred display mode.
    pub const fn new(fb_id: u32, preferred_mode: PreferredMode) -> Self {
        Self {
            fb_id,
            preferred_mode,
            pan_x: 0,
            pan_y: 0,
        }
    }

    /// Updates the pan position for display scrolling or double-buffer flip.
    ///
    /// # Parameters
    /// - `fb`: The framebuffer to validate against.
    /// - `pan_x`, `pan_y`: New pan offsets (must be within the fb dimensions).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the pan position is out of range.
    pub fn pan(&mut self, fb: &DrmFb, pan_x: u32, pan_y: u32) -> Result<()> {
        if pan_x >= fb.width || pan_y >= fb.height {
            return Err(Error::InvalidArgument);
        }
        self.pan_x = pan_x;
        self.pan_y = pan_y;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DRM Framebuffer Registry
// ---------------------------------------------------------------------------

/// Registry of allocated DRM framebuffers.
pub struct DrmFbRegistry {
    fbs: [Option<DrmFb>; MAX_FRAMEBUFFERS],
    next_id: u32,
    count: usize,
}

impl DrmFbRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            fbs: [const { None }; MAX_FRAMEBUFFERS],
            next_id: 1,
            count: 0,
        }
    }

    /// Allocates a new framebuffer and returns its ID.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the registry is full or parameters are invalid.
    pub fn create_fb(&mut self, width: u32, height: u32, format: u32, handle: u32) -> Result<u32> {
        if self.count >= MAX_FRAMEBUFFERS {
            return Err(Error::InvalidArgument);
        }
        let id = self.next_id;
        let fb = DrmFb::create(id, width, height, format, handle)?;
        for slot in &mut self.fbs {
            if slot.is_none() {
                *slot = Some(fb);
                self.next_id = self.next_id.wrapping_add(1);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Destroys a framebuffer by ID.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the ID is not found.
    pub fn destroy_fb(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.fbs {
            if let Some(fb) = slot {
                if fb.id == id {
                    fb.destroy();
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Returns a reference to the framebuffer with the given ID.
    pub fn get(&self, id: u32) -> Option<&DrmFb> {
        for slot in &self.fbs {
            if let Some(fb) = slot {
                if fb.id == id {
                    return Some(fb);
                }
            }
        }
        None
    }

    /// Returns a mutable reference to the framebuffer with the given ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut DrmFb> {
        for slot in &mut self.fbs {
            if let Some(fb) = slot {
                if fb.id == id {
                    return Some(fb);
                }
            }
        }
        None
    }

    /// Returns the number of active framebuffers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no framebuffers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DrmFbRegistry {
    fn default() -> Self {
        Self::new()
    }
}
