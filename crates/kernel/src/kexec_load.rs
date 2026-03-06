// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kexec load interface — loading new kernels for fast reboot.
//!
//! Handles loading a new kernel image and optional initrd into memory
//! for execution via kexec.  The loaded image is validated and stored
//! in reserved memory regions until the actual kexec is triggered.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    KexecLoader                               │
//! │                                                              │
//! │  KexecImage[0..MAX_IMAGES]  (loaded kernel images)           │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  image_type: ImageType                                 │  │
//! │  │  entry_point: u64                                      │  │
//! │  │  image_size: usize                                     │  │
//! │  │  state: ImageState                                     │  │
//! │  │  segments: [Segment; MAX_SEGMENTS]                      │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/kexec.c`, `kernel/kexec_file.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum loaded images (normal + crash).
const MAX_IMAGES: usize = 4;

/// Maximum segments per image.
const MAX_SEGMENTS: usize = 16;

/// Maximum image size (256 MB).
const MAX_IMAGE_SIZE: usize = 256 * 1024 * 1024;

// ══════════════════════════════════════════════════════════════
// ImageType
// ══════════════════════════════════════════════════════════════

/// Type of kexec image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ImageType {
    /// Normal reboot image.
    Normal = 0,
    /// Crash dump image (loaded into reserved memory).
    Crash = 1,
}

impl ImageType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Crash => "crash",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ImageState
// ══════════════════════════════════════════════════════════════

/// State of a loaded kexec image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ImageState {
    /// Slot is empty.
    Empty = 0,
    /// Image is being loaded.
    Loading = 1,
    /// Image is loaded and ready.
    Ready = 2,
    /// Image validation failed.
    Invalid = 3,
}

// ══════════════════════════════════════════════════════════════
// Segment
// ══════════════════════════════════════════════════════════════

/// A memory segment of a kexec image.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    /// Physical load address.
    pub phys_addr: u64,
    /// Size of the segment in bytes.
    pub size: usize,
    /// Memory size (may be larger for BSS).
    pub mem_size: usize,
    /// Whether this segment is active.
    pub active: bool,
}

impl Segment {
    /// Create an empty segment.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            size: 0,
            mem_size: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KexecImage
// ══════════════════════════════════════════════════════════════

/// A loaded kexec kernel image.
#[derive(Debug, Clone, Copy)]
pub struct KexecImage {
    /// Image type (normal or crash).
    pub image_type: ImageType,
    /// Entry point address.
    pub entry_point: u64,
    /// Total image size in bytes.
    pub image_size: usize,
    /// Current state.
    pub state: ImageState,
    /// Memory segments.
    pub segments: [Segment; MAX_SEGMENTS],
    /// Number of active segments.
    pub segment_count: usize,
    /// Whether signature verification passed.
    pub sig_verified: bool,
    /// Load timestamp (tick).
    pub load_tick: u64,
}

impl KexecImage {
    /// Create an empty image slot.
    const fn empty() -> Self {
        Self {
            image_type: ImageType::Normal,
            entry_point: 0,
            image_size: 0,
            state: ImageState::Empty,
            segments: [const { Segment::empty() }; MAX_SEGMENTS],
            segment_count: 0,
            sig_verified: false,
            load_tick: 0,
        }
    }

    /// Returns `true` if the slot has an image.
    pub const fn is_loaded(&self) -> bool {
        !matches!(self.state, ImageState::Empty)
    }

    /// Returns `true` if the image is ready for execution.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, ImageState::Ready)
    }
}

// ══════════════════════════════════════════════════════════════
// KexecLoadStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the kexec loader.
#[derive(Debug, Clone, Copy)]
pub struct KexecLoadStats {
    /// Total load attempts.
    pub total_loads: u64,
    /// Successful loads.
    pub total_success: u64,
    /// Failed loads.
    pub total_failures: u64,
    /// Total unloads.
    pub total_unloads: u64,
    /// Total bytes loaded.
    pub total_bytes: u64,
}

impl KexecLoadStats {
    const fn new() -> Self {
        Self {
            total_loads: 0,
            total_success: 0,
            total_failures: 0,
            total_unloads: 0,
            total_bytes: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KexecLoader
// ══════════════════════════════════════════════════════════════

/// Top-level kexec load subsystem.
pub struct KexecLoader {
    /// Loaded images.
    images: [KexecImage; MAX_IMAGES],
    /// Statistics.
    stats: KexecLoadStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Whether kexec loading is allowed.
    load_allowed: bool,
}

impl Default for KexecLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecLoader {
    /// Create a new kexec loader.
    pub const fn new() -> Self {
        Self {
            images: [const { KexecImage::empty() }; MAX_IMAGES],
            stats: KexecLoadStats::new(),
            initialised: false,
            load_allowed: true,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Enable or disable kexec loading.
    pub fn set_load_allowed(&mut self, allowed: bool) {
        self.load_allowed = allowed;
    }

    // ── Load operations ──────────────────────────────────────

    /// Begin loading a kexec image.
    ///
    /// Returns the image slot index.
    pub fn load(
        &mut self,
        image_type: ImageType,
        entry_point: u64,
        image_size: usize,
        tick: u64,
    ) -> Result<usize> {
        if !self.load_allowed {
            return Err(Error::PermissionDenied);
        }
        if image_size == 0 || image_size > MAX_IMAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if entry_point == 0 {
            return Err(Error::InvalidArgument);
        }

        self.stats.total_loads += 1;

        let slot = self
            .images
            .iter()
            .position(|i| matches!(i.state, ImageState::Empty))
            .ok_or(Error::OutOfMemory)?;

        self.images[slot] = KexecImage {
            image_type,
            entry_point,
            image_size,
            state: ImageState::Loading,
            segments: [const { Segment::empty() }; MAX_SEGMENTS],
            segment_count: 0,
            sig_verified: false,
            load_tick: tick,
        };

        Ok(slot)
    }

    /// Add a segment to a loading image.
    pub fn add_segment(
        &mut self,
        slot: usize,
        phys_addr: u64,
        size: usize,
        mem_size: usize,
    ) -> Result<()> {
        if slot >= MAX_IMAGES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.images[slot].state, ImageState::Loading) {
            return Err(Error::InvalidArgument);
        }
        let idx = self.images[slot].segment_count;
        if idx >= MAX_SEGMENTS {
            return Err(Error::OutOfMemory);
        }

        self.images[slot].segments[idx] = Segment {
            phys_addr,
            size,
            mem_size,
            active: true,
        };
        self.images[slot].segment_count += 1;
        Ok(())
    }

    /// Finalise loading and mark the image as ready.
    pub fn finalise(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_IMAGES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.images[slot].state, ImageState::Loading) {
            return Err(Error::InvalidArgument);
        }
        if self.images[slot].segment_count == 0 {
            self.images[slot].state = ImageState::Invalid;
            self.stats.total_failures += 1;
            return Err(Error::InvalidArgument);
        }

        self.images[slot].state = ImageState::Ready;
        self.stats.total_success += 1;
        self.stats.total_bytes += self.images[slot].image_size as u64;
        Ok(())
    }

    /// Unload a kexec image.
    pub fn unload(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_IMAGES || !self.images[slot].is_loaded() {
            return Err(Error::NotFound);
        }
        self.images[slot] = KexecImage::empty();
        self.stats.total_unloads += 1;
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return an image.
    pub fn image(&self, slot: usize) -> Result<&KexecImage> {
        if slot >= MAX_IMAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.images[slot])
    }

    /// Find a ready image by type.
    pub fn find_ready(&self, image_type: ImageType) -> Option<usize> {
        self.images
            .iter()
            .position(|i| i.is_ready() && i.image_type as u8 == image_type as u8)
    }

    /// Return statistics.
    pub fn stats(&self) -> KexecLoadStats {
        self.stats
    }

    /// Return the number of loaded images.
    pub fn loaded_count(&self) -> usize {
        self.images.iter().filter(|i| i.is_loaded()).count()
    }
}
