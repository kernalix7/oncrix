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

use crate::capability::{CAP_SYS_BOOT, CapSet};
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

/// Maximum size of a single segment in bytes (256 MB).
const MAX_SEGMENT_SIZE: usize = 256 * 1024 * 1024;

/// Required alignment for segment physical addresses (4 KiB page).
const SEGMENT_ALIGN: u64 = 0x1000;

/// Minimum valid entry point address (above the 1 MiB real-mode region
/// on x86_64).
const MIN_ENTRY_ADDR: u64 = 0x10_0000;

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
    /// Whether kernel lockdown / secure-boot enforcement is engaged.
    ///
    /// When engaged, an image may only become [`ImageState::Ready`] if
    /// its signature verified. Defaults to engaged (fail closed).
    lockdown: bool,
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
            // Fail closed: lockdown engaged until policy explicitly
            // relaxes it after a real verifier is wired up.
            lockdown: true,
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

    /// Engage or relax kernel lockdown / secure-boot enforcement.
    ///
    /// When engaged, [`finalise`](Self::finalise) refuses to mark an
    /// image ready unless its signature verified.
    ///
    // SECURITY: relaxing lockdown disables signature enforcement on the
    // replacement kernel. Only a trusted policy path (with the platform
    // secure-boot state) may call this with `false`.
    pub fn set_lockdown(&mut self, engaged: bool) {
        self.lockdown = engaged;
    }

    // ── Load operations ──────────────────────────────────────

    /// Begin loading a kexec image.
    ///
    /// Loading a replacement kernel is the most privileged operation in
    /// the system; the caller must hold `CAP_SYS_BOOT`. `caller` is the
    /// authenticated capability set of the requesting task.
    ///
    /// Returns the image slot index.
    ///
    // SECURITY: `caller` MUST be the authenticated effective capability
    // set of the requesting task. Per-task creds are not yet threaded
    // through the syscall dispatcher, so this entry point fails closed:
    // a caller without `CAP_SYS_BOOT` is denied. The dispatcher MUST
    // pass the real caller cred once available; do not default to
    // `CapSet::FULL`. `load_allowed` remains a separate global
    // kill-switch and does not replace this per-caller check.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if `caller` lacks
    /// `CAP_SYS_BOOT` or loading is globally disabled, or
    /// [`Error::InvalidArgument`] if the image parameters are invalid.
    pub fn load(
        &mut self,
        caller: CapSet,
        image_type: ImageType,
        entry_point: u64,
        image_size: usize,
        tick: u64,
    ) -> Result<usize> {
        // Fail closed: loading a kernel requires CAP_SYS_BOOT.
        if !caller.has(CAP_SYS_BOOT) {
            return Err(Error::PermissionDenied);
        }
        if !self.load_allowed {
            return Err(Error::PermissionDenied);
        }
        if image_size == 0 || image_size > MAX_IMAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Entry point must be non-zero, above the real-mode region, and
        // page-aligned. Containment within an executable segment is
        // verified in `finalise` once segments are known.
        if entry_point < MIN_ENTRY_ADDR || entry_point % SEGMENT_ALIGN != 0 {
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
    ///
    /// `phys_addr` is an attacker-controlled physical write target, so
    /// every field is bound-checked before the segment is accepted:
    /// the size must be non-zero and within [`MAX_SEGMENT_SIZE`], the
    /// file size must not exceed the memory size, the address must be
    /// page-aligned, the `[phys_addr, phys_addr + mem_size)` range must
    /// not overflow, and the range must not overlap any already-accepted
    /// segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any bound check fails,
    /// [`Error::OutOfMemory`] if the segment table is full, or
    /// [`Error::AlreadyExists`] if the range overlaps an existing
    /// segment.
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
        // Size bounds: non-zero, within the per-segment cap, and the file
        // size must fit inside the memory size (BSS may extend it).
        if size == 0 || size > MAX_SEGMENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        if mem_size > MAX_SEGMENT_SIZE || size > mem_size {
            return Err(Error::InvalidArgument);
        }
        // Physical destination must be page-aligned.
        if phys_addr % SEGMENT_ALIGN != 0 {
            return Err(Error::InvalidArgument);
        }
        // The destination range must not overflow the address space.
        let mem_size_u64 = mem_size as u64;
        let end = phys_addr
            .checked_add(mem_size_u64)
            .ok_or(Error::InvalidArgument)?;
        // Reject overlap with any already-accepted segment in this image.
        let count = self.images[slot].segment_count;
        for existing in self.images[slot].segments.iter().take(count) {
            if !existing.active {
                continue;
            }
            let e_end = existing.phys_addr.saturating_add(existing.mem_size as u64);
            if phys_addr < e_end && existing.phys_addr < end {
                return Err(Error::AlreadyExists);
            }
        }

        let idx = count;
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
    ///
    /// An image is only promoted to [`ImageState::Ready`] if it has at
    /// least one segment, its entry point is contained in an accepted
    /// segment, and — when lockdown is engaged — its signature verified.
    ///
    // SECURITY: real ELF parsing and signature verification (constant
    // time, against the platform keyring) MUST be implemented before
    // kexec is enabled. No verifier exists yet, so `sig_verified` is
    // always false and, under lockdown, finalise fails closed: an
    // unverified image is marked `Invalid`, never `Ready`. The real
    // verification state is recorded rather than assumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the image has no segments
    /// or the entry point is not contained in an accepted segment, or
    /// [`Error::PermissionDenied`] if lockdown is engaged and the image
    /// signature did not verify.
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

        // Entry point must fall within an accepted segment's range.
        let entry = self.images[slot].entry_point;
        let count = self.images[slot].segment_count;
        let entry_ok = self.images[slot].segments.iter().take(count).any(|s| {
            if !s.active {
                return false;
            }
            let s_end = s.phys_addr.saturating_add(s.mem_size as u64);
            entry >= s.phys_addr && entry < s_end
        });
        if !entry_ok {
            self.images[slot].state = ImageState::Invalid;
            self.stats.total_failures += 1;
            return Err(Error::InvalidArgument);
        }

        // No real verifier exists yet, so the image cannot be trusted.
        // Record the true verification state (false) explicitly.
        self.images[slot].sig_verified = false;

        // Fail closed: under lockdown an unverified image must never
        // become ready.
        if self.lockdown && !self.images[slot].sig_verified {
            self.images[slot].state = ImageState::Invalid;
            self.stats.total_failures += 1;
            return Err(Error::PermissionDenied);
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
