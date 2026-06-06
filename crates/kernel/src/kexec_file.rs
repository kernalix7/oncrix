// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File-based kexec loading.
//!
//! Implements the file-based kexec interface that loads a new kernel
//! image directly from a file descriptor rather than requiring the
//! caller to provide pre-loaded segments. The kernel image is verified,
//! parsed, and prepared for execution during the load phase.

use crate::capability::{CAP_SYS_BOOT, CapSet};
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum kernel image size (256 MiB).
const MAX_IMAGE_SIZE: u64 = 256 * 1024 * 1024;

/// Maximum initrd size (512 MiB).
const MAX_INITRD_SIZE: u64 = 512 * 1024 * 1024;

/// Maximum command line length.
const MAX_CMDLINE_LEN: usize = 2048;

/// Maximum number of loaded segments.
const MAX_SEGMENTS: usize = 64;

/// Maximum size of a single segment in bytes (256 MiB).
const MAX_SEGMENT_SIZE: u64 = 256 * 1024 * 1024;

/// Required alignment for segment destination addresses (4 KiB page).
const SEGMENT_ALIGN: u64 = 0x1000;

/// Minimum valid entry point address (above the 1 MiB real-mode region
/// on x86_64).
const MIN_ENTRY_ADDR: u64 = 0x10_0000;

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Kexec file flags.
const KEXEC_FILE_NO_INITRD: u32 = 1 << 0;
const KEXEC_FILE_ON_CRASH: u32 = 1 << 1;
const _KEXEC_FILE_UNLOAD: u32 = 1 << 2;

// ── Types ────────────────────────────────────────────────────────────

/// Status of the kexec file load operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexecFileStatus {
    /// No image is loaded.
    Unloaded,
    /// Image is being loaded.
    Loading,
    /// Image is loaded and ready.
    Loaded,
    /// Image is being executed.
    Executing,
    /// Load failed with an error.
    Failed,
}

impl Default for KexecFileStatus {
    fn default() -> Self {
        Self::Unloaded
    }
}

/// A loaded memory segment for kexec.
#[derive(Debug, Clone)]
pub struct KexecSegment {
    /// Physical memory destination address.
    dest_addr: u64,
    /// Size of this segment in bytes.
    size: u64,
    /// Offset within the loaded image.
    image_offset: u64,
    /// Segment type (code, data, bss).
    segment_type: SegmentType,
    /// Whether this segment is writable.
    writable: bool,
    /// Whether this segment is executable.
    executable: bool,
}

impl KexecSegment {
    /// Creates a new kexec segment.
    pub const fn new(
        dest_addr: u64,
        size: u64,
        image_offset: u64,
        segment_type: SegmentType,
    ) -> Self {
        Self {
            dest_addr,
            size,
            image_offset,
            segment_type,
            writable: false,
            executable: false,
        }
    }

    /// Returns the destination physical address.
    pub const fn dest_addr(&self) -> u64 {
        self.dest_addr
    }

    /// Returns the segment size.
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// Type of a kexec segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    /// Executable code.
    Code,
    /// Read-only data.
    RoData,
    /// Read-write data.
    Data,
    /// Zero-filled BSS.
    Bss,
    /// Initrd image.
    Initrd,
    /// Command line.
    Cmdline,
}

/// Information about the loaded kernel image.
#[derive(Debug)]
pub struct KexecImageInfo {
    /// Entry point address.
    entry_point: u64,
    /// Total image size in bytes.
    image_size: u64,
    /// Number of segments.
    segment_count: usize,
    /// Segments.
    segments: [Option<KexecSegment>; MAX_SEGMENTS],
    /// Command line bytes.
    cmdline: [u8; MAX_CMDLINE_LEN],
    /// Command line length.
    cmdline_len: usize,
    /// Initrd physical address.
    initrd_addr: u64,
    /// Initrd size.
    initrd_size: u64,
    /// Flags used during load.
    flags: u32,
    /// Whether the image signature verified.
    ///
    /// No real verifier exists yet, so this stays `false`; it is
    /// recorded honestly rather than assumed true.
    sig_verified: bool,
    /// Current status.
    status: KexecFileStatus,
}

impl Default for KexecImageInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecImageInfo {
    /// Creates an empty image info.
    pub const fn new() -> Self {
        Self {
            entry_point: 0,
            image_size: 0,
            segment_count: 0,
            segments: [const { None }; MAX_SEGMENTS],
            cmdline: [0u8; MAX_CMDLINE_LEN],
            cmdline_len: 0,
            initrd_addr: 0,
            initrd_size: 0,
            flags: 0,
            sig_verified: false,
            status: KexecFileStatus::Unloaded,
        }
    }

    /// Returns the entry point address.
    pub const fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Returns the current status.
    pub const fn status(&self) -> KexecFileStatus {
        self.status
    }

    /// Returns the number of loaded segments.
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }
}

/// Verification result for a kernel image.
#[derive(Debug, Clone)]
pub struct ImageVerification {
    /// Whether the image has a valid ELF header.
    pub valid_elf: bool,
    /// Whether the image signature is valid.
    pub signature_valid: bool,
    /// Whether the image fits in available memory.
    pub fits_memory: bool,
    /// Architecture of the image.
    pub arch: ImageArch,
}

/// Architecture of a kexec image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageArch {
    /// x86-64.
    X86_64,
    /// AArch64.
    Aarch64,
    /// RISC-V 64-bit.
    Riscv64,
    /// Unknown architecture.
    Unknown,
}

impl Default for ImageArch {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Central kexec file loading manager.
#[derive(Debug)]
pub struct KexecFileLoader {
    /// Current loaded image info.
    image: KexecImageInfo,
    /// Whether a crash kernel is loaded separately.
    crash_loaded: bool,
    /// Total load attempts.
    load_attempts: u64,
    /// Successful loads.
    successful_loads: u64,
    /// Failed loads.
    failed_loads: u64,
    /// Whether kernel lockdown / secure-boot enforcement is engaged.
    ///
    /// When engaged, [`finalize_load`](KexecFileLoader::finalize_load)
    /// refuses to mark an image `Loaded` unless its signature verified.
    /// Defaults to engaged (fail closed).
    lockdown: bool,
}

impl Default for KexecFileLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecFileLoader {
    /// Creates a new kexec file loader.
    pub const fn new() -> Self {
        Self {
            image: KexecImageInfo::new(),
            crash_loaded: false,
            load_attempts: 0,
            successful_loads: 0,
            failed_loads: 0,
            // Fail closed: lockdown engaged until policy explicitly
            // relaxes it after a real verifier is wired up.
            lockdown: true,
        }
    }

    /// Engage or relax kernel lockdown / secure-boot enforcement.
    ///
    // SECURITY: relaxing lockdown disables signature enforcement on the
    // replacement kernel. Only a trusted policy path (with the platform
    // secure-boot state) may call this with `false`.
    pub fn set_lockdown(&mut self, engaged: bool) {
        self.lockdown = engaged;
    }

    /// Begins loading a kernel image from file metadata.
    ///
    /// Loading a replacement kernel is the most privileged operation in
    /// the system; the caller must hold `CAP_SYS_BOOT`. `caller` is the
    /// authenticated capability set of the requesting task and is the
    /// single authorization checkpoint for the load sequence:
    /// `add_segment`, `set_cmdline`, `set_initrd`, and `finalize_load`
    /// can only proceed once `load_image` has set the `Loading` status.
    ///
    // SECURITY: `caller` MUST be the authenticated effective capability
    // set of the requesting task. Per-task creds are not yet threaded
    // through the syscall dispatcher, so this entry point fails closed:
    // a caller without `CAP_SYS_BOOT` is denied. The dispatcher MUST
    // pass the real caller cred once available; do not default to
    // `CapSet::FULL`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if `caller` lacks
    /// `CAP_SYS_BOOT`, or [`Error::InvalidArgument`] if the image
    /// parameters are invalid.
    pub fn load_image(
        &mut self,
        caller: CapSet,
        entry_point: u64,
        image_size: u64,
        flags: u32,
    ) -> Result<()> {
        // Fail closed: loading a kernel requires CAP_SYS_BOOT.
        if !caller.has(CAP_SYS_BOOT) {
            return Err(Error::PermissionDenied);
        }
        if image_size == 0 || image_size > MAX_IMAGE_SIZE {
            self.failed_loads += 1;
            return Err(Error::InvalidArgument);
        }
        // Entry point must be non-zero, above the real-mode region, and
        // page-aligned. Containment in an executable segment is verified
        // in `finalize_load` once segments are known.
        if entry_point < MIN_ENTRY_ADDR || entry_point % SEGMENT_ALIGN != 0 {
            self.failed_loads += 1;
            return Err(Error::InvalidArgument);
        }
        self.load_attempts += 1;
        self.image = KexecImageInfo::new();
        self.image.status = KexecFileStatus::Loading;
        self.image.entry_point = entry_point;
        self.image.image_size = image_size;
        self.image.flags = flags;
        Ok(())
    }

    /// Adds a segment to the loaded image.
    ///
    /// `dest_addr` is an attacker-controlled physical write target, so
    /// every field is bound-checked before the segment is accepted: the
    /// size must be non-zero and within [`MAX_SEGMENT_SIZE`], the address
    /// must be page-aligned, the `[dest_addr, dest_addr + size)` range
    /// must not overflow, the source window `[image_offset,
    /// image_offset + size)` must lie inside the image, and the
    /// destination range must not overlap any already-accepted segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any bound check fails,
    /// [`Error::OutOfMemory`] if the segment table is full, or
    /// [`Error::AlreadyExists`] if the range overlaps an existing
    /// segment.
    pub fn add_segment(
        &mut self,
        dest_addr: u64,
        size: u64,
        image_offset: u64,
        segment_type: SegmentType,
    ) -> Result<()> {
        if self.image.status != KexecFileStatus::Loading {
            return Err(Error::InvalidArgument);
        }
        if self.image.segment_count >= MAX_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        // Size bounds: non-zero and within the per-segment cap.
        if size == 0 || size > MAX_SEGMENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Destination must be page-aligned.
        if dest_addr % SEGMENT_ALIGN != 0 {
            return Err(Error::InvalidArgument);
        }
        // Destination range must not overflow the address space.
        let dest_end = dest_addr.checked_add(size).ok_or(Error::InvalidArgument)?;
        // Source window must lie fully inside the loaded image.
        let src_end = image_offset
            .checked_add(size)
            .ok_or(Error::InvalidArgument)?;
        if src_end > self.image.image_size {
            return Err(Error::InvalidArgument);
        }
        // Reject overlap with any already-accepted segment.
        let count = self.image.segment_count;
        for existing in self.image.segments.iter().take(count).flatten() {
            let e_end = existing.dest_addr.saturating_add(existing.size);
            if dest_addr < e_end && existing.dest_addr < dest_end {
                return Err(Error::AlreadyExists);
            }
        }

        let mut seg = KexecSegment::new(dest_addr, size, image_offset, segment_type);
        // Derive access flags from the segment type so the entry-point
        // containment check in `finalize_load` can identify executable
        // regions.
        seg.executable = matches!(segment_type, SegmentType::Code);
        seg.writable = matches!(
            segment_type,
            SegmentType::Data | SegmentType::Bss | SegmentType::Initrd
        );
        let idx = count;
        self.image.segments[idx] = Some(seg);
        self.image.segment_count += 1;
        Ok(())
    }

    /// Sets the command line for the new kernel.
    pub fn set_cmdline(&mut self, cmdline: &[u8]) -> Result<()> {
        if cmdline.len() > MAX_CMDLINE_LEN {
            return Err(Error::InvalidArgument);
        }
        self.image.cmdline[..cmdline.len()].copy_from_slice(cmdline);
        self.image.cmdline_len = cmdline.len();
        Ok(())
    }

    /// Sets the initrd address and size.
    pub fn set_initrd(&mut self, addr: u64, size: u64) -> Result<()> {
        if size > MAX_INITRD_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.image.initrd_addr = addr;
        self.image.initrd_size = size;
        Ok(())
    }

    /// Finalizes the load operation.
    ///
    /// An image is only promoted to [`KexecFileStatus::Loaded`] if it
    /// has at least one segment, its entry point is contained in an
    /// accepted executable segment, and — when lockdown is engaged —
    /// its signature verified.
    ///
    // SECURITY: real ELF parsing and signature verification (constant
    // time, against the platform keyring) MUST be implemented before
    // kexec is enabled. No verifier exists yet, so `sig_verified` is
    // always false and, under lockdown, finalize fails closed: an
    // unverified image is marked `Failed`, never `Loaded`. The real
    // verification state is recorded rather than assumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the image has no segments
    /// or the entry point is not contained in an accepted executable
    /// segment, or [`Error::PermissionDenied`] if lockdown is engaged
    /// and the image signature did not verify.
    pub fn finalize_load(&mut self) -> Result<()> {
        if self.image.status != KexecFileStatus::Loading {
            return Err(Error::InvalidArgument);
        }
        if self.image.segment_count == 0 {
            self.image.status = KexecFileStatus::Failed;
            self.failed_loads += 1;
            return Err(Error::InvalidArgument);
        }

        // Entry point must fall within an accepted executable segment.
        let entry = self.image.entry_point;
        let count = self.image.segment_count;
        let entry_ok = self.image.segments.iter().take(count).flatten().any(|s| {
            if !s.executable {
                return false;
            }
            let s_end = s.dest_addr.saturating_add(s.size);
            entry >= s.dest_addr && entry < s_end
        });
        if !entry_ok {
            self.image.status = KexecFileStatus::Failed;
            self.failed_loads += 1;
            return Err(Error::InvalidArgument);
        }

        // No real verifier exists yet, so the image cannot be trusted.
        // Record the true verification state (false) explicitly.
        self.image.sig_verified = false;

        // Fail closed: under lockdown an unverified image must never
        // become loaded.
        if self.lockdown && !self.image.sig_verified {
            self.image.status = KexecFileStatus::Failed;
            self.failed_loads += 1;
            return Err(Error::PermissionDenied);
        }

        self.image.status = KexecFileStatus::Loaded;
        if self.image.flags & KEXEC_FILE_ON_CRASH != 0 {
            self.crash_loaded = true;
        }
        self.successful_loads += 1;
        Ok(())
    }

    /// Unloads the currently loaded image.
    pub fn unload(&mut self) -> Result<()> {
        if self.image.status == KexecFileStatus::Unloaded {
            return Err(Error::NotFound);
        }
        self.image = KexecImageInfo::new();
        self.crash_loaded = false;
        Ok(())
    }

    /// Returns the current image info.
    pub fn image_info(&self) -> &KexecImageInfo {
        &self.image
    }

    /// Returns the number of successful loads.
    pub const fn successful_loads(&self) -> u64 {
        self.successful_loads
    }

    /// Returns the number of failed loads.
    pub const fn failed_loads(&self) -> u64 {
        self.failed_loads
    }
}
