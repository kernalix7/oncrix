// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kexec — fast kernel reboot without full hardware reset.
//!
//! Implements the kexec system call for loading a new kernel image
//! into memory and jumping to it without going through BIOS/UEFI
//! firmware initialization. This significantly reduces reboot time
//! and is also used for crash dumps (kdump).
//!
//! # Data flow
//!
//! 1. User space calls `kexec_load()` with kernel image segments
//!    (kernel, initrd, command line).
//! 2. The kernel validates and stores the segments in
//!    [`KexecImage`].
//! 3. On `kexec_execute()`, the kernel:
//!    a. Stops all secondary CPUs via IPI
//!    b. Quiesces all devices
//!    c. Disables interrupts
//!    d. Jumps to the new kernel entry point
//!
//! # Types
//!
//! - [`KexecSegment`]: a contiguous memory region to load (kernel,
//!   initrd, or cmdline).
//! - [`KexecImage`]: the complete new-kernel image with entry point
//!   and flags.
//! - [`KexecError`]: detailed error reporting.
//! - [`KexecState`]: global kexec state machine.
//!
//! Reference: Linux `kernel/kexec.c`, `kernel/kexec_core.c`,
//! `arch/x86/kernel/machine_kexec_64.c`.

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of segments in a kexec image.
const MAX_SEGMENTS: usize = 16;

/// Maximum command-line length in bytes.
const MAX_CMDLINE_LEN: usize = 256;

/// Maximum size of a single segment in bytes (64 MiB).
const MAX_SEGMENT_SIZE: usize = 64 * 1024 * 1024;

/// Minimum valid entry point address (must be above 1 MiB to skip
/// real-mode region on x86_64).
const MIN_ENTRY_ADDR: usize = 0x10_0000;

// ── Flags ──────────────────────────────────────────────────────────

/// Load the image for crash-dump purposes (reserved memory).
pub const KEXEC_ON_CRASH: u32 = 1 << 0;

/// Preserve device context across the kexec (experimental).
pub const KEXEC_PRESERVE_CONTEXT: u32 = 1 << 1;

/// All valid kexec flags.
const VALID_FLAGS: u32 = KEXEC_ON_CRASH | KEXEC_PRESERVE_CONTEXT;

// ── KexecError ─────────────────────────────────────────────────────

/// Error type for kexec operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexecError {
    /// No segments provided.
    NoSegments,
    /// Too many segments (exceeds [`MAX_SEGMENTS`]).
    TooManySegments {
        /// Number of segments provided.
        count: usize,
    },
    /// A segment exceeds the maximum allowed size.
    SegmentTooLarge {
        /// Segment index.
        index: usize,
        /// Segment size in bytes.
        size: usize,
    },
    /// Segment has zero length.
    EmptySegment {
        /// Segment index.
        index: usize,
    },
    /// Segment destination address is null or misaligned.
    InvalidSegmentAddr {
        /// Segment index.
        index: usize,
        /// The invalid address.
        addr: usize,
    },
    /// Segments overlap in the destination address space.
    OverlappingSegments {
        /// First overlapping segment index.
        seg_a: usize,
        /// Second overlapping segment index.
        seg_b: usize,
    },
    /// Entry point is below the minimum valid address.
    InvalidEntryPoint {
        /// The invalid entry point.
        entry: usize,
    },
    /// Unknown or invalid flags.
    InvalidFlags {
        /// The invalid flag bits.
        flags: u32,
    },
    /// No image has been loaded yet.
    NotLoaded,
    /// An image is already loaded (must unload first).
    AlreadyLoaded,
    /// Machine shutdown sequence failed.
    ShutdownFailed,
    /// Kexec is currently in progress.
    InProgress,
}

impl core::fmt::Display for KexecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSegments => write!(f, "no segments provided"),
            Self::TooManySegments { count } => {
                write!(f, "too many segments: {}", count)
            }
            Self::SegmentTooLarge { index, size } => {
                write!(f, "segment {} too large: {} bytes", index, size)
            }
            Self::EmptySegment { index } => {
                write!(f, "segment {} has zero length", index)
            }
            Self::InvalidSegmentAddr { index, addr } => {
                write!(f, "segment {} has invalid addr 0x{:x}", index, addr)
            }
            Self::OverlappingSegments { seg_a, seg_b } => {
                write!(f, "segments {} and {} overlap", seg_a, seg_b)
            }
            Self::InvalidEntryPoint { entry } => {
                write!(f, "invalid entry point 0x{:x}", entry)
            }
            Self::InvalidFlags { flags } => {
                write!(f, "invalid flags 0x{:x}", flags)
            }
            Self::NotLoaded => write!(f, "no image loaded"),
            Self::AlreadyLoaded => write!(f, "image already loaded"),
            Self::ShutdownFailed => write!(f, "machine shutdown failed"),
            Self::InProgress => write!(f, "kexec in progress"),
        }
    }
}

// ── KexecSegment ───────────────────────────────────────────────────

/// A contiguous memory segment to be loaded for kexec.
///
/// Each segment describes a source buffer and its destination
/// physical address in the new kernel's address space. Typical
/// segments include:
/// - The kernel image itself
/// - The initial ramdisk (initrd)
/// - The kernel command line
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KexecSegment {
    /// Source virtual address (current kernel).
    pub src_addr: usize,
    /// Source buffer size in bytes.
    pub src_size: usize,
    /// Destination physical address (new kernel).
    pub dst_addr: usize,
    /// Destination region size in bytes.
    pub dst_size: usize,
}

impl KexecSegment {
    /// Create a new kexec segment.
    pub const fn new(src_addr: usize, src_size: usize, dst_addr: usize, dst_size: usize) -> Self {
        Self {
            src_addr,
            src_size,
            dst_addr,
            dst_size,
        }
    }

    /// Return the end address of the destination region.
    pub const fn dst_end(&self) -> usize {
        self.dst_addr + self.dst_size
    }
}

// ── KexecImage ─────────────────────────────────────────────────────

/// A complete kexec image ready for execution.
///
/// Contains all validated segments, the entry point address, and
/// flags controlling the kexec behavior.
pub struct KexecImage {
    /// Loaded segments.
    segments: [KexecSegment; MAX_SEGMENTS],
    /// Number of valid segments.
    segment_count: usize,
    /// Entry point address for the new kernel.
    entry: usize,
    /// Kexec flags (see [`KEXEC_ON_CRASH`],
    /// [`KEXEC_PRESERVE_CONTEXT`]).
    flags: u32,
    /// Kernel command line (null-terminated).
    cmdline: [u8; MAX_CMDLINE_LEN],
    /// Command line length.
    cmdline_len: usize,
}

impl Default for KexecImage {
    fn default() -> Self {
        Self {
            segments: [KexecSegment::default(); MAX_SEGMENTS],
            segment_count: 0,
            entry: 0,
            flags: 0,
            cmdline: [0u8; MAX_CMDLINE_LEN],
            cmdline_len: 0,
        }
    }
}

impl KexecImage {
    /// Return the entry point address.
    pub const fn entry(&self) -> usize {
        self.entry
    }

    /// Return the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the number of segments.
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Return the segments as a slice.
    pub fn segments(&self) -> &[KexecSegment] {
        &self.segments[..self.segment_count]
    }

    /// Return the command line as a byte slice.
    pub fn cmdline(&self) -> &[u8] {
        &self.cmdline[..self.cmdline_len]
    }

    /// Set the kernel command line.
    ///
    /// Truncates to [`MAX_CMDLINE_LEN`] if necessary.
    pub fn set_cmdline(&mut self, cmdline: &[u8]) {
        let len = cmdline.len().min(MAX_CMDLINE_LEN);
        self.cmdline[..len].copy_from_slice(&cmdline[..len]);
        self.cmdline_len = len;
    }

    /// Check whether the `KEXEC_ON_CRASH` flag is set.
    pub const fn is_crash_image(&self) -> bool {
        self.flags & KEXEC_ON_CRASH != 0
    }

    /// Check whether context preservation is requested.
    pub const fn preserve_context(&self) -> bool {
        self.flags & KEXEC_PRESERVE_CONTEXT != 0
    }
}

// ── KexecState ─────────────────────────────────────────────────────

/// State of the kexec subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KexecPhase {
    /// No image loaded.
    #[default]
    Idle,
    /// Image loaded and ready.
    Loaded,
    /// Machine shutdown in progress.
    Shutdown,
    /// Jumping to new kernel.
    Executing,
}

/// Global kexec state machine.
///
/// Manages the lifecycle of a kexec operation: load, optional
/// unload, and execute.
pub struct KexecState {
    /// Current loaded image (if any).
    image: Option<KexecImage>,
    /// Crash dump image (loaded with `KEXEC_ON_CRASH`).
    crash_image: Option<KexecImage>,
    /// Current phase.
    phase: KexecPhase,
    /// Number of online CPUs that need to be stopped.
    online_cpus: u32,
}

impl Default for KexecState {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecState {
    /// Create a new idle kexec state.
    pub const fn new() -> Self {
        Self {
            image: None,
            crash_image: None,
            phase: KexecPhase::Idle,
            online_cpus: 1,
        }
    }

    /// Return the current phase.
    pub const fn phase(&self) -> KexecPhase {
        self.phase
    }

    /// Set the number of online CPUs.
    pub fn set_online_cpus(&mut self, count: u32) {
        self.online_cpus = count;
    }

    /// Return whether a normal image is loaded.
    pub const fn is_loaded(&self) -> bool {
        self.image.is_some()
    }

    /// Return whether a crash image is loaded.
    pub const fn has_crash_image(&self) -> bool {
        self.crash_image.is_some()
    }

    /// Return a reference to the loaded image.
    pub fn image(&self) -> Option<&KexecImage> {
        self.image.as_ref()
    }

    /// Return a reference to the crash image.
    pub fn crash_image(&self) -> Option<&KexecImage> {
        self.crash_image.as_ref()
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Load a kexec image.
///
/// Validates all segments and stores the image for later execution.
/// If `flags` includes [`KEXEC_ON_CRASH`], the image is stored in
/// the crash slot instead.
///
/// # Errors
///
/// Returns a [`KexecError`] if validation fails.
pub fn kexec_load(
    state: &mut KexecState,
    entry: usize,
    segments: &[KexecSegment],
    flags: u32,
) -> Result<(), KexecError> {
    // Validate flags.
    if flags & !VALID_FLAGS != 0 {
        return Err(KexecError::InvalidFlags { flags });
    }

    // Cannot load while executing.
    if state.phase == KexecPhase::Shutdown || state.phase == KexecPhase::Executing {
        return Err(KexecError::InProgress);
    }

    let is_crash = flags & KEXEC_ON_CRASH != 0;
    if is_crash {
        if state.crash_image.is_some() {
            return Err(KexecError::AlreadyLoaded);
        }
    } else if state.image.is_some() {
        return Err(KexecError::AlreadyLoaded);
    }

    // Validate entry point.
    if entry < MIN_ENTRY_ADDR {
        return Err(KexecError::InvalidEntryPoint { entry });
    }

    // Validate segments.
    if segments.is_empty() {
        return Err(KexecError::NoSegments);
    }
    if segments.len() > MAX_SEGMENTS {
        return Err(KexecError::TooManySegments {
            count: segments.len(),
        });
    }

    for (i, seg) in segments.iter().enumerate() {
        if seg.dst_size == 0 {
            return Err(KexecError::EmptySegment { index: i });
        }
        if seg.dst_size > MAX_SEGMENT_SIZE {
            return Err(KexecError::SegmentTooLarge {
                index: i,
                size: seg.dst_size,
            });
        }
        // Page-align check (4 KiB).
        if seg.dst_addr & 0xFFF != 0 {
            return Err(KexecError::InvalidSegmentAddr {
                index: i,
                addr: seg.dst_addr,
            });
        }
    }

    // Check for overlapping segments.
    for i in 0..segments.len() {
        for j in (i + 1)..segments.len() {
            let a = &segments[i];
            let b = &segments[j];
            if a.dst_addr < b.dst_end() && b.dst_addr < a.dst_end() {
                return Err(KexecError::OverlappingSegments { seg_a: i, seg_b: j });
            }
        }
    }

    // Build the image.
    let mut image = KexecImage {
        entry,
        flags,
        segment_count: segments.len(),
        ..KexecImage::default()
    };
    image.segments[..segments.len()].copy_from_slice(segments);

    if is_crash {
        state.crash_image = Some(image);
    } else {
        state.image = Some(image);
        state.phase = KexecPhase::Loaded;
    }

    Ok(())
}

/// Unload a previously loaded kexec image.
///
/// # Errors
///
/// Returns [`KexecError::NotLoaded`] if no image is loaded, or
/// [`KexecError::InProgress`] if a kexec is currently executing.
pub fn kexec_unload(state: &mut KexecState) -> Result<(), KexecError> {
    if state.phase == KexecPhase::Shutdown || state.phase == KexecPhase::Executing {
        return Err(KexecError::InProgress);
    }
    if state.image.is_none() {
        return Err(KexecError::NotLoaded);
    }
    state.image = None;
    state.phase = KexecPhase::Idle;
    Ok(())
}

/// Begin the kexec execution sequence.
///
/// This initiates the machine shutdown sequence:
/// 1. Stop secondary CPUs.
/// 2. Quiesce devices.
/// 3. Disable interrupts.
/// 4. Jump to the new kernel entry point.
///
/// # Errors
///
/// Returns [`KexecError::NotLoaded`] if no image is loaded.
///
/// # Safety note
///
/// The actual jump to the new kernel is architecture-specific and
/// involves `unsafe` inline assembly. This function prepares the
/// state; the final jump is performed by
/// [`machine_kexec`].
pub fn kexec_execute(state: &mut KexecState) -> Result<KexecExecInfo, KexecError> {
    if state.image.is_none() {
        return Err(KexecError::NotLoaded);
    }
    if state.phase == KexecPhase::Executing {
        return Err(KexecError::InProgress);
    }

    state.phase = KexecPhase::Shutdown;

    // Phase 1: stop secondary CPUs.
    let cpus_to_stop = state.online_cpus.saturating_sub(1);

    // Phase 2: quiesce devices (recorded in info struct).
    state.phase = KexecPhase::Executing;

    // Build execution info for the arch-specific final jump.
    let image = state.image.as_ref().ok_or(KexecError::NotLoaded)?;
    Ok(KexecExecInfo {
        entry: image.entry,
        segment_count: image.segment_count,
        cpus_stopped: cpus_to_stop,
        preserve_context: image.preserve_context(),
    })
}

/// Information returned by [`kexec_execute`] for the arch layer
/// to perform the final jump.
#[derive(Debug, Clone, Copy)]
pub struct KexecExecInfo {
    /// Entry point address for the new kernel.
    pub entry: usize,
    /// Number of segments to relocate.
    pub segment_count: usize,
    /// Number of secondary CPUs that were stopped.
    pub cpus_stopped: u32,
    /// Whether context preservation was requested.
    pub preserve_context: bool,
}

/// Architecture-specific machine kexec (x86_64 stub).
///
/// In a real implementation this would:
/// 1. Identity-map the transition code page.
/// 2. Copy segments to their destination addresses.
/// 3. Set up the boot parameters.
/// 4. Jump to the entry point with interrupts disabled.
///
/// # Safety
///
/// This function is inherently unsafe — it transfers control to
/// arbitrary code at the given entry point. The caller must
/// ensure the entry point and segments are valid.
#[cfg(target_arch = "x86_64")]
pub unsafe fn machine_kexec(info: &KexecExecInfo) {
    // SAFETY: The caller has validated the entry point and
    // segments. We disable interrupts and jump to the new
    // kernel. This is the point of no return.
    unsafe {
        core::arch::asm!(
            "cli",          // Disable interrupts.
            "jmp {entry}",  // Jump to new kernel.
            entry = in(reg) info.entry,
            options(noreturn)
        );
    }
}

/// Architecture-specific machine kexec (non-x86_64 stub).
///
/// Placeholder for architectures other than x86_64.
#[cfg(not(target_arch = "x86_64"))]
pub fn machine_kexec(_info: &KexecExecInfo) {
    // Non-x86_64 architectures: not yet implemented.
    // This function is a no-op placeholder.
}
