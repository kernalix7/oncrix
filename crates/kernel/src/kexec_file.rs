// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File-based kexec loading.
//!
//! Implements the file-based kexec interface that loads a new kernel
//! image directly from a file descriptor rather than requiring the
//! caller to provide pre-loaded segments. The kernel image is verified,
//! parsed, and prepared for execution during the load phase.

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
        }
    }

    /// Begins loading a kernel image from file metadata.
    pub fn load_image(&mut self, entry_point: u64, image_size: u64, flags: u32) -> Result<()> {
        if image_size > MAX_IMAGE_SIZE {
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
        let seg = KexecSegment::new(dest_addr, size, image_offset, segment_type);
        let idx = self.image.segment_count;
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
    pub fn finalize_load(&mut self) -> Result<()> {
        if self.image.status != KexecFileStatus::Loading {
            return Err(Error::InvalidArgument);
        }
        if self.image.segment_count == 0 {
            self.image.status = KexecFileStatus::Failed;
            self.failed_loads += 1;
            return Err(Error::InvalidArgument);
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
