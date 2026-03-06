// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `userfaultfd` — user-space page-fault handling.
//!
//! Implements the Linux `userfaultfd(2)` system call and its
//! associated ioctl operations. Userfaultfd allows user-space to
//! handle page faults for designated memory regions, enabling
//! techniques such as:
//!
//! - **Live migration**: fault in pages from a remote host on demand.
//! - **Postcopy migration**: start a VM, serve page faults from the
//!   source as they occur.
//! - **Garbage collection**: track and manage page access patterns.
//! - **Lazy allocation**: populate pages only when accessed.
//! - **Snapshotting**: implement copy-on-write semantics in user-space.
//!
//! # Syscall signature
//!
//! ```text
//! int userfaultfd(int flags);
//! ```
//!
//! # Ioctl operations
//!
//! After creating the file descriptor, the following ioctls configure
//! and control the userfaultfd:
//!
//! - `UFFDIO_API` — Handshake and feature negotiation.
//! - `UFFDIO_REGISTER` — Register a memory range for fault handling.
//! - `UFFDIO_UNREGISTER` — Unregister a memory range.
//! - `UFFDIO_COPY` — Resolve a fault by copying a page.
//! - `UFFDIO_ZEROPAGE` — Resolve a fault with a zero-filled page.
//! - `UFFDIO_WAKE` — Wake threads waiting on a fault.
//! - `UFFDIO_WRITEPROTECT` — Write-protect / unprotect a range.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page-offset mask (low 12 bits).
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// User-space address space limit (canonical lower-half on x86_64).
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Maximum number of registered regions per userfaultfd.
const UFFD_MAX_REGIONS: usize = 256;

/// Userfaultfd API version (matches Linux UFFD_API).
pub const UFFD_API: u64 = 0xAA;

/// Syscall number for `userfaultfd` (x86_64 Linux ABI).
pub const SYS_USERFAULTFD: u64 = 323;

// ---------------------------------------------------------------------------
// UffdFlags — creation flags
// ---------------------------------------------------------------------------

/// Flags for the `userfaultfd()` system call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UffdFlags(u32);

impl UffdFlags {
    /// Non-blocking mode (O_NONBLOCK).
    pub const O_NONBLOCK: u32 = 0x800;

    /// Close-on-exec (O_CLOEXEC).
    pub const O_CLOEXEC: u32 = 0x80000;

    /// User-mode only — do not require CAP_SYS_PTRACE for
    /// UFFD_USER_MODE_ONLY.
    pub const UFFD_USER_MODE_ONLY: u32 = 0x1;

    /// Mask of all valid flag bits.
    const VALID_MASK: u32 = Self::O_NONBLOCK | Self::O_CLOEXEC | Self::UFFD_USER_MODE_ONLY;

    /// Create from raw flags.
    ///
    /// Returns `InvalidArgument` if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check whether non-blocking mode is set.
    pub const fn is_nonblock(&self) -> bool {
        self.0 & Self::O_NONBLOCK != 0
    }

    /// Check whether close-on-exec is set.
    pub const fn is_cloexec(&self) -> bool {
        self.0 & Self::O_CLOEXEC != 0
    }

    /// Check whether user-mode-only is set.
    pub const fn is_user_mode_only(&self) -> bool {
        self.0 & Self::UFFD_USER_MODE_ONLY != 0
    }
}

// ---------------------------------------------------------------------------
// UffdFeatures — feature negotiation bitflags
// ---------------------------------------------------------------------------

/// Features negotiated during the `UFFDIO_API` handshake.
///
/// Both the kernel and user-space advertise their supported features.
/// The intersection becomes the active feature set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UffdFeatures(u64);

impl UffdFeatures {
    /// Page-fault events include write-protect flag.
    pub const PAGEFAULT_FLAG_WP: u64 = 1 << 0;

    /// Fork events are reported.
    pub const EVENT_FORK: u64 = 1 << 1;

    /// Remap events (mremap) are reported.
    pub const EVENT_REMAP: u64 = 1 << 2;

    /// Unmap events (munmap, madvise(DONTNEED)) are reported.
    pub const EVENT_REMOVE: u64 = 1 << 3;

    /// Minor faults on hugetlbfs are reported.
    pub const MINOR_HUGETLBFS: u64 = 1 << 4;

    /// Minor faults on shmem/tmpfs are reported.
    pub const MINOR_SHMEM: u64 = 1 << 5;

    /// UFFDIO_COPY/ZEROPAGE can specify exact address.
    pub const EXACT_ADDRESS: u64 = 1 << 6;

    /// Write-protect on hugetlbfs pages.
    pub const WP_HUGETLBFS: u64 = 1 << 7;

    /// Write-protect on shmem/tmpfs pages.
    pub const WP_SHMEM: u64 = 1 << 8;

    /// Write-protect for unpopulated PTEs.
    pub const WP_UNPOPULATED: u64 = 1 << 9;

    /// Poison pages (mark as hardware error).
    pub const POISON: u64 = 1 << 10;

    /// Continue (resolve fault without providing content).
    pub const WP_ASYNC: u64 = 1 << 11;

    /// Move pages between userfaultfd regions.
    pub const MOVE: u64 = 1 << 12;

    /// Mask of all recognised feature bits.
    const ALL_FEATURES: u64 = Self::PAGEFAULT_FLAG_WP
        | Self::EVENT_FORK
        | Self::EVENT_REMAP
        | Self::EVENT_REMOVE
        | Self::MINOR_HUGETLBFS
        | Self::MINOR_SHMEM
        | Self::EXACT_ADDRESS
        | Self::WP_HUGETLBFS
        | Self::WP_SHMEM
        | Self::WP_UNPOPULATED
        | Self::POISON
        | Self::WP_ASYNC
        | Self::MOVE;

    /// Default features supported by this implementation.
    pub const fn default_supported() -> Self {
        Self(
            Self::PAGEFAULT_FLAG_WP
                | Self::EVENT_FORK
                | Self::EVENT_REMAP
                | Self::EVENT_REMOVE
                | Self::MINOR_HUGETLBFS
                | Self::MINOR_SHMEM
                | Self::EXACT_ADDRESS
                | Self::WP_HUGETLBFS,
        )
    }

    /// Create from raw bits.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw & Self::ALL_FEATURES)
    }

    /// Return the raw bits.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Intersect with another feature set.
    pub const fn intersect(&self, other: &Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Check whether a specific feature is set.
    pub const fn has(&self, feature: u64) -> bool {
        self.0 & feature != 0
    }

    /// Return `true` if no features are enabled.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// UffdIoctl — ioctl command numbers
// ---------------------------------------------------------------------------

/// Ioctl commands for userfaultfd file descriptors.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UffdIoctl {
    /// Handshake and feature negotiation.
    Api = 0xC018_AA3F,
    /// Register a memory range.
    Register = 0xC020_AA00,
    /// Unregister a memory range.
    Unregister = 0x8010_AA01,
    /// Copy a page to resolve a fault.
    Copy = 0xC028_AA03,
    /// Resolve a fault with a zero-filled page.
    ZeroPage = 0xC020_AA04,
    /// Wake threads waiting on a fault.
    Wake = 0x8010_AA02,
    /// Write-protect / unprotect a range.
    WriteProtect = 0xC018_AA06,
    /// Continue (resolve minor faults without new content).
    Continue = 0xC018_AA07,
    /// Poison a range (mark as hardware error).
    Poison = 0xC018_AA08,
    /// Move pages between ranges.
    Move = 0xC028_AA09,
}

impl UffdIoctl {
    /// Convert a raw ioctl number to a `UffdIoctl` variant.
    pub fn from_raw(cmd: u64) -> Result<Self> {
        match cmd {
            0xC018_AA3F => Ok(Self::Api),
            0xC020_AA00 => Ok(Self::Register),
            0x8010_AA01 => Ok(Self::Unregister),
            0xC028_AA03 => Ok(Self::Copy),
            0xC020_AA04 => Ok(Self::ZeroPage),
            0x8010_AA02 => Ok(Self::Wake),
            0xC018_AA06 => Ok(Self::WriteProtect),
            0xC018_AA07 => Ok(Self::Continue),
            0xC018_AA08 => Ok(Self::Poison),
            0xC028_AA09 => Ok(Self::Move),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw ioctl number.
    pub const fn as_raw(&self) -> u64 {
        *self as u64
    }
}

// ---------------------------------------------------------------------------
// UffdRegisterMode — registration modes
// ---------------------------------------------------------------------------

/// Registration mode flags for `UFFDIO_REGISTER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UffdRegisterMode(u64);

impl UffdRegisterMode {
    /// Handle missing-page faults.
    pub const MISSING: u64 = 1 << 0;

    /// Handle write-protect faults.
    pub const WP: u64 = 1 << 1;

    /// Handle minor faults (e.g. shmem, hugetlbfs).
    pub const MINOR: u64 = 1 << 2;

    /// Mask of all valid mode bits.
    const VALID_MASK: u64 = Self::MISSING | Self::WP | Self::MINOR;

    /// Create from raw bits.
    pub fn from_raw(raw: u64) -> Result<Self> {
        if raw == 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bits.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Check whether missing-page mode is enabled.
    pub const fn is_missing(&self) -> bool {
        self.0 & Self::MISSING != 0
    }

    /// Check whether write-protect mode is enabled.
    pub const fn is_wp(&self) -> bool {
        self.0 & Self::WP != 0
    }

    /// Check whether minor-fault mode is enabled.
    pub const fn is_minor(&self) -> bool {
        self.0 & Self::MINOR != 0
    }
}

// ---------------------------------------------------------------------------
// UffdRange — address range for ioctl operations
// ---------------------------------------------------------------------------

/// An address range for userfaultfd ioctl operations.
///
/// Both `start` and `len` must be page-aligned. The range must lie
/// within user-space.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UffdRange {
    /// Start address (page-aligned).
    pub start: u64,
    /// Length in bytes (page-aligned, non-zero).
    pub len: u64,
}

impl UffdRange {
    /// Create a new range.
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    /// Validate the range.
    pub fn validate(&self) -> Result<()> {
        if self.start & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len == 0 || self.len & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let end = self
            .start
            .checked_add(self.len)
            .ok_or(Error::InvalidArgument)?;

        if end > USER_SPACE_END {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Return the end address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start + self.len
    }

    /// Return the number of pages in the range.
    pub const fn page_count(&self) -> u64 {
        self.len / PAGE_SIZE
    }

    /// Check whether this range overlaps with another.
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Check whether this range fully contains another.
    pub const fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end() <= self.end()
    }
}

// ---------------------------------------------------------------------------
// UffdRegistration — registered region
// ---------------------------------------------------------------------------

/// A registered userfaultfd region.
///
/// Created by a successful `UFFDIO_REGISTER` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UffdRegistration {
    /// Address range being monitored.
    pub range: UffdRange,
    /// Registration mode (which fault types to handle).
    pub mode: UffdRegisterMode,
    /// Ioctls available for this registration.
    pub ioctls: u64,
}

impl UffdRegistration {
    /// Create a new registration record.
    pub const fn new(range: UffdRange, mode: UffdRegisterMode, ioctls: u64) -> Self {
        Self {
            range,
            mode,
            ioctls,
        }
    }
}

// ---------------------------------------------------------------------------
// UffdConfig — per-fd configuration
// ---------------------------------------------------------------------------

/// Configuration for a userfaultfd file descriptor.
///
/// Created by `userfaultfd()` and populated during the `UFFDIO_API`
/// handshake.
#[derive(Debug, Clone)]
pub struct UffdConfig {
    /// Creation flags.
    pub flags: UffdFlags,
    /// Negotiated features.
    pub features: UffdFeatures,
    /// Whether the API handshake has been completed.
    pub api_done: bool,
    /// Registered regions.
    regions: [Option<UffdRegistration>; UFFD_MAX_REGIONS],
    /// Number of active registrations.
    region_count: usize,
}

impl UffdConfig {
    /// Create a new userfaultfd configuration.
    pub fn new(flags: UffdFlags) -> Self {
        Self {
            flags,
            features: UffdFeatures::default(),
            api_done: false,
            regions: [None; UFFD_MAX_REGIONS],
            region_count: 0,
        }
    }

    /// Perform the `UFFDIO_API` handshake.
    ///
    /// Negotiates the feature set between kernel and user-space.
    /// Must be called exactly once before any other ioctl.
    ///
    /// # Arguments
    ///
    /// - `api` — The API version requested by user-space (must
    ///   match `UFFD_API`).
    /// - `requested_features` — Features requested by user-space.
    ///
    /// # Returns
    ///
    /// The negotiated feature set (intersection of kernel and
    /// user-space features).
    pub fn do_api_handshake(&mut self, api: u64, requested_features: u64) -> Result<UffdFeatures> {
        if self.api_done {
            return Err(Error::Busy);
        }

        if api != UFFD_API {
            return Err(Error::InvalidArgument);
        }

        let supported = UffdFeatures::default_supported();
        let requested = UffdFeatures::from_raw(requested_features);
        let negotiated = supported.intersect(&requested);

        self.features = negotiated;
        self.api_done = true;

        Ok(negotiated)
    }

    /// Ensure the API handshake has been performed.
    fn require_api(&self) -> Result<()> {
        if !self.api_done {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Register a memory range for fault handling.
    ///
    /// # Arguments
    ///
    /// - `range` — The address range to register.
    /// - `mode` — Which fault types to handle.
    ///
    /// # Returns
    ///
    /// A [`UffdRegistration`] describing the registered region.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — API not done, bad range or mode.
    /// - `AlreadyExists` — The range overlaps an existing
    ///   registration.
    /// - `OutOfMemory` — Too many regions registered.
    pub fn do_register(
        &mut self,
        range: UffdRange,
        mode: UffdRegisterMode,
    ) -> Result<UffdRegistration> {
        self.require_api()?;
        range.validate()?;

        // Check for overlaps with existing registrations.
        for entry in &self.regions {
            if let Some(reg) = entry {
                if reg.range.overlaps(&range) {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        if self.region_count >= UFFD_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        // Compute available ioctls based on mode.
        let ioctls = self.compute_available_ioctls(&mode);

        let registration = UffdRegistration::new(range, mode, ioctls);

        // Find a free slot.
        for slot in &mut self.regions {
            if slot.is_none() {
                *slot = Some(registration);
                self.region_count += 1;
                return Ok(registration);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unregister a memory range.
    ///
    /// The range must exactly match a previously registered range.
    pub fn do_unregister(&mut self, range: &UffdRange) -> Result<()> {
        self.require_api()?;
        range.validate()?;

        for slot in &mut self.regions {
            if let Some(reg) = slot {
                if reg.range == *range {
                    *slot = None;
                    self.region_count -= 1;
                    return Ok(());
                }
            }
        }

        Err(Error::NotFound)
    }

    /// Return the number of active registrations.
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    /// Find the registration covering a given address.
    pub fn find_registration(&self, addr: u64) -> Option<&UffdRegistration> {
        for entry in &self.regions {
            if let Some(reg) = entry {
                if addr >= reg.range.start && addr < reg.range.end() {
                    return Some(reg);
                }
            }
        }
        None
    }

    /// Compute which ioctls are available for a given mode.
    fn compute_available_ioctls(&self, mode: &UffdRegisterMode) -> u64 {
        let mut ioctls: u64 = 0;

        // COPY and WAKE are always available.
        ioctls |= 1 << 0; // COPY
        ioctls |= 1 << 1; // WAKE

        if mode.is_missing() {
            ioctls |= 1 << 2; // ZEROPAGE
        }

        if mode.is_wp() {
            ioctls |= 1 << 3; // WRITEPROTECT
        }

        if mode.is_minor() {
            ioctls |= 1 << 4; // CONTINUE
        }

        ioctls
    }
}

impl Default for UffdConfig {
    fn default() -> Self {
        Self::new(UffdFlags::default())
    }
}

// ---------------------------------------------------------------------------
// UffdCopyArgs — UFFDIO_COPY arguments
// ---------------------------------------------------------------------------

/// Arguments for the `UFFDIO_COPY` ioctl.
///
/// Copies a page from a source address (in the calling process) to
/// the faulting address (in the registered range).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UffdCopyArgs {
    /// Destination address (in the registered range, page-aligned).
    pub dst: u64,
    /// Source address (in the calling process, page-aligned).
    pub src: u64,
    /// Number of bytes to copy (page-aligned).
    pub len: u64,
    /// Mode flags (0 or `UFFDIO_COPY_MODE_DONTWAKE`).
    pub mode: u64,
    /// Output: actual bytes copied.
    pub copy_bytes: i64,
}

/// Do not wake the faulting thread after copy.
pub const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1 << 0;

/// Write-protect the destination page after copy.
pub const UFFDIO_COPY_MODE_WP: u64 = 1 << 1;

/// Valid copy-mode mask.
const UFFDIO_COPY_MODE_VALID: u64 = UFFDIO_COPY_MODE_DONTWAKE | UFFDIO_COPY_MODE_WP;

impl UffdCopyArgs {
    /// Validate the copy arguments.
    pub fn validate(&self) -> Result<()> {
        if self.dst & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.src & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len == 0 || self.len & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.mode & !UFFDIO_COPY_MODE_VALID != 0 {
            return Err(Error::InvalidArgument);
        }

        // Overflow checks.
        self.dst
            .checked_add(self.len)
            .ok_or(Error::InvalidArgument)?;
        self.src
            .checked_add(self.len)
            .ok_or(Error::InvalidArgument)?;

        Ok(())
    }

    /// Check whether the wake-after-copy is suppressed.
    pub const fn is_dontwake(&self) -> bool {
        self.mode & UFFDIO_COPY_MODE_DONTWAKE != 0
    }

    /// Check whether write-protect after copy is requested.
    pub const fn is_wp(&self) -> bool {
        self.mode & UFFDIO_COPY_MODE_WP != 0
    }
}

// ---------------------------------------------------------------------------
// UffdZeropageArgs — UFFDIO_ZEROPAGE arguments
// ---------------------------------------------------------------------------

/// Arguments for the `UFFDIO_ZEROPAGE` ioctl.
///
/// Maps a zero-filled page at the faulting address.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UffdZeropageArgs {
    /// Address range to zero-fill.
    pub range: UffdRange,
    /// Mode flags (0 or `UFFDIO_ZEROPAGE_MODE_DONTWAKE`).
    pub mode: u64,
    /// Output: actual bytes zeroed.
    pub zeropage_bytes: i64,
}

/// Do not wake the faulting thread after zero-fill.
pub const UFFDIO_ZEROPAGE_MODE_DONTWAKE: u64 = 1 << 0;

impl UffdZeropageArgs {
    /// Validate the zeropage arguments.
    pub fn validate(&self) -> Result<()> {
        self.range.validate()?;
        if self.mode & !UFFDIO_ZEROPAGE_MODE_DONTWAKE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check whether wake-after-zeropage is suppressed.
    pub const fn is_dontwake(&self) -> bool {
        self.mode & UFFDIO_ZEROPAGE_MODE_DONTWAKE != 0
    }
}

// ---------------------------------------------------------------------------
// UffdWriteProtectArgs — UFFDIO_WRITEPROTECT arguments
// ---------------------------------------------------------------------------

/// Arguments for the `UFFDIO_WRITEPROTECT` ioctl.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UffdWriteProtectArgs {
    /// Address range to write-protect / unprotect.
    pub range: UffdRange,
    /// Mode flags.
    pub mode: u64,
}

/// Enable write protection on the range.
pub const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1 << 0;

/// Do not wake faulting threads after changing protection.
pub const UFFDIO_WRITEPROTECT_MODE_DONTWAKE: u64 = 1 << 1;

/// Valid write-protect mode mask.
const UFFDIO_WP_MODE_VALID: u64 = UFFDIO_WRITEPROTECT_MODE_WP | UFFDIO_WRITEPROTECT_MODE_DONTWAKE;

impl UffdWriteProtectArgs {
    /// Validate the write-protect arguments.
    pub fn validate(&self) -> Result<()> {
        self.range.validate()?;
        if self.mode & !UFFDIO_WP_MODE_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check whether write protection is being enabled.
    pub const fn is_wp(&self) -> bool {
        self.mode & UFFDIO_WRITEPROTECT_MODE_WP != 0
    }

    /// Check whether wake is suppressed.
    pub const fn is_dontwake(&self) -> bool {
        self.mode & UFFDIO_WRITEPROTECT_MODE_DONTWAKE != 0
    }
}

// ---------------------------------------------------------------------------
// UffdFaultEvent — page-fault notification
// ---------------------------------------------------------------------------

/// Type of page fault reported by userfaultfd.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UffdFaultType {
    /// Missing page (demand-paging).
    Missing = 0,
    /// Write-protect violation.
    WriteProtect = 1,
    /// Minor fault (page present but needs update).
    Minor = 2,
}

/// A page-fault event read from the userfaultfd file descriptor.
///
/// The kernel writes these events when a fault occurs in a registered
/// region. User-space reads them to determine which page to provide.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UffdFaultEvent {
    /// Type of fault.
    pub fault_type: UffdFaultType,
    /// Flags providing additional context.
    pub flags: u64,
    /// Faulting address (page-aligned).
    pub address: u64,
    /// Thread ID of the faulting thread.
    pub thread_id: u64,
}

impl UffdFaultEvent {
    /// Size of the event structure in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new fault event.
    pub const fn new(fault_type: UffdFaultType, flags: u64, address: u64, thread_id: u64) -> Self {
        Self {
            fault_type,
            flags,
            address,
            thread_id,
        }
    }

    /// Convenience: create a missing-page fault event.
    pub const fn missing(address: u64, tid: u64) -> Self {
        Self::new(UffdFaultType::Missing, 0, address, tid)
    }

    /// Convenience: create a write-protect fault event.
    pub const fn write_protect(address: u64, tid: u64) -> Self {
        Self::new(UffdFaultType::WriteProtect, 0, address, tid)
    }

    /// Convenience: create a minor fault event.
    pub const fn minor(address: u64, tid: u64) -> Self {
        Self::new(UffdFaultType::Minor, 0, address, tid)
    }
}

// ---------------------------------------------------------------------------
// UffdEventType — non-fault event types
// ---------------------------------------------------------------------------

/// Non-fault event types read from the userfaultfd fd.
///
/// In addition to page faults, userfaultfd can report lifecycle
/// events when the corresponding features are negotiated.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UffdEventType {
    /// The target process called `fork()`.
    Fork = 1,
    /// The target process called `mremap()`.
    Remap = 2,
    /// A registered region was unmapped or discarded.
    Remove = 3,
}

/// A non-fault event read from the userfaultfd fd.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UffdEvent {
    /// Event type.
    pub event_type: UffdEventType,
    /// Event-specific data (e.g. child uffd for fork, new range
    /// for remap, removed range for remove).
    pub arg1: u64,
    /// Second event-specific argument.
    pub arg2: u64,
    /// Third event-specific argument.
    pub arg3: u64,
}

impl UffdEvent {
    /// Create a fork event.
    ///
    /// `child_uffd` is the userfaultfd fd inherited by the child.
    pub const fn fork(child_uffd: u64) -> Self {
        Self {
            event_type: UffdEventType::Fork,
            arg1: child_uffd,
            arg2: 0,
            arg3: 0,
        }
    }

    /// Create a remap event.
    ///
    /// - `old_addr` — Previous start address.
    /// - `new_addr` — New start address after mremap.
    /// - `len` — Length of the remapped region.
    pub const fn remap(old_addr: u64, new_addr: u64, len: u64) -> Self {
        Self {
            event_type: UffdEventType::Remap,
            arg1: old_addr,
            arg2: new_addr,
            arg3: len,
        }
    }

    /// Create a remove event.
    ///
    /// - `start` — Start of the removed range.
    /// - `end` — End of the removed range (exclusive).
    pub const fn remove(start: u64, end: u64) -> Self {
        Self {
            event_type: UffdEventType::Remove,
            arg1: start,
            arg2: end,
            arg3: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// do_userfaultfd — create a new userfaultfd
// ---------------------------------------------------------------------------

/// Create a new userfaultfd configuration.
///
/// This is the kernel-side implementation of the `userfaultfd(2)`
/// syscall. In a real kernel, this would allocate an fd and return
/// it. Here, we return the `UffdConfig` struct.
///
/// # Arguments
///
/// - `flags` — Creation flags.
///
/// # Errors
///
/// - `InvalidArgument` — Unknown flags.
pub fn do_userfaultfd(flags: u32) -> Result<UffdConfig> {
    let parsed_flags = UffdFlags::from_raw(flags)?;
    Ok(UffdConfig::new(parsed_flags))
}

// ---------------------------------------------------------------------------
// do_uffdio_copy — resolve a fault by copying a page
// ---------------------------------------------------------------------------

/// Resolve a page fault by copying data from the caller's address
/// space to the faulting address.
///
/// # Arguments
///
/// - `config` — The userfaultfd configuration.
/// - `args` — Copy arguments (src, dst, len, mode).
///
/// # Returns
///
/// The number of bytes copied.
///
/// # Errors
///
/// - `InvalidArgument` — Bad arguments or destination not in a
///   registered region.
pub fn do_uffdio_copy(config: &UffdConfig, args: &UffdCopyArgs) -> Result<u64> {
    config.require_api()?;
    args.validate()?;

    // Destination must fall within a registered region.
    let reg = config
        .find_registration(args.dst)
        .ok_or(Error::InvalidArgument)?;

    // The destination range must be fully contained.
    let dst_range = UffdRange::new(args.dst, args.len);
    if !reg.range.contains(&dst_range) {
        return Err(Error::InvalidArgument);
    }

    // In a real kernel, this is where we would:
    // 1. Allocate page frames.
    // 2. Copy data from src to the new pages.
    // 3. Install PTEs mapping the new pages at dst.
    // 4. Optionally write-protect if COPY_MODE_WP.
    // 5. Optionally wake faulting threads unless DONTWAKE.

    Ok(args.len)
}

// ---------------------------------------------------------------------------
// do_uffdio_zeropage — resolve a fault with a zero page
// ---------------------------------------------------------------------------

/// Resolve a page fault by mapping zero-filled pages.
///
/// # Arguments
///
/// - `config` — The userfaultfd configuration.
/// - `args` — Zeropage arguments.
///
/// # Returns
///
/// The number of bytes zeroed.
pub fn do_uffdio_zeropage(config: &UffdConfig, args: &UffdZeropageArgs) -> Result<u64> {
    config.require_api()?;
    args.validate()?;

    let reg = config
        .find_registration(args.range.start)
        .ok_or(Error::InvalidArgument)?;

    if !reg.range.contains(&args.range) {
        return Err(Error::InvalidArgument);
    }

    // Registration must support missing-page mode for ZEROPAGE.
    if !reg.mode.is_missing() {
        return Err(Error::InvalidArgument);
    }

    // In a real kernel: allocate zero pages, install PTEs, wake.

    Ok(args.range.len)
}

// ---------------------------------------------------------------------------
// do_uffdio_writeprotect — change write protection
// ---------------------------------------------------------------------------

/// Change write protection on a registered range.
///
/// # Arguments
///
/// - `config` — The userfaultfd configuration.
/// - `args` — Write-protect arguments.
pub fn do_uffdio_writeprotect(config: &UffdConfig, args: &UffdWriteProtectArgs) -> Result<()> {
    config.require_api()?;
    args.validate()?;

    let reg = config
        .find_registration(args.range.start)
        .ok_or(Error::InvalidArgument)?;

    if !reg.range.contains(&args.range) {
        return Err(Error::InvalidArgument);
    }

    // Registration must support WP mode.
    if !reg.mode.is_wp() {
        return Err(Error::InvalidArgument);
    }

    // In a real kernel: update PTEs to set/clear write-protect,
    // flush TLB, optionally wake faulting threads.

    Ok(())
}

// ---------------------------------------------------------------------------
// do_uffdio_wake — wake faulting threads
// ---------------------------------------------------------------------------

/// Wake threads waiting on faults in a range.
///
/// # Arguments
///
/// - `config` — The userfaultfd configuration.
/// - `range` — The range to wake.
pub fn do_uffdio_wake(config: &UffdConfig, range: &UffdRange) -> Result<()> {
    config.require_api()?;
    range.validate()?;

    // In a real kernel: walk the wait queue and wake threads whose
    // fault address falls within the range.

    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process a `userfaultfd` syscall from raw register arguments.
///
/// # Arguments
///
/// - `flags` — Raw flags value from the syscall register.
///
/// # Returns
///
/// A new `UffdConfig` on success.
pub fn sys_userfaultfd(flags: u64) -> Result<UffdConfig> {
    let flags_u32 = u32::try_from(flags).map_err(|_| Error::InvalidArgument)?;
    do_userfaultfd(flags_u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uffd_flags_from_raw() {
        assert!(UffdFlags::from_raw(0).is_ok());
        assert!(UffdFlags::from_raw(UffdFlags::O_NONBLOCK).is_ok());
        assert!(UffdFlags::from_raw(UffdFlags::O_CLOEXEC).is_ok());
        assert!(UffdFlags::from_raw(UffdFlags::O_NONBLOCK | UffdFlags::O_CLOEXEC).is_ok());
        assert_eq!(
            UffdFlags::from_raw(0x1_0000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_uffd_features() {
        let f = UffdFeatures::default_supported();
        assert!(f.has(UffdFeatures::PAGEFAULT_FLAG_WP));
        assert!(f.has(UffdFeatures::EVENT_FORK));
        assert!(!f.has(UffdFeatures::MOVE));
    }

    #[test]
    fn test_uffd_features_intersect() {
        let kernel = UffdFeatures::default_supported();
        let user = UffdFeatures::from_raw(UffdFeatures::PAGEFAULT_FLAG_WP | UffdFeatures::MOVE);
        let negotiated = kernel.intersect(&user);
        assert!(negotiated.has(UffdFeatures::PAGEFAULT_FLAG_WP));
        assert!(!negotiated.has(UffdFeatures::MOVE));
    }

    #[test]
    fn test_uffd_ioctl_from_raw() {
        assert_eq!(UffdIoctl::from_raw(0xC018_AA3F).unwrap(), UffdIoctl::Api);
        assert_eq!(
            UffdIoctl::from_raw(0xC020_AA00).unwrap(),
            UffdIoctl::Register
        );
        assert_eq!(
            UffdIoctl::from_raw(0xDEAD).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_uffd_range_validate() {
        let r = UffdRange::new(0x1000, 0x2000);
        assert!(r.validate().is_ok());
        assert_eq!(r.page_count(), 2);

        // Unaligned start.
        assert_eq!(
            UffdRange::new(0x1001, 0x1000).validate().unwrap_err(),
            Error::InvalidArgument
        );

        // Zero length.
        assert_eq!(
            UffdRange::new(0x1000, 0).validate().unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_uffd_range_overlaps() {
        let r1 = UffdRange::new(0x1000, 0x2000);
        let r2 = UffdRange::new(0x2000, 0x2000);
        let r3 = UffdRange::new(0x5000, 0x1000);

        assert!(r1.overlaps(&r2));
        assert!(r2.overlaps(&r1));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn test_uffd_range_contains() {
        let outer = UffdRange::new(0x1000, 0x4000);
        let inner = UffdRange::new(0x2000, 0x1000);
        let partial = UffdRange::new(0x4000, 0x2000);

        assert!(outer.contains(&inner));
        assert!(!outer.contains(&partial));
    }

    #[test]
    fn test_create_userfaultfd() {
        let config = do_userfaultfd(0).unwrap();
        assert!(!config.api_done);
        assert_eq!(config.region_count(), 0);
    }

    #[test]
    fn test_api_handshake() {
        let mut config = do_userfaultfd(0).unwrap();

        let features = config
            .do_api_handshake(
                UFFD_API,
                UffdFeatures::PAGEFAULT_FLAG_WP | UffdFeatures::EVENT_FORK,
            )
            .unwrap();

        assert!(features.has(UffdFeatures::PAGEFAULT_FLAG_WP));
        assert!(features.has(UffdFeatures::EVENT_FORK));
        assert!(config.api_done);

        // Double handshake should fail.
        assert_eq!(
            config.do_api_handshake(UFFD_API, 0).unwrap_err(),
            Error::Busy
        );
    }

    #[test]
    fn test_api_handshake_bad_version() {
        let mut config = do_userfaultfd(0).unwrap();
        assert_eq!(
            config.do_api_handshake(0xFF, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_register_unregister() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x1000, 0x4000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();

        let reg = config.do_register(range, mode).unwrap();
        assert_eq!(reg.range, range);
        assert_eq!(config.region_count(), 1);

        // Overlapping registration should fail.
        let overlap = UffdRange::new(0x2000, 0x1000);
        assert_eq!(
            config.do_register(overlap, mode).unwrap_err(),
            Error::AlreadyExists
        );

        // Unregister.
        config.do_unregister(&range).unwrap();
        assert_eq!(config.region_count(), 0);
    }

    #[test]
    fn test_register_before_api() {
        let mut config = do_userfaultfd(0).unwrap();
        let range = UffdRange::new(0x1000, 0x1000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();

        assert_eq!(
            config.do_register(range, mode).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_find_registration() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x10000, 0x10000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();
        config.do_register(range, mode).unwrap();

        assert!(config.find_registration(0x10000).is_some());
        assert!(config.find_registration(0x18000).is_some());
        assert!(config.find_registration(0x20000).is_none());
        assert!(config.find_registration(0x5000).is_none());
    }

    #[test]
    fn test_uffdio_copy() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x10000, 0x10000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();
        config.do_register(range, mode).unwrap();

        let args = UffdCopyArgs {
            dst: 0x10000,
            src: 0x20000,
            len: 0x1000,
            mode: 0,
            copy_bytes: 0,
        };

        let copied = do_uffdio_copy(&config, &args).unwrap();
        assert_eq!(copied, 0x1000);
    }

    #[test]
    fn test_uffdio_copy_out_of_range() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x10000, 0x1000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();
        config.do_register(range, mode).unwrap();

        // Copy too big.
        let args = UffdCopyArgs {
            dst: 0x10000,
            src: 0x20000,
            len: 0x2000,
            mode: 0,
            copy_bytes: 0,
        };

        assert_eq!(
            do_uffdio_copy(&config, &args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_uffdio_zeropage() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x10000, 0x10000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();
        config.do_register(range, mode).unwrap();

        let args = UffdZeropageArgs {
            range: UffdRange::new(0x10000, 0x1000),
            mode: 0,
            zeropage_bytes: 0,
        };

        let zeroed = do_uffdio_zeropage(&config, &args).unwrap();
        assert_eq!(zeroed, 0x1000);
    }

    #[test]
    fn test_uffdio_writeprotect() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x10000, 0x10000);
        let mode =
            UffdRegisterMode::from_raw(UffdRegisterMode::MISSING | UffdRegisterMode::WP).unwrap();
        config.do_register(range, mode).unwrap();

        let args = UffdWriteProtectArgs {
            range: UffdRange::new(0x10000, 0x1000),
            mode: UFFDIO_WRITEPROTECT_MODE_WP,
        };

        assert!(do_uffdio_writeprotect(&config, &args).is_ok());
    }

    #[test]
    fn test_uffdio_writeprotect_no_wp_mode() {
        let mut config = do_userfaultfd(0).unwrap();
        config
            .do_api_handshake(UFFD_API, 0xFFFF_FFFF_FFFF_FFFF)
            .unwrap();

        let range = UffdRange::new(0x10000, 0x10000);
        let mode = UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).unwrap();
        config.do_register(range, mode).unwrap();

        let args = UffdWriteProtectArgs {
            range: UffdRange::new(0x10000, 0x1000),
            mode: UFFDIO_WRITEPROTECT_MODE_WP,
        };

        assert_eq!(
            do_uffdio_writeprotect(&config, &args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_fault_event() {
        let ev = UffdFaultEvent::missing(0x1000, 42);
        assert_eq!(ev.fault_type, UffdFaultType::Missing);
        assert_eq!(ev.address, 0x1000);
        assert_eq!(ev.thread_id, 42);

        let ev = UffdFaultEvent::write_protect(0x2000, 99);
        assert_eq!(ev.fault_type, UffdFaultType::WriteProtect);
    }

    #[test]
    fn test_non_fault_events() {
        let fork_ev = UffdEvent::fork(5);
        assert_eq!(fork_ev.event_type, UffdEventType::Fork);
        assert_eq!(fork_ev.arg1, 5);

        let remap_ev = UffdEvent::remap(0x1000, 0x2000, 0x3000);
        assert_eq!(remap_ev.event_type, UffdEventType::Remap);

        let remove_ev = UffdEvent::remove(0x1000, 0x2000);
        assert_eq!(remove_ev.event_type, UffdEventType::Remove);
    }

    #[test]
    fn test_register_mode_from_raw() {
        assert!(UffdRegisterMode::from_raw(UffdRegisterMode::MISSING).is_ok());
        assert!(UffdRegisterMode::from_raw(UffdRegisterMode::WP).is_ok());
        assert!(
            UffdRegisterMode::from_raw(UffdRegisterMode::MISSING | UffdRegisterMode::WP).is_ok()
        );

        // Zero mode is invalid.
        assert_eq!(
            UffdRegisterMode::from_raw(0).unwrap_err(),
            Error::InvalidArgument
        );

        // Unknown bits.
        assert_eq!(
            UffdRegisterMode::from_raw(0x100).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_sys_userfaultfd() {
        let config = sys_userfaultfd(0).unwrap();
        assert!(!config.api_done);

        assert_eq!(
            sys_userfaultfd(0xFFFF_FFFF).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_copy_args_validate() {
        let args = UffdCopyArgs {
            dst: 0x1000,
            src: 0x2000,
            len: 0x1000,
            mode: 0,
            copy_bytes: 0,
        };
        assert!(args.validate().is_ok());

        // Unaligned dst.
        let bad = UffdCopyArgs {
            dst: 0x1001,
            ..args
        };
        assert_eq!(bad.validate().unwrap_err(), Error::InvalidArgument);

        // Bad mode.
        let bad = UffdCopyArgs {
            mode: 0x100,
            ..args
        };
        assert_eq!(bad.validate().unwrap_err(), Error::InvalidArgument);
    }
}
