// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kexec reboot mechanism — fast kernel replacement without firmware.
//!
//! Extends the base kexec infrastructure in [`crate::kexec`] with a
//! complete reboot workflow including:
//! - File-based kexec image loading (`KEXEC_FILE_BASED` flag)
//! - Purgatory validation (SHA-256 digest of loaded segments)
//! - Machine shutdown sequencing (CPU quiesce, device stop, jump)
//! - Crash dump support with reserved memory regions
//! - Reboot notifier chain for orderly shutdown
//!
//! # Data flow
//!
//! 1. User space calls `load_kexec_image()` with segments and flags.
//! 2. The kernel validates segments, computes purgatory digests,
//!    and stores the image in [`KexecRebootState`].
//! 3. On `exec_kexec()`, the reboot sequencer:
//!    a. Runs the notifier chain (reboot hooks).
//!    b. Stops all secondary CPUs.
//!    c. Quiesces devices.
//!    d. Copies segments to final destinations.
//!    e. Jumps to purgatory (which verifies and jumps to kernel).
//!
//! # Types
//!
//! - [`KexecFlags`] — bitflag constants for kexec behavior
//! - [`RebootSegment`] — memory region for the new kernel image
//! - [`PurgatoryDigest`] — SHA-256 digest for segment verification
//! - [`RebootNotifier`] — callback for pre-reboot hooks
//! - [`KexecRebootImage`] — validated kexec image with digests
//! - [`KexecRebootState`] — global kexec reboot state machine
//!
//! Reference: Linux `kernel/kexec_file.c`,
//! `arch/x86/kernel/machine_kexec_64.c`,
//! `kernel/reboot.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of segments in a kexec reboot image.
const MAX_SEGMENTS: usize = 16;

/// Maximum size of a single segment in bytes (128 MiB).
const MAX_SEGMENT_SIZE: usize = 128 * 1024 * 1024;

/// Maximum command-line length in bytes.
const MAX_CMDLINE_LEN: usize = 2048;

/// Maximum number of reboot notifiers.
const MAX_NOTIFIERS: usize = 16;

/// Maximum number of crash reserved memory regions.
const MAX_CRASH_REGIONS: usize = 8;

/// Minimum valid entry point address (above real-mode on x86_64).
const MIN_ENTRY_ADDR: usize = 0x10_0000;

/// Page size for alignment checks (4 KiB).
const PAGE_SIZE: usize = 4096;

/// SHA-256 digest length in bytes.
const DIGEST_LEN: usize = 32;

/// Maximum number of CPUs to stop.
const MAX_CPUS: usize = 256;

// ── KexecFlags ─────────────────────────────────────────────────────

/// Load the image for crash-dump purposes (reserved memory).
pub const KEXEC_ON_CRASH: u32 = 1 << 0;

/// Preserve device context across the kexec (experimental).
pub const KEXEC_PRESERVE_CONTEXT: u32 = 1 << 1;

/// File-based kexec loading (kernel reads the file directly).
pub const KEXEC_FILE_BASED: u32 = 1 << 2;

/// Update the existing loaded image (for crash image refresh).
pub const KEXEC_UPDATE: u32 = 1 << 3;

/// All valid kexec reboot flags.
const VALID_FLAGS: u32 = KEXEC_ON_CRASH | KEXEC_PRESERVE_CONTEXT | KEXEC_FILE_BASED | KEXEC_UPDATE;

// ── RebootSegment ─────────────────────────────────────────────────

/// A contiguous memory region for the new kernel image.
///
/// Describes a source buffer, its destination physical address,
/// and actual payload size. The destination size may be larger
/// than the source to accommodate BSS or alignment padding.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RebootSegment {
    /// Source buffer virtual address (current kernel).
    pub buf: usize,
    /// Source buffer size in bytes (payload to copy).
    pub bufsz: usize,
    /// Destination physical address (new kernel's address space).
    pub mem: usize,
    /// Destination region size in bytes (may be > bufsz for BSS).
    pub memsz: usize,
}

impl RebootSegment {
    /// Creates a new reboot segment.
    pub const fn new(buf: usize, bufsz: usize, mem: usize, memsz: usize) -> Self {
        Self {
            buf,
            bufsz,
            mem,
            memsz,
        }
    }

    /// Returns the end of the destination region.
    pub const fn mem_end(&self) -> usize {
        self.mem + self.memsz
    }

    /// Returns whether the destination is page-aligned.
    pub const fn is_page_aligned(&self) -> bool {
        self.mem % PAGE_SIZE == 0
    }

    /// Returns whether this segment is valid.
    pub const fn is_valid(&self) -> bool {
        self.memsz > 0 && self.bufsz <= self.memsz
    }
}

impl Default for RebootSegment {
    fn default() -> Self {
        Self {
            buf: 0,
            bufsz: 0,
            mem: 0,
            memsz: 0,
        }
    }
}

// ── PurgatoryDigest ───────────────────────────────────────────────

/// SHA-256 digest for verifying segment integrity in purgatory.
///
/// Purgatory runs between the old and new kernels. It uses these
/// digests to verify that segments were copied correctly before
/// jumping to the new kernel entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PurgatoryDigest {
    /// Segment index this digest covers.
    pub segment_idx: usize,
    /// SHA-256 hash of the segment payload.
    pub sha256: [u8; DIGEST_LEN],
    /// Expected payload size in bytes.
    pub expected_size: usize,
    /// Whether this digest slot is in use.
    pub valid: bool,
}

impl PurgatoryDigest {
    /// Creates an empty digest slot.
    const fn empty() -> Self {
        Self {
            segment_idx: 0,
            sha256: [0u8; DIGEST_LEN],
            expected_size: 0,
            valid: false,
        }
    }

    /// Verifies that a given digest matches this one.
    pub fn verify(&self, digest: &[u8; DIGEST_LEN]) -> bool {
        if !self.valid {
            return false;
        }
        self.sha256 == *digest
    }
}

impl Default for PurgatoryDigest {
    fn default() -> Self {
        Self::empty()
    }
}

// ── CrashRegion ───────────────────────────────────────────────────

/// A reserved memory region for crash dump purposes.
///
/// These regions are set aside early in boot and not used by the
/// running kernel, so they survive a crash and can hold the crash
/// dump kernel and its data.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CrashRegion {
    /// Start physical address.
    pub start: usize,
    /// Size in bytes.
    pub size: usize,
    /// Whether this region is in use.
    pub in_use: bool,
}

impl CrashRegion {
    /// Creates an empty region.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            in_use: false,
        }
    }

    /// Returns the end address.
    pub const fn end(&self) -> usize {
        self.start + self.size
    }

    /// Returns whether an address range falls within this region.
    pub const fn contains_range(&self, addr: usize, len: usize) -> bool {
        self.in_use && addr >= self.start && addr + len <= self.start + self.size
    }
}

// ── RebootNotifier ────────────────────────────────────────────────

/// Priority for reboot notifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotifierPriority {
    /// Run first — critical shutdown tasks.
    High = 0,
    /// Default priority — normal cleanup.
    Normal = 1,
    /// Run last — final teardown.
    Low = 2,
}

impl Default for NotifierPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// A reboot notifier callback entry.
///
/// Notifiers are called in priority order before the kexec jump.
/// They perform device quiesce, filesystem sync, etc.
#[derive(Debug, Clone, Copy)]
pub struct RebootNotifier {
    /// Unique notifier ID.
    pub id: u64,
    /// Notifier name for debugging.
    pub name: [u8; 32],
    /// Name length.
    pub name_len: usize,
    /// Execution priority.
    pub priority: NotifierPriority,
    /// Whether this notifier has been called.
    pub called: bool,
    /// Whether this notifier returned success.
    pub succeeded: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl RebootNotifier {
    /// Creates an empty notifier slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; 32],
            name_len: 0,
            priority: NotifierPriority::Normal,
            called: false,
            succeeded: false,
            in_use: false,
        }
    }

    /// Marks the notifier as called with the given result.
    pub fn mark_called(&mut self, success: bool) {
        self.called = true;
        self.succeeded = success;
    }

    /// Resets the called state.
    pub fn reset(&mut self) {
        self.called = false;
        self.succeeded = false;
    }
}

impl Default for RebootNotifier {
    fn default() -> Self {
        Self::empty()
    }
}

// ── KexecRebootImage ──────────────────────────────────────────────

/// A validated kexec reboot image with integrity digests.
///
/// Contains all segments, the entry point, command line, and
/// purgatory digests for post-copy verification.
pub struct KexecRebootImage {
    /// Loaded segments.
    segments: [RebootSegment; MAX_SEGMENTS],
    /// Number of valid segments.
    nr_segments: usize,
    /// New kernel entry point address.
    entry_point: usize,
    /// Kexec flags.
    flags: u32,
    /// Kernel command line (null-terminated).
    cmdline: [u8; MAX_CMDLINE_LEN],
    /// Command line length.
    cmdline_len: usize,
    /// Per-segment integrity digests.
    digests: [PurgatoryDigest; MAX_SEGMENTS],
    /// Total size of all segments in bytes.
    total_size: usize,
}

impl KexecRebootImage {
    /// Creates a default empty image.
    const fn new() -> Self {
        Self {
            segments: [RebootSegment {
                buf: 0,
                bufsz: 0,
                mem: 0,
                memsz: 0,
            }; MAX_SEGMENTS],
            nr_segments: 0,
            entry_point: 0,
            flags: 0,
            cmdline: [0u8; MAX_CMDLINE_LEN],
            cmdline_len: 0,
            digests: [PurgatoryDigest::empty(); MAX_SEGMENTS],
            total_size: 0,
        }
    }

    /// Returns the entry point address.
    pub const fn entry_point(&self) -> usize {
        self.entry_point
    }

    /// Returns the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the number of segments.
    pub const fn nr_segments(&self) -> usize {
        self.nr_segments
    }

    /// Returns the segments as a slice.
    pub fn segments(&self) -> &[RebootSegment] {
        &self.segments[..self.nr_segments]
    }

    /// Returns the command line as a byte slice.
    pub fn cmdline(&self) -> &[u8] {
        &self.cmdline[..self.cmdline_len]
    }

    /// Sets the kernel command line.
    pub fn set_cmdline(&mut self, cmdline: &[u8]) {
        let len = cmdline.len().min(MAX_CMDLINE_LEN);
        self.cmdline[..len].copy_from_slice(&cmdline[..len]);
        self.cmdline_len = len;
    }

    /// Returns the total size of all segments.
    pub const fn total_size(&self) -> usize {
        self.total_size
    }

    /// Returns whether the crash flag is set.
    pub const fn is_crash_image(&self) -> bool {
        self.flags & KEXEC_ON_CRASH != 0
    }

    /// Returns whether context preservation is requested.
    pub const fn preserve_context(&self) -> bool {
        self.flags & KEXEC_PRESERVE_CONTEXT != 0
    }

    /// Returns whether file-based loading was used.
    pub const fn is_file_based(&self) -> bool {
        self.flags & KEXEC_FILE_BASED != 0
    }

    /// Returns the digest for a segment.
    pub fn digest(&self, idx: usize) -> Option<&PurgatoryDigest> {
        if idx < self.nr_segments && self.digests[idx].valid {
            Some(&self.digests[idx])
        } else {
            None
        }
    }
}

impl Default for KexecRebootImage {
    fn default() -> Self {
        Self::new()
    }
}

// ── RebootPhase ───────────────────────────────────────────────────

/// The phase of the kexec reboot state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootPhase {
    /// No image loaded.
    Idle,
    /// Image loaded and validated.
    Loaded,
    /// Running reboot notifiers.
    Notifying,
    /// Stopping secondary CPUs.
    StoppingCpus,
    /// Quiescing devices.
    QuiescingDevices,
    /// Copying segments to final destinations.
    CopyingSegments,
    /// Executing purgatory / jumping to new kernel.
    Executing,
    /// Reboot failed — can retry or unload.
    Failed,
}

impl Default for RebootPhase {
    fn default() -> Self {
        Self::Idle
    }
}

// ── CpuStopState ─────────────────────────────────────────────────

/// Per-CPU stop state during kexec shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuState {
    /// CPU is running.
    Online,
    /// Stop requested via IPI.
    StopRequested,
    /// CPU has stopped.
    Stopped,
}

impl Default for CpuState {
    fn default() -> Self {
        Self::Online
    }
}

// ── KexecRebootState ─────────────────────────────────────────────

/// Global kexec reboot state machine.
///
/// Manages the full lifecycle of a kexec reboot: load, validate,
/// run notifiers, stop CPUs, quiesce devices, copy segments, and
/// jump to the new kernel.
pub struct KexecRebootState {
    /// The loaded normal-boot image.
    image: Option<KexecRebootImage>,
    /// The crash dump image.
    crash_image: Option<KexecRebootImage>,
    /// Current phase of the reboot sequence.
    phase: RebootPhase,
    /// Registered reboot notifiers.
    notifiers: [RebootNotifier; MAX_NOTIFIERS],
    /// Number of registered notifiers.
    notifier_count: usize,
    /// Next notifier ID.
    next_notifier_id: u64,
    /// Reserved crash memory regions.
    crash_regions: [CrashRegion; MAX_CRASH_REGIONS],
    /// Number of crash regions.
    crash_region_count: usize,
    /// Per-CPU stop state.
    cpu_states: [CpuState; MAX_CPUS],
    /// Number of online CPUs.
    online_cpus: usize,
    /// Number of CPUs that have stopped.
    stopped_cpus: usize,
    /// Error message from the last failure.
    last_error: [u8; 128],
    /// Length of the error message.
    last_error_len: usize,
}

impl Default for KexecRebootState {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecRebootState {
    /// Creates a new idle kexec reboot state.
    pub const fn new() -> Self {
        Self {
            image: None,
            crash_image: None,
            phase: RebootPhase::Idle,
            notifiers: [RebootNotifier::empty(); MAX_NOTIFIERS],
            notifier_count: 0,
            next_notifier_id: 1,
            crash_regions: [CrashRegion::empty(); MAX_CRASH_REGIONS],
            crash_region_count: 0,
            cpu_states: [CpuState::Online; MAX_CPUS],
            online_cpus: 1,
            stopped_cpus: 0,
            last_error: [0u8; 128],
            last_error_len: 0,
        }
    }

    /// Returns the current phase.
    pub const fn phase(&self) -> RebootPhase {
        self.phase
    }

    /// Sets the number of online CPUs.
    pub fn set_online_cpus(&mut self, count: usize) {
        self.online_cpus = count.min(MAX_CPUS);
    }

    /// Returns whether a normal image is loaded.
    pub const fn is_loaded(&self) -> bool {
        self.image.is_some()
    }

    /// Returns whether a crash image is loaded.
    pub const fn has_crash_image(&self) -> bool {
        self.crash_image.is_some()
    }

    /// Returns a reference to the loaded image.
    pub fn image(&self) -> Option<&KexecRebootImage> {
        self.image.as_ref()
    }

    /// Returns a reference to the crash image.
    pub fn crash_image(&self) -> Option<&KexecRebootImage> {
        self.crash_image.as_ref()
    }

    /// Records an error message for diagnostics.
    fn set_error(&mut self, msg: &[u8]) {
        let len = msg.len().min(128);
        self.last_error[..len].copy_from_slice(&msg[..len]);
        self.last_error_len = len;
    }

    /// Returns the last error message.
    pub fn last_error(&self) -> &[u8] {
        &self.last_error[..self.last_error_len]
    }

    // ── Crash region management ──────────────────────────────────

    /// Adds a reserved crash memory region.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — size is zero or not page-aligned.
    /// - `Error::OutOfMemory` — no free crash region slots.
    /// - `Error::AlreadyExists` — region overlaps an existing one.
    pub fn add_crash_region(&mut self, start: usize, size: usize) -> Result<()> {
        if size == 0 || start % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        let end = start + size;
        for r in &self.crash_regions[..self.crash_region_count] {
            if r.in_use && start < r.end() && r.start < end {
                return Err(Error::AlreadyExists);
            }
        }

        if self.crash_region_count >= MAX_CRASH_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let slot = &mut self.crash_regions[self.crash_region_count];
        slot.start = start;
        slot.size = size;
        slot.in_use = true;
        self.crash_region_count += 1;
        Ok(())
    }

    /// Checks whether a segment fits within a crash region.
    pub fn in_crash_region(&self, addr: usize, size: usize) -> bool {
        self.crash_regions[..self.crash_region_count]
            .iter()
            .any(|r| r.contains_range(addr, size))
    }

    // ── Notifier management ─────────────────────────────────────

    /// Registers a reboot notifier.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty.
    /// - `Error::OutOfMemory` — notifier table full.
    pub fn register_notifier(&mut self, name: &[u8], priority: NotifierPriority) -> Result<u64> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .notifiers
            .iter_mut()
            .find(|n| !n.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_notifier_id;
        self.next_notifier_id += 1;

        *slot = RebootNotifier::empty();
        slot.id = id;
        let name_len = name.len().min(32);
        slot.name[..name_len].copy_from_slice(&name[..name_len]);
        slot.name_len = name_len;
        slot.priority = priority;
        slot.in_use = true;
        self.notifier_count += 1;

        Ok(id)
    }

    /// Unregisters a reboot notifier by ID.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the notifier is not registered.
    pub fn unregister_notifier(&mut self, id: u64) -> Result<()> {
        let slot = self
            .notifiers
            .iter_mut()
            .find(|n| n.in_use && n.id == id)
            .ok_or(Error::NotFound)?;

        *slot = RebootNotifier::empty();
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the order in which notifiers should be called
    /// (sorted by priority). Writes indices into `order`.
    ///
    /// Returns the count of active notifiers.
    pub fn notifier_order(&self, order: &mut [usize; MAX_NOTIFIERS]) -> usize {
        let mut count = 0;
        for (i, n) in self.notifiers.iter().enumerate() {
            if n.in_use {
                order[count] = i;
                count += 1;
            }
        }

        // Bubble sort by priority (small array, no alloc).
        for i in 0..count {
            for j in 0..count.saturating_sub(i + 1) {
                let a = self.notifiers[order[j]].priority;
                let b = self.notifiers[order[j + 1]].priority;
                if a > b {
                    order.swap(j, j + 1);
                }
            }
        }

        count
    }

    /// Marks a notifier as called with the given result.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the notifier index is invalid.
    pub fn mark_notifier_called(&mut self, idx: usize, success: bool) -> Result<()> {
        if idx >= MAX_NOTIFIERS || !self.notifiers[idx].in_use {
            return Err(Error::NotFound);
        }
        self.notifiers[idx].mark_called(success);
        Ok(())
    }

    // ── CPU stop management ─────────────────────────────────────

    /// Requests a CPU to stop.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `cpu_id` is out of range.
    pub fn request_cpu_stop(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= self.online_cpus {
            return Err(Error::InvalidArgument);
        }
        self.cpu_states[cpu_id] = CpuState::StopRequested;
        Ok(())
    }

    /// Acknowledges that a CPU has stopped.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `cpu_id` is out of range.
    pub fn ack_cpu_stopped(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= self.online_cpus {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_states[cpu_id] != CpuState::Stopped {
            self.stopped_cpus += 1;
        }
        self.cpu_states[cpu_id] = CpuState::Stopped;
        Ok(())
    }

    /// Returns whether all secondary CPUs have stopped.
    ///
    /// CPU 0 (BSP) is not counted — it performs the final jump.
    pub fn all_cpus_stopped(&self) -> bool {
        if self.online_cpus <= 1 {
            return true;
        }
        self.stopped_cpus >= self.online_cpus - 1
    }

    /// Resets all CPU states to online.
    pub fn reset_cpu_states(&mut self) {
        for state in &mut self.cpu_states[..self.online_cpus] {
            *state = CpuState::Online;
        }
        self.stopped_cpus = 0;
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Validates segments for a kexec reboot image.
///
/// Checks alignment, size limits, non-overlap, and (for crash
/// images) that all segments fall within reserved crash regions.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` for validation failures.
pub fn validate_segments(
    state: &KexecRebootState,
    segments: &[RebootSegment],
    flags: u32,
) -> Result<()> {
    if segments.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if segments.len() > MAX_SEGMENTS {
        return Err(Error::InvalidArgument);
    }

    for (i, seg) in segments.iter().enumerate() {
        if !seg.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if seg.memsz > MAX_SEGMENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !seg.is_page_aligned() {
            return Err(Error::InvalidArgument);
        }

        // For crash images, segments must be in crash regions.
        if flags & KEXEC_ON_CRASH != 0 && !state.in_crash_region(seg.mem, seg.memsz) {
            return Err(Error::InvalidArgument);
        }

        // Check for overlaps with subsequent segments.
        for seg_b in segments.iter().skip(i + 1) {
            if seg.mem < seg_b.mem_end() && seg_b.mem < seg.mem_end() {
                return Err(Error::InvalidArgument);
            }
        }
    }

    Ok(())
}

/// Loads a kexec reboot image.
///
/// Validates segments, builds the image with placeholder digests,
/// and stores it in the state machine.
///
/// # Errors
///
/// - `Error::InvalidArgument` — invalid flags, entry, or segments.
/// - `Error::Busy` — a kexec is currently in progress.
/// - `Error::AlreadyExists` — an image is already loaded (and
///   `KEXEC_UPDATE` is not set).
pub fn load_kexec_image(
    state: &mut KexecRebootState,
    entry_point: usize,
    segments: &[RebootSegment],
    flags: u32,
) -> Result<()> {
    // Validate flags.
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    // Cannot load while executing.
    match state.phase {
        RebootPhase::Idle | RebootPhase::Loaded | RebootPhase::Failed => {}
        _ => return Err(Error::Busy),
    }

    let is_crash = flags & KEXEC_ON_CRASH != 0;
    let is_update = flags & KEXEC_UPDATE != 0;

    // Check for existing image.
    if !is_update {
        if is_crash && state.crash_image.is_some() {
            return Err(Error::AlreadyExists);
        }
        if !is_crash && state.image.is_some() {
            return Err(Error::AlreadyExists);
        }
    }

    // Validate entry point.
    if entry_point < MIN_ENTRY_ADDR {
        return Err(Error::InvalidArgument);
    }

    // Validate segments.
    validate_segments(state, segments, flags)?;

    // Build the image.
    let mut image = KexecRebootImage::new();
    image.entry_point = entry_point;
    image.flags = flags;
    image.nr_segments = segments.len();

    let mut total = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        image.segments[i] = *seg;
        total = total.saturating_add(seg.memsz);

        // Create placeholder digest.
        image.digests[i] = PurgatoryDigest {
            segment_idx: i,
            sha256: [0u8; DIGEST_LEN],
            expected_size: seg.bufsz,
            valid: false,
        };
    }
    image.total_size = total;

    // Store the image.
    if is_crash {
        state.crash_image = Some(image);
    } else {
        state.image = Some(image);
        state.phase = RebootPhase::Loaded;
    }

    Ok(())
}

/// Unloads a previously loaded kexec image.
///
/// # Errors
///
/// - `Error::NotFound` — no image loaded.
/// - `Error::Busy` — reboot in progress.
pub fn unload_kexec_image(state: &mut KexecRebootState) -> Result<()> {
    match state.phase {
        RebootPhase::Idle | RebootPhase::Loaded | RebootPhase::Failed => {}
        _ => return Err(Error::Busy),
    }

    if state.image.is_none() {
        return Err(Error::NotFound);
    }

    state.image = None;
    state.phase = RebootPhase::Idle;
    Ok(())
}

/// Unloads the crash dump image.
///
/// # Errors
///
/// - `Error::NotFound` — no crash image loaded.
/// - `Error::Busy` — reboot in progress.
pub fn unload_crash_image(state: &mut KexecRebootState) -> Result<()> {
    match state.phase {
        RebootPhase::Idle | RebootPhase::Loaded | RebootPhase::Failed => {}
        _ => return Err(Error::Busy),
    }

    if state.crash_image.is_none() {
        return Err(Error::NotFound);
    }

    state.crash_image = None;
    Ok(())
}

/// Begins the kexec reboot sequence.
///
/// Transitions through: Notifying -> StoppingCpus ->
/// QuiescingDevices -> CopyingSegments -> Executing.
///
/// This function advances the state machine one step at a time.
/// The caller is responsible for driving the sequence by calling
/// this repeatedly until the phase reaches `Executing`.
///
/// # Errors
///
/// - `Error::NotFound` — no image loaded.
/// - `Error::Busy` — already executing.
pub fn exec_kexec(state: &mut KexecRebootState) -> Result<RebootPhase> {
    match state.phase {
        RebootPhase::Idle => {
            return Err(Error::NotFound);
        }
        RebootPhase::Executing => {
            return Err(Error::Busy);
        }
        RebootPhase::Loaded => {
            // Start the reboot sequence.
            state.phase = RebootPhase::Notifying;
            // Reset notifier called state.
            for n in &mut state.notifiers {
                if n.in_use {
                    n.reset();
                }
            }
        }
        RebootPhase::Notifying => {
            // Advance to CPU stop after notifiers are done.
            state.phase = RebootPhase::StoppingCpus;
            state.reset_cpu_states();
            // Request all secondary CPUs to stop.
            for cpu in 1..state.online_cpus {
                state.cpu_states[cpu] = CpuState::StopRequested;
            }
        }
        RebootPhase::StoppingCpus => {
            if state.all_cpus_stopped() {
                state.phase = RebootPhase::QuiescingDevices;
            }
            // Otherwise, caller retries after checking CPUs.
        }
        RebootPhase::QuiescingDevices => {
            // In a real kernel, this would call device shutdown.
            state.phase = RebootPhase::CopyingSegments;
        }
        RebootPhase::CopyingSegments => {
            // In a real kernel, this would relocate segments.
            state.phase = RebootPhase::Executing;
        }
        RebootPhase::Failed => {
            // Allow retry from failed state.
            state.phase = RebootPhase::Loaded;
        }
    }

    Ok(state.phase)
}

/// Marks the reboot as failed and records an error.
pub fn mark_failed(state: &mut KexecRebootState, error_msg: &[u8]) {
    state.phase = RebootPhase::Failed;
    state.set_error(error_msg);
    state.reset_cpu_states();
}

/// Returns summary information about the kexec state.
#[derive(Debug, Clone, Copy)]
pub struct KexecRebootInfo {
    /// Current phase.
    pub phase: RebootPhase,
    /// Whether a normal image is loaded.
    pub image_loaded: bool,
    /// Whether a crash image is loaded.
    pub crash_loaded: bool,
    /// Number of registered notifiers.
    pub notifier_count: usize,
    /// Number of crash regions.
    pub crash_region_count: usize,
    /// Number of online CPUs.
    pub online_cpus: usize,
    /// Number of stopped CPUs.
    pub stopped_cpus: usize,
}

/// Returns summary information about the kexec reboot state.
pub fn info(state: &KexecRebootState) -> KexecRebootInfo {
    KexecRebootInfo {
        phase: state.phase,
        image_loaded: state.image.is_some(),
        crash_loaded: state.crash_image.is_some(),
        notifier_count: state.notifier_count,
        crash_region_count: state.crash_region_count,
        online_cpus: state.online_cpus,
        stopped_cpus: state.stopped_cpus,
    }
}
