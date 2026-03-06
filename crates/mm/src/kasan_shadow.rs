// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KASAN (Kernel Address Sanitizer) shadow memory subsystem.
//!
//! Implements the shadow memory layout and access-checking logic for
//! detecting out-of-bounds accesses, use-after-free, and other memory
//! bugs in kernel code at runtime.
//!
//! # How It Works
//!
//! Every 8 bytes of kernel memory has a corresponding 1-byte shadow
//! value that encodes whether accesses are valid:
//! - `0x00` — all 8 bytes are accessible
//! - `0x01..=0x07` — only the first N bytes are accessible
//! - `0xFx` — various poison patterns (freed, redzoned, etc.)
//!
//! # Subsystems
//!
//! - [`ShadowValue`] — shadow byte encoding
//! - [`ShadowRegion`] — contiguous shadow memory region
//! - [`QuarantineEntry`] — freed-object quarantine for use-after-free
//!   detection
//! - [`Quarantine`] — quarantine pool manager
//! - [`KasanReport`] — detailed error report for violations
//! - [`KasanReportLog`] — ring buffer of error reports
//! - [`KasanShadowMap`] — the shadow memory manager
//! - [`KasanStats`] — aggregate sanitizer statistics
//!
//! Reference: Linux `mm/kasan/`, `Documentation/dev-tools/kasan.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Each shadow byte covers this many kernel bytes.
const SHADOW_SCALE: u64 = 8;

/// Maximum number of shadow regions tracked.
const MAX_SHADOW_REGIONS: usize = 32;

/// Maximum quarantine entries.
const MAX_QUARANTINE: usize = 256;

/// Maximum number of error reports in the log.
const MAX_REPORTS: usize = 64;

/// Maximum number of redzone entries tracked.
const MAX_REDZONES: usize = 128;

/// Maximum number of stack-related shadow entries.
const MAX_STACK_ENTRIES: usize = 64;

/// Default quarantine size in bytes before oldest entries are evicted.
const DEFAULT_QUARANTINE_SIZE: u64 = 4 * 1024 * 1024;

// -------------------------------------------------------------------
// ShadowValue — shadow byte encoding
// -------------------------------------------------------------------

/// Shadow byte value encoding access permissions.
///
/// Mirrors the Linux KASAN shadow encoding in `mm/kasan/kasan.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowValue {
    /// All 8 bytes accessible.
    Accessible,
    /// First `n` bytes (1..=7) accessible, rest poisoned.
    PartialAccess(u8),
    /// Object has been freed — use-after-free detection.
    Freed,
    /// Slab redzone — out-of-bounds detection between objects.
    SlabRedzone,
    /// Object padding area (internal alignment).
    ObjectPadding,
    /// Kmalloc redzone (allocated size < slab size).
    KmallocRedzone,
    /// Global variable redzone.
    GlobalRedzone,
    /// Stack left redzone.
    StackLeft,
    /// Stack mid redzone (between stack variables).
    StackMid,
    /// Stack right redzone.
    StackRight,
    /// Stack variable has gone out of scope (use-after-return).
    UseAfterScope,
    /// Alloc-meta padding.
    AllocMeta,
    /// Free-meta padding.
    FreeMeta,
}

impl ShadowValue {
    /// Converts a raw shadow byte to a [`ShadowValue`].
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::Accessible,
            0x01..=0x07 => Self::PartialAccess(byte),
            0xFA => Self::Freed,
            0xFC => Self::SlabRedzone,
            0xFE => Self::ObjectPadding,
            0xFB => Self::KmallocRedzone,
            0xF9 => Self::GlobalRedzone,
            0xF1 => Self::StackLeft,
            0xF2 => Self::StackMid,
            0xF3 => Self::StackRight,
            0xF8 => Self::UseAfterScope,
            0xFD => Self::AllocMeta,
            0xFF => Self::FreeMeta,
            _ => Self::SlabRedzone, // Unknown → treat as redzone.
        }
    }

    /// Converts a [`ShadowValue`] to its raw byte encoding.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Accessible => 0x00,
            Self::PartialAccess(n) => n,
            Self::Freed => 0xFA,
            Self::SlabRedzone => 0xFC,
            Self::ObjectPadding => 0xFE,
            Self::KmallocRedzone => 0xFB,
            Self::GlobalRedzone => 0xF9,
            Self::StackLeft => 0xF1,
            Self::StackMid => 0xF2,
            Self::StackRight => 0xF3,
            Self::UseAfterScope => 0xF8,
            Self::AllocMeta => 0xFD,
            Self::FreeMeta => 0xFF,
        }
    }

    /// Returns `true` if this shadow value indicates a poisoned byte.
    pub fn is_poisoned(self) -> bool {
        !matches!(self, Self::Accessible | Self::PartialAccess(_))
    }

    /// Returns a human-readable description of the shadow value.
    pub fn description(self) -> &'static str {
        match self {
            Self::Accessible => "accessible",
            Self::PartialAccess(_) => "partial access",
            Self::Freed => "use-after-free",
            Self::SlabRedzone => "slab out-of-bounds",
            Self::ObjectPadding => "object padding",
            Self::KmallocRedzone => "kmalloc out-of-bounds",
            Self::GlobalRedzone => "global out-of-bounds",
            Self::StackLeft => "stack left redzone",
            Self::StackMid => "stack mid redzone",
            Self::StackRight => "stack right redzone",
            Self::UseAfterScope => "use-after-scope",
            Self::AllocMeta => "alloc-meta",
            Self::FreeMeta => "free-meta",
        }
    }
}

impl Default for ShadowValue {
    fn default() -> Self {
        Self::Accessible
    }
}

// -------------------------------------------------------------------
// ShadowRegion
// -------------------------------------------------------------------

/// A contiguous shadow memory region.
///
/// Maps a kernel virtual address range to its shadow byte storage.
/// Shadow bytes are stored inline (up to a fixed array size) for
/// `no_std` compatibility.
#[derive(Debug, Clone, Copy)]
pub struct ShadowRegion {
    /// Start of the kernel address range covered.
    pub kernel_start: u64,
    /// End of the kernel address range (exclusive).
    pub kernel_end: u64,
    /// Start of the shadow byte storage (virtual address).
    pub shadow_start: u64,
    /// Number of shadow bytes in this region.
    pub shadow_size: u64,
    /// Whether this region is active.
    pub active: bool,
    /// Region type for diagnostics.
    pub region_type: ShadowRegionType,
}

/// Type of shadow region for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShadowRegionType {
    /// Covers the kernel text/data segments.
    #[default]
    KernelImage,
    /// Covers kmalloc/slab memory.
    SlabHeap,
    /// Covers vmalloc'd memory.
    Vmalloc,
    /// Covers module memory.
    Module,
    /// Covers stack memory.
    Stack,
    /// Covers global variables.
    Global,
}

impl Default for ShadowRegion {
    fn default() -> Self {
        Self {
            kernel_start: 0,
            kernel_end: 0,
            shadow_start: 0,
            shadow_size: 0,
            active: false,
            region_type: ShadowRegionType::KernelImage,
        }
    }
}

impl ShadowRegion {
    /// Computes the shadow address for a kernel address.
    ///
    /// Returns `None` if the address is outside this region.
    pub fn shadow_addr(&self, kernel_addr: u64) -> Option<u64> {
        if kernel_addr < self.kernel_start || kernel_addr >= self.kernel_end {
            return None;
        }
        let offset = (kernel_addr - self.kernel_start) / SHADOW_SCALE;
        Some(self.shadow_start + offset)
    }

    /// Returns the kernel address range size in bytes.
    pub fn kernel_size(&self) -> u64 {
        self.kernel_end.saturating_sub(self.kernel_start)
    }
}

// -------------------------------------------------------------------
// Access checking types
// -------------------------------------------------------------------

/// Type of memory access being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessType {
    /// Read access.
    #[default]
    Read,
    /// Write access.
    Write,
    /// Free operation.
    Free,
}

/// Access size classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessSize {
    /// 1-byte access.
    #[default]
    Byte1,
    /// 2-byte access.
    Byte2,
    /// 4-byte access.
    Byte4,
    /// 8-byte access.
    Byte8,
    /// 16-byte access.
    Byte16,
    /// N-byte access (custom size).
    ByteN(u64),
}

impl AccessSize {
    /// Returns the access size in bytes.
    pub fn bytes(self) -> u64 {
        match self {
            Self::Byte1 => 1,
            Self::Byte2 => 2,
            Self::Byte4 => 4,
            Self::Byte8 => 8,
            Self::Byte16 => 16,
            Self::ByteN(n) => n,
        }
    }
}

// -------------------------------------------------------------------
// QuarantineEntry / Quarantine
// -------------------------------------------------------------------

/// A freed object held in quarantine for use-after-free detection.
///
/// Objects remain in quarantine (with their shadow marked as
/// [`ShadowValue::Freed`]) for a period before being returned to the
/// slab. This window allows detection of accesses to freed memory.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuarantineEntry {
    /// Start address of the freed object.
    pub addr: u64,
    /// Size of the freed object in bytes.
    pub size: u64,
    /// Slab cache index this object belongs to.
    pub cache_idx: u32,
    /// Tick when the object was freed.
    pub free_tick: u64,
    /// Whether this quarantine slot is in use.
    pub in_use: bool,
}

/// Quarantine pool for freed objects.
///
/// Maintains a FIFO queue of freed objects. When the quarantine
/// exceeds its size limit, the oldest objects are evicted and their
/// shadow is cleared.
#[derive(Debug)]
pub struct Quarantine {
    /// Quarantine entries.
    entries: [QuarantineEntry; MAX_QUARANTINE],
    /// Number of active entries.
    entry_count: usize,
    /// Current total bytes in quarantine.
    current_bytes: u64,
    /// Maximum bytes before eviction starts.
    max_bytes: u64,
    /// Total objects quarantined (all time).
    total_quarantined: u64,
    /// Total objects evicted.
    total_evicted: u64,
    /// FIFO head (oldest entry).
    head: usize,
    /// FIFO tail (next write position).
    tail: usize,
}

impl Default for Quarantine {
    fn default() -> Self {
        Self::new()
    }
}

impl Quarantine {
    /// Creates a new quarantine with default size limit.
    pub const fn new() -> Self {
        Self {
            entries: [QuarantineEntry {
                addr: 0,
                size: 0,
                cache_idx: 0,
                free_tick: 0,
                in_use: false,
            }; MAX_QUARANTINE],
            entry_count: 0,
            current_bytes: 0,
            max_bytes: DEFAULT_QUARANTINE_SIZE,
            total_quarantined: 0,
            total_evicted: 0,
            head: 0,
            tail: 0,
        }
    }

    /// Adds a freed object to quarantine.
    ///
    /// If the quarantine is full or exceeds the size limit, the
    /// oldest entry is evicted first.
    ///
    /// # Returns
    ///
    /// The address of the evicted object (if any), so the caller
    /// can clear its shadow.
    pub fn add(&mut self, addr: u64, size: u64, cache_idx: u32, tick: u64) -> Option<(u64, u64)> {
        let mut evicted = None;

        // Evict if full or over size limit.
        if self.entry_count >= MAX_QUARANTINE || self.current_bytes + size > self.max_bytes {
            evicted = self.evict_oldest();
        }

        self.entries[self.tail] = QuarantineEntry {
            addr,
            size,
            cache_idx,
            free_tick: tick,
            in_use: true,
        };
        self.tail = (self.tail + 1) % MAX_QUARANTINE;
        self.entry_count += 1;
        self.current_bytes += size;
        self.total_quarantined += 1;

        evicted
    }

    /// Evicts the oldest quarantine entry.
    ///
    /// Returns `(addr, size)` of the evicted object, or `None`.
    pub fn evict_oldest(&mut self) -> Option<(u64, u64)> {
        if self.entry_count == 0 {
            return None;
        }
        let entry = &mut self.entries[self.head];
        if !entry.in_use {
            return None;
        }
        let addr = entry.addr;
        let size = entry.size;
        entry.in_use = false;
        self.head = (self.head + 1) % MAX_QUARANTINE;
        self.entry_count -= 1;
        self.current_bytes = self.current_bytes.saturating_sub(size);
        self.total_evicted += 1;
        Some((addr, size))
    }

    /// Sets the maximum quarantine size in bytes.
    pub fn set_max_bytes(&mut self, max_bytes: u64) {
        self.max_bytes = max_bytes;
    }

    /// Returns the current number of quarantined objects.
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /// Returns `true` if the quarantine is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Returns the current quarantine size in bytes.
    pub fn current_bytes(&self) -> u64 {
        self.current_bytes
    }

    /// Returns total objects quarantined (all time).
    pub fn total_quarantined(&self) -> u64 {
        self.total_quarantined
    }

    /// Returns total objects evicted.
    pub fn total_evicted(&self) -> u64 {
        self.total_evicted
    }
}

// -------------------------------------------------------------------
// RedZoneEntry
// -------------------------------------------------------------------

/// Tracks a redzone around an allocated object.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedZoneEntry {
    /// Object start address.
    pub obj_addr: u64,
    /// Object size (actual allocation).
    pub obj_size: u64,
    /// Left redzone size in bytes.
    pub left_redzone: u32,
    /// Right redzone size in bytes.
    pub right_redzone: u32,
    /// Shadow value used for this redzone.
    pub shadow_val: u8,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// KasanReport
// -------------------------------------------------------------------

/// Detailed error report generated when KASAN detects a violation.
#[derive(Debug, Clone, Copy, Default)]
pub struct KasanReport {
    /// Timestamp (tick) of the violation.
    pub timestamp: u64,
    /// Faulting kernel address.
    pub fault_addr: u64,
    /// Shadow address corresponding to the fault.
    pub shadow_addr: u64,
    /// Shadow value at the fault location.
    pub shadow_val: u8,
    /// Type of access that caused the violation.
    pub access_type: AccessType,
    /// Size of the access.
    pub access_bytes: u64,
    /// Bug type classification.
    pub bug_type: KasanBugType,
    /// Instruction pointer (caller address).
    pub caller_ip: u64,
    /// Task/thread ID.
    pub task_id: u64,
    /// Whether this report slot is in use.
    pub in_use: bool,
}

/// Bug type classification for KASAN reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KasanBugType {
    /// Out-of-bounds access (slab, stack, or global).
    #[default]
    OutOfBounds,
    /// Use-after-free — accessing freed memory.
    UseAfterFree,
    /// Use-after-scope — stack variable out of scope.
    UseAfterScope,
    /// Double-free — freeing already-freed memory.
    DoubleFree,
    /// Invalid free — freeing non-heap memory.
    InvalidFree,
    /// Slab out-of-bounds — between slab objects.
    SlabOutOfBounds,
    /// Global out-of-bounds — beyond global variable.
    GlobalOutOfBounds,
    /// Stack buffer overflow.
    StackOverflow,
    /// Wild memory access (unmapped shadow).
    WildAccess,
}

impl KasanBugType {
    /// Infers the bug type from a shadow value.
    pub fn from_shadow(val: ShadowValue) -> Self {
        match val {
            ShadowValue::Freed => Self::UseAfterFree,
            ShadowValue::SlabRedzone => Self::SlabOutOfBounds,
            ShadowValue::KmallocRedzone => Self::OutOfBounds,
            ShadowValue::GlobalRedzone => Self::GlobalOutOfBounds,
            ShadowValue::StackLeft | ShadowValue::StackMid | ShadowValue::StackRight => {
                Self::StackOverflow
            }
            ShadowValue::UseAfterScope => Self::UseAfterScope,
            ShadowValue::ObjectPadding => Self::OutOfBounds,
            _ => Self::WildAccess,
        }
    }
}

/// Ring-buffer report log.
#[derive(Debug)]
pub struct KasanReportLog {
    /// Report entries.
    reports: [KasanReport; MAX_REPORTS],
    /// Write cursor.
    write_pos: usize,
    /// Total reports generated.
    total_reports: u64,
}

impl Default for KasanReportLog {
    fn default() -> Self {
        Self::new()
    }
}

impl KasanReportLog {
    /// Creates an empty report log.
    pub const fn new() -> Self {
        Self {
            reports: [KasanReport {
                timestamp: 0,
                fault_addr: 0,
                shadow_addr: 0,
                shadow_val: 0,
                access_type: AccessType::Read,
                access_bytes: 0,
                bug_type: KasanBugType::OutOfBounds,
                caller_ip: 0,
                task_id: 0,
                in_use: false,
            }; MAX_REPORTS],
            write_pos: 0,
            total_reports: 0,
        }
    }

    /// Records a KASAN report.
    pub fn record(&mut self, report: KasanReport) {
        self.reports[self.write_pos] = report;
        self.write_pos = (self.write_pos + 1) % MAX_REPORTS;
        self.total_reports += 1;
    }

    /// Returns the most recent `count` reports.
    pub fn recent(&self, count: usize) -> &[KasanReport] {
        let available = core::cmp::min(
            count,
            core::cmp::min(self.total_reports as usize, MAX_REPORTS),
        );
        if available == 0 {
            return &[];
        }
        let start = if self.write_pos >= available {
            self.write_pos - available
        } else {
            0
        };
        let end = core::cmp::min(start + available, MAX_REPORTS);
        &self.reports[start..end]
    }

    /// Total reports generated (including overwritten).
    pub fn total_reports(&self) -> u64 {
        self.total_reports
    }
}

// -------------------------------------------------------------------
// KasanStats
// -------------------------------------------------------------------

/// Aggregate KASAN statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct KasanStats {
    /// Total access checks performed.
    pub checks: u64,
    /// Total violations detected.
    pub violations: u64,
    /// Out-of-bounds violations.
    pub oob_violations: u64,
    /// Use-after-free violations.
    pub uaf_violations: u64,
    /// Use-after-scope violations.
    pub uas_violations: u64,
    /// Double-free detections.
    pub double_frees: u64,
    /// Invalid free detections.
    pub invalid_frees: u64,
    /// Stack overflow detections.
    pub stack_overflows: u64,
    /// Shadow regions active.
    pub regions_active: u32,
    /// Quarantine objects currently held.
    pub quarantine_objects: u32,
    /// Quarantine bytes currently held.
    pub quarantine_bytes: u64,
}

// -------------------------------------------------------------------
// KasanShadowMap
// -------------------------------------------------------------------

/// KASAN shadow memory manager.
///
/// Manages the mapping between kernel addresses and their shadow
/// bytes, provides access checking, object tracking with redzones,
/// and use-after-free detection via quarantine.
pub struct KasanShadowMap {
    /// Shadow regions mapping kernel ranges to shadow storage.
    regions: [ShadowRegion; MAX_SHADOW_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Redzone tracking for allocated objects.
    redzones: [RedZoneEntry; MAX_REDZONES],
    /// Number of active redzones.
    redzone_count: usize,
    /// Stack shadow entries.
    stack_entries: [StackShadowEntry; MAX_STACK_ENTRIES],
    /// Number of active stack entries.
    stack_count: usize,
    /// Freed-object quarantine.
    quarantine: Quarantine,
    /// Error report log.
    report_log: KasanReportLog,
    /// Aggregate statistics.
    stats: KasanStats,
    /// Whether KASAN checking is enabled.
    enabled: bool,
    /// Whether to panic on first violation.
    panic_on_violation: bool,
    /// Monotonic tick counter.
    tick: u64,
}

/// Stack shadow tracking entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackShadowEntry {
    /// Stack frame start address.
    pub frame_addr: u64,
    /// Frame size in bytes.
    pub frame_size: u64,
    /// Task/thread ID.
    pub task_id: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl Default for KasanShadowMap {
    fn default() -> Self {
        Self::new()
    }
}

impl KasanShadowMap {
    /// Creates a new, disabled KASAN shadow map.
    pub const fn new() -> Self {
        Self {
            regions: [ShadowRegion {
                kernel_start: 0,
                kernel_end: 0,
                shadow_start: 0,
                shadow_size: 0,
                active: false,
                region_type: ShadowRegionType::KernelImage,
            }; MAX_SHADOW_REGIONS],
            region_count: 0,
            redzones: [RedZoneEntry {
                obj_addr: 0,
                obj_size: 0,
                left_redzone: 0,
                right_redzone: 0,
                shadow_val: 0,
                active: false,
            }; MAX_REDZONES],
            redzone_count: 0,
            stack_entries: [StackShadowEntry {
                frame_addr: 0,
                frame_size: 0,
                task_id: 0,
                active: false,
            }; MAX_STACK_ENTRIES],
            stack_count: 0,
            quarantine: Quarantine::new(),
            report_log: KasanReportLog::new(),
            stats: KasanStats {
                checks: 0,
                violations: 0,
                oob_violations: 0,
                uaf_violations: 0,
                uas_violations: 0,
                double_frees: 0,
                invalid_frees: 0,
                stack_overflows: 0,
                regions_active: 0,
                quarantine_objects: 0,
                quarantine_bytes: 0,
            },
            enabled: false,
            panic_on_violation: false,
            tick: 0,
        }
    }

    /// Enables KASAN checking.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables KASAN checking.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Sets whether to panic on first violation.
    pub fn set_panic_on_violation(&mut self, panic: bool) {
        self.panic_on_violation = panic;
    }

    /// Advances the tick counter.
    fn advance_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Registers a shadow region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the region table is full.
    /// Returns [`Error::InvalidArgument`] if the range is invalid.
    pub fn add_region(
        &mut self,
        kernel_start: u64,
        kernel_end: u64,
        shadow_start: u64,
        region_type: ShadowRegionType,
    ) -> Result<()> {
        if kernel_start >= kernel_end {
            return Err(Error::InvalidArgument);
        }
        if self.region_count >= MAX_SHADOW_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let shadow_size = (kernel_end - kernel_start) / SHADOW_SCALE;
        let slot = self
            .regions
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = ShadowRegion {
            kernel_start,
            kernel_end,
            shadow_start,
            shadow_size,
            active: true,
            region_type,
        };
        self.region_count += 1;
        self.stats.regions_active += 1;
        Ok(())
    }

    /// Removes a shadow region covering the given kernel start.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching region exists.
    pub fn remove_region(&mut self, kernel_start: u64) -> Result<()> {
        let region = self
            .regions
            .iter_mut()
            .find(|r| r.active && r.kernel_start == kernel_start)
            .ok_or(Error::NotFound)?;
        region.active = false;
        self.region_count = self.region_count.saturating_sub(1);
        self.stats.regions_active = self.stats.regions_active.saturating_sub(1);
        Ok(())
    }

    /// Finds the shadow region covering a kernel address.
    fn find_region(&self, addr: u64) -> Option<&ShadowRegion> {
        self.regions
            .iter()
            .find(|r| r.active && addr >= r.kernel_start && addr < r.kernel_end)
    }

    /// Checks whether an access is valid.
    ///
    /// This is the hot-path function called on every instrumented
    /// memory access. Returns `Ok(())` if access is valid, or an
    /// error with the bug type if a violation is detected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the access violates
    /// shadow memory permissions.
    pub fn check_access(
        &mut self,
        addr: u64,
        size: AccessSize,
        access_type: AccessType,
        caller_ip: u64,
        task_id: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.stats.checks += 1;
        let bytes = size.bytes();

        // Check each shadow byte covered by this access.
        let start_shadow = addr / SHADOW_SCALE;
        let end_shadow = (addr + bytes - 1) / SHADOW_SCALE;

        for shadow_offset in start_shadow..=end_shadow {
            let kernel_addr = shadow_offset * SHADOW_SCALE;

            if let Some(region) = self.find_region(kernel_addr) {
                let shadow_addr =
                    region.shadow_start + (kernel_addr - region.kernel_start) / SHADOW_SCALE;

                // In a real kernel: read the actual shadow byte.
                // Here we check against tracked redzones/quarantine.
                if let Some(violation) = self.check_shadow_byte(addr, shadow_addr) {
                    let ts = self.advance_tick();
                    let bug_type = KasanBugType::from_shadow(violation);
                    self.record_violation(
                        ts,
                        addr,
                        shadow_addr,
                        violation.to_byte(),
                        access_type,
                        bytes,
                        bug_type,
                        caller_ip,
                        task_id,
                    );
                    return Err(Error::PermissionDenied);
                }
            }
        }

        Ok(())
    }

    /// Checks a specific shadow byte for violations.
    fn check_shadow_byte(&self, addr: u64, _shadow_addr: u64) -> Option<ShadowValue> {
        // Check quarantine (use-after-free).
        for i in 0..MAX_QUARANTINE {
            let q = &self.quarantine.entries[i];
            if q.in_use && addr >= q.addr && addr < q.addr + q.size {
                return Some(ShadowValue::Freed);
            }
        }

        // Check redzones (out-of-bounds).
        for i in 0..MAX_REDZONES {
            let rz = &self.redzones[i];
            if !rz.active {
                continue;
            }
            let left_start = rz.obj_addr.saturating_sub(rz.left_redzone as u64);
            let left_end = rz.obj_addr;
            let right_start = rz.obj_addr + rz.obj_size;
            let right_end = right_start + rz.right_redzone as u64;

            if addr >= left_start && addr < left_end {
                return Some(ShadowValue::from_byte(rz.shadow_val));
            }
            if addr >= right_start && addr < right_end {
                return Some(ShadowValue::from_byte(rz.shadow_val));
            }
        }

        None
    }

    /// Records a violation in the report log and updates stats.
    fn record_violation(
        &mut self,
        timestamp: u64,
        fault_addr: u64,
        shadow_addr: u64,
        shadow_val: u8,
        access_type: AccessType,
        access_bytes: u64,
        bug_type: KasanBugType,
        caller_ip: u64,
        task_id: u64,
    ) {
        self.stats.violations += 1;

        match bug_type {
            KasanBugType::OutOfBounds
            | KasanBugType::SlabOutOfBounds
            | KasanBugType::GlobalOutOfBounds => {
                self.stats.oob_violations += 1;
            }
            KasanBugType::UseAfterFree => {
                self.stats.uaf_violations += 1;
            }
            KasanBugType::UseAfterScope => {
                self.stats.uas_violations += 1;
            }
            KasanBugType::DoubleFree => {
                self.stats.double_frees += 1;
            }
            KasanBugType::InvalidFree => {
                self.stats.invalid_frees += 1;
            }
            KasanBugType::StackOverflow => {
                self.stats.stack_overflows += 1;
            }
            KasanBugType::WildAccess => {}
        }

        self.report_log.record(KasanReport {
            timestamp,
            fault_addr,
            shadow_addr,
            shadow_val,
            access_type,
            access_bytes,
            bug_type,
            caller_ip,
            task_id,
            in_use: true,
        });
    }

    /// Marks a newly allocated object, setting up redzones.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the redzone table is full.
    pub fn mark_alloc(
        &mut self,
        addr: u64,
        size: u64,
        left_redzone: u32,
        right_redzone: u32,
        shadow_val: u8,
    ) -> Result<()> {
        if self.redzone_count >= MAX_REDZONES {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .redzones
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = RedZoneEntry {
            obj_addr: addr,
            obj_size: size,
            left_redzone,
            right_redzone,
            shadow_val,
            active: true,
        };
        self.redzone_count += 1;
        Ok(())
    }

    /// Marks an object as freed and adds it to quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the address is not a
    /// tracked allocation (potential double-free or invalid free).
    pub fn mark_free(&mut self, addr: u64, size: u64, cache_idx: u32) -> Result<()> {
        // Check for double-free: is it already in quarantine?
        for i in 0..MAX_QUARANTINE {
            let q = &self.quarantine.entries[i];
            if q.in_use && q.addr == addr {
                self.stats.double_frees += 1;
                let ts = self.advance_tick();
                self.report_log.record(KasanReport {
                    timestamp: ts,
                    fault_addr: addr,
                    shadow_addr: 0,
                    shadow_val: ShadowValue::Freed.to_byte(),
                    access_type: AccessType::Free,
                    access_bytes: size,
                    bug_type: KasanBugType::DoubleFree,
                    caller_ip: 0,
                    task_id: 0,
                    in_use: true,
                });
                return Err(Error::InvalidArgument);
            }
        }

        // Remove from redzone tracking.
        for i in 0..MAX_REDZONES {
            if self.redzones[i].active && self.redzones[i].obj_addr == addr {
                self.redzones[i].active = false;
                self.redzone_count = self.redzone_count.saturating_sub(1);
                break;
            }
        }

        // Add to quarantine.
        let tick = self.advance_tick();
        self.quarantine.add(addr, size, cache_idx, tick);
        self.stats.quarantine_objects = self.quarantine.len() as u32;
        self.stats.quarantine_bytes = self.quarantine.current_bytes();

        Ok(())
    }

    /// Registers a stack frame for shadow tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the stack table is full.
    pub fn push_stack_frame(
        &mut self,
        frame_addr: u64,
        frame_size: u64,
        task_id: u64,
    ) -> Result<()> {
        if self.stack_count >= MAX_STACK_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .stack_entries
            .iter_mut()
            .find(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = StackShadowEntry {
            frame_addr,
            frame_size,
            task_id,
            active: true,
        };
        self.stack_count += 1;
        Ok(())
    }

    /// Unregisters a stack frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the frame is not tracked.
    pub fn pop_stack_frame(&mut self, frame_addr: u64, task_id: u64) -> Result<()> {
        let slot = self
            .stack_entries
            .iter_mut()
            .find(|s| s.active && s.frame_addr == frame_addr && s.task_id == task_id)
            .ok_or(Error::NotFound)?;
        slot.active = false;
        self.stack_count = self.stack_count.saturating_sub(1);
        Ok(())
    }

    /// Returns a mutable reference to the quarantine.
    pub fn quarantine_mut(&mut self) -> &mut Quarantine {
        &mut self.quarantine
    }

    /// Returns a reference to the quarantine.
    pub fn quarantine(&self) -> &Quarantine {
        &self.quarantine
    }

    /// Returns a reference to the report log.
    pub fn report_log(&self) -> &KasanReportLog {
        &self.report_log
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &KasanStats {
        &self.stats
    }

    /// Returns the number of active shadow regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Returns `true` if KASAN checking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
