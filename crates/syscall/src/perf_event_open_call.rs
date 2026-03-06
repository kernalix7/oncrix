// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `perf_event_open(2)` — high-level performance monitoring call interface.
//!
//! Builds on the low-level types in [`crate::perf_event_open`] to provide a
//! typed, validated syscall entry point for creating and managing performance
//! monitoring event file descriptors.  Implements hardware/software counter
//! configuration, sampling setup, and event group management.
//!
//! # Architecture
//!
//! ```text
//! user space                         kernel space
//! ──────────                         ─────────────
//! perf_event_open(attr, pid,         validate_perf_args()
//!                 cpu, group_fd,     → PerfCallArgs::from_raw()
//!                 flags)             → configure_sampling()
//!                                    → sys_perf_event_open_call()
//!                                ◄── fd / -errno
//! ```
//!
//! # Key types
//!
//! - [`PerfEventAttrExt`] — extended attribute with sampling configuration
//! - [`PerfType`] — strongly-typed event type enum
//! - [`PerfConfig`] — type-safe event configuration
//! - [`SampleType`] — bitmask wrapper for sample fields
//! - [`PerfCallArgs`] — validated argument bundle for the syscall
//!
//! # POSIX context
//!
//! `perf_event_open` is a Linux-specific syscall (not defined by POSIX).
//! ONCRIX implements it for compatibility with Linux performance tools
//! (perf, bpftrace, etc.).
//!
//! # References
//!
//! - Linux: `kernel/events/core.c`, `include/uapi/linux/perf_event.h`
//! - `perf_event_open(2)` man page

use oncrix_lib::{Error, Result};

use crate::perf_event_open::{PerfEventAttr, PerfEventContext, sys_perf_event_open};

// Local constants mirroring perf_event_open module (which keeps some private).
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_TYPE_HW_CACHE: u32 = 3;
const PERF_TYPE_RAW: u32 = 4;
const PERF_TYPE_BREAKPOINT: u32 = 5;

const PERF_COUNT_HW_MAX: u64 = 10;
const PERF_COUNT_SW_MAX: u64 = 9;

const PERF_SAMPLE_IP: u64 = 1 << 0;
const PERF_SAMPLE_TID: u64 = 1 << 1;
const PERF_SAMPLE_TIME: u64 = 1 << 2;
const PERF_SAMPLE_ADDR: u64 = 1 << 3;
const PERF_SAMPLE_READ: u64 = 1 << 4;
const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
const PERF_SAMPLE_ID: u64 = 1 << 6;
const PERF_SAMPLE_CPU: u64 = 1 << 7;
const PERF_SAMPLE_PERIOD: u64 = 1 << 8;

const PERF_FLAG_FD_NO_GROUP: u64 = 1 << 0;
const PERF_FLAG_FD_OUTPUT: u64 = 1 << 1;
const PERF_FLAG_PID_CGROUP: u64 = 1 << 2;
const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

// ---------------------------------------------------------------------------
// PerfType — strongly-typed event type enum
// ---------------------------------------------------------------------------

/// Strongly-typed performance event type.
///
/// Converts the raw `PERF_TYPE_*` constant into a type-safe enum,
/// carrying the associated configuration value so that type/config
/// mismatches are caught at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfType {
    /// CPU hardware counter (cycles, instructions, cache, branches).
    Hardware(HardwareEvent),
    /// Kernel software counter (page faults, context switches, etc.).
    Software(SoftwareEvent),
    /// Static tracepoint identified by a tracepoint ID.
    Tracepoint(u64),
    /// Hardware cache counter encoded as `(cache_id, op, result)`.
    HwCache(CacheId, CacheOp, CacheResult),
    /// Raw architecture-specific PMU event code.
    Raw(u64),
    /// Hardware breakpoint at a given address.
    Breakpoint(u64),
}

impl PerfType {
    /// Convert to the raw `(type, config)` pair for [`PerfEventAttr`].
    pub const fn to_raw(&self) -> (u32, u64) {
        match *self {
            Self::Hardware(ev) => (PERF_TYPE_HARDWARE, ev.to_raw()),
            Self::Software(ev) => (PERF_TYPE_SOFTWARE, ev.to_raw()),
            Self::Tracepoint(id) => (PERF_TYPE_TRACEPOINT, id),
            Self::HwCache(cid, cop, cres) => {
                let config = (cid as u64) | ((cop as u64) << 8) | ((cres as u64) << 16);
                (PERF_TYPE_HW_CACHE, config)
            }
            Self::Raw(code) => (PERF_TYPE_RAW, code),
            Self::Breakpoint(addr) => (PERF_TYPE_BREAKPOINT, addr),
        }
    }

    /// Construct from raw `(type, config)` values, validating them.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for unknown types or invalid configs.
    pub fn from_raw(event_type: u32, config: u64) -> Result<Self> {
        match event_type {
            PERF_TYPE_HARDWARE => {
                let ev = HardwareEvent::from_raw(config)?;
                Ok(Self::Hardware(ev))
            }
            PERF_TYPE_SOFTWARE => {
                let ev = SoftwareEvent::from_raw(config)?;
                Ok(Self::Software(ev))
            }
            PERF_TYPE_TRACEPOINT => {
                if config == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::Tracepoint(config))
            }
            PERF_TYPE_HW_CACHE => {
                let cid = CacheId::from_raw((config & 0xFF) as u8)?;
                let cop = CacheOp::from_raw(((config >> 8) & 0xFF) as u8)?;
                let cres = CacheResult::from_raw(((config >> 16) & 0xFF) as u8)?;
                Ok(Self::HwCache(cid, cop, cres))
            }
            PERF_TYPE_RAW => Ok(Self::Raw(config)),
            PERF_TYPE_BREAKPOINT => Ok(Self::Breakpoint(config)),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// HardwareEvent — typed hardware counter IDs
// ---------------------------------------------------------------------------

/// Hardware performance counter event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HardwareEvent {
    /// Total CPU cycles.
    CpuCycles = 0,
    /// Retired instructions.
    Instructions = 1,
    /// Cache references (accesses).
    CacheReferences = 2,
    /// Cache misses.
    CacheMisses = 3,
    /// Retired branch instructions.
    BranchInstructions = 4,
    /// Branch mispredictions.
    BranchMisses = 5,
    /// Bus cycles.
    BusCycles = 6,
    /// Stalled cycles (front-end).
    StalledCyclesFrontend = 7,
    /// Stalled cycles (back-end).
    StalledCyclesBackend = 8,
    /// Reference CPU cycles (unscaled).
    RefCpuCycles = 9,
}

impl HardwareEvent {
    /// Convert to the raw config value.
    pub const fn to_raw(self) -> u64 {
        self as u64
    }

    /// Construct from a raw config value.
    pub fn from_raw(config: u64) -> Result<Self> {
        if config >= PERF_COUNT_HW_MAX {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: all values 0..PERF_COUNT_HW_MAX are valid enum variants.
        match config {
            0 => Ok(Self::CpuCycles),
            1 => Ok(Self::Instructions),
            2 => Ok(Self::CacheReferences),
            3 => Ok(Self::CacheMisses),
            4 => Ok(Self::BranchInstructions),
            5 => Ok(Self::BranchMisses),
            6 => Ok(Self::BusCycles),
            7 => Ok(Self::StalledCyclesFrontend),
            8 => Ok(Self::StalledCyclesBackend),
            9 => Ok(Self::RefCpuCycles),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// SoftwareEvent — typed software counter IDs
// ---------------------------------------------------------------------------

/// Software performance counter event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SoftwareEvent {
    /// CPU clock (nanoseconds).
    CpuClock = 0,
    /// Task clock (nanoseconds on-CPU).
    TaskClock = 1,
    /// Total page faults.
    PageFaults = 2,
    /// Context switches.
    ContextSwitches = 3,
    /// CPU migrations.
    CpuMigrations = 4,
    /// Minor page faults (no I/O).
    PageFaultsMin = 5,
    /// Major page faults (I/O required).
    PageFaultsMaj = 6,
    /// Alignment faults.
    AlignmentFaults = 7,
    /// Emulation faults.
    EmulationFaults = 8,
}

impl SoftwareEvent {
    /// Convert to the raw config value.
    pub const fn to_raw(self) -> u64 {
        self as u64
    }

    /// Construct from a raw config value.
    pub fn from_raw(config: u64) -> Result<Self> {
        if config >= PERF_COUNT_SW_MAX {
            return Err(Error::InvalidArgument);
        }
        match config {
            0 => Ok(Self::CpuClock),
            1 => Ok(Self::TaskClock),
            2 => Ok(Self::PageFaults),
            3 => Ok(Self::ContextSwitches),
            4 => Ok(Self::CpuMigrations),
            5 => Ok(Self::PageFaultsMin),
            6 => Ok(Self::PageFaultsMaj),
            7 => Ok(Self::AlignmentFaults),
            8 => Ok(Self::EmulationFaults),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// CacheId / CacheOp / CacheResult — typed cache event components
// ---------------------------------------------------------------------------

/// Hardware cache identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheId {
    /// Level 1 data cache.
    L1d = 0,
    /// Level 1 instruction cache.
    L1i = 1,
    /// Last-level cache.
    Ll = 2,
    /// Data TLB.
    Dtlb = 3,
    /// Instruction TLB.
    Itlb = 4,
    /// Branch prediction unit.
    Bpu = 5,
    /// Node-level (NUMA) cache.
    Node = 6,
}

impl CacheId {
    /// Construct from raw value.
    pub fn from_raw(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::L1d),
            1 => Ok(Self::L1i),
            2 => Ok(Self::Ll),
            3 => Ok(Self::Dtlb),
            4 => Ok(Self::Itlb),
            5 => Ok(Self::Bpu),
            6 => Ok(Self::Node),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Hardware cache operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheOp {
    /// Read access.
    Read = 0,
    /// Write access.
    Write = 1,
    /// Prefetch.
    Prefetch = 2,
}

impl CacheOp {
    /// Construct from raw value.
    pub fn from_raw(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Prefetch),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Hardware cache access result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheResult {
    /// Access (hit or miss).
    Access = 0,
    /// Miss.
    Miss = 1,
}

impl CacheResult {
    /// Construct from raw value.
    pub fn from_raw(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Access),
            1 => Ok(Self::Miss),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// SampleType — typed sample field bitmask
// ---------------------------------------------------------------------------

/// Bitmask wrapper for `PERF_SAMPLE_*` flags.
///
/// Controls which fields are included in each sample record written
/// to the mmap ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SampleType(u64);

/// Mask of all known sample type bits.
const SAMPLE_TYPE_VALID: u64 = PERF_SAMPLE_IP
    | PERF_SAMPLE_TID
    | PERF_SAMPLE_TIME
    | PERF_SAMPLE_ADDR
    | PERF_SAMPLE_READ
    | PERF_SAMPLE_CALLCHAIN
    | PERF_SAMPLE_ID
    | PERF_SAMPLE_CPU
    | PERF_SAMPLE_PERIOD;

impl SampleType {
    /// Construct from a raw `u64`, rejecting unknown bits.
    pub fn from_raw(raw: u64) -> Result<Self> {
        if raw & !SAMPLE_TYPE_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bitmask.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Whether instruction pointer is sampled.
    pub const fn has_ip(&self) -> bool {
        self.0 & PERF_SAMPLE_IP != 0
    }

    /// Whether thread/process IDs are sampled.
    pub const fn has_tid(&self) -> bool {
        self.0 & PERF_SAMPLE_TID != 0
    }

    /// Whether timestamp is sampled.
    pub const fn has_time(&self) -> bool {
        self.0 & PERF_SAMPLE_TIME != 0
    }

    /// Whether address is sampled.
    pub const fn has_addr(&self) -> bool {
        self.0 & PERF_SAMPLE_ADDR != 0
    }

    /// Whether counter value is included in read format.
    pub const fn has_read(&self) -> bool {
        self.0 & PERF_SAMPLE_READ != 0
    }

    /// Whether call chain is sampled.
    pub const fn has_callchain(&self) -> bool {
        self.0 & PERF_SAMPLE_CALLCHAIN != 0
    }

    /// Whether event ID is sampled.
    pub const fn has_id(&self) -> bool {
        self.0 & PERF_SAMPLE_ID != 0
    }

    /// Whether CPU number is sampled.
    pub const fn has_cpu(&self) -> bool {
        self.0 & PERF_SAMPLE_CPU != 0
    }

    /// Whether sample period is included.
    pub const fn has_period(&self) -> bool {
        self.0 & PERF_SAMPLE_PERIOD != 0
    }

    /// Compute the size in bytes of a single sample record.
    ///
    /// Each set bit adds 8 bytes (one u64) to the record, except
    /// `CALLCHAIN` which adds a variable-length header (stub: 8 bytes).
    pub const fn record_size(&self) -> usize {
        let mut size = 0usize;
        if self.has_ip() {
            size += 8;
        }
        if self.has_tid() {
            size += 8;
        }
        if self.has_time() {
            size += 8;
        }
        if self.has_addr() {
            size += 8;
        }
        if self.has_read() {
            size += 8;
        }
        if self.has_callchain() {
            size += 8;
        }
        if self.has_id() {
            size += 8;
        }
        if self.has_cpu() {
            size += 8;
        }
        if self.has_period() {
            size += 8;
        }
        size
    }
}

// ---------------------------------------------------------------------------
// PerfConfig — unified, type-safe event configuration
// ---------------------------------------------------------------------------

/// Unified event configuration combining type and config into a
/// single validated structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfConfig {
    /// Strongly-typed event type + config.
    pub event: PerfType,
    /// Sample type bitmask.
    pub sample_type: SampleType,
    /// Sampling period (0 = counting mode, >0 = sampling mode).
    pub sample_period: u64,
    /// Whether the period field is actually a frequency.
    pub freq: bool,
}

impl PerfConfig {
    /// Create a hardware counting configuration (no sampling).
    pub fn hardware_counter(event: HardwareEvent) -> Result<Self> {
        Ok(Self {
            event: PerfType::Hardware(event),
            sample_type: SampleType::from_raw(0)?,
            sample_period: 0,
            freq: false,
        })
    }

    /// Create a software counting configuration.
    pub fn software_counter(event: SoftwareEvent) -> Result<Self> {
        Ok(Self {
            event: PerfType::Software(event),
            sample_type: SampleType::from_raw(0)?,
            sample_period: 0,
            freq: false,
        })
    }

    /// Create a hardware sampling configuration.
    pub fn hardware_sampled(
        event: HardwareEvent,
        period: u64,
        sample_type: SampleType,
    ) -> Result<Self> {
        if period == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            event: PerfType::Hardware(event),
            sample_type,
            sample_period: period,
            freq: false,
        })
    }

    /// Create a frequency-based sampling configuration.
    pub fn frequency_sampled(
        event: HardwareEvent,
        frequency: u64,
        sample_type: SampleType,
    ) -> Result<Self> {
        if frequency == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            event: PerfType::Hardware(event),
            sample_type,
            sample_period: frequency,
            freq: true,
        })
    }

    /// Build a [`PerfEventAttr`] from this configuration.
    pub fn to_attr(&self) -> PerfEventAttr {
        let (event_type, config) = self.event.to_raw();
        let mut attr = PerfEventAttr::new();
        attr.event_type = event_type;
        attr.config = config;
        attr.sample_type = self.sample_type.bits();
        attr.sample_period_or_freq = self.sample_period;
        if self.freq {
            attr.flags |= 1 << 10; // freq bit
        }
        attr
    }
}

// ---------------------------------------------------------------------------
// PerfCallFlags — typed syscall flags
// ---------------------------------------------------------------------------

/// Validated `perf_event_open` syscall flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PerfCallFlags(u64);

/// Mask of all valid perf_event_open flags.
const PERF_CALL_FLAGS_VALID: u64 =
    PERF_FLAG_FD_NO_GROUP | PERF_FLAG_FD_OUTPUT | PERF_FLAG_PID_CGROUP | PERF_FLAG_FD_CLOEXEC;

impl PerfCallFlags {
    /// Construct from raw flags, rejecting unknown bits.
    pub fn from_raw(raw: u64) -> Result<Self> {
        if raw & !PERF_CALL_FLAGS_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bit pattern.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Whether `PERF_FLAG_FD_NO_GROUP` is set.
    pub const fn no_group(&self) -> bool {
        self.0 & PERF_FLAG_FD_NO_GROUP != 0
    }

    /// Whether `PERF_FLAG_FD_OUTPUT` is set.
    pub const fn fd_output(&self) -> bool {
        self.0 & PERF_FLAG_FD_OUTPUT != 0
    }

    /// Whether `PERF_FLAG_PID_CGROUP` is set.
    pub const fn pid_cgroup(&self) -> bool {
        self.0 & PERF_FLAG_PID_CGROUP != 0
    }

    /// Whether `PERF_FLAG_FD_CLOEXEC` is set.
    pub const fn cloexec(&self) -> bool {
        self.0 & PERF_FLAG_FD_CLOEXEC != 0
    }
}

// ---------------------------------------------------------------------------
// PerfCallArgs — validated argument bundle
// ---------------------------------------------------------------------------

/// Maximum number of CPUs for targeting validation.
const MAX_CPUS: i32 = 256;

/// Sentinel for "no group leader" (standalone event).
const NO_GROUP: i32 = -1;

/// Validated argument bundle for `perf_event_open`.
///
/// Constructed via [`PerfCallArgs::from_raw`], which performs all
/// validation before any kernel state is touched.
#[derive(Debug, Clone, Copy)]
pub struct PerfCallArgs {
    /// Event configuration.
    pub config: PerfConfig,
    /// Target process ID (0 = self, -1 = all).
    pub pid: i32,
    /// Target CPU (-1 = any).
    pub cpu: i32,
    /// Group leader fd (-1 = standalone).
    pub group_fd: i32,
    /// Validated flags.
    pub flags: PerfCallFlags,
}

impl PerfCallArgs {
    /// Construct from raw syscall arguments, validating everything.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — bad type/config, pid/cpu combination,
    ///   unknown flags, or cgroup flag without valid pid.
    pub fn from_raw(
        event_type: u32,
        config: u64,
        sample_type: u64,
        sample_period: u64,
        freq: bool,
        pid: i32,
        cpu: i32,
        group_fd: i32,
        raw_flags: u64,
    ) -> Result<Self> {
        let event = PerfType::from_raw(event_type, config)?;
        let st = SampleType::from_raw(sample_type)?;
        let flags = PerfCallFlags::from_raw(raw_flags)?;

        // Validate targeting: pid == -1 && cpu == -1 is invalid.
        if pid == -1 && cpu == -1 {
            return Err(Error::InvalidArgument);
        }
        // cpu must be -1 or in [0, MAX_CPUS).
        if cpu != -1 && (cpu < 0 || cpu >= MAX_CPUS) {
            return Err(Error::InvalidArgument);
        }
        // PID_CGROUP requires pid >= 0.
        if flags.pid_cgroup() && pid < 0 {
            return Err(Error::InvalidArgument);
        }
        // Sampling period must be non-zero when sample_type is set.
        if st.bits() != 0 && sample_period == 0 && !freq {
            // Counting mode with sample flags is allowed (they apply
            // to the read format), so this is not an error.
        }

        let perf_config = PerfConfig {
            event,
            sample_type: st,
            sample_period,
            freq,
        };

        Ok(Self {
            config: perf_config,
            pid,
            cpu,
            group_fd,
            flags,
        })
    }
}

// ---------------------------------------------------------------------------
// PerfEventAttrExt — extended attribute with additional metadata
// ---------------------------------------------------------------------------

/// Extended performance event attribute with sampling configuration.
///
/// Wraps [`PerfEventAttr`] with additional sampling parameters that
/// are validated and computed at construction time.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttrExt {
    /// Base attribute.
    pub attr: PerfEventAttr,
    /// Computed sample record size in bytes.
    pub sample_record_size: usize,
    /// Whether sampling is enabled.
    pub sampling_enabled: bool,
    /// Desired mmap ring buffer size (pages, must be power of 2 + 1).
    pub mmap_pages: u32,
    /// Watermark in bytes for wakeup (0 = wakeup on every sample).
    pub watermark: u32,
}

impl PerfEventAttrExt {
    /// Create from a [`PerfConfig`] with the given mmap buffer size.
    ///
    /// # Arguments
    ///
    /// * `config` — validated event configuration
    /// * `mmap_pages` — number of mmap pages (must be power of 2)
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `mmap_pages` is not a power of 2.
    pub fn from_config(config: &PerfConfig, mmap_pages: u32) -> Result<Self> {
        if mmap_pages != 0 && (mmap_pages & (mmap_pages - 1)) != 0 {
            return Err(Error::InvalidArgument);
        }
        let attr = config.to_attr();
        let sample_record_size = config.sample_type.record_size();
        let sampling_enabled = config.sample_period > 0;

        Ok(Self {
            attr,
            sample_record_size,
            sampling_enabled,
            mmap_pages,
            watermark: 0,
        })
    }

    /// Set the watermark (wakeup threshold in bytes).
    pub fn set_watermark(&mut self, watermark: u32) {
        self.watermark = watermark;
        if watermark > 0 {
            self.attr.flags |= 1 << 14; // watermark bit
            self.attr.wakeup_events_or_watermark = watermark;
        }
    }

    /// Set the wakeup event count.
    pub fn set_wakeup_events(&mut self, count: u32) {
        self.attr.flags &= !(1 << 14); // clear watermark bit
        self.attr.wakeup_events_or_watermark = count;
    }
}

// ---------------------------------------------------------------------------
// sys_perf_event_open_call — high-level syscall handler
// ---------------------------------------------------------------------------

/// High-level `perf_event_open` syscall handler.
///
/// Accepts a [`PerfCallArgs`] bundle (pre-validated from raw register
/// values) and delegates to the low-level
/// [`sys_perf_event_open`] after building the kernel-side attribute.
///
/// # Arguments
///
/// * `ctx` — per-process perf event context
/// * `args` — validated call arguments
///
/// # Returns
///
/// File descriptor for the new event.
///
/// # Errors
///
/// * `InvalidArgument` — bad attributes, targeting, or flags
/// * `OutOfMemory` — no free event slots
/// * `NotFound` — group leader fd not found
pub fn sys_perf_event_open_call(ctx: &mut PerfEventContext, args: &PerfCallArgs) -> Result<i32> {
    let attr = args.config.to_attr();
    sys_perf_event_open(
        ctx,
        &attr,
        args.pid,
        args.cpu,
        args.group_fd,
        args.flags.bits(),
    )
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Open a simple hardware counting event on the calling process, any CPU.
///
/// Shorthand for the most common `perf_event_open` usage.
///
/// # Arguments
///
/// * `ctx` — per-process perf event context
/// * `event` — hardware event to monitor
///
/// # Returns
///
/// File descriptor for the new counting event.
pub fn open_hw_counter(ctx: &mut PerfEventContext, event: HardwareEvent) -> Result<i32> {
    let config = PerfConfig::hardware_counter(event)?;
    let attr = config.to_attr();
    sys_perf_event_open(ctx, &attr, 0, -1, NO_GROUP, 0)
}

/// Open a simple software counting event on the calling process, any CPU.
pub fn open_sw_counter(ctx: &mut PerfEventContext, event: SoftwareEvent) -> Result<i32> {
    let config = PerfConfig::software_counter(event)?;
    let attr = config.to_attr();
    sys_perf_event_open(ctx, &attr, 0, -1, NO_GROUP, 0)
}

/// Open a hardware sampling event with IP + TID + TIME sample fields.
///
/// # Arguments
///
/// * `ctx` — per-process perf event context
/// * `event` — hardware event to sample
/// * `period` — sample every N events
///
/// # Returns
///
/// File descriptor for the new sampling event.
pub fn open_hw_sampled(
    ctx: &mut PerfEventContext,
    event: HardwareEvent,
    period: u64,
) -> Result<i32> {
    let sample_type = SampleType::from_raw(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME)?;
    let config = PerfConfig::hardware_sampled(event, period, sample_type)?;
    let attr = config.to_attr();
    sys_perf_event_open(ctx, &attr, 0, -1, NO_GROUP, 0)
}

/// Open a group of hardware events.
///
/// The first event becomes the group leader; subsequent events are
/// added to the group.  Returns the file descriptors in order.
///
/// # Arguments
///
/// * `ctx` — per-process perf event context
/// * `events` — slice of hardware events (max 16)
///
/// # Returns
///
/// Array of file descriptors, one per event.
///
/// # Errors
///
/// * `InvalidArgument` — empty slice or more than 16 events
/// * `OutOfMemory` — no free event slots
pub fn open_hw_group(ctx: &mut PerfEventContext, events: &[HardwareEvent]) -> Result<(i32, usize)> {
    if events.is_empty() || events.len() > 16 {
        return Err(Error::InvalidArgument);
    }

    // Open the group leader.
    let leader_fd = open_hw_counter(ctx, events[0])?;
    let mut count = 1usize;

    // Open group members.
    for event in &events[1..] {
        let config = PerfConfig::hardware_counter(*event)?;
        let attr = config.to_attr();
        let _fd = sys_perf_event_open(ctx, &attr, 0, -1, leader_fd, 0)?;
        count += 1;
    }

    Ok((leader_fd, count))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perf_type_hardware_roundtrip() {
        let pt = PerfType::Hardware(HardwareEvent::CpuCycles);
        let (ty, cfg) = pt.to_raw();
        assert_eq!(ty, PERF_TYPE_HARDWARE);
        assert_eq!(cfg, PERF_COUNT_HW_CPU_CYCLES);

        let reconstructed = PerfType::from_raw(ty, cfg).unwrap();
        assert_eq!(reconstructed, pt);
    }

    #[test]
    fn test_perf_type_software_roundtrip() {
        let pt = PerfType::Software(SoftwareEvent::ContextSwitches);
        let (ty, cfg) = pt.to_raw();
        assert_eq!(ty, PERF_TYPE_SOFTWARE);
        assert_eq!(cfg, 3);

        let reconstructed = PerfType::from_raw(ty, cfg).unwrap();
        assert_eq!(reconstructed, pt);
    }

    #[test]
    fn test_perf_type_hw_cache_roundtrip() {
        let pt = PerfType::HwCache(CacheId::L1d, CacheOp::Read, CacheResult::Miss);
        let (ty, cfg) = pt.to_raw();
        assert_eq!(ty, PERF_TYPE_HW_CACHE);
        assert_eq!(cfg, 0 | (0 << 8) | (1 << 16));

        let reconstructed = PerfType::from_raw(ty, cfg).unwrap();
        assert_eq!(reconstructed, pt);
    }

    #[test]
    fn test_perf_type_invalid_hw_config() {
        assert!(PerfType::from_raw(PERF_TYPE_HARDWARE, 999).is_err());
    }

    #[test]
    fn test_perf_type_invalid_type() {
        assert!(PerfType::from_raw(99, 0).is_err());
    }

    #[test]
    fn test_perf_type_tracepoint_zero_config() {
        assert!(PerfType::from_raw(PERF_TYPE_TRACEPOINT, 0).is_err());
    }

    #[test]
    fn test_sample_type_valid() {
        let st = SampleType::from_raw(PERF_SAMPLE_IP | PERF_SAMPLE_TID).unwrap();
        assert!(st.has_ip());
        assert!(st.has_tid());
        assert!(!st.has_time());
    }

    #[test]
    fn test_sample_type_invalid_bits() {
        assert!(SampleType::from_raw(1 << 63).is_err());
    }

    #[test]
    fn test_sample_type_record_size() {
        let st = SampleType::from_raw(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME).unwrap();
        assert_eq!(st.record_size(), 24);
    }

    #[test]
    fn test_perf_config_hardware_counter() {
        let config = PerfConfig::hardware_counter(HardwareEvent::Instructions).unwrap();
        let attr = config.to_attr();
        assert_eq!(attr.event_type, PERF_TYPE_HARDWARE);
        assert_eq!(attr.config, 1);
        assert_eq!(attr.sample_period_or_freq, 0);
    }

    #[test]
    fn test_perf_config_hardware_sampled() {
        let st = SampleType::from_raw(PERF_SAMPLE_IP).unwrap();
        let config = PerfConfig::hardware_sampled(HardwareEvent::CpuCycles, 1000, st).unwrap();
        assert_eq!(config.sample_period, 1000);
        assert!(!config.freq);
    }

    #[test]
    fn test_perf_config_hardware_sampled_zero_period() {
        let st = SampleType::from_raw(PERF_SAMPLE_IP).unwrap();
        assert!(PerfConfig::hardware_sampled(HardwareEvent::CpuCycles, 0, st,).is_err());
    }

    #[test]
    fn test_perf_config_frequency_sampled() {
        let st = SampleType::from_raw(PERF_SAMPLE_IP).unwrap();
        let config = PerfConfig::frequency_sampled(HardwareEvent::CpuCycles, 4000, st).unwrap();
        assert!(config.freq);
        let attr = config.to_attr();
        assert!(attr.is_freq());
    }

    #[test]
    fn test_perf_call_flags_valid() {
        let f = PerfCallFlags::from_raw(PERF_FLAG_FD_CLOEXEC).unwrap();
        assert!(f.cloexec());
        assert!(!f.no_group());
    }

    #[test]
    fn test_perf_call_flags_invalid() {
        assert!(PerfCallFlags::from_raw(1 << 62).is_err());
    }

    #[test]
    fn test_perf_call_args_valid() {
        let args = PerfCallArgs::from_raw(
            PERF_TYPE_HARDWARE,
            PERF_COUNT_HW_CPU_CYCLES,
            0,
            0,
            false,
            0,
            -1,
            -1,
            0,
        )
        .unwrap();
        assert_eq!(args.pid, 0);
        assert_eq!(args.cpu, -1);
    }

    #[test]
    fn test_perf_call_args_invalid_targeting() {
        assert!(
            PerfCallArgs::from_raw(
                PERF_TYPE_HARDWARE,
                PERF_COUNT_HW_CPU_CYCLES,
                0,
                0,
                false,
                -1,
                -1,
                -1,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn test_perf_call_args_cgroup_requires_pid() {
        assert!(
            PerfCallArgs::from_raw(
                PERF_TYPE_HARDWARE,
                PERF_COUNT_HW_CPU_CYCLES,
                0,
                0,
                false,
                -1,
                0,
                -1,
                PERF_FLAG_PID_CGROUP,
            )
            .is_err()
        );
    }

    #[test]
    fn test_perf_event_attr_ext() {
        let config = PerfConfig::hardware_counter(HardwareEvent::CpuCycles).unwrap();
        let ext = PerfEventAttrExt::from_config(&config, 16).unwrap();
        assert!(!ext.sampling_enabled);
        assert_eq!(ext.mmap_pages, 16);
    }

    #[test]
    fn test_perf_event_attr_ext_bad_mmap_pages() {
        let config = PerfConfig::hardware_counter(HardwareEvent::CpuCycles).unwrap();
        assert!(PerfEventAttrExt::from_config(&config, 3).is_err());
    }

    #[test]
    fn test_sys_perf_event_open_call() {
        let mut ctx = PerfEventContext::new();
        let args = PerfCallArgs::from_raw(
            PERF_TYPE_HARDWARE,
            PERF_COUNT_HW_CPU_CYCLES,
            0,
            0,
            false,
            0,
            -1,
            -1,
            0,
        )
        .unwrap();
        let fd = sys_perf_event_open_call(&mut ctx, &args).unwrap();
        assert!(fd >= 0);
        assert_eq!(ctx.event_count(), 1);
    }

    #[test]
    fn test_open_hw_counter() {
        let mut ctx = PerfEventContext::new();
        let fd = open_hw_counter(&mut ctx, HardwareEvent::Instructions).unwrap();
        assert!(fd >= 0);
    }

    #[test]
    fn test_open_sw_counter() {
        let mut ctx = PerfEventContext::new();
        let fd = open_sw_counter(&mut ctx, SoftwareEvent::PageFaults).unwrap();
        assert!(fd >= 0);
    }

    #[test]
    fn test_open_hw_sampled() {
        let mut ctx = PerfEventContext::new();
        let fd = open_hw_sampled(&mut ctx, HardwareEvent::CpuCycles, 10000).unwrap();
        assert!(fd >= 0);
    }

    #[test]
    fn test_open_hw_group() {
        let mut ctx = PerfEventContext::new();
        let events = [
            HardwareEvent::CpuCycles,
            HardwareEvent::Instructions,
            HardwareEvent::CacheMisses,
        ];
        let (leader_fd, count) = open_hw_group(&mut ctx, &events).unwrap();
        assert!(leader_fd >= 0);
        assert_eq!(count, 3);
        assert_eq!(ctx.event_count(), 3);
    }

    #[test]
    fn test_open_hw_group_empty() {
        let mut ctx = PerfEventContext::new();
        assert!(open_hw_group(&mut ctx, &[]).is_err());
    }

    #[test]
    fn test_cache_id_from_raw() {
        assert_eq!(CacheId::from_raw(0).unwrap(), CacheId::L1d);
        assert_eq!(CacheId::from_raw(6).unwrap(), CacheId::Node);
        assert!(CacheId::from_raw(7).is_err());
    }

    #[test]
    fn test_cache_op_from_raw() {
        assert_eq!(CacheOp::from_raw(0).unwrap(), CacheOp::Read);
        assert_eq!(CacheOp::from_raw(2).unwrap(), CacheOp::Prefetch);
        assert!(CacheOp::from_raw(3).is_err());
    }

    #[test]
    fn test_cache_result_from_raw() {
        assert_eq!(CacheResult::from_raw(0).unwrap(), CacheResult::Access);
        assert_eq!(CacheResult::from_raw(1).unwrap(), CacheResult::Miss);
        assert!(CacheResult::from_raw(2).is_err());
    }

    #[test]
    fn test_attr_ext_watermark() {
        let st = SampleType::from_raw(PERF_SAMPLE_IP).unwrap();
        let config = PerfConfig::hardware_sampled(HardwareEvent::CpuCycles, 1000, st).unwrap();
        let mut ext = PerfEventAttrExt::from_config(&config, 16).unwrap();
        ext.set_watermark(4096);
        assert_eq!(ext.watermark, 4096);
        assert_eq!(ext.attr.wakeup_events_or_watermark, 4096);
    }

    #[test]
    fn test_attr_ext_wakeup_events() {
        let config = PerfConfig::hardware_counter(HardwareEvent::CpuCycles).unwrap();
        let mut ext = PerfEventAttrExt::from_config(&config, 0).unwrap();
        ext.set_wakeup_events(10);
        assert_eq!(ext.attr.wakeup_events_or_watermark, 10);
    }

    #[test]
    fn test_hardware_event_from_raw_all() {
        for i in 0..10u64 {
            assert!(HardwareEvent::from_raw(i).is_ok());
        }
        assert!(HardwareEvent::from_raw(10).is_err());
    }

    #[test]
    fn test_software_event_from_raw_all() {
        for i in 0..9u64 {
            assert!(SoftwareEvent::from_raw(i).is_ok());
        }
        assert!(SoftwareEvent::from_raw(9).is_err());
    }
}
