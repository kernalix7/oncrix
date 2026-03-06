// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel timekeeping subsystem.
//!
//! Maintains the kernel's notion of time using hardware clock
//! sources. Provides wall-clock time, monotonic time, and boot
//! time through `ktime_get` variants. Uses a clock source with
//! `mult` and `shift` parameters to convert hardware counter
//! readings to nanoseconds.
//!
//! # Timebases
//!
//! | Timebase | Description |
//! |----------|-------------|
//! | Wall | Real-world (UTC) time, settable |
//! | Monotonic | Never goes backwards, not settable |
//! | Boottime | Like monotonic, includes suspend time |
//! | Raw | Direct hardware counter, no NTP adj. |
//!
//! # Clock Source Conversion
//!
//! ```text
//! ns = (cycles * mult) >> shift
//! ```
//!
//! # Architecture
//!
//! ```text
//! Timekeeper
//! ├── clock_source: ClockSource
//! │   ├── read_fn, mult, shift, mask
//! │   └── max_idle_ns
//! ├── wall_time: TimeSpec
//! ├── monotonic_offset: u64
//! ├── boot_offset: u64
//! └── stats: TimekeepingStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/time/timekeeping.c`, `include/linux/timekeeper_internal.h`,
//! `include/linux/clocksource.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of registered clock sources.
const MAX_CLOCK_SOURCES: usize = 16;

/// Maximum clock source name length.
const MAX_NAME_LEN: usize = 32;

/// Default shift value for clock conversion.
const _DEFAULT_SHIFT: u32 = 20;

/// Nanoseconds per second.
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Nanoseconds per millisecond.
const _NSEC_PER_MSEC: u64 = 1_000_000;

/// Nanoseconds per microsecond.
const _NSEC_PER_USEC: u64 = 1_000;

// ── TimeSpec ────────────────────────────────────────────────

/// A time value with seconds and nanoseconds components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeSpec {
    /// Seconds.
    pub sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub nsec: u32,
}

impl TimeSpec {
    /// Create a zero timespec.
    pub const fn zero() -> Self {
        Self { sec: 0, nsec: 0 }
    }

    /// Create from seconds and nanoseconds.
    pub const fn new(sec: i64, nsec: u32) -> Self {
        Self { sec, nsec }
    }

    /// Convert to total nanoseconds (may overflow for large values).
    pub fn to_ns(&self) -> u64 {
        (self.sec as u64)
            .wrapping_mul(NSEC_PER_SEC)
            .wrapping_add(self.nsec as u64)
    }

    /// Create from nanoseconds.
    pub fn from_ns(ns: u64) -> Self {
        Self {
            sec: (ns / NSEC_PER_SEC) as i64,
            nsec: (ns % NSEC_PER_SEC) as u32,
        }
    }

    /// Normalise: ensure nsec is in [0, 999_999_999].
    pub fn normalise(&mut self) {
        while self.nsec >= NSEC_PER_SEC as u32 {
            self.sec += 1;
            self.nsec -= NSEC_PER_SEC as u32;
        }
    }

    /// Add two timespecs.
    pub fn add(&self, other: &TimeSpec) -> TimeSpec {
        let mut result = TimeSpec {
            sec: self.sec + other.sec,
            nsec: self.nsec + other.nsec,
        };
        result.normalise();
        result
    }

    /// Subtract other from self (self - other).
    pub fn sub(&self, other: &TimeSpec) -> TimeSpec {
        let self_ns = self.to_ns();
        let other_ns = other.to_ns();
        let diff = self_ns.wrapping_sub(other_ns);
        TimeSpec::from_ns(diff)
    }
}

// ── ClockSourceRating ───────────────────────────────────────

/// Quality rating of a clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClockSourceRating(pub u32);

impl ClockSourceRating {
    /// Unusable / broken.
    pub const UNUSABLE: Self = Self(0);
    /// Very low quality (e.g., jiffies).
    pub const LOW: Self = Self(100);
    /// Acceptable (e.g., PIT).
    pub const ACCEPTABLE: Self = Self(200);
    /// Good (e.g., HPET).
    pub const GOOD: Self = Self(300);
    /// Ideal (e.g., TSC).
    pub const IDEAL: Self = Self(400);
}

// ── ClockSourceReadFn ───────────────────────────────────────

/// Function type that reads the hardware counter.
pub type ClockSourceReadFn = fn() -> u64;

// ── ClockSource ─────────────────────────────────────────────

/// A hardware clock source.
#[derive(Clone, Copy)]
pub struct ClockSource {
    /// Unique ID.
    id: u32,
    /// Name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Read function.
    read_fn: Option<ClockSourceReadFn>,
    /// Multiplier for cycle-to-nanosecond conversion.
    mult: u32,
    /// Shift for cycle-to-nanosecond conversion.
    shift: u32,
    /// Bitmask for the counter (e.g., 0xFFFF_FFFF for 32-bit).
    mask: u64,
    /// Maximum nanoseconds the source can idle without wrap.
    max_idle_ns: u64,
    /// Quality rating.
    rating: ClockSourceRating,
    /// Last read value.
    last_cycle: u64,
    /// Whether active.
    active: bool,
}

impl core::fmt::Debug for ClockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClockSource")
            .field("id", &self.id)
            .field("name", &self.name_str())
            .field("rating", &self.rating)
            .field("mult", &self.mult)
            .field("shift", &self.shift)
            .finish()
    }
}

impl ClockSource {
    /// Create an empty clock source.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            read_fn: None,
            mult: 1,
            shift: 0,
            mask: u64::MAX,
            max_idle_ns: 0,
            rating: ClockSourceRating::UNUSABLE,
            last_cycle: 0,
            active: false,
        }
    }

    /// Clock source name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Convert cycles to nanoseconds.
    pub fn cycles_to_ns(&self, cycles: u64) -> u64 {
        (cycles.wrapping_mul(self.mult as u64)) >> self.shift
    }

    /// Read the current cycle count.
    pub fn read(&mut self) -> u64 {
        if let Some(read_fn) = self.read_fn {
            let cycles = read_fn() & self.mask;
            self.last_cycle = cycles;
            cycles
        } else {
            self.last_cycle
        }
    }

    /// Quality rating.
    pub fn rating(&self) -> ClockSourceRating {
        self.rating
    }
}

// ── TimekeepingStats ────────────────────────────────────────

/// Timekeeping statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimekeepingStats {
    /// Number of clock source reads.
    pub reads: u64,
    /// Number of time updates.
    pub updates: u64,
    /// Number of NTP adjustments applied.
    pub ntp_adjustments: u64,
    /// Number of wall-clock sets.
    pub wall_sets: u64,
    /// Number of clock source switches.
    pub source_switches: u64,
}

// ── Timekeeper ──────────────────────────────────────────────

/// The kernel timekeeper.
///
/// Maintains wall clock, monotonic, and boot time using the
/// currently active clock source.
pub struct Timekeeper {
    /// Registered clock sources.
    sources: [ClockSource; MAX_CLOCK_SOURCES],
    /// Number of active sources.
    source_count: u32,
    /// Index of the current active source.
    active_source: usize,
    /// Next source ID.
    next_source_id: u32,
    /// Wall-clock time.
    wall_time: TimeSpec,
    /// Monotonic offset from boot (nanoseconds).
    monotonic_ns: u64,
    /// Boot time offset (includes suspend time, nanoseconds).
    boottime_ns: u64,
    /// Raw monotonic offset (no NTP adjustments).
    raw_ns: u64,
    /// Suspend time accumulated (nanoseconds).
    suspend_ns: u64,
    /// Last update cycle value.
    last_update_cycle: u64,
    /// NTP adjustment (parts per billion).
    ntp_adj_ppb: i64,
    /// Statistics.
    stats: TimekeepingStats,
    /// Whether initialized.
    initialized: bool,
}

impl Timekeeper {
    /// Create a new timekeeper.
    pub const fn new() -> Self {
        Self {
            sources: [ClockSource::empty(); MAX_CLOCK_SOURCES],
            source_count: 0,
            active_source: 0,
            next_source_id: 1,
            wall_time: TimeSpec::zero(),
            monotonic_ns: 0,
            boottime_ns: 0,
            raw_ns: 0,
            suspend_ns: 0,
            last_update_cycle: 0,
            ntp_adj_ppb: 0,
            stats: TimekeepingStats {
                reads: 0,
                updates: 0,
                ntp_adjustments: 0,
                wall_sets: 0,
                source_switches: 0,
            },
            initialized: false,
        }
    }

    /// Initialize.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a clock source. Returns the source ID.
    pub fn register_clocksource(
        &mut self,
        name: &str,
        read_fn: ClockSourceReadFn,
        mult: u32,
        shift: u32,
        mask: u64,
        rating: ClockSourceRating,
    ) -> Result<u32> {
        let slot = self
            .sources
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_source_id;
        self.next_source_id = self.next_source_id.wrapping_add(1);

        self.sources[slot] = ClockSource::empty();
        self.sources[slot].id = id;
        self.sources[slot].read_fn = Some(read_fn);
        self.sources[slot].mult = mult;
        self.sources[slot].shift = shift;
        self.sources[slot].mask = mask;
        self.sources[slot].rating = rating;
        self.sources[slot].active = true;

        let name_len = name.len().min(MAX_NAME_LEN);
        self.sources[slot].name[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        self.sources[slot].name_len = name_len;

        self.source_count += 1;

        // If this is better than the current source, switch.
        if self.sources[slot].rating > self.sources[self.active_source].rating
            || !self.sources[self.active_source].active
        {
            self.active_source = slot;
            self.stats.source_switches += 1;
        }

        Ok(id)
    }

    /// Update the timekeeper (called from timer interrupt).
    pub fn update(&mut self) -> Result<()> {
        if !self.initialized || self.source_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let cycles = self.sources[self.active_source].read();
        let delta_cycles =
            cycles.wrapping_sub(self.last_update_cycle) & self.sources[self.active_source].mask;
        let delta_ns = self.sources[self.active_source].cycles_to_ns(delta_cycles);

        // Apply NTP adjustment.
        let adjusted_ns = if self.ntp_adj_ppb != 0 {
            let adj = (delta_ns as i64 * self.ntp_adj_ppb) / 1_000_000_000;
            (delta_ns as i64 + adj) as u64
        } else {
            delta_ns
        };

        self.monotonic_ns += adjusted_ns;
        self.boottime_ns += adjusted_ns;
        self.raw_ns += delta_ns;

        // Update wall clock.
        self.wall_time = self.wall_time.add(&TimeSpec::from_ns(adjusted_ns));

        self.last_update_cycle = cycles;
        self.stats.reads += 1;
        self.stats.updates += 1;
        Ok(())
    }

    /// Get monotonic time in nanoseconds.
    pub fn ktime_get_ns(&self) -> u64 {
        self.monotonic_ns
    }

    /// Get monotonic time as TimeSpec.
    pub fn ktime_get(&self) -> TimeSpec {
        TimeSpec::from_ns(self.monotonic_ns)
    }

    /// Get wall-clock time.
    pub fn ktime_get_real(&self) -> TimeSpec {
        self.wall_time
    }

    /// Get wall-clock time in nanoseconds.
    pub fn ktime_get_real_ns(&self) -> u64 {
        self.wall_time.to_ns()
    }

    /// Get boot time (monotonic + suspend) in nanoseconds.
    pub fn ktime_get_boottime_ns(&self) -> u64 {
        self.boottime_ns
    }

    /// Get raw monotonic time (no NTP) in nanoseconds.
    pub fn ktime_get_raw_ns(&self) -> u64 {
        self.raw_ns
    }

    /// Set the wall-clock time.
    pub fn set_wall_time(&mut self, time: TimeSpec) -> Result<()> {
        self.wall_time = time;
        self.stats.wall_sets += 1;
        Ok(())
    }

    /// Set the NTP adjustment (parts per billion).
    pub fn set_ntp_adjustment(&mut self, ppb: i64) {
        self.ntp_adj_ppb = ppb;
        self.stats.ntp_adjustments += 1;
    }

    /// Record suspend time.
    pub fn suspend(&mut self, duration_ns: u64) {
        self.suspend_ns += duration_ns;
        self.boottime_ns += duration_ns;
    }

    /// Get the active clock source name.
    pub fn active_source_name(&self) -> &str {
        if self.sources[self.active_source].active {
            self.sources[self.active_source].name_str()
        } else {
            "<none>"
        }
    }

    /// Number of registered clock sources.
    pub fn source_count(&self) -> u32 {
        self.source_count
    }

    /// Statistics.
    pub fn stats(&self) -> &TimekeepingStats {
        &self.stats
    }
}

impl Default for Timekeeper {
    fn default() -> Self {
        Self::new()
    }
}
