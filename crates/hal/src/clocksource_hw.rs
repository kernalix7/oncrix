// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock source hardware abstraction for the ONCRIX kernel.
//!
//! Provides a unified interface for reading hardware clock sources
//! (TSC, HPET, PIT, ACPI PM timer) with rating-based selection of
//! the best available source at runtime. Each clock source is
//! represented by a [`ClockSourceHw`] descriptor that tracks its
//! frequency, rating, flags, and accumulated read count.
//!
//! # Architecture
//!
//! - [`ClockType`] -- classification of the underlying hardware timer.
//! - [`ClockRating`] -- quality/accuracy rating for source selection.
//! - [`ClockFlags`] -- capability flags (continuous, stable, etc.).
//! - [`ReadCycle`] -- a single timestamped cycle-counter reading.
//! - [`ClockSourceHw`] -- descriptor for a single hardware clock source.
//! - [`ClockSourceRegistry`] -- manages up to [`MAX_SOURCES`] sources
//!   and selects the highest-rated one as the active clocksource.
//!
//! # Selection Algorithm
//!
//! When multiple sources are registered, the registry selects the one
//! with the highest [`ClockRating`] value. If two sources share the
//! same rating, the one registered first wins. The active source can
//! also be overridden manually.
//!
//! Reference: Linux `kernel/time/clocksource.c`,
//!            Intel SDM Vol. 3B (TSC), ACPI Spec (PM Timer), HPET Spec.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of clock sources in the registry.
const MAX_SOURCES: usize = 8;

/// Maximum length of a clock source name.
const MAX_NAME_LEN: usize = 32;

/// Default rating for an uncalibrated source.
const DEFAULT_RATING: u32 = 0;

/// Maximum valid frequency in Hz (10 GHz sanity check).
const MAX_FREQUENCY_HZ: u64 = 10_000_000_000;

/// Minimum valid frequency in Hz (1 Hz sanity check).
const MIN_FREQUENCY_HZ: u64 = 1;

/// Mask shift limit for cycle counters (max 64-bit counter).
const MAX_MASK_BITS: u32 = 64;

// ---------------------------------------------------------------------------
// ClockType
// ---------------------------------------------------------------------------

/// Type of underlying hardware clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockType {
    /// x86 Time Stamp Counter (RDTSC instruction).
    #[default]
    Tsc,
    /// High Precision Event Timer (MMIO-based).
    Hpet,
    /// Programmable Interval Timer (legacy 8253/8254, PIO-based).
    Pit,
    /// ACPI Power Management Timer (24-bit or 32-bit, PIO-based).
    AcpiPm,
    /// Architecture-generic timer (e.g., ARM Generic Timer, RISC-V mtime).
    ArchTimer,
    /// Software-defined jiffies counter (lowest quality fallback).
    Jiffies,
}

// ---------------------------------------------------------------------------
// ClockRating
// ---------------------------------------------------------------------------

/// Quality/accuracy rating for clock source selection.
///
/// Higher values indicate better quality. The registry selects the
/// source with the highest rating as the active clocksource.
///
/// Typical rating ranges (following Linux convention):
/// - 1..99 -- unusable or very low quality (jiffies)
/// - 100..199 -- adequate (PIT, ACPI PM)
/// - 200..299 -- good (HPET)
/// - 300..399 -- ideal (invariant TSC)
/// - 400+ -- perfect (architectural timer)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ClockRating(pub u32);

impl ClockRating {
    /// Creates a new clock rating.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric rating value.
    pub fn value(self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// ClockFlags
// ---------------------------------------------------------------------------

/// Capability flags for a clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockFlags(pub u32);

impl ClockFlags {
    /// The clock source is continuous (never stops, even in deep sleep).
    pub const CONTINUOUS: u32 = 1 << 0;
    /// The clock source is stable across CPU frequency changes.
    pub const STABLE_FREQ: u32 = 1 << 1;
    /// The clock can be used as a watchdog reference.
    pub const WATCHDOG: u32 = 1 << 2;
    /// The clock source is per-CPU (not globally coherent).
    pub const PER_CPU: u32 = 1 << 3;
    /// The clock source supports high-resolution timekeeping.
    pub const HIGH_RES: u32 = 1 << 4;
    /// The clock source is valid for use in suspend-to-RAM paths.
    pub const VALID_FOR_SUSPEND: u32 = 1 << 5;

    /// Creates a new flags value.
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns `true` if the given flag bit is set.
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Sets a flag bit.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clears a flag bit.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }
}

// ---------------------------------------------------------------------------
// ReadCycle
// ---------------------------------------------------------------------------

/// A single timestamped cycle-counter reading from a clock source.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadCycle {
    /// Raw cycle counter value.
    pub cycles: u64,
    /// Source identifier that produced this reading.
    pub source_id: u32,
    /// Sequence number (monotonically increasing per source).
    pub sequence: u64,
}

impl ReadCycle {
    /// Computes the elapsed cycles between two readings.
    ///
    /// Handles wrap-around by using wrapping subtraction, which is
    /// correct as long as the counter has not wrapped more than once
    /// between the two readings.
    pub fn elapsed(&self, earlier: &ReadCycle) -> u64 {
        self.cycles.wrapping_sub(earlier.cycles)
    }

    /// Converts elapsed cycles to nanoseconds given a frequency in Hz.
    ///
    /// Returns 0 if `freq_hz` is 0 to avoid division by zero.
    pub fn cycles_to_ns(cycles: u64, freq_hz: u64) -> u64 {
        if freq_hz == 0 {
            return 0;
        }
        (cycles as u128)
            .saturating_mul(1_000_000_000)
            .wrapping_div(freq_hz as u128) as u64
    }

    /// Converts nanoseconds to cycles given a frequency in Hz.
    ///
    /// Returns 0 if `freq_hz` is 0.
    pub fn ns_to_cycles(ns: u64, freq_hz: u64) -> u64 {
        if freq_hz == 0 {
            return 0;
        }
        (ns as u128)
            .saturating_mul(freq_hz as u128)
            .wrapping_div(1_000_000_000) as u64
    }
}

// ---------------------------------------------------------------------------
// NameBuf (local)
// ---------------------------------------------------------------------------

/// Fixed-size name buffer for clock source names.
#[derive(Clone, Copy)]
struct NameBuf {
    bytes: [u8; MAX_NAME_LEN],
    len: usize,
}

impl NameBuf {
    const fn empty() -> Self {
        Self {
            bytes: [0u8; MAX_NAME_LEN],
            len: 0,
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes: buf,
            len: b.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(s) = core::str::from_utf8(self.as_bytes()) {
            write!(f, "\"{}\"", s)
        } else {
            write!(f, "{:?}", self.as_bytes())
        }
    }
}

// ---------------------------------------------------------------------------
// ClockSourceHw
// ---------------------------------------------------------------------------

/// Descriptor for a single hardware clock source.
///
/// Tracks the source's type, frequency, rating, flags, counter mask,
/// and accumulated statistics (read count). The registry uses the
/// [`rating`](Self::rating) field to select the best source.
pub struct ClockSourceHw {
    /// Unique source identifier.
    pub id: u32,
    /// Human-readable name.
    name: NameBuf,
    /// Type of hardware timer.
    pub clock_type: ClockType,
    /// Counter frequency in Hz.
    pub frequency_hz: u64,
    /// Quality rating (higher is better).
    pub rating: ClockRating,
    /// Capability flags.
    pub flags: ClockFlags,
    /// Bitmask applied to the counter (e.g., 0xFFFF_FFFF for 32-bit).
    pub mask: u64,
    /// Number of valid bits in the counter.
    pub mask_bits: u32,
    /// Whether this source has been calibrated/initialised.
    pub calibrated: bool,
    /// Whether this source is currently enabled.
    pub enabled: bool,
    /// Monotonic read sequence counter.
    read_seq: u64,
    /// Total number of reads performed on this source.
    pub read_count: u64,
    /// Last raw cycle value read.
    pub last_cycles: u64,
    /// Multiplier for fast ns conversion (mult * cycles >> shift).
    pub mult: u32,
    /// Shift for fast ns conversion.
    pub shift: u32,
    /// Maximum idle nanoseconds before the source wraps.
    pub max_idle_ns: u64,
}

/// Constant empty source for array initialisation.
const EMPTY_SOURCE: ClockSourceHw = ClockSourceHw {
    id: 0,
    name: NameBuf {
        bytes: [0u8; MAX_NAME_LEN],
        len: 0,
    },
    clock_type: ClockType::Tsc,
    frequency_hz: 0,
    rating: ClockRating(DEFAULT_RATING),
    flags: ClockFlags(0),
    mask: 0,
    mask_bits: 0,
    calibrated: false,
    enabled: false,
    read_seq: 0,
    read_count: 0,
    last_cycles: 0,
    mult: 0,
    shift: 0,
    max_idle_ns: 0,
};

impl ClockSourceHw {
    /// Creates a new clock source descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty or too
    /// long, or if `frequency_hz` is outside the valid range.
    pub fn new(
        id: u32,
        name: &str,
        clock_type: ClockType,
        frequency_hz: u64,
        rating: ClockRating,
        mask_bits: u32,
    ) -> Result<Self> {
        if frequency_hz < MIN_FREQUENCY_HZ || frequency_hz > MAX_FREQUENCY_HZ {
            return Err(Error::InvalidArgument);
        }
        if mask_bits == 0 || mask_bits > MAX_MASK_BITS {
            return Err(Error::InvalidArgument);
        }
        let name_buf = NameBuf::from_str(name)?;
        let mask = if mask_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << mask_bits) - 1
        };

        let (mult, shift) = Self::compute_mult_shift(frequency_hz);
        let max_idle_ns = Self::compute_max_idle_ns(frequency_hz, mask);

        Ok(Self {
            id,
            name: name_buf,
            clock_type,
            frequency_hz,
            rating,
            flags: ClockFlags(0),
            mask,
            mask_bits,
            calibrated: false,
            enabled: false,
            read_seq: 0,
            read_count: 0,
            last_cycles: 0,
            mult,
            shift,
            max_idle_ns,
        })
    }

    /// Returns the source name as a byte slice.
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Records a cycle-counter reading and returns a [`ReadCycle`].
    ///
    /// This increments the internal sequence counter and read count.
    pub fn record_read(&mut self, raw_cycles: u64) -> ReadCycle {
        let cycles = raw_cycles & self.mask;
        self.last_cycles = cycles;
        self.read_seq += 1;
        self.read_count += 1;
        ReadCycle {
            cycles,
            source_id: self.id,
            sequence: self.read_seq,
        }
    }

    /// Converts raw cycles to nanoseconds using the precomputed
    /// multiplier and shift.
    #[inline]
    pub fn cycles_to_ns(&self, cycles: u64) -> u64 {
        if self.shift == 0 || self.mult == 0 {
            return ReadCycle::cycles_to_ns(cycles, self.frequency_hz);
        }
        ((cycles as u128).saturating_mul(self.mult as u128) >> self.shift) as u64
    }

    /// Converts nanoseconds to cycles.
    #[inline]
    pub fn ns_to_cycles(&self, ns: u64) -> u64 {
        ReadCycle::ns_to_cycles(ns, self.frequency_hz)
    }

    /// Enables this clock source.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables this clock source.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Marks this clock source as calibrated.
    pub fn set_calibrated(&mut self, frequency_hz: u64) -> Result<()> {
        if frequency_hz < MIN_FREQUENCY_HZ || frequency_hz > MAX_FREQUENCY_HZ {
            return Err(Error::InvalidArgument);
        }
        self.frequency_hz = frequency_hz;
        let (mult, shift) = Self::compute_mult_shift(frequency_hz);
        self.mult = mult;
        self.shift = shift;
        self.max_idle_ns = Self::compute_max_idle_ns(frequency_hz, self.mask);
        self.calibrated = true;
        Ok(())
    }

    /// Updates the rating of this source.
    pub fn set_rating(&mut self, rating: ClockRating) {
        self.rating = rating;
    }

    /// Computes the multiplier and shift for fast ns conversion.
    ///
    /// `ns = (cycles * mult) >> shift`
    ///
    /// We target shift = 32 for a good balance of precision and range.
    fn compute_mult_shift(frequency_hz: u64) -> (u32, u32) {
        if frequency_hz == 0 {
            return (0, 0);
        }
        let shift = 32u32;
        // mult = (10^9 << shift) / freq
        let mult = ((1_000_000_000u128) << shift) / frequency_hz as u128;
        // Clamp to u32
        let mult = if mult > u32::MAX as u128 {
            u32::MAX
        } else {
            mult as u32
        };
        (mult, shift)
    }

    /// Computes the maximum idle nanoseconds before the counter wraps.
    fn compute_max_idle_ns(frequency_hz: u64, mask: u64) -> u64 {
        if frequency_hz == 0 {
            return 0;
        }
        // max_ns = mask * 10^9 / freq
        let ns = (mask as u128)
            .saturating_mul(1_000_000_000)
            .wrapping_div(frequency_hz as u128);
        if ns > u64::MAX as u128 {
            u64::MAX
        } else {
            ns as u64
        }
    }
}

// ---------------------------------------------------------------------------
// ClockSourceRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_SOURCES`] hardware clock sources.
///
/// Provides source registration, lookup, and automatic selection of
/// the highest-rated source as the active clocksource.
pub struct ClockSourceRegistry {
    /// Registered clock sources.
    sources: [ClockSourceHw; MAX_SOURCES],
    /// Number of registered sources.
    count: usize,
    /// Index of the currently active (selected) source, or `None`.
    active_index: Option<usize>,
}

impl ClockSourceRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            sources: [EMPTY_SOURCE; MAX_SOURCES],
            count: 0,
            active_index: None,
        }
    }

    /// Registers a clock source.
    ///
    /// After registration the registry re-evaluates which source
    /// should be active based on rating.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a source with the same ID exists.
    pub fn register(&mut self, source: ClockSourceHw) -> Result<()> {
        for s in &self.sources[..self.count] {
            if s.id == source.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_SOURCES {
            return Err(Error::OutOfMemory);
        }
        self.sources[self.count] = source;
        self.count += 1;
        self.select_best();
        Ok(())
    }

    /// Unregisters a clock source by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no source with the given ID exists.
    pub fn unregister(&mut self, source_id: u32) -> Result<()> {
        let idx = self.find_index(source_id)?;
        // Compact by swapping with the last element.
        let last = self.count - 1;
        if idx != last {
            // Move fields manually since ClockSourceHw doesn't implement Copy.
            self.sources.swap(idx, last);
        }
        self.sources[last] = EMPTY_SOURCE;
        self.count -= 1;
        self.select_best();
        Ok(())
    }

    /// Returns a reference to a source by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, source_id: u32) -> Result<&ClockSourceHw> {
        let idx = self.find_index(source_id)?;
        Ok(&self.sources[idx])
    }

    /// Returns a mutable reference to a source by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, source_id: u32) -> Result<&mut ClockSourceHw> {
        let idx = self.find_index(source_id)?;
        Ok(&mut self.sources[idx])
    }

    /// Returns a reference to the currently active clock source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no source is registered.
    pub fn active(&self) -> Result<&ClockSourceHw> {
        let idx = self.active_index.ok_or(Error::NotFound)?;
        Ok(&self.sources[idx])
    }

    /// Returns a mutable reference to the currently active source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no source is registered.
    pub fn active_mut(&mut self) -> Result<&mut ClockSourceHw> {
        let idx = self.active_index.ok_or(Error::NotFound)?;
        Ok(&mut self.sources[idx])
    }

    /// Overrides the active source to the one with the given ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the source is not registered.
    pub fn set_active(&mut self, source_id: u32) -> Result<()> {
        let idx = self.find_index(source_id)?;
        self.active_index = Some(idx);
        Ok(())
    }

    /// Re-selects the best (highest-rated) source as active.
    pub fn reselect(&mut self) {
        self.select_best();
    }

    /// Returns the number of registered sources.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no sources are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the slice of registered sources.
    pub fn sources(&self) -> &[ClockSourceHw] {
        &self.sources[..self.count]
    }

    /// Reads the current cycle count from the active source.
    ///
    /// This is a convenience that calls [`ClockSourceHw::record_read`]
    /// with a raw cycle value that must be provided by the caller
    /// (since reading hardware counters is architecture-specific).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active source exists.
    pub fn read_active(&mut self, raw_cycles: u64) -> Result<ReadCycle> {
        let idx = self.active_index.ok_or(Error::NotFound)?;
        Ok(self.sources[idx].record_read(raw_cycles))
    }

    /// Converts cycles to nanoseconds using the active source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active source exists.
    pub fn cycles_to_ns(&self, cycles: u64) -> Result<u64> {
        let src = self.active()?;
        Ok(src.cycles_to_ns(cycles))
    }

    // -- internal ---------------------------------------------------------

    /// Selects the source with the highest rating as active.
    fn select_best(&mut self) {
        if self.count == 0 {
            self.active_index = None;
            return;
        }
        let mut best_idx = 0;
        let mut best_rating = self.sources[0].rating;
        for i in 1..self.count {
            if self.sources[i].rating > best_rating {
                best_rating = self.sources[i].rating;
                best_idx = i;
            }
        }
        self.active_index = Some(best_idx);
    }

    /// Returns the index of a source by ID.
    fn find_index(&self, source_id: u32) -> Result<usize> {
        self.sources[..self.count]
            .iter()
            .position(|s| s.id == source_id)
            .ok_or(Error::NotFound)
    }
}

impl Default for ClockSourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
