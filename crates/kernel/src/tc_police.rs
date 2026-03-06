// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Traffic policing for the ONCRIX traffic control subsystem.
//!
//! Provides token-bucket-based packet policing that enforces rate
//! limits by metering traffic and applying conform/exceed actions.
//! This is the `tc police` equivalent from the Linux traffic control
//! infrastructure.
//!
//! # Architecture
//!
//! ```text
//! packet → Policer::check_packet()
//!             |
//!             ├─ tokens available → conform action (Pass)
//!             |
//!             └─ tokens exhausted → exceed action (Drop)
//! ```
//!
//! Key components:
//!
//! - [`PoliceAction`]: action to take on a metered packet (pass,
//!   drop, reclassify, pipe).
//! - [`PolicerParams`]: rate, burst, peak rate, and MTU parameters
//!   for the token bucket algorithm.
//! - [`TokenBucket`]: dual token bucket state with committed and
//!   peak rate tracking.
//! - [`PolicerStats`]: per-policer conform/exceed counters.
//! - [`Policer`]: a complete policer instance combining parameters,
//!   bucket state, actions, and statistics.
//! - [`PoliceRegistry`]: system-wide registry managing up to
//!   [`MAX_POLICERS`] policer instances.
//!
//! Reference: Linux `net/sched/act_police.c`,
//! `include/net/act_api.h`.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of policers in the system registry.
const MAX_POLICERS: usize = 32;

/// Default MTU for policing purposes (bytes).
const DEFAULT_MTU: u32 = 1500;

// =========================================================================
// PoliceAction
// =========================================================================

/// Action to take on a metered packet.
///
/// Values loosely correspond to Linux `TC_POLICE_*` / `TC_ACT_*`
/// constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoliceAction {
    /// Pass the packet through (conform).
    #[default]
    Pass,
    /// Drop the packet (exceed / violate).
    Drop,
    /// Reclassify the packet (re-evaluate through the filter chain).
    Reclassify,
    /// Pipe the packet to the next action in the chain.
    Pipe,
}

// =========================================================================
// PolicerParams
// =========================================================================

/// Token bucket parameters for a policer.
///
/// Defines the committed information rate (CIR), burst size, optional
/// peak information rate (PIR), and maximum transmission unit.
#[derive(Debug, Clone, Copy)]
pub struct PolicerParams {
    /// Committed rate in bytes per tick (CIR).
    pub rate: u64,
    /// Maximum burst size in bytes (committed burst size, CBS).
    pub burst: u64,
    /// Peak rate in bytes per tick (PIR).  Zero means no peak-rate
    /// enforcement.
    pub peakrate: u64,
    /// Maximum packet size that can be admitted (bytes).
    pub mtu: u32,
}

impl Default for PolicerParams {
    fn default() -> Self {
        Self {
            rate: 1000,
            burst: 4096,
            peakrate: 0,
            mtu: DEFAULT_MTU,
        }
    }
}

impl PolicerParams {
    /// Create policer parameters with the given rate and burst.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `rate` or `burst` is
    /// zero.
    pub const fn new(rate: u64, burst: u64) -> Result<Self> {
        if rate == 0 || burst == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            rate,
            burst,
            peakrate: 0,
            mtu: DEFAULT_MTU,
        })
    }

    /// Set the peak rate.
    pub const fn with_peakrate(mut self, peakrate: u64) -> Self {
        self.peakrate = peakrate;
        self
    }

    /// Set the MTU.
    pub const fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }
}

// =========================================================================
// TokenBucket
// =========================================================================

/// Dual token bucket state for committed and peak rate metering.
///
/// Tokens are replenished at the configured rate on each tick and
/// consumed when packets are admitted.  The committed bucket
/// (`tokens`) enforces the CIR, and the peak bucket
/// (`peak_tokens`) enforces the PIR when a peak rate is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenBucket {
    /// Current committed-rate tokens (bytes).  May go negative when
    /// a packet slightly exceeds the available tokens.
    pub tokens: i64,
    /// Current peak-rate tokens (bytes).  May go negative.
    pub peak_tokens: i64,
    /// Tick counter at last replenishment.
    pub last_tick: u64,
}

impl TokenBucket {
    /// Create a token bucket pre-filled to the burst ceiling.
    pub const fn new(burst: i64, peak_burst: i64) -> Self {
        Self {
            tokens: burst,
            peak_tokens: peak_burst,
            last_tick: 0,
        }
    }

    /// Replenish tokens for one tick.
    ///
    /// Adds `rate` tokens to the committed bucket (capped at `burst`)
    /// and `peakrate` tokens to the peak bucket (capped at `mtu`).
    pub fn replenish(&mut self, params: &PolicerParams) {
        self.tokens = (self.tokens + params.rate as i64).min(params.burst as i64);
        if params.peakrate > 0 {
            self.peak_tokens = (self.peak_tokens + params.peakrate as i64).min(params.mtu as i64);
        }
        self.last_tick = self.last_tick.wrapping_add(1);
    }

    /// Check whether a packet of `size` bytes can be admitted.
    ///
    /// The packet conforms if both the committed and peak buckets
    /// have enough tokens.
    pub const fn conforms(&self, size: u64, peakrate: u64) -> bool {
        if self.tokens < size as i64 {
            return false;
        }
        if peakrate > 0 && self.peak_tokens < size as i64 {
            return false;
        }
        true
    }

    /// Consume tokens for an admitted packet.
    pub fn consume(&mut self, size: u64) {
        self.tokens -= size as i64;
        self.peak_tokens -= size as i64;
    }
}

// =========================================================================
// PolicerStats
// =========================================================================

/// Per-policer traffic statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicerStats {
    /// Number of packets that conformed to the rate limit.
    pub conform_packets: u64,
    /// Total bytes of conforming packets.
    pub conform_bytes: u64,
    /// Number of packets that exceeded the rate limit.
    pub exceed_packets: u64,
    /// Total bytes of exceeding packets.
    pub exceed_bytes: u64,
}

impl PolicerStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            conform_packets: 0,
            conform_bytes: 0,
            exceed_packets: 0,
            exceed_bytes: 0,
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// =========================================================================
// Policer
// =========================================================================

/// A complete traffic policer instance.
///
/// Combines token bucket parameters, bucket state, conform/exceed
/// actions, and statistics into a single metering unit.
pub struct Policer {
    /// Policer identifier (assigned by [`PoliceRegistry`]).
    policer_id: u32,
    /// Rate limiting parameters.
    pub params: PolicerParams,
    /// Token bucket state.
    pub bucket: TokenBucket,
    /// Action to take when a packet conforms.
    pub conform_action: PoliceAction,
    /// Action to take when a packet exceeds the rate.
    pub exceed_action: PoliceAction,
    /// Traffic statistics.
    pub stats: PolicerStats,
    /// Whether this policer slot is in use.
    in_use: bool,
}

impl Policer {
    /// Create a new policer with default parameters.
    const fn new(policer_id: u32, params: PolicerParams) -> Self {
        Self {
            policer_id,
            params,
            bucket: TokenBucket::new(params.burst as i64, params.mtu as i64),
            conform_action: PoliceAction::Pass,
            exceed_action: PoliceAction::Drop,
            stats: PolicerStats::new(),
            in_use: false,
        }
    }

    /// An empty, unused policer slot.
    const EMPTY: Self = Self::new(
        0,
        PolicerParams {
            rate: 1000,
            burst: 4096,
            peakrate: 0,
            mtu: DEFAULT_MTU,
        },
    );

    /// Return the policer identifier.
    pub const fn policer_id(&self) -> u32 {
        self.policer_id
    }

    /// Meter a packet and return the appropriate action.
    ///
    /// If the token bucket has enough tokens for a packet of
    /// `packet_size` bytes, the packet conforms and tokens are
    /// consumed.  Otherwise the packet exceeds the rate limit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `packet_size` is zero
    /// or exceeds the configured MTU.
    pub fn check_packet(&mut self, packet_size: u32) -> Result<PoliceAction> {
        if packet_size == 0 || packet_size > self.params.mtu {
            return Err(Error::InvalidArgument);
        }

        let size = packet_size as u64;

        if self.bucket.conforms(size, self.params.peakrate) {
            self.bucket.consume(size);
            self.stats.conform_packets = self.stats.conform_packets.wrapping_add(1);
            self.stats.conform_bytes = self.stats.conform_bytes.wrapping_add(size);
            Ok(self.conform_action)
        } else {
            self.stats.exceed_packets = self.stats.exceed_packets.wrapping_add(1);
            self.stats.exceed_bytes = self.stats.exceed_bytes.wrapping_add(size);
            Ok(self.exceed_action)
        }
    }

    /// Replenish tokens for one tick.
    pub fn tick(&mut self) {
        self.bucket.replenish(&self.params);
    }
}

// =========================================================================
// PoliceRegistry
// =========================================================================

/// System-wide registry of traffic policers.
///
/// Manages up to [`MAX_POLICERS`] policer instances.  Each policer
/// is identified by a monotonically increasing ID.
pub struct PoliceRegistry {
    /// Policer slots.
    policers: [Policer; MAX_POLICERS],
    /// Next policer ID to assign.
    next_id: u32,
}

impl Default for PoliceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PoliceRegistry {
    /// Create an empty policer registry.
    pub const fn new() -> Self {
        Self {
            policers: [Policer::EMPTY; MAX_POLICERS],
            next_id: 1,
        }
    }

    /// Create a new policer with the given parameters.
    ///
    /// Returns the policer ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create(&mut self, params: PolicerParams) -> Result<u32> {
        for i in 0..MAX_POLICERS {
            if !self.policers[i].in_use {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.policers[i] = Policer::new(id, params);
                self.policers[i].in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a policer by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the policer does not exist.
    pub fn destroy(&mut self, policer_id: u32) -> Result<()> {
        for i in 0..MAX_POLICERS {
            if self.policers[i].in_use && self.policers[i].policer_id == policer_id {
                self.policers[i].in_use = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a policer by ID, returning a mutable reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the policer does not exist.
    pub fn find(&mut self, policer_id: u32) -> Result<&mut Policer> {
        for i in 0..MAX_POLICERS {
            if self.policers[i].in_use && self.policers[i].policer_id == policer_id {
                return Ok(&mut self.policers[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Meter a packet against a specific policer.
    ///
    /// Convenience method that finds the policer and calls
    /// [`Policer::check_packet`].
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the policer does not exist.
    /// - [`Error::InvalidArgument`] if `packet_size` is invalid.
    pub fn check_packet(&mut self, policer_id: u32, packet_size: u32) -> Result<PoliceAction> {
        let policer = self.find(policer_id)?;
        policer.check_packet(packet_size)
    }

    /// Tick all active policers (token replenishment).
    pub fn tick_all(&mut self) {
        for i in 0..MAX_POLICERS {
            if self.policers[i].in_use {
                self.policers[i].tick();
            }
        }
    }

    /// Return the number of active policers.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..MAX_POLICERS {
            if self.policers[i].in_use {
                count += 1;
            }
        }
        count
    }
}
