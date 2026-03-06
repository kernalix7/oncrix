// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GFP flag compaction helpers.
//!
//! The GFP (Get Free Pages) flags control allocation behaviour:
//! which zones to try, whether to block, and whether to invoke
//! reclaim or compaction. This module provides utilities to decode
//! GFP flag combinations, classify allocations, and determine the
//! appropriate zone and fallback strategy for each combination.
//!
//! # Design
//!
//! ```text
//!  alloc_pages(gfp_mask, order)
//!     │
//!     ├─ decode zone preference  (GFP_DMA, GFP_DMA32, GFP_NORMAL)
//!     ├─ decode reclaim flags    (GFP_NORETRY, GFP_RETRY_MAYFAIL)
//!     ├─ decode compaction flags (GFP_COMPACT_ONLY)
//!     └─ try zones in fallback order
//! ```
//!
//! # Key Types
//!
//! - [`GfpZone`] — zone preference decoded from GFP flags
//! - [`GfpReclaim`] — reclaim behaviour decoded from GFP flags
//! - [`GfpDecoded`] — fully decoded GFP flag set
//! - [`GfpDecoder`] — decodes and classifies GFP flags
//! - [`GfpCompactStats`] — decoding statistics
//!
//! Reference: Linux `include/linux/gfp.h`, `mm/page_alloc.c`.

// -------------------------------------------------------------------
// Constants / bit definitions
// -------------------------------------------------------------------

/// GFP_DMA zone.
const GFP_DMA: u32 = 0x01;
/// GFP_DMA32 zone.
const GFP_DMA32: u32 = 0x04;
/// GFP_HIGHMEM zone (ignored on x86_64).
const GFP_HIGHMEM: u32 = 0x02;
/// May block (sleep).
const GFP_WAIT: u32 = 0x10;
/// May invoke direct reclaim.
const GFP_DIRECT_RECLAIM: u32 = 0x400;
/// May invoke kswapd.
const GFP_KSWAPD_RECLAIM: u32 = 0x800;
/// Do not retry after first failure.
const GFP_NORETRY: u32 = 0x1000;
/// Retry but may fail.
const GFP_RETRY_MAYFAIL: u32 = 0x2000;
/// Do not warn on failure.
const GFP_NOWARN: u32 = 0x200;
/// Compaction-only allocation (no reclaim).
const GFP_COMPACT_ONLY: u32 = 0x4000;

/// Maximum tracked decodings.
const MAX_DECODINGS: usize = 64;

// -------------------------------------------------------------------
// GfpZone
// -------------------------------------------------------------------

/// Zone preference decoded from GFP flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfpZone {
    /// DMA zone (below 16 MiB).
    Dma,
    /// DMA32 zone (below 4 GiB).
    Dma32,
    /// Normal zone.
    Normal,
    /// HighMem zone.
    HighMem,
}

impl GfpZone {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Dma => "DMA",
            Self::Dma32 => "DMA32",
            Self::Normal => "Normal",
            Self::HighMem => "HighMem",
        }
    }

    /// Decode zone from raw GFP flags.
    pub const fn from_flags(flags: u32) -> Self {
        if flags & GFP_DMA != 0 {
            Self::Dma
        } else if flags & GFP_DMA32 != 0 {
            Self::Dma32
        } else if flags & GFP_HIGHMEM != 0 {
            Self::HighMem
        } else {
            Self::Normal
        }
    }
}

// -------------------------------------------------------------------
// GfpReclaim
// -------------------------------------------------------------------

/// Reclaim behaviour decoded from GFP flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfpReclaim {
    /// No reclaim allowed.
    None,
    /// Only kswapd reclaim.
    KswapdOnly,
    /// Direct reclaim allowed.
    Direct,
    /// Direct reclaim with retry.
    DirectRetry,
    /// Compaction only (no reclaim).
    CompactOnly,
}

impl GfpReclaim {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::KswapdOnly => "kswapd-only",
            Self::Direct => "direct",
            Self::DirectRetry => "direct-retry",
            Self::CompactOnly => "compact-only",
        }
    }

    /// Decode from raw GFP flags.
    pub const fn from_flags(flags: u32) -> Self {
        if flags & GFP_COMPACT_ONLY != 0 {
            return Self::CompactOnly;
        }
        if flags & GFP_NORETRY != 0 {
            return Self::Direct;
        }
        if flags & GFP_DIRECT_RECLAIM != 0 {
            if flags & GFP_RETRY_MAYFAIL != 0 {
                return Self::DirectRetry;
            }
            return Self::Direct;
        }
        if flags & GFP_KSWAPD_RECLAIM != 0 {
            return Self::KswapdOnly;
        }
        Self::None
    }

    /// Check whether this allows blocking.
    pub const fn may_block(&self) -> bool {
        !matches!(self, Self::None | Self::CompactOnly)
    }
}

// -------------------------------------------------------------------
// GfpDecoded
// -------------------------------------------------------------------

/// Fully decoded GFP flag set.
#[derive(Debug, Clone, Copy)]
pub struct GfpDecoded {
    /// Raw flags.
    raw: u32,
    /// Zone preference.
    zone: GfpZone,
    /// Reclaim strategy.
    reclaim: GfpReclaim,
    /// Whether blocking is allowed.
    may_block: bool,
    /// Whether warnings are suppressed.
    nowarn: bool,
}

impl GfpDecoded {
    /// Decode raw GFP flags.
    pub const fn decode(flags: u32) -> Self {
        let zone = GfpZone::from_flags(flags);
        let reclaim = GfpReclaim::from_flags(flags);
        Self {
            raw: flags,
            zone,
            reclaim,
            may_block: flags & GFP_WAIT != 0,
            nowarn: flags & GFP_NOWARN != 0,
        }
    }

    /// Return the raw flags.
    pub const fn raw(&self) -> u32 {
        self.raw
    }

    /// Return the zone.
    pub const fn zone(&self) -> GfpZone {
        self.zone
    }

    /// Return the reclaim strategy.
    pub const fn reclaim(&self) -> GfpReclaim {
        self.reclaim
    }

    /// Check whether blocking is allowed.
    pub const fn may_block(&self) -> bool {
        self.may_block
    }

    /// Check whether nowarn is set.
    pub const fn nowarn(&self) -> bool {
        self.nowarn
    }
}

impl Default for GfpDecoded {
    fn default() -> Self {
        Self::decode(0)
    }
}

// -------------------------------------------------------------------
// GfpCompactStats
// -------------------------------------------------------------------

/// Decoding statistics.
#[derive(Debug, Clone, Copy)]
pub struct GfpCompactStats {
    /// Total decodings.
    pub total_decodings: u64,
    /// DMA zone requests.
    pub dma_requests: u64,
    /// DMA32 zone requests.
    pub dma32_requests: u64,
    /// Normal zone requests.
    pub normal_requests: u64,
    /// Compact-only requests.
    pub compact_only_requests: u64,
}

impl GfpCompactStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_decodings: 0,
            dma_requests: 0,
            dma32_requests: 0,
            normal_requests: 0,
            compact_only_requests: 0,
        }
    }
}

impl Default for GfpCompactStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// GfpDecoder
// -------------------------------------------------------------------

/// Decodes and classifies GFP flags.
pub struct GfpDecoder {
    /// Recent decodings for analysis.
    recent: [GfpDecoded; MAX_DECODINGS],
    /// Number of recorded decodings.
    count: usize,
    /// Statistics.
    stats: GfpCompactStats,
}

impl GfpDecoder {
    /// Create a new decoder.
    pub const fn new() -> Self {
        Self {
            recent: [const {
                GfpDecoded {
                    raw: 0,
                    zone: GfpZone::Normal,
                    reclaim: GfpReclaim::None,
                    may_block: false,
                    nowarn: false,
                }
            }; MAX_DECODINGS],
            count: 0,
            stats: GfpCompactStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &GfpCompactStats {
        &self.stats
    }

    /// Decode a GFP flag set and record it.
    pub fn decode(&mut self, flags: u32) -> GfpDecoded {
        let decoded = GfpDecoded::decode(flags);
        self.stats.total_decodings += 1;
        match decoded.zone() {
            GfpZone::Dma => self.stats.dma_requests += 1,
            GfpZone::Dma32 => self.stats.dma32_requests += 1,
            GfpZone::Normal | GfpZone::HighMem => self.stats.normal_requests += 1,
        }
        if matches!(decoded.reclaim(), GfpReclaim::CompactOnly) {
            self.stats.compact_only_requests += 1;
        }
        if self.count < MAX_DECODINGS {
            self.recent[self.count] = decoded;
            self.count += 1;
        }
        decoded
    }

    /// Return the number of recorded decodings.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Get a recorded decoding.
    pub fn get(&self, index: usize) -> Option<&GfpDecoded> {
        if index < self.count {
            Some(&self.recent[index])
        } else {
            None
        }
    }
}

impl Default for GfpDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the GFP_DMA flag.
pub const fn gfp_dma() -> u32 {
    GFP_DMA
}

/// Return the GFP_DMA32 flag.
pub const fn gfp_dma32() -> u32 {
    GFP_DMA32
}

/// Return the GFP_WAIT flag.
pub const fn gfp_wait() -> u32 {
    GFP_WAIT
}

/// Return the GFP_NORETRY flag.
pub const fn gfp_noretry() -> u32 {
    GFP_NORETRY
}
