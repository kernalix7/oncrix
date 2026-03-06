// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Get Free Pages (GFP) flag definitions.
//!
//! Defines the allocation context flags used throughout the kernel to
//! communicate the caller's constraints to the page allocator and
//! reclaim subsystem. GFP flags encode:
//!
//! - **Zone selection** — which physical memory zone (DMA, DMA32,
//!   Normal, HighMem) the allocation should come from.
//! - **Reclaim behaviour** — whether the allocator may invoke direct
//!   reclaim, kswapd, I/O, or filesystem writeback.
//! - **Allocation context** — atomic (no sleeping), kernel (can
//!   sleep), user-space (may trigger OOM kill).
//!
//! # API
//!
//! - [`GfpFlags`] — a thin newtype over `u32` with bitwise operations.
//! - [`GfpZone`] — zone selector derived from flags.
//! - [`AllocContext`] — high-level allocation context presets.
//! - [`ReclaimMode`] — summary of what reclaim actions are permitted.
//!
//! # Usage
//!
//! ```ignore
//! let flags = GfpFlags::KERNEL;
//! assert!(flags.allows_reclaim());
//! assert!(flags.allows_io());
//! assert_eq!(flags.zone(), GfpZone::Normal);
//! ```
//!
//! Reference: Linux `include/linux/gfp_types.h`, `include/linux/gfp.h`.

use oncrix_lib::Result;

// ── GfpFlags ────────────────────────────────────────────────────────────────

/// Get Free Pages flags — controls allocation zone and reclaim behaviour.
///
/// Implements common bit-flag operations and provides named constants
/// matching the Linux GFP flag vocabulary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GfpFlags(u32);

// -- Zone modifier bits (bits 0..3) ------------------------------------------

impl GfpFlags {
    // ── Zone modifier bits ──────────────────────────────────────────

    /// Allocate from the DMA zone (ISA DMA, < 16 MiB).
    pub const DMA: Self = Self(1 << 0);

    /// Allocate from the DMA32 zone (< 4 GiB).
    pub const DMA32: Self = Self(1 << 1);

    /// Allocate from the HighMem zone (beyond direct-mapped region).
    pub const HIGHMEM: Self = Self(1 << 2);

    /// Allocate from the Movable zone (for memory hot-remove).
    pub const MOVABLE: Self = Self(1 << 3);

    // ── Reclaim modifier bits (bits 4..11) ──────────────────────────

    /// Allow the allocator to wait (sleep).
    pub const WAIT: Self = Self(1 << 4);

    /// Allow I/O during reclaim (e.g. swap writeback).
    pub const IO: Self = Self(1 << 5);

    /// Allow filesystem operations during reclaim (writeback dirty
    /// pages through the VFS).
    pub const FS: Self = Self(1 << 6);

    /// Allow direct reclaim (synchronous shrink).
    pub const DIRECT_RECLAIM: Self = Self(1 << 7);

    /// Allow kswapd to be woken up.
    pub const KSWAPD_RECLAIM: Self = Self(1 << 8);

    /// Allow OOM killer invocation.
    pub const OOM_KILL: Self = Self(1 << 9);

    /// Retry the allocation even after failure (hard allocation).
    pub const RETRY: Self = Self(1 << 10);

    /// Do not warn on allocation failure.
    pub const NOWARN: Self = Self(1 << 11);

    // ── Page property bits (bits 12..15) ────────────────────────────

    /// Zero the allocated page(s) before returning.
    pub const ZERO: Self = Self(1 << 12);

    /// Allocation is for a compound (huge) page.
    pub const COMP: Self = Self(1 << 13);

    /// Allocation must not be accounted to memory cgroups.
    pub const NO_ACCOUNT: Self = Self(1 << 14);

    /// Hardwall: allocation must not fall back to other NUMA nodes.
    pub const THISNODE: Self = Self(1 << 15);

    // ── Composite presets ───────────────────────────────────────────

    /// Internal reclaim mask — all reclaim-related bits.
    const RECLAIM_MASK: u32 = Self::WAIT.0
        | Self::IO.0
        | Self::FS.0
        | Self::DIRECT_RECLAIM.0
        | Self::KSWAPD_RECLAIM.0
        | Self::OOM_KILL.0
        | Self::RETRY.0;

    /// `GFP_ATOMIC` — cannot sleep, no reclaim, no I/O.
    pub const ATOMIC: Self = Self(0);

    /// `GFP_KERNEL` — standard kernel allocation (can sleep + reclaim).
    pub const KERNEL: Self = Self(
        Self::WAIT.0
            | Self::IO.0
            | Self::FS.0
            | Self::DIRECT_RECLAIM.0
            | Self::KSWAPD_RECLAIM.0
            | Self::OOM_KILL.0
            | Self::RETRY.0,
    );

    /// `GFP_USER` — user-space allocation (like KERNEL but from user
    /// context).
    pub const USER: Self = Self(Self::KERNEL.0 | Self::HIGHMEM.0);

    /// `GFP_HIGHUSER` — user allocation preferring high memory.
    pub const HIGHUSER: Self = Self(Self::USER.0);

    /// `GFP_HIGHUSER_MOVABLE` — user allocation in movable zone.
    pub const HIGHUSER_MOVABLE: Self = Self(Self::HIGHUSER.0 | Self::MOVABLE.0);

    /// `GFP_DMA` — DMA-safe allocation (no reclaim).
    pub const GFP_DMA: Self = Self(Self::DMA.0);

    /// `GFP_DMA32` — DMA32-zone allocation.
    pub const GFP_DMA32: Self = Self(Self::DMA32.0);

    /// `GFP_NOFS` — allocation that must not enter the filesystem.
    pub const NOFS: Self = Self(
        Self::WAIT.0
            | Self::IO.0
            | Self::DIRECT_RECLAIM.0
            | Self::KSWAPD_RECLAIM.0
            | Self::OOM_KILL.0
            | Self::RETRY.0,
    );

    /// `GFP_NOIO` — allocation that must not perform I/O.
    pub const NOIO: Self = Self(
        Self::WAIT.0
            | Self::DIRECT_RECLAIM.0
            | Self::KSWAPD_RECLAIM.0
            | Self::OOM_KILL.0
            | Self::RETRY.0,
    );

    /// Empty (no flags set).
    pub const NONE: Self = Self(0);

    // ── Constructors ────────────────────────────────────────────────

    /// Create flags from a raw `u32` value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw `u32` value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Construct flags from an [`AllocContext`] preset.
    pub const fn from_context(ctx: AllocContext) -> Self {
        match ctx {
            AllocContext::Atomic => Self::ATOMIC,
            AllocContext::Kernel => Self::KERNEL,
            AllocContext::User => Self::USER,
            AllocContext::Dma => Self::GFP_DMA,
            AllocContext::Dma32 => Self::GFP_DMA32,
            AllocContext::NoFs => Self::NOFS,
            AllocContext::NoIo => Self::NOIO,
            AllocContext::HighUser => Self::HIGHUSER_MOVABLE,
        }
    }

    // ── Bitwise combinators ─────────────────────────────────────────

    /// Combine two flag sets (bitwise OR).
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersect two flag sets (bitwise AND).
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Remove bits present in `other`.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if any bit in `other` is set in `self`.
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns `true` if no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    // ── Query methods ───────────────────────────────────────────────

    /// Returns `true` if any reclaim action is permitted.
    pub const fn allows_reclaim(self) -> bool {
        (self.0 & Self::RECLAIM_MASK) != 0
    }

    /// Returns `true` if I/O is permitted during reclaim.
    pub const fn allows_io(self) -> bool {
        self.contains(Self::IO)
    }

    /// Returns `true` if filesystem operations are permitted.
    pub const fn allows_fs(self) -> bool {
        self.contains(Self::FS)
    }

    /// Returns `true` if the allocator may sleep.
    pub const fn may_sleep(self) -> bool {
        self.contains(Self::WAIT)
    }

    /// Returns `true` if the OOM killer may be invoked.
    pub const fn allows_oom_kill(self) -> bool {
        self.contains(Self::OOM_KILL)
    }

    /// Returns `true` if allocation failures should not warn.
    pub const fn is_nowarn(self) -> bool {
        self.contains(Self::NOWARN)
    }

    /// Returns `true` if pages should be zeroed.
    pub const fn wants_zero(self) -> bool {
        self.contains(Self::ZERO)
    }

    /// Returns `true` if the allocation is NUMA-local only.
    pub const fn is_thisnode(self) -> bool {
        self.contains(Self::THISNODE)
    }

    /// Derive the target memory zone from these flags.
    pub const fn zone(self) -> GfpZone {
        if self.contains(Self::DMA) {
            GfpZone::Dma
        } else if self.contains(Self::DMA32) {
            GfpZone::Dma32
        } else if self.contains(Self::HIGHMEM) {
            GfpZone::HighMem
        } else if self.contains(Self::MOVABLE) {
            GfpZone::Movable
        } else {
            GfpZone::Normal
        }
    }

    /// Derive the zone using the standalone helper.
    pub const fn zone_for_flags(self) -> GfpZone {
        self.zone()
    }

    /// Summarise the reclaim mode permitted by these flags.
    pub const fn reclaim_mode(self) -> ReclaimMode {
        if !self.allows_reclaim() {
            ReclaimMode::NoReclaim
        } else if self.contains(Self::DIRECT_RECLAIM) {
            if self.allows_io() && self.allows_fs() {
                ReclaimMode::Full
            } else if self.allows_io() {
                ReclaimMode::NoFs
            } else {
                ReclaimMode::NoIo
            }
        } else if self.0 & Self::KSWAPD_RECLAIM.0 != 0 {
            ReclaimMode::KswapdOnly
        } else {
            ReclaimMode::NoReclaim
        }
    }
}

impl core::fmt::Debug for GfpFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GfpFlags(0x{:08x})", self.0)
    }
}

// ── GfpZone ─────────────────────────────────────────────────────────────────

/// Physical memory zone selected by GFP flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfpZone {
    /// ISA DMA zone (< 16 MiB).
    Dma,
    /// DMA32 zone (< 4 GiB).
    Dma32,
    /// Normal zone (direct-mapped kernel memory).
    Normal,
    /// High memory zone (not directly mapped).
    HighMem,
    /// Movable zone (hot-removable memory).
    Movable,
}

impl Default for GfpZone {
    fn default() -> Self {
        Self::Normal
    }
}

impl GfpZone {
    /// Returns a human-readable label for the zone.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dma => "DMA",
            Self::Dma32 => "DMA32",
            Self::Normal => "Normal",
            Self::HighMem => "HighMem",
            Self::Movable => "Movable",
        }
    }

    /// Returns the fallback zone (next lower zone to try).
    pub const fn fallback(self) -> Option<Self> {
        match self {
            Self::Movable => Some(Self::Normal),
            Self::HighMem => Some(Self::Normal),
            Self::Normal => Some(Self::Dma32),
            Self::Dma32 => Some(Self::Dma),
            Self::Dma => None,
        }
    }
}

// ── AllocContext ─────────────────────────────────────────────────────────────

/// High-level allocation context presets.
///
/// Each variant corresponds to a commonly used GFP flag combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocContext {
    /// Atomic context — no sleeping, no reclaim.
    Atomic,
    /// Standard kernel context — may sleep and reclaim.
    Kernel,
    /// User-space allocation — may OOM kill.
    User,
    /// DMA-safe allocation.
    Dma,
    /// DMA32-safe allocation.
    Dma32,
    /// No filesystem operations during reclaim.
    NoFs,
    /// No I/O during reclaim.
    NoIo,
    /// High-memory user allocation (movable).
    HighUser,
}

impl AllocContext {
    /// Convert to the corresponding [`GfpFlags`].
    pub const fn to_flags(self) -> GfpFlags {
        GfpFlags::from_context(self)
    }

    /// Validate that the context is internally consistent.
    pub const fn validate(self) -> Result<()> {
        // All predefined contexts are valid by construction.
        Ok(())
    }
}

impl Default for AllocContext {
    fn default() -> Self {
        Self::Kernel
    }
}

// ── ReclaimMode ─────────────────────────────────────────────────────────────

/// Summary of reclaim actions permitted by a set of GFP flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimMode {
    /// No reclaim permitted (atomic allocation).
    NoReclaim,
    /// Only kswapd may be woken (no direct reclaim).
    KswapdOnly,
    /// Direct reclaim but no I/O (NOIO context).
    NoIo,
    /// Direct reclaim but no filesystem writeback (NOFS context).
    NoFs,
    /// Full reclaim: direct reclaim + I/O + FS.
    Full,
}

impl ReclaimMode {
    /// Returns `true` if any form of reclaim is allowed.
    pub const fn may_reclaim(self) -> bool {
        !matches!(self, Self::NoReclaim)
    }

    /// Returns `true` if direct reclaim is allowed.
    pub const fn may_direct_reclaim(self) -> bool {
        matches!(self, Self::NoIo | Self::NoFs | Self::Full)
    }

    /// Returns `true` if I/O-based reclaim is allowed.
    pub const fn may_io(self) -> bool {
        matches!(self, Self::NoFs | Self::Full)
    }

    /// Returns `true` if filesystem writeback is allowed.
    pub const fn may_fs(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Returns a human-readable label.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoReclaim => "no-reclaim",
            Self::KswapdOnly => "kswapd-only",
            Self::NoIo => "no-io",
            Self::NoFs => "no-fs",
            Self::Full => "full",
        }
    }
}

impl Default for ReclaimMode {
    fn default() -> Self {
        Self::NoReclaim
    }
}
