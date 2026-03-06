// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Address Space Layout Randomization (KASLR).
//!
//! Randomizes the base addresses of kernel regions at boot time
//! to mitigate code-reuse attacks. Entropy is collected from
//! hardware sources (e.g., TSC) and used to compute aligned
//! random offsets for kernel text, physical map, module, and
//! vmalloc regions.
//!
//! # Architecture
//!
//! ```text
//!  Boot entry
//!      │
//!      ▼
//!  early_collect_entropy() ──► seed
//!      │
//!      ▼
//!  EntropySource::new(seed)
//!      │
//!      ▼
//!  KaslrLayout::init(&mut entropy)
//!      │
//!      ├─► randomize kernel_base
//!      ├─► randomize physical_map_base
//!      ├─► randomize module_base
//!      └─► randomize vmalloc_base
//! ```
//!
//! Reference: Linux `arch/x86/mm/kaslr.c`,
//! `arch/x86/boot/compressed/kaslr.c`.

use oncrix_lib::{Error, Result};

/// Default kernel base address (higher-half canonical).
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Range within which the kernel base may be randomized
/// (512 MiB).
pub const KASLR_RANGE: u64 = 0x2000_0000;

/// Alignment for KASLR offsets (2 MiB huge-page boundary).
pub const KASLR_ALIGN: u64 = 0x20_0000;

/// Maximum number of independently randomized regions.
pub const MAX_KASLR_REGIONS: usize = 8;

/// Default base for the physical memory direct map.
pub const PHYSICAL_MAP_BASE: u64 = 0xFFFF_8880_0000_0000;

/// Default base for loadable kernel modules.
pub const MODULE_BASE: u64 = 0xFFFF_FFFF_C000_0000;

/// Default base for the vmalloc virtual address range.
pub const VMALLOC_BASE: u64 = 0xFFFF_C900_0000_0000;

// ── State ────────────────────────────────────────────────────

/// Current state of the KASLR subsystem.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KaslrState {
    /// KASLR is disabled; all addresses are at defaults.
    #[default]
    Disabled,
    /// Entropy collected and offsets computed but not yet live.
    Initialized,
    /// KASLR offsets are actively applied.
    Active,
}

// ── KaslrRegion ──────────────────────────────────────────────

/// A single independently-randomized kernel memory region.
#[derive(Clone, Copy, Default)]
pub struct KaslrRegion {
    /// Region name stored inline (no heap allocation).
    pub name: [u8; 32],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Default (non-randomized) base address.
    pub base_addr: u64,
    /// Randomized base address.
    pub randomized_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Whether this region has been randomized.
    pub active: bool,
}

// ── KaslrLayout ──────────────────────────────────────────────

/// Tracks the randomized addresses for all kernel regions.
pub struct KaslrLayout {
    /// Signed offset applied to the default kernel base.
    pub kernel_offset: i64,
    /// Randomized kernel text base address.
    pub kernel_base: u64,
    /// Randomized physical-memory direct-map base.
    pub physical_map_base: u64,
    /// Randomized module region base.
    pub module_base: u64,
    /// Randomized vmalloc region base.
    pub vmalloc_base: u64,
    /// Per-region tracking.
    pub regions: [KaslrRegion; MAX_KASLR_REGIONS],
    /// Number of registered regions.
    pub region_count: usize,
    /// Current subsystem state.
    pub state: KaslrState,
    /// Effective entropy bits used for randomization.
    pub entropy_bits: u32,
}

impl Default for KaslrLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl KaslrLayout {
    /// Create a new layout with all addresses at their defaults.
    pub const fn new() -> Self {
        Self {
            kernel_offset: 0,
            kernel_base: KERNEL_BASE,
            physical_map_base: PHYSICAL_MAP_BASE,
            module_base: MODULE_BASE,
            vmalloc_base: VMALLOC_BASE,
            regions: [KaslrRegion {
                name: [0u8; 32],
                name_len: 0,
                base_addr: 0,
                randomized_addr: 0,
                size: 0,
                active: false,
            }; MAX_KASLR_REGIONS],
            region_count: 0,
            state: KaslrState::Disabled,
            entropy_bits: 0,
        }
    }

    /// Initialize KASLR by randomizing all region bases.
    ///
    /// Each region base is shifted by a random, aligned offset
    /// within `KASLR_RANGE`. The entropy source must be seeded
    /// before calling this method.
    pub fn init(&mut self, entropy: &mut EntropySource) -> Result<()> {
        if self.state == KaslrState::Active {
            return Err(Error::Busy);
        }

        // Randomize kernel text base.
        let k_off = entropy.next_aligned(KASLR_RANGE, KASLR_ALIGN);
        self.kernel_base = KERNEL_BASE.wrapping_add(k_off);
        self.kernel_offset = k_off as i64;

        // Randomize physical direct-map base.
        let p_off = entropy.next_aligned(KASLR_RANGE, KASLR_ALIGN);
        self.physical_map_base = PHYSICAL_MAP_BASE.wrapping_add(p_off);

        // Randomize module base.
        let m_off = entropy.next_aligned(KASLR_RANGE, KASLR_ALIGN);
        self.module_base = MODULE_BASE.wrapping_add(m_off);

        // Randomize vmalloc base.
        let v_off = entropy.next_aligned(KASLR_RANGE, KASLR_ALIGN);
        self.vmalloc_base = VMALLOC_BASE.wrapping_add(v_off);

        // Compute effective entropy bits.
        let slots = KASLR_RANGE / KASLR_ALIGN;
        self.entropy_bits = 64 - slots.leading_zeros() - 1;

        self.state = KaslrState::Initialized;
        Ok(())
    }

    /// Register a new independently-randomized region.
    ///
    /// Returns the index of the newly added region.
    pub fn add_region(&mut self, name: &[u8], base: u64, size: u64) -> Result<usize> {
        if self.region_count >= MAX_KASLR_REGIONS {
            return Err(Error::OutOfMemory);
        }
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let idx = self.region_count;
        let copy_len = name.len().min(32);
        let region = &mut self.regions[idx];

        region.name[..copy_len].copy_from_slice(&name[..copy_len]);
        region.name_len = copy_len;
        region.base_addr = base;
        region.randomized_addr = base;
        region.size = size;
        region.active = false;

        self.region_count += 1;
        Ok(idx)
    }

    /// Return the signed offset applied to the kernel base.
    pub fn kernel_offset(&self) -> i64 {
        self.kernel_offset
    }

    /// Return the (possibly randomized) kernel base address.
    pub fn kernel_base(&self) -> u64 {
        self.kernel_base
    }

    /// Translate a default kernel address to its randomized
    /// counterpart by adding the KASLR offset.
    pub fn translate_addr(&self, default_addr: u64) -> u64 {
        if self.kernel_offset >= 0 {
            default_addr.wrapping_add(self.kernel_offset as u64)
        } else {
            default_addr.wrapping_sub((-self.kernel_offset) as u64)
        }
    }

    /// Check whether `addr` falls within the randomized kernel
    /// text region.
    pub fn is_kernel_addr(&self, addr: u64) -> bool {
        addr >= self.kernel_base && addr < self.kernel_base.wrapping_add(KASLR_RANGE)
    }

    /// Return the current KASLR subsystem state.
    pub fn state(&self) -> KaslrState {
        self.state
    }

    /// Return the number of effective entropy bits.
    pub fn entropy_bits(&self) -> u32 {
        self.entropy_bits
    }
}

// ── EntropySource ────────────────────────────────────────────

/// Pseudo-random entropy source for KASLR offset generation.
///
/// Uses a xorshift64 PRNG seeded from hardware entropy
/// (e.g., TSC). This is *not* cryptographically secure — it
/// only needs to be unpredictable to remote attackers who
/// cannot observe boot-time state.
pub struct EntropySource {
    /// Internal PRNG state.
    seed: u64,
}

impl EntropySource {
    /// Create a new entropy source with the given seed.
    pub fn new(initial_seed: u64) -> Self {
        // Ensure seed is never zero (xorshift requirement).
        let seed = if initial_seed == 0 {
            0xDEAD_BEEF_CAFE_BABE
        } else {
            initial_seed
        };
        Self { seed }
    }

    /// Mix additional entropy into the internal state.
    pub fn add_entropy(&mut self, val: u64) {
        self.seed ^= val;
        self.seed = self.seed.wrapping_mul(0x517C_C1B7_2722_0A95);
        if self.seed == 0 {
            self.seed = 0xDEAD_BEEF_CAFE_BABE;
        }
    }

    /// Generate the next pseudo-random 64-bit value
    /// (xorshift64).
    pub fn next_u64(&mut self) -> u64 {
        let mut s = self.seed;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.seed = s;
        s
    }

    /// Generate a random value in `[0, range)` that is a
    /// multiple of `alignment`.
    ///
    /// Returns 0 if `alignment` is zero or exceeds `range`.
    pub fn next_aligned(&mut self, range: u64, alignment: u64) -> u64 {
        if alignment == 0 || alignment > range {
            return 0;
        }
        let slots = range / alignment;
        if slots == 0 {
            return 0;
        }
        let raw = self.next_u64();
        (raw % slots) * alignment
    }
}

// ── Helper Functions ─────────────────────────────────────────

/// Collect early boot entropy from hardware sources.
///
/// On x86_64, reads the Time Stamp Counter (TSC). On other
/// architectures, returns a compile-time placeholder.
pub fn early_collect_entropy() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: `rdtsc` is always available on x86_64 and
        // has no side effects beyond reading the TSC.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // Placeholder: no hardware entropy source available.
        0x0123_4567_89AB_CDEF
    }
}

/// Align `addr` down to the nearest multiple of `align`.
///
/// `align` must be a power of two; if it is zero the original
/// address is returned unchanged.
pub fn align_down(addr: u64, align: u64) -> u64 {
    if align == 0 {
        return addr;
    }
    addr & !(align - 1)
}

/// Align `addr` up to the nearest multiple of `align`.
///
/// `align` must be a power of two; if it is zero the original
/// address is returned unchanged. Wraps on overflow.
pub fn align_up(addr: u64, align: u64) -> u64 {
    if align == 0 {
        return addr;
    }
    let mask = align - 1;
    (addr.wrapping_add(mask)) & !mask
}
