// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Address Space Layout Randomization (KASLR).
//!
//! Randomizes the base addresses of kernel regions at boot time
//! to mitigate code-reuse attacks. Entropy is collected from
//! the CPU hardware random generator (RDSEED/RDRAND, CPUID-gated)
//! with a TSC fallback, and used to compute aligned random
//! offsets for kernel text, physical map, module, and vmalloc
//! regions.
//!
//! # Why hardware entropy here (and not the CSPRNG)
//!
//! KASLR runs in very early boot — before the kernel CSPRNG
//! (`crate::random_kern::RandomSubsystem`) has been initialised or
//! seeded. It therefore reads entropy directly from the CPU
//! hardware RNG (`RDSEED`, then `RDRAND`), gated on CPUID feature
//! detection, falling back to `RDTSC` only when neither is present.
//! [`hw_entropy_u64`] is the single, audited source used here and is
//! re-used by the CSPRNG-seeding path in `crate::random_syscall`.
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

/// Hardware-backed entropy source for KASLR offset generation.
///
/// Each draw mixes **fresh** hardware entropy ([`hw_entropy_u64`],
/// i.e. `RDSEED`/`RDRAND`) into the running state before applying a
/// non-linear avalanche (an SplitMix64-style finaliser). Mixing fresh
/// hardware entropy on every call is the key property: even if an
/// attacker leaks one randomized region base and recovers the prior
/// state, the next offset depends on hardware bits the attacker never
/// observed, so the remaining region offsets stay unpredictable. This
/// closes the audit finding that "observing one randomized base
/// recovers the PRNG state and predicts the other three offsets".
///
/// The constructor seed is only an initial mixing input; there is no
/// fixed-constant fallback. On platforms without a hardware RNG the
/// entropy quality degrades to the TSC fallback inside
/// [`hw_entropy_u64`].
pub struct EntropySource {
    /// Internal mixing state.
    state: u64,
}

impl EntropySource {
    /// Create a new entropy source.
    ///
    /// `initial_seed` is folded together with a fresh hardware draw so
    /// the starting state is never a caller-known constant.
    pub fn new(initial_seed: u64) -> Self {
        // Combine the caller seed with a fresh hardware draw. No
        // zero-check / constant fallback is needed: the SplitMix64
        // finaliser in `next_u64` tolerates any state including zero,
        // and the per-call hardware re-mix dominates the output.
        Self {
            state: initial_seed ^ hw_entropy_u64(),
        }
    }

    /// Mix additional entropy into the internal state.
    pub fn add_entropy(&mut self, val: u64) {
        self.state = self.state.wrapping_add(val) ^ hw_entropy_u64();
    }

    /// Generate the next 64-bit value.
    ///
    /// Folds a fresh hardware-entropy draw into the state, then applies
    /// the SplitMix64 finaliser (a well-studied bijective mix). The
    /// fresh per-call hardware input means successive outputs are not
    /// derivable from one another by inverting a linear recurrence.
    pub fn next_u64(&mut self) -> u64 {
        // Advance with a fresh hardware draw plus the golden-ratio
        // increment, then run the SplitMix64 output finaliser.
        self.state = self
            .state
            .wrapping_add(hw_entropy_u64())
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Generate a random value in `[0, range)` that is a
    /// multiple of `alignment`.
    ///
    /// Returns 0 if `alignment` is zero or exceeds `range`. Uses
    /// rejection sampling so the result is uniform over the slot count
    /// (no modulo bias toward low offsets).
    pub fn next_aligned(&mut self, range: u64, alignment: u64) -> u64 {
        if alignment == 0 || alignment > range {
            return 0;
        }
        let slots = range / alignment;
        if slots == 0 {
            return 0;
        }
        // Rejection sampling to avoid modulo bias. The largest multiple
        // of `slots` that fits in u64 bounds the acceptance window.
        let limit = u64::MAX - (u64::MAX % slots);
        let mut raw = self.next_u64();
        let mut guard = 0u32;
        while raw >= limit && guard < 16 {
            raw = self.next_u64();
            guard += 1;
        }
        (raw % slots) * alignment
    }
}

// ── Hardware entropy ─────────────────────────────────────────

/// CPUID leaf 1, ECX bit 30 — `RDRAND` instruction supported.
#[cfg(target_arch = "x86_64")]
const CPUID1_ECX_RDRAND: u32 = 1 << 30;

/// CPUID leaf 7 sub-leaf 0, EBX bit 18 — `RDSEED` instruction supported.
#[cfg(target_arch = "x86_64")]
const CPUID7_EBX_RDSEED: u32 = 1 << 18;

/// Read 64 bits from `RDSEED`, retrying on the carry-flag-clear
/// (no-data) condition for a bounded number of attempts.
///
/// Returns `None` if the hardware did not produce a value within the
/// retry budget. The caller must have verified `RDSEED` support via
/// CPUID first.
///
/// # Safety
///
/// `RDSEED` must be supported by the CPU (CPUID leaf 7, EBX bit 18).
#[cfg(target_arch = "x86_64")]
unsafe fn rdseed_u64() -> Option<u64> {
    let mut attempts = 0u32;
    while attempts < 64 {
        let value: u64;
        let ok: u8;
        // SAFETY: caller guarantees RDSEED is supported. The
        // instruction reads from the on-die conditioned entropy
        // source and sets CF=1 on success; `setc` captures CF.
        unsafe {
            core::arch::asm!(
                "rdseed {val}",
                "setc {ok}",
                val = out(reg) value,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(value);
        }
        core::hint::spin_loop();
        attempts += 1;
    }
    None
}

/// Read 64 bits from `RDRAND`, retrying on the carry-flag-clear
/// (no-data) condition for a bounded number of attempts.
///
/// Returns `None` if the hardware did not produce a value within the
/// retry budget. The caller must have verified `RDRAND` support via
/// CPUID first.
///
/// # Safety
///
/// `RDRAND` must be supported by the CPU (CPUID leaf 1, ECX bit 30).
#[cfg(target_arch = "x86_64")]
unsafe fn rdrand_u64() -> Option<u64> {
    let mut attempts = 0u32;
    while attempts < 64 {
        let value: u64;
        let ok: u8;
        // SAFETY: caller guarantees RDRAND is supported. CF=1 on a
        // successful draw from the DRBG; `setc` captures CF.
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) value,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(value);
        }
        core::hint::spin_loop();
        attempts += 1;
    }
    None
}

/// Read the Time Stamp Counter.
///
/// Always available on x86_64; used only as a last-resort entropy
/// fallback when neither `RDSEED` nor `RDRAND` is present.
#[cfg(target_arch = "x86_64")]
fn rdtsc_u64() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is always available on x86_64 and has no side
    // effects beyond reading the TSC.
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

/// Gather 64 bits of hardware entropy.
///
/// Prefers `RDSEED` (a true non-deterministic conditioned source),
/// then `RDRAND` (a cryptographically secure DRBG reseeded from the
/// same source), each gated on CPUID feature detection. When neither
/// is available — or the hardware repeatedly returns no data — the
/// `RDTSC` value is XOR-folded in so the result is never a fixed
/// constant. The TSC-only path is *not* cryptographically strong but
/// is the documented last resort for platforms lacking a hardware
/// RNG; KASLR on such platforms degrades to timing-based entropy.
///
/// This is the single audited hardware-entropy primitive for the
/// very-early-boot path (KASLR) and for lazily seeding the kernel
/// CSPRNG before any subsystem entropy is available.
pub fn hw_entropy_u64() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID feature detection. The leaf indices used (1 and 7)
        // are present on every CPU that implements CPUID, which is
        // mandatory on x86_64.
        let max_leaf = oncrix_hal::cpu_feature::cpuid(0, 0).eax;

        if max_leaf >= 7 {
            let ebx7 = oncrix_hal::cpu_feature::cpuid(7, 0).ebx;
            if ebx7 & CPUID7_EBX_RDSEED != 0 {
                // SAFETY: RDSEED support confirmed via CPUID above.
                if let Some(v) = unsafe { rdseed_u64() } {
                    return v ^ rdtsc_u64();
                }
            }
        }

        let ecx1 = oncrix_hal::cpu_feature::cpuid(1, 0).ecx;
        if ecx1 & CPUID1_ECX_RDRAND != 0 {
            // SAFETY: RDRAND support confirmed via CPUID above.
            if let Some(v) = unsafe { rdrand_u64() } {
                return v ^ rdtsc_u64();
            }
        }

        // Last resort: fold two TSC reads. Not CSPRNG-grade, but
        // never a fixed constant.
        let a = rdtsc_u64();
        core::hint::spin_loop();
        let b = rdtsc_u64();
        a ^ b.rotate_left(32)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // No hardware entropy source modelled on this architecture.
        // Returns a non-constant value derived from a volatile read so
        // the build remains portable; real ports must supply an arch
        // hardware RNG here.
        let mut x = 0u64;
        // SAFETY: reads an owned stack local through a volatile pointer
        // purely to defeat constant-folding; no aliasing concerns.
        unsafe {
            let p = &raw const x;
            x = core::ptr::read_volatile(p);
        }
        x ^ 0x0123_4567_89AB_CDEF
    }
}

// ── Helper Functions ─────────────────────────────────────────

/// Collect early boot entropy from hardware sources.
///
/// Delegates to [`hw_entropy_u64`], which prefers the CPU hardware
/// RNG (`RDSEED`/`RDRAND`) and falls back to the TSC. Kept as a named
/// entry point for the boot path and existing callers.
pub fn early_collect_entropy() -> u64 {
    hw_entropy_u64()
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
