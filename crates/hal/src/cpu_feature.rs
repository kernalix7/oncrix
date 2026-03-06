// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU feature detection via CPUID.
//!
//! Provides a `FeatureSet` bitmask populated at boot time by executing
//! the CPUID instruction. Callers query individual features using
//! [`has_feature`] or the [`FeatureSet`] methods.
//!
//! # CPUID leaves used
//!
//! | Leaf | Sub-leaf | Information |
//! |------|----------|-------------|
//! | 0x0  | —        | Max basic leaf, vendor string |
//! | 0x1  | —        | Family/model/stepping, ECX/EDX features |
//! | 0x7  | 0        | Extended features (EBX/ECX): AVX2, AVX-512 etc. |
//! | 0x80000001 | — | Extended ECX/EDX: LAHF, LZCNT, SSE4a, etc. |

use oncrix_lib::{Error, Result};

// ── CpuFeature ───────────────────────────────────────────────────────────────

/// Individual CPU features detectable via CPUID.
///
/// Each variant maps to a bit in [`FeatureSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum CpuFeature {
    // Leaf 0x1 EDX
    /// Streaming SIMD Extensions.
    Sse = 1 << 0,
    /// Streaming SIMD Extensions 2.
    Sse2 = 1 << 1,
    /// CLFLUSH instruction.
    Clflush = 1 << 2,
    /// Time Stamp Counter.
    Tsc = 1 << 3,
    /// Model Specific Registers.
    Msr = 1 << 4,
    /// Physical Address Extension.
    Pae = 1 << 5,
    /// APIC on-chip.
    Apic = 1 << 6,

    // Leaf 0x1 ECX
    /// Streaming SIMD Extensions 3.
    Sse3 = 1 << 7,
    /// Supplemental SSE3.
    Ssse3 = 1 << 8,
    /// SSE 4.1.
    Sse41 = 1 << 9,
    /// SSE 4.2.
    Sse42 = 1 << 10,
    /// Advanced Encryption Standard.
    Aes = 1 << 11,
    /// XSAVE/XRSTOR/XSETBV/XGETBV instructions.
    Xsave = 1 << 12,
    /// AVX (256-bit).
    Avx = 1 << 13,
    /// 16-bit FP conversion (F16C).
    F16c = 1 << 14,
    /// Fused Multiply-Add (FMA3).
    Fma = 1 << 15,
    /// RDRAND instruction.
    Rdrand = 1 << 16,
    /// x2APIC support.
    X2apic = 1 << 17,
    /// POPCNT instruction.
    Popcnt = 1 << 18,
    /// Hardware virtualisation (VMX/SVM).
    Vmx = 1 << 19,

    // Leaf 0x7 EBX
    /// AVX2 (256-bit integer SIMD).
    Avx2 = 1 << 20,
    /// AVX-512 Foundation.
    Avx512f = 1 << 21,
    /// AVX-512 Doubleword and Quadword.
    Avx512dq = 1 << 22,
    /// RDSEED instruction.
    Rdseed = 1 << 23,
    /// FSGSBASE instructions (RDFSBASE/WRFSBASE etc.).
    Fsgsbase = 1 << 24,
    /// Supervisor Mode Execution Prevention.
    Smep = 1 << 25,
    /// Supervisor Mode Access Prevention.
    Smap = 1 << 26,
    /// SHA extensions.
    Sha = 1 << 27,

    // Leaf 0x80000001
    /// LAHF/SAHF in 64-bit mode.
    Lahf64 = 1 << 28,
    /// LZCNT (leading zero count).
    Lzcnt = 1 << 29,
    /// Execute Disable Bit (NX).
    Nx = 1 << 30,
    /// 1-GiB huge pages.
    Page1gb = 1 << 31,
    /// RDTSCP instruction.
    Rdtscp = 1 << 32,
    /// Long mode (64-bit).
    LongMode = 1 << 33,
}

// ── FeatureSet ───────────────────────────────────────────────────────────────

/// Bitmask of detected CPU features.
#[derive(Debug, Clone, Copy, Default)]
pub struct FeatureSet(pub u64);

impl FeatureSet {
    /// Create an empty feature set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Test whether `feature` is present.
    pub fn has(&self, feature: CpuFeature) -> bool {
        self.0 & feature as u64 != 0
    }

    /// Set a feature bit.
    pub fn set(&mut self, feature: CpuFeature) {
        self.0 |= feature as u64;
    }

    /// Clear a feature bit.
    pub fn clear(&mut self, feature: CpuFeature) {
        self.0 &= !(feature as u64);
    }

    /// Return the raw bitmask.
    pub fn raw(&self) -> u64 {
        self.0
    }
}

// ── CpuId leaf/sub-leaf result ───────────────────────────────────────────────

/// Raw CPUID output registers.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidResult {
    /// EAX register value.
    pub eax: u32,
    /// EBX register value.
    pub ebx: u32,
    /// ECX register value.
    pub ecx: u32,
    /// EDX register value.
    pub edx: u32,
}

/// Execute the CPUID instruction with the given leaf and sub-leaf.
///
/// # Safety
///
/// Must only be called on x86_64 hardware. Callers must ensure
/// `leaf` is supported (≤ max_leaf from leaf 0).
#[cfg(target_arch = "x86_64")]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let (eax, ebx, ecx, edx);
    // SAFETY: CPUID is a non-privileged read-only instruction. EBX is a
    // callee-saved register on x86_64 but the asm! clobber handles it.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nostack, nomem, preserves_flags),
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

/// Stub for non-x86_64 platforms — always returns zeros.
#[cfg(not(target_arch = "x86_64"))]
pub fn cpuid(_leaf: u32, _subleaf: u32) -> CpuidResult {
    CpuidResult::default()
}

// ── CpuInfo ──────────────────────────────────────────────────────────────────

/// Decoded CPU identification information.
#[derive(Debug, Clone)]
pub struct CpuId {
    /// Vendor string (12 ASCII bytes, e.g. "GenuineIntel").
    pub vendor: [u8; 12],
    /// CPU family (raw + extended combined).
    pub family: u16,
    /// CPU model (raw + extended combined).
    pub model: u8,
    /// CPU stepping.
    pub stepping: u8,
    /// Detected feature bitmask.
    pub features: FeatureSet,
    /// Maximum supported basic CPUID leaf.
    pub max_basic_leaf: u32,
    /// Maximum supported extended CPUID leaf.
    pub max_extended_leaf: u32,
}

impl CpuId {
    /// Construct a blank `CpuId`.
    pub const fn new() -> Self {
        Self {
            vendor: [0u8; 12],
            family: 0,
            model: 0,
            stepping: 0,
            features: FeatureSet::empty(),
            max_basic_leaf: 0,
            max_extended_leaf: 0,
        }
    }
}

impl Default for CpuId {
    fn default() -> Self {
        Self::new()
    }
}

// ── detect_features ──────────────────────────────────────────────────────────

/// Detect CPU features by executing CPUID on x86_64.
///
/// Returns a populated [`CpuId`] structure.  On non-x86_64 platforms
/// returns an empty structure.
pub fn detect_features() -> CpuId {
    let mut info = CpuId::new();

    // Leaf 0: vendor string + max basic leaf.
    let l0 = cpuid(0, 0);
    info.max_basic_leaf = l0.eax;

    // Vendor string: EBX, EDX, ECX (in that order per Intel spec).
    let write_u32_le = |buf: &mut [u8; 12], offset: usize, val: u32| {
        buf[offset] = (val & 0xFF) as u8;
        buf[offset + 1] = ((val >> 8) & 0xFF) as u8;
        buf[offset + 2] = ((val >> 16) & 0xFF) as u8;
        buf[offset + 3] = ((val >> 24) & 0xFF) as u8;
    };
    write_u32_le(&mut info.vendor, 0, l0.ebx);
    write_u32_le(&mut info.vendor, 4, l0.edx);
    write_u32_le(&mut info.vendor, 8, l0.ecx);

    if info.max_basic_leaf == 0 {
        return info;
    }

    // Leaf 1: family/model/stepping + feature flags.
    let l1 = cpuid(1, 0);
    let stepping = (l1.eax & 0xF) as u8;
    let base_model = ((l1.eax >> 4) & 0xF) as u8;
    let base_family = ((l1.eax >> 8) & 0xF) as u8;
    let ext_model = ((l1.eax >> 16) & 0xF) as u8;
    let ext_family = ((l1.eax >> 20) & 0xFF) as u8;

    info.stepping = stepping;
    info.family = if base_family == 0xF {
        (base_family as u16) + (ext_family as u16)
    } else {
        base_family as u16
    };
    info.model = if base_family == 0xF || base_family == 0x6 {
        base_model | (ext_model << 4)
    } else {
        base_model
    };

    // ECX features (leaf 1).
    let ecx = l1.ecx;
    if ecx & (1 << 0) != 0 {
        info.features.set(CpuFeature::Sse3);
    }
    if ecx & (1 << 9) != 0 {
        info.features.set(CpuFeature::Ssse3);
    }
    if ecx & (1 << 19) != 0 {
        info.features.set(CpuFeature::Sse41);
    }
    if ecx & (1 << 20) != 0 {
        info.features.set(CpuFeature::Sse42);
    }
    if ecx & (1 << 25) != 0 {
        info.features.set(CpuFeature::Aes);
    }
    if ecx & (1 << 26) != 0 {
        info.features.set(CpuFeature::Xsave);
    }
    if ecx & (1 << 28) != 0 {
        info.features.set(CpuFeature::Avx);
    }
    if ecx & (1 << 29) != 0 {
        info.features.set(CpuFeature::F16c);
    }
    if ecx & (1 << 12) != 0 {
        info.features.set(CpuFeature::Fma);
    }
    if ecx & (1 << 30) != 0 {
        info.features.set(CpuFeature::Rdrand);
    }
    if ecx & (1 << 21) != 0 {
        info.features.set(CpuFeature::X2apic);
    }
    if ecx & (1 << 23) != 0 {
        info.features.set(CpuFeature::Popcnt);
    }
    if ecx & (1 << 5) != 0 {
        info.features.set(CpuFeature::Vmx);
    }

    // EDX features (leaf 1).
    let edx = l1.edx;
    if edx & (1 << 25) != 0 {
        info.features.set(CpuFeature::Sse);
    }
    if edx & (1 << 26) != 0 {
        info.features.set(CpuFeature::Sse2);
    }
    if edx & (1 << 19) != 0 {
        info.features.set(CpuFeature::Clflush);
    }
    if edx & (1 << 4) != 0 {
        info.features.set(CpuFeature::Tsc);
    }
    if edx & (1 << 5) != 0 {
        info.features.set(CpuFeature::Msr);
    }
    if edx & (1 << 6) != 0 {
        info.features.set(CpuFeature::Pae);
    }
    if edx & (1 << 9) != 0 {
        info.features.set(CpuFeature::Apic);
    }

    // Leaf 7, sub-leaf 0: structured extended feature flags.
    if info.max_basic_leaf >= 7 {
        let l7 = cpuid(7, 0);
        let ebx7 = l7.ebx;
        if ebx7 & (1 << 0) != 0 {
            info.features.set(CpuFeature::Fsgsbase);
        }
        if ebx7 & (1 << 5) != 0 {
            info.features.set(CpuFeature::Avx2);
        }
        if ebx7 & (1 << 16) != 0 {
            info.features.set(CpuFeature::Avx512f);
        }
        if ebx7 & (1 << 17) != 0 {
            info.features.set(CpuFeature::Avx512dq);
        }
        if ebx7 & (1 << 18) != 0 {
            info.features.set(CpuFeature::Rdseed);
        }
        if ebx7 & (1 << 20) != 0 {
            info.features.set(CpuFeature::Smep);
        }
        if ebx7 & (1 << 29) != 0 {
            info.features.set(CpuFeature::Sha);
        }
        // Leaf 7 ECX bit 2 = UMIP (not exposed separately), bit 20 = WAITPKG.
    }

    // Extended leaf 0x80000001.
    let ext_l0 = cpuid(0x8000_0000, 0);
    info.max_extended_leaf = ext_l0.eax;

    if info.max_extended_leaf >= 0x8000_0001 {
        let ext1 = cpuid(0x8000_0001, 0);
        let ecx_ext = ext1.ecx;
        let edx_ext = ext1.edx;
        if ecx_ext & (1 << 0) != 0 {
            info.features.set(CpuFeature::Lahf64);
        }
        if ecx_ext & (1 << 5) != 0 {
            info.features.set(CpuFeature::Lzcnt);
        }
        if edx_ext & (1 << 20) != 0 {
            info.features.set(CpuFeature::Nx);
        }
        if edx_ext & (1 << 26) != 0 {
            info.features.set(CpuFeature::Page1gb);
        }
        if edx_ext & (1 << 27) != 0 {
            info.features.set(CpuFeature::Rdtscp);
        }
        if edx_ext & (1 << 29) != 0 {
            info.features.set(CpuFeature::LongMode);
        }
    }

    info
}

/// Test whether the current CPU has a specific feature.
///
/// Convenience wrapper that calls [`detect_features`] on every call.
/// For performance-sensitive code, call [`detect_features`] once and
/// cache the [`CpuId`] result.
pub fn has_feature(feature: CpuFeature) -> bool {
    detect_features().features.has(feature)
}

/// Return the CPU vendor string as a UTF-8 str, if valid.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the vendor string is not
/// valid UTF-8.
pub fn vendor_string(info: &CpuId) -> Result<&str> {
    core::str::from_utf8(&info.vendor).map_err(|_| Error::InvalidArgument)
}
