// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPUID instruction wrapper and feature detection.
//!
//! Provides a safe abstraction over the raw `cpuid` instruction:
//!
//! - [`cpuid`] — raw CPUID query returning (EAX, EBX, ECX, EDX).
//! - [`CpuInfo`] — parsed CPU identity and feature flags.
//! - [`CpuFeatures`] — bitflag set for commonly-needed features.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 2A, Chapter 3 — CPUID instruction.

// ---------------------------------------------------------------------------
// Raw CPUID
// ---------------------------------------------------------------------------

/// Executes `CPUID` with the given `leaf` and `subleaf`.
///
/// Returns `(eax, ebx, ecx, edx)`.
///
/// # Safety
/// CPUID is non-destructive and can be called from any privilege level.
/// RBX is callee-saved and handled explicitly here via a temporary register.
#[cfg(target_arch = "x86_64")]
pub unsafe fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is always safe on x86_64; RBX is preserved via tmp register.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            tmp = out(reg) ebx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Returns the maximum basic CPUID leaf supported by the CPU.
///
/// # Safety
/// CPUID leaf 0 is always valid.
#[cfg(target_arch = "x86_64")]
pub unsafe fn max_basic_leaf() -> u32 {
    // SAFETY: Leaf 0 is always valid; safe to call anywhere.
    unsafe { cpuid(0, 0).0 }
}

/// Returns the maximum extended CPUID leaf (0x8000_0000+).
///
/// # Safety
/// Extended leaf 0x8000_0000 is always valid on modern CPUs.
#[cfg(target_arch = "x86_64")]
pub unsafe fn max_extended_leaf() -> u32 {
    // SAFETY: Extended leaf 0x8000_0000 is universally available.
    unsafe { cpuid(0x8000_0000, 0).0 }
}

// ---------------------------------------------------------------------------
// Vendor String
// ---------------------------------------------------------------------------

/// CPU vendor string (12 bytes from CPUID leaf 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VendorString(pub [u8; 12]);

impl VendorString {
    /// Intel GenuineIntel.
    pub const INTEL: Self = Self(*b"GenuineIntel");
    /// AMD AuthenticAMD.
    pub const AMD: Self = Self(*b"AuthenticAMD");

    /// Returns the vendor string as a `&str` if valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Returns `true` if this is an Intel CPU.
    pub fn is_intel(&self) -> bool {
        self == &Self::INTEL
    }

    /// Returns `true` if this is an AMD CPU.
    pub fn is_amd(&self) -> bool {
        self == &Self::AMD
    }
}

/// Reads the CPU vendor string from CPUID leaf 0.
///
/// # Safety
/// Always safe to call on x86_64.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_vendor() -> VendorString {
    // SAFETY: Leaf 0 is always valid.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    let mut s = [0u8; 12];
    s[0..4].copy_from_slice(&ebx.to_le_bytes());
    s[4..8].copy_from_slice(&edx.to_le_bytes());
    s[8..12].copy_from_slice(&ecx.to_le_bytes());
    VendorString(s)
}

// ---------------------------------------------------------------------------
// CPU Features (Leaf 1)
// ---------------------------------------------------------------------------

/// Feature flags from CPUID leaf 1 ECX (SSE4.2 era and later features).
pub mod feature_ecx {
    /// SSE3 support.
    pub const SSE3: u32 = 1 << 0;
    /// PCLMULQDQ support.
    pub const PCLMUL: u32 = 1 << 1;
    /// MONITOR/MWAIT support.
    pub const DTES64: u32 = 1 << 2;
    /// Supplemental SSE3 (SSSE3).
    pub const SSSE3: u32 = 1 << 9;
    /// SSE4.1 support.
    pub const SSE41: u32 = 1 << 19;
    /// SSE4.2 support.
    pub const SSE42: u32 = 1 << 20;
    /// x2APIC support.
    pub const X2APIC: u32 = 1 << 21;
    /// POPCNT instruction.
    pub const POPCNT: u32 = 1 << 23;
    /// TSC-Deadline mode for APIC timer.
    pub const TSC_DEADLINE: u32 = 1 << 24;
    /// AES-NI hardware acceleration.
    pub const AES: u32 = 1 << 25;
    /// XSAVE/XRSTOR support.
    pub const XSAVE: u32 = 1 << 26;
    /// OS has enabled XSAVE (OSXSAVE in CR4).
    pub const OSXSAVE: u32 = 1 << 27;
    /// AVX support (256-bit SIMD).
    pub const AVX: u32 = 1 << 28;
    /// F16C (half-precision) support.
    pub const F16C: u32 = 1 << 29;
    /// RDRAND instruction.
    pub const RDRAND: u32 = 1 << 30;
    /// Hypervisor present.
    pub const HYPERVISOR: u32 = 1 << 31;
}

/// Feature flags from CPUID leaf 1 EDX (legacy SSE era).
pub mod feature_edx {
    /// FPU on-chip.
    pub const FPU: u32 = 1 << 0;
    /// VME (Virtual-8086 mode extensions).
    pub const VME: u32 = 1 << 1;
    /// TSC (Time Stamp Counter).
    pub const TSC: u32 = 1 << 4;
    /// MSRs present.
    pub const MSR: u32 = 1 << 5;
    /// PAE (Physical Address Extensions).
    pub const PAE: u32 = 1 << 6;
    /// APIC on-chip.
    pub const APIC: u32 = 1 << 9;
    /// SYSCALL/SYSRET.
    pub const SEP: u32 = 1 << 11;
    /// MTRR support.
    pub const MTRR: u32 = 1 << 12;
    /// PGE (Global page support).
    pub const PGE: u32 = 1 << 13;
    /// CMOV instruction.
    pub const CMOV: u32 = 1 << 15;
    /// PAT (Page Attribute Table).
    pub const PAT: u32 = 1 << 16;
    /// MMX instructions.
    pub const MMX: u32 = 1 << 23;
    /// FXSAVE/FXRSTOR.
    pub const FXSR: u32 = 1 << 24;
    /// SSE instructions.
    pub const SSE: u32 = 1 << 25;
    /// SSE2 instructions.
    pub const SSE2: u32 = 1 << 26;
    /// Hyper-Threading Technology.
    pub const HTT: u32 = 1 << 28;
}

/// Feature flags from CPUID leaf 7, sub-leaf 0, EBX (AVX2 era).
pub mod feature_ebx7 {
    /// FSGSBASE instructions.
    pub const FSGSBASE: u32 = 1 << 0;
    /// TSC adjust MSR.
    pub const TSC_ADJUST: u32 = 1 << 1;
    /// AVX2 support.
    pub const AVX2: u32 = 1 << 5;
    /// SMEP support.
    pub const SMEP: u32 = 1 << 7;
    /// BMI2 instructions.
    pub const BMI2: u32 = 1 << 8;
    /// INVPCID instruction.
    pub const INVPCID: u32 = 1 << 10;
    /// AVX-512 Foundation.
    pub const AVX512F: u32 = 1 << 16;
    /// SMAP support.
    pub const SMAP: u32 = 1 << 20;
    /// CLFLUSHOPT instruction.
    pub const CLFLUSHOPT: u32 = 1 << 23;
    /// CLWB (cache-line write-back) instruction.
    pub const CLWB: u32 = 1 << 24;
    /// SHA instructions.
    pub const SHA: u32 = 1 << 29;
}

// ---------------------------------------------------------------------------
// CpuFeatures
// ---------------------------------------------------------------------------

/// Parsed feature set for the current CPU.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuFeatures {
    /// CPUID leaf 1, ECX output.
    pub leaf1_ecx: u32,
    /// CPUID leaf 1, EDX output.
    pub leaf1_edx: u32,
    /// CPUID leaf 7, sub-leaf 0, EBX output.
    pub leaf7_ebx: u32,
    /// CPUID leaf 7, sub-leaf 0, ECX output.
    pub leaf7_ecx: u32,
    /// CPUID extended leaf 0x8000_0001, EDX (for NX bit etc.).
    pub ext_edx: u32,
}

impl CpuFeatures {
    /// Returns `true` if SSE is supported.
    pub const fn has_sse(&self) -> bool {
        self.leaf1_edx & feature_edx::SSE != 0
    }
    /// Returns `true` if SSE2 is supported.
    pub const fn has_sse2(&self) -> bool {
        self.leaf1_edx & feature_edx::SSE2 != 0
    }
    /// Returns `true` if AVX is supported.
    pub const fn has_avx(&self) -> bool {
        self.leaf1_ecx & feature_ecx::AVX != 0
    }
    /// Returns `true` if AVX2 is supported.
    pub const fn has_avx2(&self) -> bool {
        self.leaf7_ebx & feature_ebx7::AVX2 != 0
    }
    /// Returns `true` if AES-NI is supported.
    pub const fn has_aes(&self) -> bool {
        self.leaf1_ecx & feature_ecx::AES != 0
    }
    /// Returns `true` if XSAVE is supported.
    pub const fn has_xsave(&self) -> bool {
        self.leaf1_ecx & feature_ecx::XSAVE != 0
    }
    /// Returns `true` if RDRAND is supported.
    pub const fn has_rdrand(&self) -> bool {
        self.leaf1_ecx & feature_ecx::RDRAND != 0
    }
    /// Returns `true` if SMEP is supported.
    pub const fn has_smep(&self) -> bool {
        self.leaf7_ebx & feature_ebx7::SMEP != 0
    }
    /// Returns `true` if SMAP is supported.
    pub const fn has_smap(&self) -> bool {
        self.leaf7_ebx & feature_ebx7::SMAP != 0
    }
    /// Returns `true` if INVPCID is supported.
    pub const fn has_invpcid(&self) -> bool {
        self.leaf7_ebx & feature_ebx7::INVPCID != 0
    }
    /// Returns `true` if the NX (No-Execute) page table bit is supported.
    pub const fn has_nx(&self) -> bool {
        self.ext_edx & (1 << 20) != 0
    }
    /// Returns `true` if TSC-Deadline APIC timer mode is supported.
    pub const fn has_tsc_deadline(&self) -> bool {
        self.leaf1_ecx & feature_ecx::TSC_DEADLINE != 0
    }
    /// Returns `true` if x2APIC mode is supported.
    pub const fn has_x2apic(&self) -> bool {
        self.leaf1_ecx & feature_ecx::X2APIC != 0
    }
}

// ---------------------------------------------------------------------------
// CpuInfo
// ---------------------------------------------------------------------------

/// Full CPU identification and feature snapshot.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuInfo {
    /// Vendor string.
    pub vendor: VendorString,
    /// Maximum basic CPUID leaf.
    pub max_leaf: u32,
    /// Maximum extended CPUID leaf.
    pub max_ext_leaf: u32,
    /// APIC ID of this logical processor (leaf 1, EBX bits 31:24).
    pub apic_id: u8,
    /// CPU family, model, stepping from leaf 1 EAX.
    pub signature: u32,
    /// Detected feature set.
    pub features: CpuFeatures,
}

impl CpuInfo {
    /// Returns the raw CPU stepping (bits 3:0 of signature).
    pub const fn stepping(&self) -> u8 {
        (self.signature & 0x0F) as u8
    }

    /// Returns the extended model identifier.
    pub const fn model(&self) -> u8 {
        let base = (self.signature >> 4) & 0x0F;
        let ext = (self.signature >> 16) & 0x0F;
        (ext << 4 | base) as u8
    }

    /// Returns the CPU family.
    pub const fn family(&self) -> u8 {
        let base = (self.signature >> 8) & 0x0F;
        let ext = (self.signature >> 20) & 0xFF;
        if base == 0x0F {
            (ext + base) as u8
        } else {
            base as u8
        }
    }

    /// Returns `true` if this is an Intel CPU.
    pub fn is_intel(&self) -> bool {
        self.vendor.is_intel()
    }

    /// Returns `true` if this is an AMD CPU.
    pub fn is_amd(&self) -> bool {
        self.vendor.is_amd()
    }
}

impl Default for VendorString {
    fn default() -> Self {
        Self([0u8; 12])
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Queries all relevant CPUID leaves and builds a `CpuInfo`.
///
/// # Safety
/// CPUID is always safe on x86_64. Must be called after processor reset
/// or early boot (not inside a pre-emptible context without saving RBX).
#[cfg(target_arch = "x86_64")]
pub unsafe fn detect_cpu() -> CpuInfo {
    // SAFETY: CPUID reads are always safe.
    unsafe {
        let vendor = read_vendor();
        let max_leaf = max_basic_leaf();
        let max_ext_leaf = max_extended_leaf();

        // Leaf 1: signature, APIC ID, ECX/EDX features.
        let (eax, ebx, ecx, edx) = cpuid(1, 0);
        let apic_id = ((ebx >> 24) & 0xFF) as u8;
        let (leaf1_ecx, leaf1_edx) = (ecx, edx);

        // Leaf 7, sub-leaf 0: extended features.
        let (leaf7_ebx, leaf7_ecx) = if max_leaf >= 7 {
            let (_, ebx7, ecx7, _) = cpuid(7, 0);
            (ebx7, ecx7)
        } else {
            (0, 0)
        };

        // Extended leaf 0x8000_0001: NX bit and AMD-specific features.
        let ext_edx = if max_ext_leaf >= 0x8000_0001 {
            cpuid(0x8000_0001, 0).3
        } else {
            0
        };

        CpuInfo {
            vendor,
            max_leaf,
            max_ext_leaf,
            apic_id,
            signature: eax,
            features: CpuFeatures {
                leaf1_ecx,
                leaf1_edx,
                leaf7_ebx,
                leaf7_ecx,
                ext_edx,
            },
        }
    }
}

/// Returns the APIC ID of the current logical processor.
///
/// # Safety
/// CPUID is always safe; returns 0 if leaf 1 is unavailable.
#[cfg(target_arch = "x86_64")]
pub unsafe fn current_apic_id() -> u32 {
    // SAFETY: CPUID leaf 1 is always available on x86_64.
    let (_, ebx, _, _) = unsafe { cpuid(1, 0) };
    (ebx >> 24) & 0xFF
}

/// Returns the x2APIC ID of the current logical processor (leaf 0xB).
///
/// More accurate for large SMP systems where the legacy APIC ID is 8-bit.
///
/// # Safety
/// CPUID is always safe. Returns 0 if leaf 0xB is not supported.
#[cfg(target_arch = "x86_64")]
pub unsafe fn current_x2apic_id() -> u32 {
    // SAFETY: Informational CPUID query.
    unsafe {
        let max = max_basic_leaf();
        if max >= 0x0B { cpuid(0x0B, 0).3 } else { 0 }
    }
}
