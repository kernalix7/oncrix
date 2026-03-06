// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x2APIC mode support.
//!
//! x2APIC extends the xAPIC architecture to support more than 255 logical
//! processors and uses MSR-based register access instead of MMIO. All
//! registers are accessed via `RDMSR`/`WRMSR` instructions, eliminating
//! the need for mapping the APIC register page.
//!
//! # Key Differences from xAPIC
//!
//! - APIC ID is 32-bit (vs 8-bit)
//! - ICR is a single 64-bit MSR (no two-step write)
//! - Cluster addressing for IPIs
//! - No physical MMIO mapping required
//!
//! Reference: Intel SDM Vol. 3A, Section 10.12

use oncrix_lib::{Error, Result};

// ── MSR addresses ────────────────────────────────────────────────────────────

/// x2APIC APIC ID MSR.
const MSR_X2APIC_APICID: u32 = 0x802;
/// x2APIC version MSR.
const MSR_X2APIC_VERSION: u32 = 0x803;
/// x2APIC Task Priority Register (TPR).
const MSR_X2APIC_TPR: u32 = 0x808;
/// x2APIC End-of-Interrupt MSR (write-only).
const MSR_X2APIC_EOI: u32 = 0x80B;
/// x2APIC Logical Destination Register.
const MSR_X2APIC_LDR: u32 = 0x80D;
/// x2APIC Spurious Interrupt Vector Register.
const MSR_X2APIC_SVR: u32 = 0x80F;
/// x2APIC In-Service Register base (ISR0..ISR7 = 0x810..0x817).
const MSR_X2APIC_ISR0: u32 = 0x810;
/// x2APIC IRR base (IRR0..IRR7 = 0x820..0x827).
const _MSR_X2APIC_IRR0: u32 = 0x820;
/// x2APIC Error Status Register.
const MSR_X2APIC_ESR: u32 = 0x828;
/// x2APIC Interrupt Command Register (64-bit, single write).
const MSR_X2APIC_ICR: u32 = 0x830;
/// x2APIC LVT Timer Register.
const MSR_X2APIC_LVT_TIMER: u32 = 0x832;
/// x2APIC LVT Thermal Sensor.
const MSR_X2APIC_LVT_THERMAL: u32 = 0x833;
/// x2APIC LVT Performance Monitor.
const MSR_X2APIC_LVT_PMI: u32 = 0x834;
/// x2APIC LVT LINT0.
const MSR_X2APIC_LVT_LINT0: u32 = 0x835;
/// x2APIC LVT LINT1.
const MSR_X2APIC_LVT_LINT1: u32 = 0x836;
/// x2APIC LVT Error.
const MSR_X2APIC_LVT_ERROR: u32 = 0x837;
/// x2APIC Initial Count Register (for timer).
const MSR_X2APIC_TIMER_ICR: u32 = 0x838;
/// x2APIC Current Count Register (for timer).
const MSR_X2APIC_TIMER_CCR: u32 = 0x839;
/// x2APIC Divide Configuration Register (for timer).
const MSR_X2APIC_TIMER_DCR: u32 = 0x83E;
/// x2APIC self-IPI MSR.
const MSR_X2APIC_SELF_IPI: u32 = 0x83F;

/// IA32_APIC_BASE MSR address.
const MSR_IA32_APIC_BASE: u32 = 0x1B;

// ── Bit fields ───────────────────────────────────────────────────────────────

/// IA32_APIC_BASE: xAPIC global enable bit.
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// IA32_APIC_BASE: x2APIC mode enable bit.
const APIC_BASE_X2APIC: u64 = 1 << 10;
/// IA32_APIC_BASE: BSP flag.
const APIC_BASE_BSP: u64 = 1 << 8;

/// Spurious vector register: APIC software enable bit.
const SVR_APIC_ENABLE: u32 = 1 << 8;

/// LVT: mask bit.
const LVT_MASK: u32 = 1 << 16;

/// Timer mode: one-shot.
const TIMER_MODE_ONESHOT: u32 = 0 << 17;
/// Timer mode: periodic.
const TIMER_MODE_PERIODIC: u32 = 1 << 17;
/// Timer mode: TSC-deadline.
const _TIMER_MODE_TSCDEADLINE: u32 = 2 << 17;

/// IPI delivery mode: fixed.
pub const IPI_DELIVERY_FIXED: u8 = 0;
/// IPI delivery mode: lowest priority.
pub const _IPI_DELIVERY_LOWEST: u8 = 1;
/// IPI delivery mode: NMI.
pub const IPI_DELIVERY_NMI: u8 = 4;
/// IPI delivery mode: INIT.
pub const IPI_DELIVERY_INIT: u8 = 5;
/// IPI delivery mode: SIPI.
pub const IPI_DELIVERY_SIPI: u8 = 6;

/// IPI destination shorthand: no shorthand.
const IPI_DEST_NO_SHORTHAND: u64 = 0 << 18;
/// IPI destination shorthand: self.
pub const IPI_DEST_SELF: u64 = 1 << 18;
/// IPI destination shorthand: all including self.
pub const IPI_DEST_ALL_INCL_SELF: u64 = 2 << 18;
/// IPI destination shorthand: all excluding self.
pub const IPI_DEST_ALL_EXCL_SELF: u64 = 3 << 18;

/// IPI level: assert.
const IPI_LEVEL_ASSERT: u64 = 1 << 14;

// ── CPUID helpers ────────────────────────────────────────────────────────────

/// Check whether the CPU supports x2APIC mode via CPUID.
///
/// Returns `true` if CPUID leaf 1 ECX bit 21 is set.
#[cfg(target_arch = "x86_64")]
pub fn cpuid_has_x2apic() -> bool {
    let ecx: u32;
    // SAFETY: CPUID is always safe to execute on x86_64.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    ecx & (1 << 21) != 0
}

/// Stub for non-x86_64 targets.
#[cfg(not(target_arch = "x86_64"))]
pub fn cpuid_has_x2apic() -> bool {
    false
}

// ── MSR access ───────────────────────────────────────────────────────────────

/// Read a Model Specific Register.
///
/// # Safety
///
/// The caller must ensure `msr` is a valid readable MSR on the current CPU.
#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Caller guarantees valid MSR address.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Write a Model Specific Register.
///
/// # Safety
///
/// The caller must ensure `msr` is a valid writable MSR on the current CPU.
#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: Caller guarantees valid MSR address.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

// ── IpiDestination ───────────────────────────────────────────────────────────

/// Specifies the target(s) of an inter-processor interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiDestination {
    /// Send to a specific APIC ID.
    Specific(u32),
    /// Send only to self.
    SelfOnly,
    /// Send to all CPUs including self.
    AllIncludingSelf,
    /// Send to all CPUs except self.
    AllExcludingSelf,
}

// ── TimerDivide ──────────────────────────────────────────────────────────────

/// APIC timer clock divide configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerDivide {
    /// Divide by 1.
    By1 = 0b1011,
    /// Divide by 2.
    By2 = 0b0000,
    /// Divide by 4.
    By4 = 0b0001,
    /// Divide by 8.
    By8 = 0b0010,
    /// Divide by 16.
    By16 = 0b0011,
    /// Divide by 32.
    By32 = 0b1000,
    /// Divide by 64.
    By64 = 0b1001,
    /// Divide by 128.
    By128 = 0b1010,
}

// ── X2Apic ───────────────────────────────────────────────────────────────────

/// x2APIC driver.
///
/// Manages the local APIC in x2APIC mode for the current CPU core.
/// Each core has its own x2APIC instance; this struct is not shared
/// across cores.
pub struct X2Apic {
    /// Whether x2APIC mode has been successfully enabled.
    enabled: bool,
    /// Whether this CPU is the bootstrap processor.
    is_bsp: bool,
    /// The local APIC ID (32-bit in x2APIC mode).
    apic_id: u32,
}

impl X2Apic {
    /// Create a new, uninitialised x2APIC instance.
    pub const fn new() -> Self {
        Self {
            enabled: false,
            is_bsp: false,
            apic_id: 0,
        }
    }

    /// Initialise and enable x2APIC mode on the current CPU.
    ///
    /// Checks CPUID for x2APIC support, enables x2APIC mode via
    /// IA32_APIC_BASE, enables the APIC software via SVR, and
    /// configures a spurious vector of 0xFF.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the CPU does not support x2APIC.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        if !cpuid_has_x2apic() {
            return Err(Error::NotImplemented);
        }

        // Read current APIC base MSR.
        // SAFETY: MSR_IA32_APIC_BASE is always readable on x86_64 with APIC.
        let base = unsafe { rdmsr(MSR_IA32_APIC_BASE) };

        self.is_bsp = base & APIC_BASE_BSP != 0;

        // Enable x2APIC and xAPIC if not already enabled.
        let new_base = base | APIC_BASE_ENABLE | APIC_BASE_X2APIC;
        // SAFETY: Setting x2APIC mode on a CPU that supports it.
        unsafe { wrmsr(MSR_IA32_APIC_BASE, new_base) };

        // Clear ESR before software enable.
        // SAFETY: Writing 0 to ESR is always valid.
        unsafe { wrmsr(MSR_X2APIC_ESR, 0) };

        // Read APIC ID.
        // SAFETY: Reading APICID MSR in x2APIC mode.
        self.apic_id = unsafe { rdmsr(MSR_X2APIC_APICID) } as u32;

        // Enable APIC with spurious vector 0xFF.
        // SAFETY: Writing SVR to enable the APIC.
        unsafe { wrmsr(MSR_X2APIC_SVR as u32, (SVR_APIC_ENABLE | 0xFF) as u64) };

        // Mask all LVT entries initially.
        // SAFETY: Writing LVT mask bits is always valid.
        unsafe {
            wrmsr(MSR_X2APIC_LVT_TIMER, LVT_MASK as u64);
            wrmsr(MSR_X2APIC_LVT_THERMAL, LVT_MASK as u64);
            wrmsr(MSR_X2APIC_LVT_PMI, LVT_MASK as u64);
            wrmsr(MSR_X2APIC_LVT_ERROR, LVT_MASK as u64);
        }

        self.enabled = true;
        Ok(())
    }

    /// Stub init for non-x86_64.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Send End-of-Interrupt signal.
    ///
    /// Must be called at the end of every interrupt handler that
    /// processes a local APIC interrupt.
    #[cfg(target_arch = "x86_64")]
    pub fn eoi(&self) {
        // SAFETY: Writing 0 to EOI MSR signals end of interrupt.
        unsafe { wrmsr(MSR_X2APIC_EOI, 0) };
    }

    /// Stub EOI for non-x86_64.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn eoi(&self) {}

    /// Send an Inter-Processor Interrupt.
    ///
    /// In x2APIC mode the ICR is a single 64-bit MSR write, eliminating
    /// the two-step write sequence required by xAPIC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    #[cfg(target_arch = "x86_64")]
    pub fn send_ipi(&self, dest: IpiDestination, vector: u8, delivery_mode: u8) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        let (dest_field, shorthand) = match dest {
            IpiDestination::Specific(id) => ((id as u64) << 32, IPI_DEST_NO_SHORTHAND),
            IpiDestination::SelfOnly => (0, IPI_DEST_SELF),
            IpiDestination::AllIncludingSelf => (0, IPI_DEST_ALL_INCL_SELF),
            IpiDestination::AllExcludingSelf => (0, IPI_DEST_ALL_EXCL_SELF),
        };

        let icr = dest_field
            | shorthand
            | IPI_LEVEL_ASSERT
            | ((delivery_mode as u64) << 8)
            | vector as u64;

        // SAFETY: ICR write sends IPI; dest and vector are validated above.
        unsafe { wrmsr(MSR_X2APIC_ICR, icr) };
        Ok(())
    }

    /// Stub send_ipi for non-x86_64.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn send_ipi(&self, _dest: IpiDestination, _vector: u8, _delivery_mode: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Send an INIT IPI to the specified APIC ID (for AP bring-up).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    pub fn send_init(&self, apic_id: u32) -> Result<()> {
        self.send_ipi(IpiDestination::Specific(apic_id), 0, IPI_DELIVERY_INIT)
    }

    /// Send a SIPI (Startup IPI) to the specified APIC ID.
    ///
    /// The `vector` encodes the startup address page (address / 4096).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    pub fn send_sipi(&self, apic_id: u32, vector: u8) -> Result<()> {
        self.send_ipi(IpiDestination::Specific(apic_id), vector, IPI_DELIVERY_SIPI)
    }

    /// Configure the APIC timer in one-shot mode.
    ///
    /// Sets the divide configuration and initial count. The timer fires
    /// once when the count reaches zero, generating interrupt `vector`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    #[cfg(target_arch = "x86_64")]
    pub fn timer_oneshot(&self, vector: u8, divide: TimerDivide, count: u32) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // SAFETY: Writing timer registers when x2APIC is enabled.
        unsafe {
            wrmsr(MSR_X2APIC_TIMER_DCR, divide as u64);
            wrmsr(
                MSR_X2APIC_LVT_TIMER,
                TIMER_MODE_ONESHOT as u64 | vector as u64,
            );
            wrmsr(MSR_X2APIC_TIMER_ICR, count as u64);
        }
        Ok(())
    }

    /// Configure the APIC timer in periodic mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    #[cfg(target_arch = "x86_64")]
    pub fn timer_periodic(&self, vector: u8, divide: TimerDivide, count: u32) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // SAFETY: Writing timer registers when x2APIC is enabled.
        unsafe {
            wrmsr(MSR_X2APIC_TIMER_DCR, divide as u64);
            wrmsr(
                MSR_X2APIC_LVT_TIMER,
                TIMER_MODE_PERIODIC as u64 | vector as u64,
            );
            wrmsr(MSR_X2APIC_TIMER_ICR, count as u64);
        }
        Ok(())
    }

    /// Read the APIC timer current count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    #[cfg(target_arch = "x86_64")]
    pub fn timer_current_count(&self) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // SAFETY: Reading timer CCR when x2APIC is enabled.
        let val = unsafe { rdmsr(MSR_X2APIC_TIMER_CCR) };
        Ok(val as u32)
    }

    /// Read the error status register.
    ///
    /// Writes 0 first to latch the error bits, then reads.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    #[cfg(target_arch = "x86_64")]
    pub fn error_status(&self) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // SAFETY: ESR write-then-read sequence.
        unsafe {
            wrmsr(MSR_X2APIC_ESR, 0);
            Ok(rdmsr(MSR_X2APIC_ESR) as u32)
        }
    }

    /// Return the Task Priority Register value.
    #[cfg(target_arch = "x86_64")]
    pub fn task_priority(&self) -> u8 {
        // SAFETY: Reading TPR MSR.
        unsafe { rdmsr(MSR_X2APIC_TPR) as u8 }
    }

    /// Set the Task Priority Register.
    ///
    /// Only interrupts with priority > TPR are delivered.
    #[cfg(target_arch = "x86_64")]
    pub fn set_task_priority(&self, priority: u8) {
        // SAFETY: Writing TPR to set interrupt priority.
        unsafe { wrmsr(MSR_X2APIC_TPR, priority as u64) };
    }

    /// Return the logical destination register value.
    #[cfg(target_arch = "x86_64")]
    pub fn logical_destination(&self) -> u32 {
        // SAFETY: Reading LDR MSR.
        unsafe { rdmsr(MSR_X2APIC_LDR) as u32 }
    }

    /// Check whether a given interrupt vector is in-service.
    ///
    /// The ISR spans 8 MSRs (ISR0..ISR7) covering vectors 0..255.
    pub fn vector_in_service(&self, vector: u8) -> bool {
        let word = (vector / 32) as u32;
        let bit = vector % 32;
        // SAFETY: ISR MSRs are always readable when x2APIC is enabled.
        #[cfg(target_arch = "x86_64")]
        let isr = unsafe { rdmsr(MSR_X2APIC_ISR0 + word) } as u32;
        #[cfg(not(target_arch = "x86_64"))]
        let isr = 0u32;
        isr & (1 << bit) != 0
    }

    /// Return the APIC ID of this CPU.
    pub fn apic_id(&self) -> u32 {
        self.apic_id
    }

    /// Return whether this CPU is the bootstrap processor.
    pub fn is_bsp(&self) -> bool {
        self.is_bsp
    }

    /// Return whether x2APIC mode is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Send a self-IPI via the dedicated MSR_X2APIC_SELF_IPI MSR.
    ///
    /// More efficient than writing ICR with self shorthand.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if x2APIC is not enabled.
    #[cfg(target_arch = "x86_64")]
    pub fn self_ipi(&self, vector: u8) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        // SAFETY: Self-IPI MSR write sends interrupt to self.
        unsafe { wrmsr(MSR_X2APIC_SELF_IPI, vector as u64) };
        Ok(())
    }
}

impl Default for X2Apic {
    fn default() -> Self {
        Self::new()
    }
}
