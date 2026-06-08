// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI-based CPU frequency control (acpi-cpufreq).
//!
//! Implements frequency scaling using ACPI _PCT (Performance Control),
//! _PSS (Performance Supported States), and _PPC (Performance Present
//! Capabilities) objects. This is the classic x86 P-state mechanism
//! predating the modern HWP/HFI interfaces.

#![cfg_attr(
    not(target_arch = "x86_64"),
    allow(unreachable_code, unused_variables, dead_code)
)]

use oncrix_lib::{Error, Result};

/// Maximum number of P-states per CPU.
pub const ACPI_CPUFREQ_MAX_PSTATES: usize = 16;

/// ACPI P-state descriptor (from _PSS).
#[derive(Debug, Clone, Copy, Default)]
pub struct PState {
    /// Core frequency in MHz.
    pub freq_mhz: u32,
    /// Power dissipation in mW.
    pub power_mw: u32,
    /// Transition latency in µs.
    pub latency_us: u32,
    /// Bus master latency in µs.
    pub bm_latency_us: u32,
    /// Value to write to the performance control register.
    pub control: u32,
    /// Value to compare against the status register for confirmation.
    pub status: u32,
}

/// Performance control register address types (from _PCT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PctAddrType {
    /// Fixed Function Hardware (FFH) — MSR-based control.
    Ffh,
    /// System I/O — port I/O based control.
    Sysio,
}

/// Performance Control Table (_PCT) parsed result.
#[derive(Debug, Clone, Copy)]
pub struct PctDescriptor {
    /// Address type.
    pub addr_type: PctAddrType,
    /// Register address (MSR number or I/O port).
    pub address: u64,
    /// Bit width of the control field.
    pub bit_width: u8,
    /// Bit offset within the register.
    pub bit_offset: u8,
}

impl Default for PctDescriptor {
    fn default() -> Self {
        Self {
            addr_type: PctAddrType::Ffh,
            address: 0,
            bit_width: 8,
            bit_offset: 0,
        }
    }
}

/// ACPI CPU frequency driver for a single logical CPU.
#[derive(Debug)]
pub struct AcpiCpuFreq {
    /// Logical CPU index.
    pub cpu: u32,
    /// Performance control register (from _PCT).
    pub perf_ctrl: PctDescriptor,
    /// Performance status register (from _PCT).
    pub perf_status: PctDescriptor,
    /// Number of valid P-states.
    pub num_pstates: usize,
    /// P-state table (from _PSS).
    pub pstates: [PState; ACPI_CPUFREQ_MAX_PSTATES],
    /// Current P-state index (0 = fastest).
    pub current_pstate: usize,
    /// Highest P-state allowed by platform (_PPC).
    pub max_pstate: usize,
}

impl AcpiCpuFreq {
    /// Creates a new ACPI cpufreq handle for CPU `cpu`.
    pub const fn new(cpu: u32) -> Self {
        Self {
            cpu,
            perf_ctrl: PctDescriptor {
                addr_type: PctAddrType::Ffh,
                address: 0,
                bit_width: 8,
                bit_offset: 0,
            },
            perf_status: PctDescriptor {
                addr_type: PctAddrType::Ffh,
                address: 0,
                bit_width: 8,
                bit_offset: 0,
            },
            num_pstates: 0,
            pstates: [const {
                PState {
                    freq_mhz: 0,
                    power_mw: 0,
                    latency_us: 0,
                    bm_latency_us: 0,
                    control: 0,
                    status: 0,
                }
            }; ACPI_CPUFREQ_MAX_PSTATES],
            current_pstate: 0,
            max_pstate: 0,
        }
    }

    /// Registers P-states from a parsed _PSS table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pss` is empty or too large.
    pub fn set_pstates(&mut self, pss: &[PState]) -> Result<()> {
        if pss.is_empty() || pss.len() > ACPI_CPUFREQ_MAX_PSTATES {
            return Err(Error::InvalidArgument);
        }
        self.num_pstates = pss.len();
        self.pstates[..pss.len()].copy_from_slice(pss);
        self.max_pstate = pss.len() - 1;
        Ok(())
    }

    /// Sets the current P-state (0 = highest performance).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx >= num_pstates`.
    /// Returns [`Error::PermissionDenied`] if `idx > max_pstate` (_PPC limit).
    pub fn set_pstate(&mut self, idx: usize) -> Result<()> {
        // SECURITY: also bound idx by the physical array size — `num_pstates`
        // is a pub field that could be poked above ACPI_CPUFREQ_MAX_PSTATES,
        // which would let `idx < num_pstates` still index `pstates[idx]` out
        // of bounds below.
        if idx >= self.num_pstates || idx >= ACPI_CPUFREQ_MAX_PSTATES {
            return Err(Error::InvalidArgument);
        }
        // SECURITY: max_pstate is pub and sourced from the firmware _PPC
        // object, which may supply a value >= num_pstates.  Clamp the
        // effective ceiling so a stale or adversarial _PPC cannot bypass
        // the num_pstates bound and reach an uninitialised pstates slot.
        let cap = self.max_pstate.min(self.num_pstates.saturating_sub(1));
        if idx > cap {
            return Err(Error::PermissionDenied);
        }
        let ctrl_val = self.pstates[idx].control;
        self.write_perf_ctrl(ctrl_val)?;
        self.current_pstate = idx;
        Ok(())
    }

    /// Reads the current effective P-state from the status register.
    pub fn read_current_pstate(&self) -> Result<usize> {
        let status = self.read_perf_status()?;
        // SECURITY: clamp the slice bound to the physical array size (pub
        // `num_pstates` could exceed ACPI_CPUFREQ_MAX_PSTATES).
        for (i, ps) in self.pstates[..self.num_pstates.min(ACPI_CPUFREQ_MAX_PSTATES)]
            .iter()
            .enumerate()
        {
            if ps.status == status {
                return Ok(i);
            }
        }
        Err(Error::IoError)
    }

    /// Returns the frequency of the current P-state in MHz.
    pub fn current_freq_mhz(&self) -> u32 {
        // SECURITY: current_pstate and num_pstates are pub and may be set by
        // firmware-supplied ACPI _PSS data; guard all three bounds before
        // indexing the fixed-size array to prevent out-of-bounds access.
        if self.num_pstates == 0
            || self.current_pstate >= self.num_pstates
            || self.current_pstate >= ACPI_CPUFREQ_MAX_PSTATES
        {
            return 0;
        }
        self.pstates[self.current_pstate].freq_mhz
    }

    /// Returns the maximum frequency in MHz (P-state 0).
    pub fn max_freq_mhz(&self) -> u32 {
        if self.num_pstates == 0 {
            return 0;
        }
        self.pstates[0].freq_mhz
    }

    /// Returns the minimum frequency in MHz (last P-state).
    pub fn min_freq_mhz(&self) -> u32 {
        // SECURITY: num_pstates is pub; a firmware or caller could set it
        // beyond ACPI_CPUFREQ_MAX_PSTATES, making `num_pstates - 1` an
        // out-of-bounds index on the fixed-size array.  Clamp before use.
        if self.num_pstates == 0 {
            return 0;
        }
        let last = self.num_pstates.min(ACPI_CPUFREQ_MAX_PSTATES) - 1;
        self.pstates[last].freq_mhz
    }

    // ---- private helpers ----

    fn write_perf_ctrl(&self, value: u32) -> Result<()> {
        match self.perf_ctrl.addr_type {
            PctAddrType::Ffh => {
                // Write to MSR (FFH).
                #[cfg(target_arch = "x86_64")]
                {
                    let msr = self.perf_ctrl.address as u32;
                    // SAFETY: Writing a well-known IA32_PERF_CTL MSR on
                    // the current CPU; value is a valid P-state control word.
                    unsafe {
                        core::arch::asm!(
                            "wrmsr",
                            in("ecx") msr,
                            in("eax") value,
                            in("edx") 0u32,
                            options(nostack, nomem),
                        );
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    let _ = value;
                    return Err(Error::NotImplemented);
                }
                Ok(())
            }
            PctAddrType::Sysio => {
                // Port I/O write.
                #[cfg(target_arch = "x86_64")]
                {
                    let port = self.perf_ctrl.address as u16;
                    // SAFETY: Writing to a well-known ACPI performance port.
                    unsafe {
                        core::arch::asm!(
                            "out dx, al",
                            in("dx") port,
                            in("al") value as u8,
                            options(nostack, nomem),
                        );
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    let _ = value;
                    return Err(Error::NotImplemented);
                }
                Ok(())
            }
        }
    }

    fn read_perf_status(&self) -> Result<u32> {
        match self.perf_status.addr_type {
            PctAddrType::Ffh => {
                #[cfg(target_arch = "x86_64")]
                {
                    let msr = self.perf_status.address as u32;
                    let eax: u32;
                    // SAFETY: Reading IA32_PERF_STATUS MSR.
                    unsafe {
                        core::arch::asm!(
                            "rdmsr",
                            in("ecx") msr,
                            out("eax") eax,
                            out("edx") _,
                            options(nostack, nomem),
                        );
                    }
                    Ok(eax)
                }
                #[cfg(not(target_arch = "x86_64"))]
                Err(Error::NotImplemented)
            }
            PctAddrType::Sysio => Err(Error::NotImplemented),
        }
    }
}

impl Default for AcpiCpuFreq {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Returns the best P-state index for a target frequency in MHz.
///
/// Selects the lowest-numbered (highest-performance) P-state whose frequency
/// does not exceed `target_mhz`. Returns `num_pstates - 1` if none qualifies.
pub fn select_pstate(driver: &AcpiCpuFreq, target_mhz: u32) -> usize {
    // SECURITY: clamp to the physical array size (pub `num_pstates` could
    // exceed ACPI_CPUFREQ_MAX_PSTATES and OOB-slice `pstates` below).
    let n = driver.num_pstates.min(ACPI_CPUFREQ_MAX_PSTATES);
    if n == 0 {
        return 0;
    }
    // P-states are ordered from highest to lowest frequency.
    for (i, ps) in driver.pstates[..n].iter().enumerate() {
        if ps.freq_mhz <= target_mhz {
            return i;
        }
    }
    n - 1
}
