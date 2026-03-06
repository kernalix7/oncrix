// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Secure Monitor Call (SMC) interface.
//!
//! Provides the non-secure world interface for calling into EL3 firmware
//! via the `smc` instruction, following the ARM SMC Calling Convention (SMCCC).
//!
//! # SMCCC (SMC Calling Convention)
//!
//! - Defined in ARM DEN0028B
//! - Register assignment: w0/x0 = function identifier, x1-x7 = arguments
//! - Return values in x0-x3
//! - Function IDs encode: calling convention, owner (ARM/CPU/SIP/OEM/STD/VENDOR), function number
//!
//! # Key Services
//!
//! - **PSCI** (Power State Coordination Interface): CPU on/off/suspend
//! - **SCMI** (System Control and Management Interface): clock/power/performance
//! - **TRNG**: True random number generator
//! - **Vendor-specific**: SoC-specific firmware services
//!
//! # References
//!
//! - ARM SMC Calling Convention, DEN0028B
//! - PSCI specification, DEN0022D

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// SMC function identifier fields.
pub mod smc_fn {
    /// Calling convention: SMC32 (32-bit).
    pub const CC_SMC32: u32 = 0 << 30;
    /// Calling convention: SMC64 (64-bit).
    pub const CC_SMC64: u32 = 1 << 30;

    /// Owner: ARM Architecture calls.
    pub const OWNER_ARCH: u32 = 0 << 24;
    /// Owner: CPU-specific calls.
    pub const OWNER_CPU: u32 = 1 << 24;
    /// Owner: SiP (Silicon Platform) specific.
    pub const OWNER_SIP: u32 = 2 << 24;
    /// Owner: OEM specific.
    pub const OWNER_OEM: u32 = 3 << 24;
    /// Owner: Standard Secure Services.
    pub const OWNER_STANDARD: u32 = 4 << 24;
    /// Owner: Standard Hypervisor Services.
    pub const OWNER_HYP: u32 = 5 << 24;
    /// Owner: Vendor-specific hypervisor.
    pub const OWNER_VENDOR_HYP: u32 = 6 << 24;
    /// Owner: Trusted application.
    pub const OWNER_TA: u32 = 0x30 << 24;

    /// PSCI function base (SMC32 Standard Secure).
    pub const PSCI_BASE: u32 = OWNER_STANDARD | CC_SMC32;
    /// PSCI function base (SMC64 Standard Secure).
    pub const PSCI64_BASE: u32 = OWNER_STANDARD | CC_SMC64;
}

/// PSCI function identifiers.
pub mod psci {
    use super::smc_fn;
    /// PSCI Version.
    pub const VERSION: u32 = smc_fn::PSCI_BASE;
    /// CPU Suspend (32-bit).
    pub const CPU_SUSPEND: u32 = smc_fn::PSCI_BASE | 1;
    /// CPU Off.
    pub const CPU_OFF: u32 = smc_fn::PSCI_BASE | 2;
    /// CPU On (32-bit).
    pub const CPU_ON: u32 = smc_fn::PSCI_BASE | 3;
    /// Affinity Info.
    pub const AFFINITY_INFO: u32 = smc_fn::PSCI_BASE | 4;
    /// System Off.
    pub const SYSTEM_OFF: u32 = smc_fn::PSCI_BASE | 8;
    /// System Reset.
    pub const SYSTEM_RESET: u32 = smc_fn::PSCI_BASE | 9;
    /// CPU Suspend (64-bit).
    pub const CPU_SUSPEND64: u32 = smc_fn::PSCI64_BASE | 1;
    /// CPU On (64-bit).
    pub const CPU_ON64: u32 = smc_fn::PSCI64_BASE | 3;
    /// PSCI Features query.
    pub const PSCI_FEATURES: u32 = smc_fn::PSCI_BASE | 0xA;
}

/// PSCI return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PsciError {
    /// Operation not supported.
    NotSupported = -1,
    /// Invalid parameters.
    InvalidParameters = -2,
    /// Operation denied (e.g., CPU already on).
    Denied = -3,
    /// Already on (CPU is already in the requested state).
    AlreadyOn = -4,
    /// Operation in progress.
    OnPending = -5,
    /// Internal failure.
    InternalFailure = -6,
    /// Not present (CPU is not implemented).
    NotPresent = -7,
    /// Operation disabled.
    Disabled = -8,
    /// Invalid address.
    InvalidAddress = -9,
}

impl PsciError {
    /// Converts an SMC return value to a `PsciError`, or `None` if success.
    pub fn from_ret(ret: i64) -> Option<Self> {
        match ret as i32 {
            0 => None,
            -1 => Some(Self::NotSupported),
            -2 => Some(Self::InvalidParameters),
            -3 => Some(Self::Denied),
            -4 => Some(Self::AlreadyOn),
            -5 => Some(Self::OnPending),
            -6 => Some(Self::InternalFailure),
            -7 => Some(Self::NotPresent),
            -8 => Some(Self::Disabled),
            -9 => Some(Self::InvalidAddress),
            _ => Some(Self::InternalFailure),
        }
    }
}

/// Return values from an SMC call (x0–x3).
#[derive(Debug, Clone, Copy)]
pub struct SmcResult {
    /// x0: Return value / error code.
    pub x0: u64,
    /// x1: Second return value.
    pub x1: u64,
    /// x2: Third return value.
    pub x2: u64,
    /// x3: Fourth return value.
    pub x3: u64,
}

/// Issues an SMC call with up to 8 arguments.
///
/// # Safety
///
/// The caller must ensure:
/// - The function ID is valid for the current security context
/// - Arguments satisfy the called function's requirements
/// - This is called from the Non-Secure EL1 (or EL2) world
#[cfg(target_arch = "aarch64")]
pub unsafe fn smc_call(fn_id: u32, x1: u64, x2: u64, x3: u64, x4: u64) -> SmcResult {
    let r0: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    // SAFETY: The smc instruction transitions to EL3. The caller guarantees
    // valid arguments and that this is executed in Non-Secure EL1/EL2.
    // Register x0 carries the function ID; x1-x7 carry arguments per SMCCC.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") fn_id as u64 => r0,
            inout("x1") x1 => r1,
            inout("x2") x2 => r2,
            inout("x3") x3 => r3,
            in("x4")    x4,
            // Clobber x5-x17 as per SMCCC (caller-saved across SMC)
            out("x5")  _,
            out("x6")  _,
            out("x7")  _,
            out("x8")  _,
            out("x9")  _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            out("x16") _,
            out("x17") _,
            options(nostack)
        );
    }
    SmcResult {
        x0: r0,
        x1: r1,
        x2: r2,
        x3: r3,
    }
}

/// PSCI interface for power management via SMC.
pub struct PsciInterface;

impl PsciInterface {
    /// Queries the PSCI version from firmware.
    pub fn version() -> Result<(u8, u8)> {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: PSCI VERSION is a read-only query that does not alter state.
            let result = unsafe { smc_call(psci::VERSION, 0, 0, 0, 0) };
            let major = ((result.x0 >> 16) & 0xFF) as u8;
            let minor = (result.x0 & 0xFFFF) as u8;
            return Ok((major, minor));
        }
        #[allow(unreachable_code)]
        Err(Error::NotImplemented)
    }

    /// Powers on a CPU core.
    ///
    /// # Arguments
    ///
    /// * `mpidr` - CPU affinity register value (target CPU MPIDR)
    /// * `entry_point` - Physical address to start execution (must be Non-Secure memory)
    /// * `context_id` - Opaque value passed to the entry point
    pub fn cpu_on(_mpidr: u64, _entry_point: u64, _context_id: u64) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: CPU_ON is called to boot a secondary core. entry_point must
            // be a valid Non-Secure physical address. mpidr must be a valid offline CPU.
            let result = unsafe { smc_call(psci::CPU_ON64, _mpidr, _entry_point, _context_id, 0) };
            if let Some(err) = PsciError::from_ret(result.x0 as i64) {
                return match err {
                    PsciError::AlreadyOn => Err(Error::AlreadyExists),
                    PsciError::InvalidParameters | PsciError::InvalidAddress => {
                        Err(Error::InvalidArgument)
                    }
                    _ => Err(Error::IoError),
                };
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(Error::NotImplemented)
    }

    /// Shuts down the current CPU core.
    ///
    /// This function does not return if successful.
    pub fn cpu_off() -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: CPU_OFF puts the current CPU into an offline state.
            // The CPU will not execute further instructions after this call.
            let result = unsafe { smc_call(psci::CPU_OFF, 0, 0, 0, 0) };
            if let Some(_) = PsciError::from_ret(result.x0 as i64) {
                return Err(Error::IoError);
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(Error::NotImplemented)
    }

    /// Requests system power off.
    pub fn system_off() {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: SYSTEM_OFF requests the firmware to power down the system.
            // This is a best-effort call; some systems may reset instead.
            unsafe { smc_call(psci::SYSTEM_OFF, 0, 0, 0, 0) };
        }
    }

    /// Requests system reset.
    pub fn system_reset() {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: SYSTEM_RESET triggers a firmware-controlled system reset.
            unsafe { smc_call(psci::SYSTEM_RESET, 0, 0, 0, 0) };
        }
    }
}
