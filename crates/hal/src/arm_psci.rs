// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Power State Coordination Interface (PSCI) support.
//!
//! PSCI provides a standard interface for power management operations
//! on ARM platforms, including:
//!
//! - CPU on/off/suspend
//! - System shutdown and reset
//! - PSCI version discovery
//!
//! PSCI calls are issued via the Secure Monitor Call (`smc`) or
//! Hypervisor Call (`hvc`) instruction depending on the platform
//! conduit. On AArch64, the SMC Calling Convention (SMCCC) 1.2+ is used.
//!
//! Reference: ARM DEN0022D — Power State Coordination Interface (PSCI).

use oncrix_lib::{Error, Result};

// ── PSCI Function Identifiers ──────────────────────────────────────────────

/// PSCI_VERSION — query the implemented PSCI version.
pub const PSCI_VERSION: u32 = 0x8400_0000;
/// CPU_SUSPEND — suspend the calling CPU to a power state.
pub const PSCI_CPU_SUSPEND: u32 = 0xC400_0001;
/// CPU_OFF — power down the calling CPU.
pub const PSCI_CPU_OFF: u32 = 0x8400_0002;
/// CPU_ON — power on a secondary CPU.
pub const PSCI_CPU_ON: u32 = 0xC400_0003;
/// AFFINITY_INFO — query affinity level power state.
pub const PSCI_AFFINITY_INFO: u32 = 0xC400_0004;
/// SYSTEM_OFF — shut down the system.
pub const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
/// SYSTEM_RESET — reset the system.
pub const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;
/// SYSTEM_RESET2 — extended reset with parameter.
pub const PSCI_SYSTEM_RESET2: u32 = 0xC400_0012;
/// FEATURES — query support for a PSCI function.
pub const PSCI_FEATURES: u32 = 0x8400_000A;

// ── PSCI Return Codes ──────────────────────────────────────────────────────

/// PSCI success.
pub const PSCI_SUCCESS: i32 = 0;
/// PSCI not supported.
pub const PSCI_NOT_SUPPORTED: i32 = -1;
/// PSCI invalid parameters.
pub const PSCI_INVALID_PARAMS: i32 = -2;
/// PSCI denied.
pub const PSCI_DENIED: i32 = -3;
/// PSCI already on.
pub const PSCI_ALREADY_ON: i32 = -4;
/// PSCI on pending.
pub const PSCI_ON_PENDING: i32 = -5;
/// PSCI internal failure.
pub const PSCI_INTERNAL_FAILURE: i32 = -6;
/// PSCI not present.
pub const PSCI_NOT_PRESENT: i32 = -7;
/// PSCI disabled.
pub const PSCI_DISABLED: i32 = -8;

// ── Power State Encoding ───────────────────────────────────────────────────

/// Power State parameter for CPU_SUSPEND.
#[derive(Clone, Copy)]
pub struct PowerState(pub u32);

impl PowerState {
    /// Construct a power state value.
    ///
    /// `state_id` — platform-defined power state identifier.
    /// `power_level` — highest power level affected (0=core, 1=cluster, 2=system).
    /// `state_type` — 0 for standby, 1 for power-down.
    pub fn new(state_id: u16, power_level: u8, state_type: u8) -> Self {
        let val = ((state_type as u32 & 1) << 30)
            | ((power_level as u32 & 3) << 28)
            | (state_id as u32 & 0xFFFF);
        Self(val)
    }
}

// ── PSCI Conduit ───────────────────────────────────────────────────────────

/// PSCI call conduit type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PsciConduit {
    /// Use `smc` instruction (Secure Monitor Call).
    Smc,
    /// Use `hvc` instruction (Hypervisor Call).
    Hvc,
}

// ── Low-level PSCI invocation ──────────────────────────────────────────────

/// Invoke a PSCI function with up to 3 arguments, return the result.
///
/// # Safety
/// The function ID and arguments must be valid PSCI calls. This performs
/// a privilege-level transition and may alter CPU power state.
#[cfg(target_arch = "aarch64")]
unsafe fn psci_call_0_3(conduit: PsciConduit, func: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    match conduit {
        PsciConduit::Smc => {
            // SAFETY: Issuing an SMC with valid PSCI function ID.
            unsafe {
                core::arch::asm!(
                    "smc #0",
                    inout("x0") func => ret,
                    in("x1") arg0,
                    in("x2") arg1,
                    in("x3") arg2,
                    options(nostack),
                )
            }
        }
        PsciConduit::Hvc => {
            // SAFETY: Issuing an HVC with valid PSCI function ID.
            unsafe {
                core::arch::asm!(
                    "hvc #0",
                    inout("x0") func => ret,
                    in("x1") arg0,
                    in("x2") arg1,
                    in("x3") arg2,
                    options(nostack),
                )
            }
        }
    }
    ret
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn psci_call_0_3(
    _conduit: PsciConduit,
    _func: u64,
    _arg0: u64,
    _arg1: u64,
    _arg2: u64,
) -> i64 {
    PSCI_NOT_SUPPORTED as i64
}

fn psci_to_result(ret: i32) -> Result<()> {
    match ret {
        PSCI_SUCCESS => Ok(()),
        PSCI_NOT_SUPPORTED => Err(Error::NotImplemented),
        PSCI_INVALID_PARAMS => Err(Error::InvalidArgument),
        PSCI_DENIED => Err(Error::PermissionDenied),
        PSCI_ALREADY_ON => Err(Error::AlreadyExists),
        _ => Err(Error::IoError),
    }
}

// ── PSCI Interface ─────────────────────────────────────────────────────────

/// ARM PSCI power management interface.
pub struct Psci {
    conduit: PsciConduit,
}

impl Default for Psci {
    fn default() -> Self {
        Self {
            conduit: PsciConduit::Smc,
        }
    }
}

impl Psci {
    /// Create a new PSCI handle using the specified conduit.
    pub fn new(conduit: PsciConduit) -> Self {
        Self { conduit }
    }

    /// Query the PSCI version (major.minor).
    pub fn version(&self) -> (u16, u16) {
        // SAFETY: PSCI_VERSION is a read-only query with no side effects.
        let ret = unsafe { psci_call_0_3(self.conduit, PSCI_VERSION as u64, 0, 0, 0) };
        let ver = ret as u32;
        let major = (ver >> 16) as u16;
        let minor = (ver & 0xFFFF) as u16;
        (major, minor)
    }

    /// Power on a secondary CPU.
    ///
    /// `mpidr` — the MPIDR_EL1 value identifying the target CPU.
    /// `entry` — physical address of the secondary CPU entry point.
    /// `context` — context ID passed to the entry point.
    pub fn cpu_on(&self, mpidr: u64, entry: u64, context: u64) -> Result<()> {
        // SAFETY: PSCI CPU_ON transitions a powered-off CPU to on; only
        // affects the CPU identified by mpidr, not the calling CPU.
        let ret = unsafe { psci_call_0_3(self.conduit, PSCI_CPU_ON as u64, mpidr, entry, context) };
        psci_to_result(ret as i32)
    }

    /// Power off the calling CPU (does not return on success).
    pub fn cpu_off(&self) -> Result<()> {
        // SAFETY: PSCI CPU_OFF powers down the current CPU; on success this
        // call never returns. The scheduler must have migrated all tasks first.
        let ret = unsafe { psci_call_0_3(self.conduit, PSCI_CPU_OFF as u64, 0, 0, 0) };
        psci_to_result(ret as i32)
    }

    /// Suspend the calling CPU to a power state (may return on wakeup).
    pub fn cpu_suspend(&self, state: PowerState, entry: u64, context: u64) -> Result<()> {
        // SAFETY: PSCI CPU_SUSPEND puts the CPU in the requested low-power
        // state; it must resume at the provided entry address.
        let ret = unsafe {
            psci_call_0_3(
                self.conduit,
                PSCI_CPU_SUSPEND as u64,
                state.0 as u64,
                entry,
                context,
            )
        };
        psci_to_result(ret as i32)
    }

    /// Query the power state of an affinity level instance.
    ///
    /// Returns 0 (ON), 1 (OFF), or 2 (ON_PENDING).
    pub fn affinity_info(&self, mpidr: u64, lowest_level: u64) -> i32 {
        // SAFETY: PSCI AFFINITY_INFO is a non-destructive query.
        let ret = unsafe {
            psci_call_0_3(
                self.conduit,
                PSCI_AFFINITY_INFO as u64,
                mpidr,
                lowest_level,
                0,
            )
        };
        ret as i32
    }

    /// Shut down the entire system.
    pub fn system_off(&self) -> ! {
        // SAFETY: PSCI SYSTEM_OFF powers down the system; this must only be
        // called when the OS has safely quiesced all I/O and unmounted disks.
        unsafe {
            psci_call_0_3(self.conduit, PSCI_SYSTEM_OFF as u64, 0, 0, 0);
        }
        loop {
            #[cfg(target_arch = "aarch64")]
            // SAFETY: wfi is safe to execute on AArch64.
            unsafe {
                core::arch::asm!("wfi", options(nostack, nomem));
            }
        }
    }

    /// Reset the entire system.
    pub fn system_reset(&self) -> ! {
        // SAFETY: PSCI SYSTEM_RESET resets the system; called after
        // all I/O has been quiesced.
        unsafe {
            psci_call_0_3(self.conduit, PSCI_SYSTEM_RESET as u64, 0, 0, 0);
        }
        loop {
            #[cfg(target_arch = "aarch64")]
            // SAFETY: wfi safe to execute on AArch64.
            unsafe {
                core::arch::asm!("wfi", options(nostack, nomem));
            }
        }
    }

    /// Check if a PSCI function is supported.
    pub fn features(&self, func_id: u32) -> bool {
        // SAFETY: PSCI FEATURES is a read-only capability query.
        let ret =
            unsafe { psci_call_0_3(self.conduit, PSCI_FEATURES as u64, func_id as u64, 0, 0) };
        ret as i32 >= 0
    }
}
