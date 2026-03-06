// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `reboot(2)` syscall handler — system reboot, halt, and power management.
//!
//! This module implements the kernel-side dispatcher for the `reboot(2)` syscall,
//! including:
//! - Magic-number validation (two-factor guard against accidental reboot).
//! - `CAP_SYS_BOOT` capability check before any terminal action.
//! - Command dispatch to halt, power-off, restart, kexec, and SW-suspend paths.
//! - Reboot notifier chain invocation before shutdown execution.
//! - Ctrl-Alt-Del (`CAD`) enable/disable without privilege requirement.
//!
//! # Magic numbers
//!
//! Linux defines REBOOT_MAGIC1 (`0xfee1dead`) and a set of acceptable MAGIC2
//! values.  Both must match or the syscall returns `EINVAL` immediately.
//!
//! # Privilege model
//!
//! Toggling CAD state (`CadOn`/`CadOff`) does not require privilege.
//! All other commands (`Halt`, `PowerOff`, `Restart`, `Restart2`, `Kexec`,
//! `SwSuspend`) require the caller to hold `CAP_SYS_BOOT`.
//!
//! # POSIX reference
//!
//! `reboot(2)` is a Linux extension; POSIX does not standardise it.
//! POSIX.1-2024 provides no equivalent function.
//!
//! # Linux reference
//!
//! `kernel/reboot.c` — `SYSCALL_DEFINE4(reboot, ...)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Magic constants
// ---------------------------------------------------------------------------

/// First magic number; must always be present.
pub const REBOOT_MAGIC1: u32 = 0xfee1_dead;
/// Standard second magic number.
pub const REBOOT_MAGIC2: u32 = 0x2812_1969;
/// Alternative second magic (all accepted equally).
pub const REBOOT_MAGIC2A: u32 = 0x0516_04;
/// Alternative second magic.
pub const REBOOT_MAGIC2B: u32 = 0x1121_5367;
/// Alternative second magic.
pub const REBOOT_MAGIC2C: u32 = 0x1215_0229;

// ---------------------------------------------------------------------------
// Command codes
// ---------------------------------------------------------------------------

/// Validated reboot command.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysRebootCmd {
    /// Enable automatic restart on Ctrl-Alt-Del.
    CadOn = 0x89AB_CDEF,
    /// Disable automatic restart on Ctrl-Alt-Del.
    CadOff = 0x0000_0000,
    /// Halt the CPU (power stays on).
    Halt = 0xCDEF_0123,
    /// Power off the system.
    PowerOff = 0x4321_FEDC,
    /// Restart the system.
    Restart = 0x0123_4567,
    /// Restart with argument string (e.g., kexec target).
    Restart2 = 0xA1B2_C3D4,
    /// Boot a kernel loaded via kexec.
    Kexec = 0x4558_4543,
    /// Suspend to RAM.
    SwSuspend = 0xD000_FCE2,
}

impl SysRebootCmd {
    /// Parse a raw `u32` command value.
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_raw(val: u32) -> Option<Self> {
        match val {
            0x89AB_CDEF => Some(Self::CadOn),
            0x0000_0000 => Some(Self::CadOff),
            0xCDEF_0123 => Some(Self::Halt),
            0x4321_FEDC => Some(Self::PowerOff),
            0x0123_4567 => Some(Self::Restart),
            0xA1B2_C3D4 => Some(Self::Restart2),
            0x4558_4543 => Some(Self::Kexec),
            0xD000_FCE2 => Some(Self::SwSuspend),
            _ => None,
        }
    }

    /// Return `true` for commands that permanently alter system state.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Halt | Self::PowerOff | Self::Restart | Self::Restart2 | Self::Kexec
        )
    }
}

// ---------------------------------------------------------------------------
// Notifier chain
// ---------------------------------------------------------------------------

/// Maximum number of notifier callbacks in the chain.
const MAX_NOTIFIERS: usize = 16;

/// Callback invoked before a terminal reboot command executes.
pub type RebootNotifierFn = fn(cmd: SysRebootCmd) -> Result<()>;

struct NotifierSlot {
    func: RebootNotifierFn,
    priority: i32,
    active: bool,
}

impl NotifierSlot {
    const fn empty() -> Self {
        Self {
            func: |_| Ok(()),
            priority: 0,
            active: false,
        }
    }
}

/// Chain of callbacks invoked in descending priority order before shutdown.
pub struct RebootNotifierChain {
    slots: [NotifierSlot; MAX_NOTIFIERS],
    len: usize,
}

impl RebootNotifierChain {
    /// Create an empty chain.
    pub const fn new() -> Self {
        Self {
            slots: [const { NotifierSlot::empty() }; MAX_NOTIFIERS],
            len: 0,
        }
    }

    /// Register a notifier callback at the given priority.
    ///
    /// Higher priority callbacks are called first.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — chain is full.
    pub fn register(&mut self, func: RebootNotifierFn, priority: i32) -> Result<()> {
        for slot in self.slots.iter_mut() {
            if !slot.active {
                slot.func = func;
                slot.priority = priority;
                slot.active = true;
                self.len += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Invoke all registered callbacks in descending priority order.
    ///
    /// Stops on the first error.
    pub fn notify(&self, cmd: SysRebootCmd) -> Result<()> {
        // Collect active indices sorted by descending priority.
        let mut order = [0usize; MAX_NOTIFIERS];
        let mut order_len = 0usize;

        for (i, slot) in self.slots.iter().enumerate() {
            if !slot.active {
                continue;
            }
            // Insertion-sort into descending priority order.
            let mut pos = order_len;
            while pos > 0 && self.slots[order[pos - 1]].priority < slot.priority {
                pos -= 1;
            }
            let mut j = order_len;
            while j > pos {
                order[j] = order[j - 1];
                j -= 1;
            }
            order[pos] = i;
            order_len += 1;
        }

        for k in 0..order_len {
            (self.slots[order[k]].func)(cmd)?;
        }
        Ok(())
    }

    /// Return the number of registered callbacks.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if no callbacks are registered.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RebootNotifierChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CadState
// ---------------------------------------------------------------------------

/// Ctrl-Alt-Del enable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CadState {
    /// When `true`, Ctrl-Alt-Del triggers an immediate system restart.
    pub enabled: bool,
}

impl CadState {
    /// Create with CAD initially disabled.
    pub const fn new() -> Self {
        Self { enabled: false }
    }
}

// ---------------------------------------------------------------------------
// SysRebootState
// ---------------------------------------------------------------------------

/// Tracks global reboot state between calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SysRebootPhase {
    /// System is running normally.
    #[default]
    Running,
    /// Notifiers are being called.
    Notifying,
    /// Filesystems are being synced and unmounted.
    ShuttingDown,
    /// Architecture-specific terminal action executing.
    Executing,
}

/// Global state for the reboot subsystem.
pub struct SysRebootState {
    /// Current phase of any in-progress shutdown.
    pub phase: SysRebootPhase,
    /// The command that initiated the current shutdown, if any.
    pub pending_cmd: Option<SysRebootCmd>,
}

impl SysRebootState {
    /// Create idle state.
    pub const fn new() -> Self {
        Self {
            phase: SysRebootPhase::Running,
            pending_cmd: None,
        }
    }
}

impl Default for SysRebootState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the two reboot magic numbers.
fn validate_magic(magic1: u32, magic2: u32) -> Result<()> {
    if magic1 != REBOOT_MAGIC1 {
        return Err(Error::InvalidArgument);
    }
    match magic2 {
        REBOOT_MAGIC2 | REBOOT_MAGIC2A | REBOOT_MAGIC2B | REBOOT_MAGIC2C => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Architecture stubs
// ---------------------------------------------------------------------------

/// Signal the architecture layer to halt the CPU.
///
/// In a production kernel this diverges and does not return.
fn arch_halt() -> Result<()> {
    Err(Error::NotImplemented)
}

/// Signal the architecture layer to power off the system.
///
/// In a production kernel this diverges and does not return.
fn arch_power_off() -> Result<()> {
    Err(Error::NotImplemented)
}

/// Signal the architecture layer to restart the system.
///
/// `arg` is an optional kernel-command-line fragment for kexec / Restart2.
fn arch_restart(_arg: &[u8]) -> Result<()> {
    Err(Error::NotImplemented)
}

/// Flush dirty page cache to disk.
fn emergency_sync() {}

/// Unmount all filesystems.
fn emergency_unmount() {}

// ---------------------------------------------------------------------------
// do_sys_reboot — primary dispatcher
// ---------------------------------------------------------------------------

/// Execute the `reboot(2)` syscall.
///
/// # Arguments
///
/// * `magic1`         — Must be [`REBOOT_MAGIC1`].
/// * `magic2`         — Must be one of the accepted second magic values.
/// * `cmd_raw`        — Raw command code; converted to [`SysRebootCmd`].
/// * `arg`            — Optional argument bytes (for `Restart2`/`Kexec`).
/// * `is_privileged`  — `true` when caller holds `CAP_SYS_BOOT`.
/// * `notifier`       — Mutable notifier chain to invoke before shutdown.
/// * `state`          — Mutable global reboot state tracker.
/// * `cad`            — Mutable Ctrl-Alt-Del state.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Bad magic numbers or unknown command.
/// * [`Error::PermissionDenied`] — Terminal command without `CAP_SYS_BOOT`.
/// * [`Error::NotImplemented`]   — Architecture stubs not yet wired.
pub fn do_sys_reboot(
    magic1: u32,
    magic2: u32,
    cmd_raw: u32,
    arg: &[u8],
    is_privileged: bool,
    notifier: &RebootNotifierChain,
    state: &mut SysRebootState,
    cad: &mut CadState,
) -> Result<()> {
    validate_magic(magic1, magic2)?;

    let cmd = SysRebootCmd::from_raw(cmd_raw).ok_or(Error::InvalidArgument)?;

    // CAD toggle: no privilege required.
    match cmd {
        SysRebootCmd::CadOn => {
            cad.enabled = true;
            return Ok(());
        }
        SysRebootCmd::CadOff => {
            cad.enabled = false;
            return Ok(());
        }
        _ => {}
    }

    // All other commands require CAP_SYS_BOOT.
    if !is_privileged {
        return Err(Error::PermissionDenied);
    }

    // Transition to notifying phase.
    state.phase = SysRebootPhase::Notifying;
    state.pending_cmd = Some(cmd);

    // Invoke notifier chain.
    notifier.notify(cmd)?;

    // Sync and unmount.
    state.phase = SysRebootPhase::ShuttingDown;
    emergency_sync();
    emergency_unmount();

    // Execute arch-specific action.
    state.phase = SysRebootPhase::Executing;
    match cmd {
        SysRebootCmd::Halt => arch_halt(),
        SysRebootCmd::PowerOff => arch_power_off(),
        SysRebootCmd::Restart => arch_restart(&[]),
        SysRebootCmd::Restart2 | SysRebootCmd::Kexec => arch_restart(arg),
        SysRebootCmd::SwSuspend => arch_power_off(), // stub: treat as power-off
        // CAD cases handled above.
        SysRebootCmd::CadOn | SysRebootCmd::CadOff => Ok(()),
    }
}

/// Handle a Ctrl-Alt-Del keystroke.
///
/// When CAD is enabled this triggers an immediate restart sequence.
/// When disabled, the implementation would deliver `SIGINT` to PID 1.
pub fn handle_cad_keystroke(
    cad: &CadState,
    notifier: &RebootNotifierChain,
    state: &mut SysRebootState,
) {
    if cad.enabled {
        // Best-effort; ignore error in interrupt context.
        let _ = do_sys_reboot(
            REBOOT_MAGIC1,
            REBOOT_MAGIC2,
            SysRebootCmd::Restart as u32,
            &[],
            true,
            notifier,
            state,
            &mut CadState { enabled: true },
        );
    }
    // Stub: when CAD is disabled, deliver SIGINT to init (PID 1).
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn idle() -> (RebootNotifierChain, SysRebootState, CadState) {
        (
            RebootNotifierChain::new(),
            SysRebootState::new(),
            CadState::new(),
        )
    }

    #[test]
    fn bad_magic1_rejected() {
        let (n, mut s, mut cad) = idle();
        assert_eq!(
            do_sys_reboot(
                0xdeadbeef,
                REBOOT_MAGIC2,
                SysRebootCmd::CadOn as u32,
                &[],
                true,
                &n,
                &mut s,
                &mut cad
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_magic2_rejected() {
        let (n, mut s, mut cad) = idle();
        assert_eq!(
            do_sys_reboot(
                REBOOT_MAGIC1,
                0x1234,
                SysRebootCmd::CadOn as u32,
                &[],
                true,
                &n,
                &mut s,
                &mut cad
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cad_on_no_privilege_needed() {
        let (n, mut s, mut cad) = idle();
        assert!(
            do_sys_reboot(
                REBOOT_MAGIC1,
                REBOOT_MAGIC2,
                SysRebootCmd::CadOn as u32,
                &[],
                false,
                &n,
                &mut s,
                &mut cad
            )
            .is_ok()
        );
        assert!(cad.enabled);
    }

    #[test]
    fn cad_off_no_privilege_needed() {
        let (n, mut s, mut cad) = idle();
        cad.enabled = true;
        assert!(
            do_sys_reboot(
                REBOOT_MAGIC1,
                REBOOT_MAGIC2,
                SysRebootCmd::CadOff as u32,
                &[],
                false,
                &n,
                &mut s,
                &mut cad
            )
            .is_ok()
        );
        assert!(!cad.enabled);
    }

    #[test]
    fn halt_requires_privilege() {
        let (n, mut s, mut cad) = idle();
        assert_eq!(
            do_sys_reboot(
                REBOOT_MAGIC1,
                REBOOT_MAGIC2,
                SysRebootCmd::Halt as u32,
                &[],
                false,
                &n,
                &mut s,
                &mut cad
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn unknown_command_rejected() {
        let (n, mut s, mut cad) = idle();
        assert_eq!(
            do_sys_reboot(
                REBOOT_MAGIC1,
                REBOOT_MAGIC2,
                0xBADBAD,
                &[],
                true,
                &n,
                &mut s,
                &mut cad
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn notifier_chain_called() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static CALLED: AtomicU32 = AtomicU32::new(0);

        fn callback(_cmd: SysRebootCmd) -> Result<()> {
            CALLED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        let mut n = RebootNotifierChain::new();
        n.register(callback, 0).unwrap();
        let mut s = SysRebootState::new();
        let mut cad = CadState::new();

        // Halt returns NotImplemented (stub) but notifier fires first.
        let _ = do_sys_reboot(
            REBOOT_MAGIC1,
            REBOOT_MAGIC2,
            SysRebootCmd::Halt as u32,
            &[],
            true,
            &n,
            &mut s,
            &mut cad,
        );
        assert_eq!(CALLED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn magic2_alternatives_accepted() {
        for magic2 in [REBOOT_MAGIC2A, REBOOT_MAGIC2B, REBOOT_MAGIC2C] {
            let (n, mut s, mut cad) = idle();
            assert!(
                do_sys_reboot(
                    REBOOT_MAGIC1,
                    magic2,
                    SysRebootCmd::CadOn as u32,
                    &[],
                    false,
                    &n,
                    &mut s,
                    &mut cad
                )
                .is_ok(),
                "magic2 0x{:X} was rejected",
                magic2
            );
        }
    }

    #[test]
    fn cmd_is_terminal() {
        assert!(SysRebootCmd::Halt.is_terminal());
        assert!(SysRebootCmd::PowerOff.is_terminal());
        assert!(SysRebootCmd::Restart.is_terminal());
        assert!(!SysRebootCmd::CadOn.is_terminal());
        assert!(!SysRebootCmd::CadOff.is_terminal());
    }
}
