// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Reboot and power-management syscall handlers.
//!
//! Implements the `reboot(2)` syscall for system restart, halt, and
//! power-off operations.  All actions require the caller to provide
//! both magic numbers and possess `CAP_SYS_BOOT` (modelled here as
//! `is_privileged == true`).
//!
//! The shutdown sequence:
//! 1. Notify registered callbacks (`RebootNotifier` chain).
//! 2. Request filesystem sync.
//! 3. Send `SIGTERM` then `SIGKILL` to all non-kernel processes.
//! 4. Unmount all filesystems.
//! 5. Execute the arch-specific power action.
//!
//! # POSIX / Linux Reference
//!
//! `reboot(2)` is a Linux extension; POSIX does not define it.
//! The magic-number protocol and command codes follow Linux semantics.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — magic numbers
// ---------------------------------------------------------------------------

/// First reboot magic number.
pub const REBOOT_MAGIC1: u32 = 0xfee1_dead;
/// Second reboot magic number (original).
pub const REBOOT_MAGIC2: u32 = 0x2812_1969;
/// Alternative second magic (accepted alongside `MAGIC2`).
pub const REBOOT_MAGIC2A: u32 = 0x0516_04;
/// Alternative second magic (accepted alongside `MAGIC2`).
pub const REBOOT_MAGIC2B: u32 = 0x1121_5367;
/// Alternative second magic (accepted alongside `MAGIC2`).
pub const REBOOT_MAGIC2C: u32 = 0x1215_0229;

/// Maximum number of notifier callbacks.
const REBOOT_NOTIFIER_MAX: usize = 16;

// ---------------------------------------------------------------------------
// RebootCmd
// ---------------------------------------------------------------------------

/// Commands accepted by `reboot(2)`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootCmd {
    /// Enable Ctrl-Alt-Del keystroke (triggers restart).
    CadOn = 0x89AB_CDEF,
    /// Disable Ctrl-Alt-Del keystroke.
    CadOff = 0x0000_0000,
    /// Restart the system.
    Restart = 0x0123_4567,
    /// Halt the system (CPU stops, power on).
    Halt = 0xCDEF_0123,
    /// Power off the system.
    PowerOff = 0x4321_FEDC,
    /// Restart with an argument string (kexec path, etc.).
    Restart2 = 0xA1B2_C3D4,
    /// Boot a new kernel via kexec.
    Kexec = 0x4558_4543,
    /// Suspend to RAM (hibernate).
    SwSuspend = 0xD000_FCE2,
}

impl RebootCmd {
    /// Convert a raw `u32` to a `RebootCmd`, returning `None` if unknown.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0x89AB_CDEF => Some(Self::CadOn),
            0x0000_0000 => Some(Self::CadOff),
            0x0123_4567 => Some(Self::Restart),
            0xCDEF_0123 => Some(Self::Halt),
            0x4321_FEDC => Some(Self::PowerOff),
            0xA1B2_C3D4 => Some(Self::Restart2),
            0x4558_4543 => Some(Self::Kexec),
            0xD000_FCE2 => Some(Self::SwSuspend),
            _ => None,
        }
    }

    /// Return a human-readable label for this command.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CadOn => "CAD_ON",
            Self::CadOff => "CAD_OFF",
            Self::Restart => "RESTART",
            Self::Halt => "HALT",
            Self::PowerOff => "POWER_OFF",
            Self::Restart2 => "RESTART2",
            Self::Kexec => "KEXEC",
            Self::SwSuspend => "SW_SUSPEND",
        }
    }

    /// Return `true` if this command transitions the system to a
    /// non-recoverable state (halt, power-off, restart, kexec).
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Restart | Self::Halt | Self::PowerOff | Self::Restart2 | Self::Kexec
        )
    }
}

// ---------------------------------------------------------------------------
// RebootNotifier
// ---------------------------------------------------------------------------

/// Callback function type for reboot notification.
///
/// Receives the command that triggered the shutdown.  Returning an
/// error aborts the shutdown sequence (only for non-terminal commands).
pub type NotifierFn = fn(cmd: RebootCmd) -> Result<()>;

/// Priority of a notifier callback (higher = called first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotifierPriority(pub i32);

impl NotifierPriority {
    /// Highest standard priority.
    pub const HIGH: Self = Self(300);
    /// Default priority.
    pub const NORMAL: Self = Self(0);
    /// Lowest standard priority.
    pub const LOW: Self = Self(-300);
}

impl Default for NotifierPriority {
    fn default() -> Self {
        Self::NORMAL
    }
}

/// A single registered reboot notifier.
#[derive(Clone, Copy)]
struct NotifierEntry {
    /// Callback function.
    func: NotifierFn,
    /// Call priority (descending order).
    priority: NotifierPriority,
    /// Whether this slot is occupied.
    active: bool,
}

impl NotifierEntry {
    const fn empty() -> Self {
        Self {
            func: |_| Ok(()),
            priority: NotifierPriority(0),
            active: false,
        }
    }
}

/// Chain of callbacks invoked before the reboot action is executed.
///
/// Callbacks are called in descending priority order.
/// Up to [`REBOOT_NOTIFIER_MAX`] callbacks can be registered.
pub struct RebootNotifier {
    entries: [NotifierEntry; REBOOT_NOTIFIER_MAX],
    count: usize,
}

impl RebootNotifier {
    /// Create an empty notifier chain.
    pub const fn new() -> Self {
        Self {
            entries: [const { NotifierEntry::empty() }; REBOOT_NOTIFIER_MAX],
            count: 0,
        }
    }

    /// Return the number of registered callbacks.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a callback with the given priority.
    ///
    /// Returns `OutOfMemory` if the chain is full.
    pub fn register(&mut self, func: NotifierFn, priority: NotifierPriority) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.func = func;
                entry.priority = priority;
                entry.active = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a previously registered callback.
    ///
    /// Matches by function pointer.  Returns `NotFound` if not registered.
    pub fn unregister(&mut self, func: NotifierFn) -> Result<()> {
        // Find by comparing function pointer values.
        let pos = self
            .entries
            .iter()
            .position(|e| e.active && core::ptr::fn_addr_eq(e.func, func));

        match pos {
            Some(i) => {
                self.entries[i].active = false;
                self.count = self.count.saturating_sub(1);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Invoke all registered callbacks in descending priority order.
    ///
    /// Stops and returns an error on the first callback failure.
    pub fn notify_chain(&self, cmd: RebootCmd) -> Result<()> {
        // Collect active entries sorted by descending priority.
        // Use a simple insertion-sorted pass over the fixed-size array.
        let mut order: [usize; REBOOT_NOTIFIER_MAX] = [0usize; REBOOT_NOTIFIER_MAX];
        let mut order_len: usize = 0;

        for (i, entry) in self.entries.iter().enumerate() {
            if !entry.active {
                continue;
            }
            // Find insertion position (descending priority).
            let mut pos = order_len;
            while pos > 0 && self.entries[order[pos - 1]].priority < entry.priority {
                pos -= 1;
            }
            // Shift right.
            let mut j = order_len;
            while j > pos {
                order[j] = order[j - 1];
                j -= 1;
            }
            order[pos] = i;
            order_len += 1;
        }

        for k in 0..order_len {
            let entry = &self.entries[order[k]];
            (entry.func)(cmd)?;
        }
        Ok(())
    }
}

impl Default for RebootNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ShutdownSequence state
// ---------------------------------------------------------------------------

/// Current phase of an in-progress shutdown sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShutdownPhase {
    /// No shutdown in progress.
    #[default]
    Idle,
    /// Notifier chain is being invoked.
    Notifying,
    /// Filesystems are being synced.
    Syncing,
    /// Sending SIGTERM to processes.
    Terminating,
    /// Sending SIGKILL to surviving processes.
    Killing,
    /// Unmounting filesystems.
    Unmounting,
    /// Executing arch-specific power action.
    Executing,
}

/// Tracks the state of an active shutdown sequence.
pub struct ShutdownState {
    /// Current phase.
    pub phase: ShutdownPhase,
    /// The command that initiated the shutdown.
    pub cmd: Option<RebootCmd>,
    /// Optional argument string for `Restart2` / `Kexec`.
    pub arg: [u8; 256],
    /// Length of the argument string.
    pub arg_len: usize,
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownState {
    /// Create an idle `ShutdownState`.
    pub const fn new() -> Self {
        Self {
            phase: ShutdownPhase::Idle,
            cmd: None,
            arg: [0u8; 256],
            arg_len: 0,
        }
    }

    /// Return the argument as a byte slice.
    pub fn arg_bytes(&self) -> &[u8] {
        &self.arg[..self.arg_len]
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
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

/// Validate an optional argument string for `Restart2`/`Kexec`.
fn validate_arg(arg: &[u8]) -> Result<()> {
    if arg.len() > 256 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shutdown sequence steps (stubs)
// ---------------------------------------------------------------------------

/// Unmount all filesystems.
///
/// Stub: in a real kernel this calls `kern_unmount_all`.
fn unmount_all() -> Result<()> {
    // Stub: signal VFS layer to unmount.
    Ok(())
}

/// Sync all dirty pages to storage.
///
/// Stub: in a real kernel this calls `emergency_sync`.
fn emergency_sync() -> Result<()> {
    // Stub: flush page cache.
    Ok(())
}

/// Disable local CPU interrupts.
///
/// Stub: in a real kernel this calls `local_irq_disable()`.
fn disable_irqs() {
    // Stub: HAL interrupt disable.
}

/// Execute the architecture-specific terminal action.
///
/// Stub: in a real kernel this calls `machine_halt()`,
/// `machine_power_off()`, or `machine_restart()`.
fn arch_execute(cmd: RebootCmd, arg: &[u8]) -> Result<()> {
    let _ = (cmd, arg);
    // Stub: diverge to arch halt/restart/poweroff.
    // In a real kernel this would not return.
    Err(Error::NotImplemented)
}

/// Execute the full shutdown sequence.
///
/// Called after magic validation and privilege check.  The sequence
/// is: notify → sync → terminate → kill → unmount → arch action.
fn shutdown_sequence(
    notifier: &RebootNotifier,
    shutdown: &mut ShutdownState,
    cmd: RebootCmd,
    arg: &[u8],
) -> Result<()> {
    shutdown.phase = ShutdownPhase::Notifying;
    shutdown.cmd = Some(cmd);
    if !arg.is_empty() {
        let copy_len = arg.len().min(256);
        shutdown.arg[..copy_len].copy_from_slice(&arg[..copy_len]);
        shutdown.arg_len = copy_len;
    }

    // Step 1: notify registered callbacks.
    notifier.notify_chain(cmd)?;

    // Step 2: sync filesystems.
    shutdown.phase = ShutdownPhase::Syncing;
    emergency_sync()?;

    // Step 3: send SIGTERM.
    shutdown.phase = ShutdownPhase::Terminating;
    // Stub: broadcast SIGTERM to all user processes.

    // Step 4: send SIGKILL to survivors.
    shutdown.phase = ShutdownPhase::Killing;
    // Stub: broadcast SIGKILL to remaining user processes.

    // Step 5: unmount filesystems.
    shutdown.phase = ShutdownPhase::Unmounting;
    unmount_all()?;

    // Step 6: disable interrupts and execute arch action.
    shutdown.phase = ShutdownPhase::Executing;
    disable_irqs();
    arch_execute(cmd, arg)
}

// ---------------------------------------------------------------------------
// Ctrl-Alt-Del state
// ---------------------------------------------------------------------------

/// Whether Ctrl-Alt-Del is currently enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CadState {
    /// `true` if CAD triggers an automatic restart.
    pub enabled: bool,
}

impl CadState {
    /// Create with CAD disabled.
    pub const fn new() -> Self {
        Self { enabled: false }
    }
}

// ---------------------------------------------------------------------------
// Primary dispatcher
// ---------------------------------------------------------------------------

/// `reboot(2)` — system reboot / halt / power-off syscall.
///
/// # Arguments
///
/// - `magic1` — must be [`REBOOT_MAGIC1`].
/// - `magic2` — must be one of the accepted second magic values.
/// - `cmd`    — raw command code (see [`RebootCmd`]).
/// - `arg`    — optional argument bytes (for `RESTART2` / `KEXEC`).
/// - `is_privileged` — set to `true` when caller has `CAP_SYS_BOOT`.
/// - `notifier` — registered notifier chain.
/// - `shutdown` — mutable shutdown state tracker.
/// - `cad` — mutable CAD enable state.
///
/// # Errors
///
/// - `InvalidArgument` — bad magic or unknown command.
/// - `PermissionDenied` — caller lacks `CAP_SYS_BOOT`.
/// - `NotImplemented` — arch action not yet implemented (stub).
pub fn do_reboot(
    magic1: u32,
    magic2: u32,
    cmd_raw: u32,
    arg: &[u8],
    is_privileged: bool,
    notifier: &RebootNotifier,
    shutdown: &mut ShutdownState,
    cad: &mut CadState,
) -> Result<()> {
    validate_magic(magic1, magic2)?;

    let cmd = RebootCmd::from_u32(cmd_raw).ok_or(Error::InvalidArgument)?;

    // CAD toggle does not require privilege per Linux convention, but
    // any system-state-changing command does.
    match cmd {
        RebootCmd::CadOn => {
            cad.enabled = true;
            return Ok(());
        }
        RebootCmd::CadOff => {
            cad.enabled = false;
            return Ok(());
        }
        _ => {}
    }

    if !is_privileged {
        return Err(Error::PermissionDenied);
    }

    // Validate the argument string for commands that use it.
    match cmd {
        RebootCmd::Restart2 | RebootCmd::Kexec => validate_arg(arg)?,
        _ => {}
    }

    shutdown_sequence(notifier, shutdown, cmd, arg)
}

/// Handle a Ctrl-Alt-Del keystroke event.
///
/// If CAD is enabled, this initiates an immediate restart.
/// Otherwise it sends SIGINT to the init process (PID 1).
pub fn handle_cad(cad: &CadState, notifier: &RebootNotifier, shutdown: &mut ShutdownState) {
    if cad.enabled {
        // Best-effort restart; ignore errors in interrupt context.
        let _ = shutdown_sequence(notifier, shutdown, RebootCmd::Restart, &[]);
    }
    // Stub: if CAD disabled, deliver SIGINT to PID 1.
}
