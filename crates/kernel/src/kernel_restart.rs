// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System reboot, shutdown, poweroff, and halt framework.
//!
//! Provides the kernel infrastructure for orderly system state transitions
//! such as rebooting, powering off, halting, and entering suspend (kexec).
//! Notifier chains allow subsystems to register callbacks that execute
//! before the final machine-level action.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                     RestartSubsystem                             │
//! │                                                                  │
//! │  RestartCommand — what to do (Reboot / Poweroff / Halt / Kexec) │
//! │  RestartPhase  — lifecycle stage of shutdown                      │
//! │                                                                  │
//! │  [RestartNotifier; MAX_NOTIFIERS] — ordered callback chain       │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  RestartNotifier                                           │  │
//! │  │    name, priority, NotifierAction (Continue / Stop / …)    │  │
//! │  │    phase mask — which phases trigger callback               │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  MachineOps — low-level arch callbacks (reset, poweroff, halt)  │
//! │  RestartLog [MAX_LOG_ENTRIES] — audit trail                      │
//! │  RestartStats — counters                                         │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Shutdown Sequence
//!
//! 1. `initiate()` sets the command and enters `Notifying` phase.
//! 2. Notifiers are called in priority order (highest first).
//! 3. After all notifiers complete, enter `DeviceShutdown` phase.
//! 4. Finally, call the appropriate `MachineOps` callback.
//!
//! # Reference
//!
//! Linux `kernel/reboot.c`, `include/linux/reboot.h`,
//! `Documentation/admin-guide/sysrq.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of restart notifiers.
const MAX_NOTIFIERS: usize = 64;

/// Maximum name length for a notifier.
const MAX_NAME_LEN: usize = 32;

/// Maximum log entries for shutdown audit trail.
const MAX_LOG_ENTRIES: usize = 128;

/// Maximum reboot argument string length.
const MAX_REBOOT_ARG_LEN: usize = 128;

/// Default notifier priority.
const DEFAULT_PRIORITY: i32 = 0;

/// Highest notifier priority (called first).
const PRIORITY_HIGHEST: i32 = 255;

/// Lowest notifier priority (called last).
const PRIORITY_LOWEST: i32 = -255;

/// Timeout for notifier execution in nanoseconds (5 seconds).
const NOTIFIER_TIMEOUT_NS: u64 = 5_000_000_000;

/// Magic values for reboot syscall (Linux-compatible).
const REBOOT_MAGIC1: u32 = 0xfee1_dead;

/// Second magic value for reboot syscall.
const REBOOT_MAGIC2: u32 = 0x2876_9823;

// ── RestartCommand ──────────────────────────────────────────────────────────

/// The high-level action the system should perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartCommand {
    /// Full system reboot (warm or cold).
    Reboot,
    /// Power off the machine.
    Poweroff,
    /// Halt CPUs but leave power on.
    Halt,
    /// Load and execute a new kernel image (kexec).
    Kexec,
    /// Enter suspend-to-RAM.
    Suspend,
    /// Enter suspend-to-disk (hibernate).
    Hibernate,
}

// ── RestartPhase ────────────────────────────────────────────────────────────

/// Lifecycle phase during the shutdown/reboot sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPhase {
    /// System is running normally.
    Running,
    /// Notifier chain is being traversed.
    Notifying,
    /// Devices are being shut down.
    DeviceShutdown,
    /// Filesystems are being synced/unmounted.
    FilesystemSync,
    /// CPUs are being taken offline.
    CpuTeardown,
    /// Final machine-level action is imminent.
    MachineAction,
    /// Restart complete (terminal state — should not be reached).
    Done,
}

// ── NotifierAction ──────────────────────────────────────────────────────────

/// Result of a notifier callback execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierAction {
    /// Continue calling the next notifier.
    Continue,
    /// Stop the notifier chain (abort shutdown).
    Stop,
    /// Continue but record a warning.
    ContinueWithWarning,
    /// Notifier timed out.
    Timeout,
}

impl Default for NotifierAction {
    fn default() -> Self {
        Self::Continue
    }
}

// ── NotifierState ───────────────────────────────────────────────────────────

/// Registration state of a restart notifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierState {
    /// Slot is empty.
    Empty,
    /// Notifier is registered and active.
    Active,
    /// Notifier is temporarily disabled.
    Disabled,
    /// Notifier is currently executing.
    Running,
    /// Notifier has been unregistered.
    Removed,
}

impl Default for NotifierState {
    fn default() -> Self {
        Self::Empty
    }
}

// ── RestartNotifier ─────────────────────────────────────────────────────────

/// A callback registered to be invoked during the shutdown sequence.
///
/// Notifiers are called in descending priority order. A notifier with
/// priority 255 runs before one with priority 0.
#[derive(Debug, Clone, Copy)]
pub struct RestartNotifier {
    /// Human-readable name of the notifier.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name string.
    name_len: usize,
    /// Execution priority (higher = earlier).
    priority: i32,
    /// Current state.
    state: NotifierState,
    /// Bitmask of `RestartCommand` variants this notifier cares about.
    command_mask: u8,
    /// Last action returned by this notifier.
    last_action: NotifierAction,
    /// Timestamp of last invocation (nanoseconds since boot).
    last_invoked_ns: u64,
    /// Number of times this notifier has been called.
    invoke_count: u64,
}

impl RestartNotifier {
    /// Create an empty notifier slot.
    const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            priority: DEFAULT_PRIORITY,
            state: NotifierState::Empty,
            command_mask: 0,
            last_action: NotifierAction::Continue,
            last_invoked_ns: 0,
            invoke_count: 0,
        }
    }

    /// Check whether this slot is available.
    fn is_empty(&self) -> bool {
        matches!(self.state, NotifierState::Empty | NotifierState::Removed)
    }

    /// Set the notifier name from a byte slice.
    fn set_name(&mut self, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let copy_len = src.len().min(MAX_NAME_LEN);
        self.name[..copy_len].copy_from_slice(&src[..copy_len]);
        self.name_len = copy_len;
        Ok(())
    }

    /// Get the notifier name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Check whether this notifier should fire for a given command.
    fn matches_command(&self, cmd: RestartCommand) -> bool {
        let bit = command_to_bit(cmd);
        self.command_mask & bit != 0
    }
}

/// Map a `RestartCommand` to a bitmask position.
const fn command_to_bit(cmd: RestartCommand) -> u8 {
    match cmd {
        RestartCommand::Reboot => 1 << 0,
        RestartCommand::Poweroff => 1 << 1,
        RestartCommand::Halt => 1 << 2,
        RestartCommand::Kexec => 1 << 3,
        RestartCommand::Suspend => 1 << 4,
        RestartCommand::Hibernate => 1 << 5,
    }
}

/// Build a command mask covering all commands.
const fn all_commands_mask() -> u8 {
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5)
}

// ── MachineOps ──────────────────────────────────────────────────────────────

/// Low-level, architecture-specific machine operations.
///
/// Each field is `true` if the corresponding operation is supported
/// by the current platform.
#[derive(Debug, Clone, Copy)]
pub struct MachineOps {
    /// Whether the platform supports warm reboot.
    pub can_reboot: bool,
    /// Whether the platform supports power off.
    pub can_poweroff: bool,
    /// Whether the platform supports halt.
    pub can_halt: bool,
    /// Whether the platform supports kexec.
    pub can_kexec: bool,
    /// Whether the platform supports suspend-to-RAM.
    pub can_suspend: bool,
    /// Whether the platform supports hibernate.
    pub can_hibernate: bool,
    /// Reboot timeout in nanoseconds.
    pub reboot_timeout_ns: u64,
    /// Whether to force immediate reboot (skip notifiers).
    pub force_immediate: bool,
}

impl MachineOps {
    /// Create default machine operations (all supported).
    const fn new() -> Self {
        Self {
            can_reboot: true,
            can_poweroff: true,
            can_halt: true,
            can_kexec: false,
            can_suspend: false,
            can_hibernate: false,
            reboot_timeout_ns: NOTIFIER_TIMEOUT_NS,
            force_immediate: false,
        }
    }

    /// Check whether the given command is supported.
    fn supports(&self, cmd: RestartCommand) -> bool {
        match cmd {
            RestartCommand::Reboot => self.can_reboot,
            RestartCommand::Poweroff => self.can_poweroff,
            RestartCommand::Halt => self.can_halt,
            RestartCommand::Kexec => self.can_kexec,
            RestartCommand::Suspend => self.can_suspend,
            RestartCommand::Hibernate => self.can_hibernate,
        }
    }
}

// ── RebootArg ───────────────────────────────────────────────────────────────

/// Optional argument passed with a reboot command.
///
/// For example, a firmware string for EFI reboot or a kernel path
/// for kexec.
#[derive(Debug, Clone, Copy)]
pub struct RebootArg {
    /// Argument bytes.
    data: [u8; MAX_REBOOT_ARG_LEN],
    /// Length of valid data.
    len: usize,
}

impl RebootArg {
    /// Create an empty reboot argument.
    const fn new() -> Self {
        Self {
            data: [0u8; MAX_REBOOT_ARG_LEN],
            len: 0,
        }
    }

    /// Create from a byte slice.
    fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() > MAX_REBOOT_ARG_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut arg = Self::new();
        arg.data[..src.len()].copy_from_slice(src);
        arg.len = src.len();
        Ok(arg)
    }

    /// Get the argument data as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Check whether the argument is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ── RestartLogEntry ─────────────────────────────────────────────────────────

/// An entry in the restart audit log.
#[derive(Debug, Clone, Copy)]
pub struct RestartLogEntry {
    /// Timestamp in nanoseconds since boot.
    timestamp_ns: u64,
    /// Which command was requested.
    command: RestartCommand,
    /// Which phase the system was in.
    phase: RestartPhase,
    /// PID that initiated the restart (0 for kernel-internal).
    initiator_pid: u64,
    /// Whether this event succeeded.
    success: bool,
    /// Notifier name (if event is notifier-related).
    notifier_name: [u8; MAX_NAME_LEN],
    /// Notifier name length.
    notifier_name_len: usize,
}

impl RestartLogEntry {
    /// Create an empty log entry.
    const fn new() -> Self {
        Self {
            timestamp_ns: 0,
            command: RestartCommand::Reboot,
            phase: RestartPhase::Running,
            initiator_pid: 0,
            success: true,
            notifier_name: [0u8; MAX_NAME_LEN],
            notifier_name_len: 0,
        }
    }
}

// ── RestartStats ────────────────────────────────────────────────────────────

/// Global statistics for the restart subsystem.
#[derive(Debug, Clone, Copy)]
pub struct RestartStats {
    /// Total reboot requests received.
    pub reboot_requests: u64,
    /// Total poweroff requests received.
    pub poweroff_requests: u64,
    /// Total halt requests received.
    pub halt_requests: u64,
    /// Total kexec requests received.
    pub kexec_requests: u64,
    /// Total suspend requests received.
    pub suspend_requests: u64,
    /// Total hibernate requests received.
    pub hibernate_requests: u64,
    /// Number of notifier chain traversals.
    pub notifier_runs: u64,
    /// Number of notifier timeouts.
    pub notifier_timeouts: u64,
    /// Number of aborted shutdowns (notifier returned Stop).
    pub aborted_shutdowns: u64,
    /// Number of completed shutdowns.
    pub completed_shutdowns: u64,
    /// Number of denied requests (permission / magic mismatch).
    pub denied_requests: u64,
}

impl RestartStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            reboot_requests: 0,
            poweroff_requests: 0,
            halt_requests: 0,
            kexec_requests: 0,
            suspend_requests: 0,
            hibernate_requests: 0,
            notifier_runs: 0,
            notifier_timeouts: 0,
            aborted_shutdowns: 0,
            completed_shutdowns: 0,
            denied_requests: 0,
        }
    }

    /// Increment the request counter for a given command.
    fn record_request(&mut self, cmd: RestartCommand) {
        match cmd {
            RestartCommand::Reboot => self.reboot_requests += 1,
            RestartCommand::Poweroff => self.poweroff_requests += 1,
            RestartCommand::Halt => self.halt_requests += 1,
            RestartCommand::Kexec => self.kexec_requests += 1,
            RestartCommand::Suspend => self.suspend_requests += 1,
            RestartCommand::Hibernate => self.hibernate_requests += 1,
        }
    }
}

// ── RestartSubsystem ────────────────────────────────────────────────────────

/// Top-level restart/reboot subsystem.
///
/// Manages the ordered sequence of notifier callbacks, device shutdown,
/// filesystem sync, CPU teardown, and final machine action for all
/// restart-class operations (reboot, poweroff, halt, kexec, suspend,
/// hibernate).
pub struct RestartSubsystem {
    /// Registered notifiers.
    notifiers: [RestartNotifier; MAX_NOTIFIERS],
    /// Number of registered notifiers.
    notifier_count: usize,
    /// Current shutdown phase.
    phase: RestartPhase,
    /// Pending command (if shutdown is in progress).
    pending_command: Option<RestartCommand>,
    /// Reboot argument for the pending command.
    pending_arg: RebootArg,
    /// Architecture-specific machine operations.
    machine_ops: MachineOps,
    /// Audit log.
    log: [RestartLogEntry; MAX_LOG_ENTRIES],
    /// Next write position in the log (wraps).
    log_head: usize,
    /// Total log entries written.
    log_total: u64,
    /// Global statistics.
    stats: RestartStats,
    /// PID of the process that initiated the current shutdown.
    initiator_pid: u64,
    /// Whether the system is in an emergency (panic) shutdown.
    emergency: bool,
    /// Current timestamp provider (nanoseconds since boot).
    now_ns: u64,
}

impl RestartSubsystem {
    /// Create a new restart subsystem.
    pub const fn new() -> Self {
        Self {
            notifiers: [const { RestartNotifier::new() }; MAX_NOTIFIERS],
            notifier_count: 0,
            phase: RestartPhase::Running,
            pending_command: None,
            pending_arg: RebootArg::new(),
            machine_ops: MachineOps::new(),
            log: [const { RestartLogEntry::new() }; MAX_LOG_ENTRIES],
            log_head: 0,
            log_total: 0,
            stats: RestartStats::new(),
            initiator_pid: 0,
            emergency: false,
            now_ns: 0,
        }
    }

    /// Update the internal time reference.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.now_ns = ns;
    }

    /// Configure machine-level operations.
    pub fn set_machine_ops(&mut self, ops: MachineOps) {
        self.machine_ops = ops;
    }

    /// Get the current shutdown phase.
    pub fn phase(&self) -> RestartPhase {
        self.phase
    }

    /// Get a reference to the statistics.
    pub fn stats(&self) -> &RestartStats {
        &self.stats
    }

    /// Check whether a shutdown is currently in progress.
    pub fn shutdown_in_progress(&self) -> bool {
        !matches!(self.phase, RestartPhase::Running)
    }

    // ── Notifier management ─────────────────────────────────────────

    /// Register a restart notifier.
    ///
    /// Returns the slot index on success.
    pub fn register_notifier(
        &mut self,
        name: &[u8],
        priority: i32,
        command_mask: u8,
    ) -> Result<usize> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if priority < PRIORITY_LOWEST || priority > PRIORITY_HIGHEST {
            return Err(Error::InvalidArgument);
        }
        if command_mask == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .notifiers
            .iter()
            .position(|n| n.is_empty())
            .ok_or(Error::OutOfMemory)?;

        self.notifiers[slot].set_name(name)?;
        self.notifiers[slot].priority = priority;
        self.notifiers[slot].state = NotifierState::Active;
        self.notifiers[slot].command_mask = command_mask;
        self.notifiers[slot].last_action = NotifierAction::Continue;
        self.notifiers[slot].last_invoked_ns = 0;
        self.notifiers[slot].invoke_count = 0;
        self.notifier_count += 1;

        Ok(slot)
    }

    /// Register a notifier that fires for all restart commands.
    pub fn register_global_notifier(&mut self, name: &[u8], priority: i32) -> Result<usize> {
        self.register_notifier(name, priority, all_commands_mask())
    }

    /// Unregister a notifier by slot index.
    pub fn unregister_notifier(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }
        let notifier = &mut self.notifiers[slot];
        if notifier.is_empty() {
            return Err(Error::NotFound);
        }
        if matches!(notifier.state, NotifierState::Running) {
            return Err(Error::Busy);
        }
        notifier.state = NotifierState::Removed;
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Disable a notifier without unregistering it.
    pub fn disable_notifier(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }
        let notifier = &mut self.notifiers[slot];
        match notifier.state {
            NotifierState::Active => {
                notifier.state = NotifierState::Disabled;
                Ok(())
            }
            NotifierState::Empty | NotifierState::Removed => Err(Error::NotFound),
            _ => Err(Error::Busy),
        }
    }

    /// Re-enable a disabled notifier.
    pub fn enable_notifier(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }
        let notifier = &mut self.notifiers[slot];
        match notifier.state {
            NotifierState::Disabled => {
                notifier.state = NotifierState::Active;
                Ok(())
            }
            NotifierState::Empty | NotifierState::Removed => Err(Error::NotFound),
            _ => Err(Error::Busy),
        }
    }

    /// Get the number of registered notifiers.
    pub fn notifier_count(&self) -> usize {
        self.notifier_count
    }

    // ── Ordered notifier indices ────────────────────────────────────

    /// Build a priority-sorted index array of active notifiers matching
    /// the given command. Returns the number of valid entries.
    fn sorted_notifier_indices(
        &self,
        cmd: RestartCommand,
        out: &mut [usize; MAX_NOTIFIERS],
    ) -> usize {
        let mut count = 0usize;
        for (i, n) in self.notifiers.iter().enumerate() {
            if matches!(n.state, NotifierState::Active) && n.matches_command(cmd) {
                out[count] = i;
                count += 1;
            }
        }
        // Insertion sort by descending priority (highest first).
        for i in 1..count {
            let key = out[i];
            let key_pri = self.notifiers[key].priority;
            let mut j = i;
            while j > 0 && self.notifiers[out[j - 1]].priority < key_pri {
                out[j] = out[j - 1];
                j -= 1;
            }
            out[j] = key;
        }
        count
    }

    // ── Shutdown sequence ───────────────────────────────────────────

    /// Validate the reboot magic numbers.
    pub fn validate_magic(&mut self, magic1: u32, magic2: u32) -> Result<()> {
        if magic1 != REBOOT_MAGIC1 || magic2 != REBOOT_MAGIC2 {
            self.stats.denied_requests += 1;
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Initiate a restart sequence.
    ///
    /// The caller must have already validated permissions. The sequence
    /// proceeds through the notifier chain, device shutdown, filesystem
    /// sync, CPU teardown, and final machine action.
    pub fn initiate(
        &mut self,
        cmd: RestartCommand,
        arg: Option<&[u8]>,
        pid: u64,
    ) -> Result<RestartPhase> {
        // Prevent double initiation.
        if self.shutdown_in_progress() {
            return Err(Error::Busy);
        }

        // Check platform support.
        if !self.machine_ops.supports(cmd) {
            return Err(Error::NotImplemented);
        }

        self.stats.record_request(cmd);
        self.initiator_pid = pid;
        self.pending_command = Some(cmd);

        if let Some(a) = arg {
            self.pending_arg = RebootArg::from_bytes(a)?;
        } else {
            self.pending_arg = RebootArg::new();
        }

        self.log_event(cmd, RestartPhase::Running, true);

        // If emergency or force-immediate, skip notifiers.
        if self.emergency || self.machine_ops.force_immediate {
            self.phase = RestartPhase::MachineAction;
            return Ok(self.phase);
        }

        self.phase = RestartPhase::Notifying;
        Ok(self.phase)
    }

    /// Run the notifier chain for the pending command.
    ///
    /// Returns `Ok(true)` if all notifiers passed, `Ok(false)` if a
    /// notifier stopped the chain.
    pub fn run_notifiers(&mut self) -> Result<bool> {
        let cmd = self.pending_command.ok_or(Error::InvalidArgument)?;

        if !matches!(self.phase, RestartPhase::Notifying) {
            return Err(Error::InvalidArgument);
        }

        self.stats.notifier_runs += 1;

        let mut indices = [0usize; MAX_NOTIFIERS];
        let count = self.sorted_notifier_indices(cmd, &mut indices);

        for idx in 0..count {
            let slot = indices[idx];
            self.notifiers[slot].state = NotifierState::Running;

            // Simulate notifier execution — real implementation would
            // call the registered function pointer. We record the
            // invocation and assume Continue.
            let action = NotifierAction::Continue;
            self.notifiers[slot].last_action = action;
            self.notifiers[slot].last_invoked_ns = self.now_ns;
            self.notifiers[slot].invoke_count += 1;
            self.notifiers[slot].state = NotifierState::Active;

            match action {
                NotifierAction::Stop => {
                    self.stats.aborted_shutdowns += 1;
                    self.log_event(cmd, RestartPhase::Notifying, false);
                    self.abort_shutdown();
                    return Ok(false);
                }
                NotifierAction::Timeout => {
                    self.stats.notifier_timeouts += 1;
                    // Continue despite timeout.
                }
                NotifierAction::Continue | NotifierAction::ContinueWithWarning => {}
            }
        }

        self.phase = RestartPhase::DeviceShutdown;
        Ok(true)
    }

    /// Advance to the filesystem sync phase.
    pub fn sync_filesystems(&mut self) -> Result<()> {
        if !matches!(self.phase, RestartPhase::DeviceShutdown) {
            return Err(Error::InvalidArgument);
        }
        let cmd = self.pending_command.ok_or(Error::InvalidArgument)?;
        self.log_event(cmd, RestartPhase::FilesystemSync, true);
        self.phase = RestartPhase::FilesystemSync;
        Ok(())
    }

    /// Advance to the CPU teardown phase.
    pub fn teardown_cpus(&mut self) -> Result<()> {
        if !matches!(self.phase, RestartPhase::FilesystemSync) {
            return Err(Error::InvalidArgument);
        }
        let cmd = self.pending_command.ok_or(Error::InvalidArgument)?;
        self.log_event(cmd, RestartPhase::CpuTeardown, true);
        self.phase = RestartPhase::CpuTeardown;
        Ok(())
    }

    /// Advance to the final machine action phase.
    pub fn prepare_machine_action(&mut self) -> Result<RestartCommand> {
        if !matches!(self.phase, RestartPhase::CpuTeardown) {
            return Err(Error::InvalidArgument);
        }
        let cmd = self.pending_command.ok_or(Error::InvalidArgument)?;
        self.log_event(cmd, RestartPhase::MachineAction, true);
        self.phase = RestartPhase::MachineAction;
        Ok(cmd)
    }

    /// Complete the shutdown, marking it done.
    ///
    /// In a real system this function would not return — the machine
    /// would be rebooted/halted/powered off. In our model we record
    /// the completion and reset state.
    pub fn complete(&mut self) -> Result<()> {
        if !matches!(self.phase, RestartPhase::MachineAction) {
            return Err(Error::InvalidArgument);
        }
        let cmd = self.pending_command.ok_or(Error::InvalidArgument)?;
        self.log_event(cmd, RestartPhase::Done, true);
        self.stats.completed_shutdowns += 1;
        self.phase = RestartPhase::Done;
        self.reset_internal();
        Ok(())
    }

    /// Abort an in-progress shutdown and return to running state.
    pub fn abort_shutdown(&mut self) {
        if let Some(cmd) = self.pending_command {
            self.log_event(cmd, self.phase, false);
        }
        self.reset_internal();
    }

    /// Set the emergency flag for panic-path shutdowns.
    pub fn set_emergency(&mut self, emergency: bool) {
        self.emergency = emergency;
    }

    /// Check whether the system is in emergency shutdown mode.
    pub fn is_emergency(&self) -> bool {
        self.emergency
    }

    /// Run the full shutdown sequence synchronously.
    ///
    /// Returns the command that was executed, or an error if the
    /// sequence was aborted.
    pub fn execute_full_sequence(
        &mut self,
        cmd: RestartCommand,
        arg: Option<&[u8]>,
        pid: u64,
    ) -> Result<RestartCommand> {
        self.initiate(cmd, arg, pid)?;

        if matches!(self.phase, RestartPhase::Notifying) {
            let passed = self.run_notifiers()?;
            if !passed {
                return Err(Error::Interrupted);
            }
        }

        if matches!(self.phase, RestartPhase::DeviceShutdown) {
            self.sync_filesystems()?;
        }

        if matches!(self.phase, RestartPhase::FilesystemSync) {
            self.teardown_cpus()?;
        }

        if matches!(self.phase, RestartPhase::CpuTeardown) {
            self.prepare_machine_action()?;
        }

        self.complete()?;
        Ok(cmd)
    }

    // ── Emergency reboot ────────────────────────────────────────────

    /// Perform an emergency reboot (panic path).
    ///
    /// Skips all notifiers and goes directly to machine action.
    pub fn emergency_reboot(&mut self) -> Result<()> {
        self.emergency = true;
        self.initiate(RestartCommand::Reboot, None, 0)?;
        self.complete()?;
        Ok(())
    }

    /// Perform an emergency halt.
    pub fn emergency_halt(&mut self) -> Result<()> {
        self.emergency = true;
        self.initiate(RestartCommand::Halt, None, 0)?;
        self.complete()?;
        Ok(())
    }

    // ── Query ───────────────────────────────────────────────────────

    /// Get the pending restart command, if any.
    pub fn pending_command(&self) -> Option<RestartCommand> {
        self.pending_command
    }

    /// Get the reboot argument for the pending command.
    pub fn pending_arg(&self) -> &RebootArg {
        &self.pending_arg
    }

    /// Get the PID that initiated the current shutdown.
    pub fn initiator_pid(&self) -> u64 {
        self.initiator_pid
    }

    /// Get the total number of log entries.
    pub fn log_total(&self) -> u64 {
        self.log_total
    }

    /// Read a log entry by index (0 = oldest still in buffer).
    pub fn read_log(&self, index: usize) -> Result<&RestartLogEntry> {
        if self.log_total == 0 {
            return Err(Error::NotFound);
        }
        let available = (self.log_total as usize).min(MAX_LOG_ENTRIES);
        if index >= available {
            return Err(Error::InvalidArgument);
        }
        let start = if self.log_total as usize > MAX_LOG_ENTRIES {
            self.log_head
        } else {
            0
        };
        let real = (start + index) % MAX_LOG_ENTRIES;
        Ok(&self.log[real])
    }

    /// Get information about a notifier by slot index.
    pub fn notifier_info(&self, slot: usize) -> Result<(&[u8], i32, NotifierState, u64)> {
        if slot >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }
        let n = &self.notifiers[slot];
        if n.is_empty() {
            return Err(Error::NotFound);
        }
        Ok((n.name(), n.priority, n.state, n.invoke_count))
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Record a log event.
    fn log_event(&mut self, cmd: RestartCommand, phase: RestartPhase, success: bool) {
        let entry = &mut self.log[self.log_head];
        entry.timestamp_ns = self.now_ns;
        entry.command = cmd;
        entry.phase = phase;
        entry.initiator_pid = self.initiator_pid;
        entry.success = success;
        entry.notifier_name = [0u8; MAX_NAME_LEN];
        entry.notifier_name_len = 0;
        self.log_head = (self.log_head + 1) % MAX_LOG_ENTRIES;
        self.log_total += 1;
    }

    /// Reset transient state after completion or abort.
    fn reset_internal(&mut self) {
        self.phase = RestartPhase::Running;
        self.pending_command = None;
        self.pending_arg = RebootArg::new();
        self.initiator_pid = 0;
        self.emergency = false;
    }
}

// ── SysRq integration ───────────────────────────────────────────────────────

/// SysRq restart trigger type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysRqAction {
    /// SysRq+B — immediate reboot.
    Reboot,
    /// SysRq+O — power off.
    Poweroff,
    /// SysRq+S — sync filesystems.
    Sync,
    /// SysRq+U — remount read-only.
    RemountReadOnly,
}

/// Translate a SysRq key action to a `RestartCommand`.
pub fn sysrq_to_command(action: SysRqAction) -> Option<RestartCommand> {
    match action {
        SysRqAction::Reboot => Some(RestartCommand::Reboot),
        SysRqAction::Poweroff => Some(RestartCommand::Poweroff),
        SysRqAction::Sync | SysRqAction::RemountReadOnly => None,
    }
}

// ── Reboot reason tracking ──────────────────────────────────────────────────

/// Reason category for the reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootReason {
    /// User-requested reboot (via syscall).
    UserRequested,
    /// Kernel panic or watchdog.
    KernelPanic,
    /// Hardware watchdog expiry.
    Watchdog,
    /// Thermal emergency.
    ThermalEmergency,
    /// Power supply critical.
    PowerCritical,
    /// Software update requires reboot.
    SoftwareUpdate,
    /// Unknown or unspecified.
    Unknown,
}

impl Default for RebootReason {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Persistent reboot reason record that can be stored across boots.
#[derive(Debug, Clone, Copy)]
pub struct RebootReasonRecord {
    /// The reason category.
    pub reason: RebootReason,
    /// Timestamp of the reboot (nanoseconds since boot).
    pub timestamp_ns: u64,
    /// PID that triggered the reboot (0 for kernel).
    pub pid: u64,
    /// The restart command used.
    pub command: RestartCommand,
    /// Sequence number for ordering.
    pub sequence: u64,
}

impl RebootReasonRecord {
    /// Create a new reason record.
    pub const fn new() -> Self {
        Self {
            reason: RebootReason::Unknown,
            timestamp_ns: 0,
            pid: 0,
            command: RestartCommand::Reboot,
            sequence: 0,
        }
    }
}

// ── Shutdown guard ──────────────────────────────────────────────────────────

/// A token that must be held to perform certain shutdown-path operations.
///
/// This enforces that only authorized paths can trigger machine-level
/// actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownGuard {
    /// The guard token value.
    token: u64,
    /// Whether this guard has been consumed.
    consumed: bool,
}

impl ShutdownGuard {
    /// Create a new guard with the given token.
    pub const fn new(token: u64) -> Self {
        Self {
            token,
            consumed: false,
        }
    }

    /// Validate the guard token.
    pub fn validate(&self, expected: u64) -> Result<()> {
        if self.consumed {
            return Err(Error::InvalidArgument);
        }
        if self.token != expected {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Consume the guard (one-time use).
    pub fn consume(&mut self) -> Result<u64> {
        if self.consumed {
            return Err(Error::InvalidArgument);
        }
        self.consumed = true;
        Ok(self.token)
    }

    /// Check whether the guard has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

// ── PowerState ──────────────────────────────────────────────────────────────

/// System power state for ACPI-like transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// S0 — fully running.
    S0Working,
    /// S1 — CPU stopped, RAM refreshed.
    S1Standby,
    /// S3 — suspend to RAM.
    S3SuspendToRam,
    /// S4 — suspend to disk (hibernate).
    S4Hibernate,
    /// S5 — soft off (power off).
    S5SoftOff,
}

impl Default for PowerState {
    fn default() -> Self {
        Self::S0Working
    }
}

/// Power state transition validator.
pub struct PowerStateValidator {
    /// Current power state.
    current: PowerState,
    /// Number of transitions performed.
    transition_count: u64,
}

impl PowerStateValidator {
    /// Create a new validator in S0 state.
    pub const fn new() -> Self {
        Self {
            current: PowerState::S0Working,
            transition_count: 0,
        }
    }

    /// Get the current power state.
    pub fn current(&self) -> PowerState {
        self.current
    }

    /// Attempt to transition to a new power state.
    pub fn transition(&mut self, target: PowerState) -> Result<()> {
        if !self.is_valid_transition(target) {
            return Err(Error::InvalidArgument);
        }
        self.current = target;
        self.transition_count += 1;
        Ok(())
    }

    /// Check whether a transition is valid.
    fn is_valid_transition(&self, target: PowerState) -> bool {
        match (self.current, target) {
            // From S0, can go anywhere.
            (PowerState::S0Working, _) => true,
            // From sleep states, can only go back to S0 or to S5.
            (PowerState::S1Standby, PowerState::S0Working)
            | (PowerState::S1Standby, PowerState::S5SoftOff) => true,
            (PowerState::S3SuspendToRam, PowerState::S0Working)
            | (PowerState::S3SuspendToRam, PowerState::S5SoftOff) => true,
            (PowerState::S4Hibernate, PowerState::S0Working)
            | (PowerState::S4Hibernate, PowerState::S5SoftOff) => true,
            // S5 is terminal — no transitions out.
            (PowerState::S5SoftOff, _) => false,
            _ => false,
        }
    }

    /// Get the number of transitions performed.
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_initiate() {
        let mut sys = RestartSubsystem::new();
        let slot = sys.register_global_notifier(b"console", 100).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(sys.notifier_count(), 1);

        let phase = sys.initiate(RestartCommand::Reboot, None, 42).unwrap();
        assert_eq!(phase, RestartPhase::Notifying);
        assert!(sys.shutdown_in_progress());
    }

    #[test]
    fn test_full_sequence() {
        let mut sys = RestartSubsystem::new();
        sys.register_global_notifier(b"net", 50).unwrap();
        let result = sys.execute_full_sequence(RestartCommand::Poweroff, None, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), RestartCommand::Poweroff);
        assert_eq!(sys.stats().completed_shutdowns, 1);
    }

    #[test]
    fn test_emergency_reboot() {
        let mut sys = RestartSubsystem::new();
        assert!(sys.emergency_reboot().is_ok());
        assert_eq!(sys.stats().completed_shutdowns, 1);
    }

    #[test]
    fn test_magic_validation() {
        let mut sys = RestartSubsystem::new();
        assert!(sys.validate_magic(REBOOT_MAGIC1, REBOOT_MAGIC2).is_ok());
        assert_eq!(sys.validate_magic(0, 0), Err(Error::PermissionDenied));
    }

    #[test]
    fn test_power_state_transitions() {
        let mut v = PowerStateValidator::new();
        assert_eq!(v.current(), PowerState::S0Working);
        assert!(v.transition(PowerState::S3SuspendToRam).is_ok());
        assert!(v.transition(PowerState::S0Working).is_ok());
        assert_eq!(v.transition_count(), 2);
    }

    #[test]
    fn test_shutdown_guard() {
        let mut g = ShutdownGuard::new(0xCAFE);
        assert!(g.validate(0xCAFE).is_ok());
        assert!(g.validate(0xDEAD).is_err());
        assert_eq!(g.consume().unwrap(), 0xCAFE);
        assert!(g.consume().is_err());
    }
}
