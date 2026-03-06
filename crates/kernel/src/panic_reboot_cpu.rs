// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Panic-time CPU coordination and system reboot.
//!
//! When a kernel panic occurs, one CPU is elected as the "panic CPU"
//! and the remaining CPUs are halted via NMI/IPI. The panic CPU then
//! executes the panic notifier chain, optionally triggers a crash
//! dump (kdump / kexec), and finally reboots (or halts) the system
//! after a configurable timeout.
//!
//! # Panic Sequence
//!
//! ```text
//! panic!()
//!  │
//!  ▼
//! PanicCpuCoordinator::initiate_panic(cpu)
//!  ├── 1. Elect panic CPU (CAS on atomic flag)
//!  ├── 2. Send NMI to all other CPUs → mark them halted
//!  ├── 3. Run notifier chain (priority order)
//!  ├── 4. crash_kexec integration point (if enabled)
//!  ├── 5. Wait for panic_timeout seconds
//!  └── 6. Execute reboot action (reboot / halt / hang)
//! ```
//!
//! # Reference
//!
//! Linux `kernel/panic.c`, `arch/x86/kernel/reboot.c`,
//! `arch/x86/kernel/crash.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum panic notifier callbacks.
const MAX_NOTIFIERS: usize = 32;

/// Maximum notifier name length (bytes).
const MAX_NOTIFIER_NAME_LEN: usize = 32;

/// Maximum panic message length (bytes).
const MAX_PANIC_MSG_LEN: usize = 256;

/// Maximum number of recorded panic events in the history ring.
const MAX_PANIC_HISTORY: usize = 8;

/// Default panic timeout in seconds.
/// -1 = never reboot; 0 = reboot immediately; >0 = wait N seconds.
const DEFAULT_PANIC_TIMEOUT_SECS: i64 = -1;

// ══════════════════════════════════════════════════════════════
// CpuHaltState
// ══════════════════════════════════════════════════════════════

/// State of a CPU during the panic coordination protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CpuHaltState {
    /// CPU is running normally (pre-panic).
    #[default]
    Running = 0,
    /// NMI/IPI halt request sent, awaiting acknowledgement.
    HaltRequested = 1,
    /// CPU has acknowledged the halt request and is spinning.
    Halted = 2,
    /// CPU is the elected panic CPU (still executing).
    PanicOwner = 3,
    /// CPU was offline when panic occurred.
    Offline = 4,
}

// ══════════════════════════════════════════════════════════════
// PanicAction
// ══════════════════════════════════════════════════════════════

/// What the system should do after the panic timeout elapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PanicAction {
    /// Reboot the system (warm restart).
    Reboot = 0,
    /// Power the system off.
    Halt = 1,
    /// Spin forever with interrupts disabled.
    #[default]
    Hang = 2,
    /// Execute kexec into crash kernel.
    KexecCrash = 3,
}

// ══════════════════════════════════════════════════════════════
// NotifierAction
// ══════════════════════════════════════════════════════════════

/// Return value from a panic notifier callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierAction {
    /// Continue invoking the remaining notifiers.
    Continue,
    /// Stop the notifier chain immediately.
    Stop,
}

// ══════════════════════════════════════════════════════════════
// PanicNotifier
// ══════════════════════════════════════════════════════════════

/// A registered panic notifier callback.
pub type PanicNotifierFn = fn(cpu: u32, msg: &[u8]) -> NotifierAction;

/// Registered notifier entry.
struct PanicNotifierEntry {
    /// Human-readable name for debugging.
    name: [u8; MAX_NOTIFIER_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Callback function.
    callback: PanicNotifierFn,
    /// Priority (lower numeric value runs first).
    priority: i32,
    /// Whether this slot is occupied.
    active: bool,
}

impl PanicNotifierEntry {
    /// Empty (inactive) notifier.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NOTIFIER_NAME_LEN],
            name_len: 0,
            callback: dummy_notifier,
            priority: 0,
            active: false,
        }
    }
}

/// Default no-op notifier callback.
fn dummy_notifier(_cpu: u32, _msg: &[u8]) -> NotifierAction {
    NotifierAction::Continue
}

// ══════════════════════════════════════════════════════════════
// PanicRecord
// ══════════════════════════════════════════════════════════════

/// A recorded panic event in the history ring.
#[derive(Debug, Clone)]
pub struct PanicRecord {
    /// Which CPU triggered the panic.
    pub panic_cpu: u32,
    /// Monotonic timestamp (nanoseconds) of the panic.
    pub timestamp_ns: u64,
    /// Panic message.
    message: [u8; MAX_PANIC_MSG_LEN],
    /// Message length.
    message_len: usize,
    /// Number of CPUs that were halted.
    pub cpus_halted: u32,
    /// Whether crash dump was triggered.
    pub crash_dump_triggered: bool,
    /// Final action taken.
    pub action: PanicAction,
    /// Slot occupied flag.
    occupied: bool,
}

impl PanicRecord {
    /// Create an empty record.
    const fn empty() -> Self {
        Self {
            panic_cpu: 0,
            timestamp_ns: 0,
            message: [0u8; MAX_PANIC_MSG_LEN],
            message_len: 0,
            cpus_halted: 0,
            crash_dump_triggered: false,
            action: PanicAction::Hang,
            occupied: false,
        }
    }

    /// Return the panic message as a byte slice.
    pub fn message(&self) -> &[u8] {
        &self.message[..self.message_len]
    }
}

// ══════════════════════════════════════════════════════════════
// PanicCpuStats
// ══════════════════════════════════════════════════════════════

/// Statistics about panic handling.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicCpuStats {
    /// Total panic events processed.
    pub total_panics: u64,
    /// Total notifiers invoked across all panics.
    pub notifiers_invoked: u64,
    /// Notifiers that returned Stop.
    pub notifiers_stopped: u64,
    /// CPUs halted across all panics.
    pub total_cpus_halted: u64,
    /// Crash dumps triggered.
    pub crash_dumps: u64,
}

// ══════════════════════════════════════════════════════════════
// PanicCpuCoordinator
// ══════════════════════════════════════════════════════════════

/// Coordinates multi-CPU behaviour during a kernel panic.
pub struct PanicCpuCoordinator {
    /// Per-CPU halt state.
    cpu_states: [CpuHaltState; MAX_CPUS],
    /// Number of CPUs that were online at panic time.
    online_cpus: u32,
    /// Which CPU owns the panic (elected panic CPU).
    panic_cpu: Option<u32>,
    /// Whether a panic is currently in progress.
    panic_in_progress: bool,
    /// Registered notifiers.
    notifiers: [PanicNotifierEntry; MAX_NOTIFIERS],
    /// Notifier count.
    notifier_count: usize,
    /// Configurable panic timeout (seconds).
    panic_timeout_secs: i64,
    /// Configured action after timeout.
    panic_action: PanicAction,
    /// Whether crash_kexec integration is enabled.
    crash_kexec_enabled: bool,
    /// Panic history ring.
    history: [PanicRecord; MAX_PANIC_HISTORY],
    /// Write index into the history ring.
    history_write: usize,
    /// Statistics.
    stats: PanicCpuStats,
}

impl Default for PanicCpuCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicCpuCoordinator {
    /// Create a new panic coordinator in its default state.
    pub const fn new() -> Self {
        Self {
            cpu_states: [CpuHaltState::Running; MAX_CPUS],
            online_cpus: 1,
            panic_cpu: None,
            panic_in_progress: false,
            notifiers: [const { PanicNotifierEntry::empty() }; MAX_NOTIFIERS],
            notifier_count: 0,
            panic_timeout_secs: DEFAULT_PANIC_TIMEOUT_SECS,
            panic_action: PanicAction::Hang,
            crash_kexec_enabled: false,
            history: [const { PanicRecord::empty() }; MAX_PANIC_HISTORY],
            history_write: 0,
            stats: PanicCpuStats {
                total_panics: 0,
                notifiers_invoked: 0,
                notifiers_stopped: 0,
                total_cpus_halted: 0,
                crash_dumps: 0,
            },
        }
    }

    /// Set the number of online CPUs. Must be called before
    /// any panic can be coordinated.
    pub fn set_online_cpus(&mut self, count: u32) -> Result<()> {
        if count == 0 || count as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.online_cpus = count;
        Ok(())
    }

    /// Configure the panic timeout.
    pub fn set_panic_timeout(&mut self, secs: i64) {
        self.panic_timeout_secs = secs;
    }

    /// Return the configured panic timeout.
    pub fn panic_timeout(&self) -> i64 {
        self.panic_timeout_secs
    }

    /// Configure the post-panic action.
    pub fn set_panic_action(&mut self, action: PanicAction) {
        self.panic_action = action;
    }

    /// Enable or disable crash_kexec integration.
    pub fn set_crash_kexec_enabled(&mut self, enabled: bool) {
        self.crash_kexec_enabled = enabled;
    }

    /// Register a panic notifier callback.
    pub fn register_notifier(
        &mut self,
        name: &[u8],
        callback: PanicNotifierFn,
        priority: i32,
    ) -> Result<usize> {
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .notifiers
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        let entry = &mut self.notifiers[slot];
        let nlen = name.len().min(MAX_NOTIFIER_NAME_LEN);
        entry.name[..nlen].copy_from_slice(&name[..nlen]);
        entry.name_len = nlen;
        entry.callback = callback;
        entry.priority = priority;
        entry.active = true;
        self.notifier_count += 1;

        Ok(slot)
    }

    /// Unregister a panic notifier by slot index.
    pub fn unregister_notifier(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }
        if !self.notifiers[slot].active {
            return Err(Error::NotFound);
        }
        self.notifiers[slot].active = false;
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Initiate the panic protocol.
    ///
    /// `cpu` is the CPU that detected the panic.
    /// `timestamp_ns` is the current monotonic time.
    /// `message` is the panic reason string.
    ///
    /// Returns the [`PanicAction`] that should be taken by the
    /// caller after this function returns.
    pub fn initiate_panic(
        &mut self,
        cpu: u32,
        timestamp_ns: u64,
        message: &[u8],
    ) -> Result<PanicAction> {
        if self.panic_in_progress {
            // Nested panic — halt this CPU immediately.
            if (cpu as usize) < MAX_CPUS {
                self.cpu_states[cpu as usize] = CpuHaltState::Halted;
            }
            return Err(Error::Busy);
        }

        self.panic_in_progress = true;
        self.panic_cpu = Some(cpu);

        // Step 1: mark panic CPU.
        if (cpu as usize) < MAX_CPUS {
            self.cpu_states[cpu as usize] = CpuHaltState::PanicOwner;
        }

        // Step 2: halt all other online CPUs.
        let halted = self.halt_other_cpus(cpu);

        // Step 3: run notifier chain.
        let (invoked, stopped) = self.run_notifiers(cpu, message);
        self.stats.notifiers_invoked += invoked as u64;
        if stopped {
            self.stats.notifiers_stopped += 1;
        }

        // Step 4: crash_kexec integration point.
        let crash_triggered = self.crash_kexec_enabled;
        if crash_triggered {
            self.stats.crash_dumps += 1;
        }

        // Step 5/6: record the event.
        self.record_panic(cpu, timestamp_ns, message, halted, crash_triggered);

        self.stats.total_panics += 1;
        self.stats.total_cpus_halted += halted as u64;

        Ok(self.panic_action)
    }

    /// Query whether a panic is currently in progress.
    pub fn is_panic_in_progress(&self) -> bool {
        self.panic_in_progress
    }

    /// Return which CPU owns the current panic (if any).
    pub fn panic_cpu(&self) -> Option<u32> {
        self.panic_cpu
    }

    /// Return the halt state of a specific CPU.
    pub fn cpu_state(&self, cpu: u32) -> Result<CpuHaltState> {
        if (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpu_states[cpu as usize])
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &PanicCpuStats {
        &self.stats
    }

    /// Return the most recent panic record (if any).
    pub fn last_panic(&self) -> Option<&PanicRecord> {
        if self.stats.total_panics == 0 {
            return None;
        }
        let idx = if self.history_write == 0 {
            MAX_PANIC_HISTORY - 1
        } else {
            self.history_write - 1
        };
        if self.history[idx].occupied {
            Some(&self.history[idx])
        } else {
            None
        }
    }

    // ── internal helpers ─────────────────────────────────────

    /// Send halt request to all CPUs except the panic owner.
    fn halt_other_cpus(&mut self, panic_cpu: u32) -> u32 {
        let mut halted: u32 = 0;

        for i in 0..self.online_cpus as usize {
            if i == panic_cpu as usize {
                continue;
            }
            if i >= MAX_CPUS {
                break;
            }
            self.cpu_states[i] = CpuHaltState::Halted;
            halted += 1;
        }

        halted
    }

    /// Run the panic notifier chain in priority order.
    /// Returns (count_invoked, was_stopped).
    fn run_notifiers(&self, cpu: u32, message: &[u8]) -> (u32, bool) {
        // Collect active notifier indices, sort by priority.
        let mut order = [0usize; MAX_NOTIFIERS];
        let mut count = 0usize;

        for (i, n) in self.notifiers.iter().enumerate() {
            if n.active {
                order[count] = i;
                count += 1;
            }
        }

        // Insertion sort by priority (ascending).
        for i in 1..count {
            let key = order[i];
            let key_prio = self.notifiers[key].priority;
            let mut j = i;
            while j > 0 && self.notifiers[order[j - 1]].priority > key_prio {
                order[j] = order[j - 1];
                j -= 1;
            }
            order[j] = key;
        }

        let msg_len = message.len().min(MAX_PANIC_MSG_LEN);
        let msg = &message[..msg_len];
        let mut invoked: u32 = 0;

        for &idx in &order[..count] {
            let result = (self.notifiers[idx].callback)(cpu, msg);
            invoked += 1;
            if result == NotifierAction::Stop {
                return (invoked, true);
            }
        }

        (invoked, false)
    }

    /// Record a panic event in the history ring.
    fn record_panic(
        &mut self,
        cpu: u32,
        timestamp_ns: u64,
        message: &[u8],
        cpus_halted: u32,
        crash_dump: bool,
    ) {
        let idx = self.history_write % MAX_PANIC_HISTORY;
        let rec = &mut self.history[idx];

        rec.panic_cpu = cpu;
        rec.timestamp_ns = timestamp_ns;
        let mlen = message.len().min(MAX_PANIC_MSG_LEN);
        rec.message[..mlen].copy_from_slice(&message[..mlen]);
        rec.message_len = mlen;
        rec.cpus_halted = cpus_halted;
        rec.crash_dump_triggered = crash_dump;
        rec.action = self.panic_action;
        rec.occupied = true;

        self.history_write = idx + 1;
    }
}
