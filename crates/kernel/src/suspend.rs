// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System suspend/resume orchestration.
//!
//! Manages the full system power state lifecycle:
//! freeze processes, suspend devices in reverse registration order,
//! enter platform sleep state (S3/S4), then resume devices and
//! thaw processes on wake.
//!
//! # Architecture
//!
//! ```text
//!  suspend_enter()
//!        │
//!        ▼
//!  freeze_processes() ──► SuspendState::Freezing
//!        │
//!        ▼
//!  suspend_devices()  ──► SuspendState::Suspended
//!    (reverse order)      (iterate registered devices)
//!        │
//!        ▼
//!  platform_suspend() ──► enter S3/S4 via HAL
//!        │                (CPU halted until wake event)
//!        ▼
//!  resume_devices()   ──► SuspendState::Resuming
//!    (forward order)
//!        │
//!        ▼
//!  thaw_processes()   ──► SuspendState::Thawing
//!        │
//!        ▼
//!  SuspendState::Running
//! ```
//!
//! # Integration Points
//!
//! - `hal::power`: ACPI S-state entry (referenced, not modified)
//! - `kernel::sched`: Process freezing/thawing
//! - Device drivers: `DevicePmOps` trait for per-device callbacks
//!
//! Reference: Linux `kernel/power/suspend.c`,
//! `kernel/power/hibernate.c`,
//! `include/linux/suspend.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of devices that can register PM callbacks.
const MAX_PM_DEVICES: usize = 64;

/// Maximum length of a device name in bytes.
const MAX_DEVICE_NAME_LEN: usize = 32;

/// Maximum number of suspend notifier callbacks.
const MAX_NOTIFIERS: usize = 16;

// -------------------------------------------------------------------
// SuspendState
// -------------------------------------------------------------------

/// Current state of the system suspend/resume lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum SuspendState {
    /// System is running normally.
    #[default]
    Running = 0,
    /// Processes are being frozen.
    Freezing = 1,
    /// All processes frozen, devices being suspended.
    Suspended = 2,
    /// Devices are being resumed after wake.
    Resuming = 3,
    /// Processes are being thawed.
    Thawing = 4,
}

// -------------------------------------------------------------------
// SleepState
// -------------------------------------------------------------------

/// ACPI sleep states supported by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum SleepState {
    /// S1 — CPU stops executing, power to CPU and RAM maintained.
    Standby = 1,
    /// S3 — Suspend to RAM. CPU context lost, RAM refreshed.
    #[default]
    SuspendToRam = 3,
    /// S4 — Suspend to disk (hibernate). All state saved to disk.
    SuspendToDisk = 4,
}

// -------------------------------------------------------------------
// DevicePmState
// -------------------------------------------------------------------

/// Power management state of a registered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum DevicePmState {
    /// Device is active and operational.
    #[default]
    Active = 0,
    /// Device is suspended (low-power or off).
    Suspended = 1,
    /// Device encountered an error during suspend/resume.
    Error = 2,
}

// -------------------------------------------------------------------
// DevicePmEntry
// -------------------------------------------------------------------

/// A registered device with power management callbacks.
///
/// Devices register in order; suspend iterates in reverse,
/// resume iterates forward (matching Linux DPM list ordering).
#[derive(Clone, Copy)]
pub struct DevicePmEntry {
    /// Device name for diagnostics.
    name: [u8; MAX_DEVICE_NAME_LEN],
    /// Valid length of the name.
    name_len: usize,
    /// Registration order (lower = registered earlier).
    order: u32,
    /// Callback identifier for suspend operation.
    suspend_handler_id: u32,
    /// Callback identifier for resume operation.
    resume_handler_id: u32,
    /// Current PM state of the device.
    state: DevicePmState,
    /// Whether this slot is in use.
    active: bool,
    /// Unique device identifier.
    id: u32,
}

impl Default for DevicePmEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl DevicePmEntry {
    /// Create an empty device PM entry.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_DEVICE_NAME_LEN],
            name_len: 0,
            order: 0,
            suspend_handler_id: 0,
            resume_handler_id: 0,
            state: DevicePmState::Active,
            active: false,
            id: 0,
        }
    }

    /// Device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Current PM state of this device.
    pub fn state(&self) -> DevicePmState {
        self.state
    }

    /// Unique device identifier.
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl core::fmt::Debug for DevicePmEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevicePmEntry")
            .field("id", &self.id)
            .field("order", &self.order)
            .field("state", &self.state)
            .field("active", &self.active)
            .finish()
    }
}

// -------------------------------------------------------------------
// SuspendNotifierEvent
// -------------------------------------------------------------------

/// Events emitted during the suspend/resume lifecycle that
/// registered notifiers can react to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SuspendNotifierEvent {
    /// About to start freezing processes.
    PreFreeze = 0,
    /// All processes frozen, about to suspend devices.
    PostFreeze = 1,
    /// About to enter platform sleep state.
    PreSuspend = 2,
    /// Just woke from platform sleep state.
    PostResume = 3,
    /// About to thaw processes.
    PreThaw = 4,
    /// All processes thawed, system fully running.
    PostThaw = 5,
}

// -------------------------------------------------------------------
// SuspendNotifier
// -------------------------------------------------------------------

/// A registered callback for suspend/resume lifecycle events.
#[derive(Debug, Clone, Copy, Default)]
pub struct SuspendNotifier {
    /// Callback identifier invoked for matching events.
    pub handler_id: u32,
    /// Priority (higher = called first on suspend, last on
    /// resume).
    pub priority: i32,
    /// Whether this notifier slot is in use.
    pub active: bool,
}

// -------------------------------------------------------------------
// SuspendStats
// -------------------------------------------------------------------

/// Cumulative statistics for suspend/resume operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct SuspendStats {
    /// Number of successful suspend/resume cycles.
    pub success_count: u64,
    /// Number of failed suspend attempts.
    pub fail_count: u64,
    /// Duration of the last successful suspend (in ticks).
    pub last_suspend_ticks: u64,
    /// Duration of the last successful resume (in ticks).
    pub last_resume_ticks: u64,
    /// ID of the last device that failed to suspend.
    pub last_failed_device: u32,
    /// Number of freeze timeouts (tasks that refused to freeze).
    pub freeze_timeouts: u64,
}

// -------------------------------------------------------------------
// SuspendManager
// -------------------------------------------------------------------

/// Central orchestrator for system suspend and resume.
///
/// Manages the device PM list, notifier chain, and drives the
/// full suspend/resume lifecycle including process
/// freezing/thawing, device suspend/resume, and platform sleep
/// state entry.
pub struct SuspendManager {
    /// Registered device PM entries.
    devices: [DevicePmEntry; MAX_PM_DEVICES],
    /// Number of active device entries.
    device_count: usize,
    /// Registered suspend notifiers.
    notifiers: [SuspendNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Next unique device identifier.
    next_device_id: u32,
    /// Next registration order value.
    next_order: u32,
    /// Current suspend/resume state.
    state: SuspendState,
    /// Requested sleep state for the next suspend.
    target_state: SleepState,
    /// Cumulative statistics.
    stats: SuspendStats,
    /// Number of processes frozen in the current cycle.
    frozen_count: u32,
    /// Number of devices suspended in the current cycle.
    suspended_device_count: u32,
}

impl Default for SuspendManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SuspendManager {
    /// Create a new suspend manager in the running state.
    pub const fn new() -> Self {
        const DEV_INIT: DevicePmEntry = DevicePmEntry::new();
        const NOTIF_INIT: SuspendNotifier = SuspendNotifier {
            handler_id: 0,
            priority: 0,
            active: false,
        };
        Self {
            devices: [DEV_INIT; MAX_PM_DEVICES],
            device_count: 0,
            notifiers: [NOTIF_INIT; MAX_NOTIFIERS],
            notifier_count: 0,
            next_device_id: 1,
            next_order: 0,
            state: SuspendState::Running,
            target_state: SleepState::SuspendToRam,
            stats: SuspendStats {
                success_count: 0,
                fail_count: 0,
                last_suspend_ticks: 0,
                last_resume_ticks: 0,
                last_failed_device: 0,
                freeze_timeouts: 0,
            },
            frozen_count: 0,
            suspended_device_count: 0,
        }
    }

    /// Current suspend/resume lifecycle state.
    pub fn state(&self) -> SuspendState {
        self.state
    }

    /// Target sleep state for the next suspend.
    pub fn target_state(&self) -> SleepState {
        self.target_state
    }

    /// Set the target sleep state for the next suspend cycle.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if a suspend/resume cycle is in
    ///   progress.
    pub fn set_target_state(&mut self, state: SleepState) -> Result<()> {
        if self.state != SuspendState::Running {
            return Err(Error::Busy);
        }
        self.target_state = state;
        Ok(())
    }

    /// Cumulative suspend/resume statistics.
    pub fn stats(&self) -> &SuspendStats {
        &self.stats
    }

    // ---------------------------------------------------------------
    // Device PM registration
    // ---------------------------------------------------------------

    /// Register a device for power management callbacks.
    ///
    /// Returns the unique device identifier. Devices are
    /// suspended in reverse registration order and resumed in
    /// forward order.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the device list is full.
    /// - [`Error::InvalidArgument`] if `name` exceeds
    ///   [`MAX_DEVICE_NAME_LEN`].
    pub fn register_device(
        &mut self,
        name: &[u8],
        suspend_handler: u32,
        resume_handler: u32,
    ) -> Result<u32> {
        if name.len() > MAX_DEVICE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .devices
            .iter_mut()
            .find(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_device_id;
        self.next_device_id = self.next_device_id.wrapping_add(1);

        *slot = DevicePmEntry::new();
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        slot.suspend_handler_id = suspend_handler;
        slot.resume_handler_id = resume_handler;
        slot.active = true;
        slot.id = id;
        self.device_count += 1;
        Ok(id)
    }

    /// Unregister a device from power management.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active device has this `id`.
    /// - [`Error::Busy`] if a suspend/resume cycle is in
    ///   progress.
    pub fn unregister_device(&mut self, id: u32) -> Result<()> {
        if self.state != SuspendState::Running {
            return Err(Error::Busy);
        }
        let slot = self
            .devices
            .iter_mut()
            .find(|d| d.active && d.id == id)
            .ok_or(Error::NotFound)?;

        slot.active = false;
        self.device_count = self.device_count.saturating_sub(1);
        Ok(())
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    // ---------------------------------------------------------------
    // Notifier registration
    // ---------------------------------------------------------------

    /// Register a suspend notifier callback.
    ///
    /// Returns the slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the notifier list is full.
    pub fn register_notifier(&mut self, handler_id: u32, priority: i32) -> Result<usize> {
        let (idx, slot) = self
            .notifiers
            .iter_mut()
            .enumerate()
            .find(|(_, n)| !n.active)
            .ok_or(Error::OutOfMemory)?;

        slot.handler_id = handler_id;
        slot.priority = priority;
        slot.active = true;
        self.notifier_count += 1;
        Ok(idx)
    }

    /// Unregister a suspend notifier by slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the slot is not active.
    pub fn unregister_notifier(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_NOTIFIERS {
            return Err(Error::InvalidArgument);
        }
        if !self.notifiers[idx].active {
            return Err(Error::NotFound);
        }
        self.notifiers[idx].active = false;
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Suspend lifecycle
    // ---------------------------------------------------------------

    /// Begin the freeze phase: transition to
    /// [`SuspendState::Freezing`].
    ///
    /// Returns the list of notifier handler IDs to invoke for
    /// the [`SuspendNotifierEvent::PreFreeze`] event (sorted
    /// by descending priority).
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the system is not in
    ///   [`SuspendState::Running`].
    pub fn begin_freeze(&mut self) -> Result<FreezeToken> {
        if self.state != SuspendState::Running {
            return Err(Error::Busy);
        }
        self.state = SuspendState::Freezing;
        self.frozen_count = 0;
        self.suspended_device_count = 0;
        Ok(FreezeToken { _private: () })
    }

    /// Report that a process has been frozen.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Freezing
    ///   state.
    pub fn report_frozen(&mut self) -> Result<()> {
        if self.state != SuspendState::Freezing {
            return Err(Error::InvalidArgument);
        }
        self.frozen_count += 1;
        Ok(())
    }

    /// Report that a process failed to freeze within the
    /// timeout.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Freezing
    ///   state.
    pub fn report_freeze_timeout(&mut self) -> Result<()> {
        if self.state != SuspendState::Freezing {
            return Err(Error::InvalidArgument);
        }
        self.stats.freeze_timeouts += 1;
        Ok(())
    }

    /// Complete the freeze phase and begin suspending devices.
    ///
    /// Returns an iterator-like structure of device
    /// suspend handler IDs in reverse registration order.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Freezing
    ///   state.
    pub fn begin_device_suspend(&mut self) -> Result<DeviceSuspendList> {
        if self.state != SuspendState::Freezing {
            return Err(Error::InvalidArgument);
        }
        self.state = SuspendState::Suspended;

        // Collect active device IDs sorted by reverse
        // registration order (highest order first).
        let mut ids = [0u32; MAX_PM_DEVICES];
        let mut orders = [0u32; MAX_PM_DEVICES];
        let mut handlers = [0u32; MAX_PM_DEVICES];
        let mut count = 0usize;

        for dev in &self.devices {
            if dev.active && count < MAX_PM_DEVICES {
                ids[count] = dev.id;
                orders[count] = dev.order;
                handlers[count] = dev.suspend_handler_id;
                count += 1;
            }
        }

        // Simple insertion sort by order descending.
        for i in 1..count {
            let mut j = i;
            while j > 0 && orders[j] > orders[j - 1] {
                ids.swap(j, j - 1);
                orders.swap(j, j - 1);
                handlers.swap(j, j - 1);
                j -= 1;
            }
        }

        Ok(DeviceSuspendList {
            device_ids: ids,
            handler_ids: handlers,
            count,
        })
    }

    /// Report that a device was successfully suspended.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active device has this `id`.
    pub fn report_device_suspended(&mut self, id: u32) -> Result<()> {
        let dev = self
            .devices
            .iter_mut()
            .find(|d| d.active && d.id == id)
            .ok_or(Error::NotFound)?;
        dev.state = DevicePmState::Suspended;
        self.suspended_device_count += 1;
        Ok(())
    }

    /// Report that a device failed to suspend.
    ///
    /// Records the failure and marks the device as errored.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active device has this `id`.
    pub fn report_device_suspend_failed(&mut self, id: u32) -> Result<()> {
        let dev = self
            .devices
            .iter_mut()
            .find(|d| d.active && d.id == id)
            .ok_or(Error::NotFound)?;
        dev.state = DevicePmState::Error;
        self.stats.last_failed_device = id;
        self.stats.fail_count += 1;
        Ok(())
    }

    /// Enter the platform sleep state.
    ///
    /// This is the point of no return — the CPU will halt and
    /// the system enters the target sleep state. On wake, the
    /// caller transitions to the resume phase.
    ///
    /// Returns the target [`SleepState`] so the caller can
    /// invoke the appropriate HAL power entry point.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Suspended
    ///   state.
    pub fn enter_sleep(&self) -> Result<SleepState> {
        if self.state != SuspendState::Suspended {
            return Err(Error::InvalidArgument);
        }
        Ok(self.target_state)
    }

    // ---------------------------------------------------------------
    // Resume lifecycle
    // ---------------------------------------------------------------

    /// Begin the device resume phase after waking.
    ///
    /// Returns device resume handler IDs in forward registration
    /// order.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Suspended
    ///   state.
    pub fn begin_device_resume(&mut self) -> Result<DeviceResumeList> {
        if self.state != SuspendState::Suspended {
            return Err(Error::InvalidArgument);
        }
        self.state = SuspendState::Resuming;

        // Collect active device IDs sorted by forward
        // registration order (lowest order first).
        let mut ids = [0u32; MAX_PM_DEVICES];
        let mut orders = [0u32; MAX_PM_DEVICES];
        let mut handlers = [0u32; MAX_PM_DEVICES];
        let mut count = 0usize;

        for dev in &self.devices {
            if dev.active && count < MAX_PM_DEVICES {
                ids[count] = dev.id;
                orders[count] = dev.order;
                handlers[count] = dev.resume_handler_id;
                count += 1;
            }
        }

        // Insertion sort by order ascending.
        for i in 1..count {
            let mut j = i;
            while j > 0 && orders[j] < orders[j - 1] {
                ids.swap(j, j - 1);
                orders.swap(j, j - 1);
                handlers.swap(j, j - 1);
                j -= 1;
            }
        }

        Ok(DeviceResumeList {
            device_ids: ids,
            handler_ids: handlers,
            count,
        })
    }

    /// Report that a device was successfully resumed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active device has this `id`.
    pub fn report_device_resumed(&mut self, id: u32) -> Result<()> {
        let dev = self
            .devices
            .iter_mut()
            .find(|d| d.active && d.id == id)
            .ok_or(Error::NotFound)?;
        dev.state = DevicePmState::Active;
        Ok(())
    }

    /// Begin the thaw phase: transition to
    /// [`SuspendState::Thawing`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Resuming
    ///   state.
    pub fn begin_thaw(&mut self) -> Result<()> {
        if self.state != SuspendState::Resuming {
            return Err(Error::InvalidArgument);
        }
        self.state = SuspendState::Thawing;
        Ok(())
    }

    /// Complete the full suspend/resume cycle, returning to
    /// [`SuspendState::Running`].
    ///
    /// Records the suspend and resume durations for statistics.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if not in the Thawing
    ///   state.
    pub fn complete_resume(&mut self, suspend_ticks: u64, resume_ticks: u64) -> Result<()> {
        if self.state != SuspendState::Thawing {
            return Err(Error::InvalidArgument);
        }
        self.state = SuspendState::Running;
        self.stats.success_count += 1;
        self.stats.last_suspend_ticks = suspend_ticks;
        self.stats.last_resume_ticks = resume_ticks;
        Ok(())
    }

    /// Abort a suspend cycle and return to Running.
    ///
    /// Used when a device fails to suspend or a freeze timeout
    /// occurs. Resets all suspended devices back to Active.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if already in Running state.
    pub fn abort_suspend(&mut self) -> Result<()> {
        if self.state == SuspendState::Running {
            return Err(Error::InvalidArgument);
        }
        // Reset all suspended/errored devices to Active.
        for dev in &mut self.devices {
            if dev.active && dev.state != DevicePmState::Active {
                dev.state = DevicePmState::Active;
            }
        }
        self.state = SuspendState::Running;
        self.stats.fail_count += 1;
        Ok(())
    }

    /// Number of processes frozen in the current cycle.
    pub fn frozen_count(&self) -> u32 {
        self.frozen_count
    }

    /// Number of devices suspended in the current cycle.
    pub fn suspended_device_count(&self) -> u32 {
        self.suspended_device_count
    }

    /// Collect active notifier handler IDs sorted by priority.
    ///
    /// For suspend-path events (PreFreeze, PostFreeze,
    /// PreSuspend), higher priority notifiers are called first.
    /// The returned list is sorted by descending priority.
    pub fn notifier_handlers_suspend_order(&self) -> NotifierList {
        let mut handlers = [0u32; MAX_NOTIFIERS];
        let mut priorities = [0i32; MAX_NOTIFIERS];
        let mut count = 0usize;

        for n in &self.notifiers {
            if n.active && count < MAX_NOTIFIERS {
                handlers[count] = n.handler_id;
                priorities[count] = n.priority;
                count += 1;
            }
        }

        // Insertion sort descending by priority.
        for i in 1..count {
            let mut j = i;
            while j > 0 && priorities[j] > priorities[j - 1] {
                handlers.swap(j, j - 1);
                priorities.swap(j, j - 1);
                j -= 1;
            }
        }

        NotifierList {
            handler_ids: handlers,
            count,
        }
    }

    /// Collect active notifier handler IDs in resume order
    /// (ascending priority — opposite of suspend order).
    pub fn notifier_handlers_resume_order(&self) -> NotifierList {
        let mut handlers = [0u32; MAX_NOTIFIERS];
        let mut priorities = [0i32; MAX_NOTIFIERS];
        let mut count = 0usize;

        for n in &self.notifiers {
            if n.active && count < MAX_NOTIFIERS {
                handlers[count] = n.handler_id;
                priorities[count] = n.priority;
                count += 1;
            }
        }

        // Insertion sort ascending by priority.
        for i in 1..count {
            let mut j = i;
            while j > 0 && priorities[j] < priorities[j - 1] {
                handlers.swap(j, j - 1);
                priorities.swap(j, j - 1);
                j -= 1;
            }
        }

        NotifierList {
            handler_ids: handlers,
            count,
        }
    }
}

impl core::fmt::Debug for SuspendManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SuspendManager")
            .field("state", &self.state)
            .field("target_state", &self.target_state)
            .field("device_count", &self.device_count)
            .field("notifier_count", &self.notifier_count)
            .field("frozen_count", &self.frozen_count)
            .field("suspended_devices", &self.suspended_device_count)
            .field("stats", &self.stats)
            .finish()
    }
}

// -------------------------------------------------------------------
// Helper types returned by lifecycle methods
// -------------------------------------------------------------------

/// Opaque token proving that `begin_freeze()` succeeded.
///
/// Consumed by the caller to proceed with freezing processes.
#[derive(Debug)]
pub struct FreezeToken {
    _private: (),
}

/// Ordered list of device suspend handlers.
#[derive(Debug)]
pub struct DeviceSuspendList {
    /// Device IDs in reverse registration order.
    device_ids: [u32; MAX_PM_DEVICES],
    /// Corresponding suspend handler IDs.
    handler_ids: [u32; MAX_PM_DEVICES],
    /// Number of valid entries.
    count: usize,
}

impl DeviceSuspendList {
    /// Number of devices to suspend.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the device ID and handler ID at the given index.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn get(&self, index: usize) -> Option<(u32, u32)> {
        if index >= self.count {
            return None;
        }
        Some((self.device_ids[index], self.handler_ids[index]))
    }
}

/// Ordered list of device resume handlers.
#[derive(Debug)]
pub struct DeviceResumeList {
    /// Device IDs in forward registration order.
    device_ids: [u32; MAX_PM_DEVICES],
    /// Corresponding resume handler IDs.
    handler_ids: [u32; MAX_PM_DEVICES],
    /// Number of valid entries.
    count: usize,
}

impl DeviceResumeList {
    /// Number of devices to resume.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the device ID and handler ID at the given index.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn get(&self, index: usize) -> Option<(u32, u32)> {
        if index >= self.count {
            return None;
        }
        Some((self.device_ids[index], self.handler_ids[index]))
    }
}

/// Ordered list of notifier handler IDs.
#[derive(Debug)]
pub struct NotifierList {
    /// Handler IDs in priority order.
    handler_ids: [u32; MAX_NOTIFIERS],
    /// Number of valid entries.
    count: usize,
}

impl NotifierList {
    /// Number of notifiers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the handler ID at the given index.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn get(&self, index: usize) -> Option<u32> {
        if index >= self.count {
            return None;
        }
        Some(self.handler_ids[index])
    }
}
