// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power management suspend/resume framework.
//!
//! Provides the PM core infrastructure for managing system and
//! device power states. This module handles:
//!
//! - PM domain registration and hierarchy
//! - Device power state transitions (D0-D3)
//! - System sleep state management (S0-S5)
//! - Runtime PM (autosuspend/autoresume)
//! - PM QoS constraints
//! - Wake-up source tracking
//!
//! # Architecture
//!
//! ```text
//!  PmManager (system-wide)
//!    ├── PmDomain[] — power domains (groups of devices)
//!    │     ├── devices[] — devices in this domain
//!    │     └── PmDomainOps — domain-specific callbacks
//!    ├── PmDevice[] — individual device PM state
//!    │     ├── PmDeviceState (D0..D3cold)
//!    │     ├── RuntimePmState (active/suspended/resuming)
//!    │     └── WakeupSource — can-wake tracking
//!    ├── PmQosRequest[] — latency/throughput constraints
//!    └── PmTransition — orchestrates state changes
//! ```
//!
//! # Sleep States
//!
//! | State | Name | Description |
//! |-------|------|-------------|
//! | S0 | On | Fully running |
//! | S1 | Standby | CPU stopped, RAM refreshed |
//! | S2 | — | CPU powered off, RAM refreshed |
//! | S3 | Suspend-to-RAM | Everything off except RAM |
//! | S4 | Hibernate | State saved to disk |
//! | S5 | Off | Power off |
//!
//! Reference: Linux `drivers/base/power/`,
//! `include/linux/pm.h`, `include/linux/pm_runtime.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of PM devices.
const MAX_PM_DEVICES: usize = 128;

/// Maximum number of PM domains.
const MAX_PM_DOMAINS: usize = 16;

/// Maximum number of devices per domain.
const MAX_DEVICES_PER_DOMAIN: usize = 32;

/// Maximum PM device name length.
const MAX_DEVICE_NAME_LEN: usize = 64;

/// Maximum PM domain name length.
const MAX_DOMAIN_NAME_LEN: usize = 64;

/// Maximum number of PM QoS requests.
const MAX_QOS_REQUESTS: usize = 32;

/// Maximum QoS requester name length.
const MAX_QOS_NAME_LEN: usize = 32;

/// Maximum number of wakeup sources.
const MAX_WAKEUP_SOURCES: usize = 64;

/// Maximum wakeup source name length.
const MAX_WAKEUP_NAME_LEN: usize = 64;

/// Maximum number of PM notifier callbacks.
const MAX_PM_NOTIFIERS: usize = 16;

/// Maximum PM notifier name length.
const MAX_NOTIFIER_NAME_LEN: usize = 32;

/// Default autosuspend delay in milliseconds.
const DEFAULT_AUTOSUSPEND_DELAY_MS: u64 = 2000;

// -------------------------------------------------------------------
// PmDeviceState — ACPI D-states
// -------------------------------------------------------------------

/// Device power state (ACPI D-states).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PmDeviceState {
    /// D0 — fully operational.
    D0,
    /// D1 — light sleep (device-specific).
    D1,
    /// D2 — deeper sleep (device-specific).
    D2,
    /// D3hot — software-visible off, power maintained.
    D3Hot,
    /// D3cold — power removed.
    D3Cold,
}

impl PmDeviceState {
    /// Return the numeric D-state index.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::D0 => 0,
            Self::D1 => 1,
            Self::D2 => 2,
            Self::D3Hot => 3,
            Self::D3Cold => 4,
        }
    }

    /// Return whether the device is in a low-power state.
    pub const fn is_low_power(self) -> bool {
        !matches!(self, Self::D0)
    }
}

// -------------------------------------------------------------------
// SystemSleepState — ACPI S-states
// -------------------------------------------------------------------

/// System sleep state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemSleepState {
    /// S0 — fully on (working).
    S0On,
    /// S1 — standby (CPU stopped).
    S1Standby,
    /// S2 — CPU off, RAM refreshed.
    S2Sleep,
    /// S3 — suspend to RAM.
    S3SuspendToRam,
    /// S4 — hibernate (suspend to disk).
    S4Hibernate,
    /// S5 — soft off.
    S5SoftOff,
}

impl SystemSleepState {
    /// Return the numeric S-state index.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::S0On => 0,
            Self::S1Standby => 1,
            Self::S2Sleep => 2,
            Self::S3SuspendToRam => 3,
            Self::S4Hibernate => 4,
            Self::S5SoftOff => 5,
        }
    }
}

// -------------------------------------------------------------------
// RuntimePmState
// -------------------------------------------------------------------

/// Runtime PM state for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePmState {
    /// Device is active and in use.
    Active,
    /// Device is transitioning to suspended.
    Suspending,
    /// Device is in low-power state.
    Suspended,
    /// Device is transitioning to active.
    Resuming,
    /// Runtime PM is disabled for this device.
    Disabled,
}

// -------------------------------------------------------------------
// PmTransitionPhase
// -------------------------------------------------------------------

/// Phase within a system PM transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmTransitionPhase {
    /// Before freezing processes.
    Prepare,
    /// Devices being suspended.
    Suspend,
    /// Late suspend (after interrupts disabled).
    SuspendLate,
    /// Final suspend step (noirq).
    SuspendNoirq,
    /// First resume step (noirq).
    ResumeNoirq,
    /// Early resume (before interrupts enabled).
    ResumeEarly,
    /// Devices being resumed.
    Resume,
    /// After thawing processes.
    Complete,
}

// -------------------------------------------------------------------
// PmQosType
// -------------------------------------------------------------------

/// Type of PM QoS constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmQosType {
    /// CPU latency constraint (microseconds).
    CpuLatency,
    /// Network latency constraint (microseconds).
    NetworkLatency,
    /// Memory bandwidth (MB/s).
    MemoryBandwidth,
    /// Device-specific constraint.
    DeviceLatency,
}

// -------------------------------------------------------------------
// PmQosRequest
// -------------------------------------------------------------------

/// A PM QoS constraint request.
#[derive(Clone, Copy)]
pub struct PmQosRequest {
    /// Requester name.
    name: [u8; MAX_QOS_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// QoS type.
    qos_type: PmQosType,
    /// Requested value (interpretation depends on type).
    value: u64,
    /// Whether this request is active.
    active: bool,
    /// Device ID this applies to (0 = system-wide).
    device_id: u64,
}

impl PmQosRequest {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_QOS_NAME_LEN],
            name_len: 0,
            qos_type: PmQosType::CpuLatency,
            value: u64::MAX,
            active: false,
            device_id: 0,
        }
    }

    /// Return the requester name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the QoS type.
    pub const fn qos_type(&self) -> PmQosType {
        self.qos_type
    }

    /// Return the requested value.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

impl core::fmt::Debug for PmQosRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmQosRequest")
            .field("type", &self.qos_type)
            .field("value", &self.value)
            .finish()
    }
}

// -------------------------------------------------------------------
// WakeupSource
// -------------------------------------------------------------------

/// A device or subsystem that can wake the system from sleep.
#[derive(Clone, Copy)]
pub struct WakeupSource {
    /// Source name.
    name: [u8; MAX_WAKEUP_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique ID.
    source_id: u64,
    /// Associated device ID (0 = not device-specific).
    device_id: u64,
    /// Whether the source is currently enabled.
    enabled: bool,
    /// Whether this slot is active.
    active: bool,
    /// Number of times this source has triggered a wakeup.
    wakeup_count: u64,
    /// Last wakeup timestamp (monotonic nanoseconds).
    last_wakeup_ns: u64,
    /// Whether the source is currently holding a wakeup vote.
    event_pending: bool,
    /// Total time this source prevented sleep (nanoseconds).
    prevent_sleep_time_ns: u64,
}

impl WakeupSource {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_WAKEUP_NAME_LEN],
            name_len: 0,
            source_id: 0,
            device_id: 0,
            enabled: false,
            active: false,
            wakeup_count: 0,
            last_wakeup_ns: 0,
            event_pending: false,
            prevent_sleep_time_ns: 0,
        }
    }

    /// Return the source name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the source ID.
    pub const fn source_id(&self) -> u64 {
        self.source_id
    }

    /// Return whether the source is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the wakeup count.
    pub const fn wakeup_count(&self) -> u64 {
        self.wakeup_count
    }

    /// Return whether an event is pending.
    pub const fn is_event_pending(&self) -> bool {
        self.event_pending
    }

    /// Return the total prevent-sleep time in nanoseconds.
    pub const fn prevent_sleep_time_ns(&self) -> u64 {
        self.prevent_sleep_time_ns
    }
}

impl core::fmt::Debug for WakeupSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WakeupSource")
            .field("id", &self.source_id)
            .field("enabled", &self.enabled)
            .field("wakeup_count", &self.wakeup_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// PmDevice — per-device PM state
// -------------------------------------------------------------------

/// Per-device power management state.
#[derive(Clone, Copy)]
pub struct PmDevice {
    /// Device name.
    name: [u8; MAX_DEVICE_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique device ID.
    device_id: u64,
    /// Current power state.
    power_state: PmDeviceState,
    /// Runtime PM state.
    runtime_state: RuntimePmState,
    /// PM domain this device belongs to (0 = none).
    domain_id: u64,
    /// Whether runtime PM is enabled.
    runtime_pm_enabled: bool,
    /// Autosuspend delay in milliseconds.
    autosuspend_delay_ms: u64,
    /// Last activity timestamp (monotonic ns).
    last_busy_ns: u64,
    /// Usage count (device in-use counter).
    usage_count: i32,
    /// Child count (active children).
    child_count: u32,
    /// Whether the device can wake the system.
    can_wakeup: bool,
    /// Whether wakeup is enabled for this device.
    wakeup_enabled: bool,
    /// Wakeup source ID (0 = none).
    wakeup_source_id: u64,
    /// Whether this slot is active.
    active: bool,
    /// Suspend count (how many times suspended).
    suspend_count: u64,
    /// Resume count.
    resume_count: u64,
}

impl PmDevice {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_DEVICE_NAME_LEN],
            name_len: 0,
            device_id: 0,
            power_state: PmDeviceState::D0,
            runtime_state: RuntimePmState::Disabled,
            domain_id: 0,
            runtime_pm_enabled: false,
            autosuspend_delay_ms: DEFAULT_AUTOSUSPEND_DELAY_MS,
            last_busy_ns: 0,
            usage_count: 0,
            child_count: 0,
            can_wakeup: false,
            wakeup_enabled: false,
            wakeup_source_id: 0,
            active: false,
            suspend_count: 0,
            resume_count: 0,
        }
    }

    /// Return the device name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the device ID.
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Return the current power state.
    pub const fn power_state(&self) -> PmDeviceState {
        self.power_state
    }

    /// Return the runtime PM state.
    pub const fn runtime_state(&self) -> RuntimePmState {
        self.runtime_state
    }

    /// Return whether runtime PM is enabled.
    pub const fn is_runtime_pm_enabled(&self) -> bool {
        self.runtime_pm_enabled
    }

    /// Return the usage count.
    pub const fn usage_count(&self) -> i32 {
        self.usage_count
    }

    /// Return whether the device can wake the system.
    pub const fn can_wakeup(&self) -> bool {
        self.can_wakeup
    }
}

impl core::fmt::Debug for PmDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmDevice")
            .field("id", &self.device_id)
            .field("power_state", &self.power_state)
            .field("runtime_state", &self.runtime_state)
            .finish()
    }
}

// -------------------------------------------------------------------
// PmDomain
// -------------------------------------------------------------------

/// A power domain grouping related devices.
#[derive(Clone, Copy)]
pub struct PmDomain {
    /// Domain name.
    name: [u8; MAX_DOMAIN_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique domain ID.
    domain_id: u64,
    /// Device IDs in this domain.
    device_ids: [u64; MAX_DEVICES_PER_DOMAIN],
    /// Number of devices.
    device_count: usize,
    /// Parent domain ID (0 = root).
    parent_id: u64,
    /// Current power state of the domain.
    power_state: PmDeviceState,
    /// Whether this domain is active.
    active: bool,
    /// Whether the domain is currently suspended.
    suspended: bool,
    /// Performance state (0 = highest).
    performance_state: u32,
}

impl PmDomain {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_DOMAIN_NAME_LEN],
            name_len: 0,
            domain_id: 0,
            device_ids: [0u64; MAX_DEVICES_PER_DOMAIN],
            device_count: 0,
            parent_id: 0,
            power_state: PmDeviceState::D0,
            active: false,
            suspended: false,
            performance_state: 0,
        }
    }

    /// Return the domain name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the domain ID.
    pub const fn domain_id(&self) -> u64 {
        self.domain_id
    }

    /// Return the number of devices.
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return the current power state.
    pub const fn power_state(&self) -> PmDeviceState {
        self.power_state
    }

    /// Return whether the domain is suspended.
    pub const fn is_suspended(&self) -> bool {
        self.suspended
    }
}

impl core::fmt::Debug for PmDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmDomain")
            .field("id", &self.domain_id)
            .field("devices", &self.device_count)
            .field("power_state", &self.power_state)
            .finish()
    }
}

// -------------------------------------------------------------------
// PmNotifier callback
// -------------------------------------------------------------------

/// PM event notification callback.
pub type PmNotifierFn = fn(PmTransitionPhase, SystemSleepState);

/// A registered PM notifier.
#[derive(Clone, Copy)]
struct PmNotifier {
    /// Notifier name.
    name: [u8; MAX_NOTIFIER_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Callback function.
    callback: PmNotifierFn,
    /// Priority (lower = called first).
    priority: u32,
    /// Whether this slot is active.
    active: bool,
}

/// Default PM notifier callback.
fn default_pm_notifier(_phase: PmTransitionPhase, _state: SystemSleepState) {}

impl PmNotifier {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NOTIFIER_NAME_LEN],
            name_len: 0,
            callback: default_pm_notifier,
            priority: 128,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// PmStats
// -------------------------------------------------------------------

/// Power management statistics.
#[derive(Debug, Clone, Copy)]
pub struct PmStats {
    /// Total system suspend attempts.
    pub suspend_attempts: u64,
    /// Successful system suspends.
    pub suspend_successes: u64,
    /// Failed system suspends.
    pub suspend_failures: u64,
    /// Total runtime suspends across all devices.
    pub runtime_suspends: u64,
    /// Total runtime resumes across all devices.
    pub runtime_resumes: u64,
    /// Total wakeup events.
    pub wakeup_events: u64,
    /// Last suspend duration (nanoseconds).
    pub last_suspend_duration_ns: u64,
    /// Last resume duration (nanoseconds).
    pub last_resume_duration_ns: u64,
}

impl PmStats {
    const fn new() -> Self {
        Self {
            suspend_attempts: 0,
            suspend_successes: 0,
            suspend_failures: 0,
            runtime_suspends: 0,
            runtime_resumes: 0,
            wakeup_events: 0,
            last_suspend_duration_ns: 0,
            last_resume_duration_ns: 0,
        }
    }
}

// -------------------------------------------------------------------
// PmManager
// -------------------------------------------------------------------

/// System-wide power management manager.
pub struct PmManager {
    /// Registered PM devices.
    devices: [PmDevice; MAX_PM_DEVICES],
    /// Number of active devices.
    device_count: usize,
    /// Next device ID.
    next_device_id: u64,
    /// PM domains.
    domains: [PmDomain; MAX_PM_DOMAINS],
    /// Number of active domains.
    domain_count: usize,
    /// Next domain ID.
    next_domain_id: u64,
    /// QoS requests.
    qos_requests: [PmQosRequest; MAX_QOS_REQUESTS],
    /// Number of active QoS requests.
    qos_count: usize,
    /// Wakeup sources.
    wakeup_sources: [WakeupSource; MAX_WAKEUP_SOURCES],
    /// Number of active wakeup sources.
    wakeup_count: usize,
    /// Next wakeup source ID.
    next_wakeup_id: u64,
    /// PM notifiers.
    notifiers: [PmNotifier; MAX_PM_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Current system sleep state.
    system_state: SystemSleepState,
    /// Current transition phase (None = not transitioning).
    transition_phase: Option<PmTransitionPhase>,
    /// Statistics.
    stats: PmStats,
    /// Global wakeup count (incremented on each wakeup event).
    global_wakeup_count: u64,
    /// Current monotonic timestamp (nanoseconds).
    current_ns: u64,
}

impl Default for PmManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PmManager {
    /// Create a new PM manager.
    pub const fn new() -> Self {
        Self {
            devices: [const { PmDevice::empty() }; MAX_PM_DEVICES],
            device_count: 0,
            next_device_id: 1,
            domains: [const { PmDomain::empty() }; MAX_PM_DOMAINS],
            domain_count: 0,
            next_domain_id: 1,
            qos_requests: [const { PmQosRequest::empty() }; MAX_QOS_REQUESTS],
            qos_count: 0,
            wakeup_sources: [const { WakeupSource::empty() }; MAX_WAKEUP_SOURCES],
            wakeup_count: 0,
            next_wakeup_id: 1,
            notifiers: [const { PmNotifier::empty() }; MAX_PM_NOTIFIERS],
            notifier_count: 0,
            system_state: SystemSleepState::S0On,
            transition_phase: None,
            stats: PmStats::new(),
            global_wakeup_count: 0,
            current_ns: 0,
        }
    }

    /// Register a PM device.
    pub fn register_device(&mut self, name: &[u8], can_wakeup: bool) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_DEVICE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_free_device_slot()?;
        let id = self.next_device_id;
        self.next_device_id += 1;

        self.devices[slot].name[..name.len()].copy_from_slice(name);
        self.devices[slot].name_len = name.len();
        self.devices[slot].device_id = id;
        self.devices[slot].power_state = PmDeviceState::D0;
        self.devices[slot].runtime_state = RuntimePmState::Disabled;
        self.devices[slot].can_wakeup = can_wakeup;
        self.devices[slot].wakeup_enabled = false;
        self.devices[slot].active = true;
        self.devices[slot].usage_count = 0;
        self.devices[slot].child_count = 0;
        self.devices[slot].suspend_count = 0;
        self.devices[slot].resume_count = 0;
        self.device_count += 1;
        Ok(id)
    }

    fn find_free_device_slot(&self) -> Result<usize> {
        for i in 0..MAX_PM_DEVICES {
            if !self.devices[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_device_index(&self, device_id: u64) -> Option<usize> {
        (0..MAX_PM_DEVICES)
            .find(|&i| self.devices[i].active && self.devices[i].device_id == device_id)
    }

    /// Unregister a PM device.
    pub fn unregister_device(&mut self, device_id: u64) -> Result<()> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].active = false;
        self.device_count -= 1;
        Ok(())
    }

    /// Get a reference to a PM device.
    pub fn device(&self, device_id: u64) -> Option<&PmDevice> {
        self.find_device_index(device_id)
            .map(|idx| &self.devices[idx])
    }

    /// Enable runtime PM for a device.
    pub fn pm_runtime_enable(&mut self, device_id: u64) -> Result<()> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].runtime_pm_enabled = true;
        self.devices[idx].runtime_state = RuntimePmState::Active;
        Ok(())
    }

    /// Disable runtime PM for a device.
    pub fn pm_runtime_disable(&mut self, device_id: u64) -> Result<()> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].runtime_pm_enabled = false;
        self.devices[idx].runtime_state = RuntimePmState::Disabled;
        Ok(())
    }

    /// Increment usage count (prevent suspend).
    pub fn pm_runtime_get(&mut self, device_id: u64) -> Result<i32> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].usage_count += 1;

        // If suspended, trigger resume.
        if self.devices[idx].runtime_state == RuntimePmState::Suspended {
            self.devices[idx].runtime_state = RuntimePmState::Resuming;
            self.devices[idx].runtime_state = RuntimePmState::Active;
            self.devices[idx].resume_count += 1;
            self.stats.runtime_resumes += 1;
        }
        Ok(self.devices[idx].usage_count)
    }

    /// Decrement usage count (allow suspend).
    pub fn pm_runtime_put(&mut self, device_id: u64) -> Result<i32> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        if self.devices[idx].usage_count <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].usage_count -= 1;
        self.devices[idx].last_busy_ns = self.current_ns;
        Ok(self.devices[idx].usage_count)
    }

    /// Runtime suspend a device.
    pub fn pm_runtime_suspend(&mut self, device_id: u64) -> Result<()> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        if !self.devices[idx].runtime_pm_enabled {
            return Err(Error::PermissionDenied);
        }
        if self.devices[idx].usage_count > 0 {
            return Err(Error::Busy);
        }
        if self.devices[idx].child_count > 0 {
            return Err(Error::Busy);
        }
        self.devices[idx].runtime_state = RuntimePmState::Suspending;
        self.devices[idx].power_state = PmDeviceState::D3Hot;
        self.devices[idx].runtime_state = RuntimePmState::Suspended;
        self.devices[idx].suspend_count += 1;
        self.stats.runtime_suspends += 1;
        Ok(())
    }

    /// Runtime resume a device.
    pub fn pm_runtime_resume(&mut self, device_id: u64) -> Result<()> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        if self.devices[idx].runtime_state != RuntimePmState::Suspended {
            return Ok(()); // Already active.
        }
        self.devices[idx].runtime_state = RuntimePmState::Resuming;
        self.devices[idx].power_state = PmDeviceState::D0;
        self.devices[idx].runtime_state = RuntimePmState::Active;
        self.devices[idx].resume_count += 1;
        self.stats.runtime_resumes += 1;
        Ok(())
    }

    /// Set the autosuspend delay for a device.
    pub fn set_autosuspend_delay(&mut self, device_id: u64, delay_ms: u64) -> Result<()> {
        let idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        self.devices[idx].autosuspend_delay_ms = delay_ms;
        Ok(())
    }

    /// Check devices for autosuspend eligibility.
    ///
    /// Called periodically from the timer tick. Suspends devices
    /// that have been idle longer than their autosuspend delay.
    pub fn check_autosuspend(&mut self) {
        for i in 0..MAX_PM_DEVICES {
            if !self.devices[i].active
                || !self.devices[i].runtime_pm_enabled
                || self.devices[i].runtime_state != RuntimePmState::Active
                || self.devices[i].usage_count > 0
                || self.devices[i].child_count > 0
            {
                continue;
            }
            let delay_ns = self.devices[i].autosuspend_delay_ms * 1_000_000;
            let idle_ns = self.current_ns.saturating_sub(self.devices[i].last_busy_ns);
            if idle_ns >= delay_ns {
                self.devices[i].runtime_state = RuntimePmState::Suspending;
                self.devices[i].power_state = PmDeviceState::D3Hot;
                self.devices[i].runtime_state = RuntimePmState::Suspended;
                self.devices[i].suspend_count += 1;
                self.stats.runtime_suspends += 1;
            }
        }
    }

    /// Register a PM domain.
    pub fn register_domain(&mut self, name: &[u8], parent_id: u64) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_DOMAIN_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.domain_count >= MAX_PM_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.find_free_domain_slot()?;
        let id = self.next_domain_id;
        self.next_domain_id += 1;

        self.domains[slot].name[..name.len()].copy_from_slice(name);
        self.domains[slot].name_len = name.len();
        self.domains[slot].domain_id = id;
        self.domains[slot].parent_id = parent_id;
        self.domains[slot].device_count = 0;
        self.domains[slot].power_state = PmDeviceState::D0;
        self.domains[slot].active = true;
        self.domains[slot].suspended = false;
        self.domain_count += 1;
        Ok(id)
    }

    fn find_free_domain_slot(&self) -> Result<usize> {
        for i in 0..MAX_PM_DOMAINS {
            if !self.domains[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_domain_index(&self, domain_id: u64) -> Option<usize> {
        (0..MAX_PM_DOMAINS)
            .find(|&i| self.domains[i].active && self.domains[i].domain_id == domain_id)
    }

    /// Add a device to a domain.
    pub fn add_device_to_domain(&mut self, domain_id: u64, device_id: u64) -> Result<()> {
        let dom_idx = self.find_domain_index(domain_id).ok_or(Error::NotFound)?;
        let dev_idx = self.find_device_index(device_id).ok_or(Error::NotFound)?;
        let dc = self.domains[dom_idx].device_count;
        if dc >= MAX_DEVICES_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }
        self.domains[dom_idx].device_ids[dc] = device_id;
        self.domains[dom_idx].device_count += 1;
        self.devices[dev_idx].domain_id = domain_id;
        Ok(())
    }

    /// Register a wakeup source.
    pub fn register_wakeup_source(&mut self, name: &[u8], device_id: u64) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_WAKEUP_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.wakeup_count >= MAX_WAKEUP_SOURCES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.find_free_wakeup_slot()?;
        let id = self.next_wakeup_id;
        self.next_wakeup_id += 1;

        self.wakeup_sources[slot].name[..name.len()].copy_from_slice(name);
        self.wakeup_sources[slot].name_len = name.len();
        self.wakeup_sources[slot].source_id = id;
        self.wakeup_sources[slot].device_id = device_id;
        self.wakeup_sources[slot].enabled = true;
        self.wakeup_sources[slot].active = true;
        self.wakeup_sources[slot].wakeup_count = 0;
        self.wakeup_sources[slot].event_pending = false;
        self.wakeup_count += 1;
        Ok(id)
    }

    fn find_free_wakeup_slot(&self) -> Result<usize> {
        for i in 0..MAX_WAKEUP_SOURCES {
            if !self.wakeup_sources[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_wakeup_index(&self, source_id: u64) -> Option<usize> {
        (0..MAX_WAKEUP_SOURCES).find(|&i| {
            self.wakeup_sources[i].active && self.wakeup_sources[i].source_id == source_id
        })
    }

    /// Signal a wakeup event from a source.
    pub fn wakeup_event(&mut self, source_id: u64) -> Result<()> {
        let idx = self.find_wakeup_index(source_id).ok_or(Error::NotFound)?;
        if !self.wakeup_sources[idx].enabled {
            return Err(Error::PermissionDenied);
        }
        self.wakeup_sources[idx].wakeup_count += 1;
        self.wakeup_sources[idx].last_wakeup_ns = self.current_ns;
        self.wakeup_sources[idx].event_pending = true;
        self.global_wakeup_count += 1;
        self.stats.wakeup_events += 1;
        Ok(())
    }

    /// Clear the pending event flag on a wakeup source.
    pub fn wakeup_event_clear(&mut self, source_id: u64) -> Result<()> {
        let idx = self.find_wakeup_index(source_id).ok_or(Error::NotFound)?;
        self.wakeup_sources[idx].event_pending = false;
        Ok(())
    }

    /// Check whether any wakeup event is pending.
    pub fn has_pending_wakeup(&self) -> bool {
        (0..MAX_WAKEUP_SOURCES)
            .any(|i| self.wakeup_sources[i].active && self.wakeup_sources[i].event_pending)
    }

    /// Add a PM QoS request.
    pub fn add_qos_request(
        &mut self,
        name: &[u8],
        qos_type: PmQosType,
        value: u64,
        device_id: u64,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_QOS_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.qos_count >= MAX_QOS_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.qos_count;
        self.qos_requests[idx].name[..name.len()].copy_from_slice(name);
        self.qos_requests[idx].name_len = name.len();
        self.qos_requests[idx].qos_type = qos_type;
        self.qos_requests[idx].value = value;
        self.qos_requests[idx].device_id = device_id;
        self.qos_requests[idx].active = true;
        self.qos_count += 1;
        Ok(())
    }

    /// Get the effective QoS value for a given type.
    ///
    /// Returns the minimum (most restrictive) value across all
    /// active requests of that type.
    pub fn effective_qos(&self, qos_type: PmQosType) -> u64 {
        let mut min_val = u64::MAX;
        for i in 0..self.qos_count {
            if self.qos_requests[i].active && self.qos_requests[i].qos_type == qos_type {
                if self.qos_requests[i].value < min_val {
                    min_val = self.qos_requests[i].value;
                }
            }
        }
        min_val
    }

    /// Register a PM transition notifier.
    pub fn register_notifier(
        &mut self,
        name: &[u8],
        callback: PmNotifierFn,
        priority: u32,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_NOTIFIER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.notifier_count >= MAX_PM_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.notifier_count;
        self.notifiers[idx].name[..name.len()].copy_from_slice(name);
        self.notifiers[idx].name_len = name.len();
        self.notifiers[idx].callback = callback;
        self.notifiers[idx].priority = priority;
        self.notifiers[idx].active = true;
        self.notifier_count += 1;
        Ok(())
    }

    /// Notify all PM notifiers of a transition phase.
    fn notify_all(&self, phase: PmTransitionPhase, target: SystemSleepState) {
        // Call in priority order (lower first). Simple linear
        // scan since MAX_PM_NOTIFIERS is small.
        for priority in 0..=255u32 {
            for i in 0..self.notifier_count {
                if self.notifiers[i].active && self.notifiers[i].priority == priority {
                    (self.notifiers[i].callback)(phase, target);
                }
            }
        }
    }

    /// Initiate a system suspend to the given sleep state.
    ///
    /// Orchestrates the full suspend sequence: prepare → suspend
    /// devices → enter sleep. Returns error if any phase fails.
    pub fn suspend_enter(&mut self, target: SystemSleepState) -> Result<()> {
        if self.transition_phase.is_some() {
            return Err(Error::Busy);
        }
        self.stats.suspend_attempts += 1;

        // Prepare phase.
        self.transition_phase = Some(PmTransitionPhase::Prepare);
        self.notify_all(PmTransitionPhase::Prepare, target);

        // Check for pending wakeups before proceeding.
        if self.has_pending_wakeup() {
            self.transition_phase = None;
            self.stats.suspend_failures += 1;
            return Err(Error::Interrupted);
        }

        // Suspend phase — suspend all devices.
        self.transition_phase = Some(PmTransitionPhase::Suspend);
        self.notify_all(PmTransitionPhase::Suspend, target);
        self.suspend_all_devices()?;

        // Enter target state.
        self.system_state = target;
        self.stats.suspend_successes += 1;

        // Resume happens when hardware wakes us.
        // (In real kernel, CPU is halted here.)
        Ok(())
    }

    /// Resume from a system sleep state.
    pub fn resume(&mut self) -> Result<()> {
        if self.system_state == SystemSleepState::S0On {
            return Ok(());
        }
        let from_state = self.system_state;

        self.transition_phase = Some(PmTransitionPhase::Resume);
        self.notify_all(PmTransitionPhase::Resume, from_state);
        self.resume_all_devices();

        self.transition_phase = Some(PmTransitionPhase::Complete);
        self.notify_all(PmTransitionPhase::Complete, from_state);

        self.system_state = SystemSleepState::S0On;
        self.transition_phase = None;
        Ok(())
    }

    /// Suspend all registered devices (reverse order).
    fn suspend_all_devices(&mut self) -> Result<()> {
        // Iterate in reverse registration order.
        let count = self.device_count;
        for i in (0..MAX_PM_DEVICES).rev() {
            if !self.devices[i].active {
                continue;
            }
            self.devices[i].power_state = PmDeviceState::D3Hot;
            self.devices[i].suspend_count += 1;
            if count == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Resume all devices (forward order).
    fn resume_all_devices(&mut self) {
        for i in 0..MAX_PM_DEVICES {
            if !self.devices[i].active {
                continue;
            }
            if self.devices[i].power_state != PmDeviceState::D0 {
                self.devices[i].power_state = PmDeviceState::D0;
                self.devices[i].resume_count += 1;
            }
        }
    }

    /// Update the current timestamp.
    pub fn update_timestamp(&mut self, ns: u64) {
        self.current_ns = ns;
    }

    /// Return the current system sleep state.
    pub const fn system_state(&self) -> SystemSleepState {
        self.system_state
    }

    /// Return the current transition phase.
    pub const fn transition_phase(&self) -> Option<PmTransitionPhase> {
        self.transition_phase
    }

    /// Return PM statistics.
    pub const fn stats(&self) -> &PmStats {
        &self.stats
    }

    /// Return the device count.
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return the domain count.
    pub const fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Return the global wakeup count.
    pub const fn global_wakeup_count(&self) -> u64 {
        self.global_wakeup_count
    }

    /// Get a wakeup source by ID.
    pub fn wakeup_source(&self, source_id: u64) -> Option<&WakeupSource> {
        self.find_wakeup_index(source_id)
            .map(|idx| &self.wakeup_sources[idx])
    }

    /// Get a domain by ID.
    pub fn domain(&self, domain_id: u64) -> Option<&PmDomain> {
        self.find_domain_index(domain_id)
            .map(|idx| &self.domains[idx])
    }
}
