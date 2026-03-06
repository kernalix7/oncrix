// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock event device framework.
//!
//! Manages timer hardware that generates interrupts at programmed times.
//! Clock event devices are the low-level substrate that higher-level
//! timing subsystems (hrtimers, tick scheduling, dynamic tick) build on.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                   ClockEventSubsystem                            │
//! │                                                                  │
//! │  [ClockEventDevice; MAX_DEVICES]  — registered timer hardware    │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  ClockEventDevice                                          │  │
//! │  │    name, rating, features                                  │  │
//! │  │    EventMode (Periodic / OneShot / Shutdown)                │  │
//! │  │    ClockEventState (lifecycle)                              │  │
//! │  │    min_delta_ns / max_delta_ns — programming range          │  │
//! │  │    next_event_ns — next armed expiry                       │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  per-CPU assignment: [Option<usize>; MAX_CPUS]                   │
//! │  ClockEventStats — global counters                               │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Device Selection
//!
//! Devices have a `rating` (0-400). The scheduler picks the highest-rated
//! device for each CPU. Devices with `Features::ONESHOT` support dynamic
//! tick (tickless idle).
//!
//! # Reference
//!
//! Linux `kernel/time/clockevents.c`, `include/linux/clockchips.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum clock event devices in the system.
const MAX_DEVICES: usize = 16;

/// Maximum CPUs supported for per-CPU device assignment.
const MAX_CPUS: usize = 64;

/// Maximum device name length.
const MAX_NAME_LEN: usize = 32;

/// Minimum acceptable device rating.
const MIN_RATING: u32 = 1;

/// Maximum device rating.
const MAX_RATING: u32 = 400;

/// Default minimum delta (1 microsecond in nanoseconds).
const DEFAULT_MIN_DELTA_NS: u64 = 1_000;

/// Default maximum delta (1 second in nanoseconds).
const DEFAULT_MAX_DELTA_NS: u64 = 1_000_000_000;

// ── EventMode ───────────────────────────────────────────────────────────────

/// Operating mode of a clock event device.
///
/// Determines how the hardware generates interrupts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventMode {
    /// Device generates periodic interrupts at a fixed rate.
    Periodic,
    /// Device generates a single interrupt at a programmed time,
    /// then stops until re-armed.
    OneShot,
    /// Device is shut down and generates no interrupts.
    Shutdown,
}

impl Default for EventMode {
    fn default() -> Self {
        Self::Shutdown
    }
}

// ── ClockEventState ─────────────────────────────────────────────────────────

/// Lifecycle state of a clock event device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockEventState {
    /// Slot is free.
    Free,
    /// Device is registered but not yet started.
    Registered,
    /// Device is actively generating events.
    Active,
    /// Device is suspended (e.g., during CPU idle).
    Suspended,
    /// Device is being removed.
    Detached,
}

impl Default for ClockEventState {
    fn default() -> Self {
        Self::Free
    }
}

// ── Features ────────────────────────────────────────────────────────────────

/// Feature flags for a clock event device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features(u32);

impl Features {
    /// No special features.
    pub const NONE: Self = Self(0);
    /// Device supports periodic mode.
    pub const PERIODIC: Self = Self(1 << 0);
    /// Device supports one-shot mode.
    pub const ONESHOT: Self = Self(1 << 1);
    /// Device is per-CPU (not shared).
    pub const PERCPU: Self = Self(1 << 2);
    /// Device supports stopping in C3-type idle states.
    pub const C3STOP: Self = Self(1 << 3);

    /// Create features from a raw value.
    pub const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the raw bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if a feature is present.
    pub const fn contains(self, other: Features) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two feature sets.
    pub const fn union(self, other: Features) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for Features {
    fn default() -> Self {
        Self::NONE
    }
}

// ── ClockEventDevice ────────────────────────────────────────────────────────

/// A single clock event device (timer hardware).
///
/// Represents a piece of hardware capable of generating interrupts
/// at programmed times. Examples: HPET, LAPIC timer, ARM arch timer.
#[derive(Debug, Clone, Copy)]
pub struct ClockEventDevice {
    /// Device identifier.
    pub id: u64,
    /// Human-readable name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Device quality rating (higher = preferred).
    pub rating: u32,
    /// Feature flags.
    pub features: Features,
    /// Current operating mode.
    pub mode: EventMode,
    /// Lifecycle state.
    pub state: ClockEventState,
    /// Minimum programmable delta in nanoseconds.
    pub min_delta_ns: u64,
    /// Maximum programmable delta in nanoseconds.
    pub max_delta_ns: u64,
    /// Next event expiry in nanoseconds since boot
    /// (0 if not armed).
    pub next_event_ns: u64,
    /// Frequency in Hz (0 if not calibrated).
    pub freq_hz: u64,
    /// CPU this device is bound to (u32::MAX if unbound).
    pub bound_cpu: u32,
    /// Total events generated since registration.
    pub event_count: u64,
    /// Total reprogram operations.
    pub reprogram_count: u64,
}

impl Default for ClockEventDevice {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            rating: 0,
            features: Features::NONE,
            mode: EventMode::Shutdown,
            state: ClockEventState::Free,
            min_delta_ns: DEFAULT_MIN_DELTA_NS,
            max_delta_ns: DEFAULT_MAX_DELTA_NS,
            next_event_ns: 0,
            freq_hz: 0,
            bound_cpu: u32::MAX,
            event_count: 0,
            reprogram_count: 0,
        }
    }
}

impl ClockEventDevice {
    /// Return the device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the device name.
    fn set_name(&mut self, name: &[u8]) {
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;
    }

    /// Arm the device to fire at `expires_ns` (nanoseconds since boot).
    ///
    /// Validates that the requested time is within the device's
    /// programmable range relative to `now_ns`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the delta is out of the
    ///   device's programmable range.
    /// - [`Error::Busy`] if the device is not in a programmable state.
    pub fn program(&mut self, now_ns: u64, expires_ns: u64) -> Result<()> {
        if self.state != ClockEventState::Active {
            return Err(Error::Busy);
        }
        if self.mode == EventMode::Shutdown {
            return Err(Error::Busy);
        }

        let delta = expires_ns.saturating_sub(now_ns);
        if delta < self.min_delta_ns || delta > self.max_delta_ns {
            return Err(Error::InvalidArgument);
        }

        self.next_event_ns = expires_ns;
        self.reprogram_count += 1;
        Ok(())
    }

    /// Process a device interrupt (the event fired).
    ///
    /// Clears the armed state and increments the event counter.
    /// For periodic mode, automatically re-arms using the same delta.
    pub fn handle_event(&mut self, now_ns: u64) {
        self.event_count += 1;
        match self.mode {
            EventMode::OneShot => {
                self.next_event_ns = 0;
            }
            EventMode::Periodic => {
                if self.next_event_ns > 0 {
                    let delta = self
                        .next_event_ns
                        .saturating_sub(now_ns.saturating_sub(self.next_event_ns));
                    // Re-arm at the next period boundary.
                    let period = now_ns.saturating_sub(self.next_event_ns);
                    if period > 0 {
                        self.next_event_ns = now_ns.saturating_add(delta);
                    }
                }
            }
            EventMode::Shutdown => {}
        }
    }

    /// Check whether the device supports one-shot mode.
    pub fn supports_oneshot(&self) -> bool {
        self.features.contains(Features::ONESHOT)
    }

    /// Check whether the device supports periodic mode.
    pub fn supports_periodic(&self) -> bool {
        self.features.contains(Features::PERIODIC)
    }

    /// Check whether the device is per-CPU.
    pub fn is_percpu(&self) -> bool {
        self.features.contains(Features::PERCPU)
    }
}

// ── ClockEventStats ─────────────────────────────────────────────────────────

/// Global statistics for the clock event framework.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClockEventStats {
    /// Number of registered devices.
    pub registered_count: u64,
    /// Total events delivered across all devices.
    pub total_events: u64,
    /// Total device registration operations.
    pub registrations: u64,
    /// Total device unregistration operations.
    pub unregistrations: u64,
    /// Total mode switches across all devices.
    pub mode_switches: u64,
    /// Total CPU assignment changes.
    pub cpu_assignments: u64,
}

// ── ClockEventSubsystem ─────────────────────────────────────────────────────

/// System-wide clock event device manager.
///
/// Maintains a table of registered clock event devices, manages
/// per-CPU device assignment, and provides the API for the timer
/// subsystem to program events.
pub struct ClockEventSubsystem {
    /// Registered devices.
    devices: [ClockEventDevice; MAX_DEVICES],
    /// Number of registered (non-free) devices.
    registered_count: usize,
    /// Per-CPU device assignment (index into `devices`).
    cpu_device: [Option<usize>; MAX_CPUS],
    /// Next device identifier.
    next_id: u64,
    /// Global statistics.
    stats: ClockEventStats,
}

impl Default for ClockEventSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockEventSubsystem {
    /// Create a new, empty clock event subsystem.
    pub const fn new() -> Self {
        const NONE_DEV: ClockEventDevice = ClockEventDevice {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            rating: 0,
            features: Features(0),
            mode: EventMode::Shutdown,
            state: ClockEventState::Free,
            min_delta_ns: DEFAULT_MIN_DELTA_NS,
            max_delta_ns: DEFAULT_MAX_DELTA_NS,
            next_event_ns: 0,
            freq_hz: 0,
            bound_cpu: u32::MAX,
            event_count: 0,
            reprogram_count: 0,
        };
        const NONE_OPT: Option<usize> = None;
        Self {
            devices: [NONE_DEV; MAX_DEVICES],
            registered_count: 0,
            cpu_device: [NONE_OPT; MAX_CPUS],
            next_id: 1,
            stats: ClockEventStats {
                registered_count: 0,
                total_events: 0,
                registrations: 0,
                unregistrations: 0,
                mode_switches: 0,
                cpu_assignments: 0,
            },
        }
    }

    /// Register a new clock event device.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the device table is full.
    /// - [`Error::InvalidArgument`] if the rating is out of range.
    pub fn register(
        &mut self,
        name: &[u8],
        rating: u32,
        features: Features,
        freq_hz: u64,
        min_delta_ns: u64,
        max_delta_ns: u64,
    ) -> Result<u64> {
        if rating < MIN_RATING || rating > MAX_RATING {
            return Err(Error::InvalidArgument);
        }
        if min_delta_ns > max_delta_ns {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .devices
            .iter()
            .position(|d| d.state == ClockEventState::Free)
            .ok_or(Error::OutOfMemory)?;

        let dev_id = self.next_id;
        self.next_id += 1;

        self.devices[slot] = ClockEventDevice::default();
        self.devices[slot].id = dev_id;
        self.devices[slot].set_name(name);
        self.devices[slot].rating = rating;
        self.devices[slot].features = features;
        self.devices[slot].freq_hz = freq_hz;
        self.devices[slot].min_delta_ns = min_delta_ns;
        self.devices[slot].max_delta_ns = max_delta_ns;
        self.devices[slot].state = ClockEventState::Registered;

        self.registered_count += 1;
        self.stats.registered_count = self.registered_count as u64;
        self.stats.registrations += 1;

        Ok(dev_id)
    }

    /// Unregister a clock event device.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `dev_id` is not registered.
    /// - [`Error::Busy`] if the device is still assigned to a CPU.
    pub fn unregister(&mut self, dev_id: u64) -> Result<()> {
        let idx = self.find_index(dev_id).ok_or(Error::NotFound)?;

        // Check that no CPU is using this device.
        if self.cpu_device.iter().any(|c| *c == Some(idx)) {
            return Err(Error::Busy);
        }

        self.devices[idx] = ClockEventDevice::default();
        self.registered_count -= 1;
        self.stats.registered_count = self.registered_count as u64;
        self.stats.unregistrations += 1;

        Ok(())
    }

    /// Set the operating mode of a device.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `dev_id` is not registered.
    /// - [`Error::InvalidArgument`] if the device does not support
    ///   the requested mode.
    pub fn set_mode(&mut self, dev_id: u64, mode: EventMode) -> Result<()> {
        let idx = self.find_index(dev_id).ok_or(Error::NotFound)?;
        let dev = &mut self.devices[idx];

        match mode {
            EventMode::Periodic if !dev.supports_periodic() => {
                return Err(Error::InvalidArgument);
            }
            EventMode::OneShot if !dev.supports_oneshot() => {
                return Err(Error::InvalidArgument);
            }
            _ => {}
        }

        dev.mode = mode;
        if mode != EventMode::Shutdown {
            dev.state = ClockEventState::Active;
        }
        self.stats.mode_switches += 1;

        Ok(())
    }

    /// Assign the best available device to a CPU.
    ///
    /// Selects the highest-rated registered device that is either
    /// unbound or bound to `cpu`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` is out of range.
    /// - [`Error::NotFound`] if no suitable device is available.
    pub fn assign_cpu(&mut self, cpu: u32) -> Result<u64> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        // Find the best (highest-rated) device for this CPU.
        let mut best_idx: Option<usize> = None;
        let mut best_rating: u32 = 0;
        for (i, dev) in self.devices.iter().enumerate() {
            if dev.state == ClockEventState::Free {
                continue;
            }
            let eligible = dev.bound_cpu == u32::MAX || dev.bound_cpu == cpu;
            if eligible && dev.rating > best_rating {
                best_rating = dev.rating;
                best_idx = Some(i);
            }
        }

        let idx = best_idx.ok_or(Error::NotFound)?;
        self.devices[idx].bound_cpu = cpu;
        self.cpu_device[cpu as usize] = Some(idx);
        self.stats.cpu_assignments += 1;

        Ok(self.devices[idx].id)
    }

    /// Program the device assigned to `cpu` to fire at `expires_ns`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` is out of range.
    /// - [`Error::NotFound`] if no device is assigned to `cpu`.
    /// - Other errors propagated from [`ClockEventDevice::program`].
    pub fn program_cpu(&mut self, cpu: u32, now_ns: u64, expires_ns: u64) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.cpu_device[cpu as usize].ok_or(Error::NotFound)?;
        self.devices[idx].program(now_ns, expires_ns)
    }

    /// Handle a clock event interrupt on `cpu`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` is out of range.
    /// - [`Error::NotFound`] if no device is assigned to `cpu`.
    pub fn handle_event(&mut self, cpu: u32, now_ns: u64) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.cpu_device[cpu as usize].ok_or(Error::NotFound)?;
        self.devices[idx].handle_event(now_ns);
        self.stats.total_events += 1;
        Ok(())
    }

    /// Suspend the device assigned to `cpu` (e.g., before entering
    /// deep idle).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` is out of range.
    /// - [`Error::NotFound`] if no device is assigned to `cpu`.
    pub fn suspend_cpu(&mut self, cpu: u32) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.cpu_device[cpu as usize].ok_or(Error::NotFound)?;
        self.devices[idx].state = ClockEventState::Suspended;
        self.devices[idx].mode = EventMode::Shutdown;
        Ok(())
    }

    /// Resume the device assigned to `cpu`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu` is out of range.
    /// - [`Error::NotFound`] if no device is assigned to `cpu`.
    pub fn resume_cpu(&mut self, cpu: u32) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.cpu_device[cpu as usize].ok_or(Error::NotFound)?;
        self.devices[idx].state = ClockEventState::Active;
        Ok(())
    }

    /// Look up a device by its identifier.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `dev_id` is not registered.
    pub fn get(&self, dev_id: u64) -> Result<&ClockEventDevice> {
        let idx = self.find_index(dev_id).ok_or(Error::NotFound)?;
        Ok(&self.devices[idx])
    }

    /// Return the device assigned to `cpu`, if any.
    pub fn cpu_device(&self, cpu: u32) -> Option<&ClockEventDevice> {
        if cpu as usize >= MAX_CPUS {
            return None;
        }
        self.cpu_device[cpu as usize].map(|idx| &self.devices[idx])
    }

    /// Return a snapshot of global statistics.
    pub fn stats(&self) -> &ClockEventStats {
        &self.stats
    }

    /// Return the number of registered devices.
    pub fn registered_count(&self) -> usize {
        self.registered_count
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Find the table index for device `dev_id`.
    fn find_index(&self, dev_id: u64) -> Option<usize> {
        self.devices
            .iter()
            .position(|d| d.state != ClockEventState::Free && d.id == dev_id)
    }
}
