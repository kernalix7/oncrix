// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! One-shot tick device management.
//!
//! Manages per-CPU clock event devices in one-shot mode for
//! high-resolution timer support. In one-shot mode, the tick
//! device programs the next interrupt for the earliest pending
//! timer rather than using a periodic tick, enabling tickless
//! (nohz) operation when idle.

use oncrix_lib::{Error, Result};

/// Maximum number of one-shot devices.
const MAX_DEVICES: usize = 256;

/// Maximum number of pending events per device.
const MAX_PENDING_EVENTS: usize = 32;

/// Clock event device mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TickMode {
    /// Periodic mode — fixed interval interrupts.
    Periodic,
    /// One-shot mode — programmed per-event.
    OneShot,
    /// One-shot stopped — no event programmed.
    OneShotStopped,
    /// Device is offline.
    Offline,
}

/// Clock event device features.
#[derive(Clone, Copy)]
pub struct DeviceFeatures {
    /// Raw feature bits.
    bits: u32,
}

impl DeviceFeatures {
    /// Supports periodic mode.
    pub const PERIODIC: Self = Self { bits: 1 << 0 };
    /// Supports one-shot mode.
    pub const ONESHOT: Self = Self { bits: 1 << 1 };
    /// Supports one-shot stopped state.
    pub const ONESHOT_STOPPED: Self = Self { bits: 1 << 2 };
    /// Supports C3 stop (power saving).
    pub const C3_STOP: Self = Self { bits: 1 << 3 };

    /// Creates empty features.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Checks if a feature is set.
    pub const fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Sets a feature.
    pub fn insert(&mut self, other: Self) {
        self.bits |= other.bits;
    }
}

impl Default for DeviceFeatures {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending timer event on a one-shot device.
#[derive(Clone, Copy)]
pub struct PendingEvent {
    /// Expiration time in nanoseconds.
    expires_ns: u64,
    /// Event identifier.
    event_id: u64,
    /// Whether this event is active.
    active: bool,
}

impl PendingEvent {
    /// Creates a new empty pending event.
    pub const fn new() -> Self {
        Self {
            expires_ns: 0,
            event_id: 0,
            active: false,
        }
    }

    /// Returns the expiration time.
    pub const fn expires_ns(&self) -> u64 {
        self.expires_ns
    }

    /// Returns the event identifier.
    pub const fn event_id(&self) -> u64 {
        self.event_id
    }
}

impl Default for PendingEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot tick device representing a per-CPU clock event.
#[derive(Clone, Copy)]
pub struct OneshotDevice {
    /// CPU this device belongs to.
    cpu_id: u32,
    /// Current operating mode.
    mode: TickMode,
    /// Device features.
    features: DeviceFeatures,
    /// Minimum delta between events in nanoseconds.
    min_delta_ns: u64,
    /// Maximum delta for programming.
    max_delta_ns: u64,
    /// Next programmed event time.
    next_event_ns: u64,
    /// Device rating (higher is better).
    rating: u32,
    /// Number of events programmed.
    events_programmed: u64,
    /// Number of events that fired.
    events_fired: u64,
    /// Pending events queue.
    pending: [PendingEvent; MAX_PENDING_EVENTS],
    /// Number of pending events.
    pending_count: usize,
    /// Whether the device is registered.
    registered: bool,
}

impl OneshotDevice {
    /// Creates a new one-shot device.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            mode: TickMode::Offline,
            features: DeviceFeatures::new(),
            min_delta_ns: 1000,
            max_delta_ns: u64::MAX,
            next_event_ns: 0,
            rating: 0,
            events_programmed: 0,
            events_fired: 0,
            pending: [const { PendingEvent::new() }; MAX_PENDING_EVENTS],
            pending_count: 0,
            registered: false,
        }
    }

    /// Returns the CPU this device belongs to.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the current mode.
    pub const fn mode(&self) -> TickMode {
        self.mode
    }

    /// Returns the device features.
    pub const fn features(&self) -> DeviceFeatures {
        self.features
    }

    /// Returns the minimum delta in nanoseconds.
    pub const fn min_delta_ns(&self) -> u64 {
        self.min_delta_ns
    }

    /// Returns the next programmed event time.
    pub const fn next_event_ns(&self) -> u64 {
        self.next_event_ns
    }

    /// Returns the number of events programmed.
    pub const fn events_programmed(&self) -> u64 {
        self.events_programmed
    }

    /// Returns the device rating.
    pub const fn rating(&self) -> u32 {
        self.rating
    }

    /// Programs the next event at the given time.
    pub fn program_event(&mut self, expires_ns: u64) -> Result<()> {
        if self.mode != TickMode::OneShot {
            return Err(Error::InvalidArgument);
        }
        let delta = expires_ns.saturating_sub(self.next_event_ns);
        if delta < self.min_delta_ns {
            return Err(Error::InvalidArgument);
        }
        self.next_event_ns = expires_ns;
        self.events_programmed += 1;
        Ok(())
    }

    /// Switches the device to one-shot mode.
    pub fn switch_to_oneshot(&mut self) -> Result<()> {
        if !self.features.contains(DeviceFeatures::ONESHOT) {
            return Err(Error::NotImplemented);
        }
        self.mode = TickMode::OneShot;
        Ok(())
    }

    /// Queues a pending event.
    pub fn queue_event(&mut self, event_id: u64, expires_ns: u64) -> Result<()> {
        if self.pending_count >= MAX_PENDING_EVENTS {
            return Err(Error::OutOfMemory);
        }
        self.pending[self.pending_count] = PendingEvent {
            expires_ns,
            event_id,
            active: true,
        };
        self.pending_count += 1;
        Ok(())
    }

    /// Returns the number of pending events.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }
}

impl Default for OneshotDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot tick device manager.
pub struct TickOneshotManager {
    /// Registered devices.
    devices: [OneshotDevice; MAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Whether nohz mode is active.
    nohz_active: bool,
    /// Number of CPUs currently in nohz state.
    nohz_cpu_count: usize,
}

impl TickOneshotManager {
    /// Creates a new tick one-shot manager.
    pub const fn new() -> Self {
        Self {
            devices: [const { OneshotDevice::new() }; MAX_DEVICES],
            device_count: 0,
            nohz_active: false,
            nohz_cpu_count: 0,
        }
    }

    /// Registers a new one-shot device for a CPU.
    pub fn register_device(
        &mut self,
        cpu_id: u32,
        features: DeviceFeatures,
        min_delta_ns: u64,
        rating: u32,
    ) -> Result<()> {
        if self.device_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let dev = &mut self.devices[self.device_count];
        dev.cpu_id = cpu_id;
        dev.features = features;
        dev.min_delta_ns = min_delta_ns;
        dev.rating = rating;
        dev.registered = true;
        dev.mode = TickMode::Periodic;
        self.device_count += 1;
        Ok(())
    }

    /// Gets the device for a given CPU.
    pub fn get_device(&self, cpu_id: u32) -> Result<&OneshotDevice> {
        self.devices[..self.device_count]
            .iter()
            .find(|d| d.cpu_id == cpu_id)
            .ok_or(Error::NotFound)
    }

    /// Gets a mutable device for a given CPU.
    pub fn get_device_mut(&mut self, cpu_id: u32) -> Result<&mut OneshotDevice> {
        self.devices[..self.device_count]
            .iter_mut()
            .find(|d| d.cpu_id == cpu_id)
            .ok_or(Error::NotFound)
    }

    /// Enables nohz mode globally.
    pub fn enable_nohz(&mut self) {
        self.nohz_active = true;
    }

    /// Returns whether nohz mode is active.
    pub const fn is_nohz_active(&self) -> bool {
        self.nohz_active
    }

    /// Returns the number of registered devices.
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns the number of CPUs in nohz state.
    pub const fn nohz_cpu_count(&self) -> usize {
        self.nohz_cpu_count
    }

    /// Switches all capable devices to one-shot mode.
    pub fn switch_all_to_oneshot(&mut self) -> usize {
        let mut switched = 0usize;
        for i in 0..self.device_count {
            if self.devices[i].features.contains(DeviceFeatures::ONESHOT)
                && self.devices[i].mode == TickMode::Periodic
            {
                self.devices[i].mode = TickMode::OneShot;
                switched += 1;
            }
        }
        switched
    }
}

impl Default for TickOneshotManager {
    fn default() -> Self {
        Self::new()
    }
}
