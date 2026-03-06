// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock event device.
//!
//! Clock event devices generate interrupts at programmed
//! intervals. They are used for the kernel's tick (periodic)
//! and high-resolution timer (oneshot) infrastructure.
//!
//! # Design
//!
//! ```text
//!   ClockEventDevice
//!   +-------------------+
//!   | name              |
//!   | features          |  ONESHOT | PERIODIC
//!   | rating            |  quality rating (higher = better)
//!   | mult / shift      |  nanosecond ↔ cycles conversion
//!   | min/max_delta_ns  |  programmable range
//!   | state             |  Detached → Shutdown → Oneshot/Periodic
//!   +-------------------+
//! ```
//!
//! # States
//!
//! - `Detached` — not bound to any CPU.
//! - `Shutdown` — bound but not generating events.
//! - `Oneshot` — fires once at a programmed time.
//! - `Periodic` — fires at a regular interval.
//!
//! # Reference
//!
//! Linux `kernel/time/clockevents.c`,
//! `include/linux/clockchips.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum clock event devices.
const MAX_DEVICES: usize = 64;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

// ======================================================================
// ClockEventFeature
// ======================================================================

/// Features supported by a clock event device.
pub const CLOCK_EVT_FEAT_ONESHOT: u32 = 1 << 0;

/// Periodic mode.
pub const CLOCK_EVT_FEAT_PERIODIC: u32 = 1 << 1;

/// C3-stop aware (device stops in deep C-states).
pub const CLOCK_EVT_FEAT_C3STOP: u32 = 1 << 2;

/// Device can be per-CPU.
pub const CLOCK_EVT_FEAT_PERCPU: u32 = 1 << 3;

/// Dummy device (for boot).
pub const _CLOCK_EVT_FEAT_DUMMY: u32 = 1 << 4;

// ======================================================================
// ClockEventState
// ======================================================================

/// State of a clock event device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockEventState {
    /// Not bound to a CPU.
    Detached,
    /// Bound but not active.
    Shutdown,
    /// Generating one-shot events.
    Oneshot,
    /// Generating periodic events.
    Periodic,
    /// Stopped (oneshot but no event programmed).
    OneshotStopped,
}

// ======================================================================
// ClockEventDevice
// ======================================================================

/// A clock event device.
pub struct ClockEventDevice {
    /// Device name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Feature flags.
    features: u32,
    /// Quality rating (higher is better).
    rating: u32,
    /// Multiplier for ns ↔ cycles conversion.
    mult: u32,
    /// Shift for ns ↔ cycles conversion.
    shift: u32,
    /// Minimum programmable delta (ns).
    min_delta_ns: u64,
    /// Maximum programmable delta (ns).
    max_delta_ns: u64,
    /// Current state.
    state: ClockEventState,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Bound CPU (-1 if unbound).
    bound_cpu: i32,
    /// IRQ number.
    irq: u32,
    /// Next event timestamp (ns, for oneshot mode).
    next_event_ns: u64,
    /// Period (ns, for periodic mode).
    period_ns: u64,
    /// Statistics: total events fired.
    stats_events: u64,
    /// Statistics: total set_next_event calls.
    stats_set_next: u64,
    /// Generation counter.
    generation: u64,
}

impl ClockEventDevice {
    /// Creates a new empty device.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            features: 0,
            rating: 0,
            mult: 1,
            shift: 0,
            min_delta_ns: 0,
            max_delta_ns: 0,
            state: ClockEventState::Detached,
            allocated: false,
            bound_cpu: -1,
            irq: 0,
            next_event_ns: 0,
            period_ns: 0,
            stats_events: 0,
            stats_set_next: 0,
            generation: 0,
        }
    }

    /// Returns the device name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the features.
    pub fn features(&self) -> u32 {
        self.features
    }

    /// Returns the rating.
    pub fn rating(&self) -> u32 {
        self.rating
    }

    /// Returns the multiplier.
    pub fn mult(&self) -> u32 {
        self.mult
    }

    /// Returns the shift.
    pub fn shift(&self) -> u32 {
        self.shift
    }

    /// Returns the minimum delta (ns).
    pub fn min_delta_ns(&self) -> u64 {
        self.min_delta_ns
    }

    /// Returns the maximum delta (ns).
    pub fn max_delta_ns(&self) -> u64 {
        self.max_delta_ns
    }

    /// Returns the current state.
    pub fn state(&self) -> ClockEventState {
        self.state
    }

    /// Returns the bound CPU.
    pub fn bound_cpu(&self) -> i32 {
        self.bound_cpu
    }

    /// Returns the IRQ number.
    pub fn irq(&self) -> u32 {
        self.irq
    }

    /// Returns the next event time.
    pub fn next_event_ns(&self) -> u64 {
        self.next_event_ns
    }

    /// Returns the period (ns).
    pub fn period_ns(&self) -> u64 {
        self.period_ns
    }

    /// Returns total events.
    pub fn stats_events(&self) -> u64 {
        self.stats_events
    }

    /// Returns whether oneshot is supported.
    pub fn supports_oneshot(&self) -> bool {
        self.features & CLOCK_EVT_FEAT_ONESHOT != 0
    }

    /// Returns whether periodic is supported.
    pub fn supports_periodic(&self) -> bool {
        self.features & CLOCK_EVT_FEAT_PERIODIC != 0
    }
}

// ======================================================================
// ClockEventsManager
// ======================================================================

/// Manages clock event device registration and lifecycle.
pub struct ClockEventsManager {
    /// Device pool.
    devices: [ClockEventDevice; MAX_DEVICES],
    /// Number of allocated devices.
    count: usize,
    /// Global time (ns).
    current_time_ns: u64,
}

impl ClockEventsManager {
    /// Creates a new empty manager.
    pub const fn new() -> Self {
        Self {
            devices: [const { ClockEventDevice::new() }; MAX_DEVICES],
            count: 0,
            current_time_ns: 0,
        }
    }

    /// Registers a new clock event device.
    pub fn clockevents_register(
        &mut self,
        name: &[u8],
        features: u32,
        rating: u32,
        mult: u32,
        shift: u32,
        min_delta_ns: u64,
        max_delta_ns: u64,
        irq: u32,
    ) -> Result<usize> {
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        if min_delta_ns > max_delta_ns {
            return Err(Error::InvalidArgument);
        }
        let idx = self
            .devices
            .iter()
            .position(|d| !d.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.devices[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.devices[idx].name_len = copy_len;
        self.devices[idx].features = features;
        self.devices[idx].rating = rating;
        self.devices[idx].mult = mult;
        self.devices[idx].shift = shift;
        self.devices[idx].min_delta_ns = min_delta_ns;
        self.devices[idx].max_delta_ns = max_delta_ns;
        self.devices[idx].irq = irq;
        self.devices[idx].state = ClockEventState::Detached;
        self.devices[idx].allocated = true;
        self.count += 1;
        Ok(idx)
    }

    /// Programs the next event (oneshot mode).
    pub fn set_next_event(&mut self, idx: usize, delta_ns: u64) -> Result<()> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        if !self.devices[idx].supports_oneshot() {
            return Err(Error::InvalidArgument);
        }
        if delta_ns < self.devices[idx].min_delta_ns || delta_ns > self.devices[idx].max_delta_ns {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].next_event_ns = self.current_time_ns + delta_ns;
        self.devices[idx].stats_set_next += 1;
        self.devices[idx].generation += 1;
        Ok(())
    }

    /// Sets the device to oneshot mode.
    pub fn set_state_oneshot(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        if !self.devices[idx].supports_oneshot() {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].state = ClockEventState::Oneshot;
        self.devices[idx].generation += 1;
        Ok(())
    }

    /// Sets the device to periodic mode.
    pub fn set_state_periodic(&mut self, idx: usize, period_ns: u64) -> Result<()> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        if !self.devices[idx].supports_periodic() {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].state = ClockEventState::Periodic;
        self.devices[idx].period_ns = period_ns;
        self.devices[idx].generation += 1;
        Ok(())
    }

    /// Shuts down the device.
    pub fn set_state_shutdown(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        self.devices[idx].state = ClockEventState::Shutdown;
        self.devices[idx].next_event_ns = 0;
        self.devices[idx].period_ns = 0;
        self.devices[idx].generation += 1;
        Ok(())
    }

    /// Binds a device to a CPU.
    pub fn bind_cpu(&mut self, idx: usize, cpu: i32) -> Result<()> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        self.devices[idx].bound_cpu = cpu;
        if self.devices[idx].state == ClockEventState::Detached {
            self.devices[idx].state = ClockEventState::Shutdown;
        }
        self.devices[idx].generation += 1;
        Ok(())
    }

    /// Simulates an event firing.
    pub fn fire_event(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        self.devices[idx].stats_events += 1;
        self.devices[idx].generation += 1;
        // In periodic mode, auto-schedule next.
        if self.devices[idx].state == ClockEventState::Periodic {
            self.devices[idx].next_event_ns = self.current_time_ns + self.devices[idx].period_ns;
        }
        Ok(())
    }

    /// Finds the best (highest-rated) device for a CPU.
    pub fn find_best_for_cpu(&self, cpu: i32) -> Result<usize> {
        let mut best_idx = None;
        let mut best_rating = 0u32;
        for (i, dev) in self.devices.iter().enumerate() {
            if dev.allocated
                && (dev.bound_cpu == cpu || dev.bound_cpu == -1)
                && dev.rating > best_rating
            {
                best_rating = dev.rating;
                best_idx = Some(i);
            }
        }
        best_idx.ok_or(Error::NotFound)
    }

    /// Returns a reference to a device.
    pub fn get(&self, idx: usize) -> Result<&ClockEventDevice> {
        if idx >= MAX_DEVICES || !self.devices[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.devices[idx])
    }

    /// Returns the number of registered devices.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Advances the global time.
    pub fn advance_time(&mut self, ns: u64) {
        self.current_time_ns += ns;
    }

    /// Returns the current time.
    pub fn current_time_ns(&self) -> u64 {
        self.current_time_ns
    }
}
