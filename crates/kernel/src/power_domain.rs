// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power domain management.
//!
//! Generic power domains (genpd) group devices that share a
//! common power rail. The kernel can power off an entire domain
//! when all its devices are idle, and power it back on when
//! any device needs to operate.
//!
//! # Design
//!
//! ```text
//!   GenPd
//!   +-------------------+
//!   | name              |
//!   | state (ON/OFF)    |
//!   | dev_list[]        |  attached device indices
//!   | subdomain_list[]  |  child power domain indices
//!   | perf_state        |  performance state level
//!   +-------------------+
//!
//!   Hierarchy:
//!   parent domain → subdomains → devices
//!   Parent must be ON for children to be ON.
//! ```
//!
//! # Lifecycle
//!
//! 1. `genpd_create()` — create a power domain.
//! 2. `genpd_add_device()` — attach a device.
//! 3. `power_on()` / `power_off()` — control domain power.
//! 4. `genpd_attach_subdomain()` — create hierarchy.
//! 5. `genpd_remove_device()` — detach a device.
//!
//! # Reference
//!
//! Linux `drivers/base/power/domain.c`,
//! `include/linux/pm_domain.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum power domains.
const MAX_DOMAINS: usize = 128;

/// Maximum devices per domain.
const MAX_DEVICES_PER_DOMAIN: usize = 32;

/// Maximum subdomains per domain.
const MAX_SUBDOMAINS: usize = 16;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

/// No index sentinel.
const NO_IDX: u32 = u32::MAX;

/// Maximum performance states.
const MAX_PERF_STATES: usize = 16;

// ======================================================================
// PowerState
// ======================================================================

/// Power domain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// Domain is powered on.
    On,
    /// Domain is powered off.
    Off,
    /// Domain is in a low-power idle state.
    Retention,
}

// ======================================================================
// PerfState
// ======================================================================

/// Performance state of a power domain.
#[derive(Debug, Clone, Copy)]
pub struct PerfState {
    /// Performance level (0 = lowest).
    level: u32,
    /// Frequency at this level (kHz).
    freq_khz: u32,
    /// Voltage at this level (uV).
    voltage_uv: u32,
    /// Power consumption (mW).
    power_mw: u32,
    /// Whether active.
    active: bool,
}

impl PerfState {
    /// Creates a new empty perf state.
    pub const fn new() -> Self {
        Self {
            level: 0,
            freq_khz: 0,
            voltage_uv: 0,
            power_mw: 0,
            active: false,
        }
    }

    /// Returns the performance level.
    pub fn level(&self) -> u32 {
        self.level
    }

    /// Returns the frequency.
    pub fn freq_khz(&self) -> u32 {
        self.freq_khz
    }

    /// Returns the voltage.
    pub fn voltage_uv(&self) -> u32 {
        self.voltage_uv
    }

    /// Returns the power consumption.
    pub fn power_mw(&self) -> u32 {
        self.power_mw
    }
}

// ======================================================================
// GenPd
// ======================================================================

/// A generic power domain.
pub struct GenPd {
    /// Domain name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Current power state.
    state: PowerState,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Attached device indices.
    dev_list: [u32; MAX_DEVICES_PER_DOMAIN],
    /// Number of attached devices.
    dev_count: usize,
    /// Subdomain indices.
    subdomain_list: [u32; MAX_SUBDOMAINS],
    /// Number of subdomains.
    subdomain_count: usize,
    /// Parent domain index.
    parent_idx: u32,
    /// Performance states.
    perf_states: [PerfState; MAX_PERF_STATES],
    /// Number of perf states.
    perf_state_count: usize,
    /// Current performance state level.
    cur_perf_state: u32,
    /// Reference count (devices + subdomains needing ON).
    active_refs: u32,
    /// Generation counter.
    generation: u64,
    /// Statistics: total power_on calls.
    stats_power_on: u64,
    /// Statistics: total power_off calls.
    stats_power_off: u64,
}

impl GenPd {
    /// Creates a new empty power domain.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: PowerState::Off,
            allocated: false,
            dev_list: [NO_IDX; MAX_DEVICES_PER_DOMAIN],
            dev_count: 0,
            subdomain_list: [NO_IDX; MAX_SUBDOMAINS],
            subdomain_count: 0,
            parent_idx: NO_IDX,
            perf_states: [const { PerfState::new() }; MAX_PERF_STATES],
            perf_state_count: 0,
            cur_perf_state: 0,
            active_refs: 0,
            generation: 0,
            stats_power_on: 0,
            stats_power_off: 0,
        }
    }

    /// Returns the domain name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the power state.
    pub fn state(&self) -> PowerState {
        self.state
    }

    /// Returns the device count.
    pub fn dev_count(&self) -> usize {
        self.dev_count
    }

    /// Returns the subdomain count.
    pub fn subdomain_count(&self) -> usize {
        self.subdomain_count
    }

    /// Returns the parent index.
    pub fn parent_idx(&self) -> u32 {
        self.parent_idx
    }

    /// Returns the current performance state.
    pub fn cur_perf_state(&self) -> u32 {
        self.cur_perf_state
    }

    /// Returns the active reference count.
    pub fn active_refs(&self) -> u32 {
        self.active_refs
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

// ======================================================================
// PowerDomainManager
// ======================================================================

/// Manages the global power domain hierarchy.
pub struct PowerDomainManager {
    /// Domain pool.
    domains: [GenPd; MAX_DOMAINS],
    /// Number of allocated domains.
    count: usize,
}

impl PowerDomainManager {
    /// Creates a new empty manager.
    pub const fn new() -> Self {
        Self {
            domains: [const { GenPd::new() }; MAX_DOMAINS],
            count: 0,
        }
    }

    /// Creates a new power domain.
    pub fn genpd_create(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .domains
            .iter()
            .position(|d| !d.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.domains[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.domains[idx].name_len = copy_len;
        self.domains[idx].allocated = true;
        self.domains[idx].state = PowerState::Off;
        self.count += 1;
        Ok(idx)
    }

    /// Destroys a power domain.
    pub fn genpd_destroy(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DOMAINS || !self.domains[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.domains[idx].dev_count > 0 {
            return Err(Error::Busy);
        }
        self.domains[idx] = GenPd::new();
        self.count -= 1;
        Ok(())
    }

    /// Adds a device to a power domain.
    pub fn genpd_add_device(&mut self, domain_idx: usize, dev_id: u32) -> Result<()> {
        if domain_idx >= MAX_DOMAINS || !self.domains[domain_idx].allocated {
            return Err(Error::NotFound);
        }
        let dc = self.domains[domain_idx].dev_count;
        if dc >= MAX_DEVICES_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }
        // Check duplicate.
        if self.domains[domain_idx].dev_list[..dc]
            .iter()
            .any(|&d| d == dev_id)
        {
            return Err(Error::AlreadyExists);
        }
        self.domains[domain_idx].dev_list[dc] = dev_id;
        self.domains[domain_idx].dev_count += 1;
        self.domains[domain_idx].generation += 1;
        Ok(())
    }

    /// Removes a device from a power domain.
    pub fn genpd_remove_device(&mut self, domain_idx: usize, dev_id: u32) -> Result<()> {
        if domain_idx >= MAX_DOMAINS || !self.domains[domain_idx].allocated {
            return Err(Error::NotFound);
        }
        let dc = self.domains[domain_idx].dev_count;
        let pos = self.domains[domain_idx].dev_list[..dc]
            .iter()
            .position(|&d| d == dev_id);
        match pos {
            Some(p) => {
                let last = dc - 1;
                self.domains[domain_idx].dev_list.swap(p, last);
                self.domains[domain_idx].dev_list[last] = NO_IDX;
                self.domains[domain_idx].dev_count -= 1;
                self.domains[domain_idx].generation += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Powers on a domain.
    ///
    /// If the domain has a parent, the parent must also be on.
    pub fn power_on(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DOMAINS || !self.domains[idx].allocated {
            return Err(Error::NotFound);
        }
        // Check parent is on.
        let parent = self.domains[idx].parent_idx;
        if parent != NO_IDX {
            let pi = parent as usize;
            if pi < MAX_DOMAINS
                && self.domains[pi].allocated
                && self.domains[pi].state == PowerState::Off
            {
                return Err(Error::InvalidArgument);
            }
        }
        self.domains[idx].state = PowerState::On;
        self.domains[idx].active_refs += 1;
        self.domains[idx].stats_power_on += 1;
        self.domains[idx].generation += 1;
        Ok(())
    }

    /// Powers off a domain.
    ///
    /// All subdomains must already be off.
    pub fn power_off(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DOMAINS || !self.domains[idx].allocated {
            return Err(Error::NotFound);
        }
        // Check no subdomains are on.
        let sc = self.domains[idx].subdomain_count;
        for i in 0..sc {
            let si = self.domains[idx].subdomain_list[i] as usize;
            if si < MAX_DOMAINS
                && self.domains[si].allocated
                && self.domains[si].state == PowerState::On
            {
                return Err(Error::Busy);
            }
        }
        self.domains[idx].state = PowerState::Off;
        self.domains[idx].stats_power_off += 1;
        self.domains[idx].generation += 1;
        Ok(())
    }

    /// Attaches a subdomain under a parent domain.
    pub fn genpd_attach_subdomain(&mut self, parent_idx: usize, child_idx: usize) -> Result<()> {
        if parent_idx >= MAX_DOMAINS
            || !self.domains[parent_idx].allocated
            || child_idx >= MAX_DOMAINS
            || !self.domains[child_idx].allocated
        {
            return Err(Error::NotFound);
        }
        if parent_idx == child_idx {
            return Err(Error::InvalidArgument);
        }
        let sc = self.domains[parent_idx].subdomain_count;
        if sc >= MAX_SUBDOMAINS {
            return Err(Error::OutOfMemory);
        }
        self.domains[parent_idx].subdomain_list[sc] = child_idx as u32;
        self.domains[parent_idx].subdomain_count += 1;
        self.domains[child_idx].parent_idx = parent_idx as u32;
        self.domains[parent_idx].generation += 1;
        self.domains[child_idx].generation += 1;
        Ok(())
    }

    /// Sets the performance state for a domain.
    pub fn set_performance_state(&mut self, idx: usize, level: u32) -> Result<()> {
        if idx >= MAX_DOMAINS || !self.domains[idx].allocated {
            return Err(Error::NotFound);
        }
        self.domains[idx].cur_perf_state = level;
        self.domains[idx].generation += 1;
        Ok(())
    }

    /// Adds a performance state entry to a domain.
    pub fn add_perf_state(
        &mut self,
        idx: usize,
        level: u32,
        freq_khz: u32,
        voltage_uv: u32,
        power_mw: u32,
    ) -> Result<()> {
        if idx >= MAX_DOMAINS || !self.domains[idx].allocated {
            return Err(Error::NotFound);
        }
        let pc = self.domains[idx].perf_state_count;
        if pc >= MAX_PERF_STATES {
            return Err(Error::OutOfMemory);
        }
        self.domains[idx].perf_states[pc] = PerfState {
            level,
            freq_khz,
            voltage_uv,
            power_mw,
            active: true,
        };
        self.domains[idx].perf_state_count += 1;
        Ok(())
    }

    /// Returns a reference to a domain.
    pub fn get(&self, idx: usize) -> Result<&GenPd> {
        if idx >= MAX_DOMAINS || !self.domains[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.domains[idx])
    }

    /// Returns the number of allocated domains.
    pub fn count(&self) -> usize {
        self.count
    }
}
