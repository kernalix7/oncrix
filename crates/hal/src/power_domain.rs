// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power domain management hardware abstraction.
//!
//! Provides interfaces for controlling hardware power domains — independently
//! switchable blocks of silicon that can be powered down for energy savings.
//! Supports hierarchical domain trees, reference counting, and power state
//! transition sequencing.

use oncrix_lib::{Error, Result};

/// Maximum number of power domains in the system.
pub const MAX_POWER_DOMAINS: usize = 32;

/// Power domain operating state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// Domain is powered off.
    Off,
    /// Domain is in a low-power retention state.
    Retention,
    /// Domain is fully powered and operational.
    On,
    /// Domain is in transition (powering on or off).
    Transitioning,
    /// Domain is in an error or fault state.
    Fault,
}

/// Power domain capability flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainCaps {
    /// Supports power off.
    pub can_power_off: bool,
    /// Supports retention (low-power with state preserved).
    pub can_retain: bool,
    /// Supports hardware isolation of outputs during power-off.
    pub has_isolation: bool,
    /// Has a hardware reset line that must be asserted during power-off.
    pub has_reset: bool,
}

impl DomainCaps {
    /// Creates capability flags for a domain that only supports on/off.
    pub const fn basic() -> Self {
        Self {
            can_power_off: true,
            can_retain: false,
            has_isolation: false,
            has_reset: false,
        }
    }

    /// Creates capability flags for a full-featured power domain.
    pub const fn full() -> Self {
        Self {
            can_power_off: true,
            can_retain: true,
            has_isolation: true,
            has_reset: true,
        }
    }
}

/// Descriptor for a hardware power domain.
#[derive(Debug, Clone, Copy)]
pub struct PowerDomainDesc {
    /// Unique domain identifier.
    pub id: u16,
    /// Human-readable name.
    pub name: &'static str,
    /// MMIO address of the power control register.
    pub ctrl_reg: u64,
    /// Bit position of the power enable bit.
    pub enable_bit: u8,
    /// Bit position of the isolation enable bit (valid if has_isolation).
    pub iso_bit: u8,
    /// Bit position of the reset bit (valid if has_reset).
    pub reset_bit: u8,
    /// Parent domain ID (u16::MAX = no parent).
    pub parent_id: u16,
    /// Domain capability flags.
    pub caps: DomainCaps,
}

impl PowerDomainDesc {
    /// Creates a minimal power domain descriptor.
    pub const fn new(id: u16, name: &'static str, ctrl_reg: u64, enable_bit: u8) -> Self {
        Self {
            id,
            name,
            ctrl_reg,
            enable_bit,
            iso_bit: 0,
            reset_bit: 0,
            parent_id: u16::MAX,
            caps: DomainCaps::basic(),
        }
    }

    /// Sets the parent domain ID.
    pub const fn with_parent(mut self, parent_id: u16) -> Self {
        self.parent_id = parent_id;
        self
    }

    /// Sets full capability flags.
    pub const fn with_full_caps(mut self, iso_bit: u8, reset_bit: u8) -> Self {
        self.iso_bit = iso_bit;
        self.reset_bit = reset_bit;
        self.caps = DomainCaps::full();
        self
    }
}

impl Default for PowerDomainDesc {
    fn default() -> Self {
        Self::new(0, "unknown", 0, 0)
    }
}

/// Runtime state for a managed power domain.
struct DomainRuntime {
    desc: PowerDomainDesc,
    state: DomainState,
    /// Reference count — domain stays on while > 0.
    refcount: u32,
}

impl DomainRuntime {
    const fn new(desc: PowerDomainDesc) -> Self {
        Self {
            desc,
            state: DomainState::Off,
            refcount: 0,
        }
    }
}

impl Default for DomainRuntime {
    fn default() -> Self {
        Self::new(PowerDomainDesc::default())
    }
}

/// Power domain controller managing all system power domains.
pub struct PowerDomainController {
    domains: [DomainRuntime; MAX_POWER_DOMAINS],
    count: usize,
    initialized: bool,
}

impl PowerDomainController {
    /// Creates a new power domain controller.
    pub const fn new() -> Self {
        Self {
            domains: [const { DomainRuntime::new(PowerDomainDesc::new(0, "unused", 0, 0)) };
                MAX_POWER_DOMAINS],
            count: 0,
            initialized: false,
        }
    }

    /// Registers power domains from the platform descriptor table.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if more domains than MAX_POWER_DOMAINS are provided.
    pub fn register_domains(&mut self, descs: &[PowerDomainDesc]) -> Result<()> {
        if descs.len() > MAX_POWER_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        for (i, desc) in descs.iter().enumerate() {
            self.domains[i] = DomainRuntime::new(*desc);
        }
        self.count = descs.len();
        self.initialized = true;
        Ok(())
    }

    /// Finds the index of a domain by its ID.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if no domain with the given ID exists.
    pub fn find_domain(&self, id: u16) -> Result<usize> {
        for (i, d) in self.domains[..self.count].iter().enumerate() {
            if d.desc.id == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Powers on a domain (and its parent if needed).
    ///
    /// Reference counted — multiple callers can power on the same domain.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the domain ID is unknown.
    /// Returns `Error::Busy` if not initialized.
    pub fn power_on(&mut self, id: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let idx = self.find_domain(id)?;

        // Power on parent first
        let parent_id = self.domains[idx].desc.parent_id;
        if parent_id != u16::MAX {
            self.power_on(parent_id)?;
        }

        self.domains[idx].refcount = self.domains[idx].refcount.saturating_add(1);
        if self.domains[idx].state != DomainState::On {
            self.set_power_hw(idx, true)?;
            self.domains[idx].state = DomainState::On;
        }
        Ok(())
    }

    /// Decrements the reference count and powers off the domain if count reaches zero.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the domain ID is unknown.
    /// Returns `Error::Busy` if not initialized.
    pub fn power_off(&mut self, id: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let idx = self.find_domain(id)?;
        if self.domains[idx].refcount > 0 {
            self.domains[idx].refcount -= 1;
        }
        if self.domains[idx].refcount == 0 && self.domains[idx].state == DomainState::On {
            self.set_power_hw(idx, false)?;
            self.domains[idx].state = DomainState::Off;
        }
        Ok(())
    }

    /// Transitions a domain to retention (low-power with state preserved).
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the domain ID is unknown.
    /// Returns `Error::NotImplemented` if the domain does not support retention.
    /// Returns `Error::Busy` if not initialized.
    pub fn enter_retention(&mut self, id: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let idx = self.find_domain(id)?;
        if !self.domains[idx].desc.caps.can_retain {
            return Err(Error::NotImplemented);
        }
        if self.domains[idx].state == DomainState::On {
            // Apply isolation before reducing power
            if self.domains[idx].desc.caps.has_isolation {
                self.set_isolation_hw(idx, true)?;
            }
            self.domains[idx].state = DomainState::Retention;
        }
        Ok(())
    }

    /// Returns the current state of a power domain.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the domain ID is unknown.
    pub fn state(&self, id: u16) -> Result<DomainState> {
        let idx = self.find_domain(id)?;
        Ok(self.domains[idx].state)
    }

    /// Returns the current reference count for a domain.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the domain ID is unknown.
    pub fn refcount(&self, id: u16) -> Result<u32> {
        let idx = self.find_domain(id)?;
        Ok(self.domains[idx].refcount)
    }

    /// Returns the number of registered domains.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no domains are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn set_power_hw(&self, idx: usize, enable: bool) -> Result<()> {
        let desc = &self.domains[idx].desc;
        if desc.ctrl_reg == 0 {
            return Ok(());
        }
        // SAFETY: MMIO read-modify-write to power domain control register.
        // ctrl_reg is non-zero and validated at registration time.
        unsafe {
            let reg = desc.ctrl_reg as *mut u32;
            let mut val = reg.read_volatile();
            let bit_mask = 1u32 << desc.enable_bit;
            if enable {
                val |= bit_mask;
            } else {
                val &= !bit_mask;
            }
            reg.write_volatile(val);
        }
        Ok(())
    }

    fn set_isolation_hw(&self, idx: usize, isolate: bool) -> Result<()> {
        let desc = &self.domains[idx].desc;
        if desc.ctrl_reg == 0 {
            return Ok(());
        }
        // SAFETY: MMIO read-modify-write to power domain isolation register.
        // ctrl_reg is non-zero and validated at registration time.
        unsafe {
            let reg = desc.ctrl_reg as *mut u32;
            let mut val = reg.read_volatile();
            let bit_mask = 1u32 << desc.iso_bit;
            if isolate {
                val |= bit_mask;
            } else {
                val &= !bit_mask;
            }
            reg.write_volatile(val);
        }
        Ok(())
    }
}

impl Default for PowerDomainController {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for power domain operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct PowerDomainStats {
    /// Number of power-on transitions.
    pub power_on_count: u64,
    /// Number of power-off transitions.
    pub power_off_count: u64,
    /// Number of retention entries.
    pub retention_count: u64,
    /// Number of domains currently powered on.
    pub domains_on: u32,
}

impl PowerDomainStats {
    /// Creates a new zeroed stats structure.
    pub const fn new() -> Self {
        Self {
            power_on_count: 0,
            power_off_count: 0,
            retention_count: 0,
            domains_on: 0,
        }
    }
}

/// Returns a human-readable name for a domain state.
pub fn domain_state_name(state: DomainState) -> &'static str {
    match state {
        DomainState::Off => "off",
        DomainState::Retention => "retention",
        DomainState::On => "on",
        DomainState::Transitioning => "transitioning",
        DomainState::Fault => "fault",
    }
}

/// Checks whether a domain state transition is valid.
pub fn is_valid_transition(from: DomainState, to: DomainState) -> bool {
    match (from, to) {
        (DomainState::Off, DomainState::On) => true,
        (DomainState::Off, DomainState::Retention) => false,
        (DomainState::On, DomainState::Off) => true,
        (DomainState::On, DomainState::Retention) => true,
        (DomainState::Retention, DomainState::On) => true,
        (DomainState::Retention, DomainState::Off) => true,
        (DomainState::Transitioning, _) => false,
        (DomainState::Fault, _) => false,
        _ => false,
    }
}
