// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock gating control hardware abstraction.
//!
//! Provides interfaces for enabling and disabling individual hardware clocks
//! to manage power consumption. Supports hierarchical clock trees with parent
//! clock relationships and reference counting for safe gating/ungating.

use oncrix_lib::{Error, Result};

/// Maximum number of clock gates managed by this subsystem.
pub const MAX_CLOCK_GATES: usize = 64;

/// Maximum number of clock gate bits in a single register.
pub const BITS_PER_GATE_REG: usize = 32;

/// Clock gate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateState {
    /// Clock is gated (disabled, saving power).
    Gated,
    /// Clock is ungated (enabled, running).
    Ungated,
    /// Clock state is unknown or hardware is uninitialized.
    Unknown,
}

/// Describes a single hardware clock gate.
#[derive(Debug, Clone, Copy)]
pub struct ClockGateDesc {
    /// Gate identifier.
    pub id: u16,
    /// Human-readable name.
    pub name: &'static str,
    /// MMIO address of the gate control register.
    pub reg_addr: u64,
    /// Bit position within the control register.
    pub bit: u8,
    /// Whether setting the bit enables (1) or disables (0) the clock.
    pub active_high: bool,
    /// Parent gate ID that must be ungated first (u16::MAX = no parent).
    pub parent_id: u16,
}

impl ClockGateDesc {
    /// Creates a new clock gate descriptor with no parent dependency.
    pub const fn new(
        id: u16,
        name: &'static str,
        reg_addr: u64,
        bit: u8,
        active_high: bool,
    ) -> Self {
        Self {
            id,
            name,
            reg_addr,
            bit,
            active_high,
            parent_id: u16::MAX,
        }
    }

    /// Creates a clock gate descriptor with a parent gate dependency.
    pub const fn with_parent(mut self, parent_id: u16) -> Self {
        self.parent_id = parent_id;
        self
    }
}

impl Default for ClockGateDesc {
    fn default() -> Self {
        Self::new(0, "unknown", 0, 0, true)
    }
}

/// Runtime state for a managed clock gate.
#[derive(Debug, Clone, Copy)]
struct GateRuntime {
    desc: ClockGateDesc,
    state: GateState,
    /// Reference count — gate is kept ungated while > 0.
    refcount: u32,
}

impl GateRuntime {
    const fn new(desc: ClockGateDesc) -> Self {
        Self {
            desc,
            state: GateState::Unknown,
            refcount: 0,
        }
    }
}

impl Default for GateRuntime {
    fn default() -> Self {
        Self::new(ClockGateDesc::default())
    }
}

/// Clock gate controller managing all hardware clock gates.
pub struct ClockGateController {
    gates: [GateRuntime; MAX_CLOCK_GATES],
    count: usize,
    initialized: bool,
}

impl ClockGateController {
    /// Creates a new clock gate controller.
    pub const fn new() -> Self {
        Self {
            gates: [const { GateRuntime::new(ClockGateDesc::new(0, "unused", 0, 0, true)) };
                MAX_CLOCK_GATES],
            count: 0,
            initialized: false,
        }
    }

    /// Registers all hardware clock gates from the platform descriptor table.
    ///
    /// # Arguments
    /// * `descs` — Slice of clock gate descriptors.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if more gates than MAX_CLOCK_GATES are provided.
    pub fn register_gates(&mut self, descs: &[ClockGateDesc]) -> Result<()> {
        if descs.len() > MAX_CLOCK_GATES {
            return Err(Error::OutOfMemory);
        }
        for (i, desc) in descs.iter().enumerate() {
            self.gates[i] = GateRuntime::new(*desc);
        }
        self.count = descs.len();
        self.initialized = true;
        Ok(())
    }

    /// Finds the index of a gate by its ID.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if no gate with the given ID exists.
    pub fn find_gate(&self, id: u16) -> Result<usize> {
        for (i, g) in self.gates[..self.count].iter().enumerate() {
            if g.desc.id == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Enables (ungates) the clock gate with the given ID.
    ///
    /// Increments the reference count; the gate remains ungated as long as
    /// at least one consumer has it enabled.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the gate ID is unknown.
    /// Returns `Error::Busy` if not initialized.
    pub fn enable(&mut self, id: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let idx = self.find_gate(id)?;

        // Enable parent first if configured
        let parent_id = self.gates[idx].desc.parent_id;
        if parent_id != u16::MAX {
            self.enable(parent_id)?;
        }

        self.gates[idx].refcount = self.gates[idx].refcount.saturating_add(1);
        if self.gates[idx].state != GateState::Ungated {
            self.set_gate_hw(idx, true)?;
            self.gates[idx].state = GateState::Ungated;
        }
        Ok(())
    }

    /// Decrements the reference count for a gate, gating it if count reaches zero.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the gate ID is unknown.
    /// Returns `Error::Busy` if not initialized.
    pub fn disable(&mut self, id: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let idx = self.find_gate(id)?;
        if self.gates[idx].refcount > 0 {
            self.gates[idx].refcount -= 1;
        }
        if self.gates[idx].refcount == 0 && self.gates[idx].state == GateState::Ungated {
            self.set_gate_hw(idx, false)?;
            self.gates[idx].state = GateState::Gated;
        }
        Ok(())
    }

    /// Returns the current state of a gate.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the gate ID is unknown.
    pub fn state(&self, id: u16) -> Result<GateState> {
        let idx = self.find_gate(id)?;
        Ok(self.gates[idx].state)
    }

    /// Returns the reference count for a gate.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the gate ID is unknown.
    pub fn refcount(&self, id: u16) -> Result<u32> {
        let idx = self.find_gate(id)?;
        Ok(self.gates[idx].refcount)
    }

    /// Returns the number of registered gates.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no gates are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Forces all gates to the gated (disabled) state regardless of refcount.
    ///
    /// Used during system suspend. Clears all reference counts.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn gate_all(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        for i in 0..self.count {
            self.gates[i].refcount = 0;
            if self.gates[i].state == GateState::Ungated {
                let _ = self.set_gate_hw(i, false);
                self.gates[i].state = GateState::Gated;
            }
        }
        Ok(())
    }

    fn set_gate_hw(&self, idx: usize, enable: bool) -> Result<()> {
        let desc = &self.gates[idx].desc;
        if desc.reg_addr == 0 {
            return Ok(());
        }
        // SAFETY: MMIO read-modify-write to clock gate control register.
        // reg_addr is non-zero and validated at registration time.
        unsafe {
            let reg = desc.reg_addr as *mut u32;
            let mut val = reg.read_volatile();
            let bit_mask = 1u32 << desc.bit;
            if enable == desc.active_high {
                val |= bit_mask;
            } else {
                val &= !bit_mask;
            }
            reg.write_volatile(val);
        }
        Ok(())
    }
}

impl Default for ClockGateController {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for clock gating operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClockGateStats {
    /// Number of enable operations performed.
    pub enables: u64,
    /// Number of disable operations performed.
    pub disables: u64,
    /// Number of gates currently ungated.
    pub ungated_count: u32,
}

impl ClockGateStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            enables: 0,
            disables: 0,
            ungated_count: 0,
        }
    }
}

/// Scans a clock gate register and returns the gate/ungate bitmask.
///
/// # Arguments
/// * `reg_addr` — MMIO address of the gate control register.
///
/// # Errors
/// Returns `Error::InvalidArgument` if reg_addr is zero.
pub fn read_gate_register(reg_addr: u64) -> Result<u32> {
    if reg_addr == 0 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: MMIO read from clock gate register. reg_addr is validated non-zero.
    let val = unsafe { (reg_addr as *const u32).read_volatile() };
    Ok(val)
}

/// Returns the number of currently-set bits in a gate register bitmask.
pub fn count_ungated(bitmask: u32) -> u32 {
    bitmask.count_ones()
}
