// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe native hotplug controller driver.
//!
//! Implements the PCIe native hotplug (SHPC-compatible) mechanism that
//! allows devices to be added and removed at runtime without system reset.
//!
//! The PCIe slot capability registers are accessed via the PCIe Slot
//! Control/Status registers within the device's extended capability space.
//!
//! Operations:
//! - Slot presence detection
//! - Power sequencing (enabling/disabling slot power)
//! - Attention indicator and power indicator control
//! - Hot-plug interrupt handling
//!
//! Reference: PCI Express Base Specification Rev. 6.0, §6.7 — Hot-Plug.

use oncrix_lib::{Error, Result};

// ── PCIe Slot Capability/Control/Status Offsets ────────────────────────────
// These are within the PCIe capability structure (found via capability list).

/// Slot Capabilities Register offset from capability base.
pub const SLOT_CAP: u16 = 0x14;
/// Slot Control Register.
pub const SLOT_CTL: u16 = 0x18;
/// Slot Status Register.
pub const SLOT_STS: u16 = 0x1A;

// ── Slot Capability Bits ───────────────────────────────────────────────────

/// Attention Button Present.
pub const CAP_ATTN_BTN: u32 = 1 << 0;
/// Power Controller Present.
pub const CAP_PWR_CTRL: u32 = 1 << 1;
/// MRL Sensor Present.
pub const CAP_MRL_SENSOR: u32 = 1 << 2;
/// Attention Indicator Present.
pub const CAP_ATTN_IND: u32 = 1 << 3;
/// Power Indicator Present.
pub const CAP_PWR_IND: u32 = 1 << 4;
/// Hot-Plug Surprise.
pub const CAP_HP_SURPRISE: u32 = 1 << 5;
/// Hot-Plug Capable.
pub const CAP_HP_CAPABLE: u32 = 1 << 6;
/// Slot Power Limit (bits 14:7) and scale (bits 16:15).
pub const CAP_SLOT_POWER_MASK: u32 = 0x7F80;
/// Electromechanical Interlock Present.
pub const CAP_EMI: u32 = 1 << 17;
/// No Command Completed Support.
pub const CAP_NO_CMD_COMPLETED: u32 = 1 << 18;
/// Physical Slot Number (bits 31:19).
pub const CAP_SLOT_NUMBER_SHIFT: u32 = 19;

// ── Slot Control Bits ──────────────────────────────────────────────────────

/// Attention Button Pressed Enable.
pub const CTL_ATTN_BTN_EN: u16 = 1 << 0;
/// Power Fault Detected Enable.
pub const CTL_PWR_FAULT_EN: u16 = 1 << 1;
/// MRL Sensor Changed Enable.
pub const CTL_MRL_EN: u16 = 1 << 2;
/// Presence Detect Changed Enable.
pub const CTL_PRESENCE_EN: u16 = 1 << 3;
/// Command Completed Interrupt Enable.
pub const CTL_CMD_CPLT_EN: u16 = 1 << 4;
/// Hot-Plug Interrupt Enable.
pub const CTL_HP_INT_EN: u16 = 1 << 5;
/// Attention Indicator Control (2 bits, 7:6). 01=on, 10=blink, 11=off.
pub const CTL_ATTN_IND_SHIFT: u16 = 6;
/// Power Indicator Control (2 bits, 9:8).
pub const CTL_PWR_IND_SHIFT: u16 = 8;
/// Power Controller Control: 0=on, 1=off.
pub const CTL_PWR_CTRL: u16 = 1 << 10;
/// Electromechanical Interlock Control.
pub const CTL_EMI_CTRL: u16 = 1 << 11;
/// Data Link Layer State Changed Enable.
pub const CTL_DLLSC_EN: u16 = 1 << 12;

// ── Slot Status Bits ───────────────────────────────────────────────────────

/// Attention Button Pressed.
pub const STS_ATTN_BTN: u16 = 1 << 0;
/// Power Fault Detected.
pub const STS_PWR_FAULT: u16 = 1 << 1;
/// MRL Sensor Changed.
pub const STS_MRL_CHANGED: u16 = 1 << 2;
/// Presence Detect Changed.
pub const STS_PRESENCE_CHANGED: u16 = 1 << 3;
/// Command Completed.
pub const STS_CMD_CPLT: u16 = 1 << 4;
/// MRL Sensor State: 0=closed, 1=open.
pub const STS_MRL_STATE: u16 = 1 << 5;
/// Presence Detect State: 0=empty, 1=card present.
pub const STS_PRESENCE: u16 = 1 << 6;
/// Electromechanical Interlock Status.
pub const STS_EMI: u16 = 1 << 7;
/// Data Link Layer State Changed.
pub const STS_DLLSC: u16 = 1 << 8;

/// Maximum hotplug slots tracked.
const MAX_SLOTS: usize = 64;

// ── Indicator State ────────────────────────────────────────────────────────

/// PCIe slot indicator state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IndicatorState {
    On = 1,
    Blink = 2,
    Off = 3,
}

// ── Slot Power State ───────────────────────────────────────────────────────

/// Slot power state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotPower {
    On,
    Off,
}

// ── MMIO helpers ───────────────────────────────────────────────────────────

#[inline]
unsafe fn read16(base: usize, offset: u16) -> u16 {
    // SAFETY: caller guarantees base+offset is valid ECAM capability space.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u16) }
}

#[inline]
unsafe fn write16(base: usize, offset: u16, val: u16) {
    // SAFETY: caller guarantees base+offset is valid ECAM capability space.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u16, val) }
}

#[inline]
unsafe fn read32(base: usize, offset: u16) -> u32 {
    // SAFETY: caller guarantees base+offset is valid ECAM capability space.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

// ── PCIe Hotplug Slot ──────────────────────────────────────────────────────

/// A single PCIe hotplug slot.
pub struct HotplugSlot {
    /// MMIO base of the PCIe capability registers for this port.
    cap_base: usize,
    /// Physical slot number (from SLOT_CAP).
    pub slot_number: u32,
    /// Slot capability flags.
    pub capabilities: u32,
    /// Current power state.
    pub power: SlotPower,
    /// True if a device is currently present.
    pub device_present: bool,
}

impl HotplugSlot {
    /// Create a hotplug slot from a capability MMIO base.
    ///
    /// # Safety
    /// `cap_base` must point to the start of the PCIe capability structure
    /// (where offset 0x14 is the Slot Capabilities register).
    pub unsafe fn new(cap_base: usize) -> Self {
        // SAFETY: reading SLOT_CAP to identify the slot.
        let cap = unsafe { read32(cap_base, SLOT_CAP) };
        let slot_number = cap >> CAP_SLOT_NUMBER_SHIFT;
        Self {
            cap_base,
            slot_number,
            capabilities: cap,
            power: SlotPower::Off,
            device_present: false,
        }
    }

    /// Read the slot status register.
    pub fn status(&self) -> u16 {
        // SAFETY: SLOT_STS within the capability structure.
        unsafe { read16(self.cap_base, SLOT_STS) }
    }

    /// Read the slot control register.
    pub fn control(&self) -> u16 {
        // SAFETY: SLOT_CTL within the capability structure.
        unsafe { read16(self.cap_base, SLOT_CTL) }
    }

    /// Write the slot control register.
    fn write_control(&self, val: u16) {
        // SAFETY: SLOT_CTL write programs the hotplug controller.
        unsafe { write16(self.cap_base, SLOT_CTL, val) }
    }

    /// Detect whether a card is present (reads Presence Detect State).
    pub fn detect_presence(&mut self) -> bool {
        let sts = self.status();
        self.device_present = sts & STS_PRESENCE != 0;
        self.device_present
    }

    /// Enable slot power.
    pub fn power_on(&mut self) -> Result<()> {
        if self.capabilities & CAP_PWR_CTRL == 0 {
            return Err(Error::NotImplemented);
        }
        let ctl = self.control() & !CTL_PWR_CTRL; // clear bit = power on
        self.write_control(ctl);
        self.power = SlotPower::On;
        // Wait for Command Completed.
        for _ in 0..100_000 {
            if self.status() & STS_CMD_CPLT != 0 {
                // Clear the CC status bit by writing 1.
                unsafe { write16(self.cap_base, SLOT_STS, STS_CMD_CPLT) }
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Disable slot power.
    pub fn power_off(&mut self) -> Result<()> {
        if self.capabilities & CAP_PWR_CTRL == 0 {
            return Err(Error::NotImplemented);
        }
        let ctl = self.control() | CTL_PWR_CTRL; // set bit = power off
        self.write_control(ctl);
        self.power = SlotPower::Off;
        Ok(())
    }

    /// Set the power indicator state.
    pub fn set_power_indicator(&self, state: IndicatorState) {
        if self.capabilities & CAP_PWR_IND == 0 {
            return;
        }
        let mut ctl = self.control();
        ctl &= !(0x3 << CTL_PWR_IND_SHIFT);
        ctl |= (state as u16) << CTL_PWR_IND_SHIFT;
        self.write_control(ctl);
    }

    /// Set the attention indicator state.
    pub fn set_attention_indicator(&self, state: IndicatorState) {
        if self.capabilities & CAP_ATTN_IND == 0 {
            return;
        }
        let mut ctl = self.control();
        ctl &= !(0x3 << CTL_ATTN_IND_SHIFT);
        ctl |= (state as u16) << CTL_ATTN_IND_SHIFT;
        self.write_control(ctl);
    }

    /// Enable hotplug interrupt sources.
    pub fn enable_interrupts(&self) {
        let ctl = self.control() | CTL_PRESENCE_EN | CTL_HP_INT_EN | CTL_CMD_CPLT_EN | CTL_DLLSC_EN;
        self.write_control(ctl);
    }

    /// Clear all pending status bits.
    pub fn clear_status(&self) {
        let sts = self.status();
        // SAFETY: writing 1 to RW1C status bits clears them.
        unsafe { write16(self.cap_base, SLOT_STS, sts) }
    }

    /// Process a hotplug interrupt and return which events fired.
    pub fn handle_interrupt(&mut self) -> u16 {
        let sts = self.status();
        self.clear_status();
        if sts & STS_PRESENCE_CHANGED != 0 {
            self.detect_presence();
        }
        sts
    }
}

// ── Hotplug Controller ─────────────────────────────────────────────────────

/// PCIe native hotplug controller.
pub struct PciHotplug {
    slots: [Option<HotplugSlot>; MAX_SLOTS],
    count: usize,
}

impl PciHotplug {
    /// Create an empty hotplug controller.
    pub fn new() -> Self {
        Self {
            slots: [const { None }; MAX_SLOTS],
            count: 0,
        }
    }

    /// Register a hotplug slot.
    pub fn add_slot(&mut self, slot: HotplugSlot) -> Result<usize> {
        if self.count >= MAX_SLOTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.slots[idx] = Some(slot);
        self.count += 1;
        Ok(idx)
    }

    /// Get a reference to a slot.
    pub fn slot(&self, idx: usize) -> Option<&HotplugSlot> {
        self.slots.get(idx)?.as_ref()
    }

    /// Get a mutable reference to a slot.
    pub fn slot_mut(&mut self, idx: usize) -> Option<&mut HotplugSlot> {
        self.slots.get_mut(idx)?.as_mut()
    }

    /// Return number of registered slots.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no slots are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Poll all slots for presence changes, return count of changes.
    pub fn poll_presence(&mut self) -> usize {
        let mut changes = 0;
        for slot in self.slots[..self.count].iter_mut().flatten() {
            let was_present = slot.device_present;
            let is_present = slot.detect_presence();
            if was_present != is_present {
                changes += 1;
            }
        }
        changes
    }

    /// Enable hotplug interrupts on all slots.
    pub fn enable_all_interrupts(&self) {
        for slot in self.slots[..self.count].iter().flatten() {
            slot.enable_interrupts();
        }
    }
}

impl Default for PciHotplug {
    fn default() -> Self {
        Self::new()
    }
}
