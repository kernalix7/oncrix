// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe native hotplug controller driver.
//!
//! Implements the PCIe native hotplug mechanism (PCIe Base Spec §6.7)
//! that allows devices to be added and removed at runtime without a
//! system reset.
//!
//! # Architecture
//!
//! - **[`SlotState`]** — five-state machine tracking slot lifecycle:
//!   `NotPresent → PoweredOff → PoweredOn → Enabled → LinkActive`.
//! - **[`HotplugSlot`]** — wraps a single PCIe slot capability structure
//!   (accessed via MMIO), owns the slot state machine and indicator LEDs.
//! - **[`PcieHotplugController`]** — fixed-size array of up to
//!   [`MAX_SLOTS`] slots; handles hot-add and hot-remove sequences.
//!
//! # Hot-add sequence
//!
//! 1. `detect` — read Presence Detect State from Slot Status register.
//! 2. `power_on` — assert Power Controller Control (bit clear = on).
//! 3. `wait_link` — poll Data Link Layer State Changed until link is up.
//! 4. `enable` — transition to `Enabled`; enumerate the device.
//!
//! # Hot-remove sequence
//!
//! 1. `quiesce` — notify OS to stop I/O (software responsibility).
//! 2. `disable` — transition slot from `Enabled` back to `PoweredOn`.
//! 3. `power_off` — assert Power Controller Control (bit set = off).
//! 4. `cleanup` — transition to `NotPresent`; remove device from tree.
//!
//! # Register layout
//!
//! The Slot Capability, Slot Control, and Slot Status registers sit at
//! fixed offsets within the PCIe Capability Structure:
//!
//! ```text
//! offset 0x14 — Slot Capabilities  (32-bit, RO)
//! offset 0x18 — Slot Control       (16-bit, RW)
//! offset 0x1A — Slot Status        (16-bit, RW1C)
//! ```
//!
//! Reference: PCI Express Base Specification Rev. 6.0, §7.8 — Hot-Plug Registers.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — maximum array sizes
// ---------------------------------------------------------------------------

/// Maximum number of hotplug slots tracked by a single controller.
pub const MAX_SLOTS: usize = 32;

// ---------------------------------------------------------------------------
// Register offsets within the PCIe Capability Structure
// ---------------------------------------------------------------------------

/// Slot Capabilities Register offset from capability structure base.
pub const SLOT_CAP_OFF: u16 = 0x14;

/// Slot Control Register offset.
pub const SLOT_CTL_OFF: u16 = 0x18;

/// Slot Status Register offset.
pub const SLOT_STS_OFF: u16 = 0x1A;

// ---------------------------------------------------------------------------
// Slot Capability register bits (32-bit, read-only)
// ---------------------------------------------------------------------------

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
/// Hot-Plug Surprise capable.
pub const CAP_HP_SURPRISE: u32 = 1 << 5;
/// Hot-Plug Capable.
pub const CAP_HP_CAPABLE: u32 = 1 << 6;
/// Electromechanical Interlock Present.
pub const CAP_EMI: u32 = 1 << 17;
/// No Command Completed Support.
pub const CAP_NO_CMD_COMPLETED: u32 = 1 << 18;
/// Physical Slot Number bit-shift (bits 31:19).
pub const CAP_SLOT_NUMBER_SHIFT: u32 = 19;
/// Physical Slot Number mask (after shift).
pub const CAP_SLOT_NUMBER_MASK: u32 = 0x1FFF;

// ---------------------------------------------------------------------------
// Slot Control register bits (16-bit, read/write)
// ---------------------------------------------------------------------------

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
/// Attention Indicator Control bit-shift (bits 7:6). 01=on, 10=blink, 11=off.
pub const CTL_ATTN_IND_SHIFT: u16 = 6;
/// Power Indicator Control bit-shift (bits 9:8).
pub const CTL_PWR_IND_SHIFT: u16 = 8;
/// Power Controller Control: 0 = power on, 1 = power off.
pub const CTL_PWR_CTRL: u16 = 1 << 10;
/// Electromechanical Interlock Control.
pub const CTL_EMI_CTRL: u16 = 1 << 11;
/// Data Link Layer State Changed Enable.
pub const CTL_DLLSC_EN: u16 = 1 << 12;

// ---------------------------------------------------------------------------
// Slot Status register bits (16-bit, RW1C)
// ---------------------------------------------------------------------------

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
/// MRL Sensor State: 0 = closed (device locked), 1 = open.
pub const STS_MRL_STATE: u16 = 1 << 5;
/// Presence Detect State: 0 = slot empty, 1 = card present.
pub const STS_PRESENCE: u16 = 1 << 6;
/// Electromechanical Interlock Status.
pub const STS_EMI: u16 = 1 << 7;
/// Data Link Layer State Changed (link-up/down event).
pub const STS_DLLSC: u16 = 1 << 8;

// ---------------------------------------------------------------------------
// Iteration limit for polling loops
// ---------------------------------------------------------------------------

/// Number of polling iterations to wait for a command-completed or
/// link-up event before giving up.
const POLL_LIMIT: u32 = 100_000;

// ---------------------------------------------------------------------------
// SlotState
// ---------------------------------------------------------------------------

/// PCIe slot state machine states.
///
/// Valid transitions:
/// - `NotPresent → PoweredOff` (card inserted, detection)
/// - `PoweredOff → PoweredOn` (power asserted)
/// - `PoweredOn → Enabled` (link trained, device enumerable)
/// - `Enabled → LinkActive` (device driver active)
/// - `LinkActive → Enabled` (driver unloaded)
/// - `Enabled → PoweredOn` (prepare for removal)
/// - `PoweredOn → PoweredOff` (power removed)
/// - `PoweredOff → NotPresent` (card ejected)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// No card is present in the slot.
    NotPresent,
    /// Card is present but slot power is off.
    PoweredOff,
    /// Slot power is on; link training not yet complete.
    PoweredOn,
    /// Link training complete; device is enumerable.
    Enabled,
    /// Device driver is active and the link is fully operational.
    LinkActive,
}

impl Default for SlotState {
    fn default() -> Self {
        SlotState::NotPresent
    }
}

// ---------------------------------------------------------------------------
// IndicatorState
// ---------------------------------------------------------------------------

/// PCIe slot LED indicator state.
///
/// Encoded as a 2-bit field in the Slot Control register:
/// `01` = on, `10` = blink, `11` = off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IndicatorState {
    /// Indicator LED is on (solid).
    On = 1,
    /// Indicator LED is blinking.
    Blink = 2,
    /// Indicator LED is off.
    Off = 3,
}

// ---------------------------------------------------------------------------
// SlotCapabilities
// ---------------------------------------------------------------------------

/// Parsed slot capability flags from the Slot Capabilities register.
#[derive(Debug, Clone, Copy)]
pub struct SlotCapabilities {
    /// Raw 32-bit capability register value.
    pub raw: u32,
    /// Physical slot number embedded in the capability register.
    pub slot_number: u32,
}

impl SlotCapabilities {
    /// Parses capabilities from the raw register value.
    pub const fn from_raw(raw: u32) -> Self {
        Self {
            raw,
            slot_number: (raw >> CAP_SLOT_NUMBER_SHIFT) & CAP_SLOT_NUMBER_MASK,
        }
    }

    /// Returns `true` if a Power Controller is present.
    pub const fn has_power_controller(&self) -> bool {
        self.raw & CAP_PWR_CTRL != 0
    }

    /// Returns `true` if an Attention Indicator is present.
    pub const fn has_attention_indicator(&self) -> bool {
        self.raw & CAP_ATTN_IND != 0
    }

    /// Returns `true` if a Power Indicator is present.
    pub const fn has_power_indicator(&self) -> bool {
        self.raw & CAP_PWR_IND != 0
    }

    /// Returns `true` if an MRL Sensor is present.
    pub const fn has_mrl_sensor(&self) -> bool {
        self.raw & CAP_MRL_SENSOR != 0
    }

    /// Returns `true` if the slot is Hot-Plug Capable.
    pub const fn is_hotplug_capable(&self) -> bool {
        self.raw & CAP_HP_CAPABLE != 0
    }

    /// Returns `true` if Hot-Plug Surprise (blind insertion) is supported.
    pub const fn has_hp_surprise(&self) -> bool {
        self.raw & CAP_HP_SURPRISE != 0
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 16-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address aligned to 2 bytes.
#[inline]
unsafe fn read_mmio16(base: usize, offset: u16) -> u16 {
    // SAFETY: Caller guarantees the address is valid mapped MMIO space,
    // properly aligned for a 16-bit volatile read.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u16) }
}

/// Write a 16-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address aligned to 2 bytes.
#[inline]
unsafe fn write_mmio16(base: usize, offset: u16, val: u16) {
    // SAFETY: Caller guarantees the address is valid mapped MMIO space,
    // properly aligned for a 16-bit volatile write.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u16, val) }
}

/// Read a 32-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address aligned to 4 bytes.
#[inline]
unsafe fn read_mmio32(base: usize, offset: u16) -> u32 {
    // SAFETY: Caller guarantees the address is valid mapped MMIO space,
    // properly aligned for a 32-bit volatile read.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

// ---------------------------------------------------------------------------
// HotplugSlot
// ---------------------------------------------------------------------------

/// A single PCIe hotplug-capable slot.
///
/// Wraps the slot's PCIe capability structure accessed via MMIO and
/// owns the slot state machine and last observed interrupt status.
pub struct HotplugSlot {
    /// MMIO base address of the PCIe capability structure for this port.
    ///
    /// Offsets `SLOT_CAP_OFF`, `SLOT_CTL_OFF`, `SLOT_STS_OFF` are relative
    /// to this address.
    cap_base: usize,
    /// Parsed slot capability flags.
    pub capabilities: SlotCapabilities,
    /// Current slot state machine state.
    pub state: SlotState,
    /// Last raw status bits observed by [`handle_interrupt`](Self::handle_interrupt).
    pub last_status: u16,
}

impl HotplugSlot {
    /// Creates a `HotplugSlot` from a PCIe capability structure MMIO base.
    ///
    /// Reads the Slot Capabilities register to discover hardware capabilities
    /// and the physical slot number.
    ///
    /// # Safety
    ///
    /// `cap_base` must be the start of a PCIe Capability Structure where
    /// offset `0x14` contains the Slot Capabilities register.  The address
    /// must remain valid for the lifetime of this struct.
    pub unsafe fn new(cap_base: usize) -> Self {
        // SAFETY: The caller guarantees cap_base points to a valid, mapped
        // PCIe capability structure.  SLOT_CAP_OFF (0x14) is 32-bit aligned.
        let raw_cap = unsafe { read_mmio32(cap_base, SLOT_CAP_OFF) };
        let capabilities = SlotCapabilities::from_raw(raw_cap);
        Self {
            cap_base,
            capabilities,
            state: SlotState::NotPresent,
            last_status: 0,
        }
    }

    /// Reads the raw Slot Status register.
    pub fn read_status(&self) -> u16 {
        // SAFETY: cap_base is a valid mapped PCIe capability structure;
        // SLOT_STS_OFF is the 16-bit status register offset.
        unsafe { read_mmio16(self.cap_base, SLOT_STS_OFF) }
    }

    /// Reads the raw Slot Control register.
    pub fn read_control(&self) -> u16 {
        // SAFETY: cap_base is a valid mapped PCIe capability structure;
        // SLOT_CTL_OFF is the 16-bit control register offset.
        unsafe { read_mmio16(self.cap_base, SLOT_CTL_OFF) }
    }

    /// Writes the Slot Control register.
    fn write_control(&self, val: u16) {
        // SAFETY: cap_base is a valid mapped PCIe capability structure;
        // writing SLOT_CTL_OFF programs the hotplug controller.
        unsafe { write_mmio16(self.cap_base, SLOT_CTL_OFF, val) }
    }

    /// Writes 1 to the given status bits to acknowledge (clear) them.
    ///
    /// The Slot Status register uses RW1C semantics.
    fn clear_status_bits(&self, bits: u16) {
        // SAFETY: cap_base is a valid mapped PCIe capability structure;
        // RW1C status bits are cleared by writing 1 to them.
        unsafe { write_mmio16(self.cap_base, SLOT_STS_OFF, bits) }
    }

    // -- Slot state machine transitions ------------------------------------

    /// Step 1 of hot-add: detect presence.
    ///
    /// Reads `Presence Detect State` from Slot Status. Transitions the
    /// slot from `NotPresent` to `PoweredOff` if a card is detected.
    /// Returns `true` if a card is present.
    pub fn detect(&mut self) -> bool {
        let sts = self.read_status();
        let present = sts & STS_PRESENCE != 0;
        if present && self.state == SlotState::NotPresent {
            self.state = SlotState::PoweredOff;
        } else if !present && self.state != SlotState::NotPresent {
            self.state = SlotState::NotPresent;
        }
        present
    }

    /// Step 2 of hot-add: enable slot power.
    ///
    /// Clears `CTL_PWR_CTRL` (0 = power on) and waits for `STS_CMD_CPLT`.
    /// Transitions `PoweredOff → PoweredOn`.
    ///
    /// Returns [`Error::NotImplemented`] if no Power Controller is present.
    /// Returns [`Error::Busy`] if command-completed did not arrive in time.
    pub fn power_on(&mut self) -> Result<()> {
        if !self.capabilities.has_power_controller() {
            return Err(Error::NotImplemented);
        }
        if self.state != SlotState::PoweredOff {
            return Err(Error::InvalidArgument);
        }
        let ctl = self.read_control() & !CTL_PWR_CTRL; // clear bit → power on
        self.write_control(ctl);
        self.wait_command_completed()?;
        self.set_power_indicator(IndicatorState::On);
        self.state = SlotState::PoweredOn;
        Ok(())
    }

    /// Step 3 of hot-add: wait for link training.
    ///
    /// Polls the Data Link Layer State Changed bit until it is set,
    /// indicating that the link has come up.
    /// Transitions `PoweredOn → Enabled`.
    ///
    /// Returns [`Error::Busy`] if the link does not come up in time.
    pub fn wait_link(&mut self) -> Result<()> {
        if self.state != SlotState::PoweredOn {
            return Err(Error::InvalidArgument);
        }
        for _ in 0..POLL_LIMIT {
            if self.read_status() & STS_DLLSC != 0 {
                // Clear the DLLSC bit.
                self.clear_status_bits(STS_DLLSC);
                self.state = SlotState::Enabled;
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Step 4 of hot-add: mark slot as fully active.
    ///
    /// Transitions `Enabled → LinkActive`.  Called after the device has
    /// been enumerated and a driver has been bound.
    pub fn enable(&mut self) -> Result<()> {
        if self.state != SlotState::Enabled {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::LinkActive;
        Ok(())
    }

    /// Step 1 of hot-remove: quiesce (software).
    ///
    /// Transitions `LinkActive → Enabled`.  The caller must stop all
    /// I/O to the device before invoking this function.
    pub fn quiesce(&mut self) -> Result<()> {
        if self.state != SlotState::LinkActive {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::Enabled;
        Ok(())
    }

    /// Step 2 of hot-remove: disable slot.
    ///
    /// Transitions `Enabled → PoweredOn`.
    pub fn disable(&mut self) -> Result<()> {
        if self.state != SlotState::Enabled {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::PoweredOn;
        Ok(())
    }

    /// Step 3 of hot-remove: remove slot power.
    ///
    /// Sets `CTL_PWR_CTRL` (1 = power off).
    /// Transitions `PoweredOn → PoweredOff`.
    ///
    /// Returns [`Error::NotImplemented`] if no Power Controller is present.
    pub fn power_off(&mut self) -> Result<()> {
        if !self.capabilities.has_power_controller() {
            return Err(Error::NotImplemented);
        }
        if self.state != SlotState::PoweredOn {
            return Err(Error::InvalidArgument);
        }
        let ctl = self.read_control() | CTL_PWR_CTRL; // set bit → power off
        self.write_control(ctl);
        self.set_power_indicator(IndicatorState::Off);
        self.state = SlotState::PoweredOff;
        Ok(())
    }

    /// Step 4 of hot-remove: clean up after card ejection.
    ///
    /// Transitions `PoweredOff → NotPresent`.
    pub fn cleanup(&mut self) -> Result<()> {
        if self.state != SlotState::PoweredOff {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::NotPresent;
        Ok(())
    }

    // -- Indicator LED control ---------------------------------------------

    /// Sets the power indicator LED state.
    ///
    /// Writes the 2-bit `CTL_PWR_IND` field in the Slot Control register.
    /// No-op if no Power Indicator is present.
    pub fn set_power_indicator(&self, state: IndicatorState) {
        if !self.capabilities.has_power_indicator() {
            return;
        }
        let mut ctl = self.read_control();
        ctl &= !(0x3 << CTL_PWR_IND_SHIFT);
        ctl |= (state as u16) << CTL_PWR_IND_SHIFT;
        self.write_control(ctl);
    }

    /// Sets the attention indicator LED state.
    ///
    /// Writes the 2-bit `CTL_ATTN_IND` field in the Slot Control register.
    /// No-op if no Attention Indicator is present.
    pub fn set_attention_indicator(&self, state: IndicatorState) {
        if !self.capabilities.has_attention_indicator() {
            return;
        }
        let mut ctl = self.read_control();
        ctl &= !(0x3 << CTL_ATTN_IND_SHIFT);
        ctl |= (state as u16) << CTL_ATTN_IND_SHIFT;
        self.write_control(ctl);
    }

    // -- Interrupt handling ------------------------------------------------

    /// Enables all relevant hotplug interrupt sources in the Slot Control
    /// register.
    pub fn enable_interrupts(&self) {
        let ctl =
            self.read_control() | CTL_PRESENCE_EN | CTL_HP_INT_EN | CTL_CMD_CPLT_EN | CTL_DLLSC_EN;
        self.write_control(ctl);
    }

    /// Disables all hotplug interrupt sources.
    pub fn disable_interrupts(&self) {
        let ctl = self.read_control()
            & !(CTL_PRESENCE_EN | CTL_HP_INT_EN | CTL_CMD_CPLT_EN | CTL_DLLSC_EN);
        self.write_control(ctl);
    }

    /// Handles a hotplug interrupt.
    ///
    /// Reads the Slot Status register, clears all pending RW1C bits, and
    /// updates `last_status`.  If `STS_PRESENCE_CHANGED` is set, calls
    /// [`detect`](Self::detect) to advance the state machine.
    ///
    /// Returns the raw status bits that were set before clearing.
    pub fn handle_interrupt(&mut self) -> u16 {
        let sts = self.read_status();
        self.clear_status_bits(sts);
        self.last_status = sts;
        if sts & STS_PRESENCE_CHANGED != 0 {
            self.detect();
        }
        sts
    }

    // -- Helpers -----------------------------------------------------------

    /// Polls for `STS_CMD_CPLT` and clears it when observed.
    ///
    /// Returns [`Error::Busy`] if the bit does not appear within
    /// [`POLL_LIMIT`] iterations.
    fn wait_command_completed(&self) -> Result<()> {
        // If the controller asserts no-command-completed, skip the wait.
        if self.capabilities.raw & CAP_NO_CMD_COMPLETED != 0 {
            return Ok(());
        }
        for _ in 0..POLL_LIMIT {
            if self.read_status() & STS_CMD_CPLT != 0 {
                self.clear_status_bits(STS_CMD_CPLT);
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Returns the physical slot number from the capabilities register.
    pub const fn slot_number(&self) -> u32 {
        self.capabilities.slot_number
    }
}

impl core::fmt::Debug for HotplugSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HotplugSlot")
            .field("slot_number", &self.capabilities.slot_number)
            .field("state", &self.state)
            .field("last_status", &self.last_status)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PcieHotplugController
// ---------------------------------------------------------------------------

/// PCIe native hotplug controller.
///
/// Manages up to [`MAX_SLOTS`] [`HotplugSlot`] instances and provides
/// aggregate operations (poll presence, enable interrupts on all slots,
/// execute full hot-add and hot-remove sequences).
pub struct PcieHotplugController {
    /// Fixed-size slot array.
    slots: [Option<HotplugSlot>; MAX_SLOTS],
    /// Number of registered slots.
    count: usize,
}

impl PcieHotplugController {
    /// Creates an empty hotplug controller.
    pub fn new() -> Self {
        Self {
            slots: [const { None }; MAX_SLOTS],
            count: 0,
        }
    }

    /// Registers a slot with the controller.
    ///
    /// Returns the slot index on success, or [`Error::OutOfMemory`]
    /// if [`MAX_SLOTS`] have already been registered.
    pub fn add_slot(&mut self, slot: HotplugSlot) -> Result<usize> {
        if self.count >= MAX_SLOTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.slots[idx] = Some(slot);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a shared reference to the slot at `idx`.
    pub fn slot(&self, idx: usize) -> Option<&HotplugSlot> {
        self.slots.get(idx)?.as_ref()
    }

    /// Returns a mutable reference to the slot at `idx`.
    pub fn slot_mut(&mut self, idx: usize) -> Option<&mut HotplugSlot> {
        self.slots.get_mut(idx)?.as_mut()
    }

    /// Returns the number of registered slots.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no slots have been registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Polls all slots for presence changes.
    ///
    /// Returns the number of slots whose presence state changed.
    pub fn poll_presence(&mut self) -> usize {
        let mut changes = 0usize;
        for slot in self.slots[..self.count].iter_mut().flatten() {
            let was_active = slot.state != SlotState::NotPresent;
            slot.detect();
            let is_active = slot.state != SlotState::NotPresent;
            if was_active != is_active {
                changes += 1;
            }
        }
        changes
    }

    /// Enables hotplug interrupts on all registered slots.
    pub fn enable_all_interrupts(&self) {
        for slot in self.slots[..self.count].iter().flatten() {
            slot.enable_interrupts();
        }
    }

    /// Disables hotplug interrupts on all registered slots.
    pub fn disable_all_interrupts(&self) {
        for slot in self.slots[..self.count].iter().flatten() {
            slot.disable_interrupts();
        }
    }

    /// Dispatches a hotplug interrupt to the slot at `idx`.
    ///
    /// Returns the raw status bits, or [`Error::NotFound`] if the slot
    /// does not exist.
    pub fn handle_interrupt(&mut self, idx: usize) -> Result<u16> {
        let slot = self
            .slots
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        Ok(slot.handle_interrupt())
    }

    /// Executes the full hot-add sequence on the slot at `idx`.
    ///
    /// Steps: detect → power_on → wait_link → enable.
    ///
    /// Returns [`Error::NotFound`] if no card is detected after `detect`.
    pub fn hot_add(&mut self, idx: usize) -> Result<()> {
        let slot = self
            .slots
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        let present = slot.detect();
        if !present {
            return Err(Error::NotFound);
        }
        slot.set_attention_indicator(IndicatorState::Blink);
        slot.power_on()?;
        slot.wait_link()?;
        slot.enable()?;
        slot.set_attention_indicator(IndicatorState::Off);
        Ok(())
    }

    /// Executes the full hot-remove sequence on the slot at `idx`.
    ///
    /// Steps: quiesce → disable → power_off → cleanup.
    pub fn hot_remove(&mut self, idx: usize) -> Result<()> {
        let slot = self
            .slots
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        slot.set_attention_indicator(IndicatorState::Blink);
        slot.quiesce()?;
        slot.disable()?;
        slot.power_off()?;
        slot.cleanup()?;
        slot.set_attention_indicator(IndicatorState::Off);
        Ok(())
    }
}

impl Default for PcieHotplugController {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PcieHotplugController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PcieHotplugController")
            .field("count", &self.count)
            .finish()
    }
}
