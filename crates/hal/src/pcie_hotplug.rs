// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe native hotplug controller.
//!
//! Implements the PCIe native hotplug state machine per PCI Express
//! Base Specification 5.0, section 6.7. Each hotplug-capable slot
//! tracks power state, link state, and indicator LEDs. Events are
//! queued in a ring buffer for the OS hotplug manager to consume.
//!
//! # Architecture
//!
//! - **HotplugSlot** -- per-slot state machine with power/link transitions
//! - **HotplugEvent** -- discrete events (insert, remove, fault, surprise)
//! - **HotplugEventQueue** -- 64-entry ring buffer for event delivery
//! - **HotplugController** -- manages up to 32 slots plus an event queue
//! - **HotplugRegistry** -- tracks up to 4 hotplug controllers
//!
//! Reference: PCI Express Base Specification 5.0, Chapter 6.7.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of slots per hotplug controller.
const MAX_SLOTS: usize = 32;

/// Maximum number of events in the ring buffer.
const MAX_EVENTS: usize = 64;

/// Maximum number of hotplug controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

// ---------------------------------------------------------------------------
// Slot State
// ---------------------------------------------------------------------------

/// State of a PCIe hotplug slot.
///
/// Models the slot power and link lifecycle as defined by the
/// PCIe native hotplug specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotState {
    /// No card is inserted in the slot.
    #[default]
    Empty,
    /// A card is present but slot power is off.
    PoweredOff,
    /// Slot power has been applied; awaiting link training.
    PoweredOn,
    /// PCIe link training has completed successfully.
    LinkUp,
    /// The device is fully operational and bound to a driver.
    Active,
    /// The card was removed without a prior power-off request.
    SurpriseRemoved,
}

// ---------------------------------------------------------------------------
// Slot Indicator
// ---------------------------------------------------------------------------

/// State of a slot indicator LED (power or attention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotIndicator {
    /// Indicator is off.
    #[default]
    Off,
    /// Indicator is steady on.
    On,
    /// Indicator is blinking (attention needed).
    Blinking,
}

// ---------------------------------------------------------------------------
// Hotplug Slot
// ---------------------------------------------------------------------------

/// A single PCIe hotplug slot.
///
/// Tracks the physical slot state, indicator LEDs, and the PCI
/// address of the device occupying the slot (if any).
#[derive(Debug, Clone, Copy)]
pub struct HotplugSlot {
    /// Slot identifier (0-based index within the controller).
    pub slot_id: u8,
    /// Current slot state.
    pub state: SlotState,
    /// Power indicator LED state.
    pub power_indicator: SlotIndicator,
    /// Attention indicator LED state.
    pub attention_indicator: SlotIndicator,
    /// PCI bus/device/function of the card in this slot (0 if empty).
    pub pci_address: u32,
}

impl Default for HotplugSlot {
    fn default() -> Self {
        Self {
            slot_id: 0,
            state: SlotState::Empty,
            power_indicator: SlotIndicator::Off,
            attention_indicator: SlotIndicator::Off,
            pci_address: 0,
        }
    }
}

impl HotplugSlot {
    /// Create a new hotplug slot with the given ID.
    pub fn new(slot_id: u8) -> Self {
        Self {
            slot_id,
            ..Self::default()
        }
    }

    /// Transition to powered-on state.
    ///
    /// Valid from [`SlotState::PoweredOff`]. Sets the power indicator
    /// to [`SlotIndicator::On`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the slot is not in
    /// [`SlotState::PoweredOff`].
    pub fn power_on(&mut self) -> Result<()> {
        if self.state != SlotState::PoweredOff {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::PoweredOn;
        self.power_indicator = SlotIndicator::On;
        Ok(())
    }

    /// Transition to powered-off state.
    ///
    /// Valid from [`SlotState::PoweredOn`], [`SlotState::LinkUp`],
    /// or [`SlotState::Active`]. Sets the power indicator to
    /// [`SlotIndicator::Off`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the slot is in
    /// [`SlotState::Empty`] or [`SlotState::SurpriseRemoved`].
    pub fn power_off(&mut self) -> Result<()> {
        match self.state {
            SlotState::PoweredOn | SlotState::LinkUp | SlotState::Active => {
                self.state = SlotState::PoweredOff;
                self.power_indicator = SlotIndicator::Off;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Transition to link-up state after successful link training.
    ///
    /// Valid from [`SlotState::PoweredOn`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the slot is not in
    /// [`SlotState::PoweredOn`].
    pub fn link_up(&mut self) -> Result<()> {
        if self.state != SlotState::PoweredOn {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::LinkUp;
        Ok(())
    }

    /// Record a surprise removal event.
    ///
    /// Valid from any state except [`SlotState::Empty`]. Sets the
    /// attention indicator to [`SlotIndicator::Blinking`] and clears
    /// the PCI address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the slot is already
    /// empty.
    pub fn surprise_remove(&mut self) -> Result<()> {
        if self.state == SlotState::Empty {
            return Err(Error::InvalidArgument);
        }
        self.state = SlotState::SurpriseRemoved;
        self.attention_indicator = SlotIndicator::Blinking;
        self.power_indicator = SlotIndicator::Off;
        self.pci_address = 0;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hotplug Event
// ---------------------------------------------------------------------------

/// A hotplug event generated by a slot or controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotplugEvent {
    /// A card insertion has been detected (presence-detect change).
    #[default]
    InsertRequest,
    /// An orderly removal has been requested (attention button pressed).
    RemoveRequest,
    /// A power fault was detected on the slot.
    PowerFault,
    /// The card was removed without a prior removal request.
    SurpriseRemoval,
    /// The link state changed (trained up or went down).
    LinkStateChange,
}

// ---------------------------------------------------------------------------
// Hotplug Event Entry (internal, for the ring buffer)
// ---------------------------------------------------------------------------

/// An event entry in the hotplug event queue.
#[derive(Debug, Clone, Copy, Default)]
struct HotplugEventEntry {
    /// The event type.
    event: HotplugEvent,
    /// Slot ID that generated this event.
    slot_id: u8,
    /// Whether this entry contains a valid event.
    valid: bool,
}

// ---------------------------------------------------------------------------
// Hotplug Event Queue
// ---------------------------------------------------------------------------

/// Ring buffer for hotplug events.
///
/// Stores up to [`MAX_EVENTS`] entries. When full, new events are
/// dropped with an error.
pub struct HotplugEventQueue {
    /// Backing storage.
    entries: [HotplugEventEntry; MAX_EVENTS],
    /// Write index (next slot to write).
    head: usize,
    /// Read index (next slot to read).
    tail: usize,
    /// Number of valid entries.
    count: usize,
}

impl Default for HotplugEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugEventQueue {
    /// Create an empty event queue.
    pub const fn new() -> Self {
        Self {
            entries: [HotplugEventEntry {
                event: HotplugEvent::InsertRequest,
                slot_id: 0,
                valid: false,
            }; MAX_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push an event into the queue.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn push(&mut self, event: HotplugEvent, slot_id: u8) -> Result<()> {
        if self.count >= MAX_EVENTS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.head] = HotplugEventEntry {
            event,
            slot_id,
            valid: true,
        };
        self.head = (self.head + 1) % MAX_EVENTS;
        self.count += 1;
        Ok(())
    }

    /// Pop the oldest event from the queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop(&mut self) -> Option<(HotplugEvent, u8)> {
        if self.count == 0 {
            return None;
        }
        let entry = self.entries[self.tail];
        self.entries[self.tail].valid = false;
        self.tail = (self.tail + 1) % MAX_EVENTS;
        self.count -= 1;
        if entry.valid {
            Some((entry.event, entry.slot_id))
        } else {
            None
        }
    }

    /// Return the number of pending events.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Hotplug Controller
// ---------------------------------------------------------------------------

/// A PCIe hotplug controller managing a set of physical slots.
///
/// Each controller owns up to [`MAX_SLOTS`] slots and an event
/// queue. The OS hotplug manager interacts with the controller to
/// power slots on/off, handle events, and enumerate active devices.
pub struct HotplugController {
    /// Controller identifier.
    pub controller_id: u8,
    /// Managed slots.
    pub slots: [HotplugSlot; MAX_SLOTS],
    /// Number of slots present on this controller.
    pub slot_count: usize,
    /// Event queue for this controller.
    pub event_queue: HotplugEventQueue,
}

impl HotplugController {
    /// Create a new hotplug controller with the given number of slots.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `num_slots` is zero or
    /// exceeds [`MAX_SLOTS`].
    pub fn new(controller_id: u8, num_slots: usize) -> Result<Self> {
        if num_slots == 0 || num_slots > MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }

        let mut slots = [HotplugSlot::default(); MAX_SLOTS];
        let mut i = 0;
        while i < num_slots {
            slots[i] = HotplugSlot::new(i as u8);
            i += 1;
        }

        Ok(Self {
            controller_id,
            slots,
            slot_count: num_slots,
            event_queue: HotplugEventQueue::new(),
        })
    }

    /// Handle a hotplug event for a specific slot.
    ///
    /// Updates the slot state machine and queues the event for the
    /// OS hotplug manager.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `slot_id` is out of range.
    /// - Propagates errors from slot state transitions or the event
    ///   queue.
    pub fn handle_event(&mut self, slot_id: u8, event: HotplugEvent) -> Result<()> {
        let idx = slot_id as usize;
        if idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }

        match event {
            HotplugEvent::InsertRequest => {
                let slot = &mut self.slots[idx];
                if slot.state == SlotState::Empty {
                    slot.state = SlotState::PoweredOff;
                    slot.attention_indicator = SlotIndicator::Blinking;
                }
            }
            HotplugEvent::RemoveRequest => {
                let slot = &mut self.slots[idx];
                if slot.state != SlotState::Empty {
                    slot.attention_indicator = SlotIndicator::Blinking;
                }
            }
            HotplugEvent::PowerFault => {
                let slot = &mut self.slots[idx];
                slot.attention_indicator = SlotIndicator::Blinking;
                slot.power_indicator = SlotIndicator::Off;
                if slot.state == SlotState::PoweredOn
                    || slot.state == SlotState::LinkUp
                    || slot.state == SlotState::Active
                {
                    slot.state = SlotState::PoweredOff;
                }
            }
            HotplugEvent::SurpriseRemoval => {
                self.slots[idx].surprise_remove()?;
            }
            HotplugEvent::LinkStateChange => {
                let slot = &mut self.slots[idx];
                if slot.state == SlotState::PoweredOn {
                    slot.state = SlotState::LinkUp;
                }
            }
        }

        self.event_queue.push(event, slot_id)?;
        Ok(())
    }

    /// Power on a specific slot.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `slot_id` is out of range or
    ///   the slot is not in [`SlotState::PoweredOff`].
    pub fn slot_power_on(&mut self, slot_id: u8) -> Result<()> {
        let idx = slot_id as usize;
        if idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].power_on()
    }

    /// Power off a specific slot.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `slot_id` is out of range or
    ///   the slot cannot be powered off.
    pub fn slot_power_off(&mut self, slot_id: u8) -> Result<()> {
        let idx = slot_id as usize;
        if idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].power_off()
    }

    /// Get the state of a specific slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_id` is out of range.
    pub fn get_slot_state(&self, slot_id: u8) -> Result<SlotState> {
        let idx = slot_id as usize;
        if idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.slots[idx].state)
    }

    /// Enumerate all slots that are currently in [`SlotState::Active`].
    ///
    /// Returns the number of active slots found. The caller can
    /// iterate the slot array and filter by state for details.
    pub fn enumerate_active(&self) -> usize {
        self.slots
            .iter()
            .take(self.slot_count)
            .filter(|s| s.state == SlotState::Active)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Hotplug Registry
// ---------------------------------------------------------------------------

/// Registry of PCIe hotplug controllers.
///
/// Tracks up to [`MAX_CONTROLLERS`] controllers and provides
/// lookup by controller ID.
pub struct HotplugRegistry {
    /// Fixed-size array of controller slots.
    controllers: [Option<HotplugController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for HotplugRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugRegistry {
    /// Create an empty hotplug controller registry.
    pub const fn new() -> Self {
        const NONE: Option<HotplugController> = None;
        Self {
            controllers: [NONE; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a new hotplug controller.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a controller with the same
    ///   `controller_id` is already registered.
    pub fn register(&mut self, controller: HotplugController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.controller_id == controller.controller_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.controllers {
            if slot.is_none() {
                *slot = Some(controller);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a controller by its `controller_id`.
    pub fn find(&self, controller_id: u8) -> Option<&HotplugController> {
        self.controllers
            .iter()
            .find_map(|slot| slot.as_ref().filter(|c| c.controller_id == controller_id))
    }

    /// Find a mutable reference to a controller by its `controller_id`.
    pub fn find_mut(&mut self, controller_id: u8) -> Option<&mut HotplugController> {
        self.controllers
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|c| c.controller_id == controller_id))
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
