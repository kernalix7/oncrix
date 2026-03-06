// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB xHCI (eXtensible Host Controller Interface) host controller driver.
//!
//! Implements the xHCI 1.2 host controller driver for USB 3.0/3.1
//! devices. Manages command, transfer, and event rings using
//! Transfer Request Blocks (TRBs), device slot allocation, endpoint
//! configuration, and port status monitoring.
//!
//! # Architecture
//!
//! - [`TrbType`] -- classification of TRB types (normal, setup, data,
//!   status, link, event, command).
//! - [`TransferRing`] -- a ring buffer of TRBs for command or transfer
//!   submission.
//! - [`EventRing`] -- a ring buffer for hardware-to-software event
//!   delivery.
//! - [`DeviceSlot`] -- per-device state including slot context and
//!   endpoint contexts.
//! - [`PortStatus`] -- per-port status and control state.
//! - [`XhciController`] -- the main xHCI controller managing rings,
//!   slots, and ports.
//! - [`XhciRegistry`] -- manages up to [`MAX_CONTROLLERS`] xHCI
//!   controllers.
//!
//! # Ring Architecture
//!
//! ```text
//! Software                          Hardware
//! ┌──────────────┐   doorbell   ┌──────────────┐
//! │ Command Ring │ ───────────► │ xHC Engine   │
//! │ Transfer Ring│              │              │
//! └──────────────┘              └──────┬───────┘
//!                                      │ event
//! ┌──────────────┐                     │
//! │ Event Ring   │ ◄───────────────────┘
//! └──────────────┘
//! ```
//!
//! Reference: xHCI Specification, Revision 1.2,
//!            USB 3.2 Specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of xHCI controllers.
const MAX_CONTROLLERS: usize = 4;

/// Maximum TRB entries in a transfer/command ring.
const RING_SIZE: usize = 256;

/// Maximum TRB entries in an event ring segment.
const EVENT_RING_SIZE: usize = 256;

/// Maximum device slots (USB devices).
const MAX_SLOTS: usize = 64;

/// Maximum ports per controller.
const MAX_PORTS: usize = 16;

/// Maximum endpoints per device (0 = default control, 1..30).
const MAX_ENDPOINTS: usize = 31;

/// Maximum event ring segments.
const MAX_EVENT_SEGMENTS: usize = 1;

/// TRB size in bytes.
const TRB_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// TRB Type Codes (xHCI Table 6-91)
// ---------------------------------------------------------------------------

/// TRB type codes.
pub mod trb_type {
    /// Normal Transfer TRB.
    pub const NORMAL: u32 = 1;
    /// Setup Stage TRB.
    pub const SETUP_STAGE: u32 = 2;
    /// Data Stage TRB.
    pub const DATA_STAGE: u32 = 3;
    /// Status Stage TRB.
    pub const STATUS_STAGE: u32 = 4;
    /// Isoch Transfer TRB.
    pub const ISOCH: u32 = 5;
    /// Link TRB.
    pub const LINK: u32 = 6;
    /// Event Data TRB.
    pub const EVENT_DATA: u32 = 7;
    /// No Op Transfer TRB.
    pub const NO_OP: u32 = 8;
    /// Enable Slot Command.
    pub const ENABLE_SLOT: u32 = 9;
    /// Disable Slot Command.
    pub const DISABLE_SLOT: u32 = 10;
    /// Address Device Command.
    pub const ADDRESS_DEVICE: u32 = 11;
    /// Configure Endpoint Command.
    pub const CONFIGURE_ENDPOINT: u32 = 12;
    /// Evaluate Context Command.
    pub const EVALUATE_CONTEXT: u32 = 13;
    /// Reset Endpoint Command.
    pub const RESET_ENDPOINT: u32 = 14;
    /// Stop Endpoint Command.
    pub const STOP_ENDPOINT: u32 = 15;
    /// Set TR Dequeue Pointer Command.
    pub const SET_TR_DEQUEUE: u32 = 16;
    /// Reset Device Command.
    pub const RESET_DEVICE: u32 = 17;
    /// No Op Command.
    pub const NO_OP_CMD: u32 = 23;
    /// Transfer Event.
    pub const TRANSFER_EVENT: u32 = 32;
    /// Command Completion Event.
    pub const COMMAND_COMPLETION: u32 = 33;
    /// Port Status Change Event.
    pub const PORT_STATUS_CHANGE: u32 = 34;
    /// Host Controller Event.
    pub const HOST_CONTROLLER_EVENT: u32 = 37;
}

// ---------------------------------------------------------------------------
// Completion Codes (xHCI Table 6-90)
// ---------------------------------------------------------------------------

/// TRB completion codes.
pub mod completion {
    /// Success.
    pub const SUCCESS: u8 = 1;
    /// Data Buffer Error.
    pub const DATA_BUFFER_ERROR: u8 = 2;
    /// Babble Detected Error.
    pub const BABBLE: u8 = 3;
    /// USB Transaction Error.
    pub const USB_TRANSACTION_ERROR: u8 = 4;
    /// TRB Error.
    pub const TRB_ERROR: u8 = 5;
    /// Stall Error.
    pub const STALL: u8 = 6;
    /// Short Packet.
    pub const SHORT_PACKET: u8 = 13;
    /// Ring Underrun.
    pub const RING_UNDERRUN: u8 = 14;
    /// Ring Overrun.
    pub const RING_OVERRUN: u8 = 15;
    /// Slot Not Enabled Error.
    pub const SLOT_NOT_ENABLED: u8 = 11;
    /// No Slots Available Error.
    pub const NO_SLOTS: u8 = 9;
}

// ---------------------------------------------------------------------------
// USB Speed
// ---------------------------------------------------------------------------

/// USB device speed classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsbSpeed {
    /// Full-Speed (12 Mbps, USB 1.1).
    #[default]
    Full,
    /// Low-Speed (1.5 Mbps, USB 1.0).
    Low,
    /// High-Speed (480 Mbps, USB 2.0).
    High,
    /// SuperSpeed (5 Gbps, USB 3.0).
    Super5g,
    /// SuperSpeedPlus (10 Gbps, USB 3.1).
    Super10g,
}

impl UsbSpeed {
    /// Decodes speed from the PORTSC speed field.
    pub fn from_portsc(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::Full),
            2 => Some(Self::Low),
            3 => Some(Self::High),
            4 => Some(Self::Super5g),
            5 => Some(Self::Super10g),
            _ => None,
        }
    }

    /// Returns the maximum packet size for the default control endpoint.
    pub fn default_max_packet_size(self) -> u16 {
        match self {
            Self::Low => 8,
            Self::Full => 64,
            Self::High => 64,
            Self::Super5g | Self::Super10g => 512,
        }
    }
}

// ---------------------------------------------------------------------------
// Trb
// ---------------------------------------------------------------------------

/// A single Transfer Request Block (16 bytes).
///
/// TRBs are the fundamental communication unit between software
/// and the xHCI hardware. They are arranged in rings.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Trb {
    /// Parameter (64-bit, usage depends on TRB type).
    pub parameter: u64,
    /// Status field.
    pub status: u32,
    /// Control field (TRB type, flags, cycle bit).
    pub control: u32,
}

impl Trb {
    /// Creates a new empty TRB.
    pub const fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    /// Returns the TRB type from the control field.
    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    /// Returns the cycle bit.
    pub fn cycle_bit(&self) -> bool {
        self.control & 1 != 0
    }

    /// Sets the TRB type in the control field.
    pub fn set_type(&mut self, trb_type: u32) {
        self.control = (self.control & !(0x3F << 10)) | (trb_type << 10);
    }

    /// Sets the cycle bit.
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    /// Returns the completion code from the status field (for events).
    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Returns the slot ID from the control field (for commands/events).
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    /// Builds an Enable Slot command TRB.
    pub fn enable_slot(cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.set_type(trb_type::ENABLE_SLOT);
        trb.set_cycle(cycle);
        trb
    }

    /// Builds a Disable Slot command TRB.
    pub fn disable_slot(slot_id: u8, cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.set_type(trb_type::DISABLE_SLOT);
        trb.control |= (slot_id as u32) << 24;
        trb.set_cycle(cycle);
        trb
    }

    /// Builds an Address Device command TRB.
    pub fn address_device(input_ctx_addr: u64, slot_id: u8, cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = input_ctx_addr;
        trb.set_type(trb_type::ADDRESS_DEVICE);
        trb.control |= (slot_id as u32) << 24;
        trb.set_cycle(cycle);
        trb
    }

    /// Builds a Normal Transfer TRB.
    pub fn normal_transfer(data_addr: u64, length: u32, cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = data_addr;
        trb.status = length & 0x1FFFF; // Transfer length (17 bits).
        trb.set_type(trb_type::NORMAL);
        trb.set_cycle(cycle);
        trb
    }

    /// Builds a Link TRB for ring wrap-around.
    pub fn link(ring_base: u64, cycle: bool, toggle_cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = ring_base;
        trb.set_type(trb_type::LINK);
        trb.set_cycle(cycle);
        if toggle_cycle {
            trb.control |= 1 << 1; // Toggle Cycle bit.
        }
        trb
    }

    /// Builds a No-Op command TRB.
    pub fn no_op_cmd(cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.set_type(trb_type::NO_OP_CMD);
        trb.set_cycle(cycle);
        trb
    }
}

// ---------------------------------------------------------------------------
// TransferRing
// ---------------------------------------------------------------------------

/// A ring buffer of TRBs for command or transfer submission.
///
/// Software writes TRBs to the ring and rings the doorbell.
/// The hardware reads them and produces events on the event ring.
pub struct TransferRing {
    /// TRB entries.
    trbs: [Trb; RING_SIZE],
    /// Current enqueue index (software write pointer).
    enqueue: usize,
    /// Current dequeue index (hardware read pointer, software tracks).
    dequeue: usize,
    /// Producer Cycle State (PCS) — toggles on wrap-around.
    pub cycle_state: bool,
    /// Physical base address of the ring (for hardware DMA).
    pub phys_base: u64,
    /// Whether this ring is initialised.
    pub initialised: bool,
    /// Total TRBs enqueued since initialisation.
    pub total_enqueued: u64,
}

impl TransferRing {
    /// Creates a new uninitialised transfer ring.
    pub const fn new() -> Self {
        Self {
            trbs: [Trb::new(); RING_SIZE],
            enqueue: 0,
            dequeue: 0,
            cycle_state: true,
            phys_base: 0,
            initialised: false,
            total_enqueued: 0,
        }
    }

    /// Initialises the ring with a physical base address.
    ///
    /// Clears all TRBs and places a Link TRB at the last entry
    /// to wrap around to the beginning.
    pub fn init(&mut self, phys_base: u64) {
        self.trbs = [Trb::new(); RING_SIZE];
        self.enqueue = 0;
        self.dequeue = 0;
        self.cycle_state = true;
        self.phys_base = phys_base;
        // Place a Link TRB at the last position.
        let last = RING_SIZE - 1;
        self.trbs[last] = Trb::link(phys_base, self.cycle_state, true);
        self.initialised = true;
        self.total_enqueued = 0;
    }

    /// Enqueues a TRB to the ring.
    ///
    /// Sets the cycle bit and advances the enqueue pointer. If the
    /// pointer reaches the Link TRB, it wraps around and toggles the
    /// cycle state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the ring is full, or
    /// [`Error::IoError`] if the ring is not initialised.
    pub fn enqueue(&mut self, mut trb: Trb) -> Result<usize> {
        if !self.initialised {
            return Err(Error::IoError);
        }
        // Check if ring is full (enqueue catches up to dequeue).
        let next = (self.enqueue + 1) % (RING_SIZE - 1);
        if next == self.dequeue {
            return Err(Error::Busy);
        }

        trb.set_cycle(self.cycle_state);
        let idx = self.enqueue;
        self.trbs[idx] = trb;
        self.enqueue = next;
        self.total_enqueued += 1;

        // Wrap around via Link TRB.
        if self.enqueue == RING_SIZE - 1 {
            self.enqueue = 0;
            self.cycle_state = !self.cycle_state;
            // Update Link TRB cycle bit.
            self.trbs[RING_SIZE - 1].set_cycle(self.cycle_state);
        }

        Ok(idx)
    }

    /// Advances the dequeue pointer (called after hardware processes a TRB).
    pub fn advance_dequeue(&mut self) {
        self.dequeue = (self.dequeue + 1) % (RING_SIZE - 1);
    }

    /// Returns the number of TRBs currently enqueued.
    pub fn pending_count(&self) -> usize {
        if self.enqueue >= self.dequeue {
            self.enqueue - self.dequeue
        } else {
            (RING_SIZE - 1) - self.dequeue + self.enqueue
        }
    }

    /// Returns `true` if the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.enqueue == self.dequeue
    }

    /// Returns a reference to the TRB at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get(&self, index: usize) -> Result<&Trb> {
        if index >= RING_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.trbs[index])
    }
}

impl Default for TransferRing {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EventRing
// ---------------------------------------------------------------------------

/// A ring buffer for hardware-to-software event TRB delivery.
///
/// The hardware writes event TRBs to this ring when commands complete,
/// transfers finish, or port status changes. Software reads them by
/// matching the Consumer Cycle State (CCS) with the event's cycle bit.
pub struct EventRing {
    /// Event TRB entries.
    trbs: [Trb; EVENT_RING_SIZE],
    /// Current dequeue index (software read pointer).
    dequeue: usize,
    /// Consumer Cycle State.
    pub cycle_state: bool,
    /// Physical base address.
    pub phys_base: u64,
    /// Whether this ring is initialised.
    pub initialised: bool,
    /// Total events consumed.
    pub total_consumed: u64,
}

impl EventRing {
    /// Creates a new uninitialised event ring.
    pub const fn new() -> Self {
        Self {
            trbs: [Trb::new(); EVENT_RING_SIZE],
            dequeue: 0,
            cycle_state: true,
            phys_base: 0,
            initialised: false,
            total_consumed: 0,
        }
    }

    /// Initialises the event ring.
    pub fn init(&mut self, phys_base: u64) {
        self.trbs = [Trb::new(); EVENT_RING_SIZE];
        self.dequeue = 0;
        self.cycle_state = true;
        self.phys_base = phys_base;
        self.initialised = true;
        self.total_consumed = 0;
    }

    /// Dequeues the next event TRB if one is available.
    ///
    /// Checks whether the event at the dequeue pointer has the
    /// expected cycle bit. If so, returns it and advances.
    pub fn dequeue(&mut self) -> Option<Trb> {
        if !self.initialised {
            return None;
        }
        let trb = self.trbs[self.dequeue];
        if trb.cycle_bit() != self.cycle_state {
            return None;
        }

        let result = trb;
        self.dequeue += 1;
        if self.dequeue >= EVENT_RING_SIZE {
            self.dequeue = 0;
            self.cycle_state = !self.cycle_state;
        }
        self.total_consumed += 1;
        Some(result)
    }

    /// Returns the number of events available.
    ///
    /// Scans forward from the dequeue pointer looking for events
    /// with matching cycle bits.
    pub fn available_count(&self) -> usize {
        if !self.initialised {
            return 0;
        }
        let mut count = 0;
        let mut idx = self.dequeue;
        let mut cycle = self.cycle_state;
        loop {
            if self.trbs[idx].cycle_bit() != cycle {
                break;
            }
            count += 1;
            idx += 1;
            if idx >= EVENT_RING_SIZE {
                idx = 0;
                cycle = !cycle;
            }
            if idx == self.dequeue {
                break;
            }
        }
        count
    }

    /// Writes a simulated event TRB (for testing/software injection).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn inject_event(&mut self, index: usize, trb: Trb) -> Result<()> {
        if index >= EVENT_RING_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.trbs[index] = trb;
        Ok(())
    }
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EndpointState
// ---------------------------------------------------------------------------

/// State of a USB endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointState {
    /// Endpoint is disabled.
    #[default]
    Disabled,
    /// Endpoint is running (ready for transfers).
    Running,
    /// Endpoint is halted (stall condition).
    Halted,
    /// Endpoint is stopped.
    Stopped,
    /// Endpoint has an error.
    Error,
}

/// Endpoint type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointType {
    /// Control endpoint.
    #[default]
    Control,
    /// Isochronous endpoint.
    Isochronous,
    /// Bulk endpoint.
    Bulk,
    /// Interrupt endpoint.
    Interrupt,
}

// ---------------------------------------------------------------------------
// DeviceSlot
// ---------------------------------------------------------------------------

/// Per-device state managed by the xHCI controller.
///
/// Each addressed USB device occupies one slot. The slot contains
/// the device context (address, speed, route string) and per-endpoint
/// state.
#[derive(Debug, Clone, Copy)]
pub struct DeviceSlot {
    /// Slot ID (1-based, 0 = empty/unused).
    pub slot_id: u8,
    /// Whether this slot is allocated.
    pub allocated: bool,
    /// Whether the device has been addressed.
    pub addressed: bool,
    /// USB device address (0..127).
    pub device_address: u8,
    /// Device speed.
    pub speed: UsbSpeed,
    /// Port number this device is connected to.
    pub port_number: u8,
    /// Route string for USB 3.0 hub routing.
    pub route_string: u32,
    /// Endpoint states (index 0 = EP0, 1..30 = other EPs).
    pub endpoints: [EndpointState; MAX_ENDPOINTS],
    /// Endpoint types.
    pub endpoint_types: [EndpointType; MAX_ENDPOINTS],
    /// Maximum packet size for each endpoint.
    pub max_packet_sizes: [u16; MAX_ENDPOINTS],
    /// Context base address (64-bit DMA address).
    pub context_base: u64,
}

/// Constant empty slot for array initialisation.
const EMPTY_SLOT: DeviceSlot = DeviceSlot {
    slot_id: 0,
    allocated: false,
    addressed: false,
    device_address: 0,
    speed: UsbSpeed::Full,
    port_number: 0,
    route_string: 0,
    endpoints: [EndpointState::Disabled; MAX_ENDPOINTS],
    endpoint_types: [EndpointType::Control; MAX_ENDPOINTS],
    max_packet_sizes: [0u16; MAX_ENDPOINTS],
    context_base: 0,
};

impl DeviceSlot {
    /// Creates a new empty device slot.
    pub const fn new() -> Self {
        EMPTY_SLOT
    }

    /// Allocates this slot for a new device.
    pub fn allocate(&mut self, slot_id: u8, speed: UsbSpeed, port: u8) {
        self.slot_id = slot_id;
        self.allocated = true;
        self.speed = speed;
        self.port_number = port;
        // Enable EP0 (default control endpoint).
        self.endpoints[0] = EndpointState::Running;
        self.endpoint_types[0] = EndpointType::Control;
        self.max_packet_sizes[0] = speed.default_max_packet_size();
    }

    /// Deallocates this slot.
    pub fn deallocate(&mut self) {
        *self = EMPTY_SLOT;
    }

    /// Enables an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ep` is out of range.
    pub fn enable_endpoint(
        &mut self,
        ep: usize,
        ep_type: EndpointType,
        max_packet_size: u16,
    ) -> Result<()> {
        if ep >= MAX_ENDPOINTS {
            return Err(Error::InvalidArgument);
        }
        self.endpoints[ep] = EndpointState::Running;
        self.endpoint_types[ep] = ep_type;
        self.max_packet_sizes[ep] = max_packet_size;
        Ok(())
    }

    /// Disables an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ep` is out of range.
    pub fn disable_endpoint(&mut self, ep: usize) -> Result<()> {
        if ep >= MAX_ENDPOINTS {
            return Err(Error::InvalidArgument);
        }
        self.endpoints[ep] = EndpointState::Disabled;
        Ok(())
    }

    /// Returns the number of enabled endpoints.
    pub fn enabled_endpoint_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter(|e| **e != EndpointState::Disabled)
            .count()
    }
}

impl Default for DeviceSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PortStatus
// ---------------------------------------------------------------------------

/// Per-port status and control state.
#[derive(Debug, Clone, Copy, Default)]
pub struct PortStatus {
    /// Port number (1-based).
    pub port_number: u8,
    /// Whether a device is connected.
    pub connected: bool,
    /// Whether the port is enabled.
    pub enabled: bool,
    /// Whether the port is in reset state.
    pub reset: bool,
    /// Whether port power is on.
    pub powered: bool,
    /// Detected device speed.
    pub speed: UsbSpeed,
    /// Whether a connect status change occurred.
    pub connect_change: bool,
    /// Whether a reset change occurred.
    pub reset_change: bool,
    /// Slot ID of the device on this port (0 = none).
    pub slot_id: u8,
}

// ---------------------------------------------------------------------------
// XhciController
// ---------------------------------------------------------------------------

/// USB xHCI host controller.
///
/// Manages the command ring, event ring, per-device transfer rings,
/// device slots, and port status for a single xHCI controller.
pub struct XhciController {
    /// Unique controller identifier.
    pub id: u32,
    /// MMIO base address (PCI BAR0).
    pub mmio_base: usize,
    /// Capability register length (offset to operational registers).
    pub cap_length: u8,
    /// xHCI version (e.g., 0x0110 = 1.1).
    pub hci_version: u16,
    /// Maximum device slots supported.
    pub max_slots: u8,
    /// Maximum ports.
    pub max_ports: u8,
    /// Command ring.
    pub command_ring: TransferRing,
    /// Event ring.
    pub event_ring: EventRing,
    /// Device slots.
    slots: [DeviceSlot; MAX_SLOTS],
    /// Number of allocated slots.
    slot_count: usize,
    /// Port status array.
    ports: [PortStatus; MAX_PORTS],
    /// Number of ports.
    port_count: usize,
    /// Device Context Base Address Array pointer (64-bit DMA).
    pub dcbaa_base: u64,
    /// Whether the controller is initialised.
    pub initialised: bool,
    /// Whether the controller is running.
    pub running: bool,
    /// Total interrupts processed.
    pub interrupt_count: u64,
}

impl XhciController {
    /// Creates a new xHCI controller.
    pub fn new(id: u32, mmio_base: usize) -> Self {
        Self {
            id,
            mmio_base,
            cap_length: 0,
            hci_version: 0,
            max_slots: 0,
            max_ports: 0,
            command_ring: TransferRing::new(),
            event_ring: EventRing::new(),
            slots: [EMPTY_SLOT; MAX_SLOTS],
            slot_count: 0,
            ports: [PortStatus::default(); MAX_PORTS],
            port_count: 0,
            dcbaa_base: 0,
            initialised: false,
            running: false,
            interrupt_count: 0,
        }
    }

    /// Initialises the xHCI controller.
    ///
    /// Sets up the command and event rings, configures ports, and
    /// enables the controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if initialisation fails.
    pub fn init(&mut self, cmd_ring_phys: u64, event_ring_phys: u64) -> Result<()> {
        self.command_ring.init(cmd_ring_phys);
        self.event_ring.init(event_ring_phys);

        // Initialise port status.
        let num_ports = (self.max_ports as usize).min(MAX_PORTS);
        for i in 0..num_ports {
            self.ports[i].port_number = (i + 1) as u8;
            self.ports[i].powered = true;
        }
        self.port_count = num_ports;
        self.initialised = true;
        Ok(())
    }

    /// Starts the controller (sets Run/Stop to 1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the controller is not initialised.
    pub fn start(&mut self) -> Result<()> {
        if !self.initialised {
            return Err(Error::IoError);
        }
        self.running = true;
        Ok(())
    }

    /// Stops the controller (sets Run/Stop to 0).
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Allocates a device slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slots are available.
    pub fn allocate_slot(&mut self, speed: UsbSpeed, port: u8) -> Result<u8> {
        let max = (self.max_slots as usize).min(MAX_SLOTS);
        for i in 0..max {
            if !self.slots[i].allocated {
                let slot_id = (i + 1) as u8;
                self.slots[i].allocate(slot_id, speed, port);
                self.slot_count += 1;
                return Ok(slot_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Deallocates a device slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_id` is invalid.
    pub fn deallocate_slot(&mut self, slot_id: u8) -> Result<()> {
        let idx = (slot_id as usize)
            .checked_sub(1)
            .ok_or(Error::InvalidArgument)?;
        if idx >= MAX_SLOTS || !self.slots[idx].allocated {
            return Err(Error::InvalidArgument);
        }
        self.slots[idx].deallocate();
        if self.slot_count > 0 {
            self.slot_count -= 1;
        }
        Ok(())
    }

    /// Returns a reference to a device slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_id` is invalid.
    pub fn slot(&self, slot_id: u8) -> Result<&DeviceSlot> {
        let idx = (slot_id as usize)
            .checked_sub(1)
            .ok_or(Error::InvalidArgument)?;
        if idx >= MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.slots[idx])
    }

    /// Returns a mutable reference to a device slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_id` is invalid.
    pub fn slot_mut(&mut self, slot_id: u8) -> Result<&mut DeviceSlot> {
        let idx = (slot_id as usize)
            .checked_sub(1)
            .ok_or(Error::InvalidArgument)?;
        if idx >= MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.slots[idx])
    }

    /// Returns a reference to a port status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port number is out of range.
    pub fn port(&self, port_num: u8) -> Result<&PortStatus> {
        let idx = (port_num as usize)
            .checked_sub(1)
            .ok_or(Error::InvalidArgument)?;
        if idx >= self.port_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.ports[idx])
    }

    /// Returns a mutable reference to a port status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port number is out of range.
    pub fn port_mut(&mut self, port_num: u8) -> Result<&mut PortStatus> {
        let idx = (port_num as usize)
            .checked_sub(1)
            .ok_or(Error::InvalidArgument)?;
        if idx >= self.port_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.ports[idx])
    }

    /// Handles an interrupt from this controller.
    ///
    /// Processes all pending events on the event ring and returns
    /// the number of events handled.
    pub fn handle_interrupt(&mut self) -> usize {
        self.interrupt_count += 1;
        let mut count = 0;
        while let Some(_event) = self.event_ring.dequeue() {
            count += 1;
        }
        count
    }

    /// Returns the number of allocated device slots.
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Returns the number of configured ports.
    pub fn port_count(&self) -> usize {
        self.port_count
    }
}

// ---------------------------------------------------------------------------
// XhciRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CONTROLLERS`] xHCI controllers.
pub struct XhciRegistry {
    /// Registered controllers.
    controllers: [Option<XhciController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl XhciRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers an xHCI controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same ID
    /// exists.
    pub fn register(&mut self, controller: XhciController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == controller.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.controllers.iter_mut() {
            if slot.is_none() {
                *slot = Some(controller);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&XhciController> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut XhciController> {
        for slot in self.controllers.iter_mut() {
            if let Some(c) = slot {
                if c.id == id {
                    return Ok(c);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for XhciRegistry {
    fn default() -> Self {
        Self::new()
    }
}
