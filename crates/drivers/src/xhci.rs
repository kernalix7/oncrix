// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! xHCI (eXtensible Host Controller Interface) USB driver.
//!
//! Implements a basic xHCI host controller driver supporting USB 1.x
//! through USB 3.x devices. The xHCI specification defines a register
//! interface accessed via PCI BAR0 memory-mapped I/O.
//!
//! # Architecture
//!
//! - **Capability registers** — read-only, describe controller features
//! - **Operational registers** — control host controller behavior
//! - **Port registers** — per-port status and control
//! - **Transfer Request Blocks (TRBs)** — ring-based command/transfer
//!   queues shared between software and hardware
//! - **Device slots** — per-device context structures
//!
//! Reference: xHCI Specification, Revision 1.2.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of TRB entries in a transfer ring.
const RING_SIZE: usize = 256;

/// Maximum number of device slots supported.
const MAX_SLOTS: usize = 32;

/// Maximum number of ports supported.
const MAX_PORTS: usize = 16;

/// Maximum endpoints per device (0 = default control, 1..30).
const MAX_ENDPOINTS: usize = 31;

// ---------------------------------------------------------------------------
// Capability register offsets (xHCI §5.3)
// ---------------------------------------------------------------------------

/// Capability register offsets within BAR0.
pub mod cap_reg {
    /// Capability register length (1 byte).
    pub const CAPLENGTH: u32 = 0x00;
    /// Host controller interface version (2 bytes at offset 0x02).
    pub const HCIVERSION: u32 = 0x02;
    /// Structural parameters 1.
    pub const HCSPARAMS1: u32 = 0x04;
    /// Structural parameters 2.
    pub const HCSPARAMS2: u32 = 0x08;
    /// Structural parameters 3.
    pub const HCSPARAMS3: u32 = 0x0C;
    /// Capability parameters 1.
    pub const HCCPARAMS1: u32 = 0x10;
    /// Doorbell offset (relative to BAR0).
    pub const DBOFF: u32 = 0x14;
    /// Runtime register space offset (relative to BAR0).
    pub const RTSOFF: u32 = 0x18;
    /// Capability parameters 2.
    pub const HCCPARAMS2: u32 = 0x1C;
}

// ---------------------------------------------------------------------------
// Operational register offsets (xHCI §5.4)
// ---------------------------------------------------------------------------

/// Operational register offsets (relative to cap_length).
pub mod op_reg {
    /// USB command register.
    pub const USBCMD: u32 = 0x00;
    /// USB status register.
    pub const USBSTS: u32 = 0x04;
    /// Page size register.
    pub const PAGESIZE: u32 = 0x08;
    /// Device notification control.
    pub const DNCTRL: u32 = 0x14;
    /// Command ring control (64-bit).
    pub const CRCR: u32 = 0x18;
    /// Device context base address array pointer (64-bit).
    pub const DCBAAP: u32 = 0x30;
    /// Configure register.
    pub const CONFIG: u32 = 0x38;
}

// ---------------------------------------------------------------------------
// USBCMD bits (xHCI §5.4.1)
// ---------------------------------------------------------------------------

/// USB command register bit definitions.
pub mod usbcmd {
    /// Run/Stop — set to 1 to run, 0 to stop.
    pub const RUN_STOP: u32 = 1 << 0;
    /// Host controller reset.
    pub const HCRST: u32 = 1 << 1;
    /// Interrupter enable.
    pub const INTE: u32 = 1 << 2;
    /// Host system error enable.
    pub const HSEE: u32 = 1 << 3;
}

// ---------------------------------------------------------------------------
// USBSTS bits (xHCI §5.4.2)
// ---------------------------------------------------------------------------

/// USB status register bit definitions.
pub mod usbsts {
    /// Host controller halted.
    pub const HCH: u32 = 1 << 0;
    /// Host system error.
    pub const HSE: u32 = 1 << 2;
    /// Event interrupt.
    pub const EINT: u32 = 1 << 3;
    /// Port change detect.
    pub const PCD: u32 = 1 << 4;
    /// Controller not ready.
    pub const CNR: u32 = 1 << 11;
}

// ---------------------------------------------------------------------------
// Port register offsets and bits (xHCI §5.4.8)
// ---------------------------------------------------------------------------

/// Per-port register offsets (relative to port base).
pub mod port_reg {
    /// Port status and control.
    pub const PORTSC: u32 = 0x00;
    /// Port power management status and control.
    pub const PORTPMSC: u32 = 0x04;
    /// Port link info.
    pub const PORTLI: u32 = 0x08;
    /// Port hardware LPM control.
    pub const PORTHLPMC: u32 = 0x0C;
}

/// Port status and control bit definitions.
pub mod portsc {
    /// Current connect status.
    pub const CCS: u32 = 1 << 0;
    /// Port enabled/disabled.
    pub const PED: u32 = 1 << 1;
    /// Port reset.
    pub const PR: u32 = 1 << 4;
    /// Port power.
    pub const PP: u32 = 1 << 9;
    /// Port speed mask (bits 13:10).
    pub const SPEED_MASK: u32 = 0xF << 10;
    /// Port speed shift.
    pub const SPEED_SHIFT: u32 = 10;
    /// Connect status change.
    pub const CSC: u32 = 1 << 17;
    /// Port reset change.
    pub const PRC: u32 = 1 << 21;
}

// ---------------------------------------------------------------------------
// USB speed definitions (xHCI §7.2)
// ---------------------------------------------------------------------------

/// USB device speed classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    /// Full-speed (12 Mbps, USB 1.1).
    Full,
    /// Low-speed (1.5 Mbps, USB 1.0).
    Low,
    /// High-speed (480 Mbps, USB 2.0).
    High,
    /// SuperSpeed (5 Gbps, USB 3.0).
    Super,
}

impl UsbSpeed {
    /// Decode speed from PORTSC speed field value.
    fn from_portsc(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::Full),
            2 => Some(Self::Low),
            3 => Some(Self::High),
            4 => Some(Self::Super),
            _ => None,
        }
    }
}

impl core::fmt::Display for UsbSpeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => write!(f, "Full-Speed (12 Mbps)"),
            Self::Low => write!(f, "Low-Speed (1.5 Mbps)"),
            Self::High => write!(f, "High-Speed (480 Mbps)"),
            Self::Super => write!(f, "SuperSpeed (5 Gbps)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Capability registers (xHCI §5.3)
// ---------------------------------------------------------------------------

/// xHCI capability registers (read-only).
///
/// Describes the host controller's structural parameters and
/// capabilities. Read once during initialization.
#[derive(Debug, Clone, Copy)]
pub struct XhciCapRegs {
    /// Length of capability register space in bytes.
    pub cap_length: u8,
    /// Host controller interface version (BCD, e.g. 0x0100).
    pub hci_version: u16,
    /// Structural parameters 1 (max slots, intrs, ports).
    pub hcs_params1: u32,
    /// Structural parameters 2 (IST, ERST max, SPB max).
    pub hcs_params2: u32,
    /// Structural parameters 3 (U1/U2 latency).
    pub hcs_params3: u32,
    /// Capability parameters 1 (64-bit, context size, etc).
    pub hcc_params1: u32,
    /// Doorbell array offset from BAR0.
    pub db_offset: u32,
    /// Runtime register space offset from BAR0.
    pub rts_offset: u32,
    /// Capability parameters 2.
    pub hcc_params2: u32,
}

impl XhciCapRegs {
    /// Maximum number of device slots supported by hardware.
    pub fn max_slots(&self) -> u8 {
        (self.hcs_params1 & 0xFF) as u8
    }

    /// Maximum number of interrupters.
    pub fn max_interrupters(&self) -> u16 {
        ((self.hcs_params1 >> 8) & 0x7FF) as u16
    }

    /// Maximum number of ports.
    pub fn max_ports(&self) -> u8 {
        ((self.hcs_params1 >> 24) & 0xFF) as u8
    }

    /// Whether the controller uses 64-byte device contexts.
    pub fn context_size_64(&self) -> bool {
        (self.hcc_params1 & (1 << 2)) != 0
    }
}

// ---------------------------------------------------------------------------
// Operational registers (xHCI §5.4)
// ---------------------------------------------------------------------------

/// xHCI operational registers (read/write).
///
/// Controls the host controller operation including run/stop,
/// reset, command ring, and device context base address.
#[derive(Debug, Clone, Copy, Default)]
pub struct XhciOpRegs {
    /// USB command register value.
    pub usbcmd: u32,
    /// USB status register value.
    pub usbsts: u32,
    /// Page size register value.
    pub pagesize: u32,
    /// Device notification control.
    pub dnctrl: u32,
    /// Command ring control register (64-bit).
    pub crcr: u64,
    /// Device context base address array pointer (64-bit).
    pub dcbaap: u64,
    /// Configure register.
    pub config: u32,
}

// ---------------------------------------------------------------------------
// Port registers (xHCI §5.4.8)
// ---------------------------------------------------------------------------

/// Per-port register snapshot.
///
/// Captures the current state of a single xHCI root hub port.
#[derive(Debug, Clone, Copy, Default)]
pub struct XhciPortRegs {
    /// Port status and control.
    pub portsc: u32,
    /// Port power management status and control.
    pub portpmsc: u32,
    /// Port link info.
    pub portli: u32,
    /// Port hardware LPM control.
    pub porthlpmc: u32,
}

// ---------------------------------------------------------------------------
// Port status (decoded)
// ---------------------------------------------------------------------------

/// Decoded port status information.
#[derive(Debug, Clone, Copy, Default)]
pub struct XhciPortStatus {
    /// Whether a device is physically connected.
    pub connected: bool,
    /// Whether the port is enabled.
    pub enabled: bool,
    /// Whether the port is powered.
    pub powered: bool,
    /// Detected device speed, if connected.
    pub speed: Option<UsbSpeed>,
}

impl XhciPortStatus {
    /// Create a new disconnected port status.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode port status from a PORTSC register value.
    pub fn from_portsc(portsc: u32) -> Self {
        let connected = (portsc & portsc::CCS) != 0;
        let speed_val = (portsc & portsc::SPEED_MASK) >> portsc::SPEED_SHIFT;
        Self {
            connected,
            enabled: (portsc & portsc::PED) != 0,
            powered: (portsc & portsc::PP) != 0,
            speed: if connected {
                UsbSpeed::from_portsc(speed_val)
            } else {
                None
            },
        }
    }
}

// ---------------------------------------------------------------------------
// TRB — Transfer Request Block (xHCI §4.11)
// ---------------------------------------------------------------------------

/// Transfer Request Block type codes (xHCI §6.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrbType {
    /// Normal transfer TRB.
    Normal = 1,
    /// Setup stage TRB (control transfers).
    SetupStage = 2,
    /// Data stage TRB (control transfers).
    DataStage = 3,
    /// Status stage TRB (control transfers).
    StatusStage = 4,
    /// Isoch transfer TRB.
    Isoch = 5,
    /// Link TRB (chain ring segments).
    Link = 6,
    /// Event data TRB.
    EventData = 7,
    /// No-op transfer TRB.
    NoopTransfer = 8,
    /// Enable slot command.
    EnableSlot = 9,
    /// Disable slot command.
    DisableSlot = 10,
    /// Address device command.
    AddressDevice = 11,
    /// Configure endpoint command.
    ConfigureEndpoint = 12,
    /// Evaluate context command.
    EvaluateContext = 13,
    /// Reset endpoint command.
    ResetEndpoint = 14,
    /// Stop endpoint command.
    StopEndpoint = 15,
    /// Set TR dequeue pointer command.
    SetTrDequeuePointer = 16,
    /// Reset device command.
    ResetDevice = 17,
    /// No-op command.
    NoopCommand = 23,
    /// Transfer event (completion).
    TransferEvent = 32,
    /// Command completion event.
    CommandCompletion = 33,
    /// Port status change event.
    PortStatusChange = 34,
}

impl TrbType {
    /// Convert a raw TRB type field value to a `TrbType`.
    pub fn from_raw(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Normal),
            2 => Some(Self::SetupStage),
            3 => Some(Self::DataStage),
            4 => Some(Self::StatusStage),
            5 => Some(Self::Isoch),
            6 => Some(Self::Link),
            7 => Some(Self::EventData),
            8 => Some(Self::NoopTransfer),
            9 => Some(Self::EnableSlot),
            10 => Some(Self::DisableSlot),
            11 => Some(Self::AddressDevice),
            12 => Some(Self::ConfigureEndpoint),
            13 => Some(Self::EvaluateContext),
            14 => Some(Self::ResetEndpoint),
            15 => Some(Self::StopEndpoint),
            16 => Some(Self::SetTrDequeuePointer),
            17 => Some(Self::ResetDevice),
            23 => Some(Self::NoopCommand),
            32 => Some(Self::TransferEvent),
            33 => Some(Self::CommandCompletion),
            34 => Some(Self::PortStatusChange),
            _ => None,
        }
    }
}

/// A Transfer Request Block (16 bytes, hardware layout).
///
/// TRBs are the fundamental unit of work exchanged between software
/// and the xHCI controller via ring buffers.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Trb {
    /// Parameter field (meaning varies by TRB type).
    pub parameter: u64,
    /// Status field (completion code, transfer length, etc.).
    pub status: u32,
    /// Control field (TRB type, cycle bit, flags).
    pub control: u32,
}

impl Default for Trb {
    fn default() -> Self {
        Self::new()
    }
}

impl Trb {
    /// Create a zeroed TRB.
    pub const fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    /// Get the TRB type from the control field (bits 15:10).
    pub fn trb_type(&self) -> Option<TrbType> {
        let raw = ((self.control >> 10) & 0x3F) as u8;
        TrbType::from_raw(raw)
    }

    /// Get the cycle bit (bit 0 of control).
    pub fn cycle_bit(&self) -> bool {
        (self.control & 1) != 0
    }

    /// Set the TRB type and cycle bit in the control field.
    ///
    /// Preserves other control bits while setting the type and
    /// cycle state.
    pub fn set_type_and_cycle(&mut self, trb_type: TrbType, cycle: bool) {
        let type_bits = (trb_type as u32) << 10;
        let cycle_bit = u32::from(cycle);
        // Clear type and cycle fields, then set new values.
        self.control = (self.control & !(0x3F << 10 | 1)) | type_bits | cycle_bit;
    }

    /// Build a Link TRB pointing to the given segment address.
    pub fn link(segment_addr: u64, cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = segment_addr;
        // Toggle cycle bit (bit 1 of control for Link TRBs).
        trb.control = ((TrbType::Link as u32) << 10) | u32::from(cycle) | (1 << 1); // Toggle Cycle (TC) bit
        trb
    }

    /// Extract the completion code from an event TRB status field.
    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Extract the slot ID from the control field (bits 31:24).
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }
}

// ---------------------------------------------------------------------------
// Transfer Ring (xHCI §4.9.2)
// ---------------------------------------------------------------------------

/// Producer-side TRB ring for transfers and commands.
///
/// A fixed-size ring of [`Trb`] entries with a link TRB at the end
/// that wraps back to the beginning. The producer cycle state (PCS)
/// toggles on each wrap.
pub struct TransferRing {
    /// TRB ring buffer (last entry reserved for Link TRB).
    trbs: [Trb; RING_SIZE],
    /// Producer enqueue index (0..RING_SIZE-1).
    enqueue_idx: usize,
    /// Consumer dequeue index.
    dequeue_idx: usize,
    /// Producer cycle state (toggled on wrap).
    cycle: bool,
}

impl Default for TransferRing {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferRing {
    /// Create a new transfer ring with all entries zeroed.
    pub fn new() -> Self {
        let mut ring = Self {
            trbs: [Trb::new(); RING_SIZE],
            enqueue_idx: 0,
            dequeue_idx: 0,
            cycle: true,
        };
        ring.init();
        ring
    }

    /// Initialize the ring with a trailing Link TRB.
    fn init(&mut self) {
        // The last entry is the Link TRB that wraps to the start.
        let ring_base = self.trbs.as_ptr() as u64;
        self.trbs[RING_SIZE - 1] = Trb::link(ring_base, self.cycle);
    }

    /// Return a pointer to the TRB array base (for hardware).
    pub fn base_addr(&self) -> u64 {
        self.trbs.as_ptr() as u64
    }

    /// Enqueue a TRB onto the ring.
    ///
    /// Returns the physical address of the enqueued TRB, or an
    /// error if the ring is full.
    pub fn enqueue(&mut self, mut trb: Trb) -> Result<u64> {
        // Check if the ring is full (enqueue caught up to dequeue).
        let next = (self.enqueue_idx + 1) % (RING_SIZE - 1);
        if next == self.dequeue_idx {
            return Err(Error::OutOfMemory);
        }

        // Set the cycle bit to match producer cycle state.
        trb.set_type_and_cycle(trb.trb_type().ok_or(Error::InvalidArgument)?, self.cycle);

        let addr = &self.trbs[self.enqueue_idx] as *const Trb as u64;
        self.trbs[self.enqueue_idx] = trb;
        self.enqueue_idx = next;

        // If we've reached the Link TRB slot, wrap around.
        if self.enqueue_idx == RING_SIZE - 1 {
            self.cycle = !self.cycle;
            // Update Link TRB cycle bit.
            self.trbs[RING_SIZE - 1] = Trb::link(self.base_addr(), self.cycle);
            self.enqueue_idx = 0;
        }

        Ok(addr)
    }

    /// Advance the dequeue pointer by one entry.
    ///
    /// Called after the consumer (hardware) has processed a TRB.
    pub fn dequeue(&mut self) -> Result<Trb> {
        if self.dequeue_idx == self.enqueue_idx {
            return Err(Error::WouldBlock);
        }
        let trb = self.trbs[self.dequeue_idx];
        self.dequeue_idx = (self.dequeue_idx + 1) % (RING_SIZE - 1);
        Ok(trb)
    }

    /// Check if the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.dequeue_idx == self.enqueue_idx
    }

    /// Number of TRBs currently queued.
    pub fn len(&self) -> usize {
        if self.enqueue_idx >= self.dequeue_idx {
            self.enqueue_idx - self.dequeue_idx
        } else {
            (RING_SIZE - 1) - self.dequeue_idx + self.enqueue_idx
        }
    }
}

impl core::fmt::Debug for TransferRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransferRing")
            .field("enqueue_idx", &self.enqueue_idx)
            .field("dequeue_idx", &self.dequeue_idx)
            .field("cycle", &self.cycle)
            .field("len", &self.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Event Ring (xHCI §4.9.4)
// ---------------------------------------------------------------------------

/// Event Ring Segment Table Entry (16 bytes, hardware layout).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ErstEntry {
    /// Base address of the event ring segment.
    pub base_addr: u64,
    /// Number of TRBs in this segment.
    pub size: u16,
    /// Reserved.
    _rsvd: u16,
    /// Reserved.
    _rsvd2: u32,
}

impl Default for ErstEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl ErstEntry {
    /// Create a zeroed segment table entry.
    pub const fn new() -> Self {
        Self {
            base_addr: 0,
            size: 0,
            _rsvd: 0,
            _rsvd2: 0,
        }
    }
}

/// Consumer-side event ring.
///
/// Hardware enqueues event TRBs; software dequeues and processes
/// them. Uses a segment table with a single segment for simplicity.
pub struct EventRing {
    /// Event TRB buffer.
    trbs: [Trb; RING_SIZE],
    /// Segment table (single entry).
    erst: ErstEntry,
    /// Software dequeue index.
    dequeue_idx: usize,
    /// Consumer cycle state (CCS).
    cycle: bool,
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRing {
    /// Create a new event ring.
    pub fn new() -> Self {
        let mut ring = Self {
            trbs: [Trb::new(); RING_SIZE],
            erst: ErstEntry::new(),
            dequeue_idx: 0,
            cycle: true,
        };
        ring.erst.base_addr = ring.trbs.as_ptr() as u64;
        ring.erst.size = RING_SIZE as u16;
        ring
    }

    /// Base address of the segment table (for ERSTBA register).
    pub fn erst_base(&self) -> u64 {
        &self.erst as *const ErstEntry as u64
    }

    /// Number of entries in the segment table (always 1).
    pub fn erst_size(&self) -> u16 {
        1
    }

    /// Current dequeue pointer address (for ERDP register).
    pub fn dequeue_addr(&self) -> u64 {
        &self.trbs[self.dequeue_idx] as *const Trb as u64
    }

    /// Dequeue the next event TRB, if available.
    ///
    /// Returns `None` if no new events (cycle bit mismatch).
    pub fn dequeue(&mut self) -> Option<Trb> {
        let trb = self.trbs[self.dequeue_idx];
        if trb.cycle_bit() != self.cycle {
            return None;
        }
        self.dequeue_idx += 1;
        if self.dequeue_idx >= RING_SIZE {
            self.dequeue_idx = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }

    /// Check if there is a pending event.
    pub fn has_pending(&self) -> bool {
        self.trbs[self.dequeue_idx].cycle_bit() == self.cycle
    }
}

impl core::fmt::Debug for EventRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventRing")
            .field("dequeue_idx", &self.dequeue_idx)
            .field("cycle", &self.cycle)
            .field("has_pending", &self.has_pending())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Endpoint state (xHCI §6.2.3)
// ---------------------------------------------------------------------------

/// Endpoint operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointState {
    /// Endpoint is disabled.
    #[default]
    Disabled,
    /// Endpoint is running.
    Running,
    /// Endpoint is halted (error).
    Halted,
    /// Endpoint is stopped.
    Stopped,
}

// ---------------------------------------------------------------------------
// Device Slot (xHCI §4.5.3)
// ---------------------------------------------------------------------------

/// Per-device slot context and endpoint state.
///
/// Tracks the device context for an assigned slot, including the
/// USB address, speed, and endpoint operational states.
#[derive(Debug)]
pub struct DeviceSlot {
    /// Slot ID (1-based, 0 = invalid).
    slot_id: u8,
    /// Whether this slot is currently assigned.
    active: bool,
    /// USB device address (assigned by Address Device command).
    usb_address: u8,
    /// Device speed.
    speed: Option<UsbSpeed>,
    /// Root hub port number (1-based).
    root_port: u8,
    /// Endpoint states (index 0 = default control endpoint).
    endpoints: [EndpointState; MAX_ENDPOINTS],
}

impl Default for DeviceSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceSlot {
    /// Create a new inactive device slot.
    pub fn new() -> Self {
        Self {
            slot_id: 0,
            active: false,
            usb_address: 0,
            speed: None,
            root_port: 0,
            endpoints: [EndpointState::Disabled; MAX_ENDPOINTS],
        }
    }

    /// Activate this slot with the given ID and port.
    pub fn activate(&mut self, slot_id: u8, port: u8, speed: UsbSpeed) {
        self.slot_id = slot_id;
        self.active = true;
        self.root_port = port;
        self.speed = Some(speed);
        // Default control endpoint is always running.
        self.endpoints[0] = EndpointState::Running;
    }

    /// Deactivate the slot, resetting all state.
    pub fn deactivate(&mut self) {
        *self = Self::new();
    }

    /// Whether this slot is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the slot ID.
    pub fn slot_id(&self) -> u8 {
        self.slot_id
    }

    /// Get the device speed.
    pub fn speed(&self) -> Option<UsbSpeed> {
        self.speed
    }

    /// Get the USB device address.
    pub fn usb_address(&self) -> u8 {
        self.usb_address
    }

    /// Set the USB device address.
    pub fn set_usb_address(&mut self, addr: u8) {
        self.usb_address = addr;
    }

    /// Get the state of an endpoint.
    pub fn endpoint_state(&self, ep_idx: usize) -> Result<EndpointState> {
        if ep_idx >= MAX_ENDPOINTS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.endpoints[ep_idx])
    }

    /// Set the state of an endpoint.
    pub fn set_endpoint_state(&mut self, ep_idx: usize, state: EndpointState) -> Result<()> {
        if ep_idx >= MAX_ENDPOINTS {
            return Err(Error::InvalidArgument);
        }
        self.endpoints[ep_idx] = state;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// The address must be a valid, mapped MMIO register.
unsafe fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: Caller guarantees the address is valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// The address must be a valid, mapped MMIO register.
unsafe fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: Caller guarantees the address is valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Read a 64-bit value from a memory-mapped register (two 32-bit).
///
/// # Safety
///
/// The address must be a valid, mapped MMIO register pair.
unsafe fn mmio_read64(addr: u64) -> u64 {
    // SAFETY: Caller guarantees the address is valid MMIO.
    unsafe {
        let lo = core::ptr::read_volatile(addr as *const u32);
        let hi = core::ptr::read_volatile((addr + 4) as *const u32);
        (hi as u64) << 32 | lo as u64
    }
}

/// Write a 64-bit value to a memory-mapped register (two 32-bit).
///
/// # Safety
///
/// The address must be a valid, mapped MMIO register pair.
unsafe fn mmio_write64(addr: u64, val: u64) {
    // SAFETY: Caller guarantees the address is valid MMIO.
    unsafe {
        let lo = val as u32;
        let hi = (val >> 32) as u32;
        core::ptr::write_volatile(addr as *mut u32, lo);
        core::ptr::write_volatile((addr + 4) as *mut u32, hi);
    }
}

// ---------------------------------------------------------------------------
// XhciController — main driver
// ---------------------------------------------------------------------------

/// xHCI host controller driver.
///
/// Manages the xHCI register interface, command and event rings,
/// device slots, and port status. Initialized from the PCI BAR0
/// base address.
pub struct XhciController {
    /// BAR0 base address (memory-mapped).
    bar_base: u64,
    /// Cached capability registers.
    cap_regs: XhciCapRegs,
    /// Operational register base address.
    op_base: u64,
    /// Doorbell array base address.
    db_base: u64,
    /// Runtime register base address.
    rt_base: u64,
    /// Command ring (host -> controller).
    command_ring: TransferRing,
    /// Primary event ring (controller -> host).
    event_ring: EventRing,
    /// Device slot table.
    slots: [DeviceSlot; MAX_SLOTS],
    /// Number of enabled slots (from CONFIG register).
    max_slots_enabled: u8,
    /// Number of ports detected.
    num_ports: u8,
}

/// Helper to build a const-initialized slot array.
const EMPTY_SLOT: DeviceSlot = DeviceSlot {
    slot_id: 0,
    active: false,
    usb_address: 0,
    speed: None,
    root_port: 0,
    endpoints: [EndpointState::Disabled; MAX_ENDPOINTS],
};

impl XhciController {
    /// Create a new xHCI controller from PCI BAR0 base address.
    ///
    /// Reads capability registers and computes derived base addresses
    /// but does not reset or start the controller. Call [`init`]
    /// after construction.
    ///
    /// [`init`]: Self::init
    pub fn new(bar_base: u64) -> Self {
        // SAFETY: BAR0 is mapped into kernel address space by the
        // PCI subsystem before driver initialization.
        let cap_regs = unsafe { Self::read_cap_regs(bar_base) };
        let op_base = bar_base + cap_regs.cap_length as u64;
        let db_base = bar_base + cap_regs.db_offset as u64;
        let rt_base = bar_base + cap_regs.rts_offset as u64;

        let num_ports = cap_regs.max_ports();
        let clamped_ports = if num_ports > MAX_PORTS as u8 {
            MAX_PORTS as u8
        } else {
            num_ports
        };

        Self {
            bar_base,
            cap_regs,
            op_base,
            db_base,
            rt_base,
            command_ring: TransferRing::new(),
            event_ring: EventRing::new(),
            slots: [EMPTY_SLOT; MAX_SLOTS],
            max_slots_enabled: 0,
            num_ports: clamped_ports,
        }
    }

    /// Read capability registers from BAR0.
    ///
    /// # Safety
    ///
    /// BAR0 must be a valid mapped MMIO region.
    unsafe fn read_cap_regs(base: u64) -> XhciCapRegs {
        // SAFETY: Caller guarantees base is valid MMIO.
        unsafe {
            let cap_length = mmio_read32(base + cap_reg::CAPLENGTH as u64) as u8;
            let hci_version = mmio_read32(base + cap_reg::HCIVERSION as u64) as u16;
            XhciCapRegs {
                cap_length,
                hci_version,
                hcs_params1: mmio_read32(base + cap_reg::HCSPARAMS1 as u64),
                hcs_params2: mmio_read32(base + cap_reg::HCSPARAMS2 as u64),
                hcs_params3: mmio_read32(base + cap_reg::HCSPARAMS3 as u64),
                hcc_params1: mmio_read32(base + cap_reg::HCCPARAMS1 as u64),
                db_offset: mmio_read32(base + cap_reg::DBOFF as u64),
                rts_offset: mmio_read32(base + cap_reg::RTSOFF as u64),
                hcc_params2: mmio_read32(base + cap_reg::HCCPARAMS2 as u64),
            }
        }
    }

    /// Initialize the controller: reset, configure, start.
    ///
    /// Performs the full xHCI initialization sequence:
    /// 1. Wait for controller not ready (CNR) to clear
    /// 2. Reset the host controller
    /// 3. Configure max device slots
    /// 4. Set up command and event rings
    /// 5. Start the controller
    pub fn init(&mut self) -> Result<()> {
        self.wait_ready()?;
        self.reset()?;
        self.wait_ready()?;

        // Configure max slots.
        let hw_max = self.cap_regs.max_slots();
        let slots_to_enable = if hw_max > MAX_SLOTS as u8 {
            MAX_SLOTS as u8
        } else {
            hw_max
        };
        self.max_slots_enabled = slots_to_enable;

        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            mmio_write32(self.op_base + op_reg::CONFIG as u64, slots_to_enable as u32);
        }

        // Set up command ring.
        let crcr = self.command_ring.base_addr() | 1; // RCS = 1
        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            mmio_write64(self.op_base + op_reg::CRCR as u64, crcr);
        }

        // Set up event ring (interrupter 0 runtime registers).
        self.setup_event_ring()?;

        // Start the controller.
        self.start()
    }

    /// Wait for the Controller Not Ready (CNR) bit to clear.
    fn wait_ready(&self) -> Result<()> {
        // Poll with a bounded iteration count to avoid hangs.
        for _ in 0..100_000u32 {
            // SAFETY: op_base is valid MMIO derived from BAR0.
            let sts = unsafe { mmio_read32(self.op_base + op_reg::USBSTS as u64) };
            if (sts & usbsts::CNR) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Issue a host controller reset (HCRST).
    fn reset(&self) -> Result<()> {
        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            mmio_write32(self.op_base + op_reg::USBCMD as u64, usbcmd::HCRST);
        }

        // Wait for HCRST to self-clear.
        for _ in 0..100_000u32 {
            // SAFETY: op_base is valid MMIO derived from BAR0.
            let cmd = unsafe { mmio_read32(self.op_base + op_reg::USBCMD as u64) };
            if (cmd & usbcmd::HCRST) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Set up the primary event ring (interrupter 0).
    fn setup_event_ring(&mut self) -> Result<()> {
        // Interrupter 0 registers are at rt_base + 0x20.
        let ir0_base = self.rt_base + 0x20;

        // SAFETY: rt_base is valid MMIO derived from BAR0.
        unsafe {
            // ERSTSZ — event ring segment table size.
            mmio_write32(ir0_base, self.event_ring.erst_size() as u32);

            // ERDP — event ring dequeue pointer.
            mmio_write64(ir0_base + 0x18, self.event_ring.dequeue_addr());

            // ERSTBA — event ring segment table base address.
            mmio_write64(ir0_base + 0x10, self.event_ring.erst_base());
        }

        Ok(())
    }

    /// Start the host controller (set Run/Stop).
    fn start(&self) -> Result<()> {
        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            let cmd = mmio_read32(self.op_base + op_reg::USBCMD as u64);
            mmio_write32(
                self.op_base + op_reg::USBCMD as u64,
                cmd | usbcmd::RUN_STOP | usbcmd::INTE,
            );
        }

        // Wait for HCH (halted) to clear.
        for _ in 0..100_000u32 {
            // SAFETY: op_base is valid MMIO derived from BAR0.
            let sts = unsafe { mmio_read32(self.op_base + op_reg::USBSTS as u64) };
            if (sts & usbsts::HCH) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Stop the host controller (clear Run/Stop).
    pub fn stop(&self) -> Result<()> {
        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            let cmd = mmio_read32(self.op_base + op_reg::USBCMD as u64);
            mmio_write32(
                self.op_base + op_reg::USBCMD as u64,
                cmd & !usbcmd::RUN_STOP,
            );
        }

        // Wait for HCH (halted) to set.
        for _ in 0..100_000u32 {
            // SAFETY: op_base is valid MMIO derived from BAR0.
            let sts = unsafe { mmio_read32(self.op_base + op_reg::USBSTS as u64) };
            if (sts & usbsts::HCH) != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Get the cached capability registers.
    pub fn cap_regs(&self) -> &XhciCapRegs {
        &self.cap_regs
    }

    /// Read the current operational register snapshot.
    pub fn read_op_regs(&self) -> XhciOpRegs {
        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            XhciOpRegs {
                usbcmd: mmio_read32(self.op_base + op_reg::USBCMD as u64),
                usbsts: mmio_read32(self.op_base + op_reg::USBSTS as u64),
                pagesize: mmio_read32(self.op_base + op_reg::PAGESIZE as u64),
                dnctrl: mmio_read32(self.op_base + op_reg::DNCTRL as u64),
                crcr: mmio_read64(self.op_base + op_reg::CRCR as u64),
                dcbaap: mmio_read64(self.op_base + op_reg::DCBAAP as u64),
                config: mmio_read32(self.op_base + op_reg::CONFIG as u64),
            }
        }
    }

    /// Compute the base address of a port register set.
    ///
    /// Port registers start at op_base + 0x400, each port
    /// occupies 16 bytes. Port numbers are 1-based.
    fn port_base(&self, port: u8) -> Result<u64> {
        if port == 0 || port > self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let offset = 0x400u64 + (port as u64 - 1) * 0x10;
        Ok(self.op_base + offset)
    }

    /// Read the register set for a specific port (1-based).
    pub fn read_port_regs(&self, port: u8) -> Result<XhciPortRegs> {
        let base = self.port_base(port)?;
        // SAFETY: port base is within the MMIO region.
        unsafe {
            Ok(XhciPortRegs {
                portsc: mmio_read32(base + port_reg::PORTSC as u64),
                portpmsc: mmio_read32(base + port_reg::PORTPMSC as u64),
                portli: mmio_read32(base + port_reg::PORTLI as u64),
                porthlpmc: mmio_read32(base + port_reg::PORTHLPMC as u64),
            })
        }
    }

    /// Get the decoded status of a port (1-based).
    pub fn port_status(&self, port: u8) -> Result<XhciPortStatus> {
        let regs = self.read_port_regs(port)?;
        Ok(XhciPortStatus::from_portsc(regs.portsc))
    }

    /// Reset a port (1-based) and wait for completion.
    pub fn reset_port(&self, port: u8) -> Result<()> {
        let base = self.port_base(port)?;
        // SAFETY: port base is within the MMIO region.
        unsafe {
            let sc = mmio_read32(base + port_reg::PORTSC as u64);
            // Write PR (port reset), preserve PP, clear RW1C bits.
            let preserve = portsc::PP;
            let clear_rw1c = portsc::CSC | portsc::PRC | portsc::PED;
            let val = (sc & preserve & (!clear_rw1c)) | portsc::PR;
            mmio_write32(base + port_reg::PORTSC as u64, val);
        }

        // Wait for PRC (port reset change) to indicate completion.
        for _ in 0..100_000u32 {
            // SAFETY: port base is within the MMIO region.
            let sc = unsafe { mmio_read32(base + port_reg::PORTSC as u64) };
            if (sc & portsc::PRC) != 0 {
                // Clear PRC by writing 1 to it.
                // SAFETY: port base is within the MMIO region.
                unsafe {
                    mmio_write32(
                        base + port_reg::PORTSC as u64,
                        (sc & portsc::PP) | portsc::PRC,
                    );
                }
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Number of ports on this controller.
    pub fn num_ports(&self) -> u8 {
        self.num_ports
    }

    /// Maximum slots enabled on this controller.
    pub fn max_slots_enabled(&self) -> u8 {
        self.max_slots_enabled
    }

    /// Ring the doorbell for a given slot (0 = host controller).
    pub fn ring_doorbell(&self, slot: u8, target: u32) {
        let addr = self.db_base + slot as u64 * 4;
        // SAFETY: db_base is valid MMIO derived from BAR0.
        unsafe {
            mmio_write32(addr, target);
        }
    }

    /// Enqueue a command TRB and ring the host controller doorbell.
    pub fn send_command(&mut self, trb: Trb) -> Result<u64> {
        let addr = self.command_ring.enqueue(trb)?;
        self.ring_doorbell(0, 0); // slot 0, target 0 = command ring
        Ok(addr)
    }

    /// Poll the event ring for the next event TRB.
    pub fn poll_event(&mut self) -> Option<Trb> {
        let event = self.event_ring.dequeue()?;

        // Update the ERDP (event ring dequeue pointer).
        let ir0_base = self.rt_base + 0x20;
        // SAFETY: rt_base is valid MMIO derived from BAR0.
        unsafe {
            mmio_write64(ir0_base + 0x18, self.event_ring.dequeue_addr() | (1 << 3));
        }

        Some(event)
    }

    /// Issue an Enable Slot command and return the slot ID.
    pub fn enable_slot(&mut self) -> Result<u8> {
        let mut trb = Trb::new();
        trb.set_type_and_cycle(TrbType::EnableSlot, true);
        self.send_command(trb)?;

        // Poll for command completion.
        for _ in 0..100_000u32 {
            if let Some(event) = self.poll_event() {
                if event.trb_type() == Some(TrbType::CommandCompletion) {
                    let code = event.completion_code();
                    if code != 1 {
                        // 1 = Success
                        return Err(Error::IoError);
                    }
                    let slot_id = event.slot_id();
                    if slot_id == 0 || slot_id as usize > MAX_SLOTS {
                        return Err(Error::IoError);
                    }
                    return Ok(slot_id);
                }
            }
        }
        Err(Error::Busy)
    }

    /// Disable a previously enabled slot.
    pub fn disable_slot(&mut self, slot_id: u8) -> Result<()> {
        if slot_id == 0 || slot_id as usize > MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }

        let mut trb = Trb::new();
        trb.set_type_and_cycle(TrbType::DisableSlot, true);
        trb.control |= (slot_id as u32) << 24;
        self.send_command(trb)?;

        // Poll for completion.
        for _ in 0..100_000u32 {
            if let Some(event) = self.poll_event() {
                if event.trb_type() == Some(TrbType::CommandCompletion) {
                    let code = event.completion_code();
                    if code != 1 {
                        return Err(Error::IoError);
                    }
                    let idx = (slot_id - 1) as usize;
                    self.slots[idx].deactivate();
                    return Ok(());
                }
            }
        }
        Err(Error::Busy)
    }

    /// Activate a device slot with port and speed information.
    pub fn activate_slot(&mut self, slot_id: u8, port: u8, speed: UsbSpeed) -> Result<()> {
        if slot_id == 0 || slot_id as usize > MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }
        let idx = (slot_id - 1) as usize;
        self.slots[idx].activate(slot_id, port, speed);
        Ok(())
    }

    /// Get a reference to a device slot (1-based slot ID).
    pub fn slot(&self, slot_id: u8) -> Result<&DeviceSlot> {
        if slot_id == 0 || slot_id as usize > MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.slots[(slot_id - 1) as usize])
    }

    /// Get a mutable reference to a device slot (1-based slot ID).
    pub fn slot_mut(&mut self, slot_id: u8) -> Result<&mut DeviceSlot> {
        if slot_id == 0 || slot_id as usize > MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.slots[(slot_id - 1) as usize])
    }

    /// Acknowledge pending interrupts by reading and clearing USBSTS.
    pub fn ack_interrupts(&self) -> u32 {
        // SAFETY: op_base is valid MMIO derived from BAR0.
        unsafe {
            let sts = mmio_read32(self.op_base + op_reg::USBSTS as u64);
            // Write back to clear RW1C status bits.
            mmio_write32(self.op_base + op_reg::USBSTS as u64, sts);
            sts
        }
    }
}

impl core::fmt::Debug for XhciController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XhciController")
            .field("bar_base", &format_args!("{:#X}", self.bar_base))
            .field("hci_version", &self.cap_regs.hci_version)
            .field("num_ports", &self.num_ports)
            .field("max_slots_enabled", &self.max_slots_enabled)
            .finish()
    }
}
