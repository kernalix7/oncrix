// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! xHCI Transfer Ring and Event Ring management.
//!
//! Implements the ring structures used by the eXtensible Host Controller
//! Interface (xHCI) for USB 3.x communication:
//!
//! - **Transfer Ring** — used by software to post TRBs (Transfer Request
//!   Blocks) to the controller for execution on a specific endpoint.
//! - **Event Ring** — used by the controller to report completion events
//!   back to software (Transfer Events, Command Completion Events, etc.)
//! - **Command Ring** — a transfer ring used specifically for host
//!   controller commands.
//!
//! # TRB Types
//!
//! Transfer TRBs: Normal, Setup Stage, Data Stage, Status Stage, Link.
//! Event TRBs: Transfer Event, Command Completion, Port Status Change.
//!
//! Reference: eXtensible Host Controller Interface (xHCI) Specification
//! for USB 3.2 Revision 1.2, Section 4.11 (Transfer Ring Management)

use oncrix_lib::{Error, Result};

// ── TRB type codes ────────────────────────────────────────────────────────────

/// TRB Type: Normal Transfer (bulk/interrupt IN/OUT data).
pub const TRB_TYPE_NORMAL: u32 = 1;
/// TRB Type: Setup Stage (control).
pub const TRB_TYPE_SETUP_STAGE: u32 = 2;
/// TRB Type: Data Stage (control).
pub const TRB_TYPE_DATA_STAGE: u32 = 3;
/// TRB Type: Status Stage (control).
pub const TRB_TYPE_STATUS_STAGE: u32 = 4;
/// TRB Type: Isoch.
pub const _TRB_TYPE_ISOCH: u32 = 5;
/// TRB Type: Link TRB (wraps ring back to start).
pub const TRB_TYPE_LINK: u32 = 6;
/// TRB Type: Event Data.
pub const _TRB_TYPE_EVENT_DATA: u32 = 7;
/// TRB Type: No-Op Transfer.
pub const _TRB_TYPE_NOOP: u32 = 8;
/// TRB Type: Enable Slot Command.
pub const TRB_TYPE_ENABLE_SLOT: u32 = 9;
/// TRB Type: Disable Slot Command.
pub const _TRB_TYPE_DISABLE_SLOT: u32 = 10;
/// TRB Type: Address Device Command.
pub const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
/// TRB Type: Configure Endpoint Command.
pub const TRB_TYPE_CONFIG_ENDPOINT: u32 = 12;
/// TRB Type: Transfer Event.
pub const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
/// TRB Type: Command Completion Event.
pub const TRB_TYPE_CMD_COMPLETION: u32 = 33;
/// TRB Type: Port Status Change Event.
pub const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;

// ── TRB completion codes ──────────────────────────────────────────────────────

/// Completion Code: Success.
pub const CC_SUCCESS: u8 = 1;
/// Completion Code: Data Buffer Error.
pub const CC_DATA_BUFFER_ERROR: u8 = 2;
/// Completion Code: Short Packet.
pub const CC_SHORT_PACKET: u8 = 13;
/// Completion Code: Stall Error.
pub const CC_STALL_ERROR: u8 = 6;
/// Completion Code: TRB Error.
pub const CC_TRB_ERROR: u8 = 5;

// ── Ring sizes ────────────────────────────────────────────────────────────────

/// Number of TRBs in a transfer ring (including one Link TRB).
const TRANSFER_RING_SIZE: usize = 256;
/// Number of TRBs in the event ring.
const EVENT_RING_SIZE: usize = 256;
/// Number of TRBs in the command ring.
const COMMAND_RING_SIZE: usize = 64;

// ── Trb ──────────────────────────────────────────────────────────────────────

/// A Transfer Request Block (TRB) — 16 bytes, must be 16-byte aligned.
///
/// Layout varies by TRB type but the control DWORD always contains the
/// TRB type in bits 15:10 and the Cycle bit in bit 0.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(16))]
pub struct Trb {
    /// Parameter field (address, setup data, etc.).
    pub parameter: u64,
    /// Status field (length, completion code).
    pub status: u32,
    /// Control field: TRB type [15:10], flags, Cycle bit [0].
    pub control: u32,
}

impl Trb {
    /// Return the TRB type (bits 15:10 of control).
    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    /// Return the Cycle bit (bit 0 of control).
    pub fn cycle_bit(&self) -> bool {
        self.control & 1 != 0
    }

    /// Return the completion code (bits 31:24 of status).
    pub fn completion_code(&self) -> u8 {
        (self.status >> 24) as u8
    }

    /// Return the transfer length remaining (bits 23:0 of status).
    pub fn transfer_length(&self) -> u32 {
        self.status & 0x00FF_FFFF
    }

    /// Build a Normal TRB.
    pub fn normal(buf_addr: u64, len: u32, ioc: bool, cycle: bool) -> Self {
        let status = len & 0x1FFFF;
        let mut control = TRB_TYPE_NORMAL << 10;
        if ioc {
            control |= 1 << 5; // IOC: Interrupt On Completion
        }
        if cycle {
            control |= 1;
        }
        Self {
            parameter: buf_addr,
            status,
            control,
        }
    }

    /// Build a Setup Stage TRB for control transfers.
    pub fn setup_stage(
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
        cycle: bool,
    ) -> Self {
        let param = (request_type as u64)
            | ((request as u64) << 8)
            | ((value as u64) << 16)
            | ((index as u64) << 32)
            | ((length as u64) << 48);
        // TRT=3 (IN data), IDT=1 (Immediate Data)
        let mut control = (TRB_TYPE_SETUP_STAGE << 10) | (3 << 16) | (1 << 6);
        if cycle {
            control |= 1;
        }
        Self {
            parameter: param,
            status: 8,
            control,
        }
    }

    /// Build a Data Stage TRB.
    pub fn data_stage(buf_addr: u64, len: u32, dir_in: bool, cycle: bool) -> Self {
        let status = len & 0x1FFFF;
        let mut control = TRB_TYPE_DATA_STAGE << 10;
        if dir_in {
            control |= 1 << 16; // DIR bit
        }
        control |= 1 << 5; // IOC
        if cycle {
            control |= 1;
        }
        Self {
            parameter: buf_addr,
            status,
            control,
        }
    }

    /// Build a Status Stage TRB.
    pub fn status_stage(dir_in: bool, cycle: bool) -> Self {
        let mut control = (TRB_TYPE_STATUS_STAGE << 10) | (1 << 5); // IOC
        if dir_in {
            control |= 1 << 16; // DIR bit: opposite of data direction
        }
        if cycle {
            control |= 1;
        }
        Self {
            parameter: 0,
            status: 0,
            control,
        }
    }

    /// Build a Link TRB pointing to `next_ring_addr`.
    pub fn link(next_ring_addr: u64, toggle_cycle: bool, cycle: bool) -> Self {
        let mut control = TRB_TYPE_LINK << 10;
        if toggle_cycle {
            control |= 1 << 1; // TC bit
        }
        if cycle {
            control |= 1;
        }
        Self {
            parameter: next_ring_addr,
            status: 0,
            control,
        }
    }

    /// Build an Enable Slot command TRB.
    pub fn enable_slot(slot_type: u8, cycle: bool) -> Self {
        let mut control = (TRB_TYPE_ENABLE_SLOT << 10) | ((slot_type as u32) << 16);
        if cycle {
            control |= 1;
        }
        Self {
            parameter: 0,
            status: 0,
            control,
        }
    }

    /// Build an Address Device command TRB.
    pub fn address_device(
        input_ctx_addr: u64,
        slot_id: u8,
        block_set_addr: bool,
        cycle: bool,
    ) -> Self {
        let mut control = (TRB_TYPE_ADDRESS_DEVICE << 10) | ((slot_id as u32) << 24);
        if block_set_addr {
            control |= 1 << 9; // BSR bit
        }
        if cycle {
            control |= 1;
        }
        Self {
            parameter: input_ctx_addr,
            status: 0,
            control,
        }
    }
}

// ── TransferRing ──────────────────────────────────────────────────────────────

/// xHCI Transfer Ring.
///
/// A circular buffer of TRBs with a Link TRB at the end that wraps
/// back to the beginning. The controller processes TRBs starting at
/// the enqueue pointer when the Cycle bit matches.
pub struct TransferRing {
    /// TRB buffer.
    trbs: [Trb; TRANSFER_RING_SIZE],
    /// Current enqueue index (where software writes next TRB).
    enqueue: usize,
    /// Current dequeue index (where controller is reading).
    dequeue: usize,
    /// Current producer cycle state (flips when ring wraps).
    cycle: bool,
    /// Physical address of the ring buffer.
    ring_addr: u64,
}

impl TransferRing {
    /// Create a new transfer ring at the given physical address.
    pub fn new(ring_addr: u64) -> Self {
        let mut ring = Self {
            trbs: [Trb::default(); TRANSFER_RING_SIZE],
            enqueue: 0,
            dequeue: 0,
            cycle: true,
            ring_addr,
        };
        // Set up the Link TRB at the last slot.
        let last = TRANSFER_RING_SIZE - 1;
        ring.trbs[last] = Trb::link(ring_addr, true, ring.cycle);
        ring
    }

    /// Enqueue a TRB onto the ring.
    ///
    /// Sets the Cycle bit to the current producer state before writing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the ring is full (enqueue caught up to dequeue).
    pub fn enqueue(&mut self, mut trb: Trb) -> Result<u64> {
        // Check if ring is full.
        let next = (self.enqueue + 1) % (TRANSFER_RING_SIZE - 1);
        if next == self.dequeue {
            return Err(Error::Busy);
        }

        // Set cycle bit.
        if self.cycle {
            trb.control |= 1;
        } else {
            trb.control &= !1;
        }

        // SAFETY: Writing TRB to ring; ring_addr is mapped DMA memory.
        unsafe { core::ptr::write_volatile(&mut self.trbs[self.enqueue], trb) };

        let trb_addr = self.ring_addr + (self.enqueue * core::mem::size_of::<Trb>()) as u64;

        self.enqueue += 1;
        if self.enqueue == TRANSFER_RING_SIZE - 1 {
            // Hit the Link TRB — update it and wrap.
            let cycle = self.cycle;
            // SAFETY: Updating Link TRB cycle bit.
            unsafe {
                let link = &mut self.trbs[TRANSFER_RING_SIZE - 1];
                if cycle {
                    link.control |= 1;
                } else {
                    link.control &= !1;
                }
                core::ptr::write_volatile(link, *link);
            }
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }

        Ok(trb_addr)
    }

    /// Advance the dequeue pointer (after controller notifies via event).
    pub fn advance_dequeue(&mut self) {
        self.dequeue = (self.dequeue + 1) % (TRANSFER_RING_SIZE - 1);
    }

    /// Return the physical address of the ring.
    pub fn ring_addr(&self) -> u64 {
        self.ring_addr
    }

    /// Return the current enqueue pointer physical address.
    pub fn enqueue_addr(&self) -> u64 {
        self.ring_addr + (self.enqueue * core::mem::size_of::<Trb>()) as u64
    }

    /// Return the current producer cycle bit.
    pub fn cycle(&self) -> bool {
        self.cycle
    }

    /// Return whether the ring is empty (enqueue == dequeue).
    pub fn is_empty(&self) -> bool {
        self.enqueue == self.dequeue
    }
}

// ── EventRing ─────────────────────────────────────────────────────────────────

/// xHCI Event Ring.
///
/// Software reads events from the event ring. The controller writes
/// Transfer Events, Command Completion Events, and Port Status Change
/// Events here. Software advances the dequeue pointer in the Event Ring
/// Dequeue Pointer (ERDP) register after processing each event.
pub struct EventRing {
    /// Event TRB buffer.
    trbs: [Trb; EVENT_RING_SIZE],
    /// Current dequeue index.
    dequeue: usize,
    /// Consumer cycle state (matches controller's produce cycle).
    cycle: bool,
    /// Physical address of the event ring.
    ring_addr: u64,
}

impl EventRing {
    /// Create a new event ring at the given physical address.
    pub fn new(ring_addr: u64) -> Self {
        Self {
            trbs: [Trb::default(); EVENT_RING_SIZE],
            dequeue: 0,
            cycle: true,
            ring_addr,
        }
    }

    /// Dequeue an event TRB if one is available.
    ///
    /// Returns `None` if the ring is empty (no new events from controller).
    pub fn dequeue(&mut self) -> Option<Trb> {
        // SAFETY: Reading TRB from event ring with volatile for DMA sync.
        let trb = unsafe { core::ptr::read_volatile(&self.trbs[self.dequeue]) };

        // Event is valid if its cycle bit matches the consumer cycle.
        if trb.cycle_bit() != self.cycle {
            return None;
        }

        let result = trb;
        self.dequeue = (self.dequeue + 1) % EVENT_RING_SIZE;
        if self.dequeue == 0 {
            self.cycle = !self.cycle;
        }
        Some(result)
    }

    /// Return the physical address of the current dequeue pointer.
    ///
    /// Software writes this to the ERDP register to inform the controller.
    pub fn dequeue_addr(&self) -> u64 {
        self.ring_addr + (self.dequeue * core::mem::size_of::<Trb>()) as u64
    }

    /// Return the physical address of the segment table entry (for ERST).
    pub fn ring_addr(&self) -> u64 {
        self.ring_addr
    }

    /// Return the ring size.
    pub fn ring_size(&self) -> usize {
        EVENT_RING_SIZE
    }
}

// ── CommandRing ───────────────────────────────────────────────────────────────

/// xHCI Command Ring (a specialized transfer ring for host commands).
pub struct CommandRing {
    inner: TransferRing,
}

impl CommandRing {
    /// Create a new command ring at the given physical address.
    pub fn new(ring_addr: u64) -> Self {
        let mut inner = TransferRing::new(ring_addr);
        // Command ring uses a smaller buffer.
        // Re-create with COMMAND_RING_SIZE semantics.
        // For simplicity, reuse the full transfer ring struct but note
        // only COMMAND_RING_SIZE - 1 entries are usable.
        let last = COMMAND_RING_SIZE - 1;
        inner.trbs[last] = Trb::link(ring_addr, true, inner.cycle);
        Self { inner }
    }

    /// Enqueue a command TRB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the command ring is full.
    pub fn enqueue_cmd(&mut self, trb: Trb) -> Result<u64> {
        self.inner.enqueue(trb)
    }

    /// Return the ring address for writing to CRCR.
    pub fn ring_addr(&self) -> u64 {
        self.inner.ring_addr()
    }

    /// Return the current cycle bit for writing to CRCR.
    pub fn cycle(&self) -> bool {
        self.inner.cycle()
    }

    /// Advance the dequeue pointer after a Command Completion Event.
    pub fn advance_dequeue(&mut self) {
        self.inner.advance_dequeue();
    }
}

// ── EventRingSegmentTableEntry ─────────────────────────────────────────────

/// Event Ring Segment Table Entry (ERSTE).
///
/// The xHCI Event Ring Segment Table (ERST) is an array of these entries
/// that tells the controller where each event ring segment is located.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(64))]
pub struct EventRingSegmentTableEntry {
    /// Physical base address of the segment.
    pub ring_segment_base_address: u64,
    /// Number of TRBs in the segment (must be a multiple of 16).
    pub ring_segment_size: u16,
    /// Reserved (must be 0).
    pub _reserved: [u16; 3],
}

impl EventRingSegmentTableEntry {
    /// Create a new ERSTE for the given event ring.
    pub fn new(base_addr: u64, size: u16) -> Self {
        Self {
            ring_segment_base_address: base_addr,
            ring_segment_size: size,
            _reserved: [0; 3],
        }
    }
}

/// Check whether a TRB completion indicates success.
pub fn trb_is_success(trb: &Trb) -> bool {
    let cc = trb.completion_code();
    cc == CC_SUCCESS || cc == CC_SHORT_PACKET
}
