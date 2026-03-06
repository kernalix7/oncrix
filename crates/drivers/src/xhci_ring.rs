// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! xHCI Transfer Ring and Event Ring management.
//!
//! In xHCI, all communication between software and hardware uses rings of
//! Transfer Request Blocks (TRBs). Each TRB is 16 bytes. There are three
//! ring types:
//!
//! - **Transfer Ring** (one per endpoint): Software enqueues TRBs for the
//!   host controller to process.
//! - **Command Ring** (one per controller): Software sends commands (enable
//!   slot, configure endpoint, etc.).
//! - **Event Ring** (one per interrupter): Controller writes completion
//!   events here; software reads them.
//!
//! Reference: xHCI Specification 1.2, §4 — USB Device Model.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Ring Constants
// ---------------------------------------------------------------------------

/// Size of a single TRB in bytes (always 16).
pub const TRB_SIZE: usize = 16;

/// Default ring size (number of TRBs, excluding Link TRB).
pub const DEFAULT_RING_SIZE: usize = 256;

/// Maximum ring size.
pub const MAX_RING_SIZE: usize = 1024;

// ---------------------------------------------------------------------------
// TRB Types
// ---------------------------------------------------------------------------

/// TRB type field values (bits 15:10 of DW3).
pub mod trb_type {
    /// Normal transfer TRB.
    pub const NORMAL: u8 = 1;
    /// Setup Stage TRB (control transfers).
    pub const SETUP_STAGE: u8 = 2;
    /// Data Stage TRB (control transfers).
    pub const DATA_STAGE: u8 = 3;
    /// Status Stage TRB (control transfers).
    pub const STATUS_STAGE: u8 = 4;
    /// Isoch TRB.
    pub const ISOCH: u8 = 5;
    /// Link TRB (ring wrap-around).
    pub const LINK: u8 = 6;
    /// Event Data TRB.
    pub const EVENT_DATA: u8 = 7;
    /// No-Op Transfer TRB.
    pub const NOOP: u8 = 8;
    /// Enable Slot Command.
    pub const ENABLE_SLOT: u8 = 9;
    /// Disable Slot Command.
    pub const DISABLE_SLOT: u8 = 10;
    /// Address Device Command.
    pub const ADDRESS_DEVICE: u8 = 11;
    /// Configure Endpoint Command.
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    /// Evaluate Context Command.
    pub const EVALUATE_CONTEXT: u8 = 13;
    /// Reset Endpoint Command.
    pub const RESET_ENDPOINT: u8 = 14;
    /// Stop Endpoint Command.
    pub const STOP_ENDPOINT: u8 = 15;
    /// Set TR Dequeue Pointer Command.
    pub const SET_TR_DEQUEUE: u8 = 16;
    /// Reset Device Command.
    pub const RESET_DEVICE: u8 = 17;
    /// No-Op Command.
    pub const NOOP_CMD: u8 = 23;
    /// Transfer Event (from hardware).
    pub const TRANSFER_EVENT: u8 = 32;
    /// Command Completion Event (from hardware).
    pub const CMD_COMPLETION_EVENT: u8 = 33;
    /// Port Status Change Event.
    pub const PORT_STATUS_CHANGE: u8 = 34;
    /// Host Controller Event.
    pub const HOST_CONTROLLER_EVENT: u8 = 37;
}

/// Completion codes for event TRBs.
pub mod completion_code {
    /// Command/transfer completed successfully.
    pub const SUCCESS: u8 = 1;
    /// Data Buffer Error.
    pub const DATA_BUFFER: u8 = 2;
    /// Babble Detected Error.
    pub const BABBLE_DETECTED: u8 = 3;
    /// USB Transaction Error.
    pub const USB_TRANSACTION: u8 = 4;
    /// TRB Error.
    pub const TRB_ERROR: u8 = 5;
    /// Stall Error.
    pub const STALL: u8 = 6;
    /// Ring Underrun.
    pub const RING_UNDERRUN: u8 = 14;
    /// Ring Overrun.
    pub const RING_OVERRUN: u8 = 15;
    /// Short Packet.
    pub const SHORT_PACKET: u8 = 13;
    /// Stopped (endpoint was stopped mid-transfer).
    pub const STOPPED: u8 = 26;
}

// ---------------------------------------------------------------------------
// Raw TRB
// ---------------------------------------------------------------------------

/// A 16-byte Transfer Request Block.
///
/// `#[repr(C)]` is required for DMA; the hardware interprets this layout directly.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Trb {
    /// DW0: parameter / data buffer pointer low.
    pub dw0: u32,
    /// DW1: parameter / data buffer pointer high.
    pub dw1: u32,
    /// DW2: status / transfer length.
    pub dw2: u32,
    /// DW3: control — type, flags, cycle bit, etc.
    pub dw3: u32,
}

impl Trb {
    /// Creates a null (zero) TRB.
    pub const fn null() -> Self {
        Self {
            dw0: 0,
            dw1: 0,
            dw2: 0,
            dw3: 0,
        }
    }

    /// Returns the TRB type (bits 15:10 of DW3).
    pub const fn trb_type(&self) -> u8 {
        ((self.dw3 >> 10) & 0x3F) as u8
    }

    /// Returns the Cycle bit (bit 0 of DW3).
    pub const fn cycle(&self) -> bool {
        self.dw3 & 1 != 0
    }

    /// Returns the completion code from an event TRB (bits 31:24 of DW2).
    pub const fn completion_code(&self) -> u8 {
        (self.dw2 >> 24) as u8
    }

    /// Returns the Transfer Length Remaining from an event TRB (bits 23:0 of DW2).
    pub const fn transfer_length(&self) -> u32 {
        self.dw2 & 0x00FF_FFFF
    }

    /// Builds DW3 with the given type and flags.
    pub const fn make_dw3(trb_type: u8, flags: u16, cycle: bool) -> u32 {
        ((trb_type as u32) << 10) | ((flags as u32) << 16) | (cycle as u32)
    }

    /// Creates a Normal TRB for a data transfer.
    ///
    /// # Parameters
    /// - `buf_phys`: Physical address of the data buffer.
    /// - `length`: Transfer length in bytes.
    /// - `ioc`: If `true`, set the Interrupt On Completion flag.
    /// - `cycle`: Current cycle bit value for this ring.
    pub fn normal(buf_phys: u64, length: u32, ioc: bool, cycle: bool) -> Self {
        let flags: u16 = if ioc { 0x20 } else { 0 }; // IOC flag
        Self {
            dw0: (buf_phys & 0xFFFF_FFFF) as u32,
            dw1: (buf_phys >> 32) as u32,
            dw2: length & 0x0001_FFFF,
            dw3: Self::make_dw3(trb_type::NORMAL, flags, cycle),
        }
    }

    /// Creates a Link TRB for ring wrap-around.
    ///
    /// # Parameters
    /// - `ring_phys`: Physical address of the first TRB in the ring.
    /// - `toggle_cycle`: If `true`, set the Toggle Cycle bit.
    /// - `cycle`: Current cycle bit.
    pub fn link(ring_phys: u64, toggle_cycle: bool, cycle: bool) -> Self {
        let tc: u32 = if toggle_cycle { 1 << 1 } else { 0 };
        Self {
            dw0: (ring_phys & 0xFFFF_FFFF) as u32,
            dw1: (ring_phys >> 32) as u32,
            dw2: 0,
            dw3: ((trb_type::LINK as u32) << 10) | tc | (cycle as u32),
        }
    }

    /// Creates a No-Op Command TRB.
    pub fn noop_cmd(cycle: bool) -> Self {
        Self {
            dw0: 0,
            dw1: 0,
            dw2: 0,
            dw3: ((trb_type::NOOP_CMD as u32) << 10) | (cycle as u32),
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer Ring
// ---------------------------------------------------------------------------

/// An xHCI transfer/command ring (software → hardware).
pub struct TransferRing {
    /// Physical base address of the ring.
    phys_base: u64,
    /// Virtual base address.
    virt_base: u64,
    /// Number of TRBs (excluding the Link TRB).
    capacity: usize,
    /// Current enqueue pointer (index of next slot to write).
    enqueue: usize,
    /// Current Producer Cycle State.
    cycle: bool,
}

impl TransferRing {
    /// Creates a new transfer ring.
    ///
    /// # Parameters
    /// - `phys_base`: Physical address of the DMA-accessible TRB array.
    /// - `virt_base`: Virtual address of the same array.
    /// - `capacity`: Number of usable TRB slots (Link TRB will be placed at `capacity`).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `capacity == 0` or `capacity > MAX_RING_SIZE`.
    pub fn new(phys_base: u64, virt_base: u64, capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_RING_SIZE {
            return Err(Error::InvalidArgument);
        }
        let ring = Self {
            phys_base,
            virt_base,
            capacity,
            enqueue: 0,
            cycle: true,
        };
        // Write the Link TRB at index `capacity`.
        let link_addr = ring.trb_virt(capacity);
        let link = Trb::link(phys_base, true, ring.cycle);
        // SAFETY: virt_base is a valid DMA allocation of size (capacity+1)*TRB_SIZE.
        unsafe {
            core::ptr::write_volatile(link_addr as *mut Trb, link);
        }
        Ok(ring)
    }

    /// Returns the virtual address of TRB at `index`.
    fn trb_virt(&self, index: usize) -> u64 {
        self.virt_base + (index * TRB_SIZE) as u64
    }

    /// Returns the physical address of the enqueue pointer (for CRCR/TREP).
    pub fn enqueue_phys(&self) -> u64 {
        self.phys_base + (self.enqueue * TRB_SIZE) as u64
    }

    /// Returns the physical base of the ring.
    pub fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Returns the current cycle bit.
    pub fn cycle(&self) -> bool {
        self.cycle
    }

    /// Enqueues a single TRB.
    ///
    /// Automatically advances past the Link TRB and toggles the cycle bit.
    ///
    /// # Errors
    /// Returns `Error::Busy` if the ring is full.
    ///
    /// # Safety
    /// `virt_base` must point to a valid DMA ring allocation.
    pub unsafe fn enqueue(&mut self, mut trb: Trb) -> Result<u64> {
        // Set cycle bit in the TRB.
        if self.cycle {
            trb.dw3 |= 1;
        } else {
            trb.dw3 &= !1;
        }

        let slot = self.enqueue;
        let slot_virt = self.trb_virt(slot);

        // SAFETY: Caller guarantees virt_base is a valid ring.
        unsafe {
            core::ptr::write_volatile(slot_virt as *mut Trb, trb);
        }

        self.enqueue += 1;
        // Wrap at Link TRB.
        if self.enqueue >= self.capacity {
            self.enqueue = 0;
            self.cycle = !self.cycle;
            // Rewrite the Link TRB with the new cycle bit.
            let link_virt = self.trb_virt(self.capacity);
            let link = Trb::link(self.phys_base, true, self.cycle);
            // SAFETY: link_virt is within the allocated ring.
            unsafe {
                core::ptr::write_volatile(link_virt as *mut Trb, link);
            }
        }

        Ok(self.phys_base + (slot * TRB_SIZE) as u64)
    }
}

// ---------------------------------------------------------------------------
// Event Ring Segment Table Entry
// ---------------------------------------------------------------------------

/// Event Ring Segment Table Entry (ERSTE) as required by xHCI §6.5.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ErsteEntry {
    /// Physical base address of the event ring segment.
    pub base_lo: u32,
    /// Physical base high.
    pub base_hi: u32,
    /// Segment size (number of TRBs).
    pub size: u32,
    /// Reserved.
    _reserved: u32,
}

impl ErsteEntry {
    /// Creates an ERSTE entry.
    pub fn new(base_phys: u64, size: u32) -> Self {
        Self {
            base_lo: (base_phys & 0xFFFF_FFFF) as u32,
            base_hi: (base_phys >> 32) as u32,
            size,
            _reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Event Ring
// ---------------------------------------------------------------------------

/// An xHCI event ring (hardware → software).
pub struct EventRing {
    /// Physical base of the TRB array.
    phys_base: u64,
    /// Virtual base of the TRB array.
    virt_base: u64,
    /// Ring capacity (number of TRBs).
    capacity: usize,
    /// Current dequeue index.
    dequeue: usize,
    /// Current Consumer Cycle State.
    cycle: bool,
}

impl EventRing {
    /// Creates a new event ring.
    ///
    /// # Parameters
    /// - `phys_base`: Physical address of the hardware-written TRB array.
    /// - `virt_base`: Virtual address of the same array.
    /// - `capacity`: Number of TRB slots (must be > 0 and <= `MAX_RING_SIZE`).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `capacity` is out of range.
    pub fn new(phys_base: u64, virt_base: u64, capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_RING_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            phys_base,
            virt_base,
            capacity,
            dequeue: 0,
            cycle: true,
        })
    }

    /// Returns the physical address of the current dequeue pointer.
    ///
    /// This should be written to the ERDP register after processing events.
    pub fn dequeue_phys(&self) -> u64 {
        self.phys_base + (self.dequeue * TRB_SIZE) as u64
    }

    /// Attempts to dequeue one event TRB.
    ///
    /// Returns `None` if the ring is empty (no new events from hardware).
    ///
    /// # Safety
    /// `virt_base` must point to a valid DMA region written by the xHCI controller.
    pub unsafe fn dequeue(&mut self) -> Option<Trb> {
        let slot_virt = self.virt_base + (self.dequeue * TRB_SIZE) as u64;
        // SAFETY: Hardware writes this region; volatile read prevents elision.
        let trb = unsafe { core::ptr::read_volatile(slot_virt as *const Trb) };
        // A TRB is valid if its Cycle bit matches the Consumer Cycle State.
        if trb.cycle() != self.cycle {
            return None;
        }
        self.dequeue += 1;
        if self.dequeue >= self.capacity {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }

    /// Returns the physical base of this ring.
    pub fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Returns the ring capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}
