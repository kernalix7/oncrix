// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CAN (Controller Area Network) socket interface.
//!
//! Provides the upper-layer CAN socket abstraction analogous to Linux's
//! SocketCAN subsystem. Supports raw CAN frames, CAN FD frames, filtering,
//! error frame delivery, and timestamping.

use oncrix_lib::{Error, Result};

/// Maximum CAN 2.0 frame payload length.
pub const CAN_MAX_DLC: usize = 8;
/// Maximum CAN FD frame payload length.
pub const CANFD_MAX_DLC: usize = 64;

/// CAN frame ID flags.
/// Bit 31: Extended frame format (EFF) — 29-bit ID.
pub const CAN_EFF_FLAG: u32 = 0x8000_0000;
/// Bit 30: Remote Transmission Request.
pub const CAN_RTR_FLAG: u32 = 0x4000_0000;
/// Bit 29: Error frame.
pub const CAN_ERR_FLAG: u32 = 0x2000_0000;
/// Mask for standard 11-bit ID.
pub const CAN_SFF_MASK: u32 = 0x0000_07FF;
/// Mask for extended 29-bit ID.
pub const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;

/// CAN FD frame flags.
/// BRS — Bit Rate Switch.
pub const CANFD_BRS: u8 = 1 << 0;
/// ESI — Error State Indicator.
pub const CANFD_ESI: u8 = 1 << 1;

/// Standard CAN 2.0B frame.
#[derive(Clone, Copy, Debug)]
pub struct CanFrame {
    /// CAN ID with EFF/RTR/ERR flags.
    pub can_id: u32,
    /// Data length code (0–8).
    pub dlc: u8,
    /// Frame payload (only dlc bytes are valid).
    pub data: [u8; CAN_MAX_DLC],
}

impl CanFrame {
    /// Create a new data frame.
    pub const fn new(id: u32, dlc: u8, data: [u8; CAN_MAX_DLC]) -> Self {
        Self {
            can_id: id,
            dlc,
            data,
        }
    }

    /// Create a new remote transmission request.
    pub const fn rtr(id: u32, dlc: u8) -> Self {
        Self {
            can_id: id | CAN_RTR_FLAG,
            dlc,
            data: [0u8; CAN_MAX_DLC],
        }
    }

    /// Return true if this is an RTR frame.
    pub fn is_rtr(&self) -> bool {
        (self.can_id & CAN_RTR_FLAG) != 0
    }

    /// Return true if this uses the extended 29-bit ID.
    pub fn is_eff(&self) -> bool {
        (self.can_id & CAN_EFF_FLAG) != 0
    }

    /// Return the raw CAN ID (without flag bits).
    pub fn id(&self) -> u32 {
        if self.is_eff() {
            self.can_id & CAN_EFF_MASK
        } else {
            self.can_id & CAN_SFF_MASK
        }
    }
}

impl Default for CanFrame {
    fn default() -> Self {
        Self {
            can_id: 0,
            dlc: 0,
            data: [0u8; CAN_MAX_DLC],
        }
    }
}

/// CAN FD frame (ISO 11898-1:2015).
#[derive(Clone, Copy, Debug)]
pub struct CanFdFrame {
    /// CAN ID with EFF/RTR/ERR flags.
    pub can_id: u32,
    /// Data length (0–64).
    pub len: u8,
    /// FD flags (BRS, ESI).
    pub flags: u8,
    /// Frame payload.
    pub data: [u8; CANFD_MAX_DLC],
}

impl CanFdFrame {
    /// Create a new CAN FD data frame.
    pub const fn new(id: u32, len: u8, flags: u8, data: [u8; CANFD_MAX_DLC]) -> Self {
        Self {
            can_id: id,
            len,
            flags,
            data,
        }
    }
}

impl Default for CanFdFrame {
    fn default() -> Self {
        Self {
            can_id: 0,
            len: 0,
            flags: 0,
            data: [0u8; CANFD_MAX_DLC],
        }
    }
}

/// CAN receive filter.
#[derive(Clone, Copy, Debug)]
pub struct CanFilter {
    /// ID value to match (with flag bits).
    pub can_id: u32,
    /// Mask specifying which bits to compare.
    pub can_mask: u32,
}

impl CanFilter {
    /// Create a filter that matches all frames.
    pub const fn accept_all() -> Self {
        Self {
            can_id: 0,
            can_mask: 0,
        }
    }

    /// Create a filter for a specific standard ID.
    pub const fn exact(id: u32) -> Self {
        Self {
            can_id: id & CAN_SFF_MASK,
            can_mask: CAN_SFF_MASK,
        }
    }

    /// Return true if `frame` passes this filter.
    pub fn matches(&self, frame: &CanFrame) -> bool {
        (frame.can_id & self.can_mask) == (self.can_id & self.can_mask)
    }
}

/// CAN bus bit rate configuration.
#[derive(Clone, Copy, Debug)]
pub struct BitTiming {
    /// Bit rate in bits/second.
    pub bitrate: u32,
    /// Propagation segment (time quanta).
    pub prop_seg: u8,
    /// Phase segment 1 (time quanta).
    pub phase_seg1: u8,
    /// Phase segment 2 (time quanta).
    pub phase_seg2: u8,
    /// Synchronization jump width (time quanta).
    pub sjw: u8,
    /// CAN clock prescaler.
    pub brp: u16,
}

impl BitTiming {
    /// Standard 500 kbps bit timing (for a 40 MHz CAN clock, example values).
    pub const RATE_500K: BitTiming = BitTiming {
        bitrate: 500_000,
        prop_seg: 4,
        phase_seg1: 7,
        phase_seg2: 4,
        sjw: 1,
        brp: 4,
    };

    /// Standard 1 Mbps bit timing.
    pub const RATE_1M: BitTiming = BitTiming {
        bitrate: 1_000_000,
        prop_seg: 4,
        phase_seg1: 4,
        phase_seg2: 3,
        sjw: 1,
        brp: 2,
    };
}

/// CAN bus error counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct ErrorCounters {
    /// Transmit error counter.
    pub tx_errors: u8,
    /// Receive error counter.
    pub rx_errors: u8,
}

/// CAN bus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusState {
    /// Normal operation.
    Active,
    /// Warning: one or both error counters exceed 96.
    Warning,
    /// Passive: one or both error counters exceed 127.
    Passive,
    /// Bus-off: TX error counter exceeded 255.
    BusOff,
}

/// Receive ring buffer capacity (must be power of 2).
const RX_RING_SIZE: usize = 64;

/// CAN socket — upper-layer interface to a physical CAN controller.
pub struct CanSocket {
    /// Interface index this socket is bound to.
    ifindex: usize,
    /// Receive filters (up to 8 active).
    filters: [CanFilter; 8],
    /// Number of active filters.
    num_filters: usize,
    /// Receive ring buffer.
    rx_ring: [CanFrame; RX_RING_SIZE],
    /// Ring producer index.
    rx_head: usize,
    /// Ring consumer index.
    rx_tail: usize,
    /// Total frames dropped due to full ring.
    drop_count: u64,
    /// Whether error frames are delivered to this socket.
    recv_error_frames: bool,
    /// Current bus state.
    bus_state: BusState,
    /// Error counters.
    error_counters: ErrorCounters,
}

impl CanSocket {
    /// Create a new CAN socket bound to the given interface index.
    pub fn new(ifindex: usize) -> Self {
        Self {
            ifindex,
            filters: [CanFilter::accept_all(); 8],
            num_filters: 0,
            rx_ring: [const { CanFrame::new(0, 0, [0u8; CAN_MAX_DLC]) }; RX_RING_SIZE],
            rx_head: 0,
            rx_tail: 0,
            drop_count: 0,
            recv_error_frames: false,
            bus_state: BusState::Active,
            error_counters: ErrorCounters::default(),
        }
    }

    /// Set the receive filter list.
    pub fn set_filters(&mut self, filters: &[CanFilter]) -> Result<()> {
        if filters.len() > 8 {
            return Err(Error::InvalidArgument);
        }
        for (i, f) in filters.iter().enumerate() {
            self.filters[i] = *f;
        }
        self.num_filters = filters.len();
        Ok(())
    }

    /// Enable or disable delivery of error frames.
    pub fn set_recv_error_frames(&mut self, enable: bool) {
        self.recv_error_frames = enable;
    }

    /// Enqueue a received frame (called by the CAN controller driver).
    pub fn enqueue_frame(&mut self, frame: CanFrame) -> bool {
        // Apply filters.
        if self.num_filters > 0 {
            let passes = self.filters[..self.num_filters]
                .iter()
                .any(|f| f.matches(&frame));
            if !passes {
                return false;
            }
        }
        let next = (self.rx_head + 1) & (RX_RING_SIZE - 1);
        if next == self.rx_tail {
            self.drop_count += 1;
            return false;
        }
        self.rx_ring[self.rx_head] = frame;
        self.rx_head = next;
        true
    }

    /// Dequeue a received frame. Returns `None` if the ring is empty.
    pub fn recv(&mut self) -> Option<CanFrame> {
        if self.rx_head == self.rx_tail {
            return None;
        }
        let frame = self.rx_ring[self.rx_tail];
        self.rx_tail = (self.rx_tail + 1) & (RX_RING_SIZE - 1);
        Some(frame)
    }

    /// Return the number of frames waiting in the receive ring.
    pub fn rx_pending(&self) -> usize {
        (self.rx_head.wrapping_sub(self.rx_tail)) & (RX_RING_SIZE - 1)
    }

    /// Update the bus state and error counters.
    pub fn update_bus_state(&mut self, state: BusState, counters: ErrorCounters) {
        self.bus_state = state;
        self.error_counters = counters;
    }

    /// Return the current bus state.
    pub fn bus_state(&self) -> BusState {
        self.bus_state
    }

    /// Return the drop counter.
    pub fn drop_count(&self) -> u64 {
        self.drop_count
    }

    /// Return the interface index.
    pub fn ifindex(&self) -> usize {
        self.ifindex
    }
}
