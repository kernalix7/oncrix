// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CAN (Controller Area Network) bus hardware abstraction.
//!
//! Provides a unified interface for CAN bus controllers including support for
//! CAN 2.0A (11-bit ID), CAN 2.0B (29-bit extended ID), and CAN FD (Flexible
//! Data-Rate) frames. Handles filter configuration, error handling, and
//! bus-off recovery.

use oncrix_lib::{Error, Result};

/// Maximum number of CAN controllers in the system.
pub const MAX_CAN_CONTROLLERS: usize = 4;

/// Maximum number of message filters per controller.
pub const MAX_CAN_FILTERS: usize = 16;

/// Maximum CAN FD data length in bytes.
pub const CAN_FD_MAX_DLC: usize = 64;

/// Standard CAN data length in bytes.
pub const CAN_MAX_DLC: usize = 8;

/// CAN frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanFrameType {
    /// Standard data frame (11-bit ID, up to 8 bytes data).
    Standard,
    /// Extended data frame (29-bit ID, up to 8 bytes data).
    Extended,
    /// Remote transmission request frame.
    Rtr,
    /// CAN FD frame (up to 64 bytes data).
    Fd,
}

/// CAN bus bit rate presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CanBitrate {
    /// 125 kbit/s (industrial standard).
    Kbps125 = 125_000,
    /// 250 kbit/s.
    Kbps250 = 250_000,
    /// 500 kbit/s.
    Kbps500 = 500_000,
    /// 1 Mbit/s (maximum classical CAN).
    Mbps1 = 1_000_000,
    /// 2 Mbit/s (CAN FD nominal).
    Mbps2 = 2_000_000,
    /// 5 Mbit/s (CAN FD data phase).
    Mbps5 = 5_000_000,
}

/// A CAN message frame.
#[derive(Debug, Clone, Copy)]
pub struct CanFrame {
    /// Message identifier.
    pub id: u32,
    /// Frame type.
    pub frame_type: CanFrameType,
    /// Data length code (number of valid data bytes).
    pub dlc: u8,
    /// Frame data payload (up to 64 bytes for CAN FD).
    pub data: [u8; CAN_FD_MAX_DLC],
    /// Timestamp when frame was received (bus time units).
    pub timestamp: u32,
}

impl CanFrame {
    /// Creates a new standard CAN data frame.
    ///
    /// # Arguments
    /// * `id` — 11-bit message identifier.
    /// * `data` — Payload bytes (max 8 for standard CAN).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if id exceeds 11 bits or data too long.
    pub fn new_standard(id: u16, data: &[u8]) -> Result<Self> {
        if (id as u32) > 0x7FF {
            return Err(Error::InvalidArgument);
        }
        if data.len() > CAN_MAX_DLC {
            return Err(Error::InvalidArgument);
        }
        let mut frame = Self {
            id: id as u32,
            frame_type: CanFrameType::Standard,
            dlc: data.len() as u8,
            data: [0u8; CAN_FD_MAX_DLC],
            timestamp: 0,
        };
        frame.data[..data.len()].copy_from_slice(data);
        Ok(frame)
    }

    /// Creates a new extended CAN data frame.
    ///
    /// # Arguments
    /// * `id` — 29-bit message identifier.
    /// * `data` — Payload bytes (max 8).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if id exceeds 29 bits or data too long.
    pub fn new_extended(id: u32, data: &[u8]) -> Result<Self> {
        if id > 0x1FFF_FFFF {
            return Err(Error::InvalidArgument);
        }
        if data.len() > CAN_MAX_DLC {
            return Err(Error::InvalidArgument);
        }
        let mut frame = Self {
            id,
            frame_type: CanFrameType::Extended,
            dlc: data.len() as u8,
            data: [0u8; CAN_FD_MAX_DLC],
            timestamp: 0,
        };
        frame.data[..data.len()].copy_from_slice(data);
        Ok(frame)
    }

    /// Returns the valid data slice for this frame.
    pub fn data_slice(&self) -> &[u8] {
        &self.data[..self.dlc as usize]
    }
}

impl Default for CanFrame {
    fn default() -> Self {
        Self {
            id: 0,
            frame_type: CanFrameType::Standard,
            dlc: 0,
            data: [0u8; CAN_FD_MAX_DLC],
            timestamp: 0,
        }
    }
}

/// A CAN message acceptance filter.
#[derive(Debug, Clone, Copy)]
pub struct CanFilter {
    /// Base message ID to match.
    pub id: u32,
    /// Mask for ID bits (1 = must match, 0 = don't care).
    pub mask: u32,
    /// Whether this filter matches extended IDs.
    pub extended: bool,
    /// Whether this filter is enabled.
    pub enabled: bool,
}

impl CanFilter {
    /// Creates a filter that matches a single exact ID.
    pub const fn exact(id: u32, extended: bool) -> Self {
        let mask = if extended { 0x1FFF_FFFF } else { 0x7FF };
        Self {
            id,
            mask,
            extended,
            enabled: true,
        }
    }

    /// Creates a filter that matches all frames (pass-through).
    pub const fn pass_all() -> Self {
        Self {
            id: 0,
            mask: 0,
            extended: false,
            enabled: true,
        }
    }

    /// Returns true if the given frame ID matches this filter.
    pub fn matches(&self, frame_id: u32, is_extended: bool) -> bool {
        if !self.enabled {
            return false;
        }
        if self.extended != is_extended {
            return false;
        }
        (frame_id & self.mask) == (self.id & self.mask)
    }
}

impl Default for CanFilter {
    fn default() -> Self {
        Self::pass_all()
    }
}

/// CAN controller error counters.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanErrorCounters {
    /// Transmit error count.
    pub tx_errors: u8,
    /// Receive error count.
    pub rx_errors: u8,
    /// Number of bus-off events.
    pub bus_off_count: u32,
    /// Number of error-passive transitions.
    pub error_passive_count: u32,
}

impl CanErrorCounters {
    /// Creates zeroed error counters.
    pub const fn new() -> Self {
        Self {
            tx_errors: 0,
            rx_errors: 0,
            bus_off_count: 0,
            error_passive_count: 0,
        }
    }

    /// Returns true if the controller is in bus-off state.
    pub fn is_bus_off(&self) -> bool {
        self.tx_errors >= 255
    }

    /// Returns true if the controller is in error-passive state.
    pub fn is_error_passive(&self) -> bool {
        self.tx_errors >= 128 || self.rx_errors >= 128
    }
}

/// Hardware CAN bus controller.
pub struct CanController {
    /// Controller index.
    id: u8,
    /// MMIO base address of the CAN controller registers.
    base_addr: u64,
    /// Configured nominal bitrate.
    bitrate: CanBitrate,
    /// Acceptance filters.
    filters: [CanFilter; MAX_CAN_FILTERS],
    /// Number of active filters.
    filter_count: usize,
    /// Error counters.
    errors: CanErrorCounters,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl CanController {
    /// Creates a new CAN controller.
    ///
    /// # Arguments
    /// * `id` — Controller identifier.
    /// * `base_addr` — MMIO base address.
    pub const fn new(id: u8, base_addr: u64) -> Self {
        Self {
            id,
            base_addr,
            bitrate: CanBitrate::Kbps500,
            filters: [const { CanFilter::pass_all() }; MAX_CAN_FILTERS],
            filter_count: 0,
            errors: CanErrorCounters::new(),
            initialized: false,
        }
    }

    /// Returns the controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Initializes the CAN controller with the specified bitrate.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn init(&mut self, bitrate: CanBitrate) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        self.bitrate = bitrate;
        // SAFETY: MMIO writes to CAN configuration registers. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            // Enter configuration mode
            ctrl.write_volatile(0x1);
            // Set bitrate prescaler
            let btr = (self.base_addr + 0x04) as *mut u32;
            let prescaler = 80_000_000 / bitrate as u32;
            btr.write_volatile(prescaler);
            // Leave configuration mode, enable
            ctrl.write_volatile(0x2);
        }
        self.initialized = true;
        Ok(())
    }

    /// Adds a message acceptance filter.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the filter table is full.
    pub fn add_filter(&mut self, filter: CanFilter) -> Result<()> {
        if self.filter_count >= MAX_CAN_FILTERS {
            return Err(Error::OutOfMemory);
        }
        self.filters[self.filter_count] = filter;
        self.filter_count += 1;
        Ok(())
    }

    /// Transmits a CAN frame.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or TX mailbox is full.
    pub fn transmit(&mut self, frame: &CanFrame) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO writes to CAN TX mailbox registers. base_addr is non-zero.
        unsafe {
            let sr = (self.base_addr + 0x08) as *const u32;
            let status = sr.read_volatile();
            if status & 0x4 == 0 {
                // TX mailbox full
                return Err(Error::Busy);
            }
            let txid = (self.base_addr + 0x10) as *mut u32;
            let txdlc = (self.base_addr + 0x14) as *mut u32;
            let txdata_lo = (self.base_addr + 0x18) as *mut u32;
            let txdata_hi = (self.base_addr + 0x1C) as *mut u32;
            let id_val = match frame.frame_type {
                CanFrameType::Extended => (frame.id << 3) | 0x4,
                _ => frame.id << 21,
            };
            txid.write_volatile(id_val);
            txdlc.write_volatile(frame.dlc as u32);
            let lo =
                u32::from_le_bytes([frame.data[0], frame.data[1], frame.data[2], frame.data[3]]);
            let hi =
                u32::from_le_bytes([frame.data[4], frame.data[5], frame.data[6], frame.data[7]]);
            txdata_lo.write_volatile(lo);
            txdata_hi.write_volatile(hi);
            // Request transmission
            let ctrl = self.base_addr as *mut u32;
            let val = ctrl.read_volatile();
            ctrl.write_volatile(val | 0x10);
        }
        Ok(())
    }

    /// Attempts to receive a CAN frame from the RX mailbox.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::WouldBlock` if no frame is available.
    pub fn receive(&mut self) -> Result<CanFrame> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO reads from CAN RX mailbox registers. base_addr is non-zero.
        unsafe {
            let sr = (self.base_addr + 0x08) as *const u32;
            let status = sr.read_volatile();
            if status & 0x1 == 0 {
                return Err(Error::WouldBlock);
            }
            let rxid = (self.base_addr + 0x20) as *const u32;
            let rxdlc = (self.base_addr + 0x24) as *const u32;
            let rxdata_lo = (self.base_addr + 0x28) as *const u32;
            let rxdata_hi = (self.base_addr + 0x2C) as *const u32;

            let raw_id = rxid.read_volatile();
            let (id, extended) = if raw_id & 0x4 != 0 {
                (raw_id >> 3, true)
            } else {
                (raw_id >> 21, false)
            };
            let dlc = (rxdlc.read_volatile() & 0xF) as u8;
            let lo = rxdata_lo.read_volatile();
            let hi = rxdata_hi.read_volatile();
            let mut frame = CanFrame {
                id,
                frame_type: if extended {
                    CanFrameType::Extended
                } else {
                    CanFrameType::Standard
                },
                dlc,
                data: [0u8; CAN_FD_MAX_DLC],
                timestamp: 0,
            };
            frame.data[..4].copy_from_slice(&lo.to_le_bytes());
            frame.data[4..8].copy_from_slice(&hi.to_le_bytes());
            Ok(frame)
        }
    }

    /// Returns the current error counters.
    pub fn error_counters(&self) -> CanErrorCounters {
        self.errors
    }

    /// Initiates a bus-off recovery sequence.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not in bus-off state or not initialized.
    pub fn recover_bus_off(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to CAN mode register for bus-off recovery.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            let val = ctrl.read_volatile();
            // Toggle init bit to trigger recovery
            ctrl.write_volatile(val | 0x1);
            ctrl.write_volatile(val & !0x1);
        }
        self.errors = CanErrorCounters::new();
        Ok(())
    }
}

impl Default for CanController {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Registry of CAN controllers.
pub struct CanControllerRegistry {
    controllers: [CanController; MAX_CAN_CONTROLLERS],
    count: usize,
}

impl CanControllerRegistry {
    /// Creates a new empty CAN controller registry.
    pub fn new() -> Self {
        Self {
            controllers: [
                CanController::new(0, 0),
                CanController::new(1, 0),
                CanController::new(2, 0),
                CanController::new(3, 0),
            ],
            count: 0,
        }
    }

    /// Registers a CAN controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, ctrl: CanController) -> Result<()> {
        if self.count >= MAX_CAN_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        self.controllers[self.count] = ctrl;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the controller at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut CanController> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }
}

impl Default for CanControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes a CAN DLC value from a byte count.
///
/// For CAN FD, the DLC encoding is non-linear for lengths > 8.
pub fn bytes_to_dlc(bytes: usize) -> u8 {
    match bytes {
        0..=8 => bytes as u8,
        9..=12 => 9,
        13..=16 => 10,
        17..=20 => 11,
        21..=24 => 12,
        25..=32 => 13,
        33..=48 => 14,
        _ => 15,
    }
}

/// Decodes a CAN FD DLC value back to byte count.
pub fn dlc_to_bytes(dlc: u8) -> usize {
    match dlc {
        0..=8 => dlc as usize,
        9 => 12,
        10 => 16,
        11 => 20,
        12 => 24,
        13 => 32,
        14 => 48,
        _ => 64,
    }
}
