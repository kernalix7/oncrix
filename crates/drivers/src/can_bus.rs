// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CAN bus controller driver.
//!
//! Implements the Controller Area Network (CAN) 2.0A/2.0B bus protocol as
//! used in automotive, industrial, and embedded systems. The driver models a
//! generic CAN controller (e.g. SJA1000-compatible or similar MMIO device)
//! and provides:
//!
//! # Architecture
//!
//! - **CanFrame** — standard (11-bit ID) and extended (29-bit ID) data frames
//! - **CanFilter** — hardware acceptance filter with mask support
//! - **CanController** — single CAN controller instance (init, send, receive)
//! - **CanRegistry** — tracks up to [`MAX_CAN_CONTROLLERS`] bus instances
//!
//! # Bit-Timing
//!
//! Bit timing registers follow the Bosch CAN 2.0 specification with
//! separate prescaler, sync-jump-width, time-segment-1, and time-segment-2
//! fields. Common pre-computed settings for 125 kbit/s, 250 kbit/s,
//! 500 kbit/s, and 1 Mbit/s are provided as associated constants.
//!
//! Reference: Bosch CAN 2.0 Specification (Sept. 1991);
//! ISO 11898-1:2015 (CAN data link layer).

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CAN controllers.
pub const MAX_CAN_CONTROLLERS: usize = 4;

/// Maximum number of acceptance filters per controller.
pub const MAX_FILTERS: usize = 16;

/// CAN 2.0A maximum standard frame ID (11 bits).
pub const CAN_SFF_MASK: u32 = 0x7FF;

/// CAN 2.0B maximum extended frame ID (29 bits).
pub const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;

/// Maximum data bytes in a CAN data frame.
pub const CAN_MAX_DLC: usize = 8;

/// Frame flag: extended frame format (EFF, 29-bit ID).
pub const CAN_EFF_FLAG: u32 = 0x8000_0000;

/// Frame flag: remote transmission request (RTR).
pub const CAN_RTR_FLAG: u32 = 0x4000_0000;

/// Frame flag: error frame indicator.
pub const CAN_ERR_FLAG: u32 = 0x2000_0000;

// ---------------------------------------------------------------------------
// MMIO register offsets (SJA1000-compatible layout, 8-bit wide)
// ---------------------------------------------------------------------------

/// Mode register offset.
const REG_MODE: usize = 0x00;

/// Command register offset.
const REG_CMD: usize = 0x01;

/// Status register offset.
const REG_STATUS: usize = 0x02;

/// Interrupt register offset.
const REG_INT: usize = 0x03;

/// Interrupt enable register offset.
const REG_INT_EN: usize = 0x04;

/// Bus timing register 0 offset.
const REG_BTR0: usize = 0x06;

/// Bus timing register 1 offset.
const REG_BTR1: usize = 0x07;

/// Output control register offset.
const REG_OCR: usize = 0x08;

/// Acceptance code register 0 (reset mode only).
const REG_ACR0: usize = 0x10;

/// Acceptance mask register 0 (reset mode only).
const REG_AMR0: usize = 0x14;

/// Transmit buffer base (reset mode for extended frames).
const REG_TX_BUF: usize = 0x10;

/// Receive buffer base.
const REG_RX_BUF: usize = 0x10;

/// Error warning limit register.
const REG_EWLR: usize = 0x0C;

/// RX error counter.
const REG_RXERR: usize = 0x0E;

/// TX error counter.
const REG_TXERR: usize = 0x0F;

// ---------------------------------------------------------------------------
// Mode register bits
// ---------------------------------------------------------------------------

/// Mode: Reset mode (holds controller in reset).
const MODE_RM: u8 = 1 << 0;

/// Mode: Listen-only mode.
const MODE_LOM: u8 = 1 << 1;

/// Mode: Self test mode.
const MODE_STM: u8 = 1 << 2;

/// Mode: Acceptance filter mode (0 = single, 1 = dual).
const MODE_AFM: u8 = 1 << 3;

/// Mode: Sleep mode.
const MODE_SM: u8 = 1 << 4;

// ---------------------------------------------------------------------------
// Command register bits
// ---------------------------------------------------------------------------

/// Command: Transmit request.
const CMD_TR: u8 = 1 << 0;

/// Command: Abort transmission.
const CMD_AT: u8 = 1 << 1;

/// Command: Release receive buffer.
const CMD_RRB: u8 = 1 << 2;

/// Command: Clear data overrun.
const CMD_CDO: u8 = 1 << 3;

/// Command: Self reception request.
const CMD_SRR: u8 = 1 << 4;

// ---------------------------------------------------------------------------
// Status register bits
// ---------------------------------------------------------------------------

/// Status: Receive buffer status (1 = frame available).
const SR_RBS: u8 = 1 << 0;

/// Status: Data overrun status.
const SR_DOS: u8 = 1 << 1;

/// Status: Transmit buffer status (1 = released/available).
const SR_TBS: u8 = 1 << 2;

/// Status: Transmission complete status.
const SR_TCS: u8 = 1 << 3;

/// Status: Receive status (1 = receiving).
const SR_RS: u8 = 1 << 4;

/// Status: Transmit status (1 = transmitting).
const SR_TS: u8 = 1 << 5;

/// Status: Error status (1 = error or bus-off).
const SR_ES: u8 = 1 << 6;

/// Status: Bus status (1 = bus-off).
const SR_BS: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Interrupt bits
// ---------------------------------------------------------------------------

/// Interrupt: Receive interrupt.
const IR_RI: u8 = 1 << 0;

/// Interrupt: Transmit interrupt.
const IR_TI: u8 = 1 << 1;

/// Interrupt: Error warning interrupt.
const IR_EI: u8 = 1 << 2;

/// Interrupt: Data overrun interrupt.
const IR_DOI: u8 = 1 << 3;

/// Interrupt: Wakeup interrupt.
const IR_WUI: u8 = 1 << 4;

/// Interrupt: Error passive interrupt.
const IR_EPI: u8 = 1 << 5;

/// Interrupt: Arbitration lost interrupt.
const IR_ALI: u8 = 1 << 6;

/// Interrupt: Bus error interrupt.
const IR_BEI: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// CanBitrate
// ---------------------------------------------------------------------------

/// Pre-defined CAN bus bit rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanBitrate {
    /// 125 kbit/s — used in automotive body/comfort networks.
    Kbps125,
    /// 250 kbit/s — common in automotive powertrain networks.
    #[default]
    Kbps250,
    /// 500 kbit/s — high-speed automotive and industrial.
    Kbps500,
    /// 1 Mbit/s — maximum rate per ISO 11898-1.
    Mbps1,
}

impl CanBitrate {
    /// Return (BTR0, BTR1) register bytes for an 8 MHz crystal.
    ///
    /// These values are pre-computed for an SJA1000-compatible controller
    /// with an 8 MHz input clock. BTR0 = (SJW-1)<<6 | BRP-1;
    /// BTR1 = SAM<<7 | (TSEG2-1)<<4 | (TSEG1-1).
    pub fn btr_bytes_8mhz(self) -> (u8, u8) {
        match self {
            // 8 MHz / (BRP=4) → 2 MHz tq; TSEG1=13, TSEG2=2 → 16 tq/bit = 125 kbps
            CanBitrate::Kbps125 => (0x03, 0x1C),
            // 8 MHz / (BRP=2) → 4 MHz tq; TSEG1=13, TSEG2=2 → 16 tq/bit = 250 kbps
            CanBitrate::Kbps250 => (0x01, 0x1C),
            // 8 MHz / (BRP=1) → 8 MHz tq; TSEG1=13, TSEG2=2 → 16 tq/bit = 500 kbps
            CanBitrate::Kbps500 => (0x00, 0x1C),
            // 8 MHz / (BRP=1) → 8 MHz tq; TSEG1=5, TSEG2=2 → 8 tq/bit = 1 Mbps
            CanBitrate::Mbps1 => (0x00, 0x14),
        }
    }
}

// ---------------------------------------------------------------------------
// CanFrameType
// ---------------------------------------------------------------------------

/// CAN frame type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanFrameType {
    /// Standard data frame (11-bit ID, 0–8 data bytes).
    #[default]
    StandardData,
    /// Extended data frame (29-bit ID, 0–8 data bytes).
    ExtendedData,
    /// Standard remote frame (11-bit ID, no data, requests transmission).
    StandardRemote,
    /// Extended remote frame (29-bit ID, no data).
    ExtendedRemote,
}

// ---------------------------------------------------------------------------
// CanFrame
// ---------------------------------------------------------------------------

/// A single CAN bus frame (data or remote).
///
/// The `can_id` field uses Linux-style flag encoding:
/// - bit 31: [`CAN_EFF_FLAG`] — extended frame format
/// - bit 30: [`CAN_RTR_FLAG`] — remote transmission request
/// - bits 28:0: the 29-bit (EFF) or bits 10:0: the 11-bit (SFF) arbitration ID
#[derive(Clone, Copy, Default)]
pub struct CanFrame {
    /// Arbitration ID with flag bits (EFF, RTR).
    pub can_id: u32,
    /// Data length code (0–8).
    pub dlc: u8,
    /// Frame data bytes (only first `dlc` bytes are valid).
    pub data: [u8; CAN_MAX_DLC],
}

impl CanFrame {
    /// Create a standard (11-bit) data frame.
    ///
    /// Returns [`Error::InvalidArgument`] if `id > 0x7FF` or
    /// `data.len() > 8`.
    pub fn new_standard(id: u16, data: &[u8]) -> Result<Self> {
        if id as u32 > CAN_SFF_MASK || data.len() > CAN_MAX_DLC {
            return Err(Error::InvalidArgument);
        }
        let mut frame = Self {
            can_id: id as u32,
            dlc: data.len() as u8,
            data: [0u8; CAN_MAX_DLC],
        };
        frame.data[..data.len()].copy_from_slice(data);
        Ok(frame)
    }

    /// Create an extended (29-bit) data frame.
    ///
    /// Returns [`Error::InvalidArgument`] if `id > 0x1FFF_FFFF` or
    /// `data.len() > 8`.
    pub fn new_extended(id: u32, data: &[u8]) -> Result<Self> {
        if id > CAN_EFF_MASK || data.len() > CAN_MAX_DLC {
            return Err(Error::InvalidArgument);
        }
        let mut frame = Self {
            can_id: id | CAN_EFF_FLAG,
            dlc: data.len() as u8,
            data: [0u8; CAN_MAX_DLC],
        };
        frame.data[..data.len()].copy_from_slice(data);
        Ok(frame)
    }

    /// Create a standard (11-bit) remote frame (RTR, no data).
    pub fn new_remote_standard(id: u16, dlc: u8) -> Result<Self> {
        if id as u32 > CAN_SFF_MASK || dlc > 8 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            can_id: id as u32 | CAN_RTR_FLAG,
            dlc,
            data: [0u8; CAN_MAX_DLC],
        })
    }

    /// Return `true` if this is an extended frame.
    pub fn is_extended(&self) -> bool {
        self.can_id & CAN_EFF_FLAG != 0
    }

    /// Return `true` if this is a remote frame.
    pub fn is_rtr(&self) -> bool {
        self.can_id & CAN_RTR_FLAG != 0
    }

    /// Return the arbitration ID (masked to 29 or 11 bits).
    pub fn id(&self) -> u32 {
        if self.is_extended() {
            self.can_id & CAN_EFF_MASK
        } else {
            self.can_id & CAN_SFF_MASK
        }
    }

    /// Return the frame type.
    pub fn frame_type(&self) -> CanFrameType {
        match (self.is_extended(), self.is_rtr()) {
            (false, false) => CanFrameType::StandardData,
            (true, false) => CanFrameType::ExtendedData,
            (false, true) => CanFrameType::StandardRemote,
            (true, true) => CanFrameType::ExtendedRemote,
        }
    }

    /// Return the valid data slice (first `dlc` bytes).
    pub fn data_bytes(&self) -> &[u8] {
        &self.data[..self.dlc as usize]
    }
}

// ---------------------------------------------------------------------------
// CanFilter
// ---------------------------------------------------------------------------

/// CAN hardware acceptance filter (code + mask pair).
///
/// A frame is accepted when `(frame_id & mask) == (code & mask)`.
/// Setting `mask = 0` accepts all frames. Setting `mask = 0xFFFF_FFFF`
/// accepts only exact ID matches.
#[derive(Clone, Copy, Default)]
pub struct CanFilter {
    /// Acceptance code (the expected pattern).
    pub code: u32,
    /// Acceptance mask (1 = must match, 0 = don't care).
    pub mask: u32,
    /// Whether this filter also matches extended (29-bit) IDs.
    pub extended: bool,
    /// Whether this filter slot is active.
    pub enabled: bool,
}

impl CanFilter {
    /// Create an acceptance filter that matches a single standard ID.
    pub fn match_standard(id: u16) -> Self {
        Self {
            code: id as u32,
            mask: CAN_SFF_MASK,
            extended: false,
            enabled: true,
        }
    }

    /// Create an acceptance filter that matches a single extended ID.
    pub fn match_extended(id: u32) -> Self {
        Self {
            code: id & CAN_EFF_MASK,
            mask: CAN_EFF_MASK,
            extended: true,
            enabled: true,
        }
    }

    /// Create an open (pass-all) filter.
    pub fn pass_all() -> Self {
        Self {
            code: 0,
            mask: 0,
            extended: false,
            enabled: true,
        }
    }

    /// Test whether `frame` passes this filter.
    pub fn accepts(&self, frame: &CanFrame) -> bool {
        if !self.enabled {
            return false;
        }
        if self.extended != frame.is_extended() {
            return false;
        }
        (frame.id() & self.mask) == (self.code & self.mask)
    }
}

// ---------------------------------------------------------------------------
// CanErrorCounters
// ---------------------------------------------------------------------------

/// CAN bus error counters as reported by the controller.
#[derive(Clone, Copy, Default)]
pub struct CanErrorCounters {
    /// Transmit error counter (TEC).
    pub tx_errors: u8,
    /// Receive error counter (REC).
    pub rx_errors: u8,
    /// Number of bus-off events since reset.
    pub bus_off_count: u32,
    /// Number of arbitration-lost events.
    pub arb_lost_count: u32,
}

// ---------------------------------------------------------------------------
// CanState
// ---------------------------------------------------------------------------

/// CAN node error state per ISO 11898-1 §12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanState {
    /// Error-active (TEC < 128 and REC < 128).
    #[default]
    Active,
    /// Error-passive (TEC ≥ 128 or REC ≥ 128).
    Passive,
    /// Bus-off (TEC ≥ 256).
    BusOff,
    /// Controller is stopped (reset mode).
    Stopped,
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read an 8-bit MMIO register at `base + offset`.
///
/// # Safety
///
/// `base` must be a valid, mapped CAN controller MMIO base address.
unsafe fn read_reg8(base: usize, offset: usize) -> u8 {
    // SAFETY: Caller guarantees base is valid MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u8) }
}

/// Write an 8-bit MMIO register at `base + offset`.
///
/// # Safety
///
/// `base` must be a valid, mapped CAN controller MMIO base address.
unsafe fn write_reg8(base: usize, offset: usize, val: u8) {
    // SAFETY: Caller guarantees base is valid MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u8, val) };
}

// ---------------------------------------------------------------------------
// CanController
// ---------------------------------------------------------------------------

/// A single CAN bus controller instance.
///
/// Wraps the MMIO registers of one SJA1000-compatible controller,
/// manages bit timing, filters, and frame I/O.
pub struct CanController {
    /// Unique controller index in the registry.
    pub id: u8,
    /// MMIO base address (mapped by the platform).
    pub mmio_base: usize,
    /// Active bit rate.
    pub bitrate: CanBitrate,
    /// Current error state.
    pub state: CanState,
    /// Hardware acceptance filters.
    pub filters: [CanFilter; MAX_FILTERS],
    /// Error counters.
    pub errors: CanErrorCounters,
    /// Whether the controller is initialised and running.
    pub running: bool,
}

impl CanController {
    /// Create a new controller descriptor.
    ///
    /// Call [`init`](Self::init) to configure and start the controller.
    pub fn new(id: u8, mmio_base: usize, bitrate: CanBitrate) -> Self {
        Self {
            id,
            mmio_base,
            bitrate,
            state: CanState::Stopped,
            filters: [CanFilter::default(); MAX_FILTERS],
            errors: CanErrorCounters::default(),
            running: false,
        }
    }

    /// Initialise the CAN controller.
    ///
    /// Puts the device in reset mode, programs bit timing, enables all
    /// interrupts, sets an open (pass-all) acceptance filter, then
    /// transitions to operating mode.
    pub fn init(&mut self) -> Result<()> {
        let base = self.mmio_base;

        // SAFETY: mmio_base is a valid mapped MMIO address provided by
        // the HAL platform layer during PCI/DT enumeration.
        unsafe {
            // Enter reset mode.
            write_reg8(base, REG_MODE, MODE_RM);

            // Configure bit timing.
            let (btr0, btr1) = self.bitrate.btr_bytes_8mhz();
            write_reg8(base, REG_BTR0, btr0);
            write_reg8(base, REG_BTR1, btr1);

            // Output control — normal output mode (push-pull).
            write_reg8(base, REG_OCR, 0x1A);

            // Single acceptance filter — accept all (code=0, mask=0xFF).
            write_reg8(base, REG_ACR0, 0x00);
            write_reg8(base, REG_AMR0, 0xFF);

            // Error warning limit (default 96).
            write_reg8(base, REG_EWLR, 96);

            // Enable all interrupts except wakeup.
            write_reg8(
                base,
                REG_INT_EN,
                IR_RI | IR_TI | IR_EI | IR_DOI | IR_EPI | IR_ALI | IR_BEI,
            );

            // Leave reset mode → operating mode.
            write_reg8(base, REG_MODE, 0x00);
        }

        self.state = CanState::Active;
        self.running = true;
        Ok(())
    }

    /// Stop the controller (enter reset mode).
    pub fn stop(&mut self) {
        let base = self.mmio_base;
        // SAFETY: mmio_base is valid MMIO as established in init().
        unsafe {
            write_reg8(base, REG_MODE, MODE_RM);
        }
        self.state = CanState::Stopped;
        self.running = false;
    }

    /// Install an acceptance filter in slot `index`.
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= MAX_FILTERS`.
    pub fn set_filter(&mut self, index: usize, filter: CanFilter) -> Result<()> {
        if index >= MAX_FILTERS {
            return Err(Error::InvalidArgument);
        }
        self.filters[index] = filter;
        Ok(())
    }

    /// Return `true` if `frame` passes at least one enabled filter.
    pub fn frame_passes_filter(&self, frame: &CanFrame) -> bool {
        self.filters.iter().any(|f| f.accepts(frame))
    }

    /// Transmit a CAN frame.
    ///
    /// Writes frame bytes into the controller's TX buffer and issues
    /// the transmit request command. Returns [`Error::Busy`] if the TX
    /// buffer is not available.
    pub fn send(&mut self, frame: &CanFrame) -> Result<()> {
        if !self.running {
            return Err(Error::Busy);
        }

        let base = self.mmio_base;

        // SAFETY: mmio_base is valid MMIO; we read status before writing TX buf.
        let status = unsafe { read_reg8(base, REG_STATUS) };
        if status & SR_TBS == 0 {
            // TX buffer occupied.
            return Err(Error::Busy);
        }

        // Build the frame info byte (DLC + EFF/RTR flags).
        let ff_byte: u8 = if frame.is_extended() { 0x80 } else { 0x00 }
            | if frame.is_rtr() { 0x40 } else { 0x00 }
            | (frame.dlc & 0x0F);

        // SAFETY: mmio_base is valid MMIO; TX_BUF is within mapped region.
        unsafe {
            write_reg8(base, REG_TX_BUF, ff_byte);

            if frame.is_extended() {
                // Extended frame: 4 ID bytes + data bytes.
                let id = frame.id();
                write_reg8(base, REG_TX_BUF + 1, ((id >> 21) & 0xFF) as u8);
                write_reg8(base, REG_TX_BUF + 2, ((id >> 13) & 0xFF) as u8);
                write_reg8(base, REG_TX_BUF + 3, ((id >> 5) & 0xFF) as u8);
                write_reg8(base, REG_TX_BUF + 4, ((id << 3) & 0xF8) as u8);
                for i in 0..frame.dlc as usize {
                    write_reg8(base, REG_TX_BUF + 5 + i, frame.data[i]);
                }
            } else {
                // Standard frame: 2 ID bytes + data bytes.
                let id = frame.id();
                write_reg8(base, REG_TX_BUF + 1, ((id >> 3) & 0xFF) as u8);
                write_reg8(base, REG_TX_BUF + 2, ((id << 5) & 0xE0) as u8);
                for i in 0..frame.dlc as usize {
                    write_reg8(base, REG_TX_BUF + 3 + i, frame.data[i]);
                }
            }

            // Issue transmit request.
            write_reg8(base, REG_CMD, CMD_TR);
        }

        Ok(())
    }

    /// Attempt to receive a CAN frame from the RX FIFO.
    ///
    /// Returns [`Error::WouldBlock`] if no frame is available.
    pub fn recv(&mut self) -> Result<CanFrame> {
        if !self.running {
            return Err(Error::Busy);
        }

        let base = self.mmio_base;

        // SAFETY: mmio_base is valid MMIO.
        let status = unsafe { read_reg8(base, REG_STATUS) };
        if status & SR_RBS == 0 {
            return Err(Error::WouldBlock);
        }

        // SAFETY: mmio_base is valid MMIO; SR_RBS confirmed frame available.
        let frame = unsafe {
            let ff_byte = read_reg8(base, REG_RX_BUF);
            let is_eff = ff_byte & 0x80 != 0;
            let is_rtr = ff_byte & 0x40 != 0;
            let dlc = (ff_byte & 0x0F).min(8);

            let (can_id, data_offset) = if is_eff {
                let b1 = read_reg8(base, REG_RX_BUF + 1) as u32;
                let b2 = read_reg8(base, REG_RX_BUF + 2) as u32;
                let b3 = read_reg8(base, REG_RX_BUF + 3) as u32;
                let b4 = read_reg8(base, REG_RX_BUF + 4) as u32;
                let id = (b1 << 21) | (b2 << 13) | (b3 << 5) | (b4 >> 3);
                let flags = CAN_EFF_FLAG | if is_rtr { CAN_RTR_FLAG } else { 0 };
                (id | flags, 5)
            } else {
                let b1 = read_reg8(base, REG_RX_BUF + 1) as u32;
                let b2 = read_reg8(base, REG_RX_BUF + 2) as u32;
                let id = (b1 << 3) | (b2 >> 5);
                let flags = if is_rtr { CAN_RTR_FLAG } else { 0 };
                (id | flags, 3)
            };

            let mut data = [0u8; CAN_MAX_DLC];
            for i in 0..dlc as usize {
                data[i] = read_reg8(base, REG_RX_BUF + data_offset + i);
            }

            // Release receive buffer.
            write_reg8(base, REG_CMD, CMD_RRB);

            CanFrame { can_id, dlc, data }
        };

        Ok(frame)
    }

    /// Handle a controller interrupt.
    ///
    /// Reads and clears the interrupt register, updates error counters,
    /// and returns a bitmask of interrupt causes for the caller to act on.
    pub fn handle_interrupt(&mut self) -> u8 {
        let base = self.mmio_base;

        // SAFETY: mmio_base is valid MMIO.
        let ir = unsafe { read_reg8(base, REG_INT) };

        if ir & IR_EI != 0 || ir & IR_EPI != 0 || ir & IR_BEI != 0 {
            // Update error counters from hardware.
            // SAFETY: mmio_base is valid MMIO.
            unsafe {
                self.errors.tx_errors = read_reg8(base, REG_TXERR);
                self.errors.rx_errors = read_reg8(base, REG_RXERR);
            }

            // Update error state based on TEC/REC.
            let status = unsafe { read_reg8(base, REG_STATUS) };
            if status & SR_BS != 0 {
                self.state = CanState::BusOff;
                self.errors.bus_off_count = self.errors.bus_off_count.wrapping_add(1);
            } else if self.errors.tx_errors >= 128 || self.errors.rx_errors >= 128 {
                self.state = CanState::Passive;
            } else {
                self.state = CanState::Active;
            }
        }

        if ir & IR_ALI != 0 {
            self.errors.arb_lost_count = self.errors.arb_lost_count.wrapping_add(1);
        }

        ir
    }

    /// Attempt bus-off recovery by re-entering normal operating mode.
    ///
    /// Only valid when [`state`](Self::state) is [`CanState::BusOff`].
    pub fn bus_off_recovery(&mut self) -> Result<()> {
        if self.state != CanState::BusOff {
            return Err(Error::InvalidArgument);
        }
        let base = self.mmio_base;
        // SAFETY: mmio_base is valid MMIO.
        unsafe {
            // Enter reset then leave — triggers 128 occurrences of 11
            // consecutive recessive bits for automatic bus-off recovery.
            write_reg8(base, REG_MODE, MODE_RM);
            write_reg8(base, REG_MODE, 0x00);
        }
        self.state = CanState::Active;
        Ok(())
    }

    /// Read current TX and RX error counters from hardware.
    pub fn read_error_counters(&mut self) {
        let base = self.mmio_base;
        // SAFETY: mmio_base is valid MMIO.
        unsafe {
            self.errors.tx_errors = read_reg8(base, REG_TXERR);
            self.errors.rx_errors = read_reg8(base, REG_RXERR);
        }
    }
}

// ---------------------------------------------------------------------------
// CanRegistry
// ---------------------------------------------------------------------------

/// Registry of CAN bus controllers in the system.
///
/// Supports up to [`MAX_CAN_CONTROLLERS`] simultaneously active controllers.
pub struct CanRegistry {
    /// Controller slots.
    controllers: [Option<CanController>; MAX_CAN_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for CanRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CanRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a controller.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same ID
    /// is already present.
    pub fn register(&mut self, ctrl: CanController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == ctrl.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.controllers {
            if slot.is_none() {
                *slot = Some(ctrl);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a controller by ID.
    pub fn unregister(&mut self, id: u8) -> Result<()> {
        for slot in &mut self.controllers {
            if let Some(c) = slot {
                if c.id == id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a controller by ID (shared reference).
    pub fn get(&self, id: u8) -> Option<&CanController> {
        self.controllers
            .iter()
            .find_map(|s| s.as_ref().filter(|c| c.id == id))
    }

    /// Look up a controller by ID (mutable reference).
    pub fn get_mut(&mut self, id: u8) -> Option<&mut CanController> {
        self.controllers
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|c| c.id == id))
    }

    /// Number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
