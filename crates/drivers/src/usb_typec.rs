// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Type-C and USB Power Delivery (PD) controller driver.
//!
//! Implements a USB Type-C port controller compliant with the
//! USB Type-C specification rev 2.1 and USB Power Delivery 3.1
//! specification. Handles CC line logic, data role negotiation
//! (DFP/UFP/DRP), VBUS sourcing/sinking, and PD message exchange.
//!
//! # Architecture
//!
//! - **TypeCPort** — represents a single USB Type-C physical port.
//!   Tracks orientation (CC1/CC2 flip), role (host/device/dual),
//!   VBUS state, and the active PD contract.
//! - **PdController** — manages the PD protocol state machine.
//!   Builds, sends, and parses PD messages over the BMC-encoded
//!   CC lines.
//! - **TypeCRegistry** — fixed-size registry for all ports in the
//!   system (e.g., on a multiport hub or platform EC).
//!
//! # Roles
//!
//! | Role | Description |
//! |------|-------------|
//! | DFP  | Downstream Facing Port — acts as host, provides VBUS |
//! | UFP  | Upstream Facing Port — acts as device, sinks VBUS |
//! | DRP  | Dual Role Port — can be DFP or UFP, negotiates role |
//!
//! # Power Delivery Contracts
//!
//! A PD contract is established by a Request/Accept/PS_RDY sequence:
//! 1. Source sends `Source_Capabilities` with a list of PDOs.
//! 2. Sink selects a PDO and sends `Request`.
//! 3. Source accepts and drives the requested voltage/current.
//!
//! Reference: USB Type-C Specification rev 2.1,
//!            USB Power Delivery Specification rev 3.1.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ── MMIO Register Offsets ────────────────────────────────────────

/// Port status register.
const REG_STATUS: u32 = 0x00;

/// Port control register.
const REG_CTRL: u32 = 0x04;

/// CC line status register.
const REG_CC_STATUS: u32 = 0x08;

/// CC line control register.
const REG_CC_CTRL: u32 = 0x0C;

/// VBUS voltage measurement register (mV).
const REG_VBUS_VOLT: u32 = 0x10;

/// VBUS current measurement register (mA).
const REG_VBUS_CURR: u32 = 0x14;

/// PD transmit data register.
const REG_PD_TX_DATA: u32 = 0x18;

/// PD receive data register.
const REG_PD_RX_DATA: u32 = 0x1C;

/// PD message status register.
const REG_PD_STATUS: u32 = 0x20;

/// PD message control register.
const REG_PD_CTRL: u32 = 0x24;

/// Interrupt enable register.
const REG_INT_ENABLE: u32 = 0x28;

/// Interrupt status register (write 1 to clear).
const REG_INT_STATUS: u32 = 0x2C;

/// VBUS control register.
const REG_VBUS_CTRL: u32 = 0x30;

/// Power path control register.
const REG_POWER_CTRL: u32 = 0x34;

// ── Status Register Bits ─────────────────────────────────────────

/// A cable is attached on CC1 or CC2.
const STATUS_ATTACHED: u32 = 1 << 0;

/// Orientation: 0 = CC1 active, 1 = CC2 active (flip).
const STATUS_FLIPPED: u32 = 1 << 1;

/// Current role is DFP (host).
const STATUS_DFP: u32 = 1 << 2;

/// VBUS is present (above threshold).
const STATUS_VBUS_PRESENT: u32 = 1 << 3;

/// PD contract is active.
const STATUS_PD_CONTRACT: u32 = 1 << 4;

/// USB 3.x SuperSpeed lanes active.
const STATUS_USB3: u32 = 1 << 5;

/// Alternate mode (e.g., DisplayPort) active.
const STATUS_ALT_MODE: u32 = 1 << 6;

// ── CC Status Bits ────────────────────────────────────────────────

/// CC1 pull-up/down state mask (2 bits).
const CC1_STATE_MASK: u32 = 0x03;

/// CC2 pull-up/down state mask (2 bits at offset 2).
const CC2_STATE_MASK: u32 = 0x0C;

/// CC state: open (no cable).
const CC_OPEN: u32 = 0x00;

/// CC state: Rd detected (UFP attached).
const CC_RD: u32 = 0x01;

/// CC state: Rp default (500 mA capability).
const CC_RP_DEFAULT: u32 = 0x01;

/// CC state: Rp 1.5 A.
const CC_RP_1P5A: u32 = 0x02;

/// CC state: Rp 3.0 A.
const CC_RP_3P0A: u32 = 0x03;

// ── PD Status Bits ────────────────────────────────────────────────

/// PD TX FIFO ready to accept data.
const PD_TX_READY: u32 = 1 << 0;

/// PD RX FIFO has data available.
const PD_RX_AVAILABLE: u32 = 1 << 1;

/// PD TX in progress.
const PD_TX_BUSY: u32 = 1 << 2;

/// PD RX error (CRC mismatch or framing).
const PD_RX_ERROR: u32 = 1 << 3;

// ── VBUS Control Bits ─────────────────────────────────────────────

/// Enable VBUS sourcing (host mode).
const VBUS_CTRL_SRC_ENABLE: u32 = 1 << 0;

/// Enable VBUS sinking (device mode).
const VBUS_CTRL_SNK_ENABLE: u32 = 1 << 1;

/// VBUS discharge enable.
const VBUS_CTRL_DISCHARGE: u32 = 1 << 2;

// ── Interrupt Bits ────────────────────────────────────────────────

/// Attach/detach event.
const INT_ATTACH: u32 = 1 << 0;

/// Role change event.
const INT_ROLE_CHANGE: u32 = 1 << 1;

/// PD message received.
const INT_PD_RX: u32 = 1 << 2;

/// PD message transmitted.
const INT_PD_TX: u32 = 1 << 3;

/// VBUS change event.
const INT_VBUS_CHANGE: u32 = 1 << 4;

// ── PD Message Header Bits ────────────────────────────────────────

/// PD message type mask (5 bits).
const PD_HDR_MSG_TYPE_MASK: u16 = 0x001F;

/// Number of data objects shift in header.
const PD_HDR_NUM_DO_SHIFT: u16 = 12;

/// PD message ID shift in header.
const PD_HDR_MSG_ID_SHIFT: u16 = 9;

/// Power role bit: 0 = sink, 1 = source.
const PD_HDR_PWR_ROLE: u16 = 1 << 8;

/// Data role bit: 0 = UFP, 1 = DFP.
const PD_HDR_DATA_ROLE: u16 = 1 << 5;

/// PD specification revision: 1 = 2.0, 2 = 3.0.
const PD_HDR_SPEC_REV_SHIFT: u16 = 6;

// ── PD Message Types ─────────────────────────────────────────────

/// Source Capabilities message type.
const PD_MSG_SRC_CAP: u8 = 0x01;

/// Request message type.
const PD_MSG_REQUEST: u8 = 0x02;

/// Accept message type.
const _PD_MSG_ACCEPT: u8 = 0x03;

/// Reject message type.
const _PD_MSG_REJECT: u8 = 0x04;

/// PS_RDY message type.
const _PD_MSG_PS_RDY: u8 = 0x06;

/// GoodCRC message type.
const _PD_MSG_GOOD_CRC: u8 = 0x01;

/// Get Capabilities message type.
const _PD_MSG_GET_SRC_CAP: u8 = 0x07;

// ── Limits ────────────────────────────────────────────────────────

/// Maximum number of PDOs in a Source_Capabilities message.
const MAX_PDOS: usize = 7;

/// Maximum number of Type-C ports in the registry.
const MAX_PORTS: usize = 8;

/// PD transmit timeout (polling iterations).
const PD_TX_TIMEOUT: u32 = 100_000;

// ── MMIO Helpers ─────────────────────────────────────────────────

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// `base + offset` must point to a valid, mapped MMIO register.
unsafe fn mmio_read32(base: usize, offset: u32) -> u32 {
    // SAFETY: Caller guarantees the address is valid MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// `base + offset` must point to a valid, mapped MMIO register.
unsafe fn mmio_write32(base: usize, offset: u32, val: u32) {
    // SAFETY: Caller guarantees the address is valid MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

// ── Data Structures ───────────────────────────────────────────────

/// USB Type-C port orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcOrientation {
    /// CC1 is the active CC line (normal plug orientation).
    #[default]
    Cc1,
    /// CC2 is the active CC line (flipped plug orientation).
    Cc2,
}

/// USB Type-C data/power role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TypeCRole {
    /// Downstream Facing Port — hosts a device, provides VBUS.
    #[default]
    Dfp,
    /// Upstream Facing Port — acts as device, sinks VBUS.
    Ufp,
    /// Dual Role Port — can negotiate either role.
    Drp,
}

/// USB Power Delivery power supply type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PdoType {
    /// Fixed supply (constant voltage).
    #[default]
    Fixed,
    /// Battery supply.
    Battery,
    /// Variable supply (range of voltages).
    Variable,
    /// Programmable power supply (PPS, PD 3.0+).
    Pps,
}

/// A USB Power Delivery Power Data Object (PDO).
///
/// Describes a power capability offered by the source.
#[derive(Debug, Clone, Copy)]
pub struct Pdo {
    /// PDO supply type.
    pub pdo_type: PdoType,
    /// Voltage in millivolts.
    pub voltage_mv: u32,
    /// Maximum current in milliamps.
    pub current_ma: u32,
    /// Maximum power in milliwatts (for Battery PDOs).
    pub power_mw: u32,
    /// Raw PDO value from the PD message.
    pub raw: u32,
}

impl Pdo {
    /// Parse a Fixed Supply PDO from its raw 32-bit encoding.
    ///
    /// Bits[31:30] = 0b00 for Fixed Supply.
    /// Bits[19:10] = voltage in 50 mV units.
    /// Bits[9:0]   = max current in 10 mA units.
    pub fn from_fixed(raw: u32) -> Self {
        let voltage_mv = ((raw >> 10) & 0x3FF) * 50;
        let current_ma = (raw & 0x3FF) * 10;
        Self {
            pdo_type: PdoType::Fixed,
            voltage_mv,
            current_ma,
            power_mw: voltage_mv * current_ma / 1000,
            raw,
        }
    }

    /// Parse a Variable Supply PDO from its raw 32-bit encoding.
    ///
    /// Bits[29:20] = max voltage in 50 mV units.
    /// Bits[19:10] = min voltage in 50 mV units.
    /// Bits[9:0]   = max current in 10 mA units.
    pub fn from_variable(raw: u32) -> Self {
        let max_voltage_mv = ((raw >> 20) & 0x3FF) * 50;
        let current_ma = (raw & 0x3FF) * 10;
        Self {
            pdo_type: PdoType::Variable,
            voltage_mv: max_voltage_mv,
            current_ma,
            power_mw: max_voltage_mv * current_ma / 1000,
            raw,
        }
    }

    /// Parse any PDO from its raw 32-bit encoding.
    pub fn from_raw(raw: u32) -> Self {
        match (raw >> 30) & 0x3 {
            0b00 => Self::from_fixed(raw),
            0b01 => Self::from_variable(raw),
            0b10 => {
                // Battery
                let max_voltage_mv = ((raw >> 20) & 0x3FF) * 50;
                let power_mw = ((raw >> 10) & 0x3FF) * 250;
                Self {
                    pdo_type: PdoType::Battery,
                    voltage_mv: max_voltage_mv,
                    current_ma: if max_voltage_mv > 0 {
                        power_mw * 1000 / max_voltage_mv
                    } else {
                        0
                    },
                    power_mw,
                    raw,
                }
            }
            _ => {
                // Programmable Power Supply (PPS)
                let max_voltage_mv = ((raw >> 17) & 0xFF) * 100;
                let current_ma = (raw & 0x7F) * 50;
                Self {
                    pdo_type: PdoType::Pps,
                    voltage_mv: max_voltage_mv,
                    current_ma,
                    power_mw: max_voltage_mv * current_ma / 1000,
                    raw,
                }
            }
        }
    }

    /// Build a Fixed PDO raw value for a Request message.
    ///
    /// Encodes the requested operating current and max current.
    /// `position` is 1-based index into the source capabilities list.
    pub fn build_request(position: u8, op_current_ma: u32, max_current_ma: u32) -> u32 {
        let op_current = (op_current_ma / 10) & 0x3FF;
        let max_current = (max_current_ma / 10) & 0x3FF;
        ((position as u32 & 0x7) << 28) | (op_current << 10) | max_current
    }
}

/// A negotiated USB PD contract.
#[derive(Debug, Clone, Copy, Default)]
pub struct PdContract {
    /// Whether a PD contract is active.
    pub active: bool,
    /// The selected PDO from the source capabilities.
    pub pdo: Option<Pdo>,
    /// Agreed voltage in millivolts.
    pub voltage_mv: u32,
    /// Agreed current in milliamps.
    pub current_ma: u32,
    /// PDO position (1-based) in source capabilities list.
    pub pdo_position: u8,
    /// PD specification revision in use (2 or 3).
    pub spec_rev: u8,
    /// Message ID counter for next outgoing message.
    pub msg_id: u8,
}

/// USB Type-C port state machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortState {
    /// Port is unattached — waiting for connection.
    #[default]
    Unattached,
    /// Attachment detected, resolving role.
    AttachWait,
    /// Attached as DFP (host).
    AttachedDfp,
    /// Attached as UFP (device).
    AttachedUfp,
    /// PD negotiation in progress.
    PdNegotiating,
    /// PD contract established.
    PdContracted,
    /// Error or fault state.
    ErrorRecovery,
}

/// A single USB Type-C physical port.
pub struct TypeCPort {
    /// MMIO base address for this port's controller registers.
    mmio_base: usize,
    /// Port index in the system (0-based).
    port_index: u8,
    /// Current port state machine state.
    pub state: PortState,
    /// Port role configuration.
    pub role: TypeCRole,
    /// Active CC line orientation.
    pub orientation: CcOrientation,
    /// Whether VBUS is present.
    pub vbus_present: bool,
    /// Measured VBUS voltage in millivolts.
    pub vbus_mv: u32,
    /// Measured VBUS current in milliamps.
    pub vbus_ma: u32,
    /// Active PD contract (if any).
    pub contract: PdContract,
    /// Source capabilities received from the partner.
    pub source_caps: [Option<Pdo>; MAX_PDOS],
    /// Number of valid source capabilities.
    pub source_caps_count: usize,
    /// Total attach events on this port.
    pub attach_count: u32,
    /// Total PD contracts established on this port.
    pub contract_count: u32,
}

impl TypeCPort {
    /// Create a new, uninitialized Type-C port.
    ///
    /// `mmio_base` is the MMIO base address of the port controller
    /// registers. `port_index` is the 0-based port number.
    pub fn new(mmio_base: usize, port_index: u8) -> Self {
        Self {
            mmio_base,
            port_index,
            state: PortState::Unattached,
            role: TypeCRole::Drp,
            orientation: CcOrientation::Cc1,
            vbus_present: false,
            vbus_mv: 0,
            vbus_ma: 0,
            contract: PdContract::default(),
            source_caps: [None; MAX_PDOS],
            source_caps_count: 0,
            attach_count: 0,
            contract_count: 0,
        }
    }

    /// Read a controller register.
    fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base is the valid, mapped Type-C controller
        // MMIO region; offset is within the defined register space.
        unsafe { mmio_read32(self.mmio_base, offset) }
    }

    /// Write a controller register.
    fn write_reg(&self, offset: u32, val: u32) {
        // SAFETY: mmio_base is the valid, mapped Type-C controller
        // MMIO region; offset is within the defined register space.
        unsafe { mmio_write32(self.mmio_base, offset, val) }
    }

    /// Initialize the port controller.
    ///
    /// Enables interrupts for attach, PD RX, and VBUS changes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the hardware does not respond.
    pub fn init(&mut self) -> Result<()> {
        // Enable interrupt sources.
        let int_mask = INT_ATTACH | INT_ROLE_CHANGE | INT_PD_RX | INT_PD_TX | INT_VBUS_CHANGE;
        self.write_reg(REG_INT_ENABLE, int_mask);

        // Clear any pending interrupts.
        let pending = self.read_reg(REG_INT_STATUS);
        self.write_reg(REG_INT_STATUS, pending);

        // Read initial status.
        self.refresh_status();

        Ok(())
    }

    /// Refresh port status from hardware registers.
    ///
    /// Updates orientation, VBUS state, and measured voltage/current.
    pub fn refresh_status(&mut self) {
        let status = self.read_reg(REG_STATUS);
        self.vbus_present = status & STATUS_VBUS_PRESENT != 0;
        self.orientation = if status & STATUS_FLIPPED != 0 {
            CcOrientation::Cc2
        } else {
            CcOrientation::Cc1
        };

        if status & STATUS_ATTACHED != 0 {
            let vbus_volt = self.read_reg(REG_VBUS_VOLT);
            let vbus_curr = self.read_reg(REG_VBUS_CURR);
            self.vbus_mv = vbus_volt & 0xFFFF;
            self.vbus_ma = vbus_curr & 0xFFFF;

            if status & STATUS_DFP != 0 {
                self.role = TypeCRole::Dfp;
            } else {
                self.role = TypeCRole::Ufp;
            }
        }
    }

    /// Handle a hardware interrupt for this port.
    ///
    /// Reads the interrupt status, acknowledges the interrupt, and
    /// drives the port state machine. Returns the interrupt cause bits.
    pub fn handle_interrupt(&mut self) -> u32 {
        let cause = self.read_reg(REG_INT_STATUS);

        // Acknowledge all interrupts.
        self.write_reg(REG_INT_STATUS, cause);

        if cause & INT_ATTACH != 0 {
            self.refresh_status();
            let status = self.read_reg(REG_STATUS);
            if status & STATUS_ATTACHED != 0 {
                self.attach_count += 1;
                self.state = PortState::AttachWait;
            } else {
                // Detach.
                self.state = PortState::Unattached;
                self.contract = PdContract::default();
                self.source_caps_count = 0;
            }
        }

        if cause & INT_VBUS_CHANGE != 0 {
            self.refresh_status();
        }

        if cause & INT_PD_RX != 0 {
            let _ = self.process_pd_rx();
        }

        cause
    }

    /// Process a received PD message from the RX FIFO.
    fn process_pd_rx(&mut self) -> Result<()> {
        let pd_status = self.read_reg(REG_PD_STATUS);
        if pd_status & PD_RX_AVAILABLE == 0 {
            return Err(Error::NotFound);
        }
        if pd_status & PD_RX_ERROR != 0 {
            return Err(Error::IoError);
        }

        // Read message header (first 32-bit word contains the 16-bit header).
        let header_word = self.read_reg(REG_PD_RX_DATA);
        let header = (header_word & 0xFFFF) as u16;
        let msg_type = (header & PD_HDR_MSG_TYPE_MASK) as u8;
        let num_do = ((header >> PD_HDR_NUM_DO_SHIFT) & 0x7) as usize;

        match msg_type {
            PD_MSG_SRC_CAP => {
                // Parse up to MAX_PDOS power data objects.
                let count = num_do.min(MAX_PDOS);
                self.source_caps_count = 0;
                for i in 0..count {
                    let pdo_raw = self.read_reg(REG_PD_RX_DATA);
                    self.source_caps[i] = Some(Pdo::from_raw(pdo_raw));
                    self.source_caps_count += 1;
                }
                // Automatically request the highest-power PDO.
                self.auto_request_contract()?;
            }
            PD_MSG_REQUEST => {
                // As source: acknowledge the request.
                self.state = PortState::PdNegotiating;
            }
            _ => {}
        }

        Ok(())
    }

    /// Automatically select and request the highest-power PDO.
    ///
    /// Iterates through source capabilities and picks the PDO that
    /// offers the most power (voltage × current).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no source capabilities are
    /// available, or [`Error::Busy`] if the TX is not ready.
    pub fn auto_request_contract(&mut self) -> Result<()> {
        if self.source_caps_count == 0 {
            return Err(Error::NotFound);
        }

        // Find the PDO with the highest power.
        let mut best_idx = 0usize;
        let mut best_power = 0u32;
        for (i, cap) in self.source_caps[..self.source_caps_count]
            .iter()
            .enumerate()
        {
            if let Some(pdo) = cap {
                if pdo.power_mw > best_power {
                    best_power = pdo.power_mw;
                    best_idx = i;
                }
            }
        }

        let pdo = self.source_caps[best_idx].ok_or(Error::NotFound)?;

        // Build the request DO.
        let request_do = Pdo::build_request((best_idx + 1) as u8, pdo.current_ma, pdo.current_ma);

        self.send_pd_request(request_do, &pdo)?;

        Ok(())
    }

    /// Send a PD Request message for a specific PDO.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the TX FIFO is not ready or times
    /// out waiting for transmission to complete.
    pub fn send_pd_request(&mut self, request_do: u32, pdo: &Pdo) -> Result<()> {
        // Wait for TX ready.
        let mut timeout = PD_TX_TIMEOUT;
        loop {
            let pd_status = self.read_reg(REG_PD_STATUS);
            if pd_status & PD_TX_READY != 0 && pd_status & PD_TX_BUSY == 0 {
                break;
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }

        // Build message header: 1 data object, Request type.
        let msg_id = self.contract.msg_id;
        let header: u16 = (PD_MSG_REQUEST as u16 & PD_HDR_MSG_TYPE_MASK)
            | ((msg_id as u16 & 0x7) << PD_HDR_MSG_ID_SHIFT)
            | (1u16 << PD_HDR_NUM_DO_SHIFT)
            | (2u16 << PD_HDR_SPEC_REV_SHIFT); // PD 3.0

        // Write header + data object.
        self.write_reg(REG_PD_TX_DATA, header as u32);
        self.write_reg(REG_PD_TX_DATA, request_do);

        // Trigger transmit.
        self.write_reg(REG_PD_CTRL, 0x1);

        // Update contract state.
        self.contract.pdo = Some(*pdo);
        self.contract.pdo_position = (request_do >> 28) as u8 & 0x7;
        self.contract.voltage_mv = pdo.voltage_mv;
        self.contract.current_ma = pdo.current_ma;
        self.contract.msg_id = msg_id.wrapping_add(1) & 0x7;

        self.state = PortState::PdNegotiating;

        Ok(())
    }

    /// Enable VBUS sourcing (DFP mode).
    ///
    /// Configures the port to source 5 V VBUS at the default current.
    pub fn enable_vbus_source(&self) {
        self.write_reg(REG_VBUS_CTRL, VBUS_CTRL_SRC_ENABLE);
    }

    /// Disable VBUS sourcing.
    pub fn disable_vbus_source(&self) {
        let val = self.read_reg(REG_VBUS_CTRL);
        self.write_reg(REG_VBUS_CTRL, val & !VBUS_CTRL_SRC_ENABLE);
    }

    /// Enable VBUS sinking (UFP mode).
    pub fn enable_vbus_sink(&self) {
        self.write_reg(REG_VBUS_CTRL, VBUS_CTRL_SNK_ENABLE);
    }

    /// Discharge VBUS (drive it to ground).
    pub fn discharge_vbus(&self) {
        let val = self.read_reg(REG_VBUS_CTRL);
        self.write_reg(REG_VBUS_CTRL, val | VBUS_CTRL_DISCHARGE);
    }

    /// Return the port index.
    pub fn port_index(&self) -> u8 {
        self.port_index
    }

    /// Return `true` if a cable is attached to this port.
    pub fn is_attached(&self) -> bool {
        matches!(
            self.state,
            PortState::AttachWait
                | PortState::AttachedDfp
                | PortState::AttachedUfp
                | PortState::PdNegotiating
                | PortState::PdContracted
        )
    }

    /// Return `true` if a PD contract is active on this port.
    pub fn has_pd_contract(&self) -> bool {
        self.contract.active
    }

    /// Return the CC line state word for diagnostics.
    pub fn cc_status(&self) -> u32 {
        self.read_reg(REG_CC_STATUS)
    }

    /// Return which CC pin is active (1 or 2) based on orientation.
    pub fn active_cc_pin(&self) -> u8 {
        match self.orientation {
            CcOrientation::Cc1 => 1,
            CcOrientation::Cc2 => 2,
        }
    }

    /// Return the measured VBUS power in milliwatts.
    pub fn vbus_power_mw(&self) -> u32 {
        // P = V * I / 1000  (mV * mA / 1000 = mW)
        self.vbus_mv.saturating_mul(self.vbus_ma) / 1000
    }
}

// ── Registry ─────────────────────────────────────────────────────

/// Registry for USB Type-C port controllers.
pub struct TypeCRegistry {
    /// MMIO base addresses of registered ports.
    ports: [Option<usize>; MAX_PORTS],
    /// Number of registered ports.
    count: usize,
}

impl Default for TypeCRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeCRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            ports: [None; MAX_PORTS],
            count: 0,
        }
    }

    /// Register a Type-C port by its MMIO base address.
    ///
    /// Returns the assigned port index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: usize) -> Result<usize> {
        if self.count >= MAX_PORTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.ports[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Get the MMIO base address of a registered port.
    pub fn get(&self, index: usize) -> Option<usize> {
        if index < self.count {
            self.ports[index]
        } else {
            None
        }
    }

    /// Return the number of registered ports.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no ports are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
