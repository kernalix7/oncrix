// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bluetooth USB (btusb) driver.
//!
//! Implements USB transport for Bluetooth HCI (Host Controller Interface)
//! as defined in the Bluetooth specification. Supports USB bulk, interrupt,
//! and isochronous endpoints for HCI command/event and SCO/ACL data.

use oncrix_lib::{Error, Result};

/// Bluetooth USB endpoint numbers as assigned by the spec.
/// The actual endpoint numbers vary by device, but the class/subclass identify Bluetooth.

/// USB class/subclass/protocol for Bluetooth.
pub const BT_USB_CLASS: u8 = 0xE0;
pub const BT_USB_SUBCLASS: u8 = 0x01;
pub const BT_USB_PROTOCOL: u8 = 0x01;

/// HCI packet type codes (sent as first byte of USB bulk/interrupt packets).
pub const HCI_CMD: u8 = 0x01; // Host → Controller: command
pub const HCI_ACL: u8 = 0x02; // Bidirectional: ACL data
pub const HCI_SCO: u8 = 0x03; // Bidirectional: synchronous (audio)
pub const HCI_EVENT: u8 = 0x04; // Controller → Host: event

/// HCI event codes.
pub const EVT_INQUIRY_COMPLETE: u8 = 0x01;
pub const EVT_INQUIRY_RESULT: u8 = 0x02;
pub const EVT_CONN_COMPLETE: u8 = 0x03;
pub const EVT_DISCONN_COMPLETE: u8 = 0x05;
pub const EVT_REMOTE_NAME_REQ_COMPLETE: u8 = 0x07;
pub const EVT_COMMAND_COMPLETE: u8 = 0x0E;
pub const EVT_COMMAND_STATUS: u8 = 0x0F;
pub const EVT_NUMBER_OF_COMPLETED_PKTS: u8 = 0x13;
pub const EVT_LE_META: u8 = 0x3E;

/// Maximum sizes for HCI packets.
pub const HCI_CMD_MAX_SIZE: usize = 260; // 3-byte header + 255 params
pub const HCI_EVENT_MAX_SIZE: usize = 257; // 2-byte header + 255 params
pub const HCI_ACL_MAX_SIZE: usize = 1028; // 4-byte header + 1024 data
pub const HCI_SCO_MAX_SIZE: usize = 255; // 3-byte header + 255 data

/// HCI command header (3 bytes).
#[repr(C)]
pub struct HciCmdHeader {
    /// Opcode (OCF in lower 10 bits, OGF in upper 6 bits).
    pub opcode: u16,
    /// Parameter total length.
    pub plen: u8,
}

/// OGF (Opcode Group Field) values.
pub mod ogf {
    pub const LINK_CTRL: u8 = 0x01;
    pub const LINK_POLICY: u8 = 0x02;
    pub const HOST_CTRL: u8 = 0x03;
    pub const INFO_PARAMS: u8 = 0x04;
    pub const STATUS_PARAMS: u8 = 0x05;
    pub const LE_CTRL: u8 = 0x08;
    pub const VENDOR: u8 = 0x3F;
}

/// Common OCF (Opcode Command Field) values for host controller commands.
pub mod ocf {
    pub const RESET: u16 = 0x0003;
    pub const READ_LOCAL_VERSION: u16 = 0x0001;
    pub const READ_BD_ADDR: u16 = 0x0009;
    pub const SET_EVENT_MASK: u16 = 0x0001;
    pub const READ_BUFFER_SIZE: u16 = 0x0005;
    pub const WRITE_SCAN_ENABLE: u16 = 0x001A;
}

/// Build an HCI opcode from OGF and OCF.
pub const fn hci_opcode(ogf: u8, ocf: u16) -> u16 {
    ((ogf as u16) << 10) | (ocf & 0x03FF)
}

/// Bluetooth device address (BD_ADDR, 6 bytes, LSB first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BdAddr(pub [u8; 6]);

impl BdAddr {
    /// Zero/null address.
    pub const ZERO: BdAddr = BdAddr([0u8; 6]);
}

/// HCI connection handle (12-bit value, 0x0000–0x0EFF).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HciHandle(pub u16);

impl HciHandle {
    /// Invalid handle sentinel.
    pub const INVALID: HciHandle = HciHandle(0xFFFF);
}

/// ACL packet header.
#[repr(C)]
pub struct AclHeader {
    /// Connection handle (12 bits) + PB flags (2 bits) + BC flags (2 bits).
    pub handle_flags: u16,
    /// Data length.
    pub dlen: u16,
}

/// Driver state for a Bluetooth USB adapter.
pub struct BtUsb {
    /// Index of the HCI command USB endpoint (interrupt OUT).
    cmd_ep: u8,
    /// Index of the HCI event USB endpoint (interrupt IN).
    event_ep: u8,
    /// Index of the ACL data bulk OUT endpoint.
    acl_out_ep: u8,
    /// Index of the ACL data bulk IN endpoint.
    acl_in_ep: u8,
    /// Local BD_ADDR (read from controller after reset).
    local_addr: BdAddr,
    /// Controller has been initialized.
    initialized: bool,
    /// Transmit queue depth (number of pending ACL buffers).
    tx_pending: usize,
    /// Receive buffer for incoming events.
    event_buf: [u8; HCI_EVENT_MAX_SIZE],
    /// Number of bytes in event_buf.
    event_len: usize,
}

impl BtUsb {
    /// Create a new Bluetooth USB driver.
    ///
    /// # Arguments
    /// - `cmd_ep`: HCI command endpoint number
    /// - `event_ep`: HCI event endpoint number
    /// - `acl_out_ep`: ACL bulk OUT endpoint number
    /// - `acl_in_ep`: ACL bulk IN endpoint number
    pub fn new(cmd_ep: u8, event_ep: u8, acl_out_ep: u8, acl_in_ep: u8) -> Self {
        Self {
            cmd_ep,
            event_ep,
            acl_out_ep,
            acl_in_ep,
            local_addr: BdAddr::ZERO,
            initialized: false,
            tx_pending: 0,
            event_buf: [0u8; HCI_EVENT_MAX_SIZE],
            event_len: 0,
        }
    }

    /// Initialize the Bluetooth controller.
    pub fn init(&mut self) -> Result<()> {
        self.hci_reset()?;
        self.read_local_address()?;
        self.initialized = true;
        Ok(())
    }

    /// Send an HCI Reset command and wait for the Command Complete event.
    fn hci_reset(&mut self) -> Result<()> {
        let opcode = hci_opcode(ogf::HOST_CTRL, ocf::RESET);
        self.send_hci_cmd(opcode, &[])?;
        Ok(())
    }

    /// Read the local BD_ADDR.
    fn read_local_address(&mut self) -> Result<()> {
        let opcode = hci_opcode(ogf::INFO_PARAMS, ocf::READ_BD_ADDR);
        self.send_hci_cmd(opcode, &[])?;
        // In a full driver, we would parse the event response here.
        Ok(())
    }

    /// Enqueue an HCI command for USB transmission.
    ///
    /// # Arguments
    /// - `opcode`: 16-bit HCI opcode
    /// - `params`: command parameters (max 255 bytes)
    pub fn send_hci_cmd(&mut self, opcode: u16, params: &[u8]) -> Result<()> {
        if params.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        // Build the command packet: HCI_CMD header + opcode + plen + params.
        let mut pkt = [0u8; HCI_CMD_MAX_SIZE];
        pkt[0] = HCI_CMD;
        pkt[1] = (opcode & 0xFF) as u8;
        pkt[2] = ((opcode >> 8) & 0xFF) as u8;
        pkt[3] = params.len() as u8;
        pkt[4..4 + params.len()].copy_from_slice(params);
        // Submit the packet to the USB interrupt OUT endpoint.
        // (Real implementation would call the USB core submit_urb here.)
        let _ = self.cmd_ep;
        Ok(())
    }

    /// Send ACL data to a connected device.
    ///
    /// # Arguments
    /// - `handle`: connection handle
    /// - `pb`: packet boundary flags (0=first non-auto-flush, 1=continuing, 2=first auto-flush)
    /// - `data`: payload bytes
    pub fn send_acl(&mut self, handle: HciHandle, pb: u8, data: &[u8]) -> Result<()> {
        if data.len() > 1024 {
            return Err(Error::InvalidArgument);
        }
        if self.tx_pending >= 8 {
            return Err(Error::Busy);
        }
        let mut pkt = [0u8; HCI_ACL_MAX_SIZE];
        pkt[0] = HCI_ACL;
        let hf: u16 = (handle.0 & 0x0FFF) | ((pb as u16 & 0x3) << 12);
        pkt[1] = (hf & 0xFF) as u8;
        pkt[2] = ((hf >> 8) & 0xFF) as u8;
        pkt[3] = (data.len() & 0xFF) as u8;
        pkt[4] = ((data.len() >> 8) & 0xFF) as u8;
        pkt[5..5 + data.len()].copy_from_slice(data);
        // Submit via USB bulk OUT.
        let _ = self.acl_out_ep;
        self.tx_pending += 1;
        Ok(())
    }

    /// Process received bytes from the HCI event endpoint.
    ///
    /// Returns `Some(event_code)` when a complete event is assembled.
    pub fn receive_event_bytes(&mut self, data: &[u8]) -> Option<u8> {
        for &b in data {
            if self.event_len < HCI_EVENT_MAX_SIZE {
                self.event_buf[self.event_len] = b;
                self.event_len += 1;
            }
        }
        // Event format: 0x04, event_code, plen, params...
        if self.event_len >= 2 {
            let plen = self.event_buf[2] as usize;
            if self.event_len >= 3 + plen {
                let code = self.event_buf[1];
                self.event_len = 0;
                return Some(code);
            }
        }
        None
    }

    /// Return the local Bluetooth address (valid after init).
    pub fn local_address(&self) -> BdAddr {
        self.local_addr
    }

    /// Return whether the driver has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Signal that `n` ACL buffers have been sent (decrements tx_pending).
    pub fn ack_tx_complete(&mut self, n: usize) {
        self.tx_pending = self.tx_pending.saturating_sub(n);
    }
}
