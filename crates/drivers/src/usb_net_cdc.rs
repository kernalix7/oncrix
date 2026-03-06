// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB CDC-ECM / CDC-NCM network driver.
//!
//! Implements USB Communication Device Class (CDC) Ethernet Control Model
//! (ECM) and Network Control Model (NCM) for USB network adapters. These
//! are the standard USB networking classes used by dongles, tethered phones,
//! and embedded Ethernet adapters.
//!
//! Reference: USB CDC specification rev. 1.2 (USB-IF).

use oncrix_lib::{Error, Result};

/// Maximum Ethernet frame size (excluding USB framing).
pub const ETH_MAX_FRAME: usize = 1514;
/// Maximum NCM datagram size.
pub const NCM_MAX_DATAGRAM: usize = 16384;
/// Maximum transfer size for a bulk transaction.
pub const CDC_MAX_BULK: usize = 65536;

/// CDC subclass codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CdcSubclass {
    /// Ethernet Control Model.
    Ecm = 0x06,
    /// Network Control Model.
    Ncm = 0x0D,
    /// Ethernet Emulation Model.
    Eem = 0x0C,
}

/// CDC request codes (control transfers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CdcRequest {
    /// Set Ethernet multicast filters.
    SetEthMulticastFilters = 0x40,
    /// Set Ethernet power management pattern filter.
    SetEthPowerMgmtFilter = 0x41,
    /// Get Ethernet power management pattern filter.
    GetEthPowerMgmtFilter = 0x42,
    /// Set Ethernet packet filter (promisc, multicast, etc.).
    SetEthPacketFilter = 0x43,
    /// Get Ethernet statistical counter.
    GetEthStatistic = 0x44,
    /// Get NTB parameters (NCM).
    GetNtbParameters = 0x80,
    /// Set NTB format (NCM).
    SetNtbFormat = 0x83,
}

/// Ethernet packet filter flags (CDC SetEthPacketFilter).
pub mod packet_filter {
    /// Promiscuous mode.
    pub const PROMISC: u16 = 1 << 0;
    /// All multicast.
    pub const ALL_MULTICAST: u16 = 1 << 1;
    /// Directed (unicast to our MAC).
    pub const DIRECTED: u16 = 1 << 2;
    /// Broadcast.
    pub const BROADCAST: u16 = 1 << 3;
    /// Multicast (filtered list).
    pub const MULTICAST: u16 = 1 << 4;
}

/// NTB (Network Transfer Block) parameters (NCM).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NtbParameters {
    /// Length of this structure (28 bytes for 16-bit NTB).
    pub w_length: u16,
    /// Bitmap of supported NTB formats (bit 0 = 16-bit, bit 1 = 32-bit).
    pub bm_ntb_formats_supported: u16,
    /// Maximum IN NTB size (bytes).
    pub dw_ntb_in_max_size: u32,
    /// NDP IN divisor.
    pub w_ndp_in_divisor: u16,
    /// NDP IN payload remainder.
    pub w_ndp_in_payload_remainder: u16,
    /// NDP IN alignment.
    pub w_ndp_in_alignment: u16,
    /// Reserved.
    pub _reserved: u16,
    /// Maximum OUT NTB size.
    pub dw_ntb_out_max_size: u32,
    /// NDP OUT divisor.
    pub w_ndp_out_divisor: u16,
    /// NDP OUT payload remainder.
    pub w_ndp_out_payload_remainder: u16,
    /// NDP OUT alignment.
    pub w_ndp_out_alignment: u16,
    /// Maximum number of datagrams per OUT NTB.
    pub w_ntb_out_max_datagrams: u16,
}

/// CDC ECM/NCM device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdcLinkState {
    /// Device is not configured.
    Unconfigured,
    /// Device is configured, no carrier.
    Configured,
    /// Carrier detected, ready to transfer.
    Connected,
    /// Suspended.
    Suspended,
}

/// CDC network device driver state.
pub struct CdcNetDevice {
    /// USB device address.
    pub dev_addr: u8,
    /// CDC subclass (ECM or NCM).
    pub subclass: CdcSubclass,
    /// Bulk-IN endpoint address.
    pub ep_in: u8,
    /// Bulk-OUT endpoint address.
    pub ep_out: u8,
    /// Interrupt endpoint address (for notifications).
    pub ep_notify: u8,
    /// Current link state.
    pub link: CdcLinkState,
    /// Device MAC address.
    pub mac: [u8; 6],
    /// Active packet filter flags.
    pub packet_filter: u16,
    /// NTB parameters (NCM only).
    pub ntb_params: NtbParameters,
    /// TX sequence number (NCM).
    pub tx_seq: u16,
}

impl CdcNetDevice {
    /// Creates a new CDC net device.
    pub const fn new(dev_addr: u8, subclass: CdcSubclass) -> Self {
        Self {
            dev_addr,
            subclass,
            ep_in: 0,
            ep_out: 0,
            ep_notify: 0,
            link: CdcLinkState::Unconfigured,
            mac: [0u8; 6],
            packet_filter: 0,
            ntb_params: NtbParameters {
                w_length: 28,
                bm_ntb_formats_supported: 0x01,
                dw_ntb_in_max_size: NCM_MAX_DATAGRAM as u32,
                w_ndp_in_divisor: 4,
                w_ndp_in_payload_remainder: 0,
                w_ndp_in_alignment: 4,
                _reserved: 0,
                dw_ntb_out_max_size: NCM_MAX_DATAGRAM as u32,
                w_ndp_out_divisor: 4,
                w_ndp_out_payload_remainder: 0,
                w_ndp_out_alignment: 4,
                w_ntb_out_max_datagrams: 0,
            },
            tx_seq: 0,
        }
    }

    /// Configures endpoint addresses after descriptor parsing.
    pub fn set_endpoints(&mut self, ep_in: u8, ep_out: u8, ep_notify: u8) {
        self.ep_in = ep_in;
        self.ep_out = ep_out;
        self.ep_notify = ep_notify;
        self.link = CdcLinkState::Configured;
    }

    /// Sets the device MAC address (parsed from the CDC functional descriptor).
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    /// Sets the packet filter on the device (ECM SetEthPacketFilter).
    ///
    /// In a real driver this issues a USB control transfer.
    pub fn set_packet_filter(&mut self, flags: u16) -> Result<()> {
        self.packet_filter = flags;
        Ok(())
    }

    /// Builds an ECM TX transfer from a raw Ethernet frame.
    ///
    /// For ECM, the USB payload is simply the raw Ethernet frame.
    pub fn ecm_build_tx<'a>(&self, frame: &'a [u8]) -> Result<&'a [u8]> {
        if self.subclass != CdcSubclass::Ecm {
            return Err(Error::InvalidArgument);
        }
        if frame.len() > ETH_MAX_FRAME {
            return Err(Error::InvalidArgument);
        }
        Ok(frame)
    }

    /// Builds an NCM NTB (16-bit) transfer wrapping `frame`.
    ///
    /// Writes the NTH16 + NDP16 + datagram into `buf`, returns bytes used.
    pub fn ncm_build_ntb(&mut self, frame: &[u8], buf: &mut [u8]) -> Result<usize> {
        if self.subclass != CdcSubclass::Ncm {
            return Err(Error::InvalidArgument);
        }
        if frame.len() > ETH_MAX_FRAME {
            return Err(Error::InvalidArgument);
        }
        // Minimal NTH16 (12 bytes) + NDP16 header (8 bytes) + 1 datagram pointer (4 bytes)
        // + null terminator (4 bytes) + frame data.
        const NTH_SIZE: usize = 12;
        const NDP_OFFSET: usize = NTH_SIZE;
        const NDP_SIZE: usize = 16; // 8 header + 2×4 pointers
        let data_offset = NDP_OFFSET + NDP_SIZE;
        let total = data_offset + frame.len();
        if buf.len() < total {
            return Err(Error::OutOfMemory);
        }
        // NTH16: signature "NCMH", sequence, block_length, ndp_index.
        buf[0..4].copy_from_slice(b"NCMH");
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6..8].copy_from_slice(&self.tx_seq.to_le_bytes());
        buf[8..10].copy_from_slice(&(total as u16).to_le_bytes());
        buf[10..12].copy_from_slice(&(NDP_OFFSET as u16).to_le_bytes());
        self.tx_seq = self.tx_seq.wrapping_add(1);
        // NDP16: signature "NCM0", length, next_ndp_index, datagram[0], null terminator.
        buf[NDP_OFFSET..NDP_OFFSET + 4].copy_from_slice(b"NCM0");
        buf[NDP_OFFSET + 4..NDP_OFFSET + 6].copy_from_slice(&(NDP_SIZE as u16).to_le_bytes());
        buf[NDP_OFFSET + 6..NDP_OFFSET + 8].copy_from_slice(&0u16.to_le_bytes());
        buf[NDP_OFFSET + 8..NDP_OFFSET + 10].copy_from_slice(&(data_offset as u16).to_le_bytes());
        buf[NDP_OFFSET + 10..NDP_OFFSET + 12].copy_from_slice(&(frame.len() as u16).to_le_bytes());
        buf[NDP_OFFSET + 12..NDP_OFFSET + 16].fill(0); // null terminator
        buf[data_offset..data_offset + frame.len()].copy_from_slice(frame);
        Ok(total)
    }

    /// Processes a notification from the interrupt endpoint.
    pub fn handle_notification(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        // Standard CDC notification header: bmRequestType, bNotification, wValue, wIndex, wLength.
        let notification = data[1];
        match notification {
            0x00 => {
                /* NETWORK_CONNECTION */
                self.link = CdcLinkState::Connected;
            }
            0x2A => { /* CONNECTION_SPEED_CHANGE — ignore for now */ }
            _ => {}
        }
        Ok(())
    }

    /// Returns the link state.
    pub fn link_state(&self) -> CdcLinkState {
        self.link
    }
}

impl Default for CdcNetDevice {
    fn default() -> Self {
        Self::new(0, CdcSubclass::Ecm)
    }
}

/// Parses a MAC address from the CDC iMACAddress string descriptor value.
///
/// The descriptor encodes 12 uppercase hex digits (e.g. "001122334455").
pub fn parse_mac(s: &[u8]) -> Result<[u8; 6]> {
    if s.len() < 12 {
        return Err(Error::InvalidArgument);
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        let hi = hex_nibble(s[i * 2])?;
        let lo = hex_nibble(s[i * 2 + 1])?;
        mac[i] = (hi << 4) | lo;
    }
    Ok(mac)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Error::InvalidArgument),
    }
}
