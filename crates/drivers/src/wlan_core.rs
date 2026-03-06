// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Wireless LAN (WLAN) core driver framework.
//!
//! Provides the common abstractions for IEEE 802.11 wireless LAN drivers,
//! including BSS management, station tracking, frame construction, and
//! management of the scan/association state machine.

use oncrix_lib::{Error, Result};

/// IEEE 802.11 MAC address (6 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Broadcast address (FF:FF:FF:FF:FF:FF).
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);
    /// Zero address.
    pub const ZERO: MacAddr = MacAddr([0u8; 6]);

    /// Return true if this is a multicast address.
    pub fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }
}

/// IEEE 802.11 SSID (max 32 octets).
#[derive(Clone, Copy, Debug)]
pub struct Ssid {
    pub bytes: [u8; 32],
    pub len: usize,
}

impl Ssid {
    /// Create an SSID from a byte slice (truncated to 32 bytes).
    pub fn from_bytes(s: &[u8]) -> Self {
        let len = s.len().min(32);
        let mut bytes = [0u8; 32];
        bytes[..len].copy_from_slice(&s[..len]);
        Self { bytes, len }
    }
}

/// 802.11 operation modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperMode {
    /// Client (STA) mode — associate with an AP.
    Station,
    /// Software AP mode.
    AccessPoint,
    /// Monitor mode — receive all frames.
    Monitor,
    /// Peer-to-peer (ad-hoc / IBSS).
    AdHoc,
}

/// 802.11 frequency band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    /// 2.4 GHz band (802.11b/g/n).
    Band2GHz,
    /// 5 GHz band (802.11a/n/ac/ax).
    Band5GHz,
    /// 6 GHz band (802.11ax).
    Band6GHz,
}

/// A wireless channel.
#[derive(Clone, Copy, Debug)]
pub struct WlanChannel {
    /// Center frequency in MHz.
    pub freq_mhz: u32,
    /// Channel number.
    pub number: u8,
    /// Band.
    pub band: Band,
    /// Channel bandwidth in MHz (20, 40, 80, 160).
    pub bandwidth_mhz: u8,
}

impl WlanChannel {
    /// 2.4 GHz channel 1 (2412 MHz).
    pub const CHAN_2G_1: WlanChannel = WlanChannel {
        freq_mhz: 2412,
        number: 1,
        band: Band::Band2GHz,
        bandwidth_mhz: 20,
    };

    /// 5 GHz channel 36 (5180 MHz).
    pub const CHAN_5G_36: WlanChannel = WlanChannel {
        freq_mhz: 5180,
        number: 36,
        band: Band::Band5GHz,
        bandwidth_mhz: 20,
    };
}

/// BSS (Basic Service Set) descriptor, filled in by scan.
#[derive(Clone, Copy, Debug)]
pub struct BssDesc {
    /// AP MAC address (BSSID).
    pub bssid: MacAddr,
    /// SSID of the network.
    pub ssid: Ssid,
    /// Operating channel.
    pub channel: WlanChannel,
    /// RSSI in dBm (negative value).
    pub rssi_dbm: i8,
    /// Beacon interval in TUs (1 TU = 1024 µs).
    pub beacon_interval: u16,
    /// Supported capabilities (from beacon).
    pub capabilities: u16,
    /// Security (WPA/WPA2/open).
    pub security: SecurityMode,
}

/// Security mode of an AP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    /// Open (no encryption).
    Open,
    /// WEP (deprecated).
    Wep,
    /// WPA-TKIP.
    WpaTkip,
    /// WPA2-CCMP (AES).
    Wpa2Ccmp,
    /// WPA3-SAE.
    Wpa3Sae,
}

/// Station association state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssocState {
    /// Not associated.
    Disconnected,
    /// Scanning for networks.
    Scanning,
    /// Authenticating with an AP.
    Authenticating,
    /// Associating with an AP.
    Associating,
    /// Fully associated and connected.
    Associated,
}

/// Maximum number of BSS entries remembered from a scan.
const MAX_BSS_ENTRIES: usize = 64;

/// Maximum number of simultaneously tracked stations (AP mode).
const MAX_STATIONS: usize = 32;

/// 802.11 frame type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// Management frame.
    Management,
    /// Control frame.
    Control,
    /// Data frame.
    Data,
}

/// 802.11 management frame subtypes.
pub mod mgmt_subtype {
    pub const ASSOC_REQ: u8 = 0x00;
    pub const ASSOC_RESP: u8 = 0x01;
    pub const REASSOC_REQ: u8 = 0x02;
    pub const REASSOC_RESP: u8 = 0x03;
    pub const PROBE_REQ: u8 = 0x04;
    pub const PROBE_RESP: u8 = 0x05;
    pub const BEACON: u8 = 0x08;
    pub const DISASSOC: u8 = 0x0A;
    pub const AUTH: u8 = 0x0B;
    pub const DEAUTH: u8 = 0x0C;
    pub const ACTION: u8 = 0x0D;
}

/// 802.11 MAC frame header in `#[repr(C)]`.
#[repr(C)]
pub struct Dot11Header {
    /// Frame control (type, subtype, flags).
    pub frame_ctrl: u16,
    /// Duration / ID.
    pub duration: u16,
    /// Address 1 (receiver / BSSID).
    pub addr1: MacAddr,
    /// Address 2 (transmitter / SA).
    pub addr2: MacAddr,
    /// Address 3 (destination / BSSID).
    pub addr3: MacAddr,
    /// Sequence control.
    pub seq_ctrl: u16,
}

/// Frame control bits.
pub const FC_TYPE_MGMT: u16 = 0 << 2;
pub const FC_TYPE_CTRL: u16 = 1 << 2;
pub const FC_TYPE_DATA: u16 = 2 << 2;
pub const FC_TO_DS: u16 = 1 << 8;
pub const FC_FROM_DS: u16 = 1 << 9;
pub const FC_MORE_FRAG: u16 = 1 << 10;
pub const FC_RETRY: u16 = 1 << 11;
pub const FC_POWER_MGMT: u16 = 1 << 12;
pub const FC_MORE_DATA: u16 = 1 << 13;
pub const FC_PROTECTED: u16 = 1 << 14;
pub const FC_HTC_ORDER: u16 = 1 << 15;

/// WLAN core driver state.
pub struct WlanCore {
    /// Local MAC address.
    local_mac: MacAddr,
    /// Current operating mode.
    mode: OperMode,
    /// Current association state.
    assoc_state: AssocState,
    /// Currently associated BSS (valid in Associated state).
    current_bss: Option<BssDesc>,
    /// Cached scan results.
    bss_list: [Option<BssDesc>; MAX_BSS_ENTRIES],
    /// Number of BSS entries in bss_list.
    bss_count: usize,
    /// Sequence number counter for transmitted frames.
    seq_num: u16,
    /// Channel the radio is currently tuned to.
    current_channel: Option<WlanChannel>,
}

impl WlanCore {
    /// Create a new WLAN core driver.
    pub fn new(local_mac: MacAddr) -> Self {
        Self {
            local_mac,
            mode: OperMode::Station,
            assoc_state: AssocState::Disconnected,
            current_bss: None,
            bss_list: [const { None }; MAX_BSS_ENTRIES],
            bss_count: 0,
            seq_num: 0,
            current_channel: None,
        }
    }

    /// Set the operating mode.
    pub fn set_mode(&mut self, mode: OperMode) -> Result<()> {
        if self.assoc_state == AssocState::Associated {
            return Err(Error::Busy);
        }
        self.mode = mode;
        Ok(())
    }

    /// Begin a scan (transitions to Scanning state).
    pub fn start_scan(&mut self) -> Result<()> {
        if self.mode != OperMode::Station && self.mode != OperMode::Monitor {
            return Err(Error::InvalidArgument);
        }
        self.bss_count = 0;
        for entry in self.bss_list.iter_mut() {
            *entry = None;
        }
        self.assoc_state = AssocState::Scanning;
        Ok(())
    }

    /// Record a BSS found during a scan.
    pub fn add_bss(&mut self, bss: BssDesc) -> Result<()> {
        if self.bss_count >= MAX_BSS_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Update existing entry if same BSSID.
        for entry in self.bss_list[..self.bss_count].iter_mut() {
            if let Some(existing) = entry {
                if existing.bssid == bss.bssid {
                    *existing = bss;
                    return Ok(());
                }
            }
        }
        self.bss_list[self.bss_count] = Some(bss);
        self.bss_count += 1;
        Ok(())
    }

    /// Initiate association with the BSS having the given BSSID.
    pub fn connect(&mut self, bssid: MacAddr) -> Result<()> {
        if self.mode != OperMode::Station {
            return Err(Error::InvalidArgument);
        }
        let bss = self.find_bss(bssid).ok_or(Error::NotFound)?;
        self.current_bss = Some(bss);
        self.assoc_state = AssocState::Authenticating;
        Ok(())
    }

    /// Mark the association as complete.
    pub fn assoc_complete(&mut self) -> Result<()> {
        self.assoc_state = AssocState::Associated;
        Ok(())
    }

    /// Disconnect from the current AP.
    pub fn disconnect(&mut self) {
        self.current_bss = None;
        self.assoc_state = AssocState::Disconnected;
    }

    /// Build an 802.11 management frame header.
    pub fn build_mgmt_header(
        &mut self,
        subtype: u8,
        addr1: MacAddr,
        addr3: MacAddr,
    ) -> Dot11Header {
        let frame_ctrl = FC_TYPE_MGMT | ((subtype as u16) << 4);
        let seq = self.seq_num;
        self.seq_num = self.seq_num.wrapping_add(1);
        Dot11Header {
            frame_ctrl,
            duration: 0,
            addr1,
            addr2: self.local_mac,
            addr3,
            seq_ctrl: seq << 4,
        }
    }

    /// Return the current association state.
    pub fn assoc_state(&self) -> AssocState {
        self.assoc_state
    }

    /// Return the current BSS descriptor (if associated).
    pub fn current_bss(&self) -> Option<&BssDesc> {
        self.current_bss.as_ref()
    }

    /// Return the number of BSS entries from the last scan.
    pub fn bss_count(&self) -> usize {
        self.bss_count
    }

    /// Look up a BSS entry by BSSID.
    fn find_bss(&self, bssid: MacAddr) -> Option<BssDesc> {
        for entry in &self.bss_list[..self.bss_count] {
            if let Some(bss) = entry {
                if bss.bssid == bssid {
                    return Some(*bss);
                }
            }
        }
        None
    }

    /// Return the local MAC address.
    pub fn local_mac(&self) -> MacAddr {
        self.local_mac
    }
}
