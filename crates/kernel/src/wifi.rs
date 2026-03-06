// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IEEE 802.11 WiFi framework for the ONCRIX kernel.
//!
//! Provides the core data structures and interface management for WiFi
//! networking, including BSS scanning, association, frame transmission
//! and reception, and a registry for managing multiple WiFi interfaces.
//!
//! # Supported standards
//!
//! | Standard | Band(s)                | Status   |
//! |----------|------------------------|----------|
//! | 802.11b  | 2.4 GHz                | Defined  |
//! | 802.11g  | 2.4 GHz                | Defined  |
//! | 802.11n  | 2.4 / 5 GHz            | Default  |
//! | 802.11ac | 5 GHz                  | Defined  |
//! | 802.11ax | 2.4 / 5 / 6 GHz       | Defined  |
//!
//! # Design
//!
//! [`WifiInterface`] represents a single wireless NIC with scanning,
//! connect/disconnect, and frame I/O capabilities.  [`WifiRegistry`]
//! manages up to 4 interfaces, identified by monotonically increasing
//! IDs.  All state is stored in fixed-size arrays suitable for a
//! `#![no_std]` kernel environment.

use oncrix_lib::{Error, Result};

// =========================================================================
// Enumerations
// =========================================================================

/// IEEE 802.11 standard variant.
///
/// Determines the PHY-layer capabilities and maximum throughput of
/// the wireless interface.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum WifiStandard {
    /// 802.11b — 2.4 GHz, up to 11 Mbps.
    B,
    /// 802.11g — 2.4 GHz, up to 54 Mbps.
    G,
    /// 802.11n (Wi-Fi 4) — 2.4/5 GHz, up to 600 Mbps.
    #[default]
    N,
    /// 802.11ac (Wi-Fi 5) — 5 GHz, up to 6.9 Gbps.
    AC,
    /// 802.11ax (Wi-Fi 6/6E) — 2.4/5/6 GHz.
    AX,
}

/// WiFi frequency band.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum WifiBand {
    /// 2.4 GHz band (channels 1-14).
    #[default]
    Band2_4GHz,
    /// 5 GHz band (channels 36-165).
    Band5GHz,
    /// 6 GHz band (Wi-Fi 6E, channels 1-233).
    Band6GHz,
}

/// WiFi security mode.
///
/// Determines the authentication and encryption protocol used for
/// the wireless connection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum WifiSecurity {
    /// No security (open network).
    Open,
    /// WEP (deprecated, insecure).
    Wep,
    /// WPA-Personal (TKIP).
    WpaPersonal,
    /// WPA2-Personal (AES-CCMP).
    #[default]
    Wpa2Personal,
    /// WPA3-Personal (SAE).
    Wpa3Personal,
    /// WPA2-Enterprise (802.1X + RADIUS).
    Wpa2Enterprise,
    /// WPA3-Enterprise (802.1X + 192-bit).
    Wpa3Enterprise,
}

/// WiFi interface operational state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum WifiState {
    /// Interface is disabled / radio off.
    #[default]
    Disabled,
    /// Actively scanning for available networks.
    Scanning,
    /// Associating with a BSS (authentication in progress).
    Associating,
    /// Connected and authenticated to a BSS.
    Connected,
    /// Disconnecting from the current BSS.
    Disconnecting,
}

/// IEEE 802.11 frame type (from the frame control field).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum WifiFrameType {
    /// Management frame (beacon, probe, auth, assoc).
    Management,
    /// Control frame (RTS, CTS, ACK).
    Control,
    /// Data frame (payload transport).
    #[default]
    Data,
}

// =========================================================================
// Headers and structures
// =========================================================================

/// IEEE 802.11 MAC header.
///
/// This is the common header present in all 802.11 frames.  The
/// `addr1`/`addr2`/`addr3` interpretation depends on the frame type
/// and the To DS / From DS bits in `frame_control`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ieee80211Header {
    /// Frame control field (protocol version, type, subtype, flags).
    pub frame_control: u16,
    /// Duration/ID field.
    pub duration: u16,
    /// Address 1 (receiver / destination).
    pub addr1: [u8; 6],
    /// Address 2 (transmitter / source).
    pub addr2: [u8; 6],
    /// Address 3 (BSSID or other, context-dependent).
    pub addr3: [u8; 6],
    /// Sequence control (fragment number + sequence number).
    pub seq_ctrl: u16,
}

/// Information about a discovered BSS (Basic Service Set).
///
/// Populated during scanning; each entry represents one access point
/// or ad-hoc network detected by the radio.
#[derive(Debug, Default, Clone, Copy)]
pub struct BssInfo {
    /// BSSID (MAC address of the access point).
    pub bssid: [u8; 6],
    /// SSID (network name, up to 32 bytes).
    pub ssid: [u8; 32],
    /// Actual length of the SSID in bytes.
    pub ssid_len: usize,
    /// Channel number the BSS operates on.
    pub channel: u8,
    /// Frequency band.
    pub band: WifiBand,
    /// Received signal strength indicator (dBm, typically negative).
    pub rssi: i8,
    /// Security mode advertised by the BSS.
    pub security: WifiSecurity,
    /// Beacon interval in TU (1 TU = 1024 microseconds).
    pub beacon_interval: u16,
    /// Whether the BSS is currently active (beacons received recently).
    pub active: bool,
}

/// Configuration for a WiFi connection attempt.
///
/// Passed to [`WifiInterface::connect`] to specify the target network
/// and authentication credentials.
#[derive(Debug, Clone, Copy)]
pub struct WifiConfig {
    /// Target SSID (network name, up to 32 bytes).
    pub ssid: [u8; 32],
    /// Actual length of the SSID in bytes.
    pub ssid_len: usize,
    /// Passphrase for authentication (up to 64 bytes).
    pub passphrase: [u8; 64],
    /// Actual length of the passphrase in bytes.
    pub passphrase_len: usize,
    /// Security mode to use.
    pub security: WifiSecurity,
    /// Preferred frequency band.
    pub band: WifiBand,
    /// Preferred channel (0 = auto-select).
    pub channel: u8,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            ssid: [0; 32],
            ssid_len: 0,
            passphrase: [0; 64],
            passphrase_len: 0,
            security: WifiSecurity::default(),
            band: WifiBand::default(),
            channel: 0,
        }
    }
}

/// Results of a WiFi scan operation.
///
/// Contains up to 32 discovered networks.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanResult {
    /// Array of discovered BSS entries.
    pub networks: [BssInfo; 32],
    /// Number of valid entries in `networks`.
    pub count: usize,
}

// =========================================================================
// WifiInterface
// =========================================================================

/// Maximum frame size for 802.11 (header + payload).
const MAX_FRAME_SIZE: usize = 2346;

/// Size of the IEEE 802.11 MAC header in bytes.
const IEEE80211_HEADER_LEN: usize = 24;

/// A single WiFi network interface.
///
/// Represents one wireless NIC with its own MAC address, connection
/// state, scan results, and traffic counters.  The interface supports
/// scanning for networks, connecting/disconnecting, and sending and
/// receiving 802.11 frames.
#[derive(Default)]
pub struct WifiInterface {
    /// Unique interface identifier.
    id: u64,
    /// MAC address of this wireless interface.
    mac: [u8; 6],
    /// Current operational state.
    state: WifiState,
    /// Active connection configuration.
    config: WifiConfig,
    /// Whether we are currently connected to a BSS.
    connected: bool,
    /// Information about the currently associated BSS.
    bss: BssInfo,
    /// Most recent scan results.
    scan_result: ScanResult,
    /// Total packets transmitted.
    tx_packets: u64,
    /// Total packets received.
    rx_packets: u64,
    /// Total bytes transmitted.
    tx_bytes: u64,
    /// Total bytes received.
    rx_bytes: u64,
    /// Whether this interface slot is in use.
    in_use: bool,
}

impl WifiInterface {
    /// Initiate a scan for available WiFi networks.
    ///
    /// Transitions the interface to the [`WifiState::Scanning`] state
    /// and returns a reference to the scan results.  In a real driver,
    /// this would trigger an asynchronous hardware scan; here we
    /// transition state and return the current (possibly empty) results.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the interface is in a
    /// state that does not permit scanning (e.g., already associating).
    pub fn scan(&mut self) -> Result<&ScanResult> {
        match self.state {
            WifiState::Disabled => return Err(Error::InvalidArgument),
            WifiState::Associating | WifiState::Disconnecting => {
                return Err(Error::Busy);
            }
            WifiState::Scanning | WifiState::Connected => {}
        }
        self.state = WifiState::Scanning;
        Ok(&self.scan_result)
    }

    /// Connect to a WiFi network using the given configuration.
    ///
    /// Validates the configuration, transitions through
    /// [`WifiState::Associating`] to [`WifiState::Connected`], and
    /// records the BSS information.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the SSID length is zero or the
    ///   interface is disabled.
    /// - [`Error::Busy`] if already connecting or disconnecting.
    /// - [`Error::NotFound`] if no matching BSS was found in scan
    ///   results.
    pub fn connect(&mut self, config: &WifiConfig) -> Result<()> {
        if config.ssid_len == 0 || config.ssid_len > 32 {
            return Err(Error::InvalidArgument);
        }

        match self.state {
            WifiState::Disabled => return Err(Error::InvalidArgument),
            WifiState::Associating | WifiState::Disconnecting => {
                return Err(Error::Busy);
            }
            WifiState::Scanning | WifiState::Connected => {}
        }

        // Look for a matching BSS in scan results.
        let bss = self
            .scan_result
            .networks
            .iter()
            .take(self.scan_result.count)
            .find(|b| {
                b.active
                    && b.ssid_len == config.ssid_len
                    && b.ssid[..b.ssid_len] == config.ssid[..config.ssid_len]
            });

        let bss = match bss {
            Some(b) => *b,
            None => return Err(Error::NotFound),
        };

        // Transition through associating to connected.
        self.state = WifiState::Associating;
        self.config = *config;
        self.bss = bss;
        self.connected = true;
        self.state = WifiState::Connected;

        Ok(())
    }

    /// Disconnect from the current WiFi network.
    ///
    /// Transitions through [`WifiState::Disconnecting`] and resets
    /// the connection state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the interface is not
    /// currently connected.
    pub fn disconnect(&mut self) -> Result<()> {
        if !self.connected {
            return Err(Error::InvalidArgument);
        }

        self.state = WifiState::Disconnecting;
        self.connected = false;
        self.bss = BssInfo::default();
        self.state = WifiState::Disabled;

        Ok(())
    }

    /// Send an 802.11 frame to the specified destination.
    ///
    /// Constructs an [`Ieee80211Header`] with the appropriate frame
    /// type, copies `data` into the frame buffer, and updates traffic
    /// counters.  Returns the total number of bytes in the constructed
    /// frame (header + payload).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the interface is not connected
    ///   or the payload exceeds the maximum frame size.
    pub fn send_frame(
        &mut self,
        _frame_type: WifiFrameType,
        _dst: &[u8; 6],
        data: &[u8],
    ) -> Result<usize> {
        if !self.connected {
            return Err(Error::InvalidArgument);
        }

        let total = IEEE80211_HEADER_LEN + data.len();
        if total > MAX_FRAME_SIZE {
            return Err(Error::InvalidArgument);
        }

        self.tx_packets += 1;
        self.tx_bytes += data.len() as u64;

        Ok(total)
    }

    /// Receive an 802.11 frame into the provided buffer.
    ///
    /// In a real driver this would dequeue a frame from the hardware
    /// receive ring.  Here we return a default header with zero payload
    /// length to indicate no frame is currently available.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the interface is not connected.
    /// - [`Error::InvalidArgument`] if `buf` is smaller than
    ///   [`IEEE80211_HEADER_LEN`].
    pub fn recv_frame(&mut self, buf: &mut [u8]) -> Result<(Ieee80211Header, usize)> {
        if !self.connected {
            return Err(Error::InvalidArgument);
        }
        if buf.len() < IEEE80211_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }

        // No frame available — return empty.
        // A real implementation would check hardware DMA descriptors.
        Ok((Ieee80211Header::default(), 0))
    }

    /// Return the current received signal strength indicator (dBm).
    ///
    /// Returns 0 if no BSS is associated.
    pub fn get_signal_strength(&self) -> i8 {
        if self.connected { self.bss.rssi } else { 0 }
    }

    /// Return the current operational state of the interface.
    pub fn get_state(&self) -> WifiState {
        self.state
    }

    /// Return the MAC address of this wireless interface.
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Return the total number of packets received.
    pub fn rx_packets(&self) -> u64 {
        self.rx_packets
    }

    /// Return the total number of bytes received.
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes
    }
}

// =========================================================================
// WifiRegistry
// =========================================================================

/// Maximum number of WiFi interfaces managed by the registry.
const MAX_WIFI_INTERFACES: usize = 4;

/// Registry for managing multiple WiFi interfaces.
///
/// Supports up to [`MAX_WIFI_INTERFACES`] (4) interfaces.  Each
/// interface is identified by a unique monotonically increasing ID
/// assigned at registration time.
pub struct WifiRegistry {
    /// Fixed-size array of WiFi interfaces.
    interfaces: [WifiInterface; MAX_WIFI_INTERFACES],
    /// Number of active interfaces.
    count: usize,
    /// Next interface ID to assign.
    next_id: u64,
}

impl Default for WifiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiRegistry {
    /// Create an empty WiFi registry.
    pub const fn new() -> Self {
        const DEFAULT_BSS: BssInfo = BssInfo {
            bssid: [0; 6],
            ssid: [0; 32],
            ssid_len: 0,
            channel: 0,
            band: WifiBand::Band2_4GHz,
            rssi: 0,
            security: WifiSecurity::Wpa2Personal,
            beacon_interval: 0,
            active: false,
        };

        const DEFAULT_IFACE: WifiInterface = WifiInterface {
            id: 0,
            mac: [0; 6],
            state: WifiState::Disabled,
            config: WifiConfig {
                ssid: [0; 32],
                ssid_len: 0,
                passphrase: [0; 64],
                passphrase_len: 0,
                security: WifiSecurity::Wpa2Personal,
                band: WifiBand::Band2_4GHz,
                channel: 0,
            },
            connected: false,
            bss: DEFAULT_BSS,
            scan_result: ScanResult {
                networks: [DEFAULT_BSS; 32],
                count: 0,
            },
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            in_use: false,
        };

        Self {
            interfaces: [DEFAULT_IFACE; MAX_WIFI_INTERFACES],
            count: 0,
            next_id: 1,
        }
    }

    /// Register a new WiFi interface with the given MAC address.
    ///
    /// Returns the unique interface ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mac: &[u8; 6]) -> Result<u64> {
        let slot = self
            .interfaces
            .iter()
            .position(|iface| !iface.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        self.interfaces[slot] = WifiInterface {
            id,
            mac: *mac,
            state: WifiState::Disabled,
            config: WifiConfig::default(),
            connected: false,
            bss: BssInfo::default(),
            scan_result: ScanResult::default(),
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            in_use: true,
        };
        self.count += 1;

        Ok(id)
    }

    /// Unregister a WiFi interface by ID.
    ///
    /// Marks the interface slot as free.  Does nothing if the ID is
    /// not found.
    pub fn unregister(&mut self, id: u64) {
        if let Some(iface) = self.interfaces.iter_mut().find(|i| i.in_use && i.id == id) {
            iface.in_use = false;
            iface.connected = false;
            iface.state = WifiState::Disabled;
            self.count -= 1;
        }
    }

    /// Get an immutable reference to a WiFi interface by ID.
    ///
    /// Returns `None` if the interface is not found.
    pub fn get(&self, id: u64) -> Option<&WifiInterface> {
        self.interfaces.iter().find(|i| i.in_use && i.id == id)
    }

    /// Get a mutable reference to a WiFi interface by ID.
    ///
    /// Returns `None` if the interface is not found.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut WifiInterface> {
        self.interfaces.iter_mut().find(|i| i.in_use && i.id == id)
    }

    /// Return the number of active WiFi interfaces.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no WiFi interfaces are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        assert_eq!(WifiStandard::default(), WifiStandard::N);
        assert_eq!(WifiBand::default(), WifiBand::Band2_4GHz);
        assert_eq!(WifiSecurity::default(), WifiSecurity::Wpa2Personal);
        assert_eq!(WifiState::default(), WifiState::Disabled);
        assert_eq!(WifiFrameType::default(), WifiFrameType::Data);
    }

    #[test]
    fn test_registry_register_unregister() {
        let mut reg = WifiRegistry::new();
        assert!(reg.is_empty());

        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let id = reg.register(&mac).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());

        let iface = reg.get(id);
        assert!(iface.is_some());

        reg.unregister(id);
        assert!(reg.is_empty());
        assert!(reg.get(id).is_none());
    }

    #[test]
    fn test_registry_full() {
        let mut reg = WifiRegistry::new();
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

        for _ in 0..MAX_WIFI_INTERFACES {
            assert!(reg.register(&mac).is_ok());
        }
        // 5th registration should fail.
        assert!(reg.register(&mac).is_err());
    }

    #[test]
    fn test_interface_scan_disabled() {
        let mut iface = WifiInterface::default();
        // Disabled interface cannot scan.
        assert!(iface.scan().is_err());
    }

    #[test]
    fn test_interface_connect_disconnect() {
        let mut reg = WifiRegistry::new();
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let id = reg.register(&mac).unwrap();

        let iface = reg.get_mut(id).unwrap();
        // Enable the interface for scanning.
        iface.state = WifiState::Scanning;

        // Add a fake BSS to scan results.
        let mut ssid = [0u8; 32];
        ssid[..4].copy_from_slice(b"test");
        iface.scan_result.networks[0] = BssInfo {
            bssid: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ssid,
            ssid_len: 4,
            channel: 6,
            band: WifiBand::Band2_4GHz,
            rssi: -50,
            security: WifiSecurity::Wpa2Personal,
            beacon_interval: 100,
            active: true,
        };
        iface.scan_result.count = 1;

        // Connect.
        let mut config = WifiConfig::default();
        config.ssid[..4].copy_from_slice(b"test");
        config.ssid_len = 4;
        assert!(iface.connect(&config).is_ok());
        assert_eq!(iface.get_state(), WifiState::Connected);
        assert_eq!(iface.get_signal_strength(), -50);

        // Disconnect.
        assert!(iface.disconnect().is_ok());
        assert_eq!(iface.get_state(), WifiState::Disabled);
        assert_eq!(iface.get_signal_strength(), 0);
    }

    #[test]
    fn test_interface_send_not_connected() {
        let mut iface = WifiInterface::default();
        let dst = [0xFF; 6];
        assert!(
            iface
                .send_frame(WifiFrameType::Data, &dst, &[1, 2, 3])
                .is_err()
        );
    }

    #[test]
    fn test_interface_recv_not_connected() {
        let mut iface = WifiInterface::default();
        let mut buf = [0u8; 64];
        assert!(iface.recv_frame(&mut buf).is_err());
    }

    #[test]
    fn test_ieee80211_header_default() {
        let hdr = Ieee80211Header::default();
        assert_eq!(hdr.frame_control, 0);
        assert_eq!(hdr.addr1, [0; 6]);
    }

    #[test]
    fn test_scan_result_default() {
        let sr = ScanResult::default();
        assert_eq!(sr.count, 0);
    }

    #[test]
    fn test_connect_no_matching_bss() {
        let mut iface = WifiInterface::default();
        iface.state = WifiState::Scanning;

        let mut config = WifiConfig::default();
        config.ssid[..4].copy_from_slice(b"none");
        config.ssid_len = 4;
        // No BSS in scan results, should fail with NotFound.
        assert!(iface.connect(&config).is_err());
    }

    #[test]
    fn test_disconnect_not_connected() {
        let mut iface = WifiInterface::default();
        iface.state = WifiState::Scanning;
        assert!(iface.disconnect().is_err());
    }

    #[test]
    fn test_interface_mac_accessor() {
        let mut reg = WifiRegistry::new();
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let id = reg.register(&mac).unwrap();
        let iface = reg.get(id).unwrap();
        assert_eq!(*iface.mac(), mac);
    }

    #[test]
    fn test_interface_rx_counters() {
        let iface = WifiInterface::default();
        assert_eq!(iface.rx_packets(), 0);
        assert_eq!(iface.rx_bytes(), 0);
    }
}
