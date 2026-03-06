// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network polling for emergency console and crash dump transport.
//!
//! Provides a minimal, polling-mode network I/O path that bypasses
//! the normal interrupt-driven network stack. This is used for:
//!
//! - **Emergency console** (`netconsole`): sending kernel log
//!   messages to a remote host when the system is in a degraded
//!   state (panic, watchdog, etc.).
//! - **Crash dump transport**: shipping crash dumps to a
//!   collection server when kdump cannot write to local storage.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    NetpollSubsystem                           │
//! │                                                              │
//! │  NetpollDevice[0..MAX_NETPOLL_DEVICES]                       │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  NetpollTarget: name, IPs, ports, MAC                  │  │
//! │  │  NetpollState: Disabled → Setup → Running → Error      │  │
//! │  │  tx_buffer [u8; MTU], rx_buffer [u8; MTU]              │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  NetpollStats (global counters)                              │
//! │  - packets_sent, packets_received, errors, retries           │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Polling Model
//!
//! All I/O is synchronous and polling-based (no IRQs). The caller
//! repeatedly calls `poll_rx()` to check for incoming data and
//! `send_udp()` to transmit. This is intentionally simple to
//! minimize the amount of code that must work during a crash.
//!
//! # Reference
//!
//! Linux `net/core/netpoll.c`, `drivers/net/netconsole.c`,
//! `include/linux/netpoll.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum netpoll devices.
const MAX_NETPOLL_DEVICES: usize = 4;

/// Maximum MTU for netpoll buffers.
const NETPOLL_MTU: usize = 1500;

/// Target name buffer length.
const TARGET_NAME_LEN: usize = 32;

/// MAC address length.
const MAC_LEN: usize = 6;

/// UDP header size.
const UDP_HEADER_SIZE: usize = 8;

/// IP header size (no options).
const IP_HEADER_SIZE: usize = 20;

/// Ethernet header size.
const ETH_HEADER_SIZE: usize = 14;

/// Total overhead for UDP-over-Ethernet.
const TOTAL_OVERHEAD: usize = ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;

/// Maximum payload per netpoll UDP packet.
const MAX_PAYLOAD: usize = NETPOLL_MTU - TOTAL_OVERHEAD;

/// Maximum retry count for send operations.
const MAX_SEND_RETRIES: u32 = 3;

/// Netconsole message prefix.
const NETCONSOLE_PREFIX: &[u8] = b"[netconsole] ";

/// Maximum netconsole message length (fits in one UDP packet).
const NETCONSOLE_MAX_MSG: usize = MAX_PAYLOAD - 14; // prefix len

// ══════════════════════════════════════════════════════════════
// NetpollState
// ══════════════════════════════════════════════════════════════

/// State of a netpoll device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetpollState {
    /// Device is disabled / not configured.
    Disabled = 0,
    /// Configuration applied, waiting for link.
    Setup = 1,
    /// Device is active and ready for I/O.
    Running = 2,
    /// Device encountered an unrecoverable error.
    Error = 3,
}

impl NetpollState {
    /// Convert from raw u8.
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Setup),
            2 => Ok(Self::Running),
            3 => Ok(Self::Error),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NetpollTarget
// ══════════════════════════════════════════════════════════════

/// Configuration for a netpoll target endpoint.
///
/// Specifies the local/remote IP addresses, ports, and the
/// remote MAC address for ARP-less direct transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NetpollTarget {
    /// Human-readable name for this target.
    pub name: [u8; TARGET_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Local IPv4 address (host byte order).
    pub local_ip: u32,
    /// Remote IPv4 address (host byte order).
    pub remote_ip: u32,
    /// Local UDP port.
    pub local_port: u16,
    /// Remote UDP port.
    pub remote_port: u16,
    /// Remote MAC address for direct Ethernet framing.
    pub remote_mac: [u8; MAC_LEN],
    /// Interface index to bind to.
    pub ifindex: u32,
}

impl NetpollTarget {
    /// Create an empty target.
    pub const fn new() -> Self {
        Self {
            name: [0u8; TARGET_NAME_LEN],
            name_len: 0,
            local_ip: 0,
            remote_ip: 0,
            local_port: 0,
            remote_port: 0,
            remote_mac: [0u8; MAC_LEN],
            ifindex: 0,
        }
    }

    /// Set the target name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(TARGET_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Configure IP addresses and ports.
    pub fn configure(&mut self, local_ip: u32, remote_ip: u32, local_port: u16, remote_port: u16) {
        self.local_ip = local_ip;
        self.remote_ip = remote_ip;
        self.local_port = local_port;
        self.remote_port = remote_port;
    }

    /// Set the remote MAC address.
    pub fn set_remote_mac(&mut self, mac: &[u8; MAC_LEN]) {
        self.remote_mac = *mac;
    }

    /// Validate target configuration.
    pub fn validate(&self) -> Result<()> {
        if self.local_ip == 0 || self.remote_ip == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.remote_port == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// NetpollTxPacket / NetpollRxPacket
// ══════════════════════════════════════════════════════════════

/// A transmit packet assembled in the netpoll TX buffer.
#[derive(Debug, Clone, Copy)]
pub struct NetpollTxPacket {
    /// Packet data (Ethernet + IP + UDP + payload).
    pub data: [u8; NETPOLL_MTU],
    /// Total packet length in bytes.
    pub len: usize,
}

impl NetpollTxPacket {
    /// Create an empty TX packet.
    pub const fn new() -> Self {
        Self {
            data: [0u8; NETPOLL_MTU],
            len: 0,
        }
    }
}

/// A received packet from the netpoll RX buffer.
#[derive(Debug, Clone, Copy)]
pub struct NetpollRxPacket {
    /// Packet data.
    pub data: [u8; NETPOLL_MTU],
    /// Total packet length in bytes.
    pub len: usize,
    /// Source IPv4 address.
    pub src_ip: u32,
    /// Source port.
    pub src_port: u16,
}

impl NetpollRxPacket {
    /// Create an empty RX packet.
    pub const fn new() -> Self {
        Self {
            data: [0u8; NETPOLL_MTU],
            len: 0,
            src_ip: 0,
            src_port: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NetpollDevice
// ══════════════════════════════════════════════════════════════

/// A single netpoll device with TX/RX buffers.
///
/// Represents a network interface configured for polling-mode
/// emergency I/O. Each device has its own target configuration
/// and independent buffer state.
pub struct NetpollDevice {
    /// Target endpoint configuration.
    pub target: NetpollTarget,
    /// Current device state.
    pub state: NetpollState,
    /// Transmit buffer.
    tx_buffer: [u8; NETPOLL_MTU],
    /// TX buffer used length.
    tx_len: usize,
    /// Receive buffer.
    rx_buffer: [u8; NETPOLL_MTU],
    /// RX buffer used length.
    rx_len: usize,
    /// Sequence number for netconsole messages.
    seq: u64,
    /// Number of packets sent through this device.
    packets_sent: u64,
    /// Number of packets received through this device.
    packets_received: u64,
    /// Number of send errors.
    send_errors: u64,
    /// Number of retries.
    retries: u64,
}

impl NetpollDevice {
    /// Create a new disabled netpoll device.
    pub const fn new() -> Self {
        Self {
            target: NetpollTarget::new(),
            state: NetpollState::Disabled,
            tx_buffer: [0u8; NETPOLL_MTU],
            tx_len: 0,
            rx_buffer: [0u8; NETPOLL_MTU],
            rx_len: 0,
            seq: 0,
            packets_sent: 0,
            packets_received: 0,
            send_errors: 0,
            retries: 0,
        }
    }

    /// Set up the device with a target configuration.
    pub fn setup(&mut self, target: NetpollTarget) -> Result<()> {
        target.validate()?;
        if self.state == NetpollState::Running {
            return Err(Error::Busy);
        }
        self.target = target;
        self.state = NetpollState::Setup;
        self.seq = 0;
        self.tx_len = 0;
        self.rx_len = 0;
        Ok(())
    }

    /// Activate the device (transition from Setup to Running).
    pub fn activate(&mut self) -> Result<()> {
        if self.state != NetpollState::Setup {
            return Err(Error::InvalidArgument);
        }
        self.state = NetpollState::Running;
        Ok(())
    }

    /// Tear down the device, returning it to Disabled state.
    pub fn teardown(&mut self) {
        self.state = NetpollState::Disabled;
        self.tx_len = 0;
        self.rx_len = 0;
        self.target = NetpollTarget::new();
    }

    /// Build and "send" a UDP packet (stub — fills TX buffer).
    ///
    /// Constructs an Ethernet + IP + UDP frame in the TX buffer.
    /// In a real implementation this would write to the NIC's
    /// transmit ring via polling.
    pub fn send_udp(&mut self, payload: &[u8]) -> Result<usize> {
        if self.state != NetpollState::Running {
            return Err(Error::InvalidArgument);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }

        let total_len = TOTAL_OVERHEAD + payload.len();
        self.tx_buffer = [0u8; NETPOLL_MTU];

        // Build Ethernet header (stub: just set MAC and ethertype)
        self.tx_buffer[..MAC_LEN].copy_from_slice(&self.target.remote_mac);
        // Source MAC = 00:00:00:00:00:00 (placeholder)
        // EtherType = 0x0800 (IPv4)
        self.tx_buffer[12] = 0x08;
        self.tx_buffer[13] = 0x00;

        // Build IP header (stub: version, length, protocol)
        let ip_start = ETH_HEADER_SIZE;
        self.tx_buffer[ip_start] = 0x45; // version 4, IHL 5
        let ip_total = (IP_HEADER_SIZE + UDP_HEADER_SIZE + payload.len()) as u16;
        self.tx_buffer[ip_start + 2] = (ip_total >> 8) as u8;
        self.tx_buffer[ip_start + 3] = ip_total as u8;
        self.tx_buffer[ip_start + 9] = 17; // UDP protocol

        // Source IP
        let src_ip = self.target.local_ip;
        self.tx_buffer[ip_start + 12] = (src_ip >> 24) as u8;
        self.tx_buffer[ip_start + 13] = (src_ip >> 16) as u8;
        self.tx_buffer[ip_start + 14] = (src_ip >> 8) as u8;
        self.tx_buffer[ip_start + 15] = src_ip as u8;

        // Dest IP
        let dst_ip = self.target.remote_ip;
        self.tx_buffer[ip_start + 16] = (dst_ip >> 24) as u8;
        self.tx_buffer[ip_start + 17] = (dst_ip >> 16) as u8;
        self.tx_buffer[ip_start + 18] = (dst_ip >> 8) as u8;
        self.tx_buffer[ip_start + 19] = dst_ip as u8;

        // Build UDP header
        let udp_start = ip_start + IP_HEADER_SIZE;
        let sp = self.target.local_port;
        self.tx_buffer[udp_start] = (sp >> 8) as u8;
        self.tx_buffer[udp_start + 1] = sp as u8;
        let dp = self.target.remote_port;
        self.tx_buffer[udp_start + 2] = (dp >> 8) as u8;
        self.tx_buffer[udp_start + 3] = dp as u8;
        let udp_len = (UDP_HEADER_SIZE + payload.len()) as u16;
        self.tx_buffer[udp_start + 4] = (udp_len >> 8) as u8;
        self.tx_buffer[udp_start + 5] = udp_len as u8;

        // Payload
        let payload_start = udp_start + UDP_HEADER_SIZE;
        self.tx_buffer[payload_start..payload_start + payload.len()].copy_from_slice(payload);

        self.tx_len = total_len;
        self.packets_sent += 1;
        self.seq += 1;

        Ok(payload.len())
    }

    /// Poll for a received packet (stub — returns WouldBlock).
    ///
    /// In a real implementation this would read from the NIC's
    /// receive ring. Currently always returns `WouldBlock` since
    /// there is no physical hardware to poll.
    pub fn poll_rx(&mut self) -> Result<NetpollRxPacket> {
        if self.state != NetpollState::Running {
            return Err(Error::InvalidArgument);
        }
        // Stub: no actual hardware to poll
        Err(Error::WouldBlock)
    }

    /// Simulate receiving a packet (for testing).
    pub fn inject_rx(&mut self, data: &[u8], src_ip: u32, src_port: u16) -> Result<()> {
        if data.len() > NETPOLL_MTU {
            return Err(Error::InvalidArgument);
        }
        self.rx_buffer = [0u8; NETPOLL_MTU];
        self.rx_buffer[..data.len()].copy_from_slice(data);
        self.rx_len = data.len();
        self.packets_received += 1;
        let _ = src_ip;
        let _ = src_port;
        Ok(())
    }

    /// Return the last transmitted packet data.
    pub fn last_tx(&self) -> &[u8] {
        &self.tx_buffer[..self.tx_len]
    }

    /// Return device statistics.
    pub fn device_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.packets_sent,
            self.packets_received,
            self.send_errors,
            self.retries,
        )
    }
}

// ══════════════════════════════════════════════════════════════
// NetpollStats
// ══════════════════════════════════════════════════════════════

/// Global netpoll subsystem statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetpollStats {
    /// Total packets sent across all devices.
    pub packets_sent: u64,
    /// Total packets received across all devices.
    pub packets_received: u64,
    /// Total errors across all devices.
    pub errors: u64,
    /// Total retries across all devices.
    pub retries: u64,
    /// Total netconsole messages sent.
    pub console_messages: u64,
    /// Total devices configured.
    pub devices_active: u32,
}

impl NetpollStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            errors: 0,
            retries: 0,
            console_messages: 0,
            devices_active: 0,
        }
    }

    /// Aggregate statistics from all devices.
    pub fn aggregate(devices: &[NetpollDevice; MAX_NETPOLL_DEVICES]) -> Self {
        let mut stats = Self::new();
        for dev in devices {
            let (sent, recv, errs, retries) = dev.device_stats();
            stats.packets_sent += sent;
            stats.packets_received += recv;
            stats.errors += errs;
            stats.retries += retries;
            if dev.state == NetpollState::Running {
                stats.devices_active += 1;
            }
        }
        stats
    }
}

// ══════════════════════════════════════════════════════════════
// NetpollSubsystem
// ══════════════════════════════════════════════════════════════

/// The top-level netpoll subsystem.
///
/// Manages multiple netpoll devices and provides the emergency
/// console (`netconsole_write`) interface.
pub struct NetpollSubsystem {
    /// Netpoll devices.
    devices: [NetpollDevice; MAX_NETPOLL_DEVICES],
    /// Global statistics.
    stats: NetpollStats,
    /// Whether the subsystem is initialized.
    initialized: bool,
}

impl NetpollSubsystem {
    /// Create a new netpoll subsystem.
    pub const fn new() -> Self {
        Self {
            devices: [const { NetpollDevice::new() }; MAX_NETPOLL_DEVICES],
            stats: NetpollStats::new(),
            initialized: false,
        }
    }

    /// Initialize the subsystem.
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Set up a netpoll device at the given index.
    pub fn setup(&mut self, dev_idx: usize, target: NetpollTarget) -> Result<()> {
        if dev_idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[dev_idx].setup(target)?;
        self.devices[dev_idx].activate()?;
        self.refresh_stats();
        Ok(())
    }

    /// Tear down a netpoll device.
    pub fn teardown(&mut self, dev_idx: usize) -> Result<()> {
        if dev_idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[dev_idx].teardown();
        self.refresh_stats();
        Ok(())
    }

    /// Send a UDP payload through a netpoll device.
    pub fn send_udp(&mut self, dev_idx: usize, payload: &[u8]) -> Result<usize> {
        if dev_idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        let result = self.devices[dev_idx].send_udp(payload);
        self.refresh_stats();
        result
    }

    /// Poll for received data on a device.
    pub fn poll_rx(&mut self, dev_idx: usize) -> Result<NetpollRxPacket> {
        if dev_idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[dev_idx].poll_rx()
    }

    /// Send an emergency console message.
    ///
    /// Prepends the `[netconsole]` prefix and sends the message
    /// as a UDP packet to the first running netpoll device.
    pub fn netconsole_write(&mut self, msg: &[u8]) -> Result<usize> {
        // Find first running device
        let dev_idx = self
            .devices
            .iter()
            .position(|d| d.state == NetpollState::Running)
            .ok_or(Error::NotFound)?;

        // Build prefixed message
        let prefix_len = NETCONSOLE_PREFIX.len();
        let msg_len = msg.len().min(NETCONSOLE_MAX_MSG);
        let total = prefix_len + msg_len;

        // Use a stack buffer for the prefixed message
        let mut buf = [0u8; MAX_PAYLOAD];
        buf[..prefix_len].copy_from_slice(NETCONSOLE_PREFIX);
        buf[prefix_len..prefix_len + msg_len].copy_from_slice(&msg[..msg_len]);

        let result = self.devices[dev_idx].send_udp(&buf[..total]);
        if result.is_ok() {
            self.stats.console_messages += 1;
        }
        self.refresh_stats();
        result
    }

    /// Return a reference to a device.
    pub fn device(&self, idx: usize) -> Result<&NetpollDevice> {
        if idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.devices[idx])
    }

    /// Return a mutable reference to a device.
    pub fn device_mut(&mut self, idx: usize) -> Result<&mut NetpollDevice> {
        if idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.devices[idx])
    }

    /// Return global statistics.
    pub fn stats(&self) -> &NetpollStats {
        &self.stats
    }

    /// Refresh aggregated stats from devices.
    fn refresh_stats(&mut self) {
        let mut new_stats = NetpollStats::aggregate(&self.devices);
        new_stats.console_messages = self.stats.console_messages;
        self.stats = new_stats;
    }

    /// Send a UDP packet with retries.
    pub fn send_udp_reliable(&mut self, dev_idx: usize, payload: &[u8]) -> Result<usize> {
        if dev_idx >= MAX_NETPOLL_DEVICES {
            return Err(Error::InvalidArgument);
        }
        let mut last_err = Error::IoError;
        for _ in 0..MAX_SEND_RETRIES {
            match self.devices[dev_idx].send_udp(payload) {
                Ok(n) => {
                    self.refresh_stats();
                    return Ok(n);
                }
                Err(e) => {
                    self.devices[dev_idx].retries += 1;
                    last_err = e;
                }
            }
        }
        self.refresh_stats();
        Err(last_err)
    }
}

/// Send a raw packet bypassing the normal network stack.
///
/// This is the lowest-level netpoll send path. The caller
/// provides a complete Ethernet frame.
pub fn netpoll_send_skb(
    subsystem: &mut NetpollSubsystem,
    dev_idx: usize,
    data: &[u8],
) -> Result<usize> {
    subsystem.send_udp(dev_idx, data)
}

/// Write an emergency console message over netpoll.
pub fn netconsole_write(subsystem: &mut NetpollSubsystem, msg: &[u8]) -> Result<usize> {
    subsystem.netconsole_write(msg)
}
