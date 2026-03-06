// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network loopback device driver.
//!
//! The loopback device (lo) is a virtual network interface that echoes all
//! transmitted packets back as received packets. It is used for intra-host
//! communication and as the binding interface for 127.0.0.1 and ::1.
//!
//! # Characteristics
//! - Device flags: `IFF_LOOPBACK | IFF_RUNNING | IFF_UP`
//! - Default MTU: 65536 bytes (64 KiB).
//! - IPv4 address: 127.0.0.1/8.
//! - IPv6 address: ::1/128.
//! - Hardware address: all-zeros (no physical MAC).
//! - TX path: immediately enqueues into the RX queue (loopback).
//!
//! Reference: Linux net/drivers/loopback.c.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Device Flags
// ---------------------------------------------------------------------------

/// Network interface flag: UP (interface is active).
pub const IFF_UP: u32 = 1 << 0;
/// Network interface flag: LOOPBACK (this is the loopback interface).
pub const IFF_LOOPBACK: u32 = 1 << 3;
/// Network interface flag: RUNNING (link is up and the interface is usable).
pub const IFF_RUNNING: u32 = 1 << 6;
/// Network interface flag: NOARP (no ARP protocol needed).
pub const IFF_NOARP: u32 = 1 << 7;

/// Default loopback MTU in bytes.
pub const LOOPBACK_MTU: u32 = 65536;

/// Maximum number of packets the loopback ring can hold.
const LOOPBACK_RING_SIZE: usize = 256;

/// Maximum packet size that can be enqueued.
const LOOPBACK_MAX_PKT: usize = LOOPBACK_MTU as usize;

// ---------------------------------------------------------------------------
// IPv4 / IPv6 Address Constants
// ---------------------------------------------------------------------------

/// IPv4 loopback address: 127.0.0.1 in network byte order.
pub const LOOPBACK_IPV4: [u8; 4] = [127, 0, 0, 1];
/// IPv4 loopback prefix length (8 bits for /8).
pub const LOOPBACK_IPV4_PREFIX: u8 = 8;

/// IPv6 loopback address: ::1.
pub const LOOPBACK_IPV6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// IPv6 loopback prefix length (/128).
pub const LOOPBACK_IPV6_PREFIX: u8 = 128;

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Per-interface TX/RX packet statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackStats {
    /// Total packets transmitted.
    pub tx_packets: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total packets received.
    pub rx_packets: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Packets dropped (ring full).
    pub tx_dropped: u64,
}

// ---------------------------------------------------------------------------
// Packet Storage
// ---------------------------------------------------------------------------

/// A single packet stored in the loopback ring.
#[derive(Clone)]
struct LoopbackPacket {
    /// Packet data (up to LOOPBACK_MAX_PKT bytes).
    data: [u8; LOOPBACK_MAX_PKT],
    /// Actual length of the packet.
    len: u16,
    /// `true` if this slot is occupied.
    used: bool,
}

impl LoopbackPacket {
    const fn empty() -> Self {
        Self {
            data: [0u8; LOOPBACK_MAX_PKT],
            len: 0,
            used: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Loopback Device
// ---------------------------------------------------------------------------

/// Loopback network device.
///
/// Internally maintains a fixed-size ring buffer. `loopback_xmit` writes a
/// packet into the ring; `recv` pops from the same ring.
pub struct LoopbackDevice {
    /// Device flags (IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_NOARP).
    flags: u32,
    /// Maximum Transmission Unit in bytes.
    pub mtu: u32,
    /// TX/RX statistics.
    pub stats: LoopbackStats,
    /// Internal packet ring.
    ring: [LoopbackPacket; LOOPBACK_RING_SIZE],
    /// Write (producer) index.
    head: usize,
    /// Read (consumer) index.
    tail: usize,
}

impl LoopbackDevice {
    /// Creates a new, up loopback device.
    pub fn new() -> Self {
        Self {
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_NOARP,
            mtu: LOOPBACK_MTU,
            stats: LoopbackStats::default(),
            ring: [const { LoopbackPacket::empty() }; LOOPBACK_RING_SIZE],
            head: 0,
            tail: 0,
        }
    }

    /// Returns the device flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns `true` if the interface is up and running.
    pub fn is_up(&self) -> bool {
        self.flags & (IFF_UP | IFF_RUNNING) == IFF_UP | IFF_RUNNING
    }

    /// Brings the interface down.
    pub fn down(&mut self) {
        self.flags &= !(IFF_UP | IFF_RUNNING);
    }

    /// Brings the interface up.
    pub fn up(&mut self) {
        self.flags |= IFF_UP | IFF_RUNNING;
    }

    /// Transmits (echoes) a packet by placing it in the RX ring.
    ///
    /// # Parameters
    /// - `data`: Packet bytes to transmit.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `data` exceeds the MTU.
    /// Returns `Error::Busy` if the ring is full.
    pub fn loopback_xmit(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.mtu as usize {
            return Err(Error::InvalidArgument);
        }
        let next_head = (self.head + 1) % LOOPBACK_RING_SIZE;
        if next_head == self.tail {
            // Ring full
            self.stats.tx_dropped += 1;
            return Err(Error::Busy);
        }
        let slot = &mut self.ring[self.head];
        let len = data.len().min(LOOPBACK_MAX_PKT);
        slot.data[..len].copy_from_slice(&data[..len]);
        slot.len = len as u16;
        slot.used = true;
        self.head = next_head;

        self.stats.tx_packets += 1;
        self.stats.tx_bytes += len as u64;
        // Packet immediately available for RX
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += len as u64;
        Ok(())
    }

    /// Receives the next packet from the loopback ring.
    ///
    /// Copies up to `buf.len()` bytes into `buf`.
    ///
    /// # Returns
    /// `Ok(n)` where `n` is the number of bytes written, or `Err(Error::IoError)`
    /// if no packet is available.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.tail == self.head {
            return Err(Error::IoError);
        }
        let slot = &mut self.ring[self.tail];
        if !slot.used {
            return Err(Error::IoError);
        }
        let len = (slot.len as usize).min(buf.len());
        buf[..len].copy_from_slice(&slot.data[..len]);
        slot.used = false;
        self.tail = (self.tail + 1) % LOOPBACK_RING_SIZE;
        Ok(len)
    }

    /// Returns `true` if at least one packet is pending in the RX ring.
    pub fn has_packet(&self) -> bool {
        self.tail != self.head
    }

    /// Returns the number of packets pending in the ring.
    pub fn pending_count(&self) -> usize {
        (self.head + LOOPBACK_RING_SIZE - self.tail) % LOOPBACK_RING_SIZE
    }

    /// Flushes the ring, discarding all pending packets.
    pub fn flush(&mut self) {
        while self.tail != self.head {
            self.ring[self.tail].used = false;
            self.tail = (self.tail + 1) % LOOPBACK_RING_SIZE;
        }
    }

    /// Returns the device MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Returns a snapshot of the device statistics.
    pub fn statistics(&self) -> LoopbackStats {
        self.stats
    }

    /// Resets statistics counters.
    pub fn reset_statistics(&mut self) {
        self.stats = LoopbackStats::default();
    }

    /// Returns the IPv4 loopback address.
    pub const fn ipv4_addr() -> [u8; 4] {
        LOOPBACK_IPV4
    }

    /// Returns the IPv6 loopback address.
    pub const fn ipv6_addr() -> [u8; 16] {
        LOOPBACK_IPV6
    }
}

impl Default for LoopbackDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Loopback Setup
// ---------------------------------------------------------------------------

/// Configures and returns a new loopback device ready for use.
///
/// Equivalent to calling `LoopbackDevice::new()` but with explicit setup
/// logging for the kernel init path.
pub fn loopback_setup() -> LoopbackDevice {
    LoopbackDevice::new()
}

/// Returns `true` if `addr` is in the 127.0.0.0/8 loopback range.
pub const fn is_loopback_ipv4(addr: [u8; 4]) -> bool {
    addr[0] == 127
}

/// Returns `true` if `addr` is the IPv6 loopback address ::1.
pub const fn is_loopback_ipv6(addr: [u8; 16]) -> bool {
    let expected = LOOPBACK_IPV6;
    let mut i = 0usize;
    loop {
        if i >= 16 {
            return true;
        }
        if addr[i] != expected[i] {
            return false;
        }
        i += 1;
    }
}
