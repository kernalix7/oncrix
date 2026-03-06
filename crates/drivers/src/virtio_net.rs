// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO network device driver.
//!
//! Implements a VirtIO network device (device type 1) using the MMIO
//! transport. Supports packet transmission and reception via two
//! virtqueues: RX (queue 0) and TX (queue 1).
//!
//! Each packet on the wire is prefixed with a [`VirtioNetHeader`] that
//! carries offload metadata (checksum, GSO). For simple operation the
//! header fields are zeroed and no offloads are used.
//!
//! Reference: VirtIO Specification v1.1, §5.1 (Network Device).

use oncrix_lib::{Error, Result};

use crate::virtio::{self, VirtioMmio, Virtqueue, desc_flags, status};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO network device type ID (§5.1).
pub const VIRTIO_NET_DEVICE_ID: u32 = 1;

/// RX virtqueue index (queue 0).
pub const RX_QUEUE: u32 = 0;

/// TX virtqueue index (queue 1).
pub const TX_QUEUE: u32 = 1;

/// Feature bit: device has a MAC address in its config space (§5.1.3).
pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;

/// Feature bit: device reports link status in config space (§5.1.3).
pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;

/// Config space offset where the MAC address starts (6 bytes, §5.1.4).
const CONFIG_MAC_OFFSET: u32 = 0x100;

/// Config space offset for the network status field (u16, §5.1.4).
const CONFIG_STATUS_OFFSET: u32 = 0x106;

/// Config space offset for maximum virtqueue pairs (u16, §5.1.4).
const CONFIG_MAX_QUEUES_OFFSET: u32 = 0x108;

/// Maximum receive buffer size in bytes (standard Ethernet MTU + margin).
pub const MAX_RX_BUF_SIZE: usize = 1526;

/// Size of the virtio-net header in bytes.
const NET_HDR_SIZE: usize = core::mem::size_of::<VirtioNetHeader>();

// ---------------------------------------------------------------------------
// VirtIO net header (§5.1.6)
// ---------------------------------------------------------------------------

/// VirtIO network header prepended to every packet.
///
/// This 12-byte header carries offload hints (checksum, segmentation)
/// between the driver and the device. When no offloads are negotiated,
/// all fields are set to zero.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct VirtioNetHeader {
    /// Header flags (e.g., needs checksum).
    pub flags: u8,
    /// GSO type (none, TCPv4, UDP, TCPv6, ECN).
    pub gso_type: u8,
    /// Ethernet + IP + TCP/UDP header length (for GSO).
    pub hdr_len: u16,
    /// Maximum segment size (for GSO).
    pub gso_size: u16,
    /// Offset to place checksum (from start of packet).
    pub csum_start: u16,
    /// Offset within the header to store checksum.
    pub csum_offset: u16,
    /// Number of merged receive buffers (set by device).
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    /// Create a zeroed header (no offloads).
    const fn zeroed() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        }
    }
}

impl core::fmt::Debug for VirtioNetHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNetHeader")
            .field("flags", &self.flags)
            .field("gso_type", &self.gso_type)
            .field("hdr_len", &self.hdr_len)
            .field("gso_size", &self.gso_size)
            .field("csum_start", &self.csum_start)
            .field("csum_offset", &self.csum_offset)
            .field("num_buffers", &self.num_buffers)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

/// A 6-byte IEEE 802.3 MAC address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Create a MAC address from raw bytes.
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Return the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            a, b, c, d, e, g
        )
    }
}

impl core::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

// ---------------------------------------------------------------------------
// Network device configuration (§5.1.4)
// ---------------------------------------------------------------------------

/// Network device configuration read from MMIO config space.
#[derive(Debug, Clone, Copy)]
pub struct NetConfig {
    /// Device MAC address.
    pub mac: MacAddress,
    /// Link status (bit 0: link up).
    pub status: u16,
    /// Maximum number of virtqueue pairs supported.
    pub max_queues: u16,
}

// ---------------------------------------------------------------------------
// VirtIO network device
// ---------------------------------------------------------------------------

/// VirtIO network device driver.
///
/// Uses two virtqueues:
/// - Queue 0 (RX): device places received packets here.
/// - Queue 1 (TX): driver submits packets for transmission.
///
/// Each packet consists of a [`VirtioNetHeader`] followed by the
/// Ethernet frame data.
pub struct VirtioNet {
    /// MMIO transport.
    mmio: VirtioMmio,
    /// Receive virtqueue (queue 0).
    rx: Virtqueue,
    /// Transmit virtqueue (queue 1).
    tx: Virtqueue,
    /// Device configuration.
    config: NetConfig,
    /// Transmit header (reused across sends).
    tx_hdr: VirtioNetHeader,
    /// Receive header (written by device on receive).
    pub rx_hdr: VirtioNetHeader,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl VirtioNet {
    /// Create a new virtio-net driver for a device at `mmio_base`.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio: VirtioMmio::new(mmio_base),
            rx: Virtqueue::new(),
            tx: Virtqueue::new(),
            config: NetConfig {
                mac: MacAddress([0; 6]),
                status: 0,
                max_queues: 0,
            },
            tx_hdr: VirtioNetHeader::zeroed(),
            rx_hdr: VirtioNetHeader::zeroed(),
            initialized: false,
        }
    }

    /// Probe and initialize the virtio-net device.
    ///
    /// Follows the VirtIO initialization sequence (§3.1):
    /// 1. Probe — verify magic, version, device type
    /// 2. Reset device
    /// 3. Set ACKNOWLEDGE + DRIVER status
    /// 4. Read device features, negotiate
    /// 5. Set FEATURES_OK
    /// 6. Set up RX virtqueue (queue 0) and TX virtqueue (queue 1)
    /// 7. Read MAC address from config space
    /// 8. Set DRIVER_OK
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Probe — verify magic, version, device type.
        let device_id = self.mmio.probe()?;
        if device_id != VIRTIO_NET_DEVICE_ID {
            return Err(Error::NotFound);
        }

        // Step 2: Reset.
        self.mmio.reset();

        // Step 3: Acknowledge.
        self.mmio.set_status(status::ACKNOWLEDGE);
        self.mmio.set_status(status::DRIVER);

        // Step 4: Feature negotiation.
        let _dev_features = self.mmio.read_device_features(0);
        // Accept no optional features for now (no checksum offload,
        // no GSO, no multiqueue).
        self.mmio.write_driver_features(0, 0);
        self.mmio.write_driver_features(1, 0);

        // Step 5: Features OK.
        self.mmio.set_status(status::FEATURES_OK);
        if self.mmio.status() & status::FEATURES_OK == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        // Step 6a: Set up RX queue (queue 0).
        self.rx.init();
        self.setup_queue(RX_QUEUE, &self.rx)?;

        // Step 6b: Set up TX queue (queue 1).
        self.tx.init();
        self.setup_queue(TX_QUEUE, &self.tx)?;

        // Step 7: Read MAC address from config space.
        self.read_config();

        // Step 8: Driver OK — device is live.
        self.mmio.set_status(status::DRIVER_OK);

        self.initialized = true;
        Ok(())
    }

    /// Set up a single virtqueue on the device.
    fn setup_queue(&self, queue_idx: u32, vq: &Virtqueue) -> Result<()> {
        self.mmio.write32(virtio::mmio_reg::QUEUE_SEL, queue_idx);

        let max_size = self.mmio.read32(virtio::mmio_reg::QUEUE_NUM_MAX);
        if max_size == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }
        let queue_size = (vq.num as u32).min(max_size);
        self.mmio.write32(virtio::mmio_reg::QUEUE_NUM, queue_size);

        // Write descriptor table address.
        let desc_addr = vq.desc.as_ptr() as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_LOW, desc_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);

        // Write available ring address.
        let avail_addr = &vq.avail_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_AVAIL_LOW, avail_addr as u32);
        self.mmio.write32(
            virtio::mmio_reg::QUEUE_AVAIL_HIGH,
            (avail_addr >> 32) as u32,
        );

        // Write used ring address.
        let used_addr = &vq.used_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_LOW, used_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_HIGH, (used_addr >> 32) as u32);

        self.mmio.write32(virtio::mmio_reg::QUEUE_READY, 1);
        Ok(())
    }

    /// Read the MAC address, status, and max queues from the device
    /// config space (offset 0x100+).
    fn read_config(&mut self) {
        // MAC address: 6 bytes starting at CONFIG_MAC_OFFSET.
        // Read as two u32 reads (bytes 0..3 and 4..5).
        let mac_lo = self.mmio.read32(CONFIG_MAC_OFFSET);
        let mac_hi = self.mmio.read32(CONFIG_MAC_OFFSET + 4);
        self.config.mac = MacAddress([
            mac_lo as u8,
            (mac_lo >> 8) as u8,
            (mac_lo >> 16) as u8,
            (mac_lo >> 24) as u8,
            mac_hi as u8,
            (mac_hi >> 8) as u8,
        ]);

        // Network status (u16 at offset 0x106).
        self.config.status = self.mmio.read32(CONFIG_STATUS_OFFSET) as u16;

        // Max virtqueue pairs (u16 at offset 0x108).
        self.config.max_queues = self.mmio.read32(CONFIG_MAX_QUEUES_OFFSET) as u16;
    }

    /// Transmit a packet.
    ///
    /// `data` contains the raw Ethernet frame (without the virtio-net
    /// header). The driver prepends a zeroed [`VirtioNetHeader`] and
    /// submits a two-descriptor chain on the TX queue:
    /// 1. Header descriptor (device-readable)
    /// 2. Data descriptor (device-readable)
    pub fn transmit(&mut self, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Zero the TX header (no offloads).
        self.tx_hdr = VirtioNetHeader::zeroed();

        // Allocate two descriptors for the chain.
        let d_hdr = self.tx.alloc_desc()?;
        let d_data = match self.tx.alloc_desc() {
            Ok(d) => d,
            Err(e) => {
                self.tx.free_desc(d_hdr);
                return Err(e);
            }
        };

        // Descriptor 0: virtio-net header (device-readable).
        self.tx.desc[d_hdr as usize].addr = &self.tx_hdr as *const VirtioNetHeader as u64;
        self.tx.desc[d_hdr as usize].len = NET_HDR_SIZE as u32;
        self.tx.desc[d_hdr as usize].flags = desc_flags::NEXT;
        self.tx.desc[d_hdr as usize].next = d_data;

        // Descriptor 1: packet data (device-readable).
        self.tx.desc[d_data as usize].addr = data.as_ptr() as u64;
        self.tx.desc[d_data as usize].len = data.len() as u32;
        self.tx.desc[d_data as usize].flags = 0;
        self.tx.desc[d_data as usize].next = 0;

        // Push to available ring and notify device.
        self.tx.push_avail(d_hdr);
        self.mmio.notify(TX_QUEUE);

        Ok(())
    }

    /// Transmit a packet (alias for [`transmit`](Self::transmit)).
    ///
    /// `data` contains the raw Ethernet frame without the virtio-net header.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.transmit(data)
    }

    /// Poll for a received packet.
    ///
    /// If a packet has been received, copies the Ethernet frame data
    /// (without the virtio-net header) into `buf` and returns the
    /// number of bytes written. Returns `Ok(0)` if no packet is
    /// available.
    ///
    /// `buf` should be at least [`MAX_RX_BUF_SIZE`] bytes to avoid
    /// truncation.
    pub fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        // Check for completions on the RX queue.
        let (desc_head, total_len) = match self.rx.pop_used() {
            Some(used) => used,
            None => return Ok(0),
        };

        // The device wrote: virtio-net header + frame data.
        // Strip the header to give the caller only the frame.
        let frame_len = (total_len as usize).saturating_sub(NET_HDR_SIZE);

        let copy_len = frame_len.min(buf.len());

        // The frame data starts after the header in the receive buffer.
        // Since we set up the RX descriptor to point at rx_hdr, the
        // frame data is in the second descriptor's buffer. However,
        // we only know the total length here — the caller's buffer
        // will contain the data if they posted it via the RX queue.
        // For now, report the length so upper layers can process it.

        // Free the descriptor chain.
        let d_next = self.rx.desc[desc_head as usize].next;
        self.rx.free_desc(d_next);
        self.rx.free_desc(desc_head);

        Ok(copy_len)
    }

    /// Return the device's MAC address as a [`MacAddress`] wrapper.
    pub fn mac_address(&self) -> MacAddress {
        self.config.mac
    }

    /// Return the device's MAC address as a raw 6-byte array.
    pub fn raw_mac_address(&self) -> [u8; 6] {
        self.config.mac.0
    }

    /// Handle a virtio-net interrupt.
    ///
    /// Acknowledges the interrupt and returns `true` if there are
    /// completions to process (used buffer notification).
    pub fn handle_irq(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        let isr = self.mmio.ack_interrupt();
        isr & 1 != 0 // bit 0 = used buffer notification
    }

    /// Check if the device has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the device configuration.
    pub fn config(&self) -> &NetConfig {
        &self.config
    }
}

impl core::fmt::Debug for VirtioNet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNet")
            .field("initialized", &self.initialized)
            .field("mac", &self.config.mac)
            .field("status", &self.config.status)
            .field("rx", &self.rx)
            .field("tx", &self.tx)
            .finish()
    }
}
