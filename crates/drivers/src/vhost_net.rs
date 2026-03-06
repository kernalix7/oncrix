// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vhost-net driver.
//!
//! Implements the kernel-side vhost-net interface used to accelerate
//! virtio-net packet processing by keeping data-path packet forwarding
//! in the host kernel (or a dedicated vhost process) rather than in
//! userspace QEMU. This driver manages virtqueue kick/notification
//! and descriptor ring processing.

use oncrix_lib::{Error, Result};

/// Maximum number of virtqueues per vhost-net device.
pub const MAX_QUEUES: usize = 16;
/// Maximum number of descriptors per virtqueue.
pub const MAX_RING_SIZE: usize = 256;

/// Virtqueue descriptor flags.
pub const VRING_DESC_F_NEXT: u16 = 1 << 0; // Descriptor continues via next field
pub const VRING_DESC_F_WRITE: u16 = 1 << 1; // Buffer is device-writable
pub const VRING_DESC_F_INDIRECT: u16 = 1 << 2; // Element contains table of descriptors

/// Used ring flags.
pub const VRING_USED_F_NO_NOTIFY: u16 = 1 << 0;
/// Available ring flags.
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1 << 0;

/// Virtqueue descriptor in `#[repr(C)]` for shared memory compatibility.
#[repr(C)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags.
    pub flags: u16,
    /// Index of next descriptor (if VRING_DESC_F_NEXT is set).
    pub next: u16,
}

impl VirtqDesc {
    /// Create a zeroed descriptor.
    pub const fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }
}

impl Default for VirtqDesc {
    fn default() -> Self {
        Self::new()
    }
}

/// Virtqueue available ring element.
#[repr(C)]
pub struct VirtqAvail {
    /// Flags (VRING_AVAIL_F_*).
    pub flags: u16,
    /// Index of next entry to be added.
    pub idx: u16,
    /// Ring of descriptor chain heads.
    pub ring: [u16; MAX_RING_SIZE],
    /// Used event suppression (optional feature).
    pub used_event: u16,
}

/// Virtqueue used ring element.
#[repr(C)]
pub struct VirtqUsedElem {
    /// Descriptor chain head index.
    pub id: u32,
    /// Total bytes written (from device).
    pub len: u32,
}

impl VirtqUsedElem {
    pub const fn new() -> Self {
        Self { id: 0, len: 0 }
    }
}

impl Default for VirtqUsedElem {
    fn default() -> Self {
        Self::new()
    }
}

/// Virtqueue used ring.
#[repr(C)]
pub struct VirtqUsed {
    /// Flags (VRING_USED_F_*).
    pub flags: u16,
    /// Index of next entry to be added.
    pub idx: u16,
    /// Ring of used elements.
    pub ring: [VirtqUsedElem; MAX_RING_SIZE],
    /// Available event suppression.
    pub avail_event: u16,
}

/// vhost-net virtqueue state.
pub struct VhostQueue {
    /// Queue index.
    pub index: usize,
    /// Number of descriptors in the ring.
    pub size: usize,
    /// Last seen available ring index.
    last_avail_idx: u16,
    /// Last used ring index posted.
    last_used_idx: u16,
    /// Kick file descriptor (eventfd for guest→host notification).
    kick_fd: i32,
    /// Call file descriptor (eventfd for host→guest notification).
    call_fd: i32,
    /// Queue is running.
    enabled: bool,
}

impl VhostQueue {
    /// Create a new virtqueue.
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            size: MAX_RING_SIZE,
            last_avail_idx: 0,
            last_used_idx: 0,
            kick_fd: -1,
            call_fd: -1,
            enabled: false,
        }
    }

    /// Configure the kick and call event file descriptors.
    pub fn configure(&mut self, kick_fd: i32, call_fd: i32) {
        self.kick_fd = kick_fd;
        self.call_fd = call_fd;
    }

    /// Enable this queue for processing.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable this queue.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return whether the queue has pending packets to process.
    ///
    /// In a real implementation this checks the available ring index
    /// against the last processed index.
    pub fn has_pending(&self, avail_idx: u16) -> bool {
        self.enabled && avail_idx != self.last_avail_idx
    }

    /// Consume one available descriptor chain.
    pub fn consume_avail(&mut self, head: u16) -> Option<u16> {
        if !self.enabled {
            return None;
        }
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
        Some(head)
    }

    /// Post a completion to the used ring.
    pub fn post_used(&mut self, id: u32, len: u32) {
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        // In a real driver, write (id, len) to the used ring at last_used_idx.
        let _ = (id, len);
    }
}

/// vhost-net network device driver.
pub struct VhostNet {
    /// TX/RX virtqueues (pairs: even=TX, odd=RX).
    queues: [VhostQueue; MAX_QUEUES],
    /// Number of queue pairs.
    num_queue_pairs: usize,
    /// Device MAC address.
    mac: [u8; 6],
    /// Device is active.
    active: bool,
}

impl VhostNet {
    /// Create a new vhost-net driver.
    pub fn new(num_queue_pairs: usize) -> Self {
        let np = num_queue_pairs.min(MAX_QUEUES / 2);
        Self {
            queues: core::array::from_fn(|i| VhostQueue::new(i)),
            num_queue_pairs: np,
            mac: [0u8; 6],
            active: false,
        }
    }

    /// Set the MAC address.
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    /// Configure and enable a queue pair.
    pub fn setup_queue_pair(
        &mut self,
        pair: usize,
        tx_kick: i32,
        tx_call: i32,
        rx_kick: i32,
        rx_call: i32,
    ) -> Result<()> {
        if pair >= self.num_queue_pairs {
            return Err(Error::InvalidArgument);
        }
        let tx_idx = pair * 2;
        let rx_idx = pair * 2 + 1;
        self.queues[tx_idx].configure(tx_kick, tx_call);
        self.queues[rx_idx].configure(rx_kick, rx_call);
        self.queues[tx_idx].enable();
        self.queues[rx_idx].enable();
        Ok(())
    }

    /// Start the device.
    pub fn start(&mut self) -> Result<()> {
        if self.active {
            return Err(Error::AlreadyExists);
        }
        self.active = true;
        Ok(())
    }

    /// Stop the device and disable all queues.
    pub fn stop(&mut self) {
        for q in self.queues[..self.num_queue_pairs * 2].iter_mut() {
            q.disable();
        }
        self.active = false;
    }

    /// Process incoming packets for RX queue `pair`.
    ///
    /// Returns the number of packets forwarded.
    pub fn poll_rx(&mut self, pair: usize, avail_idx: u16) -> usize {
        if pair >= self.num_queue_pairs {
            return 0;
        }
        let rx_idx = pair * 2 + 1;
        let q = &mut self.queues[rx_idx];
        if !q.has_pending(avail_idx) {
            return 0;
        }
        // In a real driver: dequeue descriptors, copy data from tap/backend,
        // post completions to the used ring, and notify the guest.
        0
    }

    /// Return the MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Return the number of queue pairs.
    pub fn num_queue_pairs(&self) -> usize {
        self.num_queue_pairs
    }
}
