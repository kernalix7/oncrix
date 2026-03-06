// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thunderbolt/USB4 host controller driver.
//!
//! Implements the NHI (Native Host Interface) for Thunderbolt/USB4
//! controllers. Supports tunnel management (DisplayPort, PCIe, USB3),
//! path setup, ring descriptors, and device connection/disconnection
//! handling.
//!
//! # Architecture
//!
//! - [`TbtController`] — NHI host controller abstraction
//! - [`TbtRing`] — TX/RX ring descriptor management
//! - [`TbtRingDescriptor`] — hardware ring descriptor (`repr(C)`)
//! - [`TbtTunnel`] — DP/PCIe/USB3 tunnel state
//! - [`TbtPath`] — configured data path through the topology
//! - [`TbtDevice`] — connected Thunderbolt device
//! - [`TbtControllerRegistry`] — system-wide controller registry
//!
//! Reference: Thunderbolt 3/USB4 specification.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum ring descriptors per ring.
const MAX_RING_DESCRIPTORS: usize = 32;

/// Maximum TX/RX rings per controller.
const MAX_RINGS: usize = 16;

/// Maximum tunnels per controller.
const MAX_TUNNELS: usize = 8;

/// Maximum paths per controller.
const MAX_PATHS: usize = 16;

/// Maximum connected devices.
const MAX_DEVICES: usize = 16;

/// Maximum hops in a path.
const MAX_PATH_HOPS: usize = 8;

/// Maximum controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

/// Timeout for controller operations (polling iterations).
const TBT_TIMEOUT: u32 = 100_000;

// -------------------------------------------------------------------
// NHI Register Offsets
// -------------------------------------------------------------------

/// Receiver ring base address low register.
const _NHI_RX_RING_BASE_LO: u32 = 0x00;

/// Receiver ring base address high register.
const _NHI_RX_RING_BASE_HI: u32 = 0x04;

/// Receiver ring consumer index register.
const _NHI_RX_RING_CONS: u32 = 0x08;

/// Receiver ring producer index register.
const _NHI_RX_RING_PROD: u32 = 0x0C;

/// Transmitter ring base address low register.
const _NHI_TX_RING_BASE_LO: u32 = 0x10;

/// Transmitter ring base address high register.
const _NHI_TX_RING_BASE_HI: u32 = 0x14;

/// Transmitter ring consumer index register.
const _NHI_TX_RING_CONS: u32 = 0x18;

/// Transmitter ring producer index register.
const _NHI_TX_RING_PROD: u32 = 0x1C;

/// Ring size register.
const _NHI_RING_SIZE: u32 = 0x20;

/// Interrupt enable register.
const _NHI_INT_ENABLE: u32 = 0x38;

/// Interrupt status register.
const NHI_INT_STATUS: u32 = 0x3C;

/// Mail data out register.
const _NHI_MAIL_DATA_OUT: u32 = 0x40;

/// Mail data in register.
const _NHI_MAIL_DATA_IN: u32 = 0x44;

/// Interrupt mask all register.
const _NHI_INT_MASK_ALL: u32 = 0x48;

// -------------------------------------------------------------------
// TunnelType
// -------------------------------------------------------------------

/// Type of Thunderbolt tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelType {
    /// PCIe tunnel.
    #[default]
    Pcie,
    /// DisplayPort tunnel.
    DisplayPort,
    /// USB 3.x tunnel.
    Usb3,
    /// DMA tunnel (bulk data transfer).
    Dma,
}

// -------------------------------------------------------------------
// TunnelState
// -------------------------------------------------------------------

/// State of a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelState {
    /// Tunnel not configured.
    #[default]
    Inactive,
    /// Tunnel being set up.
    Activating,
    /// Tunnel is active and forwarding data.
    Active,
    /// Tunnel is being torn down.
    Deactivating,
    /// Tunnel encountered an error.
    Error,
}

// -------------------------------------------------------------------
// RingDirection
// -------------------------------------------------------------------

/// Direction of a ring (TX or RX).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RingDirection {
    /// Transmit ring (host to device).
    #[default]
    Tx,
    /// Receive ring (device to host).
    Rx,
}

// -------------------------------------------------------------------
// RingState
// -------------------------------------------------------------------

/// Ring operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RingState {
    /// Ring not initialized.
    #[default]
    Disabled,
    /// Ring initialized and ready.
    Enabled,
    /// Ring is actively processing descriptors.
    Running,
    /// Ring is stopped.
    Stopped,
}

// -------------------------------------------------------------------
// TbtRingDescriptor
// -------------------------------------------------------------------

/// Hardware ring descriptor for NHI TX/RX rings.
///
/// Each descriptor points to a buffer for DMA data transfer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TbtRingDescriptor {
    /// Buffer physical address (low 32 bits).
    pub addr_lo: u32,
    /// Buffer physical address (high 32 bits).
    pub addr_hi: u32,
    /// Buffer length in bytes.
    pub length: u32,
    /// Flags and status.
    pub flags: u32,
}

impl TbtRingDescriptor {
    /// Creates an empty descriptor.
    pub const fn new() -> Self {
        Self {
            addr_lo: 0,
            addr_hi: 0,
            length: 0,
            flags: 0,
        }
    }

    /// Creates a descriptor pointing to a physical buffer.
    pub fn from_phys(phys_addr: u64, length: u32) -> Self {
        Self {
            addr_lo: phys_addr as u32,
            addr_hi: (phys_addr >> 32) as u32,
            length,
            flags: 0,
        }
    }

    /// Returns the full 64-bit physical address.
    pub fn phys_addr(&self) -> u64 {
        (self.addr_lo as u64) | ((self.addr_hi as u64) << 32)
    }

    /// Returns `true` if the descriptor is owned by hardware.
    pub fn is_hw_owned(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    /// Marks the descriptor as owned by hardware.
    pub fn set_hw_owned(&mut self) {
        self.flags |= 1 << 0;
    }

    /// Clears the hardware-owned bit.
    pub fn clear_hw_owned(&mut self) {
        self.flags &= !(1 << 0);
    }

    /// Returns `true` if this is the end-of-frame descriptor.
    pub fn is_eof(&self) -> bool {
        self.flags & (1 << 1) != 0
    }

    /// Sets the end-of-frame flag.
    pub fn set_eof(&mut self) {
        self.flags |= 1 << 1;
    }
}

// -------------------------------------------------------------------
// TbtRing
// -------------------------------------------------------------------

/// A NHI TX or RX ring.
///
/// Manages a circular buffer of ring descriptors for DMA-based
/// data transfer between the host and Thunderbolt devices.
pub struct TbtRing {
    /// Ring index within the controller.
    pub index: u8,
    /// Ring direction (TX or RX).
    pub direction: RingDirection,
    /// Ring state.
    pub state: RingState,
    /// Ring descriptors.
    descriptors: [TbtRingDescriptor; MAX_RING_DESCRIPTORS],
    /// Number of descriptors in use.
    descriptor_count: usize,
    /// Producer index (next descriptor to submit).
    producer: usize,
    /// Consumer index (next descriptor to reclaim).
    consumer: usize,
    /// Physical base address of the descriptor ring.
    pub ring_phys: u64,
    /// Hop ID associated with this ring.
    pub hop_id: u8,
}

impl Default for TbtRing {
    fn default() -> Self {
        Self::new()
    }
}

impl TbtRing {
    /// Creates an idle ring.
    pub const fn new() -> Self {
        Self {
            index: 0,
            direction: RingDirection::Tx,
            state: RingState::Disabled,
            descriptors: [TbtRingDescriptor::new(); MAX_RING_DESCRIPTORS],
            descriptor_count: MAX_RING_DESCRIPTORS,
            producer: 0,
            consumer: 0,
            ring_phys: 0,
            hop_id: 0,
        }
    }

    /// Initializes the ring with a physical base address.
    pub fn init(&mut self, index: u8, direction: RingDirection, phys_base: u64) {
        self.index = index;
        self.direction = direction;
        self.ring_phys = phys_base;
        self.state = RingState::Enabled;
        self.producer = 0;
        self.consumer = 0;
    }

    /// Enables the ring for operation.
    pub fn enable(&mut self) -> Result<()> {
        if self.state == RingState::Disabled {
            return Err(Error::InvalidArgument);
        }
        self.state = RingState::Running;
        Ok(())
    }

    /// Disables the ring.
    pub fn disable(&mut self) {
        self.state = RingState::Stopped;
    }

    /// Submits a buffer to the ring.
    pub fn submit(&mut self, phys_addr: u64, length: u32) -> Result<usize> {
        if self.state != RingState::Running {
            return Err(Error::InvalidArgument);
        }

        let next_prod = (self.producer + 1) % self.descriptor_count;
        if next_prod == self.consumer {
            return Err(Error::Busy); // Ring full
        }

        let idx = self.producer;
        self.descriptors[idx] = TbtRingDescriptor::from_phys(phys_addr, length);
        self.descriptors[idx].set_hw_owned();
        self.producer = next_prod;
        Ok(idx)
    }

    /// Reclaims completed descriptors.
    pub fn reclaim(&mut self) -> usize {
        let mut count = 0;
        while self.consumer != self.producer {
            if self.descriptors[self.consumer].is_hw_owned() {
                break; // Still owned by hardware
            }
            self.consumer = (self.consumer + 1) % self.descriptor_count;
            count += 1;
        }
        count
    }

    /// Returns the number of pending (submitted but not reclaimed) descriptors.
    pub fn pending_count(&self) -> usize {
        if self.producer >= self.consumer {
            self.producer - self.consumer
        } else {
            self.descriptor_count - self.consumer + self.producer
        }
    }

    /// Returns `true` if the ring is empty (no pending descriptors).
    pub fn is_empty(&self) -> bool {
        self.producer == self.consumer
    }

    /// Returns a reference to a descriptor by index.
    pub fn get_descriptor(&self, index: usize) -> Option<&TbtRingDescriptor> {
        if index < self.descriptor_count {
            Some(&self.descriptors[index])
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// TbtTunnel
// -------------------------------------------------------------------

/// A Thunderbolt/USB4 tunnel configuration.
///
/// Tunnels carry specific protocols (PCIe, DP, USB3) over the
/// Thunderbolt fabric between source and destination adapters.
pub struct TbtTunnel {
    /// Tunnel identifier.
    pub id: u16,
    /// Tunnel type.
    pub tunnel_type: TunnelType,
    /// Tunnel state.
    pub state: TunnelState,
    /// Source adapter port number.
    pub src_port: u8,
    /// Destination adapter port number.
    pub dst_port: u8,
    /// Source hop ID.
    pub src_hop: u8,
    /// Destination hop ID.
    pub dst_hop: u8,
    /// Assigned bandwidth (Mbps, 0 if not applicable).
    pub bandwidth_mbps: u32,
    /// TX ring index.
    pub tx_ring: u8,
    /// RX ring index.
    pub rx_ring: u8,
}

impl Default for TbtTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl TbtTunnel {
    /// Creates an empty tunnel.
    pub const fn new() -> Self {
        Self {
            id: 0,
            tunnel_type: TunnelType::Pcie,
            state: TunnelState::Inactive,
            src_port: 0,
            dst_port: 0,
            src_hop: 0,
            dst_hop: 0,
            bandwidth_mbps: 0,
            tx_ring: 0,
            rx_ring: 0,
        }
    }

    /// Returns `true` if this tunnel slot is unused.
    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.state == TunnelState::Inactive
    }

    /// Activates the tunnel.
    pub fn activate(&mut self) -> Result<()> {
        if self.state != TunnelState::Inactive {
            return Err(Error::Busy);
        }
        self.state = TunnelState::Activating;
        // In real code: configure path hops, enable adapters
        self.state = TunnelState::Active;
        Ok(())
    }

    /// Deactivates the tunnel.
    pub fn deactivate(&mut self) {
        self.state = TunnelState::Deactivating;
        // In real code: tear down path hops, disable adapters
        self.state = TunnelState::Inactive;
    }
}

// -------------------------------------------------------------------
// PathHop
// -------------------------------------------------------------------

/// A single hop in a Thunderbolt path.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathHop {
    /// Device route string for this hop.
    pub route: u64,
    /// Ingress port.
    pub in_port: u8,
    /// Egress port.
    pub out_port: u8,
    /// Ingress hop ID.
    pub in_hop: u8,
    /// Egress hop ID.
    pub out_hop: u8,
    /// Whether this hop is the initial (source) hop.
    pub initial: bool,
}

impl PathHop {
    /// Creates a path hop.
    pub const fn new(route: u64, in_port: u8, out_port: u8, in_hop: u8, out_hop: u8) -> Self {
        Self {
            route,
            in_port,
            out_port,
            in_hop,
            out_hop,
            initial: false,
        }
    }
}

// -------------------------------------------------------------------
// TbtPath
// -------------------------------------------------------------------

/// A configured data path through the Thunderbolt topology.
///
/// A path consists of a sequence of hops, each configuring the
/// routing tables in the switches along the way.
pub struct TbtPath {
    /// Path identifier.
    pub id: u16,
    /// Whether the path is active.
    pub active: bool,
    /// Hops composing this path.
    hops: [PathHop; MAX_PATH_HOPS],
    /// Number of hops.
    hop_count: usize,
    /// Weight (for bandwidth allocation).
    pub weight: u32,
}

impl Default for TbtPath {
    fn default() -> Self {
        Self::new()
    }
}

impl TbtPath {
    /// Creates an empty path.
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            hops: [PathHop {
                route: 0,
                in_port: 0,
                out_port: 0,
                in_hop: 0,
                out_hop: 0,
                initial: false,
            }; MAX_PATH_HOPS],
            hop_count: 0,
            weight: 1,
        }
    }

    /// Adds a hop to the path.
    pub fn add_hop(&mut self, hop: PathHop) -> Result<()> {
        if self.hop_count >= MAX_PATH_HOPS {
            return Err(Error::OutOfMemory);
        }
        self.hops[self.hop_count] = hop;
        self.hop_count += 1;
        Ok(())
    }

    /// Activates the path by programming all hops.
    pub fn activate(&mut self) -> Result<()> {
        if self.hop_count == 0 {
            return Err(Error::InvalidArgument);
        }
        // In real code: program hop routing tables via config space
        self.active = true;
        Ok(())
    }

    /// Deactivates the path.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Returns the number of hops.
    pub fn hop_count(&self) -> usize {
        self.hop_count
    }

    /// Returns a reference to a hop by index.
    pub fn get_hop(&self, index: usize) -> Option<&PathHop> {
        if index < self.hop_count {
            Some(&self.hops[index])
        } else {
            None
        }
    }

    /// Returns `true` if this path slot is unused.
    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.hop_count == 0
    }
}

// -------------------------------------------------------------------
// DeviceState
// -------------------------------------------------------------------

/// State of a connected Thunderbolt device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceState {
    /// Device not connected.
    #[default]
    Disconnected,
    /// Device connecting (enumeration in progress).
    Connecting,
    /// Device connected and authorized.
    Connected,
    /// Device suspended.
    Suspended,
    /// Device has errors.
    Error,
}

// -------------------------------------------------------------------
// DeviceGeneration
// -------------------------------------------------------------------

/// Thunderbolt generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceGeneration {
    /// Thunderbolt 1/2.
    Tbt1,
    /// Thunderbolt 3.
    Tbt3,
    /// USB4 / Thunderbolt 4.
    #[default]
    Usb4,
}

// -------------------------------------------------------------------
// TbtDevice
// -------------------------------------------------------------------

/// A connected Thunderbolt/USB4 device.
pub struct TbtDevice {
    /// Device route string (topology address).
    pub route: u64,
    /// Device UUID.
    pub uuid: [u8; 16],
    /// Vendor ID.
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// Generation.
    pub generation: DeviceGeneration,
    /// Connection state.
    pub state: DeviceState,
    /// Whether the device is authorized (security approved).
    pub authorized: bool,
    /// Number of ports on this device.
    pub port_count: u8,
    /// Upstream port number.
    pub upstream_port: u8,
    /// Link speed in Gbps.
    pub link_speed_gbps: u32,
    /// Link width (number of lanes).
    pub link_width: u8,
}

impl Default for TbtDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl TbtDevice {
    /// Creates a default device (disconnected).
    pub const fn new() -> Self {
        Self {
            route: 0,
            uuid: [0u8; 16],
            vendor_id: 0,
            device_id: 0,
            generation: DeviceGeneration::Usb4,
            state: DeviceState::Disconnected,
            authorized: false,
            port_count: 0,
            upstream_port: 0,
            link_speed_gbps: 0,
            link_width: 0,
        }
    }

    /// Returns `true` if this device slot is unused.
    pub fn is_empty(&self) -> bool {
        self.route == 0 && self.state == DeviceState::Disconnected
    }

    /// Authorizes the device for use.
    pub fn authorize(&mut self) -> Result<()> {
        if self.state != DeviceState::Connected {
            return Err(Error::InvalidArgument);
        }
        self.authorized = true;
        Ok(())
    }

    /// Revokes device authorization.
    pub fn deauthorize(&mut self) {
        self.authorized = false;
    }
}

// -------------------------------------------------------------------
// ControllerState
// -------------------------------------------------------------------

/// NHI controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ControllerState {
    /// Controller not initialized.
    #[default]
    Uninitialized,
    /// Initializing.
    Initializing,
    /// Ready for operation.
    Ready,
    /// In low-power state.
    Suspended,
    /// Error state.
    Error,
}

// -------------------------------------------------------------------
// MMIO helpers
// -------------------------------------------------------------------

/// Reads a u32 from MMIO.
///
/// # Safety
///
/// The caller must ensure `addr` is a valid MMIO register address.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Writes a u32 to MMIO.
///
/// # Safety
///
/// The caller must ensure `addr` is a valid MMIO register address.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// -------------------------------------------------------------------
// TbtController
// -------------------------------------------------------------------

/// Thunderbolt/USB4 NHI host controller.
///
/// Manages rings, tunnels, paths, and connected devices for a
/// single Thunderbolt host controller instance.
pub struct TbtController {
    /// MMIO base address.
    pub mmio_base: u64,
    /// Controller state.
    pub state: ControllerState,
    /// Controller generation.
    pub generation: DeviceGeneration,
    /// TX rings.
    tx_rings: [TbtRing; MAX_RINGS],
    /// RX rings.
    rx_rings: [TbtRing; MAX_RINGS],
    /// Number of configured TX rings.
    tx_ring_count: usize,
    /// Number of configured RX rings.
    rx_ring_count: usize,
    /// Active tunnels.
    tunnels: [TbtTunnel; MAX_TUNNELS],
    /// Number of active tunnels.
    tunnel_count: usize,
    /// Configured paths.
    paths: [TbtPath; MAX_PATHS],
    /// Number of paths.
    path_count: usize,
    /// Connected devices.
    devices: [TbtDevice; MAX_DEVICES],
    /// Number of connected devices.
    device_count: usize,
    /// Security level (0=none, 1=user, 2=secure, 3=dponly).
    pub security_level: u8,
}

impl TbtController {
    /// Creates a new controller at the given MMIO base.
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            state: ControllerState::Uninitialized,
            generation: DeviceGeneration::Usb4,
            tx_rings: [const { TbtRing::new() }; MAX_RINGS],
            rx_rings: [const { TbtRing::new() }; MAX_RINGS],
            tx_ring_count: 0,
            rx_ring_count: 0,
            tunnels: [const { TbtTunnel::new() }; MAX_TUNNELS],
            tunnel_count: 0,
            paths: [const { TbtPath::new() }; MAX_PATHS],
            path_count: 0,
            devices: [const { TbtDevice::new() }; MAX_DEVICES],
            device_count: 0,
            security_level: 0,
        }
    }

    /// Returns the MMIO register address.
    fn reg_addr(&self, offset: u32) -> u64 {
        self.mmio_base.wrapping_add(offset as u64)
    }

    /// Initializes the controller hardware.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        self.state = ControllerState::Initializing;

        // Check interrupt status (probe for hardware presence)
        let int_addr = self.reg_addr(NHI_INT_STATUS);
        // SAFETY: int_addr is a valid NHI register
        let _sts = unsafe { mmio_read32(int_addr) };

        // Clear pending interrupts
        // SAFETY: int_addr is a valid NHI register
        unsafe { mmio_write32(int_addr, 0xFFFF_FFFF) };

        self.state = ControllerState::Ready;
        Ok(())
    }

    /// Non-x86_64 stub for init.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        self.state = ControllerState::Ready;
        Ok(())
    }

    // --- Rings ---

    /// Allocates and initializes a TX ring.
    pub fn alloc_tx_ring(&mut self, phys_base: u64, hop_id: u8) -> Result<u8> {
        if self.tx_ring_count >= MAX_RINGS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.tx_ring_count;
        self.tx_rings[idx].init(idx as u8, RingDirection::Tx, phys_base);
        self.tx_rings[idx].hop_id = hop_id;
        self.tx_ring_count += 1;
        Ok(idx as u8)
    }

    /// Allocates and initializes an RX ring.
    pub fn alloc_rx_ring(&mut self, phys_base: u64, hop_id: u8) -> Result<u8> {
        if self.rx_ring_count >= MAX_RINGS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.rx_ring_count;
        self.rx_rings[idx].init(idx as u8, RingDirection::Rx, phys_base);
        self.rx_rings[idx].hop_id = hop_id;
        self.rx_ring_count += 1;
        Ok(idx as u8)
    }

    /// Returns a mutable reference to a TX ring.
    pub fn tx_ring_mut(&mut self, index: u8) -> Option<&mut TbtRing> {
        if (index as usize) < self.tx_ring_count {
            Some(&mut self.tx_rings[index as usize])
        } else {
            None
        }
    }

    /// Returns a mutable reference to an RX ring.
    pub fn rx_ring_mut(&mut self, index: u8) -> Option<&mut TbtRing> {
        if (index as usize) < self.rx_ring_count {
            Some(&mut self.rx_rings[index as usize])
        } else {
            None
        }
    }

    // --- Tunnels ---

    /// Creates a new tunnel.
    pub fn create_tunnel(
        &mut self,
        tunnel_type: TunnelType,
        src_port: u8,
        dst_port: u8,
        bandwidth_mbps: u32,
    ) -> Result<u16> {
        if self.tunnel_count >= MAX_TUNNELS {
            return Err(Error::OutOfMemory);
        }
        let id = (self.tunnel_count + 1) as u16;
        let tunnel = &mut self.tunnels[self.tunnel_count];
        tunnel.id = id;
        tunnel.tunnel_type = tunnel_type;
        tunnel.src_port = src_port;
        tunnel.dst_port = dst_port;
        tunnel.bandwidth_mbps = bandwidth_mbps;
        self.tunnel_count += 1;
        Ok(id)
    }

    /// Activates a tunnel by ID.
    pub fn activate_tunnel(&mut self, tunnel_id: u16) -> Result<()> {
        for i in 0..self.tunnel_count {
            if self.tunnels[i].id == tunnel_id {
                return self.tunnels[i].activate();
            }
        }
        Err(Error::NotFound)
    }

    /// Deactivates a tunnel by ID.
    pub fn deactivate_tunnel(&mut self, tunnel_id: u16) -> Result<()> {
        for i in 0..self.tunnel_count {
            if self.tunnels[i].id == tunnel_id {
                self.tunnels[i].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active tunnels.
    pub fn active_tunnel_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.tunnel_count {
            if self.tunnels[i].state == TunnelState::Active {
                count += 1;
            }
        }
        count
    }

    // --- Paths ---

    /// Creates a new path and returns its ID.
    pub fn create_path(&mut self) -> Result<u16> {
        if self.path_count >= MAX_PATHS {
            return Err(Error::OutOfMemory);
        }
        let id = (self.path_count + 1) as u16;
        self.paths[self.path_count].id = id;
        self.path_count += 1;
        Ok(id)
    }

    /// Adds a hop to a path.
    pub fn add_path_hop(&mut self, path_id: u16, hop: PathHop) -> Result<()> {
        for i in 0..self.path_count {
            if self.paths[i].id == path_id {
                return self.paths[i].add_hop(hop);
            }
        }
        Err(Error::NotFound)
    }

    /// Activates a path.
    pub fn activate_path(&mut self, path_id: u16) -> Result<()> {
        for i in 0..self.path_count {
            if self.paths[i].id == path_id {
                return self.paths[i].activate();
            }
        }
        Err(Error::NotFound)
    }

    // --- Devices ---

    /// Handles a device connection event.
    pub fn device_connected(
        &mut self,
        route: u64,
        vendor_id: u16,
        device_id: u16,
        generation: DeviceGeneration,
    ) -> Result<usize> {
        if self.device_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate route
        for i in 0..self.device_count {
            if self.devices[i].route == route && self.devices[i].state != DeviceState::Disconnected
            {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.device_count;
        self.devices[idx].route = route;
        self.devices[idx].vendor_id = vendor_id;
        self.devices[idx].device_id = device_id;
        self.devices[idx].generation = generation;
        self.devices[idx].state = DeviceState::Connected;
        self.device_count += 1;
        Ok(idx)
    }

    /// Handles a device disconnection event.
    pub fn device_disconnected(&mut self, route: u64) -> Result<()> {
        for i in 0..self.device_count {
            if self.devices[i].route == route {
                self.devices[i].state = DeviceState::Disconnected;
                self.devices[i].authorized = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Authorizes a device by route string.
    pub fn authorize_device(&mut self, route: u64) -> Result<()> {
        for i in 0..self.device_count {
            if self.devices[i].route == route {
                return self.devices[i].authorize();
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of connected devices.
    pub fn connected_device_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.device_count {
            if self.devices[i].state == DeviceState::Connected {
                count += 1;
            }
        }
        count
    }

    /// Returns a reference to a device by index.
    pub fn get_device(&self, index: usize) -> Option<&TbtDevice> {
        if index < self.device_count {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Handles an interrupt from the NHI controller.
    #[cfg(target_arch = "x86_64")]
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        let addr = self.reg_addr(NHI_INT_STATUS);
        // SAFETY: addr is a valid NHI interrupt status register
        let status = unsafe { mmio_read32(addr) };
        if status == 0 {
            return Ok(0);
        }
        // Acknowledge all interrupts
        // SAFETY: addr is a valid NHI register
        unsafe { mmio_write32(addr, status) };
        Ok(status)
    }

    /// Non-x86_64 stub for handle_interrupt.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        Ok(0)
    }

    /// Suspends the controller (power management).
    pub fn suspend(&mut self) -> Result<()> {
        // Disable all rings
        for i in 0..self.tx_ring_count {
            self.tx_rings[i].disable();
        }
        for i in 0..self.rx_ring_count {
            self.rx_rings[i].disable();
        }
        self.state = ControllerState::Suspended;
        Ok(())
    }

    /// Resumes the controller from suspend.
    pub fn resume(&mut self) -> Result<()> {
        self.state = ControllerState::Ready;
        Ok(())
    }

    /// Returns the controller state.
    pub fn controller_state(&self) -> ControllerState {
        self.state
    }
}

// -------------------------------------------------------------------
// TbtControllerRegistry
// -------------------------------------------------------------------

/// System-wide registry of Thunderbolt controllers.
pub struct TbtControllerRegistry {
    /// Registered controller MMIO bases.
    controllers: [Option<u64>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for TbtControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TbtControllerRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a controller by MMIO base.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        for i in 0..self.count {
            if self.controllers[i] == Some(mmio_base) {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.count;
        self.controllers[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Returns the MMIO base at the given index.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < MAX_CONTROLLERS {
            self.controllers[index]
        } else {
            None
        }
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
