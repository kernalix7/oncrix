// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network namespace support for the ONCRIX kernel.
//!
//! Network namespaces provide isolated instances of the network stack,
//! including their own set of network devices, routing tables, and
//! loopback interfaces. Processes in different network namespaces see
//! completely independent network environments.
//!
//! This module implements:
//! - [`NetDevice`] — a virtual or physical network device within a namespace
//! - [`NetNsRoute`] — a routing table entry scoped to a namespace
//! - [`NetNamespace`] — an isolated network namespace with devices, routes, and PIDs
//! - [`NetNsRegistry`] — system-wide management of network namespaces

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of devices per network namespace.
const MAX_DEVICES: usize = 16;

/// Maximum number of routes per network namespace.
const MAX_ROUTES: usize = 32;

/// Maximum number of PIDs per network namespace.
const MAX_PIDS: usize = 32;

/// Maximum number of network namespaces system-wide.
const MAX_NAMESPACES: usize = 32;

/// Maximum length of a device name.
const DEV_NAME_LEN: usize = 16;

/// Maximum length of a namespace name.
const NS_NAME_LEN: usize = 32;

// ── NetDevice ─────────────────────────────────────────────────────

/// A network device within a network namespace.
///
/// Each device has a unique identifier, a human-readable name,
/// MAC and IPv4 addresses, MTU, and link state.
#[derive(Debug, Clone, Copy)]
pub struct NetDevice {
    /// Unique device identifier.
    id: u64,
    /// Device name (e.g., `eth0`, `lo`).
    name: [u8; DEV_NAME_LEN],
    /// Length of the device name.
    name_len: usize,
    /// MAC address (6 bytes).
    mac: [u8; 6],
    /// IPv4 address in host byte order.
    ipv4: u32,
    /// Subnet mask in host byte order.
    netmask: u32,
    /// Maximum transmission unit.
    mtu: u32,
    /// Whether the device link is up.
    up: bool,
    /// Whether this slot is in use.
    in_use: bool,
}

impl Default for NetDevice {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl NetDevice {
    /// An empty (unused) device slot.
    const EMPTY: Self = Self {
        id: 0,
        name: [0u8; DEV_NAME_LEN],
        name_len: 0,
        mac: [0u8; 6],
        ipv4: 0,
        netmask: 0,
        mtu: 0,
        up: false,
        in_use: false,
    };

    /// Return the device identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the MAC address.
    pub const fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Return the IPv4 address.
    pub const fn ipv4(&self) -> u32 {
        self.ipv4
    }

    /// Return the subnet mask.
    pub const fn netmask(&self) -> u32 {
        self.netmask
    }

    /// Return the MTU.
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Return whether the link is up.
    pub const fn is_up(&self) -> bool {
        self.up
    }

    /// Return whether this slot is in use.
    pub const fn is_in_use(&self) -> bool {
        self.in_use
    }
}

// ── NetNsRoute ────────────────────────────────────────────────────

/// A routing table entry scoped to a network namespace.
///
/// Routes are matched by destination address and mask; the most
/// specific (longest prefix) match wins. A gateway of `0` indicates
/// a directly connected network.
#[derive(Debug, Clone, Copy)]
pub struct NetNsRoute {
    /// Destination network address.
    dst: u32,
    /// Gateway address (0 for directly connected).
    gateway: u32,
    /// Network mask.
    mask: u32,
    /// Outgoing device identifier.
    device_id: u64,
    /// Route metric (lower is preferred).
    metric: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl Default for NetNsRoute {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl NetNsRoute {
    /// An empty (unused) route slot.
    const EMPTY: Self = Self {
        dst: 0,
        gateway: 0,
        mask: 0,
        device_id: 0,
        metric: 0,
        in_use: false,
    };

    /// Return the destination network address.
    pub const fn dst(&self) -> u32 {
        self.dst
    }

    /// Return the gateway address.
    pub const fn gateway(&self) -> u32 {
        self.gateway
    }

    /// Return the network mask.
    pub const fn mask(&self) -> u32 {
        self.mask
    }

    /// Return the outgoing device identifier.
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Return the route metric.
    pub const fn metric(&self) -> u32 {
        self.metric
    }

    /// Return whether this slot is in use.
    pub const fn is_in_use(&self) -> bool {
        self.in_use
    }
}

// ── NetNamespace ──────────────────────────────────────────────────

/// An isolated network namespace.
///
/// Each namespace contains its own set of network devices, routing
/// table, loopback interface, default gateway, and a list of
/// process IDs that belong to it.
#[derive(Debug)]
pub struct NetNamespace {
    /// Unique namespace identifier.
    id: u64,
    /// Namespace name (e.g., `default`, `container0`).
    name: [u8; NS_NAME_LEN],
    /// Length of the namespace name.
    name_len: usize,
    /// Network devices in this namespace.
    devices: [NetDevice; MAX_DEVICES],
    /// Number of active devices.
    dev_count: usize,
    /// Routing table entries.
    routes: [NetNsRoute; MAX_ROUTES],
    /// Number of active routes.
    route_count: usize,
    /// Loopback device identifier.
    loopback_id: u64,
    /// Default gateway IPv4 address.
    default_gw: u32,
    /// Process IDs belonging to this namespace.
    pids: [u64; MAX_PIDS],
    /// Number of active PIDs.
    pid_count: usize,
    /// Whether this namespace slot is in use.
    in_use: bool,
}

impl Default for NetNamespace {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl NetNamespace {
    /// An empty (unused) namespace slot.
    const EMPTY: Self = Self {
        id: 0,
        name: [0u8; NS_NAME_LEN],
        name_len: 0,
        devices: [NetDevice::EMPTY; MAX_DEVICES],
        dev_count: 0,
        routes: [NetNsRoute::EMPTY; MAX_ROUTES],
        route_count: 0,
        loopback_id: 0,
        default_gw: 0,
        pids: [0u64; MAX_PIDS],
        pid_count: 0,
        in_use: false,
    };

    /// Return the namespace identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the namespace name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the number of active devices.
    pub const fn dev_count(&self) -> usize {
        self.dev_count
    }

    /// Return the number of active routes.
    pub const fn route_count(&self) -> usize {
        self.route_count
    }

    /// Return the loopback device identifier.
    pub const fn loopback_id(&self) -> u64 {
        self.loopback_id
    }

    /// Return the default gateway address.
    pub const fn default_gw(&self) -> u32 {
        self.default_gw
    }

    /// Return the number of PIDs in this namespace.
    pub const fn pid_count(&self) -> usize {
        self.pid_count
    }

    /// Return whether this namespace slot is in use.
    pub const fn is_in_use(&self) -> bool {
        self.in_use
    }

    /// Add a network device to this namespace.
    ///
    /// Creates a new device with the given name and MAC address,
    /// assigns it a unique ID from the registry's device counter,
    /// and returns that ID.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is empty or too long
    /// - `OutOfMemory` if the device table is full
    pub fn add_device(&mut self, name: &[u8], mac: &[u8; 6]) -> Result<u64> {
        if name.is_empty() || name.len() > DEV_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.dev_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot and assign a device ID based on position.
        let slot = self
            .devices
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        // Generate a unique ID from namespace ID and slot index.
        let dev_id = self
            .id
            .wrapping_mul(1000)
            .wrapping_add(slot as u64)
            .wrapping_add(1);

        let mut dev = NetDevice::EMPTY;
        dev.id = dev_id;
        dev.name[..name.len()].copy_from_slice(name);
        dev.name_len = name.len();
        dev.mac = *mac;
        dev.mtu = 1500;
        dev.in_use = true;

        self.devices[slot] = dev;
        self.dev_count = self.dev_count.saturating_add(1);
        Ok(dev_id)
    }

    /// Remove a network device from this namespace by device ID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no device with the given ID exists
    pub fn remove_device(&mut self, dev_id: u64) -> Result<()> {
        let slot = self
            .devices
            .iter()
            .position(|d| d.in_use && d.id == dev_id)
            .ok_or(Error::NotFound)?;

        self.devices[slot] = NetDevice::EMPTY;
        self.dev_count = self.dev_count.saturating_sub(1);
        Ok(())
    }

    /// Move a device out of this namespace, returning its data.
    ///
    /// The device is removed from this namespace. The caller is
    /// responsible for adding it to the target namespace via
    /// [`NetNsRegistry::move_device`].
    ///
    /// # Errors
    ///
    /// - `NotFound` if no device with the given ID exists
    /// - `InvalidArgument` if `target_ns_id` matches this namespace
    pub fn move_device_to(&mut self, dev_id: u64, target_ns_id: u64) -> Result<()> {
        if target_ns_id == self.id {
            return Err(Error::InvalidArgument);
        }
        self.remove_device(dev_id)
    }

    /// Add a routing table entry.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the routing table is full
    pub fn add_route(&mut self, dst: u32, gateway: u32, mask: u32, device_id: u64) -> Result<()> {
        if self.route_count >= MAX_ROUTES {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .routes
            .iter()
            .position(|r| !r.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.routes[slot] = NetNsRoute {
            dst,
            gateway,
            mask,
            device_id,
            metric: 0,
            in_use: true,
        };
        self.route_count = self.route_count.saturating_add(1);
        Ok(())
    }

    /// Delete a routing table entry matching destination and mask.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching route exists
    pub fn del_route(&mut self, dst: u32, mask: u32) -> Result<()> {
        let slot = self
            .routes
            .iter()
            .position(|r| r.in_use && r.dst == dst && r.mask == mask)
            .ok_or(Error::NotFound)?;

        self.routes[slot] = NetNsRoute::EMPTY;
        self.route_count = self.route_count.saturating_sub(1);
        Ok(())
    }

    /// Add a process ID to this namespace.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the PID table is full
    /// - `AlreadyExists` if the PID is already present
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        // Check for duplicate.
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count = self.pid_count.saturating_add(1);
        Ok(())
    }

    /// Remove a process ID from this namespace.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the PID is not present
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let idx = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        // Swap-remove: replace with last element.
        let last = self.pid_count.saturating_sub(1);
        self.pids[idx] = self.pids[last];
        self.pids[last] = 0;
        self.pid_count = last;
        Ok(())
    }

    /// Look up the best matching route for a destination address.
    ///
    /// Returns the route with the longest matching prefix (most
    /// specific mask). Returns `None` if no route matches.
    pub fn lookup_route(&self, dst: u32) -> Option<&NetNsRoute> {
        let mut best: Option<&NetNsRoute> = None;
        let mut best_mask: u32 = 0;

        for route in &self.routes {
            if route.in_use && (dst & route.mask) == (route.dst & route.mask) {
                // Prefer the most specific (largest) mask, then lowest metric.
                if route.mask > best_mask
                    || (route.mask == best_mask && best.is_some_and(|b| route.metric < b.metric))
                {
                    best = Some(route);
                    best_mask = route.mask;
                }
            }
        }
        best
    }

    /// Look up a device by its identifier.
    ///
    /// Returns `None` if no device with the given ID exists.
    pub fn get_device(&self, id: u64) -> Option<&NetDevice> {
        self.devices.iter().find(|d| d.in_use && d.id == id)
    }
}

// ── NetNsRegistry ─────────────────────────────────────────────────

/// System-wide registry of network namespaces.
///
/// Manages creation, destruction, device movement between namespaces,
/// and process membership tracking. The registry holds up to
/// [`MAX_NAMESPACES`] concurrent network namespaces.
pub struct NetNsRegistry {
    /// Storage for network namespaces.
    namespaces: [NetNamespace; MAX_NAMESPACES],
    /// Number of active namespaces.
    count: usize,
    /// Identifier of the initial (default) network namespace.
    init_ns_id: u64,
    /// Monotonically increasing ID counter.
    next_id: u64,
}

impl Default for NetNsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NetNsRegistry {
    /// Create an empty network namespace registry.
    pub const fn new() -> Self {
        Self {
            namespaces: [NetNamespace::EMPTY; MAX_NAMESPACES],
            count: 0,
            init_ns_id: 0,
            next_id: 1,
        }
    }

    /// Return the number of active namespaces.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry contains no namespaces.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the initial namespace identifier.
    pub const fn init_ns_id(&self) -> u64 {
        self.init_ns_id
    }

    /// Allocate the next unique namespace ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Create a new network namespace with the given name.
    ///
    /// Returns the newly assigned namespace ID. The first namespace
    /// created becomes the initial (default) namespace.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is empty or too long
    /// - `OutOfMemory` if the registry is full
    pub fn create(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > NS_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_NAMESPACES {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .namespaces
            .iter()
            .position(|ns| !ns.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.alloc_id();
        let mut ns = NetNamespace::EMPTY;
        ns.id = id;
        ns.name[..name.len()].copy_from_slice(name);
        ns.name_len = name.len();
        ns.in_use = true;

        self.namespaces[slot] = ns;
        self.count = self.count.saturating_add(1);

        // First namespace becomes the init namespace.
        if self.count == 1 {
            self.init_ns_id = id;
        }

        Ok(id)
    }

    /// Destroy a network namespace.
    ///
    /// The namespace must have no remaining PIDs (processes must
    /// leave before destruction).
    ///
    /// # Errors
    ///
    /// - `NotFound` if no namespace with the given ID exists
    /// - `Busy` if the namespace still has processes
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let slot = self
            .namespaces
            .iter()
            .position(|ns| ns.in_use && ns.id == id)
            .ok_or(Error::NotFound)?;

        if self.namespaces[slot].pid_count > 0 {
            return Err(Error::Busy);
        }

        self.namespaces[slot] = NetNamespace::EMPTY;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Move a network device from one namespace to another.
    ///
    /// # Errors
    ///
    /// - `NotFound` if either namespace or the device does not exist
    /// - `InvalidArgument` if source and target are the same
    pub fn move_device(&mut self, from_ns: u64, dev_id: u64, to_ns: u64) -> Result<()> {
        if from_ns == to_ns {
            return Err(Error::InvalidArgument);
        }

        // Find the device in the source namespace and extract its data.
        let src_idx = self
            .namespaces
            .iter()
            .position(|ns| ns.in_use && ns.id == from_ns)
            .ok_or(Error::NotFound)?;

        let dev = {
            let src = &self.namespaces[src_idx];
            let d = src
                .devices
                .iter()
                .find(|d| d.in_use && d.id == dev_id)
                .ok_or(Error::NotFound)?;
            *d
        };

        // Verify target namespace exists and has room.
        let dst_idx = self
            .namespaces
            .iter()
            .position(|ns| ns.in_use && ns.id == to_ns)
            .ok_or(Error::NotFound)?;

        if self.namespaces[dst_idx].dev_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }

        let dst_slot = self.namespaces[dst_idx]
            .devices
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        // Remove from source.
        self.namespaces[src_idx].remove_device(dev_id)?;

        // Add to destination, preserving the device data.
        self.namespaces[dst_idx].devices[dst_slot] = dev;
        self.namespaces[dst_idx].dev_count = self.namespaces[dst_idx].dev_count.saturating_add(1);

        Ok(())
    }

    /// Add a process to a network namespace.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace does not exist
    /// - `OutOfMemory` if the namespace's PID table is full
    /// - `AlreadyExists` if the PID is already in the namespace
    pub fn enter(&mut self, ns_id: u64, pid: u64) -> Result<()> {
        let ns = self.get_mut(ns_id).ok_or(Error::NotFound)?;
        ns.add_pid(pid)
    }

    /// Remove a process from a network namespace.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace or PID does not exist
    pub fn leave(&mut self, ns_id: u64, pid: u64) -> Result<()> {
        let ns = self.get_mut(ns_id).ok_or(Error::NotFound)?;
        ns.remove_pid(pid)
    }

    /// Look up a namespace by ID (immutable).
    pub fn get(&self, id: u64) -> Option<&NetNamespace> {
        self.namespaces.iter().find(|ns| ns.in_use && ns.id == id)
    }

    /// Look up a namespace by ID (mutable).
    pub fn get_mut(&mut self, id: u64) -> Option<&mut NetNamespace> {
        self.namespaces
            .iter_mut()
            .find(|ns| ns.in_use && ns.id == id)
    }

    /// Find which namespace a given PID belongs to.
    ///
    /// Returns the namespace ID, or `None` if the PID is not in any
    /// namespace.
    pub fn get_for_pid(&self, pid: u64) -> Option<u64> {
        for ns in &self.namespaces {
            if ns.in_use && ns.pids[..ns.pid_count].contains(&pid) {
                return Some(ns.id);
            }
        }
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_destroy_namespace() {
        let mut reg = NetNsRegistry::new();
        assert!(reg.is_empty());

        let id = reg.create(b"default").unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.init_ns_id(), id);

        reg.destroy(id).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn test_destroy_busy_namespace() {
        let mut reg = NetNsRegistry::new();
        let id = reg.create(b"test").unwrap();
        reg.enter(id, 100).unwrap();

        // Should fail because namespace still has a PID.
        assert!(reg.destroy(id).is_err());

        reg.leave(id, 100).unwrap();
        reg.destroy(id).unwrap();
    }

    #[test]
    fn test_add_remove_device() {
        let mut reg = NetNsRegistry::new();
        let ns_id = reg.create(b"ns0").unwrap();
        let ns = reg.get_mut(ns_id).unwrap();

        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dev_id = ns.add_device(b"eth0", &mac).unwrap();
        assert_eq!(ns.dev_count(), 1);
        assert!(ns.get_device(dev_id).is_some());

        ns.remove_device(dev_id).unwrap();
        assert_eq!(ns.dev_count(), 0);
        assert!(ns.get_device(dev_id).is_none());
    }

    #[test]
    fn test_routing() {
        let mut reg = NetNsRegistry::new();
        let ns_id = reg.create(b"ns0").unwrap();
        let ns = reg.get_mut(ns_id).unwrap();

        // Add a default route and a more specific route.
        ns.add_route(0, 0x0A000001, 0, 1).unwrap(); // default via 10.0.0.1
        ns.add_route(0xC0A80100, 0, 0xFFFFFF00, 2).unwrap(); // 192.168.1.0/24 direct

        // 192.168.1.50 should match the /24 route.
        let route = ns.lookup_route(0xC0A80132).unwrap();
        assert_eq!(route.device_id(), 2);

        // 10.0.0.5 should match the default route.
        let route = ns.lookup_route(0x0A000005).unwrap();
        assert_eq!(route.device_id(), 1);

        // Delete the specific route.
        ns.del_route(0xC0A80100, 0xFFFFFF00).unwrap();
        assert_eq!(ns.route_count(), 1);
    }

    #[test]
    fn test_pid_management() {
        let mut reg = NetNsRegistry::new();
        let ns_id = reg.create(b"ns0").unwrap();

        reg.enter(ns_id, 1).unwrap();
        reg.enter(ns_id, 2).unwrap();

        assert_eq!(reg.get_for_pid(1), Some(ns_id));
        assert_eq!(reg.get_for_pid(2), Some(ns_id));
        assert_eq!(reg.get_for_pid(999), None);

        reg.leave(ns_id, 1).unwrap();
        assert_eq!(reg.get_for_pid(1), None);
    }

    #[test]
    fn test_move_device_between_namespaces() {
        let mut reg = NetNsRegistry::new();
        let ns1 = reg.create(b"ns1").unwrap();
        let ns2 = reg.create(b"ns2").unwrap();

        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dev_id = reg.get_mut(ns1).unwrap().add_device(b"eth0", &mac).unwrap();

        reg.move_device(ns1, dev_id, ns2).unwrap();

        assert!(reg.get(ns1).unwrap().get_device(dev_id).is_none());
        assert!(reg.get(ns2).unwrap().get_device(dev_id).is_some());
    }

    #[test]
    fn test_duplicate_pid() {
        let mut reg = NetNsRegistry::new();
        let ns_id = reg.create(b"ns0").unwrap();
        reg.enter(ns_id, 42).unwrap();
        assert!(reg.enter(ns_id, 42).is_err());
    }
}
