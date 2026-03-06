// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI-to-PCI bridge controller management.
//!
//! Handles enumeration, configuration, and runtime management of
//! PCI-to-PCI (P2P) bridges as defined in the PCI Local Bus
//! Specification 3.0, Section 3.2 (Type 1 Configuration Header).
//! Each bridge connects a primary bus to a secondary bus and
//! controls address routing through programmable I/O and memory
//! windows.
//!
//! # Architecture
//!
//! - [`BusRange`] — secondary bus number range (secondary..subordinate)
//! - [`MemoryWindow`] — memory-mapped I/O window for address routing
//! - [`IoWindow`] — I/O port window for address routing
//! - [`PrefetchWindow`] — prefetchable memory window (64-bit capable)
//! - [`BridgeConfig`] — full configuration for a single bridge
//! - [`BridgeState`] — runtime state of a bridge
//! - [`PciBridge`] — a single PCI-to-PCI bridge device
//! - [`PciBridgeController`] — manages multiple bridges
//! - [`PciBridgeRegistry`] — system-wide registry of bridge controllers
//!
//! Reference: PCI Local Bus Specification 3.0, Section 3.2;
//! PCI Express Base Specification 5.0, Section 7.5.1.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of bridges per controller.
const MAX_BRIDGES: usize = 32;

/// Maximum number of bridge controllers in the registry.
const MAX_BRIDGE_CONTROLLERS: usize = 4;

/// PCI Type 1 header configuration register offsets.
const CFG_PRIMARY_BUS: u8 = 0x18;
/// Secondary bus number register offset.
const CFG_SECONDARY_BUS: u8 = 0x19;
/// Subordinate bus number register offset.
const CFG_SUBORDINATE_BUS: u8 = 0x1A;
/// Secondary latency timer register offset.
const CFG_SEC_LATENCY: u8 = 0x1B;
/// I/O base register offset.
const CFG_IO_BASE: u8 = 0x1C;
/// I/O limit register offset.
const CFG_IO_LIMIT: u8 = 0x1D;
/// Memory base register offset.
const CFG_MEM_BASE: u8 = 0x20;
/// Memory limit register offset.
const CFG_MEM_LIMIT: u8 = 0x22;
/// Prefetchable memory base register offset.
const CFG_PREF_MEM_BASE: u8 = 0x24;
/// Prefetchable memory limit register offset.
const CFG_PREF_MEM_LIMIT: u8 = 0x26;
/// Bridge control register offset.
const CFG_BRIDGE_CONTROL: u8 = 0x3E;

/// Bridge control bit: enable ISA I/O filtering.
const BRIDGE_CTL_ISA_ENABLE: u16 = 1 << 2;
/// Bridge control bit: enable VGA palette snooping.
const BRIDGE_CTL_VGA_ENABLE: u16 = 1 << 3;
/// Bridge control bit: enable SERR# forwarding.
const BRIDGE_CTL_SERR_ENABLE: u16 = 1 << 1;
/// Bridge control bit: secondary bus reset.
const BRIDGE_CTL_BUS_RESET: u16 = 1 << 6;

/// Memory window alignment (1 MiB).
const MEM_WINDOW_ALIGNMENT: u64 = 1024 * 1024;

/// I/O window alignment (4 KiB).
const IO_WINDOW_ALIGNMENT: u32 = 4096;

// ---------------------------------------------------------------------------
// BusRange
// ---------------------------------------------------------------------------

/// Secondary bus number range managed by a PCI-to-PCI bridge.
///
/// The bridge routes configuration cycles for buses in the range
/// `[secondary, subordinate]` to its secondary interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BusRange {
    /// Primary bus number (upstream side of the bridge).
    pub primary: u8,
    /// Secondary bus number (downstream side of the bridge).
    pub secondary: u8,
    /// Subordinate bus number (highest bus behind this bridge).
    pub subordinate: u8,
}

impl BusRange {
    /// Create a new bus range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `secondary` is zero,
    /// `secondary > subordinate`, or `primary >= secondary`.
    pub fn new(primary: u8, secondary: u8, subordinate: u8) -> Result<Self> {
        if secondary == 0 || secondary > subordinate || primary >= secondary {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            primary,
            secondary,
            subordinate,
        })
    }

    /// Return the number of buses in this range (inclusive).
    pub fn bus_count(&self) -> u8 {
        self.subordinate.saturating_sub(self.secondary) + 1
    }

    /// Check whether a given bus number falls within this range.
    pub fn contains(&self, bus: u8) -> bool {
        bus >= self.secondary && bus <= self.subordinate
    }

    /// Update the subordinate bus number.
    ///
    /// Used during recursive enumeration when additional bridges
    /// are found behind this one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `subordinate` is less
    /// than the current secondary bus.
    pub fn set_subordinate(&mut self, subordinate: u8) -> Result<()> {
        if subordinate < self.secondary {
            return Err(Error::InvalidArgument);
        }
        self.subordinate = subordinate;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemoryWindow
// ---------------------------------------------------------------------------

/// A non-prefetchable memory window for PCI bridge address routing.
///
/// The bridge forwards memory transactions whose addresses fall
/// within `[base, limit]` to the secondary bus. Both base and limit
/// are 1 MiB aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryWindow {
    /// Base address of the memory window (1 MiB aligned).
    pub base: u64,
    /// Limit address of the memory window (inclusive, 1 MiB aligned).
    pub limit: u64,
    /// Whether this window is currently enabled.
    pub enabled: bool,
}

impl MemoryWindow {
    /// Create a new memory window.
    ///
    /// Both `base` and `limit` must be 1 MiB aligned, and `limit`
    /// must be greater than or equal to `base`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if alignment or ordering
    /// constraints are violated.
    pub fn new(base: u64, limit: u64) -> Result<Self> {
        if base % MEM_WINDOW_ALIGNMENT != 0 || limit % MEM_WINDOW_ALIGNMENT != 0 {
            return Err(Error::InvalidArgument);
        }
        if limit < base {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            base,
            limit,
            enabled: false,
        })
    }

    /// Return the size of the memory window in bytes.
    pub fn size(&self) -> u64 {
        if self.limit >= self.base {
            self.limit - self.base + MEM_WINDOW_ALIGNMENT
        } else {
            0
        }
    }

    /// Check whether a physical address falls within this window.
    pub fn contains(&self, addr: u64) -> bool {
        self.enabled && addr >= self.base && addr <= self.limit + MEM_WINDOW_ALIGNMENT - 1
    }

    /// Enable the memory window.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the memory window.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

// ---------------------------------------------------------------------------
// IoWindow
// ---------------------------------------------------------------------------

/// An I/O port window for PCI bridge address routing.
///
/// The bridge forwards I/O transactions whose port addresses fall
/// within `[base, limit]` to the secondary bus. Both base and limit
/// are 4 KiB aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoWindow {
    /// Base port address of the I/O window (4 KiB aligned).
    pub base: u32,
    /// Limit port address of the I/O window (inclusive, 4 KiB aligned).
    pub limit: u32,
    /// Whether this window is currently enabled.
    pub enabled: bool,
}

impl IoWindow {
    /// Create a new I/O window.
    ///
    /// Both `base` and `limit` must be 4 KiB aligned, and `limit`
    /// must be greater than or equal to `base`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if alignment or ordering
    /// constraints are violated.
    pub fn new(base: u32, limit: u32) -> Result<Self> {
        if base % IO_WINDOW_ALIGNMENT != 0 || limit % IO_WINDOW_ALIGNMENT != 0 {
            return Err(Error::InvalidArgument);
        }
        if limit < base {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            base,
            limit,
            enabled: false,
        })
    }

    /// Return the size of the I/O window in bytes.
    pub fn size(&self) -> u32 {
        if self.limit >= self.base {
            self.limit - self.base + IO_WINDOW_ALIGNMENT
        } else {
            0
        }
    }

    /// Check whether a port address falls within this window.
    pub fn contains(&self, port: u32) -> bool {
        self.enabled && port >= self.base && port <= self.limit + IO_WINDOW_ALIGNMENT - 1
    }

    /// Enable the I/O window.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the I/O window.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

// ---------------------------------------------------------------------------
// PrefetchWindow
// ---------------------------------------------------------------------------

/// A prefetchable memory window for PCI bridge address routing.
///
/// Supports 64-bit base and limit addresses for large memory BARs.
/// Prefetchable windows allow the bridge to perform read-ahead
/// optimisations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefetchWindow {
    /// 64-bit base address (1 MiB aligned).
    pub base: u64,
    /// 64-bit limit address (inclusive, 1 MiB aligned).
    pub limit: u64,
    /// Whether this window supports 64-bit addressing.
    pub is_64bit: bool,
    /// Whether this window is currently enabled.
    pub enabled: bool,
}

impl PrefetchWindow {
    /// Create a new prefetchable memory window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if alignment or ordering
    /// constraints are violated.
    pub fn new(base: u64, limit: u64, is_64bit: bool) -> Result<Self> {
        if base % MEM_WINDOW_ALIGNMENT != 0 || limit % MEM_WINDOW_ALIGNMENT != 0 {
            return Err(Error::InvalidArgument);
        }
        if limit < base {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            base,
            limit,
            is_64bit,
            enabled: false,
        })
    }

    /// Return the size of the prefetchable window in bytes.
    pub fn size(&self) -> u64 {
        if self.limit >= self.base {
            self.limit - self.base + MEM_WINDOW_ALIGNMENT
        } else {
            0
        }
    }

    /// Check whether a physical address falls within this window.
    pub fn contains(&self, addr: u64) -> bool {
        self.enabled && addr >= self.base && addr <= self.limit + MEM_WINDOW_ALIGNMENT - 1
    }

    /// Enable the prefetchable window.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the prefetchable window.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

// ---------------------------------------------------------------------------
// BridgeConfig
// ---------------------------------------------------------------------------

/// Full configuration for a single PCI-to-PCI bridge.
///
/// Combines bus routing, memory window, I/O window, and
/// prefetchable window settings.
#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeConfig {
    /// Bus number range managed by this bridge.
    pub bus_range: BusRange,
    /// Non-prefetchable memory window.
    pub mem_window: MemoryWindow,
    /// I/O port window.
    pub io_window: IoWindow,
    /// Prefetchable memory window.
    pub pref_window: PrefetchWindow,
    /// Bridge control register value.
    pub bridge_control: u16,
    /// Secondary latency timer (in PCI clock cycles).
    pub secondary_latency: u8,
    /// Whether ISA I/O filtering is enabled.
    pub isa_enable: bool,
    /// Whether VGA palette snooping is enabled.
    pub vga_enable: bool,
    /// Whether SERR# forwarding is enabled.
    pub serr_enable: bool,
}

impl BridgeConfig {
    /// Create a bridge configuration from a bus range.
    ///
    /// Windows are initially disabled and must be configured
    /// separately via [`PciBridge::allocate_mem_window`] and
    /// related methods.
    pub fn from_bus_range(bus_range: BusRange) -> Self {
        Self {
            bus_range,
            mem_window: MemoryWindow::default(),
            io_window: IoWindow::default(),
            pref_window: PrefetchWindow::default(),
            bridge_control: 0,
            secondary_latency: 0,
            isa_enable: false,
            vga_enable: false,
            serr_enable: false,
        }
    }

    /// Compute the bridge control register value from flags.
    pub fn compute_bridge_control(&self) -> u16 {
        let mut ctl: u16 = 0;
        if self.isa_enable {
            ctl |= BRIDGE_CTL_ISA_ENABLE;
        }
        if self.vga_enable {
            ctl |= BRIDGE_CTL_VGA_ENABLE;
        }
        if self.serr_enable {
            ctl |= BRIDGE_CTL_SERR_ENABLE;
        }
        ctl
    }
}

// ---------------------------------------------------------------------------
// BridgeState
// ---------------------------------------------------------------------------

/// Runtime state of a PCI-to-PCI bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BridgeState {
    /// Bridge has been discovered but not yet configured.
    #[default]
    Discovered,
    /// Bridge bus numbers have been assigned.
    BusAssigned,
    /// Bridge windows have been configured.
    WindowsConfigured,
    /// Bridge is fully active and routing transactions.
    Active,
    /// Bridge has been disabled (e.g., for hotplug removal).
    Disabled,
    /// Bridge has encountered an error (e.g., secondary bus reset).
    Error,
}

// ---------------------------------------------------------------------------
// PciBridge
// ---------------------------------------------------------------------------

/// A single PCI-to-PCI bridge device.
///
/// Represents a Type 1 PCI header device that connects a primary
/// bus to a secondary bus and manages address routing through
/// configurable windows.
#[derive(Debug, Clone, Copy)]
pub struct PciBridge {
    /// Bridge identifier (unique within a controller).
    pub bridge_id: u8,
    /// PCI bus/device/function of the bridge itself.
    pub bus: u8,
    /// PCI device number.
    pub device: u8,
    /// PCI function number.
    pub function: u8,
    /// Vendor ID from PCI configuration space.
    pub vendor_id: u16,
    /// Device ID from PCI configuration space.
    pub device_id: u16,
    /// Bridge configuration (bus range, windows).
    pub config: BridgeConfig,
    /// Current runtime state.
    pub state: BridgeState,
    /// Whether hotplug is supported on the secondary bus.
    pub hotplug_capable: bool,
    /// Whether the bridge supports PCIe (vs. legacy PCI).
    pub is_pcie: bool,
    /// Number of devices discovered on the secondary bus.
    pub device_count: u8,
}

impl Default for PciBridge {
    fn default() -> Self {
        Self {
            bridge_id: 0,
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0,
            device_id: 0,
            config: BridgeConfig::default(),
            state: BridgeState::Discovered,
            hotplug_capable: false,
            is_pcie: false,
            device_count: 0,
        }
    }
}

impl PciBridge {
    /// Create a new PCI bridge descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `device > 31` or
    /// `function > 7`.
    pub fn new(
        bridge_id: u8,
        bus: u8,
        device: u8,
        function: u8,
        vendor_id: u16,
        device_id: u16,
    ) -> Result<Self> {
        if device > 31 || function > 7 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            bridge_id,
            bus,
            device,
            function,
            vendor_id,
            device_id,
            config: BridgeConfig::default(),
            state: BridgeState::Discovered,
            hotplug_capable: false,
            is_pcie: false,
            device_count: 0,
        })
    }

    /// Configure the bus range for this bridge.
    ///
    /// Assigns the primary, secondary, and subordinate bus numbers
    /// and transitions the bridge to [`BridgeState::BusAssigned`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the bus range is invalid.
    pub fn configure_bus(&mut self, primary: u8, secondary: u8, subordinate: u8) -> Result<()> {
        let range = BusRange::new(primary, secondary, subordinate)?;
        self.config.bus_range = range;
        self.state = BridgeState::BusAssigned;
        Ok(())
    }

    /// Allocate a non-prefetchable memory window.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the bus range has not been
    ///   assigned, or if the window parameters are invalid.
    pub fn allocate_mem_window(&mut self, base: u64, limit: u64) -> Result<()> {
        if self.state == BridgeState::Discovered {
            return Err(Error::InvalidArgument);
        }
        let window = MemoryWindow::new(base, limit)?;
        self.config.mem_window = window;
        self.config.mem_window.enable();
        Ok(())
    }

    /// Allocate an I/O port window.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the bus range has not been
    ///   assigned, or if the window parameters are invalid.
    pub fn allocate_io_window(&mut self, base: u32, limit: u32) -> Result<()> {
        if self.state == BridgeState::Discovered {
            return Err(Error::InvalidArgument);
        }
        let window = IoWindow::new(base, limit)?;
        self.config.io_window = window;
        self.config.io_window.enable();
        Ok(())
    }

    /// Allocate a prefetchable memory window.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the bus range has not been
    ///   assigned, or if the window parameters are invalid.
    pub fn allocate_pref_window(&mut self, base: u64, limit: u64, is_64bit: bool) -> Result<()> {
        if self.state == BridgeState::Discovered {
            return Err(Error::InvalidArgument);
        }
        let window = PrefetchWindow::new(base, limit, is_64bit)?;
        self.config.pref_window = window;
        self.config.pref_window.enable();
        Ok(())
    }

    /// Mark the bridge as fully configured and active.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the bridge has not
    /// had its bus range assigned.
    pub fn activate(&mut self) -> Result<()> {
        if self.state == BridgeState::Discovered {
            return Err(Error::InvalidArgument);
        }
        self.config.bridge_control = self.config.compute_bridge_control();
        self.state = BridgeState::Active;
        Ok(())
    }

    /// Disable the bridge, halting all transaction forwarding.
    ///
    /// Disables all windows but preserves the configuration for
    /// potential re-activation.
    pub fn disable(&mut self) {
        self.config.mem_window.disable();
        self.config.io_window.disable();
        self.config.pref_window.disable();
        self.state = BridgeState::Disabled;
    }

    /// Enable hotplug support on the secondary bus.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the bridge is not
    /// PCIe (legacy PCI bridges do not support native hotplug).
    pub fn enable_hotplug(&mut self) -> Result<()> {
        if !self.is_pcie {
            return Err(Error::InvalidArgument);
        }
        self.hotplug_capable = true;
        Ok(())
    }

    /// Issue a secondary bus reset.
    ///
    /// Sets the bus reset bit in the bridge control register. In a
    /// real implementation, the caller must wait for the reset to
    /// complete and then clear the bit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the bridge is not
    /// active.
    pub fn secondary_bus_reset(&mut self) -> Result<()> {
        if self.state != BridgeState::Active {
            return Err(Error::InvalidArgument);
        }
        self.config.bridge_control |= BRIDGE_CTL_BUS_RESET;
        // Stub: a real driver would write bridge_control to config
        // space, delay, then clear the reset bit.
        Ok(())
    }

    /// Check whether an address is routed through this bridge.
    ///
    /// Returns `true` if the address falls within any enabled
    /// memory window.
    pub fn routes_address(&self, addr: u64) -> bool {
        self.config.mem_window.contains(addr) || self.config.pref_window.contains(addr)
    }

    /// Check whether an I/O port is routed through this bridge.
    pub fn routes_io(&self, port: u32) -> bool {
        self.config.io_window.contains(port)
    }

    /// Return the secondary bus number.
    pub fn secondary_bus(&self) -> u8 {
        self.config.bus_range.secondary
    }

    /// Return the subordinate bus number.
    pub fn subordinate_bus(&self) -> u8 {
        self.config.bus_range.subordinate
    }
}

// ---------------------------------------------------------------------------
// PciBridgeController
// ---------------------------------------------------------------------------

/// PCI bridge controller managing multiple PCI-to-PCI bridges.
///
/// Provides enumeration, configuration, and runtime management
/// of bridges discovered during PCI bus scanning.
pub struct PciBridgeController {
    /// Controller identifier.
    pub controller_id: u8,
    /// Managed bridges.
    bridges: [PciBridge; MAX_BRIDGES],
    /// Number of configured bridges.
    bridge_count: usize,
    /// Whether the controller has been initialised.
    initialized: bool,
    /// Next bus number to assign during enumeration.
    next_bus: u8,
}

impl Default for PciBridgeController {
    fn default() -> Self {
        Self::new()
    }
}

impl PciBridgeController {
    /// Create an uninitialised bridge controller.
    pub const fn new() -> Self {
        Self {
            controller_id: 0,
            bridges: [PciBridge {
                bridge_id: 0,
                bus: 0,
                device: 0,
                function: 0,
                vendor_id: 0,
                device_id: 0,
                config: BridgeConfig {
                    bus_range: BusRange {
                        primary: 0,
                        secondary: 0,
                        subordinate: 0,
                    },
                    mem_window: MemoryWindow {
                        base: 0,
                        limit: 0,
                        enabled: false,
                    },
                    io_window: IoWindow {
                        base: 0,
                        limit: 0,
                        enabled: false,
                    },
                    pref_window: PrefetchWindow {
                        base: 0,
                        limit: 0,
                        is_64bit: false,
                        enabled: false,
                    },
                    bridge_control: 0,
                    secondary_latency: 0,
                    isa_enable: false,
                    vga_enable: false,
                    serr_enable: false,
                },
                state: BridgeState::Discovered,
                hotplug_capable: false,
                is_pcie: false,
                device_count: 0,
            }; MAX_BRIDGES],
            bridge_count: 0,
            initialized: false,
            next_bus: 1,
        }
    }

    /// Initialise the bridge controller.
    ///
    /// # Arguments
    ///
    /// * `controller_id` — Unique controller identifier.
    /// * `start_bus` — First bus number available for secondary bus
    ///   assignment (typically 1 for the root complex).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `start_bus` is zero.
    pub fn init(&mut self, controller_id: u8, start_bus: u8) -> Result<()> {
        if start_bus == 0 {
            return Err(Error::InvalidArgument);
        }
        self.controller_id = controller_id;
        self.next_bus = start_bus;
        self.initialized = true;
        Ok(())
    }

    /// Register a newly discovered bridge.
    ///
    /// The bridge is added to the controller's bridge table and
    /// assigned a secondary bus number from the available pool.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is not
    ///   initialised.
    /// - [`Error::OutOfMemory`] if the bridge table is full or
    ///   no bus numbers remain.
    pub fn enumerate(&mut self, mut bridge: PciBridge) -> Result<u8> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.bridge_count >= MAX_BRIDGES {
            return Err(Error::OutOfMemory);
        }
        if self.next_bus == 255 {
            return Err(Error::OutOfMemory);
        }

        let secondary = self.next_bus;
        self.next_bus = self.next_bus.saturating_add(1);

        // Assign bus range: primary = bridge's own bus, secondary and
        // subordinate initially set to the same value. Subordinate
        // will be updated after recursive enumeration.
        bridge.configure_bus(bridge.bus, secondary, secondary)?;
        bridge.bridge_id = self.bridge_count as u8;

        self.bridges[self.bridge_count] = bridge;
        self.bridge_count += 1;
        Ok(secondary)
    }

    /// Update the subordinate bus number for a bridge after
    /// recursive enumeration is complete.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no bridge with `bridge_id` exists.
    /// - [`Error::InvalidArgument`] if `subordinate` is less than
    ///   the bridge's secondary bus.
    pub fn update_subordinate(&mut self, bridge_id: u8, subordinate: u8) -> Result<()> {
        let bridge = self.find_bridge_mut(bridge_id).ok_or(Error::NotFound)?;
        bridge.config.bus_range.set_subordinate(subordinate)
    }

    /// Configure a bridge's memory window.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no bridge with `bridge_id` exists.
    /// - [`Error::InvalidArgument`] if window parameters are invalid.
    pub fn configure_mem_window(&mut self, bridge_id: u8, base: u64, limit: u64) -> Result<()> {
        let bridge = self.find_bridge_mut(bridge_id).ok_or(Error::NotFound)?;
        bridge.allocate_mem_window(base, limit)
    }

    /// Configure a bridge's I/O window.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no bridge with `bridge_id` exists.
    /// - [`Error::InvalidArgument`] if window parameters are invalid.
    pub fn configure_io_window(&mut self, bridge_id: u8, base: u32, limit: u32) -> Result<()> {
        let bridge = self.find_bridge_mut(bridge_id).ok_or(Error::NotFound)?;
        bridge.allocate_io_window(base, limit)
    }

    /// Activate a bridge after configuration is complete.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no bridge with `bridge_id` exists.
    /// - [`Error::InvalidArgument`] if the bridge is not configured.
    pub fn activate_bridge(&mut self, bridge_id: u8) -> Result<()> {
        let bridge = self.find_bridge_mut(bridge_id).ok_or(Error::NotFound)?;
        bridge.activate()
    }

    /// Enable hotplug on a PCIe bridge.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no bridge with `bridge_id` exists.
    /// - [`Error::InvalidArgument`] if the bridge is not PCIe.
    pub fn enable_hotplug(&mut self, bridge_id: u8) -> Result<()> {
        let bridge = self.find_bridge_mut(bridge_id).ok_or(Error::NotFound)?;
        bridge.enable_hotplug()
    }

    /// Find the bridge that routes a given memory address.
    ///
    /// Returns the first active bridge whose memory or prefetchable
    /// window contains the address.
    pub fn find_bridge_for_address(&self, addr: u64) -> Option<&PciBridge> {
        self.bridges[..self.bridge_count]
            .iter()
            .find(|b| b.state == BridgeState::Active && b.routes_address(addr))
    }

    /// Find the bridge that routes a given bus number.
    pub fn find_bridge_for_bus(&self, bus: u8) -> Option<&PciBridge> {
        self.bridges[..self.bridge_count]
            .iter()
            .find(|b| b.config.bus_range.contains(bus))
    }

    /// Find a bridge by its identifier.
    pub fn find_bridge(&self, bridge_id: u8) -> Option<&PciBridge> {
        self.bridges[..self.bridge_count]
            .iter()
            .find(|b| b.bridge_id == bridge_id)
    }

    /// Find a mutable reference to a bridge by its identifier.
    pub fn find_bridge_mut(&mut self, bridge_id: u8) -> Option<&mut PciBridge> {
        self.bridges[..self.bridge_count]
            .iter_mut()
            .find(|b| b.bridge_id == bridge_id)
    }

    /// Return the number of configured bridges.
    pub fn bridge_count(&self) -> usize {
        self.bridge_count
    }

    /// Return the number of active bridges.
    pub fn active_bridge_count(&self) -> usize {
        self.bridges[..self.bridge_count]
            .iter()
            .filter(|b| b.state == BridgeState::Active)
            .count()
    }

    /// Return `true` if the controller has been initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the next available bus number.
    pub fn next_bus(&self) -> u8 {
        self.next_bus
    }
}

// ---------------------------------------------------------------------------
// PciBridgeRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of PCI bridge controllers.
///
/// Tracks up to [`MAX_BRIDGE_CONTROLLERS`] controllers, typically
/// one per PCI segment or root complex.
pub struct PciBridgeRegistry {
    /// Registered bridge controllers.
    controllers: [Option<PciBridgeController>; MAX_BRIDGE_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for PciBridgeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PciBridgeRegistry {
    /// Create an empty bridge controller registry.
    pub const fn new() -> Self {
        const NONE: Option<PciBridgeController> = None;
        Self {
            controllers: [NONE; MAX_BRIDGE_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a new bridge controller.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a controller with the same
    ///   `controller_id` is already registered.
    pub fn register(&mut self, controller: PciBridgeController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.controller_id == controller.controller_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.controllers {
            if slot.is_none() {
                *slot = Some(controller);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a controller by its identifier.
    pub fn find(&self, controller_id: u8) -> Option<&PciBridgeController> {
        self.controllers
            .iter()
            .find_map(|slot| slot.as_ref().filter(|c| c.controller_id == controller_id))
    }

    /// Find a mutable reference to a controller by its identifier.
    pub fn find_mut(&mut self, controller_id: u8) -> Option<&mut PciBridgeController> {
        self.controllers
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|c| c.controller_id == controller_id))
    }

    /// Return the total number of bridges across all controllers.
    pub fn total_bridge_count(&self) -> usize {
        let mut total = 0usize;
        for ctrl in self.controllers.iter().flatten() {
            total += ctrl.bridge_count();
        }
        total
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
