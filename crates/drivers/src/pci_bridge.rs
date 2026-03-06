// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI-to-PCI bridge enumeration and secondary bus management.
//!
//! Implements discovery and configuration of PCI-to-PCI bridges (Type 1
//! configuration headers). Each bridge connects a primary (upstream) bus
//! segment to a secondary (downstream) segment, and optionally subordinate
//! segments beyond that.
//!
//! # Architecture
//!
//! ```text
//! Root Complex
//!   └─ PCI Bus 0 (primary)
//!       └─ PciBridge  [primary=0, secondary=1, subordinate=N]
//!           └─ PCI Bus 1 (secondary)
//!               ├─ Endpoint device
//!               └─ PciBridge  [primary=1, secondary=2, subordinate=M]
//! ```
//!
//! # Window Types
//!
//! Each bridge may decode three resource windows:
//! - **I/O** — port I/O space forwarded to the secondary bus.
//! - **Memory** — non-prefetchable MMIO forwarded downstream.
//! - **PrefetchMem** — prefetchable MMIO (may be cached).
//!
//! Reference: PCI Local Bus Specification 3.0, §3.2.5 (Type 1 Config Header).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum PCI-to-PCI bridges tracked by the subsystem.
const MAX_BRIDGES: usize = 16;

/// Maximum downstream device slots tracked per bridge.
const MAX_DOWNSTREAM_DEVICES: usize = 32;

/// PCI Type 1 configuration space offset: primary bus number.
const CFG_PRIMARY_BUS: u8 = 0x18;

/// PCI Type 1 configuration space offset: secondary bus number.
const CFG_SECONDARY_BUS: u8 = 0x19;

/// PCI Type 1 configuration space offset: subordinate bus number.
const CFG_SUBORDINATE_BUS: u8 = 0x1A;

/// PCI Type 1 configuration space offset: I/O base (byte).
const CFG_IO_BASE: u8 = 0x1C;

/// PCI Type 1 configuration space offset: I/O limit (byte).
const CFG_IO_LIMIT: u8 = 0x1D;

/// PCI Type 1 configuration space offset: memory base (16-bit).
const CFG_MEM_BASE: u8 = 0x20;

/// PCI Type 1 configuration space offset: memory limit (16-bit).
const CFG_MEM_LIMIT: u8 = 0x22;

/// PCI Type 1 configuration space offset: prefetchable memory base (16-bit).
const CFG_PREFETCH_BASE: u8 = 0x24;

/// PCI Type 1 configuration space offset: prefetchable memory limit (16-bit).
const CFG_PREFETCH_LIMIT: u8 = 0x26;

/// Starting bus number for secondary bus auto-assignment.
const BUS_NUMBER_START: u8 = 1;

/// Maximum PCI bus number (inclusive).
const MAX_BUS_NUMBER: u8 = 254;

/// I/O window granularity: 4 KiB aligned.
const IO_WINDOW_ALIGN: u64 = 0x1000;

/// Memory window granularity: 1 MiB aligned.
const MEM_WINDOW_ALIGN: u64 = 0x10_0000;

// ---------------------------------------------------------------------------
// WindowType
// ---------------------------------------------------------------------------

/// Classification of a PCI bridge resource window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowType {
    /// I/O port space window.
    Io,
    /// Non-prefetchable memory space window.
    Mem,
    /// Prefetchable memory space window (may be cached / speculatively read).
    PrefetchMem,
}

impl Default for WindowType {
    fn default() -> Self {
        Self::Mem
    }
}

// ---------------------------------------------------------------------------
// PciBridgeWindow
// ---------------------------------------------------------------------------

/// A forwarded resource window on a PCI-to-PCI bridge.
#[derive(Debug, Clone, Copy)]
pub struct PciBridgeWindow {
    /// Base address of the window (bus-address space).
    pub base: u64,
    /// Size of the window in bytes. Zero means the window is disabled.
    pub size: u64,
    /// Type of resource forwarded through this window.
    pub window_type: WindowType,
    /// Whether this window is active (non-zero size and valid alignment).
    pub enabled: bool,
}

impl PciBridgeWindow {
    /// Create a disabled window of the given type.
    pub const fn new(window_type: WindowType) -> Self {
        Self {
            base: 0,
            size: 0,
            window_type,
            enabled: false,
        }
    }

    /// Return the exclusive end address of the window.
    pub fn end_addr(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// Check whether `addr` falls within this window.
    pub fn contains(&self, addr: u64) -> bool {
        self.enabled && addr >= self.base && addr < self.end_addr()
    }
}

impl Default for PciBridgeWindow {
    fn default() -> Self {
        Self::new(WindowType::Mem)
    }
}

// ---------------------------------------------------------------------------
// PciBridgeConfig
// ---------------------------------------------------------------------------

/// Type 1 PCI configuration header fields relevant to bridge operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PciBridgeConfig {
    /// Bus number on the upstream (primary) side.
    pub primary_bus: u8,
    /// Bus number assigned to the downstream (secondary) side.
    pub secondary_bus: u8,
    /// Highest bus number reachable through this bridge.
    pub subordinate_bus: u8,
    /// I/O base register value (4-bit granularity, upper bits).
    pub io_base: u8,
    /// I/O limit register value.
    pub io_limit: u8,
    /// Non-prefetchable memory base (upper 12 bits, 1 MiB granularity).
    pub mem_base: u16,
    /// Non-prefetchable memory limit.
    pub mem_limit: u16,
    /// Prefetchable memory base.
    pub prefetch_base: u16,
    /// Prefetchable memory limit.
    pub prefetch_limit: u16,
}

impl PciBridgeConfig {
    /// Compute the decoded 64-bit I/O window base from the raw register byte.
    ///
    /// I/O windows are 4 KiB aligned; the lower 4 bits encode the window
    /// type (0 = 16-bit, 1 = 32-bit).
    pub fn io_base_addr(&self) -> u64 {
        ((self.io_base & 0xF0) as u64) << 8
    }

    /// Compute the decoded 64-bit I/O window end (inclusive limit + 0xFFF).
    pub fn io_limit_addr(&self) -> u64 {
        (((self.io_limit & 0xF0) as u64) << 8) | 0xFFF
    }

    /// Compute the decoded 32-bit memory base address.
    pub fn mem_base_addr(&self) -> u64 {
        ((self.mem_base & 0xFFF0) as u64) << 16
    }

    /// Compute the decoded 32-bit memory limit (inclusive limit + 0xFFFFF).
    pub fn mem_limit_addr(&self) -> u64 {
        (((self.mem_limit & 0xFFF0) as u64) << 16) | 0xF_FFFF
    }

    /// Compute the decoded 32-bit prefetchable memory base address.
    pub fn prefetch_base_addr(&self) -> u64 {
        ((self.prefetch_base & 0xFFF0) as u64) << 16
    }

    /// Compute the decoded 32-bit prefetchable memory limit address.
    pub fn prefetch_limit_addr(&self) -> u64 {
        (((self.prefetch_limit & 0xFFF0) as u64) << 16) | 0xF_FFFF
    }
}

// ---------------------------------------------------------------------------
// PciBridgeStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the PCI bridge subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PciBridgeStats {
    /// Total PCI-to-PCI bridges discovered.
    pub bridges_found: u32,
    /// Total secondary/subordinate bus numbers enumerated.
    pub buses_enumerated: u32,
    /// Total Type 1 configuration space accesses performed.
    pub config_accesses: u64,
}

impl PciBridgeStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            bridges_found: 0,
            buses_enumerated: 0,
            config_accesses: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PciBridge
// ---------------------------------------------------------------------------

/// A single PCI-to-PCI bridge device.
pub struct PciBridge {
    /// Type 1 configuration header fields.
    pub config: PciBridgeConfig,
    /// Resource windows: [I/O, Mem, PrefetchMem].
    pub windows: [PciBridgeWindow; 3],
    /// Number of downstream devices visible below this bridge.
    pub device_count: u8,
    /// BDF (Bus:Device.Function) identifiers of downstream devices.
    /// Each entry encodes: `(bus << 8) | (dev << 3) | func`.
    pub downstream_devices: [u16; MAX_DOWNSTREAM_DEVICES],
    /// Whether this bridge slot is populated.
    pub valid: bool,
    /// MMIO base address of the bridge's own configuration registers.
    pub mmio_base: u64,
}

impl PciBridge {
    /// Create an empty bridge entry.
    pub const fn new() -> Self {
        Self {
            config: PciBridgeConfig {
                primary_bus: 0,
                secondary_bus: 0,
                subordinate_bus: 0,
                io_base: 0,
                io_limit: 0,
                mem_base: 0,
                mem_limit: 0,
                prefetch_base: 0,
                prefetch_limit: 0,
            },
            windows: [
                PciBridgeWindow::new(WindowType::Io),
                PciBridgeWindow::new(WindowType::Mem),
                PciBridgeWindow::new(WindowType::PrefetchMem),
            ],
            device_count: 0,
            downstream_devices: [0u16; MAX_DOWNSTREAM_DEVICES],
            valid: false,
            mmio_base: 0,
        }
    }

    /// Register a downstream device BDF with this bridge.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device tracking array is full.
    pub fn add_downstream_device(&mut self, bdf: u16) -> Result<()> {
        if self.device_count as usize >= MAX_DOWNSTREAM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.downstream_devices[self.device_count as usize] = bdf;
        self.device_count += 1;
        Ok(())
    }

    /// Check whether `addr` is forwarded through any window of this bridge.
    pub fn forwards_addr(&self, addr: u64) -> bool {
        self.windows.iter().any(|w| w.contains(addr))
    }

    /// Check whether `bus` is in the secondary/subordinate range of this bridge.
    pub fn owns_bus(&self, bus: u8) -> bool {
        bus >= self.config.secondary_bus && bus <= self.config.subordinate_bus
    }

    // -----------------------------------------------------------------------
    // MMIO config space access helpers (read/write to bridge's config space)
    // -----------------------------------------------------------------------

    fn config_read8(&self, offset: u8) -> u8 {
        if self.mmio_base == 0 {
            return 0xFF;
        }
        // SAFETY: mmio_base is a mapped PCI configuration space address.
        // Reads use volatile to prevent compiler elision.
        unsafe {
            let addr = (self.mmio_base + offset as u64) as *const u8;
            core::ptr::read_volatile(addr)
        }
    }

    fn config_write8(&self, offset: u8, value: u8) {
        if self.mmio_base == 0 {
            return;
        }
        // SAFETY: mmio_base is a mapped PCI configuration space address.
        // Writes use volatile to prevent compiler elision.
        unsafe {
            let addr = (self.mmio_base + offset as u64) as *mut u8;
            core::ptr::write_volatile(addr, value);
        }
    }

    fn config_read16(&self, offset: u8) -> u16 {
        if self.mmio_base == 0 {
            return 0xFFFF;
        }
        // SAFETY: mmio_base is a mapped PCI configuration space address.
        unsafe {
            let addr = (self.mmio_base + offset as u64) as *const u16;
            core::ptr::read_volatile(addr)
        }
    }

    fn config_write16(&self, offset: u8, value: u16) {
        if self.mmio_base == 0 {
            return;
        }
        // SAFETY: mmio_base is a mapped PCI configuration space address.
        unsafe {
            let addr = (self.mmio_base + offset as u64) as *mut u16;
            core::ptr::write_volatile(addr, value);
        }
    }
}

impl Default for PciBridge {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PciBridgeSubsystem
// ---------------------------------------------------------------------------

/// Manages up to [`MAX_BRIDGES`] PCI-to-PCI bridge devices.
pub struct PciBridgeSubsystem {
    bridges: [PciBridge; MAX_BRIDGES],
    bridge_count: usize,
    stats: PciBridgeStats,
    /// Next free bus number for auto-assignment.
    next_bus: u8,
}

impl PciBridgeSubsystem {
    /// Create an empty subsystem.
    pub const fn new() -> Self {
        Self {
            bridges: [const { PciBridge::new() }; MAX_BRIDGES],
            bridge_count: 0,
            stats: PciBridgeStats::new(),
            next_bus: BUS_NUMBER_START,
        }
    }

    // -----------------------------------------------------------------------
    // Bridge registration
    // -----------------------------------------------------------------------

    /// Register a newly discovered PCI-to-PCI bridge.
    ///
    /// Reads the primary/secondary/subordinate bus numbers from the bridge's
    /// Type 1 configuration space (via MMIO at `mmio_base`), then stores
    /// the bridge and updates statistics.
    ///
    /// Returns the bridge ID (index) on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum bridge count is reached,
    /// or [`Error::InvalidArgument`] if `mmio_base` is zero.
    pub fn enumerate_bridge(&mut self, mmio_base: u64) -> Result<usize> {
        if self.bridge_count >= MAX_BRIDGES {
            return Err(Error::OutOfMemory);
        }
        if mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }

        let id = self.bridge_count;
        let bridge = &mut self.bridges[id];
        bridge.mmio_base = mmio_base;
        bridge.valid = true;

        // Read Type 1 bus number registers.
        bridge.config.primary_bus = bridge.config_read8(CFG_PRIMARY_BUS);
        bridge.config.secondary_bus = bridge.config_read8(CFG_SECONDARY_BUS);
        bridge.config.subordinate_bus = bridge.config_read8(CFG_SUBORDINATE_BUS);

        // Read window base/limit registers.
        bridge.config.io_base = bridge.config_read8(CFG_IO_BASE);
        bridge.config.io_limit = bridge.config_read8(CFG_IO_LIMIT);
        bridge.config.mem_base = bridge.config_read16(CFG_MEM_BASE);
        bridge.config.mem_limit = bridge.config_read16(CFG_MEM_LIMIT);
        bridge.config.prefetch_base = bridge.config_read16(CFG_PREFETCH_BASE);
        bridge.config.prefetch_limit = bridge.config_read16(CFG_PREFETCH_LIMIT);

        self.bridge_count += 1;
        self.stats.bridges_found += 1;
        self.stats.config_accesses += 9;

        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Window configuration
    // -----------------------------------------------------------------------

    /// Configure the resource windows for a bridge and program them into
    /// the Type 1 configuration registers.
    ///
    /// Window sizes are aligned up to the appropriate granularity
    /// (4 KiB for I/O, 1 MiB for memory).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bridge_id` is out of range or
    /// any window base is not properly aligned.
    pub fn configure_windows(
        &mut self,
        bridge_id: usize,
        io: Option<(u64, u64)>,
        mem: Option<(u64, u64)>,
        prefetch: Option<(u64, u64)>,
    ) -> Result<()> {
        if bridge_id >= self.bridge_count || !self.bridges[bridge_id].valid {
            return Err(Error::InvalidArgument);
        }

        if let Some((base, size)) = io {
            if base & (IO_WINDOW_ALIGN - 1) != 0 {
                return Err(Error::InvalidArgument);
            }
            let aligned_size = align_up(size, IO_WINDOW_ALIGN);
            self.bridges[bridge_id].windows[0] = PciBridgeWindow {
                base,
                size: aligned_size,
                window_type: WindowType::Io,
                enabled: aligned_size > 0,
            };
            // Program I/O base/limit registers (upper nibble = address[11:8]).
            let io_base_reg = ((base >> 8) & 0xF0) as u8;
            let io_limit_reg = (((base + aligned_size - 1) >> 8) & 0xF0) as u8;
            self.bridges[bridge_id].config.io_base = io_base_reg;
            self.bridges[bridge_id].config.io_limit = io_limit_reg;
            self.bridges[bridge_id].config_write8(CFG_IO_BASE, io_base_reg);
            self.bridges[bridge_id].config_write8(CFG_IO_LIMIT, io_limit_reg);
            self.stats.config_accesses += 2;
        }

        if let Some((base, size)) = mem {
            if base & (MEM_WINDOW_ALIGN - 1) != 0 {
                return Err(Error::InvalidArgument);
            }
            let aligned_size = align_up(size, MEM_WINDOW_ALIGN);
            self.bridges[bridge_id].windows[1] = PciBridgeWindow {
                base,
                size: aligned_size,
                window_type: WindowType::Mem,
                enabled: aligned_size > 0,
            };
            let mem_base_reg = ((base >> 16) & 0xFFF0) as u16;
            let mem_limit_reg = (((base + aligned_size - 1) >> 16) & 0xFFF0) as u16;
            self.bridges[bridge_id].config.mem_base = mem_base_reg;
            self.bridges[bridge_id].config.mem_limit = mem_limit_reg;
            self.bridges[bridge_id].config_write16(CFG_MEM_BASE, mem_base_reg);
            self.bridges[bridge_id].config_write16(CFG_MEM_LIMIT, mem_limit_reg);
            self.stats.config_accesses += 2;
        }

        if let Some((base, size)) = prefetch {
            if base & (MEM_WINDOW_ALIGN - 1) != 0 {
                return Err(Error::InvalidArgument);
            }
            let aligned_size = align_up(size, MEM_WINDOW_ALIGN);
            self.bridges[bridge_id].windows[2] = PciBridgeWindow {
                base,
                size: aligned_size,
                window_type: WindowType::PrefetchMem,
                enabled: aligned_size > 0,
            };
            let pfetch_base_reg = ((base >> 16) & 0xFFF0) as u16;
            let pfetch_limit_reg = (((base + aligned_size - 1) >> 16) & 0xFFF0) as u16;
            self.bridges[bridge_id].config.prefetch_base = pfetch_base_reg;
            self.bridges[bridge_id].config.prefetch_limit = pfetch_limit_reg;
            self.bridges[bridge_id].config_write16(CFG_PREFETCH_BASE, pfetch_base_reg);
            self.bridges[bridge_id].config_write16(CFG_PREFETCH_LIMIT, pfetch_limit_reg);
            self.stats.config_accesses += 2;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Config space routing
    // -----------------------------------------------------------------------

    /// Route a configuration space access for `bus` to the correct bridge.
    ///
    /// Returns the bridge ID whose secondary/subordinate range includes
    /// the given bus number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no registered bridge owns `bus`.
    pub fn route_config(&self, bus: u8) -> Result<usize> {
        for i in 0..self.bridge_count {
            if self.bridges[i].valid && self.bridges[i].owns_bus(bus) {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    // -----------------------------------------------------------------------
    // Bus number assignment
    // -----------------------------------------------------------------------

    /// Assign secondary and subordinate bus numbers to a bridge, updating
    /// its Type 1 configuration registers.
    ///
    /// Uses a simple depth-first assignment: secondary = `next_bus`, then
    /// subordinate is set to the maximum bus number encountered recursively.
    /// In this flat implementation, no downstream bridges are enumerated
    /// recursively; the subordinate is set equal to secondary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bridge_id` is out of range,
    /// or [`Error::OutOfMemory`] if bus numbers are exhausted.
    pub fn assign_bus_numbers(&mut self, bridge_id: usize) -> Result<u8> {
        if bridge_id >= self.bridge_count || !self.bridges[bridge_id].valid {
            return Err(Error::InvalidArgument);
        }
        if self.next_bus > MAX_BUS_NUMBER {
            return Err(Error::OutOfMemory);
        }

        let secondary = self.next_bus;
        self.next_bus += 1;

        // For this flat implementation, subordinate = secondary (no deeper scan).
        let subordinate = secondary;

        self.bridges[bridge_id].config.secondary_bus = secondary;
        self.bridges[bridge_id].config.subordinate_bus = subordinate;

        // Program bus registers.
        self.bridges[bridge_id].config_write8(CFG_SECONDARY_BUS, secondary);
        self.bridges[bridge_id].config_write8(CFG_SUBORDINATE_BUS, subordinate);
        self.stats.config_accesses += 2;
        self.stats.buses_enumerated += 1;

        Ok(subordinate)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return a reference to a bridge by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bridge_id` is out of range.
    pub fn bridge(&self, bridge_id: usize) -> Result<&PciBridge> {
        if bridge_id >= self.bridge_count || !self.bridges[bridge_id].valid {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.bridges[bridge_id])
    }

    /// Return a mutable reference to a bridge by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bridge_id` is out of range.
    pub fn bridge_mut(&mut self, bridge_id: usize) -> Result<&mut PciBridge> {
        if bridge_id >= self.bridge_count || !self.bridges[bridge_id].valid {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.bridges[bridge_id])
    }

    /// Return the number of registered bridges.
    pub fn bridge_count(&self) -> usize {
        self.bridge_count
    }

    /// Return a snapshot of the aggregate statistics.
    pub fn stats(&self) -> PciBridgeStats {
        self.stats
    }
}

impl Default for PciBridgeSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Align `value` up to the next multiple of `align` (must be power of two).
fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}
