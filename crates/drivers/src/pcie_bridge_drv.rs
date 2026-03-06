// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe bridge (PCI-to-PCI bridge, Type 1) driver.
//!
//! A PCIe switch or root port appears to software as a PCI-to-PCI bridge
//! (Type 1 configuration header). This driver manages:
//!
//! - Bus number assignment (primary, secondary, subordinate)
//! - I/O and memory window programming
//! - Prefetchable memory window programming
//! - Bus mastering and error forwarding enable
//!
//! Reference: PCI Express Base Specification Rev. 6.0, §7.5.1.2 (Type 1 Header).

use oncrix_lib::{Error, Result};

// ── Type 1 Configuration Header Offsets ───────────────────────────────────

/// Command register offset.
pub const CFG_COMMAND: u16 = 0x04;
/// Status register offset.
pub const CFG_STATUS: u16 = 0x06;
/// Primary bus number.
pub const CFG_PRIMARY_BUS: u16 = 0x18;
/// Secondary bus number.
pub const CFG_SECONDARY_BUS: u16 = 0x19;
/// Subordinate bus number.
pub const CFG_SUBORDINATE_BUS: u16 = 0x1A;
/// Secondary latency timer.
pub const CFG_SEC_LATENCY: u16 = 0x1B;
/// I/O base register.
pub const CFG_IO_BASE: u16 = 0x1C;
/// I/O limit register.
pub const CFG_IO_LIMIT: u16 = 0x1D;
/// Secondary status register.
pub const CFG_SEC_STATUS: u16 = 0x1E;
/// Memory base register.
pub const CFG_MEM_BASE: u16 = 0x20;
/// Memory limit register.
pub const CFG_MEM_LIMIT: u16 = 0x22;
/// Prefetchable memory base.
pub const CFG_PREF_MEM_BASE: u16 = 0x24;
/// Prefetchable memory limit.
pub const CFG_PREF_MEM_LIMIT: u16 = 0x26;
/// Prefetchable memory base upper 32 bits.
pub const CFG_PREF_BASE_UPPER: u16 = 0x28;
/// Prefetchable memory limit upper 32 bits.
pub const CFG_PREF_LIMIT_UPPER: u16 = 0x2C;
/// I/O base upper 16 bits.
pub const CFG_IO_BASE_UPPER: u16 = 0x30;
/// I/O limit upper 16 bits.
pub const CFG_IO_LIMIT_UPPER: u16 = 0x32;
/// Bridge control register.
pub const CFG_BRIDGE_CONTROL: u16 = 0x3E;

// ── Command Register Bits ──────────────────────────────────────────────────

/// Command: I/O Space Enable.
pub const CMD_IO_SPACE: u16 = 1 << 0;
/// Command: Memory Space Enable.
pub const CMD_MEM_SPACE: u16 = 1 << 1;
/// Command: Bus Master Enable.
pub const CMD_BUS_MASTER: u16 = 1 << 2;
/// Command: SERR# Enable.
pub const CMD_SERR_ENABLE: u16 = 1 << 8;
/// Command: Parity Error Response.
pub const CMD_PARITY_ERROR: u16 = 1 << 6;

/// Bridge Control: Secondary Bus Reset.
pub const BC_SECONDARY_RESET: u16 = 1 << 6;
/// Bridge Control: ISA Enable.
pub const BC_ISA_ENABLE: u16 = 1 << 2;

/// Maximum number of PCIe bridge instances.
const MAX_BRIDGES: usize = 32;

// ── Memory Window ──────────────────────────────────────────────────────────

/// A PCIe bridge address window (I/O, memory, or prefetchable memory).
#[derive(Clone, Copy, Default)]
pub struct AddressWindow {
    /// Base address (16 MiB aligned for memory, 4 KiB for I/O).
    pub base: u64,
    /// Limit address (inclusive, aligned to granularity - 1).
    pub limit: u64,
    /// True if this window is active (base <= limit).
    pub active: bool,
}

impl AddressWindow {
    /// Create a window covering [base, limit].
    pub fn new(base: u64, limit: u64) -> Self {
        Self {
            base,
            limit,
            active: base <= limit,
        }
    }

    /// Return the size of the window in bytes.
    pub fn size(&self) -> u64 {
        if self.active {
            self.limit - self.base + 1
        } else {
            0
        }
    }

    /// Check if an address falls within this window.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.base && addr <= self.limit
    }
}

// ── Bus Assignment ─────────────────────────────────────────────────────────

/// PCIe bus assignment for a bridge.
#[derive(Clone, Copy, Default)]
pub struct BusAssignment {
    /// Primary bus (upstream, where the bridge resides).
    pub primary: u8,
    /// Secondary bus (directly behind the bridge).
    pub secondary: u8,
    /// Subordinate bus (highest bus number behind the bridge).
    pub subordinate: u8,
}

// ── PCIe Bridge ────────────────────────────────────────────────────────────

/// PCIe bridge (Type 1) device state.
pub struct PcieBridge {
    /// Configuration space ECAM base address for this bridge.
    cfg_base: usize,
    /// Bus assignment.
    pub buses: BusAssignment,
    /// I/O address window.
    pub io_window: AddressWindow,
    /// Non-prefetchable memory window.
    pub mem_window: AddressWindow,
    /// Prefetchable memory window (64-bit capable).
    pub pref_mem_window: AddressWindow,
    /// Current command register value.
    command: u16,
}

impl PcieBridge {
    /// Read a 16-bit config register.
    ///
    /// # Safety
    /// `cfg_base + offset` must be a valid ECAM configuration space address.
    unsafe fn read16(&self, offset: u16) -> u16 {
        // SAFETY: cfg_base is valid ECAM; offset is within Type 1 header.
        unsafe { core::ptr::read_volatile((self.cfg_base + offset as usize) as *const u16) }
    }

    /// Write a 16-bit config register.
    ///
    /// # Safety
    /// `cfg_base + offset` must be a valid ECAM configuration space address.
    unsafe fn write16(&self, offset: u16, val: u16) {
        // SAFETY: cfg_base is valid ECAM; writing a known Type 1 register.
        unsafe { core::ptr::write_volatile((self.cfg_base + offset as usize) as *mut u16, val) }
    }

    /// Write a byte config register.
    ///
    /// # Safety
    /// `cfg_base + offset` must be a valid ECAM configuration space address.
    unsafe fn write8(&self, offset: u16, val: u8) {
        // SAFETY: cfg_base is valid ECAM.
        unsafe { core::ptr::write_volatile((self.cfg_base + offset as usize) as *mut u8, val) }
    }

    /// Create a new PCIe bridge driver.
    ///
    /// # Safety
    /// `cfg_base` must be the ECAM-mapped configuration space base for this
    /// Type 1 header device (bus/dev/fn specific, 4 KiB aligned).
    pub unsafe fn new(cfg_base: usize) -> Self {
        Self {
            cfg_base,
            buses: BusAssignment::default(),
            io_window: AddressWindow::default(),
            mem_window: AddressWindow::default(),
            pref_mem_window: AddressWindow::default(),
            command: 0,
        }
    }

    /// Assign bus numbers.
    pub fn assign_buses(&mut self, primary: u8, secondary: u8, subordinate: u8) -> Result<()> {
        if secondary <= primary || subordinate < secondary {
            return Err(Error::InvalidArgument);
        }
        self.buses = BusAssignment {
            primary,
            secondary,
            subordinate,
        };
        // SAFETY: write bus number registers in Type 1 header.
        unsafe {
            self.write8(CFG_PRIMARY_BUS, primary);
            self.write8(CFG_SECONDARY_BUS, secondary);
            self.write8(CFG_SUBORDINATE_BUS, subordinate);
        }
        Ok(())
    }

    /// Program the memory window (non-prefetchable, 1 MiB granularity).
    pub fn set_mem_window(&mut self, base: u64, limit: u64) -> Result<()> {
        if base & 0xFFFFF != 0 || (limit + 1) & 0xFFFFF != 0 {
            return Err(Error::InvalidArgument);
        }
        if base > 0xFFFF_FFFF || limit > 0xFFFF_FFFF {
            return Err(Error::InvalidArgument);
        }
        self.mem_window = AddressWindow::new(base, limit);
        let base16 = ((base >> 16) as u16) & 0xFFF0;
        let limit16 = ((limit >> 16) as u16) | 0x000F;
        // SAFETY: Type 1 memory base/limit registers.
        unsafe {
            self.write16(CFG_MEM_BASE, base16);
            self.write16(CFG_MEM_LIMIT, limit16);
        }
        Ok(())
    }

    /// Program the prefetchable memory window (64-bit capable).
    pub fn set_pref_mem_window(&mut self, base: u64, limit: u64) -> Result<()> {
        if base & 0xFFFFF != 0 || (limit + 1) & 0xFFFFF != 0 {
            return Err(Error::InvalidArgument);
        }
        self.pref_mem_window = AddressWindow::new(base, limit);
        let base16 = ((base >> 16) as u16) & 0xFFF0;
        let limit16 = ((limit >> 16) as u16) | 0x000F;
        // SAFETY: Type 1 prefetchable memory registers.
        unsafe {
            self.write16(CFG_PREF_MEM_BASE, base16 | 1); // bit 0: 64-bit capable
            self.write16(CFG_PREF_MEM_LIMIT, limit16 | 1);
        }
        // Upper 32 bits of prefetchable window.
        let base_hi = (base >> 32) as u32;
        let limit_hi = (limit >> 32) as u32;
        // SAFETY: upper 32-bit registers for prefetchable window.
        unsafe {
            core::ptr::write_volatile(
                (self.cfg_base + CFG_PREF_BASE_UPPER as usize) as *mut u32,
                base_hi,
            );
            core::ptr::write_volatile(
                (self.cfg_base + CFG_PREF_LIMIT_UPPER as usize) as *mut u32,
                limit_hi,
            );
        }
        Ok(())
    }

    /// Enable bus mastering and memory space.
    pub fn enable(&mut self) {
        self.command = CMD_MEM_SPACE | CMD_BUS_MASTER | CMD_SERR_ENABLE;
        // SAFETY: command register write to enable bridge forwarding.
        unsafe { self.write16(CFG_COMMAND, self.command) }
    }

    /// Reset the secondary bus via the Bridge Control register.
    pub fn secondary_bus_reset(&self) {
        // SAFETY: bridge control secondary reset bit.
        unsafe {
            let bc = self.read16(CFG_BRIDGE_CONTROL);
            self.write16(CFG_BRIDGE_CONTROL, bc | BC_SECONDARY_RESET);
            // Hold reset for a brief period (caller should delay externally).
            self.write16(CFG_BRIDGE_CONTROL, bc & !BC_SECONDARY_RESET);
        }
    }

    /// Read the current command register.
    pub fn read_command(&self) -> u16 {
        // SAFETY: command register read.
        unsafe { self.read16(CFG_COMMAND) }
    }

    /// Read secondary bus status.
    pub fn secondary_status(&self) -> u16 {
        // SAFETY: secondary status register.
        unsafe { self.read16(CFG_SEC_STATUS) }
    }
}

// ── Bridge Registry ────────────────────────────────────────────────────────

/// Registry of PCIe bridges in the system.
pub struct PcieBridgeRegistry {
    bridges: [Option<PcieBridge>; MAX_BRIDGES],
    count: usize,
}

impl PcieBridgeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            bridges: [const { None }; MAX_BRIDGES],
            count: 0,
        }
    }

    /// Register a bridge.
    pub fn register(&mut self, bridge: PcieBridge) -> Result<usize> {
        if self.count >= MAX_BRIDGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.bridges[idx] = Some(bridge);
        self.count += 1;
        Ok(idx)
    }

    /// Get a reference to a bridge by index.
    pub fn get(&self, idx: usize) -> Option<&PcieBridge> {
        self.bridges.get(idx)?.as_ref()
    }

    /// Get a mutable reference to a bridge.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut PcieBridge> {
        self.bridges.get_mut(idx)?.as_mut()
    }

    /// Return the number of registered bridges.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no bridges are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Find a bridge whose secondary bus number matches `bus`.
    pub fn find_by_secondary_bus(&self, bus: u8) -> Option<&PcieBridge> {
        self.bridges[..self.count]
            .iter()
            .flatten()
            .find(|b| b.buses.secondary == bus)
    }
}

impl Default for PcieBridgeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
