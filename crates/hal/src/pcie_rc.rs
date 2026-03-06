// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe Root Complex (RC) hardware abstraction.
//!
//! Provides initialization and configuration routines for the PCIe Root
//! Complex hardware found on SoCs. Unlike the PCI bus enumeration code in
//! `pci.rs`, this module is concerned with bringing up the RC hardware itself:
//! PHY training, link establishment, and ECAM-based config space access.

use oncrix_lib::{Error, Result};

/// Maximum number of PCIe ports on a single RC.
pub const PCIE_RC_MAX_PORTS: usize = 4;

/// PCIe link generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PcieGen {
    /// PCIe 1.0 (2.5 GT/s per lane).
    Gen1,
    /// PCIe 2.0 (5 GT/s per lane).
    Gen2,
    /// PCIe 3.0 (8 GT/s per lane).
    Gen3,
    /// PCIe 4.0 (16 GT/s per lane).
    Gen4,
    /// PCIe 5.0 (32 GT/s per lane).
    Gen5,
}

impl PcieGen {
    /// Returns the transfer speed in MT/s per lane.
    pub fn speed_mt_s(self) -> u32 {
        match self {
            PcieGen::Gen1 => 2500,
            PcieGen::Gen2 => 5000,
            PcieGen::Gen3 => 8000,
            PcieGen::Gen4 => 16000,
            PcieGen::Gen5 => 32000,
        }
    }
}

/// PCIe port link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// No device connected.
    Disconnected,
    /// PHY training in progress.
    Training,
    /// Link is up and operational.
    Active,
    /// Link went down after being active.
    Degraded,
}

/// Configuration for a single PCIe RC port.
#[derive(Debug, Clone, Copy)]
pub struct RcPortConfig {
    /// ECAM base address for this port's config space window.
    pub ecam_base: u64,
    /// ECAM size in bytes.
    pub ecam_size: usize,
    /// IO base address for legacy IO transactions.
    pub io_base: u64,
    /// Memory base address for 32-bit BARs.
    pub mem_base: u64,
    /// Memory base address for 64-bit prefetchable BARs.
    pub mem64_base: u64,
    /// Maximum link generation to negotiate.
    pub max_gen: PcieGen,
    /// Number of lanes.
    pub lanes: u8,
}

impl Default for RcPortConfig {
    fn default() -> Self {
        Self {
            ecam_base: 0,
            ecam_size: 0,
            io_base: 0,
            mem_base: 0,
            mem64_base: 0,
            max_gen: PcieGen::Gen3,
            lanes: 1,
        }
    }
}

/// State tracked per port by the RC driver.
#[derive(Debug, Clone, Copy)]
pub struct RcPort {
    /// Port configuration.
    pub config: RcPortConfig,
    /// Current link state.
    pub link: LinkState,
    /// Negotiated generation (valid when link is Active).
    pub negotiated_gen: PcieGen,
    /// Negotiated lane count.
    pub negotiated_lanes: u8,
}

impl RcPort {
    /// Creates a new unconfigured port.
    pub const fn new() -> Self {
        Self {
            config: RcPortConfig {
                ecam_base: 0,
                ecam_size: 0,
                io_base: 0,
                mem_base: 0,
                mem64_base: 0,
                max_gen: PcieGen::Gen3,
                lanes: 1,
            },
            link: LinkState::Disconnected,
            negotiated_gen: PcieGen::Gen1,
            negotiated_lanes: 0,
        }
    }
}

impl Default for RcPort {
    fn default() -> Self {
        Self::new()
    }
}

/// PCIe Root Complex controller register offsets.
struct Regs;

impl Regs {
    const CTRL: usize = 0x00;
    const PHY_CTRL: usize = 0x04;
    const LINK_STAT: usize = 0x08;
    const INTR_STAT: usize = 0x0C;
    const INTR_MASK: usize = 0x10;
    const INTR_CLR: usize = 0x14;
    const ECAM_CTRL: usize = 0x20;

    // CTRL bits
    const CTRL_RESET: u32 = 1 << 0;
    const CTRL_ENABLE: u32 = 1 << 1;
    const CTRL_PHY_EN: u32 = 1 << 2;

    // LINK_STAT bits
    const LINK_UP: u32 = 1 << 0;
    const LINK_GEN_MASK: u32 = 0xF << 4;
    const LINK_GEN_SHIFT: u32 = 4;
    const LINK_WIDTH_MASK: u32 = 0x3F << 8;
    const LINK_WIDTH_SHIFT: u32 = 8;
}

/// PCIe Root Complex hardware controller.
pub struct PcieRootComplex {
    /// MMIO base address of the RC controller.
    base: usize,
    /// Number of configured ports.
    num_ports: usize,
    /// Per-port state.
    ports: [RcPort; PCIE_RC_MAX_PORTS],
}

impl PcieRootComplex {
    /// Creates a new Root Complex handle.
    ///
    /// # Arguments
    ///
    /// * `base` — MMIO base (must be mapped).
    pub const fn new(base: usize) -> Self {
        Self {
            base,
            num_ports: 0,
            ports: [const { RcPort::new() }; PCIE_RC_MAX_PORTS],
        }
    }

    /// Registers a port configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if [`PCIE_RC_MAX_PORTS`] is exceeded.
    pub fn add_port(&mut self, cfg: RcPortConfig) -> Result<usize> {
        if self.num_ports >= PCIE_RC_MAX_PORTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.num_ports;
        self.ports[idx].config = cfg;
        self.ports[idx].link = LinkState::Disconnected;
        self.num_ports += 1;
        Ok(idx)
    }

    /// Initialises the RC: resets, enables PHY, and brings up all ports.
    pub fn init(&mut self) -> Result<()> {
        // Global reset.
        self.mmio_write32(Regs::CTRL, Regs::CTRL_RESET);
        self.mmio_write32(Regs::CTRL, 0);
        // Enable PHY and controller.
        self.mmio_write32(Regs::CTRL, Regs::CTRL_ENABLE | Regs::CTRL_PHY_EN);
        // Configure ECAM window for each port.
        for i in 0..self.num_ports {
            let ecam_base = self.ports[i].config.ecam_base;
            // Write ECAM base + enable.
            self.mmio_write32(Regs::ECAM_CTRL + i * 8, ecam_base as u32);
            self.mmio_write32(Regs::ECAM_CTRL + i * 8 + 4, (ecam_base >> 32) as u32);
            self.ports[i].link = LinkState::Training;
        }
        // Unmask link-up interrupt.
        self.mmio_write32(Regs::INTR_MASK, 0);
        Ok(())
    }

    /// Polls link status for port `port_idx`.
    pub fn poll_link(&mut self, port_idx: usize) -> Result<LinkState> {
        if port_idx >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let stat = self.mmio_read32(Regs::LINK_STAT);
        if (stat & Regs::LINK_UP) != 0 {
            let gen_raw = (stat & Regs::LINK_GEN_MASK) >> Regs::LINK_GEN_SHIFT;
            let width = ((stat & Regs::LINK_WIDTH_MASK) >> Regs::LINK_WIDTH_SHIFT) as u8;
            self.ports[port_idx].link = LinkState::Active;
            self.ports[port_idx].negotiated_gen = match gen_raw {
                1 => PcieGen::Gen1,
                2 => PcieGen::Gen2,
                3 => PcieGen::Gen3,
                4 => PcieGen::Gen4,
                _ => PcieGen::Gen5,
            };
            self.ports[port_idx].negotiated_lanes = width;
        }
        Ok(self.ports[port_idx].link)
    }

    /// Reads a 32-bit value from the ECAM config space.
    ///
    /// # Arguments
    ///
    /// * `port` — Port index.
    /// * `bus` / `dev` / `func` / `reg` — BDF + register offset.
    pub fn ecam_read32(&self, port: usize, bus: u8, dev: u8, func: u8, reg: u16) -> Result<u32> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let ecam_base = self.ports[port].config.ecam_base;
        let offset = ((bus as u64) << 20)
            | ((dev as u64) << 15)
            | ((func as u64) << 12)
            | (reg as u64 & 0xFFC);
        let ptr = (ecam_base + offset) as *const u32;
        // SAFETY: ECAM window is memory-mapped; BDF is caller-validated.
        let val = unsafe { core::ptr::read_volatile(ptr) };
        Ok(val)
    }

    /// Writes a 32-bit value to the ECAM config space.
    pub fn ecam_write32(
        &self,
        port: usize,
        bus: u8,
        dev: u8,
        func: u8,
        reg: u16,
        val: u32,
    ) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let ecam_base = self.ports[port].config.ecam_base;
        let offset = ((bus as u64) << 20)
            | ((dev as u64) << 15)
            | ((func as u64) << 12)
            | (reg as u64 & 0xFFC);
        let ptr = (ecam_base + offset) as *mut u32;
        // SAFETY: ECAM window is memory-mapped; BDF is caller-validated.
        unsafe { core::ptr::write_volatile(ptr, val) };
        Ok(())
    }

    /// Returns the number of configured ports.
    pub fn num_ports(&self) -> usize {
        self.num_ports
    }

    // ---- private helpers ----

    fn mmio_read32(&self, offset: usize) -> u32 {
        let ptr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid mapped MMIO region.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn mmio_write32(&self, offset: usize, val: u32) {
        let ptr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid mapped MMIO region.
        unsafe { core::ptr::write_volatile(ptr, val) }
    }
}
