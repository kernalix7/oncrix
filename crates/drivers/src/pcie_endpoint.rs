// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe Endpoint (EP) driver framework.
//!
//! Provides the EP-side view of a PCIe link: BAR programming, inbound/outbound
//! ATU (Address Translation Unit) window management, and MSI/MSI-X interrupt
//! generation from the device towards the host. Used for FPGA-based PCIe
//! endpoints and SoC-integrated PCIe test/development interfaces.

use oncrix_lib::{Error, Result};

/// Maximum number of BARs (Base Address Registers) per endpoint function.
pub const EP_MAX_BARS: usize = 6;
/// Maximum number of outbound ATU windows.
pub const EP_MAX_OB_ATU: usize = 8;
/// Maximum number of inbound ATU windows.
pub const EP_MAX_IB_ATU: usize = 4;

/// BAR type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    /// 32-bit memory BAR.
    Mem32,
    /// 64-bit memory BAR (occupies two consecutive BARs).
    Mem64,
    /// IO BAR (legacy).
    Io,
    /// Unused / disabled BAR.
    Unused,
}

/// A single BAR descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct BarDescriptor {
    /// BAR type.
    pub bar_type: BarType,
    /// Desired size in bytes (must be power of 2).
    pub size: u64,
    /// Physical address allocated for this BAR.
    pub phys_addr: u64,
    /// Whether the BAR is prefetchable.
    pub prefetchable: bool,
}

impl Default for BarType {
    fn default() -> Self {
        Self::Unused
    }
}

/// Address Translation Unit (ATU) region type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtuType {
    /// Memory transaction.
    Memory,
    /// I/O transaction.
    Io,
    /// Configuration type 0.
    Cfg0,
    /// Configuration type 1.
    Cfg1,
}

/// An ATU window (inbound or outbound).
#[derive(Debug, Clone, Copy, Default)]
pub struct AtuWindow {
    /// ATU transaction type.
    pub atu_type: AtuType,
    /// Base address (PCIe side for outbound, CPU side for inbound).
    pub base: u64,
    /// Limit address (base + size - 1).
    pub limit: u64,
    /// Target address (CPU side for outbound, PCIe side for inbound).
    pub target: u64,
    /// Whether this window is enabled.
    pub enabled: bool,
}

impl Default for AtuType {
    fn default() -> Self {
        Self::Memory
    }
}

/// PCIe Endpoint function configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpFunctionConfig {
    /// PCIe Vendor ID.
    pub vendor_id: u16,
    /// PCIe Device ID.
    pub device_id: u16,
    /// PCIe Class Code (3 bytes: base, sub, prog-if).
    pub class_code: [u8; 3],
    /// Subsystem Vendor ID.
    pub subsys_vendor_id: u16,
    /// Subsystem ID.
    pub subsys_id: u16,
}

/// PCIe Endpoint controller register offsets (Synopsys DesignWare-compatible).
struct EpRegs;

impl EpRegs {
    // Config space registers.
    const VENDOR_ID: usize = 0x00;
    const CLASS_CODE: usize = 0x08;
    const BAR_BASE: usize = 0x10; // BAR0 starts here, stride = 4.

    // iATU registers (outbound, index i).
    const IATU_OB_CTRL1: usize = 0x300000;
    const IATU_OB_CTRL2: usize = 0x300004;
    const IATU_OB_LBAR: usize = 0x300008;
    const IATU_OB_UBAR: usize = 0x30000C;
    const IATU_OB_LAR: usize = 0x300010;
    const IATU_OB_LTAR: usize = 0x300014;
    const IATU_OB_UTAR: usize = 0x300018;
    const IATU_STRIDE: usize = 0x200;

    // iATU outbound CTRL1 type encoding.
    const IATU_TYPE_MEM: u32 = 0x0;
    const IATU_TYPE_IO: u32 = 0x2;
    const IATU_TYPE_CFG0: u32 = 0x4;
    const IATU_TYPE_CFG1: u32 = 0x5;
    // CTRL2 bits.
    const IATU_ENABLE: u32 = 1 << 31;
}

/// PCIe Endpoint driver.
pub struct PcieEndpoint {
    /// MMIO base of the EP DBI (Data Bus Interface).
    dbi_base: usize,
    /// Function configuration.
    pub config: EpFunctionConfig,
    /// BAR descriptors.
    pub bars: [BarDescriptor; EP_MAX_BARS],
    /// Outbound ATU windows.
    pub ob_atu: [AtuWindow; EP_MAX_OB_ATU],
    /// Inbound ATU windows.
    pub ib_atu: [AtuWindow; EP_MAX_IB_ATU],
}

impl PcieEndpoint {
    /// Creates a new PCIe Endpoint driver.
    ///
    /// # Arguments
    ///
    /// * `dbi_base` — Physical MMIO address of the DBI (must be mapped).
    /// * `config` — Function identification values.
    pub const fn new(dbi_base: usize, config: EpFunctionConfig) -> Self {
        Self {
            dbi_base,
            config,
            bars: [const {
                BarDescriptor {
                    bar_type: BarType::Unused,
                    size: 0,
                    phys_addr: 0,
                    prefetchable: false,
                }
            }; EP_MAX_BARS],
            ob_atu: [const {
                AtuWindow {
                    atu_type: AtuType::Memory,
                    base: 0,
                    limit: 0,
                    target: 0,
                    enabled: false,
                }
            }; EP_MAX_OB_ATU],
            ib_atu: [const {
                AtuWindow {
                    atu_type: AtuType::Memory,
                    base: 0,
                    limit: 0,
                    target: 0,
                    enabled: false,
                }
            }; EP_MAX_IB_ATU],
        }
    }

    /// Programs the config-space header in the DBI.
    pub fn init(&self) -> Result<()> {
        // Write Vendor/Device ID.
        let vid_did = ((self.config.device_id as u32) << 16) | (self.config.vendor_id as u32);
        self.dbi_write32(EpRegs::VENDOR_ID, vid_did);
        // Write Class Code.
        let class_rev = ((self.config.class_code[0] as u32) << 24)
            | ((self.config.class_code[1] as u32) << 16)
            | ((self.config.class_code[2] as u32) << 8);
        self.dbi_write32(EpRegs::CLASS_CODE, class_rev);
        Ok(())
    }

    /// Configures a BAR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bar >= EP_MAX_BARS` or size is not a power of two.
    pub fn set_bar(&mut self, bar: usize, desc: BarDescriptor) -> Result<()> {
        if bar >= EP_MAX_BARS {
            return Err(Error::InvalidArgument);
        }
        if desc.size == 0 || (desc.size & (desc.size - 1)) != 0 {
            return Err(Error::InvalidArgument);
        }
        self.bars[bar] = desc;
        // Write BAR mask (size - 1 as mask, hardware writes base on host assignment).
        let mask = (desc.size - 1) as u32;
        self.dbi_write32(EpRegs::BAR_BASE + bar * 4, mask);
        Ok(())
    }

    /// Programs an outbound ATU window.
    pub fn set_ob_atu(&mut self, idx: usize, window: AtuWindow) -> Result<()> {
        if idx >= EP_MAX_OB_ATU {
            return Err(Error::InvalidArgument);
        }
        self.ob_atu[idx] = window;
        let base = EpRegs::IATU_OB_CTRL1 + idx * EpRegs::IATU_STRIDE;
        let atu_type = match window.atu_type {
            AtuType::Memory => EpRegs::IATU_TYPE_MEM,
            AtuType::Io => EpRegs::IATU_TYPE_IO,
            AtuType::Cfg0 => EpRegs::IATU_TYPE_CFG0,
            AtuType::Cfg1 => EpRegs::IATU_TYPE_CFG1,
        };
        self.dbi_write32(base, atu_type);
        self.dbi_write32(
            base + (EpRegs::IATU_OB_LBAR - EpRegs::IATU_OB_CTRL1),
            window.base as u32,
        );
        self.dbi_write32(
            base + (EpRegs::IATU_OB_UBAR - EpRegs::IATU_OB_CTRL1),
            (window.base >> 32) as u32,
        );
        self.dbi_write32(
            base + (EpRegs::IATU_OB_LAR - EpRegs::IATU_OB_CTRL1),
            window.limit as u32,
        );
        self.dbi_write32(
            base + (EpRegs::IATU_OB_LTAR - EpRegs::IATU_OB_CTRL1),
            window.target as u32,
        );
        self.dbi_write32(
            base + (EpRegs::IATU_OB_UTAR - EpRegs::IATU_OB_CTRL1),
            (window.target >> 32) as u32,
        );
        if window.enabled {
            self.dbi_write32(
                base + (EpRegs::IATU_OB_CTRL2 - EpRegs::IATU_OB_CTRL1),
                EpRegs::IATU_ENABLE,
            );
        }
        Ok(())
    }

    /// Returns the number of configured BARs.
    pub fn num_active_bars(&self) -> usize {
        self.bars
            .iter()
            .filter(|b| b.bar_type != BarType::Unused)
            .count()
    }

    // ---- private helpers ----

    fn dbi_write32(&self, offset: usize, val: u32) {
        let ptr = (self.dbi_base + offset) as *mut u32;
        // SAFETY: dbi_base is a valid mapped DBI MMIO region.
        unsafe { core::ptr::write_volatile(ptr, val) };
    }
}

impl Default for PcieEndpoint {
    fn default() -> Self {
        Self::new(0, EpFunctionConfig::default())
    }
}
