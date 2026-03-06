// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe endpoint (device) controller abstraction.
//!
//! Manages PCIe endpoint functionality, where the SoC acts as a PCIe device
//! rather than a root complex. Used in embedded systems that expose PCIe
//! connectivity to a host processor.
//!
//! # PCIe Endpoint vs Root Complex
//!
//! - **Root Complex (RC)**: Initiates transactions, enumerates the bus (host)
//! - **Endpoint (EP)**: Responds to transactions, exposes BAR windows (device)
//!
//! # Endpoint BAR Configuration
//!
//! Each BAR maps a region of the endpoint's local memory or MMIO into the
//! host's PCI address space. The endpoint controller provides:
//! - BAR aperture size programming
//! - Inbound/outbound address translation
//! - MSI/MSI-X signaling to the host

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum number of BARs in a PCIe endpoint.
pub const EP_MAX_BARS: usize = 6;

/// PCIe BAR type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    /// 32-bit memory BAR.
    Mem32,
    /// 64-bit memory BAR (occupies two BAR slots).
    Mem64,
    /// I/O BAR (legacy).
    Io,
}

/// PCIe endpoint BAR configuration.
#[derive(Debug, Clone, Copy)]
pub struct EpBar {
    /// BAR index (0–5).
    pub index: u8,
    /// BAR type.
    pub bar_type: BarType,
    /// Size of the BAR aperture in bytes (must be power of 2).
    pub size: u64,
    /// Local physical address this BAR maps to.
    pub local_addr: u64,
    /// Whether the BAR is prefetchable.
    pub prefetchable: bool,
    /// Whether the BAR is configured and active.
    pub enabled: bool,
}

impl EpBar {
    /// Creates a 32-bit memory BAR.
    pub const fn mem32(index: u8, size: u32, local_addr: u64) -> Self {
        Self {
            index,
            bar_type: BarType::Mem32,
            size: size as u64,
            local_addr,
            prefetchable: false,
            enabled: false,
        }
    }

    /// Creates a 64-bit memory BAR.
    pub const fn mem64(index: u8, size: u64, local_addr: u64) -> Self {
        Self {
            index,
            bar_type: BarType::Mem64,
            size,
            local_addr,
            prefetchable: true,
            enabled: false,
        }
    }

    /// Validates BAR configuration.
    pub fn validate(&self) -> Result<()> {
        if self.index as usize >= EP_MAX_BARS {
            return Err(Error::InvalidArgument);
        }
        if self.size == 0 || !self.size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if self.local_addr & (self.size - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// PCIe endpoint link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpLinkState {
    /// No host connected or link not trained.
    Down,
    /// Link is training.
    Training,
    /// Link is up and operational.
    Up,
    /// Link is in recovery.
    Recovery,
    /// Link is in hot reset.
    HotReset,
}

/// PCIe endpoint device identity.
#[derive(Debug, Clone, Copy)]
pub struct EpIdentity {
    /// Vendor ID (allocated by PCI-SIG).
    pub vendor_id: u16,
    /// Device ID (assigned by the vendor).
    pub device_id: u16,
    /// Revision ID.
    pub revision: u8,
    /// Class code (base class, sub-class, programming interface).
    pub class_code: u32,
    /// Subsystem vendor ID.
    pub subsys_vendor: u16,
    /// Subsystem device ID.
    pub subsys_device: u16,
}

/// PCIe endpoint controller driver.
pub struct PcieEndpoint {
    /// MMIO base of the endpoint controller.
    base: usize,
    /// Device identity presented to the host.
    identity: EpIdentity,
    /// BAR configurations.
    bars: [Option<EpBar>; EP_MAX_BARS],
    /// Current link state.
    link_state: EpLinkState,
    /// Whether the endpoint is initialized.
    initialized: bool,
}

// Endpoint controller register offsets (controller-specific; this uses a generic layout)
const EP_VENDOR_ID: usize = 0x00;
const EP_DEVICE_ID: usize = 0x02;
const EP_CLASS_CODE: usize = 0x08;
const EP_BAR_CTRL_BASE: usize = 0x100;
const EP_BAR_ADDR_BASE: usize = 0x200;
const EP_LINK_STATUS: usize = 0x300;
const EP_MSI_ADDR: usize = 0x400;
const EP_MSI_DATA: usize = 0x408;
const EP_MSI_CTRL: usize = 0x40C;

impl PcieEndpoint {
    /// Creates a new PCIe endpoint controller instance.
    pub const fn new(base: usize, identity: EpIdentity) -> Self {
        const NONE: Option<EpBar> = None;
        Self {
            base,
            identity,
            bars: [NONE; EP_MAX_BARS],
            link_state: EpLinkState::Down,
            initialized: false,
        }
    }

    /// Initializes the endpoint controller and programs the device identity.
    pub fn init(&mut self) -> Result<()> {
        self.write16(EP_VENDOR_ID, self.identity.vendor_id);
        self.write16(EP_DEVICE_ID, self.identity.device_id);
        self.write32(EP_CLASS_CODE, self.identity.class_code);
        self.initialized = true;
        Ok(())
    }

    /// Configures a BAR aperture.
    pub fn configure_bar(&mut self, bar: EpBar) -> Result<()> {
        bar.validate()?;
        let idx = bar.index as usize;
        // Program BAR control register with size and type
        let ctrl_val =
            (bar.size.trailing_zeros() as u32) | if bar.prefetchable { 1 << 8 } else { 0 };
        self.write32(EP_BAR_CTRL_BASE + idx * 8, ctrl_val);
        // Program local address for inbound translation
        self.write64(EP_BAR_ADDR_BASE + idx * 8, bar.local_addr);
        self.bars[idx] = Some(EpBar {
            enabled: true,
            ..bar
        });
        Ok(())
    }

    /// Reads the current link state from hardware.
    pub fn poll_link_state(&mut self) -> EpLinkState {
        let status = self.read32(EP_LINK_STATUS);
        self.link_state = match status & 0xF {
            0 => EpLinkState::Down,
            1 => EpLinkState::Training,
            2 => EpLinkState::Up,
            3 => EpLinkState::Recovery,
            4 => EpLinkState::HotReset,
            _ => EpLinkState::Down,
        };
        self.link_state
    }

    /// Programs MSI outbound signaling to the host.
    ///
    /// # Arguments
    ///
    /// * `msi_addr` - Host MSI address programmed by the host during enumeration
    /// * `msi_data` - MSI data value
    pub fn configure_msi(&self, msi_addr: u64, msi_data: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        self.write64(EP_MSI_ADDR, msi_addr);
        self.write32(EP_MSI_DATA, msi_data);
        self.write32(EP_MSI_CTRL, 1); // Enable MSI
        Ok(())
    }

    /// Triggers an MSI to the host.
    pub fn raise_msi(&self) {
        self.write32(EP_MSI_CTRL, 0x3); // Trigger bit
    }

    /// Returns the current link state.
    pub fn link_state(&self) -> EpLinkState {
        self.link_state
    }

    fn read32(&self, offset: usize) -> u32 {
        let addr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid PCIe endpoint controller MMIO region.
        // Volatile read is required for hardware register access.
        unsafe { addr.read_volatile() }
    }

    fn write16(&self, offset: usize, val: u16) {
        let addr = (self.base + offset) as *mut u16;
        // SAFETY: base is a valid PCIe endpoint controller MMIO region.
        unsafe { addr.write_volatile(val) }
    }

    fn write32(&self, offset: usize, val: u32) {
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid PCIe endpoint controller MMIO region.
        // Volatile write ensures the configuration is applied immediately.
        unsafe { addr.write_volatile(val) }
    }

    fn write64(&self, offset: usize, val: u64) {
        self.write32(offset, val as u32);
        self.write32(offset + 4, (val >> 32) as u32);
    }
}

impl Default for PcieEndpoint {
    fn default() -> Self {
        Self::new(
            0,
            EpIdentity {
                vendor_id: 0xFFFF,
                device_id: 0xFFFF,
                revision: 0,
                class_code: 0xFF_0000,
                subsys_vendor: 0,
                subsys_device: 0,
            },
        )
    }
}
