// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe PHY (Physical Layer) hardware abstraction.
//!
//! Provides a unified interface for PCIe PHY hardware managing the analog
//! transceiver layer for PCIe Gen 1 through Gen 5. Handles lane configuration,
//! link training, equalization, and power management states (L0, L0s, L1, L2).

use oncrix_lib::{Error, Result};

/// Maximum number of PCIe PHY instances.
pub const MAX_PCIE_PHY: usize = 4;

/// Maximum number of PCIe lanes per PHY.
pub const MAX_PCIE_LANES: usize = 16;

/// PCIe generation / link speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PcieGen {
    /// PCIe Gen 1 — 2.5 GT/s (2.0 Gbps usable).
    Gen1,
    /// PCIe Gen 2 — 5.0 GT/s (4.0 Gbps usable).
    Gen2,
    /// PCIe Gen 3 — 8.0 GT/s (7.877 Gbps usable, 128b/130b encoding).
    Gen3,
    /// PCIe Gen 4 — 16.0 GT/s (15.75 Gbps usable).
    Gen4,
    /// PCIe Gen 5 — 32.0 GT/s (31.5 Gbps usable).
    Gen5,
    /// PCIe Gen 6 — 64.0 GT/s (PAM4 signaling).
    Gen6,
}

impl PcieGen {
    /// Returns the transfer rate in Gigatransfers per second (GT/s).
    pub fn gtps(self) -> u32 {
        match self {
            PcieGen::Gen1 => 25, // 2.5 GT/s * 10
            PcieGen::Gen2 => 50, // 5.0 GT/s * 10
            PcieGen::Gen3 => 80,
            PcieGen::Gen4 => 160,
            PcieGen::Gen5 => 320,
            PcieGen::Gen6 => 640,
        }
    }

    /// Returns the usable bandwidth per lane in Mbps.
    pub fn lane_bandwidth_mbps(self) -> u64 {
        match self {
            PcieGen::Gen1 => 250,
            PcieGen::Gen2 => 500,
            PcieGen::Gen3 => 985,
            PcieGen::Gen4 => 1969,
            PcieGen::Gen5 => 3938,
            PcieGen::Gen6 => 7877,
        }
    }
}

/// PCIe PHY power management state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieLinkState {
    /// L0 — Normal operation.
    L0,
    /// L0s — Standby, fast exit (nanoseconds).
    L0s,
    /// L1 — Low power, moderate exit latency (microseconds).
    L1,
    /// L1.1 — ASPM L1 sub-state.
    L1Sub1,
    /// L1.2 — ASPM L1 sub-state with power off.
    L1Sub2,
    /// L2 — Auxiliary power, slow exit (milliseconds).
    L2,
    /// L3 — Powered off.
    L3,
    /// Disabled.
    Disabled,
}

/// PCIe lane equalization preset.
#[derive(Debug, Clone, Copy)]
pub struct EqPreset {
    /// Preset index (0..10 for Gen 3+).
    pub preset: u8,
    /// Transmitter pre-cursor coefficient.
    pub pre_cursor: i8,
    /// Transmitter cursor coefficient.
    pub cursor: i8,
    /// Transmitter post-cursor coefficient.
    pub post_cursor: i8,
}

impl EqPreset {
    /// Creates a preset with default coefficients (preset P7: 0,-6,0).
    pub const fn p7() -> Self {
        Self {
            preset: 7,
            pre_cursor: 0,
            cursor: -6,
            post_cursor: 0,
        }
    }
}

impl Default for EqPreset {
    fn default() -> Self {
        Self::p7()
    }
}

/// Per-lane statistics for a PCIe PHY.
#[derive(Debug, Default, Clone, Copy)]
pub struct LaneStats {
    /// Number of link training iterations.
    pub training_count: u32,
    /// Number of framing errors detected.
    pub framing_errors: u64,
    /// Number of disparity errors.
    pub disparity_errors: u64,
    /// Estimated signal-to-noise ratio (x10, e.g., 150 = 15.0 dB).
    pub snr_x10: u32,
}

impl LaneStats {
    /// Creates a new zeroed lane stats structure.
    pub const fn new() -> Self {
        Self {
            training_count: 0,
            framing_errors: 0,
            disparity_errors: 0,
            snr_x10: 0,
        }
    }
}

/// PCIe PHY driver.
pub struct PciePhy {
    /// PHY identifier.
    id: u8,
    /// MMIO base address of the PCIe PHY registers.
    base_addr: u64,
    /// Maximum supported PCIe generation.
    max_gen: PcieGen,
    /// Number of lanes.
    lane_count: u8,
    /// Current link state.
    link_state: PcieLinkState,
    /// Current negotiated generation.
    current_gen: Option<PcieGen>,
    /// Current negotiated lane width.
    current_width: u8,
    /// Per-lane statistics.
    lane_stats: [LaneStats; MAX_PCIE_LANES],
    /// Whether the PHY has been initialized.
    initialized: bool,
}

impl PciePhy {
    /// Creates a new PCIe PHY instance.
    ///
    /// # Arguments
    /// * `id` — PHY identifier.
    /// * `base_addr` — MMIO base address.
    /// * `max_gen` — Maximum supported PCIe generation.
    /// * `lane_count` — Number of physical lanes (1, 2, 4, 8, or 16).
    pub const fn new(id: u8, base_addr: u64, max_gen: PcieGen, lane_count: u8) -> Self {
        Self {
            id,
            base_addr,
            max_gen,
            lane_count,
            link_state: PcieLinkState::Disabled,
            current_gen: None,
            current_width: 0,
            lane_stats: [const { LaneStats::new() }; MAX_PCIE_LANES],
            initialized: false,
        }
    }

    /// Returns the PHY identifier.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the maximum supported PCIe generation.
    pub fn max_gen(&self) -> PcieGen {
        self.max_gen
    }

    /// Returns the number of physical lanes.
    pub fn lane_count(&self) -> u8 {
        self.lane_count
    }

    /// Returns the current link state.
    pub fn link_state(&self) -> PcieLinkState {
        self.link_state
    }

    /// Returns the currently negotiated generation, or None if not trained.
    pub fn current_gen(&self) -> Option<PcieGen> {
        self.current_gen
    }

    /// Returns the currently negotiated lane width, or 0 if not trained.
    pub fn current_width(&self) -> u8 {
        self.current_width
    }

    /// Initializes the PCIe PHY hardware.
    ///
    /// Powers on the PLL, releases resets, and waits for PLL lock.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    /// Returns `Error::IoError` if PLL lock times out.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to PCIe PHY power and PLL registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1); // PHY reset
            ctrl.write_volatile(0x0); // Release reset

            let pll = (self.base_addr + 0x04) as *mut u32;
            let gen_val = match self.max_gen {
                PcieGen::Gen1 => 1u32,
                PcieGen::Gen2 => 2,
                PcieGen::Gen3 => 3,
                PcieGen::Gen4 => 4,
                PcieGen::Gen5 => 5,
                PcieGen::Gen6 => 6,
            };
            pll.write_volatile(gen_val | 0x100); // Set rate + enable

            let sr = (self.base_addr + 0x08) as *const u32;
            let mut timeout = 10_000u32;
            while sr.read_volatile() & 0x1 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::IoError);
                }
            }
        }
        self.link_state = PcieLinkState::L3;
        self.initialized = true;
        Ok(())
    }

    /// Initiates PCIe link training.
    ///
    /// Attempts to negotiate the highest common generation and lane width
    /// with the downstream component.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::IoError` if link training fails or times out.
    pub fn train_link(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO writes/reads to PCIe link training registers. base_addr is non-zero.
        unsafe {
            let ltrain = (self.base_addr + 0x10) as *mut u32;
            ltrain.write_volatile(0x1); // Start training
            let lstatus = (self.base_addr + 0x14) as *const u32;
            let mut timeout = 100_000u32;
            while lstatus.read_volatile() & 0x1 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::IoError);
                }
            }
            // Read negotiated gen and width
            let lspeed = (self.base_addr + 0x18) as *const u32;
            let speed_raw = lspeed.read_volatile();
            let pcie_gen = match speed_raw & 0xF {
                1 => PcieGen::Gen1,
                2 => PcieGen::Gen2,
                3 => PcieGen::Gen3,
                4 => PcieGen::Gen4,
                5 => PcieGen::Gen5,
                _ => PcieGen::Gen1,
            };
            let width = ((speed_raw >> 4) & 0x1F) as u8;
            self.current_gen = Some(pcie_gen);
            self.current_width = width.max(1);
        }
        self.link_state = PcieLinkState::L0;
        for stat in self.lane_stats[..self.lane_count as usize].iter_mut() {
            stat.training_count += 1;
        }
        Ok(())
    }

    /// Transitions the PCIe link to a lower power state.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if the target state is invalid.
    pub fn enter_low_power(&mut self, target: PcieLinkState) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if target == PcieLinkState::L0 || target == PcieLinkState::Disabled {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to PCIe power management control register. base_addr is non-zero.
        unsafe {
            let pmctl = (self.base_addr + 0x1C) as *mut u32;
            let state_val = match target {
                PcieLinkState::L0s => 1u32,
                PcieLinkState::L1 => 2,
                PcieLinkState::L1Sub1 => 3,
                PcieLinkState::L1Sub2 => 4,
                PcieLinkState::L2 => 5,
                PcieLinkState::L3 => 6,
                _ => return Err(Error::InvalidArgument),
            };
            pmctl.write_volatile(state_val);
        }
        self.link_state = target;
        Ok(())
    }

    /// Returns lane statistics for the given lane.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if lane_index is out of range.
    pub fn lane_stats(&self, lane_index: usize) -> Result<LaneStats> {
        if lane_index >= self.lane_count as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(self.lane_stats[lane_index])
    }
}

impl Default for PciePhy {
    fn default() -> Self {
        Self::new(0, 0, PcieGen::Gen3, 4)
    }
}

/// Registry of PCIe PHY instances.
pub struct PciePhyRegistry {
    phys: [PciePhy; MAX_PCIE_PHY],
    count: usize,
}

impl PciePhyRegistry {
    /// Creates a new empty PCIe PHY registry.
    pub fn new() -> Self {
        Self {
            phys: [
                PciePhy::new(0, 0, PcieGen::Gen3, 4),
                PciePhy::new(1, 0, PcieGen::Gen4, 4),
                PciePhy::new(2, 0, PcieGen::Gen3, 8),
                PciePhy::new(3, 0, PcieGen::Gen5, 16),
            ],
            count: 0,
        }
    }

    /// Registers a PCIe PHY.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, phy: PciePhy) -> Result<()> {
        if self.count >= MAX_PCIE_PHY {
            return Err(Error::OutOfMemory);
        }
        self.phys[self.count] = phy;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered PHYs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no PHYs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the PHY at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut PciePhy> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.phys[index])
    }
}

impl Default for PciePhyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the theoretical peak bandwidth for a PCIe link in Mbps.
///
/// # Arguments
/// * `gen` — PCIe generation.
/// * `lanes` — Number of active lanes (x1, x2, x4, x8, x16).
pub fn compute_bandwidth_mbps(pcie_gen: PcieGen, lanes: u8) -> u64 {
    pcie_gen.lane_bandwidth_mbps() * lanes as u64
}

/// Returns whether a lane count is a valid PCIe lane width.
pub fn is_valid_lane_width(lanes: u8) -> bool {
    matches!(lanes, 1 | 2 | 4 | 8 | 16)
}
