// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe link training and speed/width management.
//!
//! Implements the PCIe link training state machine, speed negotiation
//! (Gen1 through Gen5), link width detection (x1–x16), and Active State
//! Power Management (ASPM) configuration (L0s / L1).
//!
//! # Link Training Flow
//!
//! 1. [`PcieLinkTrainer::detect`] — physical layer detects receiver.
//! 2. [`PcieLinkTrainer::polling`] — both ends transmit TS1/TS2 ordered sets.
//! 3. [`PcieLinkTrainer::config`] — agree on link width and speed.
//! 4. [`PcieLinkTrainer::l0`] — normal operational state.
//! 5. Speed change requests call [`PcieLinkTrainer::request_speed_change`].
//!
//! Reference: PCIe Base Specification 5.0, Section 4.2;
//! Linux `drivers/pci/pcie/aspm.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — PCIe Link Control / Status register offsets (from cap base)
// ---------------------------------------------------------------------------

/// Link Capabilities register offset (from PCIe capability base).
pub const LNKCAP_OFFSET: u8 = 0x0C;

/// Link Control register offset.
pub const LNKCTL_OFFSET: u8 = 0x10;

/// Link Status register offset.
pub const LNKSTA_OFFSET: u8 = 0x12;

/// Link Control 2 register offset.
pub const LNKCTL2_OFFSET: u8 = 0x30;

/// Link Status 2 register offset.
pub const LNKSTA2_OFFSET: u8 = 0x32;

/// LNKCTL bit: ASPM L0s enable.
pub const LNKCTL_ASPM_L0S: u16 = 1 << 0;

/// LNKCTL bit: ASPM L1 enable.
pub const LNKCTL_ASPM_L1: u16 = 1 << 1;

/// LNKCTL bit: retrain link.
pub const LNKCTL_RETRAIN: u16 = 1 << 5;

/// LNKSTA bit: link training in progress.
pub const LNKSTA_TRAINING: u16 = 1 << 11;

/// LNKSTA current link speed mask (bits [3:0]).
pub const LNKSTA_SPEED_MASK: u16 = 0x000F;

/// LNKSTA current link width mask (bits [9:4]).
pub const LNKSTA_WIDTH_MASK: u16 = 0x03F0;

/// LNKSTA link width shift.
pub const LNKSTA_WIDTH_SHIFT: u16 = 4;

/// Maximum training polling iterations before timeout.
const TRAIN_POLL_MAX: u32 = 100_000;

/// Maximum number of PCIe links tracked.
const MAX_LINKS: usize = 16;

// ---------------------------------------------------------------------------
// Link Speed
// ---------------------------------------------------------------------------

/// PCIe link speed encoding (matches LNKSTA Current Link Speed field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LinkSpeed {
    /// 2.5 GT/s (Gen 1).
    Gen1 = 1,
    /// 5.0 GT/s (Gen 2).
    Gen2 = 2,
    /// 8.0 GT/s (Gen 3).
    Gen3 = 3,
    /// 16.0 GT/s (Gen 4).
    Gen4 = 4,
    /// 32.0 GT/s (Gen 5).
    Gen5 = 5,
}

impl LinkSpeed {
    /// Parse from a raw LNKSTA speed field value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown values.
    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            1 => Ok(Self::Gen1),
            2 => Ok(Self::Gen2),
            3 => Ok(Self::Gen3),
            4 => Ok(Self::Gen4),
            5 => Ok(Self::Gen5),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the transfer rate in MT/s for display purposes.
    pub fn megatransfers_per_sec(self) -> u32 {
        match self {
            Self::Gen1 => 2_500,
            Self::Gen2 => 5_000,
            Self::Gen3 => 8_000,
            Self::Gen4 => 16_000,
            Self::Gen5 => 32_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Link Width
// ---------------------------------------------------------------------------

/// PCIe link width (number of lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LinkWidth {
    /// x1 — 1 lane.
    X1 = 1,
    /// x2 — 2 lanes.
    X2 = 2,
    /// x4 — 4 lanes.
    X4 = 4,
    /// x8 — 8 lanes.
    X8 = 8,
    /// x16 — 16 lanes.
    X16 = 16,
    /// x32 — 32 lanes.
    X32 = 32,
}

impl LinkWidth {
    /// Parse from raw LNKSTA width field.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unsupported values.
    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            1 => Ok(Self::X1),
            2 => Ok(Self::X2),
            4 => Ok(Self::X4),
            8 => Ok(Self::X8),
            16 => Ok(Self::X16),
            32 => Ok(Self::X32),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// Link Training State Machine
// ---------------------------------------------------------------------------

/// PCIe LTSSM (Link Training and Status State Machine) state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ltssm {
    /// Detect.Quiet — searching for receiver.
    Detect,
    /// Polling — transmitting ordered sets.
    Polling,
    /// Configuration — negotiating width and speed.
    Config,
    /// L0 — operational.
    L0,
    /// L0s — low-latency power state.
    L0s,
    /// L1 — low-power state.
    L1,
    /// Recovery — retraining after error.
    Recovery,
    /// Hot Reset.
    HotReset,
    /// Disabled.
    Disabled,
    /// Loopback.
    Loopback,
}

// ---------------------------------------------------------------------------
// ASPM Policy
// ---------------------------------------------------------------------------

/// ASPM (Active State Power Management) policy for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AspmPolicy {
    /// Allow L0s entry.
    pub l0s_enabled: bool,
    /// Allow L1 entry.
    pub l1_enabled: bool,
}

impl AspmPolicy {
    /// ASPM fully disabled.
    pub const fn disabled() -> Self {
        Self {
            l0s_enabled: false,
            l1_enabled: false,
        }
    }

    /// L1 only (most common safe policy).
    pub const fn l1_only() -> Self {
        Self {
            l0s_enabled: false,
            l1_enabled: true,
        }
    }

    /// L0s and L1 both enabled.
    pub const fn full() -> Self {
        Self {
            l0s_enabled: true,
            l1_enabled: true,
        }
    }

    /// Encode into LNKCTL bits.
    pub fn to_lnkctl_bits(self) -> u16 {
        let mut bits: u16 = 0;
        if self.l0s_enabled {
            bits |= LNKCTL_ASPM_L0S;
        }
        if self.l1_enabled {
            bits |= LNKCTL_ASPM_L1;
        }
        bits
    }
}

// ---------------------------------------------------------------------------
// PCIe Link State
// ---------------------------------------------------------------------------

/// Tracked state for a single PCIe link.
#[derive(Debug, Clone, Copy)]
pub struct PcieLinkState {
    /// PCIe capability base offset in config space.
    pub cap_offset: u8,
    /// PCI bus/device/function (encoded as u16: bus<<8 | dev<<3 | fn).
    pub bdf: u16,
    /// Maximum supported link speed.
    pub max_speed: LinkSpeed,
    /// Maximum supported link width.
    pub max_width: LinkWidth,
    /// Current negotiated link speed.
    pub current_speed: LinkSpeed,
    /// Current negotiated link width.
    pub current_width: LinkWidth,
    /// Current LTSSM state.
    pub ltssm: Ltssm,
    /// Active ASPM policy.
    pub aspm: AspmPolicy,
    /// Number of retraining attempts since last reset.
    pub retrain_count: u32,
}

impl PcieLinkState {
    /// Create a new link state in the Detect phase.
    pub const fn new(bdf: u16, cap_offset: u8) -> Self {
        Self {
            cap_offset,
            bdf,
            max_speed: LinkSpeed::Gen1,
            max_width: LinkWidth::X1,
            current_speed: LinkSpeed::Gen1,
            current_width: LinkWidth::X1,
            ltssm: Ltssm::Detect,
            aspm: AspmPolicy::disabled(),
            retrain_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Link Trainer
// ---------------------------------------------------------------------------

/// PCIe link trainer: manages training state machine and speed changes.
pub struct PcieLinkTrainer {
    state: PcieLinkState,
}

impl PcieLinkTrainer {
    /// Create a trainer for the given BDF and PCIe capability offset.
    pub const fn new(bdf: u16, cap_offset: u8) -> Self {
        Self {
            state: PcieLinkState::new(bdf, cap_offset),
        }
    }

    /// Simulate the Detect phase — transition to Polling.
    pub fn detect(&mut self) {
        self.state.ltssm = Ltssm::Polling;
    }

    /// Simulate the Polling phase — transition to Config.
    pub fn polling(&mut self) {
        self.state.ltssm = Ltssm::Config;
    }

    /// Parse LNKCAP and LNKSTA registers and transition to L0.
    ///
    /// `lnkcap` — contents of the Link Capabilities register.
    /// `lnksta` — contents of the Link Status register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if speed or width fields are invalid.
    pub fn config(&mut self, lnkcap: u32, lnksta: u16) -> Result<()> {
        let max_speed_raw = (lnkcap & 0x0F) as u8;
        let max_width_raw = ((lnkcap >> 4) & 0x3F) as u8;
        self.state.max_speed = LinkSpeed::from_raw(max_speed_raw)?;
        self.state.max_width = LinkWidth::from_raw(max_width_raw)?;

        let cur_speed_raw = (lnksta & LNKSTA_SPEED_MASK) as u8;
        let cur_width_raw = ((lnksta & LNKSTA_WIDTH_MASK) >> LNKSTA_WIDTH_SHIFT) as u8;
        self.state.current_speed = LinkSpeed::from_raw(cur_speed_raw)?;
        self.state.current_width = LinkWidth::from_raw(cur_width_raw)?;
        self.state.ltssm = Ltssm::L0;
        Ok(())
    }

    /// Request a target link speed change via LNKCTL2.
    ///
    /// Returns the new LNKCTL2 value to write to the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `target` exceeds `max_speed`.
    pub fn request_speed_change(&mut self, target: LinkSpeed) -> Result<u16> {
        if target > self.state.max_speed {
            return Err(Error::InvalidArgument);
        }
        // Encode target link speed into LNKCTL2[3:0].
        Ok(target as u16)
    }

    /// Trigger link retrain by returning the LNKCTL bit mask to set.
    ///
    /// The caller should OR this into the LNKCTL register and wait for
    /// LNKSTA.LinkTraining to clear.
    pub fn retrain(&mut self) -> u16 {
        self.state.ltssm = Ltssm::Recovery;
        self.state.retrain_count += 1;
        LNKCTL_RETRAIN
    }

    /// Poll LNKSTA to check whether training has completed.
    ///
    /// Returns `true` once `LNKSTA_TRAINING` clears.
    pub fn poll_training_done(&self, lnksta: u16) -> bool {
        lnksta & LNKSTA_TRAINING == 0
    }

    /// Apply an ASPM policy and return the LNKCTL bits to write.
    pub fn apply_aspm(&mut self, policy: AspmPolicy) -> u16 {
        self.state.aspm = policy;
        policy.to_lnkctl_bits()
    }

    /// Returns a reference to the current link state.
    pub fn link_state(&self) -> &PcieLinkState {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// Global Link Registry
// ---------------------------------------------------------------------------

/// Registry of all managed PCIe links.
pub struct PcieLinkRegistry {
    links: [Option<PcieLinkTrainer>; MAX_LINKS],
    count: usize,
}

impl PcieLinkRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<PcieLinkTrainer> = None;
        Self {
            links: [NONE; MAX_LINKS],
            count: 0,
        }
    }

    /// Register a new link.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    /// Returns [`Error::AlreadyExists`] if a link for `bdf` already exists.
    pub fn register(&mut self, bdf: u16, cap_offset: u8) -> Result<()> {
        for slot in self.links.iter().flatten() {
            if slot.link_state().bdf == bdf {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .links
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.links[idx] = Some(PcieLinkTrainer::new(bdf, cap_offset));
        self.count += 1;
        Ok(())
    }

    /// Get a mutable reference to a link by BDF.
    pub fn get_mut(&mut self, bdf: u16) -> Option<&mut PcieLinkTrainer> {
        self.links
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|t| t.link_state().bdf == bdf)
    }

    /// Returns the number of registered links.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no links are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PcieLinkRegistry {
    fn default() -> Self {
        Self::new()
    }
}
