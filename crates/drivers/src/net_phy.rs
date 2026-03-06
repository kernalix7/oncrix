// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ethernet PHY driver.
//!
//! Implements a generic PHY driver supporting IEEE 802.3 clause 22 and
//! clause 45 MDIO access, standard PHY register definitions, auto-
//! negotiation, and link-state management.
//!
//! # Architecture
//!
//! - `PhyDevice` — PHY descriptor with link state.
//! - `PhyState` — link state machine.
//! - MDIO clause 22 register definitions (BMCR, BMSR, ADVERTISE, LPA).
//! - `MdioOps` trait — bus-specific read/write callbacks.

use oncrix_lib::{Error, Result};

// ── MDIO standard register addresses (clause 22) ─────────────────────────────

/// Basic Mode Control Register.
pub const MII_BMCR: u8 = 0x00;
/// Basic Mode Status Register.
pub const MII_BMSR: u8 = 0x01;
/// PHY Identifier 1.
pub const MII_PHYSID1: u8 = 0x02;
/// PHY Identifier 2.
pub const MII_PHYSID2: u8 = 0x03;
/// Auto-Negotiation Advertisement Register.
pub const MII_ADVERTISE: u8 = 0x04;
/// Auto-Negotiation Link Partner Ability Register.
pub const MII_LPA: u8 = 0x05;
/// Auto-Negotiation Expansion Register.
pub const MII_EXPANSION: u8 = 0x06;
/// 1000Base-T Control Register (PHY extended).
pub const MII_CTRL1000: u8 = 0x09;
/// 1000Base-T Status Register (PHY extended).
pub const MII_STAT1000: u8 = 0x0A;

// ── BMCR bit definitions ─────────────────────────────────────────────────────

/// BMCR: Reset bit (self-clearing).
pub const BMCR_RESET: u16 = 1 << 15;
/// BMCR: Loopback enable.
pub const BMCR_LOOPBACK: u16 = 1 << 14;
/// BMCR: Speed select bit 0 (100 Mbit if set, 10 Mbit if clear; with bit 13).
pub const BMCR_SPEED100: u16 = 1 << 13;
/// BMCR: Auto-Negotiation Enable.
pub const BMCR_ANENABLE: u16 = 1 << 12;
/// BMCR: Power Down.
pub const BMCR_PDOWN: u16 = 1 << 11;
/// BMCR: Isolate PHY from MII.
pub const BMCR_ISOLATE: u16 = 1 << 10;
/// BMCR: Restart Auto-Negotiation.
pub const BMCR_ANRESTART: u16 = 1 << 9;
/// BMCR: Full duplex if set, half duplex if clear.
pub const BMCR_FULLDPLX: u16 = 1 << 8;
/// BMCR: Speed select bit 1 (1000 Mbit if set along with SPEED100=0).
pub const BMCR_SPEED1000: u16 = 1 << 6;

// ── BMSR bit definitions ─────────────────────────────────────────────────────

/// BMSR: 100Base-T4 capable.
pub const BMSR_100BASE4: u16 = 1 << 15;
/// BMSR: 100Base-TX full duplex capable.
pub const BMSR_100FULL: u16 = 1 << 14;
/// BMSR: 100Base-TX half duplex capable.
pub const BMSR_100HALF: u16 = 1 << 13;
/// BMSR: 10Base-T full duplex capable.
pub const BMSR_10FULL: u16 = 1 << 12;
/// BMSR: 10Base-T half duplex capable.
pub const BMSR_10HALF: u16 = 1 << 11;
/// BMSR: Auto-Negotiation complete.
pub const BMSR_ANEGCOMPLETE: u16 = 1 << 5;
/// BMSR: Remote fault.
pub const BMSR_RFAULT: u16 = 1 << 4;
/// BMSR: Auto-Negotiation ability.
pub const BMSR_ANEGCAPABLE: u16 = 1 << 3;
/// BMSR: Link status (latching, clear-on-read in some devices).
pub const BMSR_LSTATUS: u16 = 1 << 2;
/// BMSR: Jabber detect.
pub const BMSR_JCD: u16 = 1 << 1;
/// BMSR: Extended capability (registers 2+).
pub const BMSR_EXTCAP: u16 = 1 << 0;

// ── ADVERTISE / LPA bit definitions ──────────────────────────────────────────

/// ADVERTISE: 100Base-TX full duplex.
pub const ADVERTISE_100FULL: u16 = 1 << 8;
/// ADVERTISE: 100Base-TX half duplex.
pub const ADVERTISE_100HALF: u16 = 1 << 7;
/// ADVERTISE: 10Base-T full duplex.
pub const ADVERTISE_10FULL: u16 = 1 << 6;
/// ADVERTISE: 10Base-T half duplex.
pub const ADVERTISE_10HALF: u16 = 1 << 5;
/// ADVERTISE: CSMA/CD capable.
pub const ADVERTISE_CSMA: u16 = 1 << 0;

// ── PhySpeed ─────────────────────────────────────────────────────────────────

/// Link speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhySpeed {
    /// 10 Mbps.
    Speed10,
    /// 100 Mbps.
    Speed100,
    /// 1000 Mbps (1 Gbps).
    Speed1000,
    /// Link is down or speed unknown.
    Unknown,
}

// ── PhyDuplex ────────────────────────────────────────────────────────────────

/// Duplex mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyDuplex {
    /// Half duplex.
    Half,
    /// Full duplex.
    Full,
    /// Unknown / not yet negotiated.
    Unknown,
}

// ── PhyState ─────────────────────────────────────────────────────────────────

/// PHY link state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyState {
    /// PHY has been detected but not yet configured.
    Down,
    /// Auto-negotiation in progress.
    Negotiating,
    /// Link established.
    Up,
    /// PHY driver detached.
    Halted,
}

// ── MdioOps ──────────────────────────────────────────────────────────────────

/// MDIO bus read/write operations.
///
/// Implementors provide the actual clause 22 (or clause 45) bus access.
pub trait MdioOps {
    /// Read a clause 22 PHY register.
    ///
    /// `phy_addr` is the 5-bit PHY address (0–31). `reg` is the register
    /// number (0–31).
    ///
    /// # Errors
    ///
    /// Return [`Error::IoError`] on MDIO bus timeout or error.
    fn read_c22(&mut self, phy_addr: u8, reg: u8) -> Result<u16>;

    /// Write a clause 22 PHY register.
    ///
    /// # Errors
    ///
    /// Return [`Error::IoError`] on MDIO bus timeout or error.
    fn write_c22(&mut self, phy_addr: u8, reg: u8, val: u16) -> Result<()>;

    /// Read a clause 45 PHY register.
    ///
    /// `phy_addr` is the 5-bit PHY address. `mmd` is the MMD device number
    /// (0–31). `reg` is the 16-bit register address.
    ///
    /// # Errors
    ///
    /// Return [`Error::NotImplemented`] if clause 45 is not supported.
    fn read_c45(&mut self, phy_addr: u8, mmd: u8, reg: u16) -> Result<u16>;

    /// Write a clause 45 PHY register.
    fn write_c45(&mut self, phy_addr: u8, mmd: u8, reg: u16, val: u16) -> Result<()>;
}

// ── PhyDevice ────────────────────────────────────────────────────────────────

/// Ethernet PHY device descriptor.
pub struct PhyDevice {
    /// 5-bit MDIO PHY address (0–31).
    pub phy_addr: u8,
    /// Combined OUI + model + revision from registers 2 and 3.
    pub phy_id: u32,
    /// Current link speed.
    pub speed: PhySpeed,
    /// Current duplex mode.
    pub duplex: PhyDuplex,
    /// Whether auto-negotiation is enabled.
    pub autoneg: bool,
    /// Current link state.
    pub state: PhyState,
    /// Advertised capabilities bitmask (ADVERTISE register format).
    pub advertising: u16,
    /// Partner capabilities (LPA register).
    pub lp_advertising: u16,
    /// Whether the PHY is connected to an MAC.
    pub attached: bool,
}

impl PhyDevice {
    /// Create a new PHY device descriptor.
    pub const fn new(phy_addr: u8) -> Self {
        Self {
            phy_addr,
            phy_id: 0,
            speed: PhySpeed::Unknown,
            duplex: PhyDuplex::Unknown,
            autoneg: true,
            state: PhyState::Down,
            advertising: ADVERTISE_CSMA
                | ADVERTISE_10HALF
                | ADVERTISE_10FULL
                | ADVERTISE_100HALF
                | ADVERTISE_100FULL,
            lp_advertising: 0,
            attached: false,
        }
    }

    /// Connect this PHY to a MAC, read PHY ID, and start auto-negotiation.
    ///
    /// # Errors
    ///
    /// Propagates MDIO errors.
    pub fn connect(&mut self, mdio: &mut dyn MdioOps) -> Result<()> {
        // Read PHY ID.
        let id1 = mdio.read_c22(self.phy_addr, MII_PHYSID1)? as u32;
        let id2 = mdio.read_c22(self.phy_addr, MII_PHYSID2)? as u32;
        self.phy_id = (id1 << 16) | id2;

        self.attached = true;
        self.state = PhyState::Negotiating;

        // Write advertising register.
        mdio.write_c22(self.phy_addr, MII_ADVERTISE, self.advertising)?;

        // Restart auto-negotiation.
        if self.autoneg {
            let bmcr = mdio.read_c22(self.phy_addr, MII_BMCR)?;
            mdio.write_c22(
                self.phy_addr,
                MII_BMCR,
                bmcr | BMCR_ANENABLE | BMCR_ANRESTART,
            )?;
        }

        Ok(())
    }

    /// Disconnect from the MAC.
    pub fn disconnect(&mut self) {
        self.attached = false;
        self.state = PhyState::Halted;
        self.speed = PhySpeed::Unknown;
        self.duplex = PhyDuplex::Unknown;
    }

    /// Poll the PHY for link status changes.
    ///
    /// Updates `speed`, `duplex`, and `state` from the BMSR/BMCR registers.
    ///
    /// # Errors
    ///
    /// Propagates MDIO errors.
    pub fn poll_link(&mut self, mdio: &mut dyn MdioOps) -> Result<()> {
        let bmsr = mdio.read_c22(self.phy_addr, MII_BMSR)?;

        if bmsr & BMSR_LSTATUS == 0 {
            if self.state == PhyState::Up {
                self.state = PhyState::Down;
                self.speed = PhySpeed::Unknown;
                self.duplex = PhyDuplex::Unknown;
            }
            return Ok(());
        }

        // Link is up.
        if bmsr & BMSR_ANEGCOMPLETE != 0 {
            self.lp_advertising = mdio.read_c22(self.phy_addr, MII_LPA)?;
            self.resolve_speed_duplex();
            self.state = PhyState::Up;
        }

        Ok(())
    }

    /// Reset the PHY via BMCR.
    ///
    /// Polls until the reset bit self-clears (up to 1000 iterations).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if reset does not complete.
    pub fn reset(&mut self, mdio: &mut dyn MdioOps) -> Result<()> {
        mdio.write_c22(self.phy_addr, MII_BMCR, BMCR_RESET)?;
        for _ in 0..1000 {
            let bmcr = mdio.read_c22(self.phy_addr, MII_BMCR)?;
            if bmcr & BMCR_RESET == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Force a specific speed and duplex without auto-negotiation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown speed.
    pub fn force_speed_duplex(
        &mut self,
        mdio: &mut dyn MdioOps,
        speed: PhySpeed,
        duplex: PhyDuplex,
    ) -> Result<()> {
        let mut bmcr = 0u16;
        match speed {
            PhySpeed::Speed10 => {}
            PhySpeed::Speed100 => {
                bmcr |= BMCR_SPEED100;
            }
            PhySpeed::Speed1000 => {
                bmcr |= BMCR_SPEED1000;
            }
            PhySpeed::Unknown => return Err(Error::InvalidArgument),
        }
        if duplex == PhyDuplex::Full {
            bmcr |= BMCR_FULLDPLX;
        }
        mdio.write_c22(self.phy_addr, MII_BMCR, bmcr)?;
        self.autoneg = false;
        self.speed = speed;
        self.duplex = duplex;
        self.state = PhyState::Up;
        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Resolve negotiated speed and duplex from the LPA register.
    fn resolve_speed_duplex(&mut self) {
        let common = self.advertising & self.lp_advertising;
        if common & ADVERTISE_100FULL != 0 {
            self.speed = PhySpeed::Speed100;
            self.duplex = PhyDuplex::Full;
        } else if common & ADVERTISE_100HALF != 0 {
            self.speed = PhySpeed::Speed100;
            self.duplex = PhyDuplex::Half;
        } else if common & ADVERTISE_10FULL != 0 {
            self.speed = PhySpeed::Speed10;
            self.duplex = PhyDuplex::Full;
        } else {
            self.speed = PhySpeed::Speed10;
            self.duplex = PhyDuplex::Half;
        }
    }
}
