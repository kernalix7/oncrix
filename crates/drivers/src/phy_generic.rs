// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic PHY (Physical Layer) driver.
//!
//! Provides IEEE 802.3 compliant management of Ethernet PHY devices via
//! the MDIO (Management Data Input/Output) interface. Supports auto-negotiation,
//! link-speed detection, and standard register access for 10/100/1000 Mbps PHYs.

use oncrix_lib::{Error, Result};

/// Standard MII (Media Independent Interface) register numbers.
pub const MII_BMCR: u16 = 0x00; // Basic Mode Control Register
pub const MII_BMSR: u16 = 0x01; // Basic Mode Status Register
pub const MII_PHYSID1: u16 = 0x02; // PHY Identifier 1
pub const MII_PHYSID2: u16 = 0x03; // PHY Identifier 2
pub const MII_ADVERTISE: u16 = 0x04; // Auto-negotiation advertisement
pub const MII_LPA: u16 = 0x05; // Link partner ability (received)
pub const MII_EXPANSION: u16 = 0x06; // Auto-negotiation expansion
pub const MII_CTRL1000: u16 = 0x09; // 1000BASE-T control
pub const MII_STAT1000: u16 = 0x0A; // 1000BASE-T status
pub const MII_ESTATUS: u16 = 0x0F; // Extended status

/// BMCR (Basic Mode Control) bits.
pub const BMCR_SPEED100: u16 = 1 << 13;
pub const BMCR_ANENABLE: u16 = 1 << 12; // Auto-negotiation enable
pub const BMCR_PWRDOWN: u16 = 1 << 11; // Power-down
pub const BMCR_ISOLATE: u16 = 1 << 10; // Electrically isolate PHY
pub const BMCR_ANRESTART: u16 = 1 << 9; // Restart auto-negotiation
pub const BMCR_FULLDPLX: u16 = 1 << 8; // Full duplex
pub const BMCR_CTST: u16 = 1 << 7; // Collision test
pub const BMCR_SPEED1000: u16 = 1 << 6; // 1000 Mbps (in conjunction with SPEED100=0)
pub const BMCR_RESET: u16 = 1 << 15; // PHY reset

/// BMSR (Basic Mode Status) bits.
pub const BMSR_100FULL: u16 = 1 << 14; // 100BASE-TX full duplex
pub const BMSR_100HALF: u16 = 1 << 13; // 100BASE-TX half duplex
pub const BMSR_10FULL: u16 = 1 << 12; // 10BASE-T full duplex
pub const BMSR_10HALF: u16 = 1 << 11; // 10BASE-T half duplex
pub const BMSR_ANEGCAPABLE: u16 = 1 << 3; // Auto-negotiation capable
pub const BMSR_ANEGCOMPLETE: u16 = 1 << 5; // Auto-negotiation complete
pub const BMSR_LSTATUS: u16 = 1 << 2; // Link status
pub const BMSR_ERCAP: u16 = 1 << 0; // Extended register capabilities

/// ADVERTISE bits (advertised capabilities).
pub const ADVERTISE_10HALF: u16 = 1 << 5;
pub const ADVERTISE_10FULL: u16 = 1 << 6;
pub const ADVERTISE_100HALF: u16 = 1 << 7;
pub const ADVERTISE_100FULL: u16 = 1 << 8;
pub const ADVERTISE_PAUSE: u16 = 1 << 10;
pub const ADVERTISE_ASYM_PAUSE: u16 = 1 << 11;
pub const ADVERTISE_ALL: u16 =
    ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | ADVERTISE_100FULL;

/// CTRL1000 bits (1000BASE-T advertisement).
pub const ADVERTISE_1000HALF: u16 = 1 << 8;
pub const ADVERTISE_1000FULL: u16 = 1 << 9;

/// Link speed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speed {
    /// 10 Mbps.
    Mbps10,
    /// 100 Mbps.
    Mbps100,
    /// 1000 Mbps.
    Mbps1000,
    /// Unknown / not yet determined.
    Unknown,
}

/// Duplex mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duplex {
    /// Half duplex.
    Half,
    /// Full duplex.
    Full,
}

/// PHY link state.
#[derive(Clone, Copy, Debug)]
pub struct PhyLinkState {
    /// Link is up.
    pub up: bool,
    /// Negotiated speed.
    pub speed: Speed,
    /// Negotiated duplex mode.
    pub duplex: Duplex,
    /// Auto-negotiation is complete.
    pub aneg_complete: bool,
    /// Pause frames enabled.
    pub pause: bool,
}

impl Default for PhyLinkState {
    fn default() -> Self {
        Self {
            up: false,
            speed: Speed::Unknown,
            duplex: Duplex::Half,
            aneg_complete: false,
            pause: false,
        }
    }
}

/// MDIO bus read/write function signature (provided by the MAC driver).
pub type MdioReadFn = fn(bus: usize, phy_addr: u8, reg: u16) -> u16;
pub type MdioWriteFn = fn(bus: usize, phy_addr: u8, reg: u16, val: u16);

/// Generic PHY driver.
pub struct PhyGeneric {
    /// MDIO bus number.
    bus: usize,
    /// PHY device address on the MDIO bus (0–31).
    phy_addr: u8,
    /// PHY identifier (OUI + model + revision).
    phy_id: u32,
    /// Current link state.
    link: PhyLinkState,
    /// MDIO read function.
    mdio_read: MdioReadFn,
    /// MDIO write function.
    mdio_write: MdioWriteFn,
}

impl PhyGeneric {
    /// Create a new generic PHY driver.
    ///
    /// # Arguments
    /// - `bus`: MDIO bus index
    /// - `phy_addr`: PHY address on the bus (0–31)
    /// - `mdio_read`: MDIO read callback
    /// - `mdio_write`: MDIO write callback
    pub fn new(bus: usize, phy_addr: u8, mdio_read: MdioReadFn, mdio_write: MdioWriteFn) -> Self {
        Self {
            bus,
            phy_addr,
            phy_id: 0,
            link: PhyLinkState::default(),
            mdio_read,
            mdio_write,
        }
    }

    /// Initialize the PHY: reset, read ID, configure advertisement.
    pub fn init(&mut self) -> Result<()> {
        self.reset()?;
        self.phy_id = self.read_phy_id()?;
        self.configure_aneg()?;
        Ok(())
    }

    /// Perform a software reset of the PHY.
    pub fn reset(&mut self) -> Result<()> {
        let bmcr = self.read(MII_BMCR);
        self.write(MII_BMCR, bmcr | BMCR_RESET);
        let mut tries = 0u32;
        loop {
            let bmcr_now = self.read(MII_BMCR);
            if (bmcr_now & BMCR_RESET) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 50_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Read the 32-bit PHY identifier from registers 0x02 and 0x03.
    fn read_phy_id(&self) -> Result<u32> {
        let id1 = self.read(MII_PHYSID1) as u32;
        let id2 = self.read(MII_PHYSID2) as u32;
        Ok((id1 << 16) | id2)
    }

    /// Configure auto-negotiation to advertise all supported speeds.
    fn configure_aneg(&mut self) -> Result<()> {
        self.write(MII_ADVERTISE, ADVERTISE_ALL | 0x0001); // selector = IEEE 802.3
        let bmsr = self.read(MII_BMSR);
        if (bmsr & BMSR_100FULL) != 0 || (bmsr & BMSR_10FULL) != 0 {
            // Check for 1000BASE-T capability.
            let ctrl1000 = self.read(MII_CTRL1000);
            if ctrl1000 != 0 {
                self.write(MII_CTRL1000, ADVERTISE_1000FULL | ADVERTISE_1000HALF);
            }
        }
        // Enable and restart auto-negotiation.
        let bmcr = self.read(MII_BMCR);
        self.write(MII_BMCR, bmcr | BMCR_ANENABLE | BMCR_ANRESTART);
        Ok(())
    }

    /// Poll the PHY for link state changes.
    ///
    /// Returns `Some(PhyLinkState)` if the state has changed, or `None`.
    pub fn poll_link(&mut self) -> Option<PhyLinkState> {
        let _bmsr = self.read(MII_BMSR);
        // Re-read to latch the latched-low LSTATUS bit.
        let bmsr = self.read(MII_BMSR);
        let up = (bmsr & BMSR_LSTATUS) != 0;
        let prev_up = self.link.up;
        if up == prev_up && self.link.aneg_complete {
            return None;
        }
        self.link.up = up;
        if up {
            let aneg_done = (bmsr & BMSR_ANEGCOMPLETE) != 0;
            self.link.aneg_complete = aneg_done;
            if aneg_done {
                self.resolve_aneg();
            }
        } else {
            self.link.speed = Speed::Unknown;
            self.link.aneg_complete = false;
        }
        Some(self.link)
    }

    /// Resolve the auto-negotiated speed and duplex from LPA register.
    fn resolve_aneg(&mut self) {
        let lpa = self.read(MII_LPA);
        let stat1000 = self.read(MII_STAT1000);
        if (stat1000 & (1 << 11)) != 0 {
            // Remote advertises 1000BASE-T full.
            self.link.speed = Speed::Mbps1000;
            self.link.duplex = Duplex::Full;
        } else if (stat1000 & (1 << 10)) != 0 {
            self.link.speed = Speed::Mbps1000;
            self.link.duplex = Duplex::Half;
        } else if (lpa & ADVERTISE_100FULL) != 0 {
            self.link.speed = Speed::Mbps100;
            self.link.duplex = Duplex::Full;
        } else if (lpa & ADVERTISE_100HALF) != 0 {
            self.link.speed = Speed::Mbps100;
            self.link.duplex = Duplex::Half;
        } else if (lpa & ADVERTISE_10FULL) != 0 {
            self.link.speed = Speed::Mbps10;
            self.link.duplex = Duplex::Full;
        } else {
            self.link.speed = Speed::Mbps10;
            self.link.duplex = Duplex::Half;
        }
        self.link.pause = (lpa & ADVERTISE_PAUSE) != 0;
    }

    /// Return the current link state.
    pub fn link_state(&self) -> &PhyLinkState {
        &self.link
    }

    /// Return the PHY identifier.
    pub fn phy_id(&self) -> u32 {
        self.phy_id
    }

    // --- MDIO helpers ---

    fn read(&self, reg: u16) -> u16 {
        (self.mdio_read)(self.bus, self.phy_addr, reg)
    }

    fn write(&mut self, reg: u16, val: u16) {
        (self.mdio_write)(self.bus, self.phy_addr, reg, val);
    }
}
