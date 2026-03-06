// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MDIO/PHY Ethernet PHY management driver.
//!
//! The Management Data Input/Output (MDIO) interface (IEEE 802.3
//! clause 22/45) provides serial access to Ethernet PHY registers.
//! This module implements an MDIO bus controller and PHY device
//! abstraction for link detection, auto-negotiation, and
//! speed/duplex configuration.
//!
//! # Architecture
//!
//! - **MdioBus** — controls the MDIO interface via MMIO registers
//!   and provides register-level read/write access to PHYs.
//! - **PhyDevice** — represents a single Ethernet PHY identified
//!   by an OUI/model/revision tuple. Tracks link state, speed,
//!   duplex, and auto-negotiation status.
//!
//! # Standard MII Registers (Clause 22)
//!
//! | Register | Name             | Description           |
//! |----------|------------------|-----------------------|
//! | 0        | Control          | Reset, speed, AN      |
//! | 1        | Status           | Link, AN ability      |
//! | 2        | PHY ID 1         | OUI bits [3:18]       |
//! | 3        | PHY ID 2         | OUI [19:24], model    |
//! | 4        | AN Advertisement | Local capabilities    |
//! | 5        | AN Link Partner  | Partner capabilities  |
//! | 6        | AN Expansion     | AN page info          |
//! | 9        | 1000BASE-T Ctrl  | Gigabit advertisement |
//! | 10       | 1000BASE-T Stat  | Gigabit partner caps  |
//!
//! Reference: IEEE 802.3-2022, Section 22.2.4.

use oncrix_lib::{Error, Result};

// ── MII Register Addresses ───────────────────────────────────────

/// MII Control register (register 0).
const MII_BMCR: u8 = 0;

/// MII Status register (register 1).
const MII_BMSR: u8 = 1;

/// PHY Identifier register 1 (register 2).
const MII_PHYSID1: u8 = 2;

/// PHY Identifier register 2 (register 3).
const MII_PHYSID2: u8 = 3;

/// Auto-Negotiation Advertisement register (register 4).
const MII_ADVERTISE: u8 = 4;

/// Auto-Negotiation Link Partner Ability register (register 5).
const MII_LPA: u8 = 5;

/// Auto-Negotiation Expansion register (register 6).
const _MII_EXPANSION: u8 = 6;

/// 1000BASE-T Control register (register 9).
const MII_CTRL1000: u8 = 9;

/// 1000BASE-T Status register (register 10).
const MII_STAT1000: u8 = 10;

// ── BMCR (Control) Bits ──────────────────────────────────────────

/// Software reset (self-clearing).
const BMCR_RESET: u16 = 1 << 15;

/// Enable loopback mode.
const _BMCR_LOOPBACK: u16 = 1 << 14;

/// Speed select LSB: 0 = 10 Mbps, 1 = 100 Mbps.
const BMCR_SPEED100: u16 = 1 << 13;

/// Enable auto-negotiation.
const BMCR_ANENABLE: u16 = 1 << 12;

/// Power down the PHY.
const BMCR_PDOWN: u16 = 1 << 11;

/// Restart auto-negotiation process.
const BMCR_ANRESTART: u16 = 1 << 9;

/// Full duplex mode.
const BMCR_FULLDPLX: u16 = 1 << 8;

/// Speed select MSB (with bit 13): 1,0 = 1000 Mbps.
const BMCR_SPEED1000: u16 = 1 << 6;

// ── BMSR (Status) Bits ───────────────────────────────────────────

/// 100BASE-TX full duplex capable.
const BMSR_100FULL: u16 = 1 << 14;

/// 100BASE-TX half duplex capable.
const BMSR_100HALF: u16 = 1 << 13;

/// 10BASE-T full duplex capable.
const BMSR_10FULL: u16 = 1 << 12;

/// 10BASE-T half duplex capable.
const BMSR_10HALF: u16 = 1 << 11;

/// Extended status register (register 15) exists.
const _BMSR_ESTATEN: u16 = 1 << 8;

/// Auto-negotiation complete.
const BMSR_ANEGCOMPLETE: u16 = 1 << 5;

/// Remote fault detected.
const _BMSR_RFAULT: u16 = 1 << 4;

/// PHY is able to auto-negotiate.
const BMSR_ANEGCAPABLE: u16 = 1 << 3;

/// Link is up.
const BMSR_LSTATUS: u16 = 1 << 2;

// ── Advertisement / LPA Bits ─────────────────────────────────────

/// Advertise 10BASE-T half duplex.
const ADVERTISE_10HALF: u16 = 1 << 5;

/// Advertise 10BASE-T full duplex.
const ADVERTISE_10FULL: u16 = 1 << 6;

/// Advertise 100BASE-TX half duplex.
const ADVERTISE_100HALF: u16 = 1 << 7;

/// Advertise 100BASE-TX full duplex.
const ADVERTISE_100FULL: u16 = 1 << 8;

/// Advertise pause (flow control).
const ADVERTISE_PAUSE: u16 = 1 << 10;

/// IEEE 802.3 selector field.
const ADVERTISE_CSMA: u16 = 0x0001;

// ── 1000BASE-T Ctrl / Stat Bits ─────────────────────────────────

/// Advertise 1000BASE-T full duplex.
const ADVERTISE_1000FULL: u16 = 1 << 9;

/// Advertise 1000BASE-T half duplex.
const ADVERTISE_1000HALF: u16 = 1 << 8;

/// Link partner supports 1000BASE-T full duplex.
const LPA_1000FULL: u16 = 1 << 11;

/// Link partner supports 1000BASE-T half duplex.
const LPA_1000HALF: u16 = 1 << 10;

// ── MDIO MMIO Register Offsets ───────────────────────────────────

/// MDIO control register.
const REG_MDIO_CTRL: u32 = 0x00;

/// MDIO data register.
const REG_MDIO_DATA: u32 = 0x04;

/// MDIO address register (PHY addr + reg addr).
const REG_MDIO_ADDR: u32 = 0x08;

/// MDIO status register.
const REG_MDIO_STATUS: u32 = 0x0C;

// ── MDIO Control Bits ────────────────────────────────────────────

/// Start an MDIO read operation.
const MDIO_CTRL_READ: u32 = 1 << 0;

/// Start an MDIO write operation.
const MDIO_CTRL_WRITE: u32 = 1 << 1;

/// MDIO operation busy.
const MDIO_STATUS_BUSY: u32 = 1 << 0;

/// MDIO operation complete.
const MDIO_STATUS_DONE: u32 = 1 << 1;

// ── Limits & Timeouts ────────────────────────────────────────────

/// Maximum PHY address on an MDIO bus (0-31).
const MAX_PHY_ADDR: u8 = 31;

/// Maximum number of PHY devices we track per bus.
const MAX_PHYS: usize = 32;

/// Maximum number of MDIO bus controllers.
const MAX_BUSES: usize = 4;

/// MDIO operation polling timeout (iterations).
const MDIO_TIMEOUT: u32 = 100_000;

/// PHY reset polling timeout (iterations).
const PHY_RESET_TIMEOUT: u32 = 500_000;

/// Auto-negotiation polling timeout (iterations).
const AN_TIMEOUT: u32 = 1_000_000;

// ── MMIO Helpers ─────────────────────────────────────────────────

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ── MDIO Address ─────────────────────────────────────────────────

/// Identifies a PHY on an MDIO bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdioAddr {
    /// Bus identifier (index into bus registry).
    pub bus_id: u8,
    /// PHY address on the MDIO bus (0–31).
    pub phy_addr: u8,
}

impl MdioAddr {
    /// Create a new MDIO address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `phy_addr > 31`.
    pub fn new(bus_id: u8, phy_addr: u8) -> Result<Self> {
        if phy_addr > MAX_PHY_ADDR {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { bus_id, phy_addr })
    }
}

// ── PHY Identifier ───────────────────────────────────────────────

/// PHY device identifier from MII registers 2 and 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhyId {
    /// Organizationally Unique Identifier (22-bit OUI).
    pub oui: u32,
    /// Vendor model number (6 bits).
    pub model: u8,
    /// Revision number (4 bits).
    pub revision: u8,
}

impl PhyId {
    /// Construct a PHY ID from raw MII register values.
    ///
    /// `physid1` = MII register 2, `physid2` = MII register 3.
    pub fn from_regs(physid1: u16, physid2: u16) -> Self {
        // Register 2: bits [15:0] = OUI bits [3:18].
        // Register 3: bits [15:10] = OUI bits [19:24],
        //             bits [9:4] = model, bits [3:0] = revision.
        let oui_hi = (physid1 as u32) << 6;
        let oui_lo = (physid2 as u32 >> 10) & 0x3F;
        Self {
            oui: oui_hi | oui_lo,
            model: ((physid2 >> 4) & 0x3F) as u8,
            revision: (physid2 & 0x0F) as u8,
        }
    }

    /// Return `true` if the ID is all-ones (no PHY present).
    pub fn is_invalid(&self) -> bool {
        self.oui == 0x003F_FFFF && self.model == 0x3F && self.revision == 0x0F
    }

    /// Return `true` if the ID is all-zeros.
    pub fn is_zero(&self) -> bool {
        self.oui == 0 && self.model == 0 && self.revision == 0
    }
}

// ── Link Speed ───────────────────────────────────────────────────

/// Ethernet link speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSpeed {
    /// 10 Mbps.
    Speed10,
    /// 100 Mbps.
    Speed100,
    /// 1000 Mbps (Gigabit).
    Speed1000,
}

impl LinkSpeed {
    /// Return the speed in Mbps.
    pub fn mbps(self) -> u32 {
        match self {
            LinkSpeed::Speed10 => 10,
            LinkSpeed::Speed100 => 100,
            LinkSpeed::Speed1000 => 1000,
        }
    }
}

// ── Duplex Mode ──────────────────────────────────────────────────

/// Ethernet duplex mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplex {
    /// Half duplex.
    Half,
    /// Full duplex.
    Full,
}

// ── PHY State ────────────────────────────────────────────────────

/// Operational state of an Ethernet PHY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyState {
    /// PHY is powered down or not initialized.
    Down,
    /// PHY is initialized and ready but link is not established.
    Up,
    /// PHY is running with an active link.
    Running,
    /// PHY detected no link (cable disconnected or partner down).
    NoLink,
    /// PHY is halted (error state or administratively disabled).
    Halted,
}

// ── PHY Device ───────────────────────────────────────────────────

/// Represents a single Ethernet PHY device.
#[derive(Debug, Clone, Copy)]
pub struct PhyDevice {
    /// MDIO bus and address.
    pub addr: MdioAddr,
    /// PHY identifier.
    pub id: PhyId,
    /// Current operational state.
    pub state: PhyState,
    /// Negotiated link speed.
    pub speed: LinkSpeed,
    /// Negotiated duplex mode.
    pub duplex: Duplex,
    /// Whether auto-negotiation is enabled.
    pub auto_negotiation: bool,
    /// Whether link is currently up.
    pub link: bool,
    /// PHY supports 1000BASE-T.
    pub supports_gigabit: bool,
    /// PHY capabilities from BMSR.
    pub capabilities: u16,
    /// Local advertisement register value.
    pub advertisement: u16,
    /// Link partner ability.
    pub lpa: u16,
    /// 1000BASE-T control advertisement.
    pub adv_1000: u16,
    /// 1000BASE-T partner status.
    pub lpa_1000: u16,
    /// Number of link-up events.
    pub link_up_count: u32,
    /// Number of link-down events.
    pub link_down_count: u32,
}

impl PhyDevice {
    /// Create an uninitialized PHY device at the given address.
    pub fn new(addr: MdioAddr) -> Self {
        Self {
            addr,
            id: PhyId {
                oui: 0,
                model: 0,
                revision: 0,
            },
            state: PhyState::Down,
            speed: LinkSpeed::Speed10,
            duplex: Duplex::Half,
            auto_negotiation: true,
            link: false,
            supports_gigabit: false,
            capabilities: 0,
            advertisement: 0,
            lpa: 0,
            adv_1000: 0,
            lpa_1000: 0,
            link_up_count: 0,
            link_down_count: 0,
        }
    }

    /// Resolve speed and duplex from auto-negotiation results.
    ///
    /// Examines the local advertisement and link partner ability
    /// registers to determine the highest common denominator.
    pub fn resolve_autoneg(&mut self) {
        // Check gigabit first.
        if self.supports_gigabit {
            let common_1000 = self.adv_1000 & self.lpa_1000;
            if common_1000 & LPA_1000FULL != 0 {
                self.speed = LinkSpeed::Speed1000;
                self.duplex = Duplex::Full;
                return;
            }
            if common_1000 & LPA_1000HALF != 0 {
                self.speed = LinkSpeed::Speed1000;
                self.duplex = Duplex::Half;
                return;
            }
        }

        // Fall back to 10/100.
        let common = self.advertisement & self.lpa;
        if common & ADVERTISE_100FULL != 0 {
            self.speed = LinkSpeed::Speed100;
            self.duplex = Duplex::Full;
        } else if common & ADVERTISE_100HALF != 0 {
            self.speed = LinkSpeed::Speed100;
            self.duplex = Duplex::Half;
        } else if common & ADVERTISE_10FULL != 0 {
            self.speed = LinkSpeed::Speed10;
            self.duplex = Duplex::Full;
        } else {
            self.speed = LinkSpeed::Speed10;
            self.duplex = Duplex::Half;
        }
    }

    /// Update link status from a raw BMSR register read.
    ///
    /// Returns `true` if the link state changed.
    pub fn update_link(&mut self, bmsr: u16) -> bool {
        let new_link = bmsr & BMSR_LSTATUS != 0;
        let changed = new_link != self.link;
        self.link = new_link;

        if changed {
            if new_link {
                self.link_up_count += 1;
                self.state = PhyState::Running;
            } else {
                self.link_down_count += 1;
                self.state = PhyState::NoLink;
            }
        }

        changed
    }

    /// Check if auto-negotiation is complete from BMSR.
    pub fn is_aneg_complete(bmsr: u16) -> bool {
        bmsr & BMSR_ANEGCOMPLETE != 0
    }

    /// Check if the PHY is auto-negotiation capable from BMSR.
    pub fn is_aneg_capable(bmsr: u16) -> bool {
        bmsr & BMSR_ANEGCAPABLE != 0
    }
}

// ── MDIO Bus ─────────────────────────────────────────────────────

/// MDIO bus controller.
///
/// Provides low-level register read/write access to PHYs attached
/// to this MDIO bus via MMIO.
pub struct MdioBus {
    /// MMIO base address of the MDIO controller.
    mmio_base: u64,
    /// Bus identifier.
    bus_id: u8,
    /// Discovered PHY devices.
    phys: [Option<PhyDevice>; MAX_PHYS],
    /// Number of discovered PHYs.
    phy_count: usize,
    /// Whether the bus has been initialized.
    initialized: bool,
}

impl MdioBus {
    /// Create a new MDIO bus controller.
    pub fn new(mmio_base: u64, bus_id: u8) -> Self {
        Self {
            mmio_base,
            bus_id,
            phys: [None; MAX_PHYS],
            phy_count: 0,
            initialized: false,
        }
    }

    /// Read an MMIO register.
    fn read_reg(&self, offset: u32) -> u32 {
        let addr = self.mmio_base as usize + offset as usize;
        // SAFETY: mmio_base is a valid, mapped MDIO controller
        // MMIO region and offset is within the register space.
        unsafe { mmio_read32(addr) }
    }

    /// Write an MMIO register.
    fn write_reg(&self, offset: u32, val: u32) {
        let addr = self.mmio_base as usize + offset as usize;
        // SAFETY: mmio_base is a valid, mapped MDIO controller
        // MMIO region and offset is within the register space.
        unsafe { mmio_write32(addr, val) }
    }

    /// Wait for the MDIO controller to finish an operation.
    fn wait_ready(&self) -> Result<()> {
        let mut timeout = MDIO_TIMEOUT;
        loop {
            let status = self.read_reg(REG_MDIO_STATUS);
            if status & MDIO_STATUS_BUSY == 0 {
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Read a 16-bit MII register from a PHY.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `phy_addr > 31` or
    /// `reg > 31`, or [`Error::Busy`] if the operation times out.
    pub fn read(&self, phy_addr: u8, reg: u8) -> Result<u16> {
        if phy_addr > MAX_PHY_ADDR || reg > 31 {
            return Err(Error::InvalidArgument);
        }

        self.wait_ready()?;

        // Program PHY address and register address.
        let addr_val = ((phy_addr as u32) << 8) | (reg as u32);
        self.write_reg(REG_MDIO_ADDR, addr_val);

        // Initiate read.
        self.write_reg(REG_MDIO_CTRL, MDIO_CTRL_READ);

        // Wait for completion.
        let mut timeout = MDIO_TIMEOUT;
        loop {
            let status = self.read_reg(REG_MDIO_STATUS);
            if status & MDIO_STATUS_DONE != 0 {
                break;
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }

        // Read data.
        let data = self.read_reg(REG_MDIO_DATA);
        Ok((data & 0xFFFF) as u16)
    }

    /// Write a 16-bit value to a MII register on a PHY.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `phy_addr > 31` or
    /// `reg > 31`, or [`Error::Busy`] if the operation times out.
    pub fn write(&self, phy_addr: u8, reg: u8, val: u16) -> Result<()> {
        if phy_addr > MAX_PHY_ADDR || reg > 31 {
            return Err(Error::InvalidArgument);
        }

        self.wait_ready()?;

        // Program address.
        let addr_val = ((phy_addr as u32) << 8) | (reg as u32);
        self.write_reg(REG_MDIO_ADDR, addr_val);

        // Write data.
        self.write_reg(REG_MDIO_DATA, val as u32);

        // Initiate write.
        self.write_reg(REG_MDIO_CTRL, MDIO_CTRL_WRITE);

        // Wait for completion.
        let mut timeout = MDIO_TIMEOUT;
        loop {
            let status = self.read_reg(REG_MDIO_STATUS);
            if status & MDIO_STATUS_DONE != 0 {
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Initialize the MDIO bus and scan for PHYs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if no PHYs are discovered.
    pub fn init(&mut self) -> Result<()> {
        self.phy_count = 0;

        // Scan all 32 addresses.
        let mut addr: u8 = 0;
        while addr <= MAX_PHY_ADDR {
            if let Ok(id1) = self.read(addr, MII_PHYSID1) {
                if let Ok(id2) = self.read(addr, MII_PHYSID2) {
                    let id = PhyId::from_regs(id1, id2);
                    if !id.is_invalid() && !id.is_zero() {
                        let mdio_addr = MdioAddr {
                            bus_id: self.bus_id,
                            phy_addr: addr,
                        };
                        let mut phy = PhyDevice::new(mdio_addr);
                        phy.id = id;

                        // Read capabilities.
                        if let Ok(bmsr) = self.read(addr, MII_BMSR) {
                            phy.capabilities = bmsr;
                            phy.auto_negotiation = PhyDevice::is_aneg_capable(bmsr);
                        }

                        // Check gigabit support via 1000BASE-T
                        // status register.
                        if let Ok(stat1000) = self.read(addr, MII_STAT1000) {
                            phy.supports_gigabit = (stat1000 & (LPA_1000FULL | LPA_1000HALF)) != 0;
                        }

                        phy.state = PhyState::Up;
                        self.phys[addr as usize] = Some(phy);
                        self.phy_count += 1;
                    }
                }
            }
            addr += 1;
        }

        if self.phy_count == 0 {
            return Err(Error::IoError);
        }

        self.initialized = true;
        Ok(())
    }

    /// Reset a PHY via the BMCR reset bit.
    ///
    /// Waits for the reset to complete (self-clearing bit).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the reset does not complete
    /// within the timeout.
    pub fn reset_phy(&self, phy_addr: u8) -> Result<()> {
        self.write(phy_addr, MII_BMCR, BMCR_RESET)?;

        let mut timeout = PHY_RESET_TIMEOUT;
        loop {
            let bmcr = self.read(phy_addr, MII_BMCR)?;
            if bmcr & BMCR_RESET == 0 {
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Power down a PHY.
    pub fn power_down(&self, phy_addr: u8) -> Result<()> {
        let bmcr = self.read(phy_addr, MII_BMCR)?;
        self.write(phy_addr, MII_BMCR, bmcr | BMCR_PDOWN)
    }

    /// Power up a PHY.
    pub fn power_up(&self, phy_addr: u8) -> Result<()> {
        let bmcr = self.read(phy_addr, MII_BMCR)?;
        self.write(phy_addr, MII_BMCR, bmcr & !BMCR_PDOWN)
    }

    /// Start auto-negotiation on a PHY.
    ///
    /// Configures the advertisement register with all supported
    /// modes and restarts the AN process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PHY is not tracked.
    pub fn start_autoneg(&mut self, phy_addr: u8) -> Result<()> {
        let phy = self.phys[phy_addr as usize]
            .as_ref()
            .ok_or(Error::NotFound)?;

        // Build advertisement from capabilities.
        let mut adv = ADVERTISE_CSMA;
        let caps = phy.capabilities;
        if caps & BMSR_10HALF != 0 {
            adv |= ADVERTISE_10HALF;
        }
        if caps & BMSR_10FULL != 0 {
            adv |= ADVERTISE_10FULL;
        }
        if caps & BMSR_100HALF != 0 {
            adv |= ADVERTISE_100HALF;
        }
        if caps & BMSR_100FULL != 0 {
            adv |= ADVERTISE_100FULL;
        }
        adv |= ADVERTISE_PAUSE;

        // Write advertisement.
        self.write(phy_addr, MII_ADVERTISE, adv)?;

        // Gigabit advertisement.
        let supports_gigabit = phy.supports_gigabit;
        if supports_gigabit {
            let adv_1000 = ADVERTISE_1000FULL | ADVERTISE_1000HALF;
            self.write(phy_addr, MII_CTRL1000, adv_1000)?;

            // Cache in PHY.
            if let Some(phy) = &mut self.phys[phy_addr as usize] {
                phy.adv_1000 = adv_1000;
            }
        }

        // Cache advertisement in PHY.
        if let Some(phy) = &mut self.phys[phy_addr as usize] {
            phy.advertisement = adv;
        }

        // Restart auto-negotiation.
        let bmcr = self.read(phy_addr, MII_BMCR)?;
        self.write(phy_addr, MII_BMCR, bmcr | BMCR_ANENABLE | BMCR_ANRESTART)?;

        Ok(())
    }

    /// Wait for auto-negotiation to complete.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if AN does not complete within the
    /// timeout.
    pub fn wait_autoneg(&self, phy_addr: u8) -> Result<()> {
        let mut timeout = AN_TIMEOUT;
        loop {
            let bmsr = self.read(phy_addr, MII_BMSR)?;
            if PhyDevice::is_aneg_complete(bmsr) {
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Read auto-negotiation results and update the PHY device.
    ///
    /// Call this after auto-negotiation completes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PHY is not tracked.
    pub fn read_autoneg_result(&mut self, phy_addr: u8) -> Result<()> {
        if self.phys[phy_addr as usize].is_none() {
            return Err(Error::NotFound);
        }

        let lpa = self.read(phy_addr, MII_LPA)?;
        let lpa_1000 = self.read(phy_addr, MII_STAT1000)?;
        let bmsr = self.read(phy_addr, MII_BMSR)?;

        if let Some(phy) = &mut self.phys[phy_addr as usize] {
            phy.lpa = lpa;
            phy.lpa_1000 = lpa_1000;
            phy.update_link(bmsr);
            phy.resolve_autoneg();
        }

        Ok(())
    }

    /// Force a specific speed and duplex (disable AN).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on MDIO timeout.
    pub fn force_speed(&mut self, phy_addr: u8, speed: LinkSpeed, duplex: Duplex) -> Result<()> {
        let mut bmcr: u16 = 0;

        match speed {
            LinkSpeed::Speed10 => {}
            LinkSpeed::Speed100 => bmcr |= BMCR_SPEED100,
            LinkSpeed::Speed1000 => bmcr |= BMCR_SPEED1000,
        }

        if duplex == Duplex::Full {
            bmcr |= BMCR_FULLDPLX;
        }

        // Do not set ANENABLE — we are forcing.
        self.write(phy_addr, MII_BMCR, bmcr)?;

        if let Some(phy) = &mut self.phys[phy_addr as usize] {
            phy.speed = speed;
            phy.duplex = duplex;
            phy.auto_negotiation = false;
        }

        Ok(())
    }

    /// Poll link status for a PHY.
    ///
    /// Returns `true` if the link state changed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PHY is not tracked, or
    /// [`Error::Busy`] on MDIO timeout.
    pub fn poll_link(&mut self, phy_addr: u8) -> Result<bool> {
        if self.phys[phy_addr as usize].is_none() {
            return Err(Error::NotFound);
        }

        // Read BMSR twice — the link status bit latches low.
        let _ = self.read(phy_addr, MII_BMSR)?;
        let bmsr = self.read(phy_addr, MII_BMSR)?;

        let changed = if let Some(phy) = &mut self.phys[phy_addr as usize] {
            phy.update_link(bmsr)
        } else {
            false
        };

        Ok(changed)
    }

    /// Get a reference to a discovered PHY device.
    pub fn get_phy(&self, phy_addr: u8) -> Option<&PhyDevice> {
        if (phy_addr as usize) < MAX_PHYS {
            self.phys[phy_addr as usize].as_ref()
        } else {
            None
        }
    }

    /// Return the number of discovered PHYs.
    pub fn phy_count(&self) -> usize {
        self.phy_count
    }

    /// Return `true` if the bus has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the bus identifier.
    pub fn bus_id(&self) -> u8 {
        self.bus_id
    }
}

// ── Registry ─────────────────────────────────────────────────────

/// Registry for MDIO bus controllers.
pub struct MdioRegistry {
    /// Registered bus MMIO base addresses.
    buses: [Option<u64>; MAX_BUSES],
    /// Number of registered buses.
    count: usize,
}

impl Default for MdioRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MdioRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            buses: [None; MAX_BUSES],
            count: 0,
        }
    }

    /// Register an MDIO bus by its MMIO base address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_BUSES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.buses[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Get the MMIO base address of a registered bus.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            self.buses[index]
        } else {
            None
        }
    }

    /// Return the number of registered buses.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no buses are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
