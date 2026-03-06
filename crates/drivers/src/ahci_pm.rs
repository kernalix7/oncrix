// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SATA AHCI Port Multiplier (PM) support driver.
//!
//! Extends the AHCI host controller driver with Port Multiplier (PM)
//! awareness. A Port Multiplier is a 1-to-N fanout device that allows a
//! single AHCI host port to connect up to 15 SATA targets simultaneously.
//!
//! # Architecture
//!
//! - **PM Detection** — identified via port signature `0x9669_0101`
//! - **FIS-Based Switching (FBS)** — per-port FIS delivery for concurrent I/O
//! - **Command-Based Switching (CBS)** — fallback single-command model
//! - **PM Registers** — accessed via the SControl/PxSCTL PM port 15
//! - **PmPort** — models one downstream SATA device port (0–14)
//! - **PortMultiplier** — manages one PM attached to an HBA host port
//! - **PmRegistry** — tracks up to [`MAX_PM_CONTROLLERS`] PM instances
//!
//! # Register Access Protocol
//!
//! PM registers are accessed through the HBA port using a Read/Write
//! Port Multiplier FIS protocol: write a Set Device Bits FIS or use the
//! PM port (port 15) for control-register access.
//!
//! Reference: Serial ATA AHCI 1.3.1 §10 (Port Multiplier);
//! SATA PM Specification 1.2 (SATADevSlp, FBS, CBS).

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of Port Multiplier controller instances.
pub const MAX_PM_CONTROLLERS: usize = 4;

/// Maximum downstream ports per Port Multiplier (0–14; 15 is the PM itself).
pub const MAX_PM_PORTS: usize = 15;

/// PM control port number (always port 15).
pub const PM_CTRL_PORT: u8 = 15;

/// PM GSCR register: Product Identifier.
pub const PM_GSCR_PROD_ID: u8 = 0;

/// PM GSCR register: Revision.
pub const PM_GSCR_REV: u8 = 1;

/// PM GSCR register: Port Information (port count).
pub const PM_GSCR_PORT_INFO: u8 = 2;

/// PM GSCR register: Features.
pub const PM_GSCR_FEATURES: u8 = 64;

/// PM GSCR register: Features Enable.
pub const PM_GSCR_FEAT_EN: u8 = 96;

/// PM PSCR register: SStatus (DET, SPD, IPM fields).
pub const PM_PSCR_SSTATUS: u8 = 0;

/// PM PSCR register: SControl.
pub const PM_PSCR_SCONTROL: u8 = 1;

/// PM PSCR register: SError.
pub const PM_PSCR_SERROR: u8 = 2;

/// PM PSCR register: SActive.
pub const PM_PSCR_SACTIVE: u8 = 3;

/// PM PSCR register: SNotification.
pub const PM_PSCR_SNOTIFICATION: u8 = 4;

/// GSCR Feature bit: FIS-based switching capable.
pub const PM_FEAT_FBS: u32 = 1 << 0;

/// GSCR Feature bit: Command-based switching only.
pub const PM_FEAT_CBS: u32 = 1 << 3;

/// GSCR Feature bit: Asynchronous notification.
pub const PM_FEAT_ASYNC_NOTIFY: u32 = 1 << 3;

/// SStatus DET field mask (device detection).
pub const SSTATUS_DET_MASK: u32 = 0x0F;

/// SStatus DET: device present, PHY established.
pub const SSTATUS_DET_PRESENT: u32 = 0x03;

/// SStatus SPD field mask (negotiated speed).
pub const SSTATUS_SPD_MASK: u32 = 0xF0;

/// SStatus IPM field mask (interface power management).
pub const SSTATUS_IPM_MASK: u32 = 0xF00;

// ---------------------------------------------------------------------------
// MMIO helpers (reuse AHCI 32-bit volatile pattern)
// ---------------------------------------------------------------------------

/// Read a 32-bit volatile MMIO register.
///
/// # Safety
///
/// `addr` must be a valid mapped MMIO address aligned to 4 bytes.
unsafe fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: Caller guarantees addr is valid, mapped, aligned MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit volatile MMIO register.
///
/// # Safety
///
/// `addr` must be a valid mapped MMIO address aligned to 4 bytes.
unsafe fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: Caller guarantees addr is valid, mapped, aligned MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
}

// ---------------------------------------------------------------------------
// HBA host port MMIO layout (needed for PM register access)
// ---------------------------------------------------------------------------

/// Offset of the HBA port Command Issue register (PxCI).
const HBA_PORT_CI_OFFSET: usize = 0x38;

/// Offset of the HBA port SControl register (PxSCTL).
const HBA_PORT_SCTL_OFFSET: usize = 0x2C;

/// Offset of the HBA port SStatus register (PxSSTS).
const HBA_PORT_SSTS_OFFSET: usize = 0x28;

/// Offset of the HBA port FIS-Based Switching Control register (PxFBS).
const HBA_PORT_FBS_OFFSET: usize = 0x40;

/// PxFBS bit: FBS Enable.
const FBS_EN: u32 = 1 << 0;

/// PxFBS bit: FBS Active (set while FBS switching is in progress).
const FBS_ACT: u32 = 1 << 2;

/// PxFBS DEV field shift (target port for next command).
const FBS_DEV_SHIFT: u32 = 8;

/// PxFBS DEV field mask.
const FBS_DEV_MASK: u32 = 0x0F00;

// ---------------------------------------------------------------------------
// PmSwitchingMode
// ---------------------------------------------------------------------------

/// Port Multiplier command/FIS switching mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PmSwitchingMode {
    /// FIS-Based Switching — allows concurrent commands to multiple ports.
    FisBased,
    /// Command-Based Switching — one outstanding command at a time.
    #[default]
    CommandBased,
}

// ---------------------------------------------------------------------------
// SataLinkSpeed
// ---------------------------------------------------------------------------

/// SATA link negotiated speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SataLinkSpeed {
    /// No link established.
    #[default]
    None,
    /// Gen 1 — 1.5 Gbit/s.
    Gen1,
    /// Gen 2 — 3.0 Gbit/s.
    Gen2,
    /// Gen 3 — 6.0 Gbit/s.
    Gen3,
}

impl SataLinkSpeed {
    /// Parse from the SPD field of an SStatus register.
    pub fn from_sstatus(sstatus: u32) -> Self {
        match (sstatus & SSTATUS_SPD_MASK) >> 4 {
            0x1 => Self::Gen1,
            0x2 => Self::Gen2,
            0x3 => Self::Gen3,
            _ => Self::None,
        }
    }
}

// ---------------------------------------------------------------------------
// PmPortState
// ---------------------------------------------------------------------------

/// State of a single downstream PM port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PmPortState {
    /// No device attached (DET != 3).
    #[default]
    Empty,
    /// Device present, PHY established, not yet identified.
    Present,
    /// Device identified and ready for I/O.
    Ready,
    /// Port is in error state.
    Error,
}

// ---------------------------------------------------------------------------
// PmPort
// ---------------------------------------------------------------------------

/// Represents one downstream device port of a Port Multiplier.
///
/// Each PM supports up to 15 device ports (numbered 0–14). Port 15 is
/// the PM's own control register set and is not represented here.
#[derive(Clone, Copy, Default)]
pub struct PmPort {
    /// Zero-based port index (0–14).
    pub port_num: u8,
    /// Current link/device state.
    pub state: PmPortState,
    /// Negotiated SATA link speed.
    pub link_speed: SataLinkSpeed,
    /// Last SError register value (latched on error interrupt).
    pub serror: u32,
    /// SStatus register snapshot.
    pub sstatus: u32,
    /// Number of I/O errors since last reset.
    pub error_count: u32,
}

impl PmPort {
    /// Create a new, empty port descriptor.
    pub fn new(port_num: u8) -> Self {
        Self {
            port_num,
            ..Self::default()
        }
    }

    /// Return `true` if a device is physically present on this port.
    pub fn is_present(&self) -> bool {
        (self.sstatus & SSTATUS_DET_MASK) == SSTATUS_DET_PRESENT
    }
}

// ---------------------------------------------------------------------------
// PortMultiplier
// ---------------------------------------------------------------------------

/// A SATA Port Multiplier attached to one HBA host port.
///
/// Manages PM-register access, FBS/CBS configuration, per-port state
/// tracking, and the GSCR feature negotiation sequence.
pub struct PortMultiplier {
    /// Unique PM instance index.
    pub id: u8,
    /// Index of the HBA host port this PM is connected to.
    pub host_port: u8,
    /// MMIO base address of the HBA (from PCI BAR5).
    pub hba_base: usize,
    /// Active switching mode (FBS or CBS).
    pub switching_mode: PmSwitchingMode,
    /// Number of downstream device ports (1–15).
    pub port_count: u8,
    /// PM product identifier from GSCR[0].
    pub product_id: u32,
    /// PM revision from GSCR[1].
    pub revision: u32,
    /// PM supported features from GSCR[64].
    pub features: u32,
    /// Per-port descriptors for downstream devices.
    pub ports: [PmPort; MAX_PM_PORTS],
    /// Whether this PM is initialised and operational.
    pub active: bool,
}

impl PortMultiplier {
    /// Create a new PortMultiplier descriptor.
    ///
    /// Call [`init`](Self::init) to probe the PM and configure switching.
    pub fn new(id: u8, host_port: u8, hba_base: usize) -> Self {
        let mut ports = [PmPort::default(); MAX_PM_PORTS];
        for (i, p) in ports.iter_mut().enumerate() {
            p.port_num = i as u8;
        }
        Self {
            id,
            host_port,
            hba_base,
            switching_mode: PmSwitchingMode::CommandBased,
            port_count: 0,
            product_id: 0,
            revision: 0,
            features: 0,
            ports,
            active: false,
        }
    }

    /// MMIO address of the HBA port register at `offset`.
    fn hba_port_reg(&self, offset: usize) -> usize {
        // HBA port registers start at 0x100 + port * 0x80.
        self.hba_base + 0x100 + self.host_port as usize * 0x80 + offset
    }

    /// Issue a Read Port Multiplier FIS to read PM register `reg` on `pm_port`.
    ///
    /// In a real implementation this would submit a PM Read command via the
    /// HBA command list using a Register FIS with PM port = 15.
    ///
    /// # Safety
    ///
    /// `hba_base` must be a valid mapped MMIO address and the HBA must be
    /// in a state that accepts commands on `host_port`.
    unsafe fn read_pm_reg(&self, pm_port: u8, reg: u8) -> Result<u32> {
        // Stub — real implementation builds a command table with a
        // Register H2D FIS (PM_PORT=15, features=PM_READ, LBA=reg,
        // device = pm_port) and waits for D2H completion.
        let _ = (pm_port, reg);
        Ok(0)
    }

    /// Issue a Write Port Multiplier FIS to write PM register `reg` on `pm_port`.
    ///
    /// # Safety
    ///
    /// Same requirements as [`read_pm_reg`](Self::read_pm_reg).
    unsafe fn write_pm_reg(&self, pm_port: u8, reg: u8, val: u32) -> Result<()> {
        // Stub — real implementation builds a command table with a
        // Register H2D FIS (PM_PORT=15, features=PM_WRITE, LBA=reg,
        // device = pm_port, …) and waits for D2H completion.
        let _ = (pm_port, reg, val);
        Ok(())
    }

    /// Read the SStatus of a downstream PM port.
    pub fn port_sstatus(&self, port: u8) -> Result<u32> {
        if port as usize >= MAX_PM_PORTS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: hba_base is valid MMIO; read_pm_reg accesses PM port 15.
        unsafe { self.read_pm_reg(port, PM_PSCR_SSTATUS) }
    }

    /// Read the SError register of a downstream PM port and clear it.
    pub fn port_serror(&mut self, port: u8) -> Result<u32> {
        if port as usize >= MAX_PM_PORTS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: hba_base is valid MMIO.
        let serror = unsafe { self.read_pm_reg(port, PM_PSCR_SERROR)? };
        if serror != 0 {
            // SAFETY: Write clears the error bits.
            unsafe { self.write_pm_reg(port, PM_PSCR_SERROR, serror)? };
            self.ports[port as usize].serror = serror;
            self.ports[port as usize].error_count =
                self.ports[port as usize].error_count.wrapping_add(1);
        }
        Ok(serror)
    }

    /// Enable or disable FIS-Based Switching on the HBA host port.
    ///
    /// FBS must also be supported by the PM (see [`PM_FEAT_FBS`]).
    /// Returns [`Error::NotImplemented`] if the PM does not advertise FBS.
    pub fn configure_fbs(&mut self, enable: bool) -> Result<()> {
        if enable && (self.features & PM_FEAT_FBS == 0) {
            return Err(Error::NotImplemented);
        }

        let fbs_reg_addr = self.hba_port_reg(HBA_PORT_FBS_OFFSET);

        // SAFETY: fbs_reg_addr is within the mapped HBA MMIO region.
        unsafe {
            let mut fbs = mmio_read32(fbs_reg_addr);
            if enable {
                fbs |= FBS_EN;
            } else {
                fbs &= !FBS_EN;
            }
            mmio_write32(fbs_reg_addr, fbs);
        }

        self.switching_mode = if enable {
            PmSwitchingMode::FisBased
        } else {
            PmSwitchingMode::CommandBased
        };

        Ok(())
    }

    /// Set the active downstream port for the next FBS command.
    ///
    /// Only valid in [`PmSwitchingMode::FisBased`] mode. Writes the DEV
    /// field in PxFBS to direct the next outgoing FIS to `port`.
    pub fn fbs_set_dev(&mut self, port: u8) -> Result<()> {
        if self.switching_mode != PmSwitchingMode::FisBased {
            return Err(Error::InvalidArgument);
        }
        if port as usize >= MAX_PM_PORTS {
            return Err(Error::InvalidArgument);
        }

        let fbs_reg_addr = self.hba_port_reg(HBA_PORT_FBS_OFFSET);

        // SAFETY: fbs_reg_addr is within the mapped HBA MMIO region.
        unsafe {
            let mut fbs = mmio_read32(fbs_reg_addr);
            fbs = (fbs & !FBS_DEV_MASK) | ((port as u32) << FBS_DEV_SHIFT);
            mmio_write32(fbs_reg_addr, fbs);
        }

        Ok(())
    }

    /// Perform a COMRESET on a downstream PM port via SControl.
    pub fn port_reset(&mut self, port: u8) -> Result<()> {
        if port as usize >= MAX_PM_PORTS {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: hba_base is valid MMIO; write_pm_reg accesses PM port.
        unsafe {
            // Assert COMRESET: DET=1 in SControl.
            self.write_pm_reg(port, PM_PSCR_SCONTROL, 0x301)?;
            // Clear DET: DET=0 to complete reset.
            self.write_pm_reg(port, PM_PSCR_SCONTROL, 0x300)?;
        }

        self.ports[port as usize].state = PmPortState::Present;
        Ok(())
    }

    /// Probe all downstream ports and update `self.ports` state.
    fn probe_ports(&mut self) -> Result<()> {
        for port_idx in 0..self.port_count as usize {
            let port = port_idx as u8;

            // SAFETY: hba_base is valid MMIO.
            let sstatus = unsafe { self.read_pm_reg(port, PM_PSCR_SSTATUS)? };
            self.ports[port_idx].sstatus = sstatus;

            let det = sstatus & SSTATUS_DET_MASK;
            if det == SSTATUS_DET_PRESENT {
                self.ports[port_idx].state = PmPortState::Present;
                self.ports[port_idx].link_speed = SataLinkSpeed::from_sstatus(sstatus);
            } else {
                self.ports[port_idx].state = PmPortState::Empty;
                self.ports[port_idx].link_speed = SataLinkSpeed::None;
            }
        }

        Ok(())
    }

    /// Initialise the Port Multiplier.
    ///
    /// Reads GSCR registers (product ID, revision, port count, features),
    /// configures FBS if supported, then probes all downstream ports.
    pub fn init(&mut self) -> Result<()> {
        // SAFETY: hba_base is valid MMIO; PM is present (signature verified
        // by caller via PxSIG == SATA_SIG_PM before calling init).
        unsafe {
            self.product_id = self.read_pm_reg(PM_CTRL_PORT, PM_GSCR_PROD_ID)?;
            self.revision = self.read_pm_reg(PM_CTRL_PORT, PM_GSCR_REV)?;

            let port_info = self.read_pm_reg(PM_CTRL_PORT, PM_GSCR_PORT_INFO)?;
            // Lower 4 bits = number of device ports.
            self.port_count = ((port_info & 0x0F) as u8).min(MAX_PM_PORTS as u8);

            self.features = self.read_pm_reg(PM_CTRL_PORT, PM_GSCR_FEATURES)?;
        }

        // Attempt to enable FBS if available; fall back to CBS silently.
        if self.features & PM_FEAT_FBS != 0 {
            let _ = self.configure_fbs(true);
        }

        self.probe_ports()?;
        self.active = true;
        Ok(())
    }

    /// Return a shared reference to a downstream port descriptor.
    ///
    /// Returns [`None`] if `port` is out of range.
    pub fn port(&self, port: u8) -> Option<&PmPort> {
        if (port as usize) < MAX_PM_PORTS {
            Some(&self.ports[port as usize])
        } else {
            None
        }
    }

    /// Return a mutable reference to a downstream port descriptor.
    ///
    /// Returns [`None`] if `port` is out of range.
    pub fn port_mut(&mut self, port: u8) -> Option<&mut PmPort> {
        if (port as usize) < MAX_PM_PORTS {
            Some(&mut self.ports[port as usize])
        } else {
            None
        }
    }

    /// Return an iterator over ports that have a device present.
    pub fn present_ports(&self) -> impl Iterator<Item = &PmPort> {
        self.ports[..self.port_count as usize]
            .iter()
            .filter(|p| p.state != PmPortState::Empty)
    }

    /// Handle an asynchronous notification from the PM.
    ///
    /// Reads the SNotification register to determine which ports have
    /// changed state, clears the notification, and refreshes port status.
    pub fn handle_async_notify(&mut self) -> Result<()> {
        // SAFETY: hba_base is valid MMIO.
        let notify = unsafe { self.read_pm_reg(PM_CTRL_PORT, PM_PSCR_SNOTIFICATION)? };

        // Each bit i in `notify` corresponds to downstream port i.
        for port_idx in 0..self.port_count as usize {
            if notify & (1 << port_idx) != 0 {
                // SAFETY: hba_base is valid MMIO.
                let sstatus = unsafe { self.read_pm_reg(port_idx as u8, PM_PSCR_SSTATUS)? };
                self.ports[port_idx].sstatus = sstatus;

                let det = sstatus & SSTATUS_DET_MASK;
                if det == SSTATUS_DET_PRESENT {
                    self.ports[port_idx].state = PmPortState::Present;
                    self.ports[port_idx].link_speed = SataLinkSpeed::from_sstatus(sstatus);
                } else {
                    self.ports[port_idx].state = PmPortState::Empty;
                    self.ports[port_idx].link_speed = SataLinkSpeed::None;
                }
            }
        }

        // Clear SNotification register.
        // SAFETY: hba_base is valid MMIO.
        unsafe {
            self.write_pm_reg(PM_CTRL_PORT, PM_PSCR_SNOTIFICATION, notify)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PmRegistry
// ---------------------------------------------------------------------------

/// Registry of Port Multiplier instances in the system.
///
/// Supports up to [`MAX_PM_CONTROLLERS`] simultaneously active PMs.
pub struct PmRegistry {
    /// PM instance slots.
    pms: [Option<PortMultiplier>; MAX_PM_CONTROLLERS],
    /// Number of registered PMs.
    count: usize,
}

impl Default for PmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PmRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            pms: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a Port Multiplier.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a PM with the same ID already exists.
    pub fn register(&mut self, pm: PortMultiplier) -> Result<()> {
        for slot in self.pms.iter().flatten() {
            if slot.id == pm.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.pms {
            if slot.is_none() {
                *slot = Some(pm);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a PM by ID.
    pub fn unregister(&mut self, id: u8) -> Result<()> {
        for slot in &mut self.pms {
            if let Some(pm) = slot {
                if pm.id == id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a PM by ID (shared reference).
    pub fn get(&self, id: u8) -> Option<&PortMultiplier> {
        self.pms
            .iter()
            .find_map(|s| s.as_ref().filter(|pm| pm.id == id))
    }

    /// Look up a PM by ID (mutable reference).
    pub fn get_mut(&mut self, id: u8) -> Option<&mut PortMultiplier> {
        self.pms
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|pm| pm.id == id))
    }

    /// Look up a PM by host port number (shared reference).
    pub fn get_by_host_port(&self, host_port: u8) -> Option<&PortMultiplier> {
        self.pms
            .iter()
            .find_map(|s| s.as_ref().filter(|pm| pm.host_port == host_port))
    }

    /// Look up a PM by host port number (mutable reference).
    pub fn get_by_host_port_mut(&mut self, host_port: u8) -> Option<&mut PortMultiplier> {
        self.pms
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|pm| pm.host_port == host_port))
    }

    /// Number of registered PMs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if no PMs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
