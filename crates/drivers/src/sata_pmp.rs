// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SATA Port Multiplier (PMP) support.
//!
//! Implements detection, configuration, and management of SATA Port
//! Multipliers as defined in the Serial ATA Revision 3.1 specification
//! and the SATA Port Multiplier specification.
//!
//! # Architecture
//!
//! A PMP attaches to a single host AHCI port and fans out to up to 15
//! device ports. The PMP exposes a control port (port 15) accessible
//! via the General Status and Control Registers (GSCRs), and up to 14
//! device ports (0–13) for attached drives.
//!
//! ```text
//! Host AHCI Port
//!   └── PMP (port 15 = control)
//!         ├── Device Port 0 (SSD)
//!         ├── Device Port 1 (HDD)
//!         └── ...
//! ```
//!
//! Reference: Linux `drivers/ata/libata-pmp.c`,
//! Serial ATA Port Multiplier Specification Rev 1.2.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SATA PMP control port number.
pub const PMP_CONTROL_PORT: u8 = 15;

/// Maximum device ports on a PMP (0–14; port 15 is reserved for control).
pub const PMP_MAX_DEVICE_PORTS: usize = 15;

/// Maximum PMP devices in the system.
const MAX_PMP_DEVICES: usize = 8;

// ---------------------------------------------------------------------------
// GSCR Register Indices
// ---------------------------------------------------------------------------

/// GSCR[0] — Product Identifier.
const GSCR_PROD_ID: u8 = 0;

/// GSCR[1] — Revision.
const GSCR_REVISION: u8 = 1;

/// GSCR[2] — Port Information.
const GSCR_PORT_INFO: u8 = 2;

/// GSCR[32] — Error register.
const GSCR_ERROR: u8 = 32;

/// GSCR[33] — Error Enable register.
const GSCR_ERROR_EN: u8 = 33;

/// GSCR[64] — Features register.
const GSCR_FEAT: u8 = 64;

/// GSCR[65] — Features Enable register.
const GSCR_FEAT_EN: u8 = 65;

// ---------------------------------------------------------------------------
// GSCR Port Information Bits (GSCR[2])
// ---------------------------------------------------------------------------

/// Number of device ports mask (bits 3:0).
const GSCR_PORT_COUNT_MASK: u32 = 0x0F;

// ---------------------------------------------------------------------------
// PMP Error Bits (GSCR[32])
// ---------------------------------------------------------------------------

/// Device-to-host error on any port.
const GSCR_ERR_D2H: u32 = 1 << 0;

/// CRC error detected.
const GSCR_ERR_CRC: u32 = 1 << 1;

/// Handshake error.
const GSCR_ERR_HANDSHAKE: u32 = 1 << 2;

/// Link sequence error.
const GSCR_ERR_LINK_SEQ: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// SStatus (SControl/SStatus register) link detection
// ---------------------------------------------------------------------------

/// SStatus DET field mask (bits 3:0).
const SSTATUS_DET_MASK: u32 = 0x0F;

/// DET = 3: device present and communication established.
const SSTATUS_DET_PRESENT: u32 = 3;

// ---------------------------------------------------------------------------
// Port Status
// ---------------------------------------------------------------------------

/// Status of a single PMP device port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmpPortStatus {
    /// No device connected or link not established.
    Empty,
    /// Device detected, link active.
    Present,
    /// Device was detected but link was lost (hot-unplug).
    Lost,
    /// Port is in error state.
    Error,
}

impl PmpPortStatus {
    /// Whether a device is (or was) connected.
    pub fn has_device(&self) -> bool {
        matches!(self, Self::Present | Self::Lost)
    }
}

// ---------------------------------------------------------------------------
// PMP Port Info
// ---------------------------------------------------------------------------

/// Per-port information for a PMP device port.
#[derive(Debug, Clone, Copy)]
pub struct PmpPort {
    /// Port index (0–14).
    pub port_idx: u8,
    /// Current link/device status.
    pub status: PmpPortStatus,
    /// Last-read SStatus register value.
    pub sstatus: u32,
    /// Last-read SError register value.
    pub serror: u32,
    /// Number of errors since last clear.
    pub error_count: u32,
    /// Whether this port is enabled.
    pub enabled: bool,
}

impl PmpPort {
    /// Create a new, empty PMP port.
    pub const fn new(port_idx: u8) -> Self {
        Self {
            port_idx,
            status: PmpPortStatus::Empty,
            sstatus: 0,
            serror: 0,
            error_count: 0,
            enabled: true,
        }
    }

    /// Refresh status from a newly-read SStatus value.
    pub fn update_sstatus(&mut self, sstatus: u32) {
        self.sstatus = sstatus;
        let det = sstatus & SSTATUS_DET_MASK;
        self.status = if det == SSTATUS_DET_PRESENT {
            PmpPortStatus::Present
        } else if self.status == PmpPortStatus::Present {
            PmpPortStatus::Lost
        } else {
            PmpPortStatus::Empty
        };
    }
}

// ---------------------------------------------------------------------------
// PMP Identity
// ---------------------------------------------------------------------------

/// Identity information read from the PMP's GSCR registers.
#[derive(Debug, Clone, Copy)]
pub struct PmpIdentity {
    /// Product identifier (GSCR[0]).
    pub product_id: u32,
    /// Revision (GSCR[1]).
    pub revision: u32,
    /// Number of device ports (decoded from GSCR[2]).
    pub num_ports: u8,
}

impl PmpIdentity {
    /// Decode identity from raw GSCR values.
    pub fn from_gscr(prod_id: u32, revision: u32, port_info: u32) -> Self {
        let num_ports = ((port_info & GSCR_PORT_COUNT_MASK) + 1) as u8;
        Self {
            product_id: prod_id,
            revision,
            num_ports,
        }
    }
}

// ---------------------------------------------------------------------------
// GSCR Access Trait Abstraction
// ---------------------------------------------------------------------------

/// Callback-based GSCR read/write interface.
///
/// Implementations forward these calls to the AHCI port's NCQ-off
/// or FIS-based PMP GSCR access mechanisms.
pub struct GscrAccessor {
    /// Host AHCI port index.
    pub host_port: u8,
    /// Read a GSCR register: `(host_port, pmp_port, gscr_idx) -> value`.
    read_fn: fn(u8, u8, u8) -> u32,
    /// Write a GSCR register: `(host_port, pmp_port, gscr_idx, value)`.
    write_fn: fn(u8, u8, u8, u32),
}

impl GscrAccessor {
    /// Create a new accessor with the given host port and callbacks.
    pub const fn new(
        host_port: u8,
        read_fn: fn(u8, u8, u8) -> u32,
        write_fn: fn(u8, u8, u8, u32),
    ) -> Self {
        Self {
            host_port,
            read_fn,
            write_fn,
        }
    }

    /// Read GSCR register `gscr_idx` from PMP port `pmp_port`.
    pub fn read(&self, pmp_port: u8, gscr_idx: u8) -> u32 {
        (self.read_fn)(self.host_port, pmp_port, gscr_idx)
    }

    /// Write `value` to GSCR register `gscr_idx` on PMP port `pmp_port`.
    pub fn write(&self, pmp_port: u8, gscr_idx: u8, value: u32) {
        (self.write_fn)(self.host_port, pmp_port, gscr_idx, value);
    }
}

// ---------------------------------------------------------------------------
// PMP Device
// ---------------------------------------------------------------------------

/// Represents a single SATA Port Multiplier.
pub struct PmpDevice {
    /// Index of the AHCI host port this PMP is attached to.
    pub host_port_idx: u8,
    /// PMP identity (product ID, revision, port count).
    pub identity: PmpIdentity,
    /// Per-port state (indices 0–14).
    ports: [PmpPort; PMP_MAX_DEVICE_PORTS],
    /// Whether the PMP has been successfully detected and configured.
    pub initialized: bool,
    /// GSCR error flags accumulated since last clear.
    pub gscr_errors: u32,
}

impl PmpDevice {
    /// Create an uninitialised PMP device attached to `host_port_idx`.
    pub fn new(host_port_idx: u8) -> Self {
        let ports = core::array::from_fn(|i| PmpPort::new(i as u8));
        Self {
            host_port_idx,
            identity: PmpIdentity {
                product_id: 0,
                revision: 0,
                num_ports: 0,
            },
            ports,
            initialized: false,
            gscr_errors: 0,
        }
    }

    /// Detect and configure the PMP.
    ///
    /// Reads GSCR[0], GSCR[1], GSCR[2] from the control port to
    /// determine the PMP's identity and port count, then enumerates
    /// all device ports.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no PMP is detected (product_id == 0
    /// or 0xFFFFFFFF), or [`Error::IoError`] if port count is zero.
    pub fn detect(&mut self, gscr: &GscrAccessor) -> Result<()> {
        let prod_id = gscr.read(PMP_CONTROL_PORT, GSCR_PROD_ID);
        if prod_id == 0 || prod_id == 0xFFFF_FFFF {
            return Err(Error::NotFound);
        }
        let revision = gscr.read(PMP_CONTROL_PORT, GSCR_REVISION);
        let port_info = gscr.read(PMP_CONTROL_PORT, GSCR_PORT_INFO);
        self.identity = PmpIdentity::from_gscr(prod_id, revision, port_info);

        if self.identity.num_ports == 0 {
            return Err(Error::IoError);
        }

        // Enable error reporting.
        gscr.write(
            PMP_CONTROL_PORT,
            GSCR_ERROR_EN,
            GSCR_ERR_D2H | GSCR_ERR_CRC | GSCR_ERR_HANDSHAKE | GSCR_ERR_LINK_SEQ,
        );

        self.initialized = true;
        Ok(())
    }

    /// Poll link status for all device ports.
    ///
    /// Reads the SStatus register for each port via GSCR access and
    /// updates the [`PmpPort::status`] field.
    pub fn poll_port_status(&mut self, gscr: &GscrAccessor) {
        let num = self.identity.num_ports as usize;
        for i in 0..num.min(PMP_MAX_DEVICE_PORTS) {
            // SStatus is accessed through port-specific GSCR address space.
            // The SATA spec maps SStatus at GSCR index 0 within each port.
            let sstatus = gscr.read(i as u8, 0 /* SStatus index in per-port GSCR */);
            self.ports[i].update_sstatus(sstatus);
        }
    }

    /// Read the GSCR error register and accumulate errors.
    ///
    /// Clears the error register in hardware by writing back the read value.
    pub fn service_errors(&mut self, gscr: &GscrAccessor) {
        let errors = gscr.read(PMP_CONTROL_PORT, GSCR_ERROR);
        if errors != 0 {
            self.gscr_errors |= errors;
            // W1C: clear by writing back the error bits.
            gscr.write(PMP_CONTROL_PORT, GSCR_ERROR, errors);
        }
    }

    /// Handle a hot-plug event on the given device port.
    ///
    /// Re-reads SStatus and updates the port state. If a device arrived,
    /// marks the port as `Present`; if it departed, marks it as `Lost`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx >= num_ports`.
    pub fn handle_hotplug(&mut self, port_idx: u8, gscr: &GscrAccessor) -> Result<PmpPortStatus> {
        if port_idx as usize >= self.identity.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        let sstatus = gscr.read(port_idx, 0);
        self.ports[port_idx as usize].update_sstatus(sstatus);
        Ok(self.ports[port_idx as usize].status)
    }

    /// Enable or disable a specific device port.
    ///
    /// Writes to the port-level SControl GSCR (index 1) to assert or
    /// de-assert COMRESET on the port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx` is out of range.
    pub fn set_port_enabled(
        &mut self,
        port_idx: u8,
        enable: bool,
        gscr: &GscrAccessor,
    ) -> Result<()> {
        if port_idx as usize >= self.identity.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        // SControl is at GSCR index 1 in the per-port register space.
        // DET=1 initiates COMRESET; DET=0 is normal operation.
        let sctl = gscr.read(port_idx, 1);
        let new_sctl = if enable {
            sctl & !0x0F // DET = 0: normal
        } else {
            (sctl & !0x0F) | 0x01 // DET = 1: reset
        };
        gscr.write(port_idx, 1, new_sctl);
        self.ports[port_idx as usize].enabled = enable;
        Ok(())
    }

    /// Read a GSCR register from a specific device port.
    pub fn read_gscr(&self, port: u8, gscr_idx: u8, gscr: &GscrAccessor) -> u32 {
        gscr.read(port, gscr_idx)
    }

    /// Write a value to a GSCR register on a specific device port.
    pub fn write_gscr(&self, port: u8, gscr_idx: u8, value: u32, gscr: &GscrAccessor) {
        gscr.write(port, gscr_idx, value);
    }

    /// Return port information for a given port index.
    pub fn port(&self, idx: usize) -> Option<&PmpPort> {
        if idx < PMP_MAX_DEVICE_PORTS {
            Some(&self.ports[idx])
        } else {
            None
        }
    }

    /// Return the number of device ports.
    pub fn num_ports(&self) -> u8 {
        self.identity.num_ports
    }

    /// Return whether any GSCR errors have been observed.
    pub fn has_errors(&self) -> bool {
        self.gscr_errors != 0
    }

    /// Clear the accumulated GSCR error flags.
    pub fn clear_errors(&mut self) {
        self.gscr_errors = 0;
    }

    /// Return the count of ports in `Present` state.
    pub fn present_port_count(&self) -> usize {
        self.ports[..self.identity.num_ports as usize]
            .iter()
            .filter(|p| p.status == PmpPortStatus::Present)
            .count()
    }
}

// ---------------------------------------------------------------------------
// PMP Registry
// ---------------------------------------------------------------------------

/// System-wide registry of SATA Port Multipliers.
pub struct PmpRegistry {
    /// Registered PMP devices.
    devices: [Option<PmpDevice>; MAX_PMP_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for PmpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PmpRegistry {
    /// Create an empty PMP registry.
    pub fn new() -> Self {
        Self {
            devices: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Register a PMP device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: PmpDevice) -> Result<usize> {
        if self.count >= MAX_PMP_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Get a reference to a PMP device by index.
    pub fn get(&self, idx: usize) -> Option<&PmpDevice> {
        if idx < self.count {
            self.devices[idx].as_ref()
        } else {
            None
        }
    }

    /// Get a mutable reference to a PMP device by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut PmpDevice> {
        if idx < self.count {
            self.devices[idx].as_mut()
        } else {
            None
        }
    }

    /// Find a PMP by host port index.
    pub fn find_by_host_port(&self, host_port: u8) -> Option<&PmpDevice> {
        self.devices[..self.count]
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.host_port_idx == host_port))
    }

    /// Return the number of registered PMP devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the registry has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
