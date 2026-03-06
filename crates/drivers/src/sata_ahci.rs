// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SATA AHCI port-level command dispatch layer.
//!
//! Wraps the low-level AHCI HBA register access to provide a
//! port-centric interface: port initialization, device detection,
//! command slot allocation, and DMA command submission.
//!
//! This module sits above `ahci.rs` (raw register layout) and below
//! the block I/O layer (`bio.rs`).  It models up to [`MAX_SATA_PORTS`]
//! physical ports and tracks per-port command slot bitmaps.
//!
//! Reference: Serial ATA AHCI 1.3.1, §§3 (Port registers), 4 (FIS).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum SATA ports managed by this layer.
pub const MAX_SATA_PORTS: usize = 32;

/// Maximum command slots per port (AHCI supports 1–32).
pub const MAX_CMD_SLOTS: usize = 32;

/// Sector size in bytes.
pub const SATA_SECTOR_SIZE: usize = 512;

/// PxCMD: Start (ST) — starts command list DMA engine.
pub const PORT_CMD_ST: u32 = 1 << 0;

/// PxCMD: FIS Receive Enable (FRE).
pub const PORT_CMD_FRE: u32 = 1 << 4;

/// PxCMD: FIS Receive Running (FR).
pub const PORT_CMD_FR: u32 = 1 << 14;

/// PxCMD: Command List Running (CR).
pub const PORT_CMD_CR: u32 = 1 << 15;

/// PxSSTS: Device Present and communication established (DET == 3).
pub const SSTS_DET_PRESENT: u32 = 0x3;

/// PxSSTS: DET field mask.
pub const SSTS_DET_MASK: u32 = 0xF;

/// PxSIG: SATA device signature (ATA disk).
pub const SIG_ATA: u32 = 0x0000_0101;

/// PxSIG: ATAPI device signature.
pub const SIG_ATAPI: u32 = 0xEB14_0101;

/// PxIS / PxIE: Device-to-Host Register FIS interrupt.
pub const PORT_IS_DHRS: u32 = 1 << 0;

/// PxIS: Task File Error Status.
pub const PORT_IS_TFES: u32 = 1 << 30;

/// Polling iterations before timeout.
const POLL_LIMIT: u32 = 500_000;

// ---------------------------------------------------------------------------
// SataDeviceType
// ---------------------------------------------------------------------------

/// Type of device attached to a SATA port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SataDeviceType {
    /// No device or unknown.
    #[default]
    None,
    /// Standard ATA disk.
    Ata,
    /// ATAPI device (optical drive, tape).
    Atapi,
}

// ---------------------------------------------------------------------------
// SataPort
// ---------------------------------------------------------------------------

/// State for a single AHCI SATA port.
#[derive(Debug)]
pub struct SataPort {
    /// MMIO base address for this port's register block.
    pub mmio_base: u64,
    /// Port index (0–31).
    pub index: usize,
    /// Type of device attached.
    pub device_type: SataDeviceType,
    /// Bitmap of free command slots (bit N = slot N free).
    pub free_slots: u32,
    /// Whether the port has been initialized.
    pub initialized: bool,
    /// Total sectors on attached ATA device (0 if none/unknown).
    pub sector_count: u64,
}

impl SataPort {
    const fn empty(index: usize) -> Self {
        Self {
            mmio_base: 0,
            index,
            device_type: SataDeviceType::None,
            free_slots: u32::MAX,
            initialized: false,
            sector_count: 0,
        }
    }

    /// Reads a 32-bit port register at `offset` bytes from `mmio_base`.
    ///
    /// # Safety
    ///
    /// Caller must ensure `mmio_base` is a valid MMIO mapping and
    /// `offset` is within the port's 128-byte register block.
    unsafe fn read32(&self, offset: u64) -> u32 {
        let addr = (self.mmio_base + offset) as *const u32;
        // SAFETY: Caller guarantees valid MMIO mapping; volatile required for HW registers.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Writes a 32-bit port register at `offset` bytes from `mmio_base`.
    ///
    /// # Safety
    ///
    /// Same as [`read32`](Self::read32).
    unsafe fn write32(&self, offset: u64, val: u32) {
        let addr = (self.mmio_base + offset) as *mut u32;
        // SAFETY: Caller guarantees valid MMIO mapping; volatile required for HW registers.
        unsafe { core::ptr::write_volatile(addr, val) };
    }

    /// Returns `true` if a device is present on this port.
    ///
    /// # Safety
    ///
    /// Caller must ensure the MMIO mapping is valid.
    pub unsafe fn device_present(&self) -> bool {
        // PxSSTS is at offset 0x28.
        // SAFETY: Delegated to read32; same precondition.
        let ssts = unsafe { self.read32(0x28) };
        (ssts & SSTS_DET_MASK) == SSTS_DET_PRESENT
    }

    /// Detects the device type from PxSIG (offset 0x24).
    ///
    /// # Safety
    ///
    /// Caller must ensure the MMIO mapping is valid.
    pub unsafe fn detect_device(&mut self) {
        // SAFETY: Delegated to read32; same precondition.
        let sig = unsafe { self.read32(0x24) };
        self.device_type = match sig {
            SIG_ATA => SataDeviceType::Ata,
            SIG_ATAPI => SataDeviceType::Atapi,
            _ => SataDeviceType::None,
        };
    }

    /// Stops DMA engines (clear ST and FRE) and waits for quiescence.
    ///
    /// # Safety
    ///
    /// Caller must ensure MMIO mapping is valid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the engines do not stop in time.
    pub unsafe fn stop_engines(&self) -> Result<()> {
        // PxCMD at offset 0x18.
        // SAFETY: Delegated.
        let mut cmd = unsafe { self.read32(0x18) };
        cmd &= !(PORT_CMD_ST | PORT_CMD_FRE);
        // SAFETY: Delegated.
        unsafe { self.write32(0x18, cmd) };

        // Wait for FR and CR to clear.
        for _ in 0..POLL_LIMIT {
            // SAFETY: Delegated.
            let c = unsafe { self.read32(0x18) };
            if c & (PORT_CMD_FR | PORT_CMD_CR) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Starts DMA engines (set FRE then ST).
    ///
    /// # Safety
    ///
    /// Caller must ensure MMIO mapping is valid and engines are stopped.
    pub unsafe fn start_engines(&self) {
        // SAFETY: Delegated.
        let mut cmd = unsafe { self.read32(0x18) };
        cmd |= PORT_CMD_FRE;
        // SAFETY: Delegated.
        unsafe { self.write32(0x18, cmd) };
        cmd |= PORT_CMD_ST;
        // SAFETY: Delegated.
        unsafe { self.write32(0x18, cmd) };
    }

    /// Allocates a command slot from the free bitmap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if all slots are occupied.
    pub fn alloc_slot(&mut self) -> Result<usize> {
        if self.free_slots == 0 {
            return Err(Error::Busy);
        }
        let slot = self.free_slots.trailing_zeros() as usize;
        self.free_slots &= !(1 << slot);
        Ok(slot)
    }

    /// Releases a previously allocated command slot.
    pub fn free_slot(&mut self, slot: usize) {
        if slot < MAX_CMD_SLOTS {
            self.free_slots |= 1 << slot;
        }
    }

    /// Issues a command by setting PxCI bit for `slot`.
    ///
    /// # Safety
    ///
    /// Caller must have filled the command table for `slot` before calling.
    pub unsafe fn issue_command(&self, slot: usize) {
        // PxCI at offset 0x38.
        // SAFETY: Delegated.
        unsafe { self.write32(0x38, 1u32 << slot) };
    }

    /// Waits for slot `slot` to complete (PxCI bit clears).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout, [`Error::IoError`] on task file error.
    pub unsafe fn wait_command(&self, slot: usize) -> Result<()> {
        for _ in 0..POLL_LIMIT {
            // SAFETY: Delegated.
            let is = unsafe { self.read32(0x10) };
            if is & PORT_IS_TFES != 0 {
                return Err(Error::IoError);
            }
            // PxCI at offset 0x38.
            // SAFETY: Delegated.
            let ci = unsafe { self.read32(0x38) };
            if ci & (1u32 << slot) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }
}

// ---------------------------------------------------------------------------
// SataController
// ---------------------------------------------------------------------------

/// SATA controller managing up to [`MAX_SATA_PORTS`] ports.
pub struct SataController {
    /// MMIO base of the AHCI HBA global register area.
    pub hba_base: u64,
    /// Per-port state.
    ports: [SataPort; MAX_SATA_PORTS],
    /// Number of implemented ports (from HBA CAP.NP + 1).
    pub port_count: usize,
}

impl SataController {
    /// Creates a new controller instance for the HBA at `hba_base`.
    pub fn new(hba_base: u64) -> Self {
        Self {
            hba_base,
            ports: core::array::from_fn(|i| SataPort::empty(i)),
            port_count: 0,
        }
    }

    /// Reads the HBA CAP register (offset 0x00).
    ///
    /// # Safety
    ///
    /// `hba_base` must be a valid MMIO mapping.
    pub unsafe fn read_cap(&self) -> u32 {
        let addr = self.hba_base as *const u32;
        // SAFETY: Caller guarantees valid MMIO; volatile required.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Initialises the controller: detects implemented ports and device types.
    ///
    /// # Safety
    ///
    /// `hba_base` must be a valid AHCI MMIO mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if CAP reads zero (HBA not present).
    pub unsafe fn init(&mut self) -> Result<()> {
        // SAFETY: Caller guarantees valid MMIO.
        let cap = unsafe { self.read_cap() };
        if cap == 0 {
            return Err(Error::IoError);
        }

        // NP = bits[4:0] = max ports - 1.
        let np = ((cap & 0x1F) as usize) + 1;
        self.port_count = np.min(MAX_SATA_PORTS);

        // Each port's register block starts at HBA_BASE + 0x100 + port*0x80.
        for i in 0..self.port_count {
            let port_base = self.hba_base + 0x100 + (i as u64) * 0x80;
            self.ports[i].mmio_base = port_base;

            // SAFETY: port_base is within the valid MMIO mapping.
            if unsafe { self.ports[i].device_present() } {
                // SAFETY: Same precondition.
                unsafe { self.ports[i].detect_device() };
                self.ports[i].initialized = true;
            }
        }
        Ok(())
    }

    /// Returns a shared reference to port `index`.
    pub fn port(&self, index: usize) -> Option<&SataPort> {
        if index < self.port_count {
            Some(&self.ports[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to port `index`.
    pub fn port_mut(&mut self, index: usize) -> Option<&mut SataPort> {
        if index < self.port_count {
            Some(&mut self.ports[index])
        } else {
            None
        }
    }

    /// Returns the number of ports that have a device present.
    pub fn connected_port_count(&self) -> usize {
        self.ports[..self.port_count]
            .iter()
            .filter(|p| p.device_type != SataDeviceType::None)
            .count()
    }
}
