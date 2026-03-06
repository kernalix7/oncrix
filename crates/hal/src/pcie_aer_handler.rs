// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe Advanced Error Reporting (AER) handler.
//!
//! Implements capability parsing, error detection, and recovery for the
//! PCIe AER mechanism as defined in the PCIe Base Specification.
//!
//! # Architecture
//!
//! AER extends each PCIe device with an Extended Capability (offset in
//! the extended configuration space, starting at 0x100). The capability
//! contains:
//!
//! - Uncorrectable Error Status/Mask/Severity registers
//! - Correctable Error Status/Mask registers
//! - Root Error Status register (root ports only)
//! - Error Source Identification register
//!
//! # Error Classes
//!
//! - **Correctable** — hardware corrects automatically; software logs only.
//! - **Uncorrectable Non-Fatal** — hardware cannot correct but the link
//!   remains operational; software may attempt recovery.
//! - **Uncorrectable Fatal** — link integrity lost; link reset required.
//!
//! Reference: Linux `drivers/pci/pcie/aer.c`, PCIe Spec §6.2.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// AER Extended Capability Register Offsets
// ---------------------------------------------------------------------------

/// AER capability header (offset from cap base).
const AER_CAP_HEADER: u16 = 0x00;

/// Uncorrectable Error Status register offset.
const AER_UNCORR_STATUS: u16 = 0x04;

/// Uncorrectable Error Mask register offset.
const AER_UNCORR_MASK: u16 = 0x08;

/// Uncorrectable Error Severity register offset.
const AER_UNCORR_SEVERITY: u16 = 0x0C;

/// Correctable Error Status register offset.
const AER_CORR_STATUS: u16 = 0x10;

/// Correctable Error Mask register offset.
const AER_CORR_MASK: u16 = 0x14;

/// Advanced Error Capabilities and Control register offset.
const AER_CAP_CTRL: u16 = 0x18;

/// Root Error Command register offset (root port only).
const AER_ROOT_CMD: u16 = 0x2C;

/// Root Error Status register offset (root port only).
const AER_ROOT_STATUS: u16 = 0x30;

/// Error Source Identification register offset.
const AER_ERR_SOURCE_ID: u16 = 0x34;

// ---------------------------------------------------------------------------
// Uncorrectable Error Status Bits
// ---------------------------------------------------------------------------

/// Undefined/link training error.
const AER_UNCORR_TRAINING: u32 = 1 << 0;

/// Data Link Protocol Error.
const AER_UNCORR_DLP: u32 = 1 << 4;

/// Surprise Down Error.
const AER_UNCORR_SURPRISE_DOWN: u32 = 1 << 5;

/// Poisoned TLP Received.
const AER_UNCORR_POISON_TLP: u32 = 1 << 12;

/// Flow Control Protocol Error.
const AER_UNCORR_FCP: u32 = 1 << 13;

/// Completion Timeout.
const AER_UNCORR_COMP_TIMEOUT: u32 = 1 << 14;

/// Completer Abort.
const AER_UNCORR_COMP_ABORT: u32 = 1 << 15;

/// Unexpected Completion.
const AER_UNCORR_UNEXP_COMP: u32 = 1 << 16;

/// Receiver Overflow.
const AER_UNCORR_RX_OVERFLOW: u32 = 1 << 17;

/// Malformed TLP.
const AER_UNCORR_MALFORMED_TLP: u32 = 1 << 18;

/// ECRC Error.
const AER_UNCORR_ECRC: u32 = 1 << 19;

/// Unsupported Request Error.
const AER_UNCORR_UNSUPPORTED_REQ: u32 = 1 << 20;

/// ACS Violation.
const AER_UNCORR_ACS_VIOLATION: u32 = 1 << 21;

/// Uncorrectable Internal Error.
const AER_UNCORR_INTERNAL: u32 = 1 << 22;

// ---------------------------------------------------------------------------
// Correctable Error Status Bits
// ---------------------------------------------------------------------------

/// Receiver Error.
const AER_CORR_RX_ERR: u32 = 1 << 0;

/// Bad TLP.
const AER_CORR_BAD_TLP: u32 = 1 << 6;

/// Bad DLLP.
const AER_CORR_BAD_DLLP: u32 = 1 << 7;

/// REPLAY_NUM Rollover.
const AER_CORR_REPLAY_ROLLOVER: u32 = 1 << 8;

/// Replay Timer Timeout.
const AER_CORR_REPLAY_TIMEOUT: u32 = 1 << 12;

/// Advisory Non-Fatal Error.
const AER_CORR_ADVISORY_NON_FATAL: u32 = 1 << 13;

// ---------------------------------------------------------------------------
// Root Error Status / Command Bits
// ---------------------------------------------------------------------------

/// Root Error Command: enable correctable error reporting.
const AER_ROOT_CMD_CORR_EN: u32 = 1 << 0;

/// Root Error Command: enable non-fatal error reporting.
const AER_ROOT_CMD_NONFATAL_EN: u32 = 1 << 1;

/// Root Error Command: enable fatal error reporting.
const AER_ROOT_CMD_FATAL_EN: u32 = 1 << 2;

/// Root Error Status: correctable error received.
const AER_ROOT_STS_CORR: u32 = 1 << 0;

/// Root Error Status: multiple correctable errors.
const AER_ROOT_STS_MULTI_CORR: u32 = 1 << 1;

/// Root Error Status: uncorrectable (non-fatal) error received.
const AER_ROOT_STS_UNCORR_NONFATAL: u32 = 1 << 2;

/// Root Error Status: multiple uncorrectable errors.
const AER_ROOT_STS_MULTI_UNCORR: u32 = 1 << 3;

/// Root Error Status: first uncorrectable fatal.
const AER_ROOT_STS_FIRST_FATAL: u32 = 1 << 4;

// ---------------------------------------------------------------------------
// PCIe Extended Capability ID
// ---------------------------------------------------------------------------

/// PCIe Extended Capability ID for AER.
pub const PCIE_EXT_CAP_AER: u16 = 0x0001;

/// PCIe Extended Capability start offset.
const PCIE_EXT_CAP_BASE: u16 = 0x100;

/// Maximum number of AER-capable devices tracked.
const MAX_AER_DEVICES: usize = 16;

// ---------------------------------------------------------------------------
// Error Classification
// ---------------------------------------------------------------------------

/// Classification of a detected PCIe error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AerErrorClass {
    /// Hardware corrected the error; only logging is needed.
    Correctable,
    /// Error is uncorrectable but the link is still functional.
    UncorrectableNonFatal,
    /// Link integrity is lost; link reset is required.
    UncorrectableFatal,
}

// ---------------------------------------------------------------------------
// AER Error Record
// ---------------------------------------------------------------------------

/// Describes a single AER error event.
#[derive(Debug, Clone, Copy)]
pub struct AerErrorRecord {
    /// BDF (bus/device/function, packed as `bus<<8 | devfn`) of the
    /// device that reported the error.
    pub source_bdf: u16,
    /// BDF of the device that originally generated the error (may
    /// differ from `source_bdf` for downstream devices).
    pub requester_bdf: u16,
    /// Raw uncorrectable error status register value.
    pub uncorr_status: u32,
    /// Raw correctable error status register value.
    pub corr_status: u32,
    /// Highest severity classification of the errors in this record.
    pub error_class: AerErrorClass,
}

impl AerErrorRecord {
    /// Create a new error record.
    pub const fn new(
        source_bdf: u16,
        requester_bdf: u16,
        uncorr_status: u32,
        corr_status: u32,
        error_class: AerErrorClass,
    ) -> Self {
        Self {
            source_bdf,
            requester_bdf,
            uncorr_status,
            corr_status,
            error_class,
        }
    }

    /// Whether any fatal uncorrectable errors are present.
    pub fn is_fatal(&self) -> bool {
        matches!(self.error_class, AerErrorClass::UncorrectableFatal)
    }
}

// ---------------------------------------------------------------------------
// AER Device State
// ---------------------------------------------------------------------------

/// AER state for a single PCIe device or root port.
#[derive(Debug)]
pub struct AerDevice {
    /// BDF identifier.
    pub bdf: u16,
    /// Base offset of the AER extended capability in config space.
    pub cap_offset: u16,
    /// Whether this is a root port (has Root Error Command/Status).
    pub is_root_port: bool,
    /// Saved uncorrectable mask (for restore after reset).
    saved_uncorr_mask: u32,
    /// Saved correctable mask.
    saved_corr_mask: u32,
    /// Total errors logged since registration.
    pub error_count: u64,
}

impl AerDevice {
    /// Create a new AER device entry.
    pub const fn new(bdf: u16, cap_offset: u16, is_root_port: bool) -> Self {
        Self {
            bdf,
            cap_offset,
            is_root_port,
            saved_uncorr_mask: 0,
            saved_corr_mask: 0,
            error_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers (config space access via caller-supplied read/write fn)
// ---------------------------------------------------------------------------

/// Classify uncorrectable error status bits.
///
/// Returns the worst-case class: Fatal > NonFatal > Correctable.
fn classify_uncorr(status: u32, severity: u32) -> AerErrorClass {
    if status == 0 {
        return AerErrorClass::Correctable;
    }
    // Any bit set in status that is also set in severity is fatal.
    if status & severity != 0 {
        AerErrorClass::UncorrectableFatal
    } else {
        AerErrorClass::UncorrectableNonFatal
    }
}

// ---------------------------------------------------------------------------
// AER Handler
// ---------------------------------------------------------------------------

/// Root port AER handler.
///
/// Manages a set of AER-capable devices discovered during PCI enumeration.
/// Call [`AerHandler::register_device`] for each AER-capable device found,
/// then call [`AerHandler::handle_root_interrupt`] from the root port's
/// interrupt handler.
pub struct AerHandler {
    /// Registered AER devices.
    devices: [Option<AerDevice>; MAX_AER_DEVICES],
    /// Number of registered devices.
    count: usize,
    /// Total AER interrupts serviced.
    irq_count: u64,
}

impl Default for AerHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AerHandler {
    /// Create a new AER handler with no registered devices.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_AER_DEVICES],
            count: 0,
            irq_count: 0,
        }
    }

    /// Register an AER-capable device.
    ///
    /// `cap_offset` is the offset of the AER extended capability block in
    /// configuration space (typically found by scanning the extended cap
    /// chain starting at 0x100).
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the device table is full.
    /// - [`Error::AlreadyExists`] if `bdf` is already registered.
    pub fn register_device(&mut self, bdf: u16, cap_offset: u16, is_root_port: bool) -> Result<()> {
        if self.count >= MAX_AER_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let already = self.devices[..self.count]
            .iter()
            .filter_map(|d| d.as_ref())
            .any(|d| d.bdf == bdf);
        if already {
            return Err(Error::AlreadyExists);
        }
        let idx = self.count;
        self.devices[idx] = Some(AerDevice::new(bdf, cap_offset, is_root_port));
        self.count += 1;
        Ok(())
    }

    /// Scan an extended capability chain for the AER capability.
    ///
    /// Walks the linked list of PCIe Extended Capabilities starting at
    /// `PCIE_EXT_CAP_BASE`, calling `read_cfg` to read 32-bit dwords.
    /// Returns the offset of the AER capability header, or
    /// [`Error::NotFound`] if AER is not present.
    ///
    /// # Arguments
    ///
    /// - `read_cfg` — closure: `(bdf, offset) -> u32` reading a dword
    ///   from PCI configuration space.
    pub fn find_aer_cap<F>(&self, _bdf: u16, read_cfg: F) -> Result<u16>
    where
        F: Fn(u16) -> u32,
    {
        let mut offset = PCIE_EXT_CAP_BASE;
        let mut depth = 0u32;
        loop {
            if offset < PCIE_EXT_CAP_BASE || offset & 0x3 != 0 {
                return Err(Error::NotFound);
            }
            let header = read_cfg(offset);
            if header == 0 || header == 0xFFFF_FFFF {
                return Err(Error::NotFound);
            }
            let cap_id = (header & 0xFFFF) as u16;
            if cap_id == PCIE_EXT_CAP_AER {
                return Ok(offset);
            }
            let next = ((header >> 20) & 0xFFC) as u16;
            if next == 0 {
                return Err(Error::NotFound);
            }
            offset = next;
            depth += 1;
            if depth > 64 {
                return Err(Error::NotFound);
            }
        }
    }

    /// Handle an AER interrupt from a root port.
    ///
    /// Reads the Root Error Status, identifies the error source device,
    /// classifies the error, logs it, and acknowledges the interrupt.
    ///
    /// # Arguments
    ///
    /// - `root_bdf` — BDF of the root port that signalled the interrupt.
    /// - `read_cfg` — closure reading config space: `(offset) -> u32`.
    /// - `write_cfg` — closure writing config space: `(offset, val)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `root_bdf` is not registered.
    pub fn handle_root_interrupt<R, W>(
        &mut self,
        root_bdf: u16,
        read_cfg: R,
        write_cfg: W,
    ) -> Result<Option<AerErrorRecord>>
    where
        R: Fn(u16) -> u32,
        W: Fn(u16, u32),
    {
        self.irq_count += 1;

        // Find the root port entry.
        let dev_idx = self.devices[..self.count]
            .iter()
            .position(|d| d.as_ref().map_or(false, |d| d.bdf == root_bdf))
            .ok_or(Error::NotFound)?;

        let cap = self.devices[dev_idx]
            .as_ref()
            .map(|d| d.cap_offset)
            .ok_or(Error::NotFound)?;

        let root_status = read_cfg(cap + AER_ROOT_STATUS);

        if root_status == 0 {
            return Ok(None);
        }

        // Identify error source from ERR_SOURCE_ID.
        let src_id_raw = read_cfg(cap + AER_ERR_SOURCE_ID);
        let corr_src = (src_id_raw & 0xFFFF) as u16;
        let uncorr_src = ((src_id_raw >> 16) & 0xFFFF) as u16;

        // Read the AER status from the error source device if registered.
        let (uncorr_status, corr_status, severity) = if let Some(src_dev) =
            self.devices[..self.count].iter().find_map(|d| {
                d.as_ref()
                    .filter(|d| d.bdf == uncorr_src || d.bdf == corr_src)
            }) {
            let base = src_dev.cap_offset;
            let u = read_cfg(base + AER_UNCORR_STATUS);
            let c = read_cfg(base + AER_CORR_STATUS);
            let sev = read_cfg(base + AER_UNCORR_SEVERITY);
            (u, c, sev)
        } else {
            (0, 0, 0)
        };

        // Classify error.
        let error_class = if uncorr_status != 0 {
            classify_uncorr(uncorr_status, severity)
        } else {
            AerErrorClass::Correctable
        };

        let record = AerErrorRecord::new(
            if uncorr_status != 0 {
                uncorr_src
            } else {
                corr_src
            },
            if uncorr_status != 0 {
                uncorr_src
            } else {
                corr_src
            },
            uncorr_status,
            corr_status,
            error_class,
        );

        // Acknowledge by writing 1 to set status bits (W1C).
        write_cfg(cap + AER_ROOT_STATUS, root_status);

        // Increment error count for this root port.
        if let Some(dev) = self.devices[dev_idx].as_mut() {
            dev.error_count += 1;
        }

        Ok(Some(record))
    }

    /// Enable AER error reporting on a root port.
    ///
    /// Sets the Root Error Command register to receive all error classes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `root_bdf` is not registered.
    pub fn enable_root_reporting<W>(&self, root_bdf: u16, write_cfg: W) -> Result<()>
    where
        W: Fn(u16, u32),
    {
        let dev = self.devices[..self.count]
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.bdf == root_bdf))
            .ok_or(Error::NotFound)?;

        if !dev.is_root_port {
            return Err(Error::InvalidArgument);
        }

        let cmd = AER_ROOT_CMD_CORR_EN | AER_ROOT_CMD_NONFATAL_EN | AER_ROOT_CMD_FATAL_EN;
        write_cfg(dev.cap_offset + AER_ROOT_CMD, cmd);
        Ok(())
    }

    /// Perform a link reset on the given root port to recover from a fatal
    /// error.
    ///
    /// Disables error reporting, saves the AER masks, and signals that a
    /// secondary bus reset should be issued (the actual bus-reset must be
    /// performed by the PCI core). Returns the BDF for confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `root_bdf` is not registered.
    pub fn initiate_link_reset<R, W>(
        &mut self,
        root_bdf: u16,
        read_cfg: R,
        write_cfg: W,
    ) -> Result<u16>
    where
        R: Fn(u16) -> u32,
        W: Fn(u16, u32),
    {
        let dev_idx = self.devices[..self.count]
            .iter()
            .position(|d| d.as_ref().map_or(false, |d| d.bdf == root_bdf))
            .ok_or(Error::NotFound)?;

        let cap = self.devices[dev_idx]
            .as_ref()
            .map(|d| d.cap_offset)
            .ok_or(Error::NotFound)?;

        // Save and mask all errors.
        let uncorr_mask = read_cfg(cap + AER_UNCORR_MASK);
        let corr_mask = read_cfg(cap + AER_CORR_MASK);

        if let Some(dev) = self.devices[dev_idx].as_mut() {
            dev.saved_uncorr_mask = uncorr_mask;
            dev.saved_corr_mask = corr_mask;
        }

        // Mask all uncorrectable and correctable errors during reset.
        write_cfg(cap + AER_UNCORR_MASK, 0xFFFF_FFFF);
        write_cfg(cap + AER_CORR_MASK, 0xFFFF_FFFF);
        // Disable root error reporting.
        write_cfg(cap + AER_ROOT_CMD, 0);

        Ok(root_bdf)
    }

    /// Return the total number of AER interrupts handled.
    pub fn irq_count(&self) -> u64 {
        self.irq_count
    }

    /// Return the number of registered AER devices.
    pub fn device_count(&self) -> usize {
        self.count
    }

    /// Look up a registered device by BDF.
    pub fn find_device(&self, bdf: u16) -> Option<&AerDevice> {
        self.devices[..self.count]
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.bdf == bdf))
    }

    // Keep these public for unit tests and allow dead_code.
    #[allow(dead_code)]
    const AER_CAP_HEADER_VAL: u16 = AER_CAP_HEADER;

    #[allow(dead_code)]
    const AER_UNCORR_BITS: u32 = AER_UNCORR_TRAINING
        | AER_UNCORR_DLP
        | AER_UNCORR_SURPRISE_DOWN
        | AER_UNCORR_POISON_TLP
        | AER_UNCORR_FCP
        | AER_UNCORR_COMP_TIMEOUT
        | AER_UNCORR_COMP_ABORT
        | AER_UNCORR_UNEXP_COMP
        | AER_UNCORR_RX_OVERFLOW
        | AER_UNCORR_MALFORMED_TLP
        | AER_UNCORR_ECRC
        | AER_UNCORR_UNSUPPORTED_REQ
        | AER_UNCORR_ACS_VIOLATION
        | AER_UNCORR_INTERNAL;

    #[allow(dead_code)]
    const AER_CORR_BITS: u32 = AER_CORR_RX_ERR
        | AER_CORR_BAD_TLP
        | AER_CORR_BAD_DLLP
        | AER_CORR_REPLAY_ROLLOVER
        | AER_CORR_REPLAY_TIMEOUT
        | AER_CORR_ADVISORY_NON_FATAL;
}
