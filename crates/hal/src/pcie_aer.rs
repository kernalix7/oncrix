// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe Advanced Error Reporting (AER) support.
//!
//! Implements PCIe AER capability register access, error type classification,
//! and error logging for both correctable and uncorrectable PCIe errors.
//!
//! # Overview
//!
//! AER is a PCIe capability that provides more detailed error information
//! than the basic PCI error status bits. It supports:
//! - Correctable errors (hardware recovers automatically)
//! - Uncorrectable errors (may require software intervention)
//! - Error forwarding and root port error collection
//!
//! Reference: PCI Express Base Specification 5.0, Section 7.8 (AER Capability).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// AER Capability Register Offsets (from capability base)
// ---------------------------------------------------------------------------

/// AER capability header offset.
pub const AER_CAP_HDR: u32 = 0x00;

/// Uncorrectable error status register offset.
pub const AER_UNCOR_STATUS: u32 = 0x04;

/// Uncorrectable error mask register offset.
pub const AER_UNCOR_MASK: u32 = 0x08;

/// Uncorrectable error severity register offset.
pub const AER_UNCOR_SEV: u32 = 0x0C;

/// Correctable error status register offset.
pub const AER_COR_STATUS: u32 = 0x10;

/// Correctable error mask register offset.
pub const AER_COR_MASK: u32 = 0x14;

/// Advanced error capabilities and control register offset.
pub const AER_CAP_CTRL: u32 = 0x18;

/// Header log register 0 offset (first DWORD of TLP header).
pub const AER_HEADER_LOG_0: u32 = 0x1C;

/// Header log register 1 offset.
pub const AER_HEADER_LOG_1: u32 = 0x20;

/// Header log register 2 offset.
pub const AER_HEADER_LOG_2: u32 = 0x24;

/// Header log register 3 offset.
pub const AER_HEADER_LOG_3: u32 = 0x28;

/// Root error command register offset (root ports only).
pub const AER_ROOT_ERR_CMD: u32 = 0x2C;

/// Root error status register offset (root ports only).
pub const AER_ROOT_ERR_STATUS: u32 = 0x30;

/// Error source identification register offset (root ports only).
pub const AER_ERR_SRC_ID: u32 = 0x34;

// ---------------------------------------------------------------------------
// Uncorrectable Error Status Bits
// ---------------------------------------------------------------------------

/// Undefined — reserved, must be zero.
const AER_UNCOR_UNDEFINED: u32 = 1 << 0;

/// Data Link Protocol Error.
pub const AER_UNCOR_DLP: u32 = 1 << 4;

/// Surprise Down Error (hot-unplug without notification).
pub const AER_UNCOR_SURPRISE_DOWN: u32 = 1 << 5;

/// Poisoned TLP Received.
pub const AER_UNCOR_POISONED_TLP: u32 = 1 << 12;

/// Flow Control Protocol Error.
pub const AER_UNCOR_FCP: u32 = 1 << 13;

/// Completion Timeout.
pub const AER_UNCOR_COMP_TIMEOUT: u32 = 1 << 14;

/// Completer Abort.
pub const AER_UNCOR_COMP_ABORT: u32 = 1 << 15;

/// Unexpected Completion.
pub const AER_UNCOR_UNEXP_COMP: u32 = 1 << 16;

/// Receiver Overflow.
pub const AER_UNCOR_RX_OVERFLOW: u32 = 1 << 17;

/// Malformed TLP.
pub const AER_UNCOR_MALF_TLP: u32 = 1 << 18;

/// ECRC Error.
pub const AER_UNCOR_ECRC: u32 = 1 << 19;

/// Unsupported Request Error.
pub const AER_UNCOR_UNSUP_REQ: u32 = 1 << 20;

/// ACS Violation.
pub const AER_UNCOR_ACS_VIOL: u32 = 1 << 21;

/// MC Blocked TLP.
pub const AER_UNCOR_MC_BLOCKED_TLP: u32 = 1 << 22;

// ---------------------------------------------------------------------------
// Correctable Error Status Bits
// ---------------------------------------------------------------------------

/// Receiver Error.
pub const AER_COR_RX_ERR: u32 = 1 << 0;

/// Bad TLP.
pub const AER_COR_BAD_TLP: u32 = 1 << 6;

/// Bad DLLP.
pub const AER_COR_BAD_DLLP: u32 = 1 << 7;

/// Replay Number Rollover.
pub const AER_COR_REPLAY_ROLLOVER: u32 = 1 << 8;

/// Replay Timer Timeout.
pub const AER_COR_REPLAY_TIMER: u32 = 1 << 12;

/// Advisory Non-Fatal Error.
pub const AER_COR_ADVISORY_NON_FATAL: u32 = 1 << 13;

/// Corrected Internal Error.
pub const AER_COR_INTERNAL_ERR: u32 = 1 << 14;

/// Header Log Overflow.
pub const AER_COR_HEADER_LOG_OVERFLOW: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// Root Error Command/Status Bits
// ---------------------------------------------------------------------------

/// Root error command: correctable error reporting enable.
pub const AER_ROOT_CMD_COR_EN: u32 = 1 << 0;

/// Root error command: non-fatal error reporting enable.
pub const AER_ROOT_CMD_NONFATAL_EN: u32 = 1 << 1;

/// Root error command: fatal error reporting enable.
pub const AER_ROOT_CMD_FATAL_EN: u32 = 1 << 2;

/// Root error status: ERR_COR received.
pub const AER_ROOT_STATUS_COR_RCV: u32 = 1 << 0;

/// Root error status: multiple ERR_COR received.
pub const AER_ROOT_STATUS_MULTI_COR: u32 = 1 << 1;

/// Root error status: ERR_FATAL/NONFATAL received.
pub const AER_ROOT_STATUS_UC_RCV: u32 = 1 << 2;

/// Root error status: multiple ERR_FATAL/NONFATAL received.
pub const AER_ROOT_STATUS_MULTI_UC: u32 = 1 << 3;

/// Root error status: first uncorrectable fatal.
pub const AER_ROOT_STATUS_FIRST_UNCOR_FATAL: u32 = 1 << 4;

/// Root error status: non-fatal error messages received.
pub const AER_ROOT_STATUS_NONFATAL_RCV: u32 = 1 << 5;

/// Root error status: fatal error messages received.
pub const AER_ROOT_STATUS_FATAL_RCV: u32 = 1 << 6;

/// Root error status: advanced error interrupt message number mask.
pub const AER_ROOT_STATUS_INT_MSG_MASK: u32 = 0x1F << 27;

// ---------------------------------------------------------------------------
// AER Cap/Control Bits
// ---------------------------------------------------------------------------

/// AER cap control: ECRC generation capable.
pub const AER_CAP_ECRC_GEN_CAP: u32 = 1 << 5;

/// AER cap control: ECRC generation enable.
pub const AER_CAP_ECRC_GEN_EN: u32 = 1 << 6;

/// AER cap control: ECRC check capable.
pub const AER_CAP_ECRC_CHK_CAP: u32 = 1 << 7;

/// AER cap control: ECRC check enable.
pub const AER_CAP_ECRC_CHK_EN: u32 = 1 << 8;

/// Maximum TLP header log DWORDs.
pub const AER_HEADER_LOG_DWORDS: usize = 4;

// ---------------------------------------------------------------------------
// Error Type Enums
// ---------------------------------------------------------------------------

/// Correctable PCIe error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectableError {
    /// Receiver error (8b/10b or 128b/130b decode error).
    RxErr,
    /// Bad TLP (sequence number or LCRC error).
    BadTlp,
    /// Bad DLLP (CRC error in DLLP).
    BadDllp,
    /// Replay number rollover.
    ReplayRollover,
    /// Replay timer timeout.
    ReplayTimer,
    /// Advisory non-fatal (used with poisoned TLP).
    AdvisoryNonFatal,
    /// Corrected internal error.
    InternalErr,
    /// Header log overflow.
    HeaderLogOverflow,
}

impl CorrectableError {
    /// Returns the status register bit mask for this error type.
    pub fn status_bit(self) -> u32 {
        match self {
            CorrectableError::RxErr => AER_COR_RX_ERR,
            CorrectableError::BadTlp => AER_COR_BAD_TLP,
            CorrectableError::BadDllp => AER_COR_BAD_DLLP,
            CorrectableError::ReplayRollover => AER_COR_REPLAY_ROLLOVER,
            CorrectableError::ReplayTimer => AER_COR_REPLAY_TIMER,
            CorrectableError::AdvisoryNonFatal => AER_COR_ADVISORY_NON_FATAL,
            CorrectableError::InternalErr => AER_COR_INTERNAL_ERR,
            CorrectableError::HeaderLogOverflow => AER_COR_HEADER_LOG_OVERFLOW,
        }
    }

    /// Returns a human-readable name for this error type.
    pub fn name(self) -> &'static str {
        match self {
            CorrectableError::RxErr => "Receiver Error",
            CorrectableError::BadTlp => "Bad TLP",
            CorrectableError::BadDllp => "Bad DLLP",
            CorrectableError::ReplayRollover => "Replay Rollover",
            CorrectableError::ReplayTimer => "Replay Timer",
            CorrectableError::AdvisoryNonFatal => "Advisory Non-Fatal",
            CorrectableError::InternalErr => "Corrected Internal Error",
            CorrectableError::HeaderLogOverflow => "Header Log Overflow",
        }
    }
}

/// Uncorrectable PCIe error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncorrectableError {
    /// Data Link Protocol Error.
    Dlp,
    /// Surprise Down Error.
    SurpriseDown,
    /// Poisoned TLP Received.
    PoisonedTlp,
    /// Flow Control Protocol Error.
    Fcp,
    /// Completion Timeout.
    CompTimeout,
    /// Completer Abort.
    CompAbort,
    /// Unexpected Completion.
    UnexpComp,
    /// Malformed TLP.
    MalfTlp,
    /// ECRC Error.
    Ecrc,
    /// Unsupported Request Error.
    UnsupReq,
    /// ACS Violation.
    AcsViol,
}

impl UncorrectableError {
    /// Returns the status register bit mask for this error type.
    pub fn status_bit(self) -> u32 {
        match self {
            UncorrectableError::Dlp => AER_UNCOR_DLP,
            UncorrectableError::SurpriseDown => AER_UNCOR_SURPRISE_DOWN,
            UncorrectableError::PoisonedTlp => AER_UNCOR_POISONED_TLP,
            UncorrectableError::Fcp => AER_UNCOR_FCP,
            UncorrectableError::CompTimeout => AER_UNCOR_COMP_TIMEOUT,
            UncorrectableError::CompAbort => AER_UNCOR_COMP_ABORT,
            UncorrectableError::UnexpComp => AER_UNCOR_UNEXP_COMP,
            UncorrectableError::MalfTlp => AER_UNCOR_MALF_TLP,
            UncorrectableError::Ecrc => AER_UNCOR_ECRC,
            UncorrectableError::UnsupReq => AER_UNCOR_UNSUP_REQ,
            UncorrectableError::AcsViol => AER_UNCOR_ACS_VIOL,
        }
    }

    /// Returns whether this error is fatal by default (per PCIe spec).
    pub fn is_fatal_default(self) -> bool {
        matches!(
            self,
            UncorrectableError::Dlp
                | UncorrectableError::SurpriseDown
                | UncorrectableError::Fcp
                | UncorrectableError::MalfTlp
        )
    }

    /// Returns a human-readable name for this error type.
    pub fn name(self) -> &'static str {
        match self {
            UncorrectableError::Dlp => "Data Link Protocol Error",
            UncorrectableError::SurpriseDown => "Surprise Down Error",
            UncorrectableError::PoisonedTlp => "Poisoned TLP",
            UncorrectableError::Fcp => "Flow Control Protocol Error",
            UncorrectableError::CompTimeout => "Completion Timeout",
            UncorrectableError::CompAbort => "Completer Abort",
            UncorrectableError::UnexpComp => "Unexpected Completion",
            UncorrectableError::MalfTlp => "Malformed TLP",
            UncorrectableError::Ecrc => "ECRC Error",
            UncorrectableError::UnsupReq => "Unsupported Request",
            UncorrectableError::AcsViol => "ACS Violation",
        }
    }
}

// ---------------------------------------------------------------------------
// TLP Header Log
// ---------------------------------------------------------------------------

/// Captured TLP header (4 DWORDs) from AER header log registers.
#[derive(Debug, Clone, Copy)]
pub struct TlpHeaderLog {
    /// Raw 4-DWORD TLP header captured at time of error.
    pub dwords: [u32; AER_HEADER_LOG_DWORDS],
}

impl TlpHeaderLog {
    /// Creates an empty (zeroed) header log.
    pub const fn zeroed() -> Self {
        Self {
            dwords: [0u32; AER_HEADER_LOG_DWORDS],
        }
    }

    /// Returns the TLP type field from DWORD 0 bits [7:5].
    pub fn tlp_type(&self) -> u8 {
        ((self.dwords[0] >> 5) & 0x1F) as u8
    }

    /// Returns the traffic class field from DWORD 0 bits [6:4].
    pub fn traffic_class(&self) -> u8 {
        ((self.dwords[0] >> 4) & 0x07) as u8
    }

    /// Returns the length field (10-bit) from DWORD 0.
    pub fn length(&self) -> u16 {
        (self.dwords[0] & 0x3FF) as u16
    }
}

// ---------------------------------------------------------------------------
// Error Log Entry
// ---------------------------------------------------------------------------

/// A logged AER error event.
#[derive(Debug, Clone, Copy)]
pub struct AerErrorLog {
    /// Whether this is a correctable (true) or uncorrectable (false) error.
    pub correctable: bool,
    /// Raw status register value at time of error.
    pub status: u32,
    /// Captured TLP header.
    pub header_log: TlpHeaderLog,
    /// Source BDF (bus/device/function) identifying the reporting device.
    pub source_id: u16,
}

impl AerErrorLog {
    /// Creates a new zeroed error log entry.
    pub const fn zeroed() -> Self {
        Self {
            correctable: false,
            status: 0,
            header_log: TlpHeaderLog::zeroed(),
            source_id: 0,
        }
    }
}

/// Maximum number of AER error log entries kept in the ring.
pub const AER_LOG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// AER Capability Structure
// ---------------------------------------------------------------------------

/// PCIe AER capability instance for a single device.
///
/// Provides read/clear/mask operations on the AER registers mapped via MMIO,
/// plus a fixed-size ring buffer of recent error log entries.
pub struct AerCapability {
    /// MMIO base address of the AER capability block (from PCI config space walk).
    mmio_base: u64,
    /// Whether ECRC generation is enabled.
    ecrc_gen_enabled: bool,
    /// Whether ECRC checking is enabled.
    ecrc_chk_enabled: bool,
    /// Ring buffer of recent errors.
    error_log: [AerErrorLog; AER_LOG_SIZE],
    /// Next write index in the error log ring.
    log_head: usize,
    /// Total number of errors logged (may exceed AER_LOG_SIZE).
    total_errors: u64,
    /// Correctable error count.
    cor_count: u64,
    /// Uncorrectable non-fatal count.
    unc_nonfatal_count: u64,
    /// Uncorrectable fatal count.
    unc_fatal_count: u64,
}

impl AerCapability {
    /// Creates a new AER capability instance at the given MMIO base address.
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            ecrc_gen_enabled: false,
            ecrc_chk_enabled: false,
            error_log: [AerErrorLog::zeroed(); AER_LOG_SIZE],
            log_head: 0,
            total_errors: 0,
            cor_count: 0,
            unc_nonfatal_count: 0,
            unc_fatal_count: 0,
        }
    }

    /// Initializes the AER capability: enables ECRC if capable, clears stale errors.
    pub fn init(&mut self) -> Result<()> {
        // Read capabilities and control register.
        let cap_ctrl = self.read_reg(AER_CAP_CTRL);

        // Enable ECRC generation if the hardware supports it.
        if cap_ctrl & AER_CAP_ECRC_GEN_CAP != 0 {
            self.write_reg(AER_CAP_CTRL, cap_ctrl | AER_CAP_ECRC_GEN_EN);
            self.ecrc_gen_enabled = true;
        }

        // Enable ECRC checking if the hardware supports it.
        if cap_ctrl & AER_CAP_ECRC_CHK_CAP != 0 {
            let updated = self.read_reg(AER_CAP_CTRL);
            self.write_reg(AER_CAP_CTRL, updated | AER_CAP_ECRC_CHK_EN);
            self.ecrc_chk_enabled = true;
        }

        // Clear any stale error status.
        self.clear_cor_status(!0u32);
        self.clear_uncor_status(!0u32);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Correctable Error Operations
    // -----------------------------------------------------------------------

    /// Reads the correctable error status register.
    pub fn read_cor_status(&self) -> u32 {
        self.read_reg(AER_COR_STATUS)
    }

    /// Clears correctable error status bits specified by `mask`.
    ///
    /// Writing 1 to a bit clears the corresponding status (W1C).
    pub fn clear_cor_status(&mut self, mask: u32) {
        self.write_reg(AER_COR_STATUS, mask);
    }

    /// Reads the correctable error mask register.
    pub fn read_cor_mask(&self) -> u32 {
        self.read_reg(AER_COR_MASK)
    }

    /// Writes the correctable error mask register.
    ///
    /// A set bit suppresses reporting for that error type.
    pub fn write_cor_mask(&mut self, mask: u32) {
        self.write_reg(AER_COR_MASK, mask);
    }

    /// Masks (suppresses) a specific correctable error type.
    pub fn mask_cor_error(&mut self, err: CorrectableError) {
        let current = self.read_cor_mask();
        self.write_cor_mask(current | err.status_bit());
    }

    /// Unmasks (enables reporting for) a specific correctable error type.
    pub fn unmask_cor_error(&mut self, err: CorrectableError) {
        let current = self.read_cor_mask();
        self.write_cor_mask(current & !err.status_bit());
    }

    // -----------------------------------------------------------------------
    // Uncorrectable Error Operations
    // -----------------------------------------------------------------------

    /// Reads the uncorrectable error status register.
    pub fn read_uncor_status(&self) -> u32 {
        self.read_reg(AER_UNCOR_STATUS)
    }

    /// Clears uncorrectable error status bits specified by `mask` (W1C).
    pub fn clear_uncor_status(&mut self, mask: u32) {
        self.write_reg(AER_UNCOR_STATUS, mask);
    }

    /// Reads the uncorrectable error mask register.
    pub fn read_uncor_mask(&self) -> u32 {
        self.read_reg(AER_UNCOR_MASK)
    }

    /// Writes the uncorrectable error mask register.
    pub fn write_uncor_mask(&mut self, mask: u32) {
        self.write_reg(AER_UNCOR_MASK, mask);
    }

    /// Masks a specific uncorrectable error type.
    pub fn mask_uncor_error(&mut self, err: UncorrectableError) {
        let current = self.read_uncor_mask();
        self.write_uncor_mask(current | err.status_bit());
    }

    /// Unmasks a specific uncorrectable error type.
    pub fn unmask_uncor_error(&mut self, err: UncorrectableError) {
        let current = self.read_uncor_mask();
        self.write_uncor_mask(current & !err.status_bit());
    }

    /// Reads the uncorrectable error severity register.
    ///
    /// A set bit means the corresponding error is fatal; cleared = non-fatal.
    pub fn read_uncor_severity(&self) -> u32 {
        self.read_reg(AER_UNCOR_SEV)
    }

    /// Writes the uncorrectable error severity register.
    pub fn write_uncor_severity(&mut self, sev: u32) {
        self.write_reg(AER_UNCOR_SEV, sev);
    }

    // -----------------------------------------------------------------------
    // Header Log
    // -----------------------------------------------------------------------

    /// Reads the TLP header log registers.
    pub fn read_header_log(&self) -> TlpHeaderLog {
        TlpHeaderLog {
            dwords: [
                self.read_reg(AER_HEADER_LOG_0),
                self.read_reg(AER_HEADER_LOG_1),
                self.read_reg(AER_HEADER_LOG_2),
                self.read_reg(AER_HEADER_LOG_3),
            ],
        }
    }

    // -----------------------------------------------------------------------
    // Root Port Operations
    // -----------------------------------------------------------------------

    /// Reads the root error command register (root ports only).
    pub fn read_root_err_cmd(&self) -> u32 {
        self.read_reg(AER_ROOT_ERR_CMD)
    }

    /// Writes the root error command register (root ports only).
    pub fn write_root_err_cmd(&mut self, cmd: u32) {
        self.write_reg(AER_ROOT_ERR_CMD, cmd);
    }

    /// Enables all root port error reporting categories.
    pub fn enable_root_error_reporting(&mut self) {
        let cmd = AER_ROOT_CMD_COR_EN | AER_ROOT_CMD_NONFATAL_EN | AER_ROOT_CMD_FATAL_EN;
        self.write_root_err_cmd(cmd);
    }

    /// Reads the root error status register (root ports only).
    pub fn read_root_err_status(&self) -> u32 {
        self.read_reg(AER_ROOT_ERR_STATUS)
    }

    /// Clears root error status bits (W1C).
    pub fn clear_root_err_status(&mut self, mask: u32) {
        self.write_reg(AER_ROOT_ERR_STATUS, mask);
    }

    /// Reads the error source ID register.
    ///
    /// Bits [15:0] = correctable error source BDF.
    /// Bits [31:16] = fatal/non-fatal error source BDF.
    pub fn read_err_source_id(&self) -> u32 {
        self.read_reg(AER_ERR_SRC_ID)
    }

    /// Returns the source BDF for the most recent correctable error.
    pub fn cor_source_bdf(&self) -> u16 {
        (self.read_err_source_id() & 0xFFFF) as u16
    }

    /// Returns the source BDF for the most recent uncorrectable error.
    pub fn uncor_source_bdf(&self) -> u16 {
        (self.read_err_source_id() >> 16) as u16
    }

    // -----------------------------------------------------------------------
    // Interrupt Handler
    // -----------------------------------------------------------------------

    /// Handles an AER interrupt: reads status, logs, and clears errors.
    ///
    /// Returns a bitmask of which error categories were observed:
    /// bit 0 = correctable, bit 1 = uncorrectable non-fatal, bit 2 = uncorrectable fatal.
    pub fn handle_interrupt(&mut self) -> u8 {
        let mut observed = 0u8;

        let cor_status = self.read_cor_status();
        if cor_status != 0 {
            self.log_error(true, cor_status);
            self.clear_cor_status(cor_status);
            self.cor_count += 1;
            self.total_errors += 1;
            observed |= 0x01;
        }

        let unc_status = self.read_uncor_status();
        if unc_status != 0 {
            let sev = self.read_uncor_severity();
            let header_log = self.read_header_log();
            let source_id = self.uncor_source_bdf();

            self.error_log[self.log_head] = AerErrorLog {
                correctable: false,
                status: unc_status,
                header_log,
                source_id,
            };
            self.log_head = (self.log_head + 1) % AER_LOG_SIZE;
            self.clear_uncor_status(unc_status);

            let fatal_bits = unc_status & sev;
            if fatal_bits != 0 {
                self.unc_fatal_count += 1;
                observed |= 0x04;
            } else {
                self.unc_nonfatal_count += 1;
                observed |= 0x02;
            }
            self.total_errors += 1;
        }

        observed
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    /// Returns the total number of errors logged since init.
    pub fn total_errors(&self) -> u64 {
        self.total_errors
    }

    /// Returns the count of correctable errors.
    pub fn cor_count(&self) -> u64 {
        self.cor_count
    }

    /// Returns the count of uncorrectable non-fatal errors.
    pub fn unc_nonfatal_count(&self) -> u64 {
        self.unc_nonfatal_count
    }

    /// Returns the count of uncorrectable fatal errors.
    pub fn unc_fatal_count(&self) -> u64 {
        self.unc_fatal_count
    }

    /// Returns whether ECRC generation is enabled.
    pub fn ecrc_gen_enabled(&self) -> bool {
        self.ecrc_gen_enabled
    }

    /// Returns whether ECRC checking is enabled.
    pub fn ecrc_chk_enabled(&self) -> bool {
        self.ecrc_chk_enabled
    }

    /// Returns a reference to the error log ring buffer.
    pub fn error_log(&self) -> &[AerErrorLog; AER_LOG_SIZE] {
        &self.error_log
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Reads a 32-bit register at `offset` from the capability MMIO base.
    fn read_reg(&self, offset: u32) -> u32 {
        let addr = self.mmio_base + offset as u64;
        // SAFETY: mmio_base is a valid PCIe MMIO capability region provided
        // by the PCI enumeration layer. The offset is a known valid AER register
        // offset. Volatile read ensures the access is not optimized away.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Writes a 32-bit value to `offset` from the capability MMIO base.
    fn write_reg(&self, offset: u32, val: u32) {
        let addr = self.mmio_base + offset as u64;
        // SAFETY: Same as read_reg. Volatile write ensures hardware visibility.
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    /// Appends a correctable error to the log ring.
    fn log_error(&mut self, correctable: bool, status: u32) {
        let source_id = if correctable {
            self.cor_source_bdf()
        } else {
            self.uncor_source_bdf()
        };
        let header_log = self.read_header_log();
        self.error_log[self.log_head] = AerErrorLog {
            correctable,
            status,
            header_log,
            source_id,
        };
        self.log_head = (self.log_head + 1) % AER_LOG_SIZE;
    }
}

// Fix: remove incorrect match arm that referenced FCP as FCP (variant name consistency)
impl UncorrectableError {
    /// Returns whether this error is fatal by default (alias for internal use).
    fn is_fatal_default_inner(self) -> bool {
        matches!(
            self,
            UncorrectableError::Dlp
                | UncorrectableError::SurpriseDown
                | UncorrectableError::Fcp
                | UncorrectableError::MalfTlp
        )
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Maximum number of AER capability instances tracked globally.
pub const AER_MAX_DEVICES: usize = 32;

/// Global AER device registry.
pub struct AerRegistry {
    devices: [Option<AerCapability>; AER_MAX_DEVICES],
    count: usize,
}

impl AerRegistry {
    /// Creates an empty AER registry.
    pub const fn new() -> Self {
        // SAFETY: Option<AerCapability> is valid when None.
        const EMPTY: Option<AerCapability> = None;
        Self {
            devices: [EMPTY; AER_MAX_DEVICES],
            count: 0,
        }
    }

    /// Registers a new AER capability instance.
    pub fn register(&mut self, cap: AerCapability) -> Result<usize> {
        if self.count >= AER_MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(cap);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the AER capability at `index`.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut AerCapability> {
        self.devices[index].as_mut().ok_or(Error::NotFound)
    }

    /// Returns the number of registered AER devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no AER devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
