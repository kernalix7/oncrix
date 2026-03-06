// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Error Detection and Correction (EDAC) memory controller core.
//!
//! Implements the memory controller registration layer, DIMM geometry
//! tracking, per-DIMM/channel/rank correctable and uncorrectable error
//! counting, structured error reporting with physical location details,
//! and scrubbing-rate management.
//!
//! # Architecture
//!
//! - [`DimmLocation`] — full hierarchy address (MC, channel, slot, rank).
//! - [`DimmInfo`] — capacity, type, and per-location error counters.
//! - [`ErrorRecord`] — one ECC event: type, address, syndrome, location.
//! - [`MemController`] — one memory controller with its DIMM population.
//! - [`EdacMcCore`] — global registry of up to [`MAX_MCS`] controllers;
//!   global CE/UE totals and an error log ring buffer.
//!
//! Reference: Linux `drivers/edac/edac_mc.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum memory controllers in the system.
const MAX_MCS: usize = 4;
/// Maximum DIMMs per controller.
const MAX_DIMMS: usize = 8;
/// Error log ring-buffer depth.
const ERROR_LOG_DEPTH: usize = 128;
/// Maximum length of a DIMM type name (e.g., "DDR5").
const DIMM_TYPE_LEN: usize = 8;
/// Maximum length of a controller name.
const MC_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// DimmLocation
// ---------------------------------------------------------------------------

/// Full physical address of a DIMM within the memory hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DimmLocation {
    /// Memory controller index (0-based).
    pub mc: u8,
    /// Channel index on the controller (0-based).
    pub channel: u8,
    /// DIMM slot on the channel (0-based).
    pub slot: u8,
    /// Rank within the DIMM (0-based).
    pub rank: u8,
}

impl DimmLocation {
    /// Creates a new DIMM location descriptor.
    pub const fn new(mc: u8, channel: u8, slot: u8, rank: u8) -> Self {
        Self {
            mc,
            channel,
            slot,
            rank,
        }
    }
}

// ---------------------------------------------------------------------------
// DimmInfo
// ---------------------------------------------------------------------------

/// Descriptor for a single DIMM module installed in the system.
#[derive(Clone, Copy)]
pub struct DimmInfo {
    /// Physical location in the memory hierarchy.
    pub location: DimmLocation,
    /// Capacity in mebibytes.
    pub size_mb: u32,
    /// Type string (e.g., b"DDR5\0\0\0\0").
    pub type_name: [u8; DIMM_TYPE_LEN],
    /// Number of valid bytes in `type_name`.
    pub type_name_len: usize,
    /// Correctable errors detected on this DIMM.
    pub ce_count: u64,
    /// Uncorrectable errors detected on this DIMM.
    pub ue_count: u64,
    /// Whether this slot is populated.
    pub present: bool,
}

/// Constant empty DIMM for array initialisation.
const EMPTY_DIMM: DimmInfo = DimmInfo {
    location: DimmLocation {
        mc: 0,
        channel: 0,
        slot: 0,
        rank: 0,
    },
    size_mb: 0,
    type_name: [0u8; DIMM_TYPE_LEN],
    type_name_len: 0,
    ce_count: 0,
    ue_count: 0,
    present: false,
};

impl DimmInfo {
    /// Creates a populated DIMM descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `type_name` is empty or too long.
    pub fn new(location: DimmLocation, size_mb: u32, type_name: &[u8]) -> Result<Self> {
        if type_name.is_empty() || type_name.len() > DIMM_TYPE_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut d = EMPTY_DIMM;
        d.location = location;
        d.size_mb = size_mb;
        d.type_name[..type_name.len()].copy_from_slice(type_name);
        d.type_name_len = type_name.len();
        d.present = true;
        Ok(d)
    }

    /// Returns the type name as a byte slice.
    pub fn type_str(&self) -> &[u8] {
        &self.type_name[..self.type_name_len]
    }

    /// Increments the correctable error count.
    pub fn inc_ce(&mut self) {
        self.ce_count = self.ce_count.saturating_add(1);
    }

    /// Increments the uncorrectable error count.
    pub fn inc_ue(&mut self) {
        self.ue_count = self.ue_count.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// ErrorType / ErrorRecord
// ---------------------------------------------------------------------------

/// Classification of a detected memory error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    /// Single-bit error corrected by ECC hardware.
    Correctable,
    /// Multi-bit error that could not be corrected.
    Uncorrectable,
    /// Catastrophic error requiring immediate action.
    Fatal,
}

/// A single ECC error event with full location details.
#[derive(Clone, Copy)]
pub struct ErrorRecord {
    /// Error classification.
    pub error_type: ErrorType,
    /// Faulting physical address.
    pub phys_addr: u64,
    /// ECC syndrome bits (hardware-specific encoding).
    pub syndrome: u32,
    /// Physical location of the affected DIMM.
    pub location: DimmLocation,
    /// Monotonic timestamp (e.g., HPET tick at detection).
    pub timestamp: u64,
}

/// Constant empty record for array initialisation.
const EMPTY_RECORD: ErrorRecord = ErrorRecord {
    error_type: ErrorType::Correctable,
    phys_addr: 0,
    syndrome: 0,
    location: DimmLocation {
        mc: 0,
        channel: 0,
        slot: 0,
        rank: 0,
    },
    timestamp: 0,
};

impl ErrorRecord {
    /// Creates a new error record.
    pub const fn new(
        error_type: ErrorType,
        phys_addr: u64,
        syndrome: u32,
        location: DimmLocation,
        timestamp: u64,
    ) -> Self {
        Self {
            error_type,
            phys_addr,
            syndrome,
            location,
            timestamp,
        }
    }
}

// ---------------------------------------------------------------------------
// MemController
// ---------------------------------------------------------------------------

/// A memory controller with its installed DIMM population.
pub struct MemController {
    /// Unique controller ID.
    pub id: u32,
    /// Human-readable name.
    name: [u8; MC_NAME_LEN],
    /// Number of valid bytes in `name`.
    name_len: usize,
    /// DIMM slots managed by this controller.
    dimms: [DimmInfo; MAX_DIMMS],
    /// Number of populated DIMM slots.
    dimm_count: usize,
    /// Correctable errors reported by this controller.
    pub ce_total: u64,
    /// Uncorrectable errors reported by this controller.
    pub ue_total: u64,
    /// Scrubbing rate in MiB/s (0 = disabled).
    pub scrub_rate_mbs: u32,
    /// Whether this slot in the global registry is occupied.
    pub present: bool,
}

/// Constant empty controller for array initialisation.
const EMPTY_MC: MemController = MemController {
    id: 0,
    name: [0u8; MC_NAME_LEN],
    name_len: 0,
    dimms: [EMPTY_DIMM; MAX_DIMMS],
    dimm_count: 0,
    ce_total: 0,
    ue_total: 0,
    scrub_rate_mbs: 0,
    present: false,
};

impl MemController {
    /// Creates a new memory controller descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty or too long.
    pub fn new(id: u32, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MC_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut mc = EMPTY_MC;
        mc.id = id;
        mc.name[..name.len()].copy_from_slice(name);
        mc.name_len = name.len();
        mc.present = true;
        Ok(mc)
    }

    /// Returns the controller name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Adds a DIMM to this controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the DIMM array is full.
    pub fn add_dimm(&mut self, dimm: DimmInfo) -> Result<usize> {
        if self.dimm_count >= MAX_DIMMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.dimm_count;
        self.dimms[idx] = dimm;
        self.dimm_count += 1;
        Ok(idx)
    }

    /// Returns a reference to a DIMM by slot index.
    pub fn get_dimm(&self, idx: usize) -> Option<&DimmInfo> {
        if idx < self.dimm_count && self.dimms[idx].present {
            Some(&self.dimms[idx])
        } else {
            None
        }
    }

    /// Returns a mutable reference to a DIMM by slot index.
    pub fn get_dimm_mut(&mut self, idx: usize) -> Option<&mut DimmInfo> {
        if idx < self.dimm_count && self.dimms[idx].present {
            Some(&mut self.dimms[idx])
        } else {
            None
        }
    }

    /// Records an error on the specified DIMM slot, updating counters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `dimm_idx` is invalid.
    pub fn record_error(&mut self, dimm_idx: usize, error_type: ErrorType) -> Result<()> {
        if dimm_idx >= self.dimm_count || !self.dimms[dimm_idx].present {
            return Err(Error::NotFound);
        }
        match error_type {
            ErrorType::Correctable => {
                self.dimms[dimm_idx].inc_ce();
                self.ce_total = self.ce_total.saturating_add(1);
            }
            ErrorType::Uncorrectable | ErrorType::Fatal => {
                self.dimms[dimm_idx].inc_ue();
                self.ue_total = self.ue_total.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Sets the memory scrubbing rate in MiB/s.
    ///
    /// A value of 0 disables scrubbing.
    pub fn set_scrub_rate(&mut self, rate_mbs: u32) {
        self.scrub_rate_mbs = rate_mbs;
    }

    /// Returns the number of populated DIMM slots.
    pub fn dimm_count(&self) -> usize {
        self.dimm_count
    }
}

// ---------------------------------------------------------------------------
// EdacMcCore
// ---------------------------------------------------------------------------

/// Global EDAC memory controller core registry.
///
/// Manages up to [`MAX_MCS`] memory controllers, maintains global
/// correctable/uncorrectable error totals, and stores a ring buffer
/// of the most recent error records.
pub struct EdacMcCore {
    /// Registered memory controllers.
    mcs: [MemController; MAX_MCS],
    /// Number of registered controllers.
    mc_count: usize,
    /// Global correctable error count.
    pub global_ce: u64,
    /// Global uncorrectable error count.
    pub global_ue: u64,
    /// Error log ring buffer.
    log: [ErrorRecord; ERROR_LOG_DEPTH],
    /// Write head into the ring buffer.
    log_head: usize,
    /// Total errors ever logged (for ring-full detection).
    log_total: usize,
}

impl EdacMcCore {
    /// Creates a new, empty EDAC core.
    pub const fn new() -> Self {
        Self {
            mcs: [EMPTY_MC; MAX_MCS],
            mc_count: 0,
            global_ce: 0,
            global_ue: 0,
            log: [EMPTY_RECORD; ERROR_LOG_DEPTH],
            log_head: 0,
            log_total: 0,
        }
    }

    /// Registers a memory controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if a controller with the same ID
    /// is already registered, or [`Error::OutOfMemory`] if the table is full.
    pub fn register_mc(&mut self, mc: MemController) -> Result<usize> {
        for i in 0..self.mc_count {
            if self.mcs[i].id == mc.id && self.mcs[i].present {
                return Err(Error::AlreadyExists);
            }
        }
        if self.mc_count >= MAX_MCS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.mc_count;
        self.mcs[idx] = mc;
        self.mc_count += 1;
        Ok(idx)
    }

    /// Unregisters a memory controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the controller is not registered.
    pub fn unregister_mc(&mut self, mc_id: u32) -> Result<()> {
        let idx = self.mc_index(mc_id)?;
        let last = self.mc_count - 1;
        if idx != last {
            self.mcs.swap(idx, last);
        }
        self.mcs[last] = EMPTY_MC;
        self.mc_count -= 1;
        Ok(())
    }

    /// Returns a reference to a registered controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not present.
    pub fn get_mc(&self, mc_id: u32) -> Result<&MemController> {
        let idx = self.mc_index(mc_id)?;
        Ok(&self.mcs[idx])
    }

    /// Returns a mutable reference to a registered controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not present.
    pub fn get_mc_mut(&mut self, mc_id: u32) -> Result<&mut MemController> {
        let idx = self.mc_index(mc_id)?;
        Ok(&mut self.mcs[idx])
    }

    /// Reports a memory error: updates counters and appends to the log.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the controller or DIMM is invalid.
    pub fn report_error(&mut self, record: ErrorRecord, dimm_idx: usize) -> Result<()> {
        let mc_id = record.location.mc as u32;
        let idx = self.mc_index(mc_id)?;
        self.mcs[idx].record_error(dimm_idx, record.error_type)?;
        match record.error_type {
            ErrorType::Correctable => self.global_ce = self.global_ce.saturating_add(1),
            ErrorType::Uncorrectable | ErrorType::Fatal => {
                self.global_ue = self.global_ue.saturating_add(1)
            }
        }
        self.push_log(record);
        Ok(())
    }

    /// Returns the error record at ring-buffer position `pos`.
    ///
    /// Position 0 is the oldest retained entry.
    pub fn get_log(&self, pos: usize) -> Option<&ErrorRecord> {
        let retained = self.log_total.min(ERROR_LOG_DEPTH);
        if pos >= retained {
            return None;
        }
        let start = if self.log_total > ERROR_LOG_DEPTH {
            self.log_head
        } else {
            0
        };
        Some(&self.log[(start + pos) % ERROR_LOG_DEPTH])
    }

    /// Returns the number of entries retained in the error log.
    pub fn log_len(&self) -> usize {
        self.log_total.min(ERROR_LOG_DEPTH)
    }

    /// Sets the scrub rate on the specified controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the controller is not registered.
    pub fn set_scrub_rate(&mut self, mc_id: u32, rate_mbs: u32) -> Result<()> {
        let idx = self.mc_index(mc_id)?;
        self.mcs[idx].set_scrub_rate(rate_mbs);
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn mc_count(&self) -> usize {
        self.mc_count
    }

    // -- internal -----------------------------------------------------------

    fn mc_index(&self, mc_id: u32) -> Result<usize> {
        self.mcs[..self.mc_count]
            .iter()
            .position(|m| m.id == mc_id && m.present)
            .ok_or(Error::NotFound)
    }

    fn push_log(&mut self, record: ErrorRecord) {
        self.log[self.log_head] = record;
        self.log_head = (self.log_head + 1) % ERROR_LOG_DEPTH;
        self.log_total = self.log_total.saturating_add(1);
    }
}

impl Default for EdacMcCore {
    fn default() -> Self {
        Self::new()
    }
}
