// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Error Detection and Correction (EDAC) subsystem.
//!
//! Provides a framework for reporting and tracking memory errors from
//! hardware ECC logic, analogous to the Linux EDAC subsystem but
//! adapted for a no_std microkernel environment.
//!
//! # Architecture
//!
//! - [`EdacErrorType`] — classification of a memory error (correctable,
//!   uncorrectable, or fatal).
//! - [`DimmInfo`] — physical DIMM location and size descriptor.
//! - [`MemoryController`] — a memory controller with associated DIMMs.
//! - [`EdacError`] — a single error event with address, syndrome, and
//!   timestamp.
//! - [`ErrorLog`] — ring buffer storing the last 256 error events.
//! - [`EdacRegistry`] — manages up to 4 memory controllers and provides
//!   global CE/UE counters.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of DIMMs per memory controller.
const MAX_DIMMS_PER_MC: usize = 8;

/// Maximum number of memory controllers in the registry.
const MAX_MEMORY_CONTROLLERS: usize = 4;

/// Capacity of the error log ring buffer.
const ERROR_LOG_CAPACITY: usize = 256;

// -------------------------------------------------------------------
// EdacErrorType
// -------------------------------------------------------------------

/// Classification of a detected memory error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EdacErrorType {
    /// Single-bit error that was corrected by ECC hardware.
    #[default]
    Correctable,
    /// Multi-bit error that could not be corrected.
    Uncorrectable,
    /// Fatal multi-bit error requiring immediate system halt.
    Fatal,
}

// -------------------------------------------------------------------
// DimmInfo
// -------------------------------------------------------------------

/// Physical location and capacity descriptor for a DIMM module.
#[derive(Debug, Clone, Copy)]
pub struct DimmInfo {
    /// Memory controller index this DIMM belongs to.
    pub controller: u8,
    /// Channel index on the controller (0-based).
    pub channel: u8,
    /// Slot index on the channel (0-based).
    pub slot: u8,
    /// DIMM capacity in mebibytes (MiB).
    pub size_mb: u32,
    /// DIMM type name stored as UTF-8 bytes (e.g., b"DDR5").
    pub type_name: [u8; 8],
    /// Number of valid bytes in [`type_name`](Self::type_name).
    pub type_name_len: usize,
    /// Per-DIMM correctable error count.
    pub ce_count: u64,
    /// Per-DIMM uncorrectable error count.
    pub ue_count: u64,
}

impl DimmInfo {
    /// Creates a `DimmInfo` for a DIMM at the given location.
    pub fn new(controller: u8, channel: u8, slot: u8, size_mb: u32, type_name: &[u8]) -> Self {
        let copy_len = type_name.len().min(8);
        let mut buf = [0u8; 8];
        buf[..copy_len].copy_from_slice(&type_name[..copy_len]);
        Self {
            controller,
            channel,
            slot,
            size_mb,
            type_name: buf,
            type_name_len: copy_len,
            ce_count: 0,
            ue_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// MemoryController
// -------------------------------------------------------------------

/// A hardware memory controller with associated DIMM slots.
#[derive(Debug, Clone)]
pub struct MemoryController {
    /// Unique memory controller identifier.
    pub id: u32,
    /// DIMM descriptors (populated slots).
    pub dimms: [Option<DimmInfo>; MAX_DIMMS_PER_MC],
    /// Number of populated DIMM slots.
    pub dimm_count: usize,
    /// Total correctable errors reported by this controller.
    pub ce_count: u64,
    /// Total uncorrectable errors reported by this controller.
    pub ue_count: u64,
}

impl MemoryController {
    /// Creates a new memory controller with the given `id`.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            dimms: [const { None }; MAX_DIMMS_PER_MC],
            dimm_count: 0,
            ce_count: 0,
            ue_count: 0,
        }
    }

    /// Adds a DIMM to this controller.
    ///
    /// Returns [`Error::OutOfMemory`] if all [`MAX_DIMMS_PER_MC`]
    /// slots are occupied.
    pub fn add_dimm(&mut self, dimm: DimmInfo) -> Result<()> {
        for slot in &mut self.dimms {
            if slot.is_none() {
                *slot = Some(dimm);
                self.dimm_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to the DIMM at `(channel, slot)`.
    ///
    /// Returns [`Error::NotFound`] if no matching DIMM is registered.
    pub fn get_dimm(&self, channel: u8, slot: u8) -> Result<&DimmInfo> {
        self.dimms
            .iter()
            .flatten()
            .find(|d| d.channel == channel && d.slot == slot)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the DIMM at `(channel, slot)`.
    fn get_dimm_mut(&mut self, channel: u8, slot: u8) -> Result<&mut DimmInfo> {
        self.dimms
            .iter_mut()
            .flatten()
            .find(|d| d.channel == channel && d.slot == slot)
            .ok_or(Error::NotFound)
    }

    /// Records an error and updates per-DIMM and per-controller counters.
    ///
    /// If the DIMM at `(channel, rank)` exists, its per-DIMM counter
    /// is also updated.
    pub fn record_error(&mut self, error: &EdacError) {
        match error.error_type {
            EdacErrorType::Correctable => {
                self.ce_count = self.ce_count.saturating_add(1);
                if let Ok(dimm) = self.get_dimm_mut(error.channel, error.rank) {
                    dimm.ce_count = dimm.ce_count.saturating_add(1);
                }
            }
            EdacErrorType::Uncorrectable | EdacErrorType::Fatal => {
                self.ue_count = self.ue_count.saturating_add(1);
                if let Ok(dimm) = self.get_dimm_mut(error.channel, error.rank) {
                    dimm.ue_count = dimm.ue_count.saturating_add(1);
                }
            }
        }
    }
}

// -------------------------------------------------------------------
// EdacError
// -------------------------------------------------------------------

/// A single memory error event.
#[derive(Debug, Clone, Copy)]
pub struct EdacError {
    /// Type of error (correctable, uncorrectable, fatal).
    pub error_type: EdacErrorType,
    /// ID of the memory controller that reported the error.
    pub controller_id: u32,
    /// Channel index on the controller.
    pub channel: u8,
    /// Rank (row) on the channel — used to locate the DIMM slot.
    pub rank: u8,
    /// Physical memory address where the error was detected.
    pub address: u64,
    /// Timestamp in nanoseconds (monotonic clock).
    pub timestamp_ns: u64,
    /// ECC syndrome value (hardware-specific).
    pub syndrome: u32,
}

// -------------------------------------------------------------------
// ErrorLog
// -------------------------------------------------------------------

/// Ring buffer storing the most recent memory error events.
///
/// Holds up to [`ERROR_LOG_CAPACITY`] (256) entries.
pub struct ErrorLog {
    /// Circular buffer of error records.
    entries: [Option<EdacError>; ERROR_LOG_CAPACITY],
    /// Write head (next insert position).
    head: usize,
    /// Total errors logged (not capped at capacity).
    total: u64,
}

impl Default for ErrorLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorLog {
    /// Creates an empty error log.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; ERROR_LOG_CAPACITY],
            head: 0,
            total: 0,
        }
    }

    /// Appends an error to the ring buffer, overwriting the oldest
    /// entry when the buffer is full.
    pub fn push(&mut self, error: EdacError) {
        self.entries[self.head] = Some(error);
        self.head = (self.head + 1) % ERROR_LOG_CAPACITY;
        self.total = self.total.saturating_add(1);
    }

    /// Returns the number of valid entries currently in the buffer.
    ///
    /// Capped at [`ERROR_LOG_CAPACITY`].
    pub fn len(&self) -> usize {
        (self.total as usize).min(ERROR_LOG_CAPACITY)
    }

    /// Returns `true` if the log contains no entries.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Returns the total number of errors ever logged (may exceed
    /// the ring buffer capacity).
    pub fn total_logged(&self) -> u64 {
        self.total
    }

    /// Returns the most recently logged error, or `None` if empty.
    pub fn latest(&self) -> Option<&EdacError> {
        if self.total == 0 {
            return None;
        }
        let prev = if self.head == 0 {
            ERROR_LOG_CAPACITY - 1
        } else {
            self.head - 1
        };
        self.entries[prev].as_ref()
    }

    /// Iterates over all valid entries in insertion order.
    ///
    /// Calls `f` with each `&EdacError`. Oldest first.
    pub fn for_each<F: FnMut(&EdacError)>(&self, mut f: F) {
        let count = self.len();
        let start = if self.total as usize > ERROR_LOG_CAPACITY {
            // Buffer has wrapped; oldest entry is at current head.
            self.head
        } else {
            0
        };
        for i in 0..count {
            let idx = (start + i) % ERROR_LOG_CAPACITY;
            if let Some(ref e) = self.entries[idx] {
                f(e);
            }
        }
    }
}

// -------------------------------------------------------------------
// EdacRegistry
// -------------------------------------------------------------------

/// Global EDAC registry managing memory controllers and the error log.
///
/// Tracks up to [`MAX_MEMORY_CONTROLLERS`] (4) controllers and
/// maintains aggregate CE and UE counters.
pub struct EdacRegistry {
    /// Registered memory controllers.
    controllers: [Option<MemoryController>; MAX_MEMORY_CONTROLLERS],
    /// Number of registered controllers.
    controller_count: usize,
    /// Global correctable error counter across all controllers.
    pub global_ce_count: u64,
    /// Global uncorrectable error counter across all controllers.
    pub global_ue_count: u64,
    /// Ring-buffer error log.
    pub log: ErrorLog,
}

impl Default for EdacRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EdacRegistry {
    /// Creates a new, empty EDAC registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_MEMORY_CONTROLLERS],
            controller_count: 0,
            global_ce_count: 0,
            global_ue_count: 0,
            log: ErrorLog::new(),
        }
    }

    /// Registers a memory controller.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same id is
    /// already registered.
    pub fn register_controller(&mut self, mc: MemoryController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == mc.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.controllers {
            if slot.is_none() {
                *slot = Some(mc);
                self.controller_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a shared reference to the controller with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_controller(&self, id: u32) -> Result<&MemoryController> {
        self.controllers
            .iter()
            .flatten()
            .find(|mc| mc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the controller with `id`.
    fn get_controller_mut(&mut self, id: u32) -> Result<&mut MemoryController> {
        self.controllers
            .iter_mut()
            .flatten()
            .find(|mc| mc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Reports a memory error.
    ///
    /// Updates the controller's per-DIMM and per-controller counters,
    /// updates global counters, and appends the error to the log.
    ///
    /// Returns [`Error::NotFound`] if the referenced controller is
    /// not registered.
    pub fn report_error(&mut self, error: EdacError) -> Result<()> {
        // Update per-controller counters.
        let mc = self.get_controller_mut(error.controller_id)?;
        mc.record_error(&error);

        // Update global counters.
        match error.error_type {
            EdacErrorType::Correctable => {
                self.global_ce_count = self.global_ce_count.saturating_add(1);
            }
            EdacErrorType::Uncorrectable | EdacErrorType::Fatal => {
                self.global_ue_count = self.global_ue_count.saturating_add(1);
            }
        }

        // Append to error log.
        self.log.push(error);
        Ok(())
    }

    /// Polls all registered controllers for new errors.
    ///
    /// In a real driver this would read hardware status registers.
    /// This implementation provides the interface hook; callers
    /// inject discovered errors via [`report_error`](Self::report_error).
    ///
    /// Returns the total number of errors discovered across all
    /// controllers during this poll (always 0 in this stub —
    /// hardware-specific drivers override this by calling
    /// `report_error` directly).
    pub fn poll_errors(&mut self) -> u32 {
        // Hardware-specific polling logic is implemented in the
        // platform driver; this stub returns 0.
        0
    }

    /// Returns the number of registered memory controllers.
    pub fn len(&self) -> usize {
        self.controller_count
    }

    /// Returns `true` if no memory controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.controller_count == 0
    }
}
