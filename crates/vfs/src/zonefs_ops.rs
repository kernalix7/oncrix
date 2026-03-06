// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ZoneFS file operations for zone-backed files.
//!
//! Each ZoneFS file maps to a single zone on a zoned block device.
//! This module implements the POSIX file operation semantics for zone-backed
//! files, enforcing the sequential-write constraints of the underlying device.
//!
//! # Write Constraints
//!
//! Sequential zones require writes to start at the current write pointer.
//! Any write that does not begin at the write pointer returns `EINVAL`.
//! Conventional zones allow random writes within the zone's capacity.
//!
//! # File Size Semantics
//!
//! For sequential zones, the file's apparent size equals the number of bytes
//! written (write pointer offset from zone start). Reads beyond the write
//! pointer return zeros without performing I/O.
//!
//! # Zone Reset
//!
//! Truncating a sequential zone file to size 0 issues a zone reset command
//! to the device, moving the write pointer back to the zone start.

use oncrix_lib::{Error, Result};

/// I/O access type for a ZoneFS operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ZoneIoDir {
    /// Read operation.
    Read,
    /// Write operation.
    Write,
}

/// Request descriptor for a ZoneFS I/O operation.
#[derive(Clone, Copy, Default)]
pub struct ZoneIoReq {
    /// Zone number.
    pub zone_no: u32,
    /// Byte offset within the zone.
    pub offset: u64,
    /// Number of bytes to transfer.
    pub len: u64,
    /// Whether this is a read or write.
    pub is_write: bool,
}

impl ZoneIoReq {
    /// Validates this I/O request against zone parameters.
    ///
    /// `zone_capacity_bytes` is the usable capacity of the zone in bytes.
    /// `write_ptr_bytes` is the current write pointer offset from zone start.
    /// `is_sequential` indicates if the zone requires sequential writes.
    pub fn validate(
        &self,
        zone_capacity_bytes: u64,
        write_ptr_bytes: u64,
        is_sequential: bool,
    ) -> Result<()> {
        if self.len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.offset + self.len > zone_capacity_bytes {
            return Err(Error::InvalidArgument);
        }
        if self.is_write && is_sequential && self.offset != write_ptr_bytes {
            // Sequential write zone: must write at the write pointer.
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Result of a ZoneFS I/O dispatch.
#[derive(Clone, Copy, Default, Debug)]
pub struct ZoneIoResult {
    /// Number of bytes actually transferred.
    pub bytes_transferred: u64,
    /// New write pointer position (for writes to sequential zones).
    pub new_write_ptr: u64,
}

/// ZoneFS file context (tracks per-open-file state).
pub struct ZoneFileCtx {
    /// Zone number this file is backed by.
    pub zone_no: u32,
    /// Whether the zone requires sequential writes.
    pub is_sequential: bool,
    /// Zone start LBA (in 512-byte sectors).
    pub zone_start_lba: u64,
    /// Zone capacity in bytes.
    pub zone_capacity_bytes: u64,
    /// Current write pointer offset in bytes from zone start.
    pub write_ptr_bytes: u64,
    /// Current file size in bytes (= write pointer for sequential zones).
    pub file_size_bytes: u64,
    /// Whether this file was opened read-only.
    pub read_only: bool,
}

impl Default for ZoneFileCtx {
    fn default() -> Self {
        Self {
            zone_no: 0,
            is_sequential: false,
            zone_start_lba: 0,
            zone_capacity_bytes: 0,
            write_ptr_bytes: 0,
            file_size_bytes: 0,
            read_only: false,
        }
    }
}

impl ZoneFileCtx {
    /// Creates a new file context for a zone.
    pub fn new(
        zone_no: u32,
        is_sequential: bool,
        zone_start_lba: u64,
        zone_capacity_bytes: u64,
        write_ptr_bytes: u64,
        read_only: bool,
    ) -> Self {
        Self {
            zone_no,
            is_sequential,
            zone_start_lba,
            zone_capacity_bytes,
            write_ptr_bytes,
            file_size_bytes: write_ptr_bytes,
            read_only,
        }
    }

    /// Validates and returns the I/O parameters for a `read` call.
    ///
    /// Returns `(zone_offset, actual_read_len)`.
    pub fn prepare_read(&self, offset: u64, requested_len: u64) -> Result<(u64, u64)> {
        if offset >= self.file_size_bytes {
            return Ok((offset, 0)); // EOF
        }
        let available = self.file_size_bytes - offset;
        let read_len = requested_len.min(available);
        Ok((offset, read_len))
    }

    /// Validates and returns the I/O parameters for a `write` call.
    ///
    /// For sequential zones, enforces that `offset == write_ptr_bytes`.
    pub fn prepare_write(&self, offset: u64, len: u64) -> Result<(u64, u64)> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        if offset + len > self.zone_capacity_bytes {
            return Err(Error::InvalidArgument);
        }
        if self.is_sequential && offset != self.write_ptr_bytes {
            return Err(Error::InvalidArgument);
        }
        Ok((offset, len))
    }

    /// Records a completed write, advancing the write pointer and file size.
    pub fn complete_write(&mut self, bytes_written: u64) {
        self.write_ptr_bytes += bytes_written;
        if self.write_ptr_bytes > self.file_size_bytes {
            self.file_size_bytes = self.write_ptr_bytes;
        }
    }

    /// Performs a zone reset (truncate to size 0 for sequential zones).
    ///
    /// Returns `Err(InvalidArgument)` for conventional zones.
    pub fn reset(&mut self) -> Result<()> {
        if !self.is_sequential {
            return Err(Error::InvalidArgument);
        }
        self.write_ptr_bytes = 0;
        self.file_size_bytes = 0;
        Ok(())
    }
}
