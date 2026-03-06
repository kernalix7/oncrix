// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! process_vm_readv / process_vm_writev implementation.
//!
//! Implements the Linux `process_vm_readv(2)` and `process_vm_writev(2)`
//! system calls, which allow one process to read from or write to the
//! address space of another process without ptrace attachment.
//!
//! # Design
//!
//! The operation transfers data between a local I/O vector (`local_iov`)
//! and a remote I/O vector (`remote_iov`) referencing the target process.
//! Both vectors are scatter-gather lists (arrays of `[addr, len]` pairs).
//!
//! Each transfer:
//! 1. Validates that the calling process has `PTRACE_MODE_ATTACH` or
//!    equivalent capability over the target.
//! 2. Iterates over the remote iovecs, resolving each virtual address
//!    to a physical page in the target's address space.
//! 3. Copies data between the resolved pages and the local iovecs.
//!
//! # Key Types
//!
//! - [`IoVec`] — a single scatter-gather segment `(base, len)`
//! - [`TransferDir`] — read (remote→local) or write (local→remote)
//! - [`AccessCheck`] — permission check result for a remote process
//! - [`ProcessVmRequest`] — a complete transfer request
//! - [`TransferResult`] — outcome of one segment transfer
//! - [`ProcessVmSubsystem`] — main dispatcher
//!
//! Reference: Linux `mm/process_vm_access.c`, `man 2 process_vm_readv`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of iovecs per call (matches Linux UIO_MAXIOV = 1024).
const MAX_IOV_COUNT: usize = 1024;

/// Maximum total bytes that can be transferred in one request.
const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Maximum number of concurrently tracked requests.
const MAX_REQUESTS: usize = 32;

/// Maximum number of segments per transfer result record.
const MAX_RESULT_SEGMENTS: usize = 64;

// -------------------------------------------------------------------
// IoVec
// -------------------------------------------------------------------

/// A single scatter-gather I/O segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoVec {
    /// Base virtual address.
    pub base: u64,
    /// Length in bytes.
    pub len: usize,
}

impl IoVec {
    /// Create a new `IoVec`.
    pub const fn new(base: u64, len: usize) -> Self {
        IoVec { base, len }
    }

    /// Return `true` if the segment is empty (len == 0).
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Return the exclusive end address.
    ///
    /// Returns `None` on overflow.
    pub fn end(self) -> Option<u64> {
        self.base.checked_add(self.len as u64)
    }

    /// Validate that the iovec does not wrap around the address space.
    pub fn validate(self) -> Result<()> {
        if self.end().is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// TransferDir
// -------------------------------------------------------------------

/// Direction of a process_vm transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferDir {
    /// Read from remote process into local buffers.
    #[default]
    Read,
    /// Write from local buffers into remote process.
    Write,
}

// -------------------------------------------------------------------
// AccessCheck
// -------------------------------------------------------------------

/// Result of checking whether the caller may access a remote process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessCheck {
    /// Access is permitted (caller has ptrace-like rights).
    #[default]
    Allowed,
    /// Access is denied (insufficient privileges).
    Denied,
    /// The target process does not exist.
    NoSuchProcess,
    /// The target process is in an incompatible state (zombie, etc.).
    InvalidState,
}

impl AccessCheck {
    /// Return `true` if access is permitted.
    pub const fn is_allowed(self) -> bool {
        matches!(self, AccessCheck::Allowed)
    }

    /// Convert a non-allowed result to an error.
    pub fn into_result(self) -> Result<()> {
        match self {
            AccessCheck::Allowed => Ok(()),
            AccessCheck::Denied => Err(Error::PermissionDenied),
            AccessCheck::NoSuchProcess => Err(Error::NotFound),
            AccessCheck::InvalidState => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// ProcessVmRequest
// -------------------------------------------------------------------

/// A complete `process_vm_readv` / `process_vm_writev` request.
#[derive(Debug, Clone)]
pub struct ProcessVmRequest {
    /// PID of the calling process.
    pub caller_pid: u32,
    /// PID of the remote (target) process.
    pub remote_pid: u32,
    /// Direction of transfer.
    pub dir: TransferDir,
    /// Local scatter-gather list.
    pub local_iov: [IoVec; MAX_IOV_COUNT],
    /// Number of valid local iovecs.
    pub local_iov_count: usize,
    /// Remote scatter-gather list.
    pub remote_iov: [IoVec; MAX_IOV_COUNT],
    /// Number of valid remote iovecs.
    pub remote_iov_count: usize,
}

impl ProcessVmRequest {
    /// Create a new request with empty iovec arrays.
    pub fn new(caller_pid: u32, remote_pid: u32, dir: TransferDir) -> Self {
        ProcessVmRequest {
            caller_pid,
            remote_pid,
            dir,
            local_iov: [const { IoVec { base: 0, len: 0 } }; MAX_IOV_COUNT],
            local_iov_count: 0,
            remote_iov: [const { IoVec { base: 0, len: 0 } }; MAX_IOV_COUNT],
            remote_iov_count: 0,
        }
    }

    /// Add a local iovec to the request.
    pub fn add_local_iov(&mut self, iov: IoVec) -> Result<()> {
        if self.local_iov_count >= MAX_IOV_COUNT {
            return Err(Error::InvalidArgument);
        }
        iov.validate()?;
        self.local_iov[self.local_iov_count] = iov;
        self.local_iov_count += 1;
        Ok(())
    }

    /// Add a remote iovec to the request.
    pub fn add_remote_iov(&mut self, iov: IoVec) -> Result<()> {
        if self.remote_iov_count >= MAX_IOV_COUNT {
            return Err(Error::InvalidArgument);
        }
        iov.validate()?;
        self.remote_iov[self.remote_iov_count] = iov;
        self.remote_iov_count += 1;
        Ok(())
    }

    /// Compute the total bytes in all local iovecs.
    pub fn local_total_bytes(&self) -> usize {
        let mut total = 0usize;
        for i in 0..self.local_iov_count {
            total = total.saturating_add(self.local_iov[i].len);
        }
        total
    }

    /// Compute the total bytes in all remote iovecs.
    pub fn remote_total_bytes(&self) -> usize {
        let mut total = 0usize;
        for i in 0..self.remote_iov_count {
            total = total.saturating_add(self.remote_iov[i].len);
        }
        total
    }

    /// Validate the request structure.
    pub fn validate(&self) -> Result<()> {
        if self.local_iov_count == 0 || self.remote_iov_count == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.local_total_bytes() > MAX_TRANSFER_BYTES {
            return Err(Error::InvalidArgument);
        }
        if self.remote_total_bytes() > MAX_TRANSFER_BYTES {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// SegmentTransferResult
// -------------------------------------------------------------------

/// Outcome of transferring one segment (one pair of local+remote iovecs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentTransferResult {
    /// Virtual address of the remote segment.
    pub remote_addr: u64,
    /// Number of bytes actually transferred.
    pub bytes_transferred: usize,
    /// Whether the segment completed without error.
    pub ok: bool,
}

// -------------------------------------------------------------------
// TransferResult
// -------------------------------------------------------------------

/// Aggregate result of a complete `process_vm_readv/writev` operation.
#[derive(Debug, Clone)]
pub struct TransferResult {
    /// Total bytes successfully transferred.
    pub bytes_total: usize,
    /// Number of segments processed.
    pub segments_processed: usize,
    /// Number of segments that encountered errors.
    pub segments_failed: usize,
    /// Per-segment detail records (up to MAX_RESULT_SEGMENTS).
    segments: [SegmentTransferResult; MAX_RESULT_SEGMENTS],
    /// Number of valid entries in `segments`.
    segment_count: usize,
}

impl TransferResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        TransferResult {
            bytes_total: 0,
            segments_processed: 0,
            segments_failed: 0,
            segments: [const {
                SegmentTransferResult {
                    remote_addr: 0,
                    bytes_transferred: 0,
                    ok: false,
                }
            }; MAX_RESULT_SEGMENTS],
            segment_count: 0,
        }
    }

    /// Record the outcome of one segment.
    pub fn record_segment(&mut self, remote_addr: u64, bytes: usize, ok: bool) {
        self.segments_processed += 1;
        if ok {
            self.bytes_total = self.bytes_total.saturating_add(bytes);
        } else {
            self.segments_failed += 1;
        }
        if self.segment_count < MAX_RESULT_SEGMENTS {
            self.segments[self.segment_count] = SegmentTransferResult {
                remote_addr,
                bytes_transferred: bytes,
                ok,
            };
            self.segment_count += 1;
        }
    }

    /// Iterate over recorded segment results.
    pub fn segment_results(&self) -> &[SegmentTransferResult] {
        &self.segments[..self.segment_count]
    }
}

impl Default for TransferResult {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ProcessVmStats
// -------------------------------------------------------------------

/// Aggregate statistics for the process_vm subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessVmStats {
    /// Total `process_vm_readv` calls.
    pub readv_calls: u64,
    /// Total `process_vm_writev` calls.
    pub writev_calls: u64,
    /// Total bytes read across all calls.
    pub bytes_read: u64,
    /// Total bytes written across all calls.
    pub bytes_written: u64,
    /// Calls rejected due to permission check failure.
    pub permission_denied: u64,
    /// Calls rejected due to invalid arguments.
    pub invalid_args: u64,
    /// Partial transfers (some segments failed).
    pub partial_transfers: u64,
}

// -------------------------------------------------------------------
// ProcessVmSubsystem
// -------------------------------------------------------------------

/// The main `process_vm_readv` / `process_vm_writev` dispatcher.
///
/// In a real kernel this would walk the target process's page tables via
/// GUP to obtain physical addresses, then copy data using direct physical
/// mappings. Here the subsystem tracks requests and accumulates statistics
/// while simulating page-resolution logic.
pub struct ProcessVmSubsystem {
    /// Aggregate statistics.
    stats: ProcessVmStats,
    /// Active request records (ring buffer for audit purposes).
    recent: [RecentEntry; MAX_REQUESTS],
    /// Write head in `recent`.
    head: usize,
    /// Total requests ever submitted.
    total: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct RecentEntry {
    caller_pid: u32,
    remote_pid: u32,
    dir: TransferDir,
    bytes: usize,
    ok: bool,
}

impl ProcessVmSubsystem {
    /// Create a new subsystem instance.
    pub const fn new() -> Self {
        ProcessVmSubsystem {
            stats: ProcessVmStats {
                readv_calls: 0,
                writev_calls: 0,
                bytes_read: 0,
                bytes_written: 0,
                permission_denied: 0,
                invalid_args: 0,
                partial_transfers: 0,
            },
            recent: [const {
                RecentEntry {
                    caller_pid: 0,
                    remote_pid: 0,
                    dir: TransferDir::Read,
                    bytes: 0,
                    ok: false,
                }
            }; MAX_REQUESTS],
            head: 0,
            total: 0,
        }
    }

    /// Check if `caller_pid` is permitted to access `remote_pid`.
    ///
    /// In a real kernel this would check `ptrace_may_access()`.
    pub fn check_access(&self, caller_pid: u32, remote_pid: u32) -> AccessCheck {
        // A process may always access itself.
        if caller_pid == remote_pid {
            return AccessCheck::Allowed;
        }
        // PID 0 is invalid.
        if remote_pid == 0 {
            return AccessCheck::NoSuchProcess;
        }
        // Placeholder policy: process 1 (init) can access anyone;
        // other processes require explicit capability (always allowed
        // here for simulation purposes).
        let _ = caller_pid;
        AccessCheck::Allowed
    }

    /// Execute a `process_vm_readv` request.
    ///
    /// Returns a [`TransferResult`] describing the outcome.
    pub fn readv(&mut self, req: &ProcessVmRequest) -> Result<TransferResult> {
        self.stats.readv_calls += 1;

        let check = self.check_access(req.caller_pid, req.remote_pid);
        if !check.is_allowed() {
            self.stats.permission_denied += 1;
            return check.into_result().map(|_| TransferResult::new());
        }

        if let Err(e) = req.validate() {
            self.stats.invalid_args += 1;
            return Err(e);
        }

        let result = self.do_transfer(req);
        self.stats.bytes_read += result.bytes_total as u64;
        if result.segments_failed > 0 {
            self.stats.partial_transfers += 1;
        }
        self.record_recent(req, result.bytes_total, result.segments_failed == 0);
        Ok(result)
    }

    /// Execute a `process_vm_writev` request.
    ///
    /// Returns a [`TransferResult`] describing the outcome.
    pub fn writev(&mut self, req: &ProcessVmRequest) -> Result<TransferResult> {
        self.stats.writev_calls += 1;

        let check = self.check_access(req.caller_pid, req.remote_pid);
        if !check.is_allowed() {
            self.stats.permission_denied += 1;
            return check.into_result().map(|_| TransferResult::new());
        }

        if let Err(e) = req.validate() {
            self.stats.invalid_args += 1;
            return Err(e);
        }

        let result = self.do_transfer(req);
        self.stats.bytes_written += result.bytes_total as u64;
        if result.segments_failed > 0 {
            self.stats.partial_transfers += 1;
        }
        self.record_recent(req, result.bytes_total, result.segments_failed == 0);
        Ok(result)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> ProcessVmStats {
        self.stats
    }

    /// Return the total number of requests processed.
    pub fn total_requests(&self) -> u64 {
        self.total
    }

    // -- Private helpers

    fn do_transfer(&self, req: &ProcessVmRequest) -> TransferResult {
        let mut result = TransferResult::new();

        // Simulate segment-by-segment transfer.
        // In a full implementation each remote iovec segment would be
        // resolved to physical pages via GUP, then data copied.
        let seg_count = req.remote_iov_count.min(req.local_iov_count);
        for i in 0..seg_count {
            let remote = req.remote_iov[i];
            let local = req.local_iov[i];
            if remote.is_empty() || local.is_empty() {
                result.record_segment(remote.base, 0, true);
                continue;
            }
            // Check alignment and page boundaries.
            let remote_page = remote.base / PAGE_SIZE as u64;
            let bytes = remote.len.min(local.len);
            let ok = remote_page > 0 && bytes > 0;
            result.record_segment(remote.base, if ok { bytes } else { 0 }, ok);
        }
        result
    }

    fn record_recent(&mut self, req: &ProcessVmRequest, bytes: usize, ok: bool) {
        self.recent[self.head] = RecentEntry {
            caller_pid: req.caller_pid,
            remote_pid: req.remote_pid,
            dir: req.dir,
            bytes,
            ok,
        };
        self.head = (self.head + 1) % MAX_REQUESTS;
        self.total += 1;
    }
}

impl Default for ProcessVmSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
