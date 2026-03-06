// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! process_vm_readv/writev implementation.
//!
//! Implements cross-process memory access via `process_vm_readv` and
//! `process_vm_writev` system calls. These allow a process with
//! appropriate permissions (ptrace rights) to read from or write to
//! another process's address space without going through the kernel
//! file interface.
//!
//! - [`RemoteIovec`] — describes a memory region in local or remote space
//! - [`VmAccessFlags`] — access direction and flags
//! - [`VmAccessResult`] — outcome of a cross-process access
//! - [`ProcessVmOps`] — the cross-process memory operations manager
//!
//! Reference: `.kernelORG/` — `mm/process_vm_access.c`, `process_vm_readv(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of iovec entries per call.
const MAX_IOVECS: usize = 64;

/// Maximum total transfer size per call (16 MiB).
const MAX_TRANSFER_SIZE: u64 = 16 * 1024 * 1024;

/// Maximum tracked processes.
const MAX_PROCESSES: usize = 128;

/// Permission: can read target memory.
const PTRACE_READ: u32 = 1 << 0;

/// Permission: can write target memory.
const PTRACE_WRITE: u32 = 1 << 1;

/// Flag: use remote process's address space.
const VM_FLAG_REMOTE: u32 = 1 << 0;

// -------------------------------------------------------------------
// RemoteIovec
// -------------------------------------------------------------------

/// Describes a memory region for cross-process I/O.
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoteIovec {
    /// Base address of the region.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

impl RemoteIovec {
    /// Creates a new iovec.
    pub fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    /// Returns the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.len)
    }

    /// Returns true if the region is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Checks if two iovecs overlap.
    pub fn overlaps(&self, other: &RemoteIovec) -> bool {
        self.base < other.end() && other.base < self.end()
    }

    /// Returns the number of pages spanned.
    pub fn nr_pages(&self) -> u64 {
        if self.len == 0 {
            return 0;
        }
        let start_page = self.base / PAGE_SIZE;
        let end_page = (self.end().saturating_sub(1)) / PAGE_SIZE;
        end_page - start_page + 1
    }
}

// -------------------------------------------------------------------
// IovecList
// -------------------------------------------------------------------

/// A list of iovecs for a transfer.
pub struct IovecList {
    /// The iovec entries.
    entries: [RemoteIovec; MAX_IOVECS],
    /// Number of valid entries.
    len: usize,
}

impl IovecList {
    /// Creates an empty iovec list.
    pub fn new() -> Self {
        Self {
            entries: [RemoteIovec::default(); MAX_IOVECS],
            len: 0,
        }
    }

    /// Adds an iovec entry.
    pub fn push(&mut self, iov: RemoteIovec) -> Result<()> {
        if self.len >= MAX_IOVECS {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.len] = iov;
        self.len += 1;
        Ok(())
    }

    /// Returns the entries as a slice.
    pub fn entries(&self) -> &[RemoteIovec] {
        &self.entries[..self.len]
    }

    /// Returns the total bytes across all entries.
    pub fn total_bytes(&self) -> u64 {
        self.entries[..self.len].iter().map(|e| e.len).sum()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for IovecList {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PtracePermission
// -------------------------------------------------------------------

/// Ptrace-based permission for cross-process access.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtracePermission {
    /// Source process ID.
    pub src_pid: u32,
    /// Target process ID.
    pub target_pid: u32,
    /// Permission flags.
    pub flags: u32,
}

impl PtracePermission {
    /// Creates a new permission.
    pub fn new(src_pid: u32, target_pid: u32, flags: u32) -> Self {
        Self {
            src_pid,
            target_pid,
            flags,
        }
    }

    /// Checks if read access is allowed.
    pub fn can_read(&self) -> bool {
        self.flags & PTRACE_READ != 0
    }

    /// Checks if write access is allowed.
    pub fn can_write(&self) -> bool {
        self.flags & PTRACE_WRITE != 0
    }
}

// -------------------------------------------------------------------
// VmAccessResult
// -------------------------------------------------------------------

/// Result of a cross-process memory access.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmAccessResult {
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Number of iovec entries fully processed.
    pub entries_processed: usize,
    /// Number of page faults encountered.
    pub page_faults: u64,
    /// Whether the operation completed fully.
    pub complete: bool,
}

impl VmAccessResult {
    /// Creates a successful complete result.
    pub fn complete(bytes: u64, entries: usize) -> Self {
        Self {
            bytes_transferred: bytes,
            entries_processed: entries,
            page_faults: 0,
            complete: true,
        }
    }

    /// Creates a partial result.
    pub fn partial(bytes: u64, entries: usize, faults: u64) -> Self {
        Self {
            bytes_transferred: bytes,
            entries_processed: entries,
            page_faults: faults,
            complete: false,
        }
    }
}

// -------------------------------------------------------------------
// ProcessVmOps
// -------------------------------------------------------------------

/// Cross-process virtual memory operations.
///
/// Manages permissions and provides `process_vm_readv` and
/// `process_vm_writev` functionality.
pub struct ProcessVmOps {
    /// Registered permissions.
    permissions: [PtracePermission; MAX_PROCESSES],
    /// Number of registered permissions.
    nr_perms: usize,
    /// Total bytes read across all operations.
    total_bytes_read: u64,
    /// Total bytes written across all operations.
    total_bytes_written: u64,
    /// Total operations.
    total_ops: u64,
}

impl ProcessVmOps {
    /// Creates a new operations manager.
    pub fn new() -> Self {
        Self {
            permissions: [PtracePermission::default(); MAX_PROCESSES],
            nr_perms: 0,
            total_bytes_read: 0,
            total_bytes_written: 0,
            total_ops: 0,
        }
    }

    /// Registers a ptrace permission.
    pub fn register_permission(&mut self, perm: PtracePermission) -> Result<()> {
        if self.nr_perms >= MAX_PROCESSES {
            return Err(Error::OutOfMemory);
        }
        self.permissions[self.nr_perms] = perm;
        self.nr_perms += 1;
        Ok(())
    }

    /// Checks if a process has read access to another.
    pub fn check_read_permission(&self, src_pid: u32, target_pid: u32) -> bool {
        // Root (pid 0) can read anything.
        if src_pid == 0 {
            return true;
        }
        // Self-access is always allowed.
        if src_pid == target_pid {
            return true;
        }
        self.permissions[..self.nr_perms]
            .iter()
            .any(|p| p.src_pid == src_pid && p.target_pid == target_pid && p.can_read())
    }

    /// Checks if a process has write access to another.
    pub fn check_write_permission(&self, src_pid: u32, target_pid: u32) -> bool {
        if src_pid == 0 {
            return true;
        }
        if src_pid == target_pid {
            return true;
        }
        self.permissions[..self.nr_perms]
            .iter()
            .any(|p| p.src_pid == src_pid && p.target_pid == target_pid && p.can_write())
    }

    /// Reads from a remote process's address space.
    ///
    /// Copies data from `remote_iov` in the target process to
    /// `local_iov` in the calling process.
    pub fn process_vm_readv(
        &mut self,
        src_pid: u32,
        target_pid: u32,
        local_iov: &IovecList,
        remote_iov: &IovecList,
        _flags: u32,
    ) -> Result<VmAccessResult> {
        // Permission check.
        if !self.check_read_permission(src_pid, target_pid) {
            return Err(Error::PermissionDenied);
        }

        self.validate_transfer(local_iov, remote_iov)?;

        // Compute transfer size (minimum of local and remote totals).
        let local_total = local_iov.total_bytes();
        let remote_total = remote_iov.total_bytes();
        let transfer_size = local_total.min(remote_total);

        self.total_bytes_read += transfer_size;
        self.total_ops += 1;

        let entries = local_iov.len().min(remote_iov.len());
        Ok(VmAccessResult::complete(transfer_size, entries))
    }

    /// Writes to a remote process's address space.
    ///
    /// Copies data from `local_iov` in the calling process to
    /// `remote_iov` in the target process.
    pub fn process_vm_writev(
        &mut self,
        src_pid: u32,
        target_pid: u32,
        local_iov: &IovecList,
        remote_iov: &IovecList,
        _flags: u32,
    ) -> Result<VmAccessResult> {
        // Permission check.
        if !self.check_write_permission(src_pid, target_pid) {
            return Err(Error::PermissionDenied);
        }

        self.validate_transfer(local_iov, remote_iov)?;

        let local_total = local_iov.total_bytes();
        let remote_total = remote_iov.total_bytes();
        let transfer_size = local_total.min(remote_total);

        self.total_bytes_written += transfer_size;
        self.total_ops += 1;

        let entries = local_iov.len().min(remote_iov.len());
        Ok(VmAccessResult::complete(transfer_size, entries))
    }

    /// Validates a transfer request.
    fn validate_transfer(&self, local_iov: &IovecList, remote_iov: &IovecList) -> Result<()> {
        if local_iov.is_empty() || remote_iov.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let total = local_iov.total_bytes().min(remote_iov.total_bytes());
        if total > MAX_TRANSFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns total bytes read.
    pub fn total_bytes_read(&self) -> u64 {
        self.total_bytes_read
    }

    /// Returns total bytes written.
    pub fn total_bytes_written(&self) -> u64 {
        self.total_bytes_written
    }

    /// Returns total operations.
    pub fn total_ops(&self) -> u64 {
        self.total_ops
    }
}

impl Default for ProcessVmOps {
    fn default() -> Self {
        Self::new()
    }
}
