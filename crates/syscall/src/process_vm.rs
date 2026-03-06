// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `process_vm_readv(2)` and `process_vm_writev(2)` syscall handlers.
//!
//! These syscalls perform a direct cross-process memory transfer without going
//! through a pipe or ptrace.  They are primarily used by debuggers and profilers
//! to read/write another process's address space efficiently.
//!
//! # Transfer model
//!
//! ```text
//! process_vm_readv(pid, local_iov[], liovcnt, remote_iov[], riovcnt, flags)
//!   → reads from remote process's memory at remote_iov[]
//!     into the calling process's buffers at local_iov[]
//!
//! process_vm_writev(pid, local_iov[], liovcnt, remote_iov[], riovcnt, flags)
//!   → writes from local_iov[] into remote process's memory at remote_iov[]
//! ```
//!
//! Scatter/gather: local and remote iovec arrays are traversed in parallel.
//! Transfer stops at the shorter of the two total lengths.
//!
//! # Partial transfer semantics
//!
//! If a fault occurs mid-transfer, the number of bytes successfully transferred
//! so far is returned (not an error), matching Linux semantics.  Only when zero
//! bytes can be transferred before a fault does the call return `EFAULT`.
//!
//! # References
//!
//! - Linux: `mm/process_vm_access.c`, `include/linux/mm.h`
//! - man: `process_vm_readv(2)`, `process_vm_writev(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of iovec elements per call (`IOV_MAX`, POSIX `UIO_MAXIOV`).
pub const PROCESS_VM_IOV_MAX: usize = 1024;

/// Maximum total transfer size per call (128 MiB — matches Linux).
pub const PROCESS_VM_MAX_BYTES: u64 = 128 * 1024 * 1024;

// ---------------------------------------------------------------------------
// IoVec — local scatter/gather element
// ---------------------------------------------------------------------------

/// A local (caller's address space) I/O vector element.
///
/// Layout matches `struct iovec` from POSIX `<sys/uio.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoVec {
    /// Base address in the caller's address space.
    pub iov_base: u64,
    /// Length in bytes.
    pub iov_len: u64,
}

impl IoVec {
    /// Construct a new `IoVec`.
    pub const fn new(base: u64, len: u64) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Return `true` if this iovec has zero length.
    pub const fn is_empty(&self) -> bool {
        self.iov_len == 0
    }

    /// Validate that `iov_base + iov_len` does not overflow and the address
    /// is not null (for non-empty iovecs).
    pub fn validate(&self) -> Result<()> {
        if self.iov_len == 0 {
            return Ok(());
        }
        if self.iov_base == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for address-space overflow.
        self.iov_base
            .checked_add(self.iov_len)
            .ok_or(Error::InvalidArgument)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RemoteIoVec — remote scatter/gather element
// ---------------------------------------------------------------------------

/// A remote (target process) I/O vector element.
///
/// Semantically identical to [`IoVec`] but typed separately so that callers
/// cannot mix local and remote addresses accidentally.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoteIoVec {
    /// Base address in the remote process's address space.
    pub iov_base: u64,
    /// Length in bytes.
    pub iov_len: u64,
}

impl RemoteIoVec {
    /// Construct a new `RemoteIoVec`.
    pub const fn new(base: u64, len: u64) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Return `true` if this iovec has zero length.
    pub const fn is_empty(&self) -> bool {
        self.iov_len == 0
    }

    /// Validate that `iov_base + iov_len` does not overflow.
    pub fn validate(&self) -> Result<()> {
        if self.iov_len == 0 {
            return Ok(());
        }
        if self.iov_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.iov_base
            .checked_add(self.iov_len)
            .ok_or(Error::InvalidArgument)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Credentials / permission model
// ---------------------------------------------------------------------------

/// Minimal credential set for permission checks.
#[derive(Debug, Clone, Copy)]
pub struct Creds {
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Whether the process has `CAP_SYS_PTRACE`.
    pub cap_ptrace: bool,
}

impl Creds {
    /// Construct credentials for a root process.
    pub const fn root() -> Self {
        Self {
            euid: 0,
            egid: 0,
            cap_ptrace: true,
        }
    }

    /// Construct credentials for an unprivileged process.
    pub const fn user(euid: u32, egid: u32) -> Self {
        Self {
            euid,
            egid,
            cap_ptrace: false,
        }
    }
}

/// A minimal process descriptor in the stub registry.
#[derive(Debug, Clone, Copy)]
pub struct ProcDesc {
    /// Process ID.
    pub pid: u32,
    /// Owner effective UID.
    pub euid: u32,
    /// Owner effective GID.
    pub egid: u32,
    /// Whether this process has exited.
    pub exited: bool,
}

impl ProcDesc {
    /// Construct a live process descriptor.
    pub const fn new(pid: u32, euid: u32, egid: u32) -> Self {
        Self {
            pid,
            euid,
            egid,
            exited: false,
        }
    }
}

/// Maximum entries in the stub process registry.
pub const PROC_REG_SIZE: usize = 32;

/// Stub process registry for PID lookup.
pub struct ProcReg {
    entries: [Option<ProcDesc>; PROC_REG_SIZE],
}

impl ProcReg {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; PROC_REG_SIZE],
        }
    }

    /// Register a process.
    pub fn register(&mut self, desc: ProcDesc) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(desc);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a process by PID.
    pub fn find(&self, pid: u32) -> Option<&ProcDesc> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|p| p.pid == pid))
    }
}

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Check whether `caller` may access the memory of `target`.
///
/// Mirrors Linux `process_vm_access_permission` / `ptrace_may_access`:
/// - Root (`euid == 0`) or `CAP_SYS_PTRACE` → always permitted.
/// - Same UID/GID → permitted.
/// - Different UID/GID → denied.
///
/// Returns `Err(PermissionDenied)` if access is not allowed,
/// `Err(NotFound)` if the process does not exist,
/// `Err(InvalidArgument)` if the process has already exited.
pub fn check_permission(caller: &Creds, target: &ProcDesc) -> Result<()> {
    if target.exited {
        return Err(Error::InvalidArgument);
    }
    if caller.euid == 0 || caller.cap_ptrace {
        return Ok(());
    }
    if caller.euid == target.euid && caller.egid == target.egid {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// Iovec validation helpers
// ---------------------------------------------------------------------------

/// Validate a slice of local iovecs.
///
/// * `count > PROCESS_VM_IOV_MAX` → `EINVAL`
/// * Any individual iovec fails [`IoVec::validate`] → `EINVAL`
/// * Total length overflow → `EINVAL`
pub fn validate_local_iov(iov: &[IoVec]) -> Result<u64> {
    if iov.len() > PROCESS_VM_IOV_MAX {
        return Err(Error::InvalidArgument);
    }
    let mut total: u64 = 0;
    for v in iov {
        v.validate()?;
        total = total.checked_add(v.iov_len).ok_or(Error::InvalidArgument)?;
    }
    Ok(total)
}

/// Validate a slice of remote iovecs.
///
/// * `count > PROCESS_VM_IOV_MAX` → `EINVAL`
/// * Any individual iovec fails [`RemoteIoVec::validate`] → `EINVAL`
/// * Total length overflow → `EINVAL`
pub fn validate_remote_iov(iov: &[RemoteIoVec]) -> Result<u64> {
    if iov.len() > PROCESS_VM_IOV_MAX {
        return Err(Error::InvalidArgument);
    }
    let mut total: u64 = 0;
    for v in iov {
        v.validate()?;
        total = total.checked_add(v.iov_len).ok_or(Error::InvalidArgument)?;
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Transfer simulation
// ---------------------------------------------------------------------------

/// Simulates one cross-process memory segment copy.
///
/// In a real kernel this would:
///   1. Pin the remote pages with `get_user_pages`.
///   2. `memcpy` from/to a kmap'd page.
///   3. Unpin pages.
///
/// Here we model success for well-formed addresses and inject faults for
/// addresses in the "fault zone" (`0xDEAD_xxxx_xxxx`).
fn simulate_copy(dst_addr: u64, src_addr: u64, len: u64) -> Result<u64> {
    if len == 0 {
        return Ok(0);
    }
    // Fault injection: addresses in the 0xDEAD_0000_0000 range fault.
    if src_addr >> 32 == 0xDEAD || dst_addr >> 32 == 0xDEAD {
        return Err(Error::IoError);
    }
    Ok(len)
}

/// Outcome of a cross-process scatter/gather transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferResult {
    /// Total bytes successfully transferred.
    pub bytes: u64,
    /// Whether a fault stopped the transfer early.
    pub partial: bool,
}

/// Perform a scatter/gather transfer between two iovec arrays.
///
/// Traverses `src_iov` and `dst_iov` in parallel, advancing through both
/// arrays segment by segment.  Stops at the shorter of the two total
/// lengths.  On a simulated fault, returns the bytes transferred so far
/// (partial transfer semantics matching Linux).
fn do_transfer(
    src_iov: &[(u64, u64)], // (base, len) pairs
    dst_iov: &[(u64, u64)],
) -> TransferResult {
    let mut src_idx = 0usize;
    let mut dst_idx = 0usize;
    let mut src_off = 0u64;
    let mut dst_off = 0u64;
    let mut total = 0u64;

    loop {
        // Advance past exhausted entries.
        while src_idx < src_iov.len() && src_off >= src_iov[src_idx].1 {
            src_idx += 1;
            src_off = 0;
        }
        while dst_idx < dst_iov.len() && dst_off >= dst_iov[dst_idx].1 {
            dst_idx += 1;
            dst_off = 0;
        }

        if src_idx >= src_iov.len() || dst_idx >= dst_iov.len() {
            break;
        }

        let src_rem = src_iov[src_idx].1 - src_off;
        let dst_rem = dst_iov[dst_idx].1 - dst_off;
        let chunk = src_rem.min(dst_rem);

        let src_addr = src_iov[src_idx].0 + src_off;
        let dst_addr = dst_iov[dst_idx].0 + dst_off;

        match simulate_copy(dst_addr, src_addr, chunk) {
            Ok(copied) => {
                total += copied;
                src_off += copied;
                dst_off += copied;
            }
            Err(_) => {
                return TransferResult {
                    bytes: total,
                    partial: true,
                };
            }
        }
    }

    TransferResult {
        bytes: total,
        partial: false,
    }
}

// ---------------------------------------------------------------------------
// do_process_vm_readv
// ---------------------------------------------------------------------------

/// Handler for `process_vm_readv(2)`.
///
/// Reads from the address space of process `pid` into the calling process's
/// buffers.  The remote regions are described by `rvec` and the local
/// destination buffers by `lvec`.
///
/// # Arguments
///
/// * `reg`    — Process registry for PID validation.
/// * `caller` — Credentials of the calling process.
/// * `pid`    — Target process PID.
/// * `lvec`   — Local destination iovecs.
/// * `rvec`   — Remote source iovecs.
/// * `flags`  — Must be 0 (reserved).
///
/// # Returns
///
/// Number of bytes read on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags, iovec count > `IOV_MAX`,
///                                 overflow, null base, or process exited.
/// * [`Error::NotFound`]         — No process with `pid`.
/// * [`Error::PermissionDenied`] — Caller lacks permission.
/// * [`Error::IoError`]          — Fault in remote address space (no bytes).
///
/// # Partial transfer
///
/// If a fault occurs after some bytes have been transferred, the number
/// successfully transferred is returned (not an error).  Only when the
/// very first copy fails is `EFAULT` returned.
///
/// # Linux conformance
///
/// - `flags` must be 0 (reserved for future use).
/// - Empty iovecs are silently skipped.
/// - `pid` == calling process PID is allowed (reads own memory).
pub fn do_process_vm_readv(
    reg: &ProcReg,
    caller: &Creds,
    pid: u32,
    lvec: &[IoVec],
    rvec: &[RemoteIoVec],
    flags: u32,
) -> Result<u64> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate iovec arrays.
    let _local_total = validate_local_iov(lvec)?;
    let _remote_total = validate_remote_iov(rvec)?;

    // Validate total transfer size.
    let total_len = _local_total.min(_remote_total);
    if total_len > PROCESS_VM_MAX_BYTES {
        return Err(Error::InvalidArgument);
    }

    // Permission check.
    let target = reg.find(pid).ok_or(Error::NotFound)?;
    check_permission(caller, target)?;

    // Build (base, len) pairs for the transfer engine.
    let src: alloc::vec::Vec<(u64, u64)> = rvec.iter().map(|v| (v.iov_base, v.iov_len)).collect();
    let dst: alloc::vec::Vec<(u64, u64)> = lvec.iter().map(|v| (v.iov_base, v.iov_len)).collect();

    let result = do_transfer(&src, &dst);

    if result.bytes == 0 && result.partial {
        return Err(Error::IoError);
    }
    Ok(result.bytes)
}

// ---------------------------------------------------------------------------
// do_process_vm_writev
// ---------------------------------------------------------------------------

/// Handler for `process_vm_writev(2)`.
///
/// Writes from the calling process's buffers into the address space of
/// process `pid`.  The local sources are described by `lvec` and the
/// remote destinations by `rvec`.
///
/// # Arguments
///
/// * `reg`    — Process registry for PID validation.
/// * `caller` — Credentials of the calling process.
/// * `pid`    — Target process PID.
/// * `lvec`   — Local source iovecs.
/// * `rvec`   — Remote destination iovecs.
/// * `flags`  — Must be 0 (reserved).
///
/// # Returns
///
/// Number of bytes written on success.
///
/// # Errors
///
/// Same as [`do_process_vm_readv`] but faults are in the remote
/// *destination* rather than source.
pub fn do_process_vm_writev(
    reg: &ProcReg,
    caller: &Creds,
    pid: u32,
    lvec: &[IoVec],
    rvec: &[RemoteIoVec],
    flags: u32,
) -> Result<u64> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    let _local_total = validate_local_iov(lvec)?;
    let _remote_total = validate_remote_iov(rvec)?;

    let total_len = _local_total.min(_remote_total);
    if total_len > PROCESS_VM_MAX_BYTES {
        return Err(Error::InvalidArgument);
    }

    let target = reg.find(pid).ok_or(Error::NotFound)?;
    check_permission(caller, target)?;

    // For write: src = local, dst = remote.
    let src: alloc::vec::Vec<(u64, u64)> = lvec.iter().map(|v| (v.iov_base, v.iov_len)).collect();
    let dst: alloc::vec::Vec<(u64, u64)> = rvec.iter().map(|v| (v.iov_base, v.iov_len)).collect();

    let result = do_transfer(&src, &dst);

    if result.bytes == 0 && result.partial {
        return Err(Error::IoError);
    }
    Ok(result.bytes)
}

extern crate alloc;

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with(pid: u32, euid: u32) -> ProcReg {
        let mut r = ProcReg::new();
        r.register(ProcDesc::new(pid, euid, euid)).unwrap();
        r
    }

    fn local(base: u64, len: u64) -> IoVec {
        IoVec::new(base, len)
    }
    fn remote(base: u64, len: u64) -> RemoteIoVec {
        RemoteIoVec::new(base, len)
    }

    // --- IoVec validation ---

    #[test]
    fn iovec_validate_ok() {
        assert_eq!(IoVec::new(0x1000, 64).validate(), Ok(()));
    }

    #[test]
    fn iovec_validate_zero_len_ok() {
        assert_eq!(IoVec::new(0, 0).validate(), Ok(()));
    }

    #[test]
    fn iovec_validate_null_base_nonzero_len_fails() {
        assert_eq!(IoVec::new(0, 64).validate(), Err(Error::InvalidArgument));
    }

    #[test]
    fn iovec_validate_overflow_fails() {
        assert_eq!(
            IoVec::new(u64::MAX, 1).validate(),
            Err(Error::InvalidArgument)
        );
    }

    // --- RemoteIoVec validation ---

    #[test]
    fn remote_iovec_validate_ok() {
        assert_eq!(RemoteIoVec::new(0x2000, 128).validate(), Ok(()));
    }

    #[test]
    fn remote_iovec_null_base_fails() {
        assert_eq!(
            RemoteIoVec::new(0, 4).validate(),
            Err(Error::InvalidArgument)
        );
    }

    // --- validate_local_iov ---

    #[test]
    fn too_many_iovecs_rejected() {
        let big: alloc::vec::Vec<IoVec> = (0..=PROCESS_VM_IOV_MAX)
            .map(|i| IoVec::new(0x1000 + i as u64, 1))
            .collect();
        assert_eq!(validate_local_iov(&big), Err(Error::InvalidArgument));
    }

    // --- check_permission ---

    #[test]
    fn root_can_access_any() {
        let target = ProcDesc::new(100, 500, 500);
        assert_eq!(check_permission(&Creds::root(), &target), Ok(()));
    }

    #[test]
    fn cap_ptrace_can_access_any() {
        let caller = Creds {
            euid: 1000,
            egid: 1000,
            cap_ptrace: true,
        };
        let target = ProcDesc::new(100, 500, 500);
        assert_eq!(check_permission(&caller, &target), Ok(()));
    }

    #[test]
    fn same_uid_gid_allowed() {
        let caller = Creds::user(500, 500);
        let target = ProcDesc::new(100, 500, 500);
        assert_eq!(check_permission(&caller, &target), Ok(()));
    }

    #[test]
    fn different_uid_denied() {
        let caller = Creds::user(999, 999);
        let target = ProcDesc::new(100, 500, 500);
        assert_eq!(
            check_permission(&caller, &target),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn exited_process_denied() {
        let mut target = ProcDesc::new(100, 500, 500);
        target.exited = true;
        assert_eq!(
            check_permission(&Creds::user(500, 500), &target),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_process_vm_readv ---

    #[test]
    fn readv_basic_success() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x1000, 256)];
        let rvec = [remote(0x2000, 256)];
        let n = do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 256);
    }

    #[test]
    fn readv_nonzero_flags_rejected() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        assert_eq!(
            do_process_vm_readv(&r, &caller, 200, &[], &[], 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn readv_unknown_pid_fails() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x1000, 64)];
        let rvec = [remote(0x2000, 64)];
        assert_eq!(
            do_process_vm_readv(&r, &caller, 999, &lvec, &rvec, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn readv_permission_denied() {
        let r = reg_with(200, 500);
        let caller = Creds::user(999, 999);
        let lvec = [local(0x1000, 64)];
        let rvec = [remote(0x2000, 64)];
        assert_eq!(
            do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn readv_partial_transfer_on_fault() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        // First segment is fine, second triggers fault (0xDEAD... address).
        let lvec = [local(0x1000, 64), local(0x2000, 64)];
        let rvec = [remote(0x3000, 64), remote(0xDEAD_0000_1000, 64)];
        let n = do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 64); // only first segment copied
    }

    #[test]
    fn readv_immediate_fault_returns_efault() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x1000, 64)];
        let rvec = [remote(0xDEAD_0000_1000, 64)]; // fault immediately
        assert_eq!(
            do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0),
            Err(Error::IoError)
        );
    }

    #[test]
    fn readv_shorter_local_limits_transfer() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        // Local has 64 bytes, remote has 256 — transfer limited to 64.
        let lvec = [local(0x1000, 64)];
        let rvec = [remote(0x2000, 256)];
        let n = do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 64);
    }

    #[test]
    fn readv_scatter_gather_multiple_segments() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x1000, 100), local(0x2000, 100)];
        let rvec = [remote(0x3000, 100), remote(0x4000, 100)];
        let n = do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 200);
    }

    #[test]
    fn readv_empty_iovecs_ok() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        let n = do_process_vm_readv(&r, &caller, 200, &[], &[], 0).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn readv_null_base_in_local_rejected() {
        let r = reg_with(200, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0, 64)]; // null base
        let rvec = [remote(0x1000, 64)];
        assert_eq!(
            do_process_vm_readv(&r, &caller, 200, &lvec, &rvec, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_process_vm_writev ---

    #[test]
    fn writev_basic_success() {
        let r = reg_with(300, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x5000, 128)];
        let rvec = [remote(0x6000, 128)];
        let n = do_process_vm_writev(&r, &caller, 300, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 128);
    }

    #[test]
    fn writev_flags_nonzero_rejected() {
        let r = reg_with(300, 500);
        let caller = Creds::user(500, 500);
        assert_eq!(
            do_process_vm_writev(&r, &caller, 300, &[], &[], 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn writev_fault_in_remote_dest() {
        let r = reg_with(300, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x5000, 64)];
        let rvec = [remote(0xDEAD_0000_2000, 64)]; // fault destination
        assert_eq!(
            do_process_vm_writev(&r, &caller, 300, &lvec, &rvec, 0),
            Err(Error::IoError)
        );
    }

    #[test]
    fn writev_partial_write() {
        let r = reg_with(300, 500);
        let caller = Creds::user(500, 500);
        let lvec = [local(0x5000, 64), local(0x6000, 64)];
        let rvec = [remote(0x7000, 64), remote(0xDEAD_0001_0000, 64)];
        let n = do_process_vm_writev(&r, &caller, 300, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 64);
    }

    #[test]
    fn writev_root_can_write_any_process() {
        let r = reg_with(400, 1000);
        let caller = Creds::root();
        let lvec = [local(0x1000, 32)];
        let rvec = [remote(0x2000, 32)];
        let n = do_process_vm_writev(&r, &caller, 400, &lvec, &rvec, 0).unwrap();
        assert_eq!(n, 32);
    }

    // --- do_transfer edge cases ---

    #[test]
    fn transfer_unequal_segment_sizes() {
        // local: [200], remote: [100, 100]
        // transfer should yield 200 total.
        let src = [(0x1000u64, 200u64)];
        let dst = [(0x3000u64, 100u64), (0x4000u64, 100u64)];
        let r = do_transfer(&src, &dst);
        assert_eq!(r.bytes, 200);
        assert!(!r.partial);
    }

    #[test]
    fn transfer_empty_src() {
        let r = do_transfer(&[], &[(0x1000, 64)]);
        assert_eq!(r.bytes, 0);
    }
}
