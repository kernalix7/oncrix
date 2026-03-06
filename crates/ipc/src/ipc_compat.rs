// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC compatibility layer — 32-bit/64-bit and cross-version IPC structure
//! translation.
//!
//! On a 64-bit kernel running 32-bit user-space processes (e.g., x86 compat on
//! x86_64) the IPC data structures have different sizes and alignment.  This
//! module provides conversion functions between the 32-bit and 64-bit wire
//! layouts so the kernel can accept syscalls from both ABI variants.
//!
//! # Structures covered
//!
//! | Object         | 32-bit struct         | 64-bit struct         |
//! |----------------|-----------------------|-----------------------|
//! | IPC permission | [`IpcPerm32`]         | [`IpcPerm64`]         |
//! | Shared memory  | [`IpcCompat32Shmid`]  | [`IpcCompat64Shmid`]  |
//! | Semaphore set  | [`IpcCompat32Semid`]  | [`IpcCompat64Semid`]  |
//! | Message queue  | [`IpcCompat32Msqid`]  | [`IpcCompat64Msqid`]  |
//!
//! # ABI variants
//!
//! [`IpcAbi`] distinguishes between the two calling conventions.  The
//! [`IpcCompatSubsystem`] selects the appropriate conversion path.
//!
//! # Reference
//!
//! Linux: `ipc/compat.c`, `include/uapi/linux/compat.h`.
//! POSIX IPC spec: `.TheOpenGroup/susv5-html/functions/shmctl.html`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// IpcAbi — ABI selector
// ---------------------------------------------------------------------------

/// The ABI variant of a syscall originating process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcAbi {
    /// 32-bit compatibility ABI (e.g., x86 compat on x86_64).
    Compat32,
    /// Native 64-bit ABI.
    Native64,
}

// ---------------------------------------------------------------------------
// IpcPerm32 / IpcPerm64
// ---------------------------------------------------------------------------

/// 32-bit IPC permission structure.
///
/// Matches the Linux `compat_ipc_perm` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcPerm32 {
    /// IPC key.
    pub key: u32,
    /// Owner UID (16-bit in 32-bit ABI).
    pub uid: u16,
    /// Owner GID (16-bit in 32-bit ABI).
    pub gid: u16,
    /// Creator UID (16-bit in 32-bit ABI).
    pub cuid: u16,
    /// Creator GID (16-bit in 32-bit ABI).
    pub cgid: u16,
    /// Permission mode bits.
    pub mode: u16,
    /// Padding.
    pub _pad: u16,
}

impl IpcPerm32 {
    /// Construct a new 32-bit permission structure.
    pub const fn new(key: u32, uid: u16, gid: u16, cuid: u16, cgid: u16, mode: u16) -> Self {
        Self {
            key,
            uid,
            gid,
            cuid,
            cgid,
            mode,
            _pad: 0,
        }
    }
}

/// 64-bit IPC permission structure.
///
/// Matches the Linux `ipc64_perm` / POSIX `ipc_perm` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcPerm64 {
    /// IPC key.
    pub key: u32,
    /// Owner UID (32-bit).
    pub uid: u32,
    /// Owner GID (32-bit).
    pub gid: u32,
    /// Creator UID (32-bit).
    pub cuid: u32,
    /// Creator GID (32-bit).
    pub cgid: u32,
    /// Permission mode bits (32-bit).
    pub mode: u32,
    /// Padding to match kernel struct layout.
    pub _pad: [u32; 2],
}

impl IpcPerm64 {
    /// Construct a new 64-bit permission structure.
    pub const fn new(key: u32, uid: u32, gid: u32, cuid: u32, cgid: u32, mode: u32) -> Self {
        Self {
            key,
            uid,
            gid,
            cuid,
            cgid,
            mode,
            _pad: [0u32; 2],
        }
    }
}

// ---------------------------------------------------------------------------
// Perm conversion
// ---------------------------------------------------------------------------

/// Convert a 32-bit IPC permission to 64-bit.
///
/// UID/GID fields are zero-extended from `u16` to `u32`.
pub fn ipc_perm_32_to_64(p32: &IpcPerm32) -> IpcPerm64 {
    IpcPerm64::new(
        p32.key,
        p32.uid as u32,
        p32.gid as u32,
        p32.cuid as u32,
        p32.cgid as u32,
        p32.mode as u32,
    )
}

/// Convert a 64-bit IPC permission to 32-bit.
///
/// UID/GID fields are truncated to `u16`.  Returns `InvalidArgument` if any
/// UID/GID value exceeds `u16::MAX` (cannot be represented in 32-bit ABI).
pub fn ipc_perm_64_to_32(p64: &IpcPerm64) -> Result<IpcPerm32> {
    let uid = u16::try_from(p64.uid).map_err(|_| Error::InvalidArgument)?;
    let gid = u16::try_from(p64.gid).map_err(|_| Error::InvalidArgument)?;
    let cuid = u16::try_from(p64.cuid).map_err(|_| Error::InvalidArgument)?;
    let cgid = u16::try_from(p64.cgid).map_err(|_| Error::InvalidArgument)?;
    Ok(IpcPerm32::new(
        p64.key,
        uid,
        gid,
        cuid,
        cgid,
        p64.mode as u16,
    ))
}

// ---------------------------------------------------------------------------
// IpcCompat32Shmid / IpcCompat64Shmid
// ---------------------------------------------------------------------------

/// 32-bit `shmid_ds` compatibility structure.
///
/// Matches the Linux `compat_shmid_ds` layout used for 32-bit processes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCompat32Shmid {
    /// IPC permission structure (32-bit).
    pub shm_perm: IpcPerm32,
    /// Segment size in bytes (32-bit).
    pub shm_segsz: u32,
    /// Last attach time (32-bit timestamp).
    pub shm_atime: u32,
    /// Last detach time (32-bit timestamp).
    pub shm_dtime: u32,
    /// Last change time (32-bit timestamp).
    pub shm_ctime: u32,
    /// PID of creator.
    pub shm_cpid: u32,
    /// PID of last operator.
    pub shm_lpid: u32,
    /// Number of current attaches.
    pub shm_nattch: u32,
}

impl IpcCompat32Shmid {
    /// Construct a new 32-bit shmid_ds.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        perm: IpcPerm32,
        segsz: u32,
        atime: u32,
        dtime: u32,
        ctime: u32,
        cpid: u32,
        lpid: u32,
        nattch: u32,
    ) -> Self {
        Self {
            shm_perm: perm,
            shm_segsz: segsz,
            shm_atime: atime,
            shm_dtime: dtime,
            shm_ctime: ctime,
            shm_cpid: cpid,
            shm_lpid: lpid,
            shm_nattch: nattch,
        }
    }
}

/// 64-bit `shmid_ds` structure.
///
/// Matches the Linux `shmid_ds` / POSIX `struct shmid_ds` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCompat64Shmid {
    /// IPC permission structure (64-bit).
    pub shm_perm: IpcPerm64,
    /// Segment size in bytes (64-bit).
    pub shm_segsz: u64,
    /// Last attach time (64-bit timestamp).
    pub shm_atime: u64,
    /// Last detach time (64-bit timestamp).
    pub shm_dtime: u64,
    /// Last change time (64-bit timestamp).
    pub shm_ctime: u64,
    /// PID of creator.
    pub shm_cpid: u32,
    /// PID of last operator.
    pub shm_lpid: u32,
    /// Number of current attaches.
    pub shm_nattch: u64,
    /// Padding.
    pub _pad: [u64; 2],
}

impl IpcCompat64Shmid {
    /// Construct a new 64-bit shmid_ds.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        perm: IpcPerm64,
        segsz: u64,
        atime: u64,
        dtime: u64,
        ctime: u64,
        cpid: u32,
        lpid: u32,
        nattch: u64,
    ) -> Self {
        Self {
            shm_perm: perm,
            shm_segsz: segsz,
            shm_atime: atime,
            shm_dtime: dtime,
            shm_ctime: ctime,
            shm_cpid: cpid,
            shm_lpid: lpid,
            shm_nattch: nattch,
            _pad: [0u64; 2],
        }
    }
}

// ---------------------------------------------------------------------------
// Shmid conversion
// ---------------------------------------------------------------------------

/// Convert a 32-bit `shmid_ds` to 64-bit.
pub fn shmid_ds_32_to_64(ds32: &IpcCompat32Shmid) -> IpcCompat64Shmid {
    IpcCompat64Shmid::new(
        ipc_perm_32_to_64(&ds32.shm_perm),
        ds32.shm_segsz as u64,
        ds32.shm_atime as u64,
        ds32.shm_dtime as u64,
        ds32.shm_ctime as u64,
        ds32.shm_cpid,
        ds32.shm_lpid,
        ds32.shm_nattch as u64,
    )
}

/// Convert a 64-bit `shmid_ds` to 32-bit.
///
/// Returns `InvalidArgument` if any 64-bit value exceeds 32-bit range.
pub fn shmid_ds_64_to_32(ds64: &IpcCompat64Shmid) -> Result<IpcCompat32Shmid> {
    let perm32 = ipc_perm_64_to_32(&ds64.shm_perm)?;
    let segsz = u32::try_from(ds64.shm_segsz).map_err(|_| Error::InvalidArgument)?;
    let atime = u32::try_from(ds64.shm_atime).map_err(|_| Error::InvalidArgument)?;
    let dtime = u32::try_from(ds64.shm_dtime).map_err(|_| Error::InvalidArgument)?;
    let ctime = u32::try_from(ds64.shm_ctime).map_err(|_| Error::InvalidArgument)?;
    let nattch = u32::try_from(ds64.shm_nattch).map_err(|_| Error::InvalidArgument)?;
    Ok(IpcCompat32Shmid::new(
        perm32,
        segsz,
        atime,
        dtime,
        ctime,
        ds64.shm_cpid,
        ds64.shm_lpid,
        nattch,
    ))
}

// ---------------------------------------------------------------------------
// IpcCompat32Semid / IpcCompat64Semid
// ---------------------------------------------------------------------------

/// 32-bit `semid_ds` compatibility structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCompat32Semid {
    /// IPC permission structure (32-bit).
    pub sem_perm: IpcPerm32,
    /// Last semop time (32-bit).
    pub sem_otime: u32,
    /// Last change time (32-bit).
    pub sem_ctime: u32,
    /// Number of semaphores in set.
    pub sem_nsems: u32,
}

impl IpcCompat32Semid {
    /// Construct a new 32-bit semid_ds.
    pub const fn new(perm: IpcPerm32, otime: u32, ctime: u32, nsems: u32) -> Self {
        Self {
            sem_perm: perm,
            sem_otime: otime,
            sem_ctime: ctime,
            sem_nsems: nsems,
        }
    }
}

/// 64-bit `semid_ds` structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCompat64Semid {
    /// IPC permission structure (64-bit).
    pub sem_perm: IpcPerm64,
    /// Last semop time (64-bit).
    pub sem_otime: u64,
    /// Last change time (64-bit).
    pub sem_ctime: u64,
    /// Number of semaphores in set (64-bit).
    pub sem_nsems: u64,
    /// Padding.
    pub _pad: [u64; 2],
}

impl IpcCompat64Semid {
    /// Construct a new 64-bit semid_ds.
    pub const fn new(perm: IpcPerm64, otime: u64, ctime: u64, nsems: u64) -> Self {
        Self {
            sem_perm: perm,
            sem_otime: otime,
            sem_ctime: ctime,
            sem_nsems: nsems,
            _pad: [0; 2],
        }
    }
}

// ---------------------------------------------------------------------------
// Semid conversion
// ---------------------------------------------------------------------------

/// Convert a 32-bit `semid_ds` to 64-bit.
pub fn semid_ds_32_to_64(ds32: &IpcCompat32Semid) -> IpcCompat64Semid {
    IpcCompat64Semid::new(
        ipc_perm_32_to_64(&ds32.sem_perm),
        ds32.sem_otime as u64,
        ds32.sem_ctime as u64,
        ds32.sem_nsems as u64,
    )
}

/// Convert a 64-bit `semid_ds` to 32-bit.
///
/// Returns `InvalidArgument` if any value exceeds 32-bit range.
pub fn semid_ds_64_to_32(ds64: &IpcCompat64Semid) -> Result<IpcCompat32Semid> {
    let perm32 = ipc_perm_64_to_32(&ds64.sem_perm)?;
    let otime = u32::try_from(ds64.sem_otime).map_err(|_| Error::InvalidArgument)?;
    let ctime = u32::try_from(ds64.sem_ctime).map_err(|_| Error::InvalidArgument)?;
    let nsems = u32::try_from(ds64.sem_nsems).map_err(|_| Error::InvalidArgument)?;
    Ok(IpcCompat32Semid::new(perm32, otime, ctime, nsems))
}

// ---------------------------------------------------------------------------
// IpcCompat32Msqid / IpcCompat64Msqid
// ---------------------------------------------------------------------------

/// 32-bit `msqid_ds` compatibility structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCompat32Msqid {
    /// IPC permission structure (32-bit).
    pub msg_perm: IpcPerm32,
    /// Last msgsnd time (32-bit).
    pub msg_stime: u32,
    /// Last msgrcv time (32-bit).
    pub msg_rtime: u32,
    /// Last change time (32-bit).
    pub msg_ctime: u32,
    /// Number of bytes in queue.
    pub msg_cbytes: u32,
    /// Number of messages in queue.
    pub msg_qnum: u32,
    /// Maximum bytes in queue.
    pub msg_qbytes: u32,
    /// PID of last msgsnd.
    pub msg_lspid: u32,
    /// PID of last msgrcv.
    pub msg_lrpid: u32,
}

impl IpcCompat32Msqid {
    /// Construct a new 32-bit msqid_ds.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        perm: IpcPerm32,
        stime: u32,
        rtime: u32,
        ctime: u32,
        cbytes: u32,
        qnum: u32,
        qbytes: u32,
        lspid: u32,
        lrpid: u32,
    ) -> Self {
        Self {
            msg_perm: perm,
            msg_stime: stime,
            msg_rtime: rtime,
            msg_ctime: ctime,
            msg_cbytes: cbytes,
            msg_qnum: qnum,
            msg_qbytes: qbytes,
            msg_lspid: lspid,
            msg_lrpid: lrpid,
        }
    }
}

/// 64-bit `msqid_ds` structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCompat64Msqid {
    /// IPC permission structure (64-bit).
    pub msg_perm: IpcPerm64,
    /// Last msgsnd time (64-bit).
    pub msg_stime: u64,
    /// Last msgrcv time (64-bit).
    pub msg_rtime: u64,
    /// Last change time (64-bit).
    pub msg_ctime: u64,
    /// Number of bytes in queue (64-bit).
    pub msg_cbytes: u64,
    /// Number of messages in queue (64-bit).
    pub msg_qnum: u64,
    /// Maximum bytes in queue (64-bit).
    pub msg_qbytes: u64,
    /// PID of last msgsnd.
    pub msg_lspid: u32,
    /// PID of last msgrcv.
    pub msg_lrpid: u32,
    /// Padding.
    pub _pad: [u64; 2],
}

impl IpcCompat64Msqid {
    /// Construct a new 64-bit msqid_ds.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        perm: IpcPerm64,
        stime: u64,
        rtime: u64,
        ctime: u64,
        cbytes: u64,
        qnum: u64,
        qbytes: u64,
        lspid: u32,
        lrpid: u32,
    ) -> Self {
        Self {
            msg_perm: perm,
            msg_stime: stime,
            msg_rtime: rtime,
            msg_ctime: ctime,
            msg_cbytes: cbytes,
            msg_qnum: qnum,
            msg_qbytes: qbytes,
            msg_lspid: lspid,
            msg_lrpid: lrpid,
            _pad: [0u64; 2],
        }
    }
}

// ---------------------------------------------------------------------------
// Msqid conversion
// ---------------------------------------------------------------------------

/// Convert a 32-bit `msqid_ds` to 64-bit.
pub fn msqid_ds_32_to_64(ds32: &IpcCompat32Msqid) -> IpcCompat64Msqid {
    IpcCompat64Msqid::new(
        ipc_perm_32_to_64(&ds32.msg_perm),
        ds32.msg_stime as u64,
        ds32.msg_rtime as u64,
        ds32.msg_ctime as u64,
        ds32.msg_cbytes as u64,
        ds32.msg_qnum as u64,
        ds32.msg_qbytes as u64,
        ds32.msg_lspid,
        ds32.msg_lrpid,
    )
}

/// Convert a 64-bit `msqid_ds` to 32-bit.
///
/// Returns `InvalidArgument` if any value exceeds 32-bit range.
pub fn msqid_ds_64_to_32(ds64: &IpcCompat64Msqid) -> Result<IpcCompat32Msqid> {
    let perm32 = ipc_perm_64_to_32(&ds64.msg_perm)?;
    let stime = u32::try_from(ds64.msg_stime).map_err(|_| Error::InvalidArgument)?;
    let rtime = u32::try_from(ds64.msg_rtime).map_err(|_| Error::InvalidArgument)?;
    let ctime = u32::try_from(ds64.msg_ctime).map_err(|_| Error::InvalidArgument)?;
    let cbytes = u32::try_from(ds64.msg_cbytes).map_err(|_| Error::InvalidArgument)?;
    let qnum = u32::try_from(ds64.msg_qnum).map_err(|_| Error::InvalidArgument)?;
    let qbytes = u32::try_from(ds64.msg_qbytes).map_err(|_| Error::InvalidArgument)?;
    Ok(IpcCompat32Msqid::new(
        perm32,
        stime,
        rtime,
        ctime,
        cbytes,
        qnum,
        qbytes,
        ds64.msg_lspid,
        ds64.msg_lrpid,
    ))
}

// ---------------------------------------------------------------------------
// IpcCompatStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the IPC compatibility layer.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcCompatStats {
    /// Total number of compatibility conversion calls.
    pub compat_calls: u64,
    /// Number of calls that returned a conversion error.
    pub conversion_errors: u64,
}

impl IpcCompatStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            compat_calls: 0,
            conversion_errors: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IpcCompatCall — raw syscall argument bundle
// ---------------------------------------------------------------------------

/// Raw IPC compat syscall argument bundle.
///
/// Represents the raw register arguments passed to a compat IPC syscall.
#[derive(Debug, Clone, Copy)]
pub struct IpcCompatCall {
    /// IPC call number (SHMCTL, SEMCTL, MSGCTL, etc.).
    pub call: u32,
    /// First argument (IPC ID).
    pub first: u32,
    /// Second argument (command or semnum).
    pub second: u32,
    /// Third argument (flags or buf pointer — treated as opaque here).
    pub third: u64,
}

impl IpcCompatCall {
    /// Construct a new raw compat call descriptor.
    pub const fn new(call: u32, first: u32, second: u32, third: u64) -> Self {
        Self {
            call,
            first,
            second,
            third,
        }
    }
}

// ---------------------------------------------------------------------------
// IpcCompatSubsystem
// ---------------------------------------------------------------------------

/// IPC compatibility layer subsystem.
///
/// Translates compat (32-bit) IPC arguments to native (64-bit) form so the
/// kernel's main IPC handlers can process them uniformly.
#[derive(Debug, Default)]
pub struct IpcCompatSubsystem {
    /// Accumulated statistics.
    pub stats: IpcCompatStats,
}

impl IpcCompatSubsystem {
    /// Create a new subsystem.
    pub const fn new() -> Self {
        Self {
            stats: IpcCompatStats::new(),
        }
    }

    /// Convert a compat IPC syscall's raw arguments to native form.
    ///
    /// Currently validates that the `call` number is known and the `first`
    /// argument (IPC ID) is representable.  Actual argument pointer
    /// translation would be handled by the architecture-specific compat
    /// layer; this function models the dispatch and statistics tracking.
    ///
    /// # Arguments
    ///
    /// * `abi`  — The calling ABI (`Compat32` or `Native64`).
    /// * `args` — Raw argument bundle from the syscall trap frame.
    ///
    /// # Returns
    ///
    /// A normalised [`IpcCompatCall`] with arguments in native form.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — Unknown call number.
    pub fn convert_call(&mut self, abi: IpcAbi, args: IpcCompatCall) -> Result<IpcCompatCall> {
        self.stats.compat_calls += 1;

        if abi == IpcAbi::Native64 {
            // No conversion needed for native calls.
            return Ok(args);
        }

        // For Compat32: validate call number and sign-extend if needed.
        // Known call numbers: 1=SEMOP, 2=SEMGET, 3=SEMCTL, 4=MSGSND, 5=MSGRCV,
        //                     6=MSGGET, 7=MSGCTL, 21=SHMAT, 22=SHMDT,
        //                     23=SHMGET, 24=SHMCTL.
        const KNOWN_CALLS: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 21, 22, 23, 24];
        if !KNOWN_CALLS.contains(&args.call) {
            self.stats.conversion_errors += 1;
            return Err(Error::InvalidArgument);
        }

        // In a real kernel: sign-extend `third` from 32-bit compat pointer.
        // Here: pass through unchanged since `third` is already u64.
        Ok(args)
    }

    /// Convert a 32-bit `shmid_ds` to 64-bit and update statistics.
    pub fn compat_shmid_to_native(&mut self, ds32: &IpcCompat32Shmid) -> IpcCompat64Shmid {
        self.stats.compat_calls += 1;
        shmid_ds_32_to_64(ds32)
    }

    /// Convert a 64-bit `shmid_ds` to 32-bit and update statistics.
    pub fn native_shmid_to_compat(&mut self, ds64: &IpcCompat64Shmid) -> Result<IpcCompat32Shmid> {
        self.stats.compat_calls += 1;
        shmid_ds_64_to_32(ds64).map_err(|e| {
            self.stats.conversion_errors += 1;
            e
        })
    }

    /// Convert a 32-bit `semid_ds` to 64-bit and update statistics.
    pub fn compat_semid_to_native(&mut self, ds32: &IpcCompat32Semid) -> IpcCompat64Semid {
        self.stats.compat_calls += 1;
        semid_ds_32_to_64(ds32)
    }

    /// Convert a 64-bit `semid_ds` to 32-bit and update statistics.
    pub fn native_semid_to_compat(&mut self, ds64: &IpcCompat64Semid) -> Result<IpcCompat32Semid> {
        self.stats.compat_calls += 1;
        semid_ds_64_to_32(ds64).map_err(|e| {
            self.stats.conversion_errors += 1;
            e
        })
    }

    /// Convert a 32-bit `msqid_ds` to 64-bit and update statistics.
    pub fn compat_msqid_to_native(&mut self, ds32: &IpcCompat32Msqid) -> IpcCompat64Msqid {
        self.stats.compat_calls += 1;
        msqid_ds_32_to_64(ds32)
    }

    /// Convert a 64-bit `msqid_ds` to 32-bit and update statistics.
    pub fn native_msqid_to_compat(&mut self, ds64: &IpcCompat64Msqid) -> Result<IpcCompat32Msqid> {
        self.stats.compat_calls += 1;
        msqid_ds_64_to_32(ds64).map_err(|e| {
            self.stats.conversion_errors += 1;
            e
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn perm32() -> IpcPerm32 {
        IpcPerm32::new(0x1234, 500, 100, 500, 100, 0o660)
    }

    fn perm64() -> IpcPerm64 {
        IpcPerm64::new(0x1234, 500, 100, 500, 100, 0o660)
    }

    // --- IpcPerm conversion ---

    #[test]
    fn test_perm_32_to_64() {
        let p32 = perm32();
        let p64 = ipc_perm_32_to_64(&p32);
        assert_eq!(p64.key, p32.key);
        assert_eq!(p64.uid, p32.uid as u32);
        assert_eq!(p64.gid, p32.gid as u32);
        assert_eq!(p64.cuid, p32.cuid as u32);
        assert_eq!(p64.cgid, p32.cgid as u32);
        assert_eq!(p64.mode, p32.mode as u32);
    }

    #[test]
    fn test_perm_64_to_32_ok() {
        let p64 = perm64();
        let p32 = ipc_perm_64_to_32(&p64).unwrap();
        assert_eq!(p32.key, p64.key);
        assert_eq!(p32.uid, p64.uid as u16);
    }

    #[test]
    fn test_perm_64_to_32_overflow() {
        let p64 = IpcPerm64::new(0, 0x10000, 0, 0, 0, 0); // uid > u16::MAX
        assert_eq!(ipc_perm_64_to_32(&p64), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_perm_roundtrip_32_64_32() {
        let orig = perm32();
        let p64 = ipc_perm_32_to_64(&orig);
        let p32_back = ipc_perm_64_to_32(&p64).unwrap();
        assert_eq!(orig.key, p32_back.key);
        assert_eq!(orig.uid, p32_back.uid);
        assert_eq!(orig.mode, p32_back.mode);
    }

    // --- Shmid conversion ---

    #[test]
    fn test_shmid_32_to_64() {
        let ds32 = IpcCompat32Shmid::new(perm32(), 65536, 100, 200, 300, 42, 99, 3);
        let ds64 = shmid_ds_32_to_64(&ds32);
        assert_eq!(ds64.shm_segsz, 65536);
        assert_eq!(ds64.shm_atime, 100);
        assert_eq!(ds64.shm_nattch, 3);
    }

    #[test]
    fn test_shmid_64_to_32_ok() {
        let ds64 = IpcCompat64Shmid::new(perm64(), 4096, 10, 20, 30, 1, 2, 5);
        let ds32 = shmid_ds_64_to_32(&ds64).unwrap();
        assert_eq!(ds32.shm_segsz, 4096);
        assert_eq!(ds32.shm_nattch, 5);
    }

    #[test]
    fn test_shmid_64_to_32_overflow_segsz() {
        // segsz > u32::MAX
        let ds64 = IpcCompat64Shmid::new(perm64(), u64::MAX, 0, 0, 0, 0, 0, 0);
        assert_eq!(shmid_ds_64_to_32(&ds64), Err(Error::InvalidArgument));
    }

    // --- Semid conversion ---

    #[test]
    fn test_semid_32_to_64() {
        let ds32 = IpcCompat32Semid::new(perm32(), 1000, 2000, 8);
        let ds64 = semid_ds_32_to_64(&ds32);
        assert_eq!(ds64.sem_otime, 1000);
        assert_eq!(ds64.sem_nsems, 8);
    }

    #[test]
    fn test_semid_64_to_32_ok() {
        let ds64 = IpcCompat64Semid::new(perm64(), 5000, 6000, 4);
        let ds32 = semid_ds_64_to_32(&ds64).unwrap();
        assert_eq!(ds32.sem_nsems, 4);
    }

    #[test]
    fn test_semid_64_to_32_overflow_otime() {
        let ds64 = IpcCompat64Semid::new(perm64(), u64::MAX, 0, 2);
        assert_eq!(semid_ds_64_to_32(&ds64), Err(Error::InvalidArgument));
    }

    // --- Msqid conversion ---

    #[test]
    fn test_msqid_32_to_64() {
        let ds32 = IpcCompat32Msqid::new(perm32(), 100, 200, 300, 1024, 5, 8192, 10, 20);
        let ds64 = msqid_ds_32_to_64(&ds32);
        assert_eq!(ds64.msg_cbytes, 1024);
        assert_eq!(ds64.msg_qnum, 5);
    }

    #[test]
    fn test_msqid_64_to_32_ok() {
        let ds64 = IpcCompat64Msqid::new(perm64(), 1, 2, 3, 512, 2, 4096, 7, 8);
        let ds32 = msqid_ds_64_to_32(&ds64).unwrap();
        assert_eq!(ds32.msg_lspid, 7);
    }

    #[test]
    fn test_msqid_64_to_32_overflow_qbytes() {
        let ds64 = IpcCompat64Msqid::new(perm64(), 0, 0, 0, 0, 0, u64::MAX, 0, 0);
        assert_eq!(msqid_ds_64_to_32(&ds64), Err(Error::InvalidArgument));
    }

    // --- IpcCompatSubsystem ---

    #[test]
    fn test_convert_call_native() {
        let mut sys = IpcCompatSubsystem::new();
        let args = IpcCompatCall::new(7, 1, 0, 0);
        let out = sys.convert_call(IpcAbi::Native64, args).unwrap();
        assert_eq!(out.call, 7);
        assert_eq!(sys.stats.compat_calls, 1);
    }

    #[test]
    fn test_convert_call_compat32_valid() {
        let mut sys = IpcCompatSubsystem::new();
        let args = IpcCompatCall::new(24, 5, 0, 0); // SHMCTL
        sys.convert_call(IpcAbi::Compat32, args).unwrap();
        assert_eq!(sys.stats.compat_calls, 1);
        assert_eq!(sys.stats.conversion_errors, 0);
    }

    #[test]
    fn test_convert_call_compat32_unknown() {
        let mut sys = IpcCompatSubsystem::new();
        let args = IpcCompatCall::new(99, 0, 0, 0);
        assert_eq!(
            sys.convert_call(IpcAbi::Compat32, args),
            Err(Error::InvalidArgument)
        );
        assert_eq!(sys.stats.conversion_errors, 1);
    }

    #[test]
    fn test_subsystem_shmid_roundtrip() {
        let mut sys = IpcCompatSubsystem::new();
        let ds32 = IpcCompat32Shmid::new(perm32(), 1024, 10, 20, 30, 1, 2, 4);
        let ds64 = sys.compat_shmid_to_native(&ds32);
        let ds32_back = sys.native_shmid_to_compat(&ds64).unwrap();
        assert_eq!(ds32.shm_segsz, ds32_back.shm_segsz);
        assert_eq!(sys.stats.compat_calls, 2);
    }

    #[test]
    fn test_subsystem_semid_roundtrip() {
        let mut sys = IpcCompatSubsystem::new();
        let ds32 = IpcCompat32Semid::new(perm32(), 100, 200, 3);
        let ds64 = sys.compat_semid_to_native(&ds32);
        let ds32_back = sys.native_semid_to_compat(&ds64).unwrap();
        assert_eq!(ds32.sem_nsems, ds32_back.sem_nsems);
    }

    #[test]
    fn test_subsystem_msqid_roundtrip() {
        let mut sys = IpcCompatSubsystem::new();
        let ds32 = IpcCompat32Msqid::new(perm32(), 50, 60, 70, 256, 1, 512, 11, 22);
        let ds64 = sys.compat_msqid_to_native(&ds32);
        let ds32_back = sys.native_msqid_to_compat(&ds64).unwrap();
        assert_eq!(ds32.msg_cbytes, ds32_back.msg_cbytes);
    }
}
