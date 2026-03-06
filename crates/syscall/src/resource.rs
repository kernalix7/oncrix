// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Resource and system information syscall handlers.
//!
//! Implements `uname`, `sysinfo`, `getrusage`, and identity syscalls
//! (`getpid`, `getppid`, `getuid`, `geteuid`, `getgid`, `getegid`,
//! `gettid`, `set_tid_address`, `sethostname`) per POSIX.1-2024.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `getrusage` — report usage for the calling process.
pub const RUSAGE_SELF: i32 = 0;

/// `getrusage` — report usage for the calling thread.
pub const RUSAGE_THREAD: i32 = 1;

/// Maximum hostname length (excluding NUL terminator).
const MAX_HOSTNAME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Copy `src` bytes into a fixed-size `field`, NUL-padding the rest.
///
/// If `src` is longer than `field`, only the first `field.len()` bytes
/// are copied (no NUL terminator is guaranteed in that case).
pub fn copy_str_to_field(field: &mut [u8], src: &[u8]) {
    let copy_len = src.len().min(field.len());
    field[..copy_len].copy_from_slice(&src[..copy_len]);
    // Zero-fill the remainder.
    for byte in &mut field[copy_len..] {
        *byte = 0;
    }
}

// ---------------------------------------------------------------------------
// Utsname
// ---------------------------------------------------------------------------

/// POSIX `struct utsname` — system identification.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Utsname {
    /// Operating system name.
    pub sysname: [u8; 65],
    /// Network node hostname.
    pub nodename: [u8; 65],
    /// Operating system release.
    pub release: [u8; 65],
    /// Operating system version.
    pub version: [u8; 65],
    /// Hardware architecture identifier.
    pub machine: [u8; 65],
    /// NIS/YP domain name (Linux extension).
    pub domainname: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            sysname: [0u8; 65],
            nodename: [0u8; 65],
            release: [0u8; 65],
            version: [0u8; 65],
            machine: [0u8; 65],
            domainname: [0u8; 65],
        }
    }
}

impl Utsname {
    /// Create a `Utsname` pre-filled with ONCRIX default values.
    pub fn oncrix_default() -> Self {
        let mut u = Self::default();
        copy_str_to_field(&mut u.sysname, b"ONCRIX");
        copy_str_to_field(&mut u.nodename, b"oncrix");
        copy_str_to_field(&mut u.release, b"0.1.0");
        copy_str_to_field(&mut u.version, b"#1 SMP PREEMPT");
        copy_str_to_field(&mut u.machine, b"x86_64");
        copy_str_to_field(&mut u.domainname, b"(none)");
        u
    }
}

// ---------------------------------------------------------------------------
// Sysinfo
// ---------------------------------------------------------------------------

/// Linux-compatible `struct sysinfo` — overall system statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sysinfo {
    /// Seconds since boot.
    pub uptime: i64,
    /// 1-, 5-, and 15-minute load averages (scaled by 65536).
    pub loads: [u64; 3],
    /// Total usable main memory (bytes).
    pub totalram: u64,
    /// Available memory (bytes).
    pub freeram: u64,
    /// Amount of shared memory (bytes).
    pub sharedram: u64,
    /// Memory used by buffers (bytes).
    pub bufferram: u64,
    /// Total swap space (bytes).
    pub totalswap: u64,
    /// Swap space still available (bytes).
    pub freeswap: u64,
    /// Number of current processes.
    pub procs: u16,
    /// Total high memory (bytes).
    pub totalhigh: u64,
    /// Available high memory (bytes).
    pub freehigh: u64,
    /// Memory unit size in bytes.
    pub mem_unit: u32,
}

// ---------------------------------------------------------------------------
// Rusage
// ---------------------------------------------------------------------------

/// POSIX `struct rusage` — resource usage statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Rusage {
    /// User CPU time — seconds component.
    pub utime_sec: i64,
    /// User CPU time — microseconds component.
    pub utime_usec: i64,
    /// System CPU time — seconds component.
    pub stime_sec: i64,
    /// System CPU time — microseconds component.
    pub stime_usec: i64,
    /// Maximum resident set size (kilobytes).
    pub maxrss: i64,
    /// Page reclaims (soft page faults).
    pub minflt: i64,
    /// Page faults (hard page faults).
    pub majflt: i64,
    /// Voluntary context switches.
    pub nvcsw: i64,
    /// Involuntary context switches.
    pub nivcsw: i64,
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `uname` — return ONCRIX system identification.
pub fn do_uname() -> Result<Utsname> {
    Ok(Utsname::oncrix_default())
}

/// `sysinfo` — return overall system statistics.
///
/// Returns a default (zeroed) `Sysinfo` structure. A real kernel
/// would populate the fields from scheduler and MM subsystems.
pub fn do_sysinfo() -> Result<Sysinfo> {
    Ok(Sysinfo {
        procs: 1,
        mem_unit: 1,
        ..Sysinfo::default()
    })
}

/// `getrusage` — get resource usage for the calling process,
/// its children, or the calling thread.
///
/// `who` must be one of:
/// - [`RUSAGE_SELF`] (0) — calling process
/// - `-1` — terminated children
/// - [`RUSAGE_THREAD`] (1) — calling thread
pub fn do_getrusage(who: i32) -> Result<Rusage> {
    match who {
        RUSAGE_SELF | RUSAGE_THREAD | -1 => Ok(Rusage::default()),
        _ => Err(Error::InvalidArgument),
    }
}

/// `getpid` — return the process ID of the calling process.
///
/// Stub: always returns PID 1 (init-like process).
pub fn do_getpid() -> Result<u64> {
    Ok(1)
}

/// `getppid` — return the parent process ID.
///
/// Stub: always returns 0 (no parent).
pub fn do_getppid() -> Result<u64> {
    Ok(0)
}

/// `getuid` — return the real user ID of the calling process.
///
/// Stub: always returns 0 (root).
pub fn do_getuid() -> Result<u32> {
    Ok(0)
}

/// `geteuid` — return the effective user ID.
///
/// Stub: always returns 0 (root).
pub fn do_geteuid() -> Result<u32> {
    Ok(0)
}

/// `getgid` — return the real group ID of the calling process.
///
/// Stub: always returns 0 (root group).
pub fn do_getgid() -> Result<u32> {
    Ok(0)
}

/// `getegid` — return the effective group ID.
///
/// Stub: always returns 0 (root group).
pub fn do_getegid() -> Result<u32> {
    Ok(0)
}

/// `gettid` — return the thread ID of the calling thread.
///
/// Stub: always returns 1.
pub fn do_gettid() -> Result<u64> {
    Ok(1)
}

/// `set_tid_address` — set the clear-child-TID pointer.
///
/// Stub: records the address but always returns the current TID.
pub fn do_set_tid_address(addr: u64) -> Result<u64> {
    // Stub: a real kernel stores `addr` in the current task
    // struct and clears it + futex-wakes on thread exit.
    let _tid_addr = addr;
    Ok(1)
}

/// `sethostname` — set the system hostname.
///
/// `name` must be at most [`MAX_HOSTNAME_LEN`] (64) bytes.
pub fn do_sethostname(name: &[u8]) -> Result<()> {
    if name.len() > MAX_HOSTNAME_LEN {
        return Err(Error::InvalidArgument);
    }
    // Stub: a real kernel would copy `name` into a global
    // hostname buffer protected by a lock.
    Ok(())
}
