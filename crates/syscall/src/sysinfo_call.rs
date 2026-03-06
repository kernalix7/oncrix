// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sysinfo(2)` syscall handler.
//!
//! Returns global system statistics including uptime, load averages, memory
//! usage, and swap usage.
//!
//! # References
//!
//! - Linux man pages: `sysinfo(2)`
//! - Linux source: `kernel/sys.c` (`sys_sysinfo`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Sysinfo struct
// ---------------------------------------------------------------------------

/// System information structure returned by `sysinfo(2)`.
///
/// All memory values are in units of `mem_unit` bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysinfoBuf {
    /// Seconds since boot.
    pub uptime: i64,
    /// 1, 5, 15-minute load averages (scaled by 2^16).
    pub loads: [u64; 3],
    /// Total usable main memory size (in `mem_unit` units).
    pub totalram: u64,
    /// Available memory size (in `mem_unit` units).
    pub freeram: u64,
    /// Amount of shared memory (in `mem_unit` units).
    pub sharedram: u64,
    /// Memory used by buffers (in `mem_unit` units).
    pub bufferram: u64,
    /// Total swap space size.
    pub totalswap: u64,
    /// Swap space still available.
    pub freeswap: u64,
    /// Number of current processes.
    pub procs: u16,
    /// Padding.
    pub _pad: u16,
    /// Padding to align to 8 bytes.
    pub _pad2: u32,
    /// Total high memory size (0 on 64-bit).
    pub totalhigh: u64,
    /// Available high memory (0 on 64-bit).
    pub freehigh: u64,
    /// Memory unit size in bytes (typically 1).
    pub mem_unit: u32,
    /// Padding / reserved.
    pub _reserved: [u8; 4],
}

impl Default for SysinfoBuf {
    fn default() -> Self {
        Self {
            uptime: 0,
            loads: [0u64; 3],
            totalram: 0,
            freeram: 0,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 0,
            _pad: 0,
            _pad2: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
            _reserved: [0u8; 4],
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel sysinfo data
// ---------------------------------------------------------------------------

/// Kernel-side system information data provided by subsystems.
#[derive(Debug, Clone, Copy)]
pub struct KernelSysinfo {
    /// System uptime in seconds.
    pub uptime_secs: i64,
    /// 1-min load average scaled by 2^16.
    pub load_1: u64,
    /// 5-min load average scaled by 2^16.
    pub load_5: u64,
    /// 15-min load average scaled by 2^16.
    pub load_15: u64,
    /// Total physical RAM in bytes.
    pub total_ram: u64,
    /// Free physical RAM in bytes.
    pub free_ram: u64,
    /// Shared RAM in bytes.
    pub shared_ram: u64,
    /// Buffer RAM in bytes.
    pub buffer_ram: u64,
    /// Total swap in bytes.
    pub total_swap: u64,
    /// Free swap in bytes.
    pub free_swap: u64,
    /// Running process count.
    pub procs: u16,
    /// Memory unit size (1 = bytes, 4096 = pages).
    pub mem_unit: u32,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `sysinfo(2)`.
///
/// Translates kernel system data into the ABI struct.
///
/// # Errors
///
/// Returns `Err(InvalidArg)` if `mem_unit` is 0 (division by zero).
pub fn do_sysinfo(info: &KernelSysinfo) -> Result<SysinfoBuf> {
    if info.mem_unit == 0 {
        return Err(Error::InvalidArgument);
    }

    let unit = info.mem_unit as u64;

    // Divide memory values by mem_unit so the struct carries unit-sized chunks.
    Ok(SysinfoBuf {
        uptime: info.uptime_secs,
        loads: [info.load_1, info.load_5, info.load_15],
        totalram: info.total_ram / unit,
        freeram: info.free_ram / unit,
        sharedram: info.shared_ram / unit,
        bufferram: info.buffer_ram / unit,
        totalswap: info.total_swap / unit,
        freeswap: info.free_swap / unit,
        procs: info.procs,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: info.mem_unit,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> KernelSysinfo {
        KernelSysinfo {
            uptime_secs: 3600,
            load_1: 65536,  // 1.0
            load_5: 49152,  // 0.75
            load_15: 32768, // 0.5
            total_ram: 8 * 1024 * 1024 * 1024,
            free_ram: 4 * 1024 * 1024 * 1024,
            shared_ram: 512 * 1024 * 1024,
            buffer_ram: 256 * 1024 * 1024,
            total_swap: 2 * 1024 * 1024 * 1024,
            free_swap: 2 * 1024 * 1024 * 1024,
            procs: 128,
            mem_unit: 1,
        }
    }

    #[test]
    fn sysinfo_basic() {
        let buf = do_sysinfo(&sample_info()).unwrap();
        assert_eq!(buf.uptime, 3600);
        assert_eq!(buf.loads[0], 65536);
        assert_eq!(buf.procs, 128);
        assert_eq!(buf.totalram, 8 * 1024 * 1024 * 1024);
        assert_eq!(buf.mem_unit, 1);
    }

    #[test]
    fn sysinfo_page_units() {
        let mut info = sample_info();
        info.mem_unit = 4096;
        let buf = do_sysinfo(&info).unwrap();
        assert_eq!(buf.totalram, (8 * 1024 * 1024 * 1024u64) / 4096);
    }

    #[test]
    fn sysinfo_zero_mem_unit_fails() {
        let mut info = sample_info();
        info.mem_unit = 0;
        assert_eq!(do_sysinfo(&info), Err(Error::InvalidArgument));
    }
}
