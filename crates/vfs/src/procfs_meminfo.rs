// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/meminfo implementation.
//!
//! Generates the content of `/proc/meminfo`, which exposes kernel memory
//! statistics in a human-readable key-value format. All values are in
//! kibibytes (KiB) to match the Linux format.
//!
//! # Format
//!
//! ```text
//! MemTotal:       16384000 kB
//! MemFree:         8192000 kB
//! ...
//! ```
//!
//! # References
//!
//! - Linux `fs/proc/meminfo.c`
//! - `include/linux/mm.h` (SI_UNIT_KB)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum output buffer size for /proc/meminfo content.
pub const MEMINFO_BUF_SIZE: usize = 4096;

/// Number of memory info fields.
pub const MEMINFO_FIELD_COUNT: usize = 20;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// All memory statistics exposed via /proc/meminfo.
///
/// All values are in kibibytes (KiB).
#[derive(Debug, Clone, Copy, Default)]
pub struct MemInfoData {
    /// Total usable RAM.
    pub mem_total: u64,
    /// Free RAM (not including caches).
    pub mem_free: u64,
    /// Estimate of available memory for new applications.
    pub mem_available: u64,
    /// Relatively temporary storage for raw disk blocks.
    pub buffers: u64,
    /// In-memory cache for files read from disk.
    pub cached: u64,
    /// Memory that was swapped out and then swapped back in, still in swap.
    pub swap_cached: u64,
    /// Memory used often and not recently freed.
    pub active: u64,
    /// Memory used less recently; eligible for reclaim.
    pub inactive: u64,
    /// Anonymous active memory.
    pub active_anon: u64,
    /// Anonymous inactive memory.
    pub inactive_anon: u64,
    /// File-backed active memory.
    pub active_file: u64,
    /// File-backed inactive memory.
    pub inactive_file: u64,
    /// Memory undergoing reclaim.
    pub unevictable: u64,
    /// Dirty pages awaiting writeback.
    pub dirty: u64,
    /// Pages currently being written to disk.
    pub writeback: u64,
    /// Non-file backed pages mapped into user-space page tables.
    pub anon_pages: u64,
    /// Files mapped into memory with mmap.
    pub mapped: u64,
    /// Memory used by shared memory (shmem/tmpfs).
    pub shmem: u64,
    /// Total slab memory.
    pub slab: u64,
    /// Reclaimable slab memory.
    pub s_reclaimable: u64,
    /// Unreclaimable slab memory.
    pub s_unreclaim: u64,
    /// Memory used for kernel stacks.
    pub kernel_stack: u64,
    /// Memory used for page tables.
    pub page_tables: u64,
    /// Total swap space.
    pub swap_total: u64,
    /// Free swap space.
    pub swap_free: u64,
    /// Memory used for huge pages.
    pub huge_pages_total: u64,
    /// Free huge pages.
    pub huge_pages_free: u64,
    /// Huge page size in kB.
    pub huge_page_size: u64,
}

impl MemInfoData {
    /// Create a MemInfoData with all zeros.
    pub const fn zeroed() -> Self {
        Self {
            mem_total: 0,
            mem_free: 0,
            mem_available: 0,
            buffers: 0,
            cached: 0,
            swap_cached: 0,
            active: 0,
            inactive: 0,
            active_anon: 0,
            inactive_anon: 0,
            active_file: 0,
            inactive_file: 0,
            unevictable: 0,
            dirty: 0,
            writeback: 0,
            anon_pages: 0,
            mapped: 0,
            shmem: 0,
            slab: 0,
            s_reclaimable: 0,
            s_unreclaim: 0,
            kernel_stack: 0,
            page_tables: 0,
            swap_total: 0,
            swap_free: 0,
            huge_pages_total: 0,
            huge_pages_free: 0,
            huge_page_size: 2048, // 2 MiB default
        }
    }

    /// Compute MemAvailable as a rough estimate.
    pub fn compute_available(&self) -> u64 {
        self.mem_free + self.buffers + self.s_reclaimable + self.cached
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Write a decimal `u64` into `buf` at `pos`. Returns new `pos`.
fn write_u64(buf: &mut [u8], mut pos: usize, mut val: u64) -> usize {
    if pos >= buf.len() {
        return pos;
    }
    if val == 0 {
        if pos < buf.len() {
            buf[pos] = b'0';
            pos += 1;
        }
        return pos;
    }
    // Write digits in reverse then reverse.
    let start = pos;
    while val > 0 && pos < buf.len() {
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    buf[start..pos].reverse();
    pos
}

/// Write a static byte string into `buf` at `pos`. Returns new `pos`.
fn write_str(buf: &mut [u8], mut pos: usize, s: &[u8]) -> usize {
    for &b in s {
        if pos >= buf.len() {
            break;
        }
        buf[pos] = b;
        pos += 1;
    }
    pos
}

/// Append one meminfo line: `"Name:         NNN kB\n"`.
fn append_line(buf: &mut [u8], pos: usize, name: &[u8], val: u64) -> usize {
    let mut p = write_str(buf, pos, name);
    p = write_str(buf, p, b":");
    // Padding to column 16.
    let col = name.len() + 1;
    let pad = if col < 16 { 16 - col } else { 1 };
    for _ in 0..pad {
        if p < buf.len() {
            buf[p] = b' ';
            p += 1;
        }
    }
    p = write_u64(buf, p, val);
    p = write_str(buf, p, b" kB\n");
    p
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Format `data` into `buf` in /proc/meminfo format.
///
/// Returns the number of bytes written, or `Err(InvalidArgument)` if `buf`
/// is too small.
pub fn format_meminfo(data: &MemInfoData, buf: &mut [u8]) -> Result<usize> {
    if buf.len() < 256 {
        return Err(Error::InvalidArgument);
    }

    let available = data.compute_available();
    let mut p = 0;

    p = append_line(buf, p, b"MemTotal", data.mem_total);
    p = append_line(buf, p, b"MemFree", data.mem_free);
    p = append_line(buf, p, b"MemAvailable", available);
    p = append_line(buf, p, b"Buffers", data.buffers);
    p = append_line(buf, p, b"Cached", data.cached);
    p = append_line(buf, p, b"SwapCached", data.swap_cached);
    p = append_line(buf, p, b"Active", data.active);
    p = append_line(buf, p, b"Inactive", data.inactive);
    p = append_line(buf, p, b"Active(anon)", data.active_anon);
    p = append_line(buf, p, b"Inactive(anon)", data.inactive_anon);
    p = append_line(buf, p, b"Active(file)", data.active_file);
    p = append_line(buf, p, b"Inactive(file)", data.inactive_file);
    p = append_line(buf, p, b"Unevictable", data.unevictable);
    p = append_line(buf, p, b"Dirty", data.dirty);
    p = append_line(buf, p, b"Writeback", data.writeback);
    p = append_line(buf, p, b"AnonPages", data.anon_pages);
    p = append_line(buf, p, b"Mapped", data.mapped);
    p = append_line(buf, p, b"Shmem", data.shmem);
    p = append_line(buf, p, b"Slab", data.slab);
    p = append_line(buf, p, b"SReclaimable", data.s_reclaimable);
    p = append_line(buf, p, b"SUnreclaim", data.s_unreclaim);
    p = append_line(buf, p, b"KernelStack", data.kernel_stack);
    p = append_line(buf, p, b"PageTables", data.page_tables);
    p = append_line(buf, p, b"SwapTotal", data.swap_total);
    p = append_line(buf, p, b"SwapFree", data.swap_free);
    p = append_line(buf, p, b"HugePages_Total", data.huge_pages_total);
    p = append_line(buf, p, b"HugePages_Free", data.huge_pages_free);
    p = append_line(buf, p, b"Hugepagesize", data.huge_page_size);

    if p > buf.len() {
        return Err(Error::InvalidArgument);
    }
    Ok(p)
}

/// Read a slice of the formatted meminfo starting at `offset`.
///
/// Writes up to `out.len()` bytes into `out`. Returns bytes written.
pub fn read_meminfo(data: &MemInfoData, offset: usize, out: &mut [u8]) -> Result<usize> {
    let mut tmp = [0u8; MEMINFO_BUF_SIZE];
    let total = format_meminfo(data, &mut tmp)?;
    if offset >= total {
        return Ok(0);
    }
    let avail = total - offset;
    let copy = avail.min(out.len());
    out[..copy].copy_from_slice(&tmp[offset..offset + copy]);
    Ok(copy)
}

/// Return the total size of the formatted /proc/meminfo content.
pub fn meminfo_size(data: &MemInfoData) -> Result<usize> {
    let mut tmp = [0u8; MEMINFO_BUF_SIZE];
    format_meminfo(data, &mut tmp)
}
