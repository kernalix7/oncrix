// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Procfs `/proc/<pid>/maps` and `/proc/<pid>/smaps` implementation.
//!
//! These virtual files expose the memory map of a process: each line
//! describes one VMA (Virtual Memory Area) with its address range, permissions,
//! backing file offset and name.

use oncrix_lib::{Error, Result};

/// Maximum number of VMAs in a process memory map.
pub const PROC_MAPS_MAX_VMAS: usize = 65536;

/// VMA permission bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaPerms(pub u8);

impl VmaPerms {
    pub const READ: u8 = 0x01;
    pub const WRITE: u8 = 0x02;
    pub const EXEC: u8 = 0x04;
    pub const SHARED: u8 = 0x08;

    pub fn is_readable(&self) -> bool {
        self.0 & Self::READ != 0
    }
    pub fn is_writable(&self) -> bool {
        self.0 & Self::WRITE != 0
    }
    pub fn is_executable(&self) -> bool {
        self.0 & Self::EXEC != 0
    }
    pub fn is_shared(&self) -> bool {
        self.0 & Self::SHARED != 0
    }

    /// Format as `rwxp` or `---s` string into `out[..4]`.
    pub fn format(&self, out: &mut [u8; 4]) {
        out[0] = if self.is_readable() { b'r' } else { b'-' };
        out[1] = if self.is_writable() { b'w' } else { b'-' };
        out[2] = if self.is_executable() { b'x' } else { b'-' };
        out[3] = if self.is_shared() { b's' } else { b'p' };
    }
}

/// Type of VMA backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaBacking {
    /// Anonymous mapping (stack, heap, mmap(MAP_ANONYMOUS)).
    Anonymous,
    /// File-backed mapping.
    File,
    /// Special (vdso, vsyscall, etc.).
    Special,
}

/// A single VMA entry.
#[derive(Debug, Clone)]
pub struct VmaEntry {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// Permission bits.
    pub perms: VmaPerms,
    /// File offset (0 for anonymous mappings).
    pub file_offset: u64,
    /// Device number (major:minor, 0:0 for anonymous).
    pub dev_major: u8,
    pub dev_minor: u8,
    /// Inode number (0 for anonymous).
    pub ino: u64,
    /// VMA name: file path, `[heap]`, `[stack]`, `[vdso]`, or empty.
    pub name: [u8; 256],
    pub name_len: u8,
    /// VMA type.
    pub backing: VmaBacking,
    /// Resident set size in KiB (for smaps).
    pub rss_kb: u64,
    /// Anonymous pages in KiB.
    pub anon_kb: u64,
    /// Swapped pages in KiB.
    pub swap_kb: u64,
}

impl VmaEntry {
    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Size of the VMA in bytes.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// The memory map of one process.
pub struct ProcMaps {
    vmas: [Option<VmaEntry>; PROC_MAPS_MAX_VMAS],
    count: usize,
}

impl ProcMaps {
    /// Create an empty map.
    pub const fn new() -> Self {
        Self {
            vmas: [const { None }; PROC_MAPS_MAX_VMAS],
            count: 0,
        }
    }

    /// Add a VMA entry (VMAs must be added in address order for correct output).
    pub fn add(&mut self, entry: VmaEntry) -> Result<()> {
        if self.count >= PROC_MAPS_MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        self.vmas[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Find the VMA containing `addr`.
    pub fn find_containing(&self, addr: u64) -> Option<&VmaEntry> {
        self.vmas[..self.count]
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|vma| addr >= vma.start && addr < vma.end)
    }

    /// Number of VMAs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all VMAs in order.
    pub fn iter(&self) -> impl Iterator<Item = &VmaEntry> {
        self.vmas[..self.count].iter().filter_map(|s| s.as_ref())
    }

    /// Format one `/proc/<pid>/maps` line for VMA at index `idx`.
    ///
    /// Returns the number of bytes written into `buf`.
    pub fn format_maps_line(&self, idx: usize, buf: &mut [u8]) -> Result<usize> {
        let vma = self.vmas[idx].as_ref().ok_or(Error::NotFound)?;
        // Format: "start-end perms offset dev ino [name]\n"
        // We write a simplified fixed hex representation.
        if buf.len() < 80 {
            return Err(Error::InvalidArgument);
        }
        let mut off = 0;
        off += fmt_hex64(&mut buf[off..], vma.start);
        buf[off] = b'-';
        off += 1;
        off += fmt_hex64(&mut buf[off..], vma.end);
        buf[off] = b' ';
        off += 1;
        let mut perms_buf = [0u8; 4];
        vma.perms.format(&mut perms_buf);
        buf[off..off + 4].copy_from_slice(&perms_buf);
        off += 4;
        buf[off] = b' ';
        off += 1;
        off += fmt_hex64(&mut buf[off..], vma.file_offset);
        buf[off] = b' ';
        off += 1;
        // Device: "XX:XX"
        off += fmt_hex8(&mut buf[off..], vma.dev_major);
        buf[off] = b':';
        off += 1;
        off += fmt_hex8(&mut buf[off..], vma.dev_minor);
        buf[off] = b' ';
        off += 1;
        // Inode
        off += fmt_dec64(&mut buf[off..], vma.ino);
        buf[off] = b' ';
        off += 1;
        // Name
        let name = vma.name_bytes();
        if off + name.len() + 1 <= buf.len() {
            buf[off..off + name.len()].copy_from_slice(name);
            off += name.len();
        }
        buf[off] = b'\n';
        off += 1;
        Ok(off)
    }
}

impl Default for ProcMaps {
    fn default() -> Self {
        Self::new()
    }
}

// -- Minimal formatting helpers (no_std safe) --

fn fmt_hex64(buf: &mut [u8], v: u64) -> usize {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut i = 16;
    let mut n = v;
    loop {
        i -= 1;
        tmp[i] = DIGITS[(n & 0xf) as usize];
        n >>= 4;
        if n == 0 {
            break;
        }
    }
    let len = 16 - i;
    let written = len.min(buf.len());
    buf[..written].copy_from_slice(&tmp[i..i + written]);
    written
}

fn fmt_hex8(buf: &mut [u8], v: u8) -> usize {
    const DIGITS: &[u8] = b"0123456789abcdef";
    if buf.len() < 2 {
        return 0;
    }
    buf[0] = DIGITS[(v >> 4) as usize];
    buf[1] = DIGITS[(v & 0xf) as usize];
    2
}

fn fmt_dec64(buf: &mut [u8], v: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut i = 20;
    let mut n = v;
    if n == 0 {
        if buf.is_empty() {
            return 0;
        }
        buf[0] = b'0';
        return 1;
    }
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = (20 - i).min(buf.len());
    buf[..len].copy_from_slice(&tmp[i..i + len]);
    len
}
