// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process filesystem (procfs).
//!
//! Provides `/proc` entries exposing kernel and process information
//! as virtual files. Read-only; content is generated on the fly.
//!
//! Supports two-level hierarchy:
//! - `/proc/<file>` — global kernel information (version, uptime, etc.)
//! - `/proc/self/` — virtual directory for the current process
//! - `/proc/<pid>/` — virtual directory for a specific process
//!
//! Per-process subdirectories contain: `status`, `cmdline`, `maps`.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Maximum number of top-level procfs entries.
const MAX_PROC_ENTRIES: usize = 64;

/// Number of virtual files within each `/proc/<pid>/` directory.
const PID_DIR_FILES: usize = 3;

/// Inode range reserved for per-PID directories.
///
/// PIDs 0..4095 map to inodes `PID_INO_BASE + pid * PID_INO_STRIDE`.
/// Each PID directory occupies `PID_INO_STRIDE` inode numbers:
///   +0 = directory, +1 = status, +2 = cmdline, +3 = maps.
const PID_INO_BASE: u64 = 0x1_0000;
const PID_INO_STRIDE: u64 = 8;

/// Inode number for `/proc/self` (symlink-like directory).
const SELF_DIR_INO: u64 = 0xFFFF;

/// Per-process file names and their offsets within the PID inode range.
const PID_FILES: [(&str, u64); PID_DIR_FILES] = [("status", 1), ("cmdline", 2), ("maps", 3)];

/// A procfs entry.
#[derive(Debug, Clone, Copy)]
pub struct ProcEntry {
    /// Inode metadata.
    pub inode: Inode,
    /// Entry name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Content generator ID (identifies which data to produce).
    pub generator: ProcGenerator,
}

/// Which data a procfs entry generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcGenerator {
    /// `/proc/version` — kernel version string.
    Version,
    /// `/proc/uptime` — system uptime in seconds.
    Uptime,
    /// `/proc/meminfo` — memory usage statistics.
    MemInfo,
    /// `/proc/cpuinfo` — CPU information.
    CpuInfo,
    /// `/proc/self/status` or `/proc/<pid>/status`.
    PidStatus(u64),
    /// `/proc/<pid>/cmdline`.
    PidCmdline(u64),
    /// `/proc/<pid>/maps`.
    PidMaps(u64),
}

/// Process filesystem.
pub struct ProcFs {
    /// Top-level static entries.
    entries: [Option<ProcEntry>; MAX_PROC_ENTRIES],
    /// Root inode.
    root: Inode,
    /// Next inode number (for top-level entries).
    next_ino: u64,
    /// Top-level entry count.
    count: usize,
    /// PID of the "current" process (for `/proc/self`).
    ///
    /// Updated by the kernel on context switch or syscall entry.
    current_pid: u64,
}

impl core::fmt::Debug for ProcFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcFs")
            .field("count", &self.count)
            .field("current_pid", &self.current_pid)
            .finish()
    }
}

impl Default for ProcFs {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcFs {
    /// Create a new procfs with standard entries.
    pub fn new() -> Self {
        const NONE: Option<ProcEntry> = None;
        let mut fs = Self {
            entries: [NONE; MAX_PROC_ENTRIES],
            root: Inode::new(InodeNumber(1), FileType::Directory, FileMode::DIR_DEFAULT),
            next_ino: 2,
            count: 0,
            current_pid: 0,
        };

        // Register standard procfs entries.
        let _ = fs.add_entry("version", ProcGenerator::Version);
        let _ = fs.add_entry("uptime", ProcGenerator::Uptime);
        let _ = fs.add_entry("meminfo", ProcGenerator::MemInfo);
        let _ = fs.add_entry("cpuinfo", ProcGenerator::CpuInfo);

        fs
    }

    /// Return the root inode.
    pub fn root(&self) -> &Inode {
        &self.root
    }

    /// Set the current PID (used to resolve `/proc/self`).
    pub fn set_current_pid(&mut self, pid: u64) {
        self.current_pid = pid;
    }

    /// Return the current PID.
    pub fn current_pid(&self) -> u64 {
        self.current_pid
    }

    /// Add a top-level procfs entry.
    pub fn add_entry(&mut self, name: &str, generator: ProcGenerator) -> Result<InodeNumber> {
        if self.count >= MAX_PROC_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 32 {
            return Err(Error::InvalidArgument);
        }

        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        let mut entry_name = [0u8; 32];
        entry_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let entry = ProcEntry {
            inode: Inode::new(ino, FileType::Regular, FileMode::FILE_DEFAULT),
            name: entry_name,
            name_len: name_bytes.len(),
            generator,
        };

        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a top-level entry by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ProcEntry> {
        let name_bytes = name.as_bytes();
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| &e.name[..e.name_len] == name_bytes)
    }

    /// Compute the directory inode for a given PID.
    fn pid_dir_inode(pid: u64) -> Inode {
        let ino = PID_INO_BASE + pid.saturating_mul(PID_INO_STRIDE);
        Inode::new(InodeNumber(ino), FileType::Directory, FileMode::DIR_DEFAULT)
    }

    /// Compute the file inode for a per-PID file.
    fn pid_file_inode(pid: u64, offset: u64) -> Inode {
        let ino = PID_INO_BASE + pid.saturating_mul(PID_INO_STRIDE) + offset;
        Inode::new(InodeNumber(ino), FileType::Regular, FileMode::FILE_DEFAULT)
    }

    /// Try to parse a name as a numeric PID.
    fn parse_pid(name: &str) -> Option<u64> {
        if name.is_empty() {
            return None;
        }
        let mut val: u64 = 0;
        for &b in name.as_bytes() {
            if !b.is_ascii_digit() {
                return None;
            }
            val = val.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        }
        Some(val)
    }

    /// Decode an inode number into a `(pid, file_offset)` pair.
    ///
    /// Returns `None` if the inode is not in the PID range.
    fn decode_pid_inode(ino: u64) -> Option<(u64, u64)> {
        if ino < PID_INO_BASE {
            return None;
        }
        let relative = ino - PID_INO_BASE;
        let pid = relative / PID_INO_STRIDE;
        let offset = relative % PID_INO_STRIDE;
        Some((pid, offset))
    }

    /// Generate content for a procfs entry.
    ///
    /// Writes the content into `buf` and returns the number of bytes.
    pub fn generate(&self, generator: ProcGenerator, buf: &mut [u8]) -> Result<usize> {
        // Use a stack buffer for dynamic content formatting.
        let mut tmp = [0u8; 256];
        let content: &[u8] = match generator {
            ProcGenerator::Version => b"ONCRIX 0.1.0 (microkernel)\n",
            ProcGenerator::Uptime => b"0\n",
            ProcGenerator::MemInfo => b"MemTotal: 131072 kB\nMemFree: 0 kB\n",
            ProcGenerator::CpuInfo => b"processor: 0\nmodel name: ONCRIX vCPU\n",
            ProcGenerator::PidStatus(pid) => {
                let n = fmt_pid_status(pid, &mut tmp);
                &tmp[..n]
            }
            ProcGenerator::PidCmdline(pid) => {
                let n = fmt_pid_cmdline(pid, &mut tmp);
                &tmp[..n]
            }
            ProcGenerator::PidMaps(pid) => {
                let n = fmt_pid_maps(pid, &mut tmp);
                &tmp[..n]
            }
        };

        let len = content.len().min(buf.len());
        buf[..len].copy_from_slice(&content[..len]);
        Ok(len)
    }

    /// Determine the generator for a PID-scoped inode.
    fn generator_for_pid_file(pid: u64, offset: u64) -> Option<ProcGenerator> {
        match offset {
            1 => Some(ProcGenerator::PidStatus(pid)),
            2 => Some(ProcGenerator::PidCmdline(pid)),
            3 => Some(ProcGenerator::PidMaps(pid)),
            _ => None,
        }
    }
}

// ── Content formatters for per-PID files ─────────────────────────

/// Format `/proc/<pid>/status` content into `buf`. Returns bytes written.
fn fmt_pid_status(pid: u64, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += copy_str(&mut buf[pos..], "Name: process-");
    pos += copy_u64(&mut buf[pos..], pid);
    pos += copy_str(&mut buf[pos..], "\nState: S (sleeping)\nPid: ");
    pos += copy_u64(&mut buf[pos..], pid);
    pos += copy_str(&mut buf[pos..], "\nThreads: 1\n");
    pos
}

/// Format `/proc/<pid>/cmdline` content into `buf`. Returns bytes written.
fn fmt_pid_cmdline(pid: u64, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += copy_str(&mut buf[pos..], "/bin/process-");
    pos += copy_u64(&mut buf[pos..], pid);
    pos += copy_str(&mut buf[pos..], "\0");
    pos
}

/// Format `/proc/<pid>/maps` content into `buf`. Returns bytes written.
fn fmt_pid_maps(pid: u64, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += copy_str(&mut buf[pos..], "00400000-00401000 r-xp 00000000 00:00 ");
    pos += copy_u64(&mut buf[pos..], pid);
    pos += copy_str(&mut buf[pos..], " [text]\n");
    pos += copy_str(
        &mut buf[pos..],
        "7fff0000-7fff1000 rw-p 00000000 00:00 0 [stack]\n",
    );
    pos
}

/// Copy a static string into a byte buffer. Returns bytes written.
fn copy_str(buf: &mut [u8], s: &str) -> usize {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    len
}

/// Write a `u64` as decimal digits into a byte buffer. Returns bytes written.
fn copy_u64(buf: &mut [u8], val: u64) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    // Format into a small stack buffer (max 20 digits for u64).
    let mut digits = [0u8; 20];
    let mut n = val;
    let mut i = 20usize;
    while n > 0 && i > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = (20 - i).min(buf.len());
    buf[..len].copy_from_slice(&digits[i..i + len]);
    len
}

impl InodeOps for ProcFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        // Check if parent is /proc/self directory.
        if parent.ino == InodeNumber(SELF_DIR_INO) {
            let pid = self.current_pid;
            for &(fname, offset) in &PID_FILES {
                if name == fname {
                    return Ok(Self::pid_file_inode(pid, offset));
                }
            }
            return Err(Error::NotFound);
        }

        // Check if parent is a /proc/<pid>/ directory.
        if let Some((pid, 0)) = Self::decode_pid_inode(parent.ino.0) {
            for &(fname, offset) in &PID_FILES {
                if name == fname {
                    return Ok(Self::pid_file_inode(pid, offset));
                }
            }
            return Err(Error::NotFound);
        }

        // Top-level lookup under /proc root.
        if name == "self" {
            return Ok(Inode::new(
                InodeNumber(SELF_DIR_INO),
                FileType::Directory,
                FileMode::DIR_DEFAULT,
            ));
        }

        // Check numeric PID directories.
        if let Some(pid) = Self::parse_pid(name) {
            return Ok(Self::pid_dir_inode(pid));
        }

        // Check static entries (version, uptime, etc.).
        self.find_by_name(name)
            .map(|e| e.inode)
            .ok_or(Error::NotFound)
    }

    fn create(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        Err(Error::NotImplemented)
    }

    fn mkdir(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        Err(Error::NotImplemented)
    }

    fn unlink(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn rmdir(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        // Check if this is a PID-scoped file.
        if let Some((pid, file_offset)) = Self::decode_pid_inode(inode.ino.0) {
            if file_offset == 0 {
                // It's the directory itself — cannot read.
                return Err(Error::InvalidArgument);
            }
            let generator =
                Self::generator_for_pid_file(pid, file_offset).ok_or(Error::NotFound)?;
            let mut tmp = [0u8; 256];
            let total = self.generate(generator, &mut tmp)?;
            let off = offset as usize;
            if off >= total {
                return Ok(0);
            }
            let available = total - off;
            let to_copy = buf.len().min(available);
            buf[..to_copy].copy_from_slice(&tmp[off..off + to_copy]);
            return Ok(to_copy);
        }

        // /proc/self is a directory — cannot read.
        if inode.ino.0 == SELF_DIR_INO {
            return Err(Error::InvalidArgument);
        }

        // Find the static entry for this inode and generate content.
        let entry = self
            .entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.inode.ino == inode.ino)
            .ok_or(Error::NotFound)?;

        let mut tmp = [0u8; 256];
        let total = self.generate(entry.generator, &mut tmp)?;
        let off = offset as usize;
        if off >= total {
            return Ok(0);
        }
        let available = total - off;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&tmp[off..off + to_copy]);
        Ok(to_copy)
    }

    fn write(&mut self, _inode: &Inode, _offset: u64, _data: &[u8]) -> Result<usize> {
        Err(Error::NotImplemented)
    }

    fn truncate(&mut self, _inode: &Inode, _size: u64) -> Result<()> {
        Err(Error::NotImplemented)
    }
}
