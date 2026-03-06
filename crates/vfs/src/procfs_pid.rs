// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/[pid]/ directory entries.
//!
//! Implements the virtual files under `/proc/<pid>/` that expose per-process
//! information. Each virtual file generates its content on the fly from the
//! process descriptor.
//!
//! # Supported entries
//!
//! | Path | Content |
//! |------|---------|
//! | `status` | Human-readable process status |
//! | `stat` | Machine-readable process statistics |
//! | `statm` | Memory usage in pages |
//! | `cmdline` | Null-separated argv |
//! | `maps` | Virtual memory area mappings |
//! | `fd/` | Directory of open file descriptors |
//! | `exe` | Symlink to executable |
//! | `cwd` | Symlink to current working directory |
//! | `root` | Symlink to filesystem root |
//! | `environ` | Null-separated environment variables |
//!
//! # References
//!
//! - Linux `fs/proc/base.c`
//! - `man 5 proc`

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum PID value.
pub const MAX_PID: u32 = 65535;

/// Maximum command-line length stored.
pub const MAX_CMDLINE: usize = 4096;

/// Maximum environment length stored.
pub const MAX_ENVIRON: usize = 4096;

/// Maximum path length for exe/cwd/root symlinks.
pub const MAX_PATH: usize = 256;

/// Maximum number of VMAs in maps output.
pub const MAX_VMA: usize = 64;

/// Maximum number of open FDs listed.
pub const MAX_FDS: usize = 256;

/// Output buffer size for text generation.
pub const PID_BUF_SIZE: usize = 8192;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Process state as reported in /proc/[pid]/status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// Running.
    Running,
    /// Sleeping (interruptible).
    Sleeping,
    /// Stopped.
    Stopped,
    /// Zombie.
    Zombie,
    /// Dead.
    Dead,
}

impl ProcState {
    fn as_char(self) -> u8 {
        match self {
            ProcState::Running => b'R',
            ProcState::Sleeping => b'S',
            ProcState::Stopped => b'T',
            ProcState::Zombie => b'Z',
            ProcState::Dead => b'X',
        }
    }

    fn as_str(self) -> &'static [u8] {
        match self {
            ProcState::Running => b"R (running)",
            ProcState::Sleeping => b"S (sleeping)",
            ProcState::Stopped => b"T (stopped)",
            ProcState::Zombie => b"Z (zombie)",
            ProcState::Dead => b"X (dead)",
        }
    }
}

/// A virtual memory area entry for maps output.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaEntry {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address.
    pub end: u64,
    /// Permissions (r/w/x/p or s).
    pub perm: u8,
    /// Offset into backing file.
    pub offset: u64,
    /// Device major number.
    pub dev_major: u8,
    /// Device minor number.
    pub dev_minor: u8,
    /// Inode of backing file (0 for anonymous).
    pub inode: u64,
}

/// Process descriptor used to generate /proc/[pid]/* content.
#[derive(Clone)]
pub struct ProcPidDesc {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// Process name (null-terminated at `name_len`).
    pub name: [u8; 16],
    /// Length of `name`.
    pub name_len: usize,
    /// Process state.
    pub state: ProcState,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Virtual memory size in pages.
    pub vm_size_pages: u64,
    /// Resident set size in pages.
    pub vm_rss_pages: u64,
    /// Shared pages.
    pub vm_shared_pages: u64,
    /// Text (code) pages.
    pub vm_text_pages: u64,
    /// Library pages.
    pub vm_lib_pages: u64,
    /// Data + stack pages.
    pub vm_data_pages: u64,
    /// Command-line bytes.
    pub cmdline: [u8; MAX_CMDLINE],
    /// Length of cmdline.
    pub cmdline_len: usize,
    /// Environment bytes.
    pub environ: [u8; MAX_ENVIRON],
    /// Length of environ.
    pub environ_len: usize,
    /// Executable path.
    pub exe_path: [u8; MAX_PATH],
    /// Length of exe_path.
    pub exe_path_len: usize,
    /// CWD path.
    pub cwd_path: [u8; MAX_PATH],
    /// Length of cwd_path.
    pub cwd_path_len: usize,
    /// Open FD numbers.
    pub open_fds: [i32; MAX_FDS],
    /// Number of open FDs.
    pub fd_count: usize,
    /// VMA list.
    pub vmas: [VmaEntry; MAX_VMA],
    /// Number of VMAs.
    pub vma_count: usize,
    /// CPU time (user ticks).
    pub utime: u64,
    /// CPU time (kernel ticks).
    pub stime: u64,
    /// Priority.
    pub priority: i32,
    /// Nice value.
    pub nice: i32,
}

impl ProcPidDesc {
    /// Create a minimal descriptor for `pid`.
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            ppid: 0,
            tgid: pid,
            name: [0u8; 16],
            name_len: 0,
            state: ProcState::Sleeping,
            uid: 0,
            gid: 0,
            vm_size_pages: 0,
            vm_rss_pages: 0,
            vm_shared_pages: 0,
            vm_text_pages: 0,
            vm_lib_pages: 0,
            vm_data_pages: 0,
            cmdline: [0u8; MAX_CMDLINE],
            cmdline_len: 0,
            environ: [0u8; MAX_ENVIRON],
            environ_len: 0,
            exe_path: [0u8; MAX_PATH],
            exe_path_len: 0,
            cwd_path: [0u8; MAX_PATH],
            cwd_path_len: 0,
            open_fds: [0i32; MAX_FDS],
            fd_count: 0,
            vmas: [VmaEntry::default(); MAX_VMA],
            vma_count: 0,
            utime: 0,
            stime: 0,
            priority: 20,
            nice: 0,
        }
    }

    /// Return process name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// Text generation helpers
// ---------------------------------------------------------------------------

fn write_u64(buf: &mut [u8], mut pos: usize, mut val: u64) -> usize {
    if pos >= buf.len() {
        return pos;
    }
    if val == 0 {
        buf[pos] = b'0';
        return pos + 1;
    }
    let start = pos;
    while val > 0 && pos < buf.len() {
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    buf[start..pos].reverse();
    pos
}

fn write_i64(buf: &mut [u8], pos: usize, val: i64) -> usize {
    if val < 0 {
        let p = write_byte(buf, pos, b'-');
        write_u64(buf, p, val.unsigned_abs())
    } else {
        write_u64(buf, pos, val as u64)
    }
}

fn write_byte(buf: &mut [u8], pos: usize, b: u8) -> usize {
    if pos < buf.len() {
        buf[pos] = b;
        pos + 1
    } else {
        pos
    }
}

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

fn write_hex(buf: &mut [u8], mut pos: usize, mut val: u64, width: usize) -> usize {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut len = 0;
    loop {
        tmp[len] = HEX[(val & 0xf) as usize];
        val >>= 4;
        len += 1;
        if val == 0 {
            break;
        }
    }
    // Pad to width.
    while len < width && pos < buf.len() {
        buf[pos] = b'0';
        pos += 1;
    }
    // Write reversed.
    let pad_written = if len >= width { 0 } else { width - len };
    let _ = pad_written;
    for j in (0..len).rev() {
        if pos >= buf.len() {
            break;
        }
        buf[pos] = tmp[j];
        pos += 1;
    }
    pos
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate /proc/[pid]/status content into `buf`.
///
/// Returns bytes written.
pub fn generate_status(desc: &ProcPidDesc, buf: &mut [u8]) -> Result<usize> {
    let mut p = 0;
    p = write_str(buf, p, b"Name:\t");
    p = write_str(buf, p, desc.name_bytes());
    p = write_byte(buf, p, b'\n');
    p = write_str(buf, p, b"State:\t");
    p = write_str(buf, p, desc.state.as_str());
    p = write_byte(buf, p, b'\n');
    p = write_str(buf, p, b"Pid:\t");
    p = write_u64(buf, p, desc.pid as u64);
    p = write_byte(buf, p, b'\n');
    p = write_str(buf, p, b"PPid:\t");
    p = write_u64(buf, p, desc.ppid as u64);
    p = write_byte(buf, p, b'\n');
    p = write_str(buf, p, b"Uid:\t");
    p = write_u64(buf, p, desc.uid as u64);
    p = write_byte(buf, p, b'\n');
    p = write_str(buf, p, b"Gid:\t");
    p = write_u64(buf, p, desc.gid as u64);
    p = write_byte(buf, p, b'\n');
    p = write_str(buf, p, b"VmSize:\t");
    p = write_u64(buf, p, desc.vm_size_pages * 4);
    p = write_str(buf, p, b" kB\n");
    p = write_str(buf, p, b"VmRSS:\t");
    p = write_u64(buf, p, desc.vm_rss_pages * 4);
    p = write_str(buf, p, b" kB\n");
    Ok(p)
}

/// Generate /proc/[pid]/stat content into `buf` (space-separated fields).
///
/// Returns bytes written.
pub fn generate_stat(desc: &ProcPidDesc, buf: &mut [u8]) -> Result<usize> {
    let mut p = 0;
    p = write_u64(buf, p, desc.pid as u64);
    p = write_byte(buf, p, b' ');
    p = write_byte(buf, p, b'(');
    p = write_str(buf, p, desc.name_bytes());
    p = write_byte(buf, p, b')');
    p = write_byte(buf, p, b' ');
    p = write_byte(buf, p, desc.state.as_char());
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.ppid as u64);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.tgid as u64);
    p = write_byte(buf, p, b' ');
    // Remaining fields: utime, stime, priority, nice.
    p = write_u64(buf, p, desc.utime);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.stime);
    p = write_byte(buf, p, b' ');
    p = write_i64(buf, p, desc.priority as i64);
    p = write_byte(buf, p, b' ');
    p = write_i64(buf, p, desc.nice as i64);
    p = write_byte(buf, p, b'\n');
    Ok(p)
}

/// Generate /proc/[pid]/statm content into `buf`.
///
/// Format: `size resident shared text lib data dt`
pub fn generate_statm(desc: &ProcPidDesc, buf: &mut [u8]) -> Result<usize> {
    let mut p = 0;
    p = write_u64(buf, p, desc.vm_size_pages);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.vm_rss_pages);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.vm_shared_pages);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.vm_text_pages);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.vm_lib_pages);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, desc.vm_data_pages);
    p = write_byte(buf, p, b' ');
    p = write_u64(buf, p, 0); // dt (dirty pages, simplified)
    p = write_byte(buf, p, b'\n');
    Ok(p)
}

/// Generate /proc/[pid]/maps content into `buf`.
///
/// Returns bytes written.
pub fn generate_maps(desc: &ProcPidDesc, buf: &mut [u8]) -> Result<usize> {
    let mut p = 0;
    for i in 0..desc.vma_count {
        let vma = &desc.vmas[i];
        p = write_hex(buf, p, vma.start, 12);
        p = write_byte(buf, p, b'-');
        p = write_hex(buf, p, vma.end, 12);
        p = write_byte(buf, p, b' ');
        let r = if vma.perm & 0x4 != 0 { b'r' } else { b'-' };
        let w = if vma.perm & 0x2 != 0 { b'w' } else { b'-' };
        let x = if vma.perm & 0x1 != 0 { b'x' } else { b'-' };
        p = write_byte(buf, p, r);
        p = write_byte(buf, p, w);
        p = write_byte(buf, p, x);
        p = write_byte(buf, p, b'p');
        p = write_byte(buf, p, b' ');
        p = write_hex(buf, p, vma.offset, 8);
        p = write_byte(buf, p, b' ');
        p = write_hex(buf, p, vma.dev_major as u64, 2);
        p = write_byte(buf, p, b':');
        p = write_hex(buf, p, vma.dev_minor as u64, 2);
        p = write_byte(buf, p, b' ');
        p = write_u64(buf, p, vma.inode);
        p = write_byte(buf, p, b'\n');
    }
    Ok(p)
}

/// List open file descriptors for a process into `out`.
///
/// Each element is an fd number (non-negative). Returns the count written.
pub fn fd_readdir(desc: &ProcPidDesc, out: &mut [i32]) -> usize {
    let count = desc.fd_count.min(out.len());
    out[..count].copy_from_slice(&desc.open_fds[..count]);
    count
}

/// Read the cmdline for a process into `buf`.
///
/// Returns bytes written (arguments are NUL-separated as in Linux).
pub fn read_cmdline(desc: &ProcPidDesc, buf: &mut [u8]) -> Result<usize> {
    let len = desc.cmdline_len.min(buf.len());
    buf[..len].copy_from_slice(&desc.cmdline[..len]);
    Ok(len)
}

/// Read the environ for a process into `buf`.
///
/// Returns bytes written (variables are NUL-separated).
pub fn read_environ(desc: &ProcPidDesc, buf: &mut [u8]) -> Result<usize> {
    let len = desc.environ_len.min(buf.len());
    buf[..len].copy_from_slice(&desc.environ[..len]);
    Ok(len)
}

/// Return the exe path for the process.
pub fn read_exe_path(desc: &ProcPidDesc) -> &[u8] {
    &desc.exe_path[..desc.exe_path_len]
}

/// Return the cwd path for the process.
pub fn read_cwd_path(desc: &ProcPidDesc) -> &[u8] {
    &desc.cwd_path[..desc.cwd_path_len]
}
