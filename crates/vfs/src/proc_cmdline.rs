// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Procfs `/proc/cmdline` and `/proc/<pid>/cmdline` implementations.
//!
//! `/proc/cmdline` exposes the kernel command line passed by the bootloader.
//! `/proc/<pid>/cmdline` exposes the null-separated argument vector of a
//! process, terminated by an extra NUL byte (Linux semantics).

use oncrix_lib::{Error, Result};

/// Maximum length of the kernel command line.
pub const KERNEL_CMDLINE_MAX: usize = 4096;

/// Maximum length of a process cmdline (/proc/<pid>/cmdline).
pub const PROC_PID_CMDLINE_MAX: usize = 131072; // 128 KiB

/// Kernel command line (static buffer set once at boot).
pub struct KernelCmdline {
    buf: [u8; KERNEL_CMDLINE_MAX],
    len: usize,
}

impl KernelCmdline {
    /// Create an empty command line.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; KERNEL_CMDLINE_MAX],
            len: 0,
        }
    }

    /// Set the kernel command line (called once during boot).
    pub fn set(&mut self, cmdline: &[u8]) -> Result<()> {
        if cmdline.len() >= KERNEL_CMDLINE_MAX {
            return Err(Error::InvalidArgument);
        }
        self.buf[..cmdline.len()].copy_from_slice(cmdline);
        self.buf[cmdline.len()] = b'\n'; // Linux appends a newline
        self.len = cmdline.len() + 1;
        Ok(())
    }

    /// Read the command line into `out` at byte offset `off`.
    ///
    /// Returns the number of bytes copied.
    pub fn read(&self, off: usize, out: &mut [u8]) -> usize {
        if off >= self.len || out.is_empty() {
            return 0;
        }
        let available = self.len - off;
        let to_copy = available.min(out.len());
        out[..to_copy].copy_from_slice(&self.buf[off..off + to_copy]);
        to_copy
    }

    /// Length of the command line including trailing newline.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the command line is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check whether a specific kernel parameter is present.
    ///
    /// Looks for `param=` or bare `param` in the command line.
    pub fn has_param(&self, param: &[u8]) -> bool {
        let cmdline = &self.buf[..self.len];
        let mut i = 0;
        while i < cmdline.len() {
            // Skip leading spaces.
            while i < cmdline.len() && cmdline[i] == b' ' {
                i += 1;
            }
            let start = i;
            // Advance to next space or end.
            while i < cmdline.len() && cmdline[i] != b' ' && cmdline[i] != b'\n' {
                i += 1;
            }
            let token = &cmdline[start..i];
            // Strip `=value` suffix for matching.
            let name = token.split(|&b| b == b'=').next().unwrap_or(token);
            if name == param {
                return true;
            }
        }
        false
    }

    /// Extract the value of `param=value` from the command line.
    ///
    /// Returns the value slice within `self.buf`, or `None` if not found.
    pub fn get_param_value(&self, param: &[u8]) -> Option<&[u8]> {
        let cmdline = &self.buf[..self.len];
        let mut i = 0;
        while i < cmdline.len() {
            while i < cmdline.len() && cmdline[i] == b' ' {
                i += 1;
            }
            let start = i;
            while i < cmdline.len() && cmdline[i] != b' ' && cmdline[i] != b'\n' {
                i += 1;
            }
            let token = &cmdline[start..i];
            if token.len() > param.len() + 1 && token[param.len()] == b'=' {
                if &token[..param.len()] == param {
                    return Some(&token[param.len() + 1..]);
                }
            }
        }
        None
    }
}

impl Default for KernelCmdline {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-process cmdline reader.
///
/// Stores a null-separated argument vector as a flat byte buffer.
/// The Linux format is: `arg0\0arg1\0…argN\0\0` (double-NUL at the end
/// when the process has finished exec).
pub struct ProcPidCmdline {
    buf: [u8; 512],
    len: usize,
}

impl ProcPidCmdline {
    /// Create an empty process cmdline.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; 512],
            len: 0,
        }
    }

    /// Build the cmdline from a slice of argument strings.
    pub fn from_args(args: &[&[u8]]) -> Result<Self> {
        let mut this = Self::new();
        let mut off = 0usize;
        for arg in args {
            if off + arg.len() + 1 > this.buf.len() {
                return Err(Error::OutOfMemory);
            }
            this.buf[off..off + arg.len()].copy_from_slice(arg);
            off += arg.len();
            this.buf[off] = 0; // NUL separator
            off += 1;
        }
        this.len = off;
        Ok(this)
    }

    /// Read bytes at offset `off`.
    pub fn read(&self, off: usize, out: &mut [u8]) -> usize {
        if off >= self.len || out.is_empty() {
            return 0;
        }
        let available = self.len - off;
        let to_copy = available.min(out.len());
        out[..to_copy].copy_from_slice(&self.buf[off..off + to_copy]);
        to_copy
    }

    /// Total length of the cmdline.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this cmdline is empty (zombie or kernel thread).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the first argument (argv[0]) as a byte slice.
    pub fn argv0(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        let end = self.buf[..self.len]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.len);
        &self.buf[..end]
    }
}

impl Default for ProcPidCmdline {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over the null-separated arguments in a `ProcPidCmdline`.
pub struct CmdlineIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CmdlineIter<'a> {
    /// Create an iterator over a cmdline's buffer.
    pub fn new(cmdline: &'a ProcPidCmdline) -> Self {
        Self {
            buf: &cmdline.buf[..cmdline.len],
            pos: 0,
        }
    }
}

impl<'a> Iterator for CmdlineIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        // Advance to next NUL.
        while self.pos < self.buf.len() && self.buf[self.pos] != 0 {
            self.pos += 1;
        }
        let arg = &self.buf[start..self.pos];
        if self.pos < self.buf.len() {
            self.pos += 1; // skip NUL
        }
        if arg.is_empty() {
            None // terminating double-NUL
        } else {
            Some(arg)
        }
    }
}
