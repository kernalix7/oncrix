// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Script binary format handler (`#!` interpreter).
//!
//! Implements recognition and handling of Unix interpreter scripts.
//! When the kernel executes a file beginning with `#!`, it extracts
//! the interpreter path and optional argument, then re-executes
//! with the interpreter as the binary and the script as the first argument.
//!
//! Per POSIX.1-2024 XBD 3.226: the `#!` mechanism is implementation-defined
//! but universally supported.

use oncrix_lib::{Error, Result};

/// Magic bytes that identify a script: `#!`.
pub const SCRIPT_MAGIC: [u8; 2] = [b'#', b'!'];

/// Maximum length of the interpreter line (including `#!`).
pub const INTERP_LINE_MAX: usize = 256;

/// Maximum length of the interpreter path.
pub const INTERP_PATH_MAX: usize = 128;

/// Maximum length of the optional interpreter argument.
pub const INTERP_ARG_MAX: usize = 128;

/// Parsed `#!` interpreter directive.
#[derive(Debug, Clone, Copy)]
pub struct ScriptInterp {
    /// Interpreter path bytes.
    pub path: [u8; INTERP_PATH_MAX],
    /// Length of the path.
    pub path_len: usize,
    /// Optional single argument.
    pub arg: [u8; INTERP_ARG_MAX],
    /// Length of the optional argument (0 = no argument).
    pub arg_len: usize,
}

impl ScriptInterp {
    /// Create a new empty interpreter directive.
    pub const fn new() -> Self {
        ScriptInterp {
            path: [0u8; INTERP_PATH_MAX],
            path_len: 0,
            arg: [0u8; INTERP_ARG_MAX],
            arg_len: 0,
        }
    }

    /// Return the interpreter path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Return the argument as a byte slice.
    pub fn arg_bytes(&self) -> &[u8] {
        &self.arg[..self.arg_len]
    }

    /// Return true if an argument was found.
    pub fn has_arg(&self) -> bool {
        self.arg_len > 0
    }
}

impl Default for ScriptInterp {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a file header starts with `#!`.
///
/// Returns true if the first two bytes are `#!`.
pub fn is_script(header: &[u8]) -> bool {
    header.len() >= 2 && header[0] == b'#' && header[1] == b'!'
}

/// Parse a `#!` interpreter line from a file header.
///
/// The header must start with `#!`. The interpreter path and optional
/// argument are extracted, skipping whitespace.
///
/// Returns `Err(InvalidArgument)` for malformed or overlong lines.
pub fn parse_shebang(header: &[u8]) -> Result<ScriptInterp> {
    if !is_script(header) {
        return Err(Error::InvalidArgument);
    }
    let mut interp = ScriptInterp::new();
    // Skip '#!'
    let mut pos = 2;
    // Skip optional whitespace after #!
    while pos < header.len() && (header[pos] == b' ' || header[pos] == b'\t') {
        pos += 1;
    }
    // Read interpreter path (until whitespace or newline).
    let path_start = pos;
    while pos < header.len()
        && header[pos] != b' '
        && header[pos] != b'\t'
        && header[pos] != b'\n'
        && header[pos] != b'\r'
    {
        pos += 1;
        if pos - path_start > INTERP_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
    }
    let path_len = pos - path_start;
    if path_len == 0 {
        return Err(Error::InvalidArgument);
    }
    interp.path[..path_len].copy_from_slice(&header[path_start..path_start + path_len]);
    interp.path_len = path_len;
    // Skip whitespace between path and optional arg.
    while pos < header.len() && (header[pos] == b' ' || header[pos] == b'\t') {
        pos += 1;
    }
    // Read optional argument (until whitespace or newline).
    if pos < header.len() && header[pos] != b'\n' && header[pos] != b'\r' {
        let arg_start = pos;
        // Trim trailing whitespace from arg simultaneously.
        let mut arg_end = pos;
        while pos < header.len() && header[pos] != b'\n' && header[pos] != b'\r' {
            if header[pos] != b' ' && header[pos] != b'\t' {
                arg_end = pos + 1;
            }
            pos += 1;
            if pos - arg_start > INTERP_ARG_MAX {
                return Err(Error::InvalidArgument);
            }
        }
        let arg_len = arg_end - arg_start;
        if arg_len > 0 {
            interp.arg[..arg_len].copy_from_slice(&header[arg_start..arg_start + arg_len]);
            interp.arg_len = arg_len;
        }
    }
    Ok(interp)
}

/// Script execution context after shebang parsing.
#[derive(Debug, Clone, Copy)]
pub struct ScriptExecContext {
    /// Parsed interpreter directive.
    pub interp: ScriptInterp,
    /// Inode number of the script file.
    pub script_ino: u64,
    /// Flags inherited from the original exec (e.g., close-on-exec).
    pub exec_flags: u32,
}

impl ScriptExecContext {
    /// Create a new script execution context.
    pub const fn new(interp: ScriptInterp, script_ino: u64, exec_flags: u32) -> Self {
        ScriptExecContext {
            interp,
            script_ino,
            exec_flags,
        }
    }
}

/// Build the new argument vector for interpreter execution.
///
/// The new argv is: `[interp_path, optional_arg, script_path, original_argv[1..]...]`.
/// Writes up to `out.len()` pointers; returns the actual count.
pub fn build_interp_argv<'a>(
    ctx: &'a ScriptExecContext,
    script_path: &'a [u8],
    original_argv: &[&'a [u8]],
    out: &mut [&'a [u8]; 64],
) -> Result<usize> {
    let mut idx = 0;
    // Interpreter path.
    if idx >= 64 {
        return Err(Error::InvalidArgument);
    }
    out[idx] = ctx.interp.path_bytes();
    idx += 1;
    // Optional interpreter argument.
    if ctx.interp.has_arg() {
        if idx >= 64 {
            return Err(Error::InvalidArgument);
        }
        out[idx] = ctx.interp.arg_bytes();
        idx += 1;
    }
    // Script path.
    if idx >= 64 {
        return Err(Error::InvalidArgument);
    }
    out[idx] = script_path;
    idx += 1;
    // Original argv[1..] (skip argv[0] which was the script).
    for arg in original_argv.iter().skip(1) {
        if idx >= 64 {
            return Err(Error::InvalidArgument);
        }
        out[idx] = arg;
        idx += 1;
    }
    Ok(idx)
}

/// Registry of known safe interpreter paths (allowlist).
pub struct InterpAllowlist {
    paths: [[u8; INTERP_PATH_MAX]; 16],
    lens: [usize; 16],
    count: usize,
}

impl InterpAllowlist {
    /// Create a new empty allowlist.
    pub const fn new() -> Self {
        InterpAllowlist {
            paths: [[0u8; INTERP_PATH_MAX]; 16],
            lens: [0usize; 16],
            count: 0,
        }
    }

    /// Add an interpreter path to the allowlist.
    pub fn add(&mut self, path: &[u8]) -> Result<()> {
        if self.count >= 16 {
            return Err(Error::OutOfMemory);
        }
        if path.len() > INTERP_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        self.paths[self.count][..path.len()].copy_from_slice(path);
        self.lens[self.count] = path.len();
        self.count += 1;
        Ok(())
    }

    /// Check if an interpreter path is in the allowlist.
    pub fn is_allowed(&self, path: &[u8]) -> bool {
        for i in 0..self.count {
            if self.lens[i] == path.len() && self.paths[i][..self.lens[i]] == *path {
                return true;
            }
        }
        false
    }

    /// Return the count of registered paths.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for InterpAllowlist {
    fn default() -> Self {
        Self::new()
    }
}
