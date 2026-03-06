// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Procfs `/proc/<pid>/environ` implementation.
//!
//! `/proc/<pid>/environ` exposes the environment of a process as a flat
//! buffer of NUL-separated `NAME=VALUE` strings, terminated by a double
//! NUL byte.  Access is restricted to the process owner or a privileged
//! user (capability `CAP_SYS_PTRACE`).

use oncrix_lib::{Error, Result};

/// Maximum total size of the environment buffer.
pub const ENVIRON_MAX_SIZE: usize = 1024 * 1024; // 1 MiB

/// Maximum length of a single environment variable (name=value).
pub const ENVIRON_VAR_MAX: usize = 4096;

/// Maximum number of environment variables tracked.
pub const ENVIRON_MAX_VARS: usize = 512;

/// A single environment variable (stored as `NAME=VALUE`).
#[derive(Debug, Clone)]
pub struct EnvVar {
    /// Flat `NAME=VALUE` byte string (NUL-terminated).
    pub data: [u8; ENVIRON_VAR_MAX],
    pub data_len: u16,
}

impl EnvVar {
    /// Create an environment variable from a `NAME=VALUE` slice.
    pub fn new(kv: &[u8]) -> Result<Self> {
        if kv.len() >= ENVIRON_VAR_MAX {
            return Err(Error::InvalidArgument);
        }
        if !kv.contains(&b'=') {
            return Err(Error::InvalidArgument);
        }
        let mut data = [0u8; ENVIRON_VAR_MAX];
        data[..kv.len()].copy_from_slice(kv);
        Ok(Self {
            data,
            data_len: kv.len() as u16,
        })
    }

    /// The full `NAME=VALUE` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.data_len as usize]
    }

    /// The variable name (bytes before the first `=`).
    pub fn name(&self) -> &[u8] {
        let kv = self.as_bytes();
        kv.iter()
            .position(|&b| b == b'=')
            .map(|i| &kv[..i])
            .unwrap_or(kv)
    }

    /// The variable value (bytes after the first `=`).
    pub fn value(&self) -> &[u8] {
        let kv = self.as_bytes();
        kv.iter()
            .position(|&b| b == b'=')
            .map(|i| &kv[i + 1..])
            .unwrap_or(b"")
    }
}

/// The environment of one process.
pub struct ProcEnviron {
    vars: [Option<EnvVar>; ENVIRON_MAX_VARS],
    count: usize,
}

impl ProcEnviron {
    /// Create an empty environment.
    pub const fn new() -> Self {
        Self {
            vars: [const { None }; ENVIRON_MAX_VARS],
            count: 0,
        }
    }

    /// Add a variable.
    pub fn push(&mut self, kv: &[u8]) -> Result<()> {
        if self.count >= ENVIRON_MAX_VARS {
            return Err(Error::OutOfMemory);
        }
        let var = EnvVar::new(kv)?;
        // Copy name into a local fixed buffer for comparison.
        let var_name_len = var.name().len();
        let mut name_buf = [0u8; ENVIRON_VAR_MAX];
        name_buf[..var_name_len].copy_from_slice(var.name());
        let name_cmp = &name_buf[..var_name_len];
        // If a variable with this name already exists, overwrite it.
        for slot in &mut self.vars[..self.count] {
            if let Some(existing) = slot.as_ref() {
                if existing.name() == name_cmp {
                    *slot = Some(var);
                    return Ok(());
                }
            }
        }
        self.vars[self.count] = Some(var);
        self.count += 1;
        Ok(())
    }

    /// Look up a variable by name.
    pub fn get(&self, name: &[u8]) -> Option<&EnvVar> {
        self.vars[..self.count]
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|v| v.name() == name)
    }

    /// Number of variables.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Serialize the environment into a flat NUL-separated buffer.
    ///
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = 0;
        for slot in &self.vars[..self.count] {
            if let Some(var) = slot.as_ref() {
                let bytes = var.as_bytes();
                if off + bytes.len() + 1 > buf.len() {
                    return Err(Error::InvalidArgument);
                }
                buf[off..off + bytes.len()].copy_from_slice(bytes);
                off += bytes.len();
                buf[off] = 0; // NUL separator
                off += 1;
            }
        }
        Ok(off)
    }

    /// Read bytes from the serialized environment into `out` at `offset`.
    pub fn read(&self, offset: usize, out: &mut [u8]) -> Result<usize> {
        // Serialize to a temporary stack buffer (up to 16 KiB for test).
        let mut tmp = [0u8; 16384];
        let len = self.serialize(&mut tmp)?;
        if offset >= len {
            return Ok(0);
        }
        let available = len - offset;
        let to_copy = available.min(out.len());
        out[..to_copy].copy_from_slice(&tmp[offset..offset + to_copy]);
        Ok(to_copy)
    }

    /// Iterate over all variables.
    pub fn iter(&self) -> impl Iterator<Item = &EnvVar> {
        self.vars[..self.count].iter().filter_map(|s| s.as_ref())
    }
}

impl Default for ProcEnviron {
    fn default() -> Self {
        Self::new()
    }
}

/// Ownership/permission check for `/proc/<pid>/environ` access.
///
/// Returns `Ok(())` if `accessing_uid` may read the environment of the
/// process with `proc_uid`, or `Err(PermissionDenied)` otherwise.
pub fn check_environ_access(accessing_uid: u32, proc_uid: u32, is_privileged: bool) -> Result<()> {
    if accessing_uid == proc_uid || is_privileged {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}
