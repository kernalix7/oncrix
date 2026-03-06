// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Remount operations for changing mount options on an already-mounted filesystem.
//!
//! Implements the `MS_REMOUNT` flag of `mount(2)`. Remounting allows changing
//! mount flags (e.g., read-only ↔ read-write) and filesystem-specific options
//! without unmounting and remounting the filesystem.

use oncrix_lib::{Error, Result};

/// Mount flags that can be changed via remount.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountFlags(pub u64);

impl MountFlags {
    /// Read-only mount.
    pub const MS_RDONLY: u64 = 1 << 0;
    /// Do not allow execution of binaries.
    pub const MS_NOEXEC: u64 = 1 << 1;
    /// Do not allow set-UID/GID bits to take effect.
    pub const MS_NOSUID: u64 = 1 << 2;
    /// Do not update access times.
    pub const MS_NOATIME: u64 = 1 << 10;
    /// Only update access time if it is older than mtime/ctime.
    pub const MS_RELATIME: u64 = 1 << 21;
    /// Strict access time update.
    pub const MS_STRICTATIME: u64 = 1 << 24;
    /// Remount an existing mount.
    pub const MS_REMOUNT: u64 = 1 << 5;
    /// Make mount point read-only.
    pub const MS_BIND: u64 = 1 << 12;

    /// Check if read-only flag is set.
    pub fn is_rdonly(self) -> bool {
        self.0 & Self::MS_RDONLY != 0
    }

    /// Check if noexec flag is set.
    pub fn is_noexec(self) -> bool {
        self.0 & Self::MS_NOEXEC != 0
    }

    /// Check if nosuid flag is set.
    pub fn is_nosuid(self) -> bool {
        self.0 & Self::MS_NOSUID != 0
    }

    /// Check if remount flag is set.
    pub fn is_remount(self) -> bool {
        self.0 & Self::MS_REMOUNT != 0
    }

    /// Mask to the flags that are changeable via remount.
    pub fn remountable_mask() -> u64 {
        Self::MS_RDONLY
            | Self::MS_NOEXEC
            | Self::MS_NOSUID
            | Self::MS_NOATIME
            | Self::MS_RELATIME
            | Self::MS_STRICTATIME
    }
}

/// Current state of a mounted filesystem relevant to remount.
#[derive(Debug, Clone, Copy)]
pub struct MountState {
    /// Mount ID.
    pub id: u32,
    /// Current flags.
    pub flags: MountFlags,
    /// Whether there are active writers (prevents rw→ro transitions).
    pub active_writers: u32,
    /// Whether the filesystem supports the requested flags.
    pub fs_supports_rw: bool,
}

impl MountState {
    /// Create a new mount state.
    pub const fn new(
        id: u32,
        flags: MountFlags,
        active_writers: u32,
        fs_supports_rw: bool,
    ) -> Self {
        MountState {
            id,
            flags,
            active_writers,
            fs_supports_rw,
        }
    }
}

/// Options for a remount operation.
#[derive(Debug, Clone, Copy)]
pub struct RemountOptions {
    /// New mount flags to apply.
    pub new_flags: MountFlags,
    /// Caller has CAP_SYS_ADMIN.
    pub privileged: bool,
}

impl RemountOptions {
    /// Create remount options.
    pub const fn new(new_flags: MountFlags, privileged: bool) -> Self {
        RemountOptions {
            new_flags,
            privileged,
        }
    }
}

/// Result of a remount operation.
#[derive(Debug, Clone, Copy)]
pub struct RemountResult {
    /// Flags after remount.
    pub applied_flags: MountFlags,
    /// Whether a read-write to read-only transition was performed.
    pub became_readonly: bool,
    /// Whether a read-only to read-write transition was performed.
    pub became_readwrite: bool,
}

/// Validate a remount request.
///
/// Checks privilege, flag compatibility, and writer presence for ro transitions.
pub fn validate_remount(state: &MountState, opts: &RemountOptions) -> Result<()> {
    if !opts.privileged {
        return Err(Error::PermissionDenied);
    }
    let new = opts.new_flags;
    // Transitioning to read-only is only allowed if there are no active writers.
    if new.is_rdonly() && !state.flags.is_rdonly() {
        if state.active_writers > 0 {
            return Err(Error::Busy);
        }
    }
    // Transitioning to read-write requires the filesystem to support it.
    if !new.is_rdonly() && state.flags.is_rdonly() {
        if !state.fs_supports_rw {
            return Err(Error::InvalidArgument);
        }
    }
    // Only remountable flags may change.
    let changed = state.flags.0 ^ new.0;
    if changed & !MountFlags::remountable_mask() != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Apply a remount operation.
pub fn do_remount(state: &MountState, opts: &RemountOptions) -> Result<RemountResult> {
    validate_remount(state, opts)?;
    let was_rdonly = state.flags.is_rdonly();
    let will_rdonly = opts.new_flags.is_rdonly();
    Ok(RemountResult {
        applied_flags: opts.new_flags,
        became_readonly: !was_rdonly && will_rdonly,
        became_readwrite: was_rdonly && !will_rdonly,
    })
}

/// Filesystem-specific remount option parser.
///
/// Parses a comma-separated option string and extracts known options.
pub struct RemountOptionParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> RemountOptionParser<'a> {
    /// Create a new parser.
    pub fn new(data: &'a [u8]) -> Self {
        RemountOptionParser { data, pos: 0 }
    }

    /// Parse the next key=value or bare key option.
    pub fn next_option(&mut self) -> Option<(&'a [u8], Option<&'a [u8]>)> {
        while self.pos < self.data.len() && self.data[self.pos] == b',' {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != b',' {
            self.pos += 1;
        }
        let token = &self.data[start..self.pos];
        // Split on '='.
        if let Some(eq) = token.iter().position(|&b| b == b'=') {
            Some((&token[..eq], Some(&token[eq + 1..])))
        } else {
            Some((token, None))
        }
    }
}

/// Registry of mount states for remount management.
pub struct RemountRegistry {
    states: [Option<MountState>; 64],
    count: usize,
}

impl RemountRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        RemountRegistry {
            states: [None; 64],
            count: 0,
        }
    }

    /// Register a mount state.
    pub fn register(&mut self, state: MountState) -> Result<()> {
        for slot in &mut self.states {
            if slot.is_none() {
                *slot = Some(state);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Update the flags for a mount after a successful remount.
    pub fn update_flags(&mut self, mount_id: u32, new_flags: MountFlags) -> Result<()> {
        for slot in &mut self.states {
            if let Some(s) = slot {
                if s.id == mount_id {
                    s.flags = new_flags;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Perform a remount on the registered state.
    pub fn remount(&mut self, mount_id: u32, opts: &RemountOptions) -> Result<RemountResult> {
        let state = self
            .states
            .iter()
            .flatten()
            .find(|s| s.id == mount_id)
            .copied();
        let state = state.ok_or(Error::NotFound)?;
        let result = do_remount(&state, opts)?;
        self.update_flags(mount_id, result.applied_flags)?;
        Ok(result)
    }

    /// Return the count of registered mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for RemountRegistry {
    fn default() -> Self {
        Self::new()
    }
}
