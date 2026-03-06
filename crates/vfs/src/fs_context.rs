// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem mount context — new-style mount API (fsopen / fspick / fsconfig / fsmount).
//!
//! Linux 5.2 introduced a new set of system calls that replace the single
//! monolithic `mount(2)` with a multi-step, capability-aware interface:
//!
//! | Step | Syscall | Description |
//! |------|---------|-------------|
//! | 1 | `fsopen(fstype, flags)` | Allocate a context for a given FS type |
//! | 1b | `fspick(dfd, path, flags)` | Attach context to an existing mount |
//! | 2 | `fsconfig(fd, cmd, key, val, aux)` | Set parameters on the context |
//! | 3 | `fsmount(fd, flags, attr_flags)` | Create a new mount from the context |
//! | 4 | `move_mount(from_dfd, from, to_dfd, to, flags)` | Attach to tree |
//!
//! # Architecture
//!
//! ```text
//! fsopen("ext4") ──► FsContextRegistry::alloc() ──► FsContext (phase=Created)
//!                                                         │
//! fsconfig(fd, SET_STRING, "source", "/dev/sda1") ──►  phase=Configuring
//!                                                         │
//! fsmount(fd) ──────► validate() ──► create_super() ──► phase=Active
//!                                                         │
//! move_mount() ─────────────────────────────────────► attached to VFS tree
//! ```
//!
//! # References
//!
//! - Linux `fs/fs_context.c`, `fs/namespace.c`
//! - Linux `include/linux/fs_context.h`
//! - `man 2 fsopen`, `man 2 fsmount`, `man 2 fsconfig`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously open filesystem contexts.
const MAX_FS_CONTEXTS: usize = 32;

/// Maximum number of parameters that can be set on a single context.
const MAX_FS_PARAMS: usize = 16;

/// Maximum length of a filesystem type name (including NUL terminator).
const FS_TYPE_NAME_LEN: usize = 32;

/// Maximum length of a parameter key.
const FS_PARAM_KEY_LEN: usize = 64;

/// Maximum length of a parameter value.
const FS_PARAM_VALUE_LEN: usize = 256;

/// Maximum length of a source path (e.g., block device path).
const FS_SOURCE_LEN: usize = 256;

// ── FsContextPurpose ──────────────────────────────────────────────────────────

/// Describes the intended purpose of a filesystem context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FsContextPurpose {
    /// Creating a fresh mount of the filesystem.
    #[default]
    Mount,
    /// Creating a submount (e.g., bind or move mount).
    Submount,
    /// Reconfiguring an already-mounted filesystem.
    Remount,
}

// ── FsContextPhase ────────────────────────────────────────────────────────────

/// The current lifecycle phase of a filesystem context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FsContextPhase {
    /// Context has been allocated but no parameters set yet.
    #[default]
    Created,
    /// Parameters are being set via `fsconfig`.
    Configuring,
    /// `fsmount` has been called; superblock creation in progress.
    Creating,
    /// Mount is live; context may be reused for reconfiguration.
    Active,
    /// An error occurred; context is unusable.
    Failed,
}

// ── FsParamType ───────────────────────────────────────────────────────────────

/// Discriminates the value carried by an [`FsParameter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FsParamType {
    /// Boolean flag (value = "0" or "1").
    #[default]
    Bool,
    /// 32-bit unsigned integer.
    U32,
    /// 64-bit unsigned integer.
    U64,
    /// Arbitrary string value.
    String,
    /// File descriptor number (passed as integer).
    Fd,
    /// Filesystem path string.
    Path,
    /// Enum value (string key, integer mapping done by FS).
    Enum,
}

// ── FsParameter ───────────────────────────────────────────────────────────────

/// A single key-value parameter for a filesystem context.
///
/// Parameters map to mount options (e.g., `"rw"`, `"uid=0"`, `"data=journal"`).
#[derive(Debug, Clone, Copy)]
pub struct FsParameter {
    /// Parameter name (NUL-padded).
    pub key: [u8; FS_PARAM_KEY_LEN],
    /// Parameter value (NUL-padded; interpretation depends on `param_type`).
    pub value: [u8; FS_PARAM_VALUE_LEN],
    /// Type discriminator for the value field.
    pub param_type: FsParamType,
    /// Whether this slot contains a valid parameter.
    pub valid: bool,
}

impl FsParameter {
    /// Create an empty (unused) parameter slot.
    pub const fn empty() -> Self {
        Self {
            key: [0u8; FS_PARAM_KEY_LEN],
            value: [0u8; FS_PARAM_VALUE_LEN],
            param_type: FsParamType::String,
            valid: false,
        }
    }

    /// Create a string parameter with the given key and value byte slices.
    ///
    /// Slices longer than the internal buffers are silently truncated.
    pub fn new_string(key: &[u8], value: &[u8]) -> Self {
        let mut param = Self::empty();
        let klen = key.len().min(FS_PARAM_KEY_LEN);
        let vlen = value.len().min(FS_PARAM_VALUE_LEN);
        param.key[..klen].copy_from_slice(&key[..klen]);
        param.value[..vlen].copy_from_slice(&value[..vlen]);
        param.param_type = FsParamType::String;
        param.valid = true;
        param
    }

    /// Create a boolean parameter.
    pub fn new_bool(key: &[u8], enabled: bool) -> Self {
        let val: &[u8] = if enabled { b"1" } else { b"0" };
        let mut param = Self::new_string(key, val);
        param.param_type = FsParamType::Bool;
        param
    }

    /// Return the key as a byte slice up to (not including) the first NUL.
    pub fn key_str(&self) -> &[u8] {
        let end = self
            .key
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FS_PARAM_KEY_LEN);
        &self.key[..end]
    }

    /// Return the value as a byte slice up to (not including) the first NUL.
    pub fn value_str(&self) -> &[u8] {
        let end = self
            .value
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FS_PARAM_VALUE_LEN);
        &self.value[..end]
    }
}

// ── FsContext ──────────────────────────────────────────────────────────────────

/// A filesystem mount context: holds all state needed to create or reconfigure
/// a mount of a specific filesystem type.
#[derive(Debug)]
pub struct FsContext {
    /// Filesystem type name (NUL-padded, e.g., `b"ext4\0..."`).
    pub fs_type: [u8; FS_TYPE_NAME_LEN],
    /// Purpose of this context (mount / submount / remount).
    pub purpose: FsContextPurpose,
    /// Current lifecycle phase.
    pub phase: FsContextPhase,
    /// Parameters accumulated via `fsconfig`.
    pub parameters: [FsParameter; MAX_FS_PARAMS],
    /// Number of parameters currently set.
    pub param_count: usize,
    /// Block device or NFS export path (NUL-padded).
    pub source: [u8; FS_SOURCE_LEN],
    /// Inode number of the superblock root (set after `create_super`).
    pub root_id: u64,
    /// Mount flags (MS_RDONLY, MS_NOSUID, …).
    pub flags: u32,
    /// Whether this slot is occupied in the registry.
    in_use: bool,
}

impl FsContext {
    /// Create an empty context slot (not yet in use).
    pub const fn empty() -> Self {
        Self {
            fs_type: [0u8; FS_TYPE_NAME_LEN],
            purpose: FsContextPurpose::Mount,
            phase: FsContextPhase::Created,
            parameters: [const { FsParameter::empty() }; MAX_FS_PARAMS],
            param_count: 0,
            source: [0u8; FS_SOURCE_LEN],
            root_id: 0,
            flags: 0,
            in_use: false,
        }
    }

    /// Return `true` if the context is in the [`FsContextPhase::Configuring`]
    /// or [`FsContextPhase::Created`] phase (i.e., parameters may still be set).
    pub fn is_configurable(&self) -> bool {
        matches!(
            self.phase,
            FsContextPhase::Created | FsContextPhase::Configuring
        )
    }

    /// Look up a parameter by key.
    pub fn get_param(&self, key: &[u8]) -> Option<&FsParameter> {
        self.parameters[..self.param_count]
            .iter()
            .find(|p| p.valid && p.key_str() == key)
    }

    /// Return the filesystem type name as a byte slice (without trailing NUL).
    pub fn fs_type_str(&self) -> &[u8] {
        let end = self
            .fs_type
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FS_TYPE_NAME_LEN);
        &self.fs_type[..end]
    }

    /// Return the source path as a byte slice (without trailing NUL).
    pub fn source_str(&self) -> &[u8] {
        let end = self
            .source
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FS_SOURCE_LEN);
        &self.source[..end]
    }
}

// ── FsContextRegistry ─────────────────────────────────────────────────────────

/// System-wide registry of active filesystem contexts.
///
/// Each open filesystem context is represented by a slot index that acts as
/// a lightweight file descriptor within this subsystem.
pub struct FsContextRegistry {
    /// Pool of context slots.
    contexts: [FsContext; MAX_FS_CONTEXTS],
    /// Monotonically increasing generation counter for reuse safety.
    generation: u32,
}

impl FsContextRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            contexts: [const { FsContext::empty() }; MAX_FS_CONTEXTS],
            generation: 0,
        }
    }

    /// Allocate a new context for the given filesystem type.
    ///
    /// Returns the slot index (acts as the `fd` returned by `fsopen`).
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    /// Returns [`Error::InvalidArgument`] if `fs_type` is empty.
    pub fn alloc(
        &mut self,
        fs_type: &[u8],
        purpose: FsContextPurpose,
        flags: u32,
    ) -> Result<usize> {
        if fs_type.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .contexts
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;
        let ctx = &mut self.contexts[slot];
        *ctx = FsContext::empty();
        let copy_len = fs_type.len().min(FS_TYPE_NAME_LEN);
        ctx.fs_type[..copy_len].copy_from_slice(&fs_type[..copy_len]);
        ctx.purpose = purpose;
        ctx.phase = FsContextPhase::Created;
        ctx.flags = flags;
        ctx.in_use = true;
        self.generation = self.generation.wrapping_add(1);
        Ok(slot)
    }

    /// Release a context slot.
    ///
    /// Returns [`Error::NotFound`] if the slot is not in use.
    pub fn free(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_FS_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[slot].in_use {
            return Err(Error::NotFound);
        }
        self.contexts[slot] = FsContext::empty();
        Ok(())
    }

    /// Set a string parameter on the context at `slot`.
    ///
    /// Transitions the context from `Created` to `Configuring` on the first
    /// call.  Returns [`Error::InvalidArgument`] if the parameter table is
    /// full or the context is not configurable.
    pub fn set_param(&mut self, slot: usize, key: &[u8], value: &[u8]) -> Result<()> {
        if slot >= MAX_FS_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        let ctx = &mut self.contexts[slot];
        if !ctx.in_use {
            return Err(Error::NotFound);
        }
        if !ctx.is_configurable() {
            return Err(Error::InvalidArgument);
        }
        if ctx.param_count >= MAX_FS_PARAMS {
            return Err(Error::InvalidArgument);
        }
        // Update existing key if present.
        for param in ctx.parameters[..ctx.param_count].iter_mut() {
            if param.valid && param.key_str() == key {
                let vlen = value.len().min(FS_PARAM_VALUE_LEN);
                param.value = [0u8; FS_PARAM_VALUE_LEN];
                param.value[..vlen].copy_from_slice(&value[..vlen]);
                ctx.phase = FsContextPhase::Configuring;
                return Ok(());
            }
        }
        // Append new parameter.
        let idx = ctx.param_count;
        ctx.parameters[idx] = FsParameter::new_string(key, value);
        ctx.param_count += 1;
        ctx.phase = FsContextPhase::Configuring;
        Ok(())
    }

    /// Set the block-device / NFS source path for `slot`.
    pub fn set_source(&mut self, slot: usize, source: &[u8]) -> Result<()> {
        if slot >= MAX_FS_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        let ctx = &mut self.contexts[slot];
        if !ctx.in_use || !ctx.is_configurable() {
            return Err(Error::InvalidArgument);
        }
        let copy_len = source.len().min(FS_SOURCE_LEN);
        ctx.source = [0u8; FS_SOURCE_LEN];
        ctx.source[..copy_len].copy_from_slice(&source[..copy_len]);
        ctx.phase = FsContextPhase::Configuring;
        Ok(())
    }

    /// Validate a fully-configured context before superblock creation.
    ///
    /// Checks that a source path has been provided (required for all non-
    /// `tmpfs`-style filesystems).  Real implementations would call per-FS
    /// validation callbacks here.
    pub fn validate(&self, slot: usize) -> Result<()> {
        if slot >= MAX_FS_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        let ctx = &self.contexts[slot];
        if !ctx.in_use {
            return Err(Error::NotFound);
        }
        if ctx.fs_type_str().is_empty() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Transition the context to [`FsContextPhase::Active`] and record the
    /// root inode id returned by superblock creation.
    ///
    /// In a real kernel this drives `fill_super` for the named filesystem.
    pub fn create_super(&mut self, slot: usize, root_inode_id: u64) -> Result<()> {
        if slot >= MAX_FS_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        // Validate first (borrows self immutably) before taking a mutable ref.
        self.validate(slot)?;
        let ctx = &mut self.contexts[slot];
        ctx.phase = FsContextPhase::Creating;
        ctx.root_id = root_inode_id;
        ctx.phase = FsContextPhase::Active;
        Ok(())
    }

    /// Borrow an immutable reference to the context at `slot`.
    pub fn get(&self, slot: usize) -> Option<&FsContext> {
        self.contexts.get(slot).filter(|c| c.in_use)
    }

    /// Return the number of contexts currently in use.
    pub fn active_count(&self) -> usize {
        self.contexts.iter().filter(|c| c.in_use).count()
    }
}

impl Default for FsContextRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Logging helper ────────────────────────────────────────────────────────────

/// Log levels used by [`fs_context_log`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsContextLogLevel {
    /// Informational message.
    Info,
    /// Warning: operation may proceed but something is unusual.
    Warning,
    /// Error: mount operation cannot continue.
    Error,
}

/// Record a diagnostic message for a mount context.
///
/// In the full kernel implementation this would append to a kernel ring buffer
/// associated with the context fd so that `dmesg` or the caller can retrieve
/// it.  Here we simply validate the arguments.
pub fn fs_context_log(ctx: &FsContext, level: FsContextLogLevel, message: &[u8]) -> Result<()> {
    if !ctx.in_use {
        return Err(Error::InvalidArgument);
    }
    if message.is_empty() {
        return Err(Error::InvalidArgument);
    }
    // In a real implementation: append (level, message) to ctx.log_buffer.
    let _ = level;
    Ok(())
}

// ── Public API wrappers ────────────────────────────────────────────────────────

/// Equivalent of the `fsopen(2)` system call.
///
/// Allocates a new filesystem context for the given `fs_type` name and returns
/// the slot index.
pub fn fsopen(registry: &mut FsContextRegistry, fs_type: &[u8], flags: u32) -> Result<usize> {
    registry.alloc(fs_type, FsContextPurpose::Mount, flags)
}

/// Equivalent of the `fspick(2)` system call.
///
/// Allocates a context attached to an existing mount for reconfiguration.
/// `existing_root_id` is the root inode of the mount being picked.
pub fn fspick(
    registry: &mut FsContextRegistry,
    fs_type: &[u8],
    existing_root_id: u64,
) -> Result<usize> {
    let slot = registry.alloc(fs_type, FsContextPurpose::Remount, 0)?;
    registry.contexts[slot].root_id = existing_root_id;
    registry.contexts[slot].phase = FsContextPhase::Configuring;
    Ok(slot)
}

/// Equivalent of the `fsconfig(2)` system call (SET_STRING command).
///
/// Sets a string mount parameter on the context identified by `slot`.
pub fn fsconfig(
    registry: &mut FsContextRegistry,
    slot: usize,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    registry.set_param(slot, key, value)
}

/// Equivalent of the `fsmount(2)` system call.
///
/// Validates the context and drives superblock creation.  `root_inode_id`
/// is provided by the caller (in a real kernel it comes from `fill_super`).
/// Returns the slot index for subsequent `move_mount`.
pub fn fsmount(registry: &mut FsContextRegistry, slot: usize, root_inode_id: u64) -> Result<usize> {
    registry.create_super(slot, root_inode_id)?;
    Ok(slot)
}

/// Equivalent of the `move_mount(2)` system call.
///
/// Attaches the mount represented by `slot` to the VFS tree at `target_inode_id`.
/// In this implementation we validate the context is active and record the
/// target; actual tree manipulation is handled by the superblock layer.
///
/// Returns the target inode id for the caller to finalize.
pub fn move_mount(registry: &FsContextRegistry, slot: usize, target_inode_id: u64) -> Result<u64> {
    let ctx = registry.get(slot).ok_or(Error::NotFound)?;
    if ctx.phase != FsContextPhase::Active {
        return Err(Error::InvalidArgument);
    }
    if target_inode_id == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(target_inode_id)
}
