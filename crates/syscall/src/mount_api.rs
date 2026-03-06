// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! New mount API syscall handlers.
//!
//! Implements the Linux v5.2+ "new mount API" that replaces the monolithic
//! `mount(2)` with a set of composable operations:
//!
//! | Syscall       | Handler              | Purpose                            |
//! |---------------|----------------------|------------------------------------|
//! | `fsopen`      | [`do_fsopen`]        | Open a filesystem context          |
//! | `fsconfig`    | [`do_fsconfig`]      | Configure the filesystem context   |
//! | `fsmount`     | [`do_fsmount`]       | Create a mount from a context      |
//! | `move_mount`  | [`do_move_mount`]    | Attach / move a mount              |
//! | `open_tree`   | [`do_open_tree`]     | Clone or open a mount tree         |
//! | `mount_setattr` | [`do_mount_setattr`] | Change mount attributes          |
//!
//! # State machine
//!
//! ```text
//! fsopen() → FsContext{Blank}
//!     ↓ fsconfig(CREATE)
//! FsContext{Created}
//!     ↓ fsmount()
//! MountFd → move_mount() → attached to namespace
//! ```
//!
//! Reference: Linux `fs/fsopen.c`, `fs/namespace.c`,
//!            `include/uapi/linux/mount.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — fsopen flags
// ---------------------------------------------------------------------------

/// Clone the namespace's current root for the new context.
pub const FSOPEN_CLOEXEC: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// Constants — fsconfig command values
// ---------------------------------------------------------------------------

/// Set a string parameter (key + value).
pub const FSCONFIG_SET_STRING: u32 = 0;
/// Set a binary parameter (key + value + size).
pub const FSCONFIG_SET_BINARY: u32 = 1;
/// Set a path parameter (key + path fd + path string).
pub const FSCONFIG_SET_PATH: u32 = 2;
/// Set a file-descriptor parameter (key + fd).
pub const FSCONFIG_SET_FD: u32 = 3;
/// Create the superblock — no key/value.
pub const FSCONFIG_CMD_CREATE: u32 = 4;
/// Reconfigure an existing superblock.
pub const FSCONFIG_CMD_RECONFIGURE: u32 = 5;

// ---------------------------------------------------------------------------
// Constants — fsmount flags
// ---------------------------------------------------------------------------

/// Close the context fd on exec.
pub const FSMOUNT_CLOEXEC: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// Constants — move_mount flags
// ---------------------------------------------------------------------------

/// Follow symbolic links on the `from` path.
pub const MOVE_MOUNT_F_SYMLINKS: u32 = 0x0000_0001;
/// Allow automount on the `from` path.
pub const MOVE_MOUNT_F_AUTOMOUNTS: u32 = 0x0000_0002;
/// `from` fd refers to an empty path — use AT_EMPTY_PATH semantics.
pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;
/// Follow symbolic links on the `to` path.
pub const MOVE_MOUNT_T_SYMLINKS: u32 = 0x0000_0010;
/// Allow automount on the `to` path.
pub const MOVE_MOUNT_T_AUTOMOUNTS: u32 = 0x0000_0020;
/// `to` fd refers to an empty path.
pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x0000_0040;

/// All recognised `move_mount` flags.
const MOVE_MOUNT_KNOWN: u32 = MOVE_MOUNT_F_SYMLINKS
    | MOVE_MOUNT_F_AUTOMOUNTS
    | MOVE_MOUNT_F_EMPTY_PATH
    | MOVE_MOUNT_T_SYMLINKS
    | MOVE_MOUNT_T_AUTOMOUNTS
    | MOVE_MOUNT_T_EMPTY_PATH;

// ---------------------------------------------------------------------------
// Constants — open_tree flags
// ---------------------------------------------------------------------------

/// Clone the subtree rather than opening the existing one.
pub const OPEN_TREE_CLONE: u32 = 0x0000_0001;
/// Close the fd on exec.
pub const OPEN_TREE_CLOEXEC: u32 = 0x0000_0002;

// ---------------------------------------------------------------------------
// MountAttr flags (mount_setattr / fsmount)
// ---------------------------------------------------------------------------

/// Mount is read-only.
pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
/// No set-user-ID bits.
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
/// Block device access disallowed.
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
/// Execution disallowed.
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
/// Access-time update policy mask.
pub const MOUNT_ATTR__ATIME: u64 = 0x0000_0070;
/// Relative access-time updates.
pub const MOUNT_ATTR_RELATIME: u64 = 0x0000_0000;
/// Disable access-time updates entirely.
pub const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
/// Only update access time if modification time is more recent.
pub const MOUNT_ATTR_STRICTATIME: u64 = 0x0000_0020;
/// Always update directory access time.
pub const MOUNT_ATTR_NODIRATIME: u64 = 0x0000_0080;
/// Propagate idmapping from user namespace.
pub const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
/// Disallow symlink following.
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;

/// Mask of all recognised `MountAttr` attribute bits.
const MOUNT_ATTR_VALID: u64 = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR__ATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_IDMAP
    | MOUNT_ATTR_NOSYMFOLLOW;

// ---------------------------------------------------------------------------
// MountAttr structure (uAPI-compatible)
// ---------------------------------------------------------------------------

/// Mount attribute set used by `mount_setattr` and `fsmount`.
///
/// `attr_set` specifies which flags to set; `attr_clr` specifies which to
/// clear. Both are bitmasks of `MOUNT_ATTR_*` constants.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MountAttr {
    /// Attribute bits to set.
    pub attr_set: u64,
    /// Attribute bits to clear.
    pub attr_clr: u64,
    /// Access-time propagation flags.
    pub propagation: u64,
    /// User-namespace fd for idmapped mounts (0 = no idmapping).
    pub userns_fd: u64,
}

impl MountAttr {
    /// Validate that only known attribute bits are used.
    pub fn validate(&self) -> Result<()> {
        if self.attr_set & !MOUNT_ATTR_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.attr_clr & !MOUNT_ATTR_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        // attr_set and attr_clr must not overlap
        if self.attr_set & self.attr_clr != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FsconfigCmd — typed wrapper around the raw command constants
// ---------------------------------------------------------------------------

/// Typed filesystem configuration command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsconfigCmd {
    /// Set a string parameter (key, value).
    SetString,
    /// Set a binary parameter (key, value bytes).
    SetBinary,
    /// Set a path parameter (key, dirfd, path).
    SetPath,
    /// Set a file-descriptor parameter (key, fd).
    SetFd,
    /// Create the superblock.
    Create,
    /// Reconfigure an existing superblock.
    Reconfigure,
}

impl FsconfigCmd {
    /// Convert from the raw `FSCONFIG_*` constant.
    pub fn from_raw(cmd: u32) -> Result<Self> {
        match cmd {
            FSCONFIG_SET_STRING => Ok(Self::SetString),
            FSCONFIG_SET_BINARY => Ok(Self::SetBinary),
            FSCONFIG_SET_PATH => Ok(Self::SetPath),
            FSCONFIG_SET_FD => Ok(Self::SetFd),
            FSCONFIG_CMD_CREATE => Ok(Self::Create),
            FSCONFIG_CMD_RECONFIGURE => Ok(Self::Reconfigure),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns the raw numeric command code.
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::SetString => FSCONFIG_SET_STRING,
            Self::SetBinary => FSCONFIG_SET_BINARY,
            Self::SetPath => FSCONFIG_SET_PATH,
            Self::SetFd => FSCONFIG_SET_FD,
            Self::Create => FSCONFIG_CMD_CREATE,
            Self::Reconfigure => FSCONFIG_CMD_RECONFIGURE,
        }
    }
}

// ---------------------------------------------------------------------------
// FsContext state machine
// ---------------------------------------------------------------------------

/// Current lifecycle state of an [`FsContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsContextState {
    /// Opened but not yet configured.
    Blank,
    /// Parameters set; awaiting `CREATE`.
    Configured,
    /// Superblock created; ready for `fsmount`.
    Created,
    /// Superblock mounted; context is consumed.
    Mounted,
    /// Filesystem context has been closed/invalidated.
    Closed,
}

/// Maximum byte length of a filesystem type name.
const FS_TYPE_NAME_LEN: usize = 64;

/// Maximum number of configuration parameters in a single `FsContext`.
const MAX_FS_PARAMS: usize = 16;

/// Maximum byte length of a parameter key.
const PARAM_KEY_LEN: usize = 64;

/// Maximum byte length of a string parameter value.
const PARAM_VAL_LEN: usize = 256;

/// A key-value filesystem configuration parameter.
#[derive(Debug, Clone, Copy)]
pub struct FsParam {
    /// Parameter key (null-padded ASCII).
    key: [u8; PARAM_KEY_LEN],
    /// Key byte length.
    key_len: usize,
    /// Parameter value (null-padded, for string/binary parameters).
    value: [u8; PARAM_VAL_LEN],
    /// Value byte length.
    value_len: usize,
    /// Raw command type that produced this parameter.
    pub cmd: FsconfigCmd,
    /// File-descriptor value (used for `SetFd`/`SetPath`).
    pub fd: i32,
}

impl FsParam {
    /// Return the parameter key as a byte slice.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Return the parameter value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

/// An open filesystem context used to configure and create a mount.
pub struct FsContext {
    /// Filesystem type name (e.g. `b"ext4"`).
    fs_type: [u8; FS_TYPE_NAME_LEN],
    /// Byte length of `fs_type`.
    fs_type_len: usize,
    /// Configuration parameters accumulated via `fsconfig`.
    params: [Option<FsParam>; MAX_FS_PARAMS],
    /// Number of stored parameters.
    param_count: usize,
    /// Current lifecycle state.
    pub state: FsContextState,
    /// Flags from `fsopen`.
    pub flags: u32,
    /// Resulting mount ID after `fsmount` (`0` if not yet mounted).
    pub mount_id: u32,
}

impl FsContext {
    /// Create a blank filesystem context for `fs_type`.
    pub fn new(fs_type: &[u8], flags: u32) -> Result<Self> {
        if fs_type.is_empty() || fs_type.len() > FS_TYPE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if flags & !FSOPEN_CLOEXEC != 0 {
            return Err(Error::InvalidArgument);
        }
        let mut ctx = Self {
            fs_type: [0u8; FS_TYPE_NAME_LEN],
            fs_type_len: fs_type.len(),
            params: [const { None }; MAX_FS_PARAMS],
            param_count: 0,
            state: FsContextState::Blank,
            flags,
            mount_id: 0,
        };
        ctx.fs_type[..fs_type.len()].copy_from_slice(fs_type);
        Ok(ctx)
    }

    /// Return the filesystem type as a byte slice.
    pub fn fs_type_bytes(&self) -> &[u8] {
        &self.fs_type[..self.fs_type_len]
    }

    /// Add a configuration parameter. Returns `Err(Error::OutOfMemory)` if full
    /// or `Err(Error::InvalidArgument)` if called in the wrong state.
    pub fn add_param(&mut self, cmd: FsconfigCmd, key: &[u8], value: &[u8], fd: i32) -> Result<()> {
        match self.state {
            FsContextState::Blank | FsContextState::Configured => {}
            _ => return Err(Error::InvalidArgument),
        }
        if key.len() > PARAM_KEY_LEN || value.len() > PARAM_VAL_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.param_count >= MAX_FS_PARAMS {
            return Err(Error::OutOfMemory);
        }
        let mut p = FsParam {
            key: [0u8; PARAM_KEY_LEN],
            key_len: key.len(),
            value: [0u8; PARAM_VAL_LEN],
            value_len: value.len(),
            cmd,
            fd,
        };
        p.key[..key.len()].copy_from_slice(key);
        p.value[..value.len()].copy_from_slice(value);
        self.params[self.param_count] = Some(p);
        self.param_count += 1;
        self.state = FsContextState::Configured;
        Ok(())
    }

    /// Create the superblock — transition to [`FsContextState::Created`].
    pub fn create(&mut self) -> Result<()> {
        match self.state {
            FsContextState::Blank | FsContextState::Configured => {
                self.state = FsContextState::Created;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Reconfigure an already-created superblock.
    pub fn reconfigure(&mut self) -> Result<()> {
        if self.state != FsContextState::Created {
            return Err(Error::InvalidArgument);
        }
        // In a full implementation this would re-apply parameters to the live
        // superblock. Here we accept and return Ok.
        Ok(())
    }

    /// Iterate over all stored parameters.
    pub fn params(&self) -> impl Iterator<Item = &FsParam> {
        self.params[..self.param_count]
            .iter()
            .filter_map(|p| p.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Mount context registry (in-kernel mount table stub)
// ---------------------------------------------------------------------------

/// Maximum number of concurrently open filesystem contexts.
const _MAX_FS_CONTEXTS: usize = 32;

/// Maximum number of mounted filesystems tracked by the registry.
const MAX_MOUNTS: usize = 64;

/// A mounted filesystem entry.
#[derive(Debug, Clone, Copy)]
pub struct MountEntry {
    /// Unique mount ID.
    pub id: u32,
    /// Filesystem type name.
    fs_type: [u8; FS_TYPE_NAME_LEN],
    /// FS type name length.
    fs_type_len: usize,
    /// Current attribute flags.
    pub attr_flags: u64,
    /// Whether this mount is active.
    pub active: bool,
}

impl MountEntry {
    /// Return the filesystem type as a byte slice.
    pub fn fs_type_bytes(&self) -> &[u8] {
        &self.fs_type[..self.fs_type_len]
    }
}

/// In-kernel mount table.
pub struct MountRegistry {
    entries: [Option<MountEntry>; MAX_MOUNTS],
    count: usize,
    next_id: u32,
}

impl MountRegistry {
    /// Create an empty mount registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_MOUNTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Allocate a new mount entry returning its ID.
    pub fn alloc(&mut self, fs_type: &[u8], attr_flags: u64) -> Result<u32> {
        if self.count >= MAX_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        if fs_type.len() > FS_TYPE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let mut entry = MountEntry {
            id,
            fs_type: [0u8; FS_TYPE_NAME_LEN],
            fs_type_len: fs_type.len(),
            attr_flags,
            active: true,
        };
        entry.fs_type[..fs_type.len()].copy_from_slice(fs_type);
        // Find a free slot
        let slot = self
            .entries
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(entry);
        self.count += 1;
        Ok(id)
    }

    /// Look up a mount by ID.
    pub fn get(&self, id: u32) -> Option<&MountEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|m| m.id == id)
    }

    /// Look up a mount by ID (mutable).
    pub fn get_mut(&mut self, id: u32) -> Option<&mut MountEntry> {
        self.entries
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|m| m.id == id)
    }

    /// Remove a mount entry by ID.
    pub fn remove(&mut self, id: u32) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.map(|m| m.id) == Some(id) {
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Number of active mounts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no mounts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MountRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handler implementations
// ---------------------------------------------------------------------------

/// `fsopen(2)` — open a filesystem type context.
///
/// `fs_type_ptr` / `fs_type_len` identify the filesystem (e.g. `"ext4"`).
/// `flags` is a bitmask of `FSOPEN_*` constants.
///
/// Returns an opaque context index on success.
pub fn do_fsopen(fs_type: &[u8], flags: u32) -> Result<FsContext> {
    if flags & !FSOPEN_CLOEXEC != 0 {
        return Err(Error::InvalidArgument);
    }
    FsContext::new(fs_type, flags)
}

/// `fsconfig(2)` — configure a filesystem context.
///
/// `cmd_raw` is one of the `FSCONFIG_*` constants.
/// `key` and `value` carry string/binary data where applicable.
/// `aux` is an auxiliary file descriptor for `SET_FD` and `SET_PATH`.
pub fn do_fsconfig(
    ctx: &mut FsContext,
    cmd_raw: u32,
    key: &[u8],
    value: &[u8],
    aux: i32,
) -> Result<()> {
    let cmd = FsconfigCmd::from_raw(cmd_raw)?;
    match cmd {
        FsconfigCmd::SetString
        | FsconfigCmd::SetBinary
        | FsconfigCmd::SetPath
        | FsconfigCmd::SetFd => {
            if key.is_empty() {
                return Err(Error::InvalidArgument);
            }
            ctx.add_param(cmd, key, value, aux)
        }
        FsconfigCmd::Create => ctx.create(),
        FsconfigCmd::Reconfigure => ctx.reconfigure(),
    }
}

/// `fsmount(2)` — create a mount from a prepared filesystem context.
///
/// `flags` is a bitmask of `FSMOUNT_*` constants.
/// `attr_flags` is a bitmask of `MOUNT_ATTR_*` constants.
///
/// Returns the mount ID on success. The context transitions to
/// [`FsContextState::Mounted`].
pub fn do_fsmount(
    ctx: &mut FsContext,
    mount_registry: &mut MountRegistry,
    flags: u32,
    attr_flags: u64,
) -> Result<u32> {
    if flags & !FSMOUNT_CLOEXEC != 0 {
        return Err(Error::InvalidArgument);
    }
    if attr_flags & !MOUNT_ATTR_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if ctx.state != FsContextState::Created {
        return Err(Error::InvalidArgument);
    }
    let id = mount_registry.alloc(ctx.fs_type_bytes(), attr_flags)?;
    ctx.state = FsContextState::Mounted;
    ctx.mount_id = id;
    Ok(id)
}

/// `move_mount(2)` — attach or move a mount within the namespace.
///
/// `from_mount_id` identifies the mount to move (result of `fsmount` or
/// `open_tree`). `flags` is a bitmask of `MOVE_MOUNT_*` constants.
///
/// In this stub the operation succeeds if the mount ID exists in the registry.
pub fn do_move_mount(mount_registry: &MountRegistry, from_mount_id: u32, flags: u32) -> Result<()> {
    if flags & !MOVE_MOUNT_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    mount_registry
        .get(from_mount_id)
        .ok_or(Error::InvalidArgument)?;
    // In a full implementation: detach from current location, attach to target.
    Ok(())
}

/// `open_tree(2)` — open or clone an existing mount tree.
///
/// `mount_id` identifies the source mount. `flags` is a bitmask of
/// `OPEN_TREE_*` constants. When `OPEN_TREE_CLONE` is set a detached clone is
/// returned; otherwise the existing mount is re-used.
///
/// Returns the mount ID (same ID for open, new ID for clone).
pub fn do_open_tree(mount_registry: &mut MountRegistry, mount_id: u32, flags: u32) -> Result<u32> {
    let src = mount_registry.get(mount_id).ok_or(Error::InvalidArgument)?;
    if flags & OPEN_TREE_CLONE != 0 {
        // Clone: allocate a new mount entry for the same FS type.
        let fs_type_bytes = {
            let len = src.fs_type_len;
            let mut buf = [0u8; FS_TYPE_NAME_LEN];
            buf[..len].copy_from_slice(&src.fs_type[..len]);
            (buf, len)
        };
        let attr = src.attr_flags;
        let new_id = mount_registry.alloc(&fs_type_bytes.0[..fs_type_bytes.1], attr)?;
        Ok(new_id)
    } else {
        Ok(mount_id)
    }
}

/// `mount_setattr(2)` — atomically change mount attributes.
///
/// `mount_id` identifies the target mount.
/// `attr` carries the attribute bits to set and clear.
/// `size` is the size of the `MountAttr` structure as passed from userspace
/// (for forward compatibility; must equal `size_of::<MountAttr>()`).
pub fn do_mount_setattr(
    mount_registry: &mut MountRegistry,
    mount_id: u32,
    attr: &MountAttr,
    size: usize,
) -> Result<()> {
    if size != core::mem::size_of::<MountAttr>() {
        return Err(Error::InvalidArgument);
    }
    attr.validate()?;
    let entry = mount_registry
        .get_mut(mount_id)
        .ok_or(Error::InvalidArgument)?;
    // Clear requested bits first, then set.
    entry.attr_flags &= !attr.attr_clr;
    entry.attr_flags |= attr.attr_set;
    Ok(())
}

// ---------------------------------------------------------------------------
// Convenience: dispatch from raw syscall numbers
// ---------------------------------------------------------------------------

/// Raw `fsopen` syscall dispatch entry.
///
/// `fs_type` is the filesystem name slice validated from userspace.
/// Returns a new [`FsContext`] on success.
pub fn sys_fsopen(fs_type: &[u8], flags: u32) -> Result<FsContext> {
    do_fsopen(fs_type, flags)
}

/// Raw `fsmount` syscall dispatch entry.
pub fn sys_fsmount(
    ctx: &mut FsContext,
    mount_registry: &mut MountRegistry,
    flags: u32,
    attr_flags: u64,
) -> Result<u32> {
    do_fsmount(ctx, mount_registry, flags, attr_flags)
}

/// Raw `move_mount` syscall dispatch entry.
pub fn sys_move_mount(
    mount_registry: &MountRegistry,
    from_mount_id: u32,
    flags: u32,
) -> Result<()> {
    do_move_mount(mount_registry, from_mount_id, flags)
}

/// Raw `open_tree` syscall dispatch entry.
pub fn sys_open_tree(mount_registry: &mut MountRegistry, mount_id: u32, flags: u32) -> Result<u32> {
    do_open_tree(mount_registry, mount_id, flags)
}

/// Raw `mount_setattr` syscall dispatch entry.
pub fn sys_mount_setattr(
    mount_registry: &mut MountRegistry,
    mount_id: u32,
    attr: &MountAttr,
    size: usize,
) -> Result<()> {
    do_mount_setattr(mount_registry, mount_id, attr, size)
}
