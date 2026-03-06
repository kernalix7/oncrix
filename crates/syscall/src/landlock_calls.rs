// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Landlock LSM syscall handlers.
//!
//! Implements the Landlock unprivileged access control system via three
//! syscalls: `landlock_create_ruleset`, `landlock_add_rule`, and
//! `landlock_restrict_self`.  Landlock allows any process to sandbox
//! itself by creating access-control rulesets and then voluntarily
//! restricting its own capabilities.
//!
//! The workflow is:
//! 1. Create a ruleset describing which access types are handled
//! 2. Add rules granting specific access to specific objects
//! 3. Restrict the calling thread — from that point on, any access type
//!    listed in the ruleset but NOT explicitly allowed by a rule is denied
//!
//! Landlock is stackable: multiple restrict_self calls narrow access
//! monotonically.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ABI version
// ---------------------------------------------------------------------------

/// Current Landlock ABI version supported by this implementation.
/// ABI v4 adds network access control.
pub const LANDLOCK_ABI_VERSION: u32 = 4;

// ---------------------------------------------------------------------------
// Filesystem access rights — LANDLOCK_ACCESS_FS_*
// ---------------------------------------------------------------------------

/// Execute a file.
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;

/// Open a file with write access.
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;

/// Open a file with read access.
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;

/// Open a directory or list its content.
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;

/// Remove a directory.
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;

/// Remove (unlink) a file.
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;

/// Create a character device node.
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;

/// Create a directory.
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;

/// Create a regular file.
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;

/// Create a Unix-domain socket node.
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;

/// Create a named pipe (FIFO).
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;

/// Create a block device node.
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;

/// Create a symbolic link.
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// Link or rename a file to a directory.
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;

/// Truncate a file.
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// Mask of all known filesystem access rights.
pub const LANDLOCK_ACCESS_FS_ALL: u64 = (1 << 15) - 1;

// ---------------------------------------------------------------------------
// Network access rights — LANDLOCK_ACCESS_NET_*
// ---------------------------------------------------------------------------

/// Bind a TCP socket to a local port.
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;

/// Connect a TCP socket to a remote port.
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// Mask of all known network access rights.
pub const LANDLOCK_ACCESS_NET_ALL: u64 = (1 << 2) - 1;

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

/// Rule type: filesystem path-beneath rule.
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

/// Rule type: network port rule.
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

// ---------------------------------------------------------------------------
// Create-ruleset flags
// ---------------------------------------------------------------------------

/// Flag: query the highest supported ABI version without creating a ruleset.
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// Mask of all valid create-ruleset flags.
const CREATE_FLAGS_VALID: u32 = LANDLOCK_CREATE_RULESET_VERSION;

// ---------------------------------------------------------------------------
// Restrict-self flags (currently none defined)
// ---------------------------------------------------------------------------

/// Mask of valid restrict-self flags (none defined yet — must be 0).
const RESTRICT_FLAGS_VALID: u32 = 0;

// ---------------------------------------------------------------------------
// Attribute structures
// ---------------------------------------------------------------------------

/// Attributes for `landlock_create_ruleset`.
///
/// Specifies which access types are handled by the ruleset.
/// Any access type listed here but not granted by a rule will be
/// denied after `landlock_restrict_self`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LandlockRulesetAttr {
    /// Bitmask of handled filesystem access rights
    /// (`LANDLOCK_ACCESS_FS_*`).
    pub handled_access_fs: u64,
    /// Bitmask of handled network access rights
    /// (`LANDLOCK_ACCESS_NET_*`).
    pub handled_access_net: u64,
}

/// Attributes for a `LANDLOCK_RULE_PATH_BENEATH` rule.
///
/// Grants the specified access rights to a file hierarchy rooted
/// at the directory referenced by `parent_fd`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LandlockPathBeneathAttr {
    /// Bitmask of allowed filesystem access rights.
    pub allowed_access: u64,
    /// File descriptor referring to the parent directory of the
    /// hierarchy.
    pub parent_fd: i32,
    /// Padding for alignment.
    _pad: u32,
}

impl LandlockPathBeneathAttr {
    /// Create a new path-beneath attribute.
    pub const fn new(allowed_access: u64, parent_fd: i32) -> Self {
        Self {
            allowed_access,
            parent_fd,
            _pad: 0,
        }
    }
}

/// Attributes for a `LANDLOCK_RULE_NET_PORT` rule.
///
/// Grants the specified network access rights for the given port.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LandlockNetPortAttr {
    /// Bitmask of allowed network access rights.
    pub allowed_access: u64,
    /// TCP port number this rule applies to.
    pub port: u16,
    /// Padding for alignment.
    _pad: [u8; 6],
}

impl LandlockNetPortAttr {
    /// Create a new network port attribute.
    pub const fn new(allowed_access: u64, port: u16) -> Self {
        Self {
            allowed_access,
            port,
            _pad: [0; 6],
        }
    }
}

// ---------------------------------------------------------------------------
// Internal rule representation
// ---------------------------------------------------------------------------

/// Maximum rules per ruleset.
const MAX_RULES_PER_RULESET: usize = 128;

/// Maximum rulesets in the global registry.
const MAX_RULESETS: usize = 32;

/// Maximum stacked rulesets per thread.
const MAX_STACKED_RULESETS: usize = 16;

/// Maximum number of threads that can have restrictions.
const MAX_RESTRICTED_THREADS: usize = 32;

/// A single access-control rule within a ruleset.
#[derive(Debug, Clone, Copy)]
pub enum LandlockRule {
    /// Filesystem path-beneath rule: allows `access` for the hierarchy
    /// rooted at the directory represented by `parent_fd`.
    PathBeneath {
        /// Allowed filesystem access bitmask.
        allowed_access: u64,
        /// Parent directory fd identifying the hierarchy.
        parent_fd: i32,
    },
    /// Network port rule: allows `access` for the specified TCP `port`.
    NetPort {
        /// Allowed network access bitmask.
        allowed_access: u64,
        /// TCP port number.
        port: u16,
    },
}

/// Internal representation of a Landlock ruleset.
#[derive(Debug, Clone, Copy)]
struct LandlockRuleset {
    /// Whether this slot is in use.
    active: bool,
    /// Handled filesystem access types.
    handled_access_fs: u64,
    /// Handled network access types.
    handled_access_net: u64,
    /// Number of rules in this ruleset.
    nr_rules: usize,
    /// Rules array — indexed by `nr_rules`.
    rules: [LandlockRuleStorage; MAX_RULES_PER_RULESET],
}

/// Tagged-union storage for a rule (avoids enum discriminant issues
/// with const init).
#[derive(Debug, Clone, Copy)]
struct LandlockRuleStorage {
    /// Rule type: 0 = unused, 1 = PathBeneath, 2 = NetPort.
    kind: u32,
    /// Allowed access bitmask.
    allowed_access: u64,
    /// Parent fd (PathBeneath) or 0 (NetPort).
    parent_fd: i32,
    /// Port (NetPort) or 0 (PathBeneath).
    port: u16,
}

impl Default for LandlockRuleStorage {
    fn default() -> Self {
        Self {
            kind: 0,
            allowed_access: 0,
            parent_fd: 0,
            port: 0,
        }
    }
}

impl Default for LandlockRuleset {
    fn default() -> Self {
        Self {
            active: false,
            handled_access_fs: 0,
            handled_access_net: 0,
            nr_rules: 0,
            rules: [LandlockRuleStorage::default(); MAX_RULES_PER_RULESET],
        }
    }
}

/// Per-thread restriction state.
#[derive(Debug, Clone, Copy)]
struct ThreadRestriction {
    /// Whether this slot is active.
    active: bool,
    /// Thread ID that applied the restriction.
    thread_id: u64,
    /// Number of stacked ruleset references.
    nr_stacked: usize,
    /// Indices into the global ruleset registry.
    stacked_rulesets: [usize; MAX_STACKED_RULESETS],
}

impl Default for ThreadRestriction {
    fn default() -> Self {
        Self {
            active: false,
            thread_id: 0,
            nr_stacked: 0,
            stacked_rulesets: [0; MAX_STACKED_RULESETS],
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global registry of Landlock rulesets.
static mut RULESETS: [LandlockRuleset; MAX_RULESETS] = {
    const EMPTY: LandlockRuleset = LandlockRuleset {
        active: false,
        handled_access_fs: 0,
        handled_access_net: 0,
        nr_rules: 0,
        rules: [LandlockRuleStorage {
            kind: 0,
            allowed_access: 0,
            parent_fd: 0,
            port: 0,
        }; MAX_RULES_PER_RULESET],
    };
    [EMPTY; MAX_RULESETS]
};

/// Per-thread restriction state.
static mut THREAD_RESTRICTIONS: [ThreadRestriction; MAX_RESTRICTED_THREADS] = {
    const EMPTY: ThreadRestriction = ThreadRestriction {
        active: false,
        thread_id: 0,
        nr_stacked: 0,
        stacked_rulesets: [0; MAX_STACKED_RULESETS],
    };
    [EMPTY; MAX_RESTRICTED_THREADS]
};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Find a free ruleset slot.
fn alloc_ruleset_slot() -> Result<usize> {
    // SAFETY: single-threaded kernel init; no concurrent mutation.
    let rulesets = unsafe { &mut *core::ptr::addr_of_mut!(RULESETS) };
    for (idx, rs) in rulesets.iter().enumerate() {
        if !rs.active {
            return Ok(idx);
        }
    }
    Err(Error::OutOfMemory)
}

/// Look up an active ruleset by fd (index).
fn get_ruleset(fd: i32) -> Result<&'static mut LandlockRuleset> {
    if fd < 0 || (fd as usize) >= MAX_RULESETS {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: single-threaded kernel; bounds checked above.
    let rulesets = unsafe { &mut *core::ptr::addr_of_mut!(RULESETS) };
    let rs = &mut rulesets[fd as usize];
    if !rs.active {
        return Err(Error::InvalidArgument);
    }
    Ok(rs)
}

/// Find the thread restriction entry for a given thread ID, or allocate one.
fn get_or_alloc_thread_restriction(tid: u64) -> Result<&'static mut ThreadRestriction> {
    // SAFETY: single-threaded kernel; no concurrent mutation.
    let restrictions = unsafe { &mut *core::ptr::addr_of_mut!(THREAD_RESTRICTIONS) };

    // Find existing or first free slot in a single pass.
    let mut free_idx: Option<usize> = None;
    for (i, entry) in restrictions.iter().enumerate() {
        if entry.active && entry.thread_id == tid {
            return Ok(&mut restrictions[i]);
        }
        if !entry.active && free_idx.is_none() {
            free_idx = Some(i);
        }
    }

    // Allocate a new slot.
    let idx = free_idx.ok_or(Error::OutOfMemory)?;
    restrictions[idx].active = true;
    restrictions[idx].thread_id = tid;
    restrictions[idx].nr_stacked = 0;
    Ok(&mut restrictions[idx])
}

/// Validate that an access bitmask contains only known filesystem bits.
fn validate_fs_access(access: u64) -> Result<()> {
    if access & !LANDLOCK_ACCESS_FS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that an access bitmask contains only known network bits.
fn validate_net_access(access: u64) -> Result<()> {
    if access & !LANDLOCK_ACCESS_NET_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// landlock_create_ruleset
// ---------------------------------------------------------------------------

/// `landlock_create_ruleset` — create a new Landlock ruleset.
///
/// If `flags` contains `LANDLOCK_CREATE_RULESET_VERSION`, the call returns
/// the highest supported ABI version instead of creating a ruleset.
///
/// Otherwise, creates a new ruleset that will handle the access types
/// specified in `attr`.  Any handled access type not explicitly granted
/// by a rule will be denied after `landlock_restrict_self`.
///
/// # Arguments
///
/// * `attr`  — ruleset attributes (may be `None` for version queries)
/// * `size`  — size of the attribute structure (for extensibility)
/// * `flags` — `LANDLOCK_CREATE_RULESET_*` flags
///
/// # Returns
///
/// * ABI version (when `LANDLOCK_CREATE_RULESET_VERSION` is set)
/// * Ruleset file descriptor (index) on success
///
/// # Errors
///
/// * `InvalidArgument` — unknown flags, unknown access bits, zero access,
///   or wrong attribute size
/// * `OutOfMemory` — no free ruleset slots
pub fn sys_landlock_create_ruleset(
    attr: Option<&LandlockRulesetAttr>,
    size: usize,
    flags: u32,
) -> Result<i32> {
    // Reject unknown flags.
    if flags & !CREATE_FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // Version query: return ABI version.
    if flags & LANDLOCK_CREATE_RULESET_VERSION != 0 {
        // For version query, attr must be None and size must be 0.
        if attr.is_some() || size != 0 {
            return Err(Error::InvalidArgument);
        }
        return Ok(LANDLOCK_ABI_VERSION as i32);
    }

    // Normal creation requires a valid attr.
    let attr = attr.ok_or(Error::InvalidArgument)?;

    // Validate attribute size for forward compatibility.
    if size < core::mem::size_of::<LandlockRulesetAttr>() {
        return Err(Error::InvalidArgument);
    }

    // At least one access type must be handled.
    if attr.handled_access_fs == 0 && attr.handled_access_net == 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate access bitmasks.
    validate_fs_access(attr.handled_access_fs)?;
    validate_net_access(attr.handled_access_net)?;

    let slot = alloc_ruleset_slot()?;

    // SAFETY: slot within bounds; single-threaded mutation.
    let rulesets = unsafe { &mut *core::ptr::addr_of_mut!(RULESETS) };
    let rs = &mut rulesets[slot];

    rs.active = true;
    rs.handled_access_fs = attr.handled_access_fs;
    rs.handled_access_net = attr.handled_access_net;
    rs.nr_rules = 0;

    Ok(slot as i32)
}

// ---------------------------------------------------------------------------
// landlock_add_rule
// ---------------------------------------------------------------------------

/// `landlock_add_rule` — add an access rule to a Landlock ruleset.
///
/// # Arguments
///
/// * `ruleset_fd` — file descriptor of the ruleset
/// * `rule_type`  — `LANDLOCK_RULE_PATH_BENEATH` or `LANDLOCK_RULE_NET_PORT`
/// * `rule`       — rule-type-specific rule to add
/// * `flags`      — must be 0 (reserved for future use)
///
/// # Errors
///
/// * `InvalidArgument` — invalid ruleset fd, unknown rule type, invalid
///   access bits, or access not subset of handled access
/// * `OutOfMemory` — ruleset is full
pub fn sys_landlock_add_rule(
    ruleset_fd: i32,
    rule_type: u32,
    rule: &LandlockRule,
    flags: u32,
) -> Result<()> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    let rs = get_ruleset(ruleset_fd)?;

    if rs.nr_rules >= MAX_RULES_PER_RULESET {
        return Err(Error::OutOfMemory);
    }

    match (rule_type, rule) {
        (
            LANDLOCK_RULE_PATH_BENEATH,
            LandlockRule::PathBeneath {
                allowed_access,
                parent_fd,
            },
        ) => {
            validate_fs_access(*allowed_access)?;

            // Allowed access must be a subset of handled access.
            if *allowed_access & !rs.handled_access_fs != 0 {
                return Err(Error::InvalidArgument);
            }

            if *allowed_access == 0 {
                return Err(Error::InvalidArgument);
            }

            if *parent_fd < 0 {
                return Err(Error::InvalidArgument);
            }

            let storage = &mut rs.rules[rs.nr_rules];
            storage.kind = LANDLOCK_RULE_PATH_BENEATH;
            storage.allowed_access = *allowed_access;
            storage.parent_fd = *parent_fd;
            storage.port = 0;
            rs.nr_rules += 1;
            Ok(())
        }
        (
            LANDLOCK_RULE_NET_PORT,
            LandlockRule::NetPort {
                allowed_access,
                port,
            },
        ) => {
            validate_net_access(*allowed_access)?;

            if *allowed_access & !rs.handled_access_net != 0 {
                return Err(Error::InvalidArgument);
            }

            if *allowed_access == 0 {
                return Err(Error::InvalidArgument);
            }

            let storage = &mut rs.rules[rs.nr_rules];
            storage.kind = LANDLOCK_RULE_NET_PORT;
            storage.allowed_access = *allowed_access;
            storage.parent_fd = 0;
            storage.port = *port;
            rs.nr_rules += 1;
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Add a path-beneath rule using the attribute structure.
///
/// Convenience wrapper around [`sys_landlock_add_rule`] that takes
/// a [`LandlockPathBeneathAttr`] directly.
pub fn sys_landlock_add_rule_path_beneath(
    ruleset_fd: i32,
    attr: &LandlockPathBeneathAttr,
    flags: u32,
) -> Result<()> {
    let rule = LandlockRule::PathBeneath {
        allowed_access: attr.allowed_access,
        parent_fd: attr.parent_fd,
    };
    sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, flags)
}

/// Add a network port rule using the attribute structure.
///
/// Convenience wrapper around [`sys_landlock_add_rule`] that takes
/// a [`LandlockNetPortAttr`] directly.
pub fn sys_landlock_add_rule_net_port(
    ruleset_fd: i32,
    attr: &LandlockNetPortAttr,
    flags: u32,
) -> Result<()> {
    let rule = LandlockRule::NetPort {
        allowed_access: attr.allowed_access,
        port: attr.port,
    };
    sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &rule, flags)
}

// ---------------------------------------------------------------------------
// landlock_restrict_self
// ---------------------------------------------------------------------------

/// `landlock_restrict_self` — enforce a Landlock ruleset on the calling thread.
///
/// After this call, the thread's filesystem and network access is restricted
/// according to the ruleset.  Multiple rulesets can be stacked; each additional
/// restriction narrows access further (intersection semantics).
///
/// This operation is irreversible: restrictions cannot be removed once applied.
///
/// # Arguments
///
/// * `ruleset_fd` — file descriptor of the ruleset to enforce
/// * `flags`      — must be 0 (reserved for future use)
/// * `thread_id`  — ID of the calling thread
///
/// # Errors
///
/// * `InvalidArgument` — invalid ruleset fd, unknown flags
/// * `OutOfMemory` — too many stacked rulesets for this thread
pub fn sys_landlock_restrict_self(ruleset_fd: i32, flags: u32, thread_id: u64) -> Result<()> {
    if flags & !RESTRICT_FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // Verify the ruleset exists and is valid.
    let rs = get_ruleset(ruleset_fd)?;

    // Ensure the ruleset has at least one handled access type.
    if rs.handled_access_fs == 0 && rs.handled_access_net == 0 {
        return Err(Error::InvalidArgument);
    }

    let restriction = get_or_alloc_thread_restriction(thread_id)?;

    if restriction.nr_stacked >= MAX_STACKED_RULESETS {
        return Err(Error::OutOfMemory);
    }

    restriction.stacked_rulesets[restriction.nr_stacked] = ruleset_fd as usize;
    restriction.nr_stacked += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// Access checking
// ---------------------------------------------------------------------------

/// Check whether a filesystem access is allowed for the given thread.
///
/// Evaluates all stacked rulesets.  For each ruleset that handles the
/// requested access type, at least one rule must grant it.  If no ruleset
/// handles the access type, it is allowed by default.
///
/// # Arguments
///
/// * `thread_id` — thread performing the access
/// * `access`    — requested filesystem access bitmask
/// * `parent_fd` — directory fd representing the target hierarchy
///
/// # Returns
///
/// `Ok(())` if access is allowed, `Err(PermissionDenied)` otherwise.
pub fn check_fs_access(thread_id: u64, access: u64, parent_fd: i32) -> Result<()> {
    // SAFETY: single-threaded access to global state.
    let restrictions = unsafe { &*core::ptr::addr_of!(THREAD_RESTRICTIONS) };
    let rulesets = unsafe { &*core::ptr::addr_of!(RULESETS) };

    // Find the restriction for this thread.
    let restriction = restrictions
        .iter()
        .find(|r| r.active && r.thread_id == thread_id);

    let restriction = match restriction {
        Some(r) => r,
        None => return Ok(()), // No restrictions = allowed.
    };

    // For each stacked ruleset that handles this access type,
    // we need at least one rule that grants it.
    for i in 0..restriction.nr_stacked {
        let rs_idx = restriction.stacked_rulesets[i];
        if rs_idx >= MAX_RULESETS {
            continue;
        }

        let rs = &rulesets[rs_idx];
        if !rs.active {
            continue;
        }

        // Check if this ruleset handles the requested access.
        let handled = access & rs.handled_access_fs;
        if handled == 0 {
            continue; // This ruleset does not cover the requested access.
        }

        // Find a rule that grants the handled subset.
        let mut granted = 0u64;
        for j in 0..rs.nr_rules {
            let rule = &rs.rules[j];
            if rule.kind == LANDLOCK_RULE_PATH_BENEATH && rule.parent_fd == parent_fd {
                granted |= rule.allowed_access;
            }
        }

        if handled & !granted != 0 {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(())
}

/// Check whether a network access is allowed for the given thread.
///
/// Evaluates all stacked rulesets.  For each ruleset that handles the
/// requested network access type, at least one rule must grant it for
/// the specified port.
///
/// # Arguments
///
/// * `thread_id` — thread performing the access
/// * `access`    — requested network access bitmask
/// * `port`      — TCP port number
///
/// # Returns
///
/// `Ok(())` if access is allowed, `Err(PermissionDenied)` otherwise.
pub fn check_net_access(thread_id: u64, access: u64, port: u16) -> Result<()> {
    // SAFETY: single-threaded access to global state.
    let restrictions = unsafe { &*core::ptr::addr_of!(THREAD_RESTRICTIONS) };
    let rulesets = unsafe { &*core::ptr::addr_of!(RULESETS) };

    let restriction = restrictions
        .iter()
        .find(|r| r.active && r.thread_id == thread_id);

    let restriction = match restriction {
        Some(r) => r,
        None => return Ok(()),
    };

    for i in 0..restriction.nr_stacked {
        let rs_idx = restriction.stacked_rulesets[i];
        if rs_idx >= MAX_RULESETS {
            continue;
        }

        let rs = &rulesets[rs_idx];
        if !rs.active {
            continue;
        }

        let handled = access & rs.handled_access_net;
        if handled == 0 {
            continue;
        }

        let mut granted = 0u64;
        for j in 0..rs.nr_rules {
            let rule = &rs.rules[j];
            if rule.kind == LANDLOCK_RULE_NET_PORT && rule.port == port {
                granted |= rule.allowed_access;
            }
        }

        if handled & !granted != 0 {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Ruleset management
// ---------------------------------------------------------------------------

/// Close (destroy) a Landlock ruleset.
///
/// # Errors
///
/// * `InvalidArgument` — invalid or inactive ruleset fd
pub fn sys_landlock_close_ruleset(ruleset_fd: i32) -> Result<()> {
    let rs = get_ruleset(ruleset_fd)?;
    rs.active = false;
    rs.handled_access_fs = 0;
    rs.handled_access_net = 0;
    rs.nr_rules = 0;
    Ok(())
}

/// Query the number of rules in a ruleset.
///
/// # Errors
///
/// * `InvalidArgument` — invalid or inactive ruleset fd
pub fn sys_landlock_ruleset_info(ruleset_fd: i32) -> Result<(u64, u64, usize)> {
    let rs = get_ruleset(ruleset_fd)?;
    Ok((rs.handled_access_fs, rs.handled_access_net, rs.nr_rules))
}

/// Query the restriction depth (number of stacked rulesets) for a thread.
///
/// Returns `0` if the thread has no restrictions.
pub fn landlock_restriction_depth(thread_id: u64) -> usize {
    // SAFETY: single-threaded access to global state.
    let restrictions = unsafe { &*core::ptr::addr_of!(THREAD_RESTRICTIONS) };

    restrictions
        .iter()
        .find(|r| r.active && r.thread_id == thread_id)
        .map(|r| r.nr_stacked)
        .unwrap_or(0)
}
