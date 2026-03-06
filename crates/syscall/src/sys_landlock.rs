// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Landlock syscall group — create_ruleset, add_rule, restrict_self.
//!
//! Landlock is a Linux security module that lets any unprivileged process
//! sandbox itself.  A process builds a ruleset describing which access types
//! it wants to control, attaches access-grant rules to that ruleset, and then
//! commits the ruleset to itself with `restrict_self`.  From that point on,
//! any access type covered by the ruleset that is not explicitly granted is
//! denied.  Restrictions are monotonic — they can only be narrowed, never
//! lifted.
//!
//! # Syscall group
//!
//! | Syscall                      | Number (x86-64) | Purpose                           |
//! |------------------------------|-----------------|-----------------------------------|
//! | `landlock_create_ruleset(2)` | 444             | Allocate a new ruleset fd.        |
//! | `landlock_add_rule(2)`       | 445             | Add an access-grant rule.         |
//! | `landlock_restrict_self(2)`  | 446             | Enforce a ruleset on this thread. |
//!
//! # ABI versioning
//!
//! | ABI | Added capability                           |
//! |-----|--------------------------------------------|
//! | v1  | Filesystem access control (14 rights).    |
//! | v2  | `LANDLOCK_ACCESS_FS_REFER`                 |
//! | v3  | `LANDLOCK_ACCESS_FS_TRUNCATE`              |
//! | v4  | Network access control (TCP bind/connect). |
//!
//! # Workflow
//!
//! ```text
//! // 1. Create a ruleset handling filesystem reads.
//! let fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
//!
//! // 2. Allow read access to /usr.
//! let rule = LandlockPathBeneathAttr { allowed_access: FS_READ_FILE, parent_fd: usr_fd };
//! landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
//!
//! // 3. Enforce — from here any fs read outside /usr is denied.
//! landlock_restrict_self(fd, 0);
//! ```
//!
//! # Linux reference
//!
//! `security/landlock/syscalls.c`, `security/landlock/ruleset.c`

use oncrix_lib::{Error, Result};

// Re-export the rich implementation types and constants from the core module.
pub use crate::landlock_calls::{
    LANDLOCK_ABI_VERSION, LANDLOCK_ACCESS_FS_ALL, LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_MAKE_BLOCK, LANDLOCK_ACCESS_FS_MAKE_CHAR, LANDLOCK_ACCESS_FS_MAKE_DIR,
    LANDLOCK_ACCESS_FS_MAKE_FIFO, LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_MAKE_SOCK,
    LANDLOCK_ACCESS_FS_MAKE_SYM, LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_REFER, LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_ACCESS_NET_ALL,
    LANDLOCK_ACCESS_NET_BIND_TCP, LANDLOCK_ACCESS_NET_CONNECT_TCP, LANDLOCK_CREATE_RULESET_VERSION,
    LANDLOCK_RULE_NET_PORT, LANDLOCK_RULE_PATH_BENEATH, LandlockNetPortAttr,
    LandlockPathBeneathAttr, LandlockRule, LandlockRulesetAttr, check_fs_access, check_net_access,
    landlock_restriction_depth, sys_landlock_add_rule, sys_landlock_add_rule_net_port,
    sys_landlock_add_rule_path_beneath, sys_landlock_close_ruleset, sys_landlock_create_ruleset,
    sys_landlock_restrict_self, sys_landlock_ruleset_info,
};

// ---------------------------------------------------------------------------
// Session API
// ---------------------------------------------------------------------------

/// A Landlock session groups the three syscalls into a builder-style API.
///
/// This is a convenience layer on top of the three raw syscall handlers; it
/// does not change security semantics.
///
/// # Example
///
/// ```rust,ignore
/// let mut session = LandlockSession::new(
///     LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR, 0)?;
/// session.allow_path(LANDLOCK_ACCESS_FS_READ_FILE, parent_fd)?;
/// session.restrict(thread_id)?;
/// ```
pub struct LandlockSession {
    /// File descriptor (index) of the underlying ruleset.
    ruleset_fd: i32,
    /// Whether `restrict_self` has been called for this session.
    restricted: bool,
}

impl LandlockSession {
    /// Create a new Landlock session.
    ///
    /// Creates a ruleset that handles `handled_access_fs` filesystem rights
    /// and `handled_access_net` network rights.  At least one must be non-zero.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — both access masks are zero, or they
    ///   contain unknown bits.
    /// * [`Error::OutOfMemory`] — no free ruleset slots.
    pub fn new(handled_access_fs: u64, handled_access_net: u64) -> Result<Self> {
        let attr = LandlockRulesetAttr {
            handled_access_fs,
            handled_access_net,
        };
        let size = core::mem::size_of::<LandlockRulesetAttr>();
        let fd = sys_landlock_create_ruleset(Some(&attr), size, 0)?;
        Ok(Self {
            ruleset_fd: fd,
            restricted: false,
        })
    }

    /// Return the underlying ruleset file descriptor (index).
    pub const fn ruleset_fd(&self) -> i32 {
        self.ruleset_fd
    }

    /// Return `true` if `restrict_self` has been called on this session.
    pub const fn is_restricted(&self) -> bool {
        self.restricted
    }

    /// Add a filesystem path-beneath rule granting `allowed_access` to the
    /// hierarchy rooted at `parent_fd`.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — `allowed_access` is not a subset of the
    ///   handled filesystem rights, or `parent_fd < 0`.
    /// * [`Error::OutOfMemory`] — ruleset is full.
    /// * [`Error::Busy`] — `restrict_self` has already been called.
    pub fn allow_path(&mut self, allowed_access: u64, parent_fd: i32) -> Result<()> {
        if self.restricted {
            return Err(Error::Busy);
        }
        let attr = LandlockPathBeneathAttr::new(allowed_access, parent_fd);
        sys_landlock_add_rule_path_beneath(self.ruleset_fd, &attr, 0)
    }

    /// Add a network port rule granting `allowed_access` for `port`.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — `allowed_access` is not a subset of the
    ///   handled network rights.
    /// * [`Error::OutOfMemory`] — ruleset is full.
    /// * [`Error::Busy`] — `restrict_self` has already been called.
    pub fn allow_port(&mut self, allowed_access: u64, port: u16) -> Result<()> {
        if self.restricted {
            return Err(Error::Busy);
        }
        let attr = LandlockNetPortAttr::new(allowed_access, port);
        sys_landlock_add_rule_net_port(self.ruleset_fd, &attr, 0)
    }

    /// Enforce the session's ruleset on `thread_id`.
    ///
    /// After this call the session is "restricted" and no more rules may be
    /// added.  Calling `restrict` again on the same session appends another
    /// layer of restriction (stack semantics).
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — invalid ruleset fd.
    /// * [`Error::OutOfMemory`] — too many stacked rulesets for this thread.
    pub fn restrict(&mut self, thread_id: u64) -> Result<()> {
        sys_landlock_restrict_self(self.ruleset_fd, 0, thread_id)?;
        self.restricted = true;
        Ok(())
    }

    /// Return a summary of the ruleset: `(handled_fs, handled_net, rule_count)`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if the ruleset fd is invalid.
    pub fn info(&self) -> Result<(u64, u64, usize)> {
        sys_landlock_ruleset_info(self.ruleset_fd)
    }

    /// Close and destroy the underlying ruleset.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if the ruleset fd is already closed.
    pub fn close(self) -> Result<()> {
        sys_landlock_close_ruleset(self.ruleset_fd)
    }
}

// ---------------------------------------------------------------------------
// ABI version query helper
// ---------------------------------------------------------------------------

/// Query the highest Landlock ABI version supported by this kernel.
///
/// Calls `landlock_create_ruleset` with `LANDLOCK_CREATE_RULESET_VERSION`.
///
/// # Returns
///
/// The ABI version as a `u32` (currently `LANDLOCK_ABI_VERSION`).
pub fn query_abi_version() -> u32 {
    // Per the ABI contract, attrs must be None / size 0 for a version query.
    match sys_landlock_create_ruleset(None, 0, LANDLOCK_CREATE_RULESET_VERSION) {
        Ok(v) if v >= 0 => v as u32,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Batch rule helpers
// ---------------------------------------------------------------------------

/// Minimum description of a filesystem rule: `(allowed_access, parent_fd)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsRuleSpec {
    /// Allowed filesystem access bitmask.
    pub allowed_access: u64,
    /// Parent directory fd.
    pub parent_fd: i32,
}

/// Minimum description of a network rule: `(allowed_access, port)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetRuleSpec {
    /// Allowed network access bitmask.
    pub allowed_access: u64,
    /// TCP port number.
    pub port: u16,
}

/// Add a batch of filesystem rules to `session`.
///
/// Stops and returns an error if any individual rule fails validation.
pub fn add_fs_rules(session: &mut LandlockSession, rules: &[FsRuleSpec]) -> Result<()> {
    for rule in rules {
        session.allow_path(rule.allowed_access, rule.parent_fd)?;
    }
    Ok(())
}

/// Add a batch of network rules to `session`.
///
/// Stops and returns an error if any individual rule fails validation.
pub fn add_net_rules(session: &mut LandlockSession, rules: &[NetRuleSpec]) -> Result<()> {
    for rule in rules {
        session.allow_port(rule.allowed_access, rule.port)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Access-right helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `access_bits` is a valid filesystem access mask
/// (subset of `LANDLOCK_ACCESS_FS_ALL`).
pub const fn is_valid_fs_access(access_bits: u64) -> bool {
    access_bits != 0 && access_bits & !LANDLOCK_ACCESS_FS_ALL == 0
}

/// Returns `true` if `access_bits` is a valid network access mask
/// (subset of `LANDLOCK_ACCESS_NET_ALL`).
pub const fn is_valid_net_access(access_bits: u64) -> bool {
    access_bits != 0 && access_bits & !LANDLOCK_ACCESS_NET_ALL == 0
}

/// Decompose a filesystem access bitmask into a human-readable list.
///
/// Returns a fixed-length array of `(name, enabled)` pairs.  Each entry
/// reflects one `LANDLOCK_ACCESS_FS_*` bit.
pub fn decompose_fs_access(access: u64) -> [(&'static str, bool); 15] {
    [
        ("EXECUTE", access & LANDLOCK_ACCESS_FS_EXECUTE != 0),
        ("WRITE_FILE", access & LANDLOCK_ACCESS_FS_WRITE_FILE != 0),
        ("READ_FILE", access & LANDLOCK_ACCESS_FS_READ_FILE != 0),
        ("READ_DIR", access & LANDLOCK_ACCESS_FS_READ_DIR != 0),
        ("REMOVE_DIR", access & LANDLOCK_ACCESS_FS_REMOVE_DIR != 0),
        ("REMOVE_FILE", access & LANDLOCK_ACCESS_FS_REMOVE_FILE != 0),
        ("MAKE_CHAR", access & LANDLOCK_ACCESS_FS_MAKE_CHAR != 0),
        ("MAKE_DIR", access & LANDLOCK_ACCESS_FS_MAKE_DIR != 0),
        ("MAKE_REG", access & LANDLOCK_ACCESS_FS_MAKE_REG != 0),
        ("MAKE_SOCK", access & LANDLOCK_ACCESS_FS_MAKE_SOCK != 0),
        ("MAKE_FIFO", access & LANDLOCK_ACCESS_FS_MAKE_FIFO != 0),
        ("MAKE_BLOCK", access & LANDLOCK_ACCESS_FS_MAKE_BLOCK != 0),
        ("MAKE_SYM", access & LANDLOCK_ACCESS_FS_MAKE_SYM != 0),
        ("REFER", access & LANDLOCK_ACCESS_FS_REFER != 0),
        ("TRUNCATE", access & LANDLOCK_ACCESS_FS_TRUNCATE != 0),
    ]
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- LandlockSession ----

    #[test]
    fn session_create_and_info() {
        let session = LandlockSession::new(
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            0,
        )
        .unwrap();
        let (fs_handled, net_handled, rules) = session.info().unwrap();
        assert_eq!(
            fs_handled,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
        );
        assert_eq!(net_handled, 0);
        assert_eq!(rules, 0);
        session.close().unwrap();
    }

    #[test]
    fn session_allow_path_adds_rule() {
        let mut session = LandlockSession::new(LANDLOCK_ACCESS_FS_READ_FILE, 0).unwrap();
        session.allow_path(LANDLOCK_ACCESS_FS_READ_FILE, 5).unwrap();
        let (_, _, count) = session.info().unwrap();
        assert_eq!(count, 1);
        session.close().unwrap();
    }

    #[test]
    fn session_allow_port_adds_rule() {
        let mut session = LandlockSession::new(0, LANDLOCK_ACCESS_NET_BIND_TCP).unwrap();
        session
            .allow_port(LANDLOCK_ACCESS_NET_BIND_TCP, 8080)
            .unwrap();
        let (_, _, count) = session.info().unwrap();
        assert_eq!(count, 1);
        session.close().unwrap();
    }

    #[test]
    fn session_restrict_marks_restricted() {
        let mut session = LandlockSession::new(LANDLOCK_ACCESS_FS_EXECUTE, 0).unwrap();
        session.allow_path(LANDLOCK_ACCESS_FS_EXECUTE, 0).unwrap();
        assert!(!session.is_restricted());
        session.restrict(1001).unwrap();
        assert!(session.is_restricted());
        session.close().unwrap();
    }

    #[test]
    fn session_add_rule_after_restrict_rejected() {
        let mut session = LandlockSession::new(LANDLOCK_ACCESS_FS_EXECUTE, 0).unwrap();
        session.allow_path(LANDLOCK_ACCESS_FS_EXECUTE, 0).unwrap();
        session.restrict(2000).unwrap();
        assert_eq!(
            session.allow_path(LANDLOCK_ACCESS_FS_EXECUTE, 1),
            Err(Error::Busy)
        );
        session.close().unwrap();
    }

    #[test]
    fn session_both_zero_access_rejected() {
        assert_eq!(LandlockSession::new(0, 0), Err(Error::InvalidArgument));
    }

    // ---- ABI version query ----

    #[test]
    fn abi_version_is_current() {
        let v = query_abi_version();
        assert_eq!(v, LANDLOCK_ABI_VERSION);
    }

    // ---- Batch helpers ----

    #[test]
    fn add_fs_rules_batch() {
        let mut session =
            LandlockSession::new(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE, 0)
                .unwrap();
        let rules = [
            FsRuleSpec {
                allowed_access: LANDLOCK_ACCESS_FS_READ_FILE,
                parent_fd: 10,
            },
            FsRuleSpec {
                allowed_access: LANDLOCK_ACCESS_FS_EXECUTE,
                parent_fd: 11,
            },
        ];
        add_fs_rules(&mut session, &rules).unwrap();
        let (_, _, count) = session.info().unwrap();
        assert_eq!(count, 2);
        session.close().unwrap();
    }

    #[test]
    fn add_net_rules_batch() {
        let mut session = LandlockSession::new(
            0,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
        )
        .unwrap();
        let rules = [
            NetRuleSpec {
                allowed_access: LANDLOCK_ACCESS_NET_BIND_TCP,
                port: 80,
            },
            NetRuleSpec {
                allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port: 443,
            },
        ];
        add_net_rules(&mut session, &rules).unwrap();
        let (_, _, count) = session.info().unwrap();
        assert_eq!(count, 2);
        session.close().unwrap();
    }

    // ---- Access-right helpers ----

    #[test]
    fn valid_fs_access() {
        assert!(is_valid_fs_access(LANDLOCK_ACCESS_FS_READ_FILE));
        assert!(is_valid_fs_access(LANDLOCK_ACCESS_FS_ALL));
    }

    #[test]
    fn invalid_fs_access_zero() {
        assert!(!is_valid_fs_access(0));
    }

    #[test]
    fn invalid_fs_access_unknown_bits() {
        assert!(!is_valid_fs_access(LANDLOCK_ACCESS_FS_ALL | (1 << 20)));
    }

    #[test]
    fn valid_net_access() {
        assert!(is_valid_net_access(LANDLOCK_ACCESS_NET_BIND_TCP));
        assert!(is_valid_net_access(LANDLOCK_ACCESS_NET_ALL));
    }

    #[test]
    fn decompose_read_file_access() {
        let bits = decompose_fs_access(LANDLOCK_ACCESS_FS_READ_FILE);
        // Find READ_FILE entry.
        let read_file = bits.iter().find(|&&(name, _)| name == "READ_FILE").unwrap();
        assert!(read_file.1);
        // Execute should be off.
        let execute = bits.iter().find(|&&(name, _)| name == "EXECUTE").unwrap();
        assert!(!execute.1);
    }

    // ---- Access checking via core module ----

    #[test]
    fn check_access_unrestricted_thread_allowed() {
        // Thread 9999 has no restrictions.
        assert!(check_fs_access(9999, LANDLOCK_ACCESS_FS_READ_FILE, 5).is_ok());
    }

    #[test]
    fn check_access_restricted_thread_denied_without_rule() {
        let mut session = LandlockSession::new(LANDLOCK_ACCESS_FS_READ_FILE, 0).unwrap();
        // No rules added — restrict_self means all covered accesses are denied.
        session.restrict(77_777).unwrap();
        let result = check_fs_access(77_777, LANDLOCK_ACCESS_FS_READ_FILE, 10);
        assert_eq!(result, Err(Error::PermissionDenied));
        session.close().unwrap();
    }

    #[test]
    fn check_access_allowed_by_rule() {
        let mut session = LandlockSession::new(LANDLOCK_ACCESS_FS_READ_FILE, 0).unwrap();
        session
            .allow_path(LANDLOCK_ACCESS_FS_READ_FILE, 20)
            .unwrap();
        session.restrict(88_888).unwrap();
        // Access to fd 20 should be allowed.
        assert!(check_fs_access(88_888, LANDLOCK_ACCESS_FS_READ_FILE, 20).is_ok());
        session.close().unwrap();
    }

    #[test]
    fn restriction_depth_increments() {
        let mut s1 = LandlockSession::new(LANDLOCK_ACCESS_FS_READ_FILE, 0).unwrap();
        s1.allow_path(LANDLOCK_ACCESS_FS_READ_FILE, 0).unwrap();
        let mut s2 = LandlockSession::new(LANDLOCK_ACCESS_FS_EXECUTE, 0).unwrap();
        s2.allow_path(LANDLOCK_ACCESS_FS_EXECUTE, 0).unwrap();

        let tid = 55_555u64;
        assert_eq!(landlock_restriction_depth(tid), 0);
        s1.restrict(tid).unwrap();
        assert_eq!(landlock_restriction_depth(tid), 1);
        s2.restrict(tid).unwrap();
        assert_eq!(landlock_restriction_depth(tid), 2);

        s1.close().unwrap();
        s2.close().unwrap();
    }
}
