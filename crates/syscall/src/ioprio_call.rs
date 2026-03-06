// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O priority syscall interface — `ioprio_set(2)` / `ioprio_get(2)`.
//!
//! Provides a higher-level, type-safe wrapper around the raw I/O priority
//! management syscalls.  This module focuses on the per-thread and per-process
//! I/O scheduling class and priority data types, along with a dispatcher
//! that validates arguments and routes to the appropriate handler.
//!
//! # I/O Priority Encoding
//!
//! An I/O priority is a 16-bit value:
//!
//! ```text
//! bits [15:13]  class   (RT=1, BE=2, IDLE=3, NONE=0)
//! bits [12:0]   data    (level 0..7 for RT/BE; must be 0 for IDLE/NONE)
//! ```
//!
//! # Scheduling Classes
//!
//! | Class | Value | Description |
//! |-------|-------|-------------|
//! | `None` | 0 | No explicit class; inherit from process nice value |
//! | `RealTime` | 1 | Real-time I/O, served before everything else |
//! | `BestEffort` | 2 | Default class for normal processes |
//! | `Idle` | 3 | Only served when no other I/O is pending |
//!
//! # Operations
//!
//! | Syscall | Handler | Purpose |
//! |---------|---------|---------|
//! | `ioprio_get` | [`sys_ioprio_get`] | Read I/O priority of a target |
//! | `ioprio_set` | [`sys_ioprio_set`] | Set I/O priority of a target |
//!
//! # Security
//!
//! - Setting `RealTime` class requires `CAP_SYS_ADMIN` (simplified: uid 0).
//! - Non-root callers may only modify their own I/O priority.
//! - Non-root callers may only inspect processes they own.
//!
//! # References
//!
//! - Linux: `include/uapi/linux/ioprio.h`, `block/ioprio.c`
//! - `man ioprio_set(2)`, `man ioprio_get(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bit shift for the I/O priority class field.
const CLASS_SHIFT: u32 = 13;

/// Mask for the data (level) portion of the packed priority.
const DATA_MASK: u16 = 0x1FFF;

/// Maximum valid priority level within RT or BE classes.
pub const MAX_IOPRIO_LEVEL: u8 = 7;

/// Maximum number of entries in the priority registry.
const REGISTRY_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// IoprioClass — I/O scheduling class
// ---------------------------------------------------------------------------

/// I/O scheduling class.
///
/// Determines the scheduling behaviour at the block layer.
/// Values match the Linux `IOPRIO_CLASS_*` constants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoprioClass {
    /// No explicit class set; the kernel derives a class from nice value.
    None = 0,
    /// Real-time class.  Guaranteed disk time before all other classes.
    RealTime = 1,
    /// Best-effort class (default for most user processes).
    BestEffort = 2,
    /// Idle class.  I/O is served only when no other class needs the disk.
    Idle = 3,
}

impl IoprioClass {
    /// Construct from a raw 3-bit class value.
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::RealTime),
            2 => Some(Self::BestEffort),
            3 => Some(Self::Idle),
            _ => Option::None,
        }
    }

    /// Return the raw numeric value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this class carries a meaningful priority level.
    pub const fn uses_level(self) -> bool {
        matches!(self, Self::RealTime | Self::BestEffort)
    }

    /// Return a human-readable name for the class.
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RealTime => "realtime",
            Self::BestEffort => "best-effort",
            Self::Idle => "idle",
        }
    }
}

// ---------------------------------------------------------------------------
// IoprioData — decoded priority value
// ---------------------------------------------------------------------------

/// A fully decoded I/O priority combining class and level.
///
/// The level is meaningful only for `RealTime` and `BestEffort`; it must
/// be zero for `None` and `Idle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoprioData {
    /// The I/O scheduling class.
    pub class: IoprioClass,
    /// Priority level within the class (0 = highest, 7 = lowest).
    pub level: u8,
}

impl IoprioData {
    /// Default I/O priority: `BestEffort` at level 4.
    pub const DEFAULT: Self = Self {
        class: IoprioClass::BestEffort,
        level: 4,
    };

    /// Real-time priority at the highest level (0).
    pub const RT_HIGHEST: Self = Self {
        class: IoprioClass::RealTime,
        level: 0,
    };

    /// Idle priority.
    pub const IDLE: Self = Self {
        class: IoprioClass::Idle,
        level: 0,
    };

    /// Pack into the 16-bit wire encoding.
    pub const fn encode(self) -> u16 {
        ((self.class.as_u8() as u16) << CLASS_SHIFT as u16) | ((self.level as u16) & DATA_MASK)
    }

    /// Decode from a 16-bit wire value, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when:
    /// - The class bits are unrecognised.
    /// - The level exceeds [`MAX_IOPRIO_LEVEL`] for RT/BE.
    /// - The level is non-zero for `None` or `Idle`.
    pub fn decode(raw: u16) -> Result<Self> {
        let class_bits = (raw >> CLASS_SHIFT as u16) as u8;
        let level = (raw & DATA_MASK) as u8;

        let class = IoprioClass::from_raw(class_bits).ok_or(Error::InvalidArgument)?;

        if class.uses_level() {
            if level > MAX_IOPRIO_LEVEL {
                return Err(Error::InvalidArgument);
            }
        } else if level != 0 {
            return Err(Error::InvalidArgument);
        }

        Ok(Self { class, level })
    }

    /// Return `true` if this represents a real-time priority.
    pub const fn is_realtime(self) -> bool {
        matches!(self.class, IoprioClass::RealTime)
    }

    /// Return `true` if this represents an idle priority.
    pub const fn is_idle(self) -> bool {
        matches!(self.class, IoprioClass::Idle)
    }
}

impl Default for IoprioData {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ---------------------------------------------------------------------------
// IoPriorityLevel — named priority levels within RT/BE
// ---------------------------------------------------------------------------

/// Named priority levels for the `RealTime` and `BestEffort` classes.
///
/// Provides semantic names for the eight valid priority levels (0..7).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IoPriorityLevel {
    /// Level 0 — highest priority within the class.
    Highest = 0,
    /// Level 1.
    VeryHigh = 1,
    /// Level 2.
    High = 2,
    /// Level 3.
    AboveNormal = 3,
    /// Level 4 — default for `BestEffort`.
    Normal = 4,
    /// Level 5.
    BelowNormal = 5,
    /// Level 6.
    Low = 6,
    /// Level 7 — lowest priority within the class.
    Lowest = 7,
}

impl IoPriorityLevel {
    /// Construct from a raw level value.
    ///
    /// Returns `None` if the value exceeds 7.
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Highest),
            1 => Some(Self::VeryHigh),
            2 => Some(Self::High),
            3 => Some(Self::AboveNormal),
            4 => Some(Self::Normal),
            5 => Some(Self::BelowNormal),
            6 => Some(Self::Low),
            7 => Some(Self::Lowest),
            _ => Option::None,
        }
    }

    /// Return the raw numeric value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Build an [`IoprioData`] by combining this level with a class.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the class does not use levels.
    pub fn with_class(self, class: IoprioClass) -> Result<IoprioData> {
        if !class.uses_level() {
            return Err(Error::InvalidArgument);
        }
        Ok(IoprioData {
            class,
            level: self.as_u8(),
        })
    }
}

// ---------------------------------------------------------------------------
// Target selector — who argument
// ---------------------------------------------------------------------------

/// Which entity to target for I/O priority get/set.
///
/// Matches the Linux `IOPRIO_WHO_*` constants.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoprioTarget {
    /// A single process (PID).  0 means the calling process.
    Process = 1,
    /// All processes in a process group (PGID).
    ProcessGroup = 2,
    /// All processes owned by a user (UID).
    User = 3,
}

impl IoprioTarget {
    /// Construct from the raw `which` syscall argument.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unrecognised values.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Process),
            2 => Ok(Self::ProcessGroup),
            3 => Ok(Self::User),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw numeric value.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Per-process I/O priority record
// ---------------------------------------------------------------------------

/// Per-thread I/O priority record stored in the registry.
#[derive(Debug, Clone, Copy)]
pub struct IoprioEntry {
    /// Thread/process identifier.
    pub pid: u64,
    /// Thread group ID (leader PID).
    pub tgid: u64,
    /// Process group ID.
    pub pgid: u64,
    /// Owner UID.
    pub uid: u32,
    /// Current I/O priority.
    pub priority: IoprioData,
    /// Whether this slot is active.
    pub active: bool,
}

impl IoprioEntry {
    /// Create an inactive (empty) slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            tgid: 0,
            pgid: 0,
            uid: 0,
            priority: IoprioData::DEFAULT,
            active: false,
        }
    }

    /// Create an active entry with the default priority.
    pub const fn new(pid: u64, tgid: u64, pgid: u64, uid: u32) -> Self {
        Self {
            pid,
            tgid,
            pgid,
            uid,
            priority: IoprioData::DEFAULT,
            active: true,
        }
    }
}

// ---------------------------------------------------------------------------
// IoprioRegistry — priority tracking table
// ---------------------------------------------------------------------------

/// Registry of per-thread I/O priorities.
///
/// Provides O(n) lookup by PID, PGID, or UID within a fixed-capacity
/// array.  In a production kernel this would be integrated into the
/// process table; the standalone registry is useful for unit testing
/// and early bring-up.
pub struct IoprioRegistry {
    /// Fixed-size slot array.
    entries: [IoprioEntry; REGISTRY_CAPACITY],
    /// Number of active entries.
    count: usize,
}

impl IoprioRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { IoprioEntry::empty() }; REGISTRY_CAPACITY],
            count: 0,
        }
    }

    /// Return the number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry contains no active entries.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register a new entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full.
    pub fn register(&mut self, entry: IoprioEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.active {
                *slot = entry;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove an entry by PID.
    pub fn unregister(&mut self, pid: u64) {
        for slot in self.entries.iter_mut() {
            if slot.active && slot.pid == pid {
                slot.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Look up an active entry by PID.
    pub fn find_by_pid(&self, pid: u64) -> Option<&IoprioEntry> {
        self.entries.iter().find(|e| e.active && e.pid == pid)
    }

    /// Look up a mutable entry by PID.
    fn find_by_pid_mut(&mut self, pid: u64) -> Option<&mut IoprioEntry> {
        self.entries.iter_mut().find(|e| e.active && e.pid == pid)
    }

    /// Look up the first active entry by PGID.
    pub fn find_by_pgid(&self, pgid: u64) -> Option<&IoprioEntry> {
        self.entries.iter().find(|e| e.active && e.pgid == pgid)
    }

    /// Look up a mutable entry by PGID (first match).
    fn find_by_pgid_mut(&mut self, pgid: u64) -> Option<&mut IoprioEntry> {
        self.entries.iter_mut().find(|e| e.active && e.pgid == pgid)
    }

    /// Look up the first active entry by UID.
    pub fn find_by_uid(&self, uid: u32) -> Option<&IoprioEntry> {
        self.entries.iter().find(|e| e.active && e.uid == uid)
    }

    /// Look up a mutable entry by UID (first match).
    fn find_by_uid_mut(&mut self, uid: u32) -> Option<&mut IoprioEntry> {
        self.entries.iter_mut().find(|e| e.active && e.uid == uid)
    }

    /// Count entries matching a specific PGID.
    pub fn count_by_pgid(&self, pgid: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| e.active && e.pgid == pgid)
            .count()
    }

    /// Count entries matching a specific UID.
    pub fn count_by_uid(&self, uid: u32) -> usize {
        self.entries
            .iter()
            .filter(|e| e.active && e.uid == uid)
            .count()
    }
}

impl Default for IoprioRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_ioprio_get — get I/O priority
// ---------------------------------------------------------------------------

/// Handler for `ioprio_get(2)`.
///
/// Reads the I/O priority of the entity identified by `target` and `who`.
///
/// # Arguments
///
/// * `registry`   - I/O priority registry.
/// * `target`     - Which entity type to query (process, pgroup, user).
/// * `who`        - Identifier; 0 means the calling process for
///                  [`IoprioTarget::Process`].
/// * `caller_pid` - PID of the calling process.
/// * `caller_uid` - UID of the calling process.
///
/// # Returns
///
/// The packed 16-bit I/O priority value on success (as `u32`).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  - Bad `target` value.
/// * [`Error::NotFound`]         - Target entity does not exist.
/// * [`Error::PermissionDenied`] - Caller does not own the target
///   and is not privileged.
pub fn sys_ioprio_get(
    registry: &IoprioRegistry,
    target: i32,
    who: u64,
    caller_pid: u64,
    caller_uid: u32,
) -> Result<u32> {
    let target = IoprioTarget::from_raw(target)?;

    let entry = match target {
        IoprioTarget::Process => {
            let pid = if who == 0 { caller_pid } else { who };
            registry.find_by_pid(pid).ok_or(Error::NotFound)?
        }
        IoprioTarget::ProcessGroup => registry.find_by_pgid(who).ok_or(Error::NotFound)?,
        IoprioTarget::User => {
            let uid = who as u32;
            registry.find_by_uid(uid).ok_or(Error::NotFound)?
        }
    };

    // Unprivileged callers may only inspect processes they own.
    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    Ok(entry.priority.encode() as u32)
}

// ---------------------------------------------------------------------------
// sys_ioprio_set — set I/O priority
// ---------------------------------------------------------------------------

/// Handler for `ioprio_set(2)`.
///
/// Sets the I/O priority of the entity identified by `target` and `who`.
///
/// # Arguments
///
/// * `registry`   - I/O priority registry.
/// * `target`     - Which entity type to modify.
/// * `who`        - Identifier; 0 means the calling process for
///                  [`IoprioTarget::Process`].
/// * `ioprio`     - Packed 16-bit I/O priority value.
/// * `caller_pid` - PID of the calling process.
/// * `caller_uid` - UID of the calling process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  - Bad target, or malformed priority.
/// * [`Error::NotFound`]         - Target entity does not exist.
/// * [`Error::PermissionDenied`] - Caller not privileged and either
///   targeting another user's process or requesting RT class.
///
/// # Security
///
/// - Setting `RealTime` class requires `CAP_SYS_ADMIN` (root, uid 0).
/// - Unprivileged callers may only set priority on processes they own.
pub fn sys_ioprio_set(
    registry: &mut IoprioRegistry,
    target: i32,
    who: u64,
    ioprio: u16,
    caller_pid: u64,
    caller_uid: u32,
) -> Result<()> {
    let target = IoprioTarget::from_raw(target)?;
    let priority = IoprioData::decode(ioprio)?;

    // RT class requires root.
    if priority.is_realtime() && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }

    let entry = match target {
        IoprioTarget::Process => {
            let pid = if who == 0 { caller_pid } else { who };
            registry.find_by_pid_mut(pid).ok_or(Error::NotFound)?
        }
        IoprioTarget::ProcessGroup => registry.find_by_pgid_mut(who).ok_or(Error::NotFound)?,
        IoprioTarget::User => {
            let uid = who as u32;
            registry.find_by_uid_mut(uid).ok_or(Error::NotFound)?
        }
    };

    // Unprivileged callers may only modify their own priority.
    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    entry.priority = priority;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a registry with three processes.
    fn make_registry() -> IoprioRegistry {
        let mut r = IoprioRegistry::new();
        // pid=10, tgid=10, pgid=5, uid=1000
        r.register(IoprioEntry::new(10, 10, 5, 1000)).unwrap();
        // pid=20, tgid=20, pgid=5, uid=1000 (same group + user)
        r.register(IoprioEntry::new(20, 20, 5, 1000)).unwrap();
        // pid=30, tgid=30, pgid=6, uid=0 (root)
        r.register(IoprioEntry::new(30, 30, 6, 0)).unwrap();
        r
    }

    // --- IoprioData encode/decode round-trip ---

    #[test]
    fn data_default_roundtrip() {
        let raw = IoprioData::DEFAULT.encode();
        let decoded = IoprioData::decode(raw).unwrap();
        assert_eq!(decoded, IoprioData::DEFAULT);
    }

    #[test]
    fn data_idle_roundtrip() {
        let raw = IoprioData::IDLE.encode();
        let decoded = IoprioData::decode(raw).unwrap();
        assert_eq!(decoded, IoprioData::IDLE);
    }

    #[test]
    fn data_rt_highest_roundtrip() {
        let raw = IoprioData::RT_HIGHEST.encode();
        let decoded = IoprioData::decode(raw).unwrap();
        assert_eq!(decoded, IoprioData::RT_HIGHEST);
    }

    #[test]
    fn data_invalid_class_rejected() {
        // class = 5 does not exist
        let raw = (5u16 << CLASS_SHIFT as u16) | 0;
        assert_eq!(IoprioData::decode(raw), Err(Error::InvalidArgument));
    }

    #[test]
    fn data_idle_with_level_rejected() {
        let raw = (IoprioClass::Idle.as_u8() as u16) << CLASS_SHIFT as u16 | 3;
        assert_eq!(IoprioData::decode(raw), Err(Error::InvalidArgument));
    }

    #[test]
    fn data_be_level_above_max_rejected() {
        let raw = (IoprioClass::BestEffort.as_u8() as u16) << CLASS_SHIFT as u16 | 8;
        assert_eq!(IoprioData::decode(raw), Err(Error::InvalidArgument));
    }

    // --- IoPriorityLevel ---

    #[test]
    fn level_from_valid() {
        assert_eq!(IoPriorityLevel::from_raw(0), Some(IoPriorityLevel::Highest));
        assert_eq!(IoPriorityLevel::from_raw(7), Some(IoPriorityLevel::Lowest));
    }

    #[test]
    fn level_from_invalid() {
        assert!(IoPriorityLevel::from_raw(8).is_none());
    }

    #[test]
    fn level_with_class_ok() {
        let data = IoPriorityLevel::Normal
            .with_class(IoprioClass::BestEffort)
            .unwrap();
        assert_eq!(data.level, 4);
        assert_eq!(data.class, IoprioClass::BestEffort);
    }

    #[test]
    fn level_with_idle_rejected() {
        assert_eq!(
            IoPriorityLevel::Normal.with_class(IoprioClass::Idle),
            Err(Error::InvalidArgument)
        );
    }

    // --- IoprioTarget ---

    #[test]
    fn target_from_valid() {
        assert_eq!(IoprioTarget::from_raw(1), Ok(IoprioTarget::Process));
        assert_eq!(IoprioTarget::from_raw(2), Ok(IoprioTarget::ProcessGroup));
        assert_eq!(IoprioTarget::from_raw(3), Ok(IoprioTarget::User));
    }

    #[test]
    fn target_from_invalid() {
        assert_eq!(IoprioTarget::from_raw(0), Err(Error::InvalidArgument));
        assert_eq!(IoprioTarget::from_raw(4), Err(Error::InvalidArgument));
    }

    // --- Registry ---

    #[test]
    fn registry_register_and_unregister() {
        let mut r = IoprioRegistry::new();
        r.register(IoprioEntry::new(1, 1, 1, 0)).unwrap();
        assert_eq!(r.len(), 1);
        r.unregister(1);
        assert_eq!(r.len(), 0);
        assert!(r.find_by_pid(1).is_none());
    }

    #[test]
    fn registry_count_helpers() {
        let r = make_registry();
        assert_eq!(r.count_by_pgid(5), 2);
        assert_eq!(r.count_by_uid(1000), 2);
        assert_eq!(r.count_by_uid(0), 1);
    }

    #[test]
    fn registry_is_empty() {
        let r = IoprioRegistry::new();
        assert!(r.is_empty());
    }

    // --- sys_ioprio_get ---

    #[test]
    fn get_own_process_by_zero() {
        let r = make_registry();
        let raw = sys_ioprio_get(&r, 1, 0, 10, 1000).unwrap();
        let prio = IoprioData::decode(raw as u16).unwrap();
        assert_eq!(prio, IoprioData::DEFAULT);
    }

    #[test]
    fn get_by_pid_explicit() {
        let r = make_registry();
        let raw = sys_ioprio_get(&r, 1, 10, 99, 1000).unwrap();
        assert_eq!(raw as u16, IoprioData::DEFAULT.encode());
    }

    #[test]
    fn get_by_pgid() {
        let r = make_registry();
        let raw = sys_ioprio_get(&r, 2, 5, 10, 1000).unwrap();
        assert_eq!(raw as u16, IoprioData::DEFAULT.encode());
    }

    #[test]
    fn get_by_uid() {
        let r = make_registry();
        let raw = sys_ioprio_get(&r, 3, 1000, 10, 1000).unwrap();
        assert_eq!(raw as u16, IoprioData::DEFAULT.encode());
    }

    #[test]
    fn get_not_found() {
        let r = make_registry();
        assert_eq!(
            sys_ioprio_get(&r, 1, 9999, 9999, 1000),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn get_permission_denied() {
        let r = make_registry();
        // uid 2000 trying to read pid 10 (uid 1000)
        assert_eq!(
            sys_ioprio_get(&r, 1, 10, 99, 2000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn get_root_can_read_any() {
        let r = make_registry();
        assert!(sys_ioprio_get(&r, 1, 10, 30, 0).is_ok());
    }

    #[test]
    fn get_invalid_target() {
        let r = make_registry();
        assert_eq!(
            sys_ioprio_get(&r, 99, 10, 10, 1000),
            Err(Error::InvalidArgument)
        );
    }

    // --- sys_ioprio_set ---

    #[test]
    fn set_be_on_own_process() {
        let mut r = make_registry();
        let new_prio = IoprioData {
            class: IoprioClass::BestEffort,
            level: 2,
        };
        sys_ioprio_set(&mut r, 1, 10, new_prio.encode(), 10, 1000).unwrap();
        let raw = sys_ioprio_get(&r, 1, 10, 10, 1000).unwrap();
        assert_eq!(IoprioData::decode(raw as u16).unwrap(), new_prio);
    }

    #[test]
    fn set_idle_allowed() {
        let mut r = make_registry();
        sys_ioprio_set(&mut r, 1, 10, IoprioData::IDLE.encode(), 10, 1000).unwrap();
        let raw = sys_ioprio_get(&r, 1, 10, 10, 1000).unwrap();
        assert_eq!(IoprioData::decode(raw as u16).unwrap(), IoprioData::IDLE);
    }

    #[test]
    fn set_rt_requires_root() {
        let mut r = make_registry();
        assert_eq!(
            sys_ioprio_set(&mut r, 1, 10, IoprioData::RT_HIGHEST.encode(), 10, 1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn set_rt_as_root_succeeds() {
        let mut r = make_registry();
        sys_ioprio_set(&mut r, 1, 10, IoprioData::RT_HIGHEST.encode(), 30, 0).unwrap();
        let raw = sys_ioprio_get(&r, 1, 10, 30, 0).unwrap();
        assert_eq!(
            IoprioData::decode(raw as u16).unwrap(),
            IoprioData::RT_HIGHEST
        );
    }

    #[test]
    fn set_other_process_denied() {
        let mut r = make_registry();
        let prio = IoprioData {
            class: IoprioClass::BestEffort,
            level: 0,
        };
        // uid 2000 trying to set pid 10 (uid 1000)
        assert_eq!(
            sys_ioprio_set(&mut r, 1, 10, prio.encode(), 99, 2000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn set_self_via_who_zero() {
        let mut r = make_registry();
        let prio = IoprioData {
            class: IoprioClass::BestEffort,
            level: 1,
        };
        // who=0 => caller_pid=10
        sys_ioprio_set(&mut r, 1, 0, prio.encode(), 10, 1000).unwrap();
        let raw = sys_ioprio_get(&r, 1, 10, 10, 1000).unwrap();
        assert_eq!(IoprioData::decode(raw as u16).unwrap(), prio);
    }

    #[test]
    fn set_invalid_ioprio_rejected() {
        let mut r = make_registry();
        let bad = (7u16 << CLASS_SHIFT as u16) | 0;
        assert_eq!(
            sys_ioprio_set(&mut r, 1, 10, bad, 10, 1000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn set_by_pgid() {
        let mut r = make_registry();
        let prio = IoprioData {
            class: IoprioClass::BestEffort,
            level: 6,
        };
        sys_ioprio_set(&mut r, 2, 5, prio.encode(), 10, 1000).unwrap();
        // The first matching entry in pgid=5 should have been updated.
        let raw = sys_ioprio_get(&r, 2, 5, 10, 1000).unwrap();
        assert_eq!(IoprioData::decode(raw as u16).unwrap(), prio);
    }

    #[test]
    fn set_by_uid() {
        let mut r = make_registry();
        let prio = IoprioData {
            class: IoprioClass::BestEffort,
            level: 3,
        };
        sys_ioprio_set(&mut r, 3, 1000, prio.encode(), 10, 1000).unwrap();
        let raw = sys_ioprio_get(&r, 3, 1000, 10, 1000).unwrap();
        assert_eq!(IoprioData::decode(raw as u16).unwrap(), prio);
    }

    // --- IoprioClass helpers ---

    #[test]
    fn class_names() {
        assert_eq!(IoprioClass::None.name(), "none");
        assert_eq!(IoprioClass::RealTime.name(), "realtime");
        assert_eq!(IoprioClass::BestEffort.name(), "best-effort");
        assert_eq!(IoprioClass::Idle.name(), "idle");
    }

    #[test]
    fn class_uses_level() {
        assert!(!IoprioClass::None.uses_level());
        assert!(IoprioClass::RealTime.uses_level());
        assert!(IoprioClass::BestEffort.uses_level());
        assert!(!IoprioClass::Idle.uses_level());
    }

    // --- IoprioData predicates ---

    #[test]
    fn data_predicates() {
        assert!(IoprioData::RT_HIGHEST.is_realtime());
        assert!(!IoprioData::RT_HIGHEST.is_idle());
        assert!(IoprioData::IDLE.is_idle());
        assert!(!IoprioData::DEFAULT.is_realtime());
    }
}
