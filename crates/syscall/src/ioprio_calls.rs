// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `ioprio_get(2)` and `ioprio_set(2)` syscall handlers — I/O scheduling priority.
//!
//! The Linux I/O priority interface allows processes or threads to declare their
//! relative importance to the block-layer I/O scheduler.  Priorities are encoded
//! as a packed 16-bit value:
//!
//! ```text
//! bits [15:13]  class  (IOPRIO_CLASS_RT / BE / IDLE / NONE)
//! bits [12:0]   data   (0–7 within RT/BE; 0 for IDLE/NONE)
//! ```
//!
//! # Operations
//!
//! | Syscall         | Handler             | Purpose                              |
//! |-----------------|---------------------|--------------------------------------|
//! | `ioprio_get`    | [`do_ioprio_get`]   | Read I/O priority of a target        |
//! | `ioprio_set`    | [`do_ioprio_set`]   | Set  I/O priority of a target        |
//!
//! # References
//!
//! - Linux: `include/uapi/linux/ioprio.h`, `block/ioprio.c`
//! - `man ioprio_set(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Wire encoding helpers
// ---------------------------------------------------------------------------

/// Shift to extract/insert the class field.
const IOPRIO_CLASS_SHIFT: u32 = 13;
/// Mask for the data (priority level) field.
const IOPRIO_PRIO_DATA_MASK: u16 = 0x1FFF;
/// Maximum valid priority level within a class.
pub const IOPRIO_PRIO_LEVEL_MAX: u16 = 7;

/// Pack a class and level into the wire encoding.
#[inline]
pub const fn ioprio_value(class: u16, level: u16) -> u16 {
    (class << IOPRIO_CLASS_SHIFT as u16) | (level & IOPRIO_PRIO_DATA_MASK)
}

/// Extract the class from a packed I/O priority value.
#[inline]
pub const fn ioprio_class(val: u16) -> u16 {
    val >> IOPRIO_CLASS_SHIFT as u16
}

/// Extract the level (data) from a packed I/O priority value.
#[inline]
pub const fn ioprio_level(val: u16) -> u16 {
    val & IOPRIO_PRIO_DATA_MASK
}

// ---------------------------------------------------------------------------
// I/O scheduler class
// ---------------------------------------------------------------------------

/// I/O scheduling class.
///
/// Values match the Linux `IOPRIO_CLASS_*` constants.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoPrioClass {
    /// No specific I/O priority set — inherit from process nice value.
    None = 0,
    /// Real-time I/O class.  Gets I/O first regardless of anything else.
    /// Levels 0 (highest) through 7 (lowest).
    RealTime = 1,
    /// Best-effort class (default for most processes).
    /// Levels 0 (highest) through 7 (lowest).
    BestEffort = 2,
    /// Idle class.  Gets I/O time only when no other class needs the disk.
    /// Level field is unused (must be 0).
    Idle = 3,
}

impl IoPrioClass {
    /// Construct from raw wire class bits.
    ///
    /// Returns `None` for unrecognised class values.
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(IoPrioClass::None),
            1 => Some(IoPrioClass::RealTime),
            2 => Some(IoPrioClass::BestEffort),
            3 => Some(IoPrioClass::Idle),
            _ => None,
        }
    }

    /// Return the raw numeric value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Return `true` if the class uses a meaningful priority level.
    pub const fn has_level(self) -> bool {
        matches!(self, IoPrioClass::RealTime | IoPrioClass::BestEffort)
    }
}

// ---------------------------------------------------------------------------
// IoPriority — decoded priority
// ---------------------------------------------------------------------------

/// A decoded I/O priority value.
///
/// Carries the scheduling class and (where applicable) the level within
/// that class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoPriority {
    /// The scheduling class.
    pub class: IoPrioClass,
    /// Priority level within the class (0 = highest, 7 = lowest).
    /// Meaningful only for `RealTime` and `BestEffort`; must be 0 for others.
    pub level: u16,
}

impl IoPriority {
    /// The default I/O priority applied to new processes.
    ///
    /// `BestEffort` at level 4 mirrors the Linux default (BE/4).
    pub const DEFAULT: Self = Self {
        class: IoPrioClass::BestEffort,
        level: 4,
    };

    /// Idle priority — used when a process has no I/O requirements.
    pub const IDLE: Self = Self {
        class: IoPrioClass::Idle,
        level: 0,
    };

    /// Construct from a raw packed value, validating the fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the class is unrecognised or
    /// the level exceeds 7.
    pub fn from_raw(raw: u16) -> Result<Self> {
        let raw_class = ioprio_class(raw);
        let level = ioprio_level(raw);
        let class = IoPrioClass::from_raw(raw_class).ok_or(Error::InvalidArgument)?;
        // For classes without a meaningful level, require level == 0.
        if !class.has_level() && level != 0 {
            return Err(Error::InvalidArgument);
        }
        if class.has_level() && level > IOPRIO_PRIO_LEVEL_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { class, level })
    }

    /// Encode into the packed wire format.
    pub const fn to_raw(self) -> u16 {
        ioprio_value(self.class.as_u16(), self.level)
    }
}

impl Default for IoPriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ---------------------------------------------------------------------------
// Target selector — `which` argument
// ---------------------------------------------------------------------------

/// Which entity to get/set I/O priority for.
///
/// Mirrors the Linux `IOPRIO_WHO_*` constants.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoPrioWho {
    /// A single process, identified by PID (0 = calling process).
    Process = 1,
    /// All processes in a process group, identified by PGID.
    ProcessGroup = 2,
    /// All processes owned by a user, identified by UID.
    User = 3,
}

impl IoPrioWho {
    /// Construct from the raw `which` syscall argument.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            1 => Ok(IoPrioWho::Process),
            2 => Ok(IoPrioWho::ProcessGroup),
            3 => Ok(IoPrioWho::User),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// Process I/O priority entry
// ---------------------------------------------------------------------------

/// Per-process I/O priority record stored in the registry.
#[derive(Debug, Clone, Copy)]
pub struct ProcIoPrio {
    /// Process identifier.
    pub pid: u32,
    /// Thread group ID (== PID of the group leader).
    pub tgid: u32,
    /// Process group ID.
    pub pgid: u32,
    /// Owner UID.
    pub uid: u32,
    /// Current I/O priority.
    pub priority: IoPriority,
}

impl ProcIoPrio {
    /// Construct a new entry with the default I/O priority.
    pub const fn new(pid: u32, tgid: u32, pgid: u32, uid: u32) -> Self {
        Self {
            pid,
            tgid,
            pgid,
            uid,
            priority: IoPriority::DEFAULT,
        }
    }
}

// ---------------------------------------------------------------------------
// IoPrioTable — tracks per-process priorities
// ---------------------------------------------------------------------------

/// Maximum number of processes tracked in the I/O priority table.
pub const IOPRIO_TABLE_SIZE: usize = 128;

/// Registry of per-process I/O priorities.
pub struct IoPrioTable {
    entries: [Option<ProcIoPrio>; IOPRIO_TABLE_SIZE],
    count: usize,
}

impl IoPrioTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; IOPRIO_TABLE_SIZE],
            count: 0,
        }
    }

    /// Register a new process with the default I/O priority.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the table is full.
    pub fn register(&mut self, entry: ProcIoPrio) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a process from the table (called on exit).
    pub fn unregister(&mut self, pid: u32) {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map(|e| e.pid == pid).unwrap_or(false) {
                *slot = None;
                self.count -= 1;
                return;
            }
        }
    }

    /// Find a mutable entry by PID.
    pub fn get_mut_by_pid(&mut self, pid: u32) -> Option<&mut ProcIoPrio> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.pid == pid))
    }

    /// Find an immutable entry by PID.
    pub fn get_by_pid(&self, pid: u32) -> Option<&ProcIoPrio> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.pid == pid))
    }

    /// Find an immutable entry by PGID.
    pub fn get_by_pgid(&self, pgid: u32) -> Option<&ProcIoPrio> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.pgid == pgid))
    }

    /// Find a mutable entry by PGID (returns first match).
    fn get_mut_by_pgid(&mut self, pgid: u32) -> Option<&mut ProcIoPrio> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.pgid == pgid))
    }

    /// Find an immutable entry by UID.
    pub fn get_by_uid(&self, uid: u32) -> Option<&ProcIoPrio> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.uid == uid))
    }

    /// Find a mutable entry by UID (returns first match).
    fn get_mut_by_uid(&mut self, uid: u32) -> Option<&mut ProcIoPrio> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.uid == uid))
    }

    /// Return the number of tracked processes.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// do_ioprio_get
// ---------------------------------------------------------------------------

/// Handler for `ioprio_get(2)`.
///
/// Returns the I/O priority of the entity identified by `which` and `who`.
///
/// # Arguments
///
/// * `table`      — I/O priority table.
/// * `which`      — Target selector: `1` = PID, `2` = PGID, `3` = UID.
/// * `who`        — Identifier value; `0` means the calling process (`caller_pid`).
/// * `caller_pid` — PID of the calling process.
/// * `caller_uid` — UID of the calling process (for permission checks).
///
/// # Returns
///
/// The packed I/O priority value (`u16` returned as `u32` for ABI compatibility).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unrecognised `which` value.
/// * [`Error::NotFound`]        — Target process/group/user not found.
/// * [`Error::PermissionDenied`] — Caller lacks permission to inspect target.
///
/// # Linux conformance
///
/// - `who == 0` always refers to the calling process / calling thread's group.
/// - Unprivileged callers may only get the priority of processes they own.
pub fn do_ioprio_get(
    table: &IoPrioTable,
    which: i32,
    who: u32,
    caller_pid: u32,
    caller_uid: u32,
) -> Result<u32> {
    let target_who = IoPrioWho::from_raw(which)?;

    let entry = match target_who {
        IoPrioWho::Process => {
            let pid = if who == 0 { caller_pid } else { who };
            table.get_by_pid(pid).ok_or(Error::NotFound)?
        }
        IoPrioWho::ProcessGroup => {
            let pgid = who;
            table.get_by_pgid(pgid).ok_or(Error::NotFound)?
        }
        IoPrioWho::User => {
            let uid = who;
            table.get_by_uid(uid).ok_or(Error::NotFound)?
        }
    };

    // Unprivileged callers may only inspect their own processes.
    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    Ok(entry.priority.to_raw() as u32)
}

// ---------------------------------------------------------------------------
// do_ioprio_set
// ---------------------------------------------------------------------------

/// Handler for `ioprio_set(2)`.
///
/// Sets the I/O priority of the entity identified by `which` and `who`.
///
/// # Arguments
///
/// * `table`      — I/O priority table.
/// * `which`      — Target selector: `1` = PID, `2` = PGID, `3` = UID.
/// * `who`        — Identifier value; `0` means the calling process.
/// * `ioprio`     — Packed I/O priority value (class + level).
/// * `caller_pid` — PID of the calling process.
/// * `caller_uid` — UID of the calling process.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Invalid `which`, or malformed `ioprio` value.
/// * [`Error::NotFound`]         — Target not found in the table.
/// * [`Error::PermissionDenied`] — Caller lacks privilege (non-root setting RT class
///                                 requires `CAP_SYS_NICE`; simplified here to uid check).
///
/// # Linux conformance
///
/// - Setting `IOPRIO_CLASS_RT` requires `CAP_SYS_NICE` (here: `caller_uid == 0`).
/// - Setting `IOPRIO_CLASS_IDLE` on others requires `CAP_SYS_ADMIN` (here: root).
/// - Unprivileged callers may only set their own priority.
pub fn do_ioprio_set(
    table: &mut IoPrioTable,
    which: i32,
    who: u32,
    ioprio: u16,
    caller_pid: u32,
    caller_uid: u32,
) -> Result<()> {
    let target_who = IoPrioWho::from_raw(which)?;
    let priority = IoPriority::from_raw(ioprio)?;

    // RT class requires elevated privilege.
    if priority.class == IoPrioClass::RealTime && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }

    let entry = match target_who {
        IoPrioWho::Process => {
            let pid = if who == 0 { caller_pid } else { who };
            table.get_mut_by_pid(pid).ok_or(Error::NotFound)?
        }
        IoPrioWho::ProcessGroup => {
            let pgid = who;
            table.get_mut_by_pgid(pgid).ok_or(Error::NotFound)?
        }
        IoPrioWho::User => {
            let uid = who;
            table.get_mut_by_uid(uid).ok_or(Error::NotFound)?
        }
    };

    // Unprivileged callers may only set their own priority.
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

    fn make_table() -> IoPrioTable {
        let mut t = IoPrioTable::new();
        // pid 100, pgid 50, uid 500
        t.register(ProcIoPrio::new(100, 100, 50, 500)).unwrap();
        // pid 200, pgid 50, uid 500  (same group, same user)
        t.register(ProcIoPrio::new(200, 200, 50, 500)).unwrap();
        // pid 300, pgid 60, uid 0 (root process)
        t.register(ProcIoPrio::new(300, 300, 60, 0)).unwrap();
        t
    }

    // --- encoding helpers ---

    #[test]
    fn ioprio_value_roundtrip() {
        let raw = ioprio_value(IoPrioClass::BestEffort.as_u16(), 3);
        assert_eq!(ioprio_class(raw), IoPrioClass::BestEffort.as_u16());
        assert_eq!(ioprio_level(raw), 3);
    }

    #[test]
    fn ioprio_priority_default_roundtrip() {
        let prio = IoPriority::DEFAULT;
        let raw = prio.to_raw();
        let decoded = IoPriority::from_raw(raw).unwrap();
        assert_eq!(decoded, prio);
    }

    #[test]
    fn ioprio_priority_idle_roundtrip() {
        let raw = IoPriority::IDLE.to_raw();
        let decoded = IoPriority::from_raw(raw).unwrap();
        assert_eq!(decoded, IoPriority::IDLE);
    }

    #[test]
    fn ioprio_invalid_class_rejected() {
        let raw = ioprio_value(7, 0); // class 7 is undefined
        assert_eq!(IoPriority::from_raw(raw), Err(Error::InvalidArgument));
    }

    #[test]
    fn ioprio_idle_with_nonzero_level_rejected() {
        let raw = ioprio_value(IoPrioClass::Idle.as_u16(), 3);
        assert_eq!(IoPriority::from_raw(raw), Err(Error::InvalidArgument));
    }

    #[test]
    fn ioprio_level_above_max_rejected() {
        let raw = ioprio_value(IoPrioClass::BestEffort.as_u16(), 8);
        assert_eq!(IoPriority::from_raw(raw), Err(Error::InvalidArgument));
    }

    // --- IoPrioWho ---

    #[test]
    fn ioprio_who_from_valid() {
        assert_eq!(IoPrioWho::from_raw(1), Ok(IoPrioWho::Process));
        assert_eq!(IoPrioWho::from_raw(2), Ok(IoPrioWho::ProcessGroup));
        assert_eq!(IoPrioWho::from_raw(3), Ok(IoPrioWho::User));
    }

    #[test]
    fn ioprio_who_from_invalid() {
        assert_eq!(IoPrioWho::from_raw(0), Err(Error::InvalidArgument));
        assert_eq!(IoPrioWho::from_raw(4), Err(Error::InvalidArgument));
    }

    // --- do_ioprio_get ---

    #[test]
    fn get_own_pid_by_zero() {
        let t = make_table();
        // who==0 → calling process (pid 100), caller uid 500
        let raw = do_ioprio_get(&t, 1, 0, 100, 500).unwrap();
        let prio = IoPriority::from_raw(raw as u16).unwrap();
        assert_eq!(prio, IoPriority::DEFAULT);
    }

    #[test]
    fn get_by_pid_explicit() {
        let t = make_table();
        let raw = do_ioprio_get(&t, 1, 100, 999, 500).unwrap();
        assert_eq!(raw as u16, IoPriority::DEFAULT.to_raw());
    }

    #[test]
    fn get_by_pgid() {
        let t = make_table();
        let raw = do_ioprio_get(&t, 2, 50, 100, 500).unwrap();
        assert_eq!(raw as u16, IoPriority::DEFAULT.to_raw());
    }

    #[test]
    fn get_by_uid() {
        let t = make_table();
        let raw = do_ioprio_get(&t, 3, 500, 100, 500).unwrap();
        assert_eq!(raw as u16, IoPriority::DEFAULT.to_raw());
    }

    #[test]
    fn get_nonexistent_pid_notfound() {
        let t = make_table();
        assert_eq!(do_ioprio_get(&t, 1, 9999, 9999, 500), Err(Error::NotFound));
    }

    #[test]
    fn get_permission_denied_different_uid() {
        let t = make_table();
        // uid 999 trying to read pid 100 (uid 500)
        assert_eq!(
            do_ioprio_get(&t, 1, 100, 999, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn get_root_can_read_any() {
        let t = make_table();
        assert!(do_ioprio_get(&t, 1, 100, 300, 0).is_ok());
    }

    #[test]
    fn get_invalid_which() {
        let t = make_table();
        assert_eq!(
            do_ioprio_get(&t, 9, 100, 100, 500),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_ioprio_set ---

    #[test]
    fn set_be_priority_own_process() {
        let mut t = make_table();
        let new_prio = IoPriority {
            class: IoPrioClass::BestEffort,
            level: 2,
        };
        do_ioprio_set(&mut t, 1, 100, new_prio.to_raw(), 100, 500).unwrap();
        let raw = do_ioprio_get(&t, 1, 100, 100, 500).unwrap();
        assert_eq!(IoPriority::from_raw(raw as u16).unwrap(), new_prio);
    }

    #[test]
    fn set_idle_priority() {
        let mut t = make_table();
        do_ioprio_set(&mut t, 1, 100, IoPriority::IDLE.to_raw(), 100, 500).unwrap();
        let raw = do_ioprio_get(&t, 1, 100, 100, 500).unwrap();
        assert_eq!(IoPriority::from_raw(raw as u16).unwrap(), IoPriority::IDLE);
    }

    #[test]
    fn set_rt_requires_root() {
        let mut t = make_table();
        let rt_prio = IoPriority {
            class: IoPrioClass::RealTime,
            level: 0,
        };
        assert_eq!(
            do_ioprio_set(&mut t, 1, 100, rt_prio.to_raw(), 100, 500),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn set_rt_as_root_succeeds() {
        let mut t = make_table();
        let rt_prio = IoPriority {
            class: IoPrioClass::RealTime,
            level: 0,
        };
        do_ioprio_set(&mut t, 1, 100, rt_prio.to_raw(), 300, 0).unwrap();
        let raw = do_ioprio_get(&t, 1, 100, 300, 0).unwrap();
        assert_eq!(IoPriority::from_raw(raw as u16).unwrap(), rt_prio);
    }

    #[test]
    fn set_other_process_denied_for_non_root() {
        let mut t = make_table();
        let prio = IoPriority {
            class: IoPrioClass::BestEffort,
            level: 0,
        };
        // uid 999 trying to set pid 100 (uid 500)
        assert_eq!(
            do_ioprio_set(&mut t, 1, 100, prio.to_raw(), 999, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn set_by_caller_self_who_zero() {
        let mut t = make_table();
        let prio = IoPriority {
            class: IoPrioClass::BestEffort,
            level: 1,
        };
        // who==0 → calling process (pid 100)
        do_ioprio_set(&mut t, 1, 0, prio.to_raw(), 100, 500).unwrap();
        let raw = do_ioprio_get(&t, 1, 100, 100, 500).unwrap();
        assert_eq!(IoPriority::from_raw(raw as u16).unwrap(), prio);
    }

    #[test]
    fn set_invalid_ioprio_rejected() {
        let mut t = make_table();
        // class 7 is invalid
        let bad = ioprio_value(7, 0);
        assert_eq!(
            do_ioprio_set(&mut t, 1, 100, bad, 100, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn register_and_unregister() {
        let mut t = IoPrioTable::new();
        t.register(ProcIoPrio::new(1, 1, 1, 0)).unwrap();
        assert_eq!(t.count(), 1);
        t.unregister(1);
        assert_eq!(t.count(), 0);
        assert!(t.get_by_pid(1).is_none());
    }
}
