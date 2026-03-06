// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `personality` syscall handler — set process execution domain.
//!
//! Implements the Linux `personality(2)` system call, which controls
//! the kernel's personality (execution domain) for the calling process.
//! This is primarily used for Linux binary compatibility layers.
//!
//! The personality value encodes two parts:
//! - Bits 0..7: the execution domain identifier (`ExecutionDomain`).
//! - Bits 8..31: modifier flags (`PersonalityFlags`).
//!
//! Passing `0xFFFFFFFF` queries the current personality without changing it.
//!
//! # POSIX Reference
//!
//! `personality` is a Linux extension; it has no direct POSIX equivalent.
//! See the Linux man-page `personality(2)` for the authoritative description.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of per-PID personality entries in the table.
const PERSONALITY_TABLE_MAX: usize = 256;

/// Sentinel PID indicating an empty table slot.
const EMPTY_PID: u64 = u64::MAX;

/// Query-only sentinel: passed by the caller to read current personality.
pub const PERSONA_QUERY: u32 = 0xFFFF_FFFF;

/// Mask isolating the execution-domain byte (bits 0..7).
const DOMAIN_MASK: u32 = 0x00FF;

// ---------------------------------------------------------------------------
// ExecutionDomain
// ---------------------------------------------------------------------------

/// Execution domain (personality type).
///
/// Identifies the ABI / OS emulation environment the process wishes
/// to run under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ExecutionDomain {
    /// Standard Linux personality.
    #[default]
    Linux = 0,
    /// SYSV Release 4 personality.
    Svr4 = 68,
    /// SYSV Release 3 personality.
    Svr3 = 83,
    /// Xenix personality.
    Xenix = 7,
    /// BSD personality.
    Bsd = 6,
}

impl ExecutionDomain {
    /// Construct from a raw `u8` domain byte.
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Linux),
            68 => Some(Self::Svr4),
            83 => Some(Self::Svr3),
            7 => Some(Self::Xenix),
            6 => Some(Self::Bsd),
            _ => None,
        }
    }

    /// Return the raw `u8` value of this domain.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// PersonalityFlags
// ---------------------------------------------------------------------------

/// Modifier flags that adjust kernel behaviour for the process.
///
/// These are stored in the upper bits of the personality word
/// (bits 8..31).  Multiple flags may be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PersonalityFlags(u32);

impl PersonalityFlags {
    /// Disable address-space layout randomisation.
    pub const ADDR_NO_RANDOMIZE: u32 = 0x0004_0000;
    /// Map page zero (compatibility for null-pointer dereference).
    pub const MMAP_PAGE_ZERO: u32 = 0x0010_0000;
    /// Use a compatibility memory layout.
    pub const ADDR_COMPAT_LAYOUT: u32 = 0x0020_0000;
    /// `READ_IMPLIES_EXEC`: readable mappings are implicitly executable.
    pub const READ_IMPLIES_EXEC: u32 = 0x0040_0000;
    /// Limit the process to a 32-bit virtual address space.
    pub const ADDR_LIMIT_32BIT: u32 = 0x0080_0000;
    /// Use short inode numbers.
    pub const SHORT_INODE: u32 = 0x0100_0000;
    /// Report time values with whole-second granularity.
    pub const WHOLE_SECONDS: u32 = 0x0200_0000;
    /// Sticky timeouts: reset interval timers on `SIGALRM`.
    pub const STICKY_TIMEOUTS: u32 = 0x0400_0000;
    /// Limit address space to 3 GiB.
    pub const ADDR_LIMIT_3GB: u32 = 0x0800_0000;

    /// Bitmask of all valid personality flags (flags only, no domain bits).
    const VALID_FLAGS_MASK: u32 = Self::ADDR_NO_RANDOMIZE
        | Self::MMAP_PAGE_ZERO
        | Self::ADDR_COMPAT_LAYOUT
        | Self::READ_IMPLIES_EXEC
        | Self::ADDR_LIMIT_32BIT
        | Self::SHORT_INODE
        | Self::WHOLE_SECONDS
        | Self::STICKY_TIMEOUTS
        | Self::ADDR_LIMIT_3GB;

    /// Create a `PersonalityFlags` from raw bits.
    ///
    /// Only the flag portion (bits 8..31) is retained; domain bits are masked.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw & Self::VALID_FLAGS_MASK)
    }

    /// Return the raw bit value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return `true` if the given flag is set.
    pub const fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Return `true` if no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// PersonalityState
// ---------------------------------------------------------------------------

/// Per-process personality state.
#[derive(Debug, Clone, Copy)]
pub struct PersonalityState {
    /// Process identifier owning this entry.
    pub pid: u64,
    /// Execution domain for this process.
    pub domain: ExecutionDomain,
    /// Modifier flags for this process.
    pub flags: PersonalityFlags,
}

impl PersonalityState {
    /// Create an empty (invalid) state.
    const fn empty() -> Self {
        Self {
            pid: EMPTY_PID,
            domain: ExecutionDomain::Linux,
            flags: PersonalityFlags(0),
        }
    }

    /// Return `true` if this slot is occupied.
    const fn is_active(&self) -> bool {
        self.pid != EMPTY_PID
    }

    /// Encode this state into a packed `u32` personality word.
    ///
    /// Layout: `flags (bits 8..31) | domain (bits 0..7)`.
    pub fn to_persona_word(self) -> u32 {
        self.flags.bits() | (self.domain.as_u8() as u32)
    }
}

impl Default for PersonalityState {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// PersonalityTable
// ---------------------------------------------------------------------------

/// Per-PID personality table.
///
/// Holds up to [`PERSONALITY_TABLE_MAX`] entries (one per process).
/// Processes not present in the table use the default Linux personality.
pub struct PersonalityTable {
    /// Fixed-size array of personality state slots.
    entries: [PersonalityState; PERSONALITY_TABLE_MAX],
}

impl PersonalityTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PersonalityState::empty() }; PERSONALITY_TABLE_MAX],
        }
    }

    // -- internal helpers --------------------------------------------------

    /// Find the slot index for `pid`, if present.
    fn find_by_pid(&self, pid: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_active() && e.pid == pid)
    }

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.is_active())
    }

    // -- public API --------------------------------------------------------

    /// Read the personality word for `pid`.
    ///
    /// Returns the default Linux personality (0) if `pid` has no entry.
    pub fn get_persona_word(&self, pid: u64) -> u32 {
        self.find_by_pid(pid)
            .map(|i| self.entries[i].to_persona_word())
            .unwrap_or(0)
    }

    /// Read the `(domain, flags)` pair for `pid`.
    ///
    /// Defaults to `(Linux, empty)` if `pid` has no entry.
    pub fn get_personality(&self, pid: u64) -> (ExecutionDomain, PersonalityFlags) {
        self.find_by_pid(pid)
            .map(|i| (self.entries[i].domain, self.entries[i].flags))
            .unwrap_or((ExecutionDomain::Linux, PersonalityFlags::from_raw(0)))
    }

    /// Return `true` if the given `flag` is set for `pid`.
    pub fn check_personality_flag(&self, pid: u64, flag: u32) -> bool {
        let (_, flags) = self.get_personality(pid);
        flags.contains(flag)
    }

    /// Set the personality for `pid` from a packed persona word.
    ///
    /// Allocates a new entry if `pid` is not yet present.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — Unknown domain byte.
    /// - `OutOfMemory`     — Table is full and `pid` is not yet present.
    pub fn set_persona_word(&mut self, pid: u64, persona: u32) -> Result<()> {
        let domain_byte = (persona & DOMAIN_MASK) as u8;
        let domain = ExecutionDomain::from_raw(domain_byte).ok_or(Error::InvalidArgument)?;
        let flags = PersonalityFlags::from_raw(persona & !DOMAIN_MASK);

        let idx = if let Some(i) = self.find_by_pid(pid) {
            i
        } else {
            self.find_free().ok_or(Error::OutOfMemory)?
        };

        self.entries[idx] = PersonalityState { pid, domain, flags };
        Ok(())
    }
}

impl Default for PersonalityTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// `personality` syscall handler.
///
/// If `persona == 0xFFFF_FFFF` ([`PERSONA_QUERY`]), returns the current
/// personality without modifying it.  Otherwise, atomically replaces the
/// personality and returns the **previous** value.
///
/// # Arguments
///
/// - `table`  — The global personality table.
/// - `pid`    — PID of the calling process.
/// - `persona` — New personality word, or `0xFFFF_FFFF` to query only.
///
/// # Returns
///
/// The old personality word.
///
/// # Errors
///
/// - `InvalidArgument` — Unrecognised domain byte in `persona`.
/// - `OutOfMemory`     — Table is full and this is a new PID.
pub fn do_personality(table: &mut PersonalityTable, pid: u64, persona: u32) -> Result<u32> {
    // Always read the current value first.
    let old = table.get_persona_word(pid);

    if persona == PERSONA_QUERY {
        // Query-only: do not modify.
        return Ok(old);
    }

    table.set_persona_word(pid, persona)?;
    Ok(old)
}
