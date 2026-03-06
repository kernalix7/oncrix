// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `/proc/locks` — active file-lock display.
//!
//! The Linux kernel exposes all currently held file locks through the
//! pseudo-file `/proc/locks`. Each line describes one lock in the format:
//!
//! ```text
//! <id>: <TYPE> <MODE> <MANDATORY> <PID> <MAJ:MIN:INO> <START>-<END>
//! ```
//!
//! Example:
//!
//! ```text
//! 1: POSIX  ADVISORY  READ  1234 08:01:100663 0 EOF
//! 2: FLOCK  ADVISORY  WRITE 5678 08:01:200114 0 EOF
//! ```
//!
//! # Design
//!
//! - [`ProcLockEntry`] — one lock record (type, mode, pid, inode, range).
//! - [`ProcLockTable`] — fixed-size array of 256 entries with add/remove/query.
//! - [`format_proc_locks`] — serialises the table into a text buffer.
//!
//! # References
//!
//! - Linux `fs/locks.c` — `lock_get_status()`, `locks_show()`
//! - `proc(5)` man page — `/proc/locks` description
//! - POSIX.1-2024 — `fcntl()` advisory lock semantics

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of lock entries tracked.
pub const PROC_LOCK_MAX: usize = 256;

/// Sentinel value for the end of a whole-file lock.
pub const LOCK_END_WHOLE_FILE: u64 = u64::MAX;

/// Maximum output buffer size for [`format_proc_locks`].
pub const PROC_LOCKS_BUF_SIZE: usize = 32768;

// ── ProcLockType ─────────────────────────────────────────────────────────────

/// The locking mechanism that created this lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcLockType {
    /// POSIX advisory lock (`fcntl(F_SETLK/F_SETLKW)`).
    Posix,
    /// BSD `flock(2)` lock (whole-file).
    Flock,
    /// Lease granted by the kernel (`fcntl(F_SETLEASE)`).
    Lease,
    /// Open-file-description lock (`fcntl(F_OFD_SETLK)`).
    Ofd,
}

impl ProcLockType {
    /// Returns the text token used in `/proc/locks` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProcLockType::Posix => "POSIX ",
            ProcLockType::Flock => "FLOCK ",
            ProcLockType::Lease => "LEASE ",
            ProcLockType::Ofd => "OFDLCK",
        }
    }
}

// ── ProcLockMode ─────────────────────────────────────────────────────────────

/// Whether the lock grants read or write (exclusive) access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcLockMode {
    /// Shared read lock.
    Read,
    /// Exclusive write lock.
    Write,
    /// Read-write (upgrade pending); reported for some lease states.
    ReadWrite,
}

impl ProcLockMode {
    /// Returns the text token used in `/proc/locks` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProcLockMode::Read => "READ ",
            ProcLockMode::Write => "WRITE",
            ProcLockMode::ReadWrite => "RW   ",
        }
    }
}

// ── ProcLockEntry ─────────────────────────────────────────────────────────────

/// A single active lock record.
#[derive(Debug, Clone, Copy)]
pub struct ProcLockEntry {
    /// Unique lock identifier (used as the line number in `/proc/locks`).
    pub id: u64,
    /// Locking mechanism.
    pub lock_type: ProcLockType,
    /// Access mode.
    pub mode: ProcLockMode,
    /// Whether this is a mandatory lock (rare; most Linux locks are advisory).
    pub mandatory: bool,
    /// PID of the process holding the lock.
    pub pid: u32,
    /// Inode number of the locked file.
    pub inode_id: u64,
    /// First byte of the locked range (inclusive).
    pub start_offset: u64,
    /// Last byte of the locked range (inclusive); [`LOCK_END_WHOLE_FILE`] = EOF.
    pub end_offset: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl ProcLockEntry {
    /// Constructs an empty (inactive) entry slot.
    pub const fn new() -> Self {
        Self {
            id: 0,
            lock_type: ProcLockType::Posix,
            mode: ProcLockMode::Read,
            mandatory: false,
            pid: 0,
            inode_id: 0,
            start_offset: 0,
            end_offset: LOCK_END_WHOLE_FILE,
            active: false,
        }
    }
}

impl Default for ProcLockEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ── ProcLockStats ─────────────────────────────────────────────────────────────

/// Cumulative statistics for the lock table.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcLockStats {
    /// Total locks currently registered.
    pub total_locks: u32,
    /// Number of POSIX locks currently registered.
    pub posix_locks: u32,
    /// Number of flock locks currently registered.
    pub flock_locks: u32,
    /// Number of lease locks currently registered.
    pub lease_locks: u32,
}

impl ProcLockStats {
    /// Constructs zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_locks: 0,
            posix_locks: 0,
            flock_locks: 0,
            lease_locks: 0,
        }
    }
}

// ── ProcLockTable ─────────────────────────────────────────────────────────────

/// Fixed-size table of up to 256 active file locks.
pub struct ProcLockTable {
    /// Lock entries.
    pub entries: [ProcLockEntry; PROC_LOCK_MAX],
    /// Next ID to assign (monotonically increasing).
    next_id: u64,
}

impl ProcLockTable {
    /// Constructs an empty lock table.
    pub const fn new() -> Self {
        Self {
            entries: [const { ProcLockEntry::new() }; PROC_LOCK_MAX],
            next_id: 1,
        }
    }

    /// Adds a new lock entry to the table.
    ///
    /// Returns the assigned lock ID on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — table is full.
    pub fn add(
        &mut self,
        lock_type: ProcLockType,
        mode: ProcLockMode,
        mandatory: bool,
        pid: u32,
        inode_id: u64,
        start_offset: u64,
        end_offset: u64,
    ) -> Result<u64> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.entries[slot] = ProcLockEntry {
            id,
            lock_type,
            mode,
            mandatory,
            pid,
            inode_id,
            start_offset,
            end_offset,
            active: true,
        };
        Ok(id)
    }

    /// Removes the lock with the given `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — no active lock with that ID exists.
    pub fn remove(&mut self, id: u64) -> Result<()> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        self.entries[pos] = ProcLockEntry::new();
        Ok(())
    }

    /// Returns a slice of all active entries held by `pid`.
    ///
    /// Writes matching entries into `out` and returns the count found.
    pub fn find_by_pid<'a>(&'a self, pid: u32, out: &mut [&'a ProcLockEntry]) -> usize {
        let mut count = 0;
        for entry in self.entries.iter() {
            if entry.active && entry.pid == pid {
                if count < out.len() {
                    out[count] = entry;
                    count += 1;
                }
            }
        }
        count
    }

    /// Returns a slice of all active entries on inode `inode_id`.
    ///
    /// Writes matching entries into `out` and returns the count found.
    pub fn find_by_inode<'a>(&'a self, inode_id: u64, out: &mut [&'a ProcLockEntry]) -> usize {
        let mut count = 0;
        for entry in self.entries.iter() {
            if entry.active && entry.inode_id == inode_id {
                if count < out.len() {
                    out[count] = entry;
                    count += 1;
                }
            }
        }
        count
    }

    /// Computes live statistics from the current table contents.
    pub fn stats(&self) -> ProcLockStats {
        let mut s = ProcLockStats::new();
        for e in self.entries.iter() {
            if !e.active {
                continue;
            }
            s.total_locks = s.total_locks.wrapping_add(1);
            match e.lock_type {
                ProcLockType::Posix => {
                    s.posix_locks = s.posix_locks.wrapping_add(1);
                }
                ProcLockType::Flock => {
                    s.flock_locks = s.flock_locks.wrapping_add(1);
                }
                ProcLockType::Lease => {
                    s.lease_locks = s.lease_locks.wrapping_add(1);
                }
                ProcLockType::Ofd => {
                    s.posix_locks = s.posix_locks.wrapping_add(1);
                }
            }
        }
        s
    }
}

impl Default for ProcLockTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── format_proc_locks ─────────────────────────────────────────────────────────

/// Formats all active locks into `buf` in `/proc/locks` text format.
///
/// Each line follows:
/// ```text
/// <id>: <TYPE> ADVISORY <MODE> <PID> 00:00:<INO> <START> <END|EOF>
/// ```
///
/// Returns the number of bytes written, or [`Error::OutOfMemory`] if `buf`
/// is too small to hold the full output.
pub fn format_proc_locks(table: &ProcLockTable, buf: &mut [u8]) -> Result<usize> {
    let mut pos = 0usize;

    // Helper: write a decimal u64 into buf starting at `pos`.
    // Returns new pos or None on overflow.
    fn write_u64(buf: &mut [u8], pos: usize, mut val: u64) -> Option<usize> {
        if val == 0 {
            if pos >= buf.len() {
                return None;
            }
            buf[pos] = b'0';
            return Some(pos + 1);
        }
        let mut tmp = [0u8; 20];
        let mut i = 20usize;
        while val > 0 {
            i -= 1;
            tmp[i] = b'0' + (val % 10) as u8;
            val /= 10;
        }
        let digits = &tmp[i..];
        if pos + digits.len() > buf.len() {
            return None;
        }
        buf[pos..pos + digits.len()].copy_from_slice(digits);
        Some(pos + digits.len())
    }

    // Helper: write a byte slice.
    fn write_bytes(buf: &mut [u8], pos: usize, src: &[u8]) -> Option<usize> {
        if pos + src.len() > buf.len() {
            return None;
        }
        buf[pos..pos + src.len()].copy_from_slice(src);
        Some(pos + src.len())
    }

    let mut line_num = 1u64;
    for entry in table.entries.iter() {
        if !entry.active {
            continue;
        }

        // <line_num>: <TYPE> ADVISORY|MANDATORY <MODE> <PID> 00:00:<INO> <START> <END|EOF>\n

        pos = write_u64(buf, pos, line_num).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, b": ").ok_or(Error::OutOfMemory)?;
        pos =
            write_bytes(buf, pos, entry.lock_type.as_str().as_bytes()).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, b" ").ok_or(Error::OutOfMemory)?;
        let advisory = if entry.mandatory {
            b"MANDATORY " as &[u8]
        } else {
            b"ADVISORY  "
        };
        pos = write_bytes(buf, pos, advisory).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, entry.mode.as_str().as_bytes()).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, b" ").ok_or(Error::OutOfMemory)?;
        pos = write_u64(buf, pos, entry.pid as u64).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, b" 00:00:").ok_or(Error::OutOfMemory)?;
        pos = write_u64(buf, pos, entry.inode_id).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, b" ").ok_or(Error::OutOfMemory)?;
        pos = write_u64(buf, pos, entry.start_offset).ok_or(Error::OutOfMemory)?;
        pos = write_bytes(buf, pos, b" ").ok_or(Error::OutOfMemory)?;
        if entry.end_offset == LOCK_END_WHOLE_FILE {
            pos = write_bytes(buf, pos, b"EOF").ok_or(Error::OutOfMemory)?;
        } else {
            pos = write_u64(buf, pos, entry.end_offset).ok_or(Error::OutOfMemory)?;
        }
        pos = write_bytes(buf, pos, b"\n").ok_or(Error::OutOfMemory)?;
        line_num = line_num.wrapping_add(1);
    }
    Ok(pos)
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_remove() {
        let mut table = ProcLockTable::new();
        let id = table
            .add(
                ProcLockType::Posix,
                ProcLockMode::Read,
                false,
                100,
                500,
                0,
                LOCK_END_WHOLE_FILE,
            )
            .unwrap();
        assert_eq!(table.stats().total_locks, 1);
        assert_eq!(table.stats().posix_locks, 1);
        table.remove(id).unwrap();
        assert_eq!(table.stats().total_locks, 0);
    }

    #[test]
    fn find_by_pid_works() {
        let mut table = ProcLockTable::new();
        table
            .add(
                ProcLockType::Flock,
                ProcLockMode::Write,
                false,
                42,
                1,
                0,
                LOCK_END_WHOLE_FILE,
            )
            .unwrap();
        table
            .add(
                ProcLockType::Flock,
                ProcLockMode::Write,
                false,
                99,
                2,
                0,
                LOCK_END_WHOLE_FILE,
            )
            .unwrap();
        let mut out = [&ProcLockEntry::new(); 4];
        let n = table.find_by_pid(42, &mut out);
        assert_eq!(n, 1);
    }

    #[test]
    fn format_output_non_empty() {
        let mut table = ProcLockTable::new();
        table
            .add(
                ProcLockType::Posix,
                ProcLockMode::Read,
                false,
                1,
                100,
                0,
                LOCK_END_WHOLE_FILE,
            )
            .unwrap();
        let mut buf = [0u8; PROC_LOCKS_BUF_SIZE];
        let n = format_proc_locks(&table, &mut buf).unwrap();
        assert!(n > 0);
        // Output must contain "POSIX"
        assert!(buf[..n].windows(5).any(|w| w == b"POSIX"));
    }
}
