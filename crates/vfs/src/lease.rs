// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File lease management (`F_SETLEASE` / `F_GETLEASE`).
//!
//! File leases allow a process to be notified when another process
//! tries to open or truncate a file it holds a lease on. The kernel
//! sends `SIGIO` (or the configured signal) to the lease holder,
//! which then has a grace period to release the lease before the
//! conflicting open proceeds.
//!
//! # Lease types
//!
//! - `F_RDLCK` — Read lease: notified when another process opens for writing.
//! - `F_WRLCK` — Write lease: notified when any other process opens the file.
//! - `F_UNLCK` — Release/remove an existing lease.
//!
//! # References
//!
//! - Linux `fcntl(2)` — file leases section
//! - Linux `lease(7)` — overview of file leases

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of leases tracked system-wide.
pub const MAX_LEASES: usize = 256;

/// Read lease — holder notified on conflicting write-open.
pub const F_RDLCK: u32 = 0;
/// Write lease — holder notified on any conflicting open.
pub const F_WRLCK: u32 = 1;
/// Unlock / remove an existing lease.
pub const F_UNLCK: u32 = 2;

/// Grace period (in milliseconds) before the kernel breaks the lease.
pub const LEASE_BREAK_TIME_MS: u64 = 45_000;

// ── LeaseType ────────────────────────────────────────────────────────

/// The type of a file lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseType {
    /// Read lease.
    Read,
    /// Write lease.
    Write,
}

// ── LeaseState ───────────────────────────────────────────────────────

/// The current state of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Lease is active and held.
    Active,
    /// Lease is being broken (grace period running).
    Breaking,
    /// Lease has been released.
    Released,
}

// ── Lease ────────────────────────────────────────────────────────────

/// A single file lease entry.
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    /// Inode number the lease is on.
    pub ino: u64,
    /// PID of the lease holder.
    pub pid: u32,
    /// Lease type.
    pub lease_type: LeaseType,
    /// Current state.
    pub state: LeaseState,
    /// Signal to send on lease break (default: `SIGIO` = 29).
    pub signal: u32,
    /// Monotonic timestamp (ms) when the break was initiated.
    pub break_start_ms: u64,
}

impl Lease {
    /// Create a new active lease.
    pub const fn new(ino: u64, pid: u32, lease_type: LeaseType, signal: u32) -> Self {
        Self {
            ino,
            pid,
            lease_type,
            state: LeaseState::Active,
            signal,
            break_start_ms: 0,
        }
    }

    /// Returns `true` if the lease is currently active.
    pub fn is_active(&self) -> bool {
        self.state == LeaseState::Active
    }

    /// Begin breaking this lease (enter grace period).
    pub fn begin_break(&mut self, now_ms: u64) {
        if self.state == LeaseState::Active {
            self.state = LeaseState::Breaking;
            self.break_start_ms = now_ms;
        }
    }

    /// Returns `true` if the grace period has expired.
    pub fn grace_expired(&self, now_ms: u64) -> bool {
        if self.state == LeaseState::Breaking {
            now_ms.saturating_sub(self.break_start_ms) >= LEASE_BREAK_TIME_MS
        } else {
            false
        }
    }

    /// Release (remove) this lease.
    pub fn release(&mut self) {
        self.state = LeaseState::Released;
    }
}

// ── LeaseTable ───────────────────────────────────────────────────────

/// System-wide lease table.
pub struct LeaseTable {
    leases: [Option<Lease>; MAX_LEASES],
    count: usize,
}

impl LeaseTable {
    /// Create an empty lease table.
    pub const fn new() -> Self {
        Self {
            leases: [const { None }; MAX_LEASES],
            count: 0,
        }
    }

    /// Set a lease on `ino` for `pid`.
    ///
    /// If a lease already exists for this `(ino, pid)` pair, it is
    /// replaced. Pass `F_UNLCK` as `lease_cmd` to remove an existing
    /// lease.
    pub fn set_lease(&mut self, ino: u64, pid: u32, lease_cmd: u32, signal: u32) -> Result<()> {
        if lease_cmd == F_UNLCK {
            return self.remove_lease(ino, pid);
        }

        let lease_type = match lease_cmd {
            F_RDLCK => LeaseType::Read,
            F_WRLCK => LeaseType::Write,
            _ => return Err(Error::InvalidArgument),
        };

        // Check for conflicting leases from other PIDs.
        for slot in self.leases.iter() {
            if let Some(l) = slot {
                if l.ino == ino && l.pid != pid && l.is_active() {
                    if lease_type == LeaseType::Write || l.lease_type == LeaseType::Write {
                        return Err(Error::Busy);
                    }
                }
            }
        }

        // Replace existing lease from same PID, or allocate new slot.
        for slot in self.leases.iter_mut() {
            if let Some(l) = slot {
                if l.ino == ino && l.pid == pid {
                    l.lease_type = lease_type;
                    l.state = LeaseState::Active;
                    l.signal = signal;
                    return Ok(());
                }
            }
        }

        if self.count >= MAX_LEASES {
            return Err(Error::OutOfMemory);
        }
        for slot in self.leases.iter_mut() {
            if slot.is_none() {
                *slot = Some(Lease::new(ino, pid, lease_type, signal));
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get the current lease type for `(ino, pid)`.
    pub fn get_lease(&self, ino: u64, pid: u32) -> u32 {
        for slot in self.leases.iter() {
            if let Some(l) = slot {
                if l.ino == ino && l.pid == pid && l.is_active() {
                    return match l.lease_type {
                        LeaseType::Read => F_RDLCK,
                        LeaseType::Write => F_WRLCK,
                    };
                }
            }
        }
        F_UNLCK
    }

    /// Remove a lease held by `pid` on `ino`.
    pub fn remove_lease(&mut self, ino: u64, pid: u32) -> Result<()> {
        for slot in self.leases.iter_mut() {
            if let Some(l) = slot {
                if l.ino == ino && l.pid == pid {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Notify and begin breaking all write-incompatible leases on `ino`.
    ///
    /// Returns `true` if any leases are currently in the breaking state
    /// (caller should wait or re-check after the grace period).
    pub fn break_leases(&mut self, ino: u64, is_write: bool, now_ms: u64) -> bool {
        let mut breaking = false;
        for slot in self.leases.iter_mut() {
            if let Some(l) = slot {
                if l.ino != ino || !l.is_active() {
                    continue;
                }
                if is_write || l.lease_type == LeaseType::Write {
                    l.begin_break(now_ms);
                    breaking = true;
                }
            }
        }
        breaking
    }

    /// Forcibly expire all leases whose grace period has elapsed.
    ///
    /// Returns the number of leases forcibly released.
    pub fn expire_broken(&mut self, now_ms: u64) -> usize {
        let mut count = 0;
        for slot in self.leases.iter_mut() {
            if let Some(l) = slot {
                if l.grace_expired(now_ms) {
                    *slot = None;
                    count += 1;
                }
            }
        }
        self.count = self.count.saturating_sub(count);
        count
    }

    /// Remove all leases held by `pid` (e.g., on process exit).
    pub fn remove_pid(&mut self, pid: u32) {
        for slot in self.leases.iter_mut() {
            if let Some(l) = slot {
                if l.pid == pid {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Returns the number of active leases.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for LeaseTable {
    fn default() -> Self {
        Self::new()
    }
}

// Global operations performed through owned instance, avoiding static mut.
