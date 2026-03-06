// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File lease support (`fcntl` `F_SETLEASE` / `F_GETLEASE`).
//!
//! File leases allow a process to be notified (via signal) when another
//! process opens a file it holds a lease on. This provides a cooperative
//! mechanism for applications to maintain cache coherency, and is the
//! basis for NFS delegation.
//!
//! # Lease types
//!
//! - **Read lease** (`F_RDLCK`): The leaseholder is notified when any
//!   process opens the file for writing. Multiple read leases may
//!   coexist on the same file.
//! - **Write lease** (`F_WRLCK`): The leaseholder is notified when any
//!   other process opens the file (for reading or writing). Only one
//!   write lease may exist per file.
//!
//! # Lease lifecycle
//!
//! 1. A process acquires a lease with `fcntl(fd, F_SETLEASE, type)`.
//! 2. When a conflicting open occurs, the kernel sends `SIGIO` (or the
//!    signal set by `F_SETSIG`) to the leaseholder.
//! 3. The leaseholder has `break_timeout` seconds to downgrade or
//!    release the lease before the kernel forcibly breaks it.
//! 4. The process may voluntarily downgrade (write -> read) or release
//!    the lease at any time.
//!
//! # NFS delegation
//!
//! NFS servers use file leases as the kernel-side mechanism for NFSv4
//! delegations. A delegation lease is essentially a remote read/write
//! lease that must be recalled before the server grants conflicting
//! access to another client.
//!
//! # References
//!
//! - Linux `fcntl(2)` — `F_SETLEASE`, `F_GETLEASE`
//! - POSIX.1-2024 `fcntl()` (informative, leases are Linux-specific)
//! - Linux kernel `fs/locks.c`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Lease type: read lease.
pub const F_RDLCK: i32 = 0;

/// Lease type: write lease.
pub const F_WRLCK: i32 = 1;

/// Lease type: unlock (release lease).
pub const F_UNLCK: i32 = 2;

/// fcntl command: set file lease.
pub const F_SETLEASE: i32 = 1024;

/// fcntl command: get file lease.
pub const F_GETLEASE: i32 = 1025;

/// Default break timeout in seconds.
pub const DEFAULT_BREAK_TIMEOUT_SECS: u32 = 45;

/// Maximum number of concurrent leases system-wide.
const MAX_LEASES: usize = 256;

/// Maximum number of pending break notifications.
const MAX_BREAK_QUEUE: usize = 64;

/// Lease state: active and held.
const LEASE_STATE_ACTIVE: u8 = 1;

/// Lease state: break in progress (waiting for leaseholder response).
const LEASE_STATE_BREAKING: u8 = 2;

/// Delegation type: none.
pub const DELEGATION_NONE: u8 = 0;

/// Delegation type: NFS read delegation.
pub const DELEGATION_READ: u8 = 1;

/// Delegation type: NFS write delegation.
pub const DELEGATION_WRITE: u8 = 2;

// ── LeaseType ────────────────────────────────────────────────────

/// Type of a file lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeaseType {
    /// Read lease — notified on write-opens.
    Read = 0,
    /// Write lease — notified on any open.
    Write = 1,
}

impl LeaseType {
    /// Convert from an `fcntl` lease type constant.
    pub fn from_fcntl(val: i32) -> Option<Self> {
        match val {
            F_RDLCK => Some(Self::Read),
            F_WRLCK => Some(Self::Write),
            _ => None,
        }
    }

    /// Convert to an `fcntl` lease type constant.
    pub fn to_fcntl(self) -> i32 {
        match self {
            Self::Read => F_RDLCK,
            Self::Write => F_WRLCK,
        }
    }
}

// ── Lease ────────────────────────────────────────────────────────

/// A single file lease held by a process.
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    /// Inode number the lease applies to.
    pub inode: u64,
    /// PID of the leaseholder.
    pub owner_pid: u64,
    /// File descriptor used to acquire the lease.
    pub fd: i32,
    /// Lease type (read or write).
    pub lease_type: LeaseType,
    /// Current state of the lease.
    state: u8,
    /// Delegation type for NFS (0 = none).
    pub delegation: u8,
    /// Break timeout in seconds.
    pub break_timeout: u32,
    /// Timestamp (kernel ticks) when break was initiated.
    pub break_start_tick: u64,
    /// Signal number to deliver on break (default: SIGIO = 29).
    pub notify_signal: i32,
}

impl Lease {
    /// Creates a new active lease.
    fn new(inode: u64, owner_pid: u64, fd: i32, lease_type: LeaseType) -> Self {
        Self {
            inode,
            owner_pid,
            fd,
            lease_type,
            state: LEASE_STATE_ACTIVE,
            delegation: DELEGATION_NONE,
            break_timeout: DEFAULT_BREAK_TIMEOUT_SECS,
            break_start_tick: 0,
            notify_signal: 29, // SIGIO
        }
    }

    /// Returns `true` if the lease is in the active state.
    pub fn is_active(&self) -> bool {
        self.state == LEASE_STATE_ACTIVE
    }

    /// Returns `true` if the lease is being broken.
    pub fn is_breaking(&self) -> bool {
        self.state == LEASE_STATE_BREAKING
    }

    /// Returns `true` if this is an NFS delegation lease.
    pub fn is_delegation(&self) -> bool {
        self.delegation != DELEGATION_NONE
    }
}

// ── BreakNotification ────────────────────────────────────────────

/// A pending lease break notification to be delivered to a leaseholder.
#[derive(Debug, Clone, Copy)]
pub struct BreakNotification {
    /// Inode whose lease is being broken.
    pub inode: u64,
    /// PID of the leaseholder to notify.
    pub target_pid: u64,
    /// Signal to deliver.
    pub signal: i32,
    /// The new lease type after downgrade (Read), or F_UNLCK if full break.
    pub break_to: i32,
    /// Whether this notification has been delivered.
    pub delivered: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl BreakNotification {
    /// Creates an empty notification slot.
    const fn empty() -> Self {
        Self {
            inode: 0,
            target_pid: 0,
            signal: 0,
            break_to: 0,
            delivered: false,
            active: false,
        }
    }
}

// ── LeaseTable ───────────────────────────────────────────────────

/// System-wide file lease table.
///
/// Manages up to [`MAX_LEASES`] concurrent file leases. Handles
/// acquisition, release, break initiation, timeout enforcement, and
/// NFS delegation support.
pub struct LeaseTable {
    /// Lease slots.
    leases: [Option<Lease>; MAX_LEASES],
    /// Pending break notifications.
    breaks: [BreakNotification; MAX_BREAK_QUEUE],
    /// Number of active leases.
    count: usize,
    /// Global break timeout override (0 = use per-lease timeout).
    global_break_timeout: u32,
}

impl Default for LeaseTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaseTable {
    /// Creates an empty lease table.
    pub const fn new() -> Self {
        const NONE: Option<Lease> = None;
        Self {
            leases: [NONE; MAX_LEASES],
            breaks: [BreakNotification::empty(); MAX_BREAK_QUEUE],
            count: 0,
            global_break_timeout: 0,
        }
    }

    /// Set a lease on a file (`fcntl F_SETLEASE`).
    ///
    /// # Arguments
    ///
    /// - `inode` — inode number of the file
    /// - `pid` — PID of the calling process
    /// - `fd` — file descriptor
    /// - `lease_type` — `F_RDLCK`, `F_WRLCK`, or `F_UNLCK`
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — invalid lease type
    /// - [`Error::Busy`] — a conflicting lease exists
    /// - [`Error::OutOfMemory`] — no free lease slots
    pub fn set_lease(&mut self, inode: u64, pid: u64, fd: i32, lease_type: i32) -> Result<()> {
        if lease_type == F_UNLCK {
            return self.release_lease(inode, pid, fd);
        }

        let lt = LeaseType::from_fcntl(lease_type).ok_or(Error::InvalidArgument)?;

        // Check for conflicting leases from other owners.
        if self.has_conflict(inode, pid, lt) {
            return Err(Error::Busy);
        }

        // If the same owner already has a lease on this inode+fd,
        // upgrade or downgrade it.
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    lease.lease_type = lt;
                    lease.state = LEASE_STATE_ACTIVE;
                    return Ok(());
                }
            }
        }

        // Insert a new lease.
        self.insert_lease(Lease::new(inode, pid, fd, lt))
    }

    /// Get the current lease type on a file (`fcntl F_GETLEASE`).
    ///
    /// Returns `F_RDLCK`, `F_WRLCK`, or `F_UNLCK` for the calling
    /// process's lease on the given inode.
    pub fn get_lease(&self, inode: u64, pid: u64, fd: i32) -> i32 {
        for lease in self.leases.iter().flatten() {
            if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                return lease.lease_type.to_fcntl();
            }
        }
        F_UNLCK
    }

    /// Release a specific lease.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching lease exists.
    pub fn release_lease(&mut self, inode: u64, pid: u64, fd: i32) -> Result<()> {
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Release all leases held by a process.
    ///
    /// Called during process exit or `close()` cleanup.
    /// Returns the number of leases released.
    pub fn release_all_for_pid(&mut self, pid: u64) -> usize {
        let mut released = 0;
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.owner_pid == pid {
                    *slot = None;
                    self.count -= 1;
                    released += 1;
                }
            }
        }
        released
    }

    /// Release all leases on an inode.
    ///
    /// Called during inode eviction. Returns the number released.
    pub fn release_all_for_inode(&mut self, inode: u64) -> usize {
        let mut released = 0;
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode {
                    *slot = None;
                    self.count -= 1;
                    released += 1;
                }
            }
        }
        released
    }

    /// Initiate a lease break on all conflicting leases for `inode`.
    ///
    /// This is called when a new `open()` conflicts with existing
    /// leases. Each affected leaseholder receives a break notification.
    ///
    /// # Arguments
    ///
    /// - `inode` — the file being opened
    /// - `opener_pid` — PID of the process opening the file
    /// - `for_write` — `true` if the open is for writing
    /// - `current_tick` — current kernel tick for timeout tracking
    ///
    /// Returns the number of leases being broken.
    pub fn initiate_break(
        &mut self,
        inode: u64,
        opener_pid: u64,
        for_write: bool,
        current_tick: u64,
    ) -> usize {
        let mut broken = 0;

        // First pass: collect notification data to avoid double mutable borrow.
        let mut pending: [(u64, i32, i32); MAX_LEASES] = [(0, 0, 0); MAX_LEASES];
        let mut pending_count = 0;

        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode != inode || lease.owner_pid == opener_pid {
                    continue;
                }

                let should_break = match lease.lease_type {
                    LeaseType::Write => true,
                    LeaseType::Read => for_write,
                };

                if !should_break || lease.is_breaking() {
                    continue;
                }

                lease.state = LEASE_STATE_BREAKING;
                lease.break_start_tick = current_tick;

                // Determine what the lease should downgrade to.
                let break_to = if lease.lease_type == LeaseType::Write && !for_write {
                    F_RDLCK // Downgrade write -> read
                } else {
                    F_UNLCK // Full break
                };

                pending[pending_count] = (lease.owner_pid, lease.notify_signal, break_to);
                pending_count += 1;
                broken += 1;
            }
        }

        // Second pass: queue notifications.
        for i in 0..pending_count {
            let (owner_pid, signal, break_to) = pending[i];
            self.queue_break_notification(inode, owner_pid, signal, break_to);
        }

        broken
    }

    /// Check whether any leases are still breaking on `inode`.
    ///
    /// Returns `true` if at least one lease is in the BREAKING state.
    pub fn has_pending_breaks(&self, inode: u64) -> bool {
        self.leases
            .iter()
            .flatten()
            .any(|l| l.inode == inode && l.state == LEASE_STATE_BREAKING)
    }

    /// Process lease break timeouts.
    ///
    /// For any lease in BREAKING state whose timeout has expired,
    /// forcibly release or downgrade the lease. Call this periodically
    /// from the kernel timer tick.
    ///
    /// Returns the number of leases forcibly broken.
    pub fn process_timeouts(&mut self, current_tick: u64) -> usize {
        let mut force_broken = 0;

        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.state != LEASE_STATE_BREAKING {
                    continue;
                }

                let timeout = if self.global_break_timeout > 0 {
                    self.global_break_timeout as u64
                } else {
                    lease.break_timeout as u64
                };

                let elapsed = current_tick.saturating_sub(lease.break_start_tick);
                if elapsed >= timeout {
                    // Timeout expired — forcibly break.
                    *slot = None;
                    self.count -= 1;
                    force_broken += 1;
                }
            }
        }

        force_broken
    }

    /// Downgrade a write lease to a read lease.
    ///
    /// Typically called by the leaseholder in response to a break
    /// notification when only a read conflict was detected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching lease exists.
    /// Returns [`Error::InvalidArgument`] if the lease is already a
    /// read lease.
    pub fn downgrade_lease(&mut self, inode: u64, pid: u64, fd: i32) -> Result<()> {
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    if lease.lease_type == LeaseType::Read {
                        return Err(Error::InvalidArgument);
                    }
                    lease.lease_type = LeaseType::Read;
                    lease.state = LEASE_STATE_ACTIVE;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Upgrade a read lease to a write lease.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching lease exists.
    /// Returns [`Error::Busy`] if other read leases exist on the inode.
    /// Returns [`Error::InvalidArgument`] if already a write lease.
    pub fn upgrade_lease(&mut self, inode: u64, pid: u64, fd: i32) -> Result<()> {
        // Check if other leases would conflict with a write lease.
        let has_other_leases = self
            .leases
            .iter()
            .flatten()
            .any(|l| l.inode == inode && (l.owner_pid != pid || l.fd != fd));
        if has_other_leases {
            return Err(Error::Busy);
        }

        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    if lease.lease_type == LeaseType::Write {
                        return Err(Error::InvalidArgument);
                    }
                    lease.lease_type = LeaseType::Write;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Set an NFS delegation on a lease.
    ///
    /// Marks an existing lease as an NFS delegation lease, changing
    /// the break behavior to use the delegation recall protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching lease exists.
    /// Returns [`Error::InvalidArgument`] if `delegation` is invalid.
    pub fn set_delegation(&mut self, inode: u64, pid: u64, fd: i32, delegation: u8) -> Result<()> {
        if delegation > DELEGATION_WRITE {
            return Err(Error::InvalidArgument);
        }

        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    lease.delegation = delegation;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Set the break timeout for a specific lease.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching lease exists.
    pub fn set_break_timeout(
        &mut self,
        inode: u64,
        pid: u64,
        fd: i32,
        timeout_secs: u32,
    ) -> Result<()> {
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    lease.break_timeout = timeout_secs;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Set the global break timeout override.
    ///
    /// A value of 0 means per-lease timeouts are used.
    pub fn set_global_break_timeout(&mut self, timeout_secs: u32) {
        self.global_break_timeout = timeout_secs;
    }

    /// Set the notification signal for a specific lease.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching lease exists.
    pub fn set_notify_signal(&mut self, inode: u64, pid: u64, fd: i32, signal: i32) -> Result<()> {
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.inode == inode && lease.owner_pid == pid && lease.fd == fd {
                    lease.notify_signal = signal;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Drain pending break notifications.
    ///
    /// Returns an array of notifications and the count of valid ones.
    /// Marks all returned notifications as delivered.
    pub fn drain_notifications(&mut self) -> ([BreakNotification; MAX_BREAK_QUEUE], usize) {
        let mut result = [BreakNotification::empty(); MAX_BREAK_QUEUE];
        let mut count = 0;

        for notif in &mut self.breaks {
            if notif.active && !notif.delivered {
                result[count] = *notif;
                notif.delivered = true;
                count += 1;
            }
        }

        // Manual insertion sort (sort_by_key unavailable in no_std without alloc).
        let mut i = 1;
        while i < count {
            let key = result[i];
            let mut j = i;
            while j > 0 && result[j - 1].target_pid > key.target_pid {
                result[j] = result[j - 1];
                j -= 1;
            }
            result[j] = key;
            i += 1;
        }
        (result, count)
    }

    /// Returns the number of active leases.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no leases are held.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Count leases on a specific inode.
    pub fn count_for_inode(&self, inode: u64) -> usize {
        self.leases
            .iter()
            .filter(|s| s.as_ref().is_some_and(|l| l.inode == inode))
            .count()
    }

    /// Count leases held by a specific process.
    pub fn count_for_pid(&self, pid: u64) -> usize {
        self.leases
            .iter()
            .filter(|s| s.as_ref().is_some_and(|l| l.owner_pid == pid))
            .count()
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Insert a lease into the first available slot.
    fn insert_lease(&mut self, lease: Lease) -> Result<()> {
        for slot in &mut self.leases {
            if slot.is_none() {
                *slot = Some(lease);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Check whether a conflicting lease exists on `inode` from a
    /// different owner.
    fn has_conflict(&self, inode: u64, pid: u64, new_type: LeaseType) -> bool {
        for lease in self.leases.iter().flatten() {
            if lease.inode != inode || lease.owner_pid == pid {
                continue;
            }
            match (new_type, lease.lease_type) {
                // Write lease conflicts with everything.
                (LeaseType::Write, _) => return true,
                (_, LeaseType::Write) => return true,
                // Read leases do not conflict with each other.
                (LeaseType::Read, LeaseType::Read) => {}
            }
        }
        false
    }

    /// Queue a break notification for delivery.
    fn queue_break_notification(
        &mut self,
        inode: u64,
        target_pid: u64,
        signal: i32,
        break_to: i32,
    ) {
        for notif in &mut self.breaks {
            if !notif.active {
                *notif = BreakNotification {
                    inode,
                    target_pid,
                    signal,
                    break_to,
                    delivered: false,
                    active: true,
                };
                return;
            }
        }
        // Queue full — overwrite oldest delivered notification.
        for notif in &mut self.breaks {
            if notif.delivered {
                *notif = BreakNotification {
                    inode,
                    target_pid,
                    signal,
                    break_to,
                    delivered: false,
                    active: true,
                };
                return;
            }
        }
    }
}

// ── fcntl dispatch ───────────────────────────────────────────────

/// Handle `fcntl(fd, F_SETLEASE, type)`.
///
/// Dispatches to [`LeaseTable::set_lease`]. This is the entry point
/// called from the syscall layer.
pub fn fcntl_setlease(
    table: &mut LeaseTable,
    inode: u64,
    pid: u64,
    fd: i32,
    lease_type: i32,
) -> Result<()> {
    table.set_lease(inode, pid, fd, lease_type)
}

/// Handle `fcntl(fd, F_GETLEASE)`.
///
/// Dispatches to [`LeaseTable::get_lease`]. Returns the current lease
/// type for the calling process.
pub fn fcntl_getlease(table: &LeaseTable, inode: u64, pid: u64, fd: i32) -> i32 {
    table.get_lease(inode, pid, fd)
}

/// Check and break leases on file open.
///
/// Called from the VFS `open()` path before granting access. If
/// conflicting leases exist, initiates a break and returns
/// [`Error::WouldBlock`] so the caller can wait or retry.
///
/// Returns `Ok(())` if no conflicting leases exist.
pub fn break_leases_on_open(
    table: &mut LeaseTable,
    inode: u64,
    opener_pid: u64,
    for_write: bool,
    current_tick: u64,
) -> Result<()> {
    let broken = table.initiate_break(inode, opener_pid, for_write, current_tick);
    if broken > 0 {
        Err(Error::WouldBlock)
    } else {
        Ok(())
    }
}
