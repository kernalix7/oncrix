// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Autofs kernel automounter filesystem.
//!
//! Implements the Linux-compatible autofs kernel side. User-space automount
//! daemons communicate with the kernel via an anonymous pipe; the kernel sends
//! [`AutofsPacket`] messages to the daemon when a lookup or expiry occurs, and
//! the daemon mounts/unmounts filesystems in response.
//!
//! # Design
//!
//! - [`AutofsSuperblock`] — one per mount, owns the wait queue and pipe fds.
//! - [`AutofsWaitQueue`] — ring of up to [`MAX_PENDING_REQS`] pending requests.
//! - [`AutofsDentry`] — per-dentry automount state (pending / mounted / expired).
//! - [`AutofsPacket`] — wire format sent to the daemon (missing / expire).
//!
//! # Daemon protocol
//!
//! 1. Daemon opens `/dev/autofs` (or an ioctl to get a pipe pair).
//! 2. Kernel writes an [`AutofsPacket`] into the write end whenever a path is
//!    looked up that has no current mount.
//! 3. Daemon mounts the target and calls `AUTOFS_IOC_READY` (or
//!    `AUTOFS_IOC_FAIL`) via ioctl to wake the waiting process.
//! 4. For expiry, the kernel sends an [`AutofsPacketType::Expire`] packet; the
//!    daemon unmounts the target and calls `AUTOFS_IOC_EXPIRE_DONE`.
//!
//! Reference: Linux `fs/autofs/`, `include/uapi/linux/auto_fs.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum concurrent pending automount requests.
pub const MAX_PENDING_REQS: usize = 64;

/// Maximum length of a path component in an autofs packet.
pub const AUTOFS_MAX_NAME: usize = 256;

/// Maximum number of dentry slots tracked per superblock.
pub const MAX_AUTOFS_DENTRIES: usize = 128;

/// Maximum number of ioctl commands that can be queued.
pub const MAX_IOCTL_CMDS: usize = 16;

// ---------------------------------------------------------------------------
// AutofsVersion
// ---------------------------------------------------------------------------

/// Autofs protocol version negotiated with the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutofsVersion {
    /// Major protocol version (kernel supports 5).
    pub major: u32,
    /// Minor protocol version.
    pub minor: u32,
}

impl AutofsVersion {
    /// The default kernel-side autofs protocol version.
    pub const fn default_version() -> Self {
        Self { major: 5, minor: 4 }
    }

    /// Return `true` if this version is compatible with the kernel's.
    pub fn is_compatible(self) -> bool {
        self.major == 5
    }
}

impl Default for AutofsVersion {
    fn default() -> Self {
        Self::default_version()
    }
}

// ---------------------------------------------------------------------------
// AutofsPacketType
// ---------------------------------------------------------------------------

/// Type tag embedded in every autofs packet sent to the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AutofsPacketType {
    /// A path lookup caused a miss; daemon should mount the target.
    Missing = 0,
    /// A mounted subtree has been idle long enough; daemon should unmount it.
    Expire = 1,
    /// Expiry with full path (v5+ extension).
    ExpireDirect = 2,
    /// Indirect expiry (v5+ extension).
    ExpireIndirect = 3,
}

// ---------------------------------------------------------------------------
// AutofsPacket
// ---------------------------------------------------------------------------

/// Wire-format packet written to the daemon pipe.
///
/// The daemon reads one [`AutofsPacket`] at a time from its read end of the
/// control pipe. It identifies the request via `wait_queue_token` and,
/// upon completion, calls the appropriate ioctl with the same token.
#[derive(Debug, Clone, Copy)]
pub struct AutofsPacket {
    /// Unique token identifying this wait-queue entry.
    pub wait_queue_token: u64,
    /// Packet type (missing lookup or expiry).
    pub packet_type: AutofsPacketType,
    /// Length of `name` in bytes.
    pub name_len: u32,
    /// Path component or full path being automounted / expired.
    pub name: [u8; AUTOFS_MAX_NAME],
    /// Device number of the mount point (for expiry packets).
    pub dev: u64,
    /// Inode number of the mount point (for expiry packets).
    pub ino: u64,
    /// UID of the process that triggered the lookup.
    pub uid: u32,
    /// GID of the process that triggered the lookup.
    pub gid: u32,
    /// PID of the process that triggered the lookup.
    pub pid: u32,
    /// TGID (thread group leader) of the triggering process.
    pub tgid: u32,
}

impl AutofsPacket {
    /// Construct a `Missing` packet for a path lookup.
    pub fn missing(token: u64, name: &[u8], uid: u32, gid: u32, pid: u32, tgid: u32) -> Self {
        let copy_len = name.len().min(AUTOFS_MAX_NAME);
        let mut name_buf = [0u8; AUTOFS_MAX_NAME];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            wait_queue_token: token,
            packet_type: AutofsPacketType::Missing,
            name_len: copy_len as u32,
            name: name_buf,
            dev: 0,
            ino: 0,
            uid,
            gid,
            pid,
            tgid,
        }
    }

    /// Construct an `Expire` packet for an idle mount.
    pub fn expire(token: u64, name: &[u8], dev: u64, ino: u64) -> Self {
        let copy_len = name.len().min(AUTOFS_MAX_NAME);
        let mut name_buf = [0u8; AUTOFS_MAX_NAME];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            wait_queue_token: token,
            packet_type: AutofsPacketType::Expire,
            name_len: copy_len as u32,
            name: name_buf,
            dev,
            ino,
            uid: 0,
            gid: 0,
            pid: 0,
            tgid: 0,
        }
    }

    /// Return the name as a byte slice (without null padding).
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ---------------------------------------------------------------------------
// WaitStatus
// ---------------------------------------------------------------------------

/// Outcome of an automount wait entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    /// Still waiting for the daemon to respond.
    Pending,
    /// Daemon reported success; mount is ready.
    Ready,
    /// Daemon reported failure (mount failed).
    Failed,
}

// ---------------------------------------------------------------------------
// AutofsWaitEntry
// ---------------------------------------------------------------------------

/// A single entry in the [`AutofsWaitQueue`].
#[derive(Debug, Clone, Copy)]
pub struct AutofsWaitEntry {
    /// Unique token for this wait entry.
    pub token: u64,
    /// The packet sent to the daemon.
    pub packet: AutofsPacket,
    /// Current status.
    pub status: WaitStatus,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl AutofsWaitEntry {
    const fn empty() -> Self {
        Self {
            token: 0,
            packet: AutofsPacket {
                wait_queue_token: 0,
                packet_type: AutofsPacketType::Missing,
                name_len: 0,
                name: [0u8; AUTOFS_MAX_NAME],
                dev: 0,
                ino: 0,
                uid: 0,
                gid: 0,
                pid: 0,
                tgid: 0,
            },
            status: WaitStatus::Pending,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// AutofsWaitQueue
// ---------------------------------------------------------------------------

/// Ring-buffer of pending automount / expiry requests.
///
/// Holds up to [`MAX_PENDING_REQS`] simultaneous outstanding requests.
/// The daemon resolves each entry by calling the appropriate ioctl with
/// the matching `wait_queue_token`.
pub struct AutofsWaitQueue {
    /// Fixed-size slot array.
    entries: [AutofsWaitEntry; MAX_PENDING_REQS],
    /// Monotonically increasing token counter.
    next_token: u64,
    /// Number of currently active (pending) entries.
    active_count: usize,
}

impl AutofsWaitQueue {
    /// Create an empty wait queue.
    pub const fn new() -> Self {
        const EMPTY: AutofsWaitEntry = AutofsWaitEntry::empty();
        Self {
            entries: [EMPTY; MAX_PENDING_REQS],
            next_token: 1,
            active_count: 0,
        }
    }

    /// Allocate a new token and enqueue `packet`.
    ///
    /// Returns the token assigned to this request, or
    /// `Err(Error::OutOfMemory)` if the queue is full.
    pub fn enqueue(&mut self, packet: AutofsPacket) -> Result<u64> {
        if self.active_count >= MAX_PENDING_REQS {
            return Err(Error::OutOfMemory);
        }
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        for slot in self.entries.iter_mut() {
            if !slot.active {
                slot.token = token;
                slot.packet = packet;
                slot.status = WaitStatus::Pending;
                slot.active = true;
                self.active_count += 1;
                return Ok(token);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Mark the request identified by `token` as ready (daemon succeeded).
    pub fn complete_ready(&mut self, token: u64) -> Result<()> {
        self.set_status(token, WaitStatus::Ready)
    }

    /// Mark the request identified by `token` as failed (daemon failed).
    pub fn complete_failed(&mut self, token: u64) -> Result<()> {
        self.set_status(token, WaitStatus::Failed)
    }

    fn set_status(&mut self, token: u64, status: WaitStatus) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.active && slot.token == token {
                slot.status = status;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove and return an entry by token, regardless of status.
    pub fn dequeue(&mut self, token: u64) -> Result<AutofsWaitEntry> {
        for slot in self.entries.iter_mut() {
            if slot.active && slot.token == token {
                slot.active = false;
                self.active_count -= 1;
                return Ok(*slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Look up an entry by token without removing it.
    pub fn find(&self, token: u64) -> Option<&AutofsWaitEntry> {
        self.entries.iter().find(|e| e.active && e.token == token)
    }

    /// Iterate over all active pending entries.
    pub fn pending_iter(&self) -> impl Iterator<Item = &AutofsWaitEntry> {
        self.entries
            .iter()
            .filter(|e| e.active && e.status == WaitStatus::Pending)
    }

    /// Number of outstanding requests.
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for AutofsWaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AutofsDentryState
// ---------------------------------------------------------------------------

/// Per-dentry automount state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutofsDentryState {
    /// No active mount; a lookup will trigger a daemon request.
    Pending,
    /// A daemon request is in flight; lookups must wait.
    InProgress,
    /// A filesystem is currently mounted here.
    Mounted,
    /// The mount has been flagged for expiry.
    Expiring,
}

// ---------------------------------------------------------------------------
// AutofsDentry
// ---------------------------------------------------------------------------

/// Automount state for a single directory entry.
#[derive(Debug, Clone, Copy)]
pub struct AutofsDentry {
    /// Entry name (path component).
    pub name: [u8; AUTOFS_MAX_NAME],
    /// Length of the name.
    pub name_len: u16,
    /// Current mount state.
    pub state: AutofsDentryState,
    /// Token of the in-flight request, if `state == InProgress`.
    pub pending_token: Option<u64>,
    /// Monotonic timestamp of last access (used by expiry logic).
    pub last_used: u64,
    /// Whether this dentry slot is occupied.
    pub active: bool,
}

impl AutofsDentry {
    const fn empty() -> Self {
        Self {
            name: [0u8; AUTOFS_MAX_NAME],
            name_len: 0,
            state: AutofsDentryState::Pending,
            pending_token: None,
            last_used: 0,
            active: false,
        }
    }

    /// Create a new dentry entry for `name`.
    fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > AUTOFS_MAX_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self::empty();
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len() as u16;
        entry.active = true;
        Ok(entry)
    }

    /// Return the name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ---------------------------------------------------------------------------
// AutofsIoctlCmd
// ---------------------------------------------------------------------------

/// Ioctl commands understood by autofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutofsIoctlCmd {
    /// Notify the kernel that the daemon is ready (mount succeeded).
    Ready(u64),
    /// Notify the kernel that the daemon failed.
    Fail(u64),
    /// Set the expiry timeout (seconds).
    SetTimeout(u64),
    /// Mark expiry of a mount as done.
    ExpireDone(u64),
    /// Request protocol version negotiation.
    ProtoVersion,
    /// Query whether a specific path is mounted.
    AskMounted,
}

// ---------------------------------------------------------------------------
// AutofsMountFlags
// ---------------------------------------------------------------------------

/// Mount flags controlling autofs behaviour.
#[derive(Debug, Clone, Copy)]
pub struct AutofsMountFlags {
    /// Enable direct mounts (single-level).
    pub direct: bool,
    /// Enable indirect mounts (multi-level).
    pub indirect: bool,
    /// Enable offset mounts (multi-component).
    pub offset: bool,
    /// Expiry timeout in seconds (0 = disabled).
    pub timeout_secs: u64,
}

impl Default for AutofsMountFlags {
    fn default() -> Self {
        Self {
            direct: false,
            indirect: true,
            offset: false,
            timeout_secs: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// AutofsSuperblock
// ---------------------------------------------------------------------------

/// Autofs filesystem superblock — one per mount point.
///
/// Owns the wait queue, dentry table, mount flags, and the pipe
/// file descriptors used to communicate with the automount daemon.
pub struct AutofsSuperblock {
    /// Protocol version negotiated with the daemon.
    pub version: AutofsVersion,
    /// Pending request queue.
    pub wait_queue: AutofsWaitQueue,
    /// Dentry state table.
    dentries: [AutofsDentry; MAX_AUTOFS_DENTRIES],
    /// Number of active dentry entries.
    dentry_count: usize,
    /// Mount flags.
    pub flags: AutofsMountFlags,
    /// Pipe write-end fd (kernel writes packets here).
    pub pipe_write_fd: i32,
    /// Pipe read-end fd (daemon reads packets from here).
    pub pipe_read_fd: i32,
    /// PID of the automount daemon.
    pub daemon_pid: u32,
    /// Whether the superblock is fully initialised.
    pub mounted: bool,
    /// Pending ioctl command ring.
    ioctl_ring: [Option<AutofsIoctlCmd>; MAX_IOCTL_CMDS],
    /// Write index into ioctl ring.
    ioctl_write: usize,
    /// Read index into ioctl ring.
    ioctl_read: usize,
    /// Count of pending ioctl commands.
    ioctl_count: usize,
}

impl AutofsSuperblock {
    /// Create an uninitialised superblock.
    pub const fn new() -> Self {
        const EMPTY_DENTRY: AutofsDentry = AutofsDentry::empty();
        const NONE_IOCTL: Option<AutofsIoctlCmd> = None;
        Self {
            version: AutofsVersion { major: 5, minor: 4 },
            wait_queue: AutofsWaitQueue::new(),
            dentries: [EMPTY_DENTRY; MAX_AUTOFS_DENTRIES],
            dentry_count: 0,
            flags: AutofsMountFlags {
                direct: false,
                indirect: true,
                offset: false,
                timeout_secs: 300,
            },
            pipe_write_fd: -1,
            pipe_read_fd: -1,
            daemon_pid: 0,
            mounted: false,
            ioctl_ring: [NONE_IOCTL; MAX_IOCTL_CMDS],
            ioctl_write: 0,
            ioctl_read: 0,
            ioctl_count: 0,
        }
    }

    // --- Lifecycle ----------------------------------------------------------

    /// Mount autofs with the given pipe fds and daemon PID.
    ///
    /// `pipe_read_fd` and `pipe_write_fd` must refer to the two ends of
    /// an anonymous pipe opened before calling `mount`.
    pub fn mount(&mut self, pipe_read_fd: i32, pipe_write_fd: i32, daemon_pid: u32) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        if pipe_read_fd < 0 || pipe_write_fd < 0 {
            return Err(Error::InvalidArgument);
        }
        self.pipe_read_fd = pipe_read_fd;
        self.pipe_write_fd = pipe_write_fd;
        self.daemon_pid = daemon_pid;
        self.mounted = true;
        Ok(())
    }

    /// Unmount: flush pending requests and reset state.
    pub fn umount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        // Fail all pending requests so waiting processes wake up.
        for slot in self.wait_queue.entries.iter_mut() {
            if slot.active && slot.status == WaitStatus::Pending {
                slot.status = WaitStatus::Failed;
            }
        }
        self.mounted = false;
        Ok(())
    }

    // --- Path lookup (automount trigger) ------------------------------------

    /// Initiate an automount for `name`.
    ///
    /// Builds an [`AutofsPacket::missing`] packet, enqueues it, and
    /// returns the assigned token. The caller is responsible for
    /// writing the packet to `pipe_write_fd`.
    pub fn autofs_mount(&mut self, name: &[u8], uid: u32, gid: u32, pid: u32) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        // Locate or create the dentry.
        let dentry_idx = self.find_or_create_dentry(name)?;
        match self.dentries[dentry_idx].state {
            AutofsDentryState::Mounted => return Err(Error::AlreadyExists),
            AutofsDentryState::InProgress => {
                // Already a request in flight.
                return self.dentries[dentry_idx].pending_token.ok_or(Error::Busy);
            }
            _ => {}
        }
        let packet = AutofsPacket::missing(0, name, uid, gid, pid, pid);
        let token = self.wait_queue.enqueue(packet)?;
        self.dentries[dentry_idx].state = AutofsDentryState::InProgress;
        self.dentries[dentry_idx].pending_token = Some(token);
        Ok(token)
    }

    /// Retrieve the packet queued for delivery to the daemon.
    ///
    /// Returns the packet for a pending request identified by `token`.
    pub fn get_pending_packet(&self, token: u64) -> Result<AutofsPacket> {
        self.wait_queue
            .find(token)
            .map(|e| e.packet)
            .ok_or(Error::NotFound)
    }

    // --- Daemon response ----------------------------------------------------

    /// `AUTOFS_IOC_READY` — daemon successfully mounted the path.
    pub fn ioctl_ready(&mut self, token: u64) -> Result<()> {
        self.wait_queue.complete_ready(token)?;
        self.mark_dentry_for_token(token, AutofsDentryState::Mounted);
        Ok(())
    }

    /// `AUTOFS_IOC_FAIL` — daemon failed to mount the path.
    pub fn ioctl_fail(&mut self, token: u64) -> Result<()> {
        self.wait_queue.complete_failed(token)?;
        self.mark_dentry_for_token(token, AutofsDentryState::Pending);
        Ok(())
    }

    /// `AUTOFS_IOC_EXPIRE_DONE` — daemon finished unmounting.
    pub fn ioctl_expire_done(&mut self, token: u64) -> Result<()> {
        self.wait_queue.complete_ready(token)?;
        self.remove_dentry_for_token(token);
        Ok(())
    }

    /// `AUTOFS_IOC_SETTIMEOUT` — set the expiry timeout.
    pub fn ioctl_set_timeout(&mut self, secs: u64) -> Result<()> {
        self.flags.timeout_secs = secs;
        Ok(())
    }

    // --- Expiry -------------------------------------------------------------

    /// Check for dentries that have been idle longer than the timeout.
    ///
    /// Returns the token of the first expiry request sent, or `None` if
    /// no dentry is due for expiry. `now` is a monotonic tick count in
    /// seconds.
    pub fn expire(&mut self, now: u64) -> Result<Option<u64>> {
        if !self.mounted || self.flags.timeout_secs == 0 {
            return Ok(None);
        }
        // Find the first mounted dentry that has exceeded the timeout.
        let mut expired_idx = None;
        for (i, d) in self.dentries.iter().enumerate() {
            if d.active
                && d.state == AutofsDentryState::Mounted
                && now.saturating_sub(d.last_used) >= self.flags.timeout_secs
            {
                expired_idx = Some(i);
                break;
            }
        }
        let idx = match expired_idx {
            Some(i) => i,
            None => return Ok(None),
        };
        let name_len = self.dentries[idx].name_len as usize;
        let mut name_copy = [0u8; AUTOFS_MAX_NAME];
        name_copy[..name_len].copy_from_slice(&self.dentries[idx].name[..name_len]);
        let packet = AutofsPacket::expire(0, &name_copy[..name_len], 0, 0);
        let token = self.wait_queue.enqueue(packet)?;
        self.dentries[idx].state = AutofsDentryState::Expiring;
        self.dentries[idx].pending_token = Some(token);
        Ok(Some(token))
    }

    // --- Dev-ioctl dispatch -------------------------------------------------

    /// Dispatch a dev-ioctl command from user space.
    ///
    /// Returns encoded response bytes into `buf` and the byte count written.
    pub fn dev_ioctl(&mut self, cmd: AutofsIoctlCmd, buf: &mut [u8]) -> Result<usize> {
        match cmd {
            AutofsIoctlCmd::ProtoVersion => {
                // Write `major.minor` as two u32 LE values.
                if buf.len() < 8 {
                    return Err(Error::InvalidArgument);
                }
                let maj = self.version.major.to_le_bytes();
                let min = self.version.minor.to_le_bytes();
                buf[..4].copy_from_slice(&maj);
                buf[4..8].copy_from_slice(&min);
                Ok(8)
            }
            AutofsIoctlCmd::Ready(token) => {
                self.ioctl_ready(token)?;
                Ok(0)
            }
            AutofsIoctlCmd::Fail(token) => {
                self.ioctl_fail(token)?;
                Ok(0)
            }
            AutofsIoctlCmd::SetTimeout(secs) => {
                self.ioctl_set_timeout(secs)?;
                Ok(0)
            }
            AutofsIoctlCmd::ExpireDone(token) => {
                self.ioctl_expire_done(token)?;
                Ok(0)
            }
            AutofsIoctlCmd::AskMounted => {
                // Return 1-byte: 0 = not mounted, 1 = mounted.
                if buf.is_empty() {
                    return Err(Error::InvalidArgument);
                }
                buf[0] = if self.mounted { 1 } else { 0 };
                Ok(1)
            }
        }
    }

    // --- Helpers ------------------------------------------------------------

    fn find_or_create_dentry(&mut self, name: &[u8]) -> Result<usize> {
        // Search for existing.
        for (i, d) in self.dentries.iter().enumerate() {
            if d.active && d.name_bytes() == name {
                return Ok(i);
            }
        }
        // Allocate new.
        if self.dentry_count >= MAX_AUTOFS_DENTRIES {
            return Err(Error::OutOfMemory);
        }
        let entry = AutofsDentry::new(name)?;
        for (i, slot) in self.dentries.iter_mut().enumerate() {
            if !slot.active {
                *slot = entry;
                self.dentry_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn mark_dentry_for_token(&mut self, token: u64, state: AutofsDentryState) {
        for d in self.dentries.iter_mut() {
            if d.active && d.pending_token == Some(token) {
                d.state = state;
                d.pending_token = None;
                return;
            }
        }
    }

    fn remove_dentry_for_token(&mut self, token: u64) {
        for d in self.dentries.iter_mut() {
            if d.active && d.pending_token == Some(token) {
                d.active = false;
                d.pending_token = None;
                if self.dentry_count > 0 {
                    self.dentry_count -= 1;
                }
                return;
            }
        }
    }

    /// Update the last-used timestamp for `name`.
    pub fn touch_dentry(&mut self, name: &[u8], now: u64) {
        for d in self.dentries.iter_mut() {
            if d.active && d.name_bytes() == name {
                d.last_used = now;
                return;
            }
        }
    }

    /// Look up the current state of `name`.
    pub fn dentry_state(&self, name: &[u8]) -> Option<AutofsDentryState> {
        self.dentries
            .iter()
            .find(|d| d.active && d.name_bytes() == name)
            .map(|d| d.state)
    }

    /// Number of active dentries.
    pub fn dentry_count(&self) -> usize {
        self.dentry_count
    }
}

impl Default for AutofsSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AutofsSuperblock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AutofsSuperblock")
            .field("mounted", &self.mounted)
            .field("daemon_pid", &self.daemon_pid)
            .field("version", &self.version)
            .field("dentry_count", &self.dentry_count)
            .field("pending_requests", &self.wait_queue.active_count())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global autofs superblock (one mount assumed for now).
static mut AUTOFS_SB: Option<AutofsSuperblock> = None;

/// Initialise the global autofs superblock.
///
/// # Safety
///
/// Must be called exactly once during single-threaded kernel initialisation.
pub unsafe fn autofs_init() {
    // SAFETY: Single-threaded init; no concurrent access.
    unsafe {
        *core::ptr::addr_of_mut!(AUTOFS_SB) = Some(AutofsSuperblock::new());
    }
}

/// Obtain a shared reference to the global autofs superblock.
pub fn autofs_get() -> Option<&'static AutofsSuperblock> {
    // SAFETY: Read-only after init; superblock is never moved.
    unsafe { (*core::ptr::addr_of!(AUTOFS_SB)).as_ref() }
}

/// Obtain a mutable reference to the global autofs superblock.
///
/// # Safety
///
/// The caller must ensure no other reference is live.
pub unsafe fn autofs_get_mut() -> Option<&'static mut AutofsSuperblock> {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { (*core::ptr::addr_of_mut!(AUTOFS_SB)).as_mut() }
}
