// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Eventpoll filesystem — pseudo-filesystem backing `epoll` file descriptors.
//!
//! The eventpoll filesystem is an internal, non-mountable pseudo-filesystem
//! that provides the inode backing for `epoll(7)` file descriptors.  Each call
//! to `epoll_create1(2)` allocates one [`EventpollInode`] here; the inode is
//! freed when the last file descriptor referencing it is closed.
//!
//! # Design
//!
//! ```text
//! epoll_create1()
//!   │
//!   └── EventpollFs::alloc_eventpoll(creation_tick)
//!           │
//!           ├── find free slot in inode table
//!           ├── assign epoll_id = slot index + 1
//!           └── return epoll_id
//!
//! epoll_ctl() / epoll_wait()  ← operates on EventpollInode via epoll_id
//!
//! close(epfd)
//!   └── EventpollFs::eventpoll_release(epoll_id) ← decrement ref_count → free
//! ```
//!
//! # References
//!
//! - Linux `fs/eventpoll.c`, `fs/anon_inodes.c`
//! - `man 7 epoll`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Filesystem magic number for the eventpoll pseudo-filesystem.
pub const EVENTPOLL_FS_MAGIC: u32 = 0xEF01;

/// Maximum number of concurrent epoll instances (inode table size).
pub const MAX_EVENTPOLL_INODES: usize = 128;

/// Pseudo block size returned in `stat` for an eventpoll inode.
pub const EVENTPOLL_BLKSIZE: u32 = 0;

/// Permission mode returned in `stat` for an eventpoll inode (rw------- owner).
pub const EVENTPOLL_MODE: u16 = 0o600;

/// Hard-link count in the pseudo stat (epoll fd is not linked into any directory).
pub const EVENTPOLL_NLINK: u32 = 1;

// ── EventpollInode ────────────────────────────────────────────────────────────

/// The inode backing a single epoll file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct EventpollInode {
    /// Unique identifier for this epoll instance (1-based slot index).
    pub epoll_id: u32,
    /// Number of file descriptors currently referencing this inode.
    pub ref_count: u32,
    /// Value of the kernel tick counter when this inode was created.
    pub creation_tick: u64,
    /// Number of file descriptors registered in the interest list.
    pub interest_count: u32,
    /// Whether this inode slot is occupied.
    pub in_use: bool,
    /// Whether at least one event is pending (drives `eventpoll_poll`).
    pub events_pending: bool,
}

impl Default for EventpollInode {
    fn default() -> Self {
        Self {
            epoll_id: 0,
            ref_count: 0,
            creation_tick: 0,
            interest_count: 0,
            in_use: false,
            events_pending: false,
        }
    }
}

impl EventpollInode {
    /// Construct a new inode for the given `epoll_id`.
    pub const fn new(epoll_id: u32, creation_tick: u64) -> Self {
        Self {
            epoll_id,
            ref_count: 1,
            creation_tick,
            interest_count: 0,
            in_use: true,
            events_pending: false,
        }
    }

    /// Increment the reference count.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrement the reference count; returns `true` when it reaches zero.
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

// ── EventpollSuperblock ───────────────────────────────────────────────────────

/// Superblock for the eventpoll pseudo-filesystem.
#[derive(Debug, Clone, Copy)]
pub struct EventpollSuperblock {
    /// Filesystem magic number (must equal [`EVENTPOLL_FS_MAGIC`]).
    pub magic: u32,
    /// Monotonically increasing inode counter.
    pub next_ino: u64,
}

impl Default for EventpollSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

impl EventpollSuperblock {
    /// Construct the superblock for a fresh eventpoll filesystem.
    pub const fn new() -> Self {
        Self {
            magic: EVENTPOLL_FS_MAGIC,
            next_ino: 1,
        }
    }

    /// Allocate the next inode number.
    pub fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino = self.next_ino.wrapping_add(1).max(1);
        ino
    }
}

// ── EventpollPseudoStat ───────────────────────────────────────────────────────

/// Pseudo-`stat` structure returned by [`eventpoll_fstat`].
#[derive(Debug, Clone, Copy)]
pub struct EventpollPseudoStat {
    /// Inode number.
    pub st_ino: u64,
    /// File mode (always [`EVENTPOLL_MODE`]).
    pub st_mode: u16,
    /// Hard-link count (always [`EVENTPOLL_NLINK`]).
    pub st_nlink: u32,
    /// Block size (always [`EVENTPOLL_BLKSIZE`]).
    pub st_blksize: u32,
    /// File size in bytes (always 0 for epoll inodes).
    pub st_size: u64,
}

// ── EventpollFs ───────────────────────────────────────────────────────────────

/// The eventpoll pseudo-filesystem instance.
///
/// Owns a fixed-size inode table and the filesystem superblock.
pub struct EventpollFs {
    /// Fixed-size inode table.
    inodes: [EventpollInode; MAX_EVENTPOLL_INODES],
    /// Superblock metadata.
    superblock: EventpollSuperblock,
    /// Accumulated operational statistics.
    stats: EventpollFsStats,
}

impl Default for EventpollFs {
    fn default() -> Self {
        Self::new()
    }
}

impl EventpollFs {
    /// Construct an empty eventpoll filesystem.
    pub const fn new() -> Self {
        Self {
            inodes: [const {
                EventpollInode {
                    epoll_id: 0,
                    ref_count: 0,
                    creation_tick: 0,
                    interest_count: 0,
                    in_use: false,
                    events_pending: false,
                }
            }; MAX_EVENTPOLL_INODES],
            superblock: EventpollSuperblock {
                magic: EVENTPOLL_FS_MAGIC,
                next_ino: 1,
            },
            stats: EventpollFsStats::new(),
        }
    }

    /// Allocate a new epoll inode and return its `epoll_id`.
    ///
    /// # Parameters
    ///
    /// - `creation_tick` — current kernel tick for timestamping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the inode table is full.
    pub fn alloc_eventpoll(&mut self, creation_tick: u64) -> Result<u32> {
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let epoll_id = (slot as u32) + 1;
        self.inodes[slot] = EventpollInode::new(epoll_id, creation_tick);
        self.superblock.alloc_ino();
        self.stats.total_created += 1;
        self.stats.current_active += 1;
        Ok(epoll_id)
    }

    /// Free the inode backing `epoll_id`.
    ///
    /// Decrements the reference count; the inode is only truly freed when the
    /// count reaches zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no inode with `epoll_id` exists.
    pub fn free_eventpoll(&mut self, epoll_id: u32) -> Result<()> {
        let slot = self.slot_of(epoll_id).ok_or(Error::NotFound)?;
        let freed = self.inodes[slot].put();
        if freed {
            self.inodes[slot] = EventpollInode::default();
            self.stats.total_destroyed += 1;
            self.stats.current_active = self.stats.current_active.saturating_sub(1);
        }
        Ok(())
    }

    /// Return an immutable reference to the inode for `epoll_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn get(&self, epoll_id: u32) -> Result<&EventpollInode> {
        let slot = self.slot_of(epoll_id).ok_or(Error::NotFound)?;
        Ok(&self.inodes[slot])
    }

    /// Return a mutable reference to the inode for `epoll_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn get_mut(&mut self, epoll_id: u32) -> Result<&mut EventpollInode> {
        let slot = self.slot_of(epoll_id).ok_or(Error::NotFound)?;
        Ok(&mut self.inodes[slot])
    }

    /// Increment the reference count for `epoll_id` (e.g., `dup(2)`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn get_ref(&mut self, epoll_id: u32) -> Result<()> {
        let inode = self.get_mut(epoll_id)?;
        inode.get();
        Ok(())
    }

    /// Return pseudo-`stat` data for `epoll_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn eventpoll_fstat(&self, epoll_id: u32) -> Result<EventpollPseudoStat> {
        let inode = self.get(epoll_id)?;
        Ok(EventpollPseudoStat {
            st_ino: inode.epoll_id as u64,
            st_mode: EVENTPOLL_MODE,
            st_nlink: EVENTPOLL_NLINK,
            st_blksize: EVENTPOLL_BLKSIZE,
            st_size: 0,
        })
    }

    /// Return `true` if there are pending events on `epoll_id` (i.e. readable).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn eventpoll_poll(&self, epoll_id: u32) -> Result<bool> {
        let inode = self.get(epoll_id)?;
        Ok(inode.events_pending)
    }

    /// Mark events as pending on `epoll_id`, waking potential waiters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn mark_events_pending(&mut self, epoll_id: u32, pending: bool) -> Result<()> {
        let inode = self.get_mut(epoll_id)?;
        inode.events_pending = pending;
        Ok(())
    }

    /// Notify that `epoll_id` is being released (last `close(2)` call).
    ///
    /// Removes the inode regardless of the reference count (equivalent to a
    /// forced teardown on the last `close`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when no such inode exists.
    pub fn eventpoll_release(&mut self, epoll_id: u32) -> Result<()> {
        let slot = self.slot_of(epoll_id).ok_or(Error::NotFound)?;
        self.inodes[slot] = EventpollInode::default();
        self.stats.total_destroyed += 1;
        self.stats.current_active = self.stats.current_active.saturating_sub(1);
        Ok(())
    }

    /// Write a human-readable description of `epoll_id` into `out`.
    ///
    /// Mimics the `/proc/<pid>/fdinfo/<fd>` output produced by the Linux
    /// kernel's `eventpoll_show_fdinfo()`.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]       — no such epoll instance.
    /// - [`Error::InvalidArgument`] — `out` is too small for the formatted output.
    pub fn eventpoll_show_fdinfo(&self, epoll_id: u32, out: &mut [u8]) -> Result<usize> {
        let inode = self.get(epoll_id)?;
        // Format: "tfd: <epoll_id> events: <interest_count> ref: <ref_count>\n"
        // We write a fixed-width ASCII representation without heap allocation.
        let line = format_fdinfo(inode);
        if out.len() < line.len() {
            return Err(Error::InvalidArgument);
        }
        out[..line.len()].copy_from_slice(line.as_bytes());
        Ok(line.len())
    }

    /// Return a snapshot of filesystem statistics.
    pub fn stats(&self) -> &EventpollFsStats {
        &self.stats
    }

    /// Return a reference to the superblock.
    pub fn superblock(&self) -> &EventpollSuperblock {
        &self.superblock
    }

    // -- private helpers ------------------------------------------------------

    fn find_free_slot(&self) -> Option<usize> {
        self.inodes.iter().position(|i| !i.in_use)
    }

    fn slot_of(&self, epoll_id: u32) -> Option<usize> {
        if epoll_id == 0 {
            return None;
        }
        let slot = (epoll_id as usize).checked_sub(1)?;
        if slot >= MAX_EVENTPOLL_INODES {
            return None;
        }
        if self.inodes[slot].in_use && self.inodes[slot].epoll_id == epoll_id {
            Some(slot)
        } else {
            None
        }
    }
}

// ── fdinfo formatter ──────────────────────────────────────────────────────────

/// Format the fdinfo line for an epoll inode without heap allocation.
///
/// Returns a fixed-capacity stack string.
fn format_fdinfo(inode: &EventpollInode) -> FdInfoLine {
    let mut line = FdInfoLine::new();
    write_u32(&mut line, b"tfd: ", inode.epoll_id);
    write_u32(&mut line, b" events: ", inode.interest_count);
    write_u32(&mut line, b" ref: ", inode.ref_count);
    line.push(b'\n');
    line
}

/// Tiny stack-based string for fdinfo output (no heap).
struct FdInfoLine {
    buf: [u8; 64],
    len: usize,
}

impl FdInfoLine {
    fn new() -> Self {
        Self {
            buf: [0u8; 64],
            len: 0,
        }
    }

    fn push_slice(&mut self, s: &[u8]) {
        let avail = self.buf.len().saturating_sub(self.len);
        let n = s.len().min(avail);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }

    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl core::ops::Deref for FdInfoLine {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Write `prefix` then the decimal representation of `n` into a [`FdInfoLine`].
fn write_u32(line: &mut FdInfoLine, prefix: &[u8], n: u32) {
    line.push_slice(prefix);
    let mut tmp = [0u8; 10];
    let s = u32_to_decimal(n, &mut tmp);
    line.push_slice(s);
}

/// Convert `n` to ASCII decimal in `buf`; returns the relevant slice.
fn u32_to_decimal(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[9] = b'0';
        return &buf[9..];
    }
    let mut pos = 10usize;
    while n > 0 && pos > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[pos..]
}

// ── EventpollFsStats ──────────────────────────────────────────────────────────

/// Cumulative statistics for the eventpoll filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventpollFsStats {
    /// Total epoll instances created since boot.
    pub total_created: u64,
    /// Total epoll instances destroyed since boot.
    pub total_destroyed: u64,
    /// Number of epoll instances currently alive.
    pub current_active: u64,
}

impl EventpollFsStats {
    /// Construct zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_created: 0,
            total_destroyed: 0,
            current_active: 0,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_free() {
        let mut fs = EventpollFs::new();
        let id = fs.alloc_eventpoll(100).unwrap();
        assert_eq!(id, 1);
        assert_eq!(fs.stats().current_active, 1);
        fs.free_eventpoll(id).unwrap();
        assert_eq!(fs.stats().current_active, 0);
    }

    #[test]
    fn table_full() {
        let mut fs = EventpollFs::new();
        for _ in 0..MAX_EVENTPOLL_INODES {
            fs.alloc_eventpoll(0).unwrap();
        }
        assert!(fs.alloc_eventpoll(0).is_err());
    }

    #[test]
    fn fstat_returns_mode() {
        let mut fs = EventpollFs::new();
        let id = fs.alloc_eventpoll(42).unwrap();
        let st = fs.eventpoll_fstat(id).unwrap();
        assert_eq!(st.st_mode, EVENTPOLL_MODE);
        assert_eq!(st.st_nlink, EVENTPOLL_NLINK);
    }

    #[test]
    fn poll_readable_when_pending() {
        let mut fs = EventpollFs::new();
        let id = fs.alloc_eventpoll(0).unwrap();
        assert!(!fs.eventpoll_poll(id).unwrap());
        fs.mark_events_pending(id, true).unwrap();
        assert!(fs.eventpoll_poll(id).unwrap());
    }

    #[test]
    fn release_cleans_up() {
        let mut fs = EventpollFs::new();
        let id = fs.alloc_eventpoll(0).unwrap();
        fs.eventpoll_release(id).unwrap();
        assert!(fs.get(id).is_err());
    }

    #[test]
    fn fdinfo_output() {
        let mut fs = EventpollFs::new();
        let id = fs.alloc_eventpoll(0).unwrap();
        let mut buf = [0u8; 64];
        let n = fs.eventpoll_show_fdinfo(id, &mut buf).unwrap();
        assert!(n > 0);
        assert!(buf[..n].starts_with(b"tfd: "));
    }
}
