// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Anonymous inode filesystem (anon_inode).
//!
//! The anonymous inode filesystem provides a pseudo-filesystem that hosts
//! kernel objects which need a file descriptor but do not correspond to any
//! file in a real filesystem.  Classic examples are `epoll`, `eventfd`,
//! `signalfd`, `timerfd`, `io_uring`, and `pidfd`.
//!
//! Each anonymous inode has a human-readable name string (e.g., `"[eventfd]"`)
//! visible in `/proc/<pid>/fd/` links.  All anonymous inodes share a single
//! superblock with magic number `0xAF01`.
//!
//! # Architecture
//!
//! ```text
//! epoll_create1()
//!     │
//!     └─► anon_inode_getfd("[eventpoll]", AnonInodeType::Epoll)
//!             │
//!             ├─► AnonInodeFs::alloc_inode()  ← assign inode_id from next_ino
//!             │       AnonInode { inode_type=Epoll, name="[eventpoll]", ref_count=1 }
//!             │
//!             └─► return fd  (backed by AnonInode)
//! ```
//!
//! # References
//!
//! - Linux `fs/anon_inodes.c`, `include/linux/anon_inodes.h`
//! - `man 2 epoll_create`, `man 2 eventfd`, `man 2 signalfd`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic number for the anonymous inode superblock.
pub const ANON_INODE_MAGIC: u32 = 0xAF01;

/// Maximum number of anonymous inodes active at once.
const MAX_ANON_INODES: usize = 512;

/// Maximum length of the name string for an anonymous inode.
const ANON_INODE_NAME_LEN: usize = 32;

/// Starting inode number (root is 1, first anon inode is 2).
const ANON_INO_START: u64 = 2;

// ── AnonInodeType ─────────────────────────────────────────────────────────────

/// Classifies the kernel object backed by an anonymous inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonInodeType {
    /// `epoll_create` file descriptor.
    Epoll,
    /// `eventfd` file descriptor.
    Eventfd,
    /// `signalfd` file descriptor.
    Signalfd,
    /// `timerfd` file descriptor.
    Timerfd,
    /// `userfaultfd` file descriptor.
    Userfaultfd,
    /// `io_uring` file descriptor.
    IoUring,
    /// `pidfd` — file descriptor referencing a process.
    PidFd,
    /// `fanotify` notification group file descriptor.
    Fanotify,
    /// `perf_event_open` file descriptor.
    Perf,
    /// BPF map or program file descriptor.
    Bpf,
    /// `memfd_create` in-memory file descriptor.
    Memfd,
    /// DMA-BUF shared buffer file descriptor.
    DmaBuf,
}

impl AnonInodeType {
    /// Return the canonical name string for this inode type.
    ///
    /// The name is displayed in `/proc/<pid>/fd/` and `lsof` output.
    pub fn default_name(self) -> &'static [u8] {
        match self {
            Self::Epoll => b"[eventpoll]",
            Self::Eventfd => b"[eventfd]",
            Self::Signalfd => b"[signalfd]",
            Self::Timerfd => b"[timerfd]",
            Self::Userfaultfd => b"[userfaultfd]",
            Self::IoUring => b"[io_uring]",
            Self::PidFd => b"[pidfd]",
            Self::Fanotify => b"[fanotify]",
            Self::Perf => b"[perf_event]",
            Self::Bpf => b"[bpf-map]",
            Self::Memfd => b"[memfd]",
            Self::DmaBuf => b"[dmabuf]",
        }
    }

    /// Return the index into the per-type statistics array.
    fn stats_index(self) -> usize {
        match self {
            Self::Epoll => 0,
            Self::Eventfd => 1,
            Self::Signalfd => 2,
            Self::Timerfd => 3,
            Self::Userfaultfd => 4,
            Self::IoUring => 5,
            Self::PidFd => 6,
            Self::Fanotify => 7,
            Self::Perf => 8,
            Self::Bpf => 9,
            Self::Memfd => 10,
            Self::DmaBuf => 11,
        }
    }
}

// ── AnonInode ─────────────────────────────────────────────────────────────────

/// A single anonymous inode entry.
#[derive(Debug, Clone, Copy)]
pub struct AnonInode {
    /// Globally unique inode number assigned by the superblock.
    pub inode_id: u64,
    /// Type of kernel object this inode represents.
    pub inode_type: AnonInodeType,
    /// Human-readable name (NUL-padded, shown in procfs).
    pub name: [u8; ANON_INODE_NAME_LEN],
    /// Reference count: number of file descriptors backed by this inode.
    pub ref_count: u32,
    /// Kernel tick at which this inode was created.
    pub creation_tick: u64,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl AnonInode {
    /// Create an empty (unused) inode slot.
    pub const fn empty() -> Self {
        Self {
            inode_id: 0,
            inode_type: AnonInodeType::Epoll,
            name: [0u8; ANON_INODE_NAME_LEN],
            ref_count: 0,
            creation_tick: 0,
            in_use: false,
        }
    }

    /// Return the name as a byte slice up to (not including) the first NUL.
    pub fn name_str(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ANON_INODE_NAME_LEN);
        &self.name[..end]
    }

    /// Increment the reference count.
    pub fn inc_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrement the reference count.  Returns the new count.
    pub fn dec_ref(&mut self) -> u32 {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count
    }
}

// ── AnonInodeSuperblock ───────────────────────────────────────────────────────

/// Superblock for the anonymous inode pseudo-filesystem.
#[derive(Debug, Clone, Copy)]
pub struct AnonInodeSuperblock {
    /// Filesystem magic number (`ANON_INODE_MAGIC`).
    pub magic: u32,
    /// Next inode number to assign.
    pub next_ino: u64,
}

impl AnonInodeSuperblock {
    /// Create a new superblock.
    pub const fn new() -> Self {
        Self {
            magic: ANON_INODE_MAGIC,
            next_ino: ANON_INO_START,
        }
    }

    /// Allocate and return the next unique inode number.
    pub fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino = self.next_ino.wrapping_add(1).max(ANON_INO_START);
        ino
    }
}

impl Default for AnonInodeSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

// ── AnonInodeStats ────────────────────────────────────────────────────────────

/// Per-type and aggregate statistics for the anonymous inode filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnonInodeStats {
    /// Per-type allocation counts (indexed by [`AnonInodeType::stats_index`]).
    pub per_type: [u64; 12],
    /// Total anonymous inodes allocated since boot.
    pub total_allocated: u64,
    /// Total anonymous inodes freed since boot.
    pub total_freed: u64,
}

impl AnonInodeStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            per_type: [0u64; 12],
            total_allocated: 0,
            total_freed: 0,
        }
    }

    /// Return the number of currently live anonymous inodes.
    pub fn current_active(&self) -> u64 {
        self.total_allocated.saturating_sub(self.total_freed)
    }
}

// ── AnonInodeFs ───────────────────────────────────────────────────────────────

/// The anonymous inode filesystem state.
pub struct AnonInodeFs {
    /// Superblock (magic + inode counter).
    pub superblock: AnonInodeSuperblock,
    /// Pool of inode slots.
    inodes: [AnonInode; MAX_ANON_INODES],
    /// Operational statistics.
    pub stats: AnonInodeStats,
}

impl AnonInodeFs {
    /// Create a new, empty anonymous inode filesystem.
    pub const fn new() -> Self {
        Self {
            superblock: AnonInodeSuperblock::new(),
            inodes: [const { AnonInode::empty() }; MAX_ANON_INODES],
            stats: AnonInodeStats::new(),
        }
    }

    /// Allocate a new anonymous inode of the given type.
    ///
    /// Uses `name` if provided; otherwise falls back to the type's default
    /// name.  Returns the slot index on success.
    ///
    /// Returns [`Error::OutOfMemory`] if the pool is full.
    fn alloc_inode(
        &mut self,
        inode_type: AnonInodeType,
        name: Option<&[u8]>,
        tick: u64,
    ) -> Result<usize> {
        let slot = self
            .inodes
            .iter()
            .position(|i| !i.in_use)
            .ok_or(Error::OutOfMemory)?;
        let ino = self.superblock.alloc_ino();
        let inode = &mut self.inodes[slot];
        *inode = AnonInode::empty();
        inode.inode_id = ino;
        inode.inode_type = inode_type;
        inode.ref_count = 1;
        inode.creation_tick = tick;
        inode.in_use = true;
        // Set name: caller-supplied or type default.
        let raw_name = name.unwrap_or_else(|| inode_type.default_name());
        let copy_len = raw_name.len().min(ANON_INODE_NAME_LEN);
        inode.name[..copy_len].copy_from_slice(&raw_name[..copy_len]);
        // Update statistics.
        self.stats.per_type[inode_type.stats_index()] += 1;
        self.stats.total_allocated += 1;
        Ok(slot)
    }

    /// Release an anonymous inode, decrementing its reference count.
    ///
    /// If the reference count reaches zero, the inode slot is freed.
    /// Returns [`Error::NotFound`] if `slot` is not in use.
    pub fn anon_inode_release(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_ANON_INODES {
            return Err(Error::InvalidArgument);
        }
        let inode = &mut self.inodes[slot];
        if !inode.in_use {
            return Err(Error::NotFound);
        }
        let remaining = inode.dec_ref();
        if remaining == 0 {
            inode.in_use = false;
            self.stats.total_freed += 1;
        }
        Ok(())
    }

    /// Retrieve an immutable reference to the inode at `slot`.
    pub fn get(&self, slot: usize) -> Option<&AnonInode> {
        self.inodes.get(slot).filter(|i| i.in_use)
    }

    /// Retrieve a mutable reference to the inode at `slot`.
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut AnonInode> {
        let inode = self.inodes.get_mut(slot)?;
        if inode.in_use { Some(inode) } else { None }
    }

    /// Return the number of currently occupied inode slots.
    pub fn active_count(&self) -> usize {
        self.inodes.iter().filter(|i| i.in_use).count()
    }
}

impl Default for AnonInodeFs {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate an anonymous inode and return a simulated file descriptor.
///
/// Corresponds to the kernel `anon_inode_getfd()` function.  The returned
/// value is the slot index in the anonymous inode pool, which the caller
/// maps to a real file-descriptor table entry.
///
/// # Parameters
///
/// - `fs` — mutable reference to the anonymous inode filesystem.
/// - `inode_type` — kind of kernel object to create an inode for.
/// - `name` — optional custom name; defaults to the type's canonical name.
/// - `tick` — current kernel time tick (for `creation_tick`).
///
/// Returns the slot index (pseudo-fd) on success.
pub fn anon_inode_getfd(
    fs: &mut AnonInodeFs,
    inode_type: AnonInodeType,
    name: Option<&[u8]>,
    tick: u64,
) -> Result<usize> {
    fs.alloc_inode(inode_type, name, tick)
}

/// Increment the reference count for an existing anonymous inode.
///
/// Corresponds to the kernel `anon_inode_getfile()` — used when duplicating
/// a file descriptor that refers to an anonymous inode.
///
/// Returns the inode_id of the inode on success.
pub fn anon_inode_getfile(fs: &mut AnonInodeFs, slot: usize) -> Result<u64> {
    if slot >= MAX_ANON_INODES {
        return Err(Error::InvalidArgument);
    }
    let inode = fs.get_mut(slot).ok_or(Error::NotFound)?;
    inode.inc_ref();
    Ok(inode.inode_id)
}

/// Release one reference to an anonymous inode.
///
/// Corresponds to the kernel `anon_inode_release()` / `fput()` path.
/// Frees the inode slot when the reference count reaches zero.
pub fn anon_inode_release(fs: &mut AnonInodeFs, slot: usize) -> Result<()> {
    fs.anon_inode_release(slot)
}
