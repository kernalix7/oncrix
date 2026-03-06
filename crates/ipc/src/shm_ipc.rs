// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System V IPC shared memory implementation.
//!
//! Provides System V-style shared memory segments compatible with
//! POSIX `shmget(2)`, `shmat(2)`, `shmdt(2)`, and `shmctl(2)`.
//! Each segment stores data inline (no heap allocation) with a
//! fixed 64 KiB capacity.
//!
//! # Features
//!
//! - `shmget` — create or look up shared memory segments by key
//! - `shmat` / `shmdt` — attach and detach segments
//! - `shmctl` — query, modify permissions, and remove segments
//! - `ftok`-style key generation from path and project id
//! - Registry for up to 32 concurrent segments
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/shmget.html` and
//! related pages for the authoritative specification.

use oncrix_lib::{Error, Result};

// ── Key type ──────────────────────────────────────────────────

/// IPC key type, equivalent to POSIX `key_t`.
///
/// Used to identify shared memory segments across processes.
/// A value of [`IPC_PRIVATE`] requests a new private segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcKey(i32);

/// Private key: always creates a new, unshared segment.
pub const IPC_PRIVATE: IpcKey = IpcKey(0);

impl IpcKey {
    /// Create an IPC key from a raw `i32` value.
    pub const fn new(val: i32) -> Self {
        Self(val)
    }

    /// Return the raw `i32` value of this key.
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Generate a key from a path hash and project id, similar
    /// to POSIX `ftok(3)`.
    ///
    /// The `path_hash` should be a stable hash of the pathname.
    /// The `proj_id` is the low 8 bits of the project identifier.
    ///
    /// Returns [`IPC_PRIVATE`] if the resulting key would be 0.
    pub const fn ftok(path_hash: u32, proj_id: u8) -> Self {
        // Combine: proj_id in bits [31:24], path_hash in [23:0].
        let key = ((proj_id as i32) << 24) | (path_hash as i32 & 0x00FF_FFFF);
        if key == 0 { IPC_PRIVATE } else { Self(key) }
    }
}

// ── Permission struct ─────────────────────────────────────────

/// IPC permission structure, equivalent to POSIX `struct ipc_perm`.
///
/// Stores ownership and permission mode for an IPC object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcPerm {
    /// Effective UID of the owner.
    pub uid: u32,
    /// Effective GID of the owner.
    pub gid: u32,
    /// UID of the creator.
    pub cuid: u32,
    /// GID of the creator.
    pub cgid: u32,
    /// Permission mode bits (low 9 bits: rwxrwxrwx).
    pub mode: u16,
}

impl IpcPerm {
    /// Create a new permission structure with default root
    /// ownership and the given mode.
    pub const fn new(mode: u16) -> Self {
        Self {
            uid: 0,
            gid: 0,
            cuid: 0,
            cgid: 0,
            mode,
        }
    }
}

impl Default for IpcPerm {
    fn default() -> Self {
        Self::new(0o600)
    }
}

// ── Flags ─────────────────────────────────────────────────────

/// Flags for System V shared memory operations.
///
/// Combines creation flags (`IPC_CREAT`, `IPC_EXCL`, `IPC_RMID`)
/// with attach flags (`SHM_RDONLY`, `SHM_RND`, `SHM_HUGETLB`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmFlags(u32);

impl ShmFlags {
    /// Create a new segment if one does not exist.
    pub const IPC_CREAT: u32 = 0o1000;
    /// Fail if the segment already exists (with `IPC_CREAT`).
    pub const IPC_EXCL: u32 = 0o2000;
    /// Remove a shared memory segment (for `shmctl`).
    pub const IPC_RMID: u32 = 0o4000;
    /// Attach the segment read-only.
    pub const SHM_RDONLY: u32 = 0o10000;
    /// Round attach address down to `SHMLBA` boundary.
    pub const SHM_RND: u32 = 0o20000;
    /// Use huge pages for the segment.
    pub const SHM_HUGETLB: u32 = 0o40000;

    /// Bitmask of all valid flag bits.
    const VALID: u32 = Self::IPC_CREAT
        | Self::IPC_EXCL
        | Self::IPC_RMID
        | Self::SHM_RDONLY
        | Self::SHM_RND
        | Self::SHM_HUGETLB
        | 0o777; // permission bits

    /// Create a flags value from a raw `u32`.
    ///
    /// Unknown bits are masked off.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw & Self::VALID)
    }

    /// Return the raw `u32` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Test whether a particular flag bit is set.
    pub const fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Extract the permission mode bits (low 9 bits).
    pub const fn mode(self) -> u16 {
        (self.0 & 0o777) as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
/// Commands for [`shmctl`].
pub enum ShmCtlCmd {
    /// Return segment info in the provided [`ShmInfo`] buffer.
    #[default]
    IpcStat = 0,
    /// Update segment permissions from the provided [`ShmInfo`].
    IpcSet = 1,
    /// Mark the segment for removal.
    IpcRmid = 2,
}

// ── Segment ───────────────────────────────────────────────────

/// Maximum inline data capacity per segment (64 KiB).
const SHM_DATA_CAPACITY: usize = 65536;

/// A System V shared memory segment with inline storage.
///
/// Data is stored in a fixed `[u8; 65536]` array (64 KiB) with
/// no heap allocation, suitable for `#![no_std]` kernel use.
pub struct ShmSegment {
    /// IPC key associated with this segment.
    key: IpcKey,
    /// Unique segment identifier (shmid).
    id: i32,
    /// Logical size in bytes.
    size: usize,
    /// Inline data buffer.
    data: [u8; SHM_DATA_CAPACITY],
    /// Number of current attaches.
    nattch: u32,
    /// Creation / permission info.
    perm: IpcPerm,
    /// PID of the creator.
    cpid: u32,
    /// PID of last `shmat` / `shmdt` caller.
    lpid: u32,
    /// Last attach time (seconds since epoch).
    atime: u64,
    /// Last detach time (seconds since epoch).
    dtime: u64,
    /// Last change time (seconds since epoch).
    ctime: u64,
    /// Segment marked for removal.
    marked_for_removal: bool,
    /// Slot occupied.
    in_use: bool,
}

impl ShmSegment {
    /// Create a new segment with the given key, id, size, and mode.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `size` is 0 or exceeds
    ///   64 KiB.
    pub fn new(key: IpcKey, id: i32, size: usize, mode: u16) -> Result<Self> {
        if size == 0 || size > SHM_DATA_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            key,
            id,
            size,
            data: [0u8; SHM_DATA_CAPACITY],
            nattch: 0,
            perm: IpcPerm::new(mode),
            cpid: 0,
            lpid: 0,
            atime: 0,
            dtime: 0,
            ctime: 0,
            marked_for_removal: false,
            in_use: true,
        })
    }

    /// Return an empty, unused segment (for registry init).
    const fn empty() -> Self {
        Self {
            key: IPC_PRIVATE,
            id: -1,
            size: 0,
            data: [0u8; SHM_DATA_CAPACITY],
            nattch: 0,
            perm: IpcPerm::new(0),
            cpid: 0,
            lpid: 0,
            atime: 0,
            dtime: 0,
            ctime: 0,
            marked_for_removal: false,
            in_use: false,
        }
    }

    /// Return the IPC key.
    pub const fn key(&self) -> IpcKey {
        self.key
    }

    /// Return the segment identifier.
    pub const fn id(&self) -> i32 {
        self.id
    }

    /// Return the logical size in bytes.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Return the number of current attaches.
    pub const fn nattch(&self) -> u32 {
        self.nattch
    }

    /// Return the permission structure.
    pub const fn perm(&self) -> &IpcPerm {
        &self.perm
    }

    /// Return whether the segment is marked for removal.
    pub const fn marked_for_removal(&self) -> bool {
        self.marked_for_removal
    }

    /// Build a [`ShmInfo`] snapshot of this segment.
    pub fn info(&self) -> ShmInfo {
        ShmInfo {
            perm: self.perm,
            size: self.size,
            atime: self.atime,
            dtime: self.dtime,
            ctime: self.ctime,
            cpid: self.cpid,
            lpid: self.lpid,
            nattch: self.nattch,
        }
    }

    /// Return a read-only reference to the data buffer
    /// (up to `self.size` bytes).
    pub fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }

    /// Return a mutable reference to the data buffer
    /// (up to `self.size` bytes).
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.size]
    }
}

// ── ShmInfo ───────────────────────────────────────────────────

/// Shared memory segment descriptor, equivalent to POSIX
/// `struct shmid_ds`.
///
/// Used by [`shmctl`] for `IPC_STAT` and `IPC_SET` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShmInfo {
    /// Ownership and permission info.
    pub perm: IpcPerm,
    /// Segment size in bytes.
    pub size: usize,
    /// Last attach time (seconds since epoch).
    pub atime: u64,
    /// Last detach time (seconds since epoch).
    pub dtime: u64,
    /// Last change time (seconds since epoch).
    pub ctime: u64,
    /// PID of the creator.
    pub cpid: u32,
    /// PID of last `shmat` / `shmdt` caller.
    pub lpid: u32,
    /// Number of current attaches.
    pub nattch: u32,
}

// ── Registry ──────────────────────────────────────────────────

/// Maximum number of System V shared memory segments.
const SHM_MAX_SEGMENTS: usize = 32;

/// Registry that manages up to [`SHM_MAX_SEGMENTS`] System V
/// shared memory segments.
///
/// Segments are identified by a monotonically increasing `shmid`.
/// The registry provides `shmget`, `shmat`, `shmdt`, and `shmctl`
/// operations that mirror the POSIX System V IPC interface.
pub struct ShmRegistry {
    /// Fixed-size array of segment slots.
    segments: [ShmSegment; SHM_MAX_SEGMENTS],
    /// Next shmid to assign.
    next_id: i32,
}

impl Default for ShmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ShmRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            segments: [const { ShmSegment::empty() }; SHM_MAX_SEGMENTS],
            next_id: 0,
        }
    }

    /// Return the number of active (in-use) segments.
    pub fn count(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < SHM_MAX_SEGMENTS {
            if self.segments[i].in_use {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Find a slot index by segment id.
    fn find_by_id(&self, id: i32) -> Option<usize> {
        let mut i = 0;
        while i < SHM_MAX_SEGMENTS {
            if self.segments[i].in_use && self.segments[i].id == id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Find a slot index by IPC key (skips `IPC_PRIVATE`).
    fn find_by_key(&self, key: IpcKey) -> Option<usize> {
        if key == IPC_PRIVATE {
            return None;
        }
        let mut i = 0;
        while i < SHM_MAX_SEGMENTS {
            let seg = &self.segments[i];
            if seg.in_use && seg.key == key {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Allocate a free slot index.
    fn alloc_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < SHM_MAX_SEGMENTS {
            if !self.segments[i].in_use {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Create or look up a shared memory segment by key.
    ///
    /// Equivalent to POSIX `shmget(2)`.
    ///
    /// - If `key` is [`IPC_PRIVATE`], a new segment is always
    ///   created.
    /// - If `IPC_CREAT` is set and no segment exists for `key`,
    ///   a new segment is created.
    /// - If `IPC_CREAT | IPC_EXCL` are both set and a segment
    ///   already exists, returns [`Error::AlreadyExists`].
    /// - If no flags are set and the segment does not exist,
    ///   returns [`Error::NotFound`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `size` is 0 or exceeds
    ///   64 KiB.
    /// - [`Error::OutOfMemory`] if all 32 slots are occupied.
    /// - [`Error::AlreadyExists`] if `IPC_EXCL` is set and the
    ///   segment already exists.
    /// - [`Error::NotFound`] if the segment does not exist and
    ///   `IPC_CREAT` is not set.
    pub fn shmget(&mut self, key: IpcKey, size: usize, flags: ShmFlags) -> Result<i32> {
        if size == 0 || size > SHM_DATA_CAPACITY {
            return Err(Error::InvalidArgument);
        }

        // Check for existing segment (unless IPC_PRIVATE).
        if let Some(idx) = self.find_by_key(key) {
            if flags.contains(ShmFlags::IPC_CREAT) && flags.contains(ShmFlags::IPC_EXCL) {
                return Err(Error::AlreadyExists);
            }
            return Ok(self.segments[idx].id);
        }

        // No existing segment — need IPC_CREAT (or IPC_PRIVATE).
        if key != IPC_PRIVATE && !flags.contains(ShmFlags::IPC_CREAT) {
            return Err(Error::NotFound);
        }

        let slot = self.alloc_slot().ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.segments[slot] = ShmSegment::new(key, id, size, flags.mode())?;
        Ok(id)
    }

    /// Attach to a shared memory segment, returning a reference
    /// to its data.
    ///
    /// Equivalent to POSIX `shmat(2)`. If `SHM_RDONLY` is set in
    /// `flags`, the returned slice is read-only; otherwise a
    /// mutable slice is provided (via a separate method or by
    /// calling without `SHM_RDONLY`).
    ///
    /// This implementation returns a read-only data reference in
    /// all cases. Use [`shmat_mut`](Self::shmat_mut) to obtain a
    /// mutable reference when `SHM_RDONLY` is not set.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no segment with `id` exists.
    /// - [`Error::PermissionDenied`] if the segment is marked for
    ///   removal.
    pub fn shmat(&mut self, id: i32, flags: ShmFlags) -> Result<&[u8]> {
        let _ = flags; // SHM_RND, SHM_HUGETLB ignored for now.
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        if self.segments[idx].marked_for_removal {
            return Err(Error::PermissionDenied);
        }
        self.segments[idx].nattch = self.segments[idx].nattch.saturating_add(1);
        self.segments[idx].atime = 0; // Placeholder: no clock yet.
        let size = self.segments[idx].size;
        Ok(&self.segments[idx].data[..size])
    }

    /// Attach to a shared memory segment with mutable access.
    ///
    /// Same as [`shmat`](Self::shmat) but returns `&mut [u8]`.
    /// Must not be called when `SHM_RDONLY` is intended.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no segment with `id` exists.
    /// - [`Error::PermissionDenied`] if the segment is marked for
    ///   removal.
    pub fn shmat_mut(&mut self, id: i32) -> Result<&mut [u8]> {
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        if self.segments[idx].marked_for_removal {
            return Err(Error::PermissionDenied);
        }
        self.segments[idx].nattch = self.segments[idx].nattch.saturating_add(1);
        self.segments[idx].atime = 0;
        let size = self.segments[idx].size;
        Ok(&mut self.segments[idx].data[..size])
    }

    /// Detach from a shared memory segment.
    ///
    /// Equivalent to POSIX `shmdt(2)`. Decrements the attach
    /// count. If the segment is marked for removal and `nattch`
    /// reaches 0, the segment is destroyed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no segment with `id` exists.
    /// - [`Error::InvalidArgument`] if `nattch` is already 0.
    pub fn shmdt(&mut self, id: i32) -> Result<()> {
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        if self.segments[idx].nattch == 0 {
            return Err(Error::InvalidArgument);
        }
        self.segments[idx].nattch -= 1;
        self.segments[idx].dtime = 0; // Placeholder: no clock.

        // Destroy if marked for removal and no attaches remain.
        if self.segments[idx].marked_for_removal && self.segments[idx].nattch == 0 {
            self.segments[idx] = ShmSegment::empty();
        }
        Ok(())
    }

    /// Perform a control operation on a shared memory segment.
    ///
    /// Equivalent to POSIX `shmctl(2)`.
    ///
    /// - [`ShmCtlCmd::IpcStat`] — fills `buf` with the segment
    ///   descriptor.
    /// - [`ShmCtlCmd::IpcSet`] — updates `uid`, `gid`, and `mode`
    ///   from `buf`.
    /// - [`ShmCtlCmd::IpcRmid`] — marks the segment for removal.
    ///   If `nattch` is 0, the segment is destroyed immediately.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no segment with `id` exists.
    pub fn shmctl(&mut self, id: i32, cmd: ShmCtlCmd, buf: &mut ShmInfo) -> Result<()> {
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;

        match cmd {
            ShmCtlCmd::IpcStat => {
                *buf = self.segments[idx].info();
            }
            ShmCtlCmd::IpcSet => {
                self.segments[idx].perm.uid = buf.perm.uid;
                self.segments[idx].perm.gid = buf.perm.gid;
                self.segments[idx].perm.mode = buf.perm.mode;
                self.segments[idx].ctime = 0; // Placeholder.
            }
            ShmCtlCmd::IpcRmid => {
                self.segments[idx].marked_for_removal = true;
                if self.segments[idx].nattch == 0 {
                    self.segments[idx] = ShmSegment::empty();
                }
            }
        }
        Ok(())
    }
}
