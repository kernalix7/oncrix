// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PID bitmap allocator.
//!
//! Manages allocation and release of process IDs using a bitmap.
//! PIDs 0 and 1 are reserved (swapper/idle and init), and allocation
//! wraps around when the maximum is reached.
//!
//! # PID Levels
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ PID Namespace                                    │
//! │                                                  │
//! │  Level 0: Thread ID (TID)                        │
//! │  Level 1: Process ID (PID/TGID)                  │
//! │  Level 2: Process Group ID (PGID)                │
//! │  Level 3: Session ID (SID)                       │
//! │                                                  │
//! │  Each task has IDs at all 4 levels.               │
//! │  Threads share level 1-3 with their group.       │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Bitmap Layout
//!
//! ```text
//! Bitmap: [u64; 512] = 32768 bits = 32768 PIDs
//!
//! Bit 0 = PID 0 (reserved, always set)
//! Bit 1 = PID 1 (reserved, always set)
//! Bit 2 = PID 2 (first allocatable)
//! ...
//! Bit 32767 = PID 32767 (max PID)
//! ```
//!
//! # Reference
//!
//! Linux `kernel/pid.c`, `include/linux/pid.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of PIDs.
const MAX_PIDS: usize = 32768;

/// Number of u64 words in the bitmap.
const BITMAP_WORDS: usize = MAX_PIDS / 64;

/// First allocatable PID (0 and 1 are reserved).
const FIRST_PID: u32 = 2;

/// Maximum PID namespaces.
const MAX_PID_NS: usize = 16;

/// PID 0 — swapper/idle process.
const _PID_SWAPPER: u32 = 0;

/// PID 1 — init process.
const _PID_INIT: u32 = 1;

// ======================================================================
// PID level
// ======================================================================

/// PID hierarchy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidLevel {
    /// Thread ID.
    Thread = 0,
    /// Process ID (thread group leader).
    Process = 1,
    /// Process group ID.
    ProcessGroup = 2,
    /// Session ID.
    Session = 3,
}

/// Number of PID levels.
const NUM_PID_LEVELS: usize = 4;

impl PidLevel {
    /// Returns the level index.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Creates from an index.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(Self::Thread),
            1 => Ok(Self::Process),
            2 => Ok(Self::ProcessGroup),
            3 => Ok(Self::Session),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ======================================================================
// PID entry
// ======================================================================

/// Tracks the IDs associated with a single task at all levels.
#[derive(Debug, Clone, Copy)]
pub struct PidEntry {
    /// IDs at each level.
    ids: [u32; NUM_PID_LEVELS],
    /// Namespace depth (0 = root).
    ns_level: u8,
    /// Whether this entry is in use.
    active: bool,
}

impl PidEntry {
    /// Creates an empty PID entry.
    pub const fn new() -> Self {
        Self {
            ids: [0; NUM_PID_LEVELS],
            ns_level: 0,
            active: false,
        }
    }

    /// Returns the ID at a given level.
    pub fn id(&self, level: PidLevel) -> u32 {
        self.ids[level.index()]
    }

    /// Returns the thread ID.
    pub fn tid(&self) -> u32 {
        self.ids[PidLevel::Thread.index()]
    }

    /// Returns the process ID.
    pub fn pid(&self) -> u32 {
        self.ids[PidLevel::Process.index()]
    }

    /// Returns the process group ID.
    pub fn pgid(&self) -> u32 {
        self.ids[PidLevel::ProcessGroup.index()]
    }

    /// Returns the session ID.
    pub fn sid(&self) -> u32 {
        self.ids[PidLevel::Session.index()]
    }

    /// Returns the namespace level.
    pub fn ns_level(&self) -> u8 {
        self.ns_level
    }
}

// ======================================================================
// PID bitmap
// ======================================================================

/// Bitmap-based PID allocator.
pub struct PidBitmap {
    /// Bitmap words (1 = allocated, 0 = free).
    bits: [u64; BITMAP_WORDS],
    /// Next PID to try allocating (for sequential allocation).
    last_pid: u32,
    /// Number of allocated PIDs.
    count: u32,
}

impl PidBitmap {
    /// Creates a new PID bitmap with reserved PIDs set.
    pub const fn new() -> Self {
        let mut bits = [0u64; BITMAP_WORDS];
        // Reserve PID 0 and PID 1.
        bits[0] = 0b11;
        Self {
            bits,
            last_pid: FIRST_PID,
            count: 2, // PID 0 and 1 are reserved.
        }
    }

    /// Returns the number of allocated PIDs.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Returns the number of free PIDs.
    pub fn free_count(&self) -> u32 {
        (MAX_PIDS as u32).saturating_sub(self.count)
    }

    /// Tests whether a PID is allocated.
    pub fn is_allocated(&self, pid: u32) -> bool {
        if pid as usize >= MAX_PIDS {
            return false;
        }
        let word = pid as usize / 64;
        let bit = pid as usize % 64;
        (self.bits[word] & (1u64 << bit)) != 0
    }

    /// Allocates the next available PID.
    pub fn alloc_pid(&mut self) -> Result<u32> {
        // Search starting from last_pid, wrapping around.
        let start = self.last_pid.max(FIRST_PID);
        // First pass: from start to MAX_PIDS.
        if let Some(pid) = self.find_free_from(start as usize) {
            self.set_bit(pid as usize);
            self.last_pid = pid + 1;
            self.count += 1;
            return Ok(pid);
        }
        // Second pass: from FIRST_PID to start.
        if let Some(pid) = self.find_free_range(FIRST_PID as usize, start as usize) {
            self.set_bit(pid as usize);
            self.last_pid = pid + 1;
            self.count += 1;
            return Ok(pid);
        }
        Err(Error::OutOfMemory)
    }

    /// Allocates a specific PID (if free).
    pub fn alloc_specific(&mut self, pid: u32) -> Result<()> {
        if pid as usize >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        if self.is_allocated(pid) {
            return Err(Error::AlreadyExists);
        }
        self.set_bit(pid as usize);
        self.count += 1;
        Ok(())
    }

    /// Frees a previously allocated PID.
    pub fn free_pid(&mut self, pid: u32) -> Result<()> {
        if pid as usize >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        if pid < FIRST_PID {
            return Err(Error::PermissionDenied);
        }
        if !self.is_allocated(pid) {
            return Err(Error::NotFound);
        }
        self.clear_bit(pid as usize);
        self.count -= 1;
        Ok(())
    }

    /// Finds the first free PID starting from a given position.
    fn find_free_from(&self, start: usize) -> Option<u32> {
        self.find_free_range(start, MAX_PIDS)
    }

    /// Finds the first free PID in a range [start, end).
    fn find_free_range(&self, start: usize, end: usize) -> Option<u32> {
        let start_word = start / 64;
        let end_word = (end + 63) / 64;
        for w in start_word..end_word.min(BITMAP_WORDS) {
            if self.bits[w] == u64::MAX {
                continue; // All bits set, skip.
            }
            let inverted = !self.bits[w];
            let bit_in_word = inverted.trailing_zeros() as usize;
            let pid = w * 64 + bit_in_word;
            if pid >= start && pid < end && pid < MAX_PIDS {
                return Some(pid as u32);
            }
            // Also check remaining bits in this word.
            for b in (bit_in_word + 1)..64 {
                let candidate = w * 64 + b;
                if candidate >= end || candidate >= MAX_PIDS {
                    break;
                }
                if candidate >= start && (self.bits[w] & (1u64 << b)) == 0 {
                    return Some(candidate as u32);
                }
            }
        }
        None
    }

    /// Sets a bit in the bitmap.
    fn set_bit(&mut self, pid: usize) {
        let word = pid / 64;
        let bit = pid % 64;
        self.bits[word] |= 1u64 << bit;
    }

    /// Clears a bit in the bitmap.
    fn clear_bit(&mut self, pid: usize) {
        let word = pid / 64;
        let bit = pid % 64;
        self.bits[word] &= !(1u64 << bit);
    }
}

// ======================================================================
// PID namespace
// ======================================================================

/// A PID namespace with its own PID allocator.
pub struct PidNamespace {
    /// Namespace ID.
    ns_id: u32,
    /// Depth in the namespace hierarchy (0 = root).
    level: u8,
    /// PID bitmap for this namespace.
    bitmap: PidBitmap,
    /// Parent namespace index (u8::MAX = no parent).
    parent: u8,
    /// Whether this namespace is active.
    active: bool,
    /// Init task PID in this namespace.
    init_pid: u32,
}

impl PidNamespace {
    /// Creates a new PID namespace.
    pub const fn new() -> Self {
        Self {
            ns_id: 0,
            level: 0,
            bitmap: PidBitmap::new(),
            parent: u8::MAX,
            active: false,
            init_pid: 1,
        }
    }

    /// Returns the namespace ID.
    pub fn ns_id(&self) -> u32 {
        self.ns_id
    }

    /// Returns the hierarchy level.
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Returns the number of allocated PIDs.
    pub fn pid_count(&self) -> u32 {
        self.bitmap.count()
    }

    /// Allocates a PID in this namespace.
    pub fn alloc_pid(&mut self) -> Result<u32> {
        self.bitmap.alloc_pid()
    }

    /// Frees a PID in this namespace.
    pub fn free_pid(&mut self, pid: u32) -> Result<()> {
        self.bitmap.free_pid(pid)
    }
}

// ======================================================================
// PID allocator manager
// ======================================================================

/// Global PID allocation manager with namespace support.
pub struct PidAllocator {
    /// PID namespaces.
    namespaces: [PidNamespace; MAX_PID_NS],
    /// Number of active namespaces.
    nr_namespaces: usize,
    /// Next namespace ID.
    next_ns_id: u32,
    /// PID entries (global tracking).
    entries: [PidEntry; MAX_PIDS],
}

impl PidAllocator {
    /// Creates a new PID allocator with root namespace.
    pub const fn new() -> Self {
        let mut namespaces = [const { PidNamespace::new() }; MAX_PID_NS];
        namespaces[0].active = true;
        namespaces[0].ns_id = 0;
        namespaces[0].level = 0;
        Self {
            namespaces,
            nr_namespaces: 1,
            next_ns_id: 1,
            entries: [const { PidEntry::new() }; MAX_PIDS],
        }
    }

    /// Returns the number of active namespaces.
    pub fn nr_namespaces(&self) -> usize {
        self.nr_namespaces
    }

    /// Returns the root namespace's PID count.
    pub fn root_pid_count(&self) -> u32 {
        self.namespaces[0].pid_count()
    }

    /// Allocates a PID in the root namespace.
    pub fn alloc_pid(&mut self) -> Result<u32> {
        let pid = self.namespaces[0].alloc_pid()?;
        let idx = pid as usize;
        if idx < MAX_PIDS {
            self.entries[idx].ids[PidLevel::Thread.index()] = pid;
            self.entries[idx].ids[PidLevel::Process.index()] = pid;
            self.entries[idx].active = true;
            self.entries[idx].ns_level = 0;
        }
        Ok(pid)
    }

    /// Allocates a thread PID for an existing process.
    pub fn alloc_thread(&mut self, tgid: u32, pgid: u32, sid: u32) -> Result<u32> {
        let tid = self.namespaces[0].alloc_pid()?;
        let idx = tid as usize;
        if idx < MAX_PIDS {
            self.entries[idx].ids[PidLevel::Thread.index()] = tid;
            self.entries[idx].ids[PidLevel::Process.index()] = tgid;
            self.entries[idx].ids[PidLevel::ProcessGroup.index()] = pgid;
            self.entries[idx].ids[PidLevel::Session.index()] = sid;
            self.entries[idx].active = true;
        }
        Ok(tid)
    }

    /// Frees a PID.
    pub fn free_pid(&mut self, pid: u32) -> Result<()> {
        self.namespaces[0].free_pid(pid)?;
        let idx = pid as usize;
        if idx < MAX_PIDS {
            self.entries[idx].active = false;
        }
        Ok(())
    }

    /// Looks up a PID entry.
    pub fn lookup(&self, pid: u32) -> Result<&PidEntry> {
        if pid as usize >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[pid as usize].active {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[pid as usize])
    }

    /// Creates a new child PID namespace.
    pub fn create_namespace(&mut self, parent_idx: usize) -> Result<usize> {
        if parent_idx >= MAX_PID_NS {
            return Err(Error::InvalidArgument);
        }
        if !self.namespaces[parent_idx].active {
            return Err(Error::NotFound);
        }
        let slot = self
            .namespaces
            .iter()
            .position(|ns| !ns.active)
            .ok_or(Error::OutOfMemory)?;
        let ns_id = self.next_ns_id;
        self.next_ns_id = self.next_ns_id.wrapping_add(1);
        let parent_level = self.namespaces[parent_idx].level;
        self.namespaces[slot].ns_id = ns_id;
        self.namespaces[slot].level = parent_level + 1;
        self.namespaces[slot].parent = parent_idx as u8;
        self.namespaces[slot].active = true;
        self.nr_namespaces += 1;
        Ok(slot)
    }

    /// Destroys a PID namespace.
    pub fn destroy_namespace(&mut self, ns_idx: usize) -> Result<()> {
        if ns_idx >= MAX_PID_NS || ns_idx == 0 {
            return Err(Error::InvalidArgument);
        }
        if !self.namespaces[ns_idx].active {
            return Err(Error::NotFound);
        }
        self.namespaces[ns_idx].active = false;
        self.nr_namespaces = self.nr_namespaces.saturating_sub(1);
        Ok(())
    }
}
